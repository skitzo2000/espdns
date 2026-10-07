#include "blocking.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "health_node.h"
#include "hosted.h"
#include "jsonw.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "ota.h"
#include "power.h"
#include "querylog.h"
#include "reboot.h"
#include "sd.h"
#include "server.h"
#include "settings.h"
#include "share.h"
#include "supervisor.h"

static const char *TAG = "blocking";

#define OVR_MAX       (1024 * 1024) /* overrides: hundreds of entries, a few KB */

enum { K_LIST, K_OVR, K_N };
enum { ST_OFF, ST_LOADING, ST_ON, ST_FAILED };
static const char *const ST_NAME[] = { "off", "loading", "on", "failed" };
static const uint8_t KIND[K_N] = { REL_BLOCKLIST, REL_OVERRIDES };
static const char *const FILE_NAME[K_N] = { "list", "overrides" };

typedef struct {
    blk_ref_t *ref;
    int slot;         /* the active list's slot, -1 for none */
    volatile int state;
    const char *volatile err; /* why it is off or failed, or the last push that didn't apply */
    /* what the active list is, for /status (written under s_mu) */
    uint64_t seq;
    uint8_t sha256[32];
    uint32_t entries;
    blk_tier_t tier;
    size_t bytes;
    /* what it takes of the service's share (memplan.h): of the lists' memory, and of the
     * internal RAM for indexes */
    size_t data_bytes, index_bytes;
    /* a revert command moved it back from this seq (0: none); the boot keeps to it */
    uint64_t reverted;
    /* the boot fell back to this older copy: why the newest isn't in use (NULL: it is) */
    const char *older;
} svc_t;

static svc_t s_svc[K_N];
static SemaphoreHandle_t s_mu; /* loads and swaps; never taken on the query path */
static bool s_ready;           /* s_mu and the refs exist (made at the first start, then kept:
                                * the query path may still hold a ref): lists can load */
static volatile bool s_enabled; /* the service runs: the node config's blocking.enabled */
static bool s_loader;          /* a load task exists (under s_mu) */
static volatile bool s_start_failed; /* the last start couldn't make its task or memory */
static volatile bool s_sd_ok;
static volatile bool s_on;     /* a list or overrides are loaded: else queries skip all this */
static volatile uint32_t s_pause_until; /* uptime seconds; 0: not paused */
static uint8_t s_ctl[BLK_CTL_MAX];
static size_t s_ctl_len;
static uint32_t s_blocked, s_cname_blocked, s_allowed, s_reads, s_errors;
static char s_ctl_why[160];    /* a control release's refusal, when it names seqs */

#define COUNT(v, n) __atomic_fetch_add(&(v), (n), __ATOMIC_RELAXED)

static uint32_t now_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

static bool paused(void)
{
    uint32_t until = s_pause_until;
    return until && now_s() < until;
}

/* ---- memory ----
 * From the service's share of the memory plan (memplan.h, share.h), never from what happens to
 * be free: memory.blocklist_kb for the lists (PSRAM where the board has some), and
 * memory.blocklist_index_kb of internal RAM for their indexes. A list that doesn't fit is
 * refused or waits for a reboot, never loaded on a guess. */

static mp_pool_t data_pool(void) { return mp_data_pool(share_board()); }
static void *alloc_data(size_t n) { return share_alloc(SVC_BLOCKING, data_pool(), n); }
static void *alloc_internal(size_t n) { return share_alloc(SVC_BLOCKING, MP_INTERNAL, n); }

/* The indexes in internal RAM (the index share), or with the list. */
static const blk_alloc_t s_alloc_int = { alloc_data, alloc_internal, share_free };
static const blk_alloc_t s_alloc_data = { alloc_data, alloc_data, share_free };

static size_t s_stacks; /* the load task's stack, noted against the service while it runs */

/* What the lists in memory take, including any a query still holds after a swap. */
static size_t data_used(void)
{
    size_t u = share_used(SVC_BLOCKING, data_pool());
    return data_pool() == MP_INTERNAL ? u - s_stacks : u;
}

static size_t index_used(void)
{
    /* Without PSRAM the indexes go with the lists: there is no separate share. */
    return data_pool() == MP_PSRAM ? share_used(SVC_BLOCKING, MP_INTERNAL) - s_stacks : 0;
}

/* Where a list of kind k goes (docs/design.md, Lookup tiers; blk_place): the RAM tier when
 * the whole table fits the share once the list it replaces is gone, else the SD tier. now
 * in *pl: it fits next to that list, so it can be switched to live; else it applies with a
 * reboot. */
static const char *place(int k, const blk_need_t *n, blk_place_t *pl)
{
    const mp_board_t *mb = share_board();
    const svc_t *s = &s_svc[k];
    bool on = s->state == ST_ON;
    if (k == K_OVR && n->front + n->sectors > OVR_MAX)
        return "overrides too big";
    blk_room_t r = {
        .budget = (size_t)mb->blocklist_kb * 1024,
        .used = data_used(),
        .held = on ? s->data_bytes : 0,
        .index_budget = data_pool() == MP_PSRAM ? (size_t)mb->blocklist_index_kb * 1024 : 0,
        .index_used = index_used(),
        .index_held = on ? s->index_bytes : 0,
        .ram_tier = data_pool() == MP_PSRAM,
        .overrides = k == K_OVR,
    };
    return blk_place(n, &r, pl);
}

static void note_stack(long n)
{
    s_stacks += (size_t)n;
    share_note(SVC_BLOCKING, MP_INTERNAL, n);
}

/* ---- slots ---- */

static void slot_path(int k, int slot, char *p, size_t cap) { snprintf(p, cap, DNS2_BLOCK_DIR "/%s.%d", FILE_NAME[k], slot); }

/* A revert (BLK_CTL_REVERT) is kept in NVS, next to the release seqs: the seq it moved away
 * from. The boot never loads that copy while it is still the newest the node took; a newer
 * release makes it moot (blk_slot_order, blk_slot_older). */
#define REV_NS "espdns"

static void rev_key(uint8_t kind, char key[8]) { snprintf(key, 8, "rev%u", kind); }

uint64_t blocking_rev_get(uint8_t kind)
{
    char key[8];
    uint64_t v = 0;
    nvs_handle_t h;
    rev_key(kind, key);
    if (nvs_open(REV_NS, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u64(h, key, &v);
        nvs_close(h);
    }
    return v;
}

bool blocking_rev_set(uint8_t kind, uint64_t v)
{
    char key[8];
    nvs_handle_t h;
    rev_key(kind, key);
    if (nvs_open(REV_NS, NVS_READWRITE, &h) != ESP_OK)
        return false;
    esp_err_t e = v ? nvs_set_u64(h, key, v) : nvs_erase_key(h, key);
    bool ok = (e == ESP_OK || (!v && e == ESP_ERR_NVS_NOT_FOUND)) && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

static uint64_t rev_get(int k) { return blocking_rev_get(KIND[k]); }
static bool rev_set(int k, uint64_t v) { return blocking_rev_set(KIND[k], v); }

/* Opens a slot and checks its release header (and with hash, its payload). */
static const char *slot_open(int k, int slot, bool hash, rel_manifest_t *m, int *fd)
{
    char path[64];
    slot_path(k, slot, path, sizeof(path));
    *fd = open(path, O_RDONLY);
    if (*fd < 0)
        return errno == ENOENT ? "missing" : "slot unreadable";
    const char *why = blk_slot_read(*fd, ota_trust(), KIND[k], m);
    if (!why && hash)
        why = blk_slot_hash(*fd, m);
    if (why) {
        close(*fd);
        *fd = -1;
    }
    return why;
}

/* Loads a checked slot file (takes fd). *reboot instead of a list: it fits only once the
 * active one is gone (place). */
static const char *load(int k, int fd, const rel_manifest_t *m, blk_list_t **out, bool *reboot)
{
    uint8_t hdr[BL_HEADER];
    blk_need_t n;
    blk_place_t pl = { 0 };
    *out = NULL;
    *reboot = false;
    const char *why = m->payload_len < BL_HEADER || pread(fd, hdr, BL_HEADER, 0) != BL_HEADER
                          ? "not a blocklist"
                          : blk_plan(hdr, (size_t)m->payload_len, &n);
    if (!why)
        why = place(k, &n, &pl);
    if (why || !pl.now) {
        close(fd);
        *reboot = !why;
        return why;
    }
    return blk_load(fd, m, pl.tier, pl.index_internal ? &s_alloc_int : &s_alloc_data, out);
}

/* Makes l (from slot) the active list of kind k. Under s_mu. */
static void activate(int k, blk_list_t *l, int slot)
{
    svc_t *s = &s_svc[k];
    l->slot = slot;
    s->slot = slot;
    s->seq = l->m.seq;
    memcpy(s->sha256, l->m.sha256, 32);
    s->entries = l->entries;
    s->tier = l->tier;
    s->bytes = l->mem_bytes + l->index_bytes;
    bool idx_int = l->alloc == &s_alloc_int;
    s->data_bytes = l->mem_bytes + (idx_int ? 0 : l->index_bytes);
    s->index_bytes = idx_int ? l->index_bytes : 0;
    s->err = NULL;
    s->reverted = 0;
    s->older = NULL;
    s->state = ST_ON;
    blk_swap(s->ref, l);
    s_on = true;
    /* Cached answers were checked against the old lists (their CNAMEs). */
    server_cache_flush();
    ESP_LOGI(TAG, "%s: seq %llu from slot %d, %lu entries, %s tier, %u KB", FILE_NAME[k],
             (unsigned long long)l->m.seq, slot, (unsigned long)l->entries, l->tier == BLK_TIER_RAM ? "RAM" : "SD",
             (unsigned)(s->bytes / 1024));
}

/* At boot: the valid slot with the highest seq, else the other one (blk_slot_order), but
 * never the copy a revert moved away from. A boot that falls back to an older copy than the
 * newest the node took says so: degraded, "older copy" (blk_slot_older). */
static void boot_load(int k)
{
    svc_t *s = &s_svc[k];
    rel_manifest_t m[2];
    int fd[2];
    const char *why[2];
    bool ok[2];
    uint64_t seq[2];
    for (int i = 0; i < 2; i++) {
        why[i] = slot_open(k, i, false, &m[i], &fd[i]);
        ok[i] = !why[i];
        seq[i] = ok[i] ? m[i].seq : 0;
    }
    if (why[0] && why[1] && !strcmp(why[0], "missing") && !strcmp(why[1], "missing")) {
        bool installed = ota_seq(KIND[k]) != 0;
        s->state = installed ? ST_FAILED : ST_OFF;
        s->err = installed ? "missing from the SD card" : NULL;
        if (installed)
            ESP_LOGE(TAG, "%s: installed, but missing from the SD card: blocking without it", FILE_NAME[k]);
        return;
    }
    uint64_t recorded = ota_seq(KIND[k]), rev = rev_get(k);
    if (rev != recorded)
        rev = 0; /* a newer release came since the revert: it no longer holds */
    const char *last = NULL; /* why the last slot tried (or one that can't be) isn't used */
    for (int i = 0; i < 2; i++) {
        if (why[i] && strcmp(why[i], "missing")) {
            ESP_LOGW(TAG, "%s slot %d: %s", FILE_NAME[k], i, why[i]);
            last = why[i];
        } else if (!why[i] && rev && seq[i] == rev) {
            ESP_LOGI(TAG, "%s slot %d: seq %llu was reverted from: not loaded", FILE_NAME[k], i,
                     (unsigned long long)seq[i]);
        }
    }
    int order[2];
    int n = blk_slot_order(ok, seq, rev, order);
    for (int j = 0; j < n; j++) {
        int i = order[j];
        blk_list_t *l = NULL;
        bool reboot;
        const char *w = blk_slot_hash(fd[i], &m[i]);
        if (w)
            close(fd[i]);
        else
            w = load(k, fd[i], &m[i], &l, &reboot);
        fd[i] = -1;
        if (l) {
            activate(k, l, i);
            s->reverted = rev;
            if (blk_slot_older(m[i].seq, recorded, rev)) {
                /* The newest is the slot tried before this one, else the other slot, which
                 * failed its header check or isn't there. */
                s->older = j ? last : why[1 - i] ? why[1 - i] : "not on the SD card";
                ESP_LOGE(TAG, "%s: seq %llu, the newest taken, is not usable (%s): running the older seq %llu",
                         FILE_NAME[k], (unsigned long long)recorded, s->older, (unsigned long long)m[i].seq);
            }
            break;
        }
        ESP_LOGW(TAG, "%s slot %d (seq %llu): %s", FILE_NAME[k], i, (unsigned long long)m[i].seq, w);
        last = w;
    }
    for (int i = 0; i < 2; i++)
        if (fd[i] >= 0)
            close(fd[i]);
    if (s->state != ST_ON) {
        s->state = ST_FAILED;
        s->err = last ? last : rev ? "only the copy reverted from is on the SD card" : "missing from the SD card";
        ESP_LOGE(TAG, "%s: no usable slot (%s): blocking without it", FILE_NAME[k], s->err);
    }
}

const char BLOCKING_LOADING[] = "blocking is still loading; try again shortly";

/* Off if it was never installed, else failed for why. */
static void unavailable(int k, const char *why)
{
    bool installed = ota_seq(KIND[k]) != 0;
    s_svc[k].state = installed ? ST_FAILED : ST_OFF;
    s_svc[k].err = installed ? why : NULL;
}

#define LOAD_STACK MP_BLOCKING_STACK

static void load_task(void *arg)
{
    /* The card may still be mounting (sd.c): its result, however long it takes. */
    bool sd_ok = sd_wait() == SD_MOUNTED;
    xSemaphoreTake(s_mu, portMAX_DELAY);
    s_sd_ok = sd_ok;
    /* Turned off while the card was mounting: nothing to load. */
    if (s_enabled && !sd_ok) {
        for (int k = 0; k < K_N; k++)
            unavailable(k, "no SD card");
    } else if (s_enabled) {
        if (mkdir(DNS2_BLOCK_DIR, 0755) < 0 && errno != EEXIST)
            ESP_LOGE(TAG, "cannot create %s", DNS2_BLOCK_DIR);
        /* Watched while it loads (sup.h): a card that hangs fails the service, visibly. */
        int watch = supervisor_watch(SVC_BLOCKING, SUP_TASK, SUP_TASK_MS);
        int64_t t0 = esp_timer_get_time();
        power_hold(POWER_WORK); /* at the full clock (power.h) */
        boot_load(K_OVR);
        supervisor_kick(watch);
        boot_load(K_LIST);
        power_release(POWER_WORK);
        supervisor_unwatch(watch);
        ESP_LOGI(TAG, "loaded in %lld ms", (esp_timer_get_time() - t0) / 1000);
    }
    s_loader = false;
    note_stack(-LOAD_STACK);
    xSemaphoreGive(s_mu);
    vTaskDelete(NULL);
}

void blocking_start(void)
{
    if (!settings()->blocking) {
        ESP_LOGI(TAG, "off in the node config");
        return;
    }
    s_start_failed = false;
    if (!s_mu)
        s_mu = xSemaphoreCreateMutex();
    bool ok = s_mu != NULL;
    for (int k = 0; k < K_N; k++) {
        if (!s_svc[k].ref)
            s_svc[k].ref = blk_ref_new();
        ok = ok && s_svc[k].ref;
    }
    if (!ok) {
        ESP_LOGE(TAG, "out of memory: blocking unavailable");
        s_enabled = true;
        s_start_failed = true;
        for (int k = 0; k < K_N; k++) {
            s_svc[k].slot = -1;
            unavailable(k, "out of memory");
        }
        return;
    }
    s_ready = true;
    /* s_enabled under s_mu: a load task from an earlier start, still waiting for the card,
     * decides under it whether to load, so it and this start never both load. */
    xSemaphoreTake(s_mu, portMAX_DELAY);
    s_enabled = true;
    for (int k = 0; k < K_N; k++) {
        s_svc[k].slot = -1;
        s_svc[k].state = ST_OFF;
    }
    if (sd_state() == SD_NONE || sd_state() == SD_FAILED) {
        for (int k = 0; k < K_N; k++)
            unavailable(k, "no SD card");
    } else {
        s_svc[K_LIST].state = s_svc[K_OVR].state = ST_LOADING;
        /* Below the DNS tasks: answering comes first, and answers are unblocked until it's
         * done. A task from an earlier start still waiting for the card does this load. */
        bool test_fail = false;
#ifdef DNS2_TEST_START_FAILS
        static int fails; /* test hook (CMakeLists.txt): the supervisor's restarts */
        test_fail = !s_loader && fails < DNS2_TEST_START_FAILS && ++fails;
#endif
        if (s_loader) {
            /* the earlier start's task loads */
        } else if (test_fail || xTaskCreate(load_task, "blocking", LOAD_STACK, NULL, 2, NULL) != pdPASS) {
            s_svc[K_LIST].state = s_svc[K_OVR].state = ST_FAILED;
            s_svc[K_LIST].err = s_svc[K_OVR].err = "could not start";
            s_start_failed = true;
        } else {
            s_loader = true;
            note_stack(LOAD_STACK);
        }
    }
    xSemaphoreGive(s_mu);
}

void blocking_stop(void)
{
    if (!s_ready) { /* never started, or out of memory at the start: nothing loaded */
        s_enabled = false;
        for (int k = 0; k < K_N; k++) {
            s_svc[k].state = ST_OFF;
            s_svc[k].err = NULL;
        }
        return;
    }
    xSemaphoreTake(s_mu, portMAX_DELAY); /* after a load in progress */
    s_enabled = false;
    s_on = false; /* queries skip blocking from here */
    for (int k = 0; k < K_N; k++) {
        svc_t *s = &s_svc[k];
        blk_swap(s->ref, NULL); /* freed once the last query using it is done */
        s->slot = -1;
        s->state = ST_OFF;
        s->err = NULL;
        s->seq = 0;
        s->entries = 0;
        s->bytes = s->data_bytes = s->index_bytes = 0;
        s->reverted = 0;
        s->older = NULL;
    }
    s_start_failed = false;
    xSemaphoreGive(s_mu);
    /* A list waiting for a reboot to fit never loads while blocking is off; turned on again,
     * it loads then, with the old one gone. */
    ota_reboot_update(RB_BLOCKLIST, 0);
    ESP_LOGI(TAG, "off: lists unloaded");
}

bool blocking_broken(void) { return s_enabled && s_start_failed; }

svc_state_t blocking_state(void)
{
    if (!s_enabled)
        return SVC_OFF;
    int l = s_svc[K_LIST].state, o = s_svc[K_OVR].state;
    if (l == ST_LOADING || o == ST_LOADING)
        return SVC_STARTING;
    return l == ST_FAILED || o == ST_FAILED ? SVC_FAILED : SVC_RUNNING;
}

/* ---- the query path ---- */

static void count_stats(const bl_stats_t *st)
{
    if (st->reads)
        COUNT(s_reads, st->reads);
    if (st->errors)
        COUNT(s_errors, st->errors);
}

blk_result_t blocking_query(const uint8_t *qname)
{
    if (!s_on)
        return BLK_PASS;
    bl_stats_t st = { 0 };
    blk_list_t *ovr = blk_get(s_svc[K_OVR].ref), *list = blk_get(s_svc[K_LIST].ref);
    bool by_ovr;
    blk_result_t r = blk_decide_by(ovr, paused(), list, qname, &st, &by_ovr);
    blk_put(list);
    blk_put(ovr);
    count_stats(&st);
    if (r == BLK_BLOCK)
        COUNT(s_blocked, 1);
    else if (r == BLK_ALLOW)
        COUNT(s_allowed, 1);
    if (r != BLK_PASS)
        querylog_note_rule(r == BLK_ALLOW ? QL_RULE_ALLOW : by_ovr ? QL_RULE_OVERRIDE : QL_RULE_LIST);
    return r;
}

/* The answer and its TTL are live settings. */
int blocking_answer(dns_builder_t *b, const dns_query_t *q)
{
    return blk_answer(b, q, settings()->block_nxdomain, (uint32_t)settings()->block_ttl);
}

typedef struct {
    const blk_list_t *ovr, *list;
    bl_stats_t st;
} cname_ctx_t;

/* Judged as if not paused: a paused node answers with it but doesn't cache it. */
static bool cname_blocked(void *ctx, const uint8_t *name)
{
    cname_ctx_t *c = ctx;
    return blk_decide(c->ovr, false, c->list, name, &c->st) == BLK_BLOCK;
}

blocking_cname_t blocking_cnames(const uint8_t *msg, size_t len)
{
    if (!s_on)
        return BLOCKING_CNAME_PASS;
    cname_ctx_t c = { .ovr = blk_get(s_svc[K_OVR].ref), .list = blk_get(s_svc[K_LIST].ref) };
    bool hit = blk_cname_any(msg, len, cname_blocked, &c);
    blk_put((blk_list_t *)c.list);
    blk_put((blk_list_t *)c.ovr);
    count_stats(&c.st);
    if (!hit)
        return BLOCKING_CNAME_PASS;
    if (paused())
        return BLOCKING_CNAME_NOCACHE;
    COUNT(s_cname_blocked, 1);
    querylog_note_rule(QL_RULE_CNAME);
    return BLOCKING_CNAME_BLOCK;
}

/* ---- releases ---- */

bool blocking_kind(uint8_t kind) { return kind == REL_BLOCKLIST || kind == REL_OVERRIDES || kind == REL_CONTROL; }

static int kind_index(uint8_t kind) { return kind == REL_OVERRIDES ? K_OVR : K_LIST; }

/* The slot a new release goes in: never the active one (the SD tier reads from it). */
static int next_slot(int k) { return s_svc[k].slot == 0 ? 1 : 0; }

/* ---- revert (BLK_CTL_REVERT) ---- */

/* The list a revert payload names (s_ctl), or -1 (the hosted zones' is hosted.c's). */
static int revert_kind(void)
{
    uint8_t kind = blk_ctl_revert_kind(s_ctl, s_ctl_len);
    return kind == REL_BLOCKLIST ? K_LIST : kind == REL_OVERRIDES ? K_OVR : -1;
}

/* A revert of the hosted zones (hosted.c), which take control releases through here. */
static bool revert_zones(void) { return blk_ctl_revert_kind(s_ctl, s_ctl_len) == REL_ZONES; }

/* Why kind k can't go back to the copy in its other slot, or NULL; with m and fd, that
 * slot's header and the open file (its payload not yet hashed). Under s_mu (the boot load
 * holds it while it runs; a release is never received during another). */
static const char *revert_check(int k, rel_manifest_t *m, int *fd)
{
    const svc_t *s = &s_svc[k];
    if (!s_enabled)
        return settings()->blocking ? BLOCKING_LOADING : "blocking is off in the node config";
    if (s->state == ST_LOADING)
        return BLOCKING_LOADING;
    if (!s_ready)
        return "blocking is unavailable (out of memory)";
    if (!s_sd_ok)
        return "no SD card: blocking is unavailable";
    if (s->state != ST_ON) {
        snprintf(s_ctl_why, sizeof(s_ctl_why), "no %s in use: nothing to revert from", FILE_NAME[k]);
        return s_ctl_why;
    }
    rel_manifest_t om;
    int ofd;
    int other = 1 - s->slot;
    const char *why = slot_open(k, other, false, &om, &ofd);
    why = blk_revert_check(FILE_NAME[k], other, why, why ? 0 : om.seq, s->seq, s->reverted,
                           k == K_LIST && (ota_reboot_reasons() & RB_BLOCKLIST) ? "waiting for a reboot" : "newer",
                           s_ctl_why, sizeof(s_ctl_why));
    if (why) {
        if (ofd >= 0)
            close(ofd);
        return why;
    }
    if (fd) {
        *m = om;
        *fd = ofd;
    } else {
        close(ofd);
    }
    return NULL;
}

/* Goes back to the older copy in the other slot: loaded and swapped in live as a push is, or,
 * when two copies don't fit, at the next boot (*reboot). The revert is recorded first, so
 * whatever boot comes next keeps to it; a newer release ends it. */
static const char *revert(int k, char *msg, size_t cap, bool *reboot)
{
    svc_t *s = &s_svc[k];
    rel_manifest_t m;
    int fd = -1;
    blk_list_t *l = NULL;
    if (!s_ready)
        return revert_check(k, NULL, NULL);
    xSemaphoreTake(s_mu, portMAX_DELAY);
    uint64_t from = s->seq;
    int slot = 1 - s->slot;
    const char *why = revert_check(k, &m, &fd);
    /* It has sat on the card since it was written: its payload is checked again. */
    if (!why && (why = blk_slot_hash(fd, &m)) != NULL)
        close(fd);
    else if (!why)
        why = load(k, fd, &m, &l, reboot);
    if (!why && !rev_set(k, from)) {
        why = "could not record the revert";
        blk_list_free(l);
        l = NULL;
        *reboot = false;
    }
    if (l) {
        activate(k, l, slot);
        s->reverted = from;
        snprintf(msg, cap, "ok, %s reverted to seq %llu (slot %d) from seq %llu: %lu entries, %s tier\n",
                 FILE_NAME[k], (unsigned long long)m.seq, slot, (unsigned long long)from, (unsigned long)s->entries,
                 s->tier == BLK_TIER_RAM ? "RAM" : "SD");
        ESP_LOGW(TAG, "%s reverted to seq %llu from seq %llu", FILE_NAME[k], (unsigned long long)m.seq,
                 (unsigned long long)from);
    } else if (*reboot) {
        ota_reboot_update(RB_BLOCKLIST, RB_BLOCKLIST);
        snprintf(msg, cap, "ok, %s reverts to seq %llu at the next reboot (two copies don't fit); seq %llu until then\n",
                 FILE_NAME[k], (unsigned long long)m.seq, (unsigned long long)from);
    } else {
        ESP_LOGE(TAG, "%s revert to slot %d not applied: %s", FILE_NAME[k], slot, why);
    }
    xSemaphoreGive(s_mu);
    return why;
}

const char *blocking_store(const uint8_t hdr[REL_HEADER_LEN], const rel_manifest_t *m, blk_recv_fn recv, void *ctx)
{
    if (m->kind == REL_CONTROL) {
        uint8_t sha[32];
        if (m->payload_len == 0 || m->payload_len > BLK_CTL_MAX)
            return "bad control payload";
        if (!recv(ctx, s_ctl, (size_t)m->payload_len))
            return "receive failed";
        mbedtls_sha256(s_ctl, (size_t)m->payload_len, sha, 0);
        if (memcmp(sha, m->sha256, 32) != 0)
            return "payload does not match the signed hash";
        s_ctl_len = (size_t)m->payload_len;
        /* A revert with nothing to go back to is refused before its seq is taken. */
        if (revert_zones())
            return hosted_revert_check();
        if (s_ctl[0] == BLK_CTL_REVERT) {
            int k = revert_kind();
            if (k < 0)
                return "bad revert payload";
            /* Never started, or the boot load waiting for the card or running (it holds s_mu
             * for seconds): refused before the slots are looked at, a 503 as a push's is. */
            if (!s_ready || !s_enabled || s_svc[k].state == ST_LOADING)
                return revert_check(k, NULL, NULL);
            xSemaphoreTake(s_mu, portMAX_DELAY);
            const char *why = revert_check(k, NULL, NULL);
            xSemaphoreGive(s_mu);
            return why;
        }
        return NULL;
    }
    /* On in the config but not started yet: the moment between the HTTP server and
     * blocking_start at boot. */
    if (!s_enabled)
        return settings()->blocking ? BLOCKING_LOADING : "blocking is off in the node config";
    int k = kind_index(m->kind);
    /* Not while the boot load is waiting for the card or running: it holds s_mu for seconds. */
    if (s_svc[k].state == ST_LOADING)
        return BLOCKING_LOADING;
    if (!s_ready)
        return "blocking is unavailable (out of memory)";
    if (!s_sd_ok)
        return "no SD card: blocking is unavailable";
    if (k == K_OVR && m->payload_len > OVR_MAX)
        return "overrides too big";
    char path[64];
    const char *why;
    xSemaphoreTake(s_mu, portMAX_DELAY);
    /* Before the boot load has run, the active slot isn't known yet: writing now could
     * overwrite the newest good list, and the boot load would then run after this one. */
    if (s_svc[k].state == ST_LOADING) {
        why = BLOCKING_LOADING;
    } else {
        slot_path(k, next_slot(k), path, sizeof(path));
        /* A list pending a reboot is in that slot: from here it is gone. */
        if (k == K_LIST)
            ota_reboot_update(RB_BLOCKLIST, 0);
        why = blk_slot_store(path, hdr, m, recv, ctx);
    }
    xSemaphoreGive(s_mu);
    return why;
}

static const char *apply_control(char *msg, size_t cap, bool *reboot)
{
    if (revert_zones())
        return hosted_revert(msg, cap);
    if (s_ctl_len && s_ctl[0] == BLK_CTL_REVERT) {
        int k = revert_kind();
        return k < 0 ? "bad revert payload" : revert(k, msg, cap, reboot);
    }
    if (s_ctl_len == 5 && s_ctl[0] == BLK_CTL_PAUSE) {
        uint32_t secs = s_ctl[1] | (uint32_t)s_ctl[2] << 8 | (uint32_t)s_ctl[3] << 16 | (uint32_t)s_ctl[4] << 24;
        uint32_t now = now_s();
        s_pause_until = !secs ? 0 : secs > UINT32_MAX - now ? UINT32_MAX : now + secs; /* no wrap */
        if (secs)
            snprintf(msg, cap, "ok, blocking paused for %lu s\n", (unsigned long)secs);
        else
            snprintf(msg, cap, "ok, blocking resumed\n");
        ESP_LOGW(TAG, "%s", secs ? "paused" : "resumed");
        return NULL;
    }
    if (s_ctl_len == 5 && s_ctl[0] == BLK_CTL_IDENTIFY) {
        uint32_t secs = s_ctl[1] | (uint32_t)s_ctl[2] << 8 | (uint32_t)s_ctl[3] << 16 | (uint32_t)s_ctl[4] << 24;
        bool led = health_identify(secs);
        if (!secs)
            snprintf(msg, cap, "ok, identify stopped\n");
        else
            snprintf(msg, cap, "ok, identifying for %lu s%s\n", (unsigned long)health_identify_left(),
                     led ? "" : " (this board has no LED: only the log shows it)");
        return NULL;
    }
    if (s_ctl_len && s_ctl[0] == RB_CTL_REBOOT) {
        rb_ctl_t c;
        const char *why = rb_ctl_parse(s_ctl, s_ctl_len, &c);
        if (why)
            return why;
        if ((c.flags & RB_FLAG_IF_PENDING) && !ota_reboot_reasons()) {
            snprintf(msg, cap, "ok, no reboot pending: not rebooting\n");
            return NULL;
        }
        ota_reboot_after(c.delay_ms);
        snprintf(msg, cap, "ok, rebooting in %lu ms\n", (unsigned long)c.delay_ms);
        return NULL;
    }
    if (s_ctl_len == 1 && s_ctl[0] == BLK_CTL_FLUSH) {
        server_cache_flush();
        ESP_LOGW(TAG, "cache flushed");
        snprintf(msg, cap, "ok, cache flushed\n");
        return NULL;
    }
    return "unknown control command";
}

const char *blocking_apply(const rel_manifest_t *m, char *msg, size_t cap, bool *reboot)
{
    *reboot = false;
    if (m->kind == REL_CONTROL)
        return apply_control(msg, cap, reboot);
    if (!s_enabled)
        return "blocking is off in the node config";
    if (!s_ready)
        return "blocking is unavailable (out of memory)";
    int k = kind_index(m->kind);
    svc_t *s = &s_svc[k];
    xSemaphoreTake(s_mu, portMAX_DELAY);
    int slot = next_slot(k);
    rel_manifest_t sm;
    int fd;
    blk_list_t *l = NULL;
    /* Just written and hashed: the header check is enough. */
    const char *why = slot_open(k, slot, false, &sm, &fd);
    if (!why && sm.seq != m->seq)
        why = "slot holds another release";
    if (!why)
        why = load(k, fd, &sm, &l, reboot);
    else if (fd >= 0)
        close(fd);
    /* A revert in force ends with a newer release taken. */
    if ((l || *reboot) && rev_get(k))
        rev_set(k, 0);
    if (l) {
        activate(k, l, slot);
        if (k == K_LIST)
            ota_reboot_update(RB_BLOCKLIST, 0);
        snprintf(msg, cap, "ok, %s seq %llu applied: %lu entries, %s tier\n", FILE_NAME[k],
                 (unsigned long long)l->m.seq, (unsigned long)s->entries, s->tier == BLK_TIER_RAM ? "RAM" : "SD");
    } else if (*reboot) {
        /* The active list stays until the controller reboots the node; the boot loads this
         * slot first (the highest seq). */
        ota_reboot_update(RB_BLOCKLIST, RB_BLOCKLIST);
        snprintf(msg, cap, "ok, %s seq %llu stored; applies at the next reboot (two copies don't fit)\n",
                 FILE_NAME[k], (unsigned long long)m->seq);
    } else {
        /* The active list (if any) stays; the next boot tries this slot first and falls back. */
        s->err = why;
        if (s->state != ST_ON)
            s->state = ST_FAILED;
        ESP_LOGE(TAG, "%s seq %llu not applied: %s", FILE_NAME[k], (unsigned long long)m->seq, why);
    }
    xSemaphoreGive(s_mu);
    return l || *reboot ? NULL : why;
}

/* ---- health ---- */

bool blocking_degraded(void)
{
    return s_enabled && (s_svc[K_LIST].state == ST_FAILED || s_svc[K_OVR].state == ST_FAILED || s_errors != 0);
}

bool blocking_older(void)
{
    return s_enabled && ((s_svc[K_LIST].state == ST_ON && s_svc[K_LIST].older) ||
                         (s_svc[K_OVR].state == ST_ON && s_svc[K_OVR].older));
}

/* bytes: what the list takes; data_bytes of that in the lists' memory (memory.blocklist_kb),
 * internal_bytes its indexes in internal RAM (memory.blocklist_index_kb): what the controller
 * places the next list from, as place() does. */
/* An error or fallback reason (all are constants or s_ctl_why-sized), escaped for /status */
#define STATUS_STR (2 * sizeof(s_ctl_why) + 3)

static size_t list_json(char *j, size_t cap, int k)
{
    const svc_t *s = &s_svc[k];
    const char *err = s->err;
    bool on = s->state == ST_ON;
    const char *older = on ? s->older : NULL;
    char sha[65] = "", qo[STATUS_STR], qe[STATUS_STR];
    if (s->state == ST_ON)
        for (int i = 0; i < 32; i++)
            sprintf(sha + 2 * i, "%02x", s->sha256[i]);
    return (size_t)snprintf(j, cap,
                            "{\"state\":\"%s\",\"seq\":%llu,\"sha256\":\"%s\",\"entries\":%lu,\"tier\":\"%s\","
                            "\"bytes\":%u,\"data_bytes\":%u,\"internal_bytes\":%u,\"slot\":%d,\"reverted_from\":%llu,"
                            "\"fallback\":%s,\"error\":%s}",
                            ST_NAME[s->state], (unsigned long long)(s->state == ST_ON ? s->seq : 0), sha,
                            (unsigned long)(s->state == ST_ON ? s->entries : 0),
                            s->state != ST_ON ? "" : s->tier == BLK_TIER_RAM ? "ram" : "sd",
                            (unsigned)(s->state == ST_ON ? s->bytes : 0), (unsigned)(s->state == ST_ON ? s->data_bytes : 0),
                            (unsigned)(s->state == ST_ON ? s->index_bytes : 0), on ? s->slot : -1,
                            (unsigned long long)(on ? s->reverted : 0), json_q(qo, sizeof(qo), older),
                            json_q(qe, sizeof(qe), err));
}

size_t blocking_health_json(char *j, size_t cap)
{
    size_t n = 0;
    for (int k = 0; k < K_N && n < cap; k++) {
        const svc_t *s = &s_svc[k];
        bool on = s->state == ST_ON;
        char sha[65] = "";
        if (on)
            for (int i = 0; i < 32; i++)
                sprintf(sha + 2 * i, "%02x", s->sha256[i]);
        n += (size_t)snprintf(j + n, cap - n, "%s\"%s\":{\"state\":\"%s\",\"seq\":%llu,\"sha256\":\"%s\"}", k ? "," : "",
                              k == K_LIST ? "blocklist" : "overrides", ST_NAME[s->state],
                              (unsigned long long)(on ? s->seq : 0), sha);
    }
    return n < cap ? n : cap - 1;
}

size_t blocking_status_json(char *j, size_t cap)
{
    size_t n = 0;
    uint32_t until = s_pause_until, now = now_s();
    n += (size_t)snprintf(j + n, cap - n, "\"blocking\":{\"list\":");
    if (n < cap)
        n += list_json(j + n, cap - n, K_LIST);
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, ",\"overrides\":");
    if (n < cap)
        n += list_json(j + n, cap - n, K_OVR);
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n,
                              ",\"paused_s\":%lu,\"blocked\":%lu,\"cname_blocked\":%lu,\"allowed\":%lu,"
                              "\"sector_reads\":%lu,\"errors\":%lu}",
                              (unsigned long)(until > now ? until - now : 0), (unsigned long)s_blocked,
                              (unsigned long)s_cname_blocked, (unsigned long)s_allowed, (unsigned long)s_reads,
                              (unsigned long)s_errors);
    return n < cap ? n : cap - 1;
}

/* ---- metrics ---- */

void blocking_metrics(blocking_metrics_t *m)
{
    for (int k = 0; k < K_N; k++) {
        const svc_t *s = &s_svc[k];
        bool on = s->state == ST_ON;
        m->list[k].state = ST_NAME[s->state];
        m->list[k].on = on;
        m->list[k].seq = on ? s->seq : 0;
        m->list[k].entries = on ? s->entries : 0;
        m->list[k].bytes = on ? s->bytes : 0;
    }
    uint32_t until = s_pause_until, now = now_s();
    m->paused_s = until > now ? until - now : 0;
    m->blocked = s_blocked;
    m->cname_blocked = s_cname_blocked;
    m->allowed = s_allowed;
    m->sector_reads = s_reads;
    m->errors = s_errors;
}
