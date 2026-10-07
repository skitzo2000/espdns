#include "hosted.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blocking.h"
#include "board.h"
#include "config.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "hzone.h"
#include "jsonw.h"
#include "mbedtls/sha256.h"
#include "ota.h"
#include "power.h"
#include "registry.h"
#include "sd.h"
#include "server.h"
#include "settings.h"
#include "share.h"
#include "supervisor.h"

static const char *TAG = "hosted";

enum { ST_OFF, ST_LOADING, ST_ON, ST_FAILED };
static const char *const ST_NAME[] = { "off", "loading", "on", "failed" };

static SemaphoreHandle_t s_mu;  /* loads, stores and swaps; never taken on the query path */
static volatile int s_state = ST_OFF;
static int s_slot = -1;         /* the slot in use */
static uint64_t s_seq;
static uint64_t s_reverted;     /* a revert moved the zones back from this seq (0: none) */
static uint8_t s_sha[32];
static char s_err[384];         /* why it failed, or a zone not served; "" if none */
static char s_older[160];       /* the boot fell back to an older bundle: why the newest isn't used */
static bool s_sd_ok;
static volatile bool s_enabled; /* the service runs: the node config's hosted.enabled */
static bool s_loader;           /* a load task exists (under s_mu) */
static hz_set_t *s_pending;     /* stored by hosted_store, put to use by hosted_apply */
static volatile size_t s_mem, s_pending_mem; /* hz_mem of the zones in use, and pending */
static volatile bool s_start_failed; /* the last start couldn't make its task or lock */
static int s_pending_slot = -1;
static char s_reply[384];

const char HOSTED_LOADING[] = "hosted zones are still loading; try again shortly";

/* The most the zones may take: the board's memory.hosted_zones_kb, else the image's
 * default (memplan.h). The service's share of the plan is three times this: the zones in
 * use, a new bundle checked next to them, and its payload as it arrives. */
static size_t limit(void) { return (size_t)share_board()->hosted_zones_kb * 1024; }

static void slot_path(int slot, char *p, size_t cap) { snprintf(p, cap, DNS2_HOSTED_DIR "/zones.%d", slot); }

/* s_err goes into /status as a JSON string: no quotes or backslashes (names come from
 * dns_name_to_str, which has none; hz_parse's messages may quote). */
static void set_err(const char *why)
{
    snprintf(s_err, sizeof(s_err), "%s", why);
    for (char *c = s_err; *c; c++)
        if (*c == '"' || *c == '\\' || (unsigned char)*c < 32)
            *c = '\'';
}

/* Drops the zones the config also names (a secondary or forward zone takes precedence:
 * it was set up first); says which in s_err. */
static void drop_clashes(hz_set_t *s)
{
    int i;
    while ((i = hz_clash(s, settings())) >= 0) {
        char n[256];
        dns_name_to_str(s->z[i]->apex, n, sizeof(n));
        snprintf(s_err, sizeof(s_err), "%s is also a secondary or forward zone in the node config: not served", n);
        ESP_LOGE(TAG, "%s", s_err);
        hz_drop(s, i);
    }
}

/* Makes s (from slot) the zones in use. Under s_mu. */
static void activate(hz_set_t *s, int slot, const rel_manifest_t *m)
{
    s_slot = slot;
    s_seq = m->seq;
    s_reverted = 0;
    s_older[0] = 0;
    memcpy(s_sha, m->sha256, 32);
    s_state = ST_ON;
    s_mem = s->mem;
    hz_free(reg_hosted_swap(s));
    /* Answers cached while a name wasn't hosted (or was hosted differently) must go. */
    server_cache_flush();
    unsigned recs = 0;
    for (int i = 0; i < s->n; i++)
        recs += (unsigned)s->z[i]->n;
    ESP_LOGI(TAG, "seq %llu from slot %d: %d zones, %u records, %u of %u KB", (unsigned long long)m->seq, slot, s->n,
             recs, (unsigned)((s->mem + 1023) / 1024), (unsigned)(limit() / 1024));
}

/* Loads and checks one slot; err holds a refusal's details. */
static const char *slot_load(int slot, rel_manifest_t *m, hz_set_t **out, char *err, size_t errlen)
{
    char path[64];
    *out = NULL;
    slot_path(slot, path, sizeof(path));
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return errno == ENOENT ? "missing" : "slot unreadable";
    const char *why = blk_slot_read(fd, ota_trust(), REL_ZONES, m);
    uint8_t *buf = NULL;
    if (!why && m->payload_len > limit())
        why = "bundle bigger than this board's limit";
    if (!why && !(buf = malloc((size_t)m->payload_len ? (size_t)m->payload_len : 1)))
        why = "out of memory";
    if (!why && pread(fd, buf, (size_t)m->payload_len, 0) != (ssize_t)m->payload_len)
        why = "slot unreadable";
    close(fd);
    if (!why) {
        uint8_t sha[32];
        mbedtls_sha256(buf, (size_t)m->payload_len, sha, 0);
        if (memcmp(sha, m->sha256, 32) != 0)
            why = "slot does not match its signed hash";
    }
    if (!why)
        why = hz_parse(buf, (size_t)m->payload_len, limit(), out, err, errlen);
    free(buf);
    return why;
}

/* A slot's header (signature, node, image, kind), without reading the payload. */
static const char *slot_header(int slot, rel_manifest_t *m)
{
    char path[64];
    slot_path(slot, path, sizeof(path));
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return errno == ENOENT ? "missing" : "slot unreadable";
    const char *why = blk_slot_read(fd, ota_trust(), REL_ZONES, m);
    close(fd);
    return why;
}

/* The valid slot with the highest seq, else the other (blk_slot_order), but never the bundle a
 * revert moved away from: only the one used is parsed. A fall back to an older bundle than the
 * newest the node took is degraded ("older copy", blk_slot_older). Under s_mu. */
static void boot_load(void)
{
    rel_manifest_t m[2];
    const char *why[2];
    bool ok[2];
    uint64_t seq[2];
    for (int i = 0; i < 2; i++) {
        why[i] = slot_header(i, &m[i]);
        ok[i] = !why[i];
        seq[i] = ok[i] ? m[i].seq : 0;
    }
    bool installed = ota_seq(REL_ZONES) != 0;
    if (!strcmp(why[0] ? why[0] : "", "missing") && !strcmp(why[1] ? why[1] : "", "missing")) {
        s_state = installed ? ST_FAILED : ST_OFF;
        if (installed) {
            set_err("missing from the SD card");
            ESP_LOGE(TAG, "installed, but missing from the SD card");
        }
        return;
    }
    char err[160];
    const char *last = "missing";
    uint64_t recorded = ota_seq(REL_ZONES), rev = blocking_rev_get(REL_ZONES);
    if (rev != recorded)
        rev = 0; /* a newer bundle came since the revert: it no longer holds */
    for (int i = 0; i < 2; i++) {
        if (why[i] && strcmp(why[i], "missing")) {
            ESP_LOGW(TAG, "slot %d: %s", i, why[i]);
            last = why[i];
        } else if (!why[i] && rev && seq[i] == rev) {
            ESP_LOGI(TAG, "slot %d: seq %llu was reverted from: not loaded", i, (unsigned long long)seq[i]);
        }
    }
    if (rev && !strcmp(last, "missing") && (seq[0] == rev || seq[1] == rev))
        last = "only the bundle reverted from is on the SD card";
    int order[2];
    int n = blk_slot_order(ok, seq, rev, order);
    for (int j = 0; j < n; j++) {
        int i = order[j];
        hz_set_t *s;
        const char *w = slot_load(i, &m[i], &s, err, sizeof(err));
        if (!w) {
            /* The newest is the slot tried before this one (its error in s_err), else the
             * other slot, which failed its header check or isn't there. */
            char older[sizeof(s_older)] = "";
            if (blk_slot_older(m[i].seq, recorded, rev))
                snprintf(older, sizeof(older), "%.150s", j ? s_err : why[1 - i] ? why[1 - i] : "not on the SD card");
            s_err[0] = 0;
            drop_clashes(s);
            activate(s, i, &m[i]);
            s_reverted = rev;
            if (older[0]) {
                snprintf(s_older, sizeof(s_older), "%s", older);
                ESP_LOGE(TAG, "seq %llu, the newest taken, is not usable (%s): serving the older seq %llu",
                         (unsigned long long)ota_seq(REL_ZONES), s_older, (unsigned long long)m[i].seq);
            }
            return;
        }
        ESP_LOGW(TAG, "slot %d (seq %llu): %s", i, (unsigned long long)m[i].seq, w);
        set_err(w); /* w may be err: keep it before the next slot reuses it */
        last = s_err;
    }
    s_state = ST_FAILED;
    if (last != s_err)
        set_err(last);
    ESP_LOGE(TAG, "no usable slot (%s): hosted names are forwarded", s_err);
}

/* The load runs in its own task: hz_parse and the signature check need more stack than
 * app_main's (CONFIG_ESP_MAIN_TASK_STACK_SIZE, 3.5 KB). arg: a semaphore to give when done
 * (the card mounted in time and app_main waits), or NULL (once the card mounts). */
#define LOAD_STACK MP_HOSTED_STACK

static void load_task(void *arg)
{
    SemaphoreHandle_t done = arg;
    bool sd_ok = done || sd_wait() == SD_MOUNTED;
    xSemaphoreTake(s_mu, portMAX_DELAY);
    s_sd_ok = sd_ok;
    if (!s_enabled) {
        /* turned off while the card was mounting: nothing to load */
    } else if (s_sd_ok) {
        if (mkdir(DNS2_HOSTED_DIR, 0755) < 0 && errno != EEXIST)
            ESP_LOGE(TAG, "cannot create %s", DNS2_HOSTED_DIR);
        int watch = supervisor_watch(SVC_HOSTED, SUP_TASK, SUP_TASK_MS); /* sup.h */
        int64_t t0 = esp_timer_get_time();
        power_hold(POWER_WORK); /* at the full clock (power.h) */
        boot_load();
        power_release(POWER_WORK);
        supervisor_unwatch(watch);
        ESP_LOGI(TAG, "loaded in %lld ms", (esp_timer_get_time() - t0) / 1000);
    } else {
        bool installed = ota_seq(REL_ZONES) != 0;
        s_state = installed ? ST_FAILED : ST_OFF;
        if (installed)
            set_err("no SD card");
    }
    s_loader = false;
    share_note(SVC_HOSTED, MP_INTERNAL, -LOAD_STACK);
    xSemaphoreGive(s_mu);
    if (done)
        xSemaphoreGive(done);
    vTaskDelete(NULL);
}

void hosted_start(bool sd_in_time)
{
    if (!settings()->hosted) {
        ESP_LOGI(TAG, "off in the node config");
        return;
    }
    s_start_failed = false;
    if (!s_mu)
        s_mu = xSemaphoreCreateMutex(); /* kept once made */
    if (!s_mu) {
        s_enabled = true;
        s_state = ST_FAILED;
        s_start_failed = true;
        set_err("out of memory");
        return;
    }
    if (sd_in_time) {
        /* At boot, before the listeners (no other task yet): wait for the load. */
        s_enabled = true;
        s_sd_ok = true;
        s_state = ST_LOADING;
        s_loader = true;
        SemaphoreHandle_t done = xSemaphoreCreateBinary();
        if (!done || xTaskCreate(load_task, "hosted", LOAD_STACK, done, 2, NULL) != pdPASS) {
            s_loader = false;
            s_state = ST_FAILED;
            s_start_failed = true;
            set_err("could not start");
        } else {
            share_note(SVC_HOSTED, MP_INTERNAL, LOAD_STACK);
            xSemaphoreTake(done, portMAX_DELAY);
        }
        if (done)
            vSemaphoreDelete(done);
        return;
    }
    /* s_enabled under s_mu: a load task from an earlier start, still waiting for the card,
     * decides under it whether to load, so it and this start never both load. */
    xSemaphoreTake(s_mu, portMAX_DELAY);
    s_enabled = true;
    if (sd_state() == SD_NONE || sd_state() == SD_FAILED) {
        bool installed = ota_seq(REL_ZONES) != 0;
        s_state = installed ? ST_FAILED : ST_OFF;
        if (installed)
            set_err("no SD card");
    } else {
        /* Still mounting (or a live start): below the DNS tasks, like the blocking load. A
         * task from an earlier start still waiting for the card does this load. */
        s_state = ST_LOADING;
        if (s_loader) {
            /* the earlier start's task loads */
        } else if (xTaskCreate(load_task, "hosted", LOAD_STACK, NULL, 2, NULL) != pdPASS) {
            s_state = ST_FAILED;
            s_start_failed = true;
            set_err("could not start");
        } else {
            s_loader = true;
            share_note(SVC_HOSTED, MP_INTERNAL, LOAD_STACK);
        }
    }
    xSemaphoreGive(s_mu);
}

void hosted_stop(void)
{
    if (!s_mu) { /* never started, or out of memory at the start: nothing loaded */
        s_enabled = false;
        s_state = ST_OFF;
        s_err[0] = 0;
        return;
    }
    xSemaphoreTake(s_mu, portMAX_DELAY); /* after a load in progress */
    s_enabled = false;
    /* Its names are forwarded from here; no query can still be reading the old set. Their
     * answers were authoritative, never cached: nothing to flush. */
    hz_free(reg_hosted_swap(NULL));
    s_mem = 0;
    hz_free(s_pending);
    s_pending = NULL;
    s_pending_mem = 0;
    s_pending_slot = -1;
    s_state = ST_OFF;
    s_slot = -1;
    s_err[0] = 0;
    s_start_failed = false;
    xSemaphoreGive(s_mu);
    ESP_LOGI(TAG, "off: zones unloaded");
}

bool hosted_broken(void) { return s_enabled && s_start_failed; }

size_t hosted_held(void)
{
    return share_used(SVC_HOSTED, MP_INTERNAL) + share_used(SVC_HOSTED, MP_PSRAM) + s_mem + s_pending_mem;
}

svc_state_t hosted_state(void)
{
    if (!s_enabled)
        return SVC_OFF;
    return s_state == ST_LOADING ? SVC_STARTING : s_state == ST_FAILED ? SVC_FAILED : SVC_RUNNING;
}

/* ---- releases ---- */

bool hosted_kind(uint8_t kind) { return kind == REL_ZONES; }

typedef struct {
    const uint8_t *p;
    size_t off;
} mem_src_t;

static bool mem_recv(void *ctx, uint8_t *buf, size_t n)
{
    mem_src_t *s = ctx;
    memcpy(buf, s->p + s->off, n);
    s->off += n;
    return true;
}

const char *hosted_store(const uint8_t hdr[REL_HEADER_LEN], const rel_manifest_t *m, blk_recv_fn recv, void *ctx)
{
    if (!s_enabled)
        return "hosted zones are off in the node config";
    if (s_state == ST_LOADING)
        return HOSTED_LOADING;
    if (!s_mu)
        return "hosted zones are unavailable (out of memory)";
    if (!s_sd_ok)
        return "no SD card: hosted zones are unavailable";
    if (m->payload_len > limit()) {
        snprintf(s_reply, sizeof(s_reply), "zones bundle of %llu bytes: this board holds %u KB (memory.hosted_zones_kb)",
                 (unsigned long long)m->payload_len, (unsigned)(limit() / 1024));
        return s_reply;
    }
    size_t len = (size_t)m->payload_len;
    uint8_t *buf = malloc(len ? len : 1);
    if (!buf)
        return "out of memory";
    const char *why = NULL;
    uint8_t sha[32];
    hz_set_t *set = NULL;
    char err[160];
    if (!recv(ctx, buf, len)) {
        why = "receive failed";
    } else if (mbedtls_sha256(buf, len, sha, 0) != 0 || memcmp(sha, m->sha256, 32) != 0) {
        why = "payload does not match the signed hash";
    } else if (hz_parse(buf, len, limit(), &set, err, sizeof(err)) != NULL) {
        snprintf(s_reply, sizeof(s_reply), "zones refused: %s", err);
        why = s_reply;
    } else {
        int c = hz_clash(set, settings());
        if (c >= 0) {
            char n[256];
            dns_name_to_str(set->z[c]->apex, n, sizeof(n));
            snprintf(s_reply, sizeof(s_reply), "zones refused: %s is a secondary or forward zone in the node config", n);
            why = s_reply;
        }
    }
    if (!why) {
        xSemaphoreTake(s_mu, portMAX_DELAY);
        if (s_state == ST_LOADING) {
            why = HOSTED_LOADING;
        } else {
            if (mkdir(DNS2_HOSTED_DIR, 0755) < 0 && errno != EEXIST)
                ESP_LOGE(TAG, "cannot create %s", DNS2_HOSTED_DIR);
            char path[64];
            int slot = s_slot == 0 ? 1 : 0; /* never the one in use */
            slot_path(slot, path, sizeof(path));
            mem_src_t src = { buf, 0 };
            why = blk_slot_store(path, hdr, m, mem_recv, &src);
            if (!why) {
                hz_free(s_pending);
                s_pending = set;
                s_pending_mem = set->mem;
                s_pending_slot = slot;
                set = NULL;
            }
        }
        xSemaphoreGive(s_mu);
    }
    hz_free(set);
    free(buf);
    return why;
}

const char *hosted_apply(const rel_manifest_t *m, char *msg, size_t cap, bool *reboot)
{
    *reboot = false;
    if (!s_mu)
        return "nothing stored to apply";
    xSemaphoreTake(s_mu, portMAX_DELAY);
    hz_set_t *s = s_pending;
    int slot = s_pending_slot;
    s_pending = NULL;
    s_pending_mem = 0;
    if (s) {
        /* A revert in force ends with a newer bundle taken. */
        if (blocking_rev_get(REL_ZONES))
            blocking_rev_set(REL_ZONES, 0);
        s_err[0] = 0;
        activate(s, slot, m);
        unsigned recs = 0;
        for (int i = 0; i < s->n; i++)
            recs += (unsigned)s->z[i]->n;
        snprintf(msg, cap, "ok, zones seq %llu applied: %d zones, %u records, %u of %u KB\n",
                 (unsigned long long)m->seq, s->n, recs, (unsigned)((s->mem + 1023) / 1024),
                 (unsigned)(limit() / 1024));
    }
    xSemaphoreGive(s_mu);
    return s ? NULL : "nothing stored to apply";
}

/* ---- revert (BLK_CTL_REVERT with REL_ZONES, through blocking.c) ---- */

/* Why the zones can't go back to the bundle in the other slot, or NULL; with m, that slot's
 * header. Under s_mu. */
static const char *revert_why(rel_manifest_t *m)
{
    if (s_state != ST_ON) {
        snprintf(s_reply, sizeof(s_reply), "no zones in use: nothing to revert from");
        return s_reply;
    }
    rel_manifest_t om;
    int other = 1 - s_slot;
    const char *why = slot_header(other, &om);
    why = blk_revert_check("zones", other, why, why ? 0 : om.seq, s_seq, s_reverted, "newer", s_reply,
                           sizeof(s_reply));
    if (!why && m)
        *m = om;
    return why;
}

/* Refused before the lock: the service off, never started, or the boot load waiting for the
 * card or running (it holds s_mu for seconds; a 503, as a push's). */
static const char *revert_unavailable(void)
{
    if (!s_enabled)
        return settings()->hosted ? HOSTED_LOADING : "hosted zones are off in the node config";
    if (s_state == ST_LOADING)
        return HOSTED_LOADING;
    if (!s_mu)
        return "hosted zones are unavailable (out of memory)";
    if (!s_sd_ok)
        return "no SD card: hosted zones are unavailable";
    return NULL;
}

const char *hosted_revert_check(void)
{
    const char *why = revert_unavailable();
    if (why)
        return why;
    xSemaphoreTake(s_mu, portMAX_DELAY);
    why = s_state == ST_LOADING ? HOSTED_LOADING : revert_why(NULL);
    xSemaphoreGive(s_mu);
    return why;
}

const char *hosted_revert(char *msg, size_t cap)
{
    const char *why = revert_unavailable();
    if (why)
        return why;
    xSemaphoreTake(s_mu, portMAX_DELAY);
    rel_manifest_t m;
    hz_set_t *set = NULL;
    uint64_t from = s_seq;
    int slot = 1 - s_slot;
    char err[160];
    why = s_state == ST_LOADING ? HOSTED_LOADING : revert_why(&m);
    /* It has sat on the card since it was written: checked in full again, as a boot does. */
    if (!why && (why = slot_load(slot, &m, &set, err, sizeof(err))) != NULL) {
        snprintf(s_reply, sizeof(s_reply), "zones seq %llu in slot %d not usable: %s", (unsigned long long)m.seq, slot,
                 why);
        why = s_reply;
    }
    /* Recorded first, so whatever boot comes next keeps to it. */
    if (!why && !blocking_rev_set(REL_ZONES, from))
        why = "could not record the revert";
    if (why) {
        hz_free(set);
        ESP_LOGE(TAG, "revert to slot %d not applied: %s", slot, why);
    } else {
        s_err[0] = 0;
        drop_clashes(set);
        activate(set, slot, &m);
        s_reverted = from;
        unsigned recs = 0;
        for (int i = 0; i < set->n; i++)
            recs += (unsigned)set->z[i]->n;
        snprintf(msg, cap, "ok, zones reverted to seq %llu (slot %d) from seq %llu: %d zones, %u records\n",
                 (unsigned long long)m.seq, slot, (unsigned long long)from, set->n, recs);
        ESP_LOGW(TAG, "reverted to seq %llu from seq %llu", (unsigned long long)m.seq, (unsigned long long)from);
    }
    xSemaphoreGive(s_mu);
    return why;
}

const char *hosted_clash(const cfg_t *c, char *buf, size_t cap)
{
    if (!c->hosted)
        return NULL; /* turned off by this config: nothing is hosted then */
    const char *why = NULL;
    reg_rdlock();
    const hz_set_t *s = reg_hosted();
    int i = hz_clash(s, c);
    if (i >= 0) {
        char n[256];
        dns_name_to_str(s->z[i]->apex, n, sizeof(n));
        snprintf(buf, cap, "%s is a hosted zone: a zone has one source", n);
        why = buf;
    }
    reg_unlock();
    return why;
}

/* ---- health ---- */

bool hosted_degraded(void) { return s_enabled && (s_state == ST_FAILED || (s_state == ST_ON && s_err[0])); }

bool hosted_older(void) { return s_enabled && s_state == ST_ON && s_older[0]; }

static void sha_hex(char out[65])
{
    out[0] = 0;
    if (s_state == ST_ON)
        for (int i = 0; i < 32; i++)
            sprintf(out + 2 * i, "%02x", s_sha[i]);
}

size_t hosted_health_json(char *j, size_t cap)
{
    char sha[65];
    sha_hex(sha);
    int n = snprintf(j, cap, "\"zones\":{\"state\":\"%s\",\"seq\":%llu,\"sha256\":\"%s\"}", ST_NAME[s_state],
                     (unsigned long long)(s_state == ST_ON ? s_seq : 0), sha);
    return n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap - 1;
}

/* The object with s_err, the fallback and the numbers at their longest (800 bytes), and each
 * zone with its name at its longest (apex_len: the wire name, a byte longer than its text)
 * and the numbers at theirs. */
#define STATUS_HEAD 832
#define STATUS_ZONE 64

size_t hosted_status_max(void)
{
    size_t n = STATUS_HEAD;
    reg_rdlock();
    const hz_set_t *s = reg_hosted();
    for (int i = 0; s && i < s->n; i++)
        n += STATUS_ZONE + (size_t)s->z[i]->apex_len;
    reg_unlock();
    return n;
}

size_t hosted_status_json(char *j, size_t cap)
{
    char sha[65], older[2 * sizeof(s_older) + 3], err[2 * sizeof(s_err) + 3];
    sha_hex(sha);
    bool on = s_state == ST_ON;
    reg_rdlock();
    const hz_set_t *s = reg_hosted();
    size_t n = (size_t)snprintf(j, cap,
                                "\"hosted\":{\"state\":\"%s\",\"seq\":%llu,\"sha256\":\"%s\",\"slot\":%d,"
                                "\"reverted_from\":%llu,\"bytes\":%u,\"limit_bytes\":%u,\"fallback\":%s,"
                                "\"error\":%s,\"zones\":[",
                                ST_NAME[s_state], (unsigned long long)(on ? s_seq : 0), sha, on ? s_slot : -1,
                                (unsigned long long)(on ? s_reverted : 0), (unsigned)(s ? s->mem : 0), (unsigned)limit(),
                                json_qz(older, sizeof(older), on ? s_older : NULL), json_qz(err, sizeof(err), s_err));
    for (int i = 0; s && i < s->n && n < cap; i++) {
        char name[256], q[2 * sizeof(name) + 3];
        dns_name_to_str(s->z[i]->apex, name, sizeof(name));
        n += (size_t)snprintf(j + n, cap - n, "%s{\"name\":%s,\"serial\":%lu,\"records\":%u}", i ? "," : "",
                              json_q(q, sizeof(q), name),
                              (unsigned long)s->z[i]->serial, (unsigned)s->z[i]->n);
    }
    reg_unlock();
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, "]}");
    return n < cap ? n : cap - 1;
}
