#include "settings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "board.h"
#include "clock.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hosted.h"
#include "jsonw.h"
#include "mbedtls/sha256.h"
#include "net.h"
#include "nvs.h"
#include "ota.h"
#include "power.h"
#include "querylog.h"
#include "reboot.h"
#include "server.h"
#include "services.h"
#include "share.h"

static const char *TAG = "settings";

#define NVS_NS    "espdns_cfg" /* slots, on a node without a config partition */
#define STATE_NS  "espdns"     /* trial and refused seqs, next to the release seqs */
#define KEY_TRIAL "cfgtrial"
#define KEY_BAD   "cfgbad"

static cfg_t *s_run;     /* never freed: zone names in it are used by the registry */
static cfg_t *s_pending; /* stored by settings_store, used by settings_apply */
static uint64_t s_pending_seq;
static int s_pending_slot;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED; /* the live settings */

static const esp_partition_t *s_part; /* NULL: slots in NVS */
static int s_slot = -1;               /* the slot in use, -1: defaults */
static uint64_t s_seq;
static bool s_trial;
static char s_err[224];
static char s_reply[160];

const cfg_t *settings(void) { return s_run; }
const char *settings_error(void) { return s_err[0] ? s_err : NULL; }
bool settings_on_trial(void) { return s_trial; }
bool settings_adopted(void) { return s_slot >= 0; }

int settings_forwarders(uint32_t *out, int *timeout_ms)
{
    taskENTER_CRITICAL(&s_mux);
    int n = s_run->nfwd;
    memcpy(out, s_run->fwd, sizeof(uint32_t) * (size_t)n);
    *timeout_ms = s_run->upstream_timeout_ms;
    taskEXIT_CRITICAL(&s_mux);
    return n;
}

/* ---- NVS state ---- */

static uint64_t state_get(const char *key)
{
    uint64_t v = 0;
    nvs_handle_t h;
    if (nvs_open(STATE_NS, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u64(h, key, &v);
        nvs_close(h);
    }
    return v;
}

static bool state_set(const char *key, uint64_t v)
{
    nvs_handle_t h;
    if (nvs_open(STATE_NS, NVS_READWRITE, &h) != ESP_OK)
        return false;
    esp_err_t e = v ? nvs_set_u64(h, key, v) : nvs_erase_key(h, key);
    bool ok = (e == ESP_OK || (!v && e == ESP_ERR_NVS_NOT_FOUND)) && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

/* ---- slots: the release header, then the payload ---- */

static size_t slot_cap(void) { return s_part ? CFG_JSON_MAX : SETTINGS_NVS_MAX; }

/* Reads slot i into buf (CFG_SLOT_SIZE bytes): the header and as much payload as its
 * (not yet verified) length says. Returns the payload bytes read, or -1. */
static int slot_read(int i, uint8_t *buf)
{
    if (s_part) {
        if (esp_partition_read(s_part, (size_t)i * CFG_SLOT_SIZE, buf, REL_HEADER_LEN) != ESP_OK)
            return -1;
        uint64_t len = 0;
        for (int b = 7; b >= 0; b--)
            len = len << 8 | buf[40 + b];
        if (len == 0 || len > CFG_JSON_MAX)
            return -1;
        if (esp_partition_read(s_part, (size_t)i * CFG_SLOT_SIZE + REL_HEADER_LEN, buf + REL_HEADER_LEN, (size_t)len) != ESP_OK)
            return -1;
        return (int)len;
    }
    nvs_handle_t h;
    char key[16];
    snprintf(key, sizeof(key), "slot%d", i);
    size_t n = CFG_SLOT_SIZE;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK)
        return -1;
    esp_err_t e = nvs_get_blob(h, key, buf, &n);
    nvs_close(h);
    return e == ESP_OK && n > REL_HEADER_LEN ? (int)(n - REL_HEADER_LEN) : -1;
}

/* Writes slot i: payload first, header last, so a slot cut short by a power cut has no
 * header (erased flash) and is never taken for a config. */
static const char *slot_write(int i, const uint8_t *buf, size_t payload_len)
{
    if (s_part) {
        size_t off = (size_t)i * CFG_SLOT_SIZE;
        if (esp_partition_erase_range(s_part, off, CFG_SLOT_SIZE) != ESP_OK ||
            esp_partition_write(s_part, off + REL_HEADER_LEN, buf + REL_HEADER_LEN, payload_len) != ESP_OK ||
            esp_partition_write(s_part, off, buf, REL_HEADER_LEN) != ESP_OK)
            return "could not write the config partition";
        return NULL;
    }
    nvs_handle_t h;
    char key[16];
    snprintf(key, sizeof(key), "slot%d", i);
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK)
        return "could not open NVS";
    esp_err_t e = nvs_set_blob(h, key, buf, REL_HEADER_LEN + payload_len);
    if (e == ESP_OK)
        e = nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? NULL : "could not write the config to NVS";
}

/* ---- boot ---- */

/* Loads slot i into s_run if it is valid and this firmware takes it. */
static const char *try_slot(int i, uint8_t *buf)
{
    int len = slot_read(i, buf);
    if (len < 0)
        return "unreadable";
    rel_manifest_t m;
    const char *why = cfg_slot_check(buf, buf + REL_HEADER_LEN, (size_t)len, ota_trust(), &m);
    if (why)
        return why;
    char err[96];
    if (!cfg_build(s_run, &board, (const char *)buf + REL_HEADER_LEN, (size_t)m.payload_len, err, sizeof(err))) {
        snprintf(s_err, sizeof(s_err), "config seq %llu refused: %s", (unsigned long long)m.seq, err);
        return s_err;
    }
    /* Its services must fit the board before any of them starts (memplan.h): a plan that
     * doesn't never half-starts, the older config runs instead. */
    if (!share_check(s_run, err, sizeof(err))) {
        snprintf(s_err, sizeof(s_err), "config seq %llu refused: memory plan: %s", (unsigned long long)m.seq, err);
        cfg_build(s_run, &board, NULL, 0, err, sizeof(err));
        return s_err;
    }
    s_slot = i;
    s_seq = m.seq;
    return NULL;
}

void settings_load(void)
{
    s_run = calloc(1, sizeof(cfg_t));
    if (!s_run) {
        ESP_LOGE(TAG, "out of memory");
        abort();
    }
    char err[96];
    cfg_build(s_run, &board, NULL, 0, err, sizeof(err)); /* defaults and board */

    s_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "config");
    if (s_part && s_part->size < 2 * CFG_SLOT_SIZE) {
        ESP_LOGE(TAG, "config partition too small (%lu bytes): config in NVS", (unsigned long)s_part->size);
        s_part = NULL;
    }
    uint8_t *buf = malloc(CFG_SLOT_SIZE);
    if (!buf) {
        ESP_LOGE(TAG, "out of memory: firmware defaults");
        return;
    }
    /* Order by the (unverified) seqs; only the slot used is fully checked. */
    bool ok[2];
    uint64_t seq[2];
    for (int i = 0; i < 2; i++) {
        uint8_t hdr[REL_HEADER_LEN];
        ok[i] = false;
        seq[i] = 0;
        if (s_part) {
            ok[i] = esp_partition_read(s_part, (size_t)i * CFG_SLOT_SIZE, hdr, sizeof(hdr)) == ESP_OK;
        } else {
            ok[i] = slot_read(i, buf) >= 0;
            memcpy(hdr, buf, sizeof(hdr));
        }
        ok[i] = ok[i] && memcmp(hdr, "ESPDNS1", 8) == 0 && hdr[8] == REL_CONFIG;
        for (int b = 7; ok[i] && b >= 0; b--)
            seq[i] = seq[i] << 8 | hdr[32 + b];
    }
    /* A slot whose seq was never recorded (a power cut, or a failed push, between writing it
     * and recording the seq) was never accepted: not used. */
    uint64_t committed = ota_seq(REL_CONFIG);
    for (int i = 0; i < 2; i++)
        if (ok[i] && seq[i] > committed) {
            ESP_LOGW(TAG, "config slot %d: seq %llu never recorded: not used", i, (unsigned long long)seq[i]);
            ok[i] = false;
        }
    uint64_t bad = state_get(KEY_BAD);
    int other, first = cfg_slot_pick(ok, seq, bad, &other);
    for (int k = 0; k < 2 && s_slot < 0; k++) {
        int i = k ? other : first;
        if (i < 0)
            break;
        const char *why = try_slot(i, buf);
        if (why) {
            if (why != s_err)
                snprintf(s_err, sizeof(s_err), "config slot %d: %s", i, why);
            ESP_LOGE(TAG, "%s", s_err);
        }
    }
    free(buf);
    for (char *e = s_err; *e; e++) /* it goes into /status as a JSON string */
        if (*e == '"' || *e == '\\' || (unsigned char)*e < 0x20)
            *e = '\'';
    if (s_slot >= 0 && bad && s_seq != bad)
        ESP_LOGW(TAG, "config seq %llu failed its trial earlier: not used", (unsigned long long)bad);
    /* Running an older config than the one that failed: degraded until a newer one is in. */
    if (s_slot >= 0 && bad > s_seq && !s_err[0])
        snprintf(s_err, sizeof(s_err), "config seq %llu failed its trial: running seq %llu", (unsigned long long)bad,
                 (unsigned long long)s_seq);
    if (s_slot < 0 && bad && !s_err[0])
        snprintf(s_err, sizeof(s_err), "config seq %llu failed its trial: firmware defaults", (unsigned long long)bad);
    if (s_slot >= 0 && s_err[0])
        ESP_LOGW(TAG, "fell back to the older config");
    s_trial = s_slot >= 0 && s_seq == state_get(KEY_TRIAL);
    /* The firmware defaults have nothing to fall back to: they run, and say so. Only a board
     * definition with values its memory can't hold gets here. */
    if (s_slot < 0 && !share_check(s_run, err, sizeof(err))) {
        ESP_LOGE(TAG, "firmware defaults don't fit this board: memory plan: %s", err);
        if (!s_err[0]) /* a refused config's reason comes first */
            snprintf(s_err, sizeof(s_err), "firmware defaults don't fit this board: memory plan: %s", err);
    }
    share_set_plan(svc_enabled(s_run));
    if (s_slot < 0)
        ESP_LOGI(TAG, "no node config: defaults (%s address, from the %s)", cfg_addr_kind(s_run),
                 cfg_addr_from(s_run));
    else
        ESP_LOGI(TAG, "config seq %llu from %s slot %d%s", (unsigned long long)s_seq, s_part ? "partition" : "NVS",
                 s_slot, s_trial ? ", on trial" : "");
}

/* ---- releases ---- */

const char *settings_store(const uint8_t hdr[REL_HEADER_LEN], const rel_manifest_t *m, settings_recv_fn recv,
                           void *ctx)
{
    if (m->payload_len == 0 || m->payload_len > slot_cap()) {
        snprintf(s_reply, sizeof(s_reply), "config too big: %u bytes at most on this node", (unsigned)slot_cap());
        return s_reply;
    }
    size_t len = (size_t)m->payload_len;
    uint8_t *buf = malloc(REL_HEADER_LEN + len + 1);
    cfg_t *c = calloc(1, sizeof(cfg_t));
    const char *why = NULL;
    uint8_t sha[32];
    char err[96];
    if (!buf || !c) {
        why = "out of memory";
    } else if (!recv(ctx, buf + REL_HEADER_LEN, len)) {
        why = "receive failed";
    } else if (mbedtls_sha256(buf + REL_HEADER_LEN, len, sha, 0) != 0 || memcmp(sha, m->sha256, 32) != 0) {
        why = "payload does not match the signed hash";
    } else if (!cfg_build(c, &board, (const char *)buf + REL_HEADER_LEN, len, err, sizeof(err))) {
        snprintf(s_reply, sizeof(s_reply), "config refused: %s", err);
        why = s_reply;
    } else if (hosted_clash(c, err, sizeof(err)) != NULL) {
        snprintf(s_reply, sizeof(s_reply), "config refused: %s", err);
        why = s_reply;
    } else if (!share_check(c, err, sizeof(err))) {
        snprintf(s_reply, sizeof(s_reply), "config refused: memory plan: %s", err);
        why = s_reply;
    } else if (memcmp(m->target, ota_trust()->node_id, 6) != 0) {
        why = "a config is for one node, not any node";
    } else if (cfg_net_changed(s_run, c) && !state_set(KEY_TRIAL, m->seq)) {
        /* The trial is armed before the slot is written: whatever cuts this push short, a
         * config with a new address never boots without it. */
        why = "could not record the config trial";
    } else {
        memcpy(buf, hdr, REL_HEADER_LEN);
        int slot = s_slot == 0 ? 1 : 0; /* never the slot in use */
        /* A config pending a reboot is in that slot: from here it is gone. */
        ota_reboot_update(RB_CONFIG, 0);
        why = slot_write(slot, buf, len);
        if (!why) {
            free(s_pending);
            s_pending = c;
            s_pending_seq = m->seq;
            s_pending_slot = slot;
            c = NULL;
        }
    }
    free(buf);
    free(c);
    return why;
}

const char *settings_apply(const rel_manifest_t *m, char *msg, size_t cap, bool *reboot)
{
    *reboot = false;
    if (!s_pending || s_pending_seq != m->seq)
        return "no stored config";
    uint32_t why = cfg_reboot_reasons(s_run, s_pending);
    if (why) {
        /* Stored and its seq recorded: whichever boot comes next (the controller's reboot, or
         * a power cut) runs it, on trial if the address or the network changes. Until then
         * the node serves on the config it runs. */
        *reboot = true;
        bool trial = (why & (RB_CONFIG_ADDRESS | RB_CONFIG_WIFI)) != 0;
        state_set(KEY_TRIAL, trial ? m->seq : 0);
        ota_reboot_update(RB_CONFIG, why);
        snprintf(msg, cap, "ok, config seq %llu stored; applies at the next reboot%s\n", (unsigned long long)m->seq,
                 trial ? " (trial then: a DNS query must reach its new address within 90 s)" : "");
    } else {
        uint32_t before = svc_enabled(s_run);
        taskENTER_CRITICAL(&s_mux);
        cfg_copy_live(s_run, s_pending);
        taskEXIT_CRITICAL(&s_mux);
        s_slot = s_pending_slot;
        s_seq = m->seq;
        s_err[0] = 0;
        state_set(KEY_TRIAL, 0);
        ota_reboot_update(RB_CONFIG, 0);
        net_apply_live(); /* the resolver first: new NTP names resolve through it */
        clock_apply();
        power_apply(); /* clock scaling */
        services_apply(before, svc_enabled(s_run)); /* forwarding, hosted zones, blocking, the query log */
        querylog_apply();                           /* a stricter client setting: what it holds */
        snprintf(msg, cap, "ok, config seq %llu applied live\n", (unsigned long long)m->seq);
    }
    ESP_LOGI(TAG, "%s", msg);
    free(s_pending);
    s_pending = NULL;
    return NULL;
}

/* ---- trial ---- */

static void trial_task(void *arg)
{
    const uint64_t seq = s_seq;
    for (int t = 0; t < SETTINGS_TRIAL_S; t++) {
        /* A later push (it reached the node, so the address works) took the trial over or
         * ended it: leave it to that one. */
        if (state_get(KEY_TRIAL) != seq) {
            s_trial = false;
            vTaskDelete(NULL);
        }
        server_stats_t st;
        server_get_stats(&st);
        if (net_ip() && server_running() && st.queries) {
            state_set(KEY_TRIAL, 0);
            s_trial = false;
            ESP_LOGI(TAG, "config seq %llu confirmed: reached on its address after %d s", (unsigned long long)seq, t);
            vTaskDelete(NULL);
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    ESP_LOGE(TAG, "config seq %llu: not reached within %d s: back to the previous config", (unsigned long long)seq,
             SETTINGS_TRIAL_S);
    /* KEY_TRIAL stays: if KEY_BAD can't be written, the next boot is on trial again rather
     * than kept for good. The boot skips the bad seq, so a stale trial seq does nothing. */
    state_set(KEY_BAD, seq);
    /* The one reboot the node decides on by itself: unreachable on this config, it can't
     * be rebooted from the controller. */
    ota_reboot_after(0);
    vTaskDelete(NULL);
}

void settings_confirm_when_healthy(void)
{
    if (s_trial)
        xTaskCreate(trial_task, "cfg_trial", 3072, NULL, 4, NULL);
}

/* ---- status ---- */

size_t settings_status_json(char *j, size_t cap)
{
    const char *err = settings_error();
    char name[2 * CFG_NAME_MAX + 3], e[2 * sizeof(s_err) + 3];
    /* The static address as set (prefix length and gateway, which /status "ip" lacks), so a
     * controller can adopt a node on the address it already has. */
    char addr[64] = "";
    if (s_run->ip) {
        const uint8_t *a = (const uint8_t *)&s_run->ip, *g = (const uint8_t *)&s_run->gateway;
        snprintf(addr, sizeof(addr), ",\"ip\":\"%u.%u.%u.%u/%d\",\"gateway\":\"%u.%u.%u.%u\"", a[0], a[1], a[2],
                 a[3], __builtin_popcount(s_run->netmask), g[0], g[1], g[2], g[3]);
    }
    int n = snprintf(j, cap,
                     "\"config\":{\"source\":\"%s\",\"seq\":%llu,\"slot\":%d,\"storage\":\"%s\",\"trial\":%s,"
                     "\"name\":%s,\"address\":\"%s\",\"address_from\":\"%s\"%s,\"error\":%s}",
                     s_slot >= 0 ? "node" : "defaults", (unsigned long long)(s_slot >= 0 ? s_seq : 0), s_slot,
                     s_part ? "partition" : "nvs", s_trial ? "true" : "false", json_q(name, sizeof(name), s_run->name),
                     cfg_addr_kind(s_run), cfg_addr_from(s_run), addr, json_q(e, sizeof(e), err));
    return n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap - 1;
}
