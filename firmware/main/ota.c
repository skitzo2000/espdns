#include "ota.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "blocking.h"
#include "board.h"
#include "boot.h"
#include "clock.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_mac.h"
#include "health_node.h"
#include "hosted.h"
#include "httpguard.h"
#include "jsonw.h"
#include "led.h"
#include "mbedtls/sha256.h"
#include "net.h"
#include "nvs.h"
#include "metrics_node.h"
#include "power.h"
#include "querylog.h"
#include "reboot.h"
#include "registry.h"
#include "release.h"
#include "sd.h"
#include "server.h"
#include "services.h"
#include "settings.h"
#include "share.h"

static const char *TAG = "ota";

/* Public keys this node trusts (keys/release.pub, keys/recovery.pub: raw P-256 points). */
extern const uint8_t release_pub_start[] asm("_binary_release_pub_start");
extern const uint8_t release_pub_end[] asm("_binary_release_pub_end");
extern const uint8_t recovery_pub_start[] asm("_binary_recovery_pub_start");
extern const uint8_t recovery_pub_end[] asm("_binary_recovery_pub_end");

#ifdef DNS2_BENCH_BLOCKLIST
#include "bench_http.h"
/* A bench build never passes: it rolls back by itself after this long. */
#define HEALTH_TIMEOUT_S 600
#else
#define HEALTH_TIMEOUT_S 90
#endif
#define CHUNK            4096
#define SEQ_NS           "espdns"

static rel_trust_t s_trust;
static char s_key_fp[REL_NKEYS][17]; /* first 8 bytes of SHA-256(public key), hex */

static volatile bool s_busy;

/* Takes the right to receive a release (or, for the reboot, to stop the node); false if
 * another holder has it. */
/* A release being received, verified and applied holds the full clock (power.h): the SHA-256
 * and the flash or SD writes keep pace with the network, and a list's live load runs at
 * speed. */
static bool busy_take(void)
{
    if (__atomic_exchange_n(&s_busy, true, __ATOMIC_ACQ_REL))
        return false;
    power_hold(POWER_WORK);
    return true;
}

static void busy_give(void)
{
    power_release(POWER_WORK);
    __atomic_store_n(&s_busy, false, __ATOMIC_RELEASE);
}

static bool peer_is_private(httpd_req_t *req)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getpeername(httpd_req_to_sockfd(req), (struct sockaddr *)&ss, &sl) < 0)
        return false;
    uint32_t a;
    if (ss.ss_family == AF_INET) {
        a = ntohl(((struct sockaddr_in *)&ss)->sin_addr.s_addr);
    } else if (ss.ss_family == AF_INET6) {
        /* httpd listens on IPv6; IPv4 peers arrive as ::ffff:a.b.c.d */
        const uint8_t *b = (const uint8_t *)&((struct sockaddr_in6 *)&ss)->sin6_addr;
        static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        if (memcmp(b, mapped, 12) != 0)
            return false;
        a = (uint32_t)b[12] << 24 | (uint32_t)b[13] << 16 | (uint32_t)b[14] << 8 | b[15];
    } else {
        return false;
    }
    return (a >> 24) == 10 || (a >> 20) == (172 << 4 | 1) || (a >> 16) == (192 << 8 | 168) ||
           (a >> 22) == (100 << 2 | 1);
}

bool ota_peer_private(httpd_req_t *req) { return peer_is_private(req); }

/* ---- reboot pending ---- */

#define REBOOT_MIN_MS 500 /* lets the HTTP reply go out */

static rb_state_t s_rb;
static portMUX_TYPE s_rb_mux = portMUX_INITIALIZER_UNLOCKED;
static int64_t s_reboot_at; /* esp_timer µs; 0: none scheduled */

static uint32_t uptime_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

void ota_reboot_update(uint32_t mask, uint32_t set)
{
    taskENTER_CRITICAL(&s_rb_mux);
    uint32_t was = s_rb.reasons;
    rb_update(&s_rb, mask, set, uptime_s());
    uint32_t now = s_rb.reasons;
    taskEXIT_CRITICAL(&s_rb_mux);
    for (int i = 0; i < RB_NBITS; i++) {
        uint32_t b = 1u << i;
        if ((now & b) && !(was & b))
            ESP_LOGW(TAG, "reboot pending: %s", rb_reason_name(b));
        else if (!(now & b) && (was & b))
            ESP_LOGI(TAG, "no longer pending a reboot: %s", rb_reason_name(b));
    }
}

uint32_t ota_reboot_reasons(void) { return s_rb.reasons; }

static int64_t reboot_at(void)
{
    taskENTER_CRITICAL(&s_rb_mux);
    int64_t at = s_reboot_at;
    taskEXIT_CRITICAL(&s_rb_mux);
    return at;
}

bool ota_rebooting(void) { return reboot_at() != 0; }

static void reboot_task(void *arg)
{
    /* In short steps: a sooner reboot may be asked for meanwhile. */
    while (reboot_at() > esp_timer_get_time())
        vTaskDelay(pdMS_TO_TICKS(100));
    /* Not in the middle of receiving a release: wait for it, and take the slot so no new
     * one starts. */
    while (!busy_take())
        vTaskDelay(pdMS_TO_TICKS(100));
    ESP_LOGW(TAG, "rebooting%s", s_rb.reasons ? " to apply what is pending" : "");
    esp_restart();
}

void ota_reboot_after(uint32_t delay_ms)
{
    if (delay_ms < REBOOT_MIN_MS)
        delay_ms = REBOOT_MIN_MS;
    int64_t at = esp_timer_get_time() + (int64_t)delay_ms * 1000;
    taskENTER_CRITICAL(&s_rb_mux);
    int64_t was = s_reboot_at;
    if (!was || at < was)
        s_reboot_at = at;
    taskEXIT_CRITICAL(&s_rb_mux);
    if (was && was <= at)
        return; /* sooner already */
    ESP_LOGW(TAG, "reboot in %lu ms", (unsigned long)delay_ms);
    if (!was && xTaskCreate(reboot_task, "reboot", 2048, NULL, 10, NULL) != pdPASS) {
        ESP_LOGE(TAG, "reboot task failed to start: rebooting now");
        esp_restart();
    }
}

/* A success reply to a release: {"ok":true,"message":"...","reboot_pending":b,"rebooting":b}.
 * reboot_pending is the node's (a reboot would apply something), not only this release's. */
static esp_err_t reply_ok(httpd_req_t *req, const char *msg)
{
    ota_http_reply(req);
    char m[192], e[400], j[512];
    size_t len = (size_t)snprintf(m, sizeof(m), "%s", msg);
    if (len && len < sizeof(m) && m[len - 1] == '\n') /* the line's newline is not part of the message */
        m[len - 1] = 0;
    json_esc(e, sizeof(e), m);
    size_t n = (size_t)snprintf(j, sizeof(j), "{\"ok\":true,\"message\":\"%s\",\"reboot_pending\":%s,\"rebooting\":%s}\n",
                                e, ota_reboot_reasons() ? "true" : "false", ota_rebooting() ? "true" : "false");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, j, (ssize_t)(n < sizeof(j) ? n : sizeof(j) - 1));
}

static esp_err_t fail(httpd_req_t *req, const char *status, const char *msg)
{
    ESP_LOGW(TAG, "update rejected: %s", msg);
    ota_http_reply(req);
    httpd_resp_set_status(req, status);
    httpd_resp_sendstr(req, msg);
    return ESP_OK;
}

/* A release refused before its payload (its checks or its signed header): fail, for a
 * head handler (false: refused, the reply sent). */
static bool head_fail(httpd_req_t *req, const char *status, const char *msg)
{
    fail(req, status, msg);
    return false;
}

/* Highest seq applied per release kind, kept in NVS so a replay is refused after reboot. */
static uint64_t seq_get(uint8_t kind)
{
    char key[8];
    uint64_t v = 0;
    nvs_handle_t h;
    snprintf(key, sizeof(key), "seq%u", kind);
    if (nvs_open(SEQ_NS, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u64(h, key, &v);
        nvs_close(h);
    }
    return v;
}

static bool seq_set(uint8_t kind, uint64_t v)
{
    char key[8];
    nvs_handle_t h;
    snprintf(key, sizeof(key), "seq%u", kind);
    if (nvs_open(SEQ_NS, NVS_READWRITE, &h) != ESP_OK)
        return false;
    bool ok = nvs_set_u64(h, key, v) == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

/* The highest seq this node takes now (rel_seq_limit, issue #55): its clock plus 24 h once
 * SNTP set it; no limit before that. */
static uint64_t seq_limit(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return rel_seq_limit(clock_synced(), (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000);
}

/* why, as the reply says it: a seq too far ahead names the limit. */
static void why_msg(char *msg, size_t cap, const char *why, uint64_t seq, uint64_t limit)
{
    if (why == rel_why_ahead)
        snprintf(msg, cap, "seq %llu too far ahead: this node takes up to %llu (its clock and 24 h)\n",
                 (unsigned long long)seq, (unsigned long long)limit);
    else
        snprintf(msg, cap, "%s\n", why);
}

/* The built-in keys and who this node is. Needed before ota_start: the settings check
 * their stored config at boot. */
static void trust_init(void)
{
    if (s_trust.board)
        return;
    const uint8_t *keys[REL_NKEYS][2] = { { release_pub_start, release_pub_end },
                                          { recovery_pub_start, recovery_pub_end } };
    for (int i = 0; i < REL_NKEYS; i++) {
        uint8_t h[32];
        bool ok = keys[i][1] - keys[i][0] == REL_PUBKEY_LEN && keys[i][0][0] == 0x04;
        s_trust.keys[i] = ok ? keys[i][0] : NULL;
        if (ok) {
            mbedtls_sha256(keys[i][0], REL_PUBKEY_LEN, h, 0);
            for (int j = 0; j < 8; j++)
                sprintf(s_key_fp[i] + 2 * j, "%02x", h[j]);
        } else {
            ESP_LOGE(TAG, "built-in public key %d is malformed: releases signed with it are refused", i);
        }
    }
    esp_efuse_mac_get_default(s_trust.node_id);
    s_trust.board_alt = board_fallback_name()[0] ? board_fallback_name() : NULL;
    s_trust.board = board_image();
}

const rel_trust_t *ota_trust(void)
{
    trust_init();
    return &s_trust;
}

uint64_t ota_seq(uint8_t kind) { return seq_get(kind); }

bool ota_busy(void) { return s_busy; }

/* Receives n bytes of the body, within the request's deadline (httpguard.h: the connection's
 * receive waits until then, never longer); false if the client closed, failed or ran out
 * of time. */
static bool recv_all(httpd_req_t *req, uint8_t *p, size_t n)
{
    while (n) {
        int r = httpd_req_recv(req, (char *)p, n);
        if (r <= 0)
            return false;
        p += r;
        n -= (size_t)r;
    }
    return true;
}

/* Selects the running firmware for the next boot again if another image is selected.
 * esp_ota_set_boot_partition() writes the entry as a new image (ESP_OTA_IMG_NEW with
 * rollback on): left so, the next boot would put this firmware on trial again, and a failed
 * health check would roll "back" to the other slot, which the upload is erasing. This
 * firmware is confirmed (an image can't be received while it is on trial), so the entry is
 * marked valid at once. */
static bool unstage(void)
{
    const esp_partition_t *run = esp_ota_get_running_partition(), *boot = esp_ota_get_boot_partition();
    if (boot && boot != run) {
        esp_ota_img_states_t st;
        if (esp_ota_get_state_partition(run, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY)
            return false; /* not reached: esp_ota_begin refuses while on trial */
        if (esp_ota_set_boot_partition(run) != ESP_OK || esp_ota_mark_app_valid_cancel_rollback() != ESP_OK)
            return false;
        ESP_LOGW(TAG, "image in %s unstaged: %s boots next", boot->label, run->label);
    }
    ota_reboot_update(RB_FIRMWARE, 0);
    return true;
}

/* A release whose signed header verified in the server task (guard), as the worker gets it. */
typedef struct {
    uint8_t hdr[REL_HEADER_LEN];
    rel_manifest_t m;
    const esp_partition_t *part; /* /ota: the slot the image goes into */
    bool later;                  /* /ota: staged, not rebooted into */
    httpd_req_t *req;            /* the server's async copy of the request */
    const void *rt;              /* its route (hroute_t) */
} rjob_t;

/* POST /ota. Body: release header (manifest + signature, see release.h), then the app image.
 * In the server task: the checks and the signed header, within HG_HEAD_MS; false: refused
 * (the reply is sent). */
static bool ota_head(httpd_req_t *req, rjob_t *j)
{
    if (!peer_is_private(req))
        return head_fail(req, "403 Forbidden", "private networks only\n");
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part || req->content_len <= REL_HEADER_LEN || req->content_len - REL_HEADER_LEN > part->size)
        return head_fail(req, "400 Bad Request", "bad image size\n");
    /* X-OTA-Reboot: later (or ?reboot=0) stages the image: the node goes on running this
     * firmware, with a reboot pending, until a control release reboots it. Without it the
     * node reboots into the image as soon as it is accepted, as ota_push.py expects. */
    bool later = false;
    char v[16];
    /* A value too long to read is refused, not taken for "now". */
    esp_err_t e = httpd_req_get_hdr_value_str(req, "X-OTA-Reboot", v, sizeof(v));
    if (e == ESP_ERR_HTTPD_RESULT_TRUNC)
        return head_fail(req, "400 Bad Request", "X-OTA-Reboot: now or later\n");
    if (e == ESP_OK) {
        if (!strcasecmp(v, "later"))
            later = true;
        else if (strcasecmp(v, "now"))
            return head_fail(req, "400 Bad Request", "X-OTA-Reboot: now or later\n");
    }
    char q[64];
    e = httpd_req_get_url_query_str(req, q, sizeof(q));
    if (e == ESP_OK)
        e = httpd_query_key_value(q, "reboot", v, sizeof(v));
    if (e == ESP_ERR_HTTPD_RESULT_TRUNC)
        return head_fail(req, "400 Bad Request", "query too long: reboot=0 or reboot=1\n");
    if (e == ESP_OK) {
        if (!strcmp(v, "0"))
            later = true;
        else if (strcmp(v, "1"))
            return head_fail(req, "400 Bad Request", "reboot=0 or reboot=1\n");
    }
    const char *why;
    /* The signed header first, and nothing held while it arrives: the update lock, the full
     * clock and the worker only once it verifies (guard). */
    if (!recv_all(req, j->hdr, sizeof(j->hdr)))
        return head_fail(req, "400 Bad Request", "receive failed\n");
    uint64_t limit = seq_limit();
    if (j->hdr[8] != REL_FIRMWARE)
        why = "not a firmware release";
    else
        why = rel_verify(j->hdr, &s_trust, seq_get(REL_FIRMWARE), limit, &j->m);
    if (!why && j->m.payload_len != req->content_len - REL_HEADER_LEN)
        why = "payload length does not match the manifest";
    if (why) {
        char msg[160];
        why_msg(msg, sizeof(msg), why, j->m.seq, limit);
        return head_fail(req, "403 Forbidden", msg);
    }
    j->part = part;
    j->later = later;
    return true;
}

/* In the worker, with the update lock held: the image, then the reply. */
static esp_err_t ota_body(httpd_req_t *req, rjob_t *j)
{
    const esp_partition_t *part = j->part;
    const rel_manifest_t m = j->m;
    const bool later = j->later;
    const char *why = NULL;
    int64_t t0 = esp_timer_get_time();
    ESP_LOGI(TAG, "firmware release seq %llu (key %u) verified; receiving %llu bytes into %s",
             (unsigned long long)m.seq, m.key_id, (unsigned long long)m.payload_len, part->label);
    /* An image selected for the next boot (staged, or accepted with a reboot still to come)
     * is about to be erased: boot this firmware until the new one is in, so a power cut or a
     * failed upload meanwhile doesn't leave a half-written slot selected. */
    if (!unstage()) {
        busy_give();
        return fail(req, "500 Internal Server Error", "could not unstage the staged firmware\n");
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    esp_ota_handle_t h = 0;
    char *buf = malloc(CHUNK);
    esp_err_t err = buf ? esp_ota_begin(part, OTA_WITH_SEQUENTIAL_WRITES, &h) : ESP_ERR_NO_MEM;
    size_t left = (size_t)m.payload_len;
    while (err == ESP_OK && left) {
        size_t n = left < CHUNK ? left : CHUNK;
        if (!recv_all(req, (uint8_t *)buf, n)) {
            err = ESP_FAIL;
            break;
        }
        mbedtls_sha256_update(&sha, (const uint8_t *)buf, n);
        err = esp_ota_write(h, buf, n);
        left -= n;
    }
    free(buf);
    uint8_t got[32];
    mbedtls_sha256_finish(&sha, got);
    mbedtls_sha256_free(&sha);

    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= got[i] ^ m.sha256[i];

    if (err != ESP_OK) {
        why = "receive/write failed\n";
    } else if (diff) {
        why = "image does not match the signed hash\n";
    } else if (esp_ota_end(h) != ESP_OK) {
        h = 0;
        why = "image failed validation\n";
    } else {
        h = 0;
        esp_app_desc_t d;
        if (esp_ota_get_partition_description(part, &d) != ESP_OK ||
            strcmp(d.project_name, esp_app_get_description()->project_name) != 0)
            why = "not a dns2 image\n";
        else if (!seq_set(REL_FIRMWARE, m.seq))
            why = "could not record the release seq\n";
        else if (esp_ota_set_boot_partition(part) != ESP_OK)
            why = "could not select new slot\n";
    }
    if (h)
        esp_ota_abort(h);
    busy_give();
    if (why)
        return fail(req, "400 Bad Request", why);

    if (later) {
        ESP_LOGI(TAG, "image accepted in %lld ms, staged in %s", (esp_timer_get_time() - t0) / 1000, part->label);
        ota_reboot_update(RB_FIRMWARE, RB_FIRMWARE);
        char msg[96];
        snprintf(msg, sizeof(msg), "ok, firmware seq %llu staged in %s; applies at the next reboot",
                 (unsigned long long)m.seq, part->label);
        return reply_ok(req, msg);
    }
    ESP_LOGI(TAG, "image accepted in %lld ms, rebooting into %s", (esp_timer_get_time() - t0) / 1000,
             part->label);
    ota_http_reply(req);
    httpd_resp_sendstr(req, "ok, rebooting\n");
    ota_reboot_after(0);
    return ESP_OK;
}

static bool recv_cb(void *req, uint8_t *p, size_t n) { return recv_all(req, p, n); }

/* Body: release header (release.h), then the payload: a config (settings.h), hosted zones
 * (hosted.h), or a kind the blocking service takes (blocklist, overrides, control). It is
 * stored and verified, its seq recorded, then put to use: live, or at the next reboot (a
 * list that only fits once the old one is gone, a setting that can't change live), which
 * the controller asks for with a reboot control release. The node never reboots itself
 * for a release. */
static bool release_head(httpd_req_t *req, rjob_t *j)
{
    if (!peer_is_private(req))
        return head_fail(req, "403 Forbidden", "private networks only\n");
    if (req->content_len <= REL_HEADER_LEN)
        return head_fail(req, "400 Bad Request", "bad release size\n");
    const char *why;
    /* As /ota: the lock only once the signed header verifies. */
    if (!recv_all(req, j->hdr, sizeof(j->hdr)))
        return head_fail(req, "400 Bad Request", "receive failed\n");
    uint8_t kind = j->hdr[8];
    uint64_t limit = seq_limit();
    if (kind != REL_CONFIG && !hosted_kind(kind) && !blocking_kind(kind))
        why = kind == REL_FIRMWARE ? "firmware releases go to /ota" : "release kind not supported here";
    else
        why = rel_verify(j->hdr, &s_trust, seq_get(kind), limit, &j->m);
    if (!why && j->m.payload_len != req->content_len - REL_HEADER_LEN)
        why = "payload length does not match the manifest";
    if (why) {
        char msg[160];
        why_msg(msg, sizeof(msg), why, j->m.seq, limit);
        return head_fail(req, "403 Forbidden", msg);
    }
    return true;
}

/* In the worker, with the update lock held: the payload, then the reply. */
static esp_err_t release_body(httpd_req_t *req, rjob_t *j)
{
    const uint8_t *hdr = j->hdr;
    const rel_manifest_t m = j->m;
    bool config = m.kind == REL_CONFIG, zones = hosted_kind(m.kind);
    const char *why, *status;
    char msg[160];
    bool pending = false;
    ESP_LOGI(TAG, "%s release seq %llu (key %u) verified; receiving %llu bytes", rel_kind_name(m.kind),
             (unsigned long long)m.seq, m.key_id, (unsigned long long)m.payload_len);
    why = config  ? settings_store(hdr, &m, recv_cb, req)
          : zones ? hosted_store(hdr, &m, recv_cb, req)
                  : blocking_store(hdr, &m, recv_cb, req);
    status = why == BLOCKING_LOADING || why == HOSTED_LOADING ? "503 Service Unavailable" : "400 Bad Request";
    if (!why && !seq_set(m.kind, m.seq))
        why = "could not record the release seq";
    if (!why) {
        status = "500 Internal Server Error";
        why = config  ? settings_apply(&m, msg, sizeof(msg), &pending)
              : zones ? hosted_apply(&m, msg, sizeof(msg), &pending)
                      : blocking_apply(&m, msg, sizeof(msg), &pending);
    }
    busy_give();
    if (why) {
        snprintf(msg, sizeof(msg), "%s\n", why);
        return fail(req, status, msg);
    }
    return reply_ok(req, msg);
}

static const char *state_name(esp_ota_img_states_t s)
{
    switch (s) {
    case ESP_OTA_IMG_NEW: return "new";
    case ESP_OTA_IMG_PENDING_VERIFY: return "trial";
    case ESP_OTA_IMG_VALID: return "valid";
    case ESP_OTA_IMG_INVALID: return "invalid";
    case ESP_OTA_IMG_ABORTED: return "aborted";
    default: return "undefined";
    }
}

static const char *reset_name(esp_reset_reason_t r)
{
    switch (r) {
    case ESP_RST_POWERON: return "power_on";
    case ESP_RST_EXT: return "pin";
    case ESP_RST_SW: return "software";
    case ESP_RST_PANIC: return "panic";
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT: return "watchdog";
    case ESP_RST_BROWNOUT: return "brownout";
    case ESP_RST_USB: return "usb";
    case ESP_RST_JTAG: return "jtag";
    default: return "other";
    }
}

/* /status without its zones: about 5 KB with every string at its longest, under 7 KB with
 * each of them escaped at its longest (jsonw.h: the errors' quotes and backslashes); and a
 * secondary zone's entry without its name, with every number at its longest (111 bytes),
 * which also holds a forward zone's (41 bytes without its name). */
#define STATUS_FIXED 9216
#define STATUS_SLOT  128

static esp_err_t status_get(httpd_req_t *req)
{
    const esp_app_desc_t *d = esp_app_get_description();
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st = ESP_OTA_IMG_UNDEFINED;
    esp_ota_get_state_partition(run, &st);
    server_stats_t s;
    server_get_stats(&s);
    char sha[17];
    for (int i = 0; i < 8; i++)
        sprintf(sha + 2 * i, "%02x", d->app_elf_sha256[i]);
    uint32_t ip = net_ip();
    health_t h = health_now();
    /* Every string escaped (jsonw.h): an error that quotes what it refused, a board name,
     * a version must never break the JSON. */
    char built[40], e_proj[2 * sizeof(d->project_name) + 1], e_ver[2 * sizeof(d->version) + 1],
        e_built[2 * sizeof(built) + 1], e_idf[2 * sizeof(d->idf_ver) + 1], e_board[2 * sizeof(board.name) + 1],
        e_image[64], e_src[32], e_err[200], e_fb[64];
    snprintf(built, sizeof(built), "%s %s", d->date, d->time);
    json_esc(e_proj, sizeof(e_proj), d->project_name);
    json_esc(e_ver, sizeof(e_ver), d->version);
    json_esc(e_built, sizeof(e_built), built);
    json_esc(e_idf, sizeof(e_idf), d->idf_ver);
    json_esc(e_board, sizeof(e_board), board.name);
    json_esc(e_image, sizeof(e_image), board_image());
    json_esc(e_src, sizeof(e_src), board_source());
    json_esc(e_err, sizeof(e_err), board_error());
    json_esc(e_fb, sizeof(e_fb), board_fallback_name());

    /* Sized for what this node reports: everything but the zones fits in STATUS_FIXED (with
     * every string at its longest), then each secondary and hosted zone at its longest. A
     * bundle swapped in after this is measured can only cut the reply short (the writers
     * below stop at cap), never overrun it. */
    size_t cap = STATUS_FIXED + hosted_status_max(), n = 0;
    reg_rdlock();
    for (int i = 0; i < reg_nslots(); i++)
        cap += STATUS_SLOT + strlen(reg_slot(i)->name);
    for (int i = 0; i < reg_nfzones(); i++)
        cap += STATUS_SLOT + strlen(reg_fzone(i)->name);
    reg_unlock();
    char *j = malloc(cap);
    if (!j)
        return httpd_resp_send_500(req);
    n += (size_t)snprintf(j + n, cap - n,
        "{\"project\":\"%s\",\"version\":\"%s\",\"elf_sha256\":\"%s\",\"built\":\"%s\",\"idf\":\"%s\","
        "\"slot\":\"%s\",\"ota_state\":\"%s\",\"uptime_s\":%lld,\"ip\":\"" IPSTR "\","
        "\"node_id\":\"" MACSTR "\",\"board\":\"%s\",\"image\":\"%s\",\"board_source\":\"%s\","
        "\"board_error\":\"%s\",\"fallback_board\":\"%s\",\"keys\":[\"%s\",\"%s\"],"
        "\"seq\":{\"firmware\":%llu,\"config\":%llu,\"zones\":%llu,\"blocklist\":%llu,\"overrides\":%llu,\"control\":%llu},"
        "\"degraded\":%s,\"heap_free\":%u,\"psram_free\":%u,"
        "\"queries\":{\"total\":%lu,\"udp\":%lu,\"tcp\":%lu,\"auth\":%lu,\"forwarded\":%lu,\"cache_hits\":%lu,"
        "\"nxdomain\":%lu,\"servfail\":%lu,\"refused\":%lu,\"notifies\":%lu,\"dropped\":%lu},",
        e_proj, e_ver, sha, e_built, e_idf, run->label, state_name(st),
        esp_timer_get_time() / 1000000, IP2STR((esp_ip4_addr_t *)&ip), MAC2STR(s_trust.node_id), e_board,
        e_image, e_src, e_err, e_fb, s_key_fp[0], s_key_fp[1], (unsigned long long)seq_get(REL_FIRMWARE),
        (unsigned long long)seq_get(REL_CONFIG), (unsigned long long)seq_get(REL_ZONES), (unsigned long long)seq_get(REL_BLOCKLIST), (unsigned long long)seq_get(REL_OVERRIDES),
        (unsigned long long)seq_get(REL_CONTROL), (h.reasons & HR_DEGRADED_MASK) ? "true" : "false",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
        (unsigned long)s.queries, (unsigned long)s.udp, (unsigned long)s.tcp, (unsigned long)s.auth,
        (unsigned long)s.forwarded, (unsigned long)s.cache_hits, (unsigned long)s.nxdomain,
        (unsigned long)s.servfail, (unsigned long)s.refused, (unsigned long)s.notifies, (unsigned long)s.dropped);
    /* Boot timing in ms since the app started; null for a step that hasn't finished. */
    /* The MAC of the interface it uses (Ethernet or Wi-Fi), what a DHCP reservation or a
     * static address is set by; "" before the interface is up. */
    uint8_t mac[6];
    char e_mac[18];
    net_mac(mac);
    n += (size_t)snprintf(j + n, cap - n,
                          "\"net\":{\"kind\":\"%s\",\"mac\":\"%s\",\"link\":%s,\"hostname\":\"%s.local\"",
                          net_kind_name(), json_mac(e_mac, sizeof(e_mac), mac), net_link_up() ? "true" : "false",
                          net_hostname());
    if (net_kind() == NET_WIFI) {
        net_wifi_stats_t ws;
        net_wifi_stats(&ws);
        n += (size_t)snprintf(j + n, cap - n,
                              ",\"rssi\":%d,\"ap\":\"" MACSTR "\",\"channel\":%u,\"connects\":%lu,\"drops\":%lu,"
                              "\"failed_attempts\":%lu,\"last_join_ms\":%lu,\"last_error\":\"%s\",\"last_error_code\":%u",
                              net_wifi_rssi(), MAC2STR(ws.bssid), ws.channel, (unsigned long)ws.connects,
                              (unsigned long)ws.drops, (unsigned long)ws.failed_attempts,
                              (unsigned long)ws.last_join_ms, net_wifi_reason(net_wifi_last_reason()),
                              net_wifi_last_reason());
    }
    n += (size_t)snprintf(j + n, cap - n, "},");
    /* Health: the same state and reasons as /health. */
    n += (size_t)snprintf(j + n, cap - n, "\"health\":{");
    if (n < cap)
        n += health_json(&h, j + n, cap - n);
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n,
                              "},\"sd\":{\"state\":\"%s\",\"timed_out\":%s,\"timeout_ms\":%d},"
                              "\"led\":{\"kind\":\"%s\",\"identify_s\":%lu},",
                              sd_state_name(sd_state()), sd_timed_out() ? "true" : "false", SD_BOOT_TIMEOUT_MS,
                              led_kind_name(), (unsigned long)health_identify_left());
    n += (size_t)snprintf(j + n, cap - n, "\"reset\":\"%s\",\"boot_ms\":", reset_name(esp_reset_reason()));
    n += (size_t)(boot_ms() ? snprintf(j + n, cap - n, "%lu", (unsigned long)boot_ms()) : snprintf(j + n, cap - n, "null"));
    n += (size_t)snprintf(j + n, cap - n, ",\"boot_limit_ms\":%d,\"boot\":{", BOOT_LIMIT_MS);
    for (int i = 0; i < BOOT_NSTEPS; i++) {
        uint32_t ms = boot_step_ms(i);
        n += (size_t)(ms ? snprintf(j + n, cap - n, "%s\"%s\":%lu", i ? "," : "", boot_step_name(i), (unsigned long)ms)
                         : snprintf(j + n, cap - n, "%s\"%s\":null", i ? "," : "", boot_step_name(i)));
    }
    n += (size_t)snprintf(j + n, cap - n, "},\"zones\":[");
    char e_zone[2 * 254 + 1];
    reg_rdlock();
    for (int i = 0; i < reg_nslots() && n < cap; i++) {
        zslot_t *z = reg_slot(i);
        json_esc(e_zone, sizeof(e_zone), z->name);
        n += (size_t)snprintf(j + n, cap - n, "%s{\"name\":\"%s\",\"serial\":%lu,\"records\":%u,"
                              "\"transfers\":%lu,\"fails\":%lu,\"expired\":%s}",
                              i ? "," : "", e_zone, z->z ? (unsigned long)z->z->serial : 0UL,
                              z->z ? (unsigned)z->z->n : 0U, (unsigned long)z->transfers,
                              (unsigned long)z->fails, z->expired ? "true" : "false");
    }
    /* The forward zones it runs (the config's, as of the last boot), so a controller can
     * refuse a hosted zone that is one of them. */
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, "],\"forward_zones\":[");
    for (int i = 0; i < reg_nfzones() && n < cap; i++) {
        const fzone_t *f = reg_fzone(i);
        const uint8_t *a = (const uint8_t *)&f->forwarder;
        json_esc(e_zone, sizeof(e_zone), f->name);
        n += (size_t)snprintf(j + n, cap - n, "%s{\"name\":\"%s\",\"forwarder\":\"%u.%u.%u.%u\"}", i ? "," : "",
                              e_zone, a[0], a[1], a[2], a[3]);
    }
    reg_unlock();
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, "],");
    if (n < cap)
        n += services_status_json(j + n, cap - n);
    if (n + 1 < cap) {
        j[n++] = ',';
        n += share_status_json(j + n, cap - n);
    }
    if (n + 1 < cap) {
        j[n++] = ',';
        n += hosted_status_json(j + n, cap - n);
    }
    if (n + 1 < cap) {
        j[n++] = ',';
        n += blocking_status_json(j + n, cap - n);
    }
    if (n + 1 < cap) {
        j[n++] = ',';
        n += settings_status_json(j + n, cap - n);
    }
    if (n + 1 < cap) {
        j[n++] = ',';
        n += clock_status_json(j + n, cap - n);
    }
    if (n + 1 < cap) {
        j[n++] = ',';
        n += power_status_json(j + n, cap - n);
    }
    if (n + 1 < cap) {
        j[n++] = ',';
        n += querylog_status_json(j + n, cap - n);
    }
    if (n + 1 < cap) {
        j[n++] = ',';
        taskENTER_CRITICAL(&s_rb_mux);
        rb_state_t rb = s_rb;
        taskEXIT_CRITICAL(&s_rb_mux);
        n += rb_json(&rb, uptime_s(), j + n, cap - n);
    }
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, "}\n");
    httpd_resp_set_type(req, "application/json");
    esp_err_t r = httpd_resp_send(req, j, n < cap ? (ssize_t)n : (ssize_t)cap - 1);
    free(j);
    return r;
}

/* GET /health: cheap and open (no names), for load balancers, monitoring and the controller.
 * 200 while the node answers DNS (healthy, degraded, updating), 503 otherwise. */
static esp_err_t health_get(httpd_req_t *req)
{
    health_t h = health_now();
    char j[1024];
    size_t n = (size_t)snprintf(j, sizeof(j), "{");
    n += health_json(&h, j + n, sizeof(j) - n);
    if (n < sizeof(j))
        n += (size_t)snprintf(j + n, sizeof(j) - n, ",\"uptime_s\":%lld,\"boot_ms\":%lu,",
                              esp_timer_get_time() / 1000000, (unsigned long)boot_ms());
    if (n < sizeof(j))
        n += blocking_health_json(j + n, sizeof(j) - n);
    if (n + 1 < sizeof(j)) {
        j[n++] = ',';
        n += hosted_health_json(j + n, sizeof(j) - n);
    }
    if (n < sizeof(j))
        n += (size_t)snprintf(j + n, sizeof(j) - n, "}\n");
    if (n >= sizeof(j))
        n = sizeof(j) - 1;
    if (!health_answering(h.state))
        httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, j, (ssize_t)n);
}

/* ---- the HTTP server (httpguard.h) ----
 *
 * Every connection receives and sends against its request's deadline (conn_recv,
 * conn_send), and every request passes the Host check first (guard). The GETs run in the
 * server's task, each within HG_REPLY_MS. A release (POST /ota, /release) has its checks
 * and its signed header read and verified in the server's task, within HG_HEAD_MS, like the
 * HTTP headers before it; only a release whose header verified takes the update lock
 * (busy_take) and the worker, a task of its own (one at a time), which has hg_body_ms(payload)
 * for the payload. So a sender without the key never holds the lock nor the worker, and the
 * server goes on answering GETs on its other connections however long a push takes. The
 * worker's reply closes the connection. */

#define WORKER_STACK 8192 /* what the server's own task had for the release handlers */

typedef struct {
    esp_err_t (*fn)(httpd_req_t *req); /* a GET, in the server task */
    /* A POST: its checks and header in the server task (false: refused, the reply sent),
     * then its body in the worker. */
    bool (*head)(httpd_req_t *req, rjob_t *j);
    esp_err_t (*body)(httpd_req_t *req, rjob_t *j);
    bool lock; /* a release: the update lock, taken once the header verified, given by body */
} hroute_t;

static volatile bool s_worker; /* the worker is taken */

static hg_conn_t *conn_of(httpd_handle_t hd, int fd) { return httpd_sess_get_transport_ctx(hd, fd); }

static int conn_recv(httpd_handle_t hd, int fd, char *buf, size_t len, int flags)
{
    hg_conn_t *c = conn_of(hd, fd);
    int r = c ? hg_recv(c, fd, buf, len, flags) : -1;
    return r < 0 ? HTTPD_SOCK_ERR_FAIL : r;
}

static int conn_send(httpd_handle_t hd, int fd, const char *buf, size_t len, int flags)
{
    hg_conn_t *c = conn_of(hd, fd);
    int r = c ? hg_send(c, fd, buf, len, flags) : -1;
    return r < 0 ? HTTPD_SOCK_ERR_FAIL : r;
}

static esp_err_t conn_open(httpd_handle_t hd, int fd)
{
    hg_conn_t *c = calloc(1, sizeof(*c));
    if (!c)
        return ESP_FAIL;
    httpd_sess_set_transport_ctx(hd, fd, c, free);
    httpd_sess_set_recv_override(hd, fd, conn_recv);
    httpd_sess_set_send_override(hd, fd, conn_send);
    return ESP_OK;
}

static void body_deadline(httpd_req_t *req, uint64_t len)
{
    hg_conn_t *c = conn_of(req->handle, httpd_req_to_sockfd(req));
    if (c)
        hg_set(c, hg_body_ms(len));
}

void ota_http_reply(httpd_req_t *req)
{
    hg_conn_t *c = conn_of(req->handle, httpd_req_to_sockfd(req));
    if (c)
        hg_set(c, HG_REPLY_MS);
}

/* The reply says the connection closes after it (set once: a release's async copy keeps
 * it). */
static void closing(httpd_req_t *req) { httpd_resp_set_hdr(req, "Connection", "close"); }

/* A refusal: the reply, then the connection closes (a body it carries is never read). The
 * caller has set closing(). */
static esp_err_t refuse(httpd_req_t *req, const char *status, const char *msg)
{
    httpd_resp_set_status(req, status);
    httpd_resp_sendstr(req, msg);
    return ESP_FAIL;
}

static bool host_ok(httpd_req_t *req)
{
    char host[96];
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK)
        return false; /* none, or longer than any name of this node */
    return hg_host_ok(host, net_ip(), net_hostname(), settings()->name);
}

static void worker_task(void *arg)
{
    rjob_t *j = arg;
    httpd_req_t *req = j->req;
    const hroute_t *rt = j->rt;
    hg_conn_t *c = conn_of(req->handle, httpd_req_to_sockfd(req));
    rt->body(req, j); /* its reply closes the connection (guard set closing()) */
    /* What is left of a body it refused (a config too big, a list that doesn't fit), read
     * and dropped within the reply's deadline, so the client reads the reply rather than a
     * reset connection. Only a sender whose header verified gets here. */
    char rest[256];
    while (httpd_req_recv(req, rest, sizeof(rest)) > 0) {
    }
    ESP_LOGD(TAG, "release worker: %u bytes of stack unused", (unsigned)uxTaskGetStackHighWaterMark(NULL));
    /* The client was told the connection closes; anything more on it fails, and the server
     * drops it. */
    if (c)
        c->closed = true;
    free(j);
    httpd_req_async_handler_complete(req);
    __atomic_store_n(&s_worker, false, __ATOMIC_RELEASE);
    vTaskDelete(NULL);
}

static bool worker_take(void) { return !__atomic_exchange_n(&s_worker, true, __ATOMIC_ACQ_REL); }

static const hg_locks_t s_locks = { .take = busy_take, .give = busy_give, .seq = seq_get, .worker = worker_take };

/* A release whose header verified: the update lock, then the worker (hg_gate). Takes j. */
static esp_err_t worker_start(httpd_req_t *req, hg_conn_t *c, const hroute_t *rt, rjob_t *j)
{
    hg_gate_t g = hg_gate(&s_locks, rt->lock, j->m.kind, j->m.seq);
    if (g != HG_GO) {
        free(j);
        return g == HG_STALE ? refuse(req, "403 Forbidden", "stale release (seq not above the last one applied)\n")
                             : refuse(req, "409 Conflict", "update already in progress\n");
    }
    httpd_req_t *a = NULL;
    if (httpd_req_async_handler_begin(req, &a) != ESP_OK) {
        if (rt->lock)
            busy_give();
        free(j);
        __atomic_store_n(&s_worker, false, __ATOMIC_RELEASE);
        return refuse(req, "503 Service Unavailable", "out of memory: try again\n");
    }
    j->req = a;
    j->rt = rt;
    if (rt->lock)
        body_deadline(req, j->m.payload_len); /* the payload, now that its header verified */
    if (xTaskCreate(worker_task, "http_rel", WORKER_STACK, j, 5, NULL) != pdPASS) {
        if (rt->lock)
            busy_give();
        free(j);
        refuse(a, "503 Service Unavailable", "out of memory: try again\n");
        c->closed = true;
        httpd_req_async_handler_complete(a);
        __atomic_store_n(&s_worker, false, __ATOMIC_RELEASE);
    }
    return ESP_OK;
}

/* Every request: the Host check, then its handler within its deadline. */
static esp_err_t guard(httpd_req_t *req)
{
    const hroute_t *rt = req->user_ctx;
    hg_conn_t *c = conn_of(req->handle, httpd_req_to_sockfd(req));
    if (!c)
        return ESP_FAIL;
    if (!host_ok(req)) {
        closing(req);
        return refuse(req, "421 Misdirected Request", "Host: this node's address or name only\n");
    }
    if (rt->head) {
        /* Whatever its reply, a POST's connection closes after it: a refusal's deadline
         * (below) is not the next request's. */
        closing(req);
        rjob_t *j = calloc(1, sizeof(*j));
        if (!j)
            return refuse(req, "503 Service Unavailable", "out of memory: try again\n");
        hg_set(c, HG_HEAD_MS); /* the checks and the signed header */
        if (!rt->head(req, j)) {
            free(j);
            /* Refused, the reply sent: what is left of the body is read and dropped (by the
             * server, after this) within HG_HEAD_MS, so a client sending it reads the reply,
             * and a slow one is cut off. */
            hg_set(c, HG_HEAD_MS);
            return ESP_OK;
        }
        return worker_start(req, c, rt, j);
    }
    if (req->content_len) {
        closing(req);
        return refuse(req, "400 Bad Request", "no body here\n");
    }
    hg_set(c, HG_REPLY_MS);
    esp_err_t r = rt->fn(req);
    hg_done(c); /* the next request on this connection starts its own deadline */
    return r;
}

#ifdef DNS2_BENCH_BLOCKLIST
/* A bench build's /bench: no signed header to wait for, the body has its time by size. */
static bool bench_head(httpd_req_t *req, rjob_t *j)
{
    if (!peer_is_private(req))
        return head_fail(req, "403 Forbidden", "private addresses only\n");
    body_deadline(req, req->content_len);
    return true;
}

static esp_err_t bench_body(httpd_req_t *req, rjob_t *j) { return bench_post(req); }
#endif

static void route(httpd_handle_t srv, const char *uri, httpd_method_t method, const hroute_t *rt)
{
    httpd_uri_t u = { .uri = uri, .method = method, .handler = guard, .user_ctx = (void *)rt };
    httpd_register_uri_handler(srv, &u);
}

void ota_start(void)
{
    trust_init();
    ESP_LOGI(TAG, "node " MACSTR " image %s, release key %s, recovery key %s", MAC2STR(s_trust.node_id),
             s_trust.board, s_key_fp[0], s_key_fp[1]);
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.max_open_sockets = 3;
    cfg.stack_size = 8192;
    /* The connections' receives and sends wait as long as their request's deadline allows
     * (conn_recv): these are only what a socket starts with. */
    cfg.recv_wait_timeout = HG_HEAD_MS / 1000;
    cfg.send_wait_timeout = HG_HEAD_MS / 1000;
    cfg.lru_purge_enable = true;
    cfg.max_uri_handlers = 10;
    cfg.open_fn = conn_open;
    httpd_handle_t srv = NULL;
    if (httpd_start(&srv, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "http server failed to start");
        return;
    }
    static const hroute_t status = { .fn = status_get }, health = { .fn = health_get },
                          metrics = { .fn = metrics_get }, querylog = { .fn = querylog_get },
                          ota = { .head = ota_head, .body = ota_body, .lock = true },
                          rel = { .head = release_head, .body = release_body, .lock = true };
    route(srv, "/status", HTTP_GET, &status);
    route(srv, "/health", HTTP_GET, &health);   /* open (no names), for monitoring */
    route(srv, "/metrics", HTTP_GET, &metrics); /* open, as /health */
    route(srv, "/querylog", HTTP_GET, &querylog); /* private addresses only */
    route(srv, "/ota", HTTP_POST, &ota);
    route(srv, "/release", HTTP_POST, &rel);
#ifdef DNS2_BENCH_BLOCKLIST
    static const hroute_t bench = { .head = bench_head, .body = bench_body };
    route(srv, "/bench", HTTP_POST, &bench);
    ESP_LOGW(TAG, "bench build: POST /bench; rolls back by itself in %d s", HEALTH_TIMEOUT_S);
#endif
    ESP_LOGI(TAG, "http on :80 (/health, /status, /metrics, /querylog, /ota, /release)");
}

static bool any_zone_loaded(void)
{
    bool zones = false;
    for (int i = 0; i < reg_nslots(); i++)
        zones |= reg_slot(i)->z != NULL;
    return zones;
}

static void confirm_task(void *arg)
{
    /* Zones are part of the check only if the node had some on its SD card at boot (they are
     * loaded before this task starts). A node with none yet, such as one the primary doesn't
     * allow transfers to, must still be able to take an update. */
    bool need_zones = any_zone_loaded();
    if (!need_zones)
        ESP_LOGW(TAG, "no saved zones: health check without zones");
    for (int t = 0; t < HEALTH_TIMEOUT_S; t++) {
        bool zones = !need_zones || any_zone_loaded();
#if defined(DNS2_TEST_FAIL_HEALTH) || defined(DNS2_BENCH_BLOCKLIST)
        zones = false;
#endif
        /* The limit is for a static address. On DHCP (a config that asks for it), boot_ms mostly
         * measures the DHCP server (78 s seen on a home Wi-Fi network): reported, not enforced. */
        if (boot_ms() > BOOT_LIMIT_MS && settings()->ip) {
            ESP_LOGE(TAG, "trial boot took %lu ms to answer, over the %d ms limit: rolling back",
                     (unsigned long)boot_ms(), BOOT_LIMIT_MS);
            esp_ota_mark_app_invalid_rollback_and_reboot();
        }
        if (net_ip() && server_running() && zones) {
            esp_ota_mark_app_valid_cancel_rollback();
            ESP_LOGI(TAG, "trial boot healthy after %ds: firmware confirmed", t);
            vTaskDelete(NULL);
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    ESP_LOGE(TAG, "trial boot not healthy after %ds: rolling back", HEALTH_TIMEOUT_S);
    esp_ota_mark_app_invalid_rollback_and_reboot();
}

void ota_confirm_when_healthy(void)
{
    esp_ota_img_states_t st;
    if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK &&
        st == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGW(TAG, "trial boot of new firmware: checking health");
        xTaskCreate(confirm_task, "ota_ok", 4096, NULL, 4, NULL);
    }
}
