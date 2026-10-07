#include "querylog.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "clock.h"
#include "dns_wire.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ota.h"
#include "settings.h"
#include "share.h"

static const char *TAG = "querylog";

_Static_assert(sizeof(ql_entry_t) == MP_QUERYLOG_ENTRY, "the plan's query log entry (memplan.h)");

static st_t s_st; /* the counters: always, whether the log runs or not */

/* The ring, and the next seq across the service's stops and starts: under s_mux, which is
 * held for one entry's copy at a time. */
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static ql_ring_t s_ring;
static uint64_t s_next = 1;
static void *s_mem;               /* the ring's memory, from the service's share */
static volatile bool s_on;        /* writing entries */
static volatile bool s_failed;    /* its start found no memory where the plan said there was */
static char s_boot_id[17];

static __thread ql_note_t *t_note;

static uint64_t uptime_ms(void) { return (uint64_t)(esp_timer_get_time() / 1000); }

/* ---- the DNS path ---- */

ql_note_t *querylog_note(void) { return t_note; }
void querylog_note_set(ql_note_t *n) { t_note = n; }

void querylog_note_rule(ql_rule_t r)
{
    if (t_note)
        t_note->rule = (uint8_t)r;
}

void querylog_query(const ql_note_t *n, uint32_t src, bool tcp, const uint8_t *out, size_t len, uint32_t us)
{
    int rcode = len >= DNS_HDR_LEN ? DNS_RCODE(rd16(out + 2)) : -1;
    ql_result_t r = ql_result(n, rcode, len);
    /* NOTIFYs and drops have their counters in server.c already: /metrics reads them there. */
    if (r != QR_NOTIFY && r != QR_DROPPED)
        st_query(&s_st, r, rcode, us);
    if (!s_on || !len)
        return;
    const cfg_t *c = settings();
    ql_entry_t e = { 0 };
    e.t_ms = uptime_ms();
    e.client_mode = c->querylog_client;
    e.client = ql_client_addr(src, (ql_client_t)c->querylog_client);
    e.latency_us = us;
    e.result = (uint8_t)r;
    e.rcode = (uint8_t)rcode;
    /* The rule only where it decided the answer (a local zone's CNAME target is checked,
     * never blocked). */
    e.rule = r == QR_BLOCKED || r == QR_OVERRIDDEN || n->rule == QL_RULE_ALLOW ? n->rule : QL_RULE_NONE;
    e.flags = tcp ? QL_F_TCP : 0;
    if (n->parsed) {
        e.qtype = n->qtype;
        e.name_len = n->name_len;
        memcpy(e.name, n->name, n->name_len);
        if (n->name_trunc)
            e.flags |= QL_F_TRUNC;
    }
    taskENTER_CRITICAL(&s_mux);
    if (s_ring.n) {
        ql_add(&s_ring, &e);
        s_next = s_ring.next;
    }
    taskEXIT_CRITICAL(&s_mux);
}

void querylog_upstream(uint32_t server, fwd_try_t how, uint32_t us)
{
    st_upstream(&s_st, server, how == FWD_TRY_ANSWER, how == FWD_TRY_TIMEOUT, us);
}

const st_t *querylog_stats(void) { return &s_st; }

void querylog_ring_info(uint32_t *capacity, uint64_t *first, uint64_t *next)
{
    taskENTER_CRITICAL(&s_mux);
    *capacity = s_ring.n;
    *first = s_ring.n ? s_ring.first : s_next;
    *next = s_next;
    taskEXIT_CRITICAL(&s_mux);
}

const char *querylog_boot_id(void)
{
    if (!s_boot_id[0])
        snprintf(s_boot_id, sizeof(s_boot_id), "%08lx%08lx", (unsigned long)esp_random(), (unsigned long)esp_random());
    return s_boot_id;
}

/* ---- the service ---- */

void querylog_start(void)
{
    querylog_boot_id();
    if (s_mem || !settings()->querylog)
        return; /* running, or off in the config (at boot: main.c starts every service) */
    size_t bytes = (size_t)share_board()->querylog_kb * 1024;
    s_failed = false;
    if (!ql_capacity(bytes)) {
        ESP_LOGI(TAG, "no memory for it on this board (memory.querylog_kb %lu): off",
                 (unsigned long)share_board()->querylog_kb);
        return;
    }
    void *mem = share_alloc(SVC_QUERYLOG, mp_data_pool(share_board()), bytes);
    if (!mem) {
        /* The plan said it fits: the board definition is wrong. The supervisor tries again. */
        ESP_LOGE(TAG, "no memory for its %u KB", (unsigned)(bytes / 1024));
        s_failed = true;
        return;
    }
    memset(mem, 0, bytes);
    taskENTER_CRITICAL(&s_mux);
    ql_init(&s_ring, mem, bytes, s_next);
    s_mem = mem;
    taskEXIT_CRITICAL(&s_mux);
    s_on = true;
    ESP_LOGI(TAG, "on: %lu queries in %u KB", (unsigned long)s_ring.n, (unsigned)(bytes / 1024));
}

void querylog_stop(void)
{
    s_on = false;
    taskENTER_CRITICAL(&s_mux);
    void *mem = s_mem;
    s_mem = NULL;
    s_ring.n = 0;
    s_ring.e = NULL;
    taskEXIT_CRITICAL(&s_mux);
    /* No writer or reader is in the ring now: both look at it only under s_mux. */
    share_free(mem);
    s_failed = false;
}

void querylog_apply(void)
{
    /* Made stricter: what the ring holds from before keeps no more than the new setting
     * (an entry a worker writes as this runs, under the old setting, is masked as it is
     * read: querylog_get). One entry per critical section. */
    ql_client_t mode = (ql_client_t)settings()->querylog_client;
    if (mode == QL_CLIENT_FULL)
        return;
    uint32_t capacity;
    uint64_t first, next;
    querylog_ring_info(&capacity, &first, &next);
    for (uint64_t seq = first; capacity && seq < next; seq++) {
        taskENTER_CRITICAL(&s_mux);
        ql_privacy(&s_ring, seq, mode);
        taskEXIT_CRITICAL(&s_mux);
    }
}

svc_state_t querylog_state(void) { return s_on ? SVC_RUNNING : s_failed ? SVC_FAILED : SVC_OFF; }

bool querylog_broken(void) { return s_failed; }

/* ---- HTTP ---- */

#define QL_CHUNK  4096 /* sent once this much is written */
#define QL_BUF    (QL_CHUNK + 1 + QL_JSON_MAX + 128)
#define LIMIT_DEF 100
#define LIMIT_MAX 1000

static uint64_t arg_u64(const char *q, const char *key, uint64_t def, bool *bad)
{
    char v[24];
    if (!q)
        return def;
    esp_err_t err = httpd_query_key_value(q, key, v, sizeof(v));
    if (err == ESP_ERR_NOT_FOUND)
        return def;
    if (err != ESP_OK) {
        *bad = true; /* longer than any number it takes */
        return def;
    }
    /* Digits only: strtoull would take a sign or white space, and says ERANGE past 2^64. */
    for (const char *p = v; *p; p++)
        if (*p < '0' || *p > '9')
            *bad = true;
    errno = 0;
    unsigned long long n = strtoull(v, NULL, 10);
    if (!v[0] || errno == ERANGE)
        *bad = true;
    return n;
}

static uint64_t unix_ms(void)
{
    if (!clock_synced())
        return 0;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

esp_err_t querylog_get(httpd_req_t *req)
{
    if (!ota_peer_private(req)) {
        httpd_resp_set_status(req, "403 Forbidden");
        return httpd_resp_sendstr(req, "private addresses only\n");
    }
    char q[96];
    esp_err_t qerr = httpd_req_get_url_query_str(req, q, sizeof(q));
    const char *qs = qerr == ESP_OK ? q : NULL;
    bool bad = qerr != ESP_OK && qerr != ESP_ERR_NOT_FOUND; /* too long for any it takes */
    uint64_t cursor = arg_u64(qs, "cursor", 0, &bad);
    uint64_t limit = arg_u64(qs, "limit", LIMIT_DEF, &bad);
    if (bad || limit == 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "cursor and limit: whole numbers, limit 1 or more\n");
    }
    if (limit > LIMIT_MAX)
        limit = LIMIT_MAX;
    char *buf = malloc(QL_BUF);
    if (!buf)
        return httpd_resp_send_500(req);

    uint32_t capacity;
    uint64_t first, next;
    querylog_ring_info(&capacity, &first, &next);
    ql_cursor_t c = ql_cursor(cursor, first, next);
    uint64_t now = uptime_ms(), wall = unix_ms();
    const cfg_t *cfg = settings();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    size_t n = (size_t)snprintf(buf, QL_CHUNK,
                                "{\"boot_id\":\"%s\",\"enabled\":%s,\"state\":\"%s\",\"client\":\"%s\","
                                "\"capacity\":%lu,\"oldest\":%llu,\"newest\":%llu,\"cursor\":%llu,\"uptime_ms\":%llu,"
                                "\"time\":",
                                querylog_boot_id(), cfg->querylog ? "true" : "false", svc_state_name(querylog_state()),
                                ql_client_name(cfg->querylog_client), (unsigned long)capacity, (unsigned long long)first,
                                (unsigned long long)(next - 1), (unsigned long long)cursor, (unsigned long long)now);
    n += (size_t)(wall ? snprintf(buf + n, QL_CHUNK - n, "%llu", (unsigned long long)wall)
                       : snprintf(buf + n, QL_CHUNK - n, "null"));
    n += (size_t)snprintf(buf + n, QL_CHUNK - n, ",\"entries\":[");

    /* One entry copied out at a time: the critical section is one 160-byte copy. */
    uint64_t last = c.from - 1, lost = c.lost, seq = c.from;
    uint32_t sent = 0;
    esp_err_t err = ESP_OK;
    while (sent < limit && err == ESP_OK) {
        ql_entry_t e;
        taskENTER_CRITICAL(&s_mux);
        bool got = ql_get(&s_ring, seq, &e);
        uint64_t now_first = s_ring.n ? s_ring.first : s_next;
        taskEXIT_CRITICAL(&s_mux);
        if (!got) {
            if (seq >= now_first)
                break; /* nothing newer (or the service is off) */
            /* Overwritten while this read went on: those are lost too. */
            lost += now_first - seq;
            last = now_first - 1;
            seq = now_first;
            continue;
        }
        /* The client setting as it is now, if stricter than when the entry was logged. */
        ql_entry_privacy(&e, (ql_client_t)cfg->querylog_client);
        if (sent)
            buf[n++] = ',';
        n += ql_entry_json(&e, now, wall, buf + n, QL_JSON_MAX);
        last = e.seq;
        seq = e.seq + 1;
        sent++;
        if (n >= QL_CHUNK) {
            err = httpd_resp_send_chunk(req, buf, (ssize_t)n);
            n = 0;
        }
    }
    uint64_t newest;
    querylog_ring_info(&capacity, &first, &newest);
    if (err == ESP_OK) {
        n += (size_t)snprintf(buf + n, QL_BUF - n, "],\"next\":%llu,\"lost\":%llu,\"reset\":%s,\"more\":%s}\n",
                              (unsigned long long)last, (unsigned long long)lost, c.reset ? "true" : "false",
                              last + 1 < newest ? "true" : "false");
        err = httpd_resp_send_chunk(req, buf, (ssize_t)n);
    }
    if (err == ESP_OK)
        err = httpd_resp_send_chunk(req, NULL, 0);
    free(buf);
    return err;
}

size_t querylog_status_json(char *j, size_t cap)
{
    uint32_t capacity;
    uint64_t first, next;
    querylog_ring_info(&capacity, &first, &next);
    const cfg_t *c = settings();
    int n = snprintf(j, cap,
                     "\"querylog\":{\"enabled\":%s,\"state\":\"%s\",\"client\":\"%s\",\"capacity\":%lu,"
                     "\"entries\":%llu,\"oldest\":%llu,\"newest\":%llu,\"boot_id\":\"%s\"}",
                     c->querylog ? "true" : "false", svc_state_name(querylog_state()),
                     ql_client_name(c->querylog_client), (unsigned long)capacity,
                     (unsigned long long)(next - first), (unsigned long long)first, (unsigned long long)(next - 1),
                     querylog_boot_id());
    return n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap ? cap - 1 : 0;
}
