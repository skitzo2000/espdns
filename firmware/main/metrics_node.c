#include "metrics_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blocking.h"
#include "board.h"
#include "boot.h"
#include "clock.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "health.h"
#include "health_node.h"
#include "hosted.h"
#include "metrics.h"
#include "net.h"
#include "ota.h"
#include "power.h"
#include "querylog.h"
#include "registry.h"
#include "release.h"
#include "server.h"
#include "services.h"
#include "settings.h"
#include "share.h"

#define CHUNK (4 * 1024)

typedef struct {
    httpd_req_t *req;
    esp_err_t err; /* the first chunk that failed (the client gone): nothing more is sent */
} sender_t;

static void send_chunk(void *ctx, const char *buf, size_t n)
{
    sender_t *s = ctx;
    if (s->err == ESP_OK)
        s->err = httpd_resp_send_chunk(s->req, buf, (ssize_t)n);
}

/* name{k="v"} value: one label. */
static void one(mx_t *w, const char *name, const char *k, const char *v, uint64_t value)
{
    char lb[MX_LABELS_MAX] = "";
    mx_label(lb, k, v);
    mx_u64(w, name, lb, value);
}

static void node(mx_t *w)
{
    const esp_app_desc_t *d = esp_app_get_description();
    char lb[MX_LABELS_MAX] = "";
    mx_label(lb, "version", d->version);
    mx_label(lb, "image", board_image());
    mx_label(lb, "board", board.name);
    mx_label(lb, "idf", d->idf_ver);
    mx_family(w, "espdns_build_info", "gauge", "The firmware, chip image and board: always 1.");
    mx_u64(w, "espdns_build_info", lb, 1);
    mx_family(w, "espdns_uptime_seconds", "gauge", "Time since boot.");
    mx_seconds(w, "espdns_uptime_seconds", "", (uint64_t)esp_timer_get_time());
    mx_family(w, "espdns_boot_seconds", "gauge", "Time from power-on to answering DNS this boot (0 until it answers).");
    mx_seconds(w, "espdns_boot_seconds", "", (uint64_t)boot_ms() * 1000);

    health_t h = health_now();
    mx_family(w, "espdns_health_state", "gauge", "The node's health state: 1 for the one it is in.");
    for (int s = 0; s < HEALTH_NSTATES; s++)
        one(w, "espdns_health_state", "state", health_state_name(s), h.state == (health_state_t)s);
    mx_family(w, "espdns_health_reason", "gauge", "Each health reason: 1 while it applies.");
    for (int i = 0; i < HR_NBITS; i++)
        one(w, "espdns_health_reason", "reason", health_reason_name(1u << i), (h.reasons >> i) & 1);
    mx_family(w, "espdns_reboot_pending", "gauge", "1 while a release waits for a reboot.");
    mx_u64(w, "espdns_reboot_pending", "", ota_reboot_reasons() != 0);

    mx_family(w, "espdns_release_seq", "gauge", "The highest release seq applied, per kind.");
    static const struct {
        uint8_t kind;
        const char *name;
    } K[] = { { REL_FIRMWARE, "firmware" }, { REL_CONFIG, "config" },       { REL_ZONES, "zones" },
              { REL_BLOCKLIST, "blocklist" }, { REL_OVERRIDES, "overrides" }, { REL_CONTROL, "control" } };
    for (size_t i = 0; i < sizeof(K) / sizeof(K[0]); i++)
        one(w, "espdns_release_seq", "kind", K[i].name, ota_seq(K[i].kind));

    mx_family(w, "espdns_link_up", "gauge", "1 while the network link is up.");
    mx_u64(w, "espdns_link_up", "", net_link_up());
    if (net_kind() == NET_WIFI) {
        mx_family(w, "espdns_wifi_rssi_dbm", "gauge", "The Wi-Fi signal, dBm.");
        mx_i64(w, "espdns_wifi_rssi_dbm", "", net_wifi_rssi());
    }
    mx_family(w, "espdns_clock_synced", "gauge", "1 once the clock is set over SNTP.");
    mx_u64(w, "espdns_clock_synced", "", clock_synced());
}

/* Forward zone i's name (mx_forward), copied under the registry's read lock. */
static bool fzone_name(void *ctx, int i, char *name, size_t cap)
{
    reg_rdlock();
    bool ok = i < reg_nfzones();
    if (ok)
        snprintf(name, cap, "%s", reg_fzone(i)->name);
    reg_unlock();
    return ok;
}

static void queries(mx_t *w)
{
    server_stats_t s;
    server_get_stats(&s);
    const st_t *st = querylog_stats();
    mx_family(w, "espdns_queries_received_total", "counter", "DNS messages received, by transport.");
    one(w, "espdns_queries_received_total", "transport", "udp", s.udp);
    one(w, "espdns_queries_received_total", "transport", "tcp", s.tcp);
    mx_family(w, "espdns_queries_total", "counter",
              "Queries by what answered them: cache, forwarded, hosted, secondary, blocked (the blocklist), "
              "overridden (the overrides), refused, servfail, error, notify, dropped (never answered).");
    for (int r = 0; r < QR_N; r++) {
        uint64_t v = r == QR_NOTIFY    ? s.notifies
                     : r == QR_DROPPED ? s.dropped
                                       : __atomic_load_n(&st->result[r], __ATOMIC_RELAXED);
        one(w, "espdns_queries_total", "result", ql_result_name(r), v);
    }
    mx_family(w, "espdns_responses_total", "counter", "Responses by rcode (NOTIFY replies not included).");
    for (int rc = 0; rc < 16; rc++) {
        uint32_t v = __atomic_load_n(&st->rcode[rc], __ATOMIC_RELAXED);
        char b[12];
        if (rc <= 5 || v)
            one(w, "espdns_responses_total", "rcode", ql_rcode_name(rc, b), v);
    }
    mx_family(w, "espdns_query_duration_seconds", "histogram",
              "Time to answer a query: from a worker taking it to its answer being ready, forwarders included.");
    mx_hist(w, "espdns_query_duration_seconds", "", &st->latency);

    /* The forwarders, in the order they were first asked. */
    mx_upstreams(w, st);
    health_fwd_t f;
    server_upstream(&f);
    mx_family(w, "espdns_upstream_failing", "gauge",
              "Forwarded queries in a row the default forwarders gave no answer to (0 after any answer).");
    mx_u64(w, "espdns_upstream_failing", "", f.fails);
    upq_stats_t us;
    if (server_forward_stats(&us))
        mx_forward(w, &us, fzone_name, NULL);
}

static void cache(mx_t *w)
{
    cache_stats_t c = { 0 };
    uint32_t max_entries, bytes;
    server_cache_stats(&c, &max_entries, &bytes);
    mx_family(w, "espdns_cache_entries", "gauge", "Answers in the cache.");
    mx_u64(w, "espdns_cache_entries", "", c.entries);
    mx_family(w, "espdns_cache_entries_max", "gauge", "The most answers the cache holds (memory.cache_entries).");
    mx_u64(w, "espdns_cache_entries_max", "", max_entries);
    mx_family(w, "espdns_cache_bytes", "gauge", "Bytes the cached answers take.");
    mx_u64(w, "espdns_cache_bytes", "", c.bytes);
    mx_family(w, "espdns_cache_capacity_bytes", "gauge", "The cache's memory (memory.cache_kb).");
    mx_u64(w, "espdns_cache_capacity_bytes", "", bytes);
    mx_family(w, "espdns_cache_hits_total", "counter", "Lookups answered from the cache.");
    mx_u64(w, "espdns_cache_hits_total", "", c.hits);
    mx_family(w, "espdns_cache_misses_total", "counter", "Lookups the cache didn't have.");
    mx_u64(w, "espdns_cache_misses_total", "", c.misses);
    mx_family(w, "espdns_cache_inserts_total", "counter", "Answers put in the cache.");
    mx_u64(w, "espdns_cache_inserts_total", "", c.inserts);
    mx_family(w, "espdns_cache_evictions_total", "counter", "Answers dropped to make room.");
    mx_u64(w, "espdns_cache_evictions_total", "", c.evictions);
}

static void blocking(mx_t *w)
{
    blocking_metrics_t b;
    blocking_metrics(&b);
    static const char *const LIST[2] = { "blocklist", "overrides" };
    mx_family(w, "espdns_blocklist_loaded", "gauge", "1 while the list is loaded and in use.");
    for (int k = 0; k < 2; k++)
        one(w, "espdns_blocklist_loaded", "list", LIST[k], b.list[k].on);
    mx_family(w, "espdns_blocklist_entries", "gauge", "Entries in the list in use.");
    for (int k = 0; k < 2; k++)
        one(w, "espdns_blocklist_entries", "list", LIST[k], b.list[k].entries);
    mx_family(w, "espdns_blocklist_seq", "gauge", "The release seq of the list in use (0: none).");
    for (int k = 0; k < 2; k++)
        one(w, "espdns_blocklist_seq", "list", LIST[k], b.list[k].seq);
    mx_family(w, "espdns_blocklist_bytes", "gauge", "Bytes the list in use takes.");
    for (int k = 0; k < 2; k++)
        one(w, "espdns_blocklist_bytes", "list", LIST[k], b.list[k].bytes);
    mx_family(w, "espdns_blocking_paused_seconds", "gauge", "Time left of a pause (0: not paused).");
    mx_u64(w, "espdns_blocking_paused_seconds", "", b.paused_s);
    mx_family(w, "espdns_blocking_decisions_total", "counter",
              "Names blocked (by name, or by a CNAME target in the answer) and allowed by the overrides.");
    one(w, "espdns_blocking_decisions_total", "decision", "blocked", b.blocked);
    one(w, "espdns_blocking_decisions_total", "decision", "cname_blocked", b.cname_blocked);
    one(w, "espdns_blocking_decisions_total", "decision", "allowed", b.allowed);
    mx_family(w, "espdns_blocking_sector_reads_total", "counter", "Sectors read from SD for the SD tier.");
    mx_u64(w, "espdns_blocking_sector_reads_total", "", b.sector_reads);
    mx_family(w, "espdns_blocking_errors_total", "counter", "Sector reads that failed.");
    mx_u64(w, "espdns_blocking_errors_total", "", b.errors);
}

/* One zone's values, copied out under the registry's read lock (never held while sending). */
typedef struct {
    char name[256];
    uint32_t serial, records, transfers, fails;
    bool expired, loaded;
} zone_row_t;

static bool secondary_row(int i, zone_row_t *r)
{
    reg_rdlock();
    bool ok = i < reg_nslots();
    if (ok) {
        const zslot_t *z = reg_slot(i);
        snprintf(r->name, sizeof(r->name), "%s", z->name);
        r->loaded = z->z != NULL;
        r->serial = z->z ? z->z->serial : 0;
        r->records = z->z ? (uint32_t)z->z->n : 0;
        r->transfers = z->transfers;
        r->fails = z->fails;
        r->expired = z->expired;
    }
    reg_unlock();
    return ok;
}

static bool hosted_row(int i, zone_row_t *r)
{
    reg_rdlock();
    const hz_set_t *s = reg_hosted();
    bool ok = s && i < s->n;
    if (ok) {
        dns_name_to_str(s->z[i]->apex, r->name, sizeof(r->name));
        r->loaded = true;
        r->serial = s->z[i]->serial;
        r->records = (uint32_t)s->z[i]->n;
        r->transfers = r->fails = 0;
        r->expired = false;
    }
    reg_unlock();
    return ok;
}

typedef enum { Z_SERIAL, Z_RECORDS, Z_TRANSFERS, Z_FAILS, Z_EXPIRED } zfield_t;

static void zone_family(mx_t *w, const char *name, const char *type, const char *help, zfield_t f, bool hosted_too)
{
    mx_family(w, name, type, help);
    zone_row_t r;
    for (int kind = 0; kind < (hosted_too ? 2 : 1); kind++)
        for (int i = 0; kind ? hosted_row(i, &r) : secondary_row(i, &r); i++) {
            uint64_t v = f == Z_SERIAL ? r.serial : f == Z_RECORDS ? r.records : f == Z_TRANSFERS ? r.transfers
                         : f == Z_FAILS ? r.fails : r.expired;
            char lb[MX_LABELS_MAX] = "";
            mx_label(lb, "zone", r.name);
            mx_label(lb, "kind", kind ? "hosted" : "secondary");
            mx_u64(w, name, lb, v);
        }
}

static void zones(mx_t *w)
{
    reg_rdlock();
    const hz_set_t *hs = reg_hosted();
    int nsec = reg_nslots(), nhosted = hs ? hs->n : 0, nfwd = reg_nfzones();
    size_t hosted_bytes = hs ? hs->mem : 0;
    reg_unlock();
    mx_family(w, "espdns_zones", "gauge", "Zones the node serves, by kind (forward: conditional forwarders).");
    one(w, "espdns_zones", "kind", "secondary", (uint64_t)nsec);
    one(w, "espdns_zones", "kind", "hosted", (uint64_t)nhosted);
    one(w, "espdns_zones", "kind", "forward", (uint64_t)nfwd);
    zone_family(w, "espdns_zone_serial", "gauge", "Each zone's SOA serial (0: a secondary zone not loaded).",
                Z_SERIAL, true);
    zone_family(w, "espdns_zone_records", "gauge", "Records in each zone.", Z_RECORDS, true);
    zone_family(w, "espdns_zone_transfers_total", "counter", "Transfers of each secondary zone since boot.",
                Z_TRANSFERS, false);
    zone_family(w, "espdns_zone_refresh_failures", "gauge",
                "SOA checks or transfers of each secondary zone that failed in a row.", Z_FAILS, false);
    zone_family(w, "espdns_zone_expired", "gauge", "1 while a secondary zone is past its SOA EXPIRE.", Z_EXPIRED,
                false);
    mx_family(w, "espdns_hosted_zones_bytes", "gauge", "Memory the hosted zones take (limit: memory.hosted_zones_kb).");
    mx_u64(w, "espdns_hosted_zones_bytes", "", hosted_bytes);
    mx_family(w, "espdns_hosted_zones_loaded", "gauge", "1 while the hosted zones service runs with a bundle.");
    mx_u64(w, "espdns_hosted_zones_loaded", "", hosted_state() == SVC_RUNNING && hs != NULL);
}

static void memory(mx_t *w)
{
    svc_state_t st[SVC_N];
    size_t planned[SVC_N], held[SVC_N];
    services_snapshot(st, planned, held);
    mx_family(w, "espdns_service_state", "gauge", "Each service, with its state (off, starting, running, failed): 1.");
    for (int i = 0; i < SVC_N; i++) {
        char lb[MX_LABELS_MAX] = "";
        mx_label(lb, "service", svc_name(i));
        mx_label(lb, "state", svc_state_name(st[i]));
        mx_u64(w, "espdns_service_state", lb, 1);
    }
    mx_family(w, "espdns_service_memory_planned_bytes", "gauge", "Each service's share of the memory plan.");
    for (int i = 0; i < SVC_N; i++)
        one(w, "espdns_service_memory_planned_bytes", "service", svc_name(i), planned[i]);
    mx_family(w, "espdns_service_memory_allocated_bytes", "gauge", "What each service holds now.");
    for (int i = 0; i < SVC_N; i++)
        one(w, "espdns_service_memory_allocated_bytes", "service", svc_name(i), held[i]);

    const mp_plan_t *p = share_plan();
    static const char *const POOL[MP_NPOOLS] = { "internal", "psram" };
    mx_family(w, "espdns_memory_capacity_bytes", "gauge", "What the services may plan in each pool (board data).");
    for (int k = 0; k < MP_NPOOLS; k++)
        one(w, "espdns_memory_capacity_bytes", "pool", POOL[k], p->capacity[k]);
    mx_family(w, "espdns_memory_planned_bytes", "gauge", "What the running services' plan takes in each pool.");
    for (int k = 0; k < MP_NPOOLS; k++)
        one(w, "espdns_memory_planned_bytes", "pool", POOL[k], p->total[k]);
    /* Observed, for monitoring only: nothing is sized from these. */
    static const uint32_t CAPS[MP_NPOOLS] = { MALLOC_CAP_INTERNAL, MALLOC_CAP_SPIRAM };
    mx_family(w, "espdns_heap_free_bytes", "gauge", "Heap free now, per pool (observed; nothing is sized from it).");
    for (int k = 0; k < MP_NPOOLS; k++)
        one(w, "espdns_heap_free_bytes", "pool", POOL[k], heap_caps_get_free_size(CAPS[k]));
    mx_family(w, "espdns_heap_min_free_bytes", "gauge", "The least heap free since boot, per pool (observed).");
    for (int k = 0; k < MP_NPOOLS; k++)
        one(w, "espdns_heap_min_free_bytes", "pool", POOL[k], heap_caps_get_minimum_free_size(CAPS[k]));
}

static void cpu_and_log(mx_t *w)
{
    power_info_t pi;
    power_info(&pi);
    mx_family(w, "espdns_cpu_mhz", "gauge", "The CPU clock: max (while working) and idle (what it drops to).");
    one(w, "espdns_cpu_mhz", "clock", "max", (uint64_t)pi.max_mhz);
    one(w, "espdns_cpu_mhz", "clock", "idle", (uint64_t)pi.idle_mhz);
    mx_family(w, "espdns_cpu_dfs", "gauge", "1 while idle clock scaling is on.");
    mx_u64(w, "espdns_cpu_dfs", "", pi.dfs);
    mx_family(w, "espdns_cpu_busy_seconds_total", "counter",
              "Time the full clock was held: dns (answering queries), work (loads, transfers, releases).");
    static const char *const HOLD[POWER_NHOLDS] = { "dns", "work" };
    for (int i = 0; i < POWER_NHOLDS; i++) {
        char lb[MX_LABELS_MAX] = "";
        mx_label(lb, "hold", HOLD[i]);
        mx_seconds(w, "espdns_cpu_busy_seconds_total", lb, pi.busy_us[i]);
    }

    uint32_t capacity;
    uint64_t first, next;
    querylog_ring_info(&capacity, &first, &next);
    mx_family(w, "espdns_querylog_enabled", "gauge", "1 while the query log runs.");
    mx_u64(w, "espdns_querylog_enabled", "", querylog_state() == SVC_RUNNING);
    mx_family(w, "espdns_querylog_capacity", "gauge", "Queries the query log's ring holds (memory.querylog_kb).");
    mx_u64(w, "espdns_querylog_capacity", "", capacity);
    mx_family(w, "espdns_querylog_entries", "gauge", "Queries in the ring now.");
    mx_u64(w, "espdns_querylog_entries", "", next - first);
    mx_family(w, "espdns_querylog_seq", "gauge", "The newest entry's seq (starts over at a reboot).");
    mx_u64(w, "espdns_querylog_seq", "", next - 1);
}

esp_err_t metrics_get(httpd_req_t *req)
{
    char *buf = malloc(CHUNK);
    if (!buf)
        return httpd_resp_send_500(req);
    httpd_resp_set_type(req, "text/plain; version=0.0.4; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    mx_t w;
    sender_t snd = { .req = req, .err = ESP_OK };
    mx_init(&w, buf, CHUNK, send_chunk, &snd);
    node(&w);
    queries(&w);
    cache(&w);
    blocking(&w);
    zones(&w);
    memory(&w);
    cpu_and_log(&w);
    mx_end(&w);
    free(buf);
    /* A failed chunk ends the reply: the server closes the connection on the error. */
    return snd.err != ESP_OK ? snd.err : httpd_resp_send_chunk(req, NULL, 0);
}
