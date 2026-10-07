/*
 * Observability's portable parts: the query log's ring and its cursor, what a query's result
 * was, an entry's JSON (qlog.h); the counters for /metrics (stats.h) and the Prometheus text
 * (metrics.h, on tests/metrics_vector.txt, which the controller's parser reads too); the node
 * config's "querylog" and the memory plan's querylog_kb.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "board_def.h"
#include "cJSON.h"
#include "cfg.h"
#include "dns_wire.h"
#include "memplan.h"
#include "metrics.h"
#include "qlog.h"
#include "stats.h"
#include "svc.h"

static int s_fail;
#define CHECK(x)                                                         \
    do {                                                                 \
        if (!(x)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); \
            s_fail++;                                                    \
        }                                                                \
    } while (0)

static uint32_t ip4(const char *s)
{
    uint32_t a = 0;
    cfg_parse_ipv4(s, &a);
    return a;
}

static ql_entry_t entry(const char *name, uint16_t qtype)
{
    ql_entry_t e = { 0 };
    uint8_t w[DNS_MAX_NAME];
    int n = dns_name_from_str(name, w);
    ql_set_name(&e, w, n);
    e.qtype = qtype;
    return e;
}

/* ---- the ring and the cursor ---- */

static void test_ring(void)
{
    static uint8_t mem[160 * 4 + 100];
    ql_ring_t r;
    CHECK(ql_capacity(sizeof(mem)) == 4 && ql_capacity(159) == 0);
    CHECK(!ql_init(&r, mem, 100, 1) && r.n == 0);
    ql_entry_t e = entry("a.example", DNS_T_A), out;
    CHECK(ql_add(&r, &e) == 1 && !ql_get(&r, 1, &out)); /* no room: counted, not kept */
    CHECK(ql_init(&r, mem, sizeof(mem), 1) && r.n == 4 && r.first == 1 && r.next == 1);
    CHECK(!ql_get(&r, 1, &out) && !ql_get(&r, 0, &out));
    for (int i = 1; i <= 3; i++)
        CHECK(ql_add(&r, &e) == (uint64_t)i);
    CHECK(r.first == 1 && r.next == 4 && ql_get(&r, 1, &out) && out.seq == 1 && ql_get(&r, 3, &out) && out.seq == 3);
    CHECK(!ql_get(&r, 4, &out));
    /* Six more: 10 in all, the ring keeps 7-10. */
    for (int i = 4; i <= 10; i++)
        ql_add(&r, &e);
    CHECK(r.first == 7 && r.next == 11 && !ql_get(&r, 6, &out) && ql_get(&r, 7, &out) && out.seq == 7 &&
          ql_get(&r, 10, &out) && out.seq == 10 && out.qtype == DNS_T_A);

    /* The cursor: entries after it, how many were lost, a cursor from before a reboot. */
    ql_cursor_t c = ql_cursor(8, 7, 11);
    CHECK(c.from == 9 && c.lost == 0 && !c.reset);
    c = ql_cursor(10, 7, 11); /* up to date: nothing */
    CHECK(c.from == 11 && c.lost == 0 && !c.reset);
    c = ql_cursor(0, 7, 11); /* from the start: 1-6 overwritten */
    CHECK(c.from == 7 && c.lost == 6 && !c.reset);
    c = ql_cursor(6, 7, 11);
    CHECK(c.from == 7 && c.lost == 0 && !c.reset);
    c = ql_cursor(3, 7, 11);
    CHECK(c.from == 7 && c.lost == 3);
    c = ql_cursor(500, 7, 11); /* past the newest: the node started over */
    CHECK(c.from == 7 && c.lost == 0 && c.reset);
    c = ql_cursor(11, 7, 11);
    CHECK(c.reset && c.from == 7);
    c = ql_cursor(0, 1, 1); /* nothing logged yet */
    CHECK(c.from == 1 && !c.lost && !c.reset);
    c = ql_cursor(0, 1, 2);
    CHECK(c.from == 1 && !c.lost && !c.reset);

    /* Turned off and on: the ring starts empty, the numbers go on. */
    CHECK(ql_init(&r, mem, sizeof(mem), 11) && r.first == 11 && r.next == 11 && !ql_get(&r, 10, &out));
    CHECK(ql_add(&r, &e) == 11 && ql_get(&r, 11, &out));
    c = ql_cursor(10, r.first, r.next);
    CHECK(c.from == 11 && !c.lost);
    c = ql_cursor(4, r.first, r.next); /* 5-10 went with the ring that was stopped */
    CHECK(c.from == 11 && c.lost == 6);
}

/* ---- names and JSON ---- */

static void test_names(void)
{
    char j[QL_NAME_MAX * 5 + 8];
    uint8_t w[DNS_MAX_NAME];
    int n = dns_name_from_str("WWW.Example.COM", w);
    CHECK(ql_name_json(w, (size_t)n, j, sizeof(j)) == 15 && !strcmp(j, "www.example.com"));
    CHECK(ql_name_json((const uint8_t *)"", 1, j, sizeof(j)) == 1 && !strcmp(j, "."));
    /* A dot, a backslash and a quote in a label, a space and a byte past ASCII. */
    static const uint8_t odd[] = { 5, 'a', '.', 'b', '\\', '"', 3, 'x', ' ', 0xC3, 0 };
    ql_name_json(odd, sizeof(odd), j, sizeof(j));
    CHECK(!strcmp(j, "a\\\\.b\\\\\\\\\\\\\\\".x\\\\032\\\\195"));
    /* As JSON, that is the zone-file text a\.b\\\".x\032\195. */
    char doc[sizeof(j) + 4];
    snprintf(doc, sizeof(doc), "\"%s\"", j);
    cJSON *v = cJSON_Parse(doc);
    CHECK(v && cJSON_IsString(v) && !strcmp(v->valuestring, "a\\.b\\\\\\\".x\\032\\195"));
    cJSON_Delete(v);
    /* Cut short: still a string. */
    CHECK(ql_name_json(w, (size_t)n, j, 6) == 5 && !strcmp(j, "www.e"));

    /* A name longer than an entry keeps: its last labels, flagged. */
    char lng[300] = "";
    for (int i = 0; i < 6; i++)
        strcat(lng, "abcdefghijklmnopqrstuvwxyz0123456789.");
    strcat(lng, "example.com");
    ql_entry_t e = entry(lng, DNS_T_AAAA);
    CHECK((e.flags & QL_F_TRUNC) && e.name_len <= QL_NAME_MAX);
    ql_name_json(e.name, e.name_len, j, sizeof(j));
    CHECK(strlen(j) > 20 && !strcmp(j + strlen(j) - 12, ".example.com") && !strncmp(j, "abcdefghij", 10));
    e = entry("example.com", DNS_T_A);
    CHECK(!(e.flags & QL_F_TRUNC) && e.name_len == 13);
    char tb[12];
    CHECK(!strcmp(ql_type_name(65, tb), "HTTPS") && !strcmp(ql_type_name(4242, tb), "TYPE4242"));
    CHECK(!strcmp(ql_rcode_name(3, tb), "NXDOMAIN") && !strcmp(ql_rcode_name(12, tb), "RCODE12"));
}

static void test_entry_json(void)
{
    ql_entry_t e = entry("Ads.Example", DNS_T_A);
    e.seq = 42;
    e.t_ms = 5000;
    e.client = ip4("192.0.2.77");
    e.client_mode = QL_CLIENT_FULL;
    e.latency_us = 1234;
    e.result = QR_BLOCKED;
    e.rcode = 0;
    e.rule = QL_RULE_LIST;
    char j[QL_JSON_MAX];
    size_t n = ql_entry_json(&e, 6000, 1700000000000ULL, j, sizeof(j));
    CHECK(n == strlen(j));
    CHECK(!strcmp(j, "{\"seq\":42,\"uptime_ms\":5000,\"time\":1699999999000,\"client\":\"192.0.2.77\","
                     "\"transport\":\"udp\",\"qname\":\"ads.example\",\"qtype\":\"A\",\"result\":\"blocked\","
                     "\"rcode\":\"NOERROR\",\"latency_us\":1234,\"rule\":\"list\"}"));
    /* The clock not set, the client hidden, over TCP, no rule. */
    e.client = ql_client_addr(ip4("192.0.2.77"), QL_CLIENT_HIDDEN);
    e.client_mode = QL_CLIENT_HIDDEN;
    e.flags |= QL_F_TCP;
    e.rule = QL_RULE_NONE;
    e.result = QR_FORWARDED;
    e.rcode = 3;
    ql_entry_json(&e, 6000, 0, j, sizeof(j));
    CHECK(e.client == 0);
    CHECK(!strcmp(j, "{\"seq\":42,\"uptime_ms\":5000,\"time\":null,\"client\":null,\"transport\":\"tcp\","
                     "\"qname\":\"ads.example\",\"qtype\":\"A\",\"result\":\"forwarded\",\"rcode\":\"NXDOMAIN\","
                     "\"latency_us\":1234}"));
    /* Its /24 only. */
    CHECK(ql_client_addr(ip4("192.0.2.77"), QL_CLIENT_SUBNET) == ip4("192.0.2.0"));
    CHECK(ql_client_addr(ip4("192.0.2.77"), QL_CLIENT_FULL) == ip4("192.0.2.77"));
    CHECK(!strcmp(ql_client_name(QL_CLIENT_SUBNET), "subnet"));

    /* Every entry, however odd its name, is JSON, within QL_JSON_MAX. */
    uint8_t worst[DNS_MAX_NAME];
    size_t p = 0;
    while (p + 64 < sizeof(worst)) {
        worst[p++] = 63;
        memset(worst + p, '"', 63);
        p += 63;
    }
    worst[p++] = 0;
    ql_set_name(&e, worst, (int)p);
    e.rule = QL_RULE_OVERRIDE;
    e.flags |= QL_F_TRUNC;
    e.client_mode = QL_CLIENT_SUBNET;
    n = ql_entry_json(&e, 1, 1, j, sizeof(j));
    CHECK(n < sizeof(j) - 1);
    cJSON *v = cJSON_Parse(j);
    CHECK(v && cJSON_IsTrue(cJSON_GetObjectItem(v, "truncated")) &&
          !strcmp(cJSON_GetObjectItem(v, "rule")->valuestring, "override") &&
          strlen(cJSON_GetObjectItem(v, "qname")->valuestring) > 100);
    cJSON_Delete(v);
}

/* The client setting made stricter live applies to what the ring holds and to what is read:
 * an address logged in full is kept as the /24 or not at all from then on; one logged under
 * a stricter setting never comes back. */
static void test_privacy(void)
{
    static uint8_t mem[160 * 4];
    ql_ring_t r;
    CHECK(ql_init(&r, mem, sizeof(mem), 1));
    uint32_t a = ip4("192.0.2.77");
    ql_entry_t e = entry("a.example", DNS_T_A), out;
    e.client = ql_client_addr(a, QL_CLIENT_FULL);
    e.client_mode = QL_CLIENT_FULL;
    for (int i = 0; i < 6; i++)
        ql_add(&r, &e); /* 3-6 held */
    for (uint64_t seq = r.first; seq < r.next; seq++)
        ql_privacy(&r, seq, QL_CLIENT_SUBNET);
    ql_privacy(&r, 1, QL_CLIENT_HIDDEN); /* not held: nothing */
    ql_privacy(&r, 7, QL_CLIENT_HIDDEN);
    for (uint64_t seq = 3; seq <= 6; seq++)
        CHECK(ql_get(&r, seq, &out) && out.client == ip4("192.0.2.0") && out.client_mode == QL_CLIENT_SUBNET);
    ql_privacy(&r, 4, QL_CLIENT_HIDDEN);
    CHECK(ql_get(&r, 4, &out) && out.client == 0 && out.client_mode == QL_CLIENT_HIDDEN);
    char j[QL_JSON_MAX];
    ql_entry_json(&out, 1, 0, j, sizeof(j));
    CHECK(strstr(j, "\"client\":null"));
    /* Back to full: nothing logged under a stricter setting comes back. */
    ql_privacy(&r, 4, QL_CLIENT_FULL);
    ql_privacy(&r, 5, QL_CLIENT_FULL);
    CHECK(ql_get(&r, 4, &out) && out.client == 0 && out.client_mode == QL_CLIENT_HIDDEN);
    CHECK(ql_get(&r, 5, &out) && out.client == ip4("192.0.2.0") && out.client_mode == QL_CLIENT_SUBNET);
    /* As read (querylog_get): an entry written under the old setting, masked by the new. */
    e.seq = 9;
    ql_entry_privacy(&e, QL_CLIENT_HIDDEN);
    CHECK(e.client == 0 && e.client_mode == QL_CLIENT_HIDDEN);
    e.client = a;
    e.client_mode = QL_CLIENT_FULL;
    ql_entry_privacy(&e, QL_CLIENT_FULL);
    CHECK(e.client == a);
    ql_entry_privacy(&e, (ql_client_t)7); /* not a setting: the strictest */
    CHECK(e.client == 0);

    /* The note keeps the name as an entry does: its last labels, flagged. */
    char lng[300] = "";
    for (int i = 0; i < 6; i++)
        strcat(lng, "abcdefghijklmnopqrstuvwxyz0123456789.");
    strcat(lng, "example.com");
    uint8_t w[DNS_MAX_NAME];
    int wn = dns_name_from_str(lng, w);
    ql_note_t n = { 0 };
    ql_note_name(&n, w, wn);
    ql_entry_t want = { 0 };
    ql_set_name(&want, w, wn);
    CHECK(n.name_trunc && (want.flags & QL_F_TRUNC) && n.name_len == want.name_len && n.name_len <= QL_NAME_MAX &&
          !memcmp(n.name, want.name, n.name_len));
    wn = dns_name_from_str("www.example.com", w);
    ql_note_name(&n, w, wn);
    CHECK(!n.name_trunc && n.name_len == wn && !memcmp(n.name, w, (size_t)wn));
    ql_note_name(&n, w, 0);
    CHECK(!n.name_trunc && n.name_len == 0);
    CHECK(sizeof(ql_note_t) <= 136); /* on each worker's stack while a query is handled */
}

/* ---- results ---- */

static void test_results(void)
{
    ql_note_t n = { .parsed = true };
    CHECK(ql_result(&n, 0, 0) == QR_DROPPED);
    n.notify = true;
    CHECK(ql_result(&n, 0, 12) == QR_NOTIFY);
    n = (ql_note_t){ 0 };
    CHECK(ql_result(&n, DNS_R_FORMERR, 12) == QR_ERROR);
    n.parsed = true;
    CHECK(ql_result(&n, DNS_R_NOTIMP, 12) == QR_ERROR);
    CHECK(ql_result(&n, DNS_R_REFUSED, 12) == QR_REFUSED);
    CHECK(ql_result(&n, DNS_R_SERVFAIL, 12) == QR_SERVFAIL); /* a secondary zone expired */
    n.hosted = true;
    n.asked = n.answered = true; /* its CNAME followed upstream */
    n.rule = QL_RULE_CNAME;      /* checked, never blocked */
    CHECK(ql_result(&n, DNS_R_NOERROR, 40) == QR_HOSTED);
    n = (ql_note_t){ .parsed = true, .secondary = true };
    CHECK(ql_result(&n, DNS_R_NXDOMAIN, 40) == QR_SECONDARY);
    n = (ql_note_t){ .parsed = true, .rule = QL_RULE_LIST };
    CHECK(ql_result(&n, DNS_R_NOERROR, 40) == QR_BLOCKED);
    n.rule = QL_RULE_OVERRIDE;
    CHECK(ql_result(&n, DNS_R_NXDOMAIN, 40) == QR_OVERRIDDEN);
    n = (ql_note_t){ .parsed = true, .asked = true, .answered = true, .rule = QL_RULE_CNAME };
    CHECK(ql_result(&n, DNS_R_NOERROR, 40) == QR_BLOCKED);
    n.rule = QL_RULE_ALLOW;
    CHECK(ql_result(&n, DNS_R_NOERROR, 40) == QR_FORWARDED);
    n = (ql_note_t){ .parsed = true, .cache = true };
    CHECK(ql_result(&n, DNS_R_NXDOMAIN, 40) == QR_CACHE);
    n = (ql_note_t){ .parsed = true, .asked = true };
    CHECK(ql_result(&n, DNS_R_SERVFAIL, 40) == QR_SERVFAIL);
    for (int r = 0; r < QR_N; r++)
        CHECK(strcmp(ql_result_name(r), "unknown") != 0);
    CHECK(!strcmp(ql_result_name(QR_N), "unknown") && ql_rule_name(QL_RULE_NONE) == NULL);
}

/* ---- the counters ---- */

static st_t s_st;

static void *hammer(void *arg)
{
    for (int i = 0; i < 100000; i++) {
        st_query(&s_st, QR_FORWARDED, 0, 1500);
        st_upstream(&s_st, (uint32_t)(uintptr_t)arg, i % 10 != 0, i % 20 == 0, 2000);
    }
    return NULL;
}

static void test_stats(void)
{
    st_hist_t h = { 0 };
    uint64_t cum[ST_NBUCKETS], sum;
    st_hist_add(&h, 50);      /* le 0.0001 */
    st_hist_add(&h, 100);     /* le 0.0001: the bound is in */
    st_hist_add(&h, 101);     /* le 0.00025 */
    st_hist_add(&h, 3000000); /* +Inf */
    st_hist_read(&h, cum, &sum);
    CHECK(cum[0] == 2 && cum[1] == 3 && cum[ST_NBUCKETS - 2] == 3 && cum[ST_NBUCKETS - 1] == 4 && sum == 3000251);
    /* The sum carries past 32 bits. */
    h = (st_hist_t){ .sum_lo = 0xFFFFFFF0u };
    st_hist_add(&h, 0x20);
    st_hist_read(&h, cum, &sum);
    CHECK(sum == 0x100000010ULL && h.sum_hi == 1);

    /* Four workers at once, three forwarders between them, lock-free. */
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, hammer, (void *)(uintptr_t)(i % 3 + 1));
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
    CHECK(s_st.result[QR_FORWARDED] == 400000 && s_st.rcode[0] == 400000);
    st_hist_read(&s_st.latency, cum, &sum);
    CHECK(cum[ST_NBUCKETS - 1] == 400000 && sum == 400000ULL * 1500 && cum[3] == 0 && cum[4] == 400000);
    int slots = 0;
    uint32_t q = 0, f = 0, to = 0;
    for (int i = 0; i < ST_UPSTREAMS; i++)
        if (s_st.up[i].addr) {
            slots++;
            q += s_st.up[i].queries;
            f += s_st.up[i].failures;
            to += s_st.up[i].timeouts;
        }
    /* Of the failures (every tenth), the timeouts (every twentieth) */
    CHECK(slots == 3 && q == 400000 && f == 40000 && to == 20000 && s_st.other_queries == 0);
    /* An answer is never a timeout, whatever it is told. */
    st_upstream(&s_st, 1, true, true, 10);
    uint32_t to1 = 0;
    for (int i = 0; i < ST_UPSTREAMS; i++)
        to1 += s_st.up[i].timeouts;
    CHECK(to1 == to);
    /* More forwarders than slots: the rest count together. */
    for (uint32_t a = 100; a < 100 + ST_UPSTREAMS; a++)
        st_upstream(&s_st, a, false, a % 2, 10);
    CHECK(s_st.other_queries == 3 && s_st.other_failures == 3 && s_st.up[ST_UPSTREAMS - 1].addr != 0);
    CHECK(s_st.other_timeouts == 2); /* 113, 114 and 115 past the slots: two odd */
    /* A dropped query has no latency; an rcode out of range no rcode. */
    st_query(&s_st, QR_DROPPED, -1, 99);
    CHECK(s_st.result[QR_DROPPED] == 1);
    st_hist_read(&s_st.latency, cum, &sum);
    CHECK(cum[ST_NBUCKETS - 1] == 400000);
}

/* ---- the Prometheus text ---- */

static char s_out[65536];
static size_t s_out_n, s_flushes, s_biggest;

static void collect(void *ctx, const char *buf, size_t n)
{
    CHECK(s_out_n + n < sizeof(s_out));
    memcpy(s_out + s_out_n, buf, n);
    s_out_n += n;
    s_out[s_out_n] = 0;
    s_flushes++;
    if (n > s_biggest)
        s_biggest = n;
}

/* Two forward zones (mx_forward's names). */
static bool fzone(void *ctx, int i, char *name, size_t cap)
{
    static const char *const Z[] = { "corp.example.com", "lab.example.net" };
    if (i >= 2)
        return false;
    snprintf(name, cap, "%s", Z[i]);
    return true;
}

static void test_metrics_text(void)
{
    static char buf[2 * MX_LINE_MAX];
    mx_t w;
    s_out_n = s_flushes = s_biggest = 0;
    mx_init(&w, buf, sizeof(buf), collect, NULL);
    mx_family(&w, "espdns_zone_serial", "gauge", "Each zone's SOA serial.");
    char lb[MX_LABELS_MAX] = "";
    mx_label(lb, "zone", "a\"b\\c\nd");
    mx_label(lb, "kind", "hosted");
    mx_u64(&w, "espdns_zone_serial", lb, 2026100401);
    mx_u64(&w, "espdns_up", "", 1);
    mx_i64(&w, "espdns_wifi_rssi_dbm", "", -61);
    mx_seconds(&w, "espdns_uptime_seconds", "", 3723004005ULL);
    st_hist_t h = { 0 };
    st_hist_add(&h, 700);
    st_hist_add(&h, 1200000);
    mx_family(&w, "espdns_query_duration_seconds", "histogram", "Time to answer.");
    mx_hist(&w, "espdns_query_duration_seconds", "", &h);
    /* The forwarders, as the node writes them: one that answered twice and timed out once,
     * one that answered SERVFAIL. */
    static st_t st;
    uint32_t a1 = ip4("192.0.2.1"), a2 = ip4("192.0.2.2");
    st_upstream(&st, a1, true, false, 700);
    st_upstream(&st, a1, false, true, 1500000);
    st_upstream(&st, a2, false, false, 9000);
    st_upstream(&st, a1, true, false, 1200000);
    mx_upstreams(&w, &st);
    /* The forward loop (#53): its table, sheds, expiries, TCP retries and select() errors. */
    upq_stats_t us = { .table = { .slots = 32, .group_cap = 16, .zones_held = 3, .held_all = 7, .peak = 17 },
                       .shed = { 4, 1 }, .expired = { 2, 0 }, .tcp_retries = 6, .select_errors = 1 };
    us.table.held[FLIGHT_GROUP_DEFAULT] = 4;
    us.table.held[FLIGHT_GROUP_ZONE(0)] = 1;
    us.table.held[FLIGHT_GROUP_ZONE(1)] = 2;
    mx_forward(&w, &us, fzone, NULL);
    mx_end(&w);
    CHECK(s_biggest <= sizeof(buf));
    /* The shared vector: the controller's parser reads the same text (internal/fleet). */
    FILE *f = fopen("metrics_vector.txt", "r");
    static char want[sizeof(s_out)];
    size_t wn = f ? fread(want, 1, sizeof(want) - 1, f) : 0;
    if (f)
        fclose(f);
    want[wn] = 0;
    if (strcmp(s_out, want))
        fprintf(stderr, "metrics_vector.txt differs from the writer's output:\n%s", s_out);
    CHECK(wn && !strcmp(s_out, want));
    CHECK(strstr(s_out, "# HELP espdns_zone_serial Each zone's SOA serial.\n# TYPE espdns_zone_serial gauge\n"
                        "espdns_zone_serial{zone=\"a\\\"b\\\\c\\nd\",kind=\"hosted\"} 2026100401\n"
                        "espdns_up 1\nespdns_wifi_rssi_dbm -61\nespdns_uptime_seconds 3723.004005\n") == s_out);
    CHECK(strstr(s_out, "espdns_query_duration_seconds_bucket{le=\"0.0005\"} 0\n"
                        "espdns_query_duration_seconds_bucket{le=\"0.001\"} 1\n"));
    CHECK(strstr(s_out, "espdns_query_duration_seconds_bucket{le=\"1\"} 1\n"
                        "espdns_query_duration_seconds_bucket{le=\"2.5\"} 2\n"
                        "espdns_query_duration_seconds_bucket{le=\"+Inf\"} 2\n"
                        "espdns_query_duration_seconds_sum 1.200700\n"
                        "espdns_query_duration_seconds_count 2\n"));
    CHECK(strstr(s_out, "espdns_upstream_duration_seconds_bucket{upstream=\"192.0.2.1\",le=\"0.0001\"} 0\n"));
    CHECK(strstr(s_out, "espdns_upstream_duration_seconds_count{upstream=\"192.0.2.1\"} 2\n"));
    CHECK(strstr(s_out, "espdns_upstream_queries_total{upstream=\"192.0.2.1\"} 3\n"
                        "espdns_upstream_queries_total{upstream=\"192.0.2.2\"} 1\n"));
    CHECK(strstr(s_out, "espdns_upstream_failures_total{upstream=\"192.0.2.1\"} 1\n"
                        "espdns_upstream_failures_total{upstream=\"192.0.2.2\"} 1\n"));
    CHECK(strstr(s_out, "# TYPE espdns_upstream_timeouts_total counter\n"
                        "espdns_upstream_timeouts_total{upstream=\"192.0.2.1\"} 1\n"
                        "espdns_upstream_timeouts_total{upstream=\"192.0.2.2\"} 0\n"));
    CHECK(!strstr(s_out, "upstream=\"other\"")); /* none past the slots */
    CHECK(strstr(s_out, "espdns_upstream_duration_seconds_count{upstream=\"192.0.2.2\"} 0\n"));
    CHECK(strstr(s_out, "espdns_fwd_slots 32\n"));
    CHECK(strstr(s_out, "espdns_fwd_group_cap 16\n"));
    CHECK(strstr(s_out, "espdns_fwd_inflight{group=\"default\"} 4\nespdns_fwd_inflight{group=\"zones\"} 3\n"));
    CHECK(strstr(s_out, "espdns_fwd_inflight_peak 17\n"));
    CHECK(strstr(s_out, "espdns_fwd_zone_inflight{zone=\"corp.example.com\"} 1\n"
                        "espdns_fwd_zone_inflight{zone=\"lab.example.net\"} 2\n# HELP espdns_fwd_shed_total"));
    CHECK(strstr(s_out, "espdns_fwd_shed_total{group=\"default\"} 4\nespdns_fwd_shed_total{group=\"zones\"} 1\n"));
    CHECK(strstr(s_out, "espdns_fwd_expired_total{group=\"default\"} 2\nespdns_fwd_expired_total{group=\"zones\"} 0\n"));
    CHECK(strstr(s_out, "# TYPE espdns_fwd_tcp_retries_total counter\nespdns_fwd_tcp_retries_total 6\n"));
    CHECK(strstr(s_out, "espdns_fwd_select_errors_total 1\n"));
    CHECK(s_out[s_out_n - 1] == '\n');

    /* Many lines through a small buffer: handed on in pieces, nothing lost, none over. */
    size_t before = s_flushes;
    s_out_n = 0;
    mx_init(&w, buf, sizeof(buf), collect, NULL);
    for (int i = 0; i < 500; i++)
        mx_u64(&w, "espdns_test_total", "", (uint64_t)i);
    mx_end(&w);
    CHECK(s_flushes - before > 5 && s_biggest <= sizeof(buf));
    size_t lines = 0;
    for (size_t i = 0; i < s_out_n; i++)
        lines += s_out[i] == '\n';
    CHECK(lines == 500 && strstr(s_out, "espdns_test_total 499\n"));
    /* A label longer than the labels buffer is cut, still closed. */
    char big[2000];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = 0;
    lb[0] = 0;
    mx_label(lb, "zone", big);
    CHECK(strlen(lb) < MX_LABELS_MAX && lb[strlen(lb) - 1] == '"');
}

/* ---- the config and the memory plan ---- */

static void test_config_and_plan(void)
{
    static cfg_t c, d;
    char err[160];
    CHECK(cfg_build(&c, NULL, NULL, 0, err, sizeof(err)) && c.querylog && c.querylog_client == QL_CLIENT_FULL &&
          (svc_enabled(&c) & SVC_BIT(SVC_QUERYLOG)));
    const char *j = "{\"querylog\":{\"enabled\":false}}";
    CHECK(cfg_build(&c, NULL, j, strlen(j), err, sizeof(err)) && !c.querylog &&
          !(svc_enabled(&c) & SVC_BIT(SVC_QUERYLOG)));
    j = "{\"querylog\":{\"client\":\"subnet\"}}";
    CHECK(cfg_build(&d, NULL, j, strlen(j), err, sizeof(err)) && d.querylog && d.querylog_client == QL_CLIENT_SUBNET);
    j = "{\"querylog\":{\"client\":\"hidden\"}}";
    CHECK(cfg_build(&d, NULL, j, strlen(j), err, sizeof(err)) && d.querylog_client == QL_CLIENT_HIDDEN);
    j = "{\"querylog\":{\"client\":\"some\"}}";
    CHECK(!cfg_build(&d, NULL, j, strlen(j), err, sizeof(err)) && strstr(err, "querylog.client"));
    j = "{\"querylog\":{\"size\":10}}";
    CHECK(!cfg_build(&d, NULL, j, strlen(j), err, sizeof(err)) && strstr(err, "size"));
    j = "{\"querylog\":true}";
    CHECK(!cfg_build(&d, NULL, j, strlen(j), err, sizeof(err)));
    /* Live: on, off and the privacy setting, no reboot; the service starts and stops. */
    j = "{\"querylog\":{\"client\":\"hidden\"}}";
    CHECK(cfg_build(&d, NULL, j, strlen(j), err, sizeof(err)));
    CHECK(cfg_reboot_reasons(&c, &d) == 0);
    cfg_copy_live(&c, &d);
    CHECK(c.querylog && c.querylog_client == QL_CLIENT_HIDDEN);
    uint32_t stop, start;
    svc_changes(SVC_BIT(SVC_DNS), SVC_BIT(SVC_DNS) | SVC_BIT(SVC_QUERYLOG), &stop, &start);
    CHECK(start == SVC_BIT(SVC_QUERYLOG) && stop == 0);
    CHECK(!strcmp(svc_name(SVC_QUERYLOG), "querylog"));

    /* The board's querylog_kb: 0 is no query log; left out, the image's default. */
    board_desc_t b;
    j = "{\"name\":\"x\",\"image\":\"esp32s3-octal\",\"psram_mb\":8,\"memory\":{\"querylog_kb\":0}}";
    CHECK(board_def_parse(j, strlen(j), &b, err, sizeof(err)) && b.mem.querylog_kb == 0);
    j = "{\"name\":\"x\",\"image\":\"esp32s3-octal\",\"memory\":{\"querylog_kb\":70000}}";
    CHECK(!board_def_parse(j, strlen(j), &b, err, sizeof(err)) && strstr(err, "querylog_kb"));
    j = "{\"name\":\"x\",\"image\":\"esp32s3-octal\"}";
    CHECK(board_def_parse(j, strlen(j), &b, err, sizeof(err)) && b.mem.querylog_kb == -1);
    mp_board_t mb;
    mp_board(&b, "esp32s3-octal", 8192, &mb);
    CHECK(mb.querylog_kb == 64);
    mp_board(&b, "esp32p4", 32768, &mb);
    CHECK(mb.querylog_kb == 1024);
    mp_board(&b, "esp32s3-octal", 0, &mb); /* no PSRAM: no query log */
    CHECK(mb.querylog_kb == 0);
    mp_plan_t p;
    mp_board(&b, "esp32p4", 32768, &mb);
    mp_plan(&mb, SVC_BIT(SVC_DNS) | SVC_BIT(SVC_QUERYLOG), &p, err, sizeof(err));
    CHECK(p.share[SVC_QUERYLOG][MP_PSRAM] == 1024 * 1024 && p.share[SVC_QUERYLOG][MP_INTERNAL] == 0);
    mp_plan(&mb, SVC_BIT(SVC_DNS), &p, err, sizeof(err));
    CHECK(mp_share(&p, SVC_QUERYLOG) == 0);
    char js[1024];
    mp_json(&mb, &p, js, sizeof(js));
    CHECK(strstr(js, "\"querylog_kb\":1024,\"fwd_pending\":32}"));
    CHECK(sizeof(ql_entry_t) == MP_QUERYLOG_ENTRY && ql_capacity(1024 * 1024) == 6553 && ql_capacity(64 * 1024) == 409);
}

int main(void)
{
    test_ring();
    test_names();
    test_entry_json();
    test_privacy();
    test_results();
    test_stats();
    test_metrics_text();
    test_config_and_plan();
    if (s_fail) {
        fprintf(stderr, "%d check(s) failed\n", s_fail);
        return 1;
    }
    printf("observe: all tests passed\n");
    return 0;
}
