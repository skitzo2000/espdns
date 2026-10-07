#include "metrics.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void mx_init(mx_t *w, char *buf, size_t cap, mx_flush_fn flush, void *ctx)
{
    *w = (mx_t){ .buf = buf, .cap = cap, .flush = flush, .ctx = ctx };
}

void mx_end(mx_t *w)
{
    if (w->n && w->flush)
        w->flush(w->ctx, w->buf, w->n);
    w->n = 0;
}

/* Room for one more line. */
static void room(mx_t *w)
{
    if (w->cap - w->n < MX_LINE_MAX)
        mx_end(w);
}

/* Appends a formatted line, cut at MX_LINE_MAX (never more than the buffer has). */
static void line(mx_t *w, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void line(mx_t *w, const char *fmt, ...)
{
    room(w);
    size_t left = w->cap - w->n, limit = left < MX_LINE_MAX ? left : MX_LINE_MAX;
    if (limit < 2)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(w->buf + w->n, limit, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    w->n += (size_t)n < limit ? (size_t)n : limit - 1;
    if (w->n && w->buf[w->n - 1] != '\n' && w->n < w->cap)
        w->buf[w->n++] = '\n'; /* a line cut short still ends */
}

void mx_family(mx_t *w, const char *name, const char *type, const char *help)
{
    line(w, "# HELP %s %s\n", name, help);
    line(w, "# TYPE %s %s\n", name, type);
}

void mx_label(char *lb, const char *name, const char *value)
{
    size_t n = strlen(lb);
    int k = snprintf(lb + n, MX_LABELS_MAX - n, "%s%s=\"", n ? "," : "", name);
    if (k < 0 || (size_t)k >= MX_LABELS_MAX - n)
        return;
    n += (size_t)k;
    for (const char *p = value; *p && n + 3 < MX_LABELS_MAX; p++) {
        if (*p == '\\' || *p == '"') {
            lb[n++] = '\\';
            lb[n++] = *p;
        } else if (*p == '\n') {
            lb[n++] = '\\';
            lb[n++] = 'n';
        } else {
            lb[n++] = *p;
        }
    }
    if (n + 1 < MX_LABELS_MAX)
        lb[n++] = '"';
    lb[n] = 0;
}

void mx_u64(mx_t *w, const char *name, const char *lb, uint64_t v)
{
    if (lb && *lb)
        line(w, "%s{%s} %llu\n", name, lb, (unsigned long long)v);
    else
        line(w, "%s %llu\n", name, (unsigned long long)v);
}

void mx_i64(mx_t *w, const char *name, const char *lb, int64_t v)
{
    if (lb && *lb)
        line(w, "%s{%s} %lld\n", name, lb, (long long)v);
    else
        line(w, "%s %lld\n", name, (long long)v);
}

void mx_seconds(mx_t *w, const char *name, const char *lb, uint64_t us)
{
    unsigned long long s = us / 1000000, f = us % 1000000;
    if (lb && *lb)
        line(w, "%s{%s} %llu.%06llu\n", name, lb, s, f);
    else
        line(w, "%s %llu.%06llu\n", name, s, f);
}

void mx_hist(mx_t *w, const char *name, const char *lb, const st_hist_t *h)
{
    uint64_t cum[ST_NBUCKETS], sum;
    st_hist_read(h, cum, &sum);
    bool any = lb && *lb;
    for (int b = 0; b < ST_NBUCKETS; b++)
        line(w, "%s_bucket{%s%sle=\"%s\"} %llu\n", name, any ? lb : "", any ? "," : "", ST_BUCKET_LE[b],
             (unsigned long long)cum[b]);
    char n[96];
    snprintf(n, sizeof(n), "%s_sum", name);
    mx_seconds(w, n, lb, sum);
    snprintf(n, sizeof(n), "%s_count", name);
    mx_u64(w, n, lb, cum[ST_NBUCKETS - 1]);
}

/* An IPv4 address (network order) as text. */
static void ipv4(uint32_t a, char ip[16])
{
    const uint8_t *b = (const uint8_t *)&a;
    snprintf(ip, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* name{k="v"} value: one label. */
static void one(mx_t *w, const char *name, const char *k, const char *v, uint64_t value)
{
    char lb[MX_LABELS_MAX] = "";
    mx_label(lb, k, v);
    mx_u64(w, name, lb, value);
}

typedef enum { UP_QUERIES, UP_FAILURES, UP_TIMEOUTS } up_field_t;

static void up_family(mx_t *w, const st_t *st, const char *name, const char *help, up_field_t f)
{
    mx_family(w, name, "counter", help);
    for (int i = 0; i < ST_UPSTREAMS; i++) {
        uint32_t a = __atomic_load_n(&st->up[i].addr, __ATOMIC_ACQUIRE);
        if (!a)
            break;
        const st_upstream_t *u = &st->up[i];
        const uint32_t *v = f == UP_QUERIES ? &u->queries : f == UP_FAILURES ? &u->failures : &u->timeouts;
        char ip[16];
        ipv4(a, ip);
        one(w, name, "upstream", ip, __atomic_load_n(v, __ATOMIC_RELAXED));
    }
    uint32_t oq = __atomic_load_n(&st->other_queries, __ATOMIC_RELAXED);
    if (oq) {
        uint32_t ov = f == UP_QUERIES ? oq
                      : f == UP_FAILURES ? __atomic_load_n(&st->other_failures, __ATOMIC_RELAXED)
                                         : __atomic_load_n(&st->other_timeouts, __ATOMIC_RELAXED);
        one(w, name, "upstream", "other", ov);
    }
}

void mx_upstreams(mx_t *w, const st_t *st)
{
    up_family(w, st, "espdns_upstream_queries_total", "Attempts at each forwarder (each server tried, each retry).",
              UP_QUERIES);
    up_family(w, st, "espdns_upstream_failures_total", "Attempts at each forwarder that got no answer, or SERVFAIL.",
              UP_FAILURES);
    up_family(w, st, "espdns_upstream_timeouts_total",
              "Attempts at each forwarder with no answer within the try's timeout (upstream_timeout_ms): of its "
              "failures.",
              UP_TIMEOUTS);
    mx_family(w, "espdns_upstream_duration_seconds", "histogram", "Time each forwarder took to answer.");
    for (int i = 0; i < ST_UPSTREAMS; i++) {
        uint32_t a = __atomic_load_n(&st->up[i].addr, __ATOMIC_ACQUIRE);
        if (!a)
            break;
        char ip[16], lb[MX_LABELS_MAX] = "";
        ipv4(a, ip);
        mx_label(lb, "upstream", ip);
        mx_hist(w, "espdns_upstream_duration_seconds", lb, &st->up[i].latency);
    }
}

void mx_forward(mx_t *w, const upq_stats_t *s, bool (*zone)(void *ctx, int i, char *name, size_t cap), void *ctx)
{
    static const char *const KIND[UPQ_KINDS] = { "default", "zones" };
    const flight_counts_t *t = &s->table;
    mx_family(w, "espdns_fwd_slots", "gauge",
              "Upstream queries the node may have outstanding at once (memory.fwd_pending).");
    mx_u64(w, "espdns_fwd_slots", "", t->slots);
    mx_family(w, "espdns_fwd_group_cap", "gauge",
              "The most of them one group may hold: the default forwarders, a forward zone, and the forward zones "
              "together.");
    mx_u64(w, "espdns_fwd_group_cap", "", t->group_cap);
    mx_family(w, "espdns_fwd_inflight", "gauge",
              "Upstream queries outstanding now: to the default forwarders, and to the forward zones together.");
    one(w, "espdns_fwd_inflight", "group", KIND[UPQ_DEFAULT], t->held[FLIGHT_GROUP_DEFAULT]);
    one(w, "espdns_fwd_inflight", "group", KIND[UPQ_ZONES], t->zones_held);
    mx_family(w, "espdns_fwd_inflight_peak", "gauge", "The most upstream queries outstanding at once since boot.");
    mx_u64(w, "espdns_fwd_inflight_peak", "", t->peak);
    mx_family(w, "espdns_fwd_zone_inflight", "gauge", "Upstream queries outstanding now, per forward zone.");
    char name[256];
    for (int i = 0; zone && i < FLIGHT_GROUPS - 1 && zone(ctx, i, name, sizeof(name)); i++)
        one(w, "espdns_fwd_zone_inflight", "zone", name, t->held[FLIGHT_GROUP_ZONE(i)]);
    mx_family(w, "espdns_fwd_shed_total", "counter",
              "Queries answered SERVFAIL at once: their group, or the table, was at its cap.");
    for (int k = 0; k < UPQ_KINDS; k++)
        one(w, "espdns_fwd_shed_total", "group", KIND[k], s->shed[k]);
    mx_family(w, "espdns_fwd_expired_total", "counter",
              "Upstream queries that ended with no answer: every try, or the budget, spent.");
    for (int k = 0; k < UPQ_KINDS; k++)
        one(w, "espdns_fwd_expired_total", "group", KIND[k], s->expired[k]);
    mx_family(w, "espdns_fwd_tcp_retries_total", "counter", "Truncated answers asked again over TCP.");
    mx_u64(w, "espdns_fwd_tcp_retries_total", "", s->tcp_retries);
    mx_family(w, "espdns_fwd_select_errors_total", "counter",
              "Times the forward loop's select() failed (it waits, longer each time in a row).");
    mx_u64(w, "espdns_fwd_select_errors_total", "", s->select_errors);
}
