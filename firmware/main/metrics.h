/*
 * The Prometheus text exposition format (version 0.0.4) for GET /metrics (docs/design.md,
 * Observability; metrics_node.c gathers the values): a writer that fills a fixed buffer and
 * hands it on whenever the next line might not fit (the node sends each as an HTTP chunk),
 * so a reply of any length takes no more memory than the buffer.
 *
 * A family is its "# HELP" and "# TYPE" lines, then every sample of it. Label values are
 * escaped as the format says (backslash, double quote and newline); names are the caller's
 * constants. Values are integers, or microseconds written as seconds.
 *
 * Portable: run on the host in the tests.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "stats.h"
#include "upq.h"

#define MX_LINE_MAX 640 /* the longest line: a sample with its labels at their longest */

typedef void (*mx_flush_fn)(void *ctx, const char *buf, size_t n);

typedef struct {
    char *buf;
    size_t cap, n; /* cap at least 2 * MX_LINE_MAX */
    mx_flush_fn flush;
    void *ctx;
} mx_t;

void mx_init(mx_t *w, char *buf, size_t cap, mx_flush_fn flush, void *ctx);
/* Hands on what is left in the buffer. */
void mx_end(mx_t *w);

/* "# HELP name help" and "# TYPE name type" (counter, gauge, histogram). */
void mx_family(mx_t *w, const char *name, const char *type, const char *help);

/* Labels: lb is a buffer the caller keeps (MX_LABELS_MAX); mx_label appends name="value"
 * to it, escaped; "" is no labels. */
#define MX_LABELS_MAX 512
void mx_label(char *lb, const char *name, const char *value);

/* name{labels} value */
void mx_u64(mx_t *w, const char *name, const char *lb, uint64_t v);
void mx_i64(mx_t *w, const char *name, const char *lb, int64_t v);
/* name{labels} value, us microseconds as seconds ("0.001234") */
void mx_seconds(mx_t *w, const char *name, const char *lb, uint64_t us);
/* A histogram's samples (its family written before): name_bucket{labels,le="..."} for each
 * bucket, name_sum (seconds) and name_count. */
void mx_hist(mx_t *w, const char *name, const char *lb, const st_hist_t *h);

/* The forwarders' families, from the query path's counters (stats.h), in the order they were
 * first asked: espdns_upstream_queries_total, _failures_total, _timeouts_total (of the
 * failures, those with no answer within the try's timeout) and _duration_seconds, each per
 * upstream (its address; "other" for the forwarders past ST_UPSTREAMS). */
void mx_upstreams(mx_t *w, const st_t *st);

/* The forward loop's families (upq.h, fwdq.h): the upstream query table (its slots, a group's
 * cap, the slots held per kind of group and the most at once), the
 * queries shed and the upstream queries that ended unanswered per kind of group (group
 * "default" or "zones"), the TCP retries and select() errors. zone(ctx, i, name, cap) names
 * forward zone i (its group FLIGHT_GROUP_ZONE(i)) into name, false past the last: each one's
 * slots held, as espdns_fwd_zone_inflight{zone}. */
void mx_forward(mx_t *w, const upq_stats_t *s, bool (*zone)(void *ctx, int i, char *name, size_t cap), void *ctx);
