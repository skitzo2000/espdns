/*
 * Counters for /metrics that the query path keeps (docs/design.md, Observability): queries
 * by result and by rcode, how long answering took, and per forwarder its queries, failures
 * (and of them the timeouts) and how long it took to answer. Each is a 32-bit counter
 * added to with a relaxed atomic: lock-free on every chip, nothing allocated. A counter
 * wraps at 2^32, which Prometheus reads as a counter reset. The counters /status already
 * had stay where they are (server.c, blocking.c, cache.c) and /metrics reads them there.
 *
 * Latency is a histogram with fixed buckets (seconds, as Prometheus has it): 0.1, 0.25 and
 * 0.5 ms, 1, 2.5, 5, 10, 25, 50, 100, 250 and 500 ms, 1 and 2.5 s, and +Inf. Its sum is kept
 * in microseconds in two 32-bit words; a reader racing the carry may see it 2^32 µs low for
 * a moment, which also reads as a reset.
 *
 * Portable: run on the host in the tests.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qlog.h"

#define ST_NBUCKETS 15 /* with +Inf */
/* Each bucket's upper bound, µs (the last, +Inf, has none), and its "le" label. */
extern const uint32_t ST_BUCKET_US[ST_NBUCKETS - 1];
extern const char *const ST_BUCKET_LE[ST_NBUCKETS];

typedef struct {
    uint32_t count[ST_NBUCKETS]; /* in each bucket (not cumulative) */
    uint32_t sum_lo, sum_hi;     /* µs */
} st_hist_t;

void st_hist_add(st_hist_t *h, uint32_t us);
/* Cumulative counts per bucket (cum[ST_NBUCKETS-1] is the count), and the sum in µs. */
void st_hist_read(const st_hist_t *h, uint64_t cum[ST_NBUCKETS], uint64_t *sum_us);

/* Forwarders, by address: the first ST_UPSTREAMS asked get a slot each (the default
 * forwarders and the forward zones' are a few); any after them count together as "other". */
#define ST_UPSTREAMS 16
typedef struct {
    uint32_t addr; /* IPv4, network order; 0: free */
    uint32_t queries, failures;
    uint32_t timeouts; /* of the failures, those with no answer within the try's timeout */
    st_hist_t latency; /* the attempts it answered */
} st_upstream_t;

typedef struct {
    uint32_t result[QR_N];
    uint32_t rcode[16];
    st_hist_t latency;
    st_upstream_t up[ST_UPSTREAMS];
    uint32_t other_queries, other_failures, other_timeouts;
} st_t;

/* One query answered (or not: QR_DROPPED) with rcode (-1: no response), taking us. */
void st_query(st_t *s, ql_result_t r, int rcode, uint32_t us);
/* One attempt at forwarder addr: answered (ok) or not (timeout: no answer within the try's
 * timeout; else SERVFAIL, or not sent), taking us. */
void st_upstream(st_t *s, uint32_t addr, bool ok, bool timeout, uint32_t us);
