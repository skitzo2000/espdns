/*
 * Upstream queries, the DNS workers' side (issue #53): no worker ever waits on a forwarder.
 *
 * A query the cache can't answer opens a flight for its question (flight.h), or joins the one
 * open for it, and waits on it (upq_ask): a UDP query parked, its item handed to the flight
 * and its worker back to its queue at once; a TCP query on its own TCP worker. A flight
 * opened is handed to the forward loop (fwdq.h), which asks upstream for every flight at once
 * and ends each by its budget. A finished flight goes on the loop's done queue, and upq asks
 * the workers to take it (wake): a UDP worker takes the finished flights before each query
 * it answers (upq_take), and so does one woken with nothing else to do. Taking a flight:
 *   - notes the default forwarders' run of failures and whether it was slow (health.h: one
 *     upstream query, however many waited on it; slow: longer than one try's timeout, the
 *     config's upstream_timeout_ms), thread-safe: any worker may take a flight at any time;
 *     and counts it, per kind of group, if it ended unanswered (upq_stats)
 *   - caches its answer, under the cache generation the flight was routed under (cache.h)
 *     and only if its CNAMEs pass the blocking decision (cacheable), as the flight asked
 *   - ends the flight: its TCP waiters get a copy and are woken, its parked UDP queries
 *     are handed back, in the order they came, for the worker to answer from the answer,
 *     which stays in place (the slot, or the loop's TCP buffer) until upq_release.
 *
 * A query past the table's caps (FLIGHT_FULL) is counted as shed, per kind of group, and one
 * to the default forwarders is noted for health ("forwarders slow").
 *
 * Portable C (pthreads, BSD sockets): server.c runs it on the node, the tests on threads.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cache.h"
#include "flight.h"
#include "fwdq.h"
#include "health.h"

/* The kinds of group counted apart: the default forwarders, and the forward zones together
 * (a zone's index is its place in the config, which can change live). */
#define UPQ_DEFAULT 0
#define UPQ_ZONES   1
#define UPQ_KINDS   2
static inline int upq_kind(int group) { return group == FLIGHT_GROUP_DEFAULT ? UPQ_DEFAULT : UPQ_ZONES; }

typedef struct {
    flights_t fl;
    fwdq_t q;
    cache_t *cache; /* NULL: nothing cached */
    /* An answer whose CNAMEs go through blocking (the flight's cnames): cached only if this
     * says so. NULL: always. */
    bool (*cacheable)(const uint8_t *ans, size_t len);
    /* Asks a worker to take the finished flights (upq_take): false if it couldn't (every
     * worker is busy and its queue full: they take them before their next query anyway). */
    bool (*wake)(void *ctx);
    void *ctx;
    bool wake_pending; /* a wake is on its way: no other needed until upq_woken */
    health_upstream_t health; /* the default forwarders' run of failures, sheds, slow queries */
    uint32_t shed[UPQ_KINDS];    /* queries past the caps (FLIGHT_FULL), per kind of group */
    uint32_t expired[UPQ_KINDS]; /* flights that ended unanswered, per kind of group */
} upq_t;

/* For /metrics: the table's counts, and the counters, each as a 32-bit counter (it wraps). */
typedef struct {
    flight_counts_t table;
    uint32_t shed[UPQ_KINDS], expired[UPQ_KINDS];
    uint32_t tcp_retries, select_errors; /* the forward loop's (fwdq.h) */
} upq_stats_t;

void upq_stats(upq_t *u, upq_stats_t *s);

/* slots_mem: flights_bytes(nslots) (memory.fwd_pending slots); max_waiting: the parked UDP
 * queries in all (MP_FLIGHT_WAITERS); tcp_buf, tcp_cap: the loop's TCP retry buffer
 * (MP_FWD_TCP). False if the loop can't be set up (fwdq_init). The caller then runs
 * fwdq_run(&u->q) and fwdq_tcp_run(&u->q), each on a task of its own. */
bool upq_init(upq_t *u, void *slots_mem, int nslots, uint32_t max_waiting, uint8_t *tcp_buf, size_t tcp_cap,
              cache_t *cache, bool (*cacheable)(const uint8_t *ans, size_t len), bool (*wake)(void *ctx), void *ctx);

/* q's question, for a query that waits with w (a UDP item, or a flight_tcp_t) at now_ms:
 * FLIGHT_OPENED (a flight opened for it and handed to the loop) or FLIGHT_JOINED (one was
 * open), w waits on it until *deadline_ms at the latest; or FLIGHT_FULL: the table, or a
 * cap, is full (SERVFAIL at once), w isn't waiting: shed, counted. */
flight_role_t upq_ask(upq_t *u, const flight_query_t *q, flight_waiter_t *w, uint32_t now_ms,
                      uint32_t *deadline_ms);

/* A worker took a wake (before it takes the finished flights): the next flight to finish
 * wakes one again. */
void upq_woken(upq_t *u);

/* A flight taken from the done queue. */
typedef struct {
    int slot;
    const flight_t *f;       /* its question */
    const uint8_t *answer;   /* the answer, len bytes; len <= 0: none (every try failed) */
    int len;
    flight_waiter_t *parked; /* the parked UDP queries to answer from it, in the order they came */
} upq_done_t;

/* Takes a finished flight, if there is one, at now_ms (now_s for the cache): noted, cached
 * and ended, as above. The caller answers d->parked, then upq_release. */
bool upq_take(upq_t *u, upq_done_t *d, uint32_t now_ms, uint32_t now_s);

/* Done with d: its slot is free (and the loop's TCP buffer, if its answer was there). */
void upq_release(upq_t *u, upq_done_t *d);
