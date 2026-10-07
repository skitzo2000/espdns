/*
 * The pending table: the upstream queries outstanding at once, one per question (name, type,
 * class, CD), and the queries waiting on each.
 *
 * A query the cache can't answer opens a flight for its question, or joins the one open for
 * it, and waits on it either way: when a popular forwarded name's cache entry expires, every
 * query for it misses at once, and they share one upstream query instead of each asking. The
 * flight's owner (the forward loop, fwdq.h, then the DNS worker that takes it from there) asks
 * upstream and ends it with the answer, or its failure (flight_end); each waiting query, the
 * one that opened it among them, is answered from that. A flight has one deadline, set when it
 * opens: its upstream query's whole budget (flight_wait_ms). That is every waiter's deadline:
 * the forward loop ends every query by its budget, before it, and a flight still open past it
 * can be ended as failed (flight_expire), its waiters answered SERVFAIL, as queries whose
 * forwarders didn't answer in time.
 *
 * Waiters come in two kinds:
 *   - a UDP query: its item from the UDP receive pool (server.c), parked here off the
 *     worker. Ending the flight hands the parked items back, in the order they joined, for
 *     the caller to answer. At most max_waiting are parked in all, as each holds an item.
 *   - a TCP query (flight_tcp_t): its own TCP worker blocks until the flight ends. Ending it
 *     copies the answer into the waiter's buffer and wakes it (its wake function, called
 *     under the table's lock). A TCP waiter that gives up first takes itself off
 *     (flight_cancel); that and the flight ending are decided under the lock, so exactly one
 *     of them happens.
 *
 * Groups and caps. Each flight belongs to a group: the default forwarders, or forward zone i.
 * So that one dead forwarder can't take the whole table, a group holds at most half the
 * slots and half the parked queries, and the forward zones together at most half as well:
 * the default forwarders always keep half the table. A query past a cap, or with the table
 * full, gets FLIGHT_FULL: it is answered SERVFAIL at once, which costs nothing else.
 *
 * What the table holds is counted for /metrics and health (flight_counts): the slots each
 * group holds, the most held at once, and whether the default forwarders have held more than
 * half their cap, and since when (health.h, "forwarders slow").
 *
 * A slot holds the question, the group, the upstream query's state (fwd_up_t: its servers
 * and timeout, the try under way and its deadline, the query's ID and socket), the cache
 * generation the query was routed under and whether its CNAMEs go through blocking, and an
 * answer buffer (MP_UDP_OUT): what the upstream query's owner needs to drive it and to
 * complete the flight. A slot is held from flight_begin until its owner frees it
 * (flight_free), also after the flight has ended, while its answer is used.
 *
 * Sizes from the board (memplan.h): memory.fwd_pending slots of MP_FWD_SLOT bytes, from the
 * DNS service's share; MP_FLIGHT_WAITERS parked UDP queries.
 *
 * The question is keyed as the cache keys it (cache.h): the name without regard to case,
 * the type, the class and CD; the DO bit isn't in it, as every upstream query asks with DO.
 *
 * Thread-safe. Portable C (pthreads), host tested.
 */
#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "dns_wire.h"
#include "forward.h"
#include "memplan.h"

/* Past the upstream query's budget: its answer is back and handed to the waiters a little
 * after its last try ends (the worker may wait for the CPU). */
#define FLIGHT_WAIT_MARGIN_MS 250

/* A flight's deadline from when it opens, ms: the whole upstream attempt, asking nservers
 * with timeout_ms (forward.h, fwd_budget_ms), and the margin. */
static inline uint32_t flight_wait_ms(int nservers, int timeout_ms)
{
    return fwd_budget_ms(nservers, timeout_ms) + FLIGHT_WAIT_MARGIN_MS;
}

/* The groups: the default forwarders, and each forward zone (its index in the registry). */
#define FLIGHT_GROUP_DEFAULT 0
#define FLIGHT_GROUP_ZONE(i) (1 + (i))
#define FLIGHT_GROUPS        (1 + CFG_MAX_FZONES)

/* A query waiting on a flight: embedded first in what the caller parks (server.c: the UDP
 * item; flight_tcp_t). */
typedef struct flight_waiter {
    struct flight_waiter *next;
    /* NULL: a parked UDP query, handed back when the flight ends. Else a TCP waiter
     * (flight_tcp_t), woken by this when the flight ends. Called under the table's lock: it
     * only signals, never calls into the table. */
    void (*wake)(struct flight_waiter *w);
} flight_waiter_t;

/* A TCP query waiting on a flight, on its worker's stack. The caller sets w.wake, buf and
 * cap; the table the rest. */
typedef struct {
    flight_waiter_t w;
    uint8_t *buf; /* where the answer is copied */
    size_t cap;
    int slot;     /* the flight it waits on */
    int len;      /* once done: the answer's length, or -1: none (failed, expired, too big) */
    bool done;    /* the flight ended: len is set, w.wake called (flight_tcp_done) */
} flight_tcp_t;

typedef enum {
    FLIGHT_FREE,
    FLIGHT_OPEN, /* asking upstream: joinable */
    FLIGHT_DONE, /* ended (answered, failed or expired), still held by its owner */
} flight_state_t;

/* One slot of the table. */
typedef struct {
    uint8_t state; /* flight_state_t */
    uint8_t group;
    uint8_t qlen;
    bool cd, cnames;
    uint16_t qtype, qclass;
    uint8_t name[DNS_MAX_NAME]; /* lowercase */
    uint32_t gen;               /* the cache's generation it was routed under (cache.h) */
    uint32_t opened_ms;         /* when it opened: how long its upstream query took (health.h) */
    uint32_t deadline_ms;       /* the whole budget: every waiter's deadline */
    /* The upstream query (forward.h), for its owner: its servers and timeout from
     * flight_begin, the rest as it is asked (fwdq.h). */
    fwd_up_t up;
    /* For the forward loop (fwdq.h), under its lock. */
    int16_t fq_next; /* the next slot on the fwdq queue it is on (-1: the last) */
    bool fq_fresh;   /* on the loop's queue to start (else to go on after a TCP retry) */
    flight_waiter_t *head, *tail; /* in the order they joined */
    uint16_t alen; /* the answer's length in answer; 0: none here (failed, or in fwdq's TCP buffer) */
    uint8_t answer[MP_UDP_OUT];
} flight_t;

/* What a query opens or joins a flight for. */
typedef struct {
    const uint8_t *qname;
    int qlen;
    uint16_t qtype, qclass;
    bool cd;
    int group;               /* FLIGHT_GROUP_DEFAULT or FLIGHT_GROUP_ZONE(i) */
    const uint32_t *servers; /* the forwarders asked (network order), nservers of them */
    int nservers;
    int timeout_ms; /* each try's */
    uint32_t gen;
    bool cnames;
} flight_query_t;

typedef struct {
    pthread_mutex_t lock;
    flight_t *f;
    int n;                /* slots */
    uint32_t max_waiting; /* parked UDP queries, in all */
    uint32_t waiting;     /* ...parked now; read without the lock by flight_waiting */
    uint16_t held[FLIGHT_GROUPS], parked[FLIGHT_GROUPS]; /* slots held, UDP queries parked */
    uint16_t zones_held, zones_parked;                  /* ...by the forward zones in all */
    uint16_t held_all, peak;   /* slots held in all, and the most at once since flights_init */
    bool busy;                 /* the default forwarders hold more than flight_busy_level */
    uint32_t busy_since_ms;    /* ...since (the flight_begin that took them past it) */
} flights_t;

/* Half of a cap, never 0. */
static inline uint32_t flight_half(uint32_t n) { return n / 2 ? n / 2 : 1; }
/* A group's cap of n slots (half the table), and the slots past which its group is busy:
 * more than half that. */
static inline uint32_t flight_group_cap(int n) { return flight_half(n > 0 ? (uint32_t)n : 0); }
static inline uint32_t flight_busy_level(int n) { return flight_half(flight_group_cap(n)); }

/* A copy of the table's counts. */
typedef struct {
    uint16_t held[FLIGHT_GROUPS]; /* slots held per group */
    uint16_t zones_held;          /* ...by the forward zones in all */
    uint16_t held_all, peak;      /* in all, now and the most at once */
    uint16_t slots, group_cap;    /* the table's size, and a group's cap */
    bool busy;                    /* the default forwarders past flight_busy_level... */
    uint32_t busy_since_ms;       /* ...since */
} flight_counts_t;

void flight_counts(flights_t *fl, flight_counts_t *c);

/* The table's memory for n slots. */
static inline size_t flights_bytes(int n) { return (size_t)n * sizeof(flight_t); }

/* mem: flights_bytes(n), from the DNS service's share (memory.fwd_pending slots, n >= 2);
 * max_waiting: MP_FLIGHT_WAITERS on the node; the tests give their own. */
void flights_init(flights_t *fl, void *mem, int n, uint32_t max_waiting);

typedef enum {
    FLIGHT_OPENED, /* a flight was opened (*slot) and w waits on it: ask upstream, flight_end,
                    * then flight_free */
    FLIGHT_JOINED, /* w waits on the flight open for q: no answer now */
    FLIGHT_FULL,   /* the table, or a cap, is full (or no w to join with): SERVFAIL */
} flight_role_t;

/* q's flight. None open: opens one (*slot) with a deadline wait_ms from now_ms, and w waits
 * on it (the caller hands the slot to be asked: fwdq_submit). One open: w waits on it. Either
 * way w is a UDP item, parked, or a flight_tcp_t, and *deadline_ms is the flight's deadline.
 * A slot past the table or its group's caps, or a parked UDP query past max_waiting or its
 * group's caps, is FLIGHT_FULL: nothing is opened or parked. w NULL (the tests): opens one
 * with no one waiting, or FLIGHT_FULL if one is open. */
flight_role_t flight_begin(flights_t *fl, const flight_query_t *q, flight_waiter_t *w, uint32_t now_ms,
                           uint32_t wait_ms, int *slot, uint32_t *deadline_ms);

/* The slot, for its owner: the question and the upstream query's state. */
flight_t *flight_slot(flights_t *fl, int slot);

/* The flight's answer is back (len > 0, answer), or it failed (len <= 0): ends it. Each TCP
 * waiter gets a copy (or -1 if it doesn't fit its buffer) and is woken; the parked UDP
 * queries are returned, in the order they joined, for the caller to answer from answer. The
 * slot stays held (flight_free). A flight already ended (expired) returns NULL. */
flight_waiter_t *flight_end(flights_t *fl, int slot, const uint8_t *answer, int len);

/* The owner is done with the slot: free for another. Its parked UDP queries, if the flight
 * was still open (ended as failed), are returned for SERVFAIL. */
flight_waiter_t *flight_free(flights_t *fl, int slot);

/* Ends as failed every open flight whose deadline has come (now_ms): their TCP waiters are
 * woken, their parked UDP queries returned for SERVFAIL. The slots stay held. */
flight_waiter_t *flight_expire(flights_t *fl, uint32_t now_ms);

/* A TCP waiter gives up, or makes sure it is done: true if it was taken off (no answer is
 * coming, nor a wake); false if the flight ended first (t->len is set, and t->w.wake has
 * returned: the table is done with t). */
bool flight_cancel(flights_t *fl, flight_tcp_t *t);

/* Whether a TCP waiter's flight has ended: then t->len is its answer's length. Its wake may
 * still be under way (it is set first): a waiter that saw it without waiting for the wake
 * calls flight_cancel (false) before it is done with t. */
bool flight_tcp_done(const flight_tcp_t *t);

/* The earliest deadline of an open flight a query waits on, if any. */
bool flight_next_deadline(flights_t *fl, uint32_t *deadline_ms);

/* Parked UDP queries in all. */
uint32_t flight_waiting(flights_t *fl);
