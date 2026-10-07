/*
 * Upstream queries: UDP with EDNS0, TCP retry on truncation, fail over across servers.
 * BSD sockets only, so it builds against lwIP and on a Linux host.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cfg.h"

uint32_t dns2_random(void);

/* Build a query with a fresh ID into out. Returns length. */
size_t fwd_build_query(uint8_t *out, size_t cap, uint16_t id, const uint8_t *qname, int qlen,
                       uint16_t qtype, uint16_t qclass, bool do_bit, bool cd, bool rd);

/* How one attempt at a server ended. */
typedef enum {
    FWD_TRY_ANSWER,   /* an answer that isn't SERVFAIL */
    FWD_TRY_SERVFAIL, /* SERVFAIL */
    FWD_TRY_TIMEOUT,  /* no answer within the try's timeout (the config's upstream_timeout_ms) */
    FWD_TRY_ERROR,    /* the query couldn't be sent, or its TCP retry got no answer */
} fwd_try_t;

/* Called after each attempt at a server (network order) with how it ended and how long it
 * took, µs: the forwarders' counters for /metrics (stats.h). NULL: nothing. On the node it is
 * called from the forward loop and its TCP task (fwdq.h) at once: it must be thread-safe
 * (stats.h's counters are atomic). */
void fwd_set_observer(void (*fn)(uint32_t server, fwd_try_t how, uint32_t us));

/* How fwd_query tries: each server FWD_TRIES_PER_SERVER times in turn (a, b, a, b), each try
 * over UDP waiting at most timeout_ms for its answer; a truncated answer is asked again over
 * TCP, the whole exchange (connect, query, answer) in FWD_TCP_TIMEOUT_MUL times timeout_ms. */
#define FWD_TRIES_PER_SERVER 2
#define FWD_TCP_TIMEOUT_MUL  2

/* How long fwd_query may take, ms, asking nservers with timeout_ms: every UDP try waiting out
 * its timeout, and one TCP retry's exchange (a truncated answer comes from a forwarder that
 * is up, so one is counted). fwd_query keeps to it: once it is spent no more is tried, and a
 * wait still going (a try, a TCP retry, more of them than counted) ends with it. So a query
 * parked on another's upstream query (flight.h) waits this long and is answered from it. */
static inline uint32_t fwd_budget_ms(int nservers, int timeout_ms)
{
    if (nservers < 1)
        nservers = 1;
    if (timeout_ms < 0)
        timeout_ms = 0;
    return (uint32_t)nservers * FWD_TRIES_PER_SERVER * (uint32_t)timeout_ms +
           FWD_TCP_TIMEOUT_MUL * (uint32_t)timeout_ms;
}

/* The clock the steps below keep time by: ms since boot (CLOCK_MONOTONIC), wrapping. */
uint32_t fwd_now_ms(void);

/* ---- one upstream query in steps (fwdq.h drives many at once) ----
 *
 * The same query fwd_query asks, cut into steps that never block but the TCP retry: send a
 * try, take an answer when its socket is readable, go on to the next try when its timeout
 * comes. Each try is FWD_TRIES_PER_SERVER times a server in turn, waiting at most
 * timeout_ms, all within fwd_budget_ms from the start; strays (from elsewhere, or not
 * answering the question) are dropped and never end or restart a try's wait. One socket and
 * one random ID for the whole query, its source port random too (fwd_bind_random), against
 * spoofing. Each try is reported to the observer (fwd_set_observer). Not thread-safe: one
 * owner at a time drives a query (the loop, or the TCP task while it retries). */

/* The question asked: the name (wire format) stays where it is while the query runs. */
typedef struct {
    const uint8_t *qname;
    int qlen;
    uint16_t qtype, qclass;
    bool cd;
} fwd_q_t;

typedef struct {
    uint32_t servers[CFG_MAX_FWD]; /* network order */
    uint8_t nservers;
    uint8_t attempt;     /* the try under way: servers[attempt % nservers] */
    uint16_t id;
    int timeout_ms;      /* each try's */
    int sock;            /* -1: none */
    uint32_t try_end_ms; /* the try's deadline (fwd_now_ms) */
    uint32_t end_ms;     /* the whole budget's */
    int64_t try_t0_us;   /* when the try began, for the observer */
} fwd_up_t;

typedef enum {
    FWD_WAIT,   /* the try under way waits for its answer: fwd_up_recv when the socket is
                 * readable, fwd_up_timeout at fwd_up_due */
    FWD_ANSWER, /* the answer is in: the buffer handed to fwd_up_answer */
    FWD_FAILED, /* no answer: every try is spent, or the budget, or no socket */
} fwd_step_t;

/* servers (n of them, at most CFG_MAX_FWD), each try timeout_ms; nothing is sent yet. */
void fwd_up_init(fwd_up_t *u, const uint32_t *servers, int n, int timeout_ms);

/* Starts at now_ms: a random ID, a non-blocking socket (below FD_SETSIZE, for select), the
 * first try sent (a try whose send fails is over at once: the next). FWD_WAIT, or
 * FWD_FAILED. */
fwd_step_t fwd_up_start(fwd_up_t *u, const fwd_q_t *q, uint32_t now_ms);

/* The socket is readable: reads what is there into buf (cap: a datagram's room, 1500),
 * dropping strays. Returns the length of the answer to the try under way (it may be
 * truncated, DNS_F_TC: then fwd_up_tcp), or 0: nothing for it yet. */
int fwd_up_recv(fwd_up_t *u, const fwd_q_t *q, uint8_t *buf, size_t cap);

/* The try under way ended at now_ms with ans (len > 0: from fwd_up_recv, or fwd_up_tcp), or
 * without one (len <= 0: a TCP retry that failed). FWD_ANSWER: ans is the answer. A SERVFAIL
 * with tries and budget left, or no answer, goes on to the next try: FWD_WAIT, or FWD_FAILED
 * if none is left (a SERVFAIL on the last try is the answer). */
fwd_step_t fwd_up_answer(fwd_up_t *u, const fwd_q_t *q, const uint8_t *ans, int len, uint32_t now_ms);

/* now_ms: if the try's deadline has come, it failed: the next try (FWD_WAIT), or FWD_FAILED.
 * Before it, FWD_WAIT. */
fwd_step_t fwd_up_timeout(fwd_up_t *u, const fwd_q_t *q, uint32_t now_ms);

/* When the try under way ends without an answer: fwd_up_timeout is due. */
static inline uint32_t fwd_up_due(const fwd_up_t *u) { return u->try_end_ms; }

/* The server the try under way asks. */
static inline uint32_t fwd_up_server(const fwd_up_t *u) { return u->servers[u->attempt % u->nservers]; }

/* The try's answer was truncated: asks it again over TCP from the try's server (blocking),
 * the whole exchange within FWD_TCP_TIMEOUT_MUL times the timeout and what the budget has
 * left at now_ms. The answer's length in out, or -1 (none, or one not answering the
 * question asked, with its ID). Then fwd_up_answer. */
int fwd_up_tcp(fwd_up_t *u, const fwd_q_t *q, uint8_t *out, size_t cap, uint32_t now_ms);

/* Done with it: its socket closed. */
void fwd_up_close(fwd_up_t *u);

/* Upstream queries' source ports: random in [FWD_PORT_MIN, 65535], so an off-path forger
 * must guess the port as well as the ID (lwIP hands out local ports in sequence after the
 * first). A port in use is passed over: FWD_BIND_TRIES ports, then the query fails. */
#define FWD_PORT_MIN   1024
#define FWD_BIND_TRIES 8

/* A random port of that range (dns2_random). */
uint16_t fwd_random_port(void);

/* Binds UDP socket s to a random source port on any address (fwd_random_port). */
bool fwd_bind_random(int s);

/* Ask servers (IPv4, network order) in turn (FWD_TRIES_PER_SERVER), within fwd_budget_ms:
 * the steps above, waited on one at a time. Always with DO: the answer carries its DNSSEC
 * records, so one cached copy serves clients with and without DO (cache.h). Returns
 * response length, or -1. Blocking: the node's DNS workers never call it (they hand their
 * queries to the forward loop, fwdq.h); the tests drive the steps with it. */
int fwd_query(const uint32_t *servers, int nservers, const uint8_t *qname, int qlen,
              uint16_t qtype, uint16_t qclass, bool cd,
              uint8_t *out, size_t cap, int timeout_ms);

/* One query over TCP to server:53, the whole exchange within timeout_ms. Returns response
 * length, or -1. */
int fwd_query_tcp(uint32_t server, const uint8_t *query, size_t qlen, uint8_t *out, size_t cap,
                  int timeout_ms);

/* Connect with a timeout; returns a blocking socket with SO_RCVTIMEO/SO_SNDTIMEO set, or -1. */
int tcp_connect_timeout(uint32_t server, uint16_t port, int timeout_ms);
bool tcp_read_full(int s, uint8_t *buf, size_t n);
bool tcp_write_full(int s, const uint8_t *buf, size_t n);
