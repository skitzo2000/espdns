/*
 * What the node's HTTP server (ota.c) checks before it serves a request, and the deadlines
 * that keep one slow client from holding it (docs/design.md, Controller ↔ node: the node's
 * HTTP server).
 *
 * The Host header. A request is served only if its Host names this node: its address
 * (dotted IPv4), its mDNS name (<hostname>.local), or the name in its node config, any of
 * them with a port. Anything else (another name, an IPv6 literal, no Host at all) is refused
 * with 421, so a web page whose name was rebound to a node's address (DNS rebinding) can't
 * read /status or /querylog through a browser on the LAN: the browser sends the page's own
 * name.
 *
 * Deadlines. Every receive and send on a connection runs against one deadline for the
 * request, not a timeout that starts over with each byte:
 *   - the request line and headers: HG_HEAD_MS from their first byte;
 *   - a GET's reply: HG_REPLY_MS from when its headers are in;
 *   - a release: its signed header (release.h) within HG_HEAD_MS of the HTTP headers, read
 *     and verified in the server's task like them, then the payload, once the header
 *     verifies (and only then: hg_gate), within hg_body_ms(its length).
 * A connection past its deadline is closed. So a client that trickles bytes holds the
 * server for at most HG_HEAD_MS (or HG_REPLY_MS) before it is dropped, and only a sender
 * whose release header verified (signed by a key the node trusts) gets the longer time a
 * payload needs.
 *
 * Portable (POSIX sockets, CLOCK_MONOTONIC): run on the host in the tests.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HG_HEAD_MS       5000  /* request line and headers; a release's signed header */
#define HG_REPLY_MS      15000 /* a GET's reply (/querylog's 1000 entries at 13 KB/s) */
#define HG_BODY_BASE_MS  10000 /* a verified payload: this, plus */
#define HG_BODY_MIN_BPS  4096  /* its length at this rate (a 2 MB image: 522 s) */

/* One connection's state. All zero: no request under way (the next byte starts one). */
typedef struct {
    int64_t deadline_ms; /* hg_now_ms() clock; 0: none set */
    bool closed;         /* past a deadline: every receive and send fails from then on */
} hg_conn_t;

/* Milliseconds on a monotonic clock. */
int64_t hg_now_ms(void);

/* The time a verified payload of len bytes may take. */
int64_t hg_body_ms(uint64_t len);

/* The request's deadline is now ms from now (a new phase: the reply, a release's header, its
 * payload). */
void hg_set(hg_conn_t *c, int64_t ms);
/* The request is over: the next byte received starts the next one's HG_HEAD_MS. */
void hg_done(hg_conn_t *c);
/* Milliseconds left before the deadline; one is started (HG_HEAD_MS) if none is set. 0 or
 * less: past it. */
int64_t hg_left_ms(hg_conn_t *c);

/* recv() and send() on fd against c's deadline: each call waits at most until the deadline,
 * and a short wait (the socket's timeout) is retried until then, never past it. Returns the
 * bytes moved, 0 if the peer closed (receive), or -1: an error, or past the deadline (and c
 * is closed from then on). */
int hg_recv(hg_conn_t *c, int fd, void *buf, size_t len, int flags);
int hg_send(hg_conn_t *c, int fd, const void *buf, size_t len, int flags);

/* Whether host (a Host header's value, NULL if none) names this node: ip (IPv4, network
 * order; 0 if it has none), mdns (its mDNS hostname, without ".local"; NULL or "" if none),
 * name (its configured name; NULL or "" if none). Case does not matter; a trailing dot and a
 * port are allowed. */
bool hg_host_ok(const char *host, uint32_t ip, const char *mdns, const char *name);

/* What a release whose signed header verified takes before its payload is read, in this
 * order: the update lock (if lock; the full clock with it), then, under the lock, its seq
 * checked again (another release of the kind may have recorded the same or a later one
 * since the header was checked: a replay of one in flight), then the worker. Nothing is
 * taken before the header verifies, so a sender without the key holds neither. */
typedef struct {
    bool (*take)(void);            /* the update lock; false: another holder has it */
    void (*give)(void);            /* gives it back */
    uint64_t (*seq)(uint8_t kind); /* the last seq applied of a kind */
    bool (*worker)(void);          /* the worker; false: taken */
} hg_locks_t;

typedef enum {
    HG_GO,    /* the lock (if asked for) and the worker are held */
    HG_BUSY,  /* another release holds the lock or the worker: nothing held (409) */
    HG_STALE, /* its seq is no longer above the last one applied: nothing held (403) */
} hg_gate_t;

hg_gate_t hg_gate(const hg_locks_t *l, bool lock, uint8_t kind, uint64_t seq);
