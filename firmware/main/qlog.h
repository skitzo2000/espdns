/*
 * The query log's portable core (docs/design.md, Observability): a fixed ring of recent
 * queries in memory the query log service took at its start (memory.querylog_kb, memplan.h),
 * read with a cursor; what a query's result was; and the JSON for one entry. querylog.c puts
 * it on the node (the lock, the service, GET /querylog).
 *
 * Every entry has a sequence number, one more than the entry before, from 1 at boot; the
 * ring holds the newest ql_capacity of them and overwrites the oldest. A reader asks for
 * the entries after a cursor (the last seq it has): those still in the ring come back
 * oldest first, and if the oldest it would need was overwritten, how many were lost. The
 * numbers go on across the service being turned off and on (the ring starts empty, the next
 * entry's seq where it was), and start over at a reboot: a reader tells by the boot ID
 * querylog.c reports with them, or by a cursor past the newest.
 *
 * Writing an entry is a bounded copy (sizeof(ql_entry_t)) into its slot: nothing is
 * allocated. The ring has no lock of its own: the caller serialises ql_add and ql_get (a
 * short critical section per entry on the node).
 *
 * Portable: run on the host in the tests.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What happened to a query, one of: */
typedef enum {
    QR_CACHE,      /* answered from the cache */
    QR_FORWARDED,  /* answered by a forwarder (default or a forward zone's) */
    QR_HOSTED,     /* answered from a hosted zone */
    QR_SECONDARY,  /* answered from a secondary zone */
    QR_BLOCKED,    /* blocked by the blocklist (the name, or a CNAME target in the answer) */
    QR_OVERRIDDEN, /* blocked by the overrides */
    QR_REFUSED,    /* refused: not recursion for this client, forwarding off, AXFR, a class not IN */
    QR_SERVFAIL,   /* the forwarders gave no answer, or a secondary zone expired */
    QR_ERROR,      /* malformed (FORMERR), or an opcode not implemented (NOTIMP) */
    QR_NOTIFY,     /* a NOTIFY from the primary */
    QR_DROPPED,    /* never answered: garbage, a response, or no worker free */
    QR_N
} ql_result_t;

/* Which rule decided a blocked or allowed name (blocking.c), if any. */
typedef enum { QL_RULE_NONE, QL_RULE_LIST, QL_RULE_OVERRIDE, QL_RULE_CNAME, QL_RULE_ALLOW, QL_RULE_N } ql_rule_t;

const char *ql_result_name(int r);
const char *ql_rule_name(int r); /* NULL for QL_RULE_NONE */

#define QL_NAME_MAX 124 /* the most of a query name (wire form) an entry keeps: its last labels */

/* What the DNS path noted about one query as it went (server.c), for ql_result. It lives on
 * the worker's stack while the query is handled: the name is kept as an entry keeps it (its
 * last QL_NAME_MAX bytes), not whole. */
typedef struct {
    bool parsed;          /* a well-formed query: the name and type below are its */
    bool notify;          /* a NOTIFY */
    bool hosted, secondary; /* answered from a local zone */
    bool cache;           /* the forwarded answer came from the cache */
    bool asked;           /* a forwarder was asked */
    bool answered;        /* ...and answered */
    uint8_t rule;         /* ql_rule_t */
    bool name_trunc;      /* the name was longer: its first labels are left out */
    uint8_t name_len;
    uint16_t qtype;
    uint8_t name[QL_NAME_MAX]; /* wire form, as sent */
} ql_note_t;

/* Notes the query's name (wire form), as an entry keeps it (ql_set_name). */
void ql_note_name(ql_note_t *n, const uint8_t *qname, int qname_len);

/* The result of a query from what was noted, its response's rcode and length (0: no response). */
ql_result_t ql_result(const ql_note_t *n, int rcode, size_t len);

/* ---- the ring ---- */

enum {
    QL_F_TCP = 1,   /* came over TCP */
    QL_F_TRUNC = 2, /* the name was longer: its first labels are left out */
};

/* Client address privacy (the node config's querylog.client). */
typedef enum { QL_CLIENT_FULL, QL_CLIENT_SUBNET, QL_CLIENT_HIDDEN, QL_CLIENT_N } ql_client_t;
const char *ql_client_name(int c);
/* The address as the log keeps it: whole, its /24 (the last byte 0), or 0 (none). */
uint32_t ql_client_addr(uint32_t addr, ql_client_t mode);

typedef struct {
    uint64_t seq;
    uint64_t t_ms;       /* ms since boot when it was answered */
    uint32_t client;     /* IPv4, network order (ql_client_addr); 0: not kept */
    uint32_t latency_us; /* taking the query to the answer being ready */
    uint16_t qtype;
    uint8_t result, rcode, rule, flags, name_len, client_mode;
    uint8_t pad[4];
    uint8_t name[QL_NAME_MAX]; /* wire form, as sent (case kept) */
} ql_entry_t;

typedef struct {
    ql_entry_t *e;
    uint32_t n;    /* entries the ring holds */
    uint64_t next; /* the seq the next entry gets */
    uint64_t first; /* the oldest seq in the ring (== next while empty) */
} ql_ring_t;

/* Entries bytes of memory hold. */
uint32_t ql_capacity(size_t bytes);
/* A ring in mem (bytes long, 8-aligned); the next entry's seq is next_seq (1 at boot). False
 * if mem holds no entry. */
bool ql_init(ql_ring_t *r, void *mem, size_t bytes, uint64_t next_seq);
/* Sets e's name from a query name (wire form): its last labels if it is longer than the
 * entry keeps (QL_F_TRUNC). */
void ql_set_name(ql_entry_t *e, const uint8_t *qname, int qname_len);
/* Adds a copy of e with the next seq; returns that seq. */
uint64_t ql_add(ql_ring_t *r, const ql_entry_t *e);
/* Copies the entry with seq into out if the ring still holds it. */
bool ql_get(const ql_ring_t *r, uint64_t seq, ql_entry_t *out);

/* The client privacy setting made stricter (full, then subnet, then hidden) applies to what
 * was logged before it too: ql_entry_privacy keeps no more of e's client than mode does (an
 * entry logged under a stricter mode stays as it is), and ql_privacy does it to the entry
 * with seq in the ring, if held. */
void ql_entry_privacy(ql_entry_t *e, ql_client_t mode);
void ql_privacy(ql_ring_t *r, uint64_t seq, ql_client_t mode);

/* Where a read after cursor starts. next is the seq the ring gives next, first the oldest it
 * holds. from: the first seq to return (from == next: none); lost: entries after cursor
 * overwritten before they were read; reset: the cursor is past the newest (the node started
 * over, or the cursor is from elsewhere): the read starts at the oldest. */
typedef struct {
    uint64_t from, lost;
    bool reset;
} ql_cursor_t;
ql_cursor_t ql_cursor(uint64_t cursor, uint64_t first, uint64_t next);

/* ---- JSON ---- */

/* The name as text in JSON (no quotes): labels joined by dots, lowercase, a dot, backslash
 * or quote in a label escaped as in a zone file ("\."), other bytes outside printable ASCII
 * as \DDD; then escaped for JSON. "." for the root. Returns the length (cut short at cap). */
size_t ql_name_json(const uint8_t *name, size_t len, char *out, size_t cap);
/* A query type's name ("A", "AAAA", "TYPE65"). Writes into buf (at least 12 bytes). */
const char *ql_type_name(uint16_t t, char *buf);
/* A rcode's name ("NOERROR", "NXDOMAIN", "RCODE11"). Writes into buf (at least 12 bytes). */
const char *ql_rcode_name(int rc, char *buf);
/* One entry as a JSON object. now_ms is ms since boot now and unix_ms the time now (0: the
 * clock isn't set), for its "time". Returns the bytes written (cut short at cap). */
#define QL_JSON_MAX 1024 /* the most one entry takes */
size_t ql_entry_json(const ql_entry_t *e, uint64_t now_ms, uint64_t unix_ms, char *j, size_t cap);
