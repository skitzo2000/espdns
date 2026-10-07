/*
 * DNS listeners on UDP and TCP port 53, and the per-query dispatch:
 * NOTIFY, authoritative answers, conditional/default forwarding with a cache. NOTIFY only
 * with secondary zones, forwarding only with forwarders (svc.h).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cache.h"
#include "dns_wire.h"
#include "health.h"
#include "svc.h"
#include "upq.h"

typedef struct {
    uint32_t queries, udp, tcp;
    uint32_t auth, forwarded, cache_hits;
    uint32_t nxdomain, servfail, refused, formerr, notifies, dropped;
} server_stats_t;

/* Takes the dns service's memory (the cache, the workers' buffers: share.h) and opens the
 * listeners. */
void server_start(void);
/* True once both UDP and TCP listeners are bound. */
bool server_running(void);
/* True if a listener could not be bound: the node can't answer. */
bool server_failed(void);
/* The dns service (svc.h): the listeners and the cache, always on. */
svc_state_t server_state(void);
/* The default forwarders, as health judges them (health.h): their run of failures (one per
 * flight, however many queries waited on it: upq.h), their sheds, their slow queries over the
 * last HEALTH_FWD_WINDOW_MS, and whether they hold more than half their cap of the upstream
 * query table (flight.h). All 0 before the DNS service is up. Any task may call it. */
void server_upstream(health_fwd_t *f);
/* Forgets all that (forwarding turned on: a new start). */
void server_upstream_reset(void);
/* The forward loop's counts for /metrics (upq.h); false before the DNS service is up. */
bool server_forward_stats(upq_stats_t *s);
void server_get_stats(server_stats_t *s);
/* The cache's counters, for /metrics; false if it has none (no memory). max_entries and bytes:
 * its size from the memory plan (memory.cache_entries, cache_kb). */
bool server_cache_stats(cache_stats_t *s, uint32_t *max_entries, uint32_t *bytes);
/* Drops every cached answer (a new blocklist: cached CNAMEs were checked against the old). */
void server_cache_flush(void);

/* Handles one query, and tells the query log (querylog.h) how it went: its result, the
 * response's rcode and how long it took. src is IPv4 in network order; out, scratch and b are the worker's
 * (nothing is allocated here). Returns response length (0 = no reply: also a UDP query parked
 * on its upstream query, answered once that is over, upq.h). The caller holds POWER_DNS
 * (power.h); a TCP query lets it go while it waits for its upstream answer. */
size_t server_handle(const uint8_t *q, size_t qlen, uint32_t src, bool tcp, uint8_t *out, size_t cap,
                     uint8_t *scratch, size_t scratch_cap, dns_builder_t *b);
