/*
 * Cache of raw upstream responses, keyed by (qname without regard to case, qtype, qclass,
 * CD). LRU eviction with entry and byte limits. Thread-safe. Portable C (pthreads).
 *
 * One entry answers every equivalent question: the DO bit, EDNS (present, its size, its
 * options) and RD aren't in the key, as the answer doesn't depend on them. Every upstream
 * query asks with DO (server.c), so an entry holds the DNSSEC records too, and the relay
 * leaves them out for a client without DO (dnsb_relay). CD is in the key, one way only: an
 * answer asked for with CD may be data the forwarder's validation would refuse (bogus), so
 * it never answers a query without CD; an answer asked for without CD is validated or
 * insecure data, the same a query with CD gets, so it answers both (cache_get).
 *
 * All of its memory is one block, taken when the cache is made (the dns service's share of
 * the memory plan, memplan.h): a table of max_entries entries and the rest in 64-byte
 * chunks that hold the names and answers. Caching an answer allocates nothing; it evicts
 * the least recently used until the answer fits.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct cache cache_t;

typedef struct {
    uint32_t entries, bytes, hits, misses, inserts, evictions; /* bytes: in the chunks in use */
} cache_stats_t;

/* A cache in mem (bytes long, 8-aligned), which it never frees. NULL if bytes can't hold
 * the table for max_entries and some chunks. */
cache_t *cache_new_in(void *mem, size_t bytes, size_t max_entries);
/* A cache of max_bytes from malloc (the tests); cache_free frees it. */
cache_t *cache_new(size_t max_entries, size_t max_bytes);
void cache_free(cache_t *c);
/* Copies the stored response into out. *age_s = seconds since it was stored. cd: the query
 * has CD: an answer stored with CD, else one stored without it. */
bool cache_get(cache_t *c, const uint8_t *qname, int qlen, uint16_t qtype, uint16_t qclass,
               bool cd, uint32_t now_s, uint8_t *out, size_t cap, size_t *len, uint32_t *age_s);
/* Stores msg if dns_resp_ttl() says it is cacheable. cd: it was asked for with CD. */
void cache_put(cache_t *c, const uint8_t *qname, int qlen, uint16_t qtype, uint16_t qclass,
               bool cd, uint32_t now_s, const uint8_t *msg, size_t len);
/* Drops every answer, and starts a new generation. */
void cache_flush(cache_t *c);
/* The generation: a count of flushes. A caller that decides on an answer (whether it is
 * blocked, which zone it belongs to) reads it before deciding, and stores the answer with
 * cache_put_gen: if a flush came in between (a new list or zones swapped in, whose answers
 * the flush was to drop), the answer was decided on what was there before, and isn't kept. */
uint32_t cache_gen(cache_t *c);
/* cache_put, only if no flush came since gen was read. Returns whether it was stored. */
bool cache_put_gen(cache_t *c, uint32_t gen, const uint8_t *qname, int qlen, uint16_t qtype, uint16_t qclass,
                   bool cd, uint32_t now_s, const uint8_t *msg, size_t len);
void cache_get_stats(cache_t *c, cache_stats_t *s);
