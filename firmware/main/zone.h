/*
 * In-memory copy of one zone, built from an AXFR or loaded from the SD card.
 * Immutable once finalized: refreshes build a new zone and swap the pointer.
 *
 * Records are kept in DNSSEC canonical order (RFC 4034 6.1: label by label from the root),
 * so a name and everything under it are one run: a lookup, and whether a name exists as an
 * empty non-terminal, is a binary search, whatever the zone's size.
 *
 * A zone never holds more than the limit it was made with (zone_new), counting a buffer's
 * old copy while it grows: a transfer from a broken primary fails at the record that would
 * take it over, not after it has.
 *
 * Portable C, no ESP-IDF dependencies.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns_wire.h"

typedef struct {
    uint32_t owner_off; /* into arena: lowercased wire name */
    uint32_t rdata_off; /* into arena: rdata with names decompressed */
    uint32_t ttl;
    uint16_t type;
    uint16_t rdlen;
    uint8_t  owner_len;
} zrr_t;

typedef struct {
    uint8_t  apex[DNS_MAX_NAME];
    int      apex_len;
    uint32_t serial, refresh, retry, expire, minimum, soa_ttl;
    size_t   soa_idx;

    zrr_t   *rrs;       /* sorted by owner (canonical order), then type */
    size_t   n, cap;
    uint8_t *arena;
    size_t   arena_len, arena_cap;
    size_t   limit;     /* the most zone_mem may reach, a growing buffer's old copy included */
    bool     over;      /* a zone_add or zone_reserve was refused for the limit */
} zone_t;

/* A zone that may hold at most limit bytes at any moment (zone_mem, with a buffer's old copy
 * while it grows; SIZE_MAX: no limit). NULL if limit can't hold the zone_t itself. */
zone_t *zone_new(const uint8_t *apex, int apex_len, size_t limit);
void    zone_free(zone_t *z);
/* The memory z holds (the memory plan's secondary zones, memplan.h); 0 for NULL. */
size_t  zone_mem(const zone_t *z);
/* Sizes the record table and the arena for exactly this many records and bytes (owners
 * plus rdata), so adding them allocates nothing more (hosted zones: hzone.h). */
bool    zone_reserve(zone_t *z, size_t nrr, size_t arena_bytes);
/* Class IN only. Owner must be at or below the apex (anything else is skipped). False when
 * out of memory, or when the record would take the zone over its limit (z->over set). */
bool    zone_add(zone_t *z, const uint8_t *owner, int owner_len, uint16_t type,
                 uint32_t ttl, const uint8_t *rdata, uint16_t rdlen);
/* Sorts (in place: it allocates nothing), drops duplicates, and requires exactly one SOA at
 * the apex. */
bool    zone_finalize(zone_t *z);

static inline const uint8_t *zrr_owner(const zone_t *z, const zrr_t *r) { return z->arena + r->owner_off; }
static inline const uint8_t *zrr_rdata(const zone_t *z, const zrr_t *r) { return z->arena + r->rdata_off; }

/* All RRs owned by name (any case): returns count, *first = index. O(log n) comparisons. */
size_t zone_find(const zone_t *z, const uint8_t *name, int len, size_t *first);
/* True when name owns RRs or is an empty non-terminal (has descendants). O(log n)
 * comparisons: the first record at or after name in canonical order is name's or a
 * descendant's, if it has any. */
bool   zone_name_exists(const zone_t *z, const uint8_t *name, int len);
/* RFC 4034 6.1 canonical order of two lowercase wire names: <0, 0, >0. */
int    zone_name_cmp(const uint8_t *a, int alen, const uint8_t *b, int blen);

/* RFC 1982 serial comparison: true when a is newer than b. */
static inline bool serial_newer(uint32_t a, uint32_t b) { return a != b && (int32_t)(a - b) > 0; }

/* Persistence: a small checksummed binary file. Writes path.tmp then renames. */
bool    zone_save(const zone_t *z, const char *path);
/* Loaded into exactly the memory its records need (zone_reserve), streamed: nothing else is
 * held meanwhile. NULL also when that is more than limit bytes. */
zone_t *zone_load(const char *path, const uint8_t *apex, int apex_len, size_t limit);
