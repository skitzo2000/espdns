/*
 * Hosted zones (docs/design.md, Answering and Signed releases): zones espDNS itself is the
 * primary for. They are edited in the controller (RFC 1035 master files) and reach every
 * node as a signed REL_ZONES release whose payload is a bundle of whole zones, written by
 * controller/internal/zones:
 *
 *   off  size
 *     0     8  magic "EDZONES1"
 *     8     2  zone count (0 to HZ_MAX_ZONES; 0 removes every hosted zone)
 *   then for each zone:
 *          1  apex length, then the apex (wire form, uncompressed)
 *          4  record count
 *          then for each record (class IN):
 *             1  owner length, then the owner (wire form, uncompressed, absolute)
 *             2  type
 *             4  TTL
 *             2  rdata length, then the rdata (names in it uncompressed)
 *
 * Integers are big-endian, as on the wire. The node checks a bundle in full before it is
 * stored, with the same checks as controller/internal/zones:
 *
 *   - names are valid wire names; owners are at or below their zone's apex; "*" only as a
 *     whole first label (a wildcard); no zone twice;
 *   - types A, AAAA, CNAME, MX, TXT, SRV, NS, PTR, CAA and SOA, with well-formed rdata;
 *     the zones are unsigned (no DNSSEC types);
 *   - exactly one SOA, at the apex; a CNAME owner has nothing else; below a delegation
 *     (NS below the apex) only the NS records and their A/AAAA glue;
 *   - TTLs at most 2^31-1;
 *   - the memory the zones take (hz_mem) within the board's limit (board_def.h,
 *     memory.hosted_zones_kb).
 *
 * Portable C, no ESP-IDF: parsed and checked on the host in the tests.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "zone.h"

#define HZ_MAGIC     "EDZONES1"
#define HZ_MAX_ZONES 32
/* What hz_mem counts: per zone (at least sizeof(zone_t)), per record (sizeof(zrr_t)),
 * plus every owner and rdata byte. The same on the host and the node, and in Go. */
#define HZ_ZONE_COST 512
#define HZ_RR_COST   20

typedef struct {
    int n;
    zone_t *z[HZ_MAX_ZONES];
    size_t mem; /* hz_mem of the bundle */
} hz_set_t;

/* Parses and checks a bundle. limit: the most memory (hz_mem) it may take. NULL and *out
 * on success; else why not, in err (nothing is left allocated). */
const char *hz_parse(const uint8_t *p, size_t len, size_t limit, hz_set_t **out, char *err, size_t errlen);
void hz_free(hz_set_t *s);
/* Drops zone i (its memory is freed). */
void hz_drop(hz_set_t *s, int i);

/* A hosted zone that the config also names as a secondary or forward zone: the index of
 * the first, or -1. A name has exactly one source (docs/design.md, Answering). */
int hz_clash(const hz_set_t *s, const cfg_t *c);

/* The zone in s whose apex is the longest one name is at or below, or NULL. */
zone_t *hz_find(const hz_set_t *s, const uint8_t *name, int len);
