/*
 * Blocklist lookups (portable: plain C, no ESP-IDF).
 *
 * The controller compiles the lists into one file (format in
 * controller/internal/blocklist/file.go): a SipHash key, and four tables of w-bit hashes:
 * names blocked exactly, names blocked with their subdomains, and the same two for allowed
 * names. Each table is a RAM index (the first hash of each 512-byte sector), an optional
 * xor filter, and the sectors themselves, Elias-Fano coded. The live overrides are a small
 * file of the same format, checked first with bl_verdict.
 *
 * A name's verdict is the most specific entry that matches it: an exact entry matches only
 * its name, a suffix entry the name and its subdomains; at the same name, allow beats
 * block. So an allowed www.ads.com under a blocked ads.com resolves, and a blocked
 * x.ok.com under an allowed ok.com doesn't.
 *
 * The same code serves both tiers: the caller hands over the front of the file (header,
 * indexes, filters) and a function that returns one sector. In the SD tier it reads the
 * card, and the front stays in RAM for the filters. The RAM tier doesn't use the filters
 * (1.5 bytes a domain for a few µs a query) and keeps only the sectors and the indexes:
 * open the front with BL_NO_XOR, bl_index_move the indexes out, free the front, and
 * load the file from bl_front_len on, the sector at file offset off being at
 * off - bl_front_len in that buffer.
 *
 * Each check binary-searches an index, so where the index lives sets the speed: on the
 * node, bl_index_move puts it in internal RAM rather than PSRAM.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BL_SECTOR 512
#define BL_HEADER 160 /* version 2; version 1 files (block tables only) have 96 */

/* Returns the BL_SECTOR bytes at file offset off (always sector-aligned), or NULL if they
 * can't be read; a lookup that can't read its sector answers "not blocked" (a block table)
 * or "allowed" (an allow table), so a bad card makes a list block less, never more. */
typedef const uint8_t *(*bl_read_fn)(void *ctx, uint32_t off);

typedef struct {
    uint32_t hashes, sectors;
    const uint64_t *index; /* first hash of each sector */
    const uint8_t *xor;   /* NULL: no filter */
    uint32_t xor_seg;
    uint64_t xor_seed;
    uint32_t sectors_off;
} bl_table_t;

enum { BL_EXACT, BL_SUFFIX, BL_ALLOW_EXACT, BL_ALLOW_SUFFIX, BL_TABLES };

typedef enum { BL_NONE, BL_BLOCK, BL_ALLOW } bl_verdict_t;

typedef struct {
    uint8_t bits, xor_bits;
    bool allow; /* an allow table has entries */
    uint64_t k0, k1;
    bl_table_t t[BL_TABLES];
    bl_read_fn read;
    void *ctx;
} bl_t;

typedef struct {
    uint32_t checks;  /* table lookups */
    uint32_t filtered; /* lookups the xor filter answered */
    uint32_t reads;    /* sectors read */
    uint32_t errors;   /* sectors that couldn't be read */
} bl_stats_t;

/* bl_open flags. BL_NO_XOR: leave the file's xor filters out (the RAM tier); nothing
 * points into them, so after bl_index_move nothing points into the front at all. */
#define BL_NO_XOR 1u

/* Checks the header and that every section lies inside the file. front is the start of the
 * file, 8-aligned, at least up to the first table's sectors. Returns NULL on success, else
 * a short reason. */
const char *bl_open(bl_t *b, const uint8_t *front, size_t front_len, size_t file_len, bl_read_fn read,
                    void *ctx, unsigned flags);

/* The front_len bl_open needs: everything before the sectors. 0 if hdr isn't a header. */
size_t bl_front_len(const uint8_t hdr[BL_HEADER]);

/* The bytes bl_index_move needs: every table's index. */
size_t bl_index_size(const bl_t *b);

/* Copies the indexes to buf (bl_index_size bytes, 8-aligned) and searches them there from
 * now on. buf must outlive b; the front no longer needs the indexes after this. */
void bl_index_move(bl_t *b, uint64_t *buf);

/* Whether a query name is blocked. qname is in wire format (length-prefixed labels, then a
 * zero byte), any case. st may be NULL. The allow tables are only checked once a block
 * entry matches, so they cost nothing for names no list blocks. */
bool bl_blocked(const bl_t *b, const uint8_t *qname, bl_stats_t *st);

/* What the file says about a name: no entry matches, blocked, or allowed. For the
 * overrides, where BL_ALLOW means the main lists aren't checked. Checks every table at
 * every level, so it costs more than bl_blocked. */
bl_verdict_t bl_verdict(const bl_t *b, const uint8_t *qname, bl_stats_t *st);

/* SipHash-2-4, as the controller computes it. */
uint64_t bl_siphash(uint64_t k0, uint64_t k1, const void *p, size_t n);

/* One table lookup for an already-hashed (w-bit) value, for tests and benchmarks. */
bool bl_contains(const bl_t *b, int table, uint64_t h, bl_stats_t *st);

/* ---- Bench only (tests/bench_blocklist.c): the stages of a lookup, one at a time ---- */

/* The hashes bl_blocked computes for qname, shortest suffix first; the last is also the
 * one it checks against the exact tables, unless a label holds a dot (the walk stops there,
 * before the whole name). Returns how many (≤ room), 0 for a name it never blocks. */
size_t bl_name_hashes(const bl_t *b, const uint8_t *qname, uint64_t *out, size_t room);

/* The index search: the sector h would be in, plus one; 0 if it's below the first. */
uint32_t bl_index_find(const bl_t *b, int table, uint64_t h);

/* The xor filter probe: false means certainly not in the table (always true without one). */
bool bl_xor_maybe(const bl_t *b, int table, uint64_t h);

/* The in-sector search: whether sec holds offset d (> 0) from its first hash. */
bool bl_sector_has(const uint8_t *sec, uint64_t d);
