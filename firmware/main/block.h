/*
 * The blocking service's portable core (plain C, POSIX files, pthreads; no ESP-IDF):
 * the decision for a query name, the blocked answer, the CNAME check, lists loaded from
 * their slot files in either tier, and the pointer the query path reads them through.
 * blocking.c puts it on the node (memory plan, SD paths, /release, /status).
 *
 * Lists reach a node as signed releases (release.h) of kind REL_BLOCKLIST (the main list)
 * and REL_OVERRIDES (a small file of the same format), each kept on SD in two slot files.
 * A slot file is the payload followed by its 192-byte signed release header, so the list's
 * sectors stay 512-aligned in the file and a file cut short by a power cut has no valid
 * header: at boot the node loads the valid slot with the highest seq.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blocklist.h"
#include "dns_wire.h"
#include "release.h"

/* ---- the decision ---- */

typedef enum { BLK_PASS, BLK_BLOCK, BLK_ALLOW } blk_result_t;

typedef struct blk_list blk_list_t;

/* docs/design.md, Blocking: the overrides first (allow means the lists aren't checked),
 * then pause, then the main list. Either list may be NULL. */
blk_result_t blk_decide(const blk_list_t *ovr, bool paused, const blk_list_t *list, const uint8_t *qname,
                        bl_stats_t *st);
/* The same, and whether the overrides decided it (*by_overrides; NULL: not asked), for the
 * query log: a block or allow by the overrides, else by the main list. */
blk_result_t blk_decide_by(const blk_list_t *ovr, bool paused, const blk_list_t *list, const uint8_t *qname,
                           bl_stats_t *st, bool *by_overrides);

/* The blocked answer, added to b: 0.0.0.0 for A, :: for AAAA, no records (NODATA) for any
 * other type; or, with nxdomain, NXDOMAIN for every type. No SOA, so nothing downstream
 * caches it longer than ttl. Returns the rcode to set. */
int blk_answer(dns_builder_t *b, const dns_query_t *q, bool nxdomain, uint32_t ttl);

/* Calls check with each CNAME and DNAME target (wire form) in a response's answer section, and
 * returns true at the first it says is blocked. A malformed message counts as no CNAMEs. */
typedef bool (*blk_name_fn)(void *ctx, const uint8_t *name);
bool blk_cname_any(const uint8_t *msg, size_t len, blk_name_fn check, void *ctx);

/* ---- a loaded list ---- */

typedef enum { BLK_TIER_RAM, BLK_TIER_SD } blk_tier_t;

/* Where a list's memory comes from: big for the sectors (RAM tier) or the front (SD tier);
 * index for the indexes (blk_place says which: internal RAM or with the list). Both return
 * 8-aligned memory or NULL. */
typedef struct {
    void *(*big)(size_t n);
    void *(*index)(size_t n);
    void (*free)(void *p);
} blk_alloc_t;

struct blk_list {
    bl_t bl;
    blk_tier_t tier;
    int fd;           /* SD tier: the slot file, a sector read per lookup; else -1 */
    uint8_t *mem;     /* RAM tier: the file from front_len on; SD tier: the front (filters) */
    uint64_t *index;  /* every table's index, moved out of the front */
    size_t front_len, file_len;
    size_t mem_bytes, index_bytes;
    uint32_t entries; /* hashes in the block tables */
    rel_manifest_t m; /* the release it came in */
    int slot;
    int refs;
    const blk_alloc_t *alloc;
};

/* What loading a file in each tier costs, from its first BL_HEADER bytes. */
typedef struct {
    size_t front, index, sectors; /* bytes: before the sectors, all indexes, the rest */
    uint32_t entries;
} blk_need_t;
const char *blk_plan(const uint8_t hdr[BL_HEADER], size_t file_len, blk_need_t *n);

/* The blocking service's share of the memory plan (memplan.h), and what is in it: never
 * free heap. Bytes. */
typedef struct {
    size_t budget, used, held;                   /* lists (the data pool): the share, what
                                                  * the lists in it take now, and what the
                                                  * one being replaced takes of that */
    size_t index_budget, index_used, index_held; /* indexes in internal RAM, the same */
    bool ram_tier;                               /* the data pool is PSRAM: whole tables fit there */
    bool overrides;                              /* the overrides: the RAM tier, and live only */
} blk_room_t;

/* Where a list goes. */
typedef struct {
    blk_tier_t tier;
    bool index_internal; /* its indexes in internal RAM (loading now) */
    bool now;            /* it fits next to the list it replaces: load it now; else only once
                          * that one is gone, at the next boot */
} blk_place_t;

/* docs/design.md, Lookup tiers: the RAM tier if the whole table fits the share once the
 * list it replaces is gone, else the SD tier (the front and indexes in memory), else it
 * doesn't fit the board (why). The indexes go to internal RAM while what is left of
 * index_budget holds them, else with the list. Overrides take the RAM tier and must fit
 * now. */
const char *blk_place(const blk_need_t *n, const blk_room_t *r, blk_place_t *out);

/* Loads the payload of an open slot file (m from blk_slot_read) in a tier. Takes the fd:
 * the SD tier keeps it, otherwise it is closed. Returns NULL and *out, else why not. */
const char *blk_load(int fd, const rel_manifest_t *m, blk_tier_t tier, const blk_alloc_t *a, blk_list_t **out);

/* ---- slot files ---- */

/* Reads a slot file's release header and checks it (signature, node, image, kind) and
 * that the file is as long as it says. Doesn't read the payload. */
const char *blk_slot_read(int fd, const rel_trust_t *t, uint8_t kind, rel_manifest_t *m);
/* Checks the payload against the header's SHA-256. */
const char *blk_slot_hash(int fd, const rel_manifest_t *m);

/* Writes a release into a slot file: the payload from recv (which returns false on a
 * receive error), then, only if it matches the signed SHA-256, the header. hdr and m have
 * passed rel_verify. On failure the file is left empty. */
typedef bool (*blk_recv_fn)(void *ctx, uint8_t *buf, size_t n);
const char *blk_slot_store(const char *path, const uint8_t hdr[REL_HEADER_LEN], const rel_manifest_t *m,
                           blk_recv_fn recv, void *ctx);

/* Which of a kind's two slots a boot tries, in order (the blocklist's, the overrides' and the
 * hosted zones'): the valid slot with the highest seq first, then the other valid one. ok[i]:
 * slot i's header passed (blk_slot_read); seq[i] its seq. reverted: the seq a revert
 * command moved away from (0: none), never tried. Returns how many slots to try (0 to 2). */
int blk_slot_order(const bool ok[2], const uint64_t seq[2], uint64_t reverted, int order[2]);
/* Whether the copy a boot loaded (seq loaded) is an older one than it should run: the
 * newest stored (recorded, the highest seq the node took for the kind) is corrupt,
 * unreadable or doesn't fit, so the node fell back. Not when a revert to it is in force
 * (reverted == recorded: nothing newer came since). */
bool blk_slot_older(uint64_t loaded, uint64_t recorded, uint64_t reverted);
/* Why a revert can't go back to the copy in the other slot (the blocklist's, the overrides'
 * and the hosted zones'), written into buf, or NULL when it can. what names the kind ("list",
 * "overrides", "zones"); other: the other slot; other_why: its header check (NULL: it passed,
 * "missing": no file); other_seq its seq; in_use the seq in use; reverted the seq a revert
 * moved away from (0: none); newer: what a newer copy there is otherwise ("newer", or
 * "waiting for a reboot"). Only an older copy is gone back to: never the one reverted from,
 * nor one pushed since. */
const char *blk_revert_check(const char *what, int other, const char *other_why, uint64_t other_seq,
                             uint64_t in_use, uint64_t reverted, const char *newer, char *buf, size_t cap);

/* ---- the active list, swapped under running queries ---- */

/* A pointer the query path takes a reference through: a lookup holds the list it got
 * until blk_put, so a swap never frees a list in use; the last reference frees it. The
 * lock is held only to read the pointer and count the reference. */
typedef struct blk_ref blk_ref_t;
blk_ref_t *blk_ref_new(void);
blk_list_t *blk_get(blk_ref_t *r);         /* NULL if none; else blk_put it when done */
void blk_put(blk_list_t *l);               /* NULL is fine */
void blk_swap(blk_ref_t *r, blk_list_t *l); /* l (may be NULL) replaces the active list */
void blk_list_free(blk_list_t *l);         /* a list never handed to blk_swap */

/* ---- control releases ---- */

/* REL_CONTROL payload: u8 command, then its arguments, little-endian. */
enum {
    BLK_CTL_PAUSE = 1,    /* u32 seconds blocking stays off from receipt (0 resumes) */
    BLK_CTL_IDENTIFY = 2, /* u32 seconds the LED shows identify (0 stops; at most an hour) */
    BLK_CTL_FLUSH = 3,    /* no arguments: drop every cached answer */
    /* 4: reboot (RB_CTL_REBOOT, reboot.h) */
    BLK_CTL_REVERT = 5,   /* u8 kind, REL_BLOCKLIST, REL_OVERRIDES or REL_ZONES: back to the
                           * older copy in the other slot, live (a list at the next boot if two
                           * copies don't fit); kept across reboots until a newer one is pushed */
};
#define BLK_CTL_MAX 64
/* The kind a revert payload names (REL_BLOCKLIST, REL_OVERRIDES or REL_ZONES), else 0. */
uint8_t blk_ctl_revert_kind(const uint8_t *p, size_t n);
