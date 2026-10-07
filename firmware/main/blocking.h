/*
 * The blocking service (docs/design.md, Blocking): the main list and the overrides, loaded
 * from their SD slots in the background after the node is answering, swapped live when a
 * new release arrives, and the pause command. The portable parts are in block.h.
 *
 * The service runs while the node config enables it (blocking.enabled, svc.h), and starts
 * and stops live. Off, nothing is in memory, no task runs, the query path skips it, and
 * lists and overrides are refused (control releases still apply). On but never sent a
 * list, nothing loads and the query path skips it too. Once a list has been installed (its
 * release seq is in NVS), a list that is missing, corrupt, unreadable or too big makes the
 * node degraded, and it answers unblocked. A boot that has to fall back to the older slot
 * (the newest corrupt, unreadable or too big) is degraded too ("older copy").
 *
 * Revert (BLK_CTL_REVERT, a control release) goes back to the older copy in the other slot,
 * live as a push is (at the next boot when two copies don't fit), and records the seq it left
 * in NVS, so later boots keep to it; the next list pushed ends it. Control releases come
 * here for every service: a revert of the hosted zones goes to hosted.c.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "block.h"
#include "dns_wire.h"
#include "release.h"
#include "svc.h"

/* After ota_start (it needs the node's trust for the saved releases) and sd_start: the
 * load waits for the card's mount result. Does nothing while the node config has it off;
 * also the live start once a config turns it on. */
void blocking_start(void);
/* The live stop, when a config turns it off: the lists are unloaded and freed. */
void blocking_stop(void);
svc_state_t blocking_state(void);
/* Its start failed (its load task or its memory), not a list: the supervisor starts it again. */
bool blocking_broken(void);

/* ---- the query path ---- */

/* The decision for a name about to be forwarded. BLK_PASS also when blocking is off. */
blk_result_t blocking_query(const uint8_t *qname);
/* The blocked answer for q (blk_answer with this node's settings); returns the rcode. */
int blocking_answer(dns_builder_t *b, const dns_query_t *q);

/* The CNAME targets in a forwarded answer, checked once as it enters the cache. */
typedef enum { BLOCKING_CNAME_PASS, BLOCKING_CNAME_BLOCK, BLOCKING_CNAME_NOCACHE } blocking_cname_t;
/* PASS: cache it. BLOCK: answer blocked, don't cache. NOCACHE: blocking is paused: answer
 * it, but don't cache it, so it isn't served once the pause ends. */
blocking_cname_t blocking_cnames(const uint8_t *msg, size_t len);

/* ---- releases (POST /release, in ota.c) ---- */

/* The kinds this service takes: REL_BLOCKLIST, REL_OVERRIDES, REL_CONTROL. */
bool blocking_kind(uint8_t kind);
/* Why blocking_store refuses a list while the boot load hasn't finished: try again later. */
extern const char BLOCKING_LOADING[];
/* Receives a verified release's payload and stores it (control: keeps it in memory).
 * Returns NULL, BLOCKING_LOADING (compare the pointer), or why it was refused. */
const char *blocking_store(const uint8_t hdr[REL_HEADER_LEN], const rel_manifest_t *m, blk_recv_fn recv,
                           void *ctx);
/* Puts the stored release to use, once its seq is recorded. Control releases: pause,
 * identify, flush cache, revert (block.h) and reboot (reboot.h) apply here; a revert with
 * no older copy to go back to is refused by blocking_store, before its seq is taken. Writes a line for the
 * reply to msg. *reboot: it only fits in memory once the current list is gone, so it
 * applies at the next boot, which is now pending (the node doesn't reboot). Returns NULL,
 * or why it wasn't applied (the previous list stays). */
const char *blocking_apply(const rel_manifest_t *m, char *msg, size_t cap, bool *reboot);

/* A revert in force for a kind (REL_BLOCKLIST, REL_OVERRIDES, REL_ZONES), kept in NVS: the
 * seq it moved away from, 0 for none. blocking_rev_set(kind, 0) ends it. */
uint64_t blocking_rev_get(uint8_t kind);
bool blocking_rev_set(uint8_t kind, uint64_t seq);

/* ---- health ---- */

bool blocking_degraded(void);
/* The boot fell back to an older list or overrides than the newest the node took (its slot
 * corrupt, unreadable or too big): degraded, "older copy". Not after a revert command. */
bool blocking_older(void);
/* Appends "blocklist":{"state","seq","sha256"},"overrides":{...} for /health. */
size_t blocking_health_json(char *j, size_t cap);
/* Appends "blocking":{...} to a JSON object being written. Returns the bytes written. */
size_t blocking_status_json(char *j, size_t cap);

/* ---- metrics ---- */

/* The lists (0: the blocklist, 1: the overrides) and the counters, for /metrics. */
typedef struct {
    struct {
        const char *state; /* off, loading, on, failed */
        bool on;
        uint64_t seq;
        uint32_t entries;
        size_t bytes;
    } list[2];
    uint32_t paused_s;
    uint32_t blocked, cname_blocked, allowed, sector_reads, errors;
} blocking_metrics_t;
void blocking_metrics(blocking_metrics_t *m);
