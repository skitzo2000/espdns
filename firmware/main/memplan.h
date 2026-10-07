/*
 * The memory plan (docs/design.md, Node OS): how much memory each service the node config
 * enables (svc.h) gets, from fixed per-board values, and whether they fit the board. The
 * values come from the board definition's "memory" (board_def.h), else this chip image's
 * defaults below; nothing is guessed from free heap at run time. The defaults are today's
 * sizes on the production boards (p4-ip101, ws-s3-eth), so a board partition written
 * before these keys existed keeps them; the final values are set from measurements
 * (docs/plan.md, phase F).
 *
 * Memory comes in two pools: internal RAM and PSRAM. A service's data (the cache, lists,
 * zones, buffers) goes in PSRAM where the board has some, else in internal RAM; task
 * stacks and the blocklist indexes (memory.blocklist_index_kb) in internal RAM. What the
 * services may plan in each pool:
 *
 *   internal  memory.internal_kb: what the services may take of it, besides what the
 *             system (ESP-IDF, the network stack, the HTTP server) uses
 *   PSRAM     psram_mb (else the chip's), less MP_PSRAM_SYSTEM_KB for the system
 *
 * Each service's share, in bytes:
 *
 *   dns            stacks (internal): the listener and worker tasks, the forward loop and
 *                  its TCP task (fwdq.h); data: the cache (memory.cache_kb), the workers'
 *                  buffers, the UDP receive pool, the table of outstanding upstream
 *                  queries (memory.fwd_pending slots of MP_FWD_SLOT bytes, flight.h) and
 *                  the forward loop's TCP retry buffer (MP_FWD_TCP)
 *   forwarding,    nothing of their own (the DNS service asks the forwarders)
 *   forward_zones
 *   secondary      stack (internal): the zone task; data: the zones
 *                  (memory.secondary_zones_kb, with a new copy during a transfer) and the
 *                  transfer buffers
 *   hosted         stack (internal): the load task; data: three times
 *                  memory.hosted_zones_kb (the zones in use, a new bundle checked next to
 *                  them, and its payload as it arrives)
 *   blocking       stack (internal): the load task; data: memory.blocklist_kb (the list
 *                  and the overrides, two copies of each during a live swap) and its read
 *                  buffer; internal: memory.blocklist_index_kb for the indexes
 *   querylog       data: memory.querylog_kb, the ring of recent queries (MP_QUERYLOG_ENTRY
 *                  bytes each, qlog.h); no task of its own. 0 (a board without PSRAM): no
 *                  query log
 *
 * A config whose enabled services don't fit is refused: at boot it falls back to the
 * previous config (settings.h), and a pushed one isn't stored. The controller runs the same
 * plan (controller/internal/memplan) with the same test vectors (tests/memplan_vectors.json).
 *
 * Portable: run on the host in the tests.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "board_def.h"
#include "svc.h"

typedef enum { MP_INTERNAL, MP_PSRAM, MP_NPOOLS } mp_pool_t;

/* PSRAM kept for the system (ESP-IDF, lwIP, the HTTP server, TLS), KB. */
#define MP_PSRAM_SYSTEM_KB 1024

/* ---- the DNS service's fixed parts (server.c is built from these) ---- */
#define MP_UDP_WORKERS     4
#define MP_TCP_WORKERS     2
#define MP_WORKER_STACK    12288 /* each UDP and TCP worker */
#define MP_LISTENER_STACK  4096  /* the UDP receive and TCP accept tasks */
#define MP_UDP_QUEUE       64    /* queries waiting for a UDP worker */
#define MP_UDP_ITEM        1536  /* one received query (server.c checks its struct fits) */
#define MP_BUILDER         4096  /* a worker's response builder (server.c checks dns_builder_t fits) */
#define MP_UDP_OUT         1232  /* DNS_EDNS_SIZE */
#define MP_TCP_MSG         65535
#define MP_SCRATCH         65535 /* an upstream answer */
/* The UDP pool: one item per queue place, one per worker, one being received. */
#define MP_UDP_ITEMS       (MP_UDP_QUEUE + MP_UDP_WORKERS + 1)
/* Queries parked on another's upstream query (flight.h), in all. Each holds its item from
 * the pool, as a queued one would, so at most half the queue's places: the rest stays for
 * queries for other names while one name's forwarder is slow. */
#define MP_FLIGHT_WAITERS  (MP_UDP_QUEUE / 2)
/* One outstanding upstream query in the table (flight.h checks its struct fits): the
 * question, the upstream query's state and its answer buffer (MP_UDP_OUT). */
#define MP_FWD_SLOT        1600
/* The forward loop and its TCP task (fwdq.h), each; and the TCP task's answer buffer, one
 * truncated answer asked again at a time. */
#define MP_FWD_STACK       6144
#define MP_FWD_TCP         MP_TCP_MSG
/* The cache (cache.c checks these): its fixed part, and per answer its table entry and at
 * least one 64-byte chunk with its link. memory.cache_kb must hold cache_entries of them. */
#define MP_CACHE_FIXED     8192
#define MP_CACHE_ENTRY     (40 + 68)

/* ---- the other services' fixed parts ---- */
#define MP_XFR_STACK       8192
#define MP_XFR_BUFFERS     (2 * 65535) /* a transfer's message and decompressed rdata */
#define MP_HOSTED_STACK    8192
#define MP_BLOCKING_STACK  8192
#define MP_BLOCKING_IO     4096        /* the slot hash's read buffer (block.c) */
#define MP_QUERYLOG_ENTRY  160         /* one query log entry (qlog.c checks its struct) */

/* The board's memory, in KB (cache_entries: answers; fwd_pending: queries): from the board definition's
 * "memory" (board_def.h), else the chip image's defaults (mp_board). */
typedef struct {
    uint32_t psram_kb;    /* fitted: psram_mb, else what the chip has */
    uint32_t internal_kb; /* what the services may take of internal RAM */
    uint32_t cache_kb, cache_entries;
    uint32_t blocklist_kb, blocklist_index_kb;
    uint32_t hosted_zones_kb;
    uint32_t secondary_zones_kb;
    uint32_t querylog_kb;
    uint32_t fwd_pending; /* upstream queries outstanding at once: the table's slots (flight.h) */
} mp_board_t;

/* Fills *out from a board definition (b may be NULL: none) on the chip image named image.
 * chip_psram_kb: the PSRAM the chip has, or -1 if unknown (the controller): the board's
 * psram_mb is used, and on the node never more than the chip has. A key the board leaves
 * out is the image's default; a board without PSRAM gets the small defaults. */
void mp_board(const board_desc_t *b, const char *image, int chip_psram_kb, mp_board_t *out);

/* Which pool a service's data goes in: PSRAM where the board has some. */
static inline mp_pool_t mp_data_pool(const mp_board_t *b) { return b->psram_kb ? MP_PSRAM : MP_INTERNAL; }

typedef struct {
    size_t capacity[MP_NPOOLS];        /* what the services may plan, bytes */
    size_t share[SVC_N][MP_NPOOLS]; /* each service's share, bytes (0 for one that's off) */
    size_t total[MP_NPOOLS];
} mp_plan_t;

/* The plan for the services in enabled (svc_enabled) on board b. False if it doesn't fit,
 * with why in err ("PSRAM: the services need 33012 KB, the board has 31744 KB for them"),
 * or if memory.cache_kb can't hold memory.cache_entries answers ("cache: 8192 answers need
 * at least 872 KB, memory.cache_kb is 512"); *out is filled either way. */
bool mp_plan(const mp_board_t *b, uint32_t enabled, mp_plan_t *out, char *err, size_t errlen);

/* A service's planned bytes in both pools. */
size_t mp_share(const mp_plan_t *p, int svc);

/* "memory":{...} for /status: the board's values, and the plan per pool. */
size_t mp_json(const mp_board_t *b, const mp_plan_t *p, char *j, size_t cap);
