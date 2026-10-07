/*
 * Observability on the node (docs/design.md, Observability): the query log service and
 * what the DNS path tells it, and GET /querylog. The ring and the JSON are qlog.h's, the
 * counters stats.h's; GET /metrics is metrics_node.c.
 *
 * Every query the workers handle goes through querylog_query once it is answered: the
 * counters for /metrics always (lock-free atomics), and, while the service runs, one entry
 * in the ring (a 160-byte copy in a short critical section). Nothing on that path allocates.
 *
 * The service (svc.h, SVC_QUERYLOG) runs while the node config's "querylog": {"enabled"}
 * (on unless a config says false) and the board has memory.querylog_kb for it: the ring is
 * taken from its share of the memory plan at the start and given back at the stop, live.
 * The client privacy setting ("querylog": {"client"}) applies as an entry is written, so an
 * address the setting leaves out is never stored; made stricter live, it applies to what the
 * ring holds from before too (querylog_apply), and to every entry as it is read.
 *
 * GET /querylog?cursor=N&limit=M (private source addresses only, as the release endpoints:
 * it says what clients look up): the entries after seq N (0: everything held), oldest first,
 * at most M (default 100, at most 1000), and where to go on from:
 *
 *   {"boot_id":"8f3a...","enabled":true,"state":"running","client":"full","capacity":6553,
 *    "oldest":120,"newest":6672,"cursor":100,"uptime_ms":...,"time":...,
 *    "entries":[{...},...],"next":219,"lost":19,"reset":false,"more":true}
 *
 * next: the cursor for the next read (the last seq returned, else the cursor); lost: entries
 * after the cursor overwritten before they could be read (counted to the end of this read,
 * so it comes after the entries); reset: the cursor was past the newest (it
 * is from before a reboot): the entries start at the oldest held; more: entries after next
 * are held already. boot_id changes at every boot, when the numbers start over at 1. time
 * is the node's clock in Unix ms, null until it is set; each entry's time is worked out from
 * it and its uptime_ms.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_http_server.h"
#include "forward.h"
#include "qlog.h"
#include "stats.h"
#include "svc.h"

/* ---- the service (services.c) ---- */
void querylog_start(void);
void querylog_stop(void);
svc_state_t querylog_state(void);
/* A config applied live (settings.c): a stricter "client" applies to what the ring holds. */
void querylog_apply(void);
bool querylog_broken(void);

/* ---- the DNS path (server.c, blocking.c) ---- */

/* The note for the query this task is handling, or NULL (a task not answering one). */
ql_note_t *querylog_note(void);
void querylog_note_set(ql_note_t *n);
/* A rule decided the name (blocking.c). */
void querylog_note_rule(ql_rule_t r);
/* A query answered: the counters, and the ring while the service runs. src: the client
 * (IPv4, network order); out/len: the response (len 0: none). */
void querylog_query(const ql_note_t *n, uint32_t src, bool tcp, const uint8_t *out, size_t len, uint32_t us);
/* One attempt at a forwarder (forward.c's observer). */
void querylog_upstream(uint32_t server, fwd_try_t how, uint32_t us);

/* The counters, for /metrics. */
const st_t *querylog_stats(void);
/* What the ring holds now, for /metrics and /status: capacity, oldest and next seq. */
void querylog_ring_info(uint32_t *capacity, uint64_t *first, uint64_t *next);
/* This boot's ID: 16 hex digits. */
const char *querylog_boot_id(void);

/* ---- HTTP ---- */
/* GET /querylog (ota.c serves it, after its Host check). */
esp_err_t querylog_get(httpd_req_t *req);
/* "querylog":{...} for /status: the service, its ring and the settings. */
size_t querylog_status_json(char *j, size_t cap);
