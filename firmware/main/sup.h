/*
 * The supervisor's rules (docs/design.md, Node OS and Health): watchdogs on the service
 * tasks, restarts of a failed optional service with backoff, and when the DNS listeners'
 * stall reboots the node. Portable: run on the host in the tests; supervisor.c runs them
 * on the node.
 *
 * Watchdogs. Every task a service runs for good (the DNS listeners and workers, the zone
 * task) and each load task while it runs checks in at least once per deadline, unless it
 * is parked: waiting for work (sup_watch_t). One that misses it is late:
 *   - the UDP receive or TCP accept task, or every UDP worker at once: the listeners have
 *     stalled. The node isn't answering, so a reboot loses nothing: it reboots, unless it
 *     already did for a stall SUP_STALL_REBOOTS times in a row without staying up
 *     SUP_STALL_WINDOW_MS in between. Then it stays up in fault ("listeners stalled") for
 *     the controller to act on, rather than boot-loop. A TCP worker is never a stall: a slow
 *     client may hold one as long as it keeps sending.
 *   - an optional service's task: that service has failed. FreeRTOS can't stop a task that
 *     may hold a lock, so it isn't restarted: the node is degraded ("service failed") until
 *     the task checks in again.
 *   - the forward loop (fwdq.h, SUP_FORWARDER): forwarded queries go unanswered, but cached
 *     and local ones are still answered, so it is never a stall and never a reboot: the node
 *     is degraded ("forwarder task stalled") until the loop checks in again.
 *
 * Restarts. An optional service whose start failed (its task couldn't be made, or its
 * memory) is started again after SUP_BACKOFF_MIN_MS, doubling up to SUP_BACKOFF_MAX_MS, for
 * as long as it keeps failing. While it does, "service restarting" is listed (not degraded);
 * from its SUP_FAILED_AFTER-th failure in a row the node is degraded ("service failed").
 * After SUP_STABLE_MS running, the count starts over. A service whose data failed (a list
 * or bundle that doesn't load) isn't restarted: that has its own reason (blocking, hosted
 * zones), and loading it again changes nothing. The node never reboots for a service.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SUP_BACKOFF_MIN_MS  5000
#define SUP_BACKOFF_MAX_MS  300000
#define SUP_FAILED_AFTER    3
#define SUP_STABLE_MS       60000
#define SUP_STALL_REBOOTS   3
#define SUP_STALL_WINDOW_MS 600000
/* Deadlines: the listeners check in every SUP_LISTENER_CHECKIN_MS, a fifth of their
 * deadline, so only a listener kept from running for 8 s or more is late (against two
 * wakeups a second at idle, next to the 1 kHz tick's thousand: nothing to save there); a
 * UDP worker when it takes a query and before each parked query it answers, and never waits
 * on a forwarder (it hands its upstream queries to the forward loop, fwdq.h), so one late
 * by 10 s is stuck; the forward loop at least every FWDQ_CHECKIN_MS (1 s) while it waits; a
 * service task may wait on a zone transfer or the SD card. */
#define SUP_LISTENER_MS     10000
#define SUP_LISTENER_CHECKIN_MS 2000
#define SUP_WORKER_MS       10000
#define SUP_FORWARDER_MS    10000
#define SUP_TASK_MS         300000

/* ---- restarts ---- */

typedef struct {
    bool waiting;    /* failed: restart at at_ms */
    bool checking;   /* restarted: the next look says whether it took */
    uint32_t fails;  /* failures in a row */
    uint32_t at_ms;  /* waiting: when to restart; else since when it has run */
} sup_svc_t;

/* The backoff before the restart after the fails-th failure in a row. */
uint32_t sup_backoff_ms(uint32_t fails);
/* One look at a service, every second or so: broken is whether its start failed. True:
 * restart it now. */
bool sup_svc_tick(sup_svc_t *s, bool broken, uint32_t now_ms);
/* Failed now, SUP_FAILED_AFTER times in a row or more: the node is degraded. */
bool sup_svc_failed(const sup_svc_t *s);
/* Failed now, fewer times than that: listed only. */
bool sup_svc_restarting(const sup_svc_t *s);

/* ---- watchdogs ---- */

typedef enum { SUP_LISTENER, SUP_WORKER, SUP_TASK, SUP_FORWARDER } sup_role_t;

/* parked: the task waits for work that may never come (a UDP worker on its empty queue),
 * so it can't be stuck and isn't late however long it waits; its next check-in ends it.
 * Idle means idle: a parked task needn't wake to check in. */
typedef struct {
    bool on;
    uint8_t role; /* sup_role_t */
    int8_t svc;   /* the service it belongs to (svc.h) */
    uint32_t deadline_ms;
    volatile uint32_t kick_ms;
    volatile bool parked;
} sup_watch_t;

/* The services (as SVC_BITs) whose tasks are late at now; *stalled: the listeners have
 * stalled (a listener late, or every worker). The forward loop isn't counted here. */
uint32_t sup_late(const sup_watch_t *w, int n, uint32_t now_ms, bool *stalled);
/* Whether the forward loop (SUP_FORWARDER) is late at now. */
bool sup_forwarder_late(const sup_watch_t *w, int n, uint32_t now_ms);

/* ---- listener stalls ---- */

/* The stall reboots in a row (kept across boots), at a boot: count, plus one if this boot
 * follows a reset by the hardware task watchdog (the supervisor itself stalled). */
uint32_t sup_stall_boot(uint32_t count, bool after_watchdog);
/* The listeners stalled with count stall reboots in a row behind: true to reboot (count is
 * then one more, to keep before it), false to stay up in fault. */
bool sup_stall_reboot(uint32_t *count);
/* Up this long: the stall reboots in a row start over. */
bool sup_stall_settled(uint32_t uptime_ms);
