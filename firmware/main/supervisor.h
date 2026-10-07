/*
 * The supervisor on the node (rules in sup.h; docs/design.md, Node OS): a task that looks
 * at every watched service task and every optional service once a second, restarts a
 * service whose start failed (with backoff), and reboots the node if the DNS listeners
 * stall, at most SUP_STALL_REBOOTS times in a row. It is itself watched by ESP-IDF's task
 * watchdog (in hardware, with a reset if it stops), which watches nothing else: a busy DNS
 * worker never trips it.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "sup.h"

/* After the listeners are open. */
void supervisor_start(void);

/* A service task to watch: it must call supervisor_kick(h) at least every deadline_ms.
 * Returns the handle, or -1 (the table is full: it isn't watched). Any task may call these,
 * before the supervisor starts too. */
int supervisor_watch(int svc, sup_role_t role, uint32_t deadline_ms);
void supervisor_kick(int h);
void supervisor_unwatch(int h);
/* The task is about to wait for work that may never come: not late while it waits (sup.h,
 * parked); its next supervisor_kick ends that. */
void supervisor_park(int h);

/* For health (health.h): services failing or whose task stalled; services restarting;
 * the listeners stalled and the node stays up in fault. */
uint32_t supervisor_failed(void);
uint32_t supervisor_restarting(void);
bool supervisor_stalled(void);
/* The forward loop missed its watchdog (sup.h, SUP_FORWARDER): degraded, never a reboot. */
bool supervisor_fwd_stalled(void);
