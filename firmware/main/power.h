/*
 * Idle clock scaling on the node (docs/design.md, Node OS: idle means idle): applies the
 * CPU clock plan (cpuplan.h) with ESP-IDF power management, live, and holds the clock at
 * its maximum while there is work.
 *
 * ESP-IDF already runs a core at the maximum while it has a task to run, and raises the
 * clock on the interrupt that wakes it; the clock drops only while both cores are idle.
 * The holds below say where work is, so a short wait inside it (a worker handing its
 * answer to the network stack, a load task between two SD reads) doesn't drop the clock
 * and raise it again, and so /status can say how long the node was busy:
 *
 *   POWER_DNS   a DNS worker from taking a query to sending its answer, but not while it
 *            waits on a forwarder (server.c): that wait is idle time, and the clock is
 *            back up on the answer's interrupt, microseconds against the forwarder's
 *            milliseconds.
 *   POWER_WORK  CPU-bound background work, so it never runs slower for the scaling: the
 *            blocklist and hosted zones' loads, a zone transfer and its save, a release
 *            being received, verified and applied (firmware, config, zones, lists).
 *
 * Holds nest and may be taken from any task; they cost a few hundred nanoseconds.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum { POWER_DNS, POWER_WORK, POWER_NHOLDS } power_hold_t;

/* First thing at boot: makes the holds (no scaling yet). */
void power_init(void);
/* After the listeners are open: scaling as the board and the node config say. Boot runs at
 * the full clock throughout. */
void power_start(void);
/* A node config applied live (settings.c): its "cpu": {"dfs"}. */
void power_apply(void);

void power_hold(power_hold_t h);
void power_release(power_hold_t h);

/* The clock and the holds, for /metrics: what /status "cpu" says. */
typedef struct {
    bool dfs;
    int max_mhz, idle_mhz;
    unsigned long holds[POWER_NHOLDS];
    uint64_t busy_us[POWER_NHOLDS]; /* held by anyone since boot */
} power_info_t;
void power_info(power_info_t *p);

/* "cpu":{...} for /status. */
size_t power_status_json(char *j, size_t cap);
