/*
 * Secondary-zone maintenance: load saved zones from SD, poll the primary's SOA serial,
 * pull full zone transfers (AXFR) when it changes, react to NOTIFY, enforce EXPIRE. The
 * secondary service (svc.h): it runs only on a node config with secondary zones, which
 * change with a reboot.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "svc.h"

/* Loads every configured zone from SD (before the network is up). */
void xfr_load_saved(void);
/* Starts the refresh task, if the config has secondary zones. */
void xfr_start(void);
svc_state_t xfr_state(void);
/* Its start failed (its task or its buffers): the supervisor starts it again. */
bool xfr_broken(void);
/* What it holds now, bytes: the zones, the transfer buffers and the task's stack. */
size_t xfr_held(void);
/* Called by the server for a NOTIFY from the primary. */
void xfr_notify(int slot);
