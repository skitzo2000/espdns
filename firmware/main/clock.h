/*
 * The clock service (docs/design.md, Time): SNTP once the node is answering, never in front
 * of it. Servers come from the node config; with none, on DHCP the NTP server the lease
 * names, then the default gateway, then pool.ntp.org (cfg_ntp_slots). The time zone (a POSIX TZ string) is a setting too; both apply live.
 * Until the first sync the clock counts from boot; an unsynced clock is not a fault.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/* Right after net_start (so an NTP server in the DHCP lease is taken); SNTP itself starts
 * once the node has an address and its DNS listeners are open. */
void clock_start(void);
/* The time settings changed (settings_apply): new zone, servers. */
void clock_apply(void);
/* True once the clock has been set over SNTP. */
bool clock_synced(void);
/* Appends "time":{...} to a JSON object being written. Returns the bytes written. */
size_t clock_status_json(char *j, size_t cap);
