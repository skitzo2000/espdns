/*
 * Services (docs/design.md, Node OS): the node config decides which of the services built
 * into the image run. Each has a name, a start and a stop, and a state; one that is off has
 * no task, no stack, no buffers and no timers, and no work on the query path. Portable:
 * which services a config enables, what a live config change starts and stops, and the
 * /status JSON run on the host in the tests; services.c holds the node's table.
 *
 * Enabled by the config (cfg.h):
 *   dns            always: the DNS listeners and the cache
 *   forwarding     while it has default forwarders ("forwarders": [] turns it off)
 *   forward_zones  while it has conditional forwarders
 *   secondary      while it has secondary zones (zone transfers, SOA polling, NOTIFY)
 *   hosted         "hosted": {"enabled"}, on unless a config says false
 *   blocking       "blocking": {"enabled"}, on unless a config says false
 *   querylog       "querylog": {"enabled"}, on unless a config says false: the ring of recent
 *                  queries (qlog.h), in memory.querylog_kb (none on a board without PSRAM)
 *
 * Forwarding, hosted zones, blocking and the query log start and stop live (SVC_LIVE). Forward zones and
 * secondary zones are what the zone registry is built from at boot: a change to them is a
 * reboot (RB_CONFIG_ZONES), as any change of zones is.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cfg.h"

typedef enum {
    SVC_DNS,
    SVC_FORWARDING,
    SVC_FORWARD_ZONES,
    SVC_SECONDARY,
    SVC_HOSTED,
    SVC_BLOCKING,
    SVC_QUERYLOG,
    SVC_N
} svc_id_t;

#define SVC_BIT(id) (1u << (id))
#define SVC_ALL     (SVC_BIT(SVC_N) - 1)
/* The services that start and stop with a live config change. */
#define SVC_LIVE    (SVC_BIT(SVC_FORWARDING) | SVC_BIT(SVC_HOSTED) | SVC_BIT(SVC_BLOCKING) | SVC_BIT(SVC_QUERYLOG))
/* The services that keep data on the SD card (saved zones, hosted zones, lists). */
#define SVC_SD      (SVC_BIT(SVC_SECONDARY) | SVC_BIT(SVC_HOSTED) | SVC_BIT(SVC_BLOCKING))

typedef enum { SVC_OFF, SVC_STARTING, SVC_RUNNING, SVC_FAILED, SVC_NSTATES } svc_state_t;

/* The services c enables, as SVC_BITs. */
uint32_t svc_enabled(const cfg_t *c);
/* Going from the services in before to those in after (svc_enabled): the live ones to stop
 * and to start. A change to the others waits for the reboot the config change asks for. */
void svc_changes(uint32_t before, uint32_t after, uint32_t *stop, uint32_t *start);

const char *svc_name(svc_id_t id);
const char *svc_state_name(svc_state_t s);
/* "services":[{"name":"dns","state":"running","memory":{"planned":N,"allocated":M}},...]
 * (no outer braces): each service's share of the memory plan (memplan.h) and what it holds
 * now, in bytes. Returns the bytes written. */
size_t svc_json(const svc_state_t st[SVC_N], const size_t planned[SVC_N], const size_t allocated[SVC_N], char *j,
                size_t cap);
