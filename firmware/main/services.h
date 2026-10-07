/*
 * The node's service table (svc.h): each service's start, stop and state. app_main starts
 * them in the boot order (docs/design.md, Boot), each only if the node config enables it;
 * a config applied live starts and stops the light ones here, and the supervisor
 * (supervisor.h) starts again one whose start failed.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "svc.h"

/* Before anything below: at boot, before the supervisor and the HTTP server start. */
void services_init(void);
/* A config applied live went from the services in before to those in after
 * (svc_enabled): sets the memory plan for after (share.h), then stops and starts the live
 * ones that changed. */
void services_apply(uint32_t before, uint32_t after);
/* Whether svc's start failed (its task or its memory), as opposed to its data: the
 * supervisor starts it again. */
bool services_broken(int svc);
/* Starts svc again after its start failed, if the config that runs still enables it. */
void services_restart(int svc);
/* Each service's state, its share of the memory plan and what it holds now, bytes (for
 * /status and /metrics). */
void services_snapshot(svc_state_t st[SVC_N], size_t planned[SVC_N], size_t held[SVC_N]);
/* Appends "services":[...] to a JSON object being written. Returns the bytes written. */
size_t services_status_json(char *j, size_t cap);
