/*
 * The memory plan on the node (memplan.h): the board's values, worked out once at boot
 * from the board definition, this chip image and the PSRAM the chip found; the plan for the
 * services the node config runs, checked before they start (settings.c refuses a config
 * whose plan doesn't fit); and what each service holds, counted against its share.
 *
 * A service takes its big blocks (the cache, the DNS buffers, the lists) with share_alloc
 * when it starts or loads, never on the query path, and notes what else it holds (task
 * stacks) with share_note, so /status shows each service's planned and allocated bytes.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "memplan.h"

/* After board_load, before settings_load. */
void share_init(void);
const mp_board_t *share_board(void);
/* Whether the services c enables fit the board. False with why in err. */
bool share_check(const cfg_t *c, char *err, size_t errlen);
/* The plan the services run on: for the services in enabled (svc_enabled), from boot and
 * after each config applied live. */
void share_set_plan(uint32_t enabled);
const mp_plan_t *share_plan(void);

/* n bytes for service svc from pool (8-aligned), counted against it; NULL if the heap has
 * no such block. share_free gives it back (NULL is fine). */
void *share_alloc(int svc, mp_pool_t pool, size_t n);
void share_free(void *p);
/* Counts n more bytes (or fewer, negative) that svc holds outside share_alloc: task stacks. */
void share_note(int svc, mp_pool_t pool, long n);
/* What svc holds in pool: from share_alloc and share_note. */
size_t share_used(int svc, mp_pool_t pool);

/* Appends "memory":{...} (memplan.h, mp_json). Returns the bytes written. */
size_t share_status_json(char *j, size_t cap);
