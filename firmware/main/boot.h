/*
 * Boot timing: milliseconds since the app started (esp_timer) at which each startup step
 * finished. The node is answering once it has an IP and its DNS listeners are open; that
 * moment is boot_ms in /status. esp_timer misses ROM and bootloader time, which
 * tools/boottime.py measures from outside.
 */
#pragma once

#include <stdint.h>

/* Must fit under this or the post-update health check fails (docs/design.md, Boot). */
#define BOOT_LIMIT_MS 15000

typedef enum { BOOT_SD, BOOT_ZONES, BOOT_LINK, BOOT_IP, BOOT_LISTEN, BOOT_NSTEPS } boot_step_t;

/* Records the first time a step finishes; later calls (a link flap) are ignored. */
void boot_mark(boot_step_t step);
/* When the step finished, 0 if it hasn't. */
uint32_t boot_step_ms(boot_step_t step);
const char *boot_step_name(boot_step_t step);
/* When the node started answering (IP and listeners both up), 0 until then. */
uint32_t boot_ms(void);
