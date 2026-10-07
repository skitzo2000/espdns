/*
 * Health on the node: gathers health.h's inputs from every service, logs each change of
 * state, and shows the state on the board's LED (or identify, when the controller asks).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "health.h"

/* The state now. */
health_t health_now(void);
/* Starts the monitor: the LED if the board has one, and a log line per change of state. */
void health_start(void);
/* Identify for secs seconds (0 stops). False if the board has no LED to show it on. */
bool health_identify(uint32_t secs);
/* Seconds of identify left. */
uint32_t health_identify_left(void);
