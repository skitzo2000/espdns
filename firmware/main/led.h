/*
 * The board's status LED, as its definition declares it (board.led): none, a plain GPIO
 * (active high or low), or one WS2812 RGB LED driven with the RMT peripheral. health_node.c
 * decides what it shows.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Sets the LED up. False if the board has none or it failed to start (then led_set does
 * nothing). */
bool led_init(void);
/* On in colour r,g,b (a single-colour LED ignores the colour), or off. */
void led_set(bool on, uint8_t r, uint8_t g, uint8_t b);
/* "none", "gpio" or "ws2812"; "failed" if it didn't start. */
const char *led_kind_name(void);
