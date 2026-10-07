/*
 * Board layer. The board is data, not code (docs/design.md, Boards and images): its
 * definition is read at boot from the `board` partition (format in board_def.h) and says
 * how the board is wired: Ethernet (the chip's own MAC with a PHY, or a W5500 over SPI), SD
 * card (SDMMC or SPI, possibly sharing a bus with the W5500), LED, Wi-Fi defaults. The code
 * here brings up whatever it describes.
 *
 * The image is built per chip (`make build IMAGE=esp32s3-octal`). A transitional image for
 * a node without a `board` partition yet also carries one catalog board as a fallback
 * (`make build BOARD=xiao-s3-sense`).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "board_def.h"
#include "esp_eth.h"

/* The board this node is, once board_load() has run. */
extern board_desc_t board;

/* Reads the board definition: the `board` partition, else the image's fallback board.
 * False if neither gives one that fits this image; the node then runs with no Ethernet and
 * no SD card, and says why (board_source(), board_error()). */
bool board_load(void);
/* "partition", "fallback" or "none". */
const char *board_source(void);
/* Why the `board` partition wasn't used, or "" if it was. */
const char *board_error(void);
/* The chip image this firmware is (ESPDNS_IMAGE), and the fallback board's name or "". */
const char *board_image(void);
const char *board_fallback_name(void);

/* Installs the board's Ethernet driver (not started, no interface attached). False if the
 * board has no Ethernet or it failed to start (a W5500 module not fitted). */
bool board_eth_install(esp_eth_handle_t *eth);
/* Mounts the SD card at DNS2_SD_MOUNT and creates the zone directory. */
bool board_sd_mount(void);
