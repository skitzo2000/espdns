/*
 * The SD card at boot (docs/design.md, Boot and The SD card): mounted in its own task, in
 * parallel with the network link, with a hard timeout. Saved zones load only if it mounted
 * within the timeout; blocking waits for the result however long it takes. A missing card
 * never delays answering: the node runs from its config and forwarders, degraded.
 *
 * A card on the same SPI bus as a W5500 is mounted before the network starts instead (both
 * set the bus up, and the card's start-up must not see the W5500's traffic).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define SD_BOOT_TIMEOUT_MS 1500

typedef enum { SD_NONE, SD_PENDING, SD_MOUNTED, SD_FAILED } sd_state_t;

/* Starts mounting the board's card (after board_load). */
void sd_start(void);
/* Waits until SD_BOOT_TIMEOUT_MS after sd_start for the mount. A card still pending then
 * has timed out: it can still mount later (blocking then loads), but saved zones don't. */
sd_state_t sd_wait_boot(void);
/* Waits for the mount to finish, however long it takes. */
sd_state_t sd_wait(void);
sd_state_t sd_state(void);
bool sd_timed_out(void);
const char *sd_state_name(sd_state_t s);
/* When the mount finished (ms since the app started), 0 if it hasn't. */
uint32_t sd_done_ms(void);
