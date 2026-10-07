/*
 * The CPU clock plan (docs/design.md, Node OS: idle means idle). With dynamic frequency
 * scaling (DFS, ESP-IDF power management) the CPU runs at the image's clock (max_mhz)
 * whenever a core has work, and at min_mhz while both are idle; ESP-IDF raises the clock
 * in the first instructions of the interrupt that wakes a core, before any handler runs.
 * There is no automatic light sleep: it would drop the Ethernet link or the Wi-Fi
 * association, and every board here has a link to keep.
 *
 * Whether DFS is on, and the idle clock, come from the board definition's "cpu"
 * (board_def.h), else this chip image's defaults below; the node config's "cpu": {"dfs"}
 * turns it on or off live (cfg.h). Nothing is guessed at run time.
 *
 * The idle clock has a floor while a driver holds the APB clock at its maximum: the chip's
 * built-in Ethernet MAC holds it for as long as it runs, and Wi-Fi while its radio is awake
 * (always with power saving off). ESP-IDF then idles at the "APB max" clock: apb_mhz below,
 * or min_mhz if higher (cp_idle_mhz).
 *
 * Portable: run on the host in the tests; power.c applies it on the node. The controller
 * checks a board's "cpu" the same way (controller/internal/boards, the same test vectors in
 * firmware/tests/cpu_vectors.json).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "board_def.h"

#define CP_MAX_MINS 3

/* A chip image's clocks, MHz. */
typedef struct {
    const char *image;
    int max_mhz;               /* the image's clock (CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ) */
    int apb_mhz;               /* the idle floor while the APB clock is held at its maximum */
    bool dfs;                  /* on by default */
    int min_mhz;               /* the default idle clock */
    int mins[CP_MAX_MINS + 1]; /* the idle clocks a board may choose, 0-terminated */
} cp_image_t;

/* The image's clocks, or NULL for an image not in the table. */
const cp_image_t *cp_image(const char *image);

/* Whether min_mhz is one of the image's idle clocks (true for an image not in the table:
 * board_def.c checks only what it knows). */
bool cp_min_ok(const char *image, int min_mhz);

/* The board's clocks. */
typedef struct {
    bool dfs;        /* on, before the node config has its say */
    bool dfs_board;  /* the board definition says so (else the image's default) */
    int max_mhz, min_mhz, apb_mhz;
} cp_board_t;

/* Fills *out from a board definition (b may be NULL: none) on the chip image named image. A
 * key the board leaves out is the image's default; an image not in the table runs without
 * DFS. */
void cp_board(const board_desc_t *b, const char *image, cp_board_t *out);

/* DFS on or off: the node config's "cpu": {"dfs"} (cfg_dfs: -1 not given, 0, 1), else the
 * board's. Never on where the image has no idle clock (min_mhz 0). */
bool cp_dfs(const cp_board_t *b, int cfg_dfs);

/* The clock the node idles at: max_mhz without DFS; with it, min_mhz, or the APB floor if
 * apb_held (an EMAC running, or Wi-Fi with power saving off). */
int cp_idle_mhz(const cp_board_t *b, bool dfs, bool apb_held);
