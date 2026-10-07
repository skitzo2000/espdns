/*
 * The node's settings (cfg.h) on the node: the node config is a signed REL_CONFIG release
 * kept in the `config` partition in two 16 KB slots (the release header, then the JSON).
 * At boot the valid slot with the highest seq is used, else the other, else the firmware
 * defaults; a stored config the firmware now refuses falls back the same way and says so
 * (settings_error()).
 *
 * A pushed config is checked in full before anything is written, stored in the slot not in
 * use, then applied: live if only live settings differ, else at the next reboot (reboot
 * pending, reboot.h: the node goes on serving on the config it runs until the controller
 * reboots it; a power cut boots into the new one the same way). A change of address or
 * Wi-Fi network boots on trial (docs/design.md, Adoption and addressing): the trial is
 * armed before the slot is written, and holds at whichever boot first runs the config;
 * unless a DNS query reaches the node within SETTINGS_TRIAL_S of that boot, it goes back to
 * the previous config (or the defaults) and reboots onto its old address.
 *
 * A node flashed before the `config` partition existed keeps its slots in NVS instead, up
 * to SETTINGS_NVS_MAX bytes each, until it is reflashed with the new layout.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "release.h"

#define SETTINGS_TRIAL_S 90
#define SETTINGS_NVS_MAX 4000

/* Board layer first (after board_load), then the stored node config. Before net_start. */
void settings_load(void);
/* The settings the node runs with. Live settings may change under a reader (word-sized
 * fields only); use settings_forwarders for the list. */
const cfg_t *settings(void);
/* A consistent copy of the default forwarders (out has CFG_MAX_FWD room); returns how many. */
int settings_forwarders(uint32_t *out, int *timeout_ms);

/* ---- releases (POST /release, in ota.c) ---- */
typedef bool (*settings_recv_fn)(void *ctx, uint8_t *buf, size_t n);
/* Receives a verified config release's payload, checks it (JSON, every setting) and stores
 * it in the free slot. NULL, or why it was refused (nothing is stored then). */
const char *settings_store(const uint8_t hdr[REL_HEADER_LEN], const rel_manifest_t *m, settings_recv_fn recv,
                           void *ctx);
/* Puts the stored config to use once its seq is recorded; a line for the reply in msg.
 * *reboot: it applies at the next reboot, which is now pending (the node doesn't reboot). */
const char *settings_apply(const rel_manifest_t *m, char *msg, size_t cap, bool *reboot);

/* If this boot runs a config on trial: confirm it once a query arrives, else revert. */
void settings_confirm_when_healthy(void);

/* ---- health ---- */
/* Why the stored config isn't in use (refused, unreadable, failed its trial), or NULL. A
 * hook for the health states: the node runs on its previous config or the defaults. */
const char *settings_error(void);
/* True while a config is on trial. */
bool settings_on_trial(void);
/* True if the node runs on a node config (it has been adopted), not the firmware defaults. */
bool settings_adopted(void);
/* Appends "config":{...} to a JSON object being written. Returns the bytes written. */
size_t settings_status_json(char *j, size_t cap);
