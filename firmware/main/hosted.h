/*
 * The hosted zones service (docs/design.md, Answering; format and checks in hzone.h): the
 * zones bundle of the last REL_ZONES release, kept on SD in two slots under
 * DNS2_HOSTED_DIR (zones.0, zones.1: the payload, then its signed release header, as the
 * blocklist's), and answered from RAM through the registry. A revert goes back to the
 * older bundle in the other slot, as the blocklist's does (hosted_revert).
 *
 * At boot the valid slot with the highest seq loads before the listeners open, if the card
 * mounted in time (the saved zones' place in the boot budget); a card that mounts later
 * gets them loaded then, in the background. A pushed bundle is checked in full before it
 * is stored, then swapped in live: queries see the old zones or the new ones, never a mix.
 *
 * The service runs while the node config enables it (hosted.enabled, svc.h), and starts and
 * stops live: off, no zones are in memory, no task runs, the names are forwarded and a
 * bundle is refused. On but never sent a bundle, it has nothing to load and is not
 * degraded. Once one was installed (its seq is in NVS), a bundle that is missing, corrupt,
 * refused or too big for the board makes the node degraded ("hosted zones"), and its
 * hosted names are forwarded as if not hosted. A hosted zone that the node config also names as a secondary or
 * forward zone is refused when pushed; one left over from before a config change is not
 * served, and degrades the node.
 *
 * Hosted zones are served as any local zone: authoritative answers, CNAME chains across
 * local zones, never blocked. Nodes don't serve AXFR/IXFR or send NOTIFY for them: every
 * node gets the bundle from the controller.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "block.h"
#include "cfg.h"
#include "release.h"
#include "svc.h"

/* At boot, after reg_init and settings_load. sd_in_time: the card mounted within its boot
 * timeout (the zones load now); else they load in the background once it mounts. Does
 * nothing while the node config has it off; hosted_start(false) is the live start once a
 * config turns it on. */
void hosted_start(bool sd_in_time);
/* The live stop, when a config turns it off: the zones are unloaded and freed. */
void hosted_stop(void);
svc_state_t hosted_state(void);
/* Its start failed (its load task or lock), not its zones: the supervisor starts it again. */
bool hosted_broken(void);
/* What it holds now, bytes: the zones (hz_mem) in use and pending, and its load task. */
size_t hosted_held(void);

/* ---- releases (POST /release, in ota.c) ---- */
bool hosted_kind(uint8_t kind);
/* Why hosted_store refuses while the boot load hasn't finished: try again later. */
extern const char HOSTED_LOADING[];
/* Receives a verified REL_ZONES payload, checks it in full and stores it in the free slot.
 * NULL, HOSTED_LOADING (compare the pointer), or why it was refused (nothing stored). */
const char *hosted_store(const uint8_t hdr[REL_HEADER_LEN], const rel_manifest_t *m, blk_recv_fn recv, void *ctx);
/* Puts the stored bundle to use (live) once its seq is recorded; a line for the reply. */
const char *hosted_apply(const rel_manifest_t *m, char *msg, size_t cap, bool *reboot);

/* Revert (BLK_CTL_REVERT naming REL_ZONES, a control release blocking.c takes): back to the
 * older bundle in the other slot, live as a push is (the service's share holds the bundle in
 * use and one more, memplan.h). The seq it left is recorded in NVS (blocking_rev_set), so
 * later boots keep to it; the next bundle pushed ends it. hosted_revert_check: why it can't,
 * before the control release's seq is taken (HOSTED_LOADING: try again later), or NULL.
 * hosted_revert: does it, a line for the reply in msg; NULL, or why not (the zones in use
 * stay). Never the bundle reverted from, nor one newer than the zones in use. */
const char *hosted_revert_check(void);
const char *hosted_revert(char *msg, size_t cap);

/* For a config being pushed: why it can't be used with the hosted zones (a zone both
 * hosted and secondary or forwarded), or NULL. Uses buf for the message. */
const char *hosted_clash(const cfg_t *c, char *buf, size_t cap);

/* ---- health ---- */
bool hosted_degraded(void);
/* The boot fell back to an older bundle than the newest the node took (its slot corrupt,
 * unreadable or refused): degraded, "older copy". */
bool hosted_older(void);
/* "zones":{"state","seq","sha256"} for /health. */
size_t hosted_health_json(char *j, size_t cap);
/* "hosted":{...} for /status. */
size_t hosted_status_json(char *j, size_t cap);
/* The most hosted_status_json writes for the zones hosted now. */
size_t hosted_status_max(void);
