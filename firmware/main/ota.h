/*
 * Network firmware updates and a status page, on HTTP port 80.
 *
 *   GET  /health  JSON: state, reasons, blocklist seq and hash; 200 while answering, else 503
 *   GET  /status  JSON: firmware, running slot, node ID, trusted keys, release seqs, boot times,
 *                 zones, counters
 *   GET  /metrics Prometheus text: counters and gauges, no names clients looked up (metrics_node.h);
 *                 open, as /health
 *   GET  /querylog JSON: the query log after a cursor (querylog.h); private addresses only
 *   POST /ota     signed firmware release: header (release.h) + dns2.bin; reboots into it,
 *                 or with "X-OTA-Reboot: later" (or ?reboot=0) stages it: reboot pending
 *   POST /release signed release of another kind: header + payload (config, settings.h;
 *                 hosted zones, hosted.h; blocklist, overrides and control, blocking.h)
 *
 * Every request must name this node in its Host header (its address, its .local name or its
 * configured name; else 421), and runs against a deadline; a release's payload, once its
 * signed header verified, in a worker task of its own (httpguard.h).
 *
 * Only public keys are built in (keys/release.pub, keys/recovery.pub), so a build holds no
 * secret. A new image boots on trial and must pass ota_confirm_when_healthy() or the
 * bootloader rolls back.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_http_server.h"
#include "release.h"

void ota_start(void);
/* Whether the request comes from a private address (RFC 1918, RFC 6598), as the release
 * endpoints and GET /querylog require. */
bool ota_peer_private(httpd_req_t *req);
/* If this boot is a trial after an update: mark it good once healthy, else roll back. */
void ota_confirm_when_healthy(void);
/* What this node trusts and who it is (usable from boot, after board_load). */
const rel_trust_t *ota_trust(void);
/* The highest seq applied for a release kind (NVS); 0 if none ever was. */
uint64_t ota_seq(uint8_t kind);
/* True while a release (firmware or another kind) is being received. */
bool ota_busy(void);
/* The request's reply starts now: it has HG_REPLY_MS to go out (httpguard.h), however long
 * the work before it took (a release's apply, a benchmark). */
void ota_http_reply(httpd_req_t *req);

/* ---- reboot pending (reboot.h) ---- */

/* Replaces the pending-reboot reasons in mask with set (RB_* bits). */
void ota_reboot_update(uint32_t mask, uint32_t set);
/* The reasons a reboot is pending; 0: none. */
uint32_t ota_reboot_reasons(void);
/* Reboots in delay_ms (at least long enough for the HTTP reply to go out), once no
 * release is being received. A reboot already scheduled sooner stays. */
void ota_reboot_after(uint32_t delay_ms);
/* True once a reboot is scheduled. */
bool ota_rebooting(void);
