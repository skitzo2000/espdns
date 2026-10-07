/*
 * Reboot pending (docs/design.md, Signed releases): a release that only applies at a boot
 * (a config with a new address, a list two copies of which don't fit, a staged firmware) is
 * stored, checked and kept, and the node goes on serving on what it runs until the
 * controller reboots it with a control release (payload below), one node at a time.
 * Portable: the state, its /status JSON and the control payload run on the host in the
 * tests; ota.c keeps the node's state and does the reboot.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Why a reboot is pending, as bits; several can be. */
enum {
    RB_CONFIG_ADDRESS = 1u << 0, /* the config changes the address, netmask or gateway */
    RB_CONFIG_WIFI = 1u << 1,    /* ...the Wi-Fi network */
    RB_CONFIG_ZONES = 1u << 2,   /* ...secondary zones, the primary, forward zones */
    RB_BLOCKLIST = 1u << 3,      /* a list that only fits once the active one is gone */
    RB_FIRMWARE = 1u << 4,       /* a firmware staged by POST /ota with X-OTA-Reboot: later */
    RB_NBITS = 5
};
#define RB_CONFIG (RB_CONFIG_ADDRESS | RB_CONFIG_WIFI | RB_CONFIG_ZONES)

typedef struct {
    uint32_t reasons;
    uint32_t since_s; /* uptime when the first reason still pending was set */
} rb_state_t;

/* Replaces the reasons in mask with set (set outside mask is ignored). The pending time
 * starts when the node goes from none to some, and is kept while any stays. */
void rb_update(rb_state_t *s, uint32_t mask, uint32_t set, uint32_t now_s);
/* A reason bit's name, as /status lists it ("config: address", "blocklist: size", ...). */
const char *rb_reason_name(uint32_t bit);
/* "reboot":{"pending":bool,"reasons":[...],"since_s":N} (no outer braces): since_s is how
 * long a reboot has been pending, 0 when none is. Returns the bytes written. */
size_t rb_json(const rb_state_t *s, uint32_t now_s, char *j, size_t cap);

/* ---- control release: reboot ---- */

/* REL_CONTROL payload 04, u32 delay_ms (little-endian, at most RB_DELAY_MAX_MS), then an
 * optional u8 of flags. The node replies, then reboots after the delay. */
#define RB_CTL_REBOOT      4
#define RB_DELAY_MAX_MS    60000
#define RB_FLAG_IF_PENDING 0x01 /* reboot only if a reboot is pending */

typedef struct {
    uint32_t delay_ms;
    uint8_t flags;
} rb_ctl_t;

/* Parses a reboot control payload. Returns NULL, or why it is refused. */
const char *rb_ctl_parse(const uint8_t *p, size_t n, rb_ctl_t *out);
