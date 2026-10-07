/*
 * Node settings in layers (docs/design.md, Boards and images: settings in layers). A value
 * comes from the first of:
 *
 *   1. the node config: a signed REL_CONFIG release whose payload is JSON (below);
 *   2. the board definition (board_def.h): the Wi-Fi transmit power cap, the address
 *      the builder flashed the node with, and clock scaling (cpuplan.h, which applies it);
 *   3. the firmware default (config.h; the chip image's clocks, cpuplan.h): none for an
 *      address, unless the build sets one.
 *
 * A key the node config leaves out keeps the layer below; a list it gives replaces the
 * lower one whole ("forward_zones": [] means none). Unknown keys are refused, so a typo
 * never silently does nothing. The node config, all keys optional:
 *
 *   {
 *     "format": 1,
 *     "name": "dns-a",                       (also a Host its HTTP server answers to: httpguard.h)
 *     "network": { "address": "192.0.2.53/24", "gateway": "192.0.2.1" },
 *                 (or { "address": "dhcp" }, for a network with a DHCP server; without it
 *                  the board's address, else the firmware's. A node with none of them has
 *                  no address: it never asks DHCP on its own)
 *     "wifi": { "ssid": "home", "password": "...", "tx_power_dbm": 11, "power_save": false },
 *     "forwarders": [ "9.9.9.9", "1.1.1.1" ],              (0-4; [] turns forwarding off)
 *     "upstream_timeout_ms": 1500,
 *     "forward_zones": [ { "zone": "corp.example", "forwarder": "198.51.100.53" } ],
 *     "secondary": { "primary": "192.0.2.254", "zones": [ "local", "example.com" ],
 *                    "soa_poll_s": 60, "retry_s": 30 },
 *     "hosted": { "enabled": true },
 *     "time": { "ntp": [ "192.0.2.1" ], "tz": "EST5EDT,M3.2.0,M11.1.0" },
 *                 (no ntp servers: on DHCP the one the lease names, then the default
 *                  gateway, then pool.ntp.org: cfg_ntp_slots)
 *     "blocking": { "enabled": true, "answer": "null", "ttl": 10 },
 *                                           (answer "null": 0.0.0.0 / :: / NODATA, or "nxdomain")
 *     "cpu": { "dfs": false },              (clock scaling; left out: the board's, else the
 *                                            chip image's default: cpuplan.h)
 *     "querylog": { "enabled": true, "client": "full" }
 *                                           (the query log, qlog.h; client: "full", "subnet"
 *                                            (the /24 only) or "hidden" (no address kept))
 *   }
 *
 * The services a node runs follow from it (svc.h): forwarding while it has default
 * forwarders, forward zones and secondary zones while it has any, and hosted zones and
 * blocking and the query log while "enabled" (true unless a config says false: the firmware
 * defaults, config.h). A service that is off costs nothing.
 *
 * Settings that can change live (name, wifi tx_power_dbm and power_save, forwarders,
 * upstream_timeout_ms, secondary soa_poll_s and retry_s, hosted, time, blocking, cpu, querylog) do,
 * and so forwarding, hosted zones, blocking and the query log start and stop live; any other change (address,
 * Wi-Fi network, zones, primary, forward zones) applies with a reboot.
 *
 * Portable: parsed and checked on the host in the tests.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "board_def.h"
#include "release.h"

#define CFG_FORMAT     1
#define CFG_MAX_FWD    4
#define CFG_MAX_ZONES  32
#define CFG_MAX_FZONES 32
#define CFG_MAX_NTP    3
#define CFG_HOST_MAX   64 /* an NTP server's name, with its NUL */
#define CFG_TZ_MAX     64
#define CFG_NAME_MAX   32
#define CFG_POOL       4096 /* zone names */
/* A slot of the `config` partition (two of them): the release header, then the payload. */
#define CFG_SLOT_SIZE  16384
#define CFG_JSON_MAX   (CFG_SLOT_SIZE - REL_HEADER_LEN)

typedef struct {
    const char *zone;
    uint32_t forwarder; /* IPv4, network order */
} cfg_fzone_t;

/* Which layer the address came from. */
typedef enum { CFG_ADDR_NONE, CFG_ADDR_FIRMWARE, CFG_ADDR_BOARD, CFG_ADDR_CONFIG } cfg_addr_from_t;

/* The settings a node runs with. Zone names point into pool (or at the built-in defaults),
 * so a cfg_t is never copied by value: fill one in place with cfg_build. */
typedef struct {
    char name[CFG_NAME_MAX];

    /* network (reboot); IPv4 in network order. ip 0 is no static address: DHCP if dhcp is
     * set (a layer asked for it), else no address at all. */
    uint32_t ip, netmask, gateway;
    bool dhcp;
    cfg_addr_from_t addr_from;
    char wifi_ssid[33]; /* "" = the network saved over USB (Improv) */
    char wifi_pass[64];
    /* live */
    int wifi_tx_dbm; /* 0 = the chip's default */
    bool wifi_power_save;

    /* forwarding (live) */
    uint32_t fwd[CFG_MAX_FWD];
    int nfwd;
    int upstream_timeout_ms;
    /* conditional forwarders (reboot) */
    cfg_fzone_t fzones[CFG_MAX_FZONES];
    int nfzones;

    /* secondary zones (reboot), and how often they are checked (live) */
    uint32_t primary;
    const char *zones[CFG_MAX_ZONES];
    int nzones;
    int soa_poll_s, retry_s;

    /* hosted zones (live) */
    bool hosted;

    /* time (live) */
    char ntp[CFG_MAX_NTP][CFG_HOST_MAX];
    int nntp;
    char tz[CFG_TZ_MAX];

    /* blocking (live) */
    bool blocking; /* the service runs */
    bool block_nxdomain;
    int block_ttl;

    /* CPU clock scaling (live): 1 on, 0 off, -1 not given (the board's, else the image's:
     * cpuplan.h) */
    int cpu_dfs;

    /* the query log (live): the service runs, and how much of a client's address it keeps
     * (ql_client_t, qlog.h) */
    bool querylog;
    uint8_t querylog_client;

    char pool[CFG_POOL];
    size_t pool_used;
} cfg_t;

/* Fills c with the layers: firmware defaults, then the board (b may be NULL), then the node
 * config (json NULL: none). False with a reason in err if the node config is malformed or
 * fails a check; c is then the defaults and board only. */
bool cfg_build(cfg_t *c, const board_desc_t *b, const char *json, size_t len, char *err, size_t errlen);

/* True if going from a to b needs a reboot (a setting that can't change live differs). */
bool cfg_needs_reboot(const cfg_t *a, const cfg_t *b);
/* Which settings that apply only at a boot differ from a to b: RB_CONFIG_* (reboot.h). */
uint32_t cfg_reboot_reasons(const cfg_t *a, const cfg_t *b);
/* True if the address or the Wi-Fi network differs: such a change boots on trial, and goes
 * back to the previous config unless the node is reached on its new address. */
bool cfg_net_changed(const cfg_t *a, const cfg_t *b);
/* Copies the settings that change live from src into dst (and, with the same address, where
 * the address comes from). */
void cfg_copy_live(cfg_t *dst, const cfg_t *src);

/* The SNTP server slots for the config (docs/design.md, Time), max of them (lwIP's count,
 * at most CFG_MAX_NTP): the configured servers; with none, the server a DHCP lease names
 * (on a config that asks for DHCP: *dhcp set and slot 0 left empty for it), then the gateway (network order; 0 =
 * none), then DNS2_NTP_FALLBACK. lwIP moves on to the next slot when one doesn't answer,
 * so a router that doesn't serve NTP costs one timeout. Unused slots are "". */
void cfg_ntp_slots(const cfg_t *c, uint32_t gateway, int max, char slots[][CFG_HOST_MAX], bool *dhcp);

/* A network setting's address and gateway (address NULL: not given; gateway NULL: not
 * given): "dhcp", or an address with its prefix length (8-30) and a gateway in its network.
 * Shared by the node config and the board definition. False with a reason in err. */
bool cfg_parse_net(const char *address, const char *gateway, board_net_t *out, char *err, size_t errlen);
/* "static", "dhcp" or "none", and the layer it came from ("config", "board", "firmware"). */
const char *cfg_addr_kind(const cfg_t *c);
const char *cfg_addr_from(const cfg_t *c);

/* The address built into this image (DNS2_STATIC_IP, config.h), "" for none. In the image
 * it follows CFG_BUILTIN_ADDR_MARK, which the controller and tools/ota_push.py look for. */
#define CFG_BUILTIN_ADDR_MARK "espdns:builtin-address="
const char *cfg_builtin_addr(void);

/* Strict dotted-quad IPv4 ("198.51.100.1"; no shorthand, no leading zeros). Network order. */
bool cfg_parse_ipv4(const char *s, uint32_t *out);

/* Checks a stored config slot: the release header (signature, kind, node, image) and the
 * payload's SHA-256. avail is how many payload bytes the slot can hold. NULL if good. */
const char *cfg_slot_check(const uint8_t hdr[REL_HEADER_LEN], const uint8_t *payload, size_t avail,
                           const rel_trust_t *t, rel_manifest_t *m);

/* Which of two slots to try first at boot: the valid one with the higher seq. ok[i] says
 * whether slot i passed cfg_slot_check; a slot whose seq is bad_seq (a config that failed
 * its trial) is skipped. Returns the slot, or -1 if neither is usable; *other is the one
 * to fall back to, or -1. */
int cfg_slot_pick(const bool ok[2], const uint64_t seq[2], uint64_t bad_seq, int *other);
