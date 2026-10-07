/*
 * Firmware defaults: the lowest layer of the node's settings (cfg.h). A node config pushed
 * as a signed release overrides any of them; until one is, a node runs on these. The
 * project's are neutral: no address, no zone primary, no zones, no conditional forwarders,
 * public forwarders. A deployment may build in its own (site defaults, below).
 */
#pragma once

/* ---- site defaults ---- A deployment's own firmware defaults: a header outside the repo
 * that the build includes first (make SITE_DEFAULTS=<file.h>, set in firmware/local.mk;
 * firmware/site-defaults.h.example shows every macro it may define). What it defines
 * replaces the project's default below; what it leaves out keeps it. */
#ifdef DNS2_SITE_DEFAULTS
#include DNS2_SITE_DEFAULTS
#endif

/* ---- network ---- The address a node starts on comes from its node config, else its board
 * definition (the builder writes it when it flashes the node), else DNS2_STATIC_IP. The build
 * sets that only for a transitional image of a node in service (make STATIC_IP=..., with
 * STATIC_NETMASK and STATIC_GATEWAY, which it requires with it); empty is no address. A node
 * never asks DHCP for one unless a layer says "dhcp". */
#ifndef DNS2_STATIC_IP
#define DNS2_STATIC_IP   ""
#endif
#ifndef DNS2_NETMASK
#define DNS2_NETMASK     ""
#endif
#ifndef DNS2_GATEWAY
#define DNS2_GATEWAY     ""
#endif
_Static_assert(sizeof(DNS2_STATIC_IP) == 1 || (sizeof(DNS2_NETMASK) > 1 && sizeof(DNS2_GATEWAY) > 1),
               "a built-in address (STATIC_IP) needs its netmask and gateway (STATIC_NETMASK, STATIC_GATEWAY)");

/* ---- zone transfers ---- The zone primary and the zones copied from it: none here. Each
 * list is the body of a brace-enclosed initializer; an empty string is no entry. */
#ifndef DNS2_PRIMARY
#define DNS2_PRIMARY     ""
#endif
#define DNS2_SOA_POLL_S  60   /* check the primary's serial at least this often */
#define DNS2_RETRY_MIN_S 30

#ifndef DNS2_SECONDARY_ZONES_LIST
#define DNS2_SECONDARY_ZONES_LIST ""
#endif
static const char *const DNS2_SECONDARY_ZONES[] = { DNS2_SECONDARY_ZONES_LIST };

/* ---- forwarding ---- Quad9's two resolvers */
#ifndef DNS2_FORWARDERS_LIST
#define DNS2_FORWARDERS_LIST "9.9.9.9", "149.112.112.112"
#endif
static const char *const DNS2_FORWARDERS[] = { DNS2_FORWARDERS_LIST };

typedef struct {
    const char *zone;
    const char *forwarder;
} dns2_fwd_zone_t;

/* Conditional forwarders ({ "zone", "forwarder" }, ...): none here. A primary's can't be
 * transferred, so a deployment copies them (into its node configs, or its site defaults). */
#ifndef DNS2_FORWARDER_ZONES_LIST
#define DNS2_FORWARDER_ZONES_LIST { "", "" }
#endif
static const dns2_fwd_zone_t DNS2_FORWARDER_ZONES[] = { DNS2_FORWARDER_ZONES_LIST };

#define DNS2_UPSTREAM_TIMEOUT_MS 1500

/* ---- time ---- NTP from the default gateway (on DHCP, the lease's server first), else the
 * fallback below, unless a config names servers (cfg_ntp_slots). Many routers don't answer NTP; the fallback name is
 * looked up through the default forwarders on a static address, never the node itself. */
#define DNS2_TZ           "UTC0" /* POSIX TZ string */
#define DNS2_NTP_FALLBACK "pool.ntp.org"

/* ---- memory ---- What each service may take (the cache, the lists, the zones, the
 * buffers) comes from the board definition's "memory", else the chip image's defaults
 * (memplan.c), not from here. */

/* ---- hosted zones ---- on unless a node config turns them off ("hosted": {"enabled"}). The
 * most memory they may take is memory.hosted_zones_kb (memplan.h). */
#define DNS2_HOSTED          1

/* ---- storage ---- */
#define DNS2_SD_MOUNT  "/sd"
#define DNS2_ZONE_DIR  "/sd/dns2/zones"
#define DNS2_HOSTED_DIR "/sd/dns2/hosted" /* hosted zones slots (hosted.c) */
#define DNS2_BLOCK_DIR "/sd/dns2/block" /* blocklist and overrides slots (blocking.c) */

/* ---- blocking ---- on unless a node config turns it off ("blocking": {"enabled"}); the answer
 * for a blocked name: 0.0.0.0 / :: / NODATA, or NXDOMAIN */
#define DNS2_BLOCKING       1
#define DNS2_BLOCK_NXDOMAIN 0
#define DNS2_BLOCK_TTL      10 /* short: an override or a pause takes effect at once */

/* ---- query log ---- on unless a node config turns it off ("querylog": {"enabled"}); its ring
 * is memory.querylog_kb (memplan.h), none on a board without PSRAM */
#define DNS2_QUERYLOG 1

#define DNS2_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
