/*
 * The set of zones this server knows: secondary zones (with their live data and
 * refresh state), hosted zones (hzone.h, swapped whole when a bundle arrives) and
 * conditional-forwarder zones. Routes query names to them: the zone with the longest apex
 * the name is at or below wins, whatever its source. No name is two kinds of zone at once:
 * the config refuses a secondary that is also a forward zone, and hosted zones that clash
 * with either are refused (hosted.c).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "dns_wire.h"
#include "hzone.h"
#include "zone.h"

typedef struct {
    const char *name;
    uint8_t     apex[DNS_MAX_NAME];
    int         apex_len;
    zone_t     *z;             /* swap only under reg_wrlock */
    bool        expired;       /* no successful check within SOA EXPIRE */

    /* refresh state, owned by the xfr task */
    int64_t     last_ok_ms;
    int64_t     next_check_ms;
    uint32_t    fails;
    uint32_t    transfers;
    volatile bool notify;      /* set by the server on NOTIFY */
} zslot_t;

typedef struct {
    const char *name;
    uint8_t     apex[DNS_MAX_NAME];
    int         apex_len;
    uint32_t    forwarder;     /* IPv4, network byte order */
} fzone_t;

typedef enum {
    ROUTE_AUTH,       /* answer from z: a secondary slot (data present, not expired) or a hosted zone */
    ROUTE_AUTH_FAIL,  /* ours, but no usable data: SERVFAIL */
    ROUTE_FWD_ZONE,   /* conditional forwarder */
    ROUTE_DEFAULT,    /* not ours: default forwarders */
} route_kind_t;

typedef struct {
    route_kind_t kind;
    int          idx;    /* the secondary slot or forward zone; -1 for a hosted zone */
    zone_t      *z;      /* ROUTE_AUTH: the zone to answer from */
    bool         hosted; /* a hosted zone (no slot, no refresh, no NOTIFY) */
} route_t;

void     reg_init(void);
int      reg_nslots(void);
zslot_t *reg_slot(int i);
int      reg_nfzones(void);
fzone_t *reg_fzone(int i);

void reg_rdlock(void);
void reg_wrlock(void);
void reg_unlock(void);

/* Caller holds at least the read lock. */
route_t reg_route(const uint8_t *name, int len);
/* zone_finder_fn for answer_auth; caller holds the read lock. */
zone_t *reg_find_auth(void *ctx, const uint8_t *name, int len);

/* Installs new data for slot i and returns the old zone (free it after unlocking). */
zone_t *reg_swap(int i, zone_t *nz);

/* The hosted zones (caller holds at least the read lock); NULL if none. */
const hz_set_t *reg_hosted(void);
/* Installs a new set of hosted zones (NULL: none) and returns the old one (free it after
 * unlocking: no query can still be reading it). */
hz_set_t *reg_hosted_swap(hz_set_t *s);
