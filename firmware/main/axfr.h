/*
 * A secondary zone's exchanges with its primary: the SOA serial (UDP) and a full zone
 * transfer (AXFR, TCP), each within one deadline for the whole exchange, whatever the
 * primary sends meanwhile (a stray datagram, or a transfer trickled a byte at a time, never
 * restarts a wait). The zone task (xfr.h) drives them. Portable: run on the host in the
 * tests, against a fake primary on the loopback.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zone.h"

/* The SOA check and the whole transfer, connect to last record. Both well within the zone
 * task's check-in (SUP_TASK_MS, sup.h), which xfr.c asserts. */
#define AXFR_SOA_TIMEOUT_MS 2000
#define AXFR_DEADLINE_MS    120000
/* The transfer's connection, within its deadline. */
#define AXFR_CONNECT_MS     5000

/* The primary's serial for apex (an authoritative SOA), asked of primary:port (network
 * order address) over UDP; false without one within timeout_ms. */
bool axfr_soa_serial(uint32_t primary, uint16_t port, const uint8_t *apex, int apex_len, int timeout_ms,
                     uint32_t *serial);

typedef enum {
    AXFR_OK,
    AXFR_NET,       /* no connection, or it closed */
    AXFR_TIMEOUT,   /* the transfer's deadline passed */
    AXFR_REFUSED,   /* an rcode other than NOERROR */
    AXFR_MALFORMED, /* not a transfer of this zone, or no SOA at the apex at both ends */
    AXFR_TOO_BIG,   /* the zone would take more than its limit */
    AXFR_NOMEM,
} axfr_err_t;

const char *axfr_err_str(axfr_err_t e);

typedef struct {
    uint8_t *msg, *rdata; /* 65535 bytes each: a message, and a record's rdata decompressed */
    size_t   limit;       /* the most the new zone may hold at any moment (zone_new) */
    int      deadline_ms; /* the whole transfer */
    void   (*progress)(void *ctx); /* after each message, if set */
    void    *ctx;
} axfr_opts_t;

/* A full transfer of apex from primary:port, built within o->limit and o->deadline_ms; NULL
 * on failure, with why in *err. */
zone_t *axfr_pull(uint32_t primary, uint16_t port, const uint8_t *apex, int apex_len, const axfr_opts_t *o,
                  axfr_err_t *err);
