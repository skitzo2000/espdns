/*
 * Authoritative answers from local zones (RFC 1034 4.3.2): exact matches, CNAME
 * chains across local zones, wildcards, delegations, NODATA vs NXDOMAIN.
 * Portable C, no ESP-IDF dependencies.
 */
#pragma once

#include "dns_wire.h"
#include "zone.h"

/* Returns the local zone with the longest apex containing name, or NULL. */
typedef zone_t *(*zone_finder_fn)(void *ctx, const uint8_t *name, int len);

typedef struct {
    int     rcode;
    bool    authoritative;
    /* The CNAME chain left our zones: the caller may resolve target upstream
     * and append the answers. */
    bool    external;
    const uint8_t *target;
    int     target_len;
} answer_result_t;

/* z must contain q->qname. Adds RRs to b (answer/authority/additional, in order). */
void answer_auth(zone_finder_fn find, void *ctx, zone_t *z, const dns_query_t *q,
                 dns_builder_t *b, answer_result_t *res);
