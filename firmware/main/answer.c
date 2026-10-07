#include "answer.h"

#include <string.h>

#define MAX_CHAIN 8

static void add_soa(zone_t *z, dns_builder_t *b)
{
    const zrr_t *soa = &z->rrs[z->soa_idx];
    uint32_t ttl = z->soa_ttl < z->minimum ? z->soa_ttl : z->minimum;
    dnsb_rr(b, DNSB_AUTHORITY, zrr_owner(z, soa), soa->owner_len, DNS_T_SOA, DNS_C_IN, ttl,
            zrr_rdata(z, soa), soa->rdlen);
}

static void add_rrs(zone_t *z, dns_builder_t *b, int section, const uint8_t *owner, int owner_len,
                    size_t first, size_t cnt, uint16_t type)
{
    for (size_t i = first; i < first + cnt; i++) {
        const zrr_t *r = &z->rrs[i];
        if (type == DNS_T_ANY || r->type == type)
            dnsb_rr(b, section, owner, owner_len, r->type, DNS_C_IN, r->ttl, zrr_rdata(z, r), r->rdlen);
    }
}

static bool has_type(zone_t *z, size_t first, size_t cnt, uint16_t type, size_t *idx)
{
    for (size_t i = first; i < first + cnt; i++) {
        if (z->rrs[i].type == type) {
            if (idx)
                *idx = i;
            return true;
        }
    }
    return false;
}

/* Highest zone cut strictly between the apex and name (inclusive of name). Returns its
 * offset inside name, or -1. */
static int find_cut(zone_t *z, const uint8_t *name, int len, size_t *first, size_t *cnt)
{
    int offs[128], n = 0, pos = 0;
    while (name[pos] && n < 128) {
        if (len - pos == z->apex_len)
            break;
        offs[n++] = pos;
        pos += name[pos] + 1;
    }
    for (int i = n - 1; i >= 0; i--) {
        size_t f, c = zone_find(z, name + offs[i], len - offs[i], &f);
        if (c && has_type(z, f, c, DNS_T_NS, NULL)) {
            *first = f;
            *cnt = c;
            return offs[i];
        }
    }
    return -1;
}

static void add_referral(zone_t *z, dns_builder_t *b, size_t first, size_t cnt)
{
    for (size_t i = first; i < first + cnt; i++) {
        const zrr_t *r = &z->rrs[i];
        if (r->type == DNS_T_NS)
            dnsb_rr(b, DNSB_AUTHORITY, zrr_owner(z, r), r->owner_len, DNS_T_NS, DNS_C_IN, r->ttl,
                    zrr_rdata(z, r), r->rdlen);
    }
    /* Glue: addresses for name servers inside this zone. */
    for (size_t i = first; i < first + cnt; i++) {
        const zrr_t *r = &z->rrs[i];
        if (r->type != DNS_T_NS)
            continue;
        const uint8_t *ns = zrr_rdata(z, r);
        size_t gf, gc = zone_find(z, ns, r->rdlen, &gf);
        for (size_t j = gf; j < gf + gc; j++) {
            const zrr_t *g = &z->rrs[j];
            if (g->type == DNS_T_A || g->type == DNS_T_AAAA)
                dnsb_rr(b, DNSB_ADDITIONAL, zrr_owner(z, g), g->owner_len, g->type, DNS_C_IN, g->ttl,
                        zrr_rdata(z, g), g->rdlen);
        }
    }
}

/* Closest encloser's wildcard: "*.<ancestor>" RRs, if any. */
static size_t find_wildcard(zone_t *z, const uint8_t *name, int len, size_t *first)
{
    int pos = dns_name_parent(name, len);
    while (pos >= 0) {
        const uint8_t *anc = name + pos;
        int alen = len - pos;
        if (alen < z->apex_len)
            break;
        if (zone_name_exists(z, anc, alen)) {
            uint8_t wc[DNS_MAX_NAME];
            if (alen + 2 > DNS_MAX_NAME)
                return 0;
            wc[0] = 1;
            wc[1] = '*';
            memcpy(wc + 2, anc, (size_t)alen);
            return zone_find(z, wc, alen + 2, first);
        }
        int p = dns_name_parent(anc, alen);
        if (p < 0)
            break;
        pos += p;
    }
    return 0;
}

void answer_auth(zone_finder_fn find, void *ctx, zone_t *z, const dns_query_t *q,
                 dns_builder_t *b, answer_result_t *res)
{
    const uint8_t *name = q->qname;
    int len = q->qname_len;

    memset(res, 0, sizeof(*res));
    res->rcode = DNS_R_NOERROR;
    res->authoritative = true;

    for (int chain = 0;; chain++) {
        size_t first, cnt;

        int cut = find_cut(z, name, len, &first, &cnt);
        if (cut >= 0) {
            /* Delegated below us: not authoritative for this name. */
            if (chain == 0)
                res->authoritative = false;
            add_referral(z, b, first, cnt);
            return;
        }

        cnt = zone_find(z, name, len, &first);
        const uint8_t *owner = name; /* synthesized owner for wildcards */
        if (cnt == 0) {
            if (zone_name_exists(z, name, len)) {
                add_soa(z, b); /* empty non-terminal: NODATA */
                return;
            }
            cnt = find_wildcard(z, name, len, &first);
            if (cnt == 0) {
                res->rcode = DNS_R_NXDOMAIN;
                add_soa(z, b);
                return;
            }
        }

        if (q->qtype == DNS_T_ANY || has_type(z, first, cnt, q->qtype, NULL)) {
            add_rrs(z, b, DNSB_ANSWER, owner, len, first, cnt, q->qtype);
            return;
        }

        size_t ci;
        if (!has_type(z, first, cnt, DNS_T_CNAME, &ci)) {
            add_soa(z, b); /* NODATA */
            return;
        }
        const zrr_t *c = &z->rrs[ci];
        dnsb_rr(b, DNSB_ANSWER, owner, len, DNS_T_CNAME, DNS_C_IN, c->ttl, zrr_rdata(z, c), c->rdlen);

        name = zrr_rdata(z, c);
        len = c->rdlen;
        if (chain + 1 >= MAX_CHAIN)
            return;
        zone_t *next = find(ctx, name, len);
        if (!next) {
            res->external = true;
            res->target = name;
            res->target_len = len;
            return;
        }
        z = next;
    }
}
