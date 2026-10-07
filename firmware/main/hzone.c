#include "hzone.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(zone_t) <= HZ_ZONE_COST, "HZ_ZONE_COST must cover a zone_t");
_Static_assert(sizeof(zrr_t) <= HZ_RR_COST, "HZ_RR_COST must cover a zrr_t");

#define TTL_MAX 0x7fffffffu

typedef struct {
    const uint8_t *p;
    size_t len, pos;
    char *err;
    size_t errlen;
} rd_t;

static const char *fail(rd_t *r, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (r->errlen)
        vsnprintf(r->err, r->errlen, fmt, ap);
    va_end(ap);
    return r->errlen ? r->err : "bad zones bundle";
}

/* Length of the valid uncompressed wire name at p (at most avail bytes), or -1. */
static int wire_name(const uint8_t *p, size_t avail)
{
    size_t pos = 0;
    for (;;) {
        if (pos >= avail)
            return -1;
        uint8_t l = p[pos];
        if (l > 63)
            return -1;
        pos += (size_t)l + 1;
        if (pos > DNS_MAX_NAME)
            return -1;
        if (!l)
            return (int)pos;
    }
}

/* A "*" label anywhere but first. */
static bool inner_star(const uint8_t *n)
{
    for (int pos = n[0] + 1; n[pos]; pos += n[pos] + 1)
        if (n[pos] == 1 && n[pos + 1] == '*')
            return true;
    return false;
}

static bool exact_name(const uint8_t *p, size_t len) { return len && wire_name(p, len) == (int)len; }

static const char *type_name(uint16_t t)
{
    switch (t) {
    case DNS_T_A: return "A";
    case DNS_T_NS: return "NS";
    case DNS_T_CNAME: return "CNAME";
    case DNS_T_SOA: return "SOA";
    case DNS_T_PTR: return "PTR";
    case DNS_T_MX: return "MX";
    case DNS_T_TXT: return "TXT";
    case DNS_T_AAAA: return "AAAA";
    case DNS_T_SRV: return "SRV";
    case DNS_T_CAA: return "CAA";
    default: return NULL;
    }
}

static bool rdata_ok(uint16_t type, const uint8_t *rd, size_t len)
{
    switch (type) {
    case DNS_T_A: return len == 4;
    case DNS_T_AAAA: return len == 16;
    case DNS_T_NS:
    case DNS_T_CNAME:
    case DNS_T_PTR: return exact_name(rd, len);
    case DNS_T_MX: return len > 2 && exact_name(rd + 2, len - 2);
    case DNS_T_SRV: return len > 6 && exact_name(rd + 6, len - 6);
    case DNS_T_TXT: {
        if (!len)
            return false;
        size_t pos = 0;
        while (pos < len)
            pos += (size_t)rd[pos] + 1;
        return pos == len;
    }
    case DNS_T_CAA: {
        if (len < 3 || rd[1] < 1 || rd[1] > 15 || (size_t)rd[1] + 2 > len)
            return false;
        for (int i = 0; i < rd[1]; i++) {
            uint8_t c = rd[2 + i];
            if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9'))
                return false;
        }
        return true;
    }
    case DNS_T_SOA: {
        int a = wire_name(rd, len);
        if (a < 0)
            return false;
        int b = wire_name(rd + a, len - (size_t)a);
        return b >= 0 && (size_t)a + (size_t)b + 20 == len;
    }
    default: return false;
    }
}

static bool get8(rd_t *r, uint8_t *v)
{
    if (r->pos + 1 > r->len)
        return false;
    *v = r->p[r->pos++];
    return true;
}

static bool get16(rd_t *r, uint16_t *v)
{
    if (r->pos + 2 > r->len)
        return false;
    *v = rd16(r->p + r->pos);
    r->pos += 2;
    return true;
}

static bool get32(rd_t *r, uint32_t *v)
{
    if (r->pos + 4 > r->len)
        return false;
    *v = rd32(r->p + r->pos);
    r->pos += 4;
    return true;
}

/* A length-prefixed wire name at r->pos: *name points at it. */
static bool get_name(rd_t *r, const uint8_t **name, int *nlen)
{
    uint8_t l;
    if (!get8(r, &l) || r->pos + l > r->len || wire_name(r->p + r->pos, l) != l)
        return false;
    *name = r->p + r->pos;
    *nlen = l;
    r->pos += l;
    return true;
}

typedef struct {
    const uint8_t *owner;
    int owner_len;
    uint16_t type;
    uint32_t ttl;
    uint16_t rdlen;
    const uint8_t *rdata;
} rec_t;

static bool get_rec(rd_t *r, rec_t *x)
{
    if (!get_name(r, &x->owner, &x->owner_len) || !get16(r, &x->type) || !get32(r, &x->ttl) || !get16(r, &x->rdlen) ||
        r->pos + x->rdlen > r->len)
        return false;
    x->rdata = r->p + r->pos;
    r->pos += x->rdlen;
    return true;
}

/* Checks after the records are in and sorted: CNAMEs alone, and only NS and glue at and below
 * a delegation. */
static const char *check_zone(rd_t *r, const zone_t *z, const char *zname)
{
    char on[256];
    for (size_t a = 0; a < z->n;) {
        const zrr_t *first = &z->rrs[a];
        const uint8_t *owner = zrr_owner(z, first);
        int olen = first->owner_len;
        size_t b = a, cnames = 0;
        while (b < z->n && z->rrs[b].owner_len == olen && !memcmp(zrr_owner(z, &z->rrs[b]), owner, (size_t)olen)) {
            cnames += z->rrs[b].type == DNS_T_CNAME;
            b++;
        }
        dns_name_to_str(owner, on, sizeof(on));
        if (cnames > 1)
            return fail(r, "zone %s: %s: more than one CNAME", zname, on);
        if (cnames && b - a > 1)
            return fail(r, "zone %s: %s: a CNAME and other records", zname, on);
        /* At or below a delegation: the nearest NS owner between name and the apex. */
        int cut = -1;
        for (int pos = 0; olen - pos > z->apex_len; pos += owner[pos] + 1) {
            size_t f, c = zone_find(z, owner + pos, olen - pos, &f);
            for (size_t i = f; i < f + c; i++)
                if (z->rrs[i].type == DNS_T_NS) {
                    cut = pos;
                    break;
                }
            if (cut >= 0)
                break;
        }
        for (size_t i = a; cut >= 0 && i < b; i++) {
            uint16_t t = z->rrs[i].type;
            if (t != DNS_T_A && t != DNS_T_AAAA && !(cut == 0 && t == DNS_T_NS))
                return fail(r, "zone %s: %s: %s %s a delegation (only NS and A/AAAA glue)", zname, on, type_name(t),
                            cut ? "below" : "at");
        }
        a = b;
    }
    return NULL;
}

const char *hz_parse(const uint8_t *p, size_t len, size_t limit, hz_set_t **out, char *err, size_t errlen)
{
    rd_t r = { .p = p, .len = len, .err = err, .errlen = errlen };
    char zname[256], on[256];
    uint16_t nz;
    *out = NULL;
    if (len < 10 || memcmp(p, HZ_MAGIC, 8) != 0)
        return fail(&r, "not a zones bundle");
    r.pos = 8;
    get16(&r, &nz);
    if (nz > HZ_MAX_ZONES)
        return fail(&r, "%u zones: at most %d", nz, HZ_MAX_ZONES);

    /* Pass 1: structure, names, types, rdata, and the memory it all takes. */
    size_t mem = 0;
    struct {
        uint32_t n;
        size_t bytes; /* owners and rdata */
    } zi[HZ_MAX_ZONES];
    for (int i = 0; i < nz; i++) {
        const uint8_t *apex;
        int alen;
        if (!get_name(&r, &apex, &alen) || alen < 2)
            return fail(&r, "zone %d: not a zone name", i + 1);
        dns_name_to_str(apex, zname, sizeof(zname));
        if (apex[0] == 1 && apex[1] == '*') /* not a wildcard either */
            return fail(&r, "zone %s: not a zone name", zname);
        if (inner_star(apex))
            return fail(&r, "zone %s: not a zone name", zname);
        if (!get32(&r, &zi[i].n))
            return fail(&r, "zone %s: cut short", zname);
        zi[i].bytes = 0;
        for (uint32_t k = 0; k < zi[i].n; k++) {
            rec_t x;
            if (!get_rec(&r, &x))
                return fail(&r, "zone %s: record %lu malformed or cut short", zname, (unsigned long)k + 1);
            dns_name_to_str(x.owner, on, sizeof(on));
            if (!dns_name_under(x.owner, x.owner_len, apex, alen))
                return fail(&r, "zone %s: %s is outside the zone", zname, on);
            if (inner_star(x.owner))
                return fail(&r, "zone %s: %s: \"*\" only as the first label", zname, on);
            const char *tn = type_name(x.type);
            if (!tn)
                return fail(&r, "zone %s: %s: type %u not supported (A, AAAA, CNAME, MX, TXT, SRV, NS, PTR, CAA, SOA; "
                                "no DNSSEC)", zname, on, x.type);
            if (x.ttl > TTL_MAX)
                return fail(&r, "zone %s: %s %s: TTL above 2147483647", zname, on, tn);
            if (!rdata_ok(x.type, x.rdata, x.rdlen))
                return fail(&r, "zone %s: %s %s: malformed rdata", zname, on, tn);
            if (x.type == DNS_T_SOA && !dns_name_eq(x.owner, x.owner_len, apex, alen))
                return fail(&r, "zone %s: %s: SOA only at the apex", zname, on);
            /* A wildcard can't be delegated (RFC 4592 4.2): it would be a referral for any
             * name under it, which no resolver follows. */
            if (x.type == DNS_T_NS && x.owner[0] == 1 && x.owner[1] == '*')
                return fail(&r, "zone %s: %s: NS at a wildcard name (a wildcard can't be delegated)", zname, on);
            zi[i].bytes += (size_t)x.owner_len + x.rdlen;
        }
        mem += HZ_ZONE_COST + (size_t)zi[i].n * HZ_RR_COST + zi[i].bytes;
    }
    if (r.pos != len)
        return fail(&r, "%u bytes after the last zone", (unsigned)(len - r.pos));
    if (mem > limit)
        return fail(&r, "the zones need %u KB; this board holds %u KB (memory.hosted_zones_kb)",
                    (unsigned)((mem + 1023) / 1024), (unsigned)(limit / 1024));

    /* Pass 2: build each zone in exactly the memory counted. */
    hz_set_t *s = calloc(1, sizeof(*s));
    if (!s)
        return fail(&r, "out of memory");
    s->mem = mem;
    r.pos = 10;
    const char *why = NULL;
    for (int i = 0; i < nz && !why; i++) {
        const uint8_t *apex;
        int alen;
        get_name(&r, &apex, &alen);
        dns_name_to_str(apex, zname, sizeof(zname));
        uint32_t n = zi[i].n;
        r.pos += 4;
        /* Within exactly what pass 1 counted for it. */
        zone_t *z = zone_new(apex, alen, HZ_ZONE_COST + (size_t)n * HZ_RR_COST + zi[i].bytes);
        if (!z || !zone_reserve(z, n, zi[i].bytes)) {
            zone_free(z);
            why = fail(&r, "out of memory");
            break;
        }
        s->z[s->n++] = z;
        for (int j = 0; j < s->n - 1; j++)
            if (dns_name_eq(s->z[j]->apex, s->z[j]->apex_len, z->apex, z->apex_len)) {
                why = fail(&r, "zone %s twice", zname);
                break;
            }
        for (uint32_t k = 0; k < n && !why; k++) {
            rec_t x;
            get_rec(&r, &x);
            if (!zone_add(z, x.owner, x.owner_len, x.type, x.ttl, x.rdata, x.rdlen))
                why = fail(&r, "out of memory");
        }
        if (why)
            break;
        if (!zone_finalize(z))
            why = fail(&r, "zone %s: needs exactly one SOA, at the apex", zname);
        else
            why = check_zone(&r, z, zname);
    }
    if (why) {
        hz_free(s);
        return why;
    }
    *out = s;
    return NULL;
}

void hz_free(hz_set_t *s)
{
    if (!s)
        return;
    for (int i = 0; i < s->n; i++)
        zone_free(s->z[i]);
    free(s);
}

void hz_drop(hz_set_t *s, int i)
{
    if (i < 0 || i >= s->n)
        return;
    zone_free(s->z[i]);
    memmove(&s->z[i], &s->z[i + 1], sizeof(s->z[0]) * (size_t)(s->n - i - 1));
    s->n--;
}

int hz_clash(const hz_set_t *s, const cfg_t *c)
{
    uint8_t n[DNS_MAX_NAME];
    for (int i = 0; s && i < s->n; i++) {
        const zone_t *z = s->z[i];
        for (int j = 0; j < c->nzones + c->nfzones; j++) {
            const char *name = j < c->nzones ? c->zones[j] : c->fzones[j - c->nzones].zone;
            int l = dns_name_from_str(name, n);
            if (l > 0 && dns_name_eq(n, l, z->apex, z->apex_len))
                return i;
        }
    }
    return -1;
}

zone_t *hz_find(const hz_set_t *s, const uint8_t *name, int len)
{
    zone_t *best = NULL;
    for (int i = 0; s && i < s->n; i++) {
        zone_t *z = s->z[i];
        if ((!best || z->apex_len > best->apex_len) && dns_name_under(name, len, z->apex, z->apex_len))
            best = z;
    }
    return best;
}
