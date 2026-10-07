#include "dns_wire.h"

#include <stdio.h>
#include <string.h>

#define OPT_RR_LEN 11 /* root name + type + class + ttl + rdlen, empty rdata */

static inline uint8_t lc(uint8_t c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

int dns_name_read(const uint8_t *msg, size_t len, size_t *off, uint8_t out[DNS_MAX_NAME])
{
    size_t pos = *off;
    int n = 0;
    int hops = 0;
    bool jumped = false;

    for (;;) {
        if (pos >= len)
            return -1;
        uint8_t l = msg[pos];
        if ((l & 0xC0) == 0xC0) {
            if (pos + 1 >= len || ++hops > 32)
                return -1;
            size_t ptr = (size_t)(l & 0x3F) << 8 | msg[pos + 1];
            if (!jumped)
                *off = pos + 2;
            jumped = true;
            if (ptr >= pos) /* pointers must go backwards: rules out loops */
                return -1;
            pos = ptr;
            continue;
        }
        if (l & 0xC0)
            return -1; /* 0x40/0x80 label types are obsolete */
        if (n + l + 1 > DNS_MAX_NAME || pos + 1 + l > len)
            return -1;
        memcpy(out + n, msg + pos, (size_t)l + 1);
        n += l + 1;
        pos += (size_t)l + 1;
        if (l == 0)
            break;
    }
    if (!jumped)
        *off = pos;
    return n;
}

int dns_name_skip(const uint8_t *msg, size_t len, size_t *off)
{
    uint8_t tmp[DNS_MAX_NAME];
    return dns_name_read(msg, len, off, tmp);
}

void dns_name_lower(uint8_t *name, int len)
{
    int pos = 0;
    while (pos < len && name[pos]) {
        int l = name[pos];
        for (int i = 1; i <= l && pos + i < len; i++)
            name[pos + i] = lc(name[pos + i]);
        pos += l + 1;
    }
}

bool dns_name_eq(const uint8_t *a, int alen, const uint8_t *b, int blen)
{
    if (alen != blen)
        return false;
    for (int i = 0; i < alen; i++)
        if (lc(a[i]) != lc(b[i]))
            return false;
    return true;
}

bool dns_name_under(const uint8_t *name, int len, const uint8_t *parent, int plen)
{
    int pos = 0;
    while (len - pos >= plen) {
        if (len - pos == plen)
            return dns_name_eq(name + pos, plen, parent, plen);
        if (name[pos] == 0)
            return false;
        pos += name[pos] + 1;
    }
    return false;
}

int dns_name_parent(const uint8_t *name, int len)
{
    if (len <= 1 || name[0] == 0)
        return -1;
    return name[0] + 1;
}

int dns_name_from_str(const char *s, uint8_t out[DNS_MAX_NAME])
{
    int n = 0;
    while (*s == '.')
        s++;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t l = dot ? (size_t)(dot - s) : strlen(s);
        if (l == 0 || l > 63 || n + (int)l + 2 > DNS_MAX_NAME)
            return -1;
        out[n++] = (uint8_t)l;
        for (size_t i = 0; i < l; i++)
            out[n++] = lc((uint8_t)s[i]);
        s += l;
        if (*s == '.')
            s++;
    }
    out[n++] = 0;
    return n;
}

void dns_name_to_str(const uint8_t *name, char *out, size_t outlen)
{
    size_t o = 0;
    int pos = 0;
    if (outlen == 0)
        return;
    if (name[0] == 0) {
        snprintf(out, outlen, ".");
        return;
    }
    while (name[pos] && o + 1 < outlen) {
        int l = name[pos];
        for (int i = 1; i <= l && o + 1 < outlen; i++) {
            uint8_t c = name[pos + i];
            out[o++] = (c > 32 && c < 127 && c != '"' && c != '\\') ? (char)c : '?';
        }
        pos += l + 1;
        if (name[pos] && o + 1 < outlen)
            out[o++] = '.';
    }
    out[o] = 0;
}

bool dns_hdr_parse(const uint8_t *m, size_t len, dns_hdr_t *h)
{
    if (len < DNS_HDR_LEN)
        return false;
    h->id = rd16(m);
    h->flags = rd16(m + 2);
    h->qd = rd16(m + 4);
    h->an = rd16(m + 6);
    h->ns = rd16(m + 8);
    h->ar = rd16(m + 10);
    return true;
}

bool dns_rr_parse(const uint8_t *msg, size_t len, size_t *off, dns_rr_view_t *rr)
{
    size_t pos = *off;
    rr->name_len = dns_name_read(msg, len, &pos, rr->name);
    if (rr->name_len < 0 || pos + 10 > len)
        return false;
    rr->type = rd16(msg + pos);
    rr->cls = rd16(msg + pos + 2);
    rr->ttl_off = pos + 4;
    rr->ttl = rd32(msg + pos + 4);
    rr->rdlen = rd16(msg + pos + 8);
    rr->rdata_off = pos + 10;
    if (rr->rdata_off + rr->rdlen > len)
        return false;
    *off = rr->rdata_off + rr->rdlen;
    return true;
}

/* Decompress one name from rdata into out; advances *in and *o. */
static bool expand_name(const uint8_t *msg, size_t len, size_t *in, size_t end,
                        uint8_t *out, size_t cap, size_t *o)
{
    uint8_t name[DNS_MAX_NAME];
    size_t p = *in;
    int n = dns_name_read(msg, len, &p, name);
    if (n < 0 || p > end || *o + (size_t)n > cap)
        return false;
    memcpy(out + *o, name, (size_t)n);
    *o += (size_t)n;
    *in = p;
    return true;
}

static bool copy_raw(const uint8_t *msg, size_t *in, size_t end, size_t n,
                     uint8_t *out, size_t cap, size_t *o)
{
    if (*in + n > end || *o + n > cap)
        return false;
    memcpy(out + *o, msg + *in, n);
    *in += n;
    *o += n;
    return true;
}

int dns_rdata_expand(const uint8_t *msg, size_t len, const dns_rr_view_t *rr,
                     uint8_t *out, size_t cap)
{
    size_t in = rr->rdata_off;
    size_t end = rr->rdata_off + rr->rdlen;
    size_t o = 0;
    bool ok = true;

    switch (rr->type) {
    case DNS_T_NS:
    case DNS_T_CNAME:
    case DNS_T_PTR:
    case DNS_T_DNAME:
        ok = expand_name(msg, len, &in, end, out, cap, &o);
        break;
    case DNS_T_MX:
        ok = copy_raw(msg, &in, end, 2, out, cap, &o) &&
             expand_name(msg, len, &in, end, out, cap, &o);
        break;
    case DNS_T_SRV:
        ok = copy_raw(msg, &in, end, 6, out, cap, &o) &&
             expand_name(msg, len, &in, end, out, cap, &o);
        break;
    case DNS_T_SOA:
        ok = expand_name(msg, len, &in, end, out, cap, &o) &&
             expand_name(msg, len, &in, end, out, cap, &o) &&
             copy_raw(msg, &in, end, 20, out, cap, &o);
        break;
    default:
        ok = copy_raw(msg, &in, end, rr->rdlen, out, cap, &o);
        break;
    }
    if (!ok || in != end)
        return -1;
    return (int)o;
}

int dns_query_parse(const uint8_t *m, size_t len, dns_query_t *q)
{
    dns_hdr_t h;
    memset(q, 0, sizeof(*q));
    if (!dns_hdr_parse(m, len, &h))
        return DNS_R_FORMERR;
    q->id = h.id;
    q->flags = h.flags;
    if (h.qd != 1)
        return DNS_R_FORMERR;

    size_t pos = DNS_HDR_LEN;
    q->qname_len = dns_name_read(m, len, &pos, q->qname);
    if (q->qname_len < 0 || pos + 4 > len)
        return DNS_R_FORMERR;
    q->qtype = rd16(m + pos);
    q->qclass = rd16(m + pos + 2);
    pos += 4;
    q->q_end = pos;

    /* Skip answer/authority, look for OPT in additional. */
    for (int i = 0; i < h.an + h.ns + h.ar; i++) {
        dns_rr_view_t rr;
        if (!dns_rr_parse(m, len, &pos, &rr))
            return DNS_R_FORMERR;
        if (i >= h.an + h.ns && rr.type == DNS_T_OPT) {
            if (q->has_edns || rr.name_len != 1)
                return DNS_R_FORMERR;
            q->has_edns = true;
            q->edns_size = rr.cls < 512 ? 512 : rr.cls;
            q->edns_version = (uint8_t)(rr.ttl >> 16);
            q->do_bit = (rr.ttl & 0x8000) != 0;
        }
    }
    return DNS_R_NOERROR;
}

/* ---- builder ---- */

/* Remember every suffix of a name written at off, for label starts below literal_len
 * (bytes past that were emitted as a pointer and do not exist at off + pos). */
static void ctab_add(dns_builder_t *b, size_t off, const uint8_t *name, int len, int literal_len)
{
    int pos = 0;
    if (literal_len <= 0 || name[0] == 0 || b->pool_len + (size_t)len > sizeof(b->pool))
        return;
    uint8_t *copy = b->pool + b->pool_len;
    memcpy(copy, name, (size_t)len);
    b->pool_len += (size_t)len;
    name = copy;
    while (pos < literal_len && name[pos] && b->nctab < DNSB_CTAB) {
        if (off + (size_t)pos > 0x3FFF)
            return;
        b->ctab[b->nctab].off = (uint16_t)(off + (size_t)pos);
        b->ctab[b->nctab].name = name + pos;
        b->ctab[b->nctab].len = (uint8_t)(len - pos);
        b->nctab++;
        pos += name[pos] + 1;
    }
}

/* Size the name will take once compressed; *ptr_at receives the label offset where a
 * pointer starts (or -1) and *ptr the target offset. */
static int name_plan(const dns_builder_t *b, const uint8_t *name, int len, int *ptr_at, uint16_t *ptr)
{
    int pos = 0;
    while (name[pos]) {
        for (int i = 0; i < b->nctab; i++) {
            if (dns_name_eq(name + pos, len - pos, b->ctab[i].name, b->ctab[i].len)) {
                *ptr_at = pos;
                *ptr = b->ctab[i].off;
                return pos + 2;
            }
        }
        pos += name[pos] + 1;
    }
    *ptr_at = -1;
    return len;
}

static void name_put(dns_builder_t *b, const uint8_t *name, int len)
{
    int ptr_at;
    uint16_t ptr;
    size_t start = b->len;
    name_plan(b, name, len, &ptr_at, &ptr);
    if (ptr_at < 0) {
        memcpy(b->buf + b->len, name, (size_t)len);
        b->len += (size_t)len;
    } else {
        memcpy(b->buf + b->len, name, (size_t)ptr_at);
        b->len += (size_t)ptr_at;
        wr16(b->buf + b->len, 0xC000 | ptr);
        b->len += 2;
    }
    ctab_add(b, start, name, len, ptr_at < 0 ? len : ptr_at);
}

void dnsb_init(dns_builder_t *b, uint8_t *buf, size_t cap, size_t limit,
               const dns_query_t *q, uint16_t flags)
{
    memset(b, 0, sizeof(*b));
    b->buf = buf;
    b->cap = cap;
    b->limit = limit < cap ? limit : cap;
    wr16(buf, q->id);
    wr16(buf + 2, flags);
    wr16(buf + 4, 1);
    memset(buf + 6, 0, 6);
    b->len = DNS_HDR_LEN;
    memcpy(buf + b->len, q->qname, (size_t)q->qname_len);
    ctab_add(b, b->len, q->qname, q->qname_len, q->qname_len);
    b->len += (size_t)q->qname_len;
    wr16(buf + b->len, q->qtype);
    wr16(buf + b->len + 2, q->qclass);
    b->len += 4;
    b->q_end = b->len;
}

bool dnsb_rr(dns_builder_t *b, int section, const uint8_t *owner, int owner_len,
             uint16_t type, uint16_t cls, uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
    if (b->truncated || section < b->section)
        return false;
    int ptr_at;
    uint16_t ptr;
    size_t need = (size_t)name_plan(b, owner, owner_len, &ptr_at, &ptr) + 10 + rdlen;
    size_t reserve = b->opt_size ? OPT_RR_LEN : 0;
    if (b->len + need + reserve > b->limit) {
        b->truncated = true;
        return false;
    }
    b->section = section;
    name_put(b, owner, owner_len);
    wr16(b->buf + b->len, type);
    wr16(b->buf + b->len + 2, cls);
    wr32(b->buf + b->len + 4, ttl);
    wr16(b->buf + b->len + 8, rdlen);
    b->len += 10;
    memcpy(b->buf + b->len, rdata, rdlen);
    b->len += rdlen;
    if (section == DNSB_ANSWER)
        b->an++;
    else if (section == DNSB_AUTHORITY)
        b->ns++;
    else
        b->ar++;
    return true;
}

void dnsb_opt(dns_builder_t *b, uint16_t udp_size, bool do_bit)
{
    b->opt_size = udp_size;
    b->opt_do = do_bit;
}

void dnsb_set_rcode(dns_builder_t *b, int rcode)
{
    uint16_t f = rd16(b->buf + 2);
    wr16(b->buf + 2, (uint16_t)((f & ~0xF) | (rcode & 0xF)));
}

void dnsb_set_flags(dns_builder_t *b, uint16_t set, uint16_t clear)
{
    uint16_t f = rd16(b->buf + 2);
    wr16(b->buf + 2, (uint16_t)((f | set) & ~clear));
}

size_t dnsb_finish(dns_builder_t *b)
{
    if (b->truncated) {
        /* Nothing partial: the client must retry over TCP. */
        b->len = b->q_end;
        b->an = b->ns = b->ar = 0;
        dnsb_set_flags(b, DNS_F_TC, 0);
    }
    if (b->opt_size && b->len + OPT_RR_LEN <= b->cap) {
        uint8_t *p = b->buf + b->len;
        p[0] = 0;
        wr16(p + 1, DNS_T_OPT);
        wr16(p + 3, b->opt_size);
        wr32(p + 5, b->opt_do ? 0x8000 : 0);
        wr16(p + 9, 0);
        b->len += OPT_RR_LEN;
        b->ar++;
    }
    wr16(b->buf + 6, b->an);
    wr16(b->buf + 8, b->ns);
    wr16(b->buf + 10, b->ar);
    return b->len;
}

size_t dns_make_error(const dns_query_t *q, uint8_t *out, size_t cap, int rcode, uint16_t extra_flags)
{
    dns_builder_t b;
    if (q->qname_len <= 0) {
        /* Question unusable: header only. */
        if (cap < DNS_HDR_LEN)
            return 0;
        wr16(out, q->id);
        wr16(out + 2, (uint16_t)(DNS_F_QR | (q->flags & (DNS_F_RD | 0x7800)) | extra_flags | (rcode & 0xF)));
        memset(out + 4, 0, 8);
        return DNS_HDR_LEN;
    }
    dnsb_init(&b, out, cap, cap, q,
              (uint16_t)(DNS_F_QR | (q->flags & (DNS_F_RD | 0x7800)) | extra_flags | (rcode & 0xF)));
    if (q->has_edns)
        dnsb_opt(&b, DNS_EDNS_SIZE, q->do_bit);
    return dnsb_finish(&b);
}

static bool dnssec_type(uint16_t t) { return t == DNS_T_RRSIG || t == DNS_T_NSEC || t == DNS_T_NSEC3; }

int dnsb_relay(dns_builder_t *b, const uint8_t *m, size_t len, uint32_t age, bool answers_only, bool dnssec)
{
    dns_hdr_t h;
    size_t pos = DNS_HDR_LEN;
    uint8_t rdata[1024];
    uint16_t qtype = 0;

    if (!dns_hdr_parse(m, len, &h))
        return -1;
    for (int i = 0; i < h.qd; i++) {
        if (dns_name_skip(m, len, &pos) < 0 || pos + 4 > len)
            return -1;
        qtype = rd16(m + pos);
        pos += 4;
    }
    for (int i = 0; i < h.an + h.ns + h.ar; i++) {
        dns_rr_view_t rr;
        if (!dns_rr_parse(m, len, &pos, &rr))
            return -1;
        if (rr.type == DNS_T_OPT || (answers_only && i >= h.an))
            continue;
        if (!dnssec && dnssec_type(rr.type) && rr.type != qtype && qtype != DNS_T_ANY)
            continue;
        int section = i < h.an ? DNSB_ANSWER : i < h.an + h.ns ? DNSB_AUTHORITY : DNSB_ADDITIONAL;
        int rdlen = dns_rdata_expand(m, len, &rr, rdata, sizeof(rdata));
        if (rdlen < 0)
            return -1;
        uint32_t ttl = rr.ttl > age ? rr.ttl - age : 0;
        if (!dnsb_rr(b, section, rr.name, rr.name_len, rr.type, rr.cls, ttl, rdata, (uint16_t)rdlen))
            break; /* truncated; dnsb_finish sets TC */
    }
    return DNS_RCODE(h.flags);
}

uint32_t dns_resp_ttl(const uint8_t *m, size_t len)
{
    dns_hdr_t h;
    size_t pos = DNS_HDR_LEN;
    uint32_t ttl = UINT32_MAX;
    bool soa = false;

    if (!dns_hdr_parse(m, len, &h) || (h.flags & DNS_F_TC))
        return 0;
    int rcode = DNS_RCODE(h.flags);
    if (rcode != DNS_R_NOERROR && rcode != DNS_R_NXDOMAIN)
        return 0;
    for (int i = 0; i < h.qd; i++) {
        if (dns_name_skip(m, len, &pos) < 0 || pos + 4 > len)
            return 0;
        pos += 4;
    }
    for (int i = 0; i < h.an + h.ns; i++) {
        dns_rr_view_t rr;
        if (!dns_rr_parse(m, len, &pos, &rr))
            return 0;
        uint32_t t = rr.ttl;
        if (i >= h.an && rr.type == DNS_T_SOA) {
            soa = true;
            if (rr.rdlen >= 4) {
                /* SOA MINIMUM is the last 4 bytes of rdata, even when names are compressed */
                uint32_t min = rd32(m + rr.rdata_off + rr.rdlen - 4);
                if (min < t)
                    t = min;
            }
        }
        if (t < ttl)
            ttl = t;
    }
    if (h.an == 0 && !soa)
        return 0; /* negative answer without SOA: RFC 2308 says do not cache */
    if (ttl == UINT32_MAX)
        return 0;
    return ttl > 86400 ? 86400 : ttl;
}
