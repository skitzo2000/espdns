#include "qlog.h"

#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(ql_entry_t) == 160, "a query log entry is 160 bytes (memplan.h, MP_QUERYLOG_ENTRY)");

static const char *const RESULT[QR_N] = { "cache",   "forwarded", "hosted",   "secondary", "blocked", "overridden",
                                          "refused", "servfail",  "error",    "notify",    "dropped" };
static const char *const RULE[QL_RULE_N] = { NULL, "list", "override", "cname", "allow" };
static const char *const CLIENT[QL_CLIENT_N] = { "full", "subnet", "hidden" };

const char *ql_result_name(int r) { return (unsigned)r < QR_N ? RESULT[r] : "unknown"; }
const char *ql_rule_name(int r) { return (unsigned)r < QL_RULE_N ? RULE[r] : NULL; }
const char *ql_client_name(int c) { return (unsigned)c < QL_CLIENT_N ? CLIENT[c] : "unknown"; }

ql_result_t ql_result(const ql_note_t *n, int rcode, size_t len)
{
    if (!len)
        return QR_DROPPED;
    if (n->notify)
        return QR_NOTIFY;
    if (!n->parsed || rcode == 1 /* FORMERR */ || rcode == 4 /* NOTIMP */)
        return QR_ERROR;
    /* A local zone's answer, even if a CNAME out of it was followed upstream (local zones
     * aren't blocked, nor where their CNAMEs lead). */
    if (n->hosted)
        return QR_HOSTED;
    if (n->secondary)
        return QR_SECONDARY;
    if (n->rule == QL_RULE_OVERRIDE)
        return QR_OVERRIDDEN;
    if (n->rule == QL_RULE_LIST || n->rule == QL_RULE_CNAME)
        return QR_BLOCKED;
    if (rcode == 5)
        return QR_REFUSED;
    if (n->cache)
        return QR_CACHE;
    if (n->asked && n->answered)
        return QR_FORWARDED;
    return QR_SERVFAIL;
}

uint32_t ql_client_addr(uint32_t addr, ql_client_t mode)
{
    if (mode == QL_CLIENT_FULL)
        return addr;
    if (mode == QL_CLIENT_SUBNET) {
        /* Network order: the last byte of the address is the last in memory. */
        uint8_t b[4];
        memcpy(b, &addr, 4);
        b[3] = 0;
        memcpy(&addr, b, 4);
        return addr;
    }
    return 0;
}

uint32_t ql_capacity(size_t bytes) { return (uint32_t)(bytes / sizeof(ql_entry_t)); }

bool ql_init(ql_ring_t *r, void *mem, size_t bytes, uint64_t next_seq)
{
    memset(r, 0, sizeof(*r));
    r->n = ql_capacity(bytes);
    r->e = r->n ? mem : NULL;
    r->next = r->first = next_seq ? next_seq : 1;
    return r->n > 0;
}

/* The last labels of qname that fit QL_NAME_MAX bytes, into name; true if any were left out. */
static bool name_tail(const uint8_t *qname, int qname_len, uint8_t name[QL_NAME_MAX], uint8_t *name_len)
{
    if (qname_len <= 0) {
        *name_len = 0;
        return false;
    }
    size_t len = (size_t)qname_len, off = 0;
    bool trunc = false;
    if (len > QL_NAME_MAX) {
        /* Its last labels: skip whole labels from the front until the rest fits. */
        while (off < len && qname[off] && len - off > QL_NAME_MAX)
            off += 1 + (size_t)qname[off];
        if (off > len)
            off = len;
        trunc = true;
    }
    if (len - off > QL_NAME_MAX)
        off = len - QL_NAME_MAX; /* not a name a parse gives: kept within the entry all the same */
    *name_len = (uint8_t)(len - off);
    memcpy(name, qname + off, len - off);
    return trunc;
}

void ql_set_name(ql_entry_t *e, const uint8_t *qname, int qname_len)
{
    e->flags &= (uint8_t)~QL_F_TRUNC;
    if (name_tail(qname, qname_len, e->name, &e->name_len))
        e->flags |= QL_F_TRUNC;
}

void ql_note_name(ql_note_t *n, const uint8_t *qname, int qname_len)
{
    n->name_trunc = name_tail(qname, qname_len, n->name, &n->name_len);
}

uint64_t ql_add(ql_ring_t *r, const ql_entry_t *e)
{
    uint64_t seq = r->next++;
    if (!r->n)
        return seq;
    ql_entry_t *s = &r->e[seq % r->n];
    *s = *e;
    s->seq = seq;
    if (r->next - r->first > r->n)
        r->first = r->next - r->n;
    return seq;
}

bool ql_get(const ql_ring_t *r, uint64_t seq, ql_entry_t *out)
{
    if (!r->n || seq < r->first || seq >= r->next)
        return false;
    *out = r->e[seq % r->n];
    return out->seq == seq;
}

void ql_entry_privacy(ql_entry_t *e, ql_client_t mode)
{
    if ((unsigned)mode >= QL_CLIENT_N)
        mode = QL_CLIENT_HIDDEN;
    if (e->client_mode >= mode)
        return; /* logged under this mode or a stricter one */
    e->client = ql_client_addr(e->client, mode);
    e->client_mode = (uint8_t)mode;
}

void ql_privacy(ql_ring_t *r, uint64_t seq, ql_client_t mode)
{
    if (!r->n || seq < r->first || seq >= r->next)
        return;
    ql_entry_t *e = &r->e[seq % r->n];
    if (e->seq == seq)
        ql_entry_privacy(e, mode);
}

ql_cursor_t ql_cursor(uint64_t cursor, uint64_t first, uint64_t next)
{
    ql_cursor_t c = { .from = cursor + 1 };
    if (cursor >= next) {
        /* Past the newest (next - 1): from another boot. Everything held is new to it. */
        c.from = first;
        c.reset = true;
    } else if (cursor + 1 < first) {
        c.from = first;
        c.lost = first - (cursor + 1);
    }
    return c;
}

/* ---- JSON ---- */

/* Appends s (n bytes) to out, JSON-escaped; returns the new length. */
static size_t put(char *out, size_t cap, size_t o, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char ch = s[i];
        if ((ch == '\\' || ch == '"') && o + 2 < cap) {
            out[o++] = '\\';
            out[o++] = ch;
        } else if (ch != '\\' && ch != '"' && o + 1 < cap) {
            out[o++] = ch;
        } else {
            break;
        }
    }
    if (cap)
        out[o < cap ? o : cap - 1] = 0;
    return o;
}

size_t ql_name_json(const uint8_t *name, size_t len, char *out, size_t cap)
{
    size_t o = 0, p = 0;
    if (cap)
        out[0] = 0;
    if (!len || !name[0])
        return put(out, cap, 0, ".", 1);
    while (p < len && name[p]) {
        size_t l = name[p++];
        if (o)
            o = put(out, cap, o, ".", 1);
        for (size_t i = 0; i < l && p < len; i++, p++) {
            uint8_t ch = name[p];
            char t[5];
            size_t tn;
            if (ch >= 'A' && ch <= 'Z') {
                t[0] = (char)(ch - 'A' + 'a');
                tn = 1;
            } else if (ch == '.' || ch == '\\' || ch == '"') {
                t[0] = '\\';
                t[1] = (char)ch;
                tn = 2;
            } else if (ch < 0x21 || ch > 0x7e) {
                snprintf(t, sizeof(t), "\\%03u", ch);
                tn = 4;
            } else {
                t[0] = (char)ch;
                tn = 1;
            }
            o = put(out, cap, o, t, tn);
        }
    }
    return o;
}

const char *ql_type_name(uint16_t t, char *buf)
{
    static const struct {
        uint16_t t;
        const char *n;
    } T[] = { { 1, "A" },      { 2, "NS" },     { 5, "CNAME" },  { 6, "SOA" },     { 12, "PTR" },   { 13, "HINFO" },
              { 15, "MX" },    { 16, "TXT" },   { 28, "AAAA" },  { 33, "SRV" },    { 35, "NAPTR" }, { 39, "DNAME" },
              { 41, "OPT" },   { 43, "DS" },    { 46, "RRSIG" }, { 47, "NSEC" },   { 48, "DNSKEY" }, { 50, "NSEC3" },
              { 52, "TLSA" },  { 64, "SVCB" },  { 65, "HTTPS" }, { 99, "SPF" },    { 251, "IXFR" }, { 252, "AXFR" },
              { 255, "ANY" },  { 257, "CAA" } };
    for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++)
        if (T[i].t == t)
            return T[i].n;
    snprintf(buf, 12, "TYPE%u", (unsigned)t);
    return buf;
}

const char *ql_rcode_name(int rc, char *buf)
{
    static const char *const R[] = { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
                                     "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE" };
    if (rc >= 0 && (size_t)rc < sizeof(R) / sizeof(R[0]))
        return R[rc];
    snprintf(buf, 12, "RCODE%d", rc);
    return buf;
}

size_t ql_entry_json(const ql_entry_t *e, uint64_t now_ms, uint64_t unix_ms, char *j, size_t cap)
{
    char name[QL_NAME_MAX * 5 + 8], tb[12], rb[12], client[24] = "null", time[24] = "null";
    ql_name_json(e->name, e->name_len, name, sizeof(name));
    if (e->client_mode != QL_CLIENT_HIDDEN) {
        const uint8_t *a = (const uint8_t *)&e->client;
        snprintf(client, sizeof(client), "\"%u.%u.%u.%u\"", a[0], a[1], a[2], a[3]);
    }
    if (unix_ms && now_ms >= e->t_ms)
        snprintf(time, sizeof(time), "%llu", (unsigned long long)(unix_ms - (now_ms - e->t_ms)));
    const char *rule = ql_rule_name(e->rule);
    int n = snprintf(j, cap,
                     "{\"seq\":%llu,\"uptime_ms\":%llu,\"time\":%s,\"client\":%s,\"transport\":\"%s\","
                     "\"qname\":\"%s\",\"qtype\":\"%s\",\"result\":\"%s\",\"rcode\":\"%s\",\"latency_us\":%lu%s%s%s%s}",
                     (unsigned long long)e->seq, (unsigned long long)e->t_ms, time, client,
                     e->flags & QL_F_TCP ? "tcp" : "udp", name, ql_type_name(e->qtype, tb), ql_result_name(e->result),
                     ql_rcode_name(e->rcode, rb), (unsigned long)e->latency_us, rule ? ",\"rule\":\"" : "",
                     rule ? rule : "", rule ? "\"" : "", e->flags & QL_F_TRUNC ? ",\"truncated\":true" : "");
    return n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap ? cap - 1 : 0;
}
