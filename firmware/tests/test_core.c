/* Host tests for the portable DNS core: gcc + ASan/UBSan, no hardware. */
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "answer.h"
#include "block.h"
#include "blocklist.h"
#include "blocklist_vectors.h"
#include "board_def.h"
#include "cJSON.h"
#include "cache.h"
#include "cfg.h"
#include "config.h"
#include "cpuplan.h"
#include "dns_wire.h"
#include "flight.h"
#include "forward.h"
#include "fwdq.h"
#include "health.h"
#include "reboot.h"
#include "hzone.h"
#include "mbedtls/sha256.h"
#include "memplan.h"
#include "release.h"
#include "release_vectors.h"
#include "sup.h"
#include "svc.h"
#include "upq.h"
#include "zone.h"

static int s_fail;
#define CHECK(c)                                                          \
    do {                                                                  \
        if (!(c)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);  \
            s_fail++;                                                     \
        }                                                                 \
    } while (0)

static int N(const char *s, uint8_t *out) { return dns_name_from_str(s, out); }

static void add_name_rr(zone_t *z, const char *owner, uint16_t type, const char *target)
{
    uint8_t o[256], t[256];
    int ol = N(owner, o), tl = N(target, t);
    assert(zone_add(z, o, ol, type, 300, t, (uint16_t)tl));
}

static void add_a(zone_t *z, const char *owner, uint8_t last)
{
    uint8_t o[256], a[4] = { 10, 0, 0, last };
    assert(zone_add(z, o, N(owner, o), DNS_T_A, 300, a, 4));
}

static zone_t *make_zone(void)
{
    uint8_t apex[256], rd[600], o[256];
    int al = N("example.test", apex);
    zone_t *z = zone_new(apex, al, SIZE_MAX);
    int p = N("ns1.example.test", rd);
    p += N("admin.example.test", rd + p);
    uint32_t v[5] = { 2026093001, 3600, 900, 604800, 120 };
    for (int i = 0; i < 5; i++, p += 4)
        wr32(rd + p, v[i]);
    assert(zone_add(z, apex, al, DNS_T_SOA, 3600, rd, (uint16_t)p));
    add_name_rr(z, "example.test", DNS_T_NS, "ns1.example.test");
    add_a(z, "ns1.example.test", 1);
    add_a(z, "www.example.test", 2);
    add_a(z, "WWW.example.test", 2); /* duplicate in another case: dropped */
    add_name_rr(z, "alias.example.test", DNS_T_CNAME, "www.example.test");
    add_name_rr(z, "ext.example.test", DNS_T_CNAME, "foo.other.test");
    add_name_rr(z, "loop1.example.test", DNS_T_CNAME, "loop2.example.test");
    add_name_rr(z, "loop2.example.test", DNS_T_CNAME, "loop1.example.test");
    add_a(z, "*.wild.example.test", 3);
    add_a(z, "a.b.c.example.test", 4);
    add_name_rr(z, "sub.example.test", DNS_T_NS, "ns.sub.example.test");
    add_a(z, "ns.sub.example.test", 5);
    uint8_t mx[260];
    wr16(mx, 10);
    int ml = N("www.example.test", mx + 2) + 2;
    assert(zone_add(z, o, N("mail.example.test", o), DNS_T_MX, 300, mx, (uint16_t)ml));
    add_a(z, "outside.test", 9); /* out of zone: ignored */
    assert(zone_finalize(z));
    return z;
}

static zone_t *g_zone;
static zone_t *finder(void *ctx, const uint8_t *name, int len)
{
    (void)ctx;
    return dns_name_under(name, len, g_zone->apex, g_zone->apex_len) ? g_zone : NULL;
}

/* Encodes name keeping its case (dns_name_from_str lowercases). */
static int encode_keep_case(const char *s, uint8_t *out)
{
    int nl = N(s, out);
    int pos = 0;
    while (out[pos]) {
        memcpy(out + pos + 1, s, out[pos]);
        s += out[pos] + (s[out[pos]] == '.' ? 1 : 0);
        pos += out[pos] + 1;
    }
    return nl;
}

static size_t make_query(uint8_t *buf, const char *name, uint16_t type, bool edns)
{
    uint8_t n[256];
    int nl = encode_keep_case(name, n);
    memset(buf, 0, 12);
    wr16(buf, 0x1234);
    wr16(buf + 2, DNS_F_RD);
    wr16(buf + 4, 1);
    size_t p = 12;
    memcpy(buf + p, n, (size_t)nl);
    p += (size_t)nl;
    wr16(buf + p, type);
    wr16(buf + p + 2, DNS_C_IN);
    p += 4;
    if (edns) {
        wr16(buf + 10, 1);
        buf[p] = 0;
        wr16(buf + p + 1, DNS_T_OPT);
        wr16(buf + p + 3, 4096);
        wr32(buf + p + 5, 0x8000);
        wr16(buf + p + 9, 0);
        p += 11;
    }
    return p;
}

typedef struct {
    dns_hdr_t h;
    int n;
    dns_rr_view_t rr[32];
    int section[32];
} parsed_t;

static bool parse_resp(const uint8_t *m, size_t len, parsed_t *p)
{
    memset(p, 0, sizeof(*p));
    if (!dns_hdr_parse(m, len, &p->h))
        return false;
    size_t pos = 12;
    for (int i = 0; i < p->h.qd; i++) {
        if (dns_name_skip(m, len, &pos) < 0)
            return false;
        pos += 4;
    }
    int total = p->h.an + p->h.ns + p->h.ar;
    for (int i = 0; i < total && i < 32; i++) {
        if (!dns_rr_parse(m, len, &pos, &p->rr[i]))
            return false;
        p->section[i] = i < p->h.an ? 0 : i < p->h.an + p->h.ns ? 1 : 2;
        p->n++;
    }
    return pos == len;
}

static void ask(const char *name, uint16_t type, uint8_t *out, size_t *olen, answer_result_t *res, size_t limit)
{
    uint8_t qb[512];
    dns_query_t q;
    size_t ql = make_query(qb, name, type, false);
    assert(dns_query_parse(qb, ql, &q) == 0);
    dns_builder_t b;
    dnsb_init(&b, out, 4096, limit, &q, DNS_F_QR | DNS_F_RD);
    answer_auth(finder, NULL, g_zone, &q, &b, res);
    if (res->authoritative)
        dnsb_set_flags(&b, DNS_F_AA, 0);
    dnsb_set_rcode(&b, res->rcode);
    *olen = dnsb_finish(&b);
}

static bool name_is(const dns_rr_view_t *rr, const char *s)
{
    uint8_t n[256];
    return dns_name_eq(rr->name, rr->name_len, n, N(s, n));
}

static void test_names(void)
{
    uint8_t n[256], out[256];
    CHECK(N("Example.TEST.", n) == 14);
    CHECK(N("", n) == 1 && n[0] == 0);
    CHECK(N("a..b", n) < 0);
    char s[64];
    N("www.example.test", n);
    dns_name_to_str(n, s, sizeof(s));
    CHECK(strcmp(s, "www.example.test") == 0);
    const uint8_t q[] = { 3, 'a', '"', '\\', 4, 't', 'e', 's', 't', 0 }; /* safe in JSON */
    dns_name_to_str(q, s, sizeof(s));
    CHECK(strcmp(s, "a??.test") == 0);

    uint8_t p[256];
    int pl = N("example.test", p);
    CHECK(dns_name_under(n, 18, p, pl));
    CHECK(!dns_name_under(p, pl, n, 18));
    uint8_t bad[256];
    int bl = N("xample.test", bad);
    CHECK(!dns_name_under(n, 18, bad, bl)); /* label boundary respected */

    /* compression: name at 12, then "www" + pointer to 12 */
    uint8_t msg[64] = { 0 };
    memcpy(msg + 12, p, (size_t)pl);
    size_t off = 12 + (size_t)pl;
    msg[off] = 3;
    memcpy(msg + off + 1, "www", 3);
    msg[off + 4] = 0xC0;
    msg[off + 5] = 12;
    size_t pos = off;
    CHECK(dns_name_read(msg, off + 6, &pos, out) == 18 && pos == off + 6);
    CHECK(dns_name_eq(out, 18, n, 18));

    /* self-pointing and forward pointers are rejected */
    uint8_t loop[16] = { 0 };
    loop[12] = 0xC0;
    loop[13] = 12;
    pos = 12;
    CHECK(dns_name_read(loop, 14, &pos, out) < 0);
    loop[13] = 14;
    pos = 12;
    CHECK(dns_name_read(loop, 16, &pos, out) < 0);
}

static void test_answers(void)
{
    uint8_t out[4096];
    size_t len;
    answer_result_t res;
    parsed_t p;

    ask("www.example.test", DNS_T_A, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p));
    CHECK(res.rcode == 0 && res.authoritative && p.h.an == 1 && (p.h.flags & DNS_F_AA));
    CHECK(p.rr[0].type == DNS_T_A && out[p.rr[0].rdata_off + 3] == 2);

    ask("WwW.ExAmPlE.tEsT", DNS_T_A, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && p.h.an == 1);
    CHECK(memcmp(out + 13, "WwW", 3) == 0); /* question case preserved */

    ask("alias.example.test", DNS_T_A, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && p.h.an == 2);
    CHECK(p.rr[0].type == DNS_T_CNAME && p.rr[1].type == DNS_T_A && name_is(&p.rr[1], "www.example.test"));

    ask("alias.example.test", DNS_T_CNAME, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && p.h.an == 1 && p.rr[0].type == DNS_T_CNAME);

    ask("ext.example.test", DNS_T_A, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && p.h.an == 1 && res.external);
    uint8_t t[256];
    CHECK(dns_name_eq(res.target, res.target_len, t, N("foo.other.test", t)));

    ask("loop1.example.test", DNS_T_A, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && p.h.an == 8); /* chain capped */

    ask("nope.example.test", DNS_T_A, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && res.rcode == DNS_R_NXDOMAIN && p.h.an == 0 && p.h.ns == 1);
    CHECK(p.rr[0].type == DNS_T_SOA && p.rr[0].ttl == 120); /* min(SOA ttl, MINIMUM) */

    ask("www.example.test", DNS_T_AAAA, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && res.rcode == 0 && p.h.an == 0 && p.h.ns == 1);

    ask("b.c.example.test", DNS_T_A, out, &len, &res, 4096); /* empty non-terminal */
    CHECK(parse_resp(out, len, &p) && res.rcode == 0 && p.h.an == 0 && p.h.ns == 1);

    ask("x.y.wild.example.test", DNS_T_A, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && res.rcode == 0 && p.h.an == 1 && name_is(&p.rr[0], "x.y.wild.example.test"));

    ask("host.sub.example.test", DNS_T_A, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && !res.authoritative && p.h.an == 0 && p.h.ns == 1 && p.h.ar == 1);
    CHECK(!(p.h.flags & DNS_F_AA) && p.rr[0].type == DNS_T_NS && p.rr[1].type == DNS_T_A);

    ask("mail.example.test", DNS_T_MX, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && p.h.an == 1 && p.rr[0].type == DNS_T_MX);

    ask("example.test", DNS_T_ANY, out, &len, &res, 4096);
    CHECK(parse_resp(out, len, &p) && p.h.an == 2); /* SOA + NS */

    ask("outside.test", DNS_T_A, out, &len, &res, 4096); /* never stored */
    CHECK(parse_resp(out, len, &p) && res.rcode == DNS_R_NXDOMAIN);

    /* truncation: 40-byte limit cannot hold the answer → TC, no records */
    ask("www.example.test", DNS_T_A, out, &len, &res, 40);
    CHECK(parse_resp(out, len, &p) && (p.h.flags & DNS_F_TC) && p.h.an == 0);
}

static void test_persistence(void)
{
    char path[] = "/tmp/dns2_test_zone.bin";
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    remove(path);
    remove(tmp);

    CHECK(zone_save(g_zone, path));
    zone_t *z = zone_load(path, g_zone->apex, g_zone->apex_len, SIZE_MAX);
    CHECK(z && z->n == g_zone->n && z->serial == 2026093001);
    zone_free(z);

    /* corrupt one byte: checksum rejects it */
    FILE *f = fopen(path, "r+b");
    fseek(f, 20, SEEK_SET);
    fputc(0x5A, f);
    fclose(f);
    CHECK(zone_load(path, g_zone->apex, g_zone->apex_len, SIZE_MAX) == NULL);

    /* crash after remove(), before rename(): only .tmp exists */
    CHECK(zone_save(g_zone, tmp));
    remove(path);
    z = zone_load(path, g_zone->apex, g_zone->apex_len, SIZE_MAX);
    CHECK(z && z->n == g_zone->n);
    zone_free(z);
    remove(tmp);
    remove(path);
}

/* Upstream-style response: www.example.org A, TTL 300, compressed owner. */
static size_t upstream_resp(uint8_t *m, uint16_t flags, bool with_answer, bool with_soa)
{
    uint8_t n[256];
    int nl = N("www.example.org", n);
    memset(m, 0, 12);
    wr16(m + 2, (uint16_t)(DNS_F_QR | DNS_F_RD | DNS_F_RA | flags));
    wr16(m + 4, 1);
    size_t p = 12;
    memcpy(m + p, n, (size_t)nl);
    p += (size_t)nl;
    wr16(m + p, DNS_T_A);
    wr16(m + p + 2, 1);
    p += 4;
    if (with_answer) {
        wr16(m + 6, 1);
        m[p] = 0xC0; m[p + 1] = 12;
        wr16(m + p + 2, DNS_T_A); wr16(m + p + 4, 1); wr32(m + p + 6, 300); wr16(m + p + 10, 4);
        m[p + 12] = 1; m[p + 13] = 2; m[p + 14] = 3; m[p + 15] = 4;
        p += 16;
    }
    if (with_soa) {
        wr16(m + 8, 1);
        m[p] = 0xC0; m[p + 1] = 12 + 4; /* example.org */
        wr16(m + p + 2, DNS_T_SOA); wr16(m + p + 4, 1); wr32(m + p + 6, 3600);
        size_t rd = p + 12;
        m[rd] = 0xC0; m[rd + 1] = 16;
        m[rd + 2] = 0xC0; m[rd + 3] = 16;
        uint32_t v[5] = { 1, 2, 3, 4, 60 };
        for (int i = 0; i < 5; i++)
            wr32(m + rd + 4 + 4 * i, v[i]);
        wr16(m + p + 10, 24);
        p = rd + 24;
    }
    return p;
}

/* The cache's key (cache.h): the name without regard to case, the type, the class and CD.
 * The rollout's checks ask as Go's miekg/dns does (RD, no EDNS); a client may ask the same
 * question with EDNS, DO, AD and another case: one entry answers both. */
static void test_cache_key(void)
{
    uint8_t m[512], got[512], qb[512];
    size_t len = upstream_resp(m, 0, true, false), gl;
    uint32_t age;
    cache_t *c = cache_new(16, 1 << 20);

    dns_query_t check, client, client_cd;
    size_t ql = make_query(qb, "www.example.org", DNS_T_A, false);
    CHECK(dns_query_parse(qb, ql, &check) == 0 && !check.has_edns && !check.do_bit);
    ql = make_query(qb, "WWW.Example.ORG", DNS_T_A, true);
    wr16(qb + 2, DNS_F_RD | DNS_F_AD);
    CHECK(dns_query_parse(qb, ql, &client) == 0 && client.has_edns && client.do_bit);
    wr16(qb + 2, DNS_F_RD | DNS_F_CD);
    CHECK(dns_query_parse(qb, ql, &client_cd) == 0 && (client_cd.flags & DNS_F_CD));

    /* The check's answer is cached as server.c keys it ... */
    cache_put(c, check.qname, check.qname_len, check.qtype, check.qclass, (check.flags & DNS_F_CD) != 0, 1000, m, len);
    /* ... and the client's first query hits it: DO, EDNS, AD and case aren't in the key. */
    CHECK(cache_get(c, client.qname, client.qname_len, client.qtype, client.qclass, (client.flags & DNS_F_CD) != 0,
                    1001, got, sizeof(got), &gl, &age) && gl == len && memcmp(got, m, len) == 0);
    /* A client with CD is served the answer asked for without it (validated or insecure). */
    CHECK(cache_get(c, client_cd.qname, client_cd.qname_len, client_cd.qtype, client_cd.qclass, true, 1001, got,
                    sizeof(got), &gl, &age));
    /* Another type or class is another question. */
    CHECK(!cache_get(c, check.qname, check.qname_len, DNS_T_AAAA, DNS_C_IN, false, 1001, got, sizeof(got), &gl, &age));
    CHECK(!cache_get(c, check.qname, check.qname_len, DNS_T_A, 3, false, 1001, got, sizeof(got), &gl, &age));

    /* An answer asked for with CD (possibly bogus) never answers a query without it. */
    uint8_t n2[256];
    int n2l = N("cd.example.org", n2);
    cache_put(c, n2, n2l, DNS_T_A, DNS_C_IN, true, 1000, m, len);
    CHECK(!cache_get(c, n2, n2l, DNS_T_A, DNS_C_IN, false, 1001, got, sizeof(got), &gl, &age));
    CHECK(cache_get(c, n2, n2l, DNS_T_A, DNS_C_IN, true, 1001, got, sizeof(got), &gl, &age));
    /* Both stored: each its own. */
    cache_put(c, n2, n2l, DNS_T_A, DNS_C_IN, false, 1000, m, len);
    cache_stats_t st;
    cache_get_stats(c, &st);
    CHECK(st.entries == 3);
    CHECK(cache_get(c, n2, n2l, DNS_T_A, DNS_C_IN, false, 1001, got, sizeof(got), &gl, &age));
    cache_free(c);
}

/* An upstream answer asked with DO: www.example.org A with its RRSIG, an NSEC in authority. */
static size_t signed_resp(uint8_t *m, uint16_t qtype)
{
    uint8_t n[256];
    int nl = N("www.example.org", n);
    memset(m, 0, 12);
    wr16(m + 2, DNS_F_QR | DNS_F_RD | DNS_F_RA | DNS_F_AD);
    wr16(m + 4, 1);
    wr16(m + 6, 2);
    wr16(m + 8, 1);
    size_t p = 12;
    memcpy(m + p, n, (size_t)nl);
    p += (size_t)nl;
    wr16(m + p, qtype);
    wr16(m + p + 2, DNS_C_IN);
    p += 4;
    const uint16_t types[3] = { DNS_T_A, DNS_T_RRSIG, DNS_T_NSEC };
    for (int i = 0; i < 3; i++) {
        uint16_t rdlen = types[i] == DNS_T_A ? 4 : 20;
        m[p] = 0xC0;
        m[p + 1] = 12;
        wr16(m + p + 2, types[i]);
        wr16(m + p + 4, DNS_C_IN);
        wr32(m + p + 6, 300);
        wr16(m + p + 10, rdlen);
        memset(m + p + 12, 7, rdlen);
        p += 12 + rdlen;
    }
    return p;
}

static void relay_types(const uint8_t *m, size_t len, bool dnssec, bool answers_only, uint16_t *types, int *n)
{
    uint8_t qb[512], out[1024];
    dns_query_t q;
    size_t ql = make_query(qb, "www.example.org", DNS_T_A, dnssec);
    CHECK(dns_query_parse(qb, ql, &q) == 0);
    dns_builder_t b;
    dnsb_init(&b, out, sizeof(out), sizeof(out), &q, DNS_F_QR);
    CHECK(dnsb_relay(&b, m, len, 0, answers_only, dnssec) == 0);
    size_t ol = dnsb_finish(&b);
    parsed_t p;
    CHECK(parse_resp(out, ol, &p));
    *n = p.h.an + p.h.ns;
    for (int i = 0; i < *n; i++)
        types[i] = p.rr[i].type;
}

/* One cached answer (asked with DO) serves clients with and without DO: without it the
 * DNSSEC records are left out, unless asked for by type (RFC 4035, 3.2.1). */
static void test_dnssec_relay(void)
{
    uint8_t m[512];
    uint16_t t[8];
    int n;
    size_t len = signed_resp(m, DNS_T_A);
    relay_types(m, len, true, false, t, &n);
    CHECK(n == 3 && t[0] == DNS_T_A && t[1] == DNS_T_RRSIG && t[2] == DNS_T_NSEC);
    relay_types(m, len, false, false, t, &n);
    CHECK(n == 1 && t[0] == DNS_T_A);
    relay_types(m, len, false, true, t, &n); /* a local CNAME's chain: the answers */
    CHECK(n == 1 && t[0] == DNS_T_A);
    /* Asked for RRSIG by type: kept; the NSEC still isn't. */
    len = signed_resp(m, DNS_T_RRSIG);
    relay_types(m, len, false, false, t, &n);
    CHECK(n == 2 && t[0] == DNS_T_A && t[1] == DNS_T_RRSIG);
    /* ANY: everything. */
    len = signed_resp(m, DNS_T_ANY);
    relay_types(m, len, false, false, t, &n);
    CHECK(n == 3);
}

/* ---- the pending table: one upstream query per question (flight.h) ---- */

typedef struct {
    flight_waiter_t fw; /* first, as in server.c's UDP item */
    int id;
} fake_item_t;

/* A TCP waiter as server.c has one: woken by a semaphore here (a task notification there). */
typedef struct {
    flight_tcp_t t; /* first */
    sem_t sem;
    int wakes;
} fake_tcp_t;

static void fake_tcp_wake(flight_waiter_t *w)
{
    fake_tcp_t *f = (fake_tcp_t *)w;
    /* Slow to start, as a woken task's notification may be (the waiter's done is set
     * first): a waiter that frees itself on seeing done, before flight_cancel, is caught. */
    for (int spin = 2000; spin > 0; spin--)
        __asm__ __volatile__("" ::: "memory");
    __atomic_fetch_add(&f->wakes, 1, __ATOMIC_RELAXED);
    sem_post(&f->sem);
}

static void fake_tcp_init(fake_tcp_t *f, uint8_t *buf, size_t cap)
{
    memset(f, 0, sizeof(*f));
    f->t.w.wake = fake_tcp_wake;
    f->t.buf = buf;
    f->t.cap = cap;
    sem_init(&f->sem, 0, 0);
}

static int list_ids(flight_waiter_t *w, int *ids, int max)
{
    int n = 0;
    for (; w && n < max; w = w->next)
        ids[n++] = ((fake_item_t *)w)->id;
    return n;
}

/* The table's memory, as server.c takes it from the share. */
static flight_t s_fl_mem[64];

static flight_query_t fq(const uint8_t *name, int len, uint16_t qtype, bool cd, int group)
{
    static const uint32_t servers[2] = { 0x0100007f, 0x0200007f };
    return (flight_query_t){ .qname = name, .qlen = len, .qtype = qtype, .qclass = DNS_C_IN, .cd = cd,
                             .group = group, .servers = servers, .nservers = 2, .timeout_ms = 1500, .gen = 7,
                             .cnames = true };
}

/* Opens or joins q's flight, now_ms 1000 and a 1500 ms wait; the role. */
static flight_role_t begin(flights_t *fl, flight_query_t q, flight_waiter_t *w, int *slot)
{
    uint32_t d;
    return flight_begin(fl, &q, w, 1000, 1500, slot, &d);
}

static void test_flights(void)
{
    static flights_t fl;
    flights_init(&fl, s_fl_mem, 8, MP_FLIGHT_WAITERS);
    CHECK(sizeof(flight_t) <= MP_FWD_SLOT && flights_bytes(32) == 32 * sizeof(flight_t));
    uint8_t a[256], up[256], b[256];
    int al = N("popular.example.org", a), ul = N("POPULAR.Example.Org", up), bl = N("other.example.org", b);
    fake_item_t it[8];
    for (int i = 0; i < 8; i++)
        it[i].id = i, it[i].fw.wake = NULL;
    int slot, s2, s3, ids[8];
    uint32_t d;
    const int DEF = FLIGHT_GROUP_DEFAULT;

    /* Coalescing: the first opens a flight (to be asked) and waits on it, the next for the
     * question (any case) wait on it too, with its deadline. */
    flight_query_t q = fq(a, al, DNS_T_A, false, DEF);
    CHECK(flight_begin(&fl, &q, &it[0].fw, 1000, 1500, &slot, &d) == FLIGHT_OPENED && slot >= 0 && d == 2500);
    flight_t *f = flight_slot(&fl, slot);
    CHECK(f && f->state == FLIGHT_OPEN && f->group == DEF && f->up.nservers == 2 && f->up.servers[1] == 0x0200007f &&
          f->up.timeout_ms == 1500 && f->gen == 7 && f->cnames && f->up.sock == -1 && f->deadline_ms == 2500 &&
          f->qlen == al && !memcmp(f->name, a, (size_t)al));
    q = fq(up, ul, DNS_T_A, false, DEF);
    CHECK(flight_begin(&fl, &q, &it[1].fw, 1400, 9000, &s2, &d) == FLIGHT_JOINED && s2 < 0 && d == 2500);
    CHECK(begin(&fl, fq(a, al, DNS_T_A, false, DEF), &it[2].fw, &s2) == FLIGHT_JOINED);
    CHECK(flight_waiting(&fl) == 3 && flight_next_deadline(&fl, &d) && d == 2500);
    /* Different types (and CD) of the same name don't coalesce: each its own flight. */
    CHECK(begin(&fl, fq(a, al, DNS_T_AAAA, false, DEF), &it[3].fw, &s2) == FLIGHT_OPENED && s2 != slot);
    CHECK(begin(&fl, fq(a, al, DNS_T_A, true, DEF), &it[4].fw, &s3) == FLIGHT_OPENED && s3 != slot && s3 != s2);
    CHECK(flight_waiting(&fl) == 5);
    int scd = s3;
    /* No waiter to join with: FULL (every caller has one). */
    CHECK(begin(&fl, fq(a, al, DNS_T_A, false, DEF), NULL, &s3) == FLIGHT_FULL);
    /* The answer is back: the parked ones, the opener first, in the order they came, for the
     * owner to answer. */
    static const uint8_t ans[] = "an answer";
    CHECK(list_ids(flight_end(&fl, slot, ans, sizeof(ans)), ids, 8) == 3 && ids[0] == 0 && ids[1] == 1 && ids[2] == 2);
    CHECK(flight_waiting(&fl) == 2 && f->state == FLIGHT_DONE); /* the AAAA's and the CD's openers */
    CHECK(list_ids(flight_end(&fl, s2, ans, sizeof(ans)), ids, 8) == 1 && ids[0] == 3);
    flight_t *fcd = flight_slot(&fl, scd);
    CHECK(fcd->head == &it[4].fw && fcd->tail == &it[4].fw);
    CHECK(flight_end(&fl, slot, ans, sizeof(ans)) == NULL); /* once */
    CHECK(list_ids(flight_free(&fl, scd), ids, 8) == 1 && ids[0] == 4); /* freed open: failed */
    /* Ended: the next query for it opens a new flight, while the owner still holds the old
     * slot (its answer may be in it). */
    CHECK(begin(&fl, fq(a, al, DNS_T_A, false, DEF), &it[5].fw, &s3) == FLIGHT_OPENED && s3 != slot);
    CHECK(flight_free(&fl, slot) == NULL && f->state == FLIGHT_FREE);
    /* Freeing an open flight ends it as failed: its parked queries, the opener's too, come
     * back for SERVFAIL. */
    CHECK(begin(&fl, fq(a, al, DNS_T_A, false, DEF), &it[6].fw, &slot) == FLIGHT_JOINED);
    CHECK(list_ids(flight_free(&fl, s3), ids, 8) == 2 && ids[0] == 5 && ids[1] == 6 && flight_waiting(&fl) == 0);
    for (int i = 0; i < 8; i++)
        flight_free(&fl, i);
    for (int g = 0; g < FLIGHT_GROUPS; g++)
        CHECK(fl.held[g] == 0 && fl.parked[g] == 0);

    /* A TCP waiter gets a copy of the answer and is woken; one whose buffer is too small,
     * -1. Neither is parked (no item of the pool). */
    uint8_t big[64], small[4];
    fake_tcp_t t1, t2;
    fake_tcp_init(&t1, big, sizeof(big));
    fake_tcp_init(&t2, small, sizeof(small));
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), NULL, &slot) == FLIGHT_OPENED);
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), &t1.t.w, &s2) == FLIGHT_JOINED && t1.t.slot == slot);
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), &it[0].fw, &s2) == FLIGHT_JOINED);
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), &t2.t.w, &s2) == FLIGHT_JOINED);
    CHECK(flight_waiting(&fl) == 1 && !flight_tcp_done(&t1.t));
    CHECK(list_ids(flight_end(&fl, slot, ans, sizeof(ans)), ids, 8) == 1 && ids[0] == 0);
    CHECK(flight_tcp_done(&t1.t) && t1.t.len == (int)sizeof(ans) && !memcmp(big, ans, sizeof(ans)) && t1.wakes == 1);
    CHECK(flight_tcp_done(&t2.t) && t2.t.len == -1 && t2.wakes == 1);
    /* Its flight over, a TCP waiter can't cancel: its answer is in. */
    CHECK(!flight_cancel(&fl, &t1.t) && t1.t.len == (int)sizeof(ans));
    flight_free(&fl, slot);
    /* A TCP waiter that gives up first is taken off: no answer, no wake, the others keep
     * theirs (the last one cancelling leaves the list's tail right). */
    fake_tcp_init(&t1, big, sizeof(big));
    fake_tcp_init(&t2, big, sizeof(big));
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), NULL, &slot) == FLIGHT_OPENED);
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), &it[0].fw, &s2) == FLIGHT_JOINED);
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), &t1.t.w, &s2) == FLIGHT_JOINED);
    CHECK(flight_cancel(&fl, &t1.t) && !flight_tcp_done(&t1.t) && t1.t.len == -1);
    CHECK(!flight_cancel(&fl, &t1.t)); /* not there any more */
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), &it[1].fw, &s2) == FLIGHT_JOINED);
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), &t2.t.w, &s2) == FLIGHT_JOINED);
    CHECK(list_ids(flight_end(&fl, slot, ans, sizeof(ans)), ids, 8) == 2 && ids[0] == 0 && ids[1] == 1);
    CHECK(t1.wakes == 0 && t2.wakes == 1 && t2.t.len == (int)sizeof(ans));
    flight_free(&fl, slot);
    /* A TCP query that opens a flight waits on it as any other: woken with the answer, and
     * not parked (it holds no item). */
    fake_tcp_init(&t1, big, sizeof(big));
    CHECK(begin(&fl, fq(b, bl, DNS_T_A, false, DEF), &t1.t.w, &slot) == FLIGHT_OPENED && t1.t.slot == slot);
    CHECK(flight_waiting(&fl) == 0 && !flight_tcp_done(&t1.t));
    CHECK(flight_end(&fl, slot, ans, sizeof(ans)) == NULL && t1.wakes == 1 && t1.t.len == (int)sizeof(ans));
    flight_free(&fl, slot);
    sem_destroy(&t1.sem);
    sem_destroy(&t2.sem);
}

/* The caps (issue #53, test 1): a group holds at most half the slots and half the parked
 * queries, the forward zones together half as well, so a dead forwarder can't take the
 * table: past them, FULL (SERVFAIL at once). */
static void test_flight_caps(void)
{
    static flights_t fl;
    flights_init(&fl, s_fl_mem, 8, 8);
    fake_item_t it[16];
    for (int i = 0; i < 16; i++)
        it[i].id = i, it[i].fw.wake = NULL;
    uint8_t k[256];
    char s[48];
    int slot, slots[8], z;
#define NAME(fmt, i) (snprintf(s, sizeof(s), fmt, i), N(s, k))
    /* The default forwarders: 4 of the 8 slots. */
    for (int i = 0; i < 4; i++) {
        int kl = NAME("d%d.example.org", i);
        CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), NULL, &slots[i]) == FLIGHT_OPENED);
    }
    int kl = NAME("d%d.example.org", 4);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), &it[0].fw, &slot) == FLIGHT_FULL && slot < 0);
    /* A forward zone: the other 4. Then another zone has none (the zones' half is taken),
     * and still the default forwarders can't take more than theirs. */
    for (int i = 0; i < 4; i++) {
        kl = NAME("z%d.zone.example", i);
        CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_ZONE(0)), NULL, &slots[4 + i]) == FLIGHT_OPENED);
    }
    kl = NAME("y%d.other.example", 0);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_ZONE(1)), NULL, &slot) == FLIGHT_FULL);
    CHECK(fl.held[FLIGHT_GROUP_DEFAULT] == 4 && fl.held[FLIGHT_GROUP_ZONE(0)] == 4 && fl.zones_held == 4);
    /* An ended flight still holds its slot until it is freed. */
    flight_end(&fl, slots[0], NULL, -1);
    kl = NAME("d%d.example.org", 5);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), NULL, &slot) == FLIGHT_FULL);
    flight_free(&fl, slots[0]);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), NULL, &slots[0]) == FLIGHT_OPENED);
    /* Parked queries: 4 of the 8 on the default forwarders' flights... */
    kl = NAME("d%d.example.org", 1);
    for (int i = 0; i < 4; i++)
        CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), &it[i].fw, &slot) == FLIGHT_JOINED);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), &it[4].fw, &slot) == FLIGHT_FULL);
    /* ...4 on the zones' (any zone's flight, the zones together)... */
    for (int i = 0; i < 4; i++) {
        kl = NAME("z%d.zone.example", i);
        CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_ZONE(0)), &it[5 + i].fw, &slot) == FLIGHT_JOINED);
    }
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_ZONE(0)), &it[9].fw, &slot) == FLIGHT_FULL);
    CHECK(flight_waiting(&fl) == 8 && fl.parked[FLIGHT_GROUP_DEFAULT] == 4 && fl.zones_parked == 4);
    /* ...and a TCP waiter holds only its own worker: no cap. */
    uint8_t buf[64];
    fake_tcp_t t;
    fake_tcp_init(&t, buf, sizeof(buf));
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_ZONE(0)), &t.t.w, &slot) == FLIGHT_JOINED);
    /* Ending a flight gives its parked queries' places back to its group. */
    kl = NAME("d%d.example.org", 1);
    CHECK(flight_end(&fl, slots[1], NULL, -1) != NULL && fl.parked[FLIGHT_GROUP_DEFAULT] == 0);
    kl = NAME("d%d.example.org", 2);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), &it[10].fw, &slot) == FLIGHT_JOINED);
    for (int i = 0; i < 8; i++)
        flight_free(&fl, slots[i]);
    CHECK(t.wakes == 1 && t.t.len == -1);
    CHECK(flight_waiting(&fl) == 0 && fl.zones_held == 0 && fl.zones_parked == 0);
    for (int g = 0; g < FLIGHT_GROUPS; g++)
        CHECK(fl.held[g] == 0 && fl.parked[g] == 0);
    /* At most max_waiting parked in all, whatever the groups. */
    flights_init(&fl, s_fl_mem, 8, 2);
    kl = NAME("d%d.example.org", 0);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), NULL, &slot) == FLIGHT_OPENED);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), &it[0].fw, &z) == FLIGHT_JOINED);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), &it[1].fw, &z) == FLIGHT_FULL);
    kl = NAME("z%d.zone.example", 0);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_ZONE(3)), NULL, &z) == FLIGHT_OPENED);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_ZONE(3)), &it[2].fw, &z) == FLIGHT_JOINED);
    CHECK(flight_waiting(&fl) == 2);
    /* A UDP query opening a flight is parked on it too: past the parked caps it opens none,
     * and holds no slot. A TCP one isn't capped. */
    kl = NAME("d%d.example.org", 9);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), &it[5].fw, &z) == FLIGHT_FULL && z < 0);
    CHECK(fl.held[FLIGHT_GROUP_DEFAULT] == 1 && fl.parked[FLIGHT_GROUP_DEFAULT] == 1);
    fake_tcp_init(&t, buf, sizeof(buf));
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), &t.t.w, &z) == FLIGHT_OPENED);
    CHECK(fl.held[FLIGHT_GROUP_DEFAULT] == 2 && flight_waiting(&fl) == 2);
    CHECK(flight_end(&fl, z, NULL, -1) == NULL && t.wakes == 1 && t.t.len == -1);
    flight_free(&fl, z);
    kl = NAME("z%d.zone.example", 1);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_ZONE(4)), NULL, &z) == FLIGHT_OPENED);
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUP_ZONE(4)), &it[3].fw, &slot) == FLIGHT_FULL);
    /* A group out of range is never opened. */
    CHECK(begin(&fl, fq(k, kl, DNS_T_A, false, FLIGHT_GROUPS), NULL, &slot) == FLIGHT_FULL);
#undef NAME
    /* The node's sizes: the waiters at most half the UDP queue; the board's slots. */
    CHECK(MP_FLIGHT_WAITERS < MP_UDP_QUEUE);
    sem_destroy(&t.sem);
}

/* What the table counts (#53 part 4, for /metrics and "forwarders slow"): the slots each group
 * holds and in all, the most at once, and when the default forwarders went past half their
 * cap; a group's cap and that level from the table's size (memory.fwd_pending). */
/* Opens or joins c<i>.example.org's flight (A, IN) in group at now_ms, one forwarder, a
 * 400 ms wait. */
static flight_role_t open_at(flights_t *fl, int group, int i, uint32_t now_ms, flight_waiter_t *w, int *slot)
{
    static const uint32_t server = 0x0100007f;
    uint8_t k[DNS_MAX_NAME];
    char s[48];
    snprintf(s, sizeof(s), "c%d.example.org", i);
    flight_query_t q = { .qname = k, .qlen = N(s, k), .qtype = DNS_T_A, .qclass = DNS_C_IN, .group = group,
                         .servers = &server, .nservers = 1, .timeout_ms = 100 };
    uint32_t d;
    return flight_begin(fl, &q, w, now_ms, 400, slot, &d);
}

static void test_flight_counts(void)
{
    static flights_t fl;
    flight_counts_t c;
    CHECK(flight_group_cap(32) == 16 && flight_busy_level(32) == 8);
    CHECK(flight_group_cap(8) == 4 && flight_busy_level(8) == 2);
    CHECK(flight_group_cap(2) == 1 && flight_busy_level(2) == 1);
    flights_init(&fl, s_fl_mem, 8, 8);
    flight_counts(&fl, &c);
    CHECK(c.slots == 8 && c.group_cap == 4 && c.held_all == 0 && c.peak == 0 && !c.busy && flight_waiting(&fl) == 0);
    int slots[8], z;
    fake_item_t it = { .id = 1 };
#define OPEN(...) open_at(&fl, __VA_ARGS__)
    /* Two default flights: at the busy level (2 of 8), not past it. */
    CHECK(OPEN(FLIGHT_GROUP_DEFAULT, 0, 1000, NULL, &slots[0]) == FLIGHT_OPENED);
    CHECK(flight_slot(&fl, slots[0])->opened_ms == 1000);
    CHECK(OPEN(FLIGHT_GROUP_DEFAULT, 1, 1100, NULL, &slots[1]) == FLIGHT_OPENED);
    flight_counts(&fl, &c);
    CHECK(c.held[FLIGHT_GROUP_DEFAULT] == 2 && c.held_all == 2 && c.peak == 2 && !c.busy);
    /* A third: busy from when it opened. Zones' flights don't make the default busy. */
    CHECK(OPEN(FLIGHT_GROUP_ZONE(2), 2, 1150, NULL, &slots[2]) == FLIGHT_OPENED);
    CHECK(OPEN(FLIGHT_GROUP_ZONE(2), 3, 1160, NULL, &slots[3]) == FLIGHT_OPENED);
    CHECK(OPEN(FLIGHT_GROUP_ZONE(5), 4, 1170, NULL, &slots[4]) == FLIGHT_OPENED);
    flight_counts(&fl, &c);
    CHECK(!c.busy && c.zones_held == 3 && c.held[FLIGHT_GROUP_ZONE(2)] == 2 && c.held[FLIGHT_GROUP_ZONE(5)] == 1);
    CHECK(OPEN(FLIGHT_GROUP_DEFAULT, 5, 1200, &it.fw, &slots[5]) == FLIGHT_OPENED);
    flight_counts(&fl, &c);
    CHECK(c.busy && c.busy_since_ms == 1200 && c.held_all == 6 && c.peak == 6 && flight_waiting(&fl) == 1);
    /* A fourth, still busy: since the first time past it. */
    CHECK(OPEN(FLIGHT_GROUP_DEFAULT, 6, 1300, NULL, &slots[6]) == FLIGHT_OPENED);
    flight_counts(&fl, &c);
    CHECK(c.busy && c.busy_since_ms == 1200 && c.peak == 7);
    /* Shed (the default's cap of 4): nothing counted. */
    CHECK(OPEN(FLIGHT_GROUP_DEFAULT, 7, 1400, NULL, &z) == FLIGHT_FULL);
    flight_counts(&fl, &c);
    CHECK(c.held_all == 7 && c.peak == 7);
    /* Ended isn't freed: still held. Freed down to the level: no longer busy. */
    flight_end(&fl, slots[6], NULL, -1);
    flight_counts(&fl, &c);
    CHECK(c.busy && c.held_all == 7);
    flight_free(&fl, slots[6]);
    flight_counts(&fl, &c);
    CHECK(c.busy && c.held[FLIGHT_GROUP_DEFAULT] == 3); /* still past 2 */
    CHECK(list_ids(flight_free(&fl, slots[5]), (int[1]){ 0 }, 1) == 1); /* failed: its query back */
    flight_counts(&fl, &c);
    CHECK(!c.busy && c.held_all == 5 && c.peak == 7 && flight_waiting(&fl) == 0);
    /* Past it again later: busy from then. */
    CHECK(OPEN(FLIGHT_GROUP_DEFAULT, 8, 5000, NULL, &slots[5]) == FLIGHT_OPENED);
    flight_counts(&fl, &c);
    CHECK(c.busy && c.busy_since_ms == 5000);
    for (int i = 0; i < 6; i++)
        flight_free(&fl, slots[i]);
    flight_counts(&fl, &c);
    CHECK(!c.busy && c.held_all == 0 && c.zones_held == 0 && c.peak == 7);
#undef OPEN
}

/* The budget expiring (issue #53, test 6): at the flight's deadline it ends as failed, every
 * waiter with it: the parked ones handed back for SERVFAIL, the TCP ones woken with none. */
static void test_flight_expiry(void)
{
    static flights_t fl;
    flights_init(&fl, s_fl_mem, 8, MP_FLIGHT_WAITERS);
    uint8_t b[256], buf[64];
    int bl = N("other.example.org", b), slot, s2, ids[8];
    fake_item_t it[8];
    for (int i = 0; i < 8; i++)
        it[i].id = i, it[i].fw.wake = NULL;
    fake_tcp_t t;
    fake_tcp_init(&t, buf, sizeof(buf));
    uint32_t d;
    flight_query_t q = fq(b, bl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT);
    CHECK(flight_begin(&fl, &q, NULL, 1000, 1500, &slot, &d) == FLIGHT_OPENED);
    /* No one waits: no deadline to keep (the owner's own query keeps to its budget). */
    CHECK(!flight_next_deadline(&fl, &d));
    /* Joiners take the flight's deadline, whenever they come and whatever their own wait. */
    CHECK(flight_begin(&fl, &q, &it[6].fw, 1000, 1500, &s2, &d) == FLIGHT_JOINED && d == 2500);
    CHECK(flight_begin(&fl, &q, &t.t.w, 1800, 1500, &s2, &d) == FLIGHT_JOINED && d == 2500);
    CHECK(flight_begin(&fl, &q, &it[7].fw, 2000, 9000, &s2, &d) == FLIGHT_JOINED && d == 2500);
    CHECK(flight_next_deadline(&fl, &d) && d == 2500);
    CHECK(flight_expire(&fl, 2499) == NULL && !flight_tcp_done(&t.t));
    CHECK(list_ids(flight_expire(&fl, 2500), ids, 8) == 2 && ids[0] == 6 && ids[1] == 7);
    CHECK(flight_tcp_done(&t.t) && t.t.len == -1 && t.wakes == 1);
    CHECK(flight_waiting(&fl) == 0 && !flight_next_deadline(&fl, &d) && flight_expire(&fl, 999999) == NULL);
    /* The owner's answer, late: no one is left to answer. A new query asks again. */
    static const uint8_t ans[] = "late";
    CHECK(flight_end(&fl, slot, ans, sizeof(ans)) == NULL && flight_free(&fl, slot) == NULL);
    CHECK(flight_begin(&fl, &q, &it[0].fw, 2600, 1500, &slot, &d) == FLIGHT_OPENED && d == 4100);
    /* Expired while the owner still asks: a query after that opens a new flight. */
    CHECK(flight_begin(&fl, &q, &it[1].fw, 2600, 1500, &s2, &d) == FLIGHT_JOINED);
    CHECK(list_ids(flight_expire(&fl, 4100), ids, 8) == 2 && ids[0] == 0 && ids[1] == 1);
    CHECK(flight_begin(&fl, &q, &it[2].fw, 4100, 1500, &s2, &d) == FLIGHT_OPENED && s2 != slot);
    flight_free(&fl, slot);
    flight_free(&fl, s2);
    /* Only the flights past their deadline. */
    uint8_t c[256];
    int cl = N("third.example.org", c);
    flight_query_t q2 = fq(c, cl, DNS_T_A, false, FLIGHT_GROUP_ZONE(2));
    int s3, junk;
    CHECK(flight_begin(&fl, &q, NULL, 0, 100, &slot, &d) == FLIGHT_OPENED);
    CHECK(flight_begin(&fl, &q, &it[0].fw, 0, 100, &junk, &d) == FLIGHT_JOINED);
    CHECK(flight_begin(&fl, &q2, NULL, 50, 100, &s3, &d) == FLIGHT_OPENED);
    CHECK(flight_begin(&fl, &q2, &it[1].fw, 50, 100, &junk, &d) == FLIGHT_JOINED);
    CHECK(list_ids(flight_expire(&fl, 120), ids, 8) == 1 && ids[0] == 0);
    CHECK(flight_next_deadline(&fl, &d) && d == 150);
    CHECK(list_ids(flight_expire(&fl, 150), ids, 8) == 1 && ids[0] == 1);
    CHECK(fl.zones_parked == 0 && fl.parked[FLIGHT_GROUP_DEFAULT] == 0 && flight_waiting(&fl) == 0);
    flight_free(&fl, slot);
    flight_free(&fl, s3);
    CHECK(fl.zones_held == 0 && fl.held[FLIGHT_GROUP_DEFAULT] == 0);
    /* Deadlines across the ms counter's wrap. */
    CHECK(flight_begin(&fl, &q, NULL, UINT32_MAX - 20, 110, &slot, &d) == FLIGHT_OPENED);
    CHECK(flight_begin(&fl, &q, &it[0].fw, UINT32_MAX - 10, 100, &s2, &d) == FLIGHT_JOINED && d == 89);
    CHECK(flight_expire(&fl, UINT32_MAX) == NULL);
    CHECK(flight_expire(&fl, 88) == NULL);
    CHECK(list_ids(flight_expire(&fl, 89), ids, 8) == 1);
    flight_free(&fl, slot);
    sem_destroy(&t.sem);
}

/* A TCP waiter giving up races cleanly with its flight ending (issue #53, test 7): exactly
 * one of them happens, and the table never touches the waiter after either. Each waiter is
 * on the heap and freed the moment its query is done with, so a late copy or wake into it is
 * a use after free under ASan. */
typedef struct {
    flights_t fl;
    pthread_barrier_t go;
    int answered, cancelled; /* rounds the waiter saw its flight end, or took itself off */
} fl_race_t;

static const uint8_t s_race_ans[200] = { 1, 2, 3 };

static void *fl_race_tcp(void *p)
{
    fl_race_t *h = p;
    uint8_t n[256];
    int nl = N("popular.example.org", n), slot;
    for (int r = 0; r < 2000; r++) {
        pthread_barrier_wait(&h->go); /* the flight is open */
        uint8_t *buf = malloc(256);
        fake_tcp_t *t = malloc(sizeof(*t));
        fake_tcp_init(t, buf, 256);
        CHECK(begin(&h->fl, fq(n, nl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), &t->t.w, &slot) == FLIGHT_JOINED);
        pthread_barrier_wait(&h->go); /* joined: the owner may end it */
        /* Wait a little (as the worker waits to its deadline), sometimes not at all. */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += (r % 7) * 10000;
        if (ts.tv_nsec >= 1000000000)
            ts.tv_sec++, ts.tv_nsec -= 1000000000;
        if (r % 5 == 4) {
            /* As server.c's TCP worker: it watches flight_tcp_done (it may wake from its
             * timeout just as the flight ends), and on either outcome finishes with
             * flight_cancel, never waiting for the wake. Seeing done alone isn't the end:
             * the wake may still be under way (it reads the waiter), so freeing it before
             * flight_cancel returns is a use after free. */
            for (int spin = (r * 13) % 2000; spin > 0 && !flight_tcp_done(&t->t); spin--)
                __asm__ __volatile__("" ::: "memory");
            if (flight_cancel(&h->fl, &t->t)) {
                CHECK(!flight_tcp_done(&t->t) && t->t.len == -1 && t->wakes == 0);
                h->cancelled++;
            } else {
                CHECK(flight_tcp_done(&t->t) && t->wakes == 1);
            }
        } else if (r % 3 == 0 || sem_timedwait(&t->sem, &ts) != 0) {
            if (flight_cancel(&h->fl, &t->t)) {
                CHECK(!flight_tcp_done(&t->t) && t->t.len == -1 && t->wakes == 0);
                h->cancelled++;
            } else {
                sem_wait(&t->sem); /* its wake came, or is coming */
            }
        }
        if (flight_tcp_done(&t->t)) {
            /* The owner ends odd rounds with the answer, even ones by the deadline. */
            CHECK(t->wakes == 1);
            if (r % 2)
                CHECK(t->t.len == (int)sizeof(s_race_ans) && !memcmp(buf, s_race_ans, sizeof(s_race_ans)));
            else
                CHECK(t->t.len == -1);
            h->answered++;
        }
        sem_destroy(&t->sem);
        free(buf);
        free(t);
        pthread_barrier_wait(&h->go); /* done with this round */
    }
    return NULL;
}

static void test_flight_cancel_race(void)
{
    static fl_race_t h;
    flights_init(&h.fl, s_fl_mem, 8, MP_FLIGHT_WAITERS);
    pthread_barrier_init(&h.go, NULL, 2);
    h.answered = h.cancelled = 0;
    pthread_t th;
    pthread_create(&th, NULL, fl_race_tcp, &h);
    uint8_t n[256];
    int nl = N("popular.example.org", n), slot;
    for (int r = 0; r < 2000; r++) {
        CHECK(begin(&h.fl, fq(n, nl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT), NULL, &slot) == FLIGHT_OPENED);
        pthread_barrier_wait(&h.go);
        pthread_barrier_wait(&h.go);
        for (int spin = (r * 37) % 3000; spin > 0; spin--)
            __asm__ __volatile__("" ::: "memory");
        /* Ended by its answer, or by its deadline. */
        if (r % 2)
            CHECK(flight_end(&h.fl, slot, s_race_ans, sizeof(s_race_ans)) == NULL);
        else
            CHECK(flight_expire(&h.fl, 2500) == NULL);
        pthread_barrier_wait(&h.go);
        flight_free(&h.fl, slot);
    }
    pthread_join(th, NULL);
    pthread_barrier_destroy(&h.go);
    CHECK(h.answered + h.cancelled == 2000);
    CHECK(h.answered > 0 && h.cancelled > 0);
    for (int i = 0; i < h.fl.n; i++)
        CHECK(h.fl.f[i].state == FLIGHT_FREE);
}

/* The table's protocol on threads: queries for one question arrive at once; one opens the
 * flight, every one parks on it (the opener too), and all are answered from its one upstream
 * answer, or its failure. */
typedef struct {
    flights_t fl;
    pthread_barrier_t go;
    int upstream; /* queries sent upstream */
    bool fail;    /* the upstream gives no answer */
    uint16_t qtype[16];
    int answer[16]; /* per query: 0 none yet, 1 an answer, -1 SERVFAIL */
    fake_item_t it[16];
} fl_harness_t;

typedef struct {
    fl_harness_t *h;
    int i;
} fl_arg_t;

static void *fl_query(void *p)
{
    fl_arg_t *a = p;
    fl_harness_t *h = a->h;
    uint8_t n[256];
    int nl = N("popular.example.org", n), slot;
    pthread_barrier_wait(&h->go);
    flight_role_t r = begin(&h->fl, fq(n, nl, h->qtype[a->i], false, FLIGHT_GROUP_DEFAULT), &h->it[a->i].fw, &slot);
    if (r == FLIGHT_JOINED)
        return NULL; /* parked: the worker is free */
    CHECK(r == FLIGHT_OPENED);
    usleep(100 * 1000); /* the forwarder takes its time */
    __atomic_fetch_add(&h->upstream, 1, __ATOMIC_RELAXED);
    int res = h->fail ? -1 : 1;
    static const uint8_t ans[] = "x";
    for (flight_waiter_t *w = flight_end(&h->fl, slot, ans, h->fail ? -1 : (int)sizeof(ans)); w; w = w->next)
        __atomic_store_n(&h->answer[((fake_item_t *)w)->id], res, __ATOMIC_RELEASE);
    flight_free(&h->fl, slot);
    return NULL;
}

static void fl_run(fl_harness_t *h, int n)
{
    pthread_t t[16];
    fl_arg_t a[16];
    flights_init(&h->fl, s_fl_mem, 32, MP_FLIGHT_WAITERS);
    pthread_barrier_init(&h->go, NULL, (unsigned)n);
    h->upstream = 0;
    for (int i = 0; i < n; i++) {
        h->it[i].id = i;
        h->it[i].fw.wake = NULL;
        h->answer[i] = 0;
        a[i] = (fl_arg_t){ h, i };
        pthread_create(&t[i], NULL, fl_query, &a[i]);
    }
    for (int i = 0; i < n; i++)
        pthread_join(t[i], NULL);
    pthread_barrier_destroy(&h->go);
}

static void test_flights_threads(void)
{
    static fl_harness_t h;
    /* Coalescing: eight queries at once, one upstream query, eight answers. */
    for (int i = 0; i < 8; i++)
        h.qtype[i] = DNS_T_A;
    h.fail = false;
    fl_run(&h, 8);
    CHECK(h.upstream == 1);
    for (int i = 0; i < 8; i++)
        CHECK(h.answer[i] == 1);
    CHECK(flight_waiting(&h.fl) == 0);
    /* The failure path: the one upstream query fails, every query is answered SERVFAIL. */
    h.fail = true;
    fl_run(&h, 8);
    CHECK(h.upstream == 1);
    for (int i = 0; i < 8; i++)
        CHECK(h.answer[i] == -1);
    /* A and AAAA of the same name: two upstream queries, four answers each. */
    h.fail = false;
    for (int i = 0; i < 8; i++)
        h.qtype[i] = i % 2 ? DNS_T_AAAA : DNS_T_A;
    fl_run(&h, 8);
    CHECK(h.upstream == 2);
    for (int i = 0; i < 8; i++)
        CHECK(h.answer[i] == 1);
}

/* ---- fake forwarders on the loopback (forward.c asks DNS2_FWD_PORT, the Makefile's) ---- */

typedef enum {
    FAKE_ANSWER,    /* answers each query */
    FAKE_SILENT,    /* reads each query and answers nothing: a forwarder that is down */
    FAKE_STRAYS,    /* answers nothing, and sends the asker a datagram from another port
                     * every 20 ms, for a second after its last query: strays a try's wait
                     * must not restart on */
    FAKE_TRUNCATE,  /* answers truncated; its TCP port takes connections and never answers */
    FAKE_TCP,       /* answers truncated; answers over TCP, tcp_len bytes */
    FAKE_UDP_BIG,   /* answers with 1400 bytes, more than a slot holds; over TCP as FAKE_TCP */
    FAKE_SERVFAIL,  /* answers SERVFAIL */
    FAKE_WRONG_ID,  /* answers from the right address and port, with another ID */
    FAKE_RECORD,    /* answers with an A record (192.0.2.1, TTL 300): an answer to cache */
} fake_fwd_mode_t;

typedef struct {
    fake_fwd_mode_t mode;
    uint32_t addr; /* network order, 127.0.0.x */
    int udp, tcp, stray;
    bool stop;
    int queries, tcp_queries;
    size_t tcp_len; /* FAKE_TCP, FAKE_UDP_BIG: the TCP answer's length, padded (at least the query's) */
    bool tcp_wrong_name; /* FAKE_TCP: the TCP answer's question names another name */
    pthread_t th;
} fake_fwd_t;

static uint32_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

static uint32_t loopback(int x) { return htonl(0x7f000000u | (uint32_t)x); }

static int fake_sock(int type, uint32_t addr, uint16_t port)
{
    int s = socket(AF_INET, type, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = addr };
    if (s < 0 || bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("fake forwarder: bind");
        exit(1);
    }
    return s;
}

/* One TCP query, if a connection waits: answered with the query as a response, padded to
 * f->tcp_len. */
static void fake_fwd_tcp(fake_fwd_t *f)
{
    int c = accept(f->tcp, NULL, NULL);
    if (c < 0)
        return;
    fcntl(c, F_SETFL, fcntl(c, F_GETFL, 0) & ~O_NONBLOCK);
    struct timeval tv = { .tv_sec = 1 };
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    uint8_t *m = malloc(2 + 65535), lp[2];
    if (m && tcp_read_full(c, lp, 2) && rd16(lp) >= DNS_HDR_LEN && tcp_read_full(c, m + 2, rd16(lp))) {
        size_t n = rd16(lp), want = __atomic_load_n(&f->tcp_len, __ATOMIC_RELAXED), len = want > n ? want : n;
        memset(m + 2 + n, 0, len - n);
        wr16(m + 4, (uint16_t)(DNS_F_QR | DNS_F_RD | DNS_F_RA));
        if (__atomic_load_n(&f->tcp_wrong_name, __ATOMIC_RELAXED))
            m[2 + DNS_HDR_LEN + 1] ^= 1; /* the first label's first letter */
        wr16(m, (uint16_t)len);
        __atomic_add_fetch(&f->tcp_queries, 1, __ATOMIC_RELAXED);
        tcp_write_full(c, m, len + 2);
    }
    free(m);
    close(c);
}

static void *fake_fwd_run(void *p)
{
    fake_fwd_t *f = p;
    struct timeval tv = { .tv_usec = (f->mode == FAKE_TCP || f->mode == FAKE_UDP_BIG ? 2 : 20) * 1000 };
    setsockopt(f->udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in asker = { 0 };
    bool asked = false;
    uint32_t last = 0;
    while (!__atomic_load_n(&f->stop, __ATOMIC_ACQUIRE)) {
        uint8_t m[512];
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(f->udp, m, sizeof(m), 0, (struct sockaddr *)&from, &fl);
        if (n >= DNS_HDR_LEN) {
            __atomic_add_fetch(&f->queries, 1, __ATOMIC_RELAXED);
            asker = from;
            asked = true;
            last = mono_ms();
            bool tc = f->mode == FAKE_TRUNCATE || f->mode == FAKE_TCP;
            if (f->mode != FAKE_SILENT && f->mode != FAKE_STRAYS) {
                /* The question as asked, as a response: what fwd_query takes for the answer. */
                wr16(m + 2, (uint16_t)(DNS_F_QR | DNS_F_RD | DNS_F_RA | (tc ? DNS_F_TC : 0) |
                                       (f->mode == FAKE_SERVFAIL ? DNS_R_SERVFAIL : 0)));
                if (f->mode == FAKE_WRONG_ID)
                    wr16(m, (uint16_t)(rd16(m) + 1));
                uint8_t big[1400];
                if (f->mode == FAKE_UDP_BIG) {
                    memset(big, 0, sizeof(big));
                    memcpy(big, m, (size_t)n);
                }
                if (f->mode == FAKE_RECORD) {
                    /* The question, then one A record; the OPT dropped. */
                    size_t q = DNS_HDR_LEN;
                    while (q < (size_t)n && m[q])
                        q += 1u + m[q];
                    q += 1 + 4;
                    static const uint8_t rr[] = { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1 };
                    if (q + sizeof(rr) <= sizeof(m)) {
                        memcpy(m + q, rr, sizeof(rr));
                        n = (ssize_t)(q + sizeof(rr));
                        wr16(m + 6, 1);
                        wr16(m + 10, 0);
                    }
                }
                sendto(f->udp, f->mode == FAKE_UDP_BIG ? big : m, f->mode == FAKE_UDP_BIG ? sizeof(big) : (size_t)n, 0,
                       (struct sockaddr *)&from, fl);
            }
        }
        if (f->mode == FAKE_TCP || f->mode == FAKE_UDP_BIG)
            fake_fwd_tcp(f);
        if (f->mode == FAKE_STRAYS && asked && mono_ms() - last < 1000) {
            uint8_t junk[DNS_HDR_LEN] = { 0 };
            sendto(f->stray, junk, sizeof(junk), 0, (struct sockaddr *)&asker, sizeof(asker));
        }
    }
    return NULL;
}

static void fake_fwd_start(fake_fwd_t *f, fake_fwd_mode_t mode, int x)
{
    memset(f, 0, sizeof(*f));
    f->mode = mode;
    f->addr = loopback(x);
    f->udp = fake_sock(SOCK_DGRAM, f->addr, DNS2_FWD_PORT);
    f->tcp = f->stray = -1;
    if (mode == FAKE_TRUNCATE || mode == FAKE_TCP || mode == FAKE_UDP_BIG) {
        f->tcp = fake_sock(SOCK_STREAM, f->addr, DNS2_FWD_PORT);
        listen(f->tcp, 8); /* FAKE_TRUNCATE: connections complete in the backlog, never accepted */
        fcntl(f->tcp, F_SETFL, fcntl(f->tcp, F_GETFL, 0) | O_NONBLOCK);
    }
    if (mode == FAKE_STRAYS)
        f->stray = fake_sock(SOCK_DGRAM, f->addr, 0);
    pthread_create(&f->th, NULL, fake_fwd_run, f);
}

static void fake_fwd_stop(fake_fwd_t *f)
{
    __atomic_store_n(&f->stop, true, __ATOMIC_RELEASE);
    pthread_join(f->th, NULL);
    close(f->udp);
    if (f->tcp >= 0)
        close(f->tcp);
    if (f->stray >= 0)
        close(f->stray);
}

/* fwd_query for popular.example.org A; *ms how long it took. */
static int ask_up(const uint32_t *servers, int nservers, int timeout_ms, uint32_t *ms)
{
    uint8_t n[256], out[1232];
    int nl = N("popular.example.org", n);
    uint32_t t = mono_ms();
    int rl = fwd_query(servers, nservers, n, nl, DNS_T_A, DNS_C_IN, false, out, sizeof(out), timeout_ms);
    *ms = mono_ms() - t;
    return rl;
}

/* The leader's whole attempt (forward.h): a parked query waits through every forwarder and
 * retry, not one upstream timeout. Queries for one question at once, two forwarders on the
 * loopback: the first is down, so the leader's fwd_query waits out its timeout there and has
 * the answer from the second; the flight's deadline is the one server.c gives it, and a
 * thread ends those past it (expire_waiters) on the clock. */
typedef struct {
    flights_t fl;
    pthread_barrier_t go;
    uint32_t servers[2];
    int nservers;
    uint32_t wait_ms;   /* the flight's wait, from when it opens */
    int timeout_ms;     /* the leader's per-try timeout */
    int leader_rl;      /* what the leader's fwd_query returned */
    uint32_t leader_ms; /* ...and how long it took */
    volatile bool done; /* the expiry thread stops */
    int answer[8];      /* 0 none yet, 1 the leader's answer, -1 SERVFAIL (expired) */
    fake_item_t it[8];
} fl_retry_t;

typedef struct {
    fl_retry_t *h;
    int i;
} fl_retry_arg_t;

static void *fl_retry_query(void *p)
{
    fl_retry_arg_t *a = p;
    fl_retry_t *h = a->h;
    uint8_t n[256];
    int nl = N("popular.example.org", n), slot;
    flight_role_t r = FLIGHT_FULL;
    flight_query_t q = fq(n, nl, DNS_T_A, false, FLIGHT_GROUP_DEFAULT);
    uint32_t d;
    if (a->i == 0) /* the leader first, the others once it has opened the flight */
        r = flight_begin(&h->fl, &q, &h->it[0].fw, mono_ms(), h->wait_ms, &slot, &d);
    pthread_barrier_wait(&h->go);
    if (a->i) {
        r = flight_begin(&h->fl, &q, &h->it[a->i].fw, mono_ms(), h->wait_ms, &slot, &d);
        CHECK(r == FLIGHT_JOINED);
        return NULL;
    }
    CHECK(r == FLIGHT_OPENED);
    h->leader_rl = ask_up(h->servers, h->nservers, h->timeout_ms, &h->leader_ms);
    int got = h->leader_rl > 0 ? 1 : -1;
    static const uint8_t ans[] = "x";
    for (flight_waiter_t *w = flight_end(&h->fl, slot, ans, got > 0 ? (int)sizeof(ans) : -1); w; w = w->next)
        __atomic_store_n(&h->answer[((fake_item_t *)w)->id], got, __ATOMIC_RELEASE);
    flight_free(&h->fl, slot);
    return NULL;
}

static void *fl_retry_expiry(void *p)
{
    fl_retry_t *h = p;
    while (!h->done) {
        for (flight_waiter_t *w = flight_expire(&h->fl, mono_ms()); w; w = w->next)
            __atomic_store_n(&h->answer[((fake_item_t *)w)->id], -1, __ATOMIC_RELEASE);
        usleep(2 * 1000);
    }
    return NULL;
}

static void fl_retry_run(fl_retry_t *h, int n)
{
    pthread_t t[8], ex;
    fl_retry_arg_t a[8];
    flights_init(&h->fl, s_fl_mem, 32, MP_FLIGHT_WAITERS);
    pthread_barrier_init(&h->go, NULL, (unsigned)n);
    h->done = false;
    h->leader_rl = 0;
    pthread_create(&ex, NULL, fl_retry_expiry, h);
    for (int i = 0; i < n; i++) {
        h->it[i].id = i;
        h->it[i].fw.wake = NULL;
        h->answer[i] = 0;
        a[i] = (fl_retry_arg_t){ h, i };
        pthread_create(&t[i], NULL, fl_retry_query, &a[i]);
    }
    for (int i = 0; i < n; i++)
        pthread_join(t[i], NULL);
    h->done = true;
    pthread_join(ex, NULL);
    pthread_barrier_destroy(&h->go);
}

static void test_flights_retry(void)
{
    /* The budget: each forwarder FWD_TRIES_PER_SERVER times at the timeout, one TCP retry at
     * FWD_TCP_TIMEOUT_MUL times it, and the margin. */
    CHECK(FWD_TRIES_PER_SERVER == 2 && FWD_TCP_TIMEOUT_MUL == 2);
    CHECK(fwd_budget_ms(1, 1500) == 2 * 1500 + 2 * 1500);
    CHECK(fwd_budget_ms(2, 1500) == 4 * 1500 + 2 * 1500);
    CHECK(flight_wait_ms(2, 1500) == 9000 + FLIGHT_WAIT_MARGIN_MS);
    CHECK(flight_wait_ms(0, 100) == flight_wait_ms(1, 100)); /* never below one forwarder's */
    CHECK(flight_wait_ms(CFG_MAX_FWD, 10000) == (uint32_t)CFG_MAX_FWD * 2 * 10000 + 2 * 10000 + FLIGHT_WAIT_MARGIN_MS);

    fake_fwd_t down, up;
    fake_fwd_start(&down, FAKE_SILENT, 2);
    fake_fwd_start(&up, FAKE_ANSWER, 1);
    static fl_retry_t h;
    h.timeout_ms = 100;
    h.servers[0] = down.addr;
    h.servers[1] = up.addr;
    h.nservers = 2;
    /* Parked for the leader's whole attempt: the first forwarder timing out fails no one,
     * every query is answered from the second's answer. */
    h.wait_ms = flight_wait_ms(h.nservers, h.timeout_ms);
    fl_retry_run(&h, 6);
    CHECK(h.leader_rl > 0 && h.leader_ms >= (uint32_t)h.timeout_ms - 5); /* the first was waited out */
    CHECK(__atomic_load_n(&down.queries, __ATOMIC_RELAXED) == 1 && __atomic_load_n(&up.queries, __ATOMIC_RELAXED) == 1);
    for (int i = 0; i < 6; i++)
        CHECK(h.answer[i] == 1);
    CHECK(flight_waiting(&h.fl) == 0);
    /* A flight whose deadline comes within the first try: it expired, every waiter (the
     * opener's own query too) answered SERVFAIL, while the upstream query went on to the
     * second forwarder and got an answer no one was left for. */
    h.wait_ms = (uint32_t)h.timeout_ms / 2;
    fl_retry_run(&h, 6);
    CHECK(h.leader_rl > 0);
    for (int i = 0; i < 6; i++)
        CHECK(h.answer[i] == -1);
    CHECK(flight_waiting(&h.fl) == 0);
    fake_fwd_stop(&down);
    fake_fwd_stop(&up);

    /* fwd_query keeps to its budget, whatever the forwarders do, so a parked query's wait
     * covers it. Both truncate and never answer over TCP: a TCP retry on each of the four
     * tries, more than the one counted (each alone would take FWD_TCP_TIMEOUT_MUL times the
     * timeout, 800 ms in all). */
    uint32_t ms;
    fake_fwd_t tc1, tc2;
    fake_fwd_start(&tc1, FAKE_TRUNCATE, 3);
    fake_fwd_start(&tc2, FAKE_TRUNCATE, 4);
    uint32_t tcs[2] = { tc1.addr, tc2.addr };
    CHECK(ask_up(tcs, 2, 100, &ms) == -1);
    CHECK(ms + 20 >= fwd_budget_ms(2, 100) && ms <= fwd_budget_ms(2, 100) + 100);
    fake_fwd_stop(&tc1);
    fake_fwd_stop(&tc2);
    /* Strays every 20 ms don't restart a try's wait: two tries at the timeout, not as long
     * as the strays go on. */
    fake_fwd_t st;
    fake_fwd_start(&st, FAKE_STRAYS, 5);
    CHECK(ask_up(&st.addr, 1, 100, &ms) == -1);
    CHECK(ms + 20 >= 2 * 100 && ms <= 2 * 100 + 100);
    fake_fwd_stop(&st);
}

/* An upstream query whose socket select() couldn't watch (at or past FD_SETSIZE) fails at
 * the start, its socket closed, never handed to FD_SET. */
static void test_fwd_fd_setsize(void)
{
    struct rlimit was, rl;
    if (getrlimit(RLIMIT_NOFILE, &was) < 0 || was.rlim_max < FD_SETSIZE + 16) {
        printf("test_fwd_fd_setsize: skipped (RLIMIT_NOFILE)\n");
        return;
    }
    rl = was;
    rl.rlim_cur = FD_SETSIZE + 16;
    CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);
    static int fds[FD_SETSIZE];
    int n = 0;
    for (int d; n < FD_SETSIZE && (d = open("/dev/null", O_RDONLY)) >= 0;) {
        if (d >= FD_SETSIZE) {
            close(d);
            break;
        }
        fds[n++] = d;
    }
    uint8_t qn[DNS_MAX_NAME], out[512];
    int ql = N("fd.example.org", qn);
    uint32_t srv = loopback(24);
    fwd_up_t u;
    fwd_q_t fq = { .qname = qn, .qlen = ql, .qtype = DNS_T_A, .qclass = DNS_C_IN };
    fwd_up_init(&u, &srv, 1, 100);
    CHECK(fwd_up_start(&u, &fq, fwd_now_ms()) == FWD_FAILED && u.sock == -1);
    CHECK(fwd_query(&srv, 1, qn, ql, DNS_T_A, DNS_C_IN, false, out, sizeof(out), 100) == -1);
    int probe = open("/dev/null", O_RDONLY); /* the socket was closed: its number is free again */
    CHECK(probe >= FD_SETSIZE);
    if (probe >= 0)
        close(probe);
    while (n)
        close(fds[--n]);
    setrlimit(RLIMIT_NOFILE, &was);
}

/* ---- the forward loop (fwdq.h): every upstream query asked off the workers ---- */

/* A fake forwarder's count, as its thread keeps it. */
static int cnt(const int *n) { return __atomic_load_n(n, __ATOMIC_RELAXED); }

/* The loop and its TCP task on threads, as server.c runs them as tasks; done slots are
 * counted under a condition, for the tests to wait on. */
typedef struct {
    flights_t fl;
    fwdq_t q;
    pthread_t loop, tcp;
    pthread_mutex_t m;
    pthread_cond_t c;
    int dones;
    uint8_t tcp_buf[MP_FWD_TCP];
} fq_harness_t;

static void fqh_done(void *ctx)
{
    fq_harness_t *h = ctx;
    pthread_mutex_lock(&h->m);
    h->dones++;
    pthread_cond_broadcast(&h->c);
    pthread_mutex_unlock(&h->m);
}

static void *fqh_loop(void *p)
{
    fwdq_run(&((fq_harness_t *)p)->q);
    return NULL;
}

static void *fqh_tcp(void *p)
{
    fwdq_tcp_run(&((fq_harness_t *)p)->q);
    return NULL;
}

static fq_harness_t *fqh_start(int slots)
{
    fq_harness_t *h = calloc(1, sizeof(*h));
    pthread_mutex_init(&h->m, NULL);
    pthread_cond_init(&h->c, NULL);
    flights_init(&h->fl, s_fl_mem, slots, MP_FLIGHT_WAITERS);
    CHECK(fwdq_init(&h->q, &h->fl, h->tcp_buf, sizeof(h->tcp_buf), fqh_done, h));
    pthread_create(&h->loop, NULL, fqh_loop, h);
    pthread_create(&h->tcp, NULL, fqh_tcp, h);
    return h;
}

static void fqh_stop(fq_harness_t *h)
{
    fwdq_stop(&h->q);
    pthread_join(h->loop, NULL);
    pthread_join(h->tcp, NULL);
    fwdq_destroy(&h->q);
    pthread_mutex_destroy(&h->m);
    pthread_cond_destroy(&h->c);
    free(h);
}

/* A slot whose query is over, waiting at most wait_ms for one. */
static bool fqh_take(fq_harness_t *h, int *slot, const uint8_t **ans, int *len, uint32_t wait_ms)
{
    uint32_t end = mono_ms() + wait_ms;
    pthread_mutex_lock(&h->m);
    bool got;
    while (!(got = fwdq_take(&h->q, slot, ans, len)) && (int32_t)(end - mono_ms()) > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 5 * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&h->c, &h->m, &ts);
    }
    pthread_mutex_unlock(&h->m);
    return got;
}

/* Opens name's flight (A, IN) in group asking servers, with the waiter w (NULL: none), and
 * hands it to the loop; the role, *slot the slot opened. */
static flight_role_t fqh_ask(fq_harness_t *h, const char *name, int group, const uint32_t *servers, int n,
                             int timeout_ms, flight_waiter_t *w, int *slot)
{
    uint8_t qn[DNS_MAX_NAME];
    int ql = N(name, qn);
    flight_query_t q = { .qname = qn, .qlen = ql, .qtype = DNS_T_A, .qclass = DNS_C_IN, .group = group,
                         .servers = servers, .nservers = n, .timeout_ms = timeout_ms };
    uint32_t d;
    flight_role_t r = flight_begin(&h->fl, &q, w, fwd_now_ms(), flight_wait_ms(n, timeout_ms), slot, &d);
    if (r == FLIGHT_OPENED)
        fwdq_submit(&h->q, *slot);
    return r;
}

/* ans answers name (A, IN): a response with its question. */
static bool answers(const uint8_t *ans, int len, const char *name)
{
    uint8_t qn[DNS_MAX_NAME], got[DNS_MAX_NAME];
    int ql = N(name, qn);
    size_t pos = DNS_HDR_LEN;
    if (len < DNS_HDR_LEN || !(rd16(ans + 2) & DNS_F_QR) || rd16(ans + 4) != 1)
        return false;
    int gl = dns_name_read(ans, (size_t)len, &pos, got);
    return gl > 0 && dns_name_eq(got, gl, qn, ql) && rd16(ans + pos) == DNS_T_A;
}

/* What the observer was told (fwd_set_observer): each try's server, whether it answered and
 * how it ended. */
static struct {
    pthread_mutex_t m;
    int n;
    uint32_t server[16];
    bool ok[16];
    fwd_try_t how[16];
} s_obs = { .m = PTHREAD_MUTEX_INITIALIZER };

static void obs_record(uint32_t server, fwd_try_t how, uint32_t us)
{
    pthread_mutex_lock(&s_obs.m);
    if (s_obs.n < 16) {
        s_obs.server[s_obs.n] = server;
        s_obs.ok[s_obs.n] = how == FWD_TRY_ANSWER;
        s_obs.how[s_obs.n] = how;
    }
    s_obs.n++;
    pthread_mutex_unlock(&s_obs.m);
}

static void obs_reset(void)
{
    pthread_mutex_lock(&s_obs.m);
    s_obs.n = 0;
    pthread_mutex_unlock(&s_obs.m);
}

/* Issue #53, test 2: an answer completes its flight, to every query waiting on it. */
static void test_fwdq_complete(void)
{
    fake_fwd_t up;
    fake_fwd_start(&up, FAKE_ANSWER, 11);
    fq_harness_t *h = fqh_start(32);
    fake_item_t it[4];
    for (int i = 0; i < 4; i++)
        it[i] = (fake_item_t){ .id = i };
    uint8_t buf[2048];
    fake_tcp_t t;
    fake_tcp_init(&t, buf, sizeof(buf));
    int slot, s2, got, len, ids[8];
    const uint8_t *ans;
    /* The opener asks; the next three, and a TCP query, for the same question wait on it. */
    CHECK(fqh_ask(h, "popular.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 500, NULL, &slot) == FLIGHT_OPENED);
    for (int i = 1; i < 4; i++)
        CHECK(fqh_ask(h, "POPULAR.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 500, &it[i].fw, &s2) ==
              FLIGHT_JOINED);
    CHECK(fqh_ask(h, "popular.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 500, &t.t.w, &s2) == FLIGHT_JOINED);
    CHECK(fqh_take(h, &got, &ans, &len, 1000) && got == slot && answers(ans, len, "popular.example.org"));
    CHECK(ans == flight_slot(&h->fl, slot)->answer); /* it fits the slot */
    /* As a worker does: the flight ended with it, the waiters answered from it. */
    CHECK(list_ids(flight_end(&h->fl, got, ans, len), ids, 8) == 3 && ids[0] == 1 && ids[1] == 2 && ids[2] == 3);
    CHECK(flight_tcp_done(&t.t) && t.t.len == len && !memcmp(buf, ans, (size_t)len) && t.wakes == 1);
    CHECK(!flight_cancel(&h->fl, &t.t));
    CHECK(fwdq_release(&h->q, got) == NULL && flight_slot(&h->fl, slot)->state == FLIGHT_FREE);
    CHECK(cnt(&up.queries) == 1);
    CHECK(!fwdq_take(&h->q, &got, &ans, &len));

    /* Many at once, in both groups: each answered with its own question. */
    char names[24][32];
    int slots[24];
    for (int i = 0; i < 24; i++) {
        snprintf(names[i], sizeof(names[i]), "n%d.example.org", i);
        CHECK(fqh_ask(h, names[i], i % 2 ? FLIGHT_GROUP_ZONE(i % 3) : FLIGHT_GROUP_DEFAULT, &up.addr, 1, 500, NULL,
                      &slots[i]) == FLIGHT_OPENED);
    }
    for (int n = 0; n < 24; n++) {
        CHECK(fqh_take(h, &got, &ans, &len, 1000));
        int i = 0;
        while (i < 24 && slots[i] != got)
            i++;
        CHECK(i < 24 && answers(ans, len, names[i]));
        flight_end(&h->fl, got, ans, len);
        fwdq_release(&h->q, got);
    }
    CHECK(h->fl.held[FLIGHT_GROUP_DEFAULT] == 0 && h->fl.zones_held == 0 && flight_waiting(&h->fl) == 0);
    CHECK(cnt(&up.queries) == 25);
    fqh_stop(h);
    fake_fwd_stop(&up);
}

/* Issue #53, test 3: from a forwarder that doesn't answer to one that does, within the budget;
 * and a forwarder that doesn't answer holds up no other query. */
static void test_fwdq_failover(void)
{
    fake_fwd_t down, up, sf, down2;
    fake_fwd_start(&down, FAKE_SILENT, 12);
    fake_fwd_start(&up, FAKE_ANSWER, 13);
    fake_fwd_start(&sf, FAKE_SERVFAIL, 14);
    fake_fwd_start(&down2, FAKE_SILENT, 15);
    fq_harness_t *h = fqh_start(32);
    int slot, a, b, got, len;
    const uint8_t *ans;
    fwd_set_observer(obs_record);
    obs_reset();
    /* The first is silent: its try times out, the second answers. */
    uint32_t servers[2] = { down.addr, up.addr }, t0 = mono_ms();
    CHECK(fqh_ask(h, "a.example.org", FLIGHT_GROUP_DEFAULT, servers, 2, 100, NULL, &slot) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && got == slot && answers(ans, len, "a.example.org"));
    uint32_t ms = mono_ms() - t0;
    CHECK(ms + 5 >= 100 && ms < 100 + 150);
    CHECK(cnt(&down.queries) == 1 && cnt(&up.queries) == 1);
    CHECK(s_obs.n == 2 && s_obs.server[0] == down.addr && !s_obs.ok[0] && s_obs.server[1] == up.addr && s_obs.ok[1]);
    CHECK(s_obs.how[0] == FWD_TRY_TIMEOUT && s_obs.how[1] == FWD_TRY_ANSWER);
    fwdq_release(&h->q, got);
    /* A SERVFAIL goes on to the next at once. */
    obs_reset();
    servers[0] = sf.addr;
    t0 = mono_ms();
    CHECK(fqh_ask(h, "b.example.org", FLIGHT_GROUP_DEFAULT, servers, 2, 400, NULL, &slot) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && answers(ans, len, "b.example.org") && DNS_RCODE(rd16(ans + 2)) == 0);
    CHECK(mono_ms() - t0 < 200 && cnt(&sf.queries) == 1 && s_obs.n == 2 && !s_obs.ok[0] && s_obs.ok[1]);
    CHECK(s_obs.how[0] == FWD_TRY_SERVFAIL); /* not a timeout */
    fwdq_release(&h->q, got);
    /* A SERVFAIL on the last try is the answer. */
    CHECK(fqh_ask(h, "c.example.org", FLIGHT_GROUP_DEFAULT, &sf.addr, 1, 400, NULL, &slot) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && answers(ans, len, "c.example.org"));
    CHECK(DNS_RCODE(rd16(ans + 2)) == DNS_R_SERVFAIL && cnt(&sf.queries) == 3);
    fwdq_release(&h->q, got);
    /* Neither answers: every try, a, b, a, b, then failed, before the budget. */
    obs_reset();
    servers[0] = down.addr;
    servers[1] = down2.addr;
    t0 = mono_ms();
    CHECK(fqh_ask(h, "d.example.org", FLIGHT_GROUP_DEFAULT, servers, 2, 100, NULL, &slot) == FLIGHT_OPENED);
    /* Meanwhile another query, to the one that answers, is answered at once. */
    CHECK(fqh_ask(h, "e.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 100, NULL, &a) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && got == a && answers(ans, len, "e.example.org"));
    CHECK(mono_ms() - t0 < 50);
    fwdq_release(&h->q, got);
    CHECK(fqh_take(h, &b, &ans, &len, 2000) && b == slot && len == -1);
    ms = mono_ms() - t0;
    CHECK(ms + 5 >= 4 * 100 && ms < 4 * 100 + 150 && ms < fwd_budget_ms(2, 100));
    CHECK(cnt(&down.queries) == 3 && cnt(&down2.queries) == 2);
    CHECK(s_obs.n == 5); /* the four tries, and e's */
    pthread_mutex_lock(&s_obs.m);
    int timeouts = 0;
    for (int i = 0; i < 5; i++)
        timeouts += s_obs.how[i] == FWD_TRY_TIMEOUT;
    pthread_mutex_unlock(&s_obs.m);
    CHECK(timeouts == 4);
    fwdq_release(&h->q, b);
    fwd_set_observer(NULL);
    fqh_stop(h);
    fake_fwd_stop(&down);
    fake_fwd_stop(&up);
    fake_fwd_stop(&sf);
    fake_fwd_stop(&down2);
}

/* Issue #53, test 4: a truncated answer is asked again over TCP, one at a time into the TCP
 * buffer, which a big answer holds until its slot is given back. */
static void test_fwdq_tcp(void)
{
    fake_fwd_t tc, big, dead;
    fake_fwd_start(&tc, FAKE_TCP, 16);
    __atomic_store_n(&tc.tcp_len, 3000, __ATOMIC_RELAXED);
    fake_fwd_start(&big, FAKE_UDP_BIG, 17);
    __atomic_store_n(&big.tcp_len, 2000, __ATOMIC_RELAXED);
    fake_fwd_start(&dead, FAKE_TRUNCATE, 18);
    fq_harness_t *h = fqh_start(32);
    int x, y, got, got2, len, len2;
    const uint8_t *ans, *ans2;
    CHECK(fqh_ask(h, "x.example.org", FLIGHT_GROUP_DEFAULT, &tc.addr, 1, 300, NULL, &x) == FLIGHT_OPENED);
    CHECK(fqh_ask(h, "y.example.org", FLIGHT_GROUP_DEFAULT, &tc.addr, 1, 300, NULL, &y) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && (got == x || got == y) && len == 3000);
    CHECK(ans == h->tcp_buf && answers(ans, len, got == x ? "x.example.org" : "y.example.org"));
    /* The other's TCP retry waits for the buffer: not done while this answer is held. */
    CHECK(!fqh_take(h, &got2, &ans2, &len2, 150));
    CHECK(cnt(&tc.tcp_queries) == 1);
    uint32_t t0 = mono_ms();
    fwdq_release(&h->q, got);
    CHECK(fqh_take(h, &got2, &ans2, &len2, 2000) && got2 == (got == x ? y : x) && len2 == 3000);
    CHECK(answers(ans2, len2, got2 == x ? "x.example.org" : "y.example.org") && mono_ms() - t0 < 100);
    fwdq_release(&h->q, got2);
    CHECK(cnt(&tc.tcp_queries) == 2 && cnt(&tc.queries) == 2);
    /* A TCP answer that fits the slot is copied there: the buffer is free at once. */
    __atomic_store_n(&tc.tcp_len, 0, __ATOMIC_RELAXED);
    CHECK(fqh_ask(h, "x.example.org", FLIGHT_GROUP_DEFAULT, &tc.addr, 1, 300, NULL, &x) == FLIGHT_OPENED);
    CHECK(fqh_ask(h, "y.example.org", FLIGHT_GROUP_DEFAULT, &tc.addr, 1, 300, NULL, &y) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && ans == flight_slot(&h->fl, got)->answer);
    CHECK(fqh_take(h, &got2, &ans2, &len2, 2000) && ans2 == flight_slot(&h->fl, got2)->answer && got2 != got);
    CHECK(answers(ans, len, got == x ? "x.example.org" : "y.example.org"));
    fwdq_release(&h->q, got);
    fwdq_release(&h->q, got2);
    /* An answer bigger than the slot, not truncated, is asked over TCP too. */
    CHECK(fqh_ask(h, "z.example.org", FLIGHT_GROUP_DEFAULT, &big.addr, 1, 300, NULL, &x) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && got == x && len == 2000 && ans == h->tcp_buf);
    CHECK(answers(ans, len, "z.example.org") && cnt(&big.tcp_queries) == 1);
    fwdq_release(&h->q, got);
    /* A TCP answer with the right ID that answers another question is no answer: each try's
     * retry fails, and the query with them. */
    __atomic_store_n(&tc.tcp_wrong_name, true, __ATOMIC_RELAXED);
    CHECK(fqh_ask(h, "x.example.org", FLIGHT_GROUP_DEFAULT, &tc.addr, 1, 300, NULL, &x) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && got == x && len == -1);
    CHECK(cnt(&tc.tcp_queries) == 6 && cnt(&tc.queries) == 6);
    /* Each retry asked is counted (for /metrics): tc's six and big's one. */
    CHECK(__atomic_load_n(&h->q.tcp_retries, __ATOMIC_RELAXED) == 7);
    fwdq_release(&h->q, got);
    /* TCP never answers: each try truncated, each retry waits out what it may, and the query
     * is over by its budget. */
    t0 = mono_ms();
    CHECK(fqh_ask(h, "w.example.org", FLIGHT_GROUP_DEFAULT, &dead.addr, 1, 100, NULL, &x) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && got == x && len == -1);
    uint32_t ms = mono_ms() - t0;
    CHECK(ms + 20 >= fwd_budget_ms(1, 100) && ms <= fwd_budget_ms(1, 100) + 100 && cnt(&dead.queries) == 2);
    fwdq_release(&h->q, got);
    fqh_stop(h);
    fake_fwd_stop(&tc);
    fake_fwd_stop(&big);
    fake_fwd_stop(&dead);
}

/* A truncated answer waiting its turn for the TCP task, which another's retry holds, is
 * over by its own budget, not when that retry ends; its server isn't counted as failing. */
static void test_fwdq_tcp_queue_budget(void)
{
    fake_fwd_t slow, quick;
    fake_fwd_start(&slow, FAKE_TRUNCATE, 22);
    fake_fwd_start(&quick, FAKE_TRUNCATE, 23);
    fq_harness_t *h = fqh_start(32);
    fwd_set_observer(obs_record);
    obs_reset();
    int a, b, got, len;
    const uint8_t *ans;
    /* a's retry blocks the TCP task for 2 x 400 ms: its TCP port never answers. */
    CHECK(fqh_ask(h, "a.example.org", FLIGHT_GROUP_DEFAULT, &slow.addr, 1, 400, NULL, &a) == FLIGHT_OPENED);
    for (uint32_t t = mono_ms(); cnt(&slow.queries) < 1 && mono_ms() - t < 1000;)
        usleep(1000);
    usleep(20 * 1000); /* its truncated answer in, its retry under way */
    uint32_t t0 = mono_ms();
    CHECK(fqh_ask(h, "b.example.org", FLIGHT_GROUP_DEFAULT, &quick.addr, 1, 50, NULL, &b) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && got == b && len == -1);
    uint32_t ms = mono_ms() - t0;
    CHECK(ms + 5 >= fwd_budget_ms(1, 50) && ms <= fwd_budget_ms(1, 50) + 100);
    CHECK(cnt(&quick.queries) == 1 && cnt(&quick.tcp_queries) == 0);
    /* Only a's retry was asked: b's, its budget spent first, isn't counted. */
    CHECK(__atomic_load_n(&h->q.tcp_retries, __ATOMIC_RELAXED) == 1);
    pthread_mutex_lock(&s_obs.m);
    for (int i = 0; i < s_obs.n && i < 16; i++)
        CHECK(s_obs.server[i] != quick.addr);
    pthread_mutex_unlock(&s_obs.m);
    fwdq_release(&h->q, got);
    CHECK(fqh_take(h, &got, &ans, &len, 3000) && got == a && len == -1);
    fwdq_release(&h->q, got);
    fwd_set_observer(NULL);
    fqh_stop(h);
    fake_fwd_stop(&slow);
    fake_fwd_stop(&quick);
}

/* Issue #53, test 5: strays (from another port, or with another ID) neither end a try nor
 * restart its wait. */
static void test_fwdq_strays(void)
{
    fake_fwd_t st, wrong;
    fake_fwd_start(&st, FAKE_STRAYS, 19);
    fake_fwd_start(&wrong, FAKE_WRONG_ID, 20);
    fq_harness_t *h = fqh_start(32);
    int a, b, got, len;
    const uint8_t *ans;
    uint32_t t0 = mono_ms();
    CHECK(fqh_ask(h, "s.example.org", FLIGHT_GROUP_DEFAULT, &st.addr, 1, 100, NULL, &a) == FLIGHT_OPENED);
    CHECK(fqh_ask(h, "t.example.org", FLIGHT_GROUP_ZONE(0), &wrong.addr, 1, 100, NULL, &b) == FLIGHT_OPENED);
    for (int i = 0; i < 2; i++) {
        CHECK(fqh_take(h, &got, &ans, &len, 2000) && (got == a || got == b) && len == -1);
        uint32_t ms = mono_ms() - t0;
        CHECK(ms + 5 >= 2 * 100 && ms <= 2 * 100 + 100);
        fwdq_release(&h->q, got);
    }
    CHECK(cnt(&st.queries) == 2 && cnt(&wrong.queries) == 2);
    fqh_stop(h);
    fake_fwd_stop(&st);
    fake_fwd_stop(&wrong);
}

/* The loop checks in while it waits, with nothing to ask (the supervisor's watch); a table
 * bigger than it drives is refused. */
static int s_alive;

static void fq_alive(void) { __atomic_add_fetch(&s_alive, 1, __ATOMIC_RELAXED); }

static void test_fwdq_alive(void)
{
    flights_t big = { .n = FWDQ_MAX_SLOTS + 1 };
    fwdq_t q;
    CHECK(!fwdq_init(&q, &big, NULL, 0, NULL, NULL) && q.wake_rx == -1 && q.wake_tx == -1);
    __atomic_store_n(&s_alive, 0, __ATOMIC_RELAXED);
    fq_harness_t *h = calloc(1, sizeof(*h));
    pthread_mutex_init(&h->m, NULL);
    pthread_cond_init(&h->c, NULL);
    flights_init(&h->fl, s_fl_mem, 8, MP_FLIGHT_WAITERS);
    CHECK(fwdq_init(&h->q, &h->fl, h->tcp_buf, sizeof(h->tcp_buf), fqh_done, h));
    fwdq_set_alive(&h->q, fq_alive);
    pthread_create(&h->loop, NULL, fqh_loop, h);
    pthread_create(&h->tcp, NULL, fqh_tcp, h);
    usleep((FWDQ_CHECKIN_MS * 2 + FWDQ_CHECKIN_MS / 2) * 1000);
    int n = __atomic_load_n(&s_alive, __ATOMIC_RELAXED);
    CHECK(n >= 3 && n <= 4); /* at the start, then once a FWDQ_CHECKIN_MS */
    fqh_stop(h);
}

/* Issue #53, test 8: 200 queries for names a silent forwarder is asked, among 1,000 answered
 * from the cache, on four workers as server.c runs them: the cached ones are answered with no
 * wait, the silent ones past their group's half of the table SERVFAIL at once (shed), and
 * those asked fail by their budget. */
typedef struct {
    fq_harness_t *h;
    cache_t *cache;
    uint32_t silent;
    int next;                        /* the next query to take */
    int cached, opened, shed, failed; /* counts */
    uint32_t t0, cached_ms;          /* when the last cached query was answered, from t0 */
} fq_load_t;

static void load_drain(fq_load_t *l)
{
    int slot, len;
    const uint8_t *ans;
    while (fwdq_take(&l->h->q, &slot, &ans, &len)) {
        flight_end(&l->h->fl, slot, ans, len);
        fwdq_release(&l->h->q, slot);
        __atomic_add_fetch(&l->failed, len < 0, __ATOMIC_RELAXED);
    }
}

static void *load_worker(void *p)
{
    fq_load_t *l = p;
    for (int i; (i = __atomic_fetch_add(&l->next, 1, __ATOMIC_RELAXED)) < 1200;) {
        load_drain(l); /* the done queue first */
        char name[40];
        if (i % 6 == 5) {
            snprintf(name, sizeof(name), "s%d.example.org", i);
            int slot;
            flight_role_t r = fqh_ask(l->h, name, FLIGHT_GROUP_DEFAULT, &l->silent, 1, 250, NULL, &slot);
            __atomic_add_fetch(r == FLIGHT_OPENED ? &l->opened : &l->shed, 1, __ATOMIC_RELAXED);
            continue;
        }
        uint8_t qn[DNS_MAX_NAME], out[512];
        snprintf(name, sizeof(name), "c%d.example.org", i % 1000);
        int ql = N(name, qn);
        size_t n;
        uint32_t age;
        if (cache_get(l->cache, qn, ql, DNS_T_A, DNS_C_IN, false, 1001, out, sizeof(out), &n, &age)) {
            __atomic_add_fetch(&l->cached, 1, __ATOMIC_RELAXED);
            uint32_t ms = mono_ms() - l->t0;
            uint32_t was = __atomic_load_n(&l->cached_ms, __ATOMIC_RELAXED);
            while (ms > was && !__atomic_compare_exchange_n(&l->cached_ms, &was, ms, false, __ATOMIC_RELAXED,
                                                            __ATOMIC_RELAXED))
                ;
        }
    }
    return NULL;
}

static void test_fwdq_load(void)
{
    fake_fwd_t silent;
    fake_fwd_start(&silent, FAKE_SILENT, 21);
    fq_load_t l = { .silent = silent.addr };
    l.cache = cache_new(2048, 4 << 20);
    uint8_t m[512];
    for (int i = 0; i < 1000; i++) {
        char name[40];
        uint8_t qn[DNS_MAX_NAME];
        snprintf(name, sizeof(name), "c%d.example.org", i);
        int ql = N(name, qn);
        size_t len = upstream_resp(m, 0, true, false);
        cache_put(l.cache, qn, ql, DNS_T_A, DNS_C_IN, false, 1000, m, len);
    }
    l.h = fqh_start(32);
    pthread_t w[MP_UDP_WORKERS];
    l.t0 = mono_ms();
    for (int i = 0; i < MP_UDP_WORKERS; i++)
        pthread_create(&w[i], NULL, load_worker, &l);
    for (int i = 0; i < MP_UDP_WORKERS; i++)
        pthread_join(w[i], NULL);
    /* Every cached query answered long before a forwarder's first try is over. */
    CHECK(l.cached == 1000 && l.cached_ms < 150);
    /* The default forwarders' half of the table asked; the rest shed at once. */
    CHECK(l.opened == 16 && l.shed == 184);
    while (l.failed < l.opened && mono_ms() - l.t0 < 3000) {
        int slot, len;
        const uint8_t *ans;
        if (fqh_take(l.h, &slot, &ans, &len, 100)) {
            flight_end(&l.h->fl, slot, ans, len);
            fwdq_release(&l.h->q, slot);
            l.failed += len < 0;
        }
    }
    uint32_t ms = mono_ms() - l.t0;
    CHECK(l.failed == 16 && ms + 5 >= 2 * 250 && ms <= fwd_budget_ms(1, 250) + 200);
    CHECK(cnt(&silent.queries) == 32); /* two tries each */
    CHECK(l.h->fl.held[FLIGHT_GROUP_DEFAULT] == 0 && flight_waiting(&l.h->fl) == 0);
    fqh_stop(l.h);
    cache_free(l.cache);
    fake_fwd_stop(&silent);
}

/* Upstream queries' source ports (issue #63): drawn at random, not the stack's next in
 * sequence; a port in use is passed over. */
static void test_fwd_random_port(void)
{
    for (int i = 0; i < 2000; i++)
        CHECK(fwd_random_port() >= FWD_PORT_MIN);
    /* The port bound is the one drawn. */
    srandom(4242);
    uint16_t want = fwd_random_port();
    srandom(4242);
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    CHECK(s >= 0 && fwd_bind_random(s) && getsockname(s, (struct sockaddr *)&sa, &sl) == 0 && ntohs(sa.sin_port) == want);
    /* That port taken, the next draw is bound instead. */
    srandom(4242);
    int s2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sl = sizeof(sa);
    CHECK(s2 >= 0 && fwd_bind_random(s2) && getsockname(s2, (struct sockaddr *)&sa, &sl) == 0 && ntohs(sa.sin_port) != want &&
          ntohs(sa.sin_port) >= FWD_PORT_MIN);
    close(s);
    close(s2);
    /* Each upstream query on its own socket and port, none in sequence with the one before. */
    srandom((unsigned)time(NULL));
    uint8_t qn[DNS_MAX_NAME];
    int ql = N("port.example.org", qn);
    fwd_q_t q = { .qname = qn, .qlen = ql, .qtype = DNS_T_A, .qclass = DNS_C_IN };
    uint32_t srv = loopback(25);
    fwd_up_t u[32];
    uint16_t port[32];
    int seq = 0;
    for (int i = 0; i < 32; i++) {
        fwd_up_init(&u[i], &srv, 1, 100);
        CHECK(fwd_up_start(&u[i], &q, fwd_now_ms()) == FWD_WAIT);
        sl = sizeof(sa);
        CHECK(getsockname(u[i].sock, (struct sockaddr *)&sa, &sl) == 0 && ntohs(sa.sin_port) >= FWD_PORT_MIN);
        port[i] = ntohs(sa.sin_port);
        seq += i && (uint16_t)(port[i] - port[i - 1]) <= 2;
    }
    CHECK(seq <= 1);
    for (int i = 0; i < 32; i++)
        fwd_up_close(&u[i]);
}

/* select() failing at once, again and again: the loop backs off instead of spinning, and goes
 * on once it works again. The wake socket's descriptor is closed under it (EBADF on every
 * select), then put back. */
static void test_fwdq_select_backoff(void)
{
    fake_fwd_t up;
    fake_fwd_start(&up, FAKE_ANSWER, 26);
    fq_harness_t *h = calloc(1, sizeof(*h));
    pthread_mutex_init(&h->m, NULL);
    pthread_cond_init(&h->c, NULL);
    flights_init(&h->fl, s_fl_mem, 8, MP_FLIGHT_WAITERS);
    CHECK(fwdq_init(&h->q, &h->fl, h->tcp_buf, sizeof(h->tcp_buf), fqh_done, h));
    fwdq_set_alive(&h->q, fq_alive);
    pthread_create(&h->loop, NULL, fqh_loop, h);
    pthread_create(&h->tcp, NULL, fqh_tcp, h);
    int fd = h->q.wake_rx, keep = dup(fd);
    CHECK(keep >= 0 && close(fd) == 0);
    /* The select under way when it was closed may wait out its timeout: then it fails. */
    for (uint32_t t = mono_ms(); !__atomic_load_n(&h->q.select_errors, __ATOMIC_RELAXED) && mono_ms() - t < 3000;)
        usleep(1000);
    __atomic_store_n(&s_alive, 0, __ATOMIC_RELAXED);
    uint32_t e0 = __atomic_load_n(&h->q.select_errors, __ATOMIC_RELAXED);
    usleep(800 * 1000);
    int n = __atomic_load_n(&s_alive, __ATOMIC_RELAXED);
    uint32_t e = __atomic_load_n(&h->q.select_errors, __ATOMIC_RELAXED) - e0;
    /* 800 ms of failing at once, waited out from 10 ms doubling to 500: a handful of looks,
     * not the millions of a spin. */
    CHECK(e0 >= 1 && e >= 2 && e <= 8 && n >= 2 && n <= 9);
    CHECK(dup2(keep, fd) == fd);
    close(keep);
    /* Working again: a query handed over is asked and answered. */
    int slot, got, len;
    const uint8_t *ans;
    CHECK(fqh_ask(h, "back.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 300, NULL, &slot) == FLIGHT_OPENED);
    CHECK(fqh_take(h, &got, &ans, &len, 2000) && got == slot && answers(ans, len, "back.example.org"));
    fwdq_release(&h->q, got);
    fqh_stop(h);
    fake_fwd_stop(&up);
}

/* The default forwarders' run of failures (health.h): a run's count with its start, thread-safe. */
typedef struct {
    health_upstream_t *u;
    uint32_t base;
} hu_arg_t;

static void *hu_fail(void *p)
{
    hu_arg_t *a = p;
    for (int i = 0; i < 2000; i++)
        health_upstream_note(a->u, false, false, a->base + (uint32_t)i);
    return NULL;
}

static void test_health_upstream(void)
{
    health_upstream_t u;
    health_fwd_t f;
    health_upstream_init(&u);
    health_upstream_get(&u, 0, &f);
    CHECK(f.fails == 0 && !f.shed && f.ended == 0 && f.slow == 0);
    health_upstream_note(&u, false, true, 100);
    health_upstream_note(&u, false, true, 200);
    health_upstream_get(&u, 200, &f);
    CHECK(f.fails == 2 && f.since_ms == 100 && f.ended == 2 && f.slow == 2);
    health_upstream_note(&u, true, false, 300); /* any answer ends the run */
    health_upstream_get(&u, 300, &f);
    CHECK(f.fails == 0 && f.ended == 3 && f.slow == 2);
    health_upstream_note(&u, false, false, 400); /* unanswered is slow, whatever it is told */
    health_upstream_get(&u, 400, &f);
    CHECK(f.fails == 1 && f.since_ms == 400 && f.ended == 4 && f.slow == 3);
    health_upstream_note(&u, true, true, 500); /* answered after a try's timeout: slow */
    health_upstream_get(&u, 500, &f);
    CHECK(f.fails == 0 && f.ended == 5 && f.slow == 4);
    CHECK(health_fwd_slow(&f, 500));
    /* The window: what ended over HEALTH_FWD_WINDOW_MS ago is out of it, give or take a
     * bucket. */
    health_upstream_get(&u, HEALTH_FWD_WINDOW_MS - HEALTH_FWD_BUCKET_MS, &f);
    CHECK(f.ended == 5);
    health_upstream_get(&u, HEALTH_FWD_WINDOW_MS + HEALTH_FWD_BUCKET_MS, &f);
    CHECK(f.ended == 0 && f.slow == 0 && !health_fwd_slow(&f, HEALTH_FWD_WINDOW_MS + HEALTH_FWD_BUCKET_MS));
    /* A bucket used again starts over: the old counts don't come back. */
    health_upstream_note(&u, true, false, HEALTH_FWD_WINDOW_MS + 100);
    health_upstream_get(&u, HEALTH_FWD_WINDOW_MS + 100, &f);
    CHECK(f.ended == 1 && f.slow == 0);
    /* Queries shed: counted over the window, as the queries ended are. */
    CHECK(!f.shed);
    health_upstream_shed(&u, 40000);
    health_upstream_shed(&u, 41000);
    health_upstream_get(&u, 41000, &f);
    CHECK(f.shed == 2 && health_fwd_slow(&f, 41000));
    health_upstream_get(&u, 41000 + HEALTH_FWD_WINDOW_MS - HEALTH_FWD_BUCKET_MS, &f);
    CHECK(f.shed == 2);
    health_upstream_get(&u, 41000 + HEALTH_FWD_WINDOW_MS + HEALTH_FWD_BUCKET_MS, &f);
    CHECK(f.shed == 0 && !health_fwd_slow(&f, 41000 + HEALTH_FWD_WINDOW_MS + HEALTH_FWD_BUCKET_MS));
    /* Long past, read for the first time since: the ms clock 2^31 on (24.8 days), where a
     * signed difference with the shed's time would read as recent again. */
    health_upstream_get(&u, 41000 + 0x80000000u + 1000, &f);
    CHECK(f.shed == 0 && !health_fwd_slow(&f, 41000 + 0x80000000u + 1000));
    /* Noted by a worker just after the reader read the clock, in the next bucket: now. */
    health_upstream_shed(&u, 3 * HEALTH_FWD_BUCKET_MS);
    health_upstream_get(&u, 3 * HEALTH_FWD_BUCKET_MS - 1, &f);
    CHECK(f.shed == 1);
    /* An isolated burst, read on (as health does every tick) past the window, then read once
     * the ms clock has come round to the same bucket (2^32 ms, 49.7 days) with no query
     * since: none of it is read again, and the forwarders aren't slow. */
    health_upstream_reset(&u);
    for (int i = 0; i < 2 * HEALTH_FWD_SLOW_MIN; i++)
        health_upstream_note(&u, false, true, 600000 + (uint32_t)i);
    health_upstream_shed(&u, 600000);
    health_upstream_get(&u, 600000, &f);
    CHECK(f.shed == 1 && f.ended == 2 * HEALTH_FWD_SLOW_MIN && health_fwd_slow(&f, 600000));
    health_upstream_note(&u, true, false, 600100); /* the run of failures ends */
    health_upstream_get(&u, 600000 + HEALTH_FWD_WINDOW_MS + HEALTH_FWD_BUCKET_MS, &f);
    CHECK(f.shed == 0 && f.ended == 0);
    health_upstream_get(&u, 600000, &f); /* 600000 + 2^32 ms: the same bucket's epoch */
    CHECK(f.shed == 0 && f.ended == 0 && f.slow == 0 && !health_fwd_slow(&f, 600000));
    /* Steady answers, each under a try's timeout: never slow. */
    health_upstream_reset(&u);
    for (uint32_t t = 0; t < 120000; t += 100)
        health_upstream_note(&u, true, false, 200000 + t);
    health_upstream_get(&u, 320000, &f);
    CHECK(f.ended >= 250 && f.ended <= 300 && f.slow == 0 && !f.shed && !health_fwd_slow(&f, 320000));
    health_upstream_note(&u, false, false, 320000);
    health_upstream_reset(&u);
    health_upstream_get(&u, 320000, &f);
    CHECK(f.fails == 0 && !f.shed && f.ended == 0);
    /* Workers ending flights at once: every failure counted, the run's start the first's. */
    pthread_t th[4];
    hu_arg_t a[4];
    for (int i = 0; i < 4; i++) {
        a[i] = (hu_arg_t){ &u, 10000u * (uint32_t)(i + 1) };
        pthread_create(&th[i], NULL, hu_fail, &a[i]);
    }
    for (int i = 0; i < 4; i++)
        pthread_join(th[i], NULL);
    health_upstream_get(&u, 50000, &f);
    CHECK(f.fails == 8000 && f.since_ms % 10000 == 0 && f.since_ms >= 10000 && f.since_ms <= 40000);
}

/* ---- the workers' side (upq.h) ---- */

/* A worker woken (upq's wake): counted, for the tests to wait on. */
static int s_upq_wakes;
static bool s_upq_cacheable = true;

static bool upq_wake_count(void *ctx)
{
    __atomic_add_fetch(&s_upq_wakes, 1, __ATOMIC_RELAXED);
    return true;
}

static bool upq_cacheable(const uint8_t *ans, size_t len) { return s_upq_cacheable; }

typedef struct {
    upq_t u;
    pthread_t loop, tcp;
    uint8_t tcp_buf[MP_FWD_TCP];
} upq_harness_t;

static void *upqh_loop(void *p)
{
    fwdq_run(&((upq_harness_t *)p)->u.q);
    return NULL;
}

static void *upqh_tcp(void *p)
{
    fwdq_tcp_run(&((upq_harness_t *)p)->u.q);
    return NULL;
}

static upq_harness_t *upqh_start(cache_t *cache, bool (*wake)(void *), void *ctx)
{
    upq_harness_t *h = calloc(1, sizeof(*h));
    CHECK(upq_init(&h->u, s_fl_mem, 32, MP_FLIGHT_WAITERS, h->tcp_buf, sizeof(h->tcp_buf), cache, upq_cacheable, wake,
                   ctx));
    pthread_create(&h->loop, NULL, upqh_loop, h);
    pthread_create(&h->tcp, NULL, upqh_tcp, h);
    return h;
}

static void upqh_stop(upq_harness_t *h)
{
    fwdq_stop(&h->u.q);
    pthread_join(h->loop, NULL);
    pthread_join(h->tcp, NULL);
    fwdq_destroy(&h->u.q);
    free(h);
}

/* name (A, IN) in group, asking servers, waiting with w. */
static flight_role_t upq_ask_name(upq_t *u, const char *name, int group, const uint32_t *servers, int n, int timeout_ms,
                                  bool cnames, flight_waiter_t *w)
{
    uint8_t qn[DNS_MAX_NAME];
    int ql = N(name, qn);
    flight_query_t q = { .qname = qn, .qlen = ql, .qtype = DNS_T_A, .qclass = DNS_C_IN, .group = group,
                         .servers = servers, .nservers = n, .timeout_ms = timeout_ms, .gen = u->cache ? cache_gen(u->cache) : 0,
                         .cnames = cnames };
    uint32_t d;
    return upq_ask(u, &q, w, fwd_now_ms(), &d);
}

/* Waits (at most wait_ms) for the wakes counted to reach n. */
static bool upq_wait_wakes(int n, uint32_t wait_ms)
{
    for (uint32_t t = mono_ms(); __atomic_load_n(&s_upq_wakes, __ATOMIC_RELAXED) < n; usleep(1000))
        if (mono_ms() - t > wait_ms)
            return false;
    return true;
}

static bool cached(cache_t *c, const char *name)
{
    uint8_t qn[DNS_MAX_NAME], out[1500];
    int ql = N(name, qn);
    size_t n;
    uint32_t age;
    return cache_get(c, qn, ql, DNS_T_A, DNS_C_IN, false, 1000, out, sizeof(out), &n, &age);
}

/* Issue #53, part 3: a flight's answer reaches every query waiting on it, the one that opened
 * it too; it is cached once (as its CNAMEs allow), counted once for the forwarders' health,
 * and a worker is woken once for any number of flights finished meanwhile. */
static void test_upq(void)
{
    fake_fwd_t up, down;
    fake_fwd_start(&up, FAKE_RECORD, 27);
    fake_fwd_start(&down, FAKE_SILENT, 28);
    cache_t *c = cache_new(256, 1 << 20);
    __atomic_store_n(&s_upq_wakes, 0, __ATOMIC_RELAXED);
    s_upq_cacheable = true;
    upq_harness_t *h = upqh_start(c, upq_wake_count, NULL);
    upq_t *u = &h->u;
    fake_item_t it[8];
    for (int i = 0; i < 8; i++)
        it[i] = (fake_item_t){ .id = i };
    uint8_t buf[2048];
    fake_tcp_t t;
    fake_tcp_init(&t, buf, sizeof(buf));
    CHECK(upq_ask_name(u, "popular.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 500, true, &it[0].fw) ==
          FLIGHT_OPENED);
    CHECK(upq_ask_name(u, "popular.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 500, true, &it[1].fw) ==
          FLIGHT_JOINED);
    CHECK(upq_ask_name(u, "popular.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 500, true, &t.t.w) == FLIGHT_JOINED);
    CHECK(upq_wait_wakes(1, 1000));
    upq_woken(u);
    upq_done_t d;
    int ids[8];
    /* Taken by a worker that read the clock just before the flight opened (the answer came
     * at once): its time from opening comes out negative, which is not slow. */
    CHECK(upq_take(u, &d, fwd_now_ms() - 50, 1000) && d.len > 0 && answers(d.answer, d.len, "popular.example.org"));
    CHECK(list_ids(d.parked, ids, 8) == 2 && ids[0] == 0 && ids[1] == 1);
    CHECK(flight_tcp_done(&t.t) && t.t.len == d.len && !memcmp(buf, d.answer, (size_t)d.len));
    CHECK(!flight_cancel(&u->fl, &t.t));
    upq_release(u, &d);
    CHECK(!upq_take(u, &d, fwd_now_ms(), 1000));
    CHECK(cached(c, "popular.example.org") && cnt(&up.queries) == 1);
    health_fwd_t f;
    health_upstream_get(&u->health, fwd_now_ms(), &f);
    CHECK(f.fails == 0 && f.ended == 1 && f.slow == 0); /* answered within a try's timeout */
    /* Blocking says its CNAMEs don't pass: answered, not cached; one that asked with no CNAME
     * check (an override allows it) is cached all the same. */
    s_upq_cacheable = false;
    CHECK(upq_ask_name(u, "blocked.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 500, true, &it[2].fw) ==
          FLIGHT_OPENED);
    CHECK(upq_ask_name(u, "allowed.example.org", FLIGHT_GROUP_DEFAULT, &up.addr, 1, 500, false, &it[3].fw) ==
          FLIGHT_OPENED);
    /* Both finished before a worker takes them: one wake for the two. */
    for (uint32_t t0 = mono_ms(); cnt(&up.queries) < 3 && mono_ms() - t0 < 1000;)
        usleep(1000);
    usleep(50 * 1000);
    CHECK(__atomic_load_n(&s_upq_wakes, __ATOMIC_RELAXED) == 2);
    upq_woken(u);
    for (int i = 0; i < 2; i++) {
        CHECK(upq_take(u, &d, fwd_now_ms(), 1000) && d.len > 0 && list_ids(d.parked, ids, 8) == 1);
        upq_release(u, &d);
    }
    CHECK(!cached(c, "blocked.example.org") && cached(c, "allowed.example.org"));
    s_upq_cacheable = true;
    /* A silent forwarder: every query on its flight is handed back without an answer by the
     * budget, and the run of failures counts the flight once. A forward zone's doesn't count. */
    uint32_t t0 = mono_ms();
    CHECK(upq_ask_name(u, "dead.example.org", FLIGHT_GROUP_DEFAULT, &down.addr, 1, 100, true, &it[4].fw) ==
          FLIGHT_OPENED);
    CHECK(upq_ask_name(u, "dead.example.org", FLIGHT_GROUP_DEFAULT, &down.addr, 1, 100, true, &it[5].fw) ==
          FLIGHT_JOINED);
    CHECK(upq_ask_name(u, "dead.zone.example", FLIGHT_GROUP_ZONE(0), &down.addr, 1, 100, true, &it[6].fw) ==
          FLIGHT_OPENED);
    CHECK(upq_wait_wakes(3, 2000));
    upq_woken(u);
    int failed = 0;
    for (uint32_t w0 = mono_ms(); failed < 3 && mono_ms() - w0 < 2000;) {
        if (!upq_take(u, &d, fwd_now_ms(), 1000)) {
            usleep(1000);
            continue;
        }
        CHECK(d.len <= 0 && d.parked);
        failed += list_ids(d.parked, ids, 8);
        upq_release(u, &d);
    }
    CHECK(failed == 3 && mono_ms() - t0 <= fwd_budget_ms(1, 100) + 100);
    health_upstream_get(&u->health, fwd_now_ms(), &f);
    CHECK(f.fails == 1 && (int32_t)(f.since_ms - t0) >= 0);
    /* The default forwarders' flight counted slow; the forward zone's not at all. */
    CHECK(f.ended == 4 && f.slow == 1);
    CHECK(!cached(c, "dead.example.org"));
    CHECK(flight_waiting(&u->fl) == 0 && u->fl.held[FLIGHT_GROUP_DEFAULT] == 0 && u->fl.zones_held == 0);
    /* Counted for /metrics: the flights that ended unanswered, per kind of group. */
    upq_stats_t us;
    upq_stats(u, &us);
    CHECK(us.expired[UPQ_DEFAULT] == 1 && us.expired[UPQ_ZONES] == 1);
    CHECK(us.shed[UPQ_DEFAULT] == 0 && us.shed[UPQ_ZONES] == 0 && us.table.held_all == 0 && us.table.peak >= 2);
    /* Past a zone's cap (half of 32): shed, counted for the zones; not noted for the default
     * forwarders' health. */
    for (int i = 0; i < 16; i++) {
        char nm[40];
        snprintf(nm, sizeof(nm), "z%d.zone.example", i);
        CHECK(upq_ask_name(u, nm, FLIGHT_GROUP_ZONE(1), &down.addr, 1, 100, true, NULL) == FLIGHT_OPENED);
    }
    CHECK(upq_ask_name(u, "z16.zone.example", FLIGHT_GROUP_ZONE(1), &down.addr, 1, 100, true, NULL) == FLIGHT_FULL);
    upq_stats(u, &us);
    CHECK(us.shed[UPQ_ZONES] == 1 && us.shed[UPQ_DEFAULT] == 0 && us.table.zones_held == 16 &&
          us.table.held[FLIGHT_GROUP_ZONE(1)] == 16 && !us.table.busy);
    health_upstream_get(&u->health, fwd_now_ms(), &f);
    CHECK(!f.shed);
    /* One to the default forwarders past theirs is noted. */
    for (int i = 0; i < 16; i++) {
        char nm[40];
        snprintf(nm, sizeof(nm), "d%d.example.org", i);
        CHECK(upq_ask_name(u, nm, FLIGHT_GROUP_DEFAULT, &down.addr, 1, 100, true, NULL) == FLIGHT_OPENED);
    }
    CHECK(upq_ask_name(u, "d16.example.org", FLIGHT_GROUP_DEFAULT, &down.addr, 1, 100, true, NULL) == FLIGHT_FULL);
    upq_stats(u, &us);
    CHECK(us.shed[UPQ_DEFAULT] == 1 && us.table.busy && us.table.held_all == 32 && us.table.peak == 32);
    health_upstream_get(&u->health, fwd_now_ms(), &f);
    CHECK(f.shed == 1 && health_fwd_slow(&f, fwd_now_ms()));
    /* They all end by their budget: taken, the table is empty again. */
    for (uint32_t w0 = mono_ms(), n = 0; n < 32 && mono_ms() - w0 < 2000;) {
        if (!upq_take(u, &d, fwd_now_ms(), 1000)) {
            usleep(1000);
            continue;
        }
        upq_release(u, &d);
        n++;
    }
    upq_stats(u, &us);
    CHECK(us.table.held_all == 0 && !us.table.busy && us.expired[UPQ_DEFAULT] == 17 && us.expired[UPQ_ZONES] == 17);
    upqh_stop(h);
    cache_free(c);
    sem_destroy(&t.sem);
    fake_fwd_stop(&up);
    fake_fwd_stop(&down);
}

/* Issue #53, part 3: the node's UDP path on four worker threads as server.c runs them (one
 * queue of received queries, a NULL on it to take the finished flights), with every forwarder
 * silent. The cached queries keep being answered at once while the uncached ones wait on
 * their flights off the workers: no worker ever waits on a forwarder. Each uncached query is
 * answered (SERVFAIL) by its flight's budget, or at once past the table's caps. */
#define UW_QUERIES 1200
#define UW_QCAP    2048

typedef struct {
    flight_waiter_t fw; /* first */
    int id;
    uint32_t t0;
} uw_item_t;

typedef struct {
    upq_harness_t *h;
    cache_t *cache;
    uint32_t servers[2];
    pthread_mutex_t m;
    pthread_cond_t c;
    uw_item_t *ring[UW_QCAP];
    int head, tail;
    bool stop;
    uw_item_t items[UW_QUERIES];
    int cached, parked, shed, failed, answered_late;
    uint32_t t0, cached_max_ms, longest_ms; /* the last cached answer, from t0; a worker's longest step */
} uw_t;

static bool uw_push(uw_t *x, uw_item_t *it)
{
    pthread_mutex_lock(&x->m);
    bool ok = (x->tail + 1) % UW_QCAP != x->head;
    if (ok) {
        x->ring[x->tail] = it;
        x->tail = (x->tail + 1) % UW_QCAP;
        pthread_cond_signal(&x->c);
    }
    pthread_mutex_unlock(&x->m);
    return ok;
}

static bool uw_wake(void *ctx) { return uw_push(ctx, NULL); }

static void uw_max(uint32_t *at, uint32_t v)
{
    uint32_t was = __atomic_load_n(at, __ATOMIC_RELAXED);
    while (v > was && !__atomic_compare_exchange_n(at, &was, v, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        ;
}

static void *uw_worker(void *p)
{
    uw_t *x = p;
    for (;;) {
        pthread_mutex_lock(&x->m);
        while (x->head == x->tail && !x->stop)
            pthread_cond_wait(&x->c, &x->m);
        if (x->head == x->tail) {
            pthread_mutex_unlock(&x->m);
            return NULL;
        }
        uw_item_t *it = x->ring[x->head];
        x->head = (x->head + 1) % UW_QCAP;
        pthread_mutex_unlock(&x->m);
        uint32_t s0 = mono_ms();
        if (!it)
            upq_woken(&x->h->u);
        /* The finished flights first: each parked query answered from its flight (SERVFAIL). */
        upq_done_t d;
        while (upq_take(&x->h->u, &d, mono_ms(), 1001)) {
            for (flight_waiter_t *w = d.parked; w; w = w->next) {
                __atomic_add_fetch(&x->failed, 1, __ATOMIC_RELAXED);
                if (mono_ms() - ((uw_item_t *)w)->t0 > fwd_budget_ms(2, 100) + FLIGHT_WAIT_MARGIN_MS)
                    __atomic_add_fetch(&x->answered_late, 1, __ATOMIC_RELAXED);
            }
            upq_release(&x->h->u, &d);
        }
        if (it) {
            char name[40];
            uint8_t qn[DNS_MAX_NAME], out[512];
            bool uncached = it->id % 6 == 5;
            snprintf(name, sizeof(name), uncached ? "s%d.example.org" : "c%d.example.org", uncached ? it->id : it->id % 1000);
            int ql = N(name, qn);
            size_t n;
            uint32_t age;
            if (cache_get(x->cache, qn, ql, DNS_T_A, DNS_C_IN, false, 1001, out, sizeof(out), &n, &age)) {
                __atomic_add_fetch(&x->cached, 1, __ATOMIC_RELAXED);
                uw_max(&x->cached_max_ms, mono_ms() - x->t0);
            } else {
                it->t0 = mono_ms();
                flight_query_t q = { .qname = qn, .qlen = ql, .qtype = DNS_T_A, .qclass = DNS_C_IN,
                                     .group = FLIGHT_GROUP_DEFAULT, .servers = x->servers, .nservers = 2,
                                     .timeout_ms = 100, .gen = cache_gen(x->cache), .cnames = true };
                uint32_t dl;
                if (upq_ask(&x->h->u, &q, &it->fw, mono_ms(), &dl) == FLIGHT_FULL)
                    __atomic_add_fetch(&x->shed, 1, __ATOMIC_RELAXED); /* SERVFAIL at once */
                else
                    __atomic_add_fetch(&x->parked, 1, __ATOMIC_RELAXED);
            }
        }
        uw_max(&x->longest_ms, mono_ms() - s0);
    }
}

static void test_upq_workers_silent(void)
{
    fake_fwd_t d1, d2;
    fake_fwd_start(&d1, FAKE_SILENT, 29);
    fake_fwd_start(&d2, FAKE_SILENT, 30);
    uw_t *x = calloc(1, sizeof(*x));
    pthread_mutex_init(&x->m, NULL);
    pthread_cond_init(&x->c, NULL);
    x->servers[0] = d1.addr;
    x->servers[1] = d2.addr;
    x->cache = cache_new(2048, 4 << 20);
    uint8_t m[512];
    for (int i = 0; i < 1000; i++) {
        char name[40];
        uint8_t qn[DNS_MAX_NAME];
        snprintf(name, sizeof(name), "c%d.example.org", i);
        int ql = N(name, qn);
        size_t len = upstream_resp(m, 0, true, false);
        cache_put(x->cache, qn, ql, DNS_T_A, DNS_C_IN, false, 1000, m, len);
    }
    x->h = upqh_start(x->cache, uw_wake, x);
    pthread_t w[MP_UDP_WORKERS];
    for (int i = 0; i < MP_UDP_WORKERS; i++)
        pthread_create(&w[i], NULL, uw_worker, x);
    /* The queries arrive over 300 ms: the cached ones go on being answered while the first
     * flights wait on their silent forwarders. */
    x->t0 = mono_ms();
    for (int i = 0; i < UW_QUERIES; i++) {
        x->items[i].id = i;
        CHECK(uw_push(x, &x->items[i]));
        if (i % 4 == 3)
            usleep(1000);
    }
    uint32_t sent_ms = mono_ms() - x->t0;
    /* Every uncached query answered: parked ones by their flight's budget, the rest shed. */
    for (uint32_t t = mono_ms();
         __atomic_load_n(&x->failed, __ATOMIC_RELAXED) < __atomic_load_n(&x->parked, __ATOMIC_RELAXED) ||
         __atomic_load_n(&x->parked, __ATOMIC_RELAXED) + __atomic_load_n(&x->shed, __ATOMIC_RELAXED) < 200;
         usleep(2000))
        if (mono_ms() - t > 5000)
            break;
    pthread_mutex_lock(&x->m);
    x->stop = true;
    pthread_cond_broadcast(&x->c);
    pthread_mutex_unlock(&x->m);
    for (int i = 0; i < MP_UDP_WORKERS; i++)
        pthread_join(w[i], NULL);
    /* Every cached query answered as it came, never later than the last one sent plus a
     * little: none waited behind a forwarder. */
    CHECK(x->cached == 1000 && x->cached_max_ms <= sent_ms + 50);
    /* No worker step took long (the forwarders' timeout is 100 ms, their budget 600). */
    CHECK(x->longest_ms < 50);
    CHECK(x->parked + x->shed == 200 && x->parked >= 16 && x->failed == x->parked && x->answered_late == 0);
    /* Each flight asked both forwarders twice, and failed once for health. */
    health_fwd_t hf;
    health_upstream_get(&x->h->u.health, mono_ms(), &hf);
    uint32_t f = hf.fails;
    CHECK(f >= 16 && (int)f == x->parked && cnt(&d1.queries) == 2 * (int)f && cnt(&d2.queries) == 2 * (int)f);
    /* Shed, slow and counted (#60, metrics): the node now reads as "forwarders slow". */
    upq_stats_t us;
    upq_stats(&x->h->u, &us);
    CHECK(us.shed[UPQ_DEFAULT] == (uint32_t)x->shed && us.shed[UPQ_ZONES] == 0);
    CHECK(us.expired[UPQ_DEFAULT] == f && us.expired[UPQ_ZONES] == 0);
    CHECK(hf.shed && hf.slow == f && hf.ended == f && health_fwd_slow(&hf, mono_ms()));
    CHECK(us.table.peak == us.table.group_cap && us.table.held_all == 0 && us.table.slots == 32);
    CHECK(flight_waiting(&x->h->u.fl) == 0 && x->h->u.fl.held[FLIGHT_GROUP_DEFAULT] == 0);
    upqh_stop(x->h);
    cache_free(x->cache);
    free(x);
    fake_fwd_stop(&d1);
    fake_fwd_stop(&d2);
}

static void test_cache_and_relay(void)
{
    uint8_t m[512], got[512], n[256];
    int nl = N("www.example.org", n);
    size_t len = upstream_resp(m, 0, true, false);

    CHECK(dns_resp_ttl(m, len) == 300);
    cache_t *c = cache_new(4, 1 << 20);
    cache_put(c, n, nl, DNS_T_A, 1, 0, 1000, m, len);
    size_t gl;
    uint32_t age;
    uint8_t upper[256];
    int ul = N("WWW.EXAMPLE.ORG", upper);
    upper[1] = 'W';
    CHECK(cache_get(c, upper, ul, DNS_T_A, 1, 0, 1100, got, sizeof(got), &gl, &age) && age == 100 && gl == len);
    CHECK(cache_get(c, n, nl, DNS_T_A, 1, true, 1100, got, sizeof(got), &gl, &age)); /* stored without CD: serves CD */
    CHECK(!cache_get(c, n, nl, DNS_T_A, 1, 0, 1300, got, sizeof(got), &gl, &age)); /* expired */

    /* relay subtracts age and decompresses */
    uint8_t qb[512], out[512];
    dns_query_t q;
    size_t ql = make_query(qb, "www.example.org", DNS_T_A, true);
    CHECK(dns_query_parse(qb, ql, &q) == 0 && q.has_edns && q.do_bit && q.edns_size == 4096);
    dns_builder_t b;
    dnsb_init(&b, out, sizeof(out), 1232, &q, DNS_F_QR);
    dnsb_opt(&b, 1232, q.do_bit);
    CHECK(dnsb_relay(&b, m, len, 100, false, true) == 0);
    size_t ol = dnsb_finish(&b);
    parsed_t p;
    CHECK(parse_resp(out, ol, &p) && p.h.an == 1 && p.h.ar == 1 && p.rr[0].ttl == 200 && p.rr[1].type == DNS_T_OPT);
    CHECK(p.rr[1].ttl == 0x8000); /* DO echoed */

    /* negative answers: cached for min(SOA ttl, MINIMUM); without SOA not at all */
    len = upstream_resp(m, DNS_R_NXDOMAIN, false, true);
    CHECK(dns_resp_ttl(m, len) == 60);
    len = upstream_resp(m, DNS_R_NXDOMAIN, false, false);
    CHECK(dns_resp_ttl(m, len) == 0);
    len = upstream_resp(m, DNS_R_SERVFAIL, false, false);
    CHECK(dns_resp_ttl(m, len) == 0);

    /* LRU eviction at 4 entries */
    for (int i = 0; i < 6; i++) {
        uint8_t k[256];
        char s[32];
        snprintf(s, sizeof(s), "h%d.example.org", i);
        int kl = N(s, k);
        len = upstream_resp(m, 0, true, false);
        cache_put(c, k, kl, DNS_T_A, 1, 0, 2000, m, len);
    }
    cache_stats_t st;
    cache_get_stats(c, &st);
    CHECK(st.entries == 4 && st.evictions >= 2);
    cache_flush(c);
    cache_get_stats(c, &st);
    CHECK(st.entries == 0 && st.bytes == 0);

    /* A fill racing a list swap (server.c, resolve): the generation read before the query
     * was checked against the old list, a flush (the swap) since, and the answer isn't kept;
     * one read after the flush is. */
    len = upstream_resp(m, 0, true, false);
    uint32_t gen = cache_gen(c);
    CHECK(cache_put_gen(c, gen, n, nl, DNS_T_A, 1, 0, 3000, m, len));
    CHECK(cache_get(c, n, nl, DNS_T_A, 1, 0, 3000, got, sizeof(got), &gl, &age));
    cache_flush(c); /* the swap */
    CHECK(cache_gen(c) != gen);
    CHECK(!cache_put_gen(c, gen, n, nl, DNS_T_A, 1, 0, 3000, m, len));
    CHECK(!cache_get(c, n, nl, DNS_T_A, 1, 0, 3000, got, sizeof(got), &gl, &age));
    gen = cache_gen(c);
    CHECK(cache_put_gen(c, gen, n, nl, DNS_T_A, 1, 0, 3000, m, len));
    CHECK(cache_get(c, n, nl, DNS_T_A, 1, 0, 3000, got, sizeof(got), &gl, &age));
    cache_free(c);

    /* All in one block: a full cache evicts the oldest to make room, by bytes as by entries,
     * and an answer bigger than the whole block isn't cached. Names and answers cross chunks. */
    static uint64_t block[2048]; /* 16 KB */
    c = cache_new_in(block, sizeof(block), 64);
    CHECK(c && !cache_new_in(block, 512, 64) && !cache_new_in(NULL, sizeof(block), 64));
    uint8_t bigm[3000];
    len = upstream_resp(m, 0, true, false);
    memset(bigm, 0, sizeof(bigm));
    memcpy(bigm, m, len); /* the same answer, padded: the TTL parse reads only the records */
    for (int i = 0; i < 40; i++) {
        uint8_t k[256];
        char s[80];
        snprintf(s, sizeof(s), "a-rather-long-label-to-cross-a-chunk-%d.example.org", i);
        int kl = N(s, k);
        cache_put(c, k, kl, DNS_T_A, 1, 0, 3000, bigm, 1000);
    }
    cache_get_stats(c, &st);
    CHECK(st.entries > 0 && st.entries < 40 && st.evictions == 40 - st.entries && st.bytes <= sizeof(block));
    uint32_t held = st.entries;
    uint8_t k[256], got2[3000];
    int kl = N("a-rather-long-label-to-cross-a-chunk-39.example.org", k);
    CHECK(cache_get(c, k, kl, DNS_T_A, 1, 0, 3001, got2, sizeof(got2), &gl, &age) && gl == 1000 &&
          !memcmp(got2, bigm, 1000));
    kl = N("a-rather-long-label-to-cross-a-chunk-0.example.org", k);
    CHECK(!cache_get(c, k, kl, DNS_T_A, 1, 0, 3001, got2, sizeof(got2), &gl, &age)); /* evicted */
    static uint8_t huge[20000];
    memcpy(huge, m, len);
    cache_put(c, n, nl, DNS_T_A, 1, 0, 3000, huge, sizeof(huge));
    CHECK(!cache_get(c, n, nl, DNS_T_A, 1, 0, 3001, got2, sizeof(got2), &gl, &age));
    cache_flush(c);
    cache_get_stats(c, &st);
    CHECK(st.entries == 0 && st.bytes == 0);
    /* After a flush the whole block is free again: as many fit as before. */
    for (int i = 0; i < 40; i++) {
        snprintf((char *)got2, 80, "a-rather-long-label-to-cross-a-chunk-%d.example.org", i);
        kl = N((const char *)got2, k);
        cache_put(c, k, kl, DNS_T_A, 1, 0, 3000, bigm, 1000);
    }
    cache_get_stats(c, &st);
    CHECK(st.entries == held);
}

/* ---- the cache under random use and from several threads (the DNS workers) ---- */

static size_t s_base_len;
static uint8_t s_base[64];

/* An answer of len bytes for key k: a cacheable response, then bytes only (k, len) decide,
 * so a reader can check what it got whoever wrote it. */
static void stress_msg(uint8_t *m, uint32_t k, size_t len)
{
    memcpy(m, s_base, s_base_len);
    for (size_t j = s_base_len; j < len; j++)
        m[j] = (uint8_t)(k * 31 + j * 7 + len);
}

static int stress_key(uint32_t k, uint8_t *out)
{
    char s[64];
    snprintf(s, sizeof(s), "%s%u.stress.test", k % 3 ? "h" : "a-label-long-enough-to-cross-a-chunk-", k);
    return N(s, out);
}

static uint32_t lcg(uint32_t *x) { return *x = *x * 1664525u + 1013904223u; }

typedef struct {
    cache_t *c;
    uint32_t seed;
    int bad;
} stress_arg_t;

static void *stress_thread(void *p)
{
    stress_arg_t *a = p;
    static __thread uint8_t m[4096], got[4096];
    for (int i = 0; i < 20000; i++) {
        uint32_t r = lcg(&a->seed) >> 8, k = r % 200;
        uint8_t key[256];
        int kl = stress_key(k, key);
        size_t gl;
        uint32_t age;
        if (r & 0x10000) {
            size_t len = s_base_len + (lcg(&a->seed) >> 8) % 3000;
            stress_msg(m, k, len);
            cache_put(a->c, key, kl, DNS_T_A, 1, 0, 100, m, len);
        } else if (cache_get(a->c, key, kl, DNS_T_A, 1, 0, 101, got, sizeof(got), &gl, &age)) {
            stress_msg(m, k, gl);
            a->bad += gl < s_base_len || memcmp(got, m, gl) != 0 || age != 1;
        }
        if (i % 5000 == 4999 && (r & 7) == 0)
            cache_flush(a->c);
    }
    return NULL;
}

static void test_cache_stress(void)
{
    s_base_len = upstream_resp(s_base, 0, true, false);
    static uint64_t block[8192]; /* 64 KB */
    cache_t *c = cache_new_in(block, sizeof(block), 128);
    CHECK(c != NULL);

    /* Against a model: every hit is the latest answer stored for its name, whole; the
     * answer just stored is always there; the chunks in use never pass the block. */
    struct {
        bool in;
        size_t len;
    } model[300] = { 0 };
    static uint8_t m[4096], got[4096];
    uint32_t x = 12345;
    int bad = 0, hits = 0;
    for (int i = 0; i < 50000; i++) {
        uint32_t r = lcg(&x) >> 8, k = r % 300;
        uint8_t key[256];
        int kl = stress_key(k, key);
        size_t gl;
        uint32_t age;
        if (r & 0x10000) {
            size_t len = s_base_len + (lcg(&x) >> 8) % 4000;
            stress_msg(m, k, len);
            cache_put(c, key, kl, DNS_T_A, 1, 0, 100, m, len);
            model[k].in = true;
            model[k].len = len;
            bad += !cache_get(c, key, kl, DNS_T_A, 1, 0, 100, got, sizeof(got), &gl, &age) || gl != len;
        } else if (cache_get(c, key, kl, DNS_T_A, 1, 0, 100, got, sizeof(got), &gl, &age)) {
            hits++;
            stress_msg(m, k, gl);
            bad += !model[k].in || gl != model[k].len || memcmp(got, m, gl) != 0;
        }
        cache_stats_t st;
        cache_get_stats(c, &st);
        bad += st.entries > 128 || st.bytes > sizeof(block);
    }
    CHECK(bad == 0 && hits > 1000);
    /* Expired answers go when asked for, and their room is used again. */
    cache_stats_t st;
    cache_get_stats(c, &st);
    for (uint32_t k = 0; k < 300; k++) {
        uint8_t key[256];
        size_t gl;
        uint32_t age;
        int kl = stress_key(k, key);
        CHECK(!cache_get(c, key, kl, DNS_T_A, 1, 0, 100 + 301, got, sizeof(got), &gl, &age));
    }
    cache_stats_t st2;
    cache_get_stats(c, &st2);
    CHECK(st2.entries == 0 && st2.bytes == 0 && st.entries > 0);

    /* Four threads at once, as the DNS workers use it. */
    pthread_t t[4];
    stress_arg_t a[4];
    for (int i = 0; i < 4; i++) {
        a[i] = (stress_arg_t){ c, 777u * (uint32_t)(i + 1), 0 };
        pthread_create(&t[i], NULL, stress_thread, &a[i]);
    }
    for (int i = 0; i < 4; i++) {
        pthread_join(t[i], NULL);
        CHECK(a[i].bad == 0);
    }
    cache_get_stats(c, &st);
    CHECK(st.entries <= 128 && st.bytes <= sizeof(block));
}

static void test_query_parse(void)
{
    uint8_t qb[512];
    dns_query_t q;
    size_t ql = make_query(qb, "www.example.test", DNS_T_A, false);
    CHECK(dns_query_parse(qb, ql, &q) == 0 && !q.has_edns && q.qtype == DNS_T_A);
    CHECK(dns_query_parse(qb, ql - 1, &q) == DNS_R_FORMERR);
    wr16(qb + 4, 2);
    CHECK(dns_query_parse(qb, ql, &q) == DNS_R_FORMERR);

    /* error response keeps ID, question and opcode */
    ql = make_query(qb, "x.test", DNS_T_A, true);
    dns_query_parse(qb, ql, &q);
    uint8_t out[512];
    size_t n = dns_make_error(&q, out, sizeof(out), DNS_R_REFUSED, 0);
    parsed_t p;
    CHECK(parse_resp(out, n, &p) && p.h.id == 0x1234 && DNS_RCODE(p.h.flags) == DNS_R_REFUSED && p.h.ar == 1);
}

/* Releases signed by tools/release.py (see gen_release_vectors.py) verify here. */
/* ---- blocklist: the C lookup against files and answers from the Go compiler ---- */

static int s_bl_reads;

static const uint8_t *bl_read_ram(void *ctx, uint32_t off)
{
    s_bl_reads++;
    return (const uint8_t *)ctx + off;
}

static const uint8_t *bl_read_fail(void *ctx, uint32_t off) { return NULL; }

/* The RAM tier's buffer: the file from its front's end on. */
static size_t s_bl_front;
static const uint8_t *bl_read_back(void *ctx, uint32_t off)
{
    s_bl_reads++;
    return (const uint8_t *)ctx + (off - s_bl_front);
}

/* One table check from the bench-only stages, put together by hand. */
static bool bl_stage_has(const bl_t *b, const uint8_t *file, int t, uint64_t h)
{
    if (!bl_xor_maybe(b, t, h))
        return false;
    uint32_t lo = bl_index_find(b, t, h);
    if (lo == 0)
        return false;
    uint64_t first = b->t[t].index[lo - 1];
    return first == h || bl_sector_has(file + b->t[t].sectors_off + (lo - 1) * BL_SECTOR, h - first);
}

/* Every query's bl_blocked and bl_verdict against the Go compiler's verdicts; how many differ. */
static int bl_wrong(const bl_t *b, const uint8_t *want, bl_stats_t *st)
{
    uint8_t q[DNS_MAX_NAME];
    int wrong = 0;
    for (size_t i = 0; i < sizeof(blv_queries) / sizeof(*blv_queries); i++) {
        N(blv_queries[i], q);
        wrong += bl_blocked(b, q, st) != (want[i] == BL_BLOCK);
        wrong += bl_verdict(b, q, st) != want[i];
    }
    return wrong;
}

static void test_blocklist_file(const uint8_t *file, size_t len, const uint8_t *want)
{
    bl_t b;
    uint8_t q[DNS_MAX_NAME];
    CHECK(bl_open(&b, file, len, len, bl_read_ram, (void *)file, 0) == NULL);
    CHECK(b.allow && b.t[BL_ALLOW_EXACT].hashes && b.t[BL_ALLOW_SUFFIX].hashes);
    for (int t = 0; t < BL_TABLES; t++)
        CHECK((b.t[t].xor != NULL) == (file[10] != 0));

    /* RAM tier: the whole file. */
    CHECK(bl_wrong(&b, want, NULL) == 0);

    /* Case doesn't matter: the same names in upper case on the wire. */
    int wrong = 0;
    for (size_t i = 0; i < sizeof(blv_queries) / sizeof(*blv_queries); i++) {
        if (N(blv_queries[i], q) <= 0)
            continue;
        for (uint8_t *p = q; *p; p += 1 + *p)
            for (unsigned j = 1; j <= *p; j++)
                if (p[j] >= 'a' && p[j] <= 'z')
                    p[j] -= 32;
        wrong += bl_verdict(&b, q, NULL) != want[i];
    }
    CHECK(wrong == 0);

    /* The bench-only stages, put back together by hand: same answers. From the whole name
     * out, the first level that matches decides, allow before block. */
    wrong = 0;
    for (size_t i = 0; i < sizeof(blv_queries) / sizeof(*blv_queries); i++) {
        N(blv_queries[i], q);
        uint64_t hs[64];
        size_t k = bl_name_hashes(&b, q, hs, 64);
        int v = BL_NONE;
        for (size_t j = k; j-- > 0 && v == BL_NONE;) {
            bool whole = j == k - 1;
            if (bl_stage_has(&b, file, BL_ALLOW_SUFFIX, hs[j]) || (whole && bl_stage_has(&b, file, BL_ALLOW_EXACT, hs[j])))
                v = BL_ALLOW;
            else if (bl_stage_has(&b, file, BL_SUFFIX, hs[j]) || (whole && bl_stage_has(&b, file, BL_EXACT, hs[j])))
                v = BL_BLOCK;
        }
        wrong += v != want[i];
    }
    CHECK(wrong == 0);

    /* SD tier: only the front in memory, sectors read one at a time; same answers. */
    size_t front = bl_front_len(file);
    CHECK(front > BL_HEADER && front < len);
    uint8_t *copy = malloc(front);
    memcpy(copy, file, front);
    CHECK(bl_open(&b, copy, front, len, bl_read_ram, (void *)file, 0) == NULL);
    s_bl_reads = 0;
    bl_stats_t st = { 0 };
    CHECK(bl_wrong(&b, want, &st) == 0);
    CHECK(st.reads == (uint32_t)s_bl_reads && st.errors == 0);

    /* Indexes moved out: the front's copies can go, the answers stay. */
    uint64_t *idx = malloc(bl_index_size(&b));
    size_t nsec = 0;
    for (int t = 0; t < BL_TABLES; t++)
        nsec += b.t[t].sectors;
    CHECK(bl_index_size(&b) == 8 * nsec);
    bl_table_t old[BL_TABLES];
    memcpy(old, b.t, sizeof(old));
    bl_index_move(&b, idx);
    for (int i = 0; i < BL_TABLES; i++)
        memset((void *)old[i].index, 0xff, 8 * (size_t)old[i].sectors);
    CHECK(bl_wrong(&b, want, NULL) == 0);
    free(idx);
    memcpy(copy, file, front);

    /* RAM tier: opened without the filter, keeping only the indexes (moved out) and the
     * sectors. The front is freed before any lookup, so ASan catches a read of the filter
     * or anything else in it. Same answers; every check goes to the index. */
    uint8_t *front_copy = malloc(front), *back = malloc(len - front);
    memcpy(front_copy, file, front);
    memcpy(back, file + front, len - front);
    CHECK(bl_open(&b, front_copy, front, len, bl_read_back, back, BL_NO_XOR) == NULL);
    for (int t = 0; t < BL_TABLES; t++)
        CHECK(b.t[t].xor == NULL);
    idx = malloc(bl_index_size(&b));
    bl_index_move(&b, idx);
    free(front_copy);
    s_bl_front = front;
    memset(&st, 0, sizeof(st));
    CHECK(bl_wrong(&b, want, &st) == 0);
    CHECK(st.filtered == 0 && st.errors == 0 && st.reads > 0);
    free(idx);
    free(back);

    /* A card that can't be read blocks less, never more: an unreadable allow sector counts
     * as an allow. */
    CHECK(bl_open(&b, copy, front, len, bl_read_fail, NULL, 0) == NULL);
    for (size_t i = 0; i < sizeof(blv_queries) / sizeof(*blv_queries); i++) {
        N(blv_queries[i], q);
        if (bl_blocked(&b, q, NULL))
            CHECK(want[i] == BL_BLOCK);
    }

    /* A version 1 file (the block tables only, as before allowlists) still opens: the same
     * file with its version byte set back has no allow tables, so it blocks every name the
     * list blocks and some it allows, and nothing no entry matches. */
    memcpy(copy, file, front);
    copy[8] = 1;
    CHECK(bl_open(&b, copy, front, len, bl_read_ram, (void *)file, 0) == NULL);
    CHECK(!b.allow && b.t[BL_ALLOW_EXACT].sectors == 0 && b.t[BL_ALLOW_SUFFIX].sectors == 0);
    CHECK(bl_index_size(&b) == 8 * ((size_t)b.t[0].sectors + b.t[1].sectors));
    wrong = 0;
    int allowed_blocked = 0;
    for (size_t i = 0; i < sizeof(blv_queries) / sizeof(*blv_queries); i++) {
        N(blv_queries[i], q);
        bool bl = bl_blocked(&b, q, NULL);
        wrong += (want[i] == BL_BLOCK && !bl) || (want[i] == BL_NONE && bl) || bl_verdict(&b, q, NULL) == BL_ALLOW;
        allowed_blocked += want[i] == BL_ALLOW && bl;
    }
    CHECK(wrong == 0 && allowed_blocked > 0);
    memcpy(copy, file, front);

    /* Damaged files are refused. */
    CHECK(bl_open(&b, file, len, len - BL_SECTOR, bl_read_ram, (void *)file, 0) != NULL);
    CHECK(bl_open(&b, file, BL_HEADER - 1, len, bl_read_ram, (void *)file, 0) != NULL);
    uint8_t *odd = malloc(front + 4);
    memcpy(odd + 4, file, front);
    CHECK(bl_open(&b, odd + 4, front, len, bl_read_ram, (void *)file, 0) != NULL);
    free(odd);
    copy[8] = 3;
    CHECK(bl_open(&b, copy, front, len, bl_read_ram, (void *)file, 0) != NULL);
    memcpy(copy, "ESPDNSXX", 8);
    CHECK(bl_open(&b, copy, front, len, bl_read_ram, (void *)file, 0) != NULL);
    free(copy);
}

/* The lookup's first, plain version (one bit or byte at a time), kept to check the fast one
 * against on random sectors, filters and messages. */
static uint64_t ref_getbits(const uint8_t *d, size_t len, uint32_t pos, unsigned n)
{
    uint64_t v = 0;
    unsigned got = 0, sh = pos & 7;
    for (size_t i = pos >> 3; got < n; i++, sh = 0) {
        uint64_t c = i < len ? d[i] : 0;
        v |= (c >> sh) << got;
        got += 8 - sh;
    }
    return n == 64 ? v : v & ((1ULL << n) - 1);
}

static bool ref_sector_has(const uint8_t *sec, uint64_t d)
{
    const uint8_t *bits = sec + 2;
    const size_t len = BL_SECTOR - 2, nbits = len * 8;
    unsigned m = sec[0], l = sec[1];
    if (m == 0 || l > 64)
        return false;
    uint64_t hb = l == 64 ? 0 : d >> l, low = l == 64 ? d : d & ((1ULL << l) - 1);
    if ((uint64_t)m * l >= nbits)
        return false;
    uint32_t pos = m * l;
    unsigned idx = 0;
    for (uint64_t zeros = 0; zeros < hb; pos++) {
        if (pos >= nbits)
            return false;
        if (ref_getbits(bits, len, pos, 1))
            idx++;
        else
            zeros++;
    }
    for (; idx < m && pos < nbits && ref_getbits(bits, len, pos, 1); idx++, pos++) {
        uint64_t v = ref_getbits(bits, len, idx * l, l);
        if (v >= low)
            return v == low;
    }
    return false;
}

static uint64_t ref_rotl(uint64_t x, unsigned r) { return r ? (x << r) | (x >> (64 - r)) : x; }

static bool ref_xor_maybe(const bl_table_t *t, unsigned f, uint64_t h)
{
    uint64_t m = h + t->xor_seed;
    m ^= m >> 33;
    m *= 0xff51afd7ed558ccdULL;
    m ^= m >> 33;
    m *= 0xc4ceb9fe1a85ec53ULL;
    m ^= m >> 33;
    uint64_t x = (m ^ (m >> 32)) & ((1ULL << f) - 1);
    size_t len = (3ull * t->xor_seg * f + 7) / 8;
    for (unsigned i = 0; i < 3; i++) {
        uint32_t r = (uint32_t)ref_rotl(m, 21 * i);
        uint64_t slot = (((uint64_t)r * t->xor_seg) >> 32) + (uint64_t)i * t->xor_seg;
        x ^= ref_getbits(t->xor, len, (uint32_t)(slot * f), f);
    }
    return x == 0;
}

static uint64_t ref_siphash(uint64_t k0, uint64_t k1, const uint8_t *p, size_t n)
{
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL, v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL, v3 = k1 ^ 0x7465646279746573ULL;
#define REF_ROUND()                                                                                                    \
    do {                                                                                                               \
        v0 += v1; v1 = ref_rotl(v1, 13); v1 ^= v0; v0 = ref_rotl(v0, 32);                                              \
        v2 += v3; v3 = ref_rotl(v3, 16); v3 ^= v2;                                                                     \
        v0 += v3; v3 = ref_rotl(v3, 21); v3 ^= v0;                                                                     \
        v2 += v1; v1 = ref_rotl(v1, 17); v1 ^= v2; v2 = ref_rotl(v2, 32);                                              \
    } while (0)
    uint64_t mw = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n)
            mw |= (uint64_t)n << 56;
        else
            mw |= (uint64_t)p[i] << (8 * (i & 7));
        if (i == n || (i & 7) == 7) {
            v3 ^= mw;
            REF_ROUND();
            REF_ROUND();
            v0 ^= mw;
            mw = 0;
        }
    }
    v2 ^= 0xff;
    for (int i = 0; i < 4; i++)
        REF_ROUND();
#undef REF_ROUND
    return v0 ^ v1 ^ v2 ^ v3;
}

static uint64_t s_rng = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void)
{
    s_rng ^= s_rng << 13;
    s_rng ^= s_rng >> 7;
    s_rng ^= s_rng << 17;
    return s_rng;
}

/* A well-formed sector of m rising offsets with l low bits each, their values in vals. */
static void make_sector(uint8_t *sec, unsigned m, unsigned l, uint64_t *vals)
{
    memset(sec, 0, BL_SECTOR);
    sec[0] = (uint8_t)m;
    sec[1] = (uint8_t)l;
    uint8_t *bits = sec + 2;
    uint64_t prev = 0, gap = l < 54 ? 3ull << l : 1ull << 55; /* m gaps stay below 2^64 */
    for (unsigned i = 0; i < m; i++) {
        prev += 1 + rnd() % gap;
        vals[i] = prev;
    }
    uint32_t hpos = m * l;
    uint64_t lasthb = 0;
    for (unsigned i = 0; i < m; i++) {
        uint64_t hb = l == 64 ? 0 : vals[i] >> l;
        for (unsigned k = 0; k < l; k++)
            if ((vals[i] >> k) & 1)
                bits[(i * l + k) >> 3] |= 1 << ((i * l + k) & 7);
        hpos += (uint32_t)(hb - lasthb); /* zeros, one per step of the high part */
        lasthb = hb;
        if (hpos < (BL_SECTOR - 2) * 8)
            bits[hpos >> 3] |= 1 << (hpos & 7);
        hpos++;
    }
}

static void test_blocklist_random(void)
{
    static uint8_t sec[BL_SECTOR];
    uint64_t vals[256];
    int wrong = 0;
    for (int it = 0; it < 20000; it++) {
        unsigned kind = it % 4;
        if (kind == 0) { /* random bytes: anything the reader might meet */
            for (int i = 0; i < BL_SECTOR; i++)
                sec[i] = (uint8_t)rnd();
            if (it % 3 == 0)
                sec[1] %= 66;
            if (it % 5 == 0)
                sec[0] %= 8;
            for (int j = 0; j < 20; j++) {
                uint64_t d = rnd() >> (rnd() % 64);
                wrong += bl_sector_has(sec, d) != ref_sector_has(sec, d);
            }
            continue;
        }
        /* well-formed sectors, small and large l, filled to the end or not */
        unsigned l = kind == 1 ? rnd() % 65 : kind == 2 ? rnd() % 8 : 20 + rnd() % 30;
        unsigned maxm = (BL_SECTOR - 2) * 8 / (l + 2);
        unsigned m = maxm > 255 ? 255 : maxm;
        m = it % 7 == 0 ? m : rnd() % (m + 1);
        make_sector(sec, m, l, vals);
        for (unsigned i = 0; i < m; i++) {
            uint64_t d = vals[i];
            wrong += bl_sector_has(sec, d) != ref_sector_has(sec, d);
            wrong += bl_sector_has(sec, d + 1) != ref_sector_has(sec, d + 1);
            wrong += bl_sector_has(sec, d - 1) != ref_sector_has(sec, d - 1);
        }
        for (int j = 0; j < 10; j++) {
            uint64_t d = rnd() >> (rnd() % 64);
            wrong += bl_sector_has(sec, d) != ref_sector_has(sec, d);
        }
    }
    CHECK(wrong == 0);

    /* Xor filters of random bytes, every width, probes near the end included. */
    static uint8_t filt[3 * 64 * 16 / 8 + 1];
    for (size_t i = 0; i < sizeof(filt); i++)
        filt[i] = (uint8_t)rnd();
    wrong = 0;
    for (unsigned f = 1; f <= 16; f++) {
        bl_t b = { .xor_bits = (uint8_t)f };
        b.t[0].sectors = 1;
        b.t[0].xor = filt;
        for (int it = 0; it < 2000; it++) {
            b.t[0].xor_seg = 1 + rnd() % 64;
            b.t[0].xor_seed = rnd();
            uint64_t h = rnd();
            wrong += bl_xor_maybe(&b, 0, h) != ref_xor_maybe(&b.t[0], f, h);
        }
    }
    CHECK(wrong == 0);

    /* SipHash of every length up to 80. */
    uint8_t msg[80];
    wrong = 0;
    for (int it = 0; it < 50; it++) {
        uint64_t k0 = rnd(), k1 = rnd();
        for (size_t i = 0; i < sizeof(msg); i++)
            msg[i] = (uint8_t)rnd();
        for (size_t n = 0; n <= sizeof(msg); n++)
            wrong += bl_siphash(k0, k1, msg, n) != ref_siphash(k0, k1, msg, n);
    }
    CHECK(wrong == 0);
}

/* The precedence rules, case by case (blv_prec in blocklist_vectors.h says why each). */
static void test_blocklist_precedence(void)
{
    bl_t b;
    uint8_t q[DNS_MAX_NAME];
    const uint8_t *f = blv_prec_file;
    CHECK(bl_open(&b, f, sizeof(blv_prec_file), sizeof(blv_prec_file), bl_read_ram, (void *)f, 0) == NULL);
    for (size_t i = 0; i < sizeof(blv_prec) / sizeof(*blv_prec); i++) {
        CHECK(N(blv_prec[i].q, q) > 0);
        bl_verdict_t v = bl_verdict(&b, q, NULL);
        bool bl = bl_blocked(&b, q, NULL);
        if (v != blv_prec[i].want || bl != (blv_prec[i].want == BL_BLOCK))
            printf("  %s: verdict %d, blocked %d, want %d\n", blv_prec[i].q, v, bl, blv_prec[i].want);
        CHECK(v == blv_prec[i].want && bl == (blv_prec[i].want == BL_BLOCK));
    }
}

static void test_blocklist(void)
{
    /* SipHash reference vectors: key 00..0f, message 00..n-1. */
    uint8_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = (uint8_t)i;
    const uint64_t k0 = 0x0706050403020100ULL, k1 = 0x0f0e0d0c0b0a0908ULL;
    CHECK(bl_siphash(k0, k1, m, 0) == 0x726fdb47dd0e0e31ULL);
    CHECK(bl_siphash(k0, k1, m, 1) == 0x74f839c593dc67fdULL);
    CHECK(bl_siphash(k0, k1, m, 8) == 0x93f5f5799a932462ULL);
    CHECK(bl_siphash(k0, k1, m, 15) == 0xa129ca6149be45e5ULL);

    test_blocklist_file(blv_f44_file, sizeof(blv_f44_file), blv_f44_verdict);
    test_blocklist_file(blv_f20_file, sizeof(blv_f20_file), blv_f20_verdict);
    test_blocklist_precedence();
    test_blocklist_random();
}

static void test_release(void)
{
    rel_trust_t t = { .keys = { V_KEY0, V_KEY1 }, .board = V_BOARD };
    memcpy(t.node_id, V_NODE, 6);
    rel_manifest_t m;
    uint8_t h[REL_HEADER_LEN], sha[32];

    CHECK(rel_verify(V_FW, &t, 999, UINT64_MAX, &m) == NULL);
    CHECK(m.kind == REL_FIRMWARE && m.key_id == 0 && m.seq == 1000);
    CHECK(m.payload_len == sizeof(V_FW_PAYLOAD) && strcmp(m.board, V_BOARD) == 0);
    mbedtls_sha256(V_FW_PAYLOAD, sizeof(V_FW_PAYLOAD), sha, 0);
    CHECK(memcmp(m.sha256, sha, 32) == 0);

    /* replay: seq must rise */
    CHECK(rel_verify(V_FW, &t, 1000, UINT64_MAX, &m) != NULL);
    CHECK(rel_verify(V_FW, &t, UINT64_MAX, UINT64_MAX, &m) != NULL);

    /* another node, another board */
    rel_trust_t other = t;
    other.node_id[5] ^= 1;
    CHECK(rel_verify(V_FW, &other, 0, UINT64_MAX, &m) != NULL);
    other = t;
    other.board = "test-boar";
    const char *why = rel_verify(V_FW, &other, 0, UINT64_MAX, &m);
    CHECK(why && strstr(why, "another chip image"));

    /* a transitional image: its chip image name, or the board name the release names (what
     * firmware from before board definitions checked) */
    other.board = "esp32s3-octal";
    other.board_alt = V_BOARD;
    CHECK(rel_verify(V_FW, &other, 0, UINT64_MAX, &m) == NULL);
    other.board_alt = "test-boar";
    CHECK(rel_verify(V_FW, &other, 0, UINT64_MAX, &m) != NULL);

    /* recovery key, addressed to any node, so it also passes on another node */
    CHECK(rel_verify(V_BL, &t, 0, UINT64_MAX, &m) == NULL && m.kind == REL_BLOCKLIST && m.key_id == 1);
    other = t;
    other.node_id[0] = 0x02;
    CHECK(rel_verify(V_BL, &other, 0, UINT64_MAX, &m) == NULL);
    /* ... but not when that key slot is empty, or the wrong key is in it */
    other = t;
    other.keys[1] = NULL;
    CHECK(rel_verify(V_BL, &other, 0, UINT64_MAX, &m) != NULL);
    other.keys[1] = V_KEY0;
    CHECK(rel_verify(V_BL, &other, 0, UINT64_MAX, &m) != NULL);

    /* any change to the manifest or signature fails */
    for (size_t i = 0; i < REL_HEADER_LEN; i++) {
        memcpy(h, V_FW, REL_HEADER_LEN);
        h[i] ^= 0x01;
        if (rel_verify(h, &t, 0, UINT64_MAX, &m) == NULL) {
            fprintf(stderr, "FAIL: flipped header byte %zu still verifies\n", i);
            s_fail++;
        }
    }
    /* key_id changed to the other slot: signature no longer matches */
    memcpy(h, V_FW, REL_HEADER_LEN);
    h[9] = 1;
    CHECK(rel_verify(h, &t, 0, UINT64_MAX, &m) != NULL);

    /* validly signed, but uses reserved bytes this firmware doesn't understand */
    CHECK(rel_verify(V_RESERVED, &t, 0, UINT64_MAX, &m) != NULL);
    CHECK(strcmp(rel_kind_name(REL_BLOCKLIST), "blocklist") == 0);

    /* issue #55: a seq above what the node can vouch for is refused, after the signature
     * (V_FW's seq is 1000), and up to it taken */
    CHECK(rel_verify(V_FW, &t, 0, 1000, &m) == NULL);
    CHECK(rel_verify(V_FW, &t, 0, 999, &m) == rel_why_ahead && m.seq == 1000);
    memcpy(h, V_FW, REL_HEADER_LEN);
    h[REL_MANIFEST_LEN] ^= 1;
    why = rel_verify(h, &t, 0, 0, &m); /* the signature is checked first */
    CHECK(why && strstr(why, "bad signature"));
}

/* The highest seq a node takes (rel_seq_limit, issue #55): its clock and a day once SNTP
 * set it, no limit before that. */
static void test_seq_limit(void)
{
    const uint64_t now = 1800000000000ULL;
    rel_trust_t t = { .keys = { V_KEY0, V_KEY1 }, .board = V_BOARD };
    memcpy(t.node_id, V_NODE, 6);
    rel_manifest_t m;
    /* clock set: the clock and a day */
    CHECK(REL_SEQ_AHEAD_MS == 86400000ULL);
    CHECK(rel_seq_limit(true, now) == now + REL_SEQ_AHEAD_MS);
    CHECK(rel_seq_limit(true, 0) == REL_SEQ_AHEAD_MS);
    /* saturates */
    CHECK(rel_seq_limit(true, UINT64_MAX - 5) == UINT64_MAX);
    /* a signer misled into near 2^64 (a spoofed /status) is refused by a node with its clock
     * set */
    CHECK(UINT64_MAX - 1 > rel_seq_limit(true, now));
    /* not set: no limit, whatever the clock reads (a node that never syncs still takes every
     * release above the seq it holds; the signers bound the seq there) */
    CHECK(rel_seq_limit(false, 0) == UINT64_MAX);
    CHECK(rel_seq_limit(false, now) == UINT64_MAX);
    CHECK(rel_verify(V_FW, &t, 999, rel_seq_limit(false, 0), &m) == NULL && m.seq == 1000);
    CHECK(rel_verify(V_FW, &t, 1000, rel_seq_limit(false, 0), &m) != NULL); /* still above the last */
    /* set: a seq within the day ahead taken (the refusal past it: test_release) */
    CHECK(rel_verify(V_FW, &t, 0, rel_seq_limit(true, 0), &m) == NULL);
}

/* ---- the blocking service's portable core (block.c) ---- */

static void *t_alloc(size_t n) { return malloc(n ? n : 8); }
static const blk_alloc_t s_t_alloc = { t_alloc, t_alloc, free };
static char s_tmp[64];

/* A list file written to disk and loaded in a tier, as the node loads its slots. */
static blk_list_t *t_load(const uint8_t *file, size_t len, blk_tier_t tier)
{
    char path[96];
    snprintf(path, sizeof(path), "%s/list.bin", s_tmp);
    FILE *f = fopen(path, "wb");
    assert(f && fwrite(file, 1, len, f) == len);
    fclose(f);
    rel_manifest_t m = { .kind = REL_BLOCKLIST, .seq = 7, .payload_len = len };
    blk_list_t *l = NULL;
    int fd = open(path, O_RDONLY);
    blk_load(fd, &m, tier, &s_t_alloc, &l);
    unlink(path); /* the SD tier keeps reading through its open fd */
    return l;
}

static bool t_cname_is(void *ctx, const uint8_t *name)
{
    uint8_t want[DNS_MAX_NAME];
    int wl = N((const char *)ctx, want);
    int len = 0;
    while (name[len])
        len += name[len] + 1;
    return dns_name_eq(name, len + 1, want, wl);
}

static int s_t_calls;
static bool t_cname_none(void *ctx, const uint8_t *name)
{
    s_t_calls++;
    return false;
}

typedef struct {
    const uint8_t *msg;
    size_t len, off;
} t_src_t;

static bool t_recv(void *ctx, uint8_t *buf, size_t n)
{
    t_src_t *s = ctx;
    if (s->off + n > s->len)
        return false;
    memcpy(buf, s->msg + s->off, n);
    s->off += n;
    return true;
}

static void test_block_answer(void)
{
    uint8_t qb[512], out[512];
    dns_query_t q;
    parsed_t p;
    static const uint16_t types[] = { DNS_T_A, DNS_T_AAAA, DNS_T_TXT, 65 /* HTTPS */ };
    for (int nx = 0; nx < 2; nx++) {
        for (size_t i = 0; i < sizeof(types) / sizeof(*types); i++) {
            size_t ql = make_query(qb, "Ads.Example.com", types[i], true);
            CHECK(dns_query_parse(qb, ql, &q) == 0);
            dns_builder_t b;
            dnsb_init(&b, out, sizeof(out), 1232, &q, DNS_F_QR | DNS_F_RD | DNS_F_RA);
            dnsb_opt(&b, 1232, q.do_bit);
            int rc = blk_answer(&b, &q, nx, 10);
            dnsb_set_rcode(&b, rc);
            size_t n = dnsb_finish(&b);
            CHECK(parse_resp(out, n, &p) && p.h.id == 0x1234 && DNS_RCODE(p.h.flags) == rc);
            CHECK(p.h.ns == 0 && p.h.ar == 1); /* no SOA: not cached downstream */
            bool addr = !nx && (types[i] == DNS_T_A || types[i] == DNS_T_AAAA);
            CHECK(rc == (nx ? DNS_R_NXDOMAIN : DNS_R_NOERROR));
            CHECK(p.h.an == (addr ? 1 : 0));
            if (addr) {
                static const uint8_t zero[16];
                CHECK(p.rr[0].type == types[i] && p.rr[0].ttl == 10 && name_is(&p.rr[0], "ads.example.com"));
                CHECK(p.rr[0].rdlen == (types[i] == DNS_T_A ? 4 : 16) && !memcmp(out + p.rr[0].rdata_off, zero, p.rr[0].rdlen));
            }
        }
    }

    /* CNAME targets in an upstream answer */
    size_t ql = make_query(qb, "www.site.test", DNS_T_A, false);
    CHECK(dns_query_parse(qb, ql, &q) == 0);
    dns_builder_t b;
    uint8_t t1[DNS_MAX_NAME], t2[DNS_MAX_NAME], a[4] = { 192, 0, 2, 1 };
    int l1 = N("cdn.site.test", t1), l2 = N("x.tracker.test", t2);
    dnsb_init(&b, out, sizeof(out), 1232, &q, DNS_F_QR);
    dnsb_rr(&b, DNSB_ANSWER, q.qname, q.qname_len, DNS_T_CNAME, DNS_C_IN, 60, t1, (uint16_t)l1);
    dnsb_rr(&b, DNSB_ANSWER, t1, l1, DNS_T_CNAME, DNS_C_IN, 60, t2, (uint16_t)l2);
    dnsb_rr(&b, DNSB_ANSWER, t2, l2, DNS_T_A, DNS_C_IN, 60, a, 4);
    size_t n = dnsb_finish(&b);
    CHECK(blk_cname_any(out, n, t_cname_is, "x.tracker.test"));
    CHECK(blk_cname_any(out, n, t_cname_is, "cdn.site.test"));
    CHECK(!blk_cname_any(out, n, t_cname_is, "www.site.test")); /* the owner isn't a target */
    s_t_calls = 0;
    CHECK(!blk_cname_any(out, n, t_cname_none, NULL) && s_t_calls == 2);
    CHECK(!blk_cname_any(out, n - 3, t_cname_none, NULL)); /* malformed: no CNAMEs */

    /* A DNAME's target counts as a target too */
    ql = make_query(qb, "www.site.test", DNS_T_A, false);
    CHECK(dns_query_parse(qb, ql, &q) == 0);
    uint8_t own[DNS_MAX_NAME], dt[DNS_MAX_NAME], syn[DNS_MAX_NAME];
    int lo = N("site.test", own), ld = N("tracker.test", dt), ls = N("www.tracker.test", syn);
    dnsb_init(&b, out, sizeof(out), 1232, &q, DNS_F_QR);
    dnsb_rr(&b, DNSB_ANSWER, own, lo, DNS_T_DNAME, DNS_C_IN, 60, dt, (uint16_t)ld);
    dnsb_rr(&b, DNSB_ANSWER, q.qname, q.qname_len, DNS_T_CNAME, DNS_C_IN, 60, syn, (uint16_t)ls);
    n = dnsb_finish(&b);
    CHECK(blk_cname_any(out, n, t_cname_is, "tracker.test"));
    CHECK(blk_cname_any(out, n, t_cname_is, "www.tracker.test"));
    s_t_calls = 0;
    CHECK(!blk_cname_any(out, n, t_cname_none, NULL) && s_t_calls == 2);
}

static void test_block_decide(void)
{
    uint8_t q[DNS_MAX_NAME];
    const size_t nq = sizeof(blv_queries) / sizeof(*blv_queries);
    for (int f = 0; f < 2; f++) {
        const uint8_t *file = f ? blv_f20_file : blv_f44_file;
        size_t len = f ? sizeof(blv_f20_file) : sizeof(blv_f44_file);
        const uint8_t *want = f ? blv_f20_verdict : blv_f44_verdict;
        blk_list_t *ram = t_load(file, len, BLK_TIER_RAM), *sd = t_load(file, len, BLK_TIER_SD);
        CHECK(ram && sd);
        if (!ram || !sd)
            return;
        CHECK(ram->fd < 0 && sd->fd >= 0 && ram->entries == sd->entries && ram->entries > 0);
        CHECK(ram->mem_bytes == len - ram->front_len && sd->mem_bytes == ram->front_len);
        for (int t = 0; t < BL_TABLES; t++)
            CHECK(ram->bl.t[t].xor == NULL && (sd->bl.t[t].xor != NULL) == (file[10] != 0));
        int wrong = 0;
        bl_stats_t st = { 0 };
        for (size_t i = 0; i < nq; i++) {
            N(blv_queries[i], q);
            blk_result_t list = want[i] == BL_BLOCK ? BLK_BLOCK : BLK_PASS;
            blk_result_t ovr = want[i] == BL_BLOCK ? BLK_BLOCK : want[i] == BL_ALLOW ? BLK_ALLOW : BLK_PASS;
            /* the main list in either tier: blocked or not */
            wrong += blk_decide(NULL, false, ram, q, NULL) != list;
            wrong += blk_decide(NULL, false, sd, q, &st) != list;
            /* paused: the list is skipped... */
            wrong += blk_decide(NULL, true, ram, q, NULL) != BLK_PASS;
            /* ...but not the overrides, whose allow also skips the list */
            wrong += blk_decide(ram, true, ram, q, NULL) != ovr;
            wrong += blk_decide(sd, false, ram, q, NULL) != ovr;
            wrong += blk_decide(NULL, false, NULL, q, NULL) != BLK_PASS;
        }
        CHECK(wrong == 0 && st.errors == 0 && st.reads > 0);

        /* A card that stops reading: lookup errors, and nothing blocked that shouldn't be. */
        close(sd->fd);
        sd->fd = -1;
        memset(&st, 0, sizeof(st));
        wrong = 0;
        for (size_t i = 0; i < nq; i++) {
            N(blv_queries[i], q);
            wrong += blk_decide(NULL, false, sd, q, &st) == BLK_BLOCK && want[i] != BL_BLOCK;
        }
        CHECK(wrong == 0 && st.errors > 0);
        blk_list_free(ram);
        blk_list_free(sd);
    }

    /* Damaged or foreign payloads aren't loaded. */
    uint8_t bad[sizeof(blv_prec_file)];
    memcpy(bad, blv_prec_file, sizeof(bad));
    memcpy(bad, "ESPDNSXX", 8);
    CHECK(t_load(bad, sizeof(bad), BLK_TIER_RAM) == NULL);
    CHECK(t_load(blv_prec_file, BL_SECTOR, BLK_TIER_SD) == NULL); /* cut short */
    blk_need_t need;
    CHECK(blk_plan(blv_f44_file, sizeof(blv_f44_file), &need) == NULL);
    CHECK(need.front == bl_front_len(blv_f44_file) && need.front + need.sectors == sizeof(blv_f44_file));
}

/* Lookups on several threads while the list under them is swapped: ASan catches a list
 * freed while a lookup still holds it. */
typedef struct {
    blk_ref_t *ref;
    volatile bool stop;
    int lookups;
} t_swap_t;

static void *t_lookups(void *arg)
{
    t_swap_t *s = arg;
    uint8_t q[DNS_MAX_NAME];
    const size_t nq = sizeof(blv_queries) / sizeof(*blv_queries);
    for (size_t i = 0; !s->stop; i++) {
        N(blv_queries[i % nq], q);
        blk_list_t *l = blk_get(s->ref);
        blk_result_t r = blk_decide(NULL, false, l, q, NULL);
        CHECK(!l || r == (blv_f44_verdict[i % nq] == BL_BLOCK ? BLK_BLOCK : BLK_PASS));
        blk_put(l);
        __atomic_fetch_add(&s->lookups, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

static void test_block_swap(void)
{
    t_swap_t s = { .ref = blk_ref_new() };
    CHECK(blk_get(s.ref) == NULL);
    pthread_t th[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&th[i], NULL, t_lookups, &s);
    for (int i = 0; i < 40; i++) {
        blk_swap(s.ref, t_load(blv_f44_file, sizeof(blv_f44_file), i % 2 ? BLK_TIER_SD : BLK_TIER_RAM));
        if (i % 10 == 9)
            blk_swap(s.ref, NULL); /* blocking off for a while */
        usleep(2000);
    }
    s.stop = true;
    for (int i = 0; i < 4; i++)
        pthread_join(th[i], NULL);
    CHECK(s.lookups > 0);

    /* A held list outlives its swap, and goes with its last reference. */
    blk_swap(s.ref, t_load(blv_f44_file, sizeof(blv_f44_file), BLK_TIER_RAM));
    blk_list_t *held = blk_get(s.ref);
    CHECK(held && held->refs == 2);
    blk_swap(s.ref, NULL);
    CHECK(held->refs == 1 && held->entries > 0);
    blk_put(held);
    free(s.ref);
}

static void test_block_slots(void)
{
    rel_trust_t t = { .keys = { V_KEY0, V_KEY1 }, .board = V_BOARD };
    memcpy(t.node_id, V_NODE, 6);
    char path[96];
    snprintf(path, sizeof(path), "%s/list.0", s_tmp);
    rel_manifest_t m, got;
    CHECK(rel_verify(V_BL, &t, 0, UINT64_MAX, &m) == NULL);

    /* stored: the payload, then the header */
    t_src_t src = { V_BL_PAYLOAD, sizeof(V_BL_PAYLOAD), 0 };
    CHECK(blk_slot_store(path, V_BL, &m, t_recv, &src) == NULL);
    struct stat sb;
    CHECK(stat(path, &sb) == 0 && (size_t)sb.st_size == sizeof(V_BL_PAYLOAD) + REL_HEADER_LEN);
    int fd = open(path, O_RDWR);
    CHECK(blk_slot_read(fd, &t, REL_BLOCKLIST, &got) == NULL && got.seq == 2000 &&
          got.payload_len == sizeof(V_BL_PAYLOAD));
    CHECK(blk_slot_hash(fd, &got) == NULL);
    CHECK(blk_slot_read(fd, &t, REL_OVERRIDES, &got) != NULL); /* another kind's slot */
    rel_trust_t other = t;
    other.keys[1] = NULL;
    CHECK(blk_slot_read(fd, &other, REL_BLOCKLIST, &got) != NULL); /* not signed by a key it trusts */
    /* Not a list file (the vector's payload is just bytes): never loaded. */
    blk_list_t *l = NULL;
    CHECK(blk_load(dup(fd), &m, BLK_TIER_RAM, &s_t_alloc, &l) != NULL && l == NULL);

    /* a payload byte changed on the card */
    uint8_t c = V_BL_PAYLOAD[3] ^ 1;
    CHECK(pwrite(fd, &c, 1, 3) == 1);
    CHECK(blk_slot_read(fd, &t, REL_BLOCKLIST, &got) == NULL && blk_slot_hash(fd, &got) != NULL);
    /* cut short, as by a power cut */
    CHECK(ftruncate(fd, (off_t)sizeof(V_BL_PAYLOAD) + 100) == 0);
    CHECK(blk_slot_read(fd, &t, REL_BLOCKLIST, &got) != NULL);
    CHECK(ftruncate(fd, 0) == 0);
    CHECK(blk_slot_read(fd, &t, REL_BLOCKLIST, &got) != NULL);
    close(fd);

    /* a payload that doesn't match its signed hash, or stops short, leaves no slot file */
    uint8_t wrong[sizeof(V_BL_PAYLOAD)];
    memcpy(wrong, V_BL_PAYLOAD, sizeof(wrong));
    wrong[0] ^= 1;
    src = (t_src_t){ wrong, sizeof(wrong), 0 };
    CHECK(blk_slot_store(path, V_BL, &m, t_recv, &src) != NULL && stat(path, &sb) != 0);
    src = (t_src_t){ V_BL_PAYLOAD, sizeof(V_BL_PAYLOAD) - 1, 0 };
    CHECK(blk_slot_store(path, V_BL, &m, t_recv, &src) != NULL && stat(path, &sb) != 0);
}

/* Which slot a boot loads, and whether that is a fall back (blocking.c, hosted.c). */
static void test_block_slot_order(void)
{
    int o[2];
    bool ok[2] = { true, true };
    uint64_t seq[2] = { 10, 20 };
    CHECK(blk_slot_order(ok, seq, 0, o) == 2 && o[0] == 1 && o[1] == 0); /* the newest first */
    seq[0] = 30;
    CHECK(blk_slot_order(ok, seq, 0, o) == 2 && o[0] == 0 && o[1] == 1);
    ok[0] = false; /* slot 0 corrupt: only slot 1 */
    CHECK(blk_slot_order(ok, seq, 0, o) == 1 && o[0] == 1);
    ok[1] = false;
    CHECK(blk_slot_order(ok, seq, 0, o) == 0);
    /* Reverted from seq 30: never that one, whichever slot it is in. */
    ok[0] = ok[1] = true;
    CHECK(blk_slot_order(ok, seq, 30, o) == 1 && o[0] == 1);
    ok[1] = false; /* the copy reverted to is gone: nothing, not the reverted one */
    CHECK(blk_slot_order(ok, seq, 30, o) == 0);

    /* The newest (seq 30, recorded) loaded: no fall back. An older one: a fall back, unless
     * a revert to it is in force (reverted from 30, the newest taken). */
    CHECK(!blk_slot_older(30, 30, 0));
    CHECK(blk_slot_older(20, 30, 0));
    CHECK(!blk_slot_older(20, 30, 30));
    /* A newer list came after the revert (40), and it is the one lost: a fall back. */
    CHECK(blk_slot_older(20, 40, 30));
    /* A slot newer than recorded (its seq not written): not older. Never sent one: no. */
    CHECK(!blk_slot_older(50, 40, 0) && !blk_slot_older(0, 0, 0));
}

/* What a revert may go back to (blocking.c, hosted.c): only an older copy in the other slot,
 * never the one reverted from nor one pushed since; and the kind its payload names. */
static void test_block_revert(void)
{
    char b[160];
    CHECK(blk_revert_check("zones", 1, NULL, 20, 30, 0, "newer", b, sizeof(b)) == NULL);
    CHECK(blk_revert_check("zones", 1, "missing", 0, 30, 0, "newer", b, sizeof(b)) == b &&
          !strcmp(b, "no previous zones to revert to: slot 1 is empty"));
    CHECK(blk_revert_check("list", 0, "slot does not match its signed hash", 0, 30, 0, "newer", b, sizeof(b)) == b &&
          !strcmp(b, "no previous list to revert to: slot 0 slot does not match its signed hash"));
    /* Reverted from 30, now on 20: the other slot holds the one left, which is not older. */
    CHECK(blk_revert_check("zones", 0, NULL, 30, 20, 30, "newer", b, sizeof(b)) == b &&
          !strcmp(b, "no previous zones to revert to: slot 0 holds seq 30, not older than seq 20 in use (reverted from)"));
    /* A newer copy pushed and not in use (it waits for a reboot), or the same seq. */
    CHECK(blk_revert_check("list", 0, NULL, 40, 30, 0, "waiting for a reboot", b, sizeof(b)) == b &&
          strstr(b, "seq 40, not older than seq 30 in use (waiting for a reboot)"));
    CHECK(blk_revert_check("overrides", 0, NULL, 30, 30, 0, "newer", b, sizeof(b)) == b && strstr(b, "(newer)"));
    /* A revert in force from another seq says newer, not reverted from. */
    CHECK(blk_revert_check("zones", 0, NULL, 40, 20, 30, "newer", b, sizeof(b)) == b && strstr(b, "(newer)"));

    const uint8_t zones[] = { BLK_CTL_REVERT, REL_ZONES }, list[] = { BLK_CTL_REVERT, REL_BLOCKLIST },
                  ovr[] = { BLK_CTL_REVERT, REL_OVERRIDES }, cfg[] = { BLK_CTL_REVERT, REL_CONFIG },
                  fw[] = { BLK_CTL_REVERT, REL_FIRMWARE }, flush[] = { BLK_CTL_FLUSH, REL_ZONES },
                  longer[] = { BLK_CTL_REVERT, REL_ZONES, 0 };
    CHECK(blk_ctl_revert_kind(zones, 2) == REL_ZONES && blk_ctl_revert_kind(list, 2) == REL_BLOCKLIST &&
          blk_ctl_revert_kind(ovr, 2) == REL_OVERRIDES);
    CHECK(!blk_ctl_revert_kind(cfg, 2) && !blk_ctl_revert_kind(fw, 2) && !blk_ctl_revert_kind(flush, 2) &&
          !blk_ctl_revert_kind(longer, 3) && !blk_ctl_revert_kind(zones, 1));
}

static void test_block(void)
{
    snprintf(s_tmp, sizeof(s_tmp), "/tmp/espdns-blkXXXXXX");
    CHECK(mkdtemp(s_tmp) != NULL);
    test_block_answer();
    test_block_decide();
    test_block_swap();
    test_block_slots();
    test_block_slot_order();
    test_block_revert();
    rmdir(s_tmp);
}

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    struct stat sb;
    char *buf = fstat(fileno(f), &sb) == 0 ? malloc((size_t)sb.st_size + 1) : NULL;
    *len = buf ? fread(buf, 1, (size_t)sb.st_size, f) : 0;
    if (buf)
        buf[*len] = 0;
    fclose(f);
    return buf;
}

static uint32_t ip4(const char *s);

static bool parse(const char *json, board_desc_t *b, char *err)
{
    return board_def_parse(json, strlen(json), b, err, 160);
}

static void test_board_defs(void)
{
    char err[160];
    board_desc_t b;

    /* The catalog's tested boards parse, with what their old C descriptions said. */
    static const char *const names[] = { "p4-ip101", "ws-s3-eth", "xiao-s3-sense" };
    for (int i = 0; i < 3; i++) {
        char path[256];
        size_t len;
        snprintf(path, sizeof(path), "%s/%s.json", BOARDS_DIR, names[i]);
        char *json = read_file(path, &len);
        CHECK(json);
        bool ok = board_def_parse(json, len, &b, err, sizeof(err));
        if (!ok)
            fprintf(stderr, "%s: %s\n", names[i], err);
        CHECK(ok && strcmp(b.name, names[i]) == 0);
        free(json);
    }
    CHECK(parse("{\"name\":\"p\",\"image\":\"esp32p4-rev1\",\"ethernet\":{\"kind\":\"emac\",\"phy\":\"ip101\","
                "\"addr\":1,\"reset\":51},\"sd\":{\"kind\":\"sdmmc\",\"slot\":0,\"width\":4,\"ldo\":4}}", &b, err));
    CHECK(b.eth.kind == BOARD_ETH_EMAC && b.eth.phy == BOARD_PHY_IP101 && b.eth.phy_reset == 51 &&
          b.eth.mdc == BOARD_NC && b.eth.rmii_clock == BOARD_CLK_DEFAULT);
    CHECK(b.sd.kind == BOARD_SD_SDMMC && b.sd.width == 4 && b.sd.ldo == 4 && b.led.kind == BOARD_LED_NONE);

    /* A classic ESP32 board: LAN8720 with its clock from GPIO0 and an oscillator enable pin. */
    CHECK(parse("{\"name\":\"wt32-eth01\",\"image\":\"esp32\",\"ethernet\":{\"kind\":\"emac\",\"phy\":\"lan87xx\","
                "\"addr\":1,\"power\":16,\"mdc\":23,\"mdio\":18,\"rmii_clock\":{\"mode\":\"in\",\"gpio\":0}}}", &b, err));
    CHECK(b.eth.phy == BOARD_PHY_LAN87XX && b.eth.power_pin == 16 && b.eth.rmii_clock == BOARD_CLK_IN &&
          b.eth.rmii_clock_gpio == 0);

    /* Malformed definitions say why. */
    CHECK(!parse("[1,2]", &b, err) && strstr(err, "not a JSON object"));
    CHECK(!parse("{\"image\":\"esp32\"}", &b, err) && strstr(err, "name: missing"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"ethernet\":{\"kind\":\"enc28j60\"}}", &b, err) &&
          strstr(err, "kind: unknown value"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32s3-octal\",\"ethernet\":{\"kind\":\"w5500\",\"spi_host\":2,"
                 "\"cs\":14}}", &b, err) && strstr(err, "no such SPI bus"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32s3-octal\",\"spi\":[{\"host\":2,\"sclk\":7,\"mosi\":9,"
                 "\"miso\":8}],\"sd\":{\"kind\":\"spi\",\"spi_host\":2,\"cs\":21},\"led\":{\"kind\":\"gpio\",\"pin\":21}}",
                 &b, err) && strstr(err, "GPIO 21 used twice"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"led\":{\"kind\":\"gpio\",\"pin\":99}}", &b, err) &&
          strstr(err, "out of range"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"wifi\":{\"tx_power_dbm\":25}}", &b, err) &&
          strstr(err, "tx_power_dbm"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"sd\":{\"kind\":\"sdmmc\",\"width\":2.5}}", &b, err) &&
          strstr(err, "not an integer"));
    CHECK(!parse("{\"name\":\"a-name-that-is-far-too-long\",\"image\":\"esp32\"}", &b, err) && strstr(err, "name"));
    /* Memory budgets: board data, the firmware's default when left out. */
    CHECK(parse("{\"name\":\"x\",\"image\":\"esp32\"}", &b, err) && b.mem.hosted_zones_kb == -1 && b.psram_mb == -1 &&
          b.mem.internal_kb == -1 && b.mem.cache_kb == -1 && b.mem.cache_entries == -1 && b.mem.blocklist_kb == -1 &&
          b.mem.blocklist_index_kb == -1 && b.mem.secondary_zones_kb == -1 && b.mem.fwd_pending == -1);
    CHECK(parse("{\"name\":\"x\",\"image\":\"esp32\",\"psram_mb\":8,\"memory\":{\"hosted_zones_kb\":256,"
                "\"internal_kb\":100,\"cache_kb\":2048,\"cache_entries\":4096,\"blocklist_kb\":3000,"
                "\"blocklist_index_kb\":0,\"secondary_zones_kb\":128}}", &b, err) &&
          b.mem.hosted_zones_kb == 256 && b.psram_mb == 8 && b.mem.internal_kb == 100 && b.mem.cache_kb == 2048 &&
          b.mem.cache_entries == 4096 && b.mem.blocklist_kb == 3000 && b.mem.blocklist_index_kb == 0 &&
          b.mem.secondary_zones_kb == 128);
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"memory\":{\"hosted_zones_kb\":8}}", &b, err) &&
          strstr(err, "hosted_zones_kb"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"memory\":{\"cache_entries\":4}}", &b, err) &&
          strstr(err, "cache_entries"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"memory\":{\"blocklist_kb\":0}}", &b, err) &&
          strstr(err, "blocklist_kb"));
    /* fwd_pending, a count: at least 2 (each half of the table has a slot), left out -1. */
    CHECK(parse("{\"name\":\"x\",\"image\":\"esp32\",\"memory\":{\"fwd_pending\":2}}", &b, err) &&
          b.mem.fwd_pending == 2);
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"memory\":{\"fwd_pending\":1}}", &b, err) &&
          strstr(err, "fwd_pending"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"memory\":{\"fwd_pending\":1025}}", &b, err) &&
          strstr(err, "fwd_pending"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"memory\":{\"internal_kb\":1.5}}", &b, err) &&
          strstr(err, "not an integer"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"psram_mb\":128}", &b, err) && strstr(err, "psram_mb"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"memory\":7}", &b, err) && strstr(err, "memory"));
    /* A key this firmware doesn't know (from a newer catalog) is left for the newer firmware. */
    CHECK(parse("{\"name\":\"x\",\"image\":\"esp32\",\"memory\":{\"query_log_kb\":64}}", &b, err));
    /* The node's address, which the builder adds when it flashes a node; DHCP only if asked. */
    CHECK(parse("{\"name\":\"x\",\"image\":\"esp32\"}", &b, err) && !b.net.set);
    CHECK(parse("{\"name\":\"x\",\"image\":\"esp32\",\"network\":{\"address\":\"192.0.2.52/25\","
                "\"gateway\":\"192.0.2.1\"}}", &b, err) &&
          b.net.set && !b.net.dhcp && b.net.ip == ip4("192.0.2.52") && b.net.netmask == ip4("255.255.255.128") &&
          b.net.gateway == ip4("192.0.2.1"));
    CHECK(parse("{\"name\":\"x\",\"image\":\"esp32\",\"network\":{\"address\":\"dhcp\"}}", &b, err) &&
          b.net.set && b.net.dhcp && !b.net.ip);
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"network\":{\"address\":\"203.0.113.5/24\","
                 "\"gateway\":\"192.0.2.1\"}}", &b, err) && strstr(err, "another address in the node's network"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"network\":{\"address\":\"203.0.113.5/24\"}}", &b, err) &&
          strstr(err, "gateway: required"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"network\":{\"gateway\":\"203.0.113.1\"}}", &b, err) &&
          strstr(err, "network.address: required"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"network\":{\"address\":\"dhcp\",\"dns\":1}}", &b, err) &&
          strstr(err, "network.dns: unknown setting"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"network\":\"dhcp\"}", &b, err) &&
          strstr(err, "network: an object"));

    /* The partition: header and CRC (vector: zlib.crc32(b"123456789") = 0xCBF43926). */
    CHECK(board_crc32((const uint8_t *)"123456789", 9) == 0xCBF43926u);
    static const char def[] = "{\"name\":\"x\",\"image\":\"esp32\"}";
    uint8_t part[BOARD_PART_SIZE];
    memset(part, 0xFF, sizeof(part));
    uint32_t n = sizeof(def) - 1, crc = board_crc32((const uint8_t *)def, n);
    memcpy(part, BOARD_PART_MAGIC, 4);
    part[4] = 1, part[5] = 0, part[6] = 0, part[7] = 0;
    for (int i = 0; i < 4; i++)
        part[8 + i] = (uint8_t)(n >> 8 * i), part[12 + i] = (uint8_t)(crc >> 8 * i);
    memcpy(part + BOARD_PART_HDR, def, n);
    const char *json, *why;
    size_t len;
    CHECK(board_part_open(part, sizeof(part), &json, &len, &why) && len == n && memcmp(json, def, n) == 0);
    CHECK(board_def_parse(json, len, &b, err, sizeof(err)) && strcmp(b.image, "esp32") == 0);
    part[BOARD_PART_HDR + 3] ^= 1;
    CHECK(!board_part_open(part, sizeof(part), &json, &len, &why) && strstr(why, "CRC"));
    uint8_t erased[BOARD_PART_SIZE];
    memset(erased, 0xFF, sizeof(erased));
    CHECK(!board_part_open(erased, sizeof(erased), &json, &len, &why) && strstr(why, "no board definition"));
}


/* ---- health ---- */

/* A node answering with everything working. */
static health_in_t healthy_in(void)
{
    health_in_t in = { 0 };
    in.enabled = SVC_ALL;
    in.uptime_ms = 60000;
    in.listening = in.answered = in.link = in.address = true;
    in.sd_slot = in.sd_mounted = true;
    in.heap_free = 200 * 1024;
    return in;
}

static void test_health(void)
{
    health_in_t in = healthy_in();
    health_t h = health_compute(&in);
    CHECK(h.state == HEALTH_HEALTHY && h.reasons == 0 && health_answering(h.state));

    /* Each degraded source alone, with its reason; still answering. */
    static const uint32_t deg[] = { HR_SD, HR_BLOCKING, HR_ZONE_EXPIRED, HR_ZONE_REFRESH,
                                    HR_LOW_MEMORY, HR_BOARD, HR_UPSTREAM, HR_CONFIG, HR_OLDER_COPY,
                                    HR_FWD_SLOW };
    for (size_t i = 0; i < sizeof(deg) / sizeof(*deg); i++) {
        in = healthy_in();
        switch (deg[i]) {
        case HR_SD: in.sd_mounted = false; break;
        case HR_BLOCKING: in.blocking = true; break;
        case HR_ZONE_EXPIRED: in.zones_expired = 1; break;
        case HR_ZONE_REFRESH: in.zones_failing = 2; break;
        case HR_LOW_MEMORY: in.heap_free = 1000; break;
        case HR_BOARD: in.board_missing = true; break;
        case HR_UPSTREAM: in.fwd.fails = 9; in.fwd.since_ms = 10000; break;
        case HR_FWD_SLOW: in.fwd.shed = 1; break;
        case HR_CONFIG: in.config_error = true; break;
        case HR_OLDER_COPY: in.older = SVC_BIT(SVC_BLOCKING); break;
        }
        h = health_compute(&in);
        CHECK(h.state == HEALTH_DEGRADED && h.reasons == deg[i] && health_answering(h.state));
        CHECK(deg[i] & HR_DEGRADED_MASK);
    }

    /* The SD card: no slot is not a fault; still mounting within the timeout isn't yet. */
    in = healthy_in();
    in.sd_slot = in.sd_mounted = false;
    CHECK(health_compute(&in).state == HEALTH_HEALTHY);
    in = healthy_in();
    in.sd_mounted = false;
    in.sd_pending = true;
    CHECK(health_compute(&in).state == HEALTH_HEALTHY);

    /* Forwarders: a few failures, or many in a short burst, aren't the forwarders failing. */
    in = healthy_in();
    in.fwd.fails = HEALTH_UPSTREAM_FAILS - 1;
    in.fwd.since_ms = 0;
    CHECK(health_compute(&in).state == HEALTH_HEALTHY);
    in.fwd.fails = 50;
    in.fwd.since_ms = in.uptime_ms - HEALTH_UPSTREAM_MS + 1;
    CHECK(health_compute(&in).state == HEALTH_HEALTHY);
    in.fwd.since_ms = in.uptime_ms - HEALTH_UPSTREAM_MS;
    CHECK(health_compute(&in).reasons == HR_UPSTREAM);

    /* Forwarders slow (#60): answering, but not fast enough for what the node is asked. */
    in = healthy_in();
    /* A query shed (past the default forwarders' cap) in the window (health_upstream_get). */
    in.fwd.shed = 1;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_DEGRADED && h.reasons == HR_FWD_SLOW && health_answering(h.state));
    char js[128];
    health_json(&h, js, sizeof(js));
    CHECK(!strcmp(js, "\"state\":\"degraded\",\"answering\":true,\"reasons\":[\"forwarders slow\"]"));
    in.fwd.shed = 0;
    CHECK(health_compute(&in).state == HEALTH_HEALTHY);
    /* More than half their cap held for 10 s, not less. */
    in.fwd.busy = true;
    in.fwd.busy_since_ms = in.uptime_ms - HEALTH_FWD_BUSY_MS + 1;
    CHECK(health_compute(&in).state == HEALTH_HEALTHY);
    in.fwd.busy_since_ms = in.uptime_ms - HEALTH_FWD_BUSY_MS;
    CHECK(health_compute(&in).reasons == HR_FWD_SLOW);
    in.fwd.busy = false;
    CHECK(health_compute(&in).state == HEALTH_HEALTHY);
    /* Over the window: more than half of at least HEALTH_FWD_SLOW_MIN slow or unanswered. */
    in.fwd.ended = HEALTH_FWD_SLOW_MIN - 1;
    in.fwd.slow = HEALTH_FWD_SLOW_MIN - 1;
    CHECK(health_compute(&in).state == HEALTH_HEALTHY); /* too few to say */
    in.fwd.ended = 10;
    in.fwd.slow = 5;
    CHECK(health_compute(&in).state == HEALTH_HEALTHY); /* half isn't most */
    in.fwd.slow = 6;
    CHECK(health_compute(&in).reasons == HR_FWD_SLOW);
    /* Only the default forwarders, only with them on: a node forwarding only to its forward
     * zones isn't judged by them. */
    in.enabled = SVC_ALL & ~SVC_BIT(SVC_FORWARDING);
    CHECK(health_compute(&in).state == HEALTH_HEALTHY);
    CHECK(health_fwd_slow(&in.fwd, in.uptime_ms));
    /* Failing and slow at once: both listed. */
    in = healthy_in();
    in.fwd = (health_fwd_t){ .fails = 9, .since_ms = 0, .ended = 9, .slow = 9 };
    CHECK(health_compute(&in).reasons == (HR_UPSTREAM | HR_FWD_SLOW));

    /* Several reasons at once, all listed. */
    in = healthy_in();
    in.blocking = true;
    in.zones_expired = 1;
    in.sd_mounted = false;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_DEGRADED && h.reasons == (HR_SD | HR_BLOCKING | HR_ZONE_EXPIRED));
    char j[400];
    health_json(&h, j, sizeof(j));
    CHECK(!strcmp(j, "\"state\":\"degraded\",\"answering\":true,\"reasons\":[\"sd card\",\"blocking\",\"zone expired\"]"));
    h = (health_t){ HEALTH_HEALTHY, 0 };
    health_json(&h, j, sizeof(j));
    CHECK(!strcmp(j, "\"state\":\"healthy\",\"answering\":true,\"reasons\":[]"));
    /* A config on trial is listed, but the node is healthy: it waits to be reached. */
    in = healthy_in();
    in.config_trial = true;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_HEALTHY && h.reasons == HR_CONFIG_TRIAL && !(HR_CONFIG_TRIAL & HR_DEGRADED_MASK));
    health_json(&h, j, sizeof(j));
    CHECK(!strcmp(j, "\"state\":\"healthy\",\"answering\":true,\"reasons\":[\"config on trial\"]"));
    /* So is a reboot pending: the node serves on what it runs until it is rebooted. */
    in = healthy_in();
    in.reboot_pending = true;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_HEALTHY && h.reasons == HR_REBOOT_PENDING && !(HR_REBOOT_PENDING & HR_DEGRADED_MASK));
    health_json(&h, j, sizeof(j));
    CHECK(!strcmp(j, "\"state\":\"healthy\",\"answering\":true,\"reasons\":[\"reboot pending\"]"));
    in.blocking = true; /* and it doesn't hide a degraded one */
    CHECK(health_compute(&in).state == HEALTH_DEGRADED);
    /* The supervisor (sup.h): a service restarting is listed; one that keeps failing, or whose
     * task stalled, degrades the node; a service that is off doesn't count. */
    in = healthy_in();
    in.svc_restarting = SVC_BIT(SVC_BLOCKING);
    h = health_compute(&in);
    CHECK(h.state == HEALTH_HEALTHY && h.reasons == HR_SVC_RESTARTING && !(HR_SVC_RESTARTING & HR_DEGRADED_MASK));
    in.svc_failed = SVC_BIT(SVC_SECONDARY);
    h = health_compute(&in);
    CHECK(h.state == HEALTH_DEGRADED && h.reasons == HR_SVC_FAILED); /* failed is the one listed */
    health_json(&h, j, sizeof(j));
    CHECK(!strcmp(j, "\"state\":\"degraded\",\"answering\":true,\"reasons\":[\"service failed\"]"));
    in.enabled = SVC_ALL & ~(SVC_BIT(SVC_SECONDARY) | SVC_BIT(SVC_BLOCKING));
    CHECK(health_compute(&in).state == HEALTH_HEALTHY && health_compute(&in).reasons == 0);
    /* Listeners that stalled, on a node that stays up rather than reboot again: fault. */
    in = healthy_in();
    in.stalled = true;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_FAULT && h.reasons == HR_STALLED && !health_answering(h.state));
    health_json(&h, j, sizeof(j));
    CHECK(!strcmp(j, "\"state\":\"fault\",\"answering\":false,\"reasons\":[\"listeners stalled\"]"));
    /* An older copy in use (the newest on the card corrupt): degraded, for the service it is
     * of; the hosted zones' alone too. */
    in = healthy_in();
    in.older = SVC_BIT(SVC_HOSTED);
    h = health_compute(&in);
    CHECK(h.state == HEALTH_DEGRADED && h.reasons == HR_OLDER_COPY);
    health_json(&h, j, sizeof(j));
    CHECK(!strcmp(j, "\"state\":\"degraded\",\"answering\":true,\"reasons\":[\"older copy\"]"));
    /* The forward loop stalled: degraded (cached and local answers go on), while the node
     * forwards (to the default forwarders or a forward zone's); otherwise it doesn't count. */
    in = healthy_in();
    in.fwd_stalled = true;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_DEGRADED && h.reasons == HR_FWD_STALLED && health_answering(h.state));
    health_json(&h, j, sizeof(j));
    CHECK(!strcmp(j, "\"state\":\"degraded\",\"answering\":true,\"reasons\":[\"forwarder task stalled\"]"));
    in.enabled = SVC_ALL & ~SVC_BIT(SVC_FORWARDING);
    CHECK(health_compute(&in).reasons == HR_FWD_STALLED);
    in.enabled = SVC_ALL & ~(SVC_BIT(SVC_FORWARDING) | SVC_BIT(SVC_FORWARD_ZONES));
    CHECK(health_compute(&in).state == HEALTH_HEALTHY && health_compute(&in).reasons == 0);
    for (int i = 0; i < HR_NBITS; i++)
        CHECK(strcmp(health_reason_name(1u << i), "unknown") != 0);
    /* Every reason at once fits the monitor's log line (health_node.c). */
    h = (health_t){ HEALTH_FAULT, (1u << HR_NBITS) - 1 };
    CHECK(health_json(&h, j, sizeof(j)) < sizeof(j) - 1 && sizeof(j) <= 512 && j[strlen(j) - 1] == ']');
    h = (health_t){ HEALTH_DEGRADED, HR_SD | HR_BLOCKING };
    CHECK(health_json(&h, j, 20) == 19 && strlen(j) == 19); /* cut short, still a string */

    /* Booting: before the listeners open; and before the first answer, until the boot window
     * is over. Then no network. */
    in = healthy_in();
    in.listening = in.answered = false;
    in.uptime_ms = 500;
    CHECK(health_compute(&in).state == HEALTH_BOOTING && !health_answering(HEALTH_BOOTING));
    in.listening = true;
    in.link = false;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_BOOTING && h.reasons == HR_NO_LINK);
    in.uptime_ms = HEALTH_BOOT_WINDOW_MS;
    CHECK(health_compute(&in).state == HEALTH_NO_NETWORK);
    /* Once it has answered, losing the link is no network at once. */
    in = healthy_in();
    in.uptime_ms = 3000;
    in.address = false;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_NO_NETWORK && h.reasons == HR_NO_ADDRESS && !health_answering(h.state));
    /* No network outranks degraded and updating; the degraded reasons still show. */
    in.blocking = in.updating = true;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_NO_NETWORK && h.reasons == (HR_NO_ADDRESS | HR_BLOCKING));

    /* Updating outranks degraded, and answers. */
    in = healthy_in();
    in.updating = true;
    in.blocking = true;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_UPDATING && h.reasons == HR_BLOCKING && health_answering(h.state));

    /* A listener that failed is a fault, whatever else holds. */
    in = healthy_in();
    in.listen_failed = true;
    in.listening = in.answered = false;
    in.link = false;
    h = health_compute(&in);
    CHECK(h.state == HEALTH_FAULT && (h.reasons & HR_LISTENERS) && !health_answering(h.state));

    /* Only the services the config enables count. Each failure again, its service off. */
    static const struct {
        uint32_t reason, svc;
    } gated[] = { { HR_BLOCKING, SVC_BIT(SVC_BLOCKING) },     { HR_ZONE_EXPIRED, SVC_BIT(SVC_SECONDARY) },
                  { HR_ZONE_REFRESH, SVC_BIT(SVC_SECONDARY) }, { HR_UPSTREAM, SVC_BIT(SVC_FORWARDING) },
                  { HR_HOSTED, SVC_BIT(SVC_HOSTED) },          { HR_SD, SVC_SD },
                  { HR_OLDER_COPY, SVC_BIT(SVC_BLOCKING) | SVC_BIT(SVC_HOSTED) },
                  { HR_FWD_SLOW, SVC_BIT(SVC_FORWARDING) } };
    for (size_t i = 0; i < sizeof(gated) / sizeof(*gated); i++) {
        in = healthy_in();
        in.blocking = in.hosted = true;
        in.older = SVC_BIT(SVC_BLOCKING) | SVC_BIT(SVC_HOSTED);
        in.zones_expired = in.zones_failing = 1;
        in.fwd.fails = 9;
        in.fwd.since_ms = 10000;
        in.fwd.ended = in.fwd.slow = 9;
        in.sd_mounted = false;
        in.enabled = SVC_ALL & ~gated[i].svc;
        h = health_compute(&in);
        CHECK(!(h.reasons & gated[i].reason) && h.state == HEALTH_DEGRADED);
        in.enabled = SVC_ALL;
        CHECK(health_compute(&in).reasons & gated[i].reason);
    }
    /* A node with no zones, no hosted zones, no blocking and no forwarders, all of which
     * would be failing, is healthy: it runs only the listeners, and they are fine. */
    in.enabled = SVC_BIT(SVC_DNS);
    h = health_compute(&in);
    CHECK(h.state == HEALTH_HEALTHY && h.reasons == 0);
    /* A node with no zones: nothing about zones, and an SD card only for what it keeps there. */
    in = healthy_in();
    in.enabled = SVC_ALL & ~SVC_BIT(SVC_SECONDARY);
    in.zones_expired = in.zones_failing = 3; /* never set without zones; ignored if they were */
    CHECK(health_compute(&in).state == HEALTH_HEALTHY);
    in.sd_mounted = false;
    CHECK(health_compute(&in).reasons == HR_SD); /* blocking and hosted zones keep data on it */
    in.enabled = SVC_BIT(SVC_DNS) | SVC_BIT(SVC_FORWARDING) | SVC_BIT(SVC_FORWARD_ZONES);
    CHECK(health_compute(&in).state == HEALTH_HEALTHY); /* a forwarder needs no card */
    /* What doesn't belong to a service still counts with all of them off. */
    in.heap_free = 1000;
    in.config_error = true;
    CHECK(health_compute(&in).reasons == (HR_LOW_MEMORY | HR_CONFIG));

    for (int s = 0; s < HEALTH_NSTATES; s++)
        CHECK(strcmp(health_state_name(s), "unknown") != 0);
    for (int b = 0; b < HR_NBITS; b++)
        CHECK(strcmp(health_reason_name(1u << b), "unknown") != 0);
    CHECK(!strcmp(health_state_name(HEALTH_NO_NETWORK), "no network"));
}

/* How many times the LED turns on in [0, ms), and for how long in all. */
static int led_flashes(const led_pattern_t *p, uint32_t ms, uint32_t *lit)
{
    int n = 0;
    bool was = false;
    *lit = 0;
    for (uint32_t t = 0; t < ms; t++) {
        bool on = led_pattern_on(p, t);
        n += on && !was;
        *lit += on;
        was = on;
    }
    return n;
}

static void test_led_patterns(void)
{
    uint32_t lit;
    /* docs/design.md, LED patterns, over 10 s */
    const led_pattern_t *p = led_pattern(HEALTH_BOOTING, false);
    CHECK(led_flashes(p, 10000, &lit) == 50); /* 5 a second */
    p = led_pattern(HEALTH_HEALTHY, false);
    CHECK(led_flashes(p, 10000, &lit) == 2 && lit <= 200); /* a short blip every 5 s, dark otherwise */
    CHECK(p->g && !p->r && !p->b);                        /* green */
    p = led_pattern(HEALTH_DEGRADED, false);
    CHECK(led_flashes(p, 10000, &lit) == 10);             /* two every 2 s */
    CHECK(led_flashes(p, 2000, &lit) == 2 && p->r && p->g && !p->b); /* amber */
    p = led_pattern(HEALTH_NO_NETWORK, false);
    CHECK(led_flashes(p, 10000, &lit) == 10 && lit == 5000); /* once a second, slow */
    CHECK(p->r && !p->g && !p->b);
    p = led_pattern(HEALTH_FAULT, false);
    CHECK(led_flashes(p, 10000, &lit) == 1 && lit == 10000); /* solid */
    CHECK(led_pattern_next(p, 1234) == UINT32_MAX);
    p = led_pattern(HEALTH_UPDATING, false);
    CHECK(led_flashes(p, 1000, &lit) == 3 && led_flashes(p, 10000, &lit) == 30); /* three a second */
    /* Identify overrides every state: a flicker faster than any of them, white. */
    for (int s = 0; s < HEALTH_NSTATES; s++) {
        p = led_pattern(s, true);
        CHECK(led_flashes(p, 1000, &lit) >= 10 && p->r && p->g && p->b);
    }
    /* Each state's pattern differs from every other's in its rhythm (a single LED tells them
     * apart): the number of flashes in 10 s, or the time lit. */
    for (int a = 0; a < HEALTH_NSTATES; a++)
        for (int b = a + 1; b < HEALTH_NSTATES; b++) {
            uint32_t la, lb;
            int fa = led_flashes(led_pattern(a, false), 10000, &la), fb = led_flashes(led_pattern(b, false), 10000, &lb);
            CHECK(fa != fb || la != lb);
        }
    /* led_pattern_next lands exactly on the next change, every time. */
    for (int s = 0; s <= HEALTH_NSTATES; s++) {
        p = led_pattern(s < HEALTH_NSTATES ? s : 0, s == HEALTH_NSTATES);
        if (!p->period_ms)
            continue;
        for (uint32_t t = 0; t < 2u * p->period_ms; t += 7) {
            uint32_t d = led_pattern_next(p, t);
            CHECK(d > 0 && d <= p->period_ms);
            for (uint32_t u = t + 1; u < t + d; u++)
                if (led_pattern_on(p, u) != led_pattern_on(p, t)) {
                    CHECK(!"a change before led_pattern_next said");
                    break;
                }
        }
    }
}

/* ---- node settings (cfg.c) ---- */

static bool cfg_try(cfg_t *c, const char *json, char *err)
{
    return cfg_build(c, NULL, json, strlen(json), err, 160);
}

static uint32_t ip4(const char *s)
{
    uint32_t v = 0;
    CHECK(cfg_parse_ipv4(s, &v));
    return v;
}

static void test_config(void)
{
    static cfg_t c, d; /* big: not on the stack */
    char err[160];

    /* IPv4: strict dotted quads only */
    uint32_t a;
    CHECK(cfg_parse_ipv4("192.0.2.53", &a) && memcmp(&a, "\xc0\x00\x02\x35", 4) == 0);
    static const char *const bad_ips[] = { "", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.4 ", "1..2.3",
                                           "a.b.c.d", "1.2.3.-4", "1234.1.1.1" };
    for (size_t i = 0; i < sizeof(bad_ips) / sizeof(bad_ips[0]); i++)
        CHECK(!cfg_parse_ipv4(bad_ips[i], &a));

    /* No config: the firmware defaults: the address built in and the site defaults, as tests/Makefile
     * builds them (site-defaults.h.example; test_defaults.c checks the project's own). */
    CHECK(cfg_build(&c, NULL, NULL, 0, err, sizeof(err)));
    CHECK(c.ip == ip4(DNS2_STATIC_IP) && c.netmask == ip4("255.255.255.0") && c.gateway == ip4("192.0.2.1"));
    CHECK(!c.dhcp && c.addr_from == CFG_ADDR_FIRMWARE && !strcmp(cfg_addr_kind(&c), "static"));
    CHECK(c.nfwd == 3 && c.fwd[0] == ip4("198.51.100.1") && c.fwd[2] == ip4("9.9.9.9"));
    CHECK(c.nzones == 5 && !strcmp(c.zones[0], "local") && !strcmp(c.zones[4], "home.example"));
    CHECK(c.nfzones == 3 && !strcmp(c.fzones[2].zone, "lab.example") && c.fzones[2].forwarder == ip4("192.0.2.20"));
    CHECK(c.primary == ip4("192.0.2.254") && c.soa_poll_s == 60 && c.retry_s == 30);
    CHECK(c.upstream_timeout_ms == 1500 && !c.block_nxdomain && c.block_ttl == 10 && !strcmp(c.tz, "UTC0"));
    CHECK(c.nntp == 0 && c.wifi_ssid[0] == 0 && c.wifi_tx_dbm == 0 && !c.wifi_power_save);
    CHECK(c.hosted && c.blocking && svc_enabled(&c) == SVC_ALL); /* every service, with the site defaults */

    /* The board layer: its Wi-Fi cap, unless the node config sets one. */
    board_desc_t b = { 0 };
    b.wifi_max_tx_dbm = 15;
    CHECK(cfg_build(&c, &b, NULL, 0, err, sizeof(err)) && c.wifi_tx_dbm == 15);
    CHECK(cfg_build(&c, &b, "{}", 2, err, sizeof(err)) && c.wifi_tx_dbm == 15);
    const char *w = "{\"wifi\":{\"tx_power_dbm\":11}}";
    CHECK(cfg_build(&c, &b, w, strlen(w), err, sizeof(err)) && c.wifi_tx_dbm == 11);
    /* Its address (the builder's) over the firmware's; a node config's over both. */
    CHECK(cfg_parse_net("203.0.113.53/24", "203.0.113.1", &b.net, err, sizeof(err)));
    CHECK(cfg_build(&c, &b, NULL, 0, err, sizeof(err)) && c.ip == ip4("203.0.113.53") &&
          c.netmask == ip4("255.255.255.0") && c.gateway == ip4("203.0.113.1") && !c.dhcp && c.addr_from == CFG_ADDR_BOARD);
    const char *na = "{\"network\":{\"address\":\"203.0.113.54/24\",\"gateway\":\"203.0.113.1\"}}";
    CHECK(cfg_build(&c, &b, na, strlen(na), err, sizeof(err)) && c.ip == ip4("203.0.113.54") &&
          c.addr_from == CFG_ADDR_CONFIG && !strcmp(cfg_addr_from(&c), "config"));
    const char *nd = "{\"network\":{\"address\":\"dhcp\"}}";
    CHECK(cfg_build(&c, &b, nd, strlen(nd), err, sizeof(err)) && !c.ip && c.dhcp && !strcmp(cfg_addr_kind(&c), "dhcp"));
    CHECK(cfg_parse_net("dhcp", NULL, &b.net, err, sizeof(err)) && b.net.set && b.net.dhcp);
    CHECK(cfg_build(&c, &b, NULL, 0, err, sizeof(err)) && !c.ip && c.dhcp && c.addr_from == CFG_ADDR_BOARD);
    CHECK(cfg_parse_net(NULL, NULL, &b.net, err, sizeof(err)) && !b.net.set); /* not given: the firmware's */
    CHECK(cfg_build(&c, &b, NULL, 0, err, sizeof(err)) && c.ip == ip4(DNS2_STATIC_IP) && !c.dhcp);
    CHECK(!cfg_parse_net(NULL, "203.0.113.1", &b.net, err, sizeof(err)) && strstr(err, "only with a static address"));
    CHECK(!cfg_parse_net("203.0.113.53/24", "203.0.113.256", &b.net, err, sizeof(err)) && strstr(err, "not an IPv4"));
    CHECK(!cfg_parse_net("203.0.113.53/24", "224.0.0.1", &b.net, err, sizeof(err)) && strstr(err, "can't be used"));
    CHECK(!cfg_parse_net("203.0.113.53/31", "203.0.113.52", &b.net, err, sizeof(err)) && strstr(err, "prefix length"));
    CHECK(!cfg_parse_net("203.0.113.53/2x", "203.0.113.1", &b.net, err, sizeof(err)) && strstr(err, "prefix length"));
    CHECK(!cfg_parse_net("203.0.113.53/24/1234567890123456789012", "203.0.113.1", &b.net, err, sizeof(err)) &&
          strstr(err, "prefix length"));
    memset(&b.net, 0, sizeof(b.net));
    /* No layer gives an address: none, and no DHCP either. */
    memset(&d, 0, sizeof(d));
    CHECK(!strcmp(cfg_addr_kind(&d), "none") && !strcmp(cfg_addr_from(&d), "none"));

    /* A full node config: what it gives replaces the lower layers, what it leaves out stays. */
    CHECK(cfg_try(&c,
                  "{\"format\":1,\"name\":\"dns-a\",\"network\":{\"address\":\"203.0.113.53/24\",\"gateway\":\"203.0.113.1\"},"
                  "\"wifi\":{\"ssid\":\"home\",\"password\":\"secret123\",\"power_save\":true},"
                  "\"forwarders\":[\"1.1.1.1\",\"9.9.9.9\"],\"upstream_timeout_ms\":900,"
                  "\"forward_zones\":[{\"zone\":\"Corp.Example.\",\"forwarder\":\"203.0.113.2\"}],"
                  "\"secondary\":{\"zones\":[\"example.com\"],\"soa_poll_s\":120},"
                  "\"time\":{\"ntp\":[\"pool.ntp.org\",\"203.0.113.1\"],\"tz\":\"EST5EDT,M3.2.0,M11.1.0\"},"
                  "\"blocking\":{\"answer\":\"nxdomain\",\"ttl\":30}}", err));
    if (err[0])
        fprintf(stderr, "config: %s\n", err);
    CHECK(!strcmp(c.name, "dns-a") && c.ip == ip4("203.0.113.53") && c.netmask == ip4("255.255.255.0") &&
          c.gateway == ip4("203.0.113.1"));
    CHECK(!strcmp(c.wifi_ssid, "home") && !strcmp(c.wifi_pass, "secret123") && c.wifi_power_save);
    CHECK(c.nfwd == 2 && c.fwd[1] == ip4("9.9.9.9") && c.upstream_timeout_ms == 900);
    CHECK(c.nfzones == 1 && !strcmp(c.fzones[0].zone, "corp.example")); /* lowercased, no trailing dot */
    CHECK(c.nzones == 1 && !strcmp(c.zones[0], "example.com") && c.primary == ip4("192.0.2.254"));
    CHECK(c.soa_poll_s == 120 && c.retry_s == 30);
    CHECK(c.nntp == 2 && !strcmp(c.ntp[0], "pool.ntp.org") && !strcmp(c.tz, "EST5EDT,M3.2.0,M11.1.0"));
    CHECK(c.block_nxdomain && c.block_ttl == 30);
    /* The POSIX TZ shapes the node takes: a quoted name, offsets with minutes, rules with times */
    CHECK(cfg_try(&c, "{\"time\":{\"tz\":\"<+0530>-5:30\"}}", err) && !strcmp(c.tz, "<+0530>-5:30"));
    CHECK(cfg_try(&c, "{\"time\":{\"tz\":\"<-03>3<-02>,M3.5.0/-2,M10.5.0/-1\"}}", err));
    CHECK(cfg_try(&c, "{\"time\":{\"tz\":\"NZST-12NZDT,M9.5.0,M4.1.0/3\"}}", err));
    CHECK(cfg_try(&c, "{\"time\":{\"tz\":\"UTC0\"}}", err));

    /* DHCP; empty lists mean none */
    CHECK(cfg_try(&c, "{\"network\":{\"address\":\"dhcp\"},\"forward_zones\":[],\"secondary\":{\"zones\":[]}}", err));
    CHECK(c.ip == 0 && c.netmask == 0 && c.gateway == 0 && c.dhcp && c.nfzones == 0 && c.nzones == 0 && c.nfwd == 3);

    /* Services: on where the config has something for them; hosted zones and blocking on
     * unless it says otherwise. */
    CHECK(svc_enabled(&c) == (SVC_ALL & ~SVC_BIT(SVC_FORWARD_ZONES) & ~SVC_BIT(SVC_SECONDARY)));
    CHECK(cfg_try(&c, "{\"forwarders\":[],\"forward_zones\":[],\"secondary\":{\"zones\":[]},"
                      "\"hosted\":{\"enabled\":false},\"blocking\":{\"enabled\":false},"
                      "\"querylog\":{\"enabled\":false}}", err));
    CHECK(c.nfwd == 0 && !c.hosted && !c.blocking && !c.querylog && svc_enabled(&c) == SVC_BIT(SVC_DNS));
    CHECK(cfg_try(&c, "{\"hosted\":{},\"blocking\":{\"ttl\":30}}", err) && c.hosted && c.blocking); /* left out: on */

    /* Clock scaling: left out, the board's (else the image's: cpuplan.h); on or off live. */
    CHECK(cfg_build(&c, NULL, NULL, 0, err, sizeof(err)) && c.cpu_dfs == -1);
    CHECK(cfg_try(&c, "{\"cpu\":{}}", err) && c.cpu_dfs == -1);
    CHECK(cfg_try(&d, "{\"cpu\":{\"dfs\":false}}", err) && d.cpu_dfs == 0);
    CHECK(!cfg_needs_reboot(&c, &d));
    cfg_copy_live(&c, &d);
    CHECK(c.cpu_dfs == 0);
    CHECK(cfg_try(&d, "{\"cpu\":{\"dfs\":true}}", err) && d.cpu_dfs == 1 && !cfg_needs_reboot(&c, &d));
    CHECK(cfg_try(&c, "{\"hosted\":{\"enabled\":true},\"blocking\":{\"enabled\":false,\"answer\":\"nxdomain\"}}",
                  err) && c.hosted && !c.blocking && c.block_nxdomain);
    CHECK(svc_enabled(&c) == (SVC_ALL & ~SVC_BIT(SVC_BLOCKING)));
    CHECK(cfg_try(&c, "{\"forwarders\":[]}", err) && c.nfwd == 0 && c.nzones == 5 && c.nfzones == 3 &&
          svc_enabled(&c) == (SVC_ALL & ~SVC_BIT(SVC_FORWARDING)));
    CHECK(cfg_try(&c, "{\"secondary\":{\"zones\":[],\"primary\":\"203.0.113.1\"}}", err) &&
          !(svc_enabled(&c) & SVC_BIT(SVC_SECONDARY)));

    /* Refused, with a reason; the result is then the lower layers alone. */
    static const struct {
        const char *json, *why;
    } bad[] = {
        { "[]", "not a JSON object" },
        { "{\"forwarders\":[\"1.1.1.1\"],}", "not a JSON object" },
        { "{\"format\":2}", "format 2" },
        { "{\"fowarders\":[\"1.1.1.1\"]}", "fowarders: unknown setting" },
        { "{\"network\":{\"address\":\"dhcp\",\"mask\":1}}", "network.mask: unknown setting" },
        { "{\"network\":{\"address\":\"203.0.113.5\"}}", "prefix length" },
        { "{\"network\":{\"address\":\"203.0.113.5/24\"}}", "gateway: required" },
        { "{\"network\":{\"address\":\"203.0.113.5/24\",\"gateway\":\"192.0.2.1\"}}", "another address in the node's network" },
        { "{\"network\":{\"address\":\"203.0.113.255/24\",\"gateway\":\"203.0.113.1\"}}", "broadcast" },
        { "{\"network\":{\"address\":\"dhcp\",\"gateway\":\"203.0.113.1\"}}", "only with a static address" },
        { "{\"hosted\":{\"enabled\":1}}", "enabled: true or false" },
        { "{\"hosted\":{\"zones\":[]}}", "hosted.zones: unknown setting" },
        { "{\"hosted\":true}", "hosted: not an object" },
        { "{\"cpu\":{\"dfs\":\"off\"}}", "dfs: true or false" },
        { "{\"cpu\":{\"min_mhz\":80}}", "cpu.min_mhz: unknown setting" }, /* the board's */
        { "{\"cpu\":false}", "cpu: not an object" },
        { "{\"blocking\":{\"enabled\":\"no\"}}", "enabled: true or false" },
        { "{\"forwarders\":[\"1.1.1.1\",\"1.1.1.2\",\"1.1.1.3\",\"1.1.1.4\",\"1.1.1.5\"]}", "at most 4" },
        { "{\"forwarders\":[\"dns.google\"]}", "not an IPv4 address" },
        { "{\"forwarders\":[\"127.0.0.1\"]}", "can't be used" },
        { "{\"upstream_timeout_ms\":50}", "from 100 to 10000" },
        { "{\"upstream_timeout_ms\":1500.5}", "from 100 to 10000" },
        { "{\"secondary\":{\"zones\":[\"a/b\"]}}", "not a zone name" },
        { "{\"secondary\":{\"zones\":[\"a..b\"]}}", "not a zone name" },
        { "{\"secondary\":{\"zones\":[\"x.com\",\"X.com.\"]}}", "x.com twice" },
        { "{\"forward_zones\":[{\"zone\":\"local\",\"forwarder\":\"1.1.1.1\"}]}", "both a secondary zone and a forward zone" },
        { "{\"forward_zones\":[{\"zone\":\"x.com\"}]}", "forwarder: required" },
        { "{\"wifi\":{\"password\":\"12345678\"}}", "only with wifi.ssid" },
        { "{\"wifi\":{\"ssid\":\"x\",\"password\":\"short\"}}", "at least 8" },
        { "{\"wifi\":{\"tx_power_dbm\":21}}", "from 2 to 20" },
        { "{\"time\":{\"tz\":\"5EST\"}}", "POSIX TZ" },
        /* Only the characters POSIX TZ uses: nothing that could break /status (#66) */
        { "{\"time\":{\"tz\":\"EST5\\\"EDT\"}}", "POSIX TZ" },
        { "{\"time\":{\"tz\":\"EST5\\\\EDT\"}}", "POSIX TZ" },
        { "{\"time\":{\"tz\":\"EST5 EDT\"}}", "POSIX TZ" },
        { "{\"time\":{\"tz\":\"EST5EDT;\"}}", "POSIX TZ" },
        { "{\"time\":{\"tz\":\"America/New_York\"}}", "POSIX TZ" },
        { "{\"time\":{\"tz\":\"<+0530-5:30\"}}", "POSIX TZ" },
        { "{\"time\":{\"tz\":\"<<+05>>-5\"}}", "POSIX TZ" },
        { "{\"time\":{\"tz\":\"UTC>0\"}}", "POSIX TZ" },
        { "{\"time\":{\"ntp\":[\"bad host\"]}}", "host names" },
        { "{\"blocking\":{\"answer\":\"refused\"}}", "\"null\" or \"nxdomain\"" },
        { "{\"name\":\"a\\\"b\"}", "printable ASCII" },
        { "{\"upstream_timeout_ms\":1e300}", "from 100 to 10000" },
        { "{\"upstream_timeout_ms\":-1e300}", "from 100 to 10000" },
        { "{\"name\":\"x\"} trailing", "not a JSON object" },
        { "{\"forwarders\":[[[[[[[[[[\"1.1.1.1\"]]]]]]]]]]}", "not a JSON object" },
        { "{\"secondary\":{\"zones\":[\"a..\"]}}", "not a zone name" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        bool ok = cfg_try(&c, bad[i].json, err);
        if (ok || !strstr(err, bad[i].why)) {
            fprintf(stderr, "FAIL config %s: %s (want %s)\n", bad[i].json, ok ? "accepted" : err, bad[i].why);
            s_fail++;
        }
        CHECK(c.nzones == 5 && c.nfwd == 3); /* back to the defaults */
    }
    char big[CFG_JSON_MAX + 16];
    memset(big, ' ', sizeof(big));
    big[0] = '{', big[sizeof(big) - 1] = '}';
    CHECK(!cfg_build(&c, NULL, big, sizeof(big), err, sizeof(err)) && strstr(err, "too big"));
    CHECK(cfg_try(&c, "{\"name\":\"x\"}\n  ", err)); /* white space after it is fine */
    CHECK(cfg_try(&c, "{\"name\":\"[[[[[{{{{{x\"}", err)); /* brackets in strings don't nest */

    /* Live or reboot: forwarders, time and blocking change live; the address, the Wi-Fi
     * network and the zones need a reboot, and a new address boots on trial. */
    CHECK(cfg_build(&c, NULL, NULL, 0, err, sizeof(err)));
    CHECK(cfg_try(&d, "{\"forwarders\":[\"1.1.1.1\"],\"time\":{\"tz\":\"CET-1CEST,M3.5.0,M10.5.0/3\"},"
                      "\"blocking\":{\"ttl\":60},\"wifi\":{\"tx_power_dbm\":8},\"secondary\":{\"soa_poll_s\":300}}", err));
    CHECK(!cfg_needs_reboot(&c, &d) && !cfg_net_changed(&c, &d));
    cfg_copy_live(&c, &d);
    CHECK(c.nfwd == 1 && c.fwd[0] == ip4("1.1.1.1") && !strcmp(c.tz, "CET-1CEST,M3.5.0,M10.5.0/3") && c.block_ttl == 60 &&
          c.wifi_tx_dbm == 8 && c.soa_poll_s == 300 && c.nzones == 5);
    /* Forwarding, hosted zones, blocking and the query log turn off and on live... */
    CHECK(cfg_try(&d, "{\"forwarders\":[],\"hosted\":{\"enabled\":false},\"blocking\":{\"enabled\":false},"
                      "\"querylog\":{\"enabled\":false}}", err));
    CHECK(!cfg_needs_reboot(&c, &d));
    uint32_t before = svc_enabled(&c), stop, start;
    cfg_copy_live(&c, &d);
    CHECK(c.nfwd == 0 && !c.hosted && !c.blocking && c.nzones == 5 && c.nfzones == 3);
    svc_changes(before, svc_enabled(&c), &stop, &start);
    CHECK(stop == SVC_LIVE && start == 0);
    CHECK(cfg_build(&d, NULL, NULL, 0, err, sizeof(err)));
    before = svc_enabled(&c);
    cfg_copy_live(&c, &d);
    svc_changes(before, svc_enabled(&c), &stop, &start);
    CHECK(stop == 0 && start == SVC_LIVE && c.nfwd == 3 && c.hosted && c.blocking);
    /* ...the zone services with a reboot, as their zones do. */
    CHECK(cfg_try(&d, "{\"secondary\":{\"zones\":[]},\"forward_zones\":[]}", err));
    CHECK(cfg_reboot_reasons(&c, &d) == RB_CONFIG_ZONES);
    svc_changes(svc_enabled(&c), svc_enabled(&d), &stop, &start);
    CHECK(stop == 0 && start == 0); /* nothing of it live */
    svc_changes(SVC_BIT(SVC_DNS), SVC_ALL, &stop, &start);
    CHECK(stop == 0 && start == SVC_LIVE);
    /* zones written differently but the same: no reboot */
    CHECK(cfg_try(&d, "{\"secondary\":{\"zones\":[\"LOCAL\",\"example.com.\",\"example.net\",\"example.org\","
                      "\"home.example\"]}}", err));
    CHECK(!cfg_needs_reboot(&c, &d));
    CHECK(cfg_try(&d, "{\"secondary\":{\"zones\":[\"local\"]}}", err) && cfg_needs_reboot(&c, &d) && !cfg_net_changed(&c, &d));
    CHECK(cfg_try(&d, "{\"secondary\":{\"primary\":\"192.0.2.250\"}}", err) && cfg_needs_reboot(&c, &d));
    CHECK(cfg_try(&d, "{\"forward_zones\":[]}", err) && cfg_needs_reboot(&c, &d));
    CHECK(cfg_try(&d, "{\"network\":{\"address\":\"dhcp\"}}", err) && cfg_needs_reboot(&c, &d) && cfg_net_changed(&c, &d));
    CHECK(cfg_try(&d, "{\"network\":{\"address\":\"192.0.2.53/24\",\"gateway\":\"192.0.2.1\"}}", err) &&
          !cfg_needs_reboot(&c, &d)); /* the built-in address, spelled out */
    /* applied live, the config owns the address from then on (adopt keeping the address) */
    CHECK(c.addr_from == CFG_ADDR_FIRMWARE && d.addr_from == CFG_ADDR_CONFIG);
    cfg_copy_live(&c, &d);
    CHECK(c.addr_from == CFG_ADDR_CONFIG && !strcmp(cfg_addr_from(&c), "config"));
    CHECK(cfg_build(&c, NULL, NULL, 0, err, sizeof(err)));
    CHECK(cfg_try(&d, "{\"network\":{\"address\":\"192.0.2.9/24\",\"gateway\":\"192.0.2.1\"}}", err));
    cfg_copy_live(&c, &d); /* (never live: a reboot) the address and its source stay */
    CHECK(c.ip == ip4(DNS2_STATIC_IP) && c.addr_from == CFG_ADDR_FIRMWARE);
    /* The built-in address, behind the marker a rollout reads in the image */
    CHECK(!strcmp(cfg_builtin_addr(), DNS2_STATIC_IP) && !strcmp(cfg_builtin_addr() - strlen(CFG_BUILTIN_ADDR_MARK),
                                                                 CFG_BUILTIN_ADDR_MARK DNS2_STATIC_IP));
    CHECK(cfg_try(&d, "{\"wifi\":{\"ssid\":\"other\"}}", err) && cfg_net_changed(&c, &d));
    /* Why, as the pending-reboot reasons (reboot.h). */
    CHECK(cfg_try(&d, "{\"wifi\":{\"ssid\":\"other\"}}", err) && cfg_reboot_reasons(&c, &d) == RB_CONFIG_WIFI);
    CHECK(cfg_try(&d, "{\"network\":{\"address\":\"dhcp\"}}", err) && cfg_reboot_reasons(&c, &d) == RB_CONFIG_ADDRESS);
    CHECK(cfg_try(&d, "{\"forward_zones\":[]}", err) && cfg_reboot_reasons(&c, &d) == RB_CONFIG_ZONES);
    CHECK(cfg_try(&d, "{\"network\":{\"address\":\"192.0.2.9/24\",\"gateway\":\"192.0.2.1\"},"
                      "\"secondary\":{\"zones\":[\"local\"]}}", err) &&
          cfg_reboot_reasons(&c, &d) == (RB_CONFIG_ADDRESS | RB_CONFIG_ZONES));
    CHECK(cfg_try(&d, "{\"forwarders\":[\"1.1.1.1\"]}", err) && cfg_reboot_reasons(&c, &d) == 0);

    /* The site defaults (the example's) written out as a config (shared with the Go tests):
     * pushing it to a node on the defaults changes nothing that needs a reboot. */
    size_t plen;
    char *prod = read_file("config_example.json", &plen);
    CHECK(prod != NULL);
    if (prod) {
        CHECK(cfg_build(&c, NULL, NULL, 0, err, sizeof(err)));
        bool ok = cfg_build(&d, NULL, prod, plen, err, sizeof(err));
        if (!ok)
            fprintf(stderr, "config_example.json: %s\n", err);
        CHECK(ok && !cfg_needs_reboot(&c, &d) && !cfg_net_changed(&c, &d) && !strcmp(d.name, "node1"));
        /* and every live setting but the name is the default too */
        memcpy(c.name, d.name, sizeof(c.name));
        CHECK(c.nfwd == d.nfwd && !memcmp(c.fwd, d.fwd, sizeof(c.fwd)) && c.upstream_timeout_ms == d.upstream_timeout_ms &&
              c.soa_poll_s == d.soa_poll_s && c.retry_s == d.retry_s && c.nntp == d.nntp && !strcmp(c.tz, d.tz) &&
              c.block_nxdomain == d.block_nxdomain && c.block_ttl == d.block_ttl && c.wifi_tx_dbm == d.wifi_tx_dbm &&
              c.wifi_power_save == d.wifi_power_save && !strcmp(c.wifi_ssid, d.wifi_ssid) &&
              c.hosted == d.hosted && c.blocking == d.blocking && svc_enabled(&c) == svc_enabled(&d));
        free(prod);
    }

    /* Stored slots: the signed release header, then the JSON. */
    rel_trust_t t = { .keys = { V_KEY0, V_KEY1 }, .board = V_BOARD };
    memcpy(t.node_id, V_NODE, 6);
    rel_manifest_t m;
    CHECK(cfg_slot_check(V_CFG, V_CFG_PAYLOAD, CFG_JSON_MAX, &t, &m) == NULL && m.seq == 3000 && m.kind == REL_CONFIG);
    CHECK(cfg_build(&c, NULL, (const char *)V_CFG_PAYLOAD, (size_t)m.payload_len, err, sizeof(err)) &&
          c.ip == ip4("192.0.2.3") && c.nfwd == 1);
    CHECK(cfg_slot_check(V_CFG, V_CFG_PAYLOAD, sizeof(V_CFG_PAYLOAD) - 1, &t, &m) != NULL); /* bigger than the slot */
    uint8_t p[sizeof(V_CFG_PAYLOAD)];
    memcpy(p, V_CFG_PAYLOAD, sizeof(p));
    p[5] ^= 1;
    CHECK(strstr(cfg_slot_check(V_CFG, p, CFG_JSON_MAX, &t, &m), "hash"));
    CHECK(strstr(cfg_slot_check(V_BL, V_BL_PAYLOAD, CFG_JSON_MAX, &t, &m), "not a config"));
    rel_trust_t other = t;
    other.node_id[5] ^= 1;
    CHECK(cfg_slot_check(V_CFG, V_CFG_PAYLOAD, CFG_JSON_MAX, &other, &m) != NULL); /* another node's */
    uint8_t erased[REL_HEADER_LEN];
    memset(erased, 0xff, sizeof(erased));
    CHECK(cfg_slot_check(erased, V_CFG_PAYLOAD, CFG_JSON_MAX, &t, &m) != NULL);

    /* Which slot at boot: the valid one with the higher seq, skipping one that failed its trial. */
    int alt;
    CHECK(cfg_slot_pick((bool[]){ true, true }, (uint64_t[]){ 5, 7 }, 0, &alt) == 1 && alt == 0);
    CHECK(cfg_slot_pick((bool[]){ true, true }, (uint64_t[]){ 9, 7 }, 0, &alt) == 0 && alt == 1);
    CHECK(cfg_slot_pick((bool[]){ true, false }, (uint64_t[]){ 5, 7 }, 0, &alt) == 0 && alt == -1);
    CHECK(cfg_slot_pick((bool[]){ true, true }, (uint64_t[]){ 5, 7 }, 7, &alt) == 0 && alt == -1);
    CHECK(cfg_slot_pick((bool[]){ false, true }, (uint64_t[]){ 5, 7 }, 7, &alt) == -1 && alt == -1);
    CHECK(cfg_slot_pick((bool[]){ false, false }, (uint64_t[]){ 0, 0 }, 0, &alt) == -1);

    /* SNTP servers: the config's; with none, DHCP's slot, the gateway, then pool.ntp.org. */
    char slots[CFG_MAX_NTP][CFG_HOST_MAX];
    bool dhcp;
    cfg_t *n = calloc(1, sizeof(*n));
    CHECK(n && cfg_build(n, NULL, NULL, 0, err, sizeof(err)) && n->ip && !n->nntp);
    cfg_ntp_slots(n, ip4("192.0.2.1"), 3, slots, &dhcp); /* static address */
    CHECK(!dhcp && !strcmp(slots[0], "192.0.2.1") && !strcmp(slots[1], "pool.ntp.org") && !slots[2][0]);
    cfg_ntp_slots(n, 0, 3, slots, &dhcp); /* no gateway */
    CHECK(!dhcp && !strcmp(slots[0], "pool.ntp.org") && !slots[1][0]);
    cfg_ntp_slots(n, ip4("192.0.2.1"), 1, slots, &dhcp); /* one lwIP slot: the gateway */
    CHECK(!dhcp && !strcmp(slots[0], "192.0.2.1"));
    n->ip = 0; /* no address: nothing from DHCP either */
    cfg_ntp_slots(n, 0, 3, slots, &dhcp);
    CHECK(!dhcp && !strcmp(slots[0], "pool.ntp.org"));
    n->dhcp = true; /* a config that asks for DHCP */
    cfg_ntp_slots(n, ip4("203.0.113.1"), 3, slots, &dhcp);
    CHECK(dhcp && !slots[0][0] && !strcmp(slots[1], "203.0.113.1") && !strcmp(slots[2], "pool.ntp.org"));
    cfg_ntp_slots(n, ip4("203.0.113.1"), 2, slots, &dhcp);
    CHECK(dhcp && !slots[0][0] && !strcmp(slots[1], "203.0.113.1"));
    cfg_ntp_slots(n, ip4("203.0.113.1"), 1, slots, &dhcp); /* no room for DHCP's */
    CHECK(!dhcp && !strcmp(slots[0], "203.0.113.1"));
    static const char ntp_cfg[] = "{\"time\":{\"ntp\":[\"time.example\",\"203.0.113.9\"]}}";
    CHECK(cfg_build(n, NULL, ntp_cfg, sizeof(ntp_cfg) - 1, err, sizeof(err)));
    cfg_ntp_slots(n, ip4("192.0.2.1"), 3, slots, &dhcp); /* configured: only those */
    CHECK(!dhcp && !strcmp(slots[0], "time.example") && !strcmp(slots[1], "203.0.113.9") && !slots[2][0]);
    free(n);
}

/* ---- hosted zones ---- */

static hz_set_t *g_set;
static zone_t *hfinder(void *ctx, const uint8_t *name, int len)
{
    (void)ctx;
    return hz_find(g_set, name, len);
}

/* Asks the hosted zones; false if no hosted zone holds name. */
static bool hask(const char *name, uint16_t type, uint8_t *out, answer_result_t *res, parsed_t *p)
{
    uint8_t qb[512];
    dns_query_t q;
    size_t ql = make_query(qb, name, type, false);
    assert(dns_query_parse(qb, ql, &q) == 0);
    zone_t *z = hz_find(g_set, q.qname, q.qname_len);
    if (!z)
        return false;
    dns_builder_t b;
    dnsb_init(&b, out, 4096, 4096, &q, DNS_F_QR | DNS_F_RD);
    answer_auth(hfinder, NULL, z, &q, &b, res);
    if (res->authoritative)
        dnsb_set_flags(&b, DNS_F_AA, 0);
    dnsb_set_rcode(&b, res->rcode);
    size_t len = dnsb_finish(&b);
    return parse_resp(out, len, p);
}

/* A bundle written by hand, for the refusals. */
typedef struct {
    uint8_t b[4096];
    size_t n, cnt_off;
    uint32_t cnt;
} hb_t;

static void hb_start(hb_t *x, uint16_t zones)
{
    memcpy(x->b, HZ_MAGIC, 8);
    wr16(x->b + 8, zones);
    x->n = 10;
}

static void hb_name(hb_t *x, const char *s)
{
    uint8_t n[256];
    int l = N(s, n);
    assert(l > 0);
    x->b[x->n++] = (uint8_t)l;
    memcpy(x->b + x->n, n, (size_t)l);
    x->n += (size_t)l;
}

static void hb_rr(hb_t *x, const char *owner, uint16_t type, uint32_t ttl, const void *rd, uint16_t rdlen)
{
    hb_name(x, owner);
    wr16(x->b + x->n, type);
    wr32(x->b + x->n + 2, ttl);
    wr16(x->b + x->n + 6, rdlen);
    memcpy(x->b + x->n + 8, rd, rdlen);
    x->n += 8u + rdlen;
    wr32(x->b + x->cnt_off, ++x->cnt);
}

static void hb_rr_name(hb_t *x, const char *owner, uint16_t type, const char *target)
{
    uint8_t t[256];
    hb_rr(x, owner, type, 300, t, (uint16_t)N(target, t));
}

/* A zone with its SOA at the apex. */
static void hb_zone(hb_t *x, const char *apex)
{
    hb_name(x, apex);
    x->cnt_off = x->n;
    x->cnt = 0;
    wr32(x->b + x->n, 0);
    x->n += 4;
    uint8_t rd[600];
    int p = N("ns.t.example", rd);
    p += N("hm.t.example", rd + p);
    memset(rd + p, 0, 20);
    wr32(rd + p, 1);
    hb_rr(x, apex, DNS_T_SOA, 300, rd, (uint16_t)(p + 20));
}

static const char *hparse(const hb_t *x, char *err)
{
    hz_set_t *s;
    const char *why = hz_parse(x->b, x->n, 64 * 1024, &s, err, 160);
    if (!why)
        hz_free(s);
    return why;
}

static void test_hosted(void)
{
    uint8_t out[4096];
    answer_result_t res;
    parsed_t p;
    char err[160];

    /* The bundle controller/internal/zones builds from its testdata (go test -update). */
    size_t len;
    uint8_t *vec = (uint8_t *)read_file("hosted_example.bin", &len);
    CHECK(vec);
    const char *why = hz_parse(vec, len, 64 * 1024, &g_set, err, sizeof(err));
    if (why)
        fprintf(stderr, "hosted_example.bin: %s\n", why);
    CHECK(!why && g_set->n == 2);
    if (why) {
        free(vec);
        return;
    }
    CHECK(g_set->z[0]->serial == 7 && g_set->z[1]->serial == 2026100201 && g_set->z[1]->n == 18);
    size_t mem = g_set->mem;
    CHECK(mem > 2 * HZ_ZONE_COST && mem < 4096);
    /* The memory limit is checked before anything is allocated. */
    hz_set_t *s2;
    CHECK(hz_parse(vec, len, mem - 1, &s2, err, sizeof(err)) && strstr(err, "hosted_zones_kb"));
    CHECK(!hz_parse(vec, len, mem, &s2, err, sizeof(err)));
    hz_free(s2);
    /* Any byte cut off is refused. */
    for (size_t cut = 0; cut < len; cut += 37)
        CHECK(hz_parse(vec, cut, 64 * 1024, &s2, err, sizeof(err)) != NULL);

    CHECK(hask("www.home.example", DNS_T_A, out, &res, &p));
    CHECK(res.rcode == 0 && res.authoritative && (p.h.flags & DNS_F_AA) && p.h.an == 1 && p.rr[0].type == DNS_T_A);
    CHECK(out[p.rr[0].rdata_off + 3] == 21 && p.rr[0].ttl == 300);
    CHECK(hask("WWW.Home.Example", DNS_T_AAAA, out, &res, &p) && p.h.an == 1 && p.rr[0].type == DNS_T_AAAA);
    CHECK(hask("nas.home.example", DNS_T_A, out, &res, &p) && p.h.an == 1 && p.rr[0].ttl == 600);
    /* A CNAME chain inside the zone: chain -> alias -> www. */
    CHECK(hask("chain.home.example", DNS_T_A, out, &res, &p) && p.h.an == 3 && !res.external);
    CHECK(p.rr[0].type == DNS_T_CNAME && p.rr[1].type == DNS_T_CNAME && p.rr[2].type == DNS_T_A &&
          name_is(&p.rr[2], "www.home.example"));
    /* One that leaves the hosted zones: the caller finishes it upstream. */
    CHECK(hask("ext.home.example", DNS_T_A, out, &res, &p) && p.h.an == 1 && res.external);
    uint8_t t[256];
    CHECK(dns_name_eq(res.target, res.target_len, t, N("files.other.example", t)));
    /* NXDOMAIN and NODATA, each with the SOA, its TTL capped at the SOA minimum. */
    CHECK(hask("nope.home.example", DNS_T_A, out, &res, &p) && res.rcode == DNS_R_NXDOMAIN && p.h.an == 0 &&
          p.h.ns == 1 && p.rr[0].type == DNS_T_SOA && p.rr[0].ttl == 60);
    CHECK(hask("mail.home.example", DNS_T_AAAA, out, &res, &p) && res.rcode == 0 && p.h.an == 0 && p.h.ns == 1);
    CHECK(hask("b.home.example", DNS_T_A, out, &res, &p) && res.rcode == 0 && p.h.an == 0); /* empty non-terminal */
    /* Wildcards: synthesized under *.dev, not at dev itself. */
    CHECK(hask("x.y.dev.home.example", DNS_T_A, out, &res, &p) && res.rcode == 0 && p.h.an == 1 &&
          name_is(&p.rr[0], "x.y.dev.home.example"));
    CHECK(hask("x.dev.home.example", DNS_T_MX, out, &res, &p) && res.rcode == 0 && p.h.an == 0);
    CHECK(hask("dev.home.example", DNS_T_A, out, &res, &p) && res.rcode == 0 && p.h.an == 0);
    /* The delegation: a referral with its glue, not authoritative. */
    CHECK(hask("host.lab.home.example", DNS_T_A, out, &res, &p) && !res.authoritative && p.h.an == 0 &&
          p.h.ns == 1 && p.h.ar == 1 && p.rr[0].type == DNS_T_NS && p.rr[1].type == DNS_T_A);
    /* Every other type. */
    CHECK(hask("home.example", DNS_T_MX, out, &res, &p) && p.h.an == 1 && p.rr[0].type == DNS_T_MX);
    CHECK(hask("home.example", DNS_T_TXT, out, &res, &p) && p.h.an == 1 && p.rr[0].type == DNS_T_TXT);
    CHECK(hask("home.example", DNS_T_CAA, out, &res, &p) && p.h.an == 1 && p.rr[0].type == DNS_T_CAA);
    CHECK(hask("home.example", DNS_T_NS, out, &res, &p) && p.h.an == 1 && p.rr[0].type == DNS_T_NS);
    CHECK(hask("_http._tcp.home.example", DNS_T_SRV, out, &res, &p) && p.h.an == 1 && p.rr[0].type == DNS_T_SRV);
    CHECK(hask("21.2.0.192.in-addr.arpa", DNS_T_PTR, out, &res, &p) && p.h.an == 1 && p.rr[0].type == DNS_T_PTR);
    CHECK(!hask("other.example", DNS_T_A, out, &res, &p));

    /* A zone a config also names is a clash; one below it is a zone of its own. */
    static cfg_t c;
    static const char sec[] = "{\"secondary\":{\"zones\":[\"local\",\"Home.Example\"]},\"forward_zones\":[]}";
    CHECK(cfg_build(&c, NULL, sec, sizeof(sec) - 1, err, sizeof(err)));
    CHECK(hz_clash(g_set, &c) == 1);
    static const char fwd[] = "{\"secondary\":{\"zones\":[\"sub.home.example\"]},\"forward_zones\":[{\"zone\":"
                              "\"2.0.192.in-addr.arpa\",\"forwarder\":\"203.0.113.1\"}]}";
    CHECK(cfg_build(&c, NULL, fwd, sizeof(fwd) - 1, err, sizeof(err)));
    CHECK(hz_clash(g_set, &c) == 0);
    hz_drop(g_set, 0);
    CHECK(g_set->n == 1 && hz_clash(g_set, &c) == -1 && !hask("21.2.0.192.in-addr.arpa", DNS_T_PTR, out, &res, &p));
    hz_free(g_set);
    g_set = NULL;
    free(vec);

    /* The longest apex wins between nested hosted zones. */
    hb_t x;
    hb_start(&x, 2);
    hb_zone(&x, "t.example");
    hb_rr_name(&x, "www.sub.t.example", DNS_T_CNAME, "www.t.example");
    hb_zone(&x, "sub.t.example");
    hz_set_t *s;
    CHECK(!hz_parse(x.b, x.n, 64 * 1024, &s, err, sizeof(err)));
    uint8_t n[256];
    int nl = N("www.sub.t.example", n);
    CHECK(s && hz_find(s, n, nl) == s->z[1]);
    hz_free(s);
    hb_start(&x, 0); /* none: removes every hosted zone */
    CHECK(!hz_parse(x.b, x.n, 64 * 1024, &s, err, sizeof(err)) && s->n == 0 && s->mem == 0);
    hz_free(s);

    /* The refusals, as controller/internal/zones makes them (zones_test.go, TestRefused). */
    static const uint8_t a4[4] = { 10, 0, 0, 1 }, a3[3] = { 10, 0, 0 }, cmp[2] = { 0xc0, 12 }, txt[2] = { 1, 'x' };
    hb_start(&x, 1);
    hb_zone(&x, "t.example");
    CHECK(!hparse(&x, err));
    x.b[0] = 'X';
    CHECK(hparse(&x, err) && strstr(err, "not a zones bundle"));
    hb_start(&x, HZ_MAX_ZONES + 1);
    CHECK(hparse(&x, err) && strstr(err, "at most"));
    struct {
        const char *owner;
        uint16_t type;
        uint32_t ttl;
        const void *rd;
        uint16_t rdlen;
        const char *why;
    } bad[] = {
        { "www.other.example", DNS_T_A, 300, a4, 4, "outside the zone" },
        { "a.*.t.example", DNS_T_A, 300, a4, 4, "first label" },
        { "www.t.example", 48, 300, a4, 4, "no DNSSEC" },
        { "www.t.example", DNS_T_A, 0x80000000u, a4, 4, "TTL above" },
        { "www.t.example", DNS_T_A, 300, a3, 3, "malformed rdata" },
        { "www.t.example", DNS_T_CNAME, 300, cmp, 2, "malformed rdata" },
        { "sub.t.example", DNS_T_SOA, 300, NULL, 0, "SOA only at the apex" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        hb_start(&x, 1);
        hb_zone(&x, "t.example");
        if (bad[i].type == DNS_T_SOA) {
            /* the apex SOA's rdata, at another owner */
            uint8_t rd[600];
            int q = N("ns.t.example", rd);
            q += N("hm.t.example", rd + q);
            memset(rd + q, 0, 20);
            hb_rr(&x, bad[i].owner, DNS_T_SOA, 300, rd, (uint16_t)(q + 20));
        } else {
            hb_rr(&x, bad[i].owner, bad[i].type, bad[i].ttl, bad[i].rd, bad[i].rdlen);
        }
        CHECK(hparse(&x, err) && strstr(err, bad[i].why));
        if (!strstr(err, bad[i].why))
            fprintf(stderr, "  %s: got %s\n", bad[i].why, err);
    }
    /* Whole-zone rules. */
    hb_start(&x, 1);
    hb_name(&x, "t.example");
    x.cnt_off = x.n;
    x.cnt = 0;
    wr32(x.b + x.n, 0);
    x.n += 4;
    hb_rr(&x, "www.t.example", DNS_T_A, 300, a4, 4);
    CHECK(hparse(&x, err) && strstr(err, "exactly one SOA"));
    hb_start(&x, 1);
    hb_zone(&x, "t.example");
    hb_rr(&x, "www.t.example", DNS_T_A, 300, a4, 4);
    hb_rr_name(&x, "www.t.example", DNS_T_CNAME, "other.t.example");
    CHECK(hparse(&x, err) && strstr(err, "a CNAME and other records"));
    hb_start(&x, 1);
    hb_zone(&x, "t.example");
    hb_rr_name(&x, "www.t.example", DNS_T_CNAME, "a.t.example");
    hb_rr_name(&x, "www.t.example", DNS_T_CNAME, "b.t.example");
    CHECK(hparse(&x, err) && strstr(err, "more than one CNAME"));
    hb_start(&x, 1);
    hb_zone(&x, "t.example");
    hb_rr_name(&x, "lab.t.example", DNS_T_NS, "ns.lab.t.example");
    hb_rr(&x, "ns.lab.t.example", DNS_T_A, 300, a4, 4);
    CHECK(!hparse(&x, err)); /* glue is fine */
    hb_rr(&x, "lab.t.example", DNS_T_TXT, 300, txt, 2);
    CHECK(hparse(&x, err) && strstr(err, "TXT at a delegation"));
    hb_start(&x, 1);
    hb_zone(&x, "t.example");
    hb_rr_name(&x, "lab.t.example", DNS_T_NS, "ns.lab.t.example");
    hb_rr_name(&x, "host.lab.t.example", DNS_T_CNAME, "www.t.example");
    CHECK(hparse(&x, err) && strstr(err, "CNAME below a delegation"));
    hb_start(&x, 2);
    hb_zone(&x, "t.example");
    hb_zone(&x, "T.Example");
    CHECK(hparse(&x, err) && strstr(err, "twice"));
    hb_start(&x, 1);
    hb_zone(&x, "t.example");
    x.b[x.n++] = 0;
    CHECK(hparse(&x, err) && strstr(err, "after the last zone"));
    hb_start(&x, 1);
    hb_zone(&x, "*.example");
    CHECK(hparse(&x, err) && strstr(err, "not a zone name"));
    /* A wildcard NS (zones_test.go, TestRefused): a wildcard can't be delegated. Other types
     * at a wildcard, and NS below one, are fine. */
    hb_start(&x, 1);
    hb_zone(&x, "t.example");
    hb_rr(&x, "*.dev.t.example", DNS_T_A, 300, a4, 4);
    CHECK(!hparse(&x, err));
    hb_rr_name(&x, "*.dev.t.example", DNS_T_NS, "ns.t.example");
    CHECK(hparse(&x, err) && strstr(err, "*.dev.t.example: NS at a wildcard name"));
    hb_start(&x, 1);
    hb_zone(&x, "t.example");
    hb_rr_name(&x, "*.t.example", DNS_T_NS, "ns.t.example");
    CHECK(hparse(&x, err) && strstr(err, "NS at a wildcard name"));
}

/* ---- reboot pending ---- */

static void test_reboot(void)
{
    rb_state_t s = { 0 };
    char j[256];
    rb_json(&s, 100, j, sizeof(j));
    CHECK(!strcmp(j, "\"reboot\":{\"pending\":false,\"reasons\":[],\"since_s\":0}"));
    /* The time starts with the first reason, and stays while any is pending. */
    rb_update(&s, RB_CONFIG, RB_CONFIG_ADDRESS, 100);
    CHECK(s.reasons == RB_CONFIG_ADDRESS && s.since_s == 100);
    rb_update(&s, RB_BLOCKLIST, RB_BLOCKLIST, 130);
    CHECK(s.reasons == (RB_CONFIG_ADDRESS | RB_BLOCKLIST) && s.since_s == 100);
    rb_json(&s, 160, j, sizeof(j));
    CHECK(!strcmp(j, "\"reboot\":{\"pending\":true,\"reasons\":[\"config: address\",\"blocklist: size\"],\"since_s\":60}"));
    /* A newer config replaces the config reasons only: here it applies live. */
    rb_update(&s, RB_CONFIG, 0, 170);
    CHECK(s.reasons == RB_BLOCKLIST && s.since_s == 100);
    rb_update(&s, RB_CONFIG, RB_CONFIG_WIFI | RB_CONFIG_ZONES | RB_BLOCKLIST, 175); /* outside mask: ignored */
    CHECK(s.reasons == (RB_BLOCKLIST | RB_CONFIG_WIFI | RB_CONFIG_ZONES));
    rb_update(&s, RB_CONFIG | RB_BLOCKLIST, 0, 180);
    CHECK(s.reasons == 0 && s.since_s == 0);
    rb_update(&s, RB_FIRMWARE, RB_FIRMWARE, 200);
    CHECK(s.since_s == 200);
    rb_json(&s, 199, j, sizeof(j)); /* read just before it was set: 0, not a wrapped number */
    CHECK(strstr(j, "\"since_s\":0}") && strstr(j, "[\"firmware\"]"));
    for (uint32_t b = 0; b < RB_NBITS; b++)
        CHECK(strcmp(rb_reason_name(1u << b), "unknown") != 0);
    CHECK(!strcmp(rb_reason_name(1u << RB_NBITS), "unknown"));
    /* Every reason at once fits, and a short buffer is cut short but still a string. */
    s.reasons = (1u << RB_NBITS) - 1;
    CHECK(rb_json(&s, 300, j, sizeof(j)) < sizeof(j) - 1 && j[strlen(j) - 1] == '}');
    CHECK(rb_json(&s, 300, j, 20) == 19 && strlen(j) == 19);

    /* The control payload: 04, u32 delay_ms little-endian, optional u8 flags. */
    rb_ctl_t c;
    const uint8_t p1[] = { 4, 0x88, 0x13, 0, 0 }; /* 5000 ms */
    CHECK(!rb_ctl_parse(p1, sizeof(p1), &c) && c.delay_ms == 5000 && c.flags == 0);
    const uint8_t p2[] = { 4, 0x60, 0xea, 0, 0, RB_FLAG_IF_PENDING }; /* 60000 ms, the most */
    CHECK(!rb_ctl_parse(p2, sizeof(p2), &c) && c.delay_ms == 60000 && c.flags == RB_FLAG_IF_PENDING);
    const uint8_t p3[] = { 4, 0, 0, 0, 0, 0 };
    CHECK(!rb_ctl_parse(p3, sizeof(p3), &c) && c.delay_ms == 0 && c.flags == 0);
    const uint8_t over[] = { 4, 0x61, 0xea, 0, 0 }; /* 60001 */
    CHECK(rb_ctl_parse(over, sizeof(over), &c) != NULL);
    const uint8_t big[] = { 4, 0, 0, 0, 0x80 };
    CHECK(rb_ctl_parse(big, sizeof(big), &c) != NULL);
    const uint8_t flags[] = { 4, 0, 0, 0, 0, 2 };
    CHECK(rb_ctl_parse(flags, sizeof(flags), &c) != NULL);
    const uint8_t shrt[] = { 4, 0, 0, 0 };
    CHECK(rb_ctl_parse(shrt, sizeof(shrt), &c) != NULL);
    const uint8_t lng[] = { 4, 0, 0, 0, 0, 0, 0 };
    CHECK(rb_ctl_parse(lng, sizeof(lng), &c) != NULL);
    const uint8_t other[] = { 3 };
    CHECK(rb_ctl_parse(other, sizeof(other), &c) != NULL && rb_ctl_parse(other, 0, &c) != NULL);
}

/* ---- services ---- */

static void test_services(void)
{
    for (int i = 0; i < SVC_N; i++)
        CHECK(strcmp(svc_name(i), "unknown") != 0);
    for (int i = 0; i < SVC_NSTATES; i++)
        CHECK(strcmp(svc_state_name(i), "unknown") != 0);
    CHECK(!strcmp(svc_name(SVC_N), "unknown") && !strcmp(svc_state_name(SVC_NSTATES), "unknown"));
    svc_state_t st[SVC_N] = { SVC_RUNNING, SVC_RUNNING, SVC_OFF, SVC_FAILED, SVC_STARTING, SVC_OFF, SVC_RUNNING };
    size_t planned[SVC_N] = { 5000000, 0, 0, 1200000, 3000000, 0, 65536 },
           used[SVC_N] = { 4900000, 0, 0, 2000, 0, 0, 65536 };
    char j[1024];
    size_t n = svc_json(st, planned, used, j, sizeof(j));
    CHECK(n == strlen(j));
    CHECK(!strcmp(j, "\"services\":[{\"name\":\"dns\",\"state\":\"running\",\"memory\":{\"planned\":5000000,"
                     "\"allocated\":4900000}},"
                     "{\"name\":\"forwarding\",\"state\":\"running\",\"memory\":{\"planned\":0,\"allocated\":0}},"
                     "{\"name\":\"forward_zones\",\"state\":\"off\",\"memory\":{\"planned\":0,\"allocated\":0}},"
                     "{\"name\":\"secondary\",\"state\":\"failed\",\"memory\":{\"planned\":1200000,"
                     "\"allocated\":2000}},"
                     "{\"name\":\"hosted\",\"state\":\"starting\",\"memory\":{\"planned\":3000000,\"allocated\":0}},"
                     "{\"name\":\"blocking\",\"state\":\"off\",\"memory\":{\"planned\":0,\"allocated\":0}},"
                     "{\"name\":\"querylog\",\"state\":\"running\",\"memory\":{\"planned\":65536,"
                     "\"allocated\":65536}}]"));
    CHECK(svc_json(st, planned, used, j, 40) == 39 && strlen(j) == 39); /* cut short, still a string */
    CHECK(svc_json(st, planned, used, j, 0) == 0);
    /* The SD and live services are among them; the listeners are neither. */
    CHECK((SVC_SD & ~SVC_ALL) == 0 && (SVC_LIVE & ~SVC_ALL) == 0 && !((SVC_LIVE | SVC_SD) & SVC_BIT(SVC_DNS)));
}

/* ---- memory plan ---- */

static uint32_t services_mask(const cJSON *names)
{
    uint32_t m = 0;
    const cJSON *n;
    cJSON_ArrayForEach(n, names)
        for (int i = 0; i < SVC_N; i++)
            if (!strcmp(n->valuestring, svc_name(i)))
                m |= SVC_BIT(i);
    return m;
}

static size_t num_at(const cJSON *o, const char *key, int i)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    return (size_t)cJSON_GetArrayItem(v, i)->valuedouble;
}

static void test_memplan(void)
{
    /* The shared vectors (tests/gen_memplan_vectors.py): the controller gives the same. */
    size_t len;
    char *text = read_file("memplan_vectors.json", &len);
    CHECK(text);
    cJSON *vec = cJSON_ParseWithLength(text, len);
    CHECK(cJSON_GetArraySize(vec) >= 10);
    const cJSON *c;
    cJSON_ArrayForEach(c, vec)
    {
        const char *name = cJSON_GetObjectItem(c, "name")->valuestring;
        const cJSON *want = cJSON_GetObjectItem(c, "want"), *bj = cJSON_GetObjectItem(c, "board");
        board_desc_t b, *bp = NULL;
        char err[160];
        if (!cJSON_IsNull(bj)) {
            char *s = cJSON_PrintUnformatted(bj);
            bool ok = board_def_parse(s, strlen(s), &b, err, sizeof(err));
            if (!ok)
                fprintf(stderr, "%s: %s\n", name, err);
            CHECK(ok);
            free(s);
            bp = &b;
        }
        mp_board_t mb;
        mp_board(bp, cJSON_GetObjectItem(c, "image")->valuestring,
                 (int)cJSON_GetObjectItem(c, "chip_psram_kb")->valuedouble, &mb);
        const cJSON *wb = cJSON_GetObjectItem(want, "board");
#define WANT(f) (mb.f == (uint32_t)cJSON_GetObjectItem(wb, #f)->valuedouble)
        bool board_ok = WANT(psram_kb) && WANT(internal_kb) && WANT(cache_kb) && WANT(cache_entries) &&
                        WANT(blocklist_kb) && WANT(blocklist_index_kb) && WANT(hosted_zones_kb) &&
                        WANT(secondary_zones_kb) && WANT(querylog_kb) && WANT(fwd_pending);
#undef WANT
        mp_plan_t p;
        bool fits = mp_plan(&mb, services_mask(cJSON_GetObjectItem(c, "services")), &p, err, sizeof(err));
        bool plan_ok = fits == cJSON_IsTrue(cJSON_GetObjectItem(want, "fits")) &&
                       !strcmp(err, cJSON_GetObjectItem(want, "error")->valuestring);
        for (int k = 0; k < MP_NPOOLS; k++) {
            plan_ok = plan_ok && p.capacity[k] == num_at(want, "capacity", k) && p.total[k] == num_at(want, "total", k);
            const cJSON *shares = cJSON_GetObjectItem(want, "shares");
            for (int s = 0; s < SVC_N; s++)
                plan_ok = plan_ok && p.share[s][k] == num_at(shares, svc_name(s), k);
        }
        if (!board_ok || !plan_ok)
            fprintf(stderr, "memplan vector \"%s\": board %s, plan %s (%s)\n", name, board_ok ? "ok" : "differs",
                    plan_ok ? "ok" : "differs", err);
        CHECK(board_ok && plan_ok);
    }
    cJSON_Delete(vec);
    free(text);

    /* A board partition written before the plan's keys runs as the catalog says, but for the
     * hosted zones (which it may or may not have had): the catalog states the defaults, so the
     * nodes in service need no reflash. */
    static const struct {
        const char *name;
        int psram_kb;
    } prod[] = { { "p4-ip101", 32768 }, { "ws-s3-eth", 8192 } };
    for (int i = 0; i < 2; i++) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%s.json", BOARDS_DIR, prod[i].name);
        char *json = read_file(path, &len), err[160];
        board_desc_t b, old;
        CHECK(json && board_def_parse(json, len, &b, err, sizeof(err)));
        old = b;
        memset(&old.mem, 0xFF, sizeof(old.mem));
        mp_board_t now, before;
        mp_board(&b, b.image, prod[i].psram_kb, &now);
        mp_board(&old, b.image, prod[i].psram_kb, &before);
        before.hosted_zones_kb = now.hosted_zones_kb;
        CHECK(!memcmp(&now, &before, sizeof(now)));
        free(json);
    }
    /* The defaults are today's sizes: a 4 MB, 8192-answer cache with PSRAM, 64 KB and 512
     * without; 64 KB of hosted zones. */
    mp_board_t mb;
    mp_board(NULL, "esp32p4-rev1", 32768, &mb);
    CHECK(mb.cache_kb == 4096 && mb.cache_entries == 8192 && mb.hosted_zones_kb == 64 && mb.blocklist_kb == 20480);
    CHECK(mb.fwd_pending == 32);
    mp_board(NULL, "esp32p4-rev1", 0, &mb);
    CHECK(mb.psram_kb == 0 && mb.cache_kb == 64 && mb.cache_entries == 512 && mp_data_pool(&mb) == MP_INTERNAL);
    CHECK(mb.fwd_pending == 8);
    /* The /status object. */
    mp_plan_t p;
    char err[160], j[600];
    mp_board(NULL, "esp32s3-octal", 8192, &mb);
    CHECK(mp_plan(&mb, SVC_ALL, &p, err, sizeof(err)) && !err[0]);
    CHECK(mp_share(&p, SVC_DNS) == p.share[SVC_DNS][0] + p.share[SVC_DNS][1] && mp_share(&p, SVC_N) == 0);
    size_t n = mp_json(&mb, &p, j, sizeof(j));
    static const char start[] = "\"memory\":{\"board\":{\"psram_kb\":8192,\"internal_kb\":160,";
    CHECK(n == strlen(j) && !strncmp(j, start, sizeof(start) - 1));
    cJSON *o = cJSON_Parse(j + 9);
    CHECK(o && cJSON_GetObjectItem(cJSON_GetObjectItem(o, "psram"), "planned")->valuedouble == p.total[MP_PSRAM]);
    cJSON_Delete(o);
    CHECK(mp_json(&mb, &p, j, 30) == 29 && strlen(j) == 29);
    /* The lists' placement (block.h) from the share: never from free heap. */
    blk_need_t need = { .front = 4096, .index = 128 * 1024, .sectors = 8 << 20 };
    blk_room_t r = { .budget = 20 << 20, .index_budget = 160 * 1024, .ram_tier = true };
    blk_place_t pl;
    CHECK(!blk_place(&need, &r, &pl) && pl.tier == BLK_TIER_RAM && pl.now && pl.index_internal);
    /* Replacing a list of the same size: both fit, the index of the new one goes with it. */
    r.used = r.held = 8 << 20;
    r.index_used = r.index_held = 128 * 1024;
    CHECK(!blk_place(&need, &r, &pl) && pl.tier == BLK_TIER_RAM && pl.now && !pl.index_internal);
    /* A bigger one fits only once the old one is gone: at the next boot. */
    need.sectors = 14 << 20;
    CHECK(!blk_place(&need, &r, &pl) && pl.tier == BLK_TIER_RAM && !pl.now);
    /* Bigger than the share: the SD tier (the front and index); bigger again: refused. */
    need.sectors = 25 << 20;
    need.front = 2 << 20;
    CHECK(!blk_place(&need, &r, &pl) && pl.tier == BLK_TIER_SD && pl.now);
    need.front = 21 << 20;
    CHECK(blk_place(&need, &r, &pl) && strstr(blk_place(&need, &r, &pl), "memory.blocklist_kb"));
    /* Without PSRAM, the SD tier only. */
    need = (blk_need_t){ .front = 4096, .index = 1024, .sectors = 64 * 1024 };
    r = (blk_room_t){ .budget = 128 * 1024 };
    CHECK(!blk_place(&need, &r, &pl) && pl.tier == BLK_TIER_SD && pl.now && !pl.index_internal);
    /* The overrides: the RAM tier, now or not at all. */
    r = (blk_room_t){ .budget = 100 * 1024, .used = 20 * 1024, .ram_tier = true, .overrides = true };
    CHECK(!blk_place(&need, &r, &pl) && pl.tier == BLK_TIER_RAM && pl.now);
    r.used = 90 * 1024;
    CHECK(blk_place(&need, &r, &pl) != NULL);
}

/* The shared placement vectors (tests/gen_place_vectors.py): the controller checks a list
 * fits before a rollout pushes it, and gives the same answers. */
static void test_place(void)
{
    size_t len;
    char *text = read_file("place_vectors.json", &len);
    CHECK(text);
    cJSON *vec = cJSON_ParseWithLength(text, len);
    CHECK(cJSON_GetArraySize(vec) >= 20);
    const cJSON *c;
    cJSON_ArrayForEach(c, vec)
    {
        const char *name = cJSON_GetObjectItem(c, "name")->valuestring;
        const char *hex = cJSON_GetObjectItem(c, "header")->valuestring;
        const cJSON *want = cJSON_GetObjectItem(c, "want"), *rj = cJSON_GetObjectItem(c, "room");
        uint8_t hdr[BL_HEADER];
        CHECK(strlen(hex) == 2 * BL_HEADER);
        for (int i = 0; i < BL_HEADER; i++)
            sscanf(hex + 2 * i, "%2hhx", &hdr[i]);
#define NUM(o, k) ((size_t)cJSON_GetObjectItem(o, k)->valuedouble)
        blk_need_t n;
        const char *why = blk_plan(hdr, NUM(c, "file_len"), &n);
        const cJSON *wn = cJSON_GetObjectItem(want, "need");
        bool ok = !why == (wn != NULL);
        if (ok && wn)
            ok = n.front == NUM(wn, "front") && n.index == NUM(wn, "index") && n.sectors == NUM(wn, "sectors") &&
                 n.entries == NUM(wn, "entries");
        blk_place_t pl = { 0 };
        if (ok && !why) {
            blk_room_t r = {
                .budget = NUM(rj, "budget"),
                .used = NUM(rj, "used"),
                .held = NUM(rj, "held"),
                .index_budget = NUM(rj, "index_budget"),
                .index_used = NUM(rj, "index_used"),
                .index_held = NUM(rj, "index_held"),
                .ram_tier = cJSON_IsTrue(cJSON_GetObjectItem(rj, "ram_tier")),
                .overrides = cJSON_IsTrue(cJSON_GetObjectItem(rj, "overrides")),
            };
            why = blk_place(&n, &r, &pl);
        }
#undef NUM
        const char *werr = cJSON_GetObjectItem(want, "error")->valuestring;
        ok = ok && !strcmp(why ? why : "", werr);
        if (ok && wn && !why) {
            const char *tier = cJSON_GetObjectItem(want, "tier")->valuestring;
            ok = !strcmp(pl.tier == BLK_TIER_RAM ? "ram" : "sd", tier) &&
                 pl.now == cJSON_IsTrue(cJSON_GetObjectItem(want, "now")) &&
                 pl.index_internal == cJSON_IsTrue(cJSON_GetObjectItem(want, "index_internal"));
        }
        if (!ok)
            fprintf(stderr, "place vector \"%s\": %s (tier %d, now %d, index internal %d)\n", name, why ? why : "fits",
                    pl.tier, pl.now, pl.index_internal);
        CHECK(ok);
    }
    cJSON_Delete(vec);
    free(text);
}

/* ---- the CPU clock plan ---- */

static void test_cpuplan(void)
{
    /* The shared vectors: the controller's board checks give the same (internal/boards). */
    size_t len;
    char *text = read_file("cpu_vectors.json", &len);
    CHECK(text);
    cJSON *vec = cJSON_ParseWithLength(text, len);
    CHECK(cJSON_GetArraySize(vec) >= 10);
    const cJSON *c;
    cJSON_ArrayForEach(c, vec)
    {
        const char *name = cJSON_GetObjectItem(c, "name")->valuestring;
        const char *image = cJSON_GetObjectItem(c, "image")->valuestring;
        const cJSON *cpu = cJSON_GetObjectItem(c, "cpu"), *want = cJSON_GetObjectItem(c, "want");
        const cJSON *error = cJSON_GetObjectItem(c, "error");
        char json[256], err[160];
        char *cs = cJSON_IsNull(cpu) ? NULL : cJSON_PrintUnformatted(cpu);
        snprintf(json, sizeof(json), "{\"name\":\"x\",\"image\":\"%s\"%s%s}", image, cs ? ",\"cpu\":" : "",
                 cs ? cs : "");
        free(cs);
        board_desc_t b;
        bool ok = board_def_parse(json, strlen(json), &b, err, sizeof(err));
        if (error) {
            if (ok || !strstr(err, error->valuestring))
                fprintf(stderr, "cpu vector \"%s\": %s\n", name, ok ? "accepted" : err);
            CHECK(!ok && strstr(err, error->valuestring));
            continue;
        }
        if (!ok)
            fprintf(stderr, "cpu vector \"%s\": %s\n", name, err);
        CHECK(ok);
        cp_board_t p;
        cp_board(&b, image, &p);
        bool same = cp_dfs(&p, -1) == cJSON_IsTrue(cJSON_GetObjectItem(want, "dfs")) &&
                    p.max_mhz == cJSON_GetObjectItem(want, "max_mhz")->valueint &&
                    p.min_mhz == cJSON_GetObjectItem(want, "min_mhz")->valueint &&
                    p.apb_mhz == cJSON_GetObjectItem(want, "apb_mhz")->valueint;
        if (!same)
            fprintf(stderr, "cpu vector \"%s\": dfs %d, %d/%d MHz, APB %d\n", name, cp_dfs(&p, -1), p.max_mhz,
                    p.min_mhz, p.apb_mhz);
        CHECK(same);
        /* No board at all (no board partition): the image's, as with a board that says nothing. */
        if (!cs) {
            cp_board_t q;
            cp_board(NULL, image, &q);
            CHECK(q.dfs == p.dfs && q.min_mhz == p.min_mhz && !q.dfs_board);
        }
    }
    cJSON_Delete(vec);
    free(text);

    /* The node config has the last word, either way. */
    cp_board_t p;
    cp_board(NULL, "esp32p4-rev1", &p);
    CHECK(!cp_dfs(&p, -1) && cp_dfs(&p, 1) && !cp_dfs(&p, 0));
    cp_board(NULL, "esp32s3-octal", &p);
    CHECK(cp_dfs(&p, -1) && !cp_dfs(&p, 0) && cp_dfs(&p, 1));
    /* An image not in the table never scales. */
    cp_board(NULL, "esp32h2", &p);
    CHECK(!cp_dfs(&p, 1) && cp_image("esp32h2") == NULL && cp_min_ok("esp32h2", 10));

    /* The clock the node idles at: the APB floor while the EMAC runs or Wi-Fi stays awake. */
    cp_board(NULL, "esp32p4-rev1", &p);
    CHECK(cp_idle_mhz(&p, false, true) == 360 && cp_idle_mhz(&p, true, true) == 180);
    p.min_mhz = 90;
    CHECK(cp_idle_mhz(&p, true, true) == 90 && cp_idle_mhz(&p, true, false) == 90);
    cp_board(NULL, "esp32s3-octal", &p);
    CHECK(cp_idle_mhz(&p, true, false) == 80 && cp_idle_mhz(&p, true, true) == 80);
    p.min_mhz = 40; /* Wi-Fi awake keeps 80; the W5500 holds it only while it transfers */
    CHECK(cp_idle_mhz(&p, true, false) == 40 && cp_idle_mhz(&p, true, true) == 80);
    cp_board(NULL, "esp32", &p); /* a wired ESP32 would never clock down */
    CHECK(cp_idle_mhz(&p, true, true) == 240 && cp_idle_mhz(&p, true, false) == 40);

    /* The board definition's "cpu": its shape, and the reasons. */
    board_desc_t b;
    char err[160];
    CHECK(parse("{\"name\":\"x\",\"image\":\"esp32\"}", &b, err) && b.cpu.dfs == -1 && b.cpu.min_mhz == -1);
    CHECK(parse("{\"name\":\"x\",\"image\":\"esp32c3\",\"cpu\":{\"dfs\":false,\"min_mhz\":40}}", &b, err) &&
          b.cpu.dfs == 0 && b.cpu.min_mhz == 40);
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"cpu\":true}", &b, err) && strstr(err, "cpu: an object"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32\",\"cpu\":{\"dfs\":1}}", &b, err) && strstr(err, "dfs"));
    CHECK(!parse("{\"name\":\"x\",\"image\":\"esp32p4-rev1\",\"cpu\":{\"min_mhz\":100}}", &b, err) &&
          !strcmp(err, "cpu min_mhz: 90, 180 on esp32p4-rev1, or leave it out for the image's 180"));
}

/* ---- the supervisor ---- */

/* ---- live or reboot: the shared vectors ---- */

/* Whether name is one of the strings in the JSON array a. */
static bool in_list(const cJSON *a, const char *name)
{
    const cJSON *v;
    cJSON_ArrayForEach(v, a)
    {
        if (cJSON_IsString(v) && !strcmp(v->valuestring, name))
            return true;
    }
    return false;
}

static void test_cfg_reboot_vectors(void)
{
    /* The controller's classification (controller/internal/nodecfg, Compare) on the same
     * vectors: every reason it is sure of is the node's, and the node's reasons are among
     * those it is sure of or says may be (a setting one side leaves to the firmware). */
    size_t len;
    char *text = read_file("cfg_reboot_vectors.json", &len);
    CHECK(text);
    cJSON *vec = cJSON_ParseWithLength(text, len);
    CHECK(cJSON_GetArraySize(vec) >= 20);
    static cfg_t a, b;
    const cJSON *v;
    cJSON_ArrayForEach(v, vec)
    {
        const char *name = cJSON_GetObjectItem(v, "name")->valuestring;
        char *from = cJSON_PrintUnformatted(cJSON_GetObjectItem(v, "from"));
        char *to = cJSON_PrintUnformatted(cJSON_GetObjectItem(v, "to"));
        char err[160];
        bool ok = cfg_build(&a, NULL, from, strlen(from), err, sizeof(err)) &&
                  cfg_build(&b, NULL, to, strlen(to), err, sizeof(err));
        if (!ok)
            fprintf(stderr, "reboot vector \"%s\": %s\n", name, err);
        CHECK(ok);
        uint32_t r = cfg_reboot_reasons(&a, &b);
        const cJSON *reboot = cJSON_GetObjectItem(v, "reboot"), *maybe = cJSON_GetObjectItem(v, "maybe");
        for (uint32_t bit = RB_CONFIG_ADDRESS; bit <= RB_CONFIG_ZONES; bit <<= 1) {
            const char *rn = rb_reason_name(bit);
            bool set = (r & bit) != 0;
            bool good = in_list(reboot, rn) ? set : !set || in_list(maybe, rn);
            if (!good)
                fprintf(stderr, "reboot vector \"%s\": %s %s\n", name, rn, set ? "set" : "not set");
            CHECK(good);
        }
        cJSON_free(from);
        cJSON_free(to);
    }
    cJSON_Delete(vec);
    free(text);
}

static void test_sup(void)
{
    static const uint32_t backoff[] = { 5000, 5000, 10000, 20000, 40000, 80000, 160000, 300000, 300000 };
    for (uint32_t i = 0; i < sizeof(backoff) / sizeof(*backoff); i++)
        CHECK(sup_backoff_ms(i) == backoff[i]);
    CHECK(sup_backoff_ms(1000) == SUP_BACKOFF_MAX_MS);

    /* A service whose start keeps failing: restarted after 5 s, 10 s, 20 s ...; restarting
     * is listed from the first failure, failed (degraded) from the third. */
    sup_svc_t s = { 0 };
    CHECK(!sup_svc_tick(&s, false, 1000) && !sup_svc_restarting(&s) && !sup_svc_failed(&s));
    CHECK(!sup_svc_tick(&s, true, 2000) && sup_svc_restarting(&s) && !sup_svc_failed(&s));
    CHECK(!sup_svc_tick(&s, true, 6999));
    CHECK(sup_svc_tick(&s, true, 7000)); /* restart */
    CHECK(!sup_svc_tick(&s, true, 8000) && s.fails == 2 && sup_svc_restarting(&s));
    CHECK(!sup_svc_tick(&s, true, 17999) && sup_svc_tick(&s, true, 18000));
    CHECK(!sup_svc_tick(&s, true, 19000) && s.fails == 3 && sup_svc_failed(&s) && !sup_svc_restarting(&s));
    CHECK(sup_svc_tick(&s, true, 39000) && sup_svc_failed(&s)); /* until the next look */
    /* It took: no longer failed, but the count starts over only after a minute running. */
    CHECK(!sup_svc_tick(&s, false, 40000) && !sup_svc_failed(&s) && !sup_svc_restarting(&s) && s.fails == 3);
    CHECK(!sup_svc_tick(&s, false, 98999) && s.fails == 3);
    CHECK(!sup_svc_tick(&s, false, 99000) && s.fails == 0);
    CHECK(!sup_svc_tick(&s, true, 99500) && sup_svc_restarting(&s)); /* a new run */
    s.fails = 3; /* failing again within the minute: failed at once */
    s.waiting = false;
    CHECK(!sup_svc_tick(&s, true, 99600) && sup_svc_failed(&s) && s.fails == 4);
    /* Back by itself before its restart: no restart. */
    s = (sup_svc_t){ 0 };
    CHECK(!sup_svc_tick(&s, true, 0) && !sup_svc_tick(&s, false, 1000) && !sup_svc_tick(&s, false, 9000));
    CHECK(s.fails == 1 && !s.waiting);
    /* Across the ms clock's wrap. */
    s = (sup_svc_t){ 0 };
    CHECK(!sup_svc_tick(&s, true, UINT32_MAX - 1000) && !sup_svc_tick(&s, true, UINT32_MAX) &&
          sup_svc_tick(&s, true, 4000));

    /* Watchdogs: a late listener, or every worker late, is a stall; a late service task
     * marks its service. */
    sup_watch_t w[5] = {
        { true, SUP_LISTENER, SVC_DNS, SUP_LISTENER_MS, 1000, false },
        { true, SUP_WORKER, SVC_DNS, SUP_WORKER_MS, 1000, false },
        { true, SUP_WORKER, SVC_DNS, SUP_WORKER_MS, 1000, false },
        { true, SUP_TASK, SVC_SECONDARY, SUP_TASK_MS, 1000, false },
        { false, SUP_TASK, SVC_BLOCKING, SUP_TASK_MS, 0, false }, /* not running */
    };
    bool stalled;
    CHECK(sup_late(w, 5, 1000 + SUP_LISTENER_MS, &stalled) == 0 && !stalled);
    CHECK(sup_late(w, 5, 1001 + SUP_LISTENER_MS, &stalled) == SVC_BIT(SVC_DNS) && stalled);
    const uint32_t wl = 1001 + SUP_WORKER_MS; /* both workers kicked at 1000 are late */
    w[0].kick_ms = wl - 1000;
    w[1].kick_ms = wl;
    CHECK(sup_late(w, 5, wl, &stalled) == SVC_BIT(SVC_DNS) && !stalled); /* one worker of two */
    w[1].kick_ms = 1000;
    w[0].kick_ms = wl - 5;
    CHECK(sup_late(w, 5, wl - 1, &stalled) == 0 && !stalled); /* not yet */
    CHECK(sup_late(w, 5, wl, &stalled) == SVC_BIT(SVC_DNS) && stalled); /* both */
    w[1].kick_ms = w[2].kick_ms = 300000;
    w[0].kick_ms = 300000;
    CHECK(sup_late(w, 5, 301001, &stalled) == SVC_BIT(SVC_SECONDARY) && !stalled);

    /* Parked (a worker waiting on its empty queue): never late, however long it waits, and
     * not one of "every worker late"; a parked task of a service doesn't mark it either. */
    const uint32_t idle = 1000 + 10 * SUP_WORKER_MS;
    w[0].kick_ms = idle;
    w[1].kick_ms = w[2].kick_ms = 1000;
    w[1].parked = w[2].parked = true;
    w[3].kick_ms = idle;
    CHECK(sup_late(w, 5, idle, &stalled) == 0 && !stalled);
    w[2].parked = false; /* one took a query long ago and is stuck on it: late, not a stall */
    CHECK(sup_late(w, 5, idle, &stalled) == SVC_BIT(SVC_DNS) && !stalled);
    w[1].parked = false;
    CHECK(sup_late(w, 5, idle, &stalled) == SVC_BIT(SVC_DNS) && stalled);
    w[3].parked = true;
    w[3].kick_ms = 0;
    w[1].parked = w[2].parked = true;
    CHECK(sup_late(w, 5, idle, &stalled) == 0 && !stalled);

    /* The forward loop: late, it is neither a stall nor a service failing, only itself; its
     * deadline is the workers' now that no worker waits on a forwarder. */
    CHECK(SUP_WORKER_MS == 10000 && SUP_FORWARDER_MS == 10000);
    sup_watch_t fw[2] = {
        { true, SUP_FORWARDER, SVC_DNS, SUP_FORWARDER_MS, 1000, false },
        { true, SUP_WORKER, SVC_DNS, SUP_WORKER_MS, 1000 + SUP_FORWARDER_MS, false },
    };
    CHECK(!sup_forwarder_late(fw, 2, 1000 + SUP_FORWARDER_MS));
    CHECK(sup_forwarder_late(fw, 2, 1001 + SUP_FORWARDER_MS));
    CHECK(sup_late(fw, 2, 1001 + SUP_FORWARDER_MS, &stalled) == 0 && !stalled);
    fw[0].kick_ms = 1001 + SUP_FORWARDER_MS; /* it checks in again: back */
    CHECK(!sup_forwarder_late(fw, 2, 1001 + SUP_FORWARDER_MS));
    CHECK(!sup_forwarder_late(w, 5, idle)); /* none watched */

    /* Stall reboots: three in a row, then the node stays up in fault; a hardware watchdog
     * reset counts as one; ten minutes up starts the count over. */
    uint32_t count = sup_stall_boot(0, false);
    CHECK(count == 0 && sup_stall_reboot(&count) && count == 1);
    count = sup_stall_boot(count, false);
    CHECK(sup_stall_reboot(&count) && count == 2);
    count = sup_stall_boot(count, true);
    CHECK(count == 3 && !sup_stall_reboot(&count) && count == 3);
    CHECK(!sup_stall_settled(SUP_STALL_WINDOW_MS - 1) && sup_stall_settled(SUP_STALL_WINDOW_MS));
}

int main(void)
{
    g_zone = make_zone();
    CHECK(g_zone->n == 13); /* 14 in-zone adds, 1 duplicate dropped */
    test_names();
    test_answers();
    test_persistence();
    test_cache_and_relay();
    test_cache_stress();
    test_cache_key();
    test_dnssec_relay();
    test_flights();
    test_flight_caps();
    test_flight_counts();
    test_flight_expiry();
    test_flight_cancel_race();
    test_flights_threads();
    test_flights_retry();
    test_fwd_fd_setsize();
    test_fwdq_complete();
    test_fwdq_failover();
    test_fwdq_tcp();
    test_fwdq_tcp_queue_budget();
    test_fwdq_strays();
    test_fwdq_alive();
    test_fwdq_load();
    test_fwd_random_port();
    test_fwdq_select_backoff();
    test_health_upstream();
    test_upq();
    test_upq_workers_silent();
    test_query_parse();
    test_release();
    test_seq_limit();
    test_blocklist();
    test_block();
    test_board_defs();
    test_health();
    test_led_patterns();
    test_config();
    test_services();
    test_memplan();
    test_place();
    test_cpuplan();
    test_cfg_reboot_vectors();
    test_sup();
    test_hosted();
    test_reboot();
    zone_free(g_zone);
    if (s_fail) {
        fprintf(stderr, "%d check(s) failed\n", s_fail);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
