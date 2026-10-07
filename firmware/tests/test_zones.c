/* Host tests for local zones' lookups and zone transfers (zone.h, axfr.h): canonical order,
 * existence in O(log n), the zone's memory limit, and the transfer's deadline, against a
 * fake primary on the loopback. gcc + ASan/UBSan, no hardware. */
#include <arpa/inet.h>
#include <assert.h>
#include <malloc.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "answer.h"
#include "axfr.h"
#include "dns_wire.h"
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

/* The heap the code under test holds (linked with --wrap, tests/Makefile): what it holds
 * now, and the most it has held, a realloc counted as its old block and its new one side by
 * side. Only this thread allocates through these (the fake primary allocates nothing). */
static size_t s_live, s_peak;
void *__real_malloc(size_t n);
void *__real_calloc(size_t k, size_t n);
void *__real_realloc(void *p, size_t n);
void  __real_free(void *p);
static void held(size_t add)
{
    s_live += add;
    if (s_live > s_peak)
        s_peak = s_live;
}
void *__wrap_malloc(size_t n)
{
    void *p = __real_malloc(n);
    if (p)
        held(malloc_usable_size(p));
    return p;
}
void *__wrap_calloc(size_t k, size_t n)
{
    void *p = __real_calloc(k, n);
    if (p)
        held(malloc_usable_size(p));
    return p;
}
void *__wrap_realloc(void *p, size_t n)
{
    size_t old = p ? malloc_usable_size(p) : 0;
    if (s_live + n > s_peak)
        s_peak = s_live + n;
    void *q = __real_realloc(p, n);
    if (q) {
        s_live -= old;
        held(malloc_usable_size(q));
    }
    return q;
}
void __wrap_free(void *p)
{
    if (p)
        s_live -= malloc_usable_size(p);
    __real_free(p);
}
/* From here, the most held above what is held now. */
static size_t peak_from(void) { s_peak = s_live; return s_live; }

static int64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static const char *APEX = "example.test";

/* SOA rdata for the test zones: serial, then refresh..minimum. */
static int soa_rdata(uint8_t *rd, uint32_t serial)
{
    int p = N("ns1.example.test", rd);
    p += N("admin.example.test", rd + p);
    uint32_t v[5] = { serial, 3600, 900, 604800, 120 };
    for (int i = 0; i < 5; i++, p += 4)
        wr32(rd + p, v[i]);
    return p;
}

static zone_t *new_zone(size_t limit)
{
    uint8_t apex[256], rd[600];
    int al = N(APEX, apex);
    zone_t *z = zone_new(apex, al, limit);
    assert(z);
    int rl = soa_rdata(rd, 1);
    assert(zone_add(z, apex, al, DNS_T_SOA, 3600, rd, (uint16_t)rl));
    return z;
}

static bool add_a(zone_t *z, const char *owner, uint8_t last)
{
    uint8_t o[256], a[4] = { 192, 0, 2, last };
    int ol = N(owner, o);
    assert(ol > 0);
    return zone_add(z, o, ol, DNS_T_A, 300, a, 4);
}

/* ---- canonical order (RFC 4034 6.1, its example, lowercased) ---- */

static void test_canonical_order(void)
{
    static const char *const order[] = {
        "example", "a.example", "yljkjljk.a.example", "z.a.example", "zabc.a.example", "z.example",
        "\x01.z.example", "*.z.example", "\xc8.z.example",
    };
    int n = (int)(sizeof(order) / sizeof(order[0]));
    uint8_t a[256], b[256];
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            int al = N(order[i], a), bl = N(order[j], b);
            assert(al > 0 && bl > 0);
            int c = zone_name_cmp(a, al, b, bl);
            CHECK(i < j ? c < 0 : i > j ? c > 0 : c == 0);
        }

    /* A zone keeps its records in that order: a name right before everything under it. */
    zone_t *z = new_zone(SIZE_MAX);
    add_a(z, "b.example.test", 1);
    add_a(z, "x.a.example.test", 2);
    add_a(z, "a.example.test", 3);
    add_a(z, "aa.example.test", 4);
    add_a(z, "y.x.a.example.test", 5);
    CHECK(zone_finalize(z));
    static const char *const sorted[] = { "example.test", "a.example.test", "x.a.example.test", "y.x.a.example.test",
                                          "aa.example.test", "b.example.test" };
    CHECK(z->n == 6);
    for (size_t i = 0; i < z->n && i < 6; i++) {
        int l = N(sorted[i], a);
        CHECK(z->rrs[i].owner_len == l && !memcmp(zrr_owner(z, &z->rrs[i]), a, (size_t)l));
    }
    zone_free(z);
}

/* ---- existence against a linear scan (what zone_name_exists did before) ---- */

static bool exists_by_scan(const zone_t *z, const uint8_t *name, int len)
{
    for (size_t i = 0; i < z->n; i++)
        if (dns_name_under(zrr_owner(z, &z->rrs[i]), z->rrs[i].owner_len, name, len))
            return true;
    return false;
}

/* A random name of 1..depth labels from a three-letter alphabet under the apex, so names
 * collide and empty non-terminals are common. */
static void rand_name(char *s, size_t cap, int depth, unsigned *seed)
{
    int labels = 1 + (int)(rand_r(seed) % (unsigned)depth);
    size_t p = 0;
    for (int i = 0; i < labels; i++) {
        int ll = 1 + (int)(rand_r(seed) % 2);
        for (int k = 0; k < ll; k++)
            s[p++] = (char)('a' + rand_r(seed) % 3);
        s[p++] = '.';
    }
    snprintf(s + p, cap - p, "%s", APEX);
}

static void test_exists_matches_scan(void)
{
    unsigned seed = 6465;
    zone_t *z = new_zone(SIZE_MAX);
    char s[256];
    for (int i = 0; i < 400; i++) {
        rand_name(s, sizeof(s), 4, &seed);
        add_a(z, s, (uint8_t)i);
    }
    CHECK(zone_finalize(z));
    uint8_t n[256];
    int yes = 0, ents = 0, agree = 0, total = 5000;
    for (int i = 0; i < total; i++) {
        rand_name(s, sizeof(s), 5, &seed);
        int nl = N(s, n);
        size_t f;
        bool want = exists_by_scan(z, n, nl), got = zone_name_exists(z, n, nl);
        agree += want == got;
        yes += got;
        ents += got && zone_find(z, n, nl, &f) == 0;
    }
    CHECK(agree == total);
    CHECK(yes > 100 && ents > 50); /* both kinds were looked at */
    /* The apex, and a name in another case. */
    CHECK(zone_name_exists(z, n, N(APEX, n)));
    int nl = N("EXAMPLE.Test", n);
    memcpy(n + 1, "EXAMPLE", 7);
    CHECK(zone_name_exists(z, n, nl));
    zone_free(z);
}

/* ---- #65: a nonexistent long name costs O(labels x log n), not O(labels x n) ---- */

static zone_t *big_zone(int records)
{
    zone_t *z = new_zone(SIZE_MAX);
    unsigned seed = (unsigned)records;
    char s[256];
    for (int i = 0; i < records; i++) {
        /* host<i>.<dept>.example.test, with empty non-terminals between */
        snprintf(s, sizeof(s), "h%d.d%u.example.test", i, rand_r(&seed) % 64);
        add_a(z, s, (uint8_t)i);
    }
    assert(zone_finalize(z));
    return z;
}

static zone_t *s_bench_zone;
static zone_t *bench_finder(void *ctx, const uint8_t *name, int len)
{
    (void)ctx;
    return dns_name_under(name, len, s_bench_zone->apex, s_bench_zone->apex_len) ? s_bench_zone : NULL;
}

/* A query for a name of as many one-letter labels as fit (120) under the apex, none of
 * which exists: every label is a lookup for the wildcard's closest encloser. */
static size_t long_query(uint8_t *q, unsigned *seed)
{
    memset(q, 0, DNS_HDR_LEN);
    wr16(q, 0x4242);
    wr16(q + 4, 1);
    size_t p = DNS_HDR_LEN;
    uint8_t apex[256];
    int al = N(APEX, apex);
    while (p - DNS_HDR_LEN + 2 + (size_t)al <= DNS_MAX_NAME) {
        q[p++] = 1;
        q[p++] = (uint8_t)('a' + rand_r(seed) % 26);
    }
    memcpy(q + p, apex, (size_t)al);
    p += (size_t)al;
    wr16(q + p, DNS_T_A);
    wr16(q + p + 2, DNS_C_IN);
    return p + 4;
}

/* Microseconds for queries answers of long nonexistent names in z: the best of three runs. */
static double bench_us(zone_t *z, int queries)
{
    s_bench_zone = z;
    double best = 1e30;
    for (int run = 0; run < 3; run++) {
        unsigned seed = 65;
        int64_t t0 = mono_us();
        for (int i = 0; i < queries; i++) {
            uint8_t qb[512], out[1232];
            dns_query_t q;
            size_t ql = long_query(qb, &seed);
            assert(dns_query_parse(qb, ql, &q) == 0);
            dns_builder_t b;
            answer_result_t res;
            dnsb_init(&b, out, sizeof(out), sizeof(out), &q, DNS_F_QR);
            answer_auth(bench_finder, NULL, z, &q, &b, &res);
            assert(res.rcode == DNS_R_NXDOMAIN);
        }
        double us = (double)(mono_us() - t0);
        if (us < best)
            best = us;
    }
    return best;
}

static void test_long_names_bounded(void)
{
    zone_t *small = big_zone(1024), *large = big_zone(65536);
    uint8_t qb[512];
    unsigned seed = 1;
    size_t ql = long_query(qb, &seed);
    CHECK(ql - DNS_HDR_LEN - 4 >= DNS_MAX_NAME - 1 && ql - DNS_HDR_LEN - 4 <= DNS_MAX_NAME);

    int queries = 200;
    double ts = bench_us(small, queries), tl = bench_us(large, queries);
    /* 64 times the records: a scan per label would take 64 times as long; a binary search
     * per label takes 16/10 the comparisons. Allow for the larger zone's cache misses. */
    printf("long nonexistent names: %.1f us/query with 1025 records, %.1f us/query with 65537 (x%.2f)\n",
           ts / queries, tl / queries, tl / ts);
    CHECK(tl < 8 * ts);
    zone_free(small);
    zone_free(large);
}

/* ---- #64: a zone's memory limit ---- */

static void test_zone_limit(void)
{
    uint8_t apex[256];
    int al = N(APEX, apex);
    CHECK(zone_new(apex, al, sizeof(zone_t) - 1) == NULL);

    /* Records added one at a time into a limit: the zone never holds more, and is refused
     * only when the next record (its buffer's growth next to the old copy) wouldn't fit. */
    for (size_t limit = 4096; limit <= 256 * 1024; limit *= 4) {
        zone_t *z = new_zone(limit);
        char s[64];
        int i = 0;
        bool ok = true;
        while (ok && i < 100000) {
            size_t before = zone_mem(z), n = z->n, cap = z->cap, alen = z->arena_len, acap = z->arena_cap;
            snprintf(s, sizeof(s), "host%d.example.test", i);
            ok = add_a(z, s, (uint8_t)i++);
            CHECK(zone_mem(z) <= limit);
            if (!ok) {
                CHECK(z->over && z->n == n);
                /* What it needed: a bigger record table, or a bigger arena, next to all it held. */
                uint8_t o[256];
                size_t rec = (size_t)N(s, o) + 4;
                bool table = n == cap && before + (n + 1) * sizeof(zrr_t) > limit;
                bool arena = alen + rec > acap && zone_mem(z) + alen + rec > limit;
                CHECK(table || arena);
            }
        }
        CHECK(!ok && i > 10);
        CHECK(zone_finalize(z) && zone_mem(z) <= limit);
        zone_free(z);
    }

    /* zone_reserve is held to the limit too. */
    zone_t *z = zone_new(apex, al, sizeof(zone_t) + 10 * sizeof(zrr_t) + 100);
    CHECK(zone_reserve(z, 10, 100) && !z->over);
    zone_free(z);
    z = zone_new(apex, al, sizeof(zone_t) + 10 * sizeof(zrr_t) + 100);
    CHECK(!zone_reserve(z, 10, 101) && z->over);
    zone_free(z);

    /* A saved copy is loaded into exactly what its records need, holding nothing else
     * meanwhile (not the file read whole next to the zone), within a limit or not at all. */
    char path[] = "/tmp/dns2_test_zones_limit.bin";
    z = big_zone(1000);
    CHECK(zone_save(z, path));
    size_t exact = sizeof(zone_t) + z->n * sizeof(zrr_t) + z->arena_len;
    size_t base = peak_from();
    zone_t *l = zone_load(path, z->apex, z->apex_len, exact);
    CHECK(l && l->n == z->n && zone_mem(l) == exact && l->serial == z->serial);
    CHECK(s_peak - base <= exact);
    for (size_t i = 0; l && i < l->n; i++)
        CHECK(l->rrs[i].type == z->rrs[i].type && l->rrs[i].rdlen == z->rrs[i].rdlen &&
              !memcmp(zrr_rdata(l, &l->rrs[i]), zrr_rdata(z, &z->rrs[i]), z->rrs[i].rdlen) &&
              zone_name_cmp(zrr_owner(l, &l->rrs[i]), l->rrs[i].owner_len, zrr_owner(z, &z->rrs[i]),
                            z->rrs[i].owner_len) == 0);
    zone_free(l);
    CHECK(zone_load(path, z->apex, z->apex_len, exact - 1) == NULL);
    CHECK(zone_load(path, z->apex, z->apex_len, exact / 4) == NULL);
    zone_free(z);

    /* A damaged copy (a byte flipped, a byte more, a byte less) doesn't load. */
    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    uint8_t *img = malloc((size_t)sz + 1);
    CHECK(fread(img, 1, (size_t)sz, f) == (size_t)sz);
    fclose(f);
    long cuts[][2] = { { sz, 1 }, { sz + 1, 0 }, { sz - 1, 0 } }; /* length, flip at sz / 2 */
    for (int c = 0; c < 3; c++) {
        img[sz / 2] ^= (uint8_t)cuts[c][1];
        f = fopen(path, "wb");
        CHECK(fwrite(img, 1, (size_t)cuts[c][0], f) == (size_t)cuts[c][0]);
        fclose(f);
        img[sz / 2] ^= (uint8_t)cuts[c][1];
        CHECK(zone_load(path, apex, al, SIZE_MAX) == NULL);
    }
    free(img);
    remove(path);

    /* A "name" longer than a name (an NS record's rdata from a damaged copy, looked up for
     * glue) owns nothing, and isn't copied into a name's buffer. */
    uint8_t big[300];
    memset(big, 1, sizeof(big));
    size_t first = 7;
    z = new_zone(SIZE_MAX);
    CHECK(zone_finalize(z));
    CHECK(zone_find(z, big, (int)sizeof(big), &first) == 0 && first == 0);
    CHECK(!zone_name_exists(z, big, (int)sizeof(big)));
    zone_free(z);
}

/* ---- a fake primary on the loopback ---- */

#define PRIMARY_PORT 15354

typedef enum {
    P_SERVE,    /* the zone: SOA, records, SOA, in messages of 50 records */
    P_TRICKLE,  /* the zone, one byte every 20 ms: never a 5 s silence */
    P_SILENT,   /* takes the connection and the query, sends nothing */
    P_REFUSE,   /* REFUSED */
    P_ENDLESS,  /* SOA, then class CH records (they take no memory) forever, never the closing SOA */
    P_STRAYS,   /* UDP: a stray datagram from another port every 20 ms, never the answer */
    P_SOA,      /* UDP: a stray first, then the answer (an authoritative SOA, serial 7) */
} pmode_t;

typedef struct {
    pmode_t mode;
    uint32_t addr;
    int records;
    int tcp, udp, stray;
    volatile bool stop;
    pthread_t th;
} primary_t;

static uint32_t loopback(int x) { return htonl(0x7f000000u | (uint32_t)x); }

static int psock(int type, uint32_t addr, uint16_t port)
{
    int s = socket(AF_INET, type, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = addr };
    if (s < 0 || bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("fake primary: bind");
        exit(1);
    }
    return s;
}

/* One record, owner and rdata uncompressed. */
static size_t put_rr(uint8_t *m, size_t p, const uint8_t *o, int ol, uint16_t type, uint16_t cls,
                     const uint8_t *rd, int rl)
{
    memcpy(m + p, o, (size_t)ol);
    p += (size_t)ol;
    wr16(m + p, type);
    wr16(m + p + 2, cls);
    wr32(m + p + 4, 300);
    wr16(m + p + 8, (uint16_t)rl);
    memcpy(m + p + 10, rd, (size_t)rl);
    return p + 10 + (size_t)rl;
}

/* Starts a message answering query q (qlen bytes) into m, after its 2-byte length. */
static size_t msg_start(uint8_t *m, const uint8_t *q, size_t qlen, int rcode)
{
    memcpy(m + 2, q, qlen);
    wr16(m + 2 + 2, (uint16_t)(DNS_F_QR | DNS_F_AA | rcode));
    wr16(m + 2 + 6, 0);
    wr16(m + 2 + 8, 0);
    wr16(m + 2 + 10, 0);
    return 2 + qlen;
}

/* False once the secondary has gone. */
static bool msg_send(primary_t *pr, int c, uint8_t *m, size_t end, int an)
{
    wr16(m, (uint16_t)(end - 2));
    wr16(m + 2 + 6, (uint16_t)an);
    if (pr->mode == P_TRICKLE) {
        for (size_t i = 0; i < end; i++) {
            if (pr->stop || send(c, m + i, 1, MSG_NOSIGNAL) != 1)
                return false;
            usleep(20 * 1000);
        }
        return true;
    }
    return send(c, m, end, MSG_NOSIGNAL) == (ssize_t)end;
}

static void serve_tcp(primary_t *pr, int c)
{
    uint8_t lp[2], q[512];
    struct timeval tv = { .tv_sec = 2 };
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (recv(c, lp, 2, MSG_WAITALL) != 2)
        return;
    size_t qlen = rd16(lp);
    if (qlen > sizeof(q) || recv(c, q, qlen, MSG_WAITALL) != (ssize_t)qlen)
        return;
    static uint8_t m[65537];
    uint8_t apex[256], rd[600], o[256];
    int al = N(APEX, apex), sl = soa_rdata(rd, 7);
    if (pr->mode == P_SILENT) {
        while (!pr->stop)
            usleep(10 * 1000);
        return;
    }
    if (pr->mode == P_REFUSE) {
        size_t e = msg_start(m, q, qlen, DNS_R_REFUSED);
        msg_send(pr, c, m, e, 0);
        return;
    }
    size_t p = msg_start(m, q, qlen, 0);
    p = put_rr(m, p, apex, al, DNS_T_SOA, DNS_C_IN, rd, sl);
    int an = 1;
    uint8_t a[4] = { 192, 0, 2, 1 };
    for (int i = 0; !pr->stop && (pr->mode == P_ENDLESS || i < pr->records); i++) {
        char s[64];
        snprintf(s, sizeof(s), "h%d.example.test", i);
        int ol = N(s, o);
        p = put_rr(m, p, o, ol, DNS_T_A, pr->mode == P_ENDLESS ? 3 /* CH */ : DNS_C_IN, a, 4);
        if (++an == 50) {
            if (!msg_send(pr, c, m, p, an))
                return;
            p = msg_start(m, q, qlen, 0);
            an = 0;
        }
    }
    p = put_rr(m, p, apex, al, DNS_T_SOA, DNS_C_IN, rd, sl);
    msg_send(pr, c, m, p, an + 1);
}

static void *primary_run(void *arg)
{
    primary_t *pr = arg;
    if (pr->mode == P_SOA) {
        struct timeval tv = { .tv_usec = 20 * 1000 };
        setsockopt(pr->udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        while (!pr->stop) {
            uint8_t q[512], m[1024], apex[256], rd[600];
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            ssize_t n = recvfrom(pr->udp, q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
            if (n < DNS_HDR_LEN)
                continue;
            uint8_t junk[DNS_HDR_LEN] = { 0 };
            sendto(pr->stray, junk, sizeof(junk), 0, (struct sockaddr *)&from, fl);
            /* The question only (the query's OPT dropped), then the SOA. */
            size_t qend = DNS_HDR_LEN;
            dns_name_skip(q, (size_t)n, &qend);
            qend += 4;
            size_t p = msg_start(m, q, qend, 0) - 2;
            memmove(m, m + 2, p);
            int al = N(APEX, apex), sl = soa_rdata(rd, 7);
            p = put_rr(m, p, apex, al, DNS_T_SOA, DNS_C_IN, rd, sl);
            wr16(m + 6, 1);
            sendto(pr->udp, m, p, 0, (struct sockaddr *)&from, fl);
        }
        return NULL;
    }
    if (pr->mode == P_STRAYS) {
        struct timeval tv = { .tv_usec = 20 * 1000 };
        setsockopt(pr->udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in asker;
        bool asked = false;
        while (!pr->stop) {
            uint8_t m[512];
            socklen_t fl = sizeof(asker);
            struct sockaddr_in from;
            if (recvfrom(pr->udp, m, sizeof(m), 0, (struct sockaddr *)&from, &fl) > 0) {
                asker = from;
                asked = true;
            }
            if (asked) {
                uint8_t junk[DNS_HDR_LEN] = { 0 };
                sendto(pr->stray, junk, sizeof(junk), 0, (struct sockaddr *)&asker, sizeof(asker));
            }
        }
        return NULL;
    }
    struct timeval tv = { .tv_usec = 20 * 1000 };
    setsockopt(pr->tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    while (!pr->stop) {
        int c = accept(pr->tcp, NULL, NULL);
        if (c < 0)
            continue;
        serve_tcp(pr, c);
        close(c);
    }
    return NULL;
}

static void primary_start(primary_t *pr, pmode_t mode, int x, int records)
{
    memset(pr, 0, sizeof(*pr));
    pr->mode = mode;
    pr->addr = loopback(x);
    pr->records = records;
    pr->tcp = pr->udp = pr->stray = -1;
    if (mode == P_STRAYS || mode == P_SOA) {
        pr->udp = psock(SOCK_DGRAM, pr->addr, PRIMARY_PORT);
        pr->stray = psock(SOCK_DGRAM, pr->addr, 0);
    } else {
        pr->tcp = psock(SOCK_STREAM, pr->addr, PRIMARY_PORT);
        listen(pr->tcp, 4);
    }
    pthread_create(&pr->th, NULL, primary_run, pr);
}

static void primary_stop(primary_t *pr)
{
    pr->stop = true;
    pthread_join(pr->th, NULL);
    if (pr->tcp >= 0)
        close(pr->tcp);
    if (pr->udp >= 0)
        close(pr->udp);
    if (pr->stray >= 0)
        close(pr->stray);
}

static uint8_t s_msg[65535], s_rdata[65535];
static int s_progress;
static void count_progress(void *ctx) { (*(int *)ctx)++; }

static zone_t *pull(int x, size_t limit, int deadline_ms, axfr_err_t *err, int64_t *ms)
{
    uint8_t apex[256];
    int al = N(APEX, apex);
    s_progress = 0;
    axfr_opts_t o = { .msg = s_msg, .rdata = s_rdata, .limit = limit, .deadline_ms = deadline_ms,
                      .progress = count_progress, .ctx = &s_progress };
    int64_t t0 = mono_us();
    zone_t *z = axfr_pull(loopback(x), PRIMARY_PORT, apex, al, &o, err);
    *ms = (mono_us() - t0) / 1000;
    return z;
}

static void test_axfr(void)
{
    primary_t pr;
    axfr_err_t err;
    int64_t ms;

    /* A transfer: 1000 records in 21 messages. */
    primary_start(&pr, P_SERVE, 31, 1000);
    zone_t *z = pull(31, SIZE_MAX, 5000, &err, &ms);
    CHECK(z && err == AXFR_OK && z->n == 1001 && z->serial == 7 && s_progress == 21);
    size_t need = zone_mem(z);
    zone_free(z);
    /* Within a limit it fits: the heap held meanwhile, a growing buffer's old copy and new
     * one together, never more than the limit. */
    size_t base = peak_from();
    z = pull(31, 3 * need, 5000, &err, &ms);
    CHECK(z && err == AXFR_OK && z->n == 1001);
    CHECK(s_peak - base <= 3 * need);
    zone_free(z);
    /* Too big for its limit: refused at the record that would take it over. */
    z = pull(31, need / 2, 5000, &err, &ms);
    CHECK(!z && err == AXFR_TOO_BIG && s_progress < 21);
    primary_stop(&pr);

    /* A trickle (a byte every 20 ms) keeps every read's wait short: only the transfer's
     * deadline ends it. */
    primary_start(&pr, P_TRICKLE, 32, 1000);
    z = pull(32, SIZE_MAX, 600, &err, &ms);
    CHECK(!z && err == AXFR_TIMEOUT && ms >= 550 && ms < 1500);
    primary_stop(&pr);

    /* Silence: the deadline, not a read's wait. */
    primary_start(&pr, P_SILENT, 33, 0);
    z = pull(33, SIZE_MAX, 400, &err, &ms);
    CHECK(!z && err == AXFR_TIMEOUT && ms >= 350 && ms < 1500);
    primary_stop(&pr);

    /* Records that take no memory, without end: the deadline. */
    primary_start(&pr, P_ENDLESS, 34, 0);
    z = pull(34, SIZE_MAX, 500, &err, &ms);
    CHECK(!z && err == AXFR_TIMEOUT && ms >= 450 && ms < 1500 && s_progress > 10);
    primary_stop(&pr);

    primary_start(&pr, P_REFUSE, 35, 0);
    z = pull(35, SIZE_MAX, 2000, &err, &ms);
    CHECK(!z && err == AXFR_REFUSED);
    primary_stop(&pr);

    /* Nothing listening. */
    z = pull(36, SIZE_MAX, 2000, &err, &ms);
    CHECK(!z && err == AXFR_NET);

    /* A limit that can't hold the zone_t. */
    z = pull(36, 16, 2000, &err, &ms);
    CHECK(!z && err == AXFR_TOO_BIG);
}

static void test_soa_deadline(void)
{
    /* Strays every 20 ms never restart the SOA check's wait. */
    primary_t pr;
    uint8_t apex[256];
    int al = N(APEX, apex);
    uint32_t serial = 0;
    primary_start(&pr, P_STRAYS, 37, 0);
    int64_t t0 = mono_us();
    CHECK(!axfr_soa_serial(loopback(37), PRIMARY_PORT, apex, al, 300, &serial));
    int64_t ms = (mono_us() - t0) / 1000;
    CHECK(ms >= 250 && ms < 1500);
    primary_stop(&pr);

    /* The answer, after a stray. */
    primary_start(&pr, P_SOA, 38, 0);
    CHECK(axfr_soa_serial(loopback(38), PRIMARY_PORT, apex, al, 2000, &serial) && serial == 7);
    primary_stop(&pr);
}

int main(void)
{
    test_canonical_order();
    test_exists_matches_scan();
    test_long_names_bounded();
    test_zone_limit();
    test_axfr();
    test_soa_deadline();
    if (s_fail) {
        fprintf(stderr, "%d check(s) failed\n", s_fail);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
