/*
 * Blocklist lookup speed on real lists. Same C as the node; runs on the host and, built
 * into bench/blocklist, on a board.
 *
 *   go run ./cmd/blockbench ... -bits 44 -write list.bin -queries q.txt   (in controller/)
 *   make bench FILE=list.bin QUERIES=q.txt                                (in tests/)
 *
 * Table lookups are timed on hashes computed up front, against a plain table of
 * whole-byte hashes (decoded from the same file) as the baseline: the RAM tier with and
 * without the xor filter, with the sector index left in the file (PSRAM on a board) or
 * moved to internal RAM, and the SD tier with sectors copied out one at a time, as a card
 * read would. Then whole queries, hashing included. Last, each stage of a lookup timed
 * alone on the same checks (hashing, xor filter, index search, sector search), and their sum
 * against the whole.
 */
#include "bench_blocklist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns_wire.h"

static const uint8_t *read_ram(void *ctx, uint32_t off) { return (const uint8_t *)ctx + off; }

static uint8_t s_buf[BL_SECTOR];
static const uint8_t *read_copy(void *ctx, uint32_t off)
{
    memcpy(s_buf, (const uint8_t *)ctx + off, BL_SECTOR);
    return s_buf;
}

/* ---- baseline: whole-byte hashes, binary search ---- */

static uint64_t bits_at(const uint8_t *d, uint32_t pos, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++)
        v |= (uint64_t)(d[(pos + i) >> 3] >> ((pos + i) & 7) & 1) << i;
    return v;
}

typedef struct {
    uint8_t *data;
    size_t n;
    unsigned eb;
} plain_t;

static bool plain_build(plain_t *p, const bl_t *b, const uint8_t *file, int table)
{
    const bl_table_t *t = &b->t[table];
    p->eb = (b->bits + 7) / 8;
    p->data = malloc((size_t)t->hashes * p->eb + 8);
    p->n = 0;
    if (!p->data)
        return false;
    for (uint32_t s = 0; s < t->sectors; s++) {
        const uint8_t *sec = file + t->sectors_off + s * BL_SECTOR, *bits = sec + 2;
        uint64_t first = t->index[s], vals[257];
        unsigned m = sec[0], l = sec[1], k = 0;
        vals[k++] = first;
        uint64_t hi = 0;
        for (uint32_t i = 0, pos = m * l; i < m; pos++) {
            if (bits_at(bits, pos, 1))
                vals[k++] = first + (hi << l | bits_at(bits, i++ * l, l));
            else
                hi++;
        }
        for (unsigned i = 0; i < k; i++, p->n++)
            for (unsigned j = 0; j < p->eb; j++)
                p->data[p->n * p->eb + j] = (uint8_t)(vals[i] >> (8 * (p->eb - 1 - j)));
    }
    return true;
}

static bool plain_has(const plain_t *p, uint64_t h)
{
    size_t lo = 0, hi = p->n;
    while (lo < hi) {
        size_t m = (lo + hi) / 2;
        uint64_t v = 0;
        for (unsigned j = 0; j < p->eb; j++)
            v = v << 8 | p->data[m * p->eb + j];
        if (v == h)
            return true;
        if (v < h)
            lo = m + 1;
        else
            hi = m;
    }
    return false;
}

static size_t wire_len(const uint8_t *q)
{
    const uint8_t *p = q;
    while (*p)
        p += 1 + *p;
    return (size_t)(p - q) + 1;
}

/* The checks bl_blocked makes for a query (every one, no early stop), hashed up front. */
typedef struct {
    uint64_t h;
    uint8_t table;
} check_t;

static size_t query_checks(const bl_t *b, const uint8_t *q, check_t *out, size_t room)
{
    const uint8_t *label[128];
    int n = 0;
    for (const uint8_t *p = q; *p && n < 128; p += 1 + *p)
        label[n++] = p;
    uint8_t rev[256];
    size_t len = 0, k = 0;
    for (int i = n - 1; i >= 0 && k + 2 <= room; i--) {
        if (i != n - 1)
            rev[len++] = '.';
        for (unsigned j = 1; j <= label[i][0]; j++) {
            uint8_t c = label[i][j];
            rev[len++] = c >= 'A' && c <= 'Z' ? c + 32 : c;
        }
        if (i > n - 2)
            continue;
        uint64_t h = bl_siphash(b->k0, b->k1, rev, len) >> (64 - b->bits);
        out[k++] = (check_t){ h, BL_SUFFIX };
        if (i == 0)
            out[k++] = (check_t){ h, BL_EXACT };
    }
    return k;
}

/* ---- where a lookup's time goes: each stage timed alone, on the same checks ---- */

static volatile uint64_t s_sink; /* every timed loop's results end here, so none is optimized away */

/* Best of three runs of the statements given, in seconds. */
#define BEST_OF_3(best, ...)                      \
    do {                                          \
        best = 1e9;                               \
        for (int rep_ = 0; rep_ < 3; rep_++) {    \
            double t0_ = bench_now();             \
            __VA_ARGS__;                          \
            double el_ = bench_now() - t0_;       \
            if (el_ < best)                       \
                best = el_;                       \
        }                                         \
    } while (0)

/* A sector search a check makes: the sector (in the file) and the offset it looks for. */
typedef struct {
    const uint8_t *sec;
    uint64_t d;
    uint32_t check;
    bool xor_pass;
} search_t;

static void stage_row(FILE *out, const char *name, double sec, size_t calls, size_t nc, size_t nq)
{
    fprintf(out, "| %s | %.3f | %.0f | %.0f | %.0f |\n", name, (double)calls / nc, sec * 1e9 / calls, sec * 1e9 / nc,
            sec * 1e9 / nq);
}

/* b has the index in the file, fast in internal RAM; both with the xor filter if the file
 * has one. Returns 0, or 1 if a stage's answers disagree with the whole lookup's. */
static int bench_stages(FILE *out, const bl_t *b, const bl_t *fast, const check_t *cs, size_t nc, const uint8_t *want,
                        const uint8_t *wire, size_t nq)
{
    uint64_t acc = 0;
    double t;
    search_t *ss = malloc((nc + 1) * sizeof(search_t));
    if (!ss) {
        fprintf(out, "out of memory for the stages\n");
        return 1;
    }
    fprintf(out, "\n| Stage (timed alone) | calls/check | ns/call | ns/check | ns/query |\n|---|---|---|---|---|\n");

    BEST_OF_3(t, for (size_t i = 0; i < nc; i++) acc += cs[i].h);
    stage_row(out, "Loop over the checks, nothing else", t, nc, nc, nq);

    /* Hashing: the label scan alone (a copy of bl_blocked's), then all of it. */
    size_t nh = 0;
    BEST_OF_3(t, for (size_t i = 0, off = 0; i < nq; i++) {
        const uint8_t *label[128], *q = wire + off;
        int n = 0;
        for (const uint8_t *p = q; *p && n < 128; p += 1 + *p)
            label[n++] = p;
        acc += n ? (uintptr_t)label[n - 1] : 0;
        off += wire_len(q);
    });
    stage_row(out, "Split the query into labels (bench copy)", t, nq, nc, nq);
    uint64_t hs[128]; /* a name has at most 127 labels */
    BEST_OF_3(t, nh = 0; for (size_t i = 0, off = 0; i < nq; i++) {
        size_t k = bl_name_hashes(b, wire + off, hs, 128);
        acc += k ? hs[k - 1] : 0;
        nh += k;
        off += wire_len(wire + off);
    });
    stage_row(out, "Hash the query's names (bl_name_hashes)", t, nh, nc, nq);
    /* The same hashes as the checks: per query, each suffix, then the last again (exact). */
    size_t c = 0, bad = 0;
    for (size_t i = 0, off = 0; i < nq; i++) {
        size_t k = bl_name_hashes(b, wire + off, hs, 128);
        for (size_t j = 0; j < k; j++)
            bad += c >= nc || cs[c++].h != hs[j];
        c += k > 0;
        off += wire_len(wire + off);
    }
    if (bad || c != nc) {
        fprintf(out, "bl_name_hashes: %zu hashes differ from the checks'\n", bad);
        free(ss);
        return 1;
    }

    /* Xor filter probe, every check. */
    double t_xor = 0;
    size_t passed = 0;
    if (b->t[0].xor || b->t[1].xor) {
        BEST_OF_3(t_xor, passed = 0; for (size_t i = 0; i < nc; i++) passed += bl_xor_maybe(b, cs[i].table, cs[i].h));
        stage_row(out, "Xor filter probe (filter in the file)", t_xor, nc, nc, nq);
    }

    /* Index search, every check, then the sector searches it leads to. */
    BEST_OF_3(t, for (size_t i = 0; i < nc; i++) acc += bl_index_find(b, cs[i].table, cs[i].h));
    stage_row(out, "Index search (index in the file)", t, nc, nc, nq);
    double t_idx;
    BEST_OF_3(t_idx, for (size_t i = 0; i < nc; i++) acc += bl_index_find(fast, cs[i].table, cs[i].h));
    stage_row(out, "Index search (index in internal RAM)", t_idx, nc, nc, nq);
    size_t nss = 0, nss_xor = 0;
    for (size_t i = 0; i < nc; i++) {
        const bl_table_t *tb = &b->t[cs[i].table];
        uint32_t lo = bl_index_find(b, cs[i].table, cs[i].h);
        if (lo == 0 || tb->index[lo - 1] == cs[i].h)
            continue;
        bool xp = bl_xor_maybe(b, cs[i].table, cs[i].h);
        ss[nss++] = (search_t){ b->read(b->ctx, tb->sectors_off + (lo - 1) * BL_SECTOR), cs[i].h - tb->index[lo - 1],
                                (uint32_t)i, xp };
        nss_xor += xp;
    }
    double t_sec = 0, t_copy = 0, t_both = 0;
    size_t found = 0;
    if (nss) {
        BEST_OF_3(t_sec, found = 0; for (size_t i = 0; i < nss; i++) found += bl_sector_has(ss[i].sec, ss[i].d));
        stage_row(out, "Sector search (sector in the file)", t_sec, nss, nc, nq);
        bad = 0;
        for (size_t i = 0; i < nss; i++)
            bad += bl_sector_has(ss[i].sec, ss[i].d) != want[ss[i].check];
        if (bad) {
            fprintf(out, "bl_sector_has: %zu answers differ\n", bad);
            free(ss);
            return 1;
        }
        /* The same, each sector copied to a buffer first, the copy's time taken off: the
         * search with its sector in internal RAM and in cache. */
        BEST_OF_3(t_copy, for (size_t i = 0; i < nss; i++) {
            memcpy(s_buf, ss[i].sec, BL_SECTOR);
            acc += s_buf[i % BL_SECTOR];
        });
        BEST_OF_3(t_both, for (size_t i = 0; i < nss; i++) {
            memcpy(s_buf, ss[i].sec, BL_SECTOR);
            acc += bl_sector_has(s_buf, ss[i].d);
        });
        stage_row(out, "Copy the sector out (512 bytes)", t_copy, nss, nc, nq);
        stage_row(out, "Sector search (just copied: copy time taken off)", t_both - t_copy, nss, nc, nq);
    }

    /* SipHash on its own: 64-bit arithmetic on a 32-bit core. */
    static const char msg[] = "ads.tracker.example."; /* 20 bytes */
    BEST_OF_3(t, for (size_t i = 0; i < nc; i++) acc += bl_siphash(b->k0, b->k1 + i, msg, 20));
    fprintf(out, "| SipHash-2-4 of 20 bytes (bl_siphash) | — | %.0f | — | — |\n", t * 1e9 / nc);

    /* The stages added up, against the lookup timed whole on the same checks. */
    double idx_call = t_idx / nc, sec_call = nss ? t_sec / nss : 0;
    double sum = idx_call * nc + sec_call * nss, sum_xor = t_xor + idx_call * passed + sec_call * nss_xor;
    bl_t m = *fast;
    m.t[0].xor = m.t[1].xor = NULL;
    double whole, whole_xor = 0, whole_q;
    BEST_OF_3(whole, for (size_t i = 0; i < nc; i++) acc += bl_contains(&m, cs[i].table, cs[i].h, NULL));
    fprintf(out, "| Sum: index (internal RAM) + sector search, no filter | | | %.0f | %.0f |\n", sum * 1e9 / nc,
            sum * 1e9 / nq);
    fprintf(out, "| Whole: bl_contains, no filter, index in internal RAM | | | %.0f | %.0f |\n", whole * 1e9 / nc,
            whole * 1e9 / nq);
    if (b->t[0].xor || b->t[1].xor) {
        BEST_OF_3(whole_xor, for (size_t i = 0; i < nc; i++) acc += bl_contains(fast, cs[i].table, cs[i].h, NULL));
        fprintf(out, "| Sum: xor + index (internal RAM) + sector search, of what passes | | | %.0f | %.0f |\n",
                sum_xor * 1e9 / nc, sum_xor * 1e9 / nq);
        fprintf(out, "| Whole: bl_contains + xor filter, index in internal RAM | | | %.0f | %.0f |\n",
                whole_xor * 1e9 / nc, whole_xor * 1e9 / nq);
    }
    double hash_q;
    BEST_OF_3(hash_q, for (size_t i = 0, off = 0; i < nq; i++) {
        acc += bl_name_hashes(b, wire + off, hs, 128);
        off += wire_len(wire + off);
    });
    BEST_OF_3(whole_q, for (size_t i = 0, off = 0; i < nq; i++) {
        acc += bl_blocked(&m, wire + off, NULL);
        off += wire_len(wire + off);
    });
    fprintf(out, "| Sum: hashing + every check, no filter | | | | %.0f |\n", (hash_q + sum) * 1e9 / nq);
    fprintf(out, "| Whole: bl_blocked, no filter, index in internal RAM (stops at the first match) | | | | %.0f |\n",
            whole_q * 1e9 / nq);
    s_sink = acc + found + passed;
    free(ss);
    return 0;
}

int bench_run(FILE *out, const uint8_t *file, size_t len, const char *qtext, size_t qlen, size_t max_queries)
{
    bl_t b;
    const char *err = bl_open(&b, file, len, len, read_ram, (void *)file, 0);
    if (err) {
        fprintf(out, "bad file: %s\n", err);
        return 1;
    }

    /* Queries, as wire names packed end to end. */
    size_t cap = 2 * qlen + 2, nq = 0, used = 0; /* a wire name is at most 2 longer than its line */
    uint8_t *wire = malloc(cap), name[DNS_MAX_NAME];
    if (!wire) {
        fprintf(out, "out of memory for the queries\n");
        return 1;
    }
    char line[256];
    for (size_t i = 0; i < qlen && nq < max_queries;) {
        size_t j = i;
        while (j < qlen && qtext[j] != '\n')
            j++;
        if (j - i < sizeof(line)) {
            memcpy(line, qtext + i, j - i);
            line[j - i] = 0;
            int n = dns_name_from_str(line, name);
            if (n > 0 && used + (size_t)n <= cap) {
                memcpy(wire + used, name, (size_t)n);
                used += (size_t)n;
                nq++;
            }
        }
        i = j + 1;
    }
    fprintf(out, "%zu bytes, %u-bit hashes, xor %u, %u+%u hashes; %zu queries\n", len, b.bits, b.xor_bits, (unsigned)b.t[0].hashes,
           (unsigned)b.t[1].hashes, nq);

    plain_t pt[2];
    if (!plain_build(&pt[0], &b, file, BL_EXACT) || !plain_build(&pt[1], &b, file, BL_SUFFIX)) {
        fprintf(out, "out of memory for the baseline\n");
        return 1;
    }
    size_t room = nq * 3 + 64, nc = 0; /* about 2.2 checks a query; any past this go untimed */
    check_t *cs = malloc(room * sizeof(check_t));
    if (!cs) {
        fprintf(out, "out of memory for the checks\n");
        return 1;
    }
    for (size_t i = 0, off = 0; i < nq; i++) {
        nc += query_checks(&b, wire + off, cs + nc, room - nc);
        off += wire_len(wire + off);
    }
    uint8_t *want = malloc(nc);
    size_t hits = 0;
    for (size_t i = 0; i < nc; i++)
        hits += want[i] = plain_has(&pt[cs[i].table], cs[i].h);
    fprintf(out, "%zu checks (%.2f per query), %.1f%% match\n\n", nc, (double)nc / nq, 100.0 * hits / nc);

    /* The same file, its indexes moved to internal RAM. */
    uint64_t *idx = bench_index_alloc(bl_index_size(&b));
    if (!idx) {
        fprintf(out, "no internal RAM for the %zu-byte index\n", bl_index_size(&b));
        return 1;
    }
    bl_t fast = b;
    bl_index_move(&fast, idx);
    fprintf(out, "index: %zu bytes (%.2f bytes/domain)\n\n", bl_index_size(&b),
            (double)bl_index_size(&b) / (b.t[0].hashes + b.t[1].hashes));

    typedef struct {
        const char *name;
        bool xor, moved, sd;
    } bench_mode_t;
    static const bench_mode_t lookups[] = {
        { "EF sectors, RAM", false, false, false },
        { "EF sectors + xor filter, RAM", true, false, false },
        { "EF sectors, RAM", false, true, false },
        { "EF sectors + xor filter, RAM", true, true, false },
        { "EF sectors + xor filter, SD (sector copied out)", true, true, true },
    };
    fprintf(out, "| Table lookups | index | ns/check | filtered | sectors/check |\n|---|---|---|---|---|\n");
    for (int mode = -1; mode < (int)(sizeof(lookups) / sizeof(*lookups)); mode++) {
        const bench_mode_t *md = mode < 0 ? NULL : &lookups[mode];
        bl_t m = md && md->moved ? fast : b;
        if (md && !md->xor)
            m.t[0].xor = m.t[1].xor = NULL;
        if (md && md->sd)
            m.read = read_copy;
        double best = 1e9;
        bl_stats_t st = { 0 };
        size_t wrong = 0;
        for (int rep = 0; rep < 3; rep++) {
            memset(&st, 0, sizeof(st));
            wrong = 0;
            double t0 = bench_now();
            for (size_t i = 0; i < nc; i++) {
                bool hit = !md ? plain_has(&pt[cs[i].table], cs[i].h) : bl_contains(&m, cs[i].table, cs[i].h, &st);
                wrong += hit != want[i];
            }
            double el = bench_now() - t0;
            if (el < best)
                best = el;
        }
        if (wrong) {
            fprintf(out, "%s: %zu answers differ from the plain table\n", md->name, wrong);
            return 1;
        }
        if (!md)
            fprintf(out, "| Plain whole-byte hashes, RAM | — | %.0f | — | — |\n", best * 1e9 / nc);
        else
            fprintf(out, "| %s | %s | %.0f | %.1f%% | %.4f |\n", md->name, md->moved ? "internal RAM" : "in the file",
                    best * 1e9 / nc, 100.0 * st.filtered / st.checks, (double)st.reads / st.checks);
    }

    static const bench_mode_t queries[] = {
        { "RAM, no filter", false, false, false },
        { "RAM, no filter", false, true, false },
        { "RAM + xor filter", true, true, false },
        { "SD + xor filter", true, true, true },
    };
    fprintf(out, "\n| Whole query (bl_blocked) | index | ns/query | sectors/query | blocked |\n|---|---|---|---|---|\n");
    for (size_t mode = 0; mode < sizeof(queries) / sizeof(*queries); mode++) {
        const bench_mode_t *md = &queries[mode];
        bl_t m = md->moved ? fast : b;
        if (!md->xor)
            m.t[0].xor = m.t[1].xor = NULL;
        if (md->sd)
            m.read = read_copy;
        double best = 1e9;
        bl_stats_t st = { 0 };
        size_t blocked = 0;
        for (int rep = 0; rep < 3; rep++) {
            memset(&st, 0, sizeof(st));
            blocked = 0;
            double t0 = bench_now();
            for (size_t i = 0, off = 0; i < nq; i++) {
                blocked += bl_blocked(&m, wire + off, &st);
                off += wire_len(wire + off);
            }
            double el = bench_now() - t0;
            if (el < best)
                best = el;
        }
        fprintf(out, "| %s | %s | %.0f | %.3f | %.1f%% |\n", md->name, md->moved ? "internal RAM" : "in the file",
                best * 1e9 / nq, (double)st.reads / nq, 100.0 * blocked / nq);
    }
    size_t front = bl_front_len(file);
    size_t ram = len - front + bl_index_size(&b), domains = b.t[0].hashes + b.t[1].hashes;
    fprintf(out, "\nSD tier keeps %zu bytes in RAM (header, index, filters): %.2f bytes/domain\n", front,
           (double)front / domains);
    fprintf(out, "RAM tier keeps %zu bytes (sectors, index; opened with BL_NO_XOR): %.2f bytes/domain, against %.2f with the filter\n",
            ram, (double)ram / domains, (double)(ram + front - BL_HEADER - bl_index_size(&b)) / domains);
    int rc = bench_stages(out, &b, &fast, cs, nc, want, wire, nq);
    free(idx);
    free(wire);
    free(cs);
    free(want);
    free(pt[0].data);
    free(pt[1].data);
    return rc;
}

#ifndef BENCH_NO_MAIN
#include <time.h>

double bench_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

void *bench_index_alloc(size_t n) { return malloc(n ? n : 1); }

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    *len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*len + 1);
    if (fread(b, 1, *len, f) != *len)
        exit(1);
    fclose(f);
    return b;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: bench_blocklist <list.bin> <queries.txt>\n");
        return 2;
    }
    size_t len, qlen;
    uint8_t *file = slurp(argv[1], &len);
    char *q = (char *)slurp(argv[2], &qlen);
    return bench_run(stdout, file, len, q, qlen, (size_t)-1 / 64);
}
#endif
