#include "blocklist.h"

#include <stdint.h>
#include <string.h>

#define SECTOR_BITS ((BL_SECTOR - 2) * 8)

static uint64_t le64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, 8); /* every target we build for is little-endian */
    return v;
}

static uint32_t le32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint64_t rotl(uint64_t x, unsigned r) { return r ? (x << r) | (x >> (64 - r)) : x; }

/* ---- SipHash-2-4, fed a byte at a time so a name can be hashed from the right ---- */

typedef struct {
    uint64_t v0, v1, v2, v3, m;
    uint32_t len;
} sip_t;

/* Always inlined, like the rest of the hashing, so name_walk keeps the state in registers. */
#define SIP_INLINE static inline __attribute__((always_inline))

SIP_INLINE void sip_round(sip_t *s)
{
    s->v0 += s->v1; s->v1 = rotl(s->v1, 13); s->v1 ^= s->v0; s->v0 = rotl(s->v0, 32);
    s->v2 += s->v3; s->v3 = rotl(s->v3, 16); s->v3 ^= s->v2;
    s->v0 += s->v3; s->v3 = rotl(s->v3, 21); s->v3 ^= s->v0;
    s->v2 += s->v1; s->v1 = rotl(s->v1, 17); s->v1 ^= s->v2; s->v2 = rotl(s->v2, 32);
}

SIP_INLINE void sip_init(sip_t *s, uint64_t k0, uint64_t k1)
{
    s->v0 = k0 ^ 0x736f6d6570736575ULL;
    s->v1 = k1 ^ 0x646f72616e646f6dULL;
    s->v2 = k0 ^ 0x6c7967656e657261ULL;
    s->v3 = k1 ^ 0x7465646279746573ULL;
    s->m = 0;
    s->len = 0;
}

/* Bytes come in at the top of m and move down, so every shift is by a constant (a variable
 * 64-bit shift is a branchy sequence on a 32-bit core); after 8 bytes the first is lowest. */
SIP_INLINE void sip_byte(sip_t *s, uint8_t c)
{
    s->m = s->m >> 8 | (uint64_t)c << 56;
    if ((++s->len & 7) == 0) {
        s->v3 ^= s->m;
        sip_round(s);
        sip_round(s);
        s->v0 ^= s->m;
        s->m = 0;
    }
}

/* The hash of what was fed so far; s itself is left as it was, to keep feeding. */
SIP_INLINE uint64_t sip_final(const sip_t *in)
{
    sip_t s = *in;
    unsigned r = s.len & 7; /* bytes waiting in the top of m */
    uint64_t b = (uint64_t)s.len << 56 | (r ? s.m >> (64 - 8 * r) : 0);
    s.v3 ^= b;
    sip_round(&s);
    sip_round(&s);
    s.v0 ^= b;
    s.v2 ^= 0xff;
    sip_round(&s);
    sip_round(&s);
    sip_round(&s);
    sip_round(&s);
    return s.v0 ^ s.v1 ^ s.v2 ^ s.v3;
}

uint64_t bl_siphash(uint64_t k0, uint64_t k1, const void *p, size_t n)
{
    sip_t s;
    sip_init(&s, k0, k1);
    for (size_t i = 0; i < n; i++)
        sip_byte(&s, ((const uint8_t *)p)[i]);
    return sip_final(&s);
}

/* ---- the file ---- */

size_t bl_front_len(const uint8_t hdr[BL_HEADER])
{
    if (memcmp(hdr, "ESPDNSBL", 8) != 0)
        return 0;
    return le32(hdr + 32 + 12); /* the exact table's sectors come first */
}

const char *bl_open(bl_t *b, const uint8_t *front, size_t front_len, size_t file_len, bl_read_fn read,
                    void *ctx, unsigned flags)
{
    memset(b, 0, sizeof(*b));
    if (front_len < 96 || memcmp(front, "ESPDNSBL", 8) != 0)
        return "not a blocklist";
    /* Version 1 had only the block tables (and a 96-byte header); the allow ones stay empty. */
    if (front[8] != 1 && front[8] != 2)
        return "unknown version";
    int tables = front[8] == 1 ? 2 : BL_TABLES;
    if (front_len < 32 + 32 * (size_t)tables)
        return "not a blocklist";
    b->bits = front[9];
    b->xor_bits = front[10];
    if (b->bits < 16 || b->bits > 64 || b->xor_bits > 16)
        return "bad widths";
    b->k0 = le64(front + 16);
    b->k1 = le64(front + 24);
    for (int i = 0; i < tables; i++) {
        const uint8_t *d = front + 32 + 32 * i;
        bl_table_t *t = &b->t[i];
        t->hashes = le32(d);
        t->sectors = le32(d + 4);
        uint32_t idx = le32(d + 8), xo = le32(d + 16);
        t->sectors_off = le32(d + 12);
        if ((uint64_t)idx + 8ull * t->sectors > front_len)
            return "index outside the file";
        if ((uintptr_t)(front + idx) % 8)
            return "index not 8-aligned";
        if (t->sectors_off % BL_SECTOR || (uint64_t)t->sectors_off + (uint64_t)BL_SECTOR * t->sectors > file_len)
            return "sectors outside the file";
        if ((t->hashes == 0) != (t->sectors == 0) || t->sectors > t->hashes)
            return "bad table size";
        t->index = (const uint64_t *)(front + idx);
        if (xo && b->xor_bits && !(flags & BL_NO_XOR)) {
            t->xor_seg = le32(d + 20);
            t->xor_seed = le64(d + 24);
            if ((uint64_t)xo + (3ull * t->xor_seg * b->xor_bits + 7) / 8 > front_len)
                return "filter outside the file";
            t->xor = front + xo;
        }
    }
    b->allow = b->t[BL_ALLOW_EXACT].sectors || b->t[BL_ALLOW_SUFFIX].sectors;
    b->read = read;
    b->ctx = ctx;
    return NULL;
}

size_t bl_index_size(const bl_t *b)
{
    size_t n = 0;
    for (int i = 0; i < BL_TABLES; i++)
        n += b->t[i].sectors;
    return 8 * n;
}

void bl_index_move(bl_t *b, uint64_t *buf)
{
    for (int i = 0; i < BL_TABLES; i++) {
        bl_table_t *t = &b->t[i];
        if (!t->sectors)
            continue;
        memcpy(buf, t->index, 8 * (size_t)t->sectors);
        t->index = buf;
        buf += t->sectors;
    }
}

/* Population count without the Zbb instructions the P4 lacks (__builtin_popcount would be
 * a libcall there). */
static inline unsigned popcount32(uint32_t x)
{
    x -= (x >> 1) & 0x55555555;
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x + (x >> 4)) & 0x0f0f0f0f;
    return (x * 0x01010101) >> 24;
}

/* The 32 bits at bit position pos, least significant first; bits past len bytes are 0.
 * Byte loads put together in registers where all five bytes are in (memcpy of an unaligned
 * word goes through the stack on the P4), a byte at a time with bounds only near the end. */
static inline uint32_t get32(const uint8_t *d, size_t len, uint32_t pos)
{
    size_t i = pos >> 3;
    unsigned sh = pos & 7;
    if (i + 5 <= len) {
        const uint8_t *p = d + i;
        uint32_t w = p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
        return w >> sh | (uint32_t)p[4] << (31 - sh) << 1; /* sh 0: no fifth byte */
    }
    uint64_t v = 0;
    for (unsigned k = 0; k < 5; k++)
        if (i + k < len)
            v |= (uint64_t)d[i + k] << (8 * k);
    return (uint32_t)(v >> sh);
}

/* n (≤ 64) bits at bit position pos, given mask_lo/mask_hi: the low n bits of a uint64,
 * as two halves (n ≤ 32 never reads the second word). */
static inline uint64_t getbits(const uint8_t *d, size_t len, uint32_t pos, uint32_t mask_lo, uint32_t mask_hi)
{
    uint32_t lo = get32(d, len, pos) & mask_lo;
    if (!mask_hi)
        return lo;
    return (uint64_t)(get32(d, len, pos + 32) & mask_hi) << 32 | lo;
}

static uint64_t mix(uint64_t h)
{
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

/* Xor filter: false means certainly not in the table. */
static bool xor_maybe(const bl_t *b, const bl_table_t *t, uint64_t h)
{
    unsigned f = b->xor_bits;
    uint64_t m = mix(h + t->xor_seed);
    uint32_t lo = (uint32_t)m, hi = (uint32_t)(m >> 32), mask = (1u << f) - 1; /* f ≤ 16 */
    uint32_t x = (lo ^ hi) & mask, seg = t->xor_seg;
    size_t len = (3ull * seg * f + 7) / 8;
    /* The low word of m rotated left by 0, 21 and 42, picking a slot in each segment
     * (all in 32 bits: no variable 64-bit shifts). */
    const uint32_t r[3] = { lo, lo << 21 | hi >> 11, hi << 10 | lo >> 22 };
    for (unsigned i = 0; i < 3; i++) {
        uint32_t slot = (uint32_t)(((uint64_t)r[i] * seg) >> 32) + i * seg;
        x ^= get32(t->xor, len, slot * f) & mask;
    }
    return x == 0;
}

/* Elias-Fano search of one sector for offset d (> 0) from its first hash. */
static bool sector_has(const uint8_t *sec, uint64_t d)
{
    const uint8_t *bits = sec + 2;
    const size_t len = BL_SECTOR - 2;
    unsigned m = sec[0], l = sec[1];
    if (m == 0 || l > 64)
        return false;
    uint64_t hb = l == 64 ? 0 : d >> l, low = l == 64 ? d : d & ((1ULL << l) - 1);
    if ((uint64_t)m * l >= SECTOR_BITS || hb >= SECTOR_BITS) /* the high part has fewer zeros */
        return false;
    uint32_t mask_lo = l >= 32 ? 0xffffffff : (1u << l) - 1;
    uint32_t mask_hi = l <= 32 ? 0 : l == 64 ? 0xffffffff : (1u << (l - 32)) - 1;
    /* Skip hb zeros in the high part, counting the ones passed: that is the entry index.
     * Bits past the sector read as 0; if the zero we want is one of those, the run of ones
     * after it is empty and the answer no, as it should be. */
    uint32_t pos = m * l, need = (uint32_t)hb;
    unsigned idx = 0;
    while (need) {
        if (pos >= SECTOR_BITS)
            return false;
        uint32_t w = get32(bits, len, pos);
        unsigned ones = popcount32(w);
        if (32 - ones < need) {
            need -= 32 - ones;
            idx += ones;
            pos += 32;
            continue;
        }
        /* The zero we want is in this word: clear the need-1 zeros below it, then count
         * the ones below it. */
        uint32_t z = ~w;
        for (uint32_t k = need; --k;)
            z &= z - 1;
        unsigned below = popcount32(w & ((z & -z) - 1));
        idx += below;
        pos += below + need;
        need = 0;
    }
    /* The ones from here are the entries whose high part is hb, in order. */
    for (;; pos += 32) {
        uint32_t w = get32(bits, len, pos);
        for (unsigned k = 0; k < 32; k++, w >>= 1, idx++) {
            if (!(w & 1) || idx >= m)
                return false;
            uint64_t v = getbits(bits, len, idx * l, mask_lo, mask_hi);
            if (v >= low)
                return v == low;
        }
    }
}

/* The last sector whose first hash is ≤ h, plus one: 0 if h is below them all. */
static uint32_t index_find(const bl_table_t *t, uint64_t h)
{
    uint32_t lo = 0, hi = t->sectors;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (t->index[mid] <= h)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/* One table lookup: 1 found, 0 not, -1 its sector couldn't be read. */
static inline int lookup(const bl_t *b, int table, uint64_t h, bl_stats_t *st)
{
    const bl_table_t *t = &b->t[table];
    if (st)
        st->checks++;
    if (t->sectors == 0)
        return 0;
    if (t->xor && !xor_maybe(b, t, h)) {
        if (st)
            st->filtered++;
        return 0;
    }
    uint32_t lo = index_find(t, h);
    if (lo == 0)
        return 0;
    uint64_t first = t->index[lo - 1];
    if (first == h)
        return 1;
    const uint8_t *sec = b->read(b->ctx, t->sectors_off + (lo - 1) * BL_SECTOR);
    if (st)
        st->reads++;
    if (!sec) {
        if (st)
            st->errors++;
        return -1;
    }
    return sector_has(sec, h - first);
}

bool bl_contains(const bl_t *b, int table, uint64_t h, bl_stats_t *st) { return lookup(b, table, h, st) > 0; }

/* What name_walk does with each hash. */
enum { WALK_BLOCKED, WALK_VERDICT, WALK_HASHES };

/* Whether h at one level matches a table pair: the suffix one, and the exact one too at
 * the whole name. A sector that can't be read counts as no block and as an allow, so a bad
 * card makes a list block less, never more. */
#define MATCH(sfx, ex) (lookup(b, sfx, h, st) > 0 || (whole && lookup(b, ex, h, st) > 0))
#define ALLOWED (lookup(b, BL_ALLOW_SUFFIX, h, st) != 0 || (whole && lookup(b, BL_ALLOW_EXACT, h, st) != 0))

/* Hashes a query's names from the right, shortest suffix first, so each level that
 * matches is more specific than the ones before: the last match decides, and at one level
 * allow beats block.
 *   WALK_BLOCKED: returns BL_BLOCK if blocked, else BL_NONE. The allow tables are checked
 *     only while a block stands, and with none it stops at the first block.
 *   WALK_VERDICT: returns the bl_verdict_t, checking all four tables at every level.
 *   WALK_HASHES: stores up to room hashes in out and returns how many (bl_name_hashes,
 *     for the benchmark).
 * Inlined into each, so mode folds away. */
static inline __attribute__((always_inline)) size_t name_walk(const bl_t *b, const uint8_t *qname, bl_stats_t *st,
                                                             int mode, uint64_t *out, size_t room)
{
    /* Find the labels, then hash from the right: after each label, the bytes fed are a
     * suffix of the name with its labels reversed ("com.example.ads"), which is what the
     * controller hashed. */
    const uint8_t *label[128];
    int n = 0;
    for (const uint8_t *p = qname; *p; p += 1 + *p) {
        if (*p > 63 || n == 128)
            return 0;
        label[n++] = p;
    }
    if (n < 2)
        return 0;
    sip_t s;
    sip_init(&s, b->k0, b->k1);
    const unsigned shift = 64 - b->bits;
    size_t k = 0, v = BL_NONE;
    for (int i = n - 1; i >= 0; i--) {
        if (i != n - 1)
            sip_byte(&s, '.');
        for (unsigned j = 1; j <= label[i][0]; j++) {
            uint8_t c = label[i][j];
            if (c == '.')
                return mode == WALK_HASHES ? k : v; /* a dot inside a label: no list holds the rest */
            sip_byte(&s, c >= 'A' && c <= 'Z' ? c + 32 : c);
        }
        if (i > n - 2)
            continue; /* one label: never blocked */
        uint64_t h = sip_final(&s) >> shift;
        const bool whole = i == 0;
        if (mode == WALK_HASHES) {
            if (k == room)
                return k;
            out[k++] = h;
        } else if (mode == WALK_VERDICT) {
            if (ALLOWED)
                v = BL_ALLOW;
            else if (v != BL_BLOCK && MATCH(BL_SUFFIX, BL_EXACT))
                v = BL_BLOCK;
        } else {
            if (v == BL_NONE && MATCH(BL_SUFFIX, BL_EXACT)) {
                if (!b->allow)
                    return BL_BLOCK;
                v = BL_BLOCK;
            }
            if (v == BL_BLOCK && ALLOWED)
                v = BL_NONE; /* an allow here or deeper; a block deeper still sets it again */
        }
    }
    return mode == WALK_HASHES ? k : v;
}

#undef MATCH
#undef ALLOWED

bool bl_blocked(const bl_t *b, const uint8_t *qname, bl_stats_t *st)
{
    return name_walk(b, qname, st, WALK_BLOCKED, NULL, 0) == BL_BLOCK;
}

bl_verdict_t bl_verdict(const bl_t *b, const uint8_t *qname, bl_stats_t *st)
{
    return (bl_verdict_t)name_walk(b, qname, st, WALK_VERDICT, NULL, 0);
}

/* ---- bench only ---- */

size_t bl_name_hashes(const bl_t *b, const uint8_t *qname, uint64_t *out, size_t room)
{
    return name_walk(b, qname, NULL, WALK_HASHES, out, room);
}

uint32_t bl_index_find(const bl_t *b, int table, uint64_t h) { return index_find(&b->t[table], h); }

bool bl_xor_maybe(const bl_t *b, int table, uint64_t h)
{
    return !b->t[table].xor || xor_maybe(b, &b->t[table], h);
}

bool bl_sector_has(const uint8_t *sec, uint64_t d) { return sector_has(sec, d); }
