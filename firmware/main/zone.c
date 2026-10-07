#include "zone.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

zone_t *zone_new(const uint8_t *apex, int apex_len, size_t limit)
{
    if (limit < sizeof(zone_t))
        return NULL;
    zone_t *z = calloc(1, sizeof(*z));
    if (!z)
        return NULL;
    memcpy(z->apex, apex, (size_t)apex_len);
    z->apex_len = apex_len;
    dns_name_lower(z->apex, apex_len);
    z->limit = limit;
    return z;
}

void zone_free(zone_t *z)
{
    if (!z)
        return;
    free(z->rrs);
    free(z->arena);
    free(z);
}

size_t zone_mem(const zone_t *z)
{
    return z ? sizeof(*z) + z->cap * sizeof(zrr_t) + z->arena_cap : 0;
}

/* A buffer of cap items of size sz must hold need: its new capacity, at least need, doubled
 * from cap (or first) where that fits. The new block is counted next to everything z holds,
 * the old copy included (a realloc that moves it holds both): 0 when even need doesn't fit
 * (z->over set). */
static size_t grow_to(zone_t *z, size_t cap, size_t need, size_t first, size_t sz)
{
    size_t room = (z->limit - zone_mem(z)) / sz;
    size_t want = cap ? cap : first;
    while (want < need && want <= SIZE_MAX / 2)
        want *= 2;
    if (want < need)
        want = need;
    if (want > room)
        want = room;
    if (want < need) {
        z->over = true;
        return 0;
    }
    return want;
}

static bool grow_rrs(zone_t *z, size_t need, size_t first)
{
    size_t cap = grow_to(z, z->cap, need, first, sizeof(zrr_t));
    if (!cap)
        return false;
    zrr_t *r = realloc(z->rrs, cap * sizeof(*r));
    if (!r)
        return false;
    z->rrs = r;
    z->cap = cap;
    return true;
}

static bool grow_arena(zone_t *z, size_t need, size_t first)
{
    size_t cap = grow_to(z, z->arena_cap, need, first, 1);
    if (!cap)
        return false;
    uint8_t *a = realloc(z->arena, cap);
    if (!a)
        return false;
    z->arena = a;
    z->arena_cap = cap;
    return true;
}

bool zone_reserve(zone_t *z, size_t nrr, size_t arena_bytes)
{
    return (nrr <= z->cap || grow_rrs(z, nrr, nrr)) &&
           (arena_bytes <= z->arena_cap || grow_arena(z, arena_bytes, arena_bytes));
}

static bool arena_put(zone_t *z, const uint8_t *p, size_t n, uint32_t *off)
{
    if (z->arena_len + n > z->arena_cap && !grow_arena(z, z->arena_len + n, 4096))
        return false;
    memcpy(z->arena + z->arena_len, p, n);
    *off = (uint32_t)z->arena_len;
    z->arena_len += n;
    return true;
}

bool zone_add(zone_t *z, const uint8_t *owner, int owner_len, uint16_t type,
              uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
    uint8_t lower[DNS_MAX_NAME];
    if (owner_len <= 0 || owner_len > DNS_MAX_NAME)
        return false;
    memcpy(lower, owner, (size_t)owner_len);
    dns_name_lower(lower, owner_len);
    if (!dns_name_under(lower, owner_len, z->apex, z->apex_len))
        return true; /* out-of-zone data: ignore */
    /* The arena's offsets are 32-bit. */
    if (z->arena_len + (size_t)owner_len + rdlen > UINT32_MAX)
        return false;

    if (z->n == z->cap && !grow_rrs(z, z->n + 1, 64))
        return false;
    zrr_t *r = &z->rrs[z->n];
    if (!arena_put(z, lower, (size_t)owner_len, &r->owner_off) ||
        !arena_put(z, rdata, rdlen, &r->rdata_off))
        return false;
    r->owner_len = (uint8_t)owner_len;
    r->type = type;
    r->ttl = ttl;
    r->rdlen = rdlen;
    z->n++;
    return true;
}

/* A wire name's label starts, leftmost first (the root's empty label not counted). */
typedef struct {
    const uint8_t *p;
    int            len, n;
    uint8_t        off[DNS_MAX_NAME / 2 + 1];
} labels_t;

static void labels(labels_t *l, const uint8_t *p, int len)
{
    l->p = p;
    l->len = len;
    l->n = 0;
    for (int i = 0; i < len && p[i] && l->n < (int)sizeof(l->off); i += p[i] + 1)
        l->off[l->n++] = (uint8_t)i;
}

/* Canonical order (RFC 4034 6.1): the labels compared from the root, each as bytes, a
 * shorter one first where one is the start of the other; fewer labels first where all the
 * ones compared are equal. So a name comes right before everything under it. */
static int labels_cmp(const labels_t *a, const labels_t *b)
{
    for (int i = a->n - 1, j = b->n - 1; i >= 0 && j >= 0; i--, j--) {
        const uint8_t *x = a->p + a->off[i], *y = b->p + b->off[j];
        int c = memcmp(x + 1, y + 1, x[0] < y[0] ? x[0] : y[0]);
        if (c)
            return c;
        if (x[0] != y[0])
            return x[0] - y[0];
    }
    return a->n - b->n;
}

int zone_name_cmp(const uint8_t *a, int alen, const uint8_t *b, int blen)
{
    labels_t la, lb;
    labels(&la, a, alen);
    labels(&lb, b, blen);
    return labels_cmp(&la, &lb);
}

static int rr_cmp(const zone_t *z, const zrr_t *a, const zrr_t *b)
{
    int c = zone_name_cmp(zrr_owner(z, a), a->owner_len, zrr_owner(z, b), b->owner_len);
    if (c)
        return c;
    if (a->type != b->type)
        return a->type < b->type ? -1 : 1;
    c = memcmp(zrr_rdata(z, a), zrr_rdata(z, b), a->rdlen < b->rdlen ? a->rdlen : b->rdlen);
    return c ? c : (int)a->rdlen - (int)b->rdlen;
}

static void sift_down(zone_t *z, size_t i, size_t n)
{
    zrr_t *r = z->rrs;
    for (;;) {
        size_t c = 2 * i + 1;
        if (c >= n)
            return;
        if (c + 1 < n && rr_cmp(z, &r[c], &r[c + 1]) < 0)
            c++;
        if (rr_cmp(z, &r[i], &r[c]) >= 0)
            return;
        zrr_t t = r[i];
        r[i] = r[c];
        r[c] = t;
        i = c;
    }
}

/* Heapsort in place: nothing allocated, so a zone within its limit stays within it (and the
 * zone is the context qsort cannot carry portably). */
static void sort_rrs(zone_t *z)
{
    size_t n = z->n;
    for (size_t i = n / 2; i-- > 0;)
        sift_down(z, i, n);
    while (n > 1) {
        n--;
        zrr_t t = z->rrs[0];
        z->rrs[0] = z->rrs[n];
        z->rrs[n] = t;
        sift_down(z, 0, n);
    }
}

bool zone_finalize(zone_t *z)
{
    sort_rrs(z);

    /* Drop exact duplicates (AXFR repeats the SOA at the end). */
    size_t w = 0;
    for (size_t i = 0; i < z->n; i++) {
        if (w > 0 && rr_cmp(z, &z->rrs[w - 1], &z->rrs[i]) == 0)
            continue;
        z->rrs[w++] = z->rrs[i];
    }
    z->n = w;

    size_t first, cnt = zone_find(z, z->apex, z->apex_len, &first);
    int soas = 0;
    for (size_t i = first; i < first + cnt; i++) {
        const zrr_t *r = &z->rrs[i];
        if (r->type != DNS_T_SOA)
            continue;
        const uint8_t *rd = zrr_rdata(z, r);
        size_t off = 0;
        uint8_t tmp[DNS_MAX_NAME];
        /* rdata is already expanded, so names are plain sequences of labels */
        if (dns_name_read(rd, r->rdlen, &off, tmp) < 0 || dns_name_read(rd, r->rdlen, &off, tmp) < 0 ||
            off + 20 != r->rdlen)
            return false;
        z->serial = rd32(rd + off);
        z->refresh = rd32(rd + off + 4);
        z->retry = rd32(rd + off + 8);
        z->expire = rd32(rd + off + 12);
        z->minimum = rd32(rd + off + 16);
        z->soa_ttl = r->ttl;
        z->soa_idx = i;
        soas++;
    }
    return soas == 1;
}

/* The first record whose owner is at or after key in canonical order. */
static size_t lower_bound(const zone_t *z, const labels_t *key)
{
    size_t lo = 0, hi = z->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const zrr_t *r = &z->rrs[mid];
        labels_t o;
        labels(&o, zrr_owner(z, r), r->owner_len);
        if (labels_cmp(&o, key) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

size_t zone_find(const zone_t *z, const uint8_t *name, int len, size_t *first)
{
    uint8_t lower[DNS_MAX_NAME];
    labels_t key;
    *first = 0;
    /* Not a name (an NS record's rdata taken as one, say, from a damaged copy): no owner. */
    if (len <= 0 || len > DNS_MAX_NAME)
        return 0;
    memcpy(lower, name, (size_t)len);
    dns_name_lower(lower, len);
    labels(&key, lower, len);

    size_t lo = lower_bound(z, &key), end = lo;
    while (end < z->n && z->rrs[end].owner_len == len && !memcmp(zrr_owner(z, &z->rrs[end]), lower, (size_t)len))
        end++;
    *first = lo;
    return end - lo;
}

bool zone_name_exists(const zone_t *z, const uint8_t *name, int len)
{
    uint8_t lower[DNS_MAX_NAME];
    labels_t key;
    if (len <= 0 || len > DNS_MAX_NAME)
        return false;
    memcpy(lower, name, (size_t)len);
    dns_name_lower(lower, len);
    labels(&key, lower, len);

    /* name and everything under it sort together, name first: the first record at or after
     * it is one of them, if there are any. */
    size_t i = lower_bound(z, &key);
    return i < z->n && dns_name_under(zrr_owner(z, &z->rrs[i]), z->rrs[i].owner_len, lower, len);
}

/* ---- persistence ---- */

static const char MAGIC[8] = { 'D', 'N', 'S', '2', 'Z', 'N', '0', '1' };

static uint32_t crc32_update(uint32_t crc, const uint8_t *p, size_t n)
{
    crc = ~crc;
    while (n--) {
        crc ^= *p++;
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1)));
    }
    return ~crc;
}

static bool put(FILE *f, uint32_t *crc, const void *p, size_t n)
{
    *crc = crc32_update(*crc, p, n);
    return fwrite(p, 1, n, f) == n;
}

bool zone_save(const zone_t *z, const char *path)
{
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return false;

    uint32_t crc = 0;
    uint8_t b[8];
    bool ok = put(f, &crc, MAGIC, sizeof(MAGIC));
    wr32(b, (uint32_t)z->n);
    ok = ok && put(f, &crc, b, 4);
    for (size_t i = 0; ok && i < z->n; i++) {
        const zrr_t *r = &z->rrs[i];
        ok = put(f, &crc, &r->owner_len, 1) && put(f, &crc, zrr_owner(z, r), r->owner_len);
        wr16(b, r->type);
        wr32(b + 2, r->ttl);
        wr16(b + 6, r->rdlen);
        ok = ok && put(f, &crc, b, 8) && put(f, &crc, zrr_rdata(z, r), r->rdlen);
    }
    wr32(b, crc);
    ok = ok && fwrite(b, 1, 4, f) == 4;
    ok = (fflush(f) == 0) && ok;
    ok = (fclose(f) == 0) && ok;
    if (!ok) {
        remove(tmp);
        return false;
    }
    remove(path); /* FAT rename does not replace */
    return rename(tmp, path) == 0;
}

/* Reads n bytes into p (or past them, p NULL), into the running CRC. */
static bool get(FILE *f, uint32_t *crc, uint8_t *p, size_t n)
{
    uint8_t chunk[256];
    while (n) {
        size_t k = p ? n : n < sizeof(chunk) ? n : sizeof(chunk);
        uint8_t *dst = p ? p : chunk;
        if (fread(dst, 1, k, f) != k)
            return false;
        *crc = crc32_update(*crc, dst, k);
        if (p)
            p += k;
        n -= k;
    }
    return true;
}

/* One record's header: its owner (lowercased, in owner[]) and type, ttl, rdlen. */
static bool get_head(FILE *f, uint32_t *crc, uint8_t *owner, int *ol, uint16_t *type, uint32_t *ttl,
                     uint16_t *rdlen)
{
    uint8_t l, b[8];
    if (!get(f, crc, &l, 1) || l == 0 || !get(f, crc, owner, l) || !get(f, crc, b, 8))
        return false;
    *ol = l;
    dns_name_lower(owner, l);
    *type = rd16(b);
    *ttl = rd32(b + 2);
    *rdlen = rd16(b + 6);
    return true;
}

/* Streamed twice, nothing read whole: first the CRC and the sizes, then the records straight
 * into a zone reserved for exactly them. So loading holds the zone and nothing else, and the
 * zone exactly what it needs (zone_reserve), within limit. */
static zone_t *load_file(const char *path, const uint8_t *apex, int apex_len, size_t limit)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    zone_t *z = NULL;
    uint8_t magic[sizeof(MAGIC)], b[4], owner[DNS_MAX_NAME], lapex[DNS_MAX_NAME];
    int ol;
    uint16_t type, rdlen;
    uint32_t ttl, crc = 0, n, file_crc;
    size_t nrr = 0, bytes = 0;

    if (apex_len <= 0 || apex_len > DNS_MAX_NAME)
        goto out;
    memcpy(lapex, apex, (size_t)apex_len);
    dns_name_lower(lapex, apex_len);

    /* Pass 1: the CRC, and how many records (owners plus rdata bytes) are in the zone. */
    if (!get(f, &crc, magic, sizeof(magic)) || memcmp(magic, MAGIC, sizeof(MAGIC)) != 0 || !get(f, &crc, b, 4))
        goto out;
    n = rd32(b);
    for (uint32_t i = 0; i < n; i++) {
        if (!get_head(f, &crc, owner, &ol, &type, &ttl, &rdlen) || !get(f, &crc, NULL, rdlen))
            goto out;
        if (dns_name_under(owner, ol, lapex, apex_len)) {
            nrr++;
            bytes += (size_t)ol + rdlen;
        }
        /* The arena's offsets are 32-bit. */
        if (bytes > UINT32_MAX)
            goto out;
    }
    if (fread(b, 1, 4, f) != 4 || rd32(b) != crc || fgetc(f) != EOF)
        goto out;
    file_crc = crc;

    /* Pass 2: the records, into exactly that much. */
    z = zone_new(apex, apex_len, limit);
    if (!z || !zone_reserve(z, nrr, bytes) || fseek(f, (long)(sizeof(MAGIC) + 4), SEEK_SET) != 0)
        goto bad;
    crc = crc32_update(0, magic, sizeof(magic));
    wr32(b, n);
    crc = crc32_update(crc, b, 4);
    for (uint32_t i = 0; i < n; i++) {
        if (!get_head(f, &crc, owner, &ol, &type, &ttl, &rdlen))
            goto bad;
        if (!dns_name_under(owner, ol, z->apex, z->apex_len)) {
            if (!get(f, &crc, NULL, rdlen))
                goto bad;
            continue;
        }
        /* The file changed between the passes: more than was reserved. */
        if (z->n == z->cap || z->arena_len + (size_t)ol + rdlen > z->arena_cap)
            goto bad;
        zrr_t *r = &z->rrs[z->n];
        r->owner_off = (uint32_t)z->arena_len;
        memcpy(z->arena + z->arena_len, owner, (size_t)ol);
        z->arena_len += (size_t)ol;
        r->rdata_off = (uint32_t)z->arena_len;
        if (!get(f, &crc, z->arena + z->arena_len, rdlen))
            goto bad;
        z->arena_len += rdlen;
        r->owner_len = (uint8_t)ol;
        r->type = type;
        r->ttl = ttl;
        r->rdlen = rdlen;
        z->n++;
    }
    if (crc != file_crc || !zone_finalize(z))
        goto bad;
    goto out;
bad:
    zone_free(z);
    z = NULL;
out:
    fclose(f);
    return z;
}

zone_t *zone_load(const char *path, const uint8_t *apex, int apex_len, size_t limit)
{
    zone_t *z = load_file(path, apex, apex_len, limit);
    if (!z) {
        /* A crash between remove() and rename() in zone_save leaves only the .tmp. */
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "%s.tmp", path);
        z = load_file(tmp, apex, apex_len, limit);
    }
    return z;
}
