#include "cache.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "dns_wire.h"
#include "memplan.h"

#define NBUCKETS 1024
#define CHUNK    64
#define NIL      UINT32_MAX

/* Entries and chunks are indexes into the block, so the cache can live anywhere. */
typedef struct {
    uint32_t hnext;      /* hash chain; the free list */
    uint32_t prev, next; /* LRU list, head = most recent */
    uint32_t hash;
    uint32_t stored_s, expires_s;
    uint32_t first;      /* its chunks: qname (lowercase) then message */
    uint16_t qtype, qclass;
    uint16_t len;
    uint8_t  cd;
    uint8_t  qlen;
} entry_t;

struct cache {
    pthread_mutex_t lock;
    bool owned; /* from cache_new */
    uint32_t buckets[NBUCKETS];
    uint32_t head, tail;
    uint32_t free_e, free_c, nfree_c;
    uint32_t nentries, nchunks;
    entry_t *e;
    uint32_t *cnext;
    uint8_t *chunk;
    cache_stats_t st;
    uint32_t gen; /* flushes; written under lock, read without it (cache_gen) */
};

/* What the plan holds for the cache (memplan.h): cache_new_in on cache_kb never fails for
 * cache_entries the plan accepts. */
_Static_assert(sizeof(entry_t) + CHUNK + sizeof(uint32_t) <= MP_CACHE_ENTRY, "MP_CACHE_ENTRY too small");
_Static_assert(sizeof(struct cache) + 16 + CHUNK + sizeof(uint32_t) <= MP_CACHE_FIXED, "MP_CACHE_FIXED too small");

static uint32_t key_hash(const uint8_t *q, int qlen, uint16_t t, uint16_t c, bool cd)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < qlen; i++) {
        uint8_t ch = q[i];
        if (ch >= 'A' && ch <= 'Z')
            ch += 32;
        h = (h ^ ch) * 16777619u;
    }
    h = (h ^ (t & 0xFF)) * 16777619u;
    h = (h ^ (t >> 8)) * 16777619u;
    h = (h ^ (c & 0xFF)) * 16777619u;
    return (h ^ (cd ? 1u : 0u)) * 16777619u;
}

static size_t align8(size_t n) { return (n + 7) & ~(size_t)7; }

cache_t *cache_new_in(void *mem, size_t bytes, size_t max_entries)
{
    size_t fixed = align8(sizeof(cache_t)) + align8(max_entries * sizeof(entry_t));
    if (!mem || !max_entries || max_entries >= NIL || bytes < fixed + CHUNK + sizeof(uint32_t))
        return NULL;
    size_t nchunks = (bytes - fixed) / (CHUNK + sizeof(uint32_t));
    if (nchunks >= NIL)
        nchunks = NIL - 1;
    cache_t *c = mem;
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->lock, NULL);
    c->e = (entry_t *)((uint8_t *)mem + align8(sizeof(cache_t)));
    c->cnext = (uint32_t *)((uint8_t *)mem + fixed);
    c->chunk = (uint8_t *)(c->cnext + nchunks);
    c->nentries = (uint32_t)max_entries;
    c->nchunks = (uint32_t)nchunks;
    for (int i = 0; i < NBUCKETS; i++)
        c->buckets[i] = NIL;
    c->head = c->tail = NIL;
    for (uint32_t i = 0; i < c->nentries; i++)
        c->e[i].hnext = i + 1 < c->nentries ? i + 1 : NIL;
    for (uint32_t i = 0; i < c->nchunks; i++)
        c->cnext[i] = i + 1 < c->nchunks ? i + 1 : NIL;
    c->free_e = 0;
    c->free_c = 0;
    c->nfree_c = c->nchunks;
    return c;
}

cache_t *cache_new(size_t max_entries, size_t max_bytes)
{
    void *mem = malloc(max_bytes);
    cache_t *c = cache_new_in(mem, max_bytes, max_entries);
    if (!c)
        free(mem);
    else
        c->owned = true;
    return c;
}

void cache_free(cache_t *c)
{
    if (c && c->owned) {
        pthread_mutex_destroy(&c->lock);
        free(c);
    }
}

static void lru_unlink(cache_t *c, uint32_t i)
{
    entry_t *e = &c->e[i];
    if (e->prev != NIL)
        c->e[e->prev].next = e->next;
    else
        c->head = e->next;
    if (e->next != NIL)
        c->e[e->next].prev = e->prev;
    else
        c->tail = e->prev;
    e->prev = e->next = NIL;
}

static void lru_push(cache_t *c, uint32_t i)
{
    entry_t *e = &c->e[i];
    e->prev = NIL;
    e->next = c->head;
    if (c->head != NIL)
        c->e[c->head].prev = i;
    c->head = i;
    if (c->tail == NIL)
        c->tail = i;
}

static void remove_entry(cache_t *c, uint32_t i)
{
    entry_t *e = &c->e[i];
    uint32_t *pp = &c->buckets[e->hash % NBUCKETS];
    while (*pp != NIL && *pp != i)
        pp = &c->e[*pp].hnext;
    if (*pp != NIL)
        *pp = e->hnext;
    lru_unlink(c, i);
    /* Its chunks back on the free list. */
    uint32_t n = 0, last = NIL;
    for (uint32_t k = e->first; k != NIL; k = c->cnext[k]) {
        last = k;
        n++;
    }
    if (last != NIL) {
        c->cnext[last] = c->free_c;
        c->free_c = e->first;
        c->nfree_c += n;
    }
    e->first = NIL;
    e->hnext = c->free_e;
    c->free_e = i;
    c->st.entries--;
    c->st.bytes -= n * CHUNK;
}

/* Copies n bytes from offset off of the chain starting at chunk k. */
static void chain_read(const cache_t *c, uint32_t k, size_t off, uint8_t *dst, size_t n)
{
    for (; off >= CHUNK; off -= CHUNK)
        k = c->cnext[k];
    while (n) {
        size_t take = CHUNK - off < n ? CHUNK - off : n;
        memcpy(dst, c->chunk + (size_t)k * CHUNK + off, take);
        dst += take;
        n -= take;
        off = 0;
        k = c->cnext[k];
    }
}

static uint32_t lookup(cache_t *c, uint32_t h, const uint8_t *q, int qlen, uint16_t t, uint16_t cl, bool cd)
{
    for (uint32_t i = c->buckets[h % NBUCKETS]; i != NIL; i = c->e[i].hnext) {
        const entry_t *e = &c->e[i];
        if (e->hash != h || e->qtype != t || e->qclass != cl || e->cd != cd || e->qlen != qlen)
            continue;
        uint8_t name[DNS_MAX_NAME];
        chain_read(c, e->first, 0, name, e->qlen);
        if (dns_name_eq(name, e->qlen, q, qlen))
            return i;
    }
    return NIL;
}

/* The live entry for the key, or NIL (an expired one is dropped). Under the lock. */
static uint32_t find_live(cache_t *c, const uint8_t *q, int qlen, uint16_t t, uint16_t cl, bool cd, uint32_t now_s)
{
    uint32_t i = lookup(c, key_hash(q, qlen, t, cl, cd), q, qlen, t, cl, cd);
    if (i != NIL && now_s >= c->e[i].expires_s) {
        remove_entry(c, i);
        i = NIL;
    }
    return i;
}

bool cache_get(cache_t *c, const uint8_t *qname, int qlen, uint16_t qtype, uint16_t qclass,
               bool cd, uint32_t now_s, uint8_t *out, size_t cap, size_t *len, uint32_t *age_s)
{
    if (qlen <= 0 || qlen > DNS_MAX_NAME)
        return false;
    bool hit = false;

    pthread_mutex_lock(&c->lock);
    uint32_t i = find_live(c, qname, qlen, qtype, qclass, cd, now_s);
    if (i == NIL && cd) /* an answer asked for without CD serves one with it (cache.h) */
        i = find_live(c, qname, qlen, qtype, qclass, false, now_s);
    if (i != NIL && c->e[i].len <= cap) {
        entry_t *e = &c->e[i];
        chain_read(c, e->first, e->qlen, out, e->len);
        *len = e->len;
        *age_s = now_s - e->stored_s;
        lru_unlink(c, i);
        lru_push(c, i);
        hit = true;
    }
    if (hit)
        c->st.hits++;
    else
        c->st.misses++;
    pthread_mutex_unlock(&c->lock);
    return hit;
}

/* Writes n bytes at offset off of the chain starting at chunk k. */
static void chain_write(cache_t *c, uint32_t k, size_t off, const uint8_t *src, size_t n)
{
    for (; off >= CHUNK; off -= CHUNK)
        k = c->cnext[k];
    while (n) {
        size_t take = CHUNK - off < n ? CHUNK - off : n;
        memcpy(c->chunk + (size_t)k * CHUNK + off, src, take);
        src += take;
        n -= take;
        off = 0;
        k = c->cnext[k];
    }
}

uint32_t cache_gen(cache_t *c) { return __atomic_load_n(&c->gen, __ATOMIC_ACQUIRE); }

void cache_put(cache_t *c, const uint8_t *qname, int qlen, uint16_t qtype, uint16_t qclass,
               bool cd, uint32_t now_s, const uint8_t *msg, size_t len)
{
    cache_put_gen(c, cache_gen(c), qname, qlen, qtype, qclass, cd, now_s, msg, len);
}

bool cache_put_gen(cache_t *c, uint32_t gen, const uint8_t *qname, int qlen, uint16_t qtype, uint16_t qclass,
                   bool cd, uint32_t now_s, const uint8_t *msg, size_t len)
{
    uint32_t ttl = dns_resp_ttl(msg, len);
    if (ttl == 0 || len > 0xFFFF || qlen <= 0 || qlen > DNS_MAX_NAME)
        return false;
    size_t need = ((size_t)qlen + len + CHUNK - 1) / CHUNK;
    if (need > c->nchunks)
        return false; /* bigger than the whole cache */
    uint8_t lower[DNS_MAX_NAME];
    memcpy(lower, qname, (size_t)qlen);
    dns_name_lower(lower, qlen);
    uint32_t h = key_hash(qname, qlen, qtype, qclass, cd);

    pthread_mutex_lock(&c->lock);
    /* Under the lock: a flush either came before (and this isn't kept) or comes after (and
     * drops it). */
    if (c->gen != gen) {
        pthread_mutex_unlock(&c->lock);
        return false;
    }
    uint32_t old = lookup(c, h, qname, qlen, qtype, qclass, cd);
    if (old != NIL)
        remove_entry(c, old);
    while (c->tail != NIL && (c->free_e == NIL || c->nfree_c < need)) {
        remove_entry(c, c->tail);
        c->st.evictions++;
    }
    uint32_t i = c->free_e;
    entry_t *e = &c->e[i];
    c->free_e = e->hnext;
    /* need chunks off the free list, in order. */
    e->first = c->free_c;
    uint32_t k = c->free_c;
    for (size_t j = 1; j < need; j++)
        k = c->cnext[k];
    c->free_c = c->cnext[k];
    c->cnext[k] = NIL;
    c->nfree_c -= (uint32_t)need;

    e->hash = h;
    e->stored_s = now_s;
    e->expires_s = now_s + ttl;
    e->qtype = qtype;
    e->qclass = qclass;
    e->cd = cd;
    e->qlen = (uint8_t)qlen;
    e->len = (uint16_t)len;
    chain_write(c, e->first, 0, lower, (size_t)qlen);
    chain_write(c, e->first, (size_t)qlen, msg, len);
    e->hnext = c->buckets[h % NBUCKETS];
    c->buckets[h % NBUCKETS] = i;
    lru_push(c, i);
    c->st.entries++;
    c->st.bytes += (uint32_t)(need * CHUNK);
    c->st.inserts++;
    pthread_mutex_unlock(&c->lock);
    return true;
}

void cache_flush(cache_t *c)
{
    pthread_mutex_lock(&c->lock);
    while (c->head != NIL)
        remove_entry(c, c->head);
    __atomic_store_n(&c->gen, c->gen + 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&c->lock);
}

void cache_get_stats(cache_t *c, cache_stats_t *s)
{
    pthread_mutex_lock(&c->lock);
    *s = c->st;
    pthread_mutex_unlock(&c->lock);
}
