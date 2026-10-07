#include "block.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mbedtls/sha256.h"

#define CHUNK 4096

static bool read_at(int fd, void *buf, size_t n, size_t off)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = pread(fd, p, n, (off_t)off);
        if (r <= 0)
            return false;
        p += r;
        off += (size_t)r;
        n -= (size_t)r;
    }
    return true;
}

static bool write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r <= 0)
            return false;
        p += r;
        n -= (size_t)r;
    }
    return true;
}

/* ---- lookups in either tier ---- */

/* The RAM tier: the sectors are in memory, from the end of the front on. */
static const uint8_t *read_ram(void *ctx, uint32_t off)
{
    const blk_list_t *l = ctx;
    if (off < l->front_len || off + BL_SECTOR > l->file_len)
        return NULL;
    return l->mem + (off - l->front_len);
}

/* The SD tier: one sector from the card into the caller's buffer. Each lookup brings its
 * own, so the query tasks can read at once (pread keeps no shared file position). */
typedef struct {
    int fd;
    uint8_t buf[BL_SECTOR];
} sd_reader_t;

static const uint8_t *read_sd(void *ctx, uint32_t off)
{
    sd_reader_t *r = ctx;
    return read_at(r->fd, r->buf, BL_SECTOR, off) ? r->buf : NULL;
}

/* verdict: bl_verdict (the overrides), else bl_blocked (the main list). */
static bl_verdict_t check(const blk_list_t *l, const uint8_t *qname, bool verdict, bl_stats_t *st)
{
    if (l->tier == BLK_TIER_RAM)
        return verdict ? bl_verdict(&l->bl, qname, st) : bl_blocked(&l->bl, qname, st) ? BL_BLOCK : BL_NONE;
    sd_reader_t r = { .fd = l->fd };
    bl_t b = l->bl;
    b.read = read_sd;
    b.ctx = &r;
    return verdict ? bl_verdict(&b, qname, st) : bl_blocked(&b, qname, st) ? BL_BLOCK : BL_NONE;
}

blk_result_t blk_decide(const blk_list_t *ovr, bool paused, const blk_list_t *list, const uint8_t *qname,
                        bl_stats_t *st)
{
    return blk_decide_by(ovr, paused, list, qname, st, NULL);
}

blk_result_t blk_decide_by(const blk_list_t *ovr, bool paused, const blk_list_t *list, const uint8_t *qname,
                           bl_stats_t *st, bool *by_overrides)
{
    if (by_overrides)
        *by_overrides = false;
    if (ovr) {
        bl_verdict_t v = check(ovr, qname, true, st);
        if (by_overrides)
            *by_overrides = v == BL_BLOCK || v == BL_ALLOW;
        if (v == BL_BLOCK)
            return BLK_BLOCK;
        if (v == BL_ALLOW)
            return BLK_ALLOW;
    }
    if (paused || !list)
        return BLK_PASS;
    return check(list, qname, false, st) == BL_BLOCK ? BLK_BLOCK : BLK_PASS;
}

int blk_answer(dns_builder_t *b, const dns_query_t *q, bool nxdomain, uint32_t ttl)
{
    static const uint8_t zero[16];
    if (nxdomain)
        return DNS_R_NXDOMAIN;
    if (q->qtype == DNS_T_A)
        dnsb_rr(b, DNSB_ANSWER, q->qname, q->qname_len, DNS_T_A, DNS_C_IN, ttl, zero, 4);
    else if (q->qtype == DNS_T_AAAA)
        dnsb_rr(b, DNSB_ANSWER, q->qname, q->qname_len, DNS_T_AAAA, DNS_C_IN, ttl, zero, 16);
    return DNS_R_NOERROR;
}

bool blk_cname_any(const uint8_t *msg, size_t len, blk_name_fn check_fn, void *ctx)
{
    dns_hdr_t h;
    size_t pos = DNS_HDR_LEN;
    if (!dns_hdr_parse(msg, len, &h))
        return false;
    for (int i = 0; i < h.qd; i++) {
        if (dns_name_skip(msg, len, &pos) < 0 || pos + 4 > len)
            return false;
        pos += 4;
    }
    for (int i = 0; i < h.an; i++) {
        dns_rr_view_t rr;
        if (!dns_rr_parse(msg, len, &pos, &rr))
            return false;
        /* A DNAME's target is checked as a name too (its synthesized CNAME usually follows). */
        if (rr.type != DNS_T_CNAME && rr.type != DNS_T_DNAME)
            continue;
        uint8_t target[DNS_MAX_NAME];
        if (dns_rdata_expand(msg, len, &rr, target, sizeof(target)) > 0 && check_fn(ctx, target))
            return true;
    }
    return false;
}

/* ---- loading ---- */

static uint32_t le32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

const char *blk_plan(const uint8_t hdr[BL_HEADER], size_t file_len, blk_need_t *n)
{
    memset(n, 0, sizeof(*n));
    n->front = bl_front_len(hdr);
    if (n->front < 96 || (hdr[8] != 1 && hdr[8] != 2))
        return "not a blocklist";
    if (n->front > file_len)
        return "list cut short";
    int tables = hdr[8] == 1 ? 2 : BL_TABLES;
    for (int i = 0; i < tables; i++) {
        uint32_t sectors = le32(hdr + 32 + 32 * i + 4);
        if (sectors > file_len / BL_SECTOR)
            return "bad table size";
        n->index += 8 * (size_t)sectors;
    }
    n->entries = le32(hdr + 32) + le32(hdr + 64);
    n->sectors = file_len - n->front;
    return NULL;
}

static size_t room(size_t budget, size_t used) { return budget > used ? budget - used : 0; }

const char *blk_place(const blk_need_t *n, const blk_room_t *r, blk_place_t *out)
{
    memset(out, 0, sizeof(*out));
    /* Now: next to the list being replaced. After: once it is gone. */
    size_t idx_now = room(r->index_budget, r->index_used);
    size_t idx_after = room(r->index_budget, r->index_used - (r->index_held < r->index_used ? r->index_held : r->index_used));
    size_t now = room(r->budget, r->used), after = room(r->budget, r->used - (r->held < r->used ? r->held : r->used));
    bool int_now = n->index && n->index <= idx_now, int_after = n->index && n->index <= idx_after;
    /* Loading the RAM tier holds the front and the indexes, then the indexes and the sectors. */
    size_t big = n->front > n->sectors ? n->front : n->sectors;
    size_t ram_now = (int_now ? 0 : n->index) + big, ram_after = (int_after ? 0 : n->index) + big;
    size_t sd_now = (int_now ? 0 : n->index) + n->front, sd_after = (int_after ? 0 : n->index) + n->front;
    out->index_internal = int_now;
    if (r->overrides) {
        out->tier = BLK_TIER_RAM;
        out->now = true;
        return ram_now <= now ? NULL : "overrides too big for this board's blocking memory (memory.blocklist_kb)";
    }
    if (r->ram_tier && ram_after <= after) {
        out->tier = BLK_TIER_RAM;
        out->now = ram_now <= now;
    } else if (sd_after <= after) {
        out->tier = BLK_TIER_SD;
        out->now = sd_now <= now;
    } else {
        return "list too big for this board's blocking memory (memory.blocklist_kb)";
    }
    return NULL;
}

void blk_list_free(blk_list_t *l)
{
    if (!l)
        return;
    if (l->fd >= 0)
        close(l->fd);
    l->alloc->free(l->mem);
    l->alloc->free(l->index);
    free(l);
}

const char *blk_load(int fd, const rel_manifest_t *m, blk_tier_t tier, const blk_alloc_t *a, blk_list_t **out)
{
    *out = NULL;
    size_t len = (size_t)m->payload_len;
    uint8_t hdr[BL_HEADER];
    blk_need_t n;
    const char *why = len < BL_HEADER || !read_at(fd, hdr, BL_HEADER, 0) ? "not a blocklist" : blk_plan(hdr, len, &n);
    blk_list_t *l = why ? NULL : calloc(1, sizeof(*l));
    if (!why && !l)
        why = "no memory for the list";
    if (why) {
        close(fd);
        return why;
    }
    l->fd = -1;
    l->alloc = a;
    l->m = *m;
    l->slot = -1;
    l->tier = tier;
    l->front_len = n.front;
    l->file_len = len;
    l->entries = n.entries;

    uint8_t *front = a->big(n.front);
    if (!front)
        why = "no memory for the list";
    else if (!read_at(fd, front, n.front, 0))
        why = "list unreadable";
    else
        why = bl_open(&l->bl, front, n.front, len, read_ram, l, tier == BLK_TIER_RAM ? BL_NO_XOR : 0);
    if (!why && n.index) {
        l->index = a->index(n.index);
        l->index_bytes = n.index;
        if (l->index)
            bl_index_move(&l->bl, l->index);
        else
            why = "no memory for the index";
    }
    if (!why && tier == BLK_TIER_RAM) {
        /* Nothing points into the front now: free it before taking the sectors' memory. */
        a->free(front);
        front = NULL;
        l->mem_bytes = n.sectors;
        l->mem = a->big(n.sectors ? n.sectors : 8);
        if (!l->mem)
            why = "no memory for the list";
        else if (!read_at(fd, l->mem, n.sectors, n.front))
            why = "list unreadable";
    } else if (!why) {
        l->mem = front; /* the filters stay in it */
        l->mem_bytes = n.front;
        front = NULL;
        l->fd = fd;
        fd = -1;
    }
    a->free(front);
    if (fd >= 0)
        close(fd);
    if (why) {
        blk_list_free(l);
        return why;
    }
    *out = l;
    return NULL;
}

/* ---- slot files ---- */

const char *blk_slot_read(int fd, const rel_trust_t *t, uint8_t kind, rel_manifest_t *m)
{
    struct stat sb;
    uint8_t hdr[REL_HEADER_LEN];
    memset(m, 0, sizeof(*m));
    if (fstat(fd, &sb) != 0 || sb.st_size <= REL_HEADER_LEN)
        return "empty slot";
    size_t len = (size_t)sb.st_size - REL_HEADER_LEN;
    if (!read_at(fd, hdr, REL_HEADER_LEN, len))
        return "slot unreadable";
    if (hdr[8] != kind)
        return "not this kind of release";
    const char *why = rel_verify(hdr, t, 0, UINT64_MAX, m);
    if (why)
        return why;
    if (m->payload_len != len)
        return "slot file has the wrong length";
    return NULL;
}

const char *blk_slot_hash(int fd, const rel_manifest_t *m)
{
    uint8_t *buf = malloc(CHUNK), got[32];
    if (!buf)
        return "no memory";
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    const char *why = NULL;
    for (size_t off = 0; off < m->payload_len && !why;) {
        size_t n = m->payload_len - off < CHUNK ? (size_t)(m->payload_len - off) : CHUNK;
        if (!read_at(fd, buf, n, off))
            why = "slot unreadable";
        mbedtls_sha256_update(&sha, buf, n);
        off += n;
    }
    mbedtls_sha256_finish(&sha, got);
    mbedtls_sha256_free(&sha);
    free(buf);
    if (!why && memcmp(got, m->sha256, 32) != 0)
        why = "slot does not match its signed hash";
    return why;
}

const char *blk_slot_store(const char *path, const uint8_t hdr[REL_HEADER_LEN], const rel_manifest_t *m,
                           blk_recv_fn recv, void *ctx)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return "cannot write the slot file";
    uint8_t *buf = malloc(CHUNK), got[32];
    const char *why = buf ? NULL : "no memory";
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    for (size_t left = (size_t)m->payload_len; left && !why;) {
        size_t n = left < CHUNK ? left : CHUNK;
        if (!recv(ctx, buf, n))
            why = "receive failed";
        else if (mbedtls_sha256_update(&sha, buf, n), !write_all(fd, buf, n))
            why = "slot write failed";
        left -= n;
    }
    mbedtls_sha256_finish(&sha, got);
    mbedtls_sha256_free(&sha);
    free(buf);
    if (!why && memcmp(got, m->sha256, 32) != 0)
        why = "payload does not match the signed hash";
    /* The header last: a file without one is never loaded. */
    if (!why && (!write_all(fd, hdr, REL_HEADER_LEN) || fsync(fd) != 0))
        why = "slot write failed";
    if (close(fd) != 0 && !why)
        why = "slot write failed";
    if (why)
        unlink(path);
    return why;
}

int blk_slot_order(const bool ok[2], const uint64_t seq[2], uint64_t reverted, int order[2])
{
    int n = 0;
    bool use[2];
    for (int i = 0; i < 2; i++)
        use[i] = ok[i] && !(reverted && seq[i] == reverted);
    int first = use[1] && (!use[0] || seq[1] > seq[0]) ? 1 : 0;
    for (int j = 0; j < 2; j++) {
        int i = j ? 1 - first : first;
        if (use[i])
            order[n++] = i;
    }
    return n;
}

bool blk_slot_older(uint64_t loaded, uint64_t recorded, uint64_t reverted)
{
    return loaded < recorded && !(reverted && reverted == recorded);
}

const char *blk_revert_check(const char *what, int other, const char *other_why, uint64_t other_seq,
                             uint64_t in_use, uint64_t reverted, const char *newer, char *buf, size_t cap)
{
    if (other_why) {
        snprintf(buf, cap, "no previous %s to revert to: slot %d %s", what, other,
                 !strcmp(other_why, "missing") ? "is empty" : other_why);
        return buf;
    }
    if (other_seq >= in_use) {
        snprintf(buf, cap, "no previous %s to revert to: slot %d holds seq %llu, not older than seq %llu in use (%s)",
                 what, other, (unsigned long long)other_seq, (unsigned long long)in_use,
                 reverted && reverted == other_seq ? "reverted from" : newer);
        return buf;
    }
    return NULL;
}

uint8_t blk_ctl_revert_kind(const uint8_t *p, size_t n)
{
    if (n != 2 || p[0] != BLK_CTL_REVERT)
        return 0;
    return p[1] == REL_BLOCKLIST || p[1] == REL_OVERRIDES || p[1] == REL_ZONES ? p[1] : 0;
}

/* ---- the active list ---- */

struct blk_ref {
    pthread_mutex_t mu;
    blk_list_t *cur;
};

blk_ref_t *blk_ref_new(void)
{
    blk_ref_t *r = calloc(1, sizeof(*r));
    if (r)
        pthread_mutex_init(&r->mu, NULL);
    return r;
}

blk_list_t *blk_get(blk_ref_t *r)
{
    pthread_mutex_lock(&r->mu);
    blk_list_t *l = r->cur;
    if (l)
        __atomic_fetch_add(&l->refs, 1, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&r->mu);
    return l;
}

void blk_put(blk_list_t *l)
{
    if (l && __atomic_sub_fetch(&l->refs, 1, __ATOMIC_ACQ_REL) == 0)
        blk_list_free(l);
}

void blk_swap(blk_ref_t *r, blk_list_t *l)
{
    if (l)
        l->refs = 1; /* the active pointer's own reference */
    pthread_mutex_lock(&r->mu);
    blk_list_t *old = r->cur;
    r->cur = l;
    pthread_mutex_unlock(&r->mu);
    blk_put(old);
}
