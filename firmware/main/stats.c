#include "stats.h"

const uint32_t ST_BUCKET_US[ST_NBUCKETS - 1] = { 100,   250,    500,    1000,   2500,   5000,    10000,
                                                 25000, 50000, 100000, 250000, 500000, 1000000, 2500000 };
const char *const ST_BUCKET_LE[ST_NBUCKETS] = { "0.0001", "0.00025", "0.0005", "0.001", "0.0025",
                                                "0.005",  "0.01",    "0.025",  "0.05",  "0.1",
                                                "0.25",   "0.5",     "1",      "2.5",   "+Inf" };

#define ADD(p, v) __atomic_fetch_add((p), (v), __ATOMIC_RELAXED)
#define LOAD(p)   __atomic_load_n((p), __ATOMIC_RELAXED)

void st_hist_add(st_hist_t *h, uint32_t us)
{
    int b = 0;
    while (b < ST_NBUCKETS - 1 && us > ST_BUCKET_US[b])
        b++;
    ADD(&h->count[b], 1);
    uint32_t old = ADD(&h->sum_lo, us);
    if ((uint32_t)(old + us) < old)
        ADD(&h->sum_hi, 1);
}

void st_hist_read(const st_hist_t *h, uint64_t cum[ST_NBUCKETS], uint64_t *sum_us)
{
    uint64_t c = 0;
    for (int b = 0; b < ST_NBUCKETS; b++)
        cum[b] = c += LOAD(&h->count[b]);
    uint32_t hi, lo;
    do {
        hi = LOAD(&h->sum_hi);
        lo = LOAD(&h->sum_lo);
    } while (hi != LOAD(&h->sum_hi));
    *sum_us = (uint64_t)hi << 32 | lo;
}

void st_query(st_t *s, ql_result_t r, int rcode, uint32_t us)
{
    if ((unsigned)r < QR_N)
        ADD(&s->result[r], 1);
    if (rcode >= 0 && rcode < 16)
        ADD(&s->rcode[rcode], 1);
    if (r != QR_DROPPED)
        st_hist_add(&s->latency, us);
}

void st_upstream(st_t *s, uint32_t addr, bool ok, bool timeout, uint32_t us)
{
    st_upstream_t *u = NULL;
    for (int i = 0; i < ST_UPSTREAMS && addr; i++) {
        uint32_t a = __atomic_load_n(&s->up[i].addr, __ATOMIC_ACQUIRE);
        if (a == 0) {
            /* A free slot: take it, unless another worker just took it (for this address
             * or another). */
            uint32_t want = 0;
            if (__atomic_compare_exchange_n(&s->up[i].addr, &want, addr, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                a = addr;
            else
                a = want;
        }
        if (a == addr) {
            u = &s->up[i];
            break;
        }
    }
    if (!u) {
        ADD(&s->other_queries, 1);
        if (!ok)
            ADD(&s->other_failures, 1);
        if (!ok && timeout)
            ADD(&s->other_timeouts, 1);
        return;
    }
    ADD(&u->queries, 1);
    if (ok) {
        st_hist_add(&u->latency, us);
    } else {
        ADD(&u->failures, 1);
        if (timeout)
            ADD(&u->timeouts, 1);
    }
}
