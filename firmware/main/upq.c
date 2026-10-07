#include "upq.h"

#include <string.h>

/* The loop put a flight on the done queue (fwdq's on_done): a worker is asked to take it,
 * unless one is asked already. */
static void on_done(void *ctx)
{
    upq_t *u = ctx;
    if (__atomic_exchange_n(&u->wake_pending, true, __ATOMIC_ACQ_REL))
        return;
    if (!u->wake || !u->wake(u->ctx))
        __atomic_store_n(&u->wake_pending, false, __ATOMIC_RELEASE);
}

bool upq_init(upq_t *u, void *slots_mem, int nslots, uint32_t max_waiting, uint8_t *tcp_buf, size_t tcp_cap,
              cache_t *cache, bool (*cacheable)(const uint8_t *ans, size_t len), bool (*wake)(void *ctx), void *ctx)
{
    memset(u, 0, sizeof(*u));
    u->cache = cache;
    u->cacheable = cacheable;
    u->wake = wake;
    u->ctx = ctx;
    health_upstream_init(&u->health);
    flights_init(&u->fl, slots_mem, nslots, max_waiting);
    return fwdq_init(&u->q, &u->fl, tcp_buf, tcp_cap, on_done, u);
}

flight_role_t upq_ask(upq_t *u, const flight_query_t *q, flight_waiter_t *w, uint32_t now_ms,
                      uint32_t *deadline_ms)
{
    int slot;
    flight_role_t r = flight_begin(&u->fl, q, w, now_ms, flight_wait_ms(q->nservers, q->timeout_ms), &slot, deadline_ms);
    if (r == FLIGHT_OPENED) {
        fwdq_submit(&u->q, slot);
    } else if (r == FLIGHT_FULL) {
        __atomic_fetch_add(&u->shed[upq_kind(q->group)], 1, __ATOMIC_RELAXED);
        if (q->group == FLIGHT_GROUP_DEFAULT)
            health_upstream_shed(&u->health, now_ms);
    }
    return r;
}

void upq_woken(upq_t *u) { __atomic_store_n(&u->wake_pending, false, __ATOMIC_RELEASE); }

bool upq_take(upq_t *u, upq_done_t *d, uint32_t now_ms, uint32_t now_s)
{
    const uint8_t *ans;
    int slot, len;
    if (!fwdq_take(&u->q, &slot, &ans, &len))
        return false;
    flight_t *f = flight_slot(&u->fl, slot);
    /* Only the default forwarders count: one conditional forwarder down is that zone's
     * problem. Any answer is the forwarders answering, SERVFAIL too; it was slow if the first
     * try's timeout passed before it came (from the config: upstream_timeout_ms). A signed
     * difference: the worker may have read now_ms just before the flight opened. */
    if (f->group == FLIGHT_GROUP_DEFAULT)
        health_upstream_note(&u->health, len > 0, (int32_t)(now_ms - f->opened_ms) > f->up.timeout_ms, now_ms);
    if (len <= 0)
        __atomic_fetch_add(&u->expired[upq_kind(f->group)], 1, __ATOMIC_RELAXED);
    if (len > 0 && u->cache && (!f->cnames || !u->cacheable || u->cacheable(ans, (size_t)len)))
        cache_put_gen(u->cache, f->gen, f->name, f->qlen, f->qtype, f->qclass, f->cd, now_s, ans, (size_t)len);
    *d = (upq_done_t){ .slot = slot, .f = f, .answer = ans, .len = len };
    d->parked = flight_end(&u->fl, slot, ans, len);
    return true;
}

void upq_release(upq_t *u, upq_done_t *d)
{
    /* Ended by upq_take: no one is left on it. */
    fwdq_release(&u->q, d->slot);
    d->slot = -1;
    d->parked = NULL;
}

void upq_stats(upq_t *u, upq_stats_t *s)
{
    flight_counts(&u->fl, &s->table);
    for (int k = 0; k < UPQ_KINDS; k++) {
        s->shed[k] = __atomic_load_n(&u->shed[k], __ATOMIC_RELAXED);
        s->expired[k] = __atomic_load_n(&u->expired[k], __ATOMIC_RELAXED);
    }
    s->tcp_retries = __atomic_load_n(&u->q.tcp_retries, __ATOMIC_RELAXED);
    s->select_errors = __atomic_load_n(&u->q.select_errors, __ATOMIC_RELAXED);
}
