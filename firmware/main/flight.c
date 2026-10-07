#include "flight.h"

#include <string.h>

_Static_assert(sizeof(flight_t) <= MP_FWD_SLOT, "the plan's upstream query slot (memplan.h) is too small");
_Static_assert(FLIGHT_GROUPS <= 256, "a slot keeps its group in a byte");

/* now has reached deadline, across the wrap of a ms counter. */
static bool due(uint32_t now_ms, uint32_t deadline_ms) { return (int32_t)(now_ms - deadline_ms) >= 0; }

void flights_init(flights_t *fl, void *mem, int n, uint32_t max_waiting)
{
    memset(fl, 0, sizeof(*fl));
    pthread_mutex_init(&fl->lock, NULL);
    fl->f = mem;
    fl->n = mem ? n : 0;
    fl->max_waiting = max_waiting;
    if (fl->f)
        memset(fl->f, 0, flights_bytes(fl->n));
    for (int i = 0; i < fl->n; i++)
        fl->f[i].up.sock = -1;
}

static int find(flights_t *fl, const flight_query_t *q)
{
    for (int i = 0; i < fl->n; i++) {
        const flight_t *f = &fl->f[i];
        if (f->state == FLIGHT_OPEN && f->qtype == q->qtype && f->qclass == q->qclass && f->cd == q->cd &&
            dns_name_eq(f->name, f->qlen, q->qname, q->qlen))
            return i;
    }
    return -1;
}

static void set_waiting(flights_t *fl, uint32_t n) { __atomic_store_n(&fl->waiting, n, __ATOMIC_RELEASE); }

/* Whether w may wait on a flight of group (under the lock). A TCP waiter holds only its own
 * worker: no cap. A parked UDP query holds an item from the receive pool: at most
 * max_waiting in all, and half that per group and for the forward zones together. */
static bool park_ok(const flights_t *fl, const flight_waiter_t *w, int group)
{
    if (w->wake)
        return true;
    uint32_t hw = flight_half(fl->max_waiting);
    return fl->waiting < fl->max_waiting && fl->parked[group] < hw &&
           (group == FLIGHT_GROUP_DEFAULT || fl->zones_parked < hw);
}

/* w waits on slot i's flight, f, after those before it (under the lock; park_ok). */
static void park(flights_t *fl, flight_t *f, int i, flight_waiter_t *w)
{
    if (w->wake) {
        flight_tcp_t *t = (flight_tcp_t *)w;
        t->slot = i;
        t->len = -1;
        __atomic_store_n(&t->done, false, __ATOMIC_RELAXED);
    } else {
        fl->parked[f->group]++;
        if (f->group != FLIGHT_GROUP_DEFAULT)
            fl->zones_parked++;
        set_waiting(fl, fl->waiting + 1);
    }
    w->next = NULL;
    if (f->tail)
        f->tail->next = w;
    else
        f->head = w;
    f->tail = w;
}

flight_role_t flight_begin(flights_t *fl, const flight_query_t *q, flight_waiter_t *w, uint32_t now_ms,
                           uint32_t wait_ms, int *slot, uint32_t *deadline_ms)
{
    *slot = -1;
    *deadline_ms = now_ms + wait_ms;
    if (q->qlen <= 0 || q->qlen > DNS_MAX_NAME || q->group < 0 || q->group >= FLIGHT_GROUPS)
        return FLIGHT_FULL;
    bool zone = q->group != FLIGHT_GROUP_DEFAULT;
    flight_role_t role = FLIGHT_FULL;
    pthread_mutex_lock(&fl->lock);
    int i = find(fl, q);
    if (i >= 0) {
        flight_t *f = &fl->f[i];
        *deadline_ms = f->deadline_ms;
        /* Its group is the flight's (the same question routes the same way). */
        if (!w || !park_ok(fl, w, f->group))
            goto out;
        park(fl, &fl->f[i], i, w);
        role = FLIGHT_JOINED;
        goto out;
    }
    uint32_t hs = flight_group_cap(fl->n);
    if (fl->held[q->group] >= hs || (zone && fl->zones_held >= hs))
        goto out;
    /* The query opening it is parked on it too: no room for that, no flight. */
    if (w && !park_ok(fl, w, q->group))
        goto out;
    for (i = 0; i < fl->n && fl->f[i].state != FLIGHT_FREE; i++)
        ;
    if (i == fl->n)
        goto out;
    flight_t *f = &fl->f[i];
    memset(f, 0, offsetof(flight_t, answer));
    f->state = FLIGHT_OPEN;
    f->group = (uint8_t)q->group;
    memcpy(f->name, q->qname, (size_t)q->qlen);
    dns_name_lower(f->name, q->qlen);
    f->qlen = (uint8_t)q->qlen;
    f->qtype = q->qtype;
    f->qclass = q->qclass;
    f->cd = q->cd;
    f->cnames = q->cnames;
    f->gen = q->gen;
    f->opened_ms = now_ms;
    f->deadline_ms = now_ms + wait_ms;
    fwd_up_init(&f->up, q->servers, q->nservers, q->timeout_ms);
    f->fq_next = -1;
    fl->held[q->group]++;
    if (zone)
        fl->zones_held++;
    if (++fl->held_all > fl->peak)
        fl->peak = fl->held_all;
    if (!fl->busy && fl->held[FLIGHT_GROUP_DEFAULT] > flight_busy_level(fl->n)) {
        fl->busy = true;
        fl->busy_since_ms = now_ms;
    }
    if (w)
        park(fl, f, i, w);
    *slot = i;
    role = FLIGHT_OPENED;
out:
    pthread_mutex_unlock(&fl->lock);
    return role;
}

flight_t *flight_slot(flights_t *fl, int slot) { return slot >= 0 && slot < fl->n ? &fl->f[slot] : NULL; }

/* Ends an open flight, under the lock: each TCP waiter gets the answer (or -1) and is woken;
 * the parked UDP queries are returned, in the order they joined. */
static flight_waiter_t *end_locked(flights_t *fl, flight_t *f, const uint8_t *answer, int len)
{
    flight_waiter_t *out = NULL, **tail = &out;
    uint32_t n = 0;
    for (flight_waiter_t *w = f->head, *next; w; w = next) {
        next = w->next; /* a TCP waiter woken may be gone at once */
        if (w->wake) {
            flight_tcp_t *t = (flight_tcp_t *)w;
            if (len > 0 && answer && (size_t)len <= t->cap) {
                memcpy(t->buf, answer, (size_t)len);
                t->len = len;
            } else {
                t->len = -1;
            }
            __atomic_store_n(&t->done, true, __ATOMIC_RELEASE);
            w->wake(w);
        } else {
            w->next = NULL;
            *tail = w;
            tail = &w->next;
            n++;
        }
    }
    f->head = f->tail = NULL;
    f->state = FLIGHT_DONE;
    fl->parked[f->group] -= (uint16_t)n;
    if (f->group != FLIGHT_GROUP_DEFAULT)
        fl->zones_parked -= (uint16_t)n;
    set_waiting(fl, fl->waiting - n);
    return out;
}

flight_waiter_t *flight_end(flights_t *fl, int slot, const uint8_t *answer, int len)
{
    if (slot < 0 || slot >= fl->n)
        return NULL;
    flight_waiter_t *list = NULL;
    pthread_mutex_lock(&fl->lock);
    flight_t *f = &fl->f[slot];
    if (f->state == FLIGHT_OPEN)
        list = end_locked(fl, f, answer, len);
    pthread_mutex_unlock(&fl->lock);
    return list;
}

flight_waiter_t *flight_free(flights_t *fl, int slot)
{
    if (slot < 0 || slot >= fl->n)
        return NULL;
    flight_waiter_t *list = NULL;
    pthread_mutex_lock(&fl->lock);
    flight_t *f = &fl->f[slot];
    if (f->state == FLIGHT_OPEN)
        list = end_locked(fl, f, NULL, -1);
    if (f->state == FLIGHT_DONE) {
        f->state = FLIGHT_FREE;
        fl->held[f->group]--;
        if (f->group != FLIGHT_GROUP_DEFAULT)
            fl->zones_held--;
        fl->held_all--;
        if (fl->held[FLIGHT_GROUP_DEFAULT] <= flight_busy_level(fl->n))
            fl->busy = false;
    }
    pthread_mutex_unlock(&fl->lock);
    return list;
}

flight_waiter_t *flight_expire(flights_t *fl, uint32_t now_ms)
{
    flight_waiter_t *out = NULL, **tail = &out;
    pthread_mutex_lock(&fl->lock);
    for (int i = 0; i < fl->n; i++) {
        flight_t *f = &fl->f[i];
        if (f->state != FLIGHT_OPEN || !due(now_ms, f->deadline_ms))
            continue;
        *tail = end_locked(fl, f, NULL, -1);
        while (*tail)
            tail = &(*tail)->next;
    }
    pthread_mutex_unlock(&fl->lock);
    return out;
}

bool flight_cancel(flights_t *fl, flight_tcp_t *t)
{
    bool taken = false;
    pthread_mutex_lock(&fl->lock);
    if (!__atomic_load_n(&t->done, __ATOMIC_RELAXED) && t->slot >= 0 && t->slot < fl->n) {
        flight_t *f = &fl->f[t->slot];
        for (flight_waiter_t **pp = &f->head, *prev = NULL; *pp; prev = *pp, pp = &(*pp)->next) {
            if (*pp != &t->w)
                continue;
            *pp = t->w.next;
            if (f->tail == &t->w)
                f->tail = prev;
            t->w.next = NULL;
            t->len = -1;
            taken = true;
            break;
        }
    }
    pthread_mutex_unlock(&fl->lock);
    return taken;
}

bool flight_tcp_done(const flight_tcp_t *t) { return __atomic_load_n(&t->done, __ATOMIC_ACQUIRE); }

bool flight_next_deadline(flights_t *fl, uint32_t *deadline_ms)
{
    bool any = false;
    uint32_t best = 0;
    pthread_mutex_lock(&fl->lock);
    for (int i = 0; i < fl->n; i++) {
        const flight_t *f = &fl->f[i];
        if (f->state != FLIGHT_OPEN || !f->head)
            continue;
        if (!any || (int32_t)(f->deadline_ms - best) < 0)
            best = f->deadline_ms;
        any = true;
    }
    pthread_mutex_unlock(&fl->lock);
    if (any)
        *deadline_ms = best;
    return any;
}

uint32_t flight_waiting(flights_t *fl) { return __atomic_load_n(&fl->waiting, __ATOMIC_ACQUIRE); }

void flight_counts(flights_t *fl, flight_counts_t *c)
{
    pthread_mutex_lock(&fl->lock);
    memcpy(c->held, fl->held, sizeof(c->held));
    c->zones_held = fl->zones_held;
    c->held_all = fl->held_all;
    c->peak = fl->peak;
    c->slots = (uint16_t)fl->n;
    c->group_cap = (uint16_t)flight_group_cap(fl->n);
    c->busy = fl->busy;
    c->busy_since_ms = fl->busy_since_ms;
    pthread_mutex_unlock(&fl->lock);
}
