#include "fwdq.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <unistd.h>

#include "dns_wire.h"

_Static_assert(MP_UDP_OUT <= FWDQ_RX, "the loop's receive buffer holds any answer a slot does");

/* ---- the loop's active set: its thread only ---- */

static bool is_active(const fwdq_t *q, int slot) { return q->active[slot / 32] >> (slot % 32) & 1; }

static void set_active(fwdq_t *q, int slot, bool on)
{
    if (on)
        q->active[slot / 32] |= 1u << (slot % 32);
    else
        q->active[slot / 32] &= ~(1u << (slot % 32));
}

/* ---- the queues: slots linked through fq_next, under q->lock ---- */

static void push(flights_t *fl, fwdq_list_t *l, int slot)
{
    flight_slot(fl, slot)->fq_next = -1;
    if (l->tail >= 0)
        flight_slot(fl, l->tail)->fq_next = (int16_t)slot;
    else
        l->head = (int16_t)slot;
    l->tail = (int16_t)slot;
}

static int pop(flights_t *fl, fwdq_list_t *l)
{
    int slot = l->head;
    if (slot >= 0) {
        l->head = flight_slot(fl, slot)->fq_next;
        if (l->head < 0)
            l->tail = -1;
    }
    return slot;
}

/* Wakes the loop (under q->lock): one byte to its wake socket, unless one is on its way. */
static void wake_locked(fwdq_t *q)
{
    if (q->woken)
        return;
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = q->wake_port, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    uint8_t b = 1;
    if (sendto(q->wake_tx, &b, 1, 0, (struct sockaddr *)&sa, sizeof(sa)) == 1)
        q->woken = true;
}

bool fwdq_init(fwdq_t *q, flights_t *fl, uint8_t *tcp_buf, size_t tcp_cap, void (*on_done)(void *ctx), void *ctx)
{
    memset(q, 0, sizeof(*q));
    q->wake_rx = q->wake_tx = -1;
    if (fl->n > FWDQ_MAX_SLOTS)
        return false;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->tcp_cond, NULL);
    q->fl = fl;
    q->in = q->tcp = q->done = (fwdq_list_t){ -1, -1 };
    q->tcp_buf = tcp_buf;
    q->tcp_cap = tcp_buf ? tcp_cap : 0;
    q->tcp_slot = -1;
    q->on_done = on_done;
    q->ctx = ctx;
    q->wake_rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    q->wake_tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t sl = sizeof(sa);
    if (q->wake_rx < 0 || q->wake_tx < 0 || bind(q->wake_rx, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        getsockname(q->wake_rx, (struct sockaddr *)&sa, &sl) < 0) {
        fwdq_destroy(q);
        return false;
    }
    q->wake_port = sa.sin_port;
    fcntl(q->wake_rx, F_SETFL, fcntl(q->wake_rx, F_GETFL, 0) | O_NONBLOCK);
    return true;
}

void fwdq_set_alive(fwdq_t *q, void (*alive)(void)) { q->alive = alive; }

static fwd_q_t question(const flight_t *f)
{
    return (fwd_q_t){ .qname = f->name, .qlen = f->qlen, .qtype = f->qtype, .qclass = f->qclass, .cd = f->cd };
}

/* A slot's query is over (its answer in the slot or the TCP buffer, or alen 0 and not the
 * TCP buffer's: failed): its socket closed, on the done queue. Not in the loop's active set. */
static void finish(fwdq_t *q, int slot)
{
    flight_t *f = flight_slot(q->fl, slot);
    fwd_up_close(&f->up);
    pthread_mutex_lock(&q->lock);
    push(q->fl, &q->done, slot);
    pthread_mutex_unlock(&q->lock);
    if (q->on_done)
        q->on_done(q->ctx);
}

static void finish_failed(fwdq_t *q, int slot)
{
    flight_slot(q->fl, slot)->alen = 0;
    finish(q, slot);
}

/* To the TCP task: the try's answer was truncated, or too big for the slot. */
static void to_tcp(fwdq_t *q, int slot)
{
    set_active(q, slot, false);
    pthread_mutex_lock(&q->lock);
    push(q->fl, &q->tcp, slot);
    pthread_cond_signal(&q->tcp_cond);
    pthread_mutex_unlock(&q->lock);
}

/* The step's outcome for a slot of the loop's: still waiting (in the active set), or over
 * (out of it). */
static void after(fwdq_t *q, int slot, fwd_step_t st)
{
    flight_t *f = flight_slot(q->fl, slot);
    bool wait = st == FWD_WAIT && f->up.sock >= 0; /* fwd_up_start: below FD_SETSIZE */
    set_active(q, slot, wait);
    if (!wait && st != FWD_ANSWER)
        finish_failed(q, slot);
    /* FWD_ANSWER: the caller finishes it */
}

/* An answer to slot's try under way, len bytes in rx. */
static void got(fwdq_t *q, int slot, const uint8_t *rx, int len, uint32_t now)
{
    flight_t *f = flight_slot(q->fl, slot);
    if ((rd16(rx + 2) & DNS_F_TC) || len > (int)sizeof(f->answer)) {
        to_tcp(q, slot);
        return;
    }
    fwd_q_t fq = question(f);
    fwd_step_t st = fwd_up_answer(&f->up, &fq, rx, len, now);
    after(q, slot, st);
    if (st == FWD_ANSWER) {
        memcpy(f->answer, rx, (size_t)len);
        f->alen = (uint16_t)len;
        finish(q, slot);
    }
}

/* The slots waiting for the TCP task whose budget is spent are over, without an answer: the
 * TCP task may be busy with another's retry (blocking, up to FWD_TCP_TIMEOUT_MUL times its
 * timeout) or its buffer held, and a query must end by its budget all the same. They were
 * never asked over TCP, so the observer isn't told their server failed. Returns wait, cut
 * to when the next of them is due. */
static int32_t expire_tcp(fwdq_t *q, uint32_t now, int32_t wait)
{
    fwdq_list_t keep = { -1, -1 }, over = { -1, -1 };
    pthread_mutex_lock(&q->lock);
    for (int slot; (slot = pop(q->fl, &q->tcp)) >= 0;) {
        int32_t left = (int32_t)(flight_slot(q->fl, slot)->up.end_ms - now);
        push(q->fl, left > 0 ? &keep : &over, slot);
        if (left > 0 && left < wait)
            wait = left;
    }
    q->tcp = keep;
    pthread_mutex_unlock(&q->lock);
    /* Out of the TCP queue: the loop's alone. */
    for (int slot = over.head, next; slot >= 0; slot = next) {
        next = flight_slot(q->fl, slot)->fq_next;
        finish_failed(q, slot);
    }
    return wait;
}

void fwdq_run(fwdq_t *q)
{
    uint8_t rx[FWDQ_RX];
    flights_t *fl = q->fl;
    uint32_t backoff = 0; /* ms: select() failing in a row */
    for (;;) {
        if (q->alive)
            q->alive();
        /* The slots handed over since the last look. */
        pthread_mutex_lock(&q->lock);
        bool stop = q->stop;
        fwdq_list_t in = q->in;
        q->in = (fwdq_list_t){ -1, -1 };
        q->woken = false;
        pthread_mutex_unlock(&q->lock);
        if (stop)
            return;
        for (int slot = in.head, next; slot >= 0; slot = next) {
            flight_t *f = flight_slot(fl, slot);
            next = f->fq_next;
            if (f->fq_fresh) {
                fwd_q_t fq = question(f);
                f->fq_fresh = false;
                after(q, slot, fwd_up_start(&f->up, &fq, fwd_now_ms()));
            } else {
                after(q, slot, FWD_WAIT); /* back from a TCP retry, its next try sent */
            }
        }
        /* The tries whose timeout has come; the wait until the next one's. */
        uint32_t now = fwd_now_ms();
        int32_t wait = expire_tcp(q, now, FWDQ_CHECKIN_MS);
        fd_set r;
        FD_ZERO(&r);
        FD_SET(q->wake_rx, &r);
        int maxfd = q->wake_rx;
        for (int i = 0; i < fl->n; i++) {
            if (!is_active(q, i))
                continue;
            flight_t *f = flight_slot(fl, i);
            fwd_q_t fq = question(f);
            after(q, i, fwd_up_timeout(&f->up, &fq, now));
            if (!is_active(q, i))
                continue;
            int32_t left = (int32_t)(fwd_up_due(&f->up) - now);
            if (left < wait)
                wait = left < 0 ? 0 : left;
            FD_SET(f->up.sock, &r);
            if (f->up.sock > maxfd)
                maxfd = f->up.sock;
        }
        /* A try's timeout is rounded up to the tick, never cut short. */
        struct timeval tv = { .tv_sec = wait / 1000, .tv_usec = (wait % 1000) * 1000 };
        int ready = select(maxfd + 1, &r, NULL, NULL, &tv);
        if (ready < 0 && errno != EINTR) {
            /* It fails at once, and would again: waited out, longer each time in a row, so
             * the loop never spins. The tries due are still looked at between, so each query
             * still ends by its budget, and with it a socket select() refused. */
            backoff = backoff ? (backoff * 2 < FWDQ_BACKOFF_MAX_MS ? backoff * 2 : FWDQ_BACKOFF_MAX_MS)
                              : FWDQ_BACKOFF_MIN_MS;
            __atomic_fetch_add(&q->select_errors, 1, __ATOMIC_RELAXED);
            usleep(backoff * 1000);
            continue;
        }
        backoff = 0;
        if (ready <= 0)
            continue; /* a timeout: the tries due are looked at above */
        if (FD_ISSET(q->wake_rx, &r))
            while (recv(q->wake_rx, rx, sizeof(rx), 0) > 0)
                ;
        now = fwd_now_ms();
        for (int i = 0; i < fl->n; i++) {
            flight_t *f = flight_slot(fl, i);
            if (!is_active(q, i) || !FD_ISSET(f->up.sock, &r))
                continue;
            fwd_q_t fq = question(f);
            int len = fwd_up_recv(&f->up, &fq, rx, sizeof(rx));
            if (len > 0)
                got(q, i, rx, len, now);
        }
    }
}

/* Waits (under q->lock) for a slot to retry over TCP and the buffer to put its answer in.
 * -1: stopped. The slots waiting whose budget is spent meanwhile are the loop's to end
 * (expire_tcp). */
static int tcp_next_locked(fwdq_t *q)
{
    while (!q->stop && (q->tcp.head < 0 || q->tcp_slot >= 0))
        pthread_cond_wait(&q->tcp_cond, &q->lock);
    if (q->stop)
        return -1;
    int slot = pop(q->fl, &q->tcp);
    q->tcp_slot = slot; /* the buffer is this slot's while it asks */
    return slot;
}

void fwdq_tcp_run(fwdq_t *q)
{
    for (;;) {
        pthread_mutex_lock(&q->lock);
        int slot = tcp_next_locked(q);
        pthread_mutex_unlock(&q->lock);
        if (slot < 0)
            return;
        flight_t *f = flight_slot(q->fl, slot);
        fwd_q_t fq = question(f);
        uint32_t now = fwd_now_ms();
        /* Its budget spent before its turn (the loop hadn't looked yet): over, unasked. */
        bool spent = (int32_t)(now - f->up.end_ms) >= 0;
        int len = -1;
        if (q->tcp_buf && !spent) {
            __atomic_fetch_add(&q->tcp_retries, 1, __ATOMIC_RELAXED);
            len = fwd_up_tcp(&f->up, &fq, q->tcp_buf, q->tcp_cap, now);
        }
        fwd_step_t st = spent ? FWD_FAILED : fwd_up_answer(&f->up, &fq, q->tcp_buf, len, fwd_now_ms());
        bool keep = st == FWD_ANSWER && len > (int)sizeof(f->answer);
        if (st == FWD_ANSWER && !keep) {
            memcpy(f->answer, q->tcp_buf, (size_t)len);
            f->alen = (uint16_t)len;
        } else {
            f->alen = 0;
        }
        pthread_mutex_lock(&q->lock);
        if (keep) {
            q->tcp_len = len; /* held until the slot is given back */
        } else {
            q->tcp_slot = -1;
        }
        if (st == FWD_WAIT) {
            /* The next try is sent: back to the loop. */
            f->fq_fresh = false;
            push(q->fl, &q->in, slot);
            wake_locked(q);
        }
        pthread_mutex_unlock(&q->lock);
        if (st != FWD_WAIT)
            finish(q, slot);
    }
}

void fwdq_submit(fwdq_t *q, int slot)
{
    flight_t *f = flight_slot(q->fl, slot);
    if (!f)
        return;
    pthread_mutex_lock(&q->lock);
    f->fq_fresh = true;
    f->alen = 0;
    push(q->fl, &q->in, slot);
    wake_locked(q);
    pthread_mutex_unlock(&q->lock);
}

bool fwdq_take(fwdq_t *q, int *slot, const uint8_t **answer, int *len)
{
    pthread_mutex_lock(&q->lock);
    int s = pop(q->fl, &q->done);
    if (s >= 0) {
        flight_t *f = flight_slot(q->fl, s);
        *slot = s;
        if (q->tcp_slot == s && q->tcp_len > 0) {
            *answer = q->tcp_buf;
            *len = q->tcp_len;
        } else {
            *answer = f->answer;
            *len = f->alen ? f->alen : -1;
        }
    }
    pthread_mutex_unlock(&q->lock);
    return s >= 0;
}

flight_waiter_t *fwdq_release(fwdq_t *q, int slot)
{
    pthread_mutex_lock(&q->lock);
    if (q->tcp_slot == slot && slot >= 0) {
        q->tcp_slot = -1;
        q->tcp_len = 0;
        pthread_cond_signal(&q->tcp_cond);
    }
    pthread_mutex_unlock(&q->lock);
    return flight_free(q->fl, slot);
}

void fwdq_stop(fwdq_t *q)
{
    pthread_mutex_lock(&q->lock);
    q->stop = true;
    q->woken = false;
    wake_locked(q);
    pthread_cond_broadcast(&q->tcp_cond);
    pthread_mutex_unlock(&q->lock);
}

void fwdq_destroy(fwdq_t *q)
{
    /* Every slot's: the loop's, and those left on a queue when it stopped (a slot not
     * handed over, or freed, has none). */
    for (int i = 0; q->fl && i < q->fl->n; i++)
        fwd_up_close(&flight_slot(q->fl, i)->up);
    if (q->wake_rx >= 0)
        close(q->wake_rx);
    if (q->wake_tx >= 0)
        close(q->wake_tx);
    q->wake_rx = q->wake_tx = -1;
}
