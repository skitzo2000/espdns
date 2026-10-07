/*
 * The forward loop: one task asks every outstanding upstream query (flight.h) at once, so no
 * DNS worker ever waits on a forwarder (issue #53).
 *
 * A query the cache can't answer opens a flight (flight_begin) and hands its slot here
 * (fwdq_submit); its worker goes straight back to its queue. The loop (fwdq_run, the dns_fwd
 * task) sends each try, takes each answer and times each try out, for every slot it has, in
 * one select(): the steps of forward.h. A loopback socket wakes it for a slot handed over.
 * When a slot's query is over (its answer, or every try and the budget spent), its socket is
 * closed and the slot goes on the done queue: on_done is called, and a worker takes it
 * (fwdq_take), ends the flight with its answer (flight_end, which wakes the TCP waiters with
 * a copy and returns the parked UDP ones to answer), and gives it back (fwdq_release, which
 * frees the slot).
 *
 * A truncated answer (or one too big for the slot's answer buffer, MP_UDP_OUT) is asked again
 * over TCP by the TCP task (fwdq_tcp_run, dns_fwdtcp), one at a time into one buffer of
 * MP_TCP_MSG, from the share: the answer stays in it until its slot is given back, and the
 * next truncated answer's retry waits for that. An answer that fits the slot is copied there
 * and the buffer is free at once. A TCP retry that fails goes on to the slot's next try, back
 * in the loop. A slot whose budget is spent while it waits its turn (another's retry under
 * way, or the buffer held) is ended by the loop, at its budget.
 *
 * Every query ends by its budget (fwd_budget_ms): a flight's deadline (flight_wait_ms) is
 * never reached while the loop runs. The caps per group are flight.c's: the loop asks what
 * the table holds.
 *
 * Ownership: a slot handed over belongs to the loop or the TCP task (each only touches the
 * slots it has, the handovers under fwdq's lock) until it is on the done queue, then to the
 * worker that takes it, until fwdq_release.
 *
 * Portable C (pthreads, BSD sockets): the tasks are started by the caller, on the host as
 * threads. Host tested.
 */
#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "flight.h"

/* The loop checks in (alive) at least this often, waiting or not. */
#define FWDQ_CHECKIN_MS 1000
/* A datagram's room: more than any answer that comes unfragmented. */
#define FWDQ_RX         1536
/* The most slots the loop drives: memory.fwd_pending's range (board_def.h). */
#define FWDQ_MAX_SLOTS  1024
/* select() failing (not a signal): the loop waits this long before it looks again, doubling
 * while it keeps failing, up to the most; back to none once it doesn't. */
#define FWDQ_BACKOFF_MIN_MS 10
#define FWDQ_BACKOFF_MAX_MS 500

typedef struct {
    int16_t head, tail; /* slots, linked by fq_next; -1: empty */
} fwdq_list_t;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t tcp_cond; /* the TCP task: a slot to retry, its buffer free, or stop */
    flights_t *fl;
    fwdq_list_t in;   /* slots for the loop: to start, or back from a TCP retry */
    fwdq_list_t tcp;  /* slots for the TCP task */
    fwdq_list_t done; /* slots whose query is over, for the workers */
    uint8_t *tcp_buf; /* the TCP retry's answer (tcp_cap, MP_TCP_MSG) */
    size_t tcp_cap;
    int tcp_slot;     /* the slot whose answer is in tcp_buf (-1: free) */
    int tcp_len;
    int wake_rx, wake_tx;   /* the loopback wake socket, and the one sending to it */
    uint16_t wake_port;     /* network order */
    bool woken;             /* a wake is on its way: no other needed */
    bool stop;
    void (*on_done)(void *ctx); /* a slot is on the done queue; NULL: nothing */
    void *ctx;
    void (*alive)(void);        /* the loop checks in (the supervisor's watch); NULL: nothing */
    uint32_t select_errors;     /* select() failed (FWDQ_BACKOFF_MIN_MS): the loop's own count */
    uint32_t tcp_retries;       /* truncated (or too big) answers asked again over TCP: the TCP
                                 * task's own count (one whose budget was spent first isn't asked) */
    /* The slots whose socket the loop waits on: its own, touched by its thread only. */
    uint32_t active[FWDQ_MAX_SLOTS / 32];
} fwdq_t;

/* fl: the table; tcp_buf (tcp_cap bytes, MP_TCP_MSG on the node): the TCP retry's answer.
 * on_done(ctx) after each slot put on the done queue, from the loop or the TCP task. False
 * if the wake socket couldn't be made, or the table has more than FWDQ_MAX_SLOTS. */
bool fwdq_init(fwdq_t *q, flights_t *fl, uint8_t *tcp_buf, size_t tcp_cap, void (*on_done)(void *ctx), void *ctx);

/* The loop checks in through alive, before each wait (at least every FWDQ_CHECKIN_MS). */
void fwdq_set_alive(fwdq_t *q, void (*alive)(void));

/* The loop (the dns_fwd task): returns once fwdq_stop is called. */
void fwdq_run(fwdq_t *q);

/* The TCP task (dns_fwdtcp): returns once fwdq_stop is called. */
void fwdq_tcp_run(fwdq_t *q);

/* Hands slot (FLIGHT_OPENED by flight_begin, its question and upstream query set) to the
 * loop, to ask now. */
void fwdq_submit(fwdq_t *q, int slot);

/* A slot whose query is over, if any: *answer and *len its answer (in the slot, or the TCP
 * buffer), or *len -1: none (every try failed or the budget is spent). The answer stays
 * until fwdq_release. */
bool fwdq_take(fwdq_t *q, int *slot, const uint8_t **answer, int *len);

/* Done with a slot taken: it is freed (flight_free; the waiters of a flight not ended are
 * returned, for SERVFAIL), and the TCP buffer with it if its answer was there. */
flight_waiter_t *fwdq_release(fwdq_t *q, int slot);

/* The tasks return; the caller joins them, then fwdq_destroy. */
void fwdq_stop(fwdq_t *q);

/* Closes the sockets (the wake socket's, and any slot's still open). */
void fwdq_destroy(fwdq_t *q);
