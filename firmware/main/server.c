#include "server.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "answer.h"
#include "blocking.h"
#include "boot.h"
#include "cache.h"
#include "config.h"
#include "dns_wire.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "flight.h"
#include "forward.h"
#include "fwdq.h"
#include "health.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "power.h"
#include "querylog.h"
#include "registry.h"
#include "settings.h"
#include "share.h"
#include "supervisor.h"
#include "upq.h"
#include "xfr.h"

static const char *TAG = "server";

/* Sizes and counts are the dns service's share of the memory plan (memplan.h). */
#define UDP_MAX_QUERY 1500
#define TCP_IDLE_MS   10000

static server_stats_t s_st;
static cache_t *s_cache;
static int s_udp = -1;
static volatile bool s_udp_ok, s_tcp_ok, s_listen_failed;

#define STAT(f) __atomic_fetch_add(&s_st.f, 1, __ATOMIC_RELAXED)
/* What the query log notes about the query this worker is handling (querylog.h). */
#define NOTE(f, v)                             \
    do {                                       \
        ql_note_t *note_ = querylog_note();    \
        if (note_)                             \
            note_->f = (v);                    \
    } while (0)

static uint32_t now_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

/* Mirrors Technitium's AllowOnlyForPrivateNetworks for recursion. */
static bool is_private(uint32_t src)
{
    uint32_t a = ntohl(src);
    return (a >> 24) == 10 || (a >> 20) == (172 << 4 | 1) || (a >> 16) == (192 << 8 | 168) ||
           (a >> 22) == (100 << 2 | 1) || (a >> 24) == 127 || (a >> 16) == (169 << 8 | 254);
}

/* ---- upstream queries (upq.h): no worker waits on a forwarder ---- */

static upq_t s_upq;
static bool s_upq_ok;        /* set up: its health counts may be read */
static int s_fwd_watch = -1; /* the forward loop's (sup.h, SUP_FORWARDER) */

/* A forwarded answer whose CNAMEs go through blocking is cached only if they all pass. */
static bool cacheable(const uint8_t *ans, size_t len) { return blocking_cnames(ans, len) == BLOCKING_CNAME_PASS; }

/* A TCP query waiting on a flight: woken by its task's notification. */
typedef struct {
    flight_tcp_t t; /* first */
    TaskHandle_t task;
} tcp_wait_t;

typedef struct udp_item udp_item_t;
struct udp_item {
    flight_waiter_t fw; /* first: the item is what a parked query is (flight.h) */
    struct sockaddr_in from;
    uint32_t t0_ms; /* parked: when its worker took it, for its time to answer */
    uint16_t len;
    uint8_t buf[UDP_MAX_QUERY];
};

/* A worker's buffers, from the dns service's share, taken at the start, and the flight whose
 * parked queries it answers. */
typedef struct {
    uint8_t *in, *out, *scratch; /* in: TCP only */
    dns_builder_t *b;
    int watch; /* supervisor.h */
    udp_item_t *item; /* the UDP query being handled (NULL: a TCP one): what is parked on a flight */
    bool parked;      /* ...it was: no answer now, and the item is the flight's */
    /* Answering the queries parked on a flight (take_flights): resolve takes the flight's
     * answer (or its failure) for its question instead of asking. A query that routes
     * elsewhere since asks for itself, and parks again. */
    struct {
        bool on;
        const uint8_t *answer; /* in the flight's slot, or the loop's TCP buffer, until upq_release */
        int len;               /* <= 0: none */
        const flight_t *f;     /* the question */
    } replay;
} worker_t;

/* The worker running on this task (NULL: none). */
static __thread worker_t *t_w;

#define RESOLVE_PARKED (-2)

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

static void tcp_wake(flight_waiter_t *w) { xTaskNotifyGive(((tcp_wait_t *)w)->task); }

/* A TCP query waits on its flight (on its own worker) until the flight ends or its deadline
 * comes. Returns the answer's length in tw's buffer, or -1. It always finishes with
 * flight_cancel, under the table's lock: seeing the flight done isn't enough, as the wake
 * (tcp_wake, reading tw) may still be under way, and tw is on this stack. */
static int tcp_wait(tcp_wait_t *tw, uint32_t deadline_ms)
{
    while (!flight_tcp_done(&tw->t)) {
        int32_t left = (int32_t)(deadline_ms - now_ms());
        if (left <= 0)
            break;
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(left) + 1);
    }
    if (flight_cancel(&s_upq.fl, &tw->t))
        return -1; /* given up: no answer, nor a wake, is coming */
    ulTaskNotifyTake(pdTRUE, 0); /* the flight ended and its wake is over: take it, if it wasn't */
    return tw->t.len;
}

/* Upstream answer for (name, type), from cache or the right forwarders: its length, the
 * answer at *ans (buf, or the flight's answer), -1 if there is none, or RESOLVE_PARKED: the
 * UDP query waits on its question's upstream query (flight.h, upq.h), off its worker, and is
 * answered when that is over (the caller answers nothing now). A TCP query waits for it on
 * its own worker. With cnames, a forwarded answer's CNAME targets go through the blocking
 * decision: *blocked if one is blocked (and the answer isn't cached: upq.h). gen: the cache's
 * generation from before the query was routed and checked against the lists: an answer is
 * kept only if no list or zones were swapped in since (their swap flushes the cache), so a
 * fill decided on the old ones never outlives them. The caller holds POWER_DNS (power.h), let
 * go while a TCP query waits. The DO bit isn't asked: every upstream query has it, and the
 * relay leaves the DNSSEC records out for a client without it (cache.h). */
static int resolve(const uint8_t *name, int len, uint16_t qtype, uint16_t qclass, bool cd, route_t r, uint8_t *buf,
                   size_t cap, const uint8_t **ans, uint32_t *age, bool cnames, bool *blocked, uint32_t gen)
{
    *blocked = false;
    *ans = buf;
    worker_t *w = t_w;
    int rl;
    size_t n;
    const flight_t *rf = w && w->replay.on ? w->replay.f : NULL;
    if (rf && rf->qtype == qtype && rf->qclass == qclass && rf->cd == cd && dns_name_eq(rf->name, rf->qlen, name, len)) {
        /* A parked query: the flight's answer (or its failure) is its answer. Cached and
         * counted for the forwarders once, as the flight was taken (upq_take). */
        *age = 0;
        rl = w->replay.len > 0 ? w->replay.len : -1;
        *ans = w->replay.answer;
        NOTE(asked, true);
        NOTE(answered, rl > 0);
        if (rl > 0 && cnames && blocking_cnames(*ans, (size_t)rl) == BLOCKING_CNAME_BLOCK)
            *blocked = true;
        return rl;
    }
    if (s_cache && cache_get(s_cache, name, len, qtype, qclass, cd, now_s(), buf, cap, &n, age)) {
        STAT(cache_hits);
        NOTE(cache, true);
        return (int)n;
    }
    *age = 0;
    uint32_t servers[CFG_MAX_FWD];
    int timeout_ms;
    int nservers = settings_forwarders(servers, &timeout_ms); /* the default forwarders can change live */
    if (r.kind == ROUTE_FWD_ZONE) {
        servers[0] = reg_fzone(r.idx)->forwarder;
        nservers = 1;
    } else if (!nservers) {
        return -1; /* forwarding turned off since the caller looked: not a forwarder failing */
    }
    if (!w)
        return -1; /* not on a DNS worker: none to wait */
    /* One upstream query per question (flight.h): this query opens its question's flight, or
     * joins the one open, and waits on it until the flight's deadline: its upstream query's
     * whole attempt, through every try (flight_wait_ms). A UDP query is parked off the
     * worker; a TCP one waits on its own worker. Past the table's or its group's caps,
     * SERVFAIL at once: the forwarder is slow. */
    flight_query_t fq = { .qname = name, .qlen = len, .qtype = qtype, .qclass = qclass, .cd = cd,
                          .group = r.kind == ROUTE_FWD_ZONE ? FLIGHT_GROUP_ZONE(r.idx) : FLIGHT_GROUP_DEFAULT,
                          .servers = servers, .nservers = nservers, .timeout_ms = timeout_ms, .gen = gen,
                          .cnames = cnames };
    uint32_t deadline;
    if (w->item) {
        if (upq_ask(&s_upq, &fq, &w->item->fw, now_ms(), &deadline) == FLIGHT_FULL)
            return -1;
        /* Parked: the item is the flight's now, and may be answered at any time. */
        w->parked = true;
        return RESOLVE_PARKED;
    }
    tcp_wait_t tw;
    memset(&tw, 0, sizeof(tw));
    tw.t.w.wake = tcp_wake;
    tw.t.buf = buf;
    tw.t.cap = cap;
    tw.task = xTaskGetCurrentTaskHandle();
    ulTaskNotifyTake(pdTRUE, 0); /* no wake left from before */
    if (upq_ask(&s_upq, &fq, &tw.t.w, now_ms(), &deadline) == FLIGHT_FULL)
        return -1;
    /* Waiting on a forwarder is idle time: the clock may drop meanwhile (power.h). */
    power_release(POWER_DNS);
    rl = tcp_wait(&tw, deadline);
    power_hold(POWER_DNS);
    NOTE(asked, true);
    NOTE(answered, rl > 0);
    if (rl > 0 && cnames && blocking_cnames(buf, (size_t)rl) == BLOCKING_CNAME_BLOCK)
        *blocked = true;
    return rl;
}

static size_t handle_notify(const dns_query_t *q, uint32_t src, uint8_t *out, size_t cap)
{
    STAT(notifies);
    NOTE(notify, true);
    if (src != settings()->primary || q->qtype != DNS_T_SOA)
        return dns_make_error(q, out, cap, DNS_R_REFUSED, 0);
    reg_rdlock();
    route_t r = reg_route(q->qname, q->qname_len);
    bool ours = (r.kind == ROUTE_AUTH || r.kind == ROUTE_AUTH_FAIL) && !r.hosted &&
                dns_name_eq(q->qname, q->qname_len, reg_slot(r.idx)->apex, reg_slot(r.idx)->apex_len);
    reg_unlock();
    if (!ours)
        return dns_make_error(q, out, cap, DNS_R_NOTAUTH, 0);
    xfr_notify(r.idx);
    return dns_make_error(q, out, cap, DNS_R_NOERROR, DNS_F_AA);
}

static size_t handle(const uint8_t *m, size_t mlen, uint32_t src, bool tcp, uint8_t *out, size_t cap,
                     uint8_t *scratch, size_t scratch_cap, dns_builder_t *b)
{
    dns_query_t q;
    /* A parked query answered now was counted when it came. */
    bool again = t_w && t_w->replay.on;
    if (!again)
        STAT(queries);

    int prc = dns_query_parse(m, mlen, &q);
    if (mlen < DNS_HDR_LEN || (q.flags & DNS_F_QR)) {
        STAT(dropped);
        return 0; /* garbage or a response: never answer */
    }
    if (prc != DNS_R_NOERROR) {
        STAT(formerr);
        q.qname_len = 0;
        return dns_make_error(&q, out, cap, DNS_R_FORMERR, 0);
    }
    ql_note_t *note = querylog_note();
    if (note) {
        note->parsed = true;
        ql_note_name(note, q.qname, q.qname_len);
        note->qtype = q.qtype;
    }
    /* Without secondary zones there is no NOTIFY handling: not implemented, below. */
    if (DNS_OPCODE(q.flags) == DNS_OP_NOTIFY && reg_nslots())
        return handle_notify(&q, src, out, cap);
    if (DNS_OPCODE(q.flags) != DNS_OP_QUERY) {
        return dns_make_error(&q, out, cap, DNS_R_NOTIMP, 0);
    }
    if (q.qclass != DNS_C_IN || q.qtype == DNS_T_AXFR || q.qtype == DNS_T_IXFR || q.qtype == DNS_T_OPT) {
        STAT(refused);
        return dns_make_error(&q, out, cap, DNS_R_REFUSED, 0);
    }

    bool rd = (q.flags & DNS_F_RD) != 0;
    /* Forwarding off (no default forwarders): names that would go to them are refused, as
     * for a client that may not recurse, and recursion isn't offered unless forward zones
     * are. REFUSED, not SERVFAIL: it is this node's policy, not a failure, so a client asks
     * its next server at once instead of retrying, and nothing caches it as a failure. */
    bool forwarding = settings()->nfwd > 0;
    bool recurse_ok = is_private(src) && (forwarding || reg_nfzones() > 0);
    bool cd = (q.flags & DNS_F_CD) != 0;
    size_t limit = tcp ? cap : q.has_edns ? (q.edns_size < DNS_EDNS_SIZE ? q.edns_size : DNS_EDNS_SIZE) : 512;
    uint16_t flags = (uint16_t)(DNS_F_QR | (rd ? DNS_F_RD : 0) | (recurse_ok ? DNS_F_RA : 0) | (cd ? DNS_F_CD : 0));

    dnsb_init(b, out, cap, limit, &q, flags);
    if (q.has_edns)
        dnsb_opt(b, DNS_EDNS_SIZE, q.do_bit);

    uint8_t target[DNS_MAX_NAME];
    int target_len = 0;
    int rcode = DNS_R_NOERROR;
    /* Before the route and the blocking decision: see resolve. */
    uint32_t gen = s_cache ? cache_gen(s_cache) : 0;

    reg_rdlock();
    route_t r = reg_route(q.qname, q.qname_len);
    if (r.kind == ROUTE_AUTH) {
        answer_result_t res;
        answer_auth(reg_find_auth, NULL, r.z, &q, b, &res);
        rcode = res.rcode;
        if (res.authoritative)
            dnsb_set_flags(b, DNS_F_AA, 0);
        if (res.external) {
            memcpy(target, res.target, (size_t)res.target_len);
            target_len = res.target_len;
        }
        reg_unlock();
        if (!again)
            STAT(auth);
        NOTE(hosted, r.hosted);
        NOTE(secondary, !r.hosted);

        if (target_len && rd && recurse_ok) {
            /* Local CNAME pointing outside: finish the chain upstream. */
            reg_rdlock();
            route_t tr = reg_route(target, target_len);
            reg_unlock();
            /* Local zones aren't blocked, nor where their CNAMEs lead: blocked is ignored. The
             * CNAME check still runs so an unchecked answer never enters the cache under target,
             * where a direct query for target would be served it. */
            uint32_t age;
            bool blocked;
            const uint8_t *ans = scratch;
            int rl = tr.kind == ROUTE_AUTH_FAIL || (tr.kind == ROUTE_DEFAULT && !forwarding) ? -1
                     : resolve(target, target_len, q.qtype, q.qclass, cd, tr, scratch, scratch_cap, &ans, &age, true,
                               &blocked, gen);
            if (rl == RESOLVE_PARKED)
                return 0;
            if (rl > 0) {
                int urc = dnsb_relay(b, ans, (size_t)rl, age, true, q.do_bit);
                if (urc == DNS_R_NXDOMAIN)
                    rcode = urc;
            }
        }
    } else if (r.kind == ROUTE_AUTH_FAIL) {
        reg_unlock();
        rcode = DNS_R_SERVFAIL;
    } else {
        reg_unlock();
        blk_result_t br = BLK_PASS;
        if (!rd || !recurse_ok || (r.kind == ROUTE_DEFAULT && !forwarding)) {
            rcode = DNS_R_REFUSED;
            STAT(refused);
        } else if ((br = blocking_query(q.qname)) == BLK_BLOCK) {
            /* Blocked: never forwarded, never cached. */
            rcode = blocking_answer(b, &q);
        } else {
            uint32_t age;
            bool blocked;
            const uint8_t *ans;
            /* A name the overrides allow is answered as it is, CNAMEs and all. */
            int rl = resolve(q.qname, q.qname_len, q.qtype, q.qclass, cd, r, scratch, scratch_cap, &ans, &age,
                             br == BLK_PASS, &blocked, gen);
            if (rl == RESOLVE_PARKED)
                return 0;
            STAT(forwarded);
            if (blocked) {
                rcode = blocking_answer(b, &q);
            } else if (rl < 0 && r.kind == ROUTE_DEFAULT && !settings()->nfwd) {
                /* Forwarding was turned off while this query was on its way: refused, as it
                 * would be now, not a failure. */
                rcode = DNS_R_REFUSED;
                STAT(refused);
            } else if (rl < 0) {
                rcode = DNS_R_SERVFAIL;
            } else {
                int urc = dnsb_relay(b, ans, (size_t)rl, age, false, q.do_bit);
                rcode = urc < 0 ? DNS_R_SERVFAIL : urc;
                if ((rd16(ans + 2) & DNS_F_AD) && (q.do_bit || (q.flags & DNS_F_AD)))
                    dnsb_set_flags(b, DNS_F_AD, 0);
            }
        }
    }

    if (rcode == DNS_R_SERVFAIL)
        STAT(servfail);
    else if (rcode == DNS_R_NXDOMAIN)
        STAT(nxdomain);
    dnsb_set_rcode(b, rcode);
    return dnsb_finish(b);
}

size_t server_handle(const uint8_t *m, size_t mlen, uint32_t src, bool tcp, uint8_t *out, size_t cap,
                     uint8_t *scratch, size_t scratch_cap, dns_builder_t *b)
{
    /* On this worker's stack: the query path allocates nothing. */
    ql_note_t note;
    memset(&note, 0, offsetof(ql_note_t, name)); /* the name is written only when there is one */
    int64_t t0 = esp_timer_get_time();
    worker_t *w = t_w;
    /* When its worker took the query, written before it may be parked: once it is, another
     * worker may answer it (and free the item) at any time, so nothing here touches the item
     * after handle returns. */
    if (w && w->item && !w->replay.on)
        w->item->t0_ms = (uint32_t)(t0 / 1000);
    querylog_note_set(&note);
    size_t n = handle(m, mlen, src, tcp, out, cap, scratch, scratch_cap, b);
    querylog_note_set(NULL);
    if (w && w->parked)
        return 0; /* noted when it is answered */
    int64_t us = esp_timer_get_time() - t0;
    if (w && w->replay.on && w->item) /* a parked query: its time to answer counts its wait */
        us += (int64_t)(uint32_t)((uint32_t)(t0 / 1000) - w->item->t0_ms) * 1000;
    querylog_query(&note, src, tcp, out, n, us > UINT32_MAX ? UINT32_MAX : (uint32_t)us);
    return n;
}

/* ---- UDP ---- */

_Static_assert(offsetof(udp_item_t, fw) == 0, "a parked query's waiter is its item");
_Static_assert(sizeof(udp_item_t) <= MP_UDP_ITEM, "the plan's UDP item (memplan.h) is too small");
/* The worker's own state is taken with its builder, in the plan's room for that. */
_Static_assert(sizeof(dns_builder_t) + sizeof(worker_t) <= MP_BUILDER, "the plan's builder (memplan.h) is too small");

static QueueHandle_t s_udp_q;    /* received queries, for the workers; NULL: take the finished flights */
static QueueHandle_t s_udp_free; /* the pool's free items: receiving allocates nothing */
static int s_rx_watch = -1, s_acc_watch = -1;

/* Answers one UDP query (it) with w's buffers, its answer built in out (MP_UDP_OUT), and
 * gives the item back unless the query was parked on a flight (then the flight has it). */
static void answer_item(worker_t *w, udp_item_t *it, uint8_t *out)
{
    w->item = it;
    w->parked = false;
    size_t n = server_handle(it->buf, it->len, it->from.sin_addr.s_addr, false, out, MP_UDP_OUT, w->scratch,
                             MP_SCRATCH, w->b);
    w->item = NULL;
    if (w->parked)
        return;
    if (n)
        sendto(s_udp, out, n, 0, (struct sockaddr *)&it->from, sizeof(it->from));
    xQueueSend(s_udp_free, &it, 0);
}

/* The flights the forward loop has finished (upq.h): each cached and ended, and the UDP
 * queries parked on it answered here from its answer (or its failure), in the order they
 * came. The caller holds POWER_DNS. */
static void take_flights(worker_t *w)
{
    upq_done_t d;
    while (upq_take(&s_upq, &d, now_ms(), now_s())) {
        w->replay.on = true;
        w->replay.answer = d.answer;
        w->replay.len = d.len;
        w->replay.f = d.f;
        for (flight_waiter_t *p = d.parked, *next; p; p = next) {
            next = p->next; /* answered, the item may be parked again, on another flight */
            supervisor_kick(w->watch);
            answer_item(w, (udp_item_t *)p, w->out);
        }
        w->replay.on = false;
        upq_release(&s_upq, &d);
    }
}

/* The forward loop finished a flight (upq.h): a worker is woken to take it, by a NULL on the
 * queue. With the queue full every worker is busy, and takes it before its next query. */
static bool wake_worker(void *ctx)
{
    udp_item_t *none = NULL;
    return xQueueSend(s_udp_q, &none, 0) == pdTRUE;
}

static void udp_worker(void *arg)
{
    worker_t *w = arg;
    udp_item_t *it;
    t_w = w;
    for (;;) {
        /* Waiting for a query, for as long as none comes: parked, never late (sup.h), so an
         * idle node's workers don't wake to check in. */
        supervisor_park(w->watch);
        if (xQueueReceive(s_udp_q, &it, portMAX_DELAY) != pdTRUE)
            continue;
        supervisor_kick(w->watch);
        power_hold(POWER_DNS);
        if (!it)
            upq_woken(&s_upq);
        /* The finished flights first: their queries came before this one. */
        take_flights(w);
        if (it)
            answer_item(w, it, w->out);
        power_release(POWER_DNS);
    }
}

/* The forward loop and its TCP task (fwdq.h): for good. */
static void fwd_task(void *arg)
{
    fwdq_run(&s_upq.q);
    vTaskDelete(NULL);
}

static void fwd_tcp_task(void *arg)
{
    fwdq_tcp_run(&s_upq.q);
    vTaskDelete(NULL);
}

static void fwd_alive(void) { supervisor_kick(s_fwd_watch); }

static void udp_rx(void *arg)
{
    udp_item_t *it = NULL;
    for (;;) {
#ifdef DNS2_TEST_STALL_S
        /* Test hook (CMakeLists.txt): the listeners stall. */
        if (esp_timer_get_time() / 1000000 >= DNS2_TEST_STALL_S)
            for (;;)
                vTaskDelay(portMAX_DELAY);
#endif
        supervisor_kick(s_rx_watch);
        if (!it) {
            if (xQueueReceive(s_udp_free, &it, pdMS_TO_TICKS(SUP_LISTENER_CHECKIN_MS)) != pdTRUE)
                continue;
            supervisor_kick(s_rx_watch); /* a check-in before each wait, never two waits apart */
        }
        socklen_t fl = sizeof(it->from);
        ssize_t n = recvfrom(s_udp, it->buf, sizeof(it->buf), 0, (struct sockaddr *)&it->from, &fl);
        if (n <= 0)
            continue; /* the receive timeout: check in, and keep the item */
        STAT(udp);
        it->len = (uint16_t)n;
        if (xQueueSend(s_udp_q, &it, 0) == pdTRUE)
            it = NULL;
        else
            STAT(dropped); /* every worker busy and the queue full: the item is reused */
    }
}

/* ---- TCP ---- */

static QueueHandle_t s_tcp_q;

static void tcp_worker(void *arg)
{
    worker_t *w = arg;
    int c;
    t_w = w;
    for (;;) {
        if (xQueueReceive(s_tcp_q, &c, portMAX_DELAY) != pdTRUE)
            continue;
        struct sockaddr_in peer;
        socklen_t pl = sizeof(peer);
        getpeername(c, (struct sockaddr *)&peer, &pl);
        struct timeval tv = { .tv_sec = TCP_IDLE_MS / 1000 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        for (;;) {
            uint8_t lp[2];
            if (!tcp_read_full(c, lp, 2))
                break;
            size_t len = rd16(lp);
            if (!len || !tcp_read_full(c, w->in, len))
                break;
            STAT(tcp);
            /* Not while reading: a slow client's pauses are idle time. */
            power_hold(POWER_DNS);
            size_t n = server_handle(w->in, len, peer.sin_addr.s_addr, true, w->out + 2, MP_TCP_MSG, w->scratch,
                                     MP_SCRATCH, w->b);
            if (n)
                wr16(w->out, (uint16_t)n);
            bool sent = n && tcp_write_full(c, w->out, n + 2);
            power_release(POWER_DNS);
            if (!sent)
                break;
        }
        close(c);
    }
}

static void tcp_accept(void *arg)
{
    int ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = INADDR_ANY };
    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(ls, 4) < 0) {
        ESP_LOGE(TAG, "tcp/53 bind failed");
        s_listen_failed = true;
        supervisor_unwatch(s_acc_watch);
        vTaskDelete(NULL);
    }
    /* accept returns at least every SUP_LISTENER_CHECKIN_MS, so the task checks in while
     * nothing connects. */
    struct timeval tv = { .tv_sec = SUP_LISTENER_CHECKIN_MS / 1000, .tv_usec = SUP_LISTENER_CHECKIN_MS % 1000 * 1000 };
    setsockopt(ls, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    s_tcp_ok = true;
    boot_mark(BOOT_LISTEN); /* UDP was bound before this task started */
    for (;;) {
        supervisor_kick(s_acc_watch);
        int c = accept(ls, NULL, NULL);
        if (c < 0)
            continue;
        if (xQueueSend(s_tcp_q, &c, 0) != pdTRUE) {
            STAT(dropped);
            close(c); /* all workers busy */
        }
    }
}

/* A task of the dns service, its stack counted against the service's share. */
static bool start_task(TaskFunction_t fn, const char *name, uint32_t stack, void *arg, UBaseType_t prio)
{
    if (xTaskCreate(fn, name, stack, arg, prio, NULL) != pdPASS) {
        ESP_LOGE(TAG, "%s: task failed to start", name);
        return false;
    }
    share_note(SVC_DNS, MP_INTERNAL, (long)stack);
    return true;
}

/* A worker's buffers from the share; NULL if the heap has none. */
static worker_t *new_worker(mp_pool_t pool, bool tcp)
{
    worker_t *w = share_alloc(SVC_DNS, pool, sizeof(*w));
    if (!w)
        return NULL;
    memset(w, 0, sizeof(*w));
    w->in = tcp ? share_alloc(SVC_DNS, pool, MP_TCP_MSG) : NULL;
    w->out = share_alloc(SVC_DNS, pool, tcp ? MP_TCP_MSG + 2 : MP_UDP_OUT);
    w->scratch = share_alloc(SVC_DNS, pool, MP_SCRATCH);
    w->b = share_alloc(SVC_DNS, pool, sizeof(dns_builder_t));
    w->watch = -1;
    if ((tcp && !w->in) || !w->out || !w->scratch || !w->b) {
        share_free(w->in);
        share_free(w->out);
        share_free(w->scratch);
        share_free(w->b);
        share_free(w);
        return NULL;
    }
    return w;
}

void server_start(void)
{
    /* Everything the service uses from here on, taken now from its share (memplan.h): the
     * cache, the workers' buffers and the UDP pool. The query path allocates nothing. */
    const mp_board_t *mb = share_board();
    mp_pool_t pool = mp_data_pool(mb);
    size_t cache_bytes = (size_t)mb->cache_kb * 1024;
    void *cache_mem = share_alloc(SVC_DNS, pool, cache_bytes);
    s_cache = cache_new_in(cache_mem, cache_bytes, mb->cache_entries);
    if (!s_cache) {
        share_free(cache_mem);
        ESP_LOGE(TAG, "cache: no memory for %lu KB: answering without one", (unsigned long)mb->cache_kb);
    } else {
        ESP_LOGI(TAG, "cache: %lu answers, %lu KB (%s)", (unsigned long)mb->cache_entries, (unsigned long)mb->cache_kb,
                 pool == MP_PSRAM ? "PSRAM" : "internal RAM");
    }
    /* The table of outstanding upstream queries and the forward loop's TCP retry buffer. */
    void *flight_mem = share_alloc(SVC_DNS, pool, flights_bytes((int)mb->fwd_pending));
    uint8_t *fwd_tcp = share_alloc(SVC_DNS, pool, MP_FWD_TCP);
    worker_t *udp[MP_UDP_WORKERS], *tcp[MP_TCP_WORKERS];
    bool ok = flight_mem && fwd_tcp;
    for (int i = 0; i < MP_UDP_WORKERS; i++)
        ok = (udp[i] = new_worker(pool, false)) && ok;
    for (int i = 0; i < MP_TCP_WORKERS; i++)
        ok = (tcp[i] = new_worker(pool, true)) && ok;
    udp_item_t *items = share_alloc(SVC_DNS, pool, MP_UDP_ITEMS * sizeof(udp_item_t));
    s_udp_q = xQueueCreate(MP_UDP_QUEUE, sizeof(udp_item_t *));
    s_udp_free = xQueueCreate(MP_UDP_ITEMS, sizeof(udp_item_t *));
    s_tcp_q = xQueueCreate(MP_TCP_WORKERS * 2, sizeof(int));
    if (!ok || !items || !s_udp_q || !s_udp_free || !s_tcp_q) {
        /* The plan said it fits: the board definition is wrong. Loud: a fault. */
        ESP_LOGE(TAG, "no memory for the DNS workers' buffers (or the upstream query table): not listening");
        s_listen_failed = true;
        return;
    }
    if (!upq_init(&s_upq, flight_mem, (int)mb->fwd_pending, MP_FLIGHT_WAITERS, fwd_tcp, MP_FWD_TCP, s_cache,
                  cacheable, wake_worker, NULL)) {
        ESP_LOGE(TAG, "the forward loop's wake socket failed: not listening");
        s_listen_failed = true;
        return;
    }
    __atomic_store_n(&s_upq_ok, true, __ATOMIC_RELEASE);
    for (int i = 0; i < MP_UDP_ITEMS; i++) {
        udp_item_t *it = &items[i];
        it->fw.wake = NULL; /* a parked UDP query (flight.h) */
        xQueueSend(s_udp_free, &it, 0);
    }

    s_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = INADDR_ANY };
    if (s_udp < 0 || bind(s_udp, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        ESP_LOGE(TAG, "udp/53 bind failed");
        s_listen_failed = true;
        return;
    }
    /* A receive returns at least every SUP_LISTENER_CHECKIN_MS, so the task checks in while
     * nothing arrives. */
    struct timeval tv = { .tv_sec = SUP_LISTENER_CHECKIN_MS / 1000, .tv_usec = SUP_LISTENER_CHECKIN_MS % 1000 * 1000 };
    setsockopt(s_udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    s_udp_ok = true;
    fwd_set_observer(querylog_upstream); /* the forwarders' counters for /metrics: thread-safe */
    /* The forward loop before the workers that hand it queries. Watched (sup.h): late, it
     * degrades the node ("forwarder task stalled"), never reboots it: cached and local
     * answers go on. A watch whose task never started is late, so that shows too. Its TCP
     * task isn't watched: it waits for truncated answers for as long as none come. */
    s_fwd_watch = supervisor_watch(SVC_DNS, SUP_FORWARDER, SUP_FORWARDER_MS);
    fwdq_set_alive(&s_upq.q, fwd_alive);
    start_task(fwd_task, "dns_fwd", MP_FWD_STACK, NULL, 6);
    start_task(fwd_tcp_task, "dns_fwdtcp", MP_FWD_STACK, NULL, 5);
    /* Watched (sup.h): the receive and accept tasks, and the UDP workers together. A TCP
     * worker isn't: a slow client may hold one for as long as it keeps sending. */
    for (int i = 0; i < MP_UDP_WORKERS; i++) {
        udp[i]->watch = supervisor_watch(SVC_DNS, SUP_WORKER, SUP_WORKER_MS);
        if (!start_task(udp_worker, "dns_udp", MP_WORKER_STACK, udp[i], 6))
            supervisor_unwatch(udp[i]->watch);
    }
    for (int i = 0; i < MP_TCP_WORKERS; i++)
        start_task(tcp_worker, "dns_tcp", MP_WORKER_STACK, tcp[i], 5);
    /* Both listeners above the workers: a flood that keeps every core busy with queries
     * must not starve them past their deadline, which would read as a stall and reboot a
     * node that is answering. Each only receives or accepts and hands over. */
    s_rx_watch = supervisor_watch(SVC_DNS, SUP_LISTENER, SUP_LISTENER_MS);
    if (!start_task(udp_rx, "dns_rx", MP_LISTENER_STACK, NULL, 7))
        s_listen_failed = true;
    s_acc_watch = supervisor_watch(SVC_DNS, SUP_LISTENER, SUP_LISTENER_MS);
    if (!start_task(tcp_accept, "dns_acc", MP_LISTENER_STACK, NULL, 7))
        s_listen_failed = true;
    ESP_LOGI(TAG, "listening on udp/53 and tcp/53");
}

bool server_running(void) { return s_udp_ok && s_tcp_ok; }

svc_state_t server_state(void)
{
    return s_listen_failed ? SVC_FAILED : server_running() ? SVC_RUNNING : SVC_STARTING;
}

void server_upstream_reset(void)
{
    if (__atomic_load_n(&s_upq_ok, __ATOMIC_ACQUIRE))
        health_upstream_reset(&s_upq.health);
}

bool server_failed(void) { return s_listen_failed; }

void server_upstream(health_fwd_t *f)
{
    *f = (health_fwd_t){ 0 };
    if (!__atomic_load_n(&s_upq_ok, __ATOMIC_ACQUIRE))
        return;
    health_upstream_get(&s_upq.health, now_ms(), f);
    flight_counts_t c;
    flight_counts(&s_upq.fl, &c);
    f->busy = c.busy;
    f->busy_since_ms = c.busy_since_ms;
}

bool server_forward_stats(upq_stats_t *s)
{
    if (!__atomic_load_n(&s_upq_ok, __ATOMIC_ACQUIRE))
        return false;
    upq_stats(&s_upq, s);
    return true;
}

void server_cache_flush(void)
{
    if (s_cache)
        cache_flush(s_cache);
}

void server_get_stats(server_stats_t *s)
{
    *s = s_st;
}

bool server_cache_stats(cache_stats_t *s, uint32_t *max_entries, uint32_t *bytes)
{
    *max_entries = share_board()->cache_entries;
    *bytes = share_board()->cache_kb * 1024;
    if (!s_cache)
        return false;
    cache_get_stats(s_cache, s);
    return true;
}
