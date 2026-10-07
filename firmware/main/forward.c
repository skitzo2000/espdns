#include "forward.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <unistd.h>

#include "dns_wire.h"

#ifdef ESP_PLATFORM
#include "esp_random.h"
uint32_t dns2_random(void) { return esp_random(); }
#else
#include <stdlib.h>
uint32_t dns2_random(void) { return (uint32_t)random() ^ ((uint32_t)random() << 16); }
#endif

size_t fwd_build_query(uint8_t *out, size_t cap, uint16_t id, const uint8_t *qname, int qlen,
                       uint16_t qtype, uint16_t qclass, bool do_bit, bool cd, bool rd)
{
    size_t need = DNS_HDR_LEN + (size_t)qlen + 4 + 11;
    if (cap < need)
        return 0;
    wr16(out, id);
    wr16(out + 2, (uint16_t)((rd ? DNS_F_RD : 0) | (cd ? DNS_F_CD : 0)));
    wr16(out + 4, 1);
    wr16(out + 6, 0);
    wr16(out + 8, 0);
    wr16(out + 10, 1);
    size_t p = DNS_HDR_LEN;
    memcpy(out + p, qname, (size_t)qlen);
    p += (size_t)qlen;
    wr16(out + p, qtype);
    wr16(out + p + 2, qclass);
    p += 4;
    out[p] = 0; /* OPT */
    wr16(out + p + 1, DNS_T_OPT);
    wr16(out + p + 3, DNS_EDNS_SIZE);
    wr32(out + p + 5, do_bit ? 0x8000 : 0);
    wr16(out + p + 9, 0);
    return p + 11;
}

/* The port forwarders are asked on: 53; the host tests' fake forwarders listen on another. */
#ifndef DNS2_FWD_PORT
#define DNS2_FWD_PORT 53
#endif

static void set_timeouts(int s, int timeout_ms)
{
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int tcp_connect_timeout(uint32_t server, uint16_t port, int timeout_ms)
{
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
        return -1;
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = server };
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, fl | O_NONBLOCK);
    int r = connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0 && errno != EINPROGRESS) {
        close(s);
        return -1;
    }
    if (r < 0) {
        fd_set w;
        FD_ZERO(&w);
        FD_SET(s, &w);
        struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
        int err = 0;
        socklen_t el = sizeof(err);
        if (select(s + 1, NULL, &w, NULL, &tv) <= 0 ||
            getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) {
            close(s);
            return -1;
        }
    }
    fcntl(s, F_SETFL, fl);
    set_timeouts(s, timeout_ms);
    return s;
}

bool tcp_read_full(int s, uint8_t *buf, size_t n)
{
    while (n) {
        ssize_t r = recv(s, buf, n, 0);
        if (r <= 0)
            return false;
        buf += r;
        n -= (size_t)r;
    }
    return true;
}

bool tcp_write_full(int s, const uint8_t *buf, size_t n)
{
    while (n) {
        ssize_t r = send(s, buf, n, 0);
        if (r <= 0)
            return false;
        buf += r;
        n -= (size_t)r;
    }
    return true;
}

static int64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* ms left until end_us (mono_us), rounded up: 0 once it has come. */
static int left_ms(int64_t end_us)
{
    int64_t l = (end_us - mono_us() + 999) / 1000;
    return l <= 0 ? 0 : l > INT_MAX ? INT_MAX : (int)l;
}

/* Sends or reads n bytes by end_us: each call waits at most what is left (a socket timeout
 * of 0 would be no timeout, so it is never set). */
static bool tcp_io_by(int s, uint8_t *buf, size_t n, bool wr, int64_t end_us)
{
    while (n) {
        int left = left_ms(end_us);
        if (!left)
            return false;
        set_timeouts(s, left);
        ssize_t r = wr ? send(s, buf, n, 0) : recv(s, buf, n, 0);
        if (r <= 0)
            return false;
        buf += r;
        n -= (size_t)r;
    }
    return true;
}

int fwd_query_tcp(uint32_t server, const uint8_t *query, size_t qlen, uint8_t *out, size_t cap,
                  int timeout_ms)
{
    if (timeout_ms <= 0)
        return -1;
    int64_t end = mono_us() + (int64_t)timeout_ms * 1000;
    int s = tcp_connect_timeout(server, DNS2_FWD_PORT, timeout_ms);
    if (s < 0)
        return -1;
    uint8_t lp[2];
    int ret = -1;
    wr16(lp, (uint16_t)qlen);
    if (tcp_io_by(s, lp, 2, true, end) && tcp_io_by(s, (uint8_t *)query, qlen, true, end) &&
        tcp_io_by(s, lp, 2, false, end)) {
        size_t n = rd16(lp);
        if (n <= cap && n >= DNS_HDR_LEN && tcp_io_by(s, out, n, false, end) && rd16(out) == rd16(query))
            ret = (int)n;
    }
    close(s);
    return ret;
}

/* resp answers q exactly: its ID, a response, one question, the name (any case), type and
 * class asked. */
static bool matches(const uint8_t *resp, size_t rlen, uint16_t id, const fwd_q_t *q)
{
    if (rlen < DNS_HDR_LEN || rd16(resp) != id || !(rd16(resp + 2) & DNS_F_QR) || rd16(resp + 4) != 1)
        return false;
    size_t pos = DNS_HDR_LEN;
    uint8_t name[DNS_MAX_NAME];
    int n = dns_name_read(resp, rlen, &pos, name);
    if (n < 0 || pos + 4 > rlen)
        return false;
    return dns_name_eq(name, n, q->qname, q->qlen) && rd16(resp + pos) == q->qtype && rd16(resp + pos + 2) == q->qclass;
}

static void (*volatile s_observer)(uint32_t server, fwd_try_t how, uint32_t us);

void fwd_set_observer(void (*fn)(uint32_t server, fwd_try_t how, uint32_t us)) { s_observer = fn; }

/* One attempt at server, begun at t0 (mono_us), is over. */
static void observe(uint32_t server, fwd_try_t how, int64_t t0)
{
    void (*fn)(uint32_t, fwd_try_t, uint32_t) = s_observer;
    if (fn) {
        int64_t us = mono_us() - t0;
        fn(server, how, us < 0 ? 0 : us > UINT32_MAX ? UINT32_MAX : (uint32_t)us);
    }
}

uint32_t fwd_now_ms(void) { return (uint32_t)(mono_us() / 1000); }

/* now has reached deadline, across the wrap of a ms counter. */
static bool due(uint32_t now_ms, uint32_t deadline_ms) { return (int32_t)(now_ms - deadline_ms) >= 0; }

/* The query as sent: with DO, RD and the question's CD. */
static size_t build(const fwd_up_t *u, const fwd_q_t *q, uint8_t *out, size_t cap)
{
    return fwd_build_query(out, cap, u->id, q->qname, q->qlen, q->qtype, q->qclass, true, q->cd, true);
}

#define FWD_QUERY_MAX (DNS_HDR_LEN + DNS_MAX_NAME + 4 + 11)

uint16_t fwd_random_port(void)
{
    return (uint16_t)(FWD_PORT_MIN + dns2_random() % (65536u - FWD_PORT_MIN));
}

bool fwd_bind_random(int s)
{
    for (int i = 0; i < FWD_BIND_TRIES; i++) {
        struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(fwd_random_port()),
                                  .sin_addr.s_addr = htonl(INADDR_ANY) };
        if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) == 0)
            return true;
        if (errno != EADDRINUSE)
            return false;
    }
    return false;
}

void fwd_up_init(fwd_up_t *u, const uint32_t *servers, int n, int timeout_ms)
{
    memset(u, 0, sizeof(*u));
    n = n < 0 ? 0 : n > CFG_MAX_FWD ? CFG_MAX_FWD : n;
    if (n)
        memcpy(u->servers, servers, (size_t)n * sizeof(u->servers[0]));
    u->nservers = (uint8_t)n;
    u->timeout_ms = timeout_ms < 0 ? 0 : timeout_ms;
    u->sock = -1;
}

/* Sends tries from u->attempt on until one goes out (FWD_WAIT); a try whose send fails is
 * over at once. FWD_FAILED: none left, or the budget is spent. */
static fwd_step_t send_try(fwd_up_t *u, const fwd_q_t *q, uint32_t now_ms)
{
    uint8_t m[FWD_QUERY_MAX];
    size_t n = build(u, q, m, sizeof(m));
    for (; u->attempt < FWD_TRIES_PER_SERVER * u->nservers && !due(now_ms, u->end_ms); u->attempt++) {
        uint32_t srv = fwd_up_server(u);
        struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(DNS2_FWD_PORT), .sin_addr.s_addr = srv };
        u->try_t0_us = mono_us();
        /* now_ms is the ms under way: a ms more, so the try never ends short of its timeout. */
        u->try_end_ms = now_ms + (uint32_t)u->timeout_ms + 1;
        if (!due(u->end_ms, u->try_end_ms)) /* the budget ends first */
            u->try_end_ms = u->end_ms;
        if (n && sendto(u->sock, m, n, 0, (struct sockaddr *)&sa, sizeof(sa)) >= 0)
            return FWD_WAIT;
        observe(srv, FWD_TRY_ERROR, u->try_t0_us);
    }
    return FWD_FAILED;
}

fwd_step_t fwd_up_start(fwd_up_t *u, const fwd_q_t *q, uint32_t now_ms)
{
    u->id = (uint16_t)dns2_random();
    u->attempt = 0;
    u->end_ms = now_ms + fwd_budget_ms(u->nservers, u->timeout_ms);
    if (!u->nservers || q->qlen <= 0 || q->qlen > DNS_MAX_NAME)
        return FWD_FAILED;
    u->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    /* At or past FD_SETSIZE select() can't watch it (FD_SET would write past its set); and
     * its source port is random, as its ID is, or it fails. */
    if (u->sock >= FD_SETSIZE || (u->sock >= 0 && !fwd_bind_random(u->sock)))
        fwd_up_close(u);
    if (u->sock < 0)
        return FWD_FAILED;
    fcntl(u->sock, F_SETFL, fcntl(u->sock, F_GETFL, 0) | O_NONBLOCK);
    return send_try(u, q, now_ms);
}

int fwd_up_recv(fwd_up_t *u, const fwd_q_t *q, uint8_t *buf, size_t cap)
{
    if (u->sock < 0 || u->attempt >= FWD_TRIES_PER_SERVER * u->nservers)
        return 0;
    uint32_t srv = fwd_up_server(u);
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t r = recvfrom(u->sock, buf, cap, 0, (struct sockaddr *)&from, &fl);
        if (r < 0)
            return 0; /* nothing more now */
        if (from.sin_addr.s_addr != srv || from.sin_port != htons(DNS2_FWD_PORT) || !matches(buf, (size_t)r, u->id, q))
            continue; /* stray or spoofed: dropped, the try's wait goes on */
        return (int)r;
    }
}

fwd_step_t fwd_up_answer(fwd_up_t *u, const fwd_q_t *q, const uint8_t *ans, int len, uint32_t now_ms)
{
    if (u->attempt >= FWD_TRIES_PER_SERVER * u->nservers)
        return FWD_FAILED;
    bool servfail = len > 0 && DNS_RCODE(rd16(ans + 2)) == DNS_R_SERVFAIL;
    observe(fwd_up_server(u), len <= 0 ? FWD_TRY_ERROR : servfail ? FWD_TRY_SERVFAIL : FWD_TRY_ANSWER, u->try_t0_us);
    bool last = u->attempt + 1 >= FWD_TRIES_PER_SERVER * u->nservers || due(now_ms, u->end_ms);
    if (len > 0 && (!servfail || last))
        return FWD_ANSWER;
    u->attempt++; /* let another upstream try */
    return send_try(u, q, now_ms);
}

fwd_step_t fwd_up_timeout(fwd_up_t *u, const fwd_q_t *q, uint32_t now_ms)
{
    if (u->attempt >= FWD_TRIES_PER_SERVER * u->nservers)
        return FWD_FAILED;
    if (!due(now_ms, u->try_end_ms))
        return FWD_WAIT;
    observe(fwd_up_server(u), FWD_TRY_TIMEOUT, u->try_t0_us);
    u->attempt++;
    return send_try(u, q, now_ms);
}

int fwd_up_tcp(fwd_up_t *u, const fwd_q_t *q, uint8_t *out, size_t cap, uint32_t now_ms)
{
    if (u->attempt >= FWD_TRIES_PER_SERVER * u->nservers || due(now_ms, u->end_ms))
        return -1;
    uint8_t m[FWD_QUERY_MAX];
    size_t n = build(u, q, m, sizeof(m));
    uint32_t tcp_ms = (uint32_t)u->timeout_ms * FWD_TCP_TIMEOUT_MUL, left = u->end_ms - now_ms;
    int len = n ? fwd_query_tcp(fwd_up_server(u), m, n, out, cap, (int)(tcp_ms < left ? tcp_ms : left)) : -1;
    /* It must answer the question asked, as a datagram must (fwd_up_recv). */
    return len > 0 && matches(out, (size_t)len, u->id, q) ? len : -1;
}

void fwd_up_close(fwd_up_t *u)
{
    if (u->sock >= 0)
        close(u->sock);
    u->sock = -1;
}

int fwd_query(const uint32_t *servers, int nservers, const uint8_t *qname, int qlen,
              uint16_t qtype, uint16_t qclass, bool cd,
              uint8_t *out, size_t cap, int timeout_ms)
{
    fwd_up_t u;
    fwd_q_t q = { .qname = qname, .qlen = qlen, .qtype = qtype, .qclass = qclass, .cd = cd };
    fwd_up_init(&u, servers, nservers, timeout_ms);
    fwd_step_t st = fwd_up_start(&u, &q, fwd_now_ms());
    int len = -1;
    /* Each try ends at its timeout and the whole query within the budget, whatever comes
     * meanwhile (strays don't restart a try's wait, nor a slow TCP retry the next try's): a
     * query parked on this one (flight.h) waits that long, so it is answered from this. */
    while (st == FWD_WAIT) {
        int32_t left = (int32_t)(fwd_up_due(&u) - fwd_now_ms());
        if (left > 0) {
            fd_set r;
            FD_ZERO(&r);
            FD_SET(u.sock, &r);
            struct timeval tv = { .tv_sec = left / 1000, .tv_usec = (left % 1000) * 1000 };
            if (select(u.sock + 1, &r, NULL, NULL, &tv) > 0 && (len = fwd_up_recv(&u, &q, out, cap)) > 0) {
                if (rd16(out + 2) & DNS_F_TC)
                    len = fwd_up_tcp(&u, &q, out, cap, fwd_now_ms());
                st = fwd_up_answer(&u, &q, out, len, fwd_now_ms());
            }
        } else {
            st = fwd_up_timeout(&u, &q, fwd_now_ms());
        }
    }
    fwd_up_close(&u);
    return st == FWD_ANSWER ? len : -1;
}
