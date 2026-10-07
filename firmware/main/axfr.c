#include "axfr.h"

#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "dns_wire.h"
#include "forward.h"

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

/* The socket's waits: at most what is left (never 0, which would be no timeout). */
static void wait_at_most(int s, int ms)
{
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Sends or reads n bytes by end_us: each call waits at most what is left. */
static bool io_by(int s, uint8_t *buf, size_t n, bool wr, int64_t end_us)
{
    while (n) {
        int left = left_ms(end_us);
        if (!left)
            return false;
        wait_at_most(s, left);
        ssize_t r = wr ? send(s, buf, n, 0) : recv(s, buf, n, 0);
        if (r <= 0)
            return false;
        buf += r;
        n -= (size_t)r;
    }
    return true;
}

bool axfr_soa_serial(uint32_t primary, uint16_t port, const uint8_t *apex, int apex_len, int timeout_ms,
                     uint32_t *serial)
{
    uint8_t q[DNS_HDR_LEN + DNS_MAX_NAME + 4 + 11];
    uint8_t r[1232];
    size_t qn = fwd_build_query(q, sizeof(q), (uint16_t)dns2_random(), apex, apex_len,
                                DNS_T_SOA, DNS_C_IN, false, false, false);
    if (!qn || timeout_ms <= 0)
        return false;
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0)
        return false;
    int64_t end = mono_us() + (int64_t)timeout_ms * 1000;
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = primary };

    bool ok = false;
    if (sendto(s, q, qn, 0, (struct sockaddr *)&sa, sizeof(sa)) > 0) {
        for (int left; (left = left_ms(end));) {
            wait_at_most(s, left);
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            ssize_t n = recvfrom(s, r, sizeof(r), 0, (struct sockaddr *)&from, &fl);
            if (n < 0)
                break;
            dns_hdr_t h;
            if (from.sin_addr.s_addr != primary || from.sin_port != htons(port) || !dns_hdr_parse(r, (size_t)n, &h) ||
                h.id != rd16(q))
                continue; /* stray: keep waiting, as long as the check has left */
            if (!(h.flags & DNS_F_AA) || DNS_RCODE(h.flags) != DNS_R_NOERROR)
                break;
            size_t pos = DNS_HDR_LEN;
            if (dns_name_skip(r, (size_t)n, &pos) < 0)
                break;
            pos += 4;
            for (int i = 0; i < h.an; i++) {
                dns_rr_view_t rr;
                if (!dns_rr_parse(r, (size_t)n, &pos, &rr))
                    break;
                if (rr.type == DNS_T_SOA && rr.rdlen >= 20 && dns_name_eq(rr.name, rr.name_len, apex, apex_len)) {
                    *serial = rd32(r + rr.rdata_off + rr.rdlen - 20);
                    ok = true;
                    break;
                }
            }
            break;
        }
    }
    close(s);
    return ok;
}

const char *axfr_err_str(axfr_err_t e)
{
    switch (e) {
    case AXFR_OK: return "ok";
    case AXFR_NET: return "connection failed or closed";
    case AXFR_TIMEOUT: return "deadline passed";
    case AXFR_REFUSED: return "refused";
    case AXFR_MALFORMED: return "malformed";
    case AXFR_TOO_BIG: return "zone too big for its memory";
    case AXFR_NOMEM: return "out of memory";
    }
    return "?";
}

zone_t *axfr_pull(uint32_t primary, uint16_t port, const uint8_t *apex, int apex_len, const axfr_opts_t *o,
                  axfr_err_t *err)
{
    uint8_t q[DNS_HDR_LEN + DNS_MAX_NAME + 4 + 11];
    uint8_t *msg = o->msg, *rdata = o->rdata;
    int64_t end = mono_us() + (int64_t)o->deadline_ms * 1000;
    int s = -1;
    int soa_seen = 0;
    size_t records = 0;
    axfr_err_t e = AXFR_MALFORMED;
    zone_t *z = zone_new(apex, apex_len, o->limit);

    if (!z) {
        e = o->limit < sizeof(zone_t) ? AXFR_TOO_BIG : AXFR_NOMEM;
        goto fail;
    }
    if (!msg || !rdata || o->deadline_ms <= 0) {
        e = AXFR_NOMEM;
        goto fail;
    }
    /* AXFR carries no EDNS here: keep the query minimal */
    size_t qn = fwd_build_query(q, sizeof(q), (uint16_t)dns2_random(), apex, apex_len,
                                DNS_T_AXFR, DNS_C_IN, false, false, false) - 11;
    wr16(q + 10, 0);

    e = AXFR_NET;
    int cms = left_ms(end);
    s = tcp_connect_timeout(primary, port, cms < AXFR_CONNECT_MS ? cms : AXFR_CONNECT_MS);
    if (s < 0)
        goto fail;
    uint8_t lp[2];
    wr16(lp, (uint16_t)qn);
    if (!io_by(s, lp, 2, true, end) || !io_by(s, q, qn, true, end))
        goto fail;

    while (soa_seen < 2) {
        if (!io_by(s, lp, 2, false, end))
            goto io_fail;
        size_t n = rd16(lp);
        if (!io_by(s, msg, n, false, end))
            goto io_fail;
        dns_hdr_t h;
        e = AXFR_MALFORMED;
        if (!dns_hdr_parse(msg, n, &h) || h.id != rd16(q))
            goto fail;
        if (DNS_RCODE(h.flags) != DNS_R_NOERROR) {
            e = AXFR_REFUSED;
            goto fail;
        }
        size_t pos = DNS_HDR_LEN;
        for (int i = 0; i < h.qd; i++) {
            if (dns_name_skip(msg, n, &pos) < 0)
                goto fail;
            pos += 4;
        }
        for (int i = 0; i < h.an && soa_seen < 2; i++) {
            dns_rr_view_t rr;
            if (!dns_rr_parse(msg, n, &pos, &rr))
                goto fail;
            if (records == 0 && rr.type != DNS_T_SOA)
                goto fail; /* must start with the SOA */
            if (rr.type == DNS_T_SOA && dns_name_eq(rr.name, rr.name_len, apex, apex_len))
                soa_seen++;
            records++;
            if (rr.cls != DNS_C_IN || rr.type == DNS_T_OPT)
                continue;
            int rl = dns_rdata_expand(msg, n, &rr, rdata, 65535);
            if (rl < 0)
                goto fail;
            /* Each record within the limit, as it comes. */
            if (!zone_add(z, rr.name, rr.name_len, rr.type, rr.ttl, rdata, (uint16_t)rl)) {
                e = z->over ? AXFR_TOO_BIG : AXFR_NOMEM;
                goto fail;
            }
        }
        if (o->progress)
            o->progress(o->ctx);
    }
    close(s);
    if (!zone_finalize(z)) {
        zone_free(z);
        *err = AXFR_MALFORMED;
        return NULL;
    }
    *err = AXFR_OK;
    return z;

io_fail:
    e = left_ms(end) ? AXFR_NET : AXFR_TIMEOUT;
fail:
    if (s >= 0)
        close(s);
    zone_free(z);
    *err = e;
    return NULL;
}
