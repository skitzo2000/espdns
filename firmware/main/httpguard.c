#include "httpguard.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

int64_t hg_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int64_t hg_body_ms(uint64_t len) { return HG_BODY_BASE_MS + (int64_t)(len * 1000 / HG_BODY_MIN_BPS); }

void hg_set(hg_conn_t *c, int64_t ms) { c->deadline_ms = hg_now_ms() + ms; }

void hg_done(hg_conn_t *c) { c->deadline_ms = 0; }

int64_t hg_left_ms(hg_conn_t *c)
{
    int64_t now = hg_now_ms();
    if (!c->deadline_ms)
        c->deadline_ms = now + HG_HEAD_MS;
    return c->deadline_ms - now;
}

static int io(hg_conn_t *c, int fd, void *buf, size_t len, int flags, bool rx)
{
    for (;;) {
        if (c->closed)
            return -1;
        int64_t left = hg_left_ms(c);
        if (left <= 0) {
            c->closed = true;
            return -1;
        }
        struct timeval tv = { .tv_sec = (time_t)(left / 1000), .tv_usec = (long)(left % 1000 * 1000) };
        setsockopt(fd, SOL_SOCKET, rx ? SO_RCVTIMEO : SO_SNDTIMEO, &tv, sizeof(tv));
        ssize_t r = rx ? recv(fd, buf, len, flags) : send(fd, buf, len, flags);
        if (r >= 0)
            return (int)r;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return -1;
    }
}

int hg_recv(hg_conn_t *c, int fd, void *buf, size_t len, int flags) { return io(c, fd, buf, len, flags, true); }

int hg_send(hg_conn_t *c, int fd, const void *buf, size_t len, int flags)
{
    return io(c, fd, (void *)buf, len, flags, false);
}

bool hg_host_ok(const char *host, uint32_t ip, const char *mdns, const char *name)
{
    if (!host || host[0] == '[') /* none, or an IPv6 literal: the node serves IPv4 only */
        return false;
    size_t n = strlen(host);
    const char *colon = strchr(host, ':');
    if (colon) {
        size_t d = strlen(colon + 1);
        if (d < 1 || d > 5 || strspn(colon + 1, "0123456789") != d)
            return false;
        n = (size_t)(colon - host);
    }
    if (n && host[n - 1] == '.')
        n--;
    if (!n)
        return false;
    if (ip) {
        const uint8_t *a = (const uint8_t *)&ip;
        char s[16];
        int k = snprintf(s, sizeof(s), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
        if ((size_t)k == n && !memcmp(host, s, n))
            return true;
    }
    if (mdns && mdns[0]) {
        size_t m = strlen(mdns);
        if (n == m + 6 && !strncasecmp(host, mdns, m) && !strncasecmp(host + m, ".local", 6))
            return true;
    }
    if (name && name[0] && strlen(name) == n && !strncasecmp(host, name, n))
        return true;
    return false;
}

hg_gate_t hg_gate(const hg_locks_t *l, bool lock, uint8_t kind, uint64_t seq)
{
    if (lock && !l->take())
        return HG_BUSY;
    if (lock && seq <= l->seq(kind)) {
        l->give();
        return HG_STALE;
    }
    if (!l->worker()) {
        if (lock)
            l->give();
        return HG_BUSY;
    }
    return HG_GO;
}
