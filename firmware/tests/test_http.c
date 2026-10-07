/*
 * The node HTTP server's portable parts (httpguard.h, jsonw.h): the Host check that stops
 * DNS rebinding (#57), the per-request deadlines on real sockets, so a client that trickles
 * bytes or never reads is dropped on time, and the order a release takes its locks in
 * (#56), and the JSON escaping /status and the release replies use (#66).
 */
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cJSON.h"
#include "httpguard.h"
#include "jsonw.h"

static int s_fail;
#define CHECK(x)                                                         \
    do {                                                                 \
        if (!(x)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); \
            s_fail++;                                                    \
        }                                                                \
    } while (0)

static uint32_t ip4(int a, int b, int c, int d)
{
    uint8_t x[4] = { (uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d };
    uint32_t v;
    memcpy(&v, x, 4); /* network order, as the node keeps it */
    return v;
}

/* ---- the Host check ---- */

static void test_host(void)
{
    uint32_t ip = ip4(192, 0, 2, 53);
    const char *mdns = "espdns-0a0b0c", *name = "dns-a.example.com";
    static const struct {
        const char *host;
        bool ok;
    } cases[] = {
        /* the node's address, as the controller sends it (Go and urllib: the URL's host) */
        { "192.0.2.53", true },
        { "192.0.2.53:80", true },
        { "192.0.2.53:8080", true },
        { "192.0.2.53.", true },
        /* its mDNS name, in any case */
        { "espdns-0a0b0c.local", true },
        { "ESPDNS-0A0B0C.LOCAL:80", true },
        { "espdns-0a0b0c.local.", true },
        /* its configured name */
        { "dns-a.example.com", true },
        { "DNS-A.Example.Com:80", true },
        /* DNS rebinding: the attacker's own name, pointed at the node */
        { "evil.example", false },
        { "evil.example:80", false },
        { "192.0.2.53.evil.example", false },
        { "dns-a.example.com.evil.example", false },
        { "espdns-0a0b0c.local.evil.example", false },
        { "espdns-0a0b0c", false },
        { "dns-a", false },
        /* another address, or the same written another way */
        { "192.0.2.54", false },
        { "192.0.2.5", false },
        { "192.000.002.053", false },
        { "3221226037", false },
        { "localhost", false },
        { "127.0.0.1", false },
        /* malformed */
        { "", false },
        { ".", false },
        { ":80", false },
        { "192.0.2.53:", false },
        { "192.0.2.53:x", false },
        { "192.0.2.53:123456", false },
        { "192.0.2.53:80:80", false },
        { "[::1]", false },
        { "[::ffff:192.0.2.53]:80", false },
        { "192.0.2.53 ", false },
        { "192.0.2.53..", false },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool ok = hg_host_ok(cases[i].host, ip, mdns, name);
        if (ok != cases[i].ok) {
            fprintf(stderr, "FAIL host \"%s\": %s\n", cases[i].host, ok ? "accepted" : "refused");
            s_fail++;
        }
    }
    CHECK(!hg_host_ok(NULL, ip, mdns, name)); /* no Host at all */
    /* What it doesn't have, it doesn't match: no address yet, no name in its config */
    CHECK(!hg_host_ok("0.0.0.0", 0, mdns, name));
    CHECK(hg_host_ok("espdns-0a0b0c.local", 0, mdns, NULL));
    CHECK(!hg_host_ok("dns-a.example.com", ip, mdns, ""));
    CHECK(!hg_host_ok(".local", ip, "", ""));
    CHECK(hg_host_ok("192.0.2.53", ip, NULL, NULL));
    /* A configured name with a space (names are display names too) never matches a Host */
    CHECK(!hg_host_ok("dns", ip, mdns, "dns a"));
}

/* ---- deadlines ---- */

static void test_budgets(void)
{
    CHECK(hg_body_ms(0) == HG_BODY_BASE_MS);
    CHECK(hg_body_ms(HG_BODY_MIN_BPS) == HG_BODY_BASE_MS + 1000);
    CHECK(hg_body_ms(2u << 20) == HG_BODY_BASE_MS + 512000); /* a 2 MB image: 522 s */
    CHECK(hg_body_ms(64ull << 30) > 0);                     /* no overflow on any length */

    hg_conn_t c = { 0 };
    int64_t left = hg_left_ms(&c); /* the first byte of a request starts its headers' deadline */
    CHECK(left > HG_HEAD_MS - 100 && left <= HG_HEAD_MS);
    CHECK(c.deadline_ms);
    hg_set(&c, HG_REPLY_MS);
    left = hg_left_ms(&c);
    CHECK(left > HG_REPLY_MS - 100 && left <= HG_REPLY_MS);
    hg_done(&c);
    CHECK(c.deadline_ms == 0);
    left = hg_left_ms(&c); /* the next request starts its own */
    CHECK(left > HG_HEAD_MS - 100 && left <= HG_HEAD_MS);
}

typedef struct {
    int fd;
    int every_ms; /* a byte this often */
    volatile bool stop;
} trickle_t;

static void *trickle(void *arg)
{
    trickle_t *t = arg;
    while (!t->stop) {
        if (send(t->fd, "x", 1, MSG_NOSIGNAL) != 1)
            break;
        usleep((useconds_t)t->every_ms * 1000);
    }
    return NULL;
}

/* A client that sends a byte every 100 ms (each well inside any per-byte timeout) is cut off
 * at the request's deadline, not served for as long as it keeps trickling (#56). */
static void test_trickle(void)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    trickle_t t = { .fd = sv[1], .every_ms = 100 };
    pthread_t th;
    pthread_create(&th, NULL, trickle, &t);
    hg_conn_t c = { 0 };
    hg_set(&c, 500);
    int64_t t0 = hg_now_ms();
    int got = 0, r;
    char b[16];
    while ((r = hg_recv(&c, sv[0], b, sizeof(b), 0)) > 0)
        got += r;
    int64_t took = hg_now_ms() - t0;
    CHECK(r == -1 && c.closed);
    CHECK(took >= 450 && took < 1500);
    CHECK(got >= 3 && got <= 8);
    /* Closed from then on: data waiting is not read */
    usleep(150 * 1000);
    CHECK(hg_recv(&c, sv[0], b, sizeof(b), 0) == -1);
    t.stop = true;
    pthread_join(th, NULL);
    close(sv[0]);
    close(sv[1]);
}

/* A client that connects and sends nothing waits out the deadline at most. */
static void test_silent(void)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    hg_conn_t c = { 0 };
    hg_set(&c, 300);
    char b[4];
    int64_t t0 = hg_now_ms();
    CHECK(hg_recv(&c, sv[0], b, sizeof(b), 0) == -1);
    int64_t took = hg_now_ms() - t0;
    CHECK(took >= 250 && took < 1200);
    close(sv[0]);
    close(sv[1]);
}

/* A client that never reads the reply: the sends stop at the deadline. */
static void test_no_reader(void)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    hg_conn_t c = { 0 };
    hg_set(&c, 300);
    static char buf[64 * 1024];
    int64_t t0 = hg_now_ms();
    long sent = 0;
    int r;
    while ((r = hg_send(&c, sv[0], buf, sizeof(buf), MSG_NOSIGNAL)) > 0)
        sent += r;
    int64_t took = hg_now_ms() - t0;
    CHECK(r == -1 && c.closed && sent > 0);
    CHECK(took >= 250 && took < 1200);
    close(sv[0]);
    close(sv[1]);
}

/* A client in good time gets it all, and the peer closing is 0, not an error. */
static void test_prompt(void)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    CHECK(send(sv[1], "GET / HTTP/1.1\r\n", 16, 0) == 16);
    shutdown(sv[1], SHUT_WR);
    hg_conn_t c = { 0 };
    char b[64];
    int got = 0, r;
    while ((r = hg_recv(&c, sv[0], b + got, sizeof(b) - (size_t)got, 0)) > 0)
        got += r;
    CHECK(r == 0 && got == 16 && !c.closed && !memcmp(b, "GET /", 5));
    CHECK(hg_send(&c, sv[0], "HTTP/1.1 200 OK\r\n", 17, MSG_NOSIGNAL) == 17);
    close(sv[0]);
    close(sv[1]);
}

/* ---- the release gate ---- */

static bool g_locked, g_lock_free, g_worker, g_worker_free;
static uint64_t g_seq;
static int g_takes;

static bool g_take(void)
{
    g_takes++;
    if (!g_lock_free)
        return false;
    g_lock_free = false, g_locked = true;
    return true;
}
static void g_give(void) { g_locked = false, g_lock_free = true; }
static uint64_t g_last(uint8_t kind) { return g_seq; }
static bool g_wtake(void)
{
    if (!g_worker_free)
        return false;
    g_worker_free = false, g_worker = true;
    return true;
}

static void g_reset(uint64_t seq)
{
    g_locked = g_worker = false, g_lock_free = g_worker_free = true, g_seq = seq, g_takes = 0;
}

/* #56: a release takes the update lock and the worker only once its header verified, in that
 * order, and never keeps one when it can't have the other; its seq is checked again under
 * the lock. */
static void test_gate(void)
{
    const hg_locks_t l = { g_take, g_give, g_last, g_wtake };
    g_reset(5);
    CHECK(hg_gate(&l, true, 3, 6) == HG_GO && g_locked && g_worker);
    /* Another push while one holds the lock: refused, holding nothing */
    g_reset(5);
    g_lock_free = false;
    CHECK(hg_gate(&l, true, 3, 6) == HG_BUSY && !g_locked && !g_worker);
    /* The one in flight recorded seq 6 since this header (a replay of it) verified
     * against 5: stale under the lock, which is given back */
    g_reset(6);
    CHECK(hg_gate(&l, true, 3, 6) == HG_STALE && !g_locked && g_lock_free && !g_worker && g_worker_free);
    g_reset(7);
    CHECK(hg_gate(&l, true, 3, 6) == HG_STALE && g_lock_free && g_worker_free);
    /* The worker still taken (the last one draining its reply): the lock is given back */
    g_reset(5);
    g_worker_free = false;
    CHECK(hg_gate(&l, true, 3, 6) == HG_BUSY && !g_locked && g_lock_free);
    /* No lock asked for (a bench build's /bench): the worker only, and no seq */
    g_reset(99);
    CHECK(hg_gate(&l, false, 0, 0) == HG_GO && !g_locked && g_takes == 0 && g_worker);
    g_reset(0);
    g_worker_free = false;
    CHECK(hg_gate(&l, false, 0, 0) == HG_BUSY && !g_locked && g_takes == 0);
}

/* ---- JSON strings ---- */

/* s as /status writes it parses back to s. */
static bool round_trip(const char *s)
{
    char q[512], doc[600];
    snprintf(doc, sizeof(doc), "{\"tz\":%s}", json_q(q, sizeof(q), s));
    cJSON *j = cJSON_Parse(doc);
    const cJSON *v = cJSON_GetObjectItem(j, "tz");
    bool ok = cJSON_IsString(v) && !strcmp(v->valuestring, s);
    cJSON_Delete(j);
    return ok;
}

static bool parses(const char *s, size_t cap)
{
    char q[512], doc[600];
    snprintf(doc, sizeof(doc), "{\"v\":%s}", json_q(q, cap, s));
    cJSON *j = cJSON_Parse(doc);
    bool ok = j && cJSON_IsString(cJSON_GetObjectItem(j, "v"));
    cJSON_Delete(j);
    return ok;
}

/* The interface's MAC as /status writes it: lower case, colons, "" for none, and never
 * written past cap. */
static void test_mac(void)
{
    char m[32];
    const unsigned char a[6] = {0xAA, 0xbb, 0x0c, 0xD0, 0x01, 0xff};
    CHECK(!strcmp(json_mac(m, sizeof(m), a), "aa:bb:0c:d0:01:ff") && strlen(m) == 17);
    const unsigned char z[6] = {0};
    CHECK(!strcmp(json_mac(m, sizeof(m), z), ""));
    CHECK(!strcmp(json_mac(m, sizeof(m), NULL), ""));
    const unsigned char one[6] = {0, 0, 0, 0, 0, 1};
    CHECK(!strcmp(json_mac(m, 18, one), "00:00:00:00:00:01"));
    memset(m, 'x', sizeof(m));
    CHECK(!strcmp(json_mac(m, 17, a), "") && m[1] == 'x');
    /* It is a JSON string's content as it is */
    CHECK(round_trip(json_mac(m, sizeof(m), a)));
    char doc[64];
    snprintf(doc, sizeof(doc), "{\"mac\":\"%s\"}", json_mac(m, sizeof(m), a));
    cJSON *j = cJSON_Parse(doc);
    const cJSON *v = cJSON_GetObjectItem(j, "mac");
    CHECK(cJSON_IsString(v) && !strcmp(v->valuestring, "aa:bb:0c:d0:01:ff"));
    cJSON_Delete(j);
}

static void test_json(void)
{
    char e[64];
    CHECK(json_esc(e, sizeof(e), "EST5EDT,M3.2.0,M11.1.0") == 22 && !strcmp(e, "EST5EDT,M3.2.0,M11.1.0"));
    CHECK(json_esc(e, sizeof(e), "a\"b\\c") == 7 && !strcmp(e, "a\\\"b\\\\c"));
    CHECK(json_esc(e, sizeof(e), "a\nb\tc\x7f") == 21 && !strcmp(e, "a\\u000ab\\u0009c\\u007f"));
    CHECK(json_esc(e, sizeof(e), "\xc3\xa9") == 12 && !strcmp(e, "\\u00c3\\u00a9"));
    CHECK(json_esc(e, sizeof(e), NULL) == 0 && !e[0]);
    /* Cut short between whole escapes, never inside one */
    CHECK(json_esc(e, 4, "ab\"c") == 2 && !strcmp(e, "ab"));
    CHECK(json_esc(e, 5, "ab\"c") == 4 && !strcmp(e, "ab\\\""));
    CHECK(json_esc(e, 8, "a\x01") == 7 && !strcmp(e, "a\\u0001"));
    CHECK(json_esc(e, 7, "a\x01") == 1 && !strcmp(e, "a"));
    CHECK(json_esc(e, 1, "abc") == 0 && !e[0]);

    char q[32];
    CHECK(!strcmp(json_q(q, sizeof(q), NULL), "null"));
    CHECK(!strcmp(json_q(q, sizeof(q), ""), "\"\""));
    CHECK(!strcmp(json_qz(q, sizeof(q), ""), "null"));
    CHECK(!strcmp(json_qz(q, sizeof(q), "x"), "\"x\""));
    CHECK(!strcmp(json_q(q, sizeof(q), "say \"hi\""), "\"say \\\"hi\\\"\""));
    CHECK(!strcmp(json_q(q, 5, "abcdef"), "\"ab\""));

    /* #66: a quote in a time zone, a backslash in an error, a control character, a refused
     * config's own words: each comes back whole, in valid JSON */
    CHECK(round_trip("EST5\"EDT"));
    CHECK(round_trip("C:\\path"));
    CHECK(round_trip("name: \"dns\\a\" can't be used"));
    CHECK(round_trip("line\nbreak\r\t"));
    CHECK(round_trip("}],\"injected\":true,\"x\":[{"));
    /* and cut short, still valid */
    for (size_t cap = 5; cap < 40; cap++)
        CHECK(parses("\"\"\"\\\\\\\x01\x02\x03 \"quoted\" \\", cap));
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    test_host();
    test_budgets();
    test_trickle();
    test_silent();
    test_no_reader();
    test_prompt();
    test_gate();
    test_json();
    test_mac();
    if (s_fail) {
        fprintf(stderr, "%d FAILED\n", s_fail);
        return 1;
    }
    printf("http: all passed\n");
    return 0;
}
