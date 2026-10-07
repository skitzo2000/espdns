#include "cfg.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "config.h"
#include "dns_wire.h"
#include "mbedtls/sha256.h"
#include "qlog.h"
#include "reboot.h"

typedef struct {
    char *err;
    size_t errlen;
    bool failed;
} ctx_t;

static void fail(ctx_t *c, const char *fmt, ...)
{
    if (c->failed)
        return;
    c->failed = true;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->err, c->errlen, fmt, ap);
    va_end(ap);
}

static uint32_t mk_ip(unsigned a, unsigned b, unsigned c, unsigned d)
{
    /* network order in memory: first octet at the lowest address */
    uint8_t q[4] = { (uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d };
    uint32_t v;
    memcpy(&v, q, 4);
    return v;
}

static uint32_t host_order(uint32_t net)
{
    uint8_t q[4];
    memcpy(q, &net, 4);
    return (uint32_t)q[0] << 24 | (uint32_t)q[1] << 16 | (uint32_t)q[2] << 8 | q[3];
}

static uint32_t net_order(uint32_t host) { return mk_ip(host >> 24, host >> 16 & 255, host >> 8 & 255, host & 255); }

bool cfg_parse_ipv4(const char *s, uint32_t *out)
{
    unsigned o[4];
    for (int i = 0; i < 4; i++) {
        if (*s < '0' || *s > '9')
            return false;
        if (*s == '0' && s[1] >= '0' && s[1] <= '9')
            return false; /* leading zero: octal to some parsers */
        unsigned v = 0;
        int digits = 0;
        while (*s >= '0' && *s <= '9' && digits < 4) {
            v = v * 10 + (unsigned)(*s++ - '0');
            digits++;
        }
        if (v > 255 || digits > 3)
            return false;
        o[i] = v;
        if (i < 3 && *s++ != '.')
            return false;
    }
    if (*s)
        return false;
    *out = mk_ip(o[0], o[1], o[2], o[3]);
    return true;
}

/* ---- the firmware and board layers ---- */

/* The built-in address, behind a marker the controller and tools/ota_push.py find in the
 * image (release.BuiltinAddress): a node with no board partition falls back on it when its
 * config is refused or gone, so an image without its address (a build missing the
 * deployment's firmware/local.mk) is refused for such a node before it is pushed. Read
 * through a volatile pointer so the marker is in every image, an empty one too. */
static const char builtin_addr[] = CFG_BUILTIN_ADDR_MARK DNS2_STATIC_IP;
const char *cfg_builtin_addr(void)
{
    const char *volatile p = builtin_addr;
    return p + sizeof(CFG_BUILTIN_ADDR_MARK) - 1;
}

static void defaults(cfg_t *c)
{
    memset(c, 0, sizeof(*c));
    /* No address unless the build gives one: never DHCP from here (config.h). */
    const char *builtin = cfg_builtin_addr();
    if (builtin[0] && cfg_parse_ipv4(builtin, &c->ip)) {
        cfg_parse_ipv4(DNS2_NETMASK, &c->netmask);
        cfg_parse_ipv4(DNS2_GATEWAY, &c->gateway);
        c->addr_from = CFG_ADDR_FIRMWARE;
    }
    for (size_t i = 0; i < DNS2_ARRAY_LEN(DNS2_FORWARDERS) && c->nfwd < CFG_MAX_FWD; i++)
        if (cfg_parse_ipv4(DNS2_FORWARDERS[i], &c->fwd[c->nfwd]))
            c->nfwd++;
    c->upstream_timeout_ms = DNS2_UPSTREAM_TIMEOUT_MS;
    for (size_t i = 0; i < DNS2_ARRAY_LEN(DNS2_FORWARDER_ZONES) && c->nfzones < CFG_MAX_FZONES; i++) {
        cfg_fzone_t *f = &c->fzones[c->nfzones];
        f->zone = DNS2_FORWARDER_ZONES[i].zone;
        if (cfg_parse_ipv4(DNS2_FORWARDER_ZONES[i].forwarder, &f->forwarder))
            c->nfzones++;
    }
    cfg_parse_ipv4(DNS2_PRIMARY, &c->primary);
    for (size_t i = 0; i < DNS2_ARRAY_LEN(DNS2_SECONDARY_ZONES) && c->nzones < CFG_MAX_ZONES; i++)
        if (DNS2_SECONDARY_ZONES[i][0]) /* "": none (config.h) */
            c->zones[c->nzones++] = DNS2_SECONDARY_ZONES[i];
    c->soa_poll_s = DNS2_SOA_POLL_S;
    c->retry_s = DNS2_RETRY_MIN_S;
    c->hosted = DNS2_HOSTED;
    strcpy(c->tz, DNS2_TZ);
    c->blocking = DNS2_BLOCKING;
    c->block_nxdomain = DNS2_BLOCK_NXDOMAIN;
    c->block_ttl = DNS2_BLOCK_TTL;
    c->cpu_dfs = -1; /* the board's, else the image's (cpuplan.h) */
    c->querylog = DNS2_QUERYLOG;
    c->querylog_client = QL_CLIENT_FULL;
}

static void set_net(cfg_t *c, const board_net_t *n, cfg_addr_from_t from)
{
    c->ip = n->ip;
    c->netmask = n->netmask;
    c->gateway = n->gateway;
    c->dhcp = n->dhcp;
    c->addr_from = from;
}

static void board_layer(cfg_t *c, const board_desc_t *b)
{
    if (b && b->wifi_max_tx_dbm)
        c->wifi_tx_dbm = b->wifi_max_tx_dbm;
    if (b && b->net.set)
        set_net(c, &b->net, CFG_ADDR_BOARD);
}

const char *cfg_addr_kind(const cfg_t *c) { return c->ip ? "static" : c->dhcp ? "dhcp" : "none"; }

const char *cfg_addr_from(const cfg_t *c)
{
    static const char *const names[] = { "none", "firmware", "board", "config" };
    return names[c->addr_from];
}

/* ---- the node config ---- */

static const cJSON *member(const cJSON *o, const char *key) { return cJSON_GetObjectItemCaseSensitive(o, key); }

/* Every member of o must be one of keys (NULL-terminated). */
static void only(ctx_t *c, const cJSON *o, const char *where, const char *const *keys)
{
    for (const cJSON *m = o ? o->child : NULL; m; m = m->next) {
        bool known = false;
        for (int i = 0; keys[i] && !known; i++)
            known = strcmp(m->string, keys[i]) == 0;
        if (!known)
            fail(c, "%s%s%s: unknown setting", where, where[0] ? "." : "", m->string);
    }
}

static const cJSON *object(ctx_t *c, const cJSON *o, const char *key)
{
    const cJSON *v = member(o, key);
    if (v && !cJSON_IsObject(v)) {
        fail(c, "%s: not an object", key);
        return NULL;
    }
    return v;
}

static const cJSON *array(ctx_t *c, const cJSON *o, const char *key, int max)
{
    const cJSON *v = member(o, key);
    if (v && (!cJSON_IsArray(v) || cJSON_GetArraySize(v) > max)) {
        fail(c, "%s: a list of at most %d", key, max);
        return NULL;
    }
    return v;
}

/* An integer member in [lo, hi] into *out, if present. */
static void integer(ctx_t *c, const cJSON *o, const char *key, int lo, int hi, int *out)
{
    const cJSON *v = member(o, key);
    if (!v)
        return;
    /* range first: casting a double outside int's range is undefined */
    if (!cJSON_IsNumber(v) || !(v->valuedouble >= lo && v->valuedouble <= hi) ||
        v->valuedouble != (double)(int)v->valuedouble) {
        fail(c, "%s: an integer from %d to %d", key, lo, hi);
        return;
    }
    *out = (int)v->valuedouble;
}

static void boolean(ctx_t *c, const cJSON *o, const char *key, bool *out)
{
    const cJSON *v = member(o, key);
    if (!v)
        return;
    if (!cJSON_IsBool(v)) {
        fail(c, "%s: true or false", key);
        return;
    }
    *out = cJSON_IsTrue(v);
}

/* A string member of up to cap-1 bytes, if present (min: the fewest allowed). */
static const char *string(ctx_t *c, const cJSON *o, const char *key, size_t min, size_t cap)
{
    const cJSON *v = member(o, key);
    if (!v)
        return NULL;
    if (!cJSON_IsString(v) || strlen(v->valuestring) < min || strlen(v->valuestring) >= cap) {
        fail(c, "%s: a string of %u-%u characters", key, (unsigned)min, (unsigned)(cap - 1));
        return NULL;
    }
    return v->valuestring;
}

/* Not 0.0.0.0, the broadcast address, multicast or loopback. */
static bool ipv4_usable(uint32_t net)
{
    uint32_t h = host_order(net);
    return !(h == 0 || h == 0xffffffffu || h >> 28 == 14 || h >> 24 == 127);
}

static bool ipv4_item(ctx_t *c, const cJSON *v, const char *what, uint32_t *out)
{
    if (!cJSON_IsString(v) || !cfg_parse_ipv4(v->valuestring, out)) {
        fail(c, "%s: not an IPv4 address", what);
        return false;
    }
    if (!ipv4_usable(*out)) {
        fail(c, "%s: %s can't be used", what, v->valuestring);
        return false;
    }
    return true;
}

/* A zone name: letters, digits, '-', '_' and dots between labels; stored lowercased, without
 * a trailing dot, in the pool (it also names the zone's file on the SD card). */
static const char *zone_name(ctx_t *c, cfg_t *cf, const cJSON *v, const char *what)
{
    const char *s = cJSON_IsString(v) ? v->valuestring : NULL;
    size_t n = s ? strlen(s) : 0;
    if (n && s[n - 1] == '.')
        n--;
    uint8_t wire[DNS_MAX_NAME];
    bool ok = s && n > 0 && n <= 253 && s[0] != '.';
    for (size_t i = 0; ok && i < n; i++) {
        char ch = s[i];
        ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' ||
             ch == '_' || (ch == '.' && s[i + 1] != '.');
    }
    if (ok) {
        char tmp[256];
        memcpy(tmp, s, n);
        tmp[n] = 0;
        ok = dns_name_from_str(tmp, wire) > 1;
    }
    if (!ok) {
        fail(c, "%s: not a zone name", what);
        return NULL;
    }
    if (cf->pool_used + n + 1 > sizeof(cf->pool)) {
        fail(c, "%s: zone names too long in all", what);
        return NULL;
    }
    char *out = cf->pool + cf->pool_used;
    for (size_t i = 0; i < n; i++)
        out[i] = (char)(s[i] >= 'A' && s[i] <= 'Z' ? s[i] - 'A' + 'a' : s[i]);
    out[n] = 0;
    cf->pool_used += n + 1;
    return out;
}

static bool host_ok(const char *s)
{
    if (!s[0] || s[0] == '.' || s[0] == '-')
        return false;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '-' ||
              *s == '.'))
            return false;
    return true;
}

/* A POSIX TZ string (EST5EDT,M3.2.0,M11.1.0 or <+0530>-5:30), checked for shape: it starts
 * with a zone name, and has only the characters POSIX TZ uses (letters, digits, + - , . / :
 * and < > around a quoted name, not nested). No quote, backslash or space gets into /status
 * or the C library's TZ. */
static bool tz_ok(const char *s)
{
    if (!((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') || s[0] == '<'))
        return false;
    bool quoted = false;
    for (; *s; s++) {
        char ch = *s;
        if (ch == '<' || ch == '>') {
            if (quoted != (ch == '>'))
                return false;
            quoted = !quoted;
        } else if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' ||
                     ch == '-' || ch == ',' || ch == '.' || ch == '/' || ch == ':')) {
            return false;
        }
    }
    return !quoted;
}

bool cfg_parse_net(const char *addr, const char *gw, board_net_t *out, char *err, size_t errlen)
{
    ctx_t ctx = { .err = err, .errlen = errlen }, *c = &ctx;
    memset(out, 0, sizeof(*out));
    if (!addr) {
        if (gw)
            fail(c, "network.gateway: only with a static address");
        return !c->failed;
    }
    if (!strcmp(addr, "dhcp")) {
        if (gw)
            fail(c, "network.gateway: only with a static address");
        out->set = out->dhcp = true;
        return !c->failed;
    }
    char ip[32] = "";
    int prefix = -1;
    if (strlen(addr) < sizeof(ip)) {
        strcpy(ip, addr);
        char *slash = strchr(ip, '/');
        if (slash) {
            *slash = 0;
            char *end = slash + 1;
            prefix = 0;
            for (int d = 0; *end >= '0' && *end <= '9' && d < 3; d++)
                prefix = prefix * 10 + (*end++ - '0');
            if (*end || end == slash + 1)
                prefix = -1;
        }
    }
    uint32_t a, g;
    if (prefix < 8 || prefix > 30 || !cfg_parse_ipv4(ip, &a)) {
        fail(c, "network.address: \"dhcp\", or an address with its prefix length (8-30), as 192.0.2.53/24");
        return false;
    }
    if (!gw) {
        fail(c, "network.gateway: required with a static address");
        return false;
    }
    if (!cfg_parse_ipv4(gw, &g)) {
        fail(c, "network.gateway: not an IPv4 address");
        return false;
    }
    if (!ipv4_usable(g)) {
        fail(c, "network.gateway: %s can't be used", gw);
        return false;
    }
    uint32_t mask = 0xffffffffu << (32 - prefix), ha = host_order(a), hg = host_order(g);
    if ((ha & ~mask) == 0 || (ha & ~mask) == ~mask) {
        fail(c, "network.address: %s is the network's own or broadcast address", ip);
        return false;
    }
    if ((hg & mask) != (ha & mask) || hg == ha) {
        fail(c, "network.gateway: must be another address in the node's network");
        return false;
    }
    out->set = true;
    out->ip = a;
    out->netmask = net_order(mask);
    out->gateway = g;
    return true;
}

static void parse_network(ctx_t *c, cfg_t *cf, const cJSON *net)
{
    static const char *const keys[] = { "address", "gateway", NULL };
    only(c, net, "network", keys);
    const char *addr = string(c, net, "address", 1, 32);
    const cJSON *gw = member(net, "gateway");
    if (c->failed)
        return;
    board_net_t n;
    if (!cfg_parse_net(addr, gw ? (cJSON_IsString(gw) ? gw->valuestring : "") : NULL, &n, c->err, c->errlen)) {
        c->failed = true; /* the reason is in err */
        return;
    }
    if (n.set)
        set_net(cf, &n, CFG_ADDR_CONFIG);
}

static void parse_wifi(ctx_t *c, cfg_t *cf, const cJSON *w)
{
    static const char *const keys[] = { "ssid", "password", "tx_power_dbm", "power_save", NULL };
    only(c, w, "wifi", keys);
    const char *ssid = string(c, w, "ssid", 1, sizeof(cf->wifi_ssid));
    const char *pass = string(c, w, "password", 0, sizeof(cf->wifi_pass));
    if (pass && !ssid)
        fail(c, "wifi.password: only with wifi.ssid");
    if (pass && pass[0] && strlen(pass) < 8)
        fail(c, "wifi.password: at least 8 characters, or empty for an open network");
    if (ssid) {
        strcpy(cf->wifi_ssid, ssid);
        strcpy(cf->wifi_pass, pass ? pass : "");
    }
    integer(c, w, "tx_power_dbm", 2, 20, &cf->wifi_tx_dbm);
    boolean(c, w, "power_save", &cf->wifi_power_save);
}

static void parse_forwarders(ctx_t *c, cfg_t *cf, const cJSON *root)
{
    const cJSON *f = array(c, root, "forwarders", CFG_MAX_FWD);
    if (!f)
        return;
    cf->nfwd = 0; /* [] is none: forwarding off */
    for (const cJSON *v = f->child; v; v = v->next)
        if (ipv4_item(c, v, "forwarders", &cf->fwd[cf->nfwd]))
            cf->nfwd++;
}

static void parse_fzones(ctx_t *c, cfg_t *cf, const cJSON *root)
{
    const cJSON *f = array(c, root, "forward_zones", CFG_MAX_FZONES);
    if (!f)
        return;
    cf->nfzones = 0;
    static const char *const keys[] = { "zone", "forwarder", NULL };
    for (const cJSON *v = f->child; v && !c->failed; v = v->next) {
        if (!cJSON_IsObject(v)) {
            fail(c, "forward_zones: a list of {\"zone\", \"forwarder\"}");
            return;
        }
        only(c, v, "forward_zones[]", keys);
        cfg_fzone_t *z = &cf->fzones[cf->nfzones];
        z->zone = zone_name(c, cf, member(v, "zone"), "forward_zones[].zone");
        if (!member(v, "forwarder"))
            fail(c, "forward_zones[].forwarder: required");
        else if (z->zone && ipv4_item(c, member(v, "forwarder"), "forward_zones[].forwarder", &z->forwarder))
            cf->nfzones++;
    }
}

static void parse_secondary(ctx_t *c, cfg_t *cf, const cJSON *s)
{
    static const char *const keys[] = { "primary", "zones", "soa_poll_s", "retry_s", NULL };
    only(c, s, "secondary", keys);
    const cJSON *p = member(s, "primary");
    if (p)
        ipv4_item(c, p, "secondary.primary", &cf->primary);
    const cJSON *z = array(c, s, "zones", CFG_MAX_ZONES);
    if (z) {
        cf->nzones = 0;
        for (const cJSON *v = z->child; v && !c->failed; v = v->next) {
            const char *n = zone_name(c, cf, v, "secondary.zones");
            if (n)
                cf->zones[cf->nzones++] = n;
        }
    }
    integer(c, s, "soa_poll_s", 10, 86400, &cf->soa_poll_s);
    integer(c, s, "retry_s", 5, 3600, &cf->retry_s);
}

static void parse_hosted(ctx_t *c, cfg_t *cf, const cJSON *h)
{
    static const char *const keys[] = { "enabled", NULL };
    only(c, h, "hosted", keys);
    boolean(c, h, "enabled", &cf->hosted);
}

static void parse_cpu(ctx_t *c, cfg_t *cf, const cJSON *o)
{
    static const char *const keys[] = { "dfs", NULL };
    only(c, o, "cpu", keys);
    bool dfs = false;
    if (member(o, "dfs")) {
        boolean(c, o, "dfs", &dfs);
        cf->cpu_dfs = dfs;
    }
}

static void parse_querylog(ctx_t *c, cfg_t *cf, const cJSON *o)
{
    static const char *const keys[] = { "enabled", "client", NULL };
    only(c, o, "querylog", keys);
    boolean(c, o, "enabled", &cf->querylog);
    const char *m = string(c, o, "client", 1, 16);
    int mode = -1;
    for (int i = 0; m && i < QL_CLIENT_N; i++)
        if (!strcmp(m, ql_client_name(i)))
            mode = i;
    if (m && mode < 0)
        fail(c, "querylog.client: \"full\", \"subnet\" or \"hidden\"");
    else if (m)
        cf->querylog_client = (uint8_t)mode;
}

static void parse_time(ctx_t *c, cfg_t *cf, const cJSON *t)
{
    static const char *const keys[] = { "ntp", "tz", NULL };
    only(c, t, "time", keys);
    const cJSON *n = array(c, t, "ntp", CFG_MAX_NTP);
    if (n) {
        cf->nntp = 0;
        for (const cJSON *v = n->child; v; v = v->next) {
            if (!cJSON_IsString(v) || strlen(v->valuestring) >= CFG_HOST_MAX || !host_ok(v->valuestring)) {
                fail(c, "time.ntp: host names or IPv4 addresses");
                return;
            }
            strcpy(cf->ntp[cf->nntp++], v->valuestring);
        }
    }
    const char *tz = string(c, t, "tz", 1, CFG_TZ_MAX);
    if (tz && !tz_ok(tz))
        fail(c, "time.tz: a POSIX TZ string, as EST5EDT,M3.2.0,M11.1.0");
    else if (tz)
        strcpy(cf->tz, tz);
}

static void parse_blocking(ctx_t *c, cfg_t *cf, const cJSON *b)
{
    static const char *const keys[] = { "enabled", "answer", "ttl", NULL };
    only(c, b, "blocking", keys);
    boolean(c, b, "enabled", &cf->blocking);
    const char *a = string(c, b, "answer", 1, 16);
    if (a && strcmp(a, "null") && strcmp(a, "nxdomain"))
        fail(c, "blocking.answer: \"null\" or \"nxdomain\"");
    else if (a)
        cf->block_nxdomain = !strcmp(a, "nxdomain");
    integer(c, b, "ttl", 0, 86400, &cf->block_ttl);
}

/* Checks across settings, once the layers are in. */
static void check_all(ctx_t *c, const cfg_t *cf)
{
    for (int i = 0; i < cf->nzones; i++)
        for (int j = 0; j < i; j++)
            if (!strcmp(cf->zones[i], cf->zones[j]))
                fail(c, "secondary.zones: %s twice", cf->zones[i]);
    for (int i = 0; i < cf->nfzones; i++) {
        for (int j = 0; j < i; j++)
            if (!strcmp(cf->fzones[i].zone, cf->fzones[j].zone))
                fail(c, "forward_zones: %s twice", cf->fzones[i].zone);
        for (int j = 0; j < cf->nzones; j++)
            if (!strcmp(cf->fzones[i].zone, cf->zones[j]))
                fail(c, "%s: both a secondary zone and a forward zone", cf->zones[j]);
    }
    if (cf->nzones && !cf->primary)
        fail(c, "secondary.primary: required with secondary zones");
    if (cf->ip && (cf->primary == cf->ip))
        fail(c, "secondary.primary: the node's own address");
}

/* At most CFG_MAX_DEPTH nested objects and lists (the format needs 3), checked before
 * cJSON's recursive parser runs on a small task stack. */
#define CFG_MAX_DEPTH 8
static bool depth_ok(const char *s, size_t len)
{
    int depth = 0;
    bool str = false;
    for (size_t i = 0; i < len; i++) {
        char ch = s[i];
        if (str) {
            if (ch == '\\')
                i++;
            else if (ch == '"')
                str = false;
        } else if (ch == '"') {
            str = true;
        } else if (ch == '{' || ch == '[') {
            if (++depth > CFG_MAX_DEPTH)
                return false;
        } else if (ch == '}' || ch == ']') {
            depth--;
        }
    }
    return true;
}

/* The whole payload is one JSON value: nothing but white space after it. */
static cJSON *parse_all(const char *json, size_t len)
{
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(json, len, &end, false);
    while (root && end && end < json + len && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        end++;
    if (root && end != json + len) {
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

bool cfg_build(cfg_t *c, const board_desc_t *b, const char *json, size_t len, char *err, size_t errlen)
{
    defaults(c);
    board_layer(c, b);
    if (errlen)
        err[0] = 0;
    if (!json)
        return true;
    ctx_t x = { .err = err, .errlen = errlen };
    cJSON *root = len <= CFG_JSON_MAX && depth_ok(json, len) ? parse_all(json, len) : NULL;
    if (!cJSON_IsObject(root)) {
        fail(&x, len > CFG_JSON_MAX ? "config too big" : "not a JSON object");
    } else {
        static const char *const keys[] = { "format", "name", "network", "wifi", "forwarders", "upstream_timeout_ms",
                                             "forward_zones", "secondary", "hosted", "time", "blocking", "cpu", "querylog",
                                             NULL };
        only(&x, root, "", keys);
        int format = CFG_FORMAT;
        integer(&x, root, "format", 1, 1000, &format);
        if (format != CFG_FORMAT)
            fail(&x, "format %d: this firmware reads format %d", format, CFG_FORMAT);
        const char *name = string(&x, root, "name", 1, CFG_NAME_MAX);
        for (const char *p = name; p && *p; p++)
            if (*p < ' ' || *p > '~' || *p == '"' || *p == '\\')
                fail(&x, "name: printable ASCII, without quotes or backslashes");
        if (name && !x.failed)
            strcpy(c->name, name);
        const cJSON *o;
        if ((o = object(&x, root, "network")))
            parse_network(&x, c, o);
        if ((o = object(&x, root, "wifi")))
            parse_wifi(&x, c, o);
        parse_forwarders(&x, c, root);
        integer(&x, root, "upstream_timeout_ms", 100, 10000, &c->upstream_timeout_ms);
        parse_fzones(&x, c, root);
        if ((o = object(&x, root, "secondary")))
            parse_secondary(&x, c, o);
        if ((o = object(&x, root, "hosted")))
            parse_hosted(&x, c, o);
        if ((o = object(&x, root, "time")))
            parse_time(&x, c, o);
        if ((o = object(&x, root, "blocking")))
            parse_blocking(&x, c, o);
        if ((o = object(&x, root, "cpu")))
            parse_cpu(&x, c, o);
        if ((o = object(&x, root, "querylog")))
            parse_querylog(&x, c, o);
        if (!x.failed)
            check_all(&x, c);
    }
    cJSON_Delete(root);
    if (x.failed) {
        defaults(c);
        board_layer(c, b);
    }
    return !x.failed;
}

/* ---- comparing ---- */

static bool zones_eq(const cfg_t *a, const cfg_t *b)
{
    if (a->nzones != b->nzones || a->nfzones != b->nfzones || a->primary != b->primary)
        return false;
    for (int i = 0; i < a->nzones; i++)
        if (strcmp(a->zones[i], b->zones[i]))
            return false;
    for (int i = 0; i < a->nfzones; i++)
        if (strcmp(a->fzones[i].zone, b->fzones[i].zone) || a->fzones[i].forwarder != b->fzones[i].forwarder)
            return false;
    return true;
}

uint32_t cfg_reboot_reasons(const cfg_t *a, const cfg_t *b)
{
    uint32_t r = 0;
    if (a->ip != b->ip || a->netmask != b->netmask || a->gateway != b->gateway || a->dhcp != b->dhcp)
        r |= RB_CONFIG_ADDRESS;
    if (strcmp(a->wifi_ssid, b->wifi_ssid) || strcmp(a->wifi_pass, b->wifi_pass))
        r |= RB_CONFIG_WIFI;
    if (!zones_eq(a, b))
        r |= RB_CONFIG_ZONES;
    return r;
}

bool cfg_net_changed(const cfg_t *a, const cfg_t *b)
{
    return (cfg_reboot_reasons(a, b) & (RB_CONFIG_ADDRESS | RB_CONFIG_WIFI)) != 0;
}

bool cfg_needs_reboot(const cfg_t *a, const cfg_t *b) { return cfg_reboot_reasons(a, b) != 0; }

void cfg_copy_live(cfg_t *dst, const cfg_t *src)
{
    memcpy(dst->name, src->name, sizeof(dst->name));
    /* The address applies live only when it is the same, but a config that spells it out
     * now owns it (adopt keeps the address a node has): say so in /status. */
    if (dst->ip == src->ip && dst->netmask == src->netmask && dst->gateway == src->gateway && dst->dhcp == src->dhcp)
        dst->addr_from = src->addr_from;
    dst->wifi_tx_dbm = src->wifi_tx_dbm;
    dst->wifi_power_save = src->wifi_power_save;
    memcpy(dst->fwd, src->fwd, sizeof(dst->fwd));
    dst->nfwd = src->nfwd;
    dst->upstream_timeout_ms = src->upstream_timeout_ms;
    dst->soa_poll_s = src->soa_poll_s;
    dst->retry_s = src->retry_s;
    dst->hosted = src->hosted;
    memcpy(dst->ntp, src->ntp, sizeof(dst->ntp));
    dst->nntp = src->nntp;
    memcpy(dst->tz, src->tz, sizeof(dst->tz));
    dst->blocking = src->blocking;
    dst->block_nxdomain = src->block_nxdomain;
    dst->block_ttl = src->block_ttl;
    dst->cpu_dfs = src->cpu_dfs;
    dst->querylog = src->querylog;
    dst->querylog_client = src->querylog_client;
}

/* ---- slots ---- */

const char *cfg_slot_check(const uint8_t hdr[REL_HEADER_LEN], const uint8_t *payload, size_t avail,
                           const rel_trust_t *t, rel_manifest_t *m)
{
    const char *why = rel_verify(hdr, t, 0, UINT64_MAX, m);
    if (why)
        return why;
    if (m->kind != REL_CONFIG)
        return "not a config release";
    if (memcmp(m->target, t->node_id, 6) != 0)
        return "a config is for one node, not any node"; /* its address would be every node's */
    if (m->payload_len == 0 || m->payload_len > avail)
        return "payload length out of range";
    uint8_t sha[32];
    mbedtls_sha256(payload, (size_t)m->payload_len, sha, 0);
    if (memcmp(sha, m->sha256, 32) != 0)
        return "payload does not match the signed hash";
    return NULL;
}

int cfg_slot_pick(const bool ok[2], const uint64_t seq[2], uint64_t bad_seq, int *other)
{
    bool use[2];
    for (int i = 0; i < 2; i++)
        use[i] = ok[i] && !(bad_seq && seq[i] == bad_seq);
    int first = use[0] && use[1] ? (seq[1] > seq[0] ? 1 : 0) : use[0] ? 0 : use[1] ? 1 : -1;
    *other = first >= 0 && use[1 - first] ? 1 - first : -1;
    return first;
}

void cfg_ntp_slots(const cfg_t *c, uint32_t gateway, int max, char slots[][CFG_HOST_MAX], bool *dhcp)
{
    if (max > CFG_MAX_NTP)
        max = CFG_MAX_NTP;
    for (int i = 0; i < max; i++)
        slots[i][0] = 0;
    *dhcp = false;
    if (c->nntp) {
        for (int i = 0; i < c->nntp && i < max; i++)
            strcpy(slots[i], c->ntp[i]);
        return;
    }
    *dhcp = c->dhcp && !c->ip && max > 1;
    int n = *dhcp ? 1 : 0;
    if (gateway && n < max) {
        const uint8_t *g = (const uint8_t *)&gateway;
        snprintf(slots[n++], CFG_HOST_MAX, "%u.%u.%u.%u", g[0], g[1], g[2], g[3]);
    }
    if (n < max)
        strcpy(slots[n], DNS2_NTP_FALLBACK);
}
