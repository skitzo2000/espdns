#include "board_def.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "cfg.h"
#include "cpuplan.h"

#define MAX_GPIO 54 /* the highest GPIO on any supported chip (ESP32-P4); per-chip rules are the builder's */

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

/* An integer member, or def if absent; a non-integer is an error. */
static int num(ctx_t *c, const cJSON *o, const char *key, int def)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!v)
        return def;
    if (!cJSON_IsNumber(v) || v->valuedouble != (double)(int)v->valuedouble) {
        fail(c, "%s: not an integer", key);
        return def;
    }
    return (int)v->valuedouble;
}

static int pin(ctx_t *c, const cJSON *o, const char *key)
{
    int p = num(c, o, key, BOARD_NC);
    if (p != BOARD_NC && (p < 0 || p > MAX_GPIO))
        fail(c, "%s: GPIO %d out of range", key, p);
    return p;
}

static bool flag(ctx_t *c, const cJSON *o, const char *key)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (v && !cJSON_IsBool(v))
        fail(c, "%s: not true or false", key);
    return v && cJSON_IsTrue(v);
}

/* A string member, one of names[]; returns its index, or def if absent. */
static int choice(ctx_t *c, const cJSON *o, const char *key, const char *const *names, int n, int def)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!v)
        return def;
    if (cJSON_IsString(v))
        for (int i = 0; i < n; i++)
            if (strcmp(v->valuestring, names[i]) == 0)
                return i;
    fail(c, "%s: unknown value", key);
    return def;
}

static void str(ctx_t *c, const cJSON *o, const char *key, char *out, size_t cap, bool required)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!v) {
        if (required)
            fail(c, "%s: missing", key);
        return;
    }
    if (!cJSON_IsString(v) || !v->valuestring[0] || strlen(v->valuestring) >= cap) {
        fail(c, "%s: must be a string of 1-%u characters", key, (unsigned)(cap - 1));
        return;
    }
    strcpy(out, v->valuestring);
}

static bool bus_defined(const board_desc_t *b, int bus)
{
    for (int i = 0; i < 2; i++)
        if (b->spi[i].bus && b->spi[i].bus == bus)
            return true;
    return false;
}

/* Every pin may be used by one thing only (an SPI bus's pins once, for all its devices). */
static void check_pins(ctx_t *c, const board_desc_t *b)
{
    struct {
        const char *what;
        int pin;
    } use[32];
    int n = 0;
#define USE(w, p) \
    do { if ((p) != BOARD_NC && n < 32) { use[n].what = (w); use[n].pin = (p); n++; } } while (0)
    for (int i = 0; i < 2; i++)
        if (b->spi[i].bus) {
            USE("spi sclk", b->spi[i].sclk);
            USE("spi mosi", b->spi[i].mosi);
            USE("spi miso", b->spi[i].miso);
        }
    if (b->eth.kind == BOARD_ETH_EMAC) {
        USE("ethernet phy reset", b->eth.phy_reset);
        USE("ethernet power", b->eth.power_pin);
        USE("ethernet mdc", b->eth.mdc);
        USE("ethernet mdio", b->eth.mdio);
        USE("ethernet rmii clock", b->eth.rmii_clock_gpio);
    } else if (b->eth.kind == BOARD_ETH_W5500) {
        USE("ethernet cs", b->eth.cs);
        USE("ethernet int", b->eth.irq);
        USE("ethernet rst", b->eth.reset);
    }
    if (b->sd.kind == BOARD_SD_SPI)
        USE("sd cs", b->sd.cs);
    if (b->led.kind != BOARD_LED_NONE)
        USE("led", b->led.pin);
#undef USE
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (use[i].pin == use[j].pin)
                fail(c, "GPIO %d used twice: %s and %s", use[i].pin, use[i].what, use[j].what);
}

bool board_def_parse(const char *json, size_t len, board_desc_t *out, char *err, size_t errlen)
{
    ctx_t c = { .err = err, .errlen = errlen };
    memset(out, 0, sizeof(*out));
    if (errlen)
        err[0] = 0;
    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!cJSON_IsObject(root)) {
        fail(&c, "not a JSON object");
        cJSON_Delete(root);
        return false;
    }
    str(&c, root, "name", out->name, sizeof(out->name), true);
    str(&c, root, "image", out->image, sizeof(out->image), true);

    const cJSON *spi = cJSON_GetObjectItemCaseSensitive(root, "spi");
    if (spi && (!cJSON_IsArray(spi) || cJSON_GetArraySize(spi) > 2))
        fail(&c, "spi: a list of at most 2 buses");
    for (int i = 0; spi && i < cJSON_GetArraySize(spi) && i < 2; i++) {
        const cJSON *s = cJSON_GetArrayItem(spi, i);
        board_spi_bus_t *b = &out->spi[i];
        b->bus = num(&c, s, "host", 0);
        if (b->bus != 2 && b->bus != 3)
            fail(&c, "spi host: 2 or 3");
        if (i == 1 && b->bus == out->spi[0].bus)
            fail(&c, "spi host %d defined twice", b->bus);
        b->sclk = pin(&c, s, "sclk");
        b->mosi = pin(&c, s, "mosi");
        b->miso = pin(&c, s, "miso");
        if (b->sclk == BOARD_NC || b->mosi == BOARD_NC || b->miso == BOARD_NC)
            fail(&c, "spi host %d: sclk, mosi and miso are required", b->bus);
    }

    static const char *const eth_kinds[] = { "none", "emac", "w5500" };
    static const char *const phys[] = { "ip101", "lan87xx", "rtl8201", "dp83848" };
    static const char *const clocks[] = { "default", "in", "out" };
    const cJSON *e = cJSON_GetObjectItemCaseSensitive(root, "ethernet");
    out->eth.kind = e ? choice(&c, e, "kind", eth_kinds, 3, BOARD_ETH_NONE) : BOARD_ETH_NONE;
    out->eth.optional = e && flag(&c, e, "optional");
    if (out->eth.kind == BOARD_ETH_EMAC) {
        out->eth.phy = choice(&c, e, "phy", phys, 4, BOARD_PHY_IP101);
        out->eth.phy_addr = num(&c, e, "addr", 1);
        out->eth.phy_reset = pin(&c, e, "reset");
        out->eth.power_pin = pin(&c, e, "power");
        out->eth.mdc = pin(&c, e, "mdc");
        out->eth.mdio = pin(&c, e, "mdio");
        const cJSON *clk = cJSON_GetObjectItemCaseSensitive(e, "rmii_clock");
        out->eth.rmii_clock = clk ? choice(&c, clk, "mode", clocks, 3, BOARD_CLK_DEFAULT) : BOARD_CLK_DEFAULT;
        out->eth.rmii_clock_gpio = clk ? pin(&c, clk, "gpio") : BOARD_NC;
        if (out->eth.rmii_clock != BOARD_CLK_DEFAULT && out->eth.rmii_clock_gpio == BOARD_NC)
            fail(&c, "ethernet rmii_clock: gpio is required with a mode");
        if (out->eth.phy_addr < -1 || out->eth.phy_addr > 31)
            fail(&c, "ethernet addr: 0-31, or -1 to search");
    } else if (out->eth.kind == BOARD_ETH_W5500) {
        out->eth.spi_bus = num(&c, e, "spi_host", 0);
        out->eth.cs = pin(&c, e, "cs");
        out->eth.irq = pin(&c, e, "int");
        out->eth.reset = pin(&c, e, "rst");
        out->eth.clock_mhz = num(&c, e, "mhz", 20);
        if (!bus_defined(out, out->eth.spi_bus))
            fail(&c, "ethernet spi_host %d: no such SPI bus on this board", out->eth.spi_bus);
        if (out->eth.cs == BOARD_NC)
            fail(&c, "ethernet cs: required");
        if (out->eth.clock_mhz < 1 || out->eth.clock_mhz > 80)
            fail(&c, "ethernet mhz: 1-80");
    }

    static const char *const sd_kinds[] = { "none", "sdmmc", "spi" };
    const cJSON *sd = cJSON_GetObjectItemCaseSensitive(root, "sd");
    out->sd.kind = sd ? choice(&c, sd, "kind", sd_kinds, 3, BOARD_SD_NONE) : BOARD_SD_NONE;
    out->sd.ldo = BOARD_NC;
    if (out->sd.kind == BOARD_SD_SDMMC) {
        out->sd.slot = num(&c, sd, "slot", 0);
        out->sd.width = num(&c, sd, "width", 4);
        out->sd.ldo = num(&c, sd, "ldo", BOARD_NC);
        if (out->sd.width != 1 && out->sd.width != 4)
            fail(&c, "sd width: 1 or 4");
    } else if (out->sd.kind == BOARD_SD_SPI) {
        out->sd.spi_bus = num(&c, sd, "spi_host", 0);
        out->sd.cs = pin(&c, sd, "cs");
        if (!bus_defined(out, out->sd.spi_bus))
            fail(&c, "sd spi_host %d: no such SPI bus on this board", out->sd.spi_bus);
        if (out->sd.cs == BOARD_NC)
            fail(&c, "sd cs: required");
    }

    static const char *const led_kinds[] = { "none", "gpio", "ws2812" };
    const cJSON *led = cJSON_GetObjectItemCaseSensitive(root, "led");
    out->led.kind = led ? choice(&c, led, "kind", led_kinds, 3, BOARD_LED_NONE) : BOARD_LED_NONE;
    out->led.pin = led ? pin(&c, led, "pin") : BOARD_NC;
    out->led.active_low = led && flag(&c, led, "active_low");
    if (out->led.kind != BOARD_LED_NONE && out->led.pin == BOARD_NC)
        fail(&c, "led pin: required");

    const cJSON *wifi = cJSON_GetObjectItemCaseSensitive(root, "wifi");
    out->wifi_max_tx_dbm = wifi ? num(&c, wifi, "tx_power_dbm", 0) : 0;
    if (out->wifi_max_tx_dbm && (out->wifi_max_tx_dbm < 2 || out->wifi_max_tx_dbm > 20))
        fail(&c, "wifi tx_power_dbm: 2-20, or 0 for the chip's default");

    out->psram_mb = num(&c, root, "psram_mb", -1);
    if (out->psram_mb != -1 && (out->psram_mb < 0 || out->psram_mb > BOARD_PSRAM_MB_MAX))
        fail(&c, "psram_mb: 0-%d", BOARD_PSRAM_MB_MAX);

    /* The memory plan's values (memplan.h): each one left out is the chip image's default. */
    const cJSON *mem = cJSON_GetObjectItemCaseSensitive(root, "memory");
    if (mem && !cJSON_IsObject(mem))
        fail(&c, "memory: an object");
    static const struct {
        const char *key;
        size_t off;
        int min, max;
    } MEM[] = {
        { "internal_kb", offsetof(board_desc_t, mem.internal_kb), BOARD_MEM_KB_MIN, BOARD_MEM_KB_MAX },
        { "cache_kb", offsetof(board_desc_t, mem.cache_kb), BOARD_MEM_KB_MIN, BOARD_MEM_KB_MAX },
        { "cache_entries", offsetof(board_desc_t, mem.cache_entries), BOARD_CACHE_ENTRIES_MIN,
          BOARD_CACHE_ENTRIES_MAX },
        { "blocklist_kb", offsetof(board_desc_t, mem.blocklist_kb), BOARD_MEM_KB_MIN, BOARD_MEM_KB_MAX },
        { "blocklist_index_kb", offsetof(board_desc_t, mem.blocklist_index_kb), 0, BOARD_MEM_KB_MAX },
        { "hosted_zones_kb", offsetof(board_desc_t, mem.hosted_zones_kb), BOARD_MEM_KB_MIN, BOARD_MEM_KB_MAX },
        { "secondary_zones_kb", offsetof(board_desc_t, mem.secondary_zones_kb), BOARD_MEM_KB_MIN,
          BOARD_MEM_KB_MAX },
        { "querylog_kb", offsetof(board_desc_t, mem.querylog_kb), 0, BOARD_MEM_KB_MAX },
        { "fwd_pending", offsetof(board_desc_t, mem.fwd_pending), BOARD_FWD_PENDING_MIN, BOARD_FWD_PENDING_MAX },
    };
    for (size_t i = 0; i < sizeof(MEM) / sizeof(MEM[0]); i++) {
        int *v = (int *)((char *)out + MEM[i].off);
        *v = cJSON_IsObject(mem) ? num(&c, mem, MEM[i].key, -1) : -1;
        if (*v != -1 && (*v < MEM[i].min || *v > MEM[i].max))
            fail(&c, "memory %s: %d-%d, or leave it out for the firmware's default", MEM[i].key, MEM[i].min,
                 MEM[i].max);
    }

    /* The CPU clock plan's values (cpuplan.h): each one left out is the chip image's default. */
    const cJSON *cpu = cJSON_GetObjectItemCaseSensitive(root, "cpu");
    out->cpu.dfs = out->cpu.min_mhz = -1;
    if (cpu && !cJSON_IsObject(cpu)) {
        fail(&c, "cpu: an object");
    } else if (cpu) {
        if (cJSON_GetObjectItemCaseSensitive(cpu, "dfs"))
            out->cpu.dfs = flag(&c, cpu, "dfs");
        out->cpu.min_mhz = num(&c, cpu, "min_mhz", -1);
        if (out->cpu.min_mhz != -1 && !cp_min_ok(out->image, out->cpu.min_mhz)) {
            const cp_image_t *im = cp_image(out->image);
            char mins[32] = "";
            for (int i = 0; im && im->mins[i]; i++)
                snprintf(mins + strlen(mins), sizeof(mins) - strlen(mins), "%s%d", i ? ", " : "", im->mins[i]);
            fail(&c, "cpu min_mhz: %s on %s, or leave it out for the image's %d", mins, out->image,
                 im ? im->min_mhz : 0);
        }
    }

    const cJSON *net = cJSON_GetObjectItemCaseSensitive(root, "network");
    if (net && !cJSON_IsObject(net)) {
        fail(&c, "network: an object");
    } else if (net && !c.failed) {
        const cJSON *a = cJSON_GetObjectItemCaseSensitive(net, "address");
        const cJSON *g = cJSON_GetObjectItemCaseSensitive(net, "gateway");
        for (const cJSON *m = net->child; m; m = m->next)
            if (strcmp(m->string, "address") && strcmp(m->string, "gateway"))
                fail(&c, "network.%s: unknown setting", m->string);
        if (!a)
            fail(&c, "network.address: required");
        else if (!c.failed && !cfg_parse_net(cJSON_IsString(a) ? a->valuestring : "",
                                             g ? (cJSON_IsString(g) ? g->valuestring : "") : NULL, &out->net, err,
                                             errlen))
            c.failed = true; /* the reason is in err */
    }

    if (!c.failed)
        check_pins(&c, out);
    cJSON_Delete(root);
    return !c.failed;
}

uint32_t board_crc32(const uint8_t *p, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

static uint32_t rd32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

bool board_part_open(const uint8_t *part, size_t size, const char **json, size_t *len, const char **err)
{
    if (size < BOARD_PART_HDR || memcmp(part, BOARD_PART_MAGIC, 4) != 0) {
        *err = "no board definition";
        return false;
    }
    if ((part[4] | part[5] << 8) != BOARD_PART_VER) {
        *err = "board definition in an unknown format version";
        return false;
    }
    uint32_t n = rd32(part + 8);
    if (n == 0 || n > size - BOARD_PART_HDR) {
        *err = "board definition length out of range";
        return false;
    }
    if (board_crc32(part + BOARD_PART_HDR, n) != rd32(part + 12)) {
        *err = "board definition fails its CRC";
        return false;
    }
    *json = (const char *)part + BOARD_PART_HDR;
    *len = n;
    return true;
}
