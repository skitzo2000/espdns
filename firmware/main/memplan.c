#include "memplan.h"

#include <stdio.h>
#include <string.h>

/* Each chip image's defaults, for a board definition that leaves a key out: today's sizes
 * on the production boards (the P4's 4 MB cache and 20 MB for the lists; on the S3-ETH's
 * 8 MB a 3 MB cache, which holds its 8192 answers at over 300 bytes each, next to 2 MB of
 * lists, about what its free PSRAM gave them before the plan; 128 KB less since, for the
 * forward loop's TCP buffer), first guesses elsewhere,
 * all to be set from measurements. With PSRAM; a board without it gets NO_PSRAM. hosted_zones_kb is 64 for
 * every image, as before the plan (a board says more). */
typedef struct {
    const char *image;
    uint32_t internal_kb, cache_kb, cache_entries, blocklist_kb, blocklist_index_kb, secondary_zones_kb, querylog_kb,
        fwd_pending;
} defaults_t;

/* The query log's ring (querylog_kb, 160 bytes a query): 1 MB on the P4 (6553 queries), 64 KB
 * on the S3's 8 MB (409), about what its PSRAM has left next to the other services' shares;
 * first guesses elsewhere. The outstanding upstream queries (fwd_pending): 32 with PSRAM, so
 * a forward zone whose forwarder is dead holds at most 16 and the default forwarders keep 16
 * (flight.h); 8 without. */
static const defaults_t DEFAULTS[] = {
    { "esp32p4-rev1", 320, 4096, 8192, 20480, 160, 1024, 1024, 32 },
    { "esp32p4", 320, 4096, 8192, 20480, 160, 1024, 1024, 32 },
    { "esp32s3-octal", 160, 2944, 8192, 2048, 0, 256, 64, 32 },
    { "esp32s3-quad", 160, 1024, 2048, 512, 0, 128, 32, 32 },
    { "esp32", 96, 1024, 2048, 512, 0, 128, 32, 32 },
    { "esp32c3", 128, 64, 512, 128, 0, 64, 16, 32 },
    { "esp32c6", 160, 64, 512, 128, 0, 64, 16, 32 },
};
/* An image not listed above. */
static const defaults_t OTHER = { "", 96, 64, 512, 128, 0, 64, 16, 32 };
/* Any image on a board without PSRAM: a small cache, blocking from SD (the SD tier), no
 * query log, 8 outstanding upstream queries. */
static const defaults_t NO_PSRAM = { "", 0, 64, 512, 128, 0, 64, 0, 8 };
#define HOSTED_ZONES_KB 64

static uint32_t pick(int board_value, uint32_t def) { return board_value >= 0 ? (uint32_t)board_value : def; }

void mp_board(const board_desc_t *b, const char *image, int chip_psram_kb, mp_board_t *out)
{
    const defaults_t *d = &OTHER;
    for (size_t i = 0; i < sizeof(DEFAULTS) / sizeof(DEFAULTS[0]); i++)
        if (image && !strcmp(image, DEFAULTS[i].image))
            d = &DEFAULTS[i];
    memset(out, 0, sizeof(*out));
    /* The board says what is fitted; the chip, what it found (a PSRAM that failed its test
     * isn't there to plan with). */
    int psram = b && b->psram_mb >= 0 ? b->psram_mb * 1024 : chip_psram_kb;
    if (psram < 0)
        psram = 0;
    if (chip_psram_kb >= 0 && psram > chip_psram_kb)
        psram = chip_psram_kb;
    out->psram_kb = (uint32_t)psram;
    out->internal_kb = pick(b ? b->mem.internal_kb : -1, d->internal_kb);
    const defaults_t *s = psram ? d : &NO_PSRAM;
    out->cache_kb = pick(b ? b->mem.cache_kb : -1, s->cache_kb);
    out->cache_entries = pick(b ? b->mem.cache_entries : -1, s->cache_entries);
    out->blocklist_kb = pick(b ? b->mem.blocklist_kb : -1, s->blocklist_kb);
    out->blocklist_index_kb = pick(b ? b->mem.blocklist_index_kb : -1, s->blocklist_index_kb);
    out->hosted_zones_kb = pick(b ? b->mem.hosted_zones_kb : -1, HOSTED_ZONES_KB);
    out->secondary_zones_kb = pick(b ? b->mem.secondary_zones_kb : -1, s->secondary_zones_kb);
    out->querylog_kb = pick(b ? b->mem.querylog_kb : -1, s->querylog_kb);
    out->fwd_pending = pick(b ? b->mem.fwd_pending : -1, s->fwd_pending);
}

static const char *const POOL_NAME[MP_NPOOLS] = { "internal RAM", "PSRAM" };

bool mp_plan(const mp_board_t *b, uint32_t enabled, mp_plan_t *p, char *err, size_t errlen)
{
    memset(p, 0, sizeof(*p));
    if (errlen)
        err[0] = 0;
    p->capacity[MP_INTERNAL] = (size_t)b->internal_kb * 1024;
    p->capacity[MP_PSRAM] = b->psram_kb > MP_PSRAM_SYSTEM_KB ? (size_t)(b->psram_kb - MP_PSRAM_SYSTEM_KB) * 1024 : 0;
    mp_pool_t data = mp_data_pool(b);
    enabled |= SVC_BIT(SVC_DNS); /* always */

    p->share[SVC_DNS][MP_INTERNAL] =
        (MP_UDP_WORKERS + MP_TCP_WORKERS) * (size_t)MP_WORKER_STACK + 2 * MP_LISTENER_STACK + 2 * MP_FWD_STACK;
    p->share[SVC_DNS][data] += (size_t)b->cache_kb * 1024 +
                               MP_UDP_WORKERS * (size_t)(MP_UDP_OUT + MP_SCRATCH + MP_BUILDER) +
                               MP_TCP_WORKERS * (size_t)(MP_TCP_MSG + MP_TCP_MSG + 2 + MP_SCRATCH + MP_BUILDER) +
                               MP_UDP_ITEMS * (size_t)MP_UDP_ITEM + (size_t)b->fwd_pending * MP_FWD_SLOT +
                               MP_FWD_TCP;
    if (enabled & SVC_BIT(SVC_SECONDARY)) {
        p->share[SVC_SECONDARY][MP_INTERNAL] += MP_XFR_STACK;
        p->share[SVC_SECONDARY][data] += (size_t)b->secondary_zones_kb * 1024 + MP_XFR_BUFFERS;
    }
    if (enabled & SVC_BIT(SVC_HOSTED)) {
        p->share[SVC_HOSTED][MP_INTERNAL] += MP_HOSTED_STACK;
        p->share[SVC_HOSTED][data] += 3 * (size_t)b->hosted_zones_kb * 1024;
    }
    if (enabled & SVC_BIT(SVC_BLOCKING)) {
        p->share[SVC_BLOCKING][MP_INTERNAL] += MP_BLOCKING_STACK + (size_t)b->blocklist_index_kb * 1024;
        p->share[SVC_BLOCKING][data] += (size_t)b->blocklist_kb * 1024 + MP_BLOCKING_IO;
    }
    if (enabled & SVC_BIT(SVC_QUERYLOG))
        p->share[SVC_QUERYLOG][data] += (size_t)b->querylog_kb * 1024;
    for (int s = 0; s < SVC_N; s++)
        for (int k = 0; k < MP_NPOOLS; k++)
            p->total[k] += p->share[s][k];
    size_t cache_min = MP_CACHE_FIXED + (size_t)b->cache_entries * MP_CACHE_ENTRY;
    if ((size_t)b->cache_kb * 1024 < cache_min) {
        snprintf(err, errlen, "cache: %u answers need at least %u KB, memory.cache_kb is %u",
                 (unsigned)b->cache_entries, (unsigned)((cache_min + 1023) / 1024), (unsigned)b->cache_kb);
        return false;
    }
    for (int k = 0; k < MP_NPOOLS; k++)
        if (p->total[k] > p->capacity[k]) {
            snprintf(err, errlen, "%s: the services need %u KB, the board has %u KB for them", POOL_NAME[k],
                     (unsigned)((p->total[k] + 1023) / 1024), (unsigned)(p->capacity[k] / 1024));
            return false;
        }
    return true;
}

size_t mp_share(const mp_plan_t *p, int svc)
{
    return (unsigned)svc < SVC_N ? p->share[svc][MP_INTERNAL] + p->share[svc][MP_PSRAM] : 0;
}

size_t mp_json(const mp_board_t *b, const mp_plan_t *p, char *j, size_t cap)
{
    if (!cap)
        return 0;
    int n = snprintf(j, cap,
                     "\"memory\":{\"board\":{\"psram_kb\":%lu,\"internal_kb\":%lu,\"cache_kb\":%lu,"
                     "\"cache_entries\":%lu,\"blocklist_kb\":%lu,\"blocklist_index_kb\":%lu,"
                     "\"hosted_zones_kb\":%lu,\"secondary_zones_kb\":%lu,\"querylog_kb\":%lu,\"fwd_pending\":%lu},"
                     "\"internal\":{\"capacity\":%lu,\"planned\":%lu},\"psram\":{\"capacity\":%lu,\"planned\":%lu}}",
                     (unsigned long)b->psram_kb, (unsigned long)b->internal_kb, (unsigned long)b->cache_kb,
                     (unsigned long)b->cache_entries, (unsigned long)b->blocklist_kb,
                     (unsigned long)b->blocklist_index_kb, (unsigned long)b->hosted_zones_kb,
                     (unsigned long)b->secondary_zones_kb, (unsigned long)b->querylog_kb,
                     (unsigned long)b->fwd_pending,
                     (unsigned long)p->capacity[MP_INTERNAL],
                     (unsigned long)p->total[MP_INTERNAL], (unsigned long)p->capacity[MP_PSRAM],
                     (unsigned long)p->total[MP_PSRAM]);
    return n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap - 1;
}
