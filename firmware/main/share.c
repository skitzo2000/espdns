#include "share.h"

#include "board.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "sdkconfig.h"
#if CONFIG_SPIRAM
#include "esp_psram.h"
#endif
#include "svc.h"

static const char *TAG = "share";

static mp_board_t s_board;
static mp_plan_t s_plan;
static size_t s_used[SVC_N][MP_NPOOLS];

/* Ahead of each block: what it is counted against. 8 bytes, so the block stays 8-aligned. */
typedef struct {
    uint32_t size;
    uint8_t svc, pool, pad[2];
} hdr_t;

void share_init(void)
{
    /* The chip's PSRAM: what was found at boot, a fact of the hardware (not free memory). */
    int chip_kb = 0;
#if CONFIG_SPIRAM
    if (esp_psram_is_initialized())
        chip_kb = (int)(esp_psram_get_size() / 1024);
#endif
    mp_board(&board, board_image(), chip_kb, &s_board);
    ESP_LOGI(TAG,
             "board: %lu KB PSRAM, %lu KB internal for the services; cache %lu KB / %lu answers, lists %lu KB "
             "(indexes %lu KB internal), hosted zones %lu KB, secondary zones %lu KB, %lu upstream queries",
             (unsigned long)s_board.psram_kb, (unsigned long)s_board.internal_kb, (unsigned long)s_board.cache_kb,
             (unsigned long)s_board.cache_entries, (unsigned long)s_board.blocklist_kb,
             (unsigned long)s_board.blocklist_index_kb, (unsigned long)s_board.hosted_zones_kb,
             (unsigned long)s_board.secondary_zones_kb, (unsigned long)s_board.fwd_pending);
    if (board.psram_mb >= 0 && (uint32_t)board.psram_mb * 1024 > s_board.psram_kb)
        ESP_LOGE(TAG, "the board has %d MB of PSRAM, the chip found %lu KB: planning with what was found",
                 board.psram_mb, (unsigned long)s_board.psram_kb);
}

const mp_board_t *share_board(void) { return &s_board; }

bool share_check(const cfg_t *c, char *err, size_t errlen)
{
    mp_plan_t p;
    return mp_plan(&s_board, svc_enabled(c), &p, err, errlen);
}

void share_set_plan(uint32_t enabled)
{
    char err[96];
    if (!mp_plan(&s_board, enabled, &s_plan, err, sizeof(err)))
        ESP_LOGE(TAG, "memory plan: %s", err);
    ESP_LOGI(TAG, "plan: %u of %u KB internal, %u of %u KB PSRAM", (unsigned)(s_plan.total[MP_INTERNAL] / 1024),
             (unsigned)(s_plan.capacity[MP_INTERNAL] / 1024), (unsigned)(s_plan.total[MP_PSRAM] / 1024),
             (unsigned)(s_plan.capacity[MP_PSRAM] / 1024));
}

const mp_plan_t *share_plan(void) { return &s_plan; }

static uint32_t caps(mp_pool_t pool)
{
    return (pool == MP_PSRAM ? MALLOC_CAP_SPIRAM : MALLOC_CAP_INTERNAL) | MALLOC_CAP_8BIT;
}

void *share_alloc(int svc, mp_pool_t pool, size_t n)
{
    if ((unsigned)svc >= SVC_N || (unsigned)pool >= MP_NPOOLS || n > UINT32_MAX - sizeof(hdr_t))
        return NULL;
    hdr_t *h = heap_caps_aligned_alloc(8, sizeof(hdr_t) + n, caps(pool));
    if (!h)
        return NULL;
    *h = (hdr_t){ .size = (uint32_t)n, .svc = (uint8_t)svc, .pool = (uint8_t)pool };
    __atomic_add_fetch(&s_used[svc][pool], n, __ATOMIC_RELAXED);
    return h + 1;
}

void share_free(void *p)
{
    if (!p)
        return;
    hdr_t *h = (hdr_t *)p - 1;
    __atomic_sub_fetch(&s_used[h->svc][h->pool], h->size, __ATOMIC_RELAXED);
    heap_caps_free(h);
}

void share_note(int svc, mp_pool_t pool, long n)
{
    if ((unsigned)svc < SVC_N && (unsigned)pool < MP_NPOOLS)
        __atomic_add_fetch(&s_used[svc][pool], (size_t)n, __ATOMIC_RELAXED);
}

size_t share_used(int svc, mp_pool_t pool)
{
    return (unsigned)svc < SVC_N && (unsigned)pool < MP_NPOOLS ? __atomic_load_n(&s_used[svc][pool], __ATOMIC_RELAXED)
                                                                : 0;
}

size_t share_status_json(char *j, size_t cap) { return mp_json(&s_board, &s_plan, j, cap); }
