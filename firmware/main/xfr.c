#include "xfr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axfr.h"
#include "config.h"
#include "dns_wire.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "net.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "power.h"
#include "registry.h"
#include "settings.h"
#include "share.h"
#include "supervisor.h"

static const char *TAG = "xfr";
static SemaphoreHandle_t s_wake;
static svc_state_t s_state = SVC_STARTING; /* with zones: until the task starts */
static bool s_start_failed;                 /* its task or buffers couldn't be made */
/* A transfer's message and decompressed rdata, from the service's share (memplan.h), taken
 * when it starts: only the zone task transfers. */
static uint8_t *s_msg, *s_rdata;
static int s_watch = -1;

/* The zones' share: memory.secondary_zones_kb, for every zone and a new copy during a
 * transfer (memplan.h). */
static size_t zones_budget(void) { return (size_t)share_board()->secondary_zones_kb * 1024; }

/* What the zones other than slot skip take (skip -1: all of them). Only the zone task swaps
 * them after boot, so it reads them without the lock. */
static size_t zones_mem(int skip)
{
    size_t n = 0;
    for (int i = 0; i < reg_nslots(); i++)
        if (i != skip)
            n += zone_mem(reg_slot(i)->z);
    return n;
}

static int64_t now_ms(void) { return esp_timer_get_time() / 1000; }

/* A zone check (the SOA, then a transfer) ends well within the task's check-in. */
_Static_assert(AXFR_SOA_TIMEOUT_MS + AXFR_DEADLINE_MS < SUP_TASK_MS / 2,
               "a zone check must end within half the zone task's check-in");

static void kick(void *ctx)
{
    (void)ctx;
    supervisor_kick(s_watch);
}

static void zone_path(const zslot_t *s, char *out, size_t n)
{
    snprintf(out, n, "%s/%s.zone", DNS2_ZONE_DIR, s->name);
}

void xfr_load_saved(void)
{
    char path[160];
    int64_t now = now_ms();
    for (int i = 0; i < reg_nslots(); i++) {
        zslot_t *s = reg_slot(i);
        zone_path(s, path, sizeof(path));
        /* Within what the zones' share has left (a transfer later needs room for a new copy
         * next to it). */
        size_t held = zones_mem(-1), budget = zones_budget();
        zone_t *z = zone_load(path, s->apex, s->apex_len, budget > held ? budget - held : 0);
        if (z) {
            reg_swap(i, z);
            /* No wall clock yet: count EXPIRE from boot. */
            s->last_ok_ms = now;
            ESP_LOGI(TAG, "%s: loaded from SD, serial %lu, %u records", s->name,
                     (unsigned long)z->serial, (unsigned)z->n);
        } else {
            ESP_LOGW(TAG, "%s: no saved copy that fits the zones' memory (memory.secondary_zones_kb, %u KB)", s->name,
                     (unsigned)(budget / 1024));
        }
    }
}

void xfr_notify(int slot)
{
    reg_slot(slot)->notify = true;
    if (s_wake)
        xSemaphoreGive(s_wake);
}

static void refresh_slot(uint32_t primary, int i)
{
    zslot_t *s = reg_slot(i);
    int64_t now = now_ms();
    zone_t *cur = s->z; /* only this task swaps, so reading without the lock is safe */
    uint32_t serial;

    if (!axfr_soa_serial(primary, 53, s->apex, s->apex_len, AXFR_SOA_TIMEOUT_MS, &serial)) {
        s->fails++;
        uint32_t poll = (uint32_t)settings()->soa_poll_s, min = (uint32_t)settings()->retry_s;
        uint32_t retry = cur ? cur->retry : min;
        if (retry > poll)
            retry = poll;
        if (retry < min)
            retry = min;
        s->next_check_ms = now + (int64_t)retry * 1000;
        ESP_LOGW(TAG, "%s: SOA check failed (%lu in a row)", s->name, (unsigned long)s->fails);
        return;
    }

    if (!cur || serial_newer(serial, cur->serial)) {
        int64_t t0 = now_ms();
        /* The transfer's parse and the save at the full clock (power.h). */
        power_hold(POWER_WORK);
        /* The new copy is built next to the one in use: both within the share. */
        size_t others = zones_mem(i) + zone_mem(cur), budget = zones_budget();
        axfr_opts_t o = { .msg = s_msg, .rdata = s_rdata, .limit = budget > others ? budget - others : 0,
                          .deadline_ms = AXFR_DEADLINE_MS, .progress = kick };
        axfr_err_t err;
        zone_t *nz = axfr_pull(primary, 53, s->apex, s->apex_len, &o, &err);
        if (!nz) {
            power_release(POWER_WORK);
            s->fails++;
            s->next_check_ms = now + (int64_t)settings()->retry_s * 1000;
            if (err == AXFR_TOO_BIG)
                ESP_LOGE(TAG, "%s: AXFR failed: the zone takes more than the %u KB left of the zones' memory "
                              "(memory.secondary_zones_kb)", s->name, (unsigned)(o.limit / 1024));
            else
                ESP_LOGW(TAG, "%s: AXFR failed: %s", s->name, axfr_err_str(err));
            return;
        }
        char path[160];
        zone_path(s, path, sizeof(path));
        bool saved = zone_save(nz, path);
        power_release(POWER_WORK);
        ESP_LOGI(TAG, "%s: transferred serial %lu (%u records) in %lld ms%s", s->name,
                 (unsigned long)nz->serial, (unsigned)nz->n, now_ms() - t0,
                 saved ? ", saved" : ", NOT saved to SD");
        zone_free(reg_swap(i, nz));
        s->transfers++;
        cur = nz;
    }
    s->fails = 0;
    s->last_ok_ms = now;
    uint32_t poll = (uint32_t)settings()->soa_poll_s;
    uint32_t every = cur->refresh < poll ? cur->refresh : poll;
    s->next_check_ms = now + (int64_t)(every ? every : poll) * 1000;
}

/* Link came up: check every zone now rather than waiting out the retry timers. */
static void on_link_up(void)
{
    for (int i = 0; i < reg_nslots(); i++)
        reg_slot(i)->next_check_ms = 0;
    if (s_wake)
        xSemaphoreGive(s_wake);
}

static void xfr_task(void *arg)
{
    uint32_t primary = settings()->primary; /* changes only with a reboot */
    for (;;) {
        supervisor_kick(s_watch);
        int64_t now = now_ms();
        bool link = net_link_up();
        /* Asleep until the next thing due: a zone's check, a zone expiring, or the check-in
         * at half its deadline (sup.h). A NOTIFY or the link coming up wakes it sooner. */
        int64_t next = now + SUP_TASK_MS / 2;
        for (int i = 0; i < reg_nslots(); i++) {
            zslot_t *s = reg_slot(i);
            /* Without a link a check can only fail; EXPIRE below still runs. */
            if (link && (s->notify || now >= s->next_check_ms)) {
                s->notify = false;
                refresh_slot(primary, i);
                supervisor_kick(s_watch);
            }
            bool exp = s->z && now - s->last_ok_ms > (int64_t)s->z->expire * 1000;
            if (exp != s->expired) {
                reg_wrlock();
                s->expired = exp;
                reg_unlock();
                ESP_LOGW(TAG, "%s: %s", s->name, exp ? "EXPIRED, answering SERVFAIL" : "no longer expired");
            }
            /* Without a link no check is due: the link coming up wakes the task. */
            if (link && s->next_check_ms < next)
                next = s->next_check_ms;
            int64_t expires = s->z && !exp ? s->last_ok_ms + (int64_t)s->z->expire * 1000 + 1 : INT64_MAX;
            if (expires < next)
                next = expires;
        }
        /* A tick more: a wait of n ticks may end up to one early, and a look a moment
         * before the time due would find nothing due and look again at once, until it is. */
        int64_t wait = next - now_ms();
        xSemaphoreTake(s_wake, wait > 0 ? pdMS_TO_TICKS(wait) + 1 : 0);
    }
}

void xfr_start(void)
{
    /* No secondary zones: no task, no SOA polling, no link watch (NOTIFY: server.c). */
    if (!reg_nslots()) {
        ESP_LOGI(TAG, "no secondary zones: off");
        return;
    }
    if (s_state == SVC_RUNNING)
        return;
    /* Also the supervisor's restart after a failed start: what was made then is kept. */
    if (!s_wake && (s_wake = xSemaphoreCreateBinary()))
        net_on_link_up(on_link_up);
    mp_pool_t pool = mp_data_pool(share_board());
    if (!s_msg)
        s_msg = share_alloc(SVC_SECONDARY, pool, 65535);
    if (!s_rdata)
        s_rdata = share_alloc(SVC_SECONDARY, pool, 65535);
    if (s_watch < 0)
        s_watch = supervisor_watch(SVC_SECONDARY, SUP_TASK, SUP_TASK_MS);
    if (!s_wake || !s_msg || !s_rdata || xTaskCreate(xfr_task, "xfr", MP_XFR_STACK, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "zone task failed to start: zones are not refreshed");
        supervisor_unwatch(s_watch);
        s_watch = -1;
        s_state = SVC_FAILED;
        s_start_failed = true;
        return;
    }
    share_note(SVC_SECONDARY, MP_INTERNAL, MP_XFR_STACK);
    s_start_failed = false;
    s_state = SVC_RUNNING;
}

svc_state_t xfr_state(void) { return reg_nslots() ? s_state : SVC_OFF; }

bool xfr_broken(void) { return reg_nslots() && s_start_failed; }

size_t xfr_held(void)
{
    reg_rdlock();
    size_t n = zones_mem(-1);
    reg_unlock();
    return n + share_used(SVC_SECONDARY, MP_INTERNAL) + share_used(SVC_SECONDARY, MP_PSRAM);
}
