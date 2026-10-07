#include "health_node.h"

#include <string.h>

#include "blocking.h"
#include "board.h"
#include "boot.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hosted.h"
#include "led.h"
#include "net.h"
#include "ota.h"
#include "registry.h"
#include "sd.h"
#include "server.h"
#include "settings.h"
#include "supervisor.h"
#include "svc.h"

static const char *TAG = "health";

#define IDENTIFY_MAX_S 3600
#define TICK_MS        500 /* how often the state is looked at; the LED wakes for its own edges */

static TaskHandle_t s_task;
static bool s_led;
static volatile uint32_t s_ident_until; /* ms since boot; 0: not identifying */

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

health_t health_now(void)
{
    health_in_t in = { 0 };
    in.enabled = svc_enabled(settings());
    in.uptime_ms = now_ms();
    in.listen_failed = server_failed();
    in.stalled = supervisor_stalled();
    in.listening = server_running();
    in.answered = boot_ms() != 0;
    in.link = net_link_up();
    in.address = net_ip() != 0;
    in.updating = ota_busy();
    in.board_missing = !strcmp(board_source(), "none");
    in.sd_slot = board.sd.kind != BOARD_SD_NONE;
    sd_state_t sd = sd_state();
    in.sd_mounted = sd == SD_MOUNTED;
    in.sd_pending = sd == SD_PENDING && !sd_timed_out();
    in.blocking = blocking_degraded();
    reg_rdlock();
    for (int i = 0; i < reg_nslots(); i++) {
        const zslot_t *z = reg_slot(i);
        in.zones_expired += z->expired;
        in.zones_failing += z->fails >= HEALTH_ZONE_FAILS;
    }
    reg_unlock();
    server_upstream(&in.fwd);
    in.fwd_stalled = supervisor_fwd_stalled();
    in.heap_free = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    in.config_error = settings_error() != NULL;
    in.config_trial = settings_on_trial();
    in.hosted = hosted_degraded();
    in.reboot_pending = ota_reboot_reasons() != 0;
    in.svc_failed = supervisor_failed();
    in.svc_restarting = supervisor_restarting();
    in.older = (blocking_older() ? SVC_BIT(SVC_BLOCKING) : 0) | (hosted_older() ? SVC_BIT(SVC_HOSTED) : 0);
    return health_compute(&in);
}

static void monitor_task(void *arg)
{
    health_t last = { HEALTH_NSTATES, 0 };
    const led_pattern_t *pat = NULL;
    uint32_t t0 = 0;
    int lit = -1;
    for (;;) {
        uint32_t now = now_ms();
        health_t h = health_now();
        if (h.state != last.state || h.reasons != last.reasons) {
            char j[512];
            health_json(&h, j, sizeof(j));
            if (h.state == HEALTH_HEALTHY || h.state == HEALTH_BOOTING || h.state == HEALTH_UPDATING)
                ESP_LOGI(TAG, "%s", j);
            else
                ESP_LOGW(TAG, "%s", j);
            last = h;
        }
        uint32_t wait = TICK_MS;
        uint32_t until = s_ident_until;
        bool ident = until && (int32_t)(until - now) > 0;
        /* Only the identify that ran out: a new one sent meanwhile stays. */
        if (until && !ident &&
            __atomic_compare_exchange_n(&s_ident_until, &until, 0, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            ESP_LOGI(TAG, "identify over");
        if (s_led) {
            const led_pattern_t *p = led_pattern(h.state, ident);
            if (p != pat) { /* a new pattern starts at its beginning */
                pat = p;
                t0 = now;
                lit = -1;
            }
            bool on = led_pattern_on(p, now - t0);
            if ((int)on != lit) {
                led_set(on, p->r, p->g, p->b);
                lit = on;
            }
            uint32_t next = led_pattern_next(p, now - t0);
            if (next < wait)
                wait = next;
        }
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(wait ? wait : 1));
    }
}

void health_start(void)
{
    s_led = led_init();
    /* Above the blocking load (2), below DNS (5+): the LED keeps its rhythm while a list loads. */
    if (xTaskCreate(monitor_task, "health", 4096, NULL, 3, &s_task) != pdPASS)
        ESP_LOGE(TAG, "monitor failed to start: no LED, no state log");
}

bool health_identify(uint32_t secs)
{
    if (secs > IDENTIFY_MAX_S)
        secs = IDENTIFY_MAX_S;
    s_ident_until = secs ? now_ms() + secs * 1000 : 0;
    if (secs)
        ESP_LOGW(TAG, "IDENTIFY for %lu s", (unsigned long)secs);
    else
        ESP_LOGI(TAG, "identify stopped");
    if (s_task)
        xTaskNotifyGive(s_task);
    return s_led;
}

uint32_t health_identify_left(void)
{
    uint32_t until = s_ident_until, now = now_ms();
    return until && (int32_t)(until - now) > 0 ? (until - now + 999) / 1000 : 0;
}
