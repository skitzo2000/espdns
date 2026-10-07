#include "supervisor.h"

#include <stdint.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "ota.h"
#include "services.h"
#include "settings.h"
#include "svc.h"

static const char *TAG = "supervisor";

#define WATCH_MAX  16
#define TICK_MS    1000
#define STACK      4096 /* NVS writes and logging */
#define PRIORITY   8 /* above the DNS tasks (5-7): it runs while they are busy */
#define STATE_NS   "espdns"
#define KEY_STALLS "stalls"

/* The services it restarts: the optional ones with a task of their own. */
static const int RESTARTABLE[] = { SVC_SECONDARY, SVC_HOSTED, SVC_BLOCKING };

static sup_watch_t s_w[WATCH_MAX];
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static sup_svc_t s_svc[SVC_N];
static volatile uint32_t s_failed, s_restarting;
static volatile bool s_stalled;
static volatile bool s_fwd_stalled;
static volatile bool s_restart_busy; /* a restart is running in its own task */
static uint32_t s_stalls;            /* stall reboots in a row, kept in NVS */
static bool s_wdt;                   /* watched by the task watchdog */

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

int supervisor_watch(int svc, sup_role_t role, uint32_t deadline_ms)
{
    int h = -1;
    taskENTER_CRITICAL(&s_mux);
    for (int i = 0; i < WATCH_MAX && h < 0; i++)
        if (!s_w[i].on) {
            s_w[i] = (sup_watch_t){ .on = true, .role = (uint8_t)role, .svc = (int8_t)svc,
                                    .deadline_ms = deadline_ms, .kick_ms = now_ms() };
            h = i;
        }
    taskEXIT_CRITICAL(&s_mux);
    if (h < 0)
        ESP_LOGE(TAG, "watch table full: a %s task isn't watched", svc_name(svc));
    return h;
}

void supervisor_kick(int h)
{
    if (h >= 0 && h < WATCH_MAX) {
        s_w[h].kick_ms = now_ms();
        /* After the time, which the look reads after this: it never sees the task unparked
         * with an old time. */
        __atomic_store_n(&s_w[h].parked, false, __ATOMIC_RELEASE);
    }
}

void supervisor_park(int h)
{
    if (h >= 0 && h < WATCH_MAX)
        s_w[h].parked = true;
}

void supervisor_unwatch(int h)
{
    if (h >= 0 && h < WATCH_MAX)
        s_w[h].on = false;
}

uint32_t supervisor_failed(void) { return s_failed; }
uint32_t supervisor_restarting(void) { return s_restarting; }
bool supervisor_stalled(void) { return s_stalled; }
bool supervisor_fwd_stalled(void) { return s_fwd_stalled; }

static uint32_t stalls_load(void)
{
    uint32_t v = 0;
    nvs_handle_t h;
    if (nvs_open(STATE_NS, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u32(h, KEY_STALLS, &v);
        nvs_close(h);
    }
    return v;
}

static void stalls_save(uint32_t v)
{
    nvs_handle_t h;
    if (nvs_open(STATE_NS, NVS_READWRITE, &h) != ESP_OK)
        return;
    if (nvs_set_u32(h, KEY_STALLS, v) == ESP_OK)
        nvs_commit(h);
    nvs_close(h);
}

static void watchdog_on(bool on)
{
    if (on && !s_wdt)
        s_wdt = esp_task_wdt_add(NULL) == ESP_OK;
    else if (!on && s_wdt && esp_task_wdt_delete(NULL) == ESP_OK)
        s_wdt = false;
}

/* The listeners stopped checking in: the node isn't answering, so a reboot loses nothing,
 * unless it has rebooted for this too often in a row: then it stays up in fault for the
 * controller. */
static void on_stall(void)
{
    uint32_t c = s_stalls;
    if (sup_stall_reboot(&c)) {
        stalls_save(c);
        ESP_LOGE(TAG, "the DNS listeners stalled: rebooting (%lu in a row; after %d the node stays up)",
                 (unsigned long)c, SUP_STALL_REBOOTS);
        ota_reboot_after(0);
        return;
    }
    s_stalled = true;
    watchdog_on(false); /* no more reboots from the hardware watchdog either */
    ESP_LOGE(TAG, "the DNS listeners stalled again after %lu reboots in a row: staying up in fault",
             (unsigned long)s_stalls);
}

static void restart_task(void *arg)
{
    int svc = (int)(intptr_t)arg;
    ESP_LOGW(TAG, "%s: starting it again", svc_name(svc));
    services_restart(svc);
    s_restart_busy = false;
    vTaskDelete(NULL);
}

static void supervisor_task(void *arg)
{
    uint32_t last_failed = 0, last_late = 0;
    bool rebooting = false;
    for (;;) {
        if (s_wdt)
            esp_task_wdt_reset();
        uint32_t now = now_ms();
        sup_watch_t w[WATCH_MAX];
        taskENTER_CRITICAL(&s_mux);
        for (int i = 0; i < WATCH_MAX; i++) {
            /* parked before the time (supervisor_kick stores them the other way round): a
             * worker that takes a query while this copies is never seen unparked with the
             * time it parked at, hours ago on an idle node, which would read as late. */
            bool parked = __atomic_load_n(&s_w[i].parked, __ATOMIC_ACQUIRE);
            w[i] = s_w[i];
            w[i].parked = parked;
        }
        taskEXIT_CRITICAL(&s_mux);
        bool stalled;
        uint32_t late = sup_late(w, WATCH_MAX, now, &stalled);
        if (stalled && !s_stalled && !rebooting) {
            on_stall();
            rebooting = !s_stalled;
        } else if (!stalled && s_stalled) {
            s_stalled = false;
            ESP_LOGW(TAG, "the DNS listeners are back");
        }
        /* Up long enough with the listeners working: the stall reboots start over. */
        if (s_stalls && !stalled && sup_stall_settled(now)) {
            s_stalls = 0;
            stalls_save(0);
            watchdog_on(true);
        }
        if (late != last_late)
            for (int s = 0; s < SVC_N; s++)
                if ((late ^ last_late) & SVC_BIT(s))
                    ESP_LOGW(TAG, "%s: a task %s", svc_name(s), late & SVC_BIT(s) ? "missed its watchdog" : "is back");
        last_late = late;
        bool fwd = sup_forwarder_late(w, WATCH_MAX, now);
        if (fwd != s_fwd_stalled)
            ESP_LOGW(TAG, "the forward loop %s", fwd ? "missed its watchdog" : "is back");
        s_fwd_stalled = fwd;

        /* A late DNS task that isn't a stall (one worker busy) is the listeners' business. */
        uint32_t enabled = svc_enabled(settings()), failed = late & ~SVC_BIT(SVC_DNS) & enabled, restarting = 0;
        for (size_t i = 0; i < sizeof(RESTARTABLE) / sizeof(RESTARTABLE[0]); i++) {
            int s = RESTARTABLE[i];
            if (!(enabled & SVC_BIT(s))) {
                s_svc[s] = (sup_svc_t){ 0 };
                continue;
            }
            if (!s_restart_busy && sup_svc_tick(&s_svc[s], services_broken(s), now)) {
                s_restart_busy = true;
                if (xTaskCreate(restart_task, "restart", 4096, (void *)(intptr_t)s, 4, NULL) != pdPASS)
                    s_restart_busy = false; /* the next look counts it as failing again */
            }
            if (sup_svc_failed(&s_svc[s]))
                failed |= SVC_BIT(s);
            else if (sup_svc_restarting(&s_svc[s]))
                restarting |= SVC_BIT(s);
        }
        if (failed & ~last_failed)
            for (int s = 0; s < SVC_N; s++)
                if (failed & ~last_failed & SVC_BIT(s))
                    ESP_LOGE(TAG, "%s: failed (%lu in a row)", svc_name(s), (unsigned long)s_svc[s].fails);
        last_failed = failed;
        s_failed = failed;
        s_restarting = restarting;
        vTaskDelay(pdMS_TO_TICKS(TICK_MS));
    }
}

void supervisor_start(void)
{
    /* A reset by the hardware watchdog is the supervisor itself having stalled: a stall reboot. */
    uint32_t was = stalls_load();
    s_stalls = sup_stall_boot(was, esp_reset_reason() == ESP_RST_TASK_WDT);
    if (s_stalls != was)
        stalls_save(s_stalls);
    if (s_stalls)
        ESP_LOGW(TAG, "%lu stall reboots in a row before this boot", (unsigned long)s_stalls);
    TaskHandle_t t;
    if (xTaskCreate(supervisor_task, "supervisor", STACK, NULL, PRIORITY, &t) != pdPASS) {
        ESP_LOGE(TAG, "failed to start: no restarts, no stall reboots");
        return;
    }
    /* Watched in hardware while it may still reboot for a stall. */
    if (s_stalls < SUP_STALL_REBOOTS && esp_task_wdt_add(t) == ESP_OK)
        s_wdt = true;
}
