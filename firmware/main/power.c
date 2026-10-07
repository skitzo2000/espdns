#include "power.h"

#include <stdio.h>

#include "board.h"
#include "cpuplan.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "jsonw.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "net.h"
#include "sdkconfig.h"
#include "settings.h"
#if CONFIG_PM_ENABLE
#include "esp_pm.h"
#define PM_BUILT "true"
#else
#define PM_BUILT "false"
#endif

static const char *TAG = "pm";

typedef struct {
    const char *name;
#if CONFIG_PM_ENABLE
    esp_pm_lock_handle_t lock; /* ESP_PM_CPU_FREQ_MAX */
#endif
    int holders;      /* under s_mux, as are the counts below */
    int64_t since_us; /* when the first holder took it */
    int64_t busy_us;  /* held by anyone, in all */
    uint32_t holds;
} hold_t;

static hold_t s_hold[POWER_NHOLDS] = { [POWER_DNS] = { .name = "dns" }, [POWER_WORK] = { .name = "work" } };
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static cp_board_t s_cp;
static SemaphoreHandle_t s_cfg_lock; /* power_start against power_apply (an early config release) */
static bool s_started, s_dfs;
static const char *s_err; /* the last configuration failed: why */

void power_init(void)
{
    s_cfg_lock = xSemaphoreCreateMutex();
#if CONFIG_PM_ENABLE
    for (int i = 0; i < POWER_NHOLDS; i++)
        if (esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, s_hold[i].name, &s_hold[i].lock) != ESP_OK)
            ESP_LOGE(TAG, "%s: no lock: its work may run at the idle clock", s_hold[i].name);
#endif
}

void power_hold(power_hold_t k)
{
    hold_t *h = &s_hold[k];
#if CONFIG_PM_ENABLE
    if (h->lock)
        esp_pm_lock_acquire(h->lock);
#endif
    int64_t now = esp_timer_get_time();
    taskENTER_CRITICAL(&s_mux);
    if (h->holders++ == 0)
        h->since_us = now;
    h->holds++;
    taskEXIT_CRITICAL(&s_mux);
}

void power_release(power_hold_t k)
{
    hold_t *h = &s_hold[k];
    int64_t now = esp_timer_get_time();
    taskENTER_CRITICAL(&s_mux);
    if (h->holders > 0 && --h->holders == 0)
        h->busy_us += now - h->since_us;
    taskEXIT_CRITICAL(&s_mux);
#if CONFIG_PM_ENABLE
    if (h->lock)
        esp_pm_lock_release(h->lock);
#endif
}

/* The source of the DFS setting, for /status. */
static const char *dfs_from(void)
{
    return settings()->cpu_dfs >= 0 ? "config" : s_cp.dfs_board ? "board" : "image";
}

static void configure(void)
{
    bool dfs = cp_dfs(&s_cp, settings()->cpu_dfs);
#if CONFIG_PM_ENABLE
    esp_pm_config_t c = { .max_freq_mhz = s_cp.max_mhz, .min_freq_mhz = dfs ? s_cp.min_mhz : s_cp.max_mhz,
                          .light_sleep_enable = false };
    esp_err_t err = esp_pm_configure(&c);
    if (err != ESP_OK) {
        /* The image's table is wrong for this chip: it keeps running as it was. */
        s_err = esp_err_to_name(err);
        ESP_LOGE(TAG, "clock scaling %u-%u MHz refused: %s", (unsigned)c.min_freq_mhz, (unsigned)c.max_freq_mhz,
                 s_err);
        return;
    }
    s_err = NULL;
#else
    if (dfs)
        ESP_LOGW(TAG, "this image is built without power management: no clock scaling");
    dfs = false;
#endif
    if (dfs != s_dfs || !s_started)
        ESP_LOGI(TAG, "clock scaling %s (%s): %d MHz, idle %d MHz", dfs ? "on" : "off", dfs_from(), s_cp.max_mhz,
                 dfs ? s_cp.min_mhz : s_cp.max_mhz);
    s_dfs = dfs;
}

void power_start(void)
{
    cp_board(&board, board_image(), &s_cp);
    /* The image's clock as built: the table's is for the controller and the tests. */
    if (s_cp.max_mhz != CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ) {
        ESP_LOGE(TAG, "the clock plan says %d MHz, the image runs %d: no clock scaling", s_cp.max_mhz,
                 CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);
        s_cp.max_mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
        s_cp.min_mhz = 0;
    }
    /* Under the lock with s_started: a config applied while this runs (the HTTP server is
     * up before it) is either seen by configure() here or configures after it. */
    xSemaphoreTake(s_cfg_lock, portMAX_DELAY);
    configure();
    s_started = true;
    xSemaphoreGive(s_cfg_lock);
}

void power_apply(void)
{
    xSemaphoreTake(s_cfg_lock, portMAX_DELAY);
    if (s_started)
        configure();
    xSemaphoreGive(s_cfg_lock);
}

/* A driver holds the APB clock at its maximum: the built-in MAC while it runs, Wi-Fi while
 * its radio is awake (always, with power saving off). The node then idles at the APB
 * floor (cpuplan.h). */
static bool apb_held(void)
{
    return (net_kind() == NET_ETHERNET && board.eth.kind == BOARD_ETH_EMAC) ||
           (net_kind() == NET_WIFI && !settings()->wifi_power_save);
}

size_t power_status_json(char *j, size_t cap)
{
    if (!cap)
        return 0;
    char e[96];
    hold_t h[POWER_NHOLDS];
    int64_t now = esp_timer_get_time();
    taskENTER_CRITICAL(&s_mux);
    for (int i = 0; i < POWER_NHOLDS; i++) {
        h[i] = s_hold[i];
        if (h[i].holders)
            h[i].busy_us += now - h[i].since_us;
    }
    taskEXIT_CRITICAL(&s_mux);
    int max = s_cp.max_mhz ? s_cp.max_mhz : CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
    int n = snprintf(j, cap,
                     "\"cpu\":{\"pm\":" PM_BUILT ",\"dfs\":%s,\"from\":\"%s\",\"max_mhz\":%d,\"min_mhz\":%d,\"idle_mhz\":%d,"
                     "\"error\":%s,\"dns\":{\"holds\":%lu,\"busy_ms\":%llu},\"work\":{\"holds\":%lu,\"busy_ms\":%llu}}",
                     s_dfs ? "true" : "false", s_started ? dfs_from() : "boot",
                     max, s_dfs ? s_cp.min_mhz : max, s_started ? cp_idle_mhz(&s_cp, s_dfs, apb_held()) : max,
                     json_q(e, sizeof(e), s_err), (unsigned long)h[POWER_DNS].holds,
                     (unsigned long long)(h[POWER_DNS].busy_us / 1000), (unsigned long)h[POWER_WORK].holds,
                     (unsigned long long)(h[POWER_WORK].busy_us / 1000));
    return n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap - 1;
}

void power_info(power_info_t *p)
{
    int64_t now = esp_timer_get_time();
    taskENTER_CRITICAL(&s_mux);
    for (int i = 0; i < POWER_NHOLDS; i++) {
        hold_t h = s_hold[i];
        if (h.holders)
            h.busy_us += now - h.since_us;
        p->holds[i] = h.holds;
        p->busy_us[i] = (uint64_t)h.busy_us;
    }
    taskEXIT_CRITICAL(&s_mux);
    int max = s_cp.max_mhz ? s_cp.max_mhz : CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
    p->dfs = s_dfs;
    p->max_mhz = max;
    p->idle_mhz = s_started ? cp_idle_mhz(&s_cp, s_dfs, apb_held()) : max;
}
