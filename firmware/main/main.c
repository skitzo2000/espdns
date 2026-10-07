/*
 * dns2 — secondary DNS for the home network on a Guition JC-ESP32P4-M3-DEV.
 *
 * Boot: SD mount in parallel with the settings and the network link → saved and hosted zones, if the card mounted within its
 * timeout (answers are possible before the primary is reachable) → DNS listeners → zone
 * refresh against the primary, and blocking. The LED shows the node's health throughout.
 * Each optional service starts only if the node config enables it (svc.h): its start does
 * nothing otherwise.
 */
#include <arpa/inet.h>

#include "blocking.h"
#include "board.h"
#include "boot.h"
#include "clock.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "health_node.h"
#include "hosted.h"
#include "improv.h"
#include "net.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "ota.h"
#include "power.h"
#include "querylog.h"
#include "registry.h"
#include "sd.h"
#include "server.h"
#include "services.h"
#include "settings.h"
#include "share.h"
#include "supervisor.h"
#include "xfr.h"

static const char *TAG = "dns2";

static void log_status(void)
{
    server_stats_t st;
    server_get_stats(&st);
    ESP_LOGI(TAG, "up %llds | q %lu (udp %lu tcp %lu) auth %lu fwd %lu cache-hit %lu nx %lu servfail %lu refused %lu notify %lu drop %lu | heap %u psram %u",
             esp_timer_get_time() / 1000000, (unsigned long)st.queries, (unsigned long)st.udp,
             (unsigned long)st.tcp, (unsigned long)st.auth, (unsigned long)st.forwarded,
             (unsigned long)st.cache_hits, (unsigned long)st.nxdomain, (unsigned long)st.servfail,
             (unsigned long)st.refused, (unsigned long)st.notifies, (unsigned long)st.dropped,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    if (net_kind() == NET_WIFI) {
        net_wifi_stats_t ws;
        net_wifi_stats(&ws);
        ESP_LOGI(TAG, "  wifi %d dBm, ap " MACSTR " ch %u, connects %lu drops %lu failed %lu, last join %lu ms, last error %s",
                 net_wifi_rssi(), MAC2STR(ws.bssid), ws.channel, (unsigned long)ws.connects, (unsigned long)ws.drops,
                 (unsigned long)ws.failed_attempts, (unsigned long)ws.last_join_ms,
                 net_wifi_reason(net_wifi_last_reason()));
    }
    for (int i = 0; i < reg_nslots(); i++) {
        zslot_t *s = reg_slot(i);
        ESP_LOGI(TAG, "  %-26s serial %-10lu records %-5u xfers %lu fails %lu%s", s->name,
                 s->z ? (unsigned long)s->z->serial : 0UL, s->z ? (unsigned)s->z->n : 0U,
                 (unsigned long)s->transfers, (unsigned long)s->fails, s->expired ? " EXPIRED" : "");
    }
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    power_init();       /* the clock holds (power.h); no scaling until the listeners are open */
    board_load();
    share_init();    /* the memory plan's board values, for the config check below */
    sd_start();      /* mounts while the settings load and the network comes up */
    settings_load(); /* node config over the board and firmware defaults; before anything uses it */
    services_init();

    reg_init();
    health_start(); /* the LED shows booting from here */
    net_start();    /* the static address the settings give; DHCP only if they ask for it */
    clock_start();  /* on DHCP takes the lease's NTP server; SNTP itself waits for the listeners */
    improv_start();
    /* Zones only from a card that mounted in time: a missing or slow one never holds up the
     * listeners. Loaded before the zone task starts, which owns them from then on. */
    bool sd = sd_wait_boot() == SD_MOUNTED;
    if (sd) {
        xfr_load_saved();
    } else if (reg_nslots()) {
        ESP_LOGE(TAG, "no SD card: zones will only live in RAM");
    }
    hosted_start(sd); /* with a card in time, before the listeners; else once it mounts */
    if (sd)
        boot_mark(BOOT_ZONES);

    xfr_start(); /* with secondary zones */
    server_start();
    supervisor_start(); /* watches the listeners from here; restarts a service that fails */
    ota_start();
    blocking_start(); /* in the background, after the listeners */
    querylog_start(); /* the query log's ring, if the config has it on */
    power_start();       /* idle clock scaling (cpuplan.h): boot ran at the full clock */
    ota_confirm_when_healthy();
    settings_confirm_when_healthy();
    ESP_LOGI(TAG, "started in %lld ms", esp_timer_get_time() / 1000);

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(60000));
        log_status();
    }
}
