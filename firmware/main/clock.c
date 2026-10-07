#include "clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "jsonw.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "net.h"
#include "server.h"
#include "sdkconfig.h"
#include "settings.h"

static const char *TAG = "clock";

#define NSERVERS (CFG_MAX_NTP < CONFIG_LWIP_SNTP_MAX_SERVERS ? CFG_MAX_NTP : CONFIG_LWIP_SNTP_MAX_SERVERS)

/* lwIP keeps the name pointers, so the names live here (cfg_ntp_slots: on DHCP without
 * configured servers, slot 0 is left to the server the lease names, if any). */
static char s_servers[CFG_MAX_NTP][CFG_HOST_MAX];
static bool s_dhcp;
static volatile bool s_started, s_synced;
static volatile int64_t s_sync_us;
static SemaphoreHandle_t s_lock; /* s_servers and lwIP's slots: clock_apply against the task */

bool clock_synced(void) { return s_synced; }

static void on_sync(struct timeval *tv)
{
    bool first = !s_synced;
    s_sync_us = esp_timer_get_time();
    s_synced = true;
    if (first) {
        char buf[40];
        time_t t = tv->tv_sec;
        struct tm tm;
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", localtime_r(&t, &tm));
        ESP_LOGI(TAG, "set over SNTP: %s", buf);
    }
}

static void set_tz(void)
{
    setenv("TZ", settings()->tz, 1);
    tzset();
}

static void set_servers(void)
{
    cfg_ntp_slots(settings(), net_gateway(), NSERVERS, s_servers, &s_dhcp);
    esp_sntp_servermode_dhcp(s_dhcp);
    /* Slot 0 on DHCP keeps the lease's server, but not a name left from configured servers. */
    for (int i = 0; i < NSERVERS; i++)
        if (s_servers[i][0] || !s_dhcp || i || esp_sntp_getservername(0))
            esp_sntp_setservername(i, s_servers[i][0] ? s_servers[i] : NULL);
}

/* lwIP clears every slot after the lease's servers on each DHCP ACK, renewals included
 * (dhcp_set_ntp_servers), and a renewal posts no event: put the gateway and the fallback
 * back. */
static void restore_servers(void)
{
    if (!s_dhcp)
        return;
    for (int i = 1; i < NSERVERS; i++)
        if (s_servers[i][0] && esp_sntp_getservername(i) != s_servers[i])
            esp_sntp_setservername(i, s_servers[i]);
}

static void clock_task(void *arg)
{
    /* Never in front of answering: once the node has an address and its listeners are open. */
    while (!net_ip() || !(server_running() || server_failed()))
        vTaskDelay(pdMS_TO_TICKS(1000));
    /* Nor during a config trial: looking a server name up through the node itself (a DHCP
     * lease that names it as the DNS server) would be the query that confirms the trial. */
    while (settings_on_trial())
        vTaskDelay(pdMS_TO_TICKS(1000));
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    sntp_set_time_sync_notification_cb(on_sync);
    set_servers();
    esp_sntp_init();
    s_started = true;
    char list[CFG_MAX_NTP * CFG_HOST_MAX] = "";
    for (int i = 0; i < NSERVERS; i++)
        if (s_servers[i][0]) {
            if (list[0])
                strlcat(list, ", ", sizeof(list));
            strlcat(list, s_servers[i], sizeof(list));
        }
    ESP_LOGI(TAG, "SNTP: %s%s", s_dhcp ? "DHCP's server, else " : "", list[0] ? list : "no server");
    xSemaphoreGive(s_lock);
    /* Only a DHCP lease's renewals undo the slots (restore_servers): a node with a static
     * address (it changes only with a reboot) has nothing to look at every minute. */
    if (!settings()->dhcp || settings()->ip)
        vTaskDelete(NULL);
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(60 * 1000));
        xSemaphoreTake(s_lock, portMAX_DELAY);
        restore_servers();
        xSemaphoreGive(s_lock);
    }
}

void clock_start(void)
{
    set_tz();
    s_lock = xSemaphoreCreateMutex();
    if (!settings()->nntp && settings()->dhcp && !settings()->ip && NSERVERS > 1)
        esp_sntp_servermode_dhcp(true);
    xTaskCreate(clock_task, "clock", 3072, NULL, 1, NULL);
}

void clock_apply(void)
{
    set_tz();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_started) { /* else the task picks the servers up when it starts */
        esp_sntp_stop();
        set_servers();
        esp_sntp_init();
    }
    xSemaphoreGive(s_lock);
}

size_t clock_status_json(char *j, size_t cap)
{
    size_t n = 0;
    char utc[24] = "null", local[48] = "null";
    if (s_synced) {
        time_t now = time(NULL);
        struct tm tm;
        strftime(utc, sizeof(utc), "\"%Y-%m-%dT%H:%M:%SZ\"", gmtime_r(&now, &tm));
        strftime(local, sizeof(local), "\"%Y-%m-%d %H:%M:%S %Z\"", localtime_r(&now, &tm));
    }
    char tz[2 * CFG_TZ_MAX + 3], q[2 * CFG_HOST_MAX + 3];
    n += (size_t)snprintf(j + n, cap - n, "\"time\":{\"synced\":%s,\"utc\":%s,\"local\":%s,\"tz\":%s,",
                          s_synced ? "true" : "false", utc, local, json_q(tz, sizeof(tz), settings()->tz));
    if (n < cap)
        n += (size_t)(s_synced ? snprintf(j + n, cap - n, "\"since_sync_s\":%lld,", (esp_timer_get_time() - s_sync_us) / 1000000)
                               : snprintf(j + n, cap - n, "\"since_sync_s\":null,"));
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, "\"servers\":[%s", s_dhcp ? "\"dhcp\"" : "");
    bool first = !s_dhcp;
    for (int i = 0; i < CFG_MAX_NTP && n < cap; i++)
        if (s_servers[i][0]) {
            n += (size_t)snprintf(j + n, cap - n, "%s%s", first ? "" : ",", json_q(q, sizeof(q), s_servers[i]));
            first = false;
        }
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, "]}");
    return n < cap ? n : cap - 1;
}
