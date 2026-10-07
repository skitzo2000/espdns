#include "improv.h"

#include <stdio.h>
#include <string.h>

#include "board.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "net.h"
#include "sdkconfig.h"

#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_netif.h"

static const char *TAG = "improv";

/* Packet: "IMPROV", version 1, type, length, data, checksum (sum of all preceding bytes). */
enum { T_STATE = 1, T_ERROR = 2, T_RPC = 3, T_RESULT = 4 };
enum { ST_READY = 2, ST_PROVISIONING = 3, ST_PROVISIONED = 4 };
enum { ERR_NONE = 0, ERR_INVALID = 1, ERR_UNKNOWN_RPC = 2, ERR_NO_CONNECT = 3 };
enum { RPC_WIFI = 1, RPC_STATE = 2, RPC_INFO = 3, RPC_SCAN = 4 };

#define JOIN_TIMEOUT_MS 30000

static void send(uint8_t type, const uint8_t *data, size_t len)
{
    uint8_t p[9 + 255 + 2];
    if (len > 255)
        return;
    memcpy(p, "IMPROV", 6);
    p[6] = 1;
    p[7] = type;
    p[8] = (uint8_t)len;
    memcpy(p + 9, data, len);
    uint8_t sum = 0;
    for (size_t i = 0; i < 9 + len; i++)
        sum += p[i];
    p[9 + len] = sum;
    p[10 + len] = '\n';
    usb_serial_jtag_write_bytes(p, 11 + len, pdMS_TO_TICKS(50));
}

static void send_byte(uint8_t type, uint8_t v) { send(type, &v, 1); }

/* RPC result: command, total length of the strings, then each string with its length. */
static void send_result(uint8_t cmd, const char *const *strs, int n)
{
    uint8_t d[255];
    size_t len = 2;
    for (int i = 0; i < n; i++) {
        size_t l = strlen(strs[i]);
        if (len + 1 + l > sizeof(d))
            return;
        d[len++] = (uint8_t)l;
        memcpy(d + len, strs[i], l);
        len += l;
    }
    d[0] = cmd;
    d[1] = (uint8_t)(len - 2);
    send(T_RESULT, d, len);
}

static void send_url(uint8_t cmd)
{
    char url[40];
    uint32_t ip = net_ip();
    snprintf(url, sizeof(url), "http://" IPSTR "/status", IP2STR((esp_ip4_addr_t *)&ip));
    const char *s[] = { url };
    send_result(cmd, s, 1);
}

static void send_state(void)
{
    bool up = net_wifi_configured() && net_online(); /* a static address is there before the link */
    send_byte(T_STATE, up ? ST_PROVISIONED : ST_READY);
    if (up)
        send_url(RPC_STATE);
}

static void scan_one(const char *ssid, int rssi, bool secure, void *arg)
{
    char r[8];
    snprintf(r, sizeof(r), "%d", rssi);
    const char *s[] = { ssid, r, secure ? "YES" : "NO" };
    send_result(RPC_SCAN, s, 3);
}

static void rpc(const uint8_t *d, size_t len)
{
    if (len < 2 || d[1] != len - 2) {
        send_byte(T_ERROR, ERR_INVALID);
        return;
    }
    switch (d[0]) {
    case RPC_WIFI: {
        const uint8_t *p = d + 2, *end = d + len;
        char ssid[33], pass[65];
        if (p >= end || p[0] > 32 || p + 1 + p[0] >= end || p[1 + p[0]] > 64 ||
            p + 2 + p[0] + p[1 + p[0]] > end) {
            send_byte(T_ERROR, ERR_INVALID);
            return;
        }
        memcpy(ssid, p + 1, p[0]);
        ssid[p[0]] = 0;
        p += 1 + p[0];
        memcpy(pass, p + 1, p[0]);
        pass[p[0]] = 0;
        send_byte(T_ERROR, ERR_NONE);
        send_byte(T_STATE, ST_PROVISIONING);
        if (net_wifi_join(ssid, pass, JOIN_TIMEOUT_MS)) {
            send_byte(T_STATE, ST_PROVISIONED);
            send_url(RPC_WIFI);
        } else {
            send_byte(T_ERROR, ERR_NO_CONNECT);
            send_byte(T_STATE, ST_READY);
        }
        memset(pass, 0, sizeof(pass));
        break;
    }
    case RPC_STATE:
        send_state();
        break;
    case RPC_INFO: {
        const char *s[] = { "espDNS", esp_app_get_description()->version, CONFIG_IDF_TARGET, net_hostname() };
        send_result(RPC_INFO, s, 4);
        break;
    }
    case RPC_SCAN:
        net_wifi_scan(scan_one, NULL);
        send_result(RPC_SCAN, NULL, 0); /* an empty result ends the list */
        break;
    default:
        send_byte(T_ERROR, ERR_UNKNOWN_RPC);
    }
}

static void improv_task(void *arg)
{
    uint8_t buf[9 + 255 + 1];
    size_t n = 0;
    for (;;) {
        uint8_t c;
        if (usb_serial_jtag_read_bytes(&c, 1, portMAX_DELAY) != 1)
            continue;
        /* Keep bytes only while they can still be the start of a packet. */
        if (n < 6 && c != (uint8_t)"IMPROV"[n]) {
            n = c == 'I' ? 1 : 0;
            buf[0] = c;
            continue;
        }
        buf[n++] = c;
        if (n < 9)
            continue;
        size_t len = buf[8];
        if (n < 10 + len)
            continue;
        uint8_t sum = 0;
        for (size_t i = 0; i < 9 + len; i++)
            sum += buf[i];
        if (buf[6] == 1 && sum == buf[9 + len] && buf[7] == T_RPC)
            rpc(buf + 9, len);
        else if (buf[6] == 1)
            send_byte(T_ERROR, ERR_INVALID);
        n = 0;
    }
}

void improv_start(void)
{
    if (net_kind() != NET_WIFI)
        return;
    usb_serial_jtag_driver_config_t cfg = { .rx_buffer_size = 512, .tx_buffer_size = 1024 };
    if (usb_serial_jtag_driver_install(&cfg) != ESP_OK) {
        ESP_LOGE(TAG, "usb serial driver failed to start");
        return;
    }
    /* Logs go through the driver too, so they and Improv packets don't collide; with no host
     * reading, output is dropped rather than blocking. */
    usb_serial_jtag_vfs_use_driver();
    xTaskCreate(improv_task, "improv", 4096, NULL, 3, NULL);
    ESP_LOGI(TAG, "listening on USB serial");
}
#else
void improv_start(void) {}
#endif
