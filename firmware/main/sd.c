#include "sd.h"

#include "board.h"
#include "boot.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

static const char *TAG = "sd";

#define DONE_BIT 1

static volatile sd_state_t s_state = SD_NONE;
static volatile bool s_timed_out;
static volatile uint32_t s_done_ms;
static int64_t s_start_us;
static EventGroupHandle_t s_ev;

static void finish(bool ok)
{
    s_done_ms = (uint32_t)(esp_timer_get_time() / 1000);
    s_state = ok ? SD_MOUNTED : SD_FAILED;
    if (ok)
        boot_mark(BOOT_SD);
    if (ok && s_timed_out)
        ESP_LOGW(TAG, "mounted after %lu ms, past the %d ms boot timeout: zones come from the primary this boot",
                 (unsigned long)s_done_ms, SD_BOOT_TIMEOUT_MS);
    if (s_ev)
        xEventGroupSetBits(s_ev, DONE_BIT);
}

static void mount_task(void *arg)
{
    finish(board_sd_mount());
    vTaskDelete(NULL);
}

static bool shares_eth_bus(void)
{
    return board.sd.kind == BOARD_SD_SPI && board.eth.kind == BOARD_ETH_W5500 && board.sd.spi_bus == board.eth.spi_bus;
}

void sd_start(void)
{
    s_start_us = esp_timer_get_time();
    if (board.sd.kind == BOARD_SD_NONE) {
        ESP_LOGW(TAG, "board %s has no SD slot", board.name);
        return;
    }
    s_ev = xEventGroupCreate();
    s_state = SD_PENDING;
    /* Above the main task, so the mount runs while it brings the network up. */
    if (shares_eth_bus() || !s_ev || xTaskCreate(mount_task, "sd", 6144, NULL, 5, NULL) != pdPASS)
        finish(board_sd_mount());
}

static sd_state_t wait_until(TickType_t ticks)
{
    if (s_state == SD_PENDING && s_ev)
        xEventGroupWaitBits(s_ev, DONE_BIT, pdFALSE, pdTRUE, ticks);
    return s_state;
}

sd_state_t sd_wait_boot(void)
{
    int64_t left_ms = SD_BOOT_TIMEOUT_MS - (esp_timer_get_time() - s_start_us) / 1000;
    sd_state_t st = wait_until(left_ms > 0 ? pdMS_TO_TICKS(left_ms) : 0);
    if (st == SD_PENDING) {
        s_timed_out = true;
        ESP_LOGE(TAG, "card not mounted within %d ms: answering without it", SD_BOOT_TIMEOUT_MS);
    }
    return st;
}

sd_state_t sd_wait(void) { return wait_until(portMAX_DELAY); }

sd_state_t sd_state(void) { return s_state; }

bool sd_timed_out(void) { return s_timed_out; }

uint32_t sd_done_ms(void) { return s_done_ms; }

const char *sd_state_name(sd_state_t s)
{
    switch (s) {
    case SD_PENDING: return "mounting";
    case SD_MOUNTED: return "mounted";
    case SD_FAILED: return "failed";
    default: return "none";
    }
}
