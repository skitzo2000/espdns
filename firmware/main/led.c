#include "led.h"

#include "board.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "soc/soc_caps.h"
#if SOC_RMT_SUPPORTED
#include "driver/rmt_tx.h"
#endif

static const char *TAG = "led";

/* WS2812 at full brightness is glaring and draws ~40 mA: colours are scaled to this. */
#define WS2812_MAX 40

static bool s_ok, s_failed;
#if SOC_RMT_SUPPORTED
static rmt_channel_handle_t s_chan;
static rmt_encoder_handle_t s_enc;
#endif

#if SOC_RMT_SUPPORTED
/* WS2812 bits at 10 MHz (0.1 us ticks): 0 = 0.3 us high, 0.9 us low; 1 = 0.9 high, 0.3 low.
 * The line idles low between frames, which is the reset (> 50 us). */
static bool ws2812_init(int pin)
{
    rmt_tx_channel_config_t cfg = {
        .gpio_num = pin,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
        .mem_block_symbols = SOC_RMT_MEM_WORDS_PER_CHANNEL,
        .trans_queue_depth = 2,
    };
    rmt_bytes_encoder_config_t enc = {
        .bit0 = { .level0 = 1, .duration0 = 3, .level1 = 0, .duration1 = 9 },
        .bit1 = { .level0 = 1, .duration0 = 9, .level1 = 0, .duration1 = 3 },
        .flags.msb_first = 1,
    };
    esp_err_t err = rmt_new_tx_channel(&cfg, &s_chan);
    if (err == ESP_OK)
        err = rmt_new_bytes_encoder(&enc, &s_enc);
    /* Enabled only while it sends (ws2812_set): an enabled channel holds the CPU at its full
     * clock (ESP-IDF's power management lock for the RMT), and the LED would keep the node
     * from ever idling at a lower one. */
    if (err == ESP_OK && (err = rmt_enable(s_chan)) == ESP_OK)
        err = rmt_disable(s_chan);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ws2812 on GPIO %d: %s", pin, esp_err_to_name(err));
        return false;
    }
    return true;
}

/* Disabled after each send. The send-done interrupt, on the core the channel was made on,
 * hands the send back (which ends rmt_tx_wait_all_done) a few microseconds before it marks
 * the channel idle, and a disable in between is refused: the channel would stay enabled,
 * holding the full clock, and every later enable would be refused, the LED stuck. So a
 * refused disable is tried again a tick later. */
static bool chan_off(void)
{
    esp_err_t err = rmt_disable(s_chan);
    for (int i = 0; err == ESP_ERR_INVALID_STATE && i < 3; i++) {
        vTaskDelay(1);
        err = rmt_disable(s_chan);
    }
    return err == ESP_OK;
}

/* Enabled for a send; one left enabled (a disable that still failed) is disabled first. */
static bool chan_on(void)
{
    esp_err_t err = rmt_enable(s_chan);
    if (err == ESP_ERR_INVALID_STATE && chan_off())
        err = rmt_enable(s_chan);
    return err == ESP_OK;
}

static void ws2812_set(uint8_t r, uint8_t g, uint8_t b)
{
    /* The RMT reads the buffer after rmt_transmit returns: static, and the send is over (or
     * given up) before the channel is disabled again. 24 bits take 30 us. */
    static uint8_t grb[3];
    grb[0] = (uint8_t)(g * WS2812_MAX / 255);
    grb[1] = (uint8_t)(r * WS2812_MAX / 255);
    grb[2] = (uint8_t)(b * WS2812_MAX / 255);
    if (!chan_on())
        return;
    rmt_transmit_config_t tx = { .loop_count = 0 };
    if (rmt_transmit(s_chan, s_enc, grb, sizeof(grb), &tx) == ESP_OK)
        rmt_tx_wait_all_done(s_chan, 10);
    chan_off();
}
#endif

bool led_init(void)
{
    switch (board.led.kind) {
    case BOARD_LED_GPIO:
        s_ok = gpio_reset_pin(board.led.pin) == ESP_OK && gpio_set_direction(board.led.pin, GPIO_MODE_OUTPUT) == ESP_OK;
        break;
    case BOARD_LED_WS2812:
#if SOC_RMT_SUPPORTED
        s_ok = ws2812_init(board.led.pin);
#else
        ESP_LOGE(TAG, "ws2812: this chip has no RMT peripheral");
#endif
        break;
    default:
        return false;
    }
    s_failed = !s_ok;
    if (s_ok) {
        led_set(false, 0, 0, 0);
        ESP_LOGI(TAG, "%s on GPIO %d", led_kind_name(), board.led.pin);
    }
    return s_ok;
}

void led_set(bool on, uint8_t r, uint8_t g, uint8_t b)
{
    if (!s_ok)
        return;
    if (board.led.kind == BOARD_LED_GPIO) {
        gpio_set_level(board.led.pin, on != board.led.active_low);
        return;
    }
#if SOC_RMT_SUPPORTED
    if (!on)
        r = g = b = 0;
    ws2812_set(r, g, b);
#endif
}

const char *led_kind_name(void)
{
    if (s_failed)
        return "failed";
    switch (board.led.kind) {
    case BOARD_LED_GPIO: return "gpio";
    case BOARD_LED_WS2812: return "ws2812";
    default: return "none";
    }
}
