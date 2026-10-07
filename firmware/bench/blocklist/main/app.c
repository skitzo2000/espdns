/* Runs the blocklist benchmark on the board: the list is copied from flash into PSRAM, as
 * the RAM tier loads it, then timed (tests/bench_blocklist.c). Output on the console. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_blocklist.h"
#include "esp_chip_info.h"
#include "esp_clk_tree.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

extern const uint8_t list_start[] asm("_binary_list_bin_start");
extern const uint8_t list_end[] asm("_binary_list_bin_end");
extern const uint8_t q_start[] asm("_binary_q_txt_start");
extern const uint8_t q_end[] asm("_binary_q_txt_end");

#define QUERIES 20000

double bench_now(void) { return esp_timer_get_time() * 1e-6; }

void *bench_index_alloc(size_t n) { return heap_caps_aligned_alloc(8, n ? n : 8, MALLOC_CAP_INTERNAL); }

void app_main(void)
{
    vTaskDelay(pdMS_TO_TICKS(2000)); /* let the console attach */
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    uint32_t hz = 0;
    esp_clk_tree_src_get_freq_hz(SOC_MOD_CLK_CPU, ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT, &hz);
    size_t len = (size_t)(list_end - list_start);
    printf("\n=== blbench: %s rev %d.%d, %lu MHz, PSRAM free %u KB ===\n", CONFIG_IDF_TARGET, chip.revision / 100,
           chip.revision % 100, (unsigned long)(hz / 1000000), heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024);
    uint8_t *file = heap_caps_aligned_alloc(8, len, MALLOC_CAP_SPIRAM);
    if (!file) {
        printf("no room in PSRAM for the %u-byte list\n", (unsigned)len);
        return;
    }
    memcpy(file, list_start, len);
    int rc = bench_run(stdout, file, len, (const char *)q_start, (size_t)(q_end - q_start), QUERIES);
    printf("=== blbench done (%s) ===\n", rc ? "FAILED" : "ok");
}
