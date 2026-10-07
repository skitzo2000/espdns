#include "boot.h"

#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "boot";

/* Each slot is written once, by whichever task finishes that step; 32-bit so reads are atomic. */
static volatile uint32_t s_ms[BOOT_NSTEPS];

static const char *const s_names[BOOT_NSTEPS] = { "sd", "zones", "link", "ip", "listen" };

void boot_mark(boot_step_t step)
{
    if (s_ms[step])
        return;
    uint32_t ms = (uint32_t)(esp_timer_get_time() / 1000);
    s_ms[step] = ms ? ms : 1;
    if ((step == BOOT_IP || step == BOOT_LISTEN) && boot_ms()) {
        uint32_t b = boot_ms();
        if (b > BOOT_LIMIT_MS)
            ESP_LOGE(TAG, "answering after %lu ms: over the %d ms limit", (unsigned long)b, BOOT_LIMIT_MS);
        else
            ESP_LOGI(TAG, "answering after %lu ms", (unsigned long)b);
    }
}

uint32_t boot_step_ms(boot_step_t step) { return s_ms[step]; }

const char *boot_step_name(boot_step_t step) { return s_names[step]; }

uint32_t boot_ms(void)
{
    uint32_t ip = s_ms[BOOT_IP], listen = s_ms[BOOT_LISTEN];
    if (!ip || !listen)
        return 0;
    return ip > listen ? ip : listen;
}
