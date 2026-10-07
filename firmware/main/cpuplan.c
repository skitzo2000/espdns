#include "cpuplan.h"

#include <string.h>

/* Each chip image's clocks (docs/design.md, Node OS; boards/README.md says why each):
 *
 *   P4      Idles at half its clock, from the same PLL (a divider change, no relock), with the
 *           APB clock (90 or 100 MHz) unchanged, so the MAC and the SD card see no change.
 *           The EMAC holds the APB maximum (90/100 MHz), below these. Silicon v3 (esp32p4):
 *           on, 200 MHz keeps the 200 MHz PSRAM and the flash at full speed. Silicon v1.x
 *           (esp32p4-rev1): off until measured. Every clock below 360 is below the PSRAM's
 *           200 MHz, so at each switch, down when the cores go idle and up on the next
 *           interrupt (the 1 kHz tick included), ESP-IDF stalls the other core, freezes the
 *           cache and moves flash and PSRAM between full speed and 20 MHz. Supported, but a
 *           cost on every interrupt of the production node: a board or node config turns it
 *           on to measure.
 *   S3      Idles at 80 MHz: still the PLL, so the APB (80), the W5500's SPI clock and the
 *           octal PSRAM's timing are untouched. 40 (the crystal) also changes those.
 *   C3, C6  As the S3: 80 keeps the PLL and the APB clock, and is Wi-Fi's floor anyway.
 *   ESP32   Off: its built-in MAC holds the APB maximum, which on a 240 MHz ESP32 is 240 MHz,
 *           so a wired ESP32 never clocks down. A Wi-Fi board may turn it on, idling at the
 *           crystal (40): the only clock reached from 240 without changing the PLL.
 */
static const cp_image_t IMAGES[] = {
    { "esp32p4-rev1", 360, 90, false, 180, { 90, 180, 0 } },
    { "esp32p4", 400, 100, true, 200, { 100, 200, 0 } },
    { "esp32s3-octal", 240, 80, true, 80, { 40, 80, 160, 0 } },
    { "esp32s3-quad", 240, 80, true, 80, { 40, 80, 160, 0 } },
    { "esp32", 240, 240, false, 40, { 40, 0 } },
    { "esp32c3", 160, 80, true, 80, { 40, 80, 0 } },
    { "esp32c6", 160, 80, true, 80, { 40, 80, 0 } },
};

const cp_image_t *cp_image(const char *image)
{
    for (size_t i = 0; image && i < sizeof(IMAGES) / sizeof(IMAGES[0]); i++)
        if (!strcmp(image, IMAGES[i].image))
            return &IMAGES[i];
    return NULL;
}

bool cp_min_ok(const char *image, int min_mhz)
{
    const cp_image_t *im = cp_image(image);
    if (!im)
        return true;
    for (int i = 0; im->mins[i]; i++)
        if (im->mins[i] == min_mhz)
            return true;
    return false;
}

void cp_board(const board_desc_t *b, const char *image, cp_board_t *out)
{
    memset(out, 0, sizeof(*out));
    const cp_image_t *im = cp_image(image);
    if (!im)
        return;
    out->max_mhz = im->max_mhz;
    out->apb_mhz = im->apb_mhz;
    out->dfs = im->dfs;
    out->min_mhz = im->min_mhz;
    if (b && b->cpu.dfs >= 0) {
        out->dfs = b->cpu.dfs != 0;
        out->dfs_board = true;
    }
    if (b && b->cpu.min_mhz > 0 && cp_min_ok(image, b->cpu.min_mhz))
        out->min_mhz = b->cpu.min_mhz;
}

bool cp_dfs(const cp_board_t *b, int cfg_dfs)
{
    if (!b->min_mhz || b->min_mhz >= b->max_mhz)
        return false;
    return cfg_dfs >= 0 ? cfg_dfs != 0 : b->dfs;
}

int cp_idle_mhz(const cp_board_t *b, bool dfs, bool apb_held)
{
    if (!dfs)
        return b->max_mhz;
    int idle = apb_held && b->apb_mhz > b->min_mhz ? b->apb_mhz : b->min_mhz;
    return idle < b->max_mhz ? idle : b->max_mhz;
}
