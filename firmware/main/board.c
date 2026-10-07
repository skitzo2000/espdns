#include "board.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>

#include "config.h"
#include "driver/gpio.h"
#include "driver/sdspi_host.h"
#include "driver/spi_master.h"
#include "esp_eth.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_vfs_fat.h"
#include "sdkconfig.h"
#include "sdmmc_cmd.h"
#include "soc/soc_caps.h"
#if SOC_SDMMC_HOST_SUPPORTED
#include "driver/sdmmc_host.h"
#endif
#if SOC_GP_LDO_SUPPORTED
#include "sd_pwr_ctrl_by_on_chip_ldo.h"
#endif

static const char *TAG = "board";

/* Files open on the SD card at once. Their descriptors, and stdio's three, must sit below
 * lwIP's sockets, which take the top CONFIG_LWIP_MAX_SOCKETS of FD_SETSIZE: past that, a file
 * on the card can't be opened (sdkconfig.defaults). */
#define SD_MAX_FILES 8
_Static_assert(3 + SD_MAX_FILES + CONFIG_LWIP_MAX_SOCKETS <= FD_SETSIZE,
               "CONFIG_LWIP_MAX_SOCKETS leaves no descriptors for stdio and the SD card's files");

board_desc_t board;

#ifndef ESPDNS_IMAGE
#error "ESPDNS_IMAGE (the chip image name) is set by the build"
#endif
#ifdef ESPDNS_FALLBACK
/* The catalog board built into a transitional image, for a node without a `board` partition. */
extern const char fallback_json_start[] asm("_binary_fallback_board_json_start");
extern const char fallback_json_end[] asm("_binary_fallback_board_json_end");
#endif

static const char *s_source = "none";
/* The SD card mounts in its own task while the network starts (sd.c): both bring the SPI
 * buses up, once. */
static StaticSemaphore_t s_spi_mu_buf;
static SemaphoreHandle_t s_spi_mu;
static char s_error[96];

const char *board_source(void) { return s_source; }
const char *board_error(void) { return s_error; }
const char *board_image(void) { return ESPDNS_IMAGE; }
#ifdef ESPDNS_FALLBACK
const char *board_fallback_name(void) { return ESPDNS_FALLBACK; }
#else
const char *board_fallback_name(void) { return ""; }
#endif

/* Parses a definition and checks it is for this image. */
static bool use_definition(const char *json, size_t len, char *why, size_t whylen)
{
    board_desc_t b;
    if (!board_def_parse(json, len, &b, why, whylen))
        return false;
    if (strcmp(b.image, ESPDNS_IMAGE) != 0) {
        snprintf(why, whylen, "board %s is for image %s, this is %s", b.name, b.image, ESPDNS_IMAGE);
        return false;
    }
    for (int i = 0; i < 2; i++)
        if (b.spi[i].bus == 3 && SOC_SPI_PERIPH_NUM < 3) {
            snprintf(why, whylen, "board %s uses SPI3, which this chip doesn't have", b.name);
            return false;
        }
    int pins = SOC_GPIO_PIN_COUNT;
    const int *all[] = { &b.spi[0].sclk, &b.spi[0].mosi, &b.spi[0].miso, &b.spi[1].sclk, &b.spi[1].mosi,
                         &b.spi[1].miso, &b.eth.phy_reset, &b.eth.power_pin, &b.eth.mdc, &b.eth.mdio,
                         &b.eth.rmii_clock_gpio, &b.eth.cs, &b.eth.irq, &b.eth.reset, &b.sd.cs, &b.led.pin };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (*all[i] >= pins) {
            snprintf(why, whylen, "board %s: GPIO %d doesn't exist on this chip", b.name, *all[i]);
            return false;
        }
    board = b;
    return true;
}

bool board_load(void)
{
    s_spi_mu = xSemaphoreCreateMutexStatic(&s_spi_mu_buf);
    const esp_partition_t *p = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "board");
    if (!p) {
        snprintf(s_error, sizeof(s_error), "no board partition (flash layout from before board definitions)");
    } else {
        uint8_t *buf = malloc(BOARD_PART_SIZE);
        const char *json, *why = NULL;
        size_t len;
        if (!buf || esp_partition_read(p, 0, buf, BOARD_PART_SIZE) != ESP_OK)
            snprintf(s_error, sizeof(s_error), "board partition unreadable");
        else if (!board_part_open(buf, BOARD_PART_SIZE, &json, &len, &why))
            snprintf(s_error, sizeof(s_error), "%s", why);
        else if (use_definition(json, len, s_error, sizeof(s_error)))
            s_source = "partition";
        free(buf);
        if (!strcmp(s_source, "partition")) {
            s_error[0] = 0;
            ESP_LOGI(TAG, "board %s (from the board partition), image %s", board.name, ESPDNS_IMAGE);
            return true;
        }
    }
    ESP_LOGW(TAG, "%s", s_error);
#ifdef ESPDNS_FALLBACK
    char why[96];
    if (use_definition(fallback_json_start, fallback_json_end - fallback_json_start, why, sizeof(why))) {
        s_source = "fallback";
        ESP_LOGW(TAG, "board %s (built-in fallback until the node is reflashed with a board partition)", board.name);
        return true;
    }
    ESP_LOGE(TAG, "built-in board: %s", why);
#endif
    memset(&board, 0, sizeof(board));
    strcpy(board.name, "unknown");
    strlcpy(board.image, ESPDNS_IMAGE, sizeof(board.image));
    board.sd.ldo = BOARD_NC;
    board.psram_mb = -1; /* the chip's, and the image's memory defaults (memplan.h) */
    memset(&board.mem, 0xFF, sizeof(board.mem));
    board.cpu.dfs = board.cpu.min_mhz = -1; /* the image's clocks (cpuplan.h) */
    ESP_LOGE(TAG, "no usable board definition: no Ethernet, no SD card. Reflash it from the dashboard's builder.");
    return false;
}

/* SPI bus number (2, 3) to ESP-IDF host (SPI2_HOST, SPI3_HOST). The C3 and C6 have no SPI3;
 * use_definition() refuses a board that asks for it there. */
static spi_host_device_t spi_host(int bus)
{
#if SOC_SPI_PERIPH_NUM > 2
    if (bus == 3)
        return SPI3_HOST;
#endif
    return SPI2_HOST;
}

/* Brings up the board's SPI buses once. Every chip select on them is driven high first, so
 * a device that isn't set up yet (the W5500 while the SD card mounts) stays off the bus. */
static bool spi_buses_init_locked(void)
{
    static bool done, ok;
    if (done)
        return ok;
    done = true;
    int cs[] = { board.eth.kind == BOARD_ETH_W5500 ? board.eth.cs : BOARD_NC,
                 board.sd.kind == BOARD_SD_SPI ? board.sd.cs : BOARD_NC };
    for (size_t i = 0; i < sizeof(cs) / sizeof(cs[0]); i++) {
        if (cs[i] == BOARD_NC)
            continue;
        gpio_set_level(cs[i], 1);
        gpio_set_direction(cs[i], GPIO_MODE_OUTPUT);
    }
    ok = true;
    for (size_t i = 0; i < sizeof(board.spi) / sizeof(board.spi[0]); i++) {
        const board_spi_bus_t *b = &board.spi[i];
        if (!b->bus)
            continue;
        spi_bus_config_t cfg = {
            .sclk_io_num = b->sclk,
            .mosi_io_num = b->mosi,
            .miso_io_num = b->miso,
            .quadwp_io_num = -1,
            .quadhd_io_num = -1,
            .max_transfer_sz = 4096,
        };
        esp_err_t err = spi_bus_initialize(spi_host(b->bus), &cfg, SPI_DMA_CH_AUTO);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "spi%d: init failed: %s", b->bus, esp_err_to_name(err));
            ok = false;
        }
    }
    return ok;
}

static bool spi_buses_init(void)
{
    xSemaphoreTake(s_spi_mu, portMAX_DELAY);
    bool ok = spi_buses_init_locked();
    xSemaphoreGive(s_spi_mu);
    return ok;
}

static bool eth_new_emac(esp_eth_mac_t **mac, esp_eth_phy_t **phy)
{
#if SOC_EMAC_SUPPORTED
    if (board.eth.power_pin != BOARD_NC) {
        /* PHY or oscillator enable (WT32-ETH01: GPIO16, Olimex ESP32-POE: GPIO12) */
        gpio_set_direction(board.eth.power_pin, GPIO_MODE_OUTPUT);
        gpio_set_level(board.eth.power_pin, 1);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t emac_cfg = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    if (board.eth.mdc != BOARD_NC)
        emac_cfg.smi_gpio.mdc_num = board.eth.mdc;
    if (board.eth.mdio != BOARD_NC)
        emac_cfg.smi_gpio.mdio_num = board.eth.mdio;
    if (board.eth.rmii_clock != BOARD_CLK_DEFAULT) {
        emac_cfg.clock_config.rmii.clock_mode = board.eth.rmii_clock == BOARD_CLK_IN ? EMAC_CLK_EXT_IN : EMAC_CLK_OUT;
        emac_cfg.clock_config.rmii.clock_gpio = (emac_rmii_clock_gpio_t)board.eth.rmii_clock_gpio;
    }
    *mac = esp_eth_mac_new_esp32(&emac_cfg, &mac_cfg);

    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.phy_addr = board.eth.phy_addr;
    phy_cfg.reset_gpio_num = board.eth.phy_reset;
    switch (board.eth.phy) {
    case BOARD_PHY_LAN87XX: *phy = esp_eth_phy_new_lan87xx(&phy_cfg); break;
    case BOARD_PHY_RTL8201: *phy = esp_eth_phy_new_rtl8201(&phy_cfg); break;
    case BOARD_PHY_DP83848: *phy = esp_eth_phy_new_dp83848(&phy_cfg); break;
    default: *phy = esp_eth_phy_new_ip101(&phy_cfg); break;
    }
    return *mac && *phy;
#else
    ESP_LOGE(TAG, "eth: this chip has no Ethernet MAC");
    return false;
#endif
}

static bool eth_new_w5500(esp_eth_mac_t **mac, esp_eth_phy_t **phy)
{
#if CONFIG_ETH_SPI_ETHERNET_W5500
    if (!spi_buses_init())
        return false;
    esp_err_t err = gpio_install_isr_service(0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "eth: gpio isr service: %s", esp_err_to_name(err));
        return false;
    }
    spi_device_interface_config_t dev = {
        .mode = 0,
        .clock_speed_hz = board.eth.clock_mhz * 1000 * 1000,
        .queue_size = 20,
        .spics_io_num = board.eth.cs,
    };
    eth_w5500_config_t w5500_cfg = ETH_W5500_DEFAULT_CONFIG(spi_host(board.eth.spi_bus), &dev);
    w5500_cfg.int_gpio_num = board.eth.irq;
    if (board.eth.irq == BOARD_NC)
        w5500_cfg.poll_period_ms = 10;
    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    *mac = esp_eth_mac_new_w5500(&w5500_cfg, &mac_cfg);

    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.reset_gpio_num = board.eth.reset;
    *phy = esp_eth_phy_new_w5500(&phy_cfg);
    return *mac && *phy;
#else
    ESP_LOGE(TAG, "eth: W5500 driver not built in (CONFIG_ETH_SPI_ETHERNET_W5500)");
    return false;
#endif
}

bool board_eth_install(esp_eth_handle_t *out)
{
    *out = NULL;
    if (board.eth.kind == BOARD_ETH_NONE)
        return false;
    esp_eth_mac_t *mac = NULL;
    esp_eth_phy_t *phy = NULL;
    bool ok = board.eth.kind == BOARD_ETH_W5500 ? eth_new_w5500(&mac, &phy) : eth_new_emac(&mac, &phy);
    esp_eth_handle_t eth = NULL;
    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_err_t err = ok ? esp_eth_driver_install(&eth_cfg, &eth) : ESP_FAIL;
    if (err != ESP_OK) {
        if (board.eth.optional)
            ESP_LOGW(TAG, "eth: not fitted or not answering (%s): an optional add-on", esp_err_to_name(err));
        else
            ESP_LOGE(TAG, "eth: driver failed to start: %s", esp_err_to_name(err));
        /* The W5500 driver starts its receive task when created: stop it, or it keeps
         * polling a chip that isn't there. */
        if (mac)
            mac->del(mac);
        if (phy)
            phy->del(phy);
        return false;
    }
    if (board.eth.kind == BOARD_ETH_W5500) {
        /* The W5500 has no MAC address of its own: use the one derived from the chip's. */
        uint8_t addr[6];
        esp_read_mac(addr, ESP_MAC_ETH);
        esp_eth_ioctl(eth, ETH_CMD_S_MAC_ADDR, addr);
    }
    *out = eth;
    return true;
}

static esp_err_t sd_mount_sdmmc(const esp_vfs_fat_mount_config_t *mount_cfg, sdmmc_card_t **card)
{
#if SOC_SDMMC_HOST_SUPPORTED
    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    host.slot = board.sd.slot;
    host.max_freq_khz = SDMMC_FREQ_HIGHSPEED;
#if SOC_GP_LDO_SUPPORTED
    if (board.sd.ldo != BOARD_NC) {
        sd_pwr_ctrl_ldo_config_t ldo_cfg = { .ldo_chan_id = board.sd.ldo };
        sd_pwr_ctrl_handle_t pwr = NULL;
        esp_err_t err = sd_pwr_ctrl_new_on_chip_ldo(&ldo_cfg, &pwr);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "sd: LDO init failed: %s", esp_err_to_name(err));
            return err;
        }
        host.pwr_ctrl_handle = pwr;
    }
#endif
    sdmmc_slot_config_t slot = SDMMC_SLOT_CONFIG_DEFAULT();
    slot.width = board.sd.width;
    return esp_vfs_fat_sdmmc_mount(DNS2_SD_MOUNT, &host, &slot, mount_cfg, card);
#else
    ESP_LOGE(TAG, "sd: this chip has no SDMMC host");
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

static esp_err_t sd_mount_spi(const esp_vfs_fat_mount_config_t *mount_cfg, sdmmc_card_t **card)
{
    if (!spi_buses_init())
        return ESP_FAIL;
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = spi_host(board.sd.spi_bus);
    sdspi_device_config_t dev = SDSPI_DEVICE_CONFIG_DEFAULT();
    dev.host_id = spi_host(board.sd.spi_bus);
    dev.gpio_cs = board.sd.cs;
    return esp_vfs_fat_sdspi_mount(DNS2_SD_MOUNT, &host, &dev, mount_cfg, card);
}

bool board_sd_mount(void)
{
    if (board.sd.kind == BOARD_SD_NONE) {
        ESP_LOGE(TAG, "sd: board %s has no SD slot", board.name);
        return false;
    }
    esp_vfs_fat_sdmmc_mount_config_t mount_cfg = {
        .format_if_mount_failed = false,
        .max_files = SD_MAX_FILES,
        .allocation_unit_size = 16 * 1024,
    };
    sdmmc_card_t *card = NULL;
    esp_err_t err = board.sd.kind == BOARD_SD_SPI ? sd_mount_spi(&mount_cfg, &card) : sd_mount_sdmmc(&mount_cfg, &card);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "sd: mount failed: %s", esp_err_to_name(err));
        return false;
    }
    if ((mkdir(DNS2_SD_MOUNT "/dns2", 0755) < 0 && errno != EEXIST) ||
        (mkdir(DNS2_ZONE_DIR, 0755) < 0 && errno != EEXIST)) {
        ESP_LOGE(TAG, "sd: cannot create %s", DNS2_ZONE_DIR);
        return false;
    }
    ESP_LOGI(TAG, "sd: %s, %llu MB, mounted at %s", card->cid.name,
             (unsigned long long)card->csd.capacity * card->csd.sector_size / (1024 * 1024), DNS2_SD_MOUNT);
    return true;
}
