/*
 * Board definitions as data (docs/design.md, Boards and images). A board is described by a
 * JSON file in the catalog (boards/<name>.json at the top of the repo). On the node it lives in
 * the `board` partition: a 16-byte header, then the JSON.
 *
 *   off  len
 *     0    4  magic "EDBD"
 *     4    2  format version (1), little endian
 *     6    2  reserved, 0
 *     8    4  JSON length
 *    12    4  CRC-32 (IEEE) of the JSON
 *    16    n  JSON, UTF-8, no NUL
 *
 * Portable: parsing and checks run on the host in the tests.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BOARD_NC          (-1) /* pin not connected, or use the peripheral's default */
#define BOARD_PART_MAGIC  "EDBD"
#define BOARD_PART_VER    1
#define BOARD_PART_HDR    16
#define BOARD_PART_SIZE   4096
#define BOARD_JSON_MAX    (BOARD_PART_SIZE - BOARD_PART_HDR)

typedef enum { BOARD_ETH_NONE, BOARD_ETH_EMAC, BOARD_ETH_W5500 } board_eth_kind_t;
typedef enum { BOARD_PHY_IP101, BOARD_PHY_LAN87XX, BOARD_PHY_RTL8201, BOARD_PHY_DP83848 } board_phy_t;
typedef enum { BOARD_CLK_DEFAULT, BOARD_CLK_IN, BOARD_CLK_OUT } board_rmii_clock_t;
typedef enum { BOARD_SD_NONE, BOARD_SD_SDMMC, BOARD_SD_SPI } board_sd_kind_t;
typedef enum { BOARD_LED_NONE, BOARD_LED_GPIO, BOARD_LED_WS2812 } board_led_kind_t;

/* A network address setting, as the board definition's "network" and the node config's write
 * it (cfg_parse_net): a static address, "dhcp", or not given. DHCP only when a setting says
 * so: a node never asks for an address on its own. */
typedef struct {
    bool set;                      /* given */
    bool dhcp;                     /* "dhcp", for a network with a DHCP server */
    uint32_t ip, netmask, gateway; /* static; IPv4 in network order */
} board_net_t;

/* An SPI bus the board wires up; Ethernet and the SD card each name one by number. */
typedef struct {
    int bus; /* 2 (SPI2) or 3 (SPI3); 0 = unused */
    int sclk, mosi, miso;
} board_spi_bus_t;

typedef struct {
    char name[24];  /* catalog name, e.g. xiao-s3-sense */
    char image[16]; /* chip image it runs on, e.g. esp32s3-octal */

    board_spi_bus_t spi[2];

    struct {
        board_eth_kind_t kind;
        bool optional; /* an add-on that may not be fitted: its absence is not a fault */
        /* Built-in MAC: PHY chip, address, reset pin, PHY power/oscillator enable pin; MDC and
         * MDIO, BOARD_NC = the chip's defaults; RMII clock in from or out to a GPIO. */
        board_phy_t phy;
        int phy_addr, phy_reset, power_pin, mdc, mdio;
        board_rmii_clock_t rmii_clock;
        int rmii_clock_gpio;
        /* W5500: SPI bus, chip select, interrupt, reset, clock. */
        int spi_bus, cs, irq, reset, clock_mhz;
    } eth;

    struct {
        board_sd_kind_t kind;
        /* SDMMC: slot and bus width; ldo = on-chip LDO channel powering the IO bank, or NC. */
        int slot, width, ldo;
        /* SPI: bus and chip select. */
        int spi_bus, cs;
    } sd;

    struct {
        board_led_kind_t kind;
        int pin;
        bool active_low;
    } led;

    /* Wi-Fi transmit power cap in dBm, 0 = the chip's default. Small boards with a marginal
     * antenna or supply often transmit cleaner below full power. */
    int wifi_max_tx_dbm;

    /* PSRAM fitted, MB; -1 = not given (the chip's, as found at boot). */
    int psram_mb;

    /* The memory plan's values (memplan.h), -1 = not given: the chip image's default. Board
     * data, not a guess made at run time from free memory (docs/design.md, Node OS). KB,
     * except cache_entries and fwd_pending. */
    struct {
        int internal_kb;        /* internal RAM the services may take */
        int cache_kb;           /* the DNS cache */
        int cache_entries;      /* answers it holds at most */
        int blocklist_kb;       /* lists and overrides, two copies of each during a live swap */
        int blocklist_index_kb; /* internal RAM for the lists' indexes; 0: they go with the lists */
        int hosted_zones_kb;    /* the most the hosted zones may take (hzone.h, hz_mem) */
        int secondary_zones_kb; /* all secondary zones, with a new copy during a transfer */
        int querylog_kb;        /* the query log's ring; 0: none */
        int fwd_pending;        /* upstream queries outstanding at once (flight.h): a count */
    } mem;

    /* The CPU clock plan's values (cpuplan.h), -1 = not given: the chip image's default.
     * dfs: clock scaling on (1) or off (0); min_mhz: the idle clock, one the image allows. */
    struct {
        int dfs;
        int min_mhz;
    } cpu;

    /* The node's address until a node config gives one: { "address": "192.0.2.52/24",
     * "gateway": "192.0.2.1" } or { "address": "dhcp" }. Not hardware: the builder adds it
     * for the node it flashes (docs/design.md, Adoption and addressing). */
    board_net_t net;
} board_desc_t;

#define BOARD_MEM_KB_MIN 16
#define BOARD_MEM_KB_MAX 65536
#define BOARD_PSRAM_MB_MAX 64
#define BOARD_CACHE_ENTRIES_MIN 16
#define BOARD_CACHE_ENTRIES_MAX 1048576
/* memory.fwd_pending: at least 2, so each half of the table (flight.h) has a slot. */
#define BOARD_FWD_PENDING_MIN 2
#define BOARD_FWD_PENDING_MAX 1024

/* Fills *out from a board definition. False with a reason in err if it is malformed: unknown
 * kinds, pins out of range, a pin used twice, a device on an SPI bus the board doesn't define. */
bool board_def_parse(const char *json, size_t len, board_desc_t *out, char *err, size_t errlen);

/* Checks a `board` partition's header and CRC. On success points *json at the definition. */
bool board_part_open(const uint8_t *part, size_t size, const char **json, size_t *len, const char **err);

/* CRC-32 (IEEE 802.3), as zlib.crc32. */
uint32_t board_crc32(const uint8_t *p, size_t n);
