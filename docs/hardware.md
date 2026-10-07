# Hardware

An espDNS node is a small ESP32 board with Ethernet and a microSD card. This page lists
the boards that are known to work, what makes a board suitable, and how to describe a board
that isn't in the catalog yet.

To flash a board, see [Getting started](getting-started.md#9-flash-both-boards).

## Tested boards

These boards are in the catalog ([`boards/`](../boards/)) as **tested**. They run on
hardware for every release.

| Board | Catalog name | Chip image | Flash | PSRAM | Network | microSD | LED |
|---|---|---|---|---|---|---|---|
| Guition JC-ESP32P4-M3-DEV | `p4-ip101` | `esp32p4-rev1` | 16 MB | 32 MB | Ethernet: built-in MAC + IP101 PHY | SDMMC, 4-bit | None usable: add one on a spare GPIO |
| Waveshare ESP32-S3-ETH | `ws-s3-eth` | `esp32s3-octal` | 16 MB | 8 MB | Ethernet: W5500 over SPI. Optional PoE module (802.3af) | SPI, its own bus | WS2812 RGB on GPIO 21 |
| Seeed XIAO ESP32S3 Sense | `xiao-s3-sense` | `esp32s3-octal` | 8 MB | 8 MB | Wi-Fi as it ships. Wired with an added W5500 module | SPI, on the Sense board | None usable: add one |

Notes on each:

- **Guition ESP32-P4.** The most capable node: 32 MB of PSRAM, so large blocklists stay in
  RAM. Wired only: its on-board ESP32-C6 (Wi-Fi) is not used. The catalog entry is for
  P4 silicon v1.x (`esp32p4-rev1`). A board with P4 silicon v3 or later needs the
  `esp32p4` chip image instead: describe it as your own board (below).
- **Waveshare ESP32-S3-ETH.** The on-board RGB LED shows the node's health in colour. With
  its PoE module, one cable carries power and network: a PoE switch on a UPS keeps both up.
  The W5500 runs at 20 MHz. The SD card is on its own SPI bus, slower than the P4's SDMMC.
- **Seeed XIAO ESP32S3 Sense.** No Ethernet on the board. It runs on Wi-Fi as it ships. For
  a wired node, add a W5500 module on the Sense board's SPI bus, shared with the SD card:
  CS on D0 (GPIO 1), INT on D1 (GPIO 2), RST on D3 (GPIO 4). The user LED shares GPIO 21
  with the SD card's chip select, so it can't be used. Its Wi-Fi transmit power is capped
  at 15 dBm: at 20 dBm it lost packets and the access point dropped it. PoE needs a
  separate splitter. The camera is not used.

## What a board needs

| Part | Needed | Why |
|---|---|---|
| **Chip** | ESP32-P4 or ESP32-S3 today | The tested boards. Chip images exist for the classic ESP32, ESP32-C3 and ESP32-C6 too, but their memory sizes are first guesses and untested |
| **PSRAM** | Yes, in practice | Without PSRAM the DNS service's buffers don't fit in internal RAM. Boards without it wait for measured memory sizes |
| **Flash** | 4 MB or more | Two app slots, so an update can roll back. The image is about 1.1 MB |
| **Ethernet** | Strongly recommended | A built-in MAC with a PHY, or a W5500 over SPI. This is what reliable nodes use |
| **microSD** | Yes | Zone copies, hosted zones and blocklists live on the card |
| **LED** | Optional | Shows the node's health. A plain GPIO LED or a WS2812 |

### Chip images

The firmware is built once per chip family, not once per board. A board picks its chip
image, and everything else about the board is data the node reads at boot.

| Chip image | For |
|---|---|
| `esp32p4-rev1` | ESP32-P4 silicon v1.x |
| `esp32p4` | ESP32-P4 silicon v3 and later |
| `esp32s3-octal` | ESP32-S3 with octal PSRAM (S3R8, S3R16V) |
| `esp32s3-quad` | ESP32-S3 with quad PSRAM (S3R2) or none |
| `esp32` | Classic ESP32 |
| `esp32c3`, `esp32c6` | Single-core, no PSRAM |

Every image holds every driver its chip can use. Unused drivers cost flash, not RAM.

### PSRAM

PSRAM holds the DNS cache, the blocklist, the zones and the query log. Each board's
definition fixes how much each service gets. These sizes are found by testing, not worked
out at run time. Some figures:

| Board | Cache | Blocklist in RAM |
|---|---|---|
| ESP32-P4, 32 MB | 4 MB, 8192 answers | 20 MB: two 8 MB lists, so a new list swaps in live |
| ESP32-S3, 8 MB | 2.9 MB, 8192 answers | 2 MB: about 650,000 domains in RAM, about 1.3 million with the SD card |

A node refuses a config whose services don't fit its board's plan, and so does the
controller before it pushes one. [`boards/README.md`](../boards/README.md) has the full
memory table.

### Ethernet

Two kinds can be described in a board definition:

- **Built-in MAC + PHY** (`emac`), on the ESP32-P4 and the classic ESP32. Supported PHYs:
  IP101, LAN87xx, RTL8201, DP83848.
- **W5500 over SPI** (`w5500`), on any chip. It can share an SPI bus with the SD card, on
  its own chip-select pin. Mark it `optional` if the module may not be fitted.

### microSD

Over **SDMMC** (1- or 4-bit) or over **SPI**. The node keeps its zones and blocklists on
the card.

If the card fails or is missing at boot, the node keeps answering from its config and its
forwarders. Secondary zones are copied again into RAM. Hosted zones and blocking are off
until the card is back. The node reports itself **degraded: SD card**. A node without its
card is a stopgap: the second node should carry the load.

## Wired first, Wi-Fi as a fallback

At boot, a node starts its board's Ethernet. If the board has none, or it doesn't start
(an optional W5500 that isn't fitted), the node uses Wi-Fi instead. It doesn't switch
between them while it runs.

Use wired Ethernet for nodes you rely on. Wi-Fi is best effort:

- 2.4 GHz only.
- A new Wi-Fi node joins your network from the builder, over USB.
- The node reconnects on its own and reports **no network** while it is off the air.
- Power saving is off by default: it adds delay to every answer.
- Small boards often transmit more cleanly below the chip's 20 dBm. Set a cap in the
  board's definition, or per node in its config.
- A Wi-Fi node's config holds the Wi-Fi password, so the controller treats it as a secret.

The ESP32-P4 has no Wi-Fi of its own. On the P4 board above, the companion Wi-Fi chip isn't
used yet, so that board is wired only.

## Describing your own board

Any ESP32, S3, C3, C6 or P4 board can be described from its pinout. Open the builder
(`http://127.0.0.1:8480/builder.html`) and choose **Describe your own board**, or pick a
catalog board and press **Copy as a custom board** to start from it. The form asks for:

- name and title, chip image, flash size and PSRAM size;
- up to two SPI buses (host 2 or 3, and their SCLK, MOSI and MISO pins);
- Ethernet: none (Wi-Fi), built-in MAC + PHY (PHY type, address, reset, power, MDC, MDIO,
  RMII clock), or W5500 over SPI (bus, CS, INT, RST, clock);
- the SD card: none, SDMMC or SPI;
- the LED, and the Wi-Fi transmit power cap.

The form checks each pin against the chip's rules as you type: pins used by flash and PSRAM
are refused, strapping pins get a warning, and input-only pins and pins used twice are
caught. The firmware checks the definition again at boot.

Saved boards go in the `boards/` folder of the controller's data directory. The builder
lists them with the shipped catalog. They are JSON files, in the same format as [`boards/`](../boards/)
([field reference](../boards/README.md)). For example:

```json
{
  "name": "my-s3-w5500",
  "title": "My ESP32-S3 board with a W5500",
  "image": "esp32s3-octal",
  "flash_mb": 16,
  "psram_mb": 8,
  "tier": "untested",
  "spi": [{ "host": 2, "sclk": 13, "mosi": 11, "miso": 12 }],
  "ethernet": { "kind": "w5500", "spi_host": 2, "cs": 14, "int": 10, "rst": 9 },
  "sd": { "kind": "spi", "spi_host": 2, "cs": 4 },
  "led": { "kind": "gpio", "pin": 48 }
}
```

A board you leave without a `memory` section gets its chip image's default sizes. Those
defaults are first guesses for chips other than the P4 and the S3 with octal PSRAM.

The node's address is not part of the board. The builder asks for it each time it flashes
a node.

A board that works for you can be shared with the project as a **community** board: open a
pull request that adds its file to `boards/`.

## Power and cost

**Power.** About 1 W per node. The ESP32-P4 board measured 0.53 W, idle and at 200
queries a second alike. Nodes never use light sleep, which would drop the network link;
idle nodes lower their CPU clock instead, where the board allows it. Power each board over
USB, or the Waveshare board over PoE from the switch.

**Cost.** Each node is one board, a microSD card and a cable or power supply. The tested
boards cost roughly US$15 to US$40 each, plus a few dollars for a W5500 module or a PoE
module where you need one. Prices change: check current ones.
