# Board catalog

One JSON file per board. The controller's builder lists these, turns one into the node's
`board` partition and flashes it with the chip image the board names. The firmware reads it
at boot (`firmware/main/board_def.c`). See [Architecture, Boards and images](../docs/architecture.md#boards-and-images).

Your own boards go in the controller's `/data/boards/`, in the same format.

| Field | Meaning |
|---|---|
| `name` | Short name, 1-23 characters: shown in `/status` and on the dashboard |
| `title` | Full name of the board |
| `image` | Chip image it runs: `esp32p4-rev1`, `esp32p4`, `esp32s3-octal`, `esp32s3-quad`, `esp32`, `esp32c3`, `esp32c6` |
| `flash_mb`, `psram_mb` | Flash and PSRAM sizes: flash picks the flash layout (4 MB, or 8 MB and up); PSRAM (0-64) is what the memory plan has, never more than the chip finds (left out: what it finds) |
| `tier` | `tested` (on hardware every release), `community` (reported working) or `untested` |
| `spi` | Up to two SPI buses: `host` (2 or 3), `sclk`, `mosi`, `miso` |
| `ethernet` | `kind`: `none`, `emac` (the chip's MAC with a PHY) or `w5500`. `optional`: an add-on that may not be fitted |
| `ethernet` (emac) | `phy` (`ip101`, `lan87xx`, `rtl8201`, `dp83848`), `addr` (0-31, -1 to search), `reset`, `power` (PHY or oscillator enable pin), `mdc`, `mdio`, `rmii_clock` (`{"mode": "in" or "out", "gpio": n}`) |
| `ethernet` (w5500) | `spi_host`, `cs`, `int`, `rst`, `mhz` (default 20) |
| `sd` | `kind`: `none`, `sdmmc` (`slot`, `width` 1 or 4, `ldo` channel powering the IO bank) or `spi` (`spi_host`, `cs`) |
| `led` | `kind`: `none`, `gpio` (`pin`, `active_low`) or `ws2812` (`pin`) |
| `wifi` | `tx_power_dbm`: transmit power cap, 2-20 (default: the chip's maximum, 20) |
| `memory` | The memory plan's values (below): how much each service gets. A key left out is the chip image's default |
| `cpu` | Idle clock scaling (below): `dfs` (true or false) and `min_mhz`, the clock it idles at. A key left out is the chip image's default |
| `network` | Not in catalog files: the node's address, which the builder adds for the node it flashes. `address` with its prefix length and `gateway` (`{"address": "192.0.2.52/24", "gateway": "192.0.2.1"}`), or `{"address": "dhcp"}` for a network with a DHCP server. A node config's `network` overrides it; without either the node has the address its image was built with, or none: it never asks DHCP on its own |
| `notes` | Free text for the builder |

**Memory** (`firmware/main/memplan.h`; [Architecture, Memory plan](../docs/architecture.md#memory-plan-from-board-data)). Fixed per board and found by
testing, never worked out from free memory: a node checks every node config's services
against them and refuses one that doesn't fit, and so does the controller before it pushes
one. A service's data goes in PSRAM where the board has some, else internal RAM; PSRAM less
1 MB for the system is what the services may plan. All KB except `cache_entries` and
`fwd_pending`:

| Key | Range | What | `esp32p4(-rev1)` default | `esp32s3-octal` default | No PSRAM |
|---|---|---|---|---|---|
| `internal_kb` | 16-65536 | Internal RAM the services may take (stacks, the blocklist indexes, all their data without PSRAM), besides the system's | 320 | 160 | the image's (96-160) |
| `cache_kb` | 16-65536 | The DNS cache: at least 8 KB plus 108 bytes per answer (`cache_entries`) | 4096 | 2944 | 64 |
| `cache_entries` | 16-1048576 | Answers the cache holds at most | 8192 | 8192 | 512 |
| `blocklist_kb` | 16-65536 | The blocklist and overrides, two copies of each during a live swap: a list that fits it whole takes the RAM tier, else the SD tier | 20480 | 2048 | 128 |
| `blocklist_index_kb` | 0-65536 | Internal RAM for the lists' indexes; 0 puts them with the lists | 160 | 0 | 0 |
| `hosted_zones_kb` | 16-65536 | The most the hosted zones may take (the plan holds three times it: the zones, a new bundle, its payload) | 64 | 64 | 64 |
| `secondary_zones_kb` | 16-65536 | Every secondary zone, with a new copy during a transfer | 1024 | 256 | 64 |
| `querylog_kb` | 0-65536 | The query log's ring of recent queries, 160 bytes each (1024: 6553 queries; 64: 409); 0: no query log | 1024 | 64 | 0 |
| `fwd_pending` | 2-1024 | Upstream queries outstanding at once, about 1.6 KB each (the table in `firmware/main/flight.h`): the default forwarders and the forward zones may each hold at most half of them | 32 | 32 | 8 |

The defaults are the production boards' sizes from before the plan: the same cache on the
P4, the same hosted zones limit and stacks; for the lists, which used to take whatever PSRAM
was free beyond 5 MB, a fixed share that fits next to every other service's (the P4's holds
two 8 MB lists for a live swap). On the S3-ETH's 8 MB the cache is 2.9 MB (3 MB less the
128 KB the forward loop's TCP buffer took), still over 300 bytes for each of its 8192
answers (before the plan it grew as answers came and rarely passed 2 MB), so the lists keep
the ~2 MB its free PSRAM allowed them: the RAM tier to
~650k domains (half that to swap one live), the SD tier to ~1.3M. The `esp32s3-quad`,
`esp32`, `esp32c3` and `esp32c6` ones are first guesses; without PSRAM the DNS service's
buffers (849 KB with its 8 upstream query slots) don't fit internal RAM, so those boards
wait for phase F's sizes. The tested boards state theirs explicitly, so a node whose board
partition was written before these keys runs the same.
The query log's (`querylog_kb`) is what each board's PSRAM has left next to the other shares:
1 MB on the P4, 64 KB on the S3s' 8 MB (the S3-ETH's services then plan 7098 of its 7168 KB);
`esp32s3-quad` and `esp32` 32, `esp32c3` and `esp32c6` 16 (first guesses), none without PSRAM.
The final values per board come from measurements on the boards.

**CPU clock** (`firmware/main/cpuplan.h`). With `dfs` the CPU runs at
the image's clock while it has work and drops to `min_mhz` while it waits (ESP-IDF's dynamic
frequency scaling; never light sleep, which would drop the link). A node config's
`"cpu": {"dfs"}` turns it on or off live, for a latency-sensitive node or to measure; the idle
clock is the board's. `min_mhz` must be one the image allows:

| Image | Clock | `min_mhz` allowed | Default | Why |
|---|---|---|---|---|
| `esp32p4` | 400 | 100, 200 | on, 200 | Same PLL (a divider change); APB 100 MHz, the MAC and SD clocks unchanged; 200 keeps the 200 MHz PSRAM at full speed |
| `esp32p4-rev1` | 360 | 90, 180 | **off**, 180 | Below 360 is below the PSRAM's 200 MHz: each switch (down on idle, up on every interrupt) stalls the other core and moves flash and PSRAM to 20 MHz and back. Measured: 0.53 → 0.51 W, not worth it; on by config if wanted |
| `esp32s3-octal`, `esp32s3-quad` | 240 | 40, 80, 160 | on, 80 | 80 stays on the PLL: APB, the W5500's SPI clock and the octal PSRAM timing are untouched. 40 (the crystal) changes them |
| `esp32c3`, `esp32c6` | 160 | 40, 80 | on, 80 | As the S3; Wi-Fi keeps 80 while its radio is awake anyway |
| `esp32` | 240 | 40 | **off**, 40 | The built-in MAC holds the APB at its maximum, 240 MHz on this chip: a wired ESP32 never clocks down. A Wi-Fi board may turn it on |

While the built-in MAC runs, or Wi-Fi stays awake (power saving off), the node idles no lower
than the APB maximum: 90/100 MHz on the P4 (below its idle clock), 80 on the S3, C3 and C6,
240 on the ESP32. `/status` `cpu` says what it idles at (`idle_mhz`).

Pins are GPIO numbers; leave one out for "not connected" or "the chip's default". The
firmware checks ranges and that no pin is used twice; the builder also checks each pin
against the chip's rules (flash and PSRAM pins, strapping pins, input-only pins).
