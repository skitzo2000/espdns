# espDNS architecture

This document explains how espDNS works: what a node does, what the controller does, and how
changes get from one to the other safely. It describes the code as it is today, in the
0.0.x alpha. Anything not built yet is marked as such.

For the security model, see [security.md](security.md). For making and checking a release,
see [releasing.md](releasing.md).

## Contents

- [The idea](#the-idea)
- [Goals](#goals)
- [Scope](#scope)
- [Principles](#principles)
- [The node](#the-node)
- [Answering a query](#answering-a-query)
- [Forwarding: the pending table and the forward loop](#forwarding-the-pending-table-and-the-forward-loop)
- [Zones](#zones)
- [Blocking](#blocking)
- [Storage](#storage)
- [Memory plan from board data](#memory-plan-from-board-data)
- [Boards and images](#boards-and-images)
- [Boot](#boot)
- [Addresses and adoption](#addresses-and-adoption)
- [Health](#health)
- [Observability](#observability)
- [Signed releases and pins](#signed-releases-and-pins)
- [Rolling updates](#rolling-updates)
- [The controller](#the-controller)
- [The data directory](#the-data-directory)
- [Not built yet](#not-built-yet)

## The idea

espDNS is reliable internal DNS on cheap, low-power ESP32 boards.

A basic setup is **two nodes and one Docker container**:

- Each **node** is an ESP32 board with Ethernet and a microSD card. It answers DNS.
- The **controller** is a Docker container. It sets nodes up, signs changes and pushes
  them to the nodes.
- Your router hands out both nodes as the clients' DNS servers. If one node is down,
  clients use the other.

```
          router: clients' DNS = node A, node B
                          │
   ┌──────────── controller (Docker, can be off) ────────────┐
   │ web UI · CLI · release signer · blocklist compiler       │
   │ adoption · config and zone editors · rolling push        │
   └──────┬────────────────────────────────┬──────────────────┘
          │  signed releases, only when you change something
   ┌──────▼──────┐                  ┌──────▼──────┐
   │   node A    │                  │   node B    │   each runs alone from flash + SD
   └──────┬──────┘                  └──────┬──────┘
          └── zone transfers from your primary (optional, per zone) ──┘
```

Most resolvers try the first DNS server and move to the second after a timeout of a few
seconds. So while one node reboots, some clients see a short delay, not a failure. You can
add more nodes the same way.

Pi-hole-style blocking is optional. It never gets in the way of answering: a node that
can't block still answers.

## Goals

In priority order. When two goals conflict, the higher one wins.

1. **Always answering.** At least one node answers at all times, including during updates.
   Nothing optional (blocking, logs, zone checks, the clock, the SD card) may delay or stop
   a node answering. A failure there makes the node *degraded*, not silent.
2. **Easy to stand up.** Two boards and one container. Flash each board from the browser,
   adopt it from the web UI, and hand both nodes out as the clients' DNS servers. No
   toolchain and no hand-edited files are needed for that.
3. **Efficient on low-power hardware.** A node runs only the services its config enables.
   A service that is off costs nothing. A node draws about half a watt to a watt.
4. **Fast cold start.** A node answers DNS within 15 seconds of power-on, with no
   controller and no zone primary reachable.
5. **Optional blocking.** Adlists, allow and deny rules, overrides, pause, a query log and
   a dashboard.
6. **Cheap.** Roughly US$20 to $40 per node.

## Scope

- **Your router owns the network.** It gives clients their DNS server list, sends IPv6
  router adverts, provides the time and routes traffic. espDNS does not run DHCP. It does
  not stop clients using other resolvers (for example IPv6 DNS from router adverts, or a
  browser's DNS over HTTPS). Setting up the router is part of setup.
- **Nodes forward.** They do not resolve from the root servers.
- **Not supported yet:** one shared IP address for several nodes, and Pi-hole regex rules.

## Principles

1. **Nodes never depend on the controller.** The controller builds, signs and pushes. You
   can switch it off at any time. A node never contacts the controller. At run time a node
   talks only to DNS clients, its upstream forwarders, its zone primary (if it has one) and
   NTP servers.
2. **Answering comes first.** The DNS listeners open before anything optional starts.
   Blocking, the query log, zone checks and the clock all start after the node answers.
3. **Never take down the last healthy node.** The controller changes one node at a time and
   waits for it to come back healthy. It refuses to start a change that needs a reboot
   while another node is unhealthy, unless you force it.
4. **Make faults obvious.** A degraded node says so in `/health`, in the controller, and on
   an LED, so you can find the bad board and swap it.

## The node

The node firmware is a small operating system, not a fixed program. It is built on ESP-IDF
and FreeRTOS.

- **One image per chip, not per board.** The same image runs on every board with that chip.
  A small data file in flash (the board definition) says how the board is wired. The image
  holds no board details, no site settings and no secrets.
- **Services.** Each feature is a service that can start and stop: the DNS listeners and
  cache (always on), forwarding, forward zones, secondary zones, hosted zones, blocking and
  the query log. The node config says which ones run. A service that is off has no task, no
  stack, no buffers and no timers.
- **Live where possible.** Turning forwarding, hosted zones, blocking or the query log on or
  off applies at once, without a reboot. Changes that need new memory layout or a new
  network address wait for a reboot, which the controller schedules.
- **No allocation on the query path.** Each service takes its memory from its share of the
  memory plan when it starts. The cache, the worker buffers and the receive pool are set
  aside up front.
- **Tasks and watchdogs.** Each running service is a FreeRTOS task with a fixed stack and
  priority. A supervisor watches them:
  - If the UDP receive task or TCP accept task stalls (or every UDP worker at once), the node
    is not answering, so it reboots. It does this at most 3 times in a row. After that it
    stays up in *fault* for you to look at, rather than boot-looping.
  - If an optional service fails to start, it is retried after 5 s, then 10 s, 20 s and so
    on up to 5 minutes. After 3 failures in a row the node is *degraded*.
  - If the forward loop stops checking in, the node is *degraded* and keeps answering from
    its cache and local zones. It does not reboot for that.
  - The node never reboots for anything else.
- **Idle means idle.** Services wait on events and do not poll. On chips where it is safe,
  the CPU clock drops when idle (ESP-IDF dynamic frequency scaling). The board definition
  sets the default, and the node config can turn it on or off live.

The node's tasks, in short:

| Task | What it does |
|---|---|
| UDP receive | Takes each query off the socket into a fixed pool and queues it |
| UDP workers | Answer queries from the cache, local zones and blocking; hand the rest to the pending table |
| TCP accept and workers | DNS over TCP, one connection per worker |
| Forward loop (`dns_fwd`) | Sends every outstanding upstream query and collects the answers |
| Forward TCP (`dns_fwdtcp`) | Retries truncated upstream answers over TCP, one at a time |
| Zone task | SOA checks, NOTIFY handling and zone transfers for secondary zones |
| Load tasks | Load blocklists and hosted zones from SD in the background |
| Clock | Sets the time over SNTP after the listeners open |
| HTTP server | `/status`, `/health`, `/metrics`, `/querylog`, and signed releases |
| Supervisor | Watchdogs and restarts, as above |

## Answering a query

For each query the node checks, in order:

1. **Local authoritative zones.** A secondary zone (copied from your primary) or a hosted
   zone (pushed by the controller). The zone with the longest matching name wins. A name is
   never in two kinds of zone at once. Local answers are never blocked.
2. **Blocking**, if the blocking service is on. A blocked name gets `0.0.0.0` for A, `::`
   for AAAA and an empty answer for other types, with a 10-second TTL. NXDOMAIN can be
   chosen instead. Blocked answers are never cached.
3. **Forward zones** (conditional forwarders): a zone whose queries go to its own
   forwarder.
4. **The cache, then the default forwarders.** If blocking is on, CNAME targets in a
   forwarded answer are checked against the lists once, when the answer enters the cache.
   This catches trackers hidden behind first-party names.

If a node has no default forwarders, a query that would go to them is answered **REFUSED**.
That tells the client to ask its next server at once.

**The cache key** is the question: the name (case-insensitive), the type, the class and the
CD bit. One entry answers every equivalent query, whatever its EDNS options. Upstream
queries always ask with DO set, so an entry holds DNSSEC records; a client that did not ask
for them gets the answer without them.

## Forwarding: the pending table and the forward loop

A slow or dead forwarder must not tie up the node. So no DNS worker ever waits for a
forwarder.

**The pending table** (`firmware/main/flight.*`) holds the upstream queries that are in
flight. There is one entry, a *flight*, per question:

- When a forwarded name's cache entry expires, many queries can miss at once. The first one
  opens a flight. Every query for the same question waits on that flight and gets its one
  answer, or SERVFAIL if it fails.
- A UDP query is *parked* on the flight. The worker goes straight back to the receive
  queue. A TCP query waits on its own worker.
- The table has a fixed number of slots (`memory.fwd_pending` in the board definition: 32
  by default, 8 on chips without PSRAM). Each flight belongs to a group: the default
  forwarders, or one forward zone. A group may use at most half the slots and half the
  parked queries. So a forward zone with a dead forwarder can never starve the default
  forwarders. A query past its group's share is answered SERVFAIL at once.
- At most half of the UDP receive queue may be parked at once, so queries for other names
  keep their room.

**The forward loop** (`firmware/main/fwdq.*`) is one task that drives every slot of the
table with a single `select()`:

- Each flight has its own socket, bound to a random source port, and a random query ID. An
  off-path attacker must guess both to forge an answer.
- Each flight has one deadline for the whole attempt: every forwarder tried twice in turn,
  each try bounded by the node's `upstream_timeout_ms`, plus one TCP retry for a truncated
  answer, plus a small margin. When the budget is spent, the flight ends.
- A finished flight wakes a worker. The worker caches the answer, answers every parked
  query from it, and gives the slot back.
- A truncated answer is asked again over TCP by a second task, through one 64 KB buffer.

## Zones

Each zone has exactly one source:

- **Secondary.** Copied from your zone primary over AXFR, saved to the SD card, refreshed
  on NOTIFY and SOA checks. The nodes are plain RFC secondaries, so any standards-compliant
  primary works: BIND, Knot, PowerDNS, Windows DNS, Technitium and others. A NOTIFY is only
  accepted from the configured primary's address.
- **Hosted.** espDNS is the primary. You keep zones as standard RFC 1035 zone files in the
  controller. The controller checks them and sends all of a node's hosted zones as one signed
  bundle. Supported types: A, AAAA, CNAME, MX, TXT, SRV, NS, PTR, CAA and SOA (no DNSSEC
  signing). At most 32 hosted zones per node, within the board's memory share for them.
  A new bundle is swapped in live. Nodes do not serve zone transfers for hosted zones; every
  node gets the bundle from the controller.
- **Forward zone.** Queries under the zone go to a named forwarder.

One setup can mix all three. The controller refuses a zone that would be both hosted and
secondary (or forward) on the same node, and so does the node.

Secondary zones loaded from the SD card answer at boot, before any check with the primary.

## Blocking

Blocking is an optional service. When it is off, none of this runs or uses memory.

**The controller compiles; nodes only receive.** The controller downloads and parses your
lists, removes duplicates, and writes one compact file. It signs the file and pushes it to
every node as a release. Every node gets the same bytes. Nodes never fetch lists themselves.

**Sources** can be hosts files, plain domain lists, adblock-style `||domain^` lists, and RPZ
zones. Each is a local file or an https URL. Allow lists work the same way.

**The file format** stores 44-bit SipHash-2-4 hashes of the names in sorted tables,
compressed with Elias-Fano coding per 512-byte sector. About 3 to 3.6 bytes per domain. There
are separate tables for exact names and for suffixes (a name and all its subdomains), for
both block and allow entries. The hash key is new for each build, so a collision can't be
planned in advance. The compiler also checks a list of popular domains and drops any
blocked entry whose hash would match one of them.

**The decision.** The most specific match wins. On a tie, allow beats block. Overrides (a
small allow/deny file pushed separately) are checked first and apply live.

**Where the list lives.** On SD, in two slots, so the previous list is always kept:

- If the board's memory share for blocking holds two copies, the node loads the new list in
  the background and swaps it in live.
- If not, the new list is stored and loaded at the next reboot, which the controller
  schedules.
- If the whole table fits in memory, lookups run from RAM (a few microseconds). If not, the
  node keeps only an index and a small filter in RAM, and reads one SD sector for likely
  matches.

**Pause** turns blocking off for a set time (at most a week from the controller). A reboot
ends a pause. **Revert** goes back to the previous list in the other slot.

**Checks before a push.** The compiler refuses a build whose size changes by more than a set
percentage from the last build (20% by default), or that blocks a name on your must-resolve
list. You can accept one such build explicitly.

## Storage

| What | Where on the node |
|---|---|
| Firmware | Two OTA app slots in flash, with automatic rollback |
| Board definition | The `board` flash partition (4 KB), written when the board is flashed |
| Node config | The `config` flash partition, two 16 KB slots |
| Wi-Fi network from setup | NVS (flash), set over USB during flashing |
| Release sequence numbers | NVS |
| Secondary zones | SD card |
| Hosted zones | SD card, two slots |
| Blocklist and overrides | SD card, two slots each |
| Query log | RAM only |

Every kind of data with two slots keeps the previous copy. At boot the node loads the valid
copy with the highest sequence number. If it had to fall back to an older copy, the node
says so: *degraded*, reason `older copy`.

**If the SD card fails** or is too slow at boot, the node keeps answering from its config
and forwarders. Secondary zones are transferred again and kept in RAM only. Hosted zones and
blocking are unavailable. The node reports *degraded*, reason `sd card`.

## Memory plan from board data

Nothing on the node looks at free memory to decide a size. Instead, each board definition
lists fixed sizes in its `memory` section, found by testing that board:

`internal_kb`, `cache_kb`, `cache_entries`, `blocklist_kb`, `blocklist_index_kb`,
`hosted_zones_kb`, `secondary_zones_kb`, `querylog_kb` and `fwd_pending`, plus `psram_mb`.

Any value the board leaves out comes from the chip image's default. The full list is in
[`boards/README.md`](../boards/README.md).

At boot, and for every config pushed, the node works out a plan for the services the config
enables:

| Service | Internal RAM | Data (PSRAM if the board has it, else internal RAM) |
|---|---|---|
| dns | Listener, worker and forward-loop stacks | The cache, worker buffers, the UDP receive pool, the forward loop's TCP buffer, and the pending table |
| secondary | The zone task's stack | `secondary_zones_kb` and the transfer buffers |
| hosted | The load task's stack | Three times `hosted_zones_kb` (the zones, a new bundle being checked, its payload) |
| blocking | The load task's stack, `blocklist_index_kb` | `blocklist_kb` (the list and overrides, two copies during a live swap) |
| querylog | None | `querylog_kb`, 160 bytes per entry |

A config whose plan does not fit the board is refused. At boot the node falls back to the
previous config (or the firmware defaults) and reports *degraded*, reason `config`. A bad
plan never half-starts.

The controller runs the same plan, from the same test vectors, before it pushes a config.
You can check a config against a catalog board yourself, from `controller/`:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  config -check -file /data/configs/node1.json -board ws-s3-eth -data /data
```

## Boards and images

Only a few things are fixed when an image is compiled: the chip, the PSRAM type, the P4
silicon revision and the flash layout. Everything else about a board is data.

| Chip image | For |
|---|---|
| `esp32p4-rev1` | ESP32-P4 silicon v1.x (wired only) |
| `esp32p4` | ESP32-P4 v3 and later |
| `esp32s3-octal` | ESP32-S3 with octal PSRAM |
| `esp32s3-quad` | ESP32-S3 with quad PSRAM or none |
| `esp32` | Classic ESP32 |
| `esp32c3`, `esp32c6` | Single-core chips without PSRAM |

Each image contains every driver its chip can use: the built-in Ethernet MAC with the
supported PHYs (IP101, LAN87xx, RTL8201, DP83848), the W5500 SPI Ethernet chip, SD over SDMMC
or SPI, Wi-Fi, and the LED drivers. Drivers a board does not use cost flash, not RAM.

**The board catalog** is a set of JSON files, shipped in [`boards/`](../boards/). Each board
is marked *tested*, *community* or *untested*. The boards tested on hardware today are:

- Guition JC-ESP32P4-M3-DEV (ESP32-P4, built-in Ethernet with an IP101 PHY, SDMMC)
- Waveshare ESP32-S3-ETH (W5500 Ethernet, optional PoE, SD over SPI)
- Seeed XIAO ESP32S3 Sense (Wi-Fi, or wired with an added W5500 module)

**The builder** is a page in the controller. You pick a board (or describe your own, with
its pins checked against the chip's rules), give the node its address, and flash it over
USB from the browser (ESP Web Tools). The controller assembles the image from the chip image
and a `board` partition in milliseconds. It does not compile anything. For a Wi-Fi board,
the same page then sends the network name and password to the node over USB (Improv Wi-Fi).

**Settings come in layers.** A value comes from the first of:

1. the node config (signed, pushed by the controller);
2. the board definition (the catalog's values, plus the node's address from the builder);
3. the firmware's default.

The board definition can only be changed by flashing the board again over USB. There is no
signed release kind for it.

**Wired is the supported way.** Wi-Fi is a best-effort fallback for boards without
Ethernet. At least one node in a setup should be wired; the controller's pages warn when
only Wi-Fi nodes are answering.

## Boot

**Requirement: DNS answered within 15 seconds of power-on.** Only these steps may stand
before the DNS listeners open: the bootloader and image check, PSRAM start-up, the Ethernet
link, the address, and mounting the SD card (in parallel, with a 1.5-second limit).

After the listeners open, and never in front of them:

- **Blocking** loads in the background. Answers in that window are simply not blocked.
- **Zone checks** with the primary run while saved zones already answer.
- **The clock** is set over SNTP: from the configured NTP servers, else the default gateway,
  else `pool.ntp.org`. An unsynced clock is not a fault.
- **Forwarders** that can't be reached never delay local answers.

The node records the time from start to listeners open as `boot_ms` in `/status`. A new
firmware that misses the 15-second limit fails its health check and rolls itself back. (On
DHCP the limit is reported but not enforced, because a DHCP server can be slow.)

## Addresses and adoption

A node never asks DHCP for an address unless one of its settings says `"dhcp"`. Its address
comes from the first of:

1. its node config (`network`), once it is adopted;
2. its board definition (`network`), written when it is flashed.

With neither, the node has no address. It says so on its LED and serial console, and sends
nothing.

How a node gets its first address depends on how you flash it:

- **From the controller's builder.** You give the node a static address (with prefix length
  and gateway), or `dhcp` for a network that has a DHCP server. The builder refuses to make
  an image with no address.
- **From a release's factory image.** A release cannot know your addresses, so its factory
  images start on **DHCP**. Adoption then gives the node its own static address, if you
  want one. On a network without a DHCP server, flash new nodes from the builder instead.

**Adoption**, from the controller's web UI or the CLI:

1. **Discovery.** Nodes advertise `_espdns._tcp` over mDNS. The controller lists nodes that
   are not adopted yet, with their board, firmware, address and **MAC address**. The MAC has
   a copy button, so you can make a DHCP reservation in your router or note it down. You can
   ask a node to *identify* (blink its LED) to match it to the board in your hand.
2. **Address.** The node keeps the address it runs on, or you give it a static one. Before a
   node moves, the controller checks that nothing else answers on the new address. A network
   listed in `settings.json`'s `"no_dhcp"` never gets a config on DHCP.
3. **Zone primary.** For each secondary zone the node will carry, the node's address must be
   allowed to transfer the zone and receive NOTIFY. With a `manual` primary (the default, for
   any primary) the controller shows you the exact change for each zone and waits for you to
   confirm it. With the `technitium` driver it makes the change over Technitium's API.
4. **Config.** The controller pushes the node's config. A new address waits for a reboot,
   which the controller then does.
5. **Confirm.** A config that changes the address or Wi-Fi network boots *on trial*. It is
   kept once a DNS query reaches the node on its new address. If none arrives within 90
   seconds, the node goes back to its previous config.
6. **Pin.** The controller records the node's ID against its address (see
   [pins](#signed-releases-and-pins)).

Once two nodes are adopted, give both addresses to your router as the clients' DNS servers.

## Health

Every node reports one state, in `/health` and `/status`:

| State | Meaning | Answering? |
|---|---|---|
| booting | Before the listeners open | No |
| healthy | Everything its config enables is running | Yes |
| degraded | Answering, but something enabled failed | Yes |
| no network | Link down or no address | No |
| fault | The listeners failed, or stalled 3 times in a row | No |
| updating | Receiving a release | Yes |

`/health` returns **200 while the node answers** and 503 otherwise, so a load balancer or
monitor only needs the status code. It also lists every reason that holds, for example
`sd card`, `blocking`, `zone expired`, `zone refresh failing`, `forwarders failing`,
`forwarders slow`, `forwarder task stalled`, `config`, `hosted zones`, `service failed` and `older copy`. Only
the services the config runs count. `reboot pending`, `config on trial` and
`service restarting` are listed but do not make a node degraded.

**LED patterns** work on a single-colour LED, and use colour on an RGB LED: a short blip
every 5 seconds when healthy, two blinks when degraded, a slow blink with no network, solid
on for a fault, and a fast flicker to identify. A board without a usable LED can use an
add-on LED on a spare pin, named in the node config.

## Observability

- **`GET /metrics`**: Prometheus text format. Query counts by result and rcode, answer-time
  histograms, per-forwarder counts and times, cache and blocking counters, zone state, each
  service's memory, health state and reasons. Counters are lock-free 32-bit atomics.
- **`GET /querylog?cursor=N&limit=M`**: the query log, an optional service. A ring of recent
  queries in memory (160 bytes each). The node config's `querylog.client` can store each
  client's address in `full`, as its `/24` (`subnet`), or not at all (`hidden`).
- **The controller's Traffic page** polls each node's `/status` and `/metrics` every 10
  seconds and keeps one hour of history in memory. It reads the query log into a buffer of
  the newest 20,000 entries. Nothing of this is written to disk; a restart starts over.

`/health` and `/metrics` are open to anyone who can reach the node, so your existing
monitoring can watch nodes with the controller off. See [security.md](security.md) for who
can read `/status` and `/querylog`.

## Signed releases and pins

Every change to a node is a **signed release**: firmware, config, hosted zones, blocklist,
overrides, and control commands (pause, identify, flush cache, reboot, revert). The format is
in `firmware/main/release.h`:

| Field | Purpose |
|---|---|
| Kind | What the payload is |
| Key slot | 0 = release key, 1 = offline recovery key |
| Target node | The node's ID (its eFuse base MAC), so a release can't be used on another node |
| Chip image | The image name, so a release can't be used on the wrong hardware |
| Sequence number | Must be above the last one the node took for that kind |
| Payload length and SHA-256 | Checked while the payload streams in |
| Signature | ECDSA P-256 over the 128-byte manifest |

- **Only public keys are in the firmware.** The firmware carries the release public key and
  the recovery public key. Images contain no secret and can be shared.
- **The node checks the signature first,** before anything else in the manifest and before
  it erases anything.
- **Sequence numbers** are milliseconds since 1970 (or one more than the last). The node
  keeps the last one per kind in NVS, so replays and downgrades are refused, even after a
  reboot. To roll back, the controller signs the older payload again with a new number.
- **The sequence bound.** A sequence number is kept for good, so one far in the future would
  lock a node out. Once its clock is set, a node refuses a number more than 24 hours past its
  clock. The controller never signs a number more than 24 hours past its own clock.
- **Pins.** A node's `/status` says who it is, but anything that answers on the node's
  address could send one. So the controller keeps its own record in the data directory
  (`pins/<node-id>.json`): each node's ID, pinned to its address at adoption, and the last
  sequence number signed for it per kind. A release is signed only for the ID pinned to the
  address, with the next number after the recorded one. A `/status` that answers as another
  node is refused. An address with no pinned node gets nothing signed, except an *identify*
  for a node being adopted. To pin a replaced board, or a node adopted before pins, from
  `controller/`:

  ```sh
  docker compose run --rm --entrypoint /espdns espdns-controller pin -data /data -host <address> -node <node ID>
  ```

**Firmware updates** are safe to fail. A new image boots on trial. It must get its address,
open its listeners and answer within its limits. If not, the bootloader rolls back to the
previous image.

**Reboot pending.** A node never reboots itself to apply a release. A release that can only
apply at boot is stored and checked, and the node reports `reboot pending` with the reason
(for example `config: address`, `blocklist: size`, `firmware`). The controller decides when
each node reboots, so it never takes two down at once. The node reboots on its own only to
undo a failed config trial or a failed firmware update.

**What applies how:**

| Kind | Where it lives | Applied |
|---|---|---|
| Firmware | OTA app slots | At a reboot, now or when the controller schedules it |
| Config | `config` partition, two slots | Live where the setting allows, else at the next reboot |
| Hosted zones | SD, two slots | Live |
| Blocklist | SD, two slots | Live if two copies fit, else at the next reboot |
| Overrides | SD | Live |
| Control | Not stored | Live |

Releases of the project itself are signed the same way: see [releasing.md](releasing.md).

## Rolling updates

Every push from the controller, whether from the web UI or the CLI, goes through one
rolling push (`controller/internal/rolling`, `controller/internal/fleet`):

1. **Check first.** Before it touches any node, the controller checks every target: the
   services it runs, its memory plan for a config, zone conflicts for hosted zones.
2. **One node at a time.** Before each change, and again just before a reboot, it checks the
   rule: another node (or a DNS peer, below) must be answering, and for a change that may
   reboot, every other one must be healthy. `-force` goes ahead with just one other node
   answering.
3. **Wait for it.** The controller waits for the node to come back on the new build or
   sequence number, healthy, and passing DNS checks, before the next node starts.
4. **Canary and soak for blocklists.** A new list goes to one node first (the canary). The
   controller sends real DNS queries to it: a local name, a forwarded name, names it must
   block and your must-resolve list. Then it watches the node for a soak time (one minute by
   default) and checks again. Then each other node the same way.
5. **Revert on failure.** If a node that took a new list fails, every node that took it
   goes back to its previous list, the failed node first. Nodes not yet changed are not
   touched.

**DNS peers.** If clients also use another resolver (for example your existing DNS server),
you can list it as a DNS peer in `settings.json` (`"dns_peers"`). While it passes its DNS
checks it counts as one healthy node, so a single espDNS node can be rebooted safely.

**One change at a time.** Every job and every CLI command that changes a node first takes
the fleet lock (a file lock on `fleet.lock` in the data directory). A second change fails at
once and names who holds the lock. So two pushes never race a node's sequence numbers.

## The controller

The controller is one Go binary with its web UI built in, plus the `espdns` CLI, in one
Docker image. It does not compile firmware. You run it with Docker Compose from
`controller/` ([`compose.yaml`](../controller/compose.yaml)), as
[Getting started](getting-started.md#5-start-the-controller) sets it up.

The dashboard is at http://127.0.0.1:8480. The controller listens on localhost only and
refuses any other address. It uses host networking so it can find nodes over mDNS and reach
them on your LAN.

**Pages:** Nodes (state, version, health, identify, add node), Zones (hosted zone editor and
the zone inventory), Blocklists (sources, overrides, compile, pause, revert), Traffic (charts
and the query log), and System (job history, push, configs, adoption, the builder, backup,
the release key and the zone primary).

**How it works:**

- **Node list.** The nodes in `settings.json`, the ones found over mDNS, and any you look up
  by address. Each is polled (`/status`) every 10 seconds. An mDNS answer is treated as a
  hint only: it never renames or moves a known node.
- **Jobs.** Fleet changes run as jobs, one at a time, with live progress in the browser.
  Every job and CLI change is written to the action log.
- **Pending changes.** Edits to node settings are collected as pending changes and sent by
  one apply job.
- **Zone primaries.** Getting a node onto a zone's transfer and NOTIFY lists is the only
  primary-specific step. It sits behind one driver interface (`internal/primary`). `manual`
  (the default) works with any primary and shows you the change to make. `technitium`
  drives Technitium's API over https.
- **CLI.** The same operations as the web UI. Run it from the same image:

  ```sh
  docker compose run --rm --entrypoint /espdns espdns-controller status -all -data /data
  ```

**Rebuilding it.** All state is in the data directory. `espdns backup` writes one encrypted
file (age format, to a passphrase or an age key), and `espdns restore` puts it back into an
empty data directory with the controller stopped. Without a backup, `espdns recover` reads
the nodes' `/status` (with the release key imported) and rebuilds `settings.json` and the
pins. Nodes do not return their configs or zone contents; those come from your own copies.

**The release key** is a file in the data directory, `keys/release.pem`, mode 0600. It is
imported from standard input with `espdns key import`, and only if the fleet trusts it: it
must match the firmware's built-in release key, or a node in `settings.json` must list it.
The recovery key is never imported. The controller does not create keys or change which
keys a node trusts. See [security.md](security.md).

## The data directory

Everything the controller keeps is in one directory: `/data` in the container, and
`controller/data` on the host by default (`ESPDNS_DATA` in `.env`). The controller and the
CLI share it. All state is JSON or plain files; there is no database. Every directory is
mode 0700 and every file 0600.

| Path | What |
|---|---|
| `settings.json` | The deployment: nodes, DNS peers, canary, networks with no DHCP server (`no_dhcp`), the zone primary, internal list servers. Example: [`configs/example-settings.json`](../configs/example-settings.json) |
| `auth.json` | The login: user name and an argon2id hash of the password |
| `keys/release.pem` | The release signing key |
| `keys/primary.token` | The zone primary's API token (API drivers only) |
| `configs/<name>.json` | Node configs, one file each. Example: [`configs/example-node.json`](../configs/example-node.json). Older versions in `configs/.history/`; the last pushed to each node in `configs/.pushed/` |
| `zones/<zone>.zone` | Hosted zone files. History in `zones/.history/`; the last pushed set per node in `zones/.pushed/` |
| `blocking/` | List definitions (`lists.json`) and local sources, allow lists and overrides |
| `lists/<name>.bin` | Compiled blocklist and overrides files |
| `boards/` | Your own board definitions from the builder |
| `firmware/images/` | Imported chip images, for the builder and firmware updates |
| `pins/<node-id>.json` | Each node's pinned ID and last signed sequence numbers |
| `changes/` | Pending changes not yet applied |
| `log/actions.jsonl` | The action log: every fleet change, by the CLI or the web UI |
| `log/jobs/` | Each job's record and progress log |
| `fleet.lock` | The fleet lock |
| `recovered/` | What `espdns recover` read from the nodes |

Back this directory up. It is the whole controller.

## Not built yet

These are planned but not in the code today:

- Signed reads: `/status` and `/querylog` protected by a request signed by the controller.
- Encrypted transport between the controller and the nodes, and DNS over TLS to forwarders.
- An endpoint for a node to return its config or zone contents (for recovery).
- Release key creation and rotation from the controller.
- Saving a secondary zone's last refresh time across reboots (today a zone's expiry timer
  starts again at each boot).
- Scheduled blocklist refreshes.
- One shared IP for several nodes, and per-client blocking groups.
- Wi-Fi through the ESP32-C6 companion on ESP32-P4 boards.
