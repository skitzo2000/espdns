# espDNS

espDNS is a full-featured DNS server for small, low-power ESP32 boards. Two or more nodes
answer for your network together, so one can be down or updating while clients keep
resolving. A web controller, run with Docker Compose, sets the nodes up and keeps them
updated.

> **Status: alpha (0.0.x).** It runs a real network today, but anything may still change
> between versions, including file formats and commands. Read the
> [changelog](CHANGELOG.md) before you update.

## Features

**On each node**

- **Hosted zones.** Make and edit your own zones in the controller. They reach the nodes as
  a signed bundle and apply live.
- **Secondary zones.** Copy zones from any standards-compliant primary (BIND, Knot,
  PowerDNS, Windows DNS, Technitium and others) by zone transfer, with NOTIFY. Zones are
  kept on the microSD card, so a node keeps answering when the primary is down.
- **Forwarders.** Names the node does not hold go to upstream resolvers. Forward zones send
  chosen names to their own servers. Recursion is for private client addresses only.
- **Cache.** In PSRAM, sized per board.
- **Blocklists.** Downloaded lists (adblock, hosts, domains, wildcard and RPZ formats, by
  URL or file) and your own lists, with allow lists. The controller compiles them, refuses
  a build whose size changes too much, and sends the same list to every node. You can
  pause blocking for a while, or go back to the previous list.
- **Overrides.** Your own block and allow rules on top of the lists, applied live.
- **Query log and charts.** Each node keeps a ring of recent queries. The controller shows
  the log and traffic charts. Every node also serves Prometheus metrics at `/metrics`.
- **Health.** Each node reports its state at `/health` and on an LED, and restarts a
  failed service on its own.

**Across the fleet**

- **Two or more nodes answering together.** Hand out every node as a DNS server. There is
  no leader and no shared state, and **a node never depends on the controller**: turn the
  controller off and DNS goes on.
- **Signed rolling updates.** Firmware, config, zones and lists are signed releases (ECDSA
  P-256), each bound to one node and refused if replayed. The controller updates one node
  at a time and never takes down the last healthy one.
- **A web controller.** Find and adopt nodes, edit their settings, zones and lists, review
  pending changes and apply them, flash new boards from the browser, back up and restore.
  The `espdns` command line tool is in the same Docker image.

## Quick start

You need a Linux machine with Docker, Docker Compose v2.17 or newer and git, two supported
boards with microSD cards, and Chrome or Edge to flash them. Then:

1. Clone the repository: `git clone https://github.com/skitzo2000/espdns.git`.
2. Make your own release key, and build the firmware with it, in the ESP-IDF Docker image.
   Nodes take changes only from the key built into their firmware, so you need your own.
3. Start the controller with `docker compose up -d --build` in `controller/`, and set its
   login with the `espdns passwd` command.
4. Import your release key and your firmware into the controller.
5. Flash each board from the controller's builder page, then adopt it.
6. Hand out both nodes as DNS servers from your router's DHCP settings.

[Getting started](docs/getting-started.md) gives every command, step by step.

## Supported boards

A board is a JSON file in the [board catalog](boards/README.md), not code. The firmware is
built once per chip, and the board file says how the board is wired.

| Board | Chip | Network | Tier |
|---|---|---|---|
| Guition JC-ESP32P4-M3-DEV (`p4-ip101`) | ESP32-P4, 32 MB PSRAM | Ethernet (built-in MAC) | Tested |
| Waveshare ESP32-S3-ETH (`ws-s3-eth`) | ESP32-S3, 8 MB PSRAM | Ethernet (W5500), optional PoE | Tested |
| Seeed XIAO ESP32S3 Sense (`xiao-s3-sense`) | ESP32-S3, 8 MB PSRAM | Wi-Fi, or Ethernet with an added W5500 | Tested |

Wire your nodes if you can; Wi-Fi is a best-effort fallback. Firmware is also built for the
classic ESP32, ESP32-C3, ESP32-C6, newer ESP32-P4 silicon and ESP32-S3 with quad PSRAM, but
no board with those chips is tested yet. Boards without PSRAM have no working memory sizes
yet. You can describe your own board in the controller's builder.

## Documentation

| Document | What it covers |
|---|---|
| [Getting started](docs/getting-started.md) | Make your keys, build the firmware, start the controller, flash and adopt two nodes |
| [Hardware](docs/hardware.md) | The tested boards, what a board needs, and describing your own board |
| [Zones and forwarding](docs/zones.md) | Hosted, secondary and forward zones, and the default forwarders |
| [Blocking](docs/blocking.md) | Blocklists, overrides, pausing, the query log and the charts |
| [Operations](docs/operations.md) | Updating the controller and the nodes, pinned nodes, backup, restore and recovery |
| [Troubleshooting](docs/troubleshooting.md) | Health states and reasons, LED patterns and common problems |
| [Architecture](docs/architecture.md) | How the nodes and the controller work, and why |
| [Security model](docs/security.md) | Keys, signed releases, the threat model and the known gaps |
| [Releasing](docs/releasing.md) | How a release is built, signed and checked, and how to use one |
| [Reference](docs/reference/README.md) | Every CLI command, setting, node config key, API route and node endpoint |
| [Board catalog](boards/README.md) | The board file format, memory and CPU settings |
| [Changelog](CHANGELOG.md) | What each version changed |
| [Contributing](CONTRIBUTING.md) | Bug reports, building, testing and pull requests |
| [Security policy](SECURITY.md) | How to report a vulnerability |

## Repository layout

| Path | What |
|---|---|
| `firmware/` | The node firmware (ESP-IDF) |
| `controller/` | The controller and the `espdns` CLI (Go, one Docker image) |
| `boards/` | The board catalog |
| `configs/` | An example settings file and node config, on documentation addresses |
| `docs/` | The documentation |
| `scripts/` | Version and release scripts |

## Versions

The firmware and the controller share one version, set in [`VERSION`](VERSION). It stays
0.0.x while espDNS is in alpha. To see the controller's version, from `controller/`:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller version
```

A node reports its version in `http://<node>/status`.

## License

espDNS is free software under the GNU Affero General Public License, version 3 only
(AGPL-3.0-only); the full text is in [`LICENSE`](LICENSE). If you run a changed version
for others over a network, the AGPL asks you to offer them its source.

The vendored ESP Web Tools bundle in
[`controller/web/vendor/esp-web-tools/`](controller/web/vendor/esp-web-tools/) keeps its
own license, Apache-2.0, which is compatible with the AGPL-3.0. Its `LICENSE` and
`THIRD_PARTY.md` there list it and the code it bundles.
