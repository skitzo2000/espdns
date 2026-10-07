# Node endpoints

Every node runs a small HTTP server on port 80. The controller uses it to watch and change
the node. You can read the same endpoints for monitoring.

Back to the [reference index](README.md).

| Method | Path | Who may call it | What it does |
|--------|------|-----------------|--------------|
| GET | [`/health`](#health) | anyone | Health in a few fields. 200 while the node answers DNS, 503 when it doesn't. |
| GET | [`/status`](#status) | anyone | Everything the node reports, as JSON. |
| GET | [`/metrics`](#metrics) | anyone | Prometheus metrics. |
| GET | [`/querylog`](#querylog) | private addresses only | The node's query log. |
| POST | `/ota` | private addresses only | A signed firmware release. |
| POST | `/release` | private addresses only | Any other signed release (config, zones, blocklist, overrides, control). |

Rules for every request:

- **Host check.** The `Host` header must name the node: its IPv4 address, its mDNS name
  (`<hostname>.local`), or the `name` from its node config, with or without a port. Anything
  else, an IPv6 literal, or no `Host` gets `421 Misdirected Request`. This stops DNS
  rebinding attacks from a web page.
- **No body on a GET.** A GET with a body gets `400`.
- **Deadlines.** Each request has one deadline for its headers and reply. A slow client is
  cut off.
- **Private addresses.** `/querylog`, `/ota` and `/release` answer `403` unless the client's
  address is in a private IPv4 range (RFC 1918) or the shared address space (RFC 6598).
- **Signed releases.** `/ota` and `/release` take only releases signed with a key the node
  trusts, bound to the node's ID. You send them with the controller or the
  [espdns CLI](cli.md), never by hand. How they are signed and checked is in
  [Architecture](../architecture.md#signed-releases-and-pins).

You can read a node from the controller's container with the CLI:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller status -data /data -host 192.0.2.53 -json
docker compose run --rm --entrypoint /espdns espdns-controller metrics -host 192.0.2.53 -raw
docker compose run --rm --entrypoint /espdns espdns-controller querylog -host 192.0.2.53
```

## /health

Small and cheap, for load balancers and monitoring. It holds no names.

Status code: `200` while the node answers DNS (state `healthy`, `degraded` or `updating`),
`503` otherwise. `Cache-Control: no-store`.

```json
{
  "state": "healthy",
  "answering": true,
  "reasons": [],
  "uptime_s": 86400,
  "boot_ms": 4210,
  "blocklist": { "state": "on", "seq": 12, "sha256": "…" },
  "overrides": { "state": "on", "seq": 3, "sha256": "…" },
  "zones": { "state": "on", "seq": 7, "sha256": "…" }
}
```

| Field | Meaning |
|-------|---------|
| `state` | One of `booting`, `healthy`, `degraded`, `no network`, `fault`, `updating`. |
| `answering` | `true` while the node answers DNS. |
| `reasons` | Why the node is not simply healthy. See [health reasons](#health-reasons). |
| `uptime_s` | Seconds since boot. |
| `boot_ms` | Milliseconds from start to answering DNS this boot. |
| `blocklist`, `overrides` | The blocklist and overrides in use: `state` (`off`, `loading`, `on`, `failed`), its release `seq` and `sha256` (both `0` / `""` unless `on`). |
| `zones` | The hosted zones bundle in use, the same three fields. |

### Health states

| State | Meaning | LED |
|-------|---------|-----|
| `booting` | Starting up. | fast blue blink |
| `healthy` | Answering, nothing wrong. | green blip every 5 s |
| `degraded` | Answering, but something needs attention (see `reasons`). | amber double blink |
| `no network` | No link or no address. | slow red blink |
| `fault` | Not answering DNS. | solid red |
| `updating` | Taking a release. Still answering. | blue triple blink |

While `identify` runs, the LED flickers white instead.

### Health reasons

`listeners failed`, `no link`, `no address`, `sd card`, `blocking`, `zone expired`,
`zone refresh failing`, `forwarders failing`, `low memory`, `no board definition`, `config`,
`config on trial`, `hosted zones`, `reboot pending`, `listeners stalled`, `service failed`,
`service restarting`, `older copy`, `forwarder task stalled`, `forwarders slow`.

## /status

Everything the node reports, as one JSON object. The controller polls it. Fields appear in
this order.

### Build and identity

| Field | Meaning |
|-------|---------|
| `project` | The firmware project name. |
| `version` | The firmware version. |
| `elf_sha256` | The first 8 bytes of the firmware's ELF SHA-256, in hex. |
| `built` | Build date and time. |
| `idf` | The ESP-IDF version. |
| `slot` | The firmware partition running (`ota_0`, `ota_1`, …). |
| `ota_state` | That partition's state: `new`, `trial`, `valid`, `invalid`, `aborted` or `undefined`. |
| `uptime_s` | Seconds since boot. |
| `ip` | The node's IPv4 address. |
| `node_id` | The node's ID: its chip MAC (`aa:bb:cc:dd:ee:ff`). Releases are signed for this ID. |
| `board` | The board definition's name. |
| `image` | The chip image the firmware was built for. |
| `board_source` | Where the board definition came from: `partition`, `fallback` or `none`. |
| `board_error` | Why the board definition was refused, or `""`. |
| `fallback_board` | The built-in fallback board's name, or `""`. |
| `keys` | Fingerprints of the two keys the node trusts: `[release, recovery]`. |
| `seq` | The highest release sequence number applied, per kind: `firmware`, `config`, `zones`, `blocklist`, `overrides`, `control`. |
| `degraded` | `true` while any degrading reason applies. |
| `heap_free` | Free internal RAM, bytes. |
| `psram_free` | Free PSRAM, bytes. |

### queries

Counters since boot: `total`, `udp`, `tcp`, `auth` (answered authoritatively, from the node's own zones),
`forwarded`, `cache_hits`, `nxdomain`, `servfail`, `refused`, `notifies`, `dropped` (never
answered).

### net

| Field | Meaning |
|-------|---------|
| `kind` | `ethernet`, `wifi` or `none`. |
| `mac` | The MAC of the interface in use. `""` until it is up. Use it for a DHCP reservation. |
| `link` | `true` while the link is up. |
| `hostname` | The mDNS name, `<hostname>.local`. |

On Wi-Fi only: `rssi` (dBm), `ap` (the access point's BSSID), `channel`, `connects`,
`drops`, `failed_attempts`, `last_join_ms`, `last_error` (a name) and `last_error_code`.

### health, sd, led and boot

| Field | Meaning |
|-------|---------|
| `health` | `state`, `answering` and `reasons`, as in [/health](#health). |
| `sd` | The SD card: `state` (`none`, `mounting`, `mounted`, `failed`), `timed_out`, `timeout_ms`. |
| `led` | `kind` (`none`, `gpio`, `ws2812`, or `failed`) and `identify_s` (seconds of identify left). |
| `reset` | Why the chip last reset: `power_on`, `pin`, `software`, `panic`, `watchdog`, `brownout`, `usb`, `jtag` or `other`. |
| `boot_ms` | Milliseconds from start to answering DNS; `null` until then. |
| `boot_limit_ms` | The boot time the firmware aims to stay under. |
| `boot` | Milliseconds at each boot step: `sd`, `zones`, `link`, `ip`, `listen` (`null` until done). |

### zones and forward_zones

`zones` lists the secondary zones. Each entry: `name`, `serial`, `records`, `transfers`
(since boot), `fails` (in a row), `expired`.

`forward_zones` lists the conditional forwarders the node runs (as of its last boot). Each
entry: `name`, `forwarder`.

### services

A list, one entry per service: `dns`, `forwarding`, `forward_zones`, `secondary`, `hosted`,
`blocking`, `querylog`. Each entry has `name`, `state` (`off`, `starting`, `running`,
`failed`) and `memory` (`planned` and `allocated` bytes).

### memory

The memory plan from the board definition:

- `board`: `psram_kb`, `internal_kb`, `cache_kb`, `cache_entries`, `blocklist_kb`,
  `blocklist_index_kb`, `hosted_zones_kb`, `secondary_zones_kb`, `querylog_kb`,
  `fwd_pending`.
- `internal` and `psram`: `capacity` and `planned`, in bytes.

### hosted

The hosted zones: `state` (`off`, `loading`, `on`, `failed`), `seq`, `sha256`, `slot`,
`reverted_from`, `bytes`, `limit_bytes`, `fallback` (why an older copy is in use, or
`null`), `error` (or `null`), and `zones` (each with `name`, `serial`, `records`).

### blocking

- `list` and `overrides`: each with `state`, `seq`, `sha256`, `entries`, `tier` (`ram`,
  `sd`, or `""` when not on), `bytes`, `data_bytes`, `internal_bytes`, `slot`,
  `reverted_from`, `fallback`, `error`.
- `paused_s`: seconds of a pause left (0: not paused).
- Counters: `blocked`, `cname_blocked`, `allowed`, `sector_reads`, `errors`.

### config

The node config in use:

| Field | Meaning |
|-------|---------|
| `source` | `node` (a pushed config) or `defaults` (the board's and firmware's settings only). |
| `seq` | The config release's sequence number (0 for `defaults`). |
| `slot` | Which stored copy is in use (`-1` for none). |
| `storage` | `partition` or `nvs`. |
| `trial` | `true` while a new config is on trial. |
| `name` | The node's name. |
| `address` | `static`, `dhcp` or `none`. |
| `address_from` | Which layer set it: `config`, `board`, `firmware` or `none`. |
| `ip`, `gateway` | With a static address: the address with its prefix length, and the gateway. |
| `error` | Why the last config was refused, or `null`. |

### time

`synced`, `utc` and `local` (`null` until synced), `tz`, `since_sync_s` (`null` until
synced), and `servers` (the NTP servers in use; `"dhcp"` first when the lease named one).

### cpu

`pm` (whether the firmware was built with power management), `dfs`, `from` (which layer set
`dfs`: `config`, `board`, `image`, or `boot` before start), `max_mhz`, `min_mhz`, `idle_mhz`,
`error`, and two holds, `dns` and `work`, each with `holds` and `busy_ms`.

### querylog

`enabled`, `state`, `client` (`full`, `subnet`, `hidden`), `capacity` (entries the ring
holds), `entries`, `oldest` and `newest` (sequence numbers), `boot_id`.

### reboot

`pending` (`true` while a release waits for a reboot), `reasons`, and `since_s`. The reasons
are `config: address`, `config: wifi`, `config: zones`, `blocklist: size` and `firmware`. The
node never reboots itself for a release: the controller reboots nodes one at a time.

## /metrics

Prometheus text format (`text/plain; version=0.0.4`). Open to anyone, like `/health`.

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `espdns_build_info` | gauge | `version`, `image`, `board`, `idf` | Always 1. |
| `espdns_uptime_seconds` | gauge | | Time since boot. |
| `espdns_boot_seconds` | gauge | | Time from power-on to answering DNS this boot (0 until it answers). |
| `espdns_health_state` | gauge | `state` | 1 for the current health state, 0 for the others. |
| `espdns_health_reason` | gauge | `reason` | 1 while that health reason applies. |
| `espdns_reboot_pending` | gauge | | 1 while a release waits for a reboot. |
| `espdns_release_seq` | gauge | `kind` (`firmware`, `config`, `zones`, `blocklist`, `overrides`, `control`) | Highest release seq applied. |
| `espdns_link_up` | gauge | | 1 while the network link is up. |
| `espdns_wifi_rssi_dbm` | gauge | | Wi-Fi signal (Wi-Fi nodes only). |
| `espdns_clock_synced` | gauge | | 1 once the clock is set over SNTP. |
| `espdns_queries_received_total` | counter | `transport` (`udp`, `tcp`) | DNS messages received. |
| `espdns_queries_total` | counter | `result` (`cache`, `forwarded`, `hosted`, `secondary`, `blocked`, `overridden`, `refused`, `servfail`, `error`, `notify`, `dropped`) | Queries by what answered them. |
| `espdns_responses_total` | counter | `rcode` (`NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`, and others once seen) | Responses by rcode. NOTIFY replies not included. |
| `espdns_query_duration_seconds` | histogram | | Time to answer a query, forwarders included. |
| `espdns_upstream_queries_total` | counter | `upstream` (an address, or `other`) | Attempts at each forwarder. |
| `espdns_upstream_failures_total` | counter | `upstream` | Attempts that got no answer, or SERVFAIL. |
| `espdns_upstream_timeouts_total` | counter | `upstream` | Of those failures, the attempts with no answer within the try's timeout (`upstream_timeout_ms`). |
| `espdns_upstream_duration_seconds` | histogram | `upstream` | Time each forwarder took to answer. |
| `espdns_upstream_failing` | gauge | | Forwarded queries in a row with no answer from the default forwarders (0 after any answer). |
| `espdns_fwd_slots` | gauge | | Upstream queries the node may have outstanding at once (`memory.fwd_pending`). |
| `espdns_fwd_group_cap` | gauge | | The most of them one group may hold: the default forwarders, a forward zone, or the forward zones together. |
| `espdns_fwd_inflight` | gauge | `group` (`default`, `zones`) | Upstream queries outstanding now. |
| `espdns_fwd_zone_inflight` | gauge | `zone` | Upstream queries outstanding now, per forward zone. |
| `espdns_fwd_inflight_peak` | gauge | | The most upstream queries outstanding at once since boot. |
| `espdns_fwd_shed_total` | counter | `group` | Queries answered SERVFAIL at once because their group, or the table, was full. |
| `espdns_fwd_expired_total` | counter | `group` | Upstream queries that ended with no answer. |
| `espdns_fwd_tcp_retries_total` | counter | | Truncated answers asked again over TCP. |
| `espdns_fwd_select_errors_total` | counter | | Times the forward loop's `select()` failed. |
| `espdns_cache_entries` | gauge | | Answers in the cache. |
| `espdns_cache_entries_max` | gauge | | The most answers the cache holds. |
| `espdns_cache_bytes` | gauge | | Bytes the cached answers take. |
| `espdns_cache_capacity_bytes` | gauge | | The cache's memory. |
| `espdns_cache_hits_total` | counter | | Lookups answered from the cache. |
| `espdns_cache_misses_total` | counter | | Lookups the cache didn't have. |
| `espdns_cache_inserts_total` | counter | | Answers put in the cache. |
| `espdns_cache_evictions_total` | counter | | Answers dropped to make room. |
| `espdns_blocklist_loaded` | gauge | `list` (`blocklist`, `overrides`) | 1 while the list is loaded and in use. |
| `espdns_blocklist_entries` | gauge | `list` | Entries in the list in use. |
| `espdns_blocklist_seq` | gauge | `list` | Release seq of the list in use (0: none). |
| `espdns_blocklist_bytes` | gauge | `list` | Bytes the list in use takes. |
| `espdns_blocking_paused_seconds` | gauge | | Time left of a pause (0: not paused). |
| `espdns_blocking_decisions_total` | counter | `decision` (`blocked`, `cname_blocked`, `allowed`) | Blocking decisions. |
| `espdns_blocking_sector_reads_total` | counter | | Sectors read from the SD card for the SD tier. |
| `espdns_blocking_errors_total` | counter | | Sector reads that failed. |
| `espdns_zones` | gauge | `kind` (`secondary`, `hosted`, `forward`) | Zones the node serves. |
| `espdns_zone_serial` | gauge | `zone`, `kind` (`secondary`, `hosted`) | Each zone's SOA serial (0: a secondary zone not loaded). |
| `espdns_zone_records` | gauge | `zone`, `kind` | Records in each zone. |
| `espdns_zone_transfers_total` | counter | `zone`, `kind` (secondary zones only) | Transfers of each secondary zone since boot. |
| `espdns_zone_refresh_failures` | gauge | `zone`, `kind` (secondary zones only) | Failed SOA checks or transfers in a row. |
| `espdns_zone_expired` | gauge | `zone`, `kind` (secondary zones only) | 1 while a secondary zone is past its SOA EXPIRE. |
| `espdns_hosted_zones_bytes` | gauge | | Memory the hosted zones take. |
| `espdns_hosted_zones_loaded` | gauge | | 1 while the hosted zones service runs with a bundle. |
| `espdns_service_state` | gauge | `service`, `state` | Always 1, for each service with its current state. |
| `espdns_service_memory_planned_bytes` | gauge | `service` | Each service's share of the memory plan. |
| `espdns_service_memory_allocated_bytes` | gauge | `service` | What each service holds now. |
| `espdns_memory_capacity_bytes` | gauge | `pool` (`internal`, `psram`) | What the services may plan in each pool. |
| `espdns_memory_planned_bytes` | gauge | `pool` | What the running services' plan takes. |
| `espdns_heap_free_bytes` | gauge | `pool` | Heap free now. |
| `espdns_heap_min_free_bytes` | gauge | `pool` | The least heap free since boot. |
| `espdns_cpu_mhz` | gauge | `clock` (`max`, `idle`) | The CPU clock. |
| `espdns_cpu_dfs` | gauge | | 1 while idle clock scaling is on. |
| `espdns_cpu_busy_seconds_total` | counter | `hold` (`dns`, `work`) | Time the full clock was held. |
| `espdns_querylog_enabled` | gauge | | 1 while the query log runs. |
| `espdns_querylog_capacity` | gauge | | Queries the query log's ring holds. |
| `espdns_querylog_entries` | gauge | | Queries in the ring now. |
| `espdns_querylog_seq` | gauge | | The newest entry's seq (starts over at a reboot). |

The histograms' buckets (`le`, seconds): 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01,
0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, +Inf.

## /querylog

The queries the node logged, oldest first, from a ring in memory. Private addresses only.

Query parameters:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `cursor` | `0` | Start after this sequence number. `0`: the oldest the node holds. |
| `limit` | `100` | Entries to return, 1 to 1000 (higher is capped at 1000). |

Reply:

| Field | Meaning |
|-------|---------|
| `boot_id` | Changes at each boot. Sequence numbers start over with it. |
| `enabled`, `state`, `client` | As in `/status` `querylog`. |
| `capacity`, `oldest`, `newest` | The ring's size and the sequence numbers it holds. |
| `cursor` | The cursor asked for. |
| `uptime_ms` | The node's uptime now. |
| `time` | The node's clock now in Unix milliseconds, or `null` if not synced. |
| `entries` | The queries (below). |
| `next` | The cursor for the next read. |
| `lost` | Entries overwritten before they could be read. |
| `reset` | `true` when the cursor was from before the node's last boot. |
| `more` | `true` when there are newer entries to read. |

Each entry: `seq`, `uptime_ms`, `time` (Unix ms or `null`), `client` (an address, or `null`
when hidden), `transport` (`udp`, `tcp`), `qname`, `qtype`, `result` (as in
`espdns_queries_total`), `rcode`, `latency_us`, and when they apply `rule` (`list`,
`override`, `cname`, `allow`) and `truncated`.
