# Node config

A node config is a JSON file that sets how one node runs: its name, address, Wi-Fi,
forwarders, zones, blocking and more. The controller keeps node configs in
`<data>/configs/<name>.json`. It sends one to a node as a signed config release (adoption,
a config push, a rollout, or an apply).

The controller checks a config with the same rules the node uses. A config the controller
accepts is one the node takes.

Back to the [reference index](README.md).

## Layers

A node takes each setting from the first layer that has it:

1. **The node config** (this page).
2. **The board definition**, written to the node when it was flashed: its address, its Wi-Fi
   transmit power cap, its CPU clock scaling, and its memory sizes.
3. **The firmware default.**

A key you leave out keeps the layer below. A list you give replaces the lower list whole:
`"forward_zones": []` means no forward zones at all.

## Rules for the whole file

- Every key is optional. `{}` is a valid config.
- Unknown keys are refused, so a typo is an error, not a setting that does nothing.
- The file holds one JSON object and nothing after it.
- The node receives the config as compact JSON. It must be at most 16,192 bytes. A node whose
  flash has no config partition yet keeps configs in NVS, which holds at most 4,000 bytes.

## Example

```json
{
  "format": 1,
  "name": "dns-a",
  "network": { "address": "192.0.2.53/24", "gateway": "192.0.2.1" },
  "wifi": { "ssid": "home", "password": "use-a-long-passphrase", "tx_power_dbm": 11, "power_save": false },
  "forwarders": ["9.9.9.9", "149.112.112.112"],
  "upstream_timeout_ms": 1500,
  "forward_zones": [{ "zone": "corp.example.com", "forwarder": "198.51.100.53" }],
  "secondary": { "primary": "192.0.2.1", "zones": ["home.arpa"], "soa_poll_s": 60, "retry_s": 30 },
  "hosted": { "enabled": true },
  "time": { "ntp": ["192.0.2.1"], "tz": "EST5EDT,M3.2.0,M11.1.0" },
  "blocking": { "enabled": true, "answer": "null", "ttl": 10 },
  "cpu": { "dfs": false },
  "querylog": { "enabled": true, "client": "full" }
}
```

## Keys

"Applies" says when a change takes effect on a running node: **live** (at once), or at the
next **reboot**. A node with a change waiting for a reboot reports it in `/status`
`reboot.reasons` (see [node-endpoints.md](node-endpoints.md#status)). The controller then
reboots it one node at a time.

### Top level

| Key | Type | Default | Checks | Applies |
|-----|------|---------|--------|---------|
| `format` | integer | `1` | `0` (left out) or `1`. | — |
| `name` | string | none | At most 31 characters. Printable ASCII only, no `"` or `\`. The node also answers HTTP requests whose `Host` is this name. | live |
| `network` | object | the board's address, else none | See [network](#network). | reboot |
| `wifi` | object | the network saved over USB | See [wifi](#wifi). | partly live |
| `forwarders` | list of IPv4 addresses | `9.9.9.9`, `149.112.112.112` (Quad9) | 0 to 4 addresses. `[]` turns forwarding off. | live |
| `upstream_timeout_ms` | integer | `1500` | 100 to 10000. | live |
| `forward_zones` | list of objects | none | See [forward_zones](#forward_zones). | reboot |
| `secondary` | object | none | See [secondary](#secondary). | partly live |
| `hosted` | object | enabled | See [hosted](#hosted). | live |
| `time` | object | see below | See [time](#time). | live |
| `blocking` | object | enabled, `null` answer, TTL 10 | See [blocking](#blocking). | live |
| `cpu` | object | the board's, else the chip image's | See [cpu](#cpu). | live |
| `querylog` | object | enabled, full client address | See [querylog](#querylog). | live |

An **IPv4 address** here means a dotted address that is not `0.0.0.0`, not loopback, not
multicast and not `255.255.255.255`.

A **zone name** is at most 253 characters, made of letters, digits, `-`, `_` and `.`, with no
empty label and no label over 63 characters. A trailing dot is allowed and dropped. Names are
compared in lower case.

### network

| Key | Meaning | Checks |
|-----|---------|--------|
| `address` | The node's static address with its prefix length (`192.0.2.53/24`), or `"dhcp"` for a network with a DHCP server. | Required in `network`. A static address: IPv4, prefix 8 to 30, not the network's own or broadcast address. |
| `gateway` | The default gateway. | Required with a static address. Refused with `"dhcp"`. Must be another address inside the node's network. |

A node never asks DHCP for an address on its own. It uses DHCP only when a layer says
`"dhcp"`. Adoption never gives `"dhcp"` to a node on a network listed in `settings.json`
`no_dhcp` (see [settings.md](settings.md#fields)).

A change of address applies at a reboot.

### wifi

| Key | Meaning | Checks | Applies |
|-----|---------|--------|---------|
| `ssid` | The Wi-Fi network's name. Left out: the network saved over USB when the node was set up. | 1 to 32 characters. | reboot |
| `password` | The Wi-Fi password. `""` for an open network. | Only with `ssid`. 8 to 63 characters, or empty. | reboot |
| `tx_power_dbm` | Transmit power in dBm. Left out: the board's cap, else the chip's default. | 2 to 20. | live |
| `power_save` | Wi-Fi power saving. | `true` or `false`. Default `false`. | live |

The dashboard never shows the Wi-Fi password in a reply, unless you ask to reveal it and enter
your password again.

### forward_zones

Conditional forwarders: queries for a zone go to a named server.

```json
"forward_zones": [{ "zone": "corp.example.com", "forwarder": "198.51.100.53" }]
```

| Key | Checks |
|-----|--------|
| `zone` | A zone name. At most 32 forward zones. No zone twice. A zone can't be both a forward zone and a secondary zone. |
| `forwarder` | Required. An IPv4 address. |

A change applies at a reboot.

### secondary

Zones the node copies from the zone primary over AXFR/IXFR, kept fresh by NOTIFY and SOA polls.

| Key | Meaning | Checks | Applies |
|-----|---------|--------|---------|
| `primary` | The zone primary's address. | An IPv4 address. Not the node's own static address. | reboot |
| `zones` | The zones to copy. | At most 32 zone names. No zone twice. | reboot |
| `soa_poll_s` | Check the primary's serial at least this often, in seconds. Default `60`. | 10 to 86400. | live |
| `retry_s` | Wait this long after a failed check, in seconds. Default `30`. | 5 to 3600. | live |

The node must be on each zone's transfer and NOTIFY lists at the primary. Adoption adds it, or
tells you the change to make by hand (see [settings.md](settings.md#primary)).

### hosted

| Key | Meaning |
|-----|---------|
| `enabled` | `false` turns the hosted zones service off. Default `true`. |

The hosted zones themselves are not in the config. They are pushed as their own release.

### time

| Key | Meaning | Checks |
|-----|---------|--------|
| `ntp` | NTP servers. Left out: on DHCP the server the lease names, then the default gateway, then `pool.ntp.org`. | At most 3. Host names or IPv4 addresses (letters, digits, `-` and `.`, at most 63 characters). |
| `tz` | The time zone as a POSIX TZ string. Default `UTC0`. | At most 63 characters. Must start with a letter or `<`. Only letters, digits, `+ - , . / :` and balanced `< >`. |

### blocking

| Key | Meaning | Checks |
|-----|---------|--------|
| `enabled` | `false` turns blocking off. Default `true`. | — |
| `answer` | What a blocked name gets: `"null"` (`0.0.0.0`, `::`, or NODATA for other types) or `"nxdomain"`. Default `"null"`. | `"null"` or `"nxdomain"`. |
| `ttl` | The TTL of a blocked answer, in seconds. Default `10`, so an override or a pause takes effect quickly. | 0 to 86400. |

### cpu

| Key | Meaning |
|-----|---------|
| `dfs` | `true` lets the CPU clock drop when idle; `false` keeps it at full speed. Left out: the board definition's setting, else the chip image's default. |

### querylog

| Key | Meaning | Checks |
|-----|---------|--------|
| `enabled` | `false` turns the query log off. Default `true`, on a board that gives the query log memory. | — |
| `client` | How much of a client's address the log keeps: `"full"`, `"subnet"` (the /24 only) or `"hidden"` (none). Default `"full"`. | One of the three. |

## Services

The services a node runs follow from its config:

| Service | Runs while |
|---------|-----------|
| `dns` | always |
| `forwarding` | it has forwarders (`[]` turns it off) |
| `forward_zones` | it has at least one forward zone |
| `secondary` | it has at least one secondary zone |
| `hosted` | `hosted.enabled` is not `false` |
| `blocking` | `blocking.enabled` is not `false` |
| `querylog` | `querylog.enabled` is not `false` |

## What applies live and what needs a reboot

Live: `name`, `wifi.tx_power_dbm`, `wifi.power_save`, `forwarders`, `upstream_timeout_ms`,
`secondary.soa_poll_s`, `secondary.retry_s`, `hosted`, `time`, `blocking`, `cpu`, `querylog`.
Services start and stop live with them.

At a reboot, with the reason the node reports:

| Change | Reason in `/status` `reboot.reasons` |
|--------|-------------------------------------|
| `network` | `config: address` |
| `wifi.ssid`, `wifi.password` | `config: wifi` |
| `secondary.zones`, `secondary.primary`, `forward_zones` | `config: zones` |

## Checking a config

Check a file without sending it. A bare file name means `<data>/configs/<name>`:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  config -data /data -check -file dns-a.json
```

It prints `ok` with the size, then the payload the node would get. The payload includes the
Wi-Fi password, so mind where the output goes.

Add `-host <address>` to also check it against that node (read only), or
`-board <catalog board>` to check its memory plan on a catalog board. See
[cli.md](cli.md#config).

The dashboard's config editor runs the same checks
(`POST /api/configs/{name}/check`, see [api.md](api.md#node-configs)).
