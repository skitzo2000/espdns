# Zones and forwarding

This guide covers how espDNS nodes answer for names: the zones they hold, the domains they
send to other servers, and the default forwarders for everything else. For blocklists, see
[blocking.md](blocking.md). For how it all fits together, see [Architecture](architecture.md).

espDNS is alpha software (0.0.x). This guide describes what the code does today.

## How a node answers a query

A node looks at each query in this order:

1. **A zone it holds.** A hosted zone or a secondary zone. The node answers with authority.
   These names are never blocked.
2. **Blocking.** If the blocking service is on, a blocked name is answered here
   ([blocking.md](blocking.md)).
3. **A forward zone.** A domain sent to its own forwarder.
4. **The cache, then the default forwarders.** Everything else.

There are three kinds of zone. Each zone name has one kind only. The controller refuses a
name that is two kinds at once, for example a hosted zone that is also a secondary zone on
the same node.

| Kind | Where the records live | How nodes get them |
|---|---|---|
| Hosted | A zone file in the controller | The controller pushes a signed bundle to every node |
| Secondary | Your own primary DNS server | Each node copies the zone by zone transfer (AXFR) |
| Forward | Another DNS server | The node forwards queries for the domain to it |

## Before you start

The controller runs with Docker Compose from the `controller/` directory. Its data
directory is the one `ESPDNS_DATA` names in `controller/.env` (`/data` inside the
container). The commands
in this guide run from `controller/`.

The command line tool (`espdns`) is in the controller's image. Run it with
`docker compose run`. Commands that change a node sign a release with your release key.
The examples use the copy you imported into the data directory
([Getting started, step 7](getting-started.md#7-import-the-release-key)):
`-key /data/keys/release.pem`. Other ways to give the key are in the
[CLI reference](reference/cli.md#secrets).

Most tasks here can be done from the dashboard at http://127.0.0.1:8480. You need to be
logged in to read or change zones.

## Hosted zones

A hosted zone is a zone where espDNS is the primary. You edit its records in the
controller. The controller pushes the zone to every node as one signed bundle. Each node
applies it live, with no reboot.

### What a hosted zone can hold

- Record types: A, AAAA, CNAME, MX, TXT, SRV, NS, PTR, CAA and SOA.
- No DNSSEC. Hosted zones are unsigned.
- Standard master file syntax (RFC 1035): `$ORIGIN`, `$TTL`, relative and absolute names.

Each zone is one file in the data directory: `zones/<zone>.zone`. For example,
`zones/home.arpa.zone` holds the zone `home.arpa`. File names use lowercase letters,
digits, `.`, `_` and `-`.

Each node has a memory limit for hosted zones. It comes from the node's board. The
controller checks every zone set against each node's limit before it pushes.

Hosted zones are kept on the node's SD card. A node without a working SD card cannot serve
hosted zones. A node config can turn the service off with `"hosted": {"enabled": false}`.

### Create and edit a zone

1. Open **Zones** in the dashboard.
2. Under **New zone**, type the zone name (for example `home.arpa`) and click **Create**.
   The new zone starts from a template: an SOA record, plus an NS record and an address
   record for each node in `settings.json`.
3. Edit the zone as text.
4. Click **Check**. The controller runs the same checks the node runs. It also checks the
   zone set against each node: its memory limit, its firmware, and any clash with the
   node's secondary or forward zones.
5. Click **Bump serial** to raise the SOA serial. A date serial (`YYYYMMDDnn`) stays a date
   serial. The page warns you if the serial is not higher than the saved file's or what a
   node serves.
6. Click **Save**. The page shows the diff and asks you to confirm. A zone that fails the
   checks is not saved.

Each save keeps the previous version in `zones/.history/`. **Delete** keeps the file in
the history too, and **Restore** opens an old version as a new zone. Nodes keep serving a
deleted zone until you push the zone set without it.

Saving does not change any node. To send zones to the nodes, push them.

### Push zones to the nodes

On the Zones page, under **Push the zones**, choose the zones and click **Open in Push**.
This opens the **Push** page with the kind set to hosted zones and the set chosen.

The pushed set **replaces** every hosted zone on each node. The Push page includes every
zone the nodes serve now, and tells you if a node would stop serving a zone.

The push is a rolling change:

1. Click **Dry run**. It checks every node and shows what each one would get.
2. Click **Roll out**. It must follow a dry run that passed in the last 15 minutes, with
   the same nodes and the same files.
3. The controller changes one node at a time. It starts with the canary node, checks that
   the node answers DNS, waits for the soak time, then moves to the next node.

The Push page is also under **System**, as **Push**.

From the command line, check zone files without touching any node:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
    zones -check -zone /data/zones/home.arpa.zone
```

Roll out the zone set to every node, one at a time (dry run first, then the same command
without `-dry-run`):

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
    rollout -kind zones -all -data /data -zone /data/zones/home.arpa.zone -dry-run -key /data/keys/release.pem
```

Repeat `-zone` for each zone in the set. `-empty` instead of `-zone` removes every hosted
zone from the nodes.

### Revert hosted zones

Each node keeps the previous zone bundle. To go back to it on one node, click
**Revert zones** next to that node on the Zones page. The node switches back live. It
stays on the older bundle until you push a newer one.

The node refuses a revert when it has nothing older to go back to. The page shows the
node's reason.

From the command line:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
    revert -host 192.0.2.53 -kind zones -data /data -key /data/keys/release.pem
```

## Secondary zones

A secondary zone lives on your own primary DNS server. Each node copies it by zone
transfer (AXFR). The node then answers for it with authority. Copies are kept on the SD
card (in memory only, on a node without a card).

espDNS works with any standards-compliant primary: BIND, Knot, PowerDNS, Windows DNS,
Technitium and others. The nodes are plain secondaries. They take NOTIFY messages from the
primary and also check the zone's SOA serial on a timer.

### Set up a secondary zone

Secondary zones are set in each node's config, under `"secondary"`:

```json
"secondary": {
  "primary": "192.0.2.254",
  "zones": ["example.com", "home.arpa"],
  "soa_poll_s": 60,
  "retry_s": 30
}
```

- `primary`: the IPv4 address of your primary. One primary per node.
- `zones`: up to 32 zone names.
- `soa_poll_s`: how often the node checks the SOA serial, in seconds (10 to 86400).
- `retry_s`: how long to wait after a failed check or transfer, in seconds (5 to 3600).

Edit node configs on the **Configs** page (under **System**). Check and save the config,
then click **Push to a node**, or push configs to several nodes from the **Push** page.

### Allow the nodes on your primary

Your primary must allow each node to transfer the zone, and should send NOTIFY to each
node. How espDNS handles this depends on the zone primary set in `settings.json` in the
data directory (`controller/data/settings.json`).

**Manual primary (the default).** This works with any primary.

```json
"primary": { "kind": "manual" }
```

When you adopt a node, the controller shows the exact change to make on the primary for
each zone: allow zone transfers to the node's address, and send NOTIFY to it. You make the
change, then confirm it, and adoption goes on. No token is needed. If `settings.json` has no
`"primary"`, the controller uses the manual kind.

**Technitium over its API.** Technitium is one primary the controller can change for you.
The controller adds each node to the zone's transfer and NOTIFY lists through Technitium's
HTTP API.

```json
"primary": { "kind": "technitium", "url": "https://192.0.2.254:53443" }
```

- The API must be **https**. The controller never sends the API token over plain http. It
  refuses a plain `http://` address. In Technitium, enable HTTPS under Settings, Web
  Service. Its HTTPS port is 53443 by default.
- The controller always verifies the primary's certificate. A certificate your system
  trusts needs nothing more. A self-signed certificate must be **pinned** (see below).
- If an older `settings.json` already names a plain http address, the controller still
  starts, but the primary is **paused**: nothing is sent to it, and adoption shows the
  change to make by hand. Change the address to https and pin the certificate.

Import the API token. The token is read from standard input, never from an argument. For
example, from a file:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
    primary import -data /data < technitium-token.txt
```

or from an environment variable:

```sh
printf '%s' "$TECHNITIUM_TOKEN" | docker compose run --rm -T --entrypoint /espdns espdns-controller \
    primary import -data /data
```

The token is stored in the data directory as `keys/primary.token` (mode 0600). It is never
shown again. Add `-replace` to replace a different token. Check the setup with:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller primary status -data /data
```

Pin a self-signed certificate. First read the certificate the primary presents:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller primary cert -data /data
```

This makes a TLS handshake only. It sends no request and no token. Compare the SHA-256
fingerprint it prints with the one shown on the primary itself. If they match, pin it:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
    primary pin -data /data -sha256 <fingerprint>
```

The pin is saved in `settings.json` as `"cert_sha256"`. Do not write it by hand. From then
on the controller accepts only that certificate. If the primary presents another one (for
example after a renewal), the controller refuses it until you check and pin the new one.
`primary unpin` removes the pin.

Without a token, the Technitium kind falls back to showing the change, as the manual kind
does.

### See the primary's lists

Open **System** and look under **Zone primary**. For an API primary, it shows each
secondary zone's transfer and NOTIFY lists and which adopted node is missing. For a manual
primary, it shows what each node needs there.

### When a copy expires

If a node goes longer than the zone's SOA expire time without a good check against the
primary, its copy expires. The node stops answering from that copy, and it reports itself
degraded with the reason `zone expired`. Check that the primary is up and still allows
the node's address.

## Forward zones

A forward zone sends every query for one domain to a server you choose. Use it for a
domain that another DNS server answers, such as a partner network or an ACME challenge
domain.

Forward zones are set in each node's config:

```json
"forward_zones": [
  { "zone": "partner.example", "forwarder": "198.51.100.53" },
  { "zone": "_acme-challenge.example.com", "forwarder": "198.51.100.54" }
]
```

- Each entry has one zone and one forwarder (an IPv4 address).
- Up to 32 forward zones per node.
- A zone cannot be both a forward zone and a secondary zone.
- `"forward_zones": []` means none.

Blocking is checked before forward zones, so a blocked name inside a forward zone is still
blocked.

## Default forwarders

Every name that is not in a zone, not blocked and not cached goes to the default
forwarders. They are set in the node config:

```json
"forwarders": ["9.9.9.9", "149.112.112.112"],
"upstream_timeout_ms": 1500
```

- Up to 4 IPv4 addresses, asked in order.
- Left out, the node uses its board's default, else the firmware's: Quad9
  (`9.9.9.9` and `149.112.112.112`).
- `"forwarders": []` turns forwarding off. The node then answers only its own zones.
- `upstream_timeout_ms` is the time for one try, from 100 to 10000 ms.

Forwarders are plain DNS: UDP, with TCP for answers that do not fit.

## Live changes and reboots

Some config changes apply live. Others wait for a reboot:

- **Live:** the default forwarders, `upstream_timeout_ms`, `soa_poll_s` and `retry_s`.
- **Reboot:** a change to the list of secondary zones, the secondary primary, or the
  forward zones.

The **Configs** page shows, before you push, what applies live and what needs a reboot. A
rolling push reboots one node at a time, and only while another node is answering.

## The zone inventory and lookup

The controller keeps an inventory of every zone the nodes answer for:

- the hosted zones, with their serial and record count;
- the secondary zones, with the primary they come from and the newest copy's serial;
- the forward zones, with their forwarders.

Each zone has a state for the whole fleet: `ok`, `partial`, `waiting` (configured but on no
node yet), `expired`, `error` (the zone file fails its checks), `no_file` or `unknown`.

The controller can also look up where a zone lives. It checks the fleet's own zones first.
Then it asks each configured primary for the zone's SOA over DNS (UDP port 53, no
recursion). The answer is one of:

- `zone`: one of the fleet's zones;
- `primary`: a zone on one of your primaries, with its serial;
- `within`: a name inside one of the fleet's zones;
- `primary_within`: a name inside a zone a primary serves;
- `none`: nowhere yet. Host it here, or forward it.

The lookup asks DNS, not an API, so it works with any primary.

The inventory and the lookup are controller APIs today (`GET /api/zone-inventory` and
`GET /api/zone-lookup?name=<zone>`). They need a login. The current Zones page does not show
them yet. They are there for the redesigned Zones page.

## Quick reference

| Task | Where |
|---|---|
| Create, edit, check, save a hosted zone | Zones page |
| Push hosted zones | Zones page, **Open in Push**; or `rollout -kind zones` |
| Revert hosted zones on one node | Zones page, **Revert zones**; or `revert -kind zones` |
| Add secondary zones, forward zones, forwarders | Configs page (node config), then push |
| Choose the zone primary | `settings.json`, `"primary"` |
| Import the primary's API token | `primary import` |
| Pin the primary's certificate | `primary cert`, then `primary pin` |
