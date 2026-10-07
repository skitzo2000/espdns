# Troubleshooting

This guide helps you find out what is wrong with a node or the controller, and what to do
about it. It covers a node's health state and the reasons behind it, the LED patterns, and
the problems people hit most often.

For updates, backups and the safety rules, see [Operations](operations.md). To set up a
fleet from the start, see [Getting started](getting-started.md).

Run every command here from the `controller/` directory of your clone. The `espdns` command
line tool runs inside the controller's image, as [Operations](operations.md#before-you-start)
explains.

## First look

**The web page.** Open the controller at `http://127.0.0.1:8480`. The **Nodes** page shows
each node's state, its LED pattern, and the reason when it is not healthy. Click a node for
its details: each health reason and what it means, the network, the firmware, the config,
and the node's raw `/status`.

**The command line.** Read every node in `settings.json`:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller status -all -mdns 0 -data /data
```

Or one node, by address, as JSON with everything it reports:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller status -host 192.0.2.54 -json -data /data
```

The first line for each node is its state, its reasons in parentheses, and `reboot pending`
when a reboot waits.

To find nodes on the network, including ones not adopted yet:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller discover -data /data
```

**The controller's log:**

```sh
docker compose logs -f
```

**The action log.** Every change to a node writes a `start` line and an `end` line to
`log/actions.jsonl` in the data directory. A `start` with no `end` is a change whose
process died part way.

## Health states

Every node reports one state. It is in `/health` and in `/status`.

| State | What it means | Answers DNS? | `/health` code |
| --- | --- | --- | --- |
| `booting` | The node is starting. Its DNS listeners are not open yet. | No | 503 |
| `healthy` | Everything its config turns on is running. | Yes | 200 |
| `degraded` | It answers, but something it should run has failed. | Yes | 200 |
| `no network` | The link is down, or the node has no address. | No | 503 |
| `fault` | Its DNS listeners failed to open, or stalled. | No | 503 |
| `updating` | It is receiving a release. | Yes | 200 |

`GET http://<node>/health` needs no login. A monitor or load balancer only needs the status
code: 200 while the node answers DNS, 503 when it does not.

The node checks the `Host` header of every request. It must be the node's address, its
mDNS name (`<hostname>.local`) or the name in its config. Anything else gets `421`. Point
your monitor at the node's address.

Only the services a node's config turns on count. A node with no zones, no blocking or no
forwarders is healthy when what it does run is fine. A clock that has not synced yet is not
a reason.

## Health reasons

A node lists every reason that holds, whatever its state. Most reasons make it `degraded`.
Two make it `fault`. Some are only for your information.

### Fault reasons

These stop the node answering DNS.

**`listeners failed`.** A DNS listener could not open its port.
Reboot the node. If it comes back with the same reason, check that its config is right
and that its firmware is current. If it persists, report it as a bug.

**`listeners stalled`.** The DNS listeners stopped working, the node rebooted for it three
times in a row, and now it stays up instead of rebooting again. It stays up so you can read
it from the controller. Read its `/status` (the JSON command above) and save it. Then
reboot or power-cycle it. Update the firmware if a newer one is out, and report it as a
bug with the `/status` you saved.

### No network

These come with the `no network` state.

**`no link`.** The network link is down. Check the cable, the switch port and the power.
On a board with Wi-Fi as a fallback, check the Wi-Fi settings in its config.

**`no address`.** The link is up, but the node has no IP address yet.

- A node on DHCP (a factory image starts on DHCP) needs a DHCP server on its network. On
  a network without one, flash the node from the controller's **Builder** instead: it
  writes a static address.
- A node with a static address in its config: check the address, prefix and gateway in the
  config.

### Degraded reasons

The node still answers. Something it should run has failed.

**`sd card`.** The board has an SD slot, and a service that keeps data on the card is on
(secondary zones, hosted zones or blocking), but there is no card, or it failed to mount,
or it timed out. The node keeps answering from its config and forwarders. Secondary zones
are fetched again from the primary and kept in memory only. Hosted zones and blocking are
off. Reseat or replace the card, then reboot the node.

**`blocking`.** A blocklist or the overrides failed to load, or the card had read errors.
Send the node back to its older list:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  revert -host 192.0.2.54 -kind blocklist -data /data -key /data/keys/release.pem
```

Use `-kind overrides` for the overrides. The **Blocklists** page has the same revert for
each node ([Revert](blocking.md#revert)). Then build and push the list again. If the card
has read errors, replace it.

**`zone expired`.** A secondary zone passed its SOA expire time: the node has not been able
to refresh it from the zone primary for too long. **`zone refresh failing`** comes first:
three refresh checks or transfers in a row have failed.

- Check that the zone primary is up and that the node can reach it.
- Check that the primary allows this node to transfer the zone and sends it NOTIFYs. The
  **Zone primary** section of the **System** page shows what each node needs there.
  [Allow the nodes on your primary](zones.md#allow-the-nodes-on-your-primary) shows how,
  for each kind of primary.
- Check the primary's address in the node's config.

**`forwarders failing`.** The default forwarders have not answered five queries in a row
over at least 30 seconds. Conditional forwarders (forward zones) do not count. Check that
the node can reach its forwarders, and the forwarders in its config.

**`forwarders slow`.** The default forwarders are too slow for what the node is asked. One
of these holds: a query to them was turned away (answered SERVFAIL at once) in the last 30
seconds because they already had their share of the upstream query table; they held more
than half that share for 10 seconds; or, of at least five upstream queries to them in the
last 30 seconds, more than half took longer than `upstream_timeout_ms` or got no answer.
Conditional forwarders do not count. The **Traffic** page shows each node's upstream
queries in flight, the queries turned away and the forwarders' timeouts. Check the
forwarders' reachability and speed, or use faster ones in the node's config.

**`forwarder task stalled`.** The task that sends forwarded queries missed its watchdog.
Forwarded queries go unanswered. Cached answers and the node's own zones still work. The
node does not reboot for this. Reboot it under the safety rules:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  reboot -host 192.0.2.54 -mdns 0 -data /data -key /data/keys/release.pem
```

If it comes back, report it as a bug.

**`low memory`.** Less than 16 KB of internal RAM is free. Turn off services the node does
not need, or give it a smaller blocklist, then reboot it.

**`no board definition`.** The node has no usable board definition, so it runs on
defaults: no Ethernet, no SD card. It may still answer over Wi-Fi. Flash it again with the
controller's **Builder**, or with the factory image for its board.

**`config`.** The stored node config is not in use. It was refused, could not be read, or
failed its trial. The node runs on its older config or on the firmware defaults. The error
is in `/status` under `config.error` (shown by `status -host <node>` on the `config:` line,
and on the node's details). A config whose memory plan does not fit the board also shows
here. Fix the config on the **Configs** page, check it, and push it again.

**`hosted zones`.** A hosted zones bundle failed to load, or one of its zones is not served
because the node's config names that zone too, as a secondary zone or a forward zone. A zone
has one source. Remove the zone from one of the two. To go back to the older bundle the
node keeps:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  revert -host 192.0.2.54 -kind zones -data /data -key /data/keys/release.pem
```

**`service failed`.** A service failed to start three times in a row, or its task missed its
watchdog. The node's details (and `/status` `services`) show which one. Check the setting
that service uses in the node's config, then reboot the node.

**`older copy`.** At boot, the newest blocklist, overrides or hosted zones bundle on the
card was corrupt, unreadable or too big, so the node runs the older copy it keeps.
`/status` says why under `fallback`. Push it again. If it was too big, push a smaller one.
If the card is failing, replace it. A revert you asked for does not show this reason.

### For your information

These do not make the node degraded.

**`config on trial`.** The node took a config with a new address or Wi-Fi network. It goes
back to its old config unless a DNS query reaches it within 90 seconds. The rollout or
adoption that sent it confirms it.

**`reboot pending`.** The node took a release that applies at the next reboot. It keeps
serving meanwhile. Reboot it under the safety rules, from the node's details on the Nodes
page (**Reboot (pending)**), or:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  reboot -host 192.0.2.54 -if-pending -mdns 0 -data /data -key /data/keys/release.pem
```

**`service restarting`.** A service failed to start and is being started again. After three
failures in a row it becomes `service failed`.

## LED patterns

Each board has one status LED, if its board definition declares one (or the node config
names an add-on LED). The patterns can be told apart on a single-colour LED. An RGB LED
blinks the same way, in colour. The Nodes page shows the same pattern for each node.

| Pattern | RGB colour | State | What to do |
| --- | --- | --- | --- |
| Fast blink, 5 a second | Blue | `booting` | Wait. Booting ends once the node answers, or after 15 seconds without a network. |
| One short blip every 5 seconds | Green | `healthy` | Nothing. |
| Two blinks every 2 seconds | Amber | `degraded` | Read its reasons: [Degraded reasons](#degraded-reasons). |
| Slow blink, once a second | Red | `no network` | [No network](#no-network). |
| On solid | Red | `fault` | [Fault reasons](#fault-reasons). |
| Three quick blinks every second | Blue | `updating` | Wait for the release to finish. Do not power it off. |
| Very fast flicker | White | Identify | Someone asked the node to identify itself. It stops on its own (30 seconds by default). |

Identify overrides every other pattern while it runs. Start it from the Adopt page or the
node's details, or:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  identify -host 192.0.2.54 -for 30s -data /data -key /data/keys/release.pem
```

## Common problems

### A node is not answering

1. Look at its LED. Solid red, slow red or fast blue means it does not answer DNS: see
   [LED patterns](#led-patterns).
2. Read it: `status -host <address>` ([First look](#first-look)). If the command can't reach
   it at all, check the power and the cable, and that the controller's host can reach the
   node's network. The controller uses host networking, so it reaches what the host
   reaches.
3. If it answers `/status` but not DNS, read its state and reasons, and look them up in
   [Health reasons](#health-reasons).
4. A node that stopped answering keeps its last status on the Nodes page, shown as stale,
   with when it was last seen. It shows as offline after 30 seconds.
5. A node found over mDNS but missing from the Nodes page list is not in `settings.json`.
   Add it (adopt it first if it is new).

### The controller does not start

Read `docker compose logs`.

- `required variable ESPDNS_UID is missing a value`: copy `.env.example` to `.env` and set
  `ESPDNS_UID` and `ESPDNS_GID` to your user's ids.
- It can't write to the data directory: the directory must exist and be owned by
  `ESPDNS_UID`. Docker makes a missing one as root, which the controller can't use.
- `settings: ...`: `settings.json` does not parse, or has a field it does not know. Fix the
  file. The message names the problem.
- The dashboard listens on localhost only. Any other `ESPDNS_LISTEN` address is refused.

### "the fleet is locked by ..."

Another change holds the fleet lock: a job in the controller, or a CLI command. The message
says which, who started it, and since when. Wait for it to finish and try again. The
running job is also shown at the top of the web page.

### "this is the only node clients use"

Every change keeps one node or DNS peer answering. With one node and no DNS peer in
`settings.json`, nothing can be changed safely. Add a second node, or add a resolver your
clients also use to `"dns_peers"`. A node that is not adopted yet does not count.

### "another node is unhealthy" or "no other node or DNS peer is answering"

The rollout did not start on that node, and nothing was pushed to it. Fix the other node
or the DNS peer first. Then run the dry run and the change again. Nodes already changed are
skipped.

### Adoption is refused

The Adopt page and `espdns adopt` say why. The common reasons:

- **The address is in use.** Adoption never moves a node onto an address something else
  answers on: another node, a web server, a host that refuses connections, a DNS server, or
  a host that answers ARP. Choose a free address.
- **The address is a node's or DNS peer's in `settings.json`.** Choose another.
- **DHCP on a network with no DHCP server.** The network is in `settings.json`'s
  `"no_dhcp"`. Give the node a static address.
- **A config on DHCP without a reservation.** Reserve the node's address for its MAC in
  your DHCP server, then adopt it with the reservation ticked (`-reserved` on the CLI).
- **The changes on the zone primary are not confirmed.** With a manual primary, or one
  the controller can't reach, the dry run names the change to make by hand for each zone:
  allow the node to transfer the zone and send it NOTIFYs. Make the changes, then tick
  "I've made the changes on the zone primary" (`-primary-done` on the CLI).
- **The dry run is too old, or something changed.** The adoption must follow a passing dry
  run of the same request in the last 15 minutes. Run the dry run again.
- **The config does not pass its checks** for this node, for example its memory plan does
  not fit the board. Fix it on the **Configs** page.
- **Its firmware takes no node configs.** Update its firmware first.
- **The node was adopted before.** A node that has taken a config, or whose ID a config was
  pushed to before, is listed but not adopted from the web page. If you know which node it
  is (for example, it was wiped), adopt it from the CLI, dry run first:

  ```sh
  docker compose run --rm --entrypoint /espdns espdns-controller \
    adopt -host 192.0.2.60 -config node3.json -mdns 0 -data /data \
    -key /data/keys/release.pem -dry-run
  ```

  Then run it again without `-dry-run`, with `-add-to-settings`. `node3.json` is a file in
  the data directory's `configs/`.
- **Another node has the same ID,** or **another node is pinned to that address**: see
  [Pinned to another node](#pinned-to-another-node).

### The zone primary is paused because it is plain http

The controller sends the zone primary's API token with every request, so it talks to the
primary's API over https only. A `settings.json` that names a plain `http://` address does
not stop the controller. It starts with the primary **paused**: nothing is sent to it, and
the token never is. Adoption then names the change to make on the primary by hand. The
log, `espdns primary status` and the **Zone primary** section of the **System** page all
give the reason: `the zone primary is plain http: switch its API to https and confirm its
certificate`.

To fix it:

1. Turn on https for the primary's API. On Technitium: Settings, Web Service, enable HTTPS.
   Its HTTPS port is 53443 by default, and its self-signed certificate will do.
2. Change `"url"` under `"primary"` in `settings.json` to the https address, for example
   `"https://192.0.2.254:53443"`. The controller reads `settings.json` again within
   10 seconds.
3. Look at the certificate the primary presents:

   ```sh
   docker compose run --rm -T --entrypoint /espdns espdns-controller primary cert -data /data
   ```

   If the system's roots trust it, you are done. If it is self-signed, check the SHA-256 it
   shows against the one the primary itself shows, then pin it:

   ```sh
   docker compose run --rm -T --entrypoint /espdns espdns-controller \
     primary pin -data /data -sha256 <the SHA-256>
   ```

4. Check:

   ```sh
   docker compose run --rm -T --entrypoint /espdns espdns-controller primary status -data /data
   ```

Once pinned, only that certificate is accepted. If the primary later presents another one
(renewed, or someone else's), it is refused until you check and pin the new one the same
way. `primary unpin` removes the pin.

A primary of the `manual` kind is never reached by the controller, so this does not apply
to it.

### "stale release"

The node refused a release with `stale release (seq not above the last one applied)`. Each
release carries a sequence number (*seq*), and a node takes only a seq above the last one it
applied for that kind of release. This stops replays and downgrades.

The controller picks the seq from its own record and its clock: the current time in
milliseconds, or one above the last seq it signed for that node, whichever is higher. So a
stale release means the node took a higher seq than the controller expects. That happens
when:

- **another controller, with its own data directory, signed for this node.** Run one
  controller per fleet.
- **the controller's clock is behind.** The node took a seq from a time the controller has
  not reached yet. Set the host's clock right (use NTP).

`status -host <node>` shows the node's seqs on its `seq:` line, in milliseconds since 1970.
Compare them with the current time.

The related refusal **`seq too far ahead of this node's clock`** means the controller's
clock is more than 24 hours ahead of the node's. The controller also refuses to sign when
the last seq it recorded is more than 24 hours past its own clock. Both mean a wrong
clock: set the host's clock right.

A node that shows as stale on the Nodes page is a different thing: the controller can't
read it now and shows its last status. See [A node is not answering](#a-node-is-not-answering).

### Pinned to another node

The controller signs releases only for the node ID pinned to an address
([Pinned nodes](operations.md#pinned-nodes)). These refusals come from that rule:

- **`<address> answers as node "<id>", but node <other id> is pinned there: not signed`.**
  Something other than the pinned node answers on that address. Find out what. Run
  `discover` and compare the `NODE` column with `pin -data /data` (the list of pins).
  - If you replaced the node's board, pin the new board to the address. The new board must
    answer there:

    ```sh
    docker compose run --rm --entrypoint /espdns espdns-controller \
      pin -data /data -host 192.0.2.54 -node <the new board's ID>
    ```

  - If it is not your node, do not pin it. Take the device off that address.

- **`<address> is not pinned to a node`.** No node is pinned there. Adopt the node, or, for
  a node already in service, pin it by hand as above.

- **`node <id> is pinned to <address>: releases for it are signed there alone`.** That node
  now answers somewhere else. If you moved it on purpose, pin it at its new address. The
  pin moves, and its seqs move with it.

### A rollout stopped

See [When a rollout stops](operations.md#when-a-rollout-stops).
