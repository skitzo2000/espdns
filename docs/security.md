# espDNS security

This document describes who espDNS defends against, what it protects today, and what it
does not protect yet. It covers the code as it is in the 0.0.x alpha. Alpha software can
change anything between versions, so read this again when you upgrade.

To report a security problem, see [Reporting a vulnerability](#reporting-a-vulnerability).

For how the pieces fit together, see [architecture.md](architecture.md).

## Contents

- [The short version](#the-short-version)
- [What there is to protect](#what-there-is-to-protect)
- [The keys decide who can change a node](#the-keys-decide-who-can-change-a-node)
- [Threat model](#threat-model)
  - [An attacker on your LAN](#an-attacker-on-your-lan)
  - [A malicious web page](#a-malicious-web-page)
  - [A compromised controller host](#a-compromised-controller-host)
  - [A stolen board](#a-stolen-board)
- [What is protected](#what-is-protected)
- [What is not protected yet](#what-is-not-protected-yet)
- [Running it safely](#running-it-safely)
- [Reporting a vulnerability](#reporting-a-vulnerability)

## The short version

- Nodes accept a change only if it is **signed** with a key their firmware trusts. Anyone
  can send a node a release; only a valid signature gets it applied.
- The controller listens on **localhost only**, needs a **login**, and sends a strict
  **Content Security Policy**.
- Traffic between the controller and the nodes is **signed but not encrypted**. Someone who
  can watch your LAN can read it, including a Wi-Fi password in a config.
- A node's flash is **not encrypted**. Someone holding a board can read what is on it.
- The private **release key** is the most important secret. Whoever has it can change every
  node that trusts it.

## What there is to protect

| Asset | Where it lives |
|---|---|
| Correct DNS answers for your clients | The nodes |
| The nodes' availability | The nodes, and the controller's rolling push |
| The release signing key | The controller's data directory (`keys/release.pem`) |
| The recovery key | Offline, kept by you. Never on the controller |
| The controller login | The data directory (`auth.json`, an argon2id hash) |
| The zone primary's API token | The data directory (`keys/primary.token`) |
| Wi-Fi passwords of Wi-Fi nodes | Node configs in the data directory; the node's flash |
| What your clients look up | Each node's query log (RAM), the controller's Traffic page (RAM) |
| Your zone data | Your zone primary, the nodes' SD cards, the data directory |

## The keys decide who can change a node

Every change to a node is a signed release (see
[architecture.md, Signed releases and pins](architecture.md#signed-releases-and-pins)):

- The firmware holds two **public** keys: the release key (slot 0) and the recovery key
  (slot 1). Only public keys are built in, so firmware images contain no secrets.
- A node accepts a release only if it is signed by one of those keys, names this node and
  this chip image, and carries a sequence number above the last one it took for that kind.
- The controller signs with the **private release key**. The **private recovery key** is
  meant to stay offline. It exists to replace a lost or leaked release key: a firmware
  signed with the recovery key can carry a new release public key.

So the security of your whole fleet rests on the private release key. A firmware signed
with it can do anything on a node, including change which keys the node trusts.

The controller will only import a release key that the fleet trusts: it must match the
firmware's built-in release key, or a node listed in `settings.json` must report it in slot
0. It refuses the recovery key. The key is read from standard input, never from an argument
or an environment variable. From `controller/`:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
  key import -data /data -pub /keys/release.pub -recovery-pub /keys/recovery.pub < release.pem
```

The controller does not create keys, and it does not change which keys a node trusts.

## Threat model

espDNS is built for a home or small-office network. We consider four attackers.

### An attacker on your LAN

Someone with a device on the same network as the nodes. This could be a compromised
laptop, a smart TV or a guest.

**What they can do today:**

- **Send DNS queries** to the nodes. Nodes answer anyone who can reach them; there is no
  client access list. A node can be used to amplify traffic towards a spoofed source
  address.
- **Read node status.** `/status`, `/health` and `/metrics` are open to anyone who can reach
  the node. They show the node's ID, firmware, config name, zone names and counters, but no
  secrets.
- **Read the query log.** `/querylog` answers any request from a private (RFC 1918) or
  shared (RFC 6598) source address. On your LAN, that means anyone. Set
  `"querylog": {"client": "subnet"}` or `"hidden"` in the node config to store less, or
  `"enabled": false` to turn the log off.
- **Watch controller-to-node traffic.** It is plain HTTP. Configs, zone bundles and lists
  can be read in transit. A config for a Wi-Fi node holds its Wi-Fi password.
- **Change forwarded answers on the path.** Queries to your upstream forwarders are plain
  DNS (DNS over TLS is not built). An attacker who sits between a node and its
  forwarders can change answers. The node does not validate DNSSEC itself.
- **Impersonate a node's address** (for example with ARP spoofing). Zone transfers from your
  primary are allowed by address, with no TSIG, so an attacker at a node's address could
  copy those zones.

**What they cannot do:**

- **Change a node.** Every release is checked against the built-in public keys before
  anything is written. A wrong signature, the wrong node, the wrong chip image, or an old
  sequence number is refused. Replays and downgrades are refused even after a reboot.
- **Push to a node from outside your network.** Nodes accept releases (`POST /release`,
  `POST /ota`) and serve `/querylog` only from private source addresses.
- **Lock a node out with a huge sequence number.** Once a node's clock is set, it refuses a
  sequence number more than 24 hours past its clock. The controller never signs one more than
  24 hours past its own clock.
- **Trick the controller into signing for the wrong node.** The controller signs only for
  the node ID pinned to an address at adoption, with sequence numbers from its own record,
  never from `/status`. If a different node answers at that address, the push is refused.
- **Tie up a node's HTTP server for long.** Each request has one deadline (5 seconds for the
  headers, then a time based on size). A release's signature is checked before it takes the
  update lock, and only one release is received at a time.
- **Tie up the DNS workers with a slow forwarder.** No DNS worker waits on a forwarder. The
  pending table caps how much of it one forwarder group can use.
- **Forge forwarder answers easily from off the path.** Each upstream query uses a random
  source port and a random ID.
- **Confuse the controller with mDNS.** mDNS answers are treated as hints. Loopback,
  link-local, multicast and broadcast addresses are ignored, at most 64 nodes are listed from
  mDNS alone, and an answer never renames or moves a known node.
- **Reach the controller's web UI.** It listens on localhost only.
- **Use NOTIFY to push zone data.** A node takes NOTIFY only from its configured primary's
  address. A NOTIFY carries no data: it only makes the node check the zone with its primary.

### A malicious web page

A web page open in the browser of someone who runs the controller. It may try cross-site
requests, or DNS rebinding (making its own host name point at a node or at the controller).

**What protects you:**

- **The controller checks every request's `Host`.** It must be a localhost name. A change
  must not carry another site's `Origin`. CORS is never answered.
- **Sessions have two halves.** An `HttpOnly`, `SameSite=Strict` cookie, plus a token the
  page keeps and sends in the `X-Session-Token` header. Another site can't send that header,
  and another program on another localhost port can't read the token. The cookie alone opens
  no API.
- **A strict Content Security Policy** on every response: only the controller's own scripts
  and styles, no inline scripts, connections only to the controller, no framing. The
  builder page also allows exactly two hashed inline styles from the bundled ESP Web Tools.
  ESP Web Tools is bundled with the controller, not loaded from a CDN.
- **Other headers:** `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`.
- **Nodes check `Host` too.** A node serves a request only if its `Host` is the node's IP
  address, its mDNS name, or the `name` in its config. Anything else gets `421 Misdirected
  Request`. So a rebound page can't read `/status` or `/querylog` through your browser.
- **Blocklist downloads can't be turned against your network.** URL sources must be https
  and must connect to public addresses. The address is checked at each connection, after
  name lookup and after every redirect, so a redirect or DNS rebinding can't reach the
  controller, the nodes or other LAN hosts. A list server inside your network is fetched only
  if you add its host to `settings.json`'s `"internal_sources"`.

### A compromised controller host

Someone who gets control of the machine that runs the controller, or of its data
directory.

**This is the most serious case.** The data directory holds the release key. With it, an
attacker can sign any release for any node that trusts it, including firmware. They can
also read the zone primary's token, node configs with Wi-Fi passwords, and the query logs.

**What limits the damage:**

- **The recovery key is never on the controller.** The controller refuses to import it. If
  the release key leaks, you can sign a firmware with the recovery key that carries a new
  release key, and push it to each node. This works only while a node still runs firmware
  that trusts your recovery key: a firmware signed with the leaked release key could
  remove it. Act quickly.
- **The data directory is private.** Every directory is mode 0700 and every file 0600, set
  whatever the umask. At start the controller removes group and other access from anything
  it owns there. The key file is refused if it is open to others, owned by someone else, or a
  symbolic link.
- **The container is hardened.** It runs as your user, not root, with every Linux
  capability dropped, `no-new-privileges`, a read-only root filesystem, a small `noexec`
  `/tmp` in memory, and memory and process limits. It has no Docker socket and no
  toolchain. Its image is built from an allowlist of the source, never the data directory.
- **The zone primary's token goes over https only.** The token is never sent over plain
  http. The primary's certificate is always checked: by the system's trusted roots, or, for
  a self-signed certificate, by a SHA-256 fingerprint you confirm once. A different
  certificate is refused until you confirm it again. From `controller/`:

  ```sh
  docker compose run --rm -T --entrypoint /espdns espdns-controller primary cert -data /data
  docker compose run --rm -T --entrypoint /espdns espdns-controller primary pin -data /data -sha256 <fingerprint>
  ```

  Check the fingerprint on the primary itself before you pin it.
- **Secrets stay out of logs.** The token, the Wi-Fi passwords and the passphrase are never
  written to a page, a reply, the action log or a job record. A backup, or showing a config's
  Wi-Fi password, needs the login password again.
- **Backups are encrypted.** `espdns backup` writes an age-encrypted file, to a passphrase
  (at least 12 characters) or an age key.

**Other users on the same machine** can reach the controller's port, because it listens on
localhost. They still need the login. Failed logins back off per client: after 3 failures in
a row, each further failure locks that client out for 1 second, doubling up to 60 seconds.
Your own browser is tracked separately, so failures from elsewhere do not lock you out.

**Until you set a password, the controller is read-only.** It shows nodes but refuses every
change. The first password can be set from the browser only from the same machine, and only
while none is set.

### A stolen board

Someone takes a node, or gets a few minutes with it and a USB cable.

**What they get:** the ESP32's flash is not encrypted, and secure boot is not enabled.
Over USB they can read everything on the board: the node config, a Wi-Fi
password (from the config or from the Wi-Fi setup in NVS), and the SD card's zones and
blocklists. They can also flash their own firmware onto that board.

**What they don't get:** no private key is on a node. The board can't sign anything, so it
can't be used to change your other nodes.

**What to do:**

1. Change the Wi-Fi password, if it was a Wi-Fi node.
2. Remove the node's address from your zone primary's transfer and NOTIFY lists.
3. Remove the node from `settings.json`. Its pin in `pins/` stays until you replace it; pin
   the replacement board with `espdns pin` (see
   [architecture.md](architecture.md#signed-releases-and-pins)).
4. Consider any secondary zones it carried as read by the thief.

## What is protected

| Protection | What it does |
|---|---|
| **Signed releases** | ECDSA P-256 over every release. Bound to one node, one chip image, and a sequence number. The payload's SHA-256 is checked as it streams in. |
| **Signed project releases** | Each published release's `SHA256SUMS` is signed with the release key. CI builds the files but never has the key. See [releasing.md](releasing.md). |
| **Pins** | The controller signs only for the node ID pinned to an address, with its own record of sequence numbers. |
| **Sequence bound** | Nodes refuse sequence numbers more than 24 hours ahead of their clock once it is set; signers never sign one. |
| **Firmware rollback** | A new firmware boots on trial and rolls back if it does not come up healthy. |
| **Node HTTP guard** | `Host` check against DNS rebinding, one deadline per request, releases verified before they take any lock, JSON-escaped output. |
| **Release endpoints** | `POST /release`, `POST /ota` and `/querylog` only from private source addresses. |
| **Forwarding** | Random source port and ID per upstream query; no worker waits on a forwarder; per-group caps. |
| **Controller on localhost** | Refuses to listen on any other address. |
| **Controller CSP and headers** | Strict CSP, no inline scripts, no framing, no referrer, no CORS; ESP Web Tools bundled, not from a CDN. |
| **Sessions** | argon2id password hash; `HttpOnly` `SameSite=Strict` cookie plus a header token; 2 hours idle, 12 hours at most; all sessions end on restart or password change; login back-off; password asked again for backups and revealed Wi-Fi passwords. |
| **https-only primary with pinned certificate** | The primary's API token never goes over plain http; its certificate is verified or pinned by fingerprint. |
| **SSRF guard** | Blocklist URL sources are https from public addresses only, checked at every connection; internal list servers only from an explicit allowlist. |
| **mDNS treated as a hint** | Bad addresses ignored, entries capped, known nodes never moved or renamed by an answer. |
| **File modes** | Data directory 0700, files 0600, fixed at start; secret files refused if they are open to others or links. |
| **Container hardening** | Non-root, no capabilities, `no-new-privileges`, read-only root, `noexec` `/tmp`, memory and process limits. |
| **Secrets in, never out** | The password, release key, primary token and backup passphrase are read from standard input or a file, never from arguments; never logged or shown. |

## What is not protected yet

These are known gaps in the 0.0.x alpha. Issue numbers refer to the project's issue
tracker.

- **Controller-to-node traffic is plain HTTP.** Releases are signed, so they can't be
  changed, but they can be read. Anyone on the path can see configs, zone bundles, lists and
  query logs. Signed reads of `/status` and `/querylog` are planned but not built.
- **A Wi-Fi password travels in config releases** in plain text, over that plain HTTP.
  Wi-Fi is a best-effort fallback; wired nodes have no Wi-Fi password to leak.
- **No DNS over TLS.** Nodes speak plain DNS on port 53, to clients and to
  forwarders.
- **No client access list.** Nodes answer anyone who can reach them, and responses can be
  larger than queries. Do not expose nodes to the internet.
- **`/status`, `/health` and `/metrics` are open**, and `/querylog` is open to any private
  address.
- **No flash encryption, secure boot or anti-rollback** on the boards.
- **Zone transfers are not authenticated** (no TSIG). Your primary allows the nodes by
  address.
- **A release may target "any node".** The controller signs for one node each time, but a
  node accepts an any-node release for every kind except config.
- **Off-path spoofing** of forwarder and SOA replies is limited by the random ID and source
  port. More hardening is planned.
- **Key rotation** and key creation are not in the controller yet. Replacing a leaked release
  key needs the offline recovery key and a firmware build.

## Running it safely

- **Keep the release key off the controller host when you can.** Import it when you need
  it. Keep the recovery key offline, never on the controller host.
- **Do not expose the controller.** It listens on localhost on purpose. To use it from
  another machine, use an SSH tunnel rather than forwarding the port.
- **Do not expose the nodes to the internet.** Keep port 53 and port 80 on your LAN.
- **Put the nodes and the controller on a trusted network segment** if you can, since
  controller-to-node traffic is not encrypted.
- **Prefer wired nodes.** Then no Wi-Fi password is in any config.
- **Use `"querylog": {"client": "subnet"}` or `"hidden"`** if you don't need full client
  addresses, or turn the query log off.
- **Back up the data directory** with `espdns backup`, and store the backup apart from the
  host.
- **Check a release before you use it.** See [releasing.md, Checking a
  release](releasing.md#checking-a-release).

## Reporting a vulnerability

Please do not report security problems in a public issue. Follow the steps in
[SECURITY.md](../SECURITY.md) to report one privately.
