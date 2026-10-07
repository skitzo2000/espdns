# espdns CLI

`espdns` is the command-line side of the controller. It finds nodes, adopts them, compiles
blocklists, checks node configs and zones, and sends signed releases to nodes one at a time.
It ships in the controller's image as `/espdns`.

Every flag below was taken from the command's own `-h` output. To see it yourself:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller <command> -h
```

Back to the [reference index](README.md).

## How to run it

Run every command from the repository's `controller/` directory, where `compose.yaml` is:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller <command> -data /data [flags]
```

Things to know:

- **Set up `.env` and the data directory first.** `docker compose run` reads the same
  `compose.yaml` as the controller, so it needs `ESPDNS_UID` and `ESPDNS_GID` in `.env` and
  an existing data directory (see [settings.md](settings.md#env-variables)).
- **Always pass `-data /data`.** The flag's default is `data`, a path that doesn't exist in
  the container. Overriding the entrypoint also drops the controller's own `-data /data`.
- **Paths are inside the container.** Your data directory is at `/data`. The board catalog
  is at `/catalog`. The firmware's public keys are at `/keys/release.pub` and
  `/keys/recovery.pub`. The container's root filesystem is read-only, so write output files
  under `/data`. To read other files from the host, mount them, for example
  `-v "$PWD/lists:/in:ro"` after `run`.
- **Use `-T` when you pipe into the command.** `-T` turns off the terminal, so standard input
  comes from your pipe or file.
- **The network is the host's.** `compose.yaml` uses host networking, so mDNS discovery and
  the nodes on your LAN work from `docker compose run` too.
- **One change at a time.** A command that changes nodes takes the fleet lock in the data
  directory and fails at once if the controller or another `espdns` holds it. It writes its
  start and result to the action log. A `-dry-run` takes no lock and is not logged.
  Ctrl-C stops a change at once; a second Ctrl-C quits.

### Secrets

Secrets never go in a command-line argument.

**The release signing key** (for every command that sends a release), one of:

- The copy imported into the data directory with [`key import`](#key), given as a file:
  `-key /data/keys/release.pem`. The examples on this page use it:

  ```sh
  docker compose run --rm --entrypoint /espdns espdns-controller \
    rollout -data /data -key /data/keys/release.pem -kind zones -all -zone /data/zones/home.arpa.zone
  ```

- On standard input with `-key -`, from a file outside the data directory:

  ```sh
  docker compose run --rm -T --entrypoint /espdns espdns-controller \
    rollout -data /data -key - -kind zones -all -zone /data/zones/home.arpa.zone < release.pem
  ```

- In the environment variable `ESPDNS_RELEASE_KEY` (the PEM, or base64 of it), passed
  through with `-e`. It is used only when `-key` is left at its default and `-recovery` is
  not set:

  ```sh
  docker compose run --rm -e ESPDNS_RELEASE_KEY --entrypoint /espdns espdns-controller \
    flush -data /data -host 192.0.2.53
  ```

The `-key` default, `../firmware/secrets/release.pem`, does not exist in the image, so give
the key one of the three ways above. The CLI does not pick up the imported key by itself.

With `-recovery` (sign with the offline recovery key, key slot 1), the environment variable is
not read: use `-key -`.

**The zone primary's API token** (`adopt` with an API-driven primary): `-primary-token-file`,
else `$ESPDNS_PRIMARY_TOKEN`, else the variable `-primary-token-env` names, else
`<data>/keys/primary.token` (stored by [`primary import`](#primary)).

**The login password and backup passphrase** are asked on the terminal, or read from the first
line of standard input when there is no terminal.

## Commands

| Command | What it does | Changes nodes |
|---------|--------------|---------------|
| [`discover`](#discover) | List the nodes found over mDNS and in `settings.json`. | no |
| [`status`](#status) | Show nodes' state. | no |
| [`adopt`](#adopt) | Give a new node its config and address. | yes |
| [`rollout`](#rollout) | Change nodes one at a time: firmware, config, zones, blocklist or overrides. | yes |
| [`reboot`](#reboot) | Reboot one node, only while another answers. | yes |
| [`blocklist`](#blocklist) | Compile lists into a blocklist or overrides file. | no |
| [`push`](#push) | Send a blocklist or overrides file to one node. | yes |
| [`config`](#config) | Check a node config, or send it to one node. | yes |
| [`zones`](#zones) | Check hosted zones, or send them to one node. | yes |
| [`pause`](#pause-identify-flush-revert) | Turn blocking off for a while. | yes |
| [`identify`](#pause-identify-flush-revert) | Flicker a node's LED. | yes |
| [`flush`](#pause-identify-flush-revert) | Drop a node's cached answers. | yes |
| [`revert`](#pause-identify-flush-revert) | Go back to the older blocklist, overrides or zones a node keeps. | yes |
| [`metrics`](#metrics) | Read a node's `/metrics`. | no |
| [`querylog`](#querylog) | Read a node's query log. | no |
| [`key`](#key) | Import or check the controller's release key. | no |
| [`primary`](#primary) | Import or check the zone primary's API token; show, pin or unpin its certificate. | no |
| [`passwd`](#passwd) | Set the dashboard login. | no |
| [`backup`](#backup) | Write an encrypted backup of the data directory. | no |
| [`restore`](#restore) | Restore a backup into a data directory. | no |
| [`recover`](#recover) | Rebuild `settings.json` from the nodes, without a backup. | no |
| [`pin`](#pin) | Bind a node's ID to its address for signing. | no |
| [`release`](#release) | Build, sign, verify or import a release's files. | no |
| [`version`](#version) | Print this build's version. | no |

## Shared flags

### Fleet flags

`discover`, `status`, `adopt`, `rollout` and `reboot` take these:

| Flag | Default | Meaning |
|------|---------|---------|
| `-data` | `data` | The data directory. Use `/data`. |
| `-settings` | `settings.json` in `-data` | The settings file. Its `nodes` count as peers, its `dns_peers` as DNS peers. |
| `-mdns` | `3s` (`discover`: `5s`) | Browse mDNS this long for other nodes. `0`: don't. |
| `-peer` | | Another node clients use. Counts for the last-healthy-node rule, never changed. Comma-separated or repeated. |
| `-dns-peer` | settings `dns_peers` | A resolver clients use besides the nodes (`addr` or `addr:port`). Counts as an answering peer while it resolves a forwarded name and answers its zones' SOA authoritatively. Repeat. |
| `-dns-peer-zone` | settings `dns_peer_zones`, else the node's secondary zones | A zone the DNS peers must answer for. Repeat. |
| `-no-dns-peers` | | Ignore the settings' `dns_peers`. |
| `-dry-run` | | Check the nodes and the rule for each; push nothing. |
| `-force` | | Start a change that may reboot a node while another node is unhealthy. One must still answer. |
| `-allow-single` | | Go ahead when the node is the only one. Clients get no DNS while it reboots. |
| `-key` | `../firmware/secrets/release.pem` | The release key: a PEM file, or `-` for standard input. See [Secrets](#secrets). |
| `-recovery` | | Sign with the offline recovery key (key slot 1). |

`discover` and `status` accept all of these but only read nodes.

### DNS check flags

`adopt`, `rollout` and `reboot` check each node's DNS after its change:

| Flag | Default | Meaning |
|------|---------|---------|
| `-check-forward` | `example.com` | A forwarded name that must resolve. Repeat. |
| `-check-local` | each zone's SOA | A name the node answers from its own zones. Repeat. |
| `-check-blocked` | | A name the blocklist must block (checked while blocking is on). Repeat. |
| `-must-resolve` | | A file of names that must resolve, one per line. |
| `-no-dns-checks` | | Only check that the node answers DNS. |

### Single-node flags

`push`, `config`, `zones`, `pause`, `identify`, `flush` and `revert` take:

| Flag | Default | Meaning |
|------|---------|---------|
| `-host` | none (required) | The node's address. There is no default node. |
| `-data` | `data` | The data directory. Use `/data`. |
| `-key` | `../firmware/secrets/release.pem` | The release key. See [Secrets](#secrets). |
| `-recovery` | | Sign with the offline recovery key. |

## discover

Lists every node found over mDNS or listed in `settings.json`: address, node ID, MAC, board,
chip image, firmware, network, addressing, state, and how it was found.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller discover -data /data
```

Flags: the [fleet flags](#fleet-flags), and `-json` to print JSON.

## status

Shows the state of some nodes or all of them.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller status -data /data -all
docker compose run --rm --entrypoint /espdns espdns-controller status -data /data -host 192.0.2.53,192.0.2.54
```

| Flag | Meaning |
|------|---------|
| `-host` | Node addresses (comma-separated or repeat). |
| `-all` | Every node found over mDNS or listed in `-settings`. |
| `-json` | Print JSON. |

One of `-host` or `-all` is required. Also takes the [fleet flags](#fleet-flags).

## adopt

Gives a node that isn't adopted yet its node config and address, and pins its ID to that
address. The node is found at the address it has now. A new address is kept only once the
node answers there.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  adopt -data /data -key /data/keys/release.pem -host 192.0.2.60 -node aa:bb:cc:dd:ee:ff \
  -config dns-a.json -address 192.0.2.53/24 -gateway 192.0.2.1 -add-to-settings -dry-run
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-host` | | The node's address now. |
| `-node` | | The node's ID (its MAC, from `discover`). Without `-host`, the node is found over mDNS; with it, the ID is checked. |
| `-config` | | The node config. A bare file name means `<data>/configs/<name>`. Its network is set from the address. |
| `-address` | the config's, else the node's current one | The static address with prefix length (`192.0.2.53/24`), or `dhcp` on a network with a DHCP server. Never `dhcp` on a network in `no_dhcp`. |
| `-gateway` | the config's, else the node's current one | The gateway. |
| `-reserved` | | With `dhcp`: the address is reserved for the node's MAC in your DHCP server. Without it, adopt asks, or stops after saying what to reserve. |
| `-name` | the config's | The node's name. |
| `-identify` | | Flicker the node's LED this long first, to match it to the board in your hand. |
| `-add-to-settings` | | Once adopted, add the node's address to `settings.json`. |
| `-wait` | `2m0s` | How long to wait for the node on its new address. |
| `-catalog` | `/catalog` | The board catalog, for the memory plan of a node on older firmware. |
| `-primary-kind` | settings `primary`, else `manual` | `manual` or `technitium`. |
| `-primary-url` | settings `primary` `url` | The zone primary's API address (`technitium`). The node is allowed to transfer its secondary zones there. |
| `-primary-token-file` | see [Secrets](#secrets) | A file holding the zone primary's API token. |
| `-primary-token-env` | | The name of an environment variable holding the token. |
| `-primary-done` | | The zone primary isn't changed from here (manual, or no API or token), and the changes adopt names were already made by hand. |

Also takes the [fleet flags](#fleet-flags) and the [DNS check flags](#dns-check-flags).

## rollout

Changes nodes one at a time: the canary first, then each node in turn. Each node is checked
and watched for `-soak` before the next starts. A change that needs a reboot reboots one node
at a time, only while another node or DNS peer answers.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  rollout -data /data -key /data/keys/release.pem -kind blocklist -all -file /data/lists/blocklist.bin -dry-run
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-kind` | | `firmware`, `config`, `zones`, `blocklist` or `overrides`. |
| `-host` | | The nodes to change, in order (comma-separated or repeat). |
| `-all` | | Every node found over mDNS or listed in `-settings`. |
| `-canary` | settings `canary` if one of them, else the first | The node to change first. |
| `-soak` | `1m0s` | How long each changed node runs, checked again, before the next starts. |
| `-image` | | `firmware`: a chip image directory (with `image.json` and `app.bin`), or `name=app.bin`. Repeat per chip image. |
| `-board` | | `firmware`, for a node from before board definitions: the board a `name=app.bin` image was built for. |
| `-reinstall` | | `firmware`: also push to nodes that already run the build. |
| `-config` | | `config`: `host=file` per node, or one file with one `-host`. A bare file name means `<data>/configs/<name>`. |
| `-catalog` | `/catalog` | `config`: the board catalog, for the memory plan of a node on older firmware. |
| `-zone` | | `zones`: a zone master file, `<zone>.zone` or `origin=path` (comma-separated or repeat). |
| `-empty` | | `zones`: remove every hosted zone. |
| `-file` | | `blocklist` or `overrides`: the file from `espdns blocklist`. |
| `-allow-degraded` | | A degraded reason accepted after the change (besides those the node had). Repeat. |

Also takes the [fleet flags](#fleet-flags) and the [DNS check flags](#dns-check-flags).

## reboot

Reboots one node, only while another node or DNS peer answers.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  reboot -data /data -key /data/keys/release.pem -host 192.0.2.53 -if-pending
```

| Flag | Meaning |
|------|---------|
| `-host` | The node to reboot. |
| `-if-pending` | Only if a release it took waits for a reboot. |

Also takes the [fleet flags](#fleet-flags) and the [DNS check flags](#dns-check-flags).

## blocklist

Compiles lists into a blocklist or overrides file. It sends nothing.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  blocklist -list hosts:/data/blocking/sources/hosts.txt \
  -allow domains:/data/blocking/sources/allow.txt -out /data/lists/blocklist.bin
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-list` | | `kind:path` or `kind:URL` of a list to block. Kinds: `hosts`, `domains`, `wildcard`, `adblock`, `rpz`. Repeat. |
| `-allow` | | `kind:path` or `kind:URL` of a list to allow. Repeat. |
| `-out` | | The file to write. |
| `-internal` | | A host (a name or an IP address) a URL source may be fetched from over plain http or at an inside (private, loopback, link-local) address, and only that host. Repeat. Without it a URL source is https from a public address only. The controller uses `settings.json`'s `internal_sources`. |
| `-popular` | | Popular names never to block by accident: a Tranco CSV (`rank,name`) or one name per line. |
| `-must-resolve` | | Names the list must not block, one per line. |
| `-keys` | `10` | Keys to try for one that blocks no popular name. |
| `-bits` | `44` | Hash bits. |
| `-xor` | `10` | Xor filter fingerprint bits for the SD tier. `0` for none (use `0` for overrides). |
| `-max-change` | `20` | Refuse a build whose entries or bytes change by more than this percentage from the previous build. `0`: any change in size. |
| `-min-change` | `100` | A change of this many entries or fewer is always taken. `0`: no floor. |
| `-previous` | `-out` | The previous build to compare the size with. None there: any size. |
| `-accept-change` | | Take this build once, even if its size changed by more than `-max-change`. |
| `-json` | | Print the result as JSON. |

## push

Sends a blocklist or overrides file to one node. To change several nodes safely, use
[`rollout`](#rollout).

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  push -data /data -key /data/keys/release.pem -host 192.0.2.53 -kind overrides -file /data/lists/overrides.bin
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-kind` | `blocklist` | `blocklist` or `overrides`. |
| `-file` | | The file from `espdns blocklist`. |

Also takes the [single-node flags](#single-node-flags).

## config

Checks a node config, or sends it to one node. See [node-config.md](node-config.md).

```sh
docker compose run --rm --entrypoint /espdns espdns-controller config -data /data -check -file dns-a.json
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-file` | | The node config. A bare file name means `<data>/configs/<name>`. Required. |
| `-check` | | Only check the file and print the payload. With `-host`, also run the checks for that node, read only. The payload includes the Wi-Fi password. |
| `-board` | | With `-check`: also check the memory plan on this catalog board. |
| `-catalog` | `/catalog` | The board catalog, for `-board`. |
| `-confirm` | `true` | After a change of address, reach the node on it so it keeps the config. |
| `-reboot` | | If the config waits for a reboot, reboot the node now (coordinated) and confirm it. |
| `-peer` | | Another node clients use, for the rule before a reboot. |
| `-allow-single` | | Reboot the node even if it is the only one answering. |
| `-force` | | Reboot the node while another node is unhealthy (one must still answer). |
| `-settings` | `settings.json` in `-data` | The settings file, for its `dns_peers`. |
| `-dns-peer`, `-dns-peer-zone`, `-no-dns-peers` | | As in the [fleet flags](#fleet-flags). |

Also takes the [single-node flags](#single-node-flags). `-host` is required unless you use
`-check`.

## zones

Checks hosted zones (RFC 1035 master files, one per zone), or sends them to one node. A push
replaces every hosted zone the node had. The node applies it live.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller zones -data /data -check -zone /data/zones/home.arpa.zone
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-zone` | | A zone's master file, named `<zone>.zone`, or `origin=path`. Repeat. |
| `-check` | | Only check the zones (against `-limit-kb`) and say what they hold. |
| `-config` | | The node's config: refuse a zone that is also one of its secondary or forward zones. |
| `-limit-kb` | `64` | With `-check` or `-out`: the node's `memory.hosted_zones_kb`. A push reads it from the node. |
| `-out` | | Write the payload to this file instead of pushing it. |
| `-empty` | | Push no zones: remove every hosted zone from the node. |

Also takes the [single-node flags](#single-node-flags). `-host` is required to push.

## pause, identify, flush, revert

Control commands. Each applies live. None survives a reboot, except `revert`, which holds
until a newer release arrives.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller pause -data /data -key /data/keys/release.pem -host 192.0.2.53 -for 30m
```

| Command | Flag | Default | Meaning |
|---------|------|---------|---------|
| `pause` | `-for` | `5m0s` | How long blocking stays off. At most `168h` (a week). `0` resumes it. |
| `identify` | `-for` | `30s` | How long the LED flickers. At most `1h`. `0` stops it. Works on a node that isn't adopted yet. |
| `flush` | | | Drops the node's cached answers. |
| `revert` | `-kind` | `blocklist` | `blocklist`, `overrides` or `zones`: go back to the older copy the node keeps. |

All four take the [single-node flags](#single-node-flags). Like every command that sends a
release, they sign only for the node ID pinned to the address (see [`pin`](#pin)).
`identify` also signs for an address with no node pinned yet.

## metrics

Reads a node's `/metrics` and sums it up. See
[node-endpoints.md](node-endpoints.md#metrics).

```sh
docker compose run --rm --entrypoint /espdns espdns-controller metrics -host 192.0.2.53
```

| Flag | Meaning |
|------|---------|
| `-host` | The node's address. |
| `-raw` | Print `/metrics` as the node sends it (Prometheus text). |
| `-json` | Print the parsed metrics as JSON. |

## querylog

Reads a node's query log: what it holds, then, with `-follow`, what comes. The node answers
only clients on private addresses. See [node-endpoints.md](node-endpoints.md#querylog).

```sh
docker compose run --rm --entrypoint /espdns espdns-controller querylog -host 192.0.2.53 -follow
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-host` | | The node's address. |
| `-cursor` | `0` | Start after this sequence number. `0`: the oldest the node holds. |
| `-follow` | | Keep reading new queries as they come. Ctrl-C ends it. |
| `-every` | `2s` | With `-follow`, how often to read. |
| `-json` | | One JSON object per query. |

## key

The controller's release key, `<data>/keys/release.pem` (mode `0600`). The dashboard signs
node actions and pushes with it.

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
  key import -data /data -key - -pub /keys/release.pub -recovery-pub /keys/recovery.pub < release.pem
docker compose run --rm --entrypoint /espdns espdns-controller \
  key status -data /data -pub /keys/release.pub -recovery-pub /keys/recovery.pub
```

`key import` reads the key (PEM, or base64 of it) and writes it only if the fleet trusts it:
it is the firmware's built-in release key (`-pub`), or a node in `settings.json` lists it as
its release key. The recovery key is always refused. `key status` says whether the key is
there and usable, and who trusts it. Neither changes a node.

| Flag | Default | Commands | Meaning |
|------|---------|----------|---------|
| `-data` | `data` | both | The data directory. |
| `-key` | `-` | import | `-` reads the key from standard input; or a PEM file. |
| `-pub` | | both | The release public key the firmware is built with. A key that matches it is trusted. |
| `-recovery-pub` | | both (required for import) | The recovery public key. That key is never imported. |
| `-replace` | | import | Replace a different key imported before. |
| `-settings` | `settings.json` in `-data` | both | The settings file whose nodes are asked which keys they trust. |
| `-mdns` | `0` | both | Browse mDNS this long for more nodes. A node found only over mDNS is reported but never vouches for a key. |

## primary

The zone primary's API token, `<data>/keys/primary.token` (mode `0600`). Needed only for an
API-driven primary (`technitium`). See [settings.md](settings.md#primary).

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller primary import -data /data < primary-token.txt
docker compose run --rm --entrypoint /espdns espdns-controller primary status -data /data
docker compose run --rm --entrypoint /espdns espdns-controller primary cert -data /data
docker compose run --rm --entrypoint /espdns espdns-controller primary pin -data /data -sha256 <fingerprint>
docker compose run --rm --entrypoint /espdns espdns-controller primary unpin -data /data
```

- `primary import` reads the token from standard input. The same token again changes
  nothing; a different one needs `-replace`.
- `primary status` says which zone primary `settings.json` names, whether it is paused
  because its address is plain `http://`, and whether the token is there and usable. It
  never prints the token and does not call the primary.
- `primary cert` shows the certificate the primary presents now: its SHA-256 fingerprint,
  subject, issuer, names and dates, and whether it is pinned or trusted by the system's
  roots. It only makes a TLS handshake: no token is sent.
- `primary pin -sha256` pins a self-signed certificate. Check the fingerprint on the
  primary itself first. It pins only if the primary still presents that certificate.
- `primary unpin` removes the pin. Then only a certificate the system's roots trust is
  accepted.

| Flag | Commands | Meaning |
|------|----------|---------|
| `-data` | all | The data directory. |
| `-replace` | import | Replace a different token imported before. |
| `-sha256` | pin | The fingerprint `primary cert` showed, once checked on the primary. |

## passwd

Sets the dashboard's one login: a user name and a password (at least 12 characters). It is
stored as an argon2id hash in `<data>/auth.json`. Every existing session ends.

On a terminal, it asks for the name (Enter keeps the one shown) and the password twice:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller passwd -data /data
```

Without a terminal, the password is the first line of standard input:

```sh
printf '%s\n' "$ESPDNS_PASSWORD" | docker compose run --rm -T --entrypoint /espdns espdns-controller passwd -data /data -user admin
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-data` | `data` | The data directory. |
| `-user` | asked on a terminal; else the one set before, else `admin` | The user name. |
| `-wait` | `4m0s` | No terminal: how long standard input may stay silent before the first line. `0`: no limit. |

You can also set the first password in the browser, from the controller's own machine, while
none is set.

## backup

Writes the data directory to one encrypted file ([age](https://age-encryption.org) format).
It waits for the fleet lock, so nothing changes while it writes.

Write it to the host through standard output, with the passphrase on standard input:

```sh
printf '%s\n' "$ESPDNS_BACKUP_PASSPHRASE" | docker compose run --rm -T --entrypoint /espdns espdns-controller \
  backup -data /data -out - > espdns-backup.age
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-data` | `data` | The data directory. |
| `-out` | | The backup file to write. It must not exist. `-` writes to standard output (not to a terminal). |
| `-recipient` | | An age public key (`age1...`) to encrypt to instead of a passphrase. Repeat for several. |
| `-firmware` | | Include `firmware/` (builds and chip images: the largest part). |
| `-wait` | `10m0s` | How long to wait for the fleet lock. `0`: not at all. |

Without `-recipient`, it asks for a passphrase (at least 12 characters) on the terminal, or
reads the first line of standard input. Keep the passphrase apart from the backup: the backup
holds the release key and the Wi-Fi passwords.

## restore

Restores a backup into a data directory. Stop the controller first
(`docker compose down`). Everything is checked before anything is put in place.

```sh
docker compose run --rm -v "$PWD/espdns-backup.age:/backup.age:ro" --entrypoint /espdns espdns-controller \
  restore -data /data -in /backup.age -dry-run
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-data` | `data` | The data directory to restore into. It must be empty unless you use `-force`. |
| `-in` | | The backup file, or `-` for standard input. |
| `-identity` | | An age identity file (`AGE-SECRET-KEY-1...`) for a backup made with `-recipient`. |
| `-dry-run` | | List and check the backup; write nothing. |
| `-force` | | Restore into a data directory that isn't empty, moving what is there aside first. |

The passphrase is asked on the terminal, else read from the first line of standard input.
With `-in -`, it must come from the terminal.

## recover

Rebuilds what it can of a data directory from the nodes, when you have no backup. Import the
release key first ([`key import`](#key)). It only reads the nodes. It writes `settings.json`
if there is none (the nodes in service that trust the key), pins each listed node to its
address, saves each node's `/status` under `recovered/<time>/`, and says per node what can't
come back.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller recover -data /data -dry-run
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-data` | `data` | The data directory. |
| `-host` | | Node addresses to read besides those found over mDNS and in `settings.json`, comma-separated. |
| `-mdns` | `3s` | How long to browse mDNS. `0`: only `-host` and `settings.json`. |
| `-add-to-settings` | | Add the nodes found to an existing `settings.json`. |
| `-dry-run` | | Read the nodes and say what would be written; write nothing. |

## pin

Releases are signed only for the node ID pinned to an address, never for the ID a node
reports. Adoption pins a node, and `recover` pins the nodes it lists. Use `pin` for the rest:
a node adopted before pins existed, or a replacement board at an adopted node's address.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller pin -data /data
docker compose run --rm --entrypoint /espdns espdns-controller pin -data /data -host 192.0.2.53 -node aa:bb:cc:dd:ee:ff
```

| Flag | Meaning |
|------|---------|
| `-data` | The data directory. |
| `-host` | The node's address. Without it: list the pinned nodes and their sequence numbers. |
| `-node` | The node's ID (its chip MAC). The node must answer at `-host` with this ID. |

## release

A release's files. See [releasing.md](../releasing.md) for the whole process.

| Command | What it does |
|---------|--------------|
| `release build` | Makes a release's files from the exported chip images and the board catalog, with `SHA256SUMS`. Uses no key. |
| `release sign` | Signs `SHA256SUMS` with the release key, read from standard input. Only the key that matches `-pub` is taken. |
| `release verify` | Checks the signature with `-pub`, and every file against `SHA256SUMS`. |
| `release import` | Verifies, then puts the release's chip images in `<data>/firmware/images`, where the dashboard finds them. |

```sh
docker compose run --rm -v "$PWD/../espdns-0.0.1:/release:ro" --entrypoint /espdns espdns-controller \
  release verify -dir /release -pub /keys/release.pub
docker compose run --rm -v "$PWD/../espdns-0.0.1:/release:ro" --entrypoint /espdns espdns-controller \
  release import -dir /release -pub /keys/release.pub -data /data
```

| Flag | Commands | Meaning |
|------|----------|---------|
| `-version` | build (required) | The version released. Every chip image must be it. |
| `-images` | build (required) | The exported chip images, `<dir>/<image>/image.json`. |
| `-catalog` | build (required) | The board catalog (`/catalog` in the image). A factory image is made for each board. |
| `-out` | build (required) | Where the release's files go. Must be missing or empty. |
| `-include` | build | Another file the release carries and `SHA256SUMS` lists. Repeat. |
| `-dir` | sign, verify, import (required) | The release's files, with `SHA256SUMS`. |
| `-pub` | sign, verify, import (required) | The release public key the firmware is built with (`/keys/release.pub` in the image). |
| `-data` | import (required) | The data directory. |

## version

Prints this build's version (the repository's `VERSION`). Takes no flags.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller version
```
