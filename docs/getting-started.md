# Getting started

This guide sets up the reference espDNS install: **two nodes and one controller**. The
nodes are small ESP32 boards that answer DNS for your network. The controller is one
Docker container that builds, flashes, adopts and updates them. Your router hands out both
nodes as DNS servers, so either one can be down without clients losing DNS.

espDNS is **alpha (0.0.x)**. Any version may change anything. Keep a second resolver
around until you trust it.

Every command here is a `docker`, `docker compose` or `git` command, plus a few lines of
plain shell to make directories and a settings file. Nothing else needs installing.

The examples use documentation addresses. Swap in your own:

| Example | What it stands for |
|---|---|
| `192.0.2.0/24` | Your LAN |
| `192.0.2.1` | Your router (the gateway) |
| `192.0.2.53`, `192.0.2.54` | The two nodes' static addresses |

## Contents

1. [What you need](#1-what-you-need)
2. [Get the code](#2-get-the-code)
3. [Make your keys](#3-make-your-keys)
4. [Build the firmware](#4-build-the-firmware)
5. [Start the controller](#5-start-the-controller)
6. [Set the password](#6-set-the-password)
7. [Import the release key](#7-import-the-release-key)
8. [Load the firmware into the controller](#8-load-the-firmware-into-the-controller)
9. [Flash both boards](#9-flash-both-boards)
10. [Write a config for each node](#10-write-a-config-for-each-node)
11. [Adopt each node](#11-adopt-each-node)
12. [Point your router at the nodes](#12-point-your-router-at-the-nodes)
13. [Check that it works](#13-check-that-it-works)

## 1. What you need

- **Two boards** from the catalog, each with a microSD card. The tested ones are the
  Guition JC-ESP32P4-M3-DEV, the Waveshare ESP32-S3-ETH and the Seeed XIAO ESP32S3 Sense.
  Use wired Ethernet where you can. See [Hardware](hardware.md).
- **A USB cable** for each board (data, not charge-only).
- **A Linux machine** on the same network as the nodes, with:
  - Docker, with the `docker compose` plugin v2.17 or newer (`docker compose version`).
  - git.
  - Chrome or Edge. The builder flashes boards over Web Serial, which Firefox and Safari
    don't have.
  - About 15 GB of disk for the ESP-IDF build image, used once to build the firmware.

  The controller uses host networking to find nodes over mDNS. Docker Desktop on macOS
  or Windows has not been tested.
- **Two free static addresses** on your LAN, outside your DHCP server's pool. Nodes don't
  ask DHCP for an address. You give each one its address when you flash it.
- **Access to your router's DHCP settings**, to hand out the nodes as DNS servers.

Run the controller on the machine you plug the boards into. Its dashboard listens on
`127.0.0.1` only, and the browser flashes over the USB port of the machine it runs on.

## 2. Get the code

```sh
git clone https://github.com/skitzo2000/espdns.git
cd espdns
```

All later commands start from this directory (the repository's top) or from
`controller/` inside it. Each step says which.

## 3. Make your keys

### Why you need your own keys

A node takes a change only when it is **signed with the release key** whose public half
is built into its firmware. Every change counts: firmware, configs, zones, blocklists,
even "flash your LED" and "reboot". The controller signs each change with the private
half of that key. So:

- **Every node and the controller must share one release key.** A node built with
  another key refuses everything the controller sends it. The only way back from that is a
  USB reflash.
- **The key is yours.** The public keys committed in this repository belong to the
  project. Only the maintainers hold their private halves. Firmware built with them would
  never take a change from your controller. So you make your own pair and build your own
  firmware with it.

You make two key pairs:

| Key | Used for | Where it lives |
|---|---|---|
| **Release key** (slot 0) | Signing every change | Your key directory, and the controller's data directory |
| **Recovery key** (slot 1) | Replacing a lost or leaked release key | Offline only. The controller refuses to import it |

Only the public halves go into the firmware. Firmware images hold no secret.

### Make them

From the repository's top, make a directory for the private keys **outside** the
checkout, then generate both pairs in the ESP-IDF image:

```sh
mkdir -m 700 "$HOME/espdns-keys"
IDF=espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp --network none \
  -v "$PWD/firmware:/fw" -v "$HOME/espdns-keys:/secrets" -w /fw "$IDF" \
  sh -c 'rm keys/release.pub keys/recovery.pub &&
    python tools/keygen.py /secrets/release.pem keys/release.pub &&
    python tools/keygen.py /secrets/recovery.pem keys/recovery.pub'
```

This replaces the project's public keys in `firmware/keys/` with yours, and writes the
private keys to `~/espdns-keys/` (mode 0600). It prints each key's fingerprint. The
container has no network. The key tool never overwrites a key file.

`git status` now shows the two `.pub` files as changed. Keep them: every later firmware
and controller build reads them. Commit them on a local branch if you like. They are
public.

Now:

- **Back up both `.pem` files** somewhere safe and private.
- **Move `recovery.pem` offline.** You only need it if the release key is lost
  ([Security](security.md#the-keys-decide-who-can-change-a-node)).

Keep the private keys out of the checkout. The firmware build in the next step mounts the
whole checkout into a container that has network access.

## 4. Build the firmware

Build the chip images with your public keys inside. From the repository's top:

```sh
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src "$IDF" \
  sh scripts/release/build-firmware.sh build/release/images esp32p4-rev1 esp32s3-octal
```

(`$IDF` is the image from step 3. Set it again if this is a new shell.)

- `esp32p4-rev1` and `esp32s3-octal` are the chip images the catalog's boards run. Leave
  the names off to build every chip image.
- Each image takes several minutes. The container needs network to fetch ESP-IDF
  components.
- The images are generic: no board, no address and no site settings are built in. The
  builder adds those when it flashes a board.
- The output is in `build/release/images/`.

The build fails on a compiler warning, on a changed component lock, or on an image with an
address built in. If it fails, the last lines of its log are printed.

## 5. Start the controller

From `controller/`. First, its settings file and its data directory. Keep the data
directory outside the checkout too: it will hold your release key.

```sh
cd controller
printf 'ESPDNS_UID=%s\nESPDNS_GID=%s\nESPDNS_DATA=%s\n' "$(id -u)" "$(id -g)" "$HOME/espdns-data" > .env
mkdir -m 700 "$HOME/espdns-data"
docker compose up -d --build
```

- `.env` tells Compose which user runs the controller (you), so the files it writes stay
  yours. Compose stops with `required variable ESPDNS_UID is missing a value` without it.
  [`.env.example`](../controller/.env.example) lists the other settings.
- Make the data directory yourself, before you start. Compose won't make it for you. The
  controller refuses to start if it can't write there.
- The image is built from your checkout, so it carries **your** public keys at `/keys`.
  Build it after step 3.

Check that it runs and is healthy:

```sh
docker compose ps
docker compose logs -f
```

The dashboard is at **http://127.0.0.1:8480**. Until a password is set it is read-only.

The controller listens on localhost only. To use it from another machine, forward the port
over SSH. To flash boards, plug them into the machine whose browser shows the dashboard.

Day to day, from `controller/`:

```sh
docker compose up -d --build    # after a git pull: rebuild and restart
docker compose down             # stop it (the nodes keep answering DNS)
```

## 6. Set the password

The dashboard has one user. Set its name and password with the `espdns` CLI, which is in the
same image. From `controller/`, on a terminal:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller passwd -data /data
```

It asks for a user name (Enter keeps `admin`), then the password twice, without echo. The
password must be at least 12 characters.

Without a terminal (a script), pipe the password in on standard input. `-T` passes
standard input through:

```sh
printf '%s\n' "$PW" | docker compose run --rm -T --entrypoint /espdns espdns-controller \
  passwd -data /data -user admin
```

The password is never an argument or an environment variable of the CLI. It is stored as
an argon2id hash. No restart is needed. Log in at http://127.0.0.1:8480.

## 7. Import the release key

Give the controller your release key. From `controller/`:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
  key import -data /data -pub /keys/release.pub -recovery-pub /keys/recovery.pub \
  < "$HOME/espdns-keys/release.pem"
```

- The key comes in on standard input, never as an argument.
- It is imported only if the firmware trusts it: it must match `/keys/release.pub`, which
  is your public key from step 3.
- The recovery key is refused, on purpose.

It prints the key's fingerprint and writes it to `keys/release.pem` in the data directory,
mode 0600. The controller uses it from its next action, with no restart.

To check it later:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  key status -data /data -pub /keys/release.pub
```

## 8. Load the firmware into the controller

The builder flashes the chip images from step 4. The controller loads chip images only as
a **signed release**, so you package your images, sign them with your release key, and
import them. From `controller/`:

```sh
# Package the chip images and the board catalog, with SHA256SUMS
docker compose run --rm -T -v "$PWD/../build/release:/release" --entrypoint /espdns espdns-controller \
  release build -version "$(cat ../VERSION)" -images /release/images -catalog /catalog -out /release/dist

# Sign SHA256SUMS with your release key (on standard input)
docker compose run --rm -T -v "$PWD/../build/release:/release" --entrypoint /espdns espdns-controller \
  release sign -dir /release/dist -pub /keys/release.pub < "$HOME/espdns-keys/release.pem"

# Check the signature and every file, then import the chip images
docker compose run --rm -T -v "$PWD/../build/release:/release:ro" --entrypoint /espdns espdns-controller \
  release import -dir /release/dist -pub /keys/release.pub -data /data
```

- `release build` needs a chip image for every board in the catalog. It writes only into
  a missing or empty directory: remove `build/release/dist` before you run it again.
- `release import` checks the signature and every file first, and imports nothing if a
  check fails. It ends with the names of the chip images it imported.

[Releasing](releasing.md) explains these files.

## 9. Flash both boards

Open **http://127.0.0.1:8480/builder.html** in Chrome or Edge. For each board:

1. **Pick the board** from the list. A board whose chip image isn't loaded says so: go
   back to step 8.
2. **Give it its address**, with the prefix length, and the **gateway**. For example
   `192.0.2.53/24` and `192.0.2.1` for the first node, `192.0.2.54/24` for the second.
   The address is written into the node's board partition. It is never saved with the
   board.
3. **Prepare image.** The controller builds the flash image in a moment: your chip image
   plus the board's definition and address.
4. **Plug the board in over USB** and press **Install over USB**. Pick the board's serial
   port. Installing **erases the board**.

If the browser lists no port, check the cable, then hold the board's BOOT button while you
plug it in.

After the install the node boots on its address. It isn't adopted yet: it runs on its
board's defaults and the firmware's, which forward queries to public resolvers.
Plug in its Ethernet cable, then do the second board.

**Wi-Fi boards.** A board with no Ethernet uses Wi-Fi (2.4 GHz only). Join it to your
network from the builder's **Wi-Fi** panel, over the same USB link, before you unplug it.
Wired is more reliable: use Wi-Fi only where you can't run a cable.

**espDNS.org** will have a web flasher. Until then, flash from your controller's builder.

## 10. Write a config for each node

Each node runs a **config**: a JSON file the controller signs and pushes to it. Open
**http://127.0.0.1:8480/configs.html**. Under **New config**, type a file name such as
`node1.json` and press **Create**. The smallest config is a name:

```json
{
  "name": "node1"
}
```

Every key you leave out keeps the board's or the firmware's default. The firmware forwards
to Quad9 (`9.9.9.9`, `149.112.112.112`) by default. To use other resolvers, add them:

```json
{
  "name": "node1",
  "forwarders": ["198.51.100.10", "198.51.100.11"],
  "time": { "tz": "UTC0", "ntp": ["pool.ntp.org"] }
}
```

Press **Create…**. The editor checks the config before it saves it. Make a second one,
`node2.json`, for the other node.

[`configs/example-node.json`](../configs/example-node.json) shows more keys: secondary
zones copied from your zone primary, conditional forwarders and blocking. Any
standards-compliant primary works: BIND, Knot, PowerDNS, Windows DNS or Technitium.

## 11. Adopt each node

Adoption gives a node its config and makes it yours. Open
**http://127.0.0.1:8480/adopt.html**. For each node:

1. **The node.** Pick it from the list of nodes that aren't adopted. The controller finds
   them over mDNS. **Identify** flashes its LED, if it has one, so you can match it to the
   board in your hand.
2. **Config and address.** Pick its config (`node1.json`). Keep **The config's, else the
   one it runs on**: the node keeps the address you flashed.
3. **The zone primary.** With no secondary zones in the config, there is nothing to do here.
   If the config has secondary zones, the dry run says what to change on your primary.
4. **Dry run**, then **Adopt**. The dry run checks everything and changes nothing. In the
   confirmation, leave **add to settings.json** ticked, so rollouts count this node.

A node that keeps its address takes the config without a reboot. Repeat for the second
node with `node2.json`.

If a node isn't listed (mDNS doesn't cross subnets), add it by its address on the Nodes
page.

## 12. Point your router at the nodes

In your router's DHCP server settings, set the **DNS servers** handed to clients to both
nodes:

```text
192.0.2.53
192.0.2.54
```

Remove any other DNS server from that list. If a third resolver is in the list, clients may
use it instead of the nodes.

Also make sure the nodes' addresses are outside the DHCP pool, or reserved, so no client
gets one of them.

Clients pick up the change when their lease renews. To see it sooner, reconnect a client
or renew its lease.

## 13. Check that it works

**On the dashboard.** http://127.0.0.1:8480 lists both nodes. Each should be healthy and
adopted.

**From the CLI.** From `controller/`:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller status -all -data /data
```

**Ask each node a question.** From any machine on the LAN:

```sh
docker run --rm --network host alpine:3 nslookup example.com 192.0.2.53
docker run --rm --network host alpine:3 nslookup example.com 192.0.2.54
```

Both should return an address. Then check failover: unplug one node and look up a new name
from a client. It still resolves through the other node. The client may wait for a
timeout on the missing node first.

## Next steps

- **Back up** the controller's data directory: the Backup page writes one encrypted file.
  It holds the release key. Keep your two private keys backed up as well, apart from it.
- **Updates.** After a `git pull`, rebuild the firmware (step 4), load it (step 8) and
  rebuild the controller (`docker compose up -d --build`). The controller updates nodes
  one at a time, and never takes down the last healthy node.
- [Operations](operations.md) covers updates, backups and recovery day to day.
- [Zones](zones.md) and [Blocking](blocking.md) cover the two main jobs a node does.
- [Architecture](architecture.md) describes how nodes, releases, blocking and zones work.
- The [Reference](reference/README.md) lists every CLI command, setting and API route.
- [Hardware](hardware.md) lists the boards and how to describe your own.
