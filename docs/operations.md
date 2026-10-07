# Operating espDNS

This guide covers the day-to-day work of running an espDNS fleet: updating the controller
and the nodes, the safety rules every change follows, pinned nodes, backup and restore, and
getting a fleet back when the controller's data is lost.

espDNS is alpha software (version 0.0.x). Any version may change anything. Read the
[CHANGELOG](../CHANGELOG.md) before you update.

It assumes a controller and nodes set up as in [Getting started](getting-started.md). When
something goes wrong, see [Troubleshooting](troubleshooting.md).

## Before you start

Run every command in this guide from the `controller/` directory of your clone. That is
where `compose.yaml` and your `.env` are.

The controller's image also holds the `espdns` command line tool (the CLI). You run it with
`docker compose run`, on the same data directory the controller uses:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller <command> -data /data [flags]
```

Two things to know about this form:

- Without `-T`, Docker gives the command a terminal. Use that when the command asks you
  something, such as a password.
- With `-T`, the command reads its standard input from a pipe or a file. Use that when you
  pipe a secret in. Secrets are never command-line arguments.

Each command prints its flags with `-h`:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller rollout -h
```

## The safety rules

Every change to a node follows the same rules, whether it comes from the web page or the
CLI. Nothing in the web page loosens them.

- **One change at a time.** Every change takes the *fleet lock* first. A second change
  stops at once with `the fleet is locked by <who> (<what>) ... since <time>`. Wait for
  the first one to finish, then try again. The lock goes away when its holder exits, even
  after a crash, so there is never a stale lock to clear.
- **One node at a time.** A rollout changes one node, checks it, watches it for a while
  (the *soak*), and only then moves to the next node.
- **The canary goes first.** The canary is the node changed first. Set a default with
  `"canary"` in `settings.json`, or choose one for each change. If the canary fails, the
  rollout stops and the other nodes are not touched.
- **Never the last healthy node.** Before each node, another node or a *DNS peer* must be
  answering. A DNS peer is a resolver your clients also use, such as your zone primary
  (`"dns_peers"` in `settings.json`). A node that is not adopted yet does not count.
- **Nobody else unwell.** If another node or DNS peer is unhealthy, a change that may
  reboot a node (firmware, a config, a blocklist) does not start.
- **Dry run first.** An Apply runs its own dry run before it touches a node. On the Push
  and Adopt pages, the real run must follow a dry run that passed in the last 15 minutes,
  of the same choices and the same files. On the CLI, run with `-dry-run` first.

So you need **at least two nodes, or one node and a DNS peer**, in `settings.json`. With a
single node and no DNS peer, every change that touches the node is refused: `this is the
only node clients use: they get no DNS while it reboots or if the change breaks it`.

Every change is written to the action log, `log/actions.jsonl` in the data directory, with
who started it and how it ended.

## Updating the controller

Back up first ([Backup](#backup)). Then pull the new version and rebuild:

```sh
git pull
docker compose up -d --build
```

Build the controller from your own checkout. Its image carries the public keys in
`firmware/keys/`, and if you made your own keys
([Getting started](getting-started.md#3-make-your-keys)), those are yours. The controller
images the project publishes carry the project's public keys instead. They suit only a
fleet that runs the project's own firmware.

Check that it came up and which version it runs:

```sh
docker compose ps
docker compose logs --tail 20
docker compose run --rm -T --entrypoint /espdns espdns-controller version
```

The data directory is not changed by an update. The nodes keep answering DNS while the
controller is down.

## Updating node firmware

### Versions

The firmware and the controller share one version number. A node reports its version in
its status. The controller compares each node's version with the newest firmware it has
for that node, and gives each node one of these states:

| State | Meaning |
| --- | --- |
| `available` | A newer build is there for this node. |
| `current` | The node runs the newest build there. |
| `newer` | The node runs a newer build than any the controller has. |
| `unordered` | The node runs firmware from before version numbers. Update it with a rollout. |
| `no_build` | The controller has no build for this node's chip image. |
| `unknown` | The controller has not read the node yet. |

Two builds of the same version are ordered by build time.

### Get the firmware into the controller

The controller pushes only firmware that is in its data directory. It loads chip images
only as a **signed release**, which it checks against the release key your nodes trust.

A node takes a release only when it is signed with the key built into the firmware it
runs. So new firmware must carry the same public keys, or the node would refuse every
change after it. If you made your own keys, as
[Getting started](getting-started.md#3-make-your-keys) does, build the new firmware
yourself, from a checkout with those keys in `firmware/keys/`:

1. Pull the new version: `git pull`.
2. Build the chip images, as in
   [Getting started, step 4](getting-started.md#4-build-the-firmware).
3. Package them, sign them with your release key and import them, as in
   [Getting started, step 8](getting-started.md#8-load-the-firmware-into-the-controller).
   Remove `build/release/dist` from the last time first: `release build` writes only into
   a missing or empty directory.

The import is the same command whoever built the release. For a release in
`../build/release/dist`:

```sh
docker compose run --rm -T -v "$PWD/../build/release:/release:ro" --entrypoint /espdns \
  espdns-controller release import -dir /release/dist -pub /keys/release.pub -data /data
```

It checks the signature and every file first. If anything does not check, it imports
nothing. It takes the fleet lock, so it is refused while a change runs. The chip images
land in `firmware/images/` in the data directory, where the Nodes page finds them.

The project's published releases are built with the project's keys. Use one only if your
nodes run the project's firmware. [Releasing](releasing.md) explains what a release holds
and how to check one.

### Update from the web page (the Apply flow)

The controller collects changes first and sends them later. An edit, or a firmware update,
becomes a *pending change*. Nothing is sent to a node until you apply.

1. Open the controller, `http://127.0.0.1:8480`. The **Nodes** page says when an update is
   there, for example "Update available: 0.0.1 → 0.0.2".
2. Click **Update** (or **Update all**). The Update panel shows each node, from which
   version to which. Confirm, and the updates join the pending changes. Nothing is sent yet.
3. The orange chip in the top bar says how many changes wait ("2 changes to apply"). Open
   it. The panel lists each change, what applying it does, and which nodes restart. You can
   discard a change here.
4. Open **How it rolls out**. Choose the node to start with (the canary) and how long to
   watch each node: 1, 5 or 15 minutes.
5. Click **Apply**. You can follow it in the panel.

The apply runs in five steps:

1. **Check.** Each changed file is still the version you edited, and every node in
   `settings.json` answers. Nothing is written yet.
2. **Write.** The changed files are saved. The version each one replaced is kept.
3. **Compile.** Any blocklist the changes touch is compiled.
4. **Dry run.** Each rollout is checked against every node it goes to, before any node is
   touched.
5. **Push.** The rollouts run one after the other: node configs, hosted zones, overrides,
   blocklists, then firmware. Each rollout changes one node at a time, canary first.

A firmware update restarts each node, one at a time. Each node boots the new firmware on
trial. If it is not up and answering within 90 seconds, it rolls back to the old firmware
on its own.

**Stop after this node** stops the apply at the next safe point: after the node being
changed is finished and checked, or during a soak.

If the apply stops part way (a node failed its checks, or you stopped it), the changes stay
pending. Click Apply again to finish them: nodes that already have a change are skipped.

The apply needs the release key in the controller. Without it, Apply is refused.

### Update from the Push page

The **Push** page (under **System**) runs one rollout directly, without pending changes.
Choose what to push (for firmware, the chip images in the data directory), the nodes and
their order, the canary and the soak (1 minute to 1 hour). Run the **Dry run**, then
**Roll out**. The page shows each node's progress, and what to do if it stops.

### Update from the command line

The same rollout, from the CLI. It signs with the controller's copy of the release key,
`/data/keys/release.pem`. Give one `-image` for each chip image your nodes run (the
`IMAGE` column of `espdns discover`). First the dry run:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  rollout -kind firmware -all -mdns 0 -data /data -key /data/keys/release.pem \
  -canary 192.0.2.53 \
  -image /data/firmware/images/esp32p4-rev1 -image /data/firmware/images/esp32s3-octal \
  -dry-run
```

It reads every node, finds the image for each one, checks the safety rules for each step,
and pushes nothing. It stops at the first problem: a node it can't reach, a chip image with
no `-image`, a rule that fails. If it passes, run the same command without `-dry-run`.

- `-all -mdns 0` means every node in `settings.json`, and only those. `-host a,b` names the
  nodes instead, in order.
- `-canary` is the node changed first. Without it, the rollout uses `settings.json`'s
  `"canary"` if it is one of the nodes, else the first node.
- `-soak 5m` watches each node longer. The default is one minute.
- A node that already runs the build is skipped (`already had it`).
- The run ends with `done: ...`, or with `stopped at <node>` and the nodes it did not touch.

Check the result:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller status -all -mdns 0 -data /data
```

Every node should be `healthy`, on the new firmware, with no `reboot pending`.

Ctrl-C stops a CLI rollout at once. The node being changed is left as
[When a rollout stops](#when-a-rollout-stops) describes.

### When a rollout stops

A stopped rollout leaves at most one node changed or rolled back. The rest still answer.
First look at every node (the Nodes page, or `status -all` as above). Then:

- **`not started: no other node or DNS peer is answering`** or **`another node is
  unhealthy`**: nothing was pushed to that node. Fix the other node or the DNS peer, then
  run the dry run and the rollout again. Nodes already updated are skipped.
- **The node rolled back** (it came back on its old firmware): it runs the old firmware
  and should be healthy. Do not push the same build again. Find out why it failed first.
- **The node took the update but is not healthy yet**: wait, and look again. A node on
  trial rolls itself back within 90 seconds if it can't come up.
- **A node shows `reboot pending`**: the rollout was cut off between the push and the
  reboot. Reboot it under the same rules, from the node's details on the Nodes page
  (**Reboot (pending)**, enabled only while a reboot is pending), or:

  ```sh
  docker compose run --rm --entrypoint /espdns espdns-controller \
    reboot -host 192.0.2.54 -if-pending -mdns 0 -data /data -key /data/keys/release.pem
  ```

- **A blocklist was sent back** (`reverted (back on the copy each had): ...`): a list
  failed its checks, so every node that took it went back to the list it had before. Fix
  the list, then start again from the dry run.
- **A node did not answer**: if it is in the `not touched` list, it was never changed.
  Find out why before you go on.

## Pinned nodes

The controller signs a release for a node only when that node is **pinned** to its address.
The pins are kept in `pins/` in the data directory, one file per node. Each holds the node's
ID (its chip's MAC address), the address it is pinned to, and the last sequence number
(*seq*) signed for it, per kind of release.

**Why.** A node's `/status` says who it is, but anything that answers on the node's address
can send a `/status`: another device that took the address, or a spoofed reply. So the
controller never signs for the ID a `/status` gives. It signs for the ID pinned to the
address, with the next seq after the one it recorded. If the address answers as another
node, the push is refused and nothing is signed.

A node is pinned:

- when it is adopted;
- when `espdns recover` finds it ([Recovering from the nodes](#recovering-from-the-nodes));
- when a config moves it to a new address, once it is confirmed there;
- by hand, with `espdns pin`.

List the pins and their seqs:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller pin -data /data
```

Pin a node by hand. The node must answer at that address as that ID. Read the ID from the
`NODE` column of `espdns discover`, from the Adopt page, or from the node's label:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller \
  pin -data /data -host 192.0.2.54 -node <its ID>
```

You need this when you replace a node's board and put the new board at the old address. The
old board's pin is then moved off that address. Its seqs are kept, in case it comes back.

Identify (flickering a node's LED) is the one exception: it is signed for a node that is
not adopted yet, so you can find the board in your hand. At worst an LED flickers.

## Backup and restore

The controller keeps everything in one data directory (`ESPDNS_DATA` in `.env`, `./data` by
default): `settings.json`, the node configs, the hosted zones, the blocklists, the pins, the
action log, the login, the release key and the zone primary's token. The nodes do not need
it to answer DNS. But without it you must import the secrets again and rewrite every config
and zone.

Back up before a risky change (a firmware update, an adoption, a config that moves a node)
and after one that went well.

### What a backup is

A backup is one file, encrypted with [age](https://age-encryption.org). It is encrypted to
a passphrase of at least 12 characters, or to one or more age public keys. It holds the
release key and the zone primary's token, encrypted. Keep the passphrase apart from the
file.

Left out: the fleet lock, temporary files, and `firmware/` (the chip images are large and
you can import them again). The file is checked as a whole: a wrong passphrase, a changed
byte or a file cut short is refused.

A backup holds the fleet lock while it reads, so no change writes files meanwhile.

### Backup

**From the web page.** Open **System**, then **Backup**. Type a passphrase and download the
file. The page asks for your password again first.

**From the command line,** with the passphrase from an environment variable or the first
line of a file. The backup goes to standard output:

```sh
printenv ESPDNS_BACKUP_PASSPHRASE | docker compose run --rm -T --entrypoint /espdns \
  espdns-controller backup -data /data -out - > espdns-backup-2026-10-07.age

docker compose run --rm -T --entrypoint /espdns espdns-controller \
  backup -data /data -out - < passphrase.txt > espdns-backup-2026-10-07.age
```

To encrypt to an age public key instead of a passphrase, add `-recipient age1...` (repeat
it for several keys). Add `-firmware` to include `firmware/`. If a change holds the fleet
lock, the backup waits for it, up to 10 minutes (`-wait`).

### Check a backup

A dry run of a restore checks everything and writes nothing. It asks for the passphrase:

```sh
docker compose run --rm -v "$PWD/espdns-backup-2026-10-07.age:/backup.age:ro" \
  --entrypoint /espdns espdns-controller restore -data /data -in /backup.age -dry-run
```

It lists every file in the backup and checks the passphrase, every path, size and sum,
the settings, the key, the token and the login.

### Restore

A restore goes into an empty data directory, with the controller stopped. On a new host,
set up the controller as for a first install ([Getting started, step
5](getting-started.md#5-start-the-controller): `.env` and an empty data directory), from a
checkout with the same public keys in `firmware/keys/`.

1. Stop the controller:

   ```sh
   docker compose down
   ```

2. Check the backup with the dry run above.
3. Restore it. The passphrase is asked once:

   ```sh
   docker compose run --rm -v "$PWD/espdns-backup-2026-10-07.age:/backup.age:ro" \
     --entrypoint /espdns espdns-controller restore -data /data -in /backup.age
   ```

   With no terminal, add `-T` and give the passphrase as the first line of standard input
   (`< passphrase.txt`). For a backup made with `-recipient`, give the age identity file
   with `-identity` (mount it into the container as you mount the backup).

   If the data directory is not empty, the restore refuses. Add `-force` to move what is
   there into `.before-restore-<time>/` first. Nothing is deleted. Nothing is put in place
   until every check has passed.

4. Start the controller and log in with the restored login:

   ```sh
   docker compose up -d
   ```

5. If the backup had no firmware, load the chip images again
   ([Get the firmware into the controller](#get-the-firmware-into-the-controller)).

## Recovering from the nodes

With no backup, the nodes still run, and a new data directory can manage them again.
`espdns recover` rebuilds what it can from the nodes. It only reads them.

1. Set up a new controller with an empty data directory, as for a first install
   ([Getting started, step 5](getting-started.md#5-start-the-controller)). Build it from a
   checkout with the public keys your nodes trust in `firmware/keys/`.
2. Import the release key the nodes trust. It is read from standard input:

   ```sh
   docker compose run --rm -T --entrypoint /espdns espdns-controller \
     key import -data /data -key - -pub /keys/release.pub -recovery-pub /keys/recovery.pub \
     < "$HOME/espdns-keys/release.pem"
   ```

3. Set the login. You are asked for a user name and the password twice:

   ```sh
   docker compose run --rm --entrypoint /espdns espdns-controller passwd -data /data
   ```

4. See what the nodes give back, writing nothing:

   ```sh
   docker compose run --rm --entrypoint /espdns espdns-controller recover -data /data -dry-run
   ```

   It finds nodes over mDNS and in `settings.json`. Add `-host 192.0.2.53,192.0.2.54` for
   nodes mDNS can't reach. Anything on the network can answer mDNS as a node, so read the
   list before you go on. `-mdns 0 -host ...` reads only the addresses you give.

5. Run it for real, without `-dry-run`.

It then:

- writes `settings.json`, if there is none, with the nodes in service that trust your key
  (`-add-to-settings` adds them to a `settings.json` that is already there);
- pins each of those nodes to its address;
- keeps each node's `/status` and a report in `recovered/<time>/`;
- says for each node which config file here matches it, and whether the zone files here
  are the same as the hosted zones it serves.

What the nodes can't give back, because the firmware has no way to send it:

- the contents of the node configs, the hosted zones' files and the blocklists;
- the DNS peers, the zone primary and the canary in `settings.json`;
- the history and the push records.

Add the DNS peers, the zone primary and the canary to `settings.json` yourself. Write the
missing configs and zones again. Compare each config with what its node runs before you push
it. Write every hosted zone before you push zones: a zones push replaces a node's whole set,
so a zone left out stops being served.

The seqs need nothing: a new release's seq is the current time in milliseconds, which is
above the node's last one as long as the controller's clock is right.

## Releases

A release is one version of the firmware and the controller together, signed with a
release key. [Releasing](releasing.md) explains what a release holds, how to check
one with `espdns release verify`, and how to use it: the controller's image, the chip images
for updates, and factory images for new nodes.
