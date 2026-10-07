# Blocking

This guide covers ad and tracker blocking: building blocklists, sending them to the nodes
safely, fixing a wrong block, and reading the query log. For zones and forwarding, see
[zones.md](zones.md). For how it all fits together, see [Architecture](architecture.md#blocking).

espDNS is alpha software (0.0.x). This guide describes what the code does today.

## How it works

- The **controller** downloads and compiles the lists. Nodes never download lists.
- A compiled list is one compact file. Every node gets the same bytes, signed with your
  release key.
- The controller sends a list to one node at a time. The first node is the canary. If a
  node fails its checks, every node that took the list goes back to the copy it had.
- Each node keeps two copies of a list: the one it runs and the one before. You can go back
  to the older copy at any time.
- With the controller off, nodes keep blocking with the last list they were given.

Lists are rebuilt only when you choose to compile them. There is no scheduled refresh yet.

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

The dashboard is at http://127.0.0.1:8480. Open **Blocking** (the **Blocklists** page).
You need to be logged in to change lists or see the query log.

## How a node decides

For each query, a node checks, in order:

1. **Its own zones.** Hosted and secondary zones are never blocked.
2. **The overrides.** Your own short block and allow list. They apply even while blocking
   is paused.
3. **Pause.** If blocking is paused, nothing else is blocked.
4. **The blocklist.** Its block entries, then its allow entries.
5. **Forwarding.** Names that pass go to the forwarders. CNAME targets in a forwarded
   answer are checked against the blocklist too, so a tracker hidden behind a first-party
   name is caught.

A blocked name gets `0.0.0.0` for A, `::` for AAAA, and an empty answer (NODATA) for other
types. Blocked answers are never cached. You can change this in the node config:

```json
"blocking": { "answer": "nxdomain", "ttl": 10 }
```

- `answer`: `"null"` (the default, as above) or `"nxdomain"`.
- `ttl`: the TTL of a blocked answer, 0 to 86400 seconds (default 10).
- `"enabled": false` turns the blocking service off on that node, live.

## Lists

A list is a named definition on the Blocklists page. It compiles into one file,
`lists/<name>.bin` in the data directory.

### Source formats

Every source names its format first, as `kind:` before the file or URL. The controller
never guesses the format.

| Kind | What a line looks like | What it blocks |
|---|---|---|
| `hosts` | `0.0.0.0 ads.example.com` | That exact name |
| `domains` | `ads.example.com` | That exact name |
| `wildcard` | `ads.example.com` | The name and all its subdomains |
| `adblock` | `\|\|ads.example.com^` | The name and all its subdomains. `@@\|\|name^` allows them |
| `rpz` | A Response Policy Zone, as a master file | See below |

An **RPZ** is read like BIND or Technitium publish it. `CNAME .`, `CNAME *.` and
`CNAME rpz-drop.` block a name. `CNAME rpz-passthru.` allows it. `*.name` covers the name
and its subdomains. Things a block or allow list cannot express are skipped and counted:
local data (A, AAAA, TXT records), `rpz-tcp-only.`, and IP, client IP and name server
triggers.

The compiler also:

- drops entries that are a public suffix or a top-level domain (such as `com` or `co.uk`);
- removes duplicates and entries already covered by a parent entry;
- never blocks a name on the **popular names** list by accident (a Tranco CSV with
  `rank,name` lines, or one name per line);
- refuses a build that blocks any name on the **must resolve** list.

### Where a source comes from

A source is either a file or a URL.

**A file** lives in the data directory under `blocking/sources/`. Create and edit these on
the Blocklists page under **Source files** (**New source file**). You can also replace one
from a file on your computer (**Replace from a file**). File names end in `.txt`, `.zone`,
`.rpz`, `.csv`, `.hosts` or `.list`. Each save keeps the previous version. Use files for
your own custom lists and allow lists.

**A URL** is fetched by the controller each time it compiles:

- It must be **https**. Plain http is refused, and so is a redirect from https to http.
- It must be on a **public address**. The controller refuses any address that is loopback,
  private, link-local, shared or reserved. It checks each address as it connects, after
  every redirect, so a name that later points inside your network is refused too.
- A download can be up to 512 MiB.

### Lists hosted inside your network

To fetch a list from a server on your own network, put that server on the **internal
allowlist**. Add its host to `settings.json` in the data directory
(`controller/data/settings.json`):

```json
"internal_sources": ["192.0.2.10", "lists.home.arpa"]
```

- Each entry is a host only: a name or an IP address, with no scheme and no port.
- A source on that host may use plain http and an inside address.
- The fetch goes to that host only. A redirect to another host is refused.
- With no `internal_sources` (the default), every URL source must be https on a public
  address.

The controller reads `settings.json` again every 10 seconds. An unknown field in it is an
error.

### Create a list

1. On the Blocklists page, under **New list**, type a name and click **Create**. The name
   `overrides` is taken.
2. Under **Block (sources)**, add one source per line, such as
   `adblock:https://lists.example.com/pro.txt` or `domains:my-blocks.txt`.
3. Under **Allow (allow lists)**, add sources whose names this list must never block, in
   the same form.
4. Optionally set **Popular names** and **Must resolve** (files in `blocking/sources/`).
5. Optionally set **Max change %** and **Min change (entries)** for the size-change check
   (below). Leave them empty for the defaults.
6. Click **Save**.

The definitions are stored in `blocking/lists.json`. Each save keeps the previous version.

## Compile

Click **Compile**. The controller fetches every source, compiles the list and writes
`lists/<name>.bin`. The job log shows each source as it is read, with its entry counts.
The page also shows the same compile as a command line.

### The size-change check

A compile is compared with the list's previous build. It is **refused**, and nothing is
written, when:

- the blocked or allowed entries change by more than **20%** and by more than **100**
  entries, or
- the file size changes by more than 20% (between builds of the same format).

This stops a source that failed, moved or was cut short from reaching the nodes unnoticed.
The first build of a list has no previous build, so any size is taken.

If the change is meant (you added or dropped a source), click **Accept this change once**.
That one build is taken. The next build is compared with it.

`Max change %` set to 0 refuses any change in size. `Min change` set to 0 removes the
floor.

### Compile from the command line

The same compile, with no node touched and no key needed:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
    blocklist -list adblock:https://lists.example.com/pro.txt \
    -list domains:/data/blocking/sources/my-blocks.txt \
    -allow domains:/data/blocking/sources/allow.txt \
    -must-resolve /data/blocking/sources/must-resolve.txt \
    -out /data/lists/main.bin
```

The directory of `-out` must already exist. The controller creates `data/lists` the first
time it compiles a list from the page.

Add `-internal <host>` (repeat it) for a list server on the internal allowlist.
`-max-change` and `-min-change` set the size-change limits. `-accept-change` takes one
refused build. `-json` prints the result as JSON.

## Roll out a list

After a compile, click **Open in Push**. The **Push** page opens with the kind and the file
chosen.

1. Choose the nodes and the **canary**, the node changed first.
2. Choose the **soak** time: how long each node runs the new list, watched, before the next
   one starts. From one minute to an hour.
3. Optionally add names the list **must block**, and a must-resolve file
   (`lists/must-resolve*.txt` in the data directory).
4. Click **Dry run**. It checks every node and shows where each list goes (memory or SD
   card, swapped live or at the next reboot).
5. Click **Roll out**. It must follow a dry run that passed in the last 15 minutes, with the
   same choices and the same files.

For each node, one at a time:

- the node takes the list and reports it in service;
- the controller sends real DNS queries to that node: a local name, a forwarded name, the
  names it must block, and the must-resolve names;
- the node is watched for the soak time: still in service, still on the new list, no
  reboot, and no jump in failed or dropped queries.

The last node is soaked too. **If any node fails**, every node that took the list goes back
to the copy it had, failed node first. Nodes not yet changed are not touched. If a node
cannot go back (it has no older copy, or does not answer), the page names it and says what
to do next.

From the command line (dry run first, then the same command without `-dry-run`):

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
    rollout -kind blocklist -all -data /data -file /data/lists/main.bin \
    -check-blocked ads.example.com -dry-run -key /data/keys/release.pem
```

`-canary <node>` picks the first node. `-soak 5m` sets the soak time.

## Overrides

The overrides are your own small block and allow list, checked before the blocklist. Use
them to fix a wrong block or add a quick block.

- `overrides.txt`: names to block.
- `overrides-allow.txt`: names to allow, even if a list blocks them.

Both are wildcard lists: an entry covers the name and all its subdomains. Edit them side by
side under **Overrides** on the Blocklists page. Then **Compile**, and push `overrides.bin`
from the Push page with the kind **Overrides**. The rollout works as it does for a list.

Overrides still apply while blocking is paused.

## Pause blocking

Each node's row on the Blocklists page has **Pause**. Choose a time from 5 minutes to 1 day.
Click **Resume** to end it early. A node's reboot also ends a pause. Pausing does not stop
the overrides.

From the command line (`-for` up to `168h`, a week; `-for 0` resumes):

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
    pause -host 192.0.2.53 -for 30m -data /data -key /data/keys/release.pem
```

## Revert

Each node keeps the list before the current one. Click **Revert list** or
**Revert overrides** in a node's row to go back to it. The node switches live. If two
copies do not fit in its memory, it switches at its next reboot instead. The node stays on
the older copy until you push a newer one.

The node refuses a revert when it has nothing older to go back to. The page shows its
reason.

From the command line:

```sh
docker compose run --rm -T --entrypoint /espdns espdns-controller \
    revert -host 192.0.2.53 -kind blocklist -data /data -key /data/keys/release.pem
```

Use `-kind overrides` for the overrides. To go further back than one copy, compile or keep
an older list and push it again.

## What each node runs

The **Nodes** table on the Blocklists page shows each node's list and overrides: sequence
number, entries, memory or SD card tier, whether it reverted, which compiled file it runs,
and whether it is paused.

How big a list a node can hold depends on its board's memory. A list that does not fit is
refused by the node, and the dry run says so.

## The query log

Each node keeps a log of recent queries in its own memory. The size comes from the board.
A board without PSRAM has no query log.

Each entry has the time, the client, the query type and name, the result, the response
code and the time to answer. The result shows which rule decided a block:
`blocked(list)`, `overridden(override)`, `blocked(cname)`, or `forwarded(allow)` for a name
the overrides let through.

### Privacy

The node config sets how much of each client address the log keeps:

```json
"querylog": { "enabled": true, "client": "subnet" }
```

- `"full"` (the default): the whole address.
- `"subnet"`: only the client's /24 network.
- `"hidden"`: no client address at all.

The setting applies as each entry is written, so an address it leaves out is never stored.
Made stricter, it also masks the entries already in the log, on the node and in the
controller. Made looser, nothing comes back. `"enabled": false` turns the log off and frees
its memory. Both changes apply live.

### Read the log

Open **Query log** in the dashboard. Filter by node, client, name, result and type. The page
follows new queries live; **Pause** stops the updates. The query log needs a login, because
it shows who asked for what.

The controller keeps the newest 20,000 entries across all nodes, **in memory only**.
Nothing is written to disk. A controller restart starts the buffer over.

From the command line, read one node's log directly:

```sh
docker compose run --rm --entrypoint /espdns espdns-controller querylog -host 192.0.2.53 -follow
```

Without `-follow` it prints what the node holds and stops. `-json` prints one JSON object per
query. A node serves its query log only to private addresses.

## Charts

The **Traffic** page shows the last hour, for the fleet and for each node:

- queries a second, and how many were blocked;
- cache hit rate;
- answer time (p50 and p95), and forwarder answer time;
- failures a minute.

It also lists the names asked and blocked most (this part needs a login).

The controller reads each node's counters every 10 seconds and keeps one hour in memory.
A controller restart starts the hour over.

Each node also serves its counters at `http://<node>/metrics` in the Prometheus text
format, with no login. You can point your own monitoring at the nodes; this works with the
controller on or off.

```sh
docker compose run --rm --entrypoint /espdns espdns-controller metrics -host 192.0.2.53
```

prints a summary of one node's counters (`-raw` prints them as the node sends them).

## Quick reference

| Task | Where |
|---|---|
| Add a source file or custom list | Blocklists page, **Source files** |
| Define a list | Blocklists page, **New list** |
| Fetch from a list server inside your network | `settings.json`, `"internal_sources"` |
| Build a list | **Compile**; or `blocklist` |
| Take a refused build | **Accept this change once**; or `-accept-change` |
| Send a list to the nodes | **Open in Push**; or `rollout -kind blocklist` |
| Fix one wrong block | **Overrides**, then compile and push `overrides.bin` |
| Pause blocking | **Pause** in the node's row; or `pause` |
| Go back to the previous list | **Revert list**; or `revert -kind blocklist` |
| Hide client addresses in the log | Node config, `"querylog": {"client": "hidden"}` |
