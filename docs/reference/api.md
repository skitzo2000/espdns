# Controller HTTP API

The controller serves its dashboard and a JSON API on `http://127.0.0.1:8480` (set by
`ESPDNS_LISTEN`, loopback only). The dashboard's pages use this API. You can use it too, from
the same machine.

This page lists every route the controller registers in this version (0.0.x, alpha). The API
may change in any 0.0.x release. There is no versioned path.

Back to the [reference index](README.md).

## Before you call it

### Where requests may come from

- The controller listens on a loopback address only. It refuses to start on any other.
- Every request under `/api/` and `/build/` must have a `Host` of `localhost` or a loopback
  address, with any port. Others get `403`. This stops DNS rebinding.
- A request that changes something must not come from another site: an `Origin` header, if
  present, must match the `Host`, and `Sec-Fetch-Site: cross-site` is refused (`403`).
- The controller never answers CORS. A page on another site can't call it.

### Logging in

A session has two halves. Send both on every request under `/api/`, and on every request that
is not a GET or HEAD:

1. **A cookie** named `espdns_session_<port>` (for example `espdns_session_8480`). It is
   `HttpOnly` and `SameSite=Strict`. `POST /api/login` sets it.
2. **A header** `X-Session-Token: <token>`, with the `token` from the login reply.

To log in:

```http
POST /api/login HTTP/1.1
Host: 127.0.0.1:8480
Content-Type: application/json

{"user": "admin", "password": "your-password"}
```

The reply sets the cookie and returns:

```json
{"user": "admin", "token": "…", "device": "…", "expires": "…"}
```

A session ends after 2 hours idle, or 12 hours after login. Failed logins back off per client
(`429` with `Retry-After`). Send the `device` value back in `X-Login-Device` on later logins
to be counted as the same client.

### Access levels

Each route below has one of these levels:

| Level | Meaning |
|-------|---------|
| **public** | No session needed. |
| **open** | A GET that anyone on this machine may call while no password is set. Once a password is set, it needs a session. |
| **login** | Always needs a session. While no password is set, it answers `403` ("read-only"). |
| **login + password** | Needs a session and a fresh password grant (see below). |

Any request that is not a GET or HEAD needs a session. While no password is set, such a
request gets `403` ("read-only"). Set the first password with
[`POST /api/setup/password`](#login-and-session) or [`espdns passwd`](cli.md#passwd).

Without a session, once a password is set, an API request gets `401`. A page request is
redirected to `/login.html`.

### Password grants

Two things need your password again: downloading a backup, and showing a config's Wi-Fi
password. Call `POST /api/reauth` with `{"password": "…"}`. The reply has a grant:

```json
{"reauth": "…", "expires": "…"}
```

Send it once, in `X-Reauth: <grant>`, with the request that needs it. A grant lasts 2 minutes
and is used up by one request. Without one, the request gets `403` with `{"reauth": true}`.

### Bodies and replies

- Request bodies are JSON. Send `Content-Type: application/json`. Routes that need a login,
  the login routes and the job routes refuse a POST without it (`403`). The board builder's
  three POSTs (`/api/boards/check`, `/api/boards`, `/api/build`) don't check the header.
- Most bodies refuse unknown fields (`400`).
- Replies are JSON with `Cache-Control: no-store`, unless noted.
- An error reply is `{"error": "…"}`. Some also name the form field: `{"error": "…", "field": "…"}`.
- Files you edit (configs, zones, blocking sources, list definitions, settings) carry a
  version: a `hash` (or `version`). Send back the version you read. If the file changed since,
  the save gets `409` and changes nothing. Use `""` for a new file.

## Routes

### Login and session

| Method | Path | Level | Body | Reply |
|--------|------|-------|------|-------|
| GET | `/api/session` | public | — | `password_set`, `logged_in`, `user`, `expires`, `version` (the controller's), `error`. |
| POST | `/api/login` | public | `{"user", "password"}` | Sets the cookie. `{"user", "token", "device", "expires"}`. `401` wrong login, `429` backing off. |
| POST | `/api/logout` | public* | — | Ends the session, clears the cookie. `{"logged_in": false}`. |
| POST | `/api/reauth` | login | `{"password"}` | `{"reauth": "<grant>", "expires"}`. `403` wrong password. Too many wrong passwords end the session (`401`). |
| POST | `/api/setup/password` | public | `{"user", "password"}` (`user` `""`: `admin`) | Sets the first password, then logs in as `/api/login` does. Only while no password is set (`409` after). Only from a loopback client address (`403` otherwise). Password: at least 12 characters. |

\* `/api/logout` is a POST, so in practice it needs the session it ends.

### Nodes

| Method | Path | Level | Body / query | Reply |
|--------|------|-------|--------------|-------|
| GET | `/api/nodes` | open | — | Every node the controller knows: `id` (chip MAC), `addr`, `hostname`, `mac`, `source` (`settings`, `mdns` or `lookup`), `online`, `last_seen`, `polled`, `error`, `qps`, and `status` (the node's last [`/status`](node-endpoints.md#status), kept while it is offline). |
| GET | `/api/nodes/found` | login | — | `{"nodes": [...]}`: nodes found over mDNS or looked up that are not in `settings.json`, each with what adds it in `next`: `adopt`, `settings-add`, or `""` (its `refusals` say why). |
| POST | `/api/nodes/lookup` | login | `{"address": "192.0.2.10"}` | Reads `/status` at that IPv4 address only. `{"address", "listed", "found", "answered", "error", "node"}`. A node found is listed from then on, as an mDNS one is. |
| GET | `/api/nodes/{id}/settings` | login | `{id}`: the node ID | The node page's form: each field's value, where it comes from, and whether a change applies live or at a restart; the config file's `version`; its pending changes. Never the Wi-Fi password. |
| POST | `/api/nodes/{id}/settings` | login | `{"settings": {...}, "version"}` | Checks the edit and adds it as a pending change of the node's config file. Returns the form again. `settings` takes `name`, `network`, `forwarders`, `tz`, `blocking` (bool), `querylog` (`{"enabled", "client"}`), and `reset` (fields to put back to the lower layer). Only for a node in `settings.json`. |

### Fleet state

| Method | Path | Level | Body / query | Reply |
|--------|------|-------|--------------|-------|
| GET | `/api/key` | open | — | The release key: `source`, `present`, and `fingerprint`, or `error` and `missing`. Never the key. |
| GET | `/api/lock` | open | — | `{"held": false}`, or `{"held": true, "holder", "text"}`: who holds the fleet lock. |
| GET | `/api/actions` | open | `?n=` (default 100) | The action log's newest `n` entries, newest first. |
| GET | `/api/dashboard` | open | — | The dashboard: `now`, `window_s`, `bin_s`, `bins`, `fleet` (rates and time series: queries a second, blocked, p95 latency, upstream p95 and failures, cache hit rate, SERVFAIL) and `nodes`. Built from each node's `/metrics`, in memory only. |
| GET | `/api/querylog` | login | `?node=&client=&name=&result=&qtype=&after=&run=&limit=` | The query log the controller holds in memory, newest first: `entries`, `run`, `last`, `matched`, `held`, `cap`, `oldest`, `newest`, `nodes`. `limit` default 200, at most 1000. To follow, send the last reply's `last` as `after` and its `run` as `run`. |
| GET | `/api/querylog/top` | login | `?node=` | The names asked most, in what the controller holds. |
| GET | `/api/search` | login | `?q=` | Nodes, zones, records, devices, sites, rules, lists and pending changes that match. Reads only what the controller holds. Takes at most 2 seconds. |

### Setup and settings

| Method | Path | Level | Body | Reply |
|--------|------|-------|------|-------|
| GET | `/api/setup` | open | — | What is set up: the password, `settings.json`, the release key, the zone primary and its token, the nodes. `first_run` while there is neither a password nor `settings.json`. The first run's steps. |
| GET | `/api/settings` | open | — | `settings.json` as the form edits it (every field, empty ones too), its `version`, the zone primary kinds, and whether the token is set. Never the token. |
| POST | `/api/settings` | login | `{"settings": {...}, "version", "primary_token", "remove_primary_token"}` | Replaces `settings.json` whole if it is still `version` (`""` while there is no file; `409` otherwise). Writes or removes the zone primary's token with it. Returns the form again. A refused field: `{"error", "field"}`. See [settings.md](settings.md#settingsjson). |

### Node configs

Node configs are files in `<data>/configs`. See [node-config.md](node-config.md).

| Method | Path | Level | Body / query | Reply |
|--------|------|-------|--------------|-------|
| GET | `/api/configs` | login | — | `{"dir", "configs", "nodes"}`: every config and the nodes that run each. |
| GET | `/api/configs/{name}` | login | `?reveal=1` (needs a [password grant](#password-grants)) | The config's text and history. The Wi-Fi password is hidden unless revealed. |
| POST | `/api/configs/{name}/check` | login | `{"text", "board", "node"}` | The checks, as the node runs them. Never saved. |
| POST | `/api/configs/{name}` | login | `{"text", "hash"}` | Saves the file (`hash`: the version edited; `""` for a new file). `409` if it changed. Where the text still has the hidden password marker, the saved password is kept. |

### Hosted zones

Hosted zones are RFC 1035 master files in `<data>/zones/<zone>.zone`.

| Method | Path | Level | Body / query | Reply |
|--------|------|-------|--------------|-------|
| GET | `/api/zones` | login | — | Every zone file, the nodes serving each, the nodes, the deleted ones. |
| GET | `/api/zones/{name}` | login | `?version=<file>` | The zone's text, hash and history; with `version`, a kept version's text. |
| GET | `/api/zones/{name}/new` | login | — | A new zone's text from the template: SOA, and NS for the nodes in `settings.json`. |
| POST | `/api/zones/{name}/check` | login | `{"text"}` | The zone checks, then the checks against each node. |
| POST | `/api/zones/{name}/serial` | login | `{"text"}` | `{"text", "serial", "was"}`: the text with the SOA serial raised above the saved file's and the nodes'. |
| POST | `/api/zones/{name}` | login | `{"text", "hash"}` | Saves the file. `409` if it changed. |
| POST | `/api/zones/{name}/delete` | login | `{"hash"}` | Deletes it. The file is kept in the history. |
| GET | `/api/zone-inventory` | login | — | Every zone the fleet answers for (hosted, secondary, forward), its source and the fleet's state, and the zone primary. |
| GET | `/api/zone-lookup` | login | `?name=<zone>` | Where a zone lives: the fleet's already, a configured primary's, or none. Sends each configured primary one SOA query. |

### Blocking

| Method | Path | Level | Body / query | Reply |
|--------|------|-------|--------------|-------|
| GET | `/api/blocking` | open (part) | — | The list definitions, source files, compiled files, the nodes' blocking, each list's last compile job and its CLI command. Without a session (no password set), only the nodes' blocking and the compiled files. |
| GET | `/api/blocking/defs` | login | `?version=<file>` | A kept version of the list definitions. |
| POST | `/api/blocking/defs` | login | `{"lists": [...], "hash"}` | Saves the list definitions (`blocking/lists.json`). `409` if changed. |
| GET | `/api/blocking/sources/{name}` | login | `?version=` | One source file: its text (the start of a big one), hash and history. |
| POST | `/api/blocking/sources/{name}` | login | `{"text", "hash"}` | Saves it (`""` hash: a new file). At most 32 MiB. |
| POST | `/api/blocking/sources/{name}/delete` | login | `{"hash"}` | Deletes it, kept in the history. Refused for a file a list reads. |

A compile is a job: kind [`blocklist`](#job-kinds). Nothing here pushes a list.

### Pending changes and updates

Edits wait here as pending changes until one [`apply`](#job-kinds) job sends them all.

| Method | Path | Level | Body / query | Reply |
|--------|------|-------|--------------|-------|
| GET | `/api/changes` | login | — | `{"changes", "restarts", "apply"}`: the pending changes, oldest first; the nodes that restart; the apply running or the last one. |
| POST | `/api/changes` | login | A file change: `{"kind", "name", "text" or "delete": true, "hash", "summary"}`. A firmware update: `{"kind": "firmware", "firmware", "nodes", "summary"}` | `201` with the change. `kind`: `config`, `zone`, `source`, `lists` or `firmware`. A firmware update goes only to nodes in `settings.json`. |
| GET | `/api/changes/file` | login | `?kind=&name=` | A file as the pending changes make it: what an edit starts from. |
| POST | `/api/changes/{id}/discard` | login | — | Discards it, and the changes of its file stacked on it. |
| POST | `/api/changes/discard` | login | — | Discards every pending change but the put-back ones. |
| GET | `/api/updates` | open | — | Each node's firmware against the newest build for it, and the builds. |
| POST | `/api/updates` | login | `{"nodes": [...], "builds": {"<host>": "<build>"}}` | `201` `{"changes": [...]}`: the updates, added as pending firmware changes. No `nodes`: every node offered one. A newer build than the one named: `409`. Nothing is pushed until an apply. |

### Rolling push

| Method | Path | Level | Body | Reply |
|--------|------|-------|------|-------|
| GET | `/api/push/sources` | login | — | What there is to push, the nodes, the defaults. |
| POST | `/api/push/preview` | login | A [rollout request](#rollout-request) | What each node would get, from its `/status`. Read only, no job. |

The push itself is a job: kind [`rollout`](#job-kinds).

### Adoption

| Method | Path | Level | Body | Reply |
|--------|------|-------|------|-------|
| GET | `/api/adopt` | login | — | The nodes found (unadopted ones to adopt; adopted ones not in `settings.json`), the configs, the zone primary. |
| POST | `/api/adopt/preview` | login | An [adoption request](#adoption-request) | The address it would get, the config checked for the node, the zones. Read only, no job. |
| GET | `/api/primary/certificate` | login | — | The certificate the zone primary in `settings.json` presents now (read in a TLS handshake; no token is sent), its fingerprint, whether the system's roots trust it, and the pin. |
| POST | `/api/primary/certificate` | login | `{"sha256"}` | Pins the certificate with that fingerprint, if the primary still presents it (`409` if not). |
| DELETE | `/api/primary/certificate` | login | — | Removes the pin. |
| GET | `/api/primary` | login | — | Each secondary zone's transfer and NOTIFY lists at the primary (or, for a primary changed by hand, what each node needs), and whether every node in `settings.json` is in them. |

Adoption itself is a job: kinds [`adopt`, `primary` and `settings-add`](#job-kinds).

### Boards and flashing

| Method | Path | Level | Body | Reply |
|--------|------|-------|------|-------|
| GET | `/api/boards` | open | — | The board catalog and your own boards, each with `image_ready` (its chip image is imported). |
| POST | `/api/boards/check` | session | A board definition | `{"errors": [...], "warnings": [...]}`. |
| POST | `/api/boards` | session | A board definition | Saves it to `<data>/boards`. `201` with the board. |
| GET | `/api/images` | open | — | `{"images", "known"}`: the imported chip images and the image names boards may use. |
| POST | `/api/build` | session | `{"name": "<catalog board>"}` or `{"board": {...}}`, with `"network": {"address": "192.0.2.52/24", "gateway": "192.0.2.1"}` or `{"address": "dhcp"}` | Builds a flash image for the board with that address. `{"id", "board", "chip"}`. `422` if it can't be built (no network, chip image not imported). |
| GET | `/build/{id}/manifest.json` | open | — | The ESP Web Tools manifest for that build. |
| GET | `/build/{id}/image.bin` | open | — | The flash image (`application/octet-stream`). |

The two `/build/` routes need only the session cookie, not the `X-Session-Token` header. "session" means any session, as every POST needs. These three POSTs have no further check.
The controller keeps the last 32 builds or so in memory. Flashing from the browser (Web Serial)
works because the dashboard is on localhost.

### Backup

| Method | Path | Level | Body | Reply |
|--------|------|-------|------|-------|
| GET | `/api/backup` | login | — | What a backup would hold: `data_dir`, `parts` (each top-level entry, its size, and whether it is included), `format`, `min_passphrase` (12), and `lock` if the fleet lock is held. |
| POST | `/api/backup` | login + password | `{"passphrase"}` or `{"recipient": "age1…"}`, and `"firmware": true` to include `firmware/` | The encrypted backup as a download (`application/octet-stream`). `409` if the fleet lock is held (it doesn't wait). |

Restore is not in the API. Use [`espdns restore`](cli.md#restore) with the controller stopped.

### Jobs

Anything that changes nodes, and a few other long tasks, run as jobs: one at a time, under the
fleet lock, in the action log with the logged-in user, their progress live.

| Method | Path | Level | Body / query | Reply |
|--------|------|-------|--------------|-------|
| POST | `/api/jobs` | session | `{"kind": "<kind>", "params": {...}}` | `202` with the job, and `Location: /api/jobs/<id>`. `400` if the params are refused (the job is not queued). `429` if 8 jobs are already waiting. |
| GET | `/api/jobs` | open | — | Every job kept, newest first, without logs. |
| GET | `/api/jobs/{id}` | open | — | One job with its progress log. `404` if unknown. |
| POST | `/api/jobs/{id}/stop` | session | — | Asks the job to stop at its next safe point. `202` with the job. `409` if it already ended. |
| GET | `/api/jobs/{id}/events` | open | `?after=<line>` or `Last-Event-ID` | Server-Sent Events (below). |

A job: `id`, `kind`, `who`, `args`, `state` (`queued`, `running`, `done`, `failed`,
`stopped`), `stopping`, `created`, `started`, `ended`, `error`, `result`, `progress` (one job
only), `lines`, `last`, and `log` (one job only).

Events on `/api/jobs/{id}/events`:

| Event | Data |
|-------|------|
| `state` | The job without its log. First, and at every change of state. |
| `log` | One progress line. The event ID is the line number, so a reconnect resumes after it. |
| `progress` | The job's progress, when it changes. |
| `end` | The job, once it ended and every line was sent. The stream then closes. |

A comment every 15 seconds keeps the connection open.

### Static files

| Method | Path | Level | Reply |
|--------|------|-------|-------|
| GET | `/` and other paths | page | The dashboard's pages. `/login.html`, `/style.css`, `/common.js` and every other `.js` and `.css` file are public. Other pages need a session once a password is set (else a redirect to `/login.html`). |

## Job kinds

Start each with `POST /api/jobs` and `{"kind": "...", "params": {...}}`. Params refuse unknown
fields.

### Node actions

Each needs the release key in the data directory. The node must be one the controller knows.

| Kind | Params | What it does | Which nodes |
|------|--------|--------------|-------------|
| `identify` | `{"node": "<address>", "seconds": 30}` | Flickers the LED. `seconds`: 1 to 3600, default 30. | Any node the controller knows (mDNS or `settings.json`). |
| `pause` | `{"node", "seconds": 300}` | Turns blocking off for that long. At most a week (604800). `0` resumes. Default 300. | Nodes in `settings.json`. |
| `flush` | `{"node"}` | Drops the node's cached answers. | Nodes in `settings.json`. |
| `revert` | `{"node", "list": "blocklist"}` | Goes back to the older copy the node keeps: `blocklist`, `overrides` or `zones`. | Nodes in `settings.json`. |
| `reboot-pending` | `{"node"}` | A coordinated reboot of a node a release left waiting for one. | Nodes in `settings.json`. |

### Fleet jobs

| Kind | Params | What it does |
|------|--------|--------------|
| `check` | none (`{}` or omitted) | Reads every node (in `settings.json` or found over mDNS) and asks it the DNS checks a rollout asks; then asks each DNS peer. Changes nothing. Result: `{"nodes", "dns_peers", "ok"}`. |
| `blocklist` | `{"list": "<name>", "accept_change": false}` | Compiles one list from its definition into `lists/<name>.bin`. `accept_change` takes a size change over the limit once. |
| `config-push` | `{"node", "config", "dry_run": true}`, then `{"node", "config", "after": "<dry run job ID>"}` | Sends one config file to one node in `settings.json`. The push must name a dry run of the same node and file that passed in the last 15 minutes, with the file unchanged. |
| `rollout` | A [rollout request](#rollout-request) with `"dry_run": true`, then the same with `"after": "<dry run job ID>"` | The rolling push, one node at a time. The push must name a passing dry run of the same request with the same file contents, from the last 15 minutes. Each dry run serves one push. |
| `apply` | `{"canary": "<node>", "soak_s": 60, "accept_change": ["<list>"]}`, all optional | Sends every pending change as one safe rolling change (below). |

### Adoption jobs

| Kind | Params | What it does |
|------|--------|--------------|
| `adopt` | An [adoption request](#adoption-request) with `"dry_run": true`, then the same with `"after": "<dry run job ID>"` | Adopts a node. The adoption must follow a passing dry run of the same request and files, from the last 15 minutes. One adoption per dry run. |
| `primary` | `{"zone", "address", "action": "allow"}` or `"remove"` | Adds a node in `settings.json` to one zone's transfer and NOTIFY lists at the primary, or takes an address that is no node off them. Only for a primary the controller drives over its API. |
| `settings-add` | `{"node": "<address>"}` | Adds a node the controller found, already adopted, to `settings.json`. |

### Rollout request

The body of `POST /api/push/preview` and the params of a `rollout` job:

| Field | Meaning |
|-------|---------|
| `kind` | `firmware`, `config`, `blocklist`, `overrides` or `zones`. |
| `nodes` | The nodes to change, from `settings.json`, in order after the canary. Required. |
| `canary` | One of `nodes`. Empty: `settings.json`'s `canary` if it is one of them, else the first. |
| `soak_s` | How long each node is watched before the next. `0`: the default (60). Never less than the default; at most 3600. |
| `firmware` | `firmware`: `builds/<board>` or `images/<image>`, one per chip image. |
| `configs` | `config`: `{"<node>": "<file in configs/>"}`, one for each node. |
| `file` | `blocklist` or `overrides`: a file in `lists/`. |
| `zones` | `zones`: files in `zones/`. |
| `check_blocked` | Names the blocklist must block after the change. |
| `must_resolve` | A file in `lists/` of names that must resolve. |
| `dry_run` | `true` for the dry run. |
| `after` | The push: the dry run's job ID. |

The page's push keeps every safety rule of the CLI: no force, no single-node override, no
skipped DNS checks, no reinstall, `settings.json`'s nodes only.

### Adoption request

The body of `POST /api/adopt/preview` and the params of an `adopt` job:

| Field | Meaning |
|-------|---------|
| `node` | The node's address now. Required. |
| `node_id` | Its ID as shown (its MAC, `aa:bb:cc:dd:ee:ff`). Required. |
| `config` | A file in `configs/`. Required. |
| `address` | `""` (the config's, else the one it runs on), `a.b.c.d/nn`, or `"dhcp"` (never on a network in `no_dhcp`). |
| `gateway` | With a static address. |
| `reserved` | With `dhcp`: the address is reserved for the node in your DHCP server. |
| `primary_done` | The primary is changed by hand, and the changes the dry run named were made. |
| `add_to_settings` | Once adopted, add its address to `settings.json`. |
| `dry_run` | `true` for the dry run. |
| `after` | The adoption: the dry run's job ID. |

Only a node that says it isn't adopted, under an ID no other known node has, can be adopted.

### The apply

An `apply` job sends every pending change in five steps:

1. **check**: the changes against the files and each other; every node in `settings.json` read.
2. **write**: the files written (each replaced version kept in its history).
3. **compile**: the blocklists the changes touch compiled again.
4. **dry run**: every rollout checked against every node it goes to, before any node is touched.
5. **push**: the rollouts one after another (configs, hosted zones, overrides, blocklists,
   firmware), each one node at a time, canary first.

Params, all optional: `canary` (one of `settings.json`'s nodes; default its `canary`),
`soak_s` (60 to 3600), `accept_change` (lists whose size change is taken this once).

If a blocklist's size changed more than allowed, the apply ends `stopped` with `questions` in
its result, and pushes nothing. Apply again with the params a question names to take the
change.

If an apply stops part way, the changes stay pending, marked written once their files are.
Applying again finishes them; discarding puts the files back.
