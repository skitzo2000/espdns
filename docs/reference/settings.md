# Controller settings

The controller reads three kinds of settings:

1. [`settings.json`](#settingsjson) in the data directory: the deployment's nodes, DNS peers
   and zone primary. The controller and the `espdns` CLI both read it.
2. [The controller's flags](#controller-flags), set in `compose.yaml`.
3. [`.env`](#env-variables) next to `compose.yaml`, which Docker Compose reads.

Back to the [reference index](README.md).

## settings.json

Path: `<data>/settings.json` (`/data/settings.json` in the container). You can edit it on the
dashboard's Settings page, which writes it whole. You can also edit the file by hand.

Rules for the whole file:

- Every field is optional. A missing file means "no settings" (all fields empty).
- Unknown fields are refused. A misspelt field is an error, never a silent default.
- The file must hold exactly one JSON object.
- The controller reads it again every 10 seconds. A change applies without a restart. A file
  that no longer parses leaves the node list as it was.
- The file is written with mode `0600`.

### Example

```json
{
  "nodes": ["192.0.2.53", "192.0.2.54"],
  "dns_peers": ["192.0.2.1"],
  "dns_peer_zones": ["home.arpa"],
  "canary": "192.0.2.53",
  "no_dhcp": ["192.0.2.0/24"],
  "primary": { "kind": "manual" }
}
```

### Fields

| Field | Type | Meaning | Checks |
|-------|------|---------|--------|
| `nodes` | list of strings | The nodes in service. The controller polls each one, even if mDNS doesn't find it. The Push page, an apply and the node actions (all but identify) change only these nodes. The CLI counts them as peers for the last-healthy-node rule. Each entry is `host` or `host:port` (for an HTTP port other than 80). | Not empty, no spaces, tabs or `/`, no leading or trailing space. No duplicates. A `host:port` must have a port. |
| `dns_peers` | list of strings | Other resolvers your clients use besides the nodes (for example the zone primary). Each counts as one answering peer while it resolves a forwarded name and answers its zones' SOA authoritatively. Entry is `host` or `host:port` (for a DNS port other than 53). | Same as `nodes`. |
| `dns_peer_zones` | list of strings | The zones the DNS peers must answer for. Empty: the secondary zones of the node about to change. | Not empty, no spaces, tabs or `/`. No duplicates. |
| `canary` | string | The node the Push page and an apply change first, unless you choose another. Empty: the first node changed. | Must be one of `nodes`. |
| `no_dhcp` | list of strings | IPv4 networks with no DHCP server, each as its network address with prefix length (`192.0.2.0/24`). A node on one of these is never given a DHCP config by adoption. Empty: none. | Must parse as an IPv4 prefix. Must be the network address itself (`192.0.2.0/24`, not `192.0.2.5/24`). No duplicates. |
| `primary` | object | The zone primary. See [primary](#primary). Absent: none set up, treated as `manual`. | See below. |
| `internal_sources` | list of strings | The internal allowlist: hosts (a name or an IP address, no scheme or port) a blocklist URL source may be fetched from over plain http or at an inside (private, loopback, link-local) address. Such a fetch goes to that host only. Empty: URL sources are https from public addresses only. See [Blocking](../blocking.md#lists-hosted-inside-your-network). | Each must be a host name or an IP address. |

A host given by name in `nodes` must be a name the node answers to: the `name` in its node
config, or its `.local` mDNS name. A node refuses any other `Host` (HTTP 421). An IP address
always works.

### primary

```json
{ "kind": "manual" }
```

```json
{ "kind": "technitium", "url": "https://192.0.2.1:53443", "cert_sha256": "<fingerprint>" }
```

| Field | Meaning | Checks |
|-------|---------|--------|
| `kind` | `manual` or `technitium`. These are the only two kinds in this version. | Required. Must be a known kind. |
| `url` | The primary's API address. Only for a kind driven over an API (`technitium`). | Required for `technitium`. Refused for `manual`. For `technitium`: `https://`, a host, no user, no path, no query, no fragment. A plain `http://` address already in the file still loads, but the primary is **paused**: nothing is sent to it and the token never is. Saving one is refused. |
| `cert_sha256` | The SHA-256 fingerprint of the primary's certificate, pinned when it is self-signed. Set it by confirming the certificate (the dashboard's Zone primary section, or [`espdns primary cert` and `primary pin`](cli.md#primary)), not by hand. | Optional. With a pin, only that certificate is accepted. Without one, only a certificate the system's roots trust. |

What each kind does:

- **`manual`** works with any standards-compliant primary: BIND, Knot, PowerDNS, Windows
  DNS, Technitium or another. The controller does not read or change the primary. When a
  node needs to be on a zone's transfer and NOTIFY lists, adoption tells you the exact change
  to make by hand. You then confirm it was made.
- **`technitium`** drives Technitium DNS Server's HTTP API. Adoption adds the node to each
  zone's transfer and NOTIFY lists itself. It needs an API token. Store the token with
  `espdns primary import` (see [cli.md](cli.md#primary)), or on the Settings page. The token
  is kept in `<data>/keys/primary.token`, mode `0600`, and never appears in a reply or a log.
  Without a URL or a token, the controller falls back to describing the change by hand.

## Controller flags

The controller binary (`/espdns-controller` in the image) takes these flags. The image's
entrypoint already sets `-data /data -catalog /catalog`. `compose.yaml` sets `-listen` from
`ESPDNS_LISTEN`.

| Flag | Default | Meaning |
|------|---------|---------|
| `-listen` | `127.0.0.1:8480` | Address for the dashboard and API. Must be a loopback address (`127.0.0.1`, `[::1]` or `localhost`) with any port. The controller refuses to start on any other address. |
| `-data` | `data` (image: `/data`) | The data directory. |
| `-catalog` | `../boards` (image: `/catalog`) | The shipped board catalog. |
| `-browse-mdns` | `true` | Browse mDNS for nodes besides `settings.json`'s. `false`: poll only the listed nodes. |
| `-check-mdns` | `3s` | How long a `check` job browses mDNS for extra nodes. `0`: don't. |
| `-healthcheck` | `false` | Only check that a controller answers on `-listen`, then exit 0 (yes) or 1 (no). The container's health check uses it. |

## .env variables

`compose.yaml` reads `.env` from the `controller/` directory. Copy `.env.example` to `.env`
and edit it.

| Variable | Default | Meaning |
|----------|---------|---------|
| `ESPDNS_UID` | none (required) | The user ID the controller runs as. Use the owner of the data directory (`id -u`). Compose refuses to start without it. |
| `ESPDNS_GID` | none (required) | The group ID (`id -g`). Required. |
| `ESPDNS_LISTEN` | `127.0.0.1:8480` | The dashboard's address. Loopback only. |
| `ESPDNS_DATA` | `./data` | The data directory on the host, mounted at `/data`. It must exist and be owned by `ESPDNS_UID`. Compose never creates it. |
| `ESPDNS_MEM_LIMIT` | `2g` | The container's memory limit. Compiling a blocklist needs about 220 bytes per domain at its peak. |
| `ESPDNS_GOMEMLIMIT` | `1800MiB` | The Go runtime's soft memory limit. Keep it about nine tenths of `ESPDNS_MEM_LIMIT`. |
| `ESPDNS_PIDS_LIMIT` | `256` | The container's process and thread limit. |
| `ESPDNS_IMAGE` | `espdns-controller` | The image name. |
| `ESPDNS_CONTAINER` | `espdns-controller` | The container name. |

## The data directory

Everything the controller keeps lives here. Directories are mode `0700` and files `0600`,
whatever the umask. At start the controller tightens anything it finds open to group or
others.

| Path | What it is |
|------|------------|
| `settings.json` | [Deployment settings](#settingsjson). |
| `auth.json` | The login: the user name and an argon2id hash of the password. |
| `keys/release.pem` | The release signing key (`espdns key import`). |
| `keys/primary.token` | The zone primary's API token (`espdns primary import`). |
| `configs/<name>.json` | [Node configs](node-config.md). |
| `zones/<zone>.zone` | Hosted zones (RFC 1035 master files). |
| `blocking/lists.json` | The blocklist definitions: what each list is compiled from. |
| `blocking/sources/` | Local list sources, allow lists and overrides. |
| `lists/` | Compiled blocklist and overrides files. |
| `boards/` | Your own board definitions. |
| `firmware/images/<image>/` | Chip images (`espdns release import`). |
| `firmware/builds/<board>/` | Per-board firmware builds for rollouts. |
| `changes/` | Pending changes, waiting for one apply. |
| `fleet.lock` | The fleet lock: one fleet change at a time. |
| `log/actions.jsonl` | The action log: every fleet change and who made it. |
| `log/jobs/<id>.json` | Each job's record and progress. |
