# Changelog

What changed in each version of espDNS, the node firmware and the controller together (they
share one version, the repository's `VERSION`). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): 0.0.x while in alpha, when any
version may change anything. Write each change under Unreleased as it merges;
`scripts/bump-version.sh` makes that section the next version's ([docs/releasing.md](docs/releasing.md)).

## [Unreleased]

### Added

- Releases: pushing a version's tag (`v<VERSION>`, checked against `VERSION` and this file)
  builds its files in CI as a draft release: the controller's image (to the forge's
  container registry), every chip image and each catalog board's factory image (generic: no
  address or site defaults; a factory image starts on DHCP) with its ESP Web Tools
  manifest, and `SHA256SUMS`. CI never has the release key: a person signs `SHA256SUMS`
  with one docker command, the key on standard input, and anyone checks a release, or
  imports its chip images into the controller, with `espdns release verify` and
  `espdns release import` (docs/releasing.md). The controller's image carries the
  firmware's public keys at `/keys`.
- The forward loop's metrics: `/metrics` has the upstream queries in flight per group
  (`fwd_inflight`, `fwd_zone_inflight`) and their peak, the table's size and a group's cap,
  the queries shed at the caps (`fwd_shed_total`), the upstream queries that went
  unanswered (`fwd_expired_total`), each forwarder's timeouts (`upstream_timeouts_total`),
  the TCP retries and the loop's `select()` errors. The Traffic tiles and `espdns metrics`
  show them.
- A health reason, `forwarders slow`: a node whose default forwarders shed queries,
  hold over half their cap for 10 s, or are mostly slower than `upstream_timeout_ms` is
  degraded instead of healthy. The Nodes page explains it.
- Documentation for the public release: a new README, getting started (your own keys and
  firmware, two nodes, one controller), hardware, zones, blocking, operations,
  troubleshooting, architecture, security, and a reference for the CLI, settings, node
  config, the controller's API and a node's endpoints. CONTRIBUTING.md and SECURITY.md.
- `scripts/export-check.sh`: checks the public export (`git archive`, without the files
  `.gitattributes` marks export-ignore) for private addresses and for site names given to it.

### Changed

- Tests, test vectors and examples use documentation addresses only. CI now refuses a
  10/8 address in a test too; a test that needs a private address builds it.

### Security

- The zone primary's API is https only: its token is never sent over plain http, and a
  plain http `"primary"` `"url"` is refused when given (`POST /api/settings`,
  `-primary-url`), saying to switch the primary's API to https. One already in
  `settings.json` doesn't stop the controller: it starts with the primary paused (never
  reached, the token never sent; changed by hand), logs a warning, and shows the reason
  wherever the primary is shown, to be fixed from the GUI.
  Its certificate is always verified, by the system's roots or, for a self-signed one,
  pinned by its SHA-256 fingerprint (`"cert_sha256"`), set only by confirming the
  fingerprint it presents (`espdns primary cert`, then `primary pin`, or
  `GET`, then `POST /api/primary/certificate`); another certificate is then refused until
  it is confirmed.
- Blocklist URL sources are https from public addresses only, each address checked as it
  is connected to (redirects and DNS rebinding included). A list server inside is fetched
  only with its host on the internal allowlist, `settings.json`'s `internal_sources` (the
  CLI's `-internal`), and from that host only.
- mDNS answers are a hint only: loopback, link-local, multicast and broadcast addresses are
  ignored, at most 64 nodes are listed from mDNS alone, and an answer never renames or
  moves a known node.

## [0.0.1] - 2026-10-07

The first numbered version: everything built so far, from the node firmware and the
controller's first pages to the security review's fixes and the backend of the redesigned GUI.

### Added

- Versions: the repository's `VERSION` is the firmware's version (its app descriptor's, so
  `/status`, the image header and the controller say it, no longer `git describe`) and the
  controller's (`espdns version`, `/api/session`, its log). Firmware updates are ordered by
  version, the build time breaking a tie between two builds of one version.
  `scripts/bump-version.sh` moves to the next version.
- The node: a small OS on ESP32-P4 and ESP32-S3 boards (wired Ethernet, Wi-Fi as a fallback,
  microSD): the services its config enables (hosted zones, secondary zones over AXFR,
  forwarding, a cache, blocking, a query log), board definitions as data, a memory plan from
  board data, health states and LEDs, `/status`, `/metrics` and the query log with a cursor.
  It takes only signed releases (ECDSA P-256, bound to the node, board and a sequence number).
- Blocking: lists compiled by the controller (adblock, hosts, domains, wildcard and RPZ
  sources, allow lists, overrides), placed in the node's memory tiers, with a size-change
  check, a list canary, a soak and a revert to the older list the node keeps.
- The controller (one Go binary with a web UI, run with Docker Compose) and its CLI
  (`espdns`): discovery, adoption, node configs and their editor, the zone editor, any zone
  primary (manual, or Technitium's API as a driver), rolling pushes that never take down the
  last healthy node, a dashboard and the query log, backup, restore and recovery from the
  nodes.
- The GUI's backend for the redesign: zone inventory and zone lookup; pending changes and
  one apply job that sends them; the node settings form, its edits as pending changes;
  firmware update availability, shown as versions; one search across nodes, zones and
  lists; the first run and `settings.json` from the browser; and looking up a node to add
  by its address.
- Forwarding: a table of the upstream queries in flight, with caps per group.
- Hosted zones: a revert to the older bundle the node keeps, from the firmware, the CLI, make,
  a controller job and the Zones page.

### Changed

- Hosted zones are held in canonical order, with a binary search for a name's existence, and
  to their memory limit; an AXFR and its SOA check run within one deadline.
- The test vectors, fixtures and tests use documentation addresses and names only, and CI
  refuses private ones.

### Security

- The controller loads esp-web-tools from its own vendored copy (10.4.0), not from a CDN.
- The controller sends a strict Content Security Policy and security headers on every
  response, with no inline scripts.
- Firmware builds: no key and no network in the build containers, signing in a step of its
  own, and container images and CI actions pinned by digest.
- The node's HTTP server checks the Host header against DNS rebinding, gives each request one
  deadline, applies releases in a worker, and JSON-escapes `/status`.
- Controller sessions are bound to the page's origin, logins back off per client, and a backup
  or a revealed Wi-Fi password asks for the password again.
- The controller's data directory is the user's only (directories 0700, files 0600), and its
  container is hardened: no capabilities, no new privileges, a read-only root, memory and
  process limits.
