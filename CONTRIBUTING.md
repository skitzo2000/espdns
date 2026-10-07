# Contributing to espDNS

Thank you for helping. espDNS is alpha software (0.0.x), so bug reports from real networks
are very welcome. This page says how to report a bug, how to build and test, and what a
pull request needs.

Everything here runs in Docker. You need Docker, Docker Compose v2.17 or newer, and git.
Nothing else needs installing.

## Reporting a bug

Open an issue on the repository. Please include:

- **The version.** The controller's: from `controller/`, run
  `docker compose run --rm -T --entrypoint /espdns espdns-controller version`. A node's:
  `"version"` in `http://<node>/status`.
- **The board** (its catalog name, such as `ws-s3-eth`) and how it is connected
  (Ethernet or Wi-Fi).
- **What you did, what you expected, and what happened.**
- **Logs.** The controller's: `docker compose logs --tail 200` from `controller/`. A
  node's: its `http://<node>/status` and `http://<node>/health`.

**Remove your own values first.** Replace real addresses, zone names, domain names and
user names with documentation values: 192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32,
example.com, home.arpa. Never paste a key, token, password or backup.

**Security problems are not issues.** Report them privately, as [SECURITY.md](SECURITY.md)
says.

## Building and testing

Run these from the top of your clone.

### The controller's tests

`go vet` and `go test` for the controller and the CLI, in the same Go image CI uses:

```sh
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e CGO_ENABLED=0 \
  -v "$PWD:/src:ro" -w /src/controller \
  golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514 \
  sh -c 'go vet ./... && go test ./...'
```

Run them in a checkout with the project's public keys in `firmware/keys/`. One test checks
that [docs/releasing.md](docs/releasing.md) names the fingerprint of
`firmware/keys/release.pub`, so it fails in a checkout with your own keys.

### The controller's image

```sh
docker build -t espdns-controller:dev \
  --build-context boards=boards --build-context version=. --build-context keys=firmware/keys \
  controller
docker run --rm --entrypoint /espdns espdns-controller:dev version
```

To run your change, rebuild and restart the controller from `controller/` with
`docker compose up -d --build`.

### The firmware

A chip image, built the way a release builds it, in the pinned ESP-IDF image. The build
fetches ESP-IDF components, so it needs the network. It fails on any compiler warning.
Name one chip image from `firmware/images/` (here `esp32s3-octal`), or leave the name off
to build them all:

```sh
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src \
  espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2 \
  sh scripts/release/build-firmware.sh build/dev esp32s3-octal
```

The exported image lands in `build/dev/esp32s3-octal/`. Build in a clean checkout, not in
one that holds your keys or your controller's data directory: the container mounts the
whole checkout. [docs/releasing.md](docs/releasing.md) has the full release build.

### What CI runs

The CI workflow ([`.gitea/workflows/ci.yml`](.gitea/workflows/ci.yml)) runs on every push:

- the firmware's host unit tests (with AddressSanitizer and UBSan);
- the controller's `go vet` and `go test`;
- a build of every chip image, which fails on a compiler warning or a changed component
  lock;
- a check that no private address (RFC 1918, or the shared range of RFC 6598) appears in
  a build file, the board catalog, an example, a test or a test fixture. Use documentation
  addresses instead.

A developer guide that covers the firmware's host tests and the browser tests on your own
machine will follow.

## Pull requests

- **One change per pull request,** based on `main`.
- **Tests.** Add or change tests for what you change. CI must pass.
- **Docs.** If you change what a user sees or runs, update the docs in the same pull
  request. Commands in the docs are `docker`, `docker compose` or `git` commands.
- **Changelog.** Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- **No site values.** No real addresses, zone names, domain names, host names or people's
  names anywhere: code, tests, examples, docs or commit messages. Use 192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, example.com and home.arpa. Your own
  settings belong in your data directory, which is never committed.
- **No secrets.** Never commit a private key, token, password or backup. Only the public
  keys in `firmware/keys/` belong in the repository.
- **Plain English.** Short sentences in docs, comments and commit messages.
- **License.** espDNS is under the GNU Affero General Public License, version 3 only
  (AGPL-3.0-only, [LICENSE](LICENSE)). By sending a pull request you agree that your
  contribution is licensed under the AGPL-3.0-only too.

## Code of conduct

Be kind and respectful. This project follows the
[Contributor Covenant, version 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Report unacceptable behaviour to the maintainers privately, the same way as a security
problem: on [github.com/skitzo2000/espdns](https://github.com/skitzo2000/espdns), the
**Security** tab, **Report a vulnerability** (see [SECURITY.md](SECURITY.md)).
