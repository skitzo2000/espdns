# Reference

Exact lists for espDNS 0.0.x (alpha). Each page was written from the code, not from
memory. When this reference and the code disagree, the code wins: please open an issue.

| Page | What it covers |
|------|----------------|
| [Controller HTTP API](api.md) | Every route the controller serves: method, path, login needed, body, reply. Also the job kinds you start through the API. |
| [espdns CLI](cli.md) | Every `espdns` command and flag, run through `docker compose`. |
| [Controller settings](settings.md) | `settings.json` (every field and its checks), the controller's own flags, and the `.env` variables `compose.yaml` reads. |
| [Node config](node-config.md) | The node config JSON a node runs: every key, its range, its default, and whether a change applies live or at a reboot. |
| [Node endpoints](node-endpoints.md) | What a node answers over HTTP: `/health`, `/status` (every field), `/metrics` (every metric), `/querylog`. |

## Words used on these pages

- **Node**: an ESP32 board that runs the espDNS firmware and answers DNS.
- **Controller**: the management service in the `espdns-controller` container. It serves the
  dashboard and the API on `http://127.0.0.1:8480`. Nodes keep answering DNS when it is off.
- **Data directory**: where the controller keeps all its state. In the container it is
  `/data`, mounted from the host (`ESPDNS_DATA` in `.env`, `./data` by default).
- **Release**: a signed change sent to a node (firmware, config, zones, blocklist, overrides
  or a control command). Nodes take only releases signed with a key they trust.
- **Zone primary**: the DNS server the nodes copy their secondary zones from, over standard
  AXFR/IXFR and NOTIFY. Any standards-compliant primary works (BIND, Knot, PowerDNS,
  Windows DNS, Technitium and others).

## Where to go next

- How the system is put together: [Architecture](../architecture.md).
- Setting it up: [Getting started](../getting-started.md).
- How a release is built, signed and checked: [releasing.md](../releasing.md).
- What changed in each version: [CHANGELOG.md](../../CHANGELOG.md).
