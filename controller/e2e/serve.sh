#!/bin/sh
# The controller the browser tests run against (playwright.config.js starts it): built from
# this checkout, on a fresh data directory with a login set, on 127.0.0.1:$E2E_PORT. The
# data directory is removed when Playwright stops it. No nodes: none listed, mDNS not browsed
# (-browse-mdns=false) nor by a check (-check-mdns 0), so nothing is sent anywhere.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
pid=
cleanup() {
	[ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 0' INT TERM
CGO_ENABLED=0 go build -o "$work/espdns-controller" ./cmd/espdns-controller
CGO_ENABLED=0 go build -o "$work/espdns" ./cmd/espdns
mkdir -m 0700 "$work/data"
printf '%s\n' "$E2E_PASSWORD" | "$work/espdns" passwd -data "$work/data" -user "$E2E_USER" >/dev/null
"$work/espdns-controller" -data "$work/data" -catalog ../boards -listen "127.0.0.1:$E2E_PORT" -browse-mdns=false -check-mdns 0 &
pid=$!
wait "$pid"
