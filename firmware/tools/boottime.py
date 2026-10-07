"""Measure how long a node is silent on DNS across a reboot or power cycle.

Queries the node every 100 ms from this host (SOA of its first zone, recursion off), waits
for it to go silent, and reports the gap until it answers again. This includes ROM and
bootloader time, which the node's own boot_ms (esp_timer, from app start) cannot see.
Afterwards it reads /status for boot_ms and the per-step times.

    python3 tools/boottime.py --host 192.0.2.53          # then power-cycle or update the node

Only NOERROR and NXDOMAIN count as answering; the gap is measured from the last answer
before the outage to the first after it, so its resolution is one interval. Gaps shorter
than --min-gap (a node busy taking an upload) are reported and not counted as a reboot.
Exit status is 1 if any gap exceeds the limit (15 s), 2 if no outage was seen.
"""
import argparse
import json
import os
import random
import socket
import struct
import sys
import time
import urllib.request

LIMIT_S = 15.0
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def status(host, timeout=2):
    with urllib.request.urlopen(f"http://{host}/status", timeout=timeout) as r:
        return json.load(r)


def query(name, qid):
    labels = [l for l in name.strip(".").split(".") if l]
    qname = b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\0"
    return struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", 6, 1)  # SOA IN, RD=0


def probe(sock, addr, name, timeout):
    """Returns the rcode of the node's reply, or None if it didn't answer in time."""
    qid = random.randrange(65536)
    deadline = time.monotonic() + timeout
    try:
        sock.sendto(query(name, qid), addr)
    except OSError:
        time.sleep(max(0, deadline - time.monotonic()))  # no route while the link is down
        return None
    while (left := deadline - time.monotonic()) > 0:
        sock.settimeout(left)
        try:
            data, src = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            return None
        if src[0] == addr[0] and len(data) >= 12 and struct.unpack_from(">H", data)[0] == qid:
            return data[3] & 0x0F
    return None


def show_status(host):
    for _ in range(20):  # HTTP can come up a little after DNS
        try:
            st = status(host)
            break
        except OSError:
            time.sleep(0.5)
    else:
        print("  /status: no reply")
        return
    boot = st.get("boot_ms")
    if "boot_ms" not in st:
        print("  /status: no boot_ms (firmware older than boot timing)")
        return
    steps = "  ".join(f"{k} {v / 1000:.2f}s" if v else f"{k} -" for k, v in st.get("boot", {}).items())
    print(f"  node: reset {st.get('reset', '?')}, answering {boot / 1000:.2f} s after app start"
          if boot else f"  node: reset {st.get('reset', '?')}, not answering yet by its own count")
    print(f"  steps: {steps}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", required=True, help="the node's address")
    ap.add_argument("--name", help="name to query (default: the node's first zone)")
    ap.add_argument("--interval", type=float, default=0.1, help="seconds between queries")
    ap.add_argument("--count", type=int, default=1, help="outages to measure before exiting")
    ap.add_argument("--wait", type=float, default=600, help="give up after this many seconds")
    ap.add_argument("--limit", type=float, default=LIMIT_S, help="seconds of silence allowed")
    ap.add_argument("--min-gap", type=float, default=1.0, help="shorter gaps are not a reboot")
    a = ap.parse_args()

    name = a.name
    if not name:
        try:
            zones = status(a.host).get("zones", [])
            name = zones[0]["name"] if zones else "."
        except OSError as e:
            sys.exit(f"{a.host}: /status unreachable ({e}); pass --name")
    addr = (socket.gethostbyname(a.host), 53)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"probing {a.host} for SOA {name} every {a.interval * 1000:.0f} ms; "
          f"reboot or power-cycle the node now", flush=True)
    end = time.monotonic() + a.wait
    last_ok = None  # time of the last answer
    down_at = None  # time of the first miss after an answer
    gaps = []
    stalls = []  # gaps under --min-gap
    said = False  # "silent" printed for the current gap
    while len(gaps) < a.count and time.monotonic() < end:
        t = time.monotonic()
        rc = probe(sock, addr, name, a.interval)
        ok = rc in (0, 3)
        if ok and down_at is not None and t - last_ok < a.min_gap:
            stalls.append(t - last_ok)
            down_at = None
        elif ok and down_at is not None:
            gap = t - last_ok
            gaps.append(gap)
            if stalls:
                print(f"  before it: {len(stalls)} brief stalls (longest {max(stalls):.1f} s), not reboots",
                      flush=True)
                stalls = []
            verdict = "OK" if gap <= a.limit else f"OVER the {a.limit:.0f} s limit"
            print(f"answering again ({RCODES.get(rc, rc)}): silent {gap:.1f} s "
                  f"(first miss to answer {t - down_at:.1f} s)  {verdict}", flush=True)
            show_status(a.host)
            down_at = None
            said = False
        elif not ok and last_ok is not None and down_at is None:
            down_at = t
        elif not ok and down_at is not None and t - last_ok >= a.min_gap and not said:
            said = True
            print(f"silent (last answer {(t - last_ok):.1f} s ago"
                  f"{', got ' + RCODES.get(rc, str(rc)) if rc is not None else ''})", flush=True)
        if ok:
            last_ok = t
        time.sleep(max(0, t + a.interval - time.monotonic()))

    if not gaps:
        print("no outage seen" if last_ok else f"{a.host} never answered")
        sys.exit(2)
    if len(gaps) > 1:
        print(f"{len(gaps)} outages: min {min(gaps):.1f} s, max {max(gaps):.1f} s")
    sys.exit(1 if max(gaps) > a.limit else 0)


if __name__ == "__main__":
    main()
