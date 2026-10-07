"""Push a firmware build to a node over the network and confirm it took over.

Sends a signed firmware release (main/release.h): a manifest naming this node, the board
and a new seq, signed with secrets/release.pem, followed by the image. A node still on
pre-manifest firmware (no "keys" in /status) gets the image signed the old way, with
HMAC-SHA256(secrets/ota.key); that is the one-time migration.

Three steps, each its own process (and, from the Makefile, its own container), so the key
is read only by the one that needs no network:

    prepare  reads the node's /status and checks the image against it; writes
             <dir>/plan.json (the network; no key)
    sign     signs the release the plan names: <dir>/release.bin and <dir>/release.json
             (the key; no network)
    push     uploads the release and waits for the node to confirm it (the network; no key)

A node already running the build (and no --force) gets no plan, and sign and push then do
nothing.

The plan is written by a step with the network, so sign trusts it only for what the node
says (its ID, the keys it trusts, its last sequence number, the name it checks): what is
signed (--image, its --image-name or --board) and with which key (--recovery) are sign's
own arguments, from the Makefile. The seq is this machine's clock, or one above the node's
last if that is higher, but never more than release.SEQ_AHEAD_MS past the clock: a last
seq near 2^64 (a spoofed /status, a rewritten plan) is refused, not signed above, as it
would leave the node no seq for the releases after it. A plan for another image or another
name is refused, and the key slot comes from --recovery alone, so nothing with the network
can get anything but this build signed, or choose the key.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
import release  # noqa: E402

APP_DESC_OFF = 32  # esp_image_header_t (24) + first segment header (8)


def app_desc(image):
    magic, = struct.unpack_from("<I", image, APP_DESC_OFF)
    if magic != 0xABCD5432:
        sys.exit("image has no app descriptor")
    s = lambda off, n: image[APP_DESC_OFF + off:APP_DESC_OFF + off + n].split(b"\0")[0].decode()
    return {
        "version": s(16, 32),
        "project": s(48, 32),
        "built": f"{s(96, 16)} {s(80, 16)}",
        "elf_sha256": image[APP_DESC_OFF + 144:APP_DESC_OFF + 152].hex(),
    }


BUILTIN_ADDR_MARK = b"espdns:builtin-address="  # main/cfg.h CFG_BUILTIN_ADDR_MARK


def builtin_address(image):
    """The address built into the image ("" for none), or None for an image from before the
    firmware marked it (controller/internal/release BuiltinAddress)."""
    i = image.find(BUILTIN_ADDR_MARK)
    if i < 0:
        return None
    rest = image[i + len(BUILTIN_ADDR_MARK):]
    end = rest.find(b"\0")
    if end < 0 or end > 15:
        return None
    return rest[:end].decode()


def address_check(cur, image):
    """Why the image would leave the node without its address, or None (as the controller's
    fleet.FirmwareAddressCheck): a node whose address is the one built into its firmware
    gets only an image with the same one; a node with no board partition whose config gives
    its address, only an image with one built in, which it falls back on if its config is
    ever refused (it never asks DHCP on its own)."""
    built, cfg = builtin_address(image), cur.get("config") or {}
    if built is None or not cfg:
        return None
    ip, frm, board = (cfg.get("ip") or "").split("/")[0], cfg.get("address_from"), cur.get("board")
    fix = f"build it with the node's address (STATIC_IP_{board} in firmware/local.mk)"
    if frm == "firmware" and built != ip:
        return (f"the node's address ({ip}) is the one built into the firmware it runs, and this image has "
                f"{built or 'none'} built in: {fix}")
    fallback = frm == "config" and cur.get("board_source") != "partition"
    if fallback and not built:
        return ("the node has no board partition, so if its config is ever refused it falls back on the address "
                f"built into its firmware, and this image has none: {fix}")
    try:
        doc = any(ipaddress.ip_address(built) in ipaddress.ip_network(n)
                  for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
    except ValueError:
        doc = False
    if fallback and built != ip and doc:
        return ("the node has no board partition, so if its config is ever refused it falls back on the address "
                f"built into its firmware, and this image has {built}, a documentation address (CI's, or an "
                f"example's): {fix}")
    return None


def status(host, timeout=3):
    with urllib.request.urlopen(f"http://{host}/status", timeout=timeout) as r:
        return json.load(r)


def dns_ok(host, name):
    """One UDP SOA query; True if the board answers with NOERROR + AA. No name (a node
    with no zones): the root's SOA, any NOERROR answer."""
    q = struct.pack(">HHHHHH", 0x5A5A, 0, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".") if l) + b"\0"
    q += struct.pack(">HH", 6, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    try:
        s.sendto(q, (host, 53))
        r = s.recv(1500)
        flags = struct.unpack_from(">H", r, 2)[0]
        return r[:2] == q[:2] and (flags & 0x0400 or not name) and flags & 0xF == 0
    except OSError:
        return False
    finally:
        s.close()


PLAN, RELEASE, HEADERS = "plan.json", "release.bin", "release.json"


def read(path):
    with open(path, "rb") as f:
        return f.read()


def load(d, name):
    """A file the step before wrote, or None if there is none (nothing to push)."""
    p = os.path.join(d, name)
    return read(p) if os.path.exists(p) else None


def write(d, name, data):
    """Written whole: a new file renamed over the old one."""
    tmp = os.path.join(d, f".{name}.tmp")
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, os.path.join(d, name))


def prepare(a):
    os.makedirs(a.dir, exist_ok=True)
    for name in (PLAN, RELEASE, HEADERS):
        try:
            os.remove(os.path.join(a.dir, name))
        except FileNotFoundError:
            pass
    image = read(a.image)
    new = app_desc(image)
    print(f"image: {new['project']} {new['version']} built {new['built']} elf {new['elf_sha256']} "
          f"({len(image)} bytes)")

    try:
        cur = status(a.host)
        print(f"board: {cur['version']} elf {cur['elf_sha256']} slot {cur['slot']} ({cur['ota_state']}), "
              f"up {cur['uptime_s']}s")
        if cur["elf_sha256"] == new["elf_sha256"] and not a.force:
            print("already running this build (use --force to push anyway)")
            return
        why = address_check(cur, image)
        if why:
            sys.exit(f"refused: {why}")
        if a.trial and cur["ota_state"] != "valid":
            sys.exit(f"node is still on a trial build ({cur['ota_state']}, up {cur['uptime_s']}s): "
                     "wait for it to roll back")
    except (OSError, ValueError) as e:
        sys.exit(f"board not reachable at http://{a.host}/status: {e}")
    if a.zone is None:
        zones = cur.get("zones") or []
        a.zone = zones[0]["name"] if zones else ""

    plan = {"host": a.host, "new_host": a.new_host or a.host,
            "image_sha256": hashlib.sha256(image).hexdigest(), "elf_sha256": new["elf_sha256"],
            "zone": a.zone, "trial": a.trial}
    if "keys" not in cur:
        print("board runs pre-manifest firmware: this push is signed with the legacy HMAC key")
        plan["legacy"] = True
    else:
        # The name the node checks: its chip image; or, on firmware from before board
        # definitions, the board it was built for (only a transitional image for that board fits).
        if "image" in cur:
            if cur["image"] != a.image_name:
                sys.exit(f"node runs chip image {cur['image']}, this is {a.image_name}")
            name = a.image_name
        else:
            if cur.get("board") != a.board:
                sys.exit(f"node runs firmware from before board definitions, built for board "
                         f"{cur.get('board')}: push a transitional image for it (BOARD={cur.get('board')})")
            name = a.board
        plan.update(legacy=False, keys=cur["keys"], node_id=cur["node_id"], name=name,
                    last_seq=cur["seq"]["firmware"])
    write(a.dir, PLAN, json.dumps(plan, indent=2).encode())


def sign(a):
    raw = load(a.dir, PLAN)
    if raw is None:
        print("nothing to sign")
        return
    plan = json.loads(raw)
    image = read(a.image)
    if hashlib.sha256(image).hexdigest() != plan["image_sha256"]:
        sys.exit(f"{a.image} changed since it was checked against the node: push again")
    headers = {"Content-Type": "application/octet-stream"}
    if plan["legacy"]:
        key = read(a.legacy_key)
        headers["X-OTA-HMAC"] = hmac.new(key, image, hashlib.sha256).hexdigest()
        body = image
    else:
        # The name the node checks is the chip image this was built as, or, on firmware from
        # before board definitions, the board it was built for: nothing else
        if plan["name"] not in (a.image_name, a.board or a.image_name):
            sys.exit(f"the plan names {plan['name']!r}, and this is chip image {a.image_name}"
                     f"{f' for board {a.board}' if a.board else ''}: push again")
        key_id = release.KEY_RECOVERY if a.recovery else release.KEY_RELEASE
        pem = a.key or ("secrets/recovery.pem" if a.recovery else "secrets/release.pem")
        keys = plan["keys"]
        trusted = keys[key_id] if isinstance(keys, list) and len(keys) > key_id else None
        priv = release.load_private(pem)
        fp = release.fingerprint(release.public_raw(priv))
        if trusted != fp:
            sys.exit(f"{pem} (fingerprint {fp}) is not the key this board trusts in slot {key_id} "
                     f"({trusted})")
        try:
            seq = release.next_seq(plan["last_seq"])
        except ValueError as e:
            sys.exit(f"refused: {e}")
        body = release.header(priv, "firmware", key_id, release.parse_mac(plan["node_id"]), plan["name"],
                              seq, image) + image
        print(f"release: firmware seq {seq} for node {plan['node_id']}, {plan['name']}, key {fp}")
    write(a.dir, RELEASE, body)
    write(a.dir, HEADERS, json.dumps(headers).encode())


def push(a):
    raw = load(a.dir, PLAN)
    if raw is None:
        print("nothing to push")
        return
    plan = json.loads(raw)
    body, headers = load(a.dir, RELEASE), load(a.dir, HEADERS)
    if body is None or headers is None:
        sys.exit(f"no signed release in {a.dir}: sign first")
    host, new_host, zone, elf = plan["host"], plan["new_host"], plan["zone"], plan["elf_sha256"]
    req = urllib.request.Request(f"http://{host}/ota", data=body, method="POST", headers=json.loads(headers))
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            print(f"upload: {r.read().decode().strip()} ({time.time() - t0:.1f}s)")
    except urllib.error.HTTPError as e:
        sys.exit(f"upload rejected: {e.code} {e.read().decode().strip()}")
    finally:
        # A signed release is for this one push: none is left behind to send again
        for name in (RELEASE, HEADERS):
            os.remove(os.path.join(a.dir, name))

    # Wait for the new build to boot, pass its health check, and answer DNS. If the build
    # moves the board to a new address, watch both: new build on new_host = success,
    # old build back on the old host = rollback.
    t1 = time.time()
    seen_down = False
    while time.time() - t1 < a.wait:
        time.sleep(0.5)
        for h in dict.fromkeys([new_host, host]):
            try:
                st = status(h, timeout=1)
            except (OSError, ValueError):
                seen_down = True
                continue
            if st["elf_sha256"] != elf:
                if seen_down:
                    sys.exit(f"board came back on the OLD build ({st['elf_sha256']}) at {h}: "
                             "the update was rolled back")
                continue
            if h == new_host and plan["trial"] and dns_ok(h, zone):
                print(f"done: running {st['elf_sha256']} in {st['slot']} at {h} ({st['ota_state']}), "
                      f"answering DNS ({time.time() - t1:.1f}s after upload)")
                return
            if h == new_host and st["ota_state"] == "valid" and dns_ok(h, zone):
                print(f"done: running {st['elf_sha256']} in {st['slot']} at {h}, confirmed healthy, "
                      f"answering DNS ({time.time() - t1:.1f}s after upload)")
                return
    sys.exit("timed out waiting for the new build to confirm itself")


def main(argv=None):
    ap = argparse.ArgumentParser()
    steps = ap.add_subparsers(dest="step", required=True)
    p = steps.add_parser("prepare", help="check the image against the node (network, no key)")
    p.add_argument("--host", required=True, help="the node's address")
    p.add_argument("--new-host", help="address the new build comes up on, if it changes the IP")
    p.add_argument("--image", required=True, help="the app to push, e.g. build/esp32s3-octal/dns2.bin")
    p.add_argument("--image-name", required=True, help="the chip image it was built as, e.g. esp32s3-octal")
    p.add_argument("--board", default="", help="for a node on firmware from before board definitions: "
                   "the board this transitional image was built for")
    p.add_argument("--zone", help="zone used for the DNS check: the node must answer its SOA authoritatively "
                   "(default: the node's first zone; with none, any answer from it)")
    p.add_argument("--force", action="store_true", help="push even if already running this build")
    p.add_argument("--trial", action="store_true", help="a build that never confirms itself (bench): "
                   "done once it runs and answers DNS; refuse while the node is still on an earlier trial")
    s = steps.add_parser("sign", help="sign this image for the node the plan names (the key, no network)")
    s.add_argument("--image", required=True, help="the app to sign, as given to prepare")
    s.add_argument("--image-name", required=True, help="the chip image it was built as, as given to prepare")
    s.add_argument("--board", default="", help="the board a transitional image was built for, as given to prepare")
    s.add_argument("--recovery", action="store_true",
                   help="sign with the offline recovery key (secrets/recovery.pem, key slot 1)")
    s.add_argument("--key", help="signing key (default secrets/release.pem, or secrets/recovery.pem "
                   "with --recovery)")
    s.add_argument("--legacy-key", default="secrets/ota.key",
                   help="HMAC key, only for a node still on pre-manifest firmware")
    u = steps.add_parser("push", help="upload the signed release and wait for it (network, no key)")
    u.add_argument("--wait", type=float, default=150, help="seconds to wait for the node to confirm it")
    for q in (p, s, u):
        q.add_argument("--dir", required=True, help="where the steps keep the plan and the release, "
                       "e.g. build/esp32s3-octal/release")
    a = ap.parse_args(argv)
    {"prepare": prepare, "sign": sign, "push": push}[a.step](a)


if __name__ == "__main__":
    main()
