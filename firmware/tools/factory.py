"""Package a board for a first flash: its chip image with its board definition.

Takes a catalog board (boards/<board>.json) and the build of the chip image it names, and
writes one image that is written at offset 0 to a new node, with an ESP Web Tools manifest:

    dist/<board>/dns2-<board>.bin       bootloader, partition table for the board's flash size,
                                        OTA data, the board partition, the app (erases NVS)
    dist/<board>/manifest.json          ESP Web Tools: {"builds": [{"chipFamily", "parts"}]}
    dist/<board>/info.json              board, chip image, version, build time, ELF SHA-256

The node's address goes into the board partition ("network"), as the builder writes it: a
static address with its prefix length and a gateway, or "dhcp" for a network with a DHCP
server. A node never asks DHCP on its own, so an image without an address is refused.

The controller's builder assembles the same image in Go; this is the command-line version.
The image holds no secrets (only public keys are built in), so it can be served openly.
Factory images are for new nodes only: nodes already running take signed updates (make ota).
"""
import argparse
import ipaddress
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from boardpart import pack  # noqa: E402
from ota_push import app_desc  # noqa: E402

CHIP_FAMILY = {"esp32": "ESP32", "esp32s3": "ESP32-S3", "esp32c3": "ESP32-C3", "esp32c6": "ESP32-C6",
               "esp32p4": "ESP32-P4"}
BOARD_OFFSET = 0x12000  # partitions-*.csv
FIRMWARE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def network(address, gateway):
    """The board definition's "network", checked as the firmware does (cfg_parse_net)."""
    if address == "dhcp":
        if gateway:
            sys.exit("--gateway: only with a static address")
        return {"address": "dhcp"}
    # A prefix length in digits: Python also takes a netmask after the slash, which the
    # firmware refuses, and a board definition the firmware refuses leaves the node with no
    # board at all (no Ethernet).
    ip, slash, bits = address.partition("/")
    if not slash or not bits.isdigit() or len(bits) > 2:
        sys.exit(f"--address {address}: an address with its prefix length (192.0.2.52/24), or dhcp")
    try:
        iface = ipaddress.IPv4Interface(f"{ip}/{int(bits)}")
    except ValueError:
        sys.exit(f"--address {address}: an address with its prefix length (192.0.2.52/24), or dhcp")
    if not 8 <= iface.network.prefixlen <= 30:
        sys.exit(f"--address {address}: a prefix length from 8 to 30")
    if iface.ip in (iface.network.network_address, iface.network.broadcast_address):
        sys.exit(f"--address {address}: the network's own or broadcast address")
    if not gateway:
        sys.exit("--gateway: required with a static address")
    try:
        gw = ipaddress.IPv4Address(gateway)
    except ValueError:
        sys.exit(f"--gateway {gateway}: not an IPv4 address")
    if gw.is_unspecified or gw.is_loopback or gw.is_multicast or gw == ipaddress.IPv4Address("255.255.255.255"):
        sys.exit(f"--gateway {gateway}: can't be used")
    if gw not in iface.network or gw == iface.ip:
        sys.exit(f"--gateway {gateway}: must be another address in {iface.network}")
    return {"address": f"{iface.ip}/{iface.network.prefixlen}", "gateway": str(gw)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--board", required=True, help="catalog board file, e.g. /boards/xiao-s3-sense.json")
    ap.add_argument("--build", required=True, help="the chip image's build, e.g. build/esp32s3-octal")
    ap.add_argument("--address", required=True,
                    help="the node's address with its prefix length (192.0.2.52/24), or dhcp")
    ap.add_argument("--gateway", help="the gateway, with a static address")
    ap.add_argument("--out", help="default: dist/<board>")
    a = ap.parse_args()

    board = json.load(open(a.board))
    if "network" in board:
        sys.exit(f"{a.board} has a network setting: the address is per node (--address)")
    board["network"] = network(a.address, a.gateway)
    name = board["name"]
    out = a.out or f"dist/{name}"
    args = json.load(open(f"{a.build}/flasher_args.json"))
    chip = args["extra_esptool_args"]["chip"]
    if chip not in CHIP_FAMILY:
        sys.exit(f"no ESP Web Tools chip family for {chip}")
    if not board["image"].startswith(chip):
        sys.exit(f"board {name} runs {board['image']}, but {a.build} is an {chip} build")
    flash_mb = board.get("flash_mb", 4)
    layout = "4mb" if flash_mb < 8 else "8mb"
    fs = args["flash_settings"]
    files = {int(off, 16): os.path.join(a.build, path) for off, path in args["flash_files"].items()}

    with tempfile.TemporaryDirectory() as tmp:
        if layout == "4mb":
            # The app is built against the 8 MB layout; a 4 MB board gets the 4 MB table.
            table = os.path.join(tmp, "partitions-4mb.bin")
            subprocess.run([sys.executable, os.path.join(os.environ["IDF_PATH"], "components", "partition_table",
                                                         "gen_esp32part.py"), "-q", "--flash-size", "4MB",
                            os.path.join(FIRMWARE, "partitions-4mb.csv"), table], check=True)
            files[0x8000] = table
        part = os.path.join(tmp, "board.bin")
        open(part, "wb").write(pack(board))
        files[BOARD_OFFSET] = part

        os.makedirs(out, exist_ok=True)
        image = f"dns2-{name}.bin"
        cmd = [sys.executable, "-m", "esptool", "--chip", chip, "merge_bin", "-o", f"{out}/{image}",
               "--flash_mode", fs["flash_mode"], "--flash_freq", fs["flash_freq"], "--flash_size", f"{flash_mb}MB"]
        for off in sorted(files):
            cmd += [hex(off), files[off]]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)

    app = open(os.path.join(a.build, args["app"]["file"]), "rb").read()
    d = app_desc(app)
    info = {"board": name, "title": board.get("title", name), "tier": board.get("tier", "untested"),
            "network": board["network"],
            "chip": chip, "chip_image": board["image"], "flash_mb": flash_mb, "version": d["version"],
            "built": d["built"], "elf_sha256": d["elf_sha256"], "image": image}
    manifest = {
        "name": f"espDNS {name}",
        "version": d["version"],
        "new_install_prompt_erase": True,
        # ESP Web Tools only installs: the dashboard sets up Wi-Fi itself over Improv, with its
        # own port handling (ESP Web Tools left the port open after a missed Improv probe).
        "new_install_improv_wait_time": 0,
        "builds": [{"chipFamily": CHIP_FAMILY[chip], "parts": [{"path": image, "offset": 0}]}],
    }
    json.dump(manifest, open(f"{out}/manifest.json", "w"), indent=2)
    json.dump(info, open(f"{out}/info.json", "w"), indent=2)
    size = os.path.getsize(f"{out}/{image}")
    print(f"{out}/{image}: {board['image']} ({layout} layout) {d['version']} elf {d['elf_sha256']}, {size} bytes")


if __name__ == "__main__":
    main()
