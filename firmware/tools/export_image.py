"""Export a chip image's build for the controller's builder.

Writes dist/images/<image>/ from build/<image>/:

    bootloader.bin            for the chip (its flash size field is set when a board is flashed)
    partitions-8mb.bin        flash layout for 8 MB and up
    partitions-4mb.bin        flash layout for 4 MB
    ota_data_initial.bin
    app.bin                   the firmware
    image.json                image name, chip, offsets, flash mode and frequency, version,
                              build time and ELF SHA-256

The builder joins these with a board partition (tools/boardpart.py format) into one image
for a board. No board, site setting or secret is in any of it.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from ota_push import app_desc  # noqa: E402

FIRMWARE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHIP_FAMILY = {"esp32": "ESP32", "esp32s3": "ESP32-S3", "esp32c3": "ESP32-C3", "esp32c6": "ESP32-C6",
               "esp32p4": "ESP32-P4"}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("image", help="chip image name, e.g. esp32s3-octal")
    ap.add_argument("--build", help="default: build/<image>")
    ap.add_argument("--out", help="default: dist/images/<image>")
    a = ap.parse_args()
    build = a.build or f"build/{a.image}"
    out = a.out or f"dist/images/{a.image}"
    args = json.load(open(f"{build}/flasher_args.json"))
    chip = args["extra_esptool_args"]["chip"]
    files = {path: int(off, 16) for off, path in args["flash_files"].items()}

    os.makedirs(out, exist_ok=True)
    offsets = {}
    for path, off in files.items():
        name = {"bootloader/bootloader.bin": "bootloader.bin", "ota_data_initial.bin": "ota_data_initial.bin",
                "partition_table/partition-table.bin": "partitions-8mb.bin"}.get(path, "app.bin")
        shutil.copy(os.path.join(build, path), os.path.join(out, name))
        offsets[name] = off
    gen = os.path.join(os.environ["IDF_PATH"], "components", "partition_table", "gen_esp32part.py")
    subprocess.run([sys.executable, gen, "-q", "--flash-size", "4MB", os.path.join(FIRMWARE, "partitions-4mb.csv"),
                    os.path.join(out, "partitions-4mb.bin")], check=True)
    offsets["partitions-4mb.bin"] = offsets["partitions-8mb.bin"]
    offsets["board"] = 0x12000

    d = app_desc(open(os.path.join(out, "app.bin"), "rb").read())
    fs = args["flash_settings"]
    info = {"image": a.image, "chip": chip, "chip_family": CHIP_FAMILY[chip], "offsets": offsets,
            "flash_mode": fs["flash_mode"], "flash_freq": fs["flash_freq"], "version": d["version"],
            "built": d["built"], "elf_sha256": d["elf_sha256"]}
    json.dump(info, open(os.path.join(out, "image.json"), "w"), indent=2)
    print(f"{out}: {chip}, app {os.path.getsize(os.path.join(out, 'app.bin')) // 1024} KB, elf {d['elf_sha256']}")


if __name__ == "__main__":
    main()
