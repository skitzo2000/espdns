"""Pack a board definition (a catalog JSON file) into a `board` partition image.

Format (firmware/main/board_def.h): "EDBD", version 1 (u16), 0 (u16), JSON length (u32),
CRC-32 of the JSON (u32), then the JSON. The controller's builder writes the same bytes.

    python tools/boardpart.py ../boards/xiao-s3-sense.json board.bin
"""
import json
import struct
import sys
import zlib

PART_SIZE = 4096
HEADER = 16


def pack(definition: dict) -> bytes:
    """The partition image (padded with 0xFF, as erased flash) for a board definition."""
    body = json.dumps(definition, separators=(",", ":"), ensure_ascii=False).encode()
    if len(body) > PART_SIZE - HEADER:
        raise ValueError(f"board definition is {len(body)} bytes; at most {PART_SIZE - HEADER} fit")
    hdr = b"EDBD" + struct.pack("<HHII", 1, 0, len(body), zlib.crc32(body))
    return (hdr + body).ljust(PART_SIZE, b"\xff")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    open(sys.argv[2], "wb").write(pack(json.load(open(sys.argv[1]))))
