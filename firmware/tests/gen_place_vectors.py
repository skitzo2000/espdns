"""Regenerate tests/place_vectors.json: where a node puts a blocklist (main/block.h, blk_plan
and blk_place; docs/design.md, Lookup tiers), worked out here apart from the C (main/block.c,
checked in test_core) and the Go (controller/internal/blocklist/place.go, which a rollout
checks before it pushes a list), which must both give the same answers. place() restates
blk_place; it is checked here against place_by_load (blk_load's allocations, step by step)
on every case and around its edges, and against what the nodes did with the real list.

    python3 tests/gen_place_vectors.py > tests/place_vectors.json
"""
import json
import struct

SECTOR = 512
HEADER = 160
KB, MB = 1024, 1024 * 1024
LIST_ERR = "list too big for this board's blocking memory (memory.blocklist_kb)"
OVR_ERR = "overrides too big for this board's blocking memory (memory.blocklist_kb)"

# The 2,599,228-entry list rolled out in October 2026 (controller/data/lists/list.bin, its
# SipHash key zeroed): 12,181,504 bytes, a 4 MB front (the indexes and the xor filters).
REAL = bytes.fromhex(
    "455350444e53424c022c0a0000000000000000000000000000000000000000006343000087000000a000000000e83e00"
    "d8040000ac1b0000ea2eaba4f166a09cd9652700f53c0000a06c000000f63f00485402003e271000ea2eaba4f166a09c"
    "000000000000000078e73e0000e0b90000000000000000000000000000000000000000000000000078e73e0000e0b900"
    "00000000000000000000000000000000")
REAL_LEN = 12181504


def header(tables, front, version=2, magic=b"ESPDNSBL"):
    """tables: (hashes, sectors) per table; the first table's sectors start at front."""
    h = bytearray(HEADER)
    h[0:8] = magic
    h[8], h[9], h[10] = version, 44, 10
    for i, (hashes, sectors) in enumerate(tables):
        struct.pack_into("<IIII", h, 32 + 32 * i, hashes, sectors, HEADER, front if i == 0 else 0)
    return bytes(h)


def plan(hdr, file_len):
    """blk_plan: (error, need)."""
    if hdr[0:8] != b"ESPDNSBL":
        return "not a blocklist", None
    front = struct.unpack_from("<I", hdr, 44)[0]
    if front < 96 or hdr[8] not in (1, 2):
        return "not a blocklist", None
    if front > file_len:
        return "list cut short", None
    index = 0
    for i in range(2 if hdr[8] == 1 else 4):
        sectors = struct.unpack_from("<I", hdr, 32 + 32 * i + 4)[0]
        if sectors > file_len // SECTOR:
            return "bad table size", None
        index += 8 * sectors
    entries = struct.unpack_from("<I", hdr, 32)[0] + struct.unpack_from("<I", hdr, 64)[0]
    return "", {"front": front, "index": index, "sectors": file_len - front, "entries": entries}


def place(n, r):
    """blk_place: (error, tier, now, index_internal)."""
    def room(budget, used):
        return max(budget - used, 0)
    idx_now = room(r["index_budget"], r["index_used"])
    idx_after = room(r["index_budget"], r["index_used"] - min(r["index_held"], r["index_used"]))
    now = room(r["budget"], r["used"])
    after = room(r["budget"], r["used"] - min(r["held"], r["used"]))
    int_now = 0 < n["index"] <= idx_now
    int_after = 0 < n["index"] <= idx_after
    whole = max(n["front"], n["sectors"])  # the RAM tier holds the front, then the sectors

    def ext(internal):
        return 0 if internal else n["index"]
    if r["overrides"]:
        return ("" if ext(int_now) + whole <= now else OVR_ERR), "ram", True, int_now
    if r["ram_tier"] and ext(int_after) + whole <= after:
        return "", "ram", ext(int_now) + whole <= now, int_now
    if ext(int_after) + n["front"] <= after:
        return "", "sd", ext(int_now) + n["front"] <= now, int_now
    return LIST_ERR, "", False, int_now


def load_fits(n, tier, data_room, index_room):
    """Whether blk_load gets its memory, step by step, with data_room bytes of the lists'
    memory and index_room of the index share: the front, the index (in internal RAM if it
    fits there), then in the RAM tier the front freed and the sectors taken. Apart from
    place(): the two must agree on every case below."""
    data = index = 0
    internal = 0 < n["index"] <= index_room

    def take(k, size):
        nonlocal data, index
        if k == "index":
            index += size
            return index <= index_room
        data += size
        return data <= data_room
    if not take("data", n["front"]) or n["index"] and not take("index" if internal else "data", n["index"]):
        return False
    if tier == "ram":
        data -= n["front"]
        return take("data", n["sectors"] or 8)
    return True


def place_by_load(n, r):
    """place(), from load_fits: the RAM tier if it loads once the replaced list is gone, else
    the SD tier, else refused; now if it loads next to that list."""
    now = max(r["budget"] - r["used"], 0)
    after = max(r["budget"] - (r["used"] - min(r["held"], r["used"])), 0)
    idx_now = max(r["index_budget"] - r["index_used"], 0)
    idx_after = max(r["index_budget"] - (r["index_used"] - min(r["index_held"], r["index_used"])), 0)
    internal = 0 < n["index"] <= idx_now
    if r["overrides"]:
        return ("" if load_fits(n, "ram", now, idx_now) else OVR_ERR), "ram", True, internal
    for tier in (("ram", "sd") if r["ram_tier"] else ("sd",)):
        if load_fits(n, tier, after, idx_after):
            return "", tier, load_fits(n, tier, now, idx_now), internal
    return LIST_ERR, "", False, internal


def rooms(budget_kb, index_kb, psram=True, used=0, held=0, index_used=0, index_held=0, overrides=False):
    """A node's blocking share as blocking.c's place() fills it in: no index share without PSRAM."""
    return {"budget": budget_kb * KB, "used": used, "held": held,
            "index_budget": index_kb * KB if psram else 0, "index_used": index_used if psram else 0,
            "index_held": index_held if psram else 0, "ram_tier": psram, "overrides": overrides}


P4, P4_IDX = 20480, 160      # p4-ip101
S3, S3_IDX = 2048, 0         # ws-s3-eth
REAL_DATA, REAL_INDEX = 8058880, 125920  # the real list in the RAM tier: its sectors, its index
small = header([(30000, 100), (2000, 10)], 64 * KB)  # 120 KB of sectors (a 64 KB front)
sd_list = header([(1500000, 8000), (100000, 400)], 1 * MB)
v1 = header([(1000, 10), (50, 2)], 4096, version=1)
cases = [
    ("the real list on ws-s3-eth: fits no tier", REAL, REAL_LEN, rooms(S3, S3_IDX)),
    ("the real list on ws-s3-eth over a list in the SD tier", REAL, REAL_LEN,
     rooms(S3, S3_IDX, used=1200 * KB, held=1200 * KB)),
    ("the real list on p4-ip101, nothing loaded", REAL, REAL_LEN, rooms(P4, P4_IDX)),
    ("the real list on p4-ip101 over itself", REAL, REAL_LEN,
     rooms(P4, P4_IDX, used=REAL_DATA, held=REAL_DATA, index_used=REAL_INDEX, index_held=REAL_INDEX)),
    ("the real list on p4-ip101 over itself, counted all in the lists' memory", REAL, REAL_LEN,
     rooms(P4, P4_IDX, used=REAL_DATA + REAL_INDEX, held=REAL_DATA + REAL_INDEX)),
    ("the real list on p4-ip101 over a 14 MB list: at the next reboot", REAL, REAL_LEN,
     rooms(P4, P4_IDX, used=14 * MB, held=14 * MB)),
    ("the real list on p4-ip101 with 13 MB of overrides: the SD tier", REAL, REAL_LEN,
     rooms(P4, P4_IDX, used=13 * MB)),
    ("the real list on p4-ip101 with 17 MB of overrides: refused", REAL, REAL_LEN,
     rooms(P4, P4_IDX, used=17 * MB)),
    ("the real list on a P4 with 8 MB for blocking", REAL, REAL_LEN, rooms(8192, P4_IDX)),
    ("the real list on a P4 with 4 MB for blocking", REAL, REAL_LEN, rooms(4096, P4_IDX)),
    ("an SD-tier list on ws-s3-eth, nothing loaded", sd_list, 1 * MB + 8400 * SECTOR, rooms(S3, S3_IDX)),
    ("an SD-tier list on ws-s3-eth over another: at the next reboot", sd_list, 1 * MB + 8400 * SECTOR,
     rooms(S3, S3_IDX, used=1500 * KB, held=1500 * KB)),
    ("a small list on ws-s3-eth over another: live", small, 64 * KB + 120 * KB,
     rooms(S3, S3_IDX, used=300 * KB, held=300 * KB)),
    ("a small list without PSRAM: the SD tier", small, 64 * KB + 120 * KB, rooms(128, 0, psram=False)),
    ("a list too big for a board without PSRAM", sd_list, 1 * MB + 8400 * SECTOR, rooms(128, 0, psram=False)),
    ("a version 1 list", v1, 4096 + 12 * SECTOR, rooms(P4, P4_IDX)),
    ("an empty list (no index)", header([(0, 0)], 4096), 4096, rooms(S3, S3_IDX)),
    ("overrides next to the real list on p4-ip101", small, 64 * KB + 120 * KB,
     rooms(P4, P4_IDX, used=REAL_DATA, index_used=REAL_INDEX, overrides=True)),
    ("overrides over overrides, next to a list in the SD tier on ws-s3-eth", small, 64 * KB + 120 * KB,
     rooms(S3, S3_IDX, used=1800 * KB, held=150 * KB, overrides=True)),
    ("overrides that don't fit next to the list", small, 64 * KB + 120 * KB,
     rooms(S3, S3_IDX, used=1950 * KB, overrides=True)),
    ("not a blocklist", header([(1, 1)], 4096, magic=b"ESPDNSXX"), 8192, rooms(P4, P4_IDX)),
    ("an unknown version", header([(1, 1)], 4096, version=3), 8192, rooms(P4, P4_IDX)),
    ("a front past the end", header([(1, 1)], 8192), 4096, rooms(P4, P4_IDX)),
    ("a front inside the header", header([(1, 1)], 64), 4096, rooms(P4, P4_IDX)),
    ("a table bigger than the file", header([(1, 100)], 4096), 8192, rooms(P4, P4_IDX)),
]
# What the nodes did with the real list (October 2026): the P4 loads it in the RAM tier, its
# index in internal RAM; pushed again, it swapped live with the new copy's index in PSRAM
# (internal heap free 211 KB -> 337 KB once the old one was gone); the S3 can't hold it.
SEEN = {
    "the real list on ws-s3-eth: fits no tier": (LIST_ERR, "", False, False),
    "the real list on p4-ip101, nothing loaded": ("", "ram", True, True),
    "the real list on p4-ip101 over itself": ("", "ram", True, False),
}
out = []
for name, hdr, file_len, room in cases:
    err, need = plan(hdr, file_len)
    want = {"error": err}
    if need:
        want["need"] = need
        got = place(need, room)
        assert got == place_by_load(need, room), (name, got, place_by_load(need, room))
        assert name not in SEEN or got == SEEN[name], (name, got)
        err, tier, now, internal = got
        want.update(error=err, tier=tier, now=now, index_internal=internal)
    out.append({"name": name, "header": hdr.hex(), "file_len": file_len, "room": room, "want": want})
assert all(any(c[0] == name for c in cases) for name in SEEN)
# And on rooms around every case's edges.
for name, hdr, file_len, room in cases:
    err, need = plan(hdr, file_len)
    if not need:
        continue
    for key in ("budget", "used", "held", "index_budget", "index_used", "index_held"):
        for v in {room[key] + d for d in (-1, 0, 1)} | {need["front"], need["index"], need["sectors"],
                                                          need["index"] + need["front"], need["index"] + need["sectors"]}:
            r = dict(room, **{key: max(v, 0)})
            assert place(need, r) == place_by_load(need, r), (name, key, v)
print(json.dumps(out, indent=1))
