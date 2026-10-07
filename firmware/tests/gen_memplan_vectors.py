"""Regenerate tests/memplan_vectors.json: memory plans (main/memplan.h) worked out here, apart
from the C (main/memplan.c, checked in test_core) and the Go (controller/internal/memplan),
which must both give the same answers.

    python3 tests/gen_memplan_vectors.py > tests/memplan_vectors.json
"""
import json
import os

BOARDS = os.path.join(os.path.dirname(__file__), "..", "..", "boards")

# memplan.h
PSRAM_SYSTEM_KB = 1024
UDP_WORKERS, TCP_WORKERS = 4, 2
WORKER_STACK, LISTENER_STACK = 12288, 4096
UDP_ITEMS, UDP_ITEM = 64 + 4 + 1, 1536
BUILDER, UDP_OUT, TCP_MSG, SCRATCH = 4096, 1232, 65535, 65535
XFR_STACK, XFR_BUFFERS = 8192, 2 * 65535
HOSTED_STACK, BLOCKING_STACK, BLOCKING_IO = 8192, 8192, 4096
CACHE_FIXED, CACHE_ENTRY = 8192, 40 + 68
FWD_SLOT = 1600
FWD_STACK, FWD_TCP = 6144, 65535
SERVICES = ["dns", "forwarding", "forward_zones", "secondary", "hosted", "blocking", "querylog"]

# memplan.c: image -> internal, cache, entries, blocklist, index, secondary, querylog,
# fwd_pending (with PSRAM)
DEFAULTS = {
    "esp32p4-rev1": (320, 4096, 8192, 20480, 160, 1024, 1024, 32),
    "esp32p4": (320, 4096, 8192, 20480, 160, 1024, 1024, 32),
    "esp32s3-octal": (160, 2944, 8192, 2048, 0, 256, 64, 32),
    "esp32s3-quad": (160, 1024, 2048, 512, 0, 128, 32, 32),
    "esp32": (96, 1024, 2048, 512, 0, 128, 32, 32),
    "esp32c3": (128, 64, 512, 128, 0, 64, 16, 32),
    "esp32c6": (160, 64, 512, 128, 0, 64, 16, 32),
}
OTHER = (96, 64, 512, 128, 0, 64, 16, 32)
NO_PSRAM = (0, 64, 512, 128, 0, 64, 0, 8)
HOSTED_KB = 64


def board_values(board, image, chip_psram_kb):
    d = DEFAULTS.get(image, OTHER)
    mem = (board or {}).get("memory", {})
    psram = board["psram_mb"] * 1024 if board and "psram_mb" in board else chip_psram_kb
    psram = max(psram, 0)
    if chip_psram_kb >= 0:
        psram = min(psram, chip_psram_kb)
    s = d if psram else NO_PSRAM
    return {
        "psram_kb": psram,
        "internal_kb": mem.get("internal_kb", d[0]),
        "cache_kb": mem.get("cache_kb", s[1]),
        "cache_entries": mem.get("cache_entries", s[2]),
        "blocklist_kb": mem.get("blocklist_kb", s[3]),
        "blocklist_index_kb": mem.get("blocklist_index_kb", s[4]),
        "hosted_zones_kb": mem.get("hosted_zones_kb", HOSTED_KB),
        "secondary_zones_kb": mem.get("secondary_zones_kb", s[5]),
        "querylog_kb": mem.get("querylog_kb", s[6]),
        "fwd_pending": mem.get("fwd_pending", s[7]),
    }


def plan(b, services):
    cap = [b["internal_kb"] * 1024, max(b["psram_kb"] - PSRAM_SYSTEM_KB, 0) * 1024]
    data = 1 if b["psram_kb"] else 0
    share = {s: [0, 0] for s in SERVICES}
    share["dns"][0] = (UDP_WORKERS + TCP_WORKERS) * WORKER_STACK + 2 * LISTENER_STACK + 2 * FWD_STACK
    share["dns"][data] += (b["cache_kb"] * 1024 + UDP_WORKERS * (UDP_OUT + SCRATCH + BUILDER) +
                           TCP_WORKERS * (2 * TCP_MSG + 2 + SCRATCH + BUILDER) + UDP_ITEMS * UDP_ITEM +
                           b["fwd_pending"] * FWD_SLOT + FWD_TCP)
    if "secondary" in services:
        share["secondary"][0] += XFR_STACK
        share["secondary"][data] += b["secondary_zones_kb"] * 1024 + XFR_BUFFERS
    if "hosted" in services:
        share["hosted"][0] += HOSTED_STACK
        share["hosted"][data] += 3 * b["hosted_zones_kb"] * 1024
    if "blocking" in services:
        share["blocking"][0] += BLOCKING_STACK + b["blocklist_index_kb"] * 1024
        share["blocking"][data] += b["blocklist_kb"] * 1024 + BLOCKING_IO
    if "querylog" in services:
        share["querylog"][data] += b["querylog_kb"] * 1024
    total = [sum(v[k] for v in share.values()) for k in (0, 1)]
    err = ""
    cache_min = CACHE_FIXED + b["cache_entries"] * CACHE_ENTRY
    if b["cache_kb"] * 1024 < cache_min:
        err = (f"cache: {b['cache_entries']} answers need at least {(cache_min + 1023) // 1024} KB, "
               f"memory.cache_kb is {b['cache_kb']}")
    for k, name in ((0, "internal RAM"), (1, "PSRAM")):
        if not err and total[k] > cap[k]:
            err = f"{name}: the services need {(total[k] + 1023) // 1024} KB, the board has {cap[k] // 1024} KB for them"
            break
    return {"capacity": cap, "total": total, "shares": share, "error": err}


def catalog(name):
    with open(os.path.join(BOARDS, name + ".json")) as f:
        return json.load(f)


def without_memory(b, hosted_kb):
    """A board partition written before the plan's keys: hosted_zones_kb only, as the
    production nodes' partitions have it."""
    b = dict(b)
    b["memory"] = {"hosted_zones_kb": hosted_kb}
    return b


ALL = SERVICES
p4, s3, xiao = catalog("p4-ip101"), catalog("ws-s3-eth"), catalog("xiao-s3-sense")
big = dict(p4, memory=dict(p4["memory"], blocklist_kb=30000))
idx = dict(p4, memory=dict(p4["memory"], blocklist_index_kb=1024))
cases = [
    ("p4-ip101 from the catalog, every service", p4, "esp32p4-rev1", 32768, ALL),
    ("p4-ip101 partition from before the plan's keys", without_memory(p4, 1024), "esp32p4-rev1", 32768, ALL),
    ("ws-s3-eth from the catalog, every service", s3, "esp32s3-octal", 8192, ALL),
    ("ws-s3-eth partition from before the plan's keys", without_memory(s3, 256), "esp32s3-octal", 8192, ALL),
    ("xiao-s3-sense from the catalog", xiao, "esp32s3-octal", 8192, ALL),
    ("ws-s3-eth with only the listeners", s3, "esp32s3-octal", 8192, ["dns"]),
    ("a P4 blocklist share too big for its PSRAM", big, "esp32p4-rev1", 32768, ALL),
    ("the same with blocking off", big, "esp32p4-rev1", 32768, ["dns", "forwarding", "secondary", "hosted"]),
    ("a P4 index share too big for its internal RAM", idx, "esp32p4-rev1", 32768, ALL),
    ("no board definition on an S3 with 8 MB", None, "esp32s3-octal", 8192, ALL),
    ("the board says PSRAM, the chip found none", p4, "esp32p4-rev1", 0, ALL),
    ("the controller: the chip unknown", s3, "esp32s3-octal", -1, ALL),
    ("a cache too small for its answers", dict(s3, memory=dict(s3["memory"], cache_kb=512)), "esp32s3-octal",
     8192, ["dns"]),
    ("an image without defaults", {"name": "x", "image": "esp32h2", "psram_mb": 0}, "esp32h2", -1, ["dns"]),
    ("ws-s3-eth with a query log too big for what its PSRAM has left",
     dict(s3, memory=dict(s3["memory"], querylog_kb=512)), "esp32s3-octal", 8192, ALL),
    ("the same with the query log off", dict(s3, memory=dict(s3["memory"], querylog_kb=512)), "esp32s3-octal", 8192,
     [s for s in ALL if s != "querylog"]),
    ("a board without PSRAM: no query log", {"name": "x", "image": "esp32c3", "psram_mb": 0}, "esp32c3", 0,
     ["dns", "querylog"]),
    ("a P4 with a bigger table of upstream queries", dict(p4, memory=dict(p4["memory"], fwd_pending=256)),
     "esp32p4-rev1", 32768, ALL),
]
out = []
for name, board, image, chip, services in cases:
    b = board_values(board, image, chip)
    p = plan(b, services)
    out.append({"name": name, "image": image, "chip_psram_kb": chip, "board": board, "services": services,
                "want": {"board": b, "fits": not p["error"], **p}})
print(json.dumps(out, indent=1))
