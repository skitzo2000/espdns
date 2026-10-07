"""Post a blocklist and query names to a node's bench build (POST /bench) and print the
results. Run by `make bench-ota`; the node must be running a bench build.

    python3 tools/bench_post.py <host> <list.bin> <queries.txt> [max queries]
"""
import struct
import sys
import urllib.request


def main():
    host, lst, qs = sys.argv[1:4]
    nq = int(sys.argv[4]) if len(sys.argv) > 4 else 20000
    data = open(lst, "rb").read()
    queries = b"".join(open(qs, "rb").readlines()[:nq])
    body = struct.pack("<I", len(data)) + data + queries
    print(f"posting {len(data)} bytes of list and {queries.count(b'\n')} queries to {host}", flush=True)
    req = urllib.request.Request(f"http://{host}/bench", data=body, method="POST",
                                 headers={"Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            print(r.read().decode())
    except urllib.error.HTTPError as e:
        sys.exit(f"{e.code}: {e.read().decode()}")


if __name__ == "__main__":
    main()
