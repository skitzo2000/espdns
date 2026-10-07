"""Build and sign espDNS release manifests (format in main/release.h).

Needs the `cryptography` package, which the espressif/idf image already has.
"""
import hashlib
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

MAGIC = b"ESPDNS1\0"
KINDS = {"firmware": 1, "config": 2, "zones": 3, "blocklist": 4, "overrides": 5, "control": 6}
KEY_RELEASE, KEY_RECOVERY = 0, 1
ANY_NODE = b"\xff" * 6
MANIFEST_LEN, SIG_LEN = 128, 64


def parse_mac(s):
    b = bytes.fromhex(s.replace(":", "").replace("-", ""))
    if len(b) != 6:
        raise ValueError(f"bad node ID {s!r}")
    return b


def manifest(kind, key_id, target, board, seq, payload):
    board_b = board.encode()
    if len(board_b) > 15:
        raise ValueError("board name longer than 15 bytes")
    m = MAGIC + struct.pack("<BB", KINDS[kind], key_id) + target + board_b.ljust(16, b"\0")
    m += struct.pack("<QQ", seq, len(payload)) + hashlib.sha256(payload).digest()
    return m.ljust(MANIFEST_LEN, b"\0")


def sign(private_key, data):
    r, s = decode_dss_signature(private_key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def header(private_key, kind, key_id, target, board, seq, payload):
    m = manifest(kind, key_id, target, board, seq, payload)
    return m + sign(private_key, m)


# How far past the signer's clock a seq may go (main/release.h REL_SEQ_AHEAD_MS, the
# controller's release.SeqAhead): a seq far in the future leaves the node no seq above it
# for the releases after it (issue #55).
SEQ_AHEAD_MS = 24 * 3600 * 1000


def next_seq(last, now_ms=None):
    """Milliseconds since 1970, or last + 1 if that is not higher. Time-based so a
    rebuilt controller with an empty database still issues seqs the nodes accept.

    last comes from the node's /status, which anything on its address can send: one more
    than SEQ_AHEAD_MS past this clock (say near 2^64) is refused (ValueError), never
    signed above."""
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if not isinstance(last, int) or isinstance(last, bool) or last < 0:
        raise ValueError(f"the node's last seq {last!r} is not a seq")
    if last >= now + SEQ_AHEAD_MS:
        raise ValueError(f"the node's last seq {last} is more than {SEQ_AHEAD_MS // 3600000} h past this clock "
                         f"({now}): not signing above it (its /status is not the node's, or a clock is wrong)")
    return max(now, last + 1)


def load_private(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_raw(private_key):
    return private_key.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)


def fingerprint(pub_raw):
    return hashlib.sha256(pub_raw).hexdigest()[:16]
