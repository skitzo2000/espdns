"""tools/ota_push.py: a push in three steps (prepare, sign, push), the key read by sign alone.

Runs against a fake node on the loopback (its /status and POST /ota), no real node and no
other network. Run by `make test` (tests/Makefile) with the ESP-IDF image's Python, which
has the cryptography package.
"""
import contextlib
import hashlib
import hmac
import http.server
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import ota_push  # noqa: E402
import release  # noqa: E402

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

NODE_ID = "02:00:5e:00:53:01"
OLD_ELF, NEW_ELF = "aa" * 8, "bb" * 8


def read(path):
    with open(path, "rb") as f:
        return f.read()


def fake_image(elf_hex, size=4096):
    """An app image with just the app descriptor ota_push reads (esp_app_desc_t at 32)."""
    b = bytearray(size)
    struct.pack_into("<I", b, 32, 0xABCD5432)
    b[32 + 16:32 + 16 + 6] = b"v0.0.1"
    b[32 + 48:32 + 48 + 4] = b"dns2"
    b[32 + 144:32 + 152] = bytes.fromhex(elf_hex)
    return bytes(b)


class Node:
    """A node's /status and POST /ota: an upload makes it run the new build, confirmed."""

    def __init__(self, keys=None, image="esp32s3-octal", last_seq=1000):
        self.st = {"version": "v0.0.0", "elf_sha256": OLD_ELF, "slot": "ota_0", "ota_state": "valid",
                   "uptime_s": 100, "node_id": NODE_ID, "image": image,
                   "seq": {"firmware": last_seq}, "zones": []}
        if keys is not None:
            self.st["keys"] = keys
        self.uploads = []
        node = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = json.dumps(node.st).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                n = int(self.headers["Content-Length"])
                node.uploads.append(({k.lower(): v for k, v in self.headers.items()}, self.rfile.read(n)))
                node.st.update(elf_sha256=NEW_ELF, slot="ota_1", ota_state="valid")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.host = f"127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def run(*argv):
    """ota_push's main with these arguments: (exit message or None, what it printed)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            ota_push.main(list(argv))
        except SystemExit as e:
            return (str(e.code) if e.code else None), out.getvalue()
    return None, out.getvalue()


@contextlib.contextmanager
def no_network():
    """Any socket opened in the block fails the test: the signing step has no network."""
    real = socket.socket

    def refuse(*a, **k):
        raise AssertionError("the signing step opened a socket")
    socket.socket = refuse
    try:
        yield
    finally:
        socket.socket = real


class OtaPushTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.dir = os.path.join(d, "release")
        self.image = os.path.join(d, "dns2.bin")
        with open(self.image, "wb") as f:
            f.write(fake_image(NEW_ELF))
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pem = os.path.join(d, "release.pem")
        with open(self.pem, "wb") as f:
            f.write(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        self.fp = release.fingerprint(release.public_raw(self.key))
        # The DNS check is the node answering on port 53; the fake node answers by fiat
        self.dns_ok = ota_push.dns_ok
        ota_push.dns_ok = lambda host, name: True
        self.node = None

    def tearDown(self):
        ota_push.dns_ok = self.dns_ok
        if self.node:
            self.node.close()
        self.tmp.cleanup()

    def prepare(self, *extra):
        return run("prepare", "--dir", self.dir, "--host", self.node.host, "--image", self.image,
                   "--image-name", "esp32s3-octal", *extra)

    def sign(self, *extra, image=None, image_name="esp32s3-octal"):
        return run("sign", "--dir", self.dir, "--image", image or self.image, "--image-name", image_name, *extra)

    def tamper(self, **change):
        """The plan as a step with the network could rewrite it."""
        p = os.path.join(self.dir, ota_push.PLAN)
        plan = json.loads(read(p))
        plan.update(change)
        with open(p, "w") as f:
            json.dump(plan, f)

    def test_three_steps_push_a_signed_release(self):
        self.node = Node(keys=[self.fp, "00" * 8])
        err, _ = self.prepare()
        self.assertIsNone(err)
        self.assertFalse(self.node.uploads, "prepare uploads nothing")
        self.assertFalse(os.path.exists(os.path.join(self.dir, ota_push.RELEASE)), "prepare signs nothing")
        with no_network():
            err, out = self.sign("--key", self.pem)
        self.assertIsNone(err, out)
        self.assertFalse(self.node.uploads, "sign uploads nothing")
        err, out = run("push", "--dir", self.dir, "--wait", "10")
        self.assertIsNone(err, out)
        self.assertIn("done: running", out)
        self.assertEqual(len(self.node.uploads), 1)
        headers, body = self.node.uploads[0]
        self.assertEqual(headers["content-type"], "application/octet-stream")
        image = read(self.image)
        m, sig, payload = body[:128], body[128:192], body[192:]
        self.assertEqual(payload, image)
        self.assertEqual(m[:8], release.MAGIC)
        self.assertEqual(m[8], release.KINDS["firmware"])
        self.assertEqual(m[9], release.KEY_RELEASE)
        self.assertEqual(m[10:16], release.parse_mac(NODE_ID))
        self.assertEqual(m[16:32].rstrip(b"\0"), b"esp32s3-octal")
        seq, length = struct.unpack_from("<QQ", m, 32)
        self.assertGreater(seq, 1000)
        self.assertEqual(length, len(image))
        self.assertEqual(m[48:80], hashlib.sha256(image).digest())
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        self.key.public_key().verify(encode_dss_signature(r, s), m, ec.ECDSA(hashes.SHA256()))
        # The signed release was for that one push: none is left to send again
        self.assertFalse(os.path.exists(os.path.join(self.dir, ota_push.RELEASE)))

    def test_only_sign_takes_a_key(self):
        self.node = Node(keys=[self.fp, "00" * 8])
        for step in (["prepare", "--host", self.node.host, "--image", self.image, "--image-name", "x"],
                     ["push"]):
            with contextlib.redirect_stderr(io.StringIO()):
                err, _ = run(*step, "--dir", self.dir, "--key", self.pem)
            self.assertIsNotNone(err, f"{step[0]} took --key")

    def test_sign_refuses_an_image_changed_since_prepare(self):
        self.node = Node(keys=[self.fp, "00" * 8])
        self.assertIsNone(self.prepare()[0])
        with open(self.image, "r+b") as f:
            f.seek(1000)
            f.write(b"changed")
        err, _ = self.sign("--key", self.pem)
        self.assertIn("changed since it was checked", err)
        self.assertFalse(os.path.exists(os.path.join(self.dir, ota_push.RELEASE)))

    def test_sign_refuses_a_key_the_node_does_not_trust(self):
        self.node = Node(keys=["11" * 8, "00" * 8])
        self.assertIsNone(self.prepare()[0])
        err, _ = self.sign("--key", self.pem)
        self.assertIn("is not the key this board trusts", err)
        err, _ = run("push", "--dir", self.dir)
        self.assertIn("no signed release", err)
        self.assertFalse(self.node.uploads)

    def test_already_running_needs_no_release(self):
        self.node = Node(keys=[self.fp, "00" * 8])
        self.node.st["elf_sha256"] = NEW_ELF
        err, out = self.prepare()
        self.assertIsNone(err)
        self.assertIn("already running", out)
        self.assertEqual(self.sign("--key", "/nonexistent")[1].strip(), "nothing to sign")
        self.assertEqual(run("push", "--dir", self.dir)[1].strip(), "nothing to push")
        self.assertFalse(self.node.uploads)

    def test_a_new_prepare_drops_an_old_release(self):
        self.node = Node(keys=[self.fp, "00" * 8])
        self.assertIsNone(self.prepare()[0])
        self.assertIsNone(self.sign("--key", self.pem)[0])
        self.node.st["elf_sha256"] = NEW_ELF
        self.assertIsNone(self.prepare()[0])
        self.assertEqual(sorted(os.listdir(self.dir)), [])

    def test_wrong_chip_image_is_refused_before_signing(self):
        self.node = Node(keys=[self.fp, "00" * 8], image="esp32p4-rev1")
        err, _ = self.prepare()
        self.assertIn("node runs chip image esp32p4-rev1", err)
        self.assertEqual(self.sign("--key", self.pem)[1].strip(), "nothing to sign")

    def test_sign_signs_its_own_image_not_the_plans(self):
        # A plan naming another image (and its hash) gets that image refused: sign reads
        # only the --image it is given, and that one is not what the plan was made for
        self.node = Node(keys=[self.fp, "00" * 8])
        self.assertIsNone(self.prepare()[0])
        evil = os.path.join(self.dir, "evil.bin")
        with open(evil, "wb") as f:
            f.write(fake_image("cc" * 8))
        self.tamper(image=evil, image_sha256=hashlib.sha256(read(evil)).hexdigest())
        err, _ = self.sign("--key", self.pem)
        self.assertIn("changed since it was checked", err)
        self.assertFalse(os.path.exists(os.path.join(self.dir, ota_push.RELEASE)))

    def test_sign_refuses_a_plan_for_another_name(self):
        self.node = Node(keys=[self.fp, "00" * 8])
        self.assertIsNone(self.prepare()[0])
        self.tamper(name="esp32p4-rev1")
        err, _ = self.sign("--key", self.pem)
        self.assertIn("the plan names 'esp32p4-rev1'", err)
        self.assertFalse(os.path.exists(os.path.join(self.dir, ota_push.RELEASE)))

    def test_a_transitional_image_may_be_signed_for_its_board(self):
        self.node = Node(keys=[self.fp, "00" * 8])
        del self.node.st["image"]
        self.node.st["board"] = "ws-s3-eth"
        self.assertIsNone(self.prepare("--board", "ws-s3-eth")[0])
        self.assertIn("the plan names 'ws-s3-eth'", self.sign("--key", self.pem)[0])
        err, out = self.sign("--key", self.pem, "--board", "ws-s3-eth")
        self.assertIsNone(err, out)
        m = read(os.path.join(self.dir, ota_push.RELEASE))[:128]
        self.assertEqual(m[16:32].rstrip(b"\0"), b"ws-s3-eth")

    def test_the_key_is_signs_choice_not_the_plans(self):
        # The plan can't ask for the recovery key: sign uses the release key's slot unless
        # it was given --recovery itself
        self.node = Node(keys=["11" * 8, self.fp])
        self.assertIsNone(self.prepare()[0])
        self.tamper(key_id=release.KEY_RECOVERY, trusted=self.fp, recovery=True)
        err, _ = self.sign("--key", self.pem)
        self.assertIn("not the key this board trusts in slot 0", err)
        err, out = self.sign("--key", self.pem, "--recovery")
        self.assertIsNone(err, out)
        self.assertEqual(read(os.path.join(self.dir, ota_push.RELEASE))[9], release.KEY_RECOVERY)

    def test_a_last_seq_far_ahead_is_never_signed_above(self):
        # Issue #55: a /status (anything on the node's address can send one) or a plan
        # rewritten by a step with the network, with a last seq near 2^64, would have had
        # sign issue the last seq there is, and the node refuse every firmware after it
        self.node = Node(keys=[self.fp, "00" * 8], last_seq=2**64 - 2)
        self.assertIsNone(self.prepare()[0])
        err, _ = self.sign("--key", self.pem)
        self.assertIn("past this clock", err)
        self.assertFalse(os.path.exists(os.path.join(self.dir, ota_push.RELEASE)))
        self.node.close()
        self.node = Node(keys=[self.fp, "00" * 8])
        for last in (2**64 - 2, 2**62, int(time.time() * 1000) + release.SEQ_AHEAD_MS + 60000, -1, "1"):
            self.assertIsNone(self.prepare()[0])
            self.tamper(last_seq=last)
            err, _ = self.sign("--key", self.pem)
            self.assertIn("refused", err or "", last)
            self.assertFalse(os.path.exists(os.path.join(self.dir, ota_push.RELEASE)), last)
        # A node a little ahead (a signer's clock that ran fast): one above it
        ahead = int(time.time() * 1000) + 3600 * 1000
        self.assertIsNone(self.prepare()[0])
        self.tamper(last_seq=ahead)
        self.assertIsNone(self.sign("--key", self.pem)[0])
        m = read(os.path.join(self.dir, ota_push.RELEASE))[:128]
        self.assertEqual(struct.unpack_from("<Q", m, 32)[0], ahead + 1)

    def test_next_seq(self):
        now = 1_800_000_000_000
        self.assertEqual(release.next_seq(0, now), now)
        self.assertEqual(release.next_seq(now, now), now + 1)
        self.assertEqual(release.next_seq(now + release.SEQ_AHEAD_MS - 1, now), now + release.SEQ_AHEAD_MS)
        for last in (now + release.SEQ_AHEAD_MS, 2**64 - 1, 2**64, -5, None, True, 1.5):
            with self.assertRaises(ValueError, msg=repr(last)):
                release.next_seq(last, now)

    def test_legacy_node_gets_the_hmac(self):
        self.node = Node(keys=None)
        legacy = os.path.join(self.tmp.name, "ota.key")
        with open(legacy, "wb") as f:
            f.write(b"k" * 32)
        self.assertIsNone(self.prepare()[0])
        with no_network():
            self.assertIsNone(self.sign("--legacy-key", legacy)[0])
        err, out = run("push", "--dir", self.dir, "--wait", "10")
        self.assertIsNone(err, out)
        headers, body = self.node.uploads[0]
        image = read(self.image)
        self.assertEqual(body, image)
        self.assertEqual(headers["x-ota-hmac"], hmac.new(b"k" * 32, image, hashlib.sha256).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=1)
