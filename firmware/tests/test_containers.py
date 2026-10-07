"""The firmware Makefile's containers: no key in any but the signing step, and no network
where none is needed (README.md, Builds and the release key).

Reads the docker commands `make -n` prints for each target (nothing is run, no docker
needed) and checks each container's mounts and network. Run by `make test`.
"""
import os
import re
import shlex
import subprocess
import unittest

FIRMWARE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SECRETS = "/project/secrets"

# A site's values never come in: no local.mk; documentation addresses (RFC 5737) only
ADDR = ["STATIC_IP=192.0.2.53", "STATIC_NETMASK=255.255.255.0", "STATIC_GATEWAY=192.0.2.1"]
TARGETS = {
    "build image": ["build", "IMAGE=esp32s3-octal"],
    "build board": ["build", "BOARD=ws-s3-eth", *ADDR],
    "images": ["images"],
    "export-images": ["export-images"],
    "factory": ["factory", "BOARD=ws-s3-eth", "ADDRESS=192.0.2.53/24", "GATEWAY=192.0.2.1"],
    "ota": ["ota", "HOST=192.0.2.53", "BOARD=ws-s3-eth", *ADDR],
    "bench-ota": ["bench-ota", "HOST=192.0.2.53", "BOARD=ws-s3-eth", "FILE=list.bin", "QUERIES=q.txt", *ADDR],
    "bench-board": ["bench-board", "IMAGE=esp32s3-octal", "FILE=list.bin", "QUERIES=q.txt"],
    "test": ["test"],
    "flash": ["flash", "IMAGE=esp32s3-octal"],
    "log": ["log"],
    "menuconfig": ["menuconfig", "IMAGE=esp32s3-octal"],
    "clean": ["clean", "IMAGE=esp32s3-octal"],
    "components": ["components"],
    "keys": ["-B", "keys/release.pub"],
}


def containers(args):
    """Each `docker run` make -n prints for these arguments: (its options, its command)."""
    env = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "NATIVE")}
    out = subprocess.run(["make", "-n", "-C", FIRMWARE, "FW_LOCAL_MK=/dev/null", "FLEET_DATA=/nonexistent",
                          *args], env=env, capture_output=True, text=True)
    if out.returncode:
        raise AssertionError(f"make -n {' '.join(args)}: {out.stderr}")
    runs = []
    for seg in re.split(r"\bdocker run ", out.stdout.replace("\\\n", " "))[1:]:
        seg = re.split(r" && |; |'|\n", seg)[0]
        words = shlex.split(seg)
        opts, i = [], 0
        while i < len(words) and words[i].startswith("-"):
            w = words[i]
            if w in ("-v", "--mount", "--network", "-u", "-e", "-w", "--device", "--group-add"):
                opts.append((w, words[i + 1]))
                i += 2
            else:
                opts.append((w, None))
                i += 1
        runs.append((opts, " ".join(words[i:])))
    return runs


def mounts(opts):
    """{destination: (kind, read-only)} of a container's mounts."""
    m = {}
    for o, v in opts:
        if o == "-v":
            parts = v.split(":")
            m[parts[1]] = ("bind", len(parts) > 2 and "ro" in parts[2].split(","))
        elif o == "--mount":
            f = dict(p.split("=", 1) if "=" in p else (p, "") for p in v.split(","))
            m[f["destination"]] = (f["type"], "readonly" in f or "ro" in f)
    return m


def network(opts):
    return next((v for o, v in opts if o == "--network"), "default")


class ContainersTest(unittest.TestCase):
    def all_runs(self):
        for name, args in TARGETS.items():
            runs = containers(args)
            self.assertTrue(runs, f"{name}: no docker run")
            for opts, cmd in runs:
                yield name, opts, cmd

    def test_only_signing_and_keygen_see_secrets(self):
        for name, opts, cmd in self.all_runs():
            m = mounts(opts)
            with self.subTest(target=name, cmd=cmd):
                if "ota_push.py sign" in cmd:
                    self.assertNotIn(SECRETS, m, "the signing step reads the key in the read-only source")
                    self.assertEqual(m["/project"], ("bind", True))
                elif "keygen.py" in cmd:
                    self.assertEqual(m[SECRETS], ("bind", False))
                else:
                    self.assertEqual(m.get(SECRETS), ("tmpfs", True), "secrets/ not covered")

    def test_source_read_only_but_for_the_lock_update(self):
        for name, opts, cmd in self.all_runs():
            m = mounts(opts)
            with self.subTest(target=name, cmd=cmd):
                self.assertEqual(m["/project"][1], name != "components", "/project read-only")
                if name != "components":
                    writable = sorted(d for d, (kind, ro) in m.items() if kind == "bind" and not ro)
                    allowed = re.compile(r"^/project/(build(/.*)?|dist|managed_components|tests|keys|secrets|bench/blocklist)$")
                    for d in writable:
                        self.assertRegex(d, allowed)
                    if "ota_push.py sign" in cmd:
                        self.assertEqual(len(writable), 1)
                        self.assertRegex(writable[0], r"^/project/build/.*/release$")

    def test_network_only_where_needed(self):
        for name, opts, cmd in self.all_runs():
            net = network(opts)
            with self.subTest(target=name, cmd=cmd):
                if re.search(r"ota_push\.py (prepare|push)", cmd):
                    self.assertEqual(net, "host")
                elif " reconfigure" in cmd:
                    self.assertEqual(net, "default", "fetches the components")
                else:
                    self.assertEqual(net, "none")

    def test_version_read_only_at_the_sources_parent(self):
        # CMakeLists.txt reads the repository's VERSION as ../VERSION from /project
        version = os.path.join(os.path.dirname(FIRMWARE), "VERSION")
        for name, opts, cmd in self.all_runs():
            with self.subTest(target=name, cmd=cmd):
                self.assertEqual(mounts(opts).get("/VERSION"), ("bind", True))
                self.assertIn(("-v", f"{FIRMWARE}/../VERSION:/VERSION:ro"), opts)
        self.assertTrue(os.path.isfile(version))

    def test_push_is_three_steps(self):
        cmds = [cmd for _, cmd in containers(TARGETS["ota"]) if "ota_push.py" in cmd]
        steps = [re.search(r"ota_push\.py (\w+)", c).group(1) for c in cmds]
        self.assertEqual(steps, ["prepare", "sign", "push"])
        for c in cmds:
            if "ota_push.py sign" not in c:
                self.assertNotIn("--key", c)
            else:
                # What it signs is its own argument, not something the networked step chose
                self.assertIn("--image build/ws-s3-eth/dns2.bin --image-name ", c)
                self.assertIn("--board ws-s3-eth", c)


if __name__ == "__main__":
    unittest.main(verbosity=1)
