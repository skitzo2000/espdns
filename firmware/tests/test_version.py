"""The firmware's version: version.cmake reads the repository's VERSION (MAJOR.MINOR.PATCH on
one line) for CMakeLists.txt, which makes it the app descriptor's version, and refuses anything
else. Run by `make test` (cmake: ESP-IDF's, on PATH once its export.sh has run, as the image's
entrypoint and CI's host-test job do)."""
import os
import subprocess
import tempfile
import unittest

FIRMWARE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SCRIPT = os.path.join(FIRMWARE, "version.cmake")


def read(text):
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "VERSION")
        if text is not None:
            with open(f, "w") as w:
                w.write(text)
        out = subprocess.run(["cmake", f"-DVERSION_FILE={f}", "-P", SCRIPT], capture_output=True, text=True)
        return out.returncode, out.stderr.strip()


class VersionTest(unittest.TestCase):
    def test_versions(self):
        for text, want in [("0.0.1\n", "0.0.1"), ("0.0.12\n", "0.0.12"), ("1.20.300\n", "1.20.300"),
                          ("999999999.999999999.999999999\n", "999999999.999999999.999999999")]:
            with self.subTest(text=text):
                self.assertEqual(read(text), (0, want))

    def test_refused(self):
        for text in [None, "", "0.0.1", "0.0.1\n\n", "v0.0.1\n", "0.01.1\n", "0.0\n", "0.0.1.2\n", "0.0.1-rc1\n",
                     "3fbae0a\n", " 0.0.1\n", "0.0.1\n0.0.2\n",
                     "0.0.1000000000\n", "4294967296.0.0\n"]:
            with self.subTest(text=text):
                code, err = read(text)
                self.assertNotEqual(code, 0, err)
                self.assertIn("VERSION", err)

    def test_repository_version(self):
        out = subprocess.run(["cmake", f"-DVERSION_FILE={os.path.join(FIRMWARE, '..', 'VERSION')}", "-P", SCRIPT],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_cmakelists_uses_it(self):
        with open(os.path.join(FIRMWARE, "CMakeLists.txt")) as f:
            cm = f.read()
        # Set before ESP-IDF's project.cmake, so the app descriptor takes it, not git describe
        use = cm.index('espdns_version("${CMAKE_CURRENT_LIST_DIR}/../VERSION" PROJECT_VER)')
        self.assertLess(use, cm.index("include($ENV{IDF_PATH}/tools/cmake/project.cmake)"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
