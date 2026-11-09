#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""finalize.py must refuse a theme pair that has only one side.

    python3 -I ops/site/tests/test_finalize_pairs.py
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parents[3]
FINALIZE = ROOT / "scripts" / "screenshots" / "finalize.py"


def png(path, color):
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", (8, 8), color).save(path)


def run(src):
    dst = src / "out"
    proc = subprocess.run(
        [sys.executable, str(FINALIZE), str(src / "in"), str(dst)],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


class FinalizePairs(unittest.TestCase):
    def test_one_side_fails(self):
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d)
            png(src / "in" / "linux-app-light.png", (240, 240, 240))
            code, out = run(src)
            self.assertEqual(code, 1, out)
            self.assertIn("linux-app", out)

    def test_neither_side_is_kept(self):
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d)
            (src / "in").mkdir()
            code, out = run(src)
            self.assertEqual(code, 0, out)
            self.assertIn("kept as they are", out)
            self.assertNotIn("only one theme", out)

    def test_both_sides_pass(self):
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d)
            png(src / "in" / "linux-app-light.png", (240, 240, 240))
            png(src / "in" / "linux-app-dark.png", (30, 30, 40))
            code, out = run(src)
            self.assertEqual(code, 0, out)
            self.assertTrue((src / "out" / "linux-app-light.png").is_file())
            self.assertTrue((src / "out" / "linux-app-dark.png").is_file())


if __name__ == "__main__":
    unittest.main()
