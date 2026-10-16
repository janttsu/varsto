#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Dry run of ops/site/screenshots-sync.py against a generated fixture tarball
and a fixture site in a temp directory (no network, no server):

    python3 -I ops/site/tests/test_screenshots_sync.py

The tarball has the layout CI packs (en/ fi/ sv/ viz/ and shots.json) plus
members the script must refuse: path tricks, wrong names, wrong bytes, a file
in an unknown directory, a second file in viz/."""
import hashlib
import io
import json
import pathlib
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zlib

HERE = pathlib.Path(__file__).resolve().parent
SYNC = HERE.parent / "screenshots-sync.py"


def png(w, h, shade=0):
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + bytes([shade]) * (w * 3) for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def add(t, name, b):
    ti = tarfile.TarInfo(name)
    ti.size = len(b)
    t.addfile(ti, io.BytesIO(b))


def make_tarball(path, shade=0):
    meta = {"version": "9.9.9-test", "commit": "0123456789abcdef", "date": "2026-01-02",
            "source": "GitHub Actions run 7", "run": "7",
            "sizes": {"en": {"desktop-overview-light": [64, 40], "android-light": [30, 60]},
                      "fi": {"desktop-overview-light": [64, 41]},
                      "sv": {"desktop-overview-light": [64, 42]},
                      "viz": {"viz-tv": [96, 54]}}}
    members = {
        "./en/desktop-overview-light.png": png(64, 40, shade),
        "./en/android-light.png": png(30, 60, shade),
        "./fi/desktop-overview-light.png": png(64, 41, shade),
        "./sv/desktop-overview-light.png": png(64, 42, shade),
        "./viz/viz-tv.png": png(96, 54, shade),
        "./shots.json": json.dumps(meta).encode(),
        # all of these must be refused
        "../evil.png": png(1, 1),
        "en/../../evil2.png": png(1, 1),
        "en/Bad Name.png": png(1, 1),
        "en/fake.png": b"not a png",
        "en/script.js": b"alert(1)",
        "xx/desktop-overview-light.png": png(1, 1),
        "viz/other.png": png(1, 1),
        "en/sub/deep.png": png(1, 1),
    }
    with tarfile.open(path, "w:gz") as t:
        for name, b in members.items():
            add(t, name, b)
        link = tarfile.TarInfo("en/link.png")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        t.addfile(link)


PAGE = ('<p class="lead"><span class="shots-meta">old caption</span></p>\n'
        '<img src="{p}assets/img/{d}/desktop-overview-light.png?v=0000000000" alt="a" width="1" height="1">\n'
        '<img src="{p}assets/img/screenshots/android-light.png" alt="b" width="1" height="1" loading="lazy">\n'
        '<img src="{p}assets/img/viz-tv.png?v=abc" alt="c" width="1" height="1">\n')


def run(site, tar, state):
    return subprocess.run([sys.executable, "-I", str(SYNC), str(site), "--from", str(tar), "--state", str(state)],
                          check=True, capture_output=True, text=True).stdout


class SyncTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.site = self.root / "site"
        for lang, d in (("", "screenshots"), ("fi", "screenshots-fi"), ("sv", "screenshots-sv"), ("fr", "screenshots")):
            page = self.site / lang / "screenshots/index.html"
            page.parent.mkdir(parents=True)
            page.write_text(PAGE.format(p="../" * (2 if lang else 1), d=d))
        self.tar = self.root / "screenshots.tar.gz"
        self.state = self.root / "state.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_layout_sizes_captions_and_refusals(self):
        make_tarball(self.tar)
        out = run(self.site, self.tar, self.state)
        self.assertIn("5 files", out)
        img = self.site / "assets/img"
        self.assertEqual(sorted(p.name for p in (img / "screenshots").iterdir()), ["android-light.png", "desktop-overview-light.png"])
        self.assertEqual([p.name for p in (img / "screenshots-fi").iterdir()], ["desktop-overview-light.png"])
        self.assertEqual([p.name for p in (img / "screenshots-sv").iterdir()], ["desktop-overview-light.png"])
        self.assertTrue((img / "viz-tv.png").exists())
        self.assertFalse((img / "other.png").exists())
        # nothing escaped the site, no temp files are left
        self.assertFalse((self.root / "evil.png").exists() or (self.root / "evil2.png").exists() or (self.site / "evil2.png").exists())
        self.assertEqual(list(self.site.rglob(".*.tmp")), [])
        en = (self.site / "screenshots/index.html").read_text()
        h = hashlib.sha256((img / "screenshots/desktop-overview-light.png").read_bytes()).hexdigest()[:10]
        self.assertIn(f'desktop-overview-light.png?v={h}" alt="a" width="64" height="40"', en)
        self.assertIn("android-light.png?v=", en)
        self.assertIn('alt="b" width="30" height="60"', en)
        self.assertIn("viz-tv.png?v=", en)
        self.assertIn('alt="c" width="96" height="54"', en)
        self.assertIn("Captured automatically from version 9.9.9-test (commit 0123456) on 2026-01-02, GitHub Actions run 7.", en)
        fi = (self.site / "fi/screenshots/index.html").read_text()
        self.assertIn("screenshots-fi/desktop-overview-light.png?v=", fi)
        self.assertIn('alt="a" width="64" height="41"', fi)
        self.assertIn('alt="b" width="30" height="60"', fi)  # shared native shot, English set
        self.assertIn("Kuvattu automaattisesti versiosta 9.9.9-test (commit 0123456) 2026-01-02, GitHub Actions -ajo 7.", fi)
        sv = (self.site / "sv/screenshots/index.html").read_text()
        self.assertIn('alt="a" width="64" height="42"', sv)
        fr = (self.site / "fr/screenshots/index.html").read_text()
        self.assertIn('alt="a" width="64" height="40"', fr)
        self.assertIn("exécution GitHub Actions 7", fr)

    def test_deploy_restores_page_and_new_run_replaces_pictures(self):
        make_tarball(self.tar)
        run(self.site, self.tar, self.state)
        # a deploy puts the repository's page back; the next run corrects it
        page = self.site / "screenshots/index.html"
        page.write_text(PAGE.format(p="../", d="screenshots"))
        make_tarball(self.tar, shade=200)
        run(self.site, self.tar, self.state)
        self.assertIn('alt="a" width="64" height="40"', page.read_text())
        self.assertEqual((self.site / "assets/img/viz-tv.png").read_bytes(), png(96, 54, 200))

    def test_old_flat_tarball_is_the_english_set(self):
        meta = {"version": "1.0", "date": "2026-02-03", "sizes": {"android-light": [30, 60]}}
        with tarfile.open(self.tar, "w:gz") as t:
            add(t, "android-light.png", png(30, 60))
            add(t, "shots.json", json.dumps(meta).encode())
        run(self.site, self.tar, self.state)
        self.assertTrue((self.site / "assets/img/screenshots/android-light.png").exists())
        self.assertIn('alt="b" width="30" height="60"', (self.site / "screenshots/index.html").read_text())


if __name__ == "__main__":
    unittest.main()
