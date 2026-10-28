#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Tests of daily-sync.py with a fake GitHub release in a temp directory.

    python3 -I -m unittest discover -s ops/site -p 'test_*.py'

A throw-away Ed25519 key signs the list through scripts/sign-daily.sh (a copy
of the script in a temp tree with the throw-away public key, since the real
script insists on the key in the repository); the build comes out of
scripts/daily-assemble.py, so the whole chain publisher -> server is covered
without network access. Needs OpenSSL 3 (as sign-daily.sh does).
"""
import importlib.util
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("daily_sync", ROOT / "ops/site/daily-sync.py")
ds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ds)

PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 20
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def run(*cmd, env=None, cwd=None):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, env=env, cwd=cwd).stdout


class Publisher:
    """What the daily workflow does, in a temp dir: assemble, sign, and a fake API."""

    def __init__(self, tmp: pathlib.Path, build_id: str, key: pathlib.Path, pub_text: str, sign_script: pathlib.Path, payload: bytes = b"a"):
        art = tmp / f"art-{build_id}"
        for rel, data in {
            "packages-linux-windows/varsto-1-x86_64-unknown-linux-musl.tar.gz": b"linux" + payload,
            "packages-android/varsto-1-android-debug.apk": b"apk" + payload,
            "installer-windows/Varsto-1-setup.exe": b"exe" + payload,
            "Varsto-macos/dist/Varsto-1-macos.dmg": b"dmg" + payload,
            "Varsto-ios-unsigned/Varsto-1-ios-unsigned.ipa": b"ipa" + payload,
            "rendezvous-linux/varsto-rendezvous-linux-x86_64": b"rv" + payload,
            "screenshots/desktop-overview-light.png": PNG,
            "screenshots/shots.json": b"{}",
        }.items():
            f = art / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        self.dist = tmp / f"dist-{build_id}"
        run(sys.executable, "-I", str(ROOT / "scripts/daily-assemble.py"), "--art", str(art), "--out", str(self.dist),
            "--build-id", build_id, "--date", f"{build_id[:4]}-{build_id[4:6]}-{build_id[6:8]}", "--version", "0.0.1-test",
            "--commit", COMMIT, "--ci-run", "https://github.com/janttsu/varsto/actions/runs/1")
        env = {"VARSTO_DAILY_KEY": str(key), "PATH": "/usr/bin:/bin:/usr/local/bin"}
        run("bash", str(sign_script), "--build-id", build_id, str(self.dist / "SHA256SUMS"), env=env)
        self.pub_text = pub_text

    def fetch(self):
        files = {p.name: p for p in self.dist.iterdir()}

        def fetch(url, dest, limit):
            if url == "api":
                return json.dumps({"assets": [{"name": n, "size": p.stat().st_size} for n, p in files.items()]}).encode()
            name = url.rsplit("/", 1)[1]
            data = files[name].read_bytes()
            assert len(data) <= limit
            if dest is None:
                return data
            dest.write_bytes(data)
        return fetch


class DailySyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="daily-sync-test-"))
        for name in ("key", "other"):
            d = cls.tmp / name
            (d / "scripts").mkdir(parents=True)
            run("openssl", "genpkey", "-algorithm", "ed25519", "-out", str(d / "k.pem"))
            (d / "k.id").write_text(("a1b2c3d4e5f60718" if name == "key" else "1122334455667788") + "\n")
            shutil.copy(ROOT / "scripts/sign-daily.sh", d / "scripts/sign-daily.sh")
            env = {"VARSTO_DAILY_KEY": str(d / "k.pem"), "PATH": "/usr/bin:/bin:/usr/local/bin"}
            pub = run("bash", str(d / "scripts/sign-daily.sh"), "--public-key", env=env)
            (d / "daily-key.pub").write_text(pub)
            setattr(cls, name + "_dir", d)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def publisher(self, build_id, **kw):
        d = self.key_dir
        return Publisher(self.tmp, build_id, d / "k.pem", (d / "daily-key.pub").read_text(), d / "scripts/sign-daily.sh", **kw)

    def site(self):
        return pathlib.Path(tempfile.mkdtemp(prefix="site-", dir=self.tmp))

    def sync(self, site, pub, verifier=ds.ed25519_verify):
        return ds.sync(site, fetch=pub.fetch(), api="api", download="https://x/", pub_text=pub.pub_text,
                       verifier=verifier, log=lambda *_: None)

    def test_embedded_key_is_the_repository_key(self):
        self.assertEqual(ds.DAILY_PUBLIC_KEY.strip(), (ROOT / "daily-key.pub").read_text().strip())

    def test_verify_ok_and_layout(self):
        pub = self.publisher("20261016-316c579")
        site = self.site()
        self.assertEqual(self.sync(site, pub), "20261016-316c579")
        d = site / "daily"
        b = d / "builds/20261016-316c579"
        for name in ("SHA256SUMS", "SHA256SUMS.sig", "latest.json", "index.html", "shots/desktop-overview-light.png",
                     "varsto-daily-linux-x86_64.tar.gz", "varsto-daily-windows-setup.exe", "varsto-daily-screenshots.tar.gz"):
            self.assertTrue((b / name).is_file(), name)
        link = d / "latest/varsto-daily-android-debug.apk"
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(), (b / "varsto-daily-android-debug.apk").resolve())
        self.assertEqual((d / "latest/SHA256SUMS").read_bytes(), (b / "SHA256SUMS").read_bytes())
        self.assertTrue((d / "latest/SHA256SUMS.sig").is_file())
        latest = json.loads((d / "latest.json").read_text())
        self.assertEqual(latest["id"], "20261016-316c579")
        self.assertEqual(latest["version"], "0.0.1-test")
        self.assertEqual([h["id"] for h in latest["history"]], ["20261016-316c579"])
        self.assertEqual({p["key"] for p in latest["platforms"]}, {"linux-x86_64", "android", "windows-setup", "macos", "ios", "rendezvous-linux-x86_64", "screenshots"})
        # the local list still verifies with the same primitive
        ds.verify_list((d / "latest/SHA256SUMS").read_bytes(), (d / "latest/SHA256SUMS.sig").read_text(), pub.pub_text)
        # a second run finds nothing to do
        self.assertIsNone(self.sync(site, pub))

    def test_pure_python_verifier_agrees(self):
        pub = self.publisher("20261017-316c579")
        self.assertEqual(self.sync(self.site(), pub, verifier=ds._ed25519_pure), "20261017-316c579")
        sums = (pub.dist / "SHA256SUMS").read_bytes()
        sig = (pub.dist / "SHA256SUMS.sig").read_text()
        with self.assertRaises(ds.SyncError):
            ds.verify_list(sums + b"x", sig, pub.pub_text, ds._ed25519_pure)

    def test_bad_signature(self):
        pub = self.publisher("20261018-316c579")
        sums = pub.dist / "SHA256SUMS"
        sums.write_text(sums.read_text().replace("a", "b", 1) if "a" in sums.read_text() else sums.read_text() + "\n")
        site = self.site()
        with self.assertRaisesRegex(ds.SyncError, "BAD signature"):
            self.sync(site, pub)
        self.assertFalse((site / "daily/latest.json").exists())
        self.assertEqual(list((site / "daily/builds").iterdir()), [])

    def test_wrong_key(self):
        pub = self.publisher("20261019-316c579")
        pub.pub_text = (self.other_dir / "daily-key.pub").read_text()
        with self.assertRaisesRegex(ds.SyncError, "different key"):
            self.sync(self.site(), pub)

    def test_bad_sha(self):
        pub = self.publisher("20261020-316c579")
        (pub.dist / "varsto-daily-android-debug.apk").write_bytes(b"tampered")
        site = self.site()
        with self.assertRaisesRegex(ds.SyncError, "SHA-256 does not match"):
            self.sync(site, pub)
        self.assertFalse((site / "daily/latest.json").exists())
        self.assertEqual(list((site / "daily/builds").iterdir()), [])  # nothing half-installed

    def test_unsigned_extra_file_name_refused(self):
        pub = self.publisher("20261021-316c579")
        with self.assertRaises(ds.SyncError):
            ds.parse_sums("0" * 64 + "  ../evil\n")
        self.assertIn("varsto-daily-ios-unsigned.ipa", ds.parse_sums((pub.dist / "SHA256SUMS").read_text()))

    def test_prune_keeps_seven_and_never_touches_other_dirs(self):
        site = self.site()
        for d in ("downloads", "testbuilds"):
            (site / d).mkdir()
            (site / d / "keep.txt").write_text("x")
        (site / "index.html").write_text("page")
        builds = site / "daily/builds"
        for day in range(1, 9):
            (builds / f"202610{day:02d}-aaaaaaa").mkdir(parents=True)
        (builds / "not-a-build").mkdir()
        pub = self.publisher("20261030-316c579")
        self.assertEqual(self.sync(site, pub), "20261030-316c579")
        left = sorted(p.name for p in builds.iterdir())
        self.assertEqual(left, ["20261003-aaaaaaa", "20261004-aaaaaaa", "20261005-aaaaaaa", "20261006-aaaaaaa",
                                "20261007-aaaaaaa", "20261008-aaaaaaa", "20261030-316c579", "not-a-build"])
        self.assertTrue((site / "downloads/keep.txt").is_file() and (site / "testbuilds/keep.txt").is_file())
        self.assertEqual((site / "index.html").read_text(), "page")

    def test_rollback_refused(self):
        site = self.site()
        self.assertEqual(self.sync(site, self.publisher("20261105-316c579")), "20261105-316c579")
        with self.assertRaisesRegex(ds.SyncError, "rollback"):
            self.sync(site, self.publisher("20261101-316c579"))
        self.assertEqual(json.loads((site / "daily/latest.json").read_text())["id"], "20261105-316c579")

    def test_screenshots_only_plain_pngs(self):
        t = self.tmp / "s.tar.gz"
        with tarfile.open(t, "w:gz") as tf:
            for name, data in (("ok-shot.png", PNG), ("../evil.png", PNG), ("fake.png", b"nope"), ("Bad Name.png", PNG), ("note.txt", b"x")):
                i = tarfile.TarInfo(name)
                i.size = len(data)
                tf.addfile(i, io.BytesIO(data))
        out = self.tmp / "shots-out"
        shutil.rmtree(out, ignore_errors=True)
        self.assertEqual(ds.unpack_screenshots(t, out), 2)  # ok-shot.png and evil.png (plain name after stripping the path)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["evil.png", "ok-shot.png"])
        self.assertFalse((self.tmp / "evil.png").exists())


if __name__ == "__main__":
    unittest.main()
