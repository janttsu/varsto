#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Pull the newest daily build from GitHub into <site>/daily/.

Runs on the web server from cron (see ops/site/README.md). The daily workflow
(.github/workflows/daily.yml) publishes every build as the assets of the
rolling GitHub pre-release "daily": the varsto-daily-* files, SHA256SUMS, its
signature SHA256SUMS.sig (daily key) and latest.json. This script

  1. reads the pre-release metadata from the public GitHub API,
  2. downloads SHA256SUMS and SHA256SUMS.sig and VERIFIES the signature with
     the embedded daily public key before anything else is trusted (Ed25519
     over the BLAKE2b-512 hash of the list plus a signed trusted comment that
     must say channel:daily and name the build; the same format
     scripts/sign-daily.sh writes and `varsto update --daily` checks),
  3. skips the build when it is already present,
  4. downloads the other files, checks every size and SHA-256 against the
     signed list, unpacks the screenshots,
  5. writes daily/builds/<id>/ (files, SHA256SUMS, .sig, latest.json, index.html,
     shots/), repoints daily/latest/*, writes daily/latest/SHA256SUMS(.sig) and
     daily/latest.json, and prunes to the newest 7 builds.

It never touches downloads/, testbuilds/ or the site pages, never runs a
shell, only writes below <site>/daily/, and only publishes names matching
varsto-daily-[A-Za-z0-9._-]+. Anything that does not verify leaves the
published state as it was. The server only reads from GitHub.

Ed25519: the `cryptography` package is used when it can be imported (the
server's Python usually has it); otherwise a small pure-Python RFC 8032
verifier below (about 0.2 s per signature, enough for two per run).

    daily-sync.py <site root>          (e.g. ~/sites/varsto/public)
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import html
import json
import os
import pathlib
import re
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.request

REPO = "janttsu/varsto"
API = f"https://api.github.com/repos/{REPO}/releases/tags/daily"
DOWNLOAD = f"https://github.com/{REPO}/releases/download/daily/"
KEEP = 7
MAX_API = 1 << 20
MAX_FILE = 300 << 20          # per asset
MAX_TOTAL = 1 << 30           # per build
MAX_SHOT = 8 << 20
MAX_SHOTS = 80

# The daily public key (minisign format), the same as /daily-key.pub and the
# one built into `varsto update --daily`. Key id 4385DC16C115A671.
DAILY_PUBLIC_KEY = """untrusted comment: minisign public key 4385DC16C115A671
RWRxphXBFtyFQ0aTGjjipZHeP6fEyWAyyL37i2jpj2IErmxOnefFd5e/
"""

BUILD_ID = re.compile(r"^[0-9]{8}-[0-9a-f]{7,40}$")
ASSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DAILY_FILE = re.compile(r"^varsto-daily-[A-Za-z0-9._-]{1,100}$")
SUMS_LINE = re.compile(r"^([0-9a-f]{64})  (varsto-daily-[A-Za-z0-9._-]{1,100})$")
SHOT_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}\.png$")
SCREENSHOTS = "varsto-daily-screenshots.tar.gz"
CONTROL = ("SHA256SUMS", "SHA256SUMS.sig", "latest.json")


class SyncError(Exception):
    pass


# ----- Ed25519 (RFC 8032) --------------------------------------------------------

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if (x & 1) != sign else x


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def _add(a, b):
    A, B = (a[1] - a[0]) * (b[1] - b[0]) % _P, (a[1] + a[0]) * (b[1] + b[0]) % _P
    C, D = 2 * a[3] * b[3] * _D % _P, 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s: int, pt):
    r = (0, 1, 1, 0)
    while s:
        if s & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        s >>= 1
    return r


def _decode_point(b: bytes):
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _eq(a, b) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _ed25519_pure(pk: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pk) != 32 or len(sig) != 64:
        return False
    a, r = _decode_point(pk), _decode_point(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % _Q
    return _eq(_mul(s, _G), _add(r, _mul(h, a)))


def ed25519_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return _ed25519_pure(pk, msg, sig)
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_list(data: bytes, sig_text: str, pub_text: str = DAILY_PUBLIC_KEY, verifier=ed25519_verify) -> dict:
    """Check a minisign-format (prehashed, "ED") signature with a trusted comment
    that names the daily channel; returns the trusted comment's fields."""
    try:
        pub = base64.b64decode(pub_text.strip().split("\n")[1], validate=True)
        lines = sig_text.split("\n")
        sig = base64.b64decode(lines[1], validate=True)
        gsig = base64.b64decode(lines[3], validate=True)
    except (IndexError, ValueError):
        raise SyncError("malformed signature file") from None
    if len(pub) != 42 or pub[:2] != b"Ed" or len(sig) != 74 or sig[:2] != b"ED" or len(gsig) != 64:
        raise SyncError("not a prehashed minisign signature")
    if sig[2:10] != pub[2:10]:
        raise SyncError("signed with a different key than the daily key")
    if not lines[2].startswith("trusted comment: "):
        raise SyncError("no trusted comment")
    trusted = lines[2][len("trusted comment: "):]
    if not verifier(pub[10:], hashlib.blake2b(data).digest(), sig[10:]):
        raise SyncError("BAD signature on SHA256SUMS")
    if not verifier(pub[10:], sig[10:] + trusted.encode(), gsig):
        raise SyncError("BAD signature on the trusted comment")
    fields = dict(f.split(":", 1) for f in trusted.split("\t") if ":" in f)
    if fields.get("channel") != "daily" or fields.get("file") != "SHA256SUMS":
        raise SyncError("the signature is not for the daily list")
    if not BUILD_ID.match(fields.get("build", "")):
        raise SyncError("the signature names no valid build")
    return fields


# ----- fetching ------------------------------------------------------------------

def http_fetch(url: str, dest: pathlib.Path | None, limit: int) -> bytes | None:
    """GET url. Into memory (dest None) or streamed to dest; never more than
    limit bytes. Returns the bytes, or None when streamed. 404 raises FileNotFoundError."""
    req = urllib.request.Request(url, headers={"User-Agent": "varsto-daily-sync", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            if dest is None:
                data = r.read(limit + 1)
                if len(data) > limit:
                    raise SyncError(f"{url}: larger than {limit} bytes")
                return data
            n = 0
            with dest.open("wb") as f:
                while chunk := r.read(1 << 20):
                    n += len(chunk)
                    if n > limit:
                        raise SyncError(f"{url}: larger than {limit} bytes")
                    f.write(chunk)
            return None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise FileNotFoundError(url) from None
        raise


# ----- helpers -------------------------------------------------------------------

def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(p: pathlib.Path, data: bytes) -> None:
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o644)
    tmp.replace(p)


def atomic_symlink(target: str, link: pathlib.Path) -> None:
    tmp = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()
    tmp.symlink_to(target)
    tmp.replace(link)


def parse_sums(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = SUMS_LINE.match(line)
        if not m or m.group(2) in out:
            raise SyncError(f"SHA256SUMS has a line that is not a plain daily file entry: {line[:80]!r}")
        out[m.group(2)] = m.group(1)
    if not out:
        raise SyncError("SHA256SUMS is empty")
    return out


def clean_meta(raw: dict, build_id: str, files: dict[str, tuple[str, int]]) -> dict:
    """latest.json rebuilt from checked values only: the id comes from the
    signature, sizes and sums from the downloaded files; free text is validated."""
    def pick(key, pattern, default=""):
        v = raw.get(key)
        return v if isinstance(v, str) and re.fullmatch(pattern, v) else default
    keys = {}
    for p in raw.get("platforms") or []:
        if isinstance(p, dict) and isinstance(p.get("file"), str) and isinstance(p.get("key"), str) \
                and re.fullmatch(r"[a-z0-9-]{1,32}", p["key"]):
            keys[p["file"]] = p["key"]
    commit = pick("commit", r"[0-9a-f]{7,40}")
    return {
        "schema": 1, "channel": "daily", "id": build_id,
        "date": pick("date", r"\d{4}-\d{2}-\d{2}"),
        "version": pick("version", r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,39}"),
        "commit": commit,
        "ci_run": pick("ci_run", r"https://github\.com/janttsu/varsto/actions/runs/[0-9]+"),
        "platforms": [
            {"key": keys.get(name, name.removeprefix("varsto-daily-").split(".")[0]), "file": name,
             "size": size, "sha256": digest, "commit": commit}
            for name, (digest, size) in sorted(files.items())
        ],
    }


def unpack_screenshots(tarball: pathlib.Path, dest: pathlib.Path) -> int:
    """Only PNG files with plain names, bounded in size and number."""
    dest.mkdir()
    n = 0
    with tarfile.open(tarball, "r:gz") as t:
        for m in t.getmembers():
            name = pathlib.PurePosixPath(m.name).name
            if not m.isfile() or m.size > MAX_SHOT or not SHOT_NAME.match(name) or n >= MAX_SHOTS:
                continue
            f = t.extractfile(m)
            b = f.read(MAX_SHOT + 1) if f else b""
            if len(b) > MAX_SHOT or not b.startswith(b"\x89PNG\r\n\x1a\n"):
                continue
            (dest / name).write_bytes(b)
            n += 1
    return n


def index_page(meta: dict, shots: list[str]) -> str:
    e = html.escape
    rows = "".join(f'<li><a href="{e(p["file"])}">{e(p["file"])}</a> ({p["size"]} bytes)</li>\n' for p in meta["platforms"])
    pics = "".join(f'<a href="shots/{e(s)}">{e(s)}</a> ' for s in shots)
    return (
        '<!doctype html><meta charset=utf-8><meta name=robots content="noindex">'
        f'<title>Varsto daily build {e(meta["id"])}</title>'
        f'<h1>Varsto daily build {e(meta["id"])}</h1>'
        '<p>Development build, not a release. See <a href="../../">the daily builds page</a>. '
        'The list is signed with the daily key (SHA256SUMS.sig).</p>'
        f'<ul>{rows}<li><a href="SHA256SUMS">SHA256SUMS</a> '
        '(<a href="SHA256SUMS.sig">signature</a>) · <a href="latest.json">latest.json</a></ul>\n'
        + (f'<p>Screenshots: {pics}</p>\n' if shots else "")
    )


# ----- the sync ------------------------------------------------------------------

def sync(site: pathlib.Path, fetch=http_fetch, api: str = API, download: str = DOWNLOAD,
         verifier=ed25519_verify, pub_text: str = DAILY_PUBLIC_KEY, log=print) -> str | None:
    """Returns the id of the build that was installed, None when nothing changed."""
    daily = site / "daily"
    builds, latest = daily / "builds", daily / "latest"
    for d in (builds, latest):
        d.mkdir(parents=True, exist_ok=True)
    with (daily / ".sync.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # BlockingIOError: another run is active
        return _sync(daily, fetch, api, download, verifier, pub_text, log)


def _sync(daily: pathlib.Path, fetch, api: str, download: str, verifier, pub_text: str, log) -> str | None:
    builds, latest = daily / "builds", daily / "latest"
    for stale in builds.glob(".incoming-*"):  # a run that died
        if time.time() - stale.stat().st_mtime > 3600:
            shutil.rmtree(stale, ignore_errors=True)

    try:
        release = json.loads(fetch(api, None, MAX_API))
    except FileNotFoundError:
        log("no daily pre-release yet")
        return None
    assets = {}
    for a in release.get("assets") or []:
        name, size = a.get("name"), a.get("size")
        if isinstance(name, str) and ASSET.match(name) and (name in CONTROL or DAILY_FILE.match(name)) \
                and isinstance(size, int) and 0 < size <= MAX_FILE:
            assets[name] = size
    if any(c not in assets for c in CONTROL):
        raise SyncError("the daily pre-release lacks SHA256SUMS, SHA256SUMS.sig or latest.json (still being published?)")

    work = builds / f".incoming-{os.getpid()}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    try:
        for name in CONTROL:
            fetch(download + name, work / name, 1 << 20)
        sums_bytes = (work / "SHA256SUMS").read_bytes()
        fields = verify_list(sums_bytes, (work / "SHA256SUMS.sig").read_text(), pub_text, verifier)
        build_id = fields["build"]
        log(f"signature ok: build {build_id}")

        newest = max((p.name for p in builds.iterdir() if BUILD_ID.match(p.name)), default="")
        current_ok = (builds / build_id / "SHA256SUMS.sig").is_file()
        if not current_ok and newest and build_id[:8] < newest[:8]:
            raise SyncError(f"build {build_id} is older than the newest present ({newest}); refusing (a rollback?)")

        if not current_ok:
            sums = parse_sums(sums_bytes.decode())
            missing = [n for n in sums if n not in assets]
            if missing:
                raise SyncError(f"signed list names files the pre-release does not have: {missing}")
            if sum(assets[n] for n in sums) > MAX_TOTAL:
                raise SyncError("build too large")
            files: dict[str, tuple[str, int]] = {}
            for name, digest in sums.items():
                fetch(download + name, work / name, MAX_FILE)
                if sha256_file(work / name) != digest:
                    raise SyncError(f"{name}: SHA-256 does not match the signed list")
                files[name] = (digest, (work / name).stat().st_size)
            try:
                raw = json.loads((work / "latest.json").read_text())
            except ValueError:
                raw = {}
            meta = clean_meta(raw if isinstance(raw, dict) else {}, build_id, files)
            shots = []
            if SCREENSHOTS in files:
                unpack_screenshots(work / SCREENSHOTS, work / "shots")
                shots = sorted(p.name for p in (work / "shots").iterdir())
            (work / "latest.json").write_text(json.dumps(meta, indent=2) + "\n")
            (work / "index.html").write_text(index_page(meta, shots))
            for p in work.rglob("*"):
                os.chmod(p, 0o755 if p.is_dir() else 0o644)
            os.chmod(work, 0o755)
            old = builds / build_id
            if old.exists():  # an incomplete earlier attempt
                shutil.move(old, builds / f".incoming-old-{os.getpid()}")
            work.rename(old)
            shutil.rmtree(builds / f".incoming-old-{os.getpid()}", ignore_errors=True)
            log(f"installed builds/{build_id}: {len(files)} files, {len(shots)} screenshots")
        else:
            shutil.rmtree(work, ignore_errors=True)
            log(f"build {build_id} is already present")
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise

    bdir = builds / build_id
    meta = json.loads((bdir / "latest.json").read_text())
    try:
        served = json.loads((daily / "latest.json").read_text()).get("id")
    except (OSError, ValueError):
        served = None
    changed = served != build_id
    if changed:
        names = [p["file"] for p in meta["platforms"]]
        for name in names:
            atomic_symlink(f"../builds/{build_id}/{name}", latest / name)
        atomic_write(latest / "SHA256SUMS", (bdir / "SHA256SUMS").read_bytes())
        atomic_write(latest / "SHA256SUMS.sig", (bdir / "SHA256SUMS.sig").read_bytes())
        for p in latest.iterdir():  # names of an older build that are gone now
            if p.name not in names and p.name not in ("SHA256SUMS", "SHA256SUMS.sig") and not p.name.startswith("."):
                p.unlink()
        # Prune, newest build ids first; the served one is never removed.
        ids = sorted((p.name for p in builds.iterdir() if BUILD_ID.match(p.name) and p.is_dir()), reverse=True)
        for old in ids[KEEP:]:
            if old != build_id:
                shutil.rmtree(builds / old)
                log(f"pruned builds/{old}")
        history = []
        for i in sorted((p.name for p in builds.iterdir() if BUILD_ID.match(p.name) and p.is_dir()), reverse=True):
            try:
                date = json.loads((builds / i / "latest.json").read_text()).get("date", "")
            except (OSError, ValueError):
                date = ""
            history.append({"id": i, "date": date})
        atomic_write(daily / "latest.json", (json.dumps({**meta, "history": history}, indent=2) + "\n").encode())
        log(f"daily/latest is now {build_id}")
    return build_id if changed else None


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    site = pathlib.Path(sys.argv[1]).expanduser()
    if not site.is_dir():
        print(f"{site} is not a directory", file=sys.stderr)
        return 2
    try:
        sync(site)
    except BlockingIOError:
        print("another sync is running")
        return 0
    except (SyncError, OSError, ValueError) as e:  # OSError: network, disk; ValueError: bad JSON or tar
        print(f"daily-sync: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
