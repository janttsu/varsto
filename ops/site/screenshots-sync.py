#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Keep the website's screenshots at those of the newest CI build.

Runs on the web server from a timer (screenshots-sync.timer). CI publishes
every successful build's screenshots as screenshots.tar.gz on the rolling
GitHub pre-release "screenshots-latest"; this downloads it when it changed,
accepts only PNG and WebP files with plain names in the known subdirectories
and shots.json, and puts them on the site:

    en/<name>.png      -> <site>/assets/img/screenshots/
    fi/<name>.png      -> <site>/assets/img/screenshots-fi/
    sv/<name>.png      -> <site>/assets/img/screenshots-sv/
    viz/viz-tv.png     -> <site>/assets/img/viz-tv.png
    shots.json         sizes per set, version, commit, date, source, run

(A flat tarball of plain names, as older builds published, counts as en/.)
Their sizes and the version, commit and date they come from are written into
<site>/screenshots/index.html and its Finnish, Swedish and French copies under
<site>/fi, <site>/sv and <site>/fr, together with a content hash on each
picture's address so browsers fetch a changed picture at once. The pages are
patched on every run, so a site deploy that brings them back from the
repository is corrected within one period. The server only reads from GitHub;
nothing on GitHub can write here.

    screenshots-sync.py <site root>     (e.g. ~/sites/varsto/public)

Options for tests and dry runs (the server's invocation does not use them):
    --from FILE    read this tarball instead of downloading
    --state FILE   keep the "seen" state here (default ~/.cache/varsto-screenshots-sync.json)
"""
import argparse
import hashlib
import io
import json
import pathlib
import re
import sys
import tarfile
import urllib.error
import urllib.request

URL = "https://github.com/janttsu/varsto/releases/download/screenshots-latest/screenshots.tar.gz"
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}\.(png|webp)$")
MAGIC = {"png": b"\x89PNG\r\n\x1a\n", "webp": b"RIFF"}
MAX_FILE = 8 << 20  # one picture
MAX_TOTAL = 96 << 20  # all pictures of one tarball
MAX_FILES = 200
MAX_DIM = 20000
# subdirectory of the tarball -> directory under <site>/assets/img ("" is assets/img itself)
DIRS = {"en": "screenshots", "fi": "screenshots-fi", "sv": "screenshots-sv", "viz": ""}
VIZ_ONLY = {"viz-tv.png"}  # the only file accepted from viz/


def parse_tarball(data):
    """Return ({(set, filename): bytes}, meta) from the tarball bytes; everything
    that is not a plain-named, size-capped, magic-checked picture in a known
    subdirectory (or shots.json at the top) is ignored."""
    files, total, meta = {}, 0, {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for m in t:
            if not m.isfile() or m.size > MAX_FILE:
                continue
            parts = [p for p in pathlib.PurePosixPath(m.name).parts if p != "."]
            if any(p == ".." or p.startswith("/") for p in parts) or not 1 <= len(parts) <= 2:
                continue
            if len(parts) == 1:
                name, group = parts[0], "en"  # flat layout
                if name == "shots.json":
                    meta = _json_object(t.extractfile(m).read())
                    continue
            else:
                group, name = parts
                if group not in DIRS:
                    continue
            ext = name.rsplit(".", 1)[-1]
            if not NAME.match(name) or (group == "viz" and name not in VIZ_ONLY):
                continue
            if len(files) >= MAX_FILES or total + m.size > MAX_TOTAL:
                continue
            b = t.extractfile(m).read()
            if not b.startswith(MAGIC[ext]) or (ext == "webp" and b[8:12] != b"WEBP"):
                continue
            total += len(b)
            files[(group, name)] = b
    return files, meta


def _json_object(b):
    try:
        v = json.loads(b)
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def clean_sizes(meta, files):
    """{(set, stem): [w, h]} for pictures that are in the tarball, sizes sane.
    shots.json carries {"en": {...}, "fi": {...}, ...}; a flat {name: [w, h]}
    (older builds) is the en set."""
    raw = meta.get("sizes") or {}
    if raw and not all(isinstance(v, dict) for v in raw.values()):
        raw = {"en": raw}
    out = {}
    stems = {(g, n.rsplit(".", 1)[0]) for g, n in files}
    for group, table in raw.items():
        if group not in DIRS or not isinstance(table, dict):
            continue
        for stem, wh in table.items():
            if (group, stem) not in stems:
                continue
            try:
                w, h = int(wh[0]), int(wh[1])
            except (TypeError, ValueError, IndexError, KeyError):
                continue
            if 0 < w <= MAX_DIM and 0 < h <= MAX_DIM:
                out[(group, stem)] = [w, h]
    return out


def target_dir(site, group):
    return site / "assets/img" / DIRS[group]


def write_files(site, files):
    """Atomic replace of each picture; a stale temp file never becomes a picture."""
    for (group, name), b in files.items():
        d = target_dir(site, group)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / f".{name}.tmp"
        tmp.write_bytes(b)
        tmp.replace(d / name)


# The caption per language; the English page and its Finnish, Swedish and French copies.
CAPTION = {
    "en": ("Captured automatically from version {v}{c} on {d}{s}.", "GitHub Actions run"),
    "fi": ("Kuvattu automaattisesti versiosta {v}{c} {d}{s}.", "GitHub Actions -ajo"),
    "sv": ("Tagna automatiskt från version {v}{c} den {d}{s}.", "GitHub Actions-körning"),
    "fr": ("Capturées automatiquement depuis la version {v}{c} le {d}{s}.", "exécution GitHub Actions"),
}


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def stamp(lang, version, commit, date, source):
    text, run = CAPTION[lang]
    source = re.sub(r"^GitHub Actions run", run, source or "")
    return '<span class="shots-meta">' + text.format(
        v=esc(version), c=f" (commit {esc(commit[:7])})" if commit else "", d=esc(date),
        s=f", {esc(source)}" if source else "") + "</span>"


def patch_page(html, lang, known, site):
    """Width, height and ?v= hash of every picture the page shows from a synced
    set, and the caption. Pictures are matched by their address, whatever the
    language page or whether the address already carries ?v=."""
    new = html
    for key, wh in sorted(known.get("sizes", {}).items()):
        group, stem = key.split("/", 1)
        if group not in DIRS:
            continue
        rel = f"{DIRS[group]}/{stem}" if DIRS[group] else stem
        f = next((site / "assets/img" / f"{rel}.{e}" for e in ("png", "webp") if (site / "assets/img" / f"{rel}.{e}").exists()), None)
        if f is None:
            continue
        ver = hashlib.sha256(f.read_bytes()).hexdigest()[:10]
        new = re.sub(
            r'(src="(?:\.\./)*assets/img/' + re.escape(rel) + r'\.' + f.suffix[1:] + r')(?:\?v=[0-9a-zA-Z]+)?("[^>]*?) width="\d+" height="\d+"',
            lambda m: f'{m.group(1)}?v={ver}{m.group(2)} width="{int(wh[0])}" height="{int(wh[1])}"', new)
    s = stamp(lang, known["version"], known.get("commit", ""), known["date"], known.get("source", ""))
    return re.sub(r'<span class="shots-meta">.*?</span>', lambda _: s, new, flags=re.S)


def fetch(known, local):
    """(tarball bytes or None, etag)."""
    if local:
        return pathlib.Path(local).read_bytes(), None
    req = urllib.request.Request(URL, headers={"User-Agent": "varsto-screenshots-sync"})
    if known.get("etag"):
        req.add_header("If-None-Match", known["etag"])
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read(64 << 20), r.headers.get("ETag")
    except urllib.error.HTTPError as e:
        if e.code not in (304, 404):  # 404: nothing published yet
            raise
        return None, known.get("etag")


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("site")
    ap.add_argument("--from", dest="local")
    ap.add_argument("--state")
    a = ap.parse_args(argv)
    site = pathlib.Path(a.site).expanduser()
    state = pathlib.Path(a.state) if a.state else pathlib.Path.home() / ".cache/varsto-screenshots-sync.json"
    known = json.loads(state.read_text()) if state.exists() else {}
    if "sizes" in known and any(isinstance(v, list) and "/" not in k for k, v in known["sizes"].items()):
        known["sizes"] = {f"en/{k}": v for k, v in known["sizes"].items() if isinstance(v, list)}  # old state file

    data, etag = fetch(known, a.local)
    if data:
        files, meta = parse_tarball(data)
        sizes = {f"{g}/{s}": wh for (g, s), wh in clean_sizes(meta, files).items()}
        write_files(site, files)
        known = {"etag": etag, "version": str(meta.get("version", ""))[:40], "commit": str(meta.get("commit", ""))[:40],
                 "date": str(meta.get("date", ""))[:10], "source": str(meta.get("source", ""))[:80],
                 "sizes": {**known.get("sizes", {}), **sizes}}
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text(json.dumps(known))
        print(f"screenshots of {known['version']} ({known['commit'][:7]}): {len(files)} files")

    for lang, page in [("en", site / "screenshots/index.html"),
                       ("fi", site / "fi/screenshots/index.html"),
                       ("sv", site / "sv/screenshots/index.html"),
                       ("fr", site / "fr/screenshots/index.html")]:
        if not (known.get("version") and page.exists()):
            continue
        html = page.read_text()
        new = patch_page(html, lang, known, site)
        if new != html:
            tmp = page.with_name(".index.html.tmp")
            tmp.write_text(new)
            tmp.replace(page)
            print(f"screenshots page updated ({lang})")


if __name__ == "__main__":
    main(sys.argv[1:])
