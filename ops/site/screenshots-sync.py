#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Keep the website's screenshots at those of the newest CI build.

Runs on the web server from a timer (screenshots-sync.timer). CI publishes
every successful build's screenshots as screenshots.tar.gz on the rolling
GitHub pre-release "screenshots-latest"; this downloads it when it changed,
accepts only PNG files with plain names and shots.json, copies them into
<site>/assets/img/screenshots and writes their sizes and the version, commit
and date they come from into <site>/screenshots/index.html and its
Finnish and Swedish copies under <site>/fi and <site>/sv. The page is
patched on every run, so a site deploy that brings the page back from the
repository is corrected within one period. The server only reads from
GitHub; nothing on GitHub can write here.

    screenshots-sync.py <site root>     (e.g. ~/sites/varsto/public)
"""
import io
import json
import pathlib
import re
import sys
import tarfile
import urllib.request

URL = "https://github.com/janttsu/varsto/releases/download/screenshots-latest/screenshots.tar.gz"
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}\.png$")
MAX_FILE = 8 << 20

site = pathlib.Path(sys.argv[1]).expanduser()
shots = site / "assets/img/screenshots"
state = pathlib.Path.home() / ".cache/varsto-screenshots-sync.json"
known = json.loads(state.read_text()) if state.exists() else {}

req = urllib.request.Request(URL, headers={"User-Agent": "varsto-screenshots-sync"})
if known.get("etag"):
    req.add_header("If-None-Match", known["etag"])
try:
    with urllib.request.urlopen(req, timeout=60) as r:
        data, etag = r.read(64 << 20), r.headers.get("ETag")
except urllib.error.HTTPError as e:
    if e.code not in (304, 404):  # 404: nothing published yet
        raise
    data, etag = None, known.get("etag")

if data:
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for m in t.getmembers():
            name = pathlib.PurePosixPath(m.name).name
            if not m.isfile() or m.size > MAX_FILE or not (NAME.match(name) or name == "shots.json"):
                continue
            b = t.extractfile(m).read()
            if name.endswith(".png") and not b.startswith(b"\x89PNG\r\n\x1a\n"):
                continue
            files[name] = b
    meta = json.loads(files.pop("shots.json", b"{}"))
    sizes = {k: v for k, v in (meta.get("sizes") or {}).items() if f"{k}.png" in files}
    shots.mkdir(parents=True, exist_ok=True)
    for name, b in files.items():
        tmp = shots / f".{name}.tmp"
        tmp.write_bytes(b)
        tmp.replace(shots / name)
    known = {"etag": etag, "version": str(meta.get("version", ""))[:40], "commit": str(meta.get("commit", ""))[:40],
             "date": str(meta.get("date", ""))[:10], "source": str(meta.get("source", ""))[:80],
             "sizes": {**known.get("sizes", {}), **sizes}}
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(known))
    print(f"screenshots of {known['version']} ({known['commit'][:7]}): {len(files)} files")

# The caption per language; the English page and its Finnish and Swedish copies.
CAPTION = {
    "en": ("Captured automatically from version {v}{c} on {d}{s}.", "GitHub Actions run"),
    "fi": ("Kuvattu automaattisesti versiosta {v}{c} {d}{s}.", "GitHub Actions -ajo"),
    "sv": ("Tagna automatiskt från version {v}{c} den {d}{s}.", "GitHub Actions-körning"),
}
def stamp(lang, version, commit, date, source, esc=lambda s: s):
    text, run = CAPTION[lang]
    source = re.sub(r"^GitHub Actions run", run, source or "")
    return '<span class="shots-meta">' + text.format(
        v=esc(version), c=f" (commit {esc(commit[:7])})" if commit else "", d=esc(date),
        s=f", {esc(source)}" if source else "") + "</span>"
esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
for lang, page in [("en", site / "screenshots/index.html"),
                   ("fi", site / "fi/screenshots/index.html"),
                   ("sv", site / "sv/screenshots/index.html")]:
    if not (known.get("version") and page.exists()):
        continue
    html = page.read_text()
    new = html
    for name, (w, h) in known.get("sizes", {}).items():
        new = re.sub(r'(src="(?:\.\./)+assets/img/screenshots/' + re.escape(name) + r'\.png"[^>]*?) width="\d+" height="\d+"',
                     rf'\1 width="{int(w)}" height="{int(h)}"', new)
    s = stamp(lang, known["version"], known.get("commit", ""), known["date"], known.get("source", ""), esc)
    new = re.sub(r'<span class="shots-meta">.*?</span>', lambda _: s, new, flags=re.S)
    if new != html:
        tmp = page.with_name(".index.html.tmp")
        tmp.write_text(new)
        tmp.replace(page)
        print(f"screenshots page updated ({lang})")
