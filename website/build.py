#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Build the static website into website/public.

Sources:
- website/src/pages/*.html   page bodies with a small front matter (title, nav, description)
- website/src/posts/*.md     blog posts (front matter: title, date, summary)
- repository Markdown files  rendered into docs/ with pandoc (GitHub-flavoured Markdown)
- website/public/downloads/SHA256SUMS  if present, becomes the download table

No inline scripts or styles are emitted (strict CSP). Run from anywhere:
    python3 website/build.py
"""
from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "website" / "src"
OUT = ROOT / "website" / "public"
BRAND = "Varsto"
SITE_URL = "https://varsto.soderlund.in"
ALPHA = (
    "<strong>Alpha software, not for production data.</strong> Bugs can cause data loss, "
    "formats may change without migration, and the cryptography has not been independently "
    "audited. Keep your own backups and check that you can restore from them."
)
FOOTER = [
    f"{BRAND} is a working name. Source will be published under the PolyForm Shield License 1.0.0 with the first public alpha.",
    "No cookies, no tracking. The web server keeps a standard access log for at most seven days.",
    '<a href="{p}docs/security-policy.html">Security policy</a> · <a href="{p}docs/licence.html">Licence</a> · <a href="{p}docs/trademark.html">Trademark</a>',
]
NAV = [("Project", ""), ("Features", "features/"), ("Use cases", "use-cases/"), ("Encryption", "encryption/"), ("Screenshots", "screenshots/"), ("Docs", "docs/"), ("Downloads", "downloads/"), ("Blog", "blog/"), ("Forum", "forum/")]

# Repository documents rendered under docs/: (source path, slug, title, group)
DOCS = [
    ("README.md", "quick-start", "Overview and quick start", "Start here"),
    ("docs/spec/alpha-0-format.md", "alpha-0-format", "Alpha-0 storage format and sync model", "Specifications"),
    ("docs/spec/format-versions.md", "format-versions", "Storage format versions", "Specifications"),
    ("docs/spec/key-hierarchy.md", "key-hierarchy", "Key hierarchy (draft)", "Specifications"),
    ("docs/spec/ledger-signing-notes.md", "ledger-signing-notes", "Ledger signing: design notes", "Specifications"),
    ("docs/spec/README.md", "specifications", "Specification status", "Specifications"),
    ("docs/architecture/threat-model.md", "threat-model", "Threat model (design stage)", "Security"),
    ("docs/architecture/security-principles.md", "security-principles", "Security principles", "Security"),
    ("docs/architecture/logging.md", "logging", "Logging architecture", "Security"),
    ("docs/failure-model.md", "failure-model", "Failure model", "Security"),
    ("docs/research/fido2-platform-support.md", "fido2-platform-support", "FIDO2 hmac-secret and PRF platform support", "Security"),
    ("SECURITY.md", "security-policy", "Security policy", "Project"),
    ("TESTING.md", "testing", "Testing", "Project"),
    ("CONTRIBUTING.md", "contributing", "Contributing", "Project"),
    ("TRADEMARK.md", "trademark", "Trademark policy (draft)", "Project"),
    ("data/providers/README.md", "provider-price-data", "Provider price data", "Project"),
    ("docs/testing/mobile.md", "mobile-testing", "Mobile testing guide", "Project"),
]


def front_matter(text: str) -> tuple[dict, str]:
    meta: dict[str, str] = {}
    if text.startswith("---\n"):
        end = text.index("\n---\n", 4)
        for line in text[4:end].splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
        text = text[end + 5 :]
    return meta, text


def asset_version(rel: str) -> str:
    """Short content hash so browsers fetch a changed stylesheet or script at once
    (the server caches assets for a day)."""
    import hashlib
    f = OUT / rel
    return hashlib.sha256(f.read_bytes()).hexdigest()[:10] if f.exists() else "0"


def page(title: str, description: str, body: str, nav: str, depth: int) -> str:
    p = "../" * depth
    nav_html = "\n".join(
        f'      <a href="{p}{href}"{" aria-current=\"page\"" if name == nav else ""}>{name}</a>' for name, href in NAV
    )
    footer = "\n".join(f"    <span>{line.format(p=p)}</span>" for line in FOOTER)
    full_title = f"{BRAND}: your files, your storage" if nav == "Project" and depth == 0 else f"{title}: {BRAND}"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(full_title)}</title>
<meta name="description" content="{html.escape(description)}">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="{p}favicon.svg" type="image/svg+xml">
<link rel="alternate" type="application/rss+xml" title="{BRAND} blog" href="{p}blog/feed.xml">
<link rel="stylesheet" href="{p}assets/css/site.css?v={asset_version("assets/css/site.css")}">
<script src="{p}assets/js/theme.js?v={asset_version("assets/js/theme.js")}"></script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="alpha" role="note">
  <div class="wrap">{ALPHA}</div>
</div>
<header class="site">
  <div class="wrap">
    <a class="brand" href="{p if depth else './'}"><img src="{p}assets/img/logo.svg" alt="" width="28" height="28"><span>{BRAND}</span></a>
    <nav class="main" aria-label="Main">
{nav_html}
      <button class="theme" id="theme-toggle" type="button" aria-label="Change colour theme">Theme: auto</button>
    </nav>
  </div>
</header>
<main id="main">
  <div class="wrap">
{body}
  </div>
</main>
<footer class="site">
  <div class="wrap">
{footer}
  </div>
</footer>
</body>
</html>
"""


def pandoc(markdown: str) -> str:
    return subprocess.run(
        ["pandoc", "-f", "gfm", "-t", "html5", "--wrap=none"],
        input=markdown,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def rewrite_links(body: str, slug_by_name: dict[str, str], docs_prefix: str = "") -> str:
    """Point links at repository files to the rendered docs; unknown repository
    files fall back to the docs index. External links are left alone."""

    def repl(m: re.Match) -> str:
        target, frag = m.group(1), m.group(2) or ""
        if target.startswith(("http://", "https://", "mailto:")) or target.endswith((".html", ".xml")):
            return m.group(0)
        name = os.path.basename(target)
        if name in slug_by_name:
            return f'href="{docs_prefix}{slug_by_name[name]}.html{frag}"'
        return f'href="{docs_prefix}./"'

    return re.sub(r'href="([^"#]+)(#[^"]*)?"', repl, body)


PLATFORMS = [
    # (title, icon, matcher for the primary file, matchers for alternatives, status line)
    ("Linux", "linux", lambda n: n.endswith("-x86_64-unknown-linux-musl.tar.gz"), [],
     "x86_64, static binary. Tray icon, background service, browser interface and command line in one file. Tested on the development machine."),
    ("macOS", "macos", lambda n: n.endswith("-macos.zip") or n.endswith("-macos-apple-silicon-lite.zip"),
     [("Command line only (Apple Silicon)", lambda n: n.endswith("-aarch64-apple-darwin.tar.gz"))],
     "Apple Silicon. The native app has its own window, a menu-bar item, the background service and the varsto command line inside the bundle (Install command-line tool in the menu). Unsigned: right-click, Open the first time. A file named ...-lite.zip is the interim cross-compiled build that opens the interface in your browser instead."),    ("Windows", "windows", lambda n: n.endswith("-x86_64-pc-windows-gnu.zip"), [],
     "x86_64 zip. Double-click Varsto.cmd for the tray icon and the interface. Cross-compiled, not yet tested on Windows."),
    ("Android", "android", lambda n: n.endswith("-android-debug.apk"), [],
     "Debug-signed APK for sideloading: allow the install when the phone asks. Runs the same core as a foreground service. Tested in the Android 15 emulator only."),
    ("iOS", "ios", None, [],
     "Not downloadable yet: the app shell is in the repository (apps/ios) and needs a Mac with Xcode to build."),
    ("Source", "source", lambda n: n.endswith("-source.tar.gz"), [],
     "Git archive of the tagged release. Build with a stable Rust toolchain: cargo build --release."),
]

ICONS = {
    "linux": '<path d="M12 3c-2.2 0-3.6 1.9-3.6 4.4 0 1.1-.6 2-1.3 3-1 1.4-2.1 3-2.1 5.2 0 .7.1 1.3.4 1.9-.9.3-1.4.8-1.4 1.4 0 .9 1.4 1.4 3.2 1.4 1.1 0 2-.2 2.7-.6.7.2 1.4.3 2.1.3s1.4-.1 2.1-.3c.7.4 1.6.6 2.7.6 1.8 0 3.2-.5 3.2-1.4 0-.6-.5-1.1-1.4-1.4.3-.6.4-1.2.4-1.9 0-2.2-1.1-3.8-2.1-5.2-.7-1-1.3-1.9-1.3-3C15.6 4.9 14.2 3 12 3zm-1.6 4.2c.5 0 .8.5.8 1.1s-.3 1.1-.8 1.1-.8-.5-.8-1.1.3-1.1.8-1.1zm3.2 0c.5 0 .8.5.8 1.1s-.3 1.1-.8 1.1-.8-.5-.8-1.1.3-1.1.8-1.1zM12 10c.9 0 1.8.4 1.8.9S12.9 12 12 12s-1.8-.6-1.8-1.1.9-.9 1.8-.9z"/>',
    "macos": '<path d="M16.4 12.6c0-2.3 1.9-3.4 2-3.5-1.1-1.6-2.8-1.8-3.4-1.8-1.4-.2-2.8.9-3.5.9s-1.8-.8-3-.8c-1.5 0-3 .9-3.8 2.3-1.6 2.8-.4 7 1.2 9.3.8 1.1 1.7 2.4 2.9 2.3 1.2 0 1.6-.8 3-.8s1.8.8 3 .7c1.3 0 2-1.1 2.8-2.3.9-1.3 1.2-2.6 1.3-2.6-.1-.1-2.5-1-2.5-3.7zM14.1 5.8c.6-.8 1.1-1.9.9-3-.9.1-2 .6-2.7 1.4-.6.7-1.1 1.8-1 2.9 1.1.1 2.1-.5 2.8-1.3z"/>',
    "windows": '<path d="M3 5.5 11 4.4v7.1H3zm0 13 8 1.1v-7H3zm9 1.2L22 21v-8.4h-10zm0-15.4V11h10V3z"/>',
    "android": '<path d="M7 9h10v8a2 2 0 0 1-2 2h-1v3h-2v-3h-1v3H9v-3H8a1 1 0 0 1-1-1zm10.6-1H6.4c.3-1.9 1.4-3.5 3-4.4L8.3 2.5l.9-.5 1.2 2.2c.5-.1 1-.2 1.6-.2s1.1.1 1.6.2l1.2-2.2.9.5-1.1 2.1c1.6.9 2.7 2.5 3 4.4zM9.5 6.5a.7.7 0 1 0 0-1.4.7.7 0 0 0 0 1.4zm5 0a.7.7 0 1 0 0-1.4.7.7 0 0 0 0 1.4zM4 10h2v7H4zm14 0h2v7h-2z"/>',
    "ios": '<path d="M8 2h8a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm0 2v15h8V4zm3 16.5h2v1h-2z"/>',
    "source": '<path d="m8.5 7-5 5 5 5 1.4-1.4L6.3 12l3.6-3.6zm7 0-1.4 1.4 3.6 3.6-3.6 3.6L15.5 17l5-5z"/>',
}


def downloads_table(depth: int) -> str:
    sums = OUT / "downloads" / "SHA256SUMS"
    manifest = OUT / "downloads" / "manifest.json"
    if not sums.exists():
        return '<p class="note">No binaries are published yet. Build from source with <code>cargo build --release</code>.</p>'
    notes = json.loads(manifest.read_text()) if manifest.exists() else {}
    files = []
    for line in sums.read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(maxsplit=1)
        name = name.lstrip("*")
        size = (OUT / "downloads" / name).stat().st_size if (OUT / "downloads" / name).exists() else 0
        files.append((name, digest, size))
    version = notes.get("_version", "")
    pre = "../" * depth

    def human(n: int) -> str:
        return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{n // 1024} KB"

    cards = []
    for title, icon, primary, alts, status in PLATFORMS:
        candidates = [(n, d, sz) for n, d, sz in files if primary and primary(n)]
        candidates.sort(key=lambda t: t[0].endswith("-lite.zip"))  # the Mac-built app first
        main = candidates[0] if candidates else None
        icon_svg = f'<svg class="dl-icon" viewBox="0 0 24 24" aria-hidden="true">{ICONS[icon]}</svg>'
        if main:
            name, digest, size = main
            label = ("Download Varsto.app (Apple Silicon)" if not name.endswith("-lite.zip") else "Download Varsto.app (interim, Apple Silicon)") if title == "macOS" else f"Download for {html.escape(title)}"
            button = (f'<a class="dl-primary" href="{pre}downloads/{html.escape(name)}">{label}</a>'
                      f'<p class="dl-meta">{html.escape(name)}<br>{human(size)} · <span class="sum" title="{digest}">SHA-256 {digest[:12]}…</span></p>')
        elif title == "Source":
            button = f'<a class="dl-primary" href="{pre}downloads/">Source</a>'
        else:
            button = f'<a class="dl-primary dl-disabled" href="{pre}docs/">Not available yet</a>'
        alt_links = []
        for label, matcher in alts:
            hit = next(((n, d, sz) for n, d, sz in files if matcher(n)), None)
            if hit:
                alt_links.append(f'<li><a href="{pre}downloads/{html.escape(hit[0])}">{html.escape(label)}</a> <span class="dl-meta">{human(hit[2])}</span></li>')
        alt_html = f'<ul class="dl-alt">{"".join(alt_links)}</ul>' if alt_links else ""
        cards.append(f'<section class="dl-card"><div class="dl-head">{icon_svg}<h3>{html.escape(title)}</h3></div>{button}{alt_html}<p class="dl-status">{html.escape(status)}</p></section>')
    rows = "\n".join(
        f'<tr><td><a href="{pre}downloads/{html.escape(n)}">{html.escape(n)}</a></td><td>{html.escape(notes.get(n, {}).get("platform", ""))}</td>'
        f'<td>{human(sz)}</td><td><code class="sum">{d}</code></td></tr>' for n, d, sz in files)
    return (
        f'<p class="dl-release">Release <strong>{html.escape(version)}</strong> · <a href="{pre}downloads/SHA256SUMS">SHA256SUMS</a> · <a href="{pre}downloads/manifest.json">manifest.json</a></p>'
        f'<div class="dl-grid">{"".join(cards)}</div>'
        f'<details class="dl-all"><summary>All files and checksums</summary><table class="downloads"><thead><tr><th>File</th><th>Platform</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>{rows}</tbody></table></details>'
    )


def build_pages(slug_by_name: dict[str, str]) -> None:
    for src in sorted((SRC / "pages").glob("*.html")):
        meta, body = front_matter(src.read_text())
        out_rel = meta.get("output", f"{src.stem}.html")
        depth = out_rel.count("/")
        body = body.replace("{{DOWNLOADS}}", downloads_table(depth)).replace("{{POSTS}}", posts_list(depth))
        body = body.replace("{{P}}", "../" * depth)
        (OUT / out_rel).parent.mkdir(parents=True, exist_ok=True)
        (OUT / out_rel).write_text(page(meta["title"], meta.get("description", ""), body, meta["nav"], depth))


def build_docs() -> dict[str, str]:
    slug_by_name = {os.path.basename(path): slug for path, slug, _, _ in DOCS}
    slug_by_name["LICENSE"] = "licence"
    groups: dict[str, list[tuple[str, str]]] = {}
    for path, slug, title, group in DOCS:
        source = ROOT / path
        if not source.exists():
            print(f"skip missing {path}", file=sys.stderr)
            continue
        text = source.read_text()
        if path == "LICENSE":
            body = f"<pre class=\"licence\">{html.escape(text)}</pre>"
        else:
            lines = text.splitlines()
            if lines and lines[0].startswith("# "):
                lines = lines[1:]
            body = rewrite_links(pandoc("\n".join(lines)), slug_by_name)
        body = f"<article class=\"prose\">\n<h1>{html.escape(title)}</h1>\n<p class=\"note\">From <code>{html.escape(path)}</code> in the repository, rendered {datetime.now(timezone.utc).date()}.</p>\n{body}\n</article>"
        (OUT / "docs").mkdir(parents=True, exist_ok=True)
        (OUT / "docs" / f"{slug}.html").write_text(page(title, f"{BRAND} documentation: {title}", body, "Docs", 1))
        groups.setdefault(group, []).append((slug, title))
    # Licence page from the plain-text LICENSE.
    licence = (ROOT / "LICENSE").read_text()
    body = f"<article class=\"prose\"><h1>Licence</h1><p class=\"note\">PolyForm Shield License 1.0.0, verbatim from <code>LICENSE</code>.</p><pre class=\"licence\">{html.escape(licence)}</pre></article>"
    (OUT / "docs" / "licence.html").write_text(page("Licence", f"{BRAND} licence", body, "Docs", 1))
    groups.setdefault("Project", []).append(("licence", "Licence (PolyForm Shield 1.0.0)"))
    # Index.
    sections = []
    for group in ["Start here", "Specifications", "Security", "Project"]:
        items = groups.get(group, [])
        if not items:
            continue
        lis = "\n".join(f'      <li><a href="{slug}.html">{html.escape(title)}</a></li>' for slug, title in items)
        sections.append(f"    <h2>{group}</h2>\n    <ul class=\"doclist\">\n{lis}\n    </ul>")
    body = (
        "    <h1>Docs</h1>\n"
        "    <p class=\"lead\">The documents below are rendered from the repository. They describe what alpha-0 does today and what the full design intends; every design document says which parts exist.</p>\n"
        + "\n".join(sections)
    )
    (OUT / "docs" / "index.html").write_text(page("Docs", f"{BRAND} documentation", body, "Docs", 1))
    return slug_by_name


def load_posts() -> list[dict]:
    posts = []
    for src in sorted((SRC / "posts").glob("*.md"), reverse=True):
        meta, body = front_matter(src.read_text())
        posts.append({"slug": src.stem, "title": meta["title"], "date": meta["date"], "summary": meta.get("summary", ""), "body": body})
    return posts


def posts_list(depth: int) -> str:
    items = []
    for post in load_posts():
        items.append(
            f'<li><time datetime="{post["date"]}">{post["date"]}</time> <a href="{"../" * depth}blog/{post["slug"]}.html">{html.escape(post["title"])}</a><br><span class="note">{html.escape(post["summary"])}</span></li>'
        )
    return '<ul class="posts">' + "\n".join(items) + "</ul>" if items else '<p class="note">No posts yet.</p>'


def build_blog(slug_by_name: dict[str, str]) -> None:
    posts = load_posts()
    (OUT / "blog").mkdir(parents=True, exist_ok=True)
    for post in posts:
        body = rewrite_links(pandoc(post["body"]), slug_by_name, "../docs/")
        body = f'<article class="prose"><h1>{html.escape(post["title"])}</h1><p class="note"><time datetime="{post["date"]}">{post["date"]}</time></p>\n{body}\n</article>'
        (OUT / "blog" / f'{post["slug"]}.html').write_text(page(post["title"], post["summary"], body, "Blog", 1))
    items = "\n".join(
        f"  <item><title>{html.escape(p['title'])}</title><link>{SITE_URL}/blog/{p['slug']}.html</link>"
        f"<guid>{SITE_URL}/blog/{p['slug']}.html</guid><pubDate>{datetime.strptime(p['date'], '%Y-%m-%d').strftime('%a, %d %b %Y 00:00:00 +0000')}</pubDate>"
        f"<description>{html.escape(p['summary'])}</description></item>"
        for p in posts
    )
    feed = f'<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel><title>{BRAND} blog</title><link>{SITE_URL}/blog/</link><description>Release notes and technical articles</description>\n{items}\n</channel></rss>\n'
    (OUT / "blog" / "feed.xml").write_text(feed)


def build_404() -> None:
    body = '    <h1>Page not found</h1>\n    <p class="lead">That page does not exist. Go back to the <a href="/">project page</a>.</p>'
    text = page("Page not found", "", body, "", 0)
    # The 404 page is served from any path: use absolute asset links.
    text = text.replace('href="favicon.svg"', 'href="/favicon.svg"').replace('href="assets/', 'href="/assets/').replace('src="assets/', 'src="/assets/').replace('href="blog/feed.xml"', 'href="/blog/feed.xml"')
    text = re.sub(r'<a href="([a-z]+/)"', r'<a href="/\1"', text)
    text = text.replace('<a href="./"', '<a href="/"').replace('href=""', 'href="/"')
    (OUT / "404.html").write_text(text)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    slugs = build_docs()
    build_blog(slugs)
    build_pages(slugs)
    build_404()
    print(f"built into {OUT}")


if __name__ == "__main__":
    main()
