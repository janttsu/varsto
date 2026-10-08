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
NAV = [("Project", ""), ("Features", "features/"), ("Use cases", "use-cases/"), ("Screenshots", "screenshots/"), ("Docs", "docs/"), ("Downloads", "downloads/"), ("Blog", "blog/"), ("Forum", "forum/")]

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
<link rel="stylesheet" href="{p}assets/css/site.css">
<script src="{p}assets/js/theme.js"></script>
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


def downloads_table(depth: int) -> str:
    sums = OUT / "downloads" / "SHA256SUMS"
    manifest = OUT / "downloads" / "manifest.json"
    if not sums.exists():
        return '<p class="note">No binaries are published yet. Build from source with <code>cargo build --release</code>.</p>'
    notes = json.loads(manifest.read_text()) if manifest.exists() else {}
    rows = []
    for line in sums.read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(maxsplit=1)
        name = name.lstrip("*")
        info = notes.get(name, {})
        size = (OUT / "downloads" / name).stat().st_size if (OUT / "downloads" / name).exists() else 0
        rows.append(
            f'<tr><td><a href="{"../" * depth}downloads/{html.escape(name)}">{html.escape(name)}</a></td>'
            f'<td>{html.escape(info.get("platform", ""))}</td><td>{size // 1024} KiB</td>'
            f'<td>{html.escape(info.get("note", ""))}</td><td><code class="sum">{digest}</code></td></tr>'
        )
    version = notes.get("_version", "")
    return (
        f'<p>Release <strong>{html.escape(version)}</strong>. Checksums: <a href="{"../" * depth}downloads/SHA256SUMS">SHA256SUMS</a>.</p>'
        '<table class="downloads"><thead><tr><th>File</th><th>Platform</th><th>Size</th><th>Notes</th><th>SHA-256</th></tr></thead><tbody>'
        + "\n".join(rows)
        + "</tbody></table>"
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
