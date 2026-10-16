#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Build the static website into website/public.

Sources:
- website/src/pages/*.html   page bodies with a small front matter (title, nav, description)
- website/src/posts/*.md     blog posts (front matter: title, date, summary)
- repository Markdown files  rendered into docs/ with pandoc (GitHub-flavoured Markdown)
- website/public/downloads/SHA256SUMS  if present, becomes the download table; without it the
  live site's list is read, read-only (DOWNLOADS_SOURCE_URL, default https://varsto.net/downloads/,
  empty turns this off)

No inline scripts or styles are emitted (strict CSP). Run from anywhere:
    python3 website/build.py
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "website" / "src"
OUT = ROOT / "website" / "public"
BRAND = "Varsto"
SITE_URL = "https://varsto.net"
ALPHA = (
    "<strong>Alpha software, not for production data.</strong> Bugs can cause data loss, "
    "formats may change without migration, and the cryptography has not been independently "
    "audited. Keep your own backups and check that you can restore from them."
)
REPO = "https://github.com/janttsu/varsto"
# The last tagged release. Update it when tagging a release: the pages say
# "released" with this value, while {{VERSION}} follows Cargo.toml (main).
RELEASED_VERSION = "0.0.1-alpha.14"
RELEASE_KEY = ROOT / "release-key.pub"
# The daily channel has its own key; it signs only daily/latest/SHA256SUMS.
DAILY_KEY = ROOT / "daily-key.pub"
FOOTER = [
    f'{BRAND} is a working name. Source: <a href="{REPO}">github.com/janttsu/varsto</a>, under the PolyForm Shield License 1.0.0 (source-available).',
    "No cookies, no tracking. The web server keeps a standard access log for at most seven days.",
    '<a href="{p}docs/security-policy.html">Security policy</a> · <a href="{p}docs/licence.html">Licence</a> · <a href="{p}docs/trademark.html">Trademark</a>',
]
NAV = [("Project", ""), ("Features", "features/"), ("Use cases", "use-cases/"), ("Compare", "compare/"), ("How it works", "how-it-works/"), ("Screenshots", "screenshots/"), ("Docs", "docs/"), ("Downloads", "downloads/"), ("Blog", "blog/"), ("Forum", "forum/"), ("Contribute", "contribute/"), ("GitHub", REPO)]

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
    ("docs/recovery.md", "recovery", "Recovery package", "Start here"),
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


def version_images(body: str) -> str:
    """Add the content hash to every picture under assets/img in a page body, so a
    re-rendered illustration replaces the cached one at once."""
    return re.sub(r'(assets/img/[A-Za-z0-9_/.-]+\.(?:png|webp|jpg|svg))(?=")',
                  lambda m: f"{m.group(1)}?v={asset_version(m.group(1))}", body)


# Website languages: English at the root, the others under /<lang>/ with
# pages translated in website/src/i18n/<lang>/pages/. Docs, blog and forum
# stay English (internal documentation is English only).
LANGS = [("en", "English"), ("fi", "Suomi"), ("sv", "Svenska"), ("fr", "Français")]
NAV_I18N = {
    "fi": {"Project": "Projekti", "Features": "Ominaisuudet", "Use cases": "Käyttötapaukset", "Compare": "Vertailu",
           "How it works": "Miten se toimii", "Screenshots": "Kuvakaappaukset", "Docs": "Dokumentaatio (en)",
           "Downloads": "Lataukset", "Blog": "Blogi (en)", "Forum": "Foorumi (en)", "Contribute": "Osallistu", "GitHub": "GitHub"},
    "sv": {"Project": "Projekt", "Features": "Funktioner", "Use cases": "Användningsfall", "Compare": "Jämförelse",
           "How it works": "Så fungerar det", "Screenshots": "Skärmbilder", "Docs": "Dokumentation (en)",
           "Downloads": "Nedladdningar", "Blog": "Blogg (en)", "Forum": "Forum (en)", "Contribute": "Bidra", "GitHub": "GitHub"},
    "fr": {"Project": "Projet", "Features": "Fonctionnalités", "Use cases": "Cas d'usage", "Compare": "Comparaison",
           "How it works": "Fonctionnement", "Screenshots": "Captures d'écran", "Docs": "Documentation (en)",
           "Downloads": "Téléchargements", "Blog": "Blog (en)", "Forum": "Forum (en)", "Contribute": "Contribuer", "GitHub": "GitHub"},
}
ENGLISH_ONLY = ("docs/", "blog/", "forum/")
ALPHA_I18N = {
    "fi": "<strong>Alpha-ohjelmisto, ei tuotantodatalle.</strong> Virheet voivat hävittää dataa, tallennusmuoto voi muuttua ilman siirtotyökalua, eikä salausta ole vielä auditoitu. Pidä omat varmuuskopiosi ja varmista, että voit palauttaa niistä.",
    "sv": "<strong>Alfaprogramvara, inte för produktionsdata.</strong> Fel kan leda till dataförlust, formatet kan ändras utan migrering och krypteringen har ännu inte granskats av utomstående. Behåll egna säkerhetskopior och kontrollera att du kan återställa från dem.",
    "fr": "<strong>Logiciel alpha, pas pour des données de production.</strong> Des erreurs peuvent entraîner une perte de données, le format de stockage peut changer sans outil de migration et le chiffrement n'a pas encore été audité. Conservez vos propres sauvegardes et vérifiez que vous pouvez en restaurer.",
}
FOOTER_I18N = {
    "fi": [
        f'{BRAND} on työnimi. Lähdekoodi: <a href="{REPO}">github.com/janttsu/varsto</a>, PolyForm Shield License 1.0.0 -lisenssillä (lähdekoodi saatavilla).',
        "Ei evästeitä, ei seurantaa. Palvelin säilyttää tavallista käyntilokia enintään seitsemän päivää.",
        '<a href="{p}docs/security-policy.html">Tietoturvakäytäntö</a> · <a href="{p}docs/licence.html">Lisenssi</a> · <a href="{p}docs/trademark.html">Tavaramerkki</a> (englanniksi)',
    ],
    "sv": [
        f'{BRAND} är ett arbetsnamn. Källkod: <a href="{REPO}">github.com/janttsu/varsto</a>, under PolyForm Shield License 1.0.0 (källkoden tillgänglig).',
        "Inga kakor, ingen spårning. Webbservern sparar en vanlig åtkomstlogg i högst sju dagar.",
        '<a href="{p}docs/security-policy.html">Säkerhetspolicy</a> · <a href="{p}docs/licence.html">Licens</a> · <a href="{p}docs/trademark.html">Varumärke</a> (på engelska)',
    ],
    "fr": [
        f'{BRAND} est un nom de travail. Code source : <a href="{REPO}">github.com/janttsu/varsto</a>, sous licence PolyForm Shield License 1.0.0 (code source disponible).',
        "Pas de cookies, pas de suivi. Le serveur web conserve un journal d'accès ordinaire pendant sept jours au plus.",
        '<a href="{p}docs/security-policy.html">Politique de sécurité</a> · <a href="{p}docs/licence.html">Licence</a> · <a href="{p}docs/trademark.html">Marque</a> (en anglais)',
    ],
}
SKIP_I18N = {"en": "Skip to content", "fi": "Siirry sisältöön", "sv": "Hoppa till innehållet",
             "fr": "Aller au contenu"}
# The home page title: what people search for.
TAGLINE = {"en": "encrypted file sync and backup on your own storage",
           "fi": "salattu tiedostojen synkronointi ja varmuuskopiointi omaan tallennustilaan",
           "sv": "krypterad filsynkronisering och säkerhetskopiering till din egen lagring",
           "fr": "synchronisation et sauvegarde de fichiers chiffrées sur votre propre stockage"}


OG_LOCALE = {"en": "en_GB", "fi": "fi_FI", "sv": "sv_SE", "fr": "fr_FR"}


def absolute(lang: str, page_rel: str) -> str:
    return f"{SITE_URL}/" + ("" if lang == "en" else lang + "/") + page_rel


def json_ld(data: dict) -> str:
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return f'<script type="application/ld+json">{text}</script>\n'


def home_structured_data(lang: str, url: str, description: str) -> str:
    """The home page describes the site, the application and its source code."""
    version = RELEASED_VERSION
    return json_ld({
        "@context": "https://schema.org",
        "@graph": [
            {"@type": "WebSite", "@id": f"{SITE_URL}/#site", "url": f"{SITE_URL}/", "name": BRAND,
             "inLanguage": [code for code, _ in LANGS]},
            {"@type": "SoftwareApplication", "name": BRAND, "url": url, "description": description,
             "applicationCategory": "UtilitiesApplication", "applicationSubCategory": "File synchronisation and backup",
             "operatingSystem": "Linux, Windows, macOS, Android", "softwareVersion": version,
             "downloadUrl": f"{SITE_URL}/downloads/", "screenshot": f"{SITE_URL}/assets/img/screenshots/desktop-files-light.png",
             "offers": {"@type": "Offer", "price": "0", "priceCurrency": "EUR"}, "isAccessibleForFree": True},
            {"@type": "SoftwareSourceCode", "name": f"{BRAND} source code", "codeRepository": REPO,
             "programmingLanguage": ["Rust", "Swift", "Kotlin", "JavaScript"], "runtimePlatform": "Rust",
             "license": "https://polyformproject.org/licenses/shield/1.0.0/", "version": version,
             "targetProduct": {"@type": "SoftwareApplication", "name": BRAND}},
        ],
    })


def page(title: str, description: str, body: str, nav: str, depth: int, lang: str = "en", rel: str = "",
         extra_head: str = "") -> str:
    """`depth`: directory levels below the site root; `rel`: the page's path
    relative to its language root (for the switcher, the canonical address and
    the hreflang links), e.g. "features/index.html"; `extra_head`: page-specific
    structured data."""
    p = "../" * depth
    body = version_images(body)
    labels = NAV_I18N.get(lang, {})
    lang_root = p if lang == "en" else p + lang + "/"

    def nav_href(href: str) -> str:
        if href.startswith("http"):
            return href
        if lang != "en" and not href.startswith(ENGLISH_ONLY):
            return lang_root + href
        return p + href

    page_rel = rel.removesuffix("index.html")
    alternates, switch = [], []
    for code, label in LANGS:
        if code != "en" and not translated(code, rel):
            continue
        href = (p if code == "en" else p + code + "/") + page_rel
        # Search engines want absolute addresses here.
        alternates.append(f'<link rel="alternate" hreflang="{code}" href="{absolute(code, page_rel)}">')
        if code == "en":
            alternates.append(f'<link rel="alternate" hreflang="x-default" href="{absolute(code, page_rel)}">')
        cur = ' aria-current="true"' if code == lang else ""
        switch.append(f'<a href="{href or "./"}" hreflang="{code}" lang="{code}"{cur}>{label}</a>')
    lang_switch = ('    <nav class="langs" aria-label="Language">' + " ".join(switch) + "</nav>\n") if len(switch) > 1 else ""
    if not rel:  # the 404 page and others without a fixed address
        alternates = []
    alternates_html = "\n".join(alternates)
    alpha = ALPHA_I18N.get(lang, ALPHA)
    footer_lines = FOOTER_I18N.get(lang, FOOTER)
    nav_html = "\n".join(
        f'      <a href="{nav_href(href)}"{" aria-current=\"page\"" if name == nav else ""}{" rel=\"noopener\"" if href.startswith("http") else ""}>{labels.get(name, name)}</a>' for name, href in NAV
    )
    footer = "\n".join(f"    <span>{line.format(p=p)}</span>" for line in footer_lines)
    is_home = nav == "Project" and rel in ("", "index.html")
    if is_home:
        full_title = f"{BRAND}: {TAGLINE[lang]}"
    else:
        full_title = title if BRAND in title else f"{title}: {BRAND}"
    social = ""
    if rel:
        url = absolute(lang, page_rel)
        social = "\n".join([
            f'<link rel="canonical" href="{url}">',
            f'<meta property="og:type" content="{"article" if nav == "Blog" and page_rel.endswith(".html") else "website"}">',
            f'<meta property="og:site_name" content="{BRAND}">',
            f'<meta property="og:title" content="{html.escape(full_title)}">',
            f'<meta property="og:description" content="{html.escape(description)}">',
            f'<meta property="og:url" content="{url}">',
            f'<meta property="og:image" content="{SITE_URL}/assets/img/og-card.png">',
            '<meta property="og:image:width" content="1200">',
            '<meta property="og:image:height" content="630">',
            f'<meta property="og:locale" content="{OG_LOCALE[lang]}">',
            '<meta name="twitter:card" content="summary_large_image">',
        ]) + "\n"
        if is_home:
            extra_head += home_structured_data(lang, url, description)
    return f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(full_title)}</title>
<meta name="description" content="{html.escape(description)}">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="{p}favicon.svg" type="image/svg+xml">
{social}{alternates_html}
{extra_head}<link rel="alternate" type="application/rss+xml" title="{BRAND} blog" href="{p}blog/feed.xml">
<link rel="stylesheet" href="{p}assets/css/site.css?v={asset_version("assets/css/site.css")}">
<script src="{p}assets/js/theme.js?v={asset_version("assets/js/theme.js")}"></script>
</head>
<body>
<a class="skip" href="#main">{SKIP_I18N[lang]}</a>
<div class="alpha" role="note">
  <div class="wrap">{alpha}</div>
</div>
<header class="site">
  <div class="wrap">
    <a class="brand" href="{lang_root if (depth or lang != 'en') else './'}"><img src="{p}assets/img/logo.svg" alt="" width="28" height="28"><span>{BRAND}</span></a>
{lang_switch}
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
     "x86_64, static binary. Unpack and run ./varsto once: it installs itself for your user (varsto on your PATH, the background service as a systemd user unit, the tray at login, Varsto in the application menu; no root). Tray icon, background service, browser interface and command line in one file."),
    ("macOS", "macos", lambda n: n.endswith("-macos.dmg") or n.endswith("-macos.zip") or n.endswith("-macos-apple-silicon-lite.zip"),
     [("Command line only (Apple Silicon)", lambda n: n.endswith("-aarch64-apple-darwin.tar.gz"))],
     "Apple Silicon. Open the disk image and drag Varsto to Applications. The app has its own window, a menu-bar item, Finder actions (right-click a file: Download or Free up space with Varsto; double-click a placeholder to download and open it), the background service and the varsto command line inside the bundle. Unsigned: right-click, Open the first time."),
    ("Windows", "windows", lambda n: n.endswith("-setup.exe") or n.endswith("-x86_64-pc-windows-gnu.zip"),
     [("Portable zip (no installer)", lambda n: n.endswith("-x86_64-pc-windows-gnu.zip"))],
     "x86_64 installer. Installs for your user without administrator rights (or for everyone): Start menu and desktop icons, Varsto in its own window, the background service and tray at login, automatic updates. Run it again to upgrade or repair; your data stays. Not code-signed, so SmartScreen may ask you to confirm. Built and smoke-tested on Windows Server 2025 in CI; not yet through the manual checklist on a real machine."),
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


_REMOTE_SET: dict | None = None


def remote_download_set() -> dict | None:
    """The live site's current download set, read-only, for a checkout that has
    none of its own (the binaries and SHA256SUMS are not in the repository).
    DOWNLOADS_SOURCE_URL names the directory (default https://varsto.net/downloads/);
    set it to an empty string to turn the fallback off. Returns
    {"sums": text, "manifest": dict, "sizes": {name: bytes}} or None when it
    cannot be fetched or does not look like a download set."""
    global _REMOTE_SET
    if _REMOTE_SET is not None:
        return _REMOTE_SET or None
    _REMOTE_SET = {}
    base = os.environ.get("DOWNLOADS_SOURCE_URL", f"{SITE_URL}/downloads/")
    if not base:
        return None
    base = base.rstrip("/") + "/"
    import urllib.request

    def fetch(name: str, method: str = "GET"):
        req = urllib.request.Request(base + name, method=method, headers={"User-Agent": "varsto-website-build"})
        return urllib.request.urlopen(req, timeout=20)

    try:
        with fetch("SHA256SUMS") as r:
            sums = r.read(1 << 20).decode()
        try:
            with fetch("manifest.json") as r:
                manifest = json.loads(r.read(1 << 20).decode())
        except Exception:
            manifest = {}
        line = re.compile(r"^[0-9a-f]{64}  \*?[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
        lines = [ln for ln in sums.splitlines() if ln.strip()]
        if not lines or not all(line.match(ln) for ln in lines):
            raise ValueError("SHA256SUMS is not a checksum list")
        sizes = {}
        for ln in lines:
            name = ln.split(maxsplit=1)[1].lstrip("*")
            try:
                with fetch(name, "HEAD") as r:
                    sizes[name] = int(r.headers.get("Content-Length", 0))
            except Exception:
                pass
    except Exception as e:
        print(f"warning: cannot read the live download set from {base}: {e}", file=sys.stderr)
        return None
    print(f"download set read from {base} ({len(lines)} files, read-only)")
    _REMOTE_SET = {"sums": sums, "manifest": manifest if isinstance(manifest, dict) else {}, "sizes": sizes}
    return _REMOTE_SET


def downloads_table(depth: int) -> str:
    sums = OUT / "downloads" / "SHA256SUMS"
    manifest = OUT / "downloads" / "manifest.json"
    remote = None if sums.exists() else remote_download_set()
    if not sums.exists() and not remote:
        return '<p class="note">No binaries are published yet. Build from source with <code>cargo build --release</code>.</p>'
    if remote:
        notes, sums_text = remote["manifest"], remote["sums"]
    else:
        notes, sums_text = (json.loads(manifest.read_text()) if manifest.exists() else {}), sums.read_text()
    files = []
    for line in sums_text.splitlines():
        if not line.strip():
            continue
        digest, name = line.split(maxsplit=1)
        name = name.lstrip("*")
        if remote:
            size = remote["sizes"].get(name, 0)
        else:
            size = (OUT / "downloads" / name).stat().st_size if (OUT / "downloads" / name).exists() else 0
        files.append((name, digest, size))
    version = notes.get("_version", "")
    pre = "../" * depth

    def human(n: int) -> str:
        if not n:
            return ""
        return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{n // 1024} KB"

    cards = []
    for title, icon, primary, alts, status in PLATFORMS:
        candidates = [(n, d, sz) for n, d, sz in files if primary and primary(n)]
        # The Mac-built app first, the Windows installer before the portable zip.
        candidates.sort(key=lambda t: (t[0].endswith("-lite.zip"), not t[0].endswith("-setup.exe")))
        main = candidates[0] if candidates else None
        icon_svg = f'<svg class="dl-icon" viewBox="0 0 24 24" aria-hidden="true">{ICONS[icon]}</svg>'
        if main:
            name, digest, size = main
            label = ("Download Varsto.app (Apple Silicon)" if not name.endswith("-lite.zip") else "Download Varsto.app (interim, Apple Silicon)") if title == "macOS" else ("Download the Windows installer" if name.endswith("-setup.exe") else "Download for Windows (zip)") if title == "Windows" else f"Download for {html.escape(title)}"
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
        + verify_section(pre, version)
    )


def verify_section(pre: str, version: str) -> str:
    """How to check a download against the signed checksum list."""
    key_lines = RELEASE_KEY.read_text().splitlines() if RELEASE_KEY.exists() else []
    if len(key_lines) < 2:
        return ""
    key = html.escape(key_lines[1].strip())
    key_id = html.escape(key_lines[0].rsplit(" ", 1)[-1])
    ver = html.escape(version or "<version>")
    return (
        '<details class="dl-all dl-verify"><summary>Verify your download</summary>'
        f'<p><a href="{pre}downloads/SHA256SUMS">SHA256SUMS</a> is signed with the Varsto release key '
        f'(<a href="{pre}downloads/SHA256SUMS.sig">SHA256SUMS.sig</a>, minisign format). The key is kept offline, '
        f'built into every <code>varsto</code> binary and published in the <a href="{REPO}/blob/main/release-key.pub">repository</a> '
        f'and <a href="{pre}release-key.pub">here</a>; key ID <code>{key_id}</code>:</p>'
        f'<pre><code>{key}</code></pre>'
        '<p>With Varsto already installed, put SHA256SUMS and SHA256SUMS.sig next to the download (or leave them out to fetch them) and run</p>'
        f'<pre><code>varsto verify-release varsto-{ver}-x86_64-unknown-linux-musl.tar.gz --github</code></pre>'
        '<p><code>--github</code> also compares the checksum with the list attached to the GitHub release, a second channel. '
        'Without Varsto, use <a href="https://jedisct1.github.io/minisign/">minisign</a> and then check the hash:</p>'
        f'<pre><code>minisign -Vm SHA256SUMS -x SHA256SUMS.sig -P {key}\nsha256sum -c --ignore-missing SHA256SUMS</code></pre>'
        '<p><code>varsto update</code> does all of this by itself and refuses an update whose signature or checksum does not match.</p>'
        '</details>'
    )


_TRANSLATED: dict[str, set[str]] = {}


def translated(lang: str, rel: str) -> bool:
    """Whether page `rel` (relative to the language root) has a translation."""
    if lang not in _TRANSLATED:
        outs = set()
        for src in (SRC / "i18n" / lang / "pages").glob("*.html"):
            meta, _ = front_matter(src.read_text())
            outs.add(meta.get("output", f"{src.stem}.html"))
        _TRANSLATED[lang] = outs
    return rel in _TRANSLATED[lang]


def build_translated_pages() -> None:
    for lang, _ in LANGS[1:]:
        for src in sorted((SRC / "i18n" / lang / "pages").glob("*.html")):
            meta, body = front_matter(src.read_text())
            rel = meta.get("output", f"{src.stem}.html")
            out_rel = f"{lang}/{rel}"
            depth = out_rel.count("/")
            body = fill(body, depth, lang)
            # {{L}}: this language's root (links between translated pages);
            # {{P}}: the site root (assets, docs, blog).
            body = body.replace("{{L}}", "../" * (depth - 1)).replace("{{P}}", "../" * depth)
            (OUT / out_rel).parent.mkdir(parents=True, exist_ok=True)
            (OUT / out_rel).write_text(page(meta["title"], meta.get("description", ""), body, meta["nav"], depth, lang, rel))


def cargo_version() -> str:
    m = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M)
    return m.group(1) if m else ""


def tree_counts() -> dict[str, str]:
    """Figures for the status section, counted from the tree: lines of Rust
    (rounded to a thousand), test functions and lab scenarios."""
    rust = tests = 0
    for f in ROOT.rglob("*.rs"):
        if "target" in f.parts or ".git" in f.parts:
            continue
        text = f.read_text(errors="ignore")
        rust += text.count("\n")
        tests += len(re.findall(r"^\s*#\[(?:tokio::)?test", text, re.M))
    lab = ROOT / "scripts" / "test" / "lab" / "scenarios.py"
    scenarios = len(re.findall(r'^@scenario\("', lab.read_text(), re.M)) if lab.exists() else 0
    return {"RUST_LINES": f"{round(rust, -3):,}".replace(",", " "), "TESTS": str(tests), "LAB_SCENARIOS": str(scenarios)}


# The daily build channel: the page body is filled from src/data/daily.json,
# which website/tools/daily/make_daily.py writes. The files themselves live on
# the server under daily/ and are not part of the generated site.
DAILY_JSON = SRC / "data" / "daily.json"
DAILY_I18N = {
    "en": {
        "build": 'Latest build <strong>{id}</strong>, {date}; version string {version}. <a href="{pre}daily/latest.json">latest.json</a> · <a href="{pre}daily/latest/SHA256SUMS">SHA256SUMS</a>',
        "cols": ("Platform", "Download", "Size", "Built from", "SHA-256"),
        "dated": "dated copy",
        "build_word": "build",
        "main": 'The main line at commit <a href="{repo}/commit/{c}">{c}</a>.',
        "prs": "Open pull requests merged on top: {list}.",
        "note": "",
        "ci": 'CI run: <a href="{url}">{url}</a>',
        "gaps": {},
    },
    "fi": {
        "build": 'Uusin versio <strong>{id}</strong>, {date}; versiotunnus {version}. <a href="{pre}daily/latest.json">latest.json</a> · <a href="{pre}daily/latest/SHA256SUMS">SHA256SUMS</a>',
        "cols": ("Alusta", "Lataus", "Koko", "Rakennettu commitista", "SHA-256"),
        "dated": "päivätty kopio",
        "build_word": "versio",
        "main": 'Päähaara commitissa <a href="{repo}/commit/{c}">{c}</a>.',
        "prs": "Päälle liitetyt avoimet pull requestit: {list}.",
        "note": "Lisäksi pieniä CI-korjauksia.",
        "ci": 'CI-ajo: <a href="{url}">{url}</a>',
        "gaps": {
            "unsigned": "Les versions n’ont ni signature de version ni signature de code Apple ou Microsoft. Seule la liste de sommes de contrôle est signée, par une clé quotidienne distincte qui ne vaut que pour le canal quotidien.",
            "not-format-2": "Muotoa 2 (tietueiden uudistus) ei ole mukana; kun se tulee, näillä versioilla luodut holvit täytyy luoda uudelleen.",
            "os-warnings": "macOS, Windows ja iOS varoittavat allekirjoittamattomasta ohjelmistosta; macOS:ssä avaus onnistuu hiiren oikealla painikkeella ja Avaa, Windowsissa SmartScreen pyytää vahvistusta.",
            "windows-ci-only": "Windows-asennusohjelma on savutestattu vain CI:ssä (asennus, päivitys, korjaus, vanhempaan versioon palaamisen esto, poisto), ei oikealla koneella.",
            "ios-untested": "iOS-ipa:a ei ole ajettu oikealla laitteella. Asenna se AltStorella, SideStorella tai Sideloadlyllä.",
            "ui-strings": "Osa sovelluksen käyttöliittymän teksteistä on vielä kääntämättä; ne kirjataan lokiin.",
            "windows-ios-previous": "Windows et iOS viennent toujours de la version précédente 20261016-316c579 ; ils n’ont pas été reconstruits cette fois.",
            "grace-default": "Le délai de grâce avant d’abandonner un stockage en retard (paquet E) est de 30 jours par défaut.",
            "devices-unverified": "Le code plein écran Kotlin, Swift et Windows et le correctif d’appairage n’ont pas été vérifiés sur de vrais appareils.",
            "first-daily-update": "La première mise à jour avec --daily exige un binaire qui contient déjà la fonction : installez cette version à la main une fois, ensuite varsto update --daily prend le relais.",
            "windows-ios-previous": "Windows och iOS kommer fortfarande från det föregående bygget 20261016-316c579; de byggdes inte om den här omgången.",
            "grace-default": "Respitiden innan en lagringsplats som har halkat efter ges upp (paket E) är som standard 30 dagar.",
            "devices-unverified": "Kotlin-, Swift- och Windows-helskärmskoden samt parningsrättningen har inte verifierats på riktiga enheter.",
            "first-daily-update": "Den första uppdateringen med --daily kräver en binär som redan har funktionen, så installera det här bygget för hand en gång; därefter kan varsto update --daily ta över.",
            "windows-ios-previous": "Windows ja iOS ovat edelleen edellisestä versiosta 20261016-316c579; niitä ei rakennettu tällä kierroksella.",
            "grace-default": "Määräaika, jonka jälkeen jälkeen jäänyt tallennuspaikka jätetään (paketti E), on oletuksena 30 päivää.",
            "devices-unverified": "Kotlin-, Swift- ja Windows-kokoruutukoodia sekä pariutuskorjausta ei ole varmistettu oikeilla laitteilla.",
            "first-daily-update": "Ensimmäinen --daily-päivitys vaatii ohjelman, jossa ominaisuus jo on, joten asenna tämä versio kerran käsin; sen jälkeen varsto update --daily hoitaa loput.",
        },
    },
    "sv": {
        "build": 'Senaste bygget <strong>{id}</strong>, {date}; versionssträng {version}. <a href="{pre}daily/latest.json">latest.json</a> · <a href="{pre}daily/latest/SHA256SUMS">SHA256SUMS</a>',
        "cols": ("Plattform", "Nedladdning", "Storlek", "Byggd från", "SHA-256"),
        "dated": "daterad kopia",
        "build_word": "bygge",
        "main": 'Huvudgrenen vid commit <a href="{repo}/commit/{c}">{c}</a>.',
        "prs": "Öppna pull requests som lagts ovanpå: {list}.",
        "note": "Dessutom små CI-rättningar.",
        "ci": 'CI-körning: <a href="{url}">{url}</a>',
        "gaps": {
            "unsigned": "Inget är signerat: ingen releasesignatur och ingen kodsignering från Apple eller Microsoft. Kontrollsummorna upptäcker bara en trasig nedladdning.",
            "not-format-2": "Format 2 (omarbetningen av posterna) ingår inte; när det kommer måste valv som skapats med dessa byggen skapas om.",
            "os-warnings": "macOS, Windows och iOS varnar för osignerad programvara; på macOS öppnar du med högerklick och Öppna, på Windows ber SmartScreen om bekräftelse.",
            "windows-ci-only": "Windows-installationsprogrammet har bara röktestats i CI (installation, uppgradering, reparation, nekad nedgradering, avinstallation), inte på en riktig dator.",
            "ios-untested": "iOS-ipa:n har inte körts på en riktig enhet. Installera den med AltStore, SideStore eller Sideloadly.",
            "ui-strings": "Vissa texter i appens gränssnitt är ännu inte översatta; de loggas.",
        },
    },
    "fr": {
        "build": 'Dernière version <strong>{id}</strong>, {date} ; chaîne de version {version}. <a href="{pre}daily/latest.json">latest.json</a> · <a href="{pre}daily/latest/SHA256SUMS">SHA256SUMS</a>',
        "cols": ("Plateforme", "Téléchargement", "Taille", "Construit depuis", "SHA-256"),
        "dated": "copie datée",
        "build_word": "version",
        "main": 'La branche principale au commit <a href="{repo}/commit/{c}">{c}</a>.',
        "prs": "Pull requests ouvertes fusionnées par-dessus : {list}.",
        "note": "Plus de petites corrections de CI.",
        "ci": 'Exécution CI : <a href="{url}">{url}</a>',
        "gaps": {
            "unsigned": "Rien n’est signé : ni signature de version, ni signature de code Apple ou Microsoft. Les sommes de contrôle ne détectent qu’un téléchargement corrompu.",
            "not-format-2": "Le format 2 (la refonte des enregistrements) n’est pas inclus ; lorsqu’il arrivera, les coffres créés avec ces versions devront être recréés.",
            "os-warnings": "macOS, Windows et iOS avertissent à propos des logiciels non signés ; sous macOS, ouvrez par clic droit puis Ouvrir, sous Windows SmartScreen demande une confirmation.",
            "windows-ci-only": "Le programme d’installation Windows n’a subi qu’un test de fumée en CI (installation, mise à jour, réparation, refus de rétrogradation, désinstallation), pas sur une vraie machine.",
            "ios-untested": "L’ipa iOS n’a pas été exécuté sur un vrai appareil. Installez-le avec AltStore, SideStore ou Sideloadly.",
            "ui-strings": "Certains textes de l’interface de l’application ne sont pas encore traduits ; ils sont consignés dans les journaux.",
        },
    },
}


def daily_blocks(lang: str, depth: int) -> dict[str, str]:
    """The pieces of the daily page: BUILD, TABLE, INCLUDED, GAPS, HISTORY."""
    t = DAILY_I18N[lang]
    pre = "../" * depth
    data = json.loads(DAILY_JSON.read_text())
    cur = data["current"]
    e = html.escape
    rows = "\n".join(
        f'<tr><th scope="row">{e(p["label"])}</th>'
        f'<td><a href="{pre}daily/latest/{e(p["latest"])}">{e(p["latest"])}</a><br>'
        f'<span class="dl-meta"><a href="{pre}daily/builds/{e(p.get("build", cur["id"]))}/{e(p["file"])}">{t["dated"]}</a> · {t["build_word"]} <code>{e(p.get("build", cur["id"]))}</code></span></td>'
        f'<td>{p["size"] / 1048576:.1f} MB</td>'
        f'<td><a href="{REPO}/commit/{e(p["commit"])}"><code>{e(p["commit"])}</code></a></td>'
        f'<td><code class="sum">{p["sha256"]}</code></td></tr>'
        for p in cur["platforms"]
    )
    head = "".join(f"<th>{e(c)}</th>" for c in t["cols"])
    included = [t["main"].format(repo=REPO, c=e(cur["main_commit"]))]
    if cur["prs"]:
        links = ", ".join(f'<a href="{REPO}/pull/{n}">#{n}</a>' for n in cur["prs"])
        included.append(t["prs"].format(list=links))
    if cur.get("note"):
        included.append(e(cur["note"]) if lang == "en" else t["note"])
    if cur.get("ci_run"):
        included.append(t["ci"].format(url=e(cur["ci_run"])))
    gaps = [t["gaps"].get(g["id"], g["text"]) for g in data["known_gaps"]]
    history = [f'<li><a href="{pre}daily/builds/{e(h["id"])}/">{e(h["id"])}</a> ({e(h["date"])})</li>' for h in [cur] + data["history"]]
    return {
        "BUILD": '<p class="lead">' + t["build"].format(id=e(cur["id"]), date=e(cur["date"]), version=e(cur["version"]), pre=pre) + "</p>",
        "TABLE": f'<table class="downloads"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>',
        "INCLUDED": "<ul>" + "".join(f"<li>{x}</li>" for x in included) + "</ul>",
        "GAPS": "<ul>" + "".join(f"<li>{e(x)}</li>" for x in gaps) + "</ul>",
        "HISTORY": "<ul>" + "".join(history) + "</ul>",
    }


def fill(body: str, depth: int, lang: str = "en") -> str:
    """The placeholders every page body may use."""
    body = body.replace("{{DOWNLOADS}}", downloads_table(depth)).replace("{{POSTS}}", posts_list(depth))
    if "{{DAILY_" in body:
        for key, value in daily_blocks(lang, depth).items():
            body = body.replace("{{DAILY_" + key + "}}", value)
    body = body.replace("{{VERSION}}", cargo_version()).replace("{{RELEASED}}", RELEASED_VERSION)
    for key, value in COUNTS.items():
        body = body.replace("{{" + key + "}}", value)
    return body


def build_pages(slug_by_name: dict[str, str]) -> None:
    for src in sorted((SRC / "pages").glob("*.html")):
        meta, body = front_matter(src.read_text())
        out_rel = meta.get("output", f"{src.stem}.html")
        depth = out_rel.count("/")
        body = fill(body, depth)
        body = body.replace("{{P}}", "../" * depth)
        (OUT / out_rel).parent.mkdir(parents=True, exist_ok=True)
        (OUT / out_rel).write_text(page(meta["title"], meta.get("description", ""), body, meta["nav"], depth, "en", out_rel))


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
        body = (f"<article class=\"prose\">\n<h1>{html.escape(title)}</h1>\n<p class=\"note\">From <code>{html.escape(path)}</code> in the repository, rendered {datetime.now(timezone.utc).date()}. "
                f"These documents describe the main branch; the released version is {RELEASED_VERSION}. Sections marked 'after {RELEASED_VERSION}' are not in a release yet.</p>\n{body}\n</article>")
        (OUT / "docs").mkdir(parents=True, exist_ok=True)
        (OUT / "docs" / f"{slug}.html").write_text(page(title, f"{BRAND} documentation: {title}", body, "Docs", 1, rel=f"docs/{slug}.html"))
        groups.setdefault(group, []).append((slug, title))
    # Licence page from the plain-text LICENSE.
    licence = (ROOT / "LICENSE").read_text()
    body = f"<article class=\"prose\"><h1>Licence</h1><p class=\"note\">PolyForm Shield License 1.0.0, verbatim from <code>LICENSE</code>.</p><pre class=\"licence\">{html.escape(licence)}</pre></article>"
    (OUT / "docs" / "licence.html").write_text(page("Licence", f"{BRAND} licence", body, "Docs", 1, rel="docs/licence.html"))
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
        "    <p class=\"lead\">The documents below are rendered from the repository. They describe what the current alpha does and what the full design intends; every design document says which parts exist.</p>\n"
        + "\n".join(sections)
    )
    (OUT / "docs" / "index.html").write_text(page("Docs", f"{BRAND} documentation", body, "Docs", 1, rel="docs/index.html"))
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
        (OUT / "blog" / f'{post["slug"]}.html').write_text(page(post["title"], post["summary"], body, "Blog", 1, rel=f'blog/{post["slug"]}.html',
                 extra_head=json_ld({"@context": "https://schema.org", "@type": "BlogPosting", "headline": post["title"],
                                     "description": post["summary"], "datePublished": post["date"],
                                     "url": f'{SITE_URL}/blog/{post["slug"]}.html', "inLanguage": "en",
                                     "author": {"@type": "Organization", "name": f"The {BRAND} Authors"},
                                     "image": f"{SITE_URL}/assets/img/og-card.png"})))
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
    text = re.sub(r'<a href="([a-z-]+/)"', r'<a href="/\1"', text)
    text = text.replace('<a href="./"', '<a href="/"').replace('href=""', 'href="/"')
    (OUT / "404.html").write_text(text)


# Pages that moved: old output path -> new path relative to the site root. The old
# URL keeps working as a small page that sends the browser on (meta refresh, no
# script, so the strict CSP holds) and names the new address as canonical.
REDIRECTS = {
    "encryption/index.html": ("how-it-works/", "How it works"),
}


def build_redirects() -> None:
    for old, (new, title) in REDIRECTS.items():
        p = "../" * old.count("/")
        target = f"{p}{new}"
        text = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}: {BRAND}</title>
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<meta http-equiv="refresh" content="0; url={target}">
<link rel="canonical" href="{SITE_URL}/{new}">
<link rel="icon" href="{p}favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="{p}assets/css/site.css?v={asset_version("assets/css/site.css")}">
</head>
<body>
<main id="main">
  <div class="wrap">
    <p class="lead">This page has moved to <a href="{target}">{html.escape(title)}</a>.</p>
  </div>
</main>
</body>
</html>
"""
        (OUT / old).parent.mkdir(parents=True, exist_ok=True)
        (OUT / old).write_text(text)


def copy_data() -> None:
    """Data files pages link to (benchmark results) are published as they are."""
    for src in sorted((SRC / "data").glob("*.json")):
        if src.name == "daily.json":  # input of the daily page, not published as it is
            continue
        (OUT / "data").mkdir(parents=True, exist_ok=True)
        (OUT / "data" / src.name).write_bytes(src.read_bytes())


COUNTS = tree_counts()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    if RELEASE_KEY.exists():
        shutil.copyfile(RELEASE_KEY, OUT / "release-key.pub")
    if DAILY_KEY.exists():
        shutil.copyfile(DAILY_KEY, OUT / "daily-key.pub")
    slugs = build_docs()
    build_blog(slugs)
    build_pages(slugs)
    build_translated_pages()
    copy_data()
    build_404()
    build_redirects()
    build_sitemap()
    print(f"built into {OUT}")


def build_sitemap() -> None:
    """sitemap.xml with every page (redirect stubs and the 404 page left
    out), and robots.txt that allows crawling and names the sitemap."""
    pages = []
    for f in sorted(OUT.rglob("*.html")):
        rel = f.relative_to(OUT).as_posix()
        if rel == "404.html" or rel.startswith("downloads/"):
            continue
        text = f.read_text(errors="ignore")
        if 'http-equiv="refresh"' in text:
            continue
        loc = rel.removesuffix("index.html")
        pages.append((loc, f.stat().st_mtime))
    from datetime import datetime, timezone as tz
    rows = "".join(
        f"  <url><loc>{SITE_URL}/{loc}</loc><lastmod>{datetime.fromtimestamp(m, tz.utc).date()}</lastmod></url>\n"
        for loc, m in pages
    )
    (OUT / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + rows + "</urlset>\n"
    )
    (OUT / "robots.txt").write_text(f"User-agent: *\nAllow: /\n\nSitemap: {SITE_URL}/sitemap.xml\n")


if __name__ == "__main__":
    main()
