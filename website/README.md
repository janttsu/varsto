# Website

Static site for the project: **Project** (front page), **Docs** (rendered from the repository), **Downloads**, **Blog** (with RSS) and **Forum** (GitHub issues and discussions for now; a forum of its own is planned). Every page shows the alpha warning. The pages are in English, Finnish, Swedish and French (`website/src/i18n/<lang>/pages/`); docs, blog and the generated downloads block are English only.

- No inline scripts or styles, no third-party resources, system fonts: the strict Content Security Policy on the server stays valid.
- Light and dark themes (follows the system, with a manual toggle).
- `RELEASED_VERSION` in `build.py` is the last tagged release; update it when tagging. `{{VERSION}}` follows `Cargo.toml`, so it may be ahead of the release on main.

## Build

```bash
website/build-release.sh          # release archives into website/public/downloads (needs rustup targets)
python3 website/build.py          # renders src/pages, src/posts and the repository docs into website/public
python3 -m http.server -d website/public 8080   # preview
```

`build.py` needs `pandoc`. Sources live in `website/src/`; the rendered pages in `website/public/` are committed, the downloads directory is not. The status counts on the front page (lines of Rust, tests, lab scenarios) are counted from the tree at build time.

Download cards: with a download set in `website/public/downloads` (`SHA256SUMS`, `manifest.json`) the cards come from it. Without one, `build.py` reads the live site's list, read-only (`DOWNLOADS_SOURCE_URL`, default `https://varsto.net/downloads/`; an empty value turns this off), so a plain checkout renders the real cards instead of "No binaries are published yet". If neither is available the stub is rendered and `deploy.sh` refuses to upload it (`ALLOW_DOWNLOAD_STUB=1` overrides, for a site that really has no binaries). `DEPLOY_HOST=local` copies to the directory `DEPLOY_PATH` on this machine, for dry runs.

Screenshots are not part of a deploy: CI takes them on every build for every platform and language (English, Finnish, Swedish interface, the full-screen visualization picture) and the web server pulls them (`ops/site/screenshots-sync.py`, see RELEASING.md). `deploy.sh` never touches `assets/img/screenshots*/` or `assets/img/viz-tv.png` on the server, nor `/testbuilds/` and `/daily/` files.

## Deploy

```bash
DEPLOY_HOST=user@host DEPLOY_PATH=/path/to/webroot website/deploy.sh
```

Host and path are never committed. The web server (TLS, headers, access-log rotation) is configured on the server side.

## Operations checklist

- Access log: time-based rotation, at most seven days (a size-only rotation keeps IP addresses for months on a low-traffic site). Caddy example: `roll_keep_for 168h`.
- DNS: keep DNSSEC on; add a CAA record for the certificate authority in use (Let's Encrypt: `0 issue "letsencrypt.org"`).
- `.well-known/security.txt`: rename the template and fill in the contact once a security contact exists.
- Re-check the response headers (CSP, HSTS, X-Frame-Options, X-Robots-Tag) after every deploy.
- Downloads: `SHA256SUMS` is signed (`SHA256SUMS.sig`, minisign format) with the offline release key; sign with `scripts/sign-release.sh` after the last file is added (see RELEASING.md). `deploy.sh` refuses to publish a checksum list whose signature does not verify.
