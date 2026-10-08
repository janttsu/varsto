# Website

Static site for the project: **Project** (front page), **Docs** (rendered from the repository), **Downloads**, **Blog** (with RSS) and **Forum** (placeholder until the public alpha). Every page shows the alpha warning. English only.

- No inline scripts or styles, no third-party resources, system fonts: the strict Content Security Policy on the server stays valid.
- Light and dark themes (follows the system, with a manual toggle).
- `robots.txt` and `noindex` stay on while the product name is provisional. Remove them deliberately before launch.

## Build

```bash
website/build-release.sh          # release archives into website/public/downloads (needs rustup targets)
python3 website/build.py          # renders src/pages, src/posts and the repository docs into website/public
python3 -m http.server -d website/public 8080   # preview
```

`build.py` needs `pandoc`. Sources live in `website/src/`; the rendered pages in `website/public/` are committed, the downloads directory is not.

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
- Footer: once the repository is public, change "Source will be published ..." to "Source-available under the PolyForm Shield License 1.0.0" in `website/build.py`.
- Downloads: checksums on the same page do not protect against a compromised site; signed releases and a second channel are planned.
