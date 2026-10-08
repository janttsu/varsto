# Website template

Static site with four sections: **Project** (front page), **Docs**, **Forum**, **Blog**. All text is placeholder and in English. Every page shows the alpha warning.

- No build step; plain HTML, one CSS file and one small script.
- Strict Content Security Policy friendly: no inline scripts or styles, no third-party resources, system fonts.
- Light and dark themes (follows the system, with a manual toggle).
- `robots.txt` and `noindex` are on while the product name is provisional. Remove them deliberately before launch.

## Preview

```
python3 -m http.server -d website/public 8080
```

## Deploy

```
DEPLOY_HOST=user@host DEPLOY_PATH=/path/to/webroot website/deploy.sh
```

Host and path are never committed. The web server (TLS, headers) is configured on the server side.
