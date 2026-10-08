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

## Security contact

A template for the security policy is provided at `website/public/.well-known/security.txt.template`. Rename it to `security.txt` and fill in the contact information once a security contact is established.

## Deploy

```
DEPLOY_HOST=user@host DEPLOY_PATH=/path/to/webroot website/deploy.sh
```

Host and path are never committed. The web server (TLS, headers) is configured on the server side.

### Footer update for public launch

The footer currently states "Source will be published under the PolyForm Shield License 1.0.0 with the first alpha release." Once the repository is made public, update this sentence on all pages to "Source-available under the PolyForm Shield License 1.0.0."
