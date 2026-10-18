# Website operations

- `screenshots-sync.py`, `.service`, `.timer`: the web server pulls the
  screenshots of the newest successful CI build (the rolling GitHub
  pre-release `screenshots-latest`, published by the `screenshots` job of
  `.github/workflows/ci.yml` on every push to `main` and every tag) and
  writes their sizes and origin into the Screenshots page. Install as a
  systemd user unit:

  ```
  install -m 755 ops/site/screenshots-sync.py ~/bin/varsto-screenshots-sync.py
  cp ops/site/screenshots-sync.{service,timer} ~/.config/systemd/user/
  systemctl --user daemon-reload && systemctl --user enable --now screenshots-sync.timer
  ```

  The package has `en/`, `fi/`, `sv/`, `viz/` and `shots.json`; the script
  writes them to `assets/img/screenshots/`, `screenshots-fi/`,
  `screenshots-sv/` and `assets/img/viz-tv.png`. Nothing changes in the
  installed unit or timer. `website/deploy.sh` leaves those paths on the
  server alone, so a deploy never puts older pictures back. Dry run without
  the server: `python3 -I ops/site/tests/test_screenshots_sync.py`.

- `daily-sync.py` (and `test_daily_sync.py`): the daily channel. The workflow
  `.github/workflows/daily.yml` builds all platforms at 03:00 UTC when `main`
  has moved, signs the file list with the daily key (repository secret
  `VARSTO_DAILY_KEY`) and publishes it as the assets of the rolling GitHub
  pre-release `daily` (recreated each run, `v*` tags untouched). The server
  pulls it from cron; nothing on GitHub can write to the server:

  ```
  install -m 755 ops/site/daily-sync.py ~/bin/varsto-daily-sync.py
  # crontab -e (the build starts 03:00 UTC and takes a while; hourly is enough)
  17 * * * * /usr/bin/python3 $HOME/bin/varsto-daily-sync.py $HOME/sites/varsto/public >> $HOME/.cache/varsto-daily-sync.log 2>&1
  ```

  It verifies `SHA256SUMS.sig` against the embedded daily public key (Ed25519
  over the BLAKE2b-512 hash plus the signed trusted comment, the format of
  `scripts/sign-daily.sh`; it uses the `cryptography` package when importable,
  else a built-in pure-Python RFC 8032 verifier), checks every size and
  SHA-256, and only then writes below `<site>/daily/`. It never touches
  `downloads/`, `testbuilds/` or the site pages:

  ```
  daily/builds/<id>/              files (stable names), SHA256SUMS, SHA256SUMS.sig,
                                  latest.json, index.html, shots/ (from the screenshots tarball)
  daily/latest/<name>             relative symlinks into ../builds/<newest id>/
  daily/latest/SHA256SUMS(.sig)   copies, for `varsto update --daily`
  daily/latest.json               newest build plus the list of kept builds (read by the page)
  ```

  The newest 7 builds are kept. A build older than the newest one present is
  refused (rollback), a build that is already present is skipped, and a
  failed check leaves the published state as it was. `/daily/` is a static
  page that reads `daily/latest.json` (`assets/js/daily.js`), so a new build
  needs no site deploy. `website/tools/daily/make_daily.py` stays as the manual
  path for a build made elsewhere (same layout; sign with
  `scripts/sign-daily.sh`).

  One-time steps: put the private key in the repository secret
  (`gh secret set VARSTO_DAILY_KEY < ~/.config/varsto-release/daily-key.pem`),
  install the cron line, then run the workflow by hand once with `publish`
  false and once with `publish` true (Actions, Daily builds, Run workflow).
  Tests: `python3 -I -m unittest discover -s ops/site -p 'test_*.py'`
  (needs OpenSSL 3; CI runs them).
