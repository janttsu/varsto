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
