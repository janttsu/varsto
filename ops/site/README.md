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

  `website/deploy.sh` leaves `assets/img/screenshots/` on the server alone,
  so a deploy never puts older pictures back.
