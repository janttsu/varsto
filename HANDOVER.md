# Handover

State of the project for whoever (or whatever) picks it up next. Keep this
file current in every pull request that changes the state it describes.
English only, no personal data, no secrets.

## State on 2026-11-23

- The repository is <https://github.com/janttsu/varsto>. Do not push to the
  old Bitbucket repository.
- `main` is `d72b31f1`. `Cargo.toml` is `0.0.1-alpha.17`. Tag
  `v0.0.1-alpha.17` is the annotated tag `be805a0c` on commit `a5f07263`
  (PR #138). The GitHub release is public, not a draft, published
  2026-11-22, with `SHA256SUMS` signed by the release key. The binaries are
  that commit's tag CI, not the website and test commits that landed on
  `main` afterwards (home page, blog languages, screenshot languages, the
  attach-after-sync assertion). Storage format is unchanged from alpha.16.
- The published daily is `Daily build 20261122-a5f0726` (pre-release tag
  `daily`, commit `a5f07263`). The site serves it at
  <https://varsto.net/daily/>. The Android object is still named
  `varsto-daily-android-debug.apk`; the bytes are the release build.
- The live site is the alpha.17 look (not the Carbon preview). Blog posts
  exist in every site language. Docs and the forum stay English. Screenshot
  captions and the download list for alpha.17 are on
  `website/alpha17-screenshots` (`7bdaeba5`), pushed, no pull request.
  Opening a pull request starts CI, which builds every platform.
- `preview/carbon-ui` is a restyle preview. It is not the production look
  and must not replace the public daily. <https://varsto.net/beta/> returns
  404.
- The only open pull request is #131 (`site/search-job`, homepage wording,
  last touched 2026-11-09). It is stale relative to `main`.

## Pushed, not compiled, no pull request

A pull request runs `.github/workflows/ci.yml` and builds packages. These
branches were pushed without one, and no local `cargo` build was run.

- `feat/daily-unlock` (code `bd1cf784`, then the commit that updates this
  file): a device can enrol a FIDO2
  security key for daily unlock (`varsto unlock-key`, or Daily unlock in
  Settings). The passphrase still takes part. Each key has its own wrap, and
  the passphrase-only copy of `keys.enc` is removed. A device with no key
  enrolled opens as before. There is no OS keystore factor, and the key is
  not mandatory. The service does not wait for a touch at startup. The
  interface language list includes French (`fr.json`, tray, macOS menu, iOS
  start strings). German, Spanish and Russian were read for terminology and
  broken patterns; the settings line that named only English, Finnish and
  Swedish now names every interface language. Unit tests are in
  `vault.rs` and were not run.
- `site/device-sites` (`fa0cf254`, parent `8dac67ad`, based on `d72b31f1`):
  `varsto device site` or Set site in Settings. Devices that publish the
  same site are one failure domain for blocks with no storage copy. A device
  with no site counts alone. Storage place rules are unchanged.

## Left alone

- Do not merge `dht-discovery` (`40a84ae0`) or `ios-camera-viewer`
  (`f6736178`) as they are. Both predate format 3.
- Two devices that are both behind NAT still have a path when the
  rendezvous is on (`https://varsto.net/rv`, since alpha.16). The use-case
  page and the failure model still say there is no path. The DHT is not
  built and would not punch two symmetric NATs. Storage credentials are not
  rotated when a device is removed; `varsto storage mark-rotated` only
  clears the warning.
- `main` is protected (no deletion, no force push, changes only through
  pull requests). The `daily` environment publishes only from `main`.
  `daily.yml` runs on `workflow_dispatch`, not on a schedule.

## How things are done

- Building every platform, the CI workflows, the Scaleway fallback, screenshots, the daily channel and the website: [BUILDING.md](BUILDING.md). Releases and signing: [RELEASING.md](RELEASING.md). CI builds
  every platform on GitHub-hosted runners (Linux about 1 h 45 min, macOS about
  1 h 10 min); the maintainer signs offline. The daily workflow is started
  by hand and signs in CI with the secret `VARSTO_DAILY_KEY` of the `daily`
  environment (the package job runs from `main` only); the Android release signing
  uses the `VARSTO_ANDROID_*` secrets. The private keys live only on the
  maintainer's machine (`~/.config/varsto-release/`, mode 600) and are never
  printed or committed.
- Local builds go to `/mnt/ssd/varsto-lab/cargo-target-<branch>` with
  `-j 2`; the root disk is nearly full. Prefer CI for anything heavier than a
  unit test. The packaging scripts read `<repo>/target`, so for them link
  `target` to that directory instead of setting `CARGO_TARGET_DIR`
  (BUILDING.md, "A layout for build outputs").
- Commits: the maintainer's noreply identity, `TZ=UTC`, no attribution
  trailers of any kind. Pull requests against `main`; never a direct push,
  never a force push. Everything in the repository is in English and holds no
  personal data (the demo vault is invented).
- Tests: [TESTING.md](TESTING.md). The lab (`scripts/test/lab`) must cover
  every scenario before a release, not only the changed areas; the
  step-by-step runbook is [docs/testing/lab.md](docs/testing/lab.md).
  Benchmarks and real-NAT tests: [docs/testing/benchmarks.md](docs/testing/benchmarks.md).
