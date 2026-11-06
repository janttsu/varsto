# Handover

State of the project for whoever (or whatever) picks it up next. Keep this
file current in every pull request that changes the state it describes.
English only, no personal data, no secrets.

## State on 2026-11-06

- The repository is <https://github.com/janttsu/varsto>. The old Bitbucket
  repository holds only a commit that points here; do not push to it.
- `main` is `46adda31` (PR #108: `GH_REPO` for the publishing jobs) on
  top of tag `v0.0.1-alpha.16` = `64346c5f` (PR #107). The copy of this
  file on `main` still describes 2026-11-04 (`main` as `64346c5f`, daily
  `20261103-64346c5`); this branch is the correction. Release
  0.0.1-alpha.16 is published on GitHub and at <https://varsto.net/downloads/>
  with `SHA256SUMS` signed by the release key. The published daily is
  `20261104-46adda3` of `46adda31` for every platform (Linux, Windows
  setup, macOS, Android, iOS `.ipa`, rendezvous binary). The Android
  object is still named `varsto-daily-android-debug.apk`; the bytes are
  the release build. A rebuild of the same commit was started on
  2026-11-06 (Actions run 42208674730) and is not the published daily
  until that run succeeds. `Cargo.toml` is `0.0.1-alpha.16`.
- What alpha.16 contains: [CHANGELOG.md](CHANGELOG.md) section
  `[0.0.1-alpha.16]` and the blog post under `website/src/posts/`. In short:
  storage format 3 (vaults of alpha.15 and earlier must be recreated), folder
  access by an owner's approval (also from the interface: Request access),
  recovery words, the rendezvous service, offline-first joining and sync, the
  Import page with torrent and YouTube imports, the mailbox for offline disks,
  the fixes of the 2026-10-30 code review, a release-signed Android APK and
  `disk init` without `wipefs`.
- Every branch of the format 3, offline, rendezvous and review work is
  merged. The branches still unmerged on GitHub (`bugfix-ui`,
  `ci-all-platforms`, `deps-rustls`, `format2-records`, `ios-ipa`,
  `policy-device-copies`, `test-latest`, `torrent-spool`, `visualization`,
  `windows-installer`) date from 2026-10-10 to 2026-10-16, before format 3,
  and look superseded; delete them after a look, do not merge them.
- The code review of 2026-10-30 (15 areas, 19 HIGH findings, none critical)
  is documented outside the repository; its fixes are the `fix/*` branches
  merged through `integrate/review-20261031` into PR #107.

## Open pull requests, not merged

Based on `main` = `46adda31`. Pull requests are open. CI on #109–#113 was
cancelled before any package was uploaded, so those branches are still
unbuilt. Each code branch adds its own line under `## Unreleased` in
CHANGELOG.md, so the later merges have small text conflicts there and in
this file. Do not merge until CI is green.

- #110 `fix/default-policy-own-disks` (`ed14001d`): a folder on the default
  policy in a vault without a disk pool or directory storage shows a warning
  ("no own disk") with the reason under the bar, instead of "violated".
- #111 `fix/list-thumbnails` (`bf17d84a`): small thumbnails in the file list on
  phones. `/api/thumb` answers 503 with `Retry-After` while the engine is
  busy (404 only when there is no thumbnail); the list loads two at a time,
  retries with backoff and keeps a memory cache.
- #112 `feat/notify-channels` (`14a095d0`): push notifications through ntfy (also
  self-hosted), Pushover and a Telegram bot: `varsto_core::notify`, the
  Notifications card in Settings with a guided setup per service, `varsto
  notify …`, [docs/notifications.md](docs/notifications.md). About 4 000 new
  lines; the external APIs have not been called for real.
- #113 `fix/pause-stops-p2p` (`d60aac69`): pausing the service stops peer-to-peer
  too, and the user's pause survives a restart (`<home>/service-paused`).
  Check on a phone that Varsto traffic stops, and whether pairing needs
  peer-to-peer while paused.
- #109 `docs/build-and-lab` (this branch): BUILDING.md, the lab runbook, the
  benchmarks guide and fixes of stale references. Documentation only.
- #114 `website/search-snippets` (`cc65856`): search titles and
  descriptions, `data-nosnippet` on the alpha warning, and a developer
  section in English, Finnish, Swedish and French. The static site was
  built and deployed to <https://varsto.net> on 2026-11-06. It is not on
  `main`, so the next deploy from `main` would put the previous pages
  back. The interface catalogues `fi.json` and `sv.json` have the same
  keys. Blog and forum stay English only. The translations still await
  a native check.

Older experiments, pushed so they are not lost, written before storage
format 3 and not merged: `dht-discovery` (`40a84ae0`, peers through the
Mainline DHT) and `ios-camera-viewer` (`f6736178`, iOS camera upload and a
native viewer). They need rework on top of `main` before any merge.

## Open

- Membership (from the review, not fixed): a gap that stays below the
  sequence cap, `Membership::join` without an administrator list, a member of
  another vault does not apply the roster cap, and a folder key already shared
  cannot be revoked (spec 21). Medium findings of the review are not
  re-checked: CRYPTO-1 (the recovery kit text of format 2), imports-1 (restic
  mirror umask), logging-1/-4 (scrubber gaps), CLI-3/-4 (`current_exe()` after
  an update), QUALITY-1/-2 (mutex `unwrap()` in service.rs, `set_var`).
- GitHub settings the workflows cannot make: branch protection on `main` and
  a protected environment for the daily key.
- A full lab run (`scripts/test/lab`, every scenario) with the alpha.16
  binary has not been done since the review fixes.
- Android: the APK is signed with a new release key. An installation of an
  earlier debug APK (alpha.15 or an older daily) does not update over it: it
  must be uninstalled first, which removes that device's copy of the vault.
  The daily file name stays `varsto-daily-android-debug.apk` (the signed list
  keeps the name); the bytes are the release build.
- Interface: after an owner approves a request, the asking phone shows the new
  state at its next status poll, not at once; the activity-log line of a
  "holds no key" error has no button.
- The Finnish, Swedish and French texts of the interface and the website are
  machine translations awaiting a native check.
- CI: on the v0.0.1-alpha.16 tag the two publishing jobs (draft release,
  screenshots-latest) failed because `gh` ran without a checkout and without
  `GH_REPO`; the release assets and screenshots were uploaded by hand from the
  run's artifacts, and PR #108 adds `GH_REPO` so the next tag works unattended.

## How things are done

- Building every platform, the CI workflows, the Scaleway fallback, screenshots, the daily channel and the website: [BUILDING.md](BUILDING.md). Releases and signing: [RELEASING.md](RELEASING.md). CI builds
  every platform on GitHub-hosted runners (Linux about 1 h 45 min, macOS about
  1 h 10 min); the maintainer signs offline. The daily workflow signs in CI
  with the repository secret `VARSTO_DAILY_KEY`; the Android release signing
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
