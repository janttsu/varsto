# Handover

State of the project for whoever (or whatever) picks it up next. Keep this
file current in every pull request that changes the state it describes.
English only, no personal data, no secrets.

## State on 2026-11-04

- `main` is `64346c5f` = tag `v0.0.1-alpha.16` (PR #107). Release
  0.0.1-alpha.16 is published on GitHub and at <https://varsto.net/downloads/>
  with `SHA256SUMS` signed by the release key; the daily channel carries
  build `20261103-64346c5` of the same commit for every platform (Linux,
  Windows setup, macOS, Android, iOS `.ipa`, rendezvous binary).
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

## Open

- File-list thumbnails on Android (busy engine answered 404, list gave up): fix on branch worktree-agent-afe048943e4c22c1b, not compiled or tested yet.
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

- Releases and the daily channel: [RELEASING.md](RELEASING.md). CI builds
  every platform on GitHub-hosted runners (Linux about 1 h 45 min, macOS about
  1 h 10 min); the maintainer signs offline. The daily workflow signs in CI
  with the repository secret `VARSTO_DAILY_KEY`; the Android release signing
  uses the `VARSTO_ANDROID_*` secrets. The private keys live only on the
  maintainer's machine (`~/.config/varsto-release/`, mode 600) and are never
  printed or committed.
- Local builds go to `/mnt/ssd/varsto-lab/cargo-target-<branch>` with
  `-j 2`; the root disk is nearly full. Prefer CI for anything heavier than a
  unit test.
- Commits: the maintainer's noreply identity, `TZ=UTC`, no attribution
  trailers of any kind. Pull requests against `main`; never a direct push,
  never a force push. Everything in the repository is in English and holds no
  personal data (the demo vault is invented).
- Tests: [TESTING.md](TESTING.md). The lab (`scripts/test/lab`) must cover
  every scenario before a release, not only the changed areas.
