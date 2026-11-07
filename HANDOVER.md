# Handover

State of the project for whoever (or whatever) picks it up next. Keep this
file current in every pull request that changes the state it describes.
English only, no personal data, no secrets.

## State on 2026-11-07

- The repository is <https://github.com/janttsu/varsto>. The old Bitbucket
  repository holds only a commit that points here; do not push to it.
- `main` is `9be27d6` (PR #120), twelve pull requests on top of `46adda31`
  (PR #108), which sits on tag `v0.0.1-alpha.16` = `64346c5f`. **Nothing
  merged on 2026-11-07 has been compiled or tested**: every CI run of those
  pull requests and of the pushes to `main` was cancelled on request before
  any package was uploaded, and no artifact was kept. The first CI run that
  is allowed to finish (the scheduled daily at 03:00 UTC builds `main` when
  it has moved) is the first test of all of it. Release 0.0.1-alpha.16 is
  published on GitHub and at <https://varsto.net/downloads/> with
  `SHA256SUMS` signed by the release key. The published daily is
  `20261106-46adda3` of `46adda31` for every platform (Linux, Windows
  setup, macOS, Android, iOS `.ipa`, rendezvous binary; Actions run
  42208674730); the site serves it at <https://varsto.net/daily/>, and
  the screenshots of that run are on the website. The Android object is
  still named `varsto-daily-android-debug.apk`; the bytes are the release
  build. `Cargo.toml` is `0.0.1-alpha.16`.
- The website on <https://varsto.net> is the build of PR #114, deployed
  on 2026-11-06; `main` now carries it, so a deploy from `main` is safe.
- What alpha.16 contains: [CHANGELOG.md](CHANGELOG.md) section
  `[0.0.1-alpha.16]` and the blog post under `website/src/posts/`. In short:
  storage format 3 (vaults of alpha.15 and earlier must be recreated), folder
  access by an owner's approval (also from the interface: Request access),
  recovery words, the rendezvous service, offline-first joining and sync, the
  Import page with torrent and YouTube imports, the mailbox for offline disks,
  the fixes of the 2026-10-30 code review, a release-signed Android APK and
  `disk init` without `wipefs`.
- The branches still unmerged on GitHub (`bugfix-ui`, `ci-all-platforms`,
  `deps-rustls`, `format2-records`, `ios-ipa`, `policy-device-copies`,
  `test-latest`, `torrent-spool`, `visualization`, `windows-installer`) date
  from 2026-10-10 to 2026-10-16, before format 3, and look superseded;
  delete them after a look, do not merge them. Older experiments, pushed so
  they are not lost and written before format 3: `dht-discovery`
  (`40a84ae0`, peers through the Mainline DHT) and `ios-camera-viewer`
  (`f6736178`, iOS camera upload and a native viewer); they need rework on
  top of `main` before any merge.
- The code review of 2026-10-30 (15 areas, 19 HIGH findings, none critical)
  is documented outside the repository; its HIGH fixes are the `fix/*`
  branches merged through `integrate/review-20261031` into PR #107.

## Merged on 2026-11-07, unbuilt and untested

In merge order. Each is in `## Unreleased` of [CHANGELOG.md](CHANGELOG.md).
Conflicts were only in CHANGELOG.md, this file, `website/public/sitemap.xml`
(site rebuilt) and one spot of `crates/varsto-cli/src/service.rs` where
two branches added functions at the same place (both kept).

- #109 `docs/build-and-lab`: BUILDING.md, the lab runbook, the benchmarks
  guide and fixes of stale references. Documentation only.
- #114 `website/search-snippets`: search titles and descriptions,
  `data-nosnippet` on the alpha warning, a developer section in four
  languages. The translations still await a native check.
- #110 `fix/default-policy-own-disks`: a folder on the default policy in a
  vault without a disk pool or directory storage shows a warning ("no own
  disk") with the reason under the bar, instead of "violated".
- #111 `fix/list-thumbnails`: thumbnails in the file list on phones;
  `/api/thumb` answers 503 with `Retry-After` while the engine is busy.
- #113 `fix/pause-stops-p2p`: pausing the service stops peer-to-peer too,
  and the user's pause survives a restart (`<home>/service-paused`). Check
  on a phone that Varsto traffic stops, and whether pairing needs
  peer-to-peer while paused.
- #112 `feat/notify-channels`: push notifications through ntfy (also
  self-hosted), Pushover and a Telegram bot: `varsto_core::notify`, the
  Notifications card in Settings with a guided setup per service, `varsto
  notify …`, [docs/notifications.md](docs/notifications.md). About 4 000
  new lines; the external APIs have not been called for real, and the
  store links in the setup guide are from memory.
- #115 `fix/join-reads-org-admins`: joining reads the organization's
  manifest and adopts vault epochs and revocations only from administrators
  (review membership gap "`Membership::join` without an administrator
  list"); and no panic when an epoch claims the last number.
- #116 `fix/restic-mirror-private`: the restic mirror root and folders are
  created mode 0700 (review imports-1).
- #117 `fix/activity-request-access`: the activity log's "holds no key"
  line has the folder row's access button.
- #118 `fix/recovery-kit-format3`: `varsto recovery kit` prints the format
  3 kit with both word sets, says in capitals when the recovery words are
  missing, and `--shares` splits both sets (review CRYPTO-1). The Help page
  and the kit dialog say the same.
- #119 `ci/daily-environment`: the daily package job names the `daily`
  environment (its secret `VARSTO_DAILY_KEY`; the repository secret is
  deleted, so a daily built from a `main` without this change would fail
  at signing, which can no longer happen).
- #120 `fix/share-request-keys-sealed`: a pending share request's K6/K8
  keys are sealed under the device passphrase (`share-request.enc`;
  review CRYPTO-2). `share request` asks for the passphrase and `share
  accept` needs the same one; a clear `share-request.json` of alpha.16 is
  sealed and removed by the next read. `OrgRequest` (`org.rs`) still keeps
  its KEM private key in clear the same way.

## Open

- Build and test everything above: let one CI run finish, run the unit
  tests, and try the notification channels, the thumbnails on a phone and
  the pause on a phone. Until then no daily or release should be trusted.
  What has been done without a build: `cargo fmt --check` (two files fixed
  in PR #122), the Python tests of `ops/site`, the import-UI node test,
  YAML and JSON checks, and a read-through review of the whole merge
  (46adda3..main) whose seven findings PR #122 fixes. A `cargo check`
  (type check only, no tests, no binaries) run by that review passed for
  `varsto-core` and `varsto-cli`; `varsto-ffi` failed because
  `desktop.rs` and `service.rs` referenced `crate::notifications::api`
  and `crate::default_device_name`, which only `main.rs` had. PR #122
  moves them into `notify_api.rs` and `device_name.rs`, which the ffi
  crate includes by path. Not re-checked after the fix by hand, but the
  scheduled daily run 42360310657 (started late, 09:34 UTC on 2026-11-07,
  on `main` = f96a9c9, before PR #122) was the first real compile: Linux
  stopped at `cargo fmt --check` (the two files PR #122 formats), macOS
  and iOS stopped at the two ffi errors PR #122 fixes, Android built its
  APK, and the run was cancelled before packaging; its four artifacts were
  deleted and nothing was published. Clippy and the test suites have not
  run on the merged code yet.
- Membership gaps the review left open are fixed on `fix/membership-gaps`
  (not merged, not compiled or tested): the registry cut-off ends below
  the first sequence number a removed device left empty; a member of
  another vault applies a removal from the folder epoch record (the
  removed owner's grants, directories and later epochs do not count); a
  folder the remover could not re-key is re-keyed at the next sync of an
  owner device holding its key (`rekey_after_removals`). What remains is
  inherent and in spec 77.20: a key already held cannot be recalled, so
  the removed device reads what was written under its keys, including a
  not re-keyed folder until such an owner syncs (never, while all of its
  owners are removed and nobody recovered it); a member cannot learn that
  an owner was removed from the vault before a folder epoch says so; old
  data is not re-encrypted. Medium findings
  of the review still not re-checked: logging-1/-4 (scrubber gaps), CLI-3/-4
  (`current_exe()` after an update), QUALITY-1/-2 (mutex `unwrap()` in
  service.rs, `set_var`), imports-2 (retention can delete the last
  snapshot), ENGINE-4…9 (everyday error paths of the sync engine).
- GitHub settings, made 2026-11-07: the ruleset "protect main" (no deletion,
  no force push, changes only through pull requests, no bypass: the
  maintainer merges pull requests too) and the `daily` environment
  (deployment branch policy: `main` only) that holds the secret
  `VARSTO_DAILY_KEY`; the repository secret of the same name is deleted.
- A full lab run (`scripts/test/lab`, every scenario) with the alpha.16
  binary has not been done since the review fixes.
- Android: the APK is signed with a new release key. An installation of an
  earlier debug APK (alpha.15 or an older daily) does not update over it: it
  must be uninstalled first, which removes that device's copy of the vault.
  The daily file name stays `varsto-daily-android-debug.apk` (the signed list
  keeps the name); the bytes are the release build.
- Interface: after an owner approves a request, the asking phone shows the new
  state at its next status poll, not at once. Four Help texts still call
  the vault key "the 24 recovery words" (join and forgot-passphrase hints).
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
  with the secret `VARSTO_DAILY_KEY` of the `daily` environment (runs from
  `main` only); the Android release signing
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
