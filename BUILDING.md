# Building Varsto

How every part of Varsto is built, where (GitHub Actions, your machine, the Scaleway fallback), and how the screenshots, the daily channel and the website are produced. Written from the scripts and workflows in this repository; if they disagree with this page, they are right and this page needs a fix.

Related: [TESTING.md](TESTING.md) (tests and the VM lab: [docs/testing/lab.md](docs/testing/lab.md)), [RELEASING.md](RELEASING.md) (signing and publishing), [HANDOVER.md](HANDOVER.md) (current state), [CONTRIBUTING.md](CONTRIBUTING.md).

**Default: let GitHub Actions build.** The repository is public, so GitHub-hosted runners are free, and they build every platform (including macOS and iOS, which need Apple hardware). Build locally for a quick check of one platform, and use the Scaleway fallback only when GitHub cannot be used.

## Contents

1. [What gets built](#what-gets-built)
2. [Local builds](#local-builds)
3. [A layout for build outputs](#a-layout-for-build-outputs)
4. [GitHub Actions](#github-actions)
5. [The Scaleway fallback](#the-scaleway-fallback)
6. [Screenshots](#screenshots)
7. [The daily channel](#the-daily-channel)
8. [The website](#the-website)

## What gets built

| Output | Built by | Notes |
|---|---|---|
| `varsto` (CLI, service, tray, local interface), Linux x86_64 static (musl) | `website/build-release.sh x86_64-unknown-linux-musl` | `varsto-<version>-x86_64-unknown-linux-musl.tar.gz` |
| `varsto.exe` and `varsto-window.exe`, Windows | `website/build-release.sh x86_64-pc-windows-gnu` (cross-compiled with mingw-w64) | staged in `dist/windows/app`; input of the installer, not a download |
| `Varsto-<version>-setup.exe` | `installer/windows/build.ps1` (Inno Setup, on Windows) | the only Windows download |
| Android APK | `apps/android/build.sh` | release-signed with four secrets, else debug |
| `Varsto-<version>-macos.dmg` (Apple Silicon) | `apps/macos/build.sh` (on a Mac) | ad-hoc signed, not notarised |
| iOS Simulator app | `apps/ios/build.sh` (on a Mac) | built and photographed in CI |
| `Varsto-<version>-ios-unsigned.ipa` | `apps/ios/make-ipa.sh` (on a Mac) | unsigned, for sideloading; [docs/ios-build.md](docs/ios-build.md) |
| `varsto-rendezvous` (the optional meeting-point service), Linux static | `cargo build --release --target x86_64-unknown-linux-musl -p varsto-rendezvous` | [docs/rendezvous.md](docs/rendezvous.md) |
| Source archive, `manifest.json`, `SHA256SUMS` | `website/assemble-release.sh` | the maintainer signs `SHA256SUMS` offline: [RELEASING.md](RELEASING.md) |

The workspace (`Cargo.toml`) has five crates: `varsto-core` (library), `varsto-cli` (the `varsto` binary), `varsto-ffi` (C ABI for iOS), `varsto-window` (the Windows window, WebView2) and `varsto-rendezvous`. The Rust version is `rust-version` in `Cargo.toml` (CI uses the current stable toolchain). Cargo features of `varsto-cli`: `mimalloc` (default), `fsevents` (macOS builds), `software-key` (security keys kept in a file: tests and the lab only; the lab's own build turns it on, release builds do not).

## Local builds

Always start with the quality gates that CI also runs:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

(`cargo audit` and `cargo deny check` also run in CI; install `cargo-audit` and `cargo-deny` to run them.) Tests are described in [TESTING.md](TESTING.md).

A plain development build on any platform: `cargo build --release -p varsto-cli`. The Linux tray needs the D-Bus development package (`libdbus-1-dev` on Debian and Ubuntu). The rest of this section is for packages.

### Linux (static musl) and Windows programs

On Debian or Ubuntu:

```bash
sudo apt-get install musl-tools mingw-w64 zip libdbus-1-dev
rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu
website/build-release.sh x86_64-unknown-linux-musl x86_64-pc-windows-gnu
```

Output: `website/public/downloads/varsto-<version>-x86_64-unknown-linux-musl.tar.gz`, `manifest.json`, `SHA256SUMS` and a source archive (`website/assemble-release.sh` runs at the end; it signs only if the release key is available, which it normally is not), and `dist/windows/app/{varsto.exe,varsto-window.exe,...}`. With no arguments the script builds Linux and Windows, plus macOS command-line binaries when `cargo-zigbuild` is installed. The script uses `musl-gcc` when present and turns `_FORTIFY_SOURCE` off, because musl lacks `__memcpy_chk`. A target that fails to build is skipped with a message (`!! build failed`), so read the output, not only the exit code.

The lab can do the same in a VM: `lab.py release` ([docs/testing/lab.md](docs/testing/lab.md)).

### Windows installer

Needs Windows with PowerShell, Python, and Inno Setup 6 (the script installs it with Chocolatey if missing). The input is the folder with `varsto.exe`, `varsto-window.exe` and the licence files, made by `website/build-release.sh` for the Windows target:

```powershell
installer\windows\build.ps1 -Version 0.0.1-alpha.16 -Source dist\windows\app -Out dist\installer
installer\windows\smoke-test.ps1 -Setup dist\installer\Varsto-<v>-setup.exe -Newer <setup of a higher version> -Version <v> -NewerVersion <n> -Work C:\smoke
```

`build.ps1` makes a multi-size icon (`make-ico.py`), downloads Microsoft's WebView2 bootstrapper and checks that Microsoft signed it (`-NoWebView2` skips it), and compiles `varsto.iss`. The smoke test installs silently, upgrades in place with a setup of a higher version (CI builds one as `99.0.0` for this), repairs, refuses a downgrade, opens the window, and uninstalls. It needs a desktop session. More about the installed product: [docs/windows.md](docs/windows.md).

### Android

Needs a JDK 17 or newer, the Android SDK with platform 35, build-tools 34 and 35 and NDK 27 (`ndk;27.2.12479018` is what the scripts install), `ANDROID_HOME` set, and Rust:

```bash
rustup target add aarch64-linux-android x86_64-linux-android
ANDROID_HOME=$HOME/android-sdk apps/android/build.sh
```

It builds `varsto` for arm64 and x86_64 with the NDK linkers, copies them into `jniLibs` as `libvarsto.so`, and runs Gradle (the wrapper in `apps/android`). Result: `apps/android/app/build/outputs/apk/release/*.apk` or `.../debug/app-debug.apk`.

Signing is decided by four environment variables, all or none: `VARSTO_ANDROID_KEYSTORE` (a path, or the keystore file as base64), `VARSTO_ANDROID_KEYSTORE_PASSWORD`, `VARSTO_ANDROID_KEY_ALIAS`, `VARSTO_ANDROID_KEY_PASSWORD`. All four set: a release APK signed with that key. None set: a debug APK for local use and the emulator, which must not be published (a debug APK is signed with a new key each time, so it cannot update over the previous one, and uninstalling removes the device's copy of the vault). A partial set is an error. In CI the four are repository secrets of the same names. The key itself is never in the repository. Version name = workspace version; the version code rules are in [apps/android/README.md](apps/android/README.md).

### macOS app

On a Mac with the Xcode command line tools and rustup:

```bash
apps/macos/build.sh --out dist        # dist/Varsto-<version>-macos.dmg
```

It builds `varsto` for `aarch64-apple-darwin` (feature `fsevents`), compiles the Swift app, assembles `Varsto.app`, signs it ad hoc and makes the disk image. Details and the Finder integration: [apps/macos/README.md](apps/macos/README.md). `website/publish-macos.sh` adds a Mac-built image to the download set (needs the release key).

### iOS

On a Mac with Xcode, `brew install xcodegen` and rustup:

```bash
apps/ios/build.sh                       # Simulator build; app in apps/ios/build/Build/Products/Release-iphonesimulator/
apps/ios/simshot.sh dist/ios            # boots a Simulator, runs the app, saves a screenshot
apps/ios/make-ipa.sh --out dist/ios-ipa # unsigned .ipa for a real device
```

The `.ipa` is for AltStore, SideStore or Sideloadly, which sign it with your own Apple ID; no Apple account, certificate or secret is needed to build it. Install steps and limits: [docs/ios-build.md](docs/ios-build.md) and [apps/ios/README.md](apps/ios/README.md).

### The rendezvous service

```bash
cargo build --release -p varsto-rendezvous                                   # for this machine
CC_x86_64_unknown_linux_musl=musl-gcc CFLAGS_x86_64_unknown_linux_musl="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0" \
  cargo build --release --target x86_64-unknown-linux-musl -p varsto-rendezvous   # static
```

`varsto-rendezvous --self-test` checks it. The lab needs a host build of it (see the lab runbook).

## A layout for build outputs

Rust builds are large: a workspace target directory runs to tens of GB, and a few branches' worth fills a small disk. A layout that works:

- Keep the build output off the disk with the source. Give every branch its own cargo target directory on a disk with room, for example `/mnt/ssd/varsto-lab/cargo-target-<branch>` ([HANDOVER.md](HANDOVER.md) uses this one). Delete the directory when the branch is merged.
- On a small machine limit parallelism: `cargo build -j 2` (or `CARGO_BUILD_JOBS=2`); a full release build with many jobs can run the machine out of memory.
- Prefer CI for anything heavier than a unit test.

How to point cargo at it: `export CARGO_TARGET_DIR=/mnt/ssd/varsto-lab/cargo-target-<branch>` works for `cargo build/test/clippy`. **The packaging scripts do not honour it**: `website/build-release.sh`, `apps/android/build.sh`, `apps/macos/build.sh` and the Xcode project (`apps/ios/project.yml`) read `<repo>/target/...`. For those, make `target` in the repository a symlink to the big directory instead (`ln -s /mnt/ssd/varsto-lab/cargo-target-<branch> target`; `target` is git-ignored) and leave `CARGO_TARGET_DIR` unset.

Other git-ignored output: `dist/` (packages, screenshots, cloud-build and benchmark output), `test-results/`, `website/public/downloads/`.

## GitHub Actions

Three workflows in `.github/workflows/`. All use `permissions: contents: read` by default; only the jobs that publish a release asset get `contents: write`. No job gets a key that can push code. **The release key is never in CI.**

### When do they run

| Workflow | Triggers |
|---|---|
| `ci.yml` (CI) | push to `main`, push of a tag `v*`, **every pull request**, manual run (`workflow_dispatch`), and `workflow_call` from `daily.yml` |
| `daily.yml` (Daily builds) | every day at 03:00 UTC (`schedule`), manual run with inputs `ref` (default `main`) and `publish` (default true) |
| `ios-ipa.yml` (iOS .ipa) | manual run (inputs `ref`, `release_tag`), push of a tag `ios-v*`, and `workflow_call` from `daily.yml`. Never on a plain push. |

A push to a branch that is not `main` and has no pull request starts nothing. Open a pull request (draft is enough), or start CI by hand: `gh workflow run ci.yml --ref <branch>`. Runs of the same workflow and ref queue instead of cancelling (`cancel-in-progress: false`). `gh run list`, `gh run watch <id>` and `gh run download <id> --name <artifact>` follow and fetch runs.

### `ci.yml` jobs

| Job | Runner | What it does | Artifacts |
|---|---|---|---|
| `linux` | `ubuntu-24.04` | `cargo fmt --check`, `clippy -D warnings`, `cargo audit`, `cargo deny check`, `cargo test --workspace`, the site-tool unit tests (`ops/site`), builds the Linux musl package and the cross-compiled Windows programs (`website/build-release.sh`), smoke-tests the Linux package, builds the rendezvous binary and runs its `--self-test`, then seeds the invented demo vault and takes the Linux screenshots (interface in English, Finnish, Swedish; the 4K TV scene, allowed to fail; tray and own window) | `packages-linux-windows`, `rendezvous-linux`, `windows-programs`, `shots-linux`, `shots-linux-fi`, `shots-linux-sv`, `shots-linux-viz` |
| `windows` | `windows-2025`, 30 min limit | smoke test of `varsto.exe` (`scripts/cloud-build/remote-windows.ps1`) and Windows screenshots (`windows-desktop.ps1`); needs `linux` | `shots-windows` |
| `windows-installer` | `windows-2025`, 30 min limit | builds the setup with Inno Setup, builds a `99.0.0` setup, runs `smoke-test.ps1` (install, upgrade, repair, window, uninstall); needs `linux` | `installer-windows`, `installer-windows-logs` |
| `android` | `ubuntu-24.04` | builds the APK with `apps/android/build.sh` (release-signed when the four secrets exist, otherwise the job fails at "Refuse a debug APK as the published package"), builds the debug APK for the emulator, runs it in an API 34 emulator with KVM, takes the Android screenshots | `packages-android`, `shots-android` |
| `macos` | `macos-15` | `cargo test --workspace`, builds `Varsto.app` and the dmg, smoke-tests the bundled command line, Finder placeholder double-click and Services, takes the window screenshot | `Varsto-macos` |
| `ios` | `macos-15` | builds the app for the Simulator and takes a screenshot | `Varsto-ios-simulator` |
| `downloads` | `ubuntu-24.04` | gathers the Linux, installer, Android, rendezvous and macOS packages and runs `website/assemble-release.sh`: source archive, `manifest.json`, unsigned `SHA256SUMS`; needs `linux`, `windows-installer`, `android`, `macos` | `downloads` |
| `release` | `ubuntu-24.04` | only on a `v*` tag: attaches the `downloads` files to a draft pre-release of that tag (`gh release create --draft --prerelease`, `gh release upload --clobber`); needs `downloads` | none |
| `screenshots` | `ubuntu-24.04` | runs after the platform jobs even if some failed; tests the website sync against a fixture; packs all screenshots with `scripts/screenshots/finalize.py --pack` | `screenshots` |
| `screenshots-publish` | `ubuntu-24.04` | only on a push (`main` or a tag): uploads `screenshots.tar.gz` to the rolling pre-release `screenshots-latest` | none |

The iOS `.ipa` is not part of `ci.yml`; it comes from `ios-ipa.yml`. The two publishing jobs run `gh` without a checkout, so they set `GH_REPO` ([HANDOVER.md](HANDOVER.md) tells why).

Duration: [HANDOVER.md](HANDOVER.md) records about 1 h 45 min for the Linux job and about 1 h 10 min for the macOS job, which run in parallel; the whole workflow is as long as the slowest chain. `ios-ipa.yml` documents 15-25 minutes cold and 8-12 warm as an estimate. Rust caches (`Swatinem/rust-cache`) make repeat runs shorter.

### `ios-ipa.yml`

One job, `ipa` on `macos-15` (60 min limit): installs Rust with the `aarch64-apple-ios` target and `xcodegen`, runs `apps/ios/make-ipa.sh --out dist/ios-ipa --version <Cargo version> --build-number <run number>`, writes install steps to the job summary, and uploads artifact `Varsto-ios-unsigned` (14 days). The `release` job attaches the file to a draft pre-release when the run was started by an `ios-v*` tag or with `release_tag`. Needs no secrets. Run it by hand:

```bash
gh workflow run ios-ipa.yml --ref main -f ref=main
gh run download <run id> --name Varsto-ios-unsigned
```

### Secrets used (names only)

| Secret | Used by | For |
|---|---|---|
| `VARSTO_ANDROID_KEYSTORE`, `VARSTO_ANDROID_KEYSTORE_PASSWORD`, `VARSTO_ANDROID_KEY_ALIAS`, `VARSTO_ANDROID_KEY_PASSWORD` | `ci.yml` job `android` | signing the release APK; if any is missing the build fails instead of using the debug key |
| `VARSTO_DAILY_KEY` | `daily.yml` job `package` | signing the daily file list (the daily key, not the release key); [ops/site/README.md](ops/site/README.md) |
| `GITHUB_TOKEN` (automatic) | publishing jobs | `gh release` calls |

`ci.yml` is called from `daily.yml` with `secrets: inherit`, so the Android secrets reach it there. Pull requests from forks do not receive secrets, so their Android job cannot make the signed APK. HANDOVER.md lists the GitHub settings that workflows cannot set (branch protection, a protected environment for the daily key).

### Cutting a release from CI

Tag `v<version>` on the merge commit (steps in [RELEASING.md](RELEASING.md)). CI builds everything and the `release` job attaches the set to a draft release; then `website/publish-ci-release.sh v<version> --publish`, run where the release key is, downloads the set, signs `SHA256SUMS`, publishes the release, pulls in the iOS `.ipa` and the screenshots, and deploys the site.

## The Scaleway fallback

`scripts/cloud-build/` builds and tests on rented Scaleway machines when GitHub Actions cannot be used. It is slower to set up and costs money; GitHub is preferred.

`scripts/cloud-build/scw-build.py <target>` needs the `scw` command line configured (`scw init`) with a project where this machine's SSH key is registered, and `rclone` for the integration test. Every machine is tagged `varsto-build` and deleted at the end, also on failure, unless `--keep` is given. `git archive HEAD` is what gets built, so commit first. Output lands in `dist/cloud/<target>/` (the `windows` target needs the cross-compiled programs in `dist/windows/app` first, or in `$ARTIFACTS/windows-app`).

| Target | Machine | What happens |
|---|---|---|
| `linux` | Ubuntu 24.04, default type `POP2-4C-16G` | `remote-linux.sh`: installs the toolchain, `cargo test --workspace --release`, `website/build-release.sh x86_64-unknown-linux-musl` |
| `android` | Ubuntu, `POP2-8C-32G`, 40 GB disk | `remote-android.sh`: JDK 17, Android SDK 35 / NDK 27, builds with `apps/android/build.sh`; publishes only a signed release APK. `scw-build.py` does not forward the four `VARSTO_ANDROID_*` variables to the machine, so as it stands the target ends with "no signed release APK" (exit 1) unless you run it with `--keep` and rerun `remote.sh` on the machine with the variables set |
| `windows` | Windows Server 2025, `POP2-2C-8G-WIN` | enables OpenSSH, copies the cross-compiled programs (`dist/windows/app`, build them first), runs `remote-windows.ps1` (smoke test). Needs an RSA key in Scaleway IAM (name from `SCW_RSA_KEY_NAME`, private key file from `SCW_RSA_KEY_FILE`) to decrypt the administrator password; the script does the `win-bootstrap` step itself if the first-boot script did not enable SSH |
| `macos` | Mac mini, Apple Silicon (`M4-S` and others; `--type`, `--zone`, `--wait-for-stock`, `--any-type`; `mac-stock` lists stock) | `remote-macos.sh`: Command Line Tools, tests, `apps/macos/build.sh`, a smoke test and a window screenshot. **Billed for 24 hours minimum** |
| `integration` | one Linux and one Windows machine plus a temporary Scaleway bucket | `it-linux.sh` and `it-windows.ps1`: sync both ways through S3, then fetch blocks peer to peer over the public internet. Needs the packages in `ARTIFACTS` (a directory; default `website/public/downloads`) |
| `shots-linux` | Ubuntu | screenshots of the tray on a virtual desktop (`shots-linux.sh`) |
| `win-bootstrap --server <id>` (also reachable as `shots-windows`) | an existing Windows instance | enables OpenSSH over RDP from a jump machine |
| `cleanup [--all]` | n/a | deletes machines tagged `varsto-build`; without `--all` it keeps those created in the last 90 minutes |

Environment: `SCW_ZONE` (default `fr-par-1`), `ARTIFACTS`. There is no iOS target here: building the `.ipa` on rented hardware means a Mac mini (`macos` target machine, then `apps/ios/make-ipa.sh` by hand); see [docs/ios-build.md](docs/ios-build.md). The benchmark and NAT tools reuse this script's machine handling: [docs/testing/benchmarks.md](docs/testing/benchmarks.md).

## Screenshots

Every CI build refreshes all website pictures, for every platform and language, with no manual step.

How they are made (`scripts/screenshots/`):

- `demo-vault.sh <varsto binary> <work dir>` seeds an invented user "aino" (laptop and phone, local storage, Documents and Photos with generated pictures from `mkimg.py`) and starts two services. `DEMO_HOME` sets where the demo files live (CI uses `/home/aino`, because the paths show in the interface).
- `ui-shots.py <demo dir> <out dir> [--lang fi|sv]` drives the interface in Chromium (Playwright) in light and dark, desktop and phone sizes. `example_data.py` supplies invented peer-to-peer, data-location and import data that a small demo vault cannot show.
- `viz-shots.py` photographs the full-screen visualization page; CI renders the 4K TV scene (`website/tools/screenshots/viz_tv_scene.py` makes the scene file).
- `linux-desktop.sh` (tray and own window on a virtual Xfce panel), `windows-desktop.ps1`, `android.sh` (emulator), the macOS and iOS jobs (`screencapture`, `simctl`).
- `finalize.py <in> <out> --pack ...` renames and scales everything to the website's names and widths and writes `shots.json`: sets `en/`, `fi/`, `sv/`, `viz/`.

Where they go:

1. The CI job `screenshots` uploads the package as artifact `screenshots`.
2. On a push to `main` or a tag, `screenshots-publish` attaches `screenshots.tar.gz` to the rolling pre-release `screenshots-latest`.
3. The web server pulls it every 15 minutes (`ops/site/screenshots-sync.py`, installed as a systemd user timer: [ops/site/README.md](ops/site/README.md)) and writes the pictures and their sizes into the live pages. A deploy never touches them.
4. `scripts/screenshots/update-site.sh [run id | --dir DIR]` puts a run's pictures (default: the newest successful CI run on `main`; needs `gh`) into the repository's copy of the site and rebuilds it; deploy separately with `website/deploy.sh`. `publish-ci-release.sh` calls it for a release.

Local test of one part: build the Linux binary, run `scripts/screenshots/demo-vault.sh`, then `ui-shots.py` (needs `pip install playwright pillow` and `playwright install chromium`). A set missing from a run keeps the website's previous picture. Fixture test of the sync: `python3 -I ops/site/tests/test_screenshots_sync.py`. More in [RELEASING.md](RELEASING.md), "Screenshots".

## The daily channel

A development build of `main` for every platform, signed with a daily key (not the release key), at <https://varsto.net/daily/>; `varsto update --daily` installs from it. [RELEASING.md](RELEASING.md) ("Daily builds") has the keys, the signature format and what the updater checks. The pipeline:

1. `daily.yml` runs at 03:00 UTC. Job `check` resolves `main` (or the `ref` input) and stops the scheduled run if that commit is already the one in the notes of the published `daily` pre-release (a manual run always builds). It also validates the version string from `Cargo.toml`.
2. Job `ci` calls `ci.yml` for that commit and job `ipa` calls `ios-ipa.yml`.
3. Job `package`: `scripts/daily-assemble.py` collects the artifacts under stable names (`varsto-daily-linux-x86_64.tar.gz`, `-windows-setup.exe`, `-macos-apple-silicon.dmg`, `-android-debug.apk` (release bytes; the name is kept so the signed list stays valid), `-ios-unsigned.ipa`, `-rendezvous-linux-x86_64`, `-screenshots.tar.gz`) and writes an unsigned `SHA256SUMS` and `latest.json`; every file must be found exactly once or the script stops. `scripts/sign-daily.sh` signs the list with the key from the secret `VARSTO_DAILY_KEY`, refusing a key that does not match `daily-key.pub`, and the step verifies it. The files go to the artifact `daily-assets` (14 days).
4. If publishing is on (always for the schedule; the `publish` input for a manual run), the old `daily` release and tag are deleted and a new pre-release `daily` is created with the files; its notes start with `commit: <sha>` and `build: <id>` (`YYYYMMDD-<short sha>`).
5. On the web server, `ops/site/daily-sync.py` (cron, hourly) fetches the release, verifies `SHA256SUMS.sig` against the built-in daily public key and every size and hash, and only then writes `daily/builds/<id>/` and the `daily/latest/` links; it keeps the newest 7 builds and refuses a rollback. Setup of the cron line and the one-time secret: [ops/site/README.md](ops/site/README.md). Nothing on GitHub writes to the server.

Rehearse with a manual run with `publish` off (Actions, Daily builds, Run workflow): the result stays an artifact. The manual path for a build made elsewhere is `website/tools/daily/make_daily.py` plus `scripts/sign-daily.sh` (see its header). Tests: `python3 -I -m unittest discover -s ops/site -p 'test_*.py'` (needs OpenSSL 3; CI runs them).

## The website

Static site in `website/` (pages in English, Finnish, Swedish and French; docs, blog and downloads in English). Full details: [website/README.md](website/README.md) and [ops/site/README.md](ops/site/README.md). Summary:

```bash
python3 website/build.py                          # needs pandoc; renders pages, posts and the repository docs into website/public
python3 -m http.server -d website/public 8080     # preview
DEPLOY_HOST=user@host DEPLOY_PATH=/path/to/webroot website/deploy.sh
```

- `website/public/` is committed (except `downloads/`); rebuild it and commit it with the change to the sources in `website/src/`. The front page counts Rust lines, tests and lab scenarios from the tree at build time (the scenario count reads `@scenario("` lines of `scenarios.py`).
- The download cards come from `website/public/downloads` (`SHA256SUMS`, `manifest.json`); without one, `build.py` reads the live site's list (`DOWNLOADS_SOURCE_URL`). If neither exists it renders a stub and `deploy.sh` refuses to upload it. `RELEASED_VERSION` in `build.py` is the last tagged release; update it when tagging.
- `deploy.sh` rsyncs to `DEPLOY_PATH` on `DEPLOY_HOST` (`DEPLOY_HOST=local` copies to a local directory for a dry run). Host and path are never committed. It refuses a `SHA256SUMS` whose signature does not verify against `release-key.pub`, and never touches the server's screenshots, `/testbuilds/` or `/daily/`.
- Release downloads are published by `website/publish-ci-release.sh` (CI-built) or `website/publish-macos.sh` (Mac-built disk image); both sign with the release key, so run them where it is.
- Benchmark page data: [docs/testing/benchmarks.md](docs/testing/benchmarks.md).
- Other tools: `website/tools/gen_svgs.py`, `og/make-card.py` (social cards), `render/` (illustrations; its own README).
