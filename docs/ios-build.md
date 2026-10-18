# Building Varsto for a real iPhone or iPad

Varsto for iOS (`apps/ios`, Rust core `crates/varsto-ffi` as a static
library, SwiftUI and `WKWebView` shell) is built and launched in the iOS
Simulator on every CI run. To put it on a real device without a paid Apple
Developer account, build an **unsigned `.ipa`** and let an alternative app
store (AltStore, SideStore, Sideloadly) sign it with your own Apple ID when it
installs it. Nothing in the build needs an Apple account, certificate or
secret.

## Build on GitHub (preferred, free for this public repository)

The workflow `.github/workflows/ios-ipa.yml` runs only by hand or on tags
named `ios-v*`, never on a push. It installs Rust with `aarch64-apple-ios`,
builds `varsto-ffi` for the device in release mode, generates the Xcode
project with xcodegen, runs `xcodebuild archive` for `generic/platform=iOS`
with `CODE_SIGNING_ALLOWED=NO`, packs `Payload/Varsto.app` into
`Varsto-<version>-ios-unsigned.ipa`, checks it (`unzip -l`, `plutil -lint`,
bundle id, minimum iOS, icon, arm64) and uploads it as the artifact
`Varsto-ios-unsigned` (kept 14 days). The same steps are in
`apps/ios/make-ipa.sh`, which the workflow calls.

```bash
gh workflow run ios-ipa.yml --repo janttsu/varsto -f ref=main
# optional: attach to a draft pre-release as well
gh workflow run ios-ipa.yml --repo janttsu/varsto -f ref=main -f release_tag=ios-v0.0.1-alpha.15
gh run list --workflow ios-ipa.yml --repo janttsu/varsto --limit 1
gh run watch <run id> --repo janttsu/varsto
gh run download <run id> --repo janttsu/varsto --name Varsto-ios-unsigned --dir ios-ipa
```

Pushing a tag `ios-v<anything>` does the same and attaches the file to a draft
pre-release of that tag. The run's summary repeats the install steps.

For a release, `website/publish-ci-release.sh v<version>` finds the run of this
workflow on the release tag (or starts it with `ref` and `release_tag` set to
the tag and waits), downloads `Varsto-ios-unsigned`, adds the `.ipa` to the
download set (`SHA256SUMS` and `manifest.json`) before signing, and the
downloads page then offers it as the iOS download. The desktop updater ignores
it; an iOS install is updated by sideloading the newer `.ipa`.

Cost: GitHub-hosted standard runners are free and unlimited for public
repositories ([runner docs](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
checked 2026-10-15). The `macos-15` runner is an arm64 M1 with 3 cores, 7 GB
RAM. For a private repository the same minutes would be billed at
$0.062 per minute for a standard macOS runner
([pricing reference](https://docs.github.com/en/billing/reference/actions-runner-pricing),
checked 2026-10-15; macOS minutes also count 10 times against the included
free minutes on a plan, which I could not confirm on the pages fetched).
Expected duration is an estimate, not a measurement: roughly 15-25 minutes for
the first run (release build of the Rust workspace dependencies dominates) and
8-12 minutes with a warm cache. The existing Simulator job builds
`aarch64-apple-ios` already, so the dependency set (ring, rustls, quinn,
mimalloc, zstd, blake3) needs no changes for the device.

## Build on your own Mac

Needs Xcode, `brew install xcodegen` and rustup:

```bash
apps/ios/make-ipa.sh                 # dist/ios-ipa/Varsto-<version>-ios-unsigned.ipa
apps/ios/make-ipa.sh --out ~/Desktop --version 0.0.1-alpha.15
```

## Install

Get the `.ipa` onto the iPad (AirDrop, Files, or the tool's file picker).

- **AltStore**: install AltServer on a Mac or PC, install AltStore on the
  iPad from it, then in AltStore open My Apps, tap +, pick the `.ipa`.
- **SideStore**: after its one-time setup (it needs no computer afterwards),
  My Apps, +, pick the `.ipa`.
- **Sideloadly** (Mac or Windows, USB): drag the `.ipa` in, enter the Apple
  ID, Start.
- Then Settings, General, VPN and Device Management: trust your Apple ID.
  On iOS 16 and later also enable Developer Mode (Settings, Privacy and
  Security), which restarts the device.

Update cycle: build a newer `.ipa`, install it over the old app (same bundle
identifier). The vault lives in the app container and is kept. If the tool
rewrites the bundle identifier (a free Apple ID cannot reuse
`in.soderlund.varsto.ios` if somebody else holds it), keep using the same
rewritten one every time.

## What is in the bundle

- Bundle identifier `in.soderlund.varsto.ios`, minimum iOS 16.0, iPhone and
  iPad (`TARGETED_DEVICE_FAMILY 1,2`), arm64 only.
- App icon: `apps/ios/Varsto/Assets.xcassets` (1024 px, from `brand/appicon.svg`
  without the rounded corners; iOS rounds it).
- Info.plist: `NSLocalNetworkUsageDescription` (pairing and peer-to-peer on
  the LAN), `NSCameraUsageDescription` (QR codes), the `varsto://` URL scheme,
  `UIBackgroundModes: fetch`, `ITSAppUsesNonExemptEncryption: false`. There is
  no photo-library key because the shell has no camera-roll backup yet. No
  `NSBonjourServices`: the core finds peers with its own UDP multicast beacon,
  not mDNS.
- No entitlements are used (no App Groups, no keychain access groups, no
  multicast), so nothing breaks when the sideloader strips or replaces them:
  keys and state live in the app's own container (`Application Support/Varsto`,
  excluded from iCloud backup).

## Known limits

- **Signature lifetime**: a free Apple ID signs for 7 days and allows 3 sideloaded
  apps. AltStore and SideStore re-sign before expiry while they can reach their
  server (AltServer on the same Wi-Fi, or SideStore's on-device loopback). If
  it lapses, the app stops opening; reinstall the same `.ipa`, the data stays.
- **No multicast LAN discovery**: receiving or sending multicast needs the
  `com.apple.developer.networking.multicast` entitlement, which Apple grants
  only on request to paid accounts and a sideloader cannot add. Pair with the
  address shown under the pairing code (unicast works with the Local Network
  permission). Peer-to-peer fetches by known address are unaffected.
- **Background sync** is only what iOS grants (`fetch` background mode, no
  guarantee when or whether it runs); sync while the app is open.
- Not yet run on a real device by CI or the author; this is the first route to
  doing so.

## Fallback: Scaleway Mac mini (checked 2026-10-15)

Needed only if GitHub were unavailable or you want a longer session than a
workflow run; the repository already has `scripts/cloud-build/scw-build.py
macos`, which creates a Mac mini, builds, fetches results and deletes it.

| Item | Finding | Source |
| --- | --- | --- |
| Price (hourly, excl. tax) | M1-M 8 GB 0.11 EUR; M2-M 16 GB 0.17 EUR; M2-L 0.21 EUR; M4-S 16 GB 0.22 EUR; M4-SP 0.24 EUR; M4-M 32 GB 0.29 EUR; M4-XL 0.49 EUR | [pricing](https://www.scaleway.com/en/pricing/apple-silicon/) |
| Monthly cap | M1-M 75 EUR, M2-M 115 EUR, M4-S 149 EUR, M4-M 199 EUR | same |
| Minimum lease | 24 hours, "due to licensing restrictions"; it cannot be deleted earlier; billing runs until you delete it (powered off still bills); auto-delete after 24 h can be enabled | [FAQ](https://www.scaleway.com/en/docs/apple-silicon/faq.md) |
| Software | Latest Xcode compatible with the installed macOS is preinstalled; M1 defaults to macOS 13 (too old for current Xcode: upgrade with softwareupdate or reinstall a newer macOS, about +1 h); M4 defaults to macOS 15 | FAQ above; search results, one French product page said Sequoia 15 on M4 |
| Zones | Docs disagree: fr-par-1 for M2/M4, fr-par-3 for M1; `scw-build.py` tries both | [create-mac-mini](https://www.scaleway.com/en/docs/apple-silicon/how-to/create-mac-mini/) |

Create and delete from the command line (this is what the helper script does):

```bash
scw apple-silicon server-type list zone=fr-par-1
scw apple-silicon server create zone=fr-par-1 name=varsto-ios type=M4-S
scw apple-silicon server get <id> zone=fr-par-1     # wait for status=ready, then ssh m1@<ip>
scw apple-silicon server delete <id> zone=fr-par-1  # only after 24 h
```

Cost estimates (arithmetic from the hourly prices above, not measured):

- One build, M4-S: 24 h x 0.22 = **5.28 EUR** (M1-M: 2.64 EUR, but its macOS 13 needs
  an upgrade first; M2-M: 4.08 EUR). Setup (delivery 10-20 min, Command Line
  Tools, Xcode check, rustup) and the build itself fit into the day.
- A month of occasional use, say four builds on four separate days:
  4 x 5.28 = **21 EUR** (M4-S); keeping one running all month is capped at
  **149 EUR**.
- GitHub (this public repository): **0 EUR**. A Mac you already own: 0 EUR plus
  about 40 GB for Xcode.

Recommendation: use the GitHub workflow; keep Scaleway as a break-glass option
at about 5 EUR per day-long session.
