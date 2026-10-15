# iOS app (source, build on a Mac)

The iOS app is a SwiftUI shell around the same Rust core and the same local
interface as the desktop app. Apple does not allow a separate background
executable, so the core is linked as a static library (`varsto-ffi`) and the
service runs on a thread inside the app process; the user interface is the
embedded web page in a `WKWebView`, reached over the loopback interface with
the session token. Background sync is limited to what iOS allows
(`BGAppRefreshTask`), as plan section 6.36 describes.

Build (macOS with Xcode):

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo build --release --target aarch64-apple-ios -p varsto-ffi
cargo build --release --target aarch64-apple-ios-sim -p varsto-ffi
apps/ios/build.sh   # creates the Xcode project with xcodegen and builds
```

Unsigned `.ipa` for AltStore, SideStore or Sideloadly (re-signed with your own
Apple ID when installed): `apps/ios/make-ipa.sh` on a Mac, or the GitHub
workflow `ios-ipa.yml` (manual or `ios-v*` tags; free for this public
repository): `gh workflow run ios-ipa.yml -f ref=main`, then `gh run download
<run id> --name Varsto-ios-unsigned`. Install steps, the Scaleway fallback and
the limits (7-day signature with a free Apple ID, no multicast LAN discovery,
no background sync guarantee) are in [docs/ios-build.md](../../docs/ios-build.md).
The app uses no entitlements (no App Groups or keychain groups), so it works
unsigned.

Status: built and launched in the iOS Simulator on GitHub's Apple Silicon
runners on every change (screenshots included); not yet run on a real iPhone
or iPad. Video thumbnails are made natively (AVAssetImageGenerator). The app
store listing, background modes and File Provider integration are future work.

Logs (debug level, on by default): the core and the app shell write
`Application Support/Varsto/logs/varsto-ffi-ios.log` inside the app container
(the shell's lines, module `app`, go through `varsto_log` in the FFI: start,
`varsto_start` result, scene phase changes, thumbnail errors). Lines logged
before `varsto_start` are dropped. The service URL, the session token,
passphrases and file contents are never logged.
