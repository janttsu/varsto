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

Status: the Swift sources and the FFI crate are written; nothing has been built
or run on a device yet, because this needs macOS. The app store listing,
background modes and File Provider integration are future work.
