# macOS app

`Varsto.app` is a menu-bar app (no Dock icon) that starts and supervises the
`varsto` background service shipped inside the bundle, shows the sync status,
opens the local interface, keeps the passphrase in the login keychain if the
user wants, offers "Start at login" (macOS 13+) and runs self-updates.

Two flavours are published:

- **Built on a Mac** with `apps/macos/build.sh`: native menu-bar app in Swift,
  ad-hoc signed. Separate zips for Apple Silicon and Intel.
- **Cross-compiled on Linux** (`website/build-release.sh`): the Rust binary
  only, in an app bundle that opens the browser interface. No menu bar.

Neither flavour is notarised; see the download page for how to open them.
