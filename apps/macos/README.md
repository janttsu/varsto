# Varsto for macOS

A native app: its own window with the interface (WebKit inside the app, no browser), a menu-bar item with status, pause, "Start at login" and, when a newer version exists, "Install update" (the app updates itself from the signed disk image), and the `varsto` binary inside the bundle. Background sync runs as a launch agent shared by the app and the command line, so it keeps running after the app quits. The `varsto` command is linked into /opt/homebrew/bin or /usr/local/bin automatically ("Install command-line tool…" in the menu remains as a fallback, or use `Varsto.app/Contents/Helpers/varsto`). Download and Free up space from Finder run in the background without opening the window. Apple Silicon only.

Build on a Mac (Xcode command line tools and rustup installed):

    apps/macos/build.sh            # -> apps/macos/dist/Varsto-<version>-macos.dmg
    open apps/macos/dist/Varsto-<version>-macos.dmg   # drag Varsto to Applications, then open it (right-click, Open the first time)

Publish to the download page from the same Mac (needs pandoc, rsync and SSH access to the site host):

    website/publish-macos.sh apps/macos/dist/Varsto-<version>-macos.dmg

The app stores its vault under `~/Library/Application Support/Varsto`, the same place the command line uses by default on macOS, so both see the same folders. The passphrase can be kept in the login keychain so the service unlocks itself after login. The app is ad-hoc signed and not notarised; a Developer ID signature and notarisation come with the Apple Developer account.

Finder: right-click files for **Download with Varsto** and **Free up space with Varsto** (Services, or Quick Actions on newer macOS; System Settings > Keyboard > Keyboard Shortcuts > Services lists them). Double-clicking a placeholder (`name.varsto-placeholder`) downloads the file and opens it. Freeing is refused unless every block is on a storage and the file on disk is the version that was synced. macOS registers the Services when Varsto.app sits in Applications and has been opened once.
