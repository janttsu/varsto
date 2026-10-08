---
title: Alpha.6: the source is public, and every platform builds in the cloud
date: 2026-10-09
summary: The repository is now public on GitHub under the PolyForm Shield licence, the native macOS and iOS apps build on GitHub Actions, Linux, Windows and Android build on short-lived cloud machines, and the interface was redone around a file view.
---
Since alpha-0 the alphas have added most of what the plan calls the core: S3 and rclone storages, sharing with another user by a sealed key, hybrid post-quantum signatures and key exchange, durability policies that warn in time, peer-to-peer transfer between your own devices, compression before encryption, Strongroom folders behind a FIDO2 security key, a printable recovery kit, and an MCP server so an assistant can read and reorganise exactly the folders you grant. Alpha.6 is about the project around that code.

## The source is public

The repository lives at [github.com/janttsu/varsto](https://github.com/janttsu/varsto) under the [PolyForm Shield License 1.0.0](../docs/licence.html): source-available, not open source. Read it, build it, report what breaks in the issue tracker. The history was rewritten before publication so that it carries no personal paths or addresses; if you cloned an earlier private copy, clone again.

## Every platform is built by a machine that did not exist an hour earlier

- **macOS and iOS** build on GitHub Actions on Apple Silicon runners: the test suite, the native Varsto.app with its own window, menu-bar item and bundled command line, and the iOS shell for the Simulator, which is launched there and photographed. A tagged release gets the macOS zip attached automatically.
- **Linux, Windows and Android** build and test on short-lived cloud machines created by a script, used once and deleted: the full test suite on a real Ubuntu, the Windows zip installed and exercised on a real Windows Server, the Android APK built with the SDK and NDK and then run in an emulator.

No build depends on a developer's laptop any more, which also means every package on the download page comes from a documented, repeatable path.

## A file view first

The interface was redone: a sidebar with a folder tree, a Files view with breadcrumbs, state squares and a details pane, and a phone mode in which tables become cards and the navigation moves to the bottom. On a phone a folder is added by name alone; the device chooses where it lives, so you never type a directory. There is also a guarded "start over on this device" in Settings for the alpha, and the overview suggests where idle files would be cheaper to keep, from Varsto's own last-used record and open price data.

## Still alpha

Nothing here changes the warning on every page: the cryptography has not been audited, the format may still change, and a bug can destroy data. Use test data, keep your own backups, and read the [failure model](../docs/failure-model.html) before trusting it with anything else.
