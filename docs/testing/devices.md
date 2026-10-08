# Test devices and what each one covers

The maintainer's test fleet (generic descriptions). Update this file when devices change.

| Device | Covers | Limits |
|---|---|---|
| Apple Silicon MacBook | macOS app and File Provider, Xcode and the iOS Simulator (all phone sizes, older iOS runtimes), Android emulator on Apple Silicon, self-hosted macOS CI runner, notarisation | No NFC reader. The Simulator has no Secure Enclave. No KVM for Linux VMs |
| M-series iPad | Real iPadOS device: Touch ID and Secure Enclave, USB-C security key, Files / File Provider, background execution and battery, local-network permission and LAN P2P, camera upload, offline pinning | **No NFC reader**, no Face ID, no iPhone layout (use the Simulator), no cellular unless a SIM is present |
| recent Samsung flagship (Android, One UI) | Real Android: hardware-backed key store, ultrasonic fingerprint, NFC and USB-C security keys, aggressive battery optimisation, camera upload, offline pinning, hotspot for the airplane scenario, remote wipe | One Android version and one vendor skin; older versions and low-end phones come from emulator images |
| Windows PC | Windows app: Cloud Files placeholders, Defender and indexer behaviour, long paths, Windows Hello and USB security keys, installer and updates, code signing | Dual boot with Linux on the same machine: not both at once |
| Linux PC (same machine) | Linux VM suites with KVM, Android emulator, hot-plugged virtual disks, multi-VM virtual networks, CLI and daemon, FUSE placeholders; runs the agent-driven suites | Not available while booted into Windows |

## Gaps (acquire once the app exists)

- An iPhone with NFC (preferably older) for iPhone layouts, NFC key tests and Face ID.
- A low-end or older Android phone from a different vendor.
- At least two hardware security keys (one USB-C, one with NFC) for backup-key and key-loss tests.
- Optionally a second Mac or Windows machine for multi-machine P2P tests.

## Suggested split

- Linux boot: Linux VM suites, Android emulator, removable-disk scenarios, deterministic simulation (agents run these).
- Mac: iOS Simulator and macOS app (an agent may run `xcodebuild test` if allowed).
- Real devices (recent Samsung flagship and M-series iPad): manual checklists in `docs/testing/manual/` for biometrics, security keys, background, LAN and camera upload.
- Windows boot: the Windows checklist.

## Network notes

Put all devices on one LAN for peer-to-peer tests and check that the router does not isolate wireless clients. For the offline scenario, use the phone's hotspot with mobile data turned off.
