# Testing the Android and iOS apps before release

A guide for people who have not tested mobile apps before. Facts below come from public documentation and articles gathered in 2026; check the linked vendors' current pages before relying on limits, prices or quotas.

## Short answer

- **Android:** yes, most tests can run in an emulator, including headless inside a Linux virtual machine, as long as the machine offers hardware virtualisation (KVM). Real phones are still needed for hardware-specific features.
- **iOS:** the iOS Simulator runs only on macOS. Apple's licence allows macOS virtual machines only on Apple hardware, so you cannot run iOS tests inside a Linux VM. Use a Mac (local or hosted).
- **Real devices** are required for anything that depends on hardware: biometrics bound to a secure element, NFC / USB security keys, real background execution and battery behaviour, and local-network behaviour between two phones.

## What an emulator can and cannot test

| Area | Android emulator | iOS Simulator | Real device needed? |
|---|---|---|---|
| UI flows, navigation, language, dark mode | yes | yes | no |
| File access, selective sync UI, offline pinning | yes | yes (File Provider works) | for final check |
| Camera upload (add test media to the gallery) | yes (scripted) | yes (add photos) | for background limits |
| Passphrase unlock, wipe counter logic | yes | yes | no |
| Biometrics bound to hardware keys | simulated only | Secure Enclave is not available; biometrics only partly simulated | **yes** |
| NFC / USB-C security key (FIDO2) | no NFC hardware | no | **yes** |
| Background execution, Doze, BGTasks, battery | partly | partly | **yes** |
| Push notifications | yes | limited (sandbox, newer Macs) | for end-to-end |
| LAN discovery and P2P between two devices | emulator network is isolated | simulator shares the Mac network | **yes** (two phones) |
| Performance and thermal behaviour | not representative | not representative | **yes** |

## Android: how to test, step by step

1. **Run the core on Linux first.** Most of the logic (crypto, sync, bookkeeping) is a Rust library that is tested on Linux (see TESTING.md). Only the thin Android layer needs an emulator.
2. **Emulator.** Install the Android command-line tools, create an Android Virtual Device (x86_64 image) and start it with hardware acceleration. Headless example: `emulator -avd <name> -no-window -no-audio -gpu swiftshader_indirect`, then `adb wait-for-device`. This is scriptable, so an AI agent or CI job can run it.
3. **KVM inside a VM.** The emulator needs KVM. On bare metal this works. Inside a virtual machine, nested virtualisation must be enabled on the host (check with `kvm-ok`). If nested virtualisation is not available, run the emulator on the host, or use Redroid (Android in a container on the host kernel, no `/dev/kvm`) for logic tests.
4. **UI tests.** Use the Android test frameworks (Espresso / UI Automator / Compose tests) or a cross-platform tool such as Maestro (YAML flows that run on Android and iOS). Appium is the heavier alternative.
5. **Real phone.** Enable developer options and USB debugging, then `adb install app.apk`. No store account is needed for this.
6. **Pre-release distribution.** Google Play *internal testing* (up to 100 testers, available within minutes, no full review) or Firebase App Distribution. Note: a new personal Play developer account may need a closed test with 12 testers for 14 days before production release; verify the current rule in Play Console help.

## iOS: how to test, step by step

1. You need a Mac with Xcode. The iOS Simulator is included.
2. **Run on the Simulator** from Xcode or from the command line with `xcodebuild test -destination 'platform=iOS Simulator,name=...'`. XCUITest and Maestro both work.
3. **Run on a real iPhone** from Xcode over a cable. A free Apple ID works for personal testing with short-lived signing; a paid Apple Developer account is required for TestFlight and the store.
4. **TestFlight.** Internal testers (up to 100) need no review; external testers (up to 10,000) need a first-build review; builds expire after 90 days.
5. **CI on macOS.** Options: Xcode Cloud (25 free compute hours per month with the Apple Developer Program, as reported), hosted macOS runners from CI providers, or a self-hosted runner on your own Mac. Standard GitHub-hosted macOS runners are reported to be free for public repositories; this repository is hosted elsewhere, so check what your CI offers.
6. **Cross-compiling the Rust core for iOS** requires the Apple SDK, i.e. macOS and Xcode.

## Device farms (optional)

Cloud services that rent real devices exist (Firebase Test Lab, AWS Device Farm, BrowserStack and others). Firebase Test Lab's free tier was reported as a small number of test runs per day; paid use is billed per device-hour. They are useful for compatibility checks on many models, not for hardware features such as NFC security keys.

## A practical plan

1. Test the Rust core on Linux (cheap, automated, no mobile tooling needed).
2. Add Android emulator tests on the same Linux machine or VM (KVM) and let a cheap AI agent run them from this document.
3. Add iOS Simulator tests on a Mac; run them yourself or from a self-hosted runner.
4. Buy or borrow two cheap real devices: one older Android phone and one older iPhone that supports the lowest iOS version you target. Use them for the hardware-dependent items in the manual checklists.
5. Distribute builds to yourself through Play internal testing and TestFlight before any public release.

## Results

Record every run with [report-template.md](report-template.md). Mark which items were verified on a real device and which only in an emulator.
