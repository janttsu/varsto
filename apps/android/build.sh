#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Build the Android app: Rust binary for arm64 and x86_64 via the NDK, then Gradle.
# Needs ANDROID_HOME with platforms;android-35, build-tools;35.0.0, ndk;27.*, and a JDK 17+.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
: "${ANDROID_HOME:?set ANDROID_HOME}"

# All four must be set for a release APK. None set: a debug APK for local use
# and the emulator (adb run-as). A partial set is a mistake, not a cue to
# sign the release with the debug keystore. Checked before the NDK build so a
# bad secret fails closed without compiling.
signing_vars=(VARSTO_ANDROID_KEYSTORE VARSTO_ANDROID_KEYSTORE_PASSWORD VARSTO_ANDROID_KEY_ALIAS VARSTO_ANDROID_KEY_PASSWORD)
present=0
missing=0
for v in "${signing_vars[@]}"; do
  if [ -n "${!v:-}" ]; then present=1; else missing=1; fi
done
if [ "$present" = 1 ] && [ "$missing" = 1 ]; then
  echo "Android release signing is incomplete. Set all of ${signing_vars[*]}, or none of them. Refusing the debug keystore for a release build." >&2
  exit 1
fi
if [ "$present" = 1 ] && [ ! -f "$VARSTO_ANDROID_KEYSTORE" ]; then
  # CI passes VARSTO_ANDROID_KEYSTORE from a GitHub secret: a filesystem path,
  # or the keystore bytes as base64. Never write that file into the tree.
  decoded="$(mktemp "${TMPDIR:-/tmp}/varsto-android-keystore.XXXXXX")"
  if ! printf '%s' "$VARSTO_ANDROID_KEYSTORE" | tr -d '[:space:]' | base64 -d > "$decoded"; then
    rm -f "$decoded"
    echo "VARSTO_ANDROID_KEYSTORE is not a file and is not valid base64. Refusing an unsigned release." >&2
    exit 1
  fi
  if [ ! -s "$decoded" ]; then
    rm -f "$decoded"
    echo "VARSTO_ANDROID_KEYSTORE decoded empty. Refusing an unsigned release." >&2
    exit 1
  fi
  export VARSTO_ANDROID_KEYSTORE="$decoded"
fi

ndk="$(ls -d "$ANDROID_HOME"/ndk/* | sort | tail -1)"
tc="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
[ -d "$tc" ] || tc="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
rustup target add aarch64-linux-android x86_64-linux-android >/dev/null
export CC_aarch64_linux_android="$tc/aarch64-linux-android24-clang" AR_aarch64_linux_android="$tc/llvm-ar" CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$tc/aarch64-linux-android24-clang"
export CC_x86_64_linux_android="$tc/x86_64-linux-android24-clang" AR_x86_64_linux_android="$tc/llvm-ar" CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$tc/x86_64-linux-android24-clang"
cargo build --release --target aarch64-linux-android -p varsto-cli
cargo build --release --target x86_64-linux-android -p varsto-cli
mkdir -p "$root/apps/android/app/src/main/jniLibs/arm64-v8a" "$root/apps/android/app/src/main/jniLibs/x86_64"
cp "$root/target/aarch64-linux-android/release/varsto" "$root/apps/android/app/src/main/jniLibs/arm64-v8a/libvarsto.so"
cp "$root/target/x86_64-linux-android/release/varsto" "$root/apps/android/app/src/main/jniLibs/x86_64/libvarsto.so"
cd "$root/apps/android"
if [ ! -f gradlew ]; then gradle wrapper --gradle-version 8.11.1 -q 2>/dev/null || { echo "no gradle; see README" >&2; exit 1; }; fi
if [ "$present" = 1 ]; then
  ./gradlew --no-daemon -q assembleRelease
  ls -l app/build/outputs/apk/release/*.apk
else
  echo "Android release signing is unset; building a debug APK, which must not be published." >&2
  ./gradlew --no-daemon -q assembleDebug
  ls -l app/build/outputs/apk/debug/*.apk
fi
