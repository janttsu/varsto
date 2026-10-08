#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Build the Android app: Rust binary for arm64 and x86_64 via the NDK, then Gradle.
# Needs ANDROID_HOME with platforms;android-35, build-tools;35.0.0, ndk;27.*, and a JDK 17+.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
: "${ANDROID_HOME:?set ANDROID_HOME}"
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
./gradlew --no-daemon -q assembleDebug
ls -l app/build/outputs/apk/debug/*.apk
