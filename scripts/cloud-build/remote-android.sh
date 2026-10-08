#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Runs on a fresh Ubuntu build instance: installs a JDK, the Android SDK
# (platform 35, build-tools 35, NDK 27) and Rust, then builds the debug APK.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential pkg-config curl git zip unzip openjdk-17-jdk-headless >/dev/null
export ANDROID_HOME=/opt/android-sdk
if [ ! -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
  mkdir -p "$ANDROID_HOME/cmdline-tools"
  curl -fsSL -o /tmp/cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
  unzip -q /tmp/cmdline-tools.zip -d "$ANDROID_HOME/cmdline-tools"
  mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
fi
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
yes | sdkmanager --licenses >/dev/null 2>&1 || true
sdkmanager --install "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;27.2.12479018" >/dev/null
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
cd /build/varsto
version="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')"
echo "== Android build ($version) on $(lsb_release -ds)"
apps/android/build.sh 2>&1 | tail -3
mkdir -p dist/android
cp apps/android/app/build/outputs/apk/debug/app-debug.apk "dist/android/varsto-$version-android-debug.apk"
(cd dist/android && sha256sum ./*.apk > SHA256SUMS)
ls -la dist/android/
