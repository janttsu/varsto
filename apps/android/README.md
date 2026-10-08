# Android app

A thin Android shell: a foreground service runs the same `varsto service`
binary as the desktop (shipped as `libvarsto.so` so that Android places it in
the executable native library directory), and the activity shows the local
interface in a WebView over loopback with the session token.

Build: `apps/android/build.sh` (Android SDK with platform 35, build-tools 35,
NDK 27 and a JDK 17 or newer). The result is a debug-signed APK for sideloading
(`adb install`). Play Store packaging, SAF folder access, camera upload and the
battery-friendly scheduling of plan 6.30/6.36 are future work; the alpha syncs
folders under the app's private storage only.
