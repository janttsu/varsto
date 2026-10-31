# Android app

A thin Android shell: a foreground service runs the same `varsto service`
binary as the desktop (shipped as `libvarsto.so` so that Android places it in
the executable native library directory), and the activity shows the local
interface in a WebView over loopback with the session token.

Build: `apps/android/build.sh` (Android SDK with platform 35, build-tools 35,
NDK 27 and a JDK 17 or newer). Set `VARSTO_ANDROID_KEYSTORE`,
`VARSTO_ANDROID_KEYSTORE_PASSWORD`, `VARSTO_ANDROID_KEY_ALIAS` and
`VARSTO_ANDROID_KEY_PASSWORD` to build a release APK signed with that key
(not debuggable). The keystore variable is a path, or the keystore file in
base64. If any of the four is missing, the release build fails instead of
using the debug keystore. With none of them set, the script builds a debug
APK for local use and the emulator; do not publish it. A debug APK is signed
with a new debug key every time, so an update cannot install over the
previous one (uninstalling wipes the vault). The version name is the
workspace Cargo.toml version. For `0.0.1-alpha.N` the version code is `N`
when `N` is an integer greater than 13 (that code already shipped); any other
version fails configuration. Each folder is either "encrypted on this phone" (only its
encrypted blocks are kept, in the app's private space; selective sync chooses
which files, as in any folder) or "plain files on this phone" under Internal
storage/Varsto, which needs all files access (asked for when that mode is
chosen). The page adds files through the system file chooser and hands files
to other apps through a FileProvider (Open with, Share); for an encrypted
folder the service first writes a decrypted copy to `files/vault/exports`
(`POST /api/export`), removed when the vault locks and when the service
starts.

Folders kept encrypted on the phone open in an in-app viewer by default:
pictures, video, audio and text are streamed from `GET /api/view`, which
decrypts only the requested byte range in memory (from the block cache when
the file is kept on the phone), so no plaintext copy is written to the phone. PDFs and other types still go to another app, which
receives a decrypted copy (the page says so before handing one over).

Camera upload (Settings): `CameraUpload.kt` runs inside the foreground
service. A ContentObserver on MediaStore images and videos, plus power,
network and a 30-minute timer, triggers a scan; new camera items (and
screenshots if chosen) are posted to `/api/upload` under `YYYY/MM/` of their
capture date, and each MediaStore id and date added is remembered in
`camera-upload-done.txt` so nothing is uploaded twice. Originals are never
changed or deleted. It asks for READ_MEDIA_IMAGES and READ_MEDIA_VIDEO
(READ_EXTERNAL_STORAGE before Android 13) when the user turns it on.

Video thumbnails are made natively (`VideoThumbs.kt`, MediaMetadataRetriever);
no ffmpeg is needed. The file list is compact on a phone: a long press starts
selecting files to download or free.

Play Store packaging, SAF folder access and the battery-friendly scheduling
of plan 6.30/6.36 are future work.

Logs (debug level, on by default) are in the app's private `files/vault/logs/`:
`varsto-service.log` from the Rust service and `varsto-app.log` from the shell
(`AppLog.kt`: service process start, exit code and restarts, activity events,
camera upload scans and uploads by file name, errors that used to be
swallowed). Both rotate at 10 MiB, keeping four old files. The service's
console output still goes to `files/vault/service.log`. The service URL, the
session token, passphrases and file contents are never logged. On a debug
build: `adb shell run-as in.soderlund.varsto cat files/vault/logs/varsto-app.log`.
