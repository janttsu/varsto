# iOS app (source, build on a Mac)

The iOS app is a SwiftUI shell around the same Rust core and the same local
interface as the desktop app. Apple does not allow a separate background
executable, so the core is linked as a static library (`varsto-ffi`) and the
service runs on a thread inside the app process; the user interface is the
embedded web page in a `WKWebView`, reached over the loopback interface with
the session token. The service is started once per process, at launch
(`AppDelegate`), also when iOS launches the app in the background for one of
its background tasks, and runs for as long as iOS keeps the process.

Build (macOS with Xcode):

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo build --release --target aarch64-apple-ios -p varsto-ffi
cargo build --release --target aarch64-apple-ios-sim -p varsto-ffi
apps/ios/build.sh   # creates the Xcode project with xcodegen and builds
```

## Files

- `Varsto/VarstoApp.swift`: app, service host, the web view and its bridges
  (`WebBridge`), video thumbnails, and `tr`, the native strings in English,
  Finnish and Swedish (following the language picked in the interface).
- `Varsto/CameraUpload.swift`: camera upload and a small client of the local API.
- `Varsto/Background.swift`: the background tasks.
- `Varsto/MediaViewer.swift`: the native viewer.

## Camera upload

The same feature as on Android, with the same settings card in the interface
(Settings, Camera upload): new photos and videos go into one Varsto folder, in
`YYYY/MM` subfolders by capture date, optionally only on Wi-Fi, only while
charging, and with or without screenshots. The page talks to the shell through
`window.VarstoIOS`, which has the methods of Android's `window.VarstoAndroid`
(`cameraUpload`, `setCameraUpload`, `hasMediaAccess`, `requestMediaAccess`,
`openAppSettings`); the settings are kept in the app's preferences
(`camera_upload.*`), not in the service.

- PhotoKit, read access (`NSPhotoLibraryUsageDescription`). With limited access
  iOS shows Varsto only the photos the user picked, so new photos are not seen;
  the status line says so. Once refused, iOS does not ask again and the page
  offers to open the app's settings.
- New means created since camera upload was switched on, in the user's own
  library (not shared albums or photos synced from a computer). Screenshots
  are left out unless chosen. Unlike Android, iOS cannot tell camera pictures
  from pictures saved from other apps, so those are uploaded too.
- Each item's original file is exported with `PHAssetResourceManager` (HEIC,
  JPEG, RAW or the video as taken, not an edited version; from iCloud if it is
  not on the phone), streamed to a temporary file and sent with
  `POST /api/upload?folder=…&path=…`; a Live Photo's video goes up as a second
  file (`IMG_1234.HEIC` and `IMG_1234.MOV`). The temporary file is removed
  after each upload. Files over 16 GiB (the service's limit) are skipped.
- Done items are remembered as `image|video:<localIdentifier>:<creation time>`
  in `Application Support/camera-upload-done.txt`; a file that is already in
  the folder with the same size is not sent again, and a different file with
  the same name gets ` (2)`.
- After a video, a frame made with AVFoundation goes to `/api/thumbnail`; in a
  folder kept encrypted on the phone, `/api/free` drops the uploaded blocks
  once a storage has them, as on Android.
- Wi-Fi only means a satisfied path over Wi-Fi or Ethernet that is neither
  expensive (a phone's hotspot) nor constrained (Low Data Mode), from
  `NWPathMonitor`. Charging means `UIDevice.batteryState` is charging or full.
- Status messages are those of Android ("Waiting for Wi-Fi", "Waiting for the
  charger", "Waiting for the Varsto service", "Waiting for Varsto to be
  unlocked", "Folder X is not on this phone", "X is larger than 16 GiB and was
  skipped"); the page translates them. Instead of Android's notification,
  progress ("Uploading 2 of 5 to Camera") is shown in the same status line.

Local API calls: `GET /api/state`, `GET /api/folders`,
`GET /api/files?folder=`, `POST /api/upload?folder=&path=` (raw body),
`POST /api/thumbnail`, `POST /api/free`, and `POST /api/sync` from the app
refresh task, all with the `X-Varsto-Token` header.

### When it runs

- In the foreground: at launch, when the app becomes active, when the photo
  library changes (`PHPhotoLibraryChangeObserver`), when the network or the
  charger changes, after a settings change, and every 30 minutes.
- When the app goes to the background, it asks for the usual extra time
  (`beginBackgroundTask`, about 30 seconds) to finish the item under way.
- In the background only when iOS decides: `BGAppRefreshTask`
  (`in.soderlund.varsto.ios.refresh`, about 30 seconds: uploads, then one sync)
  and `BGProcessingTask` (`in.soderlund.varsto.ios.camera-upload`, needs a
  network, and external power when "Only while charging" is on; iOS tends to
  run it at night on the charger). Both are requested again each time the app
  goes to the background and after each run. iOS may run them rarely or never,
  for example after the user swiped the app away, in Low Power Mode, or when
  Background App Refresh is off for Varsto. When time runs out the transfer is
  cancelled; what was uploaded stays done and the rest goes up next time.
  Nothing runs while the phone is locked before its first unlock after a restart.

## Viewer

In a folder kept encrypted on the phone, tapping a picture, video, audio or
text file opens a native full-screen viewer instead of the page's own:
`openViewer` in `app.js` posts the list to
`window.webkit.messageHandlers.varstoViewer` (only on iOS; desktop and Android
are unchanged). Everything is read through `/api/view` (token in the query, as
the page does), which decrypts in memory with range requests:

- Swipe between files, pinch or double-tap to zoom, tap to hide the bar, swipe
  down or Done to close.
- Pictures (including HEIC) are decoded with ImageIO straight to about 1.5×
  the screen size; the neighbours are decoded ahead, at most five are kept.
- Video and audio play in AVKit with seeking; a player exists only while its
  page is on screen.
- Text shows the first 256 KiB; PDFs and other files show a note.
- Share fetches the whole file (in 8 MiB ranges) into a temporary directory,
  hands it to the share sheet and removes it when the sheet closes; the first
  share in a session asks first, as the page does.

The file list's Open and Share buttons (Android's `openFile`/`shareFile`) have
no iOS counterpart yet.

## Testing

There is no XCTest target. Nothing in this directory has been run on a real
device. Manual checks on an iPhone:

1. Settings, Camera upload: switch on, create the folder, allow access. Take a
   photo, a Live Photo, a video and a screenshot; the photo, both Live Photo
   files and the video appear under `YYYY/MM`, the screenshot only with
   "Also screenshots". The status line counts them.
2. Allow only selected photos: the status line explains it. Refuse access,
   switch on again: the page offers the app settings.
3. Wi-Fi only on mobile data, and on a phone hotspot: "Waiting for Wi-Fi";
   joining Wi-Fi starts the upload. Charger only, unplugged: "Waiting for the
   charger"; plugging in starts it.
4. Lock Varsto (or quit and reopen before unlocking): "Waiting for Varsto to be
   unlocked". Remove the folder from the phone: "Folder X is not on this phone".
5. Remove `Library/Application Support/camera-upload-done.txt` from the app's
   container (Xcode, Devices and Simulators, replace container) and reopen:
   files already in the folder with the same size are not uploaded again.
6. Background: in Xcode, pause the app and run
   `e -l objc -- (void)[[BGTaskScheduler sharedScheduler] _simulateLaunchForTaskWithIdentifier:@"in.soderlund.varsto.ios.camera-upload"]`
   (and the same for `.refresh`); new photos go up while the app is in the
   background. Also leave the phone on the charger overnight.
7. Viewer: open a large HEIC, a JPEG, a 4K video (seek), an audio file, a text
   file and a PDF in an encrypted folder; swipe through, zoom, swipe down to
   close, rotate. Share a picture to Files and check that `tmp/share-*` is gone
   afterwards. Watch memory in Xcode while paging through 50 large pictures.
8. Finnish and Swedish: switch the language in Settings and repeat a few of the
   above.

Status: built and launched in the iOS Simulator on GitHub's Apple Silicon
runners on every change (screenshots included); not yet run on a real iPhone
or iPad. Camera upload, the background tasks and the native viewer were
written without a Mac at hand and have not been compiled yet. Video thumbnails are made natively (AVAssetImageGenerator). The app
store listing and File Provider integration are future work.
