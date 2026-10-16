# Varsto on Windows

Varsto for Windows has an installer, its own window, a tray icon, a
background service that starts at login, and updates itself. It needs
Windows 10 or 11 (64-bit).

## Installing

Download `Varsto-<version>-setup.exe` from the [download page](https://varsto.net/downloads/)
and run it.

- **For you only** (default): installs into
  `%LOCALAPPDATA%\Programs\Varsto`, without administrator rights.
- **For all users**: the first page of the wizard offers it; Windows asks for
  administrator rights. Varsto then starts at login for every user, each with
  their own data folder.

The installer puts a Varsto entry in the Start menu (and on the desktop,
unless you untick it), starts the background service and the tray icon, and
opens Varsto. The program is not code-signed yet, so SmartScreen may say
"Windows protected your PC": choose "More info", "Run anyway", and check the
download first as described on the download page
(`varsto verify-release <file>` or minisign).

Varsto shows its interface in a window of its own. That window uses the
Microsoft Edge **WebView2 Runtime**, which is part of Windows 11 and of
current Windows 10. If it is missing, the installer installs it (a small
download from Microsoft). If you declined or it failed, Varsto opens the
interface in your default browser instead and offers the download page;
install it from <https://developer.microsoft.com/microsoft-edge/webview2/>
(the "Evergreen Bootstrapper") and open Varsto again.

## Using it

- Start menu > **Varsto** opens the window. Closing the window does not stop
  syncing: the service and the tray icon keep running. A second click on the
  icon brings the open window to the front.
- The tray icon menu: status, **Open Varsto**, pause syncing, install an
  update, **Quit Varsto** (stops the service too).
- The window remembers its size and position.
- Right-click a file in Explorer: **Download with Varsto** and **Free up
  space with Varsto**; double-click a `.varsto-placeholder` file to download
  and open it (set up by the installer through `varsto install`).
- The command line is `varsto.exe` in the install folder. It is not on your
  `PATH`; call it by its path or add the folder to `PATH`.

## Upgrading

Run a newer `Varsto-<version>-setup.exe` over the old installation. Setup
finds the installation by its fixed identity, says whether it upgrades,
repairs (same version) or downgrades (older: it asks first), closes the
window, the tray and the service, replaces the files, and starts Varsto
again. Your vault, settings and the files you sync are not touched. The same
setup in the same version repairs a damaged installation.

### Automatic updates

The service looks for a new version once a day. When one is out:

1. the signed release is checked exactly as `varsto update` does it
   ([RELEASING.md](../RELEASING.md): release signature, version, signing
   time, the checksum on GitHub as a second channel, the SHA-256 of the file);
2. the signed `Varsto-<version>-setup.exe` is downloaded into a private temporary
   folder and run silently (`/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS`);
3. Varsto closes, is replaced and starts again within a minute, and a
   notification says so.

Nothing is installed without the signature. To turn the daily check and the
installation off, clear **Check for updates every day** (Settings, Service)
or run

```
varsto config auto-update off      # on turns it back on; varsto config shows the state
```

You can always update by hand: `varsto update` (or `varsto update --check`),
the update button in the interface or the tray menu. Both always run the
installer; a copy that the setup program did not install cannot update
itself (see "Coming from the portable zip" below).

`varsto update --daily` takes the newest daily (test) build instead of a
release: the signed `varsto-daily-windows-setup.exe`, run like the release
setup program. It is checked against the separate daily key ([RELEASING.md](../RELEASING.md),
Daily builds), never happens by itself, and `varsto --version` then names the
daily build. `varsto update --stable` goes back to releases once one is newer.

## Uninstalling

Settings > Apps > Installed apps > Varsto > Uninstall (or the "Uninstall
Varsto" entry in the Start menu). The uninstaller closes Varsto, removes the
program, the shortcuts, the login start, the Explorer menu entries and the
window and WebView2 caches.

It asks whether to delete Varsto's **data folder** too, and the answer is
No unless you say Yes. Without the data folder (or the vault key) this
device cannot open the vault again; your files in your own folders and in
your storages are never removed by the uninstaller.

## Silent installation (administrators)

```
Varsto-<version>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
Varsto-<version>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS /DIR="C:\Program Files\Varsto"
Varsto-<version>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CURRENTUSER /TASKS="!desktopicon"
```

The usual [Inno Setup switches](https://jrsoftware.org/ishelp/topic_setupcmdline.php)
apply (`/LOG=file`, `/DIR=`, `/TASKS=`, `/ALLUSERS`, `/CURRENTUSER`). Notes:

- Silent runs upgrade and repair an existing installation without asking; a
  silent run of an *older* setup is refused (exit code is not 0).
- Silent uninstall: `"%LOCALAPPDATA%\Programs\Varsto\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES`.
  It keeps the data folder; add `/DELETEDATA=1` to delete it.
- Disable automatic updates for a machine by running
  `varsto.exe config auto-update off` as the user (a per-user setting, in
  the data folder), or point `VARSTO_UPDATE_URL` at an internal mirror (the
  signature check is the same).
- With an all-users installation, run Varsto's per-user steps (`varsto
  install`, the tray) in each user's session; the Run key starts the tray for
  every user at login.

## Where things live

| What | Where |
| --- | --- |
| Program files | `%LOCALAPPDATA%\Programs\Varsto` (per user) or `C:\Program Files\Varsto` (all users); also in the registry: `HKCU\Software\Varsto\InstallPath` (`HKLM` for all users) |
| Data folder (device key, settings, service files, logs) | `%APPDATA%\Varsto`, or the folder in `VARSTO_HOME` / `--home` |
| Window position, WebView2 profile (caches) | `%LOCALAPPDATA%\Varsto` |
| Login start | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `Varsto` (`HKLM` for all users) |
| Logs | `service.log` and the log folder in the data folder (tray menu or Settings > Logs) |

## Coming from the portable zip

Up to 0.0.1-alpha.14 there was also a portable zip. It is gone: the installer
is the only Windows download, and the only way Varsto updates on Windows.
An old portable copy cannot update itself; `varsto update` (and
`varsto update --daily`) says so and names the installer. Download and run
`Varsto-<version>-setup.exe` once, and updates continue automatically from
there. Your vault and settings live in the data folder, which the installer
never touches, so the new installation finds them; you can delete the old
unzipped folder afterwards.

## Problems

- *A window opens in the browser instead.* The WebView2 Runtime is missing
  or could not start; see above.
- *Nothing happens at login.* Check the Run key above and Task Manager >
  Startup apps; run `varsto-window.exe --background` by hand.
- *The service does not start.* Read `service.log` in the data folder, or run
  `varsto.exe service run` in a terminal.
- Report a problem with the output of `varsto.exe --version` and the setup
  log (`Varsto-<version>-setup.exe /LOG=setup.log`).

## For developers

- `crates/varsto-window`: the window program (`wry` + `tao`, Windows only; on
  other systems it is a stub that explains this).
- `installer/windows/varsto.iss`, `build.ps1` (icon, WebView2 bootstrapper,
  compiler), `make-ico.py` (icon from `brand/png`), `smoke-test.ps1` (what CI
  runs: install, upgrade in place, repair, refused downgrade, window, uninstall).
- CI: the `windows-installer` job in `.github/workflows/ci.yml` builds and
  tests the installer on Windows Server 2025 and uploads it; the download
  set (`website/assemble-release.sh`) lists it as the Windows download. The
  cross-compiled `varsto.exe` and `varsto-window.exe` (`dist/windows/app`,
  made by `website/build-release.sh`) are only the installer's input and
  the Windows smoke test's, not downloads.
