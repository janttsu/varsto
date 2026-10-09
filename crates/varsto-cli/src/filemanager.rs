// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! File-manager integration on Linux and Windows, the counterpart of the
//! Finder actions of the macOS app: "Download with Varsto" and "Free up space
//! with Varsto" on any file, and a double-click on a `.varsto-placeholder`
//! downloads the file and opens it.
//!
//! Every entry runs `varsto paths fetch|free <paths>` or `varsto
//! open-placeholder <path>`. Those go through the running background service
//! (`/api/paths`), or open the vault directly when no service runs (the
//! passphrase then comes from `VARSTO_PASSPHRASE`, the keyring or the
//! terminal). Launched from a file manager there is no terminal, so failures
//! are shown as a desktop notification (Linux) or a message box (Windows).
//!
//! Linux (installed by `varsto install`): a MIME type for placeholders with a
//! hidden application entry that handles it, Nautilus scripts, a Dolphin
//! service menu and Nemo actions. Thunar's custom actions live in one shared
//! `uca.xml` that cannot be merged safely, so they are left to the user (the
//! command to enter is in the manual). Windows: per-user registry entries
//! under `HKCU\Software\Classes` (context-menu verbs on all files and the
//! `.varsto-placeholder` association).

use crate::service;
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use varsto_core::engine::PLACEHOLDER_SUFFIX;
use varsto_core::Engine;

/// Fetch or free files given by absolute path; one result per path, in one
/// ledger batch. Shared by `/api/paths` and the command line.
pub fn act(engine: &mut Engine, action: &str, paths: Vec<String>) -> Result<Vec<Value>> {
    if action != "fetch" && action != "free" {
        bail!("unknown action {action}");
    }
    engine.one_batch(|engine| {
        let mut results = Vec::new();
        for p in paths {
            let r = engine
                .locate_path(Path::new(&p))
                .and_then(|(folder, file)| {
                    if action == "fetch" {
                        engine.fetch_file(&folder, &file).map(|_| ())
                    } else {
                        engine.free_file(&folder, &file)
                    }
                    .map(|()| file)
                });
            results.push(match r {
                Ok(file) => json!({"path": p, "file": file, "ok": true}),
                Err(e) => json!({"path": p, "ok": false, "error": format!("{e:#}")}),
            });
        }
        Ok(results)
    })
}

/// The real file of a placeholder path (unchanged for other paths).
pub fn real_path(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_suffix(PLACEHOLDER_SUFFIX) {
        Some(real) => PathBuf::from(real),
        None => p.to_path_buf(),
    }
}

/// Run `action` on `paths` through the service, or on the vault directly
/// when no service answers. `passphrase` is asked only in the second case.
pub fn run_paths(
    home: &Path,
    action: &str,
    paths: &[PathBuf],
    passphrase: impl FnOnce() -> Result<String>,
) -> Result<Vec<Value>> {
    let paths: Vec<String> = paths
        .iter()
        .map(|p| std::path::absolute(p).map(|a| a.display().to_string()))
        .collect::<std::io::Result<_>>()?;
    if let Some((f, _)) = service::status(home) {
        let url = format!("http://127.0.0.1:{}/api/paths", f.port);
        let body = json!({"action": action, "paths": paths}).to_string();
        let answer = match service::http_post(&url, &f.token, &body) {
            Err(e) if format!("{e:#}").contains("locked") => {
                // A service waiting to be unlocked: with the keyring's passphrase, do it.
                let unlocked = service::passphrase_from_system(home)
                    .is_some_and(|p| service::unlock_running(home, &p));
                if !unlocked {
                    bail!("the vault is locked: open Varsto and unlock it, then try again");
                }
                service::http_post(&url, &f.token, &body)?
            }
            other => other?,
        };
        let v: Value = serde_json::from_str(&answer)?;
        return v
            .get("results")
            .and_then(|r| r.as_array())
            .cloned()
            .ok_or_else(|| anyhow!("unexpected answer from the service: {answer}"));
    }
    let pass = match service::passphrase_from_system(home) {
        Some(p) => p,
        None => passphrase()?,
    };
    let mut engine = Engine::open(home, &pass)?;
    act(&mut engine, action, paths)
}

/// Failures of `results` as lines ("name: error").
pub fn failures(results: &[Value]) -> Vec<String> {
    results
        .iter()
        .filter(|r| r["ok"] != json!(true))
        .map(|r| {
            let p = r["path"].as_str().unwrap_or("");
            let name = Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| p.to_string());
            format!("{name}: {}", r["error"].as_str().unwrap_or("failed"))
        })
        .collect()
}

/// Download a placeholder (or nothing, when the file is already here) and
/// open the real file with the desktop's default application. The opener
/// can be replaced with `VARSTO_OPENER` (a program that gets the path).
pub fn open_placeholder(
    home: &Path,
    path: &Path,
    passphrase: impl FnOnce() -> Result<String>,
) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    let real = real_path(&path);
    let placeholder = PathBuf::from(format!("{}{PLACEHOLDER_SUFFIX}", real.display()));
    if placeholder.exists() || !real.exists() {
        let results = run_paths(home, "fetch", &[placeholder], passphrase)?;
        let failed = failures(&results);
        if !failed.is_empty() {
            bail!("{}", failed.join("\n"));
        }
    }
    open_with_desktop(&real)?;
    Ok(real)
}

fn open_with_desktop(path: &Path) -> Result<()> {
    let opener = std::env::var("VARSTO_OPENER")
        .ok()
        .filter(|o| !o.is_empty());
    let program = opener.as_deref().unwrap_or(if cfg!(windows) {
        "explorer.exe"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    });
    // Null standard handles: after the console is let go (Windows), the
    // inherited ones are invalid and process creation would fail.
    let status = std::process::Command::new(program)
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    // explorer.exe exits with 1 even when it opened the file.
    if !status.success() && !cfg!(windows) {
        bail!("{program} could not open {}", path.display());
    }
    Ok(())
}

/// Windows: when Explorer started this process, the console window is its
/// own (no other process shares it): close it and return true. Run from a
/// terminal, the console stays. Elsewhere: false.
pub fn detach_own_console() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawHandle;
        use windows_sys::Win32::System::Console::{
            FreeConsole, GetConsoleProcessList, SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
            STD_OUTPUT_HANDLE,
        };
        let mut ids = [0u32; 4];
        // SAFETY: the buffer and its length match; FreeConsole has no preconditions.
        let own = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) == 1 };
        if own {
            // SAFETY: FreeConsole has no preconditions.
            unsafe { FreeConsole() };
            // The old standard handles are now invalid: point them at NUL so
            // output is dropped and child processes (the opener, rclone) start.
            if let Ok(nul) = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("NUL")
            {
                let h = nul.into_raw_handle();
                for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
                    // SAFETY: h is a valid handle that stays open for the process lifetime.
                    unsafe { SetStdHandle(which, h as _) };
                }
            }
            return true;
        }
    }
    false
}

/// Tell the user about a failure when there is no terminal, and keep it in
/// `filemanager.log` in the device directory.
pub fn report_failure(home: &Path, title: &str, body: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join("filemanager.log"))
    {
        use std::io::Write;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "{now} {title}: {}", body.replace('\n', "; "));
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK};
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (t, b) = (wide(title), wide(body));
        // SAFETY: both strings are NUL-terminated and outlive the call.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                b.as_ptr(),
                t.as_ptr(),
                MB_OK | MB_ICONWARNING,
            );
        }
    }
    #[cfg(not(windows))]
    service::notify(title, body);
}

/// A double-quoted argument for an Exec line (desktop entries, Nemo
/// actions), escaped the way the Desktop Entry specification asks.
pub fn exec_quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+,:=@".contains(c));
    if plain {
        return s.to_string();
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            // Escaped inside the quotes, and the backslash once more for the
            // key file's own string escapes.
            '"' | '`' | '$' => {
                out.push_str("\\\\");
                out.push(c);
            }
            '\\' => out.push_str("\\\\\\\\"),
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A single-quoted argument for a POSIX shell script.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ----- Linux ---------------------------------------------------------------------

/// The files `varsto install` writes for file managers on Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod linux {
    use super::*;
    #[cfg(unix)]
    use std::fs;

    pub const MIME_TYPE: &str = "application/x-varsto-placeholder";
    const MIMEAPPS_LINE: &str = "application/x-varsto-placeholder=varsto-placeholder.desktop";

    /// A file relative to the XDG data directory.
    pub struct GenFile {
        pub path: &'static str,
        pub content: String,
        pub executable: bool,
    }

    /// Everything to write, for a binary at `exe` and the device directory `home`.
    pub fn files(exe: &Path, home: &Path) -> Vec<GenFile> {
        let exec = format!(
            "{} --home {}",
            exec_quote(&exe.display().to_string()),
            exec_quote(&home.display().to_string())
        );
        let script = |action: &str| {
            format!(
                "#!/bin/sh\n# Varsto: added by `varsto install`, removed by `varsto uninstall`.\n# Nautilus passes the selected files as arguments.\nexec {} --home {} paths --notify {action} -- \"$@\"\n",
                shell_quote(&exe.display().to_string()),
                shell_quote(&home.display().to_string())
            )
        };
        let nemo = |action: &str, name: &str, comment: &str, icon: &str| {
            format!(
                "[Nemo Action]\nName={name}\nComment={comment}\nExec={exec} paths --notify {action} -- %F\nIcon-Name={icon}\nSelection=notnone\nExtensions=any;\nQuote=double\n"
            )
        };
        vec![
            GenFile {
                path: "mime/packages/varsto-placeholder.xml",
                content: format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="{MIME_TYPE}">
    <comment>Varsto placeholder</comment>
    <generic-icon name="varsto"/>
    <glob pattern="*{PLACEHOLDER_SUFFIX}" weight="80"/>
  </mime-type>
</mime-info>
"#
                ),
                executable: false,
            },
            GenFile {
                path: "applications/varsto-placeholder.desktop",
                content: format!(
                    "[Desktop Entry]\nType=Application\nName=Varsto\nComment=Download the file and open it\nExec={exec} open-placeholder %f\nIcon=varsto\nTerminal=false\nNoDisplay=true\nMimeType={MIME_TYPE};\n"
                ),
                executable: false,
            },
            GenFile {
                path: "nautilus/scripts/Varsto/Download",
                content: script("fetch"),
                executable: true,
            },
            GenFile {
                path: "nautilus/scripts/Varsto/Free up space",
                content: script("free"),
                executable: true,
            },
            GenFile {
                // Plasma 6 runs service menus only when they are executable.
                path: "kio/servicemenus/varsto.desktop",
                content: format!(
                    "[Desktop Entry]\nType=Service\nX-KDE-ServiceTypes=KonqPopupMenu/Plugin\nMimeType=all/allfiles;\nActions=fetch;free;\nX-KDE-Submenu=Varsto\nIcon=varsto\n\n[Desktop Action fetch]\nName=Download with Varsto\nIcon=folder-download\nExec={exec} paths --notify fetch -- %F\n\n[Desktop Action free]\nName=Free up space with Varsto\nIcon=edit-clear\nExec={exec} paths --notify free -- %F\n"
                ),
                executable: true,
            },
            GenFile {
                path: "nemo/actions/varsto-fetch.nemo_action",
                content: nemo(
                    "fetch",
                    "Download with Varsto",
                    "Download the selected files and keep them on this device",
                    "folder-download",
                ),
                executable: false,
            },
            GenFile {
                path: "nemo/actions/varsto-free.nemo_action",
                content: nemo(
                    "free",
                    "Free up space with Varsto",
                    "Replace the selected files with placeholders (they stay in your storage)",
                    "edit-clear",
                ),
                executable: false,
            },
        ]
    }

    /// `mimeapps.list` with Varsto as the default for placeholders, keeping
    /// every other line. `None`: nothing to change (already set, or the user
    /// chose another application).
    pub fn mimeapps_add(text: &str) -> Option<String> {
        if text
            .lines()
            .any(|l| l.trim_start().starts_with(&format!("{MIME_TYPE}=")))
        {
            return None;
        }
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        match lines
            .iter()
            .position(|l| l.trim() == "[Default Applications]")
        {
            Some(i) => lines.insert(i + 1, MIMEAPPS_LINE.to_string()),
            None => {
                if lines.last().is_some_and(|l| !l.trim().is_empty()) {
                    lines.push(String::new());
                }
                lines.push("[Default Applications]".into());
                lines.push(MIMEAPPS_LINE.into());
            }
        }
        Some(lines.join("\n") + "\n")
    }

    /// `mimeapps.list` without the line `mimeapps_add` wrote.
    pub fn mimeapps_remove(text: &str) -> Option<String> {
        if !text.lines().any(|l| l.trim() == MIMEAPPS_LINE) {
            return None;
        }
        let kept: Vec<&str> = text.lines().filter(|l| l.trim() != MIMEAPPS_LINE).collect();
        Some(kept.join("\n") + "\n")
    }

    #[cfg(unix)]
    fn write_keep_mode(path: &Path, text: &str) -> Result<()> {
        let tmp = path.with_extension("varsto-tmp");
        fs::write(&tmp, text)?;
        if let Ok(meta) = fs::metadata(path) {
            fs::set_permissions(&tmp, meta.permissions())?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn refresh(data: &Path) {
        for (tool, dir) in [
            ("update-mime-database", data.join("mime")),
            ("update-desktop-database", data.join("applications")),
        ] {
            let _ = std::process::Command::new(tool)
                .arg(&dir)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }

    /// Write the integration into `data` (XDG data home) and `config` (XDG
    /// config home). Returns what was done, one line each.
    #[cfg(unix)]
    pub fn install(data: &Path, config: &Path, exe: &Path, home: &Path) -> Result<Vec<String>> {
        use std::os::unix::fs::PermissionsExt;
        for f in files(exe, home) {
            let p = data.join(f.path);
            fs::create_dir_all(p.parent().unwrap())?;
            fs::write(&p, &f.content)?;
            let mode = if f.executable { 0o755 } else { 0o644 };
            fs::set_permissions(&p, fs::Permissions::from_mode(mode))?;
        }
        let list = config.join("mimeapps.list");
        let text = fs::read_to_string(&list).unwrap_or_default();
        if let Some(new) = mimeapps_add(&text) {
            fs::create_dir_all(config)?;
            write_keep_mode(&list, &new)?;
        }
        refresh(data);
        Ok(vec![
            "placeholders: double-click downloads and opens the file".into(),
            "file managers: Download / Free up space with Varsto (Nautilus scripts, Dolphin, Nemo)"
                .into(),
        ])
    }

    #[cfg(unix)]
    pub fn uninstall(data: &Path, config: &Path) -> Result<Vec<String>> {
        for f in files(Path::new("varsto"), Path::new("")) {
            let _ = fs::remove_file(data.join(f.path));
        }
        // Only when empty: the user may keep own scripts there.
        let _ = fs::remove_dir(data.join("nautilus/scripts/Varsto"));
        let list = config.join("mimeapps.list");
        if let Some(new) = fs::read_to_string(&list)
            .ok()
            .and_then(|t| mimeapps_remove(&t))
        {
            write_keep_mode(&list, &new)?;
        }
        refresh(data);
        Ok(vec![
            "file-manager actions and the placeholder type removed".into(),
        ])
    }
}

// ----- Windows -------------------------------------------------------------------

/// Per-user registry entries for Explorer.
#[cfg_attr(not(windows), allow(dead_code))]
pub mod windows {
    use super::*;

    /// Keys under HKEY_CURRENT_USER that `uninstall` deletes as a whole.
    pub const KEYS: [&str; 4] = [
        r"Software\Classes\*\shell\Varsto.Fetch",
        r"Software\Classes\*\shell\Varsto.Free",
        r"Software\Classes\.varsto-placeholder",
        r"Software\Classes\Varsto.Placeholder",
    ];

    /// One string value: key under HKCU, value name ("" = default), data.
    #[derive(Debug, PartialEq)]
    pub struct RegValue {
        pub key: String,
        pub name: &'static str,
        pub data: String,
    }

    /// A command-line argument quoted for CommandLineToArgvW.
    fn arg(s: &str) -> String {
        format!("\"{}\"", s.trim_end_matches('\\'))
    }

    pub fn entries(exe: &Path, home: &Path) -> Vec<RegValue> {
        let exe_s = exe.display().to_string();
        let base = format!(
            "{} --home {}",
            arg(&exe_s),
            arg(&home.display().to_string())
        );
        let icon = format!("{exe_s},0");
        let v = |key: &str, name: &'static str, data: String| RegValue {
            key: key.to_string(),
            name,
            data,
        };
        let mut out = Vec::new();
        for (key, label, action) in [
            (KEYS[0], "Download with Varsto", "fetch"),
            (KEYS[1], "Free up space with Varsto", "free"),
        ] {
            out.push(v(key, "MUIVerb", label.to_string()));
            out.push(v(key, "Icon", icon.clone()));
            out.push(v(
                &format!(r"{key}\command"),
                "",
                format!("{base} paths --notify {action} -- \"%1\""),
            ));
        }
        out.push(v(KEYS[2], "", "Varsto.Placeholder".into()));
        out.push(v(KEYS[3], "", "Varsto placeholder".into()));
        out.push(v(&format!(r"{}\DefaultIcon", KEYS[3]), "", icon));
        out.push(v(
            &format!(r"{}\shell\open\command", KEYS[3]),
            "",
            format!("{base} open-placeholder \"%1\""),
        ));
        out
    }

    #[cfg(windows)]
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    #[cfg(windows)]
    fn assoc_changed() {
        use windows_sys::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};
        // SAFETY: no item pointers are passed with SHCNE_ASSOCCHANGED.
        unsafe {
            SHChangeNotify(
                SHCNE_ASSOCCHANGED as i32,
                SHCNF_IDLIST,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
    }

    #[cfg(windows)]
    pub fn install(exe: &Path, home: &Path) -> Result<Vec<String>> {
        use windows_sys::Win32::System::Registry::{RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ};
        for e in entries(exe, home) {
            let (k, n, d) = (wide(&e.key), wide(e.name), wide(&e.data));
            // SAFETY: NUL-terminated UTF-16 strings that outlive the call;
            // the data length is in bytes and includes the terminator.
            let rc = unsafe {
                RegSetKeyValueW(
                    HKEY_CURRENT_USER,
                    k.as_ptr(),
                    if e.name.is_empty() {
                        std::ptr::null()
                    } else {
                        n.as_ptr()
                    },
                    REG_SZ,
                    d.as_ptr().cast(),
                    (d.len() * 2) as u32,
                )
            };
            if rc != 0 {
                bail!("cannot write HKCU\\{} (error {rc})", e.key);
            }
        }
        assoc_changed();
        Ok(vec![
            "Explorer: Download / Free up space with Varsto in the context menu (Windows 11: Show more options)".into(),
            "placeholders: double-click downloads and opens the file".into(),
        ])
    }

    #[cfg(windows)]
    pub fn uninstall() -> Result<Vec<String>> {
        use windows_sys::Win32::System::Registry::{RegDeleteTreeW, HKEY_CURRENT_USER};
        for key in KEYS {
            let k = wide(key);
            // SAFETY: a NUL-terminated UTF-16 string that outlives the call.
            unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, k.as_ptr()) };
        }
        assoc_changed();
        Ok(vec!["Explorer entries removed".into()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_path_strips_the_suffix() {
        assert_eq!(
            real_path(Path::new("/a/b.txt.varsto-placeholder")),
            Path::new("/a/b.txt")
        );
        assert_eq!(real_path(Path::new("/a/b.txt")), Path::new("/a/b.txt"));
    }

    #[test]
    fn quoting() {
        assert_eq!(exec_quote("/usr/bin/varsto"), "/usr/bin/varsto");
        assert_eq!(exec_quote("/srv/My Files"), "\"/srv/My Files\"");
        assert_eq!(exec_quote("/a/$b"), "\"/a/\\\\$b\"");
        assert_eq!(exec_quote("/a/100%"), "\"/a/100%%\"");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn linux_files_call_the_cli() {
        let files = linux::files(Path::new("/opt/v/varsto"), Path::new("/data/my vault"));
        let get = |p: &str| files.iter().find(|f| f.path == p).unwrap();
        let mime = &get("mime/packages/varsto-placeholder.xml").content;
        assert!(mime.contains(r#"<glob pattern="*.varsto-placeholder""#));
        let handler = &get("applications/varsto-placeholder.desktop").content;
        assert!(
            handler.contains("Exec=/opt/v/varsto --home \"/data/my vault\" open-placeholder %f")
        );
        assert!(handler.contains("MimeType=application/x-varsto-placeholder;"));
        let dl = get("nautilus/scripts/Varsto/Download");
        assert!(dl.executable);
        assert!(dl.content.starts_with("#!/bin/sh\n"));
        assert!(dl.content.contains(
            "exec '/opt/v/varsto' --home '/data/my vault' paths --notify fetch -- \"$@\""
        ));
        let kde = get("kio/servicemenus/varsto.desktop");
        assert!(kde.executable);
        assert!(kde.content.contains("paths --notify free -- %F"));
        assert!(get("nemo/actions/varsto-fetch.nemo_action")
            .content
            .contains("Exec=/opt/v/varsto --home \"/data/my vault\" paths --notify fetch -- %F"));
    }

    #[test]
    fn mimeapps_merge_keeps_the_rest() {
        let user = "[Added Associations]\ntext/plain=gedit.desktop;\n\n[Default Applications]\nimage/png=eog.desktop\n";
        let added = linux::mimeapps_add(user).unwrap();
        assert!(added.contains("text/plain=gedit.desktop;"));
        assert!(added.contains("[Default Applications]\napplication/x-varsto-placeholder=varsto-placeholder.desktop\nimage/png=eog.desktop"));
        assert!(linux::mimeapps_add(&added).is_none());
        assert_eq!(linux::mimeapps_remove(&added).unwrap(), user);
        // The user's own choice stays.
        assert!(linux::mimeapps_add(
            "[Default Applications]\napplication/x-varsto-placeholder=other.desktop\n"
        )
        .is_none());
        assert!(linux::mimeapps_remove(
            "[Default Applications]\napplication/x-varsto-placeholder=other.desktop\n"
        )
        .is_none());
        assert_eq!(
            linux::mimeapps_add("").unwrap(),
            "[Default Applications]\napplication/x-varsto-placeholder=varsto-placeholder.desktop\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_install_and_uninstall_in_a_temp_dir() {
        let t = tempfile::tempdir().unwrap();
        let (data, config) = (t.path().join("data"), t.path().join("config"));
        std::fs::create_dir_all(data.join("nautilus/scripts/Varsto")).unwrap();
        std::fs::write(data.join("nautilus/scripts/Varsto/mine"), "x").unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("mimeapps.list"),
            "[Default Applications]\nimage/png=eog.desktop\n",
        )
        .unwrap();
        linux::install(&data, &config, Path::new("/bin/varsto"), Path::new("/h")).unwrap();
        assert!(data.join("kio/servicemenus/varsto.desktop").exists());
        assert!(data.join("nautilus/scripts/Varsto/Free up space").exists());
        linux::uninstall(&data, &config).unwrap();
        assert!(!data.join("kio/servicemenus/varsto.desktop").exists());
        assert!(!data.join("nautilus/scripts/Varsto/Download").exists());
        assert!(data.join("nautilus/scripts/Varsto/mine").exists());
        assert_eq!(
            std::fs::read_to_string(config.join("mimeapps.list")).unwrap(),
            "[Default Applications]\nimage/png=eog.desktop\n"
        );
    }

    #[test]
    fn windows_registry_entries() {
        let e = windows::entries(
            Path::new(r"C:\Users\u\Varsto\varsto.exe"),
            Path::new(r"C:\Users\u\AppData\Roaming\Varsto"),
        );
        let get = |k: &str, n: &str| {
            e.iter()
                .find(|v| v.key == k && v.name == n)
                .map(|v| v.data.as_str())
                .unwrap()
        };
        assert_eq!(
            get(r"Software\Classes\*\shell\Varsto.Fetch", "MUIVerb"),
            "Download with Varsto"
        );
        assert_eq!(
            get(r"Software\Classes\*\shell\Varsto.Free\command", ""),
            r#""C:\Users\u\Varsto\varsto.exe" --home "C:\Users\u\AppData\Roaming\Varsto" paths --notify free -- "%1""#
        );
        assert_eq!(
            get(r"Software\Classes\.varsto-placeholder", ""),
            "Varsto.Placeholder"
        );
        assert!(get(
            r"Software\Classes\Varsto.Placeholder\shell\open\command",
            ""
        )
        .ends_with(r#"open-placeholder "%1""#));
        // Everything written lies under a key that uninstall deletes.
        for v in &e {
            assert!(
                windows::KEYS.iter().any(|k| v.key.starts_with(k)),
                "{}",
                v.key
            );
        }
    }
}
