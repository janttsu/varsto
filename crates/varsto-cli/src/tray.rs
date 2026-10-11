// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto tray`: the desktop app shell for Linux and Windows. It starts and
//! supervises the background service as a child process, shows a status icon
//! in the system tray with a menu (open, sync now, pause, update, quit), and
//! restarts the service after a self-update (exit code 75). On macOS the same
//! role is played by the native menu-bar app (see `apps/macos`).

use crate::service::{self, ServiceFile};
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Supervises the service child process.
pub struct Supervisor {
    home: PathBuf,
    interval: u64,
    child: Option<Child>,
    started: Option<Instant>,
}

impl Supervisor {
    pub fn new(home: PathBuf, interval: u64) -> Self {
        Supervisor {
            home,
            interval,
            child: None,
            started: None,
        }
    }

    /// Start the service unless one is already answering.
    pub fn ensure_running(&mut self) -> Result<()> {
        if let Some(c) = self.child.as_mut() {
            match c.try_wait()? {
                None => return Ok(()),
                Some(status) => {
                    eprintln!("service exited with {status}; restarting");
                    self.child = None;
                    if let Some(t) = self.started {
                        if t.elapsed() < Duration::from_secs(5) {
                            std::thread::sleep(Duration::from_secs(3));
                        }
                    }
                }
            }
        } else if service::status(&self.home).is_some() {
            return Ok(()); // started by something else (launch agent, CLI)
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let log = opts.open(self.home.join("service.log")).ok();
        let exe = std::env::current_exe()?;
        let mut cmd = Command::new(exe);
        cmd.arg("--home")
            .arg(&self.home)
            .args([
                "service",
                "run",
                "--port",
                "0",
                "--interval",
                &self.interval.to_string(),
            ])
            .stdin(Stdio::null());
        match log {
            Some(f) => {
                cmd.stdout(Stdio::from(f.try_clone()?))
                    .stderr(Stdio::from(f));
            }
            None => {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
            }
        }
        std::fs::create_dir_all(&self.home)?;
        self.child = Some(cmd.spawn()?);
        self.started = Some(Instant::now());
        Ok(())
    }

    pub fn file(&self) -> Option<ServiceFile> {
        service::read_service_file(&self.home)
    }

    pub fn call(&self, method: &str, path: &str, body: &str) -> Result<serde_json::Value> {
        let f = self.file().ok_or_else(|| anyhow!("service not running"))?;
        let url = format!("http://127.0.0.1:{}{}", f.port, path);
        let text = if method == "GET" {
            service::http_get(&url, &f.token)?
        } else {
            service::http_post(&url, &f.token, body)?
        };
        Ok(serde_json::from_str(&text)?)
    }

    pub fn open_ui(&self) {
        if let Some(f) = self.file() {
            crate::desktop::open_in_browser(&format!(
                "http://127.0.0.1:{}/?token={}",
                f.port, f.token
            ));
        }
    }

    pub fn status_line(&self) -> String {
        match self.call("GET", "/api/state", "") {
            Ok(st) => {
                if !st["has_vault"].as_bool().unwrap_or(false) {
                    return "Not set up yet: open Varsto".into();
                }
                if !st["unlocked"].as_bool().unwrap_or(false) {
                    return "Locked: open Varsto to unlock".into();
                }
                let sv = &st["service"];
                let last = sv["last_sync_utc"].as_i64().map(|t| {
                    let ago = (varsto_core::util::now_utc() - t).max(0);
                    if ago < 60 {
                        format!("{ago} s ago")
                    } else if ago < 3600 {
                        format!("{} min ago", ago / 60)
                    } else {
                        format!("{} h ago", ago / 3600)
                    }
                });
                let state = if sv["paused"].as_bool().unwrap_or(false) {
                    "Paused"
                } else {
                    "Up to date"
                };
                match (last, sv["last_error"].as_str()) {
                    (_, Some(e)) if !e.is_empty() => format!("Problem: {e}"),
                    (Some(l), _) => format!("{state} · last sync {l}"),
                    (None, _) => format!("{state} · no sync yet"),
                }
            }
            Err(_) => "Service starting…".into(),
        }
    }

    pub fn stop(&mut self) {
        let _ = self.call("POST", "/api/quit", "{}");
        if let Some(c) = self.child.as_mut() {
            for _ in 0..30 {
                if c.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = c.kill();
        }
    }
}

pub type Shared = Arc<Mutex<Supervisor>>;

pub fn run(home: PathBuf, interval: u64, open_at_start: bool) -> Result<()> {
    let sup: Shared = Arc::new(Mutex::new(Supervisor::new(home.clone(), interval)));
    sup.lock().unwrap().ensure_running()?;
    if open_at_start {
        std::thread::sleep(Duration::from_millis(800));
        sup.lock().unwrap().open_ui();
    }
    platform::run(sup, &home)
}

/// A newer version found by the automatic check (no menu item asks for it).
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[derive(Clone)]
struct Newer {
    latest: String,
    /// The service can install it itself.
    available: bool,
    page: String,
}

/// How often the tray asks the service whether a newer version is out.
#[cfg(any(target_os = "linux", target_os = "windows"))]
const UPDATE_EVERY: Duration = Duration::from_secs(6 * 3600);

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn check_newer(s: &mut Supervisor) -> Option<Newer> {
    let c = s.call("GET", "/api/update/check", "").ok()?;
    c["newer"].as_bool().filter(|n| *n)?;
    Some(Newer {
        latest: c["latest"].as_str().unwrap_or("").to_string(),
        available: c["available"].as_bool().unwrap_or(false),
        page: c["download_page"].as_str().unwrap_or("").to_string(),
    })
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn install_newer(s: &mut Supervisor, n: &Newer) -> String {
    if n.available {
        match s.call("POST", "/api/update", "{}") {
            Ok(_) => format!("Updating to {}…", n.latest),
            Err(e) => format!("Update failed: {e}"),
        }
    } else {
        crate::desktop::open_in_browser(&n.page);
        format!("Download {} from {}", n.latest, n.page)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use ksni::blocking::TrayMethods;
    use ksni::menu::{CheckmarkItem, MenuItem, StandardItem};
    use ksni::{Icon, ToolTip, Tray};

    struct VarstoTray {
        sup: Shared,
        status: String,
        paused: bool,
        update_note: String,
        newer: Option<Newer>,
        update_checked: Option<Instant>,
        quit: bool,
    }

    impl VarstoTray {
        fn refresh(&mut self) {
            let mut s = self.sup.lock().unwrap();
            let _ = s.ensure_running();
            self.status = s.status_line();
            self.paused = s
                .call("GET", "/api/service", "")
                .map(|v| v["paused"].as_bool().unwrap_or(false))
                .unwrap_or(false);
            if self
                .update_checked
                .is_none_or(|t| t.elapsed() >= UPDATE_EVERY)
            {
                self.update_checked = Some(Instant::now());
                self.newer = check_newer(&mut s);
            }
        }
    }

    impl Tray for VarstoTray {
        fn id(&self) -> String {
            "varsto".into()
        }
        fn title(&self) -> String {
            "Varsto".into()
        }
        fn icon_name(&self) -> String {
            "folder-sync".into()
        }
        fn icon_pixmap(&self) -> Vec<Icon> {
            [22u32, 32, 48]
                .iter()
                .map(|&s| Icon {
                    width: s as i32,
                    height: s as i32,
                    data: crate::icon::argb(s),
                })
                .collect()
        }
        fn tool_tip(&self) -> ToolTip {
            ToolTip {
                title: "Varsto".into(),
                description: self.status.clone(),
                ..Default::default()
            }
        }
        fn activate(&mut self, _x: i32, _y: i32) {
            self.sup.lock().unwrap().open_ui();
        }
        fn menu(&self) -> Vec<MenuItem<Self>> {
            let mut items: Vec<MenuItem<Self>> = vec![
                StandardItem {
                    label: self.status.clone(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
                MenuItem::Separator,
                StandardItem {
                    label: "Open Varsto".into(),
                    activate: Box::new(|t: &mut Self| t.sup.lock().unwrap().open_ui()),
                    ..Default::default()
                }
                .into(),
                CheckmarkItem {
                    label: "Pause syncing".into(),
                    checked: self.paused,
                    activate: Box::new(|t: &mut Self| {
                        let body = format!("{{\"paused\": {}}}", !t.paused);
                        let _ = t
                            .sup
                            .lock()
                            .unwrap()
                            .call("POST", "/api/service/pause", &body);
                        t.refresh();
                    }),
                    ..Default::default()
                }
                .into(),
            ];
            if let Some(n) = &self.newer {
                let n = n.clone();
                items.push(
                    StandardItem {
                        label: format!("Install Varsto {}", n.latest),
                        activate: Box::new(move |t: &mut Self| {
                            let note = install_newer(&mut t.sup.lock().unwrap(), &n);
                            t.update_note = note;
                        }),
                        ..Default::default()
                    }
                    .into(),
                );
            }
            if !self.update_note.is_empty() {
                items.push(
                    StandardItem {
                        label: self.update_note.clone(),
                        enabled: false,
                        ..Default::default()
                    }
                    .into(),
                );
            }
            items.push(MenuItem::Separator);
            items.push(
                StandardItem {
                    label: "Quit Varsto".into(),
                    activate: Box::new(|t: &mut Self| {
                        t.quit = true;
                    }),
                    ..Default::default()
                }
                .into(),
            );
            items
        }
    }

    pub fn run(sup: Shared, _home: &Path) -> Result<()> {
        let mut tray = VarstoTray {
            sup: sup.clone(),
            status: "Starting…".into(),
            paused: false,
            update_note: String::new(),
            newer: None,
            update_checked: None,
            quit: false,
        };
        tray.refresh();
        let handle = tray.spawn().map_err(|e| {
            anyhow!("cannot register the tray icon (is a StatusNotifier host running?): {e}")
        })?;
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let mut quit = false;
            handle.update(|t| {
                t.refresh();
                quit = t.quit;
            });
            if quit || handle.is_closed() {
                break;
            }
        }
        sup.lock().unwrap().stop();
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::sync::mpsc;
    use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };

    pub fn run(sup: Shared, _home: &Path) -> Result<()> {
        let status = MenuItem::with_id("status", "Starting…", false, None);
        let open = MenuItem::with_id("open", "Open Varsto", true, None);
        let pause = CheckMenuItem::with_id("pause", "Pause syncing", true, false, None);
        // Added to the menu only when the automatic check finds a newer version.
        let update = MenuItem::with_id("update", "Install update", true, None);
        let note = MenuItem::with_id("note", "", false, None);
        let quit = MenuItem::with_id("quit", "Quit Varsto", true, None);
        let menu = Menu::new();
        menu.append_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &open,
            &pause,
            &note,
            &PredefinedMenuItem::separator(),
            &quit,
        ])?;
        let icon = Icon::from_rgba(crate::icon::rgba(32), 32, 32)?;
        let _tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
            .with_tooltip("Varsto")
            .with_icon(icon)
            .with_menu_on_left_click(true)
            .build()?;
        let (tx, rx) = mpsc::channel::<String>();
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
            let _ = tx.send(e.id().0.clone());
        }));
        let mut last_refresh = Instant::now() - Duration::from_secs(60);
        let mut update_checked: Option<Instant> = None;
        let mut newer: Option<Newer> = None;
        let mut update_shown = false;
        loop {
            unsafe {
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            while let Ok(id) = rx.try_recv() {
                let mut s = sup.lock().unwrap();
                match id.as_str() {
                    "open" => s.open_ui(),
                    "pause" => {
                        let _ = s.call(
                            "POST",
                            "/api/service/pause",
                            &format!("{{\"paused\": {}}}", pause.is_checked()),
                        );
                    }
                    "update" => {
                        if let Some(n) = &newer {
                            note.set_text(install_newer(&mut s, n));
                        }
                    }
                    "quit" => {
                        s.stop();
                        return Ok(());
                    }
                    _ => {}
                }
                last_refresh = Instant::now() - Duration::from_secs(60);
            }
            if last_refresh.elapsed() >= Duration::from_secs(5) {
                let mut s = sup.lock().unwrap();
                let _ = s.ensure_running();
                status.set_text(s.status_line());
                if let Ok(v) = s.call("GET", "/api/service", "") {
                    pause.set_checked(v["paused"].as_bool().unwrap_or(false));
                }
                if update_checked.is_none_or(|t| t.elapsed() >= UPDATE_EVERY) {
                    update_checked = Some(Instant::now());
                    newer = check_newer(&mut s);
                    match (&newer, update_shown) {
                        (Some(n), _) => {
                            update.set_text(format!("Install Varsto {}", n.latest));
                            if !update_shown {
                                let _ = menu.insert(&update, 3);
                                update_shown = true;
                            }
                        }
                        (None, true) => {
                            let _ = menu.remove(&update);
                            update_shown = false;
                        }
                        (None, false) => {}
                    }
                }
                last_refresh = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    use super::*;
    pub fn run(sup: Shared, _home: &Path) -> Result<()> {
        // macOS uses the native menu-bar app; keep the service alive here.
        loop {
            std::thread::sleep(Duration::from_secs(5));
            sup.lock().unwrap().ensure_running()?;
        }
    }
}
