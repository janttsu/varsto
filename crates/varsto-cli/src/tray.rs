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
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.home.join("service.log"))
            .ok();
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
                StandardItem {
                    label: "Sync now".into(),
                    activate: Box::new(|t: &mut Self| {
                        let _ = t.sup.lock().unwrap().call("POST", "/api/sync", "{}");
                        t.refresh();
                    }),
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
                StandardItem {
                    label: "Check for updates".into(),
                    activate: Box::new(|t: &mut Self| {
                        let r = t.sup.lock().unwrap().call("GET", "/api/update/check", "");
                        t.update_note = match r {
                            Ok(c) if c["available"].as_bool().unwrap_or(false) => {
                                let _ = t.sup.lock().unwrap().call("POST", "/api/update", "{}");
                                format!("Updating to {}…", c["latest"].as_str().unwrap_or(""))
                            }
                            Ok(c) => {
                                format!("Up to date ({})", c["current"].as_str().unwrap_or(""))
                            }
                            Err(e) => format!("Update check failed: {e}"),
                        };
                    }),
                    ..Default::default()
                }
                .into(),
            ];
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
        let sync = MenuItem::with_id("sync", "Sync now", true, None);
        let pause = CheckMenuItem::with_id("pause", "Pause syncing", true, false, None);
        let update = MenuItem::with_id("update", "Check for updates", true, None);
        let note = MenuItem::with_id("note", "", false, None);
        let quit = MenuItem::with_id("quit", "Quit Varsto", true, None);
        let menu = Menu::new();
        menu.append_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &open,
            &sync,
            &pause,
            &update,
            &note,
            &PredefinedMenuItem::separator(),
            &quit,
        ])?;
        let icon = Icon::from_rgba(crate::icon::rgba(32), 32, 32)?;
        let _tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Varsto")
            .with_icon(icon)
            .with_menu_on_left_click(true)
            .build()?;
        let (tx, rx) = mpsc::channel::<String>();
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
            let _ = tx.send(e.id().0.clone());
        }));
        let mut last_refresh = Instant::now() - Duration::from_secs(60);
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
                    "sync" => {
                        let _ = s.call("POST", "/api/sync", "{}");
                    }
                    "pause" => {
                        let _ = s.call(
                            "POST",
                            "/api/service/pause",
                            &format!("{{\"paused\": {}}}", pause.is_checked()),
                        );
                    }
                    "update" => {
                        let text = match s.call("GET", "/api/update/check", "") {
                            Ok(c) if c["available"].as_bool().unwrap_or(false) => {
                                let _ = s.call("POST", "/api/update", "{}");
                                format!("Updating to {}…", c["latest"].as_str().unwrap_or(""))
                            }
                            Ok(c) => {
                                format!("Up to date ({})", c["current"].as_str().unwrap_or(""))
                            }
                            Err(e) => format!("Update check failed: {e}"),
                        };
                        note.set_text(text);
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
