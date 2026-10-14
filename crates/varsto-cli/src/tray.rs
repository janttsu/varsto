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

/// Menu and status texts in the interface language the user picked in the
/// web UI (`<home>/ui-language`): English, Finnish, Swedish. `{}` marks
/// where [`fill`] puts a value.
const TR: &[(&str, &str, &str)] = &[
    (
        "Not set up yet: open Varsto",
        "Ei vielä otettu käyttöön: avaa Varsto",
        "Inte konfigurerat ännu: öppna Varsto",
    ),
    (
        "Locked: open Varsto to unlock",
        "Lukittu: avaa Varsto ja avaa lukitus",
        "Låst: öppna Varsto för att låsa upp",
    ),
    ("{} s ago", "{} s sitten", "för {} s sedan"),
    ("{} min ago", "{} min sitten", "för {} min sedan"),
    ("{} h ago", "{} h sitten", "för {} h sedan"),
    ("Paused", "Keskeytetty", "Pausad"),
    ("Up to date", "Ajan tasalla", "Uppdaterad"),
    ("Problem: {}", "Ongelma: {}", "Problem: {}"),
    (
        "{} · last sync {}",
        "{} · viimeisin synkronointi {}",
        "{} · senaste synkronisering {}",
    ),
    (
        "{} · no sync yet",
        "{} · ei vielä synkronoitu",
        "{} · ingen synkronisering ännu",
    ),
    (
        "Service starting…",
        "Palvelu käynnistyy…",
        "Tjänsten startar…",
    ),
    ("Starting…", "Käynnistyy…", "Startar…"),
    (
        "Updating to {}…",
        "Päivitetään versioon {}…",
        "Uppdaterar till {}…",
    ),
    (
        "Update failed: {}",
        "Päivitys epäonnistui: {}",
        "Uppdateringen misslyckades: {}",
    ),
    (
        "Download {} from {}",
        "Lataa {} osoitteesta {}",
        "Ladda ned {} från {}",
    ),
    ("Open Varsto", "Avaa Varsto", "Öppna Varsto"),
    (
        "Pause syncing",
        "Keskeytä synkronointi",
        "Pausa synkroniseringen",
    ),
    (
        "Install update",
        "Asenna päivitys",
        "Installera uppdatering",
    ),
    (
        "Install Varsto {}",
        "Asenna Varsto {}",
        "Installera Varsto {}",
    ),
    ("Quit Varsto", "Lopeta Varsto", "Avsluta Varsto"),
];

/// `en` in `lang` ("en", "fi" or "sv"); English when there is no entry.
fn tr(lang: &str, en: &'static str) -> &'static str {
    TR.iter()
        .find(|t| t.0 == en)
        .map(|t| match lang {
            "fi" => t.1,
            "sv" => t.2,
            _ => t.0,
        })
        .unwrap_or(en)
}

/// Put `args` in place of the `{}` marks of `text`, in order.
fn fill(text: &str, args: &[&str]) -> String {
    args.iter()
        .fold(text.to_string(), |s, a| s.replacen("{}", a, 1))
}

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
            if let Ok(url) = service::boot_url(&f) {
                crate::desktop::open_in_browser(&url);
            }
        }
    }

    /// The interface language, read again each time so that a change in the
    /// web UI reaches the menu at its next refresh.
    pub fn lang(&self) -> String {
        crate::desktop::ui_language(&self.home)
    }

    pub fn status_line(&self) -> String {
        let lang = self.lang();
        let lang = lang.as_str();
        match self.call("GET", "/api/state", "") {
            Ok(st) => {
                if !st["has_vault"].as_bool().unwrap_or(false) {
                    return tr(lang, "Not set up yet: open Varsto").into();
                }
                if !st["unlocked"].as_bool().unwrap_or(false) {
                    return tr(lang, "Locked: open Varsto to unlock").into();
                }
                let sv = &st["service"];
                let last = sv["last_sync_utc"].as_i64().map(|t| {
                    let ago = (varsto_core::util::now_utc() - t).max(0);
                    if ago < 60 {
                        fill(tr(lang, "{} s ago"), &[&ago.to_string()])
                    } else if ago < 3600 {
                        fill(tr(lang, "{} min ago"), &[&(ago / 60).to_string()])
                    } else {
                        fill(tr(lang, "{} h ago"), &[&(ago / 3600).to_string()])
                    }
                });
                let state = if sv["paused"].as_bool().unwrap_or(false) {
                    tr(lang, "Paused")
                } else {
                    tr(lang, "Up to date")
                };
                match (last, sv["last_error"].as_str()) {
                    (_, Some(e)) if !e.is_empty() => fill(tr(lang, "Problem: {}"), &[e]),
                    (Some(l), _) => fill(tr(lang, "{} · last sync {}"), &[state, &l]),
                    (None, _) => fill(tr(lang, "{} · no sync yet"), &[state]),
                }
            }
            Err(_) => tr(lang, "Service starting…").into(),
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
    let lang = s.lang();
    if n.available {
        match s.call("POST", "/api/update", "{}") {
            Ok(_) => fill(tr(&lang, "Updating to {}…"), &[&n.latest]),
            Err(e) => fill(tr(&lang, "Update failed: {}"), &[&e.to_string()]),
        }
    } else {
        crate::desktop::open_in_browser(&n.page);
        fill(tr(&lang, "Download {} from {}"), &[&n.latest, &n.page])
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
        lang: String,
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
            self.lang = s.lang();
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
            let lang = self.lang.as_str();
            let mut items: Vec<MenuItem<Self>> = vec![
                StandardItem {
                    label: self.status.clone(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
                MenuItem::Separator,
                StandardItem {
                    label: tr(lang, "Open Varsto").into(),
                    activate: Box::new(|t: &mut Self| t.sup.lock().unwrap().open_ui()),
                    ..Default::default()
                }
                .into(),
                CheckmarkItem {
                    label: tr(lang, "Pause syncing").into(),
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
                        label: fill(tr(lang, "Install Varsto {}"), &[&n.latest]),
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
                    label: tr(lang, "Quit Varsto").into(),
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

    pub fn run(sup: Shared, home: &Path) -> Result<()> {
        let lang = crate::desktop::ui_language(home);
        let mut tray = VarstoTray {
            sup: sup.clone(),
            status: tr(&lang, "Starting…").into(),
            lang,
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

    pub fn run(sup: Shared, home: &Path) -> Result<()> {
        let mut lang = crate::desktop::ui_language(home);
        let l = lang.as_str();
        let status = MenuItem::with_id("status", tr(l, "Starting…"), false, None);
        let open = MenuItem::with_id("open", tr(l, "Open Varsto"), true, None);
        let pause = CheckMenuItem::with_id("pause", tr(l, "Pause syncing"), true, false, None);
        // Added to the menu only when the automatic check finds a newer version.
        let update = MenuItem::with_id("update", tr(l, "Install update"), true, None);
        let note = MenuItem::with_id("note", "", false, None);
        let quit = MenuItem::with_id("quit", tr(l, "Quit Varsto"), true, None);
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
                // A language picked in the web UI applies without a restart.
                let now = s.lang();
                if now != lang {
                    lang = now;
                    open.set_text(tr(&lang, "Open Varsto"));
                    pause.set_text(tr(&lang, "Pause syncing"));
                    quit.set_text(tr(&lang, "Quit Varsto"));
                    if let Some(n) = &newer {
                        update.set_text(fill(tr(&lang, "Install Varsto {}"), &[&n.latest]));
                    }
                }
                status.set_text(s.status_line());
                if let Ok(v) = s.call("GET", "/api/service", "") {
                    pause.set_checked(v["paused"].as_bool().unwrap_or(false));
                }
                if update_checked.is_none_or(|t| t.elapsed() >= UPDATE_EVERY) {
                    update_checked = Some(Instant::now());
                    newer = check_newer(&mut s);
                    match (&newer, update_shown) {
                        (Some(n), _) => {
                            update.set_text(fill(tr(&lang, "Install Varsto {}"), &[&n.latest]));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translations_keep_placeholders() {
        for (en, fi, sv) in TR {
            let n = en.matches("{}").count();
            assert_eq!(fi.matches("{}").count(), n, "{en}");
            assert_eq!(sv.matches("{}").count(), n, "{en}");
        }
        assert_eq!(tr("fi", "Quit Varsto"), "Lopeta Varsto");
        assert_eq!(tr("sv", "Open Varsto"), "Öppna Varsto");
        assert_eq!(tr("en", "Paused"), "Paused");
        assert_eq!(tr("fi", "not in the table"), "not in the table");
        assert_eq!(
            fill(tr("en", "{} · last sync {}"), &["Up to date", "5 s ago"]),
            "Up to date · last sync 5 s ago"
        );
        assert_eq!(
            fill(
                tr("fi", "{} · last sync {}"),
                &["Ajan tasalla", "5 s sitten"]
            ),
            "Ajan tasalla · viimeisin synkronointi 5 s sitten"
        );
    }
}
