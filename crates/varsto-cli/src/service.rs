// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Background service: watches attached folders, syncs on change and on a
//! timer, serves the local API and desktop page, and writes `service.json`
//! so that the menu-bar app and the CLI can find it.
//!
//! Unlocking: the service starts locked unless the passphrase comes from the
//! `VARSTO_PASSPHRASE` environment variable or, on macOS, from the login
//! keychain (`security find-generic-password -s varsto -a <home>`), where the
//! menu-bar app can store it. The desktop page can unlock it as well.

use crate::desktop::{self, Shared, State};
use anyhow::{anyhow, Context, Result};
use notify::Watcher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use varsto_core::engine::{PullReport, PushReport};
use varsto_core::Engine;

static QUIT: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceFile {
    pub pid: u32,
    pub port: u16,
    pub token: String,
    pub started_utc: i64,
    pub version: String,
}

/// Runtime state of the service, shared with the API.
#[derive(Default)]
pub struct ServiceState {
    pub running: bool,
    pub paused: bool,
    pub interval_secs: u64,
    pub watching: Vec<PathBuf>,
    pub last_sync_utc: Option<i64>,
    pub last_result: String,
    pub last_error: Option<String>,
    pub next_sync_utc: Option<i64>,
    pub sync_requested: bool,
    pub folders_changed: bool,
    pub syncs: u64,
    /// Set after a successful self-update: the loop exits so the supervisor restarts us.
    pub restart_requested: bool,
    /// Latest durability policy reports (F-032) and the worst state among them.
    pub policies: Vec<varsto_core::policy::PolicyReport>,
    pub policy_worst: Option<varsto_core::policy::PolicyState>,
    /// Peer-to-peer: listening address and the peers known right now.
    pub p2p_listen: Option<std::net::SocketAddr>,
    pub p2p_peers: Vec<varsto_core::p2p::PeerAddr>,
    pub p2p_lan_peers: usize,
    pub p2p_chunks: u64,
}

impl ServiceState {
    pub fn summary(&self) -> Value {
        json!({
            "running": self.running,
            "paused": self.paused,
            "interval_secs": self.interval_secs,
            "watching": self.watching.len(),
            "last_sync_utc": self.last_sync_utc,
            "last_result": self.last_result,
            "last_error": self.last_error,
            "next_sync_utc": self.next_sync_utc,
            "syncs": self.syncs,
            "policy_worst": self.policy_worst,
            "policies": self.policies,
            "p2p_listen": self.p2p_listen,
            "p2p_peers": self.p2p_peers,
            "p2p_lan_peers": self.p2p_lan_peers,
            "p2p_chunks": self.p2p_chunks,
        })
    }
    /// Store policy reports; raise a desktop notification when a folder's
    /// state got worse (ok -> at risk -> violated) or a violation persists
    /// after an hour of silence.
    pub fn record_policies(&mut self, reports: Vec<varsto_core::policy::PolicyReport>) {
        use varsto_core::policy::PolicyState;
        let mut alerts = Vec::new();
        for r in &reports {
            let before = self
                .policies
                .iter()
                .find(|p| p.folder == r.folder)
                .map(|p| p.state);
            let worse = match (before, r.state) {
                (None, PolicyState::Ok) | (None, PolicyState::Unknown) => false,
                (None, _) => true,
                (Some(b), n) => n > b && n != PolicyState::Unknown,
            };
            if worse {
                let detail = if r.reasons.is_empty() {
                    r.warnings.join("; ")
                } else {
                    r.reasons.join("; ")
                };
                alerts.push(format!(
                    "Folder {}: policy {} ({}). {}",
                    r.folder,
                    match r.state {
                        PolicyState::Violated => "violated",
                        PolicyState::AtRisk => "at risk",
                        _ => "unknown",
                    },
                    r.policy.describe(),
                    detail
                ));
            }
        }
        self.policy_worst = reports.iter().map(|r| r.state).max();
        self.policies = reports;
        for a in alerts {
            eprintln!("service: {a}");
            notify("Varsto durability policy", &a);
        }
    }
    pub fn request_sync(&mut self) {
        self.sync_requested = true;
    }
    pub fn record_sync(&mut self, reports: &[(PullReport, PushReport)]) {
        self.last_sync_utc = Some(varsto_core::util::now_utc());
        self.syncs += 1;
        let mut updated = 0;
        let mut deleted = 0;
        let mut conflicts = 0;
        let mut uploaded = 0;
        let mut unavailable = 0;
        let mut forked = false;
        for (pl, ps) in reports {
            self.p2p_chunks += pl.chunks_from_peers;
            updated += pl.files_updated;
            deleted += pl.files_deleted;
            conflicts += pl.conflicts;
            uploaded += ps.chunks_uploaded;
            unavailable += pl.files_unavailable.len();
            forked |= !pl.forked_devices.is_empty();
        }
        self.last_result = format!("{} folders: {updated} updated, {deleted} deleted, {conflicts} conflicts, {uploaded} chunks uploaded{}{}", reports.len(), if unavailable > 0 { format!(", {unavailable} unavailable") } else { String::new() }, if forked { ", FORKED device" } else { "" });
        self.last_error = None;
    }
}

/// Peer-to-peer runtime of the service: listener thread, beacon thread,
/// a shared snapshot of what we serve, and the peer table.
struct P2p {
    snapshot: Arc<Mutex<Option<Arc<varsto_core::p2p::Snapshot>>>>,
    lan_peers: Arc<Mutex<Vec<varsto_core::p2p::PeerAddr>>>,
    listen: std::net::SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
    last_publish: Mutex<Option<Instant>>,
}

impl P2p {
    fn start(state: &Shared) -> Option<P2p> {
        let (cfg, tag, device) = {
            let st = state.lock().unwrap();
            let e = st.engine.as_ref()?;
            let cfg = e.p2p_config();
            if !cfg.enabled {
                return None;
            }
            (cfg, e.wire_vault_tag(), e.device_id().clone())
        };
        let server = match varsto_core::p2p::Server::bind(([0, 0, 0, 0], cfg.port).into()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("service: p2p listener failed: {e:#}");
                return None;
            }
        };
        let listen = server.addr;
        let snapshot: Arc<Mutex<Option<Arc<varsto_core::p2p::Snapshot>>>> =
            Arc::new(Mutex::new(None));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (snap2, stop2) = (snapshot.clone(), stop.clone());
        let _ = std::thread::Builder::new()
            .name("p2p-serve".into())
            .spawn(move || server.run(snap2, stop2));
        let lan_peers: Arc<Mutex<Vec<varsto_core::p2p::PeerAddr>>> =
            Arc::new(Mutex::new(Vec::new()));
        let (lan2, stop3) = (lan_peers.clone(), stop.clone());
        match varsto_core::p2p::Beacon::new(tag, device, listen.port()) {
            Ok(beacon) => {
                let _ = std::thread::Builder::new()
                    .name("p2p-beacon".into())
                    .spawn(move || {
                        let mut heard: std::collections::BTreeMap<
                            std::net::SocketAddr,
                            (varsto_core::p2p::PeerAddr, Instant),
                        > = Default::default();
                        while !stop3.load(std::sync::atomic::Ordering::Relaxed) {
                            beacon.announce();
                            for p in beacon.listen(Duration::from_secs(5)) {
                                heard.insert(p.addr, (p, Instant::now()));
                            }
                            heard.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(60));
                            *lan2.lock().unwrap() =
                                heard.values().map(|(p, _)| p.clone()).collect();
                        }
                    });
            }
            Err(e) => eprintln!("service: LAN beacon unavailable: {e:#}"),
        }
        state.lock().unwrap().service.p2p_listen = Some(listen);
        println!(
            "Varsto p2p: listening on {listen} (encrypted blocks only; peers need the vault key)"
        );
        Some(P2p {
            snapshot,
            lan_peers,
            listen,
            stop,
            last_publish: Mutex::new(None),
        })
    }

    /// Merge LAN peers with rendezvous records and hand them to the engine.
    fn refresh_before_sync(&self, st: &mut State) {
        let Some(e) = st.engine.as_mut() else { return };
        let mut peers = self.lan_peers.lock().unwrap().clone();
        let lan = peers.len();
        if let Ok(records) = e.peer_records() {
            for r in records {
                if !peers.iter().any(|p| p.addr == r.addr) {
                    peers.push(r);
                }
            }
        }
        st.service.p2p_lan_peers = lan;
        st.service.p2p_peers = peers.clone();
        let p = varsto_core::p2p::Peers::new(e.peer_key(), e.device_id().clone(), peers);
        e.set_peers(Some(Arc::new(p)));
    }

    /// Refresh what we serve and re-publish our rendezvous record now and then.
    fn refresh_after_sync(&self, st: &mut State) {
        let Some(e) = st.engine.as_ref() else { return };
        match e.peer_snapshot() {
            Ok(s) => *self.snapshot.lock().unwrap() = Some(Arc::new(s)),
            Err(err) => eprintln!("service: p2p snapshot failed: {err:#}"),
        }
        let mut last = self.last_publish.lock().unwrap();
        if last.is_none_or(|t| t.elapsed() > Duration::from_secs(600)) {
            let cfg = e.p2p_config();
            if let Err(err) = e.publish_peer_record(self.listen.port(), cfg.public_addrs) {
                eprintln!("service: p2p record publish failed: {err:#}");
            }
            *last = Some(Instant::now());
        }
    }
}

impl Drop for P2p {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Best-effort desktop notification; silent where no notifier exists.
pub fn notify(title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .args(["--app-name=Varsto", title, body])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            body.replace('"', "'"),
            title.replace('"', "'")
        );
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (title, body);
    }
}

pub fn service_file(home: &Path) -> PathBuf {
    home.join("service.json")
}

pub fn read_service_file(home: &Path) -> Option<ServiceFile> {
    let s = fs::read(service_file(home)).ok()?;
    serde_json::from_slice(&s).ok()
}

fn write_service_file(home: &Path, f: &ServiceFile) -> Result<()> {
    fs::create_dir_all(home)?;
    let p = service_file(home);
    varsto_core::util::write_atomic(&p, &serde_json::to_vec_pretty(f)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn request_quit(_state: &Shared) {
    QUIT.store(true, Ordering::SeqCst);
}

/// Passphrase from the environment or the macOS login keychain.
pub fn passphrase_from_system(home: &Path) -> Option<String> {
    if let Ok(p) = std::env::var("VARSTO_PASSPHRASE") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                "varsto",
                "-a",
                &home.display().to_string(),
                "-w",
            ])
            .output()
            .ok()?;
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout)
                .trim_end_matches('\n')
                .to_string();
            if !p.is_empty() {
                return Some(p);
            }
        }
    }
    let _ = home;
    None
}

pub struct Options {
    pub home: PathBuf,
    pub port: u16,
    pub interval_secs: u64,
    pub open_browser: bool,
}

/// Run the service until quit. Blocks the calling thread.
pub fn run(opts: Options) -> Result<()> {
    let (server, bound) = desktop::bind(opts.port)?;
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    let port: u16 = bound.rsplit(':').next().unwrap().parse()?;
    let url = format!("http://{bound}/?token={token}");
    fs::create_dir_all(&opts.home)?;
    write_service_file(
        &opts.home,
        &ServiceFile {
            pid: std::process::id(),
            port,
            token: token.clone(),
            started_utc: varsto_core::util::now_utc(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
    )?;

    let mut engine = None;
    if opts.home.join("vault.json").exists() {
        if let Some(p) = passphrase_from_system(&opts.home) {
            match Engine::open(&opts.home, &p) {
                Ok(e) => engine = Some(e),
                Err(e) => eprintln!("service: unlock with the stored passphrase failed: {e:#}"),
            }
        }
    }
    let state: Shared = Arc::new(Mutex::new(State {
        home: opts.home.clone(),
        engine,
        token,
        bound: bound.clone(),
        service: ServiceState {
            running: true,
            interval_secs: opts.interval_secs.max(15),
            sync_requested: true,
            folders_changed: true,
            ..Default::default()
        },
    }));
    println!("Varsto service: {url}");
    println!(
        "Only this computer can reach it. Service file: {}",
        service_file(&opts.home).display()
    );
    if opts.open_browser {
        desktop::open_in_browser(&url);
    }
    let http_state = state.clone();
    let server = Arc::new(server);
    let http_server = server.clone();
    std::thread::Builder::new()
        .name("http".into())
        .spawn(move || desktop::serve_arc(http_server, http_state))?;

    // Peer-to-peer: serve our chunks, announce on the LAN, learn peers.
    let p2p = P2p::start(&state);

    // File watcher: sends a signal on any change under an attached folder.
    let (tx, rx) = mpsc::channel::<()>();
    let mut watcher = make_watcher(tx)?;
    let mut watched: Vec<PathBuf> = Vec::new();
    let mut last_change: Option<Instant> = None;
    let mut next_sync = Instant::now();
    let debounce = Duration::from_secs(2);

    while !QUIT.load(Ordering::SeqCst) {
        // Drain change notifications.
        while rx.try_recv().is_ok() {
            last_change = Some(Instant::now());
        }
        // Re-evaluate watched folders when the engine or its folders changed.
        {
            let mut st = state.lock().unwrap();
            if st.service.folders_changed {
                let paths: Vec<PathBuf> = st
                    .engine
                    .as_ref()
                    .map(|e| e.folders().into_iter().filter_map(|(_, m)| m).collect())
                    .unwrap_or_default();
                if paths != watched {
                    for p in &watched {
                        let _ = watcher.unwatch(p);
                    }
                    for p in &paths {
                        if let Err(e) = watcher.watch(p, notify::RecursiveMode::Recursive) {
                            eprintln!("service: cannot watch {}: {e}", p.display());
                        }
                    }
                    watched = paths;
                }
                st.service.watching = watched.clone();
                st.service.folders_changed = false;
            }
        }
        if state.lock().unwrap().service.restart_requested {
            eprintln!("service: restarting after update");
            std::thread::sleep(Duration::from_millis(300));
            break;
        }
        let due_change = last_change
            .map(|t| t.elapsed() >= debounce)
            .unwrap_or(false);
        let due_timer = Instant::now() >= next_sync;
        let (requested, paused, unlocked) = {
            let st = state.lock().unwrap();
            (
                st.service.sync_requested,
                st.service.paused,
                st.engine.is_some(),
            )
        };
        if unlocked && !paused && (due_change || due_timer || requested) {
            last_change = None;
            let mut st = state.lock().unwrap();
            st.service.sync_requested = false;
            let interval = st.service.interval_secs;
            if let Some(p) = &p2p {
                p.refresh_before_sync(&mut st);
            }
            let result = st.engine.as_mut().map(|e| e.sync(None));
            if let Some(p) = &p2p {
                p.refresh_after_sync(&mut st);
            }
            match result {
                Some(Ok(reports)) => {
                    st.service.record_sync(&reports);
                    let checked = st.engine.as_ref().map(|e| e.policy_check());
                    match checked {
                        Some(Ok(reps)) => st.service.record_policies(reps),
                        Some(Err(e)) => eprintln!("service: policy check failed: {e:#}"),
                        None => {}
                    }
                }
                Some(Err(e)) => {
                    st.service.last_error = Some(format!("{e:#}"));
                    eprintln!("service: sync failed: {e:#}");
                }
                None => {}
            }
            st.service.folders_changed = true; // folders may have arrived from other devices
            next_sync = Instant::now() + Duration::from_secs(interval);
            st.service.next_sync_utc = Some(varsto_core::util::now_utc() + interval as i64);
        } else if !unlocked {
            next_sync = Instant::now() + Duration::from_secs(5);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let restart = state.lock().unwrap().service.restart_requested;
    let _ = fs::remove_file(service_file(&opts.home));
    server.unblock();
    if restart {
        // Exit code 75 tells a supervisor (launchd, systemd, the tray app) to start us again.
        std::process::exit(75);
    }
    Ok(())
}

fn make_watcher(tx: mpsc::Sender<()>) -> Result<notify::RecommendedWatcher> {
    let watcher = notify::RecommendedWatcher::new(
        move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                // Ignore our own temporary files.
                if ev.paths.iter().all(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().starts_with(".varsto"))
                        .unwrap_or(false)
                }) {
                    return;
                }
                let _ = tx.send(());
            }
        },
        notify::Config::default().with_poll_interval(Duration::from_secs(30)),
    )
    .context("start file watcher")?;
    Ok(watcher)
}

/// Is the service recorded in `service.json` still alive?
pub fn status(home: &Path) -> Option<(ServiceFile, Value)> {
    let f = read_service_file(home)?;
    let url = format!("http://127.0.0.1:{}/api/service", f.port);
    let body = http_get(&url, &f.token).ok()?;
    Some((f, serde_json::from_str(&body).unwrap_or(json!({}))))
}

/// Minimal HTTP client for talking to the local service (no extra dependency).
pub fn http_get(url: &str, token: &str) -> Result<String> {
    http_call("GET", url, token, None)
}

pub fn http_post(url: &str, token: &str, body: &str) -> Result<String> {
    http_call("POST", url, token, Some(body))
}

fn http_call(method: &str, url: &str, token: &str, body: Option<&str>) -> Result<String> {
    use std::io::{Read, Write};
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("http only"))?;
    let (hostport, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let mut stream = std::net::TcpStream::connect(hostport)?;
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
    let body = body.unwrap_or("");
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: {hostport}\r\nX-Varsto-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, resp_body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("bad response"))?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(anyhow!("service answered {status}: {resp_body}"));
    }
    Ok(resp_body.to_string())
}

// ----- install as a login item ------------------------------------------------

pub fn install(home: &Path, interval_secs: u64) -> Result<String> {
    let exe = std::env::current_exe()?;
    #[cfg(target_os = "macos")]
    {
        let dir = PathBuf::from(std::env::var("HOME")?).join("Library/LaunchAgents");
        fs::create_dir_all(&dir)?;
        let plist = dir.join("in.soderlund.varsto.plist");
        let content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>in.soderlund.varsto</string>
  <key>ProgramArguments</key><array><string>{}</string><string>--home</string><string>{}</string><string>service</string><string>run</string><string>--interval</string><string>{}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{}</string>
  <key>StandardErrorPath</key><string>{}</string>
</dict></plist>
"#,
            exe.display(),
            home.display(),
            interval_secs,
            home.join("service.log").display(),
            home.join("service.log").display()
        );
        fs::write(&plist, content)?;
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist.display().to_string()])
            .output();
        let out = std::process::Command::new("launchctl")
            .args(["load", "-w", &plist.display().to_string()])
            .output()?;
        if !out.status.success() {
            return Err(anyhow!(
                "launchctl load failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        return Ok(format!("installed and started: {}", plist.display()));
    }
    #[cfg(target_os = "linux")]
    {
        // Desktop session: autostart the tray app, which runs the service.
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or(PathBuf::from(std::env::var("HOME")?).join(".config"));
        let dir = config.join("autostart");
        fs::create_dir_all(&dir)?;
        let entry = dir.join("varsto.desktop");
        fs::write(&entry, format!("[Desktop Entry]\nType=Application\nName=Varsto\nComment=Encrypted sync with your own storage\nExec={} --home {} tray --interval {}\nIcon=folder-sync\nTerminal=false\nX-GNOME-Autostart-enabled=true\n", exe.display(), home.display(), interval_secs))?;
        return Ok(format!("installed: {} (starts the tray app at login; for a headless machine create a systemd user unit running `varsto service run`)", entry.display()));
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA")?;
        let dir = PathBuf::from(appdata).join("Microsoft/Windows/Start Menu/Programs/Startup");
        fs::create_dir_all(&dir)?;
        let cmd = dir.join("Varsto.cmd");
        fs::write(
            &cmd,
            format!(
                "@echo off\r\nstart \"\" /B \"{}\" --home \"{}\" tray --interval {}\r\n",
                exe.display(),
                home.display(),
                interval_secs
            ),
        )?;
        return Ok(format!(
            "installed: {} (starts the tray app at login)",
            cmd.display()
        ));
    }
    #[allow(unreachable_code)]
    {
        let _ = (home, interval_secs, exe);
        Err(anyhow!("automatic installation is not implemented on this platform; run `varsto service run` from your login items"))
    }
}

pub fn uninstall() -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        let plist = PathBuf::from(std::env::var("HOME")?)
            .join("Library/LaunchAgents/in.soderlund.varsto.plist");
        let _ = std::process::Command::new("launchctl")
            .args(["unload", "-w", &plist.display().to_string()])
            .output();
        let _ = fs::remove_file(&plist);
        return Ok("removed the launch agent".into());
    }
    #[cfg(target_os = "linux")]
    {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or(PathBuf::from(std::env::var("HOME")?).join(".config"));
        let _ = fs::remove_file(config.join("autostart/varsto.desktop"));
        return Ok("removed the autostart entry".into());
    }
    #[cfg(target_os = "windows")]
    {
        let dir = PathBuf::from(std::env::var("APPDATA")?)
            .join("Microsoft/Windows/Start Menu/Programs/Startup");
        let _ = fs::remove_file(dir.join("Varsto.cmd"));
        return Ok("removed the startup entry".into());
    }
    #[allow(unreachable_code)]
    Err(anyhow!("not implemented on this platform"))
}
