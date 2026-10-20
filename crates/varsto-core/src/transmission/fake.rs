// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! An in-process transmission-daemon for tests: an HTTP server on
//! 127.0.0.1 answering the RPC methods a torrent job uses, with the
//! session-id handshake (409) and optional sign-in. Nothing is downloaded
//! from anywhere: [`FakeTransmission::provide`] gives it the content of a
//! torrent, and [`FakeTransmission::step`] "downloads" up to a number of
//! bytes of the wanted files of running torrents into their download
//! directory, as `<name>.part` until a file is complete (transmission's
//! `rename-partial-files`).

use super::{parse_magnet, parse_metainfo, Metainfo, RpcSettings};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

struct Torrent {
    id: i64,
    hash: String,
    name: String,
    meta: Option<Metainfo>,
    dir: PathBuf,
    wanted: Vec<bool>,
    done: Vec<u64>,
    running: bool,
    error: i64,
    error_string: String,
    limited: bool,
}

struct State {
    session: String,
    handshakes: u64,
    default_dir: PathBuf,
    metas: HashMap<String, Metainfo>,
    content: HashMap<String, Vec<Vec<u8>>>,
    torrents: Vec<Torrent>,
    next_id: i64,
    calls: Vec<String>,
}

pub struct FakeTransmission {
    url: String,
    login: Option<(String, String)>,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeTransmission {
    /// A daemon whose default download directory is `dir/downloads`.
    pub fn start(dir: &Path) -> FakeTransmission {
        Self::start_inner(dir, None)
    }

    pub fn start_with_login(dir: &Path, user: &str, password: &str) -> FakeTransmission {
        Self::start_inner(dir, Some((user.to_string(), password.to_string())))
    }

    fn start_inner(dir: &Path, login: Option<(String, String)>) -> FakeTransmission {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind the fake transmission");
        let port = server.server_addr().to_ip().expect("ip address").port();
        let state = Arc::new(Mutex::new(State {
            session: "session-1".into(),
            handshakes: 0,
            default_dir: dir.join("downloads"),
            metas: HashMap::new(),
            content: HashMap::new(),
            torrents: Vec::new(),
            next_id: 1,
            calls: Vec::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let state = state.clone();
            let stop = stop.clone();
            let login = login.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let Ok(Some(mut rq)) =
                        server.recv_timeout(std::time::Duration::from_millis(50))
                    else {
                        continue;
                    };
                    let mut body = String::new();
                    let _ = rq.as_reader().read_to_string(&mut body);
                    let header = |name: &str| {
                        rq.headers()
                            .iter()
                            .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
                            .map(|h| h.value.as_str().to_string())
                    };
                    if let Some((u, p)) = &login {
                        use base64::Engine as _;
                        let want = format!(
                            "Basic {}",
                            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
                        );
                        if header("Authorization").as_deref() != Some(want.as_str()) {
                            let _ = rq.respond(
                                tiny_http::Response::from_string("401: Unauthorized")
                                    .with_status_code(401),
                            );
                            continue;
                        }
                    }
                    let mut st = state.lock().unwrap();
                    if header(super::SESSION_HEADER).as_deref() != Some(st.session.as_str()) {
                        st.handshakes += 1;
                        let h = tiny_http::Header::from_bytes(
                            super::SESSION_HEADER.as_bytes(),
                            st.session.as_bytes(),
                        )
                        .unwrap();
                        let _ = rq.respond(
                            tiny_http::Response::from_string("409: Conflict")
                                .with_status_code(409)
                                .with_header(h),
                        );
                        continue;
                    }
                    let req: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                    let method = req["method"].as_str().unwrap_or("").to_string();
                    st.calls.push(method.clone());
                    let answer = match handle(&mut st, &method, &req["arguments"]) {
                        Ok(args) => json!({"result": "success", "arguments": args}),
                        Err(e) => json!({"result": e}),
                    };
                    drop(st);
                    let _ = rq.respond(tiny_http::Response::from_string(answer.to_string()));
                }
            })
        };
        FakeTransmission {
            url: format!("http://127.0.0.1:{port}/transmission/rpc"),
            login,
            state,
            stop,
            thread: Some(thread),
        }
    }

    pub fn settings(&self) -> RpcSettings {
        RpcSettings {
            url: self.url.clone(),
            user: self.login.as_ref().map(|l| l.0.clone()),
            password: self.login.as_ref().map(|l| l.1.clone()),
        }
    }

    /// The content of the torrent `metainfo` describes, one entry per file.
    pub fn provide(&self, metainfo: &[u8], files: &[Vec<u8>]) {
        let m = parse_metainfo(metainfo).expect("a valid torrent");
        assert_eq!(m.files.len(), files.len());
        let mut st = self.state.lock().unwrap();
        st.content.insert(m.hash.clone(), files.to_vec());
        st.metas.insert(m.hash.clone(), m);
    }

    /// Download up to `budget` bytes of the wanted, incomplete files of
    /// every running torrent, in file order. A magnet link's metadata
    /// arrives first (every file is then wanted, as in transmission).
    pub fn step(&self, mut budget: u64) {
        let mut st = self.state.lock().unwrap();
        let State {
            torrents,
            metas,
            content,
            ..
        } = &mut *st;
        for t in torrents.iter_mut().filter(|t| t.running && t.error == 0) {
            if t.meta.is_none() {
                if let Some(m) = metas.get(&t.hash) {
                    t.name = m.name.clone();
                    t.wanted = vec![true; m.files.len()];
                    t.done = vec![0; m.files.len()];
                    t.meta = Some(m.clone());
                }
                continue;
            }
            let meta = t.meta.clone().unwrap();
            let Some(data) = content.get(&t.hash) else {
                continue;
            };
            for (i, (name, len)) in meta.files.iter().enumerate() {
                if !t.wanted[i] || t.done[i] >= *len && *len > 0 {
                    continue;
                }
                let full = t.dir.join(name);
                let part = PathBuf::from(format!("{}.part", full.display()));
                std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                if *len == 0 {
                    if !full.exists() && t.done[i] == 0 {
                        std::fs::write(&full, b"").unwrap();
                    }
                    continue;
                }
                if budget == 0 {
                    return;
                }
                let n = (*len - t.done[i]).min(budget);
                let from = t.done[i] as usize;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&part)
                    .unwrap();
                f.write_all(&data[i][from..from + n as usize]).unwrap();
                drop(f);
                t.done[i] += n;
                budget -= n;
                if t.done[i] == *len {
                    std::fs::rename(&part, &full).unwrap();
                }
            }
        }
    }

    /// The daemon restarted: a new session id.
    pub fn new_session(&self) {
        let mut st = self.state.lock().unwrap();
        let n = st.handshakes + 2;
        st.session = format!("session-{n}");
    }

    /// 409 answers given so far.
    pub fn handshakes(&self) -> u64 {
        self.state.lock().unwrap().handshakes
    }

    /// How often `method` was called.
    pub fn calls(&self, method: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|m| *m == method)
            .count()
    }

    pub fn has(&self, hash: &str) -> bool {
        self.state
            .lock()
            .unwrap()
            .torrents
            .iter()
            .any(|t| t.hash == hash)
    }

    pub fn running(&self, hash: &str) -> bool {
        self.with(hash, |t| t.running)
    }

    pub fn wanted(&self, hash: &str) -> Vec<bool> {
        self.with(hash, |t| t.wanted.clone())
    }

    pub fn limited(&self, hash: &str) -> bool {
        self.with(hash, |t| t.limited)
    }

    /// A local error (as transmission reports a failed write): the torrent stops.
    pub fn set_error(&self, hash: &str, code: i64, text: &str) {
        let mut st = self.state.lock().unwrap();
        if let Some(t) = st.torrents.iter_mut().find(|t| t.hash == hash) {
            t.error = code;
            t.error_string = text.to_string();
            t.running = false;
        }
    }

    /// Forget that pieces of a file were downloaded (as a re-check after
    /// its data was deleted would).
    pub fn forget_file(&self, hash: &str, index: usize) {
        let mut st = self.state.lock().unwrap();
        if let Some(t) = st.torrents.iter_mut().find(|t| t.hash == hash) {
            t.done[index] = 0;
        }
    }

    fn with<T>(&self, hash: &str, f: impl FnOnce(&Torrent) -> T) -> T {
        let st = self.state.lock().unwrap();
        f(st.torrents
            .iter()
            .find(|t| t.hash == hash)
            .expect("the torrent"))
    }
}

impl Drop for FakeTransmission {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn ids(args: &Value) -> Vec<String> {
    args["ids"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_lowercase))
                .collect()
        })
        .unwrap_or_default()
}

fn indices(v: &Value, n: usize) -> Option<Vec<usize>> {
    let a = v.as_array()?;
    if a.is_empty() {
        return Some((0..n).collect());
    }
    Some(
        a.iter()
            .filter_map(|x| x.as_u64().map(|x| x as usize))
            .filter(|i| *i < n)
            .collect(),
    )
}

fn handle(st: &mut State, method: &str, args: &Value) -> Result<Value, String> {
    match method {
        "session-get" => Ok(json!({
            "download-dir": st.default_dir.display().to_string(),
            "version": "4.0.6 (fake)",
            "rpc-version": 17,
        })),
        "torrent-add" => {
            let dir = args["download-dir"]
                .as_str()
                .map(PathBuf::from)
                .unwrap_or_else(|| st.default_dir.clone());
            let (hash, meta, name) = if let Some(b64) = args["metainfo"].as_str() {
                use base64::Engine as _;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| "invalid or corrupt torrent file".to_string())?;
                let m = parse_metainfo(&bytes)
                    .map_err(|_| "invalid or corrupt torrent file".to_string())?;
                (m.hash.clone(), Some(m.clone()), m.name)
            } else if let Some(f) = args["filename"].as_str() {
                let (h, n) = parse_magnet(f).map_err(|e| e.to_string())?;
                (h.clone(), None, n.unwrap_or(h))
            } else {
                return Err("no filename or metainfo specified".into());
            };
            if let Some(t) = st.torrents.iter().find(|t| t.hash == hash) {
                return Ok(
                    json!({"torrent-duplicate": {"id": t.id, "name": t.name, "hashString": t.hash}}),
                );
            }
            let n = meta.as_ref().map(|m| m.files.len()).unwrap_or(0);
            let mut wanted = vec![true; n];
            if let Some(un) = args.get("files-unwanted").and_then(|v| v.as_array()) {
                for i in un.iter().filter_map(|x| x.as_u64()) {
                    if let Some(w) = wanted.get_mut(i as usize) {
                        *w = false;
                    }
                }
            }
            let id = st.next_id;
            st.next_id += 1;
            st.torrents.push(Torrent {
                id,
                hash: hash.clone(),
                name: name.clone(),
                meta,
                dir,
                wanted,
                done: vec![0; n],
                running: !args["paused"].as_bool().unwrap_or(false),
                error: 0,
                error_string: String::new(),
                limited: false,
            });
            Ok(json!({"torrent-added": {"id": id, "name": name, "hashString": hash}}))
        }
        "torrent-get" => {
            let want = ids(args);
            let list: Vec<Value> = st
                .torrents
                .iter()
                .filter(|t| want.is_empty() || want.contains(&t.hash))
                .map(|t| {
                    let files: Vec<(String, u64)> =
                        t.meta.as_ref().map(|m| m.files.clone()).unwrap_or_default();
                    let total: u64 = files.iter().map(|f| f.1).sum();
                    let wanted_total: u64 = files
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| t.wanted[*i])
                        .map(|(_, f)| f.1)
                        .sum();
                    let wanted_done: u64 = files
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| t.wanted[*i])
                        .map(|(i, _)| t.done[i])
                        .sum();
                    let seeding = wanted_done >= wanted_total;
                    json!({
                        "id": t.id,
                        "hashString": t.hash,
                        "name": t.name,
                        "totalSize": total,
                        "pieceSize": t.meta.as_ref().map(|m| m.piece_length).unwrap_or(0),
                        "files": files.iter().enumerate().map(|(i, (n, l))| json!({"name": n, "length": l, "bytesCompleted": t.done[i]})).collect::<Vec<_>>(),
                        "fileStats": files.iter().enumerate().map(|(i, _)| json!({"bytesCompleted": t.done[i], "wanted": t.wanted[i], "priority": 0})).collect::<Vec<_>>(),
                        "status": if !t.running { 0 } else if seeding { 6 } else { 4 },
                        "percentDone": if wanted_total == 0 { 1.0 } else { wanted_done as f64 / wanted_total as f64 },
                        "downloadDir": t.dir.display().to_string(),
                        "error": t.error,
                        "errorString": t.error_string,
                    })
                })
                .collect();
            Ok(json!({"torrents": list}))
        }
        "torrent-set" => {
            let want = ids(args);
            for t in st.torrents.iter_mut().filter(|t| want.contains(&t.hash)) {
                let n = t.wanted.len();
                if let Some(v) = args.get("files-wanted").and_then(|v| indices(v, n)) {
                    for i in v {
                        t.wanted[i] = true;
                    }
                }
                if let Some(v) = args.get("files-unwanted").and_then(|v| indices(v, n)) {
                    for i in v {
                        t.wanted[i] = false;
                    }
                }
                if let Some(l) = args.get("downloadLimited").and_then(|v| v.as_bool()) {
                    t.limited = l;
                }
            }
            Ok(json!({}))
        }
        "torrent-start" | "torrent-stop" => {
            let want = ids(args);
            for t in st.torrents.iter_mut().filter(|t| want.contains(&t.hash)) {
                t.running = method == "torrent-start";
                if t.running {
                    t.error = 0;
                    t.error_string.clear();
                }
            }
            Ok(json!({}))
        }
        "torrent-verify" => {
            let want = ids(args);
            for t in st.torrents.iter_mut().filter(|t| want.contains(&t.hash)) {
                let Some(m) = &t.meta else { continue };
                for (i, (n, len)) in m.files.iter().enumerate() {
                    let full = t.dir.join(n);
                    let part = PathBuf::from(format!("{}.part", full.display()));
                    t.done[i] = if full.is_file() {
                        *len
                    } else {
                        std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0)
                    };
                }
            }
            Ok(json!({}))
        }
        "torrent-remove" => {
            let want = ids(args);
            let delete = args["delete-local-data"].as_bool().unwrap_or(false);
            st.torrents.retain(|t| {
                if !want.contains(&t.hash) {
                    return true;
                }
                if delete {
                    if let Some(m) = &t.meta {
                        for (n, _) in &m.files {
                            let p = t.dir.join(n);
                            let _ = std::fs::remove_file(&p);
                            let _ = std::fs::remove_file(format!("{}.part", p.display()));
                        }
                    }
                }
                false
            });
            Ok(json!({}))
        }
        other => Err(format!("method name not recognized: {other}")),
    }
}
