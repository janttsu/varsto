// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A client for the RPC interface of a local transmission-daemon (JSON over
//! HTTP, `docs/spec/alpha-0-format.md` section "Torrents through a local
//! transmission daemon"), the little of the BitTorrent metainfo format that
//! a torrent job needs (the info hash, the file list, the piece size), and
//! [`fake`]: an in-process transmission for tests.
//!
//! Only documented RPC methods are used: `session-get`, `torrent-add`,
//! `torrent-get`, `torrent-set`, `torrent-start`, `torrent-stop`,
//! `torrent-verify` and `torrent-remove`. Torrents are always named by their info hash
//! (`ids: ["<hashString>"]`), never by transmission's numeric id, which
//! changes when the daemon restarts.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::sync::Mutex;
use std::time::Duration;

/// transmission-daemon's default RPC address.
pub const DEFAULT_URL: &str = "http://127.0.0.1:9091/transmission/rpc";
/// The header of the CSRF handshake: a request without the current value
/// is answered with 409 and the value to use.
pub const SESSION_HEADER: &str = "X-Transmission-Session-Id";

/// Where the daemon is and how to sign in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RpcSettings {
    pub url: String,
    pub user: Option<String>,
    pub password: Option<String>,
}

impl RpcSettings {
    /// Settings from the environment (`VARSTO_TRANSMISSION_URL`,
    /// `VARSTO_TRANSMISSION_USER`, `VARSTO_TRANSMISSION_PASSWORD`), each
    /// unless given here.
    pub fn resolve(url: Option<&str>, user: Option<&str>, password: Option<&str>) -> RpcSettings {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        RpcSettings {
            url: url
                .map(str::to_string)
                .or_else(|| env("VARSTO_TRANSMISSION_URL"))
                .unwrap_or_else(|| DEFAULT_URL.to_string()),
            user: user
                .map(str::to_string)
                .or_else(|| env("VARSTO_TRANSMISSION_USER")),
            password: password
                .map(str::to_string)
                .or_else(|| env("VARSTO_TRANSMISSION_PASSWORD")),
        }
    }
}

/// One file of a torrent as transmission reports it (`files` and
/// `fileStats` of `torrent-get`, joined).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TorrentFile {
    /// The path inside the download directory, `/` separated (multi-file
    /// torrents start with the torrent's name).
    pub name: String,
    pub length: u64,
    /// Bytes of pieces that were downloaded and matched their hash.
    pub bytes_completed: u64,
    pub wanted: bool,
}

impl TorrentFile {
    pub fn complete(&self) -> bool {
        self.bytes_completed >= self.length
    }
}

/// A torrent as `torrent-get` reports it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TorrentInfo {
    pub hash: String,
    pub name: String,
    pub total_size: u64,
    pub piece_size: u64,
    /// Empty while a magnet link's metadata has not arrived.
    pub files: Vec<TorrentFile>,
    /// 0 stopped, 1 queued to check, 2 checking, 3 queued to download,
    /// 4 downloading, 5 queued to seed, 6 seeding.
    pub status: i64,
    pub percent_done: f64,
    pub download_dir: String,
    /// 0 none, 1 tracker warning, 2 tracker error, 3 local error.
    pub error: i64,
    pub error_string: String,
}

impl TorrentInfo {
    pub fn stopped(&self) -> bool {
        self.status == 0
    }
    pub fn checking(&self) -> bool {
        self.status == 1 || self.status == 2
    }
}

/// What to add.
#[derive(Clone, Debug)]
pub enum AddSource {
    /// The content of a .torrent file.
    Metainfo(Vec<u8>),
    /// A magnet link.
    Magnet(String),
}

/// The answer to `torrent-add`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Added {
    pub hash: String,
    pub name: String,
    /// The daemon had the torrent already (nothing was changed).
    pub duplicate: bool,
}

/// The fields a job reads with `torrent-get`.
pub const FIELDS: &[&str] = &[
    "id",
    "hashString",
    "name",
    "totalSize",
    "pieceSize",
    "files",
    "fileStats",
    "status",
    "percentDone",
    "downloadDir",
    "error",
    "errorString",
];

/// A connection to a transmission daemon.
pub struct Rpc {
    settings: RpcSettings,
    agent: ureq::Agent,
    session: Mutex<Option<String>>,
}

impl Rpc {
    pub fn new(settings: RpcSettings) -> Rpc {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .timeout_connect(Some(Duration::from_secs(10)))
            .build()
            .into();
        Rpc {
            settings,
            agent,
            session: Mutex::new(None),
        }
    }

    pub fn url(&self) -> &str {
        &self.settings.url
    }

    /// Call `method` with `arguments`; the `arguments` of the answer.
    pub fn call(&self, method: &str, arguments: Value) -> Result<Value> {
        let body = json!({"method": method, "arguments": arguments}).to_string();
        // The first answer may be 409 with the session id to use; then
        // once more with it (also when the daemon restarted meanwhile).
        for _ in 0..2 {
            let mut req = self
                .agent
                .post(&self.settings.url)
                .header("Content-Type", "application/json");
            if let Some(id) = self.session.lock().unwrap().clone() {
                req = req.header(SESSION_HEADER, id.as_str());
            }
            if let Some(user) = &self.settings.user {
                use base64::Engine as _;
                let pass = self.settings.password.clone().unwrap_or_default();
                let token =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
                req = req.header("Authorization", format!("Basic {token}").as_str());
            }
            let mut resp = req.send(body.as_bytes()).with_context(|| {
                format!(
                    "transmission-daemon does not answer at {} (is it running? see docs/torrents.md)",
                    self.settings.url
                )
            })?;
            let status = resp.status().as_u16();
            if status == 409 {
                let id = resp
                    .headers()
                    .get(SESSION_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
                    .ok_or_else(|| anyhow!("transmission answered 409 without a session id"))?;
                *self.session.lock().unwrap() = Some(id);
                continue;
            }
            if status == 401 || status == 403 {
                bail!(
                    "transmission at {} refused the sign-in ({status}): give --rpc-user and --rpc-password or set VARSTO_TRANSMISSION_USER and VARSTO_TRANSMISSION_PASSWORD",
                    self.settings.url
                );
            }
            let text = resp
                .body_mut()
                .with_config()
                .limit(64 << 20)
                .read_to_string()
                .context("read transmission's answer")?;
            if status != 200 {
                bail!(
                    "transmission answered {status} to {method}: {}",
                    text.trim()
                );
            }
            let v: Value = serde_json::from_str(&text)
                .with_context(|| format!("transmission's answer to {method} is not JSON"))?;
            let result = v.get("result").and_then(Value::as_str).unwrap_or("");
            if result != "success" {
                bail!("transmission: {method} failed: {result}");
            }
            return Ok(v.get("arguments").cloned().unwrap_or(Value::Null));
        }
        bail!("transmission kept asking for a new session id")
    }

    /// The daemon's settings (`download-dir`, `version`, ...).
    pub fn session_get(&self) -> Result<Value> {
        self.call("session-get", json!({}))
    }

    /// Add a torrent stopped; `unwanted` file indices are not downloaded.
    pub fn add(&self, source: &AddSource, download_dir: &str, unwanted: &[usize]) -> Result<Added> {
        let mut args = json!({
            "download-dir": download_dir,
            "paused": true,
        });
        match source {
            AddSource::Metainfo(bytes) => {
                use base64::Engine as _;
                args["metainfo"] = json!(base64::engine::general_purpose::STANDARD.encode(bytes));
            }
            AddSource::Magnet(m) => args["filename"] = json!(m),
        }
        if !unwanted.is_empty() {
            args["files-unwanted"] = json!(unwanted);
        }
        let r = self.call("torrent-add", args)?;
        let (t, duplicate) = match (r.get("torrent-added"), r.get("torrent-duplicate")) {
            (Some(t), _) => (t, false),
            (None, Some(t)) => (t, true),
            _ => bail!("transmission did not say which torrent it added"),
        };
        Ok(Added {
            hash: t
                .get("hashString")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_lowercase(),
            name: t
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            duplicate,
        })
    }

    /// The torrent with this info hash, if the daemon has it.
    pub fn get(&self, hash: &str) -> Result<Option<TorrentInfo>> {
        let r = self.call("torrent-get", json!({"ids": [hash], "fields": FIELDS}))?;
        let Some(t) = r.get("torrents").and_then(Value::as_array).and_then(|a| {
            a.iter().find(|t| {
                t.get("hashString")
                    .and_then(Value::as_str)
                    .is_some_and(|h| h.eq_ignore_ascii_case(hash))
            })
        }) else {
            return Ok(None);
        };
        Ok(Some(parse_torrent(t)?))
    }

    /// Mark files wanted or unwanted. An empty list in transmission means
    /// every file, so empty lists are left out here; [`Rpc::all_unwanted`]
    /// says "every file" on purpose.
    pub fn set_files(&self, hash: &str, wanted: &[usize], unwanted: &[usize]) -> Result<()> {
        if wanted.is_empty() && unwanted.is_empty() {
            return Ok(());
        }
        let mut args = json!({"ids": [hash]});
        if !wanted.is_empty() {
            args["files-wanted"] = json!(wanted);
            args["priority-normal"] = json!(wanted);
        }
        if !unwanted.is_empty() {
            args["files-unwanted"] = json!(unwanted);
        }
        self.call("torrent-set", args).map(|_| ())
    }

    /// Every file of the torrent unwanted.
    pub fn all_unwanted(&self, hash: &str) -> Result<()> {
        self.call("torrent-set", json!({"ids": [hash], "files-unwanted": []}))
            .map(|_| ())
    }

    /// Limit (`Some(kB/s)`) or stop limiting the torrent's download speed.
    pub fn limit_download(&self, hash: &str, kbps: Option<u64>) -> Result<()> {
        let args = match kbps {
            Some(k) => json!({"ids": [hash], "downloadLimited": true, "downloadLimit": k}),
            None => json!({"ids": [hash], "downloadLimited": false}),
        };
        self.call("torrent-set", args).map(|_| ())
    }

    /// Check the downloaded data against the piece hashes again: pieces
    /// whose data is gone are forgotten (not offered to peers any more).
    pub fn verify(&self, hash: &str) -> Result<()> {
        self.call("torrent-verify", json!({"ids": [hash]}))
            .map(|_| ())
    }

    pub fn start(&self, hash: &str) -> Result<()> {
        self.call("torrent-start", json!({"ids": [hash]}))
            .map(|_| ())
    }

    pub fn stop(&self, hash: &str) -> Result<()> {
        self.call("torrent-stop", json!({"ids": [hash]}))
            .map(|_| ())
    }

    /// Remove the torrent from the daemon; `delete_data` also deletes what
    /// it downloaded.
    pub fn remove(&self, hash: &str, delete_data: bool) -> Result<()> {
        self.call(
            "torrent-remove",
            json!({"ids": [hash], "delete-local-data": delete_data}),
        )
        .map(|_| ())
    }
}

fn parse_torrent(t: &Value) -> Result<TorrentInfo> {
    let u = |k: &str| t.get(k).and_then(Value::as_u64).unwrap_or(0);
    let s = |k: &str| {
        t.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let files = t
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let stats = t
        .get("fileStats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::with_capacity(files.len());
    for (i, f) in files.iter().enumerate() {
        let st = stats.get(i);
        out.push(TorrentFile {
            name: f
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("transmission sent a file without a name"))?
                .to_string(),
            length: f.get("length").and_then(Value::as_u64).unwrap_or(0),
            bytes_completed: st
                .and_then(|s| s.get("bytesCompleted"))
                .or_else(|| f.get("bytesCompleted"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            wanted: st
                .and_then(|s| s.get("wanted"))
                .and_then(|w| w.as_bool().or_else(|| w.as_i64().map(|n| n != 0)))
                .unwrap_or(true),
        });
    }
    Ok(TorrentInfo {
        hash: s("hashString").to_lowercase(),
        name: s("name"),
        total_size: u("totalSize"),
        piece_size: u("pieceSize"),
        files: out,
        status: t.get("status").and_then(Value::as_i64).unwrap_or(0),
        percent_done: t.get("percentDone").and_then(Value::as_f64).unwrap_or(0.0),
        download_dir: s("downloadDir"),
        error: t.get("error").and_then(Value::as_i64).unwrap_or(0),
        error_string: s("errorString"),
    })
}

// ----- metainfo and magnet links ------------------------------------------------

/// What a job needs to know of a .torrent file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metainfo {
    /// SHA-1 of the bencoded info dictionary, lowercase hex (the v1 info hash).
    pub hash: String,
    pub name: String,
    /// Paths as transmission names them: `<name>/<path>` in a multi-file
    /// torrent, `<name>` in a single-file one; with their lengths.
    pub files: Vec<(String, u64)>,
    pub piece_length: u64,
}

enum Bval<'a> {
    Int(i64),
    Bytes(&'a [u8]),
    List(Vec<Bval<'a>>),
    /// Keys, values and each value's byte range in the input.
    Dict(Vec<(&'a [u8], Bval<'a>, (usize, usize))>),
}

impl<'a> Bval<'a> {
    fn get(&self, key: &str) -> Option<&Bval<'a>> {
        match self {
            Bval::Dict(d) => d
                .iter()
                .find(|(k, _, _)| *k == key.as_bytes())
                .map(|(_, v, _)| v),
            _ => None,
        }
    }
    fn span(&self, key: &str) -> Option<(usize, usize)> {
        match self {
            Bval::Dict(d) => d
                .iter()
                .find(|(k, _, _)| *k == key.as_bytes())
                .map(|(_, _, s)| *s),
            _ => None,
        }
    }
    fn int(&self) -> Option<i64> {
        match self {
            Bval::Int(n) => Some(*n),
            _ => None,
        }
    }
    fn text(&self) -> Option<String> {
        match self {
            Bval::Bytes(b) => std::str::from_utf8(b).ok().map(str::to_string),
            _ => None,
        }
    }
}

fn bdecode<'a>(d: &'a [u8], pos: &mut usize, depth: usize) -> Result<Bval<'a>> {
    if depth > 64 {
        bail!("the torrent file nests too deeply");
    }
    let c = *d
        .get(*pos)
        .ok_or_else(|| anyhow!("the torrent file ends early"))?;
    match c {
        b'i' => {
            let end = d[*pos..]
                .iter()
                .position(|&b| b == b'e')
                .ok_or_else(|| anyhow!("bad integer in the torrent file"))?
                + *pos;
            let n: i64 = std::str::from_utf8(&d[*pos + 1..end])?
                .parse()
                .context("bad integer in the torrent file")?;
            *pos = end + 1;
            Ok(Bval::Int(n))
        }
        b'l' => {
            *pos += 1;
            let mut v = Vec::new();
            while d.get(*pos) != Some(&b'e') {
                v.push(bdecode(d, pos, depth + 1)?);
            }
            *pos += 1;
            Ok(Bval::List(v))
        }
        b'd' => {
            *pos += 1;
            let mut v = Vec::new();
            while d.get(*pos) != Some(&b'e') {
                let Bval::Bytes(k) = bdecode(d, pos, depth + 1)? else {
                    bail!("a dictionary key in the torrent file is not a string");
                };
                let start = *pos;
                let val = bdecode(d, pos, depth + 1)?;
                v.push((k, val, (start, *pos)));
            }
            *pos += 1;
            Ok(Bval::Dict(v))
        }
        b'0'..=b'9' => {
            let colon = d[*pos..]
                .iter()
                .position(|&b| b == b':')
                .ok_or_else(|| anyhow!("bad string in the torrent file"))?
                + *pos;
            let len: usize = std::str::from_utf8(&d[*pos..colon])?
                .parse()
                .context("bad string length in the torrent file")?;
            let start = colon + 1;
            let end = start
                .checked_add(len)
                .filter(|e| *e <= d.len())
                .ok_or_else(|| anyhow!("the torrent file ends early"))?;
            *pos = end;
            Ok(Bval::Bytes(&d[start..end]))
        }
        _ => bail!("not a torrent file (bad bencoding)"),
    }
}

/// Read a .torrent file's info hash, name, files and piece size.
pub fn parse_metainfo(data: &[u8]) -> Result<Metainfo> {
    let mut pos = 0;
    let top = bdecode(data, &mut pos, 0)?;
    let (s, e) = top
        .span("info")
        .ok_or_else(|| anyhow!("not a torrent file: no info dictionary"))?;
    let info = top.get("info").expect("span found");
    let hash = hex::encode(Sha1::digest(&data[s..e]));
    let name = info
        .get("name.utf-8")
        .or_else(|| info.get("name"))
        .and_then(Bval::text)
        .ok_or_else(|| anyhow!("the torrent has no name"))?;
    let piece_length = info
        .get("piece length")
        .and_then(Bval::int)
        .filter(|n| *n > 0)
        .ok_or_else(|| anyhow!("the torrent has no piece length"))? as u64;
    let mut files = Vec::new();
    match info.get("files") {
        Some(Bval::List(list)) => {
            for f in list {
                let len = f
                    .get("length")
                    .and_then(Bval::int)
                    .filter(|n| *n >= 0)
                    .ok_or_else(|| anyhow!("a file of the torrent has no length"))?;
                let Some(Bval::List(parts)) = f.get("path.utf-8").or_else(|| f.get("path")) else {
                    bail!("a file of the torrent has no path");
                };
                let mut path = name.clone();
                for p in parts {
                    path.push('/');
                    path.push_str(
                        &p.text()
                            .ok_or_else(|| anyhow!("a file name of the torrent is not UTF-8"))?,
                    );
                }
                files.push((path, len as u64));
            }
        }
        _ => {
            let len = info
                .get("length")
                .and_then(Bval::int)
                .filter(|n| *n >= 0)
                .ok_or_else(|| anyhow!("the torrent has neither files nor a length"))?;
            files.push((name.clone(), len as u64));
        }
    }
    Ok(Metainfo {
        hash,
        name,
        files,
        piece_length,
    })
}

/// The info hash (lowercase hex) and display name of a magnet link.
pub fn parse_magnet(uri: &str) -> Result<(String, Option<String>)> {
    let q = uri
        .strip_prefix("magnet:?")
        .ok_or_else(|| anyhow!("not a magnet link: {uri}"))?;
    let mut hash = None;
    let mut name = None;
    for part in q.split('&') {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        match k {
            "xt" => {
                if let Some(h) = v.strip_prefix("urn:btih:") {
                    let h = if h.len() == 40 && h.chars().all(|c| c.is_ascii_hexdigit()) {
                        h.to_lowercase()
                    } else if h.len() == 32 {
                        let raw = data_encoding::BASE32
                            .decode(h.to_ascii_uppercase().as_bytes())
                            .map_err(|_| anyhow!("bad info hash in the magnet link"))?;
                        hex::encode(raw)
                    } else {
                        bail!("bad info hash in the magnet link");
                    };
                    hash = Some(h);
                }
            }
            "dn" => name = Some(percent_decode(v)),
            _ => {}
        }
    }
    let hash = hash.ok_or_else(|| {
        anyhow!("the magnet link has no BitTorrent v1 info hash (xt=urn:btih:...)")
    })?;
    Ok((hash, name))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn bencode_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(format!("{}:", b.len()).as_bytes());
    out.extend_from_slice(b);
}

/// A .torrent file for `files` (paths below the torrent's name, with their
/// content), for tests: `name` is the top directory of a multi-file
/// torrent, or the file of a single-file one when `files` has one entry
/// with an empty path.
#[doc(hidden)]
pub fn make_metainfo(name: &str, files: &[(&str, &[u8])], piece_length: usize) -> Vec<u8> {
    let mut all = Vec::new();
    for (_, d) in files {
        all.extend_from_slice(d);
    }
    let mut pieces = Vec::new();
    for chunk in all.chunks(piece_length.max(1)) {
        pieces.extend_from_slice(&Sha1::digest(chunk));
    }
    let mut info = b"d".to_vec();
    let single = files.len() == 1 && files[0].0.is_empty();
    if single {
        info.extend_from_slice(format!("6:lengthi{}e", files[0].1.len()).as_bytes());
    } else {
        info.extend_from_slice(b"5:filesl");
        for (p, d) in files {
            info.extend_from_slice(format!("d6:lengthi{}e4:pathl", d.len()).as_bytes());
            for part in p.split('/') {
                bencode_bytes(&mut info, part.as_bytes());
            }
            info.extend_from_slice(b"ee");
        }
        info.push(b'e');
    }
    info.extend_from_slice(b"4:name");
    bencode_bytes(&mut info, name.as_bytes());
    info.extend_from_slice(format!("12:piece lengthi{piece_length}e").as_bytes());
    info.extend_from_slice(b"6:pieces");
    bencode_bytes(&mut info, &pieces);
    info.push(b'e');
    let mut out = b"d8:announce".to_vec();
    bencode_bytes(&mut out, b"http://127.0.0.1:1/announce");
    out.extend_from_slice(b"4:info");
    out.extend_from_slice(&info);
    out.push(b'e');
    out
}

pub mod fake;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metainfo_multi_and_single() {
        let a: &[u8] = b"hello";
        let b: &[u8] = b"world, longer";
        let t = make_metainfo("Show", &[("a.txt", a), ("sub/b.bin", b)], 4);
        let m = parse_metainfo(&t).unwrap();
        assert_eq!(m.name, "Show");
        assert_eq!(
            m.files,
            vec![
                ("Show/a.txt".to_string(), 5),
                ("Show/sub/b.bin".to_string(), 13)
            ]
        );
        assert_eq!(m.piece_length, 4);
        assert_eq!(m.hash.len(), 40);
        let s = make_metainfo("one.iso", &[("", a)], 16);
        let m1 = parse_metainfo(&s).unwrap();
        assert_eq!(m1.files, vec![("one.iso".to_string(), 5)]);
        assert_ne!(m1.hash, m.hash);
        assert!(parse_metainfo(b"d3:fooi1ee").is_err());
        assert!(parse_metainfo(b"garbage").is_err());
        assert!(parse_metainfo(b"d4:info").is_err());
    }

    #[test]
    fn magnet_links() {
        let (h, n) = parse_magnet(
            "magnet:?xt=urn:btih:0123456789ABCDEF0123456789abcdef01234567&dn=My+Show%20S01&tr=x",
        )
        .unwrap();
        assert_eq!(h, "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(n.as_deref(), Some("My Show S01"));
        let b32 = data_encoding::BASE32.encode(&[7u8; 20]);
        let (h, _) = parse_magnet(&format!("magnet:?xt=urn:btih:{b32}")).unwrap();
        assert_eq!(h, hex::encode([7u8; 20]));
        assert!(parse_magnet("magnet:?dn=x").is_err());
        assert!(parse_magnet("http://x").is_err());
    }

    #[test]
    fn handshake_and_methods_against_the_fake() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = fake::FakeTransmission::start(tmp.path());
        let a: &[u8] = b"0123456789";
        let t = make_metainfo("T", &[("x", a), ("y", a)], 4);
        fake.provide(&t, &[a.to_vec(), a.to_vec()]);
        let rpc = Rpc::new(fake.settings());
        let s = rpc.session_get().unwrap();
        assert!(s["download-dir"].is_string());
        assert_eq!(fake.handshakes(), 1, "one 409 first, then the id is kept");
        let added = rpc
            .add(
                &AddSource::Metainfo(t.clone()),
                &tmp.path().join("dl").display().to_string(),
                &[0, 1],
            )
            .unwrap();
        assert!(!added.duplicate);
        let info = rpc.get(&added.hash).unwrap().unwrap();
        assert!(info.stopped());
        assert_eq!(info.files.len(), 2);
        assert!(info.files.iter().all(|f| !f.wanted));
        let again = rpc
            .add(
                &AddSource::Metainfo(t),
                &tmp.path().display().to_string(),
                &[],
            )
            .unwrap();
        assert!(again.duplicate);
        // A daemon restart hands out a new session id: the client follows.
        fake.new_session();
        rpc.set_files(&added.hash, &[1], &[]).unwrap();
        assert_eq!(fake.handshakes(), 2);
        rpc.start(&added.hash).unwrap();
        fake.step(u64::MAX);
        let info = rpc.get(&added.hash).unwrap().unwrap();
        assert!(!info.files[0].complete() && info.files[1].complete());
        assert_eq!(std::fs::read(tmp.path().join("dl/T/y")).unwrap(), a);
        rpc.remove(&added.hash, false).unwrap();
        assert!(rpc.get(&added.hash).unwrap().is_none());
        // Signing in.
        let fake2 = fake::FakeTransmission::start_with_login(tmp.path(), "u", "p");
        let mut bad = fake2.settings();
        bad.password = Some("wrong".into());
        let e = Rpc::new(bad).session_get().unwrap_err();
        assert!(format!("{e:#}").contains("refused the sign-in"), "{e:#}");
        Rpc::new(fake2.settings()).session_get().unwrap();
    }
}
