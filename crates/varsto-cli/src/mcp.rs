// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! MCP server (Model Context Protocol, JSON-RPC 2.0 over stdio) so that an AI
//! assistant can look at, organise and reason about the files in this vault
//! with exactly the access the user granted.
//!
//! Access is per folder: `varsto mcp grant <folder> [--analyse | --write]`
//! records a grant in `mcp-grants.json`: read-only (`ro`), read and record
//! file analyses (`an`), or read-write (`rw`, which includes analyses);
//! nothing is reachable without a grant. When the background service is running, calls are routed
//! through its local API (one process owns the state); otherwise the vault is
//! opened directly with `VARSTO_PASSPHRASE`.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use varsto_core::Engine;

const PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Grants {
    /// "ro", "an" or "rw" for every folder, or none.
    #[serde(default)]
    pub all: Option<String>,
    #[serde(default)]
    pub folders: BTreeMap<String, String>,
}

impl Grants {
    pub const FILE: &'static str = "mcp-grants.json";
    pub fn load(home: &Path) -> Result<Self> {
        varsto_core::util::read_json_or_default(&home.join(Self::FILE))
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        std::fs::create_dir_all(home)?;
        varsto_core::util::write_atomic(&home.join(Self::FILE), &serde_json::to_vec_pretty(self)?)
    }
    fn level(&self, folder: &str) -> Option<&str> {
        self.folders
            .get(folder)
            .map(|s| s.as_str())
            .or(self.all.as_deref())
    }
    /// A grant on every folder never covers a Strongroom: those need their
    /// own line in the grants file.
    pub fn explicit(&self, folder: &str) -> bool {
        self.folders.contains_key(folder)
    }
    pub fn can_read(&self, folder: &str) -> bool {
        self.level(folder).is_some()
    }
    pub fn can_write(&self, folder: &str) -> bool {
        self.level(folder) == Some("rw")
    }
    /// Recording file analyses: an `an` or `rw` grant.
    pub fn can_analyse(&self, folder: &str) -> bool {
        matches!(self.level(folder), Some("an") | Some("rw"))
    }
}

/// What a grant level allows, in words.
pub fn level_words(level: &str) -> &'static str {
    match level {
        "rw" => "read-write: list, read, record analyses, move, create files",
        "an" => "analyse: list, read and record file analyses; no moves or new files",
        _ => "read-only: list and read",
    }
}

/// Where the data comes from.
enum Backend {
    Http { port: u16, token: String },
    Direct(Box<Engine>),
}

impl Backend {
    fn open(home: &Path) -> Result<Backend> {
        if let Some((sf, _)) = crate::service::status(home) {
            return Ok(Backend::Http {
                port: sf.port,
                token: sf.token,
            });
        }
        let pass = std::env::var("VARSTO_PASSPHRASE").map_err(|_| {
            anyhow!("the background service is not running and VARSTO_PASSPHRASE is not set")
        })?;
        Ok(Backend::Direct(Box::new(Engine::open(home, &pass)?)))
    }

    fn http(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Vec<u8>)> {
        let Backend::Http { port, token } = self else {
            unreachable!()
        };
        let mut stream = TcpStream::connect(("127.0.0.1", *port))
            .with_context(|| format!("connect to the service on port {port}"))?;
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Varsto-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        stream.write_all(req.as_bytes())?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        let sep = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow!("malformed response from the service"))?;
        let head = String::from_utf8_lossy(&raw[..sep]).to_string();
        let status: u16 = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = &raw[sep + 4..];
        let chunked = head.lines().any(|l| {
            l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.contains("chunked")
        });
        Ok((
            status,
            if chunked {
                varsto_core::p2p::decode_chunked(body)?
            } else {
                body.to_vec()
            },
        ))
    }

    fn call_json(&mut self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        match self {
            Backend::Http { .. } => {
                let (status, bytes) = self.http(method, path, body.as_ref())?;
                let v: Value = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| json!({"error": String::from_utf8_lossy(&bytes)}));
                if status >= 400 {
                    bail!("{}", v["error"].as_str().unwrap_or("request failed"));
                }
                Ok(v)
            }
            Backend::Direct(_) => unreachable!("direct backend handles calls itself"),
        }
    }

    fn status(&mut self) -> Result<Value> {
        match self {
            Backend::Http { .. } => self.call_json("GET", "/api/status", None),
            Backend::Direct(e) => Ok(serde_json::to_value(e.status()?)?),
        }
    }
    fn folders(&mut self) -> Result<Vec<Value>> {
        let all = match self {
            Backend::Http { .. } => self
                .call_json("GET", "/api/folders", None)?
                .as_array()
                .cloned()
                .unwrap_or_default(),
            Backend::Direct(e) => e
                .folders()
                .into_iter()
                .map(|(r, m)| json!({"id": r.folder_id.to_string(), "name": r.name, "path": m, "strongroom": r.is_strongroom(), "plain": !e.folder_is_encrypted_here(&r.folder_id)}))
                .collect(),
        };
        // Strongroom folders are never visible to assistants (S-012).
        Ok(all
            .into_iter()
            .filter(|f| !f["strongroom"].as_bool().unwrap_or(false))
            .collect())
    }
    fn files(&mut self, folder: &str) -> Result<Value> {
        match self {
            Backend::Http { .. } => self.call_json(
                "GET",
                &format!("/api/files?folder={}", urlencode(folder)),
                None,
            ),
            Backend::Direct(e) => Ok(serde_json::to_value(e.list_files(folder)?)?),
        }
    }
    fn move_file(&mut self, folder: &str, from: &str, to: &str) -> Result<Value> {
        match self {
            Backend::Http { .. } => self.call_json(
                "POST",
                "/api/move",
                Some(json!({"folder": folder, "from": from, "to": to})),
            ),
            Backend::Direct(e) => Ok(serde_json::to_value(e.move_file(folder, from, to)?)?),
        }
    }
    fn mkdir(&mut self, folder: &str, path: &str) -> Result<()> {
        match self {
            Backend::Http { .. } => {
                self.call_json(
                    "POST",
                    "/api/mkdir",
                    Some(json!({"folder": folder, "path": path})),
                )?;
                Ok(())
            }
            Backend::Direct(e) => e.mkdir(folder, path),
        }
    }
    fn write(&mut self, folder: &str, path: &str, bytes: &[u8]) -> Result<Value> {
        match self {
            Backend::Http { .. } => self.call_json(
                "POST",
                "/api/write",
                Some(
                    json!({"folder": folder, "path": path, "text": String::from_utf8_lossy(bytes)}),
                ),
            ),
            Backend::Direct(e) => Ok(serde_json::to_value(e.create_file(folder, path, bytes)?)?),
        }
    }
    fn analysis(&mut self, folder: &str, path: &str) -> Result<Value> {
        match self {
            Backend::Http { .. } => Ok(self.call_json(
                "GET",
                &format!(
                    "/api/analysis?folder={}&path={}",
                    urlencode(folder),
                    urlencode(path)
                ),
                None,
            )?["analysis"]
                .clone()),
            Backend::Direct(e) => Ok(serde_json::to_value(e.analysis(folder, path)?)?),
        }
    }
    fn set_analysis(
        &mut self,
        folder: &str,
        path: &str,
        text: &str,
        tags: &[String],
        by: Option<&str>,
    ) -> Result<Value> {
        match self {
            Backend::Http { .. } => self.call_json(
                "POST",
                "/api/analysis",
                Some(json!({"folder": folder, "path": path, "analysis": text, "tags": tags, "by": by})),
            ),
            Backend::Direct(e) => Ok(serde_json::to_value(
                e.set_analysis(folder, path, text, tags, by)?,
            )?),
        }
    }
    fn clear_analysis(&mut self, folder: &str, path: &str) -> Result<bool> {
        match self {
            Backend::Http { .. } => Ok(self.call_json(
                "POST",
                "/api/analysis/clear",
                Some(json!({"folder": folder, "path": path})),
            )?["cleared"]
                .as_bool()
                .unwrap_or(false)),
            Backend::Direct(e) => e.clear_analysis(folder, path),
        }
    }
    fn search(&mut self, folder: &str, query: &str, tags: &[String]) -> Result<Value> {
        match self {
            Backend::Http { .. } => self.call_json(
                "POST",
                "/api/analysis/search",
                Some(json!({"folder": folder, "query": query, "tags": tags})),
            ),
            Backend::Direct(e) => Ok(serde_json::to_value(
                e.search_analyses(folder, query, tags)?,
            )?),
        }
    }
    fn sync(&mut self, folder: Option<&str>) -> Result<Value> {
        match self {
            Backend::Http { .. } => {
                self.call_json("POST", "/api/sync", Some(json!({"folder": folder})))
            }
            Backend::Direct(e) => Ok(serde_json::to_value(
                e.sync(folder)?
                    .into_iter()
                    .map(|(pl, pu)| json!({"pull": pl, "push": pu}))
                    .collect::<Vec<_>>(),
            )?),
        }
    }
}

pub(crate) fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn tools() -> Value {
    json!([
        {"name": "varsto_status", "description": "Vault, devices, storages and folders of this device, with chunk and copy counts.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "varsto_folders", "description": "Folders the assistant may see, with the access level granted (ro: read only; analyse: read and record file analyses; rw: also move and create files) and local_path: the folder's directory on this device when its files are kept there as plain files.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "varsto_files", "description": "Files of a folder: path, size, state (local, placeholder, missing), modified_utc, last_accessed_utc (Varsto's own record), content hash, and local_path: where the file is on this device's disk when it is synced here as a plain file. Varsto does not hand out file contents: read a file from its local_path with your own file tools. A file without local_path is not on this device (a placeholder, or a folder kept encrypted here). A file that was analysed carries analysis (its first 500 characters; analysis_truncated when longer, varsto_get_analysis has it all), analysis_tags, analysis_utc, analysis_by and analysis_stale (the file changed since: analyse it again). with_analysis: false leaves the analyses out.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "with_analysis": {"type": "boolean", "default": true}}, "required": ["folder"]}},
        {"name": "varsto_set_analysis", "description": "Record what a file contains, after reading it from its local_path: a plain-text analysis (at most 16 KiB; say what the file is, its subject, people, places, dates, amounts, language, anything useful to find or file it later) with up to 32 short tags, and by: your model name. Replaces the file's earlier analysis. Varsto keeps it encrypted, shows it to the user and syncs it to the user's other devices; it follows the file when it is moved or renamed and is marked stale when the file changes. Needs an analyse or read-write grant.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "path": {"type": "string"}, "analysis": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}, "by": {"type": "string"}}, "required": ["folder", "path", "analysis"]}},
        {"name": "varsto_clear_analysis", "description": "Remove the analysis of a file (it was wrong or is no longer useful). Needs an analyse or read-write grant.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "path": {"type": "string"}}, "required": ["folder", "path"]}},
        {"name": "varsto_get_analysis", "description": "The full analysis of one file, with tags, author, by, analysed_utc and stale; null when it has none.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "path": {"type": "string"}}, "required": ["folder", "path"]}},
        {"name": "varsto_search_analyses", "description": "Find files by what they contain without reading them again: every word of query must occur (case-insensitive) in the file's analysis, its tags or its path, and the file must carry every tag in tags. Searches one folder or every granted folder; best matches first, each with folder, path, a snippet of the analysis, tags, stale and local_path. Use it to plan a reorganisation (then varsto_move).",
         "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "folder": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}, "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50}}}},
        {"name": "varsto_move", "description": "Move or rename a file inside a folder (needs a read-write grant); the change syncs to the other devices. Use it to reorganise: group by year, project or topic after reading the files. The target name must be free: a move never replaces another file.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "from": {"type": "string"}, "to": {"type": "string"}}, "required": ["folder", "from", "to"]}},
        {"name": "varsto_mkdir", "description": "Create a directory inside a folder (read-write grant).",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "path": {"type": "string"}}, "required": ["folder", "path"]}},
        {"name": "varsto_write", "description": "Create a new text file inside a folder (read-write grant), for example a summary, an index or notes about what you organised; the file syncs like any other. Existing files are never overwritten: pick a new name.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "path": {"type": "string"}, "text": {"type": "string"}}, "required": ["folder", "path", "text"]}},
        {"name": "varsto_sync", "description": "Sync one folder or all granted folders now.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}},
        {"name": "varsto_storage_advice", "description": "Varsto's own placement estimate, exposed for context: files idle for idle_days (default 90) and their monthly cost in every known storage class, cheapest first, with sources. Nothing is moved.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "idle_days": {"type": "integer", "minimum": 1}}}}
    ])
}

/// A folder's directory on this device when its files are kept there as
/// plain files (not "encrypted here", not a Strongroom).
fn plain_root(f: &Value) -> Option<std::path::PathBuf> {
    if !f["plain"].as_bool().unwrap_or(false) || f["strongroom"].as_bool().unwrap_or(false) {
        return None;
    }
    f["path"]
        .as_str()
        .filter(|p| !p.is_empty())
        .map(std::path::PathBuf::from)
}

/// The plain root of a folder by name (see `plain_root`).
fn folder_root(backend: &mut Backend, folder: &str) -> Result<Option<PathBuf>> {
    Ok(backend
        .folders()?
        .iter()
        .find(|f| f["name"].as_str() == Some(folder))
        .and_then(plain_root))
}

/// Only a synced plain file on this disk has a local path: the assistant
/// reads it itself; Varsto never hands out contents.
fn local_path(root: Option<&Path>, path: &Value, state: &Value) -> Option<String> {
    let p = root?.join(path.as_str()?);
    (state.as_str() == Some("local") && p.is_file()).then(|| p.display().to_string())
}

fn str_list(args: &Value, name: &str) -> Vec<String> {
    args.get(name)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn text_result(text: String) -> Value {
    json!({"content": [{"type": "text", "text": text}]})
}

fn error_result(msg: String) -> Value {
    json!({"content": [{"type": "text", "text": msg}], "isError": true})
}

fn arg<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing argument {name}"))
}

fn call_tool(backend: &mut Backend, grants: &Grants, name: &str, args: &Value) -> Result<Value> {
    // A grant on every folder never reaches a Strongroom: those need a
    // grant of their own, by name.
    let strongrooms: std::collections::BTreeSet<String> = backend
        .folders()?
        .iter()
        .filter(|f| f["strongroom"].as_bool().unwrap_or(false))
        .filter_map(|f| f["name"].as_str().map(|s| s.to_string()))
        .collect();
    let can_read = |folder: &str| -> bool {
        grants.can_read(folder) && (!strongrooms.contains(folder) || grants.explicit(folder))
    };
    let can_write = |folder: &str| -> bool {
        grants.can_write(folder) && (!strongrooms.contains(folder) || grants.explicit(folder))
    };
    let can_analyse = |folder: &str| -> bool {
        grants.can_analyse(folder) && (!strongrooms.contains(folder) || grants.explicit(folder))
    };
    let need_analyse = |folder: &str| -> Result<()> {
        if can_analyse(folder) {
            Ok(())
        } else {
            bail!("folder {folder} does not allow recording analyses: the user must run `varsto mcp grant {folder} --analyse`")
        }
    };
    let granted_folders = |b: &mut Backend| -> Result<Vec<String>> {
        let names: Vec<String> = b
            .folders()?
            .iter()
            .filter_map(|f| f["name"].as_str().map(|s| s.to_string()))
            .collect();
        Ok(names.into_iter().filter(|n| can_read(n)).collect())
    };
    let need_read = |folder: &str| -> Result<()> {
        if can_read(folder) {
            Ok(())
        } else {
            bail!(
                "no access to folder {folder}: the user must run `varsto mcp grant {folder}` first"
            )
        }
    };
    match name {
        "varsto_status" => {
            let mut st = backend.status()?;
            if let Some(folders) = st.get_mut("folders").and_then(|f| f.as_array_mut()) {
                folders.retain(|f| f["name"].as_str().is_some_and(can_read));
            }
            Ok(text_result(serde_json::to_string_pretty(&st)?))
        }
        "varsto_folders" => {
            let all = backend.folders()?;
            let visible: Vec<Value> = all
                .into_iter()
                .filter(|f| f["name"].as_str().is_some_and(can_read))
                .map(|mut f| {
                    let n = f["name"].as_str().unwrap_or("").to_string();
                    f["access"] = json!(if can_write(&n) {
                        "rw"
                    } else if can_analyse(&n) {
                        "analyse"
                    } else {
                        "ro"
                    });
                    f["local_path"] = json!(plain_root(&f));
                    f
                })
                .collect();
            Ok(text_result(serde_json::to_string_pretty(&visible)?))
        }
        "varsto_files" => {
            let folder = arg(args, "folder")?;
            need_read(folder)?;
            let with_analysis = args
                .get("with_analysis")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let root = folder_root(backend, folder)?;
            let mut files = backend.files(folder)?;
            if let Some(list) = files.as_array_mut() {
                for f in list {
                    let local = local_path(root.as_deref(), &f["path"], &f["state"]);
                    f["local_path"] = json!(local);
                    if let (false, Some(o)) = (with_analysis, f.as_object_mut()) {
                        o.retain(|k, _| !k.starts_with("analysis"));
                    }
                }
            }
            Ok(text_result(serde_json::to_string_pretty(&files)?))
        }
        "varsto_move" => {
            let (folder, from, to) = (arg(args, "folder")?, arg(args, "from")?, arg(args, "to")?);
            if !can_write(folder) {
                bail!("folder {folder} is read-only for the assistant: the user must run `varsto mcp grant {folder} --write`");
            }
            Ok(text_result(serde_json::to_string_pretty(
                &backend.move_file(folder, from, to)?,
            )?))
        }
        "varsto_set_analysis" => {
            let (folder, path, text) = (
                arg(args, "folder")?,
                arg(args, "path")?,
                arg(args, "analysis")?,
            );
            need_analyse(folder)?;
            let tags = str_list(args, "tags");
            let by = args.get("by").and_then(|v| v.as_str());
            Ok(text_result(serde_json::to_string_pretty(
                &backend.set_analysis(folder, path, text, &tags, by)?,
            )?))
        }
        "varsto_clear_analysis" => {
            let (folder, path) = (arg(args, "folder")?, arg(args, "path")?);
            need_analyse(folder)?;
            let cleared = backend.clear_analysis(folder, path)?;
            Ok(text_result(if cleared {
                format!("the analysis of {folder}/{path} was cleared")
            } else {
                format!("{folder}/{path} had no analysis")
            }))
        }
        "varsto_get_analysis" => {
            let (folder, path) = (arg(args, "folder")?, arg(args, "path")?);
            need_read(folder)?;
            Ok(text_result(serde_json::to_string_pretty(
                &backend.analysis(folder, path)?,
            )?))
        }
        "varsto_search_analyses" => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let tags = str_list(args, "tags");
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(50)
                .clamp(1, 500) as usize;
            let folders = match args.get("folder").and_then(|v| v.as_str()) {
                Some(f) => {
                    need_read(f)?;
                    vec![f.to_string()]
                }
                None => granted_folders(backend)?,
            };
            let mut hits: Vec<Value> = Vec::new();
            for f in &folders {
                let root = folder_root(backend, f)?;
                for mut h in backend
                    .search(f, query, &tags)?
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                {
                    let local = local_path(root.as_deref(), &h["path"], &h["state"]);
                    h["local_path"] = json!(local);
                    if let Some(o) = h.as_object_mut() {
                        o.remove("disk");
                    }
                    hits.push(h);
                }
            }
            hits.sort_by(|a, b| {
                b["score"]
                    .as_u64()
                    .cmp(&a["score"].as_u64())
                    .then_with(|| a["path"].as_str().cmp(&b["path"].as_str()))
            });
            let total = hits.len();
            hits.truncate(limit);
            Ok(text_result(serde_json::to_string_pretty(
                &json!({"total": total, "hits": hits}),
            )?))
        }
        "varsto_mkdir" => {
            let (folder, path) = (arg(args, "folder")?, arg(args, "path")?);
            if !can_write(folder) {
                bail!("folder {folder} is read-only for the assistant: the user must run `varsto mcp grant {folder} --write`");
            }
            backend.mkdir(folder, path)?;
            Ok(text_result(format!("created {folder}/{path}")))
        }
        "varsto_write" => {
            let (folder, path, text) =
                (arg(args, "folder")?, arg(args, "path")?, arg(args, "text")?);
            if !can_write(folder) {
                bail!("folder {folder} is read-only for the assistant: the user must run `varsto mcp grant {folder} --write`");
            }
            if text.len() > 2 * 1024 * 1024 {
                bail!("text larger than 2 MiB");
            }
            Ok(text_result(serde_json::to_string_pretty(&backend.write(
                folder,
                path,
                text.as_bytes(),
            )?)?))
        }
        "varsto_sync" => {
            let folder = args.get("folder").and_then(|v| v.as_str());
            if let Some(f) = folder {
                need_read(f)?;
                Ok(text_result(serde_json::to_string_pretty(
                    &backend.sync(Some(f))?,
                )?))
            } else {
                let mut out = Vec::new();
                for f in granted_folders(backend)? {
                    out.push(backend.sync(Some(&f))?);
                }
                Ok(text_result(serde_json::to_string_pretty(&out)?))
            }
        }
        "varsto_storage_advice" => {
            let idle_days = args.get("idle_days").and_then(|v| v.as_i64()).unwrap_or(90);
            let folders = match args.get("folder").and_then(|v| v.as_str()) {
                Some(f) => {
                    need_read(f)?;
                    vec![f.to_string()]
                }
                None => granted_folders(backend)?,
            };
            let mut files = Vec::new();
            for f in &folders {
                for e in backend.files(f)?.as_array().into_iter().flatten() {
                    files.push((
                        f.clone(),
                        e["path"].as_str().unwrap_or("").to_string(),
                        e["size"].as_u64().unwrap_or(0),
                        e["last_accessed_utc"].as_i64(),
                        e["modified_utc"].as_i64().unwrap_or(0),
                    ));
                }
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let advice = varsto_core::advice::storage_advice(&files, idle_days, now);
            Ok(text_result(serde_json::to_string_pretty(&advice)?))
        }
        other => bail!("unknown tool {other}"),
    }
}

/// Serve MCP over stdin/stdout until EOF.
pub fn serve(home: &Path) -> Result<()> {
    let grants = Grants::load(home)?;
    let mut backend: Option<Backend> = None;
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                writeln!(
                    out,
                    "{}",
                    json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("parse error: {e}")}})
                )?;
                out.flush()?;
                continue;
            }
        };
        let id = msg.get("id").cloned();
        let method = msg["method"].as_str().unwrap_or("").to_string();
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let result: Result<Value> = match method.as_str() {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "varsto", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Varsto keeps the user's files encrypted on their own storage. You see only the folders the user granted (varsto mcp grant): read-only, analyse (may also record file analyses) or rw (may also move and create files). Typical work: list files with varsto_files, read the ones without an analysis (or with analysis_stale) from their local_path with your own file tools, record what each contains with varsto_set_analysis (text, tags, by: your model name), and later find files by content with varsto_search_analyses instead of reading them again; propose and carry out a tidier structure with varsto_mkdir and varsto_move (analyses follow the files), and leave notes or indexes with varsto_write. Files are never deleted or replaced: there is no delete tool, varsto_write only creates new files and varsto_move only moves or renames to a free name. Paths are relative to the folder. last_accessed_utc is Varsto's own record of use on this device."
            })),
            "notifications/initialized" | "notifications/cancelled" => continue,
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params["name"].as_str().unwrap_or("").to_string();
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let b = match &mut backend {
                    Some(b) => Ok(b),
                    None => match Backend::open(home) {
                        Ok(b) => {
                            backend = Some(b);
                            Ok(backend.as_mut().unwrap())
                        }
                        Err(e) => Err(e),
                    },
                };
                match b {
                    Ok(b) => Ok(call_tool(b, &grants, &name, &args)
                        .unwrap_or_else(|e| error_result(e.to_string()))),
                    Err(e) => Ok(error_result(e.to_string())),
                }
            }
            _ => Err(anyhow!("method not found: {method}")),
        };
        if id.is_none() {
            continue; // notification
        }
        let response = match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err(e) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": e.to_string()}})
            }
        };
        writeln!(out, "{response}")?;
        out.flush()?;
    }
    Ok(())
}

/// Grant `folder` (or `all`): read-write with `write`, read and analyse
/// with `analyse`, read-only otherwise.
pub fn grant(home: &Path, folder: &str, write: bool, analyse: bool) -> Result<()> {
    let mut g = Grants::load(home)?;
    let level = if write {
        "rw"
    } else if analyse {
        "an"
    } else {
        "ro"
    }
    .to_string();
    if folder == "all" {
        g.all = Some(level);
    } else {
        g.folders.insert(folder.to_string(), level);
    }
    g.save(home)
}

pub fn revoke(home: &Path, folder: &str) -> Result<()> {
    let mut g = Grants::load(home)?;
    if folder == "all" {
        g.all = None;
        g.folders.clear();
    } else {
        g.folders.remove(folder);
    }
    g.save(home)
}

pub fn grants_path(home: &Path) -> PathBuf {
    home.join(Grants::FILE)
}
