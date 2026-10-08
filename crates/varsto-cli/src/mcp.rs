// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! MCP server (Model Context Protocol, JSON-RPC 2.0 over stdio) so that an AI
//! assistant can look at, organise and reason about the files in this vault
//! with exactly the access the user granted.
//!
//! Access is per folder: `varsto mcp grant <folder> [--write]` records a
//! read-only or read-write grant in `mcp-grants.json`; nothing is reachable
//! without a grant. When the background service is running, calls are routed
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
const MAX_READ: usize = 512 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Grants {
    /// "ro" or "rw" for every folder, or none.
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
    pub fn can_read(&self, folder: &str) -> bool {
        self.level(folder).is_some()
    }
    pub fn can_write(&self, folder: &str) -> bool {
        self.level(folder) == Some("rw")
    }
    fn readable<'a>(&self, names: impl Iterator<Item = &'a str>) -> Vec<String> {
        names
            .filter(|n| self.can_read(n))
            .map(|n| n.to_string())
            .collect()
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
                .map(|(r, m)| json!({"id": r.folder_id.to_string(), "name": r.name, "path": m, "strongroom": r.is_strongroom()}))
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
    fn read(&mut self, folder: &str, path: &str) -> Result<Vec<u8>> {
        match self {
            Backend::Http { token, .. } => {
                let token = token.clone();
                let (status, bytes) = self.http(
                    "GET",
                    &format!(
                        "/api/open?folder={}&path={}&token={}",
                        urlencode(folder),
                        urlencode(path),
                        token
                    ),
                    None,
                )?;
                if status != 200 {
                    bail!("{}", String::from_utf8_lossy(&bytes));
                }
                Ok(bytes)
            }
            Backend::Direct(e) => e.read_file(folder, path),
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
            Backend::Direct(e) => Ok(serde_json::to_value(e.write_file(folder, path, bytes)?)?),
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

fn urlencode(s: &str) -> String {
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
        {"name": "varsto_folders", "description": "Folders the assistant may see, with the access level granted (ro or rw).",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "varsto_files", "description": "Files of a folder: path, size, state (local, placeholder, missing), modified_utc, last_accessed_utc (Varsto's own record), content hash.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}, "required": ["folder"]}},
        {"name": "varsto_read", "description": "Read a file (text, up to 512 KiB; fetched first if it is a placeholder). Counts as an access.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "path": {"type": "string"}}, "required": ["folder", "path"]}},
        {"name": "varsto_move", "description": "Move or rename a file inside a folder (needs a read-write grant); the change syncs to the other devices. Use it to reorganise: group by year, project or topic after reading the files.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "from": {"type": "string"}, "to": {"type": "string"}}, "required": ["folder", "from", "to"]}},
        {"name": "varsto_mkdir", "description": "Create a directory inside a folder (read-write grant).",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "path": {"type": "string"}}, "required": ["folder", "path"]}},
        {"name": "varsto_write", "description": "Create or overwrite a text file inside a folder (read-write grant), for example a summary, an index or notes about what you organised; the file syncs like any other.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "path": {"type": "string"}, "text": {"type": "string"}}, "required": ["folder", "path", "text"]}},
        {"name": "varsto_sync", "description": "Sync one folder or all granted folders now.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}},
        {"name": "varsto_storage_advice", "description": "Varsto's own placement estimate, exposed for context: files idle for idle_days (default 90) and their monthly cost in every known storage class, cheapest first, with sources. Nothing is moved.",
         "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}, "idle_days": {"type": "integer", "minimum": 1}}}}
    ])
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
    let granted_folders = |b: &mut Backend| -> Result<Vec<String>> {
        let names: Vec<String> = b
            .folders()?
            .iter()
            .filter_map(|f| f["name"].as_str().map(|s| s.to_string()))
            .collect();
        Ok(grants.readable(names.iter().map(|s| s.as_str())))
    };
    let need_read = |folder: &str| -> Result<()> {
        if grants.can_read(folder) {
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
                folders.retain(|f| f["name"].as_str().is_some_and(|n| grants.can_read(n)));
            }
            Ok(text_result(serde_json::to_string_pretty(&st)?))
        }
        "varsto_folders" => {
            let all = backend.folders()?;
            let visible: Vec<Value> = all
                .into_iter()
                .filter(|f| f["name"].as_str().is_some_and(|n| grants.can_read(n)))
                .map(|mut f| {
                    let n = f["name"].as_str().unwrap_or("").to_string();
                    f["access"] = json!(if grants.can_write(&n) { "rw" } else { "ro" });
                    f
                })
                .collect();
            Ok(text_result(serde_json::to_string_pretty(&visible)?))
        }
        "varsto_files" => {
            let folder = arg(args, "folder")?;
            need_read(folder)?;
            Ok(text_result(serde_json::to_string_pretty(
                &backend.files(folder)?,
            )?))
        }
        "varsto_read" => {
            let (folder, path) = (arg(args, "folder")?, arg(args, "path")?);
            need_read(folder)?;
            let bytes = backend.read(folder, path)?;
            let truncated = bytes.len() > MAX_READ;
            let slice = &bytes[..bytes.len().min(MAX_READ)];
            match std::str::from_utf8(slice) {
                Ok(t) => Ok(text_result(if truncated {
                    format!("{t}\n[truncated at {MAX_READ} bytes]")
                } else {
                    t.to_string()
                })),
                Err(_) => Ok(text_result(format!(
                    "binary file, {} bytes; not shown",
                    bytes.len()
                ))),
            }
        }
        "varsto_move" => {
            let (folder, from, to) = (arg(args, "folder")?, arg(args, "from")?, arg(args, "to")?);
            if !grants.can_write(folder) {
                bail!("folder {folder} is read-only for the assistant: the user must run `varsto mcp grant {folder} --write`");
            }
            Ok(text_result(serde_json::to_string_pretty(
                &backend.move_file(folder, from, to)?,
            )?))
        }
        "varsto_mkdir" => {
            let (folder, path) = (arg(args, "folder")?, arg(args, "path")?);
            if !grants.can_write(folder) {
                bail!("folder {folder} is read-only for the assistant: the user must run `varsto mcp grant {folder} --write`");
            }
            backend.mkdir(folder, path)?;
            Ok(text_result(format!("created {folder}/{path}")))
        }
        "varsto_write" => {
            let (folder, path, text) =
                (arg(args, "folder")?, arg(args, "path")?, arg(args, "text")?);
            if !grants.can_write(folder) {
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
                "instructions": "Varsto keeps the user's files encrypted on their own storage. You see only the folders the user granted (varsto mcp grant), read-only unless the grant says rw. Typical work: read files, analyse and summarise them, propose and carry out a tidier structure with varsto_mkdir and varsto_move, and leave notes or indexes with varsto_write. Paths are relative to the folder. last_accessed_utc is Varsto's own record of use on this device."
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

pub fn grant(home: &Path, folder: &str, write: bool) -> Result<()> {
    let mut g = Grants::load(home)?;
    let level = if write { "rw" } else { "ro" }.to_string();
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
