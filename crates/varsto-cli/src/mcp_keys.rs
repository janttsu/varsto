// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Scoped keys for the MCP server (`docs/mcp.md`, spec section 37).
//!
//! `varsto mcp key create` makes a key (`vmk_` and 64 hex characters, 32
//! random bytes) and prints it once. Only its BLAKE3 hash is kept, in
//! `<home>/mcp-keys.json` (owner-readable only), with a name, a scope (the
//! same shape as the grants file: a level per folder and/or for every
//! folder), the creation time, an optional expiry and the last use. The MCP
//! server given a key (`varsto mcp --key`, `VARSTO_MCP_KEY`) talks to the
//! running service with it in `X-Varsto-Mcp-Key` instead of the session
//! token, and the service answers only the routes the MCP tools need, only
//! within the key's folders and levels. A key never opens the vault itself:
//! without the service it is refused.

use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const FILE: &str = "mcp-keys.json";
/// The request header that carries a key.
pub const HEADER: &str = "X-Varsto-Mcp-Key";
pub const PREFIX: &str = "vmk_";
/// Least time between two writes of a key's last use.
const TOUCH_SECS: i64 = 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpKey {
    pub id: String,
    pub name: String,
    /// BLAKE3 of "varsto-mcp-key", a zero byte and the key, in hex.
    hash: String,
    pub scope: Grants,
    pub created_utc: i64,
    #[serde(default)]
    pub expires_utc: Option<i64>,
    #[serde(default)]
    pub last_used_utc: Option<i64>,
}

impl McpKey {
    pub fn expired(&self, now: i64) -> bool {
        self.expires_utc.is_some_and(|e| now >= e)
    }
    /// The key as shown in lists: no hash.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "scope": self.scope,
            "created_utc": self.created_utc,
            "expires_utc": self.expires_utc,
            "last_used_utc": self.last_used_utc,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct KeyFile {
    #[serde(default)]
    keys: Vec<McpKey>,
}

fn path(home: &Path) -> PathBuf {
    home.join(FILE)
}

fn load(home: &Path) -> Result<KeyFile> {
    varsto_core::util::read_json_or_default(&path(home))
}

fn save(home: &Path, f: &KeyFile) -> Result<()> {
    std::fs::create_dir_all(home)?;
    let p = path(home);
    varsto_core::util::write_atomic(&p, &serde_json::to_vec_pretty(f)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn digest(key: &str) -> String {
    let mut b = b"varsto-mcp-key\0".to_vec();
    b.extend_from_slice(key.trim().as_bytes());
    hex::encode(varsto_core::crypto::hash(&b))
}

/// The scope of a new key: `folders` ("all" or names) at the level the
/// flags give, or a copy of the current grants when no folders are named.
pub fn scope_for(home: &Path, folders: &[String], write: bool, analyse: bool) -> Result<Grants> {
    if folders.is_empty() {
        if write || analyse {
            bail!("--write and --analyse need --folders (without it the key takes the current grants)");
        }
        let g = Grants::load(home)?;
        if g.all.is_none() && g.folders.is_empty() {
            bail!("there are no grants to copy: name the folders with --folders a,b (or all), or grant them first with varsto mcp grant");
        }
        return Ok(g);
    }
    let level = if write {
        "rw"
    } else if analyse {
        "an"
    } else {
        "ro"
    };
    let mut g = Grants::default();
    for f in folders.iter().map(|f| f.trim()).filter(|f| !f.is_empty()) {
        if f == "all" {
            g.all = Some(level.into());
        } else {
            g.folders.insert(f.to_string(), level.into());
        }
    }
    Ok(g)
}

/// Make a key; returns it with the secret, which is shown only now.
pub fn create(
    home: &Path,
    name: Option<&str>,
    scope: Grants,
    expires_days: Option<i64>,
) -> Result<(McpKey, String)> {
    let mut f = load(home)?;
    let mut idb = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut idb);
    let id = hex::encode(idb);
    let name = match name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None => format!("key-{id}"),
    };
    if f.keys.iter().any(|k| k.name == name) {
        bail!("a key named {name} exists; revoke it first or choose another name");
    }
    if let Some(d) = expires_days {
        if d < 1 {
            bail!("--expires-days must be at least 1");
        }
    }
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let key = format!("{PREFIX}{}", hex::encode(secret));
    let now = varsto_core::util::now_utc();
    let k = McpKey {
        id,
        name,
        hash: digest(&key),
        scope,
        created_utc: now,
        expires_utc: expires_days.map(|d| now + d * 86_400),
        last_used_utc: None,
    };
    f.keys.push(k.clone());
    save(home, &f)?;
    Ok((k, key))
}

pub fn list(home: &Path) -> Result<Vec<McpKey>> {
    Ok(load(home)?.keys)
}

/// Remove a key by name or id.
pub fn revoke(home: &Path, name_or_id: &str) -> Result<McpKey> {
    let mut f = load(home)?;
    let i = f
        .keys
        .iter()
        .position(|k| k.name == name_or_id || k.id == name_or_id)
        .ok_or_else(|| anyhow!("no MCP key named {name_or_id}"))?;
    let k = f.keys.remove(i);
    save(home, &f)?;
    Ok(k)
}

/// Why a key was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Unknown,
    Expired,
}

/// The key a request carries, checked; its last use is recorded (at most
/// once a minute).
pub fn check(home: &Path, key: &str) -> std::result::Result<McpKey, Refused> {
    if !key.trim().starts_with(PREFIX) {
        return Err(Refused::Unknown);
    }
    let mut f = load(home).map_err(|_| Refused::Unknown)?;
    let h = digest(key);
    let now = varsto_core::util::now_utc();
    let Some(k) = f.keys.iter_mut().find(|k| k.hash == h) else {
        return Err(Refused::Unknown);
    };
    if k.expired(now) {
        return Err(Refused::Expired);
    }
    let out = k.clone();
    if k.last_used_utc.is_none_or(|t| now - t >= TOUCH_SECS) {
        k.last_used_utc = Some(now);
        let _ = save(home, &f);
    }
    Ok(out)
}

/// What a route needs of a key's scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    Read,
    Analyse,
    Write,
}

/// The routes an MCP key may use: `None` for every other route (403);
/// otherwise what it needs and the folder it touches (`None`: the answer
/// is filtered to the key's folders instead).
pub fn route(
    method: &str,
    path: &str,
    query_folder: Option<String>,
    body_folder: Option<String>,
) -> Option<(Need, Option<String>)> {
    Some(match (method, path) {
        ("GET", "/api/mcp/scope") | ("GET", "/api/status") | ("GET", "/api/folders") => {
            (Need::Read, None)
        }
        ("GET", "/api/files") | ("GET", "/api/analysis") | ("GET", "/api/analyses") => {
            (Need::Read, Some(query_folder?))
        }
        ("POST", "/api/analysis/search") | ("POST", "/api/sync") => {
            (Need::Read, Some(body_folder?))
        }
        ("POST", "/api/analysis") | ("POST", "/api/analysis/clear") => {
            (Need::Analyse, Some(body_folder?))
        }
        ("POST", "/api/move") | ("POST", "/api/mkdir") | ("POST", "/api/write") => {
            (Need::Write, Some(body_folder?))
        }
        _ => return None,
    })
}

/// Whether a scope allows `need` on `folder`; a scope on every folder never
/// covers a Strongroom (it needs its own line).
pub fn allows(scope: &Grants, folder: &str, strongroom: bool, need: Need) -> bool {
    if strongroom && !scope.explicit(folder) {
        return false;
    }
    match need {
        Need::Read => scope.can_read(folder),
        Need::Analyse => scope.can_analyse(folder),
        Need::Write => scope.can_write(folder),
    }
}

/// Folder grants for assistants (`varsto mcp grant`), `mcp-grants.json`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_created_checked_listed_and_revoked() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let scope = scope_for(home, &["docs".into()], false, true).unwrap();
        assert_eq!(scope.folders["docs"], "an");
        let (k, secret) = create(home, Some("llm"), scope, Some(30)).unwrap();
        assert!(secret.starts_with(PREFIX) && secret.len() == PREFIX.len() + 64);
        // Only the hash is kept.
        let raw = std::fs::read_to_string(home.join(FILE)).unwrap();
        assert!(!raw.contains(&secret[PREFIX.len()..]));
        assert!(create(home, Some("llm"), Grants::default(), None).is_err());
        let got = check(home, &secret).unwrap();
        assert_eq!(got.id, k.id);
        assert!(list(home).unwrap()[0].last_used_utc.is_some());
        assert_eq!(check(home, "vmk_00").unwrap_err(), Refused::Unknown);
        assert_eq!(check(home, "nonsense").unwrap_err(), Refused::Unknown);
        revoke(home, "llm").unwrap();
        assert_eq!(check(home, &secret).unwrap_err(), Refused::Unknown);
        assert!(revoke(home, "llm").is_err());
        // No grants to copy.
        assert!(scope_for(home, &[], false, false).is_err());
        assert!(create(home, None, Grants::default(), Some(0)).is_err());
    }

    #[test]
    fn routes_and_scopes() {
        let mut g = Grants::default();
        g.folders.insert("docs".into(), "an".into());
        g.all = Some("ro".into());
        let f = |s: &str| Some(s.to_string());
        assert_eq!(
            route("GET", "/api/files", f("docs"), None),
            Some((Need::Read, f("docs")))
        );
        assert_eq!(route("GET", "/api/files", None, None), None);
        assert_eq!(route("GET", "/api/devices", None, None), None);
        assert_eq!(route("POST", "/api/storage", None, f("x")), None);
        assert_eq!(
            route("POST", "/api/move", None, f("docs")),
            Some((Need::Write, f("docs")))
        );
        assert!(allows(&g, "docs", false, Need::Analyse));
        assert!(!allows(&g, "docs", false, Need::Write));
        assert!(allows(&g, "other", false, Need::Read));
        assert!(!allows(&g, "other", false, Need::Analyse));
        assert!(
            !allows(&g, "vault", true, Need::Read),
            "all never covers a Strongroom"
        );
        assert!(allows(&g, "docs", true, Need::Read));
    }
}
