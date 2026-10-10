// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Self-update from the project download page, with signed releases.
//!
//! `varsto update` fetches `manifest.json`, `SHA256SUMS` and its detached
//! signature `SHA256SUMS.sig`, and refuses to go on unless the signature
//! verifies against the release public key built into this binary
//! (`release-key.pub` at the root of the repository). The signature is in
//! minisign's format: Ed25519 over the BLAKE2b-512 hash of the file, plus a
//! signed "trusted comment" that names the version. As a second channel, the
//! checksum list attached to the GitHub release of that version is compared
//! too, when GitHub can be reached; a different checksum there stops the
//! update, an unreachable GitHub does not (the signature alone suffices).
//! Then the archive for this platform is downloaded, its SHA-256 checked
//! against the signed list, and the running binary replaced. Downloads use
//! the system `curl` so that the binary carries no TLS stack of its own.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use blake2::Blake2b512;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// The download site; the one place to change it (or override with
/// `VARSTO_UPDATE_URL`, e.g. for a mirror; the signature check stays). The old
/// address, varsto.soderlund.in, keeps serving /downloads/ for old clients.
pub const DEFAULT_SITE: &str = "https://varsto.net";
pub const SITE_ENV: &str = "VARSTO_UPDATE_URL";
/// Second channel: the checksum list attached to each GitHub release.
pub const GITHUB_RELEASES: &str = "https://github.com/janttsu/varsto/releases/download";
/// The release public key (minisign format), also on the download page.
pub const RELEASE_KEY: &str = include_str!("../../../release-key.pub");

/// The download site without a trailing slash.
pub fn site() -> String {
    std::env::var(SITE_ENV)
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SITE.to_string())
}

/// `<site>/downloads/`, where archives, the manifest and the checksums live.
pub fn downloads_base() -> String {
    format!("{}/downloads/", site())
}

pub fn target_triple() -> &'static str {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-musl"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-gnu"
    } else {
        "unsupported"
    }
}

// ----- release signatures (minisign format) ------------------------------------

/// A release public key: minisign's "Ed" || key id (8 bytes) || Ed25519 key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub id: [u8; 8],
    key: VerifyingKey,
}

impl PublicKey {
    /// The key id the way minisign shows it (a little-endian number in hex).
    pub fn id_hex(&self) -> String {
        format!("{:016X}", u64::from_le_bytes(self.id))
    }
}

/// The key built into this binary.
pub fn release_key() -> PublicKey {
    parse_public_key(RELEASE_KEY).expect("release-key.pub is a valid public key")
}

fn b64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow!("bad base64: {e}"))
}

/// Parse a public key file (an optional "untrusted comment:" line, then the key).
pub fn parse_public_key(text: &str) -> Result<PublicKey> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .ok_or_else(|| anyhow!("empty public key"))?;
    let raw = b64(line)?;
    if raw.len() != 42 || &raw[..2] != b"Ed" {
        bail!("not an Ed25519 public key in minisign format");
    }
    let key = VerifyingKey::from_bytes(raw[10..42].try_into().unwrap())?;
    Ok(PublicKey {
        id: raw[2..10].try_into().unwrap(),
        key,
    })
}

/// A detached signature file.
struct SigFile {
    prehashed: bool,
    id: [u8; 8],
    sig: Signature,
    trusted: String,
    global: Signature,
}

fn parse_signature(text: &str) -> Result<SigFile> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 4 || !lines[0].starts_with("untrusted comment:") {
        bail!("not a signature file");
    }
    let raw = b64(lines[1])?;
    if raw.len() != 74 {
        bail!("malformed signature");
    }
    let prehashed = match &raw[..2] {
        b"ED" => true,
        b"Ed" => false,
        _ => bail!("unknown signature algorithm"),
    };
    let trusted = lines[2]
        .strip_prefix("trusted comment: ")
        .ok_or_else(|| anyhow!("signature has no trusted comment"))?
        .to_string();
    let global = b64(lines[3])?;
    Ok(SigFile {
        prehashed,
        id: raw[2..10].try_into().unwrap(),
        sig: Signature::from_bytes(raw[10..74].try_into().unwrap()),
        trusted,
        global: Signature::from_bytes(
            global
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("malformed trusted comment signature"))?,
        ),
    })
}

/// Verify `data` against a detached minisign signature. Returns the signed
/// trusted comment ("timestamp:… file:… version:…").
pub fn verify_signature(key: &PublicKey, data: &[u8], sig_text: &str) -> Result<String> {
    let s = parse_signature(sig_text)?;
    if s.id != key.id {
        bail!(
            "signed with key {:016X}, not the release key {}",
            u64::from_le_bytes(s.id),
            key.id_hex()
        );
    }
    let message = if s.prehashed {
        Blake2b512::digest(data).to_vec()
    } else {
        data.to_vec()
    };
    key.key.verify_strict(&message, &s.sig).map_err(|_| {
        anyhow!("bad signature: the file was changed or not signed by the release key")
    })?;
    let mut global = s.sig.to_bytes().to_vec();
    global.extend_from_slice(s.trusted.as_bytes());
    key.key
        .verify_strict(&global, &s.global)
        .map_err(|_| anyhow!("bad signature on the trusted comment"))?;
    Ok(s.trusted)
}

/// A field of the trusted comment ("version" in "…\tversion:0.0.1").
pub fn trusted_field<'a>(trusted: &'a str, name: &str) -> Option<&'a str> {
    trusted
        .split(['\t', ' '])
        .find_map(|f| f.strip_prefix(name)?.strip_prefix(':'))
}

/// The SHA-256 listed for `name` in a SHA256SUMS text.
pub fn listed_hash(sums: &str, name: &str) -> Option<String> {
    sums.lines()
        .filter_map(|l| l.split_once("  ").or_else(|| l.split_once(" *")))
        .find(|(_, n)| n.trim() == name)
        .map(|(h, _)| h.trim().to_lowercase())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

// ----- downloads ------------------------------------------------------------------

/// How releases are fetched; tests substitute their own.
pub trait Fetch {
    /// GET a small file into memory.
    fn get(&self, url: &str) -> Result<Vec<u8>>;
    /// GET a small file from the second channel, which may be unreachable.
    fn get_second(&self, url: &str) -> Result<Vec<u8>> {
        self.get(url)
    }
    /// GET a file to disk.
    fn download(&self, url: &str, dest: &Path) -> Result<()>;
}

/// The system `curl`.
pub struct Curl;

fn curl(max_time: &str, args: &[&str]) -> Result<Vec<u8>> {
    let out = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            max_time,
            "-A",
            &format!("varsto/{}", env!("CARGO_PKG_VERSION")),
        ])
        .args(args)
        .output()
        .context("curl is required for updates (install it or download by hand)")?;
    if !out.status.success() {
        bail!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

impl Fetch for Curl {
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        curl("120", &[url])
    }
    fn get_second(&self, url: &str) -> Result<Vec<u8>> {
        curl("30", &[url])
    }
    fn download(&self, url: &str, dest: &Path) -> Result<()> {
        curl("600", &["-o", &dest.display().to_string(), url]).map(|_| ())
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Check {
    pub current: String,
    pub latest: String,
    /// A newer version exists and this binary can install it itself.
    pub available: bool,
    /// A newer version exists (also where it has to be installed by hand,
    /// such as the macOS disk image or the Android APK).
    pub newer: bool,
    /// Where to download it by hand.
    pub download_page: String,
    pub archive: Option<String>,
    pub target: String,
}

/// Parse "0.0.1-alpha.3" into a comparable tuple.
fn version_key(v: &str) -> (u64, u64, u64, u8, u64) {
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let mut nums = core.split('.').map(|x| x.parse::<u64>().unwrap_or(0));
    let (a, b, c) = (
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
    );
    // No pre-release ranks above any pre-release; alpha < beta < rc.
    let (tag, n) = if pre.is_empty() {
        (9, 0)
    } else {
        let (t, n) = pre.split_once('.').unwrap_or((pre, "0"));
        let rank = match t {
            "alpha" => 1,
            "beta" => 2,
            "rc" => 3,
            _ => 0,
        };
        (rank, n.parse().unwrap_or(0))
    };
    (a, b, c, tag, n)
}

pub fn check() -> Result<Check> {
    check_with(&Curl, &downloads_base())
}

fn check_with(fetch: &dyn Fetch, base: &str) -> Result<Check> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fetch.get(&format!("{base}manifest.json"))?)?;
    let latest = manifest
        .get("_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("manifest has no version"))?
        .to_string();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let target = target_triple().to_string();
    let archive = manifest.as_object().and_then(|m| {
        m.keys()
            .find(|k| k.contains(&target) && (k.ends_with(".tar.gz") || k.ends_with(".zip")))
            .cloned()
    });
    let newer = version_key(&latest) > version_key(&current);
    Ok(Check {
        available: newer && archive.is_some(),
        newer,
        download_page: base.to_string(),
        current,
        latest,
        archive,
        target,
    })
}

/// A downloaded archive whose checksum the signed list vouches for.
#[derive(Debug)]
pub struct Verified {
    pub path: PathBuf,
    /// What was checked, for the message to the user.
    pub notes: Vec<String>,
}

/// Fetch and check the signed checksum list (and the GitHub copy when
/// reachable), then download the archive into `dir` and check its SHA-256.
/// Nothing is installed here; every refusal is an error.
pub fn download_verified(
    fetch: &dyn Fetch,
    base: &str,
    key: &PublicKey,
    check: &Check,
    dir: &Path,
) -> Result<Verified> {
    let archive = check
        .archive
        .clone()
        .ok_or_else(|| anyhow!("no archive for {}", check.target))?;
    if !archive.starts_with(&format!("varsto-{}-", check.latest)) || archive.contains(['/', '\\']) {
        bail!("the manifest names an unexpected archive {archive}; refusing to update");
    }
    let sums = fetch.get(&format!("{base}SHA256SUMS"))?;
    let sig = fetch
        .get(&format!("{base}SHA256SUMS.sig"))
        .context("the release is not signed (no SHA256SUMS.sig); refusing to update")?;
    let trusted = verify_signature(key, &sums, &String::from_utf8_lossy(&sig))
        .context("SHA256SUMS does not carry a valid release signature; refusing to update")?;
    match trusted_field(&trusted, "version") {
        Some(v) if v == check.latest => {}
        other => bail!(
            "the signed checksum list is for version {}, not {}; refusing to update",
            other.unwrap_or("(none)"),
            check.latest
        ),
    }
    let sums = String::from_utf8(sums).context("SHA256SUMS is not text")?;
    let expected = listed_hash(&sums, &archive)
        .ok_or_else(|| anyhow!("{archive} is not listed in the signed SHA256SUMS"))?;
    let mut notes = vec![format!("signature verified (release key {})", key.id_hex())];
    let github = format!("{GITHUB_RELEASES}/v{}/SHA256SUMS", check.latest);
    match fetch.get_second(&github) {
        Ok(text) => match listed_hash(&String::from_utf8_lossy(&text), &archive) {
            Some(h) if h == expected => notes.push("checksum matches the GitHub release".into()),
            Some(h) => bail!(
                "the GitHub release lists {archive} with checksum {h}, the download site with {expected}; refusing to update"
            ),
            None => bail!(
                "the GitHub release of {} does not list {archive}; refusing to update",
                check.latest
            ),
        },
        Err(_) => notes.push("GitHub release not reachable; the signature alone was checked".into()),
    }
    let path = dir.join(&archive);
    fetch.download(&format!("{base}{archive}"), &path)?;
    let actual = sha256_file(&path)?;
    if actual != expected {
        bail!("checksum mismatch for {archive}: expected {expected}, got {actual}");
    }
    Ok(Verified { path, notes })
}

/// Download, verify and install the latest release over the running binary.
/// Returns a human-readable message. The caller restarts the service.
pub fn apply(check: &Check) -> Result<String> {
    if !check.available {
        return Ok(format!("already up to date ({})", check.current));
    }
    let tmp = tempdir()?;
    let result = install_from(check, &tmp);
    let _ = fs::remove_dir_all(&tmp);
    result
}

fn install_from(check: &Check, tmp: &Path) -> Result<String> {
    let v = download_verified(&Curl, &downloads_base(), &release_key(), check, tmp)?;
    let extract = tmp.join("x");
    fs::create_dir_all(&extract)?;
    let tar = std::process::Command::new("tar")
        .args([
            "-xf",
            &v.path.display().to_string(),
            "-C",
            &extract.display().to_string(),
        ])
        .output()
        .context("tar is required to unpack the update")?;
    if !tar.status.success() {
        bail!(
            "unpack failed: {}",
            String::from_utf8_lossy(&tar.stderr).trim()
        );
    }
    let bin_name = if cfg!(windows) {
        "varsto.exe"
    } else {
        "varsto"
    };
    let new_bin = walkdir::WalkDir::new(&extract)
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().is_file() && e.file_name() == bin_name)
        .map(|e| e.into_path())
        .ok_or_else(|| anyhow!("archive does not contain {bin_name}"))?;
    let exe = std::env::current_exe()?;
    replace_binary(&new_bin, &exe)?;
    Ok(format!(
        "updated {} -> {} ({}; {}); restart the service or app to use it",
        check.current,
        check.latest,
        exe.display(),
        v.notes.join("; ")
    ))
}

fn replace_binary(new_bin: &Path, exe: &Path) -> Result<()> {
    let staged = exe.with_extension("new");
    fs::copy(new_bin, &staged)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
        fs::rename(&staged, exe)?;
    }
    #[cfg(windows)]
    {
        // A running executable cannot be overwritten but can be renamed.
        let old = exe.with_extension("old");
        let _ = fs::remove_file(&old);
        fs::rename(exe, &old)?;
        if let Err(e) = fs::rename(&staged, exe) {
            let _ = fs::rename(&old, exe);
            return Err(e.into());
        }
    }
    Ok(())
}

fn tempdir() -> Result<PathBuf> {
    let base = std::env::temp_dir().join(format!("varsto-update-{}", std::process::id()));
    fs::create_dir_all(&base)?;
    Ok(base)
}

// ----- verify-release ---------------------------------------------------------------

/// What `varsto verify-release` found.
#[derive(Serialize, Debug)]
pub struct Report {
    pub file: String,
    pub sha256: Option<String>,
    pub key_id: String,
    pub signed: String,
    pub github: Option<bool>,
}

/// Check a downloaded file by hand: the signature on SHA256SUMS (next to the
/// file, given explicitly, or fetched from the download site), then the
/// file's SHA-256 against it; with `github`, also against the GitHub release.
pub fn verify_release(
    file: &Path,
    sums: Option<&Path>,
    sig: Option<&Path>,
    github: bool,
) -> Result<Report> {
    let key = release_key();
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("{} is not a file name", file.display()))?
        .to_string();
    let sibling = |n: &str| file.parent().unwrap_or(Path::new(".")).join(n);
    let (sums_path, sums_text) = if name == "SHA256SUMS" {
        (file.to_path_buf(), None)
    } else {
        match sums {
            Some(p) => (p.to_path_buf(), None),
            None if sibling("SHA256SUMS").exists() => (sibling("SHA256SUMS"), None),
            None => {
                let base = downloads_base();
                (
                    PathBuf::from(format!("{base}SHA256SUMS")),
                    Some((
                        Curl.get(&format!("{base}SHA256SUMS"))?,
                        Curl.get(&format!("{base}SHA256SUMS.sig"))?,
                    )),
                )
            }
        }
    };
    let (sums_bytes, sig_bytes) = match sums_text {
        Some(t) => t,
        None => {
            let sig_path = sig
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(format!("{}.sig", sums_path.display())));
            (
                fs::read(&sums_path).with_context(|| format!("read {}", sums_path.display()))?,
                fs::read(&sig_path).with_context(|| {
                    format!(
                        "read {} (download it next to SHA256SUMS)",
                        sig_path.display()
                    )
                })?,
            )
        }
    };
    let trusted = verify_signature(&key, &sums_bytes, &String::from_utf8_lossy(&sig_bytes))
        .with_context(|| format!("{}", sums_path.display()))?;
    let mut report = Report {
        file: file.display().to_string(),
        sha256: None,
        key_id: key.id_hex(),
        signed: trusted.clone(),
        github: None,
    };
    if name == "SHA256SUMS" {
        return Ok(report);
    }
    let sums_text = String::from_utf8_lossy(&sums_bytes);
    let expected = listed_hash(&sums_text, &name)
        .ok_or_else(|| anyhow!("{name} is not listed in the signed SHA256SUMS"))?;
    let actual = sha256_file(file)?;
    if actual != expected {
        bail!("{name} does NOT match the signed checksum: expected {expected}, got {actual}");
    }
    report.sha256 = Some(actual.clone());
    if github {
        let version = trusted_field(&trusted, "version")
            .ok_or_else(|| anyhow!("the signature names no version"))?;
        let text = Curl
            .get_second(&format!("{GITHUB_RELEASES}/v{version}/SHA256SUMS"))
            .context("the GitHub release has no SHA256SUMS or cannot be reached")?;
        match listed_hash(&String::from_utf8_lossy(&text), &name) {
            Some(h) if h == actual => report.github = Some(true),
            Some(h) => bail!("the GitHub release lists {name} with checksum {h}, not {actual}"),
            None => bail!("the GitHub release of {version} does not list {name}"),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[test]
    fn versions_order() {
        assert!(version_key("0.0.1-alpha.2") > version_key("0.0.1-alpha.1"));
        assert!(version_key("0.0.1-beta.1") > version_key("0.0.1-alpha.9"));
        assert!(version_key("0.0.1") > version_key("0.0.1-rc.1"));
        assert!(version_key("0.1.0-alpha.1") > version_key("0.0.9"));
    }

    const ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn test_key(seed: u8) -> (SigningKey, PublicKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let mut raw = b"Ed".to_vec();
        raw.extend_from_slice(&ID);
        raw.extend_from_slice(sk.verifying_key().as_bytes());
        let text = format!(
            "untrusted comment: minisign public key\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(raw)
        );
        (sk, parse_public_key(&text).unwrap())
    }

    /// What scripts/sign-release.sh writes.
    fn sign(sk: &SigningKey, data: &[u8], trusted: &str) -> String {
        let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let sig = sk.sign(&Blake2b512::digest(data));
        let mut raw = b"ED".to_vec();
        raw.extend_from_slice(&ID);
        raw.extend_from_slice(&sig.to_bytes());
        let mut global = sig.to_bytes().to_vec();
        global.extend_from_slice(trusted.as_bytes());
        format!(
            "untrusted comment: test\n{}\ntrusted comment: {trusted}\n{}\n",
            enc(&raw),
            enc(&sk.sign(&global).to_bytes())
        )
    }

    #[test]
    fn embedded_release_key_parses() {
        let k = release_key();
        assert_eq!(k.id_hex().len(), 16);
    }

    #[test]
    fn signature_accepts_right_key_rejects_tampering_and_wrong_key() {
        let (sk, pk) = test_key(7);
        let data = b"abc  varsto-1-x.tar.gz\n";
        let sig = sign(&sk, data, "timestamp:1\tfile:SHA256SUMS\tversion:9.9.9");
        let t = verify_signature(&pk, data, &sig).unwrap();
        assert_eq!(trusted_field(&t, "version"), Some("9.9.9"));
        // A changed file.
        assert!(verify_signature(&pk, b"abd  varsto-1-x.tar.gz\n", &sig).is_err());
        // Another key with the same id.
        let (_, other) = test_key(8);
        assert!(verify_signature(&other, data, &sig).is_err());
        // A changed trusted comment (e.g. another version).
        let forged = sig.replace("version:9.9.9", "version:9.9.10");
        assert!(verify_signature(&pk, data, &forged).is_err());
        // Garbage.
        assert!(verify_signature(&pk, data, "nonsense").is_err());
    }

    #[test]
    fn signature_from_the_signing_script_format() {
        // Made by scripts/sign-release.sh (openssl) with a throw-away key and
        // checked with minisign 0.11 (`minisign -Vm SHA256SUMS -x SHA256SUMS.sig`).
        let pk = parse_public_key(
            "untrusted comment: minisign public key 7BF54BDB8A16C3B8\nRWS4wxaK20v1e4UAAT+T9EZPQSOqOZ6XGgdLMg5VZtUTJpqjRuVC7918\n",
        )
        .unwrap();
        let sig = "untrusted comment: signature from the Varsto release key\nRUS4wxaK20v1e/Ac/gJhma6MnHvRHBT44fywiU9q3Y+rKQwWef8kVYYXOLfXAjRC5hm7KC7PcBB+f3vVoM5MkK1pla4givriQwg=\ntrusted comment: timestamp:1791558665\tfile:SHA256SUMS\tversion:0.0.1-alpha.8\nCdnQKLXWjn2uLmhat3Z0LRf6DS6npjmpXLURBoUHi7wCSeFABd2mmlekHIE7SNiS+KPUBzzLIi8HO6i2TQd2DA==\n";
        let data =
            b"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  varsto-x.tar.gz\n";
        let t = verify_signature(&pk, data, sig).unwrap();
        assert_eq!(trusted_field(&t, "version"), Some("0.0.1-alpha.8"));
        assert!(verify_signature(&pk, b"tampered", sig).is_err());
    }

    #[test]
    fn listed_hash_reads_both_formats() {
        let s = "AA  one.zip\nbb *two.tar.gz\n";
        assert_eq!(listed_hash(s, "one.zip").as_deref(), Some("aa"));
        assert_eq!(listed_hash(s, "two.tar.gz").as_deref(), Some("bb"));
        assert_eq!(listed_hash(s, "three"), None);
    }

    /// Files served from memory; a missing URL fails like curl -f.
    struct Fake {
        files: HashMap<String, Vec<u8>>,
        downloaded: RefCell<bool>,
    }

    impl Fetch for Fake {
        fn get(&self, url: &str) -> Result<Vec<u8>> {
            self.files
                .get(url)
                .cloned()
                .ok_or_else(|| anyhow!("404 {url}"))
        }
        fn download(&self, url: &str, dest: &Path) -> Result<()> {
            *self.downloaded.borrow_mut() = true;
            fs::write(dest, self.get(url)?)?;
            Ok(())
        }
    }

    const BASE: &str = "https://example.invalid/downloads/";
    const ARCHIVE: &str = "varsto-9.9.9-x86_64-unknown-linux-musl.tar.gz";

    fn release(sk: &SigningKey) -> (Fake, Check) {
        let body = b"new release".to_vec();
        let sums = format!("{}  {ARCHIVE}\n", hex::encode(Sha256::digest(&body)));
        let sig = sign(
            sk,
            sums.as_bytes(),
            "timestamp:1\tfile:SHA256SUMS\tversion:9.9.9",
        );
        let mut files = HashMap::new();
        files.insert(format!("{BASE}{ARCHIVE}"), body);
        files.insert(format!("{BASE}SHA256SUMS"), sums.into_bytes());
        files.insert(format!("{BASE}SHA256SUMS.sig"), sig.into_bytes());
        let check = Check {
            current: "0.0.1".into(),
            latest: "9.9.9".into(),
            available: true,
            newer: true,
            download_page: BASE.into(),
            archive: Some(ARCHIVE.into()),
            target: "x86_64-unknown-linux-musl".into(),
        };
        (
            Fake {
                files,
                downloaded: RefCell::new(false),
            },
            check,
        )
    }

    fn github_url() -> String {
        format!("{GITHUB_RELEASES}/v9.9.9/SHA256SUMS")
    }

    #[test]
    fn update_accepts_a_signed_release() {
        let (sk, pk) = test_key(7);
        let (mut fake, check) = release(&sk);
        let dir = tempfile::tempdir().unwrap();
        // GitHub unreachable: the signature suffices.
        let v = download_verified(&fake, BASE, &pk, &check, dir.path()).unwrap();
        assert_eq!(fs::read(&v.path).unwrap(), b"new release");
        assert!(v.notes.iter().any(|n| n.contains("not reachable")));
        // GitHub agrees.
        let sums = fake.files[&format!("{BASE}SHA256SUMS")].clone();
        fake.files.insert(github_url(), sums);
        let v = download_verified(&fake, BASE, &pk, &check, dir.path()).unwrap();
        assert!(v.notes.iter().any(|n| n.contains("GitHub release")));
    }

    #[test]
    fn update_refuses_without_a_valid_signature() {
        let (sk, pk) = test_key(7);
        let dir = tempfile::tempdir().unwrap();
        // No signature at all.
        let (mut fake, check) = release(&sk);
        fake.files.remove(&format!("{BASE}SHA256SUMS.sig"));
        let e = download_verified(&fake, BASE, &pk, &check, dir.path()).unwrap_err();
        assert!(format!("{e:#}").contains("not signed"), "{e:#}");
        assert!(!*fake.downloaded.borrow());
        // Signed by another key.
        let (other, _) = test_key(9);
        let (fake, check) = release(&other);
        assert!(download_verified(&fake, BASE, &pk, &check, dir.path()).is_err());
        assert!(!*fake.downloaded.borrow());
        // A checksum list changed after signing (archive swapped by the site).
        let (mut fake, check) = release(&sk);
        let evil = b"evil".to_vec();
        fake.files.insert(
            format!("{BASE}SHA256SUMS"),
            format!("{}  {ARCHIVE}\n", hex::encode(Sha256::digest(&evil))).into_bytes(),
        );
        fake.files.insert(format!("{BASE}{ARCHIVE}"), evil);
        assert!(download_verified(&fake, BASE, &pk, &check, dir.path()).is_err());
        // An archive that does not match the signed list.
        let (mut fake, check) = release(&sk);
        fake.files
            .insert(format!("{BASE}{ARCHIVE}"), b"evil".to_vec());
        let e = download_verified(&fake, BASE, &pk, &check, dir.path()).unwrap_err();
        assert!(format!("{e:#}").contains("checksum mismatch"), "{e:#}");
        // A signed list of another version (replayed old release).
        let (mut fake, mut check) = release(&sk);
        check.latest = "9.9.10".into();
        check.archive = Some("varsto-9.9.10-x86_64-unknown-linux-musl.tar.gz".into());
        fake.files.insert(
            format!("{BASE}varsto-9.9.10-x86_64-unknown-linux-musl.tar.gz"),
            b"x".to_vec(),
        );
        assert!(download_verified(&fake, BASE, &pk, &check, dir.path()).is_err());
    }

    #[test]
    fn update_refuses_when_github_disagrees() {
        let (sk, pk) = test_key(7);
        let dir = tempfile::tempdir().unwrap();
        let (mut fake, check) = release(&sk);
        fake.files.insert(
            github_url(),
            format!("{}  {ARCHIVE}\n", "00".repeat(32)).into_bytes(),
        );
        let e = download_verified(&fake, BASE, &pk, &check, dir.path()).unwrap_err();
        assert!(format!("{e:#}").contains("GitHub"), "{e:#}");
        assert!(!*fake.downloaded.borrow());
        let (mut fake, check) = release(&sk);
        fake.files
            .insert(github_url(), b"aa  something-else.zip\n".to_vec());
        assert!(download_verified(&fake, BASE, &pk, &check, dir.path()).is_err());
    }

    #[test]
    fn site_override() {
        // Only the default is checked here: the variable is process-wide.
        if std::env::var_os(SITE_ENV).is_none() {
            assert_eq!(downloads_base(), format!("{DEFAULT_SITE}/downloads/"));
        }
    }
}
