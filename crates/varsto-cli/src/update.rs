// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Self-update from the project download page, with signed releases.
//!
//! `varsto update` fetches `manifest.json` with its detached signature
//! `manifest.json.minisig`, `SHA256SUMS` and its detached signature
//! `SHA256SUMS.sig`, and refuses to go on unless both signatures verify
//! against the release public key built into this binary (`release-key.pub`
//! at the root of the repository). The signature is in minisign's format:
//! Ed25519 over the BLAKE2b-512 hash of the file, plus a signed "trusted
//! comment" that names the version and the time of signing.
//!
//! Against a download site that serves old or withheld releases (a freeze or
//! rollback): only a version newer than this binary (and than the version
//! compiled in as `MIN_ACCEPTED_VERSION`) is installed; the signing time of a
//! checksum list must not be older than the last one accepted
//! (`update-state.json` in the device directory); and as a second channel
//! the checksum list attached to the GitHub release of that version must be
//! reachable and agree. When GitHub does not answer, the update waits and
//! says why; `--allow-single-source` goes on with the signature alone.
//! Then the archive for this platform is downloaded, its SHA-256 checked
//! against the signed list, and the running binary replaced. Downloads use
//! the system `curl` so that the binary carries no TLS stack of its own.
//!
//! On Windows the setup program (`Varsto-<version>-setup.exe`) is the only
//! way to install and to update: the signed setup file is downloaded, checked
//! like any archive and run silently from a private folder, and it replaces
//! the installation, closes and restarts the running parts. A copy that the
//! setup program did not install (an old portable alpha.14 unzipped by hand)
//! cannot update itself; it is told to download and run the installer once,
//! and updates continue automatically from there. The service looks for
//! a new version once a day (`auto-update` setting) and installs it by itself
//! where it can (a setup-installed Windows copy), or tells the user where it
//! cannot.
//!
//! `varsto update --daily` takes the newest daily (development) build instead:
//! `daily/latest/SHA256SUMS` signed with a separate daily key
//! (`daily-key.pub`) whose trusted comment names the channel, the build id and
//! the signing time. The two channels share nothing that could be confused: the
//! key, the state file (`update-state-daily.json`) and the installed-build
//! record (`update-channel.json`) are separate, and the background updater only
//! ever uses the stable channel. See spec section 67.

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
/// address keeps serving /downloads/ for old clients.
pub const DEFAULT_SITE: &str = "https://varsto.net";
pub const SITE_ENV: &str = "VARSTO_UPDATE_URL";
/// Second channel: the checksum list attached to each GitHub release.
pub const GITHUB_RELEASES: &str = "https://github.com/janttsu/varsto/releases/download";
/// The oldest version this binary will ever install: its own. A signed list
/// of this version or an older one is a rollback, however valid the signature.
pub const MIN_ACCEPTED_VERSION: &str = env!("CARGO_PKG_VERSION");
/// A signed list older than this is reported (an error only when a newer
/// signature than the last accepted one is not the one offered).
const STALE_AFTER_SECS: i64 = 90 * 86_400;
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
    /// Which channel this key is trusted for ("release" or "daily"), for messages.
    label: &'static str,
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
        label: "release",
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
            "signed with key {:016X}, not the {} key {}",
            u64::from_le_bytes(s.id),
            key.label,
            key.id_hex()
        );
    }
    let message = if s.prehashed {
        Blake2b512::digest(data).to_vec()
    } else {
        data.to_vec()
    };
    key.key.verify_strict(&message, &s.sig).map_err(|_| {
        anyhow!(
            "bad signature: the file was changed or not signed by the {} key",
            key.label
        )
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

// ----- rollback state ---------------------------------------------------------------

/// What the updater remembers between runs, `update-state.json` in the
/// device directory.
#[derive(Serialize, serde::Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// Signing time (seconds) of the newest checksum list accepted so far.
    #[serde(default)]
    pub last_timestamp: i64,
    #[serde(default)]
    pub last_version: String,
}

pub const STATE_FILE: &str = "update-state.json";

impl State {
    pub fn load(home: &Path) -> State {
        State::load_file(home, STATE_FILE)
    }
    fn save(&self, home: &Path) -> Result<()> {
        self.save_file(home, STATE_FILE)
    }
    /// The state of one channel (`update-state.json` is the stable one).
    fn load_file(home: &Path, name: &str) -> State {
        varsto_core::util::read_json_or_default(&home.join(name)).unwrap_or_default()
    }
    fn save_file(&self, home: &Path, name: &str) -> Result<()> {
        varsto_core::util::private_dir(home)?;
        varsto_core::util::write_atomic(&home.join(name), &serde_json::to_vec_pretty(self)?)
    }
}

/// How strict an update is and where it keeps its state.
pub struct Policy<'a> {
    /// The device directory (`update-state.json`); `None` keeps no state.
    pub home: Option<&'a Path>,
    /// Go on with the signature alone when GitHub does not answer.
    pub allow_single_source: bool,
    /// Now, in seconds since the epoch.
    pub now: i64,
}

impl<'a> Policy<'a> {
    pub fn new(home: &'a Path, allow_single_source: bool) -> Policy<'a> {
        Policy {
            home: Some(home),
            allow_single_source,
            now: varsto_core::util::now_utc(),
        }
    }
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

impl Check {
    /// The update is the Windows setup program, which restarts Varsto itself.
    pub fn installer(&self) -> bool {
        self.archive.as_deref().is_some_and(is_setup_file)
    }
}

fn is_setup_file(name: &str) -> bool {
    (name.starts_with("Varsto-") && name.ends_with("-setup.exe")) || name == DAILY_SETUP
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
    check_with(&Curl, &downloads_base(), &release_key())
}

fn check_with(fetch: &dyn Fetch, base: &str, key: &PublicKey) -> Result<Check> {
    // An unsigned manifest could name any release, an old one included.
    let manifest_bytes = fetch.get(&format!("{base}manifest.json"))?;
    let manifest_sig = fetch.get(&format!("{base}manifest.json.minisig")).context(
        "the release manifest is not signed (no manifest.json.minisig); refusing to trust it",
    )?;
    let signed = verify_signature(
        key,
        &manifest_bytes,
        &String::from_utf8_lossy(&manifest_sig),
    )
    .context("manifest.json does not carry a valid release signature; refusing to trust it")?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    let latest = manifest
        .get("_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("manifest has no version"))?
        .to_string();
    match trusted_field(&signed, "version") {
        Some(v) if v == latest => {}
        other => bail!(
            "the signed manifest is for version {}, not {latest}; refusing to trust it",
            other.unwrap_or("(none)")
        ),
    }
    let current = env!("CARGO_PKG_VERSION").to_string();
    let target = target_triple().to_string();
    let archive = manifest.as_object().and_then(|m| {
        pick_archive(
            m.keys().map(String::as_str),
            &latest,
            &target,
            app_bundle().is_some(),
            installed_by_setup(),
        )
    });
    let newer = version_key(&latest) > version_key(&current)
        && version_key(&latest) > version_key(MIN_ACCEPTED_VERSION);
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

/// The file name of the Windows setup program of a release.
pub fn setup_name(version: &str) -> String {
    format!("Varsto-{version}-setup.exe")
}

/// Whether this copy was installed by the Windows setup program: its
/// uninstaller (`unins000.exe`) sits next to the binary.
pub fn installed_by_setup() -> bool {
    cfg!(windows)
        && std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join("unins000.exe")))
            .is_some_and(|u| u.is_file())
}

/// Which file of the release replaces this copy. Inside Varsto.app the whole
/// bundle comes from the disk image; a copy installed by the Windows setup
/// program takes the setup program (when the release has one); other Windows
/// copies take nothing (see `windows_installer_notice`); elsewhere the archive
/// for this platform carries the binary.
fn pick_archive<'a>(
    names: impl Iterator<Item = &'a str>,
    latest: &str,
    target: &str,
    in_bundle: bool,
    by_setup: bool,
) -> Option<String> {
    let names: Vec<&str> = names.collect();
    let dmg = format!("Varsto-{latest}-macos.dmg");
    if in_bundle {
        return names.contains(&dmg.as_str()).then_some(dmg);
    }
    if target.contains("windows") {
        let setup = setup_name(latest);
        return (by_setup && names.contains(&setup.as_str())).then_some(setup);
    }
    names
        .into_iter()
        .find(|k| k.contains(target) && k.ends_with(".tar.gz"))
        .map(str::to_string)
}

/// What a Windows copy that the setup program did not install is told: it
/// cannot update itself, the installer has to be run once. `None` elsewhere
/// and for setup-installed copies. `file` is the installer's file name.
fn windows_installer_notice(
    target: &str,
    by_setup: bool,
    base: &str,
    file: &str,
) -> Option<String> {
    (target.contains("windows") && !by_setup).then(|| {
        format!(
            "this copy was not installed with the setup program, and on Windows only the setup program updates Varsto. Download and run the installer once ({base}{file}); your vault and settings stay as they are, and updates continue automatically after that"
        )
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
    policy: &Policy,
) -> Result<Verified> {
    if version_key(&check.latest) <= version_key(MIN_ACCEPTED_VERSION) {
        bail!(
            "{} is not newer than this binary ({MIN_ACCEPTED_VERSION}); refusing to install an older or the same version",
            check.latest
        );
    }
    let archive = check
        .archive
        .clone()
        .ok_or_else(|| anyhow!("no archive for {}", check.target))?;
    let expected_name = archive.starts_with(&format!("varsto-{}-", check.latest))
        || archive == format!("Varsto-{}-macos.dmg", check.latest)
        || archive == setup_name(&check.latest);
    if !expected_name || archive.contains(['/', '\\']) {
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
    // The signing time must not go backwards: a list older than the last one
    // accepted is a replayed release.
    let timestamp: i64 = trusted_field(&trusted, "timestamp")
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| anyhow!("the signature carries no signing time; refusing to update"))?;
    let state = policy.home.map(State::load).unwrap_or_default();
    if timestamp < state.last_timestamp {
        bail!(
            "the signed checksum list is older ({}) than the last one accepted ({}, version {}); refusing to update (a rollback?)",
            varsto_core::util::format_date(timestamp),
            varsto_core::util::format_date(state.last_timestamp),
            state.last_version
        );
    }
    let sums = String::from_utf8(sums).context("SHA256SUMS is not text")?;
    let expected = listed_hash(&sums, &archive)
        .ok_or_else(|| anyhow!("{archive} is not listed in the signed SHA256SUMS"))?;
    let mut notes = vec![format!("signature verified (release key {})", key.id_hex())];
    if policy.now - timestamp > STALE_AFTER_SECS {
        notes.push(format!(
            "warning: the signed list is {} days old; it is the newest the download site offers",
            (policy.now - timestamp) / 86_400
        ));
    }
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
        Err(e) if policy.allow_single_source => notes.push(format!(
            "GitHub release not reachable ({e}); --allow-single-source: the signature alone was checked"
        )),
        Err(e) => bail!(
            "the update is postponed: the GitHub release of {} could not be reached to cross-check the download site ({e}). Try again later, or accept the download site alone with --allow-single-source",
            check.latest
        ),
    }
    let path = dir.join(&archive);
    fetch.download(&format!("{base}{archive}"), &path)?;
    let actual = sha256_file(&path)?;
    if actual != expected {
        bail!("checksum mismatch for {archive}: expected {expected}, got {actual}");
    }
    // Only now: a failed check must not move the line.
    if let Some(home) = policy.home {
        State {
            last_timestamp: timestamp.max(state.last_timestamp),
            last_version: check.latest.clone(),
        }
        .save(home)?;
    }
    Ok(Verified { path, notes })
}

/// Download, verify and install the latest release over the running binary.
/// Returns a human-readable message. The caller restarts the service.
pub fn apply(check: &Check, policy: &Policy) -> Result<String> {
    if !check.available {
        if check.newer {
            if let Some(notice) = windows_installer_notice(
                &check.target,
                installed_by_setup(),
                &check.download_page,
                &setup_name(&check.latest),
            ) {
                bail!(
                    "{} is out (you have {}), but {notice}",
                    check.latest,
                    check.current
                );
            }
            // Never "up to date" while a newer version exists: say why this
            // copy cannot replace itself and where to get the new one.
            bail!(
                "{} is out (you have {}), but this copy cannot install it by itself: there is no package for {} at the download site. Download it from {}",
                check.latest,
                check.current,
                check.target,
                check.download_page
            );
        }
        return Ok(format!("already up to date ({})", check.current));
    }
    // A fresh directory with a random name and mode 0700 (tempfile creates
    // it exclusively): nobody can pre-create it or plant a binary inside.
    remove_stale_update_dirs();
    let tmp = tempfile::Builder::new()
        .prefix(UPDATE_DIR_PREFIX)
        .tempdir()
        .context("create a temporary directory for the update")?;
    if check.installer() {
        // The setup program runs after this process is gone: its folder must
        // outlive us (the next update removes it).
        let dir = tmp.keep();
        return install_from(check, &dir, policy);
    }
    install_from(check, tmp.path(), policy)
}

const UPDATE_DIR_PREFIX: &str = "varsto-update-";

/// Setup programs of earlier updates stay in their private folders until
/// the next update; folders older than a day go now.
fn remove_stale_update_dirs() {
    let Ok(rd) = fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for e in rd.flatten() {
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > std::time::Duration::from_secs(86_400));
        if old
            && e.file_name()
                .to_string_lossy()
                .starts_with(UPDATE_DIR_PREFIX)
            && e.file_type().is_ok_and(|t| t.is_dir())
        {
            let _ = fs::remove_dir_all(e.path());
        }
    }
}

/// The command line that runs a setup program without asking anything: no
/// windows, no message boxes, no reboot, and the running Varsto closed (and,
/// by the script's own entries, started again afterwards).
pub fn setup_args(log: &Path) -> Vec<String> {
    vec![
        "/VERYSILENT".into(),
        "/SUPPRESSMSGBOXES".into(),
        "/NORESTART".into(),
        "/CLOSEAPPLICATIONS".into(),
        format!("/LOG={}", log.display()),
    ]
}

/// Start the verified setup program and let it go: it replaces files of the
/// process that started it, so it must not wait for it.
fn start_setup(setup: &Path, dir: &Path) -> Result<()> {
    let mut cmd = std::process::Command::new(setup);
    cmd.args(setup_args(&dir.join("setup.log")))
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    cmd.spawn().context("start the setup program")?;
    Ok(())
}

/// The Varsto.app bundle this binary runs from (macOS), if any.
pub fn app_bundle() -> Option<PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    exe.ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf)
}

/// Replace the whole app bundle with the one on the verified disk image:
/// copy it next to the old one, then swap by renaming, so a failure leaves
/// the old app in place. Running processes keep their open files.
fn install_app_from_dmg(dmg: &Path, bundle: &Path, tmp: &Path) -> Result<()> {
    let run = |cmd: &str, args: &[&str]| -> Result<()> {
        let out = std::process::Command::new(cmd)
            .args(args)
            .output()
            .with_context(|| format!("run {cmd}"))?;
        if !out.status.success() {
            bail!(
                "{cmd} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    };
    let mnt = tmp.join("mnt");
    fs::create_dir_all(&mnt)?;
    let mnt_s = mnt.display().to_string();
    run(
        "/usr/bin/hdiutil",
        &[
            "attach",
            "-nobrowse",
            "-readonly",
            "-noautoopen",
            "-mountpoint",
            &mnt_s,
            &dmg.display().to_string(),
        ],
    )?;
    let result = (|| -> Result<()> {
        let src = fs::read_dir(&mnt)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == "app") && !p.is_symlink())
            .ok_or_else(|| anyhow!("the disk image holds no app"))?;
        let parent = bundle
            .parent()
            .ok_or_else(|| anyhow!("app has no folder"))?;
        let name = bundle
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let staged = parent.join(format!(".{name}.new"));
        let old = parent.join(format!(".{name}.old"));
        let _ = fs::remove_dir_all(&staged);
        let _ = fs::remove_dir_all(&old);
        run(
            "/usr/bin/ditto",
            &[&src.display().to_string(), &staged.display().to_string()],
        )
        .context("copy the new app (is the Applications folder writable?)")?;
        fs::rename(bundle, &old)?;
        if let Err(e) = fs::rename(&staged, bundle) {
            let _ = fs::rename(&old, bundle);
            return Err(e.into());
        }
        let _ = fs::remove_dir_all(&old);
        Ok(())
    })();
    let _ = run("/usr/bin/hdiutil", &["detach", "-force", &mnt_s]);
    result
}

fn install_from(check: &Check, tmp: &Path, policy: &Policy) -> Result<String> {
    let v = download_verified(&Curl, &downloads_base(), &release_key(), check, tmp, policy)?;
    let message = install_file(&v, tmp, &check.current, &check.latest)?;
    // A release replaces a daily build: this copy is on the stable channel again.
    if let Some(home) = policy.home {
        clear_channel(home);
    }
    Ok(message)
}

/// Put a verified download in place of the running copy: the app bundle from
/// a disk image, the Windows setup program, or the binary from an archive.
/// `from` and `to` are only for the message.
fn install_file(v: &Verified, tmp: &Path, from: &str, to: &str) -> Result<String> {
    if v.path.extension().is_some_and(|e| e == "dmg") {
        let bundle = app_bundle().ok_or_else(|| anyhow!("not running from Varsto.app"))?;
        install_app_from_dmg(&v.path, &bundle, tmp)?;
        return Ok(format!(
            "updated {} -> {} ({}; {}); the app and service restart with it",
            from,
            to,
            bundle.display(),
            v.notes.join("; ")
        ));
    }
    if v.path
        .file_name()
        .is_some_and(|n| is_setup_file(&n.to_string_lossy()))
    {
        if !cfg!(windows) {
            bail!("the setup program only runs on Windows");
        }
        start_setup(&v.path, tmp)?;
        return Ok(format!(
            "updating {} -> {} with the setup program ({}); Varsto closes, is replaced and starts again in a moment",
            from,
            to,
            v.notes.join("; ")
        ));
    }
    if cfg!(windows) {
        bail!("on Windows only the setup program installs Varsto; run the installer once");
    }
    let exe = std::env::current_exe()?;
    install_archive(&v.path, tmp, &exe)?;
    Ok(format!(
        "updated {} -> {} ({}; {}); restart the service or app to use it",
        from,
        to,
        exe.display(),
        v.notes.join("; ")
    ))
}

/// Unpack an archive (tar.gz) and replace the binary `exe` with the
/// `varsto` it holds, atomically (a rename).
fn install_archive(archive: &Path, tmp: &Path, exe: &Path) -> Result<()> {
    let extract = tmp.join("x");
    fs::create_dir_all(&extract)?;
    let tar = std::process::Command::new("tar")
        .args([
            "-xf",
            &archive.display().to_string(),
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
    let bin_name = "varsto";
    let found: Vec<PathBuf> = walkdir::WalkDir::new(&extract)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && e.file_name() == bin_name)
        .map(|e| e.into_path())
        .collect();
    let new_bin = match found.as_slice() {
        [one] => one.clone(),
        [] => bail!("archive does not contain {bin_name}"),
        _ => bail!("archive contains more than one {bin_name}; not installed"),
    };
    replace_binary(&new_bin, exe)
}

#[cfg(unix)]
fn replace_binary(new_bin: &Path, exe: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let staged = exe.with_extension("new");
    fs::copy(new_bin, &staged)?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
    fs::rename(&staged, exe)?;
    Ok(())
}

/// Windows copies are replaced by the setup program, never by a rename.
#[cfg(not(unix))]
fn replace_binary(_new_bin: &Path, _exe: &Path) -> Result<()> {
    bail!("on Windows only the setup program installs Varsto")
}

// ----- the daily channel ------------------------------------------------------------

/// The daily public key (minisign format), also at `<site>/daily-key.pub`. It
/// is trusted for the daily channel only: `varsto update` (stable) never
/// accepts a signature made with it, and `varsto update --daily` never
/// accepts one made with the release key.
pub const DAILY_KEY: &str = include_str!("../../../daily-key.pub");
/// Where the daily builds and their signed checksum list live, below the site.
pub const DAILY_PATH: &str = "daily/latest/";
/// The Windows setup program of a daily build (a stable name; the signed list
/// says which build it is).
pub const DAILY_SETUP: &str = "varsto-daily-windows-setup.exe";
/// Freeze protection of the daily channel (its own file, never the stable one).
pub const DAILY_STATE_FILE: &str = "update-state-daily.json";
/// Which channel this copy was installed from, written by `update --daily`.
pub const CHANNEL_FILE: &str = "update-channel.json";
/// A daily list signed longer ago than this is not trusted (a frozen or
/// replayed list); builds come every few days, so a month is generous.
const DAILY_MAX_AGE_SECS: i64 = 30 * 86_400;
/// Signing times this far ahead of the clock are refused (they would freeze
/// the channel for everything signed later).
const DAILY_FUTURE_SECS: i64 = 86_400;

/// The daily key built into this binary.
pub fn daily_key() -> PublicKey {
    let mut k = parse_public_key(DAILY_KEY).expect("daily-key.pub is a valid public key");
    k.label = "daily";
    k
}

/// `<site>/daily/latest/`, where the signed list and the current files live.
pub fn daily_base() -> String {
    format!("{}/{DAILY_PATH}", site())
}

/// The daily builds page, for downloads by hand.
pub fn daily_page() -> String {
    format!("{}/daily/", site())
}

/// What `update --daily` remembers of the build it installed.
#[derive(Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub channel: String,
    /// The build id from the signed list, e.g. `20261016-316c579`.
    pub build: String,
    /// Signing time of the list the build came with.
    pub signed_at: i64,
    /// The version the build reported when installed.
    pub version: String,
}

/// The daily build this copy was installed from, if it was.
pub fn installed_daily(home: &Path) -> Option<Installed> {
    let i: Installed = serde_json::from_slice(&fs::read(home.join(CHANNEL_FILE)).ok()?).ok()?;
    (i.channel == "daily" && valid_build_id(&i.build)).then_some(i)
}

fn record_daily(home: &Path, build: &str, signed_at: i64) -> Result<()> {
    varsto_core::util::private_dir(home)?;
    let i = Installed {
        channel: "daily".into(),
        build: build.into(),
        signed_at,
        version: env!("CARGO_PKG_VERSION").into(),
    };
    varsto_core::util::write_atomic(&home.join(CHANNEL_FILE), &serde_json::to_vec_pretty(&i)?)
}

/// This copy is on the stable channel again (a release was installed).
pub fn clear_channel(home: &Path) {
    let _ = fs::remove_file(home.join(CHANNEL_FILE));
}

/// "daily build 20261016-316c579" for `--version` and `status`, if this copy
/// came from the daily channel.
pub fn channel_note(home: &Path) -> Option<String> {
    installed_daily(home).map(|i| format!("daily build {}", i.build))
}

/// A build id: `YYYYMMDD-<commit>`.
pub fn valid_build_id(id: &str) -> bool {
    match id.split_once('-') {
        Some((d, c)) => {
            d.len() == 8
                && d.bytes().all(|b| b.is_ascii_digit())
                && (7..=40).contains(&c.len())
                && c.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

/// The date part of a valid build id, as a comparable number.
fn build_date(id: &str) -> u32 {
    id.get(..8).and_then(|d| d.parse().ok()).unwrap_or(0)
}

/// The file of the daily list that carries the binary for this platform, as
/// the stable (signed) name; `Err` says why the CLI cannot install it.
fn daily_file(
    os: &str,
    arch: &str,
    in_bundle: bool,
    by_setup: bool,
) -> Result<&'static str, String> {
    match (os, arch) {
        ("linux", "x86_64") => Ok("varsto-daily-linux-x86_64.tar.gz"),
        ("windows", "x86_64") if by_setup => Ok(DAILY_SETUP),
        ("windows", "x86_64") => Err(
            "this copy was not installed with the setup program, and on Windows only the setup program updates Varsto. Download and run the installer once (varsto-daily-windows-setup.exe); your vault and settings stay as they are, and updates continue automatically after that"
                .into(),
        ),
        ("macos", _) => Err(format!(
            "the macOS daily build is a disk image (varsto-daily-macos-apple-silicon.dmg){}; the command line does not install it",
            if in_bundle { "" } else { " and there is no command-line archive for macOS" }
        )),
        _ => Err(format!("there is no daily build of the command line for {os}/{arch}")),
    }
}

/// A daily checksum list whose signature was verified, and what to do with it.
#[derive(Serialize, Clone, Debug)]
pub struct DailyCheck {
    pub channel: &'static str,
    /// The daily build installed from this channel, if this copy came from it.
    pub current_build: Option<String>,
    /// The build the signed list is for.
    pub latest_build: String,
    /// When the list was signed (seconds).
    pub signed_at: i64,
    /// The signed list is for a newer build than the installed one.
    pub newer: bool,
    /// ... and this binary can install it itself.
    pub available: bool,
    pub download_page: String,
    /// The file (stable name) that replaces this copy.
    pub archive: Option<String>,
    /// Why this copy cannot install the build itself.
    pub reason: Option<String>,
    pub target: String,
    /// The signed list; the download is checked against this text only.
    #[serde(skip)]
    sums: String,
}

pub fn check_daily(home: &Path) -> Result<DailyCheck> {
    let policy = Policy::new(home, false);
    check_daily_with(&Curl, &daily_base(), &daily_key(), &policy)
}

/// Fetch the daily list and its signature and decide what it means for this
/// copy. Only signed data is used: `latest.json` on the site is not read.
fn check_daily_with(
    fetch: &dyn Fetch,
    base: &str,
    key: &PublicKey,
    policy: &Policy,
) -> Result<DailyCheck> {
    let sums = fetch.get(&format!("{base}SHA256SUMS"))?;
    let sig = fetch
        .get(&format!("{base}SHA256SUMS.sig"))
        .context("the daily list is not signed (no SHA256SUMS.sig); refusing to trust it")?;
    let trusted = verify_signature(key, &sums, &String::from_utf8_lossy(&sig)).context(
        "the daily SHA256SUMS does not carry a valid daily signature; refusing to trust it",
    )?;
    if trusted_field(&trusted, "channel") != Some("daily") {
        bail!("the signature is not for the daily channel; refusing to trust it");
    }
    if trusted_field(&trusted, "file") != Some("SHA256SUMS") {
        bail!("the signature is for another file than SHA256SUMS; refusing to trust it");
    }
    let build = trusted_field(&trusted, "build")
        .filter(|b| valid_build_id(b))
        .ok_or_else(|| anyhow!("the signature names no valid daily build; refusing to trust it"))?
        .to_string();
    let timestamp: i64 = trusted_field(&trusted, "timestamp")
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| anyhow!("the signature carries no signing time; refusing to trust it"))?;
    // Freeze and replay protection, as for releases but with the daily
    // channel's own state: the signing time never goes backwards ...
    let state = policy
        .home
        .map(|h| State::load_file(h, DAILY_STATE_FILE))
        .unwrap_or_default();
    if timestamp < state.last_timestamp {
        bail!(
            "the signed daily list is older ({}) than the last one accepted ({}, build {}); refusing (a rollback?)",
            varsto_core::util::format_date(timestamp),
            varsto_core::util::format_date(state.last_timestamp),
            state.last_version
        );
    }
    // ... is not in the future, and is recent.
    if timestamp > policy.now + DAILY_FUTURE_SECS {
        bail!(
            "the daily list is signed in the future ({}); check this computer's clock",
            varsto_core::util::format_date(timestamp)
        );
    }
    if policy.now - timestamp > DAILY_MAX_AGE_SECS {
        bail!(
            "the newest signed daily list is {} days old (build {build}); the site may be frozen or no daily build was published. Refusing to install it",
            (policy.now - timestamp) / 86_400
        );
    }
    // Never an older build than the installed one, judged by the signed
    // build id (not the version, which daily builds share).
    let installed = policy.home.and_then(installed_daily);
    let newer = match &installed {
        None => true,
        Some(i) if i.build == build => false,
        Some(i) if build_date(&build) < build_date(&i.build) => bail!(
            "the signed daily list is for build {build}, older than the installed build {}; refusing to install an older build",
            i.build
        ),
        Some(i) if build_date(&build) == build_date(&i.build) => timestamp > i.signed_at,
        Some(_) => true,
    };
    let sums = String::from_utf8(sums).context("SHA256SUMS is not text")?;
    let (archive, reason) = match daily_file(
        std::env::consts::OS,
        std::env::consts::ARCH,
        app_bundle().is_some(),
        installed_by_setup(),
    ) {
        Ok(name) => match listed_hash(&sums, name) {
            Some(_) => (Some(name.to_string()), None),
            None => (
                None,
                Some(format!("{name} is not listed in the signed daily list")),
            ),
        },
        Err(why) => (None, Some(why)),
    };
    Ok(DailyCheck {
        channel: "daily",
        current_build: installed.map(|i| i.build),
        latest_build: build,
        signed_at: timestamp,
        newer,
        available: newer && archive.is_some(),
        download_page: daily_page(),
        archive,
        reason,
        target: target_triple().to_string(),
        sums,
    })
}

/// Download the daily file named by the signed list into `dir` and check its
/// SHA-256 against that list. Nothing is installed here.
fn download_daily_verified(
    fetch: &dyn Fetch,
    base: &str,
    check: &DailyCheck,
    dir: &Path,
    policy: &Policy,
) -> Result<Verified> {
    let archive = check
        .archive
        .clone()
        .ok_or_else(|| anyhow!("no daily file for {}", check.target))?;
    if !archive.starts_with("varsto-daily-") || archive.contains(['/', '\\']) {
        bail!("the daily list names an unexpected file {archive}; refusing to update");
    }
    let expected = listed_hash(&check.sums, &archive)
        .ok_or_else(|| anyhow!("{archive} is not listed in the signed daily list"))?;
    let path = dir.join(&archive);
    fetch.download(&format!("{base}{archive}"), &path)?;
    let actual = sha256_file(&path)?;
    if actual != expected {
        bail!(
            "checksum mismatch for {archive}: expected {expected} (signed list of build {}), got {actual}. The site may be in the middle of publishing a new build; try again in a minute",
            check.latest_build
        );
    }
    // Only now: a failed check must not move the line.
    if let Some(home) = policy.home {
        let state = State::load_file(home, DAILY_STATE_FILE);
        State {
            last_timestamp: check.signed_at.max(state.last_timestamp),
            last_version: check.latest_build.clone(),
        }
        .save_file(home, DAILY_STATE_FILE)?;
    }
    Ok(Verified {
        path,
        notes: vec![
            format!("signature verified (daily key {})", daily_key().id_hex()),
            "daily builds have no second channel: the site's signature alone was checked".into(),
        ],
    })
}

/// Download, verify and install the latest daily build over the running binary.
/// The caller restarts the service.
pub fn apply_daily(check: &DailyCheck, policy: &Policy) -> Result<String> {
    let from = check
        .current_build
        .as_deref()
        .map(|b| format!("daily {b}"))
        .unwrap_or_else(|| format!("{} (release)", env!("CARGO_PKG_VERSION")));
    if !check.newer {
        return Ok(format!(
            "already up to date (daily build {})",
            check
                .current_build
                .as_deref()
                .unwrap_or(&check.latest_build)
        ));
    }
    if !check.available {
        bail!(
            "daily build {} is out (you have {from}), but this copy cannot install it by itself: {}. Download it from {}",
            check.latest_build,
            check.reason.as_deref().unwrap_or("no file for this platform"),
            check.download_page
        );
    }
    remove_stale_update_dirs();
    let tmp = tempfile::Builder::new()
        .prefix(UPDATE_DIR_PREFIX)
        .tempdir()
        .context("create a temporary directory for the update")?;
    let installer = check.archive.as_deref().is_some_and(is_setup_file);
    // The setup program runs after this process is gone: its folder must outlive us.
    let dir = if installer {
        tmp.keep()
    } else {
        tmp.path().to_path_buf()
    };
    let v = download_daily_verified(&Curl, &daily_base(), check, &dir, policy)?;
    let message = install_file(&v, &dir, &from, &format!("daily {}", check.latest_build))?;
    if let Some(home) = policy.home {
        record_daily(home, &check.latest_build, check.signed_at)?;
    }
    Ok(message)
}

/// What to tell a user of a daily build who asked for the stable channel and
/// finds no newer release: the compiled-in version stops this binary from
/// installing an older or equal release, so the way back is by hand.
pub fn stable_hint(home: &Path, c: &Check) -> Option<String> {
    let i = installed_daily(home)?;
    if c.newer {
        return None;
    }
    Some(format!(
        "this copy is daily build {} (version {}); the latest release {} is not newer, and an update never installs an older or equal version. To go back to releases, download {} by hand, check it with `varsto verify-release`, and install it, or wait for the next release",
        i.build, i.version, c.latest, c.download_page
    ))
}

// ----- automatic updates ----------------------------------------------------------

/// The setting file in the device directory: `off` turns the daily check off.
const AUTO_FILE: &str = "auto-update";
/// When the last successful daily check ran, and for which version the user
/// was told already (one notification per version).
const AUTO_CHECKED: &str = "auto-update-checked";
const AUTO_TOLD: &str = "auto-update-told";
/// The daily check, and the wait after a failure.
const AUTO_EVERY_SECS: i64 = 86_400;
const AUTO_RETRY_SECS: u64 = 3_600;

/// Is the daily check on? It is, unless `varsto config auto-update off` or the
/// switch in the interface turned it off.
pub fn auto_update_enabled(home: &Path) -> bool {
    fs::read_to_string(home.join(AUTO_FILE))
        .map(|t| t.trim() != "off")
        .unwrap_or(true)
}

pub fn set_auto_update(home: &Path, on: bool) -> Result<()> {
    fs::create_dir_all(home)?;
    fs::write(home.join(AUTO_FILE), if on { "on\n" } else { "off\n" })?;
    Ok(())
}

/// Whether this copy installs a new version by itself: a Windows copy that
/// the setup program installed; elsewhere (and for an old portable copy) the
/// user is told and installs it from the interface or the menu.
pub fn can_install_by_itself() -> bool {
    installed_by_setup()
}

fn read_number(path: &Path) -> i64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0)
}

/// What one pass of the daily check did.
#[derive(Debug, PartialEq, Eq)]
pub enum AutoStep {
    /// Not due, or switched off.
    Idle,
    /// Up to date.
    Current,
    /// A newer version exists and the user was told (once per version).
    Told(String),
    /// A newer version is being installed (setup program started or binary replaced).
    Installing(String),
    /// Nothing could be done; try again in an hour (`reason` for the log).
    Retry(String),
}

/// One pass of the daily check: look for a newer version (at most once a day)
/// and, when this copy can, install it. The signature chain of `apply` is the
/// only way in; nothing is installed without it. `tell` shows a notification
/// (title, text); `installed` is called after a binary was replaced in place
/// (not for the setup program, which restarts Varsto itself).
pub fn auto_step(
    home: &Path,
    now: i64,
    tell: &dyn Fn(&str, &str),
    installed: &dyn Fn(&Check),
) -> AutoStep {
    if !auto_update_enabled(home) {
        return AutoStep::Idle;
    }
    if now - read_number(&home.join(AUTO_CHECKED)) < AUTO_EVERY_SECS {
        return AutoStep::Idle;
    }
    let c = match check() {
        Ok(c) => c,
        Err(e) => return AutoStep::Retry(format!("{e:#}")),
    };
    let stamp = |name: &str, v: &str| {
        let _ = fs::write(home.join(name), v);
    };
    if !c.newer {
        stamp(AUTO_CHECKED, &now.to_string());
        return AutoStep::Current;
    }
    let told_before = fs::read_to_string(home.join(AUTO_TOLD))
        .map(|t| t.trim() == c.latest)
        .unwrap_or(false);
    if c.available && can_install_by_itself() {
        if !told_before {
            stamp(AUTO_TOLD, &c.latest);
            tell(
                "Varsto update available",
                &format!(
                    "Varsto {} is out (you have {}). Installing it now.",
                    c.latest, c.current
                ),
            );
        }
        let policy = Policy::new(home, false);
        return match apply(&c, &policy) {
            Ok(_) => {
                stamp(AUTO_CHECKED, &now.to_string());
                if !c.installer() {
                    installed(&c);
                    tell(
                        "Varsto updated",
                        &format!("Varsto {} is installed; the service restarts.", c.latest),
                    );
                }
                AutoStep::Installing(c.latest)
            }
            // A cross-check that cannot be made yet, a bad network: later.
            Err(e) => AutoStep::Retry(format!("{e:#}")),
        };
    }
    stamp(AUTO_CHECKED, &now.to_string());
    if !told_before {
        stamp(AUTO_TOLD, &c.latest);
        tell(
            "Varsto update available",
            &format!(
                "Varsto {} is out (you have {}). Open Varsto to install it.",
                c.latest, c.current
            ),
        );
    }
    AutoStep::Told(c.latest)
}

/// The daily check as a background thread of the service. `tell` shows a
/// notification, `installed` asks the service to restart onto a replaced binary.
pub fn spawn_auto_update(
    home: PathBuf,
    tell: impl Fn(&str, &str) + Send + 'static,
    installed: impl Fn(&Check) + Send + 'static,
) {
    let _ = std::thread::Builder::new()
        .name("auto-update".into())
        .spawn(move || {
            // Let the service settle first; a restart loop must not hammer the site.
            std::thread::sleep(std::time::Duration::from_secs(120));
            loop {
                let now = varsto_core::util::now_utc();
                match auto_step(&home, now, &tell, &installed) {
                    AutoStep::Retry(why) => log::info!("automatic update check: {why}"),
                    AutoStep::Installing(v) => log::info!("automatic update to {v} started"),
                    AutoStep::Told(v) => log::info!("automatic update check: {v} is out"),
                    AutoStep::Idle | AutoStep::Current => {}
                }
                // Hourly pass; the check itself runs once a day (AUTO_CHECKED).
                let wait = AUTO_RETRY_SECS;
                std::thread::sleep(std::time::Duration::from_secs(wait));
            }
        });
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

    /// A policy with no state file; `single` is --allow-single-source.
    fn pol(single: bool) -> Policy<'static> {
        Policy {
            home: None,
            allow_single_source: single,
            now: 1_000_000,
        }
    }

    fn release(sk: &SigningKey) -> (Fake, Check) {
        release_at(sk, 1)
    }

    /// A release whose checksum list was signed at `ts`.
    fn release_at(sk: &SigningKey, ts: i64) -> (Fake, Check) {
        let body = b"new release".to_vec();
        let sums = format!("{}  {ARCHIVE}\n", hex::encode(Sha256::digest(&body)));
        let sig = sign(
            sk,
            sums.as_bytes(),
            &format!("timestamp:{ts}\tfile:SHA256SUMS\tversion:9.9.9"),
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
        // GitHub unreachable: the signature suffices only when asked.
        let v = download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(true)).unwrap();
        assert_eq!(fs::read(&v.path).unwrap(), b"new release");
        assert!(v.notes.iter().any(|n| n.contains("not reachable")));
        // GitHub agrees.
        let sums = fake.files[&format!("{BASE}SHA256SUMS")].clone();
        fake.files.insert(github_url(), sums);
        let v = download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(false)).unwrap();
        assert!(v.notes.iter().any(|n| n.contains("GitHub release")));
    }

    #[test]
    fn update_refuses_without_a_valid_signature() {
        let (sk, pk) = test_key(7);
        let dir = tempfile::tempdir().unwrap();
        // No signature at all.
        let (mut fake, check) = release(&sk);
        fake.files.remove(&format!("{BASE}SHA256SUMS.sig"));
        let e = download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(true)).unwrap_err();
        assert!(format!("{e:#}").contains("not signed"), "{e:#}");
        assert!(!*fake.downloaded.borrow());
        // Signed by another key.
        let (other, _) = test_key(9);
        let (fake, check) = release(&other);
        assert!(download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(true)).is_err());
        assert!(!*fake.downloaded.borrow());
        // A checksum list changed after signing (archive swapped by the site).
        let (mut fake, check) = release(&sk);
        let evil = b"evil".to_vec();
        fake.files.insert(
            format!("{BASE}SHA256SUMS"),
            format!("{}  {ARCHIVE}\n", hex::encode(Sha256::digest(&evil))).into_bytes(),
        );
        fake.files.insert(format!("{BASE}{ARCHIVE}"), evil);
        assert!(download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(true)).is_err());
        // An archive that does not match the signed list.
        let (mut fake, check) = release(&sk);
        fake.files
            .insert(format!("{BASE}{ARCHIVE}"), b"evil".to_vec());
        let e = download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(true)).unwrap_err();
        assert!(format!("{e:#}").contains("checksum mismatch"), "{e:#}");
        // A signed list of another version (replayed old release).
        let (mut fake, mut check) = release(&sk);
        check.latest = "9.9.10".into();
        check.archive = Some("varsto-9.9.10-x86_64-unknown-linux-musl.tar.gz".into());
        fake.files.insert(
            format!("{BASE}varsto-9.9.10-x86_64-unknown-linux-musl.tar.gz"),
            b"x".to_vec(),
        );
        assert!(download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(true)).is_err());
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
        let e = download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(false)).unwrap_err();
        assert!(format!("{e:#}").contains("GitHub"), "{e:#}");
        assert!(!*fake.downloaded.borrow());
        let (mut fake, check) = release(&sk);
        fake.files
            .insert(github_url(), b"aa  something-else.zip\n".to_vec());
        assert!(download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(false)).is_err());
    }

    #[test]
    fn the_setup_program_is_picked_only_for_installed_copies() {
        let names = [
            "Varsto-9.9.9-setup.exe",
            "varsto-9.9.9-x86_64-unknown-linux-musl.tar.gz",
        ];
        let pick = |setup: bool, bundle: bool, target: &str| {
            pick_archive(names.iter().copied(), "9.9.9", target, bundle, setup)
        };
        let win = "x86_64-pc-windows-gnu";
        assert_eq!(
            pick(true, false, win).as_deref(),
            Some("Varsto-9.9.9-setup.exe")
        );
        // A portable copy is offered nothing: it has to run the installer once.
        assert_eq!(pick(false, false, win), None);
        // So is an installed copy of a release without a setup program (no zip fallback).
        let no_setup = ["varsto-9.9.9-x86_64-pc-windows-gnu.zip"];
        assert_eq!(
            pick_archive(no_setup.into_iter(), "9.9.9", win, false, true),
            None
        );
        // The setup program never serves another platform.
        assert_eq!(
            pick(false, false, "x86_64-unknown-linux-musl").as_deref(),
            Some("varsto-9.9.9-x86_64-unknown-linux-musl.tar.gz")
        );
        assert_eq!(pick(false, true, win), None);
    }

    #[test]
    fn a_portable_windows_copy_is_told_to_run_the_installer_once() {
        let check = Check {
            current: "0.0.1-alpha.14".into(),
            latest: "9.9.9".into(),
            available: false,
            newer: true,
            download_page: "https://example.invalid/downloads/".into(),
            archive: None,
            target: "x86_64-pc-windows-gnu".into(),
        };
        // The running test binary has no unins000.exe beside it: a copy the
        // setup program did not install.
        assert!(!installed_by_setup());
        let e = apply(&check, &Policy::new(Path::new("/nonexistent"), false))
            .unwrap_err()
            .to_string();
        assert!(e.contains("9.9.9 is out"), "{e}");
        assert!(e.contains("not installed with the setup program"), "{e}");
        assert!(
            e.contains("https://example.invalid/downloads/Varsto-9.9.9-setup.exe"),
            "{e}"
        );
        assert!(e.contains("updates continue automatically"), "{e}");
        assert!(!e.contains(".zip"), "{e}");
        // The notice is for Windows copies the setup program did not install, only.
        let notice = |target: &str, by_setup: bool| {
            windows_installer_notice(target, by_setup, "https://x/", "Varsto-1-setup.exe")
        };
        assert!(notice("x86_64-pc-windows-gnu", false).is_some());
        assert_eq!(notice("x86_64-pc-windows-gnu", true), None);
        assert_eq!(notice("x86_64-unknown-linux-musl", false), None);
        // A setup-installed copy gets the installer as its update file, and
        // a missing installer is not papered over with another file.
        let names = [
            "Varsto-9.9.9-setup.exe",
            "varsto-9.9.9-x86_64-pc-windows-gnu.zip",
        ];
        let pick = |setup| {
            pick_archive(
                names.iter().copied(),
                "9.9.9",
                "x86_64-pc-windows-gnu",
                false,
                setup,
            )
        };
        assert_eq!(pick(true).as_deref(), Some("Varsto-9.9.9-setup.exe"));
        assert_eq!(pick(false), None);
    }

    #[test]
    fn a_signed_setup_program_is_accepted_and_a_swapped_one_is_not() {
        let (sk, pk) = test_key(7);
        let dir = tempfile::tempdir().unwrap();
        let setup = "Varsto-9.9.9-setup.exe";
        let body = b"setup program".to_vec();
        let sums = format!("{}  {setup}\n", hex::encode(Sha256::digest(&body)));
        let sig = sign(
            &sk,
            sums.as_bytes(),
            "timestamp:1\tfile:SHA256SUMS\tversion:9.9.9",
        );
        let mut files = HashMap::new();
        files.insert(format!("{BASE}{setup}"), body);
        files.insert(format!("{BASE}SHA256SUMS"), sums.into_bytes());
        files.insert(format!("{BASE}SHA256SUMS.sig"), sig.into_bytes());
        let fake = Fake {
            files,
            downloaded: RefCell::new(false),
        };
        let check = Check {
            current: "0.0.1".into(),
            latest: "9.9.9".into(),
            available: true,
            newer: true,
            download_page: BASE.into(),
            archive: Some(setup.into()),
            target: "x86_64-pc-windows-gnu".into(),
        };
        assert!(check.installer());
        let v = download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(true)).unwrap();
        assert_eq!(fs::read(&v.path).unwrap(), b"setup program");
        // The same file name for another version is refused.
        let mut other = check.clone();
        other.archive = Some("Varsto-9.9.8-setup.exe".into());
        assert!(download_verified(&fake, BASE, &pk, &other, dir.path(), &pol(true)).is_err());
        // A swapped download does not match the signed checksum.
        let mut swapped = Fake {
            files: fake.files.clone(),
            downloaded: RefCell::new(false),
        };
        swapped
            .files
            .insert(format!("{BASE}{setup}"), b"evil".to_vec());
        let e = download_verified(&swapped, BASE, &pk, &check, dir.path(), &pol(true)).unwrap_err();
        assert!(format!("{e:#}").contains("checksum mismatch"), "{e:#}");
    }

    #[test]
    fn the_setup_program_runs_silently_and_closes_varsto() {
        let args = setup_args(Path::new("C:\\t\\setup.log"));
        for want in [
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/CLOSEAPPLICATIONS",
        ] {
            assert!(args.iter().any(|a| a == want), "{want}");
        }
        assert!(args.iter().any(|a| a.starts_with("/LOG=")));
    }

    #[test]
    fn the_daily_check_can_be_turned_off() {
        let dir = tempfile::tempdir().unwrap();
        assert!(auto_update_enabled(dir.path()));
        set_auto_update(dir.path(), false).unwrap();
        assert!(!auto_update_enabled(dir.path()));
        // Off: not even a network call (the step returns before check()).
        let told = RefCell::new(0);
        let step = auto_step(
            dir.path(),
            10_000_000,
            &|_, _| *told.borrow_mut() += 1,
            &|_| {},
        );
        assert_eq!(step, AutoStep::Idle);
        assert_eq!(*told.borrow(), 0);
        set_auto_update(dir.path(), true).unwrap();
        assert!(auto_update_enabled(dir.path()));
        // On, but checked a moment ago: idle as well.
        fs::write(dir.path().join(AUTO_CHECKED), "9999990").unwrap();
        let step = auto_step(dir.path(), 10_000_000, &|_, _| {}, &|_| {});
        assert_eq!(step, AutoStep::Idle);
    }

    #[test]
    fn site_override() {
        // Only the default is checked here: the variable is process-wide.
        if std::env::var_os(SITE_ENV).is_none() {
            assert_eq!(downloads_base(), format!("{DEFAULT_SITE}/downloads/"));
        }
    }

    #[test]
    fn update_waits_when_github_does_not_answer() {
        let (sk, pk) = test_key(7);
        let dir = tempfile::tempdir().unwrap();
        let (fake, check) = release(&sk);
        let e = download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(false)).unwrap_err();
        let e = format!("{e:#}");
        assert!(
            e.contains("postponed") && e.contains("--allow-single-source"),
            "{e}"
        );
        assert!(
            !*fake.downloaded.borrow(),
            "nothing downloaded before the cross-check"
        );
    }

    #[test]
    fn update_refuses_a_checksum_list_older_than_the_last_accepted() {
        let (sk, pk) = test_key(7);
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let policy = Policy {
            home: Some(home.path()),
            allow_single_source: true,
            now: 1_000_000,
        };
        let go = |ts: i64| {
            let (fake, check) = release_at(&sk, ts);
            let r = download_verified(&fake, BASE, &pk, &check, dir.path(), &policy);
            let downloaded = *fake.downloaded.borrow();
            (r, downloaded)
        };
        assert!(go(500).0.is_ok());
        assert_eq!(State::load(home.path()).last_timestamp, 500);
        // An older signed list: valid signature, replayed release.
        let (r, downloaded) = go(400);
        let e = format!("{:#}", r.unwrap_err());
        assert!(e.contains("older") && e.contains("rollback"), "{e}");
        assert!(!downloaded);
        assert_eq!(
            State::load(home.path()).last_timestamp,
            500,
            "the line did not move back"
        );
        // The same time and newer ones are fine and move the line forward.
        assert!(go(500).0.is_ok());
        assert!(go(900).0.is_ok());
        assert_eq!(State::load(home.path()).last_timestamp, 900);
        // A refusal for another reason leaves the line where it was.
        let (mut fake, check) = release_at(&sk, 2000);
        fake.files
            .insert(format!("{BASE}{ARCHIVE}"), b"evil".to_vec());
        assert!(download_verified(&fake, BASE, &pk, &check, dir.path(), &policy).is_err());
        assert_eq!(State::load(home.path()).last_timestamp, 900);
    }

    #[test]
    fn a_signed_list_that_is_months_old_is_reported() {
        let (sk, pk) = test_key(7);
        let dir = tempfile::tempdir().unwrap();
        let (fake, check) = release_at(&sk, 10);
        let policy = Policy {
            home: None,
            allow_single_source: true,
            now: 10 + 100 * 86_400,
        };
        let v = download_verified(&fake, BASE, &pk, &check, dir.path(), &policy).unwrap();
        assert!(
            v.notes.iter().any(|n| n.contains("100 days old")),
            "{:?}",
            v.notes
        );
    }

    #[test]
    fn the_same_or_an_older_version_is_never_installed() {
        let (sk, pk) = test_key(7);
        let dir = tempfile::tempdir().unwrap();
        let (fake, mut check) = release(&sk);
        let me = env!("CARGO_PKG_VERSION");
        assert_eq!(MIN_ACCEPTED_VERSION, me);
        for v in [me, "0.0.1-alpha.1"] {
            check.latest = v.into();
            let e =
                download_verified(&fake, BASE, &pk, &check, dir.path(), &pol(true)).unwrap_err();
            assert!(format!("{e:#}").contains("not newer"), "{e:#}");
        }
        assert!(!*fake.downloaded.borrow());
    }

    fn manifest_fake(sk: &SigningKey, version: &str, signed_version: &str) -> Fake {
        let manifest = format!("{{\"_version\": \"{version}\", \"varsto-{version}-x86_64-unknown-linux-musl.tar.gz\": {{}}}}");
        let sig = sign(
            sk,
            manifest.as_bytes(),
            &format!("timestamp:1\tfile:manifest.json\tversion:{signed_version}"),
        );
        let mut files = HashMap::new();
        files.insert(format!("{BASE}manifest.json"), manifest.into_bytes());
        files.insert(format!("{BASE}manifest.json.minisig"), sig.into_bytes());
        Fake {
            files,
            downloaded: RefCell::new(false),
        }
    }

    #[test]
    fn the_manifest_must_carry_the_release_signature() {
        let (sk, pk) = test_key(7);
        // Signed: trusted.
        let fake = manifest_fake(&sk, "9.9.9", "9.9.9");
        let c = check_with(&fake, BASE, &pk).unwrap();
        assert_eq!(c.latest, "9.9.9");
        assert!(c.newer);
        // No signature file at all.
        let mut fake = manifest_fake(&sk, "9.9.9", "9.9.9");
        fake.files.remove(&format!("{BASE}manifest.json.minisig"));
        let e = check_with(&fake, BASE, &pk).unwrap_err();
        assert!(format!("{e:#}").contains("not signed"), "{e:#}");
        // Changed after signing (a newer-looking version injected).
        let mut fake = manifest_fake(&sk, "9.9.9", "9.9.9");
        let m = String::from_utf8(fake.files[&format!("{BASE}manifest.json")].clone())
            .unwrap()
            .replace("9.9.9", "9.9.10");
        fake.files
            .insert(format!("{BASE}manifest.json"), m.into_bytes());
        assert!(check_with(&fake, BASE, &pk).is_err());
        // Signed by another key.
        let (other, _) = test_key(9);
        assert!(check_with(&manifest_fake(&other, "9.9.9", "9.9.9"), BASE, &pk).is_err());
        // A genuine signature for another version (an old manifest replayed).
        let e = check_with(&manifest_fake(&sk, "9.9.9", "9.9.8"), BASE, &pk).unwrap_err();
        assert!(
            format!("{e:#}").contains("signed manifest is for version"),
            "{e:#}"
        );
    }

    // ----- the daily channel -------------------------------------------------

    const DBASE: &str = "https://example.invalid/daily/latest/";
    const DFILE: &str = "varsto-daily-linux-x86_64.tar.gz";
    const BUILD: &str = "20261016-316c579";

    /// The tests' daily list, signed with `sk`; `trusted` is the signed comment.
    fn daily_files(sk: &SigningKey, body: &[u8], trusted: &str) -> Fake {
        let sums = format!(
            "{}  {DFILE}\n{}  {DAILY_SETUP}\n",
            hex::encode(Sha256::digest(body)),
            hex::encode(Sha256::digest(b"setup"))
        );
        let sig = sign(sk, sums.as_bytes(), trusted);
        let mut files = HashMap::new();
        files.insert(format!("{DBASE}{DFILE}"), body.to_vec());
        files.insert(format!("{DBASE}SHA256SUMS"), sums.into_bytes());
        files.insert(format!("{DBASE}SHA256SUMS.sig"), sig.into_bytes());
        Fake {
            files,
            downloaded: RefCell::new(false),
        }
    }

    fn daily_comment(ts: i64, build: &str) -> String {
        format!("timestamp:{ts}\tfile:SHA256SUMS\tchannel:daily\tbuild:{build}")
    }

    fn dpol(home: &Path) -> Policy<'_> {
        Policy {
            home: Some(home),
            allow_single_source: false,
            now: 3_000_000,
        }
    }

    #[test]
    fn the_embedded_daily_key_is_not_the_release_key() {
        let (d, r) = (daily_key(), release_key());
        assert_eq!(d.id_hex().len(), 16);
        assert_ne!(d.id, r.id);
        assert_ne!(d.key.as_bytes(), r.key.as_bytes());
        assert_eq!(d.label, "daily");
        assert_eq!(r.label, "release");
    }

    #[test]
    fn a_daily_signature_is_not_a_stable_one_and_the_other_way_round() {
        let (daily_sk, daily_pk) = test_key(9);
        let (rel_sk, rel_pk) = test_key(7);
        let home = tempfile::tempdir().unwrap();
        // The daily key signs the daily list: the daily check accepts it ...
        let fake = daily_files(&daily_sk, b"build", &daily_comment(900_000, BUILD));
        let c = check_daily_with(&fake, DBASE, &daily_pk, &dpol(home.path())).unwrap();
        assert_eq!(c.latest_build, BUILD);
        // ... and the stable verifier (the release key) refuses the same bytes.
        let sums = &fake.files[&format!("{DBASE}SHA256SUMS")];
        let sig = String::from_utf8(fake.files[&format!("{DBASE}SHA256SUMS.sig")].clone()).unwrap();
        assert!(verify_signature(&rel_pk, sums, &sig).is_err());
        // A stable-signed list handed to the daily check is refused too.
        let fake = daily_files(&rel_sk, b"build", &daily_comment(900_000, BUILD));
        assert!(check_daily_with(&fake, DBASE, &daily_pk, &dpol(home.path())).is_err());
        // The whole stable download path refuses a list signed by the daily key.
        let (daily_signed, check) = release(&daily_sk);
        let dir = tempfile::tempdir().unwrap();
        let e = download_verified(&daily_signed, BASE, &rel_pk, &check, dir.path(), &pol(true))
            .unwrap_err();
        assert!(
            format!("{e:#}").contains("valid release signature"),
            "{e:#}"
        );
        assert!(!*daily_signed.downloaded.borrow());
        // Even the right key, but a comment that says nothing about the daily
        // channel (the release format), is no daily list.
        let fake = daily_files(
            &daily_sk,
            b"build",
            "timestamp:900000\tfile:SHA256SUMS\tversion:9.9.9",
        );
        let e = check_daily_with(&fake, DBASE, &daily_pk, &dpol(home.path())).unwrap_err();
        assert!(
            format!("{e:#}").contains("not for the daily channel"),
            "{e:#}"
        );
        // Another file name or build id in the signed comment.
        let fake = daily_files(
            &daily_sk,
            b"build",
            "timestamp:900000\tfile:manifest.json\tchannel:daily\tbuild:20261016-316c579",
        );
        assert!(check_daily_with(&fake, DBASE, &daily_pk, &dpol(home.path())).is_err());
        let fake = daily_files(&daily_sk, b"build", &daily_comment(900_000, "latest"));
        assert!(check_daily_with(&fake, DBASE, &daily_pk, &dpol(home.path())).is_err());
    }

    #[test]
    fn the_daily_list_must_be_signed_and_unchanged() {
        let (sk, pk) = test_key(9);
        let home = tempfile::tempdir().unwrap();
        let mut fake = daily_files(&sk, b"build", &daily_comment(900_000, BUILD));
        fake.files.remove(&format!("{DBASE}SHA256SUMS.sig"));
        let e = check_daily_with(&fake, DBASE, &pk, &dpol(home.path())).unwrap_err();
        assert!(format!("{e:#}").contains("not signed"), "{e:#}");
        // A list swapped after signing.
        let mut fake = daily_files(&sk, b"build", &daily_comment(900_000, BUILD));
        let other = format!("{}  {DFILE}\n", "0".repeat(64));
        fake.files
            .insert(format!("{DBASE}SHA256SUMS"), other.into_bytes());
        assert!(check_daily_with(&fake, DBASE, &pk, &dpol(home.path())).is_err());
        // The comment edited to name another build.
        let mut fake = daily_files(&sk, b"build", &daily_comment(900_000, BUILD));
        let sig = String::from_utf8(fake.files[&format!("{DBASE}SHA256SUMS.sig")].clone())
            .unwrap()
            .replace("316c579", "abcdef0");
        fake.files
            .insert(format!("{DBASE}SHA256SUMS.sig"), sig.into_bytes());
        assert!(check_daily_with(&fake, DBASE, &pk, &dpol(home.path())).is_err());
    }

    #[test]
    fn a_stale_replayed_or_future_daily_list_is_refused() {
        let (sk, pk) = test_key(9);
        let home = tempfile::tempdir().unwrap();
        let now = 3_000_000;
        let ok = daily_files(&sk, b"build", &daily_comment(now - 3600, BUILD));
        check_daily_with(&ok, DBASE, &pk, &dpol(home.path())).unwrap();
        // Older than the last accepted list: a rollback, per channel.
        State {
            last_timestamp: now - 100,
            last_version: "20261015-aaaaaaa".into(),
        }
        .save_file(home.path(), DAILY_STATE_FILE)
        .unwrap();
        let e = check_daily_with(&ok, DBASE, &pk, &dpol(home.path())).unwrap_err();
        assert!(format!("{e:#}").contains("older"), "{e:#}");
        // The stable state file is not the daily one: it moves nothing here.
        let home2 = tempfile::tempdir().unwrap();
        State {
            last_timestamp: now,
            last_version: "9.9.9".into(),
        }
        .save(home2.path())
        .unwrap();
        check_daily_with(&ok, DBASE, &pk, &dpol(home2.path())).unwrap();
        // A month old: frozen or replayed.
        let old = daily_files(
            &sk,
            b"build",
            &daily_comment(now - DAILY_MAX_AGE_SECS - 10, BUILD),
        );
        let e = check_daily_with(&old, DBASE, &pk, &dpol(home2.path())).unwrap_err();
        assert!(format!("{e:#}").contains("days old"), "{e:#}");
        // Signed in the future.
        let future = daily_files(
            &sk,
            b"build",
            &daily_comment(now + DAILY_FUTURE_SECS + 10, BUILD),
        );
        let e = check_daily_with(&future, DBASE, &pk, &dpol(home2.path())).unwrap_err();
        assert!(format!("{e:#}").contains("future"), "{e:#}");
    }

    #[test]
    fn a_build_older_than_the_installed_daily_build_is_refused() {
        let (sk, pk) = test_key(9);
        let home = tempfile::tempdir().unwrap();
        record_daily(home.path(), "20261016-316c579", 900_000).unwrap();
        let list = |build: &str, ts: i64| daily_files(&sk, b"b", &daily_comment(ts, build));
        let check = |f: &Fake| check_daily_with(f, DBASE, &pk, &dpol(home.path()));
        // Older day: refused, whatever the signing time says.
        let e = check(&list("20261015-1111111", 990_000)).unwrap_err();
        assert!(
            format!("{e:#}").contains("older than the installed build"),
            "{e:#}"
        );
        // The same build: up to date.
        let c = check(&list("20261016-316c579", 995_000)).unwrap();
        assert!(!c.newer && !c.available);
        // Another build of the same day: newer only when signed later.
        assert!(!check(&list("20261016-2222222", 899_000)).unwrap().newer);
        assert!(check(&list("20261016-2222222", 950_000)).unwrap().newer);
        // A later day.
        let c = check(&list("20261017-3333333", 960_000)).unwrap();
        assert!(c.newer);
        assert_eq!(c.current_build.as_deref(), Some("20261016-316c579"));
        // Not installed from daily: any signed build is an update.
        let fresh = tempfile::tempdir().unwrap();
        let c = check_daily_with(
            &list("20250101-4444444", 960_000),
            DBASE,
            &pk,
            &dpol(fresh.path()),
        )
        .unwrap();
        assert!(c.newer && c.current_build.is_none());
    }

    #[test]
    fn a_daily_download_is_checked_against_the_signed_list() {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return; // the file name is picked per platform
        }
        let (sk, pk) = test_key(9);
        let home = tempfile::tempdir().unwrap();
        let fake = daily_files(&sk, b"daily bits", &daily_comment(900_000, BUILD));
        let c = check_daily_with(&fake, DBASE, &pk, &dpol(home.path())).unwrap();
        assert!(c.available);
        let dir = tempfile::tempdir().unwrap();
        let v = download_daily_verified(&fake, DBASE, &c, dir.path(), &dpol(home.path())).unwrap();
        assert_eq!(fs::read(&v.path).unwrap(), b"daily bits");
        // Only the daily state moved.
        assert_eq!(
            State::load_file(home.path(), DAILY_STATE_FILE).last_timestamp,
            900_000
        );
        assert!(!home.path().join(STATE_FILE).exists());
        // A swapped file (the site changed it after the list was signed).
        let home = tempfile::tempdir().unwrap();
        let mut bad = daily_files(&sk, b"daily bits", &daily_comment(900_000, BUILD));
        bad.files
            .insert(format!("{DBASE}{DFILE}"), b"evil bits".to_vec());
        let c = check_daily_with(&bad, DBASE, &pk, &dpol(home.path())).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let e =
            download_daily_verified(&bad, DBASE, &c, dir.path(), &dpol(home.path())).unwrap_err();
        assert!(format!("{e:#}").contains("checksum mismatch"), "{e:#}");
        // A failed check does not move the line.
        assert!(!home.path().join(DAILY_STATE_FILE).exists());
    }

    #[test]
    fn the_daily_file_per_platform() {
        assert_eq!(
            daily_file("linux", "x86_64", false, false),
            Ok("varsto-daily-linux-x86_64.tar.gz")
        );
        // A Windows copy the setup program did not install is sent to the installer.
        let e = daily_file("windows", "x86_64", false, false).unwrap_err();
        assert!(e.contains("not installed with the setup program"), "{e}");
        assert!(e.contains(DAILY_SETUP), "{e}");
        assert!(!e.contains(".zip"), "{e}");
        assert_eq!(
            daily_file("windows", "x86_64", false, true),
            Ok(DAILY_SETUP)
        );
        assert!(is_setup_file(DAILY_SETUP));
        // The disk image and the Android and iOS packages are not installed by the CLI.
        let e = daily_file("macos", "aarch64", true, false).unwrap_err();
        assert!(e.contains("disk image"), "{e}");
        assert!(daily_file("macos", "aarch64", false, false).is_err());
        assert!(daily_file("android", "aarch64", false, false).is_err());
        assert!(daily_file("linux", "aarch64", false, false).is_err());
    }

    #[test]
    fn a_daily_install_remembers_its_channel_and_a_release_forgets_it() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(channel_note(home.path()), None);
        record_daily(home.path(), BUILD, 900_000).unwrap();
        assert_eq!(
            channel_note(home.path()).as_deref(),
            Some("daily build 20261016-316c579")
        );
        // A damaged or foreign record is no channel.
        fs::write(
            home.path().join(CHANNEL_FILE),
            b"{\"channel\":\"daily\",\"build\":\"x\",\"signed_at\":1,\"version\":\"1\"}",
        )
        .unwrap();
        assert_eq!(channel_note(home.path()), None);
        fs::write(home.path().join(CHANNEL_FILE), b"nonsense").unwrap();
        assert_eq!(channel_note(home.path()), None);
        record_daily(home.path(), BUILD, 900_000).unwrap();
        clear_channel(home.path());
        assert_eq!(channel_note(home.path()), None);
        assert!(valid_build_id("20261016-316c579"));
        assert!(!valid_build_id("20261016"));
        assert!(!valid_build_id("2026101-316c579"));
        assert!(!valid_build_id("20261016-XYZ1234"));
    }

    #[test]
    fn going_back_to_releases_from_a_daily_build_is_explained() {
        let home = tempfile::tempdir().unwrap();
        let (_, mut check) = release(&test_key(7).0);
        check.newer = false;
        assert!(stable_hint(home.path(), &check).is_none());
        record_daily(home.path(), BUILD, 900_000).unwrap();
        let h = stable_hint(home.path(), &check).unwrap();
        assert!(h.contains(BUILD) && h.contains("by hand"), "{h}");
        check.newer = true;
        assert!(stable_hint(home.path(), &check).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn an_archive_replaces_the_binary_atomically() {
        let work = tempfile::tempdir().unwrap();
        let src = work.path().join("src/varsto-daily");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("varsto"), b"new binary").unwrap();
        let pack = |name: &str| {
            let archive = work.path().join(name);
            let st = std::process::Command::new("tar")
                .arg("-czf")
                .arg(&archive)
                .arg("-C")
                .arg(work.path().join("src"))
                .arg("varsto-daily")
                .status()
                .unwrap();
            assert!(st.success());
            archive
        };
        let archive = pack("a.tar.gz");
        let exe = work.path().join("bin-varsto");
        fs::write(&exe, b"old binary").unwrap();
        let tmp = tempfile::tempdir().unwrap();
        install_archive(&archive, tmp.path(), &exe).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"new binary");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
            0o755
        );
        // No staging file is left, and an archive without the binary changes nothing.
        assert!(!work.path().join("bin-varsto.new").exists());
        fs::remove_file(src.join("varsto")).unwrap();
        fs::write(src.join("other"), b"x").unwrap();
        let empty = pack("b.tar.gz");
        let tmp2 = tempfile::tempdir().unwrap();
        assert!(install_archive(&empty, tmp2.path(), &exe).is_err());
        assert_eq!(fs::read(&exe).unwrap(), b"new binary");
    }

    #[test]
    fn the_signing_script_signs_what_the_daily_key_verifies() {
        // The list of the first signed daily build and the signature that
        // scripts/sign-daily.sh made for it with the real daily key (public
        // data: the file served at daily/latest/).
        let sums = "e881f985e35d755f184c85e00a349ec9f99ea181a5963263b0dbd3bea605b355  varsto-daily-linux-x86_64.tar.gz\ncc3d46bb3f395f77a0ccfa946ce3a89bfd433e35381eda95a8257af0be0dcf20  varsto-daily-android-debug.apk\n21030bd4b1e8a1985e517cba30cba92f8f23f9f60a38ec9372658298bd82c24d  varsto-daily-windows-setup.exe\n33af812cf359115867bbd16ac66919e6162a41b3bc63aa5780cbf81664578487  varsto-daily-windows-x86_64.zip\nea6b57df15c5089c3392071b1e2d94896219052075e35b81c60b2477d48a1f4f  varsto-daily-macos-apple-silicon.dmg\ne6d57201ca60c8e813160b359c62cb0372b1e46b9a30570382dd98235712a64b  varsto-daily-ios-unsigned.ipa\n";
        let sig = "untrusted comment: signature from the Varsto daily key\nRURxphXBFtyFQxIc8Bbm9D4n5+5aoJsBpOvVUJf6ujO9Cg9XsJT/MGK+DZ+P4QRw7i1ccCCA2klnfilOcmhUy9Pw+zK1Tvb4Eg0=\ntrusted comment: timestamp:1792145768	file:SHA256SUMS	channel:daily	build:20261016-316c579\nBTXQZQZolP8XiWbBj8r+EtJQ7BQHvG4/cXekbHxdFxB4X0Ytofox8i2zOxX9J1zHw3fxotQFGwTBK8u0VikuBw==\n";
        let key = daily_key();
        let trusted = verify_signature(&key, sums.as_bytes(), sig).unwrap();
        assert_eq!(trusted_field(&trusted, "channel"), Some("daily"));
        assert_eq!(trusted_field(&trusted, "file"), Some("SHA256SUMS"));
        assert_eq!(trusted_field(&trusted, "build"), Some("20261016-316c579"));
        // The release key does not accept it, and a changed list is refused.
        assert!(verify_signature(&release_key(), sums.as_bytes(), sig).is_err());
        assert!(verify_signature(&key, sums.replace('e', "f").as_bytes(), sig).is_err());
        // The same bytes pass the whole daily check (with a clock near the signing time).
        let mut files = HashMap::new();
        files.insert(format!("{DBASE}SHA256SUMS"), sums.as_bytes().to_vec());
        files.insert(format!("{DBASE}SHA256SUMS.sig"), sig.as_bytes().to_vec());
        let fake = Fake {
            files,
            downloaded: RefCell::new(false),
        };
        let home = tempfile::tempdir().unwrap();
        let policy = Policy {
            home: Some(home.path()),
            allow_single_source: false,
            now: 1_792_145_768 + 3600,
        };
        let c = check_daily_with(&fake, DBASE, &key, &policy).unwrap();
        assert_eq!(c.latest_build, "20261016-316c579");
        assert!(c.newer);
    }
}
