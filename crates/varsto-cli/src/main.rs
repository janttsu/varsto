// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto`: command-line interface (alpha-0). Every command has a `--json`
//! output for scripts (P-004); exit codes: 0 ok, 1 failure, 2 usage.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

mod desktop;
mod icon;
mod mcp;
mod service;
mod tray;
mod update;
mod upkeep;
mod view;

#[derive(Parser)]
#[command(
    name = "varsto",
    version,
    about = "End-to-end encrypted sync with your own storage (alpha)"
)]
struct Cli {
    /// Device directory holding keys, ledger and state.
    #[arg(long, env = "VARSTO_HOME", global = true)]
    home: Option<PathBuf>,
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault on this device and print the vault key once.
    Init {
        #[arg(long)]
        name: String,
    },
    /// Join an existing vault through a storage that holds it.
    Join {
        #[arg(long)]
        name: String,
        /// Vault key in hex (from `init`), or use --words.
        #[arg(long, conflicts_with = "words")]
        vault_key: Option<String>,
        /// The 24 words of the recovery kit instead of the hex key.
        #[arg(long)]
        words: Option<String>,
        /// Name for the storage on this device.
        #[arg(long, default_value = "primary")]
        storage_name: String,
        /// Local directory of the storage that holds the vault (or use the --s3-* options).
        #[arg(long, required_unless_present = "s3_bucket")]
        storage_path: Option<PathBuf>,
        /// Join through an S3-compatible bucket instead of a directory.
        #[arg(long, requires = "s3_endpoint")]
        s3_bucket: Option<String>,
        #[arg(long)]
        s3_endpoint: Option<String>,
        #[arg(long, default_value = "us-east-1")]
        s3_region: String,
        #[arg(long, default_value = "")]
        s3_prefix: String,
        #[arg(long)]
        s3_access_key_id: Option<String>,
        /// Secret access key; read from VARSTO_S3_SECRET if omitted.
        #[arg(long, env = "VARSTO_S3_SECRET", hide_env_values = true)]
        s3_secret_access_key: Option<String>,
    },
    /// Manage storages.
    Storage {
        #[command(subcommand)]
        cmd: StorageCmd,
    },
    /// Removable disks of a disk pool: add, list, check, eject, retire.
    Disk {
        #[command(subcommand)]
        cmd: DiskCmd,
    },
    /// Manage folders.
    Folder {
        #[command(subcommand)]
        cmd: FolderCmd,
    },
    /// Upload local changes and publish the manifest.
    Push { folder: String },
    /// Fetch other devices' changes and apply them.
    Pull { folder: String },
    /// Pull then push, for one folder or all attached folders.
    Sync { folder: Option<String> },
    /// Show vault, devices, storages and folders.
    Status,
    /// Compare the ledger with the storages; --verify downloads and hashes every chunk.
    Fsck {
        #[arg(long)]
        verify: bool,
    },
    /// List duplicate files in a folder.
    Dupes { folder: String },
    /// List ledger batches.
    Ledger,
    /// Start the background service and open the desktop interface in your browser (default when run without arguments).
    Desktop {
        /// Port on 127.0.0.1 (0 = pick a free one).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Do not open a browser automatically.
        #[arg(long)]
        no_open: bool,
        /// Seconds between periodic syncs (changes are synced within seconds anyway).
        #[arg(long, default_value_t = 300)]
        interval: u64,
    },
    /// Background service: watches folders, syncs on change and on a timer, serves the local API.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Desktop app: system tray icon that runs and supervises the background service (Linux, Windows).
    Tray {
        #[arg(long, default_value_t = 300)]
        interval: u64,
        /// Open the desktop interface right away.
        #[arg(long)]
        open: bool,
    },
    /// Share a folder with another Varsto user, or accept a folder shared with you.
    Share {
        #[command(subcommand)]
        cmd: ShareCmd,
    },
    /// Untrusted replica: hold and verify a vault's encrypted objects without any key to open them.
    Replica {
        #[command(subcommand)]
        cmd: ReplicaCmd,
    },
    /// Check for a new release and install it over this binary.
    Update {
        /// Only report whether an update exists.
        #[arg(long)]
        check: bool,
    },
    /// Alpha: forget this device's vault configuration (keys, ledger, state, grants) and start over. Files in folders stay.
    Reset {
        #[arg(long)]
        yes: bool,
    },
    /// Devices of the vault: list them, or remove a lost or stolen one.
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Pair devices with a one-time code instead of copying the vault key.
    Pair {
        #[command(subcommand)]
        cmd: PairCmd,
    },
    /// Recovery kit: the vault key as 24 words, optionally split into shares.
    Recovery {
        #[command(subcommand)]
        cmd: RecoveryCmd,
    },
    /// Strongroom folders: opened only with a touch of your FIDO2 security key.
    Strongroom {
        #[command(subcommand)]
        cmd: StrongroomCmd,
    },
    /// Peer-to-peer transfer of encrypted blocks between your devices (LAN and internet).
    P2p {
        #[command(subcommand)]
        cmd: P2pCmd,
    },
    /// Durability policies: "two cloud copies and one at home, verified within 30 days".
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// MCP server for AI assistants (stdio), with per-folder grants.
    Mcp {
        #[command(subcommand)]
        cmd: Option<McpCmd>,
    },
    /// Automatic verification of blocks other devices wrote: show, run now, set the schedule.
    Verify {
        #[command(subcommand)]
        cmd: Option<upkeep::VerifyCmd>,
    },
    /// Placement advice: idle files, storage prices, monthly costs, and suggestions to apply.
    Advice {
        /// Files not used for this many days count as idle.
        #[arg(long, default_value_t = 90, global = true)]
        idle_days: i64,
        #[command(subcommand)]
        cmd: Option<upkeep::AdviceCmd>,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// List the full devices of the vault (removed ones are marked).
    List,
    /// Remove another device: it is cut off from the ledger and from peers, and
    /// the vault gets new keys that it never sees. What it already held stays
    /// readable to it.
    Revoke {
        /// Device name or id (see `varsto device list`).
        device: String,
        /// Also order the device to delete its keys, sync state and folder
        /// contents when it next reaches a storage.
        #[arg(long)]
        wipe: bool,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum PairCmd {
    /// On a device that holds the vault: show a code and wait for the new device.
    Offer,
    /// On the new device: join the vault of the device showing the code.
    Join {
        #[arg(long)]
        name: String,
        /// The nine digits shown on the other device.
        #[arg(long)]
        code: String,
        /// The other device's address (host:port) when it is not found on the LAN.
        #[arg(long)]
        address: Option<String>,
    },
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Print the printable kit (24 words; with --shares also 3 shares of which 2 rebuild the key).
    Kit {
        #[arg(long)]
        shares: bool,
    },
    /// Rebuild the vault key from shares (`"<index>: <24 words>"` each).
    Combine {
        #[arg(required = true, num_args = 2..)]
        shares: Vec<String>,
    },
}

#[derive(Subcommand)]
enum StrongroomCmd {
    /// Create a Strongroom folder (two touches of the key). Needs the libfido2 tools (fido2-cred, fido2-assert).
    Create {
        name: String,
        path: PathBuf,
        /// Use a software key file instead of hardware: for trying the flow only, no real protection.
        #[arg(long)]
        software: bool,
        #[arg(long, default_value_t = 15)]
        minutes: u64,
    },
    /// Unlock for a while (one touch); the running background service gets the key too.
    Unlock {
        folder: String,
        #[arg(long, default_value_t = 15)]
        minutes: u64,
    },
    /// Forget the key now (also in the running service).
    Lock {
        folder: String,
    },
    Status,
    /// Turn an existing folder into a Strongroom: new key wrapped by the security key (two touches), content re-encrypted, old copies deleted from the storages. Run it again to resume an interrupted conversion (one touch).
    Convert {
        folder: String,
        /// Use a software key file instead of hardware: for trying the flow only, no real protection.
        #[arg(long)]
        software: bool,
        #[arg(long, default_value_t = 15)]
        minutes: u64,
        /// Also replace this device's plain copies with placeholders once the conversion is done.
        #[arg(long)]
        free: bool,
    },
    /// Enrol a backup security key (one touch of an enrolled key, then two of the new one).
    AddKey {
        folder: String,
        /// A name for the key, e.g. "safe".
        #[arg(long, default_value = "")]
        label: String,
        /// The new key is a software key file (testing only).
        #[arg(long)]
        software: bool,
        /// libfido2 device path of the new key (default: ask to swap keys, then the first key found).
        #[arg(long)]
        device: Option<String>,
    },
    /// List the security keys enrolled for a Strongroom.
    Keys {
        folder: String,
    },
    /// Remove an enrolled key (by number, label or credential); the last key always stays.
    RemoveKey {
        folder: String,
        key: String,
    },
}

#[derive(Subcommand)]
enum P2pCmd {
    /// Enable: the background service serves this device's blocks and pulls from peers.
    Enable {
        /// Listening port (default: a fixed port is easier to forward).
        #[arg(long, default_value_t = 17893)]
        port: u16,
        /// Address other devices reach this one at over the internet (host:port), repeatable.
        #[arg(long = "public")]
        public_addrs: Vec<std::net::SocketAddr>,
        /// STUN server (host:port) asked for the public UDP address, repeatable (default: three public servers).
        #[arg(long = "stun")]
        stun: Vec<String>,
        /// Ask no STUN server at all (no public address is learned; relays and LAN still work).
        #[arg(long, conflicts_with = "stun")]
        no_stun: bool,
    },
    Disable,
    /// Show settings, NAT guess, public address and the path to every peer.
    Status,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Set a folder's policy (replaces the previous one) and publish it to every device.
    Set {
        folder: String,
        /// Minimum copies on any non-carrier storage.
        #[arg(long, default_value_t = 0)]
        min_copies: u32,
        /// Minimum copies per place, e.g. --place cloud=2 --place home=1.
        #[arg(long = "place")]
        places: Vec<String>,
        /// Every chunk must be verified by another device within this many days.
        #[arg(long)]
        verified_within_days: Option<u32>,
    },
    /// Remove a folder's policy.
    Clear { folder: String },
    /// Show policies.
    Show,
    /// Evaluate every policy from the ledger. Exit code: 0 ok, 1 at risk, 2 violated, 3 unknown.
    Check,
}

#[derive(Subcommand)]
enum McpCmd {
    /// Serve MCP over stdin/stdout (default). Point your assistant at `varsto --home <dir> mcp`.
    Serve,
    /// Let the assistant see a folder (or `all`); --write also allows moving and renaming files.
    Grant {
        folder: String,
        #[arg(long)]
        write: bool,
    },
    /// Remove a grant (or `all`).
    Revoke { folder: String },
    /// Show current grants.
    List,
}

#[derive(Subcommand)]
enum ShareCmd {
    /// (Recipient) Print a request code for this device; the owner seals the share token to it.
    Request,
    /// (Owner) Print a share token for a folder. With --to <request-code> the folder key is
    /// encapsulated to the recipient (hybrid X25519 + ML-KEM-768) and the token is safe to send
    /// over any channel; without it the key is in the token and the channel must be secure.
    Create {
        folder: String,
        #[arg(long)]
        to: Option<String>,
    },
    /// (Recipient) Accept a shared folder into a new device directory (one per shared vault).
    Accept {
        #[arg(long)]
        name: String,
        #[arg(long)]
        token: String,
        /// Storage directory that both users can reach and that holds the owner's vault.
        #[arg(long)]
        storage_path: PathBuf,
        #[arg(long, default_value = "shared")]
        storage_name: String,
    },
}

#[derive(Subcommand)]
enum ReplicaCmd {
    /// (Owner) Print the token to give to a replica device.
    Token,
    /// (Replica) Set up this directory as a replica of a vault.
    Init {
        #[arg(long)]
        name: String,
        #[arg(long)]
        token: String,
        /// Directory the owner writes to (shared folder, synced bucket, USB disk).
        #[arg(long)]
        source: PathBuf,
        /// Directory on this device that will hold the encrypted copy.
        #[arg(long)]
        target: PathBuf,
    },
    /// (Replica) Copy new objects, verify them and record the claims.
    Run {
        /// Run once and exit instead of looping.
        #[arg(long)]
        once: bool,
        #[arg(long, default_value_t = 300)]
        interval: u64,
    },
    /// (Replica) Show what this replica mirrors.
    Status,
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Run in the foreground (used by the launch agent, systemd and the menu-bar app).
    Run {
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long, default_value_t = 300)]
        interval: u64,
    },
    /// Start at login (macOS launch agent, systemd user unit).
    Install {
        #[arg(long, default_value_t = 300)]
        interval: u64,
    },
    /// Stop starting at login.
    Uninstall,
    /// Show whether the service is running and what it did last.
    Status,
    /// Ask the running service to quit.
    Stop,
}

#[derive(Subcommand)]
enum StorageCmd {
    /// Add a local directory (local disk, removable disk or network mount).
    AddLocal {
        name: String,
        path: PathBuf,
        /// Cold storage: written, never read without confirmation.
        #[arg(long)]
        cold: bool,
        /// Transferrer: removable media carrying only what other devices still lack; emptied when delivered.
        #[arg(long)]
        carrier: bool,
        /// Place for durability policies (home, cloud, offsite, ...); default home.
        #[arg(long, default_value = "")]
        place: String,
    },
    /// Add an S3-compatible bucket (AWS, Scaleway, Hetzner, Backblaze B2, R2, MinIO, ...).
    AddS3 {
        name: String,
        /// Endpoint, e.g. https://s3.eu-central-1.amazonaws.com or http://127.0.0.1:9000
        #[arg(long)]
        endpoint: String,
        #[arg(long, default_value = "us-east-1")]
        region: String,
        #[arg(long)]
        bucket: String,
        /// Key prefix inside the bucket.
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long)]
        access_key_id: String,
        /// Secret access key; read from VARSTO_S3_SECRET if omitted. Stored encrypted in secrets.enc.
        #[arg(long, env = "VARSTO_S3_SECRET", hide_env_values = true)]
        secret_access_key: String,
        /// Use virtual-host style URLs (bucket.host) instead of path style.
        #[arg(long)]
        virtual_host: bool,
        /// Storage class for new objects (DEEP_ARCHIVE, GLACIER_IR, STANDARD_IA, ...).
        #[arg(long)]
        storage_class: Option<String>,
        /// Cold storage: written, never read without confirmation.
        #[arg(long)]
        cold: bool,
        /// Place for durability policies; default cloud.
        #[arg(long, default_value = "")]
        place: String,
    },
    /// Add any rclone remote (`remote:bucket/path`); credentials stay in rclone's own config.
    AddRclone {
        name: String,
        remote: String,
        #[arg(long)]
        cold: bool,
        /// Place for durability policies; default cloud.
        #[arg(long, default_value = "")]
        place: String,
    },
    /// Add a pool of removable disks; then `varsto disk add <mount> --pool <name> --label <label>`.
    AddPool {
        name: String,
        /// Where the disks are kept (shelf, home, offsite, ...); default home.
        #[arg(long, default_value = "")]
        place: String,
        /// Share of every disk kept free (at least 2 GiB is always kept).
        #[arg(long, default_value_t = varsto_core::pool::DEFAULT_RESERVE_PERCENT)]
        reserve_percent: u32,
        /// Extra directory scanned for attached disks, besides the platform's mount roots (repeatable).
        #[arg(long)]
        scan_root: Vec<PathBuf>,
    },
    /// List storages with their prices and monthly cost.
    List,
    /// Remove a storage. Blocks that would be left without enough copies
    /// (one, or the folder policy's minimum) are copied elsewhere first.
    Remove {
        name: String,
        /// Show what would be copied, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Also delete everything Varsto wrote on the storage afterwards.
        #[arg(long)]
        delete_data: bool,
    },
    /// Show or set a storage's prices (defaults come from the built-in price data when recognised).
    Price {
        name: String,
        /// Storage price per GB-month.
        #[arg(long)]
        gb_month: Option<f64>,
        /// Egress (data transfer out) per GB.
        #[arg(long)]
        egress: Option<f64>,
        /// Retrieval (restore) per GB, for cold classes.
        #[arg(long)]
        retrieval: Option<f64>,
        /// Minimum storage duration in days billed by a cold class.
        #[arg(long)]
        min_days: Option<u32>,
        /// Currency of the figures (EUR, USD, ...).
        #[arg(long)]
        currency: Option<String>,
        /// Remove the prices you set (built-in figures still apply).
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Subcommand)]
enum DiskCmd {
    /// Register a mounted directory as a new disk of a pool and fill it with what the pool lacks.
    Add {
        mount_path: PathBuf,
        #[arg(long)]
        pool: String,
        #[arg(long)]
        label: String,
    },
    /// Every disk of every pool: attached or away, free space, last verified, pending deletes.
    List,
    /// Reattach routine: verify the marker and the objects, apply queued deletions, add new objects.
    Check {
        label: String,
        /// Re-hash every object (sizes alone otherwise).
        #[arg(long)]
        full: bool,
    },
    /// Write the disk's index and sync it; prints when the disk is safe to remove (does not unmount).
    Eject { label: String },
    /// Nothing new goes to this disk; what it holds stays readable.
    Retire { label: String },
}

#[derive(Subcommand)]
enum FolderCmd {
    /// Stop syncing a folder on this device; its files stay where they are.
    Detach {
        name: String,
    },
    /// Remove a folder from the vault on every device (files already on
    /// devices stay). --purge also deletes its encrypted data from the storages.
    Remove {
        name: String,
        #[arg(long)]
        purge: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Create a folder in the vault and sync `path` into it.
    Add {
        name: String,
        path: PathBuf,
    },
    /// Sync an existing folder of the vault into `path` on this device.
    Attach {
        name_or_id: String,
        path: PathBuf,
        /// Selective sync: files appear as placeholders until fetched.
        #[arg(long)]
        selective: bool,
    },
    /// Turn selective sync on or off for an attached folder.
    Selective {
        name_or_id: String,
        #[arg(value_parser = clap::value_parser!(bool))]
        on: bool,
    },
    /// Download one placeholder file and keep it on this device.
    /// Give FOLDER PATH, or only the file's path on disk (the placeholder works too).
    Fetch {
        folder: String,
        path: Option<String>,
    },
    /// Replace a local file with a placeholder (only when stored elsewhere
    /// and synced). Give FOLDER PATH, or only the file's path on disk.
    Free {
        folder: String,
        path: Option<String>,
    },
    /// List files of a folder with their local state.
    Files {
        folder: String,
    },
    List,
}

/// FOLDER PATH as given, or the folder and path of one path on disk.
fn folder_and_path(
    engine: &Engine,
    first: &str,
    path: &Option<String>,
) -> Result<(String, String)> {
    match path {
        Some(p) => Ok((first.to_string(), p.clone())),
        None => engine.locate_path(&std::path::absolute(first)?),
    }
}

fn bail_usage<T>(msg: &str) -> Result<T> {
    Err(anyhow!("{msg}"))
}

/// The device passphrase: from `VARSTO_PASSPHRASE`, otherwise asked on the
/// terminal (hidden input). Scripts and services set the variable.
fn passphrase() -> Result<String> {
    if let Ok(p) = std::env::var("VARSTO_PASSPHRASE") {
        return Ok(p);
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let p = rpassword::prompt_password("Varsto passphrase for this device: ")
            .context("read the passphrase")?;
        if p.is_empty() {
            bail_usage::<()>("empty passphrase")?;
        }
        return Ok(p);
    }
    Err(anyhow!(
        "no passphrase: set VARSTO_PASSPHRASE, or run from a terminal to be asked"
    ))
}

fn home(cli: &Cli) -> Result<PathBuf> {
    if let Some(h) = &cli.home {
        return Ok(h.clone());
    }
    if cfg!(target_os = "macos") {
        let h = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set; pass --home"))?;
        return Ok(PathBuf::from(h).join("Library/Application Support/Varsto"));
    }
    if cfg!(windows) {
        let a = std::env::var_os("APPDATA")
            .ok_or_else(|| anyhow!("APPDATA is not set; pass --home"))?;
        return Ok(PathBuf::from(a).join("Varsto"));
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .ok_or_else(|| anyhow!("cannot determine a home directory; pass --home"))?;
    Ok(base.join("varsto"))
}

/// Decimal sizes for messages ("3.2 GB", "410 MB").
fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn print<T: serde::Serialize>(
    cli: &Cli,
    value: &T,
    human: impl FnOnce(&T) -> String,
) -> Result<()> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{}", human(value));
    }
    Ok(())
}

fn run(cli: &Cli) -> Result<()> {
    let home = home(cli)?;
    match &cli.cmd {
        Cmd::Init { name } => {
            let (engine, vault_key) = Engine::init(&home, name, &passphrase()?)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({ "vault_id": engine.vault_id().to_string(), "device_id": engine.device_id().to_string(), "vault_key": vault_key })
                );
            } else {
                println!(
                    "Vault {} created; this device is {}.",
                    engine.vault_id(),
                    engine.device_id()
                );
                println!("Vault key (needed to join other devices; shown once, keep it offline):");
                println!("  {vault_key}");
            }
        }
        Cmd::Join {
            name,
            vault_key,
            words,
            storage_name,
            storage_path,
            s3_bucket,
            s3_endpoint,
            s3_region,
            s3_prefix,
            s3_access_key_id,
            s3_secret_access_key,
        } => {
            let mut s3_secret: Option<String> = None;
            let spec = match (s3_bucket, storage_path) {
                (Some(bucket), _) => {
                    let secret = s3_secret_access_key.clone().ok_or_else(|| {
                        anyhow!("give --s3-secret-access-key or set VARSTO_S3_SECRET")
                    })?;
                    // The storage is opened before the vault exists, so the secret travels via the environment for this process.
                    let env_name = format!(
                        "VARSTO_S3_SECRET_{}",
                        storage_name
                            .to_uppercase()
                            .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                    );
                    std::env::set_var(env_name, &secret);
                    s3_secret = Some(secret);
                    StorageSpec::S3 {
                        name: storage_name.clone(),
                        endpoint: s3_endpoint
                            .clone()
                            .unwrap_or_default()
                            .trim_end_matches('/')
                            .to_string(),
                        region: s3_region.clone(),
                        bucket: bucket.clone(),
                        prefix: s3_prefix.trim_matches('/').to_string(),
                        access_key_id: s3_access_key_id
                            .clone()
                            .ok_or_else(|| anyhow!("give --s3-access-key-id"))?,
                        secret_ref: String::new(),
                        path_style: true,
                        storage_class: None,
                        cold: false,
                        place: String::new(),
                    }
                }
                (None, Some(path)) => StorageSpec::LocalDir {
                    name: storage_name.clone(),
                    path: path.clone(),
                    cold: false,
                    carrier: false,
                    place: String::new(),
                },
                (None, None) => bail_usage("give --storage-path <dir> or --s3-bucket ...")?,
            };
            let key_hex = match (vault_key, words) {
                (Some(k), _) => k.clone(),
                (None, Some(w)) => varsto_core::recovery::key_from_words(w)?,
                (None, None) => bail_usage("give --vault-key <hex> or --words \"<24 words>\"")?,
            };
            let mut engine = Engine::join(&home, name, &passphrase()?, &key_hex, spec)?;
            if let Some(secret) = s3_secret {
                engine.store_secret(storage_name, &secret)?;
            }
            let folders = engine.folders();
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({ "vault_id": engine.vault_id().to_string(), "device_id": engine.device_id().to_string(), "folders": folders.iter().map(|(r, _)| r.name.clone()).collect::<Vec<_>>() })
                );
            } else {
                println!(
                    "Joined vault {} as device {}.",
                    engine.vault_id(),
                    engine.device_id()
                );
                for (r, _) in folders {
                    println!(
                        "  folder {} ({}): attach it with `varsto folder attach {} <path>`",
                        r.name,
                        r.folder_id.short(),
                        r.name
                    );
                }
            }
        }
        Cmd::Storage { cmd } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            match cmd {
                StorageCmd::AddLocal {
                    name,
                    path,
                    cold,
                    carrier,
                    place,
                } => {
                    engine.add_storage(StorageSpec::LocalDir {
                        name: name.clone(),
                        path: path.clone(),
                        cold: *cold,
                        carrier: *carrier,
                        place: place.clone(),
                    })?;
                    println!("storage {name} added");
                }
                StorageCmd::AddS3 {
                    name,
                    endpoint,
                    region,
                    bucket,
                    prefix,
                    access_key_id,
                    secret_access_key,
                    virtual_host,
                    storage_class,
                    cold,
                    place,
                } => {
                    engine.add_storage_with_secret(
                        StorageSpec::S3 {
                            name: name.clone(),
                            endpoint: endpoint.trim_end_matches('/').to_string(),
                            region: region.clone(),
                            bucket: bucket.clone(),
                            prefix: prefix.trim_matches('/').to_string(),
                            access_key_id: access_key_id.clone(),
                            secret_ref: String::new(),
                            path_style: !*virtual_host,
                            storage_class: storage_class.clone(),
                            cold: *cold
                                || storage_class.as_deref().is_some_and(|c| {
                                    c.contains("GLACIER") || c.contains("ARCHIVE")
                                }),
                            place: place.clone(),
                        },
                        Some(secret_access_key.clone()),
                    )?;
                    println!("storage {name} added (secret kept in secrets.enc)");
                }
                StorageCmd::AddRclone {
                    name,
                    remote,
                    cold,
                    place,
                } => {
                    engine.add_storage(StorageSpec::Rclone {
                        name: name.clone(),
                        remote: remote.clone(),
                        cold: *cold,
                        place: place.clone(),
                    })?;
                    println!("storage {name} added");
                }
                StorageCmd::AddPool {
                    name,
                    place,
                    reserve_percent,
                    scan_root,
                } => {
                    engine.add_storage(StorageSpec::Pool {
                        name: name.clone(),
                        place: place.clone(),
                        reserve_percent: *reserve_percent,
                        min_reserve_bytes: varsto_core::pool::DEFAULT_MIN_RESERVE_BYTES,
                        disks: vec![],
                        scan_roots: scan_root.clone(),
                    })?;
                    println!("disk pool {name} added; attach a disk with: varsto disk add <mount-path> --pool {name} --label <label>");
                }
                StorageCmd::Remove {
                    name,
                    dry_run,
                    delete_data,
                } => {
                    let plan = engine.plan_storage_removal(name)?;
                    if let Some(why) = &plan.blocked {
                        bail!("cannot remove {name}: {why}");
                    }
                    println!(
                        "{name} holds {} blocks: {} have enough copies elsewhere, {} copies ({} bytes) go to {} first",
                        plan.blocks,
                        plan.blocks_ok,
                        plan.copies.len(),
                        plan.bytes_to_copy,
                        if plan.targets.is_empty() { "-".to_string() } else { plan.targets.join(", ") }
                    );
                    if *dry_run {
                        return Ok(());
                    }
                    let r = engine.remove_storage(name, *delete_data)?;
                    println!(
                        "storage {name} removed: {} blocks copied ({} bytes){}",
                        r.blocks_copied,
                        r.bytes_copied,
                        if *delete_data {
                            format!(", {} objects deleted from it", r.objects_deleted)
                        } else {
                            ", its data was left in place".to_string()
                        }
                    );
                }
                StorageCmd::List => {
                    let estimates = engine.storage_estimates()?;
                    // The specs, each with its price, stored bytes and monthly cost.
                    let listed: Vec<serde_json::Value> = engine
                        .storages()
                        .iter()
                        .zip(&estimates)
                        .map(|(spec, e)| {
                            let mut v = serde_json::to_value(spec).unwrap_or_default();
                            v["price"] = serde_json::to_value(&e.price).unwrap_or_default();
                            v["bytes"] = e.bytes.into();
                            v["monthly_cost"] =
                                serde_json::to_value(e.monthly_cost).unwrap_or_default();
                            v
                        })
                        .collect();
                    print(cli, &listed, |_| {
                        engine
                            .storages()
                            .iter()
                            .zip(&estimates)
                            .map(|(x, e)| {
                                format!(
                                    "{}{}{}{} | {} stored | {}{}",
                                    x.name(),
                                    if x.is_cold() { " (cold)" } else { "" },
                                    if x.is_carrier() { " (carrier)" } else { "" },
                                    if x.is_data_only() {
                                        format!(" ({})", x.describe())
                                    } else {
                                        String::new()
                                    },
                                    fmt_bytes(e.bytes),
                                    e.price
                                        .as_ref()
                                        .map(|p| p.describe())
                                        .unwrap_or_else(|| "no price set".to_string()),
                                    e.monthly_cost
                                        .map(|c| format!(" | about {c:.2} {} a month", e.currency))
                                        .unwrap_or_default()
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })?;
                }
                StorageCmd::Price {
                    name,
                    gb_month,
                    egress,
                    retrieval,
                    min_days,
                    currency,
                    clear,
                } => upkeep::price(
                    cli,
                    &mut engine,
                    upkeep::PriceArgs {
                        name,
                        gb_month: *gb_month,
                        egress: *egress,
                        retrieval: *retrieval,
                        min_days: *min_days,
                        currency: currency.as_deref(),
                        clear: *clear,
                    },
                )?,
            }
        }
        Cmd::Disk { cmd } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            match cmd {
                DiskCmd::Add {
                    mount_path,
                    pool,
                    label,
                } => {
                    let r = engine.disk_add(mount_path, pool, label)?;
                    print(cli, &r, |r| {
                        format!(
                            "disk {} added to pool {} at {}: {} added ({} objects)",
                            r.disk.label,
                            r.pool,
                            r.disk
                                .last_mount
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default(),
                            fmt_bytes(r.bytes_added),
                            r.objects_added
                        )
                    })?;
                }
                DiskCmd::List => {
                    let disks = engine.disks()?;
                    print(cli, &disks, |disks| {
                        if disks.is_empty() {
                            return "no disks; add a pool with `varsto storage add-pool <name>` and a disk with `varsto disk add`".to_string();
                        }
                        disks
                            .iter()
                            .map(|d| {
                                let state = if d.attached {
                                    format!(
                                        "attached at {}, {} free",
                                        d.mount.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
                                        d.free_bytes.map(fmt_bytes).unwrap_or_else(|| "? ".into())
                                    )
                                } else {
                                    "offline".to_string()
                                };
                                format!(
                                    "{} (pool {}, {}): {}{}; {} objects, {} used; last verified {}{}",
                                    d.label,
                                    d.pool,
                                    d.place,
                                    state,
                                    if d.retired { ", retired" } else { "" },
                                    d.objects,
                                    fmt_bytes(d.used_bytes),
                                    if d.last_verified_utc > 0 {
                                        varsto_core::util::format_date(d.last_verified_utc)
                                    } else {
                                        "never".to_string()
                                    },
                                    if d.pending_deletes > 0 {
                                        format!("; {} pending deletes", d.pending_deletes)
                                    } else {
                                        String::new()
                                    }
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })?;
                }
                DiskCmd::Check { label, full } => {
                    let r = engine.disk_check(label, *full)?;
                    print(cli, &r, |r| {
                        format!(
                            "{}: checked {}, {} bad{}, {} removed, {} added{}",
                            r.label,
                            fmt_bytes(r.bytes_checked),
                            r.bad.len(),
                            if r.missing.is_empty() {
                                String::new()
                            } else {
                                format!(", {} missing", r.missing.len())
                            },
                            fmt_bytes(r.bytes_removed),
                            fmt_bytes(r.bytes_added),
                            if r.adopted > 0 {
                                format!(", {} objects adopted", r.adopted)
                            } else {
                                String::new()
                            }
                        )
                    })?;
                    if !r.bad.is_empty() {
                        std::process::exit(1);
                    }
                }
                DiskCmd::Eject { label } => {
                    let mount = engine.disk_eject(label)?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({ "label": label, "mount": mount, "safe_to_remove": true })
                        );
                    } else {
                        println!(
                            "{label} ({}): index written and synced; safe to remove",
                            mount.display()
                        );
                    }
                }
                DiskCmd::Retire { label } => {
                    let only_here = engine.disk_retire(label)?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({ "label": label, "retired": true, "objects_only_here": only_here })
                        );
                    } else {
                        println!(
                            "{label} retired: nothing new goes there; {only_here} object{} exist only on it",
                            if only_here == 1 { "" } else { "s" }
                        );
                    }
                }
            }
        }
        Cmd::Folder { cmd } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            match cmd {
                FolderCmd::Add { name, path } => {
                    let id = engine.add_folder(name, path)?;
                    println!("folder {name} ({}) created", id.short());
                }
                FolderCmd::Attach {
                    name_or_id,
                    path,
                    selective,
                } => {
                    let id = engine.attach_folder(name_or_id, path, *selective)?;
                    println!("folder {} attached at {}", id.short(), path.display());
                }
                FolderCmd::Selective { name_or_id, on } => {
                    engine.set_selective(name_or_id, *on)?;
                    println!(
                        "selective sync {} for {}",
                        if *on { "on" } else { "off" },
                        name_or_id
                    );
                }
                FolderCmd::Fetch { folder, path } => {
                    let (folder, path) = &folder_and_path(&engine, folder, path)?;
                    let r = match engine.fetch_file(folder, path) {
                        Ok(r) => r,
                        Err(e) => {
                            if let Some(varsto_core::pool::PoolError::NeedsDisk {
                                label,
                                place,
                                ..
                            }) = varsto_core::pool::pool_error(&e)
                            {
                                eprintln!(
                                    "{path} is on disk {label} ({place}). Attach it and try again."
                                );
                                std::process::exit(1);
                            }
                            return Err(e);
                        }
                    };
                    println!("fetched {} ({} chunks)", path, r.chunks_downloaded);
                }
                FolderCmd::Free { folder, path } => {
                    let (folder, path) = &folder_and_path(&engine, folder, path)?;
                    engine.free_file(folder, path)?;
                    println!("{path} is now a placeholder");
                }
                FolderCmd::Detach { name } => {
                    engine.detach_folder(name)?;
                    println!(
                        "{name} is no longer synced on this device; its files stay where they are"
                    );
                }
                FolderCmd::Remove { name, purge, yes } => {
                    if !*yes {
                        bail_usage::<()>("this removes the folder from the vault on every device (files on devices stay); run again with --yes")?;
                    }
                    let n = engine.remove_folder(name, *purge)?;
                    println!(
                        "{name} removed from the vault{}",
                        if *purge {
                            format!("; {n} objects deleted from the storages")
                        } else {
                            String::new()
                        }
                    );
                }
                FolderCmd::Files { folder } => {
                    let rows = engine.list_files(folder)?;
                    print(cli, &rows, |rows| {
                        rows.iter()
                            .map(|f| {
                                format!(
                                    "{:<12} {:>10} {}{}",
                                    f.state,
                                    f.size,
                                    f.path,
                                    if f.pinned { " (pinned)" } else { "" }
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })?;
                }
                FolderCmd::List => {
                    let rows: Vec<serde_json::Value> = engine
                        .folders()
                        .into_iter()
                        .map(|(r, m)| serde_json::json!({ "id": r.folder_id.to_string(), "name": r.name, "path": m }))
                        .collect();
                    print(cli, &rows, |rows| {
                        rows.iter()
                            .map(|r| {
                                format!(
                                    "{} {} {}",
                                    r["id"].as_str().unwrap_or(""),
                                    r["name"],
                                    r["path"].as_str().unwrap_or("(not attached)")
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })?;
                }
            }
        }
        Cmd::Push { folder } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            let r = engine.push(folder)?;
            print(cli, &r, |r| {
                format!(
                    "{}: scanned {}, changed {}, uploaded {} chunks ({} bytes), manifest {:?}",
                    r.folder,
                    r.files_scanned,
                    r.files_changed,
                    r.chunks_uploaded,
                    r.bytes_uploaded,
                    r.manifest_seq
                )
            })?;
        }
        Cmd::Pull { folder } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            let r = engine.pull(folder)?;
            print(cli, &r, |r| {
                format!("{}: {} manifests, {} updated, {} deleted, {} conflicts, {} chunks downloaded; unavailable: {:?}; forked: {:?}{}", r.folder, r.manifests_applied, r.files_updated, r.files_deleted, r.conflicts, r.chunks_downloaded, r.files_unavailable, r.forked_devices, if r.disks_needed.is_empty() { String::new() } else { format!("; attach disk {}", r.disks_needed.join(", ")) })
            })?;
        }
        Cmd::Sync { folder } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            let r = engine.sync(folder.as_deref())?;
            print(cli, &r, |r| {
                r.iter().map(|(pl, ps)| format!("{}: pulled {} updated/{} deleted/{} conflicts, pushed {} changed/{} chunks{}{}", pl.folder, pl.files_updated, pl.files_deleted, pl.conflicts, ps.files_changed, ps.chunks_uploaded, if pl.disks_needed.is_empty() { String::new() } else { format!("; attach disk {}", pl.disks_needed.join(", ")) }, if ps.storages_unavailable.is_empty() { String::new() } else { format!("; not written to {}", ps.storages_unavailable.join(", ")) })).collect::<Vec<_>>().join("\n")
            })?;
        }
        Cmd::Status => {
            let engine = Engine::open(&home, &passphrase()?)?;
            let s = engine.status()?;
            print(cli, &s, |s| {
                let mut out = format!(
                    "vault {} device {} ({}) format {} lamport {} batches {}\n",
                    s.vault_id,
                    s.device_name,
                    &s.device_id[..8],
                    s.format_version,
                    s.lamport,
                    s.ledger_batches
                );
                out += &format!(
                    "devices: {}\n",
                    s.devices.values().cloned().collect::<Vec<_>>().join(", ")
                );
                out += &format!(
                    "storages: {}\n",
                    s.storages
                        .iter()
                        .map(|x| x.name().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                for f in &s.folders {
                    out += &format!("folder {} ({}): {} files, {} bytes, {} chunks, {} without storage copy, {} verified elsewhere, at {}\n", f.name, &f.folder_id[..8], f.files, f.bytes, f.chunks, f.chunks_without_storage_copy, f.chunks_verified_elsewhere, f.path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "(not attached)".into()));
                }
                if !s.forked_devices.is_empty() {
                    out += &format!("WARNING forked devices: {:?}\n", s.forked_devices);
                }
                out.trim_end().to_string()
            })?;
        }
        Cmd::Verify { cmd } => upkeep::verify(cli, &home, cmd)?,
        Cmd::Advice { idle_days, cmd } => upkeep::advice(cli, &home, *idle_days, cmd)?,
        Cmd::Fsck { verify } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            let r = engine.fsck(*verify)?;
            print(cli, &r, |r| {
                format!("referenced {} | with storage copy {} | verified elsewhere {} | claimed only {} | missing {:?} | claims without object {} | unreferenced objects {} | verified now {} | corrupt {:?} | forked {:?} | cold skipped {:?}{}", r.chunks_referenced, r.chunks_with_storage_copy, r.chunks_verified_elsewhere, r.chunks_claimed_only, r.chunks_missing, r.claims_without_object, r.objects_unreferenced, r.objects_verified_now, r.objects_corrupt, r.forked_devices, r.storages_skipped_cold, if r.disks_offline.is_empty() { String::new() } else { format!(" | offline: {} objects on {}", r.objects_offline, r.disks_offline.join("; ")) })
            })?;
            if !r.chunks_missing.is_empty()
                || !r.objects_corrupt.is_empty()
                || !r.forked_devices.is_empty()
            {
                std::process::exit(1);
            }
        }
        Cmd::Dupes { folder } => {
            let engine = Engine::open(&home, &passphrase()?)?;
            let r = engine.dupes(folder)?;
            print(cli, &r, |r| {
                r.iter()
                    .map(|g| format!("{} bytes: {}", g.size, g.paths.join(", ")))
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;
        }
        Cmd::Desktop {
            port,
            no_open,
            interval,
        } => {
            if let Some((f, _)) = service::status(&home) {
                let url = format!("http://127.0.0.1:{}/?token={}", f.port, f.token);
                println!("service already running (pid {}): {url}", f.pid);
                if !*no_open {
                    desktop::open_in_browser(&url);
                }
                return Ok(());
            }
            service::run(service::Options {
                home,
                port: *port,
                interval_secs: *interval,
                open_browser: !*no_open,
            })?;
        }
        Cmd::Service { cmd } => match cmd {
            ServiceCmd::Run { port, interval } => service::run(service::Options {
                home,
                port: *port,
                interval_secs: *interval,
                open_browser: false,
            })?,
            ServiceCmd::Install { interval } => println!("{}", service::install(&home, *interval)?),
            ServiceCmd::Uninstall => println!("{}", service::uninstall()?),
            ServiceCmd::Status => match service::status(&home) {
                Some((f, v)) => print(
                    cli,
                    &serde_json::json!({"pid": f.pid, "port": f.port, "version": f.version, "service": v}),
                    |v| {
                        format!(
                            "running: pid {} port {} version {}; {}{}",
                            v["pid"],
                            v["port"],
                            v["version"],
                            v["service"],
                            v["service"]["auto_verify_text"]
                                .as_str()
                                .map(|t| format!("\n{t}"))
                                .unwrap_or_default()
                        )
                    },
                )?,
                None => {
                    println!("not running");
                    std::process::exit(1);
                }
            },
            ServiceCmd::Stop => match service::read_service_file(&home) {
                Some(f) => {
                    service::http_post(
                        &format!("http://127.0.0.1:{}/api/quit", f.port),
                        &f.token,
                        "{}",
                    )?;
                    println!("stop requested");
                }
                None => println!("not running"),
            },
        },
        Cmd::Tray { interval, open } => {
            // The tray app has no terminal output: on Windows, let go of the
            // console window that a double-click or the .cmd starter opened.
            #[cfg(windows)]
            // SAFETY: FreeConsole has no preconditions; it only detaches this process.
            unsafe {
                windows_sys::Win32::System::Console::FreeConsole();
            }
            tray::run(home, *interval, *open)?
        }
        Cmd::Share { cmd } => match cmd {
            ShareCmd::Request => {
                let code = varsto_core::vault::ShareRequest::code_for(&home)?;
                if cli.json {
                    println!("{}", serde_json::json!({"request_code": code}));
                } else {
                    println!("share request code for this device (give it to the folder owner; it contains no secret):\n  {code}");
                }
            }
            ShareCmd::Create { folder, to } => {
                let mut engine = Engine::open(&home, &passphrase()?)?;
                let t = engine.share_create(folder)?;
                match to {
                    Some(code) => {
                        let sealed =
                            t.seal(&varsto_core::vault::ShareRequest::parse_code(code)?)?;
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::json!({"folder": sealed.name, "token": sealed.encode(), "sealed": true})
                            );
                        } else {
                            println!("sealed share token for folder {} (only the device that made the request code can open it):\n  {}", sealed.name, sealed.encode());
                        }
                    }
                    None => print(cli, &t, |t| {
                        format!("share token for folder {} (the folder key is INSIDE this token: anyone holding it can read and write the folder; prefer `share create --to <request-code>`):\n  {}", t.name, t.encode())
                    })?,
                }
            }
            ShareCmd::Accept {
                name,
                token,
                storage_path,
                storage_name,
            } => {
                let token = if varsto_core::vault::SealedShareToken::is_sealed(token) {
                    varsto_core::vault::ShareRequest::open_token(&home, token)?
                } else {
                    varsto_core::vault::ShareToken::decode(token)?
                };
                let spec = StorageSpec::LocalDir {
                    name: storage_name.clone(),
                    path: storage_path.clone(),
                    cold: false,
                    carrier: false,
                    place: String::new(),
                };
                let engine = Engine::accept_share(&home, name, &passphrase()?, &token, spec)?;
                varsto_core::vault::ShareRequest::clear(&home);
                println!("joined shared folder {} as device {}; attach it with `varsto folder attach {} <path>` and sync", token.name, engine.device_id().short(), token.name);
            }
        },
        Cmd::Replica { cmd } => {
            match cmd {
                ReplicaCmd::Token => {
                    let engine = Engine::open(&home, &passphrase()?)?;
                    let t = engine.replica_token()?;
                    print(cli, &t, |t| {
                        format!("replica token (share only with the device that will hold your encrypted copies):\n  {}", t.encode())
                    })?;
                }
                ReplicaCmd::Init {
                    name,
                    token,
                    source,
                    target,
                } => {
                    let token = varsto_core::replica::ReplicaToken::decode(token)?;
                    let src = StorageSpec::LocalDir {
                        name: "source".into(),
                        path: source.clone(),
                        cold: false,
                        carrier: false,
                        place: String::new(),
                    };
                    let tgt = StorageSpec::LocalDir {
                        name: "target".into(),
                        path: target.clone(),
                        cold: false,
                        carrier: false,
                        place: String::new(),
                    };
                    let r = varsto_core::replica::Replica::init(&home, name, &token, src, tgt)?;
                    println!(
                        "replica {} ({}) set up; run `varsto replica run`",
                        name,
                        r.device_id().short()
                    );
                }
                ReplicaCmd::Run { once, interval } => {
                    let mut r = varsto_core::replica::Replica::open(&home)?;
                    loop {
                        let rep = r.run_once()?;
                        print(cli, &rep, |rep| {
                            format!("seen {}, copied {} ({} bytes), verified {}, corrupt {}, batch {:?}", rep.objects_seen, rep.objects_copied, rep.bytes_copied, rep.chunks_verified, rep.objects_corrupt, rep.batch_seq)
                        })?;
                        if *once {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_secs((*interval).max(15)));
                    }
                }
                ReplicaCmd::Status => {
                    let r = varsto_core::replica::Replica::open(&home)?;
                    println!("{}", serde_json::to_string_pretty(&r.summary())?);
                }
            }
        }
        Cmd::Reset { yes } => {
            if !*yes {
                bail_usage::<()>("this removes keys, ledger, state and configuration from this device (files in folders stay); run again with --yes")?;
            }
            if let Some((sf, _)) = service::status(&home) {
                let url = format!("http://127.0.0.1:{}/api/reset", sf.port);
                service::http_call(
                    "POST",
                    &url,
                    &sf.token,
                    Some(&serde_json::json!({"confirm": "reset"}).to_string()),
                )?;
                println!("device reset through the running service");
            } else {
                let removed = varsto_core::engine::reset_device(&home)?;
                println!("device reset; removed: {}", removed.join(", "));
            }
        }
        Cmd::Device { cmd } => match cmd {
            DeviceCmd::List => {
                let engine = Engine::open(&home, &passphrase()?)?;
                let list = engine.devices_list();
                print(cli, &list, |list| {
                    let mut out = format!("vault key epoch {}\n", engine.key_epoch());
                    for d in list {
                        out += &format!(
                            "{} ({}){}{}\n",
                            d.name,
                            &d.device_id[..8],
                            if d.this_device { ", this device" } else { "" },
                            match (&d.revoked_by, d.revoked_utc) {
                                (Some(by), Some(t)) => format!(
                                    ", removed by {by} on {}{}",
                                    varsto_core::util::format_date(t),
                                    if d.wipe_ordered {
                                        " with a wipe order"
                                    } else {
                                        ""
                                    }
                                ),
                                _ => String::new(),
                            }
                        );
                    }
                    out.trim_end().to_string()
                })?;
            }
            DeviceCmd::Revoke { device, wipe, yes } => {
                if !*yes {
                    bail_usage::<()>(&format!(
                        "this removes {device} from the vault: its later ledger entries are ignored, peers refuse it, and the vault gets new keys for everything written from now on (folders shared with other people and Strongroom folders keep theirs). Everything it already held stays readable to it. {}Print a new recovery kit afterwards: the old one no longer opens new data. Run again with --yes",
                        if *wipe { "With --wipe it also deletes its keys, sync state and folder contents when it next reaches a storage, including changes it never synced. " } else { "" }
                    ))?;
                }
                let report: varsto_core::engine::RevokeReport = if let Some((sf, _)) =
                    service::status(&home)
                {
                    // The running service owns the keys file: let it do the change.
                    let base = format!("http://127.0.0.1:{}", sf.port);
                    let list: serde_json::Value = serde_json::from_str(&service::http_get(
                        &format!("{base}/api/devices"),
                        &sf.token,
                    )?)?;
                    let name = list["devices"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|d| d["device_id"] == device.as_str() || d["name"] == device.as_str())
                        .and_then(|d| d["name"].as_str())
                        .ok_or_else(|| anyhow!("unknown device {device}"))?
                        .to_string();
                    let body = serde_json::json!({"device": device, "wipe": wipe, "confirm": name});
                    let r = service::http_post(
                        &format!("{base}/api/device/revoke"),
                        &sf.token,
                        &body.to_string(),
                    )?;
                    serde_json::from_str(&r)
                        .map_err(|_| anyhow!("unexpected answer from the service: {r}"))?
                } else {
                    let mut engine = Engine::open(&home, &passphrase()?)?;
                    engine.revoke_device(device, *wipe)?
                };
                print(cli, &report, |r| {
                    format!(
                        "removed {} ({}); vault key epoch {}; ledger entries after #{} are ignored{}\nnew key sent to: {}{}\nre-keyed folders: {}{}\nprint a new recovery kit: `varsto recovery kit`",
                        r.name,
                        &r.device_id[..8],
                        r.key_epoch,
                        r.cutoff_seq,
                        if r.wipe { "; wipe ordered" } else { "" },
                        if r.keys_sent_to.is_empty() { "(no other device)".to_string() } else { r.keys_sent_to.join(", ") },
                        if r.keys_pending_for.is_empty() { String::new() } else { format!("\nwaiting for (they get it once they publish a key-exchange key): {}", r.keys_pending_for.join(", ")) },
                        if r.folders_rekeyed.is_empty() { "none".to_string() } else { r.folders_rekeyed.join(", ") },
                        if r.folders_not_rekeyed.is_empty() { String::new() } else { format!("\nkept their key (shared or Strongroom): {}", r.folders_not_rekeyed.join(", ")) },
                    )
                })?;
            }
        },
        Cmd::Pair { cmd } => {
            match cmd {
                PairCmd::Offer => {
                    let engine = Engine::open(&home, &passphrase()?)?;
                    let offer = varsto_core::pair::Offer::start(engine.pairing_bundle()?)?;
                    let st = offer.status();
                    println!("Pairing code: {}", st.code);
                    println!("On the new device choose \"Pair with a code\" (or run `varsto pair join`).");
                    if !st.addresses.is_empty() {
                        println!(
                            "If it does not find this device, give the address: {}",
                            st.addresses.join(" or ")
                        );
                    }
                    println!(
                        "The code works once and for {} minutes.",
                        st.expires_in_secs.div_ceil(60)
                    );
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        let st = offer.status();
                        if !st.open {
                            match (st.paired_with, st.closed_reason) {
                                (Some(n), _) => println!("Sent the vault to {n}."),
                                (None, r) => bail!("pairing closed: {}", r.unwrap_or_default()),
                            }
                            break;
                        }
                    }
                }
                PairCmd::Join {
                    name,
                    code,
                    address,
                } => {
                    let pass = passphrase()?;
                    let bundle = varsto_core::pair::receive(code, name, address.as_deref())?;
                    let (engine, notes) = Engine::join_paired(&home, name, &pass, &bundle)?;
                    println!(
                        "joined vault {} as {} (paired with {})",
                        engine.vault_id(),
                        name,
                        bundle.from
                    );
                    for n in notes {
                        println!("  {n}");
                    }
                }
            }
        }
        Cmd::Recovery { cmd } => match cmd {
            RecoveryCmd::Kit { shares } => {
                let engine = Engine::open(&home, &passphrase()?)?;
                let key = engine.export_vault_key()?;
                let sh = if *shares {
                    Some((2u8, varsto_core::recovery::split(&key, 2, 3)?))
                } else {
                    None
                };
                print!(
                    "{}",
                    varsto_core::recovery::kit_text(&engine.vault_id().to_string(), &key, sh)?
                );
            }
            RecoveryCmd::Combine { shares } => {
                let parsed: Vec<varsto_core::recovery::Share> = shares
                    .iter()
                    .map(|s| varsto_core::recovery::Share::decode(s))
                    .collect::<Result<_>>()?;
                let key = varsto_core::recovery::combine(&parsed, 2)?;
                println!("vault key: {key}");
                println!("words: {}", varsto_core::recovery::words_from_key(&key)?);
            }
        },
        Cmd::Strongroom { cmd } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            match cmd {
                StrongroomCmd::Create {
                    name,
                    path,
                    software,
                    minutes,
                } => {
                    let method = if *software {
                        varsto_core::strongroom::Method::Software
                    } else {
                        varsto_core::strongroom::Method::Fido2
                    };
                    if *software {
                        eprintln!("warning: --software keeps the secret in a file next to the vault; it demonstrates the flow and protects nothing beyond your passphrase");
                    }
                    let backend = varsto_core::strongroom::backend(&method, &home);
                    let id =
                        engine.create_strongroom(name, path, method, backend.as_ref(), *minutes)?;
                    println!("Strongroom {name} ({}) created at {}; unlocked for {minutes} minutes in this process. Files appear as placeholders; fetch them while unlocked and free them when done.", id.short(), path.display());
                }
                StrongroomCmd::Unlock { folder, minutes } => {
                    let key = engine.unlock_strongroom_enrolled(folder, *minutes)?;
                    // Hand the key to the running service so the background sync works too.
                    if let Some((sf, _)) = service::status(&home) {
                        let url = format!("http://127.0.0.1:{}/api/strongroom/unlock", sf.port);
                        let body = serde_json::json!({"folder": folder, "key_hex": key.to_hex(), "minutes": minutes}).to_string();
                        match service::http_call("POST", &url, &sf.token, Some(&body)) {
                            Ok(_) => println!("Strongroom {folder} unlocked for {minutes} minutes (background service too)"),
                            Err(e) => println!("Strongroom {folder} unlocked for this command only; the background service did not accept the key: {e}"),
                        }
                    } else {
                        let reports = engine.sync(Some(folder))?;
                        for (pl, pu) in reports {
                            println!(
                                "{}: pulled {} updated, pushed {} chunks",
                                pl.folder, pl.files_updated, pu.chunks_uploaded
                            );
                        }
                        println!("Strongroom {folder} synced; no background service is running, so the key is forgotten now");
                    }
                }
                StrongroomCmd::Lock { folder } => {
                    engine.lock_strongroom(folder)?;
                    if let Some((sf, _)) = service::status(&home) {
                        let url = format!("http://127.0.0.1:{}/api/strongroom/lock", sf.port);
                        let _ = service::http_call(
                            "POST",
                            &url,
                            &sf.token,
                            Some(&serde_json::json!({"folder": folder}).to_string()),
                        );
                    }
                    println!("Strongroom {folder} locked");
                }
                StrongroomCmd::Status => {
                    let list = engine.strongrooms();
                    if list.is_empty() {
                        println!("no Strongroom folders");
                    }
                    for (name, method, until) in list {
                        let keys = engine.strongroom_keys(&name).map(|k| k.len()).unwrap_or(0);
                        println!(
                            "{name}: {:?}, {keys} enrolled key{}, {}",
                            method,
                            if keys == 1 { "" } else { "s" },
                            match until {
                                Some(u) => format!("unlocked until {u} (this process)"),
                                None => "locked".into(),
                            }
                        );
                    }
                    for (name, switched) in engine.strongroom_conversions() {
                        println!(
                            "{name}: {}",
                            if switched {
                                "converted; old copies still being removed (retried on every sync)"
                            } else {
                                "conversion interrupted; run `varsto strongroom convert` again to resume"
                            }
                        );
                    }
                    if let Some((_, sv)) = service::status(&home) {
                        if let Some(arr) = sv.get("strongrooms").and_then(|v| v.as_array()) {
                            println!("background service: {}", serde_json::to_string(arr)?);
                        }
                    }
                }
                StrongroomCmd::Convert {
                    folder,
                    software,
                    minutes,
                    free,
                } => strongroom_convert(&mut engine, &home, folder, *software, *minutes, *free)?,
                StrongroomCmd::AddKey {
                    folder,
                    label,
                    software,
                    device,
                } => {
                    use varsto_core::strongroom::{self, Method, SecurityKey};
                    let id = engine
                        .folders()
                        .into_iter()
                        .find(|(r, _)| {
                            r.is_strongroom()
                                && (&r.name == folder || r.folder_id.as_str() == folder)
                        })
                        .map(|(r, _)| r.folder_id)
                        .ok_or_else(|| anyhow!("{folder} is not a Strongroom folder"))?;
                    eprintln!("First, open {folder} with a key that is enrolled already.");
                    let fk = engine.unlock_strongroom_enrolled(folder, 1)?;
                    let (method, backend): (Method, Box<dyn SecurityKey>) = if *software {
                        eprintln!(
                            "warning: a software key protects nothing beyond your passphrase"
                        );
                        (
                            Method::Software,
                            Box::new(strongroom::new_software_key(&home)),
                        )
                    } else {
                        if device.is_none() {
                            eprintln!(
                                "Now unplug that key, plug in the backup key and press Enter."
                            );
                            let mut line = String::new();
                            std::io::stdin().read_line(&mut line)?;
                        }
                        (
                            Method::Fido2,
                            Box::new(strongroom::Fido2Tools {
                                device: device.clone(),
                            }),
                        )
                    };
                    let k = strongroom::enroll_key(backend.as_ref(), method, &id, &fk, label)?;
                    let name = k.short();
                    let n = if let Some((sf, _)) = service::status(&home) {
                        let url = format!("http://127.0.0.1:{}/api/strongroom/add-key", sf.port);
                        let body = serde_json::json!({"folder": folder, "key": k}).to_string();
                        let r: serde_json::Value = serde_json::from_str(&service::http_call(
                            "POST",
                            &url,
                            &sf.token,
                            Some(&body),
                        )?)?;
                        r["keys"].as_u64().unwrap_or(0) as usize
                    } else {
                        engine.add_strongroom_key_enrolled(folder, k)?
                    };
                    println!("{name} enrolled for {folder}; {n} keys open it now. Keep the backup key somewhere safe.");
                }
                StrongroomCmd::Keys { folder } => {
                    let keys = engine.strongroom_keys(folder)?;
                    print(cli, &keys, |keys| {
                        keys.iter()
                            .map(|k| {
                                format!(
                                    "{}. {} ({:?}, added {}): {}",
                                    k.number,
                                    if k.label.is_empty() {
                                        "no label"
                                    } else {
                                        &k.label
                                    },
                                    k.method,
                                    if k.added_utc > 0 {
                                        varsto_core::util::format_date(k.added_utc)
                                    } else {
                                        "with the folder".to_string()
                                    },
                                    k.credential
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })?;
                }
                StrongroomCmd::RemoveKey { folder, key } => {
                    let gone = if let Some((sf, _)) = service::status(&home) {
                        let url = format!("http://127.0.0.1:{}/api/strongroom/remove-key", sf.port);
                        let body = serde_json::json!({"folder": folder, "key": key}).to_string();
                        let r: serde_json::Value = serde_json::from_str(&service::http_call(
                            "POST",
                            &url,
                            &sf.token,
                            Some(&body),
                        )?)?;
                        r["removed"].as_str().unwrap_or(key).to_string()
                    } else {
                        engine.remove_strongroom_key(folder, key)?.short()
                    };
                    println!("{gone} no longer opens {folder}. The folder key is unchanged: a removed key that was copied or kept could still open older copies of the records.");
                }
            }
        }
        Cmd::P2p { cmd } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            match cmd {
                P2pCmd::Enable {
                    port,
                    public_addrs,
                    stun,
                    no_stun,
                } => {
                    let stun = if *no_stun {
                        Vec::new()
                    } else if stun.is_empty() {
                        varsto_core::vault::default_stun()
                    } else {
                        stun.clone()
                    };
                    engine.set_p2p_config(varsto_core::vault::P2pConfig {
                        enabled: true,
                        port: *port,
                        public_addrs: public_addrs.clone(),
                        stun,
                    })?;
                    let id = engine.p2p_identity()?;
                    println!(
                        "p2p enabled on port {port}{}; certificate {}; restart the background service to apply",
                        if public_addrs.is_empty() {
                            String::new()
                        } else {
                            format!(
                                ", public {}",
                                public_addrs
                                    .iter()
                                    .map(|a| a.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        },
                        &id.sha256[..16]
                    );
                }
                P2pCmd::Disable => {
                    let mut c = engine.p2p_config();
                    c.enabled = false;
                    engine.set_p2p_config(c)?;
                    println!("p2p disabled; restart the background service to apply");
                }
                P2pCmd::Status => p2p_status(&engine, &home, cli.json)?,
            }
        }
        Cmd::Policy { cmd } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            match cmd {
                PolicyCmd::Set {
                    folder,
                    min_copies,
                    places,
                    verified_within_days,
                } => {
                    let mut policy = varsto_core::policy::Policy {
                        min_copies: *min_copies,
                        verified_within_days: *verified_within_days,
                        ..Default::default()
                    };
                    for p in places {
                        let (place, n) = varsto_core::policy::parse_place_spec(p)
                            .ok_or_else(|| anyhow!("--place expects name=count, e.g. cloud=2"))?;
                        policy.min_per_place.insert(place, n);
                    }
                    engine.set_policy(folder, Some(policy.clone()))?;
                    println!("policy for {folder}: {}", policy.describe());
                }
                PolicyCmd::Clear { folder } => {
                    engine.set_policy(folder, None)?;
                    println!("policy cleared for {folder}");
                }
                PolicyCmd::Show => {
                    for (rec, _) in engine.folders() {
                        println!(
                            "{}: {}",
                            rec.name,
                            rec.policy
                                .as_ref()
                                .map(|p| p.describe())
                                .unwrap_or_else(|| "no policy".into())
                        );
                    }
                }
                PolicyCmd::Check => {
                    let reports = engine.policy_check()?;
                    let worst = reports.iter().map(|r| r.state).max();
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&reports)?);
                    } else if reports.is_empty() {
                        println!("no policies set (varsto policy set <folder> ...)");
                    } else {
                        for r in &reports {
                            println!("{}: {:?} ({})", r.folder, r.state, r.policy.describe());
                            for x in &r.reasons {
                                println!("  - {x}");
                            }
                            for x in &r.warnings {
                                println!("  ! {x}");
                            }
                        }
                    }
                    if let Some(w) = worst {
                        std::process::exit(w.exit_code());
                    }
                }
            }
        }
        Cmd::Mcp { cmd } => match cmd.as_ref().unwrap_or(&McpCmd::Serve) {
            McpCmd::Serve => mcp::serve(&home)?,
            McpCmd::Grant { folder, write } => {
                mcp::grant(&home, folder, *write)?;
                println!(
                    "granted {} access to {folder} (recorded in {})",
                    if *write { "read-write" } else { "read-only" },
                    mcp::grants_path(&home).display()
                );
            }
            McpCmd::Revoke { folder } => {
                mcp::revoke(&home, folder)?;
                println!("revoked {folder}");
            }
            McpCmd::List => {
                let g = mcp::Grants::load(&home)?;
                println!("{}", serde_json::to_string_pretty(&g)?);
            }
        },
        Cmd::Update { check } => {
            let c = update::check()?;
            if *check {
                print(cli, &c, |c| {
                    if c.available {
                        format!(
                            "update available: {} -> {} ({})",
                            c.current,
                            c.latest,
                            c.archive.clone().unwrap_or_default()
                        )
                    } else {
                        format!("up to date: {} (latest {})", c.current, c.latest)
                    }
                })?;
            } else {
                println!("{}", update::apply(&c)?);
            }
        }
        Cmd::Ledger => {
            let engine = Engine::open(&home, &passphrase()?)?;
            let r = engine.ledger_entries()?;
            print(cli, &r, |r| {
                r.iter()
                    .map(|e| {
                        format!(
                            "{} #{} lamport {} events {} {}",
                            &e.device[..8],
                            e.seq,
                            e.lamport,
                            e.events,
                            &e.hash[..12]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;
        }
    }
    Ok(())
}

fn main() {
    // Launched from an app bundle or by double-click: no arguments (macOS may add
    // a -psn_ process serial number). Open the desktop interface.
    let mut args: Vec<String> = std::env::args()
        .filter(|a| !a.starts_with("-psn_"))
        .collect();
    if args.len() == 1 {
        args.push(if cfg!(any(target_os = "linux", target_os = "windows")) {
            "tray".to_string()
        } else {
            "desktop".to_string()
        });
    }
    let cli = Cli::parse_from(args);
    if let Err(e) = run(&cli).context("varsto") {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

/// `strongroom convert`: the security key is touched here; the conversion
/// itself runs in the background service when one is running (it owns the
/// folder state), otherwise in this process.
fn strongroom_convert(
    engine: &mut Engine,
    home: &std::path::Path,
    folder: &str,
    software: bool,
    minutes: u64,
    free: bool,
) -> Result<()> {
    use varsto_core::crypto::SecretKey;
    use varsto_core::ids::FolderId;
    use varsto_core::strongroom::{self, Method};
    let service = service::status(home);
    let (id, fk, info) = if let Some((id, info)) = engine.strongroom_conversion(folder) {
        eprintln!(
            "Resuming the interrupted conversion of {folder}: touch the key it was started with."
        );
        let (fk, _) = strongroom::unlock_enrolled(home, &id, &info)?;
        (id, fk, info)
    } else if engine
        .folders()
        .into_iter()
        .any(|(r, _)| r.is_strongroom() && (r.name == folder || r.folder_id.as_str() == folder))
    {
        if service.is_some() {
            println!("{folder} is a Strongroom already; the background service removes any old copies left on its next sync");
        } else {
            let r = engine.finish_strongroom_conversions();
            println!(
                "{folder} is a Strongroom already; removed {} old objects{}",
                r.objects_deleted,
                if r.failures.is_empty() {
                    String::new()
                } else {
                    format!(", still pending: {}", r.failures.join("; "))
                }
            );
        }
        return Ok(());
    } else {
        let method = if software {
            eprintln!("warning: --software keeps the secret in a file next to the vault; it demonstrates the flow and protects nothing beyond your passphrase");
            Method::Software
        } else {
            Method::Fido2
        };
        let id = FolderId::random();
        let fk = SecretKey::random();
        let backend = strongroom::backend(&method, home);
        let info = strongroom::enroll(backend.as_ref(), method, &id, &fk)?;
        (id, fk, info)
    };
    eprintln!("Re-encrypting {folder} under the new key; this reads and uploads the whole folder.");
    let report = if let Some((sf, _)) = service {
        let url = format!("http://127.0.0.1:{}/api/strongroom/convert", sf.port);
        let body = serde_json::json!({"folder": folder, "folder_id": id.to_string(), "key_hex": fk.to_hex(), "info": info, "minutes": minutes, "free": free}).to_string();
        serde_json::from_str(&service::http_call("POST", &url, &sf.token, Some(&body))?)?
    } else {
        let mut r = serde_json::to_value(
            engine.convert_to_strongroom_with(folder, &id, &fk, info, minutes)?,
        )?;
        if free {
            let (freed, kept) = engine.free_folder(folder)?;
            r["freed"] = serde_json::json!(freed);
            r["kept"] = serde_json::json!(kept);
        }
        r
    };
    println!(
        "{folder} is now a Strongroom ({} files re-encrypted, {} fetched to do it, {} blocks uploaded; {} old objects and {} old manifests deleted).",
        report["files"], report["files_fetched"], report["chunks_uploaded"], report["cleanup"]["objects_deleted"], report["cleanup"]["manifests_deleted"]
    );
    if let Some(f) = report["cleanup"]["failures"]
        .as_array()
        .filter(|f| !f.is_empty())
    {
        println!(
            "Old copies still to remove (retried on every sync): {}",
            serde_json::to_string(f)?
        );
    }
    println!("Other devices replace their plain copies with placeholders on their next sync.");
    if free {
        println!(
            "This device: {} files replaced with placeholders, {} kept.",
            report["freed"], report["kept"]
        );
    } else {
        println!("Plain copies on this device stay until you free them (run again with --free, or free files in the app).");
    }
    Ok(())
}

/// `p2p status`: the running service's view when there is one (its socket
/// is the one the NAT maps), otherwise the records plus a probe over TCP and
/// a STUN query from a temporary socket.
fn p2p_status(engine: &Engine, home: &std::path::Path, json: bool) -> Result<()> {
    let c = engine.p2p_config();
    let live = service::status(home).and_then(|(sf, _)| {
        let url = format!("http://127.0.0.1:{}/api/p2p", sf.port);
        service::http_get(&url, &sf.token)
            .ok()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
    });
    if let Some(v) = live {
        if json {
            println!("{v}");
            return Ok(());
        }
        println!(
            "p2p: {}, port {}, public {:?}, stun {}",
            if c.enabled { "enabled" } else { "disabled" },
            c.port,
            c.public_addrs,
            if c.stun.is_empty() {
                "off".to_string()
            } else {
                c.stun.join(", ")
            }
        );
        println!(
            "service: listening on {}, NAT {}, observed {}, {}{}",
            v["listen"].as_str().unwrap_or("-"),
            v["nat"].as_str().unwrap_or("unknown"),
            match v["public"].as_array() {
                Some(a) if !a.is_empty() => a
                    .iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => "no public address".to_string(),
            },
            if v["reachable"].as_bool() == Some(true) {
                "reachable (relays for the vault)"
            } else {
                "not reachable from the internet"
            },
            match v["relays"].as_array() {
                Some(a) if !a.is_empty() => format!(
                    ", registered with {}",
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                _ => String::new(),
            }
        );
        let paths = v["paths"].as_array().cloned().unwrap_or_default();
        if paths.is_empty() {
            println!("no peers known yet (other devices publish a record when their service runs with p2p enabled)");
        }
        for p in paths {
            println!(
                "  {} {}: {}{}",
                p["name"].as_str().unwrap_or(""),
                p["device"]
                    .as_str()
                    .map(|d| &d[..d.len().min(8)])
                    .unwrap_or(""),
                p["path"].as_str().unwrap_or("untried"),
                p["addr"]
                    .as_str()
                    .map(|a| format!(" ({a})"))
                    .unwrap_or_default()
            );
        }
        return Ok(());
    }

    let records = engine.peer_record_list()?;
    let probe = varsto_core::p2p::Peers::build(
        engine.peer_key(),
        engine.device_id().clone(),
        &records,
        &[],
        None,
    )
    .probe();
    // A temporary socket: the mapping differs from the service's, but the
    // public IP and the NAT guess are the same.
    let stun = if c.stun.is_empty() {
        None
    } else {
        std::net::UdpSocket::bind("0.0.0.0:0").ok().map(|s| {
            varsto_core::p2p::stun::probe(&s, &c.stun, std::time::Duration::from_millis(1500))
        })
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "config": c,
                "service": serde_json::Value::Null,
                "nat": stun.as_ref().map(|p| p.nat),
                "public": stun.as_ref().map(|p| p.public_addrs()),
                "records": records,
                "peers": probe,
            })
        );
        return Ok(());
    }
    println!(
        "p2p: {}, port {}, public {:?}, stun {}",
        if c.enabled { "enabled" } else { "disabled" },
        c.port,
        c.public_addrs,
        if c.stun.is_empty() {
            "off".to_string()
        } else {
            c.stun.join(", ")
        }
    );
    println!("background service not running; probing over TCP from this command");
    match &stun {
        Some(p) => println!(
            "NAT guess {} ({}, from a temporary socket)",
            p.nat.as_str(),
            if p.mapped.is_empty() {
                "no STUN answer".to_string()
            } else {
                format!(
                    "observed {}",
                    p.public_addrs()
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        ),
        None => println!("STUN disabled"),
    }
    if probe.is_empty() {
        println!("no peer records yet (other devices publish one when their service runs with p2p enabled)");
    }
    for p in probe {
        let rec = records.iter().find(|r| r.device == p.device);
        println!(
            "  {} {}: {}{}{}",
            p.name,
            p.device.short(),
            p.path,
            p.addr.map(|a| format!(" ({a})")).unwrap_or_default(),
            rec.map(|r| format!(
                "; record: nat {}, {}{}",
                r.nat.as_str(),
                if r.reachable {
                    "reachable"
                } else {
                    "behind NAT"
                },
                if r.relay_via.is_empty() {
                    String::new()
                } else {
                    format!(", relays via {} device(s)", r.relay_via.len())
                }
            ))
            .unwrap_or_default()
        );
    }
    Ok(())
}
