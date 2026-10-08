// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto`: command-line interface (alpha-0). Every command has a `--json`
//! output for scripts (P-004); exit codes: 0 ok, 1 failure, 2 usage.

use anyhow::{anyhow, Context, Result};
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
        /// Local directory of the storage.
        #[arg(long)]
        storage_path: PathBuf,
    },
    /// Manage storages.
    Storage {
        #[command(subcommand)]
        cmd: StorageCmd,
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
    },
    Disable,
    /// Show settings, known peers and whether they answer right now.
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
    List,
}

#[derive(Subcommand)]
enum FolderCmd {
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
    Fetch {
        folder: String,
        path: String,
    },
    /// Replace a local file with a placeholder (only when stored elsewhere).
    Free {
        folder: String,
        path: String,
    },
    /// List files of a folder with their local state.
    Files {
        folder: String,
    },
    List,
}

fn bail_usage(msg: &str) -> Result<String> {
    Err(anyhow!("{msg}"))
}

fn passphrase() -> Result<String> {
    std::env::var("VARSTO_PASSPHRASE")
        .map_err(|_| anyhow!("set VARSTO_PASSPHRASE (alpha: no interactive prompt yet)"))
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
        } => {
            let spec = StorageSpec::LocalDir {
                name: storage_name.clone(),
                path: storage_path.clone(),
                cold: false,
                carrier: false,
                place: String::new(),
            };
            let key_hex = match (vault_key, words) {
                (Some(k), _) => k.clone(),
                (None, Some(w)) => varsto_core::recovery::key_from_words(w)?,
                (None, None) => bail_usage("give --vault-key <hex> or --words \"<24 words>\"")?,
            };
            let engine = Engine::join(&home, name, &passphrase()?, &key_hex, spec)?;
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
                StorageCmd::List => {
                    print(cli, &engine.storages().to_vec(), |s| {
                        s.iter()
                            .map(|x| {
                                format!(
                                    "{}{}{}",
                                    x.name(),
                                    if x.is_cold() { " (cold)" } else { "" },
                                    if x.is_carrier() { " (carrier)" } else { "" }
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })?;
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
                    let r = engine.fetch_file(folder, path)?;
                    println!("fetched {} ({} chunks)", path, r.chunks_downloaded);
                }
                FolderCmd::Free { folder, path } => {
                    engine.free_file(folder, path)?;
                    println!("{path} is now a placeholder");
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
                format!("{}: {} manifests, {} updated, {} deleted, {} conflicts, {} chunks downloaded; unavailable: {:?}; forked: {:?}", r.folder, r.manifests_applied, r.files_updated, r.files_deleted, r.conflicts, r.chunks_downloaded, r.files_unavailable, r.forked_devices)
            })?;
        }
        Cmd::Sync { folder } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            let r = engine.sync(folder.as_deref())?;
            print(cli, &r, |r| {
                r.iter().map(|(pl, ps)| format!("{}: pulled {} updated/{} deleted/{} conflicts, pushed {} changed/{} chunks", pl.folder, pl.files_updated, pl.files_deleted, pl.conflicts, ps.files_changed, ps.chunks_uploaded)).collect::<Vec<_>>().join("\n")
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
        Cmd::Fsck { verify } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            let r = engine.fsck(*verify)?;
            print(cli, &r, |r| {
                format!("referenced {} | with storage copy {} | verified elsewhere {} | claimed only {} | missing {:?} | claims without object {} | unreferenced objects {} | verified now {} | corrupt {:?} | forked {:?} | cold skipped {:?}", r.chunks_referenced, r.chunks_with_storage_copy, r.chunks_verified_elsewhere, r.chunks_claimed_only, r.chunks_missing, r.claims_without_object, r.objects_unreferenced, r.objects_verified_now, r.objects_corrupt, r.forked_devices, r.storages_skipped_cold)
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
                            "running: pid {} port {} version {}; {}",
                            v["pid"], v["port"], v["version"], v["service"]
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
        Cmd::Tray { interval, open } => tray::run(home, *interval, *open)?,
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
                    let method = engine
                        .folders()
                        .into_iter()
                        .find(|(r, _)| {
                            &r.name == folder || r.folder_id.as_str().starts_with(folder.as_str())
                        })
                        .and_then(|(r, _)| r.strongroom.map(|i| i.method))
                        .ok_or_else(|| anyhow!("{folder} is not a Strongroom folder"))?;
                    let backend = varsto_core::strongroom::backend(&method, &home);
                    let key = engine.unlock_strongroom(folder, backend.as_ref(), *minutes)?;
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
                        println!(
                            "{name}: {:?}, {}",
                            method,
                            match until {
                                Some(u) => format!("unlocked until {u} (this process)"),
                                None => "locked".into(),
                            }
                        );
                    }
                    if let Some((_, sv)) = service::status(&home) {
                        if let Some(arr) = sv.get("strongrooms").and_then(|v| v.as_array()) {
                            println!("background service: {}", serde_json::to_string(arr)?);
                        }
                    }
                }
            }
        }
        Cmd::P2p { cmd } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            match cmd {
                P2pCmd::Enable { port, public_addrs } => {
                    engine.set_p2p_config(varsto_core::vault::P2pConfig {
                        enabled: true,
                        port: *port,
                        public_addrs: public_addrs.clone(),
                    })?;
                    println!(
                        "p2p enabled on port {port}{}; restart the background service to apply",
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
                        }
                    );
                }
                P2pCmd::Disable => {
                    let mut c = engine.p2p_config();
                    c.enabled = false;
                    engine.set_p2p_config(c)?;
                    println!("p2p disabled; restart the background service to apply");
                }
                P2pCmd::Status => {
                    let c = engine.p2p_config();
                    let peers = engine.peer_records()?;
                    let probe = varsto_core::p2p::Peers::new(
                        engine.peer_key(),
                        engine.device_id().clone(),
                        peers,
                    )
                    .probe();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({"config": c, "peers": probe.iter().map(|(p, ok)| serde_json::json!({"device": p.device.to_string(), "name": p.name, "addr": p.addr.to_string(), "reachable": ok})).collect::<Vec<_>>()})
                        );
                    } else {
                        println!(
                            "p2p: {}, port {}, public {:?}",
                            if c.enabled { "enabled" } else { "disabled" },
                            c.port,
                            c.public_addrs
                        );
                        if probe.is_empty() {
                            println!("no peer records yet (other devices publish one when their service runs with p2p enabled)");
                        }
                        for (p, ok) in probe {
                            println!(
                                "  {} {} at {}: {}",
                                p.name,
                                p.device.short(),
                                p.addr,
                                if ok { "reachable" } else { "no answer" }
                            );
                        }
                    }
                }
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
