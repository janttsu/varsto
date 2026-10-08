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
        #[arg(long)]
        vault_key: String,
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
            storage_name,
            storage_path,
        } => {
            let spec = StorageSpec::LocalDir {
                name: storage_name.clone(),
                path: storage_path.clone(),
                cold: false,
                carrier: false,
            };
            let engine = Engine::join(&home, name, &passphrase()?, vault_key, spec)?;
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
                } => {
                    engine.add_storage(StorageSpec::LocalDir {
                        name: name.clone(),
                        path: path.clone(),
                        cold: *cold,
                        carrier: *carrier,
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
                    };
                    let tgt = StorageSpec::LocalDir {
                        name: "target".into(),
                        path: target.clone(),
                        cold: false,
                        carrier: false,
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
