// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto`: command-line interface (alpha). Every command has a `--json`
//! output for scripts (P-004); exit codes: 0 ok, 1 failure, 2 usage.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

/// mimalloc for every allocation of the binary (feature `mimalloc`, on by
/// default): the system allocator, musl's above all, is a bottleneck on the
/// allocation-heavy paths (JSON, file lists, per-block buffers).
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod backup;
mod desktop;
mod drive_mount;
mod drives;
mod f3cmd;
mod filemanager;
mod history;
mod icon;
mod import;
mod logcmd;
mod mcp;
mod mcp_keys;
mod placing;
mod readcache;
mod remember;
mod restic;
mod service;
mod sse;
mod trash;
mod tray;
mod update;
mod upkeep;
mod view;
mod viz;

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
    /// Detail of the local debug log: error, warn, info, debug (default) or
    /// trace, or a filter such as `debug,varsto_core::p2p=trace`. Overrides
    /// VARSTO_LOG and `log_level` in config.json.
    #[arg(long, global = true, value_name = "LEVEL")]
    log_level: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum LedgerCmd {
    /// List the ledger batches held on this device.
    List,
    /// Heads per device, where each device's batches are held (this device
    /// and every storage), checkpoints, fork state, and whether a rebuild
    /// is recommended.
    Status,
    /// Restore this device's ledger from the storages: its own batches and
    /// checkpoints (continuing after the newest), the other devices'
    /// batches and the view. A device restored from an old backup adopts
    /// its later history when it is its own; two copies of one device are
    /// refused.
    Rebuild {
        /// Also rebuild the record of where the blocks are from what the
        /// storages hold (when no ledger is left anywhere): every object the
        /// folders' newest manifests name is looked up, verified and claimed.
        #[arg(long)]
        from_storage: bool,
        /// Verify every object before claiming it (default: all up to 1 GiB, otherwise up to --verify-budget-mib).
        #[arg(long, conflicts_with = "no_verify")]
        verify: bool,
        /// Claim the objects without reading them.
        #[arg(long)]
        no_verify: bool,
        /// How much to read for verification when the vault is large.
        #[arg(long, default_value_t = 1024)]
        verify_budget_mib: u64,
        /// Also read cold storages (retrievals may be billed).
        #[arg(long)]
        confirm_cold_read: bool,
    },
    /// Delete the junk under this device's ledger name on the hot storages:
    /// objects there that this device did not sign (someone with the
    /// storage's credentials wrote them). Without --yes, only lists them.
    CleanJunk {
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault on this device and print the vault key once.
    Init {
        /// Name of this device (default: the computer's name).
        #[arg(long, default_value_t = default_device_name())]
        name: String,
    },
    /// Unlock the running background service with the passphrase. With
    /// --with-recovery-key it also keeps the recovery words for this session
    /// (in memory only, until it stops or is locked): folders added and
    /// folder epochs started meanwhile get their recovery copy at once.
    Unlock {
        #[arg(long)]
        with_recovery_key: bool,
        /// File with the recovery words (24); without it VARSTO_RECOVERY_WORDS,
        /// a pipe or a hidden prompt.
        #[arg(long, value_name = "FILE", requires = "with_recovery_key")]
        recovery_file: Option<PathBuf>,
    },
    /// Join an existing vault through a storage that holds it.
    Join {
        /// Name of this device (default: the computer's name).
        #[arg(long, default_value_t = default_device_name())]
        name: String,
        /// File with the vault key (64 hex digits, from `init`) or the 24 words
        /// of the recovery kit. Without it Varsto reads VARSTO_VAULT_KEY, then
        /// standard input when it is not a terminal, then asks (hidden). The
        /// key is never taken from the command line.
        #[arg(long, value_name = "FILE")]
        key_file: Option<PathBuf>,
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
        /// File with the secret access key. Without it Varsto reads
        /// VARSTO_S3_SECRET, then asks on the terminal (hidden).
        #[arg(long, value_name = "FILE")]
        s3_secret_file: Option<PathBuf>,
        /// Allow an http:// endpoint outside this computer (no transport encryption).
        #[arg(long, requires = "s3_endpoint")]
        s3_insecure_http: bool,
        /// Also give the recovery words (asked hidden, or from
        /// VARSTO_RECOVERY_WORDS): every folder with a recovery copy opens on
        /// this device. The vault words alone give folder names, no content.
        #[arg(long)]
        recovery_words: bool,
    },
    /// Manage storages.
    Storage {
        #[command(subcommand)]
        cmd: StorageCmd,
    },
    /// Removable disks of a disk pool: init, add, insert, unmount, list, check, eject, retire.
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
    /// Move a folder's blocks (or those of its idle files) from one storage
    /// to another: copy, check, then remove from the old one. Never drops a
    /// copy the folder's policy needs, nor the last one; run it again to
    /// carry on after an interruption. A move to a disk pool (or with
    /// --path, --keep-source or --job) is a job: it moves what fits on the
    /// attached disks, waits for the next disk and goes on by itself;
    /// `move status|pause|resume|cancel` manage jobs.
    #[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
    Move {
        #[command(subcommand)]
        cmd: Option<placing::MoveCmd>,
        #[arg(required = true)]
        folder: Option<String>,
        #[arg(long, required = true)]
        from: Option<String>,
        #[arg(long, required = true)]
        to: Option<String>,
        /// Only files and directories at or under this path of the folder
        /// (repeatable; relative to the folder or inside its directory).
        #[arg(long = "path")]
        paths: Vec<String>,
        /// Copy and check, but keep the blocks on the old storage.
        #[arg(long)]
        keep_source: bool,
        /// Record the move as a job that goes on by itself, also between
        /// ordinary storages.
        #[arg(long)]
        job: bool,
        /// Only files not used for this many days.
        #[arg(long)]
        idle_days: Option<i64>,
        /// Show what would move and what it costs; change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Allow reading from cold storage (the old one, or the new one to check the copies).
        #[arg(long)]
        confirm_cold_read: bool,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Backups: read-only snapshots of a directory of this device, kept on
    /// the storages only, each for a number of days.
    Backup {
        #[command(subcommand)]
        cmd: backup::BackupCmd,
    },
    /// Import a git-annex repository, a cloud drive (Dropbox, OneDrive, any
    /// rclone remote) or a local directory into a folder; status, verify, cleanup.
    Import {
        #[command(subcommand)]
        cmd: import::ImportCmd,
    },
    /// The trash: files deleted on any device, kept for a number of days
    /// (30 by default) and restorable on every device.
    Trash {
        #[command(subcommand)]
        cmd: trash::TrashCmd,
    },
    /// Earlier versions of overwritten files: `varsto history <folder>
    /// <path>` lists them; restore, set and status. Kept on a thinning
    /// schedule for 90 days by default.
    History(history::HistoryArgs),
    /// Show vault, devices, storages and folders.
    Status,
    /// Who changed what and when: the versions of one file (renames followed), or the recent
    /// changes in a folder or under a directory, newest first, from the signed manifests.
    Changes {
        folder: String,
        /// A file, or a directory to show the changes under.
        path: Option<String>,
        /// Only changes made on this device (name or id).
        #[arg(long)]
        device: Option<String>,
        /// Only changes by this person (organizations).
        #[arg(long)]
        user: Option<String>,
        /// Only changes since: YYYY-MM-DD[THH:MM] (UTC), seconds since 1970, or an age (7d, 12h).
        #[arg(long)]
        since: Option<String>,
        /// At most this many (0: all).
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Where you are now and what to do next: where your data is, what
    /// needs attention, and the next steps with the commands to run (the
    /// interface's Help page as text). Works without a vault too.
    HelpNow,
    /// How files would be fetched: from pool disks (which ones, in which order) or the network,
    /// with the time and cost of each way. Run `varsto folder fetch` to fetch.
    FetchPlan {
        folder: String,
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Compare the ledger with the storages: every claimed pack present at its size class, every
    /// block of a current file in a pack, every announced record on the storages; --verify reads
    /// every pack whole and hashes it against its id.
    Fsck {
        #[arg(long)]
        verify: bool,
        /// Repair what was found right away: copy missing packs whole from another storage and
        /// rebuild damaged ones (see `varsto repair`).
        #[arg(long, alias = "repair")]
        fix: bool,
    },
    /// Rewrite missing or corrupt copies on this device's storages from another copy.
    Repair {
        /// Show what would be repaired and from where; write nothing.
        #[arg(long)]
        dry_run: bool,
        /// Also read cold storages as a source (retrieval fees may apply).
        #[arg(long)]
        from_cold: bool,
        /// Work on the queue only, without comparing the ledger with the storages first.
        #[arg(long)]
        no_scan: bool,
        /// Most MiB written in this run.
        #[arg(long)]
        max_mib: Option<u64>,
        /// Most blocks written in this run.
        #[arg(long)]
        max_blocks: Option<u64>,
    },
    /// List duplicate files in a folder.
    Dupes { folder: String },
    /// The ledger: list batches (default), show its state, rebuild it.
    Ledger {
        #[command(subcommand)]
        cmd: Option<LedgerCmd>,
    },
    /// The local debug log: where it is, follow it, pack it for a bug report.
    Log {
        #[command(subcommand)]
        cmd: logcmd::LogCmd,
    },
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
    /// Install on this computer: the binary on PATH, the background service
    /// and tray at login, an application menu entry (Linux: no root needed).
    Install {
        #[arg(long, default_value_t = 300)]
        interval: u64,
    },
    /// Undo `install`; the vault and folders stay.
    Uninstall,
    /// What this device and the other devices of the vault are doing right
    /// now (checking a disk, uploading a folder, ...), with progress and the
    /// estimated finish. Asks the background service, which asks the peers.
    Activity {
        /// Refresh every two seconds until interrupted.
        #[arg(long)]
        watch: bool,
    },
    /// Uploads and downloads running now in the background service: each
    /// file with its progress and speed, and the traffic with every peer.
    Transfers {
        /// Refresh every second until interrupted.
        #[arg(long)]
        watch: bool,
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
    /// Check for a new release and install it over this binary. With
    /// `--daily`: the newest daily (test) build instead of a release, from a
    /// list signed with the separate daily key.
    Update {
        /// Only report whether an update exists.
        #[arg(long)]
        check: bool,
        /// Install on the word of the download site and its signature alone
        /// when the GitHub release cannot be reached to cross-check it.
        #[arg(long)]
        allow_single_source: bool,
        /// Take the latest daily build (a development build, not a release)
        /// instead of a release. The background updater never does this.
        #[arg(long, conflicts_with = "stable")]
        daily: bool,
        /// Take releases (the default); on a daily build, go back to them.
        #[arg(long, conflicts_with = "daily")]
        stable: bool,
    },
    /// Show or change settings of this device. `varsto config` lists them;
    /// `varsto config auto-update off` stops the daily check for a new version
    /// (and, on Windows, its installation); `on` turns it back on.
    Config {
        /// Setting name: auto-update.
        key: Option<String>,
        /// New value: on or off.
        value: Option<String>,
    },
    /// Check a downloaded release file: the release signature on SHA256SUMS
    /// (next to the file, or fetched from the download page), then the file's SHA-256.
    VerifyRelease {
        /// The downloaded archive (or SHA256SUMS itself, to check only the signature).
        file: PathBuf,
        /// The checksum list (default: SHA256SUMS next to the file).
        #[arg(long)]
        sums: Option<PathBuf>,
        /// Its signature (default: the checksum list's path + .sig).
        #[arg(long)]
        sig: Option<PathBuf>,
        /// Also compare with the checksum list of the GitHub release.
        #[arg(long)]
        github: bool,
    },
    /// Download (fetch) or free files given by their paths on disk, through the
    /// running background service when there is one; used by file-manager actions.
    Paths {
        /// Report failures as a desktop notification or message box (no terminal).
        #[arg(long)]
        notify: bool,
        #[arg(value_parser = ["fetch", "free"])]
        action: String,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Download a placeholder and open the file (double-click on a .varsto-placeholder).
    OpenPlaceholder { path: PathBuf },
    /// Open a varsto:// invitation link in the interface (the system calls this when a link or a
    /// QR code scanned with the phone or computer camera is opened).
    #[command(hide = true)]
    OpenLink { uri: String },
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
    /// Organization: administrators who approve devices and remove people (business use).
    Org {
        #[command(subcommand)]
        cmd: OrgCmd,
    },
    /// Strongroom folders: opened only with a touch of your FIDO2 security key.
    Strongroom {
        /// Require user verification (the key's PIN or biometric) in addition to
        /// the PIN prompt, for every touch. An enrolment made without it opens
        /// only without it: enrol again to change it.
        #[arg(long, global = true)]
        uv: bool,
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
    /// File analyses: what a file contains, in words and tags, recorded by
    /// an assistant (MCP) or by hand; synced encrypted to every device.
    Analysis {
        #[command(subcommand)]
        cmd: AnalysisCmd,
    },
    /// Find files by their analysis, tags and path (every word must match).
    Search {
        /// Words to look for (case-insensitive).
        query: Vec<String>,
        /// Only this folder (default: every attached folder).
        #[arg(long)]
        folder: Option<String>,
        /// Only files with this tag (repeatable).
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// MCP server for AI assistants (stdio), with per-folder grants and
    /// scoped keys. See docs/mcp.md in the repository (https://github.com/janttsu/varsto).
    Mcp {
        /// File with the MCP key (from `varsto mcp key create`); its scope
        /// replaces the grants file. Without it Varsto reads VARSTO_MCP_KEY.
        /// The key is never taken from the command line.
        #[arg(long, value_name = "FILE")]
        key_file: Option<PathBuf>,
        #[command(subcommand)]
        cmd: Option<McpCmd>,
    },
    /// Forwarding: carry other devices' blocks to this device's storages
    /// (also for folders kept selective here): show, run now, turn on or off.
    Forward {
        #[command(subcommand)]
        cmd: Option<upkeep::ForwardCmd>,
    },
    /// The mailbox for offline pool disks: blocks staged from a docked disk
    /// for a disk or storage that is away; show, run now, turn on or off,
    /// set the free space it keeps.
    Mailbox {
        #[command(subcommand)]
        cmd: Option<upkeep::MailboxCmd>,
    },
    /// Automatic verification of blocks other devices wrote: show, run now, set the schedule.
    Verify {
        #[command(subcommand)]
        cmd: Option<upkeep::VerifyCmd>,
    },
    /// Bit-rot check (scrub): re-hash copies on the storages and the synced
    /// files on this device within the budget; `scrub status`, `scrub set`.
    #[command(args_conflicts_with_subcommands = true)]
    Scrub {
        #[command(subcommand)]
        cmd: Option<upkeep::ScrubCmd>,
        #[command(flatten)]
        run: upkeep::ScrubRunArgs,
    },
    /// Backups of the whole vault with restic: one device keeps every folder
    /// as a full plaintext copy (the mirror) and backs it up into a restic
    /// repository outside the vault; restoring needs only restic.
    Restic {
        #[command(subcommand)]
        cmd: restic::ResticCmd,
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
    /// Two devices wrote the same key epoch at once (each removing a
    /// device): keep the epoch of one of them. Until then this device signs
    /// nothing.
    ResolveEpoch {
        /// The key epoch number (see `varsto ledger status`).
        epoch: u32,
        /// The device whose epoch to keep (name or id).
        #[arg(long)]
        keep: String,
    },
}

#[derive(Subcommand)]
enum PairCmd {
    /// On a device that holds the vault: show a code and wait for the new
    /// device. When it connects, its name and six words are shown and you
    /// are asked whether they match the words the new device shows; only
    /// then does it get the vault, and the folders named with --folders.
    Offer {
        /// Also show a QR code (a varsto://pair link with the code and the addresses).
        #[arg(long)]
        qr: bool,
        /// Folders the new device may open at once (comma-separated names or
        /// ids; this device must own them). By default none: it asks for
        /// folders later with `varsto folder request`.
        #[arg(long, value_delimiter = ',')]
        folders: Vec<String>,
        /// The role in those folders: editor or viewer.
        #[arg(long, default_value = "editor")]
        role: String,
        /// Do not ask whether the six words match (scripts that compared
        /// them another way).
        #[arg(long)]
        yes: bool,
    },
    /// On the new device: join the vault of the device showing the code.
    Join {
        /// Name of this device (default: the computer's name).
        #[arg(long, default_value_t = default_device_name())]
        name: String,
        /// The nine digits shown on the other device, or the varsto://pair link of its QR code.
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
        /// Storage format 3: print the recovery words too, as the second word
        /// set of the kit. The words are read from VARSTO_RECOVERY_WORDS, a
        /// pipe, or asked for (hidden); they are never taken from the command line.
        #[arg(long, conflicts_with = "shares")]
        recovery_words: bool,
        /// Storage format 3: make a new recovery key and print it as the
        /// second word set. Folders get recovery copies under it with
        /// `varsto recovery escrow`.
        #[arg(long, conflicts_with_all = ["shares", "recovery_words"])]
        new_recovery_key: bool,
    },
    /// Storage format 3: write the recovery copies that folders lack, so
    /// that the vault words and the recovery words restore them. Asks for the
    /// recovery words (hidden), unless --with-recovery-key.
    Escrow {
        /// Only this folder (default: every folder that lacks a copy).
        folder: Option<String>,
        /// Take the recovery words from VARSTO_RECOVERY_WORDS (the copy kept
        /// for this session) without asking.
        #[arg(long)]
        with_recovery_key: bool,
        /// File with the recovery words (24 words).
        #[arg(long, value_name = "FILE")]
        recovery_file: Option<PathBuf>,
    },
    /// Rebuild the vault key from shares (`<index>: <24 words>`, one per line).
    /// The shares are read from the files given with --file, else from standard
    /// input when it is not a terminal, else asked for (hidden); they are never
    /// taken from the command line.
    Combine {
        /// A file with one or more shares, one per line (repeatable).
        #[arg(long = "file", value_name = "FILE")]
        files: Vec<PathBuf>,
        /// The "Key check" printed on the kit: the rebuilt key is refused when it does not match.
        #[arg(long)]
        check: Option<String>,
    },
    /// What to keep outside your devices to restore everything if all of them are lost, and
    /// the restore steps for a new device. Personal to this vault; holds no secret.
    Guide {
        #[arg(long, value_enum, default_value_t = GuideFormat::Text)]
        format: GuideFormat,
        /// Write to this file instead of standard output.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum GuideFormat {
    Text,
    Markdown,
    /// A printable page with checkboxes.
    Html,
}

#[derive(Subcommand)]
enum OrgCmd {
    /// Turn this vault into an organization's vault: this device becomes the first
    /// administrator, every current device belongs to --user, and the root key is printed
    /// once as 24 words (keep them offline; they appoint and dismiss administrators).
    Create {
        #[arg(long)]
        name: String,
        /// The person who owns the devices in the vault today.
        #[arg(long)]
        user: String,
    },
    /// Administrators, people and their devices, the policy, devices waiting to be added.
    Status,
    /// (New device) Print a request code and its six-word fingerprint for an administrator.
    Request {
        /// Name of this device, bound to the code.
        /// Name of this device (default: the computer's name).
        #[arg(long, default_value_t = default_device_name())]
        name: String,
    },
    /// (Administrator) Approve a request code: the device joins under --user and gets a token
    /// to paste. Compare the six words with the person first.
    Approve {
        code: String,
        #[arg(long)]
        user: String,
        /// The fingerprint the person read to you; it must match the code's.
        #[arg(long)]
        fingerprint: Option<String>,
        /// Approve without asking whether the fingerprint matches.
        #[arg(long)]
        yes: bool,
    },
    /// (New device) Join the vault with the approval token.
    Join {
        /// Name of this device (default: the computer's name).
        #[arg(long, default_value_t = default_device_name())]
        name: String,
        #[arg(long)]
        token: String,
    },
    /// (Administrator) Add a device that already holds the vault key (it paired, or joined
    /// with the key) to the organization; until then the others ignore it.
    AddDevice {
        device: String,
        #[arg(long)]
        user: String,
    },
    /// (Administrator) Remove a person: every device of theirs is cut off in one step and the
    /// vault gets new keys; with --wipe they delete their keys and folder contents.
    RemoveUser {
        user: String,
        #[arg(long)]
        wipe: bool,
        #[arg(long)]
        yes: bool,
    },
    /// (Administrator) What members may do on their own: share, add-storages, set-policies,
    /// add-devices; `policy platforms` sets which device platforms may belong. Without
    /// arguments, show the policy.
    #[command(args_conflicts_with_subcommands = true)]
    Policy {
        #[command(subcommand)]
        cmd: Option<OrgPolicyCmd>,
        #[arg(long, value_delimiter = ',')]
        allow: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        deny: Vec<String>,
    },
    /// Administrators: appoint or dismiss one with the organization's root words.
    Admin {
        #[command(subcommand)]
        cmd: OrgAdminCmd,
    },
    /// Who approved, added, removed or changed what, oldest first (signed by the
    /// administrator devices; use --json to export).
    Log,
}

#[derive(Subcommand)]
enum OrgPolicyCmd {
    /// (Administrator) Which device platforms may join and open the vault: linux, macos,
    /// windows, android, ios. Devices of other platforms are refused at approval, and devices
    /// already in the organization are locked out (no new keys, the others ignore what they
    /// write, their own app refuses to open the vault) until they are allowed again. Without
    /// arguments, show the setting.
    Platforms {
        /// Allowed platforms, e.g. linux,macos,windows.
        #[arg(long, value_delimiter = ',', conflicts_with = "allow_all")]
        allow: Vec<String>,
        /// Allow every platform.
        #[arg(long)]
        allow_all: bool,
        /// Oldest Varsto version a device may run (e.g. 0.0.1-alpha.14); `any` removes it.
        #[arg(long)]
        min_version: Option<String>,
    },
}

#[derive(Subcommand)]
enum OrgAdminCmd {
    /// Make a device of the organization an administrator.
    Add {
        device: String,
        /// File with the 24 root words printed when the organization was
        /// created. Without it Varsto reads VARSTO_ORG_ROOT_WORDS, then standard
        /// input when it is not a terminal, then asks (hidden).
        #[arg(long, value_name = "FILE")]
        root_words_file: Option<PathBuf>,
    },
    /// Take the administrator role from a device (it stays a member).
    Remove {
        device: String,
        /// File with the 24 root words (see `org admin add`).
        #[arg(long, value_name = "FILE")]
        root_words_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum StrongroomCmd {
    /// Create a Strongroom folder (two touches of the key). Needs the libfido2 tools (fido2-cred, fido2-assert).
    Create {
        name: String,
        path: PathBuf,
        /// Use a software key file instead of hardware: for trying the flow only, no real protection.
        #[arg(long, hide = !varsto_core::strongroom::SOFTWARE_KEYS_BUILT_IN)]
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
        #[arg(long, hide = !varsto_core::strongroom::SOFTWARE_KEYS_BUILT_IN)]
        software: bool,
        #[arg(long, default_value_t = 15)]
        minutes: u64,
        /// Also replace this device's plain copies with placeholders once the conversion is done.
        #[arg(long)]
        free: bool,
    },
    /// Enroll a backup security key (one touch of an enrolled key, then two of the new one).
    AddKey {
        folder: String,
        /// A name for the key, e.g. "safe".
        #[arg(long, default_value = "")]
        label: String,
        /// The new key is a software key file (testing only).
        #[arg(long, hide = !varsto_core::strongroom::SOFTWARE_KEYS_BUILT_IN)]
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
    /// Rotate a Strongroom's key: a new random key wrapped for every enrolled security key (one
    /// touch to unlock, then one per key), content re-encrypted, old copies deleted. Use it after
    /// removing a key that someone may have kept, or when you suspect the key leaked. Run it
    /// again to resume an interrupted re-key.
    Rekey {
        folder: String,
        #[arg(long, default_value_t = 15)]
        minutes: u64,
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
    /// Ask the home router to forward the peer-to-peer port (PCP, NAT-PMP, UPnP): on (default) or off.
    PortMapping {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Show settings, NAT guess, public address and the path to every peer.
    Status,
    /// Live traffic per peer: speed, totals and path, from the running service.
    Traffic {
        /// Refresh every second until interrupted.
        #[arg(long)]
        watch: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Set a folder's policy (replaces the previous one) and publish it to every device.
    Set {
        folder: String,
        /// Minimum copies on any storage that is not a transferrer.
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
    /// Let the assistant see a folder (or `all`); --analyse also allows
    /// recording file analyses, --write also moving, renaming and creating files.
    Grant {
        folder: String,
        #[arg(long)]
        write: bool,
        #[arg(long, alias = "analyze", conflicts_with = "write")]
        analyse: bool,
    },
    /// Remove a grant (or `all`).
    Revoke { folder: String },
    /// Show current grants.
    List,
    /// Scoped keys that let an MCP client use the running service.
    Key {
        #[command(subcommand)]
        cmd: McpKeyCmd,
    },
    /// Print a ready-to-paste configuration for an MCP client.
    Config {
        /// claude (Claude Desktop and Claude Code), opencode, crush, qwen or generic.
        #[arg(long, default_value = "generic")]
        client: String,
        /// Create a key now and put it in the configuration (else a placeholder).
        #[arg(long)]
        create_key: bool,
        /// Name of the key to create.
        #[arg(long, requires = "create_key")]
        key_name: Option<String>,
        /// Folders of the new key, comma-separated, or all (default: the current grants).
        #[arg(long, value_delimiter = ',', requires = "create_key")]
        folders: Vec<String>,
        #[arg(long, requires = "create_key")]
        write: bool,
        #[arg(
            long,
            alias = "analyze",
            requires = "create_key",
            conflicts_with = "write"
        )]
        analyse: bool,
        #[arg(long, requires = "create_key")]
        expires_days: Option<i64>,
    },
}

#[derive(Subcommand)]
enum McpKeyCmd {
    /// Create a key and print it once. Its scope: --folders at the level of
    /// --write or --analyse (read-only otherwise), or the current grants.
    Create {
        #[arg(long)]
        name: Option<String>,
        /// Comma-separated folder names, or all.
        #[arg(long, value_delimiter = ',')]
        folders: Vec<String>,
        #[arg(long)]
        write: bool,
        #[arg(long, alias = "analyze", conflicts_with = "write")]
        analyse: bool,
        /// The key stops working after this many days.
        #[arg(long)]
        expires_days: Option<i64>,
    },
    /// List keys (never the keys themselves).
    List,
    /// Revoke a key by name or id; clients using it are refused at once.
    Revoke { name_or_id: String },
}

#[derive(Subcommand)]
enum AnalysisCmd {
    /// Show a file's analysis in full.
    Show { folder: String, path: String },
    /// Record a file's analysis (replaces the earlier one): --text or
    /// --from-file (`-` reads standard input), at most 16 KiB.
    Set {
        folder: String,
        path: String,
        #[arg(
            long,
            conflicts_with = "from_file",
            required_unless_present = "from_file"
        )]
        text: Option<String>,
        #[arg(long)]
        from_file: Option<PathBuf>,
        /// A tag (repeatable, at most 32).
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Who wrote it (a model or tool name).
        #[arg(long)]
        by: Option<String>,
    },
    /// Clear a file's analysis on every device.
    Clear { folder: String, path: String },
    /// Every analysis of a folder.
    List { folder: String },
}

#[derive(Subcommand)]
enum ShareCmd {
    /// (Recipient) Print a request code for this device and its fingerprint (six words); the
    /// owner seals the share token to it after comparing the words with you.
    Request {
        /// Your name, bound to the code (the owner sees it, and it is part of the fingerprint).
        #[arg(long)]
        name: Option<String>,
        /// Also show the code as a QR code for the owner to scan.
        #[arg(long)]
        qr: bool,
    },
    /// Show a request code, a sealed token or a varsto:// link as a QR code in the terminal.
    /// Plain tokens are refused: they carry the folder key.
    Qr {
        /// The request code, sealed token (vst1…/vst2…) or varsto:// link.
        text: String,
        /// Show it as a sequence of smaller codes, one after another, for cameras that cannot read
        /// the dense one (the Varsto scanner collects them; Ctrl-C stops).
        #[arg(long)]
        parts: bool,
        /// The terminal has dark text on a light background.
        #[arg(long)]
        light: bool,
    },
    /// (Owner) Print a share token for a folder. With --to <request-code> the folder key is
    /// encapsulated to the recipient (hybrid X25519 + ML-KEM-768) and the token is safe to send
    /// over any channel; without it the key is in the token and the channel must be secure.
    /// Before sealing, compare the code's six-word fingerprint with the requester (call them,
    /// or meet): it proves the code is theirs.
    Create {
        folder: String,
        #[arg(long)]
        to: Option<String>,
        /// The fingerprint the requester read to you; it must match the code's (skips the question).
        #[arg(long)]
        fingerprint: Option<String>,
        /// Seal without asking whether the fingerprint matches (you compared it some other way).
        #[arg(long)]
        yes: bool,
        /// Also show the sealed token as a QR code for the recipient to scan.
        #[arg(long)]
        qr: bool,
        /// What the recipient may do: editor (read and write) or viewer (read only: nothing it
        /// changes is accepted by your devices or the editors). A viewer needs --to.
        #[arg(long, default_value = "editor")]
        role: String,
    },
    /// (Owner) Who has access to a shared folder, with each member's role: your devices,
    /// members (current and removed) and tokens not accepted yet.
    Members { folder: String },
    /// (Owner) Make a member a viewer (read only) or an editor (read and write). What a viewer
    /// wrote while it was an editor stays; what it writes from now on is not accepted.
    Role {
        folder: String,
        /// Member name or device id (see `share members`).
        member: String,
        /// viewer or editor.
        role: String,
    },
    /// (Owner) Remove a member (name or device id) or revoke a token not accepted yet (its id or
    /// fingerprint words), or `all`: the folder gets a new key for everything written from now on.
    Revoke {
        folder: String,
        member: String,
        #[arg(long)]
        yes: bool,
    },
    /// (Recipient) Accept a shared folder into a new device directory (one per shared vault),
    /// through a directory or an S3 bucket that both users can reach.
    Accept {
        /// Name of this device (default: the computer's name).
        #[arg(long, default_value_t = default_device_name())]
        name: String,
        /// The sealed token, as text or as the varsto://share/token link a QR code holds.
        #[arg(
            long = "token",
            value_name = "TOKEN",
            required_unless_present = "token_arg"
        )]
        token: Option<String>,
        #[arg(value_name = "TOKEN", conflicts_with = "token")]
        token_arg: Option<String>,
        /// Storage directory that both users can reach and that holds the owner's vault.
        #[arg(long, required_unless_present = "s3_bucket")]
        storage_path: Option<PathBuf>,
        #[arg(long, default_value = "shared")]
        storage_name: String,
        /// Accept through an S3-compatible bucket instead of a directory.
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
        /// File with the secret access key. Without it Varsto reads
        /// VARSTO_S3_SECRET, then asks on the terminal (hidden).
        #[arg(long, value_name = "FILE")]
        s3_secret_file: Option<PathBuf>,
        /// Allow an http:// endpoint outside this computer (no transport encryption).
        #[arg(long, requires = "s3_endpoint")]
        s3_insecure_http: bool,
    },
}

#[derive(Subcommand)]
enum ReplicaCmd {
    /// (Owner) Print the token to give to a replica device.
    Token,
    /// (Replica) Set up this directory as a replica of a vault.
    Init {
        /// Name of this device (default: the computer's name).
        #[arg(long, default_value_t = default_device_name())]
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
    /// Keep the passphrase so the service unlocks itself after a restart: in the desktop keyring, else (also over SSH) encrypted with systemd-creds, else in the kernel keyring (until restart). Says which one was used.
    Remember,
    /// Remove the remembered passphrase from every place `remember` may have put it.
    Forget,
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
        #[arg(long, conflicts_with = "cold")]
        carrier: bool,
        /// Destination device of the transferrer (repeatable): it carries what these devices lack.
        #[arg(long = "carrier-for", requires = "carrier")]
        carrier_for: Vec<String>,
        /// Place for durability policies (home, cloud, offsite, ...); default home.
        #[arg(long, default_value = "")]
        place: String,
    },
    /// Set the destination devices of a transferrer (none: any device that lacks a block).
    CarrierFor { name: String, devices: Vec<String> },
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
        /// File with the secret access key. Without it Varsto reads
        /// VARSTO_S3_SECRET, then asks on the terminal (hidden). Stored
        /// encrypted in secrets.enc; never taken from the command line.
        #[arg(long, value_name = "FILE")]
        secret_file: Option<PathBuf>,
        /// Use virtual-host style URLs (bucket.host) instead of path style.
        #[arg(long)]
        virtual_host: bool,
        /// Allow an http:// endpoint outside this computer: the request signatures and the
        /// (encrypted) objects then travel without transport encryption. A loopback address
        /// needs no flag.
        #[arg(long)]
        insecure_http: bool,
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
        /// Disk group rule: keep this many copies of every block on disks in different places.
        #[arg(long, default_value_t = 1)]
        copies: u32,
    },
    /// Change a storage's settings.
    Set {
        name: String,
        /// Free space kept on a local directory's disk: block writes stop below it,
        /// e.g. 5% or 10GB ("default": 5 %).
        #[arg(long)]
        min_free: String,
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
    /// Show or set a storage's prices (defaults come from the built-in price data when recognized).
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
    /// Empty a storage onto the others without weakening any folder's
    /// policy (to switch providers); `storage drain status` shows progress.
    Drain {
        /// The storage, or `status` for every drain.
        name: String,
        /// Stop draining: the storage takes new blocks again.
        #[arg(long, conflicts_with_all = ["plan", "remove_when_empty"])]
        stop: bool,
        /// Show what draining takes, change nothing.
        #[arg(long)]
        plan: bool,
        /// Remove the storage from this device once it is empty.
        #[arg(long)]
        remove_when_empty: bool,
        /// Copy at most this many GB (decimal) to other storages per day (egress costs).
        #[arg(long)]
        budget_gb_per_day: Option<f64>,
        /// Allow reading from this cold storage (retrieval fees, restore delays).
        #[arg(long)]
        confirm_cold_read: bool,
        /// Leave the work to the background service instead of running now.
        #[arg(long)]
        background: bool,
    },
    /// Show or set a storage's quota, which every device respects.
    Quota {
        name: String,
        /// Most bytes Varsto keeps there: 500GB, 1TB, 2TiB, ...
        #[arg(long, conflicts_with = "clear")]
        bytes: Option<String>,
        /// Most objects Varsto keeps there.
        #[arg(long, conflicts_with = "clear")]
        objects: Option<u64>,
        /// Remove the quota.
        #[arg(long)]
        clear: bool,
        /// List the storage to count its objects and measure its records.
        #[arg(long)]
        measure: bool,
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
        /// Where the disk is kept (home, offsite, ...); default the pool's place.
        #[arg(long, default_value = "")]
        place: String,
    },
    /// Set where a disk is kept ("" for the pool's place); disk groups keep copies in different places.
    Place { label: String, place: String },
    /// Disk group rules: show them, or keep N copies of every block on disks in different places.
    Group {
        pool: Option<String>,
        #[arg(long)]
        copies: Option<u32>,
    },
    /// Every disk of every pool: attached or away, free and total space (as last measured),
    /// what can be freed, the oldest copy check, last seen, the last file system check.
    List {
        /// Sort by name, free, used, checked (oldest first), reclaimable or seen (longest ago first).
        #[arg(long, default_value = "name")]
        sort: String,
        /// Reverse the order.
        #[arg(long)]
        reverse: bool,
    },
    /// Which disk to dock next and why: copies overdue for a check, data only on that disk,
    /// space to free, what the pool lacks, a repair or fetch waiting, long unseen.
    Suggest {
        /// Only the disks of this pool.
        #[arg(long)]
        pool: Option<String>,
        /// Turn the weekly "disk is overdue" reminder of the background service on or off.
        #[arg(long, value_parser = ["on", "off"])]
        remind: Option<String>,
    },
    /// Reattach routine: verify the marker and the objects, apply queued deletions, add new objects.
    Check {
        label: String,
        /// Re-hash every object (sizes alone otherwise).
        #[arg(long)]
        full: bool,
    },
    /// Write the disk's index and sync it; prints when the disk is safe to remove (does not unmount).
    Eject { label: String },
    /// Linux: erase a whole drive (e.g. /dev/sdc), make one ext4 partition, record it in
    /// disks.conf under LABEL (the name on its sticker), mount it, add it to the pool and fill it.
    Init {
        /// The whole drive, e.g. /dev/sdc or /dev/disk/by-id/usb-...
        device: PathBuf,
        #[arg(long)]
        pool: String,
        /// The drive's name, as on its sticker (spaces are fine).
        #[arg(long)]
        label: String,
        /// Where the drive is kept (home, offsite, ...); default the pool's place.
        #[arg(long, default_value = "")]
        place: String,
        /// The device path again, to erase it without being asked (scripts).
        #[arg(long)]
        confirm: Option<String>,
    },
    /// Linux: mount the known drives that are plugged in (or the named one) and bring them up to
    /// date: tidy from listings, re-hash old copies, fill, sync; then says to unmount.
    Insert {
        label: Option<String>,
        /// Skip writing new blocks.
        #[arg(long)]
        no_fill: bool,
        /// Skip re-hashing copies older than the pool's verify-after-days.
        #[arg(long)]
        no_verify: bool,
    },
    /// Linux: write the index, sync, unmount and power off a drive so it can be unplugged.
    Unmount {
        label: String,
        /// Leave the drive powered (only unmount).
        #[arg(long)]
        no_power_off: bool,
    },
    /// When large fetches propose pool disks: show the settings, or set them.
    FetchSet {
        /// Fetches at least this large are worth fetching disks for (default 2048).
        #[arg(long)]
        threshold_mib: Option<u64>,
        /// Time to fetch a disk from the shelf and plug it in (default 120).
        #[arg(long)]
        overhead_secs: Option<u64>,
        /// Download speed from the remote storages (default 100).
        #[arg(long)]
        link_mbit: Option<f64>,
        /// Read speed of a disk in the dock (default 120).
        #[arg(long)]
        disk_mb_per_sec: Option<f64>,
    },
    /// Pool settings: re-hash copies on a disk at insert when their last check is older than N days.
    PoolSet {
        pool: String,
        /// Days (default 180; 0 re-hashes everything at every insert).
        #[arg(long)]
        verify_after_days: u32,
    },
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
    ///
    /// With a DEVICE (storage format 3): remove that device from the folder.
    /// This starts a new folder epoch the device never gets; what it already
    /// read stays readable to it. Asks first; --yes skips the question.
    Remove {
        /// The folder (with DEVICE: the folder's name or id).
        name: String,
        /// Format 3: the device to remove (name or id).
        device: Option<String>,
        #[arg(long, conflicts_with = "device")]
        purge: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Storage format 3: ask the folder's owners for access. Prints this
    /// device's six words, which an owner compares before approving.
    Request {
        /// The folder (name or id).
        folder: String,
        /// The role you ask for: editor or viewer.
        #[arg(long, default_value = "editor")]
        role: String,
    },
    /// Storage format 3: requests waiting for an owner of FOLDER (default:
    /// every folder this device owns), with each device's name and six words.
    Requests {
        folder: Option<String>,
    },
    /// Storage format 3: approve a request. Shows the device's name and six
    /// words and asks "Do the six words match?"; a grant follows.
    Approve {
        folder: String,
        /// The requesting device (name or id).
        device: String,
        /// The role to give (default: the one asked for): editor or viewer.
        #[arg(long)]
        role: Option<String>,
        /// Skip the question (only when you compared the words already).
        #[arg(long)]
        yes: bool,
    },
    /// Storage format 3: deny a request.
    Deny {
        folder: String,
        device: String,
    },
    /// Storage format 3: a folder's participants with their roles, denied
    /// devices and pending requests.
    Members {
        folder: String,
    },
    /// Storage format 3: change a participant's role (owner, editor or viewer).
    Role {
        folder: String,
        device: String,
        role: String,
    },
    /// Storage format 3: two owners started the same folder epoch at once;
    /// keep the epoch of one of them.
    ResolveEpoch {
        folder: String,
        /// The folder epoch number (see `varsto folder members`).
        epoch: u32,
        /// The device whose epoch to keep (name or id).
        #[arg(long)]
        keep: String,
    },
    /// Storage format 3: make a folder in the membership records of the
    /// vault, this device its owner. `folder add` will do this once format 3
    /// is the format (work package 12).
    #[command(hide = true)]
    CreateF3 {
        name: String,
    },
    /// Create a folder in the vault and sync `path` into it.
    ///
    /// The folder's key gets a recovery copy at once under the recovery
    /// key: its 24 words come from --recovery-file, VARSTO_RECOVERY_WORDS,
    /// the copy `varsto unlock --with-recovery-key` gave the background
    /// service, or a hidden prompt (Enter writes it later with `varsto
    /// recovery escrow`; `varsto status` warns until then).
    Add {
        name: String,
        path: PathBuf,
        /// File with the recovery words (24).
        #[arg(long, value_name = "FILE")]
        recovery_file: Option<PathBuf>,
    },
    /// Sync an existing folder of the vault into `path` on this device.
    Attach {
        name_or_id: String,
        path: PathBuf,
        /// Selective sync: files appear as placeholders until fetched.
        #[arg(long)]
        selective: bool,
        /// How the folder syncs here: normal, send-only or receive-only.
        #[arg(long)]
        mode: Option<String>,
    },
    /// Turn selective sync on or off for an attached folder.
    Selective {
        name_or_id: String,
        #[arg(action = clap::ArgAction::Set, value_parser = clap::value_parser!(bool))]
        on: bool,
    },
    /// Download one placeholder file and keep it on this device.
    /// Give FOLDER PATH, or only the file's path on disk (the placeholder works too).
    Fetch {
        folder: String,
        path: Option<String>,
        /// Large fetches whose blocks are on pool disks: propose the disks and ask (default),
        /// use them without asking, or never.
        #[arg(long, value_enum, default_value_t = drives::FromDisks::Ask)]
        from_disks: drives::FromDisks,
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
    /// Show or change a folder's ignore rules (gitignore syntax): the
    /// `.varstoignore` at the folder's root, which every device shares, or
    /// with --local this device's own patterns, which are not synced.
    Ignore {
        folder: String,
        /// List the rules (what happens without --add or --remove).
        #[arg(long)]
        list: bool,
        /// Add a pattern (repeatable), e.g. --add '*.tmp' --add 'build/'.
        #[arg(long, allow_hyphen_values = true)]
        add: Vec<String>,
        /// Remove a pattern (repeatable).
        #[arg(long, allow_hyphen_values = true)]
        remove: Vec<String>,
        /// This device's own patterns instead of the synced file.
        #[arg(long)]
        local: bool,
    },
    /// Whether a path of a folder is ignored on this device, and by which
    /// pattern. A trailing / asks about a directory.
    CheckIgnore {
        folder: String,
        path: String,
    },
    /// Show or change a folder's settings on this device: which file
    /// metadata it syncs (permissions, symbolic links and extended
    /// attributes on by default, ownership off by default) and the free
    /// space kept on its disk.
    Set {
        folder: String,
        /// Free space kept on the disk holding the folder: downloads into it stop below it,
        /// e.g. 5% or 10GB ("default": 5 %).
        #[arg(long)]
        min_free: Option<String>,
        #[arg(long, value_name = "on|off", value_parser = clap::builder::BoolishValueParser::new())]
        permissions: Option<bool>,
        #[arg(long, value_name = "on|off", value_parser = clap::builder::BoolishValueParser::new())]
        symlinks: Option<bool>,
        #[arg(long, value_name = "on|off", value_parser = clap::builder::BoolishValueParser::new())]
        xattrs: Option<bool>,
        #[arg(long, value_name = "on|off", value_parser = clap::builder::BoolishValueParser::new())]
        ownership: Option<bool>,
    },
    /// Show or set which storages a folder's blocks are written to (default: every storage).
    Placement {
        folder: String,
        /// A storage that takes the folder's blocks (repeatable).
        #[arg(long)]
        storage: Vec<String>,
        /// Every storage at this place takes them (repeatable): home, cloud, offsite, ...
        #[arg(long)]
        place: Vec<String>,
        /// Back to every storage.
        #[arg(long, conflicts_with_all = ["storage", "place"])]
        every: bool,
    },
    List,
    /// Write the folder's marker (.varsto-folder) into its directory again,
    /// when the folder is paused because the marker is missing or names
    /// another folder and the directory is the right one.
    RepairMarker {
        name: String,
    },
    /// Decide on deletions the mass-deletion guard holds: confirm them
    /// (published, or applied here when another device made them), or with
    /// --discard restore the files (from the storages, or by keeping them and
    /// publishing them again).
    ConfirmDeletions {
        name: String,
        #[arg(long)]
        discard: bool,
    },
    /// Show or set this device's mode for a folder: normal, send-only (publish
    /// this device's changes, never apply the others') or receive-only (apply
    /// the others' changes, never publish this device's).
    Mode {
        name: String,
        mode: Option<String>,
    },
    /// Send-only: make every device match this one (the remote changes not
    /// applied here are overridden by this device's state).
    Override {
        name: String,
    },
    /// Receive-only: replace this device's local changes with the vault's
    /// versions; changed and added files go to the trash.
    Revert {
        name: String,
    },
    /// What waits for a decision in a folder: held deletions, local changes
    /// not published, remote changes not applied. (Who changed which file
    /// and when: `varsto changes`.)
    Pending {
        name: String,
    },
    /// Show or set when deletions are held for confirmation (default: more
    /// than 50 % and more than 100 files, or more than 1000 files).
    DeletionGuard {
        name: String,
        /// Share of the folder's files (100: no share rule).
        #[arg(long)]
        percent: Option<u32>,
        /// ... and more than this many files.
        #[arg(long)]
        min_files: Option<u64>,
        /// More than this many files whatever the share (0: no such limit).
        #[arg(long)]
        max_files: Option<u64>,
        /// Never hold deletions in this folder.
        #[arg(long, conflicts_with_all = ["percent", "min_files", "max_files", "default"])]
        off: bool,
        /// Back to the default.
        #[arg(long, conflicts_with_all = ["percent", "min_files", "max_files"])]
        default: bool,
    },
}

/// `varsto folder ignore` as text.
fn ignore_listing(i: &varsto_core::engine::IgnoreInfo, local_only: bool) -> String {
    let mut out = Vec::new();
    if !local_only {
        if !i.applies_here {
            out.push(
                "(this device keeps the folder encrypted: ignore rules apply only where it has plain files)"
                    .to_string(),
            );
        }
        out.push("synced (.varstoignore):".to_string());
        let lines: Vec<&str> = i.synced.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            out.push("  (none)".to_string());
        }
        out.extend(lines.iter().map(|l| format!("  {l}")));
        for n in &i.nested {
            out.push(format!("also: {n}"));
        }
    }
    out.push("this device only:".to_string());
    if i.local.is_empty() {
        out.push("  (none)".to_string());
    }
    out.extend(i.local.iter().map(|l| format!("  {l}")));
    out.join("\n")
}

/// "default" (or empty) for the default, else a limit such as 5% or 10GB.
fn min_free_arg(v: &str) -> Result<Option<varsto_core::freespace::MinFree>> {
    let t = v.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("default") {
        return Ok(None);
    }
    Ok(Some(varsto_core::freespace::MinFree::parse(t)?))
}

fn min_free_text(v: Option<varsto_core::freespace::MinFree>) -> String {
    match v {
        Some(m) => m.describe(),
        None => format!(
            "{} (the default)",
            varsto_core::freespace::DEFAULT.describe()
        ),
    }
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

/// Print a request code, sealed token or link as a terminal QR code (half
/// blocks), with what the other side compares: the fingerprint of a request.
/// With `parts`, cycle through smaller codes until Ctrl-C.
fn show_qr(text: &str, parts: bool, light: bool) -> Result<()> {
    use varsto_core::qr::{self, Link};
    let link = Link::from_text(text)?;
    let whole = link.to_uri()?;
    let uris = if parts || qr::code_for(&whole).is_err() {
        link.to_uris(0, qr::PART_CHARS)?
    } else {
        vec![whole.clone()]
    };
    let caption = match &link {
        Link::ShareRequest(code) => {
            let r = Engine::share_request_info(code)?;
            format!(
                "Share request{}. Fingerprint: {}",
                if r.name.is_empty() {
                    String::new()
                } else {
                    format!(" from {}", show(&r.name))
                },
                r.fingerprint
            )
        }
        Link::ShareToken(t) => format!(
            "Sealed share token for {} (only the requesting device opens it)",
            show(&varsto_core::vault::SealedShareToken::decode(t)?.name)
        ),
        Link::Pair { .. } => "Pairing code (works once, for ten minutes)".to_string(),
    };
    if uris.len() == 1 {
        println!("{}", qr::to_terminal(&uris[0], !light)?);
        println!("{caption}\nLink: {}", uris[0]);
        return Ok(());
    }
    let frames = uris
        .iter()
        .map(|u| qr::to_terminal(u, !light))
        .collect::<Result<Vec<_>>>()?;
    loop {
        for (i, f) in frames.iter().enumerate() {
            // Clear the screen and draw the next part.
            print!("\x1b[2J\x1b[H{f}\n{caption}\nPart {} of {}: scan with Varsto (Scan QR code); Ctrl-C stops.\n", i + 1, frames.len());
            std::io::Write::flush(&mut std::io::stdout())?;
            std::thread::sleep(std::time::Duration::from_millis(900));
        }
    }
}

/// `varsto share qr`: the code in the terminal, or with `--json` the links.
fn share_qr(json: bool, text: &str, parts: bool, light: bool) -> Result<()> {
    if !json {
        return show_qr(text, parts, light);
    }
    let link = varsto_core::qr::Link::from_text(text)?;
    let uris = if parts {
        link.to_uris(0, varsto_core::qr::PART_CHARS)?
    } else {
        vec![link.to_uri()?]
    };
    let mut v = serde_json::json!({"kind": link.kind(), "text": link.text(), "uris": uris});
    if let varsto_core::qr::Link::ShareRequest(c) = &link {
        v["fingerprint"] = Engine::share_request_info(c)?.fingerprint.into();
    }
    println!("{v}");
    Ok(())
}

/// `varsto open-link`: hand a `varsto://` link to the interface (the service
/// keeps it until the page takes it) and open the page; start the service
/// first when it is not running.
fn open_link(home: &Path, uri: &str) -> Result<()> {
    use std::io::IsTerminal;
    let gui = filemanager::detach_own_console() || !std::io::stderr().is_terminal();
    let run = || -> Result<()> {
        match varsto_core::qr::parse(uri)? {
            varsto_core::qr::Scanned::Link(_) => {}
            varsto_core::qr::Scanned::Part(p) => bail!(
                "this is part {} of {} of a split code: scan it in Varsto (Scan QR code)",
                p.index,
                p.count
            ),
        }
        if service::status(home).is_none() {
            std::process::Command::new(std::env::current_exe()?)
                .arg("--home")
                .arg(home)
                .args(["service", "run"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            for _ in 0..80 {
                if service::status(home).is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
        let (f, _) =
            service::status(home).ok_or_else(|| anyhow!("the Varsto service did not start"))?;
        let body = serde_json::json!({ "uri": uri }).to_string();
        let answer: serde_json::Value = serde_json::from_str(&service::http_post(
            &format!("http://127.0.0.1:{}/api/link", f.port),
            &f.token,
            &body,
        )?)?;
        if let Some(e) = answer["error"].as_str() {
            bail!("{e}");
        }
        let page = service::boot_url(&f)?;
        match std::env::var("VARSTO_OPENER")
            .ok()
            .filter(|o| !o.is_empty())
        {
            Some(opener) => {
                std::process::Command::new(opener).arg(&page).status()?;
            }
            None => desktop::open_in_browser(&page),
        }
        Ok(())
    };
    let r = run();
    if let Err(e) = &r {
        if gui {
            filemanager::report_failure(home, "Could not open the link", &format!("{e:#}"));
        }
    }
    r
}

/// This computer's name, for devices joined without `--name`.
fn default_device_name() -> String {
    let name = if cfg!(target_os = "macos") {
        std::process::Command::new("scutil")
            .args(["--get", "ComputerName"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else if cfg!(windows) {
        std::env::var("COMPUTERNAME").ok()
    } else {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .or_else(|_| std::fs::read_to_string("/etc/hostname"))
            .ok()
            .map(|h| h.trim().to_string())
    };
    name.filter(|n| !n.is_empty() && !n.contains('.'))
        .or_else(name_before_dot)
        .unwrap_or_else(|| "this-device".into())
}

fn name_before_dot() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .and_then(|h| h.trim().split('.').next().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
}

fn bail_usage<T>(msg: &str) -> Result<T> {
    Err(anyhow!("{msg}"))
}

/// A secret that must not ride in the command line (it would show in `ps`,
/// `/proc/*/cmdline` and the shell history): from a file, else from an
/// environment variable, else from standard input when it is not a terminal
/// (`stdin_ok`), else asked for on the terminal without echo.
fn secret_input(
    file: Option<&Path>,
    env: &str,
    prompt: &str,
    stdin_ok: bool,
) -> Result<zeroize::Zeroizing<String>> {
    use std::io::{IsTerminal, Read};
    let got = if let Some(f) = file {
        let text = std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?;
        zeroize::Zeroizing::new(text)
    } else if let Some(v) = std::env::var(env).ok().filter(|v| !v.trim().is_empty()) {
        zeroize::Zeroizing::new(v)
    } else if stdin_ok && !std::io::stdin().is_terminal() {
        let mut text = zeroize::Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .take(64 * 1024)
            .read_to_string(&mut text)
            .context("read standard input")?;
        text
    } else if std::io::stdin().is_terminal() {
        zeroize::Zeroizing::new(rpassword::prompt_password(prompt).context("read the secret")?)
    } else {
        bail!("no secret given: set {env}, or pass a file, or run from a terminal to be asked");
    };
    let trimmed = got.trim();
    if trimmed.is_empty() {
        bail_usage::<()>("the secret is empty")?;
    }
    varsto_core::logging::register_secret(trimmed);
    Ok(zeroize::Zeroizing::new(trimmed.to_string()))
}

/// Several secret lines (the shares of `recovery combine`): from files, else
/// standard input when it is not a terminal, else asked for line by line
/// without echo until an empty line.
fn secret_lines(files: &[PathBuf], prompt: &str) -> Result<Vec<zeroize::Zeroizing<String>>> {
    use std::io::{IsTerminal, Read};
    let mut text = zeroize::Zeroizing::new(String::new());
    if !files.is_empty() {
        for f in files {
            text.push_str(
                &std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?,
            );
            text.push('\n');
        }
    } else if !std::io::stdin().is_terminal() {
        std::io::stdin()
            .lock()
            .take(256 * 1024)
            .read_to_string(&mut text)
            .context("read standard input")?;
    } else {
        loop {
            let line = zeroize::Zeroizing::new(
                rpassword::prompt_password(prompt).context("read a share")?,
            );
            if line.trim().is_empty() {
                break;
            }
            text.push_str(&line);
            text.push('\n');
        }
    }
    let out: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            varsto_core::logging::register_secret(l);
            zeroize::Zeroizing::new(l.to_string())
        })
        .collect();
    Ok(out)
}

/// The vault key as hex from what the user gave: 64 hex digits, or the 24
/// recovery words.
fn vault_key_from_text(text: &str) -> Result<zeroize::Zeroizing<String>> {
    let t = text.trim();
    if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(zeroize::Zeroizing::new(t.to_ascii_lowercase()));
    }
    varsto_core::recovery::key_from_words(t)
        .context("this is neither 64 hex digits nor 24 recovery words")
}

/// The MCP key for `varsto mcp`: from `--key-file`, else `VARSTO_MCP_KEY`.
fn mcp_key_input(file: Option<&Path>) -> Result<Option<zeroize::Zeroizing<String>>> {
    if let Some(f) = file {
        let text = std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?;
        let k = text.trim();
        if k.is_empty() {
            bail_usage::<()>("the MCP key file is empty")?;
        }
        varsto_core::logging::register_secret(k);
        return Ok(Some(zeroize::Zeroizing::new(k.to_string())));
    }
    Ok(std::env::var("VARSTO_MCP_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .map(|k| {
            varsto_core::logging::register_secret(k.trim());
            zeroize::Zeroizing::new(k.trim().to_string())
        }))
}

/// Ask a yes/no question on the terminal; without one the answer is no.
/// Ask on standard error and read the answer from standard input, also
/// when it is not a terminal (a script or a test answers through a pipe).
fn ask_stdin(question: &str) -> Result<bool> {
    use std::io::{BufRead, Write};
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn confirm(question: &str) -> Result<bool> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Percent-encode a query value.
fn url_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `varsto changes` as lines, newest first.
fn changes_text(r: &varsto_core::engine::ChangesReport) -> String {
    let mut out = format!(
        "{}{}: {}{}",
        r.folder,
        r.path
            .as_ref()
            .map(|p| format!(" {}{p}", if r.file { "" } else { "under " }))
            .unwrap_or_default(),
        plural(r.changes.len(), "change", "changes"),
        if r.truncated {
            " (more with --limit 0)"
        } else {
            ""
        }
    );
    for c in &r.changes {
        let e = &c.event;
        let what = match (e.action.as_str(), &e.from, &e.to) {
            ("renamed", Some(f), _) => format!("renamed from {f}"),
            ("renamed", _, Some(t)) => format!("renamed to {t}"),
            (a, _, _) => a.to_string(),
        };
        let secs = e.time_utc.rem_euclid(86_400);
        out.push_str(&format!(
            "\n{} {:02}:{:02}  {}  {}  by {}{}{}{}{}",
            varsto_core::util::format_date(e.time_utc),
            secs / 3600,
            secs % 3600 / 60,
            e.path,
            what,
            c.device_name,
            c.user
                .as_ref()
                .map(|u| format!(" ({u})"))
                .unwrap_or_default(),
            if e.action.as_str() == "deleted" || e.to.is_some() || e.hash.is_empty() {
                String::new()
            } else {
                format!(", {} bytes, {}", e.size, e.hash)
            },
            if e.verified {
                ""
            } else {
                ", not verified against the ledger"
            },
            if e.backfilled {
                ", time from the file (history started later)"
            } else {
                ""
            }
        ));
    }
    out
}

/// Where a read-only folder's local changes went.
fn kept_aside_text(paths: &[String]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let shown: Vec<&str> = paths.iter().take(5).map(|p| p.as_str()).collect();
    format!(
        " ({} moved to {}/ in the device directory or put back: {}{})",
        plural(paths.len(), "file", "files"),
        varsto_core::engine::KEPT_ASIDE_DIR,
        shown.join(", "),
        if paths.len() > shown.len() {
            ", ..."
        } else {
            ""
        }
    )
}

/// Read-only members: this device's own refused changes, and changes of
/// viewers this device did not take.
fn role_notes(
    pull: &varsto_core::engine::PullReport,
    push: Option<&varsto_core::engine::PushReport>,
) -> String {
    let mut out = String::new();
    let mut kept: Vec<String> = pull.kept_aside.clone();
    if let Some(p) = push {
        kept.extend(p.kept_aside.iter().cloned());
    }
    if push.is_some_and(|p| p.read_only) || !kept.is_empty() {
        out.push_str(&format!(
            "; read-only: your changes were not published{}",
            kept_aside_text(&kept)
        ));
    }
    if !pull.writes_refused.is_empty() {
        out.push_str(&format!(
            "; not taken from read-only members: {}",
            pull.writes_refused.join(", ")
        ));
    }
    out
}

fn share_members_text(l: &varsto_core::engine::ShareMembers) -> String {
    let mut out = format!("{} ({})", l.folder, &l.folder_id[..8]);
    if l.share_epoch > 0 {
        out.push_str(&format!(", share epoch {}", l.share_epoch));
    }
    if l.access_lost {
        out.push_str("\nThis device no longer receives new content of this folder: the owner removed it, or has not sent it the new key yet.");
    }
    if l.this_role == "viewer" {
        out.push_str(
            "\nThis device may only read this folder: changes made here are not published.",
        );
    }
    for m in &l.members {
        let what = match (m.kind.as_str(), m.status.as_str()) {
            ("owner-device", _) => "owner's device".to_string(),
            ("invite", "pending") => "token not accepted yet".to_string(),
            ("invite", _) => "token revoked".to_string(),
            (_, "removed") => format!(
                "removed{}{}",
                m.removed_by
                    .as_ref()
                    .map(|b| format!(" by {b}"))
                    .unwrap_or_default(),
                m.removed_utc
                    .map(|t| format!(" on {}", varsto_core::util::format_date(t)))
                    .unwrap_or_default()
            ),
            _ => match m.role.as_str() {
                "viewer" => "member, viewer (read only)".to_string(),
                _ => "member, editor".to_string(),
            },
        };
        let what = match (m.kind.as_str(), m.status.as_str(), m.role.as_str()) {
            ("invite", "pending", "viewer") => format!("{what} (viewer)"),
            _ => what,
        };
        out.push_str(&format!(
            "\n  {:<20} {:<10} {}{}{}",
            show(&m.name),
            &m.id[..m.id.len().min(8)],
            what,
            if m.this_device { " (this device)" } else { "" },
            if m.fingerprint.is_empty() {
                String::new()
            } else {
                format!("\n  {:<20} fingerprint: {}", "", m.fingerprint)
            }
        ));
    }
    out
}

/// The device passphrase: from `VARSTO_PASSPHRASE`, otherwise asked on the
/// terminal (hidden input). Scripts and services set the variable.
/// The passphrase typed in this run, so that after a successful command a
/// locked background service can be unlocked with it (and, after setup,
/// kept in the keyring if the user wants).
static TYPED: std::sync::Mutex<Option<zeroize::Zeroizing<String>>> = std::sync::Mutex::new(None);
/// The passphrase this command used, typed or from VARSTO_PASSPHRASE: it
/// unlocks a background service that waits for it.
static USED: std::sync::Mutex<Option<zeroize::Zeroizing<String>>> = std::sync::Mutex::new(None);

/// Open the device directory. When its ledger needs a rebuild (lost or
/// damaged local files, a fork), say so on stderr: commands that only read
/// go on, commands that would sign stop with the same advice.
pub(crate) fn open_engine(home: &Path) -> Result<Engine> {
    let e = Engine::open(home, &passphrase()?)?;
    warn_ledger(&e.ledger_health());
    Ok(e)
}

/// A one-line warning about the ledger on stderr, unless it is fine.
fn warn_ledger(h: &varsto_core::engine::LedgerHealth) {
    if !h.is_ok() {
        eprintln!("warning: ledger: {}", h.describe());
    }
}

fn passphrase() -> Result<String> {
    if let Ok(p) = std::env::var("VARSTO_PASSPHRASE") {
        varsto_core::logging::register_secret(&p);
        *USED.lock().unwrap() = Some(zeroize::Zeroizing::new(p.clone()));
        return Ok(p);
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let p = rpassword::prompt_password("Varsto passphrase for this device: ")
            .context("read the passphrase")?;
        if p.is_empty() {
            bail_usage::<()>("empty passphrase")?;
        }
        varsto_core::logging::register_secret(&p);
        *TYPED.lock().unwrap() = Some(zeroize::Zeroizing::new(p.clone()));
        *USED.lock().unwrap() = Some(zeroize::Zeroizing::new(p.clone()));
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
    default_home()
}

/// The device directory when neither --home nor VARSTO_HOME names one.
fn default_home() -> Result<PathBuf> {
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
/// `varsto disk list` as a table: name (sticker), pool, place, state,
/// free/total, reclaimable, oldest check, last seen, file system check.
fn disk_table(disks: &[varsto_core::pool::DiskStatus]) -> String {
    use varsto_core::disksuggest::ago;
    let now = varsto_core::util::now_utc();
    let date = |t: i64| varsto_core::util::format_date(t);
    let mut rows: Vec<[String; 9]> = vec![[
        "NAME".into(),
        "POOL".into(),
        "PLACE".into(),
        "STATE".into(),
        "FREE / TOTAL".into(),
        "RECLAIMABLE".into(),
        "OLDEST CHECK".into(),
        "LAST SEEN".into(),
        "FSCK".into(),
    ]];
    for d in disks {
        let mut state = vec![if d.attached { "attached" } else { "away" }];
        if d.retired {
            state.push("retired");
        }
        if d.failing {
            state.push("failing");
        }
        let space = match d.free_bytes {
            Some(f) => format!("{} / {}", fmt_bytes(f), fmt_bytes(d.capacity_bytes)),
            None => format!("? / {}", fmt_bytes(d.capacity_bytes)),
        };
        let checked = match d.oldest_check_utc {
            None => "-".to_string(),
            Some(0) => "never".to_string(),
            Some(t) => date(t),
        } + &if d.copies_overdue > 0 {
            format!(" ({:.0} % due)", d.overdue_share * 100.0)
        } else {
            String::new()
        };
        let seen = if d.attached {
            "now".to_string()
        } else if d.last_seen_utc > 0 {
            ago(now, d.last_seen_utc)
        } else {
            "never".to_string()
        };
        let fsck = d
            .fsck
            .as_ref()
            .map(|c| format!("{:?} {}", c.verdict, date(c.checked_utc)).to_lowercase())
            .unwrap_or_else(|| "-".to_string());
        rows.push([
            d.label.clone(),
            d.pool.clone(),
            d.place.clone(),
            state.join(", "),
            space,
            fmt_bytes(d.reclaimable_bytes),
            checked,
            seen,
            fsck,
        ]);
    }
    let mut widths = [0usize; 9];
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    let mut out = String::new();
    for r in &rows {
        let line: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c}{}", " ".repeat(widths[i] - c.chars().count())))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out
}

/// `varsto disk suggest` as text: the suggestion with its reasons and the
/// command to run, the other disks, attached ones and the ones left out.
fn suggest_text(s: &varsto_core::disksuggest::DiskSuggestions) -> String {
    let mut out = String::new();
    let reasons = |d: &varsto_core::disksuggest::DiskSuggestion| -> String {
        if d.reasons.is_empty() {
            return "  - nothing due\n".to_string();
        }
        d.reasons
            .iter()
            .map(|r| format!("  - {}\n", r.text))
            .collect()
    };
    match &s.top {
        Some(t) => {
            out += &format!(
                "Suggested next: «{}» (pool {}, {}), score {:.1}\n{}  Run: {}\n",
                t.label,
                t.pool,
                t.place,
                t.score,
                reasons(t),
                t.command
            );
        }
        None if s.new_disk_needed.is_empty() => out += "No disk needs docking now.\n",
        None => {}
    }
    for n in &s.new_disk_needed {
        out += &format!("{}\n  Run: {}\n", n.text, n.command);
    }
    let rest: Vec<_> = s
        .ranked
        .iter()
        .filter(|d| s.top.as_ref().is_none_or(|t| t.disk_id != d.disk_id))
        .collect();
    if !rest.is_empty() {
        out += "\nOther disks that are away:\n";
        for d in rest {
            out += &format!(
                "«{}» (pool {}, {}), score {:.1}\n{}",
                d.label,
                d.pool,
                d.place,
                d.score,
                reasons(d)
            );
        }
    }
    if !s.attached.is_empty() {
        out += "\nAttached now (no docking needed; `varsto disk check <label>` checks one):\n";
        for d in &s.attached {
            out += &format!(
                "«{}» (pool {}, {}), score {:.1}\n{}",
                d.label,
                d.pool,
                d.place,
                d.score,
                reasons(d)
            );
        }
    }
    if !s.excluded.is_empty() {
        out += "\nNot suggested:\n";
        for d in &s.excluded {
            out += &format!("«{}» (pool {}): {}\n", d.label, d.pool, d.warning);
        }
    }
    out
}

/// A file name for the terminal: as it is, `:` and `\` included, with
/// control characters and direction overrides shown as `\u{..}` escapes so
/// that a name cannot move the cursor or recolour the terminal.
pub(crate) fn show(name: &str) -> std::borrow::Cow<'_, str> {
    varsto_core::names::display(name)
}

/// The files a case-insensitive disk made this device keep under another
/// local name ("vault path -> local path"), for the pull and sync lines.
fn renamed_note(renamed: &[String]) -> String {
    if renamed.is_empty() {
        String::new()
    } else {
        format!(
            "; kept under another name here because the disk ignores case: {}",
            renamed.join(", ")
        )
    }
}

/// A count with its noun: "1 file", "3 files".
fn plural<N>(n: N, one: &str, many: &str) -> String
where
    N: Copy + PartialEq + From<u8> + std::fmt::Display,
{
    format!("{n} {}", if n == N::from(1) { one } else { many })
}

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

/// `varsto mcp key`.
fn run_mcp_key(cli: &Cli, home: &Path, cmd: &McpKeyCmd) -> Result<()> {
    match cmd {
        McpKeyCmd::Create {
            name,
            folders,
            write,
            analyse,
            expires_days,
        } => {
            let scope = mcp_keys::scope_for(home, folders, *write, *analyse)?;
            let (k, secret) = mcp_keys::create(home, name.as_deref(), scope, *expires_days)?;
            if cli.json {
                let mut v = k.summary();
                v["key"] = serde_json::json!(secret);
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                println!(
                    "MCP key {} ({}) created; it is shown only now:\n\n  {secret}\n\nGive it to the MCP client as VARSTO_MCP_KEY (varsto mcp config prints a configuration). It works while the Varsto service runs{}.",
                    k.name,
                    k.id,
                    k.expires_utc
                        .map(|e| format!(", until {}", backup::fmt_utc(e)))
                        .unwrap_or_default()
                );
            }
        }
        McpKeyCmd::List => {
            let keys = mcp_keys::list(home)?;
            let rows: Vec<serde_json::Value> = keys.iter().map(|k| k.summary()).collect();
            print(cli, &rows, |_| {
                if keys.is_empty() {
                    return "no MCP keys (varsto mcp key create)".into();
                }
                let now = varsto_core::util::now_utc();
                keys.iter()
                    .map(|k| {
                        let mut scope: Vec<String> = Vec::new();
                        if let Some(a) = &k.scope.all {
                            scope.push(format!("all: {a}"));
                        }
                        scope.extend(k.scope.folders.iter().map(|(f, l)| format!("{f}: {l}")));
                        format!(
                            "{} ({}): {}; created {}{}{}",
                            k.name,
                            k.id,
                            scope.join(", "),
                            backup::fmt_utc(k.created_utc),
                            match k.expires_utc {
                                Some(_) if k.expired(now) => "; EXPIRED".to_string(),
                                Some(e) => format!("; expires {}", backup::fmt_utc(e)),
                                None => String::new(),
                            },
                            k.last_used_utc
                                .map(|t| format!("; last used {}", backup::fmt_utc(t)))
                                .unwrap_or_else(|| "; never used".into())
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;
        }
        McpKeyCmd::Revoke { name_or_id } => {
            let k = mcp_keys::revoke(home, name_or_id)?;
            println!("revoked MCP key {} ({})", k.name, k.id);
        }
    }
    Ok(())
}

/// A call to the running service's local API, if it runs.
fn service_call(
    home: &Path,
) -> Option<impl Fn(&str, &str, serde_json::Value) -> Result<serde_json::Value>> {
    let (sf, _) = service::status(home)?;
    Some(
        move |method: &str, path: &str, body: serde_json::Value| -> Result<serde_json::Value> {
            let url = format!("http://127.0.0.1:{}{path}", sf.port);
            let r = if method == "GET" {
                service::http_get(&url, &sf.token)?
            } else {
                service::http_post(&url, &sf.token, &body.to_string())?
            };
            Ok(serde_json::from_str(&r)?)
        },
    )
}

fn analysis_text(a: &varsto_core::engine::FileAnalysis) -> String {
    let mut head = format!(
        "{}{}\n  by {}{} on {}",
        a.path,
        if a.stale {
            " (stale: the file changed since)"
        } else {
            ""
        },
        a.author,
        a.by.as_ref().map(|b| format!(" ({b})")).unwrap_or_default(),
        backup::fmt_utc(a.analysed_utc),
    );
    if !a.tags.is_empty() {
        head.push_str(&format!("\n  tags: {}", a.tags.join(", ")));
    }
    format!("{head}\n\n{}", a.analysis)
}

/// `varsto analysis`: through the service when it runs, else the engine.
fn run_analysis(cli: &Cli, home: &Path, cmd: &AnalysisCmd) -> Result<()> {
    use varsto_core::engine::FileAnalysis;
    let call = service_call(home);
    match cmd {
        AnalysisCmd::Show { folder, path } => {
            let a: Option<FileAnalysis> = match &call {
                Some(call) => serde_json::from_value(
                    call(
                        "GET",
                        &format!(
                            "/api/analysis?folder={}&path={}",
                            mcp::urlencode(folder),
                            mcp::urlencode(path)
                        ),
                        serde_json::Value::Null,
                    )?["analysis"]
                        .clone(),
                )?,
                None => Engine::open(home, &passphrase()?)?.analysis(folder, path)?,
            };
            print(cli, &a, |a| match a {
                Some(a) => analysis_text(a),
                None => format!("{path} has no analysis"),
            })?;
        }
        AnalysisCmd::Set {
            folder,
            path,
            text,
            from_file,
            tags,
            by,
        } => {
            let text = match (text, from_file) {
                (Some(t), _) => t.clone(),
                (None, Some(f)) if f.as_os_str() == "-" => {
                    let mut t = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut t)?;
                    t
                }
                (None, Some(f)) => {
                    std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?
                }
                (None, None) => bail_usage("give --text or --from-file")?,
            };
            let a: FileAnalysis = match &call {
                Some(call) => serde_json::from_value(call(
                    "POST",
                    "/api/analysis",
                    serde_json::json!({"folder": folder, "path": path, "analysis": text, "tags": tags, "by": by}),
                )?)?,
                None => Engine::open(home, &passphrase()?)?.set_analysis(
                    folder,
                    path,
                    &text,
                    tags,
                    by.as_deref(),
                )?,
            };
            print(cli, &a, |a| {
                format!(
                    "recorded the analysis of {} ({} bytes{}); other devices get it with the next sync",
                    a.path,
                    a.analysis.len(),
                    if a.tags.is_empty() {
                        String::new()
                    } else {
                        format!(", tags {}", a.tags.join(", "))
                    }
                )
            })?;
        }
        AnalysisCmd::Clear { folder, path } => {
            let cleared = match &call {
                Some(call) => call(
                    "POST",
                    "/api/analysis/clear",
                    serde_json::json!({"folder": folder, "path": path}),
                )?["cleared"]
                    .as_bool()
                    .unwrap_or(false),
                None => Engine::open(home, &passphrase()?)?.clear_analysis(folder, path)?,
            };
            print(cli, &serde_json::json!({"cleared": cleared}), |_| {
                if cleared {
                    format!("cleared the analysis of {path}")
                } else {
                    format!("{path} had no analysis")
                }
            })?;
        }
        AnalysisCmd::List { folder } => {
            let all: Vec<FileAnalysis> = match &call {
                Some(call) => serde_json::from_value(call(
                    "GET",
                    &format!("/api/analyses?folder={}", mcp::urlencode(folder)),
                    serde_json::Value::Null,
                )?)?,
                None => Engine::open(home, &passphrase()?)?.analyses(folder)?,
            };
            print(cli, &all, |all| {
                if all.is_empty() {
                    return format!("no file of {folder} has an analysis");
                }
                all.iter()
                    .map(|a| {
                        let first: String = a.analysis.chars().take(100).collect();
                        format!(
                            "{}{}\n  {}{}",
                            a.path,
                            if a.stale { " (stale)" } else { "" },
                            first.replace('\n', " "),
                            if a.analysis.chars().count() > 100 {
                                "…"
                            } else {
                                ""
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;
        }
    }
    Ok(())
}

/// `varsto search`: every attached folder, or one.
fn run_search(
    cli: &Cli,
    home: &Path,
    query: &str,
    folder: Option<&str>,
    tags: &[String],
) -> Result<()> {
    use varsto_core::engine::AnalysisHit;
    let call = service_call(home);
    let mut engine = None;
    let folders: Vec<String> = match (folder, &call) {
        (Some(f), _) => vec![f.to_string()],
        (None, Some(call)) => call("GET", "/api/folders", serde_json::Value::Null)?
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| !f["path"].is_null())
            .filter_map(|f| f["name"].as_str().map(str::to_string))
            .collect(),
        (None, None) => {
            let e = Engine::open(home, &passphrase()?)?;
            let names = e
                .folders()
                .into_iter()
                .filter(|(r, m)| m.is_some() && (!r.is_strongroom() || e.is_unlocked(&r.folder_id)))
                .map(|(r, _)| r.name.clone())
                .collect();
            engine = Some(e);
            names
        }
    };
    let mut hits: Vec<AnalysisHit> = Vec::new();
    for f in &folders {
        let found: Vec<AnalysisHit> = match &call {
            Some(call) => serde_json::from_value(call(
                "POST",
                "/api/analysis/search",
                serde_json::json!({"folder": f, "query": query, "tags": tags}),
            )?)?,
            None => {
                if engine.is_none() {
                    engine = Some(Engine::open(home, &passphrase()?)?);
                }
                engine.as_ref().unwrap().search_analyses(f, query, tags)?
            }
        };
        hits.extend(found);
    }
    hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.path.cmp(&b.path)));
    print(cli, &hits, |hits| {
        if hits.is_empty() {
            return "nothing found".into();
        }
        hits.iter()
            .map(|h| {
                format!(
                    "{}/{}{}{}{}",
                    h.folder,
                    h.path,
                    if h.stale { " (stale)" } else { "" },
                    if h.tags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", h.tags.join(", "))
                    },
                    if h.snippet.is_empty() {
                        String::new()
                    } else {
                        format!("\n  {}", h.snippet)
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// Organization commands. When the background service runs it owns the
/// engine, so changes go through its API; otherwise the engine is opened here.
fn run_org(cli: &Cli, home: &Path, cmd: &OrgCmd) -> Result<()> {
    use varsto_core::org::OrgRequest;
    let via_service = service::status(home);
    let call = |method: &str, path: &str, body: serde_json::Value| -> Result<serde_json::Value> {
        let (sf, _) = via_service.as_ref().expect("service running");
        let url = format!("http://127.0.0.1:{}{path}", sf.port);
        let r = if method == "GET" {
            service::http_get(&url, &sf.token)?
        } else {
            service::http_post(&url, &sf.token, &body.to_string())?
        };
        Ok(serde_json::from_str(&r)?)
    };
    match cmd {
        OrgCmd::Request { name } => {
            let code = OrgRequest::code_for(home, Some(name))?;
            let words = OrgRequest::fingerprint_for(home)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"request_code": code, "fingerprint": words})
                );
            } else {
                println!("organization request code for this device (give it to an administrator; it contains no secret):\n  {code}\n\nfingerprint: {words}\nThe administrator sees the same six words for this code. Read them to each other over a call or in person before they approve: different words mean the code was changed on its way.");
            }
        }
        OrgCmd::Join { name, token } => {
            let (engine, notes, approval) = Engine::org_join(home, name, &passphrase()?, token)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({ "vault_id": engine.vault_id().to_string(), "device_id": engine.device_id().to_string(), "organization": approval.org_name, "user": approval.user, "notes": notes })
                );
            } else {
                println!(
                    "joined the vault of {} as {} for {} (approved by {})",
                    approval.org_name, name, approval.user, approval.bundle.from
                );
                for n in notes {
                    println!("  {n}");
                }
                println!("Attach folders under Files (`varsto folder attach`) and sync.");
            }
        }
        OrgCmd::Create { name, user } => {
            let created: varsto_core::engine::OrgCreated = if via_service.is_some() {
                serde_json::from_value(call(
                    "POST",
                    "/api/org/create",
                    serde_json::json!({"name": name, "user": user}),
                )?)?
            } else {
                let mut engine = open_engine(home)?;
                engine.org_create(name, user)?
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&created)?);
            } else {
                println!(
                    "Organization {} ({}) created; this device is its administrator, and {} now belong to {user}.\n",
                    created.name,
                    &created.org_id[..8],
                    created.devices.join(", ")
                );
                print!("{}", created.root_kit);
            }
        }
        OrgCmd::Status => {
            let summary: Option<varsto_core::engine::OrgSummary> = if via_service.is_some() {
                let v = call("GET", "/api/org", serde_json::Value::Null)?;
                if v.get("exists") == Some(&serde_json::Value::Bool(false)) {
                    None
                } else {
                    Some(serde_json::from_value(v)?)
                }
            } else {
                open_engine(home)?.org_summary()
            };
            match summary {
                None => {
                    if cli.json {
                        println!("{{\"exists\": false}}");
                    } else {
                        println!("This vault has no organization. `varsto org create --name <org> --user <you>` makes one; a vault without one works as before.");
                    }
                }
                Some(s) => print(cli, &s, org_status_text)?,
            }
        }
        OrgCmd::Approve {
            code,
            user,
            fingerprint,
            yes,
        } => {
            let info = OrgRequest::parse(code)?;
            let confirmed = match fingerprint {
                Some(f) => Some(f.clone()),
                None if *yes => None,
                None => {
                    eprintln!(
                        "Request from device {} ({}, {})\nfingerprint: {}\nAsk the person to read the fingerprint their device shows (varsto org request).",
                        if info.name.is_empty() { "(no name)".into() } else { show(&info.name) },
                        info.device.short(),
                        if info.platform.is_empty() {
                            "platform not given".to_string()
                        } else {
                            varsto_core::org::platform_name(&info.platform)
                        },
                        info.fingerprint
                    );
                    if !confirm("Do the six words match exactly?")? {
                        bail!("not approved: the fingerprint was not confirmed");
                    }
                    Some(info.fingerprint.clone())
                }
            };
            let approved: varsto_core::engine::OrgApproved = if via_service.is_some() {
                serde_json::from_value(call(
                    "POST",
                    "/api/org/approve",
                    serde_json::json!({"code": code, "user": user, "fingerprint": confirmed}),
                )?)?
            } else {
                let mut engine = open_engine(home)?;
                engine.org_approve(code, user, confirmed.as_deref())?
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&approved)?);
            } else {
                println!(
                    "approved {} for {}. Send this token back; only that device can open it:\n  {}\n\nOn the device: varsto org join --name {} --token <token>",
                    approved.name, approved.user, approved.token, approved.name
                );
            }
        }
        OrgCmd::AddDevice { device, user } => {
            if via_service.is_some() {
                call(
                    "POST",
                    "/api/org/add-device",
                    serde_json::json!({"device": device, "user": user}),
                )?;
            } else {
                open_engine(home)?.org_add_device(device, user)?;
            }
            println!("added {device} to the organization for {user}");
        }
        OrgCmd::RemoveUser { user, wipe, yes } => {
            if !*yes {
                bail_usage::<()>(&format!(
                    "this removes every device of {user} from the vault: their later ledger entries are ignored, peers refuse them, and the vault gets new keys for everything written from now on. Everything they already held stays readable to them, and their storage credentials work until you change them at the provider. {}Run again with --yes",
                    if *wipe { "With --wipe their devices also delete their keys, sync state and folder contents when they next reach a storage. " } else { "" }
                ))?;
            }
            let report: varsto_core::engine::OrgRemoveReport = if via_service.is_some() {
                serde_json::from_value(call(
                    "POST",
                    "/api/org/remove-user",
                    serde_json::json!({"user": user, "wipe": wipe, "confirm": user}),
                )?)?
            } else {
                let mut engine = open_engine(home)?;
                engine.org_remove_user(user, *wipe)?
            };
            print(cli, &report, |r| {
                format!(
                    "removed {} with {}{}; vault key epoch {}; new keys sent to {}{}",
                    r.user,
                    r.devices.join(", "),
                    if r.revoke.wipe { " (wipe ordered)" } else { "" },
                    r.revoke.key_epoch,
                    if r.revoke.keys_sent_to.is_empty() {
                        "no other device".to_string()
                    } else {
                        r.revoke.keys_sent_to.join(", ")
                    },
                    if r.revoke.keys_pending_for.is_empty() {
                        String::new()
                    } else {
                        format!("; waiting for {}", r.revoke.keys_pending_for.join(", "))
                    }
                )
            })?;
        }
        OrgCmd::Policy { cmd, allow, deny } => {
            let current: Option<varsto_core::org::OrgPolicy> = if via_service.is_some() {
                let v = call("GET", "/api/org", serde_json::Value::Null)?;
                v.get("policy")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
            } else {
                open_engine(home)?.org_summary().map(|s| s.policy)
            };
            let Some(mut p) = current else {
                bail!("this vault has no organization");
            };
            if let Some(OrgPolicyCmd::Platforms {
                allow,
                allow_all,
                min_version,
            }) = cmd
            {
                if allow.is_empty() && !*allow_all && min_version.is_none() {
                    print(cli, &p, policy_text)?;
                    return Ok(());
                }
                if *allow_all {
                    p.allowed_platforms.clear();
                } else if !allow.is_empty() {
                    p.allowed_platforms = allow.iter().map(|a| a.trim().to_string()).collect();
                }
                if let Some(v) = min_version {
                    p.min_app_version = if v.trim().eq_ignore_ascii_case("any") {
                        String::new()
                    } else {
                        v.trim().to_string()
                    };
                }
                if via_service.is_some() {
                    call("POST", "/api/org/policy", serde_json::to_value(&p)?)?;
                } else {
                    open_engine(home)?.org_set_policy(p.clone())?;
                }
                // The policy as stored (platforms normalised), and who it locks out.
                let summary: Option<varsto_core::engine::OrgSummary> = if via_service.is_some() {
                    serde_json::from_value(call("GET", "/api/org", serde_json::Value::Null)?).ok()
                } else {
                    open_engine(home)?.org_summary()
                };
                let Some(summary) = summary else {
                    return Ok(());
                };
                print(cli, &summary.policy, |p| {
                    let mut out = policy_text(p);
                    let refused: Vec<String> = summary
                        .users
                        .iter()
                        .flat_map(|u| u.devices.iter())
                        .filter_map(|d| d.refused.as_ref().map(|r| format!("{} ({r})", d.name)))
                        .collect();
                    if !refused.is_empty() {
                        out.push_str(&format!(
                            "\nlocked out until allowed again: {}",
                            refused.join(", ")
                        ));
                    }
                    out
                })?;
                return Ok(());
            }
            if allow.is_empty() && deny.is_empty() {
                print(cli, &p, policy_text)?;
                return Ok(());
            }
            for (list, value) in [(allow, true), (deny, false)] {
                for what in list {
                    match what.trim() {
                        "share" => p.members_may_share = value,
                        "add-storages" => p.members_may_add_storages = value,
                        "set-policies" => p.members_may_set_policies = value,
                        "add-devices" => p.members_may_add_devices = value,
                        other => bail!("unknown permission {other}: use share, add-storages, set-policies or add-devices"),
                    }
                }
            }
            if via_service.is_some() {
                call("POST", "/api/org/policy", serde_json::to_value(&p)?)?;
            } else {
                open_engine(home)?.org_set_policy(p.clone())?;
            }
            print(cli, &p, policy_text)?;
        }
        OrgCmd::Admin { cmd } => {
            let (action, device, file) = match cmd {
                OrgAdminCmd::Add {
                    device,
                    root_words_file,
                } => ("add", device, root_words_file),
                OrgAdminCmd::Remove {
                    device,
                    root_words_file,
                } => ("remove", device, root_words_file),
            };
            let words = secret_input(
                file.as_deref(),
                "VARSTO_ORG_ROOT_WORDS",
                "The 24 root words of the organization: ",
                true,
            )?;
            let words: &str = &words;
            if via_service.is_some() {
                call(
                    "POST",
                    "/api/org/admin",
                    serde_json::json!({"action": action, "device": device, "root_words": words}),
                )?;
            } else {
                let mut engine = open_engine(home)?;
                if action == "add" {
                    engine.org_admin_add(device, words)?;
                } else {
                    engine.org_admin_remove(device, words)?;
                }
            }
            println!(
                "{device} is {} an administrator",
                if action == "add" { "now" } else { "no longer" }
            );
        }
        OrgCmd::Log => {
            let log: Vec<varsto_core::engine::LogView> = if via_service.is_some() {
                serde_json::from_value(
                    call("GET", "/api/org/log", serde_json::Value::Null)?["log"].clone(),
                )?
            } else {
                open_engine(home)?.org_log_entries()
            };
            print(cli, &log, |l| {
                if l.is_empty() {
                    return "no organization log".to_string();
                }
                l.iter()
                    .map(|e| format!("{}  {}", varsto_core::util::format_date(e.utc), e.text))
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;
        }
    }
    Ok(())
}

fn policy_text(p: &varsto_core::org::OrgPolicy) -> String {
    let yn = |b: bool| if b { "yes" } else { "no (administrators only)" };
    format!(
        "members may share folders with other people: {}\nmembers may add or remove storages: {}\nmembers may set policies and placement: {}\nmembers may add devices and print the recovery kit: {}\ndevice platforms allowed: {}\noldest Varsto version allowed: {}",
        yn(p.members_may_share),
        yn(p.members_may_add_storages),
        yn(p.members_may_set_policies),
        yn(p.members_may_add_devices),
        if p.allowed_platforms.is_empty() {
            "all".to_string()
        } else {
            p.allowed_platforms
                .iter()
                .map(|x| varsto_core::org::platform_name(x))
                .collect::<Vec<_>>()
                .join(", ")
        },
        if p.min_app_version.is_empty() {
            "any"
        } else {
            &p.min_app_version
        }
    )
}

fn org_status_text(s: &varsto_core::engine::OrgSummary) -> String {
    let mut out = format!(
        "Organization {} ({}), manifest {}, roster {}\nThis device: {}{}",
        s.name,
        &s.org_id[..8],
        s.manifest_seq,
        s.roster_seq,
        if s.this_device_admin {
            "administrator"
        } else if s.this_device_listed {
            "member"
        } else {
            "NOT IN THE ORGANIZATION (ask an administrator to add it; the others ignore it until then)"
        },
        s.this_user
            .as_ref()
            .map(|u| format!(", user {u}"))
            .unwrap_or_default()
    );
    if let Some(b) = &s.this_device_blocked {
        out.push_str(&format!("\nThis device is locked out: {b}. It does not sync or open the vault until an administrator allows it."));
    }
    out.push_str("\n\nAdministrators:");
    for a in &s.admins {
        out.push_str(&format!(
            "\n  {} ({}){}",
            a.name,
            &a.device_id[..8],
            if a.this_device { ", this device" } else { "" }
        ));
    }
    out.push_str("\n\nUsers and devices:");
    for u in &s.users {
        out.push_str(&format!("\n  {}", u.user));
        for d in &u.devices {
            out.push_str(&format!(
                "\n    {} ({}){}{}{}{}{}",
                d.name,
                &d.device_id[..8],
                if d.platform.is_empty() {
                    String::new()
                } else {
                    format!(", {}", varsto_core::org::platform_name(&d.platform))
                },
                if d.admin { ", administrator" } else { "" },
                if d.this_device { ", this device" } else { "" },
                if d.revoked { ", removed" } else { "" },
                d.refused
                    .as_ref()
                    .map(|r| format!(", LOCKED OUT: the organization {r}"))
                    .unwrap_or_default()
            ));
        }
    }
    if !s.unlisted.is_empty() {
        out.push_str("\n\nDevices in the vault that are not in the organization (ignored until an administrator adds them with `varsto org add-device`):");
        for d in &s.unlisted {
            out.push_str(&format!(
                "\n  {} ({}), enrolled {}",
                d.name,
                &d.device_id[..8],
                varsto_core::util::format_date(d.enrolled_utc)
            ));
        }
    }
    if !s.removed.is_empty() {
        out.push_str("\n\nRemoved:");
        for r in &s.removed {
            out.push_str(&format!(
                "\n  {} ({}) of {}, removed {}{}",
                r.name,
                r.device.short(),
                r.user,
                varsto_core::util::format_date(r.removed_utc),
                if r.wipe { " with a wipe order" } else { "" }
            ));
        }
    }
    out.push_str("\n\nPolicy:\n");
    out.push_str(
        &policy_text(&s.policy)
            .lines()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    out
}

fn run(cli: &Cli) -> Result<()> {
    let home = home(cli)?;
    match &cli.cmd {
        Cmd::Log { cmd } => logcmd::run(&home, cmd, cli.json)?,
        Cmd::Unlock {
            with_recovery_key,
            recovery_file,
        } => {
            let Some((sf, _)) = service::status(&home) else {
                bail!("no background service is running here: start it with `varsto service start` (a command that opens the vault itself asks for the recovery words when it needs them)");
            };
            let pass = passphrase()?;
            let words = if *with_recovery_key {
                Some(f3cmd::recovery_words_text(recovery_file.as_deref())?)
            } else {
                None
            };
            service::http_post(
                &format!("http://127.0.0.1:{}/api/unlock", sf.port),
                &sf.token,
                &serde_json::json!({"passphrase": pass.as_str(), "recovery_words": words.as_deref().map(|w| w.as_str())})
                    .to_string(),
            )?;
            if words.is_some() {
                println!("The background service is unlocked and keeps the recovery words until it stops or is locked.");
            } else {
                println!("The background service is unlocked.");
            }
        }
        Cmd::Init { name } => {
            let (engine, vault_key) = Engine::init(&home, name, &passphrase()?)?;
            // The kit: the vault words and the recovery words, shown once.
            let kit = engine.recovery_kit_text()?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({ "vault_id": engine.vault_id().to_string(), "device_id": engine.device_id().to_string(), "vault_key": vault_key, "kit": kit })
                );
            } else {
                println!(
                    "Vault {} created; this device is {}.",
                    engine.vault_id(),
                    engine.device_id()
                );
                println!("Vault key (needed to join other devices; shown once, keep it offline):");
                println!("  {vault_key}");
                println!();
                print!("{kit}");
                println!("Write both word sets down now; they are not shown again. `varsto folder add` asks for the recovery words to make the folder's recovery copy (or give them to the background service once with `varsto unlock --with-recovery-key`).");
                println!("Next: once storages are added, see `varsto recovery guide` for everything to keep in case all your devices are lost.");
            }
        }
        Cmd::Join {
            name,
            key_file,
            storage_name,
            storage_path,
            s3_bucket,
            s3_endpoint,
            s3_region,
            s3_prefix,
            s3_access_key_id,
            s3_secret_file,
            s3_insecure_http,
            recovery_words,
        } => {
            let mut s3_secret: Option<String> = None;
            // The vault key first: it may come from standard input, which the
            // secret prompt below must not touch.
            let key_text = secret_input(
                key_file.as_deref(),
                "VARSTO_VAULT_KEY",
                "Vault key (64 hex digits) or the 24 recovery words: ",
                true,
            )?;
            let key_hex = vault_key_from_text(&key_text)?;
            let spec = match (s3_bucket, storage_path) {
                (Some(bucket), _) => {
                    let secret = secret_input(
                        s3_secret_file.as_deref(),
                        "VARSTO_S3_SECRET",
                        "S3 secret access key: ",
                        false,
                    )?
                    .to_string();
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
                        allow_insecure_http: *s3_insecure_http,
                    }
                }
                (None, Some(path)) => StorageSpec::LocalDir {
                    name: storage_name.clone(),
                    path: path.clone(),
                    cold: false,
                    carrier: false,
                    place: String::new(),
                    min_free: None,
                },
                (None, None) => bail_usage("give --storage-path <dir> or --s3-bucket ...")?,
            };
            let joined = Engine::join(&home, name, &passphrase()?, &key_hex, spec);
            std::env::remove_var(format!(
                "VARSTO_S3_SECRET_{}",
                storage_name
                    .to_uppercase()
                    .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
            ));
            let mut engine = joined?;
            if let Some(secret) = s3_secret {
                engine.store_secret(storage_name, &secret)?;
            }
            // Format 3: the vault words give names and the ledger; the
            // recovery words open every folder that has a recovery copy.
            let recovered = if *recovery_words {
                f3cmd::join_recovery_words(&mut engine)?
            } else {
                Vec::new()
            };
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
                    if recovered.contains(&r.name) || !r.key_hex.is_empty() {
                        println!(
                            "  folder {} ({}): attach it with `varsto folder attach {} <path>`",
                            r.name,
                            r.folder_id.short(),
                            r.name
                        );
                    } else {
                        println!(
                            "  folder {} ({}): ask for it with `varsto folder request {}`, then approve it on a device that has it",
                            r.name,
                            r.folder_id.short(),
                            r.name
                        );
                    }
                }
            }
        }
        Cmd::Storage { cmd } => {
            if let StorageCmd::Set { name, min_free } = cmd {
                // Through the running service when there is one: its own
                // copy of the configuration takes the change at once.
                let m = min_free_arg(min_free)?;
                if call_service(
                    &home,
                    "/api/storage/min-free",
                    serde_json::json!({"name": name, "min_free": min_free}),
                )?
                .is_none()
                {
                    open_engine(&home)?.set_storage_min_free(name, m)?;
                }
                println!("{name}: {} kept free on its disk", min_free_text(m));
                return Ok(());
            }
            let mut engine = open_engine(&home)?;
            match cmd {
                StorageCmd::AddLocal {
                    name,
                    path,
                    cold,
                    carrier,
                    carrier_for,
                    place,
                } => {
                    engine.add_storage(StorageSpec::LocalDir {
                        name: name.clone(),
                        path: path.clone(),
                        cold: *cold,
                        carrier: *carrier,
                        place: place.clone(),
                        min_free: None,
                    })?;
                    println!("storage {name} added");
                    if !carrier_for.is_empty() {
                        let names = engine.set_carrier_for(name, carrier_for)?;
                        println!("transferrer {name} carries what {} lacks", names.join(", "));
                    }
                }
                StorageCmd::CarrierFor { name, devices } => {
                    let names = engine.set_carrier_for(name, devices)?;
                    if names.is_empty() {
                        println!("transferrer {name} carries what any device lacks");
                    } else {
                        println!("transferrer {name} carries what {} lacks", names.join(", "));
                    }
                }
                StorageCmd::AddS3 {
                    name,
                    endpoint,
                    region,
                    bucket,
                    prefix,
                    access_key_id,
                    secret_file,
                    virtual_host,
                    insecure_http,
                    storage_class,
                    cold,
                    place,
                } => {
                    let secret_access_key = secret_input(
                        secret_file.as_deref(),
                        "VARSTO_S3_SECRET",
                        "S3 secret access key: ",
                        true,
                    )?;
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
                            allow_insecure_http: *insecure_http,
                        },
                        Some(secret_access_key.to_string()),
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
                    copies,
                } => {
                    engine.add_storage(StorageSpec::Pool {
                        name: name.clone(),
                        place: place.clone(),
                        reserve_percent: *reserve_percent,
                        min_reserve_bytes: varsto_core::pool::DEFAULT_MIN_RESERVE_BYTES,
                        disks: vec![],
                        scan_roots: scan_root.clone(),
                        copies: (*copies).max(1),
                        verify_after_days: varsto_core::pool::DEFAULT_VERIFY_AFTER_DAYS,
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
                StorageCmd::Drain {
                    name,
                    stop,
                    plan,
                    remove_when_empty,
                    budget_gb_per_day,
                    confirm_cold_read,
                    background,
                } => upkeep::drain(
                    cli,
                    &mut engine,
                    upkeep::DrainArgs {
                        name,
                        stop: *stop,
                        plan: *plan,
                        remove_when_empty: *remove_when_empty,
                        budget_gb_per_day: *budget_gb_per_day,
                        confirm_cold_read: *confirm_cold_read,
                        background: *background,
                    },
                )?,
                StorageCmd::Quota {
                    name,
                    bytes,
                    objects,
                    clear,
                    measure,
                } => upkeep::quota(
                    cli,
                    &mut engine,
                    name,
                    bytes.as_deref(),
                    *objects,
                    *clear,
                    *measure,
                )?,
                StorageCmd::Set { .. } => unreachable!("handled above"),
                StorageCmd::List => {
                    let estimates = engine.storage_estimates()?;
                    let quotas = engine.quota_statuses()?;
                    // The specs, each with its price, stored bytes and monthly cost.
                    let listed: Vec<serde_json::Value> = engine
                        .storages()
                        .iter()
                        .zip(&estimates)
                        .zip(&quotas)
                        .map(|((spec, e), q)| {
                            let mut v = serde_json::to_value(spec).unwrap_or_default();
                            if let Some(c) = engine.conditional_writes(spec.name()) {
                                v["conditional_writes"] = c.into();
                            }
                            v["price"] = serde_json::to_value(&e.price).unwrap_or_default();
                            v["bytes"] = e.bytes.into();
                            v["monthly_cost"] =
                                serde_json::to_value(e.monthly_cost).unwrap_or_default();
                            v["quota"] = serde_json::to_value(q).unwrap_or_default();
                            v
                        })
                        .collect();
                    print(cli, &listed, |_| {
                        engine
                            .storages()
                            .iter()
                            .zip(&estimates)
                            .zip(&quotas)
                            .map(|((x, e), q)| {
                                format!(
                                    "{}{}{}{}{}{} | {} stored{} | {}{}{}",
                                    x.name(),
                                    if x.is_cold() { " (cold)" } else { "" },
                                    if x.is_carrier() { " (transferrer)" } else { "" },
                                    if x.is_data_only() {
                                        format!(" ({})", x.describe())
                                    } else {
                                        String::new()
                                    },
                                    q.drain
                                        .as_ref()
                                        .map(|d| format!(" ({d})"))
                                        .unwrap_or_default(),
                                    match x {
                                        StorageSpec::LocalDir { min_free, .. } => format!(
                                            " (keeps {} free)",
                                            min_free
                                                .unwrap_or(varsto_core::freespace::DEFAULT)
                                                .describe()
                                        ),
                                        _ => String::new(),
                                    },
                                    fmt_bytes(e.bytes),
                                    match (q.quota_bytes, q.quota_objects) {
                                        (None, None) => String::new(),
                                        (Some(b), _) => format!(
                                            ", quota {} ({} used, {} %{})",
                                            fmt_bytes(b),
                                            fmt_bytes(q.used_bytes),
                                            q.percent.unwrap_or(0),
                                            if q.state == "full" {
                                                ", FULL"
                                            } else if q.state == "warning" {
                                                ", nearly full"
                                            } else {
                                                ""
                                            }
                                        ),
                                        (None, Some(o)) => format!(
                                            ", quota {o} objects ({} used{})",
                                            q.used_objects,
                                            if q.state == "full" { ", FULL" } else { "" }
                                        ),
                                    },
                                    e.price
                                        .as_ref()
                                        .map(|p| p.describe())
                                        .unwrap_or_else(|| "no price set".to_string()),
                                    e.monthly_cost
                                        .map(|c| format!(" | about {c:.2} {} a month", e.currency))
                                        .unwrap_or_default(),
                                    match engine.conditional_writes(x.name()) {
                                        Some(false) => " | conditional writes: unsupported",
                                        _ => "",
                                    }
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })?;
                    // Storages other devices have, and the same storage listed twice.
                    if !cli.json {
                        if let Ok(known) = engine.storage_directory() {
                            for k in known {
                                if !k.configured {
                                    println!(
                                        "{} | known from {}, not configured here: add it with the same name and its credentials",
                                        k.name,
                                        k.devices.join(", ")
                                    );
                                } else if !k.same_as.is_empty() {
                                    eprintln!(
                                        "warning: {} is the same storage as {}: keep one of them",
                                        k.name,
                                        k.same_as.join(", ")
                                    );
                                }
                            }
                        }
                    }
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
            let mut engine = open_engine(&home)?;
            match cmd {
                DiskCmd::Place { label, place } => {
                    placing::disk_place(cli, &mut engine, label, place)?;
                }
                DiskCmd::Group { pool, copies } => {
                    placing::disk_group(cli, &mut engine, pool.as_deref(), *copies)?;
                }
                DiskCmd::Add {
                    mount_path,
                    pool,
                    label,
                    place,
                } => {
                    let mut progress = drives::ProgressLine::new(cli.json);
                    let (r, fill) =
                        engine.disk_add_with(mount_path, pool, label, place, &mut |p| {
                            progress.update(p)
                        })?;
                    progress.finish();
                    if let Some(why) = fill.failed {
                        bail!(why);
                    }
                    drives::remember_mount(&home, mount_path, pool, label);
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
                        ) + &r
                            .warning
                            .as_ref()
                            .map(|w| format!("\nwarning: {w}"))
                            .unwrap_or_default()
                    })?;
                }
                DiskCmd::List { sort, reverse } => {
                    let mut disks = engine.disk_report()?;
                    varsto_core::disksuggest::sort_disks(&mut disks, sort, *reverse)?;
                    // The drives of disks.conf: their partition and whether they are plugged in.
                    let known = drives::known_drives(&home);
                    let drive_of = |pool: &str, label: &str| {
                        known
                            .iter()
                            .find(|(d, _)| d.pool == pool && d.label == label)
                    };
                    if cli.json {
                        let mut rows = serde_json::to_value(&disks)?;
                        for row in rows.as_array_mut().into_iter().flatten() {
                            let label = row["label"].as_str().unwrap_or_default().to_string();
                            let pool = row["pool"].as_str().unwrap_or_default().to_string();
                            if let Some((d, at)) = drive_of(&pool, &label) {
                                row["partuuid"] = serde_json::json!(d.partuuid);
                                row["plugged_in"] = serde_json::json!(at.is_some());
                                row["partition"] = serde_json::json!(at.as_ref().map(|a| &a.0));
                            }
                        }
                        println!("{}", serde_json::to_string_pretty(&rows)?);
                        return Ok(());
                    }
                    let mut text = String::new();
                    for (d, at) in &known {
                        text.push_str(&format!(
                            "drive \"{}\" (pool {}, PARTUUID {}): {}\n",
                            d.label,
                            d.pool,
                            d.partuuid,
                            match at {
                                Some((part, Some(m))) =>
                                    format!("plugged in as {part}, mounted at {}", m.display()),
                                Some((part, None)) => format!(
                                    "plugged in as {part}, not mounted (varsto disk insert \"{}\")",
                                    d.label
                                ),
                                None => "not plugged in".to_string(),
                            }
                        ));
                    }
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    if disks.is_empty() {
                        text.push_str("no disks; add a pool with `varsto storage add-pool <name>` and a disk with `varsto disk add`\n");
                    } else {
                        text.push_str(&disk_table(&disks));
                    }
                    // A marker that repeats the pool's public fields without the
                    // vault's MAC is not adopted, whatever it claims.
                    for (pool, mount, label) in engine.unknown_pool_disks() {
                        text.push_str(&format!(
                            "\nunknown disk \"{}\" at {}: it looks like a disk of pool {pool} but carries no valid marker MAC, so it gets no writes. If it is yours, run `varsto disk add {} --pool {pool} --label \"{}\"`\n",
                            show(&label),
                            mount.display(),
                            mount.display(),
                            show(&label)
                        ));
                    }
                    print!("{text}");
                }
                DiskCmd::Suggest { pool, remind } => {
                    if let Some(r) = remind {
                        let mut st = engine.disk_suggest_settings();
                        st.notify_overdue = r == "on";
                        engine.set_disk_suggest_settings(st)?;
                    }
                    let s = engine.disk_suggestions_for(pool.as_deref())?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "suggestions": s,
                                "settings": engine.disk_suggest_settings(),
                            }))?
                        );
                    } else {
                        print!("{}", suggest_text(&s));
                        if let Some(r) = remind {
                            println!("weekly reminder of overdue disks: {r}");
                        }
                    }
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
                        ) + &if r.group_short > 0 {
                            format!(
                                "; {} objects still have fewer than {} copies in different places",
                                r.group_short, r.group_copies
                            )
                        } else {
                            String::new()
                        }
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
                DiskCmd::Init {
                    device,
                    pool,
                    label,
                    place,
                    confirm,
                } => {
                    drives::init(cli, &home, &mut engine, device, pool, label, place, confirm)?;
                }
                DiskCmd::Insert {
                    label,
                    no_fill,
                    no_verify,
                } => {
                    drives::insert(
                        cli,
                        &home,
                        &mut engine,
                        label.as_deref(),
                        varsto_core::engine::InsertOptions {
                            verify: !no_verify,
                            fill: !no_fill,
                        },
                    )?;
                }
                DiskCmd::Unmount {
                    label,
                    no_power_off,
                } => {
                    drives::unmount(cli, &home, &mut engine, label, !no_power_off)?;
                }
                DiskCmd::FetchSet {
                    threshold_mib,
                    overhead_secs,
                    link_mbit,
                    disk_mb_per_sec,
                } => {
                    let mut st = engine.disk_fetch_settings();
                    if let Some(v) = threshold_mib {
                        st.threshold_bytes = v.saturating_mul(1 << 20);
                    }
                    if let Some(v) = overhead_secs {
                        st.overhead_secs = *v;
                    }
                    if let Some(v) = link_mbit.filter(|v| *v > 0.0) {
                        st.link_mbit_per_sec = v;
                    }
                    if let Some(v) = disk_mb_per_sec.filter(|v| *v > 0.0) {
                        st.disk_mb_per_sec = v;
                    }
                    engine.set_disk_fetch_settings(st.clone())?;
                    print(cli, &st, |st| {
                        format!(
                            "pool disks are proposed for fetches of {} or more; {} s per disk to fetch it, network {} Mbit/s, disk {} MB/s",
                            fmt_bytes(st.threshold_bytes),
                            st.overhead_secs,
                            st.link_mbit_per_sec,
                            st.disk_mb_per_sec
                        )
                    })?;
                }
                DiskCmd::PoolSet {
                    pool,
                    verify_after_days,
                } => {
                    engine.set_pool_verify_after_days(pool, *verify_after_days)?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({"pool": pool, "verify_after_days": verify_after_days})
                        );
                    } else {
                        println!("{pool}: copies on a disk are re-hashed at insert when their last check is older than {verify_after_days} days");
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
            if !cli.json
                && matches!(
                    cmd,
                    DiskCmd::Add { .. }
                        | DiskCmd::Check { .. }
                        | DiskCmd::Insert { .. }
                        | DiskCmd::Init { .. }
                )
            {
                placing::continue_hint(&engine);
            }
        }
        Cmd::Backup { cmd } => backup::run(cli, &home, cmd)?,
        Cmd::Trash { cmd } => trash::run(cli, &home, cmd)?,
        Cmd::History(args) => history::run(cli, &home, args)?,
        Cmd::Move { cmd: Some(cmd), .. } => placing::move_cmd(cli, &home, cmd)?,
        Cmd::Move {
            cmd: None,
            folder,
            from,
            to,
            paths,
            keep_source,
            job,
            idle_days,
            dry_run,
            confirm_cold_read,
            yes,
        } => {
            let (Some(folder), Some(from), Some(to)) = (folder, from, to) else {
                return bail_usage("move needs a folder, --from and --to");
            };
            let mut engine = open_engine(&home)?;
            let args = placing::MoveArgs {
                folder,
                from,
                to,
                idle_days: *idle_days,
                dry_run: *dry_run,
                confirm_cold_read: *confirm_cold_read,
                yes: *yes,
            };
            let to_pool = engine
                .storages()
                .iter()
                .any(|s| s.name() == to.as_str() && s.is_data_only());
            if to_pool || *job || *keep_source || !paths.is_empty() {
                placing::move_job(cli, &mut engine, args, paths, *keep_source)?;
            } else {
                placing::move_data(cli, &mut engine, args)?;
            }
        }
        Cmd::Folder { cmd } => {
            if f3cmd::folder(cli, &home, cmd)? {
                return Ok(());
            }
            if folder_safety_cmd(cli, &home, cmd)? {
                return Ok(());
            }
            // With the background service running, changes to which folders
            // this device syncs go through it: it starts (or stops) watching
            // at once, and its own copy of the configuration stays current.
            if let Some(done) = folder_via_service(&home, cmd)? {
                println!("{done}");
                return Ok(());
            }
            let mut engine = open_engine(&home)?;
            match cmd {
                FolderCmd::Placement {
                    folder,
                    storage,
                    place,
                    every,
                } => {
                    placing::folder_placement(cli, &mut engine, folder, storage, place, *every)?;
                }
                FolderCmd::Add {
                    name,
                    path,
                    recovery_file,
                } => {
                    let k1 = if engine.has_recovery_key() {
                        None
                    } else {
                        f3cmd::folder_add_recovery_key(recovery_file.as_deref(), true)?
                    };
                    let id = engine.add_folder_with_recovery(name, path, k1)?;
                    println!("folder {name} ({}) created", id.short());
                    f3cmd::status_warnings(&mut engine);
                }
                FolderCmd::Attach {
                    name_or_id,
                    path,
                    selective,
                    mode,
                } => {
                    // Checked first: a mode that is refused attaches nothing.
                    let mode: Option<varsto_core::vault::FolderMode> =
                        mode.as_deref().map(str::parse).transpose()?;
                    let id = engine.attach_folder(name_or_id, path, *selective)?;
                    if let Some(m) = mode.filter(|m| !m.is_normal()) {
                        engine.set_folder_mode(name_or_id, m)?;
                    }
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
                FolderCmd::Fetch {
                    folder,
                    path,
                    from_disks,
                } => {
                    let (folder, path) = &folder_and_path(&engine, folder, path)?;
                    if *from_disks != drives::FromDisks::Never
                        && engine.disks().is_ok_and(|d| !d.is_empty())
                    {
                        // Pool disks may be the better source: plan, and run the plan if chosen.
                        if drives::fetch_with_plan(
                            cli,
                            &home,
                            &mut engine,
                            folder,
                            std::slice::from_ref(path),
                            *from_disks,
                        )? {
                            return Ok(());
                        }
                        // Ran but stopped or left a file out: the plan is kept.
                        if engine.load_fetch_plan().is_some() {
                            std::process::exit(1);
                        }
                    }
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
                FolderCmd::Remove {
                    name, purge, yes, ..
                } => {
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
                    let rows = engine.list_files_with_pending(folder)?;
                    print(cli, &rows, |rows| {
                        rows.iter()
                            .map(|f| {
                                format!(
                                    "{:<12} {:>10} {}{}{}",
                                    f.state,
                                    f.size,
                                    show(&f.path),
                                    match &f.symlink {
                                        Some(t) if f.symlink_absolute =>
                                            format!(" -> {t} (absolute)"),
                                        Some(t) => format!(" -> {t}"),
                                        None => String::new(),
                                    },
                                    if f.pinned { " (pinned)" } else { "" }
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })?;
                }
                FolderCmd::Ignore {
                    folder,
                    list,
                    add,
                    remove,
                    local,
                } => {
                    for p in add {
                        let done = engine.ignore_add(folder, p, *local)?;
                        if !cli.json {
                            println!("{} {p}", if done { "added" } else { "already there:" });
                        }
                    }
                    for p in remove {
                        let done = engine.ignore_remove(folder, p, *local)?;
                        if !cli.json {
                            println!("{} {p}", if done { "removed" } else { "not there:" });
                        }
                    }
                    if *list || (add.is_empty() && remove.is_empty()) || cli.json {
                        let info = engine.folder_ignore(folder)?;
                        print(cli, &info, |i| ignore_listing(i, *local))?;
                    } else if !*local {
                        println!("the change reaches the other devices with the next sync");
                    }
                }
                FolderCmd::CheckIgnore { folder, path } => {
                    let v = engine.check_ignore(folder, path, None, None)?;
                    print(cli, &v, |v| match (&v.pattern, &v.source) {
                        (Some(p), Some(s)) => format!(
                            "{path}: {} by {p:?} ({s}{}){}",
                            if v.ignored { "ignored" } else { "included" },
                            v.line.map(|l| format!(", line {l}")).unwrap_or_default(),
                            match &v.matched_path {
                                Some(m) if m.as_str() != path.trim_matches('/') => {
                                    format!(" through {m}/")
                                }
                                _ => String::new(),
                            }
                        ),
                        _ => format!("{path}: not ignored (no pattern matches)"),
                    })?;
                }
                FolderCmd::Set {
                    folder,
                    min_free,
                    permissions,
                    symlinks,
                    xattrs,
                    ownership,
                } => {
                    if let Some(min_free) = min_free {
                        let m = min_free_arg(min_free)?;
                        engine.set_folder_min_free(folder, m)?;
                        if !cli.json {
                            println!("{folder}: {} kept free on its disk here", min_free_text(m));
                        }
                    }
                    let mut s = engine.folder_settings(folder)?;
                    let change = permissions.is_some()
                        || symlinks.is_some()
                        || xattrs.is_some()
                        || ownership.is_some();
                    s.permissions = permissions.unwrap_or(s.permissions);
                    s.symlinks = symlinks.unwrap_or(s.symlinks);
                    s.xattrs = xattrs.unwrap_or(s.xattrs);
                    s.ownership = ownership.unwrap_or(s.ownership);
                    if change {
                        engine.set_folder_settings(folder, s)?;
                    }
                    let onoff = |b: bool| if b { "on" } else { "off" };
                    print(cli, &s, |s| {
                        format!(
                            "permissions {}\nsymlinks {}\nxattrs {}\nownership {}",
                            onoff(s.permissions),
                            onoff(s.symlinks),
                            onoff(s.xattrs),
                            onoff(s.ownership)
                        )
                    })?;
                }
                FolderCmd::RepairMarker { .. }
                | FolderCmd::ConfirmDeletions { .. }
                | FolderCmd::Mode { .. }
                | FolderCmd::Override { .. }
                | FolderCmd::Revert { .. }
                | FolderCmd::Pending { .. }
                | FolderCmd::DeletionGuard { .. }
                | FolderCmd::Request { .. }
                | FolderCmd::Requests { .. }
                | FolderCmd::Approve { .. }
                | FolderCmd::Deny { .. }
                | FolderCmd::Members { .. }
                | FolderCmd::Role { .. }
                | FolderCmd::ResolveEpoch { .. }
                | FolderCmd::CreateF3 { .. } => unreachable!("handled before"),
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
            let mut engine = open_engine(&home)?;
            let r = engine.push(folder)?;
            print(cli, &r, |r| {
                if r.read_only {
                    return format!(
                        "{}: read-only: your changes were not published{}",
                        r.folder,
                        kept_aside_text(&r.kept_aside)
                    );
                }
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
            let mut engine = open_engine(&home)?;
            let r = engine.pull(folder)?;
            print(cli, &r, |r| {
                format!("{}: {} manifests, {} updated, {} deleted, {} conflicts, {} chunks downloaded; unavailable: {:?}; forked: {:?}{}{}{}", r.folder, r.manifests_applied, r.files_updated, r.files_deleted, r.conflicts, r.chunks_downloaded, r.files_unavailable, r.forked_devices, if r.disks_needed.is_empty() { String::new() } else { format!("; attach disk {}", r.disks_needed.join(", ")) }, renamed_note(&r.renamed_locally), role_notes(r, None))
            })?;
        }
        Cmd::Sync { folder } => {
            let mut engine = open_engine(&home)?;
            let r = engine.sync(folder.as_deref())?;
            warn_ledger(&engine.ledger_health());
            print(cli, &r, |r| {
                r.iter().map(|(pl, ps)| if let Some(p) = &pl.paused { format!("{}: PAUSED: {}", pl.folder, p.message) } else { format!("{}: pulled {} updated/{} deleted/{} conflicts, pushed {} changed/{} chunks{}{}{}{}", pl.folder, pl.files_updated, pl.files_deleted, pl.conflicts, ps.files_changed, ps.chunks_uploaded, if pl.disks_needed.is_empty() { String::new() } else { format!("; attach disk {}", pl.disks_needed.join(", ")) }, if ps.storages_unavailable.is_empty() { String::new() } else { format!("; not written to {}", ps.storages_unavailable.join(", ")) }, renamed_note(&pl.renamed_locally), role_notes(pl, Some(ps))) }).collect::<Vec<_>>().join("\n")
            })?;
        }
        Cmd::FetchPlan { folder, paths } => {
            let mut engine = Engine::open(&home, &passphrase()?)?;
            let plan = engine.fetch_plan(folder, paths)?;
            print(cli, &plan, drives::plan_text)?;
        }
        Cmd::Changes {
            folder,
            path,
            device,
            user,
            since,
            limit,
        } => {
            let since_utc = since
                .as_deref()
                .map(|s| varsto_core::changes::parse_since(s, varsto_core::util::now_utc()))
                .transpose()?;
            let report: varsto_core::engine::ChangesReport =
                if let Some((sf, _)) = service::status(&home) {
                    let mut url = format!(
                        "http://127.0.0.1:{}/api/changes?folder={}&limit={limit}",
                        sf.port,
                        url_escape(folder)
                    );
                    for (k, v) in [("path", path), ("device", device), ("user", user)] {
                        if let Some(v) = v {
                            url.push_str(&format!("&{k}={}", url_escape(v)));
                        }
                    }
                    if let Some(t) = since_utc {
                        url.push_str(&format!("&since={t}"));
                    }
                    serde_json::from_str(&service::http_get(&url, &sf.token)?)?
                } else {
                    let mut engine = open_engine(&home)?;
                    engine.history_start(folder)?;
                    engine.changes(
                        folder,
                        &varsto_core::engine::ChangesQuery {
                            path: path.clone(),
                            device: device.clone(),
                            user: user.clone(),
                            since_utc,
                            limit: *limit,
                        },
                    )?
                };
            print(cli, &report, changes_text)?;
        }
        Cmd::Status => {
            // The running service answers without a passphrase while it is
            // unlocked; the line about the service comes first either way.
            let svc = service::status(&home);
            if !cli.json {
                if let Some(note) = update::channel_note(&home) {
                    println!("varsto {} ({note})", env!("CARGO_PKG_VERSION"));
                }
            }
            let api = |path: &str| -> Option<serde_json::Value> {
                let (f, _) = svc.as_ref()?;
                let t = service::http_get(&format!("http://127.0.0.1:{}{path}", f.port), &f.token)
                    .ok()?;
                serde_json::from_str(&t).ok()
            };
            let from_service = api("/api/status").filter(|v| v.get("vault_id").is_some());
            if !cli.json {
                println!(
                    "{}",
                    service_line(
                        svc.as_ref().map(|(f, _)| f.pid),
                        api("/api/service"),
                        api("/api/state")
                    )
                );
            }
            if let Some(mut v) = from_service {
                if cli.json {
                    v["move_jobs"] =
                        serde_json::to_value(varsto_core::staged_move::list_active(&home))?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                } else {
                    println!("{}", status_from_value(&v));
                    for l in placing::status_lines(&home) {
                        println!("{l}");
                    }
                }
                return Ok(());
            }
            let mut engine = open_engine(&home)?;
            let s = engine.status()?;
            f3cmd::status_warnings(&mut engine);
            let move_lines = if cli.json {
                Vec::new()
            } else {
                placing::status_lines(&home)
            };
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
                    out += &folder_safety_lines(&serde_json::to_value(f).unwrap_or_default());
                }
                if !s.forked_devices.is_empty() {
                    out += &format!("WARNING forked devices: {:?}\n", s.forked_devices);
                }
                out += &format!("ledger: {}\n", s.ledger_health.describe());
                for l in &move_lines {
                    out += &format!("{l}\n");
                }
                out.trim_end().to_string()
            })?;
        }
        Cmd::HelpNow => {
            // The running service knows more (paused, peers, last error) and
            // needs no passphrase.
            let svc = service::status(&home);
            let from_service = svc.as_ref().and_then(|(f, _)| {
                let t =
                    service::http_get(&format!("http://127.0.0.1:{}/api/help", f.port), &f.token)
                        .ok()?;
                serde_json::from_str::<varsto_core::help::HelpState>(&t).ok()
            });
            let h = match from_service {
                // A locked service cannot tell; the command line may unlock.
                Some(h) if h.phase != "locked" => h,
                _ if !home.join("vault.json").exists() => {
                    varsto_core::engine::help_without_vault(&home)
                }
                _ => match open_engine(&home) {
                    Ok(mut e) => {
                        let observed = varsto_core::engine::HelpObserved {
                            // No service: nothing syncs by itself. A locked
                            // one is running but cannot say more.
                            service: svc.is_none().then(varsto_core::help::ServiceIn::default),
                            ..Default::default()
                        };
                        e.help_state(observed)?
                    }
                    Err(err) => {
                        eprintln!("the vault stays locked: {err:#}");
                        varsto_core::engine::help_without_vault(&home)
                    }
                },
            };
            print(cli, &h, varsto_core::help::render_text)?;
        }
        Cmd::Forward { cmd } => upkeep::forward(cli, &home, cmd)?,
        Cmd::Mailbox { cmd } => upkeep::mailbox(cli, &home, cmd)?,
        Cmd::Verify { cmd } => upkeep::verify(cli, &home, cmd)?,
        Cmd::Scrub { cmd, run } => upkeep::scrub(cli, &home, cmd, run)?,
        Cmd::Import { cmd } => import::run(cli, &home, cmd)?,
        Cmd::Advice { idle_days, cmd } => upkeep::advice(cli, &home, *idle_days, cmd)?,
        Cmd::Restic { cmd } => restic::run(cli, &home, cmd)?,
        Cmd::Repair {
            dry_run,
            from_cold,
            no_scan,
            max_mib,
            max_blocks,
        } => upkeep::repair(
            cli,
            &home,
            upkeep::RepairArgs {
                dry_run: *dry_run,
                from_cold: *from_cold,
                scan: !*no_scan,
                max_mib: *max_mib,
                max_blocks: *max_blocks,
            },
        )?,
        Cmd::Fsck { verify, fix } => {
            let mut engine = open_engine(&home)?;
            let r = engine.fsck(*verify)?;
            print(cli, &r, |r| {
                let summary = match &r.format3 {
                    Some(f) => f.describe(),
                    None => format!("referenced {} | with storage copy {} | missing {:?} | corrupt {:?}", r.chunks_referenced, r.chunks_with_storage_copy, r.chunks_missing, r.objects_corrupt),
                };
                summary
                    + &format!(" | repairs queued {} | cold skipped {:?}", r.repairs_queued, r.storages_skipped_cold)
                    + &if r.ledger_health.is_ok() { String::new() } else { format!("\nledger: {}", r.ledger_health.describe()) }
            })?;
            let mut repaired_all = false;
            if *fix && r.repairs_queued > 0 {
                let mut opts = varsto_core::engine::RepairOptions::manual();
                opts.scan = false;
                let rep = engine.repair(&opts)?;
                print(cli, &rep, upkeep::describe_repair)?;
                repaired_all = rep.unrepairable.is_empty() && rep.left_for_next_run == 0;
            }
            if (!r.chunks_missing.is_empty() || !r.objects_corrupt.is_empty()) && !repaired_all
                || !r.forked_devices.is_empty()
            {
                std::process::exit(1);
            }
        }
        Cmd::Dupes { folder } => {
            let engine = open_engine(&home)?;
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
                println!(
                    "service already running (pid {}): http://127.0.0.1:{}/",
                    f.pid, f.port
                );
                if !*no_open {
                    desktop::open_in_browser(&service::boot_url(&f)?);
                }
                return Ok(());
            }
            quit_on_signals();
            service::run(service::Options {
                home,
                port: *port,
                interval_secs: *interval,
                open_browser: !*no_open,
            })?;
        }
        Cmd::Service { cmd } => match cmd {
            ServiceCmd::Run { port, interval } => {
                quit_on_signals();
                service::run(service::Options {
                    home,
                    port: *port,
                    interval_secs: *interval,
                    open_browser: false,
                })?
            }
            ServiceCmd::Install { interval } => {
                service::set_opted_out(&home, false);
                println!("{}", service::install(&home, *interval)?)
            }
            ServiceCmd::Uninstall => {
                service::set_opted_out(&home, true);
                println!("{}", service::uninstall()?)
            }
            ServiceCmd::Remember => {
                let pass = passphrase()?;
                Engine::open(&home, &pass)?; // wrong passphrases are not stored
                println!("{}", service::remember_passphrase(&home, &pass)?);
            }
            ServiceCmd::Forget => println!("{}", service::forget_passphrase(&home)?),
            ServiceCmd::Status => match service::status(&home) {
                Some((f, v)) => {
                    let store = remember::where_remembered(&home);
                    print(
                        cli,
                        &serde_json::json!({"pid": f.pid, "port": f.port, "version": f.version, "service": v, "passphrase_store": store.map(|s| s.id()), "passphrase_text": remember::status_text(store)}),
                        |v| {
                            format!(
                                "running: pid {} port {} version {}; {}\n{}{}",
                                v["pid"],
                                v["port"],
                                v["version"],
                                v["service"],
                                v["passphrase_text"].as_str().unwrap_or(""),
                                v["service"]["auto_verify_text"]
                                    .as_str()
                                    .map(|t| format!("\n{t}"))
                                    .unwrap_or_default()
                                    + &v["service"]["repair_text"]
                                        .as_str()
                                        .map(|t| format!("\n{t}"))
                                        .unwrap_or_default()
                                    + &v["service"]["scrub_text"]
                                        .as_str()
                                        .map(|t| format!("\n{t}"))
                                        .unwrap_or_default()
                            )
                        },
                    )?
                }
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
        Cmd::Install { interval } => {
            service::set_opted_out(&home, false);
            println!("{}", service::install(&home, *interval)?)
        }
        Cmd::Uninstall => {
            service::set_opted_out(&home, true);
            println!("{}", service::uninstall()?)
        }
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
            ShareCmd::Request { name, qr } => {
                let code =
                    varsto_core::vault::ShareRequest::code_for_named(&home, name.as_deref())?;
                let words = varsto_core::vault::ShareRequest::fingerprint_for(&home)?;
                if *qr && !cli.json {
                    show_qr(&code, false, false)?;
                }
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({"request_code": code, "fingerprint": words})
                    );
                } else {
                    println!("share request code for this device (give it to the folder owner; it contains no secret):\n  {code}\n\nfingerprint: {words}\nThe owner sees the same six words for this code. Read them to each other over a call or in person before the owner shares: different words mean the code was changed on its way.");
                }
            }
            ShareCmd::Qr { text, parts, light } => share_qr(cli.json, text, *parts, *light)?,
            ShareCmd::Create {
                folder,
                to,
                fingerprint,
                yes,
                qr,
                role,
            } => {
                let role = varsto_core::share::ShareRole::parse(role)?;
                if !role.is_editor() && to.is_none() {
                    bail_usage::<()>("a viewer's token must be sealed to their request code: give --to <request-code> (a plain token cannot say what its holder may do)")?;
                }
                let mut engine = open_engine(&home)?;
                match to {
                    Some(code) => {
                        let req = Engine::share_request_info(code)?;
                        let confirmed = match fingerprint {
                            Some(f) => Some(f.clone()),
                            None if *yes => None,
                            None => {
                                eprintln!(
                                    "Request from {}\nfingerprint: {}\nAsk the requester to read their fingerprint (varsto share request shows it).",
                                    if req.name.is_empty() { "(no name given)".into() } else { show(&req.name) },
                                    req.fingerprint
                                );
                                if !confirm("Do the six words match exactly?")? {
                                    bail!("not shared: the fingerprint was not confirmed");
                                }
                                Some(req.fingerprint.clone())
                            }
                        };
                        let (sealed, req) = engine.share_create_sealed_as(
                            folder,
                            code,
                            confirmed.as_deref(),
                            role,
                        )?;
                        if *qr && !cli.json {
                            show_qr(&sealed.encode(), false, false)?;
                        }
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::json!({"folder": sealed.name, "token": sealed.encode(), "sealed": true, "fingerprint": req.fingerprint, "name": req.name, "role": role.as_str()})
                            );
                        } else {
                            println!("sealed share token for folder {} as {} (only the device that made the request code can open it; fingerprint {}):\n  {}", show(&sealed.name), if role.is_editor() { "an editor (read and write)" } else { "a viewer (read only)" }, req.fingerprint, sealed.encode());
                        }
                    }
                    None => {
                        let t = engine.share_create_plain(folder)?;
                        let encoded = t.encode_plain()?;
                        print(cli, &t, |t| {
                            format!("share token for folder {} (the folder key is INSIDE this token: anyone holding it can read and write the folder; prefer `share create --to <request-code>`):\n  {encoded}", t.name)
                        })?
                    }
                }
            }
            ShareCmd::Accept {
                name,
                token,
                token_arg,
                storage_path,
                storage_name,
                s3_bucket,
                s3_endpoint,
                s3_region,
                s3_prefix,
                s3_access_key_id,
                s3_secret_file,
                s3_insecure_http,
            } => {
                let token = token
                    .as_ref()
                    .or(token_arg.as_ref())
                    .ok_or_else(|| anyhow!("give the share token"))?;
                let token = if varsto_core::vault::SealedShareToken::is_sealed(token) {
                    varsto_core::vault::ShareRequest::open_token(&home, token)?
                } else {
                    varsto_core::vault::ShareToken::decode(token)?
                };
                let (spec, secret) = match (s3_bucket, storage_path) {
                    (Some(bucket), _) => (
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
                            allow_insecure_http: *s3_insecure_http,
                        },
                        Some(
                            secret_input(
                                s3_secret_file.as_deref(),
                                "VARSTO_S3_SECRET",
                                "S3 secret access key: ",
                                true,
                            )?
                            .to_string(),
                        ),
                    ),
                    (None, Some(path)) => (
                        StorageSpec::LocalDir {
                            name: storage_name.clone(),
                            path: path.clone(),
                            cold: false,
                            carrier: false,
                            place: String::new(),
                            min_free: None,
                        },
                        None,
                    ),
                    (None, None) => bail_usage("give --storage-path <dir> or --s3-bucket ...")?,
                };
                let engine = Engine::accept_share_with_secret(
                    &home,
                    name,
                    &passphrase()?,
                    &token,
                    spec,
                    secret,
                )?;
                varsto_core::vault::ShareRequest::clear(&home);
                if !token.fingerprint.is_empty() {
                    println!(
                        "the owner confirmed this device's fingerprint: {}",
                        token.fingerprint
                    );
                }
                println!("joined shared folder {} as device {}; attach it with `varsto folder attach {} <path>` and sync", show(&token.name), engine.device_id().short(), show(&token.name));
            }
            ShareCmd::Members { folder } => {
                let list: varsto_core::engine::ShareMembers =
                    if let Some((sf, _)) = service::status(&home) {
                        let url = format!(
                            "http://127.0.0.1:{}/api/share/members?folder={}",
                            sf.port,
                            url_escape(folder)
                        );
                        serde_json::from_str(&service::http_get(&url, &sf.token)?)?
                    } else {
                        let engine = open_engine(&home)?;
                        engine.share_members(folder)?
                    };
                print(cli, &list, share_members_text)?;
            }
            ShareCmd::Role {
                folder,
                member,
                role,
            } => {
                let role = varsto_core::share::ShareRole::parse(role)?;
                let report: varsto_core::engine::ShareRoleReport = if let Some((sf, _)) =
                    service::status(&home)
                {
                    let url = format!("http://127.0.0.1:{}/api/share/role", sf.port);
                    let body = serde_json::json!({"folder": folder, "member": member, "role": role.as_str()});
                    let r = service::http_post(&url, &sf.token, &body.to_string())?;
                    serde_json::from_str(&r)
                        .map_err(|_| anyhow!("unexpected answer from the service: {r}"))?
                } else {
                    let mut engine = open_engine(&home)?;
                    engine.share_set_role(folder, member, role)?
                };
                print(cli, &report, |r| {
                    format!(
                        "{}: {} is now {} (role record {}){}",
                        r.folder,
                        r.member,
                        if r.role == "viewer" {
                            "a viewer: read only"
                        } else {
                            "an editor: read and write"
                        },
                        r.seq,
                        if r.role == "viewer" {
                            "\nWhat it wrote until now stays; what it writes from now on is not accepted. It can still copy what it reads."
                        } else {
                            ""
                        }
                    )
                })?;
            }
            ShareCmd::Revoke {
                folder,
                member,
                yes,
            } => {
                if !*yes {
                    bail_usage::<()>(&format!(
                        "this removes {member} from {folder}: the folder gets a new key, the members who stay receive it, and everything written from now on is unreadable to {member}; its later changes are ignored. Everything it already received stays readable to it: a key cannot be recalled. A token not accepted yet stops bringing anything new. Run again with --yes"
                    ))?;
                }
                let report: varsto_core::engine::ShareRevokeReport = if let Some((sf, _)) =
                    service::status(&home)
                {
                    let url = format!("http://127.0.0.1:{}/api/share/revoke", sf.port);
                    let body =
                        serde_json::json!({"folder": folder, "member": member, "confirm": true});
                    let r = service::http_post(&url, &sf.token, &body.to_string())?;
                    serde_json::from_str(&r)
                        .map_err(|_| anyhow!("unexpected answer from the service: {r}"))?
                } else {
                    let mut engine = open_engine(&home)?;
                    engine.share_revoke(folder, member)?
                };
                print(cli, &report, |r| {
                    let mut out = format!(
                        "{}: new folder key (share epoch {})",
                        r.folder, r.share_epoch
                    );
                    if !r.removed.is_empty() {
                        out.push_str(&format!("\nremoved: {}", r.removed.join(", ")));
                    }
                    if !r.invites_revoked.is_empty() {
                        out.push_str(&format!(
                            "\ntokens revoked: {}",
                            r.invites_revoked.join(", ")
                        ));
                    }
                    out.push_str(&format!(
                        "\nnew key sealed to {} (members and open tokens)",
                        plural(r.grants_sealed, "recipient", "recipients")
                    ));
                    if !r.grants_pending.is_empty() {
                        out.push_str(&format!(
                            "\nwaiting for (they get it once they run this version): {}",
                            r.grants_pending.join(", ")
                        ));
                    }
                    out
                })?;
            }
        },
        Cmd::Replica { cmd } => match cmd {
            ReplicaCmd::Token => {
                let engine = open_engine(&home)?;
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
                    min_free: None,
                };
                let tgt = StorageSpec::LocalDir {
                    name: "target".into(),
                    path: target.clone(),
                    cold: false,
                    carrier: false,
                    place: String::new(),
                    min_free: None,
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
                        format!("seen {}, copied {} ({} bytes), verified {}, corrupt {}, junk skipped {}, batch {:?}", rep.objects_seen, rep.objects_copied, rep.bytes_copied, rep.chunks_verified, rep.objects_corrupt, rep.skipped_junk, rep.batch_seq)
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
        },
        Cmd::Reset { yes } => {
            if !*yes {
                bail_usage::<()>("this removes keys, ledger, state and configuration from this device (files in folders stay); run again with --yes")?;
            }
            let running = service::status(&home).is_some();
            if let Some((sf, _)) = service::status(&home) {
                let url = format!("http://127.0.0.1:{}/api/reset", sf.port);
                service::http_call(
                    "POST",
                    &url,
                    &sf.token,
                    Some(&serde_json::json!({"confirm": "reset"}).to_string()),
                )?;
                println!("device reset through the running service");
            }
            // Whatever the service did, nothing that marks this device as
            // holding a vault may be left (`ensure_no_vault` looks at vault.json).
            let removed = varsto_core::engine::reset_device(&home)?;
            if !removed.is_empty() {
                println!("removed: {}", removed.join(", "));
            }
            if running {
                // The old service keeps no state now; start it again so it
                // runs without the old vault.
                if service::restart_and_wait(&home) {
                    println!("the background service restarted");
                } else {
                    eprintln!("could not restart the background service: start it with `varsto service run` or `varsto install`");
                }
            }
        }
        Cmd::Device { cmd } => match cmd {
            DeviceCmd::ResolveEpoch { epoch, keep } => {
                let mut engine = open_engine(&home)?;
                engine.resolve_epoch_fork(*epoch, keep)?;
                print(cli, engine.epoch_forks(), |f| {
                    format!(
                        "kept {} for key epoch {epoch}; {}",
                        keep,
                        if f.unresolved().is_empty() {
                            "this device signs again".to_string()
                        } else {
                            format!("still to choose: key epochs {:?}", f.unresolved())
                        }
                    )
                })?;
            }
            DeviceCmd::List => {
                let engine = open_engine(&home)?;
                let list = engine.devices_list();
                print(cli, &list, |list| {
                    let mut out = format!("vault key epoch {}\n", engine.key_epoch());
                    for d in list {
                        out += &format!(
                            "{} ({}){}{}{}\n",
                            d.name,
                            &d.device_id[..8],
                            if d.this_device { ", this device" } else { "" },
                            match (&d.user, &d.role) {
                                (Some(u), Some(r)) => format!(", {u} ({r})"),
                                (Some(u), None) => format!(", {u}"),
                                _ => String::new(),
                            },
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
                    let mut engine = open_engine(&home)?;
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
                PairCmd::Offer {
                    qr,
                    folders,
                    role,
                    yes,
                } => {
                    use std::sync::mpsc;
                    use varsto_core::pair::v3::Joiner;
                    let mut engine = open_engine(&home)?;
                    let mut bundle = engine.pairing_bundle()?;
                    let key =
                        varsto_core::crypto::SecretKey::from_hex(&engine.export_vault_key()?)?;
                    bundle.vault_key = String::new();
                    // The offer's thread asks; this one answers, after the
                    // person compared the words and the grants are written.
                    let (ask_tx, ask_rx) = mpsc::channel::<Joiner>();
                    let (answer_tx, answer_rx) = mpsc::channel::<bool>();
                    let answer_rx = std::sync::Mutex::new(answer_rx);
                    let approve: varsto_core::pair::v3::Approve =
                        std::sync::Arc::new(move |j: &Joiner| {
                            if ask_tx.send(j.clone()).is_err() {
                                return false;
                            }
                            answer_rx
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .recv_timeout(std::time::Duration::from_secs(300))
                                .unwrap_or(false)
                        });
                    let offer = varsto_core::pair::Offer::start_v3(bundle, key, approve)?;
                    let st = offer.status();
                    if cli.json {
                        // One line a script reads before it starts the other side.
                        println!(
                            "{}",
                            serde_json::json!({"code": st.code, "port": st.port, "addresses": st.addresses})
                        );
                        use std::io::Write as _;
                        let _ = std::io::stdout().flush();
                    }
                    if *qr {
                        let link = varsto_core::qr::Link::Pair {
                            code: st.code.clone(),
                            addresses: st.addresses.clone(),
                        };
                        show_qr(&link.to_uri()?, false, false)?;
                        println!("Scan it with the new device's camera, or in Varsto: Pair with your other device, Scan QR code.");
                    }
                    println!("Pairing code: {}", st.code);
                    println!("On the new device choose \"Pair\" (or run `varsto pair join`).");
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
                        if let Ok(j) = ask_rx.recv_timeout(std::time::Duration::from_millis(500)) {
                            eprintln!("{} asks to join. Its six words: {}", j.name, j.fingerprint);
                            eprintln!("The new device shows its own six words; compare them.");
                            let mut allow = *yes || ask_stdin("Do the six words match?")?;
                            if allow && !folders.is_empty() {
                                match engine.f3_pair_grants(
                                    &j.name,
                                    &j.signing_pub,
                                    &j.kem_pub,
                                    folders,
                                    role,
                                ) {
                                    Ok(_) => println!("granted {}: {}", role, folders.join(", ")),
                                    Err(e) => {
                                        eprintln!("the folders could not be granted: {e:#}");
                                        allow = false;
                                    }
                                }
                            }
                            if !allow {
                                eprintln!("not letting {} join", j.name);
                            }
                            let _ = answer_tx.send(allow);
                        }
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
                    // The link of the other device's QR code carries the code and
                    // all its candidate addresses, best first. Order of tries:
                    // --address, the link's addresses, then the LAN search.
                    let (code, offered) = match varsto_core::qr::Link::from_text(code) {
                        Ok(varsto_core::qr::Link::Pair { code, addresses }) => (code, addresses),
                        _ => (code.clone(), Vec::new()),
                    };
                    let pass = passphrase()?;
                    // This device's keys: the other device shows their six
                    // words before it lets this one join.
                    let keys = varsto_core::pair::v3::PairingKeys::generate();
                    eprintln!("This device's six words: {}", keys.fingerprint());
                    eprintln!(
                        "The other device shows the same words before it lets this one join."
                    );
                    let result = varsto_core::pair::receive_with_progress(
                        &code,
                        &keys.join_keys(name),
                        address.as_deref(),
                        &offered,
                        &mut |step| match step {
                            varsto_core::pair::Step::Trying(a) => eprintln!("trying {a} ..."),
                            varsto_core::pair::Step::Looking => {
                                eprintln!("looking for the device on the network ...")
                            }
                        },
                    );
                    let bundle = result?;
                    let (engine, notes) = Engine::join_paired(&home, name, &pass, &bundle, keys)?;
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
            RecoveryCmd::Escrow {
                folder,
                with_recovery_key,
                recovery_file,
            } => f3cmd::recovery_escrow(
                cli,
                &home,
                folder.as_deref(),
                *with_recovery_key,
                recovery_file.as_deref(),
            )?,
            RecoveryCmd::Kit {
                recovery_words,
                new_recovery_key,
                ..
            } if *recovery_words || *new_recovery_key => {
                f3cmd::recovery_kit(&home, *new_recovery_key)?
            }
            RecoveryCmd::Kit { shares, .. } => {
                let engine = open_engine(&home)?;
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
                if let Some(note) = restic::kit_note(&home) {
                    print!("{note}");
                }
                varsto_core::recovery_guide::record_kit_printed(
                    &home,
                    engine.key_epoch(),
                    *shares,
                )?;
                println!("\nThe words alone are not the whole recovery package: `varsto recovery guide` lists what else to keep (storage keys, disks, security keys) and how to restore on a new device.");
            }
            RecoveryCmd::Guide { format, output } => {
                let engine = Engine::open(&home, &passphrase()?)?;
                let guide = engine.recovery_guide();
                let body = if cli.json {
                    serde_json::to_string_pretty(&guide)?
                } else {
                    match format {
                        GuideFormat::Text => varsto_core::recovery_guide::render_text(&guide),
                        GuideFormat::Markdown => {
                            varsto_core::recovery_guide::render_markdown(&guide)
                        }
                        GuideFormat::Html => varsto_core::recovery_guide::render_html(&guide),
                    }
                };
                match output {
                    Some(path) => {
                        std::fs::write(path, body.as_bytes())
                            .with_context(|| format!("write {}", path.display()))?;
                        eprintln!("wrote the recovery guide to {}", path.display());
                    }
                    None => print!("{body}"),
                }
            }
            RecoveryCmd::Combine { files, check } => {
                let lines = secret_lines(
                    files,
                    "Share (<index>: <24 words>), an empty line when done: ",
                )?;
                let parsed: Vec<varsto_core::recovery::Share> = lines
                    .iter()
                    .map(|s| varsto_core::recovery::Share::decode(s))
                    .collect::<Result<_>>()?;
                if parsed.len() < 2 {
                    bail_usage::<()>("give at least two shares")?;
                }
                let key = varsto_core::recovery::combine(&parsed, 2, check.as_deref())?;
                println!("vault key: {}", key.as_str());
                println!(
                    "words: {}",
                    varsto_core::recovery::words_from_key(&key)?.as_str()
                );
                println!(
                    "key check: {} (compare with the kit)",
                    varsto_core::recovery::key_check(&key)?
                );
            }
        },
        Cmd::Org { cmd } => run_org(cli, &home, cmd)?,
        Cmd::Analysis { cmd } => run_analysis(cli, &home, cmd)?,
        Cmd::Search {
            query,
            folder,
            tags,
        } => run_search(cli, &home, &query.join(" "), folder.as_deref(), tags)?,
        Cmd::Strongroom { uv, cmd } => {
            if *uv {
                std::env::set_var("VARSTO_FIDO2_UV", "1");
            }
            let mut engine = open_engine(&home)?;
            match cmd {
                StrongroomCmd::Create {
                    name,
                    path,
                    software,
                    minutes,
                } => {
                    let method = if *software {
                        software_key_warning()?;
                        varsto_core::strongroom::Method::Software
                    } else {
                        varsto_core::strongroom::Method::Fido2
                    };
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
                        .map(|(r, _)| r.folder_id.clone())
                        .ok_or_else(|| anyhow!("{folder} is not a Strongroom folder"))?;
                    eprintln!("First, open {folder} with a key that is enrolled already.");
                    let fk = engine.unlock_strongroom_enrolled(folder, 1)?;
                    let (method, backend): (Method, Box<dyn SecurityKey>) = if *software {
                        software_key_warning()?;
                        (Method::Software, strongroom::new_software_backend(&home))
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
                    let k = strongroom::enroll_key(
                        backend.as_ref(),
                        method,
                        engine.vault_id(),
                        &id,
                        &fk,
                        label,
                    )?;
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
                StrongroomCmd::Rekey { folder, minutes } => {
                    strongroom_rekey(&mut engine, &home, folder, *minutes)?
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
        Cmd::Transfers { watch } => transfers(&home, *watch, cli.json)?,
        Cmd::Activity { watch } => activity(&home, *watch, cli.json)?,
        // Counted by the running service; no passphrase needed.
        Cmd::P2p {
            cmd: P2pCmd::Traffic { watch },
        } => p2p_traffic(&home, *watch, cli.json)?,
        Cmd::P2p { cmd } => {
            // With the background service running, settings go through it:
            // it applies them (on and off at once), and its own copy of the
            // configuration does not overwrite them later.
            if let (
                Some((sf, _)),
                P2pCmd::Enable { .. } | P2pCmd::Disable | P2pCmd::PortMapping { .. },
            ) = (service::status(&home), cmd)
            {
                let body = match cmd {
                    P2pCmd::PortMapping { state } => {
                        serde_json::json!({"port_mapping": state == "on"})
                    }
                    P2pCmd::Enable {
                        port,
                        public_addrs,
                        stun,
                        no_stun,
                    } => {
                        let stun = if *no_stun {
                            String::new()
                        } else if stun.is_empty() {
                            varsto_core::vault::default_stun().join(",")
                        } else {
                            stun.join(",")
                        };
                        serde_json::json!({
                            "enabled": true,
                            "port": port,
                            "public_addrs": public_addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(","),
                            "stun": stun,
                        })
                    }
                    _ => serde_json::json!({"enabled": false}),
                };
                let url = format!("http://127.0.0.1:{}/api/p2p", sf.port);
                let r: serde_json::Value =
                    serde_json::from_str(&service::http_post(&url, &sf.token, &body.to_string())?)?;
                if let P2pCmd::PortMapping { state } = cmd {
                    println!(
                        "router port mapping is {state}{}",
                        if state == "on" {
                            " (the service asks the router now)"
                        } else {
                            " (the service removed its mappings)"
                        }
                    );
                } else {
                    println!("{}", r["note"].as_str().unwrap_or("saved"));
                }
                return Ok(());
            }
            let mut engine = open_engine(&home)?;
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
                        user_disabled: false,
                        port_mapping: engine.p2p_config().port_mapping,
                    })?;
                    let id = engine.p2p_identity()?;
                    println!(
                        "peer-to-peer is on (port {port}, certificate {}); the background service uses it when it starts",
                        &id.sha256[..16]
                    );
                }
                P2pCmd::Disable => {
                    let mut c = engine.p2p_config();
                    c.enabled = false;
                    c.user_disabled = true;
                    engine.set_p2p_config(c)?;
                    println!(
                        "peer-to-peer is off; the background service stays off it when it starts"
                    );
                }
                P2pCmd::PortMapping { state } => {
                    let mut c = engine.p2p_config();
                    c.port_mapping = state == "on";
                    engine.set_p2p_config(c)?;
                    println!(
                        "router port mapping is {state}; the background service applies it when it starts"
                    );
                }
                P2pCmd::Status => p2p_status(&engine, &home, cli.json)?,
                P2pCmd::Traffic { .. } => unreachable!("handled above"),
            }
        }
        Cmd::Policy { cmd } => {
            let mut engine = open_engine(&home)?;
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
                            rec.effective_policy()
                                .map(|p| p.describe()
                                    + if rec.policy.is_none() {
                                        " (default)"
                                    } else {
                                        ""
                                    })
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
        Cmd::Mcp { key_file, cmd } => match cmd.as_ref().unwrap_or(&McpCmd::Serve) {
            McpCmd::Serve => {
                let key = mcp_key_input(key_file.as_deref())?;
                mcp::serve(&home, key.as_deref().map(|k| k.as_str()))?
            }
            McpCmd::Key { cmd } => run_mcp_key(cli, &home, cmd)?,
            McpCmd::Config {
                client,
                create_key,
                key_name,
                folders,
                write,
                analyse,
                expires_days,
            } => {
                let secret = if *create_key {
                    let scope = mcp_keys::scope_for(&home, folders, *write, *analyse)?;
                    let (k, secret) =
                        mcp_keys::create(&home, key_name.as_deref(), scope, *expires_days)?;
                    eprintln!(
                        "created MCP key {} ({}); it is in the configuration below and is not shown again",
                        k.name, k.id
                    );
                    Some(secret)
                } else {
                    None
                };
                let custom_home = (default_home().ok().as_deref() != Some(home.as_path()))
                    .then_some(home.as_path());
                println!(
                    "{}",
                    mcp::client_config(client, secret.as_deref(), custom_home)?
                );
            }
            McpCmd::Grant {
                folder,
                write,
                analyse,
            } => {
                mcp::grant(&home, folder, *write, *analyse)?;
                println!(
                    "granted {} access to {folder} (recorded in {})",
                    if *write {
                        "read-write"
                    } else if *analyse {
                        "read and analyze"
                    } else {
                        "read-only"
                    },
                    mcp::grants_path(&home).display()
                );
            }
            McpCmd::Revoke { folder } => {
                mcp::revoke(&home, folder)?;
                println!("revoked {folder}");
            }
            McpCmd::List => {
                let g = mcp::Grants::load(&home)?;
                print(cli, &g, |g| {
                    let mut lines = Vec::new();
                    if let Some(all) = &g.all {
                        lines.push(format!(
                            "all folders (not Strongrooms): {all} ({})",
                            mcp::level_words(all)
                        ));
                    }
                    for (f, l) in &g.folders {
                        lines.push(format!("{f}: {l} ({})", mcp::level_words(l)));
                    }
                    if lines.is_empty() {
                        "no grants: the assistant sees nothing (varsto mcp grant <folder>)".into()
                    } else {
                        lines.join("\n")
                    }
                })?;
            }
        },
        Cmd::Update {
            daily: true, check, ..
        } => {
            let c = update::check_daily(&home)?;
            if *check {
                print(cli, &c, |c| {
                    if c.available {
                        format!(
                            "daily build available: {} -> {} ({})",
                            c.current_build.as_deref().unwrap_or("(a release)"),
                            c.latest_build,
                            c.archive.clone().unwrap_or_default()
                        )
                    } else if c.newer {
                        format!(
                            "daily build {} is out; this copy cannot install it itself ({}): download it from {}",
                            c.latest_build,
                            c.reason.as_deref().unwrap_or("no file for this platform"),
                            c.download_page
                        )
                    } else {
                        format!("up to date: daily build {}", c.latest_build)
                    }
                })?;
            } else {
                let policy = update::Policy::new(&home, false);
                let running = service::status(&home).is_some();
                println!("{}", update::apply_daily(&c, &policy)?);
                let installer = c.archive.as_deref() == Some(update::DAILY_SETUP);
                if c.available && running && !installer {
                    if service::restart_and_wait(&home) {
                        println!(
                            "the background service restarted with daily build {}",
                            c.latest_build
                        );
                    } else {
                        eprintln!("could not restart the background service: start it with `varsto service run` or `varsto install`");
                    }
                }
            }
        }
        Cmd::Update {
            check,
            allow_single_source,
            ..
        } => {
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
                    } else if c.newer {
                        format!(
                            "{} is out ({} installed); this build cannot update itself: download it from {}",
                            c.latest, c.current, c.download_page
                        )
                    } else {
                        format!("up to date: {} (latest {})", c.current, c.latest)
                    }
                })?;
                if !cli.json {
                    if let Some(h) = update::stable_hint(&home, &c) {
                        println!("{h}");
                    }
                }
            } else {
                let policy = update::Policy::new(&home, *allow_single_source);
                let running = service::status(&home).is_some();
                if let Some(h) = update::stable_hint(&home, &c) {
                    println!("{h}");
                    return Ok(());
                }
                println!("{}", update::apply(&c, &policy)?);
                // The Windows setup program restarts Varsto itself.
                if c.available && running && !c.installer() {
                    // The service runs the binary that was replaced: start it again.
                    if service::restart_and_wait(&home) {
                        println!("the background service restarted with {}", c.latest);
                    } else {
                        eprintln!("could not restart the background service: start it with `varsto service run` or `varsto install`");
                    }
                }
            }
        }
        Cmd::Config { key, value } => {
            match (key.as_deref(), value.as_deref()) {
                (None, _) | (Some("auto-update"), None) => {}
                (Some("auto-update"), Some(v)) => {
                    let on = match v {
                        "on" | "true" | "yes" | "1" => true,
                        "off" | "false" | "no" | "0" => false,
                        _ => bail!("auto-update takes on or off"),
                    };
                    update::set_auto_update(&home, on)?;
                }
                (Some(other), _) => bail!("unknown setting {other} (known: auto-update)"),
            }
            let on = update::auto_update_enabled(&home);
            let installs = update::can_install_by_itself();
            print(
                cli,
                &serde_json::json!({"auto-update": on, "installs-by-itself": installs}),
                |_| {
                    format!(
                        "auto-update: {} (looks for a new version once a day; {})",
                        if on { "on" } else { "off" },
                        if installs {
                            "installs it by itself after checking the signature"
                        } else {
                            "tells you when one is out"
                        }
                    )
                },
            )?;
        }
        Cmd::VerifyRelease {
            file,
            sums,
            sig,
            github,
        } => {
            let r = update::verify_release(file, sums.as_deref(), sig.as_deref(), *github)?;
            print(cli, &r, |r| {
                let what = match &r.sha256 {
                    Some(h) => format!("{} matches the signed checksum list (SHA-256 {h})", r.file),
                    None => format!("{} carries a valid signature", r.file),
                };
                format!(
                    "OK: {what}\nsigned by the Varsto release key {} ({}){}",
                    r.key_id,
                    r.signed.replace('\t', " "),
                    if r.github == Some(true) {
                        "\nthe GitHub release lists the same checksum"
                    } else {
                        ""
                    }
                )
            })?;
        }
        Cmd::Paths {
            notify,
            action,
            paths,
        } => {
            if *notify {
                filemanager::detach_own_console();
            }
            let title = if action == "fetch" {
                "Could not download"
            } else {
                "Could not free up space"
            };
            let results = match filemanager::run_paths(&home, action, paths, passphrase) {
                Ok(r) => r,
                Err(e) if *notify => {
                    filemanager::report_failure(&home, title, &format!("{e:#}"));
                    return Err(e);
                }
                Err(e) => return Err(e),
            };
            let failed = filemanager::failures(&results);
            print(cli, &results, |r| {
                r.iter()
                    .filter(|x| x["ok"] == serde_json::json!(true))
                    .map(|x| {
                        format!(
                            "{} {}",
                            if action == "fetch" {
                                "fetched"
                            } else {
                                "freed"
                            },
                            x["path"].as_str().unwrap_or("")
                        )
                    })
                    .chain(failed.iter().map(|f| format!("failed: {f}")))
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;
            if !failed.is_empty() {
                if *notify {
                    filemanager::report_failure(&home, title, &failed.join("\n"));
                }
                std::process::exit(1);
            }
        }
        Cmd::OpenLink { uri } => open_link(&home, uri)?,
        Cmd::OpenPlaceholder { path } => {
            use std::io::IsTerminal;
            let gui = filemanager::detach_own_console() || !std::io::stderr().is_terminal();
            match filemanager::open_placeholder(&home, path, passphrase) {
                Ok(real) => {
                    if !gui {
                        println!("opened {}", real.display());
                    }
                }
                Err(e) => {
                    if gui {
                        filemanager::report_failure(
                            &home,
                            "Could not open the file",
                            &format!("{e:#}"),
                        );
                    }
                    return Err(e);
                }
            }
        }
        Cmd::Ledger {
            cmd: Some(LedgerCmd::Status),
        } => {
            let mut engine = open_engine(&home)?;
            let r = engine.ledger_status(true)?;
            print(cli, &r, describe_ledger_status)?;
            if !r.health.is_ok() {
                std::process::exit(1);
            }
        }
        Cmd::Ledger {
            cmd:
                Some(LedgerCmd::Rebuild {
                    from_storage,
                    verify,
                    no_verify,
                    verify_budget_mib,
                    confirm_cold_read,
                }),
        } => {
            // A running, unlocked service owns the engine: it rebuilds (its
            // engine would not know of a rebuild made beside it).
            if let Some((f, _)) = service::status(&home) {
                let body = serde_json::json!({
                    "from_storage": from_storage,
                    "verify": if *verify { Some(true) } else if *no_verify { Some(false) } else { None },
                    "verify_budget_mib": verify_budget_mib,
                    "confirm_cold_read": confirm_cold_read,
                });
                let answer = service::http_post_within(
                    &format!("http://127.0.0.1:{}/api/ledger/rebuild", f.port),
                    &f.token,
                    &body.to_string(),
                    24 * 3600,
                );
                match answer {
                    Ok(t) => {
                        let r: varsto_core::engine::LedgerRebuildReport = serde_json::from_str(&t)?;
                        print(cli, &r, describe_rebuild)?;
                        if !r.health.is_ok() {
                            std::process::exit(1);
                        }
                        return Ok(());
                    }
                    // Locked or not answering: the rebuild runs here.
                    Err(e)
                        if format!("{e}").contains("vault is locked")
                            || !format!("{e}").contains("service answered") => {}
                    // The service refused (a fork, an unreachable storage).
                    Err(e) => {
                        let text = format!("{e}");
                        let msg = text
                            .split_once(": ")
                            .and_then(|(_, b)| serde_json::from_str::<serde_json::Value>(b).ok())
                            .and_then(|v| {
                                v.get("error").and_then(|x| x.as_str()).map(str::to_string)
                            })
                            .unwrap_or(text);
                        bail!("{msg}");
                    }
                }
            }
            let mut engine = Engine::open(&home, &passphrase()?)?;
            let opts = varsto_core::engine::LedgerRebuildOptions {
                from_storage: *from_storage,
                verify: if *verify {
                    Some(true)
                } else if *no_verify {
                    Some(false)
                } else {
                    None
                },
                verify_budget_bytes: verify_budget_mib.saturating_mul(1 << 20),
                confirm_cold_read: *confirm_cold_read,
                automatic: false,
            };
            let r = engine.ledger_rebuild(&opts)?;
            print(cli, &r, describe_rebuild)?;
            if !r.health.is_ok() {
                std::process::exit(1);
            }
        }
        Cmd::Ledger {
            cmd: Some(LedgerCmd::CleanJunk { yes }),
        } => {
            let mut engine = open_engine(&home)?;
            let r = engine.ledger_clean_junk(!*yes)?;
            print(cli, &r, |r| {
                let mut out = String::new();
                for j in &r.junk {
                    out += &format!("{} {j}\n", if r.dry_run { "junk" } else { "deleted" });
                }
                if r.junk.is_empty() {
                    out += "no junk under this device's ledger name\n";
                } else if r.dry_run {
                    out += "run again with --yes to delete these\n";
                }
                out += &format!("{} objects of this device verified and kept", r.genuine);
                out
            })?;
        }
        Cmd::Ledger { cmd: _ } => {
            let engine = open_engine(&home)?;
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

/// `varsto [--home DIR] [--json] --version` (or `-V`): the device directory
/// given on the command line, if any. `None` for any other command line.
fn version_request(args: &[String]) -> Option<Option<PathBuf>> {
    let mut home = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--version" | "-V" => return Some(home),
            "--home" => home = it.next().map(PathBuf::from),
            "--json" => {}
            a if a.starts_with("--home=") => home = Some(PathBuf::from(&a["--home=".len()..])),
            _ => return None,
        }
    }
    None
}

fn main() {
    // Launched from an app bundle or by double-click: no arguments (macOS may add
    // a -psn_ process serial number). Open the desktop interface.
    let mut args: Vec<String> = std::env::args()
        .filter(|a| !a.starts_with("-psn_"))
        .collect();
    if args.len() == 1 {
        // Linux: the first start of a downloaded binary installs it (binary on
        // PATH, service and tray at login, menu entry) and hands over to the
        // installed copy, so nobody has to run ./varsto from a folder again.
        #[cfg(target_os = "linux")]
        if !service::linux::running_installed() && std::env::var_os("VARSTO_NO_INSTALL").is_none() {
            if let Some(code) = first_start_install() {
                std::process::exit(code);
            }
        }
        args.push(if cfg!(any(target_os = "linux", target_os = "windows")) {
            "tray".to_string()
        } else {
            "desktop".to_string()
        });
    }
    if let Some(home) = version_request(&args) {
        // `--version` names the daily build of a copy installed from that channel.
        let note = home
            .or_else(|| std::env::var_os("VARSTO_HOME").map(PathBuf::from))
            .or_else(|| default_home().ok())
            .and_then(|h| update::channel_note(&h));
        match note {
            Some(n) => println!("varsto {} ({n})", env!("CARGO_PKG_VERSION")),
            None => println!("varsto {}", env!("CARGO_PKG_VERSION")),
        }
        return;
    }
    let cli = Cli::parse_from(args);
    init_logging(&cli);
    report_activity(&cli);
    let timer = varsto_core::logging::Timer::start();
    if let Err(e) = run(&cli).context("varsto") {
        log::error!(ms = timer.ms(); "command failed: {e:#}");
        varsto_core::logging::flush();
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
    log::debug!(ms = timer.ms(); "command done");
    after_command(&cli);
    varsto_core::logging::flush();
}

/// Start this process's debug log (`<home>/logs/varsto-<component>.log`)
/// and record what runs: the version and the arguments, with the values of
/// secret options left out.
fn init_logging(cli: &Cli) {
    let Ok(home) = home(cli) else { return };
    let service_run = matches!(
        cli.cmd,
        Cmd::Service {
            cmd: ServiceCmd::Run { .. }
        }
    );
    let desktop = matches!(cli.cmd, Cmd::Desktop { .. });
    let component = logcmd::component_for(
        service_run,
        desktop,
        matches!(cli.cmd, Cmd::Tray { .. }),
        matches!(cli.cmd, Cmd::Mcp { .. }),
    );
    // The service keeps writing notable events to stderr too (service.log).
    if let Err(e) = logcmd::init(
        &home,
        component,
        cli.log_level.as_deref(),
        service_run || desktop,
    ) {
        eprintln!("error: {e:#}");
        std::process::exit(2);
    }
    log::info!(
        version = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        home = home.display().to_string();
        "start: {}",
        loggable_args(std::env::args().skip(1))
    );
}

/// The command line with the values of secret options replaced.
fn loggable_args(args: impl Iterator<Item = String>) -> String {
    let secret = |a: &str| {
        let a = a.trim_start_matches('-').to_ascii_lowercase();
        [
            "key",
            "secret",
            "words",
            "passphrase",
            "password",
            "token",
            "pin",
            "code",
            "kit",
        ]
        .iter()
        .any(|w| a.contains(w))
            && !a.ends_with("key-id")
            && !a.ends_with("key-file")
    };
    let mut out: Vec<String> = Vec::new();
    let mut hide_next = false;
    for a in args {
        if hide_next {
            out.push(varsto_core::logging::REDACTED.to_string());
            hide_next = false;
            continue;
        }
        if a.starts_with("--") {
            if let Some((name, _)) = a.split_once('=') {
                if secret(name) {
                    out.push(format!("{name}={}", varsto_core::logging::REDACTED));
                    continue;
                }
            } else if secret(&a) {
                hide_next = true;
            }
        }
        out.push(a);
    }
    out.join(" ")
}

/// A command that runs a long operation itself (a disk check, a restore,
/// fsck) while the background service runs: its tasks go to the service
/// every second, which shows them and tells the other devices
/// (`varsto activity`). The service's own process needs none of this.
fn report_activity(cli: &Cli) {
    if matches!(
        cli.cmd,
        Cmd::Service {
            cmd: ServiceCmd::Run { .. }
        }
    ) {
        return;
    }
    let Ok(home) = home(cli) else { return };
    varsto_core::activity::spawn_reporter(move |tasks| {
        let Some(sf) = service::read_service_file(&home) else {
            return;
        };
        if sf.pid == std::process::id() {
            return;
        }
        let body = serde_json::json!({ "pid": std::process::id(), "tasks": tasks }).to_string();
        let _ = service::http_post_within(
            &format!("http://127.0.0.1:{}/api/activity/report", sf.port),
            &sf.token,
            &body,
            2,
        );
    });
}

/// After a successful command: a background service that is still locked is
/// unlocked with the passphrase just verified, and right after setting up a
/// vault on Linux the background service is installed, so syncing goes on
/// even for someone who only ever uses the command line.
fn after_command(cli: &Cli) {
    let Ok(home) = home(cli) else { return };
    let typed = TYPED.lock().unwrap().clone();
    let used = USED.lock().unwrap().clone();
    if let Some(pass) = &used {
        if service::unlock_running(&home, pass) {
            eprintln!("(the background service is unlocked too)");
        }
    }
    let setup = matches!(
        cli.cmd,
        Cmd::Init { .. }
            | Cmd::Join { .. }
            | Cmd::Pair {
                cmd: PairCmd::Join { .. }
            }
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::io::IsTerminal;
        // Background sync always runs once this computer holds a vault, also
        // for people who only use the command line: any command sets it up
        // when it is missing, until `varsto uninstall` turns it off. Only for
        // the user's own vault in a terminal: never for test homes
        // (--home / VARSTO_HOME) or scripts.
        let own = cli.home.is_none() && std::env::var_os("VARSTO_NO_INSTALL").is_none();
        let uninstalling = matches!(
            cli.cmd,
            Cmd::Uninstall
                | Cmd::Reset { .. }
                | Cmd::Service {
                    cmd: ServiceCmd::Uninstall | ServiceCmd::Run { .. }
                }
        );
        if own
            && !uninstalling
            && std::io::stdout().is_terminal()
            && home.join("vault.json").exists()
            && !service::opted_out(&home)
            && !service::login_service_installed()
        {
            match service::install(&home, 300) {
                Ok(report) => println!("Background sync is set up:\n{report}"),
                Err(e) => eprintln!(
                    "could not set up background sync ({e:#}); run `varsto install` later"
                ),
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::IsTerminal;
        let own = cli.home.is_none() && std::env::var_os("VARSTO_NO_INSTALL").is_none();
        if setup && own && std::io::stdin().is_terminal() {
            if let Some(pass) = &typed {
                print!("Remember the passphrase on this computer so background sync unlocks itself after a restart? [Y/n] ");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                let mut answer = String::new();
                let _ = std::io::stdin().read_line(&mut answer);
                if !answer.trim().to_lowercase().starts_with('n') {
                    match service::remember_passphrase(&home, pass) {
                        Ok(m) => println!("{m}"),
                        Err(e) => eprintln!("{e:#}; the background service waits to be unlocked (any varsto command that asks for the passphrase does it)"),
                    }
                }
            }
        }
    }
    let _ = setup;
}

fn ago(t: i64) -> String {
    let s = (chrono_now() - t).max(0);
    match s {
        0..=89 => "just now".into(),
        90..=5399 => format!("{} min ago", (s + 30) / 60),
        5400..=129_599 => format!("{} h ago", (s + 1800) / 3600),
        _ => format!("{} days ago", s / 86400),
    }
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// "background service: running (pid 4711), unlocked · last sync 3 min ago (…) · next in 2 min"
fn service_line(
    pid: Option<u32>,
    summary: Option<serde_json::Value>,
    state: Option<serde_json::Value>,
) -> String {
    let Some(pid) = pid else {
        return if cfg!(target_os = "linux") {
            "background service: not running (`varsto install` sets it up to sync in the background)".into()
        } else {
            "background service: not running".into()
        };
    };
    let mut parts = vec![format!("background service: running (pid {pid})")];
    let st = state.unwrap_or_default();
    if st.get("unlocked").and_then(|v| v.as_bool()) == Some(false) {
        parts.push(
            "LOCKED: give the passphrase to any varsto command, or `varsto service remember`"
                .into(),
        );
    }
    if let Some(v) = summary {
        if v.get("paused").and_then(|x| x.as_bool()) == Some(true) {
            parts.push("paused".into());
        }
        match v.get("last_sync_utc").and_then(|x| x.as_i64()) {
            Some(t) => {
                let result = v.get("last_result").and_then(|x| x.as_str()).unwrap_or("");
                parts.push(format!(
                    "last sync {}{}",
                    ago(t),
                    if result.is_empty() {
                        String::new()
                    } else {
                        format!(" ({result})")
                    }
                ));
            }
            None => parts.push("no sync yet".into()),
        }
        if let Some(e) = v
            .get("last_error")
            .and_then(|x| x.as_str())
            .filter(|e| !e.is_empty())
        {
            parts.push(format!("last error: {e}"));
        }
        if let Some(n) = v.get("next_sync_utc").and_then(|x| x.as_i64()) {
            parts.push(format!("next in {} s", (n - chrono_now()).max(0)));
        }
        if let Some(a) = v.get("auto_verify_text").and_then(|x| x.as_str()) {
            parts.push(a.to_string());
        }
        if let Some(a) = v.get("repair_text").and_then(|x| x.as_str()) {
            parts.push(a.to_string());
        }
        if let Some(a) = v.get("scrub_text").and_then(|x| x.as_str()) {
            parts.push(a.to_string());
        }
    }
    parts.join("\n  ")
}

/// The status as the service reports it (same lines as from the engine).
/// `ledger status` for people.
fn describe_ledger_status(r: &varsto_core::engine::LedgerStatus) -> String {
    let mut out = format!("ledger: {}\n", r.health.describe());
    for n in &r.health.notes {
        out += &format!("note: {n}\n");
    }
    for d in &r.devices {
        out += &format!(
            "{} {}{}{}{}: head #{}{}{}\n",
            &d.device[..8.min(d.device.len())],
            if d.name.is_empty() { "?" } else { &d.name },
            if d.this_device { " (this device)" } else { "" },
            if d.revoked { " (removed)" } else { "" },
            if d.forked { " FORKED" } else { "" },
            d.head,
            d.checkpoint
                .map(|c| format!(", checkpoint #{c}"))
                .unwrap_or_default(),
            if d.dropped > 0 {
                format!(", batches up to #{} dropped here", d.dropped)
            } else {
                String::new()
            }
        );
        for h in &d.held {
            let range = match (h.first, h.last) {
                (Some(f), Some(l)) => format!("{} batches #{f}..#{l}", h.batches),
                _ => "no batches".to_string(),
            };
            let cps = if h.checkpoints.is_empty() {
                String::new()
            } else {
                format!(
                    ", checkpoint {}",
                    h.checkpoints
                        .iter()
                        .map(|c| format!("#{c}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            match &h.error {
                Some(e) => out += &format!("  {}: not listed ({e})\n", h.place),
                None => {
                    out += &format!(
                        "  {}{}: {range}{cps}\n",
                        h.place,
                        if h.cold { " (cold)" } else { "" }
                    )
                }
            }
        }
    }
    out.trim_end().to_string()
}

/// `ledger rebuild` for people.
fn describe_rebuild(r: &varsto_core::engine::LedgerRebuildReport) -> String {
    let mut out = String::new();
    if !r.local.damaged.is_empty() {
        out += &format!(
            "local files set aside (unreadable): {}\n",
            r.local.damaged.join(", ")
        );
    }
    out += &if r.own_found_on_storages {
        format!(
            "this device's ledger: #{} before, #{} now ({} batches adopted from the storages{})\n",
            r.own_head_before,
            r.own_head_after,
            r.adopted_batches,
            r.adopted_checkpoint
                .map(|c| format!(", checkpoint #{c}"))
                .unwrap_or_default()
        )
    } else {
        "nothing of this device's ledger is on any storage\n".to_string()
    };
    if !r.discarded_unpublished.is_empty() {
        out += &format!(
            "batches never published set aside: {:?}; their {} events are signed again\n",
            r.discarded_unpublished, r.events_requeued
        );
    }
    out += &format!(
        "other devices: {} batches and {} checkpoints downloaded again\n",
        r.batches_pulled, r.checkpoints_pulled
    );
    if r.manifests_caught_up > 0 {
        out += &format!(
            "{} folders continue after a manifest this device published later\n",
            r.manifests_caught_up
        );
    }
    if r.reenrolled {
        out += "this device enrolled again under its name\n";
    }
    if let Some(s) = &r.from_storage {
        out += &format!(
            "from the storages: {} folders ({} manifests, {} snapshots), {} objects named, {} claims written ({} known already), {} verified ({}), {} not read, {} damaged (queued for repair), {} missing everywhere; listed {}{}\n",
            s.folders,
            s.manifests_read,
            s.snapshots_read,
            s.objects_mapped,
            s.claims_written,
            s.claims_known,
            s.objects_verified,
            fmt_bytes(s.bytes_verified),
            s.objects_unverified,
            s.objects_corrupt,
            s.objects_missing,
            s.storages_listed.join(", "),
            if s.storages_skipped_cold.is_empty() {
                String::new()
            } else {
                format!(
                    "; cold not read: {} (add --confirm-cold-read)",
                    s.storages_skipped_cold.join(", ")
                )
            }
        );
        if !s.folders_skipped.is_empty() {
            out += &format!(
                "folders skipped (locked): {}\n",
                s.folders_skipped.join(", ")
            );
        }
    }
    for n in &r.notes {
        out += &format!("note: {n}\n");
    }
    out += &format!("ledger: {}", r.health.describe());
    out
}

fn status_from_value(v: &serde_json::Value) -> String {
    let st = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let num = |x: &serde_json::Value, k: &str| x.get(k).and_then(|n| n.as_u64()).unwrap_or(0);
    let mut out = format!(
        "vault {} device {} ({}) format {} lamport {} batches {}\n",
        st("vault_id"),
        st("device_name"),
        st("device_id").chars().take(8).collect::<String>(),
        num(v, "format_version"),
        num(v, "lamport"),
        num(v, "ledger_batches")
    );
    let devices: Vec<String> = v
        .get("devices")
        .and_then(|d| d.as_object())
        .map(|m| {
            m.values()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    out += &format!("devices: {}\n", devices.join(", "));
    let storages: Vec<String> = v
        .get("storages")
        .and_then(|d| d.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.get("name").and_then(|n| n.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    out += &format!("storages: {}\n", storages.join(", "));
    for f in v
        .get("folders")
        .and_then(|d| d.as_array())
        .into_iter()
        .flatten()
    {
        let fs = |k: &str| f.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        out += &format!(
            "folder {} ({}): {} files, {} bytes, {} chunks, {} without storage copy, {} verified elsewhere, at {}\n",
            fs("name"),
            fs("folder_id").chars().take(8).collect::<String>(),
            num(f, "files"),
            num(f, "bytes"),
            num(f, "chunks"),
            num(f, "chunks_without_storage_copy"),
            num(f, "chunks_verified_elsewhere"),
            f.get("path").and_then(|p| p.as_str()).unwrap_or("(not attached)")
        );
        out += &folder_safety_lines(f);
    }
    if let Some(h) = v
        .get("ledger_health")
        .and_then(|h| serde_json::from_value::<varsto_core::engine::LedgerHealth>(h.clone()).ok())
    {
        out += &format!("ledger: {}\n", h.describe());
    }
    for w in v
        .get("recovery_warnings")
        .and_then(|w| w.as_array())
        .into_iter()
        .flatten()
        .filter_map(|w| w.as_str())
    {
        out += &format!("warning: {w}\n");
    }
    out.trim_end().to_string()
}

/// Install, then start the installed tray with the interface open. `None`
/// when installing failed (this copy then runs as before).
#[cfg(target_os = "linux")]
fn first_start_install() -> Option<i32> {
    let cli = Cli::parse_from(["varsto", "tray"]);
    let home = home(&cli).ok()?;
    match service::install(&home, 300) {
        Ok(report) => {
            println!("Varsto is installed:\n{report}\nFrom now on run `varsto` (or Varsto in the application menu).");
            let target = service::linux::installed_binary().ok()?;
            let started = std::process::Command::new(&target)
                .arg("--home")
                .arg(&home)
                .args(["tray", "--open"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            Some(if started.is_ok() { 0 } else { 1 })
        }
        Err(e) => {
            eprintln!("could not install Varsto ({e:#}); running this copy instead");
            None
        }
    }
}

/// `strongroom convert`: the security key is touched here; the conversion
/// itself runs in the background service when one is running (it owns the
/// folder state), otherwise in this process.
/// `--software`: refused in a binary built without the feature, and a
/// warning otherwise.
fn software_key_warning() -> Result<()> {
    if !varsto_core::strongroom::SOFTWARE_KEYS_BUILT_IN {
        bail!("software security keys are not built into this binary; they are for tests only (a build with the software-key feature has them)");
    }
    eprintln!("warning: --software keeps the secret in a file next to the vault; it demonstrates the flow and protects nothing beyond your passphrase");
    Ok(())
}

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
        let (fk, _) = strongroom::unlock_enrolled(home, engine.vault_id(), &id, &info)?;
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
            software_key_warning()?;
            Method::Software
        } else {
            Method::Fido2
        };
        let id = FolderId::random();
        let fk = SecretKey::random();
        let backend = strongroom::backend(&method, home);
        let info = strongroom::enroll(backend.as_ref(), method, engine.vault_id(), &id, &fk)?;
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

/// `strongroom rekey`: the security keys are touched here (unlock with the
/// current key, then one touch per enrolled key for the new wraps); the
/// re-encryption runs in the background service when one is running.
fn strongroom_rekey(
    engine: &mut Engine,
    home: &std::path::Path,
    folder: &str,
    minutes: u64,
) -> Result<()> {
    use varsto_core::crypto::SecretKey;
    use varsto_core::ids::FolderId;
    use varsto_core::strongroom;
    let (rec, _) = engine
        .folders()
        .into_iter()
        .find(|(r, _)| r.is_strongroom() && (r.name == folder || r.folder_id.as_str() == folder))
        .ok_or_else(|| anyhow!("{folder} is not a Strongroom folder"))?;
    let info = rec.strongroom.clone().expect("a Strongroom");
    eprintln!("Unlock {folder} with an enrolled key:");
    let vault_id = engine.vault_id().clone();
    let (old_key, _) = strongroom::unlock_enrolled(home, &vault_id, &rec.folder_id, &info)?;
    let (id, fk, new_info) = if let Some((id, new_info)) = engine.strongroom_conversion(folder) {
        eprintln!("Resuming the interrupted re-key of {folder}: touch an enrolled key again.");
        let (fk, _) = strongroom::unlock_enrolled(home, &vault_id, &id, &new_info)?;
        (id, fk, new_info)
    } else {
        let id = FolderId::random();
        let fk = SecretKey::random();
        eprintln!(
            "Wrapping the new key for every enrolled key ({}): touch each one when asked.",
            info.keys().len()
        );
        let new_info = strongroom::rewrap_enrolled(home, &vault_id, &id, &fk, &info)?;
        (id, fk, new_info)
    };
    eprintln!("Re-encrypting {folder} under the new key; this reads and uploads the whole folder.");
    let report = if let Some((sf, _)) = service::status(home) {
        let url = format!("http://127.0.0.1:{}/api/strongroom/rekey", sf.port);
        let body = serde_json::json!({"folder": folder, "folder_id": id.to_string(), "key_hex": fk.to_hex(), "old_key_hex": old_key.to_hex(), "info": new_info, "minutes": minutes}).to_string();
        serde_json::from_str(&service::http_call("POST", &url, &sf.token, Some(&body))?)?
    } else {
        engine.unlock_strongroom_with_key(folder, &old_key.to_hex(), minutes)?;
        serde_json::to_value(engine.rekey_strongroom_with(folder, &id, &fk, new_info, minutes)?)?
    };
    let report: serde_json::Value = report;
    println!(
        "{folder} has a new key ({} files re-encrypted, {} fetched to do it, {} blocks uploaded; {} old objects and {} old manifests deleted). Every enrolled security key opens it; other devices switch on their next sync.",
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
    Ok(())
}

/// `p2p traffic`: the running service's counters as a table, once or every
/// second. Only the service counts; without it there is nothing to show.
/// POST to the running service, unlocking it first with the passphrase when
/// it waits to be unlocked. None when no service runs for this home.
fn call_service(
    home: &std::path::Path,
    path: &str,
    body: serde_json::Value,
) -> Result<Option<serde_json::Value>> {
    let Some((sf, _)) = service::status(home) else {
        return Ok(None);
    };
    let url = format!("http://127.0.0.1:{}{path}", sf.port);
    let post = || service::http_post(&url, &sf.token, &body.to_string());
    let answer = match post() {
        Err(e) if format!("{e:#}").contains("locked") => {
            let pass = passphrase()?;
            if !service::unlock_running(home, &pass) {
                bail!("the background service could not be unlocked with that passphrase");
            }
            post()
        }
        other => other,
    };
    match answer {
        Ok(text) => Ok(Some(
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
        )),
        Err(e) => {
            // "service answered 400: {"error": "..."}": show the message itself.
            let msg = format!("{e:#}");
            let inner = msg
                .split_once(": ")
                .and_then(|(_, b)| serde_json::from_str::<serde_json::Value>(b).ok())
                .and_then(|v| v["error"].as_str().map(str::to_string));
            Err(anyhow!(inner.unwrap_or(msg)))
        }
    }
}

/// Folder commands that change what this device syncs, through the running
/// service. None: no service, or a command the service need not run.
/// The folder-safety commands (marker, held deletions, modes): through the
/// background service when it runs, else on this process's engine followed
/// by a sync of the folder. Returns false for other folder commands.
fn folder_safety_cmd(cli: &Cli, home: &std::path::Path, cmd: &FolderCmd) -> Result<bool> {
    let (name, action, extra) = match cmd {
        FolderCmd::RepairMarker { name } => (name, "repair-marker", serde_json::json!({})),
        FolderCmd::ConfirmDeletions { name, discard } => (
            name,
            if *discard {
                "discard-deletions"
            } else {
                "confirm-deletions"
            },
            serde_json::json!({}),
        ),
        FolderCmd::Mode { name, mode: None } => (name, "pending", serde_json::json!({})),
        FolderCmd::Mode {
            name,
            mode: Some(m),
        } => {
            let mode: varsto_core::vault::FolderMode = m.parse()?;
            (name, "mode", serde_json::json!({ "mode": mode }))
        }
        FolderCmd::Override { name } => (name, "override", serde_json::json!({})),
        FolderCmd::Revert { name } => (name, "revert", serde_json::json!({})),
        FolderCmd::Pending { name } => (name, "pending", serde_json::json!({})),
        FolderCmd::DeletionGuard {
            name,
            percent,
            min_files,
            max_files,
            off,
            default,
        } => {
            if percent.is_none() && min_files.is_none() && max_files.is_none() && !off && !default {
                (name, "pending", serde_json::json!({}))
            } else if *default {
                (name, "deletion-guard", serde_json::json!({ "guard": null }))
            } else {
                // Unnamed values keep the folder's current ones.
                let current = match call_service(
                    home,
                    "/api/folder/safety",
                    serde_json::json!({"folder": name, "action": "pending"}),
                )? {
                    Some(v) => serde_json::from_value(v["deletion_guard"].clone())?,
                    None => open_engine(home)?.folder_changes(name)?.deletion_guard,
                };
                let mut g: varsto_core::vault::DeletionGuard = current;
                g.enabled = !*off;
                if let Some(p) = percent {
                    g.percent = *p;
                }
                if let Some(n) = min_files {
                    g.min_files = *n;
                }
                if let Some(n) = max_files {
                    g.max_files = *n;
                }
                (name, "deletion-guard", serde_json::json!({ "guard": g }))
            }
        }
        _ => return Ok(false),
    };
    let mut body = extra;
    body["folder"] = serde_json::json!(name);
    body["action"] = serde_json::json!(action);
    let (out, via_service) = match call_service(home, "/api/folder/safety", body.clone())? {
        Some(v) => (v, true),
        None => {
            let mut engine = open_engine(home)?;
            let out = desktop::folder_safety_action(&mut engine, &body)?;
            // What changed is synced now (the service does it by itself).
            if action != "pending" {
                if let Ok(r) = engine.sync(Some(name)) {
                    if let Some(p) = r.first().and_then(|(pl, _)| pl.paused.as_ref()) {
                        eprintln!("{}", p.message);
                    }
                }
            }
            (out, false)
        }
    };
    let synced = if via_service {
        "; the background service syncs it now"
    } else {
        ""
    };
    print(cli, &out, |v| {
        let n = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        let list = |k: &str| -> Vec<String> {
            v.get(k)
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        match cmd {
            FolderCmd::RepairMarker { .. } => format!(
                "{name}: marker written at {}{synced}",
                v["path"].as_str().unwrap_or("")
            ),
            FolderCmd::ConfirmDeletions { discard: false, .. } => {
                format!("{name}: {} deletions confirmed{synced}", n("deleted"))
            }
            FolderCmd::ConfirmDeletions { discard: true, .. } => {
                let un = list("unavailable");
                let mut s = format!("{name}: {} files restored{synced}", n("restored"));
                if !un.is_empty() {
                    s += &format!(
                        "\n{} could not be restored now and stay held:\n  {}",
                        un.len(),
                        un.join("\n  ")
                    );
                }
                s
            }
            FolderCmd::Mode { mode: Some(_), .. } => {
                format!("{name}: {}{synced}", v["mode"].as_str().unwrap_or(""))
            }
            FolderCmd::Override { .. } => format!(
                "{name}: {} files now follow this device on every device{synced}",
                n("files")
            ),
            FolderCmd::Revert { .. } => {
                let un = list("unavailable");
                let mut s = format!(
                    "{name}: {} local changes reverted, {} local copies moved to the trash",
                    n("reverted"),
                    n("moved_to_trash")
                );
                if !un.is_empty() {
                    s += &format!(
                        "\n{} could not be fetched now:\n  {}",
                        un.len(),
                        un.join("\n  ")
                    );
                }
                s
            }
            FolderCmd::DeletionGuard { off, default, .. }
                if *off || *default || v.get("text").is_some() =>
            {
                format!(
                    "{name}: deletions are held when {}",
                    v["text"].as_str().unwrap_or("")
                )
            }
            _ => folder_changes_text(v),
        }
    })?;
    Ok(true)
}

/// `varsto folder pending` (and `mode`, `deletion-guard` without a value).
fn folder_changes_text(v: &serde_json::Value) -> String {
    let name = v["folder"].as_str().unwrap_or("");
    let guard: Option<varsto_core::vault::DeletionGuard> =
        serde_json::from_value(v["deletion_guard"].clone()).ok();
    let mut out = format!(
        "{name}: mode {}; deletions are held when {}\n",
        v["mode"].as_str().unwrap_or("normal"),
        guard.map(|g| g.describe()).unwrap_or_default()
    );
    if let Some(p) = v["paused"]["message"].as_str() {
        out += &format!("PAUSED: {p}\n");
    }
    let held: Vec<&str> = v["held_paths"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    if !held.is_empty() {
        out += &format!("held deletions ({}):\n", held.len());
        for p in held.iter().take(50) {
            out += &format!("  {p}\n");
        }
        if held.len() > 50 {
            out += &format!("  ... and {} more\n", held.len() - 50);
        }
    }
    for (key, title) in [
        ("local_changes", "local changes not published"),
        ("remote_not_applied", "remote changes not applied here"),
    ] {
        let rows: Vec<String> = v[key]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|c| {
                        format!(
                            "  {:<9} {}",
                            c["kind"].as_str().unwrap_or(""),
                            c["path"].as_str().unwrap_or("")
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        if !rows.is_empty() {
            out += &format!("{title} ({}):\n{}\n", rows.len(), rows.join("\n"));
        }
    }
    out.trim_end().to_string()
}

/// Mode, pause and waiting changes of a folder in status (a FolderStatus as JSON).
fn folder_safety_lines(f: &serde_json::Value) -> String {
    let name = f["name"].as_str().unwrap_or("");
    let mut out = String::new();
    if let Some(m) = f["mode"].as_str().filter(|m| *m != "normal") {
        out += &format!("  mode: {m}\n");
    }
    if let Some(p) = f["paused"]["message"].as_str() {
        out += &format!("  PAUSED: {p}\n");
    }
    let n = |k: &str| f[k].as_u64().unwrap_or(0);
    if n("remote_not_applied") > 0 {
        out += &format!(
            "  {} remote changes not applied here (`varsto folder override {name}` makes every device match this one)\n",
            n("remote_not_applied")
        );
    }
    if n("local_changes") > 0 {
        out += &format!(
            "  {} local changes not published (`varsto folder revert {name}` restores the vault's versions)\n",
            n("local_changes")
        );
    }
    out
}

fn folder_via_service(home: &std::path::Path, cmd: &FolderCmd) -> Result<Option<String>> {
    let abs = |p: &std::path::Path| -> Result<String> {
        Ok(std::path::absolute(p)?.display().to_string())
    };
    let (path, body) = match cmd {
        FolderCmd::Add {
            name,
            path,
            recovery_file,
        } => {
            // The service may hold the words already (`unlock
            // --with-recovery-key`); given here they are used for this folder.
            let words = f3cmd::recovery_words_given(recovery_file.as_deref())?;
            (
                "/api/folder",
                serde_json::json!({"name": name, "path": abs(path)?, "plain": true, "recovery_words": words.as_deref().map(|w| w.as_str())}),
            )
        }
        FolderCmd::Attach {
            name_or_id,
            path,
            selective,
            mode,
        } => (
            "/api/folder/attach",
            serde_json::json!({"name_or_id": name_or_id, "path": abs(path)?, "selective": selective, "plain": true, "mode": mode}),
        ),
        FolderCmd::Detach { name } => ("/api/folder/detach", serde_json::json!({"name": name})),
        FolderCmd::Remove {
            name, purge, yes, ..
        } => {
            if !*yes {
                return Ok(None); // the usual refusal below
            }
            (
                "/api/folder/remove",
                serde_json::json!({"name": name, "purge": purge}),
            )
        }
        FolderCmd::Selective { name_or_id, on } => (
            "/api/selective",
            serde_json::json!({"folder": name_or_id, "on": on}),
        ),
        FolderCmd::Set {
            folder,
            min_free: Some(min_free),
            permissions: None,
            symlinks: None,
            xattrs: None,
            ownership: None,
        } => {
            min_free_arg(min_free)?;
            (
                "/api/folder/min-free",
                serde_json::json!({"folder": folder, "min_free": min_free}),
            )
        }
        _ => return Ok(None),
    };
    let Some(r) = call_service(home, path, body)? else {
        return Ok(None);
    };
    let id = r["id"]
        .as_str()
        .map(|i| i.chars().take(8).collect::<String>())
        .unwrap_or_default();
    Ok(Some(match cmd {
        FolderCmd::Add { name, path, .. } => format!(
            "folder {name} ({id}) created at {}; the background service is syncing it",
            path.display()
        ),
        FolderCmd::Attach { path, .. } => format!(
            "folder {id} attached at {}; the background service is syncing it",
            path.display()
        ),
        FolderCmd::Detach { name } => {
            format!("{name} is no longer synced on this device; its files stay where they are")
        }
        FolderCmd::Remove { name, purge, .. } => format!(
            "{name} removed from the vault{}",
            if *purge {
                format!(
                    "; {} objects deleted from the storages",
                    r["objects_deleted"].as_u64().unwrap_or(0)
                )
            } else {
                String::new()
            }
        ),
        FolderCmd::Selective { name_or_id, on } => format!(
            "selective sync {} for {name_or_id}",
            if *on { "on" } else { "off" }
        ),
        FolderCmd::Set {
            folder,
            min_free: Some(min_free),
            ..
        } => format!(
            "{folder}: {} kept free on its disk here",
            min_free_text(min_free_arg(min_free)?)
        ),
        _ => String::new(),
    }))
}

fn transfers(home: &std::path::Path, watch: bool, json: bool) -> Result<()> {
    let sf = service::read_service_file(home).ok_or_else(|| {
        anyhow!("the background service is not running, so nothing is being transferred (start it with `varsto service run` or `varsto install`; `varsto service status` shows whether it runs)")
    })?;
    let base = format!("http://127.0.0.1:{}", sf.port);
    loop {
        let get = |path: &str| -> Result<serde_json::Value> {
            let body = service::http_get(&format!("{base}{path}"), &sf.token)
                .context("the background service did not answer; is it running?")?;
            Ok(serde_json::from_str(&body)?)
        };
        let progress = get("/api/progress")?;
        let traffic = get("/api/p2p/traffic")?;
        // The summary waits while a sync holds the engine: then say so.
        let summary = service::http_get_within(&format!("{base}/api/service"), &sf.token, 2)
            .ok()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok());
        if json {
            println!(
                "{}",
                serde_json::json!({"transfers": progress["transfers"], "service": summary, "p2p": traffic})
            );
        } else {
            if watch {
                print!("\x1b[H\x1b[2J");
            }
            let mut out = String::new();
            let list = progress["transfers"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if list.is_empty() {
                out.push_str("No file is being uploaded or downloaded right now.\n");
            } else {
                out.push_str(&format!(
                    "{:<9} {:>4}  {:>21}  {:>11}  file\n",
                    "", "%", "done / size", "speed"
                ));
                for t in &list {
                    let n = |k: &str| t[k].as_u64().unwrap_or(0);
                    out.push_str(&format!(
                        "{:<9} {:>3}%  {:>21}  {:>11}  {}/{}\n",
                        t["kind"].as_str().unwrap_or(""),
                        n("percent"),
                        format!("{} / {}", fmt_bytes(n("done")), fmt_bytes(n("total"))),
                        format!("{}/s", fmt_bytes(n("bytes_per_sec"))),
                        t["folder"].as_str().unwrap_or(""),
                        t["path"].as_str().unwrap_or(""),
                    ));
                }
            }
            let locked = service::http_get_within(&format!("{base}/api/state"), &sf.token, 2)
                .ok()
                .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
                .is_some_and(|v| v["has_vault"] == true && v["unlocked"] == false);
            if locked {
                out.push_str("Background sync: LOCKED, waiting for the passphrase; nothing syncs until any varsto command that uses it runs (or `varsto service remember` keeps it, in the keyring, with systemd-creds or in the kernel keyring)\n");
            }
            match &summary {
                Some(_) if locked => {}
                Some(s) => {
                    let paused = s["paused"].as_bool() == Some(true);
                    let last = s["last_sync_utc"]
                        .as_i64()
                        .map(ago)
                        .unwrap_or_else(|| "never".into());
                    out.push_str(&format!(
                        "Background sync: {}; last sync {last}{}\n",
                        if paused { "paused" } else { "on" },
                        s["last_result"]
                            .as_str()
                            .filter(|r| !r.is_empty())
                            .map(|r| format!(" ({r})"))
                            .unwrap_or_default(),
                    ));
                }
                None => out.push_str("Background sync: syncing now\n"),
            }
            if let Ok(r) =
                serde_json::from_value::<varsto_core::p2p::traffic::TrafficReport>(traffic)
            {
                let busy: Vec<_> = r
                    .peers
                    .iter()
                    .filter(|p| p.active > 0 || p.rx_bps > 0 || p.tx_bps > 0)
                    .collect();
                if busy.is_empty() {
                    out.push_str("Peers: no transfer with another device right now\n");
                } else {
                    for p in busy {
                        out.push_str(&format!(
                            "Peer {}: down {}/s, up {}/s, {} requests in flight ({})\n",
                            if p.name.is_empty() {
                                p.device.short().to_string()
                            } else {
                                p.name.clone()
                            },
                            fmt_bytes(p.rx_bps),
                            fmt_bytes(p.tx_bps),
                            p.active,
                            if p.path.is_empty() { "-" } else { &p.path },
                        ));
                    }
                }
            }
            print!("{out}");
        }
        if !watch {
            return Ok(());
        }
        use std::io::Write;
        std::io::stdout().flush()?;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// One task on one line: "checking the blocks of disk «Blue 4TB» 42%
/// (12.4 GB of 29.5 GB), 85.0 MB/s, ready in about 12 min".
fn activity_line(t: &varsto_core::activity::TaskView, now: i64) -> String {
    use varsto_core::activity::Unit;
    let mut out = varsto_core::activity::describe(t);
    let count = |n: u64| match t.unit {
        Unit::Bytes => fmt_bytes(n),
        Unit::Items => n.to_string(),
    };
    let noun = match t.unit {
        Unit::Bytes => String::new(),
        Unit::Items => format!(" {}", varsto_core::activity::item_noun(&t.kind)),
    };
    match t.percent {
        Some(p) => out.push_str(&format!(
            " {p}% ({} of {}{noun})",
            count(t.done),
            count(t.total)
        )),
        None if t.done > 0 => out.push_str(&format!(" ({}{noun} so far)", count(t.done))),
        None => {}
    }
    if t.rate > 0 {
        out.push_str(&match t.unit {
            Unit::Bytes => format!(", {}/s", fmt_bytes(t.rate)),
            Unit::Items => format!(", {}{noun}/s", t.rate),
        });
    }
    if let Some(eta) = t.eta_utc {
        let s = (eta - now).max(0);
        out.push_str(&match s {
            0..=59 => ", ready in less than a minute".to_string(),
            60..=5399 => format!(", ready in about {} min", (s + 30) / 60),
            _ => format!(", ready in about {:.1} h", s as f64 / 3600.0),
        });
    }
    out
}

fn activity(home: &std::path::Path, watch: bool, json: bool) -> Result<()> {
    use varsto_core::activity::{DeviceActivity, PeerActivity};
    let sf = service::read_service_file(home).ok_or_else(|| {
        anyhow!("the background service is not running; it is what knows and asks the other devices (start it with `varsto service run` or `varsto install`)")
    })?;
    let url = format!("http://127.0.0.1:{}/api/activity", sf.port);
    let get = || -> Result<serde_json::Value> {
        let body = service::http_get_within(&url, &sf.token, 5)
            .context("the background service did not answer; is it running?")?;
        Ok(serde_json::from_str(&body)?)
    };
    // The first question starts the service asking the peers: their
    // answers are there a moment later.
    let mut v = get()?;
    let pending = |v: &serde_json::Value| {
        v["peers"]
            .as_array()
            .is_some_and(|a| a.iter().any(|p| p["status"] == "pending"))
    };
    for _ in 0..6 {
        if !pending(&v) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        v = get()?;
    }
    loop {
        if json {
            println!("{v}");
        } else {
            if watch {
                print!("\x1b[H\x1b[2J");
            }
            let now = chrono_now();
            let me: Option<DeviceActivity> = serde_json::from_value(v["me"].clone()).ok();
            let peers: Vec<PeerActivity> =
                serde_json::from_value(v["peers"].clone()).unwrap_or_default();
            let mut out = String::new();
            let mut show = |name: &str, here: bool, a: Option<&DeviceActivity>, note: &str| {
                let who = if here {
                    format!("{name} (this device)")
                } else {
                    name.to_string()
                };
                match a {
                    Some(a) if !a.tasks.is_empty() => {
                        for t in &a.tasks {
                            out.push_str(&format!("{who}: {}{note}\n", activity_line(t, now)));
                        }
                    }
                    _ if !note.is_empty() => out.push_str(&format!("{who}:{note}\n")),
                    _ => out.push_str(&format!("{who}: idle\n")),
                }
            };
            if let Some(me) = &me {
                let name = if me.name.is_empty() {
                    "this device"
                } else {
                    &me.name
                };
                show(name, !me.name.is_empty(), Some(me), "");
            }
            for p in &peers {
                let name = if p.name.is_empty() {
                    p.device.chars().take(8).collect()
                } else {
                    p.name.clone()
                };
                let note = match p.status.as_str() {
                    "ok" if p.stale => format!(
                        " (as of {} s ago; not answering now)",
                        p.age_secs.unwrap_or(0)
                    ),
                    "ok" => String::new(),
                    "unreachable" if p.activity.is_some() => format!(
                        " (as of {} s ago; not reachable now)",
                        p.age_secs.unwrap_or(0)
                    ),
                    "unreachable" => " not reachable".into(),
                    "unsupported" => " runs an older version that does not tell".into(),
                    "refused" => " does not share its activity with this device".into(),
                    _ => " asking...".into(),
                };
                show(&name, false, p.activity.as_ref(), &note);
            }
            if peers.is_empty() {
                out.push_str("No other device is known to peer-to-peer (it starts with `varsto p2p enable` on each device).\n");
            }
            print!("{out}");
        }
        if !watch {
            return Ok(());
        }
        use std::io::Write;
        std::io::stdout().flush()?;
        std::thread::sleep(std::time::Duration::from_secs(2));
        v = get()?;
    }
}

fn p2p_traffic(home: &std::path::Path, watch: bool, json: bool) -> Result<()> {
    let sf = service::read_service_file(home).ok_or_else(|| {
        anyhow!("the background service is not running; traffic is counted by the service")
    })?;
    let url = format!("http://127.0.0.1:{}/api/p2p/traffic", sf.port);
    loop {
        let body = service::http_get(&url, &sf.token)
            .context("the background service did not answer; is it running?")?;
        if json {
            let v: serde_json::Value = serde_json::from_str(&body)?;
            println!("{v}");
        } else {
            let r: varsto_core::p2p::traffic::TrafficReport = serde_json::from_str(&body)?;
            if watch {
                print!("\x1b[H\x1b[2J"); // home and clear, like `watch`
            }
            print!("{}", traffic_table(&r));
        }
        if !watch {
            return Ok(());
        }
        use std::io::Write;
        std::io::stdout().flush()?;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn traffic_table(r: &varsto_core::p2p::traffic::TrafficReport) -> String {
    let rate = |b: u64| format!("{}/s", fmt_bytes(b));
    let ago = |t: Option<i64>| match t {
        None => "-".to_string(),
        Some(t) => match r.now_utc - t {
            s if s < 60 => format!("{}s ago", s.max(0)),
            s if s < 3600 => format!("{}m ago", s / 60),
            s => format!("{}h ago", s / 3600),
        },
    };
    let who = |name: &str, dev: &varsto_core::ids::DeviceId| {
        if name.is_empty() {
            dev.short().to_string()
        } else {
            name.to_string()
        }
    };
    let mut out = String::new();
    let t = &r.totals;
    match &r.device {
        Some(d) => out.push_str(&format!(
            "{} ({}): down {}, up {}, relayed {}; {} active; since the service started: {} down, {} up, {} relayed\n",
            who(&r.name, d),
            d.short(),
            rate(t.rx_bps),
            rate(t.tx_bps),
            rate(t.relay_bps),
            t.active,
            fmt_bytes(t.rx_total),
            fmt_bytes(t.tx_total),
            fmt_bytes(t.relay_total),
        )),
        None => out.push_str("peer-to-peer is not running in the service (enable it and restart the service)\n"),
    }
    if r.peers.is_empty() {
        out.push_str("no peers yet\n");
    } else {
        out.push_str(&format!(
            "{:<16} {:<22} {:<22} {:>11} {:>11} {:>10} {:>10} {:>9} {:>6}  {}\n",
            "DEVICE",
            "PATH",
            "ADDRESS",
            "DOWN",
            "UP",
            "DOWN TOTAL",
            "UP TOTAL",
            "OBJ IN/OUT",
            "ACTIVE",
            "LAST"
        ));
    }
    for p in &r.peers {
        out.push_str(&format!(
            "{:<16} {:<22} {:<22} {:>11} {:>11} {:>10} {:>10} {:>9} {:>6}  {}\n",
            who(&p.name, &p.device),
            if p.path.is_empty() { "-" } else { &p.path },
            p.addr.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
            rate(p.rx_bps),
            rate(p.tx_bps),
            fmt_bytes(p.rx_total),
            fmt_bytes(p.tx_total),
            format!("{}/{}", p.objects_in, p.objects_out),
            p.active,
            ago(p.last_seen_utc),
        ));
    }
    if !r.relays.is_empty() {
        out.push_str("relayed through this device:\n");
        for f in &r.relays {
            out.push_str(&format!(
                "  {} -> {}: {}, {} in {} objects, last {}\n",
                who(&f.from_name, &f.from),
                who(&f.to_name, &f.to),
                rate(f.bps),
                fmt_bytes(f.total),
                f.objects,
                ago(f.last_seen_utc),
            ));
        }
    }
    out
}

/// SIGTERM (systemd, launchd) and SIGINT (Ctrl-C) end the service loop the
/// way the interface's Quit does, so that what it set up outside this
/// computer (the router port mappings) is removed and the service file goes.
/// Should a long sync hold the loop, the process exits ten seconds later
/// regardless, as it did at once before.
#[cfg(unix)]
fn quit_on_signals() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SIGNALLED: AtomicBool = AtomicBool::new(false);
    extern "C" fn on_signal(_: libc::c_int) {
        SIGNALLED.store(true, Ordering::SeqCst);
    }
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
    let _ = std::thread::Builder::new()
        .name("signals".into())
        .spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_millis(200));
            if SIGNALLED.load(Ordering::SeqCst) {
                service::quit();
                std::thread::sleep(std::time::Duration::from_secs(10));
                std::process::exit(0);
            }
        });
}

#[cfg(not(unix))]
fn quit_on_signals() {}

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
        println!(
            "{}",
            v["portmap_text"]
                .as_str()
                .unwrap_or("router port mapping: not available")
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

    // The accepted peer records of the other devices, probed over TLS on
    // TCP with their pinned certificates.
    let records: Vec<varsto_core::p2p::PeerInfo> = engine
        .peer_directory()?
        .bodies()
        .map(|b| b.info())
        .collect();
    let probe = engine
        .p2p_peers_tcp()
        .map(|p| p.probe())
        .unwrap_or_default();
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
                "records": records
                    .iter()
                    .map(|r| serde_json::json!({
                        "device": r.device.to_string(),
                        "name": r.name,
                        "tcp": r.tcp,
                        "udp": r.udp,
                        "nat": r.nat,
                        "reachable": r.reachable,
                        "relay_via": r.relay_via.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
                    }))
                    .collect::<Vec<_>>(),
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
    println!("background service not running; probing over TLS on TCP from this command");
    println!(
        "router port mapping: {} (the background service asks the router when it runs)",
        if c.port_mapping { "on" } else { "off" }
    );
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
                    format!(
                        ", relays via {}",
                        plural(r.relay_via.len(), "device", "devices")
                    )
                }
            ))
            .unwrap_or_default()
        );
    }
    Ok(())
}

#[cfg(test)]
mod recovery_guide_tests {
    use super::*;
    use varsto_core::recovery_guide::{self as rg, Inputs};

    /// Split a shell line the way a POSIX shell would for the quoting the
    /// guide uses (double quotes with backslash escapes, single quotes).
    fn shell_words(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut any = false;
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    any = true;
                    while let Some(c) = chars.next() {
                        match c {
                            '"' => break,
                            '\\' => cur.extend(chars.next()),
                            c => cur.push(c),
                        }
                    }
                }
                '\'' => {
                    any = true;
                    for c in chars.by_ref() {
                        if c == '\'' {
                            break;
                        }
                        cur.push(c);
                    }
                }
                c if c.is_whitespace() => {
                    if any || !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                        any = false;
                    }
                }
                c => cur.push(c),
            }
        }
        if any || !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    fn pool(name: &str, copies: u32) -> StorageSpec {
        StorageSpec::Pool {
            name: name.into(),
            place: "offsite".into(),
            reserve_percent: 5,
            min_reserve_bytes: 0,
            disks: vec![],
            scan_roots: vec![],
            copies,
            verify_after_days: 180,
        }
    }

    fn every_kind() -> Inputs {
        Inputs {
            vault_id: "v".into(),
            device: "laptop".into(),
            other_devices: vec!["desk \"top\"".into()],
            storages: vec![
                StorageSpec::LocalDir {
                    name: "nas".into(),
                    path: "/mnt/nas/varsto".into(),
                    cold: false,
                    carrier: false,
                    place: String::new(),
                    min_free: None,
                },
                StorageSpec::LocalDir {
                    name: "stick".into(),
                    path: "/media/u/stick".into(),
                    cold: false,
                    carrier: true,
                    place: String::new(),
                    min_free: None,
                },
                StorageSpec::S3 {
                    name: "b2".into(),
                    endpoint: "https://s3.example".into(),
                    region: "eu".into(),
                    bucket: "bk".into(),
                    prefix: "p/x".into(),
                    access_key_id: "AKIA".into(),
                    secret_ref: String::new(),
                    path_style: false,
                    storage_class: Some("DEEP_ARCHIVE".into()),
                    cold: true,
                    place: "cloud".into(),
                    allow_insecure_http: false,
                },
                StorageSpec::S3 {
                    name: "hot bucket".into(),
                    endpoint: "https://s3.example".into(),
                    region: "eu".into(),
                    bucket: "hb".into(),
                    prefix: String::new(),
                    access_key_id: "AKIA".into(),
                    secret_ref: String::new(),
                    path_style: true,
                    storage_class: None,
                    cold: false,
                    place: String::new(),
                    allow_insecure_http: false,
                },
                StorageSpec::Rclone {
                    name: "drive".into(),
                    remote: "gdrive:v".into(),
                    cold: false,
                    place: "cloud".into(),
                },
                pool("shelf", 2),
            ],
            disk_conf: vec![("u1".into(), "shelf".into(), "Blue 4TB".into())],
            folders: vec![
                rg::FolderInput {
                    name: "docs".into(),
                    path: Some("/home/u/docs".into()),
                    selective: false,
                    strongroom: false,
                },
                rg::FolderInput {
                    name: "my $secret".into(),
                    path: None,
                    selective: true,
                    strongroom: true,
                },
            ],
            strongrooms: vec![rg::StrongroomInput {
                folder: "my $secret".into(),
                keys: vec!["blue".into()],
                software: false,
            }],
            backups: vec![rg::BackupInput {
                name: "home".into(),
                source: "/home/u".into(),
            }],
            org: Some(rg::OrgInput {
                name: "Acme".into(),
                admins: vec!["laptop".into()],
            }),
            restic: Some(rg::ResticInput {
                repository: "/srv/restic".into(),
                password: rg::ResticPassword::Command,
                env_file: None,
            }),
            ..Default::default()
        }
    }

    /// Every `varsto ...` line of a guide parses with this command line.
    fn assert_commands_parse(g: &rg::RecoveryGuide) -> usize {
        let mut n = 0;
        for step in g.steps.iter().chain(&g.alternatives) {
            for line in &step.commands {
                let words = shell_words(line);
                if words.first().map(String::as_str) != Some("varsto") {
                    continue;
                }
                if let Err(e) = Cli::try_parse_from(&words) {
                    panic!("`{line}` does not parse: {e}");
                }
                n += 1;
            }
        }
        n
    }

    #[test]
    fn guide_commands_parse_with_the_cli() {
        // `storage add-s3` takes the secret from this variable, as the guide says.
        std::env::set_var("VARSTO_S3_SECRET", "placeholder");
        let full = rg::build(&every_kind());
        let n = assert_commands_parse(&full);
        assert!(n >= 15, "only {n} commands");
        let joins: Vec<&String> = full
            .steps
            .iter()
            .flat_map(|s| &s.commands)
            .filter(|c| c.starts_with("varsto join"))
            .collect();
        assert_eq!(joins.len(), 1);
        assert!(
            joins[0].contains("--s3-bucket \"hb\""),
            "a hot bucket is joined through: {}",
            joins[0]
        );
        assert!(
            !full
                .steps
                .iter()
                .flat_map(|s| &s.commands)
                .any(|c| c.contains("stick")),
            "a transferrer is no recovery source"
        );
        assert!(full
            .steps
            .iter()
            .flat_map(|s| &s.commands)
            .any(|c| c.contains("strongroom unlock \"my \\$secret\"")));

        // Joining through a directory, and with only an rclone remote.
        let mut local = every_kind();
        local
            .storages
            .retain(|s| !matches!(s, StorageSpec::S3 { .. }));
        let g = rg::build(&local);
        assert_commands_parse(&g);
        assert!(g
            .steps
            .iter()
            .flat_map(|s| &s.commands)
            .any(|c| c.starts_with("varsto join")
                && c.contains("--storage-path \"/mnt/nas/varsto\"")));
        let mut rclone_only = every_kind();
        rclone_only
            .storages
            .retain(|s| matches!(s, StorageSpec::Rclone { .. }));
        let g = rg::build(&rclone_only);
        assert_commands_parse(&g);
        assert!(g
            .steps
            .iter()
            .flat_map(|s| &s.commands)
            .any(|c| c.starts_with("rclone mount")));
        let member = rg::build(&Inputs {
            member: true,
            ..every_kind()
        });
        assert_commands_parse(&member);
    }

    #[test]
    fn recovery_guide_command_parses() {
        for args in [
            vec!["varsto", "recovery", "guide"],
            vec!["varsto", "recovery", "guide", "--format", "markdown"],
            vec![
                "varsto", "recovery", "guide", "--format", "html", "--output", "g.html",
            ],
        ] {
            Cli::try_parse_from(args).unwrap();
        }
        assert!(Cli::try_parse_from(["varsto", "recovery", "guide", "--format", "pdf"]).is_err());
    }
}

#[cfg(test)]
mod secret_input_tests {
    use super::*;

    #[test]
    fn the_vault_key_is_hex_or_words() {
        let hex = "ab".repeat(32);
        assert_eq!(&*vault_key_from_text(&format!(" {hex}\n")).unwrap(), &hex);
        assert_eq!(&*vault_key_from_text(&hex.to_uppercase()).unwrap(), &hex);
        let words = varsto_core::recovery::words_from_key(&hex).unwrap();
        assert_eq!(&*vault_key_from_text(&words).unwrap(), &hex);
        assert!(vault_key_from_text("not a key").is_err());
        assert!(vault_key_from_text(&hex[..62]).is_err());
    }

    #[test]
    fn secrets_come_from_files_and_shares_from_lines() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("secret");
        std::fs::write(&f, "  hunter2-hunter2\n").unwrap();
        let s = secret_input(Some(&f), "VARSTO_TEST_NO_SUCH_VARIABLE", "x: ", false).unwrap();
        assert_eq!(&*s, "hunter2-hunter2");
        std::fs::write(&f, "\n\n").unwrap();
        assert!(secret_input(Some(&f), "VARSTO_TEST_NO_SUCH_VARIABLE", "x: ", false).is_err());
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, "1: one two\n\n2: three four\n").unwrap();
        std::fs::write(&b, "3: five six\n").unwrap();
        let lines = secret_lines(&[a, b], "share: ").unwrap();
        let lines: Vec<&str> = lines.iter().map(|l| l.as_str()).collect();
        assert_eq!(lines, ["1: one two", "2: three four", "3: five six"]);
    }
}

#[cfg(test)]
mod update_flag_tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("varsto").chain(args.iter().copied()))
    }

    #[test]
    fn update_takes_daily_or_stable_but_not_both() {
        let cli = parse(&["update", "--daily"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Update {
                daily: true,
                stable: false,
                check: false,
                ..
            }
        ));
        let cli = parse(&["update", "--check", "--daily"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Update {
                daily: true,
                check: true,
                ..
            }
        ));
        let cli = parse(&["update", "--stable"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Update {
                stable: true,
                daily: false,
                ..
            }
        ));
        // The plain command is the stable channel.
        let cli = parse(&["update"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Update {
                daily: false,
                stable: false,
                ..
            }
        ));
        assert!(parse(&["update", "--daily", "--stable"]).is_err());
        assert!(parse(&["update", "--stable", "--daily"]).is_err());
    }

    #[test]
    fn version_names_the_daily_build() {
        let a = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };
        assert_eq!(version_request(&a(&["varsto", "--version"])), Some(None));
        assert_eq!(version_request(&a(&["varsto", "-V"])), Some(None));
        assert_eq!(
            version_request(&a(&["varsto", "--home", "/x", "--version"])),
            Some(Some(PathBuf::from("/x")))
        );
        assert_eq!(
            version_request(&a(&["varsto", "--home=/y", "--json", "-V"])),
            Some(Some(PathBuf::from("/y")))
        );
        assert_eq!(version_request(&a(&["varsto", "status"])), None);
        assert_eq!(
            version_request(&a(&["varsto", "update", "--version"])),
            None
        );
        assert_eq!(version_request(&a(&["varsto"])), None);
    }
}
