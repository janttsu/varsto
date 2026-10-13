// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The Help page: where this device stands, where the vault's data is, what
//! needs attention and what to do next, in that order.
//!
//! [`build`] is pure: it takes [`Inputs`] (gathered cheaply by
//! `Engine::help_inputs` from the configuration, the ledger view and the
//! folder states, plus what the background service already knows) and
//! chooses the next steps by fixed rules, most urgent first. Nothing here
//! lists a storage, opens a network connection or reads a secret.
//!
//! Every sentence is a [`Text`] like the recovery guide's: an English
//! template with `{name}` placeholders and their values. The interface
//! translates the template (the English string is the key of
//! `ui/i18n/<lang>.json`) and puts the values in as they are; the command
//! line prints them in English ([`render_text`], `varsto help-now`).

use crate::policy::PolicyState;
use crate::recovery_guide::{wrap, Text};
use crate::util::human_bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The documentation on the website, linked from the guides.
pub const DOCS: &str = "https://varsto.net/docs";

/// Free space on this device's disk below which the Help page warns.
pub const LOW_FREE_BYTES: u64 = 2_000_000_000;
/// ... or below this share of the disk.
pub const LOW_FREE_PERCENT: u64 = 5;

fn tx(t: &str, p: &[(&str, String)]) -> Text {
    Text {
        t: t.to_string(),
        p: p.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
    }
}

fn t0(t: &str) -> Text {
    tx(t, &[])
}

/// Names joined for a sentence ("a, b and c" is left to the reader: commas).
fn names(list: &[String]) -> String {
    list.join(", ")
}

/// A name quoted for a shell line when it needs it.
fn sh(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:@".contains(c))
    {
        s.to_string()
    } else {
        format!(
            "\"{}\"",
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('$', "\\$")
                .replace('`', "\\`")
        )
    }
}

// ----- inputs ----------------------------------------------------------------

/// Where this device is in its life: no vault yet, a vault that is locked,
/// or an open vault.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    #[default]
    NoVault,
    Locked,
    Ready,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::NoVault => "no_vault",
            Phase::Locked => "locked",
            Phase::Ready => "ready",
        }
    }
}

/// The recovery kit (the vault key as 24 words) as this device knows it.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kit {
    #[default]
    NotPrinted,
    /// Printed before the vault key changed (a device was removed).
    Outdated,
    Printed,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StorageIn {
    pub name: String,
    /// "directory", "s3", "rclone", "pool", "transferrer".
    pub kind: String,
    pub place: String,
    pub cold: bool,
    pub carrier: bool,
    /// Bytes of current files the ledger records there.
    pub bytes: u64,
    pub quota_bytes: Option<u64>,
    pub quota_percent: Option<u32>,
    /// "none", "ok", "warning" or "full".
    pub quota_state: String,
    /// "draining", "blocked" or "drained" while a drain runs.
    pub drain: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FolderIn {
    pub name: String,
    /// Synced into a directory on this device.
    pub attached: bool,
    pub files: u64,
    pub bytes: u64,
    /// Bytes with no kept copy on any storage yet.
    pub unkept_bytes: u64,
    /// Bytes per storage name.
    pub storages: BTreeMap<String, u64>,
    /// Names of the devices holding its files.
    pub devices: Vec<String>,
    pub strongroom: bool,
    pub shared: bool,
    pub policy: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskIn {
    pub label: String,
    pub pool: String,
    pub place: String,
    pub attached: bool,
    pub retired: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BackupIn {
    pub name: String,
    pub snapshots: u64,
    pub latest_bytes: u64,
    pub latest_utc: Option<i64>,
    /// This device takes its snapshots.
    pub this_device: bool,
    pub stopped: bool,
    /// The last scheduled snapshot failed (from the service).
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyIn {
    pub folder: String,
    pub state: PolicyState,
    pub min_copies: u32,
    pub chunks_short_of_copies: u64,
    /// Places that lack copies.
    pub short_places: Vec<String>,
    pub chunks_unverified: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceIn {
    pub running: bool,
    pub paused: bool,
    pub last_error: Option<String>,
    pub p2p_listening: bool,
    pub p2p_reachable: bool,
    pub peers: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OrgIn {
    pub name: String,
    pub admin: bool,
    /// The organization's roster lists this device.
    pub listed: bool,
    /// Devices waiting for an administrator's approval.
    pub pending: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inputs {
    pub phase: Phase,
    pub device: String,
    pub now_utc: i64,
    /// This device holds only folders someone else shared with it.
    pub member: bool,
    /// Another device removed this one from the vault.
    pub removed: bool,
    /// The ledger saw two devices writing as one.
    pub forked: bool,
    /// The other devices of the vault (not removed).
    pub other_devices: Vec<String>,
    pub replicas: usize,
    pub storages: Vec<StorageIn>,
    pub folders: Vec<FolderIn>,
    /// Bytes of current files and bytes by kept copies (0, 1, 2, 3+).
    pub total_bytes: u64,
    pub copies_bytes: [u64; 4],
    pub disks: Vec<DiskIn>,
    /// Labels of disks away with copies overdue for a check.
    pub disks_overdue: Vec<String>,
    /// The disk worth docking next.
    pub disk_next: Option<String>,
    pub trash_entries: u64,
    pub trash_bytes: u64,
    pub trash_days: u32,
    pub backups: Vec<BackupIn>,
    /// Restic mirror set up on this device, and its last result.
    pub restic: bool,
    pub restic_text: Option<String>,
    pub policies: Vec<PolicyIn>,
    /// What is wrong with the ledger and what to run, when something is.
    pub ledger_problem: Option<String>,
    pub ledger_command: Option<String>,
    pub repair_queued: u64,
    pub repair_losses: u64,
    pub scrub_damaged: u64,
    pub kit: Kit,
    pub kit_printed_utc: Option<i64>,
    pub org: Option<OrgIn>,
    /// What the background service knows; `None` when it is not consulted.
    pub service: Option<ServiceIn>,
    /// Free and total bytes of the disk holding this device's directory.
    pub home_space: Option<(u64, u64)>,
    /// MCP access was set up (grants or keys).
    pub mcp_used: bool,
    /// Storages at their quota during the last sync (from the service).
    pub quota_full: Vec<String>,
}

// ----- output ----------------------------------------------------------------

/// Where a button takes the user: a page of the interface and, optionally,
/// what to open or show there (an element, a form or a dialog).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Action {
    /// "setup", "unlock", or an app page: overview, files, storages, ...
    pub page: String,
    /// An element id on that page, or a named dialog ("addfolder", "kit", "do:sync").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The button's text.
    pub label: Text,
}

/// One thing to do next.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HelpStep {
    /// Stable ("add_storage", "policy:docs", ...).
    pub id: String,
    /// "urgent" (data at risk or something broken), "important" (setup not
    /// finished), "suggested" (makes the vault safer), "tip".
    pub level: String,
    pub title: Text,
    pub why: Text,
    #[serde(default)]
    pub how: Vec<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    /// The same on the command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The guide topic that explains more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guide: Option<String>,
}

/// Something that needs attention, as one sentence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attention {
    pub id: String,
    /// "bad", "warn" or "info".
    pub level: String,
    pub text: Text,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Figures {
    /// Devices of the vault, this one included.
    pub devices: usize,
    pub storages: usize,
    pub folders: usize,
    pub files: u64,
    pub bytes: u64,
    /// Bytes with at least one kept copy on a storage.
    pub kept_bytes: u64,
    /// Bytes with two or more kept copies.
    pub two_plus_bytes: u64,
    pub unkept_bytes: u64,
    /// A storage outside the home holds data (cloud, offsite, ...).
    pub offsite: bool,
    pub disks: usize,
    pub disks_away: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamedBytes {
    pub name: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct FolderPlace {
    pub name: String,
    pub attached: bool,
    pub files: u64,
    pub bytes: u64,
    pub unkept_bytes: u64,
    /// Largest first.
    pub storages: Vec<NamedBytes>,
    pub devices: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyState>,
    /// One line about the folder.
    pub line: Text,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct StoragePlace {
    pub name: String,
    pub kind: String,
    pub place: String,
    pub cold: bool,
    pub carrier: bool,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_percent: Option<u32>,
    pub quota_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain: Option<String>,
    pub line: Text,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct HelpState {
    /// "no_vault", "locked" or "ready".
    pub phase: String,
    pub generated_utc: i64,
    pub device: String,
    /// The situation in one sentence.
    pub headline: Text,
    /// A few lines: devices, storages, folders, copies.
    pub summary: Vec<Text>,
    pub figures: Figures,
    pub folders: Vec<FolderPlace>,
    pub storages: Vec<StoragePlace>,
    pub disks: Vec<DiskIn>,
    /// Trash, backups, restic, disks: one line each.
    pub details: Vec<Text>,
    pub attention: Vec<Attention>,
    /// Most urgent first.
    pub steps: Vec<HelpStep>,
    /// Features not used yet, when nothing else needs doing.
    pub tips: Vec<HelpStep>,
    /// Nothing urgent or important to do.
    pub all_ok: bool,
}

// ----- rules -----------------------------------------------------------------

struct StepB(HelpStep);

impl StepB {
    fn new(id: &str, level: &str, title: Text, why: Text) -> Self {
        StepB(HelpStep {
            id: id.to_string(),
            level: level.to_string(),
            title,
            why,
            how: Vec::new(),
            action: None,
            command: None,
            guide: None,
        })
    }
    fn how(mut self, t: Text) -> Self {
        self.0.how.push(t);
        self
    }
    fn act(mut self, page: &str, target: Option<&str>, label: &str) -> Self {
        self.0.action = Some(Action {
            page: page.to_string(),
            target: target.map(str::to_string),
            label: t0(label),
        });
        self
    }
    fn cmd(mut self, c: impl Into<String>) -> Self {
        self.0.command = Some(c.into());
        self
    }
    fn guide(mut self, g: &str) -> Self {
        self.0.guide = Some(g.to_string());
        self
    }
}

fn level_rank(level: &str) -> u8 {
    match level {
        "urgent" => 0,
        "important" => 1,
        "suggested" => 2,
        _ => 3,
    }
}

fn fg_unkept_zero(h: &HelpState) -> bool {
    h.figures.unkept_bytes == 0
}

/// A storage's place as policies see it ("home" when none was given).
fn place_of(s: &StorageIn) -> &str {
    if s.place.is_empty() {
        "home"
    } else {
        s.place.as_str()
    }
}

fn is_home(place: &str) -> bool {
    place.is_empty() || place == "home"
}

/// The Help page's content for these inputs.
pub fn build(i: &Inputs) -> HelpState {
    let mut h = HelpState {
        phase: i.phase.as_str().to_string(),
        generated_utc: i.now_utc,
        device: i.device.clone(),
        ..Default::default()
    };
    match i.phase {
        Phase::NoVault => no_vault(&mut h),
        Phase::Locked => locked(&mut h, i),
        Phase::Ready => ready(&mut h, i),
    }
    h.all_ok = !h
        .steps
        .iter()
        .any(|s| s.level == "urgent" || s.level == "important");
    h
}

fn no_vault(h: &mut HelpState) {
    h.headline = t0("This device has no vault yet. Start here.");
    h.summary = vec![
        t0("A vault holds your folders, the list of your devices and the storages where encrypted copies of your files are kept."),
        t0("Nothing has been stored or sent anywhere yet."),
    ];
    h.steps.push(
        StepB::new(
            "create_vault",
            "important",
            t0("Create a vault, if this is your first device with Varsto"),
            t0("Every device, folder and storage belongs to a vault. This device becomes its first device."),
        )
        .how(t0("Give this device a name and a passphrase. The passphrase opens the vault on this device only."))
        .how(t0("Varsto then shows the vault key once. Write it down and keep it offline: it is the only way to recover your files if every device is lost."))
        .how(t0("Next you add a storage and a folder; this page tells you how."))
        .act("setup", Some("init"), "Create a vault")
        .cmd("varsto init --name <this device's name>")
        .guide("start")
        .0,
    );
    h.steps.push(
        StepB::new(
            "pair_device",
            "important",
            t0("Or add this device to the vault you already have"),
            t0("If Varsto already runs on another device of yours, this device joins that vault and gets its folders and storages."),
        )
        .how(t0("On the other device, open Peers and choose Add a device. It shows a nine-digit code."))
        .how(t0("Type the code here, with a name and a passphrase for this device."))
        .how(t0("No other device at hand? Join with the vault key (the 24 recovery words) and a storage that holds the vault."))
        .act("setup", Some("pair"), "Pair with a code")
        .cmd("varsto pair join --code <the nine digits>")
        .guide("devices")
        .0,
    );
    h.tips.push(
        StepB::new(
            "accept_share",
            "tip",
            t0("Someone shared a folder with you?"),
            t0("You can use only that folder without a vault of your own."),
        )
        .how(t0("Choose Accept a shared folder, send the owner your request code and paste the token they send back."))
        .act("setup", Some("acceptshare"), "Accept a shared folder")
        .guide("sharing")
        .0,
    );
}

fn locked(h: &mut HelpState, i: &Inputs) {
    h.headline = tx(
        "The vault on this device ({device}) is locked.",
        &[("device", i.device.clone())],
    );
    h.summary = vec![
        t0("Your files are safe, but this device does not sync and this page cannot show where your data is until the vault is unlocked."),
    ];
    h.steps.push(
        StepB::new(
            "unlock",
            "important",
            t0("Unlock the vault"),
            t0("Syncing, the file list and this page's overview need the vault open."),
        )
        .how(t0("Type the passphrase of this device. It is the one you chose when you created or joined the vault on this device."))
        .how(t0("Forgot it? The vault key (the 24 recovery words) lets you join again: reset this device under Settings and join with the words."))
        .act("unlock", Some("unlockform"), "Unlock")
        .guide("recovery")
        .0,
    );
}

fn ready(h: &mut HelpState, i: &Inputs) {
    let storages: Vec<&StorageIn> = i.storages.iter().filter(|s| !s.carrier).collect();
    let files: u64 = i.folders.iter().map(|f| f.files).sum();
    let unkept: u64 = i.folders.iter().map(|f| f.unkept_bytes).sum();
    let offsite = storages.iter().any(|s| !is_home(&s.place) && s.bytes > 0);
    let offsite_configured = storages.iter().any(|s| !is_home(&s.place));
    h.figures = Figures {
        devices: i.other_devices.len() + 1,
        storages: storages.len(),
        folders: i.folders.len(),
        files,
        bytes: i.total_bytes,
        kept_bytes: i.total_bytes.saturating_sub(i.copies_bytes[0]),
        two_plus_bytes: i.copies_bytes[2] + i.copies_bytes[3],
        unkept_bytes: unkept,
        offsite,
        disks: i.disks.iter().filter(|d| !d.retired).count(),
        disks_away: i.disks.iter().filter(|d| !d.retired && !d.attached).count(),
    };
    let fg = h.figures.clone();
    situation(h, i, &storages, &fg);
    attention(h, i, &storages);
    steps(h, i, &storages, offsite_configured);
    // Most urgent first; the rules' order stays within a level.
    h.steps.sort_by_key(|s| level_rank(&s.level));
    let bad = h.attention.iter().filter(|a| a.level == "bad").count();
    if bad > 0 && !storages.is_empty() && !i.folders.is_empty() && fg_unkept_zero(h) {
        h.headline = tx(
            "Your files are kept in {storages} storage(s), but {count} thing(s) need your attention.",
            &[
                ("storages", storages.len().to_string()),
                ("count", bad.to_string()),
            ],
        );
    }
}

/// "Where you are now": the headline, the summary lines, folders and storages.
fn situation(h: &mut HelpState, i: &Inputs, storages: &[&StorageIn], fg: &Figures) {
    h.headline = if i.member {
        tx(
            "This device ({device}) uses folders that someone else shared with you.",
            &[("device", i.device.clone())],
        )
    } else if storages.is_empty() && i.folders.is_empty() {
        t0("Your vault is ready, but it has no storage and no folder yet.")
    } else if storages.is_empty() {
        t0("Your files are only on this device: the vault has no storage yet.")
    } else if i.folders.is_empty() {
        t0("Your vault has a storage but no folder yet: nothing is synced.")
    } else if fg.unkept_bytes > 0 {
        tx(
            "{size} of your files have no copy on a storage yet.",
            &[("size", human_bytes(fg.unkept_bytes))],
        )
    } else {
        tx(
            "Your files are kept in {storages} storage(s) and on {devices} device(s).",
            &[
                ("storages", storages.len().to_string()),
                ("devices", fg.devices.to_string()),
            ],
        )
    };
    let mut s = Vec::new();
    s.push(if i.other_devices.is_empty() {
        tx(
            "Devices: this one ({device}) only.",
            &[("device", i.device.clone())],
        )
    } else {
        tx(
            "Devices: this one ({device}) and {others}.",
            &[
                ("device", i.device.clone()),
                ("others", names(&i.other_devices)),
            ],
        )
    });
    s.push(if storages.is_empty() {
        t0("Storages: none yet.")
    } else {
        tx(
            "Storages: {names}.",
            &[(
                "names",
                names(&storages.iter().map(|s| s.name.clone()).collect::<Vec<_>>()),
            )],
        )
    });
    s.push(if i.folders.is_empty() {
        t0("Folders: none yet.")
    } else {
        tx(
            "Folders: {count}. Files: {files}, {size} in all.",
            &[
                ("count", i.folders.len().to_string()),
                ("files", fg.files.to_string()),
                ("size", human_bytes(fg.bytes)),
            ],
        )
    });
    if fg.bytes > 0 {
        s.push(tx(
            "On at least one storage: {kept} of {total}. On two or more: {two}.",
            &[
                ("kept", human_bytes(fg.kept_bytes)),
                ("total", human_bytes(fg.bytes)),
                ("two", human_bytes(fg.two_plus_bytes)),
            ],
        ));
        s.push(if fg.offsite {
            t0("A copy is kept outside your home (in the cloud or another place).")
        } else {
            t0("No copy is kept outside your home yet.")
        });
    }
    h.summary = s;

    for f in &i.folders {
        let mut st: Vec<NamedBytes> = f
            .storages
            .iter()
            .map(|(n, b)| NamedBytes {
                name: n.clone(),
                bytes: *b,
            })
            .collect();
        st.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.name.cmp(&b.name)));
        let where_ = if st.is_empty() {
            "-".to_string()
        } else {
            names(&st.iter().map(|x| x.name.clone()).collect::<Vec<_>>())
        };
        let line = if !f.attached {
            tx(
                "{folder}: {size} in {files} file(s), not synced on this device; kept on {storages}.",
                &[
                    ("folder", f.name.clone()),
                    ("files", f.files.to_string()),
                    ("size", human_bytes(f.bytes)),
                    ("storages", where_),
                ],
            )
        } else if st.is_empty() {
            tx(
                "{folder}: {size} in {files} file(s), only on this device so far.",
                &[
                    ("folder", f.name.clone()),
                    ("files", f.files.to_string()),
                    ("size", human_bytes(f.bytes)),
                ],
            )
        } else {
            tx(
                "{folder}: {size} in {files} file(s) on {devices}; kept on {storages}.",
                &[
                    ("folder", f.name.clone()),
                    ("files", f.files.to_string()),
                    ("size", human_bytes(f.bytes)),
                    (
                        "devices",
                        if f.devices.is_empty() {
                            i.device.clone()
                        } else {
                            names(&f.devices)
                        },
                    ),
                    ("storages", where_),
                ],
            )
        };
        h.folders.push(FolderPlace {
            name: f.name.clone(),
            attached: f.attached,
            files: f.files,
            bytes: f.bytes,
            unkept_bytes: f.unkept_bytes,
            storages: st,
            devices: f.devices.clone(),
            policy: i
                .policies
                .iter()
                .find(|p| p.folder == f.name)
                .map(|p| p.state),
            line,
        });
    }
    for s in &i.storages {
        let mut line = tx(
            "{storage} ({kind}, {place}): {size} stored there (encrypted and compressed).",
            &[
                ("storage", s.name.clone()),
                ("kind", s.kind.clone()),
                (
                    "place",
                    if s.place.is_empty() {
                        "home".to_string()
                    } else {
                        s.place.clone()
                    },
                ),
                ("size", human_bytes(s.bytes)),
            ],
        );
        if s.carrier {
            line = tx(
                "{storage} (transferrer): carries blocks to other devices and keeps no copies.",
                &[("storage", s.name.clone())],
            );
        }
        h.storages.push(StoragePlace {
            name: s.name.clone(),
            kind: s.kind.clone(),
            place: s.place.clone(),
            cold: s.cold,
            carrier: s.carrier,
            bytes: s.bytes,
            quota_bytes: s.quota_bytes,
            quota_percent: s.quota_percent,
            quota_state: s.quota_state.clone(),
            drain: s.drain.clone(),
            line,
        });
    }
    h.disks = i.disks.clone();

    let mut d = Vec::new();
    if !i.disks.is_empty() {
        let away: Vec<String> = i
            .disks
            .iter()
            .filter(|x| !x.retired && !x.attached)
            .map(|x| x.label.clone())
            .collect();
        let here: Vec<String> = i
            .disks
            .iter()
            .filter(|x| !x.retired && x.attached)
            .map(|x| x.label.clone())
            .collect();
        d.push(tx(
            "Pool disks: attached {here}; away {away}.",
            &[
                (
                    "here",
                    if here.is_empty() {
                        "-".into()
                    } else {
                        names(&here)
                    },
                ),
                (
                    "away",
                    if away.is_empty() {
                        "-".into()
                    } else {
                        names(&away)
                    },
                ),
            ],
        ));
    }
    let cold: Vec<String> = storages
        .iter()
        .filter(|s| s.cold)
        .map(|s| s.name.clone())
        .collect();
    if !cold.is_empty() {
        d.push(tx(
            "Cold storages (written, read only when you confirm): {names}.",
            &[("names", names(&cold))],
        ));
    }
    if i.trash_entries > 0 {
        d.push(tx(
            "Trash: {count} deleted files ({size}), each kept {days} days.",
            &[
                ("count", i.trash_entries.to_string()),
                ("size", human_bytes(i.trash_bytes)),
                ("days", i.trash_days.to_string()),
            ],
        ));
    } else if i.trash_days > 0 {
        d.push(tx(
            "Trash: empty. Deleted files are kept {days} days.",
            &[("days", i.trash_days.to_string())],
        ));
    }
    for b in &i.backups {
        d.push(match b.latest_utc {
            Some(t) => tx(
                "Backup {name}: {count} snapshots, the latest {size} on {date}.",
                &[
                    ("name", b.name.clone()),
                    ("count", b.snapshots.to_string()),
                    ("size", human_bytes(b.latest_bytes)),
                    ("date", crate::util::format_date(t)),
                ],
            ),
            None => tx(
                "Backup {name}: no snapshot yet.",
                &[("name", b.name.clone())],
            ),
        });
    }
    if i.restic {
        d.push(match &i.restic_text {
            Some(t) => tx("Restic mirror: {text}", &[("text", t.clone())]),
            None => t0("Restic mirror: set up on this device."),
        });
    }
    if i.replicas > 0 {
        d.push(tx(
            "Replicas holding encrypted copies: {count}.",
            &[("count", i.replicas.to_string())],
        ));
    }
    h.details = d;
}

fn att(h: &mut HelpState, id: &str, level: &str, text: Text) {
    h.attention.push(Attention {
        id: id.to_string(),
        level: level.to_string(),
        text,
    });
}

/// Health: what is wrong or worth knowing, one sentence each.
fn attention(h: &mut HelpState, i: &Inputs, storages: &[&StorageIn]) {
    if i.removed {
        att(
            h,
            "removed",
            "bad",
            t0("This device was removed from the vault. It no longer syncs."),
        );
    }
    if i.forked {
        att(
            h,
            "forked",
            "bad",
            t0("The ledger shows two devices writing as one (a copied device directory)."),
        );
    }
    if let Some(p) = &i.ledger_problem {
        att(
            h,
            "ledger",
            "bad",
            tx(
                "The ledger needs attention: {problem}",
                &[("problem", p.clone())],
            ),
        );
    }
    for p in &i.policies {
        match p.state {
            PolicyState::Violated => att(
                h,
                &format!("policy:{}", p.folder),
                "bad",
                tx(
                    "Folder {folder} breaks its policy.",
                    &[("folder", p.folder.clone())],
                ),
            ),
            PolicyState::AtRisk => att(
                h,
                &format!("policy:{}", p.folder),
                "warn",
                tx(
                    "Folder {folder} is at risk of breaking its policy.",
                    &[("folder", p.folder.clone())],
                ),
            ),
            _ => {}
        }
    }
    if i.repair_losses > 0 {
        att(
            h,
            "repair",
            "bad",
            tx(
                "{count} damaged copies could not be repaired yet.",
                &[("count", i.repair_losses.to_string())],
            ),
        );
    } else if i.repair_queued > 0 {
        att(
            h,
            "repair",
            "warn",
            tx(
                "{count} damaged copies are waiting for repair.",
                &[("count", i.repair_queued.to_string())],
            ),
        );
    }
    if i.scrub_damaged > 0 {
        att(
            h,
            "scrub",
            "bad",
            tx(
                "The bit-rot check found {count} damaged files that are not restored yet.",
                &[("count", i.scrub_damaged.to_string())],
            ),
        );
    }
    for s in storages {
        match s.quota_state.as_str() {
            "full" => att(
                h,
                &format!("quota:{}", s.name),
                "bad",
                tx(
                    "Storage {storage} is at its quota: nothing new is written there.",
                    &[("storage", s.name.clone())],
                ),
            ),
            "warning" => att(
                h,
                &format!("quota:{}", s.name),
                "warn",
                tx(
                    "Storage {storage} is at {percent}% of its quota.",
                    &[
                        ("storage", s.name.clone()),
                        ("percent", s.quota_percent.unwrap_or(90).to_string()),
                    ],
                ),
            ),
            _ => {}
        }
        match s.drain.as_deref() {
            Some("draining") => att(
                h,
                &format!("drain:{}", s.name),
                "info",
                tx(
                    "Storage {storage} is being emptied onto the others.",
                    &[("storage", s.name.clone())],
                ),
            ),
            Some("blocked") => att(
                h,
                &format!("drain:{}", s.name),
                "warn",
                tx(
                    "Emptying storage {storage} is stuck: the blocks left cannot go anywhere else.",
                    &[("storage", s.name.clone())],
                ),
            ),
            Some("drained") => att(
                h,
                &format!("drain:{}", s.name),
                "info",
                tx(
                    "Storage {storage} is empty and takes no new blocks; you can remove it.",
                    &[("storage", s.name.clone())],
                ),
            ),
            _ => {}
        }
    }
    for q in &i.quota_full {
        if !storages
            .iter()
            .any(|s| &s.name == q && s.quota_state == "full")
        {
            att(
                h,
                &format!("quota:{q}"),
                "bad",
                tx(
                    "Storage {storage} is at its quota: nothing new is written there.",
                    &[("storage", q.clone())],
                ),
            );
        }
    }
    if !i.disks_overdue.is_empty() {
        att(
            h,
            "disks_overdue",
            "warn",
            tx(
                "Pool disks overdue for a check: {disks}.",
                &[("disks", names(&i.disks_overdue))],
            ),
        );
    }
    for b in &i.backups {
        if let Some(e) = &b.error {
            att(
                h,
                &format!("backup:{}", b.name),
                "bad",
                tx(
                    "The last snapshot of backup {name} failed: {error}",
                    &[("name", b.name.clone()), ("error", e.clone())],
                ),
            );
        }
    }
    if let Some(sv) = &i.service {
        if !sv.running {
            att(
                h,
                "service",
                "warn",
                t0("The background service is not running: nothing syncs until it is started."),
            );
        } else if sv.paused {
            att(
                h,
                "service",
                "warn",
                t0("Syncing is paused on this device."),
            );
        }
        if let Some(e) = &sv.last_error {
            att(
                h,
                "service_error",
                "warn",
                tx("The last sync failed: {error}", &[("error", e.clone())]),
            );
        }
        if sv.running && !i.other_devices.is_empty() && !sv.p2p_listening {
            att(
                h,
                "p2p",
                "info",
                t0("Peer-to-peer is off: your devices exchange files only through the storages."),
            );
        } else if sv.running
            && !i.other_devices.is_empty()
            && sv.p2p_listening
            && !sv.p2p_reachable
            && sv.peers == 0
        {
            att(h, "p2p", "info", t0("Your other devices cannot reach this one directly right now; files still move through the storages."));
        }
    }
    if let Some((free, total)) = i.home_space {
        if free < LOW_FREE_BYTES || (total > 0 && free * 100 < total * LOW_FREE_PERCENT) {
            att(
                h,
                "space",
                "warn",
                tx(
                    "Only {free} free on this device's disk.",
                    &[("free", human_bytes(free))],
                ),
            );
        }
    }
    if let Some(o) = &i.org {
        if !o.listed {
            att(
                h,
                "org_listed",
                "warn",
                tx(
                    "This device waits for an administrator of {org} to approve it.",
                    &[("org", o.name.clone())],
                ),
            );
        }
        if o.admin && o.pending > 0 {
            att(
                h,
                "org_pending",
                "warn",
                tx(
                    "{count} devices wait for your approval in {org}.",
                    &[("count", o.pending.to_string()), ("org", o.name.clone())],
                ),
            );
        }
    }
    if !i.member {
        match i.kit {
            Kit::NotPrinted => att(h, "kit", "warn", t0("The recovery words have not been printed on this device.")),
            Kit::Outdated => att(h, "kit", "warn", t0("The printed recovery words are out of date: the vault key changed after they were printed.")),
            Kit::Printed => {}
        }
    }
}

/// "What to do next": the rules, most urgent first.
fn steps(h: &mut HelpState, i: &Inputs, storages: &[&StorageIn], offsite_configured: bool) {
    let mut out: Vec<HelpStep> = Vec::new();
    // --- urgent: something is broken or data is at risk.
    if i.removed {
        out.push(
            StepB::new("removed", "urgent", t0("Start over on this device"), t0("Another device removed this one from the vault, so it no longer syncs."))
                .how(t0("Reset this device under Settings. Then create a new vault, or ask for this device to be added again."))
                .act("settings", Some("resetform"), "Open Settings")
                .cmd("varsto reset")
                .0,
        );
    }
    if i.forked || i.ledger_problem.is_some() {
        out.push(
            StepB::new("ledger", "urgent", t0("Repair this device's ledger"), t0("The ledger records what every device did. Until it is repaired, this device may not sync safely."))
                .how(t0("Use the button on the Overview page, or run the command below. It rebuilds the ledger from the storages."))
                .act("overview", Some("ledgerbanner"), "Show me")
                .cmd(i.ledger_command.clone().unwrap_or_else(|| "varsto ledger rebuild".into()))
                .guide("recovery")
                .0,
        );
    }
    if let Some(sv) = &i.service {
        if sv.running && sv.paused {
            out.push(
                StepB::new("resume", "urgent", t0("Resume syncing"), t0("Syncing is paused: changes on this device are not copied to your storages."))
                    .how(t0("Choose Resume on the Overview page, or in the menu of the tray icon."))
                    .act("overview", Some("pause"), "Show the Resume button")
                    .0,
            );
        } else if !sv.running {
            out.push(
                StepB::new("start_service", "important", t0("Start the background service"), t0("Without it nothing syncs, and files are not copied to your storages."))
                    .how(t0("Open Varsto from your applications menu, or run the command below. To start it at every login, run varsto service install."))
                    .cmd("varsto service run")
                    .0,
            );
        }
    }
    if storages.is_empty() && !i.member {
        out.push(
            StepB::new("add_storage", "urgent", t0("Add a storage"), t0("Your files have no copy outside this device yet. If this device breaks or is lost, they are gone."))
                .how(t0("A storage is a place where Varsto keeps encrypted copies: an S3 bucket at a cloud provider, a folder on a NAS or USB disk, an rclone remote, or a pool of disks you swap in and out."))
                .how(t0("Everything is encrypted on this device first; the storage sees only sealed blocks."))
                .how(t0("Best: one storage at home and one elsewhere, for example a USB disk and a cloud bucket."))
                .act("storages", Some("addstorage"), "Add a storage")
                .cmd("varsto storage add-local <name> <path>   (or add-s3, add-rclone, add-pool)")
                .guide("storages")
                .0,
        );
    }
    // Policies: the most concrete fix first (a place without a copy, too
    // few storages, blocks nobody else checked).
    for p in i
        .policies
        .iter()
        .filter(|p| p.state == PolicyState::Violated || p.state == PolicyState::AtRisk)
    {
        let level = if p.state == PolicyState::Violated {
            "urgent"
        } else {
            "suggested"
        };
        let folder = p.folder.clone();
        let id = format!("policy:{folder}");
        let missing_places: Vec<String> = p
            .short_places
            .iter()
            .filter(|pl| !storages.iter().any(|s| place_of(s) == pl.as_str()))
            .cloned()
            .collect();
        let step = if !missing_places.is_empty() {
            StepB::new(
                &id,
                level,
                tx(
                    "Keep a copy of {folder} in another place: {places}",
                    &[("folder", folder.clone()), ("places", names(&missing_places))],
                ),
                t0("The folder's policy asks for a copy in each of these places, and you have no storage there yet."),
            )
            .how(t0("For the cloud, add an S3 bucket or an rclone remote. For home, add a directory on a disk or NAS, or a pool of disks."))
            .how(t0("The default policy asks for one copy at home and one in the cloud, checked by another device within 30 days. You can change it on the Policies page."))
            .act("storages", Some("addstorage"), "Add a storage")
            .cmd(if missing_places.iter().any(|p| p == "home") {
                "varsto storage add-local <name> <path>"
            } else {
                "varsto storage add-s3 <name> --endpoint <url> --bucket <bucket> --access-key-id <id>"
            })
            .guide("policies")
        } else if p.chunks_short_of_copies > 0 || !p.short_places.is_empty() {
            let mut b = StepB::new(
                &id,
                level,
                tx(
                    "Give {folder} the copies its policy asks for",
                    &[("folder", folder.clone())],
                ),
                t0("The policy says how many copies the folder needs and where; some blocks do not have them now."),
            );
            if storages.len() < p.min_copies as usize {
                b = b.how(tx(
                    "The policy asks for {min} copies, but there are only {have} storages. Add a storage, or lower the number in the policy.",
                    &[("min", p.min_copies.to_string()), ("have", storages.len().to_string())],
                ));
            } else {
                b = b.how(tx(
                    "{count} blocks have fewer copies than the policy asks. Let the next sync finish, then check again; if it stays, look at the folder's placement on the Policies page.",
                    &[("count", p.chunks_short_of_copies.max(1).to_string())],
                ));
            }
            if !p.short_places.is_empty() {
                b = b.how(tx(
                    "Copies are missing in these places: {places}. Attach the pool disk kept there, or add a storage there.",
                    &[("places", names(&p.short_places))],
                ));
            }
            b.act("policies", Some("policylist"), "Open Policies")
                .cmd("varsto policy check")
                .guide("policies")
        } else if i.other_devices.is_empty() && i.replicas == 0 {
            StepB::new(
                &id,
                level,
                tx("Have another device check {folder}", &[("folder", folder.clone())]),
                t0("The folder's policy asks that a device other than the one that wrote a block checks it now and then. This is the only device of the vault."),
            )
            .how(t0("Add another device and sync the folder there; it checks the copies by itself. Or change the policy on the Policies page."))
            .act("peers", Some("pairstart"), "Add a device")
            .cmd("varsto pair offer")
            .guide("devices")
        } else {
            StepB::new(
                &id,
                level,
                tx(
                    "Check the copies of {folder}",
                    &[("folder", folder.clone())],
                ),
                tx(
                    "{count} blocks have not been checked by another device recently enough.",
                    &[("count", p.chunks_unverified.to_string())],
                ),
            )
            .how(t0(
                "Run a verification now, on this device or on another one that syncs the folder.",
            ))
            .act("policies", Some("autoverify"), "Open verification")
            .cmd("varsto verify run")
            .guide("policies")
        };
        out.push(step.0);
    }
    if i.repair_losses > 0 || i.scrub_damaged > 0 {
        out.push(
            StepB::new("repair", "urgent", t0("Repair damaged copies"), t0("Some copies on your storages or files on this device are damaged."))
                .how(t0("Run a repair: Varsto copies a good version from another storage or device. The Policies page shows what could not be repaired and why."))
                .act("policies", Some("autorepair"), "Open repair")
                .cmd("varsto repair")
                .guide("policies")
                .0,
        );
    }
    for b in i.backups.iter().filter(|b| b.error.is_some()) {
        out.push(
            StepB::new(&format!("backup:{}", b.name), "urgent", tx("Fix backup {name}", &[("name", b.name.clone())]), t0("Its last scheduled snapshot failed, so recent changes are not backed up."))
                .how(t0("Check that the directory still exists and that a storage is reachable, then take a snapshot now."))
                .act("backups", Some("backups"), "Open Backups")
                .cmd(format!("varsto backup take {}", sh(&b.name)))
                .guide("backups")
                .0,
        );
    }
    let full: Vec<String> = storages
        .iter()
        .filter(|s| s.quota_state == "full")
        .map(|s| s.name.clone())
        .chain(i.quota_full.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !full.is_empty() {
        out.push(
            StepB::new(
                "quota",
                "urgent",
                tx("Make room on {storages}", &[("storages", names(&full))]),
                t0("A storage at its quota takes no new blocks, so new files may lack copies."),
            )
            .how(t0(
                "Raise the quota, empty the trash, or add another storage.",
            ))
            .act("storages", Some("storages"), "Open Storages")
            .cmd(format!("varsto storage quota {}", sh(&full[0])))
            .guide("storages")
            .0,
        );
    }
    if let Some((free, total)) = i.home_space {
        if free < LOW_FREE_BYTES || (total > 0 && free * 100 < total * LOW_FREE_PERCENT) {
            out.push(
                StepB::new("space", "urgent", t0("Free up space on this device"), tx("Only {free} is free. Syncing stops when the disk is full.", &[("free", human_bytes(free))]))
                    .how(t0("Free up space for files you do not need here: they stay on your storages as placeholders and come back when opened."))
                    .act("files", None, "Open Files")
                    .guide("folders")
                    .0,
            );
        }
    }
    if let Some(o) = &i.org {
        if o.admin && o.pending > 0 {
            out.push(
                StepB::new(
                    "org_pending",
                    "important",
                    t0("Approve the devices that wait"),
                    tx(
                        "{count} devices wait for an administrator to add them.",
                        &[("count", o.pending.to_string())],
                    ),
                )
                .how(t0(
                    "Compare the six-word fingerprint with the person before you approve.",
                ))
                .act("organization", Some("org-approve"), "Open Organization")
                .cmd("varsto org status")
                .0,
            );
        }
        if !o.listed {
            out.push(
                StepB::new(
                    "org_listed",
                    "important",
                    t0("Ask an administrator to approve this device"),
                    t0("Until then the organization's other devices do not trust it."),
                )
                .how(t0(
                    "Send them the request code under Organization and read them the fingerprint.",
                ))
                .act("organization", None, "Open Organization")
                .0,
            );
        }
    }
    // --- important: setup not finished.
    if !storages.is_empty() && i.folders.is_empty() && !i.member {
        out.push(
            StepB::new("add_folder", "important", t0("Add a folder to sync"), t0("Nothing is synced yet. A folder is a directory on this device whose files Varsto keeps in sync on your devices and copies to your storages."))
                .how(t0("Pick a directory, for example Documents or Photos, and give the folder a name."))
                .how(t0("Its files stay where they are; Varsto copies them, encrypted, to every storage."))
                .act("files", Some("addfolder"), "Add a folder")
                .cmd("varsto folder add <name> <path>")
                .guide("folders")
                .0,
        );
    }
    let unattached: Vec<String> = i
        .folders
        .iter()
        .filter(|f| !f.attached)
        .map(|f| f.name.clone())
        .collect();
    if !unattached.is_empty() {
        out.push(
            StepB::new("attach", "suggested", tx("Sync {folders} on this device too", &[("folders", names(&unattached))]), t0("These folders of the vault are not synced on this device. That is fine if you do not need them here."))
                .how(t0("Choose Attach on the Files page and pick a directory. With selective sync, files appear as placeholders and download when opened."))
                .act("files", Some("attachfolder"), "Open Files")
                .cmd(format!("varsto folder attach {} <path>", sh(&unattached[0])))
                .guide("folders")
                .0,
        );
    }
    let unkept: u64 = i.folders.iter().map(|f| f.unkept_bytes).sum();
    if unkept > 0 && !storages.is_empty() && full.is_empty() {
        out.push(
            StepB::new("sync", "important", t0("Let the files reach your storages"), tx("{size} of your files have no copy on a storage yet.", &[("size", human_bytes(unkept))]))
                .how(t0("The background service copies them by itself within a few minutes. Sync now to do it at once."))
                .how(t0("If this stays, check that the storages are reachable: the Overview page shows the last sync and its errors."))
                .act("overview", Some("do:sync"), "Sync now")
                .cmd("varsto sync")
                .guide("storages")
                .0,
        );
    }
    if !i.member {
        match i.kit {
            Kit::NotPrinted => out.push(
                StepB::new("kit", if i.folders.is_empty() { "suggested" } else { "important" }, t0("Print your recovery words"), t0("If every device is lost, the vault key is the only way to open your files again. The recovery kit prints it as 24 words."))
                    .how(t0("Print the kit, or write the words down by hand, and keep it somewhere safe away from your devices."))
                    .how(t0("The Recovery package page lists everything else to keep with it."))
                    .act("recovery", Some("kit"), "Print the recovery kit")
                    .cmd("varsto recovery kit")
                    .guide("recovery")
                    .0,
            ),
            Kit::Outdated => out.push(
                StepB::new("kit", "important", t0("Print new recovery words"), t0("The vault key changed after the kit was printed, so the old words do not open new data."))
                    .how(t0("Print a new kit and destroy the old one."))
                    .act("recovery", Some("kit"), "Print the recovery kit")
                    .cmd("varsto recovery kit")
                    .guide("recovery")
                    .0,
            ),
            Kit::Printed => {}
        }
    }
    // --- suggested: safer with more devices, storages and places (unless
    // a step above already leads there).
    let leads_to = |out: &[HelpStep], target: &str| {
        out.iter().any(|s| {
            s.action
                .as_ref()
                .is_some_and(|a| a.target.as_deref() == Some(target))
        })
    };
    if !i.member
        && i.other_devices.is_empty()
        && !storages.is_empty()
        && !leads_to(&out, "pairstart")
    {
        out.push(
            StepB::new("add_device", "suggested", t0("Add your other devices"), t0("This is the only device of the vault. Pair your phone or another computer to have your files there too, and a device that can verify the copies."))
                .how(t0("Install Varsto on the other device and choose Pair with your other device there."))
                .how(t0("Here, choose Add a device on the Peers page and type the code it shows on the other device."))
                .act("peers", Some("pairstart"), "Add a device")
                .cmd("varsto pair offer")
                .guide("devices")
                .0,
        );
    }
    let storage_step = leads_to(&out, "addstorage");
    if !i.member && storages.len() == 1 && !i.folders.is_empty() && !storage_step {
        out.push(
            StepB::new("second_storage", "suggested", t0("Add a second storage"), tx("Everything is kept on one storage ({storage}). If it fails, your files are left only on your devices.", &[("storage", storages[0].name.clone())]))
                .how(t0("Add another storage, preferably in another place: a cloud bucket if the first is at home, or a USB disk if the first is in the cloud."))
                .act("storages", Some("addstorage"), "Add a storage")
                .cmd("varsto storage add-s3 <name> --endpoint <url> --bucket <bucket> --access-key-id <id>")
                .guide("storages")
                .0,
        );
    } else if !i.member
        && storages.len() > 1
        && !offsite_configured
        && !i.folders.is_empty()
        && !storage_step
    {
        out.push(
            StepB::new("offsite", "suggested", t0("Keep a copy outside your home"), t0("All your storages are at home. A fire, flood or burglary could take them all at once."))
                .how(t0("Add a cloud storage, or set a pool's place to offsite and keep one of its disks elsewhere."))
                .act("storages", Some("addstorage"), "Add a storage")
                .guide("storages")
                .0,
        );
    }
    if !i.disks_overdue.is_empty() {
        let label = i
            .disk_next
            .clone()
            .unwrap_or_else(|| i.disks_overdue[0].clone());
        out.push(
            StepB::new("disks", "suggested", tx("Attach disk {disk} for a check", &[("disk", label.clone())]), t0("Pool disks that stay away too long are not verified, and new files do not reach them."))
                .how(t0("Plug the disk in; Varsto checks it and fills it with what it lacks. Eject it on the Storages page before unplugging."))
                .act("storages", Some("pools"), "Open the disks")
                .cmd(crate::disksuggest::insert_command(&label))
                .guide("disks")
                .0,
        );
    }
    h.steps = out;

    // --- tips: features not used yet, when the basics are done.
    if h.steps
        .iter()
        .any(|s| s.level == "urgent" || s.level == "important")
        || i.member
    {
        return;
    }
    let mut tips = Vec::new();
    if i.backups.is_empty() {
        tips.push(
            StepB::new("tip:backups", "tip", t0("Keep snapshots of a directory"), t0("A backup keeps read-only snapshots, for example of a project folder, for as many days as you choose."))
                .act("backups", Some("addbackup"), "Add a backup")
                .cmd("varsto backup add <name> <dir>")
                .guide("backups")
                .0,
        );
    }
    tips.push(
        StepB::new("tip:policies", "tip", t0("Choose how many copies each folder needs"), t0("Every folder follows a policy: by default one copy at home and one in the cloud, checked by another device within 30 days. Varsto warns you when a folder falls short."))
            .act("policies", Some("policylist"), "Open Policies")
            .cmd("varsto policy show")
            .guide("policies")
            .0,
    );
    tips.push(
        StepB::new("tip:trash", "tip", tx("Deleted files are kept {days} days", &[("days", i.trash_days.to_string())]), t0("Files deleted on any device go to the trash first. You can restore them or change how long they are kept."))
            .act("trash", Some("trashsettings"), "Open the trash")
            .guide("trash")
            .0,
    );
    if !i.folders.iter().any(|f| f.shared) {
        tips.push(
            StepB::new("tip:sharing", "tip", t0("Share a folder with someone"), t0("Give another person access to one folder only; the rest of your vault stays private."))
                .act("shared", None, "Open Shared")
                .guide("sharing")
                .0,
        );
    }
    tips.push(
        StepB::new(
            "tip:import",
            "tip",
            t0("Bring in files from elsewhere"),
            t0("Import a directory, a cloud drive or a git-annex repository into a folder."),
        )
        .act("import", Some("importform"), "Open Import")
        .guide("imports")
        .0,
    );
    if !i.mcp_used {
        tips.push(
            StepB::new("tip:mcp", "tip", t0("Let an AI assistant work with your files"), t0("The MCP server lets an assistant of your choice read, sort and annotate the folders you allow, and nothing else."))
                .cmd("varsto mcp grant <folder>")
                .guide("mcp")
                .0,
        );
    }
    if !i.restic {
        tips.push(
            StepB::new("tip:restic", "tip", t0("Mirror your folders to restic"), t0("A restic repository gives you a second, independent way to get your files back, without Varsto."))
                .cmd("varsto restic setup --help")
                .guide("recovery")
                .0,
        );
    }
    h.tips = tips;
}

// ----- text --------------------------------------------------------------------

/// The Help page as English text for the command line.
pub fn render_text(h: &HelpState) -> String {
    let mut t = String::new();
    t.push_str("WHERE YOU ARE NOW\n-----------------\n");
    t.push_str(&wrap(&h.headline.render(), 78, ""));
    for s in &h.summary {
        t.push_str(&wrap(&s.render(), 78, "  "));
    }
    if !h.folders.is_empty() {
        t.push_str("\nFolders:\n");
        for f in &h.folders {
            t.push_str(&wrap(&f.line.render(), 78, "  * "));
        }
    }
    if !h.storages.is_empty() {
        t.push_str("\nStorages:\n");
        for s in &h.storages {
            t.push_str(&wrap(&s.line.render(), 78, "  * "));
        }
    }
    if !h.details.is_empty() {
        t.push('\n');
        for d in &h.details {
            t.push_str(&wrap(&d.render(), 78, "  "));
        }
    }
    if !h.attention.is_empty() {
        t.push_str("\nNEEDS ATTENTION\n---------------\n");
        for a in &h.attention {
            let mark = match a.level.as_str() {
                "bad" => "[!]",
                "warn" => "[~]",
                _ => "[i]",
            };
            t.push_str(&wrap(&a.text.render(), 78, &format!("{mark} ")));
        }
    }
    t.push_str("\nWHAT TO DO NEXT\n---------------\n");
    if h.steps.is_empty() {
        t.push_str("Everything is in order.\n");
    }
    for (n, s) in h.steps.iter().enumerate() {
        step_text(&mut t, &format!("{}.", n + 1), s);
    }
    if !h.tips.is_empty() {
        t.push_str("\nTIPS\n----\n");
        for s in &h.tips {
            step_text(&mut t, "-", s);
        }
    }
    t.push_str(&format!("\nMore: {DOCS}/quick-start.html\n"));
    t
}

fn step_text(t: &mut String, num: &str, s: &HelpStep) {
    t.push('\n');
    let level = match s.level.as_str() {
        "urgent" => " (urgent)",
        "important" => "",
        _ => "",
    };
    t.push_str(&wrap(
        &format!("{} {}{}", num, s.title.render(), level),
        78,
        "",
    ));
    t.push_str(&wrap(&format!("Why: {}", s.why.render()), 78, "   "));
    for x in &s.how {
        t.push_str(&wrap(&x.render(), 78, "   "));
    }
    if let Some(c) = &s.command {
        t.push_str(&format!("     $ {c}\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quoting() {
        assert_eq!(sh("docs"), "docs");
        assert_eq!(sh("My Photos"), "\"My Photos\"");
        assert_eq!(sh("a$b"), "\"a\\$b\"");
    }

    #[test]
    fn no_vault_starts_with_create() {
        let h = build(&Inputs::default());
        assert_eq!(h.phase, "no_vault");
        assert_eq!(h.steps[0].id, "create_vault");
        assert!(!h.all_ok);
        assert!(render_text(&h).contains("Create a vault"));
    }
}
