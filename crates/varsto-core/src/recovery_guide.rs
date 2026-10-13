// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Recovery package guide (`docs/recovery.md`): what to keep outside your
//! devices so that every file of the vault can be restored on a new device
//! after all of them are lost at once, and how to restore with only that.
//!
//! The guide is made for one vault from what this device knows (its
//! storages, pools, folders, Strongroom keys, organization, restic
//! settings) and never contains a secret: it names the vault key, the S3
//! secret keys, the restic password and rclone's tokens and says where to
//! keep them, but no value of theirs is ever read into it.
//!
//! Every sentence is a [`Text`]: an English template with `{name}`
//! placeholders and the values to put in. The command line renders them in
//! English ([`render_text`], [`render_markdown`], [`render_html`]); the
//! interface translates the template (the English string is the key of
//! `ui/i18n/<lang>.json`) and puts the values in untranslated. So the facts
//! come from one place and the wording is translated where the other
//! interface strings are. Commands are shell lines and stay as they are.
//!
//! [`build`] is pure (inputs in, guide out) so it can be tested with every
//! kind of storage; `Engine::recovery_guide` gathers the inputs.

use crate::storage::StorageSpec;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Where the release files are downloaded from.
pub const DOWNLOAD_SITE: &str = "https://varsto.net";

/// One sentence: an English template and the values of its placeholders.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Text {
    pub t: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub p: BTreeMap<String, String>,
}

impl Text {
    /// The sentence in English with the values put in.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut rest = self.t.as_str();
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let after = &rest[open + 1..];
            match after.find('}') {
                Some(close) if self.p.contains_key(&after[..close]) => {
                    out.push_str(&self.p[&after[..close]]);
                    rest = &after[close + 1..];
                }
                _ => {
                    out.push('{');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }
}

fn tx(t: &str, p: &[(&str, &str)]) -> Text {
    Text {
        t: t.to_string(),
        p: p.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

/// What Varsto knows about an item of the package.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Varsto knows it is covered (the recovery kit was printed for the
    /// current vault key on this device).
    Done,
    /// It was covered, but no longer is (the kit predates a key change).
    Outdated,
    /// Varsto cannot know: the user ticks it.
    Check,
    /// Nothing to keep; worth knowing.
    Info,
}

/// One thing the recovery package needs (or a fact worth knowing).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Item {
    /// Stable within the vault ("kit", "storage:<name>", ...): the interface
    /// keeps its checkbox under it.
    pub id: String,
    /// recovery_kit, s3, rclone, local_dir, transferrer, pool, org_root,
    /// strongroom, restic, devices, replica, shared_folder.
    pub kind: String,
    /// Without it some data cannot be restored.
    pub essential: bool,
    pub title: Text,
    pub what: Text,
    pub why: Text,
    /// Where it is now: endpoints, paths, disks, places.
    #[serde(default)]
    pub location: Vec<Text>,
    /// What to put in the package and where to keep it.
    #[serde(default)]
    pub keep: Vec<Text>,
    /// What happens without it.
    pub missing: Text,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_note: Option<Text>,
    /// Lines to copy as they are (disks.conf lines).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub literal: Vec<String>,
}

/// One step of the restore on a new device.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    pub id: String,
    pub title: Text,
    #[serde(default)]
    pub notes: Vec<Text>,
    /// Shell lines; `<...>` marks what the user fills in.
    #[serde(default)]
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryGuide {
    pub vault_id: String,
    pub device: String,
    pub generated_utc: i64,
    /// This device is a member of someone else's shared folder.
    pub member: bool,
    pub intro: Vec<Text>,
    pub items: Vec<Item>,
    pub steps: Vec<Step>,
    /// Ways to get the files back without Varsto (restic).
    #[serde(default)]
    pub alternatives: Vec<Step>,
}

// ----- inputs ----------------------------------------------------------------

/// When and for which vault key the recovery kit was last printed on this
/// device (`state/recovery-kit.json`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KitRecord {
    pub printed_utc: i64,
    pub key_epoch: u32,
    #[serde(default)]
    pub shares: bool,
}

const KIT_FILE: &str = "state/recovery-kit.json";

/// Note that the kit was printed (no word of it is written).
pub fn record_kit_printed(home: &Path, key_epoch: u32, shares: bool) -> Result<()> {
    std::fs::create_dir_all(home.join("state"))?;
    crate::util::write_json(
        &home.join(KIT_FILE),
        &KitRecord {
            printed_utc: crate::util::now_utc(),
            key_epoch,
            shares,
        },
    )
}

pub fn kit_record(home: &Path) -> Option<KitRecord> {
    crate::util::read_json(&home.join(KIT_FILE)).ok()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderInput {
    pub name: String,
    /// Where it is attached on this device.
    pub path: Option<String>,
    pub selective: bool,
    pub strongroom: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StrongroomInput {
    pub folder: String,
    /// Labels (or names) of the enrolled keys.
    pub keys: Vec<String>,
    /// A software key file on this device instead of a security key.
    pub software: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgInput {
    pub name: String,
    pub admins: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResticPassword {
    /// `RESTIC_PASSWORD_FILE`: the file's path (never its contents).
    File(String),
    /// `RESTIC_PASSWORD_COMMAND`: the command is not shown, it may hold the password.
    Command,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResticInput {
    /// Repository with any user and password in it replaced by placeholders.
    pub repository: String,
    pub password: ResticPassword,
    /// The file of `KEY=VALUE` credentials handed to restic (its path).
    pub env_file: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupInput {
    pub name: String,
    pub source: String,
}

/// What the guide is made from. Nothing in here is secret.
#[derive(Clone, Debug, Default)]
pub struct Inputs {
    pub vault_id: String,
    pub device: String,
    pub now_utc: i64,
    pub member: bool,
    pub key_epoch: u32,
    pub kit: Option<KitRecord>,
    pub storages: Vec<StorageSpec>,
    /// `disks.conf` lines: (partuuid, pool, label).
    pub disk_conf: Vec<(String, String, String)>,
    pub folders: Vec<FolderInput>,
    pub strongrooms: Vec<StrongroomInput>,
    pub backups: Vec<BackupInput>,
    pub org: Option<OrgInput>,
    /// The vault's other devices that are not removed.
    pub other_devices: Vec<String>,
    pub replicas: Vec<String>,
    pub restic: Option<ResticInput>,
}

/// A restic repository string with any `user:password@` replaced by placeholders.
pub fn redact_repository(repo: &str) -> String {
    if let Some(scheme_end) = repo.find("://") {
        let rest = &repo[scheme_end + 3..];
        let host_end = rest.find('/').unwrap_or(rest.len());
        if let Some(at) = rest[..host_end].rfind('@') {
            let userinfo = &rest[..at];
            let masked = if userinfo.contains(':') {
                "<user>:<password>"
            } else {
                "<user>"
            };
            return format!("{}{masked}{}", &repo[..scheme_end + 3], &rest[at..]);
        }
    }
    repo.to_string()
}

/// "2026-10-13" for seconds since the epoch (UTC).
pub fn day(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Double-quoted for a POSIX shell (and fine for PowerShell when it holds
/// no `$`, backquote or quote).
pub fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        if matches!(c, '"' | '\\' | '$' | '`') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

const WORDS: &str = "<24 recovery words>";

// ----- building ----------------------------------------------------------------

fn place_of(spec: &StorageSpec) -> Option<String> {
    let explicit = match spec {
        StorageSpec::LocalDir { place, .. }
        | StorageSpec::S3 { place, .. }
        | StorageSpec::Rclone { place, .. }
        | StorageSpec::Pool { place, .. } => place,
    };
    (!explicit.is_empty()).then(|| explicit.clone())
}

fn storage_item(spec: &StorageSpec, inputs: &Inputs) -> Item {
    let name = spec.name().to_string();
    let id = format!("storage:{name}");
    let cold = spec.is_cold();
    let holds = tx(
        "Holds the encrypted copies of your files, the folder records and the ledger: a new device joins the vault through it and fetches the files from it.",
        &[],
    );
    let cold_note = tx(
        "Cold storage: Varsto writes to it but reads it only when you confirm, and reading may cost retrieval fees.",
        &[],
    );
    let mut location = Vec::new();
    if let Some(p) = place_of(spec) {
        location.push(tx("Place: {place}", &[("place", &p)]));
    }
    match spec {
        StorageSpec::S3 {
            endpoint,
            region,
            bucket,
            prefix,
            storage_class,
            ..
        } => {
            location.insert(0, tx("Endpoint: {endpoint}", &[("endpoint", endpoint)]));
            location.insert(1, tx("Bucket: {bucket}", &[("bucket", bucket)]));
            location.insert(2, tx("Region: {region}", &[("region", region)]));
            if !prefix.is_empty() {
                location.push(tx("Key prefix: {prefix}", &[("prefix", prefix)]));
            }
            if let Some(c) = storage_class {
                location.push(tx("Storage class: {class}", &[("class", c)]));
            }
            let mut keep = vec![
                tx("The access key ID and the secret access key of bucket {bucket}. Varsto keeps the secret key only in this device's encrypted secret store, so keep both outside your devices: in a password manager you can open from a new computer, or on paper with the recovery kit.", &[("bucket", bucket)]),
                tx("The login to your account at the provider of {endpoint}, where you can make new keys if these are lost.", &[("endpoint", endpoint)]),
            ];
            if cold {
                keep.push(tx("Archive classes (DEEP_ARCHIVE, GLACIER) need a restore request at the provider before the objects can be read: know how to make one there.", &[]));
            }
            Item {
                id,
                kind: "s3".into(),
                essential: true,
                title: tx("Bucket «{bucket}» (storage {storage})", &[("bucket", bucket), ("storage", &name)]),
                what: tx("An S3-compatible bucket at {endpoint}.", &[("endpoint", endpoint)]),
                why: if cold { cold_note } else { holds },
                location,
                keep,
                missing: tx("Without the keys and without the account login, this copy of your data cannot be reached from a new device.", &[]),
                status: Status::Check,
                status_note: None,
                literal: vec![],
            }
        }
        StorageSpec::Rclone { remote, .. } => {
            let section = remote.split(':').next().unwrap_or(remote).to_string();
            location.insert(0, tx("Remote: {remote}", &[("remote", remote)]));
            location.insert(
                1,
                tx("Its settings and token: section [{section}] of rclone's configuration file (`rclone config file` shows where it is).", &[("section", &section)]),
            );
            Item {
                id,
                kind: "rclone".into(),
                essential: true,
                title: tx("rclone remote «{remote}» (storage {storage})", &[("remote", remote), ("storage", &name)]),
                what: tx("A storage reached through rclone; the credentials stay in rclone's configuration, not in Varsto.", &[]),
                why: if cold { cold_note } else { holds },
                location,
                keep: vec![
                    tx("A copy of rclone's configuration file (rclone.conf), kept like a password: its token or password opens the remote. If the file is encrypted, also its password.", &[]),
                    tx("Or what you need to set the remote {section} up again: the provider account login and the remote's settings.", &[("section", &section)]),
                ],
                missing: tx("Without rclone's configuration you have to set the remote up again from the provider account; without that account this copy cannot be reached.", &[]),
                status: Status::Check,
                status_note: None,
                literal: vec![],
            }
        }
        StorageSpec::LocalDir { path, carrier, .. } => {
            let path = path.display().to_string();
            location.insert(0, tx("Path on this device: {path}", &[("path", &path)]));
            if *carrier {
                return Item {
                    id,
                    kind: "transferrer".into(),
                    essential: false,
                    title: tx("Transferrer {path} (storage {storage})", &[("path", &path), ("storage", &name)]),
                    what: tx("Removable media that carries blocks between your devices.", &[]),
                    why: tx("It holds only what other devices still lack and is emptied as they receive it, so it is no recovery source.", &[]),
                    location,
                    keep: vec![],
                    missing: tx("Nothing: the other storages hold the data.", &[]),
                    status: Status::Info,
                    status_note: None,
                    literal: vec![],
                };
            }
            Item {
                id,
                kind: "local_dir".into(),
                essential: true,
                title: tx("Directory {path} (storage {storage})", &[("path", &path), ("storage", &name)]),
                what: tx("A directory: a disk of this device, a removable disk, a NAS or a network share.", &[]),
                why: if cold { cold_note } else { holds },
                location,
                keep: vec![
                    tx("If it is a NAS, a network share or a removable disk: where it is and how to reach it (address, share name, login).", &[]),
                    tx("If it is on this device's own disk, it is lost with the device and is no recovery source: make sure another storage holds the data.", &[]),
                ],
                missing: tx("Data that only this directory holds is lost with it.", &[]),
                status: Status::Check,
                status_note: None,
                literal: vec![],
            }
        }
        StorageSpec::Pool {
            name: pool,
            disks,
            copies,
            ..
        } => {
            let pool_place = place_of(spec).unwrap_or_else(|| "home".to_string());
            let mut location = Vec::new();
            for d in disks {
                let place = if d.place.is_empty() {
                    pool_place.clone()
                } else {
                    d.place.clone()
                };
                let seen = if d.last_seen_utc > 0 {
                    day(d.last_seen_utc)
                } else {
                    "-".to_string()
                };
                location.push(tx(
                    if d.retired {
                        "Disk «{label}» (retired), kept at: {place}; last seen {seen}"
                    } else {
                        "Disk «{label}», kept at: {place}; last seen {seen}"
                    },
                    &[("label", &d.label), ("place", &place), ("seen", &seen)],
                ));
            }
            if disks.is_empty() {
                location.push(tx("No disk has been added yet.", &[]));
            }
            if *copies > 1 {
                location.push(tx(
                    "Rule: {copies} copies of every block on disks in different places.",
                    &[("copies", &copies.to_string())],
                ));
            }
            let literal: Vec<String> = inputs
                .disk_conf
                .iter()
                .filter(|(_, p, _)| p == pool)
                .map(|(u, p, l)| format!("{u}\t{p}\t{l}"))
                .collect();
            let mut keep = vec![
                tx("The disks themselves, with their stickers, in the places above: not all in the same building as your computers.", &[]),
                tx("The pool's name exactly as written: «{pool}». The disks are recognised by the vault key and this name.", &[("pool", pool)]),
            ];
            if !literal.is_empty() {
                keep.push(tx("The lines of disks.conf below (Linux): they let Varsto mount the drives by the names on their stickers.", &[]));
            }
            Item {
                id,
                kind: "pool".into(),
                essential: true,
                title: tx("Disk pool «{pool}»", &[("pool", pool)]),
                what: tx("Removable disks that hold encrypted blocks of your files (no records or ledger).", &[]),
                why: tx("Blocks may be only on these disks: then they are needed to restore those files.", &[]),
                location,
                keep,
                missing: tx("Files whose blocks are only on these disks cannot be restored without them.", &[]),
                status: Status::Check,
                status_note: None,
                literal,
            }
        }
    }
}

/// Build the guide.
pub fn build(inputs: &Inputs) -> RecoveryGuide {
    let mut items = Vec::new();
    let mut steps = Vec::new();
    let mut alternatives = Vec::new();
    let today = day(inputs.now_utc);
    let mut intro = vec![
        tx(
            "What to keep outside your devices so that every file of vault {vault} can be restored on a new device if all your devices are lost at once (fire, theft, a flood), and how to restore with only that.",
            &[("vault", &inputs.vault_id)],
        ),
        tx(
            "This guide names the secrets and says where to keep them; it never contains them. Made on device {device} on {date}: make it again after you add a storage, a disk or a Strongroom folder.",
            &[("device", &inputs.device), ("date", &today)],
        ),
    ];

    if inputs.member {
        intro.push(tx(
            "This device belongs to a folder that someone else shares with you; it holds that folder's key only. There is no recovery kit for it: the person who shared it shares it again.",
            &[],
        ));
        for f in &inputs.folders {
            items.push(Item {
                id: format!("shared:{}", f.name),
                kind: "shared_folder".into(),
                essential: true,
                title: tx("Shared folder «{folder}»", &[("folder", &f.name)]),
                what: tx("A folder of someone else's vault that is shared with you.", &[]),
                why: tx("Its key came from the person who shared it; nothing you can print opens it.", &[]),
                location: f
                    .path
                    .iter()
                    .map(|p| tx("On this device: {path}", &[("path", p)]))
                    .collect(),
                keep: vec![tx("Who shared it with you and how to reach them.", &[])],
                missing: tx("If they cannot share it again, the folder stays out of your reach (their copy is not affected).", &[]),
                status: Status::Check,
                status_note: None,
                literal: vec![],
            });
        }
        steps.push(install_step());
        steps.push(Step {
            id: "share".into(),
            title: tx("Ask for the shared folders again", &[]),
            notes: vec![
                tx("On the new device, make a request code and send it to the person who shared the folder; they share the folder to it, and you accept what they send.", &[]),
            ],
            commands: vec!["varsto share request".into()],
        });
        return RecoveryGuide {
            vault_id: inputs.vault_id.clone(),
            device: inputs.device.clone(),
            generated_utc: inputs.now_utc,
            member: true,
            intro,
            items,
            steps,
            alternatives,
        };
    }
    intro.push(tx(
        "Not needed: the passphrase of this device. A new device gets a passphrase of its own.",
        &[],
    ));

    // The recovery kit.
    let (status, status_note) = match &inputs.kit {
        Some(k) if k.key_epoch >= inputs.key_epoch => (
            Status::Done,
            Some(tx("Printed on this device on {date}.", &[("date", &day(k.printed_utc))])),
        ),
        Some(k) => (
            Status::Outdated,
            Some(tx("The kit printed on {date} is out of date: the vault key changed afterwards (a device was removed). It still opens what was written before; print a new one for the rest.", &[("date", &day(k.printed_utc))])),
        ),
        None => (
            Status::Check,
            Some(tx("Varsto does not know whether you printed it, for example on another device.", &[])),
        ),
    };
    items.push(Item {
        id: "kit".into(),
        kind: "recovery_kit".into(),
        essential: true,
        title: tx("Recovery kit: the vault key as 24 words", &[]),
        what: tx("The vault key of vault {vault}, printed with `varsto recovery kit`.", &[("vault", &inputs.vault_id)]),
        why: tx("It is the only thing that opens the vault on a new device. Varsto keeps no copy anywhere and cannot reset it.", &[]),
        location: vec![],
        keep: vec![
            tx("On paper or metal, in at least two places away from your devices; never as a photo or a cloud note.", &[]),
            tx("Or as three shares (`varsto recovery kit --shares`), each in a different place or with a different person: any two rebuild the key, one alone reveals nothing.", &[]),
        ],
        missing: tx("Without the words, or two of the shares, nobody can read the vault: not you, not the makers of Varsto.", &[]),
        status,
        status_note,
        literal: vec![],
    });

    for spec in &inputs.storages {
        items.push(storage_item(spec, inputs));
    }
    if inputs.storages.is_empty() {
        items.push(Item {
            id: "no-storage".into(),
            kind: "local_dir".into(),
            essential: true,
            title: tx("No storage yet", &[]),
            what: tx("The vault has no storage on this device.", &[]),
            why: tx(
                "Without a storage outside this device nothing can be restored after it is lost.",
                &[],
            ),
            location: vec![],
            keep: vec![tx(
                "Add a storage outside this device: a bucket, a NAS or a disk kept elsewhere.",
                &[],
            )],
            missing: tx("Everything is lost with this device.", &[]),
            status: Status::Check,
            status_note: None,
            literal: vec![],
        });
    }

    if let Some(org) = &inputs.org {
        items.push(Item {
            id: "org-root".into(),
            kind: "org_root".into(),
            essential: false,
            title: tx("Root words of organization «{org}»", &[("org", &org.name)]),
            what: tx("24 words shown once when the organization was created. They are not the recovery kit.", &[]),
            why: tx("They appoint and dismiss administrators, the devices that approve and remove the others.", &[]),
            location: vec![tx("Administrators now: {admins}", &[("admins", &org.admins.join(", "))])],
            keep: vec![tx("Offline, in a different place from the recovery kit.", &[])],
            missing: tx("Nobody can appoint a new administrator. The data stays readable with the recovery kit.", &[]),
            status: Status::Check,
            status_note: None,
            literal: vec![],
        });
    }

    for s in &inputs.strongrooms {
        let mut location = vec![tx(
            "Enrolled keys: {count} ({keys})",
            &[
                ("count", &s.keys.len().to_string()),
                ("keys", &s.keys.join(", ")),
            ],
        )];
        let mut keep = vec![tx(
            "At least two of the enrolled security keys, kept in different places, and their PINs.",
            &[],
        )];
        if s.software {
            location.push(tx(
                "It uses a software key file on this device, which is lost with the device.",
                &[],
            ));
        } else if s.keys.len() < 2 {
            keep.push(tx(
                "Only one key is enrolled: add a backup key with `varsto strongroom add-key \"{folder}\"` and keep it elsewhere.",
                &[("folder", &s.folder)],
            ));
        }
        items.push(Item {
            id: format!("strongroom:{}", s.folder),
            kind: "strongroom".into(),
            essential: true,
            title: tx("Security keys of Strongroom folder «{folder}»", &[("folder", &s.folder)]),
            what: tx("The FIDO2 security keys that open this folder with a touch.", &[]),
            why: tx("The folder's key exists only wrapped for these security keys; the recovery kit does not open it.", &[]),
            location,
            keep,
            missing: tx("Without any of its security keys the folder cannot be opened by anyone, by design.", &[]),
            status: Status::Check,
            status_note: None,
            literal: vec![],
        });
    }

    if let Some(r) = &inputs.restic {
        let mut location = vec![tx("Repository: {repo}", &[("repo", &r.repository)])];
        match &r.password {
            ResticPassword::File(p) => location.push(tx(
                "Password: in the file {path} on this device",
                &[("path", p)],
            )),
            ResticPassword::Command => location.push(tx(
                "Password: printed by the command set in Varsto's restic settings",
                &[],
            )),
        }
        let mut keep = vec![tx(
            "The repository's password, outside your devices (a password manager you can open from a new computer, or paper).",
            &[],
        )];
        if let Some(env) = &r.env_file {
            location.push(tx(
                "Credentials of the repository: in the file {path} on this device",
                &[("path", env)],
            ));
            keep.push(tx("The credentials of the repository's storage (from that file), kept like passwords.", &[]));
        }
        items.push(Item {
            id: "restic".into(),
            kind: "restic".into(),
            essential: false,
            title: tx("restic repository", &[]),
            what: tx("A separate backup of your folders, made by restic from a full copy on one device.", &[]),
            why: tx("It can be restored with restic alone, without Varsto and without the vault key.", &[]),
            location,
            keep,
            missing: tx("Without its password the restic repository cannot be read; restic has no way to recover it either.", &[]),
            status: Status::Check,
            status_note: None,
            literal: vec![],
        });
    }

    if !inputs.other_devices.is_empty() {
        items.push(Item {
            id: "devices".into(),
            kind: "devices".into(),
            essential: false,
            title: tx("Your other devices", &[]),
            what: tx("Devices of this vault: {devices}", &[("devices", &inputs.other_devices.join(", "))]),
            why: tx("If any one of them survives, it can add the new device with a pairing code; the words are not needed then.", &[]),
            location: vec![],
            keep: vec![],
            missing: tx("Nothing more: this package is for when none of them is left.", &[]),
            status: Status::Info,
            status_note: None,
            literal: vec![],
        });
    }
    for r in &inputs.replicas {
        items.push(Item {
            id: format!("replica:{r}"),
            kind: "replica".into(),
            essential: false,
            title: tx("Replica «{name}»", &[("name", r)]),
            what: tx("An untrusted replica keeps an encrypted copy of every object of the vault, without any key to open it.", &[]),
            why: tx("If the storages are gone, its copy directory can be added on the new device as a directory storage.", &[]),
            location: vec![],
            keep: vec![tx("Who runs the replica and where its copy directory is.", &[])],
            missing: tx("Nothing, while the storages survive.", &[]),
            status: Status::Info,
            status_note: None,
            literal: vec![],
        });
    }

    // ----- the restore ----------------------------------------------------
    steps.push(install_step());
    steps.push(Step {
        id: "shares".into(),
        title: tx("Only shares of the kit? Rebuild the words", &[]),
        notes: vec![tx(
            "With two of the three shares this prints the 24 words.",
            &[],
        )],
        commands: vec![
            "varsto recovery combine \"<index>: <24 words>\" \"<index>: <24 words>\"".into(),
        ],
    });

    // Join through a storage that holds the records: a bucket first (it
    // survives a fire), then a directory; never a pool, a transferrer or
    // cold storage while there is another.
    let joinable = |s: &&StorageSpec| {
        matches!(s, StorageSpec::S3 { .. } | StorageSpec::LocalDir { .. }) && !s.is_carrier()
    };
    let join_with = inputs
        .storages
        .iter()
        .filter(joinable)
        .min_by_key(|s| (s.is_cold(), !matches!(s, StorageSpec::S3 { .. })));
    let mut join = Step {
        id: "join".into(),
        title: tx("Join the vault with the recovery words", &[]),
        notes: vec![],
        commands: vec![],
    };
    match join_with {
        Some(StorageSpec::S3 {
            name,
            endpoint,
            region,
            bucket,
            prefix,
            ..
        }) => {
            join.notes.push(tx(
                "Through bucket {bucket} (storage {storage}). Varsto reads the secret access key from the variable VARSTO_S3_SECRET; the first line sets it without showing it or keeping it in the shell history (bash, zsh).",
                &[("bucket", bucket), ("storage", name)],
            ));
            join.commands
                .push("read -rs VARSTO_S3_SECRET && export VARSTO_S3_SECRET".into());
            let mut c = format!(
                "varsto join --words {} --storage-name {} --s3-endpoint {} --s3-bucket {} --s3-region {}",
                quote(WORDS),
                quote(name),
                quote(endpoint),
                quote(bucket),
                quote(region)
            );
            if !prefix.is_empty() {
                c.push_str(&format!(" --s3-prefix {}", quote(prefix)));
            }
            c.push_str(" --s3-access-key-id \"<access key ID>\"");
            join.commands.push(c);
        }
        Some(StorageSpec::LocalDir { name, path, .. }) => {
            let path = path.display().to_string();
            join.notes.push(tx(
                "Through the directory of storage {storage}: mount the disk, NAS or share first. It was at {path}; give the path it has on the new device.",
                &[("storage", name), ("path", &path)],
            ));
            join.commands.push(format!(
                "varsto join --words {} --storage-name {} --storage-path {}",
                quote(WORDS),
                quote(name),
                quote(&path)
            ));
        }
        _ => {
            if let Some(StorageSpec::Rclone { remote, .. }) = inputs
                .storages
                .iter()
                .find(|s| matches!(s, StorageSpec::Rclone { .. }))
            {
                join.notes.push(tx(
                    "Joining needs a directory or a bucket. Mount the rclone remote {remote} as a directory first (`rclone mount`), join through it, then add the remote as a storage and remove the directory storage.",
                    &[("remote", remote)],
                ));
                join.commands.push(format!(
                    "rclone mount {} \"<empty directory>\" --daemon",
                    quote(remote)
                ));
                join.commands.push(format!(
                    "varsto join --words {} --storage-name mounted --storage-path \"<empty directory>\"",
                    quote(WORDS)
                ));
            } else {
                join.notes.push(tx(
                    "This vault has no storage a new device can join through yet: add a bucket or a directory outside this device.",
                    &[],
                ));
            }
        }
    }
    join.notes.push(tx(
        "Varsto asks for a passphrase for the new device. The words stay in the shell history: clear it afterwards.",
        &[],
    ));
    steps.push(join);

    if let Some(org) = &inputs.org {
        steps.push(Step {
            id: "org".into(),
            title: tx("Organization «{org}»", &[("org", &org.name)]),
            notes: vec![
                tx("A device that joins with the words reads everything, but the other devices ignore what it writes until an administrator adds it to the organization. If an administrator device survives, add the new device there:", &[]),
                tx("If no administrator device is left, the root words can appoint an administrator only among devices already in the organization; the data stays readable with the recovery words.", &[]),
            ],
            commands: vec![
                "varsto org add-device \"<new device>\" --user \"<your name>\"".into(),
                "varsto org admin add \"<device>\" --root-words \"<24 root words>\"".into(),
            ],
        });
    }

    let join_name = join_with.map(|s| s.name().to_string());
    let mut add = Step {
        id: "storages".into(),
        title: tx("Add the other storages with the same names", &[]),
        notes: vec![tx(
            "Use the same names: placement rules, policies and disk pools refer to storages by name. Enter the secret keys when asked, or set VARSTO_S3_SECRET as above before each bucket.",
            &[],
        )],
        commands: vec![],
    };
    let mut has_rclone = false;
    for spec in &inputs.storages {
        if Some(spec.name()) == join_name.as_deref() || spec.is_carrier() {
            continue;
        }
        let place = place_of(spec)
            .map(|p| format!(" --place {}", quote(&p)))
            .unwrap_or_default();
        let cold = if spec.is_cold() { " --cold" } else { "" };
        match spec {
            StorageSpec::S3 {
                name,
                endpoint,
                region,
                bucket,
                prefix,
                path_style,
                storage_class,
                ..
            } => {
                let mut c = format!(
                    "varsto storage add-s3 {} --endpoint {} --region {} --bucket {}",
                    quote(name),
                    quote(endpoint),
                    quote(region),
                    quote(bucket)
                );
                if !prefix.is_empty() {
                    c.push_str(&format!(" --prefix {}", quote(prefix)));
                }
                c.push_str(" --access-key-id \"<access key ID>\"");
                if !path_style {
                    c.push_str(" --virtual-host");
                }
                if let Some(class) = storage_class {
                    c.push_str(&format!(" --storage-class {}", quote(class)));
                }
                c.push_str(cold);
                c.push_str(&place);
                add.commands.push(c);
            }
            StorageSpec::Rclone { name, remote, .. } => {
                has_rclone = true;
                add.commands.push(format!(
                    "varsto storage add-rclone {} {}{cold}{place}",
                    quote(name),
                    quote(remote)
                ));
            }
            StorageSpec::LocalDir { name, path, .. } => {
                add.commands.push(format!(
                    "varsto storage add-local {} {}{cold}{place}",
                    quote(name),
                    quote(&path.display().to_string())
                ));
            }
            StorageSpec::Pool { name, copies, .. } => {
                let copies = if *copies > 1 {
                    format!(" --copies {copies}")
                } else {
                    String::new()
                };
                add.commands.push(format!(
                    "varsto storage add-pool {}{place}{copies}",
                    quote(name)
                ));
            }
        }
    }
    if has_rclone {
        add.notes.push(tx(
            "Before the rclone remotes: install rclone and put the saved rclone.conf where `rclone config file` says (or set the remotes up again with `rclone config`); `rclone listremotes` shows them.",
            &[],
        ));
    }
    if inputs
        .storages
        .iter()
        .any(|s| matches!(s, StorageSpec::LocalDir { carrier: false, .. }))
    {
        add.notes.push(tx(
            "A directory storage that was on the lost device's own disk is gone: leave it out. For a NAS or a disk, give the path it has on the new device.",
            &[],
        ));
    }
    if !add.commands.is_empty() {
        steps.push(add);
    }

    for spec in &inputs.storages {
        if let StorageSpec::Pool { name, disks, .. } = spec {
            let labels: Vec<String> = disks
                .iter()
                .filter(|d| !d.retired)
                .map(|d| format!("«{}»", d.label))
                .collect();
            let mut notes = vec![tx(
                "Bring the disks of pool {pool} and connect them one at a time: {disks}.",
                &[("pool", name), ("disks", &labels.join(", "))],
            )];
            let mut commands = vec![];
            if inputs.disk_conf.iter().any(|(_, p, _)| p == name) {
                notes.push(tx(
                    "Linux: put the disks.conf lines saved with this guide into the file disks.conf of Varsto's device directory; then `varsto disk insert` mounts each disk, checks it and brings it up to date.",
                    &[],
                ));
                commands.push("varsto disk insert".into());
            }
            notes.push(tx(
                "Elsewhere, mount the disk as usual: Varsto recognises a disk of the pool by its marker when it is attached, and `varsto disk list` shows it.",
                &[],
            ));
            commands.push("varsto disk list".into());
            steps.push(Step {
                id: format!("pool:{name}"),
                title: tx("Disks of pool «{pool}»", &[("pool", name)]),
                notes,
                commands,
            });
        }
    }

    let mut attach = Step {
        id: "folders".into(),
        title: tx("Attach the folders", &[]),
        notes: vec![tx(
            "Give each folder a directory on the new device. With --selective its files appear as placeholders and are fetched when opened, which is quicker to start with.",
            &[],
        )],
        commands: vec![],
    };
    for f in &inputs.folders {
        if let Some(p) = &f.path {
            attach.notes.push(tx(
                "Folder «{folder}» was at {path} on {device}.",
                &[("folder", &f.name), ("path", p), ("device", &inputs.device)],
            ));
        }
        attach.commands.push(format!(
            "varsto folder attach {} \"<directory>\"{}",
            quote(&f.name),
            if f.selective || f.strongroom {
                " --selective"
            } else {
                ""
            }
        ));
    }
    attach.commands.push("varsto sync".into());
    steps.push(attach);

    if !inputs.strongrooms.is_empty() {
        steps.push(Step {
            id: "strongroom".into(),
            title: tx("Open the Strongroom folders with a security key", &[]),
            notes: vec![
                tx("Install the libfido2 tools (fido2-cred, fido2-assert), insert one of the folder's security keys and touch it when asked. Without any of its keys the folder stays closed: that is what a Strongroom is for.", &[]),
            ],
            commands: inputs
                .strongrooms
                .iter()
                .map(|s| format!("varsto strongroom unlock {}", quote(&s.folder)))
                .collect(),
        });
    }

    if !inputs.backups.is_empty() {
        steps.push(Step {
            id: "backups".into(),
            title: tx("Restore the backups", &[]),
            notes: inputs
                .backups
                .iter()
                .map(|b| {
                    tx(
                        "Backup «{backup}» was taken from {path}.",
                        &[("backup", &b.name), ("path", &b.source)],
                    )
                })
                .collect(),
            commands: inputs
                .backups
                .iter()
                .map(|b| {
                    format!(
                        "varsto backup restore {} --to \"<empty directory>\"",
                        quote(&b.name)
                    )
                })
                .collect(),
        });
    }

    let colds: Vec<&StorageSpec> = inputs.storages.iter().filter(|s| s.is_cold()).collect();
    if !colds.is_empty() {
        let hot = inputs
            .storages
            .iter()
            .find(|s| !s.is_cold() && !s.is_carrier() && !s.is_data_only())
            .map(|s| s.name().to_string())
            .unwrap_or_else(|| "<hot storage>".to_string());
        let mut commands = vec!["varsto repair --from-cold".to_string()];
        for c in &colds {
            commands.push(format!(
                "varsto move \"<folder>\" --from {} --to {} --confirm-cold-read",
                quote(c.name()),
                quote(&hot)
            ));
        }
        steps.push(Step {
            id: "cold".into(),
            title: tx("Files that are only on cold storage", &[]),
            notes: vec![
                tx("Syncing never reads cold storage. Files whose blocks are only there show as unavailable until they are copied back; that may cost retrieval fees, and archive classes need a restore request at the provider first.", &[]),
            ],
            commands,
        });
    }

    let mut lost: Vec<String> = inputs.other_devices.clone();
    lost.push(inputs.device.clone());
    let mut after = Step {
        id: "after".into(),
        title: tx("Afterwards: remove the lost devices and print a new kit", &[]),
        notes: vec![
            tx(
                "Removing a lost device gives the vault new keys it never sees. Print a new recovery kit after that and keep it where the old one was, and make this guide again.",
                &[],
            ),
            tx(
                "If the new device has the same name as a lost one, give the lost one's id from `varsto device list` instead of its name.",
                &[],
            ),
        ],
        commands: std::iter::once("varsto device list".to_string())
            .chain(lost.iter().map(|d| format!("varsto device revoke {}", quote(d))))
            .collect(),
    };
    after.commands.push("varsto recovery kit".into());
    after
        .commands
        .push("varsto recovery guide --format html --output recovery-guide.html".into());
    steps.push(after);

    if let Some(r) = &inputs.restic {
        let mut notes = vec![tx(
            "Without Varsto: install restic, then list the snapshots and restore the newest into an empty directory. restic asks for the repository's password.",
            &[],
        )];
        if r.env_file.is_some() {
            notes.push(tx("Set the repository's credentials (the variables of the saved credentials file) in the shell first.", &[]));
        }
        alternatives.push(Step {
            id: "restic".into(),
            title: tx("Restore from the restic repository", &[]),
            notes,
            commands: vec![
                format!("restic -r {} snapshots --tag varsto", quote(&r.repository)),
                format!(
                    "restic -r {} restore latest --tag varsto --target \"<empty directory>\"",
                    quote(&r.repository)
                ),
            ],
        });
    }

    RecoveryGuide {
        vault_id: inputs.vault_id.clone(),
        device: inputs.device.clone(),
        generated_utc: inputs.now_utc,
        member: false,
        intro,
        items,
        steps,
        alternatives,
    }
}

fn install_step() -> Step {
    Step {
        id: "install".into(),
        title: tx("Install Varsto on the new computer", &[]),
        notes: vec![
            tx("Download Varsto from {site} and unpack it. Check the download against the signed checksums before you trust it:", &[("site", DOWNLOAD_SITE)]),
        ],
        commands: vec!["varsto verify-release \"<downloaded file>\" --github".into()],
    }
}

// ----- rendering -------------------------------------------------------------

fn status_mark(s: Status) -> &'static str {
    match s {
        Status::Done => "[x]",
        Status::Outdated => "[!]",
        Status::Check => "[ ]",
        Status::Info => " - ",
    }
}

/// Plain text for a terminal or a .txt file.
pub fn render_text(g: &RecoveryGuide) -> String {
    let mut t = String::new();
    t.push_str("VARSTO RECOVERY PACKAGE\n=======================\n\n");
    for p in &g.intro {
        t.push_str(&wrap(&p.render(), 78, ""));
        t.push('\n');
    }
    t.push_str("\nWHAT TO KEEP\n------------\n");
    for i in &g.items {
        t.push('\n');
        t.push_str(&format!(
            "{} {}{}\n",
            status_mark(i.status),
            i.title.render(),
            if i.essential { "" } else { " (optional)" }
        ));
        if let Some(n) = &i.status_note {
            t.push_str(&wrap(&n.render(), 78, "    "));
        }
        for (label, text) in [("What", &i.what), ("Why", &i.why)] {
            t.push_str(&wrap(&format!("{label}: {}", text.render()), 78, "    "));
        }
        for l in &i.location {
            t.push_str(&wrap(&l.render(), 78, "    * "));
        }
        for k in &i.keep {
            t.push_str(&wrap(&format!("Keep: {}", k.render()), 78, "    "));
        }
        for l in &i.literal {
            t.push_str(&format!("      {l}\n"));
        }
        t.push_str(&wrap(
            &format!("If missing: {}", i.missing.render()),
            78,
            "    ",
        ));
    }
    t.push_str("\nRESTORING ON A NEW DEVICE\n-------------------------\n");
    for (n, s) in g.steps.iter().enumerate() {
        step_text(&mut t, &format!("{}.", n + 1), s);
    }
    if !g.alternatives.is_empty() {
        t.push_str("\nWITHOUT VARSTO\n--------------\n");
        for s in &g.alternatives {
            step_text(&mut t, "-", s);
        }
    }
    t
}

fn step_text(t: &mut String, num: &str, s: &Step) {
    t.push('\n');
    t.push_str(&format!("{num} {}\n", s.title.render()));
    for n in &s.notes {
        t.push_str(&wrap(&n.render(), 78, "   "));
    }
    for c in &s.commands {
        t.push_str(&format!("     $ {c}\n"));
    }
}

/// Word-wrapped lines, the first with `prefix`, the rest indented as deep.
fn wrap(text: &str, width: usize, prefix: &str) -> String {
    let indent = " ".repeat(prefix.chars().count());
    let mut out = String::new();
    let mut line = prefix.to_string();
    let mut empty = true;
    for w in text.split_whitespace() {
        if !empty && line.chars().count() + 1 + w.chars().count() > width {
            out.push_str(&line);
            out.push('\n');
            line = indent.clone();
            empty = true;
        }
        if !empty {
            line.push(' ');
        }
        line.push_str(w);
        empty = false;
    }
    out.push_str(&line);
    out.push('\n');
    out
}

pub fn render_markdown(g: &RecoveryGuide) -> String {
    let mut t = String::from("# Varsto recovery package\n\n");
    for p in &g.intro {
        t.push_str(&p.render());
        t.push_str("\n\n");
    }
    t.push_str("## What to keep\n");
    for i in &g.items {
        let mark = match i.status {
            Status::Done => "- [x] ",
            Status::Outdated | Status::Check => "- [ ] ",
            Status::Info => "- ",
        };
        t.push_str(&format!(
            "\n{mark}**{}**{}\n",
            i.title.render(),
            if i.essential { "" } else { " (optional)" }
        ));
        if let Some(n) = &i.status_note {
            t.push_str(&format!("  - *{}*\n", n.render()));
        }
        t.push_str(&format!(
            "  - What: {}\n  - Why: {}\n",
            i.what.render(),
            i.why.render()
        ));
        for l in &i.location {
            t.push_str(&format!("  - {}\n", l.render()));
        }
        for k in &i.keep {
            t.push_str(&format!("  - Keep: {}\n", k.render()));
        }
        if !i.literal.is_empty() {
            t.push_str("\n    ```text\n");
            for l in &i.literal {
                t.push_str(&format!("    {l}\n"));
            }
            t.push_str("    ```\n\n");
        }
        t.push_str(&format!("  - If missing: {}\n", i.missing.render()));
    }
    t.push_str("\n## Restoring on a new device\n");
    for (n, s) in g.steps.iter().enumerate() {
        step_md(&mut t, &format!("{}. ", n + 1), s);
    }
    if !g.alternatives.is_empty() {
        t.push_str("\n## Without Varsto\n");
        for s in &g.alternatives {
            step_md(&mut t, "", s);
        }
    }
    t
}

fn step_md(t: &mut String, num: &str, s: &Step) {
    t.push_str(&format!("\n### {num}{}\n\n", s.title.render()));
    for n in &s.notes {
        t.push_str(&n.render());
        t.push_str("\n\n");
    }
    if !s.commands.is_empty() {
        t.push_str("```sh\n");
        for c in &s.commands {
            t.push_str(c);
            t.push('\n');
        }
        t.push_str("```\n");
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A printable page with checkboxes.
pub fn render_html(g: &RecoveryGuide) -> String {
    let mut t = String::from(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Varsto recovery package</title>\n<style>\nbody{font:15px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#111;background:#fff}\nh1{font-size:1.6rem}h2{margin-top:2rem;border-bottom:1px solid #ccc}h3{font-size:1.05rem;margin:1.4rem 0 .3rem}\n.item{border:1px solid #ccc;border-radius:6px;padding:.6rem .8rem;margin:.8rem 0;break-inside:avoid}\n.item label{font-weight:600;display:flex;gap:.5rem;align-items:baseline}\n.item ul{margin:.3rem 0 0 1.6rem;padding:0}.note{font-style:italic}.outdated{color:#a40000}\npre{background:#f4f4f4;padding:.5rem .7rem;border-radius:4px;white-space:pre-wrap;word-break:break-all;font-size:13px}\ncode{font-size:13px}.optional{font-weight:400;color:#555}\n@media print{body{margin:0;max-width:none}pre{border:1px solid #ccc}}\n</style></head><body>\n<h1>Varsto recovery package</h1>\n",
    );
    for p in &g.intro {
        t.push_str(&format!("<p>{}</p>\n", esc(&p.render())));
    }
    t.push_str("<h2>What to keep</h2>\n");
    for i in &g.items {
        t.push_str("<div class=\"item\">");
        let checked = if i.status == Status::Done {
            " checked"
        } else {
            ""
        };
        if i.status == Status::Info {
            t.push_str(&format!("<label>{}</label>", esc(&i.title.render())));
        } else {
            t.push_str(&format!(
                "<label><input type=\"checkbox\"{checked}> {}{}</label>",
                esc(&i.title.render()),
                if i.essential {
                    ""
                } else {
                    " <span class=\"optional\">(optional)</span>"
                }
            ));
        }
        if let Some(n) = &i.status_note {
            let cls = if i.status == Status::Outdated {
                "note outdated"
            } else {
                "note"
            };
            t.push_str(&format!("<div class=\"{cls}\">{}</div>", esc(&n.render())));
        }
        t.push_str("<ul>");
        t.push_str(&format!(
            "<li>What: {}</li><li>Why: {}</li>",
            esc(&i.what.render()),
            esc(&i.why.render())
        ));
        for l in &i.location {
            t.push_str(&format!("<li>{}</li>", esc(&l.render())));
        }
        for k in &i.keep {
            t.push_str(&format!("<li>Keep: {}</li>", esc(&k.render())));
        }
        t.push_str(&format!(
            "<li>If missing: {}</li></ul>",
            esc(&i.missing.render())
        ));
        if !i.literal.is_empty() {
            t.push_str(&format!("<pre>{}</pre>", esc(&i.literal.join("\n"))));
        }
        t.push_str("</div>\n");
    }
    t.push_str("<h2>Restoring on a new device</h2>\n");
    for (n, s) in g.steps.iter().enumerate() {
        step_html(&mut t, &format!("{}. ", n + 1), s);
    }
    if !g.alternatives.is_empty() {
        t.push_str("<h2>Without Varsto</h2>\n");
        for s in &g.alternatives {
            step_html(&mut t, "", s);
        }
    }
    t.push_str("</body></html>\n");
    t
}

fn step_html(t: &mut String, num: &str, s: &Step) {
    t.push_str(&format!("<h3>{num}{}</h3>\n", esc(&s.title.render())));
    for n in &s.notes {
        t.push_str(&format!("<p>{}</p>\n", esc(&n.render())));
    }
    if !s.commands.is_empty() {
        t.push_str(&format!("<pre>{}</pre>\n", esc(&s.commands.join("\n"))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_fills_known_placeholders_only() {
        let t = tx("A {x} and {y} and {", &[("x", "b{y}")]);
        assert_eq!(t.render(), "A b{y} and {y} and {");
    }

    #[test]
    fn repositories_lose_their_passwords() {
        assert_eq!(
            redact_repository("rest:https://bob:hunter2@backup.example:8000/repo"),
            "rest:https://<user>:<password>@backup.example:8000/repo"
        );
        assert_eq!(
            redact_repository("sftp:bob@host:/srv/restic"),
            "sftp:bob@host:/srv/restic"
        );
        assert_eq!(
            redact_repository("/mnt/backup/restic"),
            "/mnt/backup/restic"
        );
        assert_eq!(day(0), "1970-01-01");
        assert_eq!(day(1_791_849_600), "2026-10-13");
    }

    #[test]
    fn quoting_escapes_what_the_shell_expands() {
        assert_eq!(quote("a \"b\" $c"), "\"a \\\"b\\\" \\$c\"");
    }
}
