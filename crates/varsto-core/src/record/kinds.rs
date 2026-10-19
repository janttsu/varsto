// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The kind table, stream names and `key_id` grammar of format 3
//! (`docs/spec/format-3-design.md`, sections 1 and 5).

use super::Id16;
use std::fmt;

/// Longest `key_id` (bytes).
pub const MAX_KEY_ID: usize = 64;

/// The kinds of signed records (section 5, kind table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Manifest = 1,
    BlockMap = 2,
    Trash = 3,
    Snapshot = 4,
    Peer = 5,
    Epoch = 6,
    ShareEpoch = 7,
    Grant = 8,
    Request = 9,
    Revocation = 10,
    Policy = 11,
    Placement = 12,
    Checkpoint = 13,
    Batch = 14,
    Folder = 15,
    Device = 16,
    Escrow = 17,
    Settings = 18,
    StorageNames = 19,
    Access = 20,
    Notes = 21,
    Thumbs = 22,
    /// A replica enrolled by a full device (its K6 public key and name).
    Replica = 23,
    /// A Strongroom folder's K13 wraps per FIDO2 credential (and the
    /// optional K2 escrow of K13).
    Strongroom = 24,
    /// An organization's manifest, roster and log: today's signed bodies
    /// inside a signed record.
    OrgManifest = 25,
    OrgRoster = 26,
    OrgLog = 27,
    /// A device's mailbox board: what it holds staged for pool disks.
    Mailbox = 28,
}

/// One segment of a stream's storage path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seg {
    Lit(&'static str),
    /// The envelope's `scope`, hex.
    Scope,
    /// The scope, or the word `vault` for the zero scope (grants).
    ScopeOrVault,
    /// The envelope's `device`, hex.
    Device,
    /// A folder or vault epoch, 10 digits (grants, escrow).
    Epoch,
    /// The device a grant is for, hex.
    Recipient,
}

use Seg::*;

impl Kind {
    pub const ALL: [Kind; 28] = [
        Kind::Manifest,
        Kind::BlockMap,
        Kind::Trash,
        Kind::Snapshot,
        Kind::Peer,
        Kind::Epoch,
        Kind::ShareEpoch,
        Kind::Grant,
        Kind::Request,
        Kind::Revocation,
        Kind::Policy,
        Kind::Placement,
        Kind::Checkpoint,
        Kind::Batch,
        Kind::Folder,
        Kind::Device,
        Kind::Escrow,
        Kind::Settings,
        Kind::StorageNames,
        Kind::Access,
        Kind::Notes,
        Kind::Thumbs,
        Kind::Replica,
        Kind::Strongroom,
        Kind::OrgManifest,
        Kind::OrgRoster,
        Kind::OrgLog,
        Kind::Mailbox,
    ];

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: u8) -> Option<Kind> {
        Kind::ALL.iter().copied().find(|k| k.code() == code)
    }

    /// The kind name: the AEAD type of the body and the word in messages.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Manifest => "manifest",
            Kind::BlockMap => "block-map",
            Kind::Trash => "trash",
            Kind::Snapshot => "snapshot",
            Kind::Peer => "peer",
            Kind::Epoch => "epoch",
            Kind::ShareEpoch => "share-epoch",
            Kind::Grant => "grant",
            Kind::Request => "request",
            Kind::Revocation => "revocation",
            Kind::Policy => "policy",
            Kind::Placement => "placement",
            Kind::Checkpoint => "checkpoint",
            Kind::Batch => "batch",
            Kind::Folder => "folder",
            Kind::Device => "device",
            Kind::Escrow => "escrow",
            Kind::Settings => "settings",
            Kind::StorageNames => "storage-names",
            Kind::Access => "access",
            Kind::Notes => "notes",
            Kind::Thumbs => "thumbs",
            Kind::Replica => "replica",
            Kind::Strongroom => "strongroom",
            Kind::OrgManifest => "org-manifest",
            Kind::OrgRoster => "org-roster",
            Kind::OrgLog => "org-log",
            Kind::Mailbox => "mailbox",
        }
    }

    /// Whether a record of this kind counts only once a batch of its writer
    /// announces it (`record_published`); the others are "newest seq wins".
    pub fn announced(self) -> bool {
        matches!(
            self,
            Kind::Manifest | Kind::BlockMap | Kind::Trash | Kind::Snapshot
        )
    }

    /// Whether the storage name carries the scope (for the others the
    /// scope is checked from the envelope and the key_id only).
    pub fn scope_in_name(self) -> bool {
        self.segments()
            .iter()
            .any(|s| matches!(s, Scope | ScopeOrVault))
    }

    /// Whether the writing device is part of the storage name (vault and
    /// folder epochs are named by their number alone).
    pub fn device_in_name(self) -> bool {
        self.segments().contains(&Device)
    }

    fn segments(self) -> &'static [Seg] {
        match self {
            Kind::Manifest => &[Lit("manifests"), Scope, Device],
            Kind::BlockMap => &[Lit("maps"), Scope, Device],
            Kind::Trash => &[Lit("trash"), Scope, Device],
            Kind::Snapshot => &[Lit("snapshots"), Scope, Device],
            Kind::Peer => &[Lit("vault"), Lit("peers"), Device],
            Kind::Epoch => &[Lit("vault"), Lit("epochs")],
            Kind::ShareEpoch => &[Lit("vault"), Lit("folder-epochs"), Scope],
            Kind::Grant => &[
                Lit("vault"),
                Lit("grants"),
                ScopeOrVault,
                Epoch,
                Recipient,
                Device,
            ],
            Kind::Request => &[Lit("vault"), Lit("requests"), Scope, Device],
            Kind::Revocation => &[Lit("vault"), Lit("revocations"), Scope, Device],
            Kind::Policy => &[Lit("vault"), Lit("policy"), Device],
            Kind::Placement => &[Lit("vault"), Lit("placement"), Scope, Device],
            Kind::Checkpoint | Kind::Batch => &[Lit("ledger"), Device],
            Kind::Folder => &[Lit("vault"), Lit("folders"), Scope, Device],
            Kind::Device => &[Lit("vault"), Lit("devices"), Device],
            Kind::Escrow => &[Lit("vault"), Lit("escrow"), Scope, Epoch, Device],
            Kind::Settings => &[Lit("vault"), Lit("settings"), Device],
            Kind::StorageNames => &[Lit("vault"), Lit("storage-names"), Device],
            Kind::Access => &[Lit("access"), Scope, Device],
            Kind::Notes => &[Lit("notes"), Scope, Device],
            Kind::Thumbs => &[Lit("thumbs"), Scope, Device],
            Kind::Replica => &[Lit("vault"), Lit("replicas"), Device],
            Kind::Strongroom => &[Lit("vault"), Lit("strongroom"), Scope, Device],
            Kind::OrgManifest => &[Lit("vault"), Lit("org"), Lit("manifest"), Device],
            Kind::OrgRoster => &[Lit("vault"), Lit("org"), Lit("roster"), Device],
            Kind::OrgLog => &[Lit("vault"), Lit("org"), Lit("log"), Device],
            Kind::Mailbox => &[Lit("vault"), Lit("mailbox"), Device],
        }
    }

    /// Text between the last `/` of the prefix and `<seq>-<part>.rec`.
    fn file_prefix(self) -> &'static str {
        if self == Kind::Checkpoint {
            "checkpoint-"
        } else {
            ""
        }
    }

    /// Whether `key_id` may name the key of a record of this kind in
    /// `scope` (section 5's key_id column; for `share-epoch` also: the
    /// epoch of the key is the record's `seq`). A record whose key_id is
    /// of the wrong class is junk; a writer refuses to seal it.
    pub fn key_fits(self, key_id: &KeyId, scope: &Id16, seq: u64) -> bool {
        let zero = *scope == [0u8; 16];
        match (self, key_id) {
            (
                Kind::Manifest
                | Kind::BlockMap
                | Kind::Trash
                | Kind::Access
                | Kind::Notes
                | Kind::Thumbs,
                KeyId::Meta { folder, .. },
            ) => folder == scope,
            (Kind::Snapshot, KeyId::Meta { .. }) => true,
            (Kind::ShareEpoch, KeyId::Meta { folder, epoch }) => {
                folder == scope && u64::from(*epoch) == seq
            }
            (
                Kind::Peer
                | Kind::Policy
                | Kind::Settings
                | Kind::StorageNames
                | Kind::Device
                | Kind::Replica
                | Kind::OrgManifest
                | Kind::OrgRoster
                | Kind::OrgLog
                | Kind::Mailbox,
                KeyId::Registry(_),
            ) => zero,
            (Kind::Strongroom, KeyId::Registry(_)) => !zero,
            (Kind::Request | Kind::Placement | Kind::Folder, KeyId::Registry(_)) => true,
            (Kind::Request, KeyId::None) => true,
            (Kind::Revocation, KeyId::Registry(0)) => true,
            (Kind::Epoch, KeyId::Epoch(_)) => zero,
            (Kind::Grant, KeyId::Kem(_)) => true,
            (Kind::Checkpoint, KeyId::Ledger(_)) => zero,
            (Kind::Batch, KeyId::Ledger(_) | KeyId::Replica) => zero,
            (Kind::Batch, KeyId::ShareLedger { folder, .. }) => folder == scope,
            (Kind::Escrow, KeyId::Recovery) => true,
            _ => false,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Which key opens a record body (section 1). Inside every signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyId {
    /// `registry@<e>`: derive(K3ₑ, "device-registry").
    Registry(u32),
    /// `ledger@<e>`: derive(K3ₑ, "ledger").
    Ledger(u32),
    /// `epoch@<e>`: the vault epoch record key.
    Epoch(u32),
    /// `meta:<folder hex>@<e>`: K10ₑ of the folder.
    Meta { folder: Id16, epoch: u32 },
    /// `share-ledger:<folder hex>@<e>`.
    ShareLedger { folder: Id16, epoch: u32 },
    /// `kem:<recipient device hex>`: a grant to that device's K8.
    Kem(Id16),
    /// `recovery`: the escrow key under K2.
    Recovery,
    /// `replica`.
    Replica,
    /// `none`: the body is not encrypted (request codes only).
    None,
}

/// Parse an epoch number: decimal, no sign, no leading zeros.
fn parse_epoch(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// Parse 32 lower-case hex digits.
pub fn parse_id16(s: &str) -> Option<Id16> {
    if s.len() != 32 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 16];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

impl KeyId {
    /// Parse the grammar of section 1. Strict: lower-case hex, decimal
    /// epochs without leading zeros, at most `MAX_KEY_ID` bytes, so that
    /// one key has exactly one spelling.
    pub fn parse(s: &str) -> Option<KeyId> {
        if s.len() > MAX_KEY_ID {
            return None;
        }
        match s {
            "recovery" => return Some(KeyId::Recovery),
            "replica" => return Some(KeyId::Replica),
            "none" => return Some(KeyId::None),
            _ => {}
        }
        if let Some(hex) = s.strip_prefix("kem:") {
            return parse_id16(hex).map(KeyId::Kem);
        }
        let (name, epoch) = s.rsplit_once('@')?;
        let epoch = parse_epoch(epoch)?;
        match name {
            "registry" => Some(KeyId::Registry(epoch)),
            "ledger" => Some(KeyId::Ledger(epoch)),
            "epoch" => Some(KeyId::Epoch(epoch)),
            _ => {
                if let Some(hex) = name.strip_prefix("meta:") {
                    parse_id16(hex).map(|folder| KeyId::Meta { folder, epoch })
                } else if let Some(hex) = name.strip_prefix("share-ledger:") {
                    parse_id16(hex).map(|folder| KeyId::ShareLedger { folder, epoch })
                } else {
                    None
                }
            }
        }
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyId::Registry(e) => write!(f, "registry@{e}"),
            KeyId::Ledger(e) => write!(f, "ledger@{e}"),
            KeyId::Epoch(e) => write!(f, "epoch@{e}"),
            KeyId::Meta { folder, epoch } => write!(f, "meta:{}@{epoch}", hex::encode(folder)),
            KeyId::ShareLedger { folder, epoch } => {
                write!(f, "share-ledger:{}@{epoch}", hex::encode(folder))
            }
            KeyId::Kem(d) => write!(f, "kem:{}", hex::encode(d)),
            KeyId::Recovery => f.write_str("recovery"),
            KeyId::Replica => f.write_str("replica"),
            KeyId::None => f.write_str("none"),
        }
    }
}

/// One stream of records: everything that names where its records live.
/// `epoch` and `recipient` are used by grants and escrow (and `recipient`
/// is checked against the grant's `kem:` key_id); other kinds leave them
/// `None`. Kinds whose names carry no device (vault and folder epochs)
/// still set `device` to the writer: it is checked from the envelope only.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StreamRef {
    pub kind: Kind,
    pub scope: Id16,
    pub device: Id16,
    pub epoch: Option<u32>,
    pub recipient: Option<Id16>,
}

impl StreamRef {
    pub fn new(kind: Kind, scope: Id16, device: Id16) -> StreamRef {
        StreamRef {
            kind,
            scope,
            device,
            epoch: None,
            recipient: None,
        }
    }

    /// A grant stream: `vault/grants/<folder or vault>/<epoch>/<recipient>/<issuer>/`.
    pub fn grant(scope: Id16, epoch: u32, recipient: Id16, issuer: Id16) -> StreamRef {
        StreamRef {
            kind: Kind::Grant,
            scope,
            device: issuer,
            epoch: Some(epoch),
            recipient: Some(recipient),
        }
    }

    /// An escrow stream: `vault/escrow/<folder>/<epoch>/<device>/`.
    pub fn escrow(folder: Id16, epoch: u32, device: Id16) -> StreamRef {
        StreamRef {
            kind: Kind::Escrow,
            scope: folder,
            device,
            epoch: Some(epoch),
            recipient: None,
        }
    }

    /// The storage prefix every record name of this stream starts with;
    /// `<seq 16>-<part 4>.rec` follows it. `None` when a segment the kind
    /// needs (epoch, recipient) is missing.
    pub fn prefix(&self) -> Option<String> {
        let mut out = String::new();
        for seg in self.kind.segments() {
            match seg {
                Lit(s) => out.push_str(s),
                Scope => out.push_str(&hex::encode(self.scope)),
                ScopeOrVault => {
                    if self.scope == [0u8; 16] {
                        out.push_str("vault")
                    } else {
                        out.push_str(&hex::encode(self.scope))
                    }
                }
                Device => out.push_str(&hex::encode(self.device)),
                Epoch => out.push_str(&format!("{:010}", self.epoch?)),
                Recipient => out.push_str(&hex::encode(self.recipient?)),
            }
            out.push('/');
        }
        out.push_str(self.kind.file_prefix());
        Some(out)
    }

    /// The storage name of part `part` of record `seq`.
    pub fn part_name(&self, seq: u64, part: u16) -> Option<String> {
        Some(format!("{}{seq:016}-{part:04}.rec", self.prefix()?))
    }
}

/// A storage name taken apart (`<prefix>/<seq 16>-<part 4>.rec`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordName {
    pub kind: Kind,
    /// Zero for kinds whose name has no scope.
    pub scope: Id16,
    /// `None` for kinds whose name has no device.
    pub device: Option<Id16>,
    pub epoch: Option<u32>,
    pub recipient: Option<Id16>,
    pub seq: u64,
    pub part: u16,
}

/// `<seq 16 digits>-<part 4 digits>.rec`.
fn parse_file(s: &str) -> Option<(u64, u16)> {
    let s = s.strip_suffix(".rec")?;
    let (seq, part) = s.split_once('-')?;
    if seq.len() != 16 || part.len() != 4 {
        return None;
    }
    if !seq.bytes().chain(part.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((seq.parse().ok()?, part.parse().ok()?))
}

impl RecordName {
    /// Parse a storage name of `kind`. Strict: exactly the spelling
    /// `StreamRef::part_name` produces.
    pub fn parse_as(kind: Kind, name: &str) -> Option<RecordName> {
        let segs = kind.segments();
        let mut it = name.split('/');
        let mut out = RecordName {
            kind,
            scope: [0u8; 16],
            device: None,
            epoch: None,
            recipient: None,
            seq: 0,
            part: 0,
        };
        for seg in segs {
            let s = it.next()?;
            match seg {
                Lit(l) => {
                    if s != *l {
                        return None;
                    }
                }
                Scope => out.scope = parse_id16(s)?,
                ScopeOrVault => {
                    if s != "vault" {
                        out.scope = parse_id16(s)?;
                        if out.scope == [0u8; 16] {
                            return None;
                        }
                    }
                }
                Device => out.device = Some(parse_id16(s)?),
                Epoch => {
                    if s.len() != 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
                        return None;
                    }
                    out.epoch = Some(s.parse().ok()?);
                }
                Recipient => out.recipient = Some(parse_id16(s)?),
            }
        }
        let file = it.next()?;
        if it.next().is_some() {
            return None;
        }
        let file = file.strip_prefix(kind.file_prefix())?;
        let (seq, part) = parse_file(file)?;
        out.seq = seq;
        out.part = part;
        Some(out)
    }

    /// Parse a storage name of any kind (the first kind whose layout fits).
    pub fn parse(name: &str) -> Option<RecordName> {
        Kind::ALL
            .iter()
            .find_map(|k| RecordName::parse_as(*k, name))
    }
}
