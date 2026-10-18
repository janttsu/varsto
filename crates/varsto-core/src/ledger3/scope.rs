// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Who may make which event (`docs/spec/format-3-design.md` sections 4
//! and 9; the scopes of `alpha-0-format.md` section 58 with the format-3
//! events). Events outside the signer's scope are left out when the batch
//! is applied and counted in `LedgerView::events_refused`.
//!
//! Some rules depend on what the view knows about a pack (a member may
//! verify only packs of its folder and drop only packs it stored). Batches
//! arrive in any order, so those events are kept aside with their
//! condition and decided once every batch is applied (`LedgerView::finish`),
//! which keeps application order-independent.

use super::envelope::kind;
use super::events::Event;
use super::{DeviceBin, FolderBin, NO_FOLDER};

/// Key id prefixes of batch envelopes (section 1).
pub const KEY_LEDGER_PREFIX: &str = "ledger@";
pub const KEY_REPLICA: &str = "replica";
pub const KEY_SHARE_LEDGER_PREFIX: &str = "share-ledger:";

/// The role a batch is read with.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EventScope {
    /// A trusted full device of the vault (or a removed one, up to its
    /// cut-off): every event.
    Full,
    /// A replica: claims and verifications of whole packs, no folder.
    Replica,
    /// A member device of a shared folder (its folder-scoped batches).
    Member(FolderBin),
    /// A member with the viewer role: only verifications of its folder's
    /// packs (section 9). Its batches carry the member key id; the engine
    /// gives this scope from the folder record's role.
    Viewer(FolderBin),
    /// A full device of the vault writing for a folder shared with other
    /// people, in a folder-scoped batch the members can read: claims and
    /// announcements of that folder, verifications and drops of packs.
    Owner(FolderBin),
}

/// The key id of a full device's batches under vault epoch `e`.
pub fn ledger_key_id(epoch: u32) -> String {
    format!("{KEY_LEDGER_PREFIX}{epoch}")
}

/// The key id of a member's folder-scoped batches under folder epoch `e`.
pub fn share_ledger_key_id(folder: &FolderBin, epoch: u32) -> String {
    format!("{KEY_SHARE_LEDGER_PREFIX}{}@{epoch}", hex::encode(folder))
}

fn epoch_digits(s: &str) -> bool {
    !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Folder roles of full devices, from the folder records (section 9): a
/// full device's batch counts in full for the vault, but its claims that
/// name a folder and its announcements of a folder's manifests, maps and
/// trash count only while it is an owner or editor of that folder. Copies
/// of whole packs (zero folder), verifications, drops and retirements stay
/// with every full device, as for a device that holds the vault key alone.
pub trait FolderRoles {
    /// Whether `device` was an owner or editor of `folder` at Lamport time
    /// `lamport`; `None` when the folder is not known (no judgement).
    fn writes_at(&self, device: &DeviceBin, folder: &FolderBin, lamport: u64) -> Option<bool>;
}

/// No folder roles known: a full device's events all count.
pub struct NoRoles;

impl FolderRoles for NoRoles {
    fn writes_at(&self, _: &DeviceBin, _: &FolderBin, _: u64) -> Option<bool> {
        None
    }
}

/// The folder a full device's event writes for, if it writes for one: a
/// claim naming a folder, or an announcement of a folder's manifest, map
/// or trash record.
pub fn folder_written(ev: &Event) -> Option<FolderBin> {
    match ev {
        Event::PackStored(p) if p.folder != NO_FOLDER => Some(p.folder),
        Event::RecordPublished(a)
            if a.scope != NO_FOLDER
                && matches!(a.kind, kind::MANIFEST | kind::BLOCK_MAP | kind::TRASH) =>
        {
            Some(a.scope)
        }
        _ => None,
    }
}

/// What an event in a scope needs before it counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allow {
    Yes,
    No,
    /// A member's verification: the pack must be of the member's folder.
    IfPackOfFolder,
    /// A member's claim: the pack must not be another folder's.
    IfNotOtherFolder,
    /// A member's drop: the pack must be of its folder and stored by it.
    IfStoredBySigner,
}

impl EventScope {
    /// The folder of a member's or viewer's scope.
    pub fn folder(&self) -> Option<&FolderBin> {
        match self {
            EventScope::Member(f) | EventScope::Viewer(f) | EventScope::Owner(f) => Some(f),
            _ => None,
        }
    }

    /// The scope a key id implies on its own (the engine also checks that
    /// the signer has that role): `ledger@<e>` full devices, `replica`
    /// replicas, `share-ledger:<folder>@<e>` members of the folder.
    pub fn of_key_id(key_id: &str) -> Option<EventScope> {
        if let Some(e) = key_id.strip_prefix(KEY_LEDGER_PREFIX) {
            return epoch_digits(e).then_some(EventScope::Full);
        }
        if key_id == KEY_REPLICA {
            return Some(EventScope::Replica);
        }
        let rest = key_id.strip_prefix(KEY_SHARE_LEDGER_PREFIX)?;
        let (folder, epoch) = rest.split_once('@')?;
        if !epoch_digits(epoch) || folder.len() != 32 {
            return None;
        }
        let bytes = hex::decode(folder).ok()?;
        let f: FolderBin = bytes.try_into().ok()?;
        (f != NO_FOLDER).then_some(EventScope::Member(f))
    }

    /// The `scope` field a batch envelope of this role carries: the folder
    /// for members, zeros otherwise. An envelope with another scope does
    /// not count.
    pub fn record_scope(&self) -> FolderBin {
        match self {
            EventScope::Member(f) | EventScope::Viewer(f) | EventScope::Owner(f) => *f,
            _ => NO_FOLDER,
        }
    }

    /// Whether an event counts in this scope, or on what condition.
    /// `device_enrolled` (the signer's own name) counts in every scope.
    pub fn allows(&self, ev: &Event) -> Allow {
        let yes = |b: bool| if b { Allow::Yes } else { Allow::No };
        match (self, ev) {
            (EventScope::Full, _) | (_, Event::DeviceEnrolled(_)) => Allow::Yes,
            (EventScope::Replica, Event::PackStored(p)) => {
                yes(p.folder == NO_FOLDER && p.map_seq == 0)
            }
            (EventScope::Replica, Event::PackVerified(_)) => Allow::Yes,
            (EventScope::Replica, _) => Allow::No,
            (EventScope::Member(f), Event::PackStored(p)) => {
                if p.folder == *f {
                    Allow::IfNotOtherFolder
                } else {
                    Allow::No
                }
            }
            (EventScope::Member(_), Event::PackVerified(_)) => Allow::IfPackOfFolder,
            (EventScope::Member(_), Event::PackDropped(_)) => Allow::IfStoredBySigner,
            (EventScope::Member(f), Event::RecordPublished(a)) => {
                yes(a.scope == *f
                    && matches!(a.kind, kind::MANIFEST | kind::BLOCK_MAP | kind::TRASH))
            }
            // Never folders, retirements, snapshots or backups.
            (EventScope::Member(_), _) => Allow::No,
            (EventScope::Viewer(_), Event::PackVerified(_)) => Allow::IfPackOfFolder,
            (EventScope::Viewer(_), _) => Allow::No,
            (EventScope::Owner(f), Event::PackStored(p)) => yes(p.folder == *f),
            (EventScope::Owner(f), Event::RecordPublished(a)) => yes(a.scope == *f),
            (EventScope::Owner(_), Event::PackVerified(_) | Event::PackDropped(_)) => Allow::Yes,
            (EventScope::Owner(_), _) => Allow::No,
        }
    }
}
