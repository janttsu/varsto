// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Rebuilding a device's ledger on the pack-level format
//! (`docs/spec/format-3-design.md` sections 3 and 4; `alpha-0-format.md`
//! section 38 adapted; work package 10b). Built behind the `format3`
//! feature; nothing in the format-2 engine calls it.
//!
//! The scenario is a device whose local `ledger/` directory is gone. It
//! signed batches that the storages may or may not hold; signing a number
//! the storages hold already would fork the identity. [`rebuild`], signing
//! nothing until the end:
//!
//! 1. *Pull.* Every metadata storage is listed for `ledger/`; each device's
//!    newest checkpoint and the batches after it come back through the
//!    store's `ingest` (this device's own through `ingest_own_restored`,
//!    which moves its head past a gap no storage can fill). A storage that
//!    holds a second history of this identity under one number marks the
//!    identity forked, and the rebuild refuses: pair this computer again.
//! 2. *Gap check.* When another device said (signed `seen`) that it holds
//!    batches of this device that no storage returned, the next number is
//!    not free; `fill_own` (peer-to-peer, WP9) may supply them, otherwise
//!    the rebuild refuses rather than sign a number already used.
//! 3. *Reconstruct.* The events that were in lost batches are signed
//!    again in new batches: `pack_stored` for the packs this device's own
//!    block-map records name and that are on a storage at their class
//!    length; `pack_stored` for packs on a storage that no map of this
//!    device names and nobody claims, after their hash was verified (the
//!    `verify_pack` callback of WP5; no callback, no claim);
//!    `record_published` for its map and manifest records no accepted
//!    batch announces; `folder_added` for folders the engine holds that the
//!    ledger does not know; `device_enrolled` when nothing of this device
//!    was found at all. Claims the ledger has already are not repeated, so
//!    a second run changes nothing.
//! 4. *Push.* The new batches go to the hot metadata storages.
//!
//! # Report JSON (`varsto ledger rebuild --json`)
//!
//! `RebuildReport` serialises as one object: `own_head_before`,
//! `own_head_after`, `own_on_storage` (name to newest own batch listed),
//! `peer_seen`, `batches` (pulled), `checkpoints`, `refused`, `malformed`,
//! `forked_devices`, `own_records`, `claims_from_maps`,
//! `claims_from_listing`, `verified`, `unnamed_corrupt`, `announced`,
//! `folders_added`, `enrolled`, `new_batches` (seqs signed), `pushed_to`,
//! `skipped` (reasons in words). A refusal is an error with the codes
//! `forked`, `gap_needs_peers` and `storage_unreachable` and the text the
//! command line prints.
//!
//! Interpretations of the design (for review):
//! - The batch is "marked as a rebuild" only locally (`rebuild3.json` in
//!   `marker_dir` lists its seq and time): the ten events of section 4 are
//!   binding and a new wire event would be one more code older readers
//!   count as unknown.
//! - Own records of kinds other than maps and manifests (trash, snapshots)
//!   are not announced again: their body types are not part of this build.
//! - Folders whose own streams are read are those the ledger knows and
//!   those the caller passes; storages are not listed for folder names.

mod claims;
mod pull;

#[cfg(test)]
mod tests;

use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::fsck3::{StorageDesc, VerifyPack};
use crate::ledger3::checkpoint::batch_key;
use crate::ledger3::{DeviceBin, EventScope, FolderBin, LedgerStore, SignedRecord};
use crate::record::{Id16, RecordKeys, RecordTrust};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// What a rebuild needs from the engine.
pub struct RebuildInput<'a> {
    pub vault: Id16,
    pub me: DeviceBin,
    pub device_name: String,
    pub signer: &'a SigningKey,
    /// Seals this device's batches under `key_id` (`ledger@<epoch>`).
    pub ledger_key: &'a SecretKey,
    pub key_id: String,
    /// The key a ledger `key_id` names, if held.
    pub key_for: &'a dyn Fn(&str) -> Option<SecretKey>,
    /// The scope a device's batches under a key id are read with.
    pub scope_of: &'a dyn Fn(&DeviceBin, &str) -> Option<EventScope>,
    /// The signing key of a trusted device.
    pub pubkey_of: &'a dyn Fn(&DeviceBin) -> Option<VerifyingKey>,
    pub storages: &'a [StorageDesc<'a>],
    /// Folders whose keys this device holds.
    pub folders: Vec<FolderBin>,
    pub record_keys: &'a dyn RecordKeys,
    /// Signers and roles; announcements are taken from the rebuilt view.
    pub record_trust: &'a dyn RecordTrust,
    /// Per-pack verification (WP5); needed to claim packs no map names.
    pub verify_pack: Option<&'a VerifyPack<'a>>,
    /// Peer-to-peer seam (WP9): a batch of this device that another
    /// device holds and no storage does.
    pub fill_own: Option<&'a dyn Fn(u64) -> Option<SignedRecord>>,
    /// Where `rebuild3.json` is kept (the device's ledger directory).
    pub marker_dir: Option<&'a Path>,
}

/// What a rebuild may do.
#[derive(Clone, Copy, Debug)]
pub struct RebuildOptions {
    /// Read cold storages too (retrieval fees may apply).
    pub confirm_cold_read: bool,
    /// Verify the packs the maps name as well, not only unnamed ones.
    pub verify_named: bool,
    /// Push the new batches to the hot metadata storages.
    pub push: bool,
}

impl Default for RebuildOptions {
    fn default() -> Self {
        RebuildOptions {
            confirm_cold_read: false,
            verify_named: false,
            push: true,
        }
    }
}

/// What a rebuild did (the JSON of `varsto ledger rebuild --json`).
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct RebuildReport {
    pub own_head_before: u64,
    pub own_head_after: u64,
    pub own_on_storage: BTreeMap<String, u64>,
    pub peer_seen: u64,
    pub batches: u64,
    pub checkpoints: u64,
    pub refused: u64,
    pub malformed: u64,
    pub forked_devices: Vec<String>,
    pub own_records: u64,
    pub claims_from_maps: u64,
    pub claims_from_listing: u64,
    pub verified: u64,
    pub unnamed_corrupt: Vec<String>,
    pub announced: u64,
    pub folders_added: u64,
    pub enrolled: bool,
    pub new_batches: Vec<u64>,
    pub pushed_to: Vec<String>,
    pub skipped: Vec<String>,
    pub refused_records: u64,
    #[serde(skip)]
    pub(crate) forks: Vec<DeviceBin>,
}

pub(crate) type Counts = RebuildReport;

impl RebuildReport {
    /// A few lines for the command line.
    pub fn describe(&self) -> String {
        let mut out = format!(
            "own batches {} -> {} | pulled {} batches, {} checkpoints | claims from maps {}, from the listing {} | records announced {} | new batches {:?} | pushed to {:?}",
            self.own_head_before,
            self.own_head_after,
            self.batches,
            self.checkpoints,
            self.claims_from_maps,
            self.claims_from_listing,
            self.announced,
            self.new_batches,
            self.pushed_to,
        );
        for s in &self.skipped {
            out.push_str(&format!("\n  skipped: {s}"));
        }
        for s in &self.unnamed_corrupt {
            out.push_str(&format!("\n  not claimed, corrupt: {s}"));
        }
        out
    }
}

/// Why a rebuild stopped.
#[derive(Debug)]
pub enum RebuildError {
    /// Two histories of this identity exist (or a storage holds a batch
    /// under a number the rebuild thought free): pair this computer again.
    Forked(String),
    /// Other devices hold batches of this device that no storage returned.
    GapNeedsPeers {
        held: u64,
        seen: u64,
    },
    /// A hot metadata storage cannot be read; the service retries.
    StorageUnreachable(String),
    Other(anyhow::Error),
}

impl RebuildError {
    /// The code of the JSON error.
    pub fn code(&self) -> &'static str {
        match self {
            RebuildError::Forked(_) => "forked",
            RebuildError::GapNeedsPeers { .. } => "gap_needs_peers",
            RebuildError::StorageUnreachable(_) => "storage_unreachable",
            RebuildError::Other(_) => "error",
        }
    }
}

impl std::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RebuildError::Forked(what) => write!(
                f,
                "two histories of this device exist ({what}); pair this computer again as a new device (`varsto reset --yes`, then `varsto join`)"
            ),
            RebuildError::GapNeedsPeers { held, seen } => write!(
                f,
                "other devices hold batches of this device up to {seen}, the storages only up to {held}; signing now would reuse a number. Connect to the other devices so they can hand the batches back, or pair this computer again"
            ),
            RebuildError::StorageUnreachable(s) => write!(f, "cannot read the ledger of {s}"),
            RebuildError::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for RebuildError {}

impl From<anyhow::Error> for RebuildError {
    fn from(e: anyhow::Error) -> Self {
        RebuildError::Other(e)
    }
}

/// Announcements for records are read from the rebuilt view; signers and
/// roles from the engine's trust.
pub(crate) struct WithView<'a> {
    pub inner: &'a dyn RecordTrust,
    pub view: &'a crate::ledger3::LedgerView,
}

impl RecordTrust for WithView<'_> {
    fn signer_key(
        &self,
        device: &Id16,
        kind: crate::record::Kind,
        scope: &Id16,
    ) -> Option<VerifyingKey> {
        self.inner.signer_key(device, kind, scope)
    }
    fn may_write(
        &self,
        device: &Id16,
        kind: crate::record::Kind,
        scope: &Id16,
        key_id: &crate::record::KeyId,
    ) -> bool {
        self.inner.may_write(device, kind, scope, key_id)
    }
    fn announcement(
        &self,
        device: &Id16,
        kind: crate::record::Kind,
        scope: &Id16,
        seq: u64,
    ) -> Option<crate::record::Announced> {
        self.view
            .announced(kind.code(), scope, device, seq)
            .map(|a| crate::record::Announced {
                parts: a.parts,
                body_hash: a.body_hash,
                base: a.base,
            })
    }
}

fn view_of(
    store: &LedgerStore,
    input: &RebuildInput,
) -> Result<crate::ledger3::LedgerView, RebuildError> {
    Ok(store.view_scoped(
        |k| (input.key_for)(k),
        |_, _| true,
        |d, k| (input.scope_of)(d, k),
    )?)
}

/// Rebuild the local ledger of this device from the storages and sign the
/// events that were in the batches no storage returned.
pub fn rebuild(
    store: &mut LedgerStore,
    input: &RebuildInput,
    opts: &RebuildOptions,
) -> Result<RebuildReport, RebuildError> {
    let me = input.me;
    let mut rep = RebuildReport {
        own_head_before: store.head(&me).seq,
        ..Default::default()
    };

    // 1. Pull.
    pull::pull_ledger(store, input, opts, &mut rep)?;
    if store.is_forked(&me) || rep.forks.contains(&me) {
        rep.forked_devices = rep.forks.iter().map(hex::encode).collect();
        let names: Vec<&str> = rep.own_on_storage.keys().map(String::as_str).collect();
        return Err(RebuildError::Forked(format!(
            "the storages {} hold different batches under one number",
            names.join(", ")
        )));
    }
    rep.forked_devices = rep.forks.iter().map(hex::encode).collect();

    // 2. The next number must be free everywhere.
    let mut view = view_of(store, input)?;
    fn seen_by_peers(v: &crate::ledger3::LedgerView, me: &DeviceBin) -> u64 {
        v.acks
            .iter()
            .filter(|(reader, _)| *reader != me)
            .filter_map(|(_, held)| held.get(me))
            .copied()
            .max()
            .unwrap_or(0)
    }
    rep.peer_seen = seen_by_peers(&view, &me);
    let mut head = store.head(&me).seq;
    if rep.peer_seen > head {
        if let (Some(fill), Some(pubkey)) = (input.fill_own, (input.pubkey_of)(&me)) {
            for seq in head + 1..=rep.peer_seen {
                if let Some(rec) = fill(seq) {
                    let key = (input.key_for)(&rec.key_id);
                    store.ingest_own_restored(rec, &pubkey, key.as_ref())?;
                }
            }
            head = store.head(&me).seq;
            view = view_of(store, input)?;
        }
        if rep.peer_seen > head {
            return Err(RebuildError::GapNeedsPeers {
                held: head,
                seen: rep.peer_seen,
            });
        }
    }

    // 3. The events that were in the lost batches.
    let mut events = claims::reconstruct(input, opts, &view, &mut rep)?;
    if head == 0 && !view.devices.contains_key(&me) {
        events.insert(
            0,
            crate::ledger3::Event::DeviceEnrolled(crate::ledger3::events::DeviceEnrolled {
                name: input.device_name.clone(),
            }),
        );
        rep.enrolled = true;
    }
    if !events.is_empty() {
        let seen = store.vault_seen(&me);
        let mut lamport = view.max_lamport;
        let sealed = store.append_action(
            &me,
            events.iter().map(crate::ledger3::Event::to_raw).collect(),
            seen,
            || {
                lamport += 1;
                lamport
            },
            input.ledger_key,
            &input.key_id,
            crate::ledger3::NO_FOLDER,
            input.signer,
        )?;
        rep.new_batches = sealed.iter().map(|r| r.seq).collect();
        if let Some(dir) = input.marker_dir {
            mark_rebuild(dir, &rep.new_batches)?;
        }
        if opts.push {
            for s in input.storages.iter().filter(|s| s.meta && !s.cold) {
                for rec in &sealed {
                    let bytes = rec.encode();
                    let key = batch_key(&me, rec.seq);
                    if !s.storage.put_if_absent(&key, &bytes)? {
                        let same = s.storage.get(&key)?.is_some_and(|b| {
                            SignedRecord::decode(&b).is_ok_and(|e| e.body_hash == rec.body_hash)
                        });
                        if !same {
                            return Err(RebuildError::Forked(format!(
                                "{} holds another batch {} of this device",
                                s.name, rec.seq
                            )));
                        }
                    }
                }
                if let Some(last) = sealed.last() {
                    store.set_pushed(&s.name, last.seq)?;
                }
                rep.pushed_to.push(s.name.clone());
            }
        }
    }
    rep.own_head_after = store.head(&me).seq;
    Ok(rep)
}

/// Remember which batches are rebuild batches.
fn mark_rebuild(dir: &Path, seqs: &[u64]) -> anyhow::Result<()> {
    #[derive(serde::Serialize, serde::Deserialize, Default)]
    struct Marks {
        rebuilds: Vec<(i64, Vec<u64>)>,
    }
    let path = dir.join("rebuild3.json");
    let mut m: Marks = crate::util::read_json(&path).unwrap_or_default();
    m.rebuilds.push((crate::util::now_utc(), seqs.to_vec()));
    std::fs::create_dir_all(dir)?;
    crate::util::write_json(&path, &m)
}
