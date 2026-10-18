// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Probing the records a batch announced: are they on a storage, complete,
//! and accepted by `record::accept`.

use crate::blockmap::BlockMap;
use crate::ledger3::view::Announced;
use crate::manifest3::ManifestBody;
use crate::record::{
    record_hash, Acceptor, Id16, Kind, Outcome, RecordKeys, RecordStore, RecordTrust, Refusal,
    SignedRecord, StreamRef,
};
use crate::storage::Storage;
use anyhow::Result;

/// A record a batch announced.
#[derive(Clone, Debug)]
pub struct RecordRef {
    pub kind: Kind,
    pub scope: Id16,
    pub device: Id16,
    pub seq: u64,
    pub announced: Announced,
}

/// What one storage holds of an announced record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordState {
    /// All steps of the acceptance rule passed.
    Accepted,
    /// Complete, and its parts hash to the announced hash; the body is not
    /// opened (kinds whose body type is not part of this build).
    Present,
    /// Valid, but no accepted batch announces it yet.
    Waiting,
    Missing,
    Incomplete {
        have: u16,
        parts: u16,
    },
    /// Refused, with the reason in words.
    Refused(String),
}

/// Reads one announced record from one storage.
pub trait RecordProbe {
    fn probe(&self, storage: &dyn Storage, record: &RecordRef) -> Result<RecordState>;
}

/// The probe over `record::accept`: block maps and manifests are opened
/// and checked fully, the other announced kinds are checked for presence,
/// completeness and the announced hash.
pub struct AcceptorProbe<'a> {
    pub vault: Id16,
    pub keys: &'a dyn RecordKeys,
    pub trust: &'a dyn RecordTrust,
}

fn outcome<T>(o: Outcome<T>) -> RecordState {
    match o {
        Outcome::Accepted(_) => RecordState::Accepted,
        Outcome::Waiting(_) => RecordState::Waiting,
        Outcome::Refused(r) => match r.reason {
            Refusal::Incomplete { have, parts } => RecordState::Incomplete { have, parts },
            Refusal::Waiting => RecordState::Waiting,
            _ => RecordState::Refused(r.to_string()),
        },
    }
}

impl RecordProbe for AcceptorProbe<'_> {
    fn probe(&self, storage: &dyn Storage, r: &RecordRef) -> Result<RecordState> {
        let store = RecordStore {
            storage,
            acceptor: Acceptor {
                vault: self.vault,
                keys: self.keys,
                trust: self.trust,
            },
        };
        let stream = StreamRef::new(r.kind, r.scope, r.device);
        let listed = store.list_after(&stream, r.seq.saturating_sub(1))?;
        let Some(l) = listed.into_iter().find(|l| l.seq == r.seq) else {
            return Ok(RecordState::Missing);
        };
        let parts = match store.fetch(&l)? {
            Ok(p) => p,
            Err(refused) => return Ok(RecordState::Refused(refused.to_string())),
        };
        if parts.len() < usize::from(r.announced.parts) {
            return Ok(if parts.is_empty() {
                RecordState::Missing
            } else {
                RecordState::Incomplete {
                    have: parts.len() as u16,
                    parts: r.announced.parts,
                }
            });
        }
        Ok(match r.kind {
            Kind::BlockMap => outcome(store.acceptor.accept::<BlockMap>(&parts)),
            Kind::Manifest => outcome(store.acceptor.accept::<ManifestBody>(&parts)),
            _ => {
                let mut envs = Vec::new();
                for (name, bytes) in &parts {
                    match SignedRecord::decode(bytes) {
                        Ok(e) => envs.push((name.clone(), e)),
                        Err(e) => {
                            return Ok(RecordState::Refused(format!("{name} does not parse ({e})")))
                        }
                    }
                }
                envs.sort_by_key(|(_, e)| e.part);
                if record_hash(envs.iter().map(|(_, e)| &e.body_hash)) == r.announced.body_hash {
                    RecordState::Present
                } else {
                    RecordState::Refused(
                        "its parts do not hash to what its batch announced".to_string(),
                    )
                }
            }
        })
    }
}
