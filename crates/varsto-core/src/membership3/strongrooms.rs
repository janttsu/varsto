// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `strongroom` records (kind 24, format 3 design section 5, "Kinds and
//! rules of the switch"): `vault/strongroom/<folder>/<device>/`, key id
//! `registry@<e>`, written by an owner of the folder (`Trust` checks the
//! role). A Strongroom's key K13ₑ takes the place of K9ₑ for its folder; it
//! is never granted and never under K3: the record carries its wraps, one
//! per enrolled FIDO2 credential (each opens only with that credential's
//! hmac-secret output), the key commitment, and, for a folder made by a
//! conversion, the folder it replaces (that folder's record carries
//! `removed`).
//!
//! The newest record of a folder (by `updated_utc`, then stamp) counts.

use super::{store, Stamp};
use crate::record::{
    Id16, Kind, Record, RecordBody, RecordKeys, RecordMeta, RecordTrust, RecordsRefused, StreamRef,
};
use crate::storage::Storage;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Most enrolled keys one Strongroom carries.
pub const MAX_WRAPS: usize = 64;

/// One enrolled credential and its wrap of K13 (as `strongroom::EnrolledKey`
/// holds it: method, credential, salt and wrap in text form).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wrap {
    /// `fido2` or `software`.
    pub method: String,
    pub credential: String,
    pub salt_hex: String,
    pub wrapped_key_hex: String,
    pub label: String,
    pub added_utc: i64,
}

/// The body of a `strongroom` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrongroomRecord {
    pub folder: Id16,
    pub epoch: u32,
    pub wraps: Vec<Wrap>,
    /// The key commitment (`strongroom::key_check`).
    pub check_hex: String,
    /// When the list of keys last changed: the newest list counts.
    pub updated_utc: i64,
    pub stamp: Stamp,
    /// K13 under derive(K2, "strongroom-escrow", vault, K3₀, folder), when
    /// the user opted in (not written by this version).
    pub escrow: Option<Vec<u8>>,
    /// The folder this one replaces (a conversion into a Strongroom, or a
    /// new key of one).
    pub converted_from: Option<Id16>,
    /// The newest manifest of each device of the old folder that the
    /// converted copy includes: a device that published more after that
    /// keeps its plain files.
    pub covered: Vec<(Id16, u64)>,
    /// The old folder was a Strongroom already (its key was rotated).
    pub rekey: bool,
}

impl RecordBody for StrongroomRecord {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.folder != meta.scope {
            return Err("folder differs from the record's scope".into());
        }
        if self.wraps.is_empty() || self.wraps.len() > MAX_WRAPS {
            return Err("a Strongroom needs one to 64 enrolled keys".into());
        }
        if self.stamp.device != meta.device {
            return Err("the stamp is another device's".into());
        }
        if self.covered.len() > super::MAX_PARTICIPANTS {
            return Err("too many entries".into());
        }
        let long = |s: &String| s.len() > 4096;
        if self.check_hex.len() > 128
            || self.wraps.iter().any(|w| {
                long(&w.method)
                    || long(&w.credential)
                    || long(&w.salt_hex)
                    || long(&w.wrapped_key_hex)
                    || long(&w.label)
            })
        {
            return Err("a wrap is too large".into());
        }
        Ok(())
    }
}

impl StrongroomRecord {
    pub fn stream(folder: Id16, device: Id16) -> StreamRef {
        StreamRef::new(Kind::Strongroom, folder, device)
    }

    /// The enrolled keys in the form `strongroom` works with.
    pub fn info(&self) -> Result<crate::strongroom::StrongroomInfo> {
        let keys = self
            .wraps
            .iter()
            .map(|w| {
                Ok(crate::strongroom::EnrolledKey {
                    method: serde_json::from_value(serde_json::Value::String(w.method.clone()))?,
                    credential: w.credential.clone(),
                    salt_hex: w.salt_hex.clone(),
                    wrapped_key_hex: w.wrapped_key_hex.clone(),
                    label: w.label.clone(),
                    added_utc: w.added_utc,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut info = crate::strongroom::StrongroomInfo::from_keys(keys, self.updated_utc)?;
        info.check_hex = self.check_hex.clone();
        Ok(info)
    }

    /// The wraps of `info`.
    pub fn wraps_of(info: &crate::strongroom::StrongroomInfo) -> Result<Vec<Wrap>> {
        info.keys()
            .into_iter()
            .map(|k| {
                let method = match serde_json::to_value(&k.method)? {
                    serde_json::Value::String(s) => s,
                    _ => anyhow::bail!("unexpected method"),
                };
                Ok(Wrap {
                    method,
                    credential: k.credential,
                    salt_hex: k.salt_hex,
                    wrapped_key_hex: k.wrapped_key_hex,
                    label: k.label,
                    added_utc: k.added_utc,
                })
            })
            .collect()
    }
}

/// The newest accepted `strongroom` record of every folder.
pub(crate) fn read_strongrooms(
    storages: &[&dyn Storage],
    vault: Id16,
    keys: &dyn RecordKeys,
    trust: &dyn RecordTrust,
    counter: &mut RecordsRefused,
) -> Result<BTreeMap<Id16, StrongroomRecord>> {
    let recs: Vec<Record<StrongroomRecord>> = store::read_all(
        storages,
        vault,
        Kind::Strongroom,
        "vault/strongroom/",
        keys,
        trust,
        counter,
    )?;
    let mut out: BTreeMap<Id16, StrongroomRecord> = BTreeMap::new();
    for r in recs {
        let newer = out
            .get(&r.body.folder)
            .is_none_or(|o| (r.body.updated_utc, r.body.stamp) > (o.updated_utc, o.stamp));
        if newer {
            out.insert(r.body.folder, r.body);
        }
    }
    Ok(out)
}

/// The creation nonce of a Strongroom made with key `k13`: the folder id is
/// `folder_id(creator, nonce)`, so the device that holds the key can name
/// the id before it writes anything (its wraps bind the id).
pub fn creation_nonce(k13: &crate::crypto::SecretKey) -> [u8; 16] {
    let d = super::derive3(k13, "strongroom-folder-nonce", &[]);
    let mut n = [0u8; 16];
    n.copy_from_slice(&d.0[..16]);
    n
}
