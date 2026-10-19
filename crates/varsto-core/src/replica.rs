// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Untrusted replica devices ("untrusted device encryption", F-045), in
//! storage format 3 (`docs/spec/format-3-design.md` sections 5 and 9, spec
//! section 77.9).
//!
//! A replica holds and replicates a vault's encrypted objects without being
//! able to open them: it never receives a vault key or any folder key. The
//! owner hands it a *replica token* (vault id + replica key). The replica key
//! is derived from the vault key for one purpose only: sealing the replica's
//! enrolment request and its ledger batches, so that the owner's devices can
//! read its claims ("pack P is stored on replica B, read back whole").
//!
//! - At `init` the replica makes its own signing key (K6) and leaves an
//!   enrolment request on its source and target storages
//!   (`vault/replicas/<replica id>.enc`: its name and the public part of
//!   K6, sealed under the replica key). A full device of the vault that
//!   reads it writes the `replica` record (kind 23) that names the replica
//!   and its K6 ([`ReplicaBody`]); from then on the replica's batches count,
//!   within the replica scope (whole-pack claims and verifications with a
//!   zero folder).
//! - A round ([`crate::storages3::replicate`]) copies packs whole, checks
//!   each against its id and reads it back from the target, and copies
//!   every other object (records, ledger batches) as it is, never opened.
//!   The claims go into one batch (a SignedRecord under key id `replica`)
//!   on both storages.
//!
//! What a replica learns: pack names, sizes, counts and timing, which a
//! storage provider learns as well. What it cannot do: read content or
//! names, forge another device's events, or decrypt anything.

use crate::crypto::{self, SecretKey, SigningKey};
use crate::ids::{DeviceId, VaultId};
use crate::ledger3::{self, PackId};
use crate::record::{Id16, RecordBody, RecordMeta, StreamRef};
use crate::storage::StorageSpec;
use crate::util;
use crate::vault::VaultMeta;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Token the owner gives to a replica: everything it needs, nothing more.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReplicaToken {
    pub vault_id: VaultId,
    pub replica_key_hex: String,
}

crate::redacted_debug!(ReplicaToken { vault_id ; replica_key_hex });

impl ReplicaToken {
    pub fn encode(&self) -> String {
        format!("{}.{}", self.vault_id, self.replica_key_hex)
    }
    pub fn decode(s: &str) -> Result<Self> {
        let (v, k) = s
            .trim()
            .split_once('.')
            .ok_or_else(|| anyhow!("replica token must be <vault-id>.<key-hex>"))?;
        SecretKey::from_hex(k)?;
        Ok(ReplicaToken {
            vault_id: VaultId::from_hex(v)?,
            replica_key_hex: k.to_string(),
        })
    }
}

/// Where replicas leave their enrolment requests.
pub const REPLICA_PREFIX: &str = "vault/replicas/";

/// The enrolment request of replica `device`.
pub fn request_key(device: &Id16) -> String {
    format!("{REPLICA_PREFIX}{}.enc", hex::encode(device))
}

/// What a replica asks to be enrolled with (sealed under the replica key).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrolmentRequest {
    /// Hex of the replica id (BLAKE3 of `k6`, first 16 bytes).
    pub device: String,
    pub name: String,
    /// Hex of the public part of the replica's K6.
    pub k6: String,
}

fn request_aad(vault: &Id16, device: &Id16) -> Vec<u8> {
    crypto::aad("replica-enrolment", &[&vault[..], &device[..]])
}

impl EnrolmentRequest {
    pub fn seal(&self, vault: &Id16, key: &SecretKey) -> Result<Vec<u8>> {
        let device = id16_hex(&self.device)?;
        crypto::encrypt(
            key,
            &request_aad(vault, &device),
            &serde_json::to_vec(self)?,
        )
    }

    /// Open a request and check that its id is the hash of its key.
    pub fn open(blob: &[u8], vault: &Id16, device: &Id16, key: &SecretKey) -> Result<Self> {
        let plain = crypto::decrypt(key, &request_aad(vault, device), blob)?;
        let r: EnrolmentRequest = serde_json::from_slice(&plain)?;
        let pk = crypto::VerifyingKey::from_bytes(&hex::decode(&r.k6)?)?;
        if ledger3::device_bin_for(&pk) != *device || id16_hex(&r.device)? != *device {
            bail!("a replica enrolment request whose id is not its key");
        }
        if r.name.len() > 128 {
            bail!("a replica name longer than 128 bytes");
        }
        Ok(r)
    }
}

fn id16_hex(s: &str) -> Result<Id16> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(s, &mut out).map_err(|_| anyhow!("{s:?} is not a device id"))?;
    Ok(out)
}

/// One replica a full device enrolled.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplicaEntry {
    pub replica: Id16,
    pub name: String,
    /// The public part of the replica's K6.
    pub k6: Vec<u8>,
    pub enrolled_utc: i64,
}

/// The body of a `replica` record (kind 23, `vault/replicas/<device>/`,
/// under the registry key), written by the full device that enrolled the
/// replicas it lists. Newest seq of a device's stream wins. **As built:**
/// the record lists every replica its writer enrolled (a stream keeps one
/// newest record, the design's body names one replica).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplicaBody {
    pub device: Id16,
    pub seq: u64,
    pub replicas: Vec<ReplicaEntry>,
}

impl RecordBody for ReplicaBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.device != meta.device {
            return Err("its device is not the record's writer".into());
        }
        if self.seq != meta.seq || self.seq == 0 {
            return Err("its seq is not the record's".into());
        }
        if meta.scope != [0u8; 16] {
            return Err("replica records are vault-wide".into());
        }
        for e in &self.replicas {
            let pk = crypto::VerifyingKey::from_bytes(&e.k6).map_err(|e| e.to_string())?;
            if ledger3::device_bin_for(&pk) != e.replica {
                return Err("a replica whose id is not the hash of its key".into());
            }
            if e.name.len() > 128 {
                return Err("a replica name longer than 128 bytes".into());
            }
        }
        Ok(())
    }
}

/// The stream of the replicas `device` enrolled.
pub fn replica_stream(device: Id16) -> StreamRef {
    StreamRef::new(crate::record::Kind::Replica, [0u8; 16], device)
}

/// Local replica state: `home/replica.json` (+ ledger).
#[derive(Clone, Serialize, Deserialize)]
pub struct ReplicaLocal {
    pub format_version: u16,
    pub vault_id: VaultId,
    pub device_id: DeviceId,
    pub name: String,
    pub signing_hex: String,
    pub replica_key_hex: String,
    pub source: StorageSpec,
    pub target: StorageSpec,
}

crate::redacted_debug!(ReplicaLocal { format_version, vault_id, device_id, name, source, target ; signing_hex, replica_key_hex });

#[derive(Clone, Debug, Serialize, Default)]
pub struct ReplicaReport {
    pub objects_seen: u64,
    pub objects_copied: u64,
    pub bytes_copied: u64,
    pub objects_corrupt: u64,
    /// Names that are not objects of this layout (`chunks/...`, a name
    /// under `packs/` that is no pack): skipped, never copied.
    pub skipped_junk: u64,
    /// Packs claimed and read back this round.
    pub chunks_verified: u64,
    pub batch_seq: Option<u64>,
}

pub struct Replica {
    home: PathBuf,
    local: ReplicaLocal,
    signer: SigningKey,
    replica_key: SecretKey,
    ledger: ledger3::LedgerStore,
    vault: Id16,
    me: Id16,
    lamport: u64,
}

impl Replica {
    /// Set up a replica directory for the vault described by `token`.
    pub fn init(
        home: &Path,
        name: &str,
        token: &ReplicaToken,
        source: StorageSpec,
        target: StorageSpec,
    ) -> Result<Replica> {
        if home.join("replica.json").exists() {
            bail!("{} already holds a replica", home.display());
        }
        let src = source.open()?;
        let meta: VaultMeta =
            serde_json::from_slice(&src.get(VaultMeta::STORAGE_KEY)?.ok_or_else(|| {
                anyhow!("source holds no vault (no {})", VaultMeta::STORAGE_KEY)
            })?)?;
        if meta.vault_id != token.vault_id {
            bail!(
                "the source holds vault {} but the token is for {}",
                meta.vault_id,
                token.vault_id
            );
        }
        if meta.format_version != crate::FORMAT_VERSION {
            bail!(
                "{}",
                crate::storage_holds_other_format(source.name(), meta.format_version)
            );
        }
        let tgt = target.open()?;
        tgt.put_if_absent(VaultMeta::STORAGE_KEY, &serde_json::to_vec_pretty(&meta)?)?;
        util::private_dir(home)?;
        let signer = SigningKey::generate();
        let me = ledger3::device_bin_for(&signer.public());
        let local = ReplicaLocal {
            format_version: crate::FORMAT_VERSION,
            vault_id: token.vault_id.clone(),
            device_id: DeviceId::from_bytes(&me),
            name: name.to_string(),
            signing_hex: hex::encode(signer.to_bytes()),
            replica_key_hex: token.replica_key_hex.clone(),
            source,
            target,
        };
        util::write_json(&home.join("replica.json"), &local)?;
        let r = Replica::open(home)?;
        let req = EnrolmentRequest {
            device: hex::encode(me),
            name: name.to_string(),
            k6: hex::encode(r.signer.public().to_bytes()),
        };
        let blob = req.seal(&r.vault, &r.replica_key)?;
        for s in [r.local.source.open()?, r.local.target.open()?] {
            s.put_if_absent(&request_key(&me), &blob)?;
        }
        Ok(r)
    }

    pub fn open(home: &Path) -> Result<Replica> {
        let local: ReplicaLocal = util::read_json(&home.join("replica.json"))
            .with_context(|| format!("no replica in {}", home.display()))?;
        if local.format_version != crate::FORMAT_VERSION {
            bail!(
                "{} holds a replica of storage format {}; set it up again with a new token",
                home.display(),
                local.format_version
            );
        }
        let signer = SigningKey::from_bytes(&hex::decode(&local.signing_hex)?)?;
        let replica_key = SecretKey::from_hex(&local.replica_key_hex)?;
        let vault = crate::record::id16(&local.vault_id)
            .ok_or_else(|| anyhow!("a vault id is 16 bytes"))?;
        let me = ledger3::device_bin_for(&signer.public());
        let lamport = util::read_json_or_default::<serde_json::Value>(&home.join("clock.json"))?
            .get("lamport")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(Replica {
            home: home.to_path_buf(),
            ledger: ledger3::LedgerStore::open(&home.join("ledger"), vault)?,
            local,
            signer,
            replica_key,
            vault,
            me,
            lamport,
        })
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.local.device_id
    }

    fn storage_name(&self) -> String {
        format!("replica:{}", self.local.name)
    }

    fn claimed_path(&self) -> PathBuf {
        self.home.join("claimed.json")
    }

    /// Seal `events` into the replica's next batch and put every batch it
    /// has on both storages.
    fn append(&mut self, events: Vec<ledger3::Event>) -> Result<Option<u64>> {
        if events.is_empty() {
            return Ok(None);
        }
        crate::storages3::check_replica_events(&events)?;
        self.lamport += 1;
        util::write_json(
            &self.home.join("clock.json"),
            &serde_json::json!({ "lamport": self.lamport }),
        )?;
        let raw: Vec<_> = events.iter().map(ledger3::Event::to_raw).collect();
        let mut last = None;
        for group in ledger3::events::split_events(raw) {
            let rec = self.ledger.append_own(
                &self.me,
                group,
                Vec::new(),
                self.lamport,
                &self.replica_key,
                "replica",
                ledger3::NO_FOLDER,
                &self.signer,
            )?;
            last = Some(rec.seq);
        }
        let head = self.ledger.head(&self.me).seq;
        for s in [self.local.source.open()?, self.local.target.open()?] {
            for seq in 1..=head {
                if let Some(b) = self.ledger.get(&self.me, seq)? {
                    s.put_if_absent(&ledger3::checkpoint::batch_key(&self.me, seq), &b.encode())?;
                }
            }
        }
        Ok(last)
    }

    /// One replication round: copy every object the target lacks from the
    /// source (packs checked against their ids and read back), and claim
    /// the packs in the replica's ledger.
    pub fn run_once(&mut self) -> Result<ReplicaReport> {
        let src = self.local.source.open()?;
        let tgt = self.local.target.open()?;
        let mut claimed: BTreeSet<String> =
            util::read_json_or_default(&self.claimed_path()).unwrap_or_default();
        let round = crate::storages3::replicate(
            src.as_ref(),
            tgt.as_ref(),
            &self.storage_name(),
            &|p: &PackId| claimed.contains(&hex::encode(p)),
        )?;
        let r = &round.report;
        let mut report = ReplicaReport {
            objects_seen: r.objects_seen,
            objects_copied: r.packs_copied + r.records_copied,
            bytes_copied: r.bytes_copied,
            objects_corrupt: r.packs_corrupt + r.packs_refused,
            skipped_junk: r.skipped_junk,
            chunks_verified: r.packs_claimed,
            batch_seq: None,
        };
        for ev in &round.events {
            if let ledger3::Event::PackStored(p) = ev {
                claimed.insert(hex::encode(p.pack));
            }
        }
        report.batch_seq = self.append(round.events)?;
        util::write_json(&self.claimed_path(), &claimed)?;
        Ok(report)
    }

    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "vault_id": self.local.vault_id.to_string(),
            "device_id": self.local.device_id.to_string(),
            "name": self.local.name,
            "source": self.local.source,
            "target": self.local.target,
            "batches": self.ledger.head(&self.me).seq,
        })
    }
}

/// Owner side: derive the replica key and build a token.
pub fn token_for(vault_key: &SecretKey, vault_id: &VaultId) -> ReplicaToken {
    ReplicaToken {
        vault_id: vault_id.clone(),
        replica_key_hex: replica_key(vault_key, vault_id).to_hex(),
    }
}

/// The key of replicas' batches and enrolment requests: derived from the
/// vault's first key, so every full device of the vault holds it.
pub fn replica_key(vault_key: &SecretKey, vault_id: &VaultId) -> SecretKey {
    let vault = crate::record::id16(vault_id).unwrap_or_default();
    crate::membership3::derive3(vault_key, "replica-ledger", &[&vault[..]])
}
