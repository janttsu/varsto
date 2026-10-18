// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Untrusted replica devices ("untrusted device encryption", F-045).
//!
//! A replica holds and replicates a vault's encrypted objects without being
//! able to open them: it never receives the master key or any folder key. The
//! owner hands it a *replica token* (vault id + replica key). The replica key
//! is derived from the master key for one purpose only: encrypting the
//! replica's own device record and ledger batches so that the owner's devices
//! can read its claims ("object X is stored on replica B, hash verified").
//!
//! What a replica learns: object names, sizes, counts and timing, which a
//! storage provider learns as well (plan 6.10). What it cannot do: read
//! content or names, forge another device's events, or decrypt anything.
//!
//! Use: two users share backup space. User B runs `varsto replica run` with
//! A's token, a *source* A writes to (a shared directory, a bucket synced to a
//! folder, a USB disk) and a *target* on B's disk. B's target is a full
//! storage layout: A can add it as a storage when it is reachable, and A's
//! ledger counts it as a copy, verified by B.

use crate::crypto::{self, SecretKey, SigningKey};
use crate::ids::{ChunkId, DeviceId, FolderId, ObjectName, VaultId};
use crate::ledger::{self, Event, LedgerStore, SignedBatch, KEY_REPLICA};
use crate::storage::StorageSpec;
use crate::util;
use crate::vault::{DeviceRecord, VaultMeta};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

/// Storage key prefix under which replica device records live.
pub const REPLICA_PREFIX: &str = "vault/replicas/";

pub fn replica_record_key(device: &DeviceId) -> String {
    format!("{REPLICA_PREFIX}{device}.enc")
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
    /// Names under `chunks/` that are not object names (something else
    /// wrote to the source storage): skipped, never copied.
    pub skipped_junk: u64,
    pub chunks_verified: u64,
    pub batch_seq: Option<u64>,
}

pub struct Replica {
    home: PathBuf,
    local: ReplicaLocal,
    signer: SigningKey,
    replica_key: SecretKey,
    ledger: LedgerStore,
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
        let tgt = target.open()?;
        tgt.put_if_absent(VaultMeta::STORAGE_KEY, &serde_json::to_vec_pretty(&meta)?)?;
        util::private_dir(home)?;
        let signer = SigningKey::generate();
        let device_id = ledger::device_id_for(&signer.public());
        let local = ReplicaLocal {
            format_version: crate::FORMAT_VERSION,
            vault_id: token.vault_id.clone(),
            device_id: device_id.clone(),
            name: name.to_string(),
            signing_hex: hex::encode(signer.to_bytes()),
            replica_key_hex: token.replica_key_hex.clone(),
            source,
            target,
        };
        util::write_json(&home.join("replica.json"), &local)?;
        let mut r = Replica::open(home)?;
        let rec = DeviceRecord {
            device_id,
            name: name.to_string(),
            pubkey_hex: hex::encode(r.signer.public().to_bytes()),
            enrolled_utc: util::now_utc(),
        };
        let blob = rec.seal(&r.local.vault_id, &r.replica_key)?;
        for s in [r.local.source.open()?, r.local.target.open()?] {
            s.put_if_absent(&replica_record_key(&r.local.device_id), &blob)?;
        }
        r.append(vec![Event::DeviceEnrolled {
            name: format!("replica:{name}"),
        }])?;
        Ok(r)
    }

    pub fn open(home: &Path) -> Result<Replica> {
        let local: ReplicaLocal = util::read_json(&home.join("replica.json"))
            .with_context(|| format!("no replica in {}", home.display()))?;
        let signer = SigningKey::from_bytes(&hex::decode(&local.signing_hex)?)?;
        let replica_key = SecretKey::from_hex(&local.replica_key_hex)?;
        let lamport = util::read_json_or_default::<serde_json::Value>(&home.join("clock.json"))?
            .get("lamport")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(Replica {
            home: home.to_path_buf(),
            local,
            signer,
            replica_key,
            ledger: LedgerStore::open(&home.join("ledger"))?,
            lamport,
        })
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.local.device_id
    }

    fn storage_name(&self) -> String {
        format!("replica:{}", self.local.name)
    }

    fn append(&mut self, events: Vec<Event>) -> Result<Option<u64>> {
        if events.is_empty() {
            return Ok(None);
        }
        self.lamport += 1;
        util::write_json(
            &self.home.join("clock.json"),
            &serde_json::json!({ "lamport": self.lamport }),
        )?;
        let signed = self.ledger.append_own_with(
            &self.local.device_id,
            events,
            self.lamport,
            &self.replica_key,
            KEY_REPLICA,
            &self.signer,
        )?;
        for s in [self.local.source.open()?, self.local.target.open()?] {
            for seq in 1..=signed.seq {
                if let Some(b) = self.ledger.get(&self.local.device_id, seq)? {
                    s.put_if_absent(
                        &SignedBatch::storage_key(&self.local.device_id, seq),
                        &serde_json::to_vec(&b)?,
                    )?;
                }
            }
        }
        Ok(Some(signed.seq))
    }

    /// One replication round: copy every object the target lacks from the
    /// source, verify chunk hashes, and record claims in the replica ledger.
    pub fn run_once(&mut self) -> Result<ReplicaReport> {
        // Blocks live in packs (`crate::packs`): a pack is copied whole,
        // checked against its name (the hash of its bytes), and claimed by
        // its id; the owner's view places every block of the pack on the
        // replica from where the pack's original holds it. Everything else
        // (records, indexes, tombstone lists) is copied as it is.
        let src = self.local.source.open()?;
        let tgt = self.local.target.open()?;
        let mut report = ReplicaReport::default();
        let have: HashSet<String> = tgt.list("")?.into_iter().collect();
        let mut events = Vec::new();
        for key in src.list("")? {
            report.objects_seen += 1;
            if have.contains(&key) {
                continue;
            }
            // Objects under chunks/ are not written any more, and a name
            // under packs/ that is not a pack is junk left by something
            // else: skipped, not a reason to stop.
            let pack = crate::packs::pack_of_key(&key);
            if key.starts_with("chunks/") || (key.starts_with(crate::packs::PREFIX) && pack.is_none())
            {
                if report.skipped_junk == 0 {
                    log::warn!(
                        "replica {}: skipping junk on {}: {key:?}",
                        self.local.name,
                        self.local.source.name()
                    );
                }
                report.skipped_junk += 1;
                continue;
            }
            let Some(data) = src.get(&key)? else { continue };
            let mut claim = None;
            if let Some(id) = pack {
                if hex::encode(crypto::hash(&data)) != id {
                    report.objects_corrupt += 1;
                    continue; // never replicate a corrupt pack
                }
                claim = Some((ObjectName::from_hex(id)?, data.len() as u64));
            }
            if tgt.put_if_absent(&key, &data)? {
                report.objects_copied += 1;
                report.bytes_copied += data.len() as u64;
            }
            if let Some((object, size)) = claim {
                // A replica knows neither chunk ids nor which blocks a pack
                // holds: it claims the pack by its id, as chunk and object,
                // and the owner folds the claim into every block placed in
                // that pack.
                let chunk: ChunkId = object.clone();
                events.push(Event::ChunkStored {
                    folder: FolderId::default(),
                    chunk: chunk.clone(),
                    object: object.clone(),
                    storage: self.storage_name(),
                    size,
                    pack: None,
                });
                events.push(Event::ChunkVerified {
                    folder: FolderId::default(),
                    chunk,
                    object,
                    storage: self.storage_name(),
                });
                report.chunks_verified += 1;
            }
        }
        report.batch_seq = self.append(events)?;
        Ok(report)
    }

    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "vault_id": self.local.vault_id.to_string(),
            "device_id": self.local.device_id.to_string(),
            "name": self.local.name,
            "source": self.local.source,
            "target": self.local.target,
            "batches": self.ledger.head(&self.local.device_id).seq,
        })
    }
}

/// Owner side: derive the replica key and build a token.
pub fn token_for(master: &SecretKey, vault_id: &VaultId) -> ReplicaToken {
    ReplicaToken {
        vault_id: vault_id.clone(),
        replica_key_hex: replica_key(master).to_hex(),
    }
}

pub fn replica_key(master: &SecretKey) -> SecretKey {
    master.derive("replica-ledger", &[])
}
