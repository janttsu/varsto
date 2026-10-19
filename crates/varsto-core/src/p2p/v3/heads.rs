// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Head exchange, batch fetch from peers and the rollback warning of format
//! 3 (design section 8), built on the format-2 exchange of section 74
//! (`crate::ledger_heads`): the same occasions (every new connection, at
//! most every few minutes on a kept one, and `/p2p/changed`), but what a
//! peer hands over is a **proof**, not a statement.
//!
//! - A device lists `(device, seq, hash)` of the newest batch it holds of
//!   every full device (`HeadRef`, at most 256), in its peer record and on
//!   `/p2p/heads/<list>` and `/p2p/changed/<list>`.
//! - The responder answers, for every device where it holds a newer batch,
//!   that batch's SignedRecord envelope without its body (the signature
//!   covers `body_hash`, so it verifies alone and proves that the signer
//!   wrote that batch), at most 64 envelopes and 512 KiB, plus its own list.
//! - The receiver records what was proved (`Watch`, `ledger/proofs.json`)
//!   and fetches the batches it lacks from that peer (`GET
//!   /p2p/ledger/<device>/<seq>`, the whole record), checked like a record
//!   from a storage (`record::Acceptor`). Batches learnt this way are not
//!   pushed to storages: only their writers push them.
//! - `RollbackJudge`: after every pull, a storage that the writing device
//!   said it pushed to (its peer record's `pushed`) or that this device
//!   pushed to, which shows less than a proof older than the pull, is
//!   suspect; two pulls in a row make the warning.

use super::Id16;
use crate::crypto::VerifyingKey;
use crate::ids::DeviceId;
use crate::record::{Acceptor, Junk, KeyId, Kind, Record, RecordBody, Refused, SignedRecord};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Most entries of one head list.
pub const MAX_HEADS: usize = 256;
/// Most proofs in one answer, and their bytes together.
pub const MAX_PROOFS: usize = 64;
pub const MAX_ANSWER_BYTES: usize = 512 * 1024;
/// Most batches fetched from one peer for one device in one round.
pub const MAX_FETCH: u64 = 64;
/// `/p2p/changed/<list>`, `/p2p/heads/<list>`, `/p2p/ledger/<device>/<seq>`.
pub const CHANGED_PREFIX: &str = "/p2p/changed/";
pub const HEADS_PREFIX: &str = "/p2p/heads/";
pub const LEDGER_PREFIX: &str = "/p2p/ledger/";
/// A list whose path would be longer than this is not sent along; the
/// bare path asks for everything the responder can prove.
pub const MAX_PATH: usize = 24 * 1024;
/// Where a device keeps what peers proved (`ledger/watch.json` holds the
/// pull's own freshness state).
pub const WATCH_FILE: &str = "ledger/proofs.json";

/// The newest batch of `device` someone holds: its seq and the
/// `body_hash` of its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HeadRef {
    pub device: Id16,
    pub seq: u64,
    pub hash: [u8; 32],
}

/// A storage and the newest own batch a device confirmed on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pushed {
    /// The storage's identity (`vault/storage-id.json`).
    pub storage: Id16,
    pub seq: u64,
}

/// A head list as it travels in a path (`postcard`, base64url); `None`
/// when it would not fit `MAX_PATH`.
pub fn list_path(prefix: &str, heads: &[HeadRef]) -> Option<String> {
    if heads.len() > MAX_HEADS {
        return None;
    }
    let raw = postcard::to_stdvec(&heads.to_vec()).ok()?;
    let p = format!("{prefix}{}", B64URL.encode(raw));
    (p.len() <= MAX_PATH).then_some(p)
}

/// The head list a path carries after `prefix` (empty for the bare path).
pub fn list_of_path(path: &str, prefix: &str) -> Option<Vec<HeadRef>> {
    let bare = prefix.trim_end_matches('/');
    if path == bare {
        return Some(Vec::new());
    }
    let token = path.strip_prefix(prefix)?;
    let raw = B64URL.decode(token).ok()?;
    let list: Vec<HeadRef> = postcard::from_bytes(&raw).ok()?;
    (list.len() <= MAX_HEADS).then_some(list)
}

/// What a responder answers to a head list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadsAnswer {
    /// Encoded batch envelopes with an empty body.
    pub proofs: Vec<Vec<u8>>,
    /// The responder's own list.
    pub heads: Vec<HeadRef>,
}

impl HeadsAnswer {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<HeadsAnswer> {
        if bytes.len() > MAX_ANSWER_BYTES + 64 * 1024 {
            return None;
        }
        let a: HeadsAnswer = postcard::from_bytes(bytes).ok()?;
        (a.proofs.len() <= MAX_PROOFS && a.heads.len() <= MAX_HEADS).then_some(a)
    }
}

/// The local ledger as the peer-to-peer side sees it (the engine's
/// snapshot implements it over the ledger directory).
pub trait BatchSource: Send + Sync {
    /// The newest batch held of every full device (this one included).
    fn heads(&self) -> Vec<HeadRef>;
    /// The encoded record (one part) of batch `seq` of `device`.
    fn batch(&self, device: &Id16, seq: u64) -> Option<Vec<u8>>;
}

/// An envelope without its body: what proves a head.
pub fn strip_body(record: &[u8]) -> Option<Vec<u8>> {
    let mut env = SignedRecord::decode(record).ok()?;
    env.body.clear();
    Some(env.encode())
}

/// The answer to `theirs`: a proof for every device where `source` holds a
/// newer batch than they list (those they do not list at all included).
pub fn answer(source: &dyn BatchSource, theirs: &[HeadRef]) -> HeadsAnswer {
    let mine = source.heads();
    let mut proofs = Vec::new();
    let mut bytes = 0usize;
    for h in &mine {
        let behind = theirs
            .iter()
            .find(|t| t.device == h.device)
            .is_none_or(|t| t.seq < h.seq);
        if !behind || proofs.len() >= MAX_PROOFS {
            continue;
        }
        let Some(p) = source.batch(&h.device, h.seq).and_then(|r| strip_body(&r)) else {
            continue;
        };
        if bytes + p.len() > MAX_ANSWER_BYTES {
            break;
        }
        bytes += p.len();
        proofs.push(p);
    }
    let mut heads = mine;
    heads.truncate(MAX_HEADS);
    HeadsAnswer { proofs, heads }
}

/// What a verified proof says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub device: Id16,
    pub seq: u64,
    pub hash: [u8; 32],
}

/// Check a proof: a vault batch envelope (kind `batch`, zero scope, one
/// part, a `ledger@` key) of this vault whose signature verifies against
/// the writer's K6 (`key_of`: full devices only).
pub fn verify_proof(
    bytes: &[u8],
    vault: &Id16,
    key_of: &dyn Fn(&Id16) -> Option<VerifyingKey>,
) -> Result<Proof, Junk> {
    let env = SignedRecord::decode(bytes)?;
    if env.kind() != Some(Kind::Batch) {
        return Err(Junk::NotAllowed);
    }
    if &env.vault != vault {
        return Err(Junk::WrongVault);
    }
    if env.scope != [0u8; 16] || env.parts != 1 || env.part != 0 {
        return Err(Junk::NotAllowed);
    }
    if !matches!(env.key(), Some(KeyId::Ledger(_))) {
        return Err(Junk::KeyNotForKind);
    }
    let key = key_of(&env.device).ok_or(Junk::UnknownSigner)?;
    env.verify_signature(&key)?;
    Ok(Proof {
        device: env.device,
        seq: env.seq,
        hash: env.body_hash,
    })
}

/// The storage name of batch `seq` of `device`.
pub fn batch_name(device: &Id16, seq: u64) -> String {
    crate::record::StreamRef::new(Kind::Batch, [0u8; 16], *device)
        .part_name(seq, 0)
        .unwrap_or_default()
}

/// The path that fetches batch `seq` of `device` from a peer.
pub fn ledger_path(device: &Id16, seq: u64) -> String {
    format!("{LEDGER_PREFIX}{}/{seq}", hex::encode(device))
}

/// (device, seq) of a `/p2p/ledger/` path.
pub fn parse_ledger_path(path: &str) -> Option<(Id16, u64)> {
    let rest = path.strip_prefix(LEDGER_PREFIX)?;
    let (d, s) = rest.split_once('/')?;
    let seq: u64 = s.parse().ok()?;
    Some((crate::record::kinds::parse_id16(d)?, seq))
}

/// Check a batch fetched from a peer exactly like one read from a storage
/// (acceptance steps 1 to 4 under its storage name), and, when a proof
/// named it, that it is the batch proved.
pub fn check_fetched<T: RecordBody>(
    acceptor: &Acceptor<'_>,
    device: &Id16,
    seq: u64,
    bytes: Vec<u8>,
    proved: Option<&[u8; 32]>,
) -> Result<Record<T>, Refused> {
    let name = batch_name(device, seq);
    let rec = acceptor.open::<T>(&[(name.clone(), bytes)])?;
    if rec.meta.kind != Kind::Batch || rec.meta.scope != [0u8; 16] {
        return Err(Refused {
            name,
            kind: Some(rec.meta.kind),
            seq,
            device: Some(*device),
            reason: crate::record::Refusal::Junk(Junk::NotAllowed),
        });
    }
    if proved.is_some_and(|h| *h != rec.meta.body_hash) {
        return Err(Refused {
            name,
            kind: Some(Kind::Batch),
            seq,
            device: Some(*device),
            reason: crate::record::Refusal::Forked,
        });
    }
    Ok(rec)
}

/// Where batches fetched from peers go: the ledger store, which checks the
/// chain and keeps them as from any source but does not push them
/// (`Engine::p2p_catch_up`).
pub trait BatchSink {
    /// The seq of the newest batch held of `device` (0: none).
    fn head(&self, device: &Id16) -> u64;
    /// Take in one checked batch (storage name and encoded record).
    fn ingest(&mut self, name: &str, record: &[u8]) -> anyhow::Result<()>;
}

/// One proved head: by whom, and when this device learnt it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proved {
    pub seq: u64,
    pub hash: String,
    /// Hex id of the peer that handed the proof over (for the writer's own
    /// peer record: the writer).
    pub peer: String,
    /// `"envelope"` or `"peer record"`.
    pub source: String,
    pub utc: i64,
}

/// What peers proved, per writing device (`ledger/proofs.json`), and the
/// rollback judge's state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Watch {
    #[serde(default)]
    pub proved: BTreeMap<String, Proved>,
    #[serde(default)]
    pub rollback: RollbackJudge,
}

impl Watch {
    pub fn load(home: &Path) -> Watch {
        crate::util::read_json(&home.join(WATCH_FILE)).unwrap_or_default()
    }

    pub fn save(&self, home: &Path) {
        if home.join("ledger").is_dir() {
            let _ = crate::util::write_json(&home.join(WATCH_FILE), self);
        }
    }

    /// Keep a proof when it is newer than the one held; true when kept.
    pub fn note(&mut self, p: &Proof, peer: &Id16, source: &str, utc: i64) -> bool {
        let key = hex::encode(p.device);
        if self.proved.get(&key).is_some_and(|o| o.seq >= p.seq) {
            return false;
        }
        self.proved.insert(
            key,
            Proved {
                seq: p.seq,
                hash: hex::encode(p.hash),
                peer: hex::encode(peer),
                source: source.into(),
                utc,
            },
        );
        true
    }

    /// The writer's own head in its accepted peer record proves it as well
    /// (the record is signed by the writer).
    pub fn note_peer_record(&mut self, body: &super::PeerBody, utc: i64) -> bool {
        match body.heads.iter().find(|h| h.device == body.device) {
            Some(h) => self.note(
                &Proof {
                    device: h.device,
                    seq: h.seq,
                    hash: h.hash,
                },
                &body.device,
                "peer record",
                utc,
            ),
            None => false,
        }
    }

    pub fn get(&self, device: &Id16) -> Option<&Proved> {
        self.proved.get(&hex::encode(device))
    }

    /// Forget a device that does not count any more.
    pub fn forget(&mut self, device: &Id16) -> bool {
        self.proved.remove(&hex::encode(device)).is_some()
    }
}

/// Verify the proofs of an answer from `peer`, note them in `watch`.
/// Returns the proofs that verified; the rest are dropped silently (they
/// cost the sender nothing to make up, so they are not counted).
pub fn take_answer(
    answer: &HeadsAnswer,
    peer: &Id16,
    vault: &Id16,
    key_of: &dyn Fn(&Id16) -> Option<VerifyingKey>,
    watch: &mut Watch,
    utc: i64,
) -> Vec<Proof> {
    let mut out = Vec::new();
    for p in &answer.proofs {
        if let Ok(proof) = verify_proof(p, vault, key_of) {
            watch.note(&proof, peer, "envelope", utc);
            out.push(proof);
        }
    }
    out
}

/// What one catch-up round did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatchUp {
    pub proofs: usize,
    pub fetched: usize,
    pub refused: usize,
}

/// Ask every peer for what it can prove beyond `mine`, note the proofs,
/// and fetch the batches this device lacks from the peer that proved them
/// (at most `MAX_FETCH` per device and round), checked like batches from a
/// storage and handed to `sink`. `T` is the batch body type.
#[allow(clippy::too_many_arguments)]
pub fn catch_up<T: RecordBody>(
    peers: &super::super::Peers,
    mine: &[HeadRef],
    vault: &Id16,
    acceptor: &Acceptor<'_>,
    key_of: &dyn Fn(&Id16) -> Option<VerifyingKey>,
    watch: &mut Watch,
    sink: &mut dyn BatchSink,
    utc: i64,
) -> CatchUp {
    let path = list_path(HEADS_PREFIX, mine).unwrap_or_else(|| "/p2p/heads".into());
    let mut out = CatchUp::default();
    for (peer, status, body) in peers.ask_each(&path) {
        if status != 200 {
            continue;
        }
        let Some(answer) = HeadsAnswer::decode(&body) else {
            continue;
        };
        let Some(peer16) = crate::record::id16(&peer) else {
            continue;
        };
        let proofs = take_answer(&answer, &peer16, vault, key_of, watch, utc);
        out.proofs += proofs.len();
        for p in proofs {
            fetch_proved::<T>(peers, &peer, &p, acceptor, sink, &mut out);
        }
    }
    out
}

/// Fetch the batches of `p.device` after this device's head up to the
/// proved one from `peer`, in order, stopping at the first that fails.
pub fn fetch_proved<T: RecordBody>(
    peers: &super::super::Peers,
    peer: &DeviceId,
    p: &Proof,
    acceptor: &Acceptor<'_>,
    sink: &mut dyn BatchSink,
    out: &mut CatchUp,
) {
    let have = sink.head(&p.device);
    if have >= p.seq {
        return;
    }
    let first = have + 1;
    let last = p.seq.min(have + MAX_FETCH);
    for seq in first..=last {
        let Some((200, bytes)) = peers.ask(peer, &ledger_path(&p.device, seq)) else {
            return;
        };
        let proved = (seq == p.seq).then_some(&p.hash);
        match check_fetched::<T>(acceptor, &p.device, seq, bytes.clone(), proved) {
            Ok(_) => {
                if sink.ingest(&batch_name(&p.device, seq), &bytes).is_err() {
                    out.refused += 1;
                    return;
                }
                out.fetched += 1;
            }
            Err(_) => {
                out.refused += 1;
                return;
            }
        }
    }
}

// ----- the rollback warning ---------------------------------------------------

/// What one storage showed in a pull.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageView {
    pub storage: Id16,
    pub name: String,
    /// False when the storage could not be listed: it is not judged.
    pub reachable: bool,
    /// The newest batch of each device its listing shows.
    pub shown: BTreeMap<Id16, u64>,
}

/// Storage `storage` is expected to hold batch `seq` of `device`: the
/// device's accepted peer record lists the storage in `pushed` with that
/// seq, or this device pushed it there itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expectation {
    pub storage: Id16,
    pub device: Id16,
    pub seq: u64,
}

/// One suspect (storage, device) pair.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suspect {
    pub pulls: u32,
    pub shown: u64,
    pub proved: u64,
    pub source: String,
    #[serde(default)]
    pub notified_utc: i64,
}

/// `ledger_health.rollback` of the design: one entry per (storage, device).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackJudge {
    /// Keyed `<storage hex>:<device hex>`.
    #[serde(default)]
    pub suspects: BTreeMap<String, Suspect>,
}

/// A warning to show (and to notify when `notify`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackWarning {
    pub storage: Id16,
    pub device: Id16,
    pub shown: u64,
    pub proved: u64,
    pub source: String,
    pub text: String,
    /// At most once a day per (storage, device).
    pub notify: bool,
}

const DAY: i64 = 86_400;

impl RollbackJudge {
    /// Judge one pull that started at `pull_utc`. `names` gives device
    /// names for the text (hex id when missing). `proofs` are the proved
    /// heads (`Watch::proved`, already limited to full devices within their
    /// cut-off by the caller).
    pub fn after_pull(
        &mut self,
        pull_utc: i64,
        storages: &[StorageView],
        expected: &[Expectation],
        proofs: &BTreeMap<String, Proved>,
        names: &dyn Fn(&Id16) -> String,
        now: i64,
    ) -> Vec<RollbackWarning> {
        let key = |s: &Id16, d: &Id16| format!("{}:{}", hex::encode(s), hex::encode(d));
        let mut judged: Vec<String> = Vec::new();
        let mut out = Vec::new();
        for e in expected {
            let Some(view) = storages.iter().find(|v| v.storage == e.storage) else {
                continue;
            };
            let k = key(&e.storage, &e.device);
            judged.push(k.clone());
            if !view.reachable {
                continue; // not judged; the state stays as it was
            }
            let proof = proofs
                .get(&hex::encode(e.device))
                .filter(|p| p.utc < pull_utc);
            let shown = view.shown.get(&e.device).copied().unwrap_or(0);
            let Some(proof) = proof else {
                self.suspects.remove(&k);
                continue;
            };
            let n = e.seq.min(proof.seq);
            if n == 0 || shown >= n {
                self.suspects.remove(&k);
                continue;
            }
            let source = if proof.source == "peer record" {
                format!("the peer record of {}", names(&e.device))
            } else {
                let peer = crate::record::kinds::parse_id16(&proof.peer)
                    .map(|p| names(&p))
                    .unwrap_or_else(|| proof.peer.clone());
                format!("device {peer}")
            };
            let s = self.suspects.entry(k).or_default();
            s.pulls += 1;
            s.shown = shown;
            s.proved = n;
            s.source = source.clone();
            if s.pulls >= 2 {
                let notify = s.notified_utc == 0 || now - s.notified_utc >= DAY;
                if notify {
                    s.notified_utc = now;
                }
                out.push(RollbackWarning {
                    storage: e.storage,
                    device: e.device,
                    shown,
                    proved: n,
                    text: format!(
                        "storage {} may be withholding or rolled back: it shows ledger batches of {} up to {shown}, but {source} proved {n}",
                        view.name,
                        names(&e.device)
                    ),
                    source,
                    notify,
                });
            }
        }
        // A pair nobody expects any more (the writer's record stopped
        // listing the storage) is cleared.
        self.suspects.retain(|k, _| judged.contains(k));
        out
    }
}
