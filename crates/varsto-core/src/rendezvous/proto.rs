// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Wire formats of the rendezvous service (`alpha-0-format.md` section 83).
//!
//! This file is shared word for word by the client (`varsto-core`) and the
//! server (`crates/varsto-rendezvous`, which includes it with `#[path]` so
//! that the server does not link the whole core library). It therefore uses
//! no `crate::` item: only serde, hex, base64, blake3, ed25519-dalek and
//! rand.
//!
//! Three channels:
//!
//! - **HTTP** (JSON bodies): [`PutSlot`], [`DeleteSlot`], [`Lookup`] and
//!   their answers, [`Info`], `GET /health` (one text line).
//! - **Control WebSocket** (JSON text frames): [`ToServer`], [`ToClient`].
//! - **UDP** (binary, STUN-shaped): [`encode_observe`], [`parse_observe`],
//!   [`encode_observed`], [`parse_observed`].
//!
//! Every signed message signs a fixed binary string (`*_signed_bytes`), never
//! the JSON text, so that field order and escaping cannot matter.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Protocol version carried in every message (`v`). A server answers a
/// higher version with [`ErrorCode::Version`]; a lower one than it supports
/// likewise.
pub const VERSION: u32 = 1;
/// The default service, used when `p2p.rendezvous` is not set.
pub const DEFAULT_URL: &str = "https://varsto.net/rv";
/// The default UDP port of a self-hosted server. Clients never assume it:
/// they read the UDP endpoints from [`Info`].
pub const DEFAULT_UDP_PORT: u16 = 17893;

/// Length of a tag and of a slot.
pub const ID_LEN: usize = 16;
/// A tag: which vault (or which pairing offer) a slot belongs to.
pub type Tag = [u8; ID_LEN];
/// A slot within a tag: one device (or the one pairing offer).
pub type Slot = [u8; ID_LEN];
/// A random token: the UDP binding token, a relay token, a pairing `rv=`.
pub type Token = [u8; ID_LEN];
/// The slot of a pairing offer (a pairing tag has exactly one slot).
pub const PAIR_SLOT: Slot = [0u8; ID_LEN];

/// Largest blob a slot holds (bytes, before base64).
pub const MAX_BLOB: usize = 64 * 1024;
/// Largest HTTP request body the server reads.
pub const MAX_BODY: usize = 96 * 1024;
/// Largest control message (one WebSocket text frame).
pub const MAX_CONTROL_MSG: usize = 16 * 1024;
/// Most claims in one `hello` or `claim`.
pub const MAX_CLAIMS: usize = 8;
/// Largest relay frame (one WebSocket binary message).
pub const MAX_RELAY_FRAME: usize = 64 * 1024;
/// How far a signed timestamp may be from the server's clock.
pub const REPLAY_WINDOW_SECS: u64 = 300;
/// Longest life of a peer slot since its last write.
pub const PEER_TTL_MAX: u32 = 48 * 3600;
/// Longest life of a pairing offer.
pub const PAIR_TTL_MAX: u32 = 600;
/// Most slots one peer tag may hold.
pub const MAX_SLOTS_PER_TAG: usize = 64;
/// Most addresses in a pairing offer.
pub const MAX_OFFER_ADDRS: usize = 16;
/// The STUN attribute that carries the UDP binding token in an observe
/// request (comprehension-optional range, so plain STUN servers ignore it).
pub const UDP_TOKEN_ATTR: u16 = 0xC056;

/// What a tag holds. Fixed by the first slot written under the tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A device's sealed peer record (spec 75) under the vault tag.
    Peer,
    /// A pairing offer: one slot, short-lived.
    Pair,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Peer => 1,
            Kind::Pair => 2,
        }
    }
    /// Longest TTL this kind allows.
    pub fn ttl_max(self) -> u32 {
        match self {
            Kind::Peer => PEER_TTL_MAX,
            Kind::Pair => PAIR_TTL_MAX,
        }
    }
    /// Most slots one tag of this kind holds.
    pub fn slots_max(self) -> usize {
        match self {
            Kind::Peer => MAX_SLOTS_PER_TAG,
            Kind::Pair => 1,
        }
    }
}

/// Why a request was refused. Carried in [`ErrorAnswer`] and
/// [`ToClient::Error`]; the HTTP status is [`ErrorCode::status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed: a field does not parse, a length is wrong.
    BadRequest,
    /// A body, blob or frame over its cap.
    TooLarge,
    /// A protocol version this server does not speak.
    Version,
    /// The timestamp is outside the replay window, or not newer than the
    /// slot's last write.
    Stale,
    /// The signature does not verify.
    BadSignature,
    /// The slot belongs to another owner key.
    NotOwner,
    /// The tag holds its most slots, or is of the other kind.
    TagFull,
    /// Too many requests from this address or for this tag.
    RateLimited,
    /// No such tag, slot, session or token.
    NotFound,
    /// The asker has no observed UDP address (punch needs one).
    NotObserved,
    /// The server is full or shutting down.
    Unavailable,
}

impl ErrorCode {
    /// The HTTP status a server answers with.
    pub fn status(self) -> u16 {
        match self {
            ErrorCode::BadRequest | ErrorCode::BadSignature => 400,
            ErrorCode::TooLarge => 413,
            ErrorCode::Version => 400,
            ErrorCode::Stale => 409,
            ErrorCode::NotOwner => 403,
            ErrorCode::TagFull => 409,
            ErrorCode::RateLimited => 429,
            ErrorCode::NotFound | ErrorCode::NotObserved => 404,
            ErrorCode::Unavailable => 503,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::Version => "version",
            ErrorCode::Stale => "stale",
            ErrorCode::BadSignature => "bad_signature",
            ErrorCode::NotOwner => "not_owner",
            ErrorCode::TagFull => "tag_full",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::NotFound => "not_found",
            ErrorCode::NotObserved => "not_observed",
            ErrorCode::Unavailable => "unavailable",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ErrorCode {}

/// The body of every refusal over HTTP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorAnswer {
    pub error: ErrorCode,
    #[serde(default)]
    pub message: String,
}

// ---------------------------------------------------------------------------
// Field encodings: fixed-length ids as lowercase hex, blobs as base64url.

/// Fixed-length bytes, as lowercase hex in JSON.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hex<const N: usize>(pub [u8; N]);

impl<const N: usize> std::fmt::Debug for Hex<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; N];
        if s.len() != N * 2 || s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(serde::de::Error::custom("wrong hex length or case"));
        }
        hex::decode_to_slice(&s, &mut out).map_err(serde::de::Error::custom)?;
        Ok(Hex(out))
    }
}

/// Variable bytes, as base64url without padding in JSON (at most
/// [`MAX_BLOB`] bytes: longer input is refused while decoding).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Blob(pub Vec<u8>);

impl std::fmt::Debug for Blob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blob({} bytes)", self.0.len())
    }
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

impl Serialize for Blob {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() > MAX_BLOB.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom("blob too large"));
        }
        let b = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        if b.len() > MAX_BLOB {
            return Err(serde::de::Error::custom("blob too large"));
        }
        Ok(Blob(b))
    }
}

/// Parse a socket address as the messages carry it (`ip:port`, IPv6 in
/// brackets).
pub fn parse_addr(s: &str) -> Option<SocketAddr> {
    s.parse().ok()
}

// ---------------------------------------------------------------------------
// Time and signatures.

/// Whether a signed timestamp `ts` is inside the replay window around `now`
/// (both in Unix seconds).
pub fn within_window(ts: u64, now: u64) -> bool {
    ts.abs_diff(now) <= REPLAY_WINDOW_SECS
}

fn push_id(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(b);
}

/// The bytes a [`PutSlot`] signs:
/// `"varsto-rv/1 put\0" | kind (1) | tag (16) | slot (16) | owner (32) |
/// ts (u64 LE) | ttl (u32 LE) | BLAKE3(blob) (32)`.
pub fn put_signed_bytes(
    kind: Kind,
    tag: &Tag,
    slot: &Slot,
    owner: &[u8; 32],
    ts: u64,
    ttl: u32,
    blob: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 1 + 16 + 16 + 32 + 8 + 4 + 32);
    out.extend_from_slice(b"varsto-rv/1 put\0");
    out.push(kind.byte());
    push_id(&mut out, tag);
    push_id(&mut out, slot);
    push_id(&mut out, owner);
    out.extend_from_slice(&ts.to_le_bytes());
    out.extend_from_slice(&ttl.to_le_bytes());
    out.extend_from_slice(blake3::hash(blob).as_bytes());
    out
}

/// The bytes a [`DeleteSlot`] signs:
/// `"varsto-rv/1 delete\0" | tag (16) | slot (16) | owner (32) | ts (u64 LE)`.
pub fn delete_signed_bytes(tag: &Tag, slot: &Slot, owner: &[u8; 32], ts: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(19 + 16 + 16 + 32 + 8);
    out.extend_from_slice(b"varsto-rv/1 delete\0");
    push_id(&mut out, tag);
    push_id(&mut out, slot);
    push_id(&mut out, owner);
    out.extend_from_slice(&ts.to_le_bytes());
    out
}

/// The bytes a [`Claim`] signs:
/// `"varsto-rv/1 claim\0" | challenge (32) | tag (16) | slot (16) | owner (32)`.
pub fn claim_signed_bytes(
    challenge: &[u8; 32],
    tag: &Tag,
    slot: &Slot,
    owner: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + 32 + 16 + 16 + 32);
    out.extend_from_slice(b"varsto-rv/1 claim\0");
    push_id(&mut out, challenge);
    push_id(&mut out, tag);
    push_id(&mut out, slot);
    push_id(&mut out, owner);
    out
}

fn verify_sig(owner: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), ErrorCode> {
    let key = VerifyingKey::from_bytes(owner).map_err(|_| ErrorCode::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    key.verify_strict(msg, &sig)
        .map_err(|_| ErrorCode::BadSignature)
}

fn check_version(v: u32) -> Result<(), ErrorCode> {
    if v == VERSION {
        Ok(())
    } else {
        Err(ErrorCode::Version)
    }
}

// ---------------------------------------------------------------------------
// HTTP messages.

/// `POST /v1/put`: write a slot. Put-if-absent for a new slot; a slot that
/// exists takes the write only from its owner key with a newer `ts`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutSlot {
    pub v: u32,
    pub kind: Kind,
    pub tag: Hex<16>,
    pub slot: Hex<16>,
    /// Ed25519 public key that owns the slot.
    pub owner: Hex<32>,
    /// Unix seconds; inside the replay window and above the last write.
    pub ts: u64,
    /// Seconds the slot lives after this write (capped per kind).
    pub ttl: u32,
    pub blob: Blob,
    /// Ed25519 over [`put_signed_bytes`].
    pub sig: Hex<64>,
}

impl PutSlot {
    /// A signed put.
    pub fn sign(
        kind: Kind,
        tag: Tag,
        slot: Slot,
        key: &SigningKey,
        ts: u64,
        ttl: u32,
        blob: Vec<u8>,
    ) -> PutSlot {
        let owner = key.verifying_key().to_bytes();
        let sig = key
            .sign(&put_signed_bytes(kind, &tag, &slot, &owner, ts, ttl, &blob))
            .to_bytes();
        PutSlot {
            v: VERSION,
            kind,
            tag: Hex(tag),
            slot: Hex(slot),
            owner: Hex(owner),
            ts,
            ttl,
            blob: Blob(blob),
            sig: Hex(sig),
        }
    }

    /// Everything the server checks without its registry: version, sizes,
    /// TTL cap, pairing slot, replay window, signature.
    pub fn verify(&self, now: u64) -> Result<(), ErrorCode> {
        check_version(self.v)?;
        if self.blob.0.len() > MAX_BLOB {
            return Err(ErrorCode::TooLarge);
        }
        if self.ttl == 0 || self.ttl > self.kind.ttl_max() {
            return Err(ErrorCode::BadRequest);
        }
        if self.kind == Kind::Pair && self.slot.0 != PAIR_SLOT {
            return Err(ErrorCode::BadRequest);
        }
        if !within_window(self.ts, now) {
            return Err(ErrorCode::Stale);
        }
        let msg = put_signed_bytes(
            self.kind,
            &self.tag.0,
            &self.slot.0,
            &self.owner.0,
            self.ts,
            self.ttl,
            &self.blob.0,
        );
        verify_sig(&self.owner.0, &msg, &self.sig.0)
    }
}

/// The answer to a put that was stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutAnswer {
    /// Unix seconds when the slot expires unless written again.
    pub expires: u64,
    /// True when the slot was new.
    pub created: bool,
}

/// `POST /v1/delete`: remove a slot (its owner only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteSlot {
    pub v: u32,
    pub tag: Hex<16>,
    pub slot: Hex<16>,
    pub owner: Hex<32>,
    pub ts: u64,
    /// Ed25519 over [`delete_signed_bytes`].
    pub sig: Hex<64>,
}

impl DeleteSlot {
    pub fn sign(tag: Tag, slot: Slot, key: &SigningKey, ts: u64) -> DeleteSlot {
        let owner = key.verifying_key().to_bytes();
        let sig = key
            .sign(&delete_signed_bytes(&tag, &slot, &owner, ts))
            .to_bytes();
        DeleteSlot {
            v: VERSION,
            tag: Hex(tag),
            slot: Hex(slot),
            owner: Hex(owner),
            ts,
            sig: Hex(sig),
        }
    }

    pub fn verify(&self, now: u64) -> Result<(), ErrorCode> {
        check_version(self.v)?;
        if !within_window(self.ts, now) {
            return Err(ErrorCode::Stale);
        }
        let msg = delete_signed_bytes(&self.tag.0, &self.slot.0, &self.owner.0, self.ts);
        verify_sig(&self.owner.0, &msg, &self.sig.0)
    }
}

/// `POST /v1/lookup`: every live slot of a tag. A POST rather than a GET
/// so that the tag never appears in a URL or an access log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lookup {
    pub v: u32,
    pub tag: Hex<16>,
}

impl Lookup {
    pub fn new(tag: Tag) -> Lookup {
        Lookup {
            v: VERSION,
            tag: Hex(tag),
        }
    }
    pub fn verify(&self) -> Result<(), ErrorCode> {
        check_version(self.v)
    }
}

/// One live slot as a lookup returns it. The owner key is not returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotEntry {
    pub slot: Hex<16>,
    /// The `ts` of the last write.
    pub ts: u64,
    pub expires: u64,
    pub blob: Blob,
}

/// The answer to a lookup (empty for an unknown tag: a lookup never says
/// whether a tag existed).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupAnswer {
    pub kind: Option<Kind>,
    pub slots: Vec<SlotEntry>,
}

/// Limits a server announces in [`Info`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_blob: usize,
    pub max_slots_per_tag: usize,
    pub peer_ttl_max: u32,
    pub pair_ttl_max: u32,
    pub replay_window: u64,
    /// Bytes per second per relay session and direction (0: no relay).
    pub relay_rate: u64,
    /// Seconds a relay session may move nothing either way.
    pub relay_idle: u64,
    /// Most relay sessions at once per tag.
    pub relay_per_tag: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_blob: MAX_BLOB,
            max_slots_per_tag: MAX_SLOTS_PER_TAG,
            peer_ttl_max: PEER_TTL_MAX,
            pair_ttl_max: PAIR_TTL_MAX,
            replay_window: REPLAY_WINDOW_SECS,
            relay_rate: 4 * 1024 * 1024,
            // The pairing exchange waits up to five minutes for the
            // person at the offering device to say yes.
            relay_idle: 300,
            relay_per_tag: 4,
        }
    }
}

/// `GET /info`: what the client fetches first and caches (an hour). The
/// UDP endpoints come only from here: a client never assumes a port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    pub v: u32,
    /// The server program's version (free text, at most 40 characters).
    pub server: String,
    /// UDP observe endpoints as `host:port` (a name or an address).
    pub udp: Vec<String>,
    /// Whether the relay is offered.
    pub relay: bool,
    pub limits: Limits,
    /// The server's clock (Unix seconds): a client whose clock is off by
    /// more than the replay window says so in its status.
    pub time: u64,
}

// ---------------------------------------------------------------------------
// Control channel (`GET /v1/control`, WebSocket, JSON text frames).

/// One slot a control connection speaks for, proved by its owner key over
/// the connection's challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub tag: Hex<16>,
    pub slot: Hex<16>,
    pub owner: Hex<32>,
    /// Ed25519 over [`claim_signed_bytes`].
    pub sig: Hex<64>,
}

impl Claim {
    pub fn sign(challenge: &[u8; 32], tag: Tag, slot: Slot, key: &SigningKey) -> Claim {
        let owner = key.verifying_key().to_bytes();
        let sig = key
            .sign(&claim_signed_bytes(challenge, &tag, &slot, &owner))
            .to_bytes();
        Claim {
            tag: Hex(tag),
            slot: Hex(slot),
            owner: Hex(owner),
            sig: Hex(sig),
        }
    }

    /// The signature alone; the server then checks that `owner` owns the
    /// slot in its registry.
    pub fn verify(&self, challenge: &[u8; 32]) -> Result<(), ErrorCode> {
        let msg = claim_signed_bytes(challenge, &self.tag.0, &self.slot.0, &self.owner.0);
        verify_sig(&self.owner.0, &msg, &self.sig.0)
    }
}

/// Client to server on the control channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToServer {
    /// First message, after the server's challenge. Zero claims is allowed
    /// (a joining device that only reaches a pairing offer).
    Hello { v: u32, claims: Vec<Claim> },
    /// More claims on the same connection (a pairing offer opened later).
    Claim { claims: Vec<Claim> },
    /// Drop claims (a pairing offer closed).
    Unclaim { slots: Vec<(Hex<16>, Hex<16>)> },
    /// Ask the server to make the holder of (`tag`, `slot`) punch towards
    /// this connection's observed UDP address, and to tell us its own.
    Punch {
        id: u32,
        tag: Hex<16>,
        slot: Hex<16>,
    },
    /// Ask for a relay session with the holder of (`tag`, `slot`).
    Relay {
        id: u32,
        tag: Hex<16>,
        slot: Hex<16>,
    },
    /// Keep-alive; answered by `pong`.
    Ping { id: u32 },
}

/// Server to client on the control channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToClient {
    /// First message of every connection.
    Challenge {
        v: u32,
        nonce: Hex<32>,
        time: u64,
    },
    /// Answer to `hello`/`claim`: the UDP binding token of this connection
    /// (put it in every observe request) and the slots now claimed.
    Welcome {
        udp_token: Hex<16>,
        claimed: Vec<(Hex<16>, Hex<16>)>,
    },
    /// Punch now towards `peer`. To the asker (`id` set): the target's
    /// observed UDP address; to the target (`id` none): the asker's, with
    /// the target's own claimed (`tag`, `slot`) it was asked for.
    PunchGo {
        id: Option<u32>,
        tag: Hex<16>,
        slot: Hex<16>,
        peer: String,
    },
    /// The asker's relay token: open `/v1/relay/<token>` now.
    RelayReady {
        id: u32,
        token: Hex<16>,
    },
    /// Someone asked for a relay to our claimed (`tag`, `slot`): open
    /// `/v1/relay/<token>` within [`RELAY_JOIN_SECS`] to take it.
    RelayOffer {
        token: Hex<16>,
        tag: Hex<16>,
        slot: Hex<16>,
    },
    Pong {
        id: u32,
    },
    /// A refusal; `id` names the request when there was one.
    Error {
        id: Option<u32>,
        error: ErrorCode,
        #[serde(default)]
        message: String,
    },
}

/// How long the second side of a relay session has to arrive.
pub const RELAY_JOIN_SECS: u64 = 15;
/// A control connection that sends nothing for this long is closed (the
/// client pings every 25 s).
pub const CONTROL_IDLE_SECS: u64 = 90;
/// How often a client sends an observe datagram (keeps its NAT mapping and
/// the server's observed address fresh).
pub const OBSERVE_INTERVAL_SECS: u64 = 25;
/// An observed address older than this is not used for a punch.
pub const OBSERVED_MAX_AGE_SECS: u64 = 120;

/// Parse one control frame, refusing oversize text first.
pub fn parse_to_server(text: &str) -> Result<ToServer, ErrorCode> {
    if text.len() > MAX_CONTROL_MSG {
        return Err(ErrorCode::TooLarge);
    }
    let m: ToServer = serde_json::from_str(text).map_err(|_| ErrorCode::BadRequest)?;
    match &m {
        ToServer::Hello { v, claims } => {
            check_version(*v)?;
            if claims.len() > MAX_CLAIMS {
                return Err(ErrorCode::TooLarge);
            }
        }
        ToServer::Claim { claims } if claims.len() > MAX_CLAIMS => return Err(ErrorCode::TooLarge),
        ToServer::Unclaim { slots } if slots.len() > MAX_CLAIMS => return Err(ErrorCode::TooLarge),
        _ => {}
    }
    Ok(m)
}

/// Parse one control frame from the server.
pub fn parse_to_client(text: &str) -> Result<ToClient, ErrorCode> {
    if text.len() > MAX_CONTROL_MSG {
        return Err(ErrorCode::TooLarge);
    }
    serde_json::from_str(text).map_err(|_| ErrorCode::BadRequest)
}

// ---------------------------------------------------------------------------
// Pairing offer (the plaintext inside the sealed blob of a pairing slot).

/// What a pairing slot's blob holds once opened: the offering device's
/// candidate addresses, as the pairing link's `a=` carries them, best first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairOffer {
    pub v: u32,
    pub addrs: Vec<String>,
    /// Unix seconds the offer closes.
    pub expires: u64,
    /// Whether the offering device holds a control connection with this
    /// slot claimed (a joiner may then ask for a relay).
    pub relay: bool,
}

impl PairOffer {
    pub fn check(&self) -> Result<(), ErrorCode> {
        check_version(self.v)?;
        if self.addrs.len() > MAX_OFFER_ADDRS || self.addrs.iter().any(|a| a.len() > 64) {
            return Err(ErrorCode::TooLarge);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UDP: observe requests and answers, STUN-shaped (RFC 5389 Binding).
//
// An observe request is a STUN Binding Request, optionally with one
// attribute `UDP_TOKEN_ATTR` (16 bytes). The answer is a Binding Success
// Response with XOR-MAPPED-ADDRESS. So the client's existing STUN side
// channel on the QUIC socket (spec 15, 60) carries it unchanged, the same
// request works against public STUN servers (which ignore the attribute),
// and the server never sends a datagram nobody asked for.

const STUN_HEADER: usize = 20;
const STUN_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAPPED_ADDRESS: u16 = 0x0001;
/// Largest observe request the server reads.
pub const MAX_OBSERVE: usize = 64;

/// An observe request with transaction id `tx` and, when given, the
/// connection's UDP binding token.
pub fn encode_observe(tx: &[u8; 12], token: Option<&Token>) -> Vec<u8> {
    let attrs = if token.is_some() { 4 + ID_LEN } else { 0 };
    let mut out = Vec::with_capacity(STUN_HEADER + attrs);
    out.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    out.extend_from_slice(&(attrs as u16).to_be_bytes());
    out.extend_from_slice(&STUN_COOKIE.to_be_bytes());
    out.extend_from_slice(tx);
    if let Some(t) = token {
        out.extend_from_slice(&UDP_TOKEN_ATTR.to_be_bytes());
        out.extend_from_slice(&(ID_LEN as u16).to_be_bytes());
        out.extend_from_slice(t);
    }
    out
}

/// A parsed observe request: transaction id and token, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observe {
    pub tx: [u8; 12],
    pub token: Option<Token>,
}

/// Parse an observe request (the server side). Anything that is not a
/// Binding Request of at most [`MAX_OBSERVE`] bytes is `None` and gets no
/// answer. Unknown attributes are skipped.
pub fn parse_observe(buf: &[u8]) -> Option<Observe> {
    if buf.len() < STUN_HEADER || buf.len() > MAX_OBSERVE || buf[0] & 0xC0 != 0 {
        return None;
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != BINDING_REQUEST
        || buf[4..8] != STUN_COOKIE.to_be_bytes()
    {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if STUN_HEADER + len != buf.len() || len % 4 != 0 {
        return None;
    }
    let mut tx = [0u8; 12];
    tx.copy_from_slice(&buf[8..20]);
    let mut token = None;
    let mut pos = STUN_HEADER;
    while pos + 4 <= buf.len() {
        let t = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let l = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + l > buf.len() {
            return None;
        }
        if t == UDP_TOKEN_ATTR && l == ID_LEN {
            let mut tok = [0u8; ID_LEN];
            tok.copy_from_slice(&buf[pos..pos + l]);
            token = Some(tok);
        }
        pos += l.div_ceil(4) * 4;
    }
    Some(Observe { tx, token })
}

/// The answer to an observe request: a Binding Success Response with
/// XOR-MAPPED-ADDRESS = `addr`.
pub fn encode_observed(tx: &[u8; 12], addr: SocketAddr) -> Vec<u8> {
    let mut value = Vec::with_capacity(20);
    value.push(0);
    let port = addr.port() ^ (STUN_COOKIE >> 16) as u16;
    match addr.ip() {
        IpAddr::V4(ip) => {
            value.push(1);
            value.extend_from_slice(&port.to_be_bytes());
            let x = u32::from(ip) ^ STUN_COOKIE;
            value.extend_from_slice(&x.to_be_bytes());
        }
        IpAddr::V6(ip) => {
            value.push(2);
            value.extend_from_slice(&port.to_be_bytes());
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&STUN_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(tx);
            for (a, k) in ip.octets().iter().zip(key) {
                value.push(a ^ k);
            }
        }
    }
    let mut out = Vec::with_capacity(STUN_HEADER + 4 + value.len());
    out.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    out.extend_from_slice(&STUN_COOKIE.to_be_bytes());
    out.extend_from_slice(tx);
    out.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    out
}

/// The observed address in an answer for `tx` (XOR-MAPPED-ADDRESS, or
/// MAPPED-ADDRESS from an old STUN server). The client's STUN parser
/// (`p2p::stun::parse_binding_response`) reads the same answers.
pub fn parse_observed(buf: &[u8], tx: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < STUN_HEADER
        || u16::from_be_bytes([buf[0], buf[1]]) != BINDING_SUCCESS
        || buf[4..8] != STUN_COOKIE.to_be_bytes()
        || &buf[8..20] != tx
    {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = STUN_HEADER.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let mut pos = STUN_HEADER;
    let mut plain = None;
    while pos + 4 <= end {
        let t = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let l = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + l > end {
            return None;
        }
        let v = &buf[pos..pos + l];
        if t == XOR_MAPPED_ADDRESS || t == MAPPED_ADDRESS {
            let xor = t == XOR_MAPPED_ADDRESS;
            if let Some(a) = decode_address(v, xor, tx) {
                if xor {
                    return Some(a);
                }
                plain = Some(a);
            }
        }
        pos += l.div_ceil(4) * 4;
    }
    plain
}

fn decode_address(v: &[u8], xor: bool, tx: &[u8; 12]) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let mut port = u16::from_be_bytes([v[2], v[3]]);
    if xor {
        port ^= (STUN_COOKIE >> 16) as u16;
    }
    match v[1] {
        1 if v.len() >= 8 => {
            let mut ip = u32::from_be_bytes([v[4], v[5], v[6], v[7]]);
            if xor {
                ip ^= STUN_COOKIE;
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        2 if v.len() >= 20 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&v[4..20]);
            if xor {
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&STUN_COOKIE.to_be_bytes());
                key[4..].copy_from_slice(tx);
                for (b, k) in o.iter_mut().zip(key) {
                    *b ^= k;
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The one-line health answer.

/// Counters of `GET /health`: no per-tag detail.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Health {
    pub uptime: u64,
    pub tags: u64,
    pub slots: u64,
    pub pair_offers: u64,
    pub controls: u64,
    pub relays: u64,
    pub relay_bytes: u64,
    pub udp_answered: u64,
    pub refused: u64,
    pub rate_limited: u64,
}

impl Health {
    /// `ok v=1 up=.. tags=.. slots=.. pair=.. control=.. relays=..
    /// relay_bytes=.. udp=.. refused=.. limited=..`
    pub fn line(&self) -> String {
        format!(
            "ok v={VERSION} up={} tags={} slots={} pair={} control={} relays={} relay_bytes={} udp={} refused={} limited={}",
            self.uptime,
            self.tags,
            self.slots,
            self.pair_offers,
            self.controls,
            self.relays,
            self.relay_bytes,
            self.udp_answered,
            self.refused,
            self.rate_limited
        )
    }

    /// Parse a line made by [`Health::line`].
    pub fn parse(line: &str) -> Option<Health> {
        let mut it = line.split_whitespace();
        if it.next()? != "ok" {
            return None;
        }
        let mut h = Health::default();
        for kv in it {
            let (k, v) = kv.split_once('=')?;
            if k == "v" {
                continue;
            }
            let n: u64 = v.parse().ok()?;
            match k {
                "up" => h.uptime = n,
                "tags" => h.tags = n,
                "slots" => h.slots = n,
                "pair" => h.pair_offers = n,
                "control" => h.controls = n,
                "relays" => h.relays = n,
                "relay_bytes" => h.relay_bytes = n,
                "udp" => h.udp_answered = n,
                "refused" => h.refused = n,
                "limited" => h.rate_limited = n,
                _ => {}
            }
        }
        Some(h)
    }
}

// ---------------------------------------------------------------------------
// Paths. Every route works with and without the `/rv` prefix, so the
// server runs behind Caddy's `handle_path /rv/*` (prefix stripped) or
// `handle /rv/*` (prefix kept) alike. A client appends these to its base
// URL (`https://varsto.net/rv`).

pub const PATH_INFO: &str = "/info";
pub const PATH_HEALTH: &str = "/health";
pub const PATH_PUT: &str = "/v1/put";
pub const PATH_DELETE: &str = "/v1/delete";
pub const PATH_LOOKUP: &str = "/v1/lookup";
pub const PATH_CONTROL: &str = "/v1/control";
/// Followed by `/<token hex>`.
pub const PATH_RELAY: &str = "/v1/relay";

/// The relay path for `token`.
pub fn relay_path(token: &Token) -> String {
    format!("{PATH_RELAY}/{}", hex::encode(token))
}

/// A fresh random 16-byte token.
pub fn random_token() -> Token {
    use rand::RngCore as _;
    let mut t = [0u8; ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut t);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn a_put_round_trips_through_json_and_verifies() {
        let p = PutSlot::sign(
            Kind::Peer,
            [1; 16],
            [2; 16],
            &key(7),
            NOW,
            3600,
            vec![9; 1000],
        );
        let text = serde_json::to_string(&p).unwrap();
        assert!(!text.contains('='), "base64url without padding");
        let back: PutSlot = serde_json::from_str(&text).unwrap();
        assert_eq!(back, p);
        back.verify(NOW).unwrap();
        back.verify(NOW + REPLAY_WINDOW_SECS).unwrap();
    }

    #[test]
    fn forged_old_oversize_and_wrong_version_puts_are_refused() {
        let p = PutSlot::sign(
            Kind::Peer,
            [1; 16],
            [2; 16],
            &key(7),
            NOW,
            3600,
            vec![9; 10],
        );
        let mut forged = p.clone();
        forged.blob.0[0] ^= 1;
        assert_eq!(forged.verify(NOW), Err(ErrorCode::BadSignature));
        let mut other = p.clone();
        other.owner = Hex(key(8).verifying_key().to_bytes());
        assert_eq!(other.verify(NOW), Err(ErrorCode::BadSignature));
        let mut ttl = p.clone();
        ttl.ttl += 1;
        assert_eq!(ttl.verify(NOW), Err(ErrorCode::BadSignature));
        assert_eq!(
            p.verify(NOW + REPLAY_WINDOW_SECS + 1),
            Err(ErrorCode::Stale)
        );
        assert_eq!(
            p.verify(NOW - REPLAY_WINDOW_SECS - 1),
            Err(ErrorCode::Stale)
        );
        let mut v = p.clone();
        v.v = 2;
        assert_eq!(v.verify(NOW), Err(ErrorCode::Version));
        let big = PutSlot::sign(
            Kind::Peer,
            [1; 16],
            [2; 16],
            &key(7),
            NOW,
            60,
            vec![0; MAX_BLOB + 1],
        );
        assert_eq!(big.verify(NOW), Err(ErrorCode::TooLarge));
        // Too large to even decode from JSON.
        let text = serde_json::to_string(&big).unwrap();
        assert!(serde_json::from_str::<PutSlot>(&text).is_err());
        let long = PutSlot::sign(
            Kind::Pair,
            [1; 16],
            PAIR_SLOT,
            &key(7),
            NOW,
            PAIR_TTL_MAX + 1,
            vec![],
        );
        assert_eq!(long.verify(NOW), Err(ErrorCode::BadRequest));
        let peer_long = PutSlot::sign(
            Kind::Peer,
            [1; 16],
            [2; 16],
            &key(7),
            NOW,
            PEER_TTL_MAX + 1,
            vec![],
        );
        assert_eq!(peer_long.verify(NOW), Err(ErrorCode::BadRequest));
        let pair_slot = PutSlot::sign(Kind::Pair, [1; 16], [2; 16], &key(7), NOW, 60, vec![]);
        assert_eq!(pair_slot.verify(NOW), Err(ErrorCode::BadRequest));
    }

    #[test]
    fn the_signed_bytes_are_fixed() {
        let b = put_signed_bytes(Kind::Pair, &[1; 16], &[2; 16], &[3; 32], 5, 6, b"x");
        assert_eq!(b.len(), 16 + 1 + 16 + 16 + 32 + 8 + 4 + 32);
        assert_eq!(&b[..16], b"varsto-rv/1 put\0");
        assert_eq!(b[16], 2);
        assert_eq!(&b[81..89], &5u64.to_le_bytes());
        assert_eq!(&b[89..93], &6u32.to_le_bytes());
        assert_eq!(&b[93..], blake3::hash(b"x").as_bytes());
        assert_eq!(
            delete_signed_bytes(&[1; 16], &[2; 16], &[3; 32], 5).len(),
            19 + 72
        );
        assert_eq!(
            claim_signed_bytes(&[0; 32], &[1; 16], &[2; 16], &[3; 32]).len(),
            18 + 96
        );
    }

    #[test]
    fn deletes_and_claims_verify_and_forgeries_do_not() {
        let d = DeleteSlot::sign([1; 16], [2; 16], &key(3), NOW);
        let back: DeleteSlot = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        back.verify(NOW).unwrap();
        assert_eq!(back.verify(NOW + 1000), Err(ErrorCode::Stale));
        let mut f = back.clone();
        f.slot.0[0] ^= 1;
        assert_eq!(f.verify(NOW), Err(ErrorCode::BadSignature));

        let c = Claim::sign(&[5; 32], [1; 16], [2; 16], &key(3));
        c.verify(&[5; 32]).unwrap();
        assert_eq!(c.verify(&[6; 32]), Err(ErrorCode::BadSignature));
    }

    #[test]
    fn hex_fields_refuse_wrong_lengths_and_upper_case() {
        assert!(serde_json::from_str::<Hex<16>>("\"00\"").is_err());
        let up = format!("\"{}\"", "AB".repeat(16));
        assert!(serde_json::from_str::<Hex<16>>(&up).is_err());
        let ok = format!("\"{}\"", "ab".repeat(16));
        assert_eq!(serde_json::from_str::<Hex<16>>(&ok).unwrap().0, [0xab; 16]);
    }

    #[test]
    fn control_messages_round_trip_and_oversize_is_refused() {
        let msgs = vec![
            ToServer::Hello {
                v: VERSION,
                claims: vec![Claim::sign(&[1; 32], [2; 16], [3; 16], &key(1))],
            },
            ToServer::Punch {
                id: 7,
                tag: Hex([1; 16]),
                slot: Hex([2; 16]),
            },
            ToServer::Relay {
                id: 8,
                tag: Hex([1; 16]),
                slot: Hex([2; 16]),
            },
            ToServer::Unclaim {
                slots: vec![(Hex([1; 16]), Hex([0; 16]))],
            },
            ToServer::Ping { id: 9 },
        ];
        for m in msgs {
            let t = serde_json::to_string(&m).unwrap();
            assert_eq!(parse_to_server(&t).unwrap(), m);
        }
        let back = vec![
            ToClient::Challenge {
                v: VERSION,
                nonce: Hex([4; 32]),
                time: NOW,
            },
            ToClient::PunchGo {
                id: None,
                tag: Hex([1; 16]),
                slot: Hex([2; 16]),
                peer: "192.0.2.1:4000".into(),
            },
            ToClient::Error {
                id: Some(1),
                error: ErrorCode::NotObserved,
                message: String::new(),
            },
        ];
        for m in back {
            let t = serde_json::to_string(&m).unwrap();
            assert_eq!(parse_to_client(&t).unwrap(), m);
        }
        assert_eq!(
            parse_to_server(&" ".repeat(MAX_CONTROL_MSG + 1)),
            Err(ErrorCode::TooLarge)
        );
        let many = ToServer::Claim {
            claims: (0..=MAX_CLAIMS)
                .map(|_| Claim::sign(&[1; 32], [2; 16], [3; 16], &key(1)))
                .collect(),
        };
        assert_eq!(
            parse_to_server(&serde_json::to_string(&many).unwrap()),
            Err(ErrorCode::TooLarge)
        );
        let v2 = r#"{"t":"hello","v":2,"claims":[]}"#;
        assert_eq!(parse_to_server(v2), Err(ErrorCode::Version));
        assert_eq!(
            parse_to_server(r#"{"t":"nonsense"}"#),
            Err(ErrorCode::BadRequest)
        );
    }

    #[test]
    fn observe_requests_and_answers_round_trip() {
        let tx = [7u8; 12];
        for token in [None, Some([9u8; 16])] {
            let req = encode_observe(&tx, token.as_ref());
            let o = parse_observe(&req).unwrap();
            assert_eq!(o.tx, tx);
            assert_eq!(o.token, token);
        }
        for addr in ["198.51.100.7:3334", "[2001:db8::5]:17893"] {
            let a: SocketAddr = addr.parse().unwrap();
            let ans = encode_observed(&tx, a);
            assert_eq!(parse_observed(&ans, &tx), Some(a));
            assert_eq!(parse_observed(&ans, &[0; 12]), None);
        }
    }

    #[test]
    fn junk_datagrams_get_no_answer() {
        assert_eq!(parse_observe(b"VARSTOPU"), None);
        assert_eq!(parse_observe(&[0u8; 20]), None);
        let mut req = encode_observe(&[1; 12], Some(&[2; 16]));
        req[0] = 0x40; // a QUIC short header
        assert_eq!(parse_observe(&req), None);
        let mut long = encode_observe(&[1; 12], None);
        long.resize(MAX_OBSERVE + 4, 0);
        assert_eq!(parse_observe(&long), None);
        // The length field disagrees with the datagram.
        let mut bad = encode_observe(&[1; 12], Some(&[2; 16]));
        bad.truncate(bad.len() - 4);
        assert_eq!(parse_observe(&bad), None);
        // A success response is not a request.
        let ans = encode_observed(&[1; 12], "192.0.2.1:1".parse().unwrap());
        assert_eq!(parse_observe(&ans), None);
    }

    #[test]
    fn the_health_line_round_trips() {
        let h = Health {
            uptime: 5,
            tags: 2,
            slots: 3,
            pair_offers: 1,
            controls: 4,
            relays: 1,
            relay_bytes: 99,
            udp_answered: 7,
            refused: 2,
            rate_limited: 1,
        };
        let line = h.line();
        assert!(!line.contains('\n'));
        assert_eq!(Health::parse(&line), Some(h));
    }

    #[test]
    fn pair_offers_are_bounded() {
        let mut o = PairOffer {
            v: VERSION,
            addrs: vec!["192.0.2.1:17894".into()],
            expires: NOW,
            relay: true,
        };
        o.check().unwrap();
        o.addrs = vec!["192.0.2.1:1".into(); MAX_OFFER_ADDRS + 1];
        assert_eq!(o.check(), Err(ErrorCode::TooLarge));
    }
}
