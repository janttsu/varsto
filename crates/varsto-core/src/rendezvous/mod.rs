// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The rendezvous service, client side (`alpha-0-format.md` section 83).
//!
//! A small server (`crates/varsto-rendezvous`, default
//! `https://varsto.net/rv`, self-hostable) where devices of a vault find
//! each other across networks, coordinate UDP hole punching and, as the
//! last route, relay their pinned TLS sessions. It is additive: LAN, direct
//! routes, peer relays and the storages work without it, and every call
//! here is short, runs in the background and fails quietly (spec 79).
//!
//! - [`proto`]: wire formats shared with the server (HTTP JSON, control
//!   WebSocket JSON, STUN-shaped UDP), signatures, limits.
//! - [`keys`]: the vault tag, device slots, owner keys, sealed blobs, the
//!   pairing tags.
//! - [`client`]: HTTP, the control channel, the relay stream.
//!
//! The helpers below put those together for the three uses: publish this
//! device's peer record, read the vault's records, and pairing offers.

pub mod client;
pub mod keys;
pub mod proto;

pub use client::{BaseUrl, Control, RelayStream, RvClient, RvError, Welcome};
pub use keys::{PairKeys, VaultKeys};
pub use proto::{Kind, PairOffer, Slot, Tag, Token};

use crate::record::{Id16, Parts};
use ed25519_dalek::SigningKey;

/// The environment variable that overrides the setting for one process:
/// `off` turns the rendezvous off, a URL replaces the configured one (the
/// lab, tests, a device that joins through a self-hosted server).
pub const ENV_OVERRIDE: &str = "VARSTO_RENDEZVOUS";

fn from_env() -> Option<Option<String>> {
    let v = std::env::var(ENV_OVERRIDE).ok()?;
    let v = v.trim();
    Some(match v {
        "" | "off" | "none" | "0" => None,
        url => Some(url.to_string()),
    })
}

/// The rendezvous base URL a vault device uses: `p2p.rendezvous` of its
/// configuration, unless [`ENV_OVERRIDE`] says otherwise. `None`: off.
pub fn configured(cfg: &crate::vault::P2pConfig) -> Option<String> {
    from_env().unwrap_or_else(|| cfg.rendezvous.clone())
}

/// The rendezvous a device that is joining (it has no configuration yet)
/// looks a pairing offer up at: the one the pairing link names (`rvu=`,
/// an offer at a self-hosted server), else the default service, unless
/// [`ENV_OVERRIDE`] says otherwise (`off` wins over the link).
pub fn for_joining(link_url: Option<&str>) -> Option<String> {
    match from_env() {
        Some(None) => None,
        env => link_url
            .map(str::to_string)
            .or_else(|| env.flatten())
            .or_else(crate::vault::default_rendezvous),
    }
}

/// Unix seconds, as every signed timestamp carries them.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How long a published peer slot lives: the maximum, 48 h. The service
/// writes it again whenever its record changes and at least every
/// [`PEER_REFRESH`].
pub const PEER_TTL: u32 = proto::PEER_TTL_MAX;
/// How often the service rewrites its peer slot even when nothing changed.
pub const PEER_REFRESH: std::time::Duration = std::time::Duration::from_secs(6 * 3600);
/// How often the service reads the vault's slots (and at start).
pub const PEER_FETCH: std::time::Duration = std::time::Duration::from_secs(180);

/// Publish this device's peer record (`parts`: the sealed record exactly
/// as `peer::publish` writes it to a storage) in its slot under the vault
/// tag, owned by `owner` (`keys::owner_key`).
pub fn publish_peer(
    rv: &RvClient,
    vault: &VaultKeys,
    owner: &SigningKey,
    device: &Id16,
    parts: &Parts,
) -> Result<proto::PutAnswer, RvError> {
    publish_peer_at(rv, vault, owner, device, parts, now())
}

/// `publish_peer` with the signed timestamp `ts` (it must rise from one
/// write of the slot to the next: `max(now, last + 1)`).
pub fn publish_peer_at(
    rv: &RvClient,
    vault: &VaultKeys,
    owner: &SigningKey,
    device: &Id16,
    parts: &Parts,
    ts: u64,
) -> Result<proto::PutAnswer, RvError> {
    let slot = vault.slot(device);
    let blob = vault.seal_peer(&slot, parts).map_err(RvError::Transport)?;
    let put = proto::PutSlot::sign(Kind::Peer, vault.tag(), slot, owner, ts, PEER_TTL, blob);
    rv.put(&put)
}

/// Every peer record the vault's slots hold, opened: `(slot, parts)` to
/// hand to the record acceptor (`PeerDirectory` merge, spec 77.8). Blobs
/// that do not open (another vault's garbage, a damaged one) are skipped
/// and counted in the second value.
pub fn fetch_peers(
    rv: &RvClient,
    vault: &VaultKeys,
) -> Result<(Vec<(Slot, Parts)>, usize), RvError> {
    let mut out = Vec::new();
    let mut bad = 0;
    for e in rv.lookup(&vault.tag())? {
        match vault.open_peer(&e.slot.0, &e.blob.0) {
            Ok(parts) => out.push((e.slot.0, parts)),
            Err(_) => bad += 1,
        }
    }
    Ok((out, bad))
}

/// Register a pairing offer under the code's tag and, when given, under
/// the link's `rv=` token, both owned by `owner` (an ephemeral key). A
/// code tag that is taken by another offer answers [`proto::ErrorCode::TagFull`]:
/// the offering device then draws a new code.
pub fn register_pair_offer(
    rv: &RvClient,
    digits: &str,
    token: Option<&Token>,
    offer: &PairOffer,
    owner: &SigningKey,
) -> Result<(), RvError> {
    let mut keys = vec![keys::pair_code_keys(digits).map_err(RvError::Transport)?];
    if let Some(t) = token {
        keys.push(keys::pair_token_keys(t, digits).map_err(RvError::Transport)?);
    }
    let ttl = offer
        .expires
        .saturating_sub(now())
        .clamp(1, proto::PAIR_TTL_MAX as u64) as u32;
    for k in keys {
        let blob = k.seal(offer).map_err(RvError::Transport)?;
        let put =
            proto::PutSlot::sign(Kind::Pair, k.tag, proto::PAIR_SLOT, owner, now(), ttl, blob);
        rv.put(&put)?;
    }
    Ok(())
}

/// Remove a pairing offer's slots (the offer was taken or closed).
pub fn withdraw_pair_offer(
    rv: &RvClient,
    digits: &str,
    token: Option<&Token>,
    owner: &SigningKey,
) -> Result<(), RvError> {
    let mut tags = vec![
        keys::pair_code_keys(digits)
            .map_err(RvError::Transport)?
            .tag,
    ];
    if let Some(t) = token {
        tags.push(
            keys::pair_token_keys(t, digits)
                .map_err(RvError::Transport)?
                .tag,
        );
    }
    for tag in tags {
        rv.delete(&proto::DeleteSlot::sign(
            tag,
            proto::PAIR_SLOT,
            owner,
            now(),
        ))?;
    }
    Ok(())
}

/// Look a pairing offer up: by the link's token first (when the joiner
/// scanned a link), then by the code. `None` when neither tag holds an
/// offer that opens.
pub fn find_pair_offer(
    rv: &RvClient,
    digits: &str,
    token: Option<&Token>,
) -> Result<Option<(PairKeys, PairOffer)>, RvError> {
    let mut candidates = Vec::new();
    if let Some(t) = token {
        candidates.push(keys::pair_token_keys(t, digits).map_err(RvError::Transport)?);
    }
    candidates.push(keys::pair_code_keys(digits).map_err(RvError::Transport)?);
    for k in candidates {
        for e in rv.lookup(&k.tag)? {
            if let Ok(offer) = k.open(&e.blob.0) {
                if offer.expires >= now() {
                    return Ok(Some((k, offer)));
                }
            }
        }
    }
    Ok(None)
}
