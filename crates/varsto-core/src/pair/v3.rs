// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Pairing of format 3 (design sections 6 and 8), behind the `format3`
//! feature. The SPAKE2 exchange is the one of section 68, with three
//! changes:
//!
//! - the joining device's hello carries its K6 (signing) and K8 (KEM)
//!   public keys and its name, and both key confirmations bind them, so a
//!   device in the middle that relays SPAKE2 cannot swap them;
//! - the offering device shows that name and the six-word fingerprint of
//!   the keys (`crate::fingerprint::of_keys`) and asks the person before it
//!   sends anything (`Approve`);
//! - the vault key arrives sealed to the joiner's K8 inside the
//!   SPAKE2-sealed bundle: someone who learnt the code and ran the exchange
//!   still cannot open it without that K8.
//!
//! Discovery answers to `rendezvous(code)`, a tag derived from the code
//! (`derive("pair-rendezvous", code)`), instead of the code's first digits.

use super::{
    discover_rv, field, normalize, read_line, session_key, spake_ids, write_line, Attempt, Bundle,
    Offer, WrongCode, CONNECT_TIMEOUT, IO_TIMEOUT,
};
use crate::crypto::{self, SecretKey, VerifyingKey};
use crate::kem::{DecapsKey, EncapsKey};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Password, Spake2};
use std::io::BufReader;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// The protocol number in the hello.
pub const VERSION: u64 = 3;

/// Who asks to join, as the offering device shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Joiner {
    pub name: String,
    /// K6 public key (`VerifyingKey::to_bytes`).
    pub signing_pub: Vec<u8>,
    /// K8 public key (`EncapsKey::to_bytes`).
    pub kem_pub: Vec<u8>,
    /// The six words over both keys and the name.
    pub fingerprint: String,
}

/// Asks the person at the offering device whether `Joiner` may join (it
/// blocks until they answer; the interface shows name and fingerprint).
pub type Approve = Arc<dyn Fn(&Joiner) -> bool + Send + Sync>;

/// The discovery tag of a code: 10 bits of `derive("pair-rendezvous",
/// code)`, as decimal. Ten bits tell concurrent offers on one network apart
/// as well as three digits did and say as little about the code (a
/// listener narrows the 10^9 codes to about a million either way, and has
/// three online tries); unlike the digits, it is no part of the password.
pub fn rendezvous(digits: &str) -> String {
    let h = blake3::derive_key("e2ee-sync-format/3/pair-rendezvous", digits.as_bytes());
    (u16::from_le_bytes([h[0], h[1]]) & 0x3ff).to_string()
}

/// The keys and name of the hello, as both confirmations bind them.
fn transcript(name: &str, signing_pub: &[u8], kem_pub: &[u8]) -> [u8; 32] {
    crypto::hash(&crypto::aad_for_format(
        crate::record::FORMAT,
        "pair-hello",
        &[name.as_bytes(), signing_pub, kem_pub],
    ))
}

fn confirm(key: &SecretKey, side: &str, transcript: &[u8; 32]) -> String {
    let mut msg = format!("varsto-pair/3 confirm {side}").into_bytes();
    msg.extend_from_slice(transcript);
    hex::encode(crypto::keyed_hash(key, &msg))
}

fn vault_key_aad(vault_id: &str, kem_pub: &[u8]) -> Vec<u8> {
    crypto::aad_for_format(
        crate::record::FORMAT,
        "pair-vault-key",
        &[vault_id.as_bytes(), &crypto::hash(kem_pub)],
    )
}

/// The vault key sealed to a K8: KEM ciphertext, then the key under the
/// KEM secret.
pub fn seal_vault_key(vault_id: &str, kem: &EncapsKey, vault_key: &SecretKey) -> Result<Vec<u8>> {
    let (ct, secret) = kem.encapsulate()?;
    let mut out = ct;
    out.extend_from_slice(&crypto::encrypt(
        &secret,
        &vault_key_aad(vault_id, &kem.to_bytes()),
        vault_key.as_bytes(),
    )?);
    Ok(out)
}

/// Open a vault key sealed by `seal_vault_key` with this device's K8.
pub fn open_vault_key(vault_id: &str, kem: &DecapsKey, sealed: &[u8]) -> Result<SecretKey> {
    let ct = sealed
        .get(..crate::kem::CIPHERTEXT_LEN)
        .ok_or_else(|| anyhow!("sealed vault key too short"))?;
    let secret = kem.decapsulate(ct)?;
    let plain = crypto::decrypt(
        &secret,
        &vault_key_aad(vault_id, &kem.public().to_bytes()),
        &sealed[crate::kem::CIPHERTEXT_LEN..],
    )
    .context("the vault key is not sealed to this device")?;
    SecretKey::from_bytes(&plain)
}

/// What travels under the SPAKE2 key.
#[derive(Serialize, Deserialize)]
struct Payload {
    /// The bundle, its `vault_key` empty.
    bundle: Bundle,
    /// `seal_vault_key` to the joiner's K8, hex.
    vault_key: String,
}

impl Offer {
    /// Open a format-3 offer: `bundle` (whose `vault_key` is not sent) and
    /// the vault key, which goes sealed to the joiner's K8 once `approve`
    /// said yes.
    pub fn start_v3(bundle: Bundle, vault_key: SecretKey, approve: Approve) -> Result<Offer> {
        Offer::start_with(&rendezvous, move |stream, digits| {
            offer_exchange(stream, digits, &bundle, &vault_key, &approve)
        })
    }
}

fn offer_exchange(
    stream: TcpStream,
    digits: &str,
    bundle: &Bundle,
    vault_key: &SecretKey,
    approve: &Approve,
) -> Result<String, Attempt> {
    let broken = |_| Attempt::Broken;
    stream.set_nonblocking(false).map_err(broken)?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(broken)?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(broken)?;
    let mut w = stream.try_clone().map_err(broken)?;
    let mut r = BufReader::new(stream);
    let hello = read_line(&mut r).map_err(|_| Attempt::Broken)?;
    if hello.get("v").and_then(|v| v.as_u64()) != Some(VERSION) {
        return Err(Attempt::Broken);
    }
    let name = field(&hello, "name").map_err(|_| Attempt::Broken)?;
    let hexf = |k: &str| {
        field(&hello, k)
            .ok()
            .and_then(|v| hex::decode(v).ok())
            .ok_or(Attempt::Broken)
    };
    let (msg_b, k6, k8) = (hexf("spake")?, hexf("k6")?, hexf("k8")?);
    // Keys that do not parse are no hello at all.
    VerifyingKey::from_bytes(&k6).map_err(|_| Attempt::Broken)?;
    let kem = EncapsKey::from_bytes(&k8).map_err(|_| Attempt::Broken)?;
    let tr = transcript(&name, &k6, &k8);
    let (ida, idb) = spake_ids();
    let (spake, msg_a) = Spake2::<Ed25519Group>::start_a(&Password::new(digits), &ida, &idb);
    let key = spake
        .finish(&msg_b)
        .ok()
        .and_then(|k| session_key(&k).ok())
        .ok_or(Attempt::Broken)?;
    write_line(
        &mut w,
        &serde_json::json!({"spake": hex::encode(msg_a), "confirm": confirm(&key, "offer", &tr)}),
    )
    .map_err(|_| Attempt::Broken)?;
    let theirs = read_line(&mut r)
        .ok()
        .and_then(|reply| field(&reply, "confirm").ok());
    if !theirs
        .as_deref()
        .is_some_and(|t| crypto::ct_eq(t.as_bytes(), confirm(&key, "join", &tr).as_bytes()))
    {
        return Err(Attempt::Wrong);
    }
    let joiner = Joiner {
        fingerprint: crate::fingerprint::of_keys(&k6, &k8),
        name: name.clone(),
        signing_pub: k6,
        kem_pub: k8,
    };
    if !approve(&joiner) {
        let _ = write_line(&mut w, &serde_json::json!({"error": "declined"}));
        return Err(Attempt::Declined(name));
    }
    let mut sent = bundle.clone();
    sent.vault_key = String::new();
    let payload = Payload {
        vault_key: hex::encode(
            seal_vault_key(&bundle.vault_id, &kem, vault_key).map_err(|_| Attempt::Broken)?,
        ),
        bundle: sent,
    };
    let plain = serde_json::to_vec(&payload).map_err(|_| Attempt::Broken)?;
    let sealed = crypto::encrypt(
        &key.derive("pair-bundle-3", &[]),
        b"varsto-pair-bundle-3",
        &plain,
    )
    .map_err(|_| Attempt::Broken)?;
    write_line(&mut w, &serde_json::json!({"bundle": hex::encode(sealed)}))
        .map_err(|_| Attempt::Broken)?;
    let done = read_line(&mut r).map_err(|_| Attempt::Broken)?;
    if done.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(Attempt::Broken);
    }
    Ok(name)
}

/// The keys a joining device brings.
pub struct JoinKeys<'a> {
    pub name: &'a str,
    /// K6 public key.
    pub signing_pub: Vec<u8>,
    /// K8, whose public half goes in the hello and which opens the vault key.
    pub kem: &'a DecapsKey,
}

/// The person at the offering device said no.
#[derive(Debug)]
pub struct Declined;

impl std::fmt::Display for Declined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the other device did not let this one join")
    }
}

impl std::error::Error for Declined {}

/// Run the exchange with an offering device: the bundle and the vault key.
pub fn fetch(code: &str, keys: &JoinKeys<'_>, addr: SocketAddr) -> Result<(Bundle, SecretKey)> {
    let digits = normalize(code)?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .with_context(|| format!("cannot reach {addr}"))?;
    // The person at the other device decides; give them time.
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);
    let k8 = keys.kem.public().to_bytes();
    let tr = transcript(keys.name, &keys.signing_pub, &k8);
    let (ida, idb) = spake_ids();
    let (spake, msg_b) = Spake2::<Ed25519Group>::start_b(&Password::new(&digits), &ida, &idb);
    write_line(
        &mut w,
        &serde_json::json!({
            "v": VERSION,
            "name": keys.name,
            "spake": hex::encode(msg_b),
            "k6": hex::encode(&keys.signing_pub),
            "k8": hex::encode(&k8),
        }),
    )?;
    let answer = read_line(&mut r)?;
    let msg_a = hex::decode(field(&answer, "spake")?)?;
    let key = session_key(
        &spake
            .finish(&msg_a)
            .map_err(|e| anyhow!("pairing failed: {e}"))?,
    )?;
    if !crypto::ct_eq(
        field(&answer, "confirm")?.as_bytes(),
        confirm(&key, "offer", &tr).as_bytes(),
    ) {
        let _ = write_line(&mut w, &serde_json::json!({"error": "wrong code"}));
        return Err(WrongCode.into());
    }
    write_line(
        &mut w,
        &serde_json::json!({"confirm": confirm(&key, "join", &tr)}),
    )?;
    let reply = read_line(&mut r)?;
    if reply.get("error").and_then(|e| e.as_str()) == Some("declined") {
        return Err(Declined.into());
    }
    let sealed = hex::decode(field(&reply, "bundle")?)?;
    let plain = crypto::decrypt(
        &key.derive("pair-bundle-3", &[]),
        b"varsto-pair-bundle-3",
        &sealed,
    )?;
    let payload: Payload = serde_json::from_slice(&plain)?;
    let vault_key = open_vault_key(
        &payload.bundle.vault_id,
        keys.kem,
        &hex::decode(&payload.vault_key)?,
    )?;
    write_line(&mut w, &serde_json::json!({"ok": true}))?;
    Ok((payload.bundle, vault_key))
}

/// Find an open format-3 offer on the LAN for this code.
pub fn discover(code: &str, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let digits = normalize(code)?;
    discover_rv(code, &rendezvous(&digits), timeout)
}

/// Join: the typed address first, then the search of the network.
pub fn receive(
    code: &str,
    keys: &JoinKeys<'_>,
    address: Option<&str>,
) -> Result<(Bundle, SecretKey)> {
    use std::net::ToSocketAddrs;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    if let Some(t) = address.map(str::trim).filter(|t| !t.is_empty()) {
        addrs.extend(t.to_socket_addrs()?);
    }
    let mut last = None;
    for a in &addrs {
        match fetch(code, keys, *a) {
            Ok(x) => return Ok(x),
            Err(e) if e.downcast_ref::<WrongCode>().is_some() => return Err(e),
            Err(e) if e.downcast_ref::<Declined>().is_some() => return Err(e),
            Err(e) => last = Some(e),
        }
    }
    for a in discover(code, super::DISCOVER_TIMEOUT)? {
        if addrs.contains(&a) {
            continue;
        }
        match fetch(code, keys, a) {
            Ok(x) => return Ok(x),
            Err(e) if e.downcast_ref::<WrongCode>().is_some() => return Err(e),
            Err(e) if e.downcast_ref::<Declined>().is_some() => return Err(e),
            Err(e) => last = Some(e),
        }
    }
    match last {
        Some(e) => Err(e),
        None => bail!("no device offering this code answered"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use std::sync::Mutex;

    fn addr(o: &Offer) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], o.status().port))
    }

    fn bundle() -> Bundle {
        super::super::tests::bundle()
    }

    #[test]
    fn the_hello_shows_name_and_fingerprint_and_the_vault_key_opens_only_with_k8() {
        let k6 = SigningKey::generate();
        let k8 = DecapsKey::generate();
        let vault_key = SecretKey::random();
        let seen: Arc<Mutex<Vec<Joiner>>> = Arc::default();
        let seen2 = seen.clone();
        let o = Offer::start_v3(
            bundle(),
            vault_key.clone(),
            Arc::new(move |j: &Joiner| {
                seen2.lock().unwrap().push(j.clone());
                true
            }),
        )
        .unwrap();
        let code = o.status().code;
        let keys = JoinKeys {
            name: "phone",
            signing_pub: k6.public().to_bytes(),
            kem: &k8,
        };
        let (b, got) = fetch(&code, &keys, addr(&o)).unwrap();
        assert_eq!(got.as_bytes(), vault_key.as_bytes());
        assert!(
            b.vault_key.is_empty(),
            "the bundle carries no plain vault key"
        );
        assert_eq!(b.storages[0].secret.as_deref(), Some("s3cret"));
        let j = seen.lock().unwrap()[0].clone();
        assert_eq!(j.name, "phone");
        assert_eq!(j.signing_pub, k6.public().to_bytes());
        assert_eq!(j.kem_pub, k8.public().to_bytes());
        assert_eq!(
            j.fingerprint,
            crate::fingerprint::of_keys(&k6.public().to_bytes(), &k8.public().to_bytes())
        );
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(o.status().paired_with.as_deref(), Some("phone"));

        // The sealed key: only the joiner's K8 opens it.
        let sealed = seal_vault_key("v", &k8.public(), &vault_key).unwrap();
        assert_eq!(
            open_vault_key("v", &k8, &sealed).unwrap().as_bytes(),
            vault_key.as_bytes()
        );
        assert!(open_vault_key("v", &DecapsKey::generate(), &sealed).is_err());
        assert!(open_vault_key("other vault", &k8, &sealed).is_err());
    }

    #[test]
    fn a_declined_device_gets_nothing_and_the_offer_closes() {
        let k8 = DecapsKey::generate();
        let o =
            Offer::start_v3(bundle(), SecretKey::random(), Arc::new(|_: &Joiner| false)).unwrap();
        let keys = JoinKeys {
            name: "stranger",
            signing_pub: SigningKey::generate().public().to_bytes(),
            kem: &k8,
        };
        let e = fetch(&o.status().code, &keys, addr(&o)).err().unwrap();
        assert!(e.downcast_ref::<Declined>().is_some(), "{e}");
        std::thread::sleep(Duration::from_millis(300));
        let s = o.status();
        assert!(!s.open && s.paired_with.is_none());
        assert_eq!(s.closed_reason.as_deref(), Some("declined stranger"));
    }

    #[test]
    fn a_wrong_code_is_refused_before_anything_is_shown() {
        let asked = Arc::new(Mutex::new(0));
        let asked2 = asked.clone();
        let o = Offer::start_v3(
            bundle(),
            SecretKey::random(),
            Arc::new(move |_: &Joiner| {
                *asked2.lock().unwrap() += 1;
                true
            }),
        )
        .unwrap();
        let code = o.status().code;
        let wrong = if code.starts_with('0') {
            "111-111-111"
        } else {
            "000-000-000"
        };
        let k8 = DecapsKey::generate();
        let keys = JoinKeys {
            name: "mallory",
            signing_pub: SigningKey::generate().public().to_bytes(),
            kem: &k8,
        };
        let e = fetch(wrong, &keys, addr(&o)).err().unwrap();
        assert!(e.downcast_ref::<WrongCode>().is_some(), "{e}");
        assert_eq!(*asked.lock().unwrap(), 0);
    }

    #[test]
    fn the_rendezvous_tag_is_not_the_digits() {
        let t = rendezvous("123456789");
        assert_eq!(t, rendezvous("123456789"));
        assert!(t.parse::<u16>().unwrap() < 1024);
        // Over many codes the tags spread over the 1024 values.
        let tags: std::collections::BTreeSet<String> = (0..5000u32)
            .map(|i| rendezvous(&format!("{i:09}")))
            .collect();
        assert!(tags.len() > 900, "{}", tags.len());
    }

    #[test]
    fn discovery_finds_a_v3_offer_by_its_tag() {
        let o =
            Offer::start_v3(bundle(), SecretKey::random(), Arc::new(|_: &Joiner| true)).unwrap();
        let code = o.status().code;
        let found = discover(&code, Duration::from_secs(5)).unwrap();
        assert!(
            found.iter().any(|a| a.port() == o.status().port),
            "{found:?}"
        );
    }
}
