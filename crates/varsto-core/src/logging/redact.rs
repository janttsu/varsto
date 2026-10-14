// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The last line of defence of the local log: every finished line passes
//! through [`scrub`] before it is written, so a secret that slipped into a
//! message (a token in an error text, a key printed by mistake) still never
//! reaches the file.
//!
//! What it removes:
//! - values registered by the process ([`register_secret`]): the service
//!   token, storage secret keys, passphrases from the environment, …;
//! - keys registered by hash only ([`register_key`]): a 64- or 128-digit hex
//!   run whose bytes hash to a registered key, without keeping a copy of the
//!   key itself here;
//! - token shapes: `vmk_…` (MCP keys), `vst1.…`/`vst2.…` (sealed share
//!   tokens), `vot1.…` (organisation approvals), and dotted hex tokens that
//!   carry a 32-byte key (`<vault>.<folder>.<key>.<name>` share tokens,
//!   `<vault>.<key>` replica tokens);
//! - `name=value` / `name: value` assignments whose name says secret
//!   (passphrase, password, secret, token, mnemonic, bearer);
//! - runs of 12 or more BIP-39 words (recovery words and shares).
//!
//! This is defence in depth: secrets are distinct types whose `Debug` prints
//! `[redacted]`, and code must never log them in the first place.

use std::borrow::Cow;
use std::sync::{OnceLock, RwLock};
use zeroize::Zeroizing;

/// What a removed secret is replaced with.
pub const REDACTED: &str = "[redacted]";

/// Registered secrets are kept only while the process runs; the oldest go
/// first once this many are known.
const MAX_SECRETS: usize = 1024;
/// Shorter values would scrub ordinary words.
const MIN_SECRET_LEN: usize = 8;

static SECRETS: RwLock<Vec<Zeroizing<String>>> = RwLock::new(Vec::new());
static KEY_HASHES: RwLock<Vec<[u8; 32]>> = RwLock::new(Vec::new());

fn hash_key() -> &'static [u8; 32] {
    static K: OnceLock<[u8; 32]> = OnceLock::new();
    K.get_or_init(|| {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        k
    })
}

/// Remember a secret value of this process (a token, a passphrase, a
/// storage secret key) so that it is cut from every log line. Values
/// shorter than 8 characters are ignored.
pub fn register_secret(value: &str) {
    let value = value.trim();
    if value.chars().count() < MIN_SECRET_LEN {
        return;
    }
    let mut v = SECRETS.write().unwrap_or_else(|e| e.into_inner());
    if v.iter().any(|x| x.as_str() == value) {
        return;
    }
    if v.len() >= MAX_SECRETS {
        v.remove(0);
    }
    v.push(Zeroizing::new(value.to_string()));
    // Longest first, so a secret that contains another goes as a whole.
    v.sort_by_key(|x| std::cmp::Reverse(x.len()));
}

/// Remember key material by a keyed hash only: a hex rendering of these
/// bytes (64 or 128 digits) is cut from every log line.
pub fn register_key(bytes: &[u8]) {
    if bytes.len() != 32 && bytes.len() != 64 {
        return;
    }
    let h = *blake3::keyed_hash(hash_key(), bytes).as_bytes();
    let mut v = KEY_HASHES.write().unwrap_or_else(|e| e.into_inner());
    if v.contains(&h) {
        return;
    }
    if v.len() >= MAX_SECRETS {
        v.remove(0);
    }
    v.push(h);
}

/// Whether a field name says its value is secret; such values are written
/// as `[redacted]` whatever they hold.
pub fn secret_field(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const WORDS: [&str; 8] = [
        "passphrase",
        "password",
        "secret",
        "token",
        "mnemonic",
        "words",
        "private",
        "bearer",
    ];
    WORDS.iter().any(|w| n.contains(w))
        || n == "pin"
        || n.ends_with("key_hex")
        || n == "vault_key"
        || n == "master"
}

/// Replace the `user:password@` of every URL in `s` with `with` (nothing
/// at all when `with` is empty, which also drops the `@`): `rest:https://u:p@h/r`
/// becomes `rest:https://[redacted]@h/r`. The userinfo ends at the last `@`
/// before the first `/`, `?` or `#` of the authority.
fn replace_url_userinfo(s: &str, with: &str) -> Option<String> {
    if !s.contains("://") {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    let mut changed = false;
    while let Some(i) = rest.find("://") {
        let (head, after) = rest.split_at(i + 3);
        out.push_str(head);
        let end = after
            .find(|c: char| {
                matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>') || c.is_whitespace()
            })
            .unwrap_or(after.len());
        let authority = &after[..end];
        match authority.rfind('@') {
            Some(at) if at > 0 && &authority[..at] != with => {
                out.push_str(with);
                if !with.is_empty() {
                    out.push_str(&authority[at..]);
                } else {
                    out.push_str(&authority[at + 1..]);
                }
                changed = true;
            }
            _ => out.push_str(authority),
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// `scheme://user:password@host/...` with the userinfo removed.
pub fn strip_url_userinfo(s: &str) -> String {
    replace_url_userinfo(s, "").unwrap_or_else(|| s.to_string())
}

/// A copy of `config.json` for a support bundle: the restic password source
/// and environment file, every S3 access key id and secret, and the
/// `user:password@` of every URL are replaced by `[redacted]`.
pub fn redact_config_json(bytes: &[u8]) -> Vec<u8> {
    fn walk(v: &mut serde_json::Value, in_restic: bool) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, child) in m.iter_mut() {
                    let secret = k == "access_key_id"
                        || k == "secret_access_key"
                        || (in_restic && (k == "password" || k == "env_file"));
                    if secret && !child.is_null() {
                        *child = serde_json::Value::String(REDACTED.to_string());
                    } else {
                        walk(child, in_restic || k == "restic");
                    }
                }
            }
            serde_json::Value::Array(a) => {
                for x in a {
                    walk(x, in_restic);
                }
            }
            serde_json::Value::String(s) => {
                if let Some(c) = replace_url_userinfo(s, REDACTED) {
                    *s = c;
                }
            }
            _ => {}
        }
    }
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(mut v) => {
            walk(&mut v, false);
            serde_json::to_vec_pretty(&v).unwrap_or_default()
        }
        Err(_) => b"{\"config\": \"unreadable; left out of the bundle\"}".to_vec(),
    }
}

/// Remove every secret this module recognises from a log line.
pub fn scrub(line: &str) -> Cow<'_, str> {
    let mut out: Cow<str> = Cow::Borrowed(line);
    {
        let secrets = SECRETS.read().unwrap_or_else(|e| e.into_inner());
        for s in secrets.iter() {
            if out.contains(s.as_str()) {
                out = Cow::Owned(out.replace(s.as_str(), REDACTED));
            }
        }
    }
    for prefix in ["vmk_", "vst1.", "vst2.", "vot1."] {
        if out.contains(prefix) {
            out = Cow::Owned(cut_prefixed(&out, prefix));
        }
    }
    if let Some(s) = replace_url_userinfo(&out, REDACTED) {
        out = Cow::Owned(s);
    }
    if has_marker(&out) {
        out = Cow::Owned(cut_assignments(&out));
    }
    if let Some(s) = cut_hex_keys(&out) {
        out = Cow::Owned(s);
    }
    if let Some(s) = cut_bip39(&out) {
        out = Cow::Owned(s);
    }
    out
}

fn token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '~' | '+' | '/' | '=' | ':')
}

/// `vst2.<anything token-like>` → `vst2.[redacted]`.
fn cut_prefixed(s: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(prefix) {
        let boundary = rest[..i]
            .chars()
            .next_back()
            .map(|c| !c.is_ascii_alphanumeric())
            .unwrap_or(true);
        let after = &rest[i + prefix.len()..];
        out.push_str(&rest[..i + prefix.len()]);
        if !boundary || after.starts_with(REDACTED) {
            rest = after;
            continue;
        }
        let end = after.find(|c: char| !token_char(c)).unwrap_or(after.len());
        if end == 0 {
            rest = after;
            continue;
        }
        out.push_str(REDACTED);
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

const MARKERS: [&str; 6] = [
    "passphrase",
    "password",
    "secret",
    "token",
    "mnemonic",
    "bearer",
];

/// Words after `passphrase:` and the like that are prose, not a secret.
const PROSE: [&str; 24] = [
    "set",
    "the",
    "a",
    "an",
    "is",
    "not",
    "no",
    "missing",
    "none",
    "wrong",
    "required",
    "given",
    "from",
    "for",
    "and",
    "or",
    "was",
    "in",
    "of",
    "to",
    "needed",
    "empty",
    "stored",
    "unchanged",
];

fn has_marker(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    MARKERS.iter().any(|m| l.contains(m))
}

/// `token=abc`, `X-Varsto-Token: abc`, `"password":"abc"`, `Bearer abc` →
/// the value becomes `[redacted]`.
fn cut_assignments(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let bytes = s.as_bytes();
    let mut cuts: Vec<(usize, usize)> = Vec::new();
    for m in MARKERS {
        let mut from = 0;
        while let Some(off) = lower[from..].find(m) {
            let start = from + off;
            from = start + m.len();
            if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
                continue;
            }
            // The name may go on (`token_hex`, `secret_access_key`, `tokens`).
            let mut j = start + m.len();
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'-')
            {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;
            }
            let mut k = j;
            while k < bytes.len() && bytes[k] == b' ' {
                k += 1;
            }
            let assigned = k < bytes.len() && (bytes[k] == b'=' || bytes[k] == b':');
            let colon = assigned && bytes[k] == b':';
            if assigned {
                k += 1;
                while k < bytes.len() && bytes[k] == b' ' {
                    k += 1;
                }
            } else if m == "bearer" && k > j {
                // `Bearer <value>`
            } else {
                continue;
            }
            if s[k..].starts_with(REDACTED) {
                continue;
            }
            let (vs, ve) = if k < bytes.len() && bytes[k] == b'"' {
                let close = s[k + 1..].find('"').map(|e| k + 1 + e).unwrap_or(s.len());
                (k + 1, close)
            } else {
                let end = s[k..]
                    .find(|c: char| {
                        c.is_whitespace()
                            || matches!(c, '&' | ',' | ';' | ')' | '"' | '\'' | ']' | '}')
                    })
                    .map(|e| k + e)
                    .unwrap_or(s.len());
                (k, end)
            };
            // `no passphrase: set VARSTO_PASSPHRASE` is prose, not a value.
            if colon && PROSE.contains(&s[vs..ve].to_ascii_lowercase().as_str()) {
                continue;
            }
            if ve > vs {
                cuts.push((vs, ve));
            }
        }
    }
    apply_cuts(s, cuts)
}

fn apply_cuts(s: &str, mut cuts: Vec<(usize, usize)>) -> String {
    if cuts.is_empty() {
        return s.to_string();
    }
    cuts.sort();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    for (a, b) in cuts {
        if b <= pos {
            continue;
        }
        let a = a.max(pos);
        out.push_str(&s[pos..a]);
        out.push_str(REDACTED);
        pos = b;
    }
    out.push_str(&s[pos..]);
    out
}

/// Hex runs that are registered keys, or the key part of a dotted token.
fn cut_hex_keys(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let keys = KEY_HASHES.read().unwrap_or_else(|e| e.into_inner());
    let mut cuts = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_hexdigit() {
            i += 1;
        }
        let len = i - start;
        if len != 64 && len != 128 {
            continue;
        }
        let bounded = (start == 0 || !b[start - 1].is_ascii_alphanumeric())
            && (i == b.len() || !b[i].is_ascii_alphanumeric());
        if !bounded {
            continue;
        }
        // `<hex id>.<64 hex>`: the key part of a share or replica token.
        let dotted = start >= 17 && b[start - 1] == b'.' && {
            let mut j = start - 1;
            let mut n = 0;
            while j > 0 && b[j - 1].is_ascii_hexdigit() {
                j -= 1;
                n += 1;
            }
            n >= 16
        };
        let registered = !keys.is_empty()
            && hex::decode(&s[start..i])
                .map(|raw| keys.contains(blake3::keyed_hash(hash_key(), &raw).as_bytes()))
                .unwrap_or(false);
        if dotted || registered {
            cuts.push((start, i));
        }
    }
    if cuts.is_empty() {
        None
    } else {
        Some(apply_cuts(s, cuts))
    }
}

/// Twelve or more words of the BIP-39 list in a row: recovery words.
fn cut_bip39(s: &str) -> Option<String> {
    const MIN_RUN: usize = 12;
    let list = bip39::Language::English.word_list();
    let mut cuts = Vec::new();
    let mut run_start = None::<usize>;
    let mut run_end = 0usize;
    let mut run_len = 0usize;
    let mut idx = 0usize;
    let close = |run_start: &mut Option<usize>,
                 run_len: &mut usize,
                 run_end: usize,
                 cuts: &mut Vec<(usize, usize)>| {
        if let Some(st) = run_start.take() {
            if *run_len >= MIN_RUN {
                cuts.push((st, run_end));
            }
        }
        *run_len = 0;
    };
    for word in s.split_inclusive(|c: char| c.is_whitespace()) {
        let w_start = idx;
        idx += word.len();
        let core = word.trim_end_matches(|c: char| c.is_whitespace());
        let core_trim = core.trim_matches(|c: char| {
            matches!(
                c,
                ',' | '.' | '"' | '\'' | ';' | ':' | '(' | ')' | '[' | ']'
            )
        });
        if core_trim.is_empty() {
            // Whitespace only: does not break a run.
            continue;
        }
        let is_word = core_trim.len() >= 3
            && core_trim.bytes().all(|c| c.is_ascii_lowercase())
            && list.binary_search(&core_trim).is_ok();
        if is_word {
            if run_start.is_none() {
                let lead = core.len()
                    - core
                        .trim_start_matches(|c: char| !c.is_ascii_lowercase())
                        .len();
                run_start = Some(w_start + lead);
            }
            run_len += 1;
            let trail = core.len()
                - core
                    .trim_end_matches(|c: char| !c.is_ascii_lowercase())
                    .len();
            run_end = w_start + core.len() - trail;
        } else {
            close(&mut run_start, &mut run_len, run_end, &mut cuts);
        }
    }
    close(&mut run_start, &mut run_len, run_end, &mut cuts);
    if cuts.is_empty() {
        None
    } else {
        Some(apply_cuts(s, cuts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_userinfo_is_cut_everywhere() {
        for (line, host) in [
            (
                "repo rest:https://u:p@h.example/r",
                "rest:https://[redacted]@h.example/r",
            ),
            (
                "s3:https://K:S@h.example:9000/bucket",
                "s3:https://[redacted]@h.example:9000/bucket",
            ),
            (
                "sftp://user@host/path and https://a:b@c/d",
                "sftp://[redacted]@host/path and https://[redacted]@c/d",
            ),
        ] {
            let got = scrub(line);
            assert!(
                !got.contains("u:p") && !got.contains("K:S") && !got.contains("a:b"),
                "{got}"
            );
            assert!(
                got.contains(host.split(' ').next().unwrap()) || got == host,
                "{got}"
            );
        }
        assert_eq!(scrub("rest:https://u:p@h/r"), "rest:https://[redacted]@h/r");
        // Not a login: no userinfo, an @ later in the path, other schemes.
        assert_eq!(scrub("https://example.com/a@b"), "https://example.com/a@b");
        assert_eq!(
            scrub("see https://example.com:8000/x"),
            "see https://example.com:8000/x"
        );
        assert_eq!(
            strip_url_userinfo("rest:https://u:p@h:8000/r"),
            "rest:https://h:8000/r"
        );
        assert_eq!(strip_url_userinfo("/mnt/backup"), "/mnt/backup");
    }

    #[test]
    fn a_config_copy_for_a_bundle_has_no_credentials() {
        let cfg = serde_json::json!({
            "storages": [{"kind": "s3", "name": "c", "bucket": "b", "access_key_id": "AKIAEXAMPLE", "endpoint": "https://k:s@s3.example"}],
            "restic": {
                "repository": "rest:https://u:p@h/r",
                "password": {"command": "pass show backup/restic"},
                "env_file": "/home/x/restic.env",
                "binary": "restic"
            },
            "log_level": "debug"
        });
        let out = String::from_utf8(redact_config_json(cfg.to_string().as_bytes())).unwrap();
        for secret in ["AKIAEXAMPLE", "u:p", "k:s", "pass show", "restic.env"] {
            assert!(!out.contains(secret), "{secret} in {out}");
        }
        assert!(out.contains("rest:https://[redacted]@h/r"), "{out}");
        assert!(out.contains("\"log_level\": \"debug\""), "{out}");
        assert!(redact_config_json(b"not json").starts_with(b"{"));
    }

    #[test]
    fn registered_values_are_cut() {
        register_secret("s3-secret-VALUE-1234567");
        let s = scrub("PUT failed with key s3-secret-VALUE-1234567 here");
        assert!(!s.contains("s3-secret-VALUE"), "{s}");
        assert!(s.contains(REDACTED));
        // Short values are not registered.
        register_secret("abc");
        assert_eq!(scrub("abc def"), "abc def");
    }

    #[test]
    fn token_shapes_are_cut() {
        let s =
            scrub("accepted vst2.AbC-123_x.yz and vst1.qqq vmk_0123456789abcdef and vot1.aa.bb");
        assert!(!s.contains("AbC"), "{s}");
        assert!(!s.contains("qqq"), "{s}");
        assert!(!s.contains("0123456789abcdef"), "{s}");
        assert!(!s.contains("aa.bb"), "{s}");
        assert!(s.contains("vst2.[redacted]"));
        // Not a token: a word that merely contains the prefix.
        assert_eq!(scrub("xvst2.abc"), "xvst2.abc");
    }

    #[test]
    fn assignments_are_cut() {
        for line in [
            "url http://127.0.0.1:1234/?token=deadbeefcafe&x=1",
            "header X-Varsto-Token: deadbeefcafe",
            r#"body {"passphrase":"deadbeefcafe"}"#,
            "env VARSTO_PASSPHRASE=deadbeefcafe",
            "AWS_SECRET_ACCESS_KEY=deadbeefcafe",
            "Authorization: Bearer deadbeefcafe",
            "restic password: deadbeefcafe",
        ] {
            let s = scrub(line);
            assert!(!s.contains("deadbeefcafe"), "{line} -> {s}");
        }
        assert!(scrub("http://x/?token=deadbeefcafe&x=1").ends_with("&x=1"));
        assert_eq!(
            scrub("no passphrase: set VARSTO_PASSPHRASE"),
            "no passphrase: set VARSTO_PASSPHRASE"
        );
        // Names that only resemble a marker stay.
        assert_eq!(scrub("key_epoch=3 tokenizer"), "key_epoch=3 tokenizer");
    }

    #[test]
    fn dotted_key_tokens_and_registered_keys_are_cut() {
        let key = "ab".repeat(32);
        let share = format!("{}.{}.{}.Photos", "1".repeat(32), "2".repeat(32), key);
        let line = format!("share token {share}");
        let s = scrub(&line);
        assert!(!s.contains(&key), "{s}");
        // A chunk id alone is not a secret.
        let chunk = "cd".repeat(32);
        assert!(scrub(&format!("chunks/{chunk}")).contains(&chunk));
        // A registered key is cut wherever it appears.
        let raw = [7u8; 32];
        register_key(&raw);
        let line = format!("master {}", hex::encode(raw));
        let s = scrub(&line);
        assert!(!s.contains(&hex::encode(raw)), "{s}");
    }

    #[test]
    fn recovery_words_are_cut() {
        let words = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid";
        let line = format!("1: {words} done");
        let s = scrub(&line);
        assert!(!s.contains("absurd"), "{s}");
        assert!(s.starts_with("1: [redacted]"), "{s}");
        assert!(s.ends_with(" done"), "{s}");
        // Ordinary text with a few list words stays.
        let t = "the sync of folder Photos found about ten new files";
        assert_eq!(scrub(t), t);
    }

    #[test]
    fn secret_field_names() {
        for n in [
            "token",
            "service_token",
            "passphrase",
            "secret_access_key",
            "key_hex",
            "words",
            "pin",
        ] {
            assert!(secret_field(n), "{n}");
        }
        for n in ["key", "key_id", "key_epoch", "path", "bytes", "folder"] {
            assert!(!secret_field(n), "{n}");
        }
    }
}
