# Format 2 design: blocks, keys and signed records

This is the binding design for storage format version 2. Backward compatibility is not required: format-2 vaults are created fresh; format-0/1 vaults are refused with a clear message. Everything here supersedes the conflicting sentences of `alpha-0-format.md` sections 3, 4, 5, 6, 7, 11, 18, 21, 24, 30. Design goals, in order: (1) no party below full-device trust can change what another device sees; (2) no key material ever leaves a device without a signed, manually approved grant; (3) a storage sees only opaque, padded-by-packing objects; (4) every authentication decision is a signature check against a device key the vault already trusts, never a shared symmetric secret; (5) one key, one purpose; (6) nothing in the format relies on wall-clock time for security.

## 1. Keys

| Key | Purpose | How made | Where |
| --- | --- | --- | --- |
| K1 recovery key | escrow of every folder key and Strongroom key the user opts in | 256 random bits, 24 BIP-39 words, optional Shamir 2-of-3 | paper only; never on a device after the kit is printed |
| K2 = derive(K1, "recovery-wrap") | wrap folder keys for recovery | derived | in memory while printing a kit or writing escrow |
| K3 vault key | registry, ledger, local keyring, peer authentication, pool markers | 256 random bits; 24 words (second word set of the kit) | every full device, wrapped under K4 |
| K4 device unlock key | wrap K3 and K6 on one device | Argon2id (64 MiB, 3, 1) of the NFKC passphrase; on Android/iOS additionally wrapped by Keystore/Keychain | not stored |
| K6 device signing key | sign everything this device publishes | Ed25519 + ML-DSA-65, generated on the device, never exported | device only |
| K8 device KEM key | receive sealed keys | X25519 + ML-KEM-768, generated on the device | device only; public part in the device record |
| K9 folder key | one folder, one epoch | 256 random bits | only as grants (section 4) and escrow (section 5); never derived from K3 |
| K10 = derive(K9, "folder-metadata", folder) | manifests, trash records, snapshots, thumbnails, notes, history, pack indexes | derived | holders of K9 |
| K11 = derive(K9₀, "dedup-hash", folder) | chunk ids and content hashes; fixed at the folder's first epoch | derived once, carried to later epochs inside the epoch record | holders of any K9 epoch |
| K12 chunker seed = derive(K11, "chunker-seed") | Gear table seed | derived | holders of K11 |
| K14 chunk key = derive(K9ₑ, "chunk-key", folder, chunk id) | one chunk | derived | holders of K9ₑ |
| chunk nonce = keyed_hash(derive(K9ₑ, "chunk-nonce", folder), packed bytes)[..24] | one AEAD input | derived from the exact bytes that are encrypted | holders of K9ₑ |
| K13 Strongroom key | as K9 for a Strongroom folder | random; wrapped only under FIDO2 hmac-secret outputs (and K2 if the user opts in) | never under K3 |

Removed: `derive(K_epoch, "folder-epoch", vault, folder)` (folder keys from the vault key), `passphrase_key_raw`, Ed25519-only signing keys and `sig_alg = "ed25519"`, plain share tokens, `vst1` tokens, bare (unsigned) epoch records, folder records that carry `key_hex`.

K3 still wraps nothing that opens content. A holder of K3 alone can read the device registry, the ledger (object claims with keyed chunk ids), folder names and sizes, and can write ledger batches that other devices verify against the registry; it cannot open any manifest, chunk, trash record or snapshot.

## 2. Blocks and packs

- **Chunking**: content-defined (Gear/FastCDC) with the Gear table seeded from K12, so cut points are secret per folder. Size tiers by file size (`chunking: 2`): < 1 MiB one chunk; 1–32 MiB avg 1 MiB (min 256 KiB, max 4 MiB); 32 MiB–1 GiB avg 4 MiB (1–16 MiB); ≥ 1 GiB avg 8 MiB (2–16 MiB). Chunk id = keyed BLAKE3(K11, plaintext). Content hash = keyed BLAKE3(K11, whole file).
- **Packing**: `pack(plain)` = method byte || payload, method 0 raw, 1 zstd level 3; compression is attempted only when a 64 KiB probe at level 1 saves at least 5 % (deterministic, content-only). The AEAD plaintext is the packed bytes. The nonce is derived from the packed bytes (table above), so two different encodings of the same chunk can never share a nonce.
- **AAD** for a chunk: format 2, "chunk", vault id, folder id, epoch, chunk id, plaintext length (unpacked), packed length.
- **Objects**: every chunk of a push is appended to a **pack**: `packs/<xx>/<pack id>` where pack id = BLAKE3 of the pack bytes; target 64 MiB on hot, local, pool and transferrer storages, 256 MiB on cold; written with put-if-absent (S3 multipart when > 64 MiB). A pack is a plain concatenation of chunk objects (each `nonce || ciphertext || tag`); the per-chunk object name (BLAKE3 of its bytes) still exists logically and is what the ledger, verification and P2P use. There are no single-chunk objects any more, so a storage sees only pack sizes.
- **Pack index**: per push, `packs/index/<device>/<seq>.enc`: postcard + zstd, encrypted under K10 of the folder with AAD (format 2, "pack-index", vault, folder, device, seq), signed with the record envelope of section 3, listing (pack id, offset, length, object name, chunk id) for every chunk written. The `ChunkStored` ledger event carries (pack id, offset, length) as well, so a reader that already holds the ledger needs no index to fetch; the index is for fsck, recovery and readers that join later.
- **Deletion and GC**: tombstones are per device per upkeep run, `packs/tombstones/<device>/<seq>.enc` (signed, under K10 when folder-scoped, under the ledger key when vault-scoped). A hot pack is rewritten by the device that owns the folder key when more than 50 % of its bytes are dead; cold packs are never rewritten. Verification reads a whole pack (one GET) and checks every member's object name.
- **P2P** keeps serving single chunk objects re-encrypted from plaintext, which stays byte-identical because key, nonce and packing are deterministic.

## 3. Signed records

One envelope for every object a device publishes except chunks and packs:

```text
SignedRecord {
  format: 2, kind: "manifest" | "trash" | "snapshot" | "pack-index" | "tombstones" | "peer" | "epoch" | "share-epoch" | "grant" | "request" | "revocation" | "policy" | "placement" | "checkpoint" | "batch",
  vault, scope (folder id or empty), device, seq, key_id, body_hash: BLAKE3(body), sig_alg: "ed25519+ml-dsa-65",
  sig: hybrid signature over aad("record-signature", [format, kind, vault, scope, device, seq, key_id, body_hash]),
  body: AEAD ciphertext (nonce || ct || tag) under the key named by key_id, AAD = aad(kind, [format, vault, scope, device, seq, key_id])
}
```

Acceptance rule for every kind: the signature verifies against the device's public key in the registry (or the member's KEM record signing key), the device is authorized for `kind` and `scope` (section 6), the body opens under `key_id`, and, for manifests, trash records, snapshots and pack indexes, a ledger batch signed by the same device announced `(kind, scope, seq, body_hash)`; otherwise the record waits (at most MAX_AHEAD per device) and is never applied. `key_id` is inside the signed message, so a storage cannot relabel a record. Ledger batches and checkpoints use the same envelope (their `body_hash` replaces the old `hash` field, and `key_id` becomes signed).

## 4. Folder membership and grants

- A folder record (`vault/folders/<folder>.enc`, under the registry key, signed by its creator) carries id, name, settings and the list of current participants with roles; it carries no key.
- A folder key reaches a device only as a grant: `vault/grants/<folder>/<epoch>/<device>/<issuer>.json`: K9ₑ (and K11 and earlier epochs' K9 when the recipient joins late) sealed to the recipient's K8 through the hybrid KEM, inside a SignedRecord of kind `grant` signed by the issuer. A grant is accepted only when the issuer is a participant of the folder with the owner role at that epoch.
- **Requests**: `varsto folder request <folder>` publishes a SignedRecord of kind `request` (device, name, K8 public key). Every owner's CLI and interface show pending requests; `varsto folder approve <folder> <device> [--read-only]` and `deny` are manual. The background service never approves. Pairing (`varsto pair offer --folders A,B` or the interface's list) is the only automatic grant and it is chosen by the person at the offering device, who sees the joining device's id and name (SPAKE2-protected hello carries K6 and K8 public keys) before the vault is sent.
- **Roles**: owner (may grant, revoke, rotate), editor, viewer; enforced by the acceptance rule of section 3 (a viewer's manifests are never applied) and by key possession (a viewer never receives the share-ledger key for writes? no: viewers receive K9 and may read; their writes are refused by every reader). Role changes are signed records of kind `share-epoch` or `folder-roles` by an owner.
- **Removal**: a share epoch (random new K9ₑ₊₁, grants to everyone who stays, signed epoch record, ledger cut-off for the removed device) as in section 24 of alpha-0-format, now for own devices and other people alike. Re-encryption of old data under the new key is a separate, budgeted job (`varsto folder reencrypt`).
- **Organizations** (section 27) stay on top: an administrator's approval token may carry folder grants.

## 5. Recovery

- The recovery kit prints two word sets: the vault key K3 and the recovery key K1, each optionally in 2-of-3 shares, each with a key check.
- Every folder key epoch is escrowed as `vault/folder-escrow/<folder>/<epoch>.enc`: K9ₑ (with K11) encrypted under K2 with AAD (format 2, "escrow", vault, folder, epoch), written by the device that created the epoch. Writing needs K1 in memory: `folder add` and epoch rotation ask for the recovery words (or the device holds a session-only copy entered at unlock with `--with-recovery-key`); until the escrow exists, `varsto status` warns "folder X has no recovery copy" and the help page explains. Strongroom keys are escrowed only when the user says so at enrolment.
- `varsto join --recovery-words` (K1) plus the vault words (K3) rebuilds a device with every folder. The vault words alone give the registry and ledger but no content; the recovery words alone give nothing (they cannot read the registry).

## 6. Authorization matrix

| Writer | Accepted kinds | Scope |
| --- | --- | --- |
| full device, folder owner | everything | its folders |
| full device, folder editor | manifest, trash, snapshot, pack-index, tombstones, batch (folder events), request | that folder |
| full device, folder viewer | request, batch (verification claims only) | that folder |
| full device, not a participant | request, batch (object claims, verification claims), peer, policy/placement for its own folders | registry |
| member of a shared folder (another person's device) | as editor or viewer of that folder only; never registry, epoch, revocation, snapshot expiry, storage retirement | that folder |
| replica | batch with object and verification claims, empty scope | none |
| storage | nothing: every object it serves must verify | none |

## 7. Peers and transport

- Peer records are SignedRecords of kind `peer` (cert hash, addresses, relay, seq); the QUIC server admits only certificates named by a verified record, and the request token binds (device, responder, ts, nonce, path); `token.device` must equal the device of the presented certificate.
- No plaintext transport: direct connections use the same TLS 1.3 + pinned certificates as QUIC (TCP+TLS or QUIC only). LAN beacons are signed with K6 and carry a sequence number.
- Pairing: SPAKE2 as today; the hello carries the joining device's K6 and K8 public keys and name; the offering device shows them and asks before sending; the bundle is sealed to K8 in addition to the SPAKE2 key; discovery uses keyed_hash("pair-rendezvous", code) instead of the code's digits.

## 8. What the storage can learn

Vault id; device ids and their activity cadence (record names carry device and sequence, not time: `<utc>`-named records of alpha-0 are renamed to `<device>/<seq>`); folder ids and participant counts; pack sizes (64/256 MiB granularity); ledger batch sizes (zstd-compressed binary bodies); that a folder is shared with another vault's device (grants to foreign KEM keys). It cannot learn file names, sizes, counts per file, chunk boundaries or whether a known file is present.

## 9. Tests that define "done"

- A viewer, a removed member, a replica and a storage that rewrites or replays objects cannot change what any full device sees (manifests, trash, snapshots, epochs, revocations, packs, peers): one integration test per writer class, each asserting `writes_refused` and unchanged folder contents.
- Two devices on different zstd versions never produce two ciphertexts under one nonce (property test over the nonce derivation).
- A device joined with the vault words sees names and sizes and no content until an owner approves; approval on one owner device is enough; the service never approves.
- Losing every device: vault words + recovery words restore every folder; vault words alone restore none.
- Known-file confirmation from pack sizes is impossible: pushing the same 10 MiB file to two folders yields different pack layouts and no single-chunk objects.
- Every acceptance rule has a fails-before/passes-after test; the full lab passes; fuzz targets for every parser of a record.

## 10. Ownership

- Agent A (keys and records): sections 1, 3, 4, 5, 6 → `format2-records` branch.
- Agent B (blocks): section 2 and the chunk/nonce/pack/chunker/zstd changes → `format2-blocks` branch.
- Agent C (peers): section 7 → `format2-peers` branch, after A.
- Integration: FORMAT_VERSION = 2 bumped once by the integrator; `format-versions.md` says format 2 is read by nothing older; the reader tool (work 5) targets format 2.
