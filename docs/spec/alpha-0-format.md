# Alpha-0 storage format and sync model

> **Format version 0, alpha.** Implemented in `crates/varsto-core`. It may change without a migration path; every released alpha keeps a reader (see [format-versions.md](format-versions.md)). Nothing here has been reviewed or audited. The post-quantum hybrid parts of the plan are not implemented yet; algorithm identifiers in every object make that visible and allow the change.

## 1. What alpha-0 does

- Content-defined chunking of files (Gear rolling hash, FastCDC-style normalisation; defaults 64 KiB min, 256 KiB average, 1 MiB max).
- Client-side authenticated encryption of every chunk, manifest, ledger batch and record before it reaches a storage. Storage sees opaque objects and their sizes only.
- One storage backend: a local directory (covers local disks, removable disks and network mounts). S3 and rclone remotes follow.
- A per-device, append-only, signed ledger replicated through every storage. Devices that are never online at the same time converge through the storage ("mailbox").
- Two-way folder sync between devices with version vectors; concurrent edits produce a deterministic winner and a conflict copy; deletions go to a local trash.
- `fsck`: compares the ledger with what the storages actually hold and can verify every object by hash.
- Cold storages are written but never read (requirement F-043 default).

Not in alpha-0: sharing with other users, peer-to-peer transfer, hybrid post-quantum signatures and key agreement, FIDO2 security keys, Strongroom, placeholders, policies and alerts, packs, mobile, MCP, daemon. Keys are shared between devices out of band (the "vault key").

## 2. Identifiers

| Identifier | Construction | Visible to storage |
| --- | --- | --- |
| vault id | 16 random bytes | yes (`vault/meta.json`) |
| device id | first 16 bytes of BLAKE3(device public key) | yes (object names) |
| folder id | 16 random bytes | yes (object names) |
| chunk id | keyed BLAKE3 of the chunk plaintext, key = folder hash key | no (inside encrypted manifests and ledger) |
| object name | BLAKE3 of the chunk ciphertext | yes (object names) |
| content hash | keyed BLAKE3 of the whole file, folder hash key | no |

Object names are plain hashes of ciphertext, so a peer or a scrub can verify an object without any key. Chunk ids are keyed, so the storage cannot test whether a known file is present (plan 6.11).

## 3. Keys

Subset of [key-hierarchy.md](key-hierarchy.md). All keys are 256 bits. Derivation uses BLAKE3 `derive_key` with the context `e2ee-sync-format/0/<purpose>` and length-prefixed scope identifiers (vault, folder, device, chunk) in the key material.

| Key | Purpose | Derived or wrapped |
| --- | --- | --- |
| master key (K3) | root of the vault | random; shown once as the hex "vault key" for joining other devices; wrapped locally under the passphrase key |
| passphrase key (K4) | wrap the master key and device signing key on one device | Argon2id (fixed minimums: 64 MiB, 3 passes, 1 lane; readers refuse weaker parameters) |
| device signing key (K6/K7) | sign this device's ledger batches | Ed25519, random per device, wrapped with K4 |
| ledger key | encrypt ledger batch bodies | derive(K3, `ledger`) |
| device-registry key | encrypt device records | derive(K3, `device-registry`) |
| folder-record key | encrypt folder records | derive(K3, `folder-record`) |
| local-keyring key | encrypt the local copy of folder keys | derive(K3, `local-keyring`) |
| folder key (K9) | per folder | random; published in the creating device's folder record |
| folder hash key (K11) | chunk ids and content hashes | derive(K9, `dedup-hash`, folder) |
| folder metadata key (K10) | manifests | derive(K9, `folder-metadata`, folder) |
| chunk key (K14) | one chunk | derive(K9, `chunk-key`, folder, chunk id) |
| chunk nonce | one chunk | derive(K9, `chunk-nonce`, folder, chunk id), first 24 bytes |

**Alpha-0 decision (convergent chunk keys).** The chunk key and nonce are derived from the chunk's keyed hash, so the same content encrypts to the same object on every device of the vault. Two devices that ingest the same file offline therefore produce one object, deduplication works without coordination, and a future peer-to-peer swarm can advertise object names. The cost: rotating a folder key re-encrypts its data, and anyone holding the folder key can test for known content inside that folder. Shared folders (not yet implemented) will use random chunk keys wrapped under the folder key, as the key hierarchy draft proposes. Rationale and alternatives: plan section 8, "Avainnettu hash, lohkot ja padding".

## 4. Encryption and associated data

AEAD is XChaCha20-Poly1305. Every object is `nonce (24 bytes) || ciphertext || tag`. The associated data is a length-prefixed list that always starts with the format version and the AEAD identifier, then the object type and its scope:

| Object | Associated data fields |
| --- | --- |
| chunk | vault id, folder id, chunk id, plaintext length |
| manifest | vault id, folder id, device id, manifest sequence |
| ledger batch body | device id, batch sequence |
| device record | vault id, device id |
| folder record | vault id, creating device id, folder id |
| key file | vault id, device id |
| local keyring | vault id, device id |

A storage cannot move, rename or replay an object into another place without the AEAD check failing.

## 5. Storage layout

```text
vault/meta.json                          format version, vault id (plaintext)
vault/devices/<device>.enc               device record: name, Ed25519 public key
vault/folders/<device>/<folder>.enc      folder record: name, folder key
ledger/<device>/<seq 16 digits>.json     signed batch envelope (body encrypted)
manifests/<folder>/<device>/<seq>.enc    full folder view of one device
chunks/<first two hex>/<object name>     encrypted chunk
```

Every path has one writer: a device writes only under its own device id, and chunk objects are content-addressed and written with put-if-absent. No conditional writes, locks or leases are needed on the storage. Objects are never overwritten.

## 6. Ledger

Model B of [ledger-signing-notes.md](ledger-signing-notes.md): events are grouped into batches; each batch carries the device id, a sequence number, the hash of the previous batch of the same device, a Lamport clock and its events; the body is encrypted, and the signature covers `device || seq || BLAKE3(encrypted body)`. Event types:

| Event | Meaning |
| --- | --- |
| `device_enrolled` | this device joined (name) |
| `folder_added` | this device created a folder |
| `chunk_stored` | this device wrote an object to a storage (a claim) |
| `chunk_verified` | this device fetched the object from a storage and the hash matched |
| `chunk_on_device` | this device holds the plaintext as part of a file |
| `manifest_published` | this device published manifest `seq` of a folder |

Replaying every batch yields the location view: for each (folder, chunk) the object name, size, which storages claim it (by whom) and which devices verified it there. A storage copy counts as **verified** only when a device other than the writer has verified it. `varsto status` reports chunks without any storage copy and chunks verified elsewhere.

Mailbox rules:

- on every pull a device lists `ledger/` on every hot storage and ingests batches it does not have, after checking the signature against the device registry and the hash chain;
- on every push it uploads its own batches that a storage lacks;
- two different batches with the same device and sequence number are a **fork**: the device is marked forked in the local heads;
- if the mailbox holds batches of this device's own identity that it never wrote (a copy restored from an old backup, or a clone), the device fences itself: it stops signing and `push` fails until it is re-enrolled as a new device.

Lamport clocks: each device keeps one logical clock, incremented on every local change and raised to any larger value seen in batches or manifests.

## 7. Manifests and merging

Each device publishes its full view of a folder as a manifest (`seq` increases per device). A file state has: path, version vector (device -> clock of that device's last change), deleted flag, size, mtime (change detection only), content hash, chunk list (chunk id, object name, size), and the device and clock of the last change.

Merge rules for the same path, local versus remote:

- remote dominated by local: keep local; local dominated by remote: take remote;
- concurrent with identical content: keep, version = element-wise maximum;
- concurrent, one side deleted: the modification wins (a deletion never destroys a concurrent edit);
- concurrent, different content: the state with the larger (clock, device id) wins; the loser is kept as `name.conflict-<device>-<clock>.ext`, a new file with its own version; the merged version vector is the element-wise maximum so both devices converge without a further round.

Deleted files are moved to `<home>/trash/<folder>/<path>.<time>` on the device, never removed outright (F-025).

## 8. Local device directory

```text
vault.json      vault id, device id, device name, format version
keys.enc        master key and signing key, wrapped under the passphrase
keyring.enc     folder records known to this device (encrypted)
config.json     storages and folder mounts (no secrets)
devices.json    device registry cache (public keys)
clock.json      Lamport clock
ledger/         local copy of every device's batches and the heads file
state/<folder>.json  merged file states, local index, last seen manifests
trash/          deleted files
```

## 9. Known limitations

- Pairing is "copy the vault key": no hybrid KEM, no QR, no second factor. The vault key is the master key in hex; losing it and every device means losing the data (no escrow).
- Ed25519 only; ML-DSA hybrid signatures are a format change that the `sig_alg` field prepares for.
- Whole files are chunked in a stream, but a changed file is re-read twice during a push (once to hash, once to upload) when a chunk is new; packs for small files do not exist yet.
- Manifests are full views; very large folders will need incremental manifests and checkpoints (plan section 8, blocking question 1).
- Verification of cold copies, policies, placeholders, sharing and P2P are not implemented.
- Logging and the redaction rules of `docs/architecture/logging.md` are not implemented; the CLI prints only aggregate counts and identifiers.
