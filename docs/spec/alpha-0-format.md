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
- A local desktop interface (`varsto desktop`): a web page served from the binary on 127.0.0.1 with a per-session token and a Host check, the first shape of the local control API (plan 6.8, 6.32).

Not in alpha-0 (see section 10 and 11 for what later alphas added): sharing with other users, peer-to-peer transfer, hybrid post-quantum signatures and key agreement, FIDO2 security keys, Strongroom, placeholders, policies and alerts, packs, mobile, MCP, daemon. Keys are shared between devices out of band (the "vault key").

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
| device signing key (K6/K7) | sign this device's ledger batches | alpha.3: Ed25519 + ML-DSA-65 hybrid (alpha-0: Ed25519 only), random per device, wrapped with K4 |
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
vault/devices/<device>.enc               device record: name, public key (Ed25519 || ML-DSA-65; 32 bytes = legacy Ed25519 only)
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
- alpha-0 signed with Ed25519 only; since alpha.3 every batch carries `sig_alg = "ed25519+ml-dsa-65"` (section 11). The `sig_alg` field made the switch possible without rewriting stored data.
- Whole files are chunked in a stream, but a changed file is re-read twice during a push (once to hash, once to upload) when a chunk is new; packs for small files do not exist yet.
- Manifests are full views; very large folders will need incremental manifests and checkpoints (plan section 8, blocking question 1).
- Verification of cold copies, policies, placeholders, sharing and P2P are not implemented.
- Logging and the redaction rules of `docs/architecture/logging.md` are not implemented; the CLI prints only aggregate counts and identifiers.

## 10. Additions in 0.0.1-alpha.2

### Background service, tray and menu-bar apps

`varsto service run` watches attached folders (inotify, kqueue, FSEvents or ReadDirectoryChangesW through the `notify` crate), syncs within seconds of a change and on a timer, serves the local interface and writes `service.json` (`pid`, `port`, `token`, mode 0600) so that the tray app, the CLI and the mobile shells can find it. `varsto tray` (Linux: StatusNotifier over D-Bus; Windows: system tray) and the macOS menu-bar app supervise the service as a child process and restart it after a self-update (exit code 75). `varsto service install` registers a login item (LaunchAgent, autostart entry, Startup folder).

### Self-update

`varsto update` and the "Check for updates" buttons fetch `manifest.json` and `SHA256SUMS` from the download page with the system `curl`, verify the SHA-256 of the platform archive and replace the running binary (rename-over on Unix, rename-aside on Windows). The checksum comes from the same site as the archive; signed releases and a second channel are planned.

### Selective sync and placeholders (F-039)

A folder mount can be *selective*. Files the device has not fetched exist as `<name>.varsto-placeholder` (a few bytes of JSON: size and time). Placeholders are never treated as deletions; `fetch` downloads one file and pins it so later updates are downloaded too; `free` replaces a local file with a placeholder, but only when every chunk is on a storage that is not a carrier (or on a replica). The interface lists files with their state and shows encrypted thumbnails.

### Transferrer disks (F-048)

A local-directory storage can be marked `carrier`. The engine writes to it only chunks that no other device holds yet, and after every pull it deletes from the carrier the chunks that both this device and another device hold. Carriers are ignored by `fsck`'s "claim without object" check and never count as the only durable copy for `free`.

### Untrusted replicas (F-045)

A replica device holds a *replica token* (`<vault-id>.<key>`), where the key is `derive(K3, "replica-ledger")`. It mirrors every object from a source directory to a target directory, verifies chunk objects against their names, and records claims in its own ledger batches, sealed under the replica key with `key_id = "replica"` and signed with its own Ed25519 key. Its device record is published at `vault/replicas/<device>.enc` under the same key. Owner devices read those batches, fold the claims into the chunk records by object name (the replica cannot know chunk ids), and count them as verified copies. The replica never holds a key that opens content, names or manifests.

### Shared folders (F-047)

A share token is `<vault-id>.<folder-id>.<folder-key>.<name>`. The recipient creates a *member* device: a device directory with a local random root key, the owner's vault id and that one folder record. Member records live at `vault/shares/<folder>/<device>.enc` under `derive(folder key, "share-registry")`; member batches are sealed per folder under `derive(folder key, "share-ledger")` with `key_id = "share:<folder>"`. Owner devices and members resolve those keys from the folder key, so everyone holding the folder key sees everyone's claims for that folder and nothing else. Members cannot create folders, issue replica tokens or read the owner's device registry. Limitation: one device directory per shared vault; key exchange is manual.

### Encrypted thumbnails (F-046)

For image and video files, the device that holds the plaintext generates a JPEG thumbnail (longest side 256 px; videos through `ffmpeg` when installed), encrypts it under the folder metadata key with associated data (`thumbnail`, vault, folder, content hash) and stores it at `thumbs/<folder>/<content hash>.enc` on every hot, non-carrier storage. Any device with the folder key can show the preview, including for placeholders it never fetched. No thumbnail is written in clear text on disk.

### Mobile shells

Android: a foreground service runs the same `varsto service` binary (shipped as `libvarsto.so`), the activity shows the local interface in a WebView. iOS: `varsto-ffi` exposes `varsto_start` and `varsto_url` for an in-process service behind a `WKWebView`; the Xcode project is generated with xcodegen on a Mac.

## 11. Post-quantum hybrid cryptography (0.0.1-alpha.3)

Every place a public key is used now combines a classical and a post-quantum algorithm, so that stored data and signatures stay trustworthy if either is broken.

### Signatures: Ed25519 + ML-DSA-65

- A device signing key is an Ed25519 seed and an ML-DSA-65 (FIPS 204) seed, serialised as 64 bytes inside `keys.enc`. The public key is the Ed25519 key followed by the ML-DSA-65 encapsulation of the verifying key (32 + 1952 bytes) and is what the device record publishes; the device id is the keyed hash of these bytes.
- A signature is the Ed25519 signature followed by the ML-DSA-65 signature over the same message (64 + 3309 bytes). `sig_alg` is `ed25519+ml-dsa-65`. Verification requires **both** parts; a batch whose post-quantum half is missing or damaged is rejected even if the Ed25519 half is valid.
- Downgrade protection: a key that carries a post-quantum part never accepts `sig_alg = "ed25519"`. Batches signed by alpha-0 devices (32-byte public keys, `sig_alg = "ed25519"`) remain valid for those devices; such a device keeps signing Ed25519-only until it is re-enrolled, because changing its key would change its device id. No stored object had to be rewritten: the algorithm identifier on every batch selects the verification rule.
- Cost: about 3.3 KB per batch. Batches already group many events (model B), so the ledger grows by a few kilobytes per sync, not per file.

### Key encapsulation: X25519 + ML-KEM-768

- Used wherever a secret must reach another party's public key. Today that is the share token: the recipient runs `varsto share request`, which stores a private key in its device directory and prints a request code `vsr1.<X25519 key || ML-KEM-768 key>` (1216 bytes, hex). The owner runs `share create <folder> --to <code>`.
- The owner encapsulates to both halves, derives one key with `derive_key("e2ee-sync-format/0/hybrid-kem/x25519+ml-kem-768", len-prefixed(x25519_ss, mlkem_ss, ciphertext, encapsulation_key))`, and encrypts the folder key with XChaCha20-Poly1305 under associated data (`share-token`, vault id, folder id, name). The sealed token `vst1.<vault>.<folder>.<kem-alg>.<kem-ct>.<sealed-key>.<name>` carries only ciphertext and can travel over any channel; only the requesting device can open it. The plain token format of alpha.2 still exists and is marked as carrying the key.
- What this does not solve yet: the owner has no way to confirm that a request code really came from the intended person (no identity binding, no QR confirmation), and tokens are not revocable. Both are planned.

## 12. Remote storages: S3-compatible buckets and rclone remotes (0.0.1-alpha.3)

The storage abstraction (put-if-absent, get, exists, list, delete) now has three backends. Every object is ciphertext before it reaches any of them; a storage learns object names and sizes only.

- **S3-compatible** (`varsto storage add-s3`): plain HTTPS with AWS Signature Version 4, no SDK. Works with AWS S3, Scaleway, Hetzner Object Storage, Backblaze B2, Cloudflare R2, MinIO and `rclone serve s3`. Path-style URLs by default (`--virtual-host` for `bucket.host`). Writes check for existence and then PUT with `If-None-Match: *`, so an existing object is never overwritten even on servers that ignore the condition. Listing uses ListObjectsV2 with continuation. A storage class (`--storage-class DEEP_ARCHIVE`, `GLACIER_IR`, ...) is sent with every PUT; archive classes mark the storage cold automatically, and a GET that returns `InvalidObjectState` is reported as "must be restored first", never retried silently. The secret access key is kept in `secrets.enc` (XChaCha20-Poly1305 under `derive(master, "storage-secrets")`, mode 0600), never in `config.json`; `VARSTO_S3_SECRET_<NAME>` is the fallback for scripts.
- **rclone** (`varsto storage add-rclone <name> remote:path`): runs the user's own `rclone` (`rcat`, `cat`, `lsjson --stat`, `lsf -R`, `deletefile`). Credentials stay in rclone's configuration; Varsto never reads them. Any of rclone's backends (SFTP, WebDAV, Google Drive, OneDrive, Storage Box, ...) becomes a Varsto storage this way.
- **Local directory**: unchanged.

Tests: the S3 backend is exercised against `rclone serve s3` (a local S3 server with access keys) and the rclone backend against a local-path remote, both through the full two-device sync, in `crates/varsto-core/tests/remote_storages.rs`. They skip when rclone is not installed.
