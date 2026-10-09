# Key hierarchy

> **DRAFT, not final, no implementation.** This is a design-stage proposal written to answer the open question about the locked-state key set. It does not fix algorithms or parameters: wherever a value is not backed by a cited standard it is marked **TBD**. Nothing described here exists in code, and none of the properties has been tested or reviewed. Adversary IDs (A1 to A13) refer to [../architecture/threat-model.md](../architecture/threat-model.md).

Requirement IDs refer to the requirement tables of the project plan; "plan 6.28" and similar refer to plan sections, and "plan section 8" to its open questions.

## 0. Conventions and cited sizes

- **Status 0.0.1-alpha.3:** hybrid signing is implemented as Ed25519 + ML-DSA-65 (`sig_alg = "ed25519+ml-dsa-65"`) for ledger batches, and the hybrid KEM as X25519 + ML-KEM-768 for sealed share tokens; see `alpha-0-format.md` section 11. The rest of this draft is unchanged.
- "Hybrid signing" means a classical and a post-quantum signature over the same message, both required to verify (plan 6.5). Candidates: Ed25519 (RFC 8032: 32-byte public key, 64-byte signature) and ML-DSA (FIPS 204, Table 2: ML-DSA-65 public key 1952 bytes, signature 3309 bytes). The ML-DSA parameter set is **TBD**; ML-DSA-65 is used in examples only.
- "Hybrid KEM" means a classical and a post-quantum key encapsulation combined into one shared secret (plan 6.5). Candidates: X25519 and ML-KEM (FIPS 203, Table 3: ML-KEM-768 encapsulation key 1184 bytes, ciphertext 1088 bytes). The parameter set and the combiner construction (it must hash the transcript, not just concatenate secrets) are **TBD** (plan section 8, "PQ library").
- "AEAD" means XChaCha20-Poly1305 or AES-256-GCM (plan 6.5); the choice is **TBD**. Section 4 explains why the nonce strategy constrains it.
- "KDF" means a key derivation function with a context string, for example HKDF (RFC 5869) or the BLAKE3 key-derivation mode; the choice is **TBD**. "Keyed hash" means HMAC or keyed BLAKE3 (plan 6.11); the choice is **TBD**.
- "Wrap" means AEAD encryption of a key under another key, with the associated data defined in section 3.
- Passphrase stretching uses Argon2id (RFC 9106; plan 6.5, 6.15). Cost parameters are **TBD** and will be fixed minimums (S-013). The passphrase is normalised with NFKC before stretching (plan 6.15).
- Every random key is 256 bits from the operating system's CSPRNG (S-014).

## 1. Key table

"Locked" in the last columns means the vault is locked: the user has not unlocked it, or it has locked again. Section 5 lists the locked-state key set separately.

| # | Key | Purpose (exactly one) | How derived or wrapped | Where stored | When in memory | Who can use it |
| --- | --- | --- | --- | --- | --- | --- |
| K1 | Recovery key | Unwrap the master key and the Strongroom folder keys when no device or security key is left (F-020, F-042). | 256 random bits, encoded as 24 words with a checksum, optionally split into threshold shares. Encoding **TBD** (plan section 8, "recovery kit"). | Only on paper or metal held by the user (S-014, plan 6.38). Never on a device or in storage. | Only during creation and during recovery; erased right after. | The user, on a device being recovered. |
| K2 | Recovery wrapping key | Wrap K3 and K13 for recovery. | KDF(K1, context `recovery-wrap`). | Not stored. The wrapped blobs (K3 under K2, K13 under K2) are stored in every storage and on every device. | Only during recovery. | The user with K1. |
| K3 | Master key | Root of the vault: wraps K5 and the folder keys of private folders, and derives K11 for private folders. | 256 random bits, never derived from a passphrase (S-014). | Wrapped only: under K4 on each device, under K2 in storage. | While the vault is unlocked; erased on lock. | Unlocked devices of the vault owner. |
| K4 | Device unlock key | Wrap K3 on one device. | KDF over three labelled inputs: Argon2id(passphrase), a hardware-bound secret from the OS keystore, and, when enabled, a FIDO2 `hmac-secret` / PRF output. Whether the third input is mandatory is **TBD** (plan section 8, "2FA"). | Not stored. The hardware-bound secret stays in the OS keystore. | Only during unlock. | The user at that device (A3 cannot try passphrases without the hardware-bound secret). |
| K5 | Vault identity key (hybrid signing) | Sign membership statements: device enrolment and revocation, folder membership changes and key rotations. | Random key pair at vault creation; private part wrapped under K3. Whether this key exists, or membership is a chain of device signatures, is **TBD**. | Wrapped private part in storage and on devices; public part in every device's trust store. | Only while performing a membership operation, which needs an unlocked vault and the second factor (S-004). | Unlocked owner devices, with the second factor. |
| K6 | Device identity key (hybrid signing) | Identify one device: sign its own certificate requests, its K7 certificate and commands it issues (wipe, revoke requests). | Random key pair generated on the device; public part certified by K5 through a ledger event. | Private part on the device only, wrapped by an OS keystore key that requires the vault to be unlocked. | While the vault is unlocked. | That device only. |
| K7 | Device ledger key (hybrid signing) | Sign this device's own ledger batches: receipts and location facts (plan 6.19). Nothing else. | Random key pair on the device; certified by K6 with the scope "ledger facts of this device" and an expiry. Expiry length **TBD**. | OS keystore, in a class usable after the first unlock since boot. | When a batch is sealed, also while locked. | That device's daemon or background task. |
| K8 | Device transport key (hybrid KEM) | Peer-to-peer key agreement and receiving wrapped keys (new-device enrolment, shared-folder invitations). | Random key pair on the device; public part in the device certificate. | Private part in the OS keystore. | During handshakes and unwraps. Availability while locked is **TBD** (section 5). | That device only. |
| K9 | Folder key (per folder, per epoch) | Wrap the chunk keys of one folder and derive its metadata key; the unit of sharing and rotation. | 256 random bits per epoch. Wrapped under K3 (owner, private folders), under each member's K8 through the hybrid KEM (shared folders), or under K12 (Strongroom, see K13). | Wrapped copies in a folder keyring object in storage and on devices. | While the vault is unlocked. | Owner devices and members of the folder. |
| K10 | Folder metadata key | Encrypt manifests, the file tree and names of one folder. | KDF(K9, context `folder-metadata`). | Not stored. | While the vault is unlocked. | Holders of K9. |
| K11 | Keyed-hash key (per dedup domain) | Compute chunk IDs and whole-file hashes (F-023, F-024) without plaintext hashes in storage (plan 6.11). | KDF(K3, context `dedup-hash`) for the private folders of a vault; KDF(K9 of the first epoch, context `dedup-hash`) for each shared folder. Behaviour across folder-key epochs is **TBD** (section 6). | Not stored. | While the vault is unlocked. | Holders of K3 or of the shared folder key. |
| K12 | Strongroom wrapping key (per security key) | Wrap K13 and the Strongroom storage credentials (S-012, plan 6.28). | KDF(output of the FIDO2 `hmac-secret` / PRF of one enrolled credential, context `strongroom-wrap`), with a salt per folder. Platform PRF APIs hash their input while raw `hmac-secret` does not, so the project must fix one transform for all platforms; **TBD** (FIDO2 platform research, question 1). | Not stored. | Only during a Strongroom unlock. | The user holding that physical key (touch, and PIN by default). |
| K13 | Strongroom folder key | Same role as K9, for a Strongroom folder. | 256 random bits per epoch. Wrapped once under K12 for each enrolled security key and once under K2. **Never** wrapped under K3, so an unlocked session alone cannot open it (A4). | Wrapped copies in storage and on devices. | Only during the unlock window; erased when it closes (plan 6.28). | The user with a security key, or with K1. |
| K14 | Chunk key | Encrypt exactly one chunk. | 256 random bits per chunk, wrapped under K9 or K13. A random key (not a key derived from the folder key) keeps rotation cost proportional to the number of keys, not to the data (plan section 8, "sharing"). | Wrapped inside the encrypted manifest or pack index. | While that chunk is being encrypted or decrypted. | Holders of the folder key. |
| K15 | Camera-upload key pair (hybrid KEM, per target folder) | Let a locked phone add new files to a folder without being able to read the folder (F-036, plan 6.30). | Random key pair. Private part wrapped under K9 or K13 of the target folder; public part distributed to the phone. Each upload encapsulates to the public key and gets fresh chunk keys. When the vault is next unlocked, the upload is ingested: chunk keys re-wrapped under the folder key and keyed-hash IDs computed. | Public part on the phone (no secrecy needed, integrity needed). Private part wrapped in storage. | Public part: whenever uploading. Private part: during ingest only. | Phone: encrypt only. Holders of the folder key: decrypt. |
| K16 | Upload-tracking key (device-local) | Remember which camera files were already uploaded while the vault is locked, so the same file is not uploaded twice (plan 6.30). Replaces K11 in the locked state; it never leaves the device and never names objects in storage. | 256 random bits generated on the device. | OS keystore. | While uploading, also while locked. | That device only. |
| K17 | Automation key | Let scripts act on chosen folders without a person present (plan 6.8). A documented exception to S-004. | A scoped token plus copies of the scoped folder keys wrapped under an OS keystore key that does not require user presence. Created only from an unlocked vault with the second factor. Never covers Strongroom. | OS keystore on the automation device. | Whenever an automated job runs. | Scripts on that device, within the token's scope; revocable by a ledger event and rotation of the scoped folder keys. |
| K18 | Log name-hash key (device-local) | Replace file names and paths in logs with keyed hashes (S-015, plan 6.40). | 256 random bits generated on the device. | OS keystore; never synced. | Whenever logging, also while locked. | That device's logger; resolving a hash needs the same device. |
| K19 | Log encryption key pair (phase 2) | Encrypt log records at rest so that writing works while locked but reading needs an unlock (plan 6.40, phase 2). | Key pair; private part wrapped under K3. Algorithm (hybrid KEM or not, since logs stay on the device) **TBD**. | Public part on the device; wrapped private part on the device. | Public part: whenever logging. Private part: when the user reads logs. | Logger: write. User: read. |
| K20 | Storage credential wrapping key | Protect S3 keys, rclone secrets and SFTP passwords on a device (F-006, F-007). | Credentials are synced between devices encrypted under KDF(K3, context `storage-credentials`); on each device they are re-wrapped under an OS keystore key. Strongroom credentials are wrapped under K12 instead. | Wrapped credentials in storage (vault configuration) and on devices. | While syncing. Whether ordinary credentials are usable while locked is **TBD** (section 5). | Owner devices; never shared with folder members. |
| K21 | Discovery key | Derive the rendezvous-record path and the DHT key, and encrypt the presence record (plan 6.33). | KDF(shared discovery secret, context `rendezvous` plus epoch). The discovery secret is random, shared among the devices of a folder or vault, and wrapped under K3 or K9. | Discovery secret wrapped in storage; unwrapped copy in the OS keystore if presence must be published while locked (**TBD**). | While publishing or looking up presence. | Devices of the vault or folder. |
| K22 | Ledger payload key | Encrypt the payload of ledger events so that a member can be forgotten without breaking signatures (plan section 8, "GDPR and append-only ledger"). | Per event or per batch, random, wrapped under the folder key; signatures cover the ciphertext hash. Granularity **TBD**. | Wrapped next to the event. | While writing or reading events. Writing while locked needs a locked-state option; **TBD** (section 5). | Holders of the folder key. |

## 2. Derivation contexts and the one-purpose rule

- **Rule:** every key has exactly one purpose. A key that encrypts never signs; a wrapping key never encrypts data; a hash key never encrypts. A new use needs a new context string, never reuse of an existing one.
- **Format:** `<prefix>/<format-version>/<purpose>`, ASCII, fixed in the specification. The prefix is a format constant and must not follow brand renames (the product name is a working name). The prefix is **TBD**.
- **Inputs:** a KDF call takes the parent key, the context string, and identifiers that bind the result to its scope (vault ID, folder ID, epoch, device ID). Identifiers are encoded with explicit lengths so that two different tuples can never produce the same input.

Proposed purposes (strings illustrative, **TBD**):

| Context purpose | Parent | Produces |
| --- | --- | --- |
| `recovery-wrap` | K1 | K2 |
| `device-unlock` | Argon2id output, hardware-bound secret, optional PRF output | K4 |
| `folder-metadata` | K9 or K13 | K10 |
| `dedup-hash` | K3, or K9 of a shared folder | K11 |
| `strongroom-wrap` | PRF output of one credential | K12 |
| `storage-credentials` | K3 | key that encrypts synced credentials (K20) |
| `rendezvous` | discovery secret | K21 for one epoch |
| `ledger-payload` | K9 | K22, if derived rather than random (**TBD**) |
| `object-name` | none (unkeyed hash of ciphertext) | storage object names, see section 3 |

## 3. Associated data per object type

Every AEAD operation authenticates a header that binds the ciphertext to its place, so that A1 cannot swap, move or replay objects without detection. Common fields in every header:

- format version and object type;
- algorithm identifiers (AEAD, KEM, signature) for crypto-agility (plan 6.5);
- vault ID, folder ID and key epoch of the wrapping key;
- the ID of the key used (so the right wrap is chosen).

| Object | Additional fields in the associated data | What this prevents |
| --- | --- | --- |
| Chunk | Keyed-hash chunk ID (K11 over plaintext), chunk-key ID, plaintext length class. | Replacing a chunk with another chunk of the same folder; moving it to another folder. |
| Pack | Pack ID, the ordered list of chunk IDs and their offsets (or its hash), writing device ID. | Reordering or dropping chunks inside a pack; passing a pack off as another. |
| Manifest (file version) | File ID, version number or version vector, hash of the parent version, folder epoch. | Rolling a file back to an older version, or attaching a version to a different file. |
| Ledger batch | Device ID, batch sequence number, first and last event sequence, hash of the previous batch, Merkle root. See [ledger-signing-notes.md](ledger-signing-notes.md). | Reordering, replaying or truncating a device's ledger without the gap being detectable. |
| Rendezvous record | Discovery epoch, device ID, record sequence number, expiry time. | Replaying an old presence record as current. |
| Placeholder index | Device ID, folder ID, index generation number. | Showing a stale or foreign placeholder list. |
| Key wrap | ID and epoch of the wrapped key, ID and epoch of the wrapping key, purpose string. | Unwrapping a key for the wrong purpose or in the wrong folder. |

Object names in storage: the plan describes chunks as content-addressed both by "hash of the encrypted data" (plan 6.7) and by "keyed hash" (plan 6.11). This draft proposes both, for different jobs: the **storage object name** is an unkeyed hash of the ciphertext, so peers and scrub can verify a chunk without keys; the **keyed-hash ID** is used for deduplication and appears only inside encrypted manifests. Which one the swarm advertises is **TBD**.

## 4. Nonce strategy

Several devices write under the same folder key, offline, without coordinating. Counters would need per-key state shared between devices, and a device restored from a backup or a virtual-machine snapshot would reuse counter values. Nonce reuse with either AEAD candidate breaks confidentiality and authenticity of the affected messages.

Proposal:

1. **Fresh keys where possible.** Each chunk has its own random key (K14) and is encrypted once, so a nonce never repeats under it.
2. **Random 192-bit nonces for long-lived keys** (folder metadata key, wrapping keys), as in XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha). With 192 random bits, collisions are not a practical concern even across many devices and years.
3. **If AES-256-GCM is chosen instead,** random 96-bit nonces allow at most 2^32 encryptions per key (NIST SP 800-38D, section 8.3). That bound is hard to track across offline devices, so AES-GCM would be used only with single-use keys (rule 1) or with a per-message key derived from a random 256-bit value. Which AEAD is chosen remains **TBD**.
4. **No deterministic nonces derived from content** for metadata, since equal plaintexts would then be visible to A1.

## 5. Locked-state key set

The plan's blocking question asks which keys exist while the vault is locked. The answer proposed here keeps the set as small as possible and lists what each key allows. "After first unlock" means the device has been unlocked once since boot; "before first unlock" means it has not.

| Key | Mobile, before first unlock | Mobile, locked after first unlock | Desktop, locked | What it allows while locked |
| --- | --- | --- | --- | --- |
| K7 device ledger key | no | yes | yes | Sign receipts and location facts of this device only. |
| K15 camera-upload public key | yes (public) | yes | not used | Encrypt new photos and videos to a folder. |
| K16 upload-tracking key | no | yes | not used | Avoid uploading the same file twice. |
| K18 log name-hash key | no | yes | yes | Write log lines without clear-text names. |
| K19 log public key (phase 2) | yes (public) | yes | yes | Encrypt log lines. |
| Storage credential for uploads (K20) | no | **TBD** | **TBD** | Upload ciphertext. A put-only, scoped credential would be preferable where the provider supports it; **TBD**. |
| K21 discovery key | no | **TBD** | **TBD** | Publish and look up presence. |
| K22 ledger payload key (write side) | no | **TBD** | **TBD** | Encrypt new ledger payloads. A write-only (public-key) variant like K15 is one option; **TBD**. |
| K8 device transport key | no | **TBD** (proposal: no) | **TBD** (proposal: yes for headless seed devices) | Hand out ciphertext chunks to peers. |
| K9 of user-chosen plaintext-sync folders | no | yes, only for those folders (S-011 exception, plan 6.15) | yes, only for those folders | Keep folders that the user chose to sync unencrypted up to date. |
| K17 automation key | not applicable | not applicable | yes, on automation devices only | The scoped jobs only. |

While locked, these keys **must not** allow:

- decrypting any content or name, except the plaintext-sync folders the user chose;
- enrolling or revoking devices, changing folder membership, rotating keys or issuing wipe commands (K5 and K6 are absent);
- opening or listing the contents of Strongroom folders (K12 and K13 are absent);
- reading logs (K19 private part absent) or resolving name hashes for anyone but the local logger;
- hydrating placeholders (downloading content on demand); a locked desktop still shows the placeholders that already exist in the OS file system, because their names are plaintext there by design (F-039).

Consequence for A3 (thief with a locked phone after first unlock): with a keystore exploit the attacker could sign false ledger facts for that one device, upload ciphertext, and learn which camera files were uploaded. The attacker should not be able to read content or names. Revoking the device (section 6) invalidates its K7 certificate.

Desktop lock behaviour follows the same set; whether desktop apps lock at all on screen lock is **TBD** (plan section 8, "mobile lock and background sync").

## 6. Rotation and revocation

- **Device revocation.** An owner device with the second factor signs a revocation with K5. Effects: the device's K6 and K7 certificates are revoked; every folder the device could read gets a new K9 epoch; the chunk keys of existing data are re-wrapped under the new epoch (cost proportional to the number of chunk keys, not the data size); storage credentials the device held are rotated at the provider (plan 6.29). Data the device already decrypted or copied cannot be recalled (threat model, section 4). Re-encrypting existing data with new chunk keys is a separate, explicit, expensive action.
- **Shared-folder member removal.** Same steps for one folder: new K9 epoch wrapped to the remaining members' K8, chunk keys re-wrapped. Open point: chunk IDs come from K11, which the removed member knows, so the member can still recognise existing chunk IDs. Rotating K11 too would rename every chunk (cost proportional to the number of chunks) and break deduplication with older epochs; **TBD** (plan section 8, "sharing").
- **Strongroom.** Losing one security key: remove its wrap of K13 and rotate K13 from another enrolled key (plan 6.28). Enrolling a spare key needs an unlock with an existing key, because each credential produces a different secret and needs its own wrap. Built in 0.0.1-alpha.8: enrolling a spare key and removing a key's wrap (`strongroom add-key`, `remove-key`), and converting an existing folder, which gives it a new folder id and a fresh K13 and deletes the old K9 copies and old ciphertext from storage (alpha-0 format, section 17). Rotating K13 of an existing Strongroom is not built.
- **Master key rotation.** Generate a new K3, re-wrap K5, private folder keys and synced credentials; issue a new recovery wrap. Whether this also requires a new recovery key K1 is **TBD**.
- **Algorithm migration.** Every object header carries algorithm identifiers (section 3). New objects use new algorithms while old ones stay readable. Wraps that depend on a public-key algorithm (K9 wraps to K8, K15 encapsulations) can be redone without touching data. Signatures over past ledger batches can be covered by a new signature over a checkpoint. Exact procedure **TBD**.

## 7. Relation to the threat model

How this draft is meant to address each adversary of [../architecture/threat-model.md](../architecture/threat-model.md). These are design intentions, not achieved properties.

| Adversary | Keys and mechanisms involved | Remaining gap |
| --- | --- | --- |
| A1 Storage provider | K9, K10, K14 (content and names encrypted); K11 (no plaintext hashes); section 3 associated data (no swaps or replays); K2 recovery wrap stored there is protected by a 256-bit random key. | Deletion and rollback to an older state are detected only through the ledger and other copies. |
| A2 Network attacker | K6 and K8 (hybrid authentication and key agreement); chunk encryption in addition to transport encryption. | KEM combiner and handshake are **TBD**. |
| A3 Thief, locked device | K4 needs the hardware-bound secret; only the section 5 locked-state set is present. | TBD rows of section 5; strength of desktop key stores. |
| A4 Thief, unlocked device | K13 is never wrapped under K3; K5 and second factor for enrolment; revocation (section 6). | Normal folders that are unlocked are readable. |
| A5 Malicious peer | Storage object names are ciphertext hashes, so chunks can be verified before use; K7-signed ledger facts. | Resource limits belong to the transfer protocol. |
| A6 Malicious member | Per-folder K9 and K11; epochs and re-wrapping on removal. | Old chunk IDs stay recognisable (section 6). |
| A7 Release pipeline | Not addressed by key design. | Covered by S-007 and N-005. |
| A8 Quantum adversary | Symmetric 256-bit keys; every public-key wrap and handshake is hybrid; K12 relies on a symmetric FIDO2 secret, not on the key's classical signatures. | Parameter sets **TBD**. |
| A9 Coercion | Not addressed. | Out of scope. |
| A10 Same-user malware | K12 and K13 need a touch; K5 operations need the second factor. | Anything unlocked while malware runs is exposed. |
| A11 Relay or DHT operator | K21 derives opaque, epoch-based record keys and encrypts presence records. | IP addresses and timing remain visible. |
| A12 Cloud LLM via MCP | No key is ever passed through MCP; Strongroom keys are absent unless the user unlocks and allows it. | Content the user lets tools return. |
| A13 Holder of a removable disk | Same encrypted pack format and associated data as other storage. | Wipe does not reach the disk. |

## 8. Open questions

Each item is **TBD** and is not decided by this draft.

1. Is the second factor mandatory for daily unlock, or only for enrolling devices (affects K4)? Plan section 8, "2FA".
2. Which AEAD, KDF, keyed-hash function, KEM combiner and ML-DSA / ML-KEM parameter sets? Plan section 8, "PQ library".
3. Argon2id minimum costs, measured on the slowest supported phone; File Provider and DocumentsProvider extensions cannot run them (plan section 8, "extension memory limits").
4. Which transform turns a FIDO2 secret into K12 identically on every platform (FIDO2 platform research, question 1), and whether iOS needs version 26.4 or later for Strongroom (question 2).
5. Does K5 exist, or is membership a chain of device signatures?
6. Which of the TBD rows in section 5 belong to the locked-state set: upload credentials, discovery key, ledger payload key, transport key? Plan section 8, blocking question "key hierarchy and locked-state key set", and "mobile lock and background sync".
7. Dedup-domain boundaries and K11 behaviour across epochs and member removal. Plan section 8, "sharing" and "keyed hash, chunks and padding".
8. Recovery-key encoding, threshold scheme and whether master-key rotation needs a new recovery kit. Plan section 8, "recovery kit".
9. The context-string prefix and encoding of KDF inputs.
10. Granularity of K22 (per event or per batch) and how erasure interacts with signatures. Plan section 8, "GDPR and append-only ledger".

## References

- FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard, Table 3: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf> (checked 2026-10-08)
- FIPS 204, Module-Lattice-Based Digital Signature Standard, Table 2: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf> (checked 2026-10-08)
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA): <https://www.rfc-editor.org/rfc/rfc8032>
- RFC 9106, Argon2 Memory-Hard Function: <https://www.rfc-editor.org/rfc/rfc9106>
- RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF): <https://www.rfc-editor.org/rfc/rfc5869>
- draft-irtf-cfrg-xchacha-03, XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03> (checked 2026-10-08)
- NIST SP 800-38D, Galois/Counter Mode, section 8.3: <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf> (checked 2026-10-08)
- FIDO2 platform research: `docs/research/fido2-platform-support.md` (separate change)
