# Threat model

> **Design-stage model. No implementation exists.** This document describes what the design intends to protect, against whom, and where it deliberately stops. Nothing here has been built, tested or audited, so none of the properties below is achieved yet. Every statement is a design goal that implementation, tests and an independent review must still confirm. Open points are marked **TBD** and point to the open questions in the project plan.

Requirement IDs (`F-`, `S-`, `P-`, `N-`, `M-`) refer to the requirement tables of the project plan. "Plan 6.19" and similar refer to sections of that plan; "plan section 8" is its list of open questions.

## 1. Assets

| Asset | Why it matters | Main requirements |
| --- | --- | --- |
| File content | The data itself; must stay confidential for decades (harvest now, decrypt later). | S-001, S-003, S-006 |
| File names, folder tree and sizes of individual files | Often as sensitive as content (names reveal people, projects, health). | S-001, S-006, S-015 |
| Keys: master key, folder keys, Strongroom keys, device keys, recovery key and its shares | Whoever holds them holds the data. | S-002, S-012, S-014, F-042 |
| Device identities and the device list | Decide which devices may read, write, add devices and issue wipe commands. | S-004, F-035 |
| Storage credentials (S3 keys, rclone secrets, SFTP passwords) | Allow reading ciphertext, deleting it or running up costs on the user's storage, even without data keys. | S-002, S-012, F-006, F-007 |
| The ledger (where every block is) | Wrong bookkeeping can lead to deleting the last copy of data. | F-031, N-007 |
| Usage metadata | Object sizes and counts, access times, device count and online times, IP addresses. | S-006, S-015 |
| Availability of data | Encryption does not protect against deletion or loss; redundancy does. | F-018, F-020, F-021, M-005 |

## 2. Adversaries

Each adversary has an ID that other documents use (for example the key hierarchy refers to "A4").

| ID | Adversary | Assumed capabilities | Must not learn | Must not be able to do |
| --- | --- | --- | --- | --- |
| A1 | Storage provider, or anyone with access to the bucket or remote | Reads, copies, deletes, modifies, reorders and rolls back any object; sees request logs with times and client IP addresses; may lock the account. | Content, names, folder structure, keys, or whether the user holds a known file (no plaintext hashes). | Make a client accept modified, swapped or replayed objects without detection; make the ledger claim data that is not there without the claim being flagged. A1 **can** delete data and deny service; only redundancy limits that. |
| A2 | Network attacker, passive or active, on the LAN or the internet | Records all traffic for later decryption, injects, drops and replays packets, sits in the middle. | Content, names, keys, which shared folder a connection belongs to. | Impersonate a device, downgrade a handshake to classical-only cryptography, inject chunks or ledger events. |
| A3 | Thief with a stolen **locked** device | Physical access, unlimited time, can image the storage, can try passwords offline if the data allows it, can restore old app backups. | Content and names (except folders the user explicitly chose to sync unencrypted, the S-011 exception), keys. | Try passphrases offline without the device's hardware-bound secret; reset the failed-attempt counter by restoring a backup; add a new device. |
| A4 | Thief with a stolen **unlocked** device (open session) | Everything A3 can do, plus control of the running app, its UI and its local control API. | Strongroom content and names outside an open unlock window. | Open Strongroom folders, add devices to Strongroom, enrol new devices without the second factor (TBD, see section 4), block a revocation issued from another device. A4 **can** read normal folders that are already unlocked; wipe and revocation only limit further damage. |
| A5 | Malicious peer in the P2P swarm (not, or no longer, a member) | Connects, advertises chunks, serves wrong data, claims to hold data it does not have, floods requests. | Content, names, and for non-members which folder a swarm belongs to. | Make a device accept a corrupted chunk; make the ledger count a fake copy as verified; exhaust a device's resources without limits. |
| A6 | Malicious member of a shared folder | Holds the folder key legitimately; writes, deletes and renames inside the folder; keeps copies; may try to fill the owner's storage. | Other folders of the owner; content added after its removal. | Forge another member's ledger events; delete beyond what version history and trash can restore; read new content after removal. A6 **can** keep everything it saw before removal. |
| A7 | Compromised release pipeline (build system, signing key, dependency, store account) | Ships a modified binary to users. | Not applicable: a malicious client sees everything the user unlocks. | Ship a release that differs from the published source without that being detectable (reproducible builds, signatures, attestations). The goal is detection, not prevention. |
| A8 | Quantum adversary (harvest now, decrypt later) | Records ciphertext and handshakes today; later runs a large quantum computer. | Content, names and keys recorded today. | Recover any key that was protected only by classical public-key cryptography. |
| A9 | Coercion (border check, legal pressure, physical threat) | Forces the user to unlock a device or present a security key. | Not achievable in general. | Out of scope beyond the optional duress passphrase (S-009, a "Could" item). See section 4. |
| A10 | Malware running as the same OS user on a desktop | Reads the user's files and process memory where the OS allows, talks to the daemon's control socket, injects input, reads the clipboard. | Raw key material held in the OS keystore or on a security key (it can use keys while unlocked but should not be able to export them). | Trigger level-3 (irreversible) actions through the control API or MCP without a confirmation outside that API; open Strongroom without a security-key touch. A10 **can** read anything the user has unlocked while it runs. |
| A11 | Operator of a relay or DHT node | Sees IP addresses, timing, sizes and opaque records; drops, delays or replays records; may run many nodes (Sybil, eclipse). | Content, names, keys, the identity of the shared folder. | Redirect a device to an impostor: the DHT record is only a hint and authenticity is checked in the hybrid handshake. |
| A12 | Cloud LLM provider reached through MCP | Receives whatever the MCP tool results contain; the model may follow instructions hidden in file content (prompt injection). | Secrets (passwords, keys, recovery words, PINs, storage credentials) and Strongroom content. | Cause irreversible actions without user confirmation outside the LLM channel. It **does** learn whatever content the user lets the tools return; end-to-end encryption does not cover that (plan 6.9). |
| A13 | Holder of a removable disk from the offline pool | Reads and modifies the disk at leisure; clones it or returns an old copy. | Content and names. | Make stale or modified data on the disk be accepted as current. Remote wipe does not reach offline disks; only encryption protects them (plan 6.35). |

## 3. Trust boundaries

| Boundary | Trusted inside | Crosses the boundary | Design intent |
| --- | --- | --- | --- |
| User's device (running, unlocked) | The Varsto process, the OS kernel, the hardware. | Ciphertext out to storage and peers; plaintext only to the user and to apps the user opens a file with. | Plaintext and unwrapped keys exist only here and only while unlocked (S-002). |
| OS keystore (Android Keystore and StrongBox, Apple Keychain and its hardware key store, Windows and Linux key stores) | Non-exportable key storage, user-presence and biometric gating, monotonic counters where available. | Wrap and unwrap requests. | Holds the hardware-bound secret and the wrapping keys for the locked-state key set. Desktop key stores vary in strength; per-platform assessment is **TBD**. |
| FIDO2 security key | The authenticator's credential-bound `hmac-secret` (WebAuthn PRF) secret. | A salt in; a 32-byte secret out, after a touch and an optional PIN. | The secret is symmetric, so A8 gains nothing from recorded traffic. The key's own signatures (ES256, EdDSA) are classical and are not relied on for confidentiality (plan 6.5). Platform support differs; see the FIDO2 platform research (`docs/research/fido2-platform-support.md`, separate change). |
| Daemon control socket (Unix socket, named pipe) | Only the OS user boundary. | CLI, UI and MCP server requests. | Any process of the same user can reach it (A10). Level-3 actions need confirmation outside the socket (separate UI process, OS prompt or security-key touch). Peer-process checks and token storage are **TBD** (plan section 8, "local control API trust model"). |
| MCP client and the LLM behind it | Nothing. | Tool calls in, tool results out. | Read-only by default, scoped revocable tokens, summaries instead of names, no secrets, Strongroom invisible, dry-run and external confirmation (F-016, F-038, plan 6.32). |
| Storage (cloud, rclone remote, local folder, removable disk) | Nothing (S-006, S-014). | Encrypted, authenticated objects. | Confidentiality and integrity come from client-side authenticated encryption; availability only from redundancy and scrub. |
| Peers (other devices) | Own devices after authentication with device keys, until revoked; shared-folder members only for their folder. | Encrypted chunks, signed ledger events, transfer requests. | Every chunk is checked against its hash before acceptance; claims of holding data are challenged (plan 6.19). |
| Relay and DHT | Nothing. | Opaque, encrypted traffic and records. | Hints only; authenticity is established end to end in the hybrid handshake (plan 6.33). |

## 4. Non-goals and residual risks

They are listed so that nobody, marketing included (M-005, M-006), claims more than the design intends.

- **A compromised, unlocked device.** Malware or an attacker with the open session (A4, A10) can read everything that is unlocked, including a Strongroom folder during its unlock window. A security key has no display, so the user cannot see which operation a touch approves (plan 6.28).
- **Coercion (A9).** The design does not protect a user who is forced to unlock. The duress passphrase is an optional "Could" item.
- **Deletion and denial of service by the provider (A1).** Encryption prevents reading and undetected modification, not deletion, account closure or rollback to an older state. Redundancy across providers and own devices, scrub and alerts limit the effect (F-018, F-020, F-021, F-032).
- **Data copied before a theft or a member removal (A3, A4, A6).** Revocation and key rotation protect future data only.
- **Wipe only reaches devices that come online.** A device that stays offline is protected only by its lock (S-008 to S-010) and by revocation (plan 6.29). Wipe does not reach removable disks (A13).
- **Content shown to a cloud LLM (A12).** Once the user lets an MCP tool return content, the LLM provider has it.
- **Plaintext synced folders.** A folder that the user syncs unencrypted (the S-011 exception on mobile, sync folders on desktop) is protected only by the device's own lock and disk encryption.
- **Alpha-stage logs.** In the alpha, logs are redacted but not encrypted at rest; they reveal usage patterns (event types, sizes, times) even without names (plan 6.40).
- **Second factor for daily unlock.** Whether the second factor is mandatory for unlock or only for adding a device is **TBD** (plan section 8, "2FA"). Until that is decided, resistance against A3 and A4 is described for the strongest configuration only.
- **Locked-state keys.** Background sync, camera upload, ledger acknowledgements and logging need some keys while the app is locked. They are a deliberate, documented reduction of protection against A3. The exact set is drafted in the key hierarchy (`docs/spec/key-hierarchy.md`, separate change) and is **TBD**.
- **Side channels.** Compression before encryption can leak information about content through sizes (plan 6.11). Whether compression is on by default, and the padding classes, are **TBD**.
- **Implementation flaws.** Bugs, misuse of libraries and timing side channels are outside this model but are the most likely real-world failures. An independent review is planned before beta (S-007).

## 5. Metadata that can be learned

Encryption hides content and names. It does not hide that data exists, how much there is, or when and from where it is used.

| Observer | What it can learn | Mitigation in the design | Status |
| --- | --- | --- | --- |
| Storage provider (A1) | Number and sizes of objects; times of writes and reads; growth rate; deletions; client IP addresses and user agents in access logs. | Packs group small chunks (plan 6.11); chunk and pack sizes padded to size classes; object names are opaque. | Padding classes **TBD** (plan section 8, "keyed hash, chunks and padding"). |
| Storage provider through the rendezvous record (A1) | How many devices the user has, when each is online and from which IP address (home or travelling), from the reads and writes of the encrypted presence record (plan 6.33). | Record path derived from a shared secret and a time epoch; heartbeat merged with normal sync requests and randomised; a privacy mode without a rendezvous record. | Not designed in detail; **TBD** (plan section 8, "rendezvous record metadata"). |
| DHT participants (A11) | The device's IP address and that it looks up or publishes a record at certain times; a Sybil attacker may link lookups across epochs. | DHT off by default or only with explicit consent; record key derived from a shared secret and a daily epoch; records encrypted. The record carries a classical signature only, because a BEP 44 record is too small for an ML-DSA signature, so it is treated as a hint and never as proof of authenticity (plan 6.33). | Default **TBD** (plan section 8, "P2P library and discovery"). |
| Relay operator (A11) | IP addresses of both ends, timing and volume of traffic. | Self-hostable relays; direct connections preferred; relays see only encrypted traffic. | Design intent. |
| Network observer (A2) | Which devices talk to each other, when and how much; LAN discovery announcements. | LAN announcements carry only a derived identifier, no names; the handshake does not reveal the folder identity. | Design intent. |
| Peers in a swarm (A5) | Which chunk IDs a device has (bitfields) and transfer patterns. | Only members of the same folder join its swarm; chunk IDs are keyed hashes, so outsiders cannot test for known files. | Design intent. |
| Shared-folder member (A6) | The folder's full history, member device IDs and times in the ledger; old chunk IDs after removal. | Names in ledger events are keyed hashes; cryptographic erasure of event payloads (plan section 8, "GDPR and append-only ledger"). | **TBD**. |
| Holder of a removable disk (A13) | Pack sizes and counts, last write time, the disk's identity file. | Same encrypted pack format and padding as other storage. | Design intent. |
| Anyone who can read the ledger objects (A1) | Activity level and number of devices, from ledger size and event rate. | Events are batched (ledger signing notes, `docs/spec/ledger-signing-notes.md`, separate change). | **TBD**. |

## 6. Mapping: adversary to requirements and plan sections

| Adversary | Requirement IDs | Plan sections |
| --- | --- | --- |
| A1 Storage provider | S-001, S-003, S-006, S-014, F-018, F-020, F-021, F-031 | 6.10, 6.11, 6.19, 6.33 |
| A2 Network attacker | S-003, F-011, F-013 | 6.5, 6.7 |
| A3 Thief, locked device | S-008, S-009, S-010, S-011, S-014, F-035, F-037 | 6.15, 6.29, 6.31 |
| A4 Thief, unlocked device | S-004, S-012, F-035 | 6.28, 6.29 |
| A5 Malicious peer | F-011, F-012, F-031, N-007 | 6.7, 6.19, 6.33 |
| A6 Malicious shared-folder member | F-004, S-006, F-025, F-034 | 6.11, 6.19; plan section 8 "sharing" |
| A7 Compromised release pipeline | S-007, N-005 | 6.14 |
| A8 Quantum adversary | S-003, S-014, M-006 | 6.5, 6.38 |
| A9 Coercion | S-009, S-012 | 6.15, 6.28 |
| A10 Same-user malware | S-012, F-016, F-038, P-003 | 6.28, 6.32; plan section 8 "local control API" |
| A11 Relay or DHT operator | F-012, F-013, S-003 | 6.7, 6.33 |
| A12 Cloud LLM via MCP | F-014, F-015, F-016, F-038, M-001 | 6.9, 6.32 |
| A13 Holder of a removable disk | F-040, S-001, S-003, F-035 | 6.29, 6.35 |

Logging rules (S-015, N-013, plan 6.40) apply to every adversary that can obtain logs or diagnostic bundles: A3, A4, A10 and anyone the user sends a bundle to.

## Related documents

- [security-principles.md](security-principles.md)
- [logging.md](logging.md)
- [../failure-model.md](../failure-model.md)
