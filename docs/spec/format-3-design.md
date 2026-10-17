# Format 3 design: pack-level ledger, folder block maps, signed records

This is the binding design for storage format version 3. It replaces format 2 (`alpha-0-format.md` section 62) and the unmerged records design of format 2 (`format-2-design.md` on the branch `format2-records`, whose records parts are carried here). Vaults are created fresh; nothing older is read; `FORMAT_VERSION` = 3. Backward compatibility is not required. Where this document and `alpha-0-format.md` disagree, this document wins for format 3; the sections it supersedes are listed in section 11.

Design goals, in order: (1) no party below full-device trust can change what another device sees; (2) no key material leaves a device without a signed, manually approved grant; (3) a storage sees only opaque objects of a few fixed sizes; (4) every authentication decision is a signature check against a device key the vault already trusts; (5) the bookkeeping a device must hold grows with the number of packs, not the number of blocks; (6) nothing relies on wall-clock time for security.

Notation: `aad(type, [fields])` is `crypto::aad` (length-prefixed format version, AEAD id, type, fields). `derive(K, purpose, scope...)` is BLAKE3 `derive_key` with the context `e2ee-sync-format/3/<purpose>` and length-prefixed scope ids. Ids are binary on the wire: vault, device, folder 16 bytes; chunk id, object name, pack id, body hash 32 bytes. "Hex" only in object names on the storage. All integers little-endian; "postcard" is the `postcard` 1.x encoding of the Rust struct as written; "zstd" is level 3.

## 0. Scope and non-goals

In scope: the keys, the block and pack format, the folder block map, the ledger events and view, the signed record envelope and its kinds, folder membership and recovery, manifests, trash, history and snapshots as base + delta records, peer records and the transport's authentication, and what each party learns.

Not in scope (unchanged from format 2 unless a section says so): the chunker's algorithm, the merge rules of section 7, policies (section 14), placement rules (section 23) except how copies are counted, organizations (section 27) except that their roster grants travel as format-3 grants, the local control API, Strongroom FIDO2 handling (section 17) except that K13 is escrowed like K9, restic backups (section 35). Members of shared folders still do not act as peers (section 15); the format reserves folder-scoped peer records for that later (section 8). No migration tool from format 2 (section 11). No Merkle inclusion proofs for single events (`ledger-signing-notes.md` section 7 remains an option, not a requirement).

## 1. Keys

| Key | Purpose | How made | Where | Change from format 2 |
| --- | --- | --- | --- | --- |
| K1 recovery key | escrow of every folder key epoch (and Strongroom keys the user opts in) | 256 random bits, 24 BIP-39 words, optional Shamir 2-of-3 | paper only | new in practice (format 2 designed it, never shipped) |
| K2 = derive(K1, "recovery-wrap") | wrap escrowed folder keys | derived | memory, while printing a kit or writing escrow | as designed |
| K3ₑ vault key, epoch e | registry, vault ledger, peer records, local keyring, pool markers | 256 random bits; epoch 0 is the second word set of the kit; later epochs only as vault grants (section 21) | every full device, wrapped under K4 | no longer derives any folder key |
| K4 device unlock key | wrap K3ₑ, K6, K8 on one device | Argon2id (64 MiB, 3, 1) of the NFKC passphrase; Keystore/Keychain wrap on mobile | not stored | unchanged |
| K6 device signing key | sign every record, batch, checkpoint and peer token binding | Ed25519 + ML-DSA-65, made on the device, never exported | device only | signs records too, not only batches |
| K8 device KEM key | receive grants | X25519 + ML-KEM-768, made on the device | device only; public part in the device record | in the device record (no separate `vault/kem/` file) |
| K9ₑ folder key, folder epoch e | one folder, one epoch | 256 random bits, made by the owner that starts the epoch | grants (section 6) and escrow; **never derived from K3** | `derive(K_epoch, "folder-epoch")` and folder keys in folder records are gone |
| K10ₑ = derive(K9ₑ, "folder-metadata", folder) | manifests, block maps, trash and history, snapshots, thumbnails, notes, access records | derived | holders of K9ₑ | also block maps |
| K11 = derive(K9₀, "dedup-hash", folder) | chunk ids and content hashes, fixed at the folder's first epoch | derived once; carried in every grant | holders of any K9ₑ | unchanged |
| K12 = derive(K11, "chunker-seed", folder) | Gear table seed | derived | holders of K11 | unchanged |
| K14 = derive(K9ₑ, "chunk-key", folder, chunk id) | one chunk | derived | holders of K9ₑ | unchanged |
| chunk nonce = keyed_hash(derive(K9ₑ, "chunk-nonce", folder), packed)[..24] | one AEAD input | from the exact packed bytes | holders of K9ₑ | unchanged |
| K13ₑ Strongroom key | as K9ₑ for a Strongroom folder | random; wrapped under FIDO2 hmac-secret outputs, and under K2 if the user opts in | never under K3 | unchanged |
| registry key = derive(K3ₑ, "device-registry") | device, folder, request, peer, policy, placement, settings, storage-name records | derived | full devices | now also folder records and requests |
| ledger key = derive(K3ₑ, "ledger") | vault ledger batches and checkpoints | derived | full devices | unchanged |
| share-ledger key = derive(K9ₑ, "share-ledger", folder) | folder-scoped batches of members | derived | holders of K9ₑ | unchanged |

Removed: folder keys derived from K3, folder keys in folder records, `pack-tombstones` key, the `p2p-auth` keyed-hash token key (section 8), plain and `vst1` share tokens, bare (unsigned) epoch records, `SHARE_EPOCH_BASE` (with no vault-derived folder keys, one folder epoch sequence 0, 1, 2, ... serves removals of own devices and of members alike).

`key_id` strings name the key that opens a body, and are inside every signature: `registry@<e>`, `ledger@<e>`, `epoch@<e>` (vault epoch record key), `meta:<folder hex>@<e>` (K10ₑ), `share-ledger:<folder hex>@<e>`, `kem:<recipient device hex>` (grants), `recovery` (K2), `replica` (as today), `none` (body not encrypted; only for `request-code` bodies, which carry public keys and a name). MAX_KEY_ID = 64 bytes.

A holder of K3 alone (a device joined with the vault words and not yet approved for any folder) reads the registry (device names, folder names and settings, participants), the vault ledger (pack ids, pack sizes, which storages hold which packs, folder ids, writers, record announcements) and peer records; it can verify packs against their ids, copy packs between storages and sign vault batches. It cannot open any manifest, map, trash record, snapshot or chunk, and learns no chunk id, object name or place of a block.

## 2. Blocks and packs

Unchanged from format 2, stated briefly: keyed content-defined chunker with size tiers (`chunking: 2`; under 1 MiB one block; 1–32 MiB avg 1 MiB, 256 KiB–4 MiB; 32 MiB–1 GiB avg 4 MiB, 1–16 MiB; from 1 GiB avg 8 MiB, 2–16 MiB; unknown size: 1 MiB tier); chunk id = keyed BLAKE3(K11, plaintext); `pack(plain)` = method byte (0 raw, 1 zstd 3) || payload, zstd tried only when a 64 KiB level-1 probe saves at least 5 %; chunk object = `nonce (24) || ciphertext || tag (16)` under K14 with the derived nonce; chunk AAD = aad("chunk", [vault, folder, epoch u32, chunk id, plaintext length u64, packed length u64]); object name = BLAKE3(chunk object); a reader checks the nonce against the packed bytes, the plaintext against the chunk id, and the object against its name. One function seals (`chunk_seal::seal_chunk`), one opens.

**Pack layout.** `packs/<xx>/<pack id hex>`: member objects back to back from offset 0, then padding, nothing else (no header, no trailer, no index). Pack id = BLAKE3 of all bytes including the padding. Padding is bytes from the OS CSPRNG. The pack length is exactly one **size class**: 1, 4, 16 or 64 MiB on hot, local, pool and transferrer storages; 1, 4, 16, 64 or 256 MiB on cold storages (MiB = 2^20). A reader refuses a pack, a `pack_stored` event or a map pack reference whose length is not a class (`"pack <id> has length <n>, not a size class"`), and `storage::MAX_PACK` becomes exactly 256 MiB. Members never overlap, never cross the end of the members area, and a member's length is at most `MAX_CHUNK_SIZE + 1 + 40` (16 MiB + method byte + nonce and tag).

**Choosing the class.** A pack builder collects members in a buffer per **target set** (the set of storages a group of blocks goes to, so one pack is written byte-identical to every storage of the set and has one id there; packs for cold storages are built separately because their class limit differs). It closes a pack when the next member would pass the largest class of the set, filling first-fit-decreasing from the buffer so that full packs are at least 98 % members; the last pack of a push, an import, a repair or a rewrite takes the smallest class its members fit in. The padding of a pack is therefore below 3/4 of its class, and below 2 % for every pack but the last of an operation. Reason for random padding rather than zeros: a zero tail would show where members end to anyone holding the pack.

**Imports** buffer contents across files exactly like pushes (format 2 wrote one pack per content); a pack never reveals one file's size.

**Writing.** Put-if-absent; S3 multipart in 16 MiB parts above 64 MiB; HEAD before PUT finds a pack that is there. Packs are written before the map record that lists them and before the batch that claims them (section 3, "Writer").

Reservation (padding cost of small pushes): a push of one small edit costs a 1 MiB pack on every storage of its target set. With the service syncing a frequently saved document every few minutes, a hot storage gains up to ~300 MiB a day per such file before compaction (section 3, "Compaction") folds them; on S3 with request and per-object costs this is visible. Implemented as decided; the compaction rule bounds the steady state, but a smaller first class (64 KiB or 256 KiB) would cut the transient cost at a modest loss in size hiding.

## 3. Folder block map

The block map of a folder says, for every block of the folder, in which pack and at which offset it is. It is the primary structure that format 2's pack index was a by-product of. It is per folder, per writer device, sequence-numbered.

**Stream and name.** `maps/<folder hex>/<device hex>/<seq 16 digits>-<part 4 digits>.rec`, a SignedRecord (section 5) of kind `block-map`, scope = folder, key_id `meta:<folder>@<e>` with e the folder's newest epoch the writer holds, announced in the writer's batch (section 4, `record_published`). `seq` starts at 1 and increases by 1 per record of this stream.

**Body** (postcard, then zstd, then AEAD):

```text
BlockMap {
  folder: [u8;16], device: [u8;16], seq: u64, lamport: u64,
  base: u64,                 // seq of the base this record builds on; == seq for a base
  prev: [u8;32],             // body_hash of record seq-1 of this stream; zeros for seq 1
  packs: Vec<PackRef>,       // table, referenced by index
  entries: Vec<MapEntry>,    // base: every live place this writer wrote; delta: places added since seq-1
  marks: Vec<Mark>,          // dead / undead / lost marks on places of any writer of the folder
}
PackRef  { id: [u8;32], class: u8 }   // class: 0=1 MiB, 1=4, 2=16, 3=64, 4=256
MapEntry { object: [u8;32], chunk: [u8;32], pack: u32, offset: u32, len: u32, plain_len: u32, epoch: u32, flags: u8 }
Mark     { object: [u8;32], pack: [u8;32], offset: u32, kind: u8 }   // 1 dead, 2 undead, 3 lost
```

`MapEntry` is 85 bytes before compression (hashes do not compress); `flags` bit 0 is "dead" (the writer's own settled view of its own place, kept in bases until the place is collected), other bits must be 0. A place is identified by (pack id, offset); `object` repeats the object name so a reader checks every place it uses. `len` is the object length, `plain_len` the unpacked plaintext length (the chunk AAD needs both lengths; packed length = `len - 40`). Limits: at most 4 194 304 entries and 1 048 576 marks per record part, at most 65 536 packs per record, `offset + len ≤ class size`.

**Base and delta.** A base lists every live place the writer wrote (its packs that the view still shows on at least one storage) and the marks it made that are not settled-and-collected yet. A delta lists places added since `seq - 1` (new packs, rewrites, repairs) and new marks. The writer publishes a new base when the deltas since the last base reach 1024 records or their bytes reach 1/4 of the base's bytes, whichever comes first. Reason for a looser rule than manifests' 64: a map base of a large folder is hundreds of MB of incompressible hashes (section 4, "Estimates"), and deltas are pure additions that cost readers little. A record larger than 32 MiB is written in parts (section 5).

**Who writes.** Every device that writes packs of the folder: owners and editors of the folder (own full devices, and members of shared folders as editors), forwarders (section 70; they hold the folder key already), and garbage collectors and repairers (who write the new packs of rewrites and repairs). Viewers, replicas and holders of K3 alone write no maps.

**Writer.** One push (or import, data move, repair, rewrite, forward run) is: write its packs; write one map delta listing their members; seal one batch with `pack_stored` for every (pack, storage) written and `record_published` for the map delta (and the manifest delta, section 7); push the batch. A crash before the batch leaves unclaimed packs, which garbage collection deletes after 7 days when no map lists them (`orphan`). The map delta goes to every hot metadata storage, like manifests.

**Reader.** A device that holds K10 of the folder keeps a local map table per folder (`state/maps/<folder>.tbl`): the union of every accepted writer's newest base and the deltas after it, as fixed-width rows sorted by object name, with a second array of row numbers sorted by (chunk id, epoch); marks in a side table keyed by place. It is updated from new deltas after every pull (a pull lists only streams whose announced seq is newer than the one applied, as manifests do since section 25) and rebuilt when a new base is announced. Memory is O(1) in the number of blocks (the table is read through `mmap` or positioned reads); disk is about 85 bytes per place.

**Finding a block** (fetch, restore, verification, P2P serving): manifest → object name; map table → places (pack, offset, len); ledger view → storages that hold each pack (claimed, not dropped, not retired); one ranged read; check the object against its name; open. A place with a dead or lost mark is used only when no other place exists and the read is checked as usual (it is still bytes on a storage).

**Dedup for a writer.** Before writing a block the writer looks up (chunk id, epoch) in its map table. A place counts for dedup on storage S when its pack is held on S in the view and the place has no dead or lost mark (settled or not) that this device holds. If every target storage holds such a place, nothing is written; for storages that lack it, the block goes into a new pack for those storages only. A block whose only places carry a dead mark is written again, never revived by reuse. Across epochs, a chunk id the folder already holds under an older epoch keeps its object (format 2 rule).

**Dead marks, settling and collection.** Liveness is decided by references, never by marks alone. A device with write role in the folder that finds an object referenced by nothing (no current file in any accepted writer's newest manifest, no unexpired trash or history entry, no unexpired snapshot of the folder) publishes a `dead` mark for each of its places in its next map delta. The mark m, announced in the marker's batch b, is **settled** when every current writer of the folder (owners and editors, own devices and members, not revoked) has signed a batch whose `seen` names the marker at ≥ b (members: in their folder-scoped batches, which carry `seen` for the folder's devices). A place is **collectable** for device G when a settled dead mark is on it, no `undead` mark with a larger (Lamport, device) stamp is on it, and G, having applied every writer's records announced up to the batches that settled m, finds no reference to the object. The race "a block deleted on one device while another skips writing it" is closed by this ordering: a writer that skipped a block did so before it pulled the mark (after the pull it would write the block again), so its manifest naming the block is announced in a batch before the one in which it acknowledges the mark, and G sees that manifest before the place becomes collectable. A device that finds a reference to an object it marked dead publishes `undead` marks for those places. A hostile or mistaken mark therefore delays nothing and deletes nothing that is referenced.

**Who may mark.** Owners and editors (including members of shared folders with the editor role), for any place of the folder. Marks from viewers, replicas, K3-only devices, removed devices after their cut-off, and marks naming a place of another folder are ignored and counted (`marks_refused`).

**Garbage collection.** Run by the trash upkeep (`pack_upkeep`) on own full devices with write role that hold K10 (members do not collect: they may not hold the owner's storages):

- a pack whose every member place is collectable is dropped: `pack_dropped` on every storage that holds it, batch sealed and pushed, then deleted (on cold storages not before the price model's minimum storage duration);
- a hot pack whose collectable members make up more than 50 % of its member bytes (padding not counted) is rewritten: one GET, the id checked, every live member checked against its name, live members into new packs (padded, section 2) for the same storages, a map delta with the new places, one batch with `pack_stored` for the new and `pack_dropped` for the old pack, pushed, then the old pack deleted;
- cold and pool packs are never rewritten; their dead space goes when every member is collectable;
- **compaction**: hot packs of a folder smaller than 64 MiB whose live members together fill at least one 64 MiB class are merged in the same way (bounds the cost of small pushes, section 2).

Entries of a dropped pack leave their writer's next base; marks on places that are gone leave the marker's next base.

**Verification and repair** (section 26 per pack): verification reads a whole pack (one GET) and compares BLAKE3 with the pack id; that needs no folder key, so K3-only devices and replicas verify too. When the hash differs, a device holding K10 checks every member against its name; corrupt members are fetched from another place (another pack, a peer, the local file, the block cache), and the whole pack's good members are written into a new pack on that storage (also on cold storages: repair is the exception to "cold never rewritten", because a damaged pack must not keep counting); the map delta adds the new places and puts `lost` marks on the corrupt places; the batch carries `pack_stored` (new) and `pack_dropped` (damaged). A member with no good copy anywhere keeps its `lost` mark and is reported (file damaged) until a device that holds the file writes it again. A pack missing on a storage but held on another is copied whole (no key needed), claimed under the same id.

**Pruning.** A writer deletes its map records older than its newest base B (and B's parts' predecessors) on every hot metadata storage once every reader of the folder (devices holding K10 of the folder: own full devices with a grant, and members) has acknowledged the batch that announced B. Cold storages are not pruned. Readers that join later read B and its deltas.

**Worked example.** Device A pushes `photo.jpg` (3 MiB, three blocks a1..a3) to storages H1, H2 (hot) and C (cold). A builds pack P (members a1..a3, 3.1 MiB, class 4 MiB) for {H1, H2} and pack Q (class 4 MiB) for {C}; writes P to H1, H2 and Q to C; writes map delta A/17 with packs [P, Q] and entries a1..a3 at P and at Q; seals batch A/240 with `pack_stored(H1,P)`, `pack_stored(H2,P)`, `pack_stored(C,Q)`, `record_published(block-map, F, 17)`, `record_published(manifest, F, 52)`. Device B pulls: the view gains P on H1, H2 and Q on C; its map table gains six rows; to fetch a2 it reads P on H1 at a2's offset. Later A deletes the photo; after the trash days B's upkeep finds a1..a3 unreferenced, publishes B/9 with dead marks on the six places in batch B/77. A acknowledges B/77 in A/251; B's settle check passes (A and B are the only writers); B finds no reference; P is 100 % collectable and so is Q: B seals `pack_dropped(H1,P)`, `pack_dropped(H2,P)`, `pack_dropped(C,Q)` and deletes them (Q after C's minimum duration). If instead device D had re-added the same photo before pulling B/9, D's push skipped writing a1..a3 and announced D's manifest in D/30; D acknowledges B/77 only in D/31; B's settle check waits for D/31, then reads D's manifest from D/30, finds the reference, and publishes undead marks instead of dropping.

## 4. Ledger

Unchanged: per-device hash chains, Lamport clocks with reservations, order-independent application, the incremental mailbox, pending gaps, fork detection, fencing on verified objects only, checkpoints, acknowledgements (`seen`), pruning, the scopes of section 58, one batch per user action.

**Batch body** (postcard, then zstd; replaces JSON): `Batch { device: [16], seq: u64, prev: [32], lamport: u64, created_utc: i64, seen: Vec<([16], u64)>, events: Vec<RawEvent> }`, `RawEvent { code: u16, payload: Vec<u8> }`. Each payload is postcard of the event's fields; a reader skips codes it does not know (counted as `unknown`), so later events stay readable. The batch envelope is a SignedRecord (section 5) of kind `batch` at `ledger/<device hex>/<seq 16>-0000.rec` (a batch is always one part); its `body_hash` replaces `hash` and its `key_id` is signed. MAX_BATCH_BODY = 16 MiB compressed, MAX_EVENTS = 65 536 per batch; an action that would exceed either seals further batches (the "one batch per action" rule bends only there).

| Code | Event | Fields | Who may make it (scope) |
| --- | --- | --- | --- |
| 1 | `device_enrolled` | name (≤ 128 bytes) | any (own name) |
| 2 | `folder_added` | folder | full |
| 3 | `pack_stored` | storage (name, ≤ 64 bytes), pack [32], class u8, folder [16] (zeros from a replica), map_seq u64 (0 from a replica) | full; member: its folder; replica: zero folder |
| 4 | `pack_verified` | storage, pack | full; member: packs of its folder; replica |
| 5 | `pack_dropped` | storage, pack | full; member: packs it wrote |
| 6 | `record_published` | kind u8, scope [16], seq u64, base u64, parts u16, body_hash [32], size u64 | full; member: kinds `manifest`, `block-map`, `trash` of its folder |
| 7 | `storage_retired` | storage | full |
| 8 | `snapshot_taken` | backup, seq, taken_utc, expires_utc, files, bytes | full (the source device) |
| 9 | `snapshot_expired` | backup, device, seq | full |
| 10 | `backup_stopped` | backup | full |

Removed: `chunk_stored`, `chunk_verified`, `chunk_dropped` (replaced by the pack events), `manifest_published` (replaced by `record_published`), `chunk_on_device` (below). `body_hash` of a multi-part record is BLAKE3 over the concatenated `body_hash` of its parts in order.

**`chunk_on_device`.** Its users today: transferrer targeting and emptying (F-048: "a carrier takes what no other device has yet", "delivered when every destination holds it"), the folder safety indicator ("another device holds a copy"), `where` / `/api/where` bytes per device, and the forwarding report's holders. All of them decide per folder and already hold the folder key. It becomes a per-file flag in the writer's own manifest: `held: bool` on each file entry (section 7), true when this device holds every block of that version (the file on disk, or every block in the block cache). "Device D holds object O" = some entry of D's newest manifest with `held` names O. No ledger event. Holders of K3 alone lose the per-device byte counts of `where`, which they could not attribute to files anyway.

**View** (in memory; stored as postcard + zstd in `ledger/view.rec`, local key, view format 1 of format 3):

```text
LedgerView {
  packs: HashMap<[u8;32], PackRecord>,
  streams: BTreeMap<(kind, scope, device), Stream>,     // newest base and the deltas after it
  devices, devices_at, folders, max_lamport, retired, batches, acks, forked,
  snapshots, backups_stopped, events_refused,           // as in format 2
}
PackRecord { class: u8, folder: u32, writer: u16, map_seq: u64, at: Stamp,  // folder/writer interned
             places: SmallVec<[(u16 storage, PackPlace); 3]> }
PackPlace  { claimed_by: u64, verified_by: u64, stored_at: u64, verified_at: u64, dropped_at: u64 }  // device bitsets
Stream     { base: (seq, body_hash, parts), deltas: Vec<(seq, body_hash, parts)> }
```

Application stays order-independent: claims and verifications are unions, times are maxima, a drop cancels claims with a smaller Lamport time on that storage, folder/writer/map_seq of a pack come from the claim with the largest (Lamport, device, seq, position) stamp among non-replica claims. **Copies of a block** = storages holding a live place of it: pack held there (claimed, not dropped, storage not retired) and the place not marked dead or lost. Policies, placement, staged moves (section 59, counting packs), disk groups, drains and quotas count this way; they need the map only to go from a file to its packs.

**Checkpoints** keep their rules (written by the device, speak for their signer, read only from full devices, 65 536-ahead limit) with the pack-level view as body: `Checkpoint { device, seq, head_hash, created_utc, view }`, a SignedRecord of kind `checkpoint` at `ledger/<device>/checkpoint-<seq 16>-<part 4>.rec` (parts as in section 5; checkpoint names still sort after every batch name). **Acknowledgements** keep `seen`; members' folder-scoped batches carry `seen` for the folder's devices only, which count for settling marks (section 3) and folder record pruning, never for vault ledger pruning.

**Estimates** (not measured; assumptions stated): 1 M files and 10 TB in one vault; 700 000 files under 1 MiB (avg 150 KB, one block each), 280 000 files of 1–32 MiB (avg 8 MB, 1 MiB blocks), 20 000 files over 32 MiB (avg 383 MB, ~5 MiB blocks): ~4.3 M blocks. Four full devices, three storages: two hot (one target set, so both hold the same packs) and one cold.

| Quantity | Format 2 | Format 3 |
| --- | --- | --- |
| packs | ~150 k per hot storage (built per storage), ~37 k cold | ~150 k hot (shared by both hot storages) + ~37 k cold = ~187 k |
| events for the first upload | ~12.9 M `chunk_stored` (4.3 M × 3), ~260 B JSON each: ~3.4 GB before zstd | ~337 k `pack_stored` (~80 B): ~27 MB, plus map announcements |
| events for one full verification round | ~12.9 M `chunk_verified`: ~2.5 GB | ~337 k `pack_verified` (~50 B): ~17 MB |
| a day with 10 GB new data (~2 600 blocks) | ~7 800 events, ~2 MB | ~360 events, ~29 KB, plus ~440 KB of map delta |
| location view in memory | ~4.3 M chunk records with string keys and per-storage maps, ≥ 800 B each: ≥ 3 GB | 187 k pack records × ~210 B (63 B record + ~1.8 × 42 B places, ×1.5 for the hash map): ~40 MB |
| location view stored | ~2 GB JSON + zstd | ~26 MB |
| checkpoint of one busy device | grows with blocks | ≤ the view, ~26 MB |
| block places (pack indexes vs. maps) | 4.3 M × 3 × 120 B: ~1.5 GB | 8.6 M places (one hot, one cold per block) × 85 B: ~730 MB, spread over writers and folders; held on disk, not in memory |

The view is O(packs × storages) and independent of the number of blocks; the map is O(blocks) but only on disk and only at devices holding the folder key.

## 5. Signed records

Every object a device publishes, except packs, is a SignedRecord:

```text
SignedRecord (postcard, after the 4 magic bytes "VSR3") {
  format: u16 = 3, kind: u8, vault: [16], scope: [16] (zeros = vault-wide), device: [16],
  seq: u64, part: u16, parts: u16, key_id: String, body_hash: [32], sig_alg: u8 (1 = ed25519+ml-dsa-65),
  sig: Vec<u8>,   // 64 + 3309 bytes, over aad("record-signature", [kind, vault, scope, device, seq, part, parts, key_id, body_hash])
  body: Vec<u8>,  // nonce || AEAD ciphertext || tag; plaintext = zstd(postcard(body struct))
}
body AAD = aad(<kind name>, [vault, scope, device, seq u64, part u16, parts u16, key_id])
body_hash = BLAKE3(body)
```

Storage name: `<stream prefix>/<seq 16 digits>-<part 4 digits>.rec`; MAX_PART_BODY = 32 MiB, MAX_PARTS = 1024, read limit per part 33 MiB. Kinds and their streams:

| Code | Kind | Stream prefix | key_id | Announced in a batch |
| --- | --- | --- | --- | --- |
| 1 | `manifest` | `manifests/<folder>/<device>/` | `meta:` | yes |
| 2 | `block-map` | `maps/<folder>/<device>/` | `meta:` | yes |
| 3 | `trash` | `trash/<folder>/<device>/` | `meta:` | yes |
| 4 | `snapshot` | `snapshots/<backup>/<device>/` | `meta:` | yes |
| 5 | `peer` | `vault/peers/<device>/` | `registry@` | no (newest seq wins) |
| 6 | `epoch` | `vault/epochs/` (seq = vault epoch, device = issuer) | `epoch@` | no |
| 7 | `share-epoch` (folder epoch) | `vault/folder-epochs/<folder>/` (seq = folder epoch) | `meta:` of the new epoch | no |
| 8 | `grant` | `vault/grants/<folder or vault>/<epoch 10>/<recipient>/<issuer>/` | `kem:` | no |
| 9 | `request` | `vault/requests/<folder>/<device>/` | `registry@` | no |
| 10 | `revocation` | `vault/revocations/<device>/<issuer>/` | `registry@0` | no |
| 11 | `policy` | `vault/policy/<device>/` | `registry@` | no |
| 12 | `placement` | `vault/placement/<folder>/<device>/` | `registry@` | no |
| 13 | `checkpoint` | `ledger/<device>/checkpoint-` | `ledger@` (full devices only) | no (it is ledger) |
| 14 | `batch` | `ledger/<device>/` | `ledger@` / `share-ledger:` / `replica` | no (it is ledger) |
| 15 | `folder` | `vault/folders/<folder>/<device>/` | `registry@` | no |
| 16 | `device` | `vault/devices/<device>/` | `registry@` | no |
| 17 | `escrow` | `vault/escrow/<folder>/<epoch 10>/<device>/` | `recovery` | no |
| 18 | `settings` (trash and history days, trash storage) | `vault/settings/<device>/` | `registry@` | no |
| 19 | `storage-names` | `vault/storage-names/<device>/` | `registry@` | no |
| 20 | `access`, 21 `notes`, 22 `thumbs` | `access/`, `notes/`, `thumbs/` + `<folder>/<device>/` | `meta:` | no |

Records without announcement are "newest seq of the stream wins" (put-if-absent at seq; a writer keeps its own counter and starts after the highest it finds). Forward leases (section 70) stay plain JSON leases: they decide nothing a reader trusts.

**Acceptance rule** (one function, `record::accept`, for every kind): (1) the envelope parses, `format` is 3, `vault` is this vault, the storage name's prefix, device and seq equal the envelope's; (2) the signature verifies against the device's K6 public key from an accepted device record (or, for a member of a shared folder, from its member device record of that folder; for a `device` record, against the key it carries, whose BLAKE3 must be the device id); (3) the device's role allows `kind` in `scope` (section 9) at the epoch named by `key_id`; (4) the body opens under the key `key_id` names, with the AAD above; (5) for announced kinds, a batch of the same device that this device accepted carries `record_published` with the same (kind, scope, seq, parts, body_hash), and the body's own `prev` (deltas) equals the announced hash of seq − 1; (6) kind-specific checks (manifest checks of section 28, map limits of section 3). A record that fails (1), (2), (3) or (4) is junk: counted (`records_refused`, by kind), never applied, reported once. A record that passes (1)–(4) but has no announcement yet waits (at most MAX_AHEAD = 64 records per stream; more are dropped and fetched again later). A record whose announcement names another hash is refused and the writer is marked forked for that stream (`"record <kind> <seq> of <device> does not match what its batch announced"`). Removed devices' records count only up to the last announcement in their accepted batches (cut-off).

## 6. Folder membership, grants, requests, roles, removal, recovery

**Folder records** (`folder`, scope = folder): id, name, settings, `participants: Vec<{device, role: owner|editor|viewer, stamp}>`, `denied: Vec<{device, stamp}>`; no key. The creator's first record makes it the owner. Later records count only from owners; participants merge per device by the largest (Lamport, device) stamp, so two owners editing at once converge.

**Grants** (`grant`): `vault/grants/<folder>/<epoch>/<recipient>/<issuer>/<seq>-0000.rec`, key_id `kem:<recipient>`; body = hybrid KEM ciphertext to the recipient's K8, then AEAD under the KEM secret (AAD = aad("grant", [vault, folder, epoch, recipient, issuer])) of `{K9ₑ, K11, older: Vec<(epoch, K9)> (all earlier epochs the recipient should read), role}`. Accepted when the issuer is an owner of the folder at that epoch (folder records and folder epoch records). A device that holds a grant to itself holds the folder. Vault epochs use the same kind with scope = zeros and `{K3ₑ}` (section 21's vault grants).

**Requests** (`request`): a device that holds K3 but not a folder (joined with the vault words, or a new device of an organization) runs `varsto folder request <folder>`, which publishes `{device, name, kem_pub, role_wanted}` under the registry key. Every owner device lists pending requests (`varsto folder requests`, the Folders page); `varsto folder approve <folder> <device> [--role editor|viewer]` issues a grant, `varsto folder deny <folder> <device>` adds the device to `denied`. Approval is manual (S-020): the background service never approves, and an approval shows the requester's device name and the six-word fingerprint of its K6 + K8 public keys (the derivation of section 24, over these keys). Other people's devices ask out of band with the `vsr1` request code and fingerprint words of section 24; the owner answers with a grant to the code's KEM key and a folder record listing the member (the `vst2` token is gone: a member reads its grant from the storage it was given).

**Pairing** (`varsto pair offer --folders A,B`, or the list in the interface) sends the vault (K3ₑ) through SPAKE2 as today; the hello carries the joining device's K6 and K8 public keys and name, the offering device shows name and fingerprint and asks, and then issues grants for the folders the person ticked, before it reports success. Pairing is the only path that grants without a separate approval, and it is chosen by the person at the offering device. The joining device's K3 arrives sealed to its K8 in addition to the SPAKE2 key.

**Roles.** Owner: may grant, change roles, start folder epochs, write every folder kind. Editor: writes manifests, maps, trash, its folder-scoped batches; marks blocks dead. Viewer: reads; its manifests, maps, trash records and marks are refused by every reader (it holds K9 and could write them, so the refusal is by acceptance rule, not by key). Role changes are folder records by an owner.

**Removal.** Removing a participant (own device or member) starts a **folder epoch**: the owner makes a random K9ₑ₊₁, writes `vault/folder-epochs/<folder>/<e+1>` (put-if-absent at the number; signed; body under the new K10: issuer, `participants` that stay, `removed: [{device, ledger cut-off}]`), grants it to every participant that stays, escrows it (below), and writes from then on under it. Removing an own full device from the vault starts a vault epoch (section 21, unchanged except that its records are SignedRecords) and a folder epoch for every folder the device held a grant of. Re-encrypting old data is a separate, budgeted job (`varsto folder reencrypt`): new packs under K9ₑ₊₁, old ones dropped through the usual marks. Folder epochs by two owners at the same number: the rule of section 58 ("two epochs under one number") applies per folder.

**Recovery escrow.** Every folder epoch (and every Strongroom key the user opts in) is escrowed as `vault/escrow/<folder>/<epoch>/<device>/<seq>-0000.rec`, key_id `recovery`, body `{K9ₑ, K11}` under the escrow key `derive(K2, "folder-escrow", vault, K3₀)` with AAD aad("escrow", [vault, folder, epoch]), signed by the writer. Binding K3₀ into the escrow key keeps "the recovery words alone give nothing" true even for someone who can list the storage: escrow names show folder ids, and K2 alone would otherwise open them. Every full device holds K3₀ (a newer vault key opens the older ones through the epoch records). Writing needs K1 in memory: `folder add` and epoch rotation ask for the recovery words, or use the session copy entered at unlock with `--with-recovery-key`. Until the escrow exists, `varsto status` warns `"folder <name> has no recovery copy: run varsto recovery escrow <folder>"`. The recovery kit prints two word sets: the newest vault key K3ₑ (which opens K3₀ through the epoch records) and K1. `varsto join --recovery-words` plus the vault words rebuilds every folder; the vault words alone give the registry and the pack-level ledger, no content; the recovery words alone give nothing. A vault epoch (removing a device) makes the kit's vault words stale, as today: `join` refuses them and the user prints a new kit; K1 does not change, so the escrows stay valid.

## 7. Manifests, trash, history, snapshots as base + delta

**Manifests.** Stream `manifests/<folder>/<device>/`, kind `manifest`, announced. Body:

```text
Manifest { folder, device, seq, lamport, created_utc, base: u64, prev: [32],
           files: Vec<FileState>,      // base: the device's whole view; delta: entries changed since seq-1
           removed: Vec<String> }      // delta only: paths that left the view (normally never: deletions are FileStates with deleted = true)
```

`FileState` keeps its format-2 fields (path, version vector, deleted, size, mtime, content hash, chunks as (chunk id, object, size, epoch), modified_by, modified_clock, meta, chunking) and gains `held: bool` (section 4). Encoding is postcard + zstd with device ids in version vectors interned through a per-record table `devices: Vec<[16]>`. A base is written at the 64th delta after the previous base, or when the deltas since the base reach 1/4 of its bytes. Readers reconstruct a writer's view as base + deltas in order (`prev` checked) and merge it with the section 7 rules, unchanged: applying only the changed entries of a delta gives the same result as merging the full view, because unchanged entries were merged before. Pruning: a writer deletes records below its newest base once every reader of the folder has acknowledged the batch that announced that base (section 25's rule with "base" in place of "manifest").

Reservation (manifest base size): with 1 M files a base is ~350 MB (paths compress, the ~4.3 hashes per file do not), written to every hot metadata storage. "A base every 64 publishes" then costs about 5.5 MB per publish averaged, which for a service that publishes every few minutes on a busy folder is several GB a day per device. Implemented as decided (count or size, whichever first); the suggested alternative is the count rule "64 deltas and at least 1/16 of the base's bytes", which keeps chains short for small folders and stops large ones from rewriting their base for a handful of changes.

**Trash and history.** Stream `trash/<folder>/<device>/`, kind `trash`, announced. Body: `{folder, device, seq, lamport, base, prev, entries: Vec<TrashEntry>, removals: Vec<Removal>, versions: Vec<HistoryEntry>, forget: Vec<[u8;16] entry id>}`. Base = the device's whole record (what the format-2 record held); delta = entries, removals and versions added since seq − 1 plus ids the writer forgot (the 7-days-past-expiry rule). Base every 64 deltas or at 1/4 of the base's bytes; pruning as manifests. The union-and-removal semantics of sections 43 and 50 are unchanged; ids recompute as before. `<utc>`-named records disappear.

**Snapshots.** Stream `snapshots/<backup>/<device>/`, kind `snapshot`, announced, never changed once written. A snapshot is either a base (full listing) or a **differential** against a base (`base` = that base's seq): every entry that differs from the base and every path removed since it. Differential, not incremental, so expiring any snapshot never breaks another: a base is kept (body retained, hidden from listings) while any unexpired snapshot names it. A new base is taken when the differential would exceed 1/4 of the base or 32 snapshots name the current base. `snapshot_taken` carries times and sizes; `record_published` carries the hash a restore checks.

## 8. Peers and transport

**Peer records** (`peer`, `vault/peers/<device>/`, newest seq wins): `{device, name, port, lan_addrs, public_addrs, udp_public, udp_local, mapped_tcp, mapped_udp, cert_sha256, nat, relay_via, reachable, heads, pushed}` where `heads: Vec<([16] device, u64 seq, [32] hash)>` is the newest batch this device holds of every full device (≤ 256 entries) and `pushed: Vec<([16] storage identity, u64 seq)>` its own newest batch confirmed on each metadata storage (≤ 64 entries; identity from `vault/storage-id.json`). The QUIC server admits only certificates named by an accepted peer record of a trusted full device.

**No plaintext transport.** Plain HTTP over TCP is gone: TCP connections use TLS 1.3 with the same pinned self-signed certificates and client authentication as QUIC (ALPN `varsto-p2p/3`). LAN beacons are signed (Ed25519 part of K6 only, 64 bytes, for size; a beacon only suggests an address that the pinned handshake then checks) and carry a sequence number; `VARSTO3 <tag> <device> <port> <seq> <sig>`.

**Request token.** `X-Varsto-Auth: <device>:<responder>:<unix>:<nonce 16 hex>:<mac>` with `mac = keyed_hash(exporter, aad("p2p-token", [device, responder, unix, nonce, path]))`, `exporter` = TLS exporter of the connection (label `EXPORTER-varsto-p2p-token`, 32 bytes). The responder requires `device` = the device of the presented client certificate, `responder` = itself, |unix − now| ≤ 300 s, an unseen nonce within that window (≤ 65 536 kept). Reason: no shared vault secret is needed, so a token cannot be made by anyone who merely holds K3 without the device's certificate, and it cannot be replayed on another connection.

**Pairing** as section 6; rendezvous discovery uses `keyed_hash("pair-rendezvous", code)` as the record name instead of the code's digits.

**Head exchange.** On every new P2P connection between full devices, and at most every 10 minutes on a kept one, the client sends `HEADS\n` with its `heads` list (postcard, ≤ 256 entries); the responder answers with, for each device where it holds a newer batch, that batch's SignedRecord envelope without body (`body` empty, 3.5 KB with the signature), at most 64 envelopes and 512 KiB per answer, and with its own list. An envelope verifies against the batch signer's K6 (the signature covers `body_hash`, so the body is not needed): it **proves** the signer wrote that batch. The receiver records `proved[device] = (seq, hash, peer, utc)` in `ledger/watch.json` and fetches the missing batches from the peer (`GET /p2p/ledger/<device>/<seq>`, the full record, checked as from a storage), so a withheld batch reaches it anyway; batches it learns this way it does not push to storages (only their writers push them).

**Rollback warning.** Storage S is **expected** to hold batch n of device D when D's accepted peer record lists S's identity in `pushed` with seq ≥ n, or this device pushed it there itself. After every pull, for each (D, S) where S is expected to hold n but its listing after this device's head shows less, and a proof of n (a verified envelope from a peer, D's own peer record, or a full device's `seen`) is older than the pull: `ledger_health.rollback` gains `{storage, device, shown, proved, source}`; after two such pulls in a row the warning is `"storage <S> may be withholding or rolled back: it shows ledger batches of <D> up to <shown>, but <source> proved <proved>"`, shown by `varsto status`, `varsto ledger status`, the Help page and a notification (English, Finnish, Swedish). Limits: only full devices' heads within their cut-off; a storage D never confirmed is not judged; a storage that is unreachable is not judged; the warning clears when S shows the batch or D's peer record stops listing S; a warning per (S, D) at most once a day as a notification.

## 9. Authorization matrix

| Writer | Kinds it may write | Events that count | Scope |
| --- | --- | --- | --- |
| full device, folder owner | every kind | every event | its folders and the vault |
| full device, folder editor | manifest, block-map, trash, access, notes, thumbs; batch | as full device, folder events for that folder | that folder |
| full device, folder viewer | access; batch | `pack_verified`; its own `record_published` of `access` | that folder |
| full device, no grant for the folder (K3 only) | request, device, peer, policy, placement (of folders it holds), settings, storage-names; batch | `pack_stored` (copies of whole packs), `pack_verified`, `pack_dropped`, `storage_retired`, `device_enrolled` | vault |
| member device (another person's), editor | manifest, block-map, trash of that folder; folder-scoped batch | `pack_stored`, `pack_verified`, `pack_dropped` (its packs), `record_published` of those kinds, for that folder | that folder |
| member device, viewer | folder-scoped batch | `pack_verified` for that folder | that folder |
| replica | replica batch | `pack_stored` and `pack_verified` with zero folder | none |
| storage, peer, anyone else | nothing | nothing: every object must verify | none |

A member never writes registry kinds, epochs, revocations, `storage_retired`, snapshots, policy, placement or settings. Only owners write folder records, folder epochs and grants of their folders. Only full devices of the vault write vault epochs, revocations and checkpoints.

## 10. What each party can learn

- **The storage**: vault id; device ids and how often each writes (record names carry device and sequence, never time); folder ids and the number of writer streams per folder; pack sizes as size classes only, how many packs and when they appear and go; record sizes (manifests, maps, trash: roughly proportional to file counts and changes, not padded: Reservation below); that a folder has grants to KEM keys of other vaults' devices. Not: file names, file sizes, file counts per pack, where a block starts or ends, chunk ids, object names of blocks (only pack ids), whether a known file is present.
- **A holder of K3 only**: everything the storage learns, plus device names, folder names, settings and participants, which storage holds which pack, bytes per folder, record announcements (kind, seq, size) and peer addresses. Never chunk ids, object names, block places or contents.
- **A member of a shared folder**: everything of that folder (K10): file names, contents, maps; the folder's places in packs; nothing of other folders (their packs are listed on the storage, nothing more).
- **A replica**: pack ids, sizes, its own claims; it copies packs whole and needs no folder key.
- **A peer** (a full device of the vault): what any full device knows; over the wire an eavesdropper learns nothing (TLS 1.3).

Reservation (record sizes): manifests, maps and trash records are compressed but not padded, so their sizes track the number of files and blocks per folder and per change. Padding them to size classes would cost little; it is outside the lead's change 4 and not specified here.

## 11. Migration

None. Format 3 reads nothing older. `vault/meta.json` says `"format_version": 3`. A format-3 build refuses a format-2 vault before reading anything else: `"this vault uses storage format 2, which this version of Varsto (3) does not read (0.0.1-alpha.15 wrote format 2). Recreate the vault: run varsto reset --yes on this device, then varsto init, and sync your files into the new vault"` (`format_mismatch`, text updated for the release that ships format 3). 0.0.1-alpha.15 refuses a format-3 vault with its own text `"... storage format 3, which is newer than this version of Varsto reads (2). Update Varsto on this device"`. `varsto reset --yes` removes the device's vault directory (not the user's folders); `varsto init` creates a format-3 vault: K3₀, K1 (shown as the recovery kit), the device's K6/K8, the device record, epoch-0 records, and an escrow for every folder added. Storages of a format-2 vault are not cleaned: `varsto init` on a storage that holds a format-2 `vault/meta.json` stops with `"storage <name> holds a vault of format 2; use another bucket or directory, or delete it first"`. `format-versions.md` gets the row for format 3 (alpha.15 binary as the reader of format 2, rule 3).

Supersedes in `alpha-0-format.md`: sections 3 and 4 (keys, AAD), 5 (layout), 6 (events, batch body), 7 (manifests as full views), 15 (token and plaintext HTTP), 21 (folder keys from vault epochs), 22 (checkpoint body), 24 (share tokens, share keys, `SHARE_EPOCH_BASE`), 25 (manifest pruning unit), 30 and 62 (pack index, tombstones, per-block claims), 43 and 50 (`<utc>` trash records), 58 (limits on unsigned key ids and manifests).

## 12. Tests that define "done"

Each fails on format 2 (or on the pre-change code of its work package) and passes after:

1. `record::tests`: a relabelled `key_id`, a moved record (other prefix, seq or device), a body swapped between two records and an unannounced manifest are refused; a record ahead of its batch waits and applies when the batch arrives; MAX_AHEAD drops the excess; a part missing or reordered fails the announced hash. Fuzz targets for SignedRecord, Batch, BlockMap, Manifest, Trash, Snapshot and peer bodies.
2. One integration test per writer class (viewer, removed member, replica, K3-only device, storage that rewrites, replays or withholds objects): it tries every kind and every event and asserts `records_refused` / `events_refused` and unchanged folder contents on every full device.
3. `packs::tests`: every pack is exactly a size class; a pack with a wrong length is refused; padding differs between two packs of the same members; first-fit fill ≥ 98 % for a 1 GiB push of mixed blocks; an import of 1 000 small files writes packs across files.
4. Known-file test: the same 10 MiB file pushed to two folders and imported once gives no pack whose size or id reveals it (sizes are classes; ids differ).
5. `ledger::tests::view_is_pack_level`: 100 000 synthetic blocks in 1 500 packs give a view whose size is within 10 % of a view of 1 500 packs with one block each; `cached_view_equals_full_replay` over random orders with pack events, drops and retirements.
6. Map: a fresh device reads base + deltas and fetches every block; a writer skips a block held on all its targets and writes it for a target that lacks it; a dead-marked block is written again, not reused.
7. The race (section 3): device B marks dead, device D re-adds the same content before pulling; with any interleaving of pulls, pushes and upkeeps (property test over 4 devices and random schedules) no referenced block is ever collected, and every unreferenced block is collected within three upkeep rounds once everyone syncs.
8. GC: a hot pack > 50 % dead is rewritten and a device that joins later reads the moved block; a cold pack is never rewritten; compaction merges small packs; an orphan pack (crash before the batch) goes after 7 days.
9. Repair: a flipped byte in a member is found by `pack_verified` failing, the pack's good members are rewritten, the corrupt place gets `lost`, the file reads from the new pack; a pack lost on one storage is copied whole from another without folder keys.
10. Membership: a device joined with the vault words sees folder names and pack-level ledger, opens no content, its request appears on both owner devices, approval on one is enough, the service never approves; pairing with `--folders A` grants A only; a viewer's manifest is refused.
11. Recovery: losing every device, vault words + recovery words restore every folder; vault words alone restore none; a folder without escrow is warned about.
12. Manifests: base + 63 deltas, then a base; a reader that joins at any point converges to the same view as a reader that saw every record; pruning waits for every reader; `held` flags drive transferrer emptying and the safety indicator like `chunk_on_device` did (port of their existing tests).
13. Snapshots: expiring a base's differentials in any order never breaks a restore of the others; the base goes with its last differential.
14. Peers: a token from another connection, with another responder, or replayed is refused; plaintext HTTP is refused; head exchange fetches a batch every storage withholds; the rollback warning appears after two pulls when a storage the writer confirmed shows an older head, and not for a storage the writer never used.
15. Lab: every existing scenario passes on format 3 (full coverage, not only the changed areas), plus new scenarios `format3-scale` (1 M files / 1 TB synthetic: view size, map size, pull with nothing new, join time measured and written into section 4 in place of the estimates), `format3-gc-race`, `format3-withhold-rollback`, `format3-join-approve`, `format3-recovery`, `format2-refused`.

## 13. Implementation plan

Work packages, each a branch and a PR against main behind a `format3` cargo feature until WP12 flips it (the format-2 code path stays the default until then, so main always builds and its lab passes). Sizes are engineer-days.

| WP | Content | Modules | Depends on | Size | Acceptance |
| --- | --- | --- | --- | --- | --- |
| 1 | SignedRecord envelope, kinds, parts, key_id table, `record::accept` skeleton, fuzz targets | new `record.rs` (replaces `record_shim.rs`), `crypto.rs`, `storage.rs` read limits | none | 3 | tests 1 (envelope parts) |
| 2 | Size classes, padding, target-set pack builder, first-fit fill, imports across files | `packs.rs`, `pack.rs`, `engine/imports.rs`, `storage.rs` (`MAX_PACK`) | none | 3 | tests 3, 4 |
| 3 | Binary batch body, tagged events, pack events, `record_published`, pack-level view, checkpoints, scopes | `ledger.rs`, `ledger/`, `engine/ledger_upkeep.rs`, `engine/view.rs` | 1 | 4 | test 5; existing ledger tests ported |
| 4 | Folder block map: body, writer path in push, local table, reader lookup, base/delta, pruning | new `blockmap.rs`, `engine.rs` push and fetch, `engine/fetch.rs` | 1, 2, 3 | 4 | test 6 |
| 5 | Marks, settle rule, collection, rewrite, compaction, orphans, per-pack verification and repair | `engine/pack_upkeep.rs`, `engine/trash.rs`, `engine/repair.rs`, `engine/verify.rs`, `autoverify.rs`, `parverify.rs` | 4 | 4 | tests 7, 8, 9 |
| 6 | Manifests base + delta, `held` flag, consumers of `chunk_on_device` | `manifest.rs`, `engine/manifest_upkeep.rs`, `engine.rs` (carrier, `missing_on`), `engine/protection.rs`, `engine/where_data.rs`, `engine/forward.rs`, `engine/block_cache.rs` | 1, 3 | 4 | test 12 |
| 7 | Trash, history and snapshots as base + delta; differential snapshots | `engine/trash.rs`, `engine/history.rs`, `snapshot.rs`, `engine/backups.rs` | 6 | 3 | test 13; trash/history/backups suites |
| 8a | Folder records, grants, folder epochs, removal, escrow, acceptance roles | `share.rs`, `engine/share_ops.rs`, `engine/share_roles.rs`, `engine/membership.rs`, `recovery.rs`, `vault.rs` | 1 | 4 | tests 2 (member, viewer), 11 |
| 8b | Requests, approve/deny, pairing folder selection, CLI and interface (fi, sv strings), status warnings | `pair.rs`, `varsto-cli` commands and UI, `i18n/fi.json`, `sv.json` | 8a | 3 | test 10 |
| 9 | Signed peer records, TLS-only TCP, exporter tokens, signed beacons, head exchange, batch fetch, rollback warning | `p2p.rs`, `p2p/quic.rs`, `engine/ledger_upkeep.rs` (watch), service | 1, 3 | 4 | test 14 |
| 10a | Replicas, pools, transferrers, staged moves, drains, data moves, placement and quotas on pack counts | `replica.rs`, `pool.rs`, `staged_move.rs`, `engine/staged_moves.rs`, `engine/drain.rs`, `engine/data_moves.rs`, `placement.rs`, `engine/quotas.rs` | 3, 4 | 4 | their suites ported; test 2 (replica) |
| 10b | fsck, ledger rebuild from maps, scrub, disk insert tidy | `engine.rs` fsck, `engine/ledger_recovery.rs`, `scrub.rs`, `engine/scrub.rs`, `engine/disk_insert.rs` | 4, 5 | 3 | their suites ported |
| 11 | Spec text: new numbered sections in `alpha-0-format.md` for what each WP built, `format-versions.md` row | `docs/spec/` | each WP | 1 per WP | review |
| 12 | Integration: `FORMAT_VERSION` = 3, remove the feature flag and format-2 paths, `format_mismatch`, lab scenarios, scale measurements | `lib.rs`, every crate, `lab/` | all | 4 | test 15; full workspace check, clippy, fmt |

**Parallel split.** Start at once: agent A on WP1 then WP8a, WP8b; agent B on WP2 then WP3. Once WP1 and WP3's event types are merged (interfaces first: the event enum and `PackRecord` can be agreed in a day): agent C on WP4 then WP5; agent D on WP6 then WP7; agent E on WP9. After WP4: agent F on WP10a then WP10b. The integrator owns WP12 and keeps the lab running against the feature build from the first merged WP. Critical path: WP1 → WP3 → WP4 → WP5 → WP12, about 19 days.

**Risky parts.** (1) WP5's settle rule: its correctness depends on every writer acknowledging and on "pull before push" holding in every code path that skips writing a block (forwarding, data moves, imports, the block cache): audit each, and keep the property test of test 7 as the gate. (2) WP3 touches every consumer of `ChunkRecord` (`engine.rs` alone uses it in dozens of places): port behind a "copies of a block" helper first, then switch its source. (3) WP4's local map table at 10 M places: crash safety of the rebuild (write a new table beside the old, rename), and lookups by chunk id during a push of millions of blocks. (4) WP6: delta reconstruction must give byte-identical merged views; compare against full-view merging in a property test. (5) WP9 changes the transport on Android and iOS, which cannot be run locally: TLS over TCP and the exporter API must be checked in CI on those shells and by hand on devices. (6) Members' folder-scoped `seen` (WP3/WP5): a member that never syncs again blocks collection in that folder until it is removed, as a silent full device blocks pruning today; `varsto status` must say which device is waited for.
