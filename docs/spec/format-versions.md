# Storage format versions

## Purpose

During alpha development, storage formats may change without migration paths. Once a format version is released, that version stays readable. This table tracks which released versions of Varsto can read each storage format, and whether standalone reader tools are available for data recovery.

## Format versions

| Format version | First release | Releases that read it | Standalone reader tool | Archived tag |
|---|---|---|---|---|
| 0 (alpha-0) | 0.0.1-alpha.0 | 0.0.1-alpha.0 to 0.0.1-alpha.3 (no `v0.0.1-alpha.3` tag exists; the last format-0 reader tag is `v0.0.1-alpha.2`) | none (`varsto pull` and `varsto fsck` of those versions) | see the format version 1 note below |
| 1 (compression, alpha-0-format.md section 16) | 0.0.1-alpha.4 | 0.0.1-alpha.4 and later, including 0.0.1-alpha.13 | none yet (`varsto pull` and `varsto fsck` of the same version) | every tag from `v0.0.1-alpha.4` on |
| 2 (blocks, packs and keyed chunker, alpha-0-format.md section 62) | 0.0.1-alpha.15 | 0.0.1-alpha.15 and later. Vaults of format 1 (0.0.1-alpha.14 and earlier) are not read: alpha.15 refuses them and says to recreate the vault | none yet (`varsto pull` and `varsto fsck` of the same version) | `v0.0.1-alpha.15` |
| 3 (pack-level ledger, folder block maps, signed records, alpha-0-format.md section 77) | the daily channel (the first daily build after the format 3 switch was merged, 2026-10-19); no tagged release yet | every daily build from the switch on, and the first release after it. Read by nothing older: 0.0.1-alpha.15 and earlier refuse a format 3 vault ("newer than this version of Varsto reads"). Vaults of format 2 and earlier are not read by format 3 builds: they refuse them and say to recreate the vault | none yet (`varsto pull` and `varsto fsck` of the same version) | none yet: the tag of the first release that carries format 3 will be its archived tag |

## Folder creation time in format 3 folder records (format version 3 unchanged)

Alpha-0-format.md section 77.23. The creator's first `folder` record carries the setting `created_utc` (Unix seconds, decimal) in its opaque `settings` map; readers use it to decide which of two folders created under one name keeps the name. No field of the record changes; a record without the setting reads as created at 0. Format 3 is not released yet, so no released reader is affected.

## Format version 2 (0.0.1-alpha.15)

`FORMAT_VERSION` is 2. There is no migration from format 1: block objects of their own (`chunks/`) are not read, so an alpha.14 vault opens without its data. Checked in the lab (`upgrade-from-alpha-14`) with the format number left at 1: `status` worked and `fsck --verify` reported every block of the vault missing. With the bump an alpha.15 build refuses a format 1 vault when it opens it or joins through its storage and says to recreate it (`varsto reset --yes`, `varsto init`, then sync the files into the new vault). Alpha.14 refuses a format 2 vault with "vault format version 2 is not readable by this version (1)". Release rule 3 (a reader for the previous format) is met by the alpha.14 binary, which stays downloadable and is the tool to read an alpha.14 vault.

## Ledger heads between peers after 0.0.1-alpha.15 (format version 2 unchanged)

Alpha-0-format.md section 74. A peer-to-peer message (`/p2p/heads`, the head statement on `/p2p/changed`), one optional field `head` in the rendezvous record `vault/peers/<device>.enc` and the device-local file `ledger/heads-seen.json`. Batches, checkpoints and the storage layout are unchanged. Older versions answer `404` to the new path, skip the new record field and never read the file, so devices of different versions work together; only the newer ones compare heads. (Superseded by storage format 3: the heads travel in the signed peer records and the head exchange, see "Format 3 peers and transport" above.)

## Format version 3 (the daily channel from 2026-10-19; the first release after it)

`FORMAT_VERSION` is 3. Alpha-0-format.md section 77 (and `format-3-design.md`) describes it: packs of fixed size classes (256 KiB to 64 MiB, 256 MiB on cold storages, padding from the system's random source), a pack-level ledger (the ledger claims packs, not blocks), a signed block map per folder and writer, every published object except packs as a SignedRecord with a signed key id, folder keys only as approved grants with recovery escrow (a second set of 24 recovery words), manifests, trash and snapshots as base + delta records, and TLS-only peer transport with exporter-bound tokens. A storage holds `packs/<xx>/<id>`, signed `*.rec` records under `ledger/`, `manifests/`, `maps/`, `trash/`, `snapshots/` and `vault/...`, and `vault/meta.json` with `"format_version": 3`; there are no `chunks/` objects, pack indexes or tombstone lists.

There is no migration. A format 3 build refuses a vault of format 2 or earlier when it opens it, joins through its storage, or adds its storage to a new vault, with: "this vault uses storage format 2, which this version of Varsto (3) does not read (0.0.1-alpha.15 wrote format 2). Recreate the vault: run `varsto reset --yes` on this device, then `varsto init`, and sync your files into the new vault" (and "storage <name> holds a vault of format 2; use another bucket or directory, or delete it first"). 0.0.1-alpha.15 refuses a format 3 vault with "this vault uses storage format 3, which is newer than this version of Varsto reads (2). Update Varsto on this device". Release rule 3 is met by the alpha.15 binary (tag `v0.0.1-alpha.15`), which stays downloadable and is the tool to read a format 2 vault. The lab checks all of this (`upgrade-from-alpha-15`). Release rule 4: this row has no release number yet; the first tagged release that carries format 3 fills it in.

What changes for people: `varsto folder add` asks for the recovery words (or `VARSTO_RECOVERY_WORDS`, or the copy `varsto unlock --with-recovery-key` keeps in the service) to make the folder's recovery copy; a device that joins with the vault words holds no folder until it asks (`varsto folder request`) and an owner approves (`varsto folder approve`) or a pairing offer names the folders (`pair offer --folders`); pairing shows six words on both devices; removing a device or a member starts a folder epoch; `varsto status` warns about a folder without a recovery copy and about a storage that shows a rolled-back ledger.

## Format 3 peers and transport (storage format 3)

Alpha-0-format.md section 75. Format-3 peer records (`vault/peers/<device>/<seq>-0000.rec`, SignedRecords), TLS-only TCP, connection-bound tokens, signed beacons, the format-3 pairing hello and the head exchange with proofs (`ledger/proofs.json`). They replace the format-2 rendezvous records, plain HTTP and keyed-hash tokens; there is no plaintext transport any more.

## Format 3 folder membership for people (storage format 3)

Alpha-0-format.md sections 76 and 77.20. Commands, local API routes, event-stream events (`folder.request`, `folder.changed`, `pair.ask`) and a pairing question for the format-3 membership records of section 6 of the design (`request`, `grant`, `folder`, `share-epoch` and `escrow` SignedRecords). They are the only way a device gets a folder key.

## Release rules

1. Tag every alpha release (`v0.0.1-alpha.N`) with the source commit and binaries. Tags `v0.0.1-alpha.3` and `v0.0.1-alpha.9` do not exist: those releases were folded into the next tag (`v0.0.1-alpha.4` and `v0.0.1-alpha.10`).
2. Archive binaries and source on each release.
3. Before publishing a new storage format version, ensure the previous version has a reader tool (built-in or standalone).
4. Update this table before publishing each storage format version, with the release number and reader status.
5. Once the product launches (first public release), every subsequent format change requires forward compatibility for at least one previous version.

## YouTube jobs (alpha-0-format.md section 80; storage format unchanged)

The import book (section 42, sealed in `vault/imports/<folder>/<device>/<utc>.enc`) gets the optional field `youtube` (video id to the paths in the folder, left out when empty; books merge it by union), a new `kind` `youtube` with content ids `youtube:<video id>:<suffix>` and identity `youtube:<canonical address>`, and books with an empty `kind` that hold only that index (`varsto import youtube-scan` of a folder). Device-local only: `state/youtube/<job id>.json`, `<job id>.lock` and `known.json`. No ledger event or storage object changes. Earlier builds ignore the field; they list a `youtube` book in `varsto import status` like any other and an index-only book with an empty kind.

## The mailbox for offline pool disks (alpha-0-format.md section 78; storage format unchanged)

New objects `vault/mailbox/<device>/<utc>.enc` (each device's list of staged objects, sealed under the device registry key; the writer deletes its older lists) and `vault/mailbox-leases/<slot>.json` (plain JSON leases as in section 70), the device-local `outbox/` directory (staged ciphertext objects, never a storage), `state/mailbox.json`, `state/mailbox.lock` and a `mailbox` block in `config.json`. Additive fields `chunks_in_transit` and `bytes_in_transit` in policy reports, `waiting_source_*` in move reports and the `source` kind of a move job's `waiting`. No new ledger event: delivered copies are `chunk_stored` claims (and, for move jobs, the `chunk_verified` and `chunk_dropped` events of section 59) as before. Earlier versions ignore the lists and leases, never stage, and read the claims as usual. (Storage format 3: the mailbox stages and delivers whole packs, and a device's list is its signed `mailbox` record, `vault/mailbox/<device>/<seq>-0000.rec`; the leases stay plain JSON. Alpha-0-format.md section 77.21.)

## Daily update channel after 0.0.1-alpha.13 (format version 1 unchanged)

Device-local files only (alpha-0-format.md section 67): `update-state-daily.json` and `update-channel.json` in the device directory. Earlier versions ignore them. The download site gains `daily/latest/SHA256SUMS.sig`, signed with a separate daily key.

## Forwarding (alpha-0-format.md section 70; storage format unchanged)

New objects `vault/forward-leases/<folder>/<slot>.json` (plain JSON leases, deleted by their holder or once they lapse), a device-local `forward` block in `config.json` and `state/forward.json`. No new ledger event: forwarded copies are `chunk_stored` claims as before. Earlier versions ignore the leases (they never forward, so they never write the same blocks twice through forwarding) and read the claims as usual.

## Service, transport and storage hardening after 0.0.1-alpha.13 (format version 1 unchanged)

Additive fields and local files only (alpha-0-format.md section 60): `check_hex` in the `strongroom` block of a folder record, `mac_hex` in a disk pool's `.varsto-disk.json`, and the device-local files `mcp-keys-used.json` and `update-state.json`. Earlier versions ignore the fields and read the same records. Three things need a hand: a Strongroom enrolled before this change has no key check (key-by-hand operations refuse it) and was enrolled without the PIN prompt, which changes the secret the security key derives, so enrol it again; a disk marker without a MAC is added one when the disk is attached, and a copy of a marker is not adopted without `varsto disk add`; and an updater needs `manifest.json.minisig` next to `manifest.json` on the download site.

## Packs in 0.0.1-alpha.12 (format version 1 unchanged)

Small block objects are stored in packs (`packs/`; alpha-0-format.md section 30). Earlier versions do not read packs: a device on 0.0.1-alpha.11 or earlier misses every block another device packed. Update every device.

## Block sizes in 0.0.1-alpha.11 (format version 1 unchanged)

Blocks are cut by file size (up to 16 MiB; alpha-0-format.md section 29). Objects, records and batches are unchanged and older readers read them, but no compatibility with the single set of block sizes of earlier versions is kept: a device on an older version cuts large files differently and cannot re-upload their blocks from its own copy, so update every device.

## Ledger events in 0.0.1-alpha.9 (format version 1 unchanged)

A new ledger event, `chunk_dropped` (alpha-0-format.md section 23), records that a block was removed from a storage on purpose. Versions 0.0.1-alpha.8 and earlier reject a batch that holds an event type they do not know, so once any device moves data their pull fails: update every device first. From 0.0.1-alpha.9 on, unknown event types are read and ignored, so later event types do not break older readers. Objects, records and batch envelopes are unchanged; the local cached view moves to format 3 and is rebuilt once.

## Format version 1 (0.0.1-alpha.4)

Chunk payloads are packed before encryption: one method byte (`0` raw, `1` zstd level 12) followed by the data; compression is used only when it saves at least 5 %. Objects written by format 0 have no method byte and are not readable by format 1 readers; vaults created with format 0 are refused with a clear error. Readers: 0.0.1-alpha.4 and later. Archived tag of the last format-0 reader: `v0.0.1-alpha.2` (there is no `v0.0.1-alpha.3` tag).
