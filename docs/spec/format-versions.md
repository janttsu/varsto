# Storage format versions

## Purpose

During alpha development, storage formats may change without migration paths. Once a format version is released, that version stays readable. This table tracks which released versions of Varsto can read each storage format, and whether standalone reader tools are available for data recovery.

## Format versions

| Format version | First release | Releases that read it | Standalone reader tool | Archived tag |
|---|---|---|---|---|
| 0 (alpha-0) | 0.0.1-alpha.0 | 0.0.1-alpha.0 to 0.0.1-alpha.3 (no `v0.0.1-alpha.3` tag exists; the last format-0 reader tag is `v0.0.1-alpha.2`) | none (`varsto pull` and `varsto fsck` of those versions) | see the format version 1 note below |
| 1 (compression, alpha-0-format.md section 16) | 0.0.1-alpha.4 | 0.0.1-alpha.4 and later, including 0.0.1-alpha.13 | none yet (`varsto pull` and `varsto fsck` of the same version) | every tag from `v0.0.1-alpha.4` on |
| 2 (blocks, packs and keyed chunker, alpha-0-format.md section 62) | 0.0.1-alpha.15 | 0.0.1-alpha.15 and later. Vaults of format 1 (0.0.1-alpha.14 and earlier) are not read: alpha.15 refuses them and says to recreate the vault | none yet (`varsto pull` and `varsto fsck` of the same version) | `v0.0.1-alpha.15` |
| 3 (pack-level ledger, folder block maps, signed records, alpha-0-format.md section 77) | not yet assigned | read by nothing older; vaults recreated; `FORMAT_VERSION` 3 set by the integration package. Not enabled: until then every build reads and writes format 2 | none yet | none yet |

## Format version 2 (0.0.1-alpha.15)

`FORMAT_VERSION` is 2. There is no migration from format 1: block objects of their own (`chunks/`) are not read, so an alpha.14 vault opens without its data. Checked in the lab (`upgrade-from-alpha-14`) with the format number left at 1: `status` worked and `fsck --verify` reported every block of the vault missing. With the bump an alpha.15 build refuses a format 1 vault when it opens it or joins through its storage and says to recreate it (`varsto reset --yes`, `varsto init`, then sync the files into the new vault). Alpha.14 refuses a format 2 vault with "vault format version 2 is not readable by this version (1)". Release rule 3 (a reader for the previous format) is met by the alpha.14 binary, which stays downloadable and is the tool to read an alpha.14 vault.

## Ledger heads between peers after 0.0.1-alpha.15 (format version 2 unchanged)

Alpha-0-format.md section 74. A peer-to-peer message (`/p2p/heads`, the head statement on `/p2p/changed`), one optional field `head` in the rendezvous record `vault/peers/<device>.enc` and the device-local file `ledger/heads-seen.json`. Batches, checkpoints and the storage layout are unchanged. Older versions answer `404` to the new path, skip the new record field and never read the file, so devices of different versions work together; only the newer ones compare heads.

## Format version 3, planned (format version 2 unchanged)

Alpha-0-format.md section 77 describes storage format 3: packs of fixed size classes with a pack-level ledger, a signed block map per folder and writer, every published object as a SignedRecord, folder keys only as approved grants with recovery escrow, manifests, trash and snapshots as base + delta records, and TLS-only peer transport with exporter-bound tokens. It is built behind the `format3` cargo feature (off by default) and nothing in a default build reads or writes it; the shipped format stays 2, `FORMAT_VERSION` stays 2 and the format-2 row above is the one that applies to every release, until the integration package sets it to 3. Format 3 reads nothing older (no migration): a format-3 build will refuse a format-2 vault and the alpha.15 binary, which stays downloadable, is the reader of format 2 (release rule 3). When format 3 ships, this table gets its release number and reader status (release rule 4).
## Format 3 peers and transport, behind the `format3` feature (format version 2 unchanged)

Alpha-0-format.md section 75. Builds with the `format3` feature carry the format-3 peer records (`vault/peers/<device>/<seq>-0000.rec`, SignedRecords), TLS-only TCP, connection-bound tokens, signed beacons, the format-3 pairing hello and the head exchange with proofs (`ledger/watch.json`), but nothing switches to them before the format does: every build still reads, writes and speaks format 2.

## Format 3 folder membership for people, behind the `format3` feature (format version 2 unchanged)

Alpha-0-format.md section 76. Commands, local API routes, event-stream events (`folder.request`, `folder.changed`, `pair.ask`) and a pairing question for the format-3 membership records of section 6 of the design. No stored format changes: builds with the feature write `request`, `grant`, `folder`, `share-epoch` and `escrow` SignedRecords only when a person runs those commands, and no build reads them for anything else before the format flips.

## Release rules

1. Tag every alpha release (`v0.0.1-alpha.N`) with the source commit and binaries. Tags `v0.0.1-alpha.3` and `v0.0.1-alpha.9` do not exist: those releases were folded into the next tag (`v0.0.1-alpha.4` and `v0.0.1-alpha.10`).
2. Archive binaries and source on each release.
3. Before publishing a new storage format version, ensure the previous version has a reader tool (built-in or standalone).
4. Update this table before publishing each storage format version, with the release number and reader status.
5. Once the product launches (first public release), every subsequent format change requires forward compatibility for at least one previous version.

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
