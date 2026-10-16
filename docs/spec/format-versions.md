# Storage format versions

## Purpose

During alpha development, storage formats may change without migration paths. Once a format version is released, that version stays readable. This table tracks which released versions of Varsto can read each storage format, and whether standalone reader tools are available for data recovery.

## Format versions

| Format version | First release | Releases that read it | Standalone reader tool | Archived tag |
|---|---|---|---|---|
| 0 (alpha-0) | 0.0.1-alpha.0 | 0.0.1-alpha.0 to 0.0.1-alpha.3 (no `v0.0.1-alpha.3` tag exists; the last format-0 reader tag is `v0.0.1-alpha.2`) | none (`varsto pull` and `varsto fsck` of those versions) | see the format version 1 note below |
| 1 (compression, alpha-0-format.md section 16) | 0.0.1-alpha.4 | 0.0.1-alpha.4 and later, including 0.0.1-alpha.13 | none yet (`varsto pull` and `varsto fsck` of the same version) | every tag from `v0.0.1-alpha.4` on |

## Release rules

1. Tag every alpha release (`v0.0.1-alpha.N`) with the source commit and binaries. Tags `v0.0.1-alpha.3` and `v0.0.1-alpha.9` do not exist: those releases were folded into the next tag (`v0.0.1-alpha.4` and `v0.0.1-alpha.10`).
2. Archive binaries and source on each release.
3. Before publishing a new storage format version, ensure the previous version has a reader tool (built-in or standalone).
4. Update this table before publishing each storage format version, with the release number and reader status.
5. Once the product launches (first public release), every subsequent format change requires forward compatibility for at least one previous version.

## Daily update channel after 0.0.1-alpha.13 (format version 1 unchanged)

Device-local files only (alpha-0-format.md section 67): `update-state-daily.json` and `update-channel.json` in the device directory. Earlier versions ignore them. The download site gains `daily/latest/SHA256SUMS.sig`, signed with a separate daily key.

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
