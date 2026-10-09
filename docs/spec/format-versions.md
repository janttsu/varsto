# Storage format versions

## Purpose

During alpha development, storage formats may change without migration paths. Once a format version is released, that version stays readable. This table tracks which released versions of Varsto can read each storage format, and whether standalone reader tools are available for data recovery.

## Format versions

| Format version | First release | Releases that read it | Standalone reader tool | Archived tag |
|---|---|---|---|---|
| 0 (alpha-0) | 0.0.1-alpha.0 (branch `alpha-0`, not tagged yet) | 0.0.1-alpha.0 | none yet (`varsto pull` and `varsto fsck` of the same version) | - |

## Release rules

1. Tag every alpha release (for example `alpha-2026-10-08`) with the source commit and binaries.
2. Archive binaries and source on each release.
3. Before publishing a new storage format version, ensure the previous version has a reader tool (built-in or standalone).
4. Update this table before publishing each storage format version, with the release number and reader status.
5. Once the product launches (first public release), every subsequent format change requires forward compatibility for at least one previous version.

## Ledger events in 0.0.1-alpha.9 (format version 1 unchanged)

A new ledger event, `chunk_dropped` (alpha-0-format.md section 23), records that a block was removed from a storage on purpose. Versions 0.0.1-alpha.8 and earlier reject a batch that holds an event type they do not know, so once any device moves data their pull fails: update every device first. From 0.0.1-alpha.9 on, unknown event types are read and ignored, so later event types do not break older readers. Objects, records and batch envelopes are unchanged; the local cached view moves to format 3 and is rebuilt once.

## Format version 1 (0.0.1-alpha.4)

Chunk payloads are packed before encryption: one method byte (`0` raw, `1` zstd level 12) followed by the data; compression is used only when it saves at least 5 %. Objects written by format 0 have no method byte and are not readable by format 1 readers; vaults created with format 0 are refused with a clear error. Readers: 0.0.1-alpha.4 and later. Archived tag of the last format-0 reader: `v0.0.1-alpha.3`.
