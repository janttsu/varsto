# Storage format versions

## Purpose

During alpha development, storage formats may change without migration paths. Once a format version is released, that version stays readable. This table tracks which released versions of Varsto can read each storage format, and whether standalone reader tools are available for data recovery.

## Format versions

| Format version | First release | Releases that read it | Standalone reader tool | Archived tag |
|---|---|---|---|---|
| 0 (pre-alpha) | none yet | - | - | - |

## Release rules

1. Tag every alpha release (for example `alpha-2026-10-08`) with the source commit and binaries.
2. Archive binaries and source on each release.
3. Before publishing a new storage format version, ensure the previous version has a reader tool (built-in or standalone).
4. Update this table before publishing each storage format version, with the release number and reader status.
5. Once the product launches (first public release), every subsequent format change requires forward compatibility for at least one previous version.
