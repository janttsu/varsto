---
title: Alpha.14: a security review, its fixes, and everything merged since alpha.13
date: 2026-10-14
summary: A code-level security review of the whole program, the fixes it asked for, a much faster sync, resumable moves to a stack of removable disks, and the twenty-odd features that had been waiting on the main branch since alpha.13.
---
Alpha.14 is the largest release so far. It carries two things: the backlog of features that landed on the main branch after alpha.13, and the first round of fixes from a security review that read every line of the program with a hostile storage, a hostile network and a hostile fellow device in mind.

## The security review

The review found the cryptographic primitives sound and the authorization around them lacking. Alpha.14 closes the parts that could be closed without changing the storage format:

- Ledger events are accepted by role: a replica may only claim copies, a member of a shared folder may only speak about that folder, and checkpoints are taken from full devices alone. A storage that withholds a batch is noticed, a junk object under a device's own name no longer fences the device, and a revocation counts only together with its signed key epoch.
- The service and the peer transport: the STUN side channel is bounded, the browser gets a one-time start code instead of the session token, a crafted request can no longer crash the API, Strongroom keys must match a commitment and the security key asks for its PIN, secrets are gone from the command line, the updater refuses stale signed lists, and storage reads are bounded.
- Hygiene: key files are created private from the first byte, tokens are compared in constant time, key material is wiped from memory, recovery shares carry a check, and the Shamir library was replaced by a fixed fork.

Two findings need a new storage format and are not in this release: file lists and share epochs are still accepted on the folder key alone, and the chunk nonce still comes from the plaintext. Both are built on the branches for format 2, which is the next release. Until then, treat shared folders and untrusted replicas as the review describes: a holder of a folder's key can still change what that folder shows.

## Faster

Syncing 50 000 small files to a local storage went from 167 seconds to 21; 10 000 files from 77 to 8.5. The clock is no longer written to disk per file, storages are opened once per sync, uploads fan out per storage, the S3 client probes once whether conditional writes are honoured, and the binaries are built with link-time optimisation and a faster allocator.

## Everything since alpha.13

Live activity between devices, the bit-rot check, whole drives for disk pools, backups with restic, file analyses and `varsto search`, scoped MCP keys, ledger rebuild, media-aware verification, disk bookkeeping and "the next disk to dock", the recovery package guide, imports from git-annex, cloud drives and local folders, the vault-wide trash, storage quotas and draining, local debug logs, original names, folder safety (marker, mass-deletion guard, send-only and receive-only), ignore rules, file metadata, version history, QR invitations, router port mapping, minimum free disk space, the event stream, read-only members, platform rules, change history, and resumable moves of a folder onto a stack of removable disks one disk at a time.

## Compatibility

The storage format is unchanged, but every device of a vault must run alpha.14: the ledger view cache and the record checks changed, and older devices will not read what alpha.14 writes. The torrent download feature on the main branch is not part of this release.
