# Specifications

Status of the documents that will define formats and protocols. Sections 32 to 60 of alpha-0-format.md are new in 0.0.1-alpha.14 and sections 62 to 71 new in 0.0.1-alpha.15; sections 72 to 77 follow alpha.15 (section 77 describes storage format 3, not yet enabled). Most of what exists is described in [alpha-0-format.md](alpha-0-format.md), section by section; anything marked **not started** has no implementation. They are intended to be open so that implementations remain interoperable and data stays recoverable.

| Document | Status |
|---|---|
| Storage layout and pack format | alpha implemented, packs for small blocks since alpha.12: [alpha-0-format.md](alpha-0-format.md) sections 1 to 5 and 30 |
| Chunking and hashing | alpha implemented, block sizes by file size since alpha.11: [alpha-0-format.md](alpha-0-format.md) sections 1 to 3 and 29 |
| Key hierarchy and key wrapping (incl. FIDO2 `hmac-secret`) | draft; parts implemented ([alpha-0-format.md](alpha-0-format.md) sections 21, 24 and 27): [key-hierarchy.md](key-hierarchy.md) |
| Post-quantum hybrid handshakes and signatures | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 11 |
| Event ledger and bookkeeping | design notes on signing: [ledger-signing-notes.md](ledger-signing-notes.md); alpha-0 mailbox model: [alpha-0-format.md](alpha-0-format.md) section 6 |
| Peer discovery (LAN, storage rendezvous, DHT, relays) | LAN beacon, storage rendezvous record and relays through the user's own devices implemented: [alpha-0-format.md](alpha-0-format.md) section 15; DHT not started |
| Peer-to-peer transfer protocol | alpha implemented (HTTP and QUIC, NAT traversal): [alpha-0-format.md](alpha-0-format.md) section 15; router port mapping (PCP, NAT-PMP, UPnP IGD): section 52 (released in 0.0.1-alpha.14) |
| Version, trash and retention model | alpha-0 merge rules: [alpha-0-format.md](alpha-0-format.md) section 7; vault-wide trash with retention and a trash storage: section 43, and version history with staggered thinning: section 50 (both released in 0.0.1-alpha.14) |
| Durability policy language | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 14 |
| Removable-disk layout | alpha implemented (disk pool): [alpha-0-format.md](alpha-0-format.md) section 19; whole drives and disk bookkeeping: sections 34 and 40 (released in 0.0.1-alpha.14) |
| Local control API and MCP surface | alpha implemented: [alpha-0-format.md](alpha-0-format.md) sections 10 and 13; event stream for the interface: section 54 (released in 0.0.1-alpha.14); the Windows window, installer and automatic updates: section 65 (released in 0.0.1-alpha.15) |
| Recovery kit | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 18 |
| Data placement, moving data and disk groups | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 23 |
| Automatic repair | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 26 |
| Organizations (administrators, approvals, removing a person) | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 27; which device platforms may belong: section 56 (released in 0.0.1-alpha.14) |
| Background service, default policy, peer-to-peer during uploads | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 29 |
| Folder safety (folder marker, mass-deletion guard, send-only and receive-only folders) | released in 0.0.1-alpha.14: [alpha-0-format.md](alpha-0-format.md) section 47 |
| Ignore rules and file metadata (permissions, symbolic links, extended attributes, ownership) | released in 0.0.1-alpha.14: [alpha-0-format.md](alpha-0-format.md) sections 48 and 49 |
| Invitations as QR codes and `varsto://` links | released in 0.0.1-alpha.14: [alpha-0-format.md](alpha-0-format.md) section 51 |
| Minimum free disk space | released in 0.0.1-alpha.14: [alpha-0-format.md](alpha-0-format.md) section 53 |
| Shared folder roles (read-only members) | released in 0.0.1-alpha.14: [alpha-0-format.md](alpha-0-format.md) section 55 |
| Change history of files (`varsto changes`) | released in 0.0.1-alpha.14: [alpha-0-format.md](alpha-0-format.md) section 57 |
| Working offline (storage health, S3 and rclone timeouts, the service without network I/O under its lock, local actions; peers from the saved directory; membership outbox) | on main and in the daily builds (format 3), not in a release yet: [alpha-0-format.md](alpha-0-format.md) section 79, with 77.8 and 77.6 |
| Torrents through a local transmission daemon (`varsto import torrent`) | on main and in the daily builds (format 3), not in a release yet: [alpha-0-format.md](alpha-0-format.md) section 81 |
| YouTube channels through yt-dlp (`varsto import youtube`) | on main and in the daily builds (format 3), not in a release yet: [alpha-0-format.md](alpha-0-format.md) section 82 |

Storage format version history (which releases read which formats): see [format-versions.md](format-versions.md).

Storage format 3 (built behind the `format3` cargo feature, not enabled): pack-level ledger, folder block maps, signed records, folder key grants with recovery escrow, base + delta manifests and padded packs of fixed size classes. It ships only when `FORMAT_VERSION` becomes 3. Text: [alpha-0-format.md](alpha-0-format.md) section 77 (with sections 75 and 76 for peers and membership); binding design: [format-3-design.md](format-3-design.md).

Failure model (what fails and what does not): see [../failure-model.md](../failure-model.md).
