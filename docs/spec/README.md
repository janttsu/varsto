# Specifications

Status of the documents that will define formats and protocols. Most of what exists is described in [alpha-0-format.md](alpha-0-format.md), section by section; anything marked **not started** has no implementation. They are intended to be open so that implementations remain interoperable and data stays recoverable.

| Document | Status |
|---|---|
| Storage layout and pack format | alpha implemented, packs for small blocks since alpha.12: [alpha-0-format.md](alpha-0-format.md) sections 1 to 5 and 30 |
| Chunking and hashing | alpha implemented, block sizes by file size since alpha.11: [alpha-0-format.md](alpha-0-format.md) sections 1 to 3 and 29 |
| Key hierarchy and key wrapping (incl. FIDO2 `hmac-secret`) | draft; parts implemented ([alpha-0-format.md](alpha-0-format.md) sections 21, 24 and 27): [key-hierarchy.md](key-hierarchy.md) |
| Post-quantum hybrid handshakes and signatures | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 11 |
| Event ledger and bookkeeping | design notes on signing: [ledger-signing-notes.md](ledger-signing-notes.md); alpha-0 mailbox model: [alpha-0-format.md](alpha-0-format.md) section 6 |
| Peer discovery (LAN, storage rendezvous, DHT, relays) | LAN beacon, storage rendezvous record and relays through the user's own devices implemented: [alpha-0-format.md](alpha-0-format.md) section 15; DHT not started |
| Peer-to-peer transfer protocol | alpha implemented (HTTP and QUIC, NAT traversal): [alpha-0-format.md](alpha-0-format.md) section 15 |
| Version, trash and retention model | alpha-0 merge rules: [alpha-0-format.md](alpha-0-format.md) section 7; vault-wide trash with retention and a trash storage: section 36; version history not started |
| Durability policy language | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 14 |
| Removable-disk layout | alpha implemented (disk pool): [alpha-0-format.md](alpha-0-format.md) section 19 |
| Local control API and MCP surface | alpha implemented: [alpha-0-format.md](alpha-0-format.md) sections 10 and 13 |
| Recovery kit | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 18 |
| Data placement, moving data and disk groups | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 23 |
| Automatic repair | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 26 |
| Organizations (administrators, approvals, removing a person) | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 27 |
| Background service, default policy, peer-to-peer during uploads | alpha implemented: [alpha-0-format.md](alpha-0-format.md) section 29 |

Storage format version history (which releases read which formats): see [format-versions.md](format-versions.md).

Failure model (what fails and what does not): see [../failure-model.md](../failure-model.md).
