# Specifications

Status of the documents that will define formats and protocols. All are **not started** unless noted. They are intended to be open so that implementations remain interoperable and data stays recoverable.

| Document | Status |
|---|---|
| Storage layout and pack format | not started |
| Chunking and hashing | not started |
| Key hierarchy and key wrapping (incl. FIDO2 `hmac-secret`) | draft, design stage: [key-hierarchy.md](key-hierarchy.md) |
| Post-quantum hybrid handshakes and signatures | not started |
| Event ledger and bookkeeping | not started |
| Peer discovery (LAN, storage rendezvous, DHT, relays) | not started |
| Peer-to-peer transfer protocol | not started |
| Version, trash and retention model | not started |
| Durability policy language | not started |
| Removable-disk layout | not started |
| Local control API and MCP surface | not started |
| Recovery kit | not started |

Storage format version history (which releases read which formats): see [format-versions.md](format-versions.md).

Failure model (what fails and what does not): see [../failure-model.md](../failure-model.md).
