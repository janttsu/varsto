# Architecture principles (draft)

These are the design commitments. Details become specifications under `docs/spec/` as they are decided.

## Non-negotiables

- **End-to-end encrypted.** Content, file names and metadata are encrypted on the client. Storage providers are untrusted.
- **Post-quantum aware.** Symmetric 256-bit encryption for data; hybrid (classical + post-quantum) key exchange and signatures where public-key cryptography is needed; algorithm identifiers in every object (crypto-agility).
- **Bring your own storage.** The project provides no storage. Back ends: S3-compatible, rclone-compatible remotes, local folders and removable disks.
- **No central dependency.** No tracker, no account server. Peer discovery uses the local network, an encrypted rendezvous record in the user's own storage, and a DHT as a fallback. Optional self-hostable relays help with NAT traversal.
- **No silent inconsistency.** A per-device, signed, append-only ledger records where every block is. Claims expire; the system either knows or says "unknown / at risk".
- **Recoverable without us.** Open, documented storage format; self-describing packs; a recovery kit; restic-compatible backups.

## Building blocks

- Content-defined chunking, compression before encryption, keyed hashes (no plaintext hashes in storage), packs for efficiency.
- Selective sync with placeholders; block-level delta transfer; P2P swarm of encrypted chunks.
- Versions, trash, garbage collection with two-phase deletion; durability policies; sites (geographic failure domains); alerts.
- Strongroom folders: folder keys wrapped by a FIDO2 `hmac-secret`, never plaintext on the device.
- Local daemon with one control API; the CLI, the UI bindings and the MCP server are generated from the same API schema.

## Out of scope

- Selling storage; a browser version of the app; real-time collaborative editing.

## Related documents

- Security principles: [security-principles.md](security-principles.md)
- Threat model: [threat-model.md](threat-model.md)
- Logging: [logging.md](logging.md)

- Specifications: [../spec/README.md](../spec/README.md)
- Testing: [../../TESTING.md](../../TESTING.md)
