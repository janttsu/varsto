# Ledger signing: design notes

> **Design-stage notes, no implementation.** This document compares ways to sign ledger events and recommends one for further specification. The figures are estimates from cited benchmarks and stated assumptions; nothing has been measured on Varsto code because none exists. The recommendation is not a decision. Open points are marked **TBD**.

Background: each device keeps an append-only, signed event ledger that records where every block is (F-031, plan 6.19). Events are replicated to all devices and to storage. Signatures must be hybrid, classical plus post-quantum (S-003, plan 6.5). The plan's open questions (section 8, blocking question on the ledger protocol model) note that per-event post-quantum signatures would grow a ledger of millions of events to gigabytes. Keys are named as in [key-hierarchy.md](key-hierarchy.md) (K7 is the device ledger key); adversaries as in [../architecture/threat-model.md](../architecture/threat-model.md).

## 1. Models compared

- **A. Every event signed.** Each event carries a hybrid signature: Ed25519 (64 bytes, RFC 8032) and ML-DSA-65 (3309 bytes, FIPS 204, Table 2), 3373 bytes in total.
- **B. Batches signed.** Events are hashed into a Merkle tree. A batch header holds the device ID, batch sequence number, first and last event sequence numbers, the hash of the previous batch header (hash chain) and the Merkle root; only the header is signed with the hybrid signature. A single event is proven with the signed header and an inclusion proof of log2(n) hashes.
- **C. Hybrid split.** Each event carries a classical Ed25519 signature (64 bytes); each batch header as in B carries an ML-DSA-65 signature.

## 2. Assumptions

| # | Assumption | Value | Source or reason |
| --- | --- | --- | --- |
| 1 | Ledger size | 10,000,000 events | Task scenario. |
| 2 | Event payload without signature | 160 bytes on average | **TBD**; to be measured with a prototype. Only the overhead percentages depend on it. |
| 3 | Copies to replicate | 7: 5 devices and 2 storages | Task scenario. Counted as bytes transferred and stored once per copy. |
| 4 | Signature sizes | Ed25519 64 bytes; ML-DSA-65 3309 bytes | RFC 8032; FIPS 204, Table 2. |
| 5 | Batch sizes | n = 1024 (busy device) and n = 64 (quiet device, batches closed early by timeout) | Illustrative; batch policy **TBD**. |
| 6 | Mid-range phone | One Arm Cortex-A76-class big core at 2.0 GHz; cycle counts taken from a 1.5 GHz Cortex-A76 and assumed unchanged at 2.0 GHz; memory effects ignored; single core. | Assumption. Mid-range phones also use smaller cores (for example Cortex-A55) that were not measured here; **TBD** on real test devices (plan 6.39). |
| 7 | Ed25519 verification | 334,798 cycles (median) | eBACS, crypto_sign "ed25519", Raspberry Pi 5 (Cortex-A76, 1.5 GHz), supercop-20251222. |
| 8 | ML-DSA-65 verification | 446,217 cycles (median) | eBACS, crypto_sign "dilithium3", same machine. This is the round-3 Dilithium3 parameter set (signature 3293 bytes), used as a proxy for ML-DSA-65. Consistent with 447,460 cycles on Cortex-A72 for an optimised Dilithium3 (Becker et al., TCHES 2022, Table 6). |
| 9 | Hashing for B and C | SHA-256 at 4.25 cycles per byte for 64-byte inputs | eBACS, crypto_hash "sha256", same machine. Applied to 160-byte leaves and 64-byte inner nodes: about 950 cycles per event. The hash function is **TBD**. |
| 10 | Signature format | Two separate signatures concatenated, no compression | Simplest hybrid; the exact hybrid construction is **TBD**. |

Derived: one hybrid verification is 781,015 cycles, about 0.39 ms on the assumed core.

## 3. Results for 10 million events

| Metric | A: every event | B: batches, n = 1024 | B: batches, n = 64 | C: split, n = 1024 | C: split, n = 64 |
| --- | --- | --- | --- | --- | --- |
| Signed units | 10,000,000 events | 9,766 batches | 156,250 batches | 10,000,000 events + 9,766 batches | 10,000,000 events + 156,250 batches |
| Signature bytes per copy | 33.7 GB | 0.033 GB | 0.53 GB | 0.67 GB | 1.16 GB |
| Signature overhead relative to payload (1.6 GB) | 2108 % | 2.1 % | 33 % | 42 % | 72 % |
| Signature bytes for 7 copies | 236 GB | 0.23 GB | 3.7 GB | 4.7 GB | 8.1 GB |
| Full verification on the assumed phone core | about 65 min | about 9 s (3.8 s signatures, 4.8 s hashing) | about 66 s | about 28 min | about 29 min |
| Proof size for one event | its own signature (3373 bytes) | header signature + 10 hashes (320 bytes) | header signature + 6 hashes (192 bytes) | own Ed25519 signature; full hybrid proof as in B | as for n = 1024, with 6 hashes |

Notes on the numbers:

- Verification of A parallelises across cores (about 16 minutes on four big cores under the same assumptions), but it is still repeated on every device that receives the full ledger.
- Ed25519 batch verification could reduce the classical part of A and C; it is not counted because no benchmark was cited for it.
- Payload bytes (1.6 GB per copy, 11.2 GB for 7 copies) are the same in every model and not included in the signature figures.
- Ledger compaction (signed checkpoints that let old batches be dropped) would reduce all figures. It is **TBD** and not assumed here.

## 4. Behaviour when a batch is interrupted by a crash

The plan's write order applies in every model: data first, then the ledger entry, with fsync (plan 6.19).

- **A.** Each event is complete once written and signed. A crash loses at most an event that was not yet written, which the recovery replay redoes.
- **B.** Events are written to the local log before the batch is sealed. After a crash the device replays its log and seals the pending events in the next batch, with the next sequence number. Until a batch is sealed, its events exist only on this device and cannot be shown to anyone else. A receipt (plan 6.19, step 3) must not be sent before the batch that contains it is sealed, so receipts add latency.
- **C.** Each event carries a classical signature at once, so a receipt can be sent immediately. Its post-quantum protection arrives only when the batch is sealed. If the device crashes or is lost first, those events stay classically signed only.

## 5. What a verifier can prove about one event

| Model | Proof available | Strength |
| --- | --- | --- |
| A | The event, its author device, its sequence number and content, from the event alone. | Hybrid, immediately. |
| B | The same, from the signed batch header and an inclusion proof; nothing before the batch is sealed. | Hybrid, after sealing. |
| C | Classical proof immediately; hybrid proof after the batch is sealed, as in B. | Classical only until sealing. A future quantum adversary (A8) could forge classical signatures, so verifiers would have to treat classically-only signed events as provisional, never as final. |

In every model, a signature proves only that the device said something. It does not prove that the stated block really exists; that still needs challenge-response checks (plan 6.19, "proof of storage").

## 6. Interaction with rollback protection (plan 6.19)

- **Sequence numbers.** B and C sign the device ID, batch sequence and event range in one header, so a gap or a reordering is visible from headers alone. A needs a sequence number in every event to get the same.
- **Hash chain and Merkle root.** In B and C each header commits to the previous header, so replacing or dropping a past batch breaks the chain. Two different headers with the same device and sequence number prove that the device equivocated (a fork); any device that sees both can raise an alert.
- **Rollback by storage (A1).** A provider that serves an older but valid prefix of the ledger cannot be caught by signatures alone in any model. It is detected when another copy (a peer or another storage) shows a newer signed header. Devices should therefore exchange their latest signed headers on every contact. B makes this cheap: the latest header is one small signed object.
- **Device restored from a backup ("time travel").** The restored device sees its own higher sequence numbers elsewhere and must stop signing until it resynchronises; the same rule works in every model.
- **Leases.** Location claims expire (plan 6.19). Expiry times are carried inside the signed events, so they are covered by the signature in all models. How expiry is judged without a trusted clock is a separate open question (plan section 8, "lease expiry and time").
- **Locked state.** Sealing batches while the app is locked needs K7 in the locked-state key set ([key-hierarchy.md](key-hierarchy.md), section 5). In model A every event would need it.

## 7. Recommendation and limitations

**Recommendation (proposal, not a decision): model B**, with these rules:

1. Seal a batch when it reaches a maximum size, after a maximum delay, or when a receipt must be delivered, whichever comes first. Values **TBD**; 1024 events is the example used above.
2. Collect receipts for many chunks in one batch (for example everything received in the same short window) and have the sender wait for the sealed header, instead of sealing one batch per chunk.
3. Seal rare, security-relevant events at once in their own batch: device enrolment and revocation, wipe commands, key rotation, policy changes. Their cost is negligible, and they then carry an immediate hybrid signature (effectively model A for them).
4. Exchange the latest signed batch header on every contact with a peer or storage, to detect rollback and equivocation.
5. Sign the hash of the encrypted event payload, so payload keys can be destroyed later (cryptographic erasure) without breaking the chain (plan section 8, "GDPR and append-only ledger"; K22 in the key hierarchy).

Why: under the assumptions above, B with n = 1024 needs about 1/1000 of the signature bytes of A (0.23 GB instead of 236 GB for 7 copies) and about 9 seconds instead of about 65 minutes to verify on one phone core. It keeps full hybrid strength for every sealed event. C costs 20 times more bytes than B with n = 1024 and about 28 minutes of verification, and its only advantage, immediate receipts, is limited by the provisional status of classical-only signatures.

Limitations:

- Events are unprovable to others until their batch is sealed; the delay rule (rule 1) bounds this but adds latency to receipts.
- On quiet devices batches are small and overhead grows (n = 64: 3.7 GB for 7 copies, about 66 seconds to verify). A long maximum delay reduces this but lengthens the window in which events are unproven.
- A single-event proof needs the batch header and an inclusion proof, and the verifier needs the tree layout; this is more complex than one signature per event.
- All figures rest on assumptions 2, 6 and 8: an estimated payload size, an assumed phone core, and round-3 Dilithium3 used as a proxy for ML-DSA-65. They must be replaced by measurements on test devices.
- Nothing here addresses resource limits against A5 or A6 (for example a member flooding the ledger); that belongs to the protocol specification.

## 8. Open questions

All **TBD**, not decided here.

1. Batch policy: maximum size, maximum delay, and the receipt window. Plan 6.19.
2. Hash function for leaves and the hash chain (SHA-256, BLAKE3 or other), and the Merkle tree layout (domain-separated leaf and node hashes are required either way).
3. Hybrid signature format (separate concatenated signatures or a combined construction) and the ML-DSA parameter set. Plan section 8, "PQ library".
4. Checkpoints and compaction: when old batches may be dropped and what a new device must download. Plan 6.19.
5. Whether the protocol model is an own operation log with a Merkle DAG or an existing CRDT library; this note assumes an own log. Plan section 8, blocking question on the ledger protocol model.
6. Measurements on real test devices, including smaller phone cores. Plan 6.39.

## Sources

All checked on 2026-10-08.

| No. | Source | URL |
| --- | --- | --- |
| L1 | NIST FIPS 204, Module-Lattice-Based Digital Signature Standard, Table 2 (ML-DSA-65: public key 1952 bytes, signature 3309 bytes) | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf> |
| L2 | RFC 8032, Edwards-Curve Digital Signature Algorithm (Ed25519: signature 64 bytes) | <https://www.rfc-editor.org/rfc/rfc8032> |
| L3 | eBACS, measurements of public-key signature systems on one machine: aarch64, Cortex-A76, Broadcom BCM2712, 1.5 GHz ("pi5"), supercop-20251222; table "Cycles to verify 59 bytes", medians for ed25519 and dilithium3 | <https://bench.cr.yp.to/results-sign/aarch64-pi5.html> |
| L4 | eBACS, measurements of hash functions on the same machine; table "Cycles/byte for 64 bytes", sha256 | <https://bench.cr.yp.to/results-hash/aarch64-pi5.html> |
| L5 | Becker, Hwang, Kannwischer, Yang, Yang: "Neon NTT: Faster Dilithium, Kyber, and Saber on Cortex-A72 and Apple M1", IACR TCHES 2022 (1), Table 6 | <https://doi.org/10.46586/tches.v2022.i1.221-244> |
