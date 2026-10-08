# Security principles

These principles are requirements, not preferences. Details become specifications under `docs/spec/`.

## 1. Security is never traded for speed

- There is no "fast mode". No setting disables encryption, skips integrity checks, shortens keys or weakens password stretching.
- Speed comes from parallel transfers, block-level delta sync, hardware-accelerated cryptography (AES-NI, ARMv8 crypto extensions, SIMD ChaCha20), efficient compression before encryption, caching and peer-to-peer transfer. None of these weakens security.
- Security parameters (key sizes, Argon2id costs, algorithms, hybrid handshakes) have fixed minimums in the specification. They may only be tightened. A device that cannot meet the minimum waits longer or refuses; it does not use a weaker setting.
- Every object is authenticated (AEAD) before it is used. Content hashes stored in storage are keyed, never plain.
- CI tests fail if a security parameter falls below its minimum.

## 2. Keys stay with the user

- External disks, cloud storage and every provider are untrusted. Everything leaving a device is already encrypted.
- The master key is always strong: 256 random bits from the operating system's CSPRNG. It is never derived from a human-chosen password alone. A passphrase (any length) only wraps the master key locally with Argon2id, optionally combined with a hardware-bound secret and a FIDO2 security key.
- The application never writes keys in clear text to storage, disks or providers. The recovery key is kept apart from the data.
- There is no key escrow and no account recovery by the project. Losing every key and the recovery key means the data is gone; users are told this before adding data.

## 3. Post-quantum by design

- 256-bit symmetric keys. Grover's algorithm roughly halves their effective strength against a quantum computer, so 256 bits is the floor for recovery keys as well.
- Hybrid (classical + post-quantum) key exchange and signatures wherever public-key cryptography is used. Algorithm identifiers in every object allow algorithms to change without re-encrypting all data.
- Claims are worded as "designed for" until an independent audit has been published.

## 4. Recovery key custody (recommended practice)

The recovery key is 24 words with a checksum, generated and shown once on the user's device, ideally offline.

Recommended default for important data:

1. Split the recovery key with threshold sharing (for example 2-of-3 or 3-of-5).
2. Write each share by hand on archival paper, or engrave or stamp it on stainless steel for long-term storage.
3. Keep the shares in two or three different physical places (home, a trusted person, a workplace or bank). Do not rely on a single safe-deposit box.
4. Keep daily unlock separate: at least two hardware security keys.
5. Test recovery right after creation and then yearly.

Rules for creating and storing the key:

- Do not photograph, screenshot, copy to the clipboard, or store it in cloud services or a normal password manager.
- Do not print on a networked or cloud printer (printers can cache output). Prefer handwriting.
- Prefer words over QR codes as the primary medium: they tolerate wear, can be read and written by hand, and do not depend on one application surviving for decades. QR codes may be an optional extra copy.
- The recovery format is openly specified with test vectors, and a small offline reader tool restores the key without the main application.

Optional layers for advanced users: a memorised passphrase on top of the shares (adds protection, adds loss risk), and tools such as Superbacked-style offline encrypted backups, provided the tool is open source, signed and used on an air-gapped machine.
