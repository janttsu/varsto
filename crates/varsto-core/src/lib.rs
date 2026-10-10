// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Varsto core library, alpha-0.
//!
//! This is the first vertical slice of the design described in the project
//! plan: content-defined chunking, client-side authenticated encryption,
//! a local-folder storage backend, a per-device append-only signed ledger
//! that is replicated through the storage ("mailbox"), and a two-way folder
//! sync between devices that are never online at the same time.
//!
//! Everything here is **alpha**: formats may change without migration, and
//! the cryptography (hybrid Ed25519 + ML-DSA-65 signatures, X25519 + ML-KEM-768
//! key encapsulation, XChaCha20-Poly1305) has not been reviewed independently.
//! Do not use it as the only copy of anything.

pub mod advice;
pub mod autoverify;
pub mod chunking;
pub mod crypto;
pub mod engine;
pub mod ids;
pub mod kem;
pub mod ledger;
pub mod manifest;
pub mod org;
pub mod p2p;
pub mod pack;
pub mod pair;
pub mod placement;
pub mod policy;
pub mod pool;
pub mod price;
pub mod progress;
pub mod rclone;
pub mod recovery;
pub mod replica;
pub mod s3;
pub mod share;
pub mod storage;
pub mod strongroom;
pub mod thumbs;
pub mod util;
pub mod vault;

/// Storage format version written into every object header. See
/// `docs/spec/format-versions.md`.
pub const FORMAT_VERSION: u16 = 1;

pub use engine::{Engine, FsckReport, PullReport, PushReport, StatusReport};
