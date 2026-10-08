// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Varsto core library, alpha-0.
//!
//! This is the first vertical slice of the design described in the project
//! plan: content-defined chunking, client-side authenticated encryption,
//! a local-folder storage backend, a per-device append-only signed ledger
//! that is replicated through the storage ("mailbox"), and a two-way folder
//! sync between devices that are never online at the same time.
//!
//! Everything here is **alpha**: formats may change without migration, the
//! post-quantum hybrid signatures and key agreement are not implemented yet
//! (algorithm identifiers are recorded so that they can be added), and the
//! cryptography has not been reviewed. Do not use it for real data.

pub mod advice;
pub mod chunking;
pub mod crypto;
pub mod engine;
pub mod ids;
pub mod kem;
pub mod ledger;
pub mod manifest;
pub mod p2p;
pub mod pack;
pub mod policy;
pub mod rclone;
pub mod recovery;
pub mod replica;
pub mod s3;
pub mod storage;
pub mod strongroom;
pub mod thumbs;
pub mod util;
pub mod vault;

/// Storage format version written into every object header. See
/// `docs/spec/format-versions.md`.
pub const FORMAT_VERSION: u16 = 1;

pub use engine::{Engine, FsckReport, PullReport, PushReport, StatusReport};
