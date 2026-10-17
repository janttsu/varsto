// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Size classes of record bodies (format 3 design, amendment 3).
//!
//! A part's body (nonce || ciphertext || tag, or the plaintext itself for
//! `none`) is padded so that its length is a multiple of 64 KiB below
//! 4 MiB and a multiple of 1 MiB from 4 MiB up. The plaintext of a part is
//! `len: u32 LE || data || random bytes`: the reader takes `len` and
//! ignores the tail, which comes from the OS CSPRNG so it says nothing
//! about where the data ends.

use rand::RngCore;

/// Step of the classes below `LARGE_FROM`.
pub const SMALL_STEP: usize = 64 << 10;
/// From this length on the classes are multiples of `LARGE_STEP`.
pub const LARGE_FROM: usize = 4 << 20;
pub const LARGE_STEP: usize = 1 << 20;
/// Length of the `len` prefix.
pub const LEN_PREFIX: usize = 4;

fn round_up(n: usize, step: usize) -> usize {
    n.div_ceil(step).max(1) * step
}

/// The smallest class that holds `n` bytes (at least one small step).
pub fn class_for(n: usize) -> usize {
    let small = round_up(n, SMALL_STEP);
    if small < LARGE_FROM {
        small
    } else {
        round_up(n, LARGE_STEP)
    }
}

/// Whether `n` is a class length.
pub fn is_class(n: usize) -> bool {
    n > 0
        && if n < LARGE_FROM {
            n % SMALL_STEP == 0
        } else {
            n % LARGE_STEP == 0
        }
}

/// The framed plaintext of one part: `len || data || random`, `total`
/// bytes long. `total` must be at least `data.len() + LEN_PREFIX`.
pub fn frame(data: &[u8], total: usize) -> Vec<u8> {
    debug_assert!(total >= data.len() + LEN_PREFIX);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    let start = out.len();
    out.resize(total.max(start), 0);
    rand::rngs::OsRng.fill_bytes(&mut out[start..]);
    out
}

/// The data of a framed plaintext; `None` when `len` points past the end.
pub fn unframe(plain: &[u8]) -> Option<&[u8]> {
    let len: [u8; LEN_PREFIX] = plain.get(..LEN_PREFIX)?.try_into().ok()?;
    let len = usize::try_from(u32::from_le_bytes(len)).ok()?;
    plain.get(LEN_PREFIX..LEN_PREFIX.checked_add(len)?)
}
