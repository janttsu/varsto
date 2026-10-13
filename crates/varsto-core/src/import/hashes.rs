// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Content hashes of import sources, computed while the content is read so
//! that what goes into the vault is exactly what the source vouches for:
//! git-annex key hashes (SHA-2, SHA-1, MD5, BLAKE2), git blob ids, and the
//! hashes cloud providers report through rclone (Dropbox content hash,
//! OneDrive QuickXorHash, MD5, SHA-1, SHA-256, BLAKE3).

use sha2::Digest;

/// One running hash. `None` from [`Hasher::new`] means the algorithm is
/// not known here: the content is imported unverified (and said so).
pub enum Hasher {
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha1(sha1::Sha1),
    Md5(md5::Md5),
    Blake2b(blake2::Blake2bVar),
    Blake2s256(blake2::Blake2s256),
    Blake3(Box<blake3::Hasher>),
    Dropbox(DropboxHasher),
    QuickXor(QuickXorHash),
    /// A git blob id: SHA-1 or SHA-256 of `blob <size>\0` and the content.
    GitBlob(Box<Hasher>),
}

impl Hasher {
    /// Algorithms by the names used in import records: `sha256`, `sha1`,
    /// `md5`, `blake2b256`, `dropbox`, `quickxor`, `git-sha1:<size>`, ...
    pub fn new(algo: &str) -> Option<Hasher> {
        use blake2::digest::VariableOutput;
        if let Some(rest) = algo.strip_prefix("git-") {
            let (inner, size) = rest.split_once(':')?;
            let size: u64 = size.parse().ok()?;
            let mut h = Hasher::new(inner)?;
            h.update(format!("blob {size}\0").as_bytes());
            return Some(Hasher::GitBlob(Box::new(h)));
        }
        Some(match algo {
            "sha224" => Hasher::Sha224(sha2::Sha224::new()),
            "sha256" => Hasher::Sha256(sha2::Sha256::new()),
            "sha384" => Hasher::Sha384(sha2::Sha384::new()),
            "sha512" => Hasher::Sha512(sha2::Sha512::new()),
            "sha1" => Hasher::Sha1(sha1::Sha1::new()),
            "md5" => Hasher::Md5(md5::Md5::new()),
            "blake2b160" => Hasher::Blake2b(blake2::Blake2bVar::new(20).ok()?),
            "blake2b224" => Hasher::Blake2b(blake2::Blake2bVar::new(28).ok()?),
            "blake2b256" => Hasher::Blake2b(blake2::Blake2bVar::new(32).ok()?),
            "blake2b384" => Hasher::Blake2b(blake2::Blake2bVar::new(48).ok()?),
            "blake2b512" => Hasher::Blake2b(blake2::Blake2bVar::new(64).ok()?),
            "blake2s256" => Hasher::Blake2s256(blake2::Blake2s256::new()),
            "blake3" => Hasher::Blake3(Box::new(blake3::Hasher::new())),
            "dropbox" => Hasher::Dropbox(DropboxHasher::default()),
            "quickxor" => Hasher::QuickXor(QuickXorHash::default()),
            _ => return None,
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        use blake2::digest::Update;
        match self {
            Hasher::Sha224(h) => Digest::update(h, data),
            Hasher::Sha256(h) => Digest::update(h, data),
            Hasher::Sha384(h) => Digest::update(h, data),
            Hasher::Sha512(h) => Digest::update(h, data),
            Hasher::Sha1(h) => Digest::update(h, data),
            Hasher::Md5(h) => Digest::update(h, data),
            Hasher::Blake2b(h) => Update::update(h, data),
            Hasher::Blake2s256(h) => Digest::update(h, data),
            Hasher::Blake3(h) => {
                h.update(data);
            }
            Hasher::Dropbox(h) => h.update(data),
            Hasher::QuickXor(h) => h.update(data),
            Hasher::GitBlob(h) => h.update(data),
        }
    }

    /// The digest as lowercase hex.
    pub fn finish_hex(self) -> String {
        use blake2::digest::VariableOutput;
        match self {
            Hasher::Sha224(h) => hex::encode(h.finalize()),
            Hasher::Sha256(h) => hex::encode(h.finalize()),
            Hasher::Sha384(h) => hex::encode(h.finalize()),
            Hasher::Sha512(h) => hex::encode(h.finalize()),
            Hasher::Sha1(h) => hex::encode(h.finalize()),
            Hasher::Md5(h) => hex::encode(h.finalize()),
            Hasher::Blake2b(h) => {
                let mut out = vec![0u8; h.output_size()];
                let _ = h.finalize_variable(&mut out);
                hex::encode(out)
            }
            Hasher::Blake2s256(h) => hex::encode(h.finalize()),
            Hasher::Blake3(h) => h.finalize().to_hex().to_string(),
            Hasher::Dropbox(h) => hex::encode(h.finish()),
            Hasher::QuickXor(h) => hex::encode(h.finish()),
            Hasher::GitBlob(h) => h.finish_hex(),
        }
    }
}

/// Hex of the MD5 of `data` (git-annex hash directories).
pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    let mut h = md5::Md5::new();
    Digest::update(&mut h, data);
    h.finalize().into()
}

/// Dropbox's content hash: the SHA-256 of the concatenated SHA-256 digests
/// of every 4 MiB block of the file (an empty file: SHA-256 of nothing).
#[derive(Default)]
pub struct DropboxHasher {
    outer: sha2::Sha256,
    block: sha2::Sha256,
    in_block: usize,
}

const DROPBOX_BLOCK: usize = 4 * 1024 * 1024;

impl DropboxHasher {
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (DROPBOX_BLOCK - self.in_block).min(data.len());
            Digest::update(&mut self.block, &data[..take]);
            self.in_block += take;
            data = &data[take..];
            if self.in_block == DROPBOX_BLOCK {
                let d = std::mem::take(&mut self.block).finalize();
                Digest::update(&mut self.outer, d);
                self.in_block = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        if self.in_block > 0 {
            let d = std::mem::take(&mut self.block).finalize();
            Digest::update(&mut self.outer, d);
        }
        self.outer.finalize().into()
    }
}

/// Microsoft's QuickXorHash (OneDrive for Business and personal): 160 bits;
/// each byte is XORed in at a position that advances 11 bits per byte, and
/// the length is XORed into the last 8 bytes at the end. A transcription of
/// the reference algorithm published by Microsoft.
#[derive(Default)]
pub struct QuickXorHash {
    data: [u64; 3],
    shift_so_far: usize,
    length: u64,
}

const QX_WIDTH: usize = 160;
const QX_SHIFT: usize = 11;

impl QuickXorHash {
    pub fn update(&mut self, array: &[u8]) {
        let cb = array.len();
        let mut current_shift = self.shift_so_far;
        let mut vector_index = current_shift / 64;
        let mut vector_offset = current_shift % 64;
        let iterations = cb.min(QX_WIDTH);
        for i in 0..iterations {
            let is_last = vector_index == self.data.len() - 1;
            let bits_in_cell = if is_last { 32 } else { 64 };
            if vector_offset <= bits_in_cell - 8 {
                let mut j = i;
                while j < cb {
                    self.data[vector_index] ^= (array[j] as u64) << vector_offset;
                    j += QX_WIDTH;
                }
            } else {
                let index1 = vector_index;
                let index2 = if is_last { 0 } else { vector_index + 1 };
                let low = bits_in_cell - vector_offset;
                let mut xored: u8 = 0;
                let mut j = i;
                while j < cb {
                    xored ^= array[j];
                    j += QX_WIDTH;
                }
                self.data[index1] ^= (xored as u64) << vector_offset;
                self.data[index2] ^= (xored as u64) >> low;
            }
            vector_offset += QX_SHIFT;
            while vector_offset >= bits_in_cell {
                vector_index = if is_last { 0 } else { vector_index + 1 };
                vector_offset -= bits_in_cell;
            }
        }
        current_shift = (self.shift_so_far + QX_SHIFT * (cb % QX_WIDTH)) % QX_WIDTH;
        self.shift_so_far = current_shift;
        self.length = self.length.wrapping_add(cb as u64);
    }

    pub fn finish(self) -> [u8; 20] {
        let mut out = [0u8; 20];
        out[..8].copy_from_slice(&self.data[0].to_le_bytes());
        out[8..16].copy_from_slice(&self.data[1].to_le_bytes());
        out[16..20].copy_from_slice(&self.data[2].to_le_bytes()[..4]);
        for (i, b) in self.length.to_le_bytes().iter().enumerate() {
            out[QX_WIDTH / 8 - 8 + i] ^= b;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(algo: &str, data: &[u8]) -> String {
        let mut h = Hasher::new(algo).unwrap();
        h.update(data);
        h.finish_hex()
    }

    /// The same content fed in pieces of every awkward size.
    fn hash_split(algo: &str, data: &[u8], piece: usize) -> String {
        let mut h = Hasher::new(algo).unwrap();
        for c in data.chunks(piece) {
            h.update(c);
        }
        h.finish_hex()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    #[test]
    fn common_digests() {
        assert_eq!(
            hash("sha256", b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash("sha1", b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hash("md5", b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hash("blake2b512", b"abc"),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hash("blake2s256", b"abc"),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
        // git hash-object of "hello\n".
        assert_eq!(
            hash("git-sha1:6", b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
        assert!(Hasher::new("skein256").is_none());
    }

    /// Vectors from rclone 1.75 (`rclone hashsum dropbox|quickxor` over files
    /// of these contents), which follows Dropbox's and Microsoft's
    /// published reference code.
    #[test]
    fn dropbox_and_quickxor_vectors() {
        assert_eq!(
            hash("dropbox", b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash("quickxor", b""),
            "0000000000000000000000000000000000000000"
        );
        // One byte "J": 0x4a, and the length 1 XORed in at byte 12.
        assert_eq!(
            hash("quickxor", b"J"),
            "4a00000000000000000000000100000000000000"
        );
        for (len, dropbox, quickxor) in VECTORS {
            let data = pattern(*len);
            assert_eq!(&hash("dropbox", &data), dropbox, "dropbox {len}");
            assert_eq!(&hash("quickxor", &data), quickxor, "quickxor {len}");
            for piece in [1usize, 7, 159, 160, 161, 4096, 1 << 20] {
                if piece < *len && (piece > 1 || *len < 100_000) {
                    assert_eq!(&hash_split("dropbox", &data, piece), dropbox);
                    assert_eq!(&hash_split("quickxor", &data, piece), quickxor);
                }
            }
        }
    }

    /// (length of `pattern`, dropbox, quickxor), from rclone.
    const VECTORS: &[(usize, &str, &str)] = &[
        (
            3,
            "1c502ac9ab8e4dd556645c52182cd2fee2e7e1608e8655f68732993b3a1f5ae4",
            "0038800300000000000000000300000000000000",
        ),
        (
            160,
            "4d356c559f18295a393814cc29b9f14bd2fd76c34cc8f7facd5e914aac4b1f8e",
            "d2ef87d2b8b80c844552cbd630f81d07c556ff32",
        ),
        (
            161,
            "860078fc1dbc11d8645c68d71a957afbde0ff8ce1dcf69ac3726b8158ace7f68",
            "b2ef87d2b8b80c844552cbd631f81d07c556ff32",
        ),
        (
            1000,
            "4ef4e5593284115a3b40f804e6eefbfd03edc1f99b1bfc0d9406395f4ad9dc73",
            "3d54525307beb6ab01ebb82d4f659898a8fb32de",
        ),
        (
            4194304,
            "56efd10756134401ee860fc4a3d0eb99bad4be7377d696a68fe5fcb949eef227",
            "fa8e44e9f1e3420091bc59bfe8d24db5098330ca",
        ),
        (
            4194309,
            "1fd58d91c11719eaaf3634c9b29b4e7e311abf8cf49a0a8591e281bb513b2729",
            "fa8e44e9f1e34200d7d45baa5bf24bb5098330ca",
        ),
        (
            9437185,
            "ced11efb97cda31c0c7bb4dba9453f96756414bfb96c48e814fdcd260fb0023d",
            "7cbb11c9f0671f9d8310fd78aca0e9ae45746b15",
        ),
    ];
}
