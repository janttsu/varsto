// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Encrypted thumbnails (F-046): generated once on a device that holds the
//! plaintext, encrypted under the folder metadata key and stored next to the
//! data, so every device of the folder can show previews without downloading
//! or decrypting the file itself. Images are decoded in-process; videos use
//! `ffmpeg` when it is installed. Thumbnails are derived data and follow the
//! same rule as content: never stored in clear text outside the process.

use crate::crypto::{self, SecretKey};
use crate::ids::{FolderId, VaultId};
use anyhow::Result;
use std::io::Cursor;
use std::path::Path;

pub const MAX_SIDE: u32 = 256;

pub fn is_image(path: &str) -> bool {
    matches!(
        ext(path).as_str(),
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "tif" | "tiff"
    )
}

pub fn is_video(path: &str) -> bool {
    matches!(
        ext(path).as_str(),
        "mp4" | "mov" | "m4v" | "mkv" | "webm" | "avi"
    )
}

fn ext(path: &str) -> String {
    path.rsplit('.')
        .next()
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn storage_key(folder: &FolderId, content_hash: &str) -> String {
    format!("thumbs/{}/{}.enc", folder, content_hash)
}

fn aad(vault: &VaultId, folder: &FolderId, content_hash: &str) -> Vec<u8> {
    crypto::aad(
        "thumbnail",
        &[
            vault.as_str().as_bytes(),
            folder.as_str().as_bytes(),
            content_hash.as_bytes(),
        ],
    )
}

/// JPEG thumbnail bytes for an image or video file, if one can be made.
pub fn make(path: &Path, name: &str) -> Option<Vec<u8>> {
    if is_image(name) {
        let img = image::open(path).ok()?;
        return encode(img);
    }
    if is_video(name) {
        let out = std::process::Command::new("ffmpeg")
            .args(["-v", "error", "-y", "-ss", "1", "-i"])
            .arg(path)
            .args([
                "-frames:v",
                "1",
                "-vf",
                &format!("scale='min({MAX_SIDE},iw)':-2"),
                "-f",
                "image2pipe",
                "-vcodec",
                "mjpeg",
                "-",
            ])
            .output()
            .ok()?;
        if out.status.success() && !out.stdout.is_empty() {
            return Some(out.stdout);
        }
    }
    None
}

fn encode(img: image::DynamicImage) -> Option<Vec<u8>> {
    let thumb = img.thumbnail(MAX_SIDE, MAX_SIDE).to_rgb8();
    let mut buf = Cursor::new(Vec::new());
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 80)
        .encode_image(&thumb)
        .ok()?;
    Some(buf.into_inner())
}

pub fn seal(
    bytes: &[u8],
    vault: &VaultId,
    folder: &FolderId,
    content_hash: &str,
    meta_key: &SecretKey,
) -> Result<Vec<u8>> {
    crypto::encrypt(meta_key, &aad(vault, folder, content_hash), bytes)
}

pub fn open(
    blob: &[u8],
    vault: &VaultId,
    folder: &FolderId,
    content_hash: &str,
    meta_key: &SecretKey,
) -> Result<Vec<u8>> {
    crypto::decrypt(meta_key, &aad(vault, folder, content_hash), blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_thumbnail_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.png");
        let img = image::RgbImage::from_fn(900, 600, |x, y| {
            image::Rgb([(x % 255) as u8, (y % 255) as u8, 90])
        });
        img.save(&p).unwrap();
        let t = make(&p, "big.png").expect("thumbnail");
        let decoded = image::load_from_memory(&t).unwrap();
        assert!(decoded.width() <= MAX_SIDE && decoded.height() <= MAX_SIDE);
        let key = SecretKey::random();
        let (v, f) = (VaultId::random(), FolderId::random());
        let sealed = seal(&t, &v, &f, "abc", &key).unwrap();
        assert_eq!(open(&sealed, &v, &f, "abc", &key).unwrap(), t);
        assert!(open(&sealed, &v, &f, "other", &key).is_err());
        assert!(make(&p, "notes.txt").is_none());
    }
}
