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
        let reader = image::ImageReader::open(path)
            .ok()?
            .with_guessed_format()
            .ok()?;
        return encode(decode_limited(reader)?);
    }
    if is_video(name) {
        // A frame one second in; short clips have none there, so then the first.
        for at in ["1", "0"] {
            if let Some(f) = ffmpeg_frame(path, at) {
                return Some(f);
            }
        }
        #[cfg(target_os = "macos")]
        if let Some(f) = quicklook_frame(path) {
            return Some(f);
        }
    }
    None
}

/// Where ffmpeg is: on PATH, or where package managers put it (a launch
/// agent or a login service gets a short PATH without Homebrew's folder).
pub fn ffmpeg() -> Option<std::path::PathBuf> {
    let exe = if cfg!(windows) {
        "ffmpeg.exe"
    } else {
        "ffmpeg"
    };
    let mut dirs: Vec<std::path::PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    for d in [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/opt/local/bin",
        "/usr/bin",
        "/snap/bin",
    ] {
        dirs.push(d.into());
    }
    dirs.into_iter().map(|d| d.join(exe)).find(|p| p.is_file())
}

/// Whether this device can make video thumbnails itself.
pub fn video_tool_available() -> bool {
    ffmpeg().is_some() || (cfg!(target_os = "macos") && Path::new("/usr/bin/qlmanage").exists())
}

/// Run a command for at most FFMPEG_TIMEOUT and return its standard output
/// (at most MAX_THUMB_BYTES), or None when it fails or takes too long.
fn run_limited(cmd: &mut std::process::Command) -> Option<Vec<u8>> {
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    // Read on a thread so a large frame cannot fill the pipe and stall the
    // tool; a hostile or broken video must not keep it busy forever.
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(
            &mut std::io::Read::take(&mut stdout, MAX_THUMB_BYTES as u64 + 1),
            &mut buf,
        );
        buf
    });
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < FFMPEG_TIMEOUT => {
                std::thread::sleep(std::time::Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let ok = child.wait().ok()?.success();
    let out = reader.join().ok()?;
    (ok && out.len() <= MAX_THUMB_BYTES).then_some(out)
}

fn ffmpeg_frame(path: &Path, at: &str) -> Option<Vec<u8>> {
    let frame = run_limited(
        std::process::Command::new(ffmpeg()?)
            .args(["-v", "error", "-y", "-ss", at, "-i"])
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
            ]),
    )?;
    (!frame.is_empty()).then_some(frame)
}

/// macOS without ffmpeg: Quick Look makes a picture of any video the system
/// can play, into a private temporary folder.
#[cfg(target_os = "macos")]
fn quicklook_frame(path: &Path) -> Option<Vec<u8>> {
    let dir = tempfile::tempdir().ok()?;
    run_limited(
        std::process::Command::new("/usr/bin/qlmanage")
            .args(["-t", "-s", &MAX_SIDE.to_string(), "-o"])
            .arg(dir.path())
            .arg(path),
    )?;
    let png = std::fs::read_dir(dir.path())
        .ok()?
        .filter_map(|e| e.ok())
        .find(|e| e.path().extension().is_some_and(|x| x == "png"))?;
    normalize(&std::fs::read(png.path()).ok()?)
}

/// A thumbnail handed in by the app around the service (a phone makes video
/// frames with its own media framework): decoded with limits and encoded
/// again, so only a small JPEG is ever stored.
pub fn normalize(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > MAX_THUMB_BYTES * 4 {
        return None;
    }
    let reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    encode(decode_limited(reader)?)
}

/// Longest ffmpeg may take for one frame.
const FFMPEG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// Largest thumbnail kept.
const MAX_THUMB_BYTES: usize = 4 << 20;

/// Decode with limits: an image that claims huge dimensions (a decompression
/// bomb) is refused before its pixels are allocated.
fn decode_limited<R: std::io::BufRead + std::io::Seek>(
    mut reader: image::ImageReader<R>,
) -> Option<image::DynamicImage> {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(20_000);
    limits.max_image_height = Some(20_000);
    limits.max_alloc = Some(256 << 20);
    reader.limits(limits);
    reader.decode().ok()
}

/// JPEG thumbnail of a picture held in memory (folders kept encrypted on a
/// device have no plain file to read). Videos need a file and get none.
pub fn make_from_bytes(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    if !is_image(name) {
        return None;
    }
    let reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    encode(decode_limited(reader)?)
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
        let from_memory = make_from_bytes(&std::fs::read(&p).unwrap(), "big.png").unwrap();
        assert!(image::load_from_memory(&from_memory).unwrap().width() <= MAX_SIDE);
    }
}
