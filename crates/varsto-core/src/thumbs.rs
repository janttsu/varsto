// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Encrypted thumbnails (F-046): generated once on a device that holds the
//! plaintext, encrypted under the folder metadata key and stored next to the
//! data, so every device of the folder can show previews without downloading
//! or decrypting the file itself. Images are decoded in-process; videos use
//! `ffmpeg` when it is installed, with hardware decoding (`-hwaccel auto`)
//! unless it is turned off (`thumbnails.hwaccel` in `config.json`): when a
//! hardware-decoded attempt fails where software decoding then works, the
//! process remembers it and decodes later videos in software straight away.
//! Thumbnails are derived data and follow the same rule as content: never
//! stored in clear text outside the process.

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// Whether ffmpeg may decode videos on the GPU or another media engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HwAccel {
    /// `-hwaccel auto`, falling back to software decoding.
    #[default]
    Auto,
    /// Software decoding only.
    Off,
}

/// Thumbnail settings of this device (`config.json`, `thumbnails`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThumbnailSettings {
    #[serde(default)]
    pub hwaccel: HwAccel,
}

impl ThumbnailSettings {
    pub fn is_default(&self) -> bool {
        *self == ThumbnailSettings::default()
    }
}

/// Hardware decoding failed in this process where software decoding then
/// worked: later videos go straight to software.
static HW_FAILED: AtomicBool = AtomicBool::new(false);

/// Runs ffmpeg with the given arguments and returns its standard output
/// (None when it fails or takes too long). Tests put a fake in its place.
trait FrameTool {
    fn run(&self, args: &[OsString]) -> Option<Vec<u8>>;
}

struct Ffmpeg(std::path::PathBuf);

impl FrameTool for Ffmpeg {
    fn run(&self, args: &[OsString]) -> Option<Vec<u8>> {
        run_limited(std::process::Command::new(&self.0).args(args))
    }
}

/// JPEG thumbnail bytes for an image or video file, if one can be made.
pub fn make(path: &Path, name: &str) -> Option<Vec<u8>> {
    make_with(path, name, &ThumbnailSettings::default())
}

/// `make` with this device's settings.
pub fn make_with(path: &Path, name: &str, settings: &ThumbnailSettings) -> Option<Vec<u8>> {
    if is_image(name) {
        let reader = image::ImageReader::open(path)
            .ok()?
            .with_guessed_format()
            .ok()?;
        return encode(decode_limited(reader)?);
    }
    if is_video(name) {
        if let Some(tool) = ffmpeg() {
            if let Some(f) = video_frame(&Ffmpeg(tool), path, settings.hwaccel, &HW_FAILED) {
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

/// A frame one second in; short clips have none there, so then the first.
fn video_frame(
    tool: &dyn FrameTool,
    path: &Path,
    hw: HwAccel,
    hw_failed: &AtomicBool,
) -> Option<Vec<u8>> {
    ["1", "0"]
        .into_iter()
        .find_map(|at| frame_at(tool, path, at, hw, hw_failed))
}

/// One frame at `at` seconds: hardware decoding first (unless off or known
/// to fail here), then once in software. Hardware decoding is remembered as
/// failed only when software then succeeds: a file with no frame there, or
/// one ffmpeg cannot read at all, says nothing about the hardware.
fn frame_at(
    tool: &dyn FrameTool,
    path: &Path,
    at: &str,
    hw: HwAccel,
    hw_failed: &AtomicBool,
) -> Option<Vec<u8>> {
    let try_hw = hw == HwAccel::Auto && !hw_failed.load(Ordering::Relaxed);
    if try_hw {
        if let Some(f) = tool
            .run(&ffmpeg_args(path, at, true))
            .filter(|f| !f.is_empty())
        {
            return Some(f);
        }
    }
    let f = tool
        .run(&ffmpeg_args(path, at, false))
        .filter(|f| !f.is_empty())?;
    if try_hw {
        hw_failed.store(true, Ordering::Relaxed);
    }
    Some(f)
}

/// ffmpeg arguments for one JPEG frame: the seek before the input (fast:
/// it jumps to the nearest key frame instead of decoding up to it), no
/// audio, scaled down to MAX_SIDE. With `-hwaccel auto` and no output
/// format, decoded frames come back to system memory, where the scale
/// filter and the JPEG encoder run.
fn ffmpeg_args(path: &Path, at: &str, hw: bool) -> Vec<OsString> {
    let mut a: Vec<OsString> = ["-v", "error", "-nostdin", "-y"]
        .into_iter()
        .map(OsString::from)
        .collect();
    if hw {
        a.extend(["-hwaccel", "auto"].map(OsString::from));
    }
    a.extend(["-ss", at, "-i"].map(OsString::from));
    a.push(path.as_os_str().to_owned());
    a.extend(
        [
            "-an",
            "-frames:v",
            "1",
            "-vf",
            &format!("scale='min({MAX_SIDE},iw)':-2"),
            "-f",
            "image2pipe",
            "-vcodec",
            "mjpeg",
            "-",
        ]
        .map(OsString::from),
    );
    a
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A fake ffmpeg: answers by whether hardware decoding was asked for and
    /// the seek position, and records every call.
    struct Fake {
        hw_works: bool,
        has_frame_at_1: bool,
        calls: Mutex<Vec<(bool, String)>>,
    }

    impl FrameTool for Fake {
        fn run(&self, args: &[OsString]) -> Option<Vec<u8>> {
            let hw = args.iter().any(|a| a == "-hwaccel");
            let ss = args.iter().position(|a| a == "-ss").unwrap();
            let i = args.iter().position(|a| a == "-i").unwrap();
            assert!(ss < i, "the seek comes before the input");
            let at = args[ss + 1].to_string_lossy().into_owned();
            self.calls.lock().unwrap().push((hw, at.clone()));
            if hw && !self.hw_works {
                return None;
            }
            (at == "0" || self.has_frame_at_1).then(|| b"jpeg".to_vec())
        }
    }

    fn fake(hw_works: bool, has_frame_at_1: bool) -> Fake {
        Fake {
            hw_works,
            has_frame_at_1,
            calls: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn hardware_decoding_is_tried_first() {
        let f = fake(true, true);
        let failed = AtomicBool::new(false);
        let p = Path::new("/videos/a.mp4");
        assert_eq!(video_frame(&f, p, HwAccel::Auto, &failed).unwrap(), b"jpeg");
        assert_eq!(*f.calls.lock().unwrap(), vec![(true, "1".to_string())]);
        assert!(!failed.load(Ordering::Relaxed));
        // Off: software only.
        let f = fake(true, true);
        video_frame(&f, p, HwAccel::Off, &failed).unwrap();
        assert_eq!(*f.calls.lock().unwrap(), vec![(false, "1".to_string())]);
    }

    #[test]
    fn a_hardware_failure_falls_back_and_is_remembered() {
        let f = fake(false, true);
        let failed = AtomicBool::new(false);
        let p = Path::new("/videos/a.mp4");
        assert!(video_frame(&f, p, HwAccel::Auto, &failed).is_some());
        assert_eq!(
            *f.calls.lock().unwrap(),
            vec![(true, "1".to_string()), (false, "1".to_string())]
        );
        assert!(failed.load(Ordering::Relaxed));
        // The next video goes straight to software.
        f.calls.lock().unwrap().clear();
        assert!(video_frame(&f, p, HwAccel::Auto, &failed).is_some());
        assert_eq!(*f.calls.lock().unwrap(), vec![(false, "1".to_string())]);
    }

    #[test]
    fn a_short_clip_does_not_count_against_the_hardware() {
        // No frame at one second, in hardware or software: the first frame
        // is taken in hardware, and hardware decoding stays on.
        let f = fake(true, false);
        let failed = AtomicBool::new(false);
        let p = Path::new("/videos/short.mp4");
        assert!(video_frame(&f, p, HwAccel::Auto, &failed).is_some());
        assert_eq!(
            *f.calls.lock().unwrap(),
            vec![
                (true, "1".to_string()),
                (false, "1".to_string()),
                (true, "0".to_string())
            ]
        );
        assert!(!failed.load(Ordering::Relaxed));
        // Nothing decodes at all: no frame, nothing remembered.
        struct Broken;
        impl FrameTool for Broken {
            fn run(&self, _: &[OsString]) -> Option<Vec<u8>> {
                Some(Vec::new())
            }
        }
        assert!(video_frame(&Broken, p, HwAccel::Auto, &failed).is_none());
        assert!(!failed.load(Ordering::Relaxed));
    }

    #[test]
    fn settings_parse() {
        let s: ThumbnailSettings = serde_json::from_str("{}").unwrap();
        assert!(s.is_default());
        let s: ThumbnailSettings = serde_json::from_str(r#"{"hwaccel":"off"}"#).unwrap();
        assert_eq!(s.hwaccel, HwAccel::Off);
        assert!(serde_json::from_str::<ThumbnailSettings>(r#"{"hwaccel":"cuda"}"#).is_err());
    }

    /// With a real ffmpeg: a two-second test video thumbnailed with hardware
    /// decoding (falling back where there is none) and in software.
    #[test]
    #[ignore]
    fn real_ffmpeg_both_ways() {
        let Some(tool) = ffmpeg() else {
            eprintln!("no ffmpeg here");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let video = dir.path().join("test.mp4");
        let ok = std::process::Command::new(&tool)
            .args([
                "-v",
                "error",
                "-nostdin",
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=2:size=640x360:rate=25",
                "-pix_fmt",
                "yuv420p",
            ])
            .arg(&video)
            .status()
            .unwrap()
            .success();
        assert!(ok);
        for hw in [HwAccel::Auto, HwAccel::Off] {
            let failed = AtomicBool::new(false);
            let t = std::time::Instant::now();
            let f = video_frame(&Ffmpeg(tool.clone()), &video, hw, &failed).expect("frame");
            let img = image::load_from_memory(&f).unwrap();
            assert!(img.width() <= MAX_SIDE && img.height() <= MAX_SIDE);
            eprintln!(
                "{hw:?}: {}x{} in {:?}, hardware decoding failed: {}",
                img.width(),
                img.height(),
                t.elapsed(),
                failed.load(Ordering::Relaxed)
            );
        }
        let t = make_with(&video, "test.mp4", &ThumbnailSettings::default()).unwrap();
        assert!(normalize(&t).is_some());
    }

    #[test]
    fn image_thumbnail_is_small_and_other_names_make_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.png");
        let img = image::RgbImage::from_fn(900, 600, |x, y| {
            image::Rgb([(x % 255) as u8, (y % 255) as u8, 90])
        });
        img.save(&p).unwrap();
        let t = make(&p, "big.png").expect("thumbnail");
        let decoded = image::load_from_memory(&t).unwrap();
        assert!(decoded.width() <= MAX_SIDE && decoded.height() <= MAX_SIDE);
        assert!(make(&p, "notes.txt").is_none());
        let from_memory = make_from_bytes(&std::fs::read(&p).unwrap(), "big.png").unwrap();
        assert!(image::load_from_memory(&from_memory).unwrap().width() <= MAX_SIDE);
    }
}
