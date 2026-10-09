// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! In-app viewer: `GET /api/view?folder=<name>&path=<relative path>&token=<t>`
//! answers with a file's plaintext straight from memory, so that a folder kept
//! encrypted on a phone can show pictures, video, audio and text without a
//! decrypted copy ever reaching the device's storage (unlike /api/open and
//! /api/fetch, which write the file into the folder).
//!
//! HTTP range requests are honoured so that video and audio can seek; only the
//! chunks covering the requested bytes are fetched and decrypted. Responses
//! carry `Cache-Control: no-store` so the web view keeps no copy either, and
//! types that could run script in this origin (HTML, SVG, XML) are sent as
//! plain text.

use crate::desktop::Shared;
use anyhow::Result;
use tiny_http::{Header, Request, Response};

/// Largest file answered in one piece to a request without a Range header
/// (pictures, text); the bytes are held in memory while they are sent.
const MAX_WHOLE: u64 = 256 << 20;
/// Largest ranged answer; players ask again for the rest.
const MAX_WINDOW: u64 = 8 << 20;

/// What a `Range` header asks for, against a file of a known size.
#[derive(Debug, PartialEq, Eq)]
pub enum ByteRange {
    /// No (usable) range: the whole file with status 200.
    Whole,
    /// `start..end` (end exclusive) with status 206.
    Part(u64, u64),
    /// Status 416: the range starts past the end of the file.
    Unsatisfiable,
}

/// Parse a `Range` header (`bytes=a-b`, `bytes=a-`, `bytes=-n`). Anything
/// else, including several ranges, is ignored and the whole file is sent, as
/// RFC 9110 allows. Ranged answers are capped at `window` bytes.
pub fn parse_range(header: Option<&str>, size: u64, window: u64) -> ByteRange {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return ByteRange::Whole;
    };
    if spec.contains(',') {
        return ByteRange::Whole;
    }
    let Some((a, b)) = spec.trim().split_once('-') else {
        return ByteRange::Whole;
    };
    let (a, b) = (a.trim(), b.trim());
    let (start, end) = if a.is_empty() {
        // Suffix: the last n bytes.
        let Ok(n) = b.parse::<u64>() else {
            return ByteRange::Whole;
        };
        if n == 0 || size == 0 {
            return ByteRange::Unsatisfiable;
        }
        (size.saturating_sub(n), size)
    } else {
        let Ok(start) = a.parse::<u64>() else {
            return ByteRange::Whole;
        };
        let end = if b.is_empty() {
            size
        } else {
            match b.parse::<u64>() {
                Ok(last) if last >= start => last.saturating_add(1).min(size),
                _ => return ByteRange::Whole,
            }
        };
        (start, end)
    };
    if start >= size {
        return ByteRange::Unsatisfiable;
    }
    ByteRange::Part(start, end.min(start.saturating_add(window.max(1))))
}

/// Content type for the viewer, from the file name. Anything a browser would
/// render as a document with script (HTML, SVG, XML) is plain text here.
pub fn content_type(path: &str) -> &'static str {
    let ext = path
        .rsplit('/')
        .next()
        .and_then(|n| n.rsplit_once('.'))
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "bmp" => "image/bmp",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        "3gp" => "video/3gpp",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "pdf" => "application/pdf",
        "txt" | "md" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "svg" | "js" | "css"
        | "rs" | "py" | "sh" | "yaml" | "yml" | "toml" | "ini" | "conf" => {
            "text/plain; charset=utf-8"
        }
        _ => "application/octet-stream",
    }
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn plain(status: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(msg)
        .with_status_code(status)
        .with_header(header("Cache-Control", "no-store"))
}

/// Answer one /api/view request (the token was checked by the caller).
pub fn respond(
    state: &Shared,
    request: Request,
    folder: Option<String>,
    path: Option<String>,
) -> Result<()> {
    let (Some(folder), Some(path)) = (folder, path) else {
        return Ok(request.respond(plain(400, "folder and path query parameters required"))?);
    };
    let range = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Range"))
        .map(|h| h.value.as_str().to_string());
    // Decrypt under the state lock, like /api/open; the bytes stay in memory.
    let result = {
        let mut st = state.lock().unwrap();
        match st.engine.as_mut() {
            None => Err(plain(400, "vault is locked")),
            Some(engine) => match engine.view_size(&folder, &path) {
                Err(e) => Err(plain(404, &format!("{e:#}"))),
                Ok(size) => {
                    let want = parse_range(range.as_deref(), size, MAX_WINDOW);
                    let (start, end) = match want {
                        ByteRange::Whole if size > MAX_WHOLE => {
                            return Ok(request.respond(plain(
                                413,
                                "file too large to show in one piece; open it in another app",
                            ))?);
                        }
                        ByteRange::Whole => (0, size),
                        ByteRange::Part(s, e) => (s, e),
                        ByteRange::Unsatisfiable => {
                            let r = plain(416, "range not satisfiable")
                                .with_header(header("Content-Range", &format!("bytes */{size}")));
                            return Ok(request.respond(r)?);
                        }
                    };
                    match engine.view_range(&folder, &path, start, end) {
                        Ok(bytes) => {
                            if start == 0 {
                                // Opening a file counts as using it; later ranges do not.
                                let _ = engine.touch_access(&folder, &path);
                            }
                            Ok((want, size, start, bytes))
                        }
                        Err(e) => Err(plain(502, &format!("{e:#}"))),
                    }
                }
            },
        }
    };
    let (want, size, start, bytes) = match result {
        Ok(v) => v,
        Err(r) => return Ok(request.respond(r)?),
    };
    let len = bytes.len() as u64;
    // A Content-Length rather than chunked encoding: media players want it on ranged answers.
    let mut resp = Response::from_data(bytes)
        .with_chunked_threshold(usize::MAX)
        .with_header(header("Content-Type", content_type(&path)))
        .with_header(header("Accept-Ranges", "bytes"))
        .with_header(header("Cache-Control", "no-store"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
        .with_header(header(
            "Content-Security-Policy",
            "sandbox; default-src 'none'",
        ));
    if let ByteRange::Part(..) = want {
        let last = (start + len).saturating_sub(1);
        resp = resp.with_status_code(206).with_header(header(
            "Content-Range",
            &format!("bytes {start}-{last}/{size}"),
        ));
    }
    Ok(request.respond(resp)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        let r = |h: &str, size| parse_range(Some(h), size, 100);
        assert_eq!(parse_range(None, 10, 100), ByteRange::Whole);
        assert_eq!(r("bytes=0-", 10), ByteRange::Part(0, 10));
        assert_eq!(r("bytes=2-5", 10), ByteRange::Part(2, 6));
        assert_eq!(r("bytes=2-50", 10), ByteRange::Part(2, 10));
        assert_eq!(r("bytes=-3", 10), ByteRange::Part(7, 10));
        assert_eq!(r("bytes=-30", 10), ByteRange::Part(0, 10));
        assert_eq!(r("bytes=10-", 10), ByteRange::Unsatisfiable);
        assert_eq!(r("bytes=-0", 10), ByteRange::Unsatisfiable);
        assert_eq!(r("bytes=0-", 0), ByteRange::Unsatisfiable);
        // Malformed, reversed and multiple ranges fall back to the whole file.
        assert_eq!(r("bytes=5-2", 10), ByteRange::Whole);
        assert_eq!(r("bytes=a-b", 10), ByteRange::Whole);
        assert_eq!(r("items=0-1", 10), ByteRange::Whole);
        assert_eq!(r("bytes=0-1,4-5", 10), ByteRange::Whole);
        // Open-ended and large ranges are cut to the window.
        assert_eq!(r("bytes=0-", 1000), ByteRange::Part(0, 100));
        assert_eq!(r("bytes=900-999", 1000), ByteRange::Part(900, 1000));
        assert_eq!(r("bytes=10-999", 1000), ByteRange::Part(10, 110));
    }

    #[test]
    fn content_types_never_run_script() {
        assert_eq!(content_type("a/b/IMG_1.JPG"), "image/jpeg");
        assert_eq!(content_type("clip.mp4"), "video/mp4");
        assert_eq!(content_type("doc.pdf"), "application/pdf");
        for p in ["page.html", "x.HTM", "logo.svg", "feed.xml", "notes.txt"] {
            assert_eq!(content_type(p), "text/plain; charset=utf-8", "{p}");
        }
        assert_eq!(content_type("archive.tar.gz"), "application/octet-stream");
        assert_eq!(content_type("no-extension"), "application/octet-stream");
        assert_eq!(content_type("dir.d/file"), "application/octet-stream");
    }
}
