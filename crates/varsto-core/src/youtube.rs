// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! What YouTube jobs need apart from the engine (`engine::youtube`,
//! `docs/youtube.md`, `docs/spec/alpha-0-format.md` section "YouTube
//! channels through yt-dlp"): reading channel, playlist and video
//! addresses, video ids in addresses and file names, the polite yt-dlp
//! arguments, the flat listing yt-dlp prints, the names files get in the
//! folder, and the backoff of videos that failed.
//!
//! Nothing here runs yt-dlp or touches the network.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// The extractor whose ids Varsto tracks (`youtube:<id>` in import books).
pub const EXTRACTOR: &str = "youtube";

/// What a job's address names.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UrlKind {
    Channel,
    Playlist,
    Video,
}

impl UrlKind {
    pub fn as_str(self) -> &'static str {
        match self {
            UrlKind::Channel => "channel",
            UrlKind::Playlist => "playlist",
            UrlKind::Video => "video",
        }
    }
}

/// A job's address in one canonical form, so that the same channel given
/// twice (with or without `www.`, `/videos`, tracking parameters) is the
/// same source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceUrl {
    pub kind: UrlKind,
    /// `https://www.youtube.com/@name/videos`,
    /// `https://www.youtube.com/playlist?list=...`,
    /// `https://www.youtube.com/watch?v=...`.
    pub canonical: String,
    /// For people and default folder names: `@name`, the playlist id, the
    /// video id.
    pub label: String,
}

/// A YouTube video id: 11 characters of `A-Z a-z 0-9 - _`.
pub fn is_video_id(s: &str) -> bool {
    s.len() == 11
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_list_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Split `https://host/path?query#frag` into (host, path segments, query
/// pairs). Only http(s) and bare `host/path` forms are accepted.
/// (host, path segments, query pairs)
type UrlParts = (String, Vec<String>, Vec<(String, String)>);

fn split_url(raw: &str) -> Option<UrlParts> {
    let t = raw.trim();
    let rest = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    let rest = rest.split('#').next().unwrap_or("");
    let (before_query, query) = match rest.split_once('?') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    let mut parts = before_query.split('/');
    let host = parts.next()?.to_ascii_lowercase();
    if host.is_empty() || host.contains(' ') {
        return None;
    }
    let segs: Vec<String> = parts
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let pairs = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (p.to_string(), String::new()),
        })
        .collect();
    Some((host, segs, pairs))
}

fn youtube_host(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host);
    matches!(
        h,
        "youtube.com" | "www.youtube.com" | "m.youtube.com" | "music.youtube.com" | "youtu.be"
    )
}

/// The video id an address names: `watch?v=`, `youtu.be/`, `/shorts/`,
/// `/live/`, `/embed/`, `/v/`, or a bare id.
pub fn video_id_from_url(raw: &str) -> Option<String> {
    let t = raw.trim();
    if is_video_id(t) {
        return Some(t.to_string());
    }
    let (host, segs, pairs) = split_url(t)?;
    if !youtube_host(&host) {
        return None;
    }
    if host.starts_with("youtu.be") {
        return segs.first().filter(|s| is_video_id(s)).cloned();
    }
    if segs.first().map(String::as_str) == Some("watch") {
        return pairs
            .iter()
            .find(|(k, _)| k == "v")
            .map(|(_, v)| v.clone())
            .filter(|v| is_video_id(v));
    }
    match (segs.first().map(String::as_str), segs.get(1)) {
        (Some("shorts" | "live" | "embed" | "v"), Some(id)) if is_video_id(id) => Some(id.clone()),
        _ => None,
    }
}

/// Read a channel, playlist or video address (see [`SourceUrl`]).
pub fn parse_source_url(raw: &str) -> Result<SourceUrl> {
    let Some((host, segs, pairs)) = split_url(raw) else {
        bail!("not an address: {raw}");
    };
    if !youtube_host(&host) {
        bail!("{raw} is not a YouTube address (youtube.com or youtu.be)");
    }
    let q = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let first = segs.first().map(String::as_str).unwrap_or("");
    // A playlist page; a watch address with a list is the video (yt-dlp's
    // own rule with --no-playlist).
    if first == "playlist" {
        let list = q("list").filter(|l| is_list_id(l));
        let Some(list) = list else {
            bail!("{raw} names no playlist (list=...)");
        };
        return Ok(SourceUrl {
            kind: UrlKind::Playlist,
            canonical: format!("https://www.youtube.com/playlist?list={list}"),
            label: list,
        });
    }
    if let Some(id) = video_id_from_url(raw) {
        return Ok(SourceUrl {
            kind: UrlKind::Video,
            canonical: format!("https://www.youtube.com/watch?v={id}"),
            label: id,
        });
    }
    // Channels: /@handle, /channel/UC..., /c/name, /user/name, with an
    // optional tab. Without a tab (or with /featured) the uploads are
    // meant: /videos, as in `yt-dlp --flat-playlist .../videos`.
    let (base, label, rest): (String, String, &[String]) = if let Some(h) = first.strip_prefix('@')
    {
        if h.is_empty() {
            bail!("{raw} names no channel");
        }
        (format!("@{h}"), format!("@{h}"), &segs[1..])
    } else if matches!(first, "channel" | "c" | "user") && segs.len() >= 2 {
        (format!("{first}/{}", segs[1]), segs[1].clone(), &segs[2..])
    } else {
        bail!("{raw} is not a YouTube channel, playlist or video address");
    };
    if base.contains(['"', '\'', '\\', ' ']) {
        bail!("{raw} is not a YouTube channel address");
    }
    let tab = match rest.first().map(String::as_str) {
        None | Some("featured") | Some("videos") => "videos",
        Some(t @ ("shorts" | "streams" | "live" | "playlists")) => {
            if t == "live" {
                "streams"
            } else {
                t
            }
        }
        Some(other) => bail!("{raw}: the channel tab {other} is not one Varsto reads (videos, shorts, streams, playlists)"),
    };
    Ok(SourceUrl {
        kind: UrlKind::Channel,
        canonical: format!("https://www.youtube.com/{base}/{tab}"),
        label,
    })
}

/// The video id in a file name written with yt-dlp's default template
/// `%(title)s [%(id)s].%(ext)s` (the last `[...]` that holds an id and is
/// followed by the extension, or ends the name).
pub fn id_from_filename(name: &str) -> Option<String> {
    let base = name.rsplit('/').next().unwrap_or(name);
    let mut end = base.len();
    while let Some(close) = base[..end].rfind(']') {
        let after = &base[close + 1..];
        let open = base[..close].rfind('[');
        if let Some(open) = open {
            let id = &base[open + 1..close];
            if is_video_id(id) && (after.is_empty() || after.starts_with('.')) {
                return Some(id.to_string());
            }
        }
        end = close;
    }
    None
}

/// The suffix after `[<id>]` in a file name: `.mp4`, `.info.json`,
/// `.en.vtt` (empty when nothing follows).
pub fn suffix_after_id<'a>(name: &'a str, id: &str) -> Option<&'a str> {
    let base = name.rsplit('/').next().unwrap_or(name);
    let mark = format!("[{id}]");
    let at = base.rfind(&mark)?;
    Some(&base[at + mark.len()..])
}

/// The content id of one file of one video in an import book:
/// `youtube:<video id>:<suffix>`.
pub fn content_id(video: &str, suffix: &str) -> String {
    format!("{EXTRACTOR}:{video}:{suffix}")
}

/// The video id of a content id written by [`content_id`].
pub fn video_of_content_id(id: &str) -> Option<&str> {
    let rest = id.strip_prefix(EXTRACTOR)?.strip_prefix(':')?;
    let (v, _) = rest.split_once(':')?;
    is_video_id(v).then_some(v)
}

// ----- yt-dlp arguments -----------------------------------------------------------

/// How politely a job downloads. The defaults are the proven manual
/// workflow: one video at a time, 25 to 65 seconds between downloads, two
/// seconds between requests, 600 kB/s, one fragment at a time, errors of
/// one video never stop the rest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Throttle {
    pub sleep_min: u32,
    pub sleep_max: u32,
    pub sleep_requests: u32,
    /// yt-dlp's `--limit-rate` (`600K`, `1.5M`); empty: no limit.
    pub rate: String,
    pub concurrent_fragments: u32,
    /// yt-dlp's `--format`; empty: yt-dlp's default (best).
    #[serde(default)]
    pub format: String,
    /// yt-dlp's `--cookies-from-browser` (`firefox`, `chrome:Profile 1`).
    #[serde(default)]
    pub cookies_from_browser: String,
    /// More arguments passed as they are, before the address.
    #[serde(default)]
    pub extra: Vec<String>,
}

impl Default for Throttle {
    fn default() -> Self {
        Throttle {
            sleep_min: 25,
            sleep_max: 65,
            sleep_requests: 2,
            rate: "600K".into(),
            concurrent_fragments: 1,
            format: String::new(),
            cookies_from_browser: String::new(),
            extra: Vec::new(),
        }
    }
}

/// `25-65` or `30` (seconds between downloads).
pub fn parse_sleep(s: &str) -> Result<(u32, u32)> {
    let t = s.trim();
    let num = |x: &str| -> Result<u32> {
        x.trim()
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("not a number of seconds: {x} (use e.g. 25-65)"))
    };
    let (a, b) = match t.split_once('-') {
        Some((a, b)) => (num(a)?, num(b)?),
        None => {
            let v = num(t)?;
            (v, v)
        }
    };
    if a > b {
        bail!("the shortest pause ({a} s) is longer than the longest ({b} s)");
    }
    if b > 86_400 {
        bail!("a pause of more than a day between videos is not useful");
    }
    Ok((a, b))
}

/// yt-dlp's rate syntax: a number with an optional K, M or G (`600K`,
/// `1.5M`); `0`, `none` or empty for no limit (stored as empty).
pub fn parse_rate(s: &str) -> Result<String> {
    let t = s.trim();
    if t.is_empty() || t == "0" || t.eq_ignore_ascii_case("none") {
        return Ok(String::new());
    }
    let (num, unit) = match t.char_indices().find(|(_, c)| c.is_ascii_alphabetic()) {
        Some((i, _)) => t.split_at(i),
        None => (t, ""),
    };
    let ok_num = num.parse::<f64>().is_ok_and(|v| v > 0.0 && v.is_finite());
    let unit_u = unit.to_ascii_uppercase();
    let ok_unit = matches!(unit_u.as_str(), "" | "K" | "M" | "G" | "KB" | "MB" | "GB");
    if !ok_num || !ok_unit {
        bail!("not a download rate: {s} (use e.g. 600K or 1.5M)");
    }
    Ok(format!("{num}{}", unit_u.trim_end_matches('B')))
}

impl Throttle {
    /// The arguments every download gets (before the per-call ones).
    pub fn download_args(&self) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "--sleep-interval".into(),
            self.sleep_min.to_string(),
            "--max-sleep-interval".into(),
            self.sleep_max.max(self.sleep_min).to_string(),
            "--sleep-requests".into(),
            self.sleep_requests.to_string(),
        ];
        if !self.rate.is_empty() {
            a.push("--limit-rate".into());
            a.push(self.rate.clone());
        }
        a.extend([
            "--concurrent-fragments".into(),
            self.concurrent_fragments.max(1).to_string(),
            "--ignore-errors".into(),
            "--no-abort-on-error".into(),
        ]);
        a.extend(self.common_args());
        a
    }

    /// What every call gets: the format, cookies and the extra arguments.
    pub fn common_args(&self) -> Vec<String> {
        let mut a = Vec::new();
        if !self.format.is_empty() {
            a.push("--format".into());
            a.push(self.format.clone());
        }
        if !self.cookies_from_browser.is_empty() {
            a.push("--cookies-from-browser".into());
            a.push(self.cookies_from_browser.clone());
        }
        a.extend(self.extra.iter().cloned());
        a
    }

    pub fn describe(&self) -> String {
        format!(
            "{}-{} s between videos, {} s between requests, {}, {} fragment(s) at a time{}",
            self.sleep_min,
            self.sleep_max.max(self.sleep_min),
            self.sleep_requests,
            if self.rate.is_empty() {
                "no rate limit".to_string()
            } else {
                format!("at most {}/s", self.rate)
            },
            self.concurrent_fragments.max(1),
            if self.format.is_empty() {
                String::new()
            } else {
                format!(", format {}", self.format)
            }
        )
    }
}

/// Extra arguments that would undo what Varsto relies on (where files go,
/// one video per call) are refused.
pub fn check_extra_arg(a: &str) -> Result<()> {
    const REFUSED: &[&str] = &[
        "-o",
        "--output",
        "-P",
        "--paths",
        "--exec",
        "--batch-file",
        "-a",
        "--load-info-json",
        "--yes-playlist",
        "--no-continue",
        "--force-overwrites",
        "--config-locations",
    ];
    let name = a.split('=').next().unwrap_or(a);
    if REFUSED.contains(&name) {
        bail!("{name} cannot be passed: Varsto decides where yt-dlp writes and what it runs");
    }
    Ok(())
}

// ----- the flat listing -------------------------------------------------------------

/// The `--print` template of the flat listing: id, address, title.
pub const LIST_TEMPLATE: &str = "%(id)s\t%(url)s\t%(title)s";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlatEntry {
    pub id: String,
    pub url: String,
    pub title: String,
}

/// One line of the flat listing; `None` for lines that are not a video
/// (a channel's tab, a deleted entry without an id).
pub fn parse_flat_line(line: &str) -> Option<FlatEntry> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut it = line.splitn(3, '\t');
    let id = it.next()?.trim();
    let url = it.next().unwrap_or("").trim();
    let title = it.next().unwrap_or("").trim();
    if !is_video_id(id) {
        // A playlist entry whose id is missing: take it from the address.
        let from_url = video_id_from_url(url)?;
        return Some(FlatEntry {
            url: format!("https://www.youtube.com/watch?v={from_url}"),
            id: from_url,
            title: clean_na(title),
        });
    }
    let url = if url.is_empty() || url == "NA" || video_id_from_url(url).as_deref() != Some(id) {
        format!("https://www.youtube.com/watch?v={id}")
    } else {
        url.to_string()
    };
    Some(FlatEntry {
        id: id.to_string(),
        url,
        title: clean_na(title),
    })
}

fn clean_na(s: &str) -> String {
    if s == "NA" {
        String::new()
    } else {
        s.to_string()
    }
}

/// Every video of a listing, first appearance kept.
pub fn parse_flat_listing(text: &str) -> Vec<FlatEntry> {
    let mut seen = std::collections::BTreeSet::new();
    text.lines()
        .filter_map(parse_flat_line)
        .filter(|e| seen.insert(e.id.clone()))
        .collect()
}

/// The size yt-dlp's probe printed (`%(filesize,filesize_approx)s`):
/// bytes, or `None` for `NA`.
pub fn parse_probe_size(out: &str) -> Option<u64> {
    out.lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .and_then(|l| l.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0)
        .map(|v| v as u64)
}

// ----- names in the folder ------------------------------------------------------------

/// One path component from text: no `/`, `\`, `:` or control characters,
/// no leading dot (hidden, and `.varsto` names are Varsto's own), at most
/// `max` bytes on a character boundary.
pub fn clean_component(raw: &str, max: usize, fallback: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' => '-',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    let mut t = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    while t.starts_with('.') {
        t.remove(0);
    }
    let mut t = t.trim().to_string();
    if t.len() > max {
        let mut cut = max;
        while !t.is_char_boundary(cut) {
            cut -= 1;
        }
        t.truncate(cut);
        t = t.trim_end().to_string();
    }
    if t.is_empty() {
        fallback.to_string()
    } else {
        t
    }
}

/// `YYYYMMDD` as `YYYY-MM-DD`.
pub fn upload_date(raw: &str) -> Option<String> {
    let t = raw.trim();
    (t.len() == 8 && t.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("{}-{}-{}", &t[0..4], &t[4..6], &t[6..8]))
}

/// The path of one file of a video in the folder:
/// `<channel>/<upload date> <title> [<id>]<suffix>`.
pub fn video_path(
    channel: &str,
    date: Option<&str>,
    title: &str,
    id: &str,
    suffix: &str,
) -> String {
    let ch = clean_component(channel, 100, "unknown channel");
    let title = clean_component(title, 150, "untitled");
    let name = match date {
        Some(d) => format!("{d} {title} [{id}]{suffix}"),
        None => format!("{title} [{id}]{suffix}"),
    };
    format!("{ch}/{name}")
}

/// What a video's `.info.json` says about where it goes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VideoMeta {
    pub channel: String,
    pub date: Option<String>,
    pub title: String,
}

pub fn read_info_json(bytes: &[u8]) -> VideoMeta {
    let v: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let channel = [
        s("channel"),
        s("uploader"),
        s("channel_id"),
        s("uploader_id"),
    ]
    .into_iter()
    .find(|x| !x.is_empty())
    .unwrap_or_default();
    VideoMeta {
        channel,
        date: upload_date(&s("upload_date")),
        title: s("title"),
    }
}

/// Of the files yt-dlp left for one video (`<id>.<rest>`), which are kept
/// in the folder: the media file, `.info.json`, thumbnails and subtitles,
/// never unfinished pieces (`.part`, `.ytdl`, `.temp`, `.fNNN.` streams
/// before merging).
pub fn kept_file(id: &str, name: &str) -> Option<FileRole> {
    let rest = name.strip_prefix(id)?.strip_prefix('.')?;
    let last = rest.rsplit('.').next().unwrap_or("");
    if rest.is_empty()
        || matches!(last, "part" | "ytdl" | "temp" | "tmp")
        || last.starts_with("part-Frag")
        || rest.split('.').any(|p| {
            p.len() > 1 && p.starts_with('f') && p[1..].bytes().all(|b| b.is_ascii_digit())
        })
    {
        return None;
    }
    let ext = rest.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    Some(if rest == "info.json" {
        FileRole::Info
    } else if matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "webp") {
        FileRole::Thumbnail
    } else if matches!(
        ext.as_str(),
        "vtt" | "srt" | "ass" | "lrc" | "ttml" | "srv3"
    ) {
        FileRole::Subtitles
    } else if matches!(ext.as_str(), "json" | "description") {
        FileRole::Other
    } else {
        FileRole::Media
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileRole {
    Media,
    Info,
    Thumbnail,
    Subtitles,
    Other,
}

// ----- failures ------------------------------------------------------------------------

/// Seconds to wait before trying a failed video again: an hour, then four
/// times longer each time, at most a week.
pub fn backoff_secs(attempts: u32) -> i64 {
    let mut s: i64 = 3600;
    for _ in 1..attempts.max(1) {
        s = s.saturating_mul(4);
        if s >= 7 * 86_400 {
            return 7 * 86_400;
        }
    }
    s.min(7 * 86_400)
}

/// After this many failed attempts a video is given up (until `youtube
/// resume` or `youtube run --retry-failed`).
pub const MAX_ATTEMPTS: u32 = 6;

/// The reason yt-dlp gave, from its error output: the last `ERROR:` line
/// without the extractor prefix, else the last non-empty line.
pub fn error_reason(stderr: &str) -> String {
    let last_error = stderr
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| l.starts_with("ERROR:"));
    let line = last_error
        .or_else(|| stderr.lines().rev().map(str::trim).find(|l| !l.is_empty()))
        .unwrap_or("yt-dlp failed without saying why");
    let mut t = line.trim_start_matches("ERROR:").trim().to_string();
    // "[youtube] <id>: Private video. Sign in ..." -> "Private video. Sign in ..."
    if t.starts_with('[') {
        if let Some((_, rest)) = t.split_once("] ") {
            t = rest.to_string();
            if let Some((maybe_id, rest)) = t.split_once(": ") {
                if is_video_id(maybe_id) {
                    t = rest.to_string();
                }
            }
        }
    }
    t.chars().take(300).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_ids_in_addresses() {
        let id = "aBcDeFgHi_-";
        for u in [
            "https://www.youtube.com/watch?v=aBcDeFgHi_-",
            "https://youtube.com/watch?feature=share&v=aBcDeFgHi_-&t=10",
            "http://m.youtube.com/watch?v=aBcDeFgHi_-",
            "https://youtu.be/aBcDeFgHi_-?si=xyz",
            "https://www.youtube.com/shorts/aBcDeFgHi_-",
            "https://www.youtube.com/live/aBcDeFgHi_-",
            "https://www.youtube.com/embed/aBcDeFgHi_-",
            "youtube.com/watch?v=aBcDeFgHi_-",
            "aBcDeFgHi_-",
        ] {
            assert_eq!(video_id_from_url(u).as_deref(), Some(id), "{u}");
        }
        for u in [
            "https://www.youtube.com/watch?v=short",
            "https://example.com/watch?v=aBcDeFgHi_-",
            "https://www.youtube.com/@SomeChannel",
            "aBcDeFgHi_-x",
        ] {
            assert_eq!(video_id_from_url(u), None, "{u}");
        }
    }

    #[test]
    fn source_addresses_are_canonical() {
        let c = parse_source_url("https://youtube.com/@ExampleMakers").unwrap();
        assert_eq!(c.kind, UrlKind::Channel);
        assert_eq!(c.canonical, "https://www.youtube.com/@ExampleMakers/videos");
        assert_eq!(c.label, "@ExampleMakers");
        for same in [
            "https://www.youtube.com/@ExampleMakers/videos",
            "www.youtube.com/@ExampleMakers/featured?si=1",
            "https://m.youtube.com/@ExampleMakers/",
        ] {
            assert_eq!(parse_source_url(same).unwrap(), c, "{same}");
        }
        let s = parse_source_url("https://www.youtube.com/@ExampleMakers/shorts").unwrap();
        assert_eq!(s.canonical, "https://www.youtube.com/@ExampleMakers/shorts");
        let ch =
            parse_source_url("https://www.youtube.com/channel/UCabcdefghij0123456789").unwrap();
        assert_eq!(
            ch.canonical,
            "https://www.youtube.com/channel/UCabcdefghij0123456789/videos"
        );
        let p =
            parse_source_url("https://www.youtube.com/playlist?list=PLexample123&si=q").unwrap();
        assert_eq!(p.kind, UrlKind::Playlist);
        assert_eq!(
            p.canonical,
            "https://www.youtube.com/playlist?list=PLexample123"
        );
        let v = parse_source_url("https://youtu.be/aBcDeFgHi_-").unwrap();
        assert_eq!(v.kind, UrlKind::Video);
        assert_eq!(v.canonical, "https://www.youtube.com/watch?v=aBcDeFgHi_-");
        // A watch address inside a playlist is the video.
        let w = parse_source_url("https://www.youtube.com/watch?v=aBcDeFgHi_-&list=PLx").unwrap();
        assert_eq!(w.kind, UrlKind::Video);
        assert!(parse_source_url("https://vimeo.com/123").is_err());
        assert!(parse_source_url("https://www.youtube.com/").is_err());
        assert!(parse_source_url("https://www.youtube.com/@x/community").is_err());
        assert!(parse_source_url("https://www.youtube.com/playlist").is_err());
    }

    #[test]
    fn ids_in_file_names() {
        assert_eq!(
            id_from_filename("Some talk [aBcDeFgHi_-].mp4").as_deref(),
            Some("aBcDeFgHi_-")
        );
        assert_eq!(
            id_from_filename("dir/2024-01-02 A [b] title [aBcDeFgHi_-].info.json").as_deref(),
            Some("aBcDeFgHi_-")
        );
        assert_eq!(
            id_from_filename("x [aBcDeFgHi_-]").as_deref(),
            Some("aBcDeFgHi_-")
        );
        // Not followed by the extension, or not an id.
        assert_eq!(id_from_filename("x [aBcDeFgHi_-] y.mp4"), None);
        assert_eq!(id_from_filename("x [short].mp4"), None);
        assert_eq!(id_from_filename("plain.mp4"), None);
        assert_eq!(
            suffix_after_id("a [aBcDeFgHi_-].en.vtt", "aBcDeFgHi_-"),
            Some(".en.vtt")
        );
        let cid = content_id("aBcDeFgHi_-", ".mp4");
        assert_eq!(cid, "youtube:aBcDeFgHi_-:.mp4");
        assert_eq!(video_of_content_id(&cid), Some("aBcDeFgHi_-"));
        assert_eq!(video_of_content_id("dir:1:2:a"), None);
    }

    #[test]
    fn throttle_defaults_are_the_manual_workflow() {
        let t = Throttle::default();
        assert_eq!(
            t.download_args().join(" "),
            "--sleep-interval 25 --max-sleep-interval 65 --sleep-requests 2 --limit-rate 600K --concurrent-fragments 1 --ignore-errors --no-abort-on-error"
        );
        let t = Throttle {
            rate: parse_rate("1.5m").unwrap(),
            format: "bv*[height<=720]+ba/b".into(),
            cookies_from_browser: "firefox".into(),
            extra: vec!["--embed-metadata".into()],
            ..Default::default()
        };
        let a = t.download_args().join(" ");
        assert!(a.contains("--limit-rate 1.5M"), "{a}");
        assert!(a.ends_with(
            "--format bv*[height<=720]+ba/b --cookies-from-browser firefox --embed-metadata"
        ));
        assert_eq!(parse_rate("none").unwrap(), "");
        assert_eq!(parse_rate("600KB").unwrap(), "600K");
        assert!(parse_rate("fast").is_err());
        assert!(parse_rate("-3K").is_err());
        assert_eq!(parse_sleep("25-65").unwrap(), (25, 65));
        assert_eq!(parse_sleep("30").unwrap(), (30, 30));
        assert!(parse_sleep("65-25").is_err());
        assert!(check_extra_arg("--embed-metadata").is_ok());
        assert!(check_extra_arg("-o").is_err());
        assert!(check_extra_arg("--output=x").is_err());
        assert!(check_extra_arg("--exec").is_err());
    }

    #[test]
    fn flat_listing_lines() {
        let text = "aBcDeFgHi_-\thttps://www.youtube.com/watch?v=aBcDeFgHi_-\tFirst\tvideo\n\
                    NA\thttps://www.youtube.com/watch?v=zzzzzzzzzz1\tNA\n\
                    garbage line\n\
                    aBcDeFgHi_-\thttps://www.youtube.com/watch?v=aBcDeFgHi_-\tdup\n\
                    yyyyyyyyyy2\tNA\tThird\n";
        let l = parse_flat_listing(text);
        assert_eq!(l.len(), 3, "{l:?}");
        assert_eq!(l[0].title, "First\tvideo");
        assert_eq!(l[1].id, "zzzzzzzzzz1");
        assert_eq!(l[1].title, "");
        assert_eq!(l[2].url, "https://www.youtube.com/watch?v=yyyyyyyyyy2");
        assert_eq!(parse_probe_size("123456\n"), Some(123456));
        assert_eq!(parse_probe_size("1.5e6"), Some(1_500_000));
        assert_eq!(parse_probe_size("NA"), None);
    }

    #[test]
    fn folder_names_for_videos() {
        assert_eq!(
            video_path(
                "Example: Makers/Lab",
                Some("2024-03-05"),
                "How to\tbuild ../things",
                "aBcDeFgHi_-",
                ".mp4"
            ),
            "Example- Makers-Lab/2024-03-05 How to build ..-things [aBcDeFgHi_-].mp4"
        );
        assert_eq!(
            video_path("", None, "...", "aBcDeFgHi_-", ".info.json"),
            "unknown channel/untitled [aBcDeFgHi_-].info.json"
        );
        let long = "ä".repeat(200);
        let p = video_path("c", None, &long, "aBcDeFgHi_-", ".mp4");
        assert!(p.len() < 180, "{p}");
        let m = read_info_json(
            br#"{"id":"aBcDeFgHi_-","title":"T","channel":"Chan","upload_date":"20240305"}"#,
        );
        assert_eq!(m.channel, "Chan");
        assert_eq!(m.date.as_deref(), Some("2024-03-05"));
        let m = read_info_json(br#"{"uploader":"Up"}"#);
        assert_eq!((m.channel.as_str(), m.date), ("Up", None));
    }

    #[test]
    fn which_downloaded_files_are_kept() {
        let id = "aBcDeFgHi_-";
        assert_eq!(kept_file(id, "aBcDeFgHi_-.mp4"), Some(FileRole::Media));
        assert_eq!(kept_file(id, "aBcDeFgHi_-.webm"), Some(FileRole::Media));
        assert_eq!(kept_file(id, "aBcDeFgHi_-.info.json"), Some(FileRole::Info));
        assert_eq!(kept_file(id, "aBcDeFgHi_-.webp"), Some(FileRole::Thumbnail));
        assert_eq!(
            kept_file(id, "aBcDeFgHi_-.en.vtt"),
            Some(FileRole::Subtitles)
        );
        for partial in [
            "aBcDeFgHi_-.mp4.part",
            "aBcDeFgHi_-.f137.mp4",
            "aBcDeFgHi_-.f251.webm.part",
            "aBcDeFgHi_-.mp4.ytdl",
            "aBcDeFgHi_-.temp",
            "aBcDeFgHi_-.mp4.part-Frag3",
            "other_id_xx.mp4",
        ] {
            assert_eq!(kept_file(id, partial), None, "{partial}");
        }
    }

    #[test]
    fn failures_back_off() {
        assert_eq!(backoff_secs(1), 3600);
        assert_eq!(backoff_secs(2), 4 * 3600);
        assert_eq!(backoff_secs(3), 16 * 3600);
        assert_eq!(backoff_secs(5), 7 * 86_400);
        assert_eq!(backoff_secs(50), 7 * 86_400);
        assert_eq!(
            error_reason("WARNING: x\nERROR: [youtube] aBcDeFgHi_-: Private video. Sign in if you've been granted access\n"),
            "Private video. Sign in if you've been granted access"
        );
        assert_eq!(error_reason("something broke\n\n"), "something broke");
        assert_eq!(error_reason(""), "yt-dlp failed without saying why");
    }
}
