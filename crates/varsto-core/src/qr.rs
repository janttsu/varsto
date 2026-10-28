// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Invitations as `varsto://` links and QR codes
//! (`docs/spec/alpha-0-format.md` section 51).
//!
//! Two links exist:
//!
//! - `varsto://share/request?c=<request>`: a recipient asks for a share; the
//!   value is its request code (public keys and name, nothing secret). The
//!   owner answers on the storage (a grant to the code's key), not with a
//!   link.
//! - `varsto://pair?c=<nine digits>&a=<host:port>,…&rv=<32 hex>`: one of
//!   your devices offers pairing; the code is the pairing password, `rv`
//!   the token its offer is registered under at the rendezvous service
//!   (section 83.3; versions before it refuse a link that carries it).
//!
//! Request codes carry a hybrid Ed25519 + ML-DSA-65 key and a hybrid
//! X25519 + ML-KEM-768 key (about three kilobytes), so a link stores them in
//! a compact binary form, Base32 encoded: the QR code then uses its
//! alphanumeric mode (5.5 bits a character) for nearly all of it. One code
//! cannot hold that, so the link is split into parts that Varsto shows and
//! reads as an animated sequence (`p=<index>.<count>.<group>`).
//!
//! Scanning: [`decode_luma`] and [`decode_image`] find QR codes in a camera
//! frame or a screenshot; [`Assembler`] collects the parts of a split link.

use crate::vault::{ShareRequest, SHARE_REQUEST_PREFIX};
use anyhow::{anyhow, bail, Context, Result};
use data_encoding::BASE32_NOPAD;
use qrcode::{EcLevel, QrCode};
use serde::Serialize;
use std::collections::BTreeMap;

/// The scheme every link starts with (case does not matter).
pub const SCHEME: &str = "varsto://";
/// Longest text a scanned code or a pasted link may be.
pub const MAX_LINK: usize = 16 * 1024;
/// Base32 characters in one part of a split link. A part then fits a
/// version-17 code at error correction M (85 modules a side), which a phone
/// reads from a screen at arm's length and a laptop camera reads at 20 cm.
pub const PART_CHARS: usize = 560;
/// Largest camera frame or image the decoder looks at (pixels a side).
pub const MAX_IMAGE_SIDE: u32 = 4096;

/// Format 3: K6 and K8 public keys.
const REQUEST_FORMAT: u8 = 2;

/// What a link stands for, in the text forms the rest of Varsto uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    /// A share request code, `vsr1.<K6 hex>.<K8 hex>[.<name>]`.
    ShareRequest(String),
    /// A pairing offer: the nine digits, the addresses it listens on and
    /// the token of its rendezvous registration (`rv=`), if it has one.
    Pair {
        code: String,
        addresses: Vec<String>,
        rendezvous: Option<crate::rendezvous::Token>,
    },
}

/// One part of a link that was split for an animated QR sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Part {
    /// `request`.
    pub kind: String,
    /// 1-based.
    pub index: usize,
    pub count: usize,
    /// First four bytes of BLAKE3 of the whole value, hex: tells sequences
    /// apart and checks the reassembled value.
    pub group: String,
    #[serde(skip)]
    pub data: String,
}

/// What one scanned or pasted text is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scanned {
    Link(Link),
    Part(Part),
}

impl Link {
    /// Kind name used by the interface: `request` or `pair`.
    pub fn kind(&self) -> &'static str {
        match self {
            Link::ShareRequest(_) => "request",
            Link::Pair { .. } => "pair",
        }
    }

    /// The link for a request code or a pairing code given as text or as a
    /// link.
    pub fn from_text(s: &str) -> Result<Link> {
        let s = s.trim();
        if is_link(s) {
            return match parse(s)? {
                Scanned::Link(l) => Ok(l),
                Scanned::Part(p) => bail!(
                    "this is part {} of {} of a split code: scan all of them",
                    p.index,
                    p.count
                ),
            };
        }
        if s.starts_with(SHARE_REQUEST_PREFIX) {
            ShareRequest::parse(s)?;
            return Ok(Link::ShareRequest(s.to_string()));
        }
        if crate::pair::normalize(s).is_ok() {
            return Ok(Link::Pair {
                code: crate::pair::normalize(s)?,
                addresses: Vec::new(),
                rendezvous: None,
            });
        }
        if s.starts_with("vst1.") || s.starts_with("vst2.") || s.split('.').count() == 4 {
            bail!("share tokens are gone: the owner adds you with your request code, and you accept the share from the storage it names");
        }
        bail!("not a Varsto request code or pairing code")
    }

    /// The Base32 value of the link's `c=`/`t=` parameter (not for pairing).
    fn value(&self) -> Result<String> {
        Ok(BASE32_NOPAD.encode(&match self {
            Link::ShareRequest(code) => request_to_bytes(code)?,
            Link::Pair { .. } => bail!("a pairing link has no compact value"),
        }))
    }

    /// The whole link as one `varsto://` URI.
    pub fn to_uri(&self) -> Result<String> {
        Ok(match self {
            Link::ShareRequest(_) => format!("{SCHEME}share/request?c={}", self.value()?),
            Link::Pair {
                code,
                addresses,
                rendezvous,
            } => {
                let code = crate::pair::normalize(code)?;
                let mut u = format!("{SCHEME}pair?c={code}");
                if !addresses.is_empty() {
                    u.push_str("&a=");
                    u.push_str(&addresses.join(","));
                }
                if let Some(t) = rendezvous {
                    u.push_str("&rv=");
                    u.push_str(&hex::encode(t));
                }
                u
            }
        })
    }

    /// The link as URIs for QR codes: one, or `ceil(len / part_chars)` parts
    /// when the value is longer than `single_max` characters.
    pub fn to_uris(&self, single_max: usize, part_chars: usize) -> Result<Vec<String>> {
        let (path, param) = match self {
            Link::ShareRequest(_) => ("share/request", "c"),
            Link::Pair { .. } => return Ok(vec![self.to_uri()?]),
        };
        let v = self.value()?;
        if v.len() <= single_max {
            return Ok(vec![format!("{SCHEME}{path}?{param}={v}")]);
        }
        let part_chars = part_chars.max(16);
        let group = group_of(&v);
        let chunks: Vec<&str> = v
            .as_bytes()
            .chunks(part_chars)
            .map(|c| std::str::from_utf8(c).expect("base32 is ASCII"))
            .collect();
        let n = chunks.len();
        Ok(chunks
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{SCHEME}{path}?p={}.{n}.{group}&{param}={c}", i + 1))
            .collect())
    }

    /// The text form (request code or pairing code) the rest of Varsto takes.
    pub fn text(&self) -> String {
        match self {
            Link::ShareRequest(s) => s.clone(),
            Link::Pair { code, .. } => code.clone(),
        }
    }
}

/// Whether `s` looks like a `varsto://` link (it may still be malformed).
pub fn is_link(s: &str) -> bool {
    let s = s.trim().as_bytes();
    s.len() >= SCHEME.len() && s[..SCHEME.len()].eq_ignore_ascii_case(SCHEME.as_bytes())
}

fn group_of(value: &str) -> String {
    hex::encode(&blake3::hash(value.as_bytes()).as_bytes()[..4])
}

/// Parse a scanned or pasted `varsto://` link. Unknown paths, unknown or
/// repeated parameters and fragments are refused.
pub fn parse(s: &str) -> Result<Scanned> {
    let s = s.trim();
    if s.len() > MAX_LINK {
        bail!("the link is too long");
    }
    if !is_link(s) {
        bail!("not a varsto:// link");
    }
    let rest = &s[SCHEME.len()..];
    if rest.contains('#') {
        bail!("a varsto:// link has no fragment");
    }
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let path = path.trim_end_matches('/').to_ascii_lowercase();
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| anyhow!("parameter without a value in the link"))?;
        let k = k.to_ascii_lowercase();
        if params.insert(k.clone(), percent_decode(v)?).is_some() {
            bail!("parameter {k} appears twice in the link");
        }
    }
    let allowed: &[&str] = match path.as_str() {
        "share/request" => &["c", "p"],
        "pair" => &["c", "a", "rv"],
        other => bail!("unknown varsto:// link: {other}"),
    };
    if let Some(k) = params.keys().find(|k| !allowed.contains(&k.as_str())) {
        bail!("unknown parameter {k} in the link");
    }
    if path == "pair" {
        let code = crate::pair::normalize(
            params
                .get("c")
                .ok_or_else(|| anyhow!("the pairing link has no code"))?,
        )?;
        let addresses = match params.get("a") {
            Some(a) => a
                .split(',')
                .filter(|x| !x.is_empty())
                .map(|x| {
                    x.parse::<std::net::SocketAddr>()
                        .map(|_| x.to_string())
                        .with_context(|| format!("not an address in the pairing link: {x}"))
                })
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };
        if addresses.len() > 16 {
            bail!("too many addresses in the pairing link");
        }
        let rendezvous = match params.get("rv") {
            Some(t) => Some(
                crate::rendezvous::keys::parse_token(t)
                    .ok_or_else(|| anyhow!("malformed rv= value in the pairing link"))?,
            ),
            None => None,
        };
        return Ok(Scanned::Link(Link::Pair {
            code,
            addresses,
            rendezvous,
        }));
    }
    let (kind, param) = ("request", "c");
    let value = params
        .get(param)
        .ok_or_else(|| anyhow!("the link has no {param}= value"))?
        .trim()
        .to_string();
    if let Some(p) = params.get("p") {
        let f: Vec<&str> = p.split('.').collect();
        let (index, count) = match f.as_slice() {
            [i, n, g] if g.len() == 8 && g.chars().all(|c| c.is_ascii_hexdigit()) => {
                (i.parse::<usize>()?, n.parse::<usize>()?)
            }
            _ => bail!("malformed part number in the link"),
        };
        if !(2..=64).contains(&count) || index == 0 || index > count {
            bail!("malformed part number in the link");
        }
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
        {
            bail!("a part of a split link is Base32");
        }
        return Ok(Scanned::Part(Part {
            kind: kind.into(),
            index,
            count,
            group: f[2].to_ascii_lowercase(),
            data: value,
        }));
    }
    Ok(Scanned::Link(link_from_value(kind, &value)?))
}

/// A link from its kind and its `c=` value: the compact Base32 form, or the
/// text form (`vsr1.…`), which is accepted too.
fn link_from_value(kind: &str, value: &str) -> Result<Link> {
    let value = value.trim();
    match kind {
        "request" => {
            let code = if value.starts_with(SHARE_REQUEST_PREFIX) {
                value.to_string()
            } else {
                request_from_bytes(&b32(value)?)?
            };
            ShareRequest::parse(&code)?;
            Ok(Link::ShareRequest(code))
        }
        _ => bail!("unknown link kind {kind}"),
    }
}

fn b32(v: &str) -> Result<Vec<u8>> {
    BASE32_NOPAD
        .decode(v.to_ascii_uppercase().as_bytes())
        .map_err(|_| anyhow!("the link's value is not valid Base32"))
}

fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| anyhow!("bad percent escape in the link"))?;
            out.push(h);
            i += 3;
        } else if b[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| anyhow!("the link is not UTF-8"))
}

/// `format u8 | K6 length u16 BE | K6 | K8 length u16 BE | K8 | name
/// (UTF-8, the rest)`.
fn request_to_bytes(code: &str) -> Result<Vec<u8>> {
    let r = ShareRequest::parse(code)?;
    let mut out = vec![REQUEST_FORMAT];
    for key in [r.k6.clone(), r.key.to_bytes()] {
        out.extend_from_slice(
            &u16::try_from(key.len())
                .map_err(|_| anyhow!("key too long for a link"))?
                .to_be_bytes(),
        );
        out.extend_from_slice(&key);
    }
    out.extend_from_slice(r.name.as_bytes());
    Ok(out)
}

fn request_from_bytes(b: &[u8]) -> Result<String> {
    let mut r = Reader(b);
    if r.u8()? != REQUEST_FORMAT {
        bail!("this request link is from an older version of Varsto: ask for a new one");
    }
    let n = r.u16()? as usize;
    let k6 = r.take(n)?.to_vec();
    let n = r.u16()? as usize;
    let k8 = r.take(n)?.to_vec();
    let name = std::str::from_utf8(r.0).map_err(|_| anyhow!("the name is not UTF-8"))?;
    crate::names::check_display_name(name.trim())?;
    let code = ShareRequest::code_of(&k6, &k8, name.trim());
    ShareRequest::parse(&code)?;
    Ok(code)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("the link's value is cut short");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

/// Collects the parts of split links as they are scanned, in any order.
#[derive(Default)]
pub struct Assembler {
    group: Option<(String, String, usize)>,
    parts: BTreeMap<usize, String>,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a part; a part of another sequence starts over. Returns the link
    /// once every part is in.
    pub fn add(&mut self, p: Part) -> Result<Option<Link>> {
        let key = (p.kind.clone(), p.group.clone(), p.count);
        if self.group.as_ref() != Some(&key) {
            self.group = Some(key);
            self.parts.clear();
        }
        self.parts.insert(p.index, p.data);
        let (kind, group, count) = self.group.clone().expect("set above");
        if self.parts.len() < count {
            return Ok(None);
        }
        let value: String = self.parts.values().cloned().collect();
        self.parts.clear();
        self.group = None;
        if group_of(&value) != group {
            bail!("the parts do not belong together; scan the sequence again");
        }
        Ok(Some(link_from_value(&kind, &value)?))
    }
    /// Indices scanned so far and the number of parts.
    pub fn progress(&self) -> (Vec<usize>, usize) {
        (
            self.parts.keys().copied().collect(),
            self.group.as_ref().map_or(0, |g| g.2),
        )
    }
}

/// Reassemble a link from scanned texts (whole links or parts, any order).
pub fn assemble<S: AsRef<str>>(texts: &[S]) -> Result<Link> {
    let mut a = Assembler::new();
    let mut last = None;
    for t in texts {
        match parse(t.as_ref())? {
            Scanned::Link(l) => return Ok(l),
            Scanned::Part(p) => {
                last = Some((p.index, p.count));
                if let Some(l) = a.add(p)? {
                    return Ok(l);
                }
            }
        }
    }
    match last {
        Some((_, n)) => bail!("{} of {n} parts scanned", a.progress().0.len()),
        None => bail!("nothing to assemble"),
    }
}

/// A rendered QR code.
#[derive(Clone, Debug, Serialize)]
pub struct QrImage {
    pub text: String,
    /// QR version, 1 to 40.
    pub version: i16,
    /// Modules a side, without the quiet zone.
    pub modules: usize,
    /// `L` or `M`.
    pub ecc: &'static str,
    pub svg: String,
}

/// The code for `text`: error correction M when that still fits a
/// version-25 code, else L (screens are flat and sharp; capacity matters
/// more than damage tolerance).
pub fn code_for(text: &str) -> Result<(QrCode, &'static str)> {
    if let Ok(c) = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M) {
        if version_number(&c) <= 25 {
            return Ok((c, "M"));
        }
    }
    let c = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L)
        .map_err(|e| anyhow!("too long for a QR code: {e:?}"))?;
    Ok((c, "L"))
}

fn version_number(c: &QrCode) -> i16 {
    match c.version() {
        qrcode::Version::Normal(v) | qrcode::Version::Micro(v) => v,
    }
}

/// An SVG of the code (black on white, quiet zone included, scales freely).
pub fn to_svg(text: &str) -> Result<QrImage> {
    let (c, ecc) = code_for(text)?;
    let svg = c
        .render::<qrcode::render::svg::Color>()
        .quiet_zone(true)
        .module_dimensions(4, 4)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(QrImage {
        text: text.to_string(),
        version: version_number(&c),
        modules: c.width(),
        ecc,
        svg,
    })
}

/// The code in Unicode half blocks for a terminal, two modules a character
/// row. `dark_terminal` (light text on a dark background, the usual case)
/// prints the light modules as blocks so that the code reads dark on light.
pub fn to_terminal(text: &str, dark_terminal: bool) -> Result<String> {
    use qrcode::render::unicode::Dense1x2;
    let (c, _) = code_for(text)?;
    let (dark, light) = if dark_terminal {
        (Dense1x2::Light, Dense1x2::Dark)
    } else {
        (Dense1x2::Dark, Dense1x2::Light)
    };
    Ok(c.render::<Dense1x2>()
        .quiet_zone(true)
        .dark_color(dark)
        .light_color(light)
        .build())
}

/// Black and white modules of the code with a four-module quiet zone,
/// `scale` pixels a module, as greyscale (tests and the scanner check).
pub fn to_luma(text: &str, scale: usize) -> Result<(usize, Vec<u8>)> {
    let (c, _) = code_for(text)?;
    let w = c.width();
    let colors = c.to_colors();
    let side = (w + 8) * scale;
    let mut px = vec![255u8; side * side];
    for y in 0..w {
        for x in 0..w {
            if colors[y * w + x] == qrcode::Color::Dark {
                for dy in 0..scale {
                    let row = ((y + 4) * scale + dy) * side;
                    for dx in 0..scale {
                        px[row + (x + 4) * scale + dx] = 0;
                    }
                }
            }
        }
    }
    Ok((side, px))
}

/// Texts of every QR code found in a greyscale frame (one byte a pixel,
/// rows top to bottom).
pub fn decode_luma(w: usize, h: usize, px: &[u8]) -> Result<Vec<String>> {
    if w == 0 || h == 0 || w > MAX_IMAGE_SIDE as usize || h > MAX_IMAGE_SIDE as usize {
        bail!("the image is empty or too large");
    }
    if px.len() != w * h {
        bail!("the frame has {} bytes, not {w}×{h}", px.len());
    }
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| px[y * w + x]);
    let mut out = Vec::new();
    for g in img.detect_grids() {
        if let Ok((_, text)) = g.decode() {
            if text.len() <= MAX_LINK && !out.contains(&text) {
                out.push(text);
            }
        }
    }
    Ok(out)
}

/// Texts of every QR code in an image file (PNG, JPEG, …: a screenshot or
/// a photo). Light-on-dark codes are found too.
pub fn decode_image(bytes: &[u8]) -> Result<Vec<String>> {
    let img = image::load_from_memory(bytes).context("not an image Varsto can read")?;
    let mut img = img;
    let longest = img.width().max(img.height());
    if longest > MAX_IMAGE_SIDE {
        img = img.resize(
            MAX_IMAGE_SIDE,
            MAX_IMAGE_SIDE,
            image::imageops::FilterType::Triangle,
        );
    }
    let g = img.to_luma8();
    let (w, h) = (g.width() as usize, g.height() as usize);
    let px = g.into_raw();
    let mut out = decode_luma(w, h, &px)?;
    if out.is_empty() {
        let inv: Vec<u8> = px.iter().map(|p| 255 - p).collect();
        out = decode_luma(w, h, &inv)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str) -> (tempfile::TempDir, String) {
        let d = tempfile::tempdir().unwrap();
        let code = ShareRequest::code_for_named(d.path(), Some(name)).unwrap();
        (d, code)
    }

    #[test]
    fn request_links_round_trip() {
        let (_d, code) = request("Robin Söderlund");
        let l = Link::from_text(&code).unwrap();
        let uri = l.to_uri().unwrap();
        assert!(uri.starts_with("varsto://share/request?c="));
        assert_eq!(parse(&uri).unwrap(), Scanned::Link(l.clone()));
        assert_eq!(l.text(), code);
        // The text form in the parameter is accepted too, and the scheme's case.
        let alt = format!("VARSTO://share/request?c={}", code.replace(' ', "%20"));
        assert_eq!(Link::from_text(&alt).unwrap(), l);
        // The link and the code give the same fingerprint.
        assert_eq!(
            ShareRequest::parse(&uri).unwrap().fingerprint,
            ShareRequest::parse(&code).unwrap().fingerprint
        );
    }

    #[test]
    fn unknown_links_and_parameters_are_refused() {
        let (_d, code) = request("x");
        let uri = Link::from_text(&code).unwrap().to_uri().unwrap();
        for bad in [
            uri.replace("share/request", "share/other"),
            format!("{uri}&x=1"),
            format!("{uri}#frag"),
            format!("{uri}&c=AAAA"),
            uri.replace("?c=", "?c=0"),
            "varsto://pair?c=12345678".to_string(),
            "varsto://pair?c=123456789&a=evil.example".to_string(),
            "varsto://pair?c=123456789&z=1".to_string(),
            "https://share/request?c=AAAA".to_string(),
            "varsto://share/token?t=".to_string(),
            "varsto://share/token?p=1.2.zzzzzzzz&t=AAAA".to_string(),
            "varsto://share/token?p=3.2.00112233&t=AAAA".to_string(),
        ] {
            assert!(parse(&bad).is_err(), "accepted {bad}");
        }
        assert!(Link::from_text("0011.2233.4455.name").is_err());
        // Not a link at all, with a multi-byte character where the scheme ends.
        assert!(!is_link("varsto:/ä"));
        assert!(parse("varsto:/äöü").is_err());
    }

    #[test]
    fn pairing_links_round_trip() {
        let l = Link::Pair {
            code: "123-456-789".into(),
            addresses: vec!["192.168.1.20:41234".into(), "[fe80::1]:41234".into()],
            rendezvous: None,
        };
        let uri = l.to_uri().unwrap();
        assert_eq!(
            uri,
            "varsto://pair?c=123456789&a=192.168.1.20:41234,[fe80::1]:41234"
        );
        match parse(&uri).unwrap() {
            Scanned::Link(Link::Pair {
                code,
                addresses,
                rendezvous,
            }) => {
                assert_eq!(code, "123456789");
                assert_eq!(addresses.len(), 2);
                assert_eq!(rendezvous, None);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn pairing_links_carry_the_rendezvous_token() {
        let t = [0xabu8; 16];
        let l = Link::Pair {
            code: "123-456-789".into(),
            addresses: vec!["192.168.1.20:41234".into()],
            rendezvous: Some(t),
        };
        let uri = l.to_uri().unwrap();
        assert_eq!(
            uri,
            format!(
                "varsto://pair?c=123456789&a=192.168.1.20:41234&rv={}",
                "ab".repeat(16)
            )
        );
        assert!(code_for(&uri).is_ok(), "fits one QR code");
        let mut want = l.clone();
        if let Link::Pair { code, .. } = &mut want {
            *code = "123456789".into();
        }
        assert_eq!(parse(&uri).unwrap(), Scanned::Link(want));
        // A token alone, without addresses.
        let only = format!("varsto://pair?c=123456789&rv={}", "0f".repeat(16));
        match parse(&only).unwrap() {
            Scanned::Link(Link::Pair { rendezvous, .. }) => {
                assert_eq!(rendezvous, Some([0x0f; 16]))
            }
            other => panic!("{other:?}"),
        }
        for bad in [
            format!("varsto://pair?c=123456789&rv={}", "AB".repeat(16)),
            "varsto://pair?c=123456789&rv=abcd".to_string(),
            format!(
                "varsto://pair?c=123456789&rv={}&rv={}",
                "ab".repeat(16),
                "ab".repeat(16)
            ),
        ] {
            assert!(parse(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn a_pairing_link_carries_every_candidate_in_ranked_order() {
        // What an offer builds from a table of interfaces (spec section 68).
        let table = [
            crate::netif::Iface {
                name: "utun3".into(),
                ip: [10, 8, 0, 2].into(),
                prefix: 24,
                up: true,
                loopback: false,
            },
            crate::netif::Iface {
                name: "en0".into(),
                ip: [192, 168, 1, 23].into(),
                prefix: 24,
                up: true,
                loopback: false,
            },
            crate::netif::Iface {
                name: "en5".into(),
                ip: [10, 1, 2, 3].into(),
                prefix: 16,
                up: true,
                loopback: false,
            },
        ];
        let addresses: Vec<String> = crate::netif::rank(&table)
            .into_iter()
            .map(|c| format!("{}:41234", c.ip))
            .collect();
        assert_eq!(
            addresses,
            ["192.168.1.23:41234", "10.1.2.3:41234", "10.8.0.2:41234"]
        );
        let l = Link::Pair {
            code: "123-456-789".into(),
            addresses: addresses.clone(),
            rendezvous: Some([0x5a; 16]),
        };
        let uri = l.to_uri().unwrap();
        assert!(code_for(&uri).is_ok(), "fits one QR code");
        match parse(&uri).unwrap() {
            Scanned::Link(Link::Pair {
                code, addresses: a, ..
            }) => {
                assert_eq!(code, "123456789");
                assert_eq!(a, addresses, "order is the ranking");
            }
            other => panic!("{other:?}"),
        }
        // The largest offer still fits one code.
        let many: Vec<String> = (0..crate::netif::MAX_CANDIDATES)
            .map(|i| format!("192.168.{}.200:65535", 100 + i))
            .collect();
        let big = Link::Pair {
            code: "123-456-789".into(),
            addresses: many,
            rendezvous: Some([0xff; 16]),
        }
        .to_uri()
        .unwrap();
        assert!(code_for(&big).is_ok());
    }

    #[test]
    fn split_links_reassemble_in_any_order() {
        let (_d, code) = request("Robin");
        let l = Link::from_text(&code).unwrap();
        let parts = l.to_uris(100, 300).unwrap();
        assert!(parts.len() >= 5, "{}", parts.len());
        let mut shuffled = parts.clone();
        shuffled.reverse();
        shuffled.insert(1, parts[0].clone()); // a part scanned twice
        assert_eq!(assemble(&shuffled).unwrap(), l);
        // A missing part, and parts of two sequences.
        assert!(assemble(&parts[1..]).is_err());
        let (_e, other) = request("Other");
        let o = Link::from_text(&other).unwrap().to_uris(100, 300).unwrap();
        let mut a = Assembler::new();
        for p in &parts[..parts.len() - 1] {
            let Scanned::Part(p) = parse(p).unwrap() else {
                panic!()
            };
            assert!(a.add(p).unwrap().is_none());
        }
        let Scanned::Part(p) = parse(&o[0]).unwrap() else {
            panic!()
        };
        assert!(a.add(p).unwrap().is_none());
        assert_eq!(a.progress().0, vec![1]);
        // A part inside a single-link field is reported, not opened.
        assert!(Link::from_text(&parts[0]).is_err());
    }

    #[test]
    fn qr_codes_render_and_decode() {
        // A request code is too long for one code: its first part.
        let (_d, code) = request("Robin");
        let uri = Link::from_text(&code)
            .unwrap()
            .to_uris(PART_CHARS, PART_CHARS)
            .unwrap()
            .remove(0);
        let img = to_svg(&uri).unwrap();
        assert!(img.svg.starts_with("<?xml") || img.svg.contains("<svg"));
        assert!(img.version <= 40);
        let (side, px) = to_luma(&uri, 3).unwrap();
        assert_eq!(decode_luma(side, side, &px).unwrap(), vec![uri.clone()]);
        // An inverted screenshot (light code on a dark terminal) as PNG.
        let inv: Vec<u8> = px.iter().map(|p| 255 - p).collect();
        let mut png = Vec::new();
        image::GrayImage::from_raw(side as u32, side as u32, inv)
            .unwrap()
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert_eq!(decode_image(&png).unwrap(), vec![uri.clone()]);
        // Terminal rendering: half blocks, two modules a row, quiet zone.
        let t = to_terminal("varsto://pair?c=123456789", true).unwrap();
        let rows: Vec<&str> = t.lines().collect();
        let (c, _) = code_for("varsto://pair?c=123456789").unwrap();
        assert_eq!(rows.len(), (c.width() + 8).div_ceil(2));
        assert!(rows.iter().all(|r| r.chars().count() == c.width() + 8));
        assert!(t.contains('█') || t.contains('▀') || t.contains('▄'));
    }
}
