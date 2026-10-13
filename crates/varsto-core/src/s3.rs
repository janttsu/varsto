// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! S3-compatible object storage (AWS S3, MinIO, Scaleway, Hetzner, Backblaze
//! B2, Cloudflare R2, `rclone serve s3`, ...). Plain HTTP(S) with Signature
//! Version 4; no SDK. Objects are written with `If-None-Match: *` so that an
//! existing object is never overwritten; servers that do not support the
//! condition fall back to HEAD-then-PUT, which is safe because every object
//! name is either content-addressed or owned by a single writer.

use crate::storage::Storage;
use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct S3Config {
    pub name: String,
    /// `https://s3.eu-central-1.amazonaws.com`, `https://s3.fr-par.scw.cloud`, `http://127.0.0.1:9000`
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Key prefix inside the bucket, without leading slash; may be empty.
    pub prefix: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// `true`: `<endpoint>/<bucket>/<key>`; `false`: `<bucket>.<host>/<key>`.
    pub path_style: bool,
    /// `x-amz-storage-class` for new objects (e.g. `DEEP_ARCHIVE`, `GLACIER_IR`, `ONEZONE_IA`).
    pub storage_class: Option<String>,
}

crate::redacted_debug!(S3Config { name, endpoint, region, bucket, prefix, access_key_id, path_style ; secret_access_key });

pub struct S3Storage {
    cfg: S3Config,
    agent: ureq::Agent,
    host: String,
    scheme: String,
    /// Path prefix of every request (`/bucket` for path style, empty otherwise).
    base_path: String,
    /// Seconds to add to this device's clock when signing: learned from the
    /// server's `Date` header after it refused a request signed with a
    /// clock that is off (S3 refuses signatures more than 15 minutes from
    /// its own time; phones and virtual machines are often that far off).
    clock_offset: std::sync::atomic::AtomicI64,
}

/// Largest response body read into memory. Chunks are at most a few MiB;
/// manifests and ledger batches grow with the number of files.
const MAX_BODY: u64 = 2 << 30;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

impl S3Storage {
    /// A refusal in words a person can act on, then the technical details
    /// (operation, key, HTTP status, the S3 error code and message).
    fn explain(&self, op: &str, key: &str, status: u16, body: &[u8]) -> anyhow::Error {
        let doc = String::from_utf8_lossy(body);
        let code = xml_tag(&doc, "Code")
            .map(|c| c.trim().to_string())
            .unwrap_or_default();
        let message = xml_tag(&doc, "Message")
            .map(|m| xml_unescape(m.trim()))
            .unwrap_or_default();
        let bucket = &self.cfg.bucket;
        let endpoint = &self.cfg.endpoint;
        let words = match (code.as_str(), status) {
            ("InvalidAccessKeyId", _) => format!(
                "The storage does not know this access key. Check that the access key ID was copied in full and belongs to {endpoint}."
            ),
            ("SignatureDoesNotMatch", _) => {
                "The secret key does not belong to this access key. Copy the secret key again.".to_string()
            }
            ("RequestTimeTooSkewed", _) => {
                "This device's clock is too far from the storage's clock. Set the date and time automatically and try again.".to_string()
            }
            ("NoSuchBucket", _) => format!(
                "Bucket \"{bucket}\" does not exist at {endpoint}. Check the bucket name and the region of the endpoint."
            ),
            ("PermanentRedirect" | "AuthorizationHeaderMalformed" | "IllegalLocationConstraintException", _) | (_, 301) => {
                let hint = xml_tag(&doc, "Region")
                    .or_else(|| xml_tag(&doc, "Endpoint"))
                    .map(|r| format!(" It answered: {}.", r.trim()))
                    .unwrap_or_default();
                format!("Bucket \"{bucket}\" is in another region than the endpoint {endpoint}. Use the endpoint and region of the bucket.{hint}")
            }
            ("AccessDenied" | "AllAccessDisabled" | "AccountProblem", _) | (_, 401 | 403) => format!(
                "The storage refused access to bucket \"{bucket}\". The access key needs permission to list, read, write and delete objects in it; check the key's policy (IAM) and the bucket policy. A new key without a policy is refused like this."
            ),
            ("QuotaExceeded" | "StorageQuotaExceeded", _) | (_, 507) => {
                "The storage is full or over its quota. Free space there or raise the quota.".to_string()
            }
            ("SlowDown", _) | (_, 429 | 503) => {
                "The storage asked to slow down or is unavailable for a moment. Varsto tries again by itself.".to_string()
            }
            (_, 500..=599) => "The storage had an internal error. Varsto tries again by itself; if it keeps happening, check the provider's status page.".to_string(),
            _ => format!("The storage answered with HTTP {status}."),
        };
        let mut detail = format!("{op} {key}: HTTP {status}");
        if !code.is_empty() {
            detail.push_str(&format!(" {code}"));
        }
        if !message.is_empty() {
            detail.push_str(&format!(": {message}"));
        }
        anyhow!("{words} (storage {}: {detail})", self.cfg.name)
    }

    pub fn new(cfg: S3Config) -> Result<Self> {
        crate::logging::register_secret(&cfg.secret_access_key);
        let endpoint = cfg.endpoint.clone();
        let (scheme, rest) = endpoint
            .split_once("://")
            .ok_or_else(|| anyhow!("endpoint must start with http:// or https://"))?;
        let host_part = rest.trim_end_matches('/');
        if host_part.is_empty() || host_part.contains('/') {
            bail!("endpoint must be scheme://host[:port] without a path");
        }
        let (host, base_path) = if cfg.path_style {
            (host_part.to_string(), format!("/{}", cfg.bucket))
        } else {
            (format!("{}.{}", cfg.bucket, host_part), String::new())
        };
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(600)))
            // A storage that accepts the request and then goes silent must
            // not freeze a sync for the whole global limit: connecting and
            // the first byte of the answer each get their own, shorter one.
            .timeout_connect(Some(Duration::from_secs(20)))
            .timeout_recv_response(Some(Duration::from_secs(120)))
            // Downloads keep up to 32 objects in flight; with ureq's default
            // of three idle connections per host the others would pay a new
            // TLS handshake for every object.
            .max_idle_connections_per_host(32)
            .max_idle_connections(64)
            .build();
        Ok(S3Storage {
            cfg,
            agent: config.into(),
            host,
            scheme: scheme.to_string(),
            base_path,
            clock_offset: std::sync::atomic::AtomicI64::new(0),
        })
    }

    fn object_path(&self, key: &str) -> String {
        // Keys are validated by `checked` before any request is built.
        let full = if self.cfg.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", self.cfg.prefix.trim_matches('/'), key)
        };
        let encoded: Vec<String> = full.split('/').map(uri_encode).collect();
        format!("{}/{}", self.base_path, encoded.join("/"))
    }

    fn full_prefix(&self, prefix: &str) -> String {
        if self.cfg.prefix.is_empty() {
            prefix.to_string()
        } else {
            format!("{}/{}", self.cfg.prefix.trim_matches('/'), prefix)
        }
    }

    /// Build, sign and send a request. A 403 (or 400) from a server whose clock is
    /// more than five minutes from ours is retried once with our clock
    /// corrected to the server's (the offset is kept for later requests).
    fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        extra_headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>)> {
        use std::sync::atomic::Ordering;
        let t = crate::logging::Timer::start();
        let first = self.request_once(method, path, query, extra_headers, body);
        let failed = match &first {
            Ok((st, _, _)) => *st >= 400 && *st != 404,
            Err(_) => true,
        };
        // The engine logs each logical request; the HTTP level only adds
        // failures (and everything at trace).
        if failed || log::log_enabled!(log::Level::Trace) {
            crate::storage::log_request(
                &self.cfg.name,
                "s3",
                method,
                path,
                body.len() as u64,
                first.as_ref().map(|r| r.0).ok(),
                first.as_ref().map(|r| r.1.len() as u64).unwrap_or(0),
                t.ms(),
                first.as_ref().err(),
            );
        }
        let (status, bytes, server_date) = first?;
        // Refused (403, or 400 from some servers for a signature outside the
        // allowed window) by a server whose clock is far from ours: retry
        // once with our clock set to the server's.
        if status == 403 || status == 400 {
            if let Some(server) = server_date.as_deref().and_then(parse_http_date) {
                let ours = unix_now() + self.clock_offset.load(Ordering::Relaxed);
                if (server - ours).abs() > 300 {
                    log::warn!(
                        storage = self.cfg.name.as_str(),
                        skew_s = server - ours;
                        "s3: refused with our clock far from the server's; retrying with the server's time"
                    );
                    self.clock_offset
                        .store(server - unix_now(), Ordering::Relaxed);
                    let (status, bytes, _) =
                        self.request_once(method, path, query, extra_headers, body)?;
                    return Ok((status, bytes));
                }
            }
        }
        Ok((status, bytes))
    }

    /// Build and sign one request. `query` must already be sorted by key.
    fn request_once(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        extra_headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>, Option<String>)> {
        let amz_date =
            amz_date_at(unix_now() + self.clock_offset.load(std::sync::atomic::Ordering::Relaxed));
        let date = &amz_date[..8];
        let payload_hash = if body.is_empty() {
            EMPTY_SHA256.to_string()
        } else {
            hex::encode(Sha256::digest(body))
        };
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), self.host.clone()),
            ("x-amz-content-sha256".into(), payload_hash.clone()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        for (k, v) in extra_headers {
            headers.push((k.to_lowercase(), v.trim().to_string()));
        }
        headers.sort();
        let signed_headers: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        let signed_headers = signed_headers.join(";");
        let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let canonical_query: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
            .collect();
        let canonical_query = canonical_query.join("&");
        let canonical_request = format!(
            "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.cfg.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let k_date = hmac(
            format!("AWS4{}", self.cfg.secret_access_key).as_bytes(),
            date.as_bytes(),
        );
        let k_region = hmac(&k_date, self.cfg.region.as_bytes());
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.cfg.access_key_id
        );
        let url = if canonical_query.is_empty() {
            format!("{}://{}{}", self.scheme, self.host, path)
        } else {
            format!(
                "{}://{}{}?{}",
                self.scheme, self.host, path, canonical_query
            )
        };
        let mut send_headers: Vec<(String, String)> = vec![
            ("x-amz-content-sha256".into(), payload_hash.clone()),
            ("x-amz-date".into(), amz_date.clone()),
            ("authorization".into(), authorization),
        ];
        for (k, v) in extra_headers {
            send_headers.push((k.to_string(), v.to_string()));
        }
        let mut resp = match method {
            "PUT" => {
                let mut r = self.agent.put(&url);
                for (k, v) in &send_headers {
                    r = r.header(k.as_str(), v.as_str());
                }
                r.send(body)
            }
            _ => {
                let mut r = match method {
                    "GET" => self.agent.get(&url),
                    "HEAD" => self.agent.head(&url),
                    "DELETE" => self.agent.delete(&url),
                    other => bail!("unsupported method {other}"),
                };
                for (k, v) in &send_headers {
                    r = r.header(k.as_str(), v.as_str());
                }
                r.call()
            }
        }
        .with_context(|| format!("{method} {}", self.cfg.name))?;
        let status = resp.status().as_u16();
        let server_date = resp
            .headers()
            .get("date")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = if method == "HEAD" {
            Vec::new()
        } else {
            // ureq stops at 10 MiB by default, but a ledger batch or a file
            // list of a folder with tens of thousands of files is larger.
            resp.body_mut()
                .with_config()
                .limit(MAX_BODY)
                .read_to_vec()
                .with_context(|| format!("{method} {}: reading the response", self.cfg.name))?
        };
        Ok((status, bytes, server_date))
    }

    fn put(&self, key: &str, data: &[u8], if_none_match: bool) -> Result<u16> {
        crate::storage::validate_key(key)?;
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if if_none_match {
            headers.push(("if-none-match", "*"));
        }
        if let Some(c) = &self.cfg.storage_class {
            headers.push(("x-amz-storage-class", c));
        }
        let (status, body) = self.request("PUT", &self.object_path(key), &[], &headers, data)?;
        if status >= 500 {
            return Err(self.explain("PUT", key, status, &body));
        }
        Ok(status)
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `YYYYMMDDTHHMMSSZ` for the current UTC time, without a date crate.
#[cfg(test)]
fn amz_date_now() -> String {
    amz_date_at(unix_now())
}

/// Seconds since the epoch of an HTTP date (`Sun, 11 Oct 2026 07:57:54 GMT`).
fn parse_http_date(s: &str) -> Option<i64> {
    let mut it = s.split_whitespace().skip(1);
    let day: i64 = it.next()?.parse().ok()?;
    let month = match it.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':').map(|x| x.parse::<i64>().ok());
    let (h, m, sec) = (hms.next()??, hms.next()??, hms.next()??);
    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + m * 60 + sec)
}

/// `YYYYMMDDTHHMMSSZ` for `secs` since the epoch.
fn amz_date_at(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// RFC 3986 encoding as AWS expects it (unreserved characters untouched).
fn uri_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn xml_tag<'a>(doc: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = doc.find(&open)? + open.len();
    let end = doc[start..].find(&close)? + start;
    Some(&doc[start..end])
}

fn xml_tags<'a>(doc: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = doc;
    while let Some(i) = rest.find(&open) {
        let start = i + open.len();
        let Some(j) = rest[start..].find(&close) else {
            break;
        };
        out.push(&rest[start..start + j]);
        rest = &rest[start + j + close.len()..];
    }
    out
}

impl Storage for S3Storage {
    fn name(&self) -> &str {
        &self.cfg.name
    }

    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        crate::storage::validate_key(key)?;
        // Some servers silently ignore `If-None-Match`, so check first; the
        // condition then only closes the window between HEAD and PUT on
        // servers that do honour it.
        if self.exists(key)? {
            return Ok(false);
        }
        match self.put(key, data, true)? {
            200 | 201 => Ok(true),
            412 => Ok(false),
            400 | 501 => match self.put(key, data, false)? {
                200 | 201 => Ok(true),
                s => Err(self.explain("PUT", key, s, &[])),
            },
            s => Err(self.explain("PUT", key, s, &[])),
        }
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        crate::storage::validate_key(key)?;
        let (status, body) = self.request("GET", &self.object_path(key), &[], &[], &[])?;
        match status {
            200 => Ok(Some(body)),
            404 => Ok(None),
            403 if String::from_utf8_lossy(&body).contains("InvalidObjectState") => {
                bail!("GET {key}: object is in a cold storage class and must be restored first")
            }
            s => Err(self.explain("GET", key, s, &body)),
        }
    }

    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        crate::storage::validate_key(key)?;
        if len == 0 {
            return Ok(Some(Vec::new()));
        }
        let range = format!("bytes={}-{}", offset, offset + len - 1);
        let (status, body) = self.request(
            "GET",
            &self.object_path(key),
            &[],
            &[("range", &range)],
            &[],
        )?;
        match status {
            206 => Ok(Some(body)),
            // Some servers (rclone serve s3) send the range with 200; one that
            // ignores Range sends the whole object, which is longer whenever
            // the offset is not 0.
            200 if body.len() as u64 == len => Ok(Some(body)),
            200 => Ok(Some(
                body.get(offset as usize..(offset + len) as usize)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default(),
            )),
            404 => Ok(None),
            s => Err(self.explain("GET", key, s, &body)),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        crate::storage::validate_key(key)?;
        let (status, _) = self.request("HEAD", &self.object_path(key), &[], &[], &[])?;
        match status {
            200 => Ok(true),
            404 => Ok(false),
            s => Err(self.explain("HEAD", key, s, &[])),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_after(prefix, "")
    }

    /// ListObjectsV2 with `start-after`: the server skips the older keys.
    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        let full = self.full_prefix(prefix);
        let strip = if self.cfg.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", self.cfg.prefix.trim_matches('/'))
        };
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![("list-type".to_string(), "2".to_string())];
            if let Some(t) = &token {
                query.push(("continuation-token".to_string(), t.clone()));
            }
            query.push(("max-keys".to_string(), "1000".to_string()));
            query.push(("prefix".to_string(), full.clone()));
            if token.is_none() && !start_after.is_empty() {
                query.push(("start-after".to_string(), self.full_prefix(start_after)));
            }
            query.sort();
            let path = if self.base_path.is_empty() {
                "/".to_string()
            } else {
                format!("{}/", self.base_path)
            };
            let (status, body) = self.request("GET", &path, &query, &[], &[])?;
            if status != 200 {
                return Err(self.explain("LIST", prefix, status, &body));
            }
            let doc = String::from_utf8_lossy(&body).to_string();
            for k in xml_tags(&doc, "Key") {
                let k = xml_unescape(k);
                if let Some(rel) = k.strip_prefix(&strip) {
                    if rel > start_after {
                        keys.push(rel.to_string());
                    }
                }
            }
            let truncated = xml_tag(&doc, "IsTruncated")
                .map(|t| t.trim() == "true")
                .unwrap_or(false);
            if !truncated {
                break;
            }
            token = xml_tag(&doc, "NextContinuationToken").map(|t| xml_unescape(t.trim()));
            if token.is_none() {
                break;
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    fn delete(&self, key: &str) -> Result<()> {
        crate::storage::validate_key(key)?;
        let (status, body) = self.request("DELETE", &self.object_path(key), &[], &[], &[])?;
        match status {
            200 | 202 | 204 | 404 => Ok(()),
            s => Err(self.explain("DELETE", key, s, &body)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_and_xml_helpers() {
        assert_eq!(uri_encode("a b/c~d"), "a%20b%2Fc~d");
        let doc = "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a/b&amp;c</Key></Contents><Contents><Key>d</Key></Contents></ListBucketResult>";
        assert_eq!(xml_tags(doc, "Key"), vec!["a/b&amp;c", "d"]);
        assert_eq!(xml_unescape("a/b&amp;c"), "a/b&c");
        assert_eq!(xml_tag(doc, "IsTruncated"), Some("false"));
    }

    #[test]
    fn refusals_are_explained() {
        let s = S3Storage::new(S3Config {
            name: "test".into(),
            endpoint: "https://s3.example.net".into(),
            region: "us-east-1".into(),
            bucket: "photos".into(),
            prefix: String::new(),
            access_key_id: "k".into(),
            secret_access_key: "s".into(),
            path_style: true,
            storage_class: None,
        })
        .unwrap();
        let body = b"<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>";
        let e = s.explain("GET", "vault/meta.json", 403, body).to_string();
        assert!(
            e.starts_with("The storage refused access to bucket \"photos\""),
            "{e}"
        );
        assert!(
            e.contains("GET vault/meta.json: HTTP 403 AccessDenied: Access Denied"),
            "{e}"
        );
        let e = s.explain("HEAD", "x", 404, b"").to_string();
        assert!(e.contains("HTTP 404"), "{e}");
        let body = b"<Error><Code>NoSuchBucket</Code></Error>";
        assert!(s
            .explain("LIST", "", 404, body)
            .to_string()
            .contains("does not exist"));
    }

    #[test]
    fn reads_objects_larger_than_ten_mib() {
        // A file list of a large folder exceeds ureq's default body limit.
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let body: Vec<u8> = (0..12 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let served = body.clone();
        let th = std::thread::spawn(move || {
            let req = server.recv().unwrap();
            req.respond(tiny_http::Response::from_data(served)).unwrap();
        });
        let s = S3Storage::new(S3Config {
            name: "test".into(),
            endpoint: format!("http://127.0.0.1:{port}"),
            region: "us-east-1".into(),
            bucket: "b".into(),
            prefix: String::new(),
            access_key_id: "k".into(),
            secret_access_key: "s".into(),
            path_style: true,
            storage_class: None,
        })
        .unwrap();
        assert_eq!(s.get("manifests/x").unwrap().unwrap(), body);
        th.join().unwrap();
    }

    #[test]
    fn http_dates_parse_and_round_trip() {
        let t = parse_http_date("Sun, 11 Oct 2026 07:57:54 GMT").unwrap();
        assert_eq!(amz_date_at(t), "20261011T075754Z");
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Tue, 29 Feb 2028 23:59:59 GMT")
                .map(amz_date_at)
                .as_deref(),
            Some("20280229T235959Z")
        );
        assert!(parse_http_date("yesterday").is_none());
    }

    #[test]
    fn amz_date_has_the_expected_shape() {
        let d = amz_date_now();
        assert_eq!(d.len(), 16);
        assert!(d.starts_with("20"));
        assert!(d.ends_with('Z'));
    }

    #[test]
    fn sigv4_signing_key_matches_aws_example() {
        // From the AWS "Signature Version 4 signing key" example.
        let k_date = hmac(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20150830");
        let k_region = hmac(&k_date, b"us-east-1");
        let k_service = hmac(&k_region, b"iam");
        let k_signing = hmac(&k_service, b"aws4_request");
        assert_eq!(
            hex::encode(k_signing),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }
}
