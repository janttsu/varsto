// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! S3-compatible object storage (AWS S3, MinIO, Scaleway, Hetzner, Backblaze
//! B2, Cloudflare R2, `rclone serve s3`, ...). Plain HTTP(S) with Signature
//! Version 4; no SDK. Objects are written with `If-None-Match: *` so that an
//! existing object is never overwritten. Whether a server honours the
//! condition is probed once per storage (two writes of a probe object); one
//! that does gets a single PUT per object, one that does not (ignores the
//! header or refuses it) gets HEAD-then-PUT, which is safe because every
//! object name is either content-addressed or owned by a single writer.

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
    /// Accept an `http://` endpoint that is not a loopback address. Without
    /// transport encryption the request signatures and the (encrypted)
    /// objects travel in clear, so it takes an explicit choice.
    pub allow_insecure_http: bool,
    /// Whether the server honours `If-None-Match: *`, when known from an
    /// earlier probe; `None` probes on the first write.
    pub conditional_writes: Option<bool>,
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
    /// Whether the server honours `If-None-Match: *` (see `probe_conditional`).
    conditional: std::sync::Mutex<Option<bool>>,
    /// The warning about unconditional writes is given once per storage.
    fallback_warned: std::sync::atomic::AtomicBool,
}

/// Bytes of the probe object written to learn whether the server honours
/// `If-None-Match: *`.
const PROBE_BODY: &[u8] = b"varsto conditional-write probe";

/// Largest response to a listing or any other request that is not an object
/// read (object reads are capped per key, `storage::read_limit`).
const MAX_BODY: u64 = crate::storage::MAX_RECORD;

/// Objects larger than this (packs, `crate::packs`) are written in parts
/// of `MULTIPART_PART` bytes.
const MULTIPART_ABOVE: usize = 64 << 20;
const MULTIPART_PART: usize = 16 << 20;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Whether `host[:port]` names this computer: `localhost`, `127.0.0.0/8`
/// or `::1`. Plain `http://` to such an address never leaves the machine.
fn is_loopback_host(host_port: &str) -> bool {
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host_port.rsplit_once(':').map_or(host_port, |(h, _)| h)
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

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
        let cfg_conditional = cfg.conditional_writes;
        let endpoint = cfg.endpoint.clone();
        let (scheme, rest) = endpoint
            .split_once("://")
            .ok_or_else(|| anyhow!("endpoint must start with http:// or https://"))?;
        let host_part = rest.trim_end_matches('/');
        if host_part.is_empty() || host_part.contains('/') {
            bail!("endpoint must be scheme://host[:port] without a path");
        }
        match scheme {
            "https" => {}
            "http" if is_loopback_host(host_part) || cfg.allow_insecure_http => {}
            "http" => bail!(
                "the endpoint {endpoint} uses http://, so the request signatures and the objects would travel without transport encryption; use https://, or pass --insecure-http for a server on a network you trust (a loopback address needs no flag)"
            ),
            other => bail!("endpoint scheme must be https or http, not {other}://"),
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
            conditional: std::sync::Mutex::new(cfg_conditional),
            fallback_warned: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Whether the server honours `If-None-Match: *`: the configured answer,
    /// or one learned now by writing a probe object twice under
    /// `vault/.probe-<random>` (deleted afterwards). A second conditional PUT
    /// answered 412 means the condition holds; 200 means the server ignored
    /// it; 400 or 501 means it refuses the header. Servers that do not
    /// honour it get HEAD-then-PUT for every object, with one warning.
    fn conditional_writes_known(&self) -> Result<bool> {
        if let Some(known) = *self.conditional.lock().unwrap() {
            return Ok(known);
        }
        let key = format!("vault/.probe-{:016x}", rand::random::<u64>());
        let outcome = match self.put(&key, PROBE_BODY, true)? {
            200 | 201 => match self.put(&key, PROBE_BODY, true)? {
                412 => Ok(true),
                200 | 201 | 400 | 501 => Ok(false),
                s => Err(self.explain("PUT", &key, s, &[])),
            },
            400 | 501 => Ok(false),
            s => Err(self.explain("PUT", &key, s, &[])),
        };
        if let Err(e) = self.delete(&key) {
            log::debug!(storage = self.cfg.name.as_str(); "s3: probe object not deleted: {e:#}");
        }
        let honoured = outcome?;
        *self.conditional.lock().unwrap() = Some(honoured);
        log::debug!(storage = self.cfg.name.as_str(), honoured = honoured; "s3: conditional writes probed");
        if !honoured {
            self.warn_unconditional();
        }
        Ok(honoured)
    }

    fn warn_unconditional(&self) {
        use std::sync::atomic::Ordering;
        if !self.fallback_warned.swap(true, Ordering::Relaxed) {
            log::warn!(
                storage = self.cfg.name.as_str();
                "s3: the server does not honour If-None-Match: *; objects are checked with HEAD and written unconditionally"
            );
        }
    }

    /// `put_if_absent` on a server that does not honour the condition.
    fn put_after_head(&self, key: &str, data: &[u8]) -> Result<bool> {
        if self.exists(key)? {
            return Ok(false);
        }
        match self.put(key, data, false)? {
            200 | 201 => Ok(true),
            s => Err(self.explain("PUT", key, s, &[])),
        }
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
        self.request_capped(method, path, query, extra_headers, body, MAX_BODY)
    }

    /// `request`, reading at most `cap` bytes of the response: a longer
    /// `Content-Length`, or a body that runs past it, is an error before the
    /// body is held in memory.
    fn request_capped(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        extra_headers: &[(&str, &str)],
        body: &[u8],
        cap: u64,
    ) -> Result<(u16, Vec<u8>)> {
        self.request_capped_full(method, path, query, extra_headers, body, cap)
            .map(|(status, bytes, _)| (status, bytes))
    }

    /// `request_capped`, also giving the answer's `Content-Range`.
    fn request_capped_full(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        extra_headers: &[(&str, &str)],
        body: &[u8],
        cap: u64,
    ) -> Result<(u16, Vec<u8>, Option<String>)> {
        use std::sync::atomic::Ordering;
        let t = crate::logging::Timer::start();
        let first = self.request_once(method, path, query, extra_headers, body, cap);
        let failed = match &first {
            Ok((st, ..)) => *st >= 400 && *st != 404,
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
        let (status, bytes, server_date, content_range) = first?;
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
                    let (status, bytes, _, content_range) =
                        self.request_once(method, path, query, extra_headers, body, cap)?;
                    return Ok((status, bytes, content_range));
                }
            }
        }
        Ok((status, bytes, content_range))
    }

    /// Build and sign one request. `query` must already be sorted by key.
    fn request_once(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        extra_headers: &[(&str, &str)],
        body: &[u8],
        cap: u64,
    ) -> Result<Answer> {
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
            "PUT" | "POST" => {
                let mut r = if method == "PUT" {
                    self.agent.put(&url)
                } else {
                    self.agent.post(&url)
                };
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
        let content_range = resp
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = if method == "HEAD" {
            Vec::new()
        } else {
            // A server's word for the length is checked before anything is
            // read: a 2 GiB answer is refused without allocating for it.
            if status < 400 || status == 404 {
                if let Some(n) = resp.body().content_length() {
                    if n > cap {
                        bail!(
                            "{method} {}: the response is {n} bytes, more than the {cap} allowed",
                            self.cfg.name
                        );
                    }
                }
            }
            // ureq stops at 10 MiB by default, but a ledger batch or a file
            // list of a folder with tens of thousands of files is larger.
            // ureq refuses a body that reaches its limit, so the limit is one
            // past the cap: a body of exactly `cap` bytes (a pack read with
            // its class size) is accepted, a longer one is refused here.
            let limit = cap.max(64 * 1024);
            let bytes = resp
                .body_mut()
                .with_config()
                .limit(limit.saturating_add(1))
                .read_to_vec()
                .with_context(|| format!("{method} {}: reading the response", self.cfg.name))?;
            if bytes.len() as u64 > limit {
                bail!(
                    "{method} {}: the response is longer than the {limit} bytes allowed",
                    self.cfg.name
                );
            }
            bytes
        };
        Ok((status, bytes, server_date, content_range))
    }

    /// `put_if_absent` for a large object: a multipart upload. Large
    /// objects are packs, named by the hash of their bytes, so whatever
    /// already has the name holds the same bytes: a HEAD decides. A server
    /// that refuses the multipart upload gets one PUT.
    fn put_large(&self, key: &str, data: &[u8]) -> Result<bool> {
        if self.exists(key)? {
            return Ok(false);
        }
        if let Err(e) = self.put_multipart(key, data) {
            log::warn!(storage = self.cfg.name.as_str(); "s3: multipart upload of {key} failed, writing it in one request: {e:#}");
            match self.put(key, data, false)? {
                200 | 201 => {}
                s => return Err(self.explain("PUT", key, s, &[])),
            }
        }
        Ok(true)
    }

    fn put_multipart(&self, key: &str, data: &[u8]) -> Result<()> {
        crate::storage::validate_key(key)?;
        let path = self.object_path(key);
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(c) = &self.cfg.storage_class {
            headers.push(("x-amz-storage-class", c));
        }
        let (status, body) = self.request(
            "POST",
            &path,
            &[("uploads".to_string(), String::new())],
            &headers,
            &[],
        )?;
        if status != 200 {
            return Err(self.explain("POST", key, status, &body));
        }
        let doc = String::from_utf8_lossy(&body).to_string();
        let id = xml_tag(&doc, "UploadId")
            .map(xml_unescape)
            .filter(|i| !i.is_empty())
            .ok_or_else(|| anyhow!("POST {key}: the answer names no upload"))?;
        let upload = || -> Result<()> {
            let mut done = String::from("<CompleteMultipartUpload>");
            for (i, part) in data.chunks(MULTIPART_PART).enumerate() {
                let n = (i + 1).to_string();
                let query = [
                    ("partNumber".to_string(), n.clone()),
                    ("uploadId".to_string(), id.clone()),
                ];
                let (status, body) = self.request("PUT", &path, &query, &[], part)?;
                if status != 200 {
                    return Err(self.explain("PUT", key, status, &body));
                }
                // The part's ETag is the MD5 of its bytes (no server-side
                // encryption with customer keys is used).
                let etag = hex::encode(<md5::Md5 as Digest>::digest(part));
                done.push_str(&format!(
                    "<Part><PartNumber>{n}</PartNumber><ETag>\"{etag}\"</ETag></Part>"
                ));
            }
            done.push_str("</CompleteMultipartUpload>");
            let (status, body) = self.request(
                "POST",
                &path,
                &[("uploadId".to_string(), id.clone())],
                &[],
                done.as_bytes(),
            )?;
            // A completion can fail inside a 200 answer.
            if status != 200 || String::from_utf8_lossy(&body).contains("<Error>") {
                return Err(self.explain("POST", key, status, &body));
            }
            Ok(())
        };
        let result = upload();
        if result.is_err() {
            let _ = self.request(
                "DELETE",
                &path,
                &[("uploadId".to_string(), id.clone())],
                &[],
                &[],
            );
        }
        result
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
        // 501 Not Implemented is how a server refuses `If-None-Match`; the
        // caller falls back from it. Other server errors are errors here.
        if status >= 500 && status != 501 {
            return Err(self.explain("PUT", key, status, &body));
        }
        Ok(status)
    }
}

/// One answer: status, body, its `Date` and its `Content-Range` header.
type Answer = (u16, Vec<u8>, Option<String>, Option<String>);

/// The `start` of a `Content-Range: bytes start-end/total` header.
fn content_range_start(header: &str) -> Option<u64> {
    let rest = header.trim().strip_prefix("bytes")?.trim_start();
    let (span, _) = rest.split_once('/')?;
    let (start, _) = span.split_once('-')?;
    start.trim().parse().ok()
}

/// The bytes `offset .. offset + len` out of a range answer. A `206`, or a
/// `200` that names its `Content-Range` (rclone serve s3 does that), holds
/// the bytes from the header's start, which may be clipped at the object's
/// end. A `200` without one is the whole object (the server ignored Range).
/// Bytes past what was asked are dropped; a range past the end is empty.
fn range_part(
    status: u16,
    body: Vec<u8>,
    content_range: Option<&str>,
    offset: u64,
    len: u64,
) -> Vec<u8> {
    let start = match content_range.and_then(content_range_start) {
        Some(start) => start,
        // A 206 without a readable header: trust it to begin at the offset.
        None if status == 206 => offset,
        None => 0,
    };
    let Some(skip) = offset.checked_sub(start) else {
        // The answer begins after the offset: not the bytes asked for.
        return Vec::new();
    };
    let (Ok(skip), Ok(len)) = (usize::try_from(skip), usize::try_from(len)) else {
        return Vec::new();
    };
    if skip == 0 && body.len() <= len {
        return body;
    }
    body.get(skip..)
        .map(|rest| rest[..rest.len().min(len)].to_vec())
        .unwrap_or_default()
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
        if data.len() > MULTIPART_ABOVE {
            return self.put_large(key, data);
        }
        if !self.conditional_writes_known()? {
            // The server ignores or refuses `If-None-Match`: check first.
            return self.put_after_head(key, data);
        }
        match self.put(key, data, true)? {
            200 | 201 => Ok(true),
            412 => Ok(false),
            400 | 501 => {
                // Honoured by the probe, refused now: fall back for good.
                *self.conditional.lock().unwrap() = Some(false);
                self.warn_unconditional();
                self.put_after_head(key, data)
            }
            s => Err(self.explain("PUT", key, s, &[])),
        }
    }

    fn conditional_writes(&self) -> Option<bool> {
        *self.conditional.lock().unwrap()
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get_bounded(key, crate::storage::read_limit(key))
    }

    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        crate::storage::validate_key(key)?;
        let (status, body) =
            self.request_capped("GET", &self.object_path(key), &[], &[], &[], max)?;
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
        // The offset and length are claims of a pack index: checked, never added blindly.
        let len = len.min(crate::storage::MAX_PACK);
        let Some(last) = offset.checked_add(len - 1) else {
            bail!("GET {key}: the range starting at {offset} is out of bounds");
        };
        let range = format!("bytes={offset}-{last}");
        let (status, body, content_range) = self.request_capped_full(
            "GET",
            &self.object_path(key),
            &[],
            &[("range", &range)],
            &[],
            crate::storage::MAX_PACK,
        )?;
        match status {
            206 | 200 => Ok(Some(range_part(
                status,
                body,
                content_range.as_deref(),
                offset,
                len,
            ))),
            404 => Ok(None),
            // The range starts past the object's end: nothing there.
            416 => Ok(Some(Vec::new())),
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
            allow_insecure_http: false,
            conditional_writes: None,
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
            allow_insecure_http: false,
            conditional_writes: None,
        })
        .unwrap();
        assert_eq!(s.get("manifests/x").unwrap().unwrap(), body);
        th.join().unwrap();
    }

    fn storage_for(port: u16) -> S3Storage {
        S3Storage::new(S3Config {
            name: "test".into(),
            endpoint: format!("http://127.0.0.1:{port}"),
            region: "us-east-1".into(),
            bucket: "b".into(),
            prefix: String::new(),
            access_key_id: "k".into(),
            secret_access_key: "s".into(),
            path_style: true,
            storage_class: None,
            allow_insecure_http: false,
            conditional_writes: None,
        })
        .unwrap()
    }

    #[test]
    fn a_response_that_claims_two_gib_is_refused_without_reading_it() {
        // The server announces 2 GiB and sends a few bytes: the length alone
        // is the answer, nothing is allocated for it.
        use std::io::{Read, Write};
        for key in ["manifests/x", "chunks/ab/cdef"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let th = std::thread::spawn(move || {
                let (mut c, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf);
                let _ = c.write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", 2u64 << 30).as_bytes(),
                );
                let _ = c.write_all(&[0u8; 64]);
                std::thread::sleep(std::time::Duration::from_millis(300));
            });
            let e = storage_for(port).get(key).unwrap_err();
            assert!(format!("{e:#}").contains("more than"), "{e:#}");
            th.join().unwrap();
        }
    }

    #[test]
    fn a_block_read_is_capped_at_a_chunk_not_a_record() {
        // 17 MiB is a fine record but not a block object.
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let th = std::thread::spawn(move || {
            for _ in 0..2 {
                let req = server.recv().unwrap();
                let _ = req.respond(tiny_http::Response::from_data(vec![7u8; 17 << 20]));
            }
        });
        let s = storage_for(port);
        assert_eq!(s.get("manifests/x").unwrap().unwrap().len(), 17 << 20);
        assert!(s.get("chunks/ab/cdef").is_err());
        th.join().unwrap();
    }

    #[test]
    fn large_objects_are_uploaded_in_parts() {
        // A look-alike of the multipart calls: start, parts, completion.
        let server = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = server.server_addr().to_ip().unwrap().port();
        let srv = server.clone();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log = seen.clone();
        let th = std::thread::spawn(move || {
            let mut parts: std::collections::BTreeMap<u32, Vec<u8>> = Default::default();
            let mut done: Option<Vec<u8>> = None;
            for mut req in srv.incoming_requests() {
                let url = req.url().to_string();
                let method = req.method().as_str().to_string();
                log.lock().unwrap().push(format!("{method} {url}"));
                let mut body = Vec::new();
                let _ = std::io::Read::read_to_end(&mut req.as_reader(), &mut body);
                let reply = match method.as_str() {
                    "HEAD" => tiny_http::Response::from_data(Vec::new())
                        .with_status_code(if done.is_some() { 200 } else { 404 }),
                    "POST" if url.contains("uploads") => tiny_http::Response::from_data(
                        b"<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>".to_vec(),
                    ),
                    "PUT" if url.contains("partNumber=") => {
                        let n: u32 = url
                            .split("partNumber=")
                            .nth(1)
                            .unwrap()
                            .split('&')
                            .next()
                            .unwrap()
                            .parse()
                            .unwrap();
                        parts.insert(n, body);
                        tiny_http::Response::from_data(Vec::new())
                    }
                    "POST" => {
                        let etags = body.windows(6).filter(|w| w == b"<ETag>").count();
                        assert_eq!(etags, parts.len());
                        done = Some(parts.values().flatten().copied().collect());
                        tiny_http::Response::from_data(
                            b"<CompleteMultipartUploadResult></CompleteMultipartUploadResult>"
                                .to_vec(),
                        )
                    }
                    "GET" => tiny_http::Response::from_data(done.clone().unwrap_or_default()),
                    _ => tiny_http::Response::from_data(Vec::new()).with_status_code(400),
                };
                let _ = req.respond(reply);
            }
        });
        let s = storage_for(port);
        let data: Vec<u8> = (0..(MULTIPART_ABOVE + 3 * MULTIPART_PART + 5) as u32)
            .map(|i| (i % 253) as u8)
            .collect();
        assert!(s.put_if_absent("packs/ab/abcd", &data).unwrap());
        assert_eq!(s.get("packs/ab/abcd").unwrap().unwrap(), data);
        assert!(!s.put_if_absent("packs/ab/abcd", &data).unwrap());
        let calls = seen.lock().unwrap().clone();
        let parts = calls.iter().filter(|c| c.contains("partNumber=")).count();
        assert_eq!(parts, 8, "{calls:?}");
        server.unblock();
        th.join().unwrap();
    }

    /// How a fake server treats `If-None-Match: *` on an existing object.
    #[derive(Clone, Copy)]
    enum Condition {
        Honoured,
        Ignored,
        Refused,
    }

    /// A small S3 look-alike: PUT, HEAD, DELETE on object keys, with the
    /// methods and paths of every request recorded.
    struct FakeS3 {
        port: u16,
        seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        _thread: std::thread::JoinHandle<()>,
        server: std::sync::Arc<tiny_http::Server>,
    }

    fn fake_s3(how: Condition) -> FakeS3 {
        let server = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = server.server_addr().to_ip().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let (log, srv) = (seen.clone(), server.clone());
        let th = std::thread::spawn(move || {
            let mut objects = std::collections::HashSet::new();
            for mut req in srv.incoming_requests() {
                let path = req.url().to_string();
                let method = req.method().as_str().to_string();
                log.lock().unwrap().push(format!("{method} {path}"));
                let conditional = req.headers().iter().any(|h| h.field.equiv("if-none-match"));
                let mut body = Vec::new();
                let _ = std::io::Read::read_to_end(&mut req.as_reader(), &mut body);
                let status = match method.as_str() {
                    "PUT" => {
                        if conditional && matches!(how, Condition::Refused) {
                            501
                        } else if conditional
                            && matches!(how, Condition::Honoured)
                            && objects.contains(&path)
                        {
                            412
                        } else {
                            objects.insert(path.clone());
                            200
                        }
                    }
                    "HEAD" => {
                        if objects.contains(&path) {
                            200
                        } else {
                            404
                        }
                    }
                    "DELETE" => {
                        objects.remove(&path);
                        204
                    }
                    _ => 400,
                };
                let _ = req.respond(tiny_http::Response::empty(status));
            }
        });
        FakeS3 {
            port,
            seen,
            _thread: th,
            server,
        }
    }

    fn methods(seen: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|l| l.split(' ').next().unwrap().to_string())
            .collect()
    }

    #[test]
    fn conditional_writes_are_probed_once_and_skip_the_head() {
        let f = fake_s3(Condition::Honoured);
        let (seen, server) = (&f.seen, &f.server);
        let s = storage_for(f.port);
        assert_eq!(s.conditional_writes(), None);
        assert!(s.put_if_absent("chunks/ab/abcd", b"x").unwrap());
        assert_eq!(s.conditional_writes(), Some(true));
        // The probe (PUT, PUT, DELETE of a probe object), then one PUT.
        assert_eq!(methods(seen), ["PUT", "PUT", "DELETE", "PUT"]);
        assert!(seen.lock().unwrap()[0].contains("/b/vault/.probe-"));
        assert!(!seen.lock().unwrap()[3].contains(".probe-"));
        // An existing object: one request, answered 412, no HEAD.
        assert!(!s.put_if_absent("chunks/ab/abcd", b"x").unwrap());
        assert!(s.put_if_absent("chunks/cd/cdef", b"y").unwrap());
        assert_eq!(methods(seen)[4..], ["PUT", "PUT"]);
        server.unblock();
    }

    #[test]
    fn a_server_that_ignores_the_condition_gets_head_then_put() {
        let f = fake_s3(Condition::Ignored);
        let (seen, server) = (&f.seen, &f.server);
        let s = storage_for(f.port);
        assert!(s.put_if_absent("chunks/ab/abcd", b"x").unwrap());
        assert_eq!(s.conditional_writes(), Some(false));
        assert_eq!(methods(seen), ["PUT", "PUT", "DELETE", "HEAD", "PUT"]);
        assert!(!s.put_if_absent("chunks/ab/abcd", b"x").unwrap());
        assert_eq!(methods(seen)[5..], ["HEAD"]);
        server.unblock();
    }

    #[test]
    fn a_server_that_refuses_the_condition_gets_head_then_put() {
        let f = fake_s3(Condition::Refused);
        let (seen, server) = (&f.seen, &f.server);
        let s = storage_for(f.port);
        assert!(s.put_if_absent("chunks/ab/abcd", b"x").unwrap());
        assert_eq!(s.conditional_writes(), Some(false));
        // The first conditional PUT is refused: the probe stops there.
        assert_eq!(methods(seen), ["PUT", "DELETE", "HEAD", "PUT"]);
        server.unblock();
    }

    #[test]
    fn a_known_answer_is_not_probed_again() {
        let f = fake_s3(Condition::Honoured);
        let (seen, server) = (&f.seen, &f.server);
        let mut cfg = S3Config {
            name: "test".into(),
            endpoint: format!("http://127.0.0.1:{}", f.port),
            region: "us-east-1".into(),
            bucket: "b".into(),
            prefix: String::new(),
            access_key_id: "k".into(),
            secret_access_key: "s".into(),
            path_style: true,
            storage_class: None,
            allow_insecure_http: false,
            conditional_writes: Some(true),
        };
        let s = S3Storage::new(cfg.clone()).unwrap();
        assert!(s.put_if_absent("chunks/ab/abcd", b"x").unwrap());
        assert_eq!(methods(seen), ["PUT"]);
        cfg.conditional_writes = Some(false);
        let s = S3Storage::new(cfg).unwrap();
        assert!(!s.put_if_absent("chunks/ab/abcd", b"x").unwrap());
        assert_eq!(methods(seen)[1..], ["HEAD"]);
        server.unblock();
    }

    #[test]
    fn plain_http_needs_a_loopback_address_or_an_explicit_choice() {
        let cfg = |endpoint: &str, allow: bool| S3Config {
            name: "test".into(),
            endpoint: endpoint.into(),
            region: "us-east-1".into(),
            bucket: "b".into(),
            prefix: String::new(),
            access_key_id: "k".into(),
            secret_access_key: "s".into(),
            path_style: true,
            storage_class: None,
            allow_insecure_http: allow,
            conditional_writes: None,
        };
        for ok in [
            "https://s3.example.net",
            "http://127.0.0.1:9000",
            "http://127.0.0.2:9000",
            "http://localhost:9000",
            "http://LOCALHOST",
            "http://[::1]:9000",
        ] {
            S3Storage::new(cfg(ok, false)).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for refused in [
            "http://minio.lan:9000",
            "http://10.0.0.5",
            "http://[fe80::1]:9000",
        ] {
            let e = match S3Storage::new(cfg(refused, false)) {
                Ok(_) => panic!("{refused} was accepted"),
                Err(e) => e.to_string(),
            };
            assert!(e.contains("--insecure-http"), "{refused}: {e}");
            S3Storage::new(cfg(refused, true)).unwrap_or_else(|e| panic!("{refused}: {e}"));
        }
        assert!(S3Storage::new(cfg("ftp://x", true)).is_err());
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
