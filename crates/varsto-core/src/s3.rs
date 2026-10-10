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

pub struct S3Storage {
    cfg: S3Config,
    agent: ureq::Agent,
    host: String,
    scheme: String,
    /// Path prefix of every request (`/bucket` for path style, empty otherwise).
    base_path: String,
}

/// Largest response body read into memory. Chunks are at most a few MiB;
/// manifests and ledger batches grow with the number of files.
const MAX_BODY: u64 = 2 << 30;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

impl S3Storage {
    pub fn new(cfg: S3Config) -> Result<Self> {
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
        })
    }

    fn object_path(&self, key: &str) -> String {
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

    /// Build and sign a request. `query` must already be sorted by key.
    fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        extra_headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>)> {
        let amz_date = amz_date_now();
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
        Ok((status, bytes))
    }

    fn put(&self, key: &str, data: &[u8], if_none_match: bool) -> Result<u16> {
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if if_none_match {
            headers.push(("if-none-match", "*"));
        }
        if let Some(c) = &self.cfg.storage_class {
            headers.push(("x-amz-storage-class", c));
        }
        let (status, body) = self.request("PUT", &self.object_path(key), &[], &headers, data)?;
        if status >= 500 {
            bail!(
                "PUT {key}: HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        Ok(status)
    }
}

/// `YYYYMMDDTHHMMSSZ` for the current UTC time, without a date crate.
fn amz_date_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
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
                s => bail!("PUT {key}: HTTP {s}"),
            },
            s => bail!("PUT {key}: HTTP {s}"),
        }
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let (status, body) = self.request("GET", &self.object_path(key), &[], &[], &[])?;
        match status {
            200 => Ok(Some(body)),
            404 => Ok(None),
            403 if String::from_utf8_lossy(&body).contains("InvalidObjectState") => {
                bail!("GET {key}: object is in a cold storage class and must be restored first")
            }
            s => bail!("GET {key}: HTTP {s}: {}", String::from_utf8_lossy(&body)),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let (status, _) = self.request("HEAD", &self.object_path(key), &[], &[], &[])?;
        match status {
            200 => Ok(true),
            404 => Ok(false),
            s => bail!("HEAD {key}: HTTP {s}"),
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
                bail!(
                    "LIST {prefix}: HTTP {status}: {}",
                    String::from_utf8_lossy(&body)
                );
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
        let (status, body) = self.request("DELETE", &self.object_path(key), &[], &[], &[])?;
        match status {
            200 | 202 | 204 | 404 => Ok(()),
            s => bail!("DELETE {key}: HTTP {s}: {}", String::from_utf8_lossy(&body)),
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
