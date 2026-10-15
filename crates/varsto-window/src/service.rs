// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The background service as the window sees it: `service.json` in the device
//! directory names its port and session token; a one-time boot code (valid
//! for a minute) opens the interface, so the token is in no address.

use serde::Deserialize;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct ServiceFile {
    pub port: u16,
    pub token: String,
    #[serde(default)]
    pub started_utc: i64,
}

/// The device directory: `--home`, else `VARSTO_HOME`, else `%APPDATA%\Varsto`
/// (what `varsto.exe` uses).
pub fn home(arg: Option<PathBuf>) -> Option<PathBuf> {
    arg.or_else(|| std::env::var_os("VARSTO_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("Varsto")))
}

pub fn read(home: &Path) -> Option<ServiceFile> {
    serde_json::from_slice(&std::fs::read(home.join("service.json")).ok()?).ok()
}

/// One request to the service on 127.0.0.1; the body of a 2xx answer.
pub fn call(f: &ServiceFile, method: &str, path: &str, body: &str) -> Result<String, String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], f.port));
    let mut s =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    // One write: the request goes out in a single segment.
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Varsto-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        f.port,
        f.token,
        body.len()
    );
    s.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    parse_response(&String::from_utf8_lossy(&raw))
}

fn parse_response(text: &str) -> Result<String, String> {
    let (head, body) = text.split_once("\r\n\r\n").ok_or("bad response")?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if (200..300).contains(&status) {
        Ok(body.to_string())
    } else {
        Err(format!("the service answered {status}"))
    }
}

/// The service recorded in `service.json`, when it answers.
pub fn alive(home: &Path) -> Option<ServiceFile> {
    let f = read(home)?;
    call(&f, "GET", "/api/service", "").ok()?;
    Some(f)
}

/// The address that opens the interface, with a one-time boot code.
pub fn boot_url(f: &ServiceFile) -> Result<String, String> {
    let answer = call(f, "POST", "/api/session/boot", "{}")?;
    let v: serde_json::Value = serde_json::from_str(&answer).map_err(|e| e.to_string())?;
    let code = v["boot"].as_str().ok_or("the service gave no start code")?;
    Ok(format!("http://127.0.0.1:{}/?boot={code}", f.port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_read() {
        assert_eq!(
            parse_response("HTTP/1.1 200 OK\r\nA: b\r\n\r\n{\"boot\":\"x\"}"),
            Ok("{\"boot\":\"x\"}".to_string())
        );
        assert!(parse_response("HTTP/1.1 401 Unauthorized\r\n\r\nno").is_err());
        assert!(parse_response("garbage").is_err());
    }

    #[test]
    fn service_file_is_read() {
        let f: ServiceFile = serde_json::from_str(
            r#"{"pid": 4, "port": 5123, "token": "abc", "started_utc": 77, "version": "1"}"#,
        )
        .unwrap();
        assert_eq!((f.port, f.token.as_str(), f.started_utc), (5123, "abc", 77));
    }

    #[test]
    fn boot_code_comes_from_the_service() {
        // A tiny stand-in for the service: answers one POST with a boot code.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            // Read the whole request (head and the two-byte body) before answering.
            let mut req = String::new();
            let mut buf = [0u8; 2048];
            while !req.ends_with("\r\n\r\n{}") {
                let n = c.read(&mut buf).unwrap();
                assert!(n > 0, "connection closed early");
                req.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
            let body = r#"{"boot":"c0de"}"#;
            write!(
                c,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            req
        });
        let f = ServiceFile {
            port,
            token: "tok".into(),
            started_utc: 0,
        };
        assert_eq!(
            boot_url(&f).unwrap(),
            format!("http://127.0.0.1:{port}/?boot=c0de")
        );
        let req = t.join().unwrap();
        assert!(req.starts_with("POST /api/session/boot HTTP/1.1"));
        assert!(req.contains("X-Varsto-Token: tok"));
    }
}
