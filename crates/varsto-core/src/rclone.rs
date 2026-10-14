// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Any rclone remote as a storage. Varsto runs the user's own `rclone`
//! binary and never sees the remote's credentials: they stay in rclone's
//! configuration. Object names map to files under the remote path.

use crate::storage::Storage;
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

pub struct RcloneStorage {
    name: String,
    /// `remote:bucket/path` as rclone understands it, without trailing slash.
    remote: String,
    binary: String,
}

impl RcloneStorage {
    pub fn new(name: String, remote: String) -> Result<Self> {
        let remote = remote.trim().trim_end_matches('/').to_string();
        if !remote.contains(':') {
            bail!("rclone remote must look like `name:path` (see `rclone listremotes`)");
        }
        let binary = std::env::var("VARSTO_RCLONE").unwrap_or_else(|_| "rclone".to_string());
        check_binary(&binary)?;
        Ok(RcloneStorage {
            name,
            remote,
            binary,
        })
    }

    fn target(&self, key: &str) -> String {
        format!("{}/{}", self.remote, key)
    }

    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<(bool, Vec<u8>, String)> {
        let mut cmd = Command::new(&self.binary);
        // Flags first, then `--`, then the remote path: a path that starts
        // with a dash is never read as a flag.
        let (flags, paths): (Vec<&&str>, Vec<&&str>) = args
            .iter()
            .partition(|a| a.starts_with('-') || !a.contains(':'));
        let (mut head, mut tail): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
        for a in args {
            if paths.contains(&a) && !flags.contains(&a) {
                tail.push(a);
            } else {
                head.push(a);
            }
        }
        cmd.args(&head)
            .arg("--")
            .args(&tail)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let t = crate::logging::Timer::start();
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn {}", self.binary))?;
        if let Some(data) = stdin {
            let mut pipe = child.stdin.take().expect("piped stdin");
            pipe.write_all(data)?;
            drop(pipe);
        }
        let out = child.wait_with_output()?;
        // rclone's exit codes: 3 = directory not found, 4 = file not found.
        // Anything else that fails is an error, never "absent": a transport
        // failure must not look like a missing object.
        let code = out.status.code().unwrap_or(-1);
        let stderr = if !out.status.success() && (code == 3 || code == 4) {
            format!("{NOT_FOUND_MARK}{}", String::from_utf8_lossy(&out.stderr))
        } else {
            String::from_utf8_lossy(&out.stderr).to_string()
        };
        let op = args
            .iter()
            .find(|a| !a.starts_with('-'))
            .copied()
            .unwrap_or("");
        let target = tail.first().copied().unwrap_or("");
        let level = if out.status.success() || code == 3 || code == 4 {
            log::Level::Trace
        } else {
            log::Level::Debug
        };
        log::log!(
            level,
            storage = self.name.as_str(),
            backend = "rclone",
            op = op,
            target = target,
            sent = stdin.map(|d| d.len()).unwrap_or(0),
            got = out.stdout.len(),
            code = code,
            ms = t.ms();
            "rclone call{}",
            if out.status.success() { String::new() } else { format!(": {}", stderr.trim().replace(NOT_FOUND_MARK, "")) }
        );
        Ok((out.status.success(), out.stdout, stderr))
    }
}

/// Binaries that answered `rclone version` in this process: a storage is
/// opened many times per sync, and the check is the same every time. A
/// failure is not remembered, so installing rclone takes effect at once.
static CHECKED: std::sync::Mutex<Option<std::collections::HashSet<String>>> =
    std::sync::Mutex::new(None);

fn check_binary(binary: &str) -> Result<()> {
    if CHECKED
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|c| c.contains(binary))
    {
        return Ok(());
    }
    let st = Command::new(binary)
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("run {binary} (install rclone or set VARSTO_RCLONE)"))?;
    if !st.success() {
        bail!("{binary} version failed");
    }
    CHECKED
        .lock()
        .unwrap()
        .get_or_insert_with(Default::default)
        .insert(binary.to_string());
    Ok(())
}

const NOT_FOUND_MARK: &str = "\u{1}rclone-not-found\u{1}";

fn is_not_found(stderr: &str) -> bool {
    stderr.starts_with(NOT_FOUND_MARK)
}

impl Storage for RcloneStorage {
    fn name(&self) -> &str {
        &self.name
    }

    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        crate::storage::validate_key(key)?;
        if self.exists(key)? {
            return Ok(false);
        }
        let (ok, _, err) = self.run(&["rcat", &self.target(key)], Some(data))?;
        if !ok {
            bail!("rclone rcat {key}: {}", err.trim());
        }
        Ok(true)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        crate::storage::validate_key(key)?;
        let (ok, out, err) = self.run(&["cat", &self.target(key)], None)?;
        if ok {
            Ok(Some(out))
        } else if is_not_found(&err) {
            Ok(None)
        } else {
            bail!("rclone cat {key}: {}", err.trim())
        }
    }

    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        crate::storage::validate_key(key)?;
        let (off, count) = (offset.to_string(), len.to_string());
        let (ok, out, err) = self.run(
            &[
                "cat",
                "--offset",
                &off,
                "--count",
                &count,
                &self.target(key),
            ],
            None,
        )?;
        if ok {
            Ok(Some(out))
        } else if is_not_found(&err) {
            Ok(None)
        } else {
            bail!("rclone cat {key}: {}", err.trim())
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        crate::storage::validate_key(key)?;
        let (ok, out, err) = self.run(&["lsjson", "--stat", &self.target(key)], None)?;
        if ok {
            Ok(!out.is_empty() && String::from_utf8_lossy(&out).trim() != "null")
        } else if is_not_found(&err) {
            Ok(false)
        } else {
            bail!("rclone lsjson {key}: {}", err.trim())
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        // List the directory part of the prefix recursively and filter.
        let (dir, _) = prefix.rsplit_once('/').unwrap_or(("", prefix));
        let path = if dir.is_empty() {
            self.remote.clone()
        } else {
            format!("{}/{}", self.remote, dir)
        };
        let (ok, out, err) = self.run(&["lsf", "-R", "--files-only", &path], None)?;
        if !ok {
            if is_not_found(&err) {
                return Ok(Vec::new());
            }
            bail!("rclone lsf {prefix}: {}", err.trim());
        }
        let mut keys: Vec<String> = String::from_utf8_lossy(&out)
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                if dir.is_empty() {
                    l.to_string()
                } else {
                    format!("{dir}/{l}")
                }
            })
            .filter(|k| k.starts_with(prefix))
            .collect();
        keys.sort();
        Ok(keys)
    }

    fn delete(&self, key: &str) -> Result<()> {
        crate::storage::validate_key(key)?;
        let (ok, _, err) = self.run(&["deletefile", &self.target(key)], None)?;
        if ok || is_not_found(&err) {
            Ok(())
        } else {
            bail!("rclone deletefile {key}: {}", err.trim())
        }
    }
}
