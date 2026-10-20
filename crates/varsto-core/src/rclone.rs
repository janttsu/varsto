// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Any rclone remote as a storage. Varsto runs the user's own `rclone`
//! binary and never sees the remote's credentials: they stay in rclone's
//! configuration. Object names map to files under the remote path.

use crate::storage::Storage;
use anyhow::{anyhow, bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

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
        self.run_capped(args, stdin, MAX_OUTPUT)
    }

    /// `run`, reading at most `cap` bytes of rclone's output: a longer
    /// answer ends the command and is an error, never held in memory.
    fn run_capped(
        &self,
        args: &[&str],
        stdin: Option<&[u8]>,
        cap: u64,
    ) -> Result<(bool, Vec<u8>, String)> {
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
        // Never let an unreachable remote hold the call: rclone's own
        // timeouts and a single retry, and below them a wall-clock kill.
        // The subcommand stays first, as wrappers expect.
        let (sub, rest) = head
            .split_first()
            .map_or((None, &head[..]), |(s, r)| (Some(*s), r));
        if let Some(sub) = sub {
            cmd.arg(sub);
        }
        cmd.args(NETWORK_FLAGS)
            .args(rest)
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
        let size = stdin
            .map(|d| d.len() as u64)
            .unwrap_or(cap.min(crate::storage::MAX_PACK));
        let what = format!(
            "rclone {} {}",
            args.first().copied().unwrap_or(""),
            self.name
        );
        let out = run_child(cmd, stdin, cap, wall_clock(size), &what)?;
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
    let mut cmd = Command::new(binary);
    cmd.arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // `rclone version` is local, but a broken wrapper must not hang opening.
    let st = run_child(
        cmd,
        None,
        1 << 20,
        Duration::from_secs(30),
        "rclone version",
    )
    .with_context(|| format!("run {binary} (install rclone or set VARSTO_RCLONE)"))?
    .status;
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

/// Flags that bound every rclone call on a dead network: connect in 10 s, no
/// byte for 60 s ends the transfer, one try with two low-level retries.
const NETWORK_FLAGS: [&str; 8] = [
    "--contimeout",
    "10s",
    "--timeout",
    "60s",
    "--retries",
    "1",
    "--low-level-retries",
    "2",
];

/// Wall-clock limit of one call moving about `size` bytes: two minutes and
/// the time a 256 kbit/s link needs for the bytes, at most two hours.
fn wall_clock(size: u64) -> Duration {
    Duration::from_secs((120 + size / (32 << 10)).min(7200))
}

/// What a finished child left behind.
struct ChildOut {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run `cmd` (stdout and stderr piped, stdin piped when `stdin` is given),
/// reading at most `cap` bytes of its output. A child still running after
/// `wall` is killed through its own handle (never by name) and the call
/// is a network error: a stuck transfer must not hold a sync.
fn run_child(
    mut cmd: Command,
    stdin: Option<&[u8]>,
    cap: u64,
    wall: Duration,
    what: &str,
) -> Result<ChildOut> {
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    let child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", cmd.get_program().to_string_lossy()))?;
    let child = Arc::new(Mutex::new(child));
    let (stdin_pipe, mut stdout_pipe, mut stderr_pipe) = {
        let mut c = child.lock().unwrap();
        (
            c.stdin.take(),
            c.stdout.take().expect("piped stdout"),
            c.stderr.take().expect("piped stderr"),
        )
    };
    // The watchdog starts before anything is written: a child that never
    // reads its stdin would block the write for good.
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let fired = Arc::new(AtomicBool::new(false));
    let dog = {
        let (child, gate, fired) = (child.clone(), gate.clone(), fired.clone());
        std::thread::spawn(move || {
            let (lock, cv) = &*gate;
            let guard = lock.lock().unwrap();
            let (guard, _) = cv.wait_timeout_while(guard, wall, |done| !*done).unwrap();
            if !*guard {
                fired.store(true, Ordering::SeqCst);
                let _ = child.lock().unwrap().kill();
            }
        })
    };
    // Drain stderr on a thread (keeping its first MiB) so the child
    // never blocks on a full pipe while stdout is read.
    let err_reader = std::thread::spawn(move || {
        let (mut keep, mut buf) = (Vec::new(), [0u8; 8192]);
        while let Ok(n) = stderr_pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            if keep.len() < 1 << 20 {
                keep.extend_from_slice(&buf[..n]);
            }
        }
        keep
    });
    let mut write_err = None;
    if let (Some(data), Some(mut pipe)) = (stdin, stdin_pipe) {
        if let Err(e) = pipe.write_all(data) {
            write_err = Some(e);
        }
        drop(pipe);
    }
    let mut stdout = Vec::new();
    let read = (&mut stdout_pipe).take(cap + 1).read_to_end(&mut stdout);
    let overflow = stdout.len() as u64 > cap;
    if overflow {
        let _ = child.lock().unwrap().kill();
    }
    drop(stdout_pipe);
    let status = loop {
        match child.lock().unwrap().try_wait() {
            Ok(Some(st)) => break Ok(st),
            Ok(None) => {}
            Err(e) => break Err(e),
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    {
        let (lock, cv) = &*gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    let _ = dog.join();
    let stderr = err_reader.join().unwrap_or_default();
    let status = status?;
    if fired.load(Ordering::SeqCst) && !status.success() {
        return Err(crate::storage::network_unavailable(
            what,
            format!(
                "no result within {} s; the stuck rclone was stopped",
                wall.as_secs()
            ),
        ));
    }
    if overflow {
        bail!("rclone answered with more than the {cap} bytes allowed; not read");
    }
    read?;
    if let Some(e) = write_err {
        if status.success() {
            return Err(e.into());
        }
    }
    Ok(ChildOut {
        status,
        stdout,
        stderr,
    })
}

/// The error for a failed rclone call: a network error when rclone's words
/// say the remote could not be reached, otherwise a plain failure.
fn failure(what: &str, stderr: &str) -> anyhow::Error {
    let msg = stderr.trim();
    let low = msg.to_lowercase();
    const NETWORK: [&str; 12] = [
        "i/o timeout",
        "no such host",
        "connection refused",
        "connection reset",
        "network is unreachable",
        "no route to host",
        "tls handshake timeout",
        "context deadline exceeded",
        "dial tcp",
        "timeout awaiting response",
        "temporary failure in name resolution",
        "server misbehaving",
    ];
    if NETWORK.iter().any(|n| low.contains(n)) {
        crate::storage::network_unavailable(what, msg)
    } else {
        anyhow!("{what}: {msg}")
    }
}

/// Most output of one rclone command that is not an object read (listings).
const MAX_OUTPUT: u64 = 1 << 30;

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
            return Err(failure(&format!("rclone rcat {key}"), &err));
        }
        Ok(true)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get_bounded(key, crate::storage::read_limit(key))
    }

    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        crate::storage::validate_key(key)?;
        // One byte more than allowed says "too large" without reading the rest.
        let count = (max + 1).to_string();
        let (ok, out, err) = self.run_capped(
            &["cat", "--count", &count, &self.target(key)],
            None,
            max + 1,
        )?;
        if ok {
            if out.len() as u64 > max {
                return Err(crate::storage::too_large(key, out.len() as u64, max));
            }
            Ok(Some(out))
        } else if is_not_found(&err) {
            Ok(None)
        } else {
            Err(failure(&format!("rclone cat {key}"), &err))
        }
    }

    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        crate::storage::validate_key(key)?;
        let len = len.min(crate::storage::MAX_PACK);
        if offset.checked_add(len).is_none() {
            bail!("rclone cat {key}: the range starting at {offset} is out of bounds");
        }
        let (off, count) = (offset.to_string(), len.to_string());
        let (ok, out, err) = self.run_capped(
            &[
                "cat",
                "--offset",
                &off,
                "--count",
                &count,
                &self.target(key),
            ],
            None,
            len + 1,
        )?;
        if ok {
            Ok(Some(out))
        } else if is_not_found(&err) {
            Ok(None)
        } else {
            Err(failure(&format!("rclone cat {key}"), &err))
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
            Err(failure(&format!("rclone lsjson {key}"), &err))
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
            return Err(failure(&format!("rclone lsf {prefix}"), &err));
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
            Err(failure(&format!("rclone deletefile {key}"), &err))
        }
    }
}

/// An rclone remote written as `name:path`, with `alias` remotes followed to
/// what they point at (`rclone config dump`: only each remote's `type` and,
/// for an alias, its `remote` are read, never a token or password). Without
/// rclone or on any problem the remote is returned as given.
pub fn resolve_alias(remote: &str) -> String {
    let binary = std::env::var("VARSTO_RCLONE").unwrap_or_else(|_| "rclone".to_string());
    let Ok(out) = Command::new(&binary)
        .args(["config", "dump"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return remote.to_string();
    };
    let Ok(dump) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return remote.to_string();
    };
    let mut cur = remote.trim().to_string();
    for _ in 0..8 {
        let Some((name, path)) = cur.split_once(':') else {
            break;
        };
        let section = &dump[name];
        if section["type"].as_str() != Some("alias") {
            break;
        }
        let Some(target) = section["remote"].as_str() else {
            break;
        };
        let path = path.trim_matches('/');
        cur = if path.is_empty() {
            target.trim_end_matches('/').to_string()
        } else {
            format!("{}/{path}", target.trim_end_matches('/'))
        };
    }
    cur
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    #[test]
    fn a_stuck_child_is_killed_and_is_a_network_error() {
        let t = std::time::Instant::now();
        let e = match run_child(
            sh("exec sleep 60"),
            Some(b"data"),
            1 << 20,
            Duration::from_millis(300),
            "rclone cat test",
        ) {
            Ok(_) => panic!("a stuck child returned"),
            Err(e) => e,
        };
        assert!(crate::storage::is_network_error(&e), "{e:#}");
        assert!(t.elapsed() < Duration::from_secs(20));
    }

    #[test]
    fn a_child_that_never_reads_stdin_is_killed_too() {
        // More than a pipe holds: the write blocks until the kill.
        let big = vec![0u8; 8 << 20];
        let e = match run_child(
            sh("exec sleep 60"),
            Some(&big),
            1 << 20,
            Duration::from_millis(300),
            "rclone rcat test",
        ) {
            Ok(_) => panic!("a stuck child returned"),
            Err(e) => e,
        };
        assert!(crate::storage::is_network_error(&e), "{e:#}");
    }

    #[test]
    fn a_quick_child_is_not_disturbed() {
        let out = run_child(
            sh("printf abc; echo oops >&2; exit 3"),
            None,
            1 << 20,
            Duration::from_secs(30),
            "x",
        )
        .unwrap();
        assert_eq!(out.stdout, b"abc");
        assert_eq!(out.status.code(), Some(3));
        assert!(String::from_utf8_lossy(&out.stderr).contains("oops"));
    }

    #[test]
    fn failures_are_told_apart_by_rclones_words() {
        let net = failure(
            "rclone cat k",
            "Failed: dial tcp: lookup s3.example: no such host",
        );
        assert!(crate::storage::is_network_error(&net));
        let other = failure("rclone cat k", "Failed: AccessDenied");
        assert!(!crate::storage::is_network_error(&other));
    }

    #[test]
    fn the_wall_clock_grows_with_the_size() {
        assert_eq!(wall_clock(0), Duration::from_secs(120));
        assert!(wall_clock(64 << 20) > Duration::from_secs(1800));
        assert_eq!(wall_clock(u64::MAX), Duration::from_secs(7200));
    }
}
