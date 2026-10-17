// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Where `varsto service remember` keeps the vault passphrase so that the
//! background service starts unlocked (spec section 72).
//!
//! Stores are tried in this order, and the one used is always named:
//!
//! 1. the desktop keyring (Secret Service through `secret-tool`; the macOS
//!    login keychain through `security`);
//! 2. `systemd-creds encrypt --user` (Linux): the passphrase goes through
//!    standard input and output of the tool into `passphrase.cred` in the
//!    device directory (mode 600). It works without a desktop session and
//!    survives a restart;
//! 3. the Linux kernel keyring of the user (`@u`): kept until the computer
//!    restarts or the user has no process left, never on disk.
//!
//! The passphrase is never written in plain text to a file, never put in the
//! environment or in a command line, and never printed. At service start the
//! stores are read cheapest first (systemd-creds, kernel keyring, keyring).

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The places a passphrase can be remembered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Store {
    /// Secret Service keyring (Linux desktop).
    Keyring,
    /// `systemd-creds` credential file in the device directory.
    SystemdCreds,
    /// Linux kernel user keyring.
    KernelKeyring,
    /// macOS login keychain.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Keychain,
}

impl Store {
    /// Short name used in messages and in the error that lists what was tried.
    pub fn name(self) -> &'static str {
        match self {
            Store::Keyring => "desktop keyring",
            Store::SystemdCreds => "systemd-creds",
            Store::KernelKeyring => "kernel keyring",
            Store::Keychain => "login keychain",
        }
    }

    /// Stable identifier for JSON output.
    pub fn id(self) -> &'static str {
        match self {
            Store::Keyring => "keyring",
            Store::SystemdCreds => "systemd-creds",
            Store::KernelKeyring => "kernel-keyring",
            Store::Keychain => "keychain",
        }
    }

    /// What `remember` tells the user after storing there.
    pub fn kept_text(self, home: &Path) -> String {
        match self {
            Store::Keyring => "kept in your keyring".into(),
            Store::Keychain => "kept in the login keychain".into(),
            Store::SystemdCreds => format!(
                "kept encrypted with systemd-creds in {}; the service reads it at start, also without a desktop session and after a restart",
                cred_file(home).display()
            ),
            Store::KernelKeyring => "kept in the kernel keyring of your user, only until this computer restarts or you have no session left; it is not on disk. After a restart, run `varsto unlock` (or `varsto service remember` again)".into(),
        }
    }
}

/// The line `varsto service status` shows about the remembered passphrase.
pub fn status_text(store: Option<Store>) -> String {
    match store {
        Some(Store::Keyring) => "passphrase: remembered in the desktop keyring".into(),
        Some(Store::Keychain) => "passphrase: remembered in the login keychain".into(),
        Some(Store::SystemdCreds) => {
            "passphrase: remembered, encrypted with systemd-creds (survives a restart)".into()
        }
        Some(Store::KernelKeyring) => {
            "passphrase: remembered in the kernel keyring (until this computer restarts)".into()
        }
        None => "passphrase: not remembered (`varsto service remember` keeps it; until then any varsto command that asks for the passphrase unlocks the service)".into(),
    }
}

/// One place that can keep the passphrase.
pub trait Backend {
    fn kind(&self) -> Store;
    /// Store the passphrase (replacing an older one) or say why not.
    fn store(&self, home: &Path, pass: &str) -> Result<()>;
    /// The stored passphrase, if there is one that can be read now.
    fn load(&self, home: &Path) -> Option<String>;
    /// Whether something is stored (without necessarily reading it).
    fn present(&self, home: &Path) -> bool {
        self.load(home).is_some()
    }
    /// Remove what is stored; `true` when there was something.
    fn forget(&self, home: &Path) -> Result<bool>;
}

/// What a successful `remember` did.
#[derive(Debug)]
pub struct Remembered {
    pub store: Store,
    /// Why the stores tried before it could not be used.
    pub skipped: Vec<String>,
}

/// The error when no store works: names everything that was tried.
fn failure_text(tried: &[String]) -> String {
    if tried.is_empty() {
        return "no system keyring support on this platform".into();
    }
    format!(
        "could not remember the passphrase here. Tried: {}. Instead, set the VARSTO_PASSPHRASE environment variable for the service, or unlock it with `varsto unlock`",
        tried.join("; ")
    )
}

/// Store in the first backend that works, then drop copies left in the
/// others so that one store is the truth (and `status` has one answer).
pub fn remember_with(chain: &[Box<dyn Backend>], home: &Path, pass: &str) -> Result<Remembered> {
    let mut tried = Vec::new();
    for b in chain {
        match b.store(home, pass) {
            Ok(()) => {
                for other in chain.iter().filter(|o| o.kind() != b.kind()) {
                    let _ = other.forget(home);
                }
                return Ok(Remembered {
                    store: b.kind(),
                    skipped: tried,
                });
            }
            Err(e) => tried.push(format!("{}: {e:#}", b.kind().name())),
        }
    }
    Err(anyhow!(failure_text(&tried)))
}

/// The remembered passphrase, reading cheap stores before the keyring.
pub fn load_with(chain: &[Box<dyn Backend>], home: &Path) -> Option<String> {
    chain.iter().rev().find_map(|b| b.load(home))
}

/// Where the passphrase is remembered, if anywhere.
pub fn where_with(chain: &[Box<dyn Backend>], home: &Path) -> Option<Store> {
    chain
        .iter()
        .rev()
        .find(|b| b.present(home))
        .map(|b| b.kind())
}

/// Remove the passphrase from every store; the stores it was found in.
pub fn forget_with(chain: &[Box<dyn Backend>], home: &Path) -> Result<Vec<Store>> {
    let mut removed = Vec::new();
    let mut errors = Vec::new();
    for b in chain {
        match b.forget(home) {
            Ok(true) => removed.push(b.kind()),
            Ok(false) => {}
            Err(e) => errors.push(format!("{}: {e:#}", b.kind().name())),
        }
    }
    if errors.is_empty() {
        Ok(removed)
    } else {
        Err(anyhow!(
            "could not remove the remembered passphrase from: {}",
            errors.join("; ")
        ))
    }
}

/// The stores of this platform, in the order `remember` tries them.
pub fn system_chain() -> Vec<Box<dyn Backend>> {
    #[allow(unused_mut)]
    let mut v: Vec<Box<dyn Backend>> = Vec::new();
    #[cfg(target_os = "macos")]
    v.push(Box::new(Keychain));
    #[cfg(target_os = "linux")]
    {
        v.push(Box::new(SecretService));
        v.push(Box::new(SystemdCreds::new()));
        v.push(Box::new(KernelKeyring));
    }
    v
}

/// Remember the passphrase in the best store here; the text to show.
pub fn remember(home: &Path, pass: &str) -> Result<String> {
    let r = remember_with(&system_chain(), home, pass)?;
    let mut text = format!("Passphrase {}", r.store.kept_text(home));
    if !r.skipped.is_empty() {
        text.push_str(&format!("\n(not used: {})", r.skipped.join("; ")));
    }
    Ok(text)
}

/// The passphrase from the stores of this platform.
pub fn load(home: &Path) -> Option<String> {
    load_with(&system_chain(), home)
}

/// Where the passphrase is remembered on this computer.
pub fn where_remembered(home: &Path) -> Option<Store> {
    where_with(&system_chain(), home)
}

/// Remove the remembered passphrase everywhere; the text to show.
pub fn forget(home: &Path) -> Result<String> {
    let removed = forget_with(&system_chain(), home)?;
    Ok(if removed.is_empty() {
        "no passphrase was remembered".into()
    } else {
        format!(
            "forgot the remembered passphrase ({}); the service stays unlocked until it restarts",
            removed
                .iter()
                .map(|s| s.name())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

/// The credential file of `systemd-creds` in the device directory.
pub fn cred_file(home: &Path) -> PathBuf {
    home.join("passphrase.cred")
}

/// Run `program` with `args`, feeding `stdin`, and kill it after `timeout`.
/// Output is read on threads so a full pipe cannot stall it. The timeout
/// error reads "<program> timed out".
pub fn run_with_timeout(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<std::process::Output> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("{program} is not installed"))?;
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // A tool that exits early closes the pipe: its exit status tells.
        let _ = pipe.write_all(data);
    }
    let mut out_pipe = child.stdout.take().expect("piped");
    let mut err_pipe = child.stderr.take().expect("piped");
    let out_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out_pipe.read_to_end(&mut b);
        b
    });
    let err_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err_pipe.read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!("{program} timed out"));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ok(std::process::Output {
        status,
        stdout: out_t.join().unwrap_or_default(),
        stderr: err_t.join().unwrap_or_default(),
    })
}

fn account(home: &Path) -> String {
    home.display().to_string()
}

// ---------------------------------------------------------------------------
// Linux: Secret Service

/// Long enough to type a password into an unlock window.
#[cfg(target_os = "linux")]
const SECRET_TOOL_STORE_TIMEOUT: Duration = Duration::from_secs(90);
/// A locked keyring makes secret-tool wait for an unlock window, which never
/// appears without a desktop session: give up after a while instead of
/// hanging the service at start.
#[cfg(target_os = "linux")]
const SECRET_TOOL_LOOKUP_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(target_os = "linux")]
const SECRET_TOOL_FORGET_TIMEOUT: Duration = Duration::from_secs(5);

/// No desktop keyring can be reached from this process: no display, and
/// either a remote login (SSH) or no session bus.
#[cfg(target_os = "linux")]
fn no_desktop_keyring() -> bool {
    if crate::service::has_display() {
        return false;
    }
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    set("SSH_CONNECTION") || set("SSH_TTY") || !set("DBUS_SESSION_BUS_ADDRESS")
}

#[cfg(target_os = "linux")]
pub struct SecretService;

#[cfg(target_os = "linux")]
impl Backend for SecretService {
    fn kind(&self) -> Store {
        Store::Keyring
    }

    fn store(&self, home: &Path, pass: &str) -> Result<()> {
        use std::io::Write;
        if no_desktop_keyring() {
            return Err(anyhow!(
                "no desktop session: no keyring can be reached from this session (over SSH, for example)"
            ));
        }
        if crate::service::keyring_locked() == Some(true) && !crate::service::has_display() {
            return Err(anyhow!(
                "the keyring is locked and this session has no desktop to unlock it"
            ));
        }
        let _ = std::io::stdout().flush();
        eprintln!("Storing it in your keyring. If a window asks to unlock the keyring, enter your login password there.");
        let acct = account(home);
        let out = run_with_timeout(
            "secret-tool",
            &[
                "store",
                "--label=Varsto",
                "service",
                "varsto",
                "home",
                &acct,
            ],
            Some(pass.as_bytes()),
            SECRET_TOOL_STORE_TIMEOUT,
        )
        .map_err(|e| {
            if e.to_string() == "secret-tool timed out" {
                anyhow!(
                    "the keyring did not answer within {} seconds",
                    SECRET_TOOL_STORE_TIMEOUT.as_secs()
                )
            } else {
                e
            }
        })?;
        if !out.status.success() {
            return Err(anyhow!(
                "secret-tool could not store it: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    fn load(&self, home: &Path) -> Option<String> {
        self.lookup(home, SECRET_TOOL_LOOKUP_TIMEOUT)
    }

    fn present(&self, home: &Path) -> bool {
        self.lookup(home, SECRET_TOOL_FORGET_TIMEOUT).is_some()
    }

    fn forget(&self, home: &Path) -> Result<bool> {
        if self.lookup(home, SECRET_TOOL_FORGET_TIMEOUT).is_none() {
            return Ok(false);
        }
        let acct = account(home);
        let out = run_with_timeout(
            "secret-tool",
            &["clear", "service", "varsto", "home", &acct],
            None,
            SECRET_TOOL_FORGET_TIMEOUT,
        )?;
        if out.status.success() {
            Ok(true)
        } else {
            Err(anyhow!(
                "secret-tool could not remove it: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

#[cfg(target_os = "linux")]
impl SecretService {
    fn lookup(&self, home: &Path, timeout: Duration) -> Option<String> {
        let acct = account(home);
        let out = run_with_timeout(
            "secret-tool",
            &["lookup", "service", "varsto", "home", &acct],
            None,
            timeout,
        )
        .ok()?;
        let p = String::from_utf8_lossy(&out.stdout)
            .trim_end_matches('\n')
            .to_string();
        (out.status.success() && !p.is_empty()).then_some(p)
    }
}

// ---------------------------------------------------------------------------
// Linux: systemd-creds

/// Credential name bound into the encrypted file: a file copied under
/// another name does not decrypt.
#[cfg(target_os = "linux")]
const CRED_NAME: &str = "--name=varsto-passphrase";
/// `--user` scoped credentials arrived in systemd 256.
#[cfg(target_os = "linux")]
const CREDS_MIN_VERSION: u32 = 256;

/// `systemd-creds` as program name (tests may name another).
#[cfg(target_os = "linux")]
pub struct SystemdCreds {
    program: String,
}

#[cfg(target_os = "linux")]
impl SystemdCreds {
    pub fn new() -> Self {
        Self::with_program("systemd-creds")
    }

    pub fn with_program(program: &str) -> Self {
        Self {
            program: program.into(),
        }
    }

    /// The tool is there, new enough, and the user manager runs.
    pub fn usable(&self) -> Result<()> {
        let out = run_with_timeout(&self.program, &["--version"], None, Duration::from_secs(10))
            .map_err(|_| anyhow!("{} is not installed", self.program))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let version = text
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u32>().ok())
            .ok_or_else(|| anyhow!("{} gave no version", self.program))?;
        if version < CREDS_MIN_VERSION {
            return Err(anyhow!(
                "systemd {version} is too old (user credentials need systemd {CREDS_MIN_VERSION})"
            ));
        }
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
        if !runtime.join("systemd").exists() {
            return Err(anyhow!(
                "the systemd user manager is not running for this user"
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Default for SystemdCreds {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl Backend for SystemdCreds {
    fn kind(&self) -> Store {
        Store::SystemdCreds
    }

    fn store(&self, home: &Path, pass: &str) -> Result<()> {
        self.usable()?;
        // Standard input and output carry the secret, never an argument.
        let out = run_with_timeout(
            &self.program,
            &["encrypt", "--user", CRED_NAME, "-", "-"],
            Some(pass.as_bytes()),
            Duration::from_secs(60),
        )?;
        if !out.status.success() || out.stdout.is_empty() {
            return Err(anyhow!(
                "{} encrypt failed: {}",
                self.program,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        varsto_core::util::private_dir(home)?;
        // write_atomic creates the file with mode 600.
        varsto_core::util::write_atomic(&cred_file(home), &out.stdout)?;
        Ok(())
    }

    fn load(&self, home: &Path) -> Option<String> {
        let blob = std::fs::read(cred_file(home)).ok()?;
        let out = run_with_timeout(
            &self.program,
            &["decrypt", "--user", CRED_NAME, "-", "-"],
            Some(&blob),
            Duration::from_secs(30),
        )
        .ok()?;
        if !out.status.success() {
            log::warn!(
                "the remembered passphrase ({}) cannot be decrypted here: {}",
                cred_file(home).display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return None;
        }
        String::from_utf8(out.stdout).ok().filter(|p| !p.is_empty())
    }

    fn present(&self, home: &Path) -> bool {
        cred_file(home).is_file()
    }

    fn forget(&self, home: &Path) -> Result<bool> {
        match std::fs::remove_file(cred_file(home)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Linux: kernel keyring

#[cfg(target_os = "linux")]
pub struct KernelKeyring;

#[cfg(target_os = "linux")]
mod keyctl {
    use anyhow::{anyhow, Result};
    use std::ffi::CString;

    const KEY_SPEC_USER_KEYRING: libc::c_long = -4;
    const KEY_SPEC_PROCESS_KEYRING: libc::c_long = -2;
    const KEYCTL_REVOKE: libc::c_long = 3;
    const KEYCTL_LINK: libc::c_long = 8;
    const KEYCTL_SETPERM: libc::c_long = 5;
    const KEYCTL_READ: libc::c_long = 11;
    const KEYCTL_SEARCH: libc::c_long = 10;
    const KEYCTL_UNLINK: libc::c_long = 9;
    /// Possessor and owner may do everything; nobody else anything.
    const PERM_OWNER_ALL: u32 = 0x3f00_0000 | 0x003f_0000;

    fn last() -> anyhow::Error {
        anyhow!("{}", std::io::Error::last_os_error())
    }

    /// A process that does not have the user keyring in its session keyring
    /// (an SSH login, a service) does not possess what is in it, and could
    /// then neither change the permissions of its own new key nor read it.
    /// Linking `@u` into the process keyring makes it possess them.
    fn possess_user_keyring() {
        // SAFETY: plain integer arguments; a failure only means no possession.
        unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_LINK,
                KEY_SPEC_USER_KEYRING,
                KEY_SPEC_PROCESS_KEYRING,
            );
        }
    }

    pub fn add(desc: &str, payload: &[u8]) -> Result<()> {
        possess_user_keyring();
        let d = CString::new(desc)?;
        // SAFETY: valid NUL-terminated strings and a payload pointer/length pair.
        let id = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                c"user".as_ptr(),
                d.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                KEY_SPEC_USER_KEYRING,
            )
        };
        if id < 0 {
            return Err(last());
        }
        // The service is another process of the same user and may not
        // possess the key: let the owner read it.
        // SAFETY: plain integer arguments.
        let r = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SETPERM, id, PERM_OWNER_ALL) };
        if r < 0 {
            let e = last();
            let _ = remove_id(id);
            return Err(e);
        }
        Ok(())
    }

    fn search(desc: &str) -> Option<libc::c_long> {
        possess_user_keyring();
        let d = CString::new(desc).ok()?;
        // SAFETY: valid NUL-terminated strings.
        let id = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_SEARCH,
                KEY_SPEC_USER_KEYRING,
                c"user".as_ptr(),
                d.as_ptr(),
                0 as libc::c_long,
            )
        };
        (id >= 0).then_some(id)
    }

    pub fn exists(desc: &str) -> bool {
        search(desc).is_some()
    }

    pub fn read(desc: &str) -> Option<Vec<u8>> {
        let id = search(desc)?;
        // SAFETY: a null buffer asks for the size.
        let size = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_READ,
                id,
                std::ptr::null_mut::<u8>(),
                0usize,
            )
        };
        if size < 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: the buffer is `size` bytes long.
        let n = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_READ,
                id,
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        if n < 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }

    fn remove_id(id: libc::c_long) -> Result<()> {
        // SAFETY: plain integer arguments.
        let r = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_REVOKE, id) };
        // SAFETY: plain integer arguments.
        let u =
            unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_UNLINK, id, KEY_SPEC_USER_KEYRING) };
        if r < 0 && u < 0 {
            return Err(last());
        }
        Ok(())
    }

    /// Remove the key; `false` when there was none.
    pub fn remove(desc: &str) -> Result<bool> {
        match search(desc) {
            Some(id) => remove_id(id).map(|_| true),
            None => Ok(false),
        }
    }
}

#[cfg(target_os = "linux")]
fn key_desc(home: &Path) -> String {
    format!("varsto:{}", account(home))
}

#[cfg(target_os = "linux")]
impl Backend for KernelKeyring {
    fn kind(&self) -> Store {
        Store::KernelKeyring
    }

    fn store(&self, home: &Path, pass: &str) -> Result<()> {
        // An existing key is replaced by add_key; remove first so that no
        // older permissions or value remain.
        let _ = keyctl::remove(&key_desc(home));
        keyctl::add(&key_desc(home), pass.as_bytes())
            .map_err(|e| anyhow!("the kernel refused the key: {e}"))
    }

    fn load(&self, home: &Path) -> Option<String> {
        String::from_utf8(keyctl::read(&key_desc(home))?)
            .ok()
            .filter(|p| !p.is_empty())
    }

    fn present(&self, home: &Path) -> bool {
        keyctl::exists(&key_desc(home))
    }

    fn forget(&self, home: &Path) -> Result<bool> {
        keyctl::remove(&key_desc(home))
    }
}

// ---------------------------------------------------------------------------
// macOS: login keychain

#[cfg(target_os = "macos")]
pub struct Keychain;

#[cfg(target_os = "macos")]
impl Backend for Keychain {
    fn kind(&self) -> Store {
        Store::Keychain
    }

    fn store(&self, home: &Path, pass: &str) -> Result<()> {
        use std::io::Write;
        // `security -i` reads its commands from standard input, so the
        // passphrase is in no process argument (`ps` shows arguments of every
        // process of the user). Inside a command, double quotes and
        // backslashes are escaped.
        if pass.contains(['\n', '\r']) {
            return Err(anyhow!(
                "the passphrase has a line break; it cannot be kept in the keychain"
            ));
        }
        let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        let mut child = std::process::Command::new("security")
            .arg("-i")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("security: no stdin"))?;
            writeln!(
                stdin,
                "add-generic-password -U -s varsto -a {} -w {}",
                quote(&account(home)),
                quote(pass)
            )?;
        }
        let out = child.wait_with_output()?;
        // The interactive mode answers on stdout/stderr with the command's
        // errors; its exit code is 0 after end of input unless the command failed.
        if !out.status.success() || String::from_utf8_lossy(&out.stderr).contains("security:") {
            let mut msg = format!("security: {}", String::from_utf8_lossy(&out.stderr).trim());
            if std::env::var_os("SSH_CONNECTION").is_some() {
                msg.push_str(". Over SSH the login keychain is often locked: run `security unlock-keychain` in this session and try again, or unlock the service with `varsto unlock`");
            }
            return Err(anyhow!(msg));
        }
        Ok(())
    }

    fn load(&self, home: &Path) -> Option<String> {
        let out = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                "varsto",
                "-a",
                &account(home),
                "-w",
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let p = String::from_utf8_lossy(&out.stdout)
            .trim_end_matches('\n')
            .to_string();
        (!p.is_empty()).then_some(p)
    }

    fn forget(&self, home: &Path) -> Result<bool> {
        if self.load(home).is_none() {
            return Ok(false);
        }
        let out = std::process::Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                "varsto",
                "-a",
                &account(home),
            ])
            .output()?;
        if out.status.success() {
            Ok(true)
        } else {
            Err(anyhow!(
                "security: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A backend that fails or keeps the passphrase in memory.
    struct Fake {
        kind: Store,
        fail: Option<&'static str>,
        data: Mutex<Option<String>>,
    }

    impl Fake {
        fn boxed(kind: Store, fail: Option<&'static str>) -> Box<dyn Backend> {
            Box::new(Fake {
                kind,
                fail,
                data: Mutex::new(None),
            })
        }
    }

    impl Backend for Fake {
        fn kind(&self) -> Store {
            self.kind
        }
        fn store(&self, _: &Path, pass: &str) -> Result<()> {
            if let Some(why) = self.fail {
                return Err(anyhow!(why));
            }
            *self.data.lock().unwrap() = Some(pass.into());
            Ok(())
        }
        fn load(&self, _: &Path) -> Option<String> {
            self.data.lock().unwrap().clone()
        }
        fn forget(&self, _: &Path) -> Result<bool> {
            Ok(self.data.lock().unwrap().take().is_some())
        }
    }

    fn chain(keyring_fails: bool, creds_fails: bool, kernel_fails: bool) -> Vec<Box<dyn Backend>> {
        vec![
            Fake::boxed(
                Store::Keyring,
                keyring_fails.then_some("no desktop session"),
            ),
            Fake::boxed(Store::SystemdCreds, creds_fails.then_some("not installed")),
            Fake::boxed(
                Store::KernelKeyring,
                kernel_fails.then_some("kernel said no"),
            ),
        ]
    }

    #[test]
    fn keyring_first_when_it_works() {
        let c = chain(false, false, false);
        let r = remember_with(&c, Path::new("/h"), "pw").unwrap();
        assert_eq!(r.store, Store::Keyring);
        assert!(r.skipped.is_empty());
        assert_eq!(where_with(&c, Path::new("/h")), Some(Store::Keyring));
    }

    #[test]
    fn failing_keyring_falls_back_to_systemd_creds_then_kernel() {
        let c = chain(true, false, false);
        let r = remember_with(&c, Path::new("/h"), "pw").unwrap();
        assert_eq!(r.store, Store::SystemdCreds);
        assert_eq!(r.skipped, vec!["desktop keyring: no desktop session"]);
        assert_eq!(load_with(&c, Path::new("/h")).as_deref(), Some("pw"));

        let c = chain(true, true, false);
        let r = remember_with(&c, Path::new("/h"), "pw").unwrap();
        assert_eq!(r.store, Store::KernelKeyring);
        assert_eq!(r.skipped.len(), 2);
        assert_eq!(where_with(&c, Path::new("/h")), Some(Store::KernelKeyring));
    }

    #[test]
    fn all_failing_names_everything_tried_and_the_alternatives() {
        let c = chain(true, true, true);
        let e = remember_with(&c, Path::new("/h"), "pw")
            .unwrap_err()
            .to_string();
        for needle in [
            "desktop keyring: no desktop session",
            "systemd-creds: not installed",
            "kernel keyring: kernel said no",
            "VARSTO_PASSPHRASE",
            "varsto unlock",
        ] {
            assert!(e.contains(needle), "{e}");
        }
        assert!(!e.contains("pw\n"));
        assert_eq!(where_with(&c, Path::new("/h")), None);
    }

    #[test]
    fn empty_chain_is_unsupported_platform() {
        let e = remember_with(&[], Path::new("/h"), "pw").unwrap_err();
        assert_eq!(e.to_string(), "no system keyring support on this platform");
    }

    #[test]
    fn a_new_store_clears_older_copies() {
        let c = chain(false, false, false);
        // An old value sits in the kernel keyring, a new one goes to the keyring.
        c[2].store(Path::new("/h"), "old").unwrap();
        remember_with(&c, Path::new("/h"), "new").unwrap();
        assert!(c[2].load(Path::new("/h")).is_none());
        assert_eq!(load_with(&c, Path::new("/h")).as_deref(), Some("new"));
    }

    #[test]
    fn forget_removes_whichever_store_was_used() {
        for fails in [(false, false), (true, false), (true, true)] {
            let c = chain(fails.0, fails.1, false);
            let used = remember_with(&c, Path::new("/h"), "pw").unwrap().store;
            let removed = forget_with(&c, Path::new("/h")).unwrap();
            assert_eq!(removed, vec![used]);
            assert_eq!(where_with(&c, Path::new("/h")), None);
            assert_eq!(load_with(&c, Path::new("/h")), None);
            assert!(forget_with(&c, Path::new("/h")).unwrap().is_empty());
        }
    }

    #[test]
    fn status_text_says_where() {
        assert!(status_text(Some(Store::Keyring)).contains("desktop keyring"));
        assert!(status_text(Some(Store::SystemdCreds)).contains("systemd-creds"));
        let k = status_text(Some(Store::KernelKeyring));
        assert!(
            k.contains("kernel keyring") && k.contains("restarts"),
            "{k}"
        );
        assert!(status_text(None).contains("not remembered"));
        assert_eq!(Store::KernelKeyring.id(), "kernel-keyring");
    }

    #[test]
    fn kept_text_is_honest_about_the_kernel_keyring() {
        let t = Store::KernelKeyring.kept_text(Path::new("/h"));
        assert!(t.contains("only until this computer restarts"), "{t}");
        assert!(t.contains("varsto unlock"), "{t}");
        let t = Store::SystemdCreds.kept_text(Path::new("/h"));
        assert!(t.contains("/h/passphrase.cred"), "{t}");
    }

    #[cfg(target_os = "linux")]
    fn temp_home(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("varsto-remember-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_creds_missing_program_is_reported() {
        let b = SystemdCreds::with_program("varsto-no-such-tool");
        let e = b
            .store(&temp_home("nocreds"), "pw")
            .unwrap_err()
            .to_string();
        assert!(e.contains("is not installed"), "{e}");
    }

    /// End to end with the real `systemd-creds`; skips where it cannot
    /// encrypt user credentials (not installed, older than 256, no user
    /// manager, no host key access).
    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_creds_round_trip_end_to_end() {
        let b = SystemdCreds::new();
        let home = temp_home("creds");
        let pass = "correct horse battery staple \u{e5}\u{e4}\u{f6}";
        if let Err(e) = b.store(&home, pass) {
            eprintln!("skipped: systemd-creds unusable here: {e:#}");
            let _ = std::fs::remove_dir_all(&home);
            return;
        }
        let file = cred_file(&home);
        let raw = std::fs::read(&file).unwrap();
        assert!(!raw.is_empty());
        assert!(
            !String::from_utf8_lossy(&raw).contains("correct horse"),
            "the passphrase must not be in the file"
        );
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode {mode:o}");
        }
        assert!(b.present(&home));
        assert_eq!(b.load(&home).as_deref(), Some(pass));
        // A second remember replaces the first.
        b.store(&home, "second").unwrap();
        assert_eq!(b.load(&home).as_deref(), Some("second"));
        assert!(b.forget(&home).unwrap());
        assert!(!file.exists());
        assert!(!b.present(&home));
        assert_eq!(b.load(&home), None);
        assert!(!b.forget(&home).unwrap());
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The real kernel keyring; skips where the syscalls are blocked.
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_keyring_round_trip() {
        let b = KernelKeyring;
        let home = temp_home("kernel");
        if let Err(e) = b.store(&home, "kernel secret") {
            eprintln!("skipped: kernel keyring unusable here: {e:#}");
            let _ = std::fs::remove_dir_all(&home);
            return;
        }
        assert!(b.present(&home));
        assert_eq!(b.load(&home).as_deref(), Some("kernel secret"));
        b.store(&home, "replaced").unwrap();
        assert_eq!(b.load(&home).as_deref(), Some("replaced"));
        assert!(b.forget(&home).unwrap());
        assert!(!b.present(&home));
        assert_eq!(b.load(&home), None);
        assert!(!b.forget(&home).unwrap());
        let _ = std::fs::remove_dir_all(&home);
    }
}
