// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The local debug log of every Varsto program (see
//! `docs/architecture/logging.md`).
//!
//! Code logs with the `log` crate's macros (`log::debug!`, `log::trace!`, …),
//! with key-value fields where they help:
//!
//! ```ignore
//! log::debug!(op = "put", key = key, bytes = n, ms = t; "storage request");
//! ```
//!
//! Each program calls [`init`] once with its component name; the lines go to
//! `<home>/logs/varsto-<component>.log`:
//!
//! ```text
//! 2026-10-13T13:30:38.123Z DEBUG service[4242/sync] varsto_core::engine: push done files=3 ms=812
//! ```
//!
//! Level: `--log-level`, else `VARSTO_LOG`, else `log_level` in
//! `config.json`, else `debug`. A level may be a filter:
//! `debug,varsto_core::p2p=trace`. Other crates log at `warn` unless named.
//!
//! Secrets never reach the file: secret types print `[redacted]`, fields
//! with secret names are written as `[redacted]`, and every finished line
//! passes through [`redact::scrub`].

pub mod files;
pub mod redact;

pub use files::Rotation;
pub use redact::{register_key, register_secret, scrub, REDACTED};

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

/// The level when nothing else says (a user decision: everything is logged).
pub const DEFAULT_LEVEL: &str = "debug";
/// Environment variable with a level or filter.
pub const ENV_VAR: &str = "VARSTO_LOG";

/// A value whose `Debug` and `Display` print `[redacted]`.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Redacted;

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}
impl std::fmt::Display for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

/// `impl Debug` for a type with secret fields: the listed public fields are
/// shown, the secret ones print `[redacted]`.
///
/// ```ignore
/// redacted_debug!(ShareToken { vault_id, folder_id, name ; key_hex, epoch_keys });
/// ```
#[macro_export]
macro_rules! redacted_debug {
    ($ty:ident { $($shown:ident),* ; $($hidden:ident),* }) => {
        impl ::std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_struct(stringify!($ty))
                    $(.field(stringify!($shown), &self.$shown))*
                    $(.field(stringify!($hidden), &$crate::logging::Redacted))*
                    .finish_non_exhaustive()
            }
        }
    };
}

/// `impl Debug` that prints only the type name and `[redacted]`, for key
/// types and other values with nothing loggable inside.
#[macro_export]
macro_rules! redacted_opaque {
    ($($ty:ty),* $(,)?) => {
        $(impl ::std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}([redacted])", stringify!($ty))
            }
        })*
    };
}

/// Where the level came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Flag,
    Env,
    Config,
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Flag => "flag",
            Source::Env => "env",
            Source::Config => "config",
            Source::Default => "default",
        }
    }
}

/// A parsed level filter: a default for Varsto's own modules, a level for
/// other crates, and per-module directives (longest prefix wins).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    own: LevelFilter,
    foreign: LevelFilter,
    directives: Vec<(String, LevelFilter)>,
}

fn parse_level(s: &str) -> Option<LevelFilter> {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" | "none" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" | "warning" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" | "all" => Some(LevelFilter::Trace),
        _ => None,
    }
}

impl Filter {
    /// `debug`, `trace`, `info,varsto_core::p2p=trace,rustls=debug`, …
    pub fn parse(spec: &str) -> Result<Filter, String> {
        let mut f = Filter {
            own: LevelFilter::Debug,
            foreign: LevelFilter::Warn,
            directives: Vec::new(),
        };
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                Some((module, level)) => {
                    let l = parse_level(level)
                        .ok_or_else(|| format!("unknown log level `{level}` (use error, warn, info, debug or trace)"))?;
                    f.directives.push((module.trim().to_string(), l));
                }
                None => {
                    f.own = parse_level(part)
                        .ok_or_else(|| format!("unknown log level `{part}` (use error, warn, info, debug or trace)"))?;
                    // Other crates follow only when asked for less than warn.
                    f.foreign = f.own.min(LevelFilter::Warn);
                }
            }
        }
        f.directives.sort_by_key(|(m, _)| std::cmp::Reverse(m.len()));
        Ok(f)
    }

    /// The level that applies to a log target (a module path).
    pub fn level_for(&self, target: &str) -> LevelFilter {
        for (m, l) in &self.directives {
            if target == m || (target.starts_with(m.as_str()) && target[m.len()..].starts_with("::")) {
                return *l;
            }
        }
        if target.starts_with("varsto") || target == "app" || target == "panic" {
            self.own
        } else {
            self.foreign
        }
    }

    /// The most detailed level any target gets.
    pub fn max(&self) -> LevelFilter {
        self.directives
            .iter()
            .map(|(_, l)| *l)
            .fold(self.own.max(self.foreign), |a, b| a.max(b))
    }
}

/// The `log_level` of `home/config.json`, read without loading the rest.
pub fn config_level(home: &Path) -> Option<String> {
    let text = std::fs::read_to_string(home.join("config.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("log_level")?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The level spec in effect: `explicit` (a command-line flag), else
/// `VARSTO_LOG`, else the configuration, else [`DEFAULT_LEVEL`].
pub fn resolve_level(explicit: Option<&str>, home: Option<&Path>) -> (String, Source) {
    if let Some(e) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return (e.to_string(), Source::Flag);
    }
    if let Ok(e) = std::env::var(ENV_VAR) {
        if !e.trim().is_empty() {
            return (e.trim().to_string(), Source::Env);
        }
    }
    if let Some(c) = home.and_then(config_level) {
        return (c, Source::Config);
    }
    (DEFAULT_LEVEL.to_string(), Source::Default)
}

/// The log directory of a Varsto home.
pub fn dir(home: &Path) -> PathBuf {
    home.join("logs")
}

/// How a program's log is set up.
#[derive(Clone, Debug)]
pub struct Options {
    pub home: PathBuf,
    /// `service`, `cli`, `tray`, `desktop-app`, `mcp`, `ffi-ios`, …
    pub component: String,
    /// A level or filter given on the command line.
    pub level: Option<String>,
    /// Lines at or above this level are also written to stderr (the
    /// service keeps its `service.log` of notable events this way).
    pub stderr: Option<LevelFilter>,
    pub rotation: Rotation,
}

impl Options {
    pub fn new(home: &Path, component: &str) -> Options {
        Options {
            home: home.to_path_buf(),
            component: component.to_string(),
            level: None,
            stderr: None,
            rotation: Rotation::DESKTOP,
        }
    }
}

struct Config {
    component: String,
    filter: Filter,
    spec: String,
    source: Source,
    stderr: Option<LevelFilter>,
    dir: PathBuf,
}

static CONFIG: RwLock<Option<Arc<Config>>> = RwLock::new(None);
static SINK: Mutex<Option<files::Sink>> = Mutex::new(None);

struct Logger;
static LOGGER: Logger = Logger;

fn config() -> Option<Arc<Config>> {
    CONFIG.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Start (or restart with new settings) this process's log. Secrets from
/// the environment (`VARSTO_PASSPHRASE`, `VARSTO_S3_SECRET`, …) are
/// registered for scrubbing here. Returns an error only for a bad level.
pub fn init(opts: Options) -> Result<(), String> {
    let (spec, source) = resolve_level(opts.level.as_deref(), Some(&opts.home));
    let filter = match Filter::parse(&spec) {
        Ok(f) => f,
        Err(e) if source == Source::Flag => return Err(e),
        // A bad VARSTO_LOG or config value must not stop the program.
        Err(_) => Filter::parse(DEFAULT_LEVEL).expect("default level parses"),
    };
    for var in [
        "VARSTO_PASSPHRASE",
        "VARSTO_S3_SECRET",
        "VARSTO_NEW_PASSPHRASE",
        "RESTIC_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
        "RCLONE_CONFIG_PASS",
    ] {
        if let Ok(v) = std::env::var(var) {
            register_secret(&v);
        }
    }
    let dir = dir(&opts.home);
    let sink = files::Sink::new(&dir, &opts.component, opts.rotation);
    {
        let mut s = SINK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = s.as_mut() {
            old.flush();
        }
        *s = Some(sink);
    }
    let max = filter.max();
    *CONFIG.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(Config {
        component: opts.component,
        filter,
        spec,
        source,
        stderr: opts.stderr,
        dir,
    }));
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = log::set_logger(&LOGGER);
        install_panic_hook();
        let _ = std::thread::Builder::new()
            .name("log-flush".into())
            .spawn(|| loop {
                std::thread::sleep(Duration::from_secs(1));
                flush();
            });
    });
    log::set_max_level(max);
    Ok(())
}

/// Whether [`init`] has run in this process.
pub fn active() -> bool {
    config().is_some()
}

/// Change the level while running (the interface's setting).
pub fn set_level(spec: &str, source: Source) -> Result<(), String> {
    let filter = Filter::parse(spec)?;
    let mut c = CONFIG.write().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = c.as_ref() {
        let max = filter.max();
        *c = Some(Arc::new(Config {
            component: old.component.clone(),
            filter,
            spec: spec.to_string(),
            source,
            stderr: old.stderr,
            dir: old.dir.clone(),
        }));
        log::set_max_level(max);
    }
    Ok(())
}

/// The level spec in effect and where it came from.
pub fn level() -> Option<(String, Source)> {
    config().map(|c| (c.spec.clone(), c.source))
}

/// The directory this process logs to.
pub fn current_dir() -> Option<PathBuf> {
    config().map(|c| c.dir.clone())
}

/// Write out buffered lines now (at exit; the log also flushes every second
/// and at once on warnings and errors).
pub fn flush() {
    if let Ok(mut s) = SINK.try_lock() {
        if let Some(s) = s.as_mut() {
            s.flush();
        }
    }
}

fn thread_label() -> String {
    thread_local! {
        static LABEL: String = {
            let t = std::thread::current();
            match t.name() {
                Some(n) => n.replace(char::is_whitespace, "_"),
                None => {
                    let id = format!("{:?}", t.id());
                    let digits: String = id.chars().filter(|c| c.is_ascii_digit()).collect();
                    format!("t{digits}")
                }
            }
        };
    }
    LABEL.with(|l| l.clone())
}

/// `2026-10-13T13:30:38.123Z`
pub fn rfc3339_millis(t: SystemTime) -> String {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let date = crate::util::format_date(secs);
    let sod = secs.rem_euclid(86_400);
    format!(
        "{date}T{:02}:{:02}:{:02}.{:03}Z",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60,
        d.subsec_millis()
    )
}

fn push_value(out: &mut String, v: &str) {
    let plain = !v.is_empty()
        && !v
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '=' || c == '\\' || c.is_control());
    if plain {
        out.push_str(v);
        return;
    }
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Fields<'a>(&'a mut String);

impl<'kvs> log::kv::VisitSource<'kvs> for Fields<'_> {
    fn visit_pair(&mut self, key: log::kv::Key<'kvs>, value: log::kv::Value<'kvs>) -> Result<(), log::kv::Error> {
        self.0.push(' ');
        self.0.push_str(key.as_str());
        self.0.push('=');
        if redact::secret_field(key.as_str()) {
            self.0.push_str(REDACTED);
        } else {
            push_value(self.0, &value.to_string());
        }
        Ok(())
    }
}

/// One finished line (before scrubbing), with its newline.
fn format_line(component: &str, level: Level, target: &str, message: &std::fmt::Arguments<'_>, record: Option<&Record<'_>>) -> String {
    let mut s = String::with_capacity(160);
    s.push_str(&rfc3339_millis(SystemTime::now()));
    let _ = write!(s, " {:<5} {}[{}/{}] {}: ", level, component, std::process::id(), thread_label(), target);
    let start = s.len();
    let _ = write!(s, "{message}");
    if s[start..].contains(['\n', '\r']) {
        // Continuation lines are indented, so every record starts at column 0.
        let msg = s[start..].replace("\r\n", "\n").replace('\r', "\n").replace('\n', "\n    ");
        s.truncate(start);
        s.push_str(msg.trim_end());
    }
    if let Some(r) = record {
        let _ = r.key_values().visit(&mut Fields(&mut s));
    }
    s.push('\n');
    s
}

/// Scrub a finished line after its header (time, level, component,
/// thread and module), which holds nothing secret but may look like an
/// assignment to the scrubber (`varsto_core::vault::secrets: …`).
fn scrub_body(line: &str) -> String {
    // The header ends at the first ": " after the `]` of the thread.
    let split = line
        .find("] ")
        .and_then(|i| line[i..].find(": ").map(|j| i + j + 2))
        .unwrap_or(0);
    let (head, body) = line.split_at(split);
    let mut out = String::with_capacity(line.len());
    out.push_str(head);
    out.push_str(&scrub(body));
    out
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        match config() {
            Some(c) => metadata.level() <= c.filter.level_for(metadata.target()),
            None => false,
        }
    }

    fn log(&self, record: &Record<'_>) {
        let Some(c) = config() else { return };
        if record.level() > c.filter.level_for(record.target()) {
            return;
        }
        let line = format_line(&c.component, record.level(), record.target(), record.args(), Some(record));
        let line = scrub_body(&line);
        if let Some(se) = c.stderr {
            if record.level() <= se {
                let _ = std::io::stderr().write_all(line.as_bytes());
            }
        }
        let mut s = SINK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = s.as_mut() {
            s.push(line.as_bytes(), record.level() <= Level::Warn);
        }
    }

    fn flush(&self) {
        flush();
    }
}

/// Log a panic with its backtrace and flush, then run the previous hook.
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(c) = config() {
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "(non-text panic)".to_string());
            let at = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_default();
            let bt = std::backtrace::Backtrace::force_capture();
            let line = format_line(
                &c.component,
                Level::Error,
                "panic",
                &format_args!("thread {} panicked at {at}: {payload}\nbacktrace:\n{bt}", thread_label()),
                None,
            );
            let line = scrub_body(&line);
            // The panic may have happened inside the logger itself.
            if let Ok(mut s) = SINK.try_lock() {
                if let Some(s) = s.as_mut() {
                    s.push(line.as_bytes(), true);
                }
            }
        }
        prev(info);
    }));
}

/// Bytes and files in a home's log directory.
pub fn usage(home: &Path) -> (u64, usize) {
    files::usage(&dir(home))
}

/// A diagnostics bundle: the home's log files (decompressed and scrubbed
/// again), `service.log`, and the given extra files (scrubbed too), as a
/// zstd-compressed tar written to `out`.
pub fn bundle<W: std::io::Write>(home: &Path, extras: &[(String, Vec<u8>)], out: W) -> std::io::Result<W> {
    flush();
    let enc = zstd::Encoder::new(out, 3)?;
    let mut tar = files::TarWriter::new(enc);
    let now = crate::util::now_utc().max(0) as u64;
    let add = |tar: &mut files::TarWriter<_>, name: String, text: &str, mtime: u64| -> std::io::Result<()> {
        let mut clean = String::with_capacity(text.len());
        for l in text.split_inclusive('\n') {
            clean.push_str(&scrub(l));
        }
        tar.add(&name, clean.as_bytes(), mtime)
    };
    for f in files::list(&dir(home)) {
        let Ok(text) = files::read_text(&f.path) else { continue };
        let name = f.path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let name = name.trim_end_matches(".zst").to_string();
        let mtime = f
            .modified
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(now);
        add(&mut tar, format!("varsto-logs/{name}"), &text, mtime)?;
    }
    for extra in ["service.log", "restic-run.log"] {
        if let Ok(raw) = std::fs::read(home.join(extra)) {
            // Only the end of a large file.
            let tail = &raw[raw.len().saturating_sub(4 << 20)..];
            add(&mut tar, format!("varsto-logs/{extra}"), &String::from_utf8_lossy(tail), now)?;
        }
    }
    for (name, data) in extras {
        add(&mut tar, format!("varsto-logs/{name}"), &String::from_utf8_lossy(data), now)?;
    }
    tar.finish()?.finish()
}

/// Time an operation: `let t = logging::Timer::start(); …; t.ms()`.
#[derive(Clone, Copy)]
pub struct Timer(std::time::Instant);

impl Timer {
    pub fn start() -> Timer {
        Timer(std::time::Instant::now())
    }
    /// Milliseconds since start.
    pub fn ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_parsing() {
        let f = Filter::parse("info,varsto_core::p2p=trace,rustls=debug").unwrap();
        assert_eq!(f.level_for("varsto_core::engine"), LevelFilter::Info);
        assert_eq!(f.level_for("varsto_core::p2p"), LevelFilter::Trace);
        assert_eq!(f.level_for("varsto_core::p2p::quic"), LevelFilter::Trace);
        assert_eq!(f.level_for("varsto_core::p2px"), LevelFilter::Info);
        assert_eq!(f.level_for("rustls::client"), LevelFilter::Debug);
        assert_eq!(f.level_for("ureq"), LevelFilter::Warn);
        assert_eq!(f.max(), LevelFilter::Trace);
        let e = Filter::parse("error").unwrap();
        assert_eq!(e.level_for("quinn"), LevelFilter::Error);
        assert!(Filter::parse("loud").is_err());
        assert_eq!(Filter::parse("").unwrap().level_for("varsto_cli"), LevelFilter::Debug);
    }

    #[test]
    fn timestamps() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_millis(1_760_362_238_123);
        assert_eq!(rfc3339_millis(t), "2025-10-13T13:30:38.123Z");
    }

    #[test]
    fn line_format() {
        let l = format_line("cli", Level::Debug, "varsto_core::x", &format_args!("two\nlines"), None);
        assert!(l.contains(" DEBUG cli["), "{l}");
        assert!(l.ends_with("varsto_core::x: two\n    lines\n"), "{l}");
        let mut s = String::new();
        push_value(&mut s, "a b\"c");
        assert_eq!(s, "\"a b\\\"c\"");
    }
}
