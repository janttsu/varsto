// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Push notifications to a phone: ntfy, Pushover and Telegram.
//!
//! The service already shows desktop notifications. This module sends the
//! same alerts (and a few quiet ones) to channels the user set up, so a
//! failing backup or a full storage is noticed away from the computer.
//!
//! The channels live in `<home>/notify.json` (mode 0600). The file is
//! device-local and never synced: every device sends its own messages and
//! starts them with its own name. Messages that could not be sent (no
//! network) wait in `<home>/notify-outbox.json` and go out later, also after
//! a restart.
//!
//! Secrets (tokens, keys, passwords) are never logged, never put into error
//! text and never returned by the API: [`Channel::view`] masks them.

use crate::util;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime};

/// The channel list, in the device directory.
pub const CONFIG_FILE: &str = "notify.json";
/// Messages waiting to be sent, in the device directory.
pub const OUTBOX_FILE: &str = "notify-outbox.json";
/// The same message is sent once in this time.
const DEDUPE_SECS: i64 = 6 * 3600;
/// At most this many messages to one channel per hour.
const RATE_MAX: usize = 20;
const RATE_WINDOW_SECS: i64 = 3600;
/// Waiting messages: how many, and how old.
const OUTBOX_MAX: usize = 100;
const OUTBOX_MAX_AGE_SECS: i64 = 24 * 3600;
/// Retry after a failed send: 30 s, doubled each time, up to 30 min.
const RETRY_FIRST_SECS: i64 = 30;
const RETRY_MAX_SECS: i64 = 30 * 60;
/// How long the worker sleeps at most (it also checks the summary then).
const WAKE_SECS: i64 = 120;
const SEND_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_NTFY: &str = "https://ntfy.sh";

// ---------------------------------------------------------------------------
// Categories.

/// How urgent a category is: an alert needs a person, info is good to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Alert,
    Info,
}

/// What a message is about. A channel gets only the categories it asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Storage,
    Space,
    Durability,
    Integrity,
    BackupsFailed,
    Requests,
    Disks,
    Folders,
    BackupsDone,
    FilesNew,
    Updates,
    DailySummary,
    Other,
}

impl Category {
    /// Every category, alerts first, in the order a person reads them.
    pub const ALL: [Category; 13] = [
        Category::Storage,
        Category::Space,
        Category::Durability,
        Category::Integrity,
        Category::BackupsFailed,
        Category::Requests,
        Category::Disks,
        Category::Folders,
        Category::BackupsDone,
        Category::FilesNew,
        Category::Updates,
        Category::DailySummary,
        Category::Other,
    ];

    /// The name used in `notify.json`, the API and the command line.
    pub fn id(self) -> &'static str {
        match self {
            Category::Storage => "storage",
            Category::Space => "space",
            Category::Durability => "durability",
            Category::Integrity => "integrity",
            Category::BackupsFailed => "backups_failed",
            Category::Requests => "requests",
            Category::Disks => "disks",
            Category::Folders => "folders",
            Category::BackupsDone => "backups_done",
            Category::FilesNew => "files_new",
            Category::Updates => "updates",
            Category::DailySummary => "daily_summary",
            Category::Other => "other",
        }
    }

    pub fn from_id(id: &str) -> Option<Category> {
        Category::ALL.into_iter().find(|c| c.id() == id.trim())
    }

    /// A short name for lists, and the title of a message that hides details.
    pub fn title(self) -> &'static str {
        match self {
            Category::Storage => "Storage problems",
            Category::Space => "Low disk space",
            Category::Durability => "Fewer copies than wanted",
            Category::Integrity => "Damaged or missing data",
            Category::BackupsFailed => "Failed or overdue backups",
            Category::Requests => "Requests waiting for you",
            Category::Disks => "Disks",
            Category::Folders => "Folders",
            Category::BackupsDone => "Finished backups",
            Category::FilesNew => "New files from other devices",
            Category::Updates => "New Varsto version",
            Category::DailySummary => "Daily summary",
            Category::Other => "Other messages",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Category::Storage => {
                "A storage cannot be reached or fails, and when it works again."
            }
            Category::Space => {
                "Disk space is low on this device, or a storage quota is full."
            }
            Category::Durability => {
                "A folder has fewer copies than its policy asks, and the result of repairs."
            }
            Category::Integrity => {
                "Verification or the bit-rot check found damaged or missing blocks, or the ledger has problems."
            }
            Category::BackupsFailed => "A backup or a restic backup failed or is overdue.",
            Category::Requests => {
                "A device asks to pair, or asks for access to a folder. It waits for your approval."
            }
            Category::Disks => {
                "A disk check is due, a disk was attached, removed or mounted, or which disk to dock next."
            }
            Category::Folders => "A folder was paused, or a move finished or waits.",
            Category::BackupsDone => "A backup finished.",
            Category::FilesNew => {
                "New files arrived from other devices (at most one message per folder every 15 minutes)."
            }
            Category::Updates => "A new version of Varsto is available.",
            Category::DailySummary => {
                "Once a day: Varsto is running, and how many alerts there were. Shows that the device is alive."
            }
            Category::Other => "Anything else Varsto reports.",
        }
    }

    pub fn level(self) -> Level {
        match self {
            Category::Storage
            | Category::Space
            | Category::Durability
            | Category::Integrity
            | Category::BackupsFailed
            | Category::Requests => Level::Alert,
            _ => Level::Info,
        }
    }

    /// Whether a new channel gets this category until the user chooses.
    pub fn default_on(self) -> bool {
        !matches!(
            self,
            Category::BackupsDone | Category::FilesNew | Category::DailySummary
        )
    }

    pub fn defaults() -> BTreeSet<Category> {
        Category::ALL
            .into_iter()
            .filter(|c| c.default_on())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Channels and the file.

/// The service behind a channel, with what it needs to send.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "service", rename_all = "snake_case")]
pub enum ChannelKind {
    Ntfy {
        #[serde(default = "default_server")]
        server: String,
        topic: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    Pushover {
        user_key: String,
        app_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device: Option<String>,
    },
    Telegram {
        bot_token: String,
        chat_id: String,
    },
}

fn default_server() -> String {
    DEFAULT_NTFY.to_string()
}

// A derived Debug would print the secrets.
impl fmt::Debug for ChannelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelKind::{}(..)", self.service())
    }
}

impl ChannelKind {
    pub fn service(&self) -> &'static str {
        match self {
            ChannelKind::Ntfy { .. } => "ntfy",
            ChannelKind::Pushover { .. } => "pushover",
            ChannelKind::Telegram { .. } => "telegram",
        }
    }

    /// What the service is called in the interface.
    pub fn service_title(&self) -> &'static str {
        match self {
            ChannelKind::Ntfy { .. } => "ntfy",
            ChannelKind::Pushover { .. } => "Pushover",
            ChannelKind::Telegram { .. } => "Telegram",
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub kind: ChannelKind,
    /// The categories this channel receives.
    #[serde(default)]
    pub events: BTreeSet<Category>,
    /// Whether messages name folders, storages and devices. Off: only the
    /// category and "open Varsto", so no names reach the service.
    #[serde(default = "default_true")]
    pub details: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotifyConfig {
    #[serde(default)]
    pub channels: Vec<Channel>,
    /// Local hour after which the daily summary goes out.
    #[serde(default = "default_hour")]
    pub summary_hour: u8,
}

fn default_hour() -> u8 {
    9
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            channels: Vec::new(),
            summary_hour: default_hour(),
        }
    }
}

impl NotifyConfig {
    pub fn path(home: &Path) -> PathBuf {
        home.join(CONFIG_FILE)
    }

    pub fn load(home: &Path) -> Result<NotifyConfig> {
        util::read_json_or_default(&Self::path(home))
    }

    /// Written atomically with mode 0600 (it holds tokens).
    pub fn save(&self, home: &Path) -> Result<()> {
        util::write_json(&Self::path(home), self)
    }

    /// A channel by id or by name (any case).
    pub fn find(&self, key: &str) -> Option<usize> {
        let key = key.trim();
        self.channels.iter().position(|c| c.id == key).or_else(|| {
            self.channels
                .iter()
                .position(|c| c.name.eq_ignore_ascii_case(key))
        })
    }

    /// Add a channel (no id in the input) or change one (its id). Secrets
    /// left empty keep the stored ones. Returns the channel as stored.
    pub fn upsert(&mut self, input: &ChannelInput) -> Result<Channel> {
        let idx = match input.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(id) => Some(
                self.channels
                    .iter()
                    .position(|c| c.id == id)
                    .ok_or_else(|| anyhow!("no channel with id {id}"))?,
            ),
            None => None,
        };
        let mut ch = input.resolve(idx.map(|i| &self.channels[i]))?;
        // The name picks a channel on the command line, so it is unique.
        let taken = |name: &str| {
            self.channels
                .iter()
                .enumerate()
                .any(|(i, c)| Some(i) != idx && c.name.eq_ignore_ascii_case(name))
        };
        if taken(&ch.name) {
            let given = input
                .name
                .as_deref()
                .map(str::trim)
                .is_some_and(|n| !n.is_empty());
            if given {
                bail!("a channel named {:?} exists already", ch.name);
            }
            let base = ch.name.clone();
            let mut n = 2;
            while taken(&format!("{base} {n}")) {
                n += 1;
            }
            ch.name = format!("{base} {n}");
        }
        match idx {
            Some(i) => self.channels[i] = ch.clone(),
            None => self.channels.push(ch.clone()),
        }
        Ok(ch)
    }

    /// Remove a channel by id or name; the removed channel.
    pub fn remove(&mut self, key: &str) -> Result<Channel> {
        let i = self
            .find(key)
            .ok_or_else(|| anyhow!("no channel {key:?}; see `varsto notify list`"))?;
        Ok(self.channels.remove(i))
    }

    pub fn set_summary_hour(&mut self, hour: u8) -> Result<()> {
        if hour > 23 {
            bail!("the hour is 0 to 23");
        }
        self.summary_hour = hour;
        Ok(())
    }

    /// Whether any enabled channel wants the daily summary.
    pub fn wants_summary(&self) -> bool {
        self.channels
            .iter()
            .any(|c| c.enabled && c.events.contains(&Category::DailySummary))
    }
}

/// What the interface or the command line sends to add or change a channel.
/// Every field but `service` is optional; an empty secret keeps the stored
/// one.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct ChannelInput {
    pub id: Option<String>,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub service: String,
    pub server: Option<String>,
    pub topic: Option<String>,
    pub token: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    /// Remove the ntfy token, user and password.
    pub clear_auth: Option<bool>,
    pub user_key: Option<String>,
    pub app_token: Option<String>,
    pub device: Option<String>,
    pub bot_token: Option<String>,
    pub chat_id: Option<String>,
    pub events: Option<Vec<Category>>,
    pub details: Option<bool>,
}

/// A new value when one is given (non-empty), else the old one.
fn pick(new: &Option<String>, old: Option<String>, trim: bool) -> Option<String> {
    match new {
        Some(s) => {
            let t = if trim { s.trim() } else { s.as_str() };
            if t.is_empty() {
                old
            } else {
                Some(t.to_string())
            }
        }
        None => old,
    }
}

/// Like [`pick`] but an empty value clears it.
fn pick_clearable(new: &Option<String>, old: Option<String>) -> Option<String> {
    match new {
        Some(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        None => old,
    }
}

impl ChannelInput {
    /// The channel this input makes, on top of `old` when it changes one.
    pub fn resolve(&self, old: Option<&Channel>) -> Result<Channel> {
        let given = self.service.trim().to_lowercase();
        let service = if given.is_empty() {
            old.map(|c| c.kind.service().to_string())
                .ok_or_else(|| anyhow!("choose a service: ntfy, pushover or telegram"))?
        } else {
            given
        };
        if let Some(o) = old {
            if o.kind.service() != service {
                bail!("the service of a channel cannot change; add a new channel instead");
            }
        }
        let old_kind = old.map(|c| &c.kind);
        let kind = match service.as_str() {
            "ntfy" => {
                let (o_server, o_topic, o_token, o_user, o_pass) = match old_kind {
                    Some(ChannelKind::Ntfy {
                        server,
                        topic,
                        token,
                        user,
                        password,
                    }) => (
                        Some(server.clone()),
                        Some(topic.clone()),
                        token.clone(),
                        user.clone(),
                        password.clone(),
                    ),
                    _ => (None, None, None, None, None),
                };
                let clear = self.clear_auth.unwrap_or(false);
                ChannelKind::Ntfy {
                    server: pick(&self.server, o_server, true).unwrap_or_else(default_server),
                    topic: pick(&self.topic, o_topic, true)
                        .ok_or_else(|| anyhow!("a topic is needed"))?,
                    token: if clear {
                        None
                    } else {
                        pick(&self.token, o_token, true)
                    },
                    user: if clear {
                        None
                    } else {
                        pick_clearable(&self.user, o_user)
                    },
                    password: if clear {
                        None
                    } else {
                        pick(&self.password, o_pass, false)
                    },
                }
            }
            "pushover" => {
                let (o_user, o_app, o_dev) = match old_kind {
                    Some(ChannelKind::Pushover {
                        user_key,
                        app_token,
                        device,
                    }) => (
                        Some(user_key.clone()),
                        Some(app_token.clone()),
                        device.clone(),
                    ),
                    _ => (None, None, None),
                };
                ChannelKind::Pushover {
                    user_key: pick(&self.user_key, o_user, true)
                        .ok_or_else(|| anyhow!("the Pushover user key is needed"))?,
                    app_token: pick(&self.app_token, o_app, true)
                        .ok_or_else(|| anyhow!("the Pushover API token is needed"))?,
                    device: pick_clearable(&self.device, o_dev),
                }
            }
            "telegram" => {
                let (o_bot, o_chat) = match old_kind {
                    Some(ChannelKind::Telegram { bot_token, chat_id }) => {
                        (Some(bot_token.clone()), Some(chat_id.clone()))
                    }
                    _ => (None, None),
                };
                ChannelKind::Telegram {
                    bot_token: pick(&self.bot_token, o_bot, true)
                        .ok_or_else(|| anyhow!("the bot token is needed"))?,
                    chat_id: pick(&self.chat_id, o_chat, true)
                        .ok_or_else(|| anyhow!("the chat id is needed"))?,
                }
            }
            other => bail!("unknown service {other:?}: use ntfy, pushover or telegram"),
        };
        let kind = normalize_kind(kind);
        validate_kind(&kind)?;
        let name = match self.name.as_deref().map(str::trim) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => old
                .map(|c| c.name.clone())
                .unwrap_or_else(|| kind.service_title().to_string()),
        };
        if name.chars().count() > 60 || name.chars().any(char::is_control) {
            bail!("the name is at most 60 characters, without control characters");
        }
        let events = match &self.events {
            Some(list) => list.iter().copied().collect(),
            None => old
                .map(|c| c.events.clone())
                .unwrap_or_else(Category::defaults),
        };
        Ok(Channel {
            id: old.map(|c| c.id.clone()).unwrap_or_else(new_id),
            name,
            enabled: self.enabled.or(old.map(|c| c.enabled)).unwrap_or(true),
            kind,
            events,
            details: self.details.or(old.map(|c| c.details)).unwrap_or(true),
        })
    }
}

/// 8 random hex digits.
fn new_id() -> String {
    let mut b = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex::encode(b)
}

/// The ntfy server without a trailing slash.
fn normalize_kind(kind: ChannelKind) -> ChannelKind {
    match kind {
        ChannelKind::Ntfy {
            server,
            topic,
            token,
            user,
            password,
        } => ChannelKind::Ntfy {
            server: server.trim().trim_end_matches('/').to_string(),
            topic,
            token,
            user,
            password,
        },
        other => other,
    }
}

fn no_control(s: &str, what: &str) -> Result<()> {
    if s.chars().any(char::is_control) {
        bail!("{what} has a control character");
    }
    Ok(())
}

/// A token or key: no spaces or control characters (it goes into a header
/// or an URL).
fn plain_secret(s: &str, what: &str) -> Result<()> {
    if s.is_empty() || s.len() > 300 || s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        bail!("{what} must be one word of at most 300 characters, without spaces");
    }
    Ok(())
}

/// Check what can be checked without asking the service.
pub fn validate_kind(kind: &ChannelKind) -> Result<()> {
    match kind {
        ChannelKind::Ntfy {
            server,
            topic,
            token,
            user,
            password,
        } => {
            if topic.is_empty()
                || topic.len() > 64
                || !topic
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                bail!("the topic is 1 to 64 letters, digits, - or _");
            }
            let rest = server
                .strip_prefix("https://")
                .or_else(|| server.strip_prefix("http://"))
                .ok_or_else(|| anyhow!("the server address starts with https:// or http://"))?;
            if rest.is_empty()
                || rest.starts_with('/')
                || server.len() > 200
                || server.chars().any(|c| c.is_control() || c.is_whitespace())
                || server.contains('?')
                || server.contains('#')
            {
                bail!("the server address is not valid");
            }
            if let Some(t) = token {
                plain_secret(t, "the access token")?;
            }
            if let Some(u) = user {
                no_control(u, "the user name")?;
                if u.contains(':') {
                    bail!("the user name cannot contain a colon");
                }
                if password.as_deref().unwrap_or("").is_empty() {
                    bail!("a user name needs a password");
                }
            }
            if let Some(p) = password {
                no_control(p, "the password")?;
            }
        }
        ChannelKind::Pushover {
            user_key,
            app_token,
            device,
        } => {
            plain_secret(user_key, "the user key")?;
            plain_secret(app_token, "the API token")?;
            if let Some(d) = device {
                if d.len() > 25
                    || !d
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    bail!("a Pushover device name is up to 25 letters, digits, - or _");
                }
            }
        }
        ChannelKind::Telegram { bot_token, chat_id } => {
            plain_secret(bot_token, "the bot token")?;
            if !bot_token.contains(':') {
                bail!("the bot token looks like 123456789:AA... (from @BotFather)");
            }
            let numeric = {
                let digits = chat_id.strip_prefix('-').unwrap_or(chat_id);
                !digits.is_empty()
                    && digits.len() <= 20
                    && digits.chars().all(|c| c.is_ascii_digit())
            };
            let named = chat_id.strip_prefix('@').is_some_and(|n| {
                (4..=64).contains(&n.len())
                    && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
            if !numeric && !named {
                bail!("the chat id is a number (it may start with -) or @name");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The masked view.

/// A secret as the interface sees it: whether it is set, and its last
/// characters so a person can tell which one it is.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Secret {
    pub set: bool,
    pub hint: String,
}

fn mask(s: &str) -> Secret {
    let n = s.chars().count();
    let hint = if n > 8 {
        let tail: String = s.chars().skip(n - 4).collect();
        format!("…{tail}")
    } else {
        "…".to_string()
    };
    Secret { set: true, hint }
}

fn mask_opt(s: &Option<String>) -> Option<Secret> {
    s.as_deref().filter(|v| !v.is_empty()).map(mask)
}

#[derive(Clone, Debug, Serialize)]
pub struct ChannelView {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub service: &'static str,
    pub events: BTreeSet<Category>,
    pub details: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_key: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_token: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_token: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<String>,
}

impl Channel {
    /// Every secret of the channel, for the log's redaction list.
    pub fn secrets(&self) -> Vec<&str> {
        match &self.kind {
            ChannelKind::Ntfy {
                token, password, ..
            } => [token, password]
                .into_iter()
                .filter_map(|s| s.as_deref())
                .collect(),
            ChannelKind::Pushover {
                user_key,
                app_token,
                ..
            } => vec![user_key.as_str(), app_token.as_str()],
            ChannelKind::Telegram { bot_token, .. } => vec![bot_token.as_str()],
        }
    }

    /// The channel with every secret masked.
    pub fn view(&self) -> ChannelView {
        let mut v = ChannelView {
            id: self.id.clone(),
            name: self.name.clone(),
            enabled: self.enabled,
            service: self.kind.service(),
            events: self.events.clone(),
            details: self.details,
            server: None,
            topic: None,
            token: None,
            user: None,
            password: None,
            user_key: None,
            app_token: None,
            device: None,
            bot_token: None,
            chat_id: None,
        };
        match &self.kind {
            ChannelKind::Ntfy {
                server,
                topic,
                token,
                user,
                password,
            } => {
                v.server = Some(server.clone());
                v.topic = Some(topic.clone());
                v.token = mask_opt(token);
                v.user = user.clone();
                v.password = mask_opt(password);
            }
            ChannelKind::Pushover {
                user_key,
                app_token,
                device,
            } => {
                v.user_key = Some(mask(user_key));
                v.app_token = Some(mask(app_token));
                v.device = device.clone();
            }
            ChannelKind::Telegram { bot_token, chat_id } => {
                v.bot_token = Some(mask(bot_token));
                v.chat_id = Some(chat_id.clone());
            }
        }
        v
    }
}

// ---------------------------------------------------------------------------
// Messages and requests.

/// What the program wants to say.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub category: Category,
    pub title: String,
    pub body: String,
}

impl Message {
    pub fn new(category: Category, title: &str, body: &str) -> Message {
        Message {
            category,
            title: title.to_string(),
            body: body.to_string(),
        }
    }
}

/// The title and the text that are sent. Without details only the category
/// shows; the daily summary holds no names, so it always shows.
fn render(msg: &Message, device: &str, details: bool) -> (String, String) {
    if details || msg.category == Category::DailySummary {
        (msg.title.clone(), format!("{device}: {}", msg.body))
    } else {
        (
            msg.category.title().to_string(),
            format!("Open Varsto on {device} for details."),
        )
    }
}

/// One HTTP POST, ready to send. Holds secrets: no Debug output of its own.
pub struct Prepared {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub content_type: String,
    /// Strings to cut out of error text.
    pub secrets: Vec<String>,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Prepared({} bytes)", self.body.len())
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// A header value on one line.
fn header_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn pct_encode(s: &str, out: &mut String) {
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        pct_encode(k, &mut out);
        out.push('=');
        pct_encode(v, &mut out);
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The request that delivers `msg` to a channel. No I/O.
pub fn build_request(kind: &ChannelKind, msg: &Message, device: &str, details: bool) -> Prepared {
    let (title, text) = render(msg, device, details);
    let alert = msg.category.level() == Level::Alert;
    match kind {
        ChannelKind::Ntfy {
            server,
            topic,
            token,
            user,
            password,
        } => {
            let priority = if alert {
                "4"
            } else if msg.category == Category::DailySummary {
                "2"
            } else {
                "3"
            };
            let tags = if alert {
                "warning"
            } else {
                "information_source"
            };
            let mut headers = vec![
                (
                    "Title".to_string(),
                    header_text(&truncate_chars(&title, 200)),
                ),
                ("Priority".to_string(), priority.to_string()),
                ("Tags".to_string(), tags.to_string()),
            ];
            let mut secrets = Vec::new();
            if let Some(t) = token.as_deref().filter(|t| !t.is_empty()) {
                headers.push(("Authorization".to_string(), format!("Bearer {t}")));
                secrets.push(t.to_string());
            } else if let Some(u) = user.as_deref().filter(|u| !u.is_empty()) {
                use base64::Engine as _;
                let pass = password.as_deref().unwrap_or("");
                let b64 = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{pass}"));
                headers.push(("Authorization".to_string(), format!("Basic {b64}")));
                secrets.push(b64);
                if !pass.is_empty() {
                    secrets.push(pass.to_string());
                }
            }
            Prepared {
                url: format!("{}/{}", server.trim_end_matches('/'), topic),
                headers,
                body: truncate_chars(&text, 1500).into_bytes(),
                content_type: "text/plain; charset=utf-8".to_string(),
                secrets,
            }
        }
        ChannelKind::Pushover {
            user_key,
            app_token,
            device: target,
        } => {
            // Never priority 1 or 2: they bypass quiet hours or demand an
            // acknowledgement, which is not for a backup program to decide.
            let priority = if alert { "0" } else { "-1" };
            let title = truncate_chars(&title, 240);
            let text = truncate_chars(&text, 1000);
            let mut pairs: Vec<(&str, &str)> = vec![
                ("token", app_token.as_str()),
                ("user", user_key.as_str()),
                ("title", title.as_str()),
                ("message", text.as_str()),
                ("priority", priority),
            ];
            if let Some(d) = target.as_deref().filter(|d| !d.is_empty()) {
                pairs.push(("device", d));
            }
            Prepared {
                url: "https://api.pushover.net/1/messages.json".to_string(),
                headers: Vec::new(),
                body: form_encode(&pairs).into_bytes(),
                content_type: "application/x-www-form-urlencoded".to_string(),
                secrets: vec![app_token.clone(), user_key.clone()],
            }
        }
        ChannelKind::Telegram { bot_token, chat_id } => {
            let html = format!(
                "<b>{}</b>\n{}",
                html_escape(&truncate_chars(&title, 200)),
                html_escape(&truncate_chars(&text, 3500))
            );
            let body = json!({
                "chat_id": chat_id,
                "text": html,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            });
            Prepared {
                url: format!("https://api.telegram.org/bot{bot_token}/sendMessage"),
                headers: Vec::new(),
                body: body.to_string().into_bytes(),
                content_type: "application/json".to_string(),
                secrets: vec![bot_token.clone()],
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sending.

/// Cut the secrets and any Telegram `bot<token>` out of `text`.
pub fn redact(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_string();
    for s in secrets {
        if s.len() >= 4 {
            out = out.replace(s.as_str(), "…");
        }
    }
    redact_bot_token(&out)
}

/// `bot123456:ABC...` becomes `bot…`, wherever it stands in the text.
fn redact_bot_token(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("bot") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == ':' || c == '_' || c == '-'))
            .unwrap_or(tail.len());
        let run = &tail[..end];
        let looks_like_token =
            run.contains(':') && run.chars().next().is_some_and(|c| c.is_ascii_digit());
        if looks_like_token {
            out.push('…');
        } else {
            out.push_str(run);
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(SEND_TIMEOUT))
        .timeout_connect(Some(Duration::from_secs(10)))
        .user_agent(concat!("varsto/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// The reason the service gives in its answer: ntfy `error`, Pushover
/// `errors`, Telegram `description`.
fn service_error(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    if let Some(s) = v.get("error").and_then(Value::as_str) {
        return Some(s.to_string());
    }
    if let Some(a) = v.get("errors").and_then(Value::as_array) {
        let list: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
        if !list.is_empty() {
            return Some(list.join("; "));
        }
    }
    v.get("description")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn read_body(resp: &mut ureq::http::Response<ureq::Body>) -> String {
    resp.body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_string()
        .unwrap_or_default()
}

/// POST the request. The error says what went wrong in words and never
/// holds a secret.
pub fn send(p: &Prepared) -> Result<()> {
    let (status, text) = exchange(p)?;
    if (200..300).contains(&status) {
        return Ok(());
    }
    let why = service_error(&text)
        .map(|e| format!(": {}", truncate_chars(&e, 300)))
        .unwrap_or_default();
    Err(anyhow!(redact(
        &format!("the service answered HTTP {status}{why}"),
        &p.secrets
    )))
}

/// The status and the body of the answer.
fn exchange(p: &Prepared) -> Result<(u16, String)> {
    let mut req = agent()
        .post(&p.url)
        .header("Content-Type", p.content_type.as_str());
    for (k, v) in &p.headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let mut resp = req
        .send(&p.body[..])
        .map_err(|e| anyhow!(redact(&format!("not sent: {e}"), &p.secrets)))?;
    let status = resp.status().as_u16();
    let text = read_body(&mut resp);
    Ok((status, text))
}

/// Send a test message to a channel now. Details are always on: the person
/// pressing the button wants to see the text.
pub fn send_test(kind: &ChannelKind, device: &str) -> Result<()> {
    let msg = Message::new(Category::Other, "Varsto test", "Test message from Varsto.");
    send(&build_request(kind, &msg, device, true))
}

/// The chats that wrote to a bot lately, from `getUpdates`: the chat id and
/// a label. A person has to message the bot first.
pub fn telegram_chats(bot_token: &str) -> Result<Vec<(String, String)>> {
    let token = bot_token.trim();
    plain_secret(token, "the bot token")?;
    let secrets = vec![token.to_string()];
    let url = format!("https://api.telegram.org/bot{token}/getUpdates?timeout=0&limit=100");
    let mut resp = agent()
        .get(&url)
        .call()
        .map_err(|e| anyhow!(redact(&format!("not reached: {e}"), &secrets)))?;
    let status = resp.status().as_u16();
    let text = read_body(&mut resp);
    if !(200..300).contains(&status) {
        let why = service_error(&text)
            .map(|e| format!(": {e}"))
            .unwrap_or_default();
        bail!(
            "{}",
            redact(&format!("Telegram answered HTTP {status}{why}"), &secrets)
        );
    }
    let v: Value =
        serde_json::from_str(&text).map_err(|_| anyhow!("Telegram's answer is not JSON"))?;
    Ok(parse_telegram_chats(&v))
}

/// The distinct chats in a `getUpdates` answer.
fn parse_telegram_chats(answer: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let updates = answer
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for u in &updates {
        for key in [
            "message",
            "edited_message",
            "channel_post",
            "my_chat_member",
        ] {
            let Some(chat) = u.get(key).and_then(|m| m.get("chat")) else {
                continue;
            };
            let Some(id) = chat.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let id = id.to_string();
            if out.iter().any(|(i, _)| *i == id) {
                continue;
            }
            let text = |k: &str| {
                chat.get(k)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            };
            let label = match chat.get("type").and_then(Value::as_str) {
                Some("private") | None => match (text("first_name"), text("username")) {
                    (Some(n), Some(u)) => format!("{n} (@{u})"),
                    (Some(n), None) => n,
                    (None, Some(u)) => format!("@{u}"),
                    (None, None) => id.clone(),
                },
                Some(_) => text("title")
                    .or_else(|| text("username").map(|u| format!("@{u}")))
                    .unwrap_or_else(|| id.clone()),
            };
            out.push((id, label));
        }
    }
    out
}

/// Ask Pushover whether the user key and the API token belong together.
pub fn pushover_validate(user_key: &str, app_token: &str) -> Result<()> {
    let user_key = user_key.trim();
    let app_token = app_token.trim();
    plain_secret(user_key, "the user key")?;
    plain_secret(app_token, "the API token")?;
    let p = Prepared {
        url: "https://api.pushover.net/1/users/validate.json".to_string(),
        headers: Vec::new(),
        body: form_encode(&[("token", app_token), ("user", user_key)]).into_bytes(),
        content_type: "application/x-www-form-urlencoded".to_string(),
        secrets: vec![app_token.to_string(), user_key.to_string()],
    };
    send(&p)
}

/// A topic nobody will guess: anyone who knows a topic on ntfy.sh can read
/// its messages.
pub fn suggest_ntfy_topic() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rngs::OsRng;
    let tail: String = (0..20)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect();
    format!("varsto-{tail}")
}

// ---------------------------------------------------------------------------
// Pure rules for the sender: duplicates, the rate cap, the waiting list.

/// The same message is sent once in [`DEDUPE_SECS`].
#[derive(Default)]
struct Dedupe {
    seen: HashMap<String, i64>,
}

impl Dedupe {
    /// True when `key` was not seen lately; remembers it.
    fn allow(&mut self, key: &str, now: i64) -> bool {
        self.seen.retain(|_, t| now - *t < DEDUPE_SECS);
        if self.seen.contains_key(key) {
            return false;
        }
        self.seen.insert(key.to_string(), now);
        true
    }
}

fn dedupe_key(msg: &Message) -> String {
    format!("{}\u{1}{}\u{1}{}", msg.category.id(), msg.title, msg.body)
}

/// At most [`RATE_MAX`] messages an hour to one channel.
#[derive(Default)]
struct RateCap {
    sent: Vec<i64>,
    suppressed: u32,
}

impl RateCap {
    fn prune(&mut self, now: i64) {
        self.sent.retain(|t| now - *t < RATE_WINDOW_SECS);
    }

    /// True when one more message may go now; counts it. Otherwise it is
    /// counted as held back.
    fn allow(&mut self, now: i64) -> bool {
        self.prune(now);
        if self.sent.len() < RATE_MAX {
            self.sent.push(now);
            true
        } else {
            self.suppressed += 1;
            false
        }
    }

    /// How many were held back, once there is room to say so.
    fn take_suppressed(&mut self, now: i64) -> Option<u32> {
        self.prune(now);
        if self.suppressed > 0 && self.sent.len() < RATE_MAX {
            let n = self.suppressed;
            self.suppressed = 0;
            Some(n)
        } else {
            None
        }
    }
}

/// Seconds to wait after the `tries`-th failure.
fn backoff_secs(tries: u32) -> i64 {
    let shift = tries.saturating_sub(1).min(10);
    (RETRY_FIRST_SECS << shift).min(RETRY_MAX_SECS)
}

/// A message waiting for one channel.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Entry {
    channel: String,
    category: Category,
    title: String,
    body: String,
    created: i64,
    tries: u32,
    next_try: i64,
}

/// Drop what is too old, and the oldest beyond the limit.
fn trim_outbox(entries: &mut Vec<Entry>, now: i64) {
    entries.retain(|e| now - e.created < OUTBOX_MAX_AGE_SECS);
    if entries.len() > OUTBOX_MAX {
        entries.sort_by_key(|e| e.created);
        let extra = entries.len() - OUTBOX_MAX;
        entries.drain(..extra);
    }
}

#[derive(Default, Serialize, Deserialize)]
struct OutboxFile {
    #[serde(default)]
    entries: Vec<Entry>,
    /// Alerts of the last 24 hours, for the daily summary.
    #[serde(default)]
    history: Vec<(i64, Category)>,
    /// The local day the summary was sent for last.
    #[serde(default)]
    summary_day: Option<i64>,
}

/// "Varsto is running. ..." from the alerts of the last 24 hours.
fn summary_text(history: &[(i64, Category)], now: i64) -> String {
    let mut counts: BTreeMap<Category, usize> = BTreeMap::new();
    for (t, c) in history {
        if now - *t < 24 * 3600 && c.level() == Level::Alert {
            *counts.entry(*c).or_default() += 1;
        }
    }
    let total: usize = counts.values().sum();
    if total == 0 {
        return "Varsto is running. In the last 24 hours: no problems.".to_string();
    }
    let parts: Vec<String> = counts
        .iter()
        .map(|(c, n)| format!("{} {n}", c.title().to_lowercase()))
        .collect();
    format!(
        "Varsto is running. In the last 24 hours: {total} {} ({}).",
        if total == 1 { "alert" } else { "alerts" },
        parts.join(", ")
    )
}

/// Seconds east of UTC at `now`, for the local hour of the summary.
#[cfg(unix)]
fn local_utc_offset_secs(now: i64) -> i64 {
    let t = now as libc::time_t;
    // SAFETY: `tm` is plain data and `localtime_r` writes only into it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::localtime_r(&t, &mut tm) };
    if r.is_null() {
        0
    } else {
        tm.tm_gmtoff as i64
    }
}

#[cfg(windows)]
fn local_utc_offset_secs(_now: i64) -> i64 {
    use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    // SAFETY: the struct is plain data that the call fills in.
    let mut tzi: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let id = unsafe { GetTimeZoneInformation(&mut tzi) };
    // Bias is minutes west of UTC; 2 means daylight time is in effect.
    let bias = tzi.Bias
        + if id == 2 {
            tzi.DaylightBias
        } else {
            tzi.StandardBias
        };
    -(bias as i64) * 60
}

#[cfg(not(any(unix, windows)))]
fn local_utc_offset_secs(_now: i64) -> i64 {
    0
}

/// The local day number and the local hour (0 to 23).
fn local_day_hour(now: i64, offset: i64) -> (i64, i64) {
    let local = now + offset;
    (local.div_euclid(86_400), local.rem_euclid(86_400) / 3600)
}

// ---------------------------------------------------------------------------
// The notifier: one sender thread per process.

/// How the last send to a channel went.
#[derive(Clone, Debug, Serialize)]
pub struct ChannelStatus {
    pub ok: bool,
    pub utc: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Default)]
struct Shared {
    device: Mutex<String>,
    status: Mutex<BTreeMap<String, ChannelStatus>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct Notifier {
    shared: Arc<Shared>,
    tx: Mutex<Option<mpsc::Sender<Message>>>,
}

static NOTIFIER: OnceLock<Notifier> = OnceLock::new();

/// The notifier of this process. Until [`Notifier::init`] runs, messages
/// are dropped (a one-shot command has nobody to send them).
pub fn notifier() -> &'static Notifier {
    NOTIFIER.get_or_init(|| Notifier {
        shared: Arc::new(Shared::default()),
        tx: Mutex::new(None),
    })
}

impl Notifier {
    /// Start the sender thread for `home`. Calling it again only updates
    /// the device name.
    pub fn init(&self, home: &Path, device: &str) {
        self.set_device(device);
        let mut tx = lock(&self.tx);
        if tx.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let worker = Worker::new(home.to_path_buf(), self.shared.clone());
        match std::thread::Builder::new()
            .name("notify".into())
            .spawn(move || worker.run(receiver))
        {
            Ok(_) => *tx = Some(sender),
            Err(e) => log::warn!("notification sender not started: {e}"),
        }
    }

    /// The name that starts every message (known after unlock).
    pub fn set_device(&self, name: &str) {
        let name = name.trim();
        if !name.is_empty() {
            *lock(&self.shared.device) = name.to_string();
        }
    }

    pub fn device(&self) -> String {
        lock(&self.shared.device).clone()
    }

    /// Hand a message to the sender thread. Never blocks.
    pub fn push(&self, msg: Message) {
        if let Some(tx) = lock(&self.tx).as_ref() {
            let _ = tx.send(msg);
        }
    }

    /// How the last send to each channel went (by channel id).
    pub fn status(&self) -> BTreeMap<String, ChannelStatus> {
        lock(&self.shared.status).clone()
    }
}

struct Worker {
    home: PathBuf,
    shared: Arc<Shared>,
    config: NotifyConfig,
    config_mtime: Option<SystemTime>,
    config_loaded: bool,
    out: OutboxFile,
    dedupe: Dedupe,
    rates: BTreeMap<String, RateCap>,
    dirty: bool,
}

impl Worker {
    fn new(home: PathBuf, shared: Arc<Shared>) -> Worker {
        let out: OutboxFile =
            util::read_json_or_default(&home.join(OUTBOX_FILE)).unwrap_or_default();
        Worker {
            home,
            shared,
            config: NotifyConfig::default(),
            config_mtime: None,
            config_loaded: false,
            out,
            dedupe: Dedupe::default(),
            rates: BTreeMap::new(),
            dirty: false,
        }
    }

    fn run(mut self, rx: mpsc::Receiver<Message>) {
        // What waited when the program stopped goes out first.
        self.tick();
        loop {
            match rx.recv_timeout(Duration::from_secs(self.wait_secs() as u64)) {
                Ok(m) => {
                    self.handle(m);
                    while let Ok(m) = rx.try_recv() {
                        self.handle(m);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            self.tick();
        }
    }

    /// Seconds until something may be due: a retry, or the next look at the
    /// summary.
    fn wait_secs(&self) -> i64 {
        let now = util::now_utc();
        let next = self
            .out
            .entries
            .iter()
            .map(|e| e.next_try - now)
            .min()
            .unwrap_or(WAKE_SECS);
        next.clamp(1, WAKE_SECS)
    }

    fn reload(&mut self) {
        let path = NotifyConfig::path(&self.home);
        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        if self.config_loaded && mtime == self.config_mtime {
            return;
        }
        self.config_loaded = true;
        self.config_mtime = mtime;
        match NotifyConfig::load(&self.home) {
            Ok(c) => {
                // Whatever the debug log would print, these stay out of it.
                for ch in &c.channels {
                    for s in ch.secrets() {
                        crate::logging::register_secret(s);
                    }
                }
                self.config = c;
            }
            Err(e) => log::warn!("notify.json not read: {e:#}"),
        }
    }

    fn handle(&mut self, msg: Message) {
        let now = util::now_utc();
        if !self.dedupe.allow(&dedupe_key(&msg), now) {
            return;
        }
        if msg.category.level() == Level::Alert {
            self.out.history.push((now, msg.category));
            self.dirty = true;
        }
        self.reload();
        for ch in &self.config.channels {
            if ch.enabled && ch.events.contains(&msg.category) {
                self.out.entries.push(Entry {
                    channel: ch.id.clone(),
                    category: msg.category,
                    title: msg.title.clone(),
                    body: msg.body.clone(),
                    created: now,
                    tries: 0,
                    next_try: now,
                });
                self.dirty = true;
            }
        }
    }

    fn tick(&mut self) {
        let now = util::now_utc();
        self.reload();
        self.summary_if_due(now);
        self.flush(now);
        self.notice_held_back(now);
        trim_outbox(&mut self.out.entries, now);
        self.out.history.retain(|(t, _)| now - *t < 24 * 3600);
        if self.out.history.len() > 2000 {
            let extra = self.out.history.len() - 2000;
            self.out.history.drain(..extra);
        }
        if self.dirty {
            self.dirty = false;
            if let Err(e) = util::write_json(&self.home.join(OUTBOX_FILE), &self.out) {
                log::warn!("notification outbox not saved: {e:#}");
            }
        }
    }

    /// Queue the daily summary once the local hour has come.
    fn summary_if_due(&mut self, now: i64) {
        if !self.config.wants_summary() {
            return;
        }
        let (day, hour) = local_day_hour(now, local_utc_offset_secs(now));
        if hour < i64::from(self.config.summary_hour) || self.out.summary_day == Some(day) {
            return;
        }
        self.out.summary_day = Some(day);
        let body = summary_text(&self.out.history, now);
        for ch in &self.config.channels {
            if ch.enabled && ch.events.contains(&Category::DailySummary) {
                self.out.entries.push(Entry {
                    channel: ch.id.clone(),
                    category: Category::DailySummary,
                    title: "Varsto daily summary".to_string(),
                    body: body.clone(),
                    created: now,
                    tries: 0,
                    next_try: now,
                });
            }
        }
        self.dirty = true;
    }

    /// Send what is due. A channel that fails keeps its other messages for
    /// the next round.
    fn flush(&mut self, now: i64) {
        if self.out.entries.is_empty() {
            return;
        }
        let device = lock(&self.shared.device).clone();
        let device = if device.is_empty() {
            "this device".to_string()
        } else {
            device
        };
        let mut failed: BTreeSet<String> = BTreeSet::new();
        // When a channel fails, its other messages wait as long as the one
        // that failed: one attempt per channel per backoff, not one per
        // message per second.
        let mut held: BTreeMap<String, i64> = BTreeMap::new();
        let mut keep: Vec<Entry> = Vec::new();
        let entries = std::mem::take(&mut self.out.entries);
        for mut e in entries {
            let ch = self
                .config
                .channels
                .iter()
                .find(|c| c.id == e.channel && c.enabled)
                .cloned();
            let Some(ch) = ch else {
                // The channel was removed or switched off meanwhile.
                self.dirty = true;
                continue;
            };
            if e.next_try > now || failed.contains(&e.channel) {
                keep.push(e);
                continue;
            }
            if !self.rates.entry(e.channel.clone()).or_default().allow(now) {
                self.dirty = true;
                continue;
            }
            let msg = Message {
                category: e.category,
                title: e.title.clone(),
                body: e.body.clone(),
            };
            let prepared = build_request(&ch.kind, &msg, &device, ch.details);
            let result = send(&prepared);
            self.dirty = true;
            match result {
                Ok(()) => {
                    lock(&self.shared.status).insert(
                        ch.id.clone(),
                        ChannelStatus {
                            ok: true,
                            utc: now,
                            error: None,
                        },
                    );
                }
                Err(err) => {
                    e.tries += 1;
                    e.next_try = now + backoff_secs(e.tries);
                    held.insert(e.channel.clone(), e.next_try);
                    failed.insert(e.channel.clone());
                    lock(&self.shared.status).insert(
                        ch.id.clone(),
                        ChannelStatus {
                            ok: false,
                            utc: now,
                            error: Some(format!("{err:#}")),
                        },
                    );
                    keep.push(e);
                }
            }
        }
        for e in &mut keep {
            if let Some(t) = held.get(&e.channel) {
                e.next_try = e.next_try.max(*t);
            }
        }
        self.out.entries = keep;
    }

    /// Tell a channel that messages were held back by the hourly cap.
    fn notice_held_back(&mut self, now: i64) {
        let ids: Vec<String> = self.rates.keys().cloned().collect();
        for id in ids {
            let held = self.rates.get_mut(&id).and_then(|r| r.take_suppressed(now));
            if let Some(n) = held {
                self.out.entries.push(Entry {
                    channel: id,
                    category: Category::Other,
                    title: "Varsto".to_string(),
                    body: format!("{n} more alerts were not sent; open Varsto to see them."),
                    created: now,
                    tries: 0,
                    next_try: now,
                });
                self.dirty = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ntfy_input() -> ChannelInput {
        ChannelInput {
            service: "ntfy".into(),
            topic: Some("varsto-test".into()),
            ..Default::default()
        }
    }

    fn msg(cat: Category) -> Message {
        Message::new(cat, "Varsto disk", "Backup disk is full")
    }

    fn pushover() -> ChannelKind {
        ChannelKind::Pushover {
            user_key: "u1234567890123456789012345678".into(),
            app_token: "a1234567890123456789012345678".into(),
            device: None,
        }
    }

    fn telegram() -> ChannelKind {
        ChannelKind::Telegram {
            bot_token: "123456789:AAFsecretsecretsecret".into(),
            chat_id: "42".into(),
        }
    }

    #[test]
    fn config_roundtrip_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let empty = NotifyConfig::load(dir.path()).unwrap();
        assert!(empty.channels.is_empty());
        assert_eq!(empty.summary_hour, 9);

        let mut cfg = NotifyConfig::default();
        let ch = cfg.upsert(&ntfy_input()).unwrap();
        assert_eq!(ch.name, "ntfy");
        assert!(ch.enabled);
        assert!(ch.details);
        assert_eq!(ch.events, Category::defaults());
        assert_eq!(ch.id.len(), 8);
        assert!(!ch.events.contains(&Category::BackupsDone));
        assert!(ch.events.contains(&Category::Updates));
        match &ch.kind {
            ChannelKind::Ntfy { server, .. } => assert_eq!(server, "https://ntfy.sh"),
            other => panic!("wrong kind {other:?}"),
        }
        cfg.save(dir.path()).unwrap();
        let back = NotifyConfig::load(dir.path()).unwrap();
        assert_eq!(back, cfg);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(NotifyConfig::path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    fn old_file_without_fields_still_loads() {
        let text = r#"{"channels":[{"id":"ab","name":"x","kind":{"service":"telegram","bot_token":"1:a","chat_id":"5"}}]}"#;
        let cfg: NotifyConfig = serde_json::from_str(text).unwrap();
        assert_eq!(cfg.summary_hour, 9);
        assert!(cfg.channels[0].enabled);
        assert!(cfg.channels[0].details);
    }

    #[test]
    fn names_are_unique_and_found_by_id_or_name() {
        let mut cfg = NotifyConfig::default();
        let a = cfg.upsert(&ntfy_input()).unwrap();
        let b = cfg.upsert(&ntfy_input()).unwrap();
        assert_eq!(b.name, "ntfy 2");
        let mut named = ntfy_input();
        named.name = Some("NTFY".into());
        assert!(cfg.upsert(&named).is_err());
        assert_eq!(cfg.find(&a.id), Some(0));
        assert_eq!(cfg.find("NTFY 2"), Some(1));
        assert_eq!(cfg.find("nothing"), None);
        assert!(cfg.remove("ntfy 2").is_ok());
        assert_eq!(cfg.channels.len(), 1);
    }

    #[test]
    fn masking_never_leaks_a_secret() {
        let mut cfg = NotifyConfig::default();
        let kinds = [
            ChannelKind::Ntfy {
                server: "https://ntfy.example".into(),
                topic: "varsto-abc".into(),
                token: Some("tk_supersecrettoken1234".into()),
                user: Some("anna".into()),
                password: Some("hunter2hunter2".into()),
            },
            pushover(),
            telegram(),
        ];
        for (i, kind) in kinds.into_iter().enumerate() {
            cfg.channels.push(Channel {
                id: format!("0000000{i}"),
                name: format!("c{i}"),
                enabled: true,
                kind,
                events: Category::defaults(),
                details: true,
            });
        }
        let views: Vec<ChannelView> = cfg.channels.iter().map(Channel::view).collect();
        let json = serde_json::to_string(&views).unwrap();
        for secret in [
            "tk_supersecrettoken1234",
            "hunter2hunter2",
            "u1234567890123456789012345678",
            "a1234567890123456789012345678",
            "123456789:AAFsecretsecretsecret",
            "AAFsecretsecretsecret",
        ] {
            assert!(!json.contains(secret), "{secret} leaked");
        }
        assert!(json.contains("\"set\":true"));
        assert!(json.contains("…1234"));
        let debug = format!("{:?}", cfg.channels);
        assert!(!debug.contains("hunter2hunter2"));
        assert!(!debug.contains("AAFsecret"));
    }

    #[test]
    fn update_keeps_secrets_that_are_left_empty() {
        let mut cfg = NotifyConfig::default();
        let first = cfg
            .upsert(&ChannelInput {
                service: "telegram".into(),
                bot_token: Some("123456789:AAFsecret".into()),
                chat_id: Some("42".into()),
                ..Default::default()
            })
            .unwrap();
        // The page sends the id, a new chat id and an empty token.
        let changed = cfg
            .upsert(&ChannelInput {
                id: Some(first.id.clone()),
                service: "telegram".into(),
                bot_token: Some(String::new()),
                chat_id: Some("@mychannel".into()),
                name: Some("Phone".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(changed.id, first.id);
        assert_eq!(changed.name, "Phone");
        match &changed.kind {
            ChannelKind::Telegram { bot_token, chat_id } => {
                assert_eq!(bot_token, "123456789:AAFsecret");
                assert_eq!(chat_id, "@mychannel");
            }
            other => panic!("wrong kind {other:?}"),
        }
        // Absent works the same, and the service cannot change.
        let again = cfg
            .upsert(&ChannelInput {
                id: Some(first.id.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(again.kind, changed.kind);
        assert!(cfg
            .upsert(&ChannelInput {
                id: Some(first.id),
                service: "ntfy".into(),
                topic: Some("abc".into()),
                ..Default::default()
            })
            .is_err());
        assert_eq!(cfg.channels.len(), 1);
    }

    #[test]
    fn input_is_validated() {
        let mut cfg = NotifyConfig::default();
        let mut bad = ntfy_input();
        bad.topic = Some("has space".into());
        assert!(cfg.upsert(&bad).is_err());
        let mut bad = ntfy_input();
        bad.server = Some("ftp://x".into());
        assert!(cfg.upsert(&bad).is_err());
        let mut bad = ntfy_input();
        bad.user = Some("anna".into());
        assert!(cfg.upsert(&bad).is_err());
        let mut ok = ntfy_input();
        ok.server = Some("http://192.168.1.5:8080/".into());
        let ch = cfg.upsert(&ok).unwrap();
        match ch.kind {
            ChannelKind::Ntfy { server, .. } => assert_eq!(server, "http://192.168.1.5:8080"),
            _ => unreachable!(),
        }
        for chat in ["abc", "", "@ab", "12x"] {
            let r = cfg.upsert(&ChannelInput {
                service: "telegram".into(),
                bot_token: Some("1:a".into()),
                chat_id: Some(chat.into()),
                ..Default::default()
            });
            assert!(r.is_err(), "{chat:?} accepted");
        }
        assert!(cfg
            .upsert(&ChannelInput {
                service: "telegram".into(),
                bot_token: Some("1:a".into()),
                chat_id: Some("-1001234567890".into()),
                ..Default::default()
            })
            .is_ok());
        assert!(cfg
            .upsert(&ChannelInput {
                service: "pushover".into(),
                user_key: Some("k".into()),
                ..Default::default()
            })
            .is_err());
    }

    #[test]
    fn ntfy_request() {
        let kind = ChannelKind::Ntfy {
            server: "https://ntfy.example/".into(),
            topic: "varsto-abc".into(),
            token: None,
            user: None,
            password: None,
        };
        let p = build_request(&kind, &msg(Category::Space), "laptop", true);
        assert_eq!(p.url, "https://ntfy.example/varsto-abc");
        assert_eq!(
            String::from_utf8(p.body.clone()).unwrap(),
            "laptop: Backup disk is full"
        );
        let h = |name: &str| {
            p.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(h("Title").as_deref(), Some("Varsto disk"));
        assert_eq!(h("Priority").as_deref(), Some("4"));
        assert_eq!(h("Tags").as_deref(), Some("warning"));
        assert_eq!(h("Authorization"), None);

        let info = build_request(&kind, &msg(Category::Disks), "laptop", true);
        let prio = info.headers.iter().find(|(k, _)| k == "Priority").unwrap();
        assert_eq!(prio.1, "3");
        let sum = build_request(&kind, &msg(Category::DailySummary), "laptop", true);
        let prio = sum.headers.iter().find(|(k, _)| k == "Priority").unwrap();
        assert_eq!(prio.1, "2");
    }

    #[test]
    fn ntfy_auth_headers() {
        let bearer = ChannelKind::Ntfy {
            server: "https://n.example".into(),
            topic: "t".into(),
            token: Some("tk_abcdef".into()),
            user: Some("ignored".into()),
            password: Some("ignored".into()),
        };
        let p = build_request(&bearer, &msg(Category::Other), "d", true);
        let auth = p
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap();
        assert_eq!(auth.1, "Bearer tk_abcdef");

        let basic = ChannelKind::Ntfy {
            server: "https://n.example".into(),
            topic: "t".into(),
            token: None,
            user: Some("anna".into()),
            password: Some("pw".into()),
        };
        let p = build_request(&basic, &msg(Category::Other), "d", true);
        let auth = p
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap();
        // base64("anna:pw")
        assert_eq!(auth.1, "Basic YW5uYTpwdw==");
    }

    #[test]
    fn pushover_request() {
        let p = build_request(&pushover(), &msg(Category::Storage), "laptop", true);
        assert_eq!(p.url, "https://api.pushover.net/1/messages.json");
        assert_eq!(p.content_type, "application/x-www-form-urlencoded");
        let body = String::from_utf8(p.body).unwrap();
        assert!(body.contains("token=a1234567890123456789012345678"));
        assert!(body.contains("user=u1234567890123456789012345678"));
        assert!(body.contains("priority=0"));
        assert!(body.contains("title=Varsto%20disk"));
        assert!(body.contains("message=laptop%3A%20Backup%20disk%20is%20full"));
        assert!(!body.contains("device="));

        let info = build_request(&pushover(), &msg(Category::Folders), "laptop", true);
        assert!(String::from_utf8(info.body)
            .unwrap()
            .contains("priority=-1"));

        let with_device = ChannelKind::Pushover {
            user_key: "u".into(),
            app_token: "a".into(),
            device: Some("phone".into()),
        };
        let p = build_request(&with_device, &msg(Category::Storage), "d", true);
        assert!(String::from_utf8(p.body).unwrap().contains("device=phone"));
    }

    #[test]
    fn telegram_request_escapes_html() {
        let m = Message::new(Category::Folders, "Folder <a&b>", "x < y & z > w");
        let p = build_request(&telegram(), &m, "lap<top>", true);
        assert_eq!(
            p.url,
            "https://api.telegram.org/bot123456789:AAFsecretsecretsecret/sendMessage"
        );
        let v: Value = serde_json::from_slice(&p.body).unwrap();
        assert_eq!(v["chat_id"], "42");
        assert_eq!(v["parse_mode"], "HTML");
        assert_eq!(v["disable_web_page_preview"], true);
        assert_eq!(
            v["text"],
            "<b>Folder &lt;a&amp;b&gt;</b>\nlap&lt;top&gt;: x &lt; y &amp; z &gt; w"
        );
    }

    #[test]
    fn details_off_hides_names() {
        let m = Message::new(
            Category::Storage,
            "Varsto storage",
            "Storage family-photos-s3 cannot be reached",
        );
        for kind in [pushover(), telegram()] {
            let p = build_request(&kind, &m, "laptop", false);
            let all = format!(
                "{}{}",
                String::from_utf8(p.body.clone()).unwrap(),
                p.headers
                    .iter()
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>()
                    .join("")
            );
            assert!(!all.contains("family-photos"), "name leaked");
            assert!(all.contains("Storage"));
            assert!(all.contains("Open"));
        }
        // The summary has no names, so it keeps its text.
        let s = Message::new(
            Category::DailySummary,
            "Varsto daily summary",
            "no problems",
        );
        let p = build_request(&telegram(), &s, "laptop", false);
        assert!(String::from_utf8(p.body).unwrap().contains("no problems"));
    }

    #[test]
    fn long_text_is_cut() {
        let long = "x".repeat(5000);
        let m = Message::new(Category::Other, "t", &long);
        let p = build_request(&pushover(), &m, "d", true);
        let body = String::from_utf8(p.body).unwrap();
        assert!(body.len() < 1500);
    }

    #[test]
    fn errors_never_hold_the_token() {
        let secrets = vec!["123456789:AAFsecretsecretsecret".to_string()];
        let text = "not sent: error sending request for url (https://api.telegram.org/bot123456789:AAFsecretsecretsecret/sendMessage)";
        let out = redact(text, &secrets);
        assert!(!out.contains("AAFsecret"));
        assert!(!out.contains("123456789"));
        assert!(out.contains("bot…/sendMessage"));
        // Even a token we were not told about.
        let out = redact("GET /bot987654321:ZZZ-yyy_xxx/getUpdates failed", &[]);
        assert_eq!(out, "GET /bot…/getUpdates failed");
        // Words that merely contain "bot" are left alone.
        assert_eq!(redact("robot lab: ok", &[]), "robot lab: ok");
        let p = build_request(&telegram(), &msg(Category::Other), "d", true);
        assert!(!format!("{p:?}").contains("AAFsecret"));
    }

    #[test]
    fn service_errors_are_read() {
        assert_eq!(
            service_error(r#"{"code":40101,"error":"unauthorized"}"#).as_deref(),
            Some("unauthorized")
        );
        assert_eq!(
            service_error(r#"{"status":0,"errors":["user identifier is invalid","x"]}"#).as_deref(),
            Some("user identifier is invalid; x")
        );
        assert_eq!(
            service_error(
                r#"{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}"#
            )
            .as_deref(),
            Some("Bad Request: chat not found")
        );
        assert_eq!(service_error("<html>"), None);
    }

    #[test]
    fn telegram_chats_are_listed_once() {
        let answer = json!({"ok": true, "result": [
            {"update_id": 1, "message": {"chat": {"id": 42, "type": "private", "first_name": "Anna", "username": "anna"}}},
            {"update_id": 2, "message": {"chat": {"id": 42, "type": "private", "first_name": "Anna"}}},
            {"update_id": 3, "message": {"chat": {"id": -100123, "type": "supergroup", "title": "Family"}}},
            {"update_id": 4, "my_chat_member": {"chat": {"id": 7, "type": "private", "first_name": "Bo"}}},
            {"update_id": 5}
        ]});
        let chats = parse_telegram_chats(&answer);
        assert_eq!(
            chats,
            vec![
                ("42".to_string(), "Anna (@anna)".to_string()),
                ("-100123".to_string(), "Family".to_string()),
                ("7".to_string(), "Bo".to_string()),
            ]
        );
        assert!(parse_telegram_chats(&json!({"ok": true})).is_empty());
    }

    #[test]
    fn suggested_topics_are_valid_and_differ() {
        let a = suggest_ntfy_topic();
        let b = suggest_ntfy_topic();
        assert_ne!(a, b);
        assert!(a.starts_with("varsto-"));
        assert_eq!(a.len(), "varsto-".len() + 20);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        let kind = ChannelKind::Ntfy {
            server: DEFAULT_NTFY.into(),
            topic: a,
            token: None,
            user: None,
            password: None,
        };
        assert!(validate_kind(&kind).is_ok());
    }

    #[test]
    fn same_message_is_sent_once_in_six_hours() {
        let mut d = Dedupe::default();
        let key = dedupe_key(&msg(Category::Storage));
        assert!(d.allow(&key, 1000));
        assert!(!d.allow(&key, 1000 + 3600));
        assert!(!d.allow(&key, 1000 + DEDUPE_SECS - 1));
        assert!(d.allow(&key, 1000 + DEDUPE_SECS));
        let other = dedupe_key(&msg(Category::Space));
        assert_ne!(key, other);
        assert!(d.allow(&other, 1000 + DEDUPE_SECS));
    }

    #[test]
    fn rate_cap_holds_back_and_reports() {
        let mut r = RateCap::default();
        for i in 0..RATE_MAX {
            assert!(r.allow(100 + i as i64), "message {i}");
        }
        assert!(!r.allow(200));
        assert!(!r.allow(201));
        // No room yet, so no notice.
        assert_eq!(r.take_suppressed(300), None);
        // An hour after the first messages there is room.
        assert_eq!(r.take_suppressed(100 + RATE_WINDOW_SECS + 30), Some(2));
        assert_eq!(r.take_suppressed(100 + RATE_WINDOW_SECS + 31), None);
        assert!(r.allow(100 + RATE_WINDOW_SECS + 32));
    }

    #[test]
    fn retry_backoff_grows_to_half_an_hour() {
        assert_eq!(backoff_secs(1), 30);
        assert_eq!(backoff_secs(2), 60);
        assert_eq!(backoff_secs(3), 120);
        assert_eq!(backoff_secs(7), 1800);
        assert_eq!(backoff_secs(50), 1800);
    }

    fn entry(created: i64) -> Entry {
        Entry {
            channel: "c".into(),
            category: Category::Storage,
            title: "t".into(),
            body: format!("b{created}"),
            created,
            tries: 0,
            next_try: created,
        }
    }

    #[test]
    fn outbox_drops_old_and_keeps_the_newest_hundred() {
        let now = 1_000_000;
        let mut v = vec![entry(now - OUTBOX_MAX_AGE_SECS - 1), entry(now - 10)];
        trim_outbox(&mut v, now);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].created, now - 10);

        let mut many: Vec<Entry> = (0..150).map(|i| entry(now - 1000 + i)).collect();
        trim_outbox(&mut many, now);
        assert_eq!(many.len(), OUTBOX_MAX);
        assert_eq!(many[0].created, now - 1000 + 50);
        assert_eq!(many.last().unwrap().created, now - 1000 + 149);
    }

    #[test]
    fn outbox_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let f = OutboxFile {
            entries: vec![entry(5)],
            history: vec![(7, Category::Space)],
            summary_day: Some(19_000),
        };
        let path = dir.path().join(OUTBOX_FILE);
        util::write_json(&path, &f).unwrap();
        let back: OutboxFile = util::read_json(&path).unwrap();
        assert_eq!(back.entries, f.entries);
        assert_eq!(back.history, f.history);
        assert_eq!(back.summary_day, Some(19_000));
    }

    #[test]
    fn summary_counts_alerts_of_the_last_day() {
        let now = 1_000_000;
        assert!(summary_text(&[], now).contains("no problems"));
        let history = vec![
            (now - 100, Category::Storage),
            (now - 200, Category::Storage),
            (now - 300, Category::Space),
            (now - 400, Category::Disks),
            (now - 25 * 3600, Category::Integrity),
        ];
        let text = summary_text(&history, now);
        assert!(text.contains("3 alerts"), "{text}");
        assert!(text.contains("storage problems 2"));
        assert!(text.contains("low disk space 1"));
        assert!(!text.contains("damaged"));
        let one = summary_text(&[(now - 5, Category::Space)], now);
        assert!(one.contains("1 alert "));
    }

    #[test]
    fn local_day_and_hour() {
        // 2026-01-01 00:00 UTC is a whole day number.
        let midnight = 20_454 * 86_400;
        assert_eq!(local_day_hour(midnight + 9 * 3600, 0), (20_454, 9));
        // Two hours east of UTC: 23:00 UTC is 01:00 the next day.
        assert_eq!(local_day_hour(midnight + 23 * 3600, 7200), (20_455, 1));
        // Five hours west.
        assert_eq!(local_day_hour(midnight + 3600, -5 * 3600), (20_453, 20));
    }

    #[test]
    fn categories_have_unique_ids_and_text() {
        let mut seen = BTreeSet::new();
        for c in Category::ALL {
            assert!(seen.insert(c.id()), "duplicate {}", c.id());
            assert_eq!(Category::from_id(c.id()), Some(c));
            assert!(!c.title().is_empty());
            assert!(!c.description().is_empty());
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.id()));
        }
        assert_eq!(Category::from_id("nope"), None);
        assert!(Category::Storage.default_on());
        assert!(!Category::DailySummary.default_on());
        assert_eq!(Category::Updates.level(), Level::Info);
        assert_eq!(Category::Requests.level(), Level::Alert);
    }
}
