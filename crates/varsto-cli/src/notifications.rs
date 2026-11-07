// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Push notification channels (ntfy, Pushover, Telegram): `varsto notify`.
//! The HTTP routes of the interface (`/api/notify/...`) are in
//! `notify_api.rs`, which the mobile shells share.
//!
//! Both edit `notify.json` in the device directory through
//! `varsto_core::notify`; a running service notices the change by the file's
//! modification time. Neither needs the vault: they work while it is locked
//! and with no service running. Secrets come in through a hidden prompt or
//! standard input, never as an argument, and never go out again: the API
//! answers with masked copies.

use crate::notify_api::{categories_json, device_name};
use crate::{confirm, print, Cli};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read};
use std::path::Path;
use varsto_core::notify::{self, Category, Channel, ChannelInput, ChannelView, NotifyConfig};

// ---------------------------------------------------------------------------
// The command line.

#[derive(Subcommand)]
pub enum NotifyCmd {
    /// List the channels: where they send, which events, with secrets masked.
    List,
    /// Add a channel: ntfy, Pushover or Telegram.
    Add {
        #[command(subcommand)]
        service: AddCmd,
    },
    /// Change a channel (its name or id). Secrets change only with the
    /// --*-stdin options: one line on standard input for each, in the order
    /// bot token, API token, access token, password.
    Edit {
        channel: String,
        #[command(flatten)]
        opts: EditArgs,
    },
    /// Remove a channel.
    Remove {
        channel: String,
        /// Do not ask.
        #[arg(long)]
        yes: bool,
    },
    /// Turn a channel on.
    Enable { channel: String },
    /// Turn a channel off without removing it.
    Disable { channel: String },
    /// Without a channel: list the kinds of events. With one: show or change
    /// what it receives.
    Events {
        channel: Option<String>,
        /// Receive these events too (comma separated, see `varsto notify events`).
        #[arg(long, value_delimiter = ',')]
        on: Vec<String>,
        /// Stop receiving these events.
        #[arg(long, value_delimiter = ',')]
        off: Vec<String>,
        /// Reset to the recommended events first.
        #[arg(long)]
        defaults: bool,
    },
    /// Whether messages name folders, storages and devices (on) or only say
    /// what kind of event it is (off). Messages pass through the service's
    /// servers unencrypted.
    Details {
        channel: String,
        /// on or off
        state: String,
    },
    /// The local hour (0 to 23) after which the daily summary is sent.
    SummaryHour { hour: u8 },
    /// Send a test message to a channel.
    Test { channel: String },
    /// List the Telegram chats that wrote to a bot (asks for the bot token).
    TelegramChats,
}

#[derive(Subcommand)]
pub enum AddCmd {
    /// ntfy (ntfy.sh or your own server): free, no account needed.
    Ntfy {
        #[arg(long)]
        name: Option<String>,
        /// The topic to publish to (default: a new hard-to-guess one).
        #[arg(long)]
        topic: Option<String>,
        /// Your own ntfy server (default https://ntfy.sh).
        #[arg(long)]
        server: Option<String>,
        /// Read an access token from standard input.
        #[arg(long)]
        token_stdin: bool,
        /// User name for a server with logins.
        #[arg(long)]
        user: Option<String>,
        /// Read the password from standard input.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Pushover: an app on the phone, one-time purchase after a 30-day trial.
    Pushover {
        #[arg(long)]
        name: Option<String>,
        /// Your user key, shown at the top of pushover.net.
        #[arg(long)]
        user_key: String,
        /// Send to this device only.
        #[arg(long)]
        device: Option<String>,
        /// Read the API token of your application from standard input
        /// (otherwise it is asked for without echo).
        #[arg(long)]
        app_token_stdin: bool,
    },
    /// Telegram: messages from your own bot.
    Telegram {
        #[arg(long)]
        name: Option<String>,
        /// The chat to send to (a number, or @name). Without it the chats
        /// that wrote to the bot are listed to pick from.
        #[arg(long)]
        chat_id: Option<String>,
        /// Read the bot token from standard input (otherwise it is asked
        /// for without echo).
        #[arg(long)]
        bot_token_stdin: bool,
    },
}

/// The options of `notify edit`; each applies to the services it names.
#[derive(Args, Default)]
pub struct EditArgs {
    #[arg(long)]
    name: Option<String>,
    /// ntfy: the topic.
    #[arg(long)]
    topic: Option<String>,
    /// ntfy: the server address.
    #[arg(long)]
    server: Option<String>,
    /// ntfy: the user name.
    #[arg(long)]
    user: Option<String>,
    /// ntfy: remove the access token, user name and password.
    #[arg(long)]
    clear_auth: bool,
    /// Pushover: the user key.
    #[arg(long)]
    user_key: Option<String>,
    /// Pushover: the device name (empty: all devices).
    #[arg(long)]
    device: Option<String>,
    /// Telegram: the chat id.
    #[arg(long)]
    chat_id: Option<String>,
    /// Telegram: read a new bot token from standard input.
    #[arg(long)]
    bot_token_stdin: bool,
    /// Pushover: read a new API token from standard input.
    #[arg(long)]
    app_token_stdin: bool,
    /// ntfy: read a new access token from standard input.
    #[arg(long)]
    token_stdin: bool,
    /// ntfy: read a new password from standard input.
    #[arg(long)]
    password_stdin: bool,
}

/// One line of standard input per secret asked with a `--*-stdin` option.
struct StdinSecrets {
    lines: Option<std::vec::IntoIter<String>>,
}

impl StdinSecrets {
    fn new(needed: bool) -> Result<StdinSecrets> {
        if !needed {
            return Ok(StdinSecrets { lines: None });
        }
        let mut text = String::new();
        std::io::stdin()
            .lock()
            .take(64 * 1024)
            .read_to_string(&mut text)
            .context("read standard input")?;
        let lines: Vec<String> = text.lines().map(|l| l.trim().to_string()).collect();
        Ok(StdinSecrets {
            lines: Some(lines.into_iter()),
        })
    }

    /// The next line, as the secret called `what`.
    fn next(&mut self, what: &str) -> Result<String> {
        let line = self
            .lines
            .as_mut()
            .and_then(|l| l.next())
            .filter(|l| !l.is_empty())
            .ok_or_else(|| anyhow!("standard input has no line for {what}"))?;
        varsto_core::logging::register_secret(&line);
        Ok(line)
    }
}

/// A secret typed on the terminal without echo.
fn prompt_secret(prompt: &str, option: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("no terminal to ask on: pass {option} and send the secret on standard input");
    }
    let s = rpassword::prompt_password(prompt).context("read the secret")?;
    let s = s.trim().to_string();
    if s.is_empty() {
        bail!("nothing was typed");
    }
    varsto_core::logging::register_secret(&s);
    Ok(s)
}

fn find<'a>(cfg: &'a NotifyConfig, key: &str) -> Result<&'a Channel> {
    cfg.find(key)
        .map(|i| &cfg.channels[i])
        .ok_or_else(|| anyhow!("no channel {key:?}; see `varsto notify list`"))
}

/// Print a one-line result, or the JSON for scripts.
fn done(cli: &Cli, line: String, value: Value) -> Result<()> {
    print(cli, &value, |_| line)
}

fn secret_text(s: &Option<notify::Secret>) -> String {
    match s {
        Some(s) if s.set => format!("set ({})", s.hint),
        _ => "not set".to_string(),
    }
}

fn target_line(v: &ChannelView) -> String {
    match v.service {
        "ntfy" => {
            let mut s = format!(
                "{}/{}",
                v.server.as_deref().unwrap_or(""),
                v.topic.as_deref().unwrap_or("")
            );
            if v.token.is_some() {
                s += &format!("; access token {}", secret_text(&v.token));
            } else if let Some(u) = &v.user {
                s += &format!("; user {u}, password {}", secret_text(&v.password));
            }
            s
        }
        "pushover" => {
            let mut s = format!(
                "user key {}, API token {}",
                secret_text(&v.user_key),
                secret_text(&v.app_token)
            );
            if let Some(d) = &v.device {
                s += &format!(", device {d}");
            }
            s
        }
        _ => format!(
            "chat {}, bot token {}",
            v.chat_id.as_deref().unwrap_or(""),
            secret_text(&v.bot_token)
        ),
    }
}

fn list_text(cfg: &NotifyConfig) -> String {
    if cfg.channels.is_empty() {
        return "No notification channels.\nAdd one: varsto notify add ntfy (or pushover, telegram)"
            .to_string();
    }
    let mut out = String::new();
    for c in &cfg.channels {
        let v = c.view();
        out += &format!(
            "{}  {}  [{}, {}]\n",
            c.id,
            c.name,
            c.kind.service_title(),
            if c.enabled { "on" } else { "off" }
        );
        out += &format!("    sends to: {}\n", target_line(&v));
        let events: Vec<&str> = c.events.iter().map(|e| e.id()).collect();
        out += &format!(
            "    events ({}): {}\n",
            events.len(),
            if events.is_empty() {
                "none".to_string()
            } else {
                events.join(", ")
            }
        );
        out += &format!(
            "    names of folders, storages and devices in messages: {}\n",
            if c.details { "yes" } else { "no" }
        );
    }
    out += &format!(
        "Daily summary: after {:02}:00 local time, to channels with daily_summary.",
        cfg.summary_hour
    );
    out
}

fn events_text() -> String {
    let mut out = String::new();
    for c in Category::ALL {
        out += &format!(
            "{:<14} {:<6} {}  {}\n",
            c.id(),
            if c.level() == notify::Level::Alert {
                "alert"
            } else {
                "info"
            },
            if c.default_on() {
                "on by default "
            } else {
                "off by default"
            },
            c.description()
        );
    }
    out.trim_end().to_string()
}

fn parse_events(list: &[String]) -> Result<Vec<Category>> {
    list.iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            Category::from_id(s).ok_or_else(|| {
                anyhow!("unknown event {s:?}; see `varsto notify events` for the names")
            })
        })
        .collect()
}

fn save_and_report(
    cli: &Cli,
    home: &Path,
    cfg: &NotifyConfig,
    ch: &Channel,
    verb: &str,
    next: &str,
) -> Result<()> {
    cfg.save(home)?;
    let line = format!(
        "{verb} {} channel {:?} (id {}). {next}",
        ch.kind.service_title(),
        ch.name,
        ch.id
    );
    done(cli, line, json!({"ok": true, "channel": ch.view()}))
}

pub fn run(cli: &Cli, home: &Path, cmd: &NotifyCmd) -> Result<()> {
    match cmd {
        NotifyCmd::List => {
            let cfg = NotifyConfig::load(home)?;
            let views: Vec<ChannelView> = cfg.channels.iter().map(Channel::view).collect();
            let v = json!({"channels": views, "summary_hour": cfg.summary_hour});
            print(cli, &v, |_| list_text(&cfg))
        }
        NotifyCmd::Add { service } => add(cli, home, service),
        NotifyCmd::Edit { channel, opts } => edit(cli, home, channel, opts),
        NotifyCmd::Remove { channel, yes } => {
            let mut cfg = NotifyConfig::load(home)?;
            let name = find(&cfg, channel)?.name.clone();
            if !*yes && !confirm(&format!("Remove the channel {name:?}?"))? {
                bail!("not removed; pass --yes to remove without asking");
            }
            let ch = cfg.remove(channel)?;
            cfg.save(home)?;
            done(
                cli,
                format!(
                    "Removed channel {:?}. Run `varsto notify list` to see the rest.",
                    ch.name
                ),
                json!({"ok": true}),
            )
        }
        NotifyCmd::Enable { channel } | NotifyCmd::Disable { channel } => {
            let on = matches!(cmd, NotifyCmd::Enable { .. });
            let mut cfg = NotifyConfig::load(home)?;
            let id = find(&cfg, channel)?.id.clone();
            let ch = cfg.upsert(&ChannelInput {
                id: Some(id),
                enabled: Some(on),
                ..Default::default()
            })?;
            let next = if on {
                "Run `varsto notify test` to check it."
            } else {
                "It sends nothing until you enable it again."
            };
            save_and_report(
                cli,
                home,
                &cfg,
                &ch,
                if on { "Enabled" } else { "Disabled" },
                next,
            )
        }
        NotifyCmd::Events { channel: None, .. } => {
            print(cli, &json!({"events": categories_json()}), |_| {
                events_text()
            })
        }
        NotifyCmd::Events {
            channel: Some(channel),
            on,
            off,
            defaults,
        } => {
            let mut cfg = NotifyConfig::load(home)?;
            let cur = find(&cfg, channel)?.clone();
            let (add, remove) = (parse_events(on)?, parse_events(off)?);
            if !*defaults && add.is_empty() && remove.is_empty() {
                let names: Vec<&str> = cur.events.iter().map(|e| e.id()).collect();
                return done(
                    cli,
                    format!("{} receives: {}", cur.name, names.join(", ")),
                    json!({"events": cur.events}),
                );
            }
            let mut set = if *defaults {
                Category::defaults()
            } else {
                cur.events.clone()
            };
            set.extend(add);
            for c in remove {
                set.remove(&c);
            }
            let ch = cfg.upsert(&ChannelInput {
                id: Some(cur.id),
                events: Some(set.into_iter().collect()),
                ..Default::default()
            })?;
            let next = format!(
                "{} events. Try `varsto notify test {:?}`.",
                ch.events.len(),
                ch.name
            );
            save_and_report(cli, home, &cfg, &ch, "Updated", &next)
        }
        NotifyCmd::Details { channel, state } => {
            let on = match state.trim().to_lowercase().as_str() {
                "on" | "yes" => true,
                "off" | "no" => false,
                other => bail!("details is on or off, not {other:?}"),
            };
            let mut cfg = NotifyConfig::load(home)?;
            let id = find(&cfg, channel)?.id.clone();
            let ch = cfg.upsert(&ChannelInput {
                id: Some(id),
                details: Some(on),
                ..Default::default()
            })?;
            let next = if on {
                "Messages name folders, storages and devices."
            } else {
                "Messages only say what kind of event it is."
            };
            save_and_report(cli, home, &cfg, &ch, "Updated", next)
        }
        NotifyCmd::SummaryHour { hour } => {
            let mut cfg = NotifyConfig::load(home)?;
            cfg.set_summary_hour(*hour)?;
            cfg.save(home)?;
            done(
                cli,
                format!(
                    "The daily summary goes out after {hour:02}:00 local time. Turn it on for a channel with `varsto notify events CHANNEL --on daily_summary`."
                ),
                json!({"ok": true, "summary_hour": hour}),
            )
        }
        NotifyCmd::Test { channel } => {
            let cfg = NotifyConfig::load(home)?;
            let ch = find(&cfg, channel)?;
            notify::send_test(&ch.kind, &device_name())?;
            done(
                cli,
                format!(
                    "Test message sent to {:?}. Check your phone; if nothing came, see docs/notifications.md.",
                    ch.name
                ),
                json!({"ok": true}),
            )
        }
        NotifyCmd::TelegramChats => {
            let token = prompt_secret("Telegram bot token: ", "--bot-token-stdin")?;
            let chats = notify::telegram_chats(&token)?;
            print_chats(cli, &chats)
        }
    }
}

fn print_chats(cli: &Cli, chats: &[(String, String)]) -> Result<()> {
    let v = json!({"chats": chats.iter().map(|(id, label)| json!({"id": id, "label": label})).collect::<Vec<_>>()});
    print(cli, &v, |_| {
        if chats.is_empty() {
            "No chats yet. Send a message to your bot in Telegram, then run this again.".to_string()
        } else {
            chats
                .iter()
                .map(|(id, label)| format!("{id}  {label}"))
                .collect::<Vec<_>>()
                .join("\n")
        }
    })
}

fn add(cli: &Cli, home: &Path, service: &AddCmd) -> Result<()> {
    let mut cfg = NotifyConfig::load(home)?;
    let (input, next): (ChannelInput, String) = match service {
        AddCmd::Ntfy {
            name,
            topic,
            server,
            token_stdin,
            user,
            password_stdin,
        } => {
            let mut lines = StdinSecrets::new(*token_stdin || *password_stdin)?;
            let suggested = topic.is_none();
            let topic = topic.clone().unwrap_or_else(notify::suggest_ntfy_topic);
            let token = if *token_stdin {
                Some(lines.next("the access token")?)
            } else {
                None
            };
            let password = if *password_stdin {
                Some(lines.next("the password")?)
            } else {
                None
            };
            let next = format!(
                "Subscribe to the topic {topic} in the ntfy app{}, then run `varsto notify test`.",
                if suggested {
                    " (anyone who knows a topic on ntfy.sh can read it, so keep it to yourself)"
                } else {
                    ""
                }
            );
            (
                ChannelInput {
                    service: "ntfy".into(),
                    name: name.clone(),
                    server: server.clone(),
                    topic: Some(topic),
                    token,
                    user: user.clone(),
                    password,
                    ..Default::default()
                },
                next,
            )
        }
        AddCmd::Pushover {
            name,
            user_key,
            device,
            app_token_stdin,
        } => {
            let app_token = if *app_token_stdin {
                StdinSecrets::new(true)?.next("the API token")?
            } else {
                prompt_secret(
                    "Pushover API token of your application: ",
                    "--app-token-stdin",
                )?
            };
            // A wrong key is worth a warning, but the channel is kept: the
            // network may simply be down.
            if let Err(e) = notify::pushover_validate(user_key, &app_token) {
                eprintln!("warning: could not check the keys with Pushover: {e:#}");
            }
            (
                ChannelInput {
                    service: "pushover".into(),
                    name: name.clone(),
                    user_key: Some(user_key.clone()),
                    app_token: Some(app_token),
                    device: device.clone(),
                    ..Default::default()
                },
                "Run `varsto notify test` to check it.".to_string(),
            )
        }
        AddCmd::Telegram {
            name,
            chat_id,
            bot_token_stdin,
        } => {
            let bot_token = if *bot_token_stdin {
                StdinSecrets::new(true)?.next("the bot token")?
            } else {
                prompt_secret(
                    "Telegram bot token (from @BotFather): ",
                    "--bot-token-stdin",
                )?
            };
            let chat = match chat_id {
                Some(c) => c.clone(),
                None => pick_chat(&bot_token)?,
            };
            (
                ChannelInput {
                    service: "telegram".into(),
                    name: name.clone(),
                    bot_token: Some(bot_token),
                    chat_id: Some(chat),
                    ..Default::default()
                },
                "Run `varsto notify test` to check it.".to_string(),
            )
        }
    };
    let ch = cfg.upsert(&input)?;
    save_and_report(cli, home, &cfg, &ch, "Added", &next)
}

/// Let the person choose among the chats that wrote to the bot.
fn pick_chat(bot_token: &str) -> Result<String> {
    let chats = notify::telegram_chats(bot_token)?;
    if chats.is_empty() {
        bail!("the bot has no messages yet: send a message to your bot in Telegram (press Start), then run this again");
    }
    let terminal = std::io::stdin().is_terminal();
    if !terminal {
        if chats.len() == 1 {
            return Ok(chats[0].0.clone());
        }
        bail!(
            "several chats wrote to the bot; pass --chat-id (see `varsto notify telegram-chats`)"
        );
    }
    for (i, (id, label)) in chats.iter().enumerate() {
        eprintln!("  {}) {label}  ({id})", i + 1);
    }
    eprint!("Which chat? [1] ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let n: usize = match line.trim() {
        "" => 1,
        t => t
            .parse()
            .map_err(|_| anyhow!("type the number of a chat"))?,
    };
    chats
        .get(n.wrapping_sub(1))
        .map(|(id, _)| id.clone())
        .ok_or_else(|| anyhow!("there is no chat number {n}"))
}

fn edit(cli: &Cli, home: &Path, channel: &str, o: &EditArgs) -> Result<()> {
    let mut cfg = NotifyConfig::load(home)?;
    let cur = find(&cfg, channel)?.clone();
    let wanted = [
        o.bot_token_stdin,
        o.app_token_stdin,
        o.token_stdin,
        o.password_stdin,
    ];
    let mut lines = StdinSecrets::new(wanted.iter().any(|w| *w))?;
    let mut input = ChannelInput {
        id: Some(cur.id.clone()),
        name: o.name.clone(),
        topic: o.topic.clone(),
        server: o.server.clone(),
        user: o.user.clone(),
        clear_auth: Some(o.clear_auth),
        user_key: o.user_key.clone(),
        device: o.device.clone(),
        chat_id: o.chat_id.clone(),
        ..Default::default()
    };
    if o.bot_token_stdin {
        input.bot_token = Some(lines.next("the bot token")?);
    }
    if o.app_token_stdin {
        input.app_token = Some(lines.next("the API token")?);
    }
    if o.token_stdin {
        input.token = Some(lines.next("the access token")?);
    }
    if o.password_stdin {
        input.password = Some(lines.next("the password")?);
    }
    let ch = cfg.upsert(&input)?;
    save_and_report(
        cli,
        home,
        &cfg,
        &ch,
        "Updated",
        "A running service uses it at once; `varsto notify test` checks it.",
    )
}
