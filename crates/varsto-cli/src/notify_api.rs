// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The HTTP routes of the push notification channels (`/api/notify/...`),
//! answered by the service without the engine: a file in the device
//! directory, so they work while the vault is locked. Shared with the
//! mobile shells (`varsto-ffi` includes this file by path); the command
//! line half is `notifications.rs`.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::path::Path;
use tiny_http::Method;
use varsto_core::notify::{
    self, Category, Channel, ChannelInput, ChannelKind, ChannelView, NotifyConfig,
};

/// The name that starts messages: the service's device name once known.
pub(crate) fn device_name() -> String {
    let n = notify::notifier().device();
    if n.is_empty() {
        crate::default_device_name()
    } else {
        n
    }
}

pub(crate) fn categories_json() -> Value {
    Value::Array(
        Category::ALL
            .iter()
            .map(|c| {
                json!({
                    "id": c.id(),
                    "title": c.title(),
                    "description": c.description(),
                    "level": c.level(),
                    "default_on": c.default_on(),
                })
            })
            .collect(),
    )
}

fn channel_input(input: &Value) -> Result<ChannelInput> {
    serde_json::from_value(input.clone()).map_err(|e| anyhow!("the channel is not valid: {e}"))
}

fn str_field<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Answer a `/api/notify...` route.
pub fn api(home: &Path, method: &Method, path: &str, input: &Value) -> Result<Value> {
    match (method, path) {
        (Method::Get, "/api/notify") => {
            let cfg = NotifyConfig::load(home)?;
            let views: Vec<ChannelView> = cfg.channels.iter().map(Channel::view).collect();
            Ok(json!({
                "channels": views,
                "status": notify::notifier().status(),
                "categories": categories_json(),
                "summary_hour": cfg.summary_hour,
                "device": device_name(),
            }))
        }
        (Method::Get, "/api/notify/ntfy-topic") => {
            Ok(json!({"topic": notify::suggest_ntfy_topic()}))
        }
        (Method::Post, "/api/notify/channel") => {
            let ci = channel_input(input)?;
            let mut cfg = NotifyConfig::load(home)?;
            let ch = cfg.upsert(&ci)?;
            cfg.save(home)?;
            Ok(json!({"ok": true, "channel": ch.view()}))
        }
        (Method::Post, "/api/notify/channel/remove") => {
            let id = str_field(input, "id").ok_or_else(|| anyhow!("the channel id is needed"))?;
            let mut cfg = NotifyConfig::load(home)?;
            cfg.remove(id)?;
            cfg.save(home)?;
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/notify/test") => {
            // A channel not saved yet, an edited one (the stored secrets
            // fill in what the page leaves empty) or a saved one by id.
            let ci = channel_input(input)?;
            let cfg = NotifyConfig::load(home)?;
            let old = match ci.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(id) => Some(
                    cfg.channels
                        .iter()
                        .find(|c| c.id == id)
                        .ok_or_else(|| anyhow!("no channel with id {id}"))?,
                ),
                None => None,
            };
            let ch = ci.resolve(old)?;
            notify::send_test(&ch.kind, &device_name())?;
            Ok(json!({"ok": true}))
        }
        (Method::Post, "/api/notify/telegram/chats") => {
            let given = str_field(input, "bot_token").map(str::to_string);
            let token = match given {
                Some(t) => t,
                None => {
                    let id =
                        str_field(input, "id").ok_or_else(|| anyhow!("the bot token is needed"))?;
                    let cfg = NotifyConfig::load(home)?;
                    let stored =
                        cfg.channels
                            .iter()
                            .find(|c| c.id == id)
                            .and_then(|c| match &c.kind {
                                ChannelKind::Telegram { bot_token, .. } => Some(bot_token.clone()),
                                _ => None,
                            });
                    stored.ok_or_else(|| anyhow!("that channel has no Telegram bot token"))?
                }
            };
            varsto_core::logging::register_secret(&token);
            let chats = notify::telegram_chats(&token)?;
            let list: Vec<Value> = chats
                .into_iter()
                .map(|(id, label)| json!({"id": id, "label": label}))
                .collect();
            Ok(json!({"chats": list}))
        }
        (Method::Post, "/api/notify/settings") => {
            let hour = input
                .get("summary_hour")
                .and_then(Value::as_u64)
                .filter(|h| *h <= 23)
                .ok_or_else(|| anyhow!("summary_hour is a number from 0 to 23"))?;
            let mut cfg = NotifyConfig::load(home)?;
            cfg.set_summary_hour(hour as u8)?;
            cfg.save(home)?;
            Ok(json!({"ok": true, "summary_hour": cfg.summary_hour}))
        }
        _ => Err(anyhow!("unknown route {path}")),
    }
}
