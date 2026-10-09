// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Device details for the device list: system, version and when each device
//! last synced. Every device publishes its own small record, sealed under the
//! registry key like the device records, at
//! `vault/devinfo/<device>/<utc>.enc`; the newest per device wins and a
//! device deletes its older ones. Nothing here is needed for syncing.

use super::*;

const PREFIX: &str = "vault/devinfo/";
/// Republish at least this often, so "last seen" stays meaningful.
const REFRESH_SECS: i64 = 6 * 3600;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct DeviceDetails {
    pub device: String,
    /// "Linux", "macOS", "Windows", "Android", "iOS".
    pub os: String,
    /// Release, e.g. "Arch Linux (kernel 6.11)", "15.1", "15".
    pub os_version: String,
    #[serde(default)]
    pub model: String,
    pub arch: String,
    pub app_version: String,
    pub updated_utc: i64,
    #[serde(default)]
    pub last_sync_utc: Option<i64>,
}

fn aad(vault: &VaultId, device: &str) -> Vec<u8> {
    crypto::aad(
        "device-details",
        &[vault.as_str().as_bytes(), device.as_bytes()],
    )
}

fn command_line(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

/// This device's system. Mobile shells pass theirs in VARSTO_OS,
/// VARSTO_OS_VERSION and VARSTO_DEVICE_MODEL.
fn this_system() -> (String, String, String) {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    if let Some(os) = env("VARSTO_OS") {
        return (
            os,
            env("VARSTO_OS_VERSION").unwrap_or_default(),
            env("VARSTO_DEVICE_MODEL").unwrap_or_default(),
        );
    }
    match std::env::consts::OS {
        "linux" => {
            let pretty = fs::read_to_string("/etc/os-release")
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                        .map(|v| v.trim_matches('"').to_string())
                })
                .unwrap_or_else(|| "Linux".into());
            let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|k| k.trim().to_string())
                .unwrap_or_default();
            (
                "Linux".into(),
                format!("{pretty}, kernel {kernel}"),
                String::new(),
            )
        }
        "macos" => (
            "macOS".into(),
            command_line("sw_vers", &["-productVersion"]).unwrap_or_default(),
            command_line("sysctl", &["-n", "hw.model"]).unwrap_or_default(),
        ),
        "windows" => {
            // "Microsoft Windows [Version 10.0.26100.2033]"
            let v = command_line("cmd", &["/C", "ver"])
                .and_then(|s| {
                    s.split("Version ")
                        .nth(1)
                        .map(|r| r.trim_end_matches(']').to_string())
                })
                .unwrap_or_default();
            ("Windows".into(), v, String::new())
        }
        other => (other.to_string(), String::new(), String::new()),
    }
}

impl Engine {
    /// Publish this device's details when they changed or got old.
    pub fn publish_device_details(&mut self, last_sync_utc: Option<i64>) -> Result<()> {
        if self.vault.member {
            return Ok(());
        }
        let me = self.vault.device_id.to_string();
        let (os, os_version, model) = this_system();
        let now = util::now_utc();
        let mut details = DeviceDetails {
            device: me.clone(),
            os,
            os_version,
            model,
            arch: std::env::consts::ARCH.to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            updated_utc: now,
            last_sync_utc,
        };
        let path = self.home.join("devinfo.json");
        if let Ok(prev) = util::read_json_or_default::<DeviceDetails>(&path) {
            let same = DeviceDetails {
                updated_utc: prev.updated_utc,
                last_sync_utc: prev.last_sync_utc,
                ..details.clone()
            } == prev;
            if same && now - prev.updated_utc < REFRESH_SECS {
                return Ok(());
            }
        }
        let blob = crypto::encrypt(
            &self.registry_key_now(),
            &aad(&self.vault.vault_id, &me),
            &serde_json::to_vec(&details)?,
        )?;
        let key = format!("{PREFIX}{me}/{now:020}.enc");
        for (_, backend) in self.metadata_storages(false)? {
            backend.put_if_absent(&key, &blob)?;
            for old in backend.list(&format!("{PREFIX}{me}/"))? {
                if old != key {
                    let _ = backend.delete(&old);
                }
            }
        }
        details.updated_utc = now;
        util::write_json(&path, &details)?;
        self.devices
            .details
            .insert(self.vault.device_id.clone(), details);
        self.save_devices()
    }

    /// Read the other devices' newest details (part of the registry pull).
    pub(super) fn pull_device_details(&mut self) -> Result<bool> {
        let keys: Vec<SecretKey> = self.registry_keys().into_iter().map(|(_, k)| k).collect();
        let mut changed = false;
        for (_, backend) in self.metadata_storages(false)? {
            let mut newest: BTreeMap<String, String> = BTreeMap::new();
            for key in backend.list(PREFIX)? {
                if let Some((dev, _)) = key.strip_prefix(PREFIX).and_then(|r| r.split_once('/')) {
                    let e = newest.entry(dev.to_string()).or_default();
                    if key > *e {
                        *e = key.clone();
                    }
                }
            }
            for (dev, key) in newest {
                let Ok(id) = DeviceId::from_hex(&dev) else {
                    continue;
                };
                if id == self.vault.device_id {
                    continue;
                }
                let stamp: i64 = key
                    .rsplit('/')
                    .next()
                    .and_then(|n| n.strip_suffix(".enc"))
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                if self
                    .devices
                    .details
                    .get(&id)
                    .is_some_and(|d| d.updated_utc >= stamp)
                {
                    continue;
                }
                let Some(blob) = backend.get(&key)? else {
                    continue;
                };
                let opened = keys.iter().find_map(|k| {
                    crypto::decrypt(k, &aad(&self.vault.vault_id, &dev), &blob)
                        .ok()
                        .and_then(|p| serde_json::from_slice::<DeviceDetails>(&p).ok())
                });
                if let Some(mut d) = opened.filter(|d| d.device == dev) {
                    d.updated_utc = d.updated_utc.max(stamp);
                    self.devices.details.insert(id, d);
                    changed = true;
                }
            }
        }
        Ok(changed)
    }

    /// Details of a device, if it has published any.
    pub fn device_details(&self, device: &DeviceId) -> Option<&DeviceDetails> {
        self.devices.details.get(device)
    }
}
