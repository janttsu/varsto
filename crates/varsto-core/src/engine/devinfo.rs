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
    /// `linux`, `macos`, `windows`, `android` or `ios` (`org::platform_id`):
    /// what an organization's platform policy is checked against.
    #[serde(default)]
    pub platform: String,
    /// The device's own signature over the rest (section 56): a holder of
    /// the vault key cannot speak for another device.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig_alg: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig_hex: String,
}

impl DeviceDetails {
    fn message(&self, vault: &VaultId) -> Result<Vec<u8>> {
        let unsigned = DeviceDetails {
            sig_alg: String::new(),
            sig_hex: String::new(),
            ..self.clone()
        };
        Ok(crypto::aad(
            "device-details-signature",
            &[vault.as_str().as_bytes(), &serde_json::to_vec(&unsigned)?],
        ))
    }
    fn sign(&mut self, vault: &VaultId, signer: &crypto::SigningKey) -> Result<()> {
        self.sig_alg = signer.alg().to_string();
        self.sig_hex = String::new();
        self.sig_hex = hex::encode(signer.sign(&self.message(vault)?));
        Ok(())
    }
    /// Whether the device whose key is `pk` signed these details.
    pub fn verify(&self, vault: &VaultId, pk: &crypto::VerifyingKey) -> bool {
        let Ok(sig) = hex::decode(&self.sig_hex) else {
            return false;
        };
        self.message(vault)
            .is_ok_and(|m| pk.verify(&self.sig_alg, &m, &sig).is_ok())
    }
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
        let (mut os, os_version, model) = this_system();
        let platform = self.this_platform();
        if crate::org::platform_id(&os) != platform {
            os = crate::org::platform_name(&platform);
        }
        let now = util::now_utc();
        let mut details = DeviceDetails {
            device: me.clone(),
            os,
            os_version,
            model,
            arch: std::env::consts::ARCH.to_string(),
            app_version: self.this_app_version(),
            updated_utc: now,
            last_sync_utc,
            platform,
            sig_alg: String::new(),
            sig_hex: String::new(),
        };
        let path = self.home.join("devinfo.json");
        if let Ok(prev) = util::read_json_or_default::<DeviceDetails>(&path) {
            let same = DeviceDetails {
                updated_utc: prev.updated_utc,
                last_sync_utc: prev.last_sync_utc,
                sig_alg: prev.sig_alg.clone(),
                sig_hex: prev.sig_hex.clone(),
                ..details.clone()
            } == prev
                && !prev.sig_hex.is_empty();
            if same && now - prev.updated_utc < REFRESH_SECS {
                return Ok(());
            }
        }
        details.updated_utc = now;
        details.sign(&self.vault.vault_id, &self.keys.signer)?;
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

    /// Publish this device's details when they changed or got old, keeping
    /// the last sync time the service recorded.
    pub fn refresh_device_details(&mut self) -> Result<()> {
        let prev: DeviceDetails =
            util::read_json_or_default(&self.home.join("devinfo.json")).unwrap_or_default();
        self.publish_device_details(prev.last_sync_utc)
    }

    /// Tests: what a holder of the vault key could do, publish details in
    /// the name of another device (signed by this one). Readers must ignore
    /// them.
    #[doc(hidden)]
    pub fn forge_device_details_for_tests(
        &mut self,
        device: &DeviceId,
        platform: &str,
    ) -> Result<()> {
        let now = util::now_utc() + 1;
        let mut d = DeviceDetails {
            device: device.to_string(),
            os: crate::org::platform_name(platform),
            app_version: self.this_app_version(),
            updated_utc: now,
            platform: crate::org::platform_id(platform),
            ..Default::default()
        };
        d.sign(&self.vault.vault_id, &self.keys.signer)?;
        let blob = crypto::encrypt(
            &self.registry_key_now(),
            &aad(&self.vault.vault_id, device.as_str()),
            &serde_json::to_vec(&d)?,
        )?;
        let key = format!("{PREFIX}{device}/{now:020}.enc");
        for (_, backend) in self.metadata_storages(true)? {
            backend.put_if_absent(&key, &blob)?;
        }
        Ok(())
    }

    /// Read the other devices' newest details (part of the registry pull).
    pub(super) fn pull_device_details(&mut self) -> Result<bool> {
        let keys: Vec<SecretKey> = self.registry_keys().into_iter().map(|(_, k)| k).collect();
        let mut changed = false;
        for (_, backend) in self.metadata_storages(false)? {
            let mut by_device: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for key in backend.list(PREFIX)? {
                if let Some((dev, _)) = key.strip_prefix(PREFIX).and_then(|r| r.split_once('/')) {
                    by_device
                        .entry(dev.to_string())
                        .or_default()
                        .push(key.clone());
                }
            }
            for (dev, mut names) in by_device {
                let Ok(id) = DeviceId::from_hex(&dev) else {
                    continue;
                };
                if id == self.vault.device_id {
                    continue;
                }
                // Only details the device itself signed count (an
                // organization's platform policy is checked against them):
                // newest first, past records anyone else planted there.
                let Some(pk) = self
                    .device_key(&id)
                    .or_else(|| self.devices.members.get(&id).and_then(|r| r.pubkey().ok()))
                else {
                    continue;
                };
                names.sort();
                for key in names.iter().rev().take(16) {
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
                        break;
                    }
                    let Some(blob) = backend.get(key)? else {
                        continue;
                    };
                    let opened = keys.iter().find_map(|k| {
                        crypto::decrypt(k, &aad(&self.vault.vault_id, &dev), &blob)
                            .ok()
                            .and_then(|p| serde_json::from_slice::<DeviceDetails>(&p).ok())
                    });
                    if let Some(d) =
                        opened.filter(|d| d.device == dev && d.verify(&self.vault.vault_id, &pk))
                    {
                        self.devices.details.insert(id, d);
                        changed = true;
                        break;
                    }
                }
            }
        }
        Ok(changed)
    }

    /// Details of a device, if it has published any.
    pub fn device_details(&self, device: &DeviceId) -> Option<&DeviceDetails> {
        self.devices.details.get(device)
    }

    /// This device's platform (`org::platform_id`).
    pub fn this_platform(&self) -> String {
        self.platform_override
            .clone()
            .unwrap_or_else(crate::org::this_platform)
    }

    /// The Varsto version this device runs.
    pub fn this_app_version(&self) -> String {
        self.version_override
            .clone()
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
    }

    /// Tests: behave as a device on another platform or version.
    #[doc(hidden)]
    pub fn set_platform_for_tests(&mut self, platform: &str, version: Option<&str>) {
        self.platform_override = Some(crate::org::platform_id(platform));
        self.version_override = version.map(|v| v.to_string());
    }
}
