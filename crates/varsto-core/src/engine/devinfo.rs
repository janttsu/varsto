// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Device details for the device list: system, version and when each device
//! last synced. Format 3 (`docs/spec/format-3-design.md` section 5, "Kinds
//! and rules of the switch"): they are a field of the device's own `device`
//! record (`membership3::DeviceDetails`), signed by the K6 the record
//! carries, so no holder of the vault key speaks for another device; a
//! device writes its next record when they change, and at least every six
//! hours while it syncs. Nothing here is needed for syncing.

use super::*;

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
}

impl DeviceDetails {
    /// The details a device record carries, for the device list.
    pub(super) fn of_record(
        device: &DeviceId,
        d: &crate::membership3::devices::DeviceDetails,
    ) -> Self {
        DeviceDetails {
            device: device.to_string(),
            os: d.os.clone(),
            os_version: d.os_version.clone(),
            model: d.model.clone(),
            arch: d.arch.clone(),
            app_version: d.app_version.clone(),
            updated_utc: d.updated_utc,
            last_sync_utc: d.last_sync_utc,
            platform: d.platform.clone(),
        }
    }

    fn to_record(&self) -> crate::membership3::devices::DeviceDetails {
        let cut = |s: &str| {
            let mut s = s.to_string();
            while s.len() > crate::membership3::devices::MAX_DETAIL {
                s.pop();
            }
            s
        };
        crate::membership3::devices::DeviceDetails {
            os: cut(&self.os),
            os_version: cut(&self.os_version),
            model: cut(&self.model),
            arch: cut(&self.arch),
            app_version: cut(&self.app_version),
            platform: cut(&self.platform),
            updated_utc: self.updated_utc,
            last_sync_utc: self.last_sync_utc,
        }
    }
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
    /// Publish this device's details in its device record when they
    /// changed, or when the last record is older than six hours.
    pub fn publish_device_details(&mut self, last_sync_utc: Option<i64>) -> Result<()> {
        if self.vault.member {
            return Ok(());
        }
        let me = self.vault.device_id.clone();
        let (mut os, os_version, model) = this_system();
        let platform = self.this_platform();
        if crate::org::platform_id(&os) != platform {
            os = crate::org::platform_name(&platform);
        }
        let now = util::now_utc();
        let mut details = DeviceDetails {
            device: me.to_string(),
            os,
            os_version,
            model,
            arch: std::env::consts::ARCH.to_string(),
            app_version: self.this_app_version(),
            updated_utc: now,
            last_sync_utc,
            platform,
        };
        let path = self.home.join("devinfo.json");
        if let Ok(prev) = util::read_json_or_default::<DeviceDetails>(&path) {
            let same = DeviceDetails {
                updated_utc: prev.updated_utc,
                last_sync_utc: prev.last_sync_utc,
                ..details.clone()
            } == prev;
            let published = self
                .f3
                .members
                .devices
                .get(&self.me3())
                .and_then(|r| r.details.as_ref())
                .is_some_and(|d| d.updated_utc == prev.updated_utc);
            if same && published && now - prev.updated_utc < REFRESH_SECS {
                return Ok(());
            }
        }
        details.updated_utc = now;
        let name = self.vault.device_name.clone();
        let rec = details.to_record();
        if self
            .with_members3(|m| m.enrol_with(&name, Some(rec)))?
            .is_none()
        {
            return Ok(());
        }
        util::write_json(&path, &details)?;
        self.devices.details.insert(me, details);
        self.save_devices()
    }

    pub fn refresh_device_details(&mut self) -> Result<()> {
        let prev: DeviceDetails =
            util::read_json_or_default(&self.home.join("devinfo.json")).unwrap_or_default();
        self.publish_device_details(prev.last_sync_utc)
    }

    /// Tests: what a holder of the vault key could try, a device record
    /// with details for another device, signed with this device's K6. Its
    /// id is not the BLAKE3 of the key it carries, so every reader refuses
    /// it.
    #[doc(hidden)]
    pub fn forge_device_details_for_tests(
        &mut self,
        device: &DeviceId,
        platform: &str,
    ) -> Result<()> {
        let now = util::now_utc() + 1;
        let target = members3::bin(device)?;
        let details = DeviceDetails {
            device: device.to_string(),
            os: crate::org::platform_name(platform),
            app_version: self.this_app_version(),
            updated_utc: now,
            platform: crate::org::platform_id(platform),
            ..Default::default()
        }
        .to_record();
        let kem = self
            .epochs
            .kem
            .as_ref()
            .map(|k| k.public().to_bytes())
            .unwrap_or_default();
        let rec = crate::membership3::DeviceRecord {
            device: target,
            name: self.device_name(device),
            sign_pub: self.keys.signer.public().to_bytes(),
            kem_pub: kem,
            stamp: crate::membership3::Stamp {
                lamport: self.clock.lamport + 1_000,
                device: target,
            },
            details: Some(details),
        };
        let vault = members3::bin(&self.vault.vault_id)?;
        let keys = self.vault_keys3();
        let ring = self.keys3(&keys);
        let key_id = crate::record::KeyId::Registry(keys.newest_epoch());
        let signer = crate::record::DeviceSigner {
            device: target,
            key: &self.keys.signer,
        };
        let writer = crate::record::RecordWriter {
            vault,
            signer: &signer,
            keys: &ring,
        };
        let stream = crate::membership3::DeviceRecord::stream(target);
        let sealed = writer.seal(&stream, 1_000_000, 1_000_000, &key_id, &rec)?;
        for (_, backend) in self.metadata_storages(true)? {
            for (name, bytes) in &sealed.parts {
                backend.put_if_absent(name, bytes)?;
            }
        }
        Ok(())
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
