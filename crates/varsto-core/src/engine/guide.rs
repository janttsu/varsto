// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The recovery package guide of this vault (`crate::recovery_guide`): the
//! inputs come from this device's configuration and keyring only. Nothing
//! is opened, downloaded or decrypted beyond what is already in memory, and
//! no secret (vault key, storage secret, password) is read.

use super::Engine;
use crate::recovery_guide::{
    self, BackupInput, FolderInput, Inputs, OrgInput, ResticInput, ResticPassword, StrongroomInput,
};
use crate::strongroom::Method;
use crate::util;
use std::path::Path;

impl Engine {
    /// The personalised, secret-free recovery package checklist and restore steps.
    pub fn recovery_guide(&self) -> recovery_guide::RecoveryGuide {
        recovery_guide::build(&self.recovery_guide_inputs())
    }

    pub fn recovery_guide_inputs(&self) -> Inputs {
        let mut inputs = Inputs {
            vault_id: self.vault.vault_id.to_string(),
            device: self.vault.device_name.clone(),
            now_utc: util::now_utc(),
            member: self.vault.member,
            key_epoch: self.key_epoch(),
            kit: recovery_guide::kit_record(&self.home),
            storages: self.config.storages.clone(),
            ..Default::default()
        };
        if let Ok(conf) = crate::diskconf::DiskConf::load(&self.home) {
            inputs.disk_conf = conf
                .drives()
                .map(|d| (d.partuuid.clone(), d.pool.clone(), d.label.clone()))
                .collect();
        }
        for (rec, path) in self.folders() {
            let mount = self
                .config
                .folders
                .iter()
                .find(|m| m.folder_id == rec.folder_id);
            inputs.folders.push(FolderInput {
                name: rec.name.clone(),
                path: path.map(|p| p.display().to_string()),
                selective: mount.is_some_and(|m| m.selective),
                strongroom: rec.is_strongroom(),
            });
            if let Some(info) = &rec.strongroom {
                let keys = self
                    .strongroom_keys(&rec.name)
                    .map(|ks| {
                        ks.into_iter()
                            .enumerate()
                            .map(|(i, k)| {
                                if !k.label.is_empty() {
                                    k.label
                                } else if !k.name.is_empty() {
                                    k.name
                                } else {
                                    format!("key {}", i + 1)
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_else(|_| vec!["key 1".to_string()]);
                inputs.strongrooms.push(StrongroomInput {
                    folder: rec.name.clone(),
                    keys,
                    software: info.method == Method::Software,
                });
            }
        }
        for rec in self.keyring.folders.values() {
            if let (Some(b), false) = (&rec.backup, rec.is_removed()) {
                inputs.backups.push(BackupInput {
                    name: rec.name.clone(),
                    source: b.source_path.clone(),
                });
            }
        }
        if let Some(o) = &self.org {
            inputs.org = Some(OrgInput {
                name: o.name.clone(),
                admins: o
                    .manifest()
                    .map(|m| m.admins.iter().map(|a| a.name.clone()).collect())
                    .unwrap_or_default(),
            });
        }
        if !self.vault.member {
            inputs.other_devices = self
                .devices_list()
                .into_iter()
                .filter(|d| !d.this_device && !d.revoked)
                .map(|d| d.name)
                .collect();
            inputs.replicas = self
                .devices
                .replicas
                .values()
                .map(|r| r.name.clone())
                .collect();
        }
        inputs.restic = restic_settings(&self.home);
        inputs
    }
}

/// The restic settings of this device, read loosely from `config.json`
/// (`restic`: repository, password, env_file) so that the guide does not
/// depend on the restic module: only the repository (without any password
/// in it) and the paths are taken.
fn restic_settings(home: &Path) -> Option<ResticInput> {
    let v: serde_json::Value = util::read_json(&home.join("config.json")).ok()?;
    let r = v.get("restic")?;
    let repository = r.get("repository")?.as_str()?;
    let password = match r.get("password") {
        Some(p) => match p.get("file").and_then(|f| f.as_str()) {
            Some(f) => ResticPassword::File(f.to_string()),
            None => ResticPassword::Command,
        },
        None => ResticPassword::Command,
    };
    Some(ResticInput {
        repository: recovery_guide::redact_repository(repository),
        password,
        env_file: r
            .get("env_file")
            .and_then(|e| e.as_str())
            .map(str::to_string),
    })
}
