// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Where the vault's data is: how many bytes of the current files each
//! storage and each device holds, per folder, and how many kept copies the
//! blocks have. Read-only; computed in one pass over the ledger view and the
//! folder states, for the "Where your data is" chart.

use super::*;

/// One storage: configured on this device, or only seen in other devices'
/// claims (`configured` false), or a replica device (`kind` "replica").
#[derive(Clone, Debug, Default, Serialize)]
pub struct StorageShare {
    pub name: String,
    pub configured: bool,
    /// "directory", "s3", "rclone", "pool", "transferrer", "replica", or
    /// "unknown" for a storage this device has no specification for.
    pub kind: String,
    /// The storage's place ("home", "cloud", "offsite", ...); empty when unknown.
    pub place: String,
    pub cold: bool,
    pub carrier: bool,
    pub bytes: u64,
    pub blocks: u64,
    /// `bytes` as a share of the total (0..1; a storage holding everything is 1).
    pub share: f64,
    /// Bytes on this storage that a device other than the writer has verified.
    pub verified_bytes: u64,
    /// Monthly cost of `bytes`, when the storage price is known.
    pub monthly_cost: Option<f64>,
    #[serde(default)]
    pub currency: String,
}

/// One device holding the plaintext of blocks (as parts of its files).
#[derive(Clone, Debug, Default, Serialize)]
pub struct DeviceShare {
    pub device_id: String,
    pub name: String,
    pub this_device: bool,
    pub revoked: bool,
    pub bytes: u64,
    pub blocks: u64,
    pub share: f64,
}

/// One folder and where its bytes are.
#[derive(Clone, Debug, Default, Serialize)]
pub struct FolderShare {
    pub folder_id: String,
    pub name: String,
    /// Attached on this device. A folder this device never fetched the file
    /// list of counts with no bytes.
    pub attached: bool,
    pub bytes: u64,
    pub blocks: u64,
    /// Bytes of this folder per storage name (storages holding none are left out).
    pub storages: BTreeMap<String, u64>,
    /// Bytes of this folder per device id.
    pub devices: BTreeMap<String, u64>,
    /// Bytes with no kept copy on any storage (transferrers do not keep copies).
    pub unkept_bytes: u64,
}

/// Blocks by the number of kept copies on storages (transferrers excluded).
#[derive(Clone, Debug, Default, Serialize)]
pub struct CopyStats {
    pub none: u64,
    pub one: u64,
    pub two: u64,
    pub three_plus: u64,
    /// Bytes in each bucket, in the same order (0, 1, 2, 3+ copies).
    pub bytes: [u64; 4],
    /// Average kept copies per block, weighted by bytes.
    pub average: f64,
}

/// See `Engine::data_locations`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DataLocations {
    pub total_bytes: u64,
    pub total_blocks: u64,
    /// Largest first; configured storages without data are listed too.
    pub storages: Vec<StorageShare>,
    /// Largest first; this device is always listed.
    pub devices: Vec<DeviceShare>,
    /// Largest first.
    pub folders: Vec<FolderShare>,
    pub copies: CopyStats,
}

fn kind_label(spec: &StorageSpec) -> &'static str {
    if spec.is_carrier() {
        return "transferrer";
    }
    match spec.kind() {
        "local-dir" => "directory",
        other => other,
    }
}

fn share(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64
    }
}

impl Engine {
    /// Where the bytes of the current (not deleted) files are, per storage,
    /// device and folder, with copy counts. A block is one (folder, chunk)
    /// pair, counted once however many files use it.
    ///
    /// Sizes are those the ledger records for each block, which are the
    /// encrypted object sizes written to storages (a block only seen through
    /// a device's "holds it" event may carry that event's size instead). A
    /// block the ledger does not know yet counts with its manifest size.
    ///
    /// Storages hold a block when the ledger records a claim or a verification
    /// there (retired storages' older claims are already dropped). Other
    /// devices hold a block when they recorded holding it; for this device
    /// the files on disk decide, so freed files and placeholders do not count.
    ///
    /// Only folders whose file list this device has count (a folder never
    /// attached here shows no bytes), and a storage known only from other
    /// devices' claims counts as a kept copy even when it is their transferrer.
    pub fn data_locations(&self) -> Result<DataLocations> {
        let view = self.view()?;
        let me = self.vault.device_id.clone();
        let carriers: HashSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_carrier())
            .map(|s| s.name())
            .collect();

        let mut out = DataLocations::default();
        let mut storages: BTreeMap<String, StorageShare> = BTreeMap::new();
        for spec in &self.config.storages {
            storages.insert(
                spec.name().to_string(),
                StorageShare {
                    name: spec.name().to_string(),
                    configured: true,
                    kind: kind_label(spec).to_string(),
                    place: spec.place(),
                    cold: spec.is_cold(),
                    carrier: spec.is_carrier(),
                    ..Default::default()
                },
            );
        }
        let mut devices: BTreeMap<DeviceId, DeviceShare> = BTreeMap::new();
        let device_entry = |id: &DeviceId| -> DeviceShare {
            let name = if id == &me {
                self.vault.device_name.clone()
            } else {
                self.devices
                    .devices
                    .get(id)
                    .map(|r| r.name.clone())
                    .or_else(|| view.devices.get(id).cloned())
                    .unwrap_or_else(|| id.short().to_string())
            };
            DeviceShare {
                device_id: id.to_string(),
                name,
                this_device: id == &me,
                revoked: self.is_revoked(id),
                ..Default::default()
            }
        };
        devices.insert(me.clone(), device_entry(&me));
        let mut copy_sum = 0u128;

        for (rec, mount) in self.folders() {
            let state = self.load_state(&rec.folder_id)?;
            // Unique blocks of current files, with the manifest size as fallback.
            let mut chunks: BTreeMap<&ChunkId, u64> = BTreeMap::new();
            for f in state.files.values().filter(|f| !f.deleted) {
                for c in &f.chunks {
                    chunks.entry(&c.chunk).or_insert(c.size);
                }
            }
            let here: HashSet<&ChunkId> = match &mount {
                Some(_) => state
                    .files
                    .values()
                    .filter(|f| !f.deleted && state.local_index.contains_key(&f.path))
                    .flat_map(|f| f.chunks.iter().map(|c| &c.chunk))
                    .collect(),
                None => HashSet::new(),
            };
            let mut folder = FolderShare {
                folder_id: rec.folder_id.to_string(),
                name: rec.name.clone(),
                attached: mount.is_some(),
                ..Default::default()
            };
            for (chunk, manifest_size) in chunks {
                let record = view.locate(&rec.folder_id, chunk);
                let size = record
                    .map(|r| r.size)
                    .filter(|s| *s > 0)
                    .unwrap_or(manifest_size);
                folder.bytes += size;
                folder.blocks += 1;
                let mut kept = 0u64;
                if let Some(r) = record {
                    for (name, loc) in &r.storages {
                        let s = storages.entry(name.clone()).or_insert_with(|| {
                            let replica = name.starts_with("replica:");
                            StorageShare {
                                name: name.clone(),
                                kind: if replica { "replica" } else { "unknown" }.to_string(),
                                ..Default::default()
                            }
                        });
                        s.bytes += size;
                        s.blocks += 1;
                        if loc.independently_verified(name) {
                            s.verified_bytes += size;
                        }
                        *folder.storages.entry(name.clone()).or_default() += size;
                        if !carriers.contains(name.as_str()) {
                            kept += 1;
                        }
                    }
                    for d in r.devices.iter().filter(|d| **d != me) {
                        let e = devices.entry(d.clone()).or_insert_with(|| device_entry(d));
                        e.bytes += size;
                        e.blocks += 1;
                        *folder.devices.entry(d.to_string()).or_default() += size;
                    }
                }
                if here.contains(chunk) {
                    let e = devices.get_mut(&me).expect("this device is listed");
                    e.bytes += size;
                    e.blocks += 1;
                    *folder.devices.entry(me.to_string()).or_default() += size;
                }
                let bucket = (kept as usize).min(3);
                match bucket {
                    0 => out.copies.none += 1,
                    1 => out.copies.one += 1,
                    2 => out.copies.two += 1,
                    _ => out.copies.three_plus += 1,
                }
                out.copies.bytes[bucket] += size;
                if kept == 0 {
                    folder.unkept_bytes += size;
                }
                copy_sum += kept as u128 * size as u128;
            }
            out.total_bytes += folder.bytes;
            out.total_blocks += folder.blocks;
            out.folders.push(folder);
        }

        let total = out.total_bytes;
        out.copies.average = if total == 0 {
            0.0
        } else {
            copy_sum as f64 / total as f64
        };
        out.storages = storages
            .into_values()
            .map(|mut s| {
                s.share = share(s.bytes, total);
                if s.configured {
                    if let Some(p) = self.storage_price(&s.name) {
                        s.monthly_cost = p.monthly_cost(s.bytes);
                        s.currency = p.currency.clone();
                    }
                }
                s
            })
            .collect();
        out.storages
            .sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
        out.devices = devices
            .into_values()
            .map(|mut d| {
                d.share = share(d.bytes, total);
                d
            })
            .collect();
        out.devices.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| b.this_device.cmp(&a.this_device))
                .then_with(|| a.name.cmp(&b.name))
        });
        out.folders
            .sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
        Ok(out)
    }
}
