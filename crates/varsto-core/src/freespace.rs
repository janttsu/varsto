// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Minimum free disk space (like Syncthing's `minDiskFree`).
//!
//! Every place this device writes new data to has a limit: the disk holding
//! a synced folder (pulls, fetches, restores, imports, the restic mirror,
//! which is folders too), a local-directory storage (uploads), and the
//! device directory (the block cache of folders kept encrypted here, blocks
//! staged from pool disks). The default is 5 % of the disk; a storage or a
//! folder may set its own, as a share ("10%") or an amount ("10GB").
//! Pool disks keep their own reserve (`pool`), 5 % by default as well.
//!
//! A write that would leave less than the limit free is refused with
//! [`LowSpace`]; reading, uploading elsewhere, deleting and everything
//! else go on. The refused work is retried by the next sync (pulls keep
//! the files pending), and a place is recorded here while it is short, so
//! that the service can tell the user once and show a banner until space
//! is back ([`recheck`] measures again).
//!
//! The space of a path comes from the operating system or, in tests, from
//! `pool::set_fake_space`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A limit: a share of the disk in hundredths of a percent, or bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinFree {
    /// Hundredths of a percent: 500 is 5 %.
    Basis(u32),
    Bytes(u64),
}

/// 5 % of the disk.
pub const DEFAULT: MinFree = MinFree::Basis(500);

impl Default for MinFree {
    fn default() -> Self {
        DEFAULT
    }
}

impl MinFree {
    /// "5%", "2.5 %", "10GB", "500 MB", "1.5TiB", "0" (no limit) or a plain
    /// number of bytes. Decimal units are powers of 1000, binary ones of 1024.
    pub fn parse(s: &str) -> anyhow::Result<MinFree> {
        let t = s.trim().replace(' ', "").to_ascii_lowercase();
        if t.is_empty() {
            anyhow::bail!("empty minimum free space");
        }
        if let Some(p) = t.strip_suffix('%') {
            let v: f64 = p
                .replace(',', ".")
                .parse()
                .map_err(|_| anyhow::anyhow!("not a percentage: {s}"))?;
            if !(0.0..=50.0).contains(&v) {
                anyhow::bail!("the minimum free space must be between 0 % and 50 %, not {s}");
            }
            return Ok(MinFree::Basis((v * 100.0).round() as u32));
        }
        let split = t
            .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == ','))
            .unwrap_or(t.len());
        let (num, unit) = t.split_at(split);
        let v: f64 = num
            .replace(',', ".")
            .parse()
            .map_err(|_| anyhow::anyhow!("not an amount of space: {s} (use e.g. 5% or 10GB)"))?;
        let mul: f64 = match unit {
            "" | "b" => 1.0,
            "k" | "kb" => 1e3,
            "m" | "mb" => 1e6,
            "g" | "gb" => 1e9,
            "t" | "tb" => 1e12,
            "kib" => 1024.0,
            "mib" => 1024.0 * 1024.0,
            "gib" => 1024.0 * 1024.0 * 1024.0,
            "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
            _ => anyhow::bail!("unknown unit in {s} (use %, MB, GB, TB, MiB, GiB or TiB)"),
        };
        Ok(MinFree::Bytes((v * mul).round() as u64))
    }

    /// Bytes to keep free on a disk of `total` bytes.
    pub fn bytes(&self, total: u64) -> u64 {
        match self {
            MinFree::Basis(b) => ((total as u128 * *b as u128) / 10_000) as u64,
            MinFree::Bytes(n) => *n,
        }
    }

    /// "5 %", "2.5 %", "10.0 GB".
    pub fn describe(&self) -> String {
        match self {
            MinFree::Basis(b) if b % 100 == 0 => format!("{} %", b / 100),
            MinFree::Basis(b) => format!("{} %", *b as f64 / 100.0),
            MinFree::Bytes(n) => crate::util::human_bytes(*n),
        }
    }

    /// The form settings are written in: "5%", "2.5%", "10000000000".
    pub fn setting(&self) -> String {
        match self {
            MinFree::Basis(b) if b % 100 == 0 => format!("{}%", b / 100),
            MinFree::Basis(b) => format!("{}%", *b as f64 / 100.0),
            MinFree::Bytes(n) => n.to_string(),
        }
    }
}

impl Serialize for MinFree {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.setting())
    }
}

impl<'de> Deserialize<'de> for MinFree {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            S(String),
            N(u64),
        }
        match Raw::deserialize(d)? {
            Raw::S(s) => MinFree::parse(&s).map_err(serde::de::Error::custom),
            Raw::N(n) => Ok(MinFree::Bytes(n)),
        }
    }
}

/// Where data is written, for the messages and the list of places short
/// of space.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Place {
    /// `folder:<name>`, `storage:<name>`, `device`, `path:<dir>`.
    pub key: String,
    /// "folder Photos", "storage usb-disk", "the device directory".
    pub label: String,
    /// What stops: "downloads", "uploads", "writes".
    pub stops: String,
}

impl Place {
    pub fn folder(name: &str) -> Place {
        Place {
            key: format!("folder:{name}"),
            label: format!("folder {name}"),
            stops: "downloads".into(),
        }
    }
    pub fn storage(name: &str) -> Place {
        Place {
            key: format!("storage:{name}"),
            label: format!("storage {name}"),
            stops: "uploads".into(),
        }
    }
    /// The device directory: the block cache, staged blocks.
    pub fn device() -> Place {
        Place {
            key: "device".into(),
            label: "the device directory".into(),
            stops: "downloads".into(),
        }
    }
    /// A directory outside the folders (a restore target).
    pub fn path(dir: &Path) -> Place {
        Place {
            key: format!("path:{}", dir.display()),
            label: dir.display().to_string(),
            stops: "writes".into(),
        }
    }
}

/// A write refused: the disk would keep less than its limit free.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{text}")]
pub struct LowSpace {
    pub place: Place,
    /// The directory measured.
    pub path: PathBuf,
    pub free: u64,
    pub total: u64,
    /// The limit as set and in bytes.
    pub min_free: String,
    pub limit: u64,
    /// The write that was refused (0: none, the disk is below the limit).
    pub needed: u64,
    /// "disk of folder Photos has 3 % free, below the 5 % limit; downloads paused".
    pub text: String,
}

impl LowSpace {
    fn new(
        place: &Place,
        path: &Path,
        space: crate::pool::DiskSpace,
        min: MinFree,
        needed: u64,
    ) -> LowSpace {
        let limit = min.bytes(space.total);
        let free_text = match min {
            MinFree::Basis(_) => format!("{} free", percent(space.free, space.total)),
            MinFree::Bytes(_) => format!("{} free", crate::util::human_bytes(space.free)),
        };
        let text = if space.free < limit || needed == 0 {
            format!(
                "disk of {} has {free_text}, below the {} limit; {} paused",
                place.label,
                min.describe(),
                place.stops
            )
        } else {
            format!(
                "disk of {} has {free_text}; {} more would leave less than the {} limit; {} paused",
                place.label,
                crate::util::human_bytes(needed),
                min.describe(),
                place.stops
            )
        };
        LowSpace {
            place: place.clone(),
            path: path.to_path_buf(),
            free: space.free,
            total: space.total,
            min_free: min.setting(),
            limit,
            needed,
            text,
        }
    }
}

/// "3 %", "0.4 %".
fn percent(free: u64, total: u64) -> String {
    if total == 0 {
        return "0 %".into();
    }
    let p = free as f64 * 100.0 / total as f64;
    if p >= 1.0 || p == 0.0 {
        format!("{} %", p.floor() as u64)
    } else {
        format!("{:.1} %", p)
    }
}

/// The first `LowSpace` in an error chain, if any.
pub fn low_space(e: &anyhow::Error) -> Option<&LowSpace> {
    e.chain().find_map(|c| c.downcast_ref::<LowSpace>())
}

/// Free and total space of the disk holding `path`, measured at the nearest
/// directory that exists (the file to be written usually does not yet).
pub fn space_at(path: &Path) -> Option<crate::pool::DiskSpace> {
    let mut p = Some(path);
    while let Some(here) = p {
        if here.exists() {
            return crate::pool::disk_space(here);
        }
        p = here.parent();
    }
    None
}

/// Places short of space right now, by key.
static SHORT: Mutex<BTreeMap<String, (LowSpace, MinFree)>> = Mutex::new(BTreeMap::new());

/// May `needed` more bytes be written at `path` (in `place`, limit `min`)?
/// Refused writes are remembered until a check or [`recheck`] finds room
/// again. A disk whose space cannot be read is never refused.
/// The error is a [`LowSpace`] (see [`low_space`]).
pub fn check(place: &Place, path: &Path, min: MinFree, needed: u64) -> anyhow::Result<()> {
    let Some(space) = space_at(path) else {
        return Ok(());
    };
    let limit = min.bytes(space.total);
    if space.free.saturating_sub(needed) < limit {
        let low = LowSpace::new(place, path, space, min, needed);
        SHORT
            .lock()
            .unwrap()
            .insert(place.key.clone(), (low.clone(), min));
        return Err(anyhow::Error::new(low));
    }
    // Room again for this place, also for the write refused last.
    let mut short = SHORT.lock().unwrap();
    if short
        .get(&place.key)
        .is_some_and(|(l, _)| space.free.saturating_sub(l.needed) >= limit)
    {
        short.remove(&place.key);
    }
    Ok(())
}

/// The places short of space as last seen.
pub fn short_places() -> Vec<LowSpace> {
    SHORT
        .lock()
        .unwrap()
        .values()
        .map(|(l, _)| l.clone())
        .collect()
}

/// Measure every place short of space again; those with room for the
/// write that was refused (or, after it, above the limit) are dropped.
/// Returns the places that got their space back.
pub fn recheck() -> Vec<LowSpace> {
    let mut short = SHORT.lock().unwrap();
    let mut back = Vec::new();
    short.retain(|_, (low, min)| {
        let Some(space) = space_at(&low.path) else {
            return true;
        };
        let limit = min.bytes(space.total);
        if space.free.saturating_sub(low.needed) >= limit {
            back.push(low.clone());
            false
        } else {
            // Keep the figures current for the displays.
            *low = LowSpace::new(&low.place, &low.path.clone(), space, *min, low.needed);
            true
        }
    });
    back
}

/// Forget a place (its folder or storage was removed, or the setting changed).
pub fn forget(key: &str) {
    SHORT.lock().unwrap().remove(key);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{set_fake_space, DiskSpace};

    #[test]
    fn parse_and_describe() {
        assert_eq!(MinFree::parse("5%").unwrap(), MinFree::Basis(500));
        assert_eq!(MinFree::parse(" 2,5 % ").unwrap(), MinFree::Basis(250));
        assert_eq!(
            MinFree::parse("10GB").unwrap(),
            MinFree::Bytes(10_000_000_000)
        );
        assert_eq!(
            MinFree::parse("1.5 GiB").unwrap(),
            MinFree::Bytes(1_610_612_736)
        );
        assert_eq!(
            MinFree::parse("500mb").unwrap(),
            MinFree::Bytes(500_000_000)
        );
        assert_eq!(MinFree::parse("0").unwrap(), MinFree::Bytes(0));
        assert!(MinFree::parse("60%").is_err());
        assert!(MinFree::parse("ten").is_err());
        assert!(MinFree::parse("5 parsecs").is_err());
        assert_eq!(MinFree::Basis(500).describe(), "5 %");
        assert_eq!(MinFree::Basis(250).describe(), "2.5 %");
        assert_eq!(MinFree::Bytes(10_000_000_000).describe(), "10.0 GB");
        assert_eq!(MinFree::Basis(500).bytes(1_000_000), 50_000);
        // Settings round-trip through JSON as strings (numbers read as bytes).
        let j = serde_json::to_string(&MinFree::Basis(250)).unwrap();
        assert_eq!(j, "\"2.5%\"");
        assert_eq!(
            serde_json::from_str::<MinFree>(&j).unwrap(),
            MinFree::Basis(250)
        );
        assert_eq!(
            serde_json::from_str::<MinFree>("1000").unwrap(),
            MinFree::Bytes(1000)
        );
    }

    #[test]
    fn writes_stop_below_the_limit_and_resume_when_space_is_back() {
        let dir = tempfile::tempdir().unwrap();
        let place = Place::folder("Photos-test-freespace");
        let total = 100_000_000_000u64;
        set_fake_space(
            dir.path(),
            Some(DiskSpace {
                free: 3_000_000_000,
                total,
            }),
        );
        // Below the 5 % limit: refused, recorded, and the text says why.
        let e = check(&place, &dir.path().join("a/b.jpg"), DEFAULT, 1000).unwrap_err();
        let e = low_space(&e).unwrap().clone();
        assert_eq!(
            e.text,
            "disk of folder Photos-test-freespace has 3 % free, below the 5 % limit; downloads paused"
        );
        assert!(short_places().iter().any(|l| l.place == place));
        // Still short at a recheck.
        assert!(recheck().iter().all(|l| l.place != place));
        assert!(short_places().iter().any(|l| l.place == place));
        // Above the limit, but this write would cross it.
        set_fake_space(
            dir.path(),
            Some(DiskSpace {
                free: 6_000_000_000,
                total,
            }),
        );
        let e = check(&place, dir.path(), DEFAULT, 2_000_000_000).unwrap_err();
        let e = low_space(&e).unwrap().clone();
        assert!(
            e.text
                .contains("6 % free; 2.0 GB more would leave less than the 5 % limit"),
            "{}",
            e.text
        );
        // A smaller write goes ahead.
        check(&place, dir.path(), DEFAULT, 500_000_000).unwrap();
        // Space is back for the refused write: the place is dropped.
        set_fake_space(
            dir.path(),
            Some(DiskSpace {
                free: 20_000_000_000,
                total,
            }),
        );
        assert!(recheck().iter().any(|l| l.place == place));
        assert!(short_places().iter().all(|l| l.place != place));
        // A byte limit.
        let e = check(&place, dir.path(), MinFree::Bytes(30_000_000_000), 0).unwrap_err();
        let e = low_space(&e).unwrap().clone();
        assert!(
            e.text.contains("has 20.0 GB free, below the 30.0 GB limit"),
            "{}",
            e.text
        );
        forget(&place.key);
        // No limit at all.
        check(&place, dir.path(), MinFree::Bytes(0), 1_000).unwrap();
        set_fake_space(dir.path(), None);
    }
}
