// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `<home>/disks.conf`: the drives this device prepared or knows, by
//! partition, with the name on their sticker.
//!
//! ```text
//! # comment
//! 5f0c9a52-6f4e-4c1b-9a0e-1d2c3b4a5f60<TAB>shelf<TAB>Blue 4TB
//! ```
//!
//! One line per partition: PARTUUID, pool and label separated by single
//! tabs; the label is the rest of the line and may contain spaces. Lines
//! starting with `#` and blank lines are kept as they are when the file is
//! written again. The marker on the disk stays the authority for which disk
//! of which pool it is; this file only says which partition to mount for a
//! label and what to call a drive that is plugged in.

use crate::util;
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

pub const FILE: &str = "disks.conf";
/// The last forced file system check of each partition (JSON, by PARTUUID).
pub const CHECKS_FILE: &str = "disk-checks.json";

const HEADER: &str = "\
# Varsto drives on this device: one line per partition, fields separated by tabs:
# PARTUUID<TAB>POOL<TAB>LABEL
# LABEL is the name on the drive's sticker and may contain spaces.
# Written by `varsto disk init` and `varsto disk add`; lines starting with # are kept.
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drive {
    /// Lower-case partition UUID (GPT) or `xxxxxxxx-NN` (MBR).
    pub partuuid: String,
    pub pool: String,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Line {
    /// A comment or blank line, kept verbatim.
    Other(String),
    Drive(Drive),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskConf {
    lines: Vec<Line>,
}

impl Default for DiskConf {
    fn default() -> Self {
        DiskConf {
            lines: HEADER.lines().map(|l| Line::Other(l.to_string())).collect(),
        }
    }
}

fn valid_partuuid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn valid_field(s: &str) -> bool {
    !s.trim().is_empty() && !s.contains(['\t', '\n', '\r'])
}

impl DiskConf {
    pub fn path(home: &Path) -> PathBuf {
        home.join(FILE)
    }

    pub fn parse(text: &str) -> Result<DiskConf> {
        let mut lines = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                lines.push(Line::Other(line.to_string()));
                continue;
            }
            let mut parts = line.splitn(3, '\t');
            let (Some(uuid), Some(pool), Some(label)) = (parts.next(), parts.next(), parts.next())
            else {
                bail!(
                    "{FILE} line {}: expected PARTUUID, pool and label separated by tabs",
                    n + 1
                );
            };
            let uuid = uuid.trim().to_ascii_lowercase();
            if !valid_partuuid(&uuid) {
                bail!("{FILE} line {}: {uuid:?} is not a partition UUID", n + 1);
            }
            if !valid_field(pool) || !valid_field(label) {
                bail!(
                    "{FILE} line {}: the pool and the label must not be empty",
                    n + 1
                );
            }
            lines.push(Line::Drive(Drive {
                partuuid: uuid,
                pool: pool.trim().to_string(),
                label: label.trim().to_string(),
            }));
        }
        Ok(DiskConf { lines })
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for l in &self.lines {
            match l {
                Line::Other(s) => out.push_str(s),
                Line::Drive(d) => out.push_str(&format!("{}\t{}\t{}", d.partuuid, d.pool, d.label)),
            }
            out.push('\n');
        }
        out
    }

    /// The file in `home`, or an empty one with the header when there is none.
    pub fn load(home: &Path) -> Result<DiskConf> {
        match std::fs::read_to_string(Self::path(home)) {
            Ok(t) => Self::parse(&t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DiskConf::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Write atomically (temporary file, fsync, rename).
    pub fn save(&self, home: &Path) -> Result<()> {
        util::write_atomic(&Self::path(home), self.render().as_bytes())
    }

    pub fn drives(&self) -> impl Iterator<Item = &Drive> {
        self.lines.iter().filter_map(|l| match l {
            Line::Drive(d) => Some(d),
            Line::Other(_) => None,
        })
    }

    pub fn by_label(&self, label: &str) -> Option<&Drive> {
        self.drives().find(|d| d.label == label)
    }

    pub fn by_partuuid(&self, uuid: &str) -> Option<&Drive> {
        let uuid = uuid.to_ascii_lowercase();
        self.drives().find(|d| d.partuuid == uuid)
    }

    /// Add a drive, or rename the one with the same PARTUUID in place.
    /// Refuses a label another partition already has.
    pub fn upsert(&mut self, drive: Drive) -> Result<()> {
        let drive = Drive {
            partuuid: drive.partuuid.trim().to_ascii_lowercase(),
            pool: drive.pool.trim().to_string(),
            label: drive.label.trim().to_string(),
        };
        if !valid_partuuid(&drive.partuuid) {
            bail!("{:?} is not a partition UUID", drive.partuuid);
        }
        if !valid_field(&drive.pool) || !valid_field(&drive.label) {
            bail!("the pool and the label must not be empty or contain tabs or line breaks");
        }
        if let Some(other) = self
            .drives()
            .find(|d| d.label == drive.label && d.partuuid != drive.partuuid)
        {
            bail!(
                "{FILE} already names partition {} \"{}\"",
                other.partuuid,
                other.label
            );
        }
        for l in self.lines.iter_mut() {
            if let Line::Drive(d) = l {
                if d.partuuid == drive.partuuid {
                    *d = drive;
                    return Ok(());
                }
            }
        }
        self.lines.push(Line::Drive(drive));
        Ok(())
    }

    /// Forget a partition; true when it was listed.
    pub fn remove(&mut self, uuid: &str) -> bool {
        let uuid = uuid.to_ascii_lowercase();
        let before = self.lines.len();
        self.lines
            .retain(|l| !matches!(l, Line::Drive(d) if d.partuuid == uuid));
        self.lines.len() != before
    }
}

/// The last check of every partition that was checked before a mount.
pub fn checks(home: &Path) -> std::collections::BTreeMap<String, crate::blockdev::FsckOutcome> {
    util::read_json(&home.join(CHECKS_FILE)).unwrap_or_default()
}

/// Remember the check of a partition (written atomically).
pub fn record_check(
    home: &Path,
    partuuid: &str,
    outcome: &crate::blockdev::FsckOutcome,
) -> Result<()> {
    let mut all = checks(home);
    all.insert(partuuid.to_ascii_lowercase(), outcome.clone());
    util::write_json(&home.join(CHECKS_FILE), &all)
}

#[cfg(test)]
mod tests {
    use super::*;

    const U1: &str = "5f0c9a52-6f4e-4c1b-9a0e-1d2c3b4a5f60";
    const U2: &str = "0a1b2c3d-0000-4000-8000-00000000abcd";

    #[test]
    fn round_trip_keeps_comments_and_labels_with_spaces() {
        let text = format!(
            "# my drives\n\n{U1}\tshelf\tBlue 4TB\n# the offsite one\n{}\tshelf\t  Musta WD  \n",
            U2.to_uppercase()
        );
        let c = DiskConf::parse(&text).unwrap();
        let drives: Vec<&Drive> = c.drives().collect();
        assert_eq!(drives.len(), 2);
        assert_eq!(drives[0].label, "Blue 4TB");
        assert_eq!(drives[1].partuuid, U2);
        assert_eq!(drives[1].label, "Musta WD");
        let again = DiskConf::parse(&c.render()).unwrap();
        assert_eq!(again, c);
        assert!(c.render().starts_with("# my drives\n\n"));
        assert!(c.render().contains("# the offsite one\n"));
        assert_eq!(c.by_label("Blue 4TB").unwrap().partuuid, U1);
        assert_eq!(c.by_partuuid(&U2.to_uppercase()).unwrap().label, "Musta WD");
    }

    #[test]
    fn upsert_renames_in_place_and_refuses_a_taken_label() {
        let mut c = DiskConf::default();
        c.upsert(Drive {
            partuuid: U1.into(),
            pool: "shelf".into(),
            label: "Blue 4TB".into(),
        })
        .unwrap();
        c.upsert(Drive {
            partuuid: U2.into(),
            pool: "shelf".into(),
            label: "Red".into(),
        })
        .unwrap();
        c.upsert(Drive {
            partuuid: U1.into(),
            pool: "shelf".into(),
            label: "Blue 4 TB (old)".into(),
        })
        .unwrap();
        assert_eq!(c.drives().count(), 2);
        assert_eq!(c.drives().next().unwrap().label, "Blue 4 TB (old)");
        assert!(c
            .upsert(Drive {
                partuuid: U1.into(),
                pool: "shelf".into(),
                label: "Red".into(),
            })
            .is_err());
        assert!(c
            .upsert(Drive {
                partuuid: U1.into(),
                pool: "shelf".into(),
                label: "tab\there".into(),
            })
            .is_err());
        assert!(c.render().starts_with("# Varsto drives"));
        assert!(c.remove(U2));
        assert!(!c.remove(U2));
    }

    #[test]
    fn malformed_lines_are_refused_with_their_number() {
        let e = DiskConf::parse("# ok\nnot-a-line\n").unwrap_err();
        assert!(e.to_string().contains("line 2"), "{e}");
        let e = DiskConf::parse(&format!("{U1} shelf Blue\n")).unwrap_err();
        assert!(e.to_string().contains("tabs"), "{e}");
        assert!(DiskConf::parse("zzzz\tshelf\tBlue\n").is_err());
        assert!(DiskConf::parse(&format!("{U1}\t\tBlue\n")).is_err());
    }

    #[test]
    fn save_and_load_through_the_home_directory() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(DiskConf::load(tmp.path()).unwrap(), DiskConf::default());
        let mut c = DiskConf::default();
        c.upsert(Drive {
            partuuid: U1.into(),
            pool: "shelf".into(),
            label: "Blue 4TB".into(),
        })
        .unwrap();
        c.save(tmp.path()).unwrap();
        let text = std::fs::read_to_string(tmp.path().join(FILE)).unwrap();
        assert!(text.ends_with(&format!("{U1}\tshelf\tBlue 4TB\n")));
        assert_eq!(DiskConf::load(tmp.path()).unwrap(), c);
    }
}
