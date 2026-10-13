// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Mounting and unmounting pool drives for work, shared by the command line
//! (`drives`) and the local API (`desktop`, also built into the phone
//! library, where none of it runs: phones have no block devices).

use anyhow::Result;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use varsto_core::blockdev::{self, SystemRunner};
use varsto_core::diskconf::{DiskConf, Drive};

/// Check the drive's file system (`e2fsck -f -p`, unmounting it first if
/// the desktop mounted it) and mount it only when the check leaves it clean
/// or corrected. The result is recorded in disk-checks.json; corrections
/// and refusals are also shown as desktop notifications.
pub fn mount_checked(
    home: &Path,
    json_out: bool,
    drive: &Drive,
) -> Result<(PathBuf, blockdev::Method, blockdev::FsckOutcome)> {
    let live = !json_out && std::io::stderr().is_terminal();
    if !json_out {
        eprintln!("{}: checking its file system (e2fsck -f -p)", drive.label);
    }
    let task = varsto_core::activity::start(
        varsto_core::activity::DISK_FSCK,
        &drive.label,
        0,
        varsto_core::activity::Unit::Items,
    );
    let checked = blockdev::check_and_mount(&mut SystemRunner, &drive.partuuid, &drive.label, live);
    drop(task);
    match checked {
        Ok((mount, how, out)) => {
            let _ = varsto_core::diskconf::record_check(home, &drive.partuuid, &out);
            if let Some(m) = out.message(&drive.label) {
                eprintln!("warning: {m}");
                crate::service::notify("Varsto disk", &m);
            }
            if !json_out && !out.summary.is_empty() {
                eprintln!("  {}", out.summary);
            }
            Ok((mount, how, out))
        }
        Err(e) => {
            if let Some(stop) = e.downcast_ref::<blockdev::FsckStopped>() {
                let _ = varsto_core::diskconf::record_check(home, &drive.partuuid, &stop.outcome);
                crate::service::notify("Varsto disk", &stop.message);
            }
            Err(e)
        }
    }
}

/// Mount the drive of a plan step if disks.conf knows it and it is plugged
/// in. True when the disk may now be reachable (also when disks.conf does
/// not know it: the user may have mounted it).
pub fn mount_known(home: &Path, label: &str) -> Result<bool> {
    if !cfg!(target_os = "linux") {
        return Ok(true);
    }
    let conf = DiskConf::load(home)?;
    let Some(drive) = conf.by_label(label) else {
        return Ok(true);
    };
    let devs = blockdev::lsblk(&mut SystemRunner)?;
    if blockdev::find_partition(&devs, &drive.partuuid).is_none() {
        return Ok(false);
    }
    mount_checked(home, false, drive)?;
    Ok(true)
}

/// Unmount and power off the partition mounted at `mount` (Linux; nothing
/// elsewhere, or when no partition is mounted there).
pub fn release_mount(mount: &Path) -> Result<Vec<blockdev::Step>> {
    if !cfg!(target_os = "linux") {
        return Ok(Vec::new());
    }
    let mut r = SystemRunner;
    let devs = blockdev::lsblk(&mut r)?;
    if blockdev::partition_at(&devs, mount).is_none() {
        return Ok(Vec::new());
    }
    blockdev::unmount_partition(&mut r, mount, true)
}
