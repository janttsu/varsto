// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! What "format a drive" means, in one place (spec section 66).
//!
//! Every platform gets the same layout: a GPT partition table (never MBR),
//! a protective MBR as the standard asks, exactly one partition starting at
//! 1 MiB (aligned for 4 KiB sectors, SSD pages and RAID stripes), the GPT
//! partition type that fits the filesystem, and a partition name that says
//! it is a Varsto disk.
//!
//! The functions here are pure: device, label and filesystem in, command
//! lines out. Nothing runs a command and nothing opens a device, so the
//! exact commands are asserted in unit tests. Only the Linux builder is
//! executed today (`blockdev::prepare_drive`); `varsto disk init` still
//! refuses other systems, and the macOS and Windows builders define what
//! it will run there and are covered by their own tests.
//!
//! Filesystem choice. A pool keeps one file per encrypted block, wants
//! POSIX permissions, rename and hard links, and checks the disk with
//! `e2fsck`, so a pool disk is **ext4** on Linux, and that stays the
//! default and the only filesystem `disk init` makes. For a drive that is
//! also moved between Linux, macOS and Windows machines the modern
//! cross-platform choice is **exFAT** (no 4 GiB file limit, unlike FAT32,
//! and no NTFS driver needed on macOS or Linux); on a Mac that only a Mac
//! reads it is **APFS**; **NTFS** is for Windows-only drives. FAT32 is
//! never offered.

use anyhow::{bail, Result};

/// A filesystem a formatting plan can make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fs {
    /// Linux. The default, and what pool disks are.
    Ext4,
    /// Cross-platform (Linux with exfatprogs, macOS, Windows).
    Exfat,
    /// macOS only.
    Apfs,
    /// Windows only.
    Ntfs,
}

/// The operating systems with a formatting plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
}

/// GPT partition type GUID "Linux filesystem data".
pub const GUID_LINUX_DATA: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";
/// GPT partition type GUID "Microsoft basic data" (NTFS, exFAT, FAT).
pub const GUID_BASIC_DATA: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
/// GPT partition type GUID "Apple APFS".
pub const GUID_APFS: &str = "7c3457ef-0000-11aa-aa11-00306543ecac";

/// The partition starts at 1 MiB, in the notation `sgdisk` and `parted` share.
pub const PART_START: &str = "1M";
/// 1 MiB in bytes (`New-Partition -Alignment`).
pub const ALIGNMENT_BYTES: u64 = 1024 * 1024;

impl Fs {
    /// The filesystem Varsto makes unless told otherwise on this system.
    pub fn default_for(os: Os) -> Fs {
        match os {
            Os::Linux => Fs::Ext4,
            Os::MacOs | Os::Windows => Fs::Exfat,
        }
    }

    /// Whether the system can make this filesystem.
    pub fn supported_on(self, os: Os) -> bool {
        matches!(
            (self, os),
            (Fs::Ext4, Os::Linux)
                | (Fs::Exfat, _)
                | (Fs::Apfs, Os::MacOs)
                | (Fs::Ntfs, Os::Windows)
        )
    }

    /// The `sgdisk -t` code.
    pub fn sgdisk_code(self) -> &'static str {
        match self {
            Fs::Ext4 => "8300",
            Fs::Exfat | Fs::Ntfs => "0700",
            Fs::Apfs => "AF0A",
        }
    }

    /// The GPT partition type GUID, lower case.
    pub fn type_guid(self) -> &'static str {
        match self {
            Fs::Ext4 => GUID_LINUX_DATA,
            Fs::Exfat | Fs::Ntfs => GUID_BASIC_DATA,
            Fs::Apfs => GUID_APFS,
        }
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// What to make: the platform-independent part of every plan.
#[derive(Clone, Debug)]
pub struct Spec {
    /// Whole-drive path: `/dev/sdb`, `/dev/disk4` or the Windows disk number as text.
    pub device: String,
    /// The Varsto disk name; the partition name is `varsto-<name>` (36 characters at most).
    pub name: String,
    pub fs: Fs,
}

/// GPT partition name: `varsto-<name>`, at most 36 characters.
pub fn gpt_name(name: &str) -> String {
    let clean: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    format!("varsto-{clean}").chars().take(36).collect()
}

/// Volume label for a filesystem: ASCII letters, digits, `-` and `_`, at
/// most `max` bytes (ext4 16, exFAT 11 for the macOS and Windows tools,
/// NTFS 32). Other characters become `-`. Safe to put inside any shell or
/// PowerShell string.
pub fn volume_label(name: &str, max: usize) -> String {
    let mut s: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let s: String = s.trim_matches('-').chars().take(max).collect();
    let s = s.trim_end_matches('-').to_string();
    if s.is_empty() {
        "varsto".into()
    } else {
        s
    }
}

/// The `sgdisk` command that makes the one partition: from 1 MiB to the
/// last usable sector, typed for the filesystem, with a fixed PARTUUID and
/// the Varsto partition name.
pub fn sgdisk_partition(spec: &Spec, partuuid: &str) -> Vec<String> {
    vec![
        "sgdisk".into(),
        "-n".into(),
        format!("1:{PART_START}:0"),
        "-t".into(),
        format!("1:{}", spec.fs.sgdisk_code()),
        "-u".into(),
        format!("1:{partuuid}"),
        "-c".into(),
        format!("1:{}", gpt_name(&spec.name)),
        spec.device.clone(),
    ]
}

/// Linux: the commands, in order, that make the layout. `partitions` are
/// the existing partitions of the drive (wiped first, so no old filesystem
/// signature can be found later); `partuuid` is chosen by the caller so the
/// new partition can be found again; `owner` is `uid:gid` of the user.
/// Only ext4 is made on Linux (pools need POSIX semantics and `e2fsck`).
pub fn linux_commands(
    spec: &Spec,
    partitions: &[String],
    partuuid: &str,
    owner: &str,
    inode_ratio: u64,
) -> Result<Vec<Vec<String>>> {
    check_device_path(Os::Linux, &spec.device)?;
    if spec.fs != Fs::Ext4 {
        bail!(
            "disk pools on Linux are ext4; {:?} is not made by `disk init`",
            spec.fs
        );
    }
    let mut out = Vec::new();
    for p in partitions {
        out.push(argv(&["wipefs", "-a", "-q", p]));
    }
    out.push(argv(&["wipefs", "-a", "-q", &spec.device]));
    out.push(argv(&["sgdisk", "-Z", &spec.device]));
    // A new GPT with its protective MBR.
    out.push(argv(&["sgdisk", "-o", &spec.device]));
    out.push(sgdisk_partition(spec, partuuid));
    out.push(argv(&["partprobe", &spec.device]));
    out.push(vec![
        "mkfs.ext4".into(),
        "-q".into(),
        "-F".into(),
        "-L".into(),
        volume_label(&spec.name, 16),
        "-m".into(),
        "0".into(),
        "-i".into(),
        inode_ratio.to_string(),
        "-E".into(),
        format!("root_owner={owner}"),
        format!("/dev/disk/by-partuuid/{partuuid}"),
    ]);
    Ok(out)
}

/// macOS: `diskutil` unmounts the drive and erases it with the GPT scheme.
/// `eraseDisk` writes the GPT with its protective MBR, aligns the data
/// partition itself and gives it the partition type of the filesystem
/// (Microsoft basic data for exFAT, Apple APFS for APFS); it also adds the
/// small EFI system partition macOS puts on every GPT disk. The volume
/// name is the Varsto disk name. `device` must be a whole disk, `/dev/diskN`.
pub fn macos_commands(spec: &Spec) -> Result<Vec<Vec<String>>> {
    check_device_path(Os::MacOs, &spec.device)?;
    let format = match spec.fs {
        Fs::Exfat => "ExFAT",
        Fs::Apfs => "APFS",
        other => bail!("{other:?} cannot be made on macOS"),
    };
    Ok(vec![
        argv(&["diskutil", "unmountDisk", &spec.device]),
        argv(&[
            "diskutil",
            "eraseDisk",
            format,
            &volume_label(&spec.name, 11),
            "GPT",
            &spec.device,
        ]),
    ])
}

/// Windows: PowerShell statements, run in order with
/// `powershell -NoProfile -NonInteractive -Command <statement>`. `device`
/// is the disk number (`Get-Disk`), never 0 (the boot disk on Windows);
/// the caller also refuses the system, boot and read-only disks.
pub fn windows_commands(spec: &Spec) -> Result<Vec<String>> {
    check_device_path(Os::Windows, &spec.device)?;
    let n = &spec.device;
    let fs = match spec.fs {
        Fs::Exfat => "exFAT",
        Fs::Ntfs => "NTFS",
        other => bail!("{other:?} cannot be made on Windows"),
    };
    let label = volume_label(&spec.name, if spec.fs == Fs::Ntfs { 32 } else { 11 });
    Ok(vec![
        format!("Clear-Disk -Number {n} -RemoveData -RemoveOEM -Confirm:$false"),
        format!("Initialize-Disk -Number {n} -PartitionStyle GPT"),
        format!(
            "New-Partition -DiskNumber {n} -UseMaximumSize -Alignment {ALIGNMENT_BYTES} -GptType '{{{}}}' | Format-Volume -FileSystem {fs} -NewFileSystemLabel '{label}' -Confirm:$false",
            spec.fs.type_guid()
        ),
    ])
}

fn check_device_path(os: Os, device: &str) -> Result<()> {
    let ok = match os {
        Os::Linux => {
            device.starts_with("/dev/")
                && device.len() > 5
                && !device.contains("..")
                && !device.ends_with('/')
                && !device.chars().any(|c| c.is_whitespace() || c.is_control())
        }
        // Whole disks only: /dev/disk4, not /dev/disk4s2 nor /dev/rdisk4.
        Os::MacOs => device
            .strip_prefix("/dev/disk")
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) && n != "0"),
        // A plain disk number; disk 0 is the boot disk.
        Os::Windows => {
            !device.is_empty()
                && device.chars().all(|c| c.is_ascii_digit())
                && device.parse::<u32>().is_ok_and(|n| n > 0)
        }
    };
    if !ok {
        bail!("{device:?} is not a whole-drive name this system can format");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "11111111-2222-4333-8444-555555555555";

    fn spec(device: &str, fs: Fs) -> Spec {
        Spec {
            device: device.into(),
            name: "Blue 4TB".into(),
            fs,
        }
    }

    #[test]
    fn linux_makes_gpt_with_one_aligned_linux_partition() {
        let cmds = linux_commands(
            &spec("/dev/sdb", Fs::Ext4),
            &["/dev/sdb1".into(), "/dev/sdb2".into()],
            UUID,
            "1000:1000",
            65536,
        )
        .unwrap();
        let lines: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        assert_eq!(
            lines,
            vec![
                "wipefs -a -q /dev/sdb1".to_string(),
                "wipefs -a -q /dev/sdb2".to_string(),
                "wipefs -a -q /dev/sdb".to_string(),
                "sgdisk -Z /dev/sdb".to_string(),
                "sgdisk -o /dev/sdb".to_string(),
                format!("sgdisk -n 1:1M:0 -t 1:8300 -u 1:{UUID} -c 1:varsto-Blue 4TB /dev/sdb"),
                "partprobe /dev/sdb".to_string(),
                format!("mkfs.ext4 -q -F -L Blue-4TB -m 0 -i 65536 -E root_owner=1000:1000 /dev/disk/by-partuuid/{UUID}"),
            ]
        );
        let all = lines.join("\n");
        for legacy in ["msdos", "mklabel", "sfdisk", "fdisk "] {
            assert!(!all.contains(legacy), "{legacy}");
        }
    }

    #[test]
    fn linux_refuses_other_filesystems_and_odd_paths() {
        assert!(linux_commands(&spec("/dev/sdb", Fs::Exfat), &[], UUID, "1:1", 1).is_err());
        for bad in [
            "sdb",
            "/dev/",
            "/dev/../etc/passwd",
            "/dev/sd b",
            "/tmp/x",
            "",
        ] {
            assert!(
                linux_commands(&spec(bad, Fs::Ext4), &[], UUID, "1:1", 1).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn macos_erases_with_gpt() {
        let c = macos_commands(&spec("/dev/disk4", Fs::Exfat)).unwrap();
        assert_eq!(
            c,
            vec![
                argv(&["diskutil", "unmountDisk", "/dev/disk4"]),
                argv(&[
                    "diskutil",
                    "eraseDisk",
                    "ExFAT",
                    "Blue-4TB",
                    "GPT",
                    "/dev/disk4"
                ]),
            ]
        );
        let a = macos_commands(&spec("/dev/disk12", Fs::Apfs)).unwrap();
        assert_eq!(a[1][2], "APFS");
        assert_eq!(a[1][4], "GPT");
        for cmd in c.iter().chain(a.iter()) {
            assert!(!cmd.iter().any(|x| x == "MBR" || x == "MBRFormat"));
        }
    }

    #[test]
    fn macos_refuses_slices_raw_nodes_disk0_and_foreign_filesystems() {
        for bad in [
            "/dev/disk4s2",
            "/dev/rdisk4",
            "/dev/disk",
            "/dev/disk0",
            "disk4",
            "/dev/sdb",
        ] {
            assert!(macos_commands(&spec(bad, Fs::Exfat)).is_err(), "{bad}");
        }
        assert!(macos_commands(&spec("/dev/disk4", Fs::Ext4)).is_err());
        assert!(macos_commands(&spec("/dev/disk4", Fs::Ntfs)).is_err());
    }

    #[test]
    fn windows_initializes_gpt_aligned_with_basic_data_type() {
        let c = windows_commands(&spec("3", Fs::Exfat)).unwrap();
        assert_eq!(
            c[0],
            "Clear-Disk -Number 3 -RemoveData -RemoveOEM -Confirm:$false"
        );
        assert_eq!(c[1], "Initialize-Disk -Number 3 -PartitionStyle GPT");
        assert_eq!(
            c[2],
            "New-Partition -DiskNumber 3 -UseMaximumSize -Alignment 1048576 -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' | Format-Volume -FileSystem exFAT -NewFileSystemLabel 'Blue-4TB' -Confirm:$false"
        );
        assert!(!c.join("\n").to_lowercase().contains("mbr"));
        let n = windows_commands(&spec("5", Fs::Ntfs)).unwrap();
        assert!(n[2].contains("-FileSystem NTFS"));
    }

    #[test]
    fn windows_refuses_disk_zero_names_and_foreign_filesystems() {
        for bad in ["0", "", "-1", "1; Remove-Item", "PhysicalDrive1", "3 "] {
            assert!(windows_commands(&spec(bad, Fs::Exfat)).is_err(), "{bad:?}");
        }
        assert!(windows_commands(&spec("3", Fs::Ext4)).is_err());
        assert!(windows_commands(&spec("3", Fs::Apfs)).is_err());
    }

    #[test]
    fn labels_cannot_carry_quotes_or_shell_syntax() {
        let mut s = spec("3", Fs::Exfat);
        s.name = "x'; Remove-Item C:\\ #\"$(id)".into();
        let c = windows_commands(&s).unwrap();
        assert!(
            c[2].contains("-NewFileSystemLabel 'x-Remove-It'"),
            "{}",
            c[2]
        );
        let label = volume_label(&s.name, 32);
        assert!(label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_eq!(volume_label("", 16), "varsto");
        assert_eq!(volume_label("Blue 4TB", 16), "Blue-4TB");
        assert_eq!(volume_label("a very long disk name here", 11).len(), 11);
    }

    #[test]
    fn types_defaults_and_support() {
        assert_eq!(Fs::default_for(Os::Linux), Fs::Ext4);
        assert_eq!(Fs::default_for(Os::MacOs), Fs::Exfat);
        assert_eq!(Fs::default_for(Os::Windows), Fs::Exfat);
        assert_eq!(Fs::Ext4.type_guid(), GUID_LINUX_DATA);
        assert_eq!(Fs::Exfat.sgdisk_code(), "0700");
        assert_eq!(Fs::Apfs.sgdisk_code(), "AF0A");
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            assert!(Fs::default_for(os).supported_on(os));
        }
        assert!(!Fs::Ntfs.supported_on(Os::Linux));
        assert_eq!(gpt_name(&"x".repeat(80)).chars().count(), 36);
    }

    /// Run the real `sgdisk` on a plain file (no device, no root): the plan
    /// must produce a GPT with a protective MBR and one 1 MiB-aligned
    /// partition with the right type, name and UUID.
    #[test]
    fn sgdisk_on_an_image_file_makes_gpt() {
        let Some(sgdisk) = find_tool("sgdisk") else {
            eprintln!("skipped: sgdisk is not installed");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("disk.img");
        let f = std::fs::File::create(&img).unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
        drop(f);
        // Something that looks like an old MBR must not survive.
        {
            use std::io::{Seek, Write};
            let mut f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
            f.seek(std::io::SeekFrom::Start(446)).unwrap();
            f.write_all(&[0x80, 0, 0, 0, 0x83]).unwrap();
            f.seek(std::io::SeekFrom::Start(510)).unwrap();
            f.write_all(&[0x55, 0xaa]).unwrap();
        }
        let dev = img.display().to_string();
        let mut s = spec("/dev/placeholder", Fs::Ext4);
        s.name = "Image".into();
        let plan = linux_commands(&s, &[], UUID, "1:1", 65536).unwrap();
        let mut ran = 0;
        for cmd in plan.iter().filter(|c| c[0] == "sgdisk") {
            let mut cmd = cmd.clone();
            *cmd.last_mut().unwrap() = dev.clone();
            let out = std::process::Command::new(&sgdisk)
                .args(&cmd[1..])
                .output()
                .unwrap();
            // -Z may complain about a blank image; everything else must work.
            assert!(out.status.success() || cmd[1] == "-Z", "{cmd:?}: {out:?}");
            ran += 1;
        }
        assert_eq!(ran, 3);
        let out = std::process::Command::new(&sgdisk)
            .args(["-i", "1", &dev])
            .output()
            .unwrap();
        let info = String::from_utf8_lossy(&out.stdout).to_lowercase();
        assert!(info.contains(GUID_LINUX_DATA), "{info}");
        assert!(info.contains(UUID), "{info}");
        assert!(info.contains("varsto-image"), "{info}");
        assert!(info.contains("first sector: 2048"), "{info}");
        let out = std::process::Command::new(&sgdisk)
            .args(["-v", &dev])
            .output()
            .unwrap();
        assert!(out.status.success());
        let raw = std::fs::read(&img).unwrap();
        // Protective MBR: one entry of type 0xEE, signature 55AA, GPT header at LBA 1.
        assert_eq!(raw[446 + 4], 0xee);
        assert_eq!(&raw[510..512], &[0x55, 0xaa]);
        assert_eq!(&raw[512..520], b"EFI PART");
    }

    fn find_tool(name: &str) -> Option<std::path::PathBuf> {
        let mut dirs: Vec<std::path::PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        dirs.extend(["/usr/sbin", "/sbin", "/usr/local/sbin"].map(Into::into));
        dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
    }
}
