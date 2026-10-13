// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! What kind of medium a path lives on, so that verification reads
//! (`crate::parverify`) can be parallel where that is cheap and stay strictly
//! sequential on spinning disks, where parallel reads only add seeks.
//!
//! - Linux and Android: the filesystem type from `/proc/self/mountinfo` (network
//!   filesystems and FUSE mounts of network tools are `Network`, `tmpfs` is
//!   `SolidState`), then the device of the path (`st_dev`, or the mount's
//!   source device for filesystems with anonymous devices such as btrfs) is
//!   looked up in `/sys/dev/block/MAJ:MIN`: a partition is followed to its
//!   whole disk, a device-mapper or md device to its slaves (rotational when
//!   any slave is), and `queue/rotational` decides.
//! - macOS: `statfs` names network filesystems; otherwise
//!   `diskutil info -plist <mount>` tells `SolidState` (cached per device).
//! - Windows: a remote drive is `Network`; otherwise the volume is asked
//!   for its seek penalty (`IOCTL_STORAGE_QUERY_PROPERTY`,
//!   `StorageDeviceSeekPenaltyProperty`).
//! - iOS: flash storage only.
//!
//! Anything not recognised is `Unknown`, which callers treat like a spinning
//! disk: sequential reads are never wrong, only slower.

use std::path::{Path, PathBuf};

/// The medium a path is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Media {
    /// A spinning disk: read one thing after another.
    Rotational,
    /// SSD, NVMe, memory: parallel reads are cheap.
    SolidState,
    /// A network filesystem or remote storage: parallel requests hide latency.
    Network,
    /// Not known: treated as rotational.
    Unknown,
}

impl Media {
    /// Whether reads may run in parallel (never on a spinning or unknown disk).
    pub fn parallel(self) -> bool {
        matches!(self, Media::SolidState | Media::Network)
    }
    /// The medium of a set of disks read as one (a pool): the first that
    /// may not be read in parallel, if any; network when all are; else
    /// solid-state. Unknown for none.
    pub fn combined(all: &[Media]) -> Media {
        if let Some(slow) = all.iter().find(|m| !m.parallel()) {
            *slow
        } else if all.is_empty() {
            Media::Unknown
        } else if all.iter().all(|m| *m == Media::Network) {
            Media::Network
        } else {
            Media::SolidState
        }
    }
    pub fn describe(self) -> &'static str {
        match self {
            Media::Rotational => "spinning disk",
            Media::SolidState => "solid-state",
            Media::Network => "network",
            Media::Unknown => "unknown medium",
        }
    }
}

/// The medium `path` (or its nearest existing ancestor) is on.
pub fn storage_media(path: &Path) -> Media {
    let Some(path) = existing(path) else {
        return Media::Unknown;
    };
    os_media(&path)
}

/// The path itself when it exists, else its nearest existing ancestor,
/// canonicalized.
fn existing(path: &Path) -> Option<PathBuf> {
    let mut p = path;
    loop {
        if let Ok(c) = std::fs::canonicalize(p) {
            return Some(c);
        }
        p = p.parent()?;
    }
}

// ----- Linux -----------------------------------------------------------------

/// One line of `/proc/self/mountinfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    pub major: u32,
    pub minor: u32,
    pub mount_point: PathBuf,
    pub fstype: String,
    pub source: String,
}

/// `\040` and friends in mountinfo fields.
fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') as u32 * 64
                + (b[i + 2] - b'0') as u32 * 8
                + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `/proc/self/mountinfo`.
pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        if fields.len() < 5 || fields.len() < sep + 3 {
            continue;
        }
        let Some((ma, mi)) = fields[2].split_once(':') else {
            continue;
        };
        let (Ok(major), Ok(minor)) = (ma.parse(), mi.parse()) else {
            continue;
        };
        out.push(MountEntry {
            major,
            minor,
            mount_point: PathBuf::from(unescape_octal(fields[4])),
            fstype: fields[sep + 1].to_string(),
            source: unescape_octal(fields[sep + 2]),
        });
    }
    out
}

/// The mount `path` (canonical) is on: the longest mount point that
/// contains it; the last such line wins (mounts over mounts).
pub fn mount_of<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    let mut best: Option<&MountEntry> = None;
    for m in mounts {
        if path.starts_with(&m.mount_point)
            && best.is_none_or(|b| {
                m.mount_point.components().count() >= b.mount_point.components().count()
            })
        {
            best = Some(m);
        }
    }
    best
}

/// What the filesystem type alone says: `Network` for network filesystems
/// and FUSE mounts of network tools, `SolidState` for memory filesystems,
/// none when the device has to be asked.
pub fn media_of_fstype(fstype: &str) -> Option<Media> {
    let base = fstype.strip_prefix("fuse.").unwrap_or(fstype);
    const NETWORK: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "smb2",
        "ncpfs",
        "9p",
        "afs",
        "ceph",
        "glusterfs",
        "lustre",
        "gpfs",
        "beegfs",
        "davfs",
        "davfs2",
        "sshfs",
        "rclone",
        "s3fs",
        "gcsfuse",
        "goofys",
        "curlftpfs",
        "smbnetfs",
        "gvfsd-fuse",
        "juicefs",
        "seaweedfs",
        "mountpoint-s3",
    ];
    if NETWORK.contains(&base) {
        return Some(Media::Network);
    }
    match fstype {
        "tmpfs" | "ramfs" => Some(Media::SolidState),
        // Other FUSE filesystems (mergerfs, encfs, ...) may sit on anything.
        t if t.starts_with("fuse.") || t == "fuse" => Some(Media::Unknown),
        "overlay" | "zfs" | "squashfs" | "proc" | "sysfs" => Some(Media::Unknown),
        _ => None,
    }
}

/// Whether the block device `major:minor` spins, from a sysfs tree rooted
/// at `sys` (`/sys` on a real system): a partition is followed to its
/// disk, a stacked device (dm, md) to its slaves. None when unknown.
pub fn rotational_from_sys(sys: &Path, major: u32, minor: u32) -> Option<bool> {
    let dev = std::fs::canonicalize(sys.join("dev/block").join(format!("{major}:{minor}"))).ok()?;
    rotational_of_dir(&dev, 0)
}

fn rotational_of_dir(dir: &Path, depth: u32) -> Option<bool> {
    if depth > 8 {
        return None;
    }
    // A stacked device: rotational when any device under it is.
    if let Ok(rd) = std::fs::read_dir(dir.join("slaves")) {
        let mut any = false;
        let mut all_known = true;
        let mut seen = false;
        for e in rd.filter_map(|e| e.ok()) {
            seen = true;
            let Ok(slave) = std::fs::canonicalize(e.path()) else {
                all_known = false;
                continue;
            };
            match rotational_of_dir(&slave, depth + 1) {
                Some(true) => any = true,
                Some(false) => {}
                None => all_known = false,
            }
        }
        if seen {
            return if any {
                Some(true)
            } else if all_known {
                Some(false)
            } else {
                None
            };
        }
    }
    // A partition has no queue of its own: its disk is the parent directory.
    if dir.join("partition").exists() {
        return rotational_of_dir(dir.parent()?, depth + 1);
    }
    let flag = std::fs::read_to_string(dir.join("queue/rotational")).ok()?;
    match flag.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// `dev_t` as Linux encodes it.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn split_dev(dev: u64) -> (u32, u32) {
    let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff);
    let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff);
    (major as u32, minor as u32)
}

/// Linux media detection with the system's files as arguments (tests use
/// fake trees): `dev` is the path's `st_dev`, `source_rdev` the mount
/// source's device when it is a block device node.
pub fn linux_media(
    sys: &Path,
    mount: Option<&MountEntry>,
    dev: (u32, u32),
    source_rdev: Option<(u32, u32)>,
) -> Media {
    if let Some(m) = mount.and_then(|m| media_of_fstype(&m.fstype)) {
        return m;
    }
    // Filesystems with anonymous devices (btrfs, fuseblk) report major 0:
    // the mount's source names the real one.
    let dev = if dev.0 == 0 {
        match source_rdev {
            Some(d) => d,
            None => return Media::Unknown,
        }
    } else {
        dev
    };
    match rotational_from_sys(sys, dev.0, dev.1) {
        Some(true) => Media::Rotational,
        Some(false) => Media::SolidState,
        None => Media::Unknown,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn os_media(path: &Path) -> Media {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let Ok(md) = std::fs::metadata(path) else {
        return Media::Unknown;
    };
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")
        .map(|t| parse_mountinfo(&t))
        .unwrap_or_default();
    let mount = mount_of(&mounts, path);
    let source_rdev = mount
        .filter(|m| m.source.starts_with("/dev/"))
        .and_then(|m| std::fs::metadata(&m.source).ok())
        .filter(|s| s.file_type().is_block_device())
        .map(|s| split_dev(s.rdev()));
    linux_media(Path::new("/sys"), mount, split_dev(md.dev()), source_rdev)
}

// ----- macOS -----------------------------------------------------------------

/// The `SolidState` key of `diskutil info -plist`.
pub fn solid_state_from_plist(plist: &str) -> Option<bool> {
    let at = plist.find("<key>SolidState</key>")?;
    let rest = plist[at + "<key>SolidState</key>".len()..].trim_start();
    if rest.starts_with("<true/>") {
        Some(true)
    } else if rest.starts_with("<false/>") {
        Some(false)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn os_media(path: &Path) -> Media {
    use std::collections::HashMap;
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    use std::sync::Mutex;
    static CACHE: Mutex<Option<HashMap<String, Media>>> = Mutex::new(None);
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
        return Media::Unknown;
    };
    // SAFETY: statfs fills the zeroed struct; the path is NUL-terminated.
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut sf) } != 0 {
        return Media::Unknown;
    }
    // SAFETY: the kernel NUL-terminates these fixed-size fields.
    let fstype = unsafe { CStr::from_ptr(sf.f_fstypename.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let from = unsafe { CStr::from_ptr(sf.f_mntfromname.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let on = unsafe { CStr::from_ptr(sf.f_mntonname.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    match fstype.as_str() {
        "nfs" | "smbfs" | "afpfs" | "webdav" | "cifs" | "ftp" | "macfuse" | "osxfuse"
        | "fusefs" | "osxfusefs" => return Media::Network,
        "devfs" | "autofs" => return Media::Unknown,
        _ => {}
    }
    if let Some(m) = CACHE.lock().unwrap().as_ref().and_then(|c| c.get(&from)) {
        return *m;
    }
    let media = std::process::Command::new("/usr/sbin/diskutil")
        .args(["info", "-plist"])
        .arg(&on)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| solid_state_from_plist(&String::from_utf8_lossy(&o.stdout)))
        .map(|ssd| {
            if ssd {
                Media::SolidState
            } else {
                Media::Rotational
            }
        })
        .unwrap_or(Media::Unknown);
    CACHE
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(from, media);
    media
}

// ----- Windows ---------------------------------------------------------------

#[cfg(windows)]
fn os_media(path: &Path) -> Media {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumePathNameW};
    use windows_sys::Win32::System::Ioctl::{
        PropertyStandardQuery, StorageDeviceSeekPenaltyProperty, DEVICE_SEEK_PENALTY_DESCRIPTOR,
        IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROPERTY_QUERY,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    const DRIVE_REMOTE: u32 = 4;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut root = [0u16; 1024];
    // SAFETY: both buffers are valid for the lengths given.
    if unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Media::Unknown;
    }
    // SAFETY: `root` is NUL-terminated by the call above.
    if unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_REMOTE {
        return Media::Network;
    }
    let len = root.iter().position(|c| *c == 0).unwrap_or(0);
    let root = String::from_utf16_lossy(&root[..len]);
    // "C:\" -> "\\.\C:"; a volume mounted in a folder has no letter.
    let letter = root.trim_end_matches('\\');
    if letter.len() != 2 || !letter.ends_with(':') {
        return Media::Unknown;
    }
    let Ok(volume) = std::fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(3)
        .open(format!(r"\\.\{letter}"))
    else {
        return Media::Unknown;
    };
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceSeekPenaltyProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    // SAFETY: zeroed plain-data struct, filled by the call.
    let mut out: DEVICE_SEEK_PENALTY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let mut got = 0u32;
    // SAFETY: the handle is open; the buffers are the sizes given.
    let ok = unsafe {
        DeviceIoControl(
            volume.as_raw_handle() as _,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query as *const _ as *const _,
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            &mut out as *mut _ as *mut _,
            std::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
            &mut got,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || (got as usize) < std::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() {
        return Media::Unknown;
    }
    if out.IncursSeekPenalty != 0 {
        Media::Rotational
    } else {
        Media::SolidState
    }
}

/// iOS devices have flash storage only.
#[cfg(target_os = "ios")]
fn os_media(_path: &Path) -> Media {
    Media::SolidState
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
fn os_media(_path: &Path) -> Media {
    Media::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    fn link(target: &str, at: &Path) {
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, at).unwrap();
    }

    fn write(at: &Path, s: &str) {
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        fs::write(at, s).unwrap();
    }

    /// A fake /sys: sda (spinning) with partitions sda1, sda2; nvme0n1
    /// (solid-state) with nvme0n1p1; dm-0 (crypt) over sda2; md0 over
    /// nvme0n1p1 and sda1; dm-1 over md0.
    #[cfg(unix)]
    fn fake_sys() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let s = t.path();
        let pci = s.join("devices/pci0000:00");
        write(&pci.join("ata1/block/sda/queue/rotational"), "1\n");
        write(&pci.join("ata1/block/sda/sda1/partition"), "1\n");
        write(&pci.join("ata1/block/sda/sda2/partition"), "2\n");
        write(&pci.join("nvme/block/nvme0n1/queue/rotational"), "0\n");
        write(&pci.join("nvme/block/nvme0n1/nvme0n1p1/partition"), "1\n");
        let virt = s.join("devices/virtual/block");
        // Stacked devices have a queue of their own that may not tell the truth.
        write(&virt.join("dm-0/queue/rotational"), "0\n");
        link(
            "../../../../pci0000:00/ata1/block/sda/sda2",
            &virt.join("dm-0/slaves/sda2"),
        );
        write(&virt.join("md0/queue/rotational"), "0\n");
        link(
            "../../../../pci0000:00/nvme/block/nvme0n1/nvme0n1p1",
            &virt.join("md0/slaves/nvme0n1p1"),
        );
        link(
            "../../../../pci0000:00/ata1/block/sda/sda1",
            &virt.join("md0/slaves/sda1"),
        );
        write(&virt.join("dm-1/queue/rotational"), "0\n");
        link("../../md0", &virt.join("dm-1/slaves/md0"));
        write(&virt.join("dm-2/queue/rotational"), "0\n");
        link(
            "../../../../pci0000:00/nvme/block/nvme0n1",
            &virt.join("dm-2/slaves/nvme0n1"),
        );
        let dev = s.join("dev/block");
        for (num, target) in [
            ("8:0", "../../devices/pci0000:00/ata1/block/sda"),
            ("8:1", "../../devices/pci0000:00/ata1/block/sda/sda1"),
            ("8:2", "../../devices/pci0000:00/ata1/block/sda/sda2"),
            ("259:0", "../../devices/pci0000:00/nvme/block/nvme0n1"),
            (
                "259:1",
                "../../devices/pci0000:00/nvme/block/nvme0n1/nvme0n1p1",
            ),
            ("254:0", "../../devices/virtual/block/dm-0"),
            ("9:0", "../../devices/virtual/block/md0"),
            ("254:1", "../../devices/virtual/block/dm-1"),
            ("254:2", "../../devices/virtual/block/dm-2"),
        ] {
            link(target, &dev.join(num));
        }
        t
    }

    #[cfg(unix)]
    #[test]
    fn sysfs_rotational_flags() {
        let t = fake_sys();
        let s = t.path();
        assert_eq!(rotational_from_sys(s, 8, 0), Some(true));
        assert_eq!(rotational_from_sys(s, 259, 0), Some(false));
        // Partitions take their disk's flag.
        assert_eq!(rotational_from_sys(s, 8, 1), Some(true));
        assert_eq!(rotational_from_sys(s, 259, 1), Some(false));
        // dm-crypt over a spinning partition spins, whatever its own queue says.
        assert_eq!(rotational_from_sys(s, 254, 0), Some(true));
        // md over an SSD and a spinning disk counts as spinning; dm over md too.
        assert_eq!(rotational_from_sys(s, 9, 0), Some(true));
        assert_eq!(rotational_from_sys(s, 254, 1), Some(true));
        // dm over an SSD alone is solid-state.
        assert_eq!(rotational_from_sys(s, 254, 2), Some(false));
        // Unknown devices.
        assert_eq!(rotational_from_sys(s, 7, 3), None);
    }

    #[cfg(unix)]
    #[test]
    fn linux_media_from_mounts_and_devices() {
        let t = fake_sys();
        let s = t.path();
        let info = "\
22 1 259:1 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p1 rw
40 22 8:1 / /mnt/hdd rw,relatime shared:2 - ext4 /dev/sda1 rw
41 22 0:45 / /mnt/nas rw,relatime shared:3 - nfs4 nas:/export rw
42 22 0:46 / /mnt/cloud rw,nosuid shared:4 - fuse.rclone remote: rw
43 22 0:47 / /mnt/with\\040space rw shared:5 - btrfs /dev/dm-0 rw
44 22 0:48 / /mnt/merged rw shared:6 - fuse.mergerfs a:b rw
45 22 0:49 / /tmp rw shared:7 - tmpfs tmpfs rw
";
        let mounts = parse_mountinfo(info);
        assert_eq!(mounts.len(), 7);
        assert_eq!(mounts[4].mount_point, PathBuf::from("/mnt/with space"));
        let media = |p: &str, dev: (u32, u32), src: Option<(u32, u32)>| {
            linux_media(s, mount_of(&mounts, Path::new(p)), dev, src)
        };
        assert_eq!(media("/home/me", (259, 1), None), Media::SolidState);
        assert_eq!(media("/mnt/hdd/pool", (8, 1), None), Media::Rotational);
        assert_eq!(media("/mnt/nas/x", (0, 45), None), Media::Network);
        assert_eq!(media("/mnt/cloud", (0, 46), None), Media::Network);
        // btrfs: anonymous device; the source (dm-crypt over sda2) decides.
        assert_eq!(
            media("/mnt/with space/a", (0, 47), Some((254, 0))),
            Media::Rotational
        );
        assert_eq!(media("/mnt/with space/a", (0, 47), None), Media::Unknown);
        assert_eq!(media("/mnt/merged", (0, 48), None), Media::Unknown);
        assert_eq!(media("/tmp/x", (0, 49), None), Media::SolidState);
        // The longest mount point wins over "/".
        assert_eq!(
            mount_of(&mounts, Path::new("/mnt/hdd")).unwrap().source,
            "/dev/sda1"
        );
        assert!(
            mount_of(&mounts, Path::new("/mnt/hddx"))
                .unwrap()
                .mount_point
                == Path::new("/")
        );
    }

    #[test]
    fn dev_numbers_split_like_glibc() {
        assert_eq!(split_dev(0x0801), (8, 1));
        // major 259, minor 1 (NVMe partitions use the extended numbers).
        assert_eq!(split_dev((259 << 8) | 1), (259, 1));
        // Minors above 255 keep their high bits from bit 20 up.
        assert_eq!(
            split_dev((0x123 << 8) | 0x45 | (0x67 << 20)),
            (0x123, 0x6745)
        );
    }

    #[test]
    fn combined_media_is_the_slowest() {
        use Media::*;
        assert_eq!(Media::combined(&[]), Unknown);
        assert_eq!(Media::combined(&[SolidState, Rotational]), Rotational);
        assert_eq!(Media::combined(&[SolidState, Unknown]), Unknown);
        assert_eq!(Media::combined(&[Network, Network]), Network);
        assert_eq!(Media::combined(&[SolidState, Network]), SolidState);
    }

    #[test]
    fn diskutil_plist_solid_state() {
        let ssd =
            "<dict>\n\t<key>SolidState</key>\n\t<true/>\n\t<key>Internal</key>\n\t<true/>\n</dict>";
        let hdd = "<dict><key>Internal</key><true/><key>SolidState</key>\n\t\t<false/></dict>";
        assert_eq!(solid_state_from_plist(ssd), Some(true));
        assert_eq!(solid_state_from_plist(hdd), Some(false));
        assert_eq!(solid_state_from_plist("<dict></dict>"), None);
    }

    #[test]
    fn this_machine_answers_something() {
        // Any answer is fine; the call must not fail or hang.
        let d = tempfile::tempdir().unwrap();
        let _ = storage_media(d.path());
        eprintln!("/: {:?}", storage_media(Path::new("/")));
        assert_eq!(
            storage_media(Path::new("/no/such/place/at/all")).parallel(),
            storage_media(Path::new("/")).parallel()
        );
        assert!(!Media::Unknown.parallel() && !Media::Rotational.parallel());
    }
}
