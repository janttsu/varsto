// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Whole drives for disk pools on Linux: what `lsblk` says about them, the
//! checks that keep `varsto disk init` away from any drive in use, the one
//! privileged script that partitions and formats a drive, and mounting and
//! unmounting a pool partition (`udisksctl`, or `mount` through sudo where
//! udisks is missing or refuses).
//!
//! Every external command goes through a `Runner`, so the logic is tested
//! with recorded answers and never touches a real device in tests.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Columns asked from `lsblk -J -b -o ...`.
pub const LSBLK_COLUMNS: &str =
    "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,RM,RO,MOUNTPOINTS,FSTYPE,PKNAME,PARTUUID,LABEL,MAJ:MIN";

/// Filesystem types that mean "this belongs to something else": volume
/// managers, RAID, encryption, pooled filesystems.
const FOREIGN_FSTYPES: &[&str] = &[
    "LVM2_member",
    "linux_raid_member",
    "crypto_LUKS",
    "zfs_member",
    "bcache",
    "ceph_bluestore",
    "isw_raid_member",
    "ddf_raid_member",
    "promise_fasttrack_raid_member",
    "VMFS_volume_member",
];

/// Inode ratio of pool filesystems: one inode per 64 KiB. Pool objects are
/// encrypted chunks stored one per file (pools do not pack): 256 KiB on
/// average with the default chunker and up to a few MiB for big files,
/// but a small file is one small object, so a disk of many small files
/// needs far more inodes than `-T largefile4` (one per 4 MiB) gives. One
/// per 64 KiB costs 0.4 % of the disk for inode tables.
pub const INODE_RATIO: u64 = 65_536;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockDev {
    pub name: String,
    pub kname: String,
    pub path: String,
    /// "disk", "part", "crypt", "lvm", "raid1", "loop", "rom", ...
    pub kind: String,
    pub size: u64,
    pub model: String,
    pub serial: String,
    pub tran: String,
    pub removable: bool,
    pub read_only: bool,
    pub mountpoints: Vec<String>,
    pub fstype: String,
    pub partuuid: String,
    pub label: String,
    pub maj_min: String,
    pub children: Vec<BlockDev>,
}

fn text(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn flag(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "1" || s == "true",
        Some(Value::Number(n)) => n.as_u64() == Some(1),
        _ => false,
    }
}

impl BlockDev {
    fn from_json(v: &Value) -> BlockDev {
        let mut mountpoints: Vec<String> = match v.get("mountpoints") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|m| m.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        };
        // Older lsblk: one MOUNTPOINT.
        let single = text(v, "mountpoint");
        if !single.is_empty() && !mountpoints.contains(&single) {
            mountpoints.push(single);
        }
        let name = text(v, "name");
        let mut path = text(v, "path");
        if path.is_empty() {
            path = format!("/dev/{name}");
        }
        BlockDev {
            kname: {
                let k = text(v, "kname");
                if k.is_empty() {
                    name.clone()
                } else {
                    k
                }
            },
            name,
            path,
            kind: text(v, "type"),
            size: match v.get("size") {
                Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
                Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
                _ => 0,
            },
            model: text(v, "model"),
            serial: text(v, "serial"),
            tran: text(v, "tran"),
            removable: flag(v, "rm"),
            read_only: flag(v, "ro"),
            mountpoints,
            fstype: text(v, "fstype"),
            partuuid: text(v, "partuuid").to_ascii_lowercase(),
            label: text(v, "label"),
            maj_min: text(v, "maj:min"),
            children: v
                .get("children")
                .and_then(|c| c.as_array())
                .map(|a| a.iter().map(BlockDev::from_json).collect())
                .unwrap_or_default(),
        }
    }

    /// This device and everything below it (partitions, mappings).
    pub fn subtree(&self) -> Vec<&BlockDev> {
        let mut out = vec![self];
        for c in &self.children {
            out.extend(c.subtree());
        }
        out
    }

    /// One line for confirmations and listings.
    pub fn summary(&self) -> String {
        let mut what = Vec::new();
        if !self.model.is_empty() {
            what.push(self.model.clone());
        }
        if !self.serial.is_empty() {
            what.push(format!("serial {}", self.serial));
        }
        what.push(crate::util::human_bytes(self.size));
        if !self.tran.is_empty() {
            what.push(format!("via {}", self.tran));
        }
        if self.removable {
            what.push("removable".into());
        }
        format!("{} ({})", self.path, what.join(", "))
    }
}

/// Parse `lsblk -J` output: the top-level devices with their children.
pub fn parse_lsblk(json: &str) -> Result<Vec<BlockDev>> {
    let v: Value = serde_json::from_str(json).context("parse lsblk output")?;
    let list = v
        .get("blockdevices")
        .and_then(|b| b.as_array())
        .ok_or_else(|| anyhow!("lsblk output has no blockdevices"))?;
    Ok(list.iter().map(BlockDev::from_json).collect())
}

/// Devices in use as swap, from `/proc/swaps` (first column).
pub fn parse_swaps(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// What the system relies on: (what, device number "maj:min") for the
/// root filesystem, /boot, /home, Varsto's own directory and binary.
#[derive(Clone, Debug, Default)]
pub struct SystemFacts {
    pub swaps: Vec<String>,
    pub protected: Vec<(String, String)>,
}

impl SystemFacts {
    /// Read the facts of this machine.
    pub fn gather(varsto_home: &Path) -> SystemFacts {
        let swaps = std::fs::read_to_string("/proc/swaps")
            .map(|t| parse_swaps(&t))
            .unwrap_or_default();
        let mut protected = Vec::new();
        let mut paths: Vec<(String, PathBuf)> = vec![
            ("the root filesystem".into(), PathBuf::from("/")),
            ("/boot".into(), PathBuf::from("/boot")),
            ("/home".into(), PathBuf::from("/home")),
            ("Varsto's directory".into(), varsto_home.to_path_buf()),
        ];
        if let Ok(exe) = std::env::current_exe() {
            paths.push(("the varsto program".into(), exe));
        }
        for (what, p) in paths {
            if let Some(mm) = device_number(&p) {
                protected.push((what, mm));
            }
        }
        SystemFacts { swaps, protected }
    }
}

#[cfg(unix)]
fn device_number(p: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(p).ok()?.dev();
    // SAFETY: pure arithmetic on a device number (a safe fn on some targets).
    #[allow(unused_unsafe)]
    let (maj, min) = unsafe { (libc::major(dev), libc::minor(dev)) };
    Some(format!("{maj}:{min}"))
}

#[cfg(not(unix))]
fn device_number(_p: &Path) -> Option<String> {
    None
}

/// Find `device` (a path, symlinks resolved by the caller) among the
/// devices and refuse anything but a whole, unused drive. Returns the drive.
pub fn check_whole_device<'a>(
    devs: &'a [BlockDev],
    device: &str,
    facts: &SystemFacts,
) -> Result<&'a BlockDev> {
    let all: Vec<&BlockDev> = devs.iter().flat_map(|d| d.subtree()).collect();
    let Some(dev) = all.iter().copied().find(|d| d.path == device) else {
        bail!("{device} is not a block device lsblk knows");
    };
    if dev.kind == "part" {
        bail!(
            "{device} is a partition; give the whole drive (for example /dev/{}), whose every partition will be removed",
            devs.iter()
                .find(|d| d.children.iter().any(|c| c.path == device))
                .map(|d| d.name.as_str())
                .unwrap_or("sdX")
        );
    }
    if dev.kind != "disk" {
        bail!("{device} is a {} device, not a whole drive", dev.kind);
    }
    if dev.read_only {
        bail!("{device} is read-only");
    }
    let tree = dev.subtree();
    for d in &tree {
        if let Some(m) = d.mountpoints.iter().find(|m| !m.is_empty()) {
            if m == "[SWAP]" {
                bail!("{} on {device} is in use as swap", d.path);
            }
            bail!(
                "{} on {device} is mounted at {m}: this drive is in use",
                d.path
            );
        }
        let dev_path = format!("/dev/{}", d.kname);
        if facts.swaps.iter().any(|s| s == &d.path || s == &dev_path) {
            bail!("{} on {device} is in use as swap", d.path);
        }
        if FOREIGN_FSTYPES.contains(&d.fstype.as_str()) {
            bail!(
                "{} on {device} is a {} (volume manager, RAID or encryption): Varsto does not take such drives; remove it from that setup first",
                d.path,
                d.fstype
            );
        }
        if !d.maj_min.is_empty() {
            if let Some((what, _)) = facts.protected.iter().find(|(_, mm)| mm == &d.maj_min) {
                bail!("{device} holds {what}");
            }
        }
    }
    if let Some(holder) = tree.iter().skip(1).find(|d| d.kind != "part") {
        bail!(
            "{} ({}) is built on {device}: the drive is in use",
            holder.path,
            holder.kind
        );
    }
    Ok(dev)
}

/// What the confirmation shows: the drive and what is on it now.
pub fn describe(dev: &BlockDev) -> String {
    let mut out = format!("{}\n", dev.summary());
    if dev.children.is_empty() {
        out.push_str(&format!(
            "  no partitions{}\n",
            if dev.fstype.is_empty() {
                String::new()
            } else {
                format!(" (whole-drive {} filesystem)", dev.fstype)
            }
        ));
    }
    for c in &dev.children {
        out.push_str(&format!(
            "  {} {}{}{}\n",
            c.path,
            crate::util::human_bytes(c.size),
            if c.fstype.is_empty() {
                String::new()
            } else {
                format!(" {}", c.fstype)
            },
            if c.label.is_empty() {
                String::new()
            } else {
                format!(" \"{}\"", c.label)
            }
        ));
    }
    out
}

/// Filesystem label: ASCII letters, digits, `-` and `_`, at most 16 bytes
/// (the ext4 limit). Other characters become `-`.
pub fn fs_label(label: &str) -> String {
    let mut s: String = label
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
    let s = s.trim_matches('-');
    let s: String = s.chars().take(16).collect();
    let s = s.trim_end_matches('-').to_string();
    if s.is_empty() {
        "varsto".into()
    } else {
        s
    }
}

/// GPT partition name: `varsto-<label>`, at most 36 characters.
pub fn gpt_name(label: &str) -> String {
    let clean: String = label.trim().chars().filter(|c| !c.is_control()).collect();
    format!("varsto-{clean}").chars().take(36).collect()
}

/// A random (version 4) partition UUID.
pub fn new_partuuid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// The script run as root to prepare a drive. Arguments, never pasted into
/// the script text: $1 drive, $2 partition UUID, $3 GPT name, $4
/// filesystem label, $5 owner uid:gid, $6 inode ratio. It wipes every
/// signature (partitions first), writes a new GPT with one Linux partition
/// over the whole drive under the UUID chosen beforehand, waits for udev to
/// show it and makes an ext4 filesystem owned by the user with no blocks
/// reserved for root (the pool keeps its own reserve).
pub const INIT_SCRIPT: &str = r#"set -eu
echo "step: wipe signatures"
for p in $(lsblk -nrpo PATH "$1" | tail -n +2); do wipefs -a -q "$p" || true; done
wipefs -a -q "$1"
echo "step: new GPT partition table"
sgdisk -Z "$1" >/dev/null 2>&1 || true
sgdisk -o "$1" >/dev/null
echo "step: one ext4 partition over the whole drive"
sgdisk -n 1:0:0 -t 1:8300 -u "1:$2" -c "1:$3" "$1" >/dev/null
partprobe "$1" 2>/dev/null || blockdev --rereadpt "$1" 2>/dev/null || true
udevadm settle
i=0
while [ ! -b "/dev/disk/by-partuuid/$2" ]; do
  i=$((i + 1))
  if [ "$i" -gt 100 ]; then echo "the new partition did not appear" >&2; exit 3; fi
  sleep 0.2
  udevadm settle
done
echo "step: format ext4"
mkfs.ext4 -q -F -L "$4" -m 0 -i "$6" -E "root_owner=$5" "/dev/disk/by-partuuid/$2"
udevadm settle
echo "step: done"
"#;

/// One command's result.
#[derive(Clone, Debug, Default)]
pub struct Output {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    /// Exit code (-1 when killed by a signal).
    pub code: i32,
}

/// Runs external commands (a recorded fake in tests).
pub trait Runner {
    fn run(&mut self, argv: &[String]) -> Result<Output>;
    /// Run with the terminal as stdout and stderr (progress bars), nothing captured.
    fn run_live(&mut self, argv: &[String]) -> Result<Output> {
        self.run(argv)
    }
    /// Whether a program is on PATH.
    fn has(&self, program: &str) -> bool;
    /// Effective user id (0: root, no privilege helper needed).
    fn uid(&self) -> u32;
}

/// The real thing.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, argv: &[String]) -> Result<Output> {
        let (prog, args) = argv.split_first().ok_or_else(|| anyhow!("empty command"))?;
        // stdin stays the terminal: sudo and pkexec may ask for a password.
        let out = std::process::Command::new(prog)
            .args(args)
            .stdin(std::process::Stdio::inherit())
            .output()
            .with_context(|| format!("run {prog}"))?;
        Ok(Output {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            code: out.status.code().unwrap_or(-1),
        })
    }
    fn run_live(&mut self, argv: &[String]) -> Result<Output> {
        let (prog, args) = argv.split_first().ok_or_else(|| anyhow!("empty command"))?;
        let status = std::process::Command::new(prog)
            .args(args)
            .status()
            .with_context(|| format!("run {prog}"))?;
        Ok(Output {
            ok: status.success(),
            code: status.code().unwrap_or(-1),
            ..Default::default()
        })
    }
    fn has(&self, program: &str) -> bool {
        // The sbin directories too: Debian leaves them out of a user's PATH,
        // while sudo and pkexec find the tools there.
        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        dirs.extend(["/usr/local/sbin", "/usr/sbin", "/sbin"].map(PathBuf::from));
        dirs.iter().any(|d| d.join(program).is_file())
    }
    fn uid(&self) -> u32 {
        #[cfg(unix)]
        // SAFETY: getuid cannot fail.
        unsafe {
            libc::geteuid()
        }
        #[cfg(not(unix))]
        1000
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// The prefix that runs a command as root: nothing for root, `sudo`, or
/// `pkexec` where sudo is missing.
pub fn privilege(r: &dyn Runner) -> Result<Vec<String>> {
    if r.uid() == 0 {
        Ok(Vec::new())
    } else if r.has("sudo") {
        Ok(argv(&["sudo"]))
    } else if r.has("pkexec") {
        Ok(argv(&["pkexec"]))
    } else {
        bail!("preparing a drive needs root: install sudo (or polkit's pkexec), or run as root")
    }
}

/// Every top-level device with its children.
pub fn lsblk(r: &mut dyn Runner) -> Result<Vec<BlockDev>> {
    let out = r.run(&argv(&["lsblk", "-J", "-b", "-o", LSBLK_COLUMNS]))?;
    if !out.ok {
        bail!("lsblk failed: {}", out.stderr.trim());
    }
    parse_lsblk(&out.stdout)
}

/// The partition with this PARTUUID and the drive it is on.
pub fn find_partition<'a>(
    devs: &'a [BlockDev],
    partuuid: &str,
) -> Option<(&'a BlockDev, &'a BlockDev)> {
    let uuid = partuuid.to_ascii_lowercase();
    for d in devs {
        for p in d.subtree() {
            if p.kind == "part" && p.partuuid == uuid {
                return Some((p, d));
            }
        }
    }
    None
}

/// The partition mounted at `mount` and its drive.
pub fn partition_at<'a>(
    devs: &'a [BlockDev],
    mount: &Path,
) -> Option<(&'a BlockDev, &'a BlockDev)> {
    for d in devs {
        for p in d.subtree() {
            if p.mountpoints.iter().any(|m| Path::new(m) == mount) {
                return Some((p, d));
            }
        }
    }
    None
}

/// This user's (uid, gid): the owner of a new pool filesystem.
pub fn current_owner() -> (u32, u32) {
    #[cfg(unix)]
    // SAFETY: getuid and getgid cannot fail.
    unsafe {
        (libc::getuid(), libc::getgid())
    }
    #[cfg(not(unix))]
    (0, 0)
}

/// What preparing a drive ran, for the report.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct InitOutcome {
    pub device: String,
    pub partuuid: String,
    pub partition: String,
    pub fs_label: String,
    /// "sudo", "pkexec" or "root".
    pub privilege: String,
    pub steps: Vec<String>,
}

/// Partition and format `device` (already checked and confirmed) as one
/// ext4 partition, through one privileged call of `INIT_SCRIPT`. Returns
/// the new partition, found again by its UUID.
pub fn prepare_drive(
    r: &mut dyn Runner,
    device: &str,
    label: &str,
    owner: (u32, u32),
) -> Result<InitOutcome> {
    for tool in ["wipefs", "sgdisk", "mkfs.ext4", "udevadm", "lsblk"] {
        if !r.has(tool) {
            bail!(
                "{tool} is missing: install {} first",
                match tool {
                    "sgdisk" => "gdisk (sgdisk)",
                    "mkfs.ext4" => "e2fsprogs",
                    "udevadm" => "udev",
                    _ => "util-linux",
                }
            );
        }
    }
    let prefix = privilege(r)?;
    let uuid = new_partuuid();
    let fsl = fs_label(label);
    let mut cmd = prefix.clone();
    cmd.extend(argv(&["sh", "-c", INIT_SCRIPT, "varsto-disk-init"]));
    cmd.extend([
        device.to_string(),
        uuid.clone(),
        gpt_name(label),
        fsl.clone(),
        format!("{}:{}", owner.0, owner.1),
        INODE_RATIO.to_string(),
    ]);
    let out = r.run(&cmd)?;
    let steps: Vec<String> = out
        .stdout
        .lines()
        .filter_map(|l| l.strip_prefix("step: "))
        .map(str::to_string)
        .collect();
    if !out.ok {
        bail!(
            "preparing {device} failed after: {}\n{}",
            if steps.is_empty() {
                "nothing".to_string()
            } else {
                steps.join(", ")
            },
            out.stderr.trim()
        );
    }
    let devs = lsblk(r)?;
    let (part, _) = find_partition(&devs, &uuid)
        .ok_or_else(|| anyhow!("the new partition {uuid} is not visible on {device}"))?;
    if part.fstype != "ext4" {
        bail!(
            "{} has filesystem {:?} after formatting, not ext4",
            part.path,
            part.fstype
        );
    }
    Ok(InitOutcome {
        device: device.to_string(),
        partuuid: uuid,
        partition: part.path.clone(),
        fs_label: fsl,
        privilege: prefix.first().cloned().unwrap_or_else(|| "root".into()),
        steps,
    })
}

/// How a partition was mounted or unmounted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    /// udisks2 (no root needed for removable drives; mounts under /run/media or /media).
    Udisks,
    /// `mount`/`umount` through sudo or pkexec, at /mnt/varsto-<label>.
    Sudo,
    /// Already mounted.
    None,
}

/// Directory used when mounting through sudo: one level below /mnt, where
/// the pool looks for disks.
pub fn fallback_mount_dir(label: &str) -> PathBuf {
    PathBuf::from(format!(
        "/mnt/varsto-{}",
        fs_label(label).to_ascii_lowercase()
    ))
}

/// Mount the partition with this PARTUUID unless it is mounted already.
/// Tries udisks first (no password for a drive in a dock), then `mount`
/// as root. Returns the mount path.
pub fn mount_partition(
    r: &mut dyn Runner,
    partuuid: &str,
    label: &str,
) -> Result<(PathBuf, Method)> {
    let devs = lsblk(r)?;
    let (part, _) = find_partition(&devs, partuuid)
        .ok_or_else(|| anyhow!("partition {partuuid} ({label}) is not plugged in"))?;
    if let Some(m) = part.mountpoints.iter().find(|m| !m.is_empty()) {
        return Ok((PathBuf::from(m), Method::None));
    }
    let node = format!("/dev/disk/by-partuuid/{}", partuuid.to_ascii_lowercase());
    let mut why = String::new();
    if r.has("udisksctl") {
        let out = r.run(&argv(&[
            "udisksctl",
            "mount",
            "--no-user-interaction",
            "-b",
            &node,
        ]))?;
        if out.ok {
            let devs = lsblk(r)?;
            if let Some(m) = find_partition(&devs, partuuid)
                .and_then(|(p, _)| p.mountpoints.iter().find(|m| !m.is_empty()).cloned())
            {
                return Ok((PathBuf::from(m), Method::Udisks));
            }
        }
        why = out.stderr.trim().to_string();
    }
    let prefix = privilege(r).with_context(|| {
        if why.is_empty() {
            "udisksctl is missing".to_string()
        } else {
            format!("udisksctl could not mount it: {why}")
        }
    })?;
    let dir = fallback_mount_dir(label);
    let dir_s = dir.display().to_string();
    let mut mkdir = prefix.clone();
    mkdir.extend(argv(&["mkdir", "-p", &dir_s]));
    let out = r.run(&mkdir)?;
    if !out.ok {
        bail!("cannot create {dir_s}: {}", out.stderr.trim());
    }
    let mut mount = prefix;
    mount.extend(argv(&[
        "mount",
        "-o",
        "noatime,nodev,nosuid",
        &node,
        &dir_s,
    ]));
    let out = r.run(&mount)?;
    if !out.ok {
        bail!("mounting {label} at {dir_s} failed: {}", out.stderr.trim());
    }
    Ok((dir, Method::Sudo))
}

/// Filesystems a pool disk may have: the ones `e2fsck` checks.
const EXT_FSTYPES: &[&str] = &["ext4", "ext3", "ext2"];

/// What the forced check before mounting found.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FsckVerdict {
    /// Exit code 0.
    Clean,
    /// 1 (or 2, "reboot": not relevant for a data disk): errors were corrected.
    Corrected,
    /// 4: errors left uncorrected; the disk is not mounted.
    Uncorrected,
    /// 8, 16, 32, 128 (or a signal): e2fsck could not do its work.
    Failed,
}

impl FsckVerdict {
    pub fn of(code: i32) -> FsckVerdict {
        if code == 0 {
            FsckVerdict::Clean
        } else if code < 0 || code & (8 | 16 | 32 | 128) != 0 {
            FsckVerdict::Failed
        } else if code & 4 != 0 {
            FsckVerdict::Uncorrected
        } else {
            FsckVerdict::Corrected
        }
    }
    /// Whether the disk may be mounted for pool work.
    pub fn mountable(&self) -> bool {
        matches!(self, FsckVerdict::Clean | FsckVerdict::Corrected)
    }
}

/// One forced check: `e2fsck -f -p` on the unmounted partition.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FsckOutcome {
    pub partition: String,
    pub code: i32,
    pub verdict: FsckVerdict,
    /// e2fsck's summary (stdout) when it was captured, and its stderr.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stderr: String,
    pub checked_utc: i64,
}

impl FsckOutcome {
    /// The message for a verdict that stops the mount, or warns.
    pub fn message(&self, label: &str) -> Option<String> {
        match self.verdict {
            FsckVerdict::Clean => None,
            FsckVerdict::Corrected => Some(format!(
                "file system errors were found and corrected on {label} ({})",
                self.partition
            )),
            FsckVerdict::Uncorrected => Some(format!(
                "The file system on {label} has errors that could not be repaired automatically; nothing was read or written. Run `sudo e2fsck -f {}` by hand or retire the disk.",
                self.partition
            )),
            FsckVerdict::Failed => Some(format!(
                "Checking the file system on {label} ({}) failed (e2fsck exit code {}); nothing was read or written: {}",
                self.partition,
                self.code,
                self.stderr.trim()
            )),
        }
    }
}

/// Make sure the partition is not mounted (a desktop may have mounted it
/// on its own): udisks, else `umount` as root.
fn ensure_unmounted(r: &mut dyn Runner, part: &str, mounts: &[String]) -> Result<()> {
    let Some(m) = mounts.iter().find(|m| !m.is_empty()) else {
        return Ok(());
    };
    if r.has("udisksctl") {
        let out = r.run(&argv(&[
            "udisksctl",
            "unmount",
            "--no-user-interaction",
            "-b",
            part,
        ]))?;
        if out.ok {
            return Ok(());
        }
    }
    let mut cmd = privilege(r)?;
    cmd.extend(argv(&["umount", m]));
    let out = r.run(&cmd)?;
    if !out.ok {
        bail!(
            "{part} is mounted at {m} and could not be unmounted for its file system check: {}",
            out.stderr.trim()
        );
    }
    Ok(())
}

/// Before pool work on a disk: refuse anything but ext2/3/4, unmount the
/// partition if it is mounted, run `e2fsck -f -p` as root (with a progress
/// bar on a terminal: `live`), and mount it only when the check left it
/// clean or corrected. Returns the mount, how it was mounted and the check;
/// a check that leaves errors (or fails) returns `FsckOutcome` inside the
/// error, as `FsckStopped`, and nothing is mounted.
pub fn check_and_mount(
    r: &mut dyn Runner,
    partuuid: &str,
    label: &str,
    live: bool,
) -> Result<(PathBuf, Method, FsckOutcome)> {
    let devs = lsblk(r)?;
    let (part, _) = find_partition(&devs, partuuid)
        .ok_or_else(|| anyhow!("partition {partuuid} ({label}) is not plugged in"))?;
    let part_path = part.path.clone();
    if !EXT_FSTYPES.contains(&part.fstype.as_str()) {
        bail!(
            "{label} ({part_path}) has {} file system; pool disks need ext4 (checked with e2fsck before use): prepare the drive with `varsto disk init`",
            if part.fstype.is_empty() { "no known".to_string() } else { format!("a {}", part.fstype) }
        );
    }
    if !r.has("e2fsck") {
        bail!("e2fsck is missing: install e2fsprogs; a pool disk is always checked before it is mounted");
    }
    ensure_unmounted(r, &part_path, &part.mountpoints)?;
    let mut cmd = privilege(r)?;
    cmd.extend(argv(&["e2fsck", "-f", "-p"]));
    if live {
        cmd.extend(argv(&["-C", "0"]));
    }
    cmd.push(part_path.clone());
    let out = if live {
        r.run_live(&cmd)?
    } else {
        r.run(&cmd)?
    };
    let outcome = FsckOutcome {
        partition: part_path,
        code: out.code,
        verdict: FsckVerdict::of(out.code),
        summary: out.stdout.trim().to_string(),
        stderr: out.stderr.trim().to_string(),
        checked_utc: crate::util::now_utc(),
    };
    if !outcome.verdict.mountable() {
        return Err(anyhow::Error::new(FsckStopped {
            message: outcome.message(label).unwrap_or_default(),
            outcome,
        }));
    }
    let (mount, how) = mount_partition(r, partuuid, label)?;
    Ok((mount, how, outcome))
}

/// The check before mounting left errors or failed: nothing was mounted.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct FsckStopped {
    pub message: String,
    pub outcome: FsckOutcome,
}

/// One step of a safe unmount, as reported.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Step {
    pub step: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

fn sync_all() {
    #[cfg(unix)]
    // SAFETY: sync takes no arguments and cannot fail.
    unsafe {
        libc::sync();
    }
}

/// Unmount a pool partition safely: sync, unmount (udisks, else `umount`
/// as root), sync, and power the drive off (udisks) unless asked not to.
/// Fails when the unmount fails (something still uses the drive); a
/// power-off that fails is reported but the drive is safe to remove.
pub fn unmount_partition(r: &mut dyn Runner, mount: &Path, power_off: bool) -> Result<Vec<Step>> {
    let mut steps = Vec::new();
    let devs = lsblk(r)?;
    let (part, drive) = partition_at(&devs, mount)
        .map(|(p, d)| (p.path.clone(), d.path.clone()))
        .ok_or_else(|| anyhow!("nothing is mounted at {}", mount.display()))?;
    sync_all();
    steps.push(Step {
        step: "sync".into(),
        ok: true,
        note: String::new(),
    });
    let mut unmounted = false;
    let mut why = String::new();
    let udisks = r.has("udisksctl");
    if udisks {
        let out = r.run(&argv(&[
            "udisksctl",
            "unmount",
            "--no-user-interaction",
            "-b",
            &part,
        ]))?;
        unmounted = out.ok;
        why = out.stderr.trim().to_string();
        if unmounted {
            steps.push(Step {
                step: format!("unmount {part} (udisksctl)"),
                ok: true,
                note: String::new(),
            });
        }
    }
    if !unmounted {
        let prefix = privilege(r)?;
        let mount_s = mount.display().to_string();
        let mut cmd = prefix.clone();
        cmd.extend(argv(&["umount", &mount_s]));
        let out = r.run(&cmd)?;
        if !out.ok {
            bail!(
                "{part} could not be unmounted: {}{}. Close what uses {mount_s} (see `fuser -vm {mount_s}`) and try again",
                out.stderr.trim(),
                if why.is_empty() {
                    String::new()
                } else {
                    format!(" (udisksctl: {why})")
                }
            );
        }
        steps.push(Step {
            step: format!("unmount {part} (umount as root)"),
            ok: true,
            note: String::new(),
        });
        if mount_s.starts_with("/mnt/varsto-") {
            let mut rmdir = prefix;
            rmdir.extend(argv(&["rmdir", &mount_s]));
            let _ = r.run(&rmdir);
        }
    }
    sync_all();
    steps.push(Step {
        step: "sync".into(),
        ok: true,
        note: String::new(),
    });
    if power_off {
        if udisks {
            let out = r.run(&argv(&[
                "udisksctl",
                "power-off",
                "--no-user-interaction",
                "-b",
                &drive,
            ]))?;
            steps.push(Step {
                step: format!("power off {drive}"),
                ok: out.ok,
                note: if out.ok {
                    String::new()
                } else {
                    format!(
                        "{} (the partition is unmounted: the drive is safe to remove)",
                        out.stderr.trim()
                    )
                },
            });
        } else {
            steps.push(Step {
                step: format!("power off {drive}"),
                ok: false,
                note: "skipped: udisksctl is missing (the partition is unmounted: the drive is safe to remove)".into(),
            });
        }
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// lsblk of a machine: system disk sda (/, /boot, swap), sdb with a
    /// mounted data partition, sdc an LVM member, sdd an old unmounted
    /// partition (fine), sde a LUKS container open as a mapping, sdf empty.
    const LSBLK: &str = r#"{"blockdevices": [
      {"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":512110190592,"model":"Samsung SSD","serial":"S1","tran":"sata","rm":false,"ro":false,"mountpoints":[null],"fstype":null,"partuuid":null,"label":null,"maj:min":"8:0",
       "children":[
        {"name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part","size":1073741824,"mountpoints":["/boot"],"fstype":"vfat","partuuid":"aaaa0001-0000-4000-8000-000000000001","maj:min":"8:1"},
        {"name":"sda2","kname":"sda2","path":"/dev/sda2","type":"part","size":17179869184,"mountpoints":["[SWAP]"],"fstype":"swap","partuuid":"aaaa0002-0000-4000-8000-000000000002","maj:min":"8:2"},
        {"name":"sda3","kname":"sda3","path":"/dev/sda3","type":"part","size":400000000000,"mountpoints":["/"],"fstype":"ext4","partuuid":"aaaa0003-0000-4000-8000-000000000003","maj:min":"8:3"}]},
      {"name":"sdb","kname":"sdb","path":"/dev/sdb","type":"disk","size":2000398934016,"model":"WD Elements","serial":"W2","tran":"usb","rm":"1","ro":"0","mountpoints":[],
       "children":[{"name":"sdb1","kname":"sdb1","path":"/dev/sdb1","type":"part","size":2000397795328,"mountpoints":["/run/media/me/photos"],"fstype":"exfat","label":"photos","maj:min":"8:17"}]},
      {"name":"sdc","kname":"sdc","path":"/dev/sdc","type":"disk","size":1000204886016,"mountpoints":[],"fstype":"LVM2_member","maj:min":"8:32"},
      {"name":"sdd","kname":"sdd","path":"/dev/sdd","type":"disk","size":4000787030016,"model":"ST4000","serial":"Z3","tran":"sata","rm":false,"mountpoints":[],
       "children":[{"name":"sdd1","kname":"sdd1","path":"/dev/sdd1","type":"part","size":4000785104896,"mountpoints":[],"fstype":"ntfs","label":"Old backup","partuuid":"dddd0001-01","maj:min":"8:49"}]},
      {"name":"sde","kname":"sde","path":"/dev/sde","type":"disk","size":1000204886016,"mountpoints":[],"maj:min":"8:64",
       "children":[{"name":"sde1","kname":"sde1","path":"/dev/sde1","type":"part","size":1000203837440,"mountpoints":[],"fstype":"crypto_LUKS","maj:min":"8:65",
         "children":[{"name":"luks-x","kname":"dm-3","path":"/dev/mapper/luks-x","type":"crypt","size":1000187060224,"mountpoints":[],"fstype":"ext4","maj:min":"254:3"}]}]},
      {"name":"sdf","kname":"sdf","path":"/dev/sdf","type":"disk","size":"8001563222016","model":"WDC WD80","serial":"V4","tran":"usb","rm":true,"mountpoints":[],"maj:min":"8:80"},
      {"name":"sdg","kname":"sdg","path":"/dev/sdg","type":"disk","size":256060514304,"mountpoints":[],"maj:min":"8:96",
       "children":[{"name":"sdg1","kname":"sdg1","path":"/dev/sdg1","type":"part","size":256059465728,"mountpoints":[],"fstype":"swap","maj:min":"8:97"}]},
      {"name":"loop0","kname":"loop0","path":"/dev/loop0","type":"loop","size":4096,"mountpoints":[],"maj:min":"7:0"}
    ]}"#;

    fn facts() -> SystemFacts {
        SystemFacts {
            swaps: parse_swaps(
                "Filename\tType\tSize\tUsed\tPriority\n/dev/sda2 partition 16777212 0 -2\n/dev/sdg1 partition 1 0 -3\n",
            ),
            protected: vec![
                ("the root filesystem".into(), "8:3".into()),
                ("Varsto's directory".into(), "8:3".into()),
            ],
        }
    }

    fn refusal(device: &str) -> String {
        let devs = parse_lsblk(LSBLK).unwrap();
        check_whole_device(&devs, device, &facts())
            .map(|d| d.path.clone())
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn lsblk_json_is_read_leniently() {
        let devs = parse_lsblk(LSBLK).unwrap();
        assert_eq!(devs.len(), 8);
        let sdb = &devs[1];
        assert!(sdb.removable);
        assert!(!sdb.read_only);
        assert_eq!(devs[5].size, 8_001_563_222_016);
        assert!(devs[5].removable);
        assert!(
            devs[0].mountpoints.is_empty(),
            "null mountpoints are dropped"
        );
        assert_eq!(
            find_partition(&devs, "DDDD0001-01").map(|(p, d)| (p.path.as_str(), d.path.as_str())),
            Some(("/dev/sdd1", "/dev/sdd"))
        );
        assert_eq!(
            partition_at(&devs, Path::new("/run/media/me/photos")).map(|(p, _)| p.path.as_str()),
            Some("/dev/sdb1")
        );
    }

    #[test]
    fn the_system_disk_is_refused() {
        let e = refusal("/dev/sda");
        assert!(e.contains("mounted at /boot") || e.contains("swap"), "{e}");
    }

    #[test]
    fn a_drive_with_a_mounted_partition_is_refused() {
        let e = refusal("/dev/sdb");
        assert!(
            e.contains("/dev/sdb1") && e.contains("/run/media/me/photos"),
            "{e}"
        );
    }

    #[test]
    fn swap_lvm_luks_partitions_and_other_kinds_are_refused() {
        assert!(refusal("/dev/sdg").contains("swap"));
        assert!(refusal("/dev/sdc").contains("LVM2_member"));
        assert!(refusal("/dev/sde").contains("crypto_LUKS"));
        let e = refusal("/dev/sdd1");
        assert!(e.contains("partition") && e.contains("/dev/sdd"), "{e}");
        assert!(refusal("/dev/loop0").contains("not a whole drive"));
        assert!(refusal("/dev/nope").contains("not a block device"));
    }

    #[test]
    fn a_drive_holding_varsto_or_the_program_is_refused() {
        let devs = parse_lsblk(LSBLK).unwrap();
        let f = SystemFacts {
            swaps: vec![],
            protected: vec![("the varsto program".into(), "8:49".into())],
        };
        let e = check_whole_device(&devs, "/dev/sdd", &f)
            .unwrap_err()
            .to_string();
        assert!(e.contains("the varsto program"), "{e}");
    }

    #[test]
    fn an_unused_drive_passes_and_is_described() {
        let devs = parse_lsblk(LSBLK).unwrap();
        let d = check_whole_device(&devs, "/dev/sdf", &facts()).unwrap();
        assert_eq!(d.serial, "V4");
        let text = describe(d);
        assert!(text.contains("WDC WD80") && text.contains("serial V4") && text.contains("usb"));
        assert!(text.contains("no partitions"));
        // An old, unmounted NTFS partition is fine: it is shown, then wiped.
        let d = check_whole_device(&devs, "/dev/sdd", &facts()).unwrap();
        assert!(describe(d).contains("ntfs \"Old backup\""));
    }

    #[test]
    fn labels_are_made_safe() {
        assert_eq!(fs_label("Blue 4TB"), "Blue-4TB");
        assert_eq!(fs_label("Musta WD / offsite ääkköset"), "Musta-WD-offsite");
        assert_eq!(fs_label("ÄÄÄ"), "varsto");
        assert!(fs_label("a very long sticker name indeed").len() <= 16);
        assert_eq!(gpt_name("Blue 4TB"), "varsto-Blue 4TB");
        assert_eq!(gpt_name(&"x".repeat(50)).chars().count(), 36);
        let u = new_partuuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert_eq!(
            fallback_mount_dir("Blue 4TB"),
            PathBuf::from("/mnt/varsto-blue-4tb")
        );
    }

    type Answer = Box<dyn FnMut(&[String]) -> Output>;

    /// Answers commands from a script and records them.
    struct Fake {
        calls: Vec<Vec<String>>,
        programs: Vec<&'static str>,
        uid: u32,
        answer: Answer,
    }

    impl Runner for Fake {
        fn run(&mut self, argv: &[String]) -> Result<Output> {
            self.calls.push(argv.to_vec());
            Ok((self.answer)(argv))
        }
        fn has(&self, program: &str) -> bool {
            self.programs.contains(&program)
        }
        fn uid(&self) -> u32 {
            self.uid
        }
    }

    fn ok(stdout: &str) -> Output {
        Output {
            ok: true,
            stdout: stdout.into(),
            stderr: String::new(),
            code: 0,
        }
    }

    #[test]
    fn prepare_runs_one_privileged_script_and_finds_the_partition() {
        let uuid = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
        let u2 = uuid.clone();
        let mut fake = Fake {
            calls: vec![],
            programs: vec![
                "wipefs",
                "sgdisk",
                "mkfs.ext4",
                "udevadm",
                "lsblk",
                "pkexec",
            ],
            uid: 1000,
            answer: Box::new(move |a: &[String]| {
                if a[0] == "lsblk" {
                    ok(&format!(
                        r#"{{"blockdevices":[{{"name":"sdf","path":"/dev/sdf","type":"disk","size":100,"children":[{{"name":"sdf1","path":"/dev/sdf1","type":"part","size":99,"fstype":"ext4","partuuid":"{}"}}]}}]}}"#,
                        u2.borrow()
                    ))
                } else {
                    *u2.borrow_mut() = a[6].clone();
                    ok("step: wipe signatures\nstep: format ext4\nstep: done\n")
                }
            }),
        };
        let r = prepare_drive(&mut fake, "/dev/sdf", "Blue 4TB", (1000, 1000)).unwrap();
        assert_eq!(r.privilege, "pkexec");
        assert_eq!(r.partition, "/dev/sdf1");
        assert_eq!(r.partuuid, *uuid.borrow());
        assert_eq!(r.fs_label, "Blue-4TB");
        assert_eq!(r.steps.len(), 3);
        let script = &fake.calls[0];
        assert_eq!(&script[..3], &["pkexec", "sh", "-c"]);
        // User text travels as arguments only, never inside the script.
        assert_eq!(
            &script[5..],
            &[
                "/dev/sdf",
                &r.partuuid,
                "varsto-Blue 4TB",
                "Blue-4TB",
                "1000:1000",
                "65536"
            ]
        );
        assert!(!script[3].contains("Blue"));
    }

    #[test]
    fn prepare_needs_the_tools_and_reports_a_failed_step() {
        let mut fake = Fake {
            calls: vec![],
            programs: vec!["wipefs", "mkfs.ext4", "udevadm", "lsblk", "sudo"],
            uid: 1000,
            answer: Box::new(|_| ok("")),
        };
        let e = prepare_drive(&mut fake, "/dev/sdf", "x", (1, 1)).unwrap_err();
        assert!(e.to_string().contains("gdisk"), "{e}");
        assert!(fake.calls.is_empty());
        let mut fake = Fake {
            calls: vec![],
            programs: vec!["wipefs", "sgdisk", "mkfs.ext4", "udevadm", "lsblk", "sudo"],
            uid: 1000,
            answer: Box::new(|_| Output {
                ok: false,
                stdout: "step: wipe signatures\n".into(),
                stderr: "sgdisk: cannot open".into(),
                code: 1,
            }),
        };
        let e = prepare_drive(&mut fake, "/dev/sdf", "x", (1, 1))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("after: wipe signatures") && e.contains("sgdisk: cannot open"),
            "{e}"
        );
        assert_eq!(fake.calls[0][0], "sudo");
    }

    #[test]
    fn mount_falls_back_to_sudo_when_udisks_refuses() {
        let listing = r#"{"blockdevices":[{"name":"vdb","path":"/dev/vdb","type":"disk","size":100,"children":[{"name":"vdb1","path":"/dev/vdb1","type":"part","size":99,"fstype":"ext4","partuuid":"abcd-1","mountpoints":[]}]}]}"#;
        let mut fake = Fake {
            calls: vec![],
            programs: vec!["udisksctl", "sudo", "lsblk"],
            uid: 1000,
            answer: Box::new(move |a: &[String]| match a[0].as_str() {
                "lsblk" => ok(listing),
                "udisksctl" => Output {
                    ok: false,
                    stdout: String::new(),
                    stderr: "Not authorized".into(),
                    code: 1,
                },
                _ => ok(""),
            }),
        };
        let (dir, how) = mount_partition(&mut fake, "ABCD-1", "Blue 4TB").unwrap();
        assert_eq!(how, Method::Sudo);
        assert_eq!(dir, PathBuf::from("/mnt/varsto-blue-4tb"));
        let last = fake.calls.last().unwrap();
        assert_eq!(
            last,
            &argv(&[
                "sudo",
                "mount",
                "-o",
                "noatime,nodev,nosuid",
                "/dev/disk/by-partuuid/abcd-1",
                "/mnt/varsto-blue-4tb"
            ])
        );
    }

    #[test]
    fn unmount_syncs_unmounts_and_powers_off() {
        let listing = r#"{"blockdevices":[{"name":"sdf","path":"/dev/sdf","type":"disk","size":100,"children":[{"name":"sdf1","path":"/dev/sdf1","type":"part","size":99,"partuuid":"abcd-1","mountpoints":["/run/media/me/Blue-4TB"]}]}]}"#;
        let mut fake = Fake {
            calls: vec![],
            programs: vec!["udisksctl", "lsblk"],
            uid: 1000,
            answer: Box::new(
                move |a: &[String]| if a[0] == "lsblk" { ok(listing) } else { ok("") },
            ),
        };
        let steps =
            unmount_partition(&mut fake, Path::new("/run/media/me/Blue-4TB"), true).unwrap();
        let names: Vec<&str> = steps.iter().map(|s| s.step.as_str()).collect();
        assert_eq!(
            names,
            [
                "sync",
                "unmount /dev/sdf1 (udisksctl)",
                "sync",
                "power off /dev/sdf"
            ]
        );
        assert!(steps.iter().all(|s| s.ok));
        // Busy: udisks and umount both refuse; the error says what to do.
        let mut fake = Fake {
            calls: vec![],
            programs: vec!["udisksctl", "lsblk", "sudo"],
            uid: 1000,
            answer: Box::new(move |a: &[String]| {
                if a[0] == "lsblk" {
                    ok(listing)
                } else {
                    Output {
                        ok: false,
                        stdout: String::new(),
                        stderr: "target is busy".into(),
                        code: 1,
                    }
                }
            }),
        };
        let e = unmount_partition(&mut fake, Path::new("/run/media/me/Blue-4TB"), false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("target is busy") && e.contains("fuser"), "{e}");
    }

    type Checked = (Result<(PathBuf, Method, FsckOutcome)>, Vec<Vec<String>>);

    /// A drive automounted by the desktop at /run/media/me/Blue; e2fsck exits
    /// with `code`. Returns the result and the commands run.
    fn fsck_with(code: i32, fstype: &'static str) -> Checked {
        let mounted = std::rc::Rc::new(std::cell::Cell::new(true));
        let m2 = mounted.clone();
        let mut fake = Fake {
            calls: vec![],
            programs: vec!["udisksctl", "lsblk", "sudo", "e2fsck"],
            uid: 1000,
            answer: Box::new(move |a: &[String]| {
                match (a[0].as_str(), a.get(1).map(String::as_str)) {
                    ("lsblk", _) => ok(&format!(
                        r#"{{"blockdevices":[{{"name":"sdf","path":"/dev/sdf","type":"disk","size":100,"children":[{{"name":"sdf1","path":"/dev/sdf1","type":"part","size":99,"fstype":"{fstype}","partuuid":"abcd-1","mountpoints":[{}]}}]}}]}}"#,
                        if m2.get() {
                            "\"/run/media/me/Blue\""
                        } else {
                            ""
                        }
                    )),
                    ("udisksctl", Some("unmount")) => {
                        m2.set(false);
                        ok("")
                    }
                    ("udisksctl", Some("mount")) => {
                        m2.set(true);
                        ok("Mounted /dev/sdf1 at /run/media/me/Blue")
                    }
                    ("sudo", Some("e2fsck")) => Output {
                        ok: code == 0,
                        stdout: "Blue: 11/65536 files (0.0% non-contiguous), 5000/262144 blocks"
                            .into(),
                        stderr: if code >= 8 {
                            "e2fsck: Cannot continue, aborting.".into()
                        } else {
                            String::new()
                        },
                        code,
                    },
                    _ => ok(""),
                }
            }),
        };
        let r = check_and_mount(&mut fake, "abcd-1", "Blue", false);
        (r, fake.calls)
    }

    fn ran(calls: &[Vec<String>], what: &[&str]) -> bool {
        calls.iter().any(|c| {
            c.iter()
                .map(String::as_str)
                .take(what.len())
                .eq(what.iter().copied())
        })
    }

    #[test]
    fn a_clean_or_corrected_check_mounts_after_unmounting_the_automount() {
        for (code, verdict) in [
            (0, FsckVerdict::Clean),
            (1, FsckVerdict::Corrected),
            (2, FsckVerdict::Corrected),
            (3, FsckVerdict::Corrected),
        ] {
            let (r, calls) = fsck_with(code, "ext4");
            let (mount, how, out) = r.unwrap();
            assert_eq!(out.verdict, verdict, "exit code {code}");
            assert_eq!(
                (mount, how),
                (PathBuf::from("/run/media/me/Blue"), Method::Udisks)
            );
            // Unmounted, checked, mounted: in that order.
            let unmount = calls
                .iter()
                .position(|c| c[0] == "udisksctl" && c[1] == "unmount")
                .unwrap();
            let check = calls
                .iter()
                .position(|c| c.get(1).is_some_and(|x| x == "e2fsck"))
                .unwrap();
            let mount = calls
                .iter()
                .position(|c| c[0] == "udisksctl" && c[1] == "mount")
                .unwrap();
            assert!(unmount < check && check < mount);
            assert_eq!(
                calls[check],
                argv(&["sudo", "e2fsck", "-f", "-p", "/dev/sdf1"])
            );
            assert_eq!(out.message("Blue").is_some(), code != 0);
            assert!(out.summary.contains("11/65536 files"));
        }
        let (r, _) = fsck_with(1, "ext4");
        let msg = r.unwrap().2.message("Blue").unwrap();
        assert!(
            msg.contains("file system errors were found and corrected"),
            "{msg}"
        );
    }

    #[test]
    fn errors_left_or_a_failed_check_never_mount() {
        for (code, verdict, words) in [
            (
                4,
                FsckVerdict::Uncorrected,
                "could not be repaired automatically",
            ),
            (5, FsckVerdict::Uncorrected, "sudo e2fsck -f /dev/sdf1"),
            (8, FsckVerdict::Failed, "Cannot continue"),
            (12, FsckVerdict::Failed, "exit code 12"),
            (16, FsckVerdict::Failed, "failed"),
            (32, FsckVerdict::Failed, "failed"),
            (128, FsckVerdict::Failed, "failed"),
        ] {
            let (r, calls) = fsck_with(code, "ext4");
            let e = r.unwrap_err();
            let stopped = e.downcast_ref::<FsckStopped>().expect("typed error");
            assert_eq!(stopped.outcome.verdict, verdict, "exit code {code}");
            assert!(e.to_string().contains(words), "{code}: {e}");
            assert!(e.to_string().contains("nothing was read or written"), "{e}");
            assert!(
                !ran(&calls, &["udisksctl", "mount"]) && !ran(&calls, &["sudo", "mount"]),
                "mounted after code {code}"
            );
        }
        assert_eq!(FsckVerdict::of(-1), FsckVerdict::Failed);
    }

    #[test]
    fn only_ext_file_systems_are_checked_and_mounted() {
        let (r, calls) = fsck_with(0, "ntfs");
        let e = r.unwrap_err().to_string();
        assert!(
            e.contains("a ntfs file system") && e.contains("varsto disk init"),
            "{e}"
        );
        assert!(!ran(&calls, &["sudo", "e2fsck"]) && !ran(&calls, &["udisksctl"]));
        let (r, _) = fsck_with(0, "ext3");
        assert!(r.is_ok());
    }
}
