#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""A small internet in virtual machines, for testing Varsto end to end.

    lab.py up                 networks, VMs, NAT routers (idempotent)
    lab.py services           S3 (rclone serve s3) and STUN on the host, in the background
    lab.py install <tar.gz>   the Linux package's binary into every device VM
    lab.py ssh <vm> [cmd]     a shell or a command on a VM
    lab.py status             what exists
    lab.py down               delete everything the lab created (VMs, disks, networks)

Topology (all libvirt networks are isolated: nothing reaches the real LAN
or the internet):

    vl-wan     198.51.100.0/24 "the internet": the host (.1: S3 on :9900, STUN
                             on :3478), the public server "pub" (.20), and the
                             outside addresses of the two routers (.11, .12)
    vl-home    10.78.1.0/24  a home LAN behind "rhome" (.254, a cone NAT:
                             nftables masquerade): "laptop" (.10), "desktop" (.11)
    vl-office  10.78.2.0/24  an office LAN behind "roffice" (.254, a symmetric
                             NAT: masquerade fully-random): "work" (.10)

The host also holds .1 on the home and office bridges, used for SSH only:
the devices' default route is their router. Routers get a temporary NIC on
libvirt's "default" network to install nftables, removed before any test.

Disks live in a libvirt pool on --dir (default /mnt/ssd/varsto-lab). Every
name starts with "vl-"; `down` touches nothing else.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import socket
import struct
import subprocess
import sys
import time

URI = os.environ.get("VARSTO_LIBVIRT_URI", "qemu:///system")
DIR = pathlib.Path(os.environ.get("VARSTO_LAB_DIR", "/mnt/ssd/varsto-lab"))
POOL = "vl-pool"
BASE_URL = "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
SUMS_URL = "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS"
BASE_FILE = "debian-13-genericcloud-amd64.qcow2"
USER = "varsto"

NETS = {
    # Public-looking addresses (TEST-NET-2, never routed anywhere real):
    # Varsto treats private ranges as LAN, which would hide NAT behaviour.
    "vl-wan": ("198.51.100", "vlwan"),
    "vl-home": ("10.78.1", "vlhome"),
    "vl-office": ("10.78.2", "vloffice"),
}
# name: (memory MiB, [(network, last octet, gateway octet or None)], role)
VMS = {
    "vl-rhome": (512, [("vl-home", 254, None), ("vl-wan", 11, None)], "router-cone"),
    "vl-roffice": (512, [("vl-office", 254, None), ("vl-wan", 12, None)], "router-symmetric"),
    "vl-pub": (1536, [("vl-wan", 20, None)], "device"),
    "vl-laptop": (1536, [("vl-home", 10, 254)], "device"),
    "vl-desktop": (1536, [("vl-home", 11, 254)], "device"),
    "vl-work": (1536, [("vl-office", 10, 254)], "device"),
}
DEVICES = [n for n, v in VMS.items() if v[2] == "device"]
# The build machine is not part of the test network: it sits on libvirt's
# NAT network ("default") to fetch Rust and crates, and builds the static
# musl binary from a copy of the repository.
BUILD_VM = "vl-build"
WAN_HOST = "198.51.100.1"
STUN = [f"{WAN_HOST}:3478", "198.51.100.20:3478"]
S3 = {"endpoint": f"http://{WAN_HOST}:9900", "key": "vlab-access", "secret": "vlab-secret-key-123"}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def sh(cmd, check=True, capture=False, input=None):
    r = subprocess.run(cmd, check=False, text=True, input=input,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE if capture else None)
    if check and r.returncode != 0:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(cmd)}\n{r.stderr or ''}")
    return r


def virsh(*args, check=True, capture=True):
    return sh(["virsh", "-q", "-c", URI, *args], check=check, capture=capture)


def mac_for(vm, i):
    n = sorted(VMS).index(vm)
    return f"52:54:00:78:{n:02x}:{i:02x}"


def key_path():
    return DIR / "id_ed25519"


def ip_of(vm):
    # How the host reaches a VM: its first address on a network the host is on.
    if vm == BUILD_VM:
        out = virsh("domifaddr", BUILD_VM, check=False).stdout
        for line in out.splitlines():
            if "ipv4" in line:
                return line.split()[-1].split("/")[0]
        raise SystemExit("the build VM has no address yet")
    net, octet, _ = VMS[vm][1][-1] if vm.startswith("vl-r") else VMS[vm][1][0]
    return f"{NETS[net][0]}.{octet}"


def ssh_cmd(vm, cmd=None, tty=False):
    base = ["ssh", "-i", str(key_path()), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5"]
    if tty:
        base.append("-t")
    base.append(f"{USER}@{ip_of(vm)}")
    if cmd:
        base.append(cmd)
    return base


def ssh(vm, cmd, check=True, capture=True, input=None):
    return sh(ssh_cmd(vm, cmd), check=check, capture=capture, input=input)


# ----- up ------------------------------------------------------------------------------

def ensure_pool():
    DIR.mkdir(parents=True, exist_ok=True)
    (DIR / "pool").mkdir(exist_ok=True)
    os.chmod(DIR, 0o755)
    os.chmod(DIR / "pool", 0o755)
    if virsh("pool-info", POOL, check=False).returncode != 0:
        virsh("pool-define-as", POOL, "dir", "--target", str(DIR / "pool"))
        virsh("pool-start", POOL)
    virsh("pool-refresh", POOL, check=False)


def ensure_base():
    img = DIR / BASE_FILE
    cached = pathlib.Path.home() / ".cache/varsto-test/images" / BASE_FILE
    if not img.exists():
        if cached.exists():
            shutil.copy(cached, img)
        else:
            log("downloading the Debian cloud image")
            sh(["curl", "-fL", "--retry", "3", "-o", str(img) + ".part", BASE_URL])
            sums = sh(["curl", "-fsSL", SUMS_URL], capture=True).stdout
            want = next(l.split()[0] for l in sums.splitlines() if l.endswith(" " + BASE_FILE))
            got = sh(["sha512sum", str(img) + ".part"], capture=True).stdout.split()[0]
            if want != got:
                raise SystemExit("checksum mismatch for the Debian image")
            os.rename(str(img) + ".part", img)
    base_vol = DIR / "pool" / ("vl-base-" + BASE_FILE)
    if not base_vol.exists():
        shutil.copy(img, base_vol)
        virsh("pool-refresh", POOL)


def ensure_key():
    if not key_path().exists():
        sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "varsto-lab", "-f", str(key_path())])


def ensure_nets():
    for name, (prefix, bridge) in NETS.items():
        if virsh("net-info", name, check=False).returncode == 0:
            if "Active:         yes" not in virsh("net-info", name).stdout:
                virsh("net-start", name)
            continue
        xml = DIR / f"{name}.xml"
        xml.write_text(f"""<network>
  <name>{name}</name>
  <bridge name='{bridge}' stp='off' delay='0'/>
  <ip address='{prefix}.1' netmask='255.255.255.0'/>
</network>
""")
        virsh("net-define", str(xml))
        virsh("net-start", name)


def cloud_init(vm):
    mem, nics, role = VMS[vm]
    st = DIR / "vms" / vm
    st.mkdir(parents=True, exist_ok=True)
    (st / "meta-data").write_text(f"instance-id: {vm}\nlocal-hostname: {vm[3:]}\n")
    pub = (DIR / "id_ed25519.pub").read_text().strip()
    (st / "user-data").write_text(f"""#cloud-config
users:
  - name: {USER}
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - {pub}
ssh_pwauth: false
package_update: false
""")
    eths = {}
    for i, (net, octet, gw) in enumerate(nics):
        e = {"match": {"macaddress": mac_for(vm, i)}, "set-name": f"eth{i}",
             "addresses": [f"{NETS[net][0]}.{octet}/24"]}
        if gw:
            e["routes"] = [{"to": "default", "via": f"{NETS[net][0]}.{gw}"}]
        eths[f"eth{i}"] = e
    if role.startswith("router"):
        # Temporary uplink on libvirt's NAT network, for apt only.
        eths["up0"] = {"match": {"macaddress": mac_for(vm, 9)}, "set-name": "up0", "dhcp4": True}
    (st / "network-config").write_text(json.dumps({"version": 2, "ethernets": eths}, indent=1))
    iso = DIR / "pool" / f"{vm}-seed.iso"
    sh(["xorriso", "-as", "mkisofs", "-quiet", "-output", str(iso), "-volid", "cidata", "-joliet", "-rock",
        str(st / "user-data"), str(st / "meta-data"), str(st / "network-config")])


def define_vm(vm):
    mem, nics, role = VMS[vm]
    disk = DIR / "pool" / f"{vm}.qcow2"
    if not disk.exists():
        sh(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b",
            str(DIR / "pool" / ("vl-base-" + BASE_FILE)), str(disk), "12G"])
    cloud_init(vm)
    ifaces = "".join(
        f"<interface type='network'><source network='{net}'/><mac address='{mac_for(vm, i)}'/><model type='virtio'/></interface>"
        for i, (net, _, _) in enumerate(nics))
    if role.startswith("router"):
        ifaces += f"<interface type='network'><source network='default'/><mac address='{mac_for(vm, 9)}'/><model type='virtio'/></interface>"
    xml = DIR / "vms" / vm / "domain.xml"
    xml.write_text(f"""<domain type='kvm'>
  <name>{vm}</name>
  <memory unit='MiB'>{mem}</memory>
  <vcpu>2</vcpu>
  <os firmware='efi'><type arch='x86_64' machine='q35'>hvm</type><firmware><feature enabled='no' name='secure-boot'/></firmware><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough'/>
  <devices>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='{disk}'/><target dev='vda' bus='virtio'/></disk>
    <disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='{DIR / "pool" / (vm + "-seed.iso")}'/><target dev='sda' bus='sata'/><readonly/></disk>
    {ifaces}
    <controller type='pci' model='pcie-root'/>
    {"<controller type='pci' model='pcie-root-port'/>" * 14}
    <serial type='pty'><target port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>
  </devices>
</domain>
""")
    virsh("define", str(xml))


def wait_ssh(vm, timeout=300):
    end = time.time() + timeout
    while time.time() < end:
        if ssh(vm, "true", check=False).returncode == 0:
            return
        time.sleep(3)
    raise SystemExit(f"{vm} did not accept SSH within {timeout} s")


def setup_router(vm):
    role = VMS[vm][2]
    lan = "eth0"
    wan = "eth1"
    rand = " fully-random" if role == "router-symmetric" else ""
    lan_net = NETS[VMS[vm][1][0][0]][0]
    rules = f"""flush ruleset
table ip nat {{
  chain postrouting {{
    type nat hook postrouting priority srcnat;
    oifname "{wan}" ip saddr {lan_net}.0/24 masquerade{rand}
  }}
}}
table ip filter {{
  chain forward {{
    type filter hook forward priority filter; policy drop;
    iifname "{lan}" oifname "{wan}" accept
    iifname "{wan}" oifname "{lan}" ct state established,related accept
  }}
}}
"""
    have = ssh(vm, "command -v nft", check=False).returncode == 0
    if not have:
        log(f"{vm}: installing nftables")
        ssh(vm, "sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables")
    ssh(vm, "sudo tee /etc/nftables.conf >/dev/null", input=rules)
    ssh(vm, "echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/90-router.conf >/dev/null && sudo sysctl -q -p /etc/sysctl.d/90-router.conf && sudo systemctl enable -q --now nftables && sudo nft -f /etc/nftables.conf")
    # Drop the setup uplink: from now on the router knows only its LAN and the lab's WAN.
    dom = virsh("dumpxml", vm).stdout
    if mac_for(vm, 9) in dom:
        virsh("detach-interface", vm, "network", "--mac", mac_for(vm, 9), "--live", "--config", check=False)
    log(f"{vm}: {'symmetric' if rand else 'cone'} NAT ready")


def setup_device(vm):
    # Nothing to install: the musl binary needs no libraries. A few helpers.
    ssh(vm, "sudo mkdir -p /opt/varsto && sudo chown varsto: /opt/varsto && mkdir -p ~/data")
    if vm == "vl-pub":
        # A second STUN server, on another public address: telling a cone
        # NAT from a symmetric one needs two.
        sh(["scp", "-q", "-i", str(key_path()), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", __file__, f"{USER}@{ip_of(vm)}:/opt/varsto/lab.py"])
        ssh(vm, "sudo systemd-run --unit vl-stun --collect python3 /opt/varsto/lab.py stun-serve --addr 198.51.100.20 >/dev/null 2>&1 || true")


def cmd_up(_a):
    ensure_pool()
    ensure_base()
    ensure_key()
    ensure_nets()
    for vm in VMS:
        if virsh("dominfo", vm, check=False).returncode != 0:
            log(f"defining {vm}")
            define_vm(vm)
        if "running" not in virsh("domstate", vm).stdout:
            virsh("start", vm)
    for vm in VMS:
        wait_ssh(vm)
    for vm in VMS:
        if VMS[vm][2].startswith("router"):
            setup_router(vm)
        else:
            setup_device(vm)
    log("lab is up")
    cmd_status(None)


# ----- host services ---------------------------------------------------------------------

def stun_server(addr):
    """A minimal RFC 5389 STUN server: answers Binding requests with the
    source address (XOR-MAPPED-ADDRESS), which is what NAT discovery needs."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(addr)
    magic = 0x2112A442
    while True:
        data, (ip, port) = s.recvfrom(2048)
        if len(data) < 20:
            continue
        mtype, mlen, cookie = struct.unpack("!HHI", data[:8])
        tid = data[8:20]
        if mtype != 0x0001 or cookie != magic:
            continue
        xport = port ^ (magic >> 16)
        xip = struct.unpack("!I", socket.inet_aton(ip))[0] ^ magic
        attr = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, xport, xip)
        s.sendto(struct.pack("!HHI", 0x0101, len(attr), magic) + tid + attr, (ip, port))


def cmd_services(a):
    # Never two of each: stop the ones a previous call started first, or the
    # old S3 server keeps the port and "the storage is down" tests see it up.
    cmd_services_stop(a)
    run = DIR / "run"
    run.mkdir(exist_ok=True)
    s3dir = DIR / "s3"
    s3dir.mkdir(exist_ok=True)
    pids = {}
    p = subprocess.Popen(["rclone", "serve", "s3", "--addr", f"{WAN_HOST}:9900",
                          "--auth-key", f"{S3['key']},{S3['secret']}", "--vfs-cache-mode", "off",
                          "--dir-cache-time", "5s",
                          str(s3dir)], stdout=open(run / "s3.log", "a"), stderr=subprocess.STDOUT,
                         start_new_session=True)
    pids["s3"] = p.pid
    p = subprocess.Popen([sys.executable, __file__, "stun-serve"], stdout=open(run / "stun.log", "a"),
                         stderr=subprocess.STDOUT, start_new_session=True)
    pids["stun"] = p.pid
    (run / "pids.json").write_text(json.dumps(pids))
    time.sleep(1.5)
    log(f"S3 at {S3['endpoint']} (bucket dirs under {s3dir}), STUN at {WAN_HOST}:3478; pids {pids}")


def cmd_services_stop(_a):
    f = DIR / "run" / "pids.json"
    if f.exists():
        for name, pid in json.loads(f.read_text()).items():
            try:
                os.kill(pid, 15)
                log(f"stopped {name} ({pid})")
            except ProcessLookupError:
                pass
        f.unlink()


# ----- install, ssh, status, down ------------------------------------------------------

def cmd_install(a):
    tar = pathlib.Path(a.package)
    work = DIR / "pkg"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    sh(["tar", "-C", str(work), "-xzf", str(tar)])
    binp = next(work.rglob("varsto"))
    for vm in DEVICES:
        sh(["scp", "-q", "-i", str(key_path()), "-o", "StrictHostKeyChecking=no", "-o",
            "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", str(binp), f"{USER}@{ip_of(vm)}:/opt/varsto/varsto"])
        v = ssh(vm, "sudo ln -sf /opt/varsto/varsto /usr/local/bin/varsto && varsto --version").stdout.strip()
        log(f"{vm}: {v}")


def cmd_build(a):
    """Build `varsto` (static, musl) from the repository at a.repo in the
    build VM and copy it to <dir>/varsto-musl."""
    ensure_pool()
    ensure_base()
    ensure_key()
    if virsh("dominfo", BUILD_VM, check=False).returncode != 0:
        disk = DIR / "pool" / f"{BUILD_VM}.qcow2"
        if not disk.exists():
            sh(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b",
                str(DIR / "pool" / ("vl-base-" + BASE_FILE)), str(disk), "40G"])
        st = DIR / "vms" / BUILD_VM
        st.mkdir(parents=True, exist_ok=True)
        (st / "meta-data").write_text(f"instance-id: {BUILD_VM}\nlocal-hostname: build\n")
        pub = (DIR / "id_ed25519.pub").read_text().strip()
        (st / "user-data").write_text(f"""#cloud-config
users:
  - name: {USER}
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - {pub}
ssh_pwauth: false
""")
        iso = DIR / "pool" / f"{BUILD_VM}-seed.iso"
        sh(["xorriso", "-as", "mkisofs", "-quiet", "-output", str(iso), "-volid", "cidata", "-joliet",
            "-rock", str(st / "user-data"), str(st / "meta-data")])
        xml = st / "domain.xml"
        xml.write_text(f"""<domain type='kvm'>
  <name>{BUILD_VM}</name>
  <memory unit='MiB'>8192</memory>
  <vcpu>8</vcpu>
  <os firmware='efi'><type arch='x86_64' machine='q35'>hvm</type><firmware><feature enabled='no' name='secure-boot'/></firmware><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough'/>
  <devices>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='{disk}'/><target dev='vda' bus='virtio'/></disk>
    <disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='{iso}'/><target dev='sda' bus='sata'/><readonly/></disk>
    <interface type='network'><source network='default'/><model type='virtio'/></interface>
    <serial type='pty'><target port='0'/></serial>
    <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>
  </devices>
</domain>
""")
        virsh("define", str(xml))
    if "running" not in virsh("domstate", BUILD_VM).stdout:
        virsh("start", BUILD_VM)
    end = time.time() + 300
    while True:
        try:
            if ssh(BUILD_VM, "true", check=False).returncode == 0:
                break
        except SystemExit:
            pass
        if time.time() > end:
            raise SystemExit("the build VM did not come up")
        time.sleep(3)
    if ssh(BUILD_VM, "test -x ~/.cargo/bin/cargo", check=False).returncode != 0:
        log("build VM: installing Rust and musl-tools (once)")
        ssh(BUILD_VM, "sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential musl-tools rsync curl pkg-config >/dev/null "
                      "&& curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal --target x86_64-unknown-linux-musl >/dev/null")
    repo = pathlib.Path(a.repo).resolve()
    sh(["rsync", "-a", "--delete", "--exclude", "target", "--exclude", ".git", "--exclude", "website/public",
        "-e", "ssh -i " + str(key_path()) + " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR",
        str(repo) + "/", f"{USER}@{ip_of(BUILD_VM)}:src/"])
    log("build VM: cargo build --release --target x86_64-unknown-linux-musl")
    r = ssh(BUILD_VM, "cd src && ~/.cargo/bin/cargo build -q --release --locked -p varsto-cli --features software-key --target x86_64-unknown-linux-musl 2>&1 | tail -20", check=False, capture=True)
    if r.returncode != 0 or ssh(BUILD_VM, "test -x src/target/x86_64-unknown-linux-musl/release/varsto", check=False).returncode != 0:
        raise SystemExit("build failed:\n" + (r.stdout or "") + (r.stderr or ""))
    sh(["scp", "-q", "-i", str(key_path()), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", f"{USER}@{ip_of(BUILD_VM)}:src/target/x86_64-unknown-linux-musl/release/varsto",
        str(DIR / "varsto-musl")])
    log(f"built {DIR / 'varsto-musl'}")


def cmd_release(a):
    """Build the release packages that do not need a Mac in the build VM:
    the Linux (musl) and Windows (gnu) archives with website/build-release.sh
    and the Android APK with apps/android/build.sh (JDK, SDK and NDK are
    installed once). Copies them to <dir>/release/<version>/."""
    cmd_build(a)  # VM up, Rust present, sources synced
    q = "sudo DEBIAN_FRONTEND=noninteractive"
    if ssh(BUILD_VM, "command -v x86_64-w64-mingw32-gcc && command -v zip && command -v javac", check=False).returncode != 0:
        log("build VM: installing mingw-w64, zip and a JDK (once)")
        ssh(BUILD_VM, f"{q} apt-get install -y -qq mingw-w64 zip unzip openjdk-21-jdk-headless >/dev/null")
    ssh(BUILD_VM, "~/.cargo/bin/rustup target add x86_64-pc-windows-gnu aarch64-linux-android x86_64-linux-android >/dev/null 2>&1")
    sdk = "/home/" + USER + "/android-sdk"
    if ssh(BUILD_VM, f"test -d {sdk}/ndk", check=False).returncode != 0:
        log("build VM: installing the Android SDK and NDK (once)")
        ssh(BUILD_VM, f"set -e; mkdir -p {sdk}/cmdline-tools && cd /tmp && curl -fsSL -o ct.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip "
                      f"&& unzip -q -o ct.zip -d {sdk}/cmdline-tools && rm -rf {sdk}/cmdline-tools/latest && mv {sdk}/cmdline-tools/cmdline-tools {sdk}/cmdline-tools/latest "
                      f"&& (yes | {sdk}/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null 2>&1 || true) "
                      f"&& {sdk}/cmdline-tools/latest/bin/sdkmanager --install platform-tools 'platforms;android-35' 'build-tools;34.0.0' 'build-tools;35.0.0' 'ndk;27.2.12479018' >/dev/null")
    env = f"export PATH=$HOME/.cargo/bin:$PATH ANDROID_HOME={sdk};"
    log("build VM: Linux and Windows packages")
    r = ssh(BUILD_VM, f"{env} cd src && website/build-release.sh x86_64-unknown-linux-musl x86_64-pc-windows-gnu 2>&1 | tail -15", check=False, capture=True)
    print(r.stdout, r.stderr)
    log("build VM: Android APK")
    r2 = ssh(BUILD_VM, f"{env} cd src && apps/android/build.sh 2>&1 | grep -vE '^\\s*(Compiling|Downloading|Downloaded)' | tail -15", check=False, capture=True)
    print(r2.stdout, r2.stderr)
    version = re.search(r'^version\s*=\s*"([^"]+)"', (pathlib.Path(a.repo) / "Cargo.toml").read_text(), re.M).group(1)
    out = DIR / "release" / version
    out.mkdir(parents=True, exist_ok=True)
    scp = ["scp", "-q", "-i", str(key_path()), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"]
    host = f"{USER}@{ip_of(BUILD_VM)}"
    sh(scp + [f"{host}:src/website/public/downloads/varsto-{version}-*", str(out)], check=False)
    sh(scp + [f"{host}:src/apps/android/app/build/outputs/apk/debug/app-debug.apk", str(out / f"varsto-{version}-android-debug.apk")], check=False)
    for f in sorted(out.iterdir()):
        log(f"release: {f.name} {f.stat().st_size // 1024} KiB")


def cmd_install_bin(a):
    """Copy a binary (default: the last build) into every device VM."""
    binp = pathlib.Path(a.binary or DIR / "varsto-musl")
    for vm in DEVICES:
        sh(["scp", "-q", "-i", str(key_path()), "-o", "StrictHostKeyChecking=no", "-o",
            "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", str(binp), f"{USER}@{ip_of(vm)}:/opt/varsto/varsto.new"])
        v = ssh(vm, "mv /opt/varsto/varsto.new /opt/varsto/varsto && chmod 755 /opt/varsto/varsto && sudo ln -sf /opt/varsto/varsto /usr/local/bin/varsto && varsto --version").stdout.strip()
        log(f"{vm}: {v}")


def cmd_ssh(a):
    if a.cmd:
        r = sh(ssh_cmd(a.vm, " ".join(a.cmd)), check=False)
        sys.exit(r.returncode)
    os.execvp("ssh", ssh_cmd(a.vm, tty=True))


def cmd_status(_a):
    for vm in VMS:
        st = virsh("domstate", vm, check=False).stdout.strip() or "absent"
        print(f"{vm:12} {st:10} {ip_of(vm)}  {VMS[vm][2]}")


def cmd_down(a):
    cmd_services_stop(None)
    for vm in list(VMS) + ([BUILD_VM] if getattr(a, "all", False) else []):
        virsh("destroy", vm, check=False)
        virsh("undefine", vm, "--nvram", check=False)
        for f in (DIR / "pool").glob(f"{vm}*"):
            f.unlink()
        shutil.rmtree(DIR / "vms" / vm, ignore_errors=True)
    for net in NETS:
        virsh("net-destroy", net, check=False)
        virsh("net-undefine", net, check=False)
    log("lab removed (the base image, the SSH key and the S3 directory are kept)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("up").set_defaults(f=cmd_up)
    sub.add_parser("services").set_defaults(f=cmd_services)
    sub.add_parser("services-stop").set_defaults(f=cmd_services_stop)
    p = sub.add_parser("stun-serve")
    p.add_argument("--addr", default=WAN_HOST)
    p.set_defaults(f=lambda a: stun_server((a.addr, 3478)))
    p = sub.add_parser("install")
    p.add_argument("package")
    p.set_defaults(f=cmd_install)
    p = sub.add_parser("build")
    here = pathlib.Path(__file__).resolve()
    p.add_argument("repo", nargs="?", default=str(here.parents[3]) if len(here.parents) > 3 else ".")
    p.set_defaults(f=cmd_build)
    p = sub.add_parser("release")
    p.add_argument("--repo", default=str(pathlib.Path(__file__).resolve().parents[3]))
    p.set_defaults(f=cmd_release)
    p = sub.add_parser("install-bin")
    p.add_argument("binary", nargs="?")
    p.set_defaults(f=cmd_install_bin)
    p = sub.add_parser("ssh")
    p.add_argument("vm")
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    p.set_defaults(f=cmd_ssh)
    sub.add_parser("status").set_defaults(f=cmd_status)
    p = sub.add_parser("down")
    p.add_argument("--all", action="store_true", help="also the build VM")
    p.set_defaults(f=cmd_down)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
