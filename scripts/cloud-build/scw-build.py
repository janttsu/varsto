#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Build and test Varsto on throw-away Scaleway machines.

    scripts/cloud-build/scw-build.py linux    # Ubuntu: full test suite + release archives
    scripts/cloud-build/scw-build.py windows  # Windows Server: smoke-test the Windows zip
    scripts/cloud-build/scw-build.py macos    # Mac mini (Apple Silicon): tests + native app
    scripts/cloud-build/scw-build.py cleanup  # delete anything tagged varsto-build

Needs the `scw` command line configured (scw init) with a project that has
this machine's SSH key registered. Every machine is tagged `varsto-build`
and deleted at the end (also on failure) unless --keep is given. Results
land in dist/cloud/<os>/. Mac minis are billed for 24 hours minimum.
"""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
TAG = "varsto-build"
ZONE = os.environ.get("SCW_ZONE", "fr-par-1")


def scw(*args, json_out=True):
    cmd = ["scw", *args] + (["-o", "json"] if json_out else [])
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"scw {' '.join(args)} failed:\n{p.stderr.strip()}")
    return json.loads(p.stdout) if json_out and p.stdout.strip() else p.stdout


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def source_tarball(dest: pathlib.Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "archive", "--format=tar.gz", "--prefix=varsto/", "-o", str(dest), "HEAD"], cwd=ROOT, check=True)
    return dest


def ssh_base(user, ip, extra=()):
    return ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=10", *extra, f"{user}@{ip}"]


def wait_ssh(user, ip, timeout=600, extra=()):
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = subprocess.run(ssh_base(user, ip, extra) + ["echo ok"], capture_output=True, text=True)
        if p.returncode == 0 and "ok" in p.stdout:
            return True
        time.sleep(10)
    raise SystemExit(f"SSH to {user}@{ip} did not come up in {timeout}s")


def run_ssh(user, ip, cmd, extra=()):
    p = subprocess.run(ssh_base(user, ip, extra) + [cmd], text=True)
    if p.returncode != 0:
        raise SystemExit(f"remote command failed ({p.returncode}): {cmd[:80]}")


def scp(src, dst, extra=()):
    subprocess.run(["scp", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", *extra, "-r", src, dst], check=True)


# ----- Linux / Windows instances ------------------------------------------------

def create_instance(name, itype, image, user_data=None):
    args = ["instance", "server", "create", f"zone={ZONE}", f"name={name}", f"type={itype}", f"image={image}", "ip=new", f"tags.0={TAG}"]
    if user_data:
        args.append(f"cloud-init=@{user_data}")
    srv = scw(*args)
    log(f"created {srv['id']} ({itype}, {image})")
    return srv


def wait_running(server_id, timeout=900):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = scw("instance", "server", "get", server_id, f"zone={ZONE}")
        ip = (s.get("public_ip") or {}).get("address")
        if s.get("state") == "running" and ip:
            return s, ip
        time.sleep(10)
    raise SystemExit("instance did not reach running state")


def delete_instance(server_id):
    log(f"deleting instance {server_id} with its volumes")
    subprocess.run(["scw", "instance", "server", "terminate", server_id, f"zone={ZONE}", "with-ip=true", "with-block=true"], capture_output=True)


def build_linux(args):
    out = ROOT / "dist" / "cloud" / "linux"
    out.mkdir(parents=True, exist_ok=True)
    tarball = source_tarball(ROOT / "dist" / "cloud" / "src.tar.gz")
    name = f"{TAG}-linux-{int(time.time())}"
    srv = create_instance(name, args.type or "POP2-4C-16G", "ubuntu_noble")
    sid = srv["id"]
    try:
        _, ip = wait_running(sid)
        log(f"running at {ip}; waiting for SSH")
        wait_ssh("root", ip)
        run_ssh("root", ip, "mkdir -p /build")
        scp(str(tarball), f"root@{ip}:/build/src.tar.gz")
        scp(str(ROOT / "scripts/cloud-build/remote-linux.sh"), f"root@{ip}:/build/remote.sh")
        run_ssh("root", ip, "cd /build && tar xzf src.tar.gz && bash /build/remote.sh")
        scp(f"root@{ip}:/build/varsto/website/public/downloads/*", str(out))
        log(f"artifacts in {out}")
        for f in sorted(out.iterdir()):
            print(f"  {f.name}  {f.stat().st_size // 1024} KB")
    finally:
        if not args.keep:
            delete_instance(sid)


WINDOWS_USERDATA = r"""#ps1_sysnative
$ErrorActionPreference = "Continue"
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
New-NetFirewallRule -Name sshd -DisplayName "OpenSSH" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
$keys = @"
__PUBKEYS__
"@
Set-Content -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value $keys -Encoding ascii
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
Restart-Service sshd
New-Item -ItemType Directory -Force C:\build | Out-Null
"""


def local_pubkeys():
    keys = []
    for p in pathlib.Path.home().joinpath(".ssh").glob("*.pub"):
        keys.append(p.read_text().strip())
    if not keys:
        raise SystemExit("no ~/.ssh/*.pub key found")
    return "\n".join(keys)


def build_windows(args):
    out = ROOT / "dist" / "cloud" / "windows"
    out.mkdir(parents=True, exist_ok=True)
    zips = sorted((ROOT / "website/public/downloads").glob("varsto-*-x86_64-pc-windows-gnu.zip"))
    if not zips:
        raise SystemExit("no Windows zip in website/public/downloads: run website/build-release.sh first")
    zip_path = zips[-1]
    ud = ROOT / "dist" / "cloud" / "windows-userdata.ps1"
    ud.write_text(WINDOWS_USERDATA.replace("__PUBKEYS__", local_pubkeys()))
    name = f"{TAG}-windows-{int(time.time())}"
    srv = create_instance(name, args.type or "POP2-2C-8G-WIN", "windows_server_2025", user_data=ud)
    sid = srv["id"]
    try:
        _, ip = wait_running(sid)
        log(f"running at {ip}; waiting for Windows to boot and OpenSSH to come up (this takes a few minutes)")
        wait_ssh("Administrator", ip, timeout=1500)
        scp(str(zip_path), f"Administrator@{ip}:C:/build/varsto-windows.zip")
        scp(str(ROOT / "scripts/cloud-build/remote-windows.ps1"), f"Administrator@{ip}:C:/build/remote.ps1")
        run_ssh("Administrator", ip, "powershell -ExecutionPolicy Bypass -File C:\\build\\remote.ps1")
        for f in ("status.json", "service.log"):
            try:
                scp(f"Administrator@{ip}:C:/build/{f}", str(out / f))
            except subprocess.CalledProcessError:
                pass
        log(f"Windows smoke test done; details in {out}")
    finally:
        if not args.keep:
            delete_instance(sid)


# ----- Mac mini ----------------------------------------------------------------

def mac_stock(zone):
    types = scw("apple-silicon", "server-type", "list", f"zone={zone}")
    return [(t["name"], t.get("stock")) for t in types]


def build_macos(args):
    out = ROOT / "dist" / "cloud" / "macos"
    out.mkdir(parents=True, exist_ok=True)
    zone = args.zone or "fr-par-1"
    wanted = args.type or "M4-S"
    if args.wait_for_stock:
        while True:
            stock = dict(mac_stock(zone))
            avail = [n for n, s in stock.items() if s != "no_stock" and (n == wanted or args.any_type)]
            if avail:
                wanted = avail[0]
                break
            log(f"no Mac mini in stock in {zone} ({stock}); checking again in 10 min")
            time.sleep(600)
    tarball = source_tarball(ROOT / "dist" / "cloud" / "src.tar.gz")
    name = f"{TAG}-macos-{int(time.time())}"
    srv = scw("apple-silicon", "server", "create", f"zone={zone}", f"name={name}", f"type={wanted}", f"project-id={scw('config', 'get', 'default-project-id', json_out=False).strip()}", f"tags.0={TAG}")
    sid = srv["id"]
    log(f"created Mac mini {sid} ({wanted}); billed for 24 h minimum; waiting for delivery (10-20 min)")
    try:
        deadline = time.time() + 2400
        while True:
            s = scw("apple-silicon", "server", "get", sid, f"zone={zone}")
            if s.get("status") == "ready" and s.get("ip"):
                break
            if time.time() > deadline:
                raise SystemExit(f"Mac mini not ready: {s.get('status')}")
            time.sleep(20)
        ip, user, password = s["ip"], s.get("ssh_username") or "m1", s.get("sudo_password") or ""
        log(f"ready at {ip} as {user}; waiting for SSH")
        wait_ssh(user, ip, timeout=900)
        run_ssh(user, ip, "mkdir -p ~/build && printf '%s' \"$VARSTO_SUDO\" > /tmp/sudo-pass && chmod 600 /tmp/sudo-pass", extra=("-o", f"SendEnv=VARSTO_SUDO")) if False else None
        # The sudo password is only needed for the Command Line Tools install; pass it through a file.
        subprocess.run(ssh_base(user, ip) + [f"mkdir -p ~/build && umask 077 && printf '%s' '{password}' > /tmp/sudo-pass"], check=True)
        scp(str(tarball), f"{user}@{ip}:build/src.tar.gz")
        scp(str(ROOT / "scripts/cloud-build/remote-macos.sh"), f"{user}@{ip}:build/remote.sh")
        run_ssh(user, ip, "cd ~/build && tar xzf src.tar.gz && bash ~/build/remote.sh")
        scp(f"{user}@{ip}:build/dist/*", str(out))
        log(f"artifacts in {out}")
        for f in sorted(out.iterdir()):
            print(f"  {f.name}  {f.stat().st_size // 1024} KB")
    finally:
        if not args.keep:
            log(f"deleting Mac mini {sid} (the 24 h minimum is billed anyway)")
            subprocess.run(["scw", "apple-silicon", "server", "delete", sid, f"zone={zone}"], capture_output=True)


def cleanup(args):
    for s in scw("instance", "server", "list", f"zone={ZONE}", f"tags.0={TAG}"):
        delete_instance(s["id"])
    for zone in ("fr-par-1", "fr-par-3"):
        for s in scw("apple-silicon", "server", "list", f"zone={zone}"):
            if TAG in (s.get("tags") or []):
                log(f"deleting Mac mini {s['id']}")
                subprocess.run(["scw", "apple-silicon", "server", "delete", s["id"], f"zone={zone}"], capture_output=True)
    log("cleanup done")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", choices=["linux", "windows", "macos", "cleanup", "mac-stock"])
    ap.add_argument("--keep", action="store_true", help="do not delete the machine afterwards")
    ap.add_argument("--type", help="instance type (POP2-4C-16G, POP2-2C-8G-WIN, M4-S, ...)")
    ap.add_argument("--zone", help="zone for Mac minis (fr-par-1 or fr-par-3)")
    ap.add_argument("--wait-for-stock", action="store_true", help="macos: poll until a Mac mini is in stock")
    ap.add_argument("--any-type", action="store_true", help="macos: accept any Mac mini type in stock")
    args = ap.parse_args()
    if shutil.which("scw") is None:
        raise SystemExit("scw command line not found")
    if args.target == "mac-stock":
        for zone in ("fr-par-1", "fr-par-3"):
            print(zone, mac_stock(zone))
        return
    {"linux": build_linux, "windows": build_windows, "macos": build_macos, "cleanup": cleanup}[args.target](args)


if __name__ == "__main__":
    main()
