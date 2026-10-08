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
# Where the packages to test come from: the published downloads, or a directory
# of freshly built packages (ARTIFACTS=dist/cloud/artifacts).
ARTIFACTS = pathlib.Path(os.environ["ARTIFACTS"]).resolve() if os.environ.get("ARTIFACTS") else None
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

def rsa_key_id():
    """Scaleway encrypts the Windows administrator password with an RSA key from IAM."""
    for k in scw("iam", "ssh-key", "list"):
        if k.get("name") == os.environ.get("SCW_RSA_KEY_NAME", "orca-rsa"):
            return k["id"]
    raise SystemExit("register an RSA public key in IAM named orca-rsa (scw iam ssh-key create name=orca-rsa public-key=\"$(cat ~/.ssh/id_rsa.pub)\")")


def create_instance(name, itype, image, user_data=None, disk_gb=None):
    args = ["instance", "server", "create", f"zone={ZONE}", f"name={name}", f"type={itype}", f"image={image}", "ip=new", f"tags.0={TAG}"]
    if disk_gb:
        args.append(f"root-volume=sbs:{disk_gb}GB")
    if itype.endswith("-WIN"):
        args.append(f"admin-password-encryption-ssh-key-id={rsa_key_id()}")
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
        if not ip:
            ips = [i.get("address") for i in (s.get("public_ips") or []) if i.get("address") and ":" not in i.get("address", "")]
            ip = ips[0] if ips else None
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


def build_android(args):
    """Debug APK (arm64 + x86_64) built on a Linux machine with the Android SDK and NDK."""
    out = ROOT / "dist" / "cloud" / "android"
    out.mkdir(parents=True, exist_ok=True)
    tarball = source_tarball(ROOT / "dist" / "cloud" / "src.tar.gz")
    name = f"{TAG}-android-{int(time.time())}"
    srv = create_instance(name, args.type or "POP2-8C-32G", "ubuntu_noble", disk_gb=40)  # SDK, NDK and two Rust targets need more than the default disk
    sid = srv["id"]
    try:
        _, ip = wait_running(sid)
        log(f"running at {ip}; waiting for SSH")
        wait_ssh("root", ip)
        run_ssh("root", ip, "mkdir -p /build")
        scp(str(tarball), f"root@{ip}:/build/src.tar.gz")
        scp(str(ROOT / "scripts/cloud-build/remote-android.sh"), f"root@{ip}:/build/remote.sh")
        run_ssh("root", ip, "cd /build && tar xzf src.tar.gz && bash /build/remote.sh")
        scp(f"root@{ip}:/build/varsto/dist/android/*", str(out))
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
    zips = sorted(artifacts_dir().glob("varsto-*-x86_64-pc-windows-gnu.zip"))
    if not zips:
        raise SystemExit(f"no Windows zip in {artifacts_dir()}: run website/build-release.sh first")
    zip_path = zips[-1]
    ud = ROOT / "dist" / "cloud" / "windows-userdata.ps1"
    ud.write_text(WINDOWS_USERDATA.replace("__PUBKEYS__", local_pubkeys()))
    name = f"{TAG}-windows-{int(time.time())}"
    srv = create_instance(name, args.type or "POP2-2C-8G-WIN", "windows_server_2025", user_data=ud)
    sid = srv["id"]
    try:
        ip = ensure_windows_ssh(sid, out)
        run_ssh("Administrator", ip, "powershell -Command \"New-Item -ItemType Directory -Force C:\\build | Out-Null\"")
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
    zones = [args.zone] if args.zone else ["fr-par-1", "fr-par-3"]
    zone = zones[0]
    wanted = args.type or "M4-S"
    if args.wait_for_stock:
        while True:
            found = None
            for z in zones:
                stock = dict(mac_stock(z))
                avail = [n for n, s in stock.items() if s != "no_stock" and (n == wanted or args.any_type)]
                if avail:
                    found = (z, avail[0])
                    break
            if found:
                zone, wanted = found
                log(f"Mac mini {wanted} available in {zone}")
                break
            log("no Mac mini in stock in any zone; checking again in 10 min")
            time.sleep(600)
    tarball = source_tarball(ROOT / "dist" / "cloud" / "src.tar.gz")
    name = f"{TAG}-macos-{int(time.time())}"
    # Apple Silicon servers take no tags: the name prefix identifies ours.
    srv = scw("apple-silicon", "server", "create", f"zone={zone}", f"name={name}", f"type={wanted}", f"project-id={scw('config', 'get', 'default-project-id', json_out=False).strip()}")
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


# ----- cross-platform integration test -------------------------------------------

def scw_s3_env():
    """rclone environment for the Scaleway object storage of this project."""
    access = scw("config", "get", "access-key", json_out=False).strip()
    secret = scw("config", "get", "secret-key", json_out=False).strip()
    env = dict(os.environ)
    env.update({"RCLONE_CONFIG_SCW_TYPE": "s3", "RCLONE_CONFIG_SCW_PROVIDER": "Scaleway", "RCLONE_CONFIG_SCW_REGION": "fr-par",
                "RCLONE_CONFIG_SCW_ENDPOINT": "s3.fr-par.scw.cloud", "RCLONE_CONFIG_SCW_ACCESS_KEY_ID": access,
                "RCLONE_CONFIG_SCW_SECRET_ACCESS_KEY": secret})
    return env, access, secret


def artifacts_dir():
    return ARTIFACTS or (ROOT / "website/public/downloads")


def integration(args):
    """Linux and Windows machines share a temporary bucket: sync both ways through
    S3, then fetch blocks peer-to-peer across the public internet."""
    out = ROOT / "dist" / "cloud" / "integration"
    out.mkdir(parents=True, exist_ok=True)
    linux_tars = sorted(artifacts_dir().glob("varsto-*-x86_64-unknown-linux-musl.tar.gz"))
    win_zips = sorted(artifacts_dir().glob("varsto-*-x86_64-pc-windows-gnu.zip"))
    if not linux_tars or not win_zips:
        raise SystemExit(f"need the Linux tarball and the Windows zip in {artifacts_dir()}")
    env, access, secret = scw_s3_env()
    bucket = f"varsto-it-{int(time.time())}"
    subprocess.run(["rclone", "mkdir", f"scw:{bucket}"], env=env, check=True)
    log(f"bucket {bucket} created")
    ud = ROOT / "dist" / "cloud" / "windows-userdata.ps1"
    ud.write_text(WINDOWS_USERDATA.replace("__PUBKEYS__", local_pubkeys()).replace("C:\\build", "C:\\it"))
    stamp = int(time.time())
    s3 = {"S3_ENDPOINT": "https://s3.fr-par.scw.cloud", "S3_REGION": "fr-par", "S3_BUCKET": bucket, "S3_KEY": access, "S3_SECRET": secret}
    result = {"bucket": bucket}
    created = []
    try:
        # Windows first: it is the slower one to boot, and a refused creation must not leave the other machine behind.
        win = create_instance(f"{TAG}-it-windows-{stamp}", "POP2-2C-8G-WIN", "windows_server_2025", user_data=ud)
        created.append(win["id"])
        lin = create_instance(f"{TAG}-it-linux-{stamp}", "POP2-2C-8G", "ubuntu_noble")
        created.append(lin["id"])
        _, lip = wait_running(lin["id"])
        log(f"linux at {lip}; waiting for SSH")
        wait_ssh("root", lip)
        run_ssh("root", lip, "mkdir -p /it && apt-get install -y -qq python3 >/dev/null 2>&1 || true")
        scp(str(linux_tars[-1]), f"root@{lip}:/it/varsto.tar.gz")
        scp(str(ROOT / "scripts/cloud-build/it-linux.sh"), f"root@{lip}:/it/it.sh")
        envs = " ".join(f"{k}='{v}'" for k, v in s3.items())
        run_ssh("root", lip, f"cd /it && VARSTO_IT_ROLE=owner PUBLIC_IP={lip} {envs} bash /it/it.sh")
        vault_key = subprocess.run(ssh_base("root", lip) + ["cat /it/vault-key"], capture_output=True, text=True, check=True).stdout.strip()
        result["linux_owner"] = "ok"

        wip = ensure_windows_ssh(win["id"], out)
        run_ssh("Administrator", wip, "powershell -Command \"New-Item -ItemType Directory -Force C:\\it | Out-Null\"")
        scp(str(win_zips[-1]), f"Administrator@{wip}:C:/it/varsto-windows.zip")
        scp(str(ROOT / "scripts/cloud-build/it-windows.ps1"), f"Administrator@{wip}:C:/it/it.ps1")
        run_ssh("Administrator", wip, f"powershell -ExecutionPolicy Bypass -File C:\\it\\it.ps1 -VaultKey {vault_key} -S3Endpoint {s3['S3_ENDPOINT']} -S3Region fr-par -S3Bucket {bucket} -S3Key {access} -S3Secret {secret} -PublicIp {wip}")
        result["windows_join_and_sync_via_s3"] = "ok"

        # Linux pulls the Windows file through S3.
        run_ssh("root", lip, "cd /it && ls -d varsto-*/ >/dev/null && b=$(ls -d /it/varsto-*/ | head -1)varsto && VARSTO_PASSPHRASE=integration-test-passphrase $b --home /it/home sync && test -f /it/files/from-windows.bin && sha256sum /it/files/from-windows.bin | cut -c1-64 > /it/from-windows.sha")
        shas = {}
        for host, user, path in ((lip, "root", "/it/from-windows.sha"), (wip, "Administrator", "C:/it/from-windows.sha"), (lip, "root", "/it/from-linux.sha"), (wip, "Administrator", "C:/it/from-linux.sha")):
            shas[(host, path)] = subprocess.run(ssh_base(user, host) + [f"cat {path}" if user == "root" else f"type {path}"], capture_output=True, text=True).stdout.strip()
        ok_w = shas[(lip, "/it/from-windows.sha")] == shas[(wip, "C:/it/from-windows.sha")] and shas[(lip, "/it/from-windows.sha")]
        ok_l = shas[(lip, "/it/from-linux.sha")] == shas[(wip, "C:/it/from-linux.sha")] and shas[(lip, "/it/from-linux.sha")]
        result["linux_to_windows_via_s3"] = "ok" if ok_l else "MISMATCH"
        result["windows_to_linux_via_s3"] = "ok" if ok_w else "MISMATCH"

        # Peer-to-peer across the internet: both services advertise public addresses;
        # a second Linux device joins after the bucket's chunks are gone.
        subprocess.run(["rclone", "purge", f"scw:{bucket}/chunks"], env=env, check=False)
        run_ssh("root", lip, "cd /it && b=$(ls -d /it/varsto-*/ | head -1)varsto && export VARSTO_PASSPHRASE=integration-test-passphrase VARSTO_S3_SECRET='" + secret + "' && $b --home /it/home2 join --name linux-2 --vault-key " + vault_key + f" --storage-name cloud --s3-endpoint {s3['S3_ENDPOINT']} --s3-region fr-par --s3-bucket {bucket} --s3-access-key-id {access} && mkdir -p /it/files2 && $b --home /it/home2 folder attach shared /it/files2 && $b --home /it/home2 p2p enable --port 17894 && $b --home /it/home2 p2p status && $b --home /it/home2 pull shared --json > /it/pull2.json; cat /it/pull2.json")
        pull2 = subprocess.run(ssh_base("root", lip) + ["cat /it/pull2.json"], capture_output=True, text=True).stdout
        try:
            pj = json.loads(pull2)
            result["p2p_pull_after_bucket_emptied"] = {"chunks_from_peers": pj.get("chunks_from_peers"), "unavailable": pj.get("files_unavailable")}
        except json.JSONDecodeError:
            result["p2p_pull_after_bucket_emptied"] = pull2[-400:]
        status = subprocess.run(ssh_base("root", lip) + ["cd /it && b=$(ls -d /it/varsto-*/ | head -1)varsto && VARSTO_PASSPHRASE=integration-test-passphrase $b --home /it/home2 p2p status --json"], capture_output=True, text=True).stdout
        result["p2p_status_from_linux_2"] = status[-600:]
    finally:
        (out / "result.json").write_text(json.dumps(result, indent=2))
        log(f"result: {json.dumps(result, indent=2)}")
        if not args.keep:
            for sid in created:
                delete_instance(sid)
            subprocess.run(["rclone", "purge", f"scw:{bucket}"], env=env, check=False)
            log(f"bucket {bucket} removed")


def shots_linux(args):
    """Screenshots of the Linux tray icon and menu on a virtual desktop."""
    out = ROOT / "dist" / "cloud" / "shots"
    out.mkdir(parents=True, exist_ok=True)
    tars = sorted(artifacts_dir().glob("varsto-*-x86_64-unknown-linux-musl.tar.gz"))
    if not tars:
        raise SystemExit(f"no Linux tarball in {artifacts_dir()}")
    srv = create_instance(f"{TAG}-shots-{int(time.time())}", args.type or "POP2-2C-8G", "ubuntu_noble")
    try:
        _, ip = wait_running(srv["id"])
        log(f"running at {ip}; waiting for SSH")
        wait_ssh("root", ip)
        run_ssh("root", ip, "mkdir -p /it")
        scp(str(tars[-1]), f"root@{ip}:/it/varsto.tar.gz")
        scp(str(ROOT / "scripts/cloud-build/shots-linux.sh"), f"root@{ip}:/it/shots.sh")
        run_ssh("root", ip, "bash /it/shots.sh")
        scp(f"root@{ip}:/it/shots/*", str(out))
        log(f"screenshots in {out}")
    finally:
        if not args.keep:
            delete_instance(srv["id"])


def win_password(server_id):
    """The administrator password Scaleway generated at first boot, decrypted with our RSA key."""
    key = pathlib.Path.home() / ".ssh" / os.environ.get("SCW_RSA_KEY_FILE", "varsto-scw-rsa")
    p = subprocess.run(["scw", "instance", "server", "get-rdp-password", server_id, f"zone={ZONE}", f"key={key}", "-o", "json"], capture_output=True, text=True)
    try:
        d = json.loads(p.stdout) if p.stdout.strip() else {}
    except json.JSONDecodeError:
        d = {}
    pw = (d.get("Password") or d.get("password") or "") if isinstance(d, dict) else ""
    if not pw:
        raise SystemExit("no administrator password yet (cloudbase-init runs about 15 minutes after creation)")
    return pw


def ensure_windows_ssh(win_id, out):
    """Wait for Windows to boot; if OpenSSH is not up a few minutes after the
    administrator password appears, enable it over RDP from a jump machine."""
    s, wip = wait_running(win_id)
    log(f"windows at {wip}; waiting for first boot (password appears after ~15 min)")
    deadline = time.time() + 1800
    pw = None
    while time.time() < deadline:
        try:
            pw = win_password(win_id)
            break
        except SystemExit:
            time.sleep(30)
    if not pw:
        raise SystemExit("Windows administrator password never appeared")
    for _ in range(18):  # three minutes for cloud-init to have done it by itself
        if subprocess.run(["nc", "-z", "-w2", wip, "22"], capture_output=True).returncode == 0:
            log("OpenSSH came up by itself")
            return wip
        time.sleep(10)
    log("OpenSSH not up; enabling it over RDP from a jump machine")
    pub = next(iter(sorted(pathlib.Path.home().joinpath(".ssh").glob("id_ed25519.pub"))), None) or next(pathlib.Path.home().joinpath(".ssh").glob("*.pub"))
    jump = create_instance(f"{TAG}-jump-{int(time.time())}", "POP2-2C-8G", "ubuntu_noble")
    try:
        _, jip = wait_running(jump["id"])
        wait_ssh("root", jip)
        run_ssh("root", jip, "mkdir -p /it")
        scp(str(ROOT / "scripts/cloud-build/win-bootstrap.sh"), f"root@{jip}:/it/win-bootstrap.sh")
        subprocess.run(ssh_base("root", jip) + [f"umask 077 && printf '%s' '{pw}' > /it/winpass"], check=True)
        run_ssh("root", jip, f"export WIN_TOOL=winssh WIN_IP={wip} WIN_PASS=\"$(cat /it/winpass)\" PUBKEY='{pub.read_text().strip()}' && bash /it/win-bootstrap.sh")
        try:
            scp(f"root@{jip}:/it/shots/*", str(out))
        except subprocess.CalledProcessError:
            pass
    finally:
        delete_instance(jump["id"])
    wait_ssh("Administrator", wip, timeout=300)
    return wip


def win_bootstrap(args):
    """Enable OpenSSH on a Windows machine whose first-boot script did not run:
    a Linux jump machine opens an RDP session and types the PowerShell command."""
    if not args.server:
        raise SystemExit("--server <windows instance id> is required")
    win = scw("instance", "server", "get", args.server, f"zone={ZONE}")
    wip = next(i["address"] for i in win.get("public_ips", []) if ":" not in i["address"])
    pw = win_password(args.server)
    pub = next(iter(sorted(pathlib.Path.home().joinpath(".ssh").glob("id_ed25519.pub"))), None) or next(pathlib.Path.home().joinpath(".ssh").glob("*.pub"))
    out = ROOT / "dist" / "cloud" / "shots"
    out.mkdir(parents=True, exist_ok=True)
    jump = create_instance(f"{TAG}-jump-{int(time.time())}", "POP2-2C-8G", "ubuntu_noble")
    try:
        _, jip = wait_running(jump["id"])
        log(f"jump machine at {jip}; waiting for SSH")
        wait_ssh("root", jip)
        run_ssh("root", jip, "mkdir -p /it")
        scp(str(ROOT / "scripts/cloud-build/win-bootstrap.sh"), f"root@{jip}:/it/win-bootstrap.sh")
        # The password goes through a file, not the command line.
        subprocess.run(ssh_base("root", jip) + [f"umask 077 && printf '%s' '{pw}' > /it/winpass"], check=True)
        tool = "winshot" if args.target == "shots-windows" else "winssh"
        run_ssh("root", jip, f"export WIN_TOOL={tool} WIN_IP={wip} WIN_PASS=\"$(cat /it/winpass)\" PUBKEY='{pub.read_text().strip()}' && bash /it/win-bootstrap.sh")
        scp(f"root@{jip}:/it/shots/*", str(out))
        if tool == "winshot":
            # The session script wrote its captures on the Windows machine; fetch them over SSH.
            for _ in range(12):
                p = subprocess.run(["scp", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", f"Administrator@{wip}:C:/shots/*", str(out)], capture_output=True)
                if p.returncode == 0:
                    break
                time.sleep(10)
            log(f"Windows tray screenshots in {out}")
        else:
            log(f"Windows bootstrap done; screenshots in {out}")
            wait_ssh("Administrator", wip, timeout=300)
            log("SSH to the Windows machine works")
    finally:
        if not args.keep:
            delete_instance(jump["id"])


def cleanup(args):
    """Delete tagged machines. Without --all, machines created in the last 90
    minutes are kept, so a cleanup does not kill a job that is still running."""
    import datetime
    for s in scw("instance", "server", "list", f"zone={ZONE}", f"tags.0={TAG}"):
        created = s.get("creation_date", "")
        try:
            age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))).total_seconds()
        except ValueError:
            age = 10 ** 9
        if age < 5400 and not args.all:
            log(f"keeping {s['name']} (created {int(age // 60)} min ago; use --all to delete)")
            continue
        delete_instance(s["id"])
    for zone in ("fr-par-1", "fr-par-3"):
        for s in scw("apple-silicon", "server", "list", f"zone={zone}"):
            if (s.get("name") or "").startswith(f"{TAG}-"):
                log(f"deleting Mac mini {s['id']}")
                subprocess.run(["scw", "apple-silicon", "server", "delete", s["id"], f"zone={zone}"], capture_output=True)
    log("cleanup done")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", choices=["linux", "android", "windows", "macos", "integration", "shots-linux", "win-bootstrap", "shots-windows", "cleanup", "mac-stock"])
    ap.add_argument("--keep", action="store_true", help="do not delete the machine afterwards")
    ap.add_argument("--type", help="instance type (POP2-4C-16G, POP2-2C-8G-WIN, M4-S, ...)")
    ap.add_argument("--zone", help="zone for Mac minis (fr-par-1 or fr-par-3)")
    ap.add_argument("--wait-for-stock", action="store_true", help="macos: poll until a Mac mini is in stock")
    ap.add_argument("--any-type", action="store_true", help="macos: accept any Mac mini type in stock")
    ap.add_argument("--server", help="win-bootstrap: the Windows instance id")
    ap.add_argument("--all", action="store_true", help="cleanup: also delete machines created in the last 90 minutes")
    args = ap.parse_args()
    if shutil.which("scw") is None:
        raise SystemExit("scw command line not found")
    if args.target == "mac-stock":
        for zone in ("fr-par-1", "fr-par-3"):
            print(zone, mac_stock(zone))
        return
    {"linux": build_linux, "android": build_android, "windows": build_windows, "macos": build_macos, "integration": integration, "shots-linux": shots_linux, "win-bootstrap": win_bootstrap, "shots-windows": win_bootstrap, "cleanup": cleanup}[args.target](args)


if __name__ == "__main__":
    main()
