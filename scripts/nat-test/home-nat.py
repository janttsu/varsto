#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Peer-to-peer through real NATs: this machine (behind a home router) with
machines in other countries, one of them hosting devices behind a cone NAT
and a symmetric NAT.

    home-nat.py up [--type DEV1-M]      bucket in fr-par, machines in nl-ams-1 and pl-waw-1
    home-nat.py setup --package <linux tar.gz>   binary and NAT namespaces on the machines
    home-nat.py vault                   vault on Amsterdam (public, the relay); the
                                        Warsaw devices and this machine join it
    home-nat.py run [--mb 64]           transfers in every direction, from peers only
    home-nat.py shots --out <dir>       this machine's interface (Peers, traffic) during a transfer
    home-nat.py down                    delete the machines and the bucket
    home-nat.py local-reset             stop this machine's service, move its vault aside

Devices: "ams" (public address, reachable, so the relay), "waw-cone" and
"waw-sym" (network namespaces behind iptables NAT on the Warsaw machine:
MASQUERADE, and MASQUERADE --random-fully for a symmetric mapping) and
"home" (this machine, the installed `varsto` and its background service,
whatever NAT the home connection has). The bucket holds the ledger and the
rendezvous records only: before every pull its chunks are deleted, so every
block has to come from a peer; a transfer counts only when the file arrives
with the right SHA-256 and the pull reports every chunk from peers.

This machine's Varsto is used for real: `vault` joins it to the test vault
(after `local-reset` when it holds another one). Results: <work>/results.jsonl.
Needs the `scw` command line, rclone and this machine's SSH key in the project.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import secrets
import shlex
import shutil
import subprocess
import sys
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
_spec = importlib.util.spec_from_file_location("scw_build", ROOT / "scripts/cloud-build/scw-build.py")
sb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sb)
log = sb.log
TAG = sb.TAG
ZONES = {"ams": "nl-ams-1", "waw": "pl-waw-1"}
# device -> (machine, namespace, home on the machine)
REMOTE = {"ams": ("ams", "-", "/nat/h-ams"), "waw-cone": ("waw", "natc", "/nat/h-cone"), "waw-sym": ("waw", "nats", "/nat/h-sym")}
PORT = 17893
FOLDER = "nat"


def local_home():
    return pathlib.Path(os.environ.get("VARSTO_HOME") or (pathlib.Path.home() / ".local/share/varsto"))


def local_bin():
    return shutil.which("varsto") or str(pathlib.Path.home() / ".local/bin/varsto")


class Rig:
    def __init__(self, args):
        self.args = args
        self.work = pathlib.Path(args.work).resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.state_file = self.work / "state.json"
        self.state = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}

    def save(self):
        self.state_file.write_text(json.dumps(self.state, indent=2))
        os.chmod(self.state_file, 0o600)

    def ip(self, m):
        return self.state["nodes"][m]["ip"]

    def ssh(self, m, cmd, check=True):
        p = subprocess.run(sb.ssh_base("root", self.ip(m)) + [cmd], capture_output=True, text=True)
        if check and p.returncode != 0:
            what = "(command with credentials)" if "VARSTO_S3_SECRET" in cmd else cmd
            raise SystemExit(f"{m}: remote command failed ({p.returncode}): {what[:80]}\n{(p.stderr or '')[-1500:]}")
        return p.stdout

    def node(self, m, *a, env=""):
        return self.ssh(m, f"{env} bash /nat/nat-node.sh " + " ".join(shlex.quote(x) for x in a))

    def record(self, entry):
        entry["utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(self.work / "results.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")

    # ----- S3 -----------------------------------------------------------------

    def s3(self):
        return sb.scw_s3_env()  # env, access, secret

    def s3_flags(self):
        _, access, _ = self.s3()
        return ["--storage-name", "cloud", "--s3-endpoint", "https://s3.fr-par.scw.cloud", "--s3-region", "fr-par",
                "--s3-bucket", self.state["bucket"], "--s3-access-key-id", access]

    def purge_chunks(self):
        env, _, _ = self.s3()
        subprocess.run(["rclone", "purge", f"scw:{self.state['bucket']}/chunks"], env=env, capture_output=True)

    # ----- machines -----------------------------------------------------------

    def up(self):
        stamp = int(time.time())
        env, _, _ = self.s3()
        if "bucket" not in self.state:
            self.state["bucket"] = f"varsto-nat-{stamp}"
            subprocess.run(["rclone", "mkdir", f"scw:{self.state['bucket']}"], env=env, check=True)
            self.save()
            log(f"bucket {self.state['bucket']}")
        nodes = self.state.setdefault("nodes", {})
        for m, zone in ZONES.items():
            if m in nodes:
                continue
            srv = sb.scw("instance", "server", "create", f"zone={zone}", f"name={TAG}-nat-{m}-{stamp}",
                         f"type={self.args.type}", "image=ubuntu_noble", "ip=new", f"tags.0={TAG}")
            nodes[m] = {"id": srv["id"], "zone": zone}
            self.save()
            log(f"{m}: created in {zone}")
        for m, n in nodes.items():
            deadline = time.time() + 900
            while time.time() < deadline:
                s = sb.scw("instance", "server", "get", n["id"], f"zone={n['zone']}")
                ips = [i.get("address") for i in (s.get("public_ips") or []) if i.get("address") and ":" not in i["address"]]
                ip = (s.get("public_ip") or {}).get("address") or (ips[0] if ips else None)
                if s.get("state") == "running" and ip:
                    n["ip"] = ip
                    break
                time.sleep(10)
            else:
                raise SystemExit(f"{m} did not start")
            self.save()
            log(f"{m}: running at {n['ip']}")
        for m in nodes:
            sb.wait_ssh("root", self.ip(m))
        log("machines answer SSH")

    def down(self):
        env, _, _ = self.s3()
        for m, n in self.state.get("nodes", {}).items():
            subprocess.run(["scw", "instance", "server", "terminate", n["id"], f"zone={n['zone']}", "with-ip=true", "with-block=true"],
                           capture_output=True)
            log(f"{m}: terminated")
        if self.state.get("bucket"):
            subprocess.run(["rclone", "purge", f"scw:{self.state['bucket']}"], env=env, check=False)
            log(f"bucket {self.state['bucket']} removed")
        time.sleep(15)
        left = {z: [s["name"] for s in sb.scw("instance", "server", "list", f"zone={z}") if (s.get("name") or "").startswith(f"{TAG}-nat-")]
                for z in ZONES.values()}
        log(f"NAT test machines left: {left}")
        self.state.pop("nodes", None)
        self.state.pop("bucket", None)
        self.save()

    def setup(self):
        pkg = pathlib.Path(self.args.package)
        for m in self.state["nodes"]:
            self.ssh(m, "mkdir -p /nat")
            sb.scp(str(pkg), f"root@{self.ip(m)}:/nat/pkg.tar.gz")
            sb.scp(str(HERE / "nat-node.sh"), f"root@{self.ip(m)}:/nat/nat-node.sh")
            log(f"{m}: " + self.node(m, "setup").strip().replace("\n", " | "))

    # ----- devices ------------------------------------------------------------

    def remote(self, dev, *a, env=""):
        m, ns, home = REMOTE[dev]
        return self.node(m, "run", ns, home, *a, env=f"VARSTO_PASSPHRASE={shlex.quote(self.state['pass'])} {env}")

    def api(self, dev, method, path, body=None):
        if dev == "home":
            sj = json.loads((local_home() / "service.json").read_text())
            req = urllib.request.Request(f"http://127.0.0.1:{sj['port']}{path}", method=method,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"X-Varsto-Token": sj["token"], "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=1800) as r:
                return json.loads(r.read() or b"null")
        m, ns, home = REMOTE[dev]
        out = self.node(m, "api", ns, home, method, path, json.dumps(body) if body is not None else "")
        return json.loads(out) if out.strip() else None

    def local(self, *a, env=None):
        e = dict(os.environ, VARSTO_PASSPHRASE=self.state["pass"])
        e.update(env or {})
        p = subprocess.run([local_bin(), "--home", str(local_home()), *a], capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)
        if p.returncode != 0:
            raise SystemExit(f"home: varsto {a[0]} failed: {p.stderr[-1500:]}")
        return p.stdout

    def vault(self):
        _, _, secret = self.s3()
        self.state.setdefault("pass", "nat-" + secrets.token_hex(12))
        self.save()
        sec = f"VARSTO_S3_SECRET={shlex.quote(secret)}"
        if (local_home() / "vault.json").exists() and not self.state.get("home_joined"):
            raise SystemExit(f"{local_home()} already holds a vault: run local-reset first")
        # Amsterdam: owner, public and reachable, so it relays for the others.
        if "vault_key" not in self.state:
            out = self.remote("ams", "init", "--name", "ams", "--json")
            self.state["vault_key"] = json.loads(out)["vault_key"]
            self.save()
            _, access, _ = self.s3()
            self.remote("ams", "storage", "add-s3", "cloud", "--endpoint", "https://s3.fr-par.scw.cloud", "--region", "fr-par",
                        "--bucket", self.state["bucket"], "--access-key-id", access, env=sec)
            self.ssh("ams", "mkdir -p /nat/f-ams")
            self.remote("ams", "folder", "add", FOLDER, "/nat/f-ams")
            self.remote("ams", "p2p", "enable", "--port", str(PORT), "--public", f"{self.ip('ams')}:{PORT}")
            self.node("ams", "service", "-", "/nat/h-ams")
            log("ams: vault, storage, folder, p2p with its public address; service started")
        for dev in ("waw-cone", "waw-sym"):
            m, ns, home = REMOTE[dev]
            if self.state.get(f"{dev}_joined"):
                continue
            self.remote(dev, "join", "--name", dev, "--vault-key", self.state["vault_key"], *self.s3_flags(), env=sec)
            self.ssh(m, f"mkdir -p /nat/f-{dev}")
            self.remote(dev, "folder", "attach", FOLDER, f"/nat/f-{dev}")
            self.remote(dev, "p2p", "enable", "--port", str(PORT))
            self.node(m, "service", ns, home)
            self.state[f"{dev}_joined"] = True
            self.save()
            log(f"{dev}: joined behind {'a cone' if ns == 'natc' else 'a symmetric'} NAT; service started")
        if not self.state.get("home_joined"):
            files = pathlib.Path(self.args.home_folder).expanduser()
            files.mkdir(parents=True, exist_ok=True)
            self.local("join", "--name", "home", "--vault-key", self.state["vault_key"], *self.s3_flags(), env={"VARSTO_S3_SECRET": secret})
            self.local("folder", "attach", FOLDER, str(files))
            self.local("p2p", "enable", "--port", str(PORT))
            self.state["home_joined"] = True
            self.state["home_folder"] = str(files)
            self.save()
            log(f"home: joined, folder at {files}")
        self.restart_local_service()

    def restart_local_service(self):
        if subprocess.run(["systemctl", "--user", "cat", "varsto.service"], capture_output=True).returncode == 0:
            subprocess.run(["systemctl", "--user", "restart", "varsto.service"], check=True)
        else:
            self.local("install")
        for _ in range(60):
            try:
                st = self.api("home", "GET", "/api/state")
                break
            except Exception:
                time.sleep(1)
        else:
            raise SystemExit("home: the background service does not answer")
        if not st.get("unlocked"):
            self.api("home", "POST", "/api/unlock", {"passphrase": self.state["pass"]})
        log(f"home: background service {st.get('version')} running, unlocked")

    # ----- transfers ----------------------------------------------------------

    def folder_of(self, dev):
        return self.state["home_folder"] if dev == "home" else f"/nat/f-{dev}"

    def write(self, dev, name, mb):
        if dev == "home":
            p = pathlib.Path(self.state["home_folder"]) / name
            h = hashlib.sha256()
            with open(p, "wb") as f:
                for _ in range(mb):
                    b = os.urandom(1 << 20)
                    f.write(b)
                    h.update(b)
            return h.hexdigest()
        m = REMOTE[dev][0]
        return self.ssh(m, f"head -c {mb}M /dev/urandom > {self.folder_of(dev)}/{name} && sha256sum {self.folder_of(dev)}/{name}").split()[0]

    def sha(self, dev, name):
        if dev == "home":
            p = pathlib.Path(self.state["home_folder"]) / name
            if not p.exists():
                return None
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for b in iter(lambda: f.read(1 << 20), b""):
                    h.update(b)
            return h.hexdigest()
        out = self.ssh(REMOTE[dev][0], f"sha256sum {self.folder_of(dev)}/{name} 2>/dev/null || true").split()
        return out[0] if out else None

    def paths(self, dev):
        p = self.api(dev, "GET", "/api/p2p") or {}
        return {"nat": p.get("nat"), "reachable": p.get("reachable"), "public": p.get("public"),
                "paths": p.get("paths"), "relays": p.get("relays")}

    def transfer(self, src, dst, mb):
        name = f"{src}-to-{dst}-{int(time.time())}.bin"
        want = self.write(src, name, mb)
        r = self.api(src, "POST", "/api/sync", {"folder": FOLDER})
        self.purge_chunks()
        t0 = time.time()
        r = self.api(dst, "POST", "/api/sync", {"folder": FOLDER})
        secs = time.time() - t0
        pulls = [x.get("pull", {}) for x in (r if isinstance(r, list) else [r]) if isinstance(x, dict)]
        down = sum(p.get("chunks_downloaded", 0) for p in pulls)
        peers = sum(p.get("chunks_from_peers", 0) for p in pulls)
        got = self.sha(dst, name)
        ok = got == want and down > 0 and peers == down
        entry = {"kind": "transfer", "src": src, "dst": dst, "mb": mb, "seconds": round(secs, 1),
                 "mb_s": round(mb / secs, 2) if secs else None, "chunks": down, "from_peers": peers,
                 "sha_ok": got == want, "ok": ok, "dst_p2p": self.paths(dst)}
        self.record(entry)
        route = [f"{x.get('name')}: {x.get('path')} {x.get('addr') or ''}".strip() for x in (entry["dst_p2p"].get("paths") or [])]
        log(f"{src} -> {dst}: {'OK' if ok else 'FAILED'} {mb} MB in {secs:.1f} s ({entry['mb_s']} MB/s), "
            f"{peers}/{down} chunks from peers; routes at {dst}: {route}")
        return entry

    def run(self):
        mb = self.args.mb
        for dev in ("home", "ams", "waw-cone", "waw-sym"):
            p = self.paths(dev)
            self.record({"kind": "nat", "device": dev, **p})
            log(f"{dev}: nat={p['nat']} reachable={p['reachable']} public={p['public']}")
        pairs = [("home", "ams"), ("ams", "home"), ("waw-cone", "home"), ("home", "waw-cone"),
                 ("waw-sym", "home"), ("home", "waw-sym"), ("waw-sym", "waw-cone")]
        if self.args.only:
            pairs = [p for p in pairs if f"{p[0]}:{p[1]}" in self.args.only.split(",")]
        results = [self.transfer(s, d, mb) for s, d in pairs]
        log(f"{sum(r['ok'] for r in results)}/{len(results)} transfers from peers only, every file intact")

    # ----- screenshots of this machine's interface --------------------------

    def shots(self):
        from playwright.sync_api import sync_playwright
        out = pathlib.Path(self.args.out)
        out.mkdir(parents=True, exist_ok=True)
        sj = json.loads((local_home() / "service.json").read_text())
        url = f"http://127.0.0.1:{sj['port']}/?token={sj['token']}"
        import threading
        t = threading.Thread(target=self.transfer, args=("waw-cone", "home", self.args.mb))
        t.start()
        time.sleep(self.args.delay)
        with sync_playwright() as p:
            exe = os.environ.get("CHROMIUM")
            b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
            for scheme in ("light", "dark"):
                c = b.new_context(viewport={"width": 1280, "height": 900}, color_scheme=scheme, bypass_csp=True)
                pg = c.new_page()
                pg.goto(url)
                pg.wait_for_selector("#folders tbody tr", timeout=60000)
                pg.click(".nav-item[data-nav=peers]")
                time.sleep(3)
                pg.screenshot(path=str(out / f"p2p-home-{scheme}.png"))
                c.close()
            b.close()
        t.join()
        log(f"screenshots in {out}")

    def local_reset(self):
        home = local_home()
        subprocess.run(["systemctl", "--user", "stop", "varsto.service"], capture_output=True)
        if home.exists():
            dest = home.with_name(f"{home.name}.before-nat-test-{time.strftime('%Y%m%d-%H%M%S')}")
            home.rename(dest)
            log(f"home: {home} moved to {dest}")
        self.state.pop("home_joined", None)
        self.save()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["up", "setup", "vault", "run", "shots", "down", "local-reset"])
    ap.add_argument("--work", default=os.environ.get("NAT_WORK", "dist/nat-test"))
    ap.add_argument("--type", default="DEV1-M")
    ap.add_argument("--package")
    ap.add_argument("--home-folder", default="~/Varsto NAT test")
    ap.add_argument("--mb", type=int, default=64)
    ap.add_argument("--only", help="src:dst pairs, comma separated")
    ap.add_argument("--out", default="dist/nat-test/shots")
    ap.add_argument("--delay", type=float, default=6.0)
    a = ap.parse_args()
    r = Rig(a)
    {"up": r.up, "setup": r.setup, "vault": r.vault, "run": r.run, "shots": r.shots, "down": r.down,
     "local-reset": r.local_reset}[a.cmd]()


if __name__ == "__main__":
    main()
