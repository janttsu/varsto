#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""End-to-end scenarios in the lab of lab.py (run `lab.py up`, `lab.py
services`, `lab.py build` and `lab.py install-bin` first).

    scenarios.py [--only NAME[,NAME]] [--binary PATH]     run and write test-results/lab/results.json

VARSTO_LOG (default debug) is passed to every varsto run on the VMs; after
each scenario the logs of every device land in test-results/lab/logs/<scenario>/<vm>/.

Every scenario prints PASS/FAIL with the reason and goes on; the exit code
is the number of failed scenarios (0: everything passed). The vault lives in
the default home of user `varsto` on each device VM; the first scenario
resets every device and empties the S3 bucket, so a run starts clean.
"""
import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import lab  # noqa: E402

PASS_ = "lab-passphrase-1234"
# Every varsto run on the VMs (CLI calls and the backgrounded `service run`,
# `pair offer`, ...) starts with ENV, so VARSTO_LOG reaches all of them. The
# value comes from the host's VARSTO_LOG when set (e.g. "trace").
LOG_LEVEL = os.environ.get("VARSTO_LOG") or "debug"
# Secrets travel in the environment, never on the command line: the S3 secret
# for every command, the vault key per `join` (see v(..., env=)).
ENV = f"VARSTO_PASSPHRASE={PASS_} VARSTO_NO_INSTALL=1 VARSTO_LOG={shlex.quote(LOG_LEVEL)} VARSTO_S3_SECRET={shlex.quote(lab.S3['secret'])}"
REPO = pathlib.Path(__file__).resolve().parents[3]
LOGS_DIR = REPO / "test-results" / "lab" / "logs"
BUCKET = "vault1"
RESULTS = []
CTX = {}


class Fail(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Fail(msg)


def run(vm, cmd, check_rc=True, timeout_note=""):
    r = lab.ssh(vm, cmd, check=False)
    if check_rc and r.returncode != 0:
        raise Fail(f"{vm}: `{cmd[:160]}` failed ({r.returncode}): {(r.stderr or r.stdout).strip()[-600:]}")
    return r


def v(vm, args, json_out=True, check_rc=True, env=""):
    """Run varsto on a VM; parsed JSON (or text) out. `env` adds variables
    (a vault key for `join`) to this one command."""
    cmd = f"{ENV} {env} varsto {'--json ' if json_out else ''}{args}"
    r = run(vm, cmd, check_rc=check_rc)
    out = r.stdout.strip()
    if not check_rc and r.returncode != 0:
        try:
            parsed = json.loads(out) if json_out and out else None
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            return {"_failed": True, "_rc": r.returncode, "_err": (r.stderr or "").strip(), "_out": parsed}
        return {"_failed": True, "_rc": r.returncode, "_err": (r.stderr or "").strip(), "_out": out}
    if json_out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out
    return out


def tree_hashes(vm, path):
    out = run(vm, f"cd {shlex.quote(path)} 2>/dev/null && find . -type f ! -name '*.varsto-placeholder' ! -name '.varsto-tmp-*' ! -name '.varsto-folder' -print0 | sort -z | xargs -0 -r sha256sum").stdout
    return {line[66:]: line[:64] for line in out.splitlines() if line}


def bucket_packs():
    """The pack objects in the S3 bucket (format 2: `packs/<xx>/<id>`; the
    pack indexes and tombstone lists under packs/index and packs/tombstones
    are not packs), smallest first."""
    root = lab.DIR / "s3" / BUCKET / "packs"
    out = [p for p in root.glob("??/*") if p.is_file()]
    return sorted(out, key=lambda p: (p.stat().st_size, p.name))


def same_tree(a, b, what):
    if a == b:
        return
    only_a = sorted(set(a) - set(b))[:8]
    only_b = sorted(set(b) - set(a))[:8]
    diff = sorted(k for k in set(a) & set(b) if a[k] != b[k])[:8]
    raise Fail(f"{what}: only in first {only_a}, only in second {only_b}, different {diff}")


def gen_data(vm, path, seed, big_mb=6, small=150):
    py = f"""
import os, random, pathlib
r = random.Random({seed})
root = pathlib.Path({path!r}); root.mkdir(parents=True, exist_ok=True)
(root / "big.bin").write_bytes(r.randbytes({big_mb} << 20))
for i in range({small}):
    d = root / f"dir{{i % 7}}" / f"sub{{i % 3}}"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"note-{{i}}.txt").write_text(f"note {{i}} " * r.randint(1, 400))
(root / "Ääkköset ja välilyönnit.txt").write_text("unicode name\\n")
(root / "empty.txt").write_text("")
"""
    run(vm, f"python3 - <<'PY'\n{py}\nPY")


# Every home a scenario uses holds its logs under <home>/logs (varsto-<component>.log,
# rotated varsto-<component>.N.log.zst); the homes are the default
# ~/.local/share/varsto, ~/share-home and ~/dl-home, and a search under ~ also
# picks up any other. ~/*.log are the nohup outputs (svc.log, pair.log, ...).
LOG_FIND = ("cd ~ && { find . -maxdepth 6 -type f \\( -path '*/logs/varsto-*.log*' -o -name service.log \\) "
            "-not -path './data/*' 2>/dev/null; ls -1 ./*.log 2>/dev/null; true; }")


def collect_logs(name, vms=None, timeout=60):
    """Copy the Varsto logs of every device VM to test-results/lab/logs/<name>/<vm>/
    (relative to the home of user varsto). Never raises: problems are warnings."""
    dest = LOGS_DIR / name
    try:
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"warning: log collection for {name}: {e}", flush=True)
        return dest
    for vm in vms or lab.DEVICES:
        try:
            cmd = f"{LOG_FIND} | tar cf - --ignore-failed-read -T - 2>/dev/null"
            r = subprocess.run(lab.ssh_cmd(vm, cmd), capture_output=True, timeout=timeout)
            if not r.stdout:
                continue
            out = dest / vm
            out.mkdir(parents=True, exist_ok=True)
            with tarfile.open(fileobj=io.BytesIO(r.stdout), mode="r:") as t:
                t.extractall(out, filter="data")
        except Exception as e:  # noqa: BLE001
            print(f"warning: log collection from {vm} for {name}: {e.__class__.__name__}: {e}", flush=True)
    return dest


def scenario(name):
    def deco(f):
        f.scenario = name
        return f
    return deco


# ----- scenarios ---------------------------------------------------------------------------

@scenario("reset")
def s_reset():
    for vm in lab.DEVICES:
        run(vm, "pkill -x varsto; sleep 0.5; rm -rf ~/.local/share/varsto ~/data ~/sel ~/sr ~/*.log; mkdir -p ~/data", check_rc=False)
        fix_clock(vm)
    s3 = lab.DIR / "s3"
    for d in s3.glob("*"):
        import shutil
        shutil.rmtree(d) if d.is_dir() else d.unlink()
    (s3 / BUCKET).mkdir(parents=True)
    lab.cmd_services_stop(None)
    lab.cmd_services(None)


@scenario("init-and-s3-through-nat")
def s_init():
    out = v("vl-laptop", "init --name laptop")
    check(len(out["vault_key"]) == 64, "no vault key")
    CTX["vault_key"] = out["vault_key"]
    v("vl-laptop", f"storage add-s3 cloud --insecure-http --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                    f"--access-key-id {lab.S3['key']} --place cloud", json_out=False)
    gen_data("vl-laptop", "/home/varsto/data/docs", seed=1)
    v("vl-laptop", "folder add docs /home/varsto/data/docs", json_out=False)
    push = v("vl-laptop", "push docs")
    check(push["files_changed"] >= 150, f"pushed {push['files_changed']} files")
    st = v("vl-laptop", "status")
    check(st["folders"][0]["chunks_without_storage_copy"] == 0, "chunks without a storage copy")
    # Format 2 stores every block in a pack: no object of its own per block.
    packs = bucket_packs()
    check(packs, "no pack in the bucket")
    check(sum(p.stat().st_size for p in packs) > 6 << 20, f"only {sum(p.stat().st_size for p in packs)} bytes of packs in the bucket")
    check(not list((lab.DIR / "s3" / BUCKET / "chunks").rglob("*")), "block objects of their own in the bucket")
    CTX["docs"] = tree_hashes("vl-laptop", "/home/varsto/data/docs")


@scenario("pair-over-lan")
def s_pair():
    run("vl-laptop", f"{ENV} nohup varsto pair offer > ~/pair.log 2>&1 &")
    code = None
    for _ in range(30):
        m = re.search(r"Pairing code: (\d{3}-\d{3}-\d{3})", run("vl-laptop", "cat ~/pair.log").stdout)
        if m:
            code = m.group(1)
            break
        time.sleep(0.5)
    check(code, "no pairing code: " + run("vl-laptop", "cat ~/pair.log").stdout[-300:])
    t0 = time.time()
    out = v("vl-desktop", f"pair join --name desktop --code {code}", json_out=False)
    CTX["pair_secs"] = round(time.time() - t0, 1)
    check("joined vault" in out, out[-300:])
    check("cloud: joined through it" in out, "desktop did not join through the S3 storage: " + out)
    time.sleep(1)
    check("Sent the vault to desktop" in run("vl-laptop", "cat ~/pair.log").stdout, "offer did not report the pairing")
    # A wrong code is refused and the offer is closed after it.
    run("vl-laptop", f"{ENV} nohup varsto pair offer > ~/pair2.log 2>&1 &")
    time.sleep(2)
    bad = v("vl-pub", "pair join --name x --code 000-000-000 --address 10.78.1.10:1", json_out=False, check_rc=False)
    check(isinstance(bad, dict) and bad.get("_failed"), "a wrong code joined")
    run("vl-laptop", "pkill -f 'varsto pair offer'", check_rc=False)
    run("vl-pub", "rm -rf ~/.local/share/varsto", check_rc=False)


@scenario("sync-to-second-device")
def s_sync():
    v("vl-desktop", "folder attach docs /home/varsto/data/docs", json_out=False)
    v("vl-desktop", "sync")
    got = tree_hashes("vl-desktop", "/home/varsto/data/docs")
    check(got == CTX["docs"], f"desktop differs: {len(got)} vs {len(CTX['docs'])} files")
    fsck = v("vl-desktop", "fsck --verify")
    check(not fsck["chunks_missing"] and not fsck.get("objects_corrupt"), f"fsck: {fsck}")


@scenario("join-with-recovery-words")
def s_words():
    kit = v("vl-laptop", "recovery kit", json_out=False)
    words = " ".join(re.findall(r"\d+\. (\w+)", kit.split("SHARES")[0]))
    check(len(words.split()) == 24, f"kit has {len(words.split())} words")
    out = v("vl-pub", f"join --name pub --s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-insecure-http "
                      f"--s3-access-key-id {lab.S3['key']} --storage-name cloud", env=f"VARSTO_VAULT_KEY={shlex.quote(words)}")
    check("docs" in out.get("folders", []), f"pub sees {out}")
    v("vl-pub", "folder attach docs /home/varsto/data/docs", json_out=False)
    v("vl-pub", "sync")
    check(tree_hashes("vl-pub", "/home/varsto/data/docs") == CTX["docs"], "pub differs")
    # Shares: two of three rebuild the key, one does not.
    kit = v("vl-laptop", "recovery kit --shares", json_out=False)
    shares = re.findall(r"Share (\d+):\n((?:[ \t]*\d+\. \w+[ \t]*\n?)+)", kit)
    check(len(shares) == 3, "no three shares")
    enc = [f"{i}: " + " ".join(re.findall(r"\d+\. (\w+)", body)) for i, body in shares]
    # The shares come on standard input, not on the command line.
    out = run("vl-laptop", f"printf '%s\\n' {shlex.quote(enc[0])} {shlex.quote(enc[2])} | {ENV} varsto recovery combine").stdout
    check(CTX["vault_key"] in out or "vault key:" in out, "combine failed: " + out[:200])


@scenario("edits-conflicts-deletes")
def s_conflict():
    run("vl-laptop", "echo laptop-version > ~/data/docs/dir0/sub0/note-0.txt")
    run("vl-desktop", "echo desktop-version > ~/data/docs/dir0/sub0/note-0.txt")
    v("vl-laptop", "push docs")
    v("vl-desktop", "sync")
    v("vl-laptop", "sync")
    names = run("vl-laptop", "ls ~/data/docs/dir0/sub0/").stdout
    check("conflict" in names.lower(), "no conflict copy on the laptop: " + names)
    lap = tree_hashes("vl-laptop", "/home/varsto/data/docs")
    desk = tree_hashes("vl-desktop", "/home/varsto/data/docs")
    check(lap == desk, "laptop and desktop disagree after a conflict")
    run("vl-desktop", "rm ~/data/docs/dir1/sub1/note-1.txt")
    v("vl-desktop", "sync")
    v("vl-laptop", "sync")
    check(run("vl-laptop", "test -e ~/data/docs/dir1/sub1/note-1.txt", check_rc=False).returncode != 0, "deletion not applied")
    trash = run("vl-laptop", "find ~/.local/share/varsto/trash -name 'note-1.txt.*' | wc -l").stdout.strip()
    check(trash != "0", "deleted file is not in the trash")


@scenario("selective-sync")
def s_selective():
    v("vl-pub", "folder detach docs", json_out=False, check_rc=False)
    run("vl-pub", "rm -rf ~/sel")
    v("vl-pub", "folder attach docs /home/varsto/sel --selective", json_out=False)
    v("vl-pub", "sync")
    ph = int(run("vl-pub", "find ~/sel -name '*.varsto-placeholder' | wc -l").stdout)
    real = int(run("vl-pub", "find ~/sel -type f ! -name '*.varsto-placeholder' ! -name '.varsto-folder' | wc -l").stdout)
    check(ph >= 150 and real == 0, f"placeholders {ph}, files {real}")
    v("vl-pub", "folder fetch docs big.bin")
    got = run("vl-pub", "sha256sum ~/sel/big.bin").stdout.split()[0]
    check(got == CTX["docs"]["./big.bin"], "fetched file differs")
    v("vl-pub", "folder free docs big.bin")
    check(run("vl-pub", "test -e ~/sel/big.bin.varsto-placeholder && ! test -e ~/sel/big.bin", check_rc=False).returncode == 0,
          "free did not turn the file back into a placeholder")


@scenario("damage-and-repair")
def s_repair():
    # Format 2: blocks live in packs. The conflicts above made small packs next
    # to the first push's large one: flip a byte in the largest, remove the smallest.
    packs = bucket_packs()
    check(len(packs) >= 2, f"{len(packs)} packs in the bucket, need 2")
    victim, gone = packs[-1], packs[0]
    data = bytearray(victim.read_bytes())
    data[len(data) // 2] ^= 0xFF
    victim.write_bytes(bytes(data))
    gone.unlink()
    # rclone serve s3 lists from a 5 s directory cache and drops the
    # connection when a listed file is gone: let it notice first.
    time.sleep(6)
    r = v("vl-laptop", "fsck --verify", check_rc=False)
    fsck = r.get("_out", r) if isinstance(r, dict) else {}
    check(isinstance(fsck, dict), f"fsck gave no report: {r}")
    bad = len(fsck.get("chunks_missing", [])) + len(fsck.get("objects_corrupt", []))
    check(bad >= 2, f"fsck found {bad} problems: {fsck}")
    rep = v("vl-laptop", "repair", check_rc=False)
    fsck = v("vl-laptop", "fsck --verify")
    check(not fsck.get("chunks_missing") and not fsck.get("objects_corrupt"), f"after repair: {fsck}; repair said {rep}")


@scenario("policy")
def s_policy():
    v("vl-laptop", "policy set docs --min-copies 2", json_out=False)
    rep = v("vl-laptop", "policy check", check_rc=False)
    check(isinstance(rep, dict) and rep.get("_rc") in (1, 2), f"policy check exit code: {rep}")
    text = json.dumps(rep.get("_out"))
    check("violated" in text or "at_risk" in text, f"one storage cannot meet two copies: {text[:300]}")
    v("vl-desktop", "sync")
    st = v("vl-desktop", "status")
    pol = [f.get("policy") for f in st["folders"] if f["name"] == "docs"]
    check(pol and pol[0], f"desktop did not get the policy: {pol}")
    v("vl-laptop", "policy set docs --min-copies 1", json_out=False)


@scenario("strongroom-software-key")
def s_strongroom():
    run("vl-laptop", "mkdir -p ~/sr")
    out = v("vl-laptop", "strongroom create vault-secrets /home/varsto/sr --software --minutes 5", json_out=False)
    check("created" in out, out)
    run("vl-laptop", "echo 'top secret' > ~/sr/secret.txt")
    v("vl-laptop", "push vault-secrets", check_rc=False)
    v("vl-desktop", "sync", check_rc=False)
    st = v("vl-desktop", "status")
    names = [f["name"] for f in st["folders"]]
    check("vault-secrets" in names, f"desktop does not know the strongroom: {names}")
    # Without the key the desktop cannot open it.
    r = v("vl-desktop", "folder attach vault-secrets /home/varsto/sr2", json_out=False, check_rc=False)
    files = run("vl-desktop", "find ~/sr2 -type f ! -name '*.varsto-placeholder' ! -name '.varsto-folder' 2>/dev/null | wc -l").stdout.strip()
    check(files == "0", f"desktop has {files} plain files of a strongroom it cannot unlock")


@scenario("organization-across-nat")
def s_org():
    out = v("vl-laptop", "org create --name LabCo --user aino")
    CTX["root_words"] = out["root_words"]
    req = v("vl-work", "org request --name work")
    fp = req["fingerprint"]
    bad = v("vl-laptop", f"org approve {shlex.quote(req['request_code'])} --user ville --fingerprint 'wrong words here a b'", check_rc=False)
    check(isinstance(bad, dict) and bad.get("_failed"), "a wrong fingerprint was accepted")
    ap = v("vl-laptop", f"org approve {shlex.quote(req['request_code'])} --user ville --fingerprint {shlex.quote(fp)}")
    j = v("vl-work", f"org join --name work --token {shlex.quote(ap['token'])}")
    check(j["user"] == "ville" and j["organization"] == "LabCo", f"join: {j}")
    v("vl-work", "folder attach docs /home/varsto/data/docs", json_out=False)
    v("vl-work", "sync")
    v("vl-laptop", "sync")
    v("vl-work", "sync")
    want = tree_hashes("vl-laptop", "/home/varsto/data/docs")
    same_tree(want, tree_hashes("vl-work", "/home/varsto/data/docs"), "laptop vs work (behind symmetric NAT)")
    # Members cannot remove devices or print the vault key.
    for d in ("vl-desktop", "vl-work"):
        v(d, "sync", check_rc=False)
    r = v("vl-work", "device revoke desktop --yes", check_rc=False)
    check(isinstance(r, dict) and r.get("_failed"), "a member removed a device")
    r = v("vl-work", "recovery kit", json_out=False, check_rc=False)
    check(isinstance(r, dict) and r.get("_failed"), "a member printed the vault key")
    # A device that joins with the vault key alone is ignored.
    v("vl-pub", "sync", check_rc=False)
    s = v("vl-laptop", "org status")
    check(any(d["name"] == "pub" for d in s.get("unlisted", [])) or any(
        d["name"] == "pub" for u in s["users"] for d in u["devices"]), f"pub missing from status: {s}")
    if any(d["name"] == "pub" for d in s.get("unlisted", [])):
        run("vl-pub", "echo from-unlisted > ~/sel/unlisted.txt")
        v("vl-pub", "sync", check_rc=False)
        v("vl-laptop", "sync")
        check(run("vl-laptop", "test -e ~/data/docs/unlisted.txt", check_rc=False).returncode != 0,
              "a file from an unlisted device was accepted")
        v("vl-laptop", "org add-device pub --user aino", json_out=False)
        v("vl-laptop", "sync")
    log = v("vl-laptop", "org log")
    check(any("approved work for ville" in e["text"] for e in log), f"log: {[e['text'] for e in log]}")


@scenario("remove-user-with-wipe")
def s_remove_user():
    r = v("vl-laptop", "org remove-user ville --wipe --yes")
    check(r["revoke"]["key_epoch"] >= 1, f"{r}")
    out = v("vl-work", "sync", check_rc=False)
    check(isinstance(out, dict) and out.get("_failed") and "removed" in out["_err"], f"work still syncs: {out}")
    left = run("vl-work", "find ~/data/docs -type f | wc -l; ls ~/.local/share/varsto").stdout
    check(left.splitlines()[0].strip() == "0" and "wiped.json" in left, f"work not wiped: {left}")
    # The others follow the new key and keep syncing.
    run("vl-laptop", "echo after-removal > ~/data/docs/after.txt")
    v("vl-laptop", "sync")
    v("vl-desktop", "sync")
    check(run("vl-desktop", "cat ~/data/docs/after.txt").stdout.strip() == "after-removal", "desktop did not get new data")


@scenario("revoke-device")
def s_revoke():
    r = v("vl-laptop", "device revoke pub --yes")
    check(r["key_epoch"] >= 2, f"{r}")
    out = v("vl-pub", "sync", check_rc=False)
    check(isinstance(out, dict) and out.get("_failed"), "a revoked device still syncs")
    run("vl-laptop", "echo secret-after-revoke > ~/data/docs/after2.txt")
    v("vl-laptop", "sync")
    v("vl-desktop", "sync")
    check(run("vl-desktop", "cat ~/data/docs/after2.txt").stdout.strip() == "secret-after-revoke", "desktop missing new data")
    # A new device cannot join with the old key, but can with the current one.
    old = v("vl-work", f"join --name w2 --s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-insecure-http "
                       f"--s3-access-key-id {lab.S3['key']}", check_rc=False, env=f"VARSTO_VAULT_KEY={shlex.quote(CTX['vault_key'])}")
    check(isinstance(old, dict) and old.get("_failed"), "joined with a key from before the revocation")


# ----- peer to peer through the NATs (background services) ---------------------------------

P2P_MB = 64


def api(vm, method, path, body=None, timeout=900):
    data = f"-H 'Content-Type: application/json' -d {shlex.quote(json.dumps(body))}" if body is not None else ""
    cmd = ("f=~/.local/share/varsto/service.json; "
           "port=$(python3 -c \"import json,os;print(json.load(open(os.path.expanduser('$f')))['port'])\"); "
           "tok=$(python3 -c \"import json,os;print(json.load(open(os.path.expanduser('$f')))['token'])\"); "
           f"curl -sS --max-time {timeout} -X {method} \"http://127.0.0.1:$port{path}\" -H \"X-Varsto-Token: $tok\" {data}")
    out = run(vm, cmd).stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"_raw": out}


def start_service(vm):
    run(vm, f"{ENV} nohup varsto service run --interval 15 > ~/svc.log 2>&1 < /dev/null &")
    for _ in range(60):
        if run(vm, "test -s ~/.local/share/varsto/service.json", check_rc=False).returncode == 0:
            try:
                if "unlocked" in json.dumps(api(vm, "GET", "/api/state")):
                    return
            except Fail:
                pass
        time.sleep(1)
    raise Fail(f"{vm}: service did not start: " + run(vm, "tail -5 ~/svc.log").stdout)


def drop_bucket_chunks():
    import shutil
    shutil.rmtree(lab.DIR / "s3" / BUCKET / "chunks", ignore_errors=True)
    (lab.DIR / "s3" / BUCKET / "chunks").mkdir()
    # Format 2: the blocks are in packs (packs/<xx>/<id>); the pack indexes and
    # tombstone lists stay, as they are no blocks.
    for d in (lab.DIR / "s3" / BUCKET / "packs").glob("??"):
        shutil.rmtree(d, ignore_errors=True)


@scenario("p2p-setup")
def s_p2p_setup():
    s_reset()
    v("vl-laptop", "init --name laptop", json_out=True)
    key = v("vl-laptop", "recovery kit", json_out=False)
    v("vl-laptop", f"storage add-s3 cloud --insecure-http --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                    f"--access-key-id {lab.S3['key']} --place cloud", json_out=False)
    run("vl-laptop", f"mkdir -p ~/data/media && head -c {P2P_MB << 20} /dev/urandom > ~/data/media/big.bin")
    v("vl-laptop", "folder add media /home/varsto/data/media", json_out=False)
    v("vl-laptop", "push media")
    CTX["p2p_sha"] = run("vl-laptop", "sha256sum ~/data/media/big.bin").stdout.split()[0]
    words = " ".join(re.findall(r"\d+\. (\w+)", key.split("SHARES")[0]))
    for vm, name in (("vl-desktop", "desktop"), ("vl-pub", "pub"), ("vl-work", "work")):
        v(vm, f"join --name {name} --s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-insecure-http "
              f"--s3-access-key-id {lab.S3['key']} --storage-name cloud", env=f"VARSTO_VAULT_KEY={shlex.quote(words)}")
    stun = " ".join(f"--stun {x}" for x in lab.STUN)
    for vm in lab.DEVICES:
        extra = " --public 198.51.100.20:17893" if vm == "vl-pub" else ""
        v(vm, f"p2p enable {stun}{extra}", json_out=False)
    for vm in lab.DEVICES:
        start_service(vm)
    # Rendezvous records travel through the bucket; give every service two rounds.
    time.sleep(40)
    for vm in lab.DEVICES:
        p = api(vm, "GET", "/api/p2p")
        CTX[f"nat_{vm}"] = {"nat": p.get("nat"), "public": p.get("public"), "reachable": p.get("reachable")}
    check(CTX["nat_vl-pub"]["reachable"], f"pub should be reachable: {CTX['nat_vl-pub']}")


def p2p_pull(vm, label):
    # The laptop keeps serving but stops syncing (its repair would put the
    # blocks back into the bucket); the bucket loses every block; only then
    # does the target attach the folder, so every block has to come from a peer.
    api("vl-laptop", "POST", "/api/service/pause", {"paused": True})
    api(vm, "POST", "/api/service/pause", {"paused": True})
    drop_bucket_chunks()
    run(vm, "rm -rf ~/data/media")
    api(vm, "POST", "/api/folder/attach", {"name_or_id": "media", "path": "/home/varsto/data/media", "plain": True})
    before = api(vm, "GET", "/api/p2p").get("chunks_from_peers") or 0
    t0 = time.time()
    api(vm, "POST", "/api/sync", {"folder": "media"})
    secs = time.time() - t0
    got = run(vm, "sha256sum ~/data/media/big.bin 2>/dev/null || true").stdout.split()
    p = api(vm, "GET", "/api/p2p")
    peers = (p.get("chunks_from_peers") or 0) - before
    paths = {x.get("name"): x.get("path") for x in (p.get("paths") or [])}
    CTX[f"p2p_{label}"] = {"seconds": round(secs, 1), "mb_s": round(P2P_MB / secs, 1), "chunks_from_peers": peers, "paths": paths}
    check(got and got[0] == CTX["p2p_sha"], f"{vm}: file missing or different after pull ({CTX[f'p2p_{label}']})")
    check(peers > 0, f"{vm}: nothing came from peers ({CTX[f'p2p_{label}']})")
    api(vm, "POST", "/api/folder/detach", {"name": "media"})
    api(vm, "POST", "/api/service/pause", {"paused": False})


@scenario("p2p-lan")
def s_p2p_lan():
    p2p_pull("vl-desktop", "lan")
    check(CTX["p2p_lan"]["paths"].get("laptop", "").startswith("direct"), f"laptop not direct from desktop: {CTX['p2p_lan']}")


@scenario("p2p-public-server-from-cone-nat")
def s_p2p_pub():
    run("vl-desktop", "true")
    p2p_pull("vl-pub", "pub")


@scenario("p2p-symmetric-nat")
def s_p2p_sym():
    p2p_pull("vl-work", "symmetric")


@scenario("p2p-services-stop")
def s_p2p_stop():
    for vm in lab.DEVICES:
        run(vm, "pkill -x varsto; true", check_rc=False)
    for k, val in CTX.items():
        if k.startswith(("p2p_", "nat_")):
            print(f"      {k}: {val}", flush=True)


# ----- two people, one shared folder through S3 ---------------------------------------------

@scenario("share-between-people-via-s3")
def s_share():
    # The laptop owns the vault of the p2p scenarios; "ville" on the work
    # machine has a vault directory of its own for the share.
    home = "--home /home/varsto/share-home"
    run("vl-work", "rm -rf ~/share-home ~/shared; pkill -x varsto; true", check_rc=False)
    for vm in ("vl-laptop",):
        run(vm, "pkill -x varsto; true", check_rc=False)
        time.sleep(0.5)
    # The p2p scenarios emptied the bucket: the owner's repair puts every
    # block back from its own files (the member reads from the bucket).
    v("vl-laptop", "repair", check_rc=False)
    fsck = v("vl-laptop", "fsck", check_rc=False)
    fsck = fsck.get("_out", fsck) if isinstance(fsck, dict) else {}
    check(not fsck.get("chunks_missing"), f"repair left blocks missing: {fsck.get('chunks_missing')}")
    req = v("vl-work", f"{home} share request --name ville")
    tok = v("vl-laptop", f"share create media --to {shlex.quote(req['request_code'])} --fingerprint {shlex.quote(req['fingerprint'])}", json_out=False)
    token = re.search(r"(vst[12]\.\S+)", tok)
    check(token, "no sealed token: " + tok[-300:])
    out = v("vl-work", f"{home} share accept --name ville-pc --token {shlex.quote(token.group(1))} --storage-name owner "
                       f"--s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-insecure-http --s3-access-key-id {lab.S3['key']} "
                       "", json_out=False)
    check("joined shared folder media" in out, out[-300:])
    v("vl-laptop", "push media", check_rc=False)
    v("vl-work", f"{home} folder attach media /home/varsto/shared", json_out=False)
    v("vl-work", f"{home} sync")
    want = CTX.get("p2p_sha") or run("vl-laptop", "sha256sum ~/data/media/big.bin").stdout.split()[0]
    got = run("vl-work", "sha256sum ~/shared/big.bin").stdout.split()[0]
    check(got == want, "the shared file differs")
    # The member writes; the owner sees it.
    run("vl-work", "echo from-ville > ~/shared/ville.txt")
    v("vl-work", f"{home} sync")
    v("vl-laptop", "sync")
    check(run("vl-laptop", "cat ~/data/media/ville.txt").stdout.strip() == "from-ville", "owner did not get the member's file")
    # Removing the member: what is written afterwards stays away from it.
    v("vl-laptop", "share revoke media ville-pc --yes", json_out=False)
    run("vl-laptop", "echo after-revoke > ~/data/media/later.txt")
    v("vl-laptop", "sync")
    v("vl-work", f"{home} sync", check_rc=False)
    check(run("vl-work", "test -e ~/shared/later.txt", check_rc=False).returncode != 0, "a removed member got new data")


# ----- removable disks: a pool of hot-plugged virtual disks --------------------------------

def attach_disk(vm, name, size="6G"):
    img = lab.DIR / "pool" / f"{vm}-{name}.qcow2"
    if not img.exists():
        lab.sh(["qemu-img", "create", "-q", "-f", "qcow2", str(img), size])
    lab.virsh("attach-disk", vm, str(img), name, "--targetbus", "virtio", "--subdriver", "qcow2", "--live")
    for _ in range(20):
        if run(vm, f"test -b /dev/{name}", check_rc=False).returncode == 0:
            return
        time.sleep(0.5)
    raise Fail(f"/dev/{name} did not appear in {vm}")


def detach_disk(vm, name):
    lab.virsh("detach-disk", vm, name, "--live")
    for _ in range(20):
        if run(vm, f"test -b /dev/{name}", check_rc=False).returncode != 0:
            return
        time.sleep(0.5)


@scenario("disk-pool-hotplug")
def s_disks():
    vm = "vl-laptop"
    run(vm, "pkill -x varsto; true", check_rc=False)
    for name in ("vdb", "vdc"):
        run(vm, f"sudo umount /mnt/{name} 2>/dev/null; true", check_rc=False)
        lab.virsh("detach-disk", vm, name, "--live", check=False)
        for f in (lab.DIR / "pool").glob(f"{vm}-{name}.qcow2"):
            f.unlink()
    for name in ("vdb", "vdc"):
        attach_disk(vm, name)
        run(vm, f"sudo mkfs.ext4 -q -L {name} /dev/{name} && sudo mkdir -p /mnt/{name} && sudo mount /dev/{name} /mnt/{name} && sudo chown varsto: /mnt/{name}")
    out = run(vm, f"{ENV} varsto storage remove shelf 2>&1; true", check_rc=False).stdout
    check("shelf" not in json.dumps(v(vm, "status")["storages"]), "the old pool could not be removed: " + out[-300:])
    v(vm, "storage add-pool shelf --place home", json_out=False)
    # A pool rule of two copies on disks in different places: every block
    # lands on both disks.
    v(vm, "disk group shelf --copies 2", json_out=False)
    a1 = v(vm, "disk add /mnt/vdb --pool shelf --label d1 --place home")
    a2 = v(vm, "disk add /mnt/vdc --pool shelf --label d2 --place office")
    CTX["pool_added"] = (a1.get("objects_added"), a2.get("objects_added"))
    check(a1.get("objects_added") and a2.get("objects_added"), f"disk add filled nothing: {a1} {a2}")
    v(vm, "push media", check_rc=False)
    v(vm, "sync", check_rc=False)
    disks = v(vm, "disk list")
    held = {d.get("label"): d.get("objects", d.get("object_count")) for d in (disks if isinstance(disks, list) else disks.get("disks", []))}
    CTX["pool_objects"] = held
    check(all(held.get(l) for l in ("d1", "d2")), f"both disks should hold blocks: {disks}")
    # Eject one disk, unplug it, and the pool knows it is away.
    v(vm, "disk eject d1", json_out=False)
    run(vm, "sudo umount /mnt/vdb")
    detach_disk(vm, "vdb")
    disks = json.dumps(v(vm, "disk list"))
    check("away" in disks or "false" in disks.lower(), f"d1 is not shown as away: {disks[:400]}")
    # Plug it back in: the check recognises it by its marker and verifies it.
    attach_disk(vm, "vdb")
    run(vm, "sudo mount /dev/vdb /mnt/vdb")
    chk = v(vm, "disk check d1 --full")
    check(not chk.get("corrupt") and not chk.get("missing"), f"disk check: {chk}")


# ----- whole drives: disk init, insert, unmount, and fetching from disks ---------------------
# A vault of its own on the laptop (--home ~/dl-home) with a local "box" storage and a pool
# "dshelf"; virtual drives of 4 GiB (the pool keeps 2 GiB free on every disk), one at a time as vdd.

DL_VM = "vl-laptop"
DL = "--home /home/varsto/dl-home"


def dl(args, json_out=True, check_rc=True):
    return v(DL_VM, f"{DL} {args}", json_out=json_out, check_rc=check_rc)


def dl_failed(r, words):
    return isinstance(r, dict) and r.get("_failed") and all(w in (r.get("_err") or "") for w in words)


def dl_clean():
    run(DL_VM, "pkill -f 'dl-home'; sleep 0.3; true", check_rc=False)
    run(DL_VM, "sudo umount /dev/vdd1 2>/dev/null; true", check_rc=False)
    lab.virsh("detach-disk", DL_VM, "vdd", "--live", check=False)
    time.sleep(1)
    for name in ("vdd", "vde", "vdf", "red", "green"):
        for f in (lab.DIR / "pool").glob(f"{DL_VM}-{name}.qcow2"):
            f.unlink()
    run(DL_VM, "sudo rmdir /mnt/varsto-* 2>/dev/null; rm -rf ~/dl-home ~/dl-box ~/dl-docs /tmp/dl-in /tmp/dl-out; true", check_rc=False)


def dl_vault():
    dl("init --name dl")
    dl("storage add-local box /home/varsto/dl-box --place cloud", json_out=False)
    dl("storage add-pool dshelf --place home", json_out=False)
    gen_data(DL_VM, "/home/varsto/dl-docs", seed=41, big_mb=24, small=60)
    dl("folder add ddocs /home/varsto/dl-docs", json_out=False)
    dl("push ddocs")


def dl_unmounted(dev):
    return run(DL_VM, f"findmnt -n -S {dev}", check_rc=False).returncode != 0


@scenario("disk-init")
def s_disk_init():
    dl_clean()
    dl_vault()
    attach_disk(DL_VM, "vdd", size="4G")
    # Refusals: the system disk, no confirmation without a terminal, a confirmation of another device.
    r = dl("disk init /dev/vda --pool dshelf --label Sys --confirm /dev/vda", check_rc=False)
    check(dl_failed(r, ["mounted"]), f"the system disk was not refused: {r}")
    r = dl("disk init /dev/vdd --pool dshelf --label 'Blue 4GB'", check_rc=False)
    check(dl_failed(r, ["--confirm"]), f"no refusal without --confirm: {r}")
    r = dl("disk init /dev/vdd --pool dshelf --label 'Blue 4GB' --confirm /dev/vdb", check_rc=False)
    check(dl_failed(r, ["does not match"]), f"a wrong --confirm was accepted: {r}")
    out = dl("disk init /dev/vdd --pool dshelf --label 'Blue 4GB' --confirm /dev/vdd")
    uuid, mount = out["device"]["partuuid"], out["mount"]
    CTX["disk_init"] = {"privilege": out["device"]["privilege"], "mount": mount, "method": out["mount_method"],
                        "objects": out["fill"]["objects"], "bytes": out["fill"]["bytes"]}
    check(out["fill"]["objects"] > 0 and not out["fill"].get("failed"), f"init filled nothing: {out['fill']}")
    gpt = run(DL_VM, "sudo sgdisk -p /dev/vdd").stdout
    check("8300" in gpt and "varsto-Blue 4GB" in gpt, f"partition table: {gpt[-400:]}")
    info = run(DL_VM, "lsblk -no FSTYPE,PARTUUID,LABEL /dev/vdd1").stdout.split()
    check(info == ["ext4", uuid, "Blue-4GB"], f"filesystem, PARTUUID, label: {info} (want {uuid})")
    conf = run(DL_VM, "cat ~/dl-home/disks.conf").stdout
    check(f"{uuid}\tdshelf\tBlue 4GB\n" in conf, f"disks.conf: {conf}")
    check(run(DL_VM, f"stat -c %U {shlex.quote(mount)}").stdout.strip() == "varsto", "the filesystem root is not the user's")
    fs = run(DL_VM, "sudo dumpe2fs -h /dev/vdd1 2>/dev/null").stdout
    n = {k: int(re.search(rf"^{k}:\s+(\d+)", fs, re.M).group(1)) for k in ("Inode count", "Block count", "Block size", "Reserved block count")}
    ratio = n["Block count"] * n["Block size"] / n["Inode count"]
    CTX["disk_init"]["bytes_per_inode"] = round(ratio)
    check(60_000 < ratio < 70_000 and n["Reserved block count"] == 0, f"mkfs options: {n}")
    # Every object on the drive hashes to its name (a full check reads them back).
    chk = dl("disk check 'Blue 4GB' --full")
    files = int(run(DL_VM, f"find {shlex.quote(mount)}/varsto/packs -type f ! -name '.*' | wc -l").stdout)
    check(not chk["bad"] and not chk["missing"] and chk["objects_checked"] == files, f"full check: {chk}, {files} files")
    um = dl("disk unmount 'Blue 4GB'")
    CTX["disk_init"]["unmount"] = [s["step"] for s in um["steps"]]
    check(dl_unmounted("/dev/vdd1"), "still mounted after disk unmount")
    detach_disk(DL_VM, "vdd")
    # Away: new files; then half of the copies' last checks are made old.
    run(DL_VM, "head -c 3000000 /dev/urandom > ~/dl-docs/new-while-away.bin")
    dl("push ddocs")
    aged = int(run(DL_VM, """python3 - <<'PY'
import glob, json
p = glob.glob('/home/varsto/dl-home/pool-*.json')[0]
d = json.load(open(p))
n = 0
for i, (k, e) in enumerate(sorted(d['objects'].items())):
    if i % 2 == 0:
        for disk in e.get('checked', {}):
            e['checked'][disk] = 1000
            n += 1
json.dump(d, open(p, 'w'))
print(n)
PY""").stdout.strip())
    attach_disk(DL_VM, "vdd", size="4G")
    ins = dl("disk insert")
    check(len(ins) == 1, f"insert: {ins}")
    rep = ins[0]["report"]
    CTX["disk_insert"] = {"mount_method": ins[0]["mount_method"], "verified": rep["verified_objects"], "aged": aged,
                          "filled": rep["fill"]["objects"], "removed": rep["tidy"]["pending_removed"] + rep["tidy"]["unneeded_removed"]}
    check(rep["verified_objects"] == aged and not rep["bad"], f"stale verification: {rep['verified_objects']} of {aged} aged, bad {rep['bad']}")
    check(rep["fill"]["objects"] > 0 and not rep["fill"].get("failed"), f"insert filled nothing: {rep['fill']}")
    check("varsto disk unmount" in ins[0]["message"], ins[0]["message"])
    check(ins[0]["fsck"]["verdict"] == "clean", f"the check before mounting: {ins[0]['fsck']}")
    again = dl("disk insert 'Blue 4GB'")[0]["report"]
    check(again["verified_objects"] == 0 and again["fill"]["objects"] == 0, f"a second insert did work again: {again}")
    dl("disk unmount 'Blue 4GB'")
    check(dl_unmounted("/dev/vdd1"), "still mounted after the second unmount")
    lst = dl("disk list")
    row = [d for d in lst if d.get("label") == "Blue 4GB"]
    check(row and row[0].get("partuuid") == uuid and row[0].get("plugged_in") is True, f"disk list: {row}")
    check((row[0].get("fsck") or {}).get("verdict") == "clean", f"disk list has no check: {row}")
    # The forced check before mounting: an error preen fixes (a wrong free-block count)
    # is corrected and the insert goes on with a warning...
    run(DL_VM, "sudo debugfs -w -R 'set_bg 0 free_blocks_count 7' /dev/vdd1")
    ins = dl("disk insert 'Blue 4GB'")[0]
    CTX["disk_fsck"] = {"fixable": [ins["fsck"]["code"], ins["fsck"]["verdict"]]}
    check(ins["fsck"]["verdict"] == "corrected", f"a fixable error: {ins['fsck']}")
    dl("disk unmount 'Blue 4GB'")
    # ...and one it cannot fix (the data directory's inode cleared) stops it, unmounted.
    run(DL_VM, "sudo debugfs -w -R 'clri /varsto' /dev/vdd1")
    r = dl("disk insert 'Blue 4GB'", check_rc=False)
    CTX["disk_fsck"]["unfixable"] = (r.get("_err") or "")[-300:] if isinstance(r, dict) else str(r)[-300:]
    check(dl_failed(r, ["could not be repaired automatically"]), f"an unfixable error did not stop the insert: {r}")
    check(dl_unmounted("/dev/vdd1"), "mounted after a failed check")
    lst = dl("disk list")
    row = [d for d in lst if d.get("label") == "Blue 4GB"]
    check((row[0].get("fsck") or {}).get("verdict") == "uncorrected", f"the failed check is not recorded: {row}")
    detach_disk(DL_VM, "vdd")
    for f in (lab.DIR / "pool").glob(f"{DL_VM}-vdd.qcow2"):
        f.unlink()


def dl_attach(image):
    """Plug virtual drive `image` in as vdd (one drive at a time: the guest names
    hot-plugged virtio disks in order, whatever the target says)."""
    img = lab.DIR / "pool" / f"{DL_VM}-{image}.qcow2"
    if not img.exists():
        lab.sh(["qemu-img", "create", "-q", "-f", "qcow2", str(img), "4G"])
    lab.virsh("attach-disk", DL_VM, str(img), "vdd", "--targetbus", "virtio", "--subdriver", "qcow2", "--live")
    for _ in range(20):
        if run(DL_VM, "test -b /dev/vdd", check_rc=False).returncode == 0:
            return
        time.sleep(0.5)
    raise Fail(f"{image} did not appear as /dev/vdd")


@scenario("disk-fetch-plan")
def s_disk_fetch_plan():
    dl_clean()
    dl_vault()
    # film.bin: its first 12 MB go to Red, the 8 MB appended later to Green.
    dl_attach("red")
    dl("disk init /dev/vdd --pool dshelf --label Red --confirm /dev/vdd")
    run(DL_VM, "head -c 12000000 /dev/urandom > ~/dl-docs/film.bin")
    dl("push ddocs")
    dl("disk unmount Red")
    detach_disk(DL_VM, "vdd")
    dl_attach("green")
    dl("disk init /dev/vdd --pool dshelf --label Green --confirm /dev/vdd")
    run(DL_VM, "head -c 8000000 /dev/urandom >> ~/dl-docs/film.bin")
    dl("push ddocs")
    dl("disk unmount Green")
    detach_disk(DL_VM, "vdd")
    want = run(DL_VM, "sha256sum ~/dl-docs/film.bin").stdout.split()[0]
    dl("storage price box --egress 0.09 --currency EUR", json_out=False)
    dl("disk fetch-set --threshold-mib 1")
    plan = dl("fetch-plan ddocs film.bin")
    CTX["fetch_plan"] = {"recommend": plan["recommend"], "reason": plan["reason"],
                         "steps": [(s["label"], s["bytes"]) for s in plan["steps"]], "remote_cost": plan["remote"]["cost"]}
    check(plan["recommend"] == "disks" and sorted(s["label"] for s in plan["steps"]) == ["Green", "Red"], f"plan: {plan}")
    run(DL_VM, "rm ~/dl-docs/film.bin")
    # The fetch runs in the background reading Enter from a FIFO; the host plugs in each
    # drive it asks for, presses Enter, and unplugs the drive when told it can.
    run(DL_VM, "mkfifo /tmp/dl-in; (setsid sleep 3600 > /tmp/dl-in 2>/dev/null < /dev/null &); "
               f"(setsid sh -c '{ENV} varsto {DL} folder fetch ddocs film.bin --from-disks always < /tmp/dl-in > /tmp/dl-out 2>&1; "
               "echo rc=$? >> /tmp/dl-out' > /dev/null 2>&1 < /dev/null &); true")

    def wait_out(pred, what, secs=300):
        end = time.time() + secs
        while time.time() < end:
            out = run(DL_VM, "cat /tmp/dl-out 2>/dev/null; true", check_rc=False).stdout
            if pred(out):
                return out
            if "rc=" in out:
                raise Fail(f"the fetch ended while waiting for {what}: {out[-800:]}")
            time.sleep(1)
        raise Fail(f"timed out waiting for {what}")

    order = []
    try:
        for i in range(2):
            out = wait_out(lambda o: len(re.findall(r'Insert disk "([^"]+)"', o)) > i, f"prompt {i + 1}")
            label = re.findall(r'Insert disk "([^"]+)"', out)[i]
            order.append(label)
            dl_attach(label.lower())
            for _ in range(20):
                if run(DL_VM, "test -b /dev/vdd1", check_rc=False).returncode == 0:
                    break
                time.sleep(0.5)
            run(DL_VM, "echo > /tmp/dl-in")
            wait_out(lambda o: f"from {label}: you can now remove it" in o, f"{label} to be released")
            check(dl_unmounted("/dev/vdd1"), f"{label} is still mounted after its blocks")
            detach_disk(DL_VM, "vdd")
        out = wait_out(lambda o: "rc=" in o, "the end")
    finally:
        run(DL_VM, "pkill -f 'sleep 3600'; true", check_rc=False)
    CTX["fetch_plan"]["order"] = order
    check("rc=0" in out, f"fetch failed: {out[-800:]}")
    got = run(DL_VM, "sha256sum ~/dl-docs/film.bin").stdout.split()[0]
    check(got == want, "the fetched file differs")
    check(run(DL_VM, "test -e ~/dl-home/disk-fetch", check_rc=False).returncode != 0, "the staging area was left behind")
    dl_clean()


@scenario("staged-move-to-pool")
def s_staged_move():
    """A folder in the cloud-like "box" storage moves, disk by disk, onto a pool of
    4 GiB virtual drives (about 1.7 GiB usable on each, the pool keeps 2 GiB free):
    a job without a disk waits; `--path ... --keep-source` copies a directory; the
    whole-folder job fills the first drive, stops with "attach the next disk", and
    finishes on the second; the box then holds none of the folder's blocks."""
    dl_clean()
    dl("init --name dl")
    dl("storage add-local box /home/varsto/dl-box --place cloud", json_out=False)
    dl("storage add-pool dshelf --place home", json_out=False)
    run(DL_VM, "mkdir -p ~/dl-docs/big ~/dl-docs/small && for i in 1 2 3; do head -c 1073741824 /dev/urandom > ~/dl-docs/big/f$i.bin; done"
               " && for i in $(seq 1 20); do head -c 20000 /dev/urandom > ~/dl-docs/small/n$i.bin; done")
    dl("folder add ddocs /home/varsto/dl-docs", json_out=False)
    # The pool is filled by the job only, not by pushes or disk fills.
    dl("folder placement ddocs --storage box", json_out=False)
    # The default policy wants a copy in external storage, which the box is: a
    # move off it would break the policy. This move is the point of the scenario.
    dl("policy set ddocs --min-copies 1", json_out=False)
    dl("push ddocs")
    want = run(DL_VM, "cd ~/dl-docs && find . -type f | sort | xargs sha256sum | sha256sum").stdout.split()[0]

    def box_objects():
        return int(run(DL_VM, "find ~/dl-box/packs -type f ! -name '.*' ! -path '*/index/*' ! -path '*/tombstones/*' | wc -l").stdout)

    before = box_objects()
    check(before > 0, "the box holds nothing after the push")
    # No disk yet: the job is recorded and waits for one.
    r = dl("move ddocs --from box --to dshelf --yes")
    check(isinstance(r, dict) and "job" in r, f"move without a disk gave no job: {r}")
    job = r["job"]
    check(job["state"] == "open" and job["waiting"]["kind"] == "disk" and job["bytes_done"] == 0, f"first run: {job}")
    st = dl("move status")
    check(len(st) == 1 and st[0]["id"] == job["id"] and st[0]["bytes_remaining"] > 3 << 30, f"move status: {st}")
    sug = dl("disk suggest")["suggestions"]
    check(len(sug["new_disk_needed"]) == 1, f"disk suggest does not ask for a new disk: {sug['new_disk_needed']}")
    dl(f"move cancel {job['id']}", json_out=False)
    check(box_objects() == before, "cancelling a job changed the box")

    # The small directory first, with the source kept, onto the first drive.
    dl_attach("red")
    dl("disk init /dev/vdd --pool dshelf --label Red --confirm /dev/vdd")
    r = dl("move ddocs --from box --to dshelf --path small --keep-source --yes")
    check(r["job"]["state"] == "done" and r["job"]["disks_used"] == ["Red"], f"path job: {r['job']}")
    check(box_objects() == before, "--keep-source dropped blocks from the box")

    # The whole folder: the first drive takes what fits, then the job waits for the next one.
    r = dl("move ddocs --from box --to dshelf --yes")
    job = r["job"]
    CTX["staged_move"] = {"run1_done": job["bytes_done"], "left": job["bytes_remaining"], "waiting": job["waiting"]["text"]}
    check(job["state"] == "open" and 0 < job["bytes_done"] < 2 << 30 and job["bytes_remaining"] > 1 << 30, f"run 1: {job}")
    check(box_objects() < before, "nothing left the box")
    dl("disk unmount Red")
    detach_disk(DL_VM, "vdd")
    st = dl("disk suggest")["suggestions"]
    check(st["moves"] and (st["new_disk_needed"] or st["top"]), f"no suggestion for the waiting job: {st['moves']}")
    dl_attach("green")
    dl("disk init /dev/vdd --pool dshelf --label Green --confirm /dev/vdd")
    r = dl(f"move resume {job['id']}")
    job = r["job"]
    check(job["state"] == "done" and job["bytes_remaining"] == 0 and job["disks_used"][-1] == "Green", f"run 2: {job}")
    check(box_objects() == 0, f"the box still holds {box_objects()} objects")
    chk = dl("disk check Green --full")
    check(not chk["bad"] and not chk["missing"], f"full check: {chk}")
    got = run(DL_VM, "cd ~/dl-docs && find . -type f | sort | xargs sha256sum | sha256sum").stdout.split()[0]
    check(got == want, "the local files changed")
    dl_clean()


# ----- when things break: storage outage, black-holed network, crash, clock skew --------------

def fresh_pair():
    """laptop + desktop on this build, one folder, synced."""
    s_reset()
    v("vl-laptop", "init --name laptop")
    v("vl-laptop", f"storage add-s3 cloud --insecure-http --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                    f"--access-key-id {lab.S3['key']} --place cloud", json_out=False)
    gen_data("vl-laptop", "/home/varsto/data/docs", seed=5, big_mb=4, small=40)
    v("vl-laptop", "folder add docs /home/varsto/data/docs", json_out=False)
    v("vl-laptop", "push docs")
    kit = v("vl-laptop", "recovery kit", json_out=False)
    words = " ".join(re.findall(r"\d+\. (\w+)", kit.split("SHARES")[0]))
    v("vl-desktop", f"join --name desktop --s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-insecure-http "
                    f"--s3-access-key-id {lab.S3['key']} --storage-name cloud", env=f"VARSTO_VAULT_KEY={shlex.quote(words)}")
    v("vl-desktop", "folder attach docs /home/varsto/data/docs", json_out=False)
    v("vl-desktop", "sync")


@scenario("storage-outage-and-recovery")
def s_outage():
    fresh_pair()
    lab.cmd_services_stop(None)
    try:
        run("vl-laptop", "echo during-outage > ~/data/docs/outage.txt")
        t0 = time.time()
        r = v("vl-laptop", "sync", check_rc=False)
        secs = time.time() - t0
        CTX["outage_fail_secs"] = round(secs, 1)
        check(isinstance(r, dict) and r.get("_failed"), "sync claimed success with the storage down")
        check(secs < 60, f"sync took {secs:.0f} s to give up on a storage that refuses connections")
    finally:
        lab.cmd_services(None)
    time.sleep(1)
    v("vl-laptop", "sync")
    v("vl-desktop", "sync")
    check(run("vl-desktop", "cat ~/data/docs/outage.txt", check_rc=False).stdout.strip() == "during-outage",
          "the change made during the outage never arrived")
    fsck = v("vl-laptop", "fsck --verify", check_rc=False)
    fsck = fsck.get("_out", fsck) if isinstance(fsck, dict) and "_out" in fsck else fsck
    check(not fsck.get("chunks_missing") and not fsck.get("objects_corrupt"), f"fsck after the outage: {fsck}")


@scenario("blackholed-network")
def s_blackhole():
    # The home router drops everything to the WAN without an answer, like a
    # dead uplink: connections time out instead of being refused.
    rule = "sudo nft insert rule ip filter forward iifname eth0 oifname eth1 drop"
    lab.ssh("vl-rhome", rule)
    try:
        run("vl-laptop", "echo during-blackhole > ~/data/docs/bh.txt")
        t0 = time.time()
        r = v("vl-laptop", "sync", check_rc=False)
        secs = time.time() - t0
        CTX["blackhole_fail_secs"] = round(secs, 1)
        check(isinstance(r, dict) and r.get("_failed"), "sync claimed success with no network")
        check(secs < 150, f"sync took {secs:.0f} s to give up on an unreachable storage")
    finally:
        lab.ssh("vl-rhome", "sudo nft -f /etc/nftables.conf")
    v("vl-laptop", "sync")
    v("vl-desktop", "sync")
    check(run("vl-desktop", "cat ~/data/docs/bh.txt", check_rc=False).stdout.strip() == "during-blackhole",
          "the change made without network never arrived")


@scenario("crash-during-push")
def s_crash():
    run("vl-laptop", "head -c $((96<<20)) /dev/urandom > ~/data/docs/crash.bin")
    run("vl-laptop", f"{ENV} nohup varsto push docs > ~/crash.log 2>&1 &")
    time.sleep(1.5)
    run("vl-laptop", "pkill -9 -x varsto; true", check_rc=False)
    time.sleep(0.5)
    # The next run carries on; nothing is half-written or lost.
    v("vl-laptop", "push docs")
    v("vl-desktop", "sync")
    a = run("vl-laptop", "sha256sum ~/data/docs/crash.bin").stdout.split()[0]
    b = run("vl-desktop", "sha256sum ~/data/docs/crash.bin", check_rc=False).stdout.split()
    check(b and a == b[0], "the file pushed after a crash differs on the other device")
    fsck = v("vl-laptop", "fsck --verify", check_rc=False)
    fsck = fsck.get("_out", fsck) if isinstance(fsck, dict) and "_out" in fsck else fsck
    check(not fsck.get("chunks_missing") and not fsck.get("objects_corrupt"), f"fsck after the crash: {fsck}")
    st = v("vl-desktop", "status")
    check(not st.get("forked_devices"), f"a crash left a fork: {st.get('forked_devices')}")


def fix_clock(vm):
    """The host's time on `vm`, and time sync back on (a run cut off in a
    clock scenario must not leave a device days off)."""
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    run(vm, f"sudo date -u -s '{now}' >/dev/null; sudo timedatectl set-ntp true 2>/dev/null; true", check_rc=False)


@scenario("clock-two-days-ahead")
def s_clock():
    run("vl-desktop", "sudo timedatectl set-ntp false 2>/dev/null; sudo date -s '+2 days' >/dev/null")
    try:
        run("vl-desktop", "echo from-the-future > ~/data/docs/future.txt")
        v("vl-desktop", "sync")
        v("vl-laptop", "sync")
        check(run("vl-laptop", "cat ~/data/docs/future.txt", check_rc=False).stdout.strip() == "from-the-future",
              "a device with a wrong clock could not sync")
        # An edit on the laptop (right clock) after one from the future still wins:
        # ordering is by logical clocks, not wall time.
        run("vl-laptop", "echo now-correct > ~/data/docs/future.txt")
        v("vl-laptop", "sync")
        v("vl-desktop", "sync")
        got = run("vl-desktop", "cat ~/data/docs/future.txt").stdout.strip()
        check(got == "now-correct", f"the later edit lost to a device with a clock ahead: {got}")
    finally:
        fix_clock("vl-desktop")


@scenario("clock-two-days-behind")
def s_clock_behind():
    # Some S3 servers refuse a signature from the past with HTTP 400, not 403.
    run("vl-desktop", "sudo timedatectl set-ntp false 2>/dev/null; sudo date -s '-2 days' >/dev/null")
    try:
        run("vl-desktop", "echo from-the-past > ~/data/docs/past.txt")
        v("vl-desktop", "sync")
        v("vl-laptop", "sync")
        check(run("vl-laptop", "cat ~/data/docs/past.txt", check_rc=False).stdout.strip() == "from-the-past",
              "a device with a clock behind could not sync")
    finally:
        fix_clock("vl-desktop")


# ----- scale: many small files and one large one -------------------------------------------

def timed_rss(vm, args):
    """Run varsto, return (seconds, peak RSS in MiB, parsed output)."""
    cmd = (f"{ENV} python3 -c \"import resource,subprocess,sys,time,json; t=time.time(); "
           f"r=subprocess.run(sys.argv[1:], capture_output=True, text=True); "
           f"print(json.dumps({{'secs': time.time()-t, 'rss': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss/1024, "
           f"'rc': r.returncode, 'out': r.stdout[-2000:], 'err': r.stderr[-800:]}}))\" varsto --json {args}")
    r = json.loads(run(vm, cmd).stdout)
    if r["rc"] != 0:
        raise Fail(f"{vm}: varsto {args} failed: {r['err']}")
    return round(r["secs"], 1), round(r["rss"]), r["out"]


@scenario("scale-20k-files-and-1gb")
def s_scale():
    s_reset()
    v("vl-laptop", "init --name laptop")
    v("vl-laptop", f"storage add-s3 cloud --insecure-http --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                    f"--access-key-id {lab.S3['key']} --place cloud", json_out=False)
    run("vl-laptop", """python3 - <<'PY'
import os, random, pathlib
r = random.Random(7); root = pathlib.Path('/home/varsto/data/many')
for i in range(20000):
    d = root / f"d{i % 50:02d}" / f"e{i % 13:02d}"; d.mkdir(parents=True, exist_ok=True)
    (d / f"f{i:05d}.txt").write_bytes(r.randbytes(r.randint(100, 6000)))
PY""")
    run("vl-laptop", "mkdir -p ~/data/large && head -c $((1<<30)) /dev/urandom > ~/data/large/disk.img")
    v("vl-laptop", "folder add many /home/varsto/data/many", json_out=False)
    v("vl-laptop", "folder add large /home/varsto/data/large", json_out=False)
    res = {}
    res["push_20k"] = timed_rss("vl-laptop", "push many")[:2]
    res["push_1g"] = timed_rss("vl-laptop", "push large")[:2]
    res["rescan_20k_unchanged"] = timed_rss("vl-laptop", "push many")[:2]
    run("vl-laptop", "echo changed >> ~/data/many/d07/e07/f00007.txt")
    res["push_20k_one_changed"] = timed_rss("vl-laptop", "push many")[:2]
    kit = v("vl-laptop", "recovery kit", json_out=False)
    words = " ".join(re.findall(r"\d+\. (\w+)", kit.split("SHARES")[0]))
    v("vl-desktop", f"join --name desktop --s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-insecure-http "
                    f"--s3-access-key-id {lab.S3['key']} --storage-name cloud", env=f"VARSTO_VAULT_KEY={shlex.quote(words)}")
    v("vl-desktop", "folder attach many /home/varsto/data/many", json_out=False)
    v("vl-desktop", "folder attach large /home/varsto/data/large", json_out=False)
    res["pull_20k"] = timed_rss("vl-desktop", "pull many")[:2]
    res["pull_1g"] = timed_rss("vl-desktop", "pull large")[:2]
    CTX["scale"] = res
    print("      scale (seconds, peak MiB):", res, flush=True)
    n = int(run("vl-desktop", "find ~/data/many -type f ! -name '.varsto-folder' | wc -l").stdout)
    check(n == 20000, f"desktop has {n} of 20000 files")
    a = run("vl-laptop", "sha256sum ~/data/large/disk.img").stdout.split()[0]
    b = run("vl-desktop", "sha256sum ~/data/large/disk.img").stdout.split()[0]
    check(a == b, "the 1 GiB file differs")
    check(res["rescan_20k_unchanged"][0] < 30, f"an unchanged 20k-file folder took {res['rescan_20k_unchanged'][0]} s to scan")
    check(max(x[1] for x in res.values()) < 1200, f"peak memory above 1.2 GiB: {res}")


@scenario("p2p-while-uploading")
def s_p2p_upload():
    """A new large file reaches a device on the same LAN peer to peer while
    the slow upload to the bucket is still running: the home's link to the
    internet is held to 4 Mbit/s, so the 40 MiB upload takes over a minute."""
    fresh_pair()
    for vm in ("vl-laptop", "vl-desktop"):
        start_service(vm)
    time.sleep(20)  # LAN discovery and a first sync on both
    run("vl-rhome", "sudo tc qdisc replace dev eth1 root tbf rate 4mbit burst 32kbit latency 400ms")
    try:
        syncs_before = (api("vl-laptop", "GET", "/api/state").get("service") or {}).get("syncs")
        run("vl-laptop", "head -c $((40<<20)) /dev/urandom > ~/data/docs/big-upload.bin")
        want = run("vl-laptop", "sha256sum ~/data/docs/big-upload.bin").stdout.split()[0]
        t0 = time.time()
        got_at = None
        uploading_then = None
        served = 0
        while time.time() - t0 < 90:
            have = run("vl-desktop", "sha256sum ~/data/docs/big-upload.bin 2>/dev/null || true").stdout.split()
            if have and have[0] == want:
                got_at = time.time() - t0
                # The laptop's sync that carries the upload has not finished yet:
                # its sync counter has not moved since the file was written. (The
                # progress list shows a file only until its blocks are queued.)
                # A sync holds the service, so /api/state not answering within a
                # few seconds also means the upload's sync is still running.
                try:
                    st = api("vl-laptop", "GET", "/api/state", timeout=4).get("service") or {}
                    uploading_then = st.get("syncs") == syncs_before
                except Fail:
                    uploading_then = True
                served = (api("vl-laptop", "GET", "/api/p2p/traffic").get("totals") or {}).get("objects_out", 0)
                break
            time.sleep(1)
        CTX["p2p_while_uploading"] = {"desktop_has_it_after_s": got_at and round(got_at, 1),
                                      "laptop_still_uploading": uploading_then,
                                      "blocks_served_by_laptop": served if got_at else None}
        print("      p2p while uploading:", CTX["p2p_while_uploading"], flush=True)
        check(got_at is not None, "the desktop did not get the file within 90 s")
        check(uploading_then, "the laptop had already finished its upload: the file did not go peer to peer first")
        check(served > 0, "the laptop served no blocks to the desktop")
    finally:
        run("vl-rhome", "sudo tc qdisc del dev eth1 root", check_rc=False)
        for vm in ("vl-laptop", "vl-desktop"):
            run(vm, "pkill -x varsto; true", check_rc=False)


# ----- backups: snapshots on the storage only, restored elsewhere, expired by the clock ------

def bucket_snapshots():
    return sorted((lab.DIR / "s3" / BUCKET / "snapshots").rglob("*.enc"))


@scenario("backups")
def s_backup():
    """A directory of the laptop is backed up to the bucket only: the desktop
    lists it but never receives its contents, restores any snapshot byte for
    byte into a directory it names, and a snapshot whose retention ran out is
    deleted from the bucket once the laptop's clock has moved three days on,
    while the newer one stays restorable."""
    fresh_pair()
    pics = "/home/varsto/data/pics"
    gen_data("vl-laptop", pics, seed=11, big_mb=3, small=30)
    add = v("vl-laptop", f"backup add pics {pics} --retention-days 1 --manual")
    snap = add.get("snapshot") or {}
    check(snap.get("seq") == 1 and not snap.get("skipped"), f"first snapshot: {add}")
    first = tree_hashes("vl-laptop", pics)
    run("vl-laptop", f"rm {pics}/big.bin && echo second > {pics}/second.txt")
    v("vl-laptop", "backup set pics --retention-days 30")
    second = tree_hashes("vl-laptop", pics)
    s2 = v("vl-laptop", "backup take pics")
    check(s2.get("seq") == 2, f"second snapshot: {s2}")
    check(tree_hashes("vl-laptop", pics) == second, "taking a snapshot changed the directory")
    check(len(bucket_snapshots()) == 2, f"{len(bucket_snapshots())} snapshot objects in the bucket")

    # The desktop knows the backup but holds none of it and cannot attach it.
    v("vl-desktop", "sync")
    lst = v("vl-desktop", "backup list")
    check(len(lst) == 1 and lst[0]["snapshots"] == 2 and not lst[0]["this_device"], f"backup list on the desktop: {lst}")
    st = v("vl-desktop", "status")
    check(all(f["name"] != "pics" for f in st["folders"]), "the backup shows up as a folder")
    bad = v("vl-desktop", "folder attach pics /home/varsto/data/pics-attached", json_out=False, check_rc=False)
    check(isinstance(bad, dict) and bad.get("_failed"), "a backup could be attached as a folder")
    check(run("vl-desktop", f"test -e {pics}", check_rc=False).returncode != 0, "backup contents reached the desktop")

    # Restores on the desktop, by number and latest; a non-empty target is refused.
    v("vl-desktop", "backup restore pics 1 --to /home/varsto/data/restored1")
    same_tree(first, tree_hashes("vl-desktop", "/home/varsto/data/restored1"), "snapshot 1 restored on the desktop")
    v("vl-desktop", "backup restore pics latest --to /home/varsto/data/restored2")
    same_tree(second, tree_hashes("vl-desktop", "/home/varsto/data/restored2"), "snapshot 2 restored on the desktop")
    busy = v("vl-desktop", "backup restore pics --to /home/varsto/data/restored2", check_rc=False)
    check(isinstance(busy, dict) and busy.get("_failed"), "a restore into a directory with files went ahead")

    # Three days on, snapshot 1 (kept one day, one day of grace) goes from
    # the bucket with the blocks only it used; snapshot 2 stays.
    run("vl-laptop", "sudo timedatectl set-ntp false 2>/dev/null; sudo date -s '+3 days' >/dev/null")
    try:
        ex = v("vl-laptop", "backup expire")
        CTX["backup_expire"] = ex
        check(ex["snapshots_expired"] == 1 and ex["objects_deleted"] > 0, f"expiry: {ex}")
        check(len(bucket_snapshots()) == 1, f"{len(bucket_snapshots())} snapshot objects left in the bucket")
        seqs = [s["seq"] for s in v("vl-laptop", "backup snapshots pics")]
        check(seqs == [2], f"snapshots after the expiry: {seqs}")
    finally:
        fix_clock("vl-laptop")
    v("vl-desktop", "sync")
    v("vl-desktop", "backup restore pics latest --to /home/varsto/data/restored3")
    same_tree(second, tree_hashes("vl-desktop", "/home/varsto/data/restored3"), "snapshot 2 after the expiry")
    gone = v("vl-desktop", "backup restore pics 1 --to /home/varsto/data/restored4", check_rc=False)
    check(isinstance(gone, dict) and gone.get("_failed"), "an expired snapshot was restored")
    fsck = v("vl-desktop", "fsck --verify", check_rc=False)
    fsck = fsck.get("_out", fsck) if isinstance(fsck, dict) and "_out" in fsck else fsck
    check(not fsck.get("chunks_missing") and not fsck.get("objects_corrupt"), f"fsck after the expiry: {fsck}")


# ----- live activity: what the other device is doing, over peer to peer ----------------------

@scenario("activity")
def s_activity():
    """The laptop verifies every block in the bucket from its command line
    (slowed down to about 300 ms a block by the test hook) while both
    services run; the desktop's `varsto activity` shows the laptop's fsck
    with its progress, rate and finish time, fetched over peer to peer.
    Nobody watching on the laptop, the laptop asks nobody."""
    fresh_pair()
    for vm in ("vl-laptop", "vl-desktop"):
        start_service(vm)
    try:
        time.sleep(20)  # LAN discovery, then a sync that puts the peer in the table
        idle = v("vl-desktop", "activity")
        check(idle.get("me", {}).get("name") == "desktop", f"desktop activity: {idle}")
        run("vl-laptop", f"{ENV} VARSTO_ACTIVITY_TEST_DELAY_MS=300 nohup varsto fsck --verify > ~/fsck.log 2>&1 < /dev/null &")
        seen = None
        t0 = time.time()
        while time.time() - t0 < 60 and not seen:
            a = v("vl-desktop", "activity")
            for p in a.get("peers") or []:
                acts = (p.get("activity") or {}).get("tasks") or []
                hit = [t for t in acts if t.get("kind") == "fsck" and t.get("phase") == "verify" and t.get("done", 0) > 0]
                if p.get("name") == "laptop" and p.get("status") == "ok" and hit:
                    seen = hit[0]
            if not seen:
                time.sleep(1)
        CTX["activity_seen"] = seen
        print("      desktop saw:", seen, flush=True)
        check(seen, f"the desktop never saw the laptop's fsck: {a}")
        check(seen.get("total", 0) > 0 and seen.get("percent") is not None, f"no progress: {seen}")
        time.sleep(3)
        later = v("vl-desktop", "activity")
        text = v("vl-desktop", "activity", json_out=False)
        print("      " + text.replace("\n", "\n      "), flush=True)
        check("laptop" in text, f"text view: {text}")
        lap = [p for p in later.get("peers") or [] if p.get("name") == "laptop"]
        check(lap and lap[0].get("status") == "ok", f"laptop not answering: {later}")
    finally:
        for vm in ("vl-laptop", "vl-desktop"):
            run(vm, "pkill -x varsto; true", check_rc=False)

@scenario("scrub")
def s_scrub():
    """Bit rot on the bucket and on the laptop's disk: `varsto scrub` finds a
    damaged block the laptop itself wrote (no other device has re-read it)
    and repairs it, and moves a local file whose content changed under an
    unchanged size and time aside as .damaged-<date>, putting the synced
    version back; an edited file with a new time is left alone."""
    fresh_pair()
    packs = bucket_packs()
    check(packs, "no pack in the bucket")
    victim = packs[-1]  # one flipped byte damages the one block it lies in
    data = bytearray(victim.read_bytes())
    data[len(data) // 3] ^= 0xFF
    victim.write_bytes(bytes(data))
    time.sleep(6)  # rclone serve s3 lists from a 5 s directory cache
    rot = """
import os
p = os.path.expanduser("~/data/docs/dir1/sub1/note-1.txt")
st = os.stat(p)
b = bytearray(open(p, "rb").read())
b[len(b) // 2] ^= 0x01
open(p, "wb").write(bytes(b))
os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
e = os.path.expanduser("~/data/docs/dir2/sub2/note-2.txt")
open(e, "a").write("an edit\\n")
"""
    good = tree_hashes("vl-desktop", "/home/varsto/data/docs")
    run("vl-laptop", f"python3 - <<'PY'\n{rot}\nPY")
    r = v("vl-laptop", "scrub --full", check_rc=False)
    out = r.get("_out", r) if isinstance(r, dict) and "_out" in r else r
    check(isinstance(out, dict) and "scrub" in out, f"scrub gave no report: {r}")
    sc = out["scrub"]
    check(sc["corrupt"], f"the damaged block was not found: {sc}")
    check(out.get("repair") and out["repair"]["repaired"], f"nothing repaired: {out.get('repair')}")
    files = sc["damaged_files"]
    check(len(files) == 1 and files[0]["restored"], f"damaged files: {files}")
    check(files[0]["path"] == "dir1/sub1/note-1.txt", f"wrong file: {files[0]}")
    now = tree_hashes("vl-laptop", "/home/varsto/data/docs")
    check(now.get("./dir1/sub1/note-1.txt") == good.get("./dir1/sub1/note-1.txt"), "the synced version was not restored")
    aside = "./" + files[0]["moved_to"]
    check(aside in now, f"no {aside} on the laptop")
    check(now.get("./dir2/sub2/note-2.txt") != good.get("./dir2/sub2/note-2.txt"), "the edit was undone")
    check(not any(".damaged-" in k and "note-2" in k for k in now), "the edited file was moved aside")
    fsck = v("vl-laptop", "fsck --verify")
    check(not fsck.get("chunks_missing") and not fsck.get("objects_corrupt"), f"fsck after scrub: {fsck}")
    st = v("vl-laptop", "scrub status")
    check(st.get("totals", {}).get("files_restored") == 1, f"status: {st}")
    # The damaged copy and the edit reach the desktop as ordinary files.
    v("vl-laptop", "sync")
    v("vl-desktop", "sync")
    same_tree(tree_hashes("vl-desktop", "/home/varsto/data/docs"), tree_hashes("vl-laptop", "/home/varsto/data/docs"), "after sync")


@scenario("ledger-loss")
def s_ledger_loss():
    """S2: the laptop's local ledger directory is deleted. A sync stops and
    suggests `varsto ledger rebuild`, status says so, the rebuild takes the
    laptop's own batches back from the bucket and its next batch continues
    the numbering: the desktop gets the new file and sees no fork. S4: the
    ledger goes from the bucket and from both devices; the laptop's service
    restores what it can and rebuilds where the blocks are from the bucket
    by itself; the desktop rebuilds its own, gets a new file, and fsck
    --verify is clean on both."""
    import shutil
    fresh_pair()
    home = "~/.local/share/varsto"
    st = v("vl-laptop", "ledger status")
    check(st["health"]["state"] == "ok", f"ledger not ok before: {st['health']}")
    head = next(d for d in st["devices"] if d["this_device"])["head"]
    CTX["ledger_head_before_loss"] = head

    # S2
    run("vl-laptop", f"rm -rf {home}/ledger")
    run("vl-laptop", "echo after-loss > ~/data/docs/after-loss.txt")
    r = v("vl-laptop", "sync", check_rc=False)
    check(isinstance(r, dict) and r.get("_failed") and "varsto ledger rebuild" in r.get("_err", ""),
          f"sync after the loss did not stop with the advice: {r}")
    s = v("vl-laptop", "status")
    check(s["ledger_health"]["state"] == "rebuild_needed", f"status: {s['ledger_health']}")
    rb = v("vl-laptop", "ledger rebuild")
    check(rb["own_head_after"] == head, f"own head {rb['own_head_after']}, was {head}")
    check(rb["health"]["state"] == "ok", f"after rebuild: {rb['health']}")
    v("vl-laptop", "sync")
    st = v("vl-laptop", "ledger status")
    now = next(d for d in st["devices"] if d["this_device"])["head"]
    check(now == head + 1, f"next batch is #{now}, expected #{head + 1}")
    v("vl-desktop", "sync")
    got = run("vl-desktop", "cat ~/data/docs/after-loss.txt", check_rc=False).stdout.strip()
    check(got == "after-loss", "the file written after the loss did not arrive")
    ds = v("vl-desktop", "status")
    check(not ds.get("forked_devices"), f"the desktop sees a fork: {ds.get('forked_devices')}")

    # S4
    shutil.rmtree(lab.DIR / "s3" / BUCKET / "ledger", ignore_errors=True)
    for vm in ("vl-laptop", "vl-desktop"):
        run(vm, f"rm -rf {home}/ledger")
    time.sleep(6)  # rclone serve s3 lists from a 5 s directory cache
    try:
        start_service("vl-laptop")
        deadline = time.time() + 600
        state = None
        while time.time() < deadline:
            s = api("vl-laptop", "GET", "/api/status")
            state = (s.get("ledger_health") or {}).get("state")
            folders = s.get("folders") or []
            if state == "ok" and folders and folders[0].get("chunks_without_storage_copy") == 0:
                break
            time.sleep(5)
        check(state == "ok", f"the service did not rebuild the ledger: {state}")
        check(folders[0].get("chunks_without_storage_copy") == 0, f"blocks without a recorded copy: {folders[0]}")
        log = run("vl-laptop", "cat ~/svc.log").stdout
        check("where the blocks are was rebuilt" in log, "the service did not rebuild the claims: " + log[-600:])
    finally:
        run("vl-laptop", "pkill -x varsto; true", check_rc=False)
    rb = v("vl-desktop", "ledger rebuild")
    check(rb["reenrolled"], f"desktop rebuild: {rb}")
    run("vl-laptop", "echo after-rebuild > ~/data/docs/after-rebuild.txt")
    v("vl-laptop", "sync")
    v("vl-desktop", "sync")
    got = run("vl-desktop", "cat ~/data/docs/after-rebuild.txt", check_rc=False).stdout.strip()
    check(got == "after-rebuild", "the file written after the rebuild did not arrive")
    same_tree(tree_hashes("vl-desktop", "/home/varsto/data/docs"), tree_hashes("vl-laptop", "/home/varsto/data/docs"), "after the rebuild")
    for vm in ("vl-laptop", "vl-desktop"):
        fsck = v(vm, "fsck --verify")
        check(not fsck.get("chunks_missing") and not fsck.get("objects_corrupt") and not fsck.get("forked_devices"),
              f"{vm}: fsck after the rebuild: {fsck}")
        check(fsck.get("ledger_health", {}).get("state") == "ok", f"{vm}: {fsck.get('ledger_health')}")

@scenario("ledger-withhold")
def s_ledger_withhold():
    """Spec 58. The bucket withholds one ledger batch of the laptop and
    offers the next: the desktop's head for the laptop stays before the gap
    (the next batch waits), and after three syncs the desktop warns that a
    storage may be withholding the laptop's batches. Once the bucket offers
    the batch again both count and the warning goes. Junk under the
    laptop's own ledger name does not fence it, and `ledger clean-junk
    --yes` deletes exactly that."""
    fresh_pair()
    lap = v("vl-laptop", "status")["device_id"]
    ledger_dir = lab.DIR / "s3" / BUCKET / "ledger" / lap

    def head(vm, dev):
        st = v(vm, "ledger status", check_rc=False)
        st = st.get("_out", st) if isinstance(st, dict) and "_out" in st else st
        return next((d["head"] for d in st["devices"] if d["device"] == dev), 0), st["health"]

    v("vl-desktop", "sync")
    h0, _ = head("vl-desktop", lap)
    for i in (1, 2):
        run("vl-laptop", f"echo withheld-{i} > ~/data/docs/withheld-{i}.txt")
        v("vl-laptop", "sync")
    h_lap, _ = head("vl-laptop", lap)
    check(h_lap >= h0 + 2, f"laptop head {h_lap}, desktop saw {h0}")
    gap = h0 + 1
    hidden = lab.DIR / f"withheld-{gap:016}.json"
    shutil.move(str(ledger_dir / f"{gap:016}.json"), hidden)
    try:
        time.sleep(6)  # rclone serve s3 lists from a 5 s directory cache
        for pull in (1, 2, 3):
            v("vl-desktop", "sync")
            h, health = head("vl-desktop", lap)
            check(h == h0, f"pull {pull}: the desktop's head for the laptop passed the gap ({h}, gap at {gap})")
            behind = [b for b in health.get("behind", []) if b["device"] == lap]
            check(behind and behind[0]["pulls"] == pull, f"pull {pull}: gap not noticed: {health}")
        warned = " ".join(health.get("warnings", []))
        check("withholding" in warned, f"no warning after three pulls: {health}")
        s = v("vl-desktop", "status")
        check("withholding" in json.dumps(s["ledger_health"]), f"status does not show it: {s['ledger_health']}")
    finally:
        if hidden.exists():
            shutil.move(str(hidden), ledger_dir / f"{gap:016}.json")
    time.sleep(6)
    v("vl-desktop", "sync")
    h, health = head("vl-desktop", lap)
    check(h >= h0 + 2, f"after the batch came back the head is {h}")
    check(not health.get("behind") and not health.get("warnings"), f"still warned: {health}")

    # Junk under the laptop's own name.
    (ledger_dir / "9999999999999999.json").write_text("junk")
    time.sleep(6)
    run("vl-laptop", "echo after-junk > ~/data/docs/after-junk.txt")
    v("vl-laptop", "sync")
    st = v("vl-laptop", "status")["ledger_health"]
    check(st["state"] == "ok" and st.get("junk_objects") == 1, f"junk: {st}")
    r = v("vl-laptop", "ledger clean-junk --yes")
    check(r["deleted"] == 1 and r["genuine"] > 0, f"clean-junk: {r}")
    check(not (ledger_dir / "9999999999999999.json").exists(), "the junk is still in the bucket")
    v("vl-desktop", "sync")
    got = run("vl-desktop", "cat ~/data/docs/after-junk.txt", check_rc=False).stdout.strip()
    check(got == "after-junk", "the file written beside the junk did not arrive")


@scenario("ledger-rollback")
def s_ledger_rollback():
    """Spec 74. The bucket's ledger of the laptop goes back to an older copy
    after the laptop pushed two more batches, while the desktop has not
    pulled them yet. Nothing signed in the bucket contradicts the old state,
    but the laptop tells the desktop over peer-to-peer how far it holds its
    own ledger (head statement, `/p2p/heads`, `/p2p/changed`, rendezvous
    record): the desktop's gap has the source `peer`, and after three pulls
    it warns that a storage may be withholding or rolling back the laptop's
    batches. When the newer copy is back the warning goes."""
    fresh_pair()
    lap = v("vl-laptop", "status")["device_id"]
    ledger_dir = lab.DIR / "s3" / BUCKET / "ledger" / lap
    stun = " ".join(f"--stun {x}" for x in lab.STUN)
    for vm in ("vl-laptop", "vl-desktop"):
        v(vm, f"p2p enable {stun}", json_out=False)
        start_service(vm)
    time.sleep(40)  # rendezvous records travel through the bucket
    old = lab.DIR / "ledger-rollback-old"
    newer = lab.DIR / "ledger-rollback-newer"
    shutil.rmtree(old, ignore_errors=True)
    shutil.rmtree(newer, ignore_errors=True)
    shutil.copytree(ledger_dir, old)
    # The desktop stops pulling, the laptop writes two more batches.
    api("vl-desktop", "POST", "/api/service/pause", {"paused": True})
    for i in (1, 2):
        run("vl-laptop", f"echo rollback-{i} > ~/data/docs/rollback-{i}.txt")
        v("vl-laptop", "sync")
    time.sleep(10)  # the laptop's service rebuilds what it serves after a sync
    shutil.move(str(ledger_dir), newer)
    shutil.copytree(old, ledger_dir)
    try:
        time.sleep(6)  # rclone serve s3 lists from a 5 s directory cache
        api("vl-desktop", "POST", "/api/service/pause", {"paused": False})
        health = {}
        for pull in (1, 2, 3):
            v("vl-desktop", "sync")
            health = api("vl-desktop", "GET", "/api/ledger/health")
            behind = [b for b in health.get("behind", []) if b["device"] == lap]
            check(behind and behind[0]["source"] == "peer",
                  f"pull {pull}: the laptop's statement did not reveal the gap: {health}")
        warned = " ".join(health.get("warnings", []))
        check("rolling back" in warned, f"no warning after three pulls: {health}")
        s = v("vl-desktop", "status")
        check("rolling back" in json.dumps(s["ledger_health"]), f"status does not show it: {s['ledger_health']}")
    finally:
        shutil.rmtree(ledger_dir, ignore_errors=True)
        shutil.move(str(newer), ledger_dir)
    time.sleep(6)
    v("vl-desktop", "sync")
    health = api("vl-desktop", "GET", "/api/ledger/health")
    check(not health.get("behind") and not health.get("warnings"), f"still warned after the newer copy came back: {health}")


def ensure_restic(vm):
    """restic on the VM: the image's, Debian's package, or a copy of the
    binary named by VARSTO_LAB_RESTIC (best a static release build) or of
    the host's /usr/bin/restic, put in ~/bin."""
    if run(vm, "PATH=$HOME/bin:$PATH restic version", check_rc=False).returncode == 0:
        return
    run(vm, "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq restic >/dev/null 2>&1", check_rc=False)
    if run(vm, "PATH=$HOME/bin:$PATH restic version", check_rc=False).returncode == 0:
        return
    import os
    import subprocess
    src = pathlib.Path(os.environ.get("VARSTO_LAB_RESTIC", "/usr/bin/restic"))
    check(src.is_file(), f"no restic for {vm}: set VARSTO_LAB_RESTIC to a static restic binary")
    r = subprocess.run(lab.ssh_cmd(vm, "mkdir -p ~/bin && cat > ~/bin/restic && chmod +x ~/bin/restic"),
                       input=src.read_bytes(), capture_output=True)
    check(r.returncode == 0, f"copying restic to {vm} failed: {r.stderr[-300:]!r}")
    v_ = run(vm, "PATH=$HOME/bin:$PATH restic version", check_rc=False)
    check(v_.returncode == 0, f"{src} does not run on {vm} (use a static build): {(v_.stderr or v_.stdout)[-300:]}")


@scenario("restic")
def s_restic():
    """The desktop becomes the restic device: `restic setup --move` moves its
    docs folder into the mirror, `restic run` backs it up into a local
    repository, and `restic restore` alone gives back the laptop's files;
    a second run goes through the running service's API (hold and check)
    and a later file arrives in the next snapshot."""
    fresh_pair()
    vm = "vl-desktop"
    ensure_restic(vm)
    renv = "PATH=$HOME/bin:$PATH"
    run(vm, "rm -rf ~/restic-repo ~/restic-restore ~/data/mirror; printf 'lab restic password\\n' > ~/restic-pw; chmod 600 ~/restic-pw")
    r = run(vm, f"{renv} {ENV} varsto restic setup --root /home/varsto/data/mirror --repo /home/varsto/restic-repo "
                "--password-file /home/varsto/restic-pw --init --manual", check_rc=False)
    check(r.returncode != 0 and "--move" in r.stderr, f"setup did not refuse the attached folder: {r.stderr[-400:]}")
    r = run(vm, f"{renv} {ENV} varsto --json restic setup --root /home/varsto/data/mirror --repo /home/varsto/restic-repo "
                "--password-file /home/varsto/restic-pw --init --manual --move").stdout
    setup = json.loads(r)
    check(setup["setup"]["moved"], f"docs was not moved: {setup}")
    short = setup["config"]["vault_short"]
    out = run(vm, f"{renv} {ENV} varsto --json restic run", check_rc=False)
    check(out.returncode == 0, f"restic run failed ({out.returncode}): {out.stdout[-600:]} {out.stderr[-600:]}")
    rep = json.loads(out.stdout)
    check(rep["result"] == "ok" and rep["record"]["snapshot_id"], f"run: {rep}")
    rr = run(vm, f"{renv} RESTIC_REPOSITORY=~/restic-repo RESTIC_PASSWORD_FILE=~/restic-pw restic restore latest "
                 f"--tag varsto,vault:{short} --target ~/restic-restore", check_rc=False)
    check(rr.returncode == 0, f"restic restore: {rr.stderr[-400:]}")
    same_tree(tree_hashes("vl-laptop", "/home/varsto/data/docs"),
              tree_hashes(vm, "/home/varsto/restic-restore/home/varsto/data/mirror/docs"), "restored from restic")
    check(run(vm, "grep -q 'folder: docs' ~/restic-restore/home/varsto/data/mirror/VARSTO-SNAPSHOT.txt",
              check_rc=False).returncode == 0, "no VARSTO-SNAPSHOT.txt in the snapshot")
    # A new file on the laptop; the second run goes through the desktop's service.
    run("vl-laptop", "echo 'after the first snapshot' > ~/data/docs/later.txt")
    v("vl-laptop", "sync")
    start_service(vm)
    try:
        out = run(vm, f"{renv} {ENV} varsto --json restic run --no-check", check_rc=False)
        check(out.returncode == 0, f"second run ({out.returncode}): {out.stdout[-600:]} {out.stderr[-600:]}")
        ls = run(vm, f"{renv} RESTIC_REPOSITORY=~/restic-repo RESTIC_PASSWORD_FILE=~/restic-pw restic ls latest "
                     f"--tag varsto,vault:{short}").stdout
        check("/home/varsto/data/mirror/docs/later.txt" in ls, "the later file is not in the second snapshot")
        st = run(vm, f"{renv} {ENV} varsto --json restic status").stdout
        st = json.loads(st)
        check(st["state"]["last_run"]["result"] == "ok" and not st["held_now"], f"status: {st}")
    finally:
        run(vm, "pkill -x varsto; true", check_rc=False)


# ----- upgrade from the last release (alpha.14) --------------------------------------------

A14_URL = "https://varsto.net/downloads/varsto-0.0.1-alpha.14-x86_64-unknown-linux-musl.tar.gz"
A14_SUMS = "https://varsto.net/downloads/SHA256SUMS"
A14_BIN = "/opt/varsto/varsto14"
# What this build does with a vault made by alpha.14: "opens" (format version
# unchanged) or "refused" (format version moved on: refused with a message
# that says the vault must be recreated).
UPGRADE_EXPECT = "refused"


def fetch_alpha14():
    """The released alpha.14 Linux binary (cached under the lab directory),
    its package checked against the published SHA256SUMS."""
    import urllib.request
    d = lab.DIR / "alpha14"
    binp = d / "varsto"
    if binp.exists():
        return binp
    d.mkdir(exist_ok=True)
    name = A14_URL.rsplit("/", 1)[1]
    pkg = d / name
    pkg.write_bytes(urllib.request.urlopen(A14_URL, timeout=120).read())
    sums = urllib.request.urlopen(A14_SUMS, timeout=60).read().decode()
    want = next(line.split()[0] for line in sums.splitlines() if line.strip().endswith(name))
    got = hashlib.sha256(pkg.read_bytes()).hexdigest()
    check(got == want, f"alpha.14 package: sha256 {got} but SHA256SUMS says {want}")
    with tarfile.open(pkg) as t:
        member = next(m for m in t.getmembers() if m.name.endswith("/varsto") and m.isfile())
        binp.write_bytes(t.extractfile(member).read())
    binp.chmod(0o755)
    return binp


def copy_to_vm(vm, local, remote):
    lab.sh(["scp", "-q", "-i", str(lab.key_path()), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", str(local), f"{lab.USER}@{lab.ip_of(vm)}:{remote}.new"])
    run(vm, f"chmod 755 {remote}.new && mv {remote}.new {remote}")


def v14(vm, args, json_out=True, check_rc=True, env="", home=""):
    """Like v(), with the released alpha.14 binary (/opt/varsto/varsto14)."""
    cmd = f"{ENV} {env} {A14_BIN} {home} {'--json ' if json_out else ''}{args}"
    r = run(vm, cmd, check_rc=check_rc)
    out = r.stdout.strip()
    if not check_rc and r.returncode != 0:
        return {"_failed": True, "_rc": r.returncode, "_err": (r.stderr or "").strip(), "_out": out}
    if json_out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out
    return out


def outcome(r):
    """(exit code, message) of a v(..., check_rc=False) result."""
    if isinstance(r, dict) and r.get("_failed"):
        return r["_rc"], (str(r.get("_err") or "") + " " + json.dumps(r.get("_out")))[:700]
    return 0, "ok"


@scenario("upgrade-from-alpha-14")
def s_upgrade():
    """A vault made and filled with the released alpha.14 (S3 and a local
    storage, a folder of a few thousand small files, one of large files, a
    shared folder) is opened with this build: status, fsck --verify, a fresh
    device joining with the vault words, byte-identical files, new files both
    ways, an unforked ledger, `verify`. Everything seen is kept in
    CTX["upgrade"] (results.json). When UPGRADE_EXPECT is "refused" the old
    vault must be refused with a clear message instead."""
    old = fetch_alpha14()
    s_reset()
    for vm in lab.DEVICES:
        run(vm, "rm -rf ~/share-home ~/shared ~/box ~/deskbox", check_rc=False)
    for vm in ("vl-laptop", "vl-desktop", "vl-pub", "vl-work"):
        copy_to_vm(vm, old, A14_BIN)
    seen = CTX["upgrade"] = {"alpha14_sha256": hashlib.sha256(old.read_bytes()).hexdigest()}
    ver = run("vl-laptop", f"{A14_BIN} --version").stdout.strip()
    check("alpha.14" in ver, f"old binary says {ver}")
    s3 = (f"--s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-insecure-http --s3-access-key-id {lab.S3['key']} "
          "--storage-name cloud")
    # --- alpha.14 builds the vault
    v14("vl-laptop", "init --name laptop")
    v14("vl-laptop", f"storage add-s3 cloud --insecure-http --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                      f"--access-key-id {lab.S3['key']} --place cloud", json_out=False)
    v14("vl-laptop", "storage add-local box /home/varsto/box --place home", json_out=False)
    run("vl-laptop", """python3 - <<'PY'
import random, pathlib
r = random.Random(14)
root = pathlib.Path('/home/varsto/data/many')
for i in range(3000):
    d = root / f"d{i % 30:02d}" / f"e{i % 7:02d}"; d.mkdir(parents=True, exist_ok=True)
    (d / f"f{i:04d}.txt").write_bytes(r.randbytes(r.randint(50, 5000)))
(root / "Ääkköset ja välilyönnit.txt").write_text("unicode name\\n")
big = pathlib.Path('/home/varsto/data/large'); big.mkdir(parents=True, exist_ok=True)
for n, mb in (("a.bin", 40), ("b.bin", 70), ("c.bin", 5)):
    (big / n).write_bytes(r.randbytes(mb << 20))
(big / "zeros.bin").write_bytes(bytes(8 << 20))
m = pathlib.Path('/home/varsto/data/media'); m.mkdir(parents=True, exist_ok=True)
(m / "shared.bin").write_bytes(r.randbytes(9 << 20))
(m / "note.txt").write_text("shared note\\n")
PY""")
    for name in ("many", "large", "media"):
        v14("vl-laptop", f"folder add {name} /home/varsto/data/{name}", json_out=False)
    for name in ("many", "large", "media"):
        v14("vl-laptop", f"push {name}")
    kit = v14("vl-laptop", "recovery kit", json_out=False)
    words = " ".join(re.findall(r"\d+\. (\w+)", kit.split("SHARES")[0]))
    check(len(words.split()) == 24, "no recovery words")
    v14("vl-desktop", f"join --name desktop {s3}", env=f"VARSTO_VAULT_KEY={shlex.quote(words)}")
    v14("vl-desktop", "storage add-local deskbox /home/varsto/deskbox --place home", json_out=False)
    for name in ("many", "large", "media"):
        v14("vl-desktop", f"folder attach {name} /home/varsto/data/{name}", json_out=False)
        v14("vl-desktop", f"sync {name}")
    # A member of the shared folder (another person: a vault of its own).
    home = "--home /home/varsto/share-home"
    req = v14("vl-work", "share request --name ville", home=home)
    tok = v14("vl-laptop", f"share create media --to {shlex.quote(req['request_code'])} --fingerprint {shlex.quote(req['fingerprint'])}", json_out=False)
    token = re.search(r"(vst[12]\.\S+)", tok)
    check(token, "no sealed token: " + tok[-300:])
    out = v14("vl-work", f"share accept --name ville-pc --token {shlex.quote(token.group(1))} --storage-name owner "
                         f"--s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-insecure-http --s3-access-key-id {lab.S3['key']}",
              json_out=False, home=home)
    check("joined shared folder media" in out, out[-300:])
    v14("vl-laptop", "push media", check_rc=False)
    v14("vl-work", "folder attach media /home/varsto/shared", json_out=False, home=home)
    v14("vl-work", "sync", home=home)
    for vm in ("vl-laptop", "vl-desktop"):
        v14(vm, "sync")
    base = {name: tree_hashes("vl-laptop", f"/home/varsto/data/{name}") for name in ("many", "large", "media")}
    check(len(base["many"]) == 3001 and len(base["large"]) == 4, f"baseline sizes: {[len(x) for x in base.values()]}")
    for name, tree in base.items():
        same_tree(tree, tree_hashes("vl-desktop", f"/home/varsto/data/{name}"), f"alpha.14 laptop vs desktop, {name}")
    same_tree(base["media"], tree_hashes("vl-work", "/home/varsto/shared"), "alpha.14 shared folder on the member")
    fsck14 = v14("vl-laptop", "fsck --verify")
    check(not fsck14["chunks_missing"] and not fsck14.get("objects_corrupt"), f"alpha.14 fsck: {fsck14}")
    seen["baseline_files"] = {k: len(t) for k, t in base.items()}
    # --- this build opens it
    seen["new_version"] = run("vl-laptop", "varsto --version").stdout.strip()
    st = v("vl-laptop", "status", check_rc=False)
    seen["status_rc"], seen["status"] = outcome(st)
    fsck = v("vl-laptop", "fsck --verify", check_rc=False)
    seen["fsck_rc"], seen["fsck"] = outcome(fsck)
    print("      upgrade:", json.dumps(seen)[:900], flush=True)
    if UPGRADE_EXPECT == "refused":
        # Format 2 (blocks in packs) does not read the objects of format 1:
        # the vault is refused when it is opened, and the message says what to do.
        text = (str(seen["status"]) + str(seen["fsck"])).lower()
        check(seen["status_rc"] != 0 and seen["fsck_rc"] != 0 and "recreate the vault" in text and "alpha.14" in text,
              f"the new build did not refuse the alpha.14 vault clearly: {seen}")
        # Joining through the storage of an alpha.14 vault is refused the same way.
        j = v("vl-pub", f"join --name pub {s3}", env=f"VARSTO_VAULT_KEY={shlex.quote(words)}", check_rc=False)
        rc, msg = outcome(j)
        seen["join_rc"], seen["join"] = rc, msg
        check(rc != 0 and "recreate the vault" in msg.lower(), f"joining an alpha.14 vault: {rc} {msg}")
        # The old binary keeps working on its own vault, and refuses a vault of the new format.
        check(outcome(v14("vl-laptop", "status", check_rc=False))[0] == 0, "alpha.14 cannot open its own vault any more")
        run("vl-desktop", "rm -rf ~/newfmt", check_rc=False)
        v("vl-desktop", "--home /home/varsto/newfmt init --name newfmt", check_rc=True)
        r = v14("vl-desktop", "status", home="--home /home/varsto/newfmt", check_rc=False)
        rc, msg = outcome(r)
        seen["alpha14_on_new_vault"] = [rc, msg]
        check(rc != 0 and "not readable" in msg, f"alpha.14 on a format 2 vault: {rc} {msg}")
        # The way forward the message names: reset, init, sync the files into a new vault.
        # The new vault goes into the emptied bucket (rclone serve s3 lists from a 5 s cache).
        for d in (lab.DIR / "s3" / BUCKET).glob("*"):
            shutil.rmtree(d) if d.is_dir() else d.unlink()
        time.sleep(6)
        v("vl-laptop", "reset --yes", json_out=False)
        v("vl-laptop", "init --name laptop")
        v("vl-laptop", f"storage add-s3 fresh --insecure-http --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                       f"--access-key-id {lab.S3['key']} --place cloud", json_out=False)
        v("vl-laptop", "folder add many2 /home/varsto/data/many", json_out=False)
        v("vl-laptop", "push many2")
        f = v("vl-laptop", "fsck --verify")
        check(not f["chunks_missing"] and not f.get("objects_corrupt"), f"fsck of the recreated vault: {f}")
        run("vl-desktop", "rm -rf ~/newfmt")
        return
    check(seen["status_rc"] == 0, f"status of the alpha.14 vault: {seen['status']}")
    check(seen["fsck_rc"] == 0 and not fsck["chunks_missing"] and not fsck.get("objects_corrupt"), f"fsck --verify: {seen['fsck']}")
    v("vl-desktop", "status")
    v("vl-desktop", "fsck --verify")
    for name in ("many", "large", "media"):
        v("vl-laptop", f"sync {name}")
        v("vl-desktop", f"sync {name}")
        same_tree(base[name], tree_hashes("vl-laptop", f"/home/varsto/data/{name}"), f"laptop after the upgrade, {name}")
        same_tree(base[name], tree_hashes("vl-desktop", f"/home/varsto/data/{name}"), f"desktop after the upgrade, {name}")
    # A third, fresh device joins the old vault with its words.
    v("vl-pub", f"join --name pub {s3}", env=f"VARSTO_VAULT_KEY={shlex.quote(words)}")
    for name in ("many", "large", "media"):
        v("vl-pub", f"folder attach {name} /home/varsto/data/{name}", json_out=False)
        v("vl-pub", f"sync {name}")
        same_tree(base[name], tree_hashes("vl-pub", f"/home/varsto/data/{name}"), f"fresh device, {name}")
    # New files on both devices; two-way sync converges.
    run("vl-laptop", "head -c 3000000 /dev/urandom > ~/data/large/new-from-laptop.bin; echo laptop > ~/data/many/new-from-laptop.txt")
    run("vl-desktop", "head -c 2000000 /dev/urandom > ~/data/large/new-from-desktop.bin; echo desktop > ~/data/many/new-from-desktop.txt")
    for _ in range(2):
        for vm in ("vl-laptop", "vl-desktop", "vl-pub"):
            v(vm, "sync")
    for name, ext in (("many", "txt"), ("large", "bin")):
        t = tree_hashes("vl-laptop", f"/home/varsto/data/{name}")
        check(f"./new-from-desktop.{ext}" in t and f"./new-from-laptop.{ext}" in t, f"{name}: a new file did not arrive")
        same_tree(t, tree_hashes("vl-desktop", f"/home/varsto/data/{name}"), f"after new files, {name}, laptop vs desktop")
        same_tree(t, tree_hashes("vl-pub", f"/home/varsto/data/{name}"), f"after new files, {name}, laptop vs pub")
    for vm in ("vl-laptop", "vl-desktop", "vl-pub"):
        f = v(vm, "fsck --verify")
        check(not f["chunks_missing"] and not f.get("objects_corrupt") and not f.get("forked_devices"), f"{vm} fsck after the upgrade: {f}")
        ls = v(vm, "ledger status")
        check(not (isinstance(ls, dict) and ls.get("forked_devices")), f"{vm} ledger fork: {ls}")
        seen[f"ledger_status_{vm}"] = ls
    vr = v("vl-laptop", "verify run", check_rc=False)
    check(outcome(vr)[0] == 0, f"verify run: {vr}")
    seen["verify"] = vr
    # The member of the shared folder stays on alpha.14 while the owner is on this build.
    run("vl-laptop", "echo from-owner-after-upgrade > ~/data/media/after.txt")
    v("vl-laptop", "sync media")
    seen["alpha14_member_sync"] = outcome(v14("vl-work", "sync", home=home, check_rc=False))

# ----- forwarding, the live board and pairing with a wrong address ----------------------------

@scenario("forwarding-and-viz")
def s_forward():
    """Spec 70: the "phone" (pub, reachable) writes a camera folder but its only
    storage, the hub bucket, is at its quota, so no block goes anywhere. The
    laptop keeps the folder selective (placeholders only) and has a storage in
    the place "cloud" that the folder's policy wants a copy in: `forward run`
    carries the phone's blocks from the phone, as a peer, to that storage. The
    live board (`GET /api/viz`) of the running service answers meanwhile."""
    s_reset()
    run("vl-pub", "rm -rf ~/data/camera ~/sel-cam ~/cloud", check_rc=False)
    run("vl-laptop", "rm -rf ~/sel-cam ~/cloud", check_rc=False)
    v("vl-pub", "init --name phone")
    v("vl-pub", f"storage add-s3 hub --insecure-http --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                f"--access-key-id {lab.S3['key']} --place home", json_out=False)
    v("vl-pub", "storage quota hub --bytes 1", json_out=False)
    run("vl-pub", "mkdir -p ~/data/camera && for i in 1 2 3; do head -c 700000 /dev/urandom > ~/data/camera/pic$i.jpg; done")
    v("vl-pub", "folder add camera /home/varsto/data/camera", json_out=False)
    v("vl-pub", "policy set camera --min-copies 1 --place cloud=1", json_out=False)
    pushed = v("vl-pub", "push camera", check_rc=False)
    check("quota" in json.dumps(pushed), f"the phone's push did not meet the quota: {pushed}")
    check(not bucket_packs(), f"the hub is at its quota but holds {len(bucket_packs())} packs")
    kit = v("vl-pub", "recovery kit", json_out=False)
    words = " ".join(re.findall(r"\d+\. (\w+)", kit.split("SHARES")[0]))
    v("vl-laptop", f"join --name laptop --s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-insecure-http "
                   f"--s3-access-key-id {lab.S3['key']} --storage-name hub", env=f"VARSTO_VAULT_KEY={shlex.quote(words)}")
    v("vl-laptop", "storage add-local cloud /home/varsto/cloud --place cloud", json_out=False)
    v("vl-laptop", "folder attach camera /home/varsto/sel-cam --selective", json_out=False)
    v("vl-laptop", "sync")
    stun = " ".join(f"--stun {x}" for x in lab.STUN)
    v("vl-pub", f"p2p enable {stun} --public 198.51.100.20:17893", json_out=False)
    v("vl-laptop", f"p2p enable {stun}", json_out=False)
    for vm in ("vl-pub", "vl-laptop"):
        start_service(vm)
    try:
        viz = api("vl-laptop", "GET", "/api/viz")
        check(isinstance(viz, dict) and "_raw" not in viz and viz, f"/api/viz: {str(viz)[:200]}")
        CTX["viz_keys"] = sorted(viz)[:12]
        # The service forwards by itself after a sync; the rendezvous records
        # travel through the bucket first, so give it a few rounds.
        shown = {}
        for _ in range(16):
            shown = v("vl-laptop", "forward show")
            if shown.get("total_blocks", 0) >= 3:
                break
            time.sleep(10)
        CTX["forward"] = {k: shown.get(k) for k in ("total_blocks", "total_bytes", "last_error")}
        check(shown.get("total_blocks", 0) >= 3, f"nothing forwarded: {json.dumps(shown)[:600]}")
        # A second run finds nothing left to carry: every block was written once.
        again = v("vl-laptop", "forward run")
        check(again.get("blocks", 0) == 0 and not again.get("work_left"), f"forwarding again: {json.dumps(again)[:400]}")
        cloud_packs = int(run("vl-laptop", "find ~/cloud/packs -type f | wc -l").stdout)
        check(cloud_packs > 0, "the cloud storage holds no pack after forwarding")
        real = int(run("vl-laptop", "find ~/sel-cam -type f ! -name '*.varsto-placeholder' ! -name '.varsto-folder' | wc -l").stdout)
        check(real == 0, f"the forwarding device kept {real} files")
        # The cloud storage is the laptop's alone, so only the laptop can tell the policy is met.
        pol = v("vl-laptop", "policy check", check_rc=False)
        check(outcome(pol)[0] == 0, f"the policy is still violated on the laptop after forwarding: {pol}")
        fsck = v("vl-laptop", "fsck --verify")
        check(not fsck["chunks_missing"] and not fsck.get("objects_corrupt"), f"fsck --verify after forwarding: {fsck}")
        check("camera" in json.dumps(api("vl-laptop", "GET", "/api/viz")), "the live board does not know the folder")
    finally:
        for vm in ("vl-pub", "vl-laptop"):
            run(vm, "pkill -x varsto; true", check_rc=False)


@scenario("pair-wrong-address-falls-back")
def s_pair_fallback():
    """`pair join --address` with an address nobody answers on: the new device
    falls back to finding the offer on the LAN and joins."""
    s_reset()
    v("vl-laptop", "init --name laptop")
    v("vl-laptop", f"storage add-s3 cloud --insecure-http --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                   f"--access-key-id {lab.S3['key']} --place cloud", json_out=False)
    run("vl-laptop", f"{ENV} nohup varsto pair offer > ~/pair.log 2>&1 &")
    code = None
    for _ in range(30):
        m = re.search(r"Pairing code: (\d{3}-\d{3}-\d{3})", run("vl-laptop", "cat ~/pair.log").stdout)
        if m:
            code = m.group(1)
            break
        time.sleep(0.5)
    check(code, "no pairing code: " + run("vl-laptop", "cat ~/pair.log").stdout[-300:])
    out = v("vl-desktop", f"pair join --name desktop --code {code} --address 10.78.1.99:4", json_out=False)
    check("joined vault" in out, out[-400:])
    time.sleep(1)
    check("Sent the vault to desktop" in run("vl-laptop", "cat ~/pair.log").stdout, "the offer did not report the pairing")
    st = v("vl-desktop", "status")
    check(len(st.get("devices", [])) == 2, f"desktop sees {st.get('devices')}")


SCENARIOS = [s_reset, s_init, s_pair, s_sync, s_words, s_conflict, s_selective, s_repair, s_policy,
             s_strongroom, s_org, s_remove_user, s_revoke,
             s_p2p_setup, s_p2p_lan, s_p2p_pub, s_p2p_sym, s_p2p_stop, s_share, s_disks,
             s_outage, s_blackhole, s_crash, s_clock, s_clock_behind, s_p2p_upload, s_scale,
             s_backup, s_activity, s_disk_init, s_disk_fetch_plan, s_staged_move, s_scrub, s_restic, s_ledger_loss,
             s_ledger_withhold, s_upgrade, s_forward, s_pair_fallback]


def main():
    # One run at a time: two runs against the same VMs and bucket ruin both.
    import fcntl
    lock = open(lab.DIR / "scenarios.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("another scenarios.py run is using the lab; wait for it to finish")
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--binary", help="install this varsto binary into the device VMs first (under the lock)")
    a = ap.parse_args()
    if a.binary:
        lab.cmd_install_bin(argparse.Namespace(binary=a.binary))
    only = set(filter(None, a.only.split(",")))
    out_dir = REPO / "test-results" / "lab"
    out_dir.mkdir(parents=True, exist_ok=True)
    failed = 0
    for f in SCENARIOS:
        if only and f.scenario not in only:
            continue
        t0 = time.time()
        try:
            f()
            status, why = "PASS", ""
        except Fail as e:
            status, why = "FAIL", str(e)
        except SystemExit as e:
            status, why = "ERROR", f"helper gave up: {e}"
        except Exception as e:  # noqa: BLE001
            status, why = "ERROR", f"{e.__class__.__name__}: {e}\n{traceback.format_exc()[-800:]}"
        secs = round(time.time() - t0, 1)
        logs = collect_logs(f.scenario)
        if status != "PASS":
            failed += 1
        RESULTS.append({"scenario": f.scenario, "status": status, "seconds": secs, "detail": why,
                        "logs": str(logs.relative_to(REPO))})
        print(f"{status:5} {f.scenario:28} {secs:6.1f}s {why[:400]}", flush=True)
        if status != "PASS":
            print(f"      logs: {logs}", flush=True)
    (out_dir / "results.json").write_text(json.dumps({"results": RESULTS, "context": {
        k: v for k, v in CTX.items() if k not in ("vault_key", "root_words", "docs")}}, indent=1))
    sys.exit(failed)


if __name__ == "__main__":
    main()
