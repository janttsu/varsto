#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""End-to-end scenarios in the lab of lab.py (run `lab.py up`, `lab.py
services`, `lab.py build` and `lab.py install-bin` first).

    scenarios.py [--only NAME[,NAME]] [--keep]     run and write test-results/lab/results.json

Every scenario prints PASS/FAIL with the reason and goes on; the exit code
is the number of failed scenarios (0: everything passed). The vault lives in
the default home of user `varsto` on each device VM; the first scenario
resets every device and empties the S3 bucket, so a run starts clean.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shlex
import sys
import time
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import lab  # noqa: E402

PASS_ = "lab-passphrase-1234"
ENV = f"VARSTO_PASSPHRASE={PASS_} VARSTO_NO_INSTALL=1"
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


def v(vm, args, json_out=True, check_rc=True):
    """Run varsto on a VM; parsed JSON (or text) out."""
    cmd = f"{ENV} varsto {'--json ' if json_out else ''}{args}"
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
    out = run(vm, f"cd {shlex.quote(path)} 2>/dev/null && find . -type f ! -name '*.varsto-placeholder' ! -name '.varsto-tmp-*' -print0 | sort -z | xargs -0 -r sha256sum").stdout
    return {line[66:]: line[:64] for line in out.splitlines() if line}


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
    v("vl-laptop", f"storage add-s3 cloud --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                    f"--access-key-id {lab.S3['key']} --secret-access-key {lab.S3['secret']} --place cloud", json_out=False)
    gen_data("vl-laptop", "/home/varsto/data/docs", seed=1)
    v("vl-laptop", "folder add docs /home/varsto/data/docs", json_out=False)
    push = v("vl-laptop", "push docs")
    check(push["files_changed"] >= 150, f"pushed {push['files_changed']} files")
    st = v("vl-laptop", "status")
    check(st["folders"][0]["chunks_without_storage_copy"] == 0, "chunks without a storage copy")
    objs = list((lab.DIR / "s3" / BUCKET / "chunks").rglob("*"))
    check(len(objs) > 20, f"only {len(objs)} objects in the bucket")
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
    out = v("vl-pub", f"join --name pub --words {shlex.quote(words)} --s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} "
                      f"--s3-access-key-id {lab.S3['key']} --s3-secret-access-key {lab.S3['secret']} --storage-name cloud")
    check("docs" in out.get("folders", []), f"pub sees {out}")
    v("vl-pub", "folder attach docs /home/varsto/data/docs", json_out=False)
    v("vl-pub", "sync")
    check(tree_hashes("vl-pub", "/home/varsto/data/docs") == CTX["docs"], "pub differs")
    # Shares: two of three rebuild the key, one does not.
    kit = v("vl-laptop", "recovery kit --shares", json_out=False)
    shares = re.findall(r"Share (\d+):\n((?:[ \t]*\d+\. \w+[ \t]*\n?)+)", kit)
    check(len(shares) == 3, "no three shares")
    enc = [f"{i}: " + " ".join(re.findall(r"\d+\. (\w+)", body)) for i, body in shares]
    out = v("vl-laptop", f"recovery combine {shlex.quote(enc[0])} {shlex.quote(enc[2])}", json_out=False)
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
    real = int(run("vl-pub", "find ~/sel -type f ! -name '*.varsto-placeholder' | wc -l").stdout)
    check(ph >= 150 and real == 0, f"placeholders {ph}, files {real}")
    v("vl-pub", "folder fetch docs big.bin")
    got = run("vl-pub", "sha256sum ~/sel/big.bin").stdout.split()[0]
    check(got == CTX["docs"]["./big.bin"], "fetched file differs")
    v("vl-pub", "folder free docs big.bin")
    check(run("vl-pub", "test -e ~/sel/big.bin.varsto-placeholder && ! test -e ~/sel/big.bin", check_rc=False).returncode == 0,
          "free did not turn the file back into a placeholder")


@scenario("damage-and-repair")
def s_repair():
    chunks = sorted(p for p in (lab.DIR / "s3" / BUCKET / "chunks").rglob("*") if p.is_file())
    victim = chunks[len(chunks) // 2]
    data = bytearray(victim.read_bytes())
    data[len(data) // 2] ^= 0xFF
    victim.write_bytes(bytes(data))
    gone = chunks[len(chunks) // 3]
    gone.unlink()
    r = v("vl-laptop", "fsck --verify", check_rc=False)
    fsck = r.get("_out", r) if isinstance(r, dict) else {}
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
    files = run("vl-desktop", "find ~/sr2 -type f ! -name '*.varsto-placeholder' 2>/dev/null | wc -l").stdout.strip()
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
    old = v("vl-work", f"join --name w2 --vault-key {CTX['vault_key']} --s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} "
                       f"--s3-access-key-id {lab.S3['key']} --s3-secret-access-key {lab.S3['secret']}", check_rc=False)
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


@scenario("p2p-setup")
def s_p2p_setup():
    s_reset()
    v("vl-laptop", "init --name laptop", json_out=True)
    key = v("vl-laptop", "recovery kit", json_out=False)
    v("vl-laptop", f"storage add-s3 cloud --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                    f"--access-key-id {lab.S3['key']} --secret-access-key {lab.S3['secret']} --place cloud", json_out=False)
    run("vl-laptop", f"mkdir -p ~/data/media && head -c {P2P_MB << 20} /dev/urandom > ~/data/media/big.bin")
    v("vl-laptop", "folder add media /home/varsto/data/media", json_out=False)
    v("vl-laptop", "push media")
    CTX["p2p_sha"] = run("vl-laptop", "sha256sum ~/data/media/big.bin").stdout.split()[0]
    words = " ".join(re.findall(r"\d+\. (\w+)", key.split("SHARES")[0]))
    for vm, name in (("vl-desktop", "desktop"), ("vl-pub", "pub"), ("vl-work", "work")):
        v(vm, f"join --name {name} --words {shlex.quote(words)} --s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} "
              f"--s3-access-key-id {lab.S3['key']} --s3-secret-access-key {lab.S3['secret']} --storage-name cloud")
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
                       f"--s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-access-key-id {lab.S3['key']} "
                       f"--s3-secret-access-key {lab.S3['secret']}", json_out=False)
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


# ----- devices on different versions (alpha.9 and this build) -------------------------------

def v9(vm, args, json_out=True, check_rc=True):
    """Like v(), with the alpha.9 binary (/opt/varsto/varsto9)."""
    cmd = f"{ENV} /opt/varsto/varsto9 {'--json ' if json_out else ''}{args}"
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


@scenario("mixed-versions")
def s_mixed():
    check(run("vl-laptop", "test -x /opt/varsto/varsto9", check_rc=False).returncode == 0, "no alpha.9 binary on the VMs")
    s_reset()
    # The laptop stays on alpha.9; desktop and pub run this build.
    out = v9("vl-laptop", "init --name laptop")
    key = out["vault_key"]
    v9("vl-laptop", f"storage add-s3 cloud --endpoint {lab.S3['endpoint']} --region us-east-1 --bucket {BUCKET} "
                     f"--access-key-id {lab.S3['key']} --secret-access-key {lab.S3['secret']} --place cloud", json_out=False)
    gen_data("vl-laptop", "/home/varsto/data/docs", seed=9, big_mb=2, small=20)
    v9("vl-laptop", "folder add docs /home/varsto/data/docs", json_out=False)
    v9("vl-laptop", "push docs")
    s3 = (f"--s3-bucket {BUCKET} --s3-endpoint {lab.S3['endpoint']} --s3-access-key-id {lab.S3['key']} "
          f"--s3-secret-access-key {lab.S3['secret']} --storage-name cloud")
    v("vl-desktop", f"join --name desktop --vault-key {key} {s3}")
    v("vl-pub", f"join --name pub --vault-key {key} {s3}")
    for vm in ("vl-desktop", "vl-pub"):
        v(vm, "folder attach docs /home/varsto/data/docs", json_out=False)
        v(vm, "sync")
    same_tree(tree_hashes("vl-laptop", "/home/varsto/data/docs"), tree_hashes("vl-desktop", "/home/varsto/data/docs"),
              "alpha.9 laptop vs new desktop")
    # Both ways.
    run("vl-desktop", "echo from-new > ~/data/docs/from-new.txt")
    v("vl-desktop", "sync")
    v9("vl-laptop", "sync")
    check(run("vl-laptop", "cat ~/data/docs/from-new.txt", check_rc=False).stdout.strip() == "from-new",
          "alpha.9 did not get a file written by the new version")
    # Policies set on either version reach the other.
    v("vl-desktop", "policy set docs --min-copies 1 --verified-within-days 30", json_out=False)
    v9("vl-laptop", "sync")
    st = v9("vl-laptop", "status")
    pol = [f.get("policy") for f in st["folders"] if f["name"] == "docs"]
    CTX["mixed_policy_seen_by_a9"] = pol
    check(pol and pol[0] and "30" in json.dumps(pol[0]), f"alpha.9 does not see the policy set by the new version: {pol}")
    v9("vl-laptop", "policy set docs --min-copies 1 --verified-within-days 60", json_out=False)
    v("vl-desktop", "sync")
    pol = [f.get("policy") for f in v("vl-desktop", "status")["folders"] if f["name"] == "docs"]
    check(pol and "60" in json.dumps(pol[0]), f"the new version does not see the policy set by alpha.9: {pol}")
    # The new version removes a device; the alpha.9 device follows the new key.
    v("vl-desktop", "device revoke pub --yes")
    v9("vl-laptop", "sync")
    run("vl-desktop", "echo after-revoke-by-new > ~/data/docs/r1.txt")
    v("vl-desktop", "sync")
    v9("vl-laptop", "sync")
    check(run("vl-laptop", "cat ~/data/docs/r1.txt", check_rc=False).stdout.strip() == "after-revoke-by-new",
          "alpha.9 lost the vault after the new version removed a device")
    # And the other way round: alpha.9 removes a device the new version knows.
    kit = v("vl-desktop", "recovery kit", json_out=False)
    words = " ".join(re.findall(r"\d+\. (\w+)", kit.split("SHARES")[0]))
    v("vl-work", f"join --name work --words {shlex.quote(words)} {s3}")
    v9("vl-laptop", "sync")
    v9("vl-laptop", "device revoke work --yes", json_out=False)
    v("vl-desktop", "sync")
    check(any(d["name"] == "work" and d["revoked"] for d in v("vl-desktop", "device list")),
          "the new version did not accept a removal made by alpha.9")
    run("vl-laptop", "echo after-revoke-by-a9 > ~/data/docs/r2.txt")
    v9("vl-laptop", "sync")
    v("vl-desktop", "sync")
    check(run("vl-desktop", "cat ~/data/docs/r2.txt", check_rc=False).stdout.strip() == "after-revoke-by-a9",
          "the new version lost the vault after alpha.9 removed a device")
    # Upgrading in place: the laptop's own directory, opened by this build.
    v("vl-laptop", "sync")
    v("vl-laptop", "fsck")
    run("vl-laptop", "echo after-upgrade > ~/data/docs/up.txt")
    v("vl-laptop", "sync")
    v("vl-desktop", "sync")
    check(run("vl-desktop", "cat ~/data/docs/up.txt", check_rc=False).stdout.strip() == "after-upgrade",
          "the upgraded laptop does not sync")


SCENARIOS = [s_reset, s_init, s_pair, s_sync, s_words, s_conflict, s_selective, s_repair, s_policy,
             s_strongroom, s_org, s_remove_user, s_revoke,
             s_p2p_setup, s_p2p_lan, s_p2p_pub, s_p2p_sym, s_p2p_stop, s_share, s_disks, s_mixed]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    only = set(filter(None, a.only.split(",")))
    out_dir = pathlib.Path(__file__).resolve().parents[3] / "test-results" / "lab"
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
        if status != "PASS":
            failed += 1
        RESULTS.append({"scenario": f.scenario, "status": status, "seconds": secs, "detail": why})
        print(f"{status:5} {f.scenario:28} {secs:6.1f}s {why[:400]}", flush=True)
    (out_dir / "results.json").write_text(json.dumps({"results": RESULTS, "context": {
        k: v for k, v in CTX.items() if k not in ("vault_key", "root_words", "docs")}}, indent=1))
    sys.exit(failed)


if __name__ == "__main__":
    main()
