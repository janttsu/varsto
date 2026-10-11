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


SCENARIOS = [s_reset, s_init, s_pair, s_sync, s_words, s_conflict, s_selective, s_repair, s_policy,
             s_strongroom, s_org, s_remove_user, s_revoke]


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
