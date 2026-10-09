#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Summarise p2p-bench.py results (results.jsonl) into the small JSON the
website's benchmark page is written from: medians per configuration.

    report.py <work>/results.jsonl > website/src/data/benchmarks-<date>.json
"""
import json
import re
import statistics
import sys


def med(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 2) if xs else None


def main():
    rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    out = {"machines": None, "baseline": None, "datasets": {}, "push": [], "pull": [], "variants": []}
    for r in rows:
        if r["kind"] == "machines":
            out["machines"] = {"type": r["type"], "zones": r["zones"], "version": r["version"]}
        elif r["kind"] == "baseline":
            b = {"ping_ms": {}, "iperf3_mbit_s": {}, "s3": r["s3"]}
            for pair, line in r["ping"].items():
                b["ping_ms"][pair] = float(line.split("=")[1].split("/")[1])
            for k, v in r["iperf3"].items():
                b["iperf3_mbit_s"][k] = round(v["mbit_s"])
            for v in b["s3"].values():
                for k in list(v):
                    if isinstance(v[k], float):
                        v[k] = round(v[k], 1)
            out["baseline"] = b
        elif r["kind"] == "dataset":
            out["datasets"][r["set"]] = {"files": r["files"], "bytes": r["bytes"]}
    pushes = {}
    for r in rows:
        if r["kind"] == "push":
            pushes.setdefault((r["target"], r["set"], r.get("variant", "")), []).append(r)
    for (target, s, variant), rs in sorted(pushes.items()):
        rep = rs[-1]["report"]
        cpu = [float(x["time"]["user_s"]) + float(x["time"]["sys_s"]) for x in rs]
        wall = med([x["wall"] for x in rs])
        out["push"].append({
            "target": target, "set": s, "variant": variant, "runs": len(rs), "wall_s": wall,
            "files": rep.get("files_changed"), "chunks": rep.get("chunks_uploaded"),
            "bytes_stored": rep.get("bytes_uploaded"),
            "mb_s": round(out["datasets"][s]["bytes"] / 1e6 / wall, 1) if s in out["datasets"] else None,
            "cpu_s": med(cpu), "user_s": med([float(x["time"]["user_s"]) for x in rs]),
            "sys_s": med([float(x["time"]["sys_s"]) for x in rs]),
            "max_rss_mib": med([int(x["time"]["max_rss_kib"]) / 1024 for x in rs]),
        })
    pulls = {}
    for r in rows:
        if r["kind"] == "run" and r.get("variant"):
            x = r["summary"][r["readers"][0]]
            out["variants"].append({"variant": r["variant"], "mode": r["mode"], "set": r["set"], "reader": r["readers"][0],
                                    "wall_s": x["wall_s"], "mb_s": x["mb_s"], "chunks": x["chunks"]})
        elif r["kind"] == "run":
            for reader in r["readers"]:
                key = (r["mode"], r["set"], "+".join(r["readers"]), reader)
                pulls.setdefault(key, []).append((r, r["summary"][reader]))
    for (mode, s, group, reader), rs in sorted(pulls.items()):
        sums = [x for _, x in rs]
        e = {
            "mode": mode, "set": s, "group": group, "reader": reader, "runs": len(rs),
            "wall_s": med([x["wall_s"] for x in sums]),
            "wall_all_s": [x["wall_s"] for x in sums],
            "mb_s": med([x["mb_s"] for x in sums]),
            "files_s": med([x["files_s"] for x in sums]),
            "files": sums[0]["files"], "chunks": sums[0]["chunks"], "bytes": sums[0]["bytes"],
            "chunks_from_peers": [x["chunks_from_peers"] for x in sums],
            "cpu_s": med([x["cpu_s"] for x in sums]),
            "peak_rss_mib": med([x["peak_rss_mib"] for x in sums]),
            # The writer only works in the peer-to-peer runs (it is restarted between them).
            "writer_cpu_s": med([r["summary"]["writer_cpu_s"] for r, _ in rs]) if mode == "p2p" else None,
            "verified": all(x["verified"] == "identical" for x in sums),
        }
        if mode == "p2p":
            e["p2p_in_bytes"] = [sum(p.get("rx_total", 0) for p in r["traffic"][reader].get("peers", [])) for r, _ in rs]
            e["writer_tx_bytes"] = [r["traffic"]["par"]["totals"]["tx_total"] for r, _ in rs]
            e["paths"] = sorted({f"{p[0]}: {p[1]}" for x in sums for p in (x.get("paths") or [])})
            # Throw-away machines: their addresses mean nothing later, so they are left out.
            e["routes"] = sorted({re.sub(r"\d+\.\d+\.\d+\.\d+", "<writer's public address>", " ".join((x.get("routes") or "").split()))
                                  for x in sums} - {""})
        out["pull"].append(e)
    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
