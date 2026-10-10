#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Render the tables and bar charts of the website's benchmark page from the
summary JSON that report.py writes.

    page.py website/src/data/benchmarks-2026-10.json website/src/pages/benchmarks.html

Replaces what stands between `<!-- fragment: name -->` and `<!-- /fragment -->`
in the page source with freshly rendered tables and charts. The charts are inline SVG styled by classes only
(the site's Content Security Policy allows no inline styles or scripts);
every chart has a table with the same numbers next to it.
"""
import html
import json
import sys

READER = {"ams": "Amsterdam", "waw": "Warsaw"}
GROUP = {"ams": "alone", "waw": "alone", "ams+waw": "both at once"}


def fmt(x, digits=1):
    if x is None:
        return "–"
    if abs(x) >= 100:
        return f"{x:,.0f}".replace(",", " ")
    return f"{x:.{digits}f}"


def rows_for(d, s):
    """(label, p2p entry, s3 entry) per reader and group, in a fixed order."""
    out = []
    for group in ("ams", "waw", "ams+waw"):
        for reader in group.split("+"):
            p = next((e for e in d["pull"] if not e["variant"] and e["mode"] == "p2p" and e["set"] == s and e["group"] == group and e["reader"] == reader), None)
            q = next((e for e in d["pull"] if not e["variant"] and e["mode"] == "s3" and e["set"] == s and e["group"] == group and e["reader"] == reader), None)
            if p or q:
                out.append((f"{READER[reader]}, {GROUP[group]}", p, q))
    return out


EARLIER = {
    "quic-first": "Peer to peer with QUIC tried before TCP (one connection per peer), 10 October",
    "no-prefetch-across-files": "S3 before fetching ahead across files (one file at a time), 9 October",
}


def earlier_table(d, s, files):
    """The same configurations measured with an earlier build, for comparison."""
    es = [e for e in d["pull"] if e["variant"] in EARLIER and e["set"] == s]
    if not es:
        return ""
    head = "<tr><th>Build</th><th>Reader</th><th>Time</th><th>MB/s</th>" + ("<th>files/s</th>" if files else "") + "</tr>"
    body = []
    for e in es:
        runs = " / ".join(fmt(x, 0) + " s" for x in e["wall_all_s"])
        body.append(f'<tr><td>{EARLIER[e["variant"]]}</td><td>{READER[e["reader"]]}, {GROUP[e["group"]]}</td>'
                    f'<td>{fmt(e["wall_s"], 0)} s <span class="note">({runs})</span></td><td>{fmt(e["mb_s"])}</td>'
                    + (f'<td>{fmt(e["files_s"])}</td>' if files else "") + "</tr>")
    return f'<table class="downloads bench-table"><thead>{head}</thead><tbody>{"".join(body)}</tbody></table>'


def chart(rows, metric, unit, title):
    """Horizontal grouped bars: peer-to-peer and S3 per row, one scale."""
    vals = [e[metric] for _, p, q in rows for e in (p, q) if e and e.get(metric) is not None]
    top = max(vals) if vals else 1
    label_w, bar_w, bar_h, gap, row_gap = 170, 360, 14, 3, 14
    h = len(rows) * (2 * bar_h + gap + row_gap) + 8
    out = [f'<svg class="bench-chart" viewBox="0 0 {label_w + bar_w + 90} {h}" role="img" aria-label="{html.escape(title)}">']
    y = 4
    for label, p, q in rows:
        out.append(f'<text class="bench-label" x="{label_w - 8}" y="{y + bar_h + 2}" text-anchor="end">{html.escape(label)}</text>')
        for e, cls, name in ((p, "bench-p2p", "peer to peer"), (q, "bench-s3", "S3 bucket")):
            v = e.get(metric) if e else None
            w = max(2, round(bar_w * (v or 0) / top))
            out.append(f'<rect class="{cls}" x="{label_w}" y="{y}" width="{w}" height="{bar_h}" rx="3"><title>{html.escape(label)}, {name}: {fmt(v)} {unit}</title></rect>')
            out.append(f'<text class="bench-value" x="{label_w + w + 6}" y="{y + bar_h - 3}">{fmt(v) if v is not None else "not run"}</text>')
            y += bar_h + gap
        y += row_gap
    out.append(f'<line class="bench-axis" x1="{label_w}" y1="0" x2="{label_w}" y2="{h}"/>')
    out.append("</svg>")
    return "\n".join(out)


def legend(unit):
    return (f'<p class="bench-legend"><span class="bench-key bench-p2p-key"></span>Peer to peer (from the writer in Paris)'
            f' <span class="bench-key bench-s3-key"></span>S3 bucket in Paris <span class="note">({unit}, more is better)</span></p>')


def table(rows, files):
    head = ("<tr><th>Reader</th><th>Peer to peer: time</th><th>MB/s</th>" + ("<th>files/s</th>" if files else "")
            + "<th>S3: time</th><th>MB/s</th>" + ("<th>files/s</th>" if files else "") + "<th>P2P vs S3</th></tr>")
    body = []
    for label, p, q in rows:
        def cells(e):
            if not e:
                return "<td>not run</td><td>–</td>" + ("<td>–</td>" if files else "")
            runs = " / ".join(fmt(x, 0) + " s" for x in e["wall_all_s"])
            c = f'<td>{fmt(e["wall_s"], 0)} s <span class="note">({runs})</span></td><td>{fmt(e["mb_s"])}</td>'
            return c + (f'<td>{fmt(e["files_s"])}</td>' if files else "")
        ratio = f'{q["wall_s"] / p["wall_s"]:.1f}× faster' if p and q and p["wall_s"] else "–"
        if p and q and q["wall_s"] < p["wall_s"]:
            ratio = f'{p["wall_s"] / q["wall_s"]:.1f}× slower'
        body.append(f"<tr><td>{html.escape(label)}</td>{cells(p)}{cells(q)}<td>{ratio}</td></tr>")
    return f'<table class="downloads bench-table"><thead>{head}</thead><tbody>{"".join(body)}</tbody></table>'


def fragments(d):
    out = {}
    for s, metric, unit, files in (("large", "mb_s", "MB/s", False), ("files", "files_s", "files/s", True), ("text", "mb_s", "MB/s", False)):
        rows = rows_for(d, s)
        parts = [table(rows, files), earlier_table(d, s, files)]
        if any(p for _, p, _ in rows):
            parts = [legend(unit), chart(rows, metric, unit, f"{s}: {unit} per reader, peer to peer and S3")] + parts
        out[s] = "\n".join(parts)
    vr = ["<tr><th>Run</th><th>Chunks downloaded</th><th>From peers</th><th>From S3</th><th>Path</th></tr>"]
    for e in d["pull"]:
        if e["mode"] != "p2p" or e["variant"]:
            continue
        n = e["chunks"] * e["runs"]
        peers = sum(x or 0 for x in e["chunks_from_peers"])
        sp = lambda x: f"{x:,}".replace(",", " ")
        vr.append(f'<tr><td>{e["set"]}, {READER[e["reader"]]}, {GROUP[e["group"]]} (×{e["runs"]})</td><td>{sp(n)}</td>'
                  f'<td>{sp(peers)}</td><td>{sp(n - peers)}</td><td>{html.escape(", ".join(e.get("paths") or []))}</td></tr>')
    names = {"tmpfs": "RAM disk (tmpfs)", "local-disk": "Local disk (network block volume)", "s3-fr-par": "S3 bucket, same region"}
    pr = ["<tr><th>Data set</th><th>Destination</th><th>Build</th><th>Time</th><th>MB/s</th><th>CPU (user + system)</th><th>Peak memory</th></tr>"]
    for e in sorted(d["push"], key=lambda e: (["files", "small", "large", "big", "text"].index(e["set"]) if e["set"] in ["files", "small", "large", "big", "text"] else 9,
                                               list(names).index(e["target"]), e["variant"])):
        ds = d["datasets"].get(e["set"], {})
        what = f'{e["set"]}: {ds.get("files", 0):,} files'.replace(",", " ") + f', {ds.get("bytes", 0) / 2**30:.2f} GiB'
        build = "alpha.8 (before the zstd fix)" if e["variant"] == "alpha8-zstd" else "measured build"
        runs = f' <span class="note">(median of {e["runs"]})</span>' if e["runs"] > 1 else ""
        pr.append(f'<tr><td>{what}</td><td>{names[e["target"]]}</td><td>{build}</td><td>{fmt(e["wall_s"], 0)} s{runs}</td>'
                  f'<td>{fmt(e["mb_s"])}</td><td>{fmt(e["cpu_s"], 0)} s ({fmt(e["user_s"], 0)} + {fmt(e["sys_s"], 0)})</td><td>{fmt(e["max_rss_mib"], 0)} MiB</td></tr>')
    out["writer"] = f'<table class="downloads bench-table"><tbody>{"".join(pr)}</tbody></table>'
    out["verify"] = f'<table class="downloads bench-table"><tbody>{"".join(vr)}</tbody></table>'
    return out


def main():
    d = json.load(open(sys.argv[1]))
    page = open(sys.argv[2]).read()
    for name, body in fragments(d).items():
        start = f"<!-- fragment: {name} -->"
        end = "<!-- /fragment -->"
        a = page.index(start) + len(start)
        b = page.index(end, a)
        page = page[:a] + "\n" + body + "\n" + page[b:]
    open(sys.argv[2], "w").write(page)


if __name__ == "__main__":
    main()
