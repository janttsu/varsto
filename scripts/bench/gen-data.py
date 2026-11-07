#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Generate the benchmark data sets (deterministic layout, random content).

    gen-data.py small <dir> [--files 50000]   many small files, nested directories
    gen-data.py files <dir> [--files 10000]   the same distribution, fewer files
    gen-data.py big <dir>                     4 x 2 GiB + 1 x 4 GiB incompressible files
    gen-data.py large <dir>                   2 x 2 GiB incompressible files
    gen-data.py text <dir> [--mib 512]        compressible log-like text files
    gen-data.py pair <dir>                    2 x 1 GiB incompressible files
    gen-data.py dup <dir> [--mib 768]         half the bytes are copies of other files
    gen-data.py mut <dir>                     dir/big.bin (1 GiB random) and dir/app.log
                                              (128 MiB text), for changes after a sync

The layout and sizes come from a fixed seed, so every run sees the same
shape; the bytes of the random files come from the operating system.
"""
import argparse
import math
import os
import pathlib
import random
import subprocess


def small(root: pathlib.Path, files: int):
    """Sizes follow a log-normal distribution (median 16 KiB) clipped to
    1 KiB..256 KiB, which is roughly what a documents / source / photo-thumbnail
    mix looks like. One file in twenty is a copy of an earlier one."""
    rng = random.Random(20261009)
    made = []
    total = 0
    for i in range(files):
        d = root / f"d{i % 20:02d}" / f"e{(i // 20) % 25:02d}"
        if i < 500:
            d.mkdir(parents=True, exist_ok=True)
        p = d / f"f{i:06d}.bin"
        if made and rng.random() < 0.05:
            src = made[rng.randrange(len(made))]
            data = src.read_bytes()
        else:
            size = int(min(256 * 1024, max(1024, math.exp(rng.gauss(math.log(16 * 1024), 1.1)))))
            data = os.urandom(size)
        p.write_bytes(data)
        made.append(p)
        total += len(data)
    print(f"small: {files} files, {total} bytes")


def big(root: pathlib.Path, sizes=(("big-1.bin", 2), ("big-2.bin", 2), ("big-3.bin", 2), ("big-4.bin", 2), ("huge.bin", 4))):
    root.mkdir(parents=True, exist_ok=True)
    for name, gib in sizes:
        # openssl's generator is several times faster than /dev/urandom; it
        # takes at most 2^31 - 1 bytes per call, so the file grows by 1 GiB steps.
        subprocess.run(f"for i in $(seq {gib}); do openssl rand 1073741824; done > {root / name}", shell=True, check=True)
    print(f"big: {len(sizes)} files, {sum(g for _, g in sizes)} GiB")


WORDS = ("GET POST PUT DELETE /api/v1/items /api/v1/users /static/app.js /login /logout "
         "200 201 204 301 304 400 401 403 404 500 502 Mozilla/5.0 curl/8.5 okhttp/4.12 "
         "INFO WARN ERROR DEBUG request completed started failed retry cache miss hit "
         "user session token timeout upstream connection reset backend database query").split()


def log_lines(rng: random.Random, nbytes: int, day: int) -> str:
    """About `nbytes` of web-server-log-like lines (a little more: whole lines)."""
    lines = []
    size = 0
    t = 1_760_000_000 + day * 86400
    while size < nbytes:
        t += rng.randint(0, 3)
        line = (f"2026-10-{1 + day % 28:02d}T{(t // 3600) % 24:02d}:{(t // 60) % 60:02d}:{t % 60:02d}Z "
                f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)} "
                + " ".join(rng.choice(WORDS) for _ in range(rng.randint(4, 9)))
                + f" {rng.randint(1, 99999)}ms id={rng.getrandbits(32):08x}\n")
        lines.append(line)
        size += len(line)
    return "".join(lines)


def text(root: pathlib.Path, mib: int):
    """Web-server-log-like lines: zstd shrinks them several times, like real logs, CSV or source."""
    rng = random.Random(7)
    root.mkdir(parents=True, exist_ok=True)
    per_file = 4 * 1024 * 1024
    n = max(1, mib * 1024 * 1024 // per_file)
    total = 0
    for i in range(n):
        data = log_lines(rng, per_file, i)
        (root / f"log-{i:04d}.txt").write_text(data)
        total += len(data)
    print(f"text: {n} files, {total} bytes")


def dup(root: pathlib.Path, mib: int):
    """Half of the bytes are copies: unique random files of 1..16 MiB in
    `orig/`, and in `copies/` the same files again under other names (a
    photo library imported twice, a project copied to a backup directory)."""
    rng = random.Random(4)
    (root / "orig").mkdir(parents=True, exist_ok=True)
    (root / "copies").mkdir(parents=True, exist_ok=True)
    half = mib * 1024 * 1024 // 2
    total = n = 0
    while total < half:
        size = rng.randint(1, 16) * 1024 * 1024
        data = os.urandom(size)
        (root / "orig" / f"o{n:03d}.bin").write_bytes(data)
        (root / "copies" / f"copy-of-{n:03d}.dat").write_bytes(data)
        total += size
        n += 1
    print(f"dup: {2 * n} files, {2 * total} bytes, half of them copies")


def mut(root: pathlib.Path):
    """The base of the change scenarios: a 1 GiB random file and a 128 MiB
    log in one directory (changed in place, appended to, then the directory renamed)."""
    d = root / "dir"
    d.mkdir(parents=True, exist_ok=True)
    subprocess.run(f"openssl rand 1073741824 > {d / 'big.bin'}", shell=True, check=True)
    (d / "app.log").write_text(log_lines(random.Random(11), 128 * 1024 * 1024, 0))
    print("mut: dir/big.bin 1 GiB, dir/app.log 128 MiB")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("set", choices=["small", "files", "big", "large", "text", "pair", "dup", "mut"])
    ap.add_argument("dir")
    ap.add_argument("--files", type=int)
    ap.add_argument("--mib", type=int, help="text: MiB (default 512); dup: MiB in all (default 768)")
    a = ap.parse_args()
    root = pathlib.Path(a.dir)
    {"small": lambda: small(root, a.files or 50000), "files": lambda: small(root, a.files or 10000), "big": lambda: big(root), "large": lambda: big(root, (("big-1.bin", 2), ("big-2.bin", 2))), "text": lambda: text(root, a.mib or 512),
     "pair": lambda: big(root, (("one.bin", 1), ("two.bin", 1))), "dup": lambda: dup(root, a.mib or 768), "mut": lambda: mut(root)}[a.set]()


if __name__ == "__main__":
    main()
