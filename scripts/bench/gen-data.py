#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Generate the benchmark data sets (deterministic layout, random content).

    gen-data.py small <dir> [--files 50000]   many small files, nested directories
    gen-data.py files <dir> [--files 10000]   the same distribution, fewer files
    gen-data.py big <dir>                     4 x 2 GiB + 1 x 4 GiB incompressible files
    gen-data.py large <dir>                   2 x 2 GiB incompressible files
    gen-data.py text <dir> [--mib 512]        compressible log-like text files

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


def text(root: pathlib.Path, mib: int):
    """Web-server-log-like lines: zstd shrinks them several times, like real logs, CSV or source."""
    rng = random.Random(7)
    root.mkdir(parents=True, exist_ok=True)
    per_file = 4 * 1024 * 1024
    n = max(1, mib * 1024 * 1024 // per_file)
    for i in range(n):
        lines = []
        size = 0
        t = 1_760_000_000 + i * 86400
        while size < per_file:
            t += rng.randint(0, 3)
            line = (f"2026-10-{1 + i % 28:02d}T{(t // 3600) % 24:02d}:{(t // 60) % 60:02d}:{t % 60:02d}Z "
                    f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)} "
                    + " ".join(rng.choice(WORDS) for _ in range(rng.randint(4, 9)))
                    + f" {rng.randint(1, 99999)}ms id={rng.getrandbits(32):08x}\n")
            lines.append(line)
            size += len(line)
        (root / f"log-{i:04d}.txt").write_text("".join(lines))
    print(f"text: {n} files, {n * per_file} bytes")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("set", choices=["small", "files", "big", "large", "text"])
    ap.add_argument("dir")
    ap.add_argument("--files", type=int)
    ap.add_argument("--mib", type=int, default=512)
    a = ap.parse_args()
    root = pathlib.Path(a.dir)
    {"small": lambda: small(root, a.files or 50000), "files": lambda: small(root, a.files or 10000), "big": lambda: big(root), "large": lambda: big(root, (("big-1.bin", 2), ("big-2.bin", 2))), "text": lambda: text(root, a.mib)}[a.set]()


if __name__ == "__main__":
    main()
