#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Build a multi-size Windows icon (varsto.ico) from the brand PNG files.

    python3 installer/windows/make-ico.py [output.ico]

Default output: installer/windows/build/varsto.ico. Every size is a PNG
payload (Windows Vista and later read them), so no image library is needed:
the PNG files are copied into the icon container as they are. The sizes are
the ones Explorer, the taskbar, the Start menu and the title bar ask for.
"""
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SIZES = (16, 32, 48, 64, 128, 256)


def png_size(data: bytes) -> tuple[int, int]:
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise SystemExit("not a PNG file")
    return struct.unpack(">II", data[16:24])


def build(png_dir: pathlib.Path) -> bytes:
    images = []
    for size in SIZES:
        path = png_dir / f"logo-{size}.png"
        data = path.read_bytes()
        if png_size(data) != (size, size):
            raise SystemExit(f"{path} is not {size} x {size} pixels")
        images.append((size, data))
    out = bytearray(struct.pack("<HHH", 0, 1, len(images)))
    offset = 6 + 16 * len(images)
    for size, data in images:
        # Width and height 0 mean 256; 32 bits per pixel, one colour plane.
        out += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for _, data in images:
        out += data
    return bytes(out)


def main() -> None:
    target = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "installer/windows/build/varsto.ico"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(build(ROOT / "brand/png"))
    print(f"wrote {target} ({', '.join(str(s) for s in SIZES)} px)")


if __name__ == "__main__":
    main()
