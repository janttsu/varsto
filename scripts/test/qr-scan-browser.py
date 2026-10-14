#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Browser test of the QR scanner (docs/spec/alpha-0-format.md section 51):
Chromium with a fake camera that films QR codes, driving the setup page.

    python3 scripts/test/qr-scan-browser.py [path/to/varsto]

1. An owner vault in a temporary directory seals a token to the request
   code of a fresh device; the token is shown as an animated sequence of
   parts (`varsto share qr --parts`).
2. The fresh device runs the service (no vault yet). Chromium opens its
   page with a fake camera playing the sequence; "Scan QR code" under
   Accept a shared folder must fill in the sealed token.
   The same token as one dense code (version 29, 133 modules, filmed at
   640x480) must be read too.
3. A pairing link (one code): Pair with your other device,
   Scan QR code fills in the code and the address.

Needs Python Playwright and a Chromium (CHROMIUM=/path, default
/usr/bin/chromium) and Pillow. Everything lives in a temporary directory with
its own HOME; nothing of the user's is touched.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

from PIL import Image
from playwright.sync_api import sync_playwright


def boot_url(port, token):
    """The address that opens the interface: a one-time code, not the token."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/session/boot", data=b"{}", method="POST",
        headers={"X-Varsto-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return f"http://127.0.0.1:{port}/?boot={json.load(r)['boot']}"


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VARSTO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "target", "debug", "varsto")
CHROMIUM = os.environ.get("CHROMIUM", "/usr/bin/chromium")
tmp = tempfile.mkdtemp(prefix="varsto-qr-")
ENV = dict(os.environ, HOME=tmp, VARSTO_PASSPHRASE="test passphrase", VARSTO_NO_INSTALL="1",
           XDG_DATA_HOME=os.path.join(tmp, "xdg-data"), XDG_CONFIG_HOME=os.path.join(tmp, "xdg-config"),
           DBUS_SESSION_BUS_ADDRESS="disabled:")


def varsto(home, *args, json_out=True):
    cmd = [VARSTO, "--home", home] + (["--json"] if json_out else []) + list(args)
    out = subprocess.run(cmd, env=ENV, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"varsto {' '.join(args)} failed: {out.stderr}")
    if not json_out:
        return out.stdout
    try:
        return json.loads(out.stdout)
    except ValueError:
        return out.stdout


def y4m(frames, path, w=640, h=480, repeat=6):
    """Grey frames (PIL images) as a 4:2:0 Y4M file, each shown `repeat` times."""
    with open(path, "wb") as f:
        f.write(f"YUV4MPEG2 W{w} H{h} F10:1 Ip A1:1 C420jpeg\n".encode())
        chroma = bytes([128]) * ((w // 2) * (h // 2) * 2)
        for img in frames:
            canvas = Image.new("L", (w, h), 255)
            side = min(w, h) - 20
            canvas.paste(img.convert("L").resize((side, side), Image.NEAREST), ((w - side) // 2, (h - side) // 2))
            data = canvas.tobytes()
            for _ in range(repeat):
                f.write(b"FRAME\n" + data + chroma)


def qr_images(page, port, token, text, parts):
    """The service's SVGs for `text`, rasterised by the browser."""
    r = page.request.post(f"http://127.0.0.1:{port}/api/qr", headers={"X-Varsto-Token": token},
                          data=json.dumps({"text": text, "parts": parts}))
    assert r.ok, r.text()
    out = []
    for c in r.json()["codes"]:
        src = "data:image/svg+xml;base64," + base64.b64encode(c["svg"].encode()).decode()
        page.set_content(f'<body style="margin:0;background:#fff"><img id=q src="{src}" style="width:460px;height:460px;image-rendering:pixelated"></body>')
        png = os.path.join(tmp, f"q{len(out)}.png")
        page.locator("#q").screenshot(path=png)
        out.append(Image.open(png))
    return out


def main():
    owner, fresh = os.path.join(tmp, "owner"), os.path.join(tmp, "fresh")
    storage, docs = os.path.join(tmp, "storage"), os.path.join(tmp, "docs")
    varsto(owner, "init", "--name", "laptop")
    varsto(owner, "storage", "add-local", "box", storage)
    varsto(owner, "folder", "add", "docs", docs)
    req = varsto(fresh, "share", "request", "--name", "Robin")
    made = varsto(owner, "share", "create", "docs", "--to", req["request_code"], "--fingerprint", req["fingerprint"])

    svc = subprocess.Popen([VARSTO, "--home", fresh, "service", "run", "--port", "0", "--interval", "3600"],
                           env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(150):
            try:
                st = json.load(open(os.path.join(fresh, "service.json")))
                break
            except (OSError, ValueError):
                time.sleep(0.2)
        else:
            sys.exit("the service did not start")
        port, token = st["port"], st["token"]
        time.sleep(1)
        page_url = boot_url(port, token)
        with sync_playwright() as p:
            # Render the codes first (a browser without a fake camera).
            b = p.chromium.launch(executable_path=CHROMIUM)
            pg = b.new_page()
            token_frames = qr_images(pg, port, token, made["token"], True)
            single_frames = qr_images(pg, port, token, made["token"], False)
            pair_frames = qr_images(pg, port, token, "varsto://pair?c=123456789&a=192.168.1.20:41234", False)
            b.close()
            assert len(token_frames) > 1, "the token should be shown in parts"
            cases = (("token in parts", token_frames, scan_token),
                     ("token as one dense code", single_frames, scan_token),
                     ("pairing link", pair_frames, scan_pair))
            for name, frames, run in cases:
                cam = os.path.join(tmp, name.replace(" ", "-") + ".y4m")
                y4m(frames, cam)
                b = p.chromium.launch(executable_path=CHROMIUM, args=[
                    "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream",
                    f"--use-file-for-fake-video-capture={cam}"])
                pg = b.new_page()
                pg.goto(page_url)
                pg.wait_for_selector("#setup:not(.hidden)", timeout=30000)
                run(pg, made["token"])
                b.close()
                print(f"ok: {name} scanned through the fake camera ({len(frames)} code(s))")
    finally:
        svc.terminate()
        svc.wait()


def wait_closed(pg):
    """The scanner closes once it has read a whole link (the page's CSP allows no eval)."""
    try:
        pg.wait_for_selector("#scanner.hidden", state="attached", timeout=60000)
    except Exception:
        sys.exit("the scanner did not finish: " + pg.inner_text("#scanner-status"))


def scan_token(pg, expected):
    pg.click("#sharetokenscan")
    pg.wait_for_selector("#scanner:not(.hidden)")
    wait_closed(pg)
    got = pg.input_value("#acceptshare input[name=token]")
    assert got == expected, f"token field: {got[:40]}…"


def scan_pair(pg, _):
    pg.click("#pairscan")
    pg.wait_for_selector("#scanner:not(.hidden)")
    wait_closed(pg)
    assert pg.input_value("#pair input[name=code]") == "123-456-789"
    assert pg.input_value("#pair input[name=address]") == "192.168.1.20:41234"


if __name__ == "__main__":
    main()
