#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Runs on a Linux jump machine: opens an RDP session to a fresh Windows Server
# (whose cloud-init did not run), types a PowerShell command into the Run
# dialog that enables OpenSSH with our public key, and captures the desktop.
# Env: WIN_IP, WIN_PASS, PUBKEY (one OpenSSH public key line).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive DISPLAY=:98
apt-get update -qq && apt-get install -y -qq xvfb freerdp2-x11 xdotool imagemagick >/dev/null
Xvfb :98 -screen 0 1280x800x24 >/dev/null 2>&1 &
sleep 2
mkdir -p /it/shots
RDPBIN="$(command -v xfreerdp3 || command -v xfreerdp)"
echo "using $RDPBIN"
"$RDPBIN" /v:"$WIN_IP" /u:Administrator /p:"$WIN_PASS" /cert:ignore /size:1280x800 /bpp:16 -decorations /log-level:WARN >/it/rdp.log 2>&1 &
RDP=$!
set +e
for i in $(seq 1 40); do sleep 2; xdotool search --class xfreerdp >/dev/null 2>&1 && break; done
if ! xdotool search --class xfreerdp >/dev/null 2>&1; then
  echo "RDP window did not appear; xfreerdp log:"; tail -20 /it/rdp.log; exit 1
fi
sleep 25   # first login: desktop and Server Manager take a while
import -window root /it/shots/windows-desktop-first.png
win="$(xdotool search --class xfreerdp | head -1)"
xdotool windowactivate --sync "$win" 2>/dev/null || true
xdotool key --clearmodifiers super+r
sleep 3
cmd="powershell -ep bypass -c \"iwr -useb https://varsto.net/tools/${WIN_TOOL:-winssh}.ps1 | iex\""
xdotool type --delay 20 --clearmodifiers "$cmd"
sleep 1
xdotool key Return
sleep 5
import -window root /it/shots/windows-desktop-after-command.png
# Wait for OpenSSH from here (same network as the Windows machine), or for the screenshot run.
if [ "${WIN_TOOL:-winssh}" = winssh ]; then
  for i in $(seq 1 60); do nc -z -w2 "$WIN_IP" 22 && { echo "SSH_UP"; break; }; sleep 10; done
else
  sleep 90
fi
tail -5 /it/rdp.log
import -window root /it/shots/windows-desktop.png
kill $RDP 2>/dev/null || true
ls -la /it/shots
