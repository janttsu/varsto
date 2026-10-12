#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Seed the screenshot demo: an invented user "aino" with a laptop and a phone
# in one vault (a local storage, Documents and Photos, the phone selective),
# and start both background services. Everything is made up; nothing comes
# from a real machine.
#   scripts/screenshots/demo-vault.sh <varsto binary> <work dir>
# DEMO_HOME (default <work dir>/aino) is where the demo user's files live; the
# paths show in the interface, so CI points it at /home/aino. Writes
# <work dir>/laptop.json and <work dir>/phone.json (service port and token)
# and <work dir>/pids. Stop with: kill $(cat <work dir>/pids)
set -euo pipefail
bin="$(realpath "$1")"; work="$(mkdir -p "$2" && realpath "$2")"
here="$(cd "$(dirname "$0")" && pwd)"
H="${DEMO_HOME:-$work/aino}"
laptop="$H/.varsto"; phone="$H/.varsto-phone"
mkdir -p "$H/Documents/Invoices" "$H/Photos" "$laptop" "$phone" "$H/phone" "$H/phone-plain" "$H/Varsto-box"
python3 "$here/mkimg.py" "$H/Photos"
printf '# Quarterly report\nSummary of the quarter: revenue grew, costs steady, three new hires.\n' > "$H/Documents/Quarterly-report.md"
head -c 180000 /dev/urandom | base64 > "$H/Documents/Contract-draft.txt"
printf -- '- The Design of Everyday Things\n- Thinking in Systems\n- A Pattern Language\n' > "$H/Documents/Reading-list.txt"
printf 'Invoice 2026-041\nTotal 1 240,00 EUR\n' > "$H/Documents/Invoices/2026-041.txt"
head -c 4200000 /dev/urandom > "$H/Documents/Archive-2025.zip"
head -c 16000000 /dev/urandom > "$H/Documents/Backup-2025.tar"
truncate -s 1500M "$H/Documents/Backup-2024.tar"
truncate -s 900M "$H/Documents/Archive-2024.zip"
touch -d "150 days ago" "$H/Documents/Backup-2024.tar" "$H/Documents/Archive-2024.zip" "$H/Documents/Contract-draft.txt"
export VARSTO_PASSPHRASE=demo-passphrase-123
v() { "$bin" --home "$@"; }
key="$(v "$laptop" init --name laptop --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["vault_key"])')"
v "$laptop" storage add-local box "$H/Varsto-box" --place home
v "$laptop" folder add Documents "$H/Documents"
v "$laptop" folder add Photos "$H/Photos"
v "$laptop" sync
v "$laptop" policy set Photos --min-copies 1 --place home=1
v "$phone" join --name phone --vault-key "$key" --storage-path "$H/Varsto-box"
v "$phone" folder attach Photos "$H/phone/Photos" --selective
v "$phone" pull Photos
v "$phone" folder fetch Photos lake.jpg
v "$laptop" sync
# The organization page: aino's company, with the laptop as administrator.
v "$laptop" org create --name "Aino Design Oy" --user aino --json > /dev/null
v "$phone" pull Photos
: > "$work/pids"
"$bin" --home "$laptop" service run --port 0 --interval 300 > "$work/svc-laptop.log" 2>&1 &
echo $! >> "$work/pids"
VARSTO_MOBILE=1 VARSTO_FOLDER_ROOT="$H/phone" VARSTO_PLAIN_ROOT="$H/phone-plain" \
  "$bin" --home "$phone" service run --port 0 --interval 300 > "$work/svc-phone.log" 2>&1 &
echo $! >> "$work/pids"
for i in $(seq 1 60); do [ -f "$laptop/service.json" ] && [ -f "$phone/service.json" ] && break; sleep 1; done
cp "$laptop/service.json" "$work/laptop.json"
cp "$phone/service.json" "$work/phone.json"
echo "demo services: laptop $(python3 -c "import json;print(json.load(open('$work/laptop.json'))['port'])"), phone $(python3 -c "import json;print(json.load(open('$work/phone.json'))['port'])")"
