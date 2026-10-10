#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Peer to peer against an S3 bucket on one machine, over an emulated long
# link: a network namespace of its own (no root needed: `unshare -Urn`)
# whose loopback gets `tc netem` delay and rate, an S3 bucket served by
# `rclone serve s3` inside it, a writer device and a reader device. The
# writer pushes before the delay is switched on; then the reader downloads
# the folder through its background service, timed, in three modes:
#   s3    peer-to-peer off: every block from the bucket
#   p2p   the bucket's blocks moved away: every block from the writer
#   both  peer-to-peer on and the bucket complete: the reader picks
#
#   scripts/bench/netem-local.sh <varsto binary> <data dir> <work dir> [modes] [delay ms each way] [rate]
# defaults: modes "s3 p2p both", 16 ms each way (32 ms round trip, like Paris
# to Warsaw), 800mbit. Prints one JSON line per run. Needs rclone, tc, python3.
set -euo pipefail
if [ -z "${VARSTO_NETEM_INSIDE:-}" ]; then
  export VARSTO_NETEM_INSIDE=1
  exec unshare -Urn "$0" "$@"
fi
bin="$(realpath "$1")"; data="$(realpath "$2")"; work="$(mkdir -p "$3" && realpath "$3")"
modes="${4:-s3 p2p both}"; delay="${5:-16}"; rate="${6:-800mbit}"
export VARSTO_PASSPHRASE=bench-passphrase VARSTO_S3_SECRET=bench-secret-key
ip link set lo up
ip link set lo mtu 1500
netem_on() { tc qdisc replace dev lo root netem delay "${delay}ms" rate "$rate" limit 100000; }
netem_off() { tc qdisc del dev lo root 2>/dev/null || true; }
netem_off
rm -rf "$work/s3" "$work/w" "$work"/r-* "$work"/d-*
mkdir -p "$work/s3/bench"
rclone serve s3 --auth-key bench-access,bench-secret-key --addr 127.0.0.1:9000 "$work/s3" > "$work/rclone.log" 2>&1 &
rclone_pid=$!
pids=("$rclone_pid")
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
for i in $(seq 1 50); do curl -s -o /dev/null http://127.0.0.1:9000/ && break; sleep 0.2; done
s3flags=(--storage-name cloud --s3-endpoint http://127.0.0.1:9000 --s3-region us-east-1 --s3-bucket bench --s3-access-key-id bench-access)
api() { # home method path [json]
  local port tok
  port=$(python3 -c "import json;print(json.load(open('$1/service.json'))['port'])")
  tok=$(python3 -c "import json;print(json.load(open('$1/service.json'))['token'])")
  curl -sS --max-time 3600 -X "$2" "http://127.0.0.1:$port$3" -H "X-Varsto-Token: $tok" -H 'Content-Type: application/json' ${4:+-d "$4"}
}
start_service() { # home
  rm -f "$1/service.json"
  "$bin" --home "$1" service run --port 0 --interval 3600 > "$1.service.log" 2>&1 &
  pids+=("$!")
  for i in $(seq 1 100); do [ -f "$1/service.json" ] && api "$1" GET /api/state >/dev/null 2>&1 && break; sleep 0.2; done
}
# ---- writer, without the delay
W="$work/w"
key=$("$bin" --home "$W" init --name writer --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["vault_key"])')
"$bin" --home "$W" storage add-s3 cloud --endpoint http://127.0.0.1:9000 --bucket bench --access-key-id bench-access >/dev/null
"$bin" --home "$W" verify set --off >/dev/null
"$bin" --home "$W" folder add data "$data" >/dev/null
t0=$(date +%s.%N)
"$bin" --home "$W" sync >/dev/null
echo "{\"kind\":\"push\",\"seconds\":$(echo "$(date +%s.%N) - $t0" | bc)}"
"$bin" --home "$W" p2p enable --port 17893 --public 127.0.0.1:17893 >/dev/null
start_service "$W"
api "$W" POST /api/sync '{}' >/dev/null
(cd "$data" && find . -type f ! -name '.varsto*' -print0 | sort -z | xargs -0 sha256sum) > "$work/want.sha"
bytes=$(du -sb --exclude='.varsto*' "$data" | cut -f1)
netem_on
n=0
for mode in $modes; do
  n=$((n + 1))
  R="$work/r-$mode-$n"; D="$work/d-$mode-$n"
  mkdir -p "$D"
  if [ "$mode" = p2p ]; then mv "$work/s3/bench/chunks" "$work/s3/bench/chunks.away"; fi
  "$bin" --home "$R" join --name "reader-$mode" --vault-key "$key" "${s3flags[@]}" >/dev/null
  "$bin" --home "$R" verify set --off >/dev/null
  if [ "$mode" != s3 ]; then "$bin" --home "$R" p2p enable --port $((17900 + n)) >/dev/null; fi
  start_service "$R"
  api "$R" POST /api/sync '{}' >/dev/null   # registry, peer records
  api "$R" POST /api/service/pause '{"paused":true}' >/dev/null
  api "$R" POST /api/folder/attach "{\"name_or_id\":\"data\",\"path\":\"$D\",\"plain\":true}" >/dev/null
  t0=$(date +%s.%N)
  out=$(api "$R" POST /api/sync '{"folder":"data"}')
  secs=$(echo "$(date +%s.%N) - $t0" | bc)
  got=$( (cd "$D" && find . -type f ! -name '.varsto*' -print0 | sort -z | xargs -0 sha256sum) | cmp -s - "$work/want.sha" && echo identical || echo DIFFERENT)
  python3 - "$mode" "$secs" "$bytes" "$got" "$out" <<'PY'
import json, sys
mode, secs, nbytes, got, out = sys.argv[1], float(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
r = json.loads(out)
pulls = [x.get("pull", {}) for x in (r if isinstance(r, list) else [r]) if isinstance(x, dict)]
down = sum(p.get("chunks_downloaded", 0) for p in pulls)
peers = sum(p.get("chunks_from_peers", 0) for p in pulls)
print(json.dumps({"kind": "pull", "mode": mode, "seconds": round(secs, 1), "mb_s": round(nbytes / secs / 1e6, 1),
                  "chunks": down, "from_peers": peers, "files": got}))
PY
  api "$R" POST /api/quit '{}' >/dev/null 2>&1 || true
  if [ "$mode" = p2p ]; then mv "$work/s3/bench/chunks.away" "$work/s3/bench/chunks"; fi
  rm -rf "$D"
done
netem_off
api "$W" POST /api/quit '{}' >/dev/null 2>&1 || true
sleep 1
