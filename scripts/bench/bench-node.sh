#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Helper that runs on every benchmark machine (see p2p-bench.py). The varsto
# binary is /bench/varsto; every device directory lives under /bench.
#
#   bench-node.sh setup                       packages, directories
#   bench-node.sh svc-start <home>            background service, under /usr/bin/time -v
#   bench-node.sh svc-stop <home>             quit it; prints the time -v summary
#   bench-node.sh wait-sync <home> <n>        until the service finished n syncs
#   bench-node.sh api <home> <METHOD> <path> [json]
#   bench-node.sh timed-sync <home> <folder>  POST /api/sync for one folder, timed
#   bench-node.sh proc <home>                 CPU ticks and peak memory of the service
#   bench-node.sh hashes <dir> <out>          sorted sha256 list of every file
set -euo pipefail
B=/bench/varsto
export VARSTO_PASSPHRASE=${VARSTO_PASSPHRASE:-bench-passphrase}

svc_field() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]+'/service.json'))[sys.argv[2]])" "$1" "$2"; }

api() {
  local home=$1 method=$2 path=$3 body=${4:-}
  local port token
  port=$(svc_field "$home" port); token=$(svc_field "$home" token)
  if [ -n "$body" ]; then
    curl -sS --max-time 0 -X "$method" -H "X-Varsto-Token: $token" -H 'Content-Type: application/json' \
      --data "$body" "http://127.0.0.1:$port$path"
  else
    curl -sS --max-time 0 -X "$method" -H "X-Varsto-Token: $token" "http://127.0.0.1:$port$path"
  fi
}

case "$1" in
  setup)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq iperf3 rclone time python3 openssl >/dev/null
    mkdir -p /bench
    ;;
  svc-start)
    home=$2
    rm -f "$home/service.json"
    nohup /usr/bin/time -v -o "$home.time" "$B" --home "$home" service run --port 0 --interval 3600 \
      > "$home.log" 2>&1 < /dev/null &
    for _ in $(seq 1 120); do
      if [ -f "$home/service.json" ] && api "$home" GET /api/service >/dev/null 2>&1; then exit 0; fi
      sleep 0.5
    done
    echo "service did not start; log:" >&2; tail -20 "$home.log" >&2; exit 1
    ;;
  svc-stop)
    home=$2
    if [ -f "$home/service.json" ]; then
      pid=$(svc_field "$home" pid)
      curl -sS --max-time 5 -X POST -H "X-Varsto-Token: $(svc_field "$home" token)" "http://127.0.0.1:$(svc_field "$home" port)/api/quit" >/dev/null 2>&1 || true
      for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
      kill "$pid" 2>/dev/null || true
      sleep 1
    fi
    cat "$home.time" 2>/dev/null || true
    ;;
  wait-sync)
    home=$2 n=$3
    for _ in $(seq 1 1200); do
      s=$(api "$home" GET /api/service 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin).get('syncs',0))" 2>/dev/null || echo 0)
      if [ "${s:-0}" -ge "$n" ]; then exit 0; fi
      sleep 0.5
    done
    echo "no sync finished" >&2; tail -20 "$home.log" >&2; exit 1
    ;;
  api)
    api "$2" "$3" "$4" "${5:-}"
    ;;
  timed-sync)
    home=$2 folder=$3
    t0=$(date +%s.%N)
    api "$home" POST /api/sync "{\"folder\":\"$folder\"}" > "$home.sync.json"
    t1=$(date +%s.%N)
    python3 - "$home.sync.json" "$t0" "$t1" <<'EOF'
import json, sys
raw = open(sys.argv[1]).read()
try:
    rep = json.loads(raw)
except ValueError:
    rep = {"error": raw[-2000:]}
print(json.dumps({"t0": float(sys.argv[2]), "t1": float(sys.argv[3]), "wall": float(sys.argv[3]) - float(sys.argv[2]), "report": rep}))
EOF
    ;;
  proc)
    home=$2
    pid=$(svc_field "$home" pid)
    python3 - "$pid" <<'EOF'
import json, os, sys
pid = sys.argv[1]
st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
hz = os.sysconf("SC_CLK_TCK")
status = dict(l.split(":", 1) for l in open(f"/proc/{pid}/status") if ":" in l)
print(json.dumps({"user_s": int(st[11]) / hz, "sys_s": int(st[12]) / hz,
                  "hwm_kib": int(status["VmHWM"].split()[0]), "rss_kib": int(status["VmRSS"].split()[0])}))
EOF
    ;;
  hashes)
    (cd "$2" && find . -type f ! -name '.varsto*' -print0 | sort -z | xargs -0 -n 2000 -P 4 sha256sum | sort -k2) > "$3"
    wc -l < "$3"
    ;;
  *)
    echo "unknown command $1" >&2; exit 2
    ;;
esac
