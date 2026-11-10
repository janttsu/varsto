#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Helper that runs on every benchmark machine (see p2p-bench.py). The varsto
# binary is $BENCH_ROOT/varsto; every device directory lives under that root.
# BENCH_ROOT defaults to /bench. A home server without root sets another directory.
#
#   bench-node.sh setup                       packages, directories
#   bench-node.sh svc-start <home>            background service, under /usr/bin/time -v
#   bench-node.sh svc-stop <home>             quit it; prints the time -v summary
#   bench-node.sh wait-sync <home> <n>        until the service finished n syncs
#   bench-node.sh api <home> <METHOD> <path> [json]
#   bench-node.sh timed-sync <home> <folder>  POST /api/sync for one folder, timed
#   bench-node.sh proc <home>                 CPU ticks and peak memory of the service
#   bench-node.sh hashes <dir> <out>          sorted sha256 list of every file
# For resilio-vs-varsto.py:
#   bench-node.sh iface                       the interface of the default route
#   bench-node.sh dropcaches                  write back and drop the page cache
#   bench-node.sh acct <ip> ...               iptables chain BENCHACCT counting traffic with these addresses
#   bench-node.sh netem-on <qdisc args>       the same netem on the default interface's incoming
#                                             traffic (through ifb0), where a pull's data arrives
#   bench-node.sh netem-off
#   bench-node.sh rsl-install <url>           Resilio Sync into /bench/rslsync; prints its version
set -euo pipefail
ROOT=${BENCH_ROOT:-/bench}
B=$ROOT/varsto
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
    mkdir -p "$ROOT"
    if [ "$(id -u)" -eq 0 ]; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null
      apt-get install -y -qq iperf3 rclone time python3 openssl iptables >/dev/null
    fi
    ;;
  iface)
    ip route get 1.1.1.1 | grep -oP 'dev \K\S+'
    ;;
  dropcaches)
    sync; echo 3 > /proc/sys/vm/drop_caches
    ;;
  acct)
    shift
    iptables -N BENCHACCT 2>/dev/null || iptables -F BENCHACCT
    iptables -C INPUT -j BENCHACCT 2>/dev/null || iptables -I INPUT -j BENCHACCT
    iptables -C OUTPUT -j BENCHACCT 2>/dev/null || iptables -I OUTPUT -j BENCHACCT
    for ip in "$@"; do iptables -A BENCHACCT -s "$ip"; iptables -A BENCHACCT -d "$ip"; done
    iptables -L BENCHACCT -vnx | tail -n +3 | wc -l
    ;;
  netem-on)
    shift
    dev=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+')
    modprobe ifb numifbs=1 2>/dev/null || true
    ip link show ifb0 >/dev/null 2>&1 || ip link add ifb0 type ifb
    ip link set ifb0 up
    tc qdisc del dev "$dev" ingress 2>/dev/null || true
    tc qdisc del dev ifb0 root 2>/dev/null || true
    tc qdisc add dev "$dev" handle ffff: ingress
    tc filter add dev "$dev" parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ifb0
    tc qdisc add dev ifb0 root netem "$@"
    tc qdisc show dev ifb0
    ;;
  netem-off)
    dev=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+')
    tc qdisc del dev "$dev" ingress 2>/dev/null || true
    tc qdisc del dev ifb0 root 2>/dev/null || true
    tc qdisc show dev "$dev"
    ;;
  rsl-install)
    mkdir -p "$ROOT/rsl-dl" && cd "$ROOT/rsl-dl"
    curl -fsSL -o rsl.tgz "$2" && tar xzf rsl.tgz && install -m 755 rslsync "$ROOT/rslsync"
    sha256sum rsl.tgz | cut -c1-64
    "$ROOT/rslsync" --help 2>&1 | grep -m1 'Resilio Sync' || true
    ;;
  svc-start)
    home=$2
    rm -f "$home/service.json"
    if [ -x /usr/bin/time ]; then
      nohup /usr/bin/time -v -o "$home.time" "$B" --home "$home" service run --port 0 --interval 3600 \
        > "$home.log" 2>&1 < /dev/null &
    else
      : > "$home.time"
      nohup "$B" --home "$home" service run --port 0 --interval 3600 \
        > "$home.log" 2>&1 < /dev/null &
    fi
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
    # service.json is removed on the way out. A start that failed after the
    # process was up used to leave it sleeping, and the next run then bound
    # a second listener. This home only.
    pkill -f -- "${B} --home ${home} " || true
    # A sync in progress ignores SIGTERM until it finishes, and the next
    # start then shares the vault with it. Kill it before that start.
    sleep 0.3
    pkill -9 -f -- "${B} --home ${home} " || true
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
