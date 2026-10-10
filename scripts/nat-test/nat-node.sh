#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Runs as root on a test machine of home-nat.py.
#   nat-node.sh setup                 binary in place, two NAT namespaces:
#                                     natc (cone: MASQUERADE keeps the port per source)
#                                     nats (symmetric: MASQUERADE --random-fully)
#   nat-node.sh run <ns|-> <home> <varsto args...>   the command line, inside a namespace
#   nat-node.sh service <ns|-> <home>                start the background service (every 15 s)
#   nat-node.sh api <ns|-> <home> <GET|POST> <path> [json]
#   nat-node.sh log <home>                           the service's p2p lines
set -euo pipefail
B=/nat/varsto
in_ns() { local ns="$1"; shift; if [ "$ns" = "-" ]; then "$@"; else ip netns exec "$ns" "$@"; fi; }
case "${1:-}" in
  setup)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null && apt-get install -y -qq curl python3 iptables >/dev/null
    mkdir -p /nat && rm -rf /nat/varsto-*/ && tar -C /nat -xzf /nat/pkg.tar.gz && cp /nat/varsto-*/varsto $B && chmod 755 $B
    $B --version
    ext=$(ip route show default | awk '{print $5}' | head -1)
    sysctl -q -w net.ipv4.ip_forward=1
    n=77
    for ns in natc nats; do
      if ! ip netns list | grep -qw $ns; then
        ip netns add $ns
        ip link add veth-$ns type veth peer name in-$ns
        ip link set in-$ns netns $ns
        ip addr add 10.$n.0.1/24 dev veth-$ns && ip link set veth-$ns up
        ip netns exec $ns ip addr add 10.$n.0.2/24 dev in-$ns
        ip netns exec $ns ip link set in-$ns up && ip netns exec $ns ip link set lo up
        ip netns exec $ns ip route add default via 10.$n.0.1
        if [ $ns = nats ]; then extra="--random-fully"; else extra=""; fi
        iptables -t nat -A POSTROUTING -s 10.$n.0.0/24 -o "$ext" -j MASQUERADE $extra
        iptables -A FORWARD -i veth-$ns -o "$ext" -j ACCEPT
        iptables -A FORWARD -i "$ext" -o veth-$ns -m state --state RELATED,ESTABLISHED -j ACCEPT
        mkdir -p /etc/netns/$ns && echo "nameserver 1.1.1.1" > /etc/netns/$ns/resolv.conf
      fi
      n=$((n + 1))
    done
    echo "namespaces: $(ip netns list | tr '\n' ' ')"
    ;;
  run) ns="$2"; home="$3"; shift 3; in_ns "$ns" $B --home "$home" "$@" ;;
  service)
    ns="$2"; home="$3"
    in_ns "$ns" nohup $B --home "$home" service run --port 0 --interval 15 > "$home.service.log" 2>&1 &
    for i in $(seq 1 30); do [ -f "$home/service.json" ] && break; sleep 1; done
    echo "service for $home started"
    ;;
  api)
    ns="$2"; home="$3"; method="$4"; path="$5"; body="${6:-}"
    port=$(python3 -c "import json;print(json.load(open('$home/service.json'))['port'])")
    tok=$(python3 -c "import json;print(json.load(open('$home/service.json'))['token'])")
    if [ -n "$body" ]; then
      in_ns "$ns" curl -sS --max-time 1800 -X "$method" "http://127.0.0.1:$port$path" -H "X-Varsto-Token: $tok" -H 'Content-Type: application/json' -d "$body"
    else
      in_ns "$ns" curl -sS --max-time 60 -X "$method" "http://127.0.0.1:$port$path" -H "X-Varsto-Token: $tok"
    fi
    ;;
  log) grep -a "p2p:" "$2.service.log" | tail -n "${3:-40}" ;;
  *) sed -n '3,12p' "$0"; exit 2 ;;
esac
