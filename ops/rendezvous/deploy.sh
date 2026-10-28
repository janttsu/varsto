#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Deploy the rendezvous server (docs/rendezvous.md) from the CI build of one
# commit to a server you reach over SSH, as an unprivileged systemd user
# service. Run it from a checkout, on a machine with `gh` logged in:
#
#   ops/rendezvous/deploy.sh <ssh host> [commit]     (default commit: origin/main)
#
# Environment (all optional):
#   RV_PUBLIC_URL   the URL clients use         (https://varsto.net/rv)
#   RV_PUBLIC_UDP   what /info advertises       (<host of RV_PUBLIC_URL>:3334)
#   RV_LISTEN       HTTP behind the proxy       (127.0.0.1:17892)
#   RV_UDP          the UDP socket              (0.0.0.0:3334)
#   RV_REPO         the GitHub repository       (janttsu/varsto)
#
# What it does: downloads the static binary (artifact `rendezvous-linux`) of
# the CI run of that commit on main, runs its --self-test here, copies it to
# ~/rendezvous/ on the server, runs the self-test there, installs the user
# unit and ~/.config/varsto-rendezvous.env (an existing env file is kept and
# the new one written beside it as .env.new), restarts the service and checks
# it on loopback. The Caddy lines and the firewall rule are printed, not
# applied: they need root on the server.
set -euo pipefail
host="${1:?usage: deploy.sh <ssh host> [commit]}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="${RV_REPO:-janttsu/varsto}"
url="${RV_PUBLIC_URL:-https://varsto.net/rv}"
url="${url%/}"
site="${url#https://}"; site="${site%%/*}"
path="${url#https://$site}"   # /rv, or empty for a host of its own
listen="${RV_LISTEN:-127.0.0.1:17892}"
udp="${RV_UDP:-0.0.0.0:3334}"
public_udp="${RV_PUBLIC_UDP:-$site:${udp##*:}}"

git -C "$here/../.." fetch -q origin main
commit="$(git -C "$here/../.." rev-parse "${2:-origin/main}")"
echo "== commit $commit"
run="$(gh run list -R "$repo" --workflow ci.yml --commit "$commit" --event push --status success \
  --json databaseId --jq '.[0].databaseId')"
if [ -z "$run" ] || [ "$run" = null ]; then
  echo "no successful CI run (push to main) for $commit yet: gh run list -R $repo --workflow ci.yml --commit $commit" >&2
  exit 1
fi
echo "== CI run $run"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
gh run download "$run" -R "$repo" -n rendezvous-linux -D "$tmp"
bin="$tmp/varsto-rendezvous-linux-x86_64"
chmod 755 "$bin"
file "$bin"
"$bin" --version
"$bin" --self-test

cat > "$tmp/varsto-rendezvous.env" <<EOF
# Written by ops/rendezvous/deploy.sh (see varsto-rendezvous --help).
VARSTO_RV_LISTEN=$listen
VARSTO_RV_UDP=$udp
VARSTO_RV_PUBLIC_UDP_ADDR=$public_udp
VARSTO_RV_LOG=info
EOF
# The unit of this directory, with the binary where this script puts it.
sed 's|^ExecStart=.*|ExecStart=%h/rendezvous/varsto-rendezvous|' "$here/varsto-rendezvous.service" > "$tmp/varsto-rendezvous.service"

echo "== copy to $host"
ssh "$host" 'mkdir -p ~/rendezvous ~/.config/systemd/user'
scp -q "$bin" "$host:rendezvous/varsto-rendezvous.new"
scp -q "$tmp/varsto-rendezvous.service" "$host:.config/systemd/user/varsto-rendezvous.service"
scp -q "$tmp/varsto-rendezvous.env" "$host:.config/varsto-rendezvous.env.new"
ssh "$host" bash -s <<'EOS'
set -euo pipefail
cd ~/rendezvous
chmod 755 varsto-rendezvous.new
./varsto-rendezvous.new --self-test
[ -f varsto-rendezvous ] && cp -p varsto-rendezvous "varsto-rendezvous.prev.$(date -u +%Y%m%dT%H%M%SZ)"
mv varsto-rendezvous.new varsto-rendezvous
if [ -f ~/.config/varsto-rendezvous.env ]; then
  if cmp -s ~/.config/varsto-rendezvous.env ~/.config/varsto-rendezvous.env.new; then
    rm ~/.config/varsto-rendezvous.env.new
  else
    echo "kept the existing ~/.config/varsto-rendezvous.env; the new one is .env.new:"
    diff ~/.config/varsto-rendezvous.env ~/.config/varsto-rendezvous.env.new || true
  fi
else
  mv ~/.config/varsto-rendezvous.env.new ~/.config/varsto-rendezvous.env
fi
loginctl show-user "$USER" -p Linger | grep -q yes || echo "note: run 'sudo loginctl enable-linger $USER' so the service runs without a login"
systemctl --user daemon-reload
systemctl --user enable varsto-rendezvous.service >/dev/null
systemctl --user restart varsto-rendezvous.service
sleep 2
systemctl --user --no-pager --lines=5 status varsto-rendezvous.service
EOS
ssh "$host" "curl -fsS http://$listen/health && echo && curl -fsS http://$listen/info && echo"

cat <<EOF

== Caddy (as root on $host, in the site block of $site; then: sudo systemctl reload caddy)
	handle_path ${path:-}/* {
		reverse_proxy $listen {
			stream_close_delay 10s
		}
	}

== Firewall (as root on $host): UDP ${udp##*:} must be open to the internet, e.g.
	sudo ufw allow ${udp##*:}/udp
	sudo firewall-cmd --permanent --add-port=${udp##*:}/udp && sudo firewall-cmd --reload
	sudo nft add rule inet filter input udp dport ${udp##*:} accept

== Check from outside, after Caddy and the firewall
	curl -fsS $url/health
	curl -fsS $url/info        # udp: ["$public_udp"]
	varsto p2p rendezvous status   # on any device: state on, observed address
EOF
