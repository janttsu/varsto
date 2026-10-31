# The rendezvous service

<!-- Skeleton by the design branch (rv-design). The UI/docs part (U) finishes
     the user-facing sections; the operator sections are complete enough to
     deploy from. Protocol details: docs/spec/alpha-0-format.md section 83. -->

## What it is

Varsto devices of one vault talk to each other directly: on the same network
they find each other at once, across the internet they need to learn each
other's addresses and get through home routers (NAT). The rendezvous service
is a small meeting point for that:

- devices leave their **sealed address records** there, so a device that
  moved to another network is found again even when no storage answers;
- it helps two devices behind routers **punch through at the same moment**;
- when nothing else works (two strict routers, a network that blocks UDP) it
  **relays** their connection, which stays end-to-end encrypted;
- **pairing** a new device works across networks: the code (or the scanned
  link) finds the offer there.

It is optional and additive. With it switched off or unreachable, Varsto
works exactly as without it: the local network, direct addresses, your own
devices as relays and the storages.

The default is `https://varsto.net/rv`. You can run your own.

## Settings

On the **Peers** page, the *Rendezvous service* card shows the address in
use, whether the device is connected, the address the internet sees this
device as, and how many connections it relays. Tick or untick *Use the
rendezvous service*, type another address, and choose *Save*; *Use the default*
goes back to `https://varsto.net/rv`. Peers reached through the service show the
path `relayed via rendezvous` in the Peers table and in the traffic view.

The same from the command line (a running background service applies it at once):

```
$ varsto p2p rendezvous status
rendezvous: https://varsto.net/rv, connected, seen from outside as 203.0.113.77:41233, relaying 1 peer(s)

$ varsto p2p rendezvous set https://rv.example.org/rv
rendezvous service: https://rv.example.org/rv

$ varsto p2p rendezvous --off          # same as: varsto p2p rendezvous off
rendezvous service is off; devices find each other without it

$ varsto p2p rendezvous on             # back to the default service
```

`set` checks the address and asks the service for its `/info` (up to five
seconds). If it does not answer, you get a warning and the setting is saved
anyway: the service is optional, and a server that is down now may be up
later. `varsto p2p status` shows the same line among the other peer-to-peer
facts, and `--json` prints the fields (`url`, `enabled`, `state`, `observed`,
`relayed_peers`, `last_error`, `clock_skew`).

The setting is per device (`p2p.rendezvous` in the device's `config.json`).
Devices of one vault should use the same service to find each other through
it.

## Privacy: what the server sees

The server learns:

- random-looking tags (one per vault, one or two per open pairing offer) and
  slots (one per device);
- the sealed records' sizes and when they change;
- the IP addresses and ports your devices use to reach it, which of them
  belong to one vault, and when they talk to each other;
- how many bytes a relayed connection carried.

It never learns your vault id, device ids, device names, any key, the
addresses inside your records, file names or content. Relayed connections are
TLS 1.3 between your devices; the server forwards encrypted records only. It
keeps nothing on disk, logs no tags or addresses, and has no accounts.

### Honest limits

- The operator can see which IP addresses talk to the service under one tag,
  so over time it can tell which addresses belong to one vault and roughly
  where its devices are and when they are online. Use your own service, or turn
  it off, if that matters to you.
- A device you removed from the vault can still compute the vault's tag until
  you create a new vault. It learns nothing it did not know, and cannot read
  the records (they are sealed under keys it no longer receives), but it can
  see that the tag is still in use.
- A pairing code is only nine digits. The service stores the offer under a slow
  hash of the code and sealed with a key from the code, so the server cannot
  read the addresses or practise guessing quickly, and the six-word check that
  both people compare at pairing is what stops someone who guessed the code
  from joining.
- The service cannot read relayed traffic, but it sees that it flows, between
  which two addresses and how much.
- It is a single point you may depend on to find devices on other networks. If
  it is down, devices that are already connected stay connected, and everything
  that worked without it still works.

## Pairing across networks

`Add a device` (and `varsto pair offer`) registers the offer with the service
as well as announcing it on the local network. The code, and the QR code or
link (which also carries a random token), then work from any network:

1. On a device that already uses Varsto choose *Add a device*. While the offer
   is registered the page says *It works on the same network and across the
   internet (rendezvous)*.
2. On the new device choose *Pair with your other device*, type the code and
   fill in a name and passphrase. No address is needed.
3. The new device tries, in order, an address you typed, the addresses in a
   scanned link, a search of the local network, and then the rendezvous
   service. The progress line shows *Looking for the device through the
   rendezvous service ...* for the last step. If the two devices cannot reach
   each other directly the connection is relayed.
4. Both people compare the six words, as always.

The pairing exchange is encrypted end to end between the two devices in every
case. Without internet, pairing on the same network works as before.

When the offering device uses your own server instead of the default, its QR
code and link also carry that server's address (`rvu=`), and the new device
looks the offer up there. A code typed by hand does not carry it: on another
network, scan the QR code or open the link, or start the new device with
`VARSTO_RENDEZVOUS=<your server's URL>`.

## Running your own

The server is one static binary, `varsto-rendezvous` (Linux x86_64, in the
daily build as `varsto-daily-rendezvous-linux-x86_64`). It keeps everything
in memory and writes nothing to disk. It needs:

- one TCP port on loopback for HTTP and WebSocket, behind a TLS proxy;
- one public UDP port for observe requests (default 3334; any free port but
  17893, which a Varsto device on the same host uses for its own peer-to-peer).

Clients read the UDP endpoint from `/info`, so it can be any port, but it
must be the one the internet reaches: when a firewall or NAT maps another
port, pass it with `--public-udp-addr host:port`.

### Quick install

Download `varsto-daily-rendezvous-linux-x86_64` from the daily page, then on
the server (any Linux with systemd; the binary has no dependencies):

```
mkdir -p ~/bin ~/.config/systemd/user
install -m 755 varsto-daily-rendezvous-linux-x86_64 ~/bin/varsto-rendezvous
~/bin/varsto-rendezvous --self-test        # must end with "self-test passed"
```

Then the unit (below), a reverse proxy and the firewall. Only the proxy and
firewall commands differ by distribution:

**Debian / Ubuntu**

```
sudo apt install caddy ufw
sudo ufw allow 3334/udp
sudo ufw allow 80,443/tcp
# put the Caddy snippet in /etc/caddy/Caddyfile, then
sudo systemctl reload caddy
```

**Fedora**

```
sudo dnf install caddy firewalld
sudo firewall-cmd --permanent --add-port=3334/udp
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --reload
# put the Caddy snippet in /etc/caddy/Caddyfile, then
sudo systemctl enable --now caddy
```

**Arch**

```
sudo pacman -S caddy nftables
# nftables: accept udp dport 3334 in the input chain, for example
#   sudo nft add rule inet filter input udp dport 3334 accept
# put the Caddy snippet in /etc/caddy/Caddyfile, then
sudo systemctl enable --now caddy
```

The UDP port is not optional for punching and the address check: without it
devices still pair and sync through the WebSocket relay, but every
connection goes through your server. Check it from another machine with
`nc -u -z -w2 rv.example.org 3334` (no error is not proof; the real check
is a device's `varsto p2p rendezvous status` showing an observed address).

### Options

Every option can also be set in the environment as `VARSTO_RV_<NAME>` (for
example `VARSTO_RV_LISTEN`); `ops/rendezvous/varsto-rendezvous.env.example`
lists them.

```
varsto-rendezvous --listen 127.0.0.1:8790 --udp 0.0.0.0:3334 \
    --public-udp-addr rv.example.org:3334 \
    [--relay-rate 4194304] [--relay-total-rate 33554432] \
    [--relay-tag-bytes 4294967296] [--relay-idle 300] [--relay-per-tag 4] \
    [--max-relays 1000] [--no-relay] \
    [--rate-put 60] [--rate-lookup 120] [--rate-coordinate 60] [--rate-udp 600] \
    [--rate-control 20] [--rate-tag-put 120] [--rate-tag-lookup 240] \
    [--max-controls 50000] [--max-controls-per-ip 32] \
    [--max-slots 200000] [--max-bytes 1073741824] \
    [--no-trust-proxy] [--grace 5] [--log info] [--stats-every 600]
varsto-rendezvous --self-test
```

What the limits do (per minute unless stated; the defaults suit a public
service and are far above what a household needs):

| Option | Default | Meaning |
| --- | --- | --- |
| `--rate-put`, `--rate-lookup` | 60, 120 | writes and lookups per client address |
| `--rate-tag-put`, `--rate-tag-lookup` | 120, 240 | the same per vault tag, so one vault cannot starve the rest |
| `--rate-control` | 20 | control connections opened per address |
| `--rate-coordinate` | 60 | punch and relay requests per address (and per tag) |
| `--rate-udp` | 600 | observe datagrams per address |
| `--relay-rate` | 4 MiB/s | bytes per second per relay session and direction (`0` turns the relay off) |
| `--relay-total-rate` | 32 MiB/s | bytes per second over all relay sessions together (`0`: no cap) |
| `--relay-tag-bytes` | 4 GiB | relay bytes one vault may move per hour (`0`: no cap) |
| `--relay-idle` | 300 s | a session that moves nothing either way ends |
| `--relay-per-tag`, `--max-relays` | 4, 1000 | sessions at once per vault and in all |
| `--max-controls`, `--max-controls-per-ip` | 50000, 32 | open control connections |
| `--max-slots`, `--max-bytes` | 200000, 1 GiB | memory bounds of the registry; past them new slots are refused `unavailable` |

IPv6 clients are counted by their /64. A refused request is answered `429`
(`rate_limited`); clients wait and try again, and everything they need keeps
working from the local network and the storages meanwhile.

### systemd user unit

Run it as an unprivileged user (`loginctl enable-linger <user>` so it starts
at boot without a login). The unit is
`ops/rendezvous/varsto-rendezvous.service`; install it as
`~/.config/systemd/user/varsto-rendezvous.service`:

```ini
[Unit]
Description=Varsto rendezvous service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%h/bin/varsto-rendezvous
EnvironmentFile=-%h/.config/varsto-rendezvous.env
KillSignal=SIGTERM
TimeoutStopSec=15
Restart=always
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=65536
MemoryMax=1536M

[Install]
WantedBy=default.target
```

Put your options in `~/.config/varsto-rendezvous.env` (copy
`ops/rendezvous/varsto-rendezvous.env.example`; at least
`VARSTO_RV_PUBLIC_UDP_ADDR`). Then:

```
systemctl --user daemon-reload
systemctl --user enable --now varsto-rendezvous
journalctl --user -u varsto-rendezvous -f
```

`systemctl --user stop` sends SIGTERM: the server stops accepting, tells
every open connection to close and exits when they have, or after
`--grace` seconds (5). Devices notice, reconnect after a few seconds and
write their records again; nothing is lost that a restart does not restore
within minutes.

### Caddy

Every route works with and without the `/rv` prefix, so either form works.
WebSockets pass through `reverse_proxy` as they are; the server pings its
control connections every 30 s, which keeps proxies with short idle timeouts
from cutting them (Caddy's default needs no change). The snippets are in
`ops/rendezvous/Caddyfile.snippet`.

Under a path of an existing site:

```
example.org {
    handle_path /rv/* {
        reverse_proxy 127.0.0.1:8790
    }
    # ... the rest of the site
}
```

Clients then use `https://example.org/rv`.

On a host name of its own:

```
rv.example.org {
    reverse_proxy 127.0.0.1:8790
}
```

Clients then use `https://rv.example.org`.

The server takes the client address from the last `X-Forwarded-For` entry
only when the connection comes from loopback (the proxy on the same host);
`--no-trust-proxy` turns that off. Behind a proxy on another host, either
run the server on that proxy's host or accept that all clients share the
proxy's address for rate limiting.

### Firewall

| Port | Protocol | Open to | For |
| --- | --- | --- | --- |
| 443 (and 80 for certificates) | TCP | everyone | the proxy: HTTP, the control WebSocket and the relay |
| 3334, or your `--udp` port | UDP | everyone | observe datagrams and hole-punch coordination |
| 8790, or your `--listen` port | TCP | nobody (loopback only) | the proxy's upstream |

If the UDP port is forwarded from another port (a cloud security group, a
router), pass the outside port in `--public-udp-addr`.

### Checking it

```
varsto-rendezvous --self-test
curl -s https://rv.example.org/info
curl -s https://rv.example.org/health
```

`--self-test` starts a private server on loopback and plays two devices
against it (register, lookup, a refused overwrite, observe, claims, a relayed
stream, health); it proves the binary works on this machine, not the proxy
or the firewall. `/info` shows what clients will use (the `udp` endpoints,
`relay`, the limits). `/health` answers one line of counters, for example
`ok v=1 up=3600 tags=12 slots=31 pair=0 control=29 relays=1 relay_bytes=81234 udp=4410 refused=3 limited=0`.
From a device, `varsto p2p rendezvous status` shows whether it is
connected and which address the server observed.

### Logs

Logs go to stderr (journald), one line each, without timestamps of their
own. At the default `info` level they are:

- the start (version, listen and UDP addresses) and the stop;
- a totals line every 10 minutes (`--stats-every`): the `/health` counters
  plus `dropped` (control messages lost to connections that do not read),
  `slow_closed` (those connections closed) and `quota_stopped` (relay
  sessions ended by the hourly per-vault quota).

They never contain a tag, a slot, a key or an address. `--log debug` also
logs when control connections open and close and how many bytes a relay
session carried; a connection is identified there by a salted hash of its
address that changes at every restart. Use it to find out whether a problem
is yours, then turn it off again.

### What the operator can see

Everything under "Privacy: what the server sees" above, and nothing more. In
practice: `/health` gives totals only; the process can list, in memory,
which addresses belong to one vault tag and when they talk to each other
(that is inherent in a meeting point), but it cannot read any record, name
or key. There is no database to leak and no log to subpoena beyond the
totals lines. If you run a service for other people, say so in plain words
to them; the paragraph above is a good start.

### Memory and capacity

Everything is in memory with a hard bound:

- a slot costs its sealed record (usually 1 to 2 kB, at most 64 kB) plus
  about 200 bytes; `--max-slots` and `--max-bytes` stop growth (refused
  `unavailable`). A vault with 5 devices is 5 slots; peer records expire
  after 48 h without a refresh;
- an open control connection costs a few tens of kB (socket buffers and a
  64-message queue); `--max-controls` bounds them. Each device holds one
  while its service runs;
- a relay session buffers up to 128 kB per direction;
- rate-limit buckets are capped at 200 000 per class of request and pruned every minute. A flood of UDP observe sources fills only the observe map; it cannot crowd out new TCP clients.

Measured by the load test (`cargo test -p varsto-rendezvous --test load --
--ignored`): 10 000 slots of 1 kB, 1 000 held control connections and 50
concurrent relay sessions grew the resident memory of one process holding
both the server and all the test clients by 83 MiB. A server for a few
hundred vaults runs happily in 128 MiB; the 1.5 GiB in the unit is a
ceiling, not an expectation.

Bandwidth is the real cost, and only for relayed connections: the caps above
(4 MiB/s per session, 32 MiB/s in all, 4 GiB per vault and hour) bound it.
Most connections never relay; they are direct, or punched through with the
server only coordinating.

### Upgrading

The service is stateless, so an upgrade is a restart:

```
install -m 755 varsto-daily-rendezvous-linux-x86_64 ~/bin/varsto-rendezvous.new
~/bin/varsto-rendezvous.new --self-test && mv ~/bin/varsto-rendezvous.new ~/bin/varsto-rendezvous
systemctl --user restart varsto-rendezvous
curl -s https://rv.example.org/info
```

(`mv` over the running binary is safe; the old process keeps its inode.)
Connected devices reconnect within seconds (5 s, then up to 5 min if the
service stays away) and republish their records; relayed sessions in
flight are cut and the apps retry through the route list. The wire format is
versioned (`v` in every message); a server answers an unknown version with
`version`, and old and new apps keep working against a newer server because
fields are only ever added. If you roll back, no data has to be migrated.

## Troubleshooting

| What you see | What it means | What to do |
| --- | --- | --- |
| `not reachable (everything else keeps working)` | The service does not answer: your internet is down, a firewall blocks it, or the server is down. | Nothing is lost. Check `curl -s <address>/info`. Devices on the same network still find each other. |
| `not connected yet` | The background service has just started and has not talked to it yet, or the background service is not running. | Wait a minute; start the service with `varsto service start`. |
| A warning that the clock is off | This device's clock differs from the service's by more than 30 seconds. Requests are signed with the time and refused outside a five-minute window. | Set the clock right (turn on automatic time). |
| Pairing says it could not reach the device | The code expired (ten minutes), was typed wrongly, or one of the devices cannot reach the service. | Start a new offer; check both devices are online; on a phone check that the app may use the network. |
| `relayed via rendezvous` for a peer | No direct route worked (two strict routers, UDP blocked), so the service relays the encrypted connection. | Fine to leave. For a faster link, forward the peer-to-peer port on one router or run a device with a public address. |
| Peers on other networks never appear | The devices use different services. | Run `varsto p2p rendezvous status` on each and make the addresses the same. |
