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

## Running your own

The server is one static binary, `varsto-rendezvous` (Linux x86_64, in the
daily build as `varsto-daily-rendezvous-linux-x86_64`). It keeps everything
in memory. It needs:

- one TCP port on loopback for HTTP and WebSocket, behind a TLS proxy;
- one public UDP port for observe requests (default 17893; any free port).

Clients read the UDP endpoint from `/info`, so it can be any port, but it
must be the one the internet reaches: when a firewall or NAT maps another
port, pass it with `--public-udp-addr host:port`.

### Options

```
varsto-rendezvous --listen 127.0.0.1:8790 --udp 0.0.0.0:17893 \
    --public-udp-addr rv.example.org:17893 \
    [--relay-rate 4194304] [--relay-per-tag 4] [--max-relays 1000] [--no-relay] \
    [--rate-put 60] [--rate-lookup 120] [--rate-coordinate 60] [--rate-udp 600] \
    [--no-trust-proxy] [--log info]
```

### systemd user unit

Run it as an unprivileged user (`loginctl enable-linger <user>` so it starts
at boot without a login). `~/.config/systemd/user/varsto-rendezvous.service`:

```ini
[Unit]
Description=Varsto rendezvous service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%h/bin/varsto-rendezvous --listen 127.0.0.1:8790 --udp 0.0.0.0:17893 --public-udp-addr rv.example.org:17893
Restart=always
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
MemoryMax=1536M

[Install]
WantedBy=default.target
```

```
systemctl --user daemon-reload
systemctl --user enable --now varsto-rendezvous
journalctl --user -u varsto-rendezvous -f
```

Open the UDP port in the firewall (for example `ufw allow 17893/udp`).

### Caddy

Every route works with and without the `/rv` prefix, so either form works.
WebSockets pass through `reverse_proxy` as they are.

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
`--no-trust-proxy` turns that off.

### Checking it

```
curl -s https://rv.example.org/info
curl -s https://rv.example.org/health
```

`/health` answers one line of counters, for example
`ok v=1 up=3600 tags=12 slots=31 pair=0 control=29 relays=1 relay_bytes=81234 udp=4410 refused=3 limited=0`.

## Troubleshooting

| What you see | What it means | What to do |
| --- | --- | --- |
| `not reachable (everything else keeps working)` | The service does not answer: your internet is down, a firewall blocks it, or the server is down. | Nothing is lost. Check `curl -s <address>/info`. Devices on the same network still find each other. |
| `not connected yet` | The background service has just started and has not talked to it yet, or the background service is not running. | Wait a minute; start the service with `varsto service start`. |
| A warning that the clock is off | This device's clock differs from the service's by more than 30 seconds. Requests are signed with the time and refused outside a five-minute window. | Set the clock right (turn on automatic time). |
| Pairing says it could not reach the device | The code expired (ten minutes), was typed wrongly, or one of the devices cannot reach the service. | Start a new offer; check both devices are online; on a phone check that the app may use the network. |
| `relayed via rendezvous` for a peer | No direct route worked (two strict routers, UDP blocked), so the service relays the encrypted connection. | Fine to leave. For a faster link, forward the peer-to-peer port on one router or run a device with a public address. |
| Peers on other networks never appear | The devices use different services. | Run `varsto p2p rendezvous status` on each and make the addresses the same. |
