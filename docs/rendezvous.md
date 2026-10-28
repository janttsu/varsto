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

<!-- U: describe the Peers page control and the CLI with real output. -->

```
varsto p2p rendezvous status
varsto p2p rendezvous set https://rv.example.org/rv
varsto p2p rendezvous --off
```

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

<!-- U: honest limits in plain words (spec 83.11): the operator can see which
     addresses form a vault over time; a removed device can still find the
     vault's tag; pairing codes are protected by a slow hash plus the
     six-word check. -->

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

<!-- U: a "troubleshooting" section once the client shows rendezvous state
     (unreachable, clock off by more than five minutes, relay off). -->
