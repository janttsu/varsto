# Logging

Status: implemented; section 45 of [the specification](../spec/alpha-0-format.md) records what is built.

Every Varsto program (background service, CLI, tray, desktop app, MCP server, mobile library, app shells) keeps a **local debug log, on by default at level `debug`**, so that a problem can be investigated after the fact on the device where it happened. The log is for the owner of the device: it stays on that device and is never uploaded. Logging must never weaken the security model: the things that protect the data never appear in it.

## Where

- `<home>/logs/varsto-<component>.log`. Homes: Linux `~/.local/share/varsto`, macOS `~/Library/Application Support/Varsto`, Windows `%APPDATA%\Varsto`, Android `<app files>/vault`, iOS the app's vault directory, or `--home`/`VARSTO_HOME`.
- Components: `service` (`varsto service run`), `desktop-app` (`varsto desktop`, which runs the service in-process), `cli` (every other command), `tray`, `mcp`, `ffi-ios` / `ffi-android` (the mobile library, with the iOS app's own lines under module `app`), `app` (the macOS menu bar app and the Android shell, written by small native loggers in the same format).
- The directory is mode 0700 and the files 0600. `varsto log path` prints the directory.
- The service still writes its notable events (info and above) to stderr, which the launch agent, systemd unit, tray or Android shell keep in `<home>/service.log` as before.

## Format

One record per line (continuation lines of a multi-line message are indented by four spaces):

```text
2026-10-13T13:30:38.123Z DEBUG service[4242/sync] varsto_core::engine: push done subject=Photos ms=812 result={"files_changed":3}
```

RFC 3339 UTC time with milliseconds, level, component, `[pid/thread]`, module, message, then `key=value` fields (values with spaces or quotes are quoted and escaped).

## Levels and configuration

- Levels: `error`, `warn`, `info`, `debug`, `trace`. Default `debug` (a user decision: everything that happens is logged). `trace` adds the per-block events: every block read or written on a storage, every block asked of or served to a peer, write-target decisions per file.
- The level is taken from, in order: the command-line flag `--log-level`, the environment variable `VARSTO_LOG`, `log_level` in `config.json` (set from the interface), the default. A bad value in `VARSTO_LOG` or the configuration falls back to the default; a bad `--log-level` is a usage error (exit 2).
- A level can be a filter: `debug,varsto_core::p2p=trace` (longest module prefix wins). The plain level applies to Varsto's own modules; other crates log at `warn` (or less when a lower level is asked) unless named, e.g. `rustls=debug`.
- The interface can change the level while running (Settings → Logs); `VARSTO_LOG` and `--log-level` still win for that process.
- Levels are checked before a message is formatted, so disabled levels cost one comparison.

## What is logged

At `debug`: each command with its arguments (values of secret options replaced) and its outcome and duration; each local API request (method, path and query without the session token, status, duration); the start, end, duration and a compact summary of every engine operation (push, pull, sync, fetch, fsck, policy checks, verification, bit-rot checks, repair, backups and their expiry, restic mirror setup and checks, data moves, placement changes, disk insert, check, eject and retire, fetch plans, strongrooms, sharing, organizations, membership changes, configuration reloads); ledger batches sealed and pushed (sequence numbers, event counts), ledger objects found per device, manifests published (sequence, file counts); every storage request other than block objects (backend, operation, object name, bytes, result, duration), failed storage requests of any kind and S3 clock-skew retries; peer-to-peer requests other than blocks (peer device name, path, status, bytes, route, duration), connections and route decisions; restic invocations (arguments, exit code, duration, the end of stderr); MCP tool calls (tool, folder and path, outcome); the service loop (each sync round with counts and duration, upkeep duration, reloads). At `info` and above: the service's notable events (disks, policy alerts, backups, p2p state). Errors are logged with their full context chain.

## What never appears

- **Keys and secrets:** vault, device, folder, share, replica and peer keys; signing keys; passphrases; recovery words and recovery shares; the service token; MCP keys; share, replica and organisation tokens; S3 secret access keys; rclone tokens; restic passwords; security-key PINs and secrets.
- **Contents:** plaintext file contents, decrypted manifests, thumbnails and other decrypted metadata blobs. Reports logged in summaries are the operation's counts and names, never data.

What **may** appear, because this log is the owner's own record on the owner's own device: file names and paths, folder, device and storage names, storage endpoints and bucket names, access key ids, object names (chunk ids are keyed hashes), sizes, timings, peer addresses.

## Enforcement

1. **Types.** Secret types print `[redacted]` in `Debug` (`SecretKey`, `SigningKey`, `DecapsKey`, `Keys`, `FolderKeys`, peer snapshots and tables, `S3Config`'s secret, `SecretStore`'s values, share, replica and sealed tokens, folder records' keys, recovery shares, organisation results with words or tokens, restic holds, the service file); see `varsto_core::redacted_debug!` and `redacted_opaque!`.
2. **Field names.** A field whose name says secret (`passphrase`, `password`, `secret`, `token`, `mnemonic`, `words`, `pin`, `*key_hex`, `vault_key`, …) is written as `[redacted]` whatever it holds; operation summaries drop such keys too.
3. **Scrubber.** Every finished line (and every file of a diagnostics bundle) passes `varsto_core::logging::scrub`: values the process registered (the service token, storage secret keys when opened or unlocked, passphrases from the environment or the prompt, a vault key being joined with), keys registered by keyed hash only (a 64- or 128-digit hex rendering of a registered key), token shapes (`vmk_…`, `vst1.`/`vst2.`, `vot1.`, `<hex id>.<64 hex>` share and replica tokens), assignments whose name says secret (`token=…`, `X-Varsto-Token: …`, `"password":"…"`, `Bearer …`) and runs of 12 or more BIP-39 words.
4. **Code.** Code never passes a secret to a log macro in the first place; the layers above are defence in depth.
5. **Tests.** `crates/varsto-core/tests/log_secrets.rs` logs every kind of secret through every macro form (Debug, Display, message text, fields with secret and neutral names, typed fields) at every level and asserts that none appears in the log files or the bundle, that file names do, and that the files are 0600 in a 0700 directory. `varsto_core::logging` unit tests cover the scrubber, filters, format and rotation.

## Size

- Rotation by size: the active file is rotated when it passes **10 MiB** into `varsto-<component>.1.log.zst` (zstd level 3), older ones shift up; **5 files per component** (the active one and 4 rotated). The whole directory is capped at **64 MiB**: the oldest rotated files of any component go first; active files are never removed. Phones (the mobile library): 4 MiB per file, 4 per component, 24 MiB in all.
- Writes are buffered and written as whole lines with one `write` on a file opened for appending (several processes may write the same component's file); the buffer is written every second, at once for warnings and errors, at exit and on a panic. A process notices when another one rotated the file and reopens it.
- A panic is logged with its location and a full backtrace before the default handler runs.

## Diagnostics bundle

`varsto log bundle [--output FILE]` or Settings → Logs → "Save log bundle" writes a `.tar.zst` with the log files (decompressed and scrubbed again), the end of `service.log` and `restic-run.log`, `about.json` (version, platform, log level), the service's state (`/api/state`) when it runs and `config.json` (no secrets in it). Nothing is sent anywhere: the owner looks through it and decides whether to share it. The command prints a reminder that it contains file, folder, device and storage names.

## User control

- `varsto log path`, `varsto log tail [--component X] [-n N] [-f]`, `varsto log bundle`.
- Settings → Logs: level, space used, "Open log folder" (computers), "Save log bundle".
- No telemetry, no automatic upload, no crash reporting service. Logs are never synced, never stored on a storage, never included in backups made by Varsto, and never collected by CI as artifacts; the VM lab collects them from its test VMs on purpose (`TESTING.md`).

## Later

Encryption of the log at rest (a separate log key so that logging works while the vault is locked; row- or block-level encryption so the last line survives a crash) may come before a non-alpha release, on top of the rules above, never instead of them: a bundle must contain no secrets even if a log key leaks.

## Platform notes

Linux, Windows, macOS: files in the home as above. iOS: the library writes `varsto-ffi-ios.log`; the app logs through `varsto_log(level, msg)`. Android: the service binary writes `varsto-service.log`, the Kotlin shell `varsto-app.log`; nothing goes to logcat. The macOS menu bar app writes `varsto-app.log` itself.
