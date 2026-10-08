# Logging

Debug logging is **on by default in every application** (daemon, CLI, desktop and mobile apps, MCP server) so that bugs can be investigated after the fact. Logging must never weaken the security model.

## What is logged

Every operation with start, end and outcome: sync runs, block transfers (short block id, size, source: peer or storage), ledger events, peer discovery and connections, storage requests (type and result only), removable-disk attach and eject, policy evaluation and alerts, deletions and trash, device add / revoke / wipe, user actions, MCP calls (tool and result, never file content), key lifecycle events (never key material), application start, version and non-secret settings.

Format: JSON lines (UTC timestamp, level, component, event, operation id, fields). The operation id follows the operation across devices together with the ledger events.

## What is never logged

- Passwords, keys, tokens, recovery key shares, security key PINs, file content.
- File names and paths in clear text: only a locally keyed hash is logged. Strongroom items are logged without any name or hash.
- Clear-text IP addresses or user identifiers.

Enforcement: secrets are distinct types with no loggable form; logging macros accept only allowed field types; a lint and code review check this; **canary tests** feed known sentinel values as passwords, file names and keys through full scenarios and assert that none appears in any log, crash dump, diagnostics bundle or network traffic.

## Storage and size

- Logs stay on the device in the application's private directory (encrypted or free of anything forbidden by the "no clear-text data on mobile" rule). They are excluded from backups and never synchronised.
- Rotation by age (default 14 to 30 days) and size; errors and warnings are kept longer than routine events. Smaller limits on mobile.
- Asynchronous, buffered writes; logging must not noticeably slow synchronisation.
- Levels: error, warn, info, debug, trace. Debug is the default; trace is off by default.

## User control

- Nothing is sent automatically. No telemetry, no automatic crash upload.
- `logs export` builds a diagnostics bundle on request, with a preview of its content before it is shared.
- `logs tail | search | clear` in the CLI, a log view in the UI, and a read-only MCP tool that returns the already sanitised log.
- Core dumps are off by default; secrets are zeroised after use; panic messages are sanitised.

## Platform notes

Linux: files in the state directory, optional journald. Windows: files in the app data folder, nothing sensitive in the event log. macOS and iOS: own log files and `os_log` with `private` for all variable values. Android: private files; only error codes go to logcat.
