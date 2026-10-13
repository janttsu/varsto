# Varsto and AI assistants (MCP)

This page is for two readers: **you**, setting up an assistant, and **the assistant** (a local LLM or a cloud model) that works with your files through Varsto. The server sends a short version of it to the model when a client connects (the `instructions` of MCP `initialize`).

## What the server is

`varsto mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server: JSON-RPC 2.0 over stdin and stdout (protocol version 2025-06-18). An MCP client (Claude Desktop, Claude Code, OpenCode, Crush, Qwen Code or any other) starts it as a subprocess. Through it the assistant can:

- see the folders you granted and their files, with each file's place on this device's disk (`local_path`);
- record what a file contains, in words and tags: its **analysis**, kept by Varsto and synced encrypted to all your devices;
- find files by what they contain without reading them again;
- reorganise: create directories, move and rename files, write new text files (summaries, indexes);
- sync, and see Varsto's own placement advice.

It never hands out file contents. The assistant reads synced plain files itself, from `local_path`, with its own file tools. Nothing is ever deleted or overwritten: there is no delete tool, writing creates new files only, and a move needs a free target name.

## Starting it

```sh
varsto mcp                      # stdio; your MCP client runs this command
varsto --home DIR mcp           # another device directory (also VARSTO_HOME)
varsto mcp --key vmk_...        # with a scoped key (also VARSTO_MCP_KEY), see below
```

Where the data comes from:

1. **With a key** (`--key` or `VARSTO_MCP_KEY`): the running Varsto service (the app, the tray, or `varsto service run`), which checks the key's scope on every call. A key never opens the vault itself; when the service is not running the tools answer "the Varsto service is not running".
2. **Without a key, service running**: the service, with the access in the grants file.
3. **Without a key, no service**: the server opens the vault itself with `VARSTO_PASSPHRASE`.

## Access: grants and keys

Nothing is visible until you grant it. There are three levels per folder:

| Level | Command | Allows |
|---|---|---|
| `ro` | `varsto mcp grant docs` | list files, read synced files from `local_path`, read and search analyses, sync |
| `an` (analyse) | `varsto mcp grant docs --analyse` | the above, and record or clear analyses; no moves, no new files |
| `rw` | `varsto mcp grant docs --write` | everything: analyses, directories, moves and renames, new text files |

```sh
varsto mcp grant all            # every folder, read-only (never a Strongroom: those need a grant by name)
varsto mcp grant photos --analyse
varsto mcp list                 # the grants and what each level allows (--json for the file)
varsto mcp revoke photos        # or: varsto mcp revoke all
```

Grants live in `mcp-grants.json` in the device directory.

### MCP keys

A key lets an MCP client use the running service with a scope of its own, without the service's session token and without your passphrase:

```sh
varsto mcp key create --name qwen --folders docs,photos --analyse --expires-days 90
varsto mcp key create --name tidy --folders docs --write
varsto mcp key create --name reader               # no --folders: a copy of the current grants
varsto mcp key list                                # name, id, scope, created, expiry, last use
varsto mcp key revoke qwen                         # by name or id; refused at once
```

The key (`vmk_` and 64 hex characters) is printed once. Varsto keeps only its BLAKE3 hash in `mcp-keys.json` (readable by your user only). The service answers a key only on the routes the MCP tools use (status, folders, files, analyses, move, mkdir, write, sync), only within the key's folders and levels, and shows it only its folders; every other route answers 403, and an unknown, revoked or expired key 401. Keys are never logged.

A key limits what an MCP client can do through the service. It is not a sandbox: a program that can read your device directory can also read the service's session token there. Run untrusted assistants as another user or in a container that sees only the synced folders it should read.

### Client configuration

`varsto mcp config` prints a ready-to-paste configuration with the absolute path of the `varsto` binary; `--create-key` creates the key in the same step (named with `--key-name`, scoped with `--folders`, `--write`, `--analyse`, `--expires-days`) and puts it in the snippet, otherwise there is a placeholder. `VARSTO_HOME` is added when the device directory is not the default one.

```sh
varsto mcp config --client claude --create-key --key-name claude --folders docs --analyse
varsto mcp config --client opencode
varsto mcp config --client crush
varsto mcp config --client qwen
varsto mcp config --client generic
```

What it prints, for reference (`/usr/local/bin/varsto` stands for your binary):

**Claude Desktop** (`claude_desktop_config.json`) and **Claude Code** (`.mcp.json`):

```json
{"mcpServers": {"varsto": {"command": "/usr/local/bin/varsto", "args": ["mcp"], "env": {"VARSTO_MCP_KEY": "vmk_..."}}}}
```

or, for Claude Code: `claude mcp add varsto --env VARSTO_MCP_KEY=vmk_... -- /usr/local/bin/varsto mcp`

**OpenCode** (`opencode.json`):

```json
{"$schema": "https://opencode.ai/config.json",
 "mcp": {"varsto": {"type": "local", "command": ["/usr/local/bin/varsto", "mcp"], "enabled": true, "environment": {"VARSTO_MCP_KEY": "vmk_..."}}}}
```

**Crush** (`crush.json`):

```json
{"$schema": "https://charm.land/crush.json",
 "mcp": {"varsto": {"type": "stdio", "command": "/usr/local/bin/varsto", "args": ["mcp"], "env": {"VARSTO_MCP_KEY": "vmk_..."}}}}
```

**Qwen Code** (`~/.qwen/settings.json`):

```json
{"mcpServers": {"varsto": {"command": "/usr/local/bin/varsto", "args": ["mcp"], "env": {"VARSTO_MCP_KEY": "vmk_..."}}}}
```

**Any stdio client**: command `/usr/local/bin/varsto`, arguments `["mcp"]`, environment `VARSTO_MCP_KEY=vmk_...` (and `VARSTO_HOME` if needed).

## Tools

Every result is JSON in a text block. Paths are relative to the folder, with `/` between directories. Folder arguments take the folder's name.

### `varsto_status`

The vault, devices, storages and the granted folders with their block and copy counts. No arguments.

### `varsto_folders`

The folders you may see, with `access` (`ro`, `analyse` or `rw`) and `local_path`: the folder's directory on this device when its files are kept there as plain files (`null` for a folder kept encrypted on this device).

### `varsto_files`

`{"folder": "docs", "with_analysis": true}`

Every file: `path`, `size`, `state` (`local`, `placeholder`, `missing`), `modified_utc`, `last_accessed_utc` (Varsto's own record of use), `content_hash`, `local_path` (only for a synced plain file on this disk), and when the file has an analysis: `analysis` (its first 500 characters), `analysis_truncated`, `analysis_tags`, `analysis_utc`, `analysis_by`, `analysis_author` (the device) and `analysis_stale` (the file changed after it was analysed). `"with_analysis": false` leaves the analyses out, for very large folders.

### `varsto_set_analysis` (analyse or rw)

```json
{"folder": "docs", "path": "2026/receipt-0412.pdf",
 "analysis": "Receipt from a hardware store, 12 April 2026: 3 boxes of wood screws, 12.40 EUR incl. VAT. Language: Finnish.",
 "tags": ["receipt", "hardware", "2026"], "by": "qwen3:8b"}
```

Records what the file contains, replacing its earlier analysis. `analysis`: plain text, at most 16 KiB. `tags`: at most 32, each at most 64 characters; repeats are dropped. `by`: your model or tool name (at most 128 characters). The answer is the stored analysis. Other devices get it with the next sync.

### `varsto_clear_analysis` (analyse or rw)

`{"folder": "docs", "path": "2026/receipt-0412.pdf"}` removes the analysis on every device.

### `varsto_get_analysis`

`{"folder": "docs", "path": "2026/receipt-0412.pdf"}`: the full analysis (`path`, `analysis`, `tags`, `content_hash`, `stale`, `author`, `by`, `analysed_utc`), or `null`.

### `varsto_search_analyses`

```json
{"query": "screws receipt", "folder": "docs", "tags": ["2026"], "limit": 50}
```

Every word of `query` must occur, ignoring case, in the file's analysis, one of its tags or its path; the file must carry every tag in `tags`. Without `folder` every granted folder is searched. Answer: `{"total": 3, "hits": [{"folder", "path", "state", "snippet", "tags", "stale", "analysed_utc", "by", "score", "local_path"}]}`, best matches first (`limit` default 50, at most 500).

### `varsto_move` (rw)

`{"folder": "docs", "from": "scan0012.pdf", "to": "2026/receipts/hardware-0412.pdf"}`: moves or renames; the target must be free. The file's analysis goes along. The change syncs to the other devices.

### `varsto_mkdir` (rw)

`{"folder": "docs", "path": "2026/receipts"}`. In a folder kept encrypted on this device a directory exists once a file is in it.

### `varsto_write` (rw)

`{"folder": "docs", "path": "2026/receipts/INDEX.md", "text": "..."}`: creates a new text file (at most 2 MiB); an existing name is refused.

### `varsto_sync`

`{"folder": "docs"}` or `{}` for every granted folder: pull, then push. It also publishes analyses recorded since the last sync.

### `varsto_storage_advice`

`{"folder": "docs", "idle_days": 90}`: files idle for that long and their monthly cost in every known storage class, cheapest first, with sources. Nothing is moved.

## Workflow for a local LLM

1. `varsto_folders`, then `varsto_files` for a folder.
2. For each file with a `local_path` and no analysis (or `analysis_stale: true`), read it from `local_path` with your own file tools. For large files read the beginning, or what your context allows; for images and other media use what your tools can see.
3. Record what it contains with `varsto_set_analysis`: what kind of document it is, its subject, people and organisations, places, dates, amounts, language, and anything that helps to find or file it later. Add a few short, consistent tags. Set `by` to your model name.
4. Later, answer questions and plan with `varsto_search_analyses` instead of reading the files again.
5. Reorganise only when the user asks: propose the plan first, then `varsto_mkdir` and `varsto_move`. Leave a summary or an index as a new file with `varsto_write` if it helps.

## Rules for the assistant

- Stay inside the granted folders; paths are relative to the folder.
- Nothing is deleted or replaced. Choose unique names; if a name is taken, pick another one (for example add a number).
- Write summaries, indexes and notes as new files; never try to change a file in place.
- A file without `local_path` is not on this device as a plain file: it is a placeholder (only its name is here), it is missing, or the folder is kept encrypted on this device. Skip it and tell the user; they can download it in Varsto (or turn selective sync off) and ask again.
- Re-analyse a file whose analysis is `stale`.
- Analyses are synced to all of the user's devices. Do not copy secrets (passwords, card numbers, keys) into them unless the user wants them findable.

## Privacy

- File contents never pass through the MCP server. The assistant reads synced plain files from the disk itself; what it does with them is up to the assistant and where it runs (a local model keeps everything on the device; a cloud model sends what it reads to its provider).
- Analyses are encrypted under the folder's key before they reach a storage (storages see only sizes and times) and are readable on every device of the folder, also by members of a shared folder. On the device they are kept in the device directory like the folder's sync state. See section 36 of [the format specification](spec/alpha-0-format.md).
- Strongroom folders are never visible unless granted by name, and only while unlocked.
- MCP keys are stored only as hashes; the key itself is shown once.

See also: [the format specification](spec/alpha-0-format.md), sections 13 (last-accessed times and the MCP server), 36 (file analyses) and 37 (MCP keys).
