# Notifications on your phone

Varsto already shows desktop notifications. Push channels send the same
alerts to your phone through **ntfy**, **Pushover** or **Telegram**, so a
storage that stops answering, a failed backup or a full disk does not wait
until you look at the computer.

Each device sends its own messages, and every message starts with the name of
the device. A channel set up on your laptop does not send what your NAS sees.

## Privacy

- The channels live in `notify.json` in the device directory. The file is
  readable by you only (mode 0600), stays on this device and is never synced
  to the vault. It holds the tokens and keys of the services.
- A message reaches your phone through the servers of the service you chose
  (ntfy.sh, Pushover, Telegram). It is **not end-to-end encrypted** on the
  way. The text can name folders, storages and devices.
- Turn off "Include names of folders, storages and devices" for a channel and
  a message only says what kind of event it is (for example "Storage problems")
  and asks you to open Varsto on that device. No names leave the computer.
- ntfy can run on your own server (docker, a small VPS). Then the messages go
  nowhere else. Use `https://` unless the server is on your own network.
- On ntfy.sh anyone who knows a topic can read its messages and publish to it.
  Varsto suggests a topic with 20 random characters. Keep it to yourself.
- Tokens, keys and passwords are never shown again after you save them: the
  interface and `varsto notify list` show only the last four characters. They
  are not written to the debug log and are cut out of error messages.

## Set up in the interface

Open Settings and find the Notifications card (it works while the vault is
locked, too).

1. Press "Add a channel" and choose the service.
2. Follow the numbered steps. Each field sits next to its step.
3. Press "Send a test message" and check your phone.
4. Choose what the channel receives (see the table below), and whether
   messages may include names.
5. Save. The switch on a channel turns it on or off, "Edit" changes it later
   (a saved secret shows as "Saved (…1234)" and stays when you leave the field
   empty), "Test" sends a test message again.

### ntfy

1. Install the ntfy app (Android: Google Play or F-Droid; iPhone: App Store),
   or open ntfy.sh in a browser.
2. Varsto suggests a topic. Press "New name" for another one.
3. In the app press +, choose "Subscribe to topic" and enter the same topic.
4. Your own server: open "Use my own ntfy server", enter its address, and if
   it needs a login an access token (ntfy web app: Account, Access tokens, or
   `ntfy token add` on the server) or a user name and password.

### Pushover

1. Make an account at pushover.net and install the Pushover app (30 days free,
   then a one-time purchase per platform).
2. Copy your User Key from the top of pushover.net after you log in.
3. Create an application at pushover.net/apps/build (name it Varsto) and copy
   its API Token.
4. Optional: a device name, to send only to that device.

Varsto sends alerts with normal priority and the rest with low priority. It
never uses the priorities that bypass quiet hours or need an acknowledgement.

### Telegram

1. In Telegram open @BotFather, send `/newbot`, and choose a name and a user
   name that ends in `bot`.
2. Paste the token BotFather sends (it looks like `123456789:AA…`).
3. Open your new bot and press Start (or send it any message). For a group,
   add the bot to the group and send a message there.
4. Press "Find my chat" and choose the chat, or type the chat id (a number, or
   `@name` for a public channel).

## Set up on the command line

`varsto notify` edits `notify.json` directly. It works without the vault
being unlocked and without the service running; a running service notices the
change by itself. Secrets are never taken as arguments (they would show in
the shell history and `ps`): they are asked for without echo, or read from
standard input with a `--*-stdin` option.

```sh
varsto notify add ntfy --name Phone               # prints the topic to subscribe to
varsto notify add ntfy --server https://ntfy.example.org --topic backups --token-stdin < token.txt
varsto notify add pushover --user-key UQ... --device pixel   # asks for the API token
varsto notify add telegram                        # asks for the bot token, lists the chats
varsto notify add telegram --chat-id 123456789 --bot-token-stdin < bot.txt

varsto notify list                                # secrets masked
varsto notify test Phone
varsto notify events                              # the kinds of messages
varsto notify events Phone --off folders,disks --on backups_done
varsto notify events Phone --defaults
varsto notify details Phone off                   # no names in messages
varsto notify summary-hour 8
varsto notify disable Phone
varsto notify remove Phone --yes
varsto notify telegram-chats                      # asks for a bot token
```

A channel is named by its id or its name. `varsto notify edit CHANNEL` takes
the same options as `add`; a new secret goes in on standard input, one line
for each, in the order bot token, API token, access token, password.

## What can be sent

| Event | Kind | On by default | Meaning |
| --- | --- | --- | --- |
| `storage` | alert | yes | A storage cannot be reached or fails, and when it works again. |
| `space` | alert | yes | Disk space is low on this device, or a storage quota is full. |
| `durability` | alert | yes | A folder has fewer copies than its policy asks, and the result of repairs. |
| `integrity` | alert | yes | Verification or the bit-rot check found damaged or missing blocks, or the ledger has problems. |
| `backups_failed` | alert | yes | A backup or a restic backup failed or is overdue. |
| `requests` | alert | yes | A device asks to pair, or asks for access to a folder. It waits for your approval. |
| `disks` | info | yes | A disk check is due, a disk was attached, removed or mounted, or which disk to dock next. |
| `folders` | info | yes | A folder was paused, or a move finished or waits. |
| `backups_done` | info | no | A backup finished. |
| `files_new` | info | no | New files arrived from other devices (at most one message per folder every 15 minutes). |
| `updates` | info | yes | A new version of Varsto is available. |
| `daily_summary` | info | no | Once a day after the chosen local hour (9 by default): Varsto is running, and how many alerts there were. A sign that the device is alive. |
| `other` | info | yes | Anything else Varsto reports. |

The same message is sent at most once in six hours, and a channel gets at most
20 messages an hour. When the limit holds messages back, one message
later says how many were not sent.

## When there is no network

Messages that cannot be sent wait in `notify-outbox.json` (readable by you
only, at most 100 messages, nothing older than 24 hours) and are tried again
after 30 seconds, then after longer and longer waits up to 30 minutes. They
also survive a restart of the service. A phone or a laptop that was offline
sends its alerts when the network is back.

The service sends the messages. A command you run in a terminal while no
service runs does not send any; the service reports what it sees.

## Troubleshooting

- Press "Test" (or run `varsto notify test CHANNEL`). The error text comes
  from the service itself.
- ntfy `HTTP 401` or `403`: the topic or server needs a login. Add an access
  token, or a user name and password, under "Use my own ntfy server".
- ntfy nothing arrives: the app must subscribe to the same topic on the same
  server. Check for a trailing space or a different server.
- Pushover `user identifier is invalid` or `application token is invalid`: the
  User Key and the API Token must be the long strings from pushover.net, not
  your e-mail address. The API Token belongs to the application you created.
- Telegram `chat not found`: send a message to the bot first, then press
  "Find my chat". A bot cannot start a conversation. For a group the bot must
  be a member.
- Telegram `Unauthorized`: the bot token is wrong or was revoked in
  @BotFather.
- "The last message could not be sent" under a channel shows the last error.
  The service tries again by itself.
- Nothing arrives for an event: check that the channel has it in its events
  (`varsto notify events CHANNEL`), and that the event happens on this device.
