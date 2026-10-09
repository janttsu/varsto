# Forum

Flarum (a lightweight, well-maintained PHP forum) with MariaDB in Docker on the
website host, published by the host's Caddy at https://forum.varsto.net.
Chosen over Discourse because the host has about 1 GB of free memory and
Discourse needs two; over a static "forum" because real threads need accounts,
moderation and search, which Flarum gives for free. Alternatives kept in mind:
GitHub Discussions (the repository is not on GitHub) and a Matrix room (chat,
not a forum).

Files: `docker-compose.yml`, `.env` (secrets, generated, never committed; see
`.env.example`), `forum.caddy` (Caddy site block). Data lives in `./data`
(assets, extensions, logs, mariadb).

Bring it up (on the host, in ~/forum):

    docker compose up -d                 # first start creates the admin account from .env
    docker compose logs -f flarum        # until "ready"
    cp ~/forum/forum.caddy ~/caddy-sites/forum.caddy && ~/bin/caddy reload --config ~/Caddyfile

Before that, add the DNS record `forum.varsto.net A <server ip>` at the
registrar. After the first login change the admin password (in .env for the
record), set the forum language, create the first discussions (Announcements,
Help, Ideas, Bug reports) and enable the built-in extensions you want (tags,
mentions, markdown, suspend, flags). Updates: `docker compose pull && docker
compose up -d`. Backups: `./data` plus `.env`.
