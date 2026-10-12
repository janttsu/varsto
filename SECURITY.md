# Security policy

Varsto is alpha software and the cryptography has not been independently audited. See the warning in [README.md](README.md).

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

TODO before the first public release: publish a dedicated security contact (and a PGP key or `security.txt`), define response times, and set up coordinated disclosure.

Until then, report privately to the repository owner through the hosting platform's private messaging.

## Scope

In scope: the core library, the CLI, the desktop and mobile apps, the storage format and protocols, the MCP server, the website and the release process.

## Threat model

The threat model in [docs/architecture/threat-model.md](docs/architecture/threat-model.md) is a design-stage model written before the code; much of it is now implemented as 0.0.1-alpha.9, and its per-row status notes and [docs/spec/alpha-0-format.md](docs/spec/alpha-0-format.md) record what is built. Nothing has been audited, so treat every guarantee as unproven.
