# Security policy

Varsto is alpha software and the cryptography has not been independently audited. See the warning in [README.md](README.md).

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

TODO before the first public release: publish a dedicated security contact (and a PGP key or `security.txt`), define response times, and set up coordinated disclosure.

Until then, report privately to the repository owner through the hosting platform's private messaging.

## Scope

In scope: the core library, the CLI, the desktop and mobile apps, the storage format and protocols, the MCP server, the website and the release process.

## Threat model

The design-stage threat model is in [docs/architecture/threat-model.md](docs/architecture/threat-model.md). No implementation exists yet, so treat every guarantee as unproven.
