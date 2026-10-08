# Contributing

Thanks for your interest. Varsto is pre-alpha and the contribution process is still being defined.

## Rules that already apply

- **Language:** everything in this repository is written in English: code comments, identifiers, commit messages, issues, pull requests and documentation.
- **No personal data.** Never commit real personal data, real file names, real device or server names, credentials, keys or addresses. Test fixtures must be invented and generic (for example `IMG_0001.jpg`, `laptop`, `usb-a`, `cloud`).
- **No secrets.** Do not commit credentials, tokens, private keys or recovery phrases.
- **Tests.** New behaviour needs tests. See [TESTING.md](TESTING.md).
- **Security first.** Do not implement your own cryptographic primitives. Use reviewed libraries and document every choice.
- **One name in one place.** The product name lives in `brand/brand.toml`; do not hard-code it where it can be avoided, because the working name may change.

## Licence of contributions

The project is licensed under the PolyForm Shield License 1.0.0. By contributing you agree that your contribution may be distributed under that licence and relicensed by the project. The exact mechanism (Developer Certificate of Origin sign-off or a Contributor Licence Agreement) is not decided yet; until it is, please open an issue before sending large changes.

## Workflow

1. Create a branch from `main`.
2. Keep commits small and described in the imperative mood.
3. Open a pull request and describe what changed and why.
