# Releasing Varsto

How a release is built, signed and published, and how clients check it.

## Signed releases

Every release publishes, next to the archives on the download page:

- `SHA256SUMS`: the SHA-256 of every file of the release;
- `SHA256SUMS.sig`: a detached signature of `SHA256SUMS` made with the Varsto
  release key;
- `manifest.json`: version and per-file notes for the download table (not
  signed; the updater only trusts what `SHA256SUMS` vouches for).

The signature is in [minisign](https://jedisct1.github.io/minisign/) format:
Ed25519 over the BLAKE2b-512 hash of `SHA256SUMS` (the "ED" prehashed
algorithm), plus a signed trusted comment
`timestamp:<unix time> file:SHA256SUMS version:<version>`.

The **public key** is in [`release-key.pub`](release-key.pub), built into every
`varsto` binary (`crates/varsto-cli/src/update.rs`) and shown on the download
page:

```
untrusted comment: minisign public key 2861CE1D220B07F3
RWTzBwsiHc5hKJfkPOF6AQQWdIOHE1jf/UMs/GUCoOqocAJftz915FBF
```

The **private key** is the maintainer's release key, kept offline: never in
this repository, in CI or on the web server. It is an OpenSSL Ed25519 PEM
file plus its 8-byte key id in hex (same name, extension `.id`), handed to the
signing script with `VARSTO_RELEASE_KEY=/path/to/release-key.pem`. Signing
needs OpenSSL 3 (on macOS: `brew install openssl@3`; LibreSSL cannot do raw
Ed25519).

### What `varsto update` checks

1. `manifest.json` names the latest version and the archive for this platform
   (`varsto-<version>-<target>.tar.gz` or `.zip`).
2. `SHA256SUMS.sig` must verify against the built-in public key, and its
   trusted comment must name that same version (an old signed list cannot be
   replayed for a newer version). No signature, a bad one or another key:
   the update is refused.
3. The archive must be listed in the signed `SHA256SUMS`.
4. Second channel: `https://github.com/janttsu/varsto/releases/download/v<version>/SHA256SUMS`
   is fetched. If it can be fetched, it must list the archive with the same
   checksum, otherwise the update is refused. If GitHub cannot be reached (or
   the release has no `SHA256SUMS` yet), the signature alone suffices; the
   message says which happened.
5. The downloaded archive must have the signed SHA-256. Only then is the
   binary replaced.

Users check a download by hand with `varsto verify-release <file>` (it uses
`SHA256SUMS` and `SHA256SUMS.sig` next to the file, or fetches them; add
`--github` to compare with the GitHub release too), or with minisign:

```
minisign -Vm SHA256SUMS -x SHA256SUMS.sig -P RWTzBwsiHc5hKJfkPOF6AQQWdIOHE1jf/UMs/GUCoOqocAJftz915FBF
sha256sum -c --ignore-missing SHA256SUMS
```

Clients up to 0.0.1-alpha.8 check only the checksum; from the first release
with this code on, every published `SHA256SUMS` must be signed or those
clients refuse to update.

## Download site

The update base URL is one constant, `DEFAULT_SITE` in
`crates/varsto-cli/src/update.rs`: `https://varsto.net` (downloads under
`/downloads/`). `VARSTO_UPDATE_URL` overrides it (a mirror or a test server;
the signature check is the same). The old address, `https://varsto.soderlund.in`,
keeps serving `/downloads/` for clients built before the move.

## Steps

1. Bump `version` in `Cargo.toml`, commit, tag `v<version>`, push the tag. CI
   builds the macOS disk image and attaches it to a draft GitHub release.
2. Build the archives: `website/build-release.sh` (Linux, Windows, source; the
   cross-compiled macOS command line when cargo-zigbuild is installed). With
   the release key available it signs `SHA256SUMS` at the end; otherwise it
   says so and the list stays unsigned.
3. Add the Mac disk image (from a Mac build or the CI artifact) with
   `website/publish-macos.sh Varsto-<version>-macos.dmg`: it adds the image to
   `SHA256SUMS`, signs the final list, rebuilds the site and deploys. To add
   files by other means, run `scripts/sign-release.sh` last: it refuses to
   sign when a listed file is missing or differs, and notes files that are
   not listed.
4. Upload the signed list to the GitHub release (the second channel) and
   publish the release:
   `gh release upload v<version> website/public/downloads/SHA256SUMS website/public/downloads/SHA256SUMS.sig --clobber`
   Upload it again whenever the list on the site changes.
5. `website/deploy.sh` refuses to publish a `SHA256SUMS` whose signature does
   not verify against `release-key.pub` (`scripts/sign-release.sh --verify`).

## Rotating or losing the key

A new key needs a release signed with the old key that carries the new public
key; clients then trust only the new one. If the private key is lost, the
built-in key cannot be replaced remotely: users must download a new build by
hand and check it through another channel (the GitHub repository's
`release-key.pub` and release checksums). If it leaks, publish a notice on the
site and GitHub, and ship a release that changes the key as early as possible.
