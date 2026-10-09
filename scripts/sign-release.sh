#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Sign (or check) the release checksum list with the release key.
#
#   scripts/sign-release.sh [SHA256SUMS]            sign, writes SHA256SUMS.sig next to it
#   scripts/sign-release.sh --verify [SHA256SUMS]   check SHA256SUMS.sig against release-key.pub
#   scripts/sign-release.sh --public-key            print the public key file for the private key
#
# The default list is website/public/downloads/SHA256SUMS. Before signing,
# every file listed must be present next to the list with the listed SHA-256,
# so sign last, after every file (including a Mac-built disk image) is in.
#
# The signature is minisign-compatible (Ed25519 over the BLAKE2b-512 hash of
# the file, plus a signed trusted comment), so `minisign -Vm SHA256SUMS -p
# release-key.pub` verifies it as well as `varsto verify-release`. Signing
# uses OpenSSL 3 (LibreSSL lacks raw Ed25519); set OPENSSL to pick a binary.
#
# The private key is the maintainer's release key, kept offline: a PEM file
# (VARSTO_RELEASE_KEY) and its 8-byte key id in hex in the same place with
# the extension .id. See RELEASING.md.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
key="${VARSTO_RELEASE_KEY:-}"
pub="$root/release-key.pub"
mode=sign
case "${1:-}" in
  --verify) mode=verify; shift ;;
  --public-key) mode=public; shift ;;
  -h|--help) sed -n '3,20p' "$0"; exit 0 ;;
esac
sums="${1:-$root/website/public/downloads/SHA256SUMS}"

pick_openssl() {
  for o in "${OPENSSL:-}" openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    [ -n "$o" ] && command -v "$o" >/dev/null 2>&1 || continue
    "$o" version 2>/dev/null | grep -q '^OpenSSL [3-9]' && { echo "$o"; return; }
  done
  echo "OpenSSL 3 is required (macOS: brew install openssl@3)" >&2
  exit 1
}
ossl="$(pick_openssl)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

b64() { "$ossl" base64 -A; }
unb64() { "$ossl" base64 -d -A; }
hex2bin() { local h; h="$(tr -d ' \n' | sed 's/../\\x&/g')"; printf '%b' "$h"; }
bin2hex() { od -An -v -tx1 | tr -d ' \n'; }

# Public key file (minisign format): "Ed" || key id || 32-byte public key.
public_key() {
  [ -n "$key" ] && [ -f "$key" ] || { echo "no release key: set VARSTO_RELEASE_KEY to the private key file" >&2; exit 1; }
  local id; id="$(cat "${key%.pem}.id")"
  "$ossl" pkey -in "$key" -pubout -outform DER | tail -c 32 > "$tmp/pk"
  # Shown like minisign: the id as a little-endian number in hex.
  local shown; shown="$(printf '%s' "$id" | fold -w2 | awk '{a[NR]=$0} END {for (i = NR; i > 0; i--) printf "%s", toupper(a[i])}')"
  echo "untrusted comment: minisign public key $shown"
  { printf 'Ed'; printf '%s' "$id" | hex2bin; cat "$tmp/pk"; } | b64
  echo
}

verify() {
  [ -f "$sums.sig" ] || { echo "missing $sums.sig" >&2; return 1; }
  sed -n 2p "$pub" | unb64 > "$tmp/pub.bin"
  sed -n 2p "$sums.sig" | unb64 > "$tmp/sig.bin"
  sed -n 4p "$sums.sig" | unb64 > "$tmp/gsig.bin"
  local trusted; trusted="$(sed -n 3p "$sums.sig")"
  trusted="${trusted#trusted comment: }"
  [ "$(head -c 2 "$tmp/sig.bin")" = "ED" ] || { echo "not a prehashed (ED) signature" >&2; return 1; }
  [ "$(head -c 10 "$tmp/pub.bin" | tail -c 8 | bin2hex)" = "$(head -c 10 "$tmp/sig.bin" | tail -c 8 | bin2hex)" ] \
    || { echo "signed with a different key than release-key.pub" >&2; return 1; }
  # Ed25519 SubjectPublicKeyInfo: fixed DER prefix + the 32 key bytes.
  { printf '%b' '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; tail -c 32 "$tmp/pub.bin"; } > "$tmp/pub.der"
  tail -c 64 "$tmp/sig.bin" > "$tmp/s"
  "$ossl" dgst -blake2b512 -binary "$sums" > "$tmp/h"
  "$ossl" pkeyutl -verify -pubin -keyform DER -inkey "$tmp/pub.der" -rawin -in "$tmp/h" -sigfile "$tmp/s" >/dev/null \
    || { echo "BAD signature on $sums" >&2; return 1; }
  { cat "$tmp/s"; printf '%s' "$trusted"; } > "$tmp/g"
  "$ossl" pkeyutl -verify -pubin -keyform DER -inkey "$tmp/pub.der" -rawin -in "$tmp/g" -sigfile "$tmp/gsig.bin" >/dev/null \
    || { echo "BAD signature on the trusted comment of $sums.sig" >&2; return 1; }
  echo "good signature: $sums ($trusted)"
}

case "$mode" in
  public) public_key; exit 0 ;;
  verify) verify; exit $? ;;
esac

[ -f "$sums" ] || { echo "no $sums" >&2; exit 1; }
[ -n "$key" ] && [ -f "$key" ] || { echo "no release key (set VARSTO_RELEASE_KEY to the private key file); $sums stays unsigned" >&2; exit 1; }
dir="$(cd "$(dirname "$sums")" && pwd)"
# Everything listed must be here and match; anything unlisted is reported.
(cd "$dir" && sha256sum --version >/dev/null 2>&1 && sha256sum -c --quiet "$(basename "$sums")") \
  || (cd "$dir" && shasum -a 256 -c --quiet "$(basename "$sums")") \
  || { echo "files do not match $sums; not signing" >&2; exit 1; }
for f in "$dir"/*; do
  n="$(basename "$f")"
  case "$n" in SHA256SUMS|SHA256SUMS.sig|manifest.json|release-key.pub) continue ;; esac
  grep -q "  $n\$" "$sums" || echo "note: $n is not listed in $(basename "$sums") (not covered by the signature)" >&2
done
[ "$(public_key)" = "$(cat "$pub")" ] || { echo "the key at $key does not match release-key.pub" >&2; exit 1; }

version="$(grep -m1 '^version' "$root/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
trusted="$(printf 'timestamp:%s\tfile:%s\tversion:%s' "$(date +%s)" "$(basename "$sums")" "$version")"
"$ossl" dgst -blake2b512 -binary "$sums" > "$tmp/h"
"$ossl" pkeyutl -sign -inkey "$key" -rawin -in "$tmp/h" -out "$tmp/s"
{ cat "$tmp/s"; printf '%s' "$trusted"; } > "$tmp/g"
"$ossl" pkeyutl -sign -inkey "$key" -rawin -in "$tmp/g" -out "$tmp/gs"
{
  echo "untrusted comment: signature from the Varsto release key"
  { printf 'ED'; cat "${key%.pem}.id" | hex2bin; cat "$tmp/s"; } | b64; echo
  echo "trusted comment: $trusted"
  b64 < "$tmp/gs"; echo
} > "$sums.sig.new"
mv "$sums.sig.new" "$sums.sig"
verify
