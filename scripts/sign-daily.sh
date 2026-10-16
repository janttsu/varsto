#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Sign (or check) the checksum list of a DAILY build with the daily key.
#
#   scripts/sign-daily.sh --build-id ID [SHA256SUMS]   sign: writes SHA256SUMS.sig next to the list
#   scripts/sign-daily.sh --verify [SHA256SUMS]        check the signature against daily-key.pub
#   scripts/sign-daily.sh --public-key                 print the public key file for the private key
#
# The daily channel (https://varsto.net/daily/) has its own key, separate from
# the release key: `varsto update --daily` trusts daily-key.pub only for the
# daily channel and `varsto update` (stable) never accepts it. The list is the
# one served as daily/latest/SHA256SUMS (stable file names, varsto-daily-*);
# its signature is daily/latest/SHA256SUMS.sig. The signed trusted comment is
#
#   timestamp:<epoch seconds>  file:SHA256SUMS  channel:daily  build:<build id>
#
# (tab separated). The updater refuses a list whose signing time goes backwards
# or is old, whose build is older than the installed one, or that lacks
# channel:daily. The format is minisign-compatible (Ed25519 over the BLAKE2b-512
# hash of the file plus a signed trusted comment); OpenSSL 3 is needed, set
# OPENSSL to pick a binary.
#
# The private key is a PEM file (VARSTO_DAILY_KEY, default
# ~/.config/varsto-release/daily-key.pem) with its 8-byte key id in hex beside
# it (daily-key.id). It never goes into the repository; see docs/daily-channel.md.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
key="${VARSTO_DAILY_KEY:-$HOME/.config/varsto-release/daily-key.pem}"
pub="$root/daily-key.pub"
mode=sign
build=""
while [ $# -gt 0 ]; do
  case "$1" in
    --verify) mode=verify; shift ;;
    --public-key) mode=public; shift ;;
    --build-id) build="${2:?--build-id needs a value}"; shift 2 ;;
    -h|--help) sed -n '3,25p' "$0"; exit 0 ;;
    *) break ;;
  esac
done
sums="${1:-SHA256SUMS}"

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
  [ -f "$key" ] || { echo "no daily key at $key (set VARSTO_DAILY_KEY)" >&2; exit 1; }
  local id; id="$(tr -d ' \n' < "${key%.pem}.id")"
  "$ossl" pkey -in "$key" -pubout -outform DER | tail -c 32 > "$tmp/pk"
  # Shown like minisign: the id as a little-endian number in hex.
  local shown; shown="$(printf '%s' "$id" | fold -w2 | awk '{a[NR]=$0} END {for (i = NR; i > 0; i--) printf "%s", toupper(a[i])}')"
  echo "untrusted comment: minisign public key $shown"
  { printf 'Ed'; printf '%s' "$id" | hex2bin; cat "$tmp/pk"; } | b64
  echo
}

# verify_one FILE SIGFILE
verify_one() {
  local file="$1" sigf="$2"
  [ -f "$sigf" ] || { echo "missing $sigf" >&2; return 1; }
  sed -n 2p "$pub" | unb64 > "$tmp/pub.bin"
  sed -n 2p "$sigf" | unb64 > "$tmp/sig.bin"
  sed -n 4p "$sigf" | unb64 > "$tmp/gsig.bin"
  local trusted; trusted="$(sed -n 3p "$sigf")"
  trusted="${trusted#trusted comment: }"
  [ "$(head -c 2 "$tmp/sig.bin")" = "ED" ] || { echo "not a prehashed (ED) signature" >&2; return 1; }
  [ "$(head -c 10 "$tmp/pub.bin" | tail -c 8 | bin2hex)" = "$(head -c 10 "$tmp/sig.bin" | tail -c 8 | bin2hex)" ] \
    || { echo "signed with a different key than daily-key.pub" >&2; return 1; }
  # Ed25519 SubjectPublicKeyInfo: fixed DER prefix + the 32 key bytes.
  { printf '%b' '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; tail -c 32 "$tmp/pub.bin"; } > "$tmp/pub.der"
  tail -c 64 "$tmp/sig.bin" > "$tmp/s"
  "$ossl" dgst -blake2b512 -binary "$file" > "$tmp/h"
  "$ossl" pkeyutl -verify -pubin -keyform DER -inkey "$tmp/pub.der" -rawin -in "$tmp/h" -sigfile "$tmp/s" >/dev/null \
    || { echo "BAD signature on $file" >&2; return 1; }
  { cat "$tmp/s"; printf '%s' "$trusted"; } > "$tmp/g"
  "$ossl" pkeyutl -verify -pubin -keyform DER -inkey "$tmp/pub.der" -rawin -in "$tmp/g" -sigfile "$tmp/gsig.bin" >/dev/null \
    || { echo "BAD signature on the trusted comment of $sigf" >&2; return 1; }
  case "$trusted" in *"channel:daily"*) ;; *) echo "the signature is not for the daily channel" >&2; return 1 ;; esac
  echo "good signature: $file ($trusted)"
}

# sign_one FILE SIGFILE: the minisign-compatible signature of FILE.
sign_one() {
  local file="$1" sigf="$2" trusted
  trusted="$(printf 'timestamp:%s\tfile:%s\tchannel:daily\tbuild:%s' "$(date +%s)" "$(basename "$file")" "$build")"
  "$ossl" dgst -blake2b512 -binary "$file" > "$tmp/h"
  "$ossl" pkeyutl -sign -inkey "$key" -rawin -in "$tmp/h" -out "$tmp/s"
  { cat "$tmp/s"; printf '%s' "$trusted"; } > "$tmp/g"
  "$ossl" pkeyutl -sign -inkey "$key" -rawin -in "$tmp/g" -out "$tmp/gs"
  {
    echo "untrusted comment: signature from the Varsto daily key"
    { printf 'ED'; tr -d ' \n' < "${key%.pem}.id" | hex2bin; cat "$tmp/s"; } | b64; echo
    echo "trusted comment: $trusted"
    b64 < "$tmp/gs"; echo
  } > "$sigf.new"
  mv "$sigf.new" "$sigf"
}

case "$mode" in
  public) public_key; exit 0 ;;
  verify) verify_one "$sums" "$sums.sig"; exit $? ;;
esac

[ -f "$sums" ] || { echo "no $sums" >&2; exit 1; }
[ -f "$key" ] || { echo "no daily key at $key (set VARSTO_DAILY_KEY); $sums stays unsigned" >&2; exit 1; }
printf '%s' "$build" | grep -Eq '^[0-9]{8}-[0-9a-f]{7,40}$' \
  || { echo "--build-id must look like 20261016-316c579" >&2; exit 1; }
# Only the stable daily names with a SHA-256 each: nothing else is signed.
if grep -Evq '^[0-9a-f]{64}  varsto-daily-[A-Za-z0-9._-]+$' "$sums"; then
  echo "$sums must list only varsto-daily-* files with SHA-256 sums" >&2
  exit 1
fi
[ "$(public_key)" = "$(cat "$pub")" ] || { echo "the key at $key does not match daily-key.pub" >&2; exit 1; }
sign_one "$sums" "$sums.sig"
verify_one "$sums" "$sums.sig"
