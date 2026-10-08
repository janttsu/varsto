#!/usr/bin/env bash
# Shared helpers for scripts/test/*.sh. Source this file; do not execute it.
# shellcheck shell=bash
# shellcheck disable=SC2034  # variables are used by the scripts that source this file

# Exit codes shared by all scripts:
#   0 success / suite passed, 1 suite failed, 2 usage error or not implemented,
#   3 environment problem (missing tool, download or libvirt failure).
EXIT_USAGE=2
EXIT_ENV=3

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LIBVIRT_URI="${VARSTO_LIBVIRT_URI:-qemu:///system}"
POOL="${VARSTO_POOL:-default}"
CACHE_DIR="${VARSTO_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/varsto-test}"
RESULTS_DIR="${VARSTO_RESULTS_DIR:-$REPO_ROOT/test-results}"
VM_PREFIX="varsto-test-"
SSH_USER="varsto"
DRY_RUN=0

log() { printf '%s\n' "$*" >&2; }
die() { local code="$1"; shift; log "$(basename "$0"): $*"; exit "$code"; }

# Strip --dry-run from the arguments. Call as: parse_common_flags "$@"; set -- "${ARGS[@]}"
parse_common_flags() {
  ARGS=()
  local a
  for a in "$@"; do
    case "$a" in
      --dry-run) DRY_RUN=1 ;;
      *) ARGS+=("$a") ;;
    esac
  done
}

# Run a command, or only print it with --dry-run.
run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

# virsh bound to the configured connection.
virsh_() { run virsh -q -c "$LIBVIRT_URI" "$@"; }

need_tools() {
  local missing=() t
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    if [ "$DRY_RUN" = 1 ]; then
      log "note: missing tools (would fail without --dry-run): ${missing[*]}"
    else
      die "$EXIT_ENV" "missing required tools: ${missing[*]} (see TESTING.md, Prerequisites)"
    fi
  fi
}

# Image table. The distro names and architectures must exist in tests/matrix.yaml;
# only debian-stable x86_64 is implemented so far.
# Sets IMAGE_URL, CHECKSUM_URL, IMAGE_FILE for the given distro name.
lookup_image() {
  case "$1" in
    debian-stable)
      IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
      CHECKSUM_URL="https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS"
      IMAGE_FILE="debian-13-genericcloud-amd64.qcow2"
      ;;
    ubuntu-lts | fedora | arch | alpine)
      die "$EXIT_USAGE" "distro '$1' is in tests/matrix.yaml but its image is not implemented yet"
      ;;
    *)
      die "$EXIT_USAGE" "unknown distro '$1' (known: debian-stable)"
      ;;
  esac
  if ! grep -q "name: $1," "$REPO_ROOT/tests/matrix.yaml"; then
    die "$EXIT_USAGE" "distro '$1' is not listed in tests/matrix.yaml"
  fi
}

vm_state_dir() { printf '%s/vms/%s' "$CACHE_DIR" "$1"; }

# Only ever touch resources this tooling created.
require_test_vm_name() {
  case "$1" in
    "$VM_PREFIX"*) ;;
    *)
      if [ "$DRY_RUN" = 1 ]; then
        log "note: '$1' does not start with '$VM_PREFIX'; a real run would refuse it"
      else
        die "$EXIT_USAGE" "refusing to touch '$1': test VM names start with '$VM_PREFIX'"
      fi
      ;;
  esac
}

utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
