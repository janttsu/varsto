#!/usr/bin/env bash
# Destroy a test VM: stop and undefine the domain, remove its network, disks and local state.
# Always succeeds if the VM is already gone.
#
# Usage: destroy-vm.sh [--dry-run] <vm>
# Exit:  0 ok (including "already gone"), 2 usage error.
set -uo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

parse_common_flags "$@"
set -- "${ARGS[@]+"${ARGS[@]}"}"
[ "$#" -eq 1 ] && [ "$1" != "-h" ] && [ "$1" != "--help" ] || {
  log "usage: $(basename "$0") [--dry-run] <vm>"
  exit "$EXIT_USAGE"
}
VM="$1"
require_test_vm_name "$VM"
need_tools virsh

STATE="$(vm_state_dir "$VM")"

# Individual failures are expected when a resource is already gone; keep going.
v() { virsh_ "$@" >/dev/null 2>&1 || true; }
if [ "$DRY_RUN" = 1 ]; then v() { virsh_ "$@"; }; fi

v destroy "$VM"
v undefine "$VM" --nvram
v net-destroy "$VM"
v net-undefine "$VM"
v vol-delete --pool "$POOL" "${VM}.qcow2"
v vol-delete --pool "$POOL" "${VM}-seed.iso"
if [ "$DRY_RUN" = 1 ]; then
  echo "+ rm -rf $STATE"
else
  rm -rf "$STATE"
fi
log "destroyed $VM (or it was already gone)"
exit 0
