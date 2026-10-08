#!/usr/bin/env bash
# Copy /var/log and result files from a test VM to test-results/<vm>/.
#
# Usage: collect-logs.sh [--dry-run] <vm>
# Exit:  0 ok, 2 usage error, 3 environment problem (VM unreachable).
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
need_tools ssh

STATE="$(vm_state_dir "$VM")"
OUT="$RESULTS_DIR/$VM"

if [ "$DRY_RUN" = 1 ]; then
  echo "+ mkdir -p $OUT"
  echo "+ ssh -i $STATE/id_ed25519 <user>@<vm-ip> sudo tar czf - /var/log > $OUT/var-log.tar.gz"
  echo "+ ssh -i $STATE/id_ed25519 <user>@<vm-ip> tar czf - results > $OUT/vm-results.tar.gz   # if present"
  echo "+ list local result files in $OUT"
  exit 0
fi

[ -f "$STATE/meta" ] || die "$EXIT_ENV" "no state for '$VM' under $STATE"
VM_IP="$(sed -n 's/^ip=//p' "$STATE/meta")"
VM_USER="$(sed -n 's/^user=//p' "$STATE/meta")"
mkdir -p "$OUT"

vm_ssh() {
  ssh -i "$STATE/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 \
    "$VM_USER@$VM_IP" "$@"
}

vm_ssh 'sudo tar czf - /var/log 2>/dev/null' > "$OUT/var-log.tar.gz" ||
  die "$EXIT_ENV" "could not copy /var/log from $VM"
if vm_ssh 'test -d results'; then
  vm_ssh 'tar czf - results' > "$OUT/vm-results.tar.gz" || log "warning: could not copy ~/results"
fi

log "collected into $OUT:"
ls -1 "$OUT" >&2
