#!/usr/bin/env bash
# Run a test suite inside a provisioned VM over SSH and write JUnit XML and JSON results.
# Only the "smoke" suite exists so far.
#
# Usage: run-suite.sh [--dry-run] <suite> <vm>
# Exit:  0 suite passed, 1 suite failed, 2 usage error or suite not implemented,
#        3 environment problem. Results: test-results/<vm>/<suite>.junit.xml and .json
set -uo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

parse_common_flags "$@"
set -- "${ARGS[@]+"${ARGS[@]}"}"
[ "$#" -eq 2 ] && [ "$1" != "-h" ] && [ "$1" != "--help" ] || {
  log "usage: $(basename "$0") [--dry-run] <suite> <vm>"
  exit "$EXIT_USAGE"
}
SUITE="$1"
VM="$2"
if [ "$SUITE" != smoke ]; then
  log "$(basename "$0"): suite '$SUITE' is not implemented yet (only: smoke)"
  exit "$EXIT_USAGE"
fi
require_test_vm_name "$VM"
need_tools ssh

STATE="$(vm_state_dir "$VM")"
OUT="$RESULTS_DIR/$VM"

if [ "$DRY_RUN" = 1 ]; then
  echo "+ mkdir -p $OUT"
  echo "+ ssh -i $STATE/id_ed25519 <user>@<vm-ip> <check>    # for each smoke test:"
  echo "+   ssh-login, os-release, cloud-init-finished, clock-sane, network-isolated"
  echo "+ (write $OUT/smoke.junit.xml and $OUT/smoke.json)"
  exit 0
fi

[ -f "$STATE/meta" ] || die "$EXIT_ENV" "no state for '$VM' under $STATE (was it provisioned with provision-vm.sh?)"
VM_IP="$(sed -n 's/^ip=//p' "$STATE/meta")"
VM_USER="$(sed -n 's/^user=//p' "$STATE/meta")"
mkdir -p "$OUT"

vm_ssh() {
  ssh -i "$STATE/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 \
    "$VM_USER@$VM_IP" "$@"
}

xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }
json_escape() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n\t\r' '   '; }

STARTED="$(utc_now)"
COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
TESTS=()   # entries: name|status|seconds|message
FAILED=0

# check <name> <remote command...>: pass when the remote command exits 0.
check() {
  local name="$1" msg rc t0 t1
  shift
  t0=$SECONDS
  msg="$(vm_ssh "$@" 2>&1)"
  rc=$?
  t1=$SECONDS
  if [ "$rc" -eq 0 ]; then
    TESTS+=("$name|pass|$((t1 - t0))|")
  else
    FAILED=$((FAILED + 1))
    TESTS+=("$name|fail|$((t1 - t0))|exit $rc: $msg")
  fi
}

check ssh-login true
# shellcheck disable=SC2016  # the command is evaluated on the VM, not here
check os-release '. /etc/os-release && test -n "$ID"'
check cloud-init-finished 'cloud-init status --wait >/dev/null'
# shellcheck disable=SC2016
check clock-sane 'test "$(date +%s)" -gt 1700000000'
# The test network has no route out; a connection attempt must fail.
check network-isolated '! timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/53" 2>/dev/null'

FINISHED="$(utc_now)"
TOTAL=${#TESTS[@]}
if [ "$FAILED" -eq 0 ]; then RESULT=pass; else RESULT=fail; fi

{
  printf '<?xml version="1.0" encoding="UTF-8"?>\n'
  printf '<testsuite name="smoke" tests="%d" failures="%d" timestamp="%s">\n' "$TOTAL" "$FAILED" "$STARTED"
  for t in "${TESTS[@]}"; do
    IFS='|' read -r name status secs message <<<"$t"
    printf '  <testcase classname="smoke" name="%s" time="%s">' "$name" "$secs"
    if [ "$status" = fail ]; then
      printf '<failure message="%s"/>' "$(printf '%s' "$message" | xml_escape)"
    fi
    printf '</testcase>\n'
  done
  printf '</testsuite>\n'
} > "$OUT/smoke.junit.xml"

{
  printf '{"suite":"smoke","vm":"%s","commit":"%s","result":"%s","started_utc":"%s","finished_utc":"%s","tests":[' \
    "$VM" "$COMMIT" "$RESULT" "$STARTED" "$FINISHED"
  sep=""
  for t in "${TESTS[@]}"; do
    IFS='|' read -r name status secs message <<<"$t"
    printf '%s{"name":"%s","status":"%s","seconds":%s,"message":"%s"}' \
      "$sep" "$name" "$status" "$secs" "$(printf '%s' "$message" | json_escape)"
    sep=","
  done
  printf ']}\n'
} > "$OUT/smoke.json"

log "smoke: $RESULT ($((TOTAL - FAILED))/$TOTAL passed); results in $OUT"
[ "$FAILED" -eq 0 ]
