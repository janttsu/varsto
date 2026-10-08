# Runbook for AI agents that run tests

You are an agent asked to run Varsto's tests. Follow this exactly.

## Safety rules (always)

1. Work **only** inside disposable VMs or containers created for this run. Never touch the host's files, other VMs or real user accounts.
2. **No real data and no real credentials.** Use the generated test data and the test credentials provided by the scripts. Never print secrets.
3. Respect the time and resource limits in `tests/matrix.yaml`. If a limit is exceeded, stop and report.
4. **Do not change production code, tests or configuration** unless the task explicitly says so. Report failures; do not fix them.
5. Always clean up: destroy every VM and container you created, even when something failed. Report anything you could not remove.
6. If a result is ambiguous or you suspect a security issue, stop and escalate in the report instead of deciding yourself.

## Steps

1. **Preflight.** Check required tools (see TESTING.md), free disk space and that virtualisation is available. Record versions and the git commit under test.
2. **Provision.** `scripts/test/provision-vm.sh <distro>` for each distro in the chosen suite. It prints the VM name on stdout; keep it for the next steps. Exit code 3 means an environment problem: report it and stop.
3. **Run.** `scripts/test/run-suite.sh <suite> <vm>`. Capture the exit code (0 pass, 1 fail, 2 usage or not implemented, 3 environment problem), JUnit XML and JSON results from `test-results/<vm>/`.
4. **Collect.** `scripts/test/collect-logs.sh <vm>`.
5. **Reproduce failures.** For tests that print a seed, re-run once with the same seed to confirm the failure is reproducible.
6. **Report.** Fill in `docs/testing/report-template.md` (Markdown plus JSON). For each failure include: test name, seed, minimal reproduction steps, log excerpt and a suspected cause (label guesses as guesses).
7. **Clean up.** `scripts/test/destroy-vm.sh <vm>` for every VM.

## What to escalate

Anything involving: keys or secrets appearing in logs, data loss in a test that should not lose data, results that differ between identical runs without a seed explanation, or anything you are not sure is safe.
