#!/usr/bin/env bash
# Validate data/providers/*.json against data/providers/schema.json and warn about stale prices.
#
# Usage: validate-providers.sh [--max-age-days N] [--fail-on-stale] [profile.json ...]
# Without file arguments every profile in data/providers/ is checked.
# Exit:  0 valid (stale warnings do not fail unless --fail-on-stale), 1 invalid or stale with
#        --fail-on-stale, 2 usage error or no validator installed.
#
# Validator, first one found wins: check-jsonschema, ajv (ajv-cli), python3 with the jsonschema package.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCHEMA="$ROOT/data/providers/schema.json"
MAX_AGE=90
FAIL_STALE=0
FILES=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --max-age-days) MAX_AGE="${2:-}"; shift 2 || { echo "missing value for --max-age-days" >&2; exit 2; } ;;
    --fail-on-stale) FAIL_STALE=1; shift ;;
    -h | --help) sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) FILES+=("$1"); shift ;;
  esac
done
case "$MAX_AGE" in '' | *[!0-9]*) echo "--max-age-days needs a whole number" >&2; exit 2 ;; esac

if [ "${#FILES[@]}" -eq 0 ]; then
  for f in "$ROOT"/data/providers/*.json; do
    [ "$(basename "$f")" = schema.json ] || FILES+=("$f")
  done
fi
[ "${#FILES[@]}" -gt 0 ] || { echo "no profiles found" >&2; exit 2; }

install_help() {
  cat >&2 <<'HELP'
No JSON Schema validator found. Install one of:
  pipx install check-jsonschema            # preferred
  npm install -g ajv-cli ajv-formats       # alternative
  python3 -m pip install --user jsonschema # fallback (python3 -m venv works too)
HELP
}

rc=0
if command -v check-jsonschema >/dev/null 2>&1; then
  echo "validator: check-jsonschema"
  check-jsonschema --schemafile "$SCHEMA" "${FILES[@]}" || rc=1
elif command -v ajv >/dev/null 2>&1; then
  echo "validator: ajv"
  for f in "${FILES[@]}"; do
    ajv validate --spec=draft2020 -c ajv-formats --strict=false -s "$SCHEMA" -d "$f" || rc=1
  done
elif command -v python3 >/dev/null 2>&1 && python3 -I -c 'import jsonschema' >/dev/null 2>&1; then
  echo "validator: python3 jsonschema"
  python3 -I - "$SCHEMA" "${FILES[@]}" <<'PY' || rc=1
import json, sys
from jsonschema import Draft202012Validator, FormatChecker

schema = json.load(open(sys.argv[1]))
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema, format_checker=FormatChecker())
bad = 0
for path in sys.argv[2:]:
    errors = sorted(validator.iter_errors(json.load(open(path))), key=lambda e: list(e.absolute_path))
    if errors:
        bad += 1
        print(f"{path}: INVALID")
        for e in errors:
            where = "/".join(str(p) for p in e.absolute_path) or "(root)"
            print(f"  {where}: {e.message[:200]}")
    else:
        print(f"{path}: ok")
sys.exit(1 if bad else 0)
PY
else
  install_help
  exit 2
fi

# Age check: needs only python3 from the standard library.
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -I - "$MAX_AGE" "$FAIL_STALE" "${FILES[@]}" <<'PY'
import datetime, json, sys

max_age, fail_stale = int(sys.argv[1]), sys.argv[2] == "1"
today = datetime.datetime.now(datetime.timezone.utc).date()
stale = 0

def walk(node, path, out):
    if isinstance(node, dict):
        v = node.get("last_verified")
        if isinstance(v, str):
            out.append((path, v))
        for k, child in node.items():
            walk(child, path + [k], out)
    elif isinstance(node, list):
        for i, child in enumerate(node):
            walk(child, path + [i], out)

for path in sys.argv[3:]:
    found = []
    walk(json.load(open(path)), [], found)
    for where, value in found:
        try:
            age = (today - datetime.date.fromisoformat(value)).days
        except ValueError:
            continue
        if age > max_age:
            stale += 1
            print(f"WARNING {path}: /{'/'.join(map(str, where))} last verified {value} ({age} days ago, limit {max_age})")
print(f"stale entries: {stale}")
sys.exit(1 if (stale and fail_stale) else 0)
PY
  then
    rc=1
  fi
else
  echo "note: python3 not found; skipped the age check" >&2
fi
exit "$rc"
