#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Fail unless the Rust core is inside the app executable:  check-exe.sh EXECUTABLE
# (a dylib reference to varsto_ffi, or a tiny executable, means it was not linked in).
set -euo pipefail
exe="${1:?usage: $0 EXECUTABLE}"
if otool -L "$exe" | grep -q varsto_ffi; then
  echo "FAIL: $exe links libvarsto_ffi as a dylib; the Rust core must be linked statically (libvarsto_ffi.a)" >&2
  otool -L "$exe" >&2
  exit 1
fi
size="$(wc -c < "$exe" | tr -d ' ')"
if [ "$size" -lt 1048576 ]; then
  echo "FAIL: $exe is only $size bytes; the Rust core (several MB) is not linked in" >&2
  exit 1
fi
if nm "$exe" 2>/dev/null | grep -q ' U _varsto_start$'; then
  echo "FAIL: _varsto_start is undefined in $exe" >&2
  exit 1
fi
echo "ok: $exe has the Rust core linked in ($size bytes, no varsto_ffi dylib)"
