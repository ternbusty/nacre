#!/usr/bin/env bash
# scripts/runc-selinux-test.sh — Run runc's SELinux bats tests against nacre
# on a host with SELinux enforcing (CI runs it inside a Fedora Lima VM).
#
# These tests are [skip]ped in scripts/runc_test_pattern because the regular
# CI runners have no SELinux. Here, a skip means SELinux was not actually
# exercised, so any skipped test counts as a failure.
#
# Usage (as root):
#   scripts/runc-selinux-test.sh --runc-dir DIR [--nacre-dir DIR]
#
# DIR must be a runc checkout (the tag in scripts/runc-version) with test
# helpers built ("make test-binaries") and images fetched (get-images.sh).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNC_REPO_DIR=""
NACRE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TAP_OUTPUT="${TAP_OUTPUT:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runc-dir)  RUNC_REPO_DIR="$2"; shift 2 ;;
    --nacre-dir) NACRE_DIR="$2"; shift 2 ;;
    *)           echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$RUNC_REPO_DIR" ]] || { echo "ERROR: --runc-dir is required" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }
if ! selinuxenabled; then
  echo "ERROR: SELinux is not enabled on this host" >&2
  exit 1
fi

cd "$RUNC_REPO_DIR"

# selinux.bats copies $RUNC next to the bundle and relabels the copy, so the
# runtime must be a single self-contained file: point it at nacre by
# absolute path instead of using nacre-wrapper (which looks for nacre next
# to itself).
cat > runc <<EOF
#!/bin/bash
export _NACRE_BINARY_NAME=runc
exec perl "$NACRE_DIR/nacre" "\$@"
EOF
chmod +x runc

TMPOUT="$(mktemp)"
rc=0
{
  bats -t tests/integration/selinux.bats || rc=$?
  bats -t -f '^userns join other container userns\[selinux enabled\]$' \
    tests/integration/userns.bats || rc=$?
} > "$TMPOUT" 2>&1
cat "$TMPOUT"
if [[ -n "$TAP_OUTPUT" ]]; then
  cp "$TMPOUT" "$TAP_OUTPUT"
  chmod 644 "$TAP_OUTPUT"    # mktemp's 0600 would keep CI from fetching it
fi

pass=$(grep -Ec '^ok [0-9]+ ' "$TMPOUT" || true)
skip=$(grep -Ec '^ok [0-9]+ .* # skip' "$TMPOUT" || true)
fail=$(grep -Ec '^not ok [0-9]+ ' "$TMPOUT" || true)
pass=$((pass - skip))
rm -f "$TMPOUT"

echo ""
echo "SELinux bats: pass=$pass fail=$fail skip=$skip (bats rc=$rc)"
if [[ $fail -gt 0 || $skip -gt 0 || $rc -ne 0 || $pass -eq 0 ]]; then
  exit 1
fi
