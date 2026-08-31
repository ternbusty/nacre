#!/usr/bin/env bash
# scripts/runc-compat-test.sh — Run runc bats integration tests against nacre
# using a per-test-name whitelist (pattern file).
#
# Usage:
#   sudo ./scripts/runc-compat-test.sh [--runc-dir DIR] [--binary PATH] \
#                                      [--pattern FILE]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RUNC_TAG="${RUNC_TAG:-v1.5.1}"
RUNC_REPO_DIR="${RUNC_REPO_DIR:-}"
NACRE_BIN="${NACRE_BIN:-${PROJECT_ROOT}/nacre-wrapper}"
SUMMARY_FILE="${SUMMARY_FILE:-}"
TAP_OUTPUT="${TAP_OUTPUT:-}"
PATTERN_FILE="${PROJECT_ROOT}/scripts/runc_test_pattern"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runc-dir)  RUNC_REPO_DIR="$2"; shift 2 ;;
    --binary)    NACRE_BIN="$2"; shift 2 ;;
    --pattern)   PATTERN_FILE="$2"; shift 2 ;;
    *)           echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ ! -f "$PATTERN_FILE" ]]; then
  echo "ERROR: pattern file not found: $PATTERN_FILE" >&2
  exit 1
fi

if ! command -v bats >/dev/null 2>&1; then
  echo "ERROR: bats not found. Install bats-core first." >&2
  exit 1
fi

# Clone runc if needed
if [[ -z "$RUNC_REPO_DIR" ]]; then
  RUNC_REPO_DIR="$(mktemp -d)"
  echo ">>> Cloning runc ${RUNC_TAG} into ${RUNC_REPO_DIR} ..."
  git clone --depth 1 --branch "$RUNC_TAG" \
    https://github.com/opencontainers/runc "$RUNC_REPO_DIR"
fi

INTEGRATION_DIR="${RUNC_REPO_DIR}/tests/integration"
if [[ ! -d "$INTEGRATION_DIR" ]]; then
  echo "ERROR: ${INTEGRATION_DIR} not found" >&2
  exit 1
fi

# Copy nacre wrapper as "runc" into the runc tree, along with the nacre Perl
# script (the wrapper resolves the script relative to its own location via
# BASH_SOURCE, so both files must be co-located).
NACRE_SCRIPT_DIR="$(cd "$(dirname "$NACRE_BIN")" && pwd)"
cp "$NACRE_BIN" "$RUNC_REPO_DIR/runc"
cp "$NACRE_SCRIPT_DIR/nacre" "$RUNC_REPO_DIR/nacre"
chmod +x "$RUNC_REPO_DIR/runc" "$RUNC_REPO_DIR/nacre"

# Fetch rootfs images
echo ">>> Fetching rootfs images ..."
chmod +x "${INTEGRATION_DIR}/get-images.sh"
"${INTEGRATION_DIR}/get-images.sh" >/dev/null

# Build runc test helper binaries
echo ">>> Building runc test helper binaries ..."
if make -C "$RUNC_REPO_DIR" test-binaries 2>/dev/null; then
  echo "    built via 'make test-binaries'"
else
  TESTBINDIR="${RUNC_REPO_DIR}/tests/cmd/_bin"
  mkdir -p "$TESTBINDIR"
  for helper in remap-rootfs fs-idmap seccompagent pidfd-kill recvtty; do
    helperdir="${RUNC_REPO_DIR}/tests/cmd/${helper}"
    if [[ -d "$helperdir" ]] && [[ ! -x "${TESTBINDIR}/${helper}" ]]; then
      echo "    building ${helper} ..."
      build_tags=""
      [[ "$helper" == "seccompagent" ]] && build_tags="-tags seccomp"
      # shellcheck disable=SC2086
      (cd "$helperdir" && go build $build_tags -o "${TESTBINDIR}/${helper}" .) || {
        echo "WARNING: failed to build ${helper}" >&2
      }
    fi
  done
fi

cd "$RUNC_REPO_DIR" || exit 1

if [[ -z "$TAP_OUTPUT" ]]; then
  TAP_OUTPUT="$(mktemp)"
fi
: > "$TAP_OUTPUT"

cleanup_stale_state() {
  # Safe cleanup: only remove nacre-specific paths
  [[ -d /run/nacre ]] && find /run/nacre -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
  sudo ip link del dev dummy0 2>/dev/null || true
  for _cgdir in /sys/fs/cgroup/nacre/*/; do
    [ -d "$_cgdir" ] || continue
    sudo bash -c '
      echo 1 > "'"$_cgdir"'cgroup.kill" 2>/dev/null || true
      sleep 0.2
      for sub in "'"$_cgdir"'"/*/; do
        [ -d "$sub" ] || continue
        rmdir "$sub" 2>/dev/null || true
      done
      rmdir "'"$_cgdir"'" 2>/dev/null || true
    '
  done
}

escape_ere() {
  sed 's/[][\\.*^$()|+?{}]/\\&/g' <<< "$1"
}

# Build per-file filter regexes from the pattern file
declare -A NAME_TO_FILE
while IFS= read -r mapping; do
  file="${mapping%%	*}"
  tname="${mapping#*	}"
  tname="${tname%"${tname##*[! ]}"}"
  NAME_TO_FILE["$tname"]="$file"
done < <(grep -rH '@test "' tests/integration/*.bats \
    | sed -n 's/^\(.*\.bats\):.*@test "\(.*\)" {.*$/\1\t\2/p')

declare -A FILE_FILTER
declare -A FILE_TEST_COUNT
PATTERN_SKIP=0

while IFS= read -r name; do
  [[ -z "$name" || "$name" == \#* ]] && continue

  if [[ $name =~ ^\[skip\] ]]; then
    PATTERN_SKIP=$((PATTERN_SKIP + 1))
    continue
  fi

  file="${NAME_TO_FILE[$name]:-}"
  if [[ -z "$file" ]]; then
    echo "WARN: test not found in any .bats file: $name" >&2
    continue
  fi

  escaped=$(escape_ere "$name")
  if [[ -z "${FILE_FILTER[$file]:-}" ]]; then
    FILE_FILTER[$file]="^${escaped} *$"
    FILE_TEST_COUNT[$file]=1
  else
    FILE_FILTER[$file]="${FILE_FILTER[$file]}|^${escaped} *$"
    FILE_TEST_COUNT[$file]=$(( ${FILE_TEST_COUNT[$file]} + 1 ))
  fi
done < "$PATTERN_FILE"

TOTAL_ENABLED=0
for f in "${!FILE_TEST_COUNT[@]}"; do
  TOTAL_ENABLED=$(( TOTAL_ENABLED + ${FILE_TEST_COUNT[$f]} ))
done

echo ">>> Running ${TOTAL_ENABLED} tests from ${#FILE_FILTER[@]} bats files (${PATTERN_SKIP} skipped in pattern)"
echo "    Binary: $NACRE_BIN"
echo ""

PASS=0
FAIL=0
BATS_SKIP=0
FAIL_NAMES=()

FILE_INDEX=0
FILE_TOTAL=${#FILE_FILTER[@]}

for file in $(printf '%s\n' "${!FILE_FILTER[@]}" | sort); do
  FILE_INDEX=$((FILE_INDEX + 1))
  filter="${FILE_FILTER[$file]}"
  fname=$(basename "$file")
  expected=${FILE_TEST_COUNT[$file]}
  timeout_secs=$(( expected * 30 ))
  (( timeout_secs < 180 )) && timeout_secs=180

  echo "=== [$FILE_INDEX/$FILE_TOTAL] $fname ($expected tests, ${timeout_secs}s) ==="

  TMPOUT=$(mktemp)

  rc=0
  sudo -E PATH="$PATH" RUNC="$PWD/runc" _BATS_FILTER="$filter" \
      timeout "$timeout_secs" script -q -e -c \
      'exec bats -f "$_BATS_FILTER" -t '"$file" /dev/null > "$TMPOUT" 2>&1 \
    || rc=$?

  if [[ $rc -eq 124 ]]; then
    echo "  TIMEOUT ($fname), retrying..."
    cleanup_stale_state
    rc=0
    sudo -E PATH="$PATH" RUNC="$PWD/runc" _BATS_FILTER="$filter" \
        timeout "$timeout_secs" script -q -e -c \
        'exec bats -f "$_BATS_FILTER" -t '"$file" /dev/null > "$TMPOUT" 2>&1 \
      || rc=$?
  fi

  cat "$TMPOUT" >> "$TAP_OUTPUT"

  file_pass=0
  file_fail=0
  in_fail=0
  while IFS= read -r line; do
    if [[ "$line" =~ ^ok\ [0-9]+\ (.+) ]]; then
      tname="${BASH_REMATCH[1]}"
      if [[ "$tname" =~ \#\ skip ]]; then
        echo "  SKIP  ${tname%% \# skip*}"
        BATS_SKIP=$((BATS_SKIP + 1))
      else
        file_pass=$((file_pass + 1))
        echo "  PASS  $tname"
      fi
      in_fail=0
    elif [[ "$line" =~ ^not\ ok\ [0-9]+\ (.+) ]]; then
      tname="${BASH_REMATCH[1]}"
      file_fail=$((file_fail + 1))
      echo "  FAIL  $tname"
      FAIL_NAMES+=("$tname")
      in_fail=1
    elif [[ $in_fail -eq 1 && "$line" =~ ^#\  ]]; then
      echo "        ${line#\# }"
    else
      in_fail=0
    fi
  done < "$TMPOUT"

  if [[ $file_fail -gt 0 ]]; then
    echo "  --- full bats output ($fname) ---"
    cat "$TMPOUT"
    echo "  --- end ---"
    # Dump any nacre init debug logs
    for initlog in /run/nacre/*/init.log; do
      if [[ -f "$initlog" ]]; then
        echo "  --- $initlog ---"
        cat "$initlog"
        echo "  --- end init.log ---"
      fi
    done
  fi

  if [[ $rc -ne 0 && $file_pass -eq 0 && $file_fail -eq 0 ]]; then
    file_fail=$expected
    echo "  FAIL  $fname (bats exited with rc=$rc, no TAP output)"
    FAIL_NAMES+=("$fname (rc=$rc)")
  fi

  PASS=$((PASS + file_pass))
  FAIL=$((FAIL + file_fail))

  rm -f "$TMPOUT"
  cleanup_stale_state
done

TOTAL=$((PASS + FAIL + BATS_SKIP))

echo ""
echo "==========================================="
echo " runc bats compatibility — results"
echo "==========================================="
echo " Total  : $TOTAL"
echo " Pass   : $PASS"
echo " Fail   : $FAIL"
echo " Skip   : ${PATTERN_SKIP} (pattern) + ${BATS_SKIP} (bats-internal)"
echo "==========================================="

if [[ ${#FAIL_NAMES[@]} -gt 0 ]]; then
  echo ""
  echo "Failing tests:"
  for n in "${FAIL_NAMES[@]}"; do
    echo "  - $n"
  done
fi

if [[ -n "$SUMMARY_FILE" ]]; then
  {
    echo "## runc bats compatibility test results"
    echo ""
    echo "Runtime: nacre (Perl)"
    echo "runc ref: \`${RUNC_TAG}\`"
    echo ""
    echo "| Metric | Count |"
    echo "|--------|------:|"
    echo "| Total  | $TOTAL |"
    echo "| Pass   | $PASS  |"
    echo "| Fail   | $FAIL  |"
    echo "| Skip (pattern) | $PATTERN_SKIP |"
    echo "| Skip (bats)    | $BATS_SKIP |"
  } >> "$SUMMARY_FILE"
fi

echo ""
echo "Raw TAP output: $TAP_OUTPUT"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0
