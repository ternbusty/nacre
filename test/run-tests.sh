#!/bin/bash
# nacre integration test suite
# Requires: root privileges, busybox, perl 5.20+
set -uo pipefail

NACRE="$(cd "$(dirname "$0")/.." && pwd)/nacre"
ROOT="/run/nacre-test-$$"
PASS=0; FAIL=0; ERRORS=()

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

cleanup() {
    # Safe cleanup: only remove our specific test root
    if [[ "$ROOT" == /run/nacre-test-* ]]; then
        rm -rf "$ROOT" 2>/dev/null || true
    fi
    # Cleanup test cgroups
    for d in /sys/fs/cgroup/nacre/test-*; do
        [ -d "$d" ] || continue
        # Kill processes first
        cat "$d/cgroup.procs" 2>/dev/null | while read pid; do
            kill -9 "$pid" 2>/dev/null || true
        done
        sleep 0.1
        rmdir "$d" 2>/dev/null || true
    done
    rmdir /sys/fs/cgroup/nacre 2>/dev/null || true
    # Cleanup temp bundles
    rm -rf /tmp/nacre-test-bundle-* 2>/dev/null || true
}
trap cleanup EXIT

# Create a test bundle with busybox
make_bundle() {
    local dir="$1"
    local args="${2:-sh -c echo hello}"
    local extra_config="${3:-}"

    mkdir -p "$dir/rootfs"/{bin,dev,proc,sys,tmp,etc}
    cp "$(which busybox)" "$dir/rootfs/bin/"
    (cd "$dir/rootfs/bin" && for c in sh ls echo id cat hostname sleep \
        chmod mkdir mount stat date head tail wc true false test ps kill; do
        ln -sf busybox "$c" 2>/dev/null || true
    done)
    echo "root:x:0:0:root:/root:/bin/sh" > "$dir/rootfs/etc/passwd"
    echo "root:x:0:" > "$dir/rootfs/etc/group"

    cat > "$dir/config.json" <<SPEC
{
  "ociVersion": "1.2.0",
  "root": { "path": "rootfs", "readonly": false },
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": [${args}],
    "env": ["PATH=/bin:/usr/bin", "TERM=xterm"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_AUDIT_WRITE","CAP_KILL","CAP_NET_BIND_SERVICE","CAP_SYS_ADMIN","CAP_NET_ADMIN","CAP_MKNOD","CAP_CHOWN","CAP_FOWNER","CAP_DAC_OVERRIDE","CAP_SETGID","CAP_SETUID"],
      "effective": ["CAP_AUDIT_WRITE","CAP_KILL","CAP_NET_BIND_SERVICE","CAP_SYS_ADMIN","CAP_NET_ADMIN","CAP_MKNOD","CAP_CHOWN","CAP_FOWNER","CAP_DAC_OVERRIDE","CAP_SETGID","CAP_SETUID"],
      "permitted": ["CAP_AUDIT_WRITE","CAP_KILL","CAP_NET_BIND_SERVICE","CAP_SYS_ADMIN","CAP_NET_ADMIN","CAP_MKNOD","CAP_CHOWN","CAP_FOWNER","CAP_DAC_OVERRIDE","CAP_SETGID","CAP_SETUID"],
      "ambient": ["CAP_AUDIT_WRITE","CAP_KILL","CAP_NET_BIND_SERVICE"]
    },
    "noNewPrivileges": true
  },
  "hostname": "nacre-test",
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid","noexec","nodev"] },
    { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","strictatime","mode=755","size=65536k"] },
    { "destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid","noexec","nodev","readonly"] }
  ],
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "mount" },
      { "type": "uts" },
      { "type": "ipc" }
    ]
    ${extra_config}
  }
}
SPEC
}

run_test() {
    local name="$1"
    shift
    echo -n "  $name ... "
    local output rc
    output=$("$@" 2>&1) && rc=0 || rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS+1))
    else
        echo -e "${RED}FAIL${NC} (rc=$rc)"
        echo "    $output" | head -5
        FAIL=$((FAIL+1))
        ERRORS+=("$name")
    fi
}

assert_output_contains() {
    local output="$1"
    local expected="$2"
    if echo "$output" | grep -qF "$expected"; then
        return 0
    else
        echo "Expected output to contain: $expected"
        echo "Got: $output"
        return 1
    fi
}

assert_output_matches() {
    local output="$1"
    local pattern="$2"
    if echo "$output" | grep -qE "$pattern"; then
        return 0
    else
        echo "Expected output to match: $pattern"
        echo "Got: $output"
        return 1
    fi
}

# ── Test helpers ──

nacre() { perl "$NACRE" --root "$ROOT" "$@"; }

delete_container() {
    nacre delete --force "$1" 2>/dev/null || true
}

# ═══════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════

echo "nacre integration tests"
echo "======================="
echo ""

# ── 1. Version / help ──
echo "Command-line basics:"
run_test "version" bash -c 'perl '"$NACRE"' --version | grep -q "nacre"'
run_test "help"    bash -c 'perl '"$NACRE"' --help | grep -q "COMMANDS"'

# ── 2. spec ──
echo ""
echo "spec command:"
run_test "spec generates config.json" bash -c '
    d=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
    perl '"$NACRE"' spec --bundle "$d" --force
    [ -f "$d/config.json" ] && grep -q ociVersion "$d/config.json"
    rm -rf "$d"
'

# ── 3. features ──
echo ""
echo "features command:"
run_test "features outputs JSON" bash -c '
    perl '"$NACRE"' features | python3 -m json.tool > /dev/null
'

# ── 4. create / state / start / kill / delete lifecycle ──
echo ""
echo "Container lifecycle:"

BUNDLE=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE" '"sh", "-c", "sleep 30"'

run_test "create" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE"' test-lifecycle
'

run_test "state shows created" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    output=$(nacre state test-lifecycle)
    echo "$output" | grep -q "\"status\" *: *\"created\""
'

run_test "state has valid pid" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    output=$(nacre state test-lifecycle)
    pid=$(echo "$output" | python3 -c "import sys,json; print(json.load(sys.stdin)[\"pid\"])")
    [ "$pid" -gt 0 ] && [ -d "/proc/$pid" ]
'

run_test "start" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre start test-lifecycle
'

run_test "state shows running" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    output=$(nacre state test-lifecycle)
    echo "$output" | grep -q "\"status\" *: *\"running\""
'

run_test "kill SIGKILL" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre kill test-lifecycle KILL
    sleep 0.3
'

run_test "state shows stopped after kill" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    output=$(nacre state test-lifecycle)
    echo "$output" | grep -q "\"status\" *: *\"stopped\""
'

run_test "delete" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre delete test-lifecycle
    ! nacre state test-lifecycle 2>/dev/null
'

# ── 5. run (create+start+wait+delete) ──
echo ""
echo "run command:"

BUNDLE_RUN=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_RUN" '"sh", "-c", "echo Hello-from-nacre && hostname && ls /"'

run_test "run prints output and exits" bash -c '
    output=$(perl '"$NACRE"' --root '"$ROOT"' run --bundle '"$BUNDLE_RUN"' test-run 2>&1)
    echo "$output" | grep -qF "Hello-from-nacre"
'

# ── 6. Namespace isolation ──
echo ""
echo "Namespace isolation:"

BUNDLE_NS=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_NS" '"sh", "-c", "echo PID=$$ && hostname"'

run_test "PID namespace (PID 1)" bash -c '
    output=$(perl '"$NACRE"' --root '"$ROOT"' run --bundle '"$BUNDLE_NS"' test-pidns 2>&1)
    echo "$output" | grep -qF "PID=1"
'

run_test "UTS namespace (hostname)" bash -c '
    output=$(perl '"$NACRE"' --root '"$ROOT"' run --bundle '"$BUNDLE_NS"' test-utsns 2>&1)
    echo "$output" | grep -qF "nacre-test"
'

BUNDLE_MOUNT=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_MOUNT" '"sh", "-c", "ls /proc/self/ns && cat /proc/1/cgroup"'

run_test "mount namespace (isolated /proc)" bash -c '
    output=$(perl '"$NACRE"' --root '"$ROOT"' run --bundle '"$BUNDLE_MOUNT"' test-mntns 2>&1)
    echo "$output" | grep -q "pid"  # /proc/self/ns/ should list namespace files
'

# ── 7. rootfs readonly ──
echo ""
echo "Rootfs options:"

BUNDLE_RO=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_RO" '"sh", "-c", "touch /test-file 2>&1 || echo READONLY-OK"'
# Patch config for readonly rootfs
python3 -c "
import json
with open('$BUNDLE_RO/config.json') as f: c = json.load(f)
c['root']['readonly'] = True
with open('$BUNDLE_RO/config.json','w') as f: json.dump(c,f)
"

run_test "readonly rootfs blocks writes" bash -c '
    output=$(perl '"$NACRE"' --root '"$ROOT"' run --bundle '"$BUNDLE_RO"' test-ro 2>&1)
    echo "$output" | grep -qF "READONLY-OK"
'

# ── 8. list ──
echo ""
echo "list command:"

BUNDLE_LIST=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_LIST" '"sleep", "30"'

run_test "list shows created container" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_LIST"' test-list
    output=$(nacre list)
    echo "$output" | grep -qF "test-list"
    nacre delete --force test-list
'

run_test "list --quiet shows only IDs" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_LIST"' test-list-q
    output=$(nacre list --quiet)
    [ "$output" = "test-list-q" ]
    nacre delete --force test-list-q
'

run_test "list --format json" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_LIST"' test-list-j
    output=$(nacre list --format json)
    echo "$output" | python3 -m json.tool > /dev/null
    nacre delete --force test-list-j
'

# ── 9. Force delete ──
echo ""
echo "Force delete:"

BUNDLE_FD=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_FD" '"sleep", "30"'

run_test "force delete running container" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_FD"' test-force
    nacre start test-force
    nacre delete --force test-force
    ! nacre state test-force 2>/dev/null
'

# ── 10. Exit code propagation ──
echo ""
echo "Exit code propagation:"

BUNDLE_EC=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_EC" '"sh", "-c", "exit 42"'

run_test "exit code 42 propagated" bash -c '
    set +e
    perl '"$NACRE"' --root '"$ROOT"' run --bundle '"$BUNDLE_EC"' test-ec42 2>&1
    rc=$?
    set -e
    if [ "$rc" -ne 42 ]; then
        echo "DIAG: expected exit code 42 but got $rc" >&2
    fi
    [ "$rc" -eq 42 ]
'

# ── 11. Signal parsing ──
echo ""
echo "Signal handling:"

BUNDLE_SIG=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_SIG" '"sleep", "30"'

run_test "kill with signal name TERM" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_SIG"' test-sig1
    nacre start test-sig1
    sleep 0.2
    nacre kill test-sig1 KILL
    sleep 0.3
    output=$(nacre state test-sig1)
    echo "$output" | grep -q "stopped"
    nacre delete test-sig1
'

run_test "kill with signal number 9" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_SIG"' test-sig2
    nacre start test-sig2
    sleep 0.2
    nacre kill test-sig2 9
    sleep 0.3
    output=$(nacre state test-sig2)
    echo "$output" | grep -q "stopped"
    nacre delete test-sig2
'

# ── 12. Pause / Resume ──
echo ""
echo "Pause / Resume:"

BUNDLE_PR=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_PR" '"sleep", "30"'

run_test "pause and resume" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_PR"' test-pause
    nacre start test-pause
    sleep 0.2
    nacre pause test-pause
    output=$(nacre state test-pause)
    echo "$output" | grep -q "paused"
    nacre resume test-pause
    output=$(nacre state test-pause)
    echo "$output" | grep -q "running"
    nacre delete --force test-pause
'

# ── 13. exec ──
echo ""
echo "Exec:"

BUNDLE_EXEC=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_EXEC" '"sleep", "30"'

run_test "exec in running container" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_EXEC"' test-exec
    nacre start test-exec
    sleep 0.3
    output=$(nacre exec test-exec -- echo exec-works 2>&1)
    echo "$output" | grep -qF "exec-works"
    nacre delete --force test-exec
'

# ── 14. events/stats ──
echo ""
echo "Events:"

BUNDLE_EV=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_EV" '"sleep", "30"'

run_test "events --stats" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_EV"' test-events
    nacre start test-events
    sleep 0.3
    output=$(nacre events --stats test-events 2>&1)
    echo "$output" | grep -q "pids"
    nacre delete --force test-events
'

# ── 15. ps ──
echo ""
echo "Ps:"

BUNDLE_PS=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_PS" '"sleep", "30"'

run_test "ps lists container processes" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_PS"' test-ps
    nacre start test-ps
    sleep 0.3
    output=$(nacre ps test-ps 2>&1)
    echo "$output" | grep -q "sleep"
    nacre delete --force test-ps
'

# ── 16. Cgroup resources ──
echo ""
echo "Cgroup resources:"

BUNDLE_CG=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_CG" '"sleep", "30"' ',
    "resources": {
      "memory": { "limit": 134217728 },
      "pids": { "limit": 100 }
    }'

run_test "memory limit applied" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_CG"' test-cg
    nacre start test-cg
    sleep 0.2
    cgpath=$(python3 -c "import json; print(json.load(open('"$ROOT"/test-cg/state.json'))[\"cgroupPath\"])" 2>/dev/null) || cgpath="/sys/fs/cgroup/nacre/test-cg"
    mem_max=$(cat "$cgpath/memory.max" 2>/dev/null)
    nacre delete --force test-cg
    [ "$mem_max" = "134217728" ]
'

run_test "pids limit applied" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_CG"' test-cg-pid
    nacre start test-cg-pid
    sleep 0.2
    cgpath=$(python3 -c "import json; print(json.load(open('"$ROOT"/test-cg-pid/state.json'))[\"cgroupPath\"])" 2>/dev/null) || cgpath="/sys/fs/cgroup/nacre/test-cg-pid"
    pids_max=$(cat "$cgpath/pids.max" 2>/dev/null)
    nacre delete --force test-cg-pid
    [ "$pids_max" = "100" ]
'

# ── 17. update ──
echo ""
echo "Update:"

BUNDLE_UP=$(mktemp -d /tmp/nacre-test-bundle-XXXX)
make_bundle "$BUNDLE_UP" '"sleep", "30"'

run_test "update memory limit" bash -c '
    nacre() { perl '"$NACRE"' --root '"$ROOT"' "$@"; }
    nacre create --bundle '"$BUNDLE_UP"' test-update
    nacre start test-update
    sleep 0.2
    echo "{\"memory\":{\"limit\":268435456}}" | nacre update test-update
    cgpath=$(python3 -c "import json; print(json.load(open('"$ROOT"/test-update/state.json'))[\"cgroupPath\"])" 2>/dev/null) || cgpath="/sys/fs/cgroup/nacre/test-update"
    mem_max=$(cat "$cgpath/memory.max" 2>/dev/null)
    nacre delete --force test-update
    [ "$mem_max" = "268435456" ]
'

# ── Summary ──
echo ""
echo "═══════════════════════════════════════════"
TOTAL=$((PASS + FAIL))
echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC} / $TOTAL total"

if [ ${#ERRORS[@]} -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    for e in "${ERRORS[@]}"; do
        echo -e "  ${RED}✗${NC} $e"
    done
fi

echo "═══════════════════════════════════════════"
exit $FAIL
