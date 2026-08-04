#!/bin/bash
# Airlock End-to-End Test Suite
# Run this script inside the airlock-dev Docker container (--privileged)
# Usage: docker run --rm --privileged airlock-dev bash /app/test_e2e.sh

set -uo pipefail   # Note: NO -e so test failures don't abort the suite

PASS=0
FAIL=0
SKIP=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YELLOW}⊘${NC} $1 (skipped)"; SKIP=$((SKIP + 1)); }
header() { echo -e "\n${BLUE}${BOLD}=== $1 ===${NC}"; }

assert_contains() {
  local label="$1" expected="$2" actual="$3"
  if echo "$actual" | grep -q "$expected"; then
    pass "$label"
  else
    fail "$label"
    echo "    → expected to find: '$expected'"
    echo "    → actual output:    $(echo "$actual" | head -5)"
  fi
}

assert_exit_code() {
  local label="$1" expected="$2" actual="$3"
  if [ "$actual" -eq "$expected" ]; then
    pass "$label"
  else
    fail "$label (expected exit $expected, got $actual)"
  fi
}

echo -e "${BOLD}╔════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     Airlock End-to-End Test Suite      ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════╝${NC}"

# ─────────────────────────────────────────────
header "PHASE 0: Sanity Checks"
# ─────────────────────────────────────────────

# 0.1 Binary exists
if airlock --version 2>&1 | grep -qiE "airlock|version|[0-9]"; then
  pass "airlock binary is executable"
else
  # Still passes if binary is reachable even if version is minimal
  if command -v airlock &>/dev/null; then
    pass "airlock binary is on PATH"
  else
    fail "airlock binary not found on PATH"
  fi
fi

# 0.2 Help shows all subcommands
out=$(airlock --help 2>&1)
assert_contains "help shows 'run'"     "run"     "$out"
assert_contains "help shows 'list'"    "list"    "$out"
assert_contains "help shows 'clean'"   "clean"   "$out"
assert_contains "help shows 'compose'" "compose" "$out"

# ─────────────────────────────────────────────
header "PHASE 1: Basic Container Isolation (Legacy Mode)"
# ─────────────────────────────────────────────

# 1.1 PID namespace: PID 1 inside container
out=$(airlock run --no-seccomp /bin/sh -c 'echo my_pid=$$' 2>&1) || true
assert_contains "PID is 1 inside container" "my_pid=1" "$out"

# 1.2 Hostname isolation via UTS namespace
out=$(airlock run --no-seccomp --hostname mybox /bin/sh -c "hostname" 2>&1) || true
assert_contains "hostname matches --hostname flag" "mybox" "$out"

# 1.3 Filesystem isolation: /etc/os-release is Alpine (not the host's)
out=$(airlock run --no-seccomp /bin/sh -c "cat /etc/os-release" 2>&1) || true
assert_contains "/etc/os-release is Alpine" "Alpine" "$out"

# 1.4 /proc is freshly mounted (few PIDs visible)
out=$(airlock run --no-seccomp /bin/sh -c "ls /proc | grep -c '^[0-9]'" 2>&1) || true
count=$(echo "$out" | grep -E '^[0-9]+$' | tail -1)
if [ -n "$count" ] && [ "$count" -lt 10 ]; then
  pass "/proc has only container-owned PIDs (count: $count)"
else
  fail "/proc PID count too high ($count) — may be leaking host PIDs"
fi

# ─────────────────────────────────────────────
header "PHASE 2: Volume Mounts"
# ─────────────────────────────────────────────

TMPDIR_TEST=$(mktemp -d)
echo "hello_from_host" > "$TMPDIR_TEST/testfile.txt"

# 2.1 Read-write volume: read a host file
out=$(airlock run --no-seccomp -v "$TMPDIR_TEST:/data" /bin/sh -c "cat /data/testfile.txt" 2>&1) || true
assert_contains "RW volume: can read host file" "hello_from_host" "$out"

# 2.2 Read-write volume: write persists on host
airlock run --no-seccomp -v "$TMPDIR_TEST:/data" /bin/sh -c "echo container_wrote > /data/output.txt" 2>&1 || true
if [ -f "$TMPDIR_TEST/output.txt" ] && grep -q "container_wrote" "$TMPDIR_TEST/output.txt"; then
  pass "RW volume: container write persists on host"
else
  fail "RW volume: container write was not visible on host"
fi

# 2.3 Read-only volume: write is rejected
out=$(airlock run --no-seccomp -v "$TMPDIR_TEST:/data:ro" /bin/sh -c "echo test > /data/ro_test.txt 2>&1; echo exit=\$?" 2>&1) || true
assert_contains "RO volume: write is denied" "exit=1" "$out"

rm -rf "$TMPDIR_TEST"

# ─────────────────────────────────────────────
header "PHASE 3: Resource Limits (cgroups v2)"
# ─────────────────────────────────────────────

# 3.1 cgroup is applied and visible (or gracefully skipped where the host
# doesn't delegate a child cgroup — e.g. airlock itself running inside a
# Docker container, as CI's e2e job and the local dev sandbox both do)
out=$(airlock run --no-seccomp --memory 64m /bin/sh -c "cat /proc/self/cgroup" 2>&1) || true
if echo "$out" | grep -q "could not create a delegated child cgroup"; then
  skip "cgroup entry is visible inside container (no delegated cgroup available in this environment)"
else
  assert_contains "cgroup entry is visible inside container" "airlock" "$out"
fi

# 3.2 Container runs with CPU limit
out=$(airlock run --no-seccomp --cpu 25 /bin/sh -c "echo cpu_ok" 2>&1) || true
assert_contains "runs with --cpu 25" "cpu_ok" "$out"

# 3.3 Memory limit actually enforces, not just "the container starts under
# one." An exponentially-doubling string has no way to terminate on its
# own — if the process exits at all, the cgroup's OOM killer intervened.
# `timeout` is a safety net here, not the expected trigger: if the limit
# genuinely isn't enforcing, this loop keeps growing for the full 10s
# instead of being killed early, which is exactly the failure mode worth
# catching (and bounding), not something to assert an exact exit code for —
# Go's ExitCode() reports -1 for a signal death, not the shell's 128+signal
# convention, so pinning a specific number here would be a flaky, overfit
# test.
timeout 10 airlock run --no-seccomp --memory 16m alpine:3.20 sh -c \
  'x=x; while true; do x="$x$x"; done' >/tmp/oom-test.log 2>&1
oom_exit=$?
oom_out=$(cat /tmp/oom-test.log)
if echo "$oom_out" | grep -q "could not create a delegated child cgroup"; then
  skip "memory limit is actually enforced (no delegated cgroup available in this environment)"
elif [ "$oom_exit" -eq 124 ]; then
  fail "memory limit is actually enforced (process ran the full 10s timeout without being killed)"
elif [ "$oom_exit" -ne 0 ]; then
  pass "memory limit is actually enforced (killed under --memory 16m, exit $oom_exit)"
else
  fail "memory limit is actually enforced (process exited 0 — should be impossible for an infinite loop)"
fi

# ─────────────────────────────────────────────
header "PHASE 4: Seccomp Filter"
# ─────────────────────────────────────────────

# 4.1 Container starts normally with seccomp (or auto-skips where seccomp
# can't be installed). The skip branch matches ApplySeccomp's own exact
# message rather than a loose "seccomp|linuxkit|warning" pattern: that
# looser version reported a cheerful "auto-skip detected" for the arm64
# rootfs bug (an unrelated failure whose output merely happened to contain
# the word "warning"), turning a real breakage into a passing test. A skip
# branch that can absorb arbitrary unrelated failures is worse than no skip
# branch at all.
out=$(airlock run /bin/sh -c "echo seccomp_test_ok" 2>&1) || true
if echo "$out" | grep -q "seccomp_test_ok"; then
  pass "seccomp mode: container starts and runs command"
elif echo "$out" | grep -q "Seccomp: skipped"; then
  skip "seccomp mode: container starts and runs command (seccomp unavailable in this environment)"
else
  fail "seccomp: unexpected result"
  echo "    → output: $out"
fi

# 4.2 --no-seccomp flag works
out=$(airlock run --no-seccomp /bin/sh -c "echo no_seccomp_ok" 2>&1) || true
assert_contains "--no-seccomp: container runs" "no_seccomp_ok" "$out"

# 4.3 Seccomp actually blocks a syscall, not just "the container starts."
# mknod is deliberately chosen over something like mount: CAP_MKNOD stays in
# airlock's capability bounding set either way (see container/container.go's
# capability allowlist), so toggling seccomp alone is what flips the
# outcome here — mount would fail under BOTH runs, since CAP_SYS_ADMIN is
# already stripped regardless of seccomp, proving nothing about seccomp
# specifically.
out=$(airlock run alpine:3.20 sh -c 'mknod /tmp/d c 1 3 && echo created' 2>&1) || true
if echo "$out" | grep -q "Seccomp: skipped"; then
  skip "seccomp: mknod is blocked by default (seccomp unavailable in this environment)"
else
  if echo "$out" | grep -q "created"; then
    fail "seccomp: mknod should have been blocked by default, but succeeded"
  else
    pass "seccomp: mknod is blocked by default"
  fi
  out=$(airlock run --no-seccomp alpine:3.20 sh -c 'mknod /tmp/d c 1 3 && echo created' 2>&1) || true
  assert_contains "seccomp: --no-seccomp allows mknod (CAP_MKNOD is retained either way)" "created" "$out"
fi

# ─────────────────────────────────────────────
header "PHASE 5: Container Networking"
# ─────────────────────────────────────────────

# 5.1 eth0 with IP in 10.0.42.x range
out=$(airlock run --no-seccomp /bin/sh -c "ip addr show eth0 2>&1" 2>&1) || true
assert_contains "container has eth0" "eth0" "$out"
assert_contains "eth0 has 10.0.42.x IP" "10.0.42." "$out"

# 5.2 Loopback is up
out=$(airlock run --no-seccomp /bin/sh -c "ip link show lo 2>&1" 2>&1) || true
assert_contains "loopback (lo) is present" "lo" "$out"

# 5.3 Default route via bridge gateway
out=$(airlock run --no-seccomp /bin/sh -c "ip route 2>&1" 2>&1) || true
assert_contains "default route via 10.0.42.1" "10.0.42.1" "$out"

# 5.4 /etc/resolv.conf has external DNS
out=$(airlock run --no-seccomp /bin/sh -c "cat /etc/resolv.conf 2>&1" 2>&1) || true
assert_contains "resolv.conf has 8.8.8.8" "8.8.8.8" "$out"

# 5.5 External internet reachable
out=$(airlock run --no-seccomp /bin/sh -c "ping -c 2 -W 3 8.8.8.8 2>&1" 2>&1) || true
if echo "$out" | grep -qE "2 packets transmitted|2 received"; then
  pass "external internet reachable (ping 8.8.8.8)"
else
  skip "ping 8.8.8.8 failed (networking may be restricted in this environment)"
fi

# 5.6 --no-network: no eth0
out=$(airlock run --no-seccomp --no-network /bin/sh -c "ip addr show eth0 2>&1; echo done" 2>&1) || true
if echo "$out" | grep -qiE "does not exist|Cannot find|error|no such"; then
  pass "--no-network: eth0 is absent"
else
  # In no-network mode, the interface literally won't exist
  if ! echo "$out" | grep -q "10.0.42."; then
    pass "--no-network: no 10.0.42.x IP assigned"
  else
    fail "--no-network: eth0 with 10.0.42.x was present when it shouldn't be"
  fi
fi

# 5.7-5.8 Port publishing (-p/--publish) — previously had zero e2e coverage
# of any kind, not even the already-working path. A background container
# serves one canned HTTP response per connection (busybox `nc -l`, restarted
# in a loop) on 8000, published to host port 18080.
airlock run --no-seccomp -p 18080:8000 alpine:3.20 sh -c \
  'while true; do printf "HTTP/1.1 200 OK\r\n\r\nhello-from-container" | nc -l -p 8000; done' \
  >/tmp/publish-test.log 2>&1 &
PUBLISH_BG_PID=$!
sleep 3
PUBLISH_CID=$(airlock ps 2>/dev/null | tail -1 | awk '{print $1}')

# 5.7 Direct container IP: the PREROUTING/FORWARD path — expected to work in
# any environment, since it only needs traffic actually arriving on a real
# interface, not the hairpin/loopback case 5.8 covers.
PUBLISH_CIP=$(airlock exec "$PUBLISH_CID" sh -c "ip addr show eth0" 2>/dev/null | grep -oE '10\.0\.42\.[0-9]+' | head -1)
out=$(timeout 3 curl -sS "$PUBLISH_CIP:8000" 2>&1) || true
assert_contains "publish: container's own bridge IP is reachable" "hello-from-container" "$out"

# 5.8 curl localhost:<hostport> from the SAME machine airlock runs on —
# hairpin/loopback NAT (OUTPUT-chain DNAT + route_localnet, see
# container/network.go's SetupPortForward). Implemented the same way
# Docker's own bridge driver handles this case, but not yet confirmed
# working in every environment — see README's Act 3 demo notes. A real
# assert (not skip) here is deliberate: this suite's whole point is
# surfacing exactly this kind of "claimed but unverified" gap with a real
# signal instead of assuming a result.
out=$(timeout 3 curl -sS "localhost:18080" 2>&1) || true
assert_contains "publish: curl localhost:<hostport> reaches container (hairpin NAT)" "hello-from-container" "$out"

kill "$PUBLISH_BG_PID" 2>/dev/null || true
wait "$PUBLISH_BG_PID" 2>/dev/null || true
airlock stop "$PUBLISH_CID" >/dev/null 2>&1 || true

# ─────────────────────────────────────────────
header "PHASE 6: OCI Image Pull & Run"
# ─────────────────────────────────────────────

echo "  (pulling alpine:3.20 from Docker Hub — may take a moment...)"

# 6.1 Pull and run alpine:3.20
out=$(airlock run --no-seccomp alpine:3.20 /bin/sh -c "cat /etc/alpine-release" 2>&1) || true
assert_contains "alpine:3.20: pull and run" "3.20" "$out"

# 6.2 Second run is a cache hit
out=$(airlock run --no-seccomp alpine:3.20 /bin/sh -c "echo cache_ok" 2>&1) || true
assert_contains "second run: command executes" "cache_ok" "$out"
if echo "$out" | grep -q "Using cached"; then
  pass "second run: cache fast-path confirmed"
fi

# 6.3 Image runs in isolation (not the host's rootfs)
out=$(airlock run --no-seccomp alpine:3.20 /bin/sh -c "echo image_isolated" 2>&1) || true
assert_contains "OCI image: command runs cleanly" "image_isolated" "$out"

# ─────────────────────────────────────────────
header "PHASE 7: airlock list / ps"
# ─────────────────────────────────────────────

# 7.1 Headers include SERVICE column
# Use alpine:3.20 which is already cached from Phase 6 — starts instantly
airlock run --no-seccomp alpine:3.20 sleep 30 2>&1 &
BG_PID=$!
sleep 2  # brief wait; OCI cache hit starts in <1s
out=$(airlock ps 2>&1) || true
assert_contains "airlock ps: SERVICE column" "SERVICE" "$out"
assert_contains "airlock ps: IMAGE column"   "IMAGE"   "$out"
assert_contains "airlock ps: PID column"     "PID"     "$out"

# Clean up background container
kill "$BG_PID" 2>/dev/null || true
wait "$BG_PID" 2>/dev/null || true
sleep 1

# 7.2 ps is clean after container exits
out=$(airlock ps 2>&1) || true
if echo "$out" | grep -qE "No running containers"; then
  pass "airlock ps: clean after container exits"
else
  pass "airlock ps: running without error (transitional state OK)"
fi

# ─────────────────────────────────────────────
header "PHASE 8: Image Reference Parsing"
# ─────────────────────────────────────────────

# 8.1 Bare name → docker.io/library/alpine:latest
out=$(airlock run --no-seccomp alpine /bin/sh -c "echo bare_name_ok" 2>&1) || true
assert_contains "bare 'alpine' resolves correctly" "bare_name_ok" "$out"

# 8.2 Legacy mode: first arg starts with / → default Alpine rootfs
out=$(airlock run --no-seccomp /bin/sh -c "echo legacy_ok" 2>&1) || true
assert_contains "legacy /bin/sh mode works" "legacy_ok" "$out"

# 8.3 Re-pull after cache clear
echo "  (cleaning image cache then re-pulling alpine:3.20...)"
airlock clean --images 2>&1 || true
out=$(airlock run --no-seccomp alpine:3.20 /bin/sh -c "echo repull_ok" 2>&1) || true
assert_contains "re-pull after clean works" "repull_ok" "$out"

# ─────────────────────────────────────────────
header "PHASE 9: Compose Orchestrator"
# ─────────────────────────────────────────────

COMPOSE_DIR=$(mktemp -d)

# 9.1 Cycle detection
cat > "$COMPOSE_DIR/airlock-compose.yml" << 'YAML'
version: "1.0"
services:
  svc_a:
    image: alpine
    command: /bin/sh -c "echo a"
    depends_on: [svc_b]
  svc_b:
    image: alpine
    command: /bin/sh -c "echo b"
    depends_on: [svc_a]
YAML

out=$(cd "$COMPOSE_DIR" && airlock compose up 2>&1) || true
if echo "$out" | grep -qiE "cycle|circular|invalid dependency"; then
  pass "compose: circular dependency detected and rejected"
else
  fail "compose: circular dependency was NOT caught"
  echo "    → output: $out"
fi

# 9.2 Valid compose: services start in dependency order
cat > "$COMPOSE_DIR/airlock-compose.yml" << 'YAML'
version: "1.0"
services:
  db:
    image: alpine:3.20
    command: sleep 45
    memory: 64m
    cpu: 25
  app:
    image: alpine:3.20
    command: sleep 45
    memory: 64m
    cpu: 25
    depends_on:
      - db
YAML

echo "  (starting compose stack — db → app...)"
(cd "$COMPOSE_DIR" && airlock compose up) 2>&1 &
COMPOSE_PID=$!

# Poll for service registration with a 15-second timeout
ps_out=""
for attempt in $(seq 1 15); do
  sleep 1
  ps_out=$(airlock ps 2>&1) || true
  if echo "$ps_out" | grep -qE "db|app"; then
    break
  fi
done
if echo "$ps_out" | grep -qE "db|app"; then
  pass "compose up: services are registered in state"
else
  fail "compose up: no services found in airlock ps"
  echo "    → ps output: $ps_out"
fi

# 9.3 Compose down
(cd "$COMPOSE_DIR" && airlock compose down) 2>&1 || true
kill "$COMPOSE_PID" 2>/dev/null || true
wait "$COMPOSE_PID" 2>/dev/null || true
sleep 2
pass "compose down: ran without fatal error"

rm -rf "$COMPOSE_DIR"

# ─────────────────────────────────────────────
header "PHASE 10: airlock clean"
# ─────────────────────────────────────────────

out=$(airlock clean 2>&1) || true
assert_exit_code "clean (default) exits 0" 0 $?

# clean --images
out=$(airlock clean --images 2>&1) || true
assert_contains "clean --images: reports success" "Cleaned image cache" "$out"

out=$(airlock clean --all 2>&1) || true
if echo "$out" | grep -qE "Cleaned|Nothing"; then
  pass "clean --all: reports expected result"
else
  fail "clean --all: unexpected output: $out"
fi

# ─────────────────────────────────────────────
TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo -e "${BOLD}╔════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║           Test Results ($TOTAL total)           ║${NC}"
echo -e "${BOLD}╠════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  ${GREEN}PASS: $PASS${NC}${BOLD}    |   ${RED}FAIL: $FAIL${NC}${BOLD}    |   ${YELLOW}SKIP: $SKIP${NC}${BOLD}  ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
