#!/usr/bin/env bash
# REQ: CLU-004, OPS-001, DNS-001, OPS-012 — the keepalived failover proof (deploy/keepalived, T24.4):
#   a. two TelltaleDNS nodes and their keepalived sidecars start on an isolated Docker bridge network
#      (10.231.250.0/24, no route out); each node answers on its own address;
#   b. the VIP (10.231.250.10) is held by node a, and a query to the VIP is answered by node a
#      (the VIP lands on the wildcard listener, the answer names the node);
#   c. node a is killed hard (the TelltaleDNS container and its keepalived, both at once); node b
#      takes the VIP, and the VIP answers as node b within 15 s, with no query lost after that;
#   d. node a comes back and takes the VIP again (keepalived preempts a backup with higher priority).
# Nothing here touches the LAN, the host network, or any other compose project: its own project
# name (telltale-keepalived), its own bridge network, no published ports. Every container and the
# network are removed at exit, and the test image too when this run built it.
#
# Usage: deploy/keepalived/e2e.sh          (needs Docker with Compose v2)
#        TELLTALE_IMAGE=<image> deploy/keepalived/e2e.sh   (use an existing TelltaleDNS image)
#        KEEP=1 deploy/keepalived/e2e.sh   (keeps the built image)
set -euo pipefail

# Git Bash rewrites arguments that start with "/" into Windows paths; docker needs them as they are.
export MSYS_NO_PATHCONV=1

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
# Docker on Windows (Git Bash) needs the Windows form of the paths.
HERE_W=$HERE
ROOT_W=$ROOT
if command -v cygpath >/dev/null 2>&1; then HERE_W=$(cygpath -m "$HERE"); ROOT_W=$(cygpath -m "$ROOT"); fi

PROJECT=telltale-keepalived
SUBNET=10.231.250
VIP=$SUBNET.10
NET=${PROJECT}_vip
KA_IMAGE=telltale-keepalived:alpine-3.20
BUILT_IMAGE=
if [ -n "${TELLTALE_IMAGE:-}" ]; then
  IMAGE=$TELLTALE_IMAGE
else
  IMAGE=telltale:keepalived-test
  BUILT_IMAGE=$IMAGE
fi
export TELLTALE_IMAGE=$IMAGE
COMPOSE=(docker compose -p "$PROJECT" -f "$HERE_W/compose.yaml")
NODES=(a b)

cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [ "$rc" -ne 0 ]; then
    echo "--- the logs (last 40 lines each)"
    for s in keepalived-a telltale-a keepalived-b telltale-b; do
      echo "--- $s"
      "${COMPOSE[@]}" logs --no-color --tail 40 "$s" 2>&1 | sed 's/^/    /'
    done
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      echo "::error title=deploy/keepalived/e2e.sh::the keepalived failover run failed (the logs above)"
    fi
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  if [ -n "$BUILT_IMAGE" ] && [ "${KEEP:-}" != 1 ]; then
    docker image rm "$BUILT_IMAGE" >/dev/null 2>&1
  fi
  exit "$rc"
}
trap cleanup EXIT

step() { echo "== $1"; }
pass() { echo "ok${1:+ ($1)}"; }
bad() { echo "FAIL: $*"; exit 1; }
now_ms() { date +%s%3N; }

# The A or TXT answer of the VIP (or of any address given as $3) for a name: empty when no answer.
dig_at() { # address name type
  docker run --rm --network "$NET" --entrypoint dig "$KA_IMAGE" +time=1 +tries=1 +short "@$1" "$2" "$3" 2>/dev/null | head -n 1 || true
}

# Which node holds the VIP: a or b, or empty. The check runs inside each node's network namespace.
vip_owner() {
  local n
  for n in "${NODES[@]}"; do
    if "${COMPOSE[@]}" exec -T "keepalived-$n" ip -4 addr show eth0 2>/dev/null | grep -qF "inet $VIP/"; then
      echo "$n"
      return 0
    fi
  done
  return 0
}

# The node name in a TXT answer, for example "telltale-a" (the quotes are removed).
who() { sed 's/"//g' <<<"$1"; }

# Waits until the VIP answers as the wanted node, for up to budget_ms. Prints nothing.
await_vip() { # budget_ms node
  local end=$(( $(now_ms) + $1 ))
  while [ "$(now_ms)" -lt "$end" ]; do
    [ "$(who "$(dig_at "$VIP" whoami.vip.home.arpa TXT)")" = "telltale-$2" ] && return 0
    sleep 0.5
  done
  return 1
}

step "the isolated network: $SUBNET.0/24 is free"
if docker network ls -q | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | grep -qF "$SUBNET.0/24"; then
  bad "$SUBNET.0/24 is already used by a Docker network; change the subnet in compose.yaml, the node files and this script"
fi
pass

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

if [ -n "$BUILT_IMAGE" ]; then
  step "build the TelltaleDNS image from this checkout ($BUILT_IMAGE)"
  docker build --build-arg PROFILE=bench-fast --build-arg TELLTALE_BUILD_CHANNEL=dev \
    -t "$BUILT_IMAGE" "$ROOT_W" >/dev/null || bad "the image build failed"
  pass
fi

step "build the keepalived image and start the two nodes"
"${COMPOSE[@]}" build keepalived-a >/dev/null || bad "the keepalived image build failed"
"${COMPOSE[@]}" up -d >/dev/null || bad "compose up failed"
pass

step "a. each node answers on its own address"
for n in "${NODES[@]}"; do
  i=$([ "$n" = a ] && echo 11 || echo 12)
  end=$(( $(now_ms) + 120000 ))
  got=
  while [ "$(now_ms)" -lt "$end" ]; do
    got=$(who "$(dig_at "$SUBNET.$i" whoami.vip.home.arpa TXT)")
    [ "$got" = "telltale-$n" ] && break
    sleep 1
  done
  [ "$got" = "telltale-$n" ] || bad "node $n does not answer on $SUBNET.$i (got '$got')"
done
pass "telltale-a on .11, telltale-b on .12"

step "b. the VIP is held by a, and answers as telltale-a"
await_vip 60000 a || bad "the VIP $VIP does not answer as telltale-a within 60 s (owner: '$(vip_owner)')"
[ "$(vip_owner)" = a ] || bad "the VIP answers as telltale-a but is held by '$(vip_owner)'"
[ "$(dig_at "$VIP" gateway.vip.home.arpa A)" = 192.0.2.1 ] || bad "the A record does not answer through the VIP"
pass "owner a"

step "c. kill node a (TelltaleDNS and keepalived at once)"
t0=$(now_ms)
"${COMPOSE[@]}" kill telltale-a keepalived-a >/dev/null || bad "could not kill node a"
lost=0
took=
end=$(( t0 + 30000 ))
while [ "$(now_ms)" -lt "$end" ]; do
  if [ "$(who "$(dig_at "$VIP" whoami.vip.home.arpa TXT)")" = telltale-b ]; then
    took=$(( $(now_ms) - t0 ))
    break
  fi
  lost=$(( lost + 1 ))
  sleep 0.5
done
[ -n "$took" ] || bad "the VIP did not move to b within 30 s"
[ "$took" -le 15000 ] || bad "the VIP moved after ${took} ms (limit 15000 ms)"
[ "$(vip_owner)" = b ] || bad "the VIP answers as telltale-b but is held by '$(vip_owner)'"
ok_after=0
for _ in 1 2 3 4 5; do
  [ "$(who "$(dig_at "$VIP" whoami.vip.home.arpa TXT)")" = telltale-b ] && ok_after=$(( ok_after + 1 ))
done
[ "$ok_after" = 5 ] || bad "only $ok_after of 5 queries answered as telltale-b after the move"
[ "$(dig_at "$VIP" gateway.vip.home.arpa A)" = 192.0.2.1 ] || bad "the A record does not answer through the VIP after the move"
pass "the VIP moved to b after ${took} ms, $lost failed probes before the first answer, then 5 of 5 answered"

step "d. node a comes back and takes the VIP again"
"${COMPOSE[@]}" up -d >/dev/null || bad "compose up (node a) failed"
await_vip 60000 a || bad "node a did not take the VIP back within 60 s"
[ "$(vip_owner)" = a ] || bad "the VIP answers as telltale-a but is held by '$(vip_owner)'"
pass "owner a again"
echo "PASS: deploy/keepalived/e2e.sh"
