#!/usr/bin/env bash
# REQ: CLU-004, CLU-005, OPS-001, DNS-001, OPS-012 — the keepalived failover proof (deploy/keepalived,
# T24.4). On an isolated Docker bridge network (10.231.250.0/24, no route out):
#   0. node a creates a two-node cluster; node b joins it; the witness joins it; automatic
#      failover is turned on (the cluster needs the witness to promote on its own);
#   a. each node answers on its own address, and the answer names the node (NSID);
#   b. the VIP (10.231.250.10) is held by node a and answers as node a;
#   c. node a is killed hard (its TelltaleDNS and its keepalived, both at once): node b takes the VIP
#      within 15 s and answers every query after that, and the cluster promotes node b (the witness
#      and node b vote; the lease lapses first);
#   d. node a comes back: it takes the VIP again (keepalived preempts a backup with higher priority)
#      and steps down to a replica of node b in the cluster.
# Nothing here touches the LAN, the host network or any other compose project: its own project
# name (telltale-keepalived), its own bridge network, no published ports. Every container and the
# network are removed at exit, and the image too when this run built it.
#
# Usage: deploy/keepalived/e2e.sh                         (needs Docker with Compose v2, about 5 minutes)
#        TELLTALE_IMAGE=<image> deploy/keepalived/e2e.sh  (use an existing TelltaleDNS image)
#        KEEP=1 deploy/keepalived/e2e.sh                  (keeps the built image)
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
    for s in keepalived-a telltale-a keepalived-b telltale-b telltale-witness; do
      echo "--- $s"
      "${COMPOSE[@]}" --profile witness logs --no-color --tail 40 "$s" 2>&1 | sed 's/^/    /'
    done
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      echo "::error title=deploy/keepalived/e2e.sh::the keepalived failover run failed (the logs above)"
    fi
  fi
  "${COMPOSE[@]}" --profile witness down -v --remove-orphans >/dev/null 2>&1
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

# Runs a command until it succeeds, for up to budget_ms (polls every half second).
until_ok() { # budget_ms command...
  local budget=$1 end
  shift
  end=$(( $(now_ms) + budget ))
  while [ "$(now_ms)" -lt "$end" ]; do
    "$@" && return 0
    sleep 0.5
  done
  return 1
}

# The A record of a name at an address (the VIP, or a node's own address), or empty.
dig_at() { # address name type
  docker run --rm --network "$NET" --entrypoint dig "$KA_IMAGE" +time=1 +tries=1 +short "@$1" "$2" "$3" 2>/dev/null | head -n 1 || true
}

# The node that answered at an address: its name from the NSID option of the answer ([node] name),
# or empty when nothing answered.
node_at() { # address
  docker run --rm --network "$NET" --entrypoint dig "$KA_IMAGE" +time=1 +tries=1 +nsid "@$1" gateway.vip.home.arpa A 2>/dev/null \
    | sed -n 's/^; NSID: .*("\(.*\)").*$/\1/p' | head -n 1 || true
}

# One value of a node's Prometheus metric at an address (its metrics port 9153): the first sample of
# the metric whose line contains the label text, or any sample when no label text is given.
metric_at() { # address name [label-text]
  docker run --rm --network "$NET" --entrypoint wget "$KA_IMAGE" -q -O - "http://$1:9153/metrics" 2>/dev/null \
    | awk -v n="$2" -v l="${3:-}" 'index($0, n) == 1 && (l == "" || index($0, l) > 0) { print $NF; exit }' || true
}

# The checks for until_ok. Each one is a function, so until_ok runs it again on every poll: a command
# substitution written inline in the call would be evaluated once, before the first poll.
node_is() { [ "$(node_at "$1")" = "$2" ]; } # address node-name
metric_is() { [ "$(metric_at "$1" "$2" "$3")" = "$4" ]; } # address name label-text value

# The node that holds the VIP: a or b, or empty. The check runs inside each node's network namespace.
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

# A join token from node a's primary (reusable until it expires), for a node or the witness to join.
join_token() { # extra flags...
  "${COMPOSE[@]}" exec -T telltale-a /usr/local/bin/telltale cluster token create --ttl 30m "$@" \
    -c /etc/telltale/telltale.toml 2>/dev/null | tr -d '\r' | grep '^tt_join_' || true
}

# 0 when the VIP answers as the wanted node, for up to budget_ms.
vip_answers_as() { # budget_ms node
  until_ok "$1" node_is "$VIP" "telltale-$2"
}

step "the isolated network: $SUBNET.0/24 is free"
if docker network ls -q | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | grep -qF "$SUBNET.0/24"; then
  bad "$SUBNET.0/24 is already used by a Docker network; change the subnet in compose.yaml, the node files and this script"
fi
pass

"${COMPOSE[@]}" --profile witness down -v --remove-orphans >/dev/null 2>&1 || true

if [ -n "$BUILT_IMAGE" ]; then
  step "build the TelltaleDNS image from this checkout ($BUILT_IMAGE)"
  docker build --build-arg PROFILE=bench-fast --build-arg TELLTALE_BUILD_CHANNEL=dev \
    -t "$BUILT_IMAGE" "$ROOT_W" >/dev/null 2>&1 || bad "the image build failed"
  pass
fi

step "build the keepalived image and start the nodes"
"${COMPOSE[@]}" build keepalived-a >/dev/null 2>&1 || bad "the keepalived image build failed"
"${COMPOSE[@]}" up -d >/dev/null 2>&1 || bad "compose up failed"
healthy_nodes() { [ "$("${COMPOSE[@]}" ps --format '{{.Service}} {{.Health}}' 2>/dev/null | grep -c '^telltale-[ab] healthy$')" = 2 ]; }
until_ok 120000 healthy_nodes || bad "the two nodes did not come up healthy within 120 s"
pass

step "0. the cluster: a creates it, b joins, the witness joins, automatic failover is on"
TB=$(join_token --eligible)
[ -n "$TB" ] || bad "node a gave no join token"
"${COMPOSE[@]}" stop telltale-b >/dev/null 2>&1 || bad "could not stop node b to join it"
"${COMPOSE[@]}" run --rm -T --no-deps telltale-b cluster join "$TB" --site telltale-b --eligible \
  --advertise "https://$SUBNET.12:8443" -c /etc/telltale/telltale.toml >/dev/null 2>&1 || bad "node b couldn't join the cluster"
"${COMPOSE[@]}" start telltale-b >/dev/null 2>&1 || bad "node b didn't start after joining"
TW=$(join_token --witness)
[ -n "$TW" ] || bad "node a gave no witness token"
"${COMPOSE[@]}" --profile witness run --rm -T --no-deps telltale-witness cluster join "$TW" --witness \
  --site witness --advertise "https://$SUBNET.13:8443" -c /etc/telltale/telltale.toml >/dev/null 2>&1 \
  || bad "the witness couldn't join the cluster"
"${COMPOSE[@]}" --profile witness up -d telltale-witness >/dev/null 2>&1 || bad "the witness didn't start"
"${COMPOSE[@]}" exec -T telltale-a /usr/local/bin/telltale cluster set-failover auto -c /etc/telltale/telltale.toml >/dev/null 2>&1 \
  || bad "couldn't turn automatic failover on"
until_ok 120000 metric_is "$SUBNET.11" telltale_cluster_peer_up 'site="telltale-b"' 1 \
  || bad "node a doesn't see node b connected"
until_ok 120000 metric_is "$SUBNET.11" telltale_cluster_peer_up 'site="witness"' 1 \
  || bad "node a doesn't see the witness connected"
[ "$(metric_at "$SUBNET.11" telltale_cluster_primary)" = 1 ] || bad "node a is not the primary"
[ "$(metric_at "$SUBNET.12" telltale_cluster_primary)" = 0 ] || bad "node b thinks it is the primary"
until_ok 60000 metric_is "$SUBNET.12" telltale_cluster_failover_auto "" 1 || bad "node b doesn't have automatic failover on"
pass "primary a, replica b, witness connected, automatic failover on"

step "a. each node answers on its own address, and names itself"
for n in "${NODES[@]}"; do
  i=$([ "$n" = a ] && echo 11 || echo 12)
  until_ok 120000 node_is "$SUBNET.$i" "telltale-$n" || bad "node $n does not answer on $SUBNET.$i as telltale-$n"
done
pass "telltale-a on .11, telltale-b on .12"

step "b. the VIP is held by a, and answers as telltale-a"
vip_answers_as 60000 a || bad "the VIP $VIP does not answer as telltale-a within 60 s (owner: '$(vip_owner)')"
[ "$(vip_owner)" = a ] || bad "the VIP answers as telltale-a but is held by '$(vip_owner)'"
[ "$(dig_at "$VIP" gateway.vip.home.arpa A)" = 192.0.2.1 ] || bad "the A record does not answer through the VIP"
pass "owner a"

step "c. kill node a (TelltaleDNS and keepalived at once)"
t0=$(now_ms)
"${COMPOSE[@]}" kill telltale-a keepalived-a >/dev/null 2>&1 || bad "could not kill node a"
lost=0
took=
end=$(( t0 + 30000 ))
while [ "$(now_ms)" -lt "$end" ]; do
  if [ "$(node_at "$VIP")" = telltale-b ]; then
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
  [ "$(node_at "$VIP")" = telltale-b ] && ok_after=$(( ok_after + 1 ))
done
[ "$ok_after" = 5 ] || bad "only $ok_after of 5 queries answered as telltale-b after the move"
[ "$(dig_at "$VIP" gateway.vip.home.arpa A)" = 192.0.2.1 ] || bad "the A record does not answer through the VIP after the move"
pass "the VIP moved to b after ${took} ms, $lost failed probes before the first answer, then 5 of 5 answered"

until_ok 60000 metric_is "$SUBNET.12" telltale_cluster_primary "" 1 \
  || bad "the cluster did not promote node b within 60 s"
pass "the cluster promoted b (epoch $(metric_at "$SUBNET.12" telltale_cluster_epoch))"

step "d. node a comes back: it takes the VIP again and steps down to a replica"
"${COMPOSE[@]}" up -d >/dev/null 2>&1 || bad "compose up (node a) failed"
vip_answers_as 60000 a || bad "node a did not take the VIP back within 60 s (owner: '$(vip_owner)', answered by '$(node_at "$VIP")')"
[ "$(vip_owner)" = a ] || bad "the VIP answers as telltale-a but is held by '$(vip_owner)'"
until_ok 90000 metric_is "$SUBNET.11" telltale_cluster_primary "" 0 \
  || bad "node a did not step down to a replica within 90 s"
[ "$(metric_at "$SUBNET.12" telltale_cluster_primary)" = 1 ] || bad "node b lost the primary role"
pass "the VIP is back on a; a is a replica, b the primary"
echo "PASS: deploy/keepalived/e2e.sh"
