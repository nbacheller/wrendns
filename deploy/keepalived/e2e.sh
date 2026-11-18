#!/usr/bin/env bash
# REQ: CLU-004, CLU-005, OPS-001, DNS-001, OPS-010, OPS-012 — the keepalived failover proof
# (deploy/keepalived, T24.4). On an isolated Docker bridge network (10.231.250.0/24, no route out):
#   0. node a creates a two-node cluster; node b joins it; the witness joins it; automatic
#      failover is turned on (the cluster needs the witness to promote on its own); an admin is made
#      on node a, and users replicate to the other nodes;
#   a. each node answers on its own address, and the answer names the node (NSID);
#   b. the VIP (10.231.250.10) is held by node a and answers as node a;
#   c. node a is killed hard (its TelltaleDNS and its keepalived, both at once): node b takes the VIP
#      within 15 s and answers every query after that, and the cluster promotes node b (the witness
#      and node b vote; the lease lapses first);
#   d. node a comes back: it takes the VIP again (keepalived preempts a backup with higher priority)
#      and steps down to a replica of node b in the cluster;
#   f. the second network (T24.32): the same two nodes are also on 10.231.251.0/24 with a second VIP
#      (10.231.251.10, its own VRRP instance): what a pair on two VLANs looks like. The listeners on
#      the wildcard answer there too (UDP and TCP), both VIPs sit on node a, both move to node b when
#      a is killed and both come back; in maintenance both move.
#   e. node a goes into maintenance through the API: /readyz answers 503, the VIP moves to b while
#      a keeps answering on its own address, and when the window ends the VIP returns to a (the
#      runbook in docs/running.md relies on this).
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
# The second network and its VIP (T24.32): the pair's second VLAN.
SUBNET2=10.231.251
VIP2=$SUBNET2.10
NET=${PROJECT}_vip
NET2=${PROJECT}_vip2
KA_IMAGE=telltale-keepalived:alpine-3.20
# The keepalived image is removed at exit unless it was there before this run (REQ: OPS-010).
KA_PRESENT=0
docker image inspect "$KA_IMAGE" >/dev/null 2>&1 && KA_PRESENT=1
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
# The admin of the test cluster: made on node a, with a password that is random per run (never printed).
ADMIN_PASSWORD=$(python3 -c "import secrets; print('Admin-' + secrets.token_urlsafe(18))")
COOKIE=
CSRF=

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
  if [ "$KA_PRESENT" != 1 ]; then
    docker image rm "$KA_IMAGE" >/dev/null 2>&1
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

# The Docker network an address is on: the second VLAN's, or the first.
net_for() { # address
  case "$1" in "$SUBNET2".*) echo "$NET2" ;; *) echo "$NET" ;; esac
}

# The A record of a name at an address (the VIP, or a node's own address), or empty.
dig_at() { # address name type
  docker run --rm --network "$(net_for "$1")" --entrypoint dig "$KA_IMAGE" +time=1 +tries=1 +short "@$1" "$2" "$3" 2>/dev/null | head -n 1 || true
}

# The node that answered at an address: its name from the NSID option of the answer ([node] name),
# or empty when nothing answered.
node_at() { # address
  docker run --rm --network "$(net_for "$1")" --entrypoint dig "$KA_IMAGE" +time=1 +tries=1 +nsid "@$1" gateway.vip.home.arpa A 2>/dev/null \
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

# The node that holds a VIP (the first network's unless one is given): a or b, or empty. The check
# runs inside each node's network namespace, on whichever interface carries the address.
vip_owner() { # [vip]
  local n v=${1:-$VIP}
  for n in "${NODES[@]}"; do
    if "${COMPOSE[@]}" exec -T "keepalived-$n" ip -4 addr show 2>/dev/null | grep -qF "inet $v/"; then
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

# Makes the admin on a node with its setup token (node a is the primary, so the users replicate).
make_admin() { # address
  local setup status
  setup=$("${COMPOSE[@]}" exec -T telltale-a /usr/local/bin/telltale auth setup-token -c /etc/telltale/telltale.toml 2>/dev/null | tr -d '\r' | sed -n 1p)
  [ -n "$setup" ] || return 1
  status=$(docker run --rm --network "$NET" --entrypoint curl "$KA_IMAGE" -s -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d "{\"setupToken\":\"$setup\",\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" \
    "http://$1:8053/api/v1/auth/setup" 2>/dev/null || true)
  [ "$status" = 200 ] || [ "$status" = 201 ]
}

# Signs in as the admin on a node: sets COOKIE and CSRF. Fails when the sign-in is refused.
admin_login() { # address
  local out
  out=$(docker run --rm --network "$NET" --entrypoint curl "$KA_IMAGE" -s -i -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" "http://$1:8053/api/v1/auth/login" 2>/dev/null) || return 1
  COOKIE=$(sed -n 's/^[Ss]et-[Cc]ookie: \(telltale_session=[^;]*\).*/\1/p' <<<"$out" | tr -d '\r' | head -n 1)
  CSRF=$(sed -n 's/.*"csrfToken":"\([^"]*\)".*/\1/p' <<<"$out" | head -n 1)
  [ -n "$COOKIE" ] && [ -n "$CSRF" ]
}

# An API call as the signed-in admin on a node: address method path [json-body]. Prints the body, then
# the HTTP status on the last line.
admin_api() {
  local args=(-s -w '\n%{http_code}' -X "$2" -H "Cookie: $COOKIE" -H "X-CSRF-Token: $CSRF")
  if [ -n "${4:-}" ]; then args+=(-H 'Content-Type: application/json' -d "$4"); fi
  docker run --rm --network "$NET" --entrypoint curl "$KA_IMAGE" "${args[@]}" "http://$1:8053$3" 2>/dev/null || true
}

# The HTTP status of an admin_api answer, and its body (the first 300 characters, for a failure message).
api_status() { tail -n 1 <<<"$1"; }
api_body() { head -n -1 <<<"$1" | head -c 300; }

# 0 when the VIP answers as the wanted node, for up to budget_ms.
vip_answers_as() { # budget_ms node
  until_ok "$1" node_is "$VIP" "telltale-$2"
}

# 0 when both VIPs answer as the wanted node and are held by it, for up to budget_ms (T24.32).
both_vips_as() { # budget_ms node
  vip_answers_as "$1" "$2" && until_ok "$1" node_is "$VIP2" "telltale-$2" \
    && [ "$(vip_owner "$VIP")" = "$2" ] && [ "$(vip_owner "$VIP2")" = "$2" ]
}

"${COMPOSE[@]}" --profile witness down -v --remove-orphans >/dev/null 2>&1 || true

step "the isolated networks: $SUBNET.0/24 and $SUBNET2.0/24 are free"
for net in "$SUBNET" "$SUBNET2"; do
  if docker network ls -q | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | grep -qF "$net.0/24"; then
    bad "$net.0/24 is already used by a Docker network; change the subnet in compose.yaml, the node files and this script"
  fi
done
pass

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

step "0. the cluster: a creates it, b joins, the witness joins, automatic failover is on, an admin is made"
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
make_admin "$SUBNET.11" || bad "the admin couldn't be made on node a"
pass "primary a, replica b, witness connected, automatic failover on, admin made"

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

step "f. the second network: each node answers on its own address there, and both VIPs are held by a"
for n in "${NODES[@]}"; do
  i=$([ "$n" = a ] && echo 11 || echo 12)
  until_ok 60000 node_is "$SUBNET2.$i" "telltale-$n" || bad "node $n does not answer on $SUBNET2.$i as telltale-$n"
done
both_vips_as 60000 a || bad "the VIPs $VIP and $VIP2 are not both held by a and answering as telltale-a (owners: '$(vip_owner "$VIP")' and '$(vip_owner "$VIP2")')"
[ "$(dig_at "$VIP2" gateway.vip.home.arpa A)" = 192.0.2.1 ] || bad "the A record does not answer through the second VIP"
# TCP on the second VIP too: the wildcard TCP listener answers on every interface.
tcp_ok=$(docker run --rm --network "$NET2" --entrypoint dig "$KA_IMAGE" +tcp +time=2 +tries=1 +short "@$VIP2" gateway.vip.home.arpa A 2>/dev/null | head -n 1 || true)
[ "$tcp_ok" = 192.0.2.1 ] || bad "TCP to the second VIP does not answer (got '$tcp_ok')"
pass "telltale-a on $SUBNET2.11, telltale-b on $SUBNET2.12, both VIPs on a, UDP and TCP answer on the second"

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
# The second VIP moves on the same health check (T24.32).
until_ok 15000 node_is "$VIP2" telltale-b || bad "the second VIP $VIP2 did not move to b (owner: '$(vip_owner "$VIP2")')"
[ "$(vip_owner "$VIP2")" = b ] || bad "the second VIP answers as telltale-b but is held by '$(vip_owner "$VIP2")'"
[ "$(dig_at "$VIP2" gateway.vip.home.arpa A)" = 192.0.2.1 ] || bad "the A record does not answer through the second VIP after the move"
pass "both VIPs are on b"

until_ok 60000 metric_is "$SUBNET.12" telltale_cluster_primary "" 1 \
  || bad "the cluster did not promote node b within 60 s"
pass "the cluster promoted b (epoch $(metric_at "$SUBNET.12" telltale_cluster_epoch))"

step "d. node a comes back: it takes the VIP again and steps down to a replica"
"${COMPOSE[@]}" up -d >/dev/null 2>&1 || bad "compose up (node a) failed"
vip_answers_as 60000 a || bad "node a did not take the VIP back within 60 s (owner: '$(vip_owner)', answered by '$(node_at "$VIP")')"
[ "$(vip_owner)" = a ] || bad "the VIP answers as telltale-a but is held by '$(vip_owner)'"
both_vips_as 60000 a || bad "the second VIP did not come back to a with the first (owner: '$(vip_owner "$VIP2")')"
until_ok 90000 metric_is "$SUBNET.11" telltale_cluster_primary "" 0 \
  || bad "node a did not step down to a replica within 90 s"
[ "$(metric_at "$SUBNET.12" telltale_cluster_primary)" = 1 ] || bad "node b lost the primary role"
pass "both VIPs are back on a; a is a replica, b the primary"

step "e. maintenance on a hands the VIP to b, and ending it brings the VIP back"
admin_login "$SUBNET.11" || bad "the admin can't sign in on node a"
out=$(admin_api "$SUBNET.11" POST /api/v1/nodes/local/maintenance '{"forSecs":300,"reason":"keepalived e2e"}')
[ "$(api_status "$out")" = 200 ] || bad "could not start maintenance on node a (HTTP $(api_status "$out"): $(api_body "$out"))"
until_ok 30000 node_is "$VIP" telltale-b || bad "the VIP did not move to b while a is in maintenance (owner: '$(vip_owner)')"
[ "$(vip_owner)" = b ] || bad "the VIP answers as telltale-b but is held by '$(vip_owner)'"
both_vips_as 30000 b || bad "the second VIP did not move to b with the first while a is in maintenance (owner: '$(vip_owner "$VIP2")')"
[ "$(node_at "$SUBNET2.11")" = telltale-a ] || bad "node a stopped answering on its own second-network address during maintenance"
[ "$(node_at "$SUBNET.11")" = telltale-a ] || bad "node a stopped answering on its own address during maintenance"
# The first identity sync from the primary after node a rejoined replaces the admin that node a made
# locally, and that ends its sessions (crates/telltale-store identity import). It can land between
# the two calls, so the session is made again before the call that ends maintenance.
admin_login "$SUBNET.11" || bad "the admin can't sign in on node a before ending maintenance"
out=$(admin_api "$SUBNET.11" DELETE /api/v1/nodes/local/maintenance)
[ "$(api_status "$out")" = 200 ] || bad "could not end maintenance on node a (HTTP $(api_status "$out"): $(api_body "$out"))"
both_vips_as 60000 a || bad "the VIPs did not both come back to a after maintenance ended (owners: '$(vip_owner)' and '$(vip_owner "$VIP2")')"
pass "both VIPs moved to b in maintenance and back to a after it, and a kept answering on its own addresses"

echo "PASS: deploy/keepalived/e2e.sh"
