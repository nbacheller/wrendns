#!/usr/bin/env bash
# REQ: CLU-001, CLU-002, CLU-003, CLU-004, CLU-005, OPS-007, API-016, DNS-001, ADR-051, ADR-917,
# ADR-921, ADR-922, ADR-928, ADR-946 — the 3-node acceptance run (deploy/cluster3/README.md):
#   a. the three nodes join; the primary's /api/v1/cluster lists three connected nodes;
#   b. a config edit on the primary answers on all three nodes' DNS within 5 s;
#   c. a write on a replica's API is forwarded to the primary and reaches the other replica;
#   d. a secret set on the primary is readable on both replicas (a *_ref resolves), and no read
#      surface on any node, nor a log line, shows its value;
#   e. a router added on the primary appears on all nodes; the [discovery] first write goes
#      through with all three up, and a stopped member doesn't refuse it (ADR-928's rule);
#   f. queries sent to each node show up in the primary's query log, labelled by node, and in
#      the per-node top clients;
#   g. upstream #7 on the 2-CPU replica: with the primary paused, 20 concurrent reads each return
#      within 15 s, and /livez, /metrics and DNS keep answering; the primary is unpaused after;
#   h. failover with three nodes: the primary is killed, a survivor is promoted, the other follows,
#      DNS on both survivors keeps answering (0 SERVFAIL), an edit on the new primary reaches the
#      other survivor, and the old primary, started again, steps down and follows;
#   i. a rolling restart of each node in turn keeps at least two nodes answering DNS throughout.
#
# It never touches the single-node bundle (deploy/docker-desktop): its own compose project
# (telltale-cluster3), its own volumes, and host ports 2153-2353 (DNS), 8153-8353 (API), 9163-9363
# (metrics). Every credential is made here, in a temp directory that is removed at exit.
#
# Usage: deploy/cluster3/e2e.sh            (needs Docker with Compose v2, and python3)
#        KEEP=1 deploy/cluster3/e2e.sh     (keeps the test image and the temp directory)
set -euo pipefail

# Git Bash rewrites arguments that start with "/" into Windows paths; docker needs them as they are.
export MSYS_NO_PATHCONV=1

HERE=$(cd "$(dirname "$0")" && pwd)
# Docker and Python on Windows (Git Bash) need the Windows form of the same path.
HERE_W=$HERE
if command -v cygpath >/dev/null 2>&1; then HERE_W=$(cygpath -m "$HERE"); fi
PROJECT=telltale-cluster3
IMAGE=telltale:cluster3-test
COMPOSE=(docker compose -p "$PROJECT" -f "$HERE_W/compose.yaml")
PY=(python3 "$HERE_W/probe.py")
NODES=(primary replica-a replica-b)
declare -A DNS=([primary]=2153 [replica-a]=2253 [replica-b]=2353)
declare -A API=([primary]=8153 [replica-a]=8253 [replica-b]=8353)
declare -A MET=([primary]=9163 [replica-a]=9263 [replica-b]=9363)

E=$(mktemp -d)
# Python is a Windows program under Git Bash: give it the Windows form of the temp path.
E_PY=$E
if command -v cygpath >/dev/null 2>&1; then E_PY=$(cygpath -m "$E"); fi

cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [ "$rc" -ne 0 ]; then
    echo "--- the node logs (last 40 lines each)"
    for n in "${NODES[@]}"; do
      echo "--- $n"
      "${COMPOSE[@]}" logs --no-color --tail 40 "$n" 2>&1 | sed 's/^/    /'
    done
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      echo "::error title=deploy/cluster3/e2e.sh::the 3-node run failed (the logs above)"
    fi
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  if [ "${KEEP:-}" != 1 ]; then
    docker image rm "$IMAGE" >/dev/null 2>&1
    rm -rf "$E"
  else
    echo "KEEP=1: the image $IMAGE and the temp directory $E are kept"
  fi
  exit "$rc"
}
trap cleanup EXIT

step() { echo "== $1"; }
pass() { echo "ok${1:+ ($1)}"; }
bad() { echo "FAIL: $*"; exit 1; }
now_ms() { date +%s%3N; }

# The HTTP status and body of one API call on a node, as RS and RB. A session cookie per node.
RS= RB=
call() { # node METHOD PATH [json-file (a path in the temp directory)]
  local out body=
  if [ $# -ge 4 ]; then body="$E_PY/${4#"$E"/}"; fi
  if [ -n "$body" ]; then
    out=$("${PY[@]}" req "http://127.0.0.1:${API[$1]}" "$E_PY/jar-$1.json" "$2" "$3" "$body")
  else
    out=$("${PY[@]}" req "http://127.0.0.1:${API[$1]}" "$E_PY/jar-$1.json" "$2" "$3")
  fi
  RS=$(printf '%s\n' "$out" | sed -n 1p)
  RB=$(printf '%s\n' "$out" | sed '1d')
}

# 0 when the last body contains the fixed string.
has() { grep -qF -- "$1" <<<"$RB"; }

# A field of the last body: jget "d['items'][0]['name']".
jget() { printf '%s' "$RB" | python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

# The A answer of a node for a name: "NOERROR 10.0.0.1", "SERVFAIL -", or "TIMEOUT -".
dnsans() { "${PY[@]}" dns "${DNS[$1]}" "$2"; }

# 0 once a node answers name with ip; polls for up to budget_ms.
await_dns() { # budget_ms node name ip
  local end=$(( $(now_ms) + $1 ))
  while [ "$(now_ms)" -lt "$end" ]; do
    [ "$(dnsans "$2" "$3")" = "NOERROR $4" ] && return 0
    sleep 0.2
  done
  return 1
}

# How many nodes this node sees connected, as its own cluster view says.
connected_count() { # node
  call "$1" GET /api/v1/cluster
  jget 'sum(1 for n in d["nodes"] if n["connected"])' || echo 0
}

# 0 when a node's cluster view has the given count of connected nodes.
sees_connected() { [ "$(connected_count "$1")" = "$2" ]; }

# 0 when a node's cluster view has the primary connected (a replica's link to its primary).
primary_linked() { # node
  call "$1" GET /api/v1/cluster
  [ "$(jget 'next((str(n["connected"]) for n in d["nodes"] if n["role"] == "primary"), "")')" = True ]
}

# Writes a JSON file in the temp directory from a literal string.
put_json() { printf '%s' "$2" > "$E/$1"; }

# Sign in to a node: first admin (setup token as $2), or a later sign-in.
login() { # node [setup-token]
  local status
  if [ $# -ge 2 ]; then
    status=$("${PY[@]}" login "http://127.0.0.1:${API[$1]}" "$E_PY/jar-$1.json" "$E_PY/admin.txt" "$2")
  else
    status=$("${PY[@]}" login "http://127.0.0.1:${API[$1]}" "$E_PY/jar-$1.json" "$E_PY/admin.txt")
  fi
  [ "$status" = 200 ] || [ "$status" = 201 ]
}

# A join token from the primary, for a replica to join with (reusable until it expires).
join_token() {
  "${COMPOSE[@]}" exec -T primary /usr/local/bin/telltale cluster token create --ttl 30m --eligible \
    -c /etc/telltale/telltale.toml | tr -d '\r' | grep '^tt_join_'
}

container() { "${COMPOSE[@]}" ps -q "$1"; }

# ---------------------------------------------------------------------------------------------
# The admin's password and the secret the test writes: made now, held in the temp directory.
python3 -c "import secrets,sys; sys.stdout.write('Admin-' + secrets.token_urlsafe(18))" > "$E/admin.txt"
SECRET=$(python3 -c "import secrets; print('s3cr3t-' + secrets.token_hex(16))")
put_json secret.json "{\"value\":\"$SECRET\",\"kind\":\"text\"}"

step "bring-up: build the image and start the primary"
"${COMPOSE[@]}" up -d --build --wait primary >"$E/up.log" 2>&1 || { cat "$E/up.log"; bad "the primary didn't come up healthy"; }
pass

step "a. the three nodes join; the primary lists three connected nodes"
TOKEN=$(join_token)
[ -n "$TOKEN" ] || bad "no join token from the primary"
for r in replica-a replica-b; do
  "${COMPOSE[@]}" run --rm -T --no-deps "$r" cluster join "$TOKEN" --site "$r" --eligible \
    --advertise "https://$r:8443" -c /etc/telltale/telltale.toml >"$E/join-$r.log" 2>&1 \
    || { cat "$E/join-$r.log"; bad "$r couldn't join the cluster"; }
  "${COMPOSE[@]}" up -d --wait "$r" >/dev/null 2>&1 || bad "$r didn't come up healthy after joining"
done
SETUP=$("${COMPOSE[@]}" exec -T primary /usr/local/bin/telltale auth setup-token -c /etc/telltale/telltale.toml \
  | tr -d '\r' | sed -n 1p)
[ -n "$SETUP" ] || bad "no setup token on the primary"
login primary "$SETUP" || bad "the primary's first admin couldn't be created"
for _ in $(seq 120); do sees_connected primary 3 && break; sleep 0.5; done
for n in replica-a replica-b; do
  for _ in $(seq 120); do login "$n" && break; sleep 0.5; done
  login "$n" || bad "the admin made on the primary can't sign in on $n (users didn't replicate)"
  for _ in $(seq 120); do primary_linked "$n" && break; sleep 0.5; done
  primary_linked "$n" || bad "$n doesn't have its primary connected"
done
[ "$(connected_count primary)" = 3 ] || bad "the primary doesn't list three connected nodes"
pass "$(connected_count primary) connected nodes"

step "b. a config edit on the primary answers on all three nodes' DNS within 5 s"
put_json rec-ok.json '{"records":[{"type":"A","value":"10.0.0.1"}]}'
t0=$(now_ms)
call primary PUT /api/v1/records/ok.cluster3.test "$E/rec-ok.json"
[ "$RS" = 200 ] || bad "the record write on the primary answered $RS: $RB"
for n in "${NODES[@]}"; do
  budget=$(( 5000 - ($(now_ms) - t0) ))
  await_dns "$budget" "$n" ok.cluster3.test 10.0.0.1 || bad "$n doesn't answer the new record within 5 s"
done
pass "all three within $(( $(now_ms) - t0 )) ms"

step "c. a write on a replica's API reaches the primary and the other replica"
put_json rec-fwd.json '{"records":[{"type":"A","value":"10.0.0.2"}]}'
call replica-a PUT /api/v1/records/fwd.cluster3.test "$E/rec-fwd.json"
[ "$RS" = 200 ] || bad "a write on replica-a answered $RS (not forwarded): $RB"
for n in primary replica-b; do
  await_dns 10000 "$n" fwd.cluster3.test 10.0.0.2 || bad "$n doesn't answer the forwarded record"
done
call primary GET /api/v1/audit
has 'replica-a' || bad "the primary's audit log doesn't name the entry node"
pass

step "d. a secret set on the primary resolves on both replicas and is shown nowhere"
call primary PUT /api/v1/secrets/cluster3-router-key "$E/secret.json"
[ "$RS" = 200 ] || bad "the secret write on the primary answered $RS"
for n in replica-a replica-b; do
  for _ in $(seq 60); do call "$n" GET /api/v1/secrets/cluster3-router-key && [ "$RS" = 200 ] && break; sleep 0.5; done
  [ "$RS" = 200 ] || bad "$n doesn't have the secret ($RS)"
  has "$SECRET" && bad "$n's secret read shows the value"
done
# A replica's copy arrives by the cluster's replication (ADR-917), a few heartbeats after the write.
for n in replica-a replica-b; do
  for _ in $(seq 60); do
    "${COMPOSE[@]}" exec -T "$n" /usr/local/bin/telltale secrets status -c /etc/telltale/telltale.toml \
      >"$E/secrets-$n.txt" 2>&1 && grep -q '1 readable' "$E/secrets-$n.txt" && break
    sleep 0.5
  done
  grep -q '1 readable' "$E/secrets-$n.txt" || bad "$n's store doesn't hold the secret readable: $(cat "$E/secrets-$n.txt")"
  grep -q 'cluster3-router-key' "$E/secrets-$n.txt" || bad "$n's store doesn't list the secret by name"
done
# Read surfaces: every JSON API a viewer or admin reads, and the metrics, on every node.
for n in "${NODES[@]}"; do
  for path in /api/v1/secrets /api/v1/secrets/cluster3-router-key /api/v1/config/entries \
      /api/v1/cluster /api/v1/system/info /api/v1/audit; do
    call "$n" GET "$path" >/dev/null
    has "$SECRET" && bad "$n shows the secret's value on $path"
  done
  metrics=$(curl -s "http://127.0.0.1:${MET[$n]}/metrics")
  grep -qF "$SECRET" <<<"$metrics" && bad "$n's metrics show the value"
  logs=$("${COMPOSE[@]}" logs --no-color "$n" 2>&1)
  grep -qF "$SECRET" <<<"$logs" && bad "$n's log shows the value"
done
pass "readable on both replicas; not on any read surface or in any log"

step "e. a router added on the primary appears on all nodes; the [discovery] first write"
put_json router.json '{"type":"unifi","url":"https://127.0.0.1:9","api_key_ref":"cluster3-router-key"}'
call primary PUT /api/v1/routers/fake-unifi "$E/router.json"
[ "$RS" = 200 ] || bad "the router write on the primary answered $RS: $RB"
for n in "${NODES[@]}"; do
  for _ in $(seq 60); do call "$n" GET /api/v1/routers && has fake-unifi && break; sleep 0.5; done
  has fake-unifi || bad "the router isn't on $n"
done
put_json discovery.json '{"enabled":false}'
call primary PUT "/api/v1/discovery-settings/default?dryRun=true" "$E/discovery.json"
[ "$RS" = 200 ] || bad "the [discovery] first write (dry run, all three up) answered $RS: $RB"
"${COMPOSE[@]}" stop replica-b >/dev/null 2>&1
call primary PUT /api/v1/discovery-settings/default "$E/discovery.json"
[ "$RS" = 200 ] || bad "the [discovery] first write with replica-b stopped answered $RS: $RB (ADR-928 refuses only older or unreadable members)"
"${COMPOSE[@]}" up -d --wait replica-b >/dev/null 2>&1 || bad "replica-b didn't come back after the stop"
for _ in $(seq 120); do primary_linked replica-b && break; sleep 0.5; done
primary_linked replica-b || bad "replica-b doesn't see its primary again"
for _ in $(seq 60); do login replica-b && break; sleep 0.5; done
call replica-b GET /api/v1/discovery/status
has '"enabled":false' || bad "replica-b doesn't read the [discovery] section ($RS: $RB)"
pass "router on all three; first write accepted with all up and with replica-b stopped"

step "f. queries sent to each node show up on the primary, labelled by node"
for n in "${NODES[@]}"; do
  for _ in 1 2 3 4 5; do dnsans "$n" ok.cluster3.test >/dev/null; done
done
seen=""
for _ in $(seq 60); do
  call primary GET "/api/v1/queries?name=ok.cluster3.test&limit=500"
  seen=$(jget '" ".join(sorted({str(r.get("node")) for r in d["items"]}))')
  case "$seen" in *primary*replica-a*replica-b*) break ;; esac
  sleep 0.5
done
case "$seen" in *primary*replica-a*replica-b*) ;; *) bad "the primary's query log doesn't name all three nodes (got '$seen')" ;; esac
for n in "${NODES[@]}"; do
  call primary GET "/api/v1/stats/top?kind=clients&scope=node:$n"
  jget 'sum(i["count"] for i in d["items"])' | grep -qv '^0$' || bad "the top clients of $n are empty on the primary"
done
call primary GET /api/v1/stats/summary
both=$(jget 'd["queries"]')
call primary GET "/api/v1/stats/summary?scope=node:replica-a"
own=$(jget 'd["queries"]')
[ "$both" -gt "$own" ] || bad "cluster totals ($both) don't exceed replica-a's ($own)"
pass "queries from all three nodes; cluster $both, replica-a $own"

step "g. upstream #7: the 2-CPU replica answers while the primary is paused"
R_CID=$(container replica-a)
# The runtime's workers take the container's CPU quota (available_parallelism reads cgroup cpu.max):
# the log names the UDP workers, and the threads named telltale-rt (the runtime's workers and its
# blocking pool) are far fewer on the 2-CPU replica than on the 24-CPU primary.
threads=$(docker top "$R_CID" -eLo pid,lwp,comm 2>/dev/null | grep -c telltale-rt || true)
threads_p=$(docker top "$(container primary)" -eLo pid,lwp,comm 2>/dev/null | grep -c telltale-rt || true)
logs=$("${COMPOSE[@]}" logs --no-color replica-a 2>&1)
workers=$(grep -o 'workers=[0-9]*' <<<"$logs" | sed -n 1p || true)
echo "   replica-a: $workers, $threads telltale-rt threads; the 24-CPU primary has $threads_p"
[ "$workers" = workers=2 ] || bad "replica-a didn't start with 2 workers ($workers)"
[ "$threads" -le 12 ] && [ "$threads_p" -ge 24 ]   || bad "the runtime doesn't follow the 2-CPU quota ($threads telltale-rt threads on replica-a, $threads_p on the primary)"
docker pause "$(container primary)" >/dev/null
rc=0
"${PY[@]}" regression "http://127.0.0.1:${API[replica-a]}" "$E_PY/jar-replica-a.json" "${DNS[replica-a]}" \
  "http://127.0.0.1:${MET[replica-a]}" 25 15 >"$E/regression.json" || rc=$?
docker unpause "$(container primary)" >/dev/null
cat "$E/regression.json"
[ "$rc" = 0 ] || bad "the replica didn't answer within the bound while the primary was paused"
for _ in $(seq 120); do primary_linked replica-a && break; sleep 0.5; done
primary_linked replica-a || bad "replica-a doesn't see the primary again after the unpause"
pass

step "h. failover with three nodes: a survivor is promoted, the other follows"
"${COMPOSE[@]}" exec -T primary /usr/local/bin/telltale cluster set-failover auto -c /etc/telltale/telltale.toml >/dev/null \
  || bad "couldn't turn automatic failover on"
for _ in $(seq 120); do
  call replica-a GET /api/v1/cluster
  [ "$(jget 'd["failover"]["reachableVoters"]')" = 3 ] && break; sleep 0.5
done
[ "$(jget 'd["failover"]["reachableVoters"]')" = 3 ] || bad "replica-a doesn't reach all three voters"
docker kill "$(container primary)" >/dev/null
election=$("${PY[@]}" failover 40 20 replica-a "http://127.0.0.1:8253" 2253 "$E_PY/jar-replica-a.json" \
  replica-b "http://127.0.0.1:8353" 2353 "$E_PY/jar-replica-b.json")
echo "$election"
new=$(printf '%s' "$election" | python3 -c "import json,sys; print(json.load(sys.stdin)['first_primary']['who'] or '')")
[ -n "$new" ] || bad "no survivor was promoted"
other=replica-a; [ "$new" = replica-a ] && other=replica-b
servfail=$(printf '%s' "$election" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(v['servfail'] for v in d['loops'].values()))")
loss=$(printf '%s' "$election" | python3 -c "
import json,sys
d=json.load(sys.stdin)
sent=sum(v['sent'] for v in d['loops'].values()); ok=sum(v['ok'] for v in d['loops'].values())
print(f'{100.0*(sent-ok)/max(sent,1):.2f}% ({sent-ok} of {sent} not answered)')")
echo "   survivors' loss: $loss"
[ "$servfail" = 0 ] || bad "$servfail SERVFAIL answers during the failover (cluster-caused)"
put_json rec-fo.json '{"records":[{"type":"A","value":"10.0.0.9"}]}'
call "$new" PUT /api/v1/records/after-failover.cluster3.test "$E/rec-fo.json"
[ "$RS" = 200 ] || bad "an edit on the new primary $new answered $RS: $RB"
await_dns 10000 "$other" after-failover.cluster3.test 10.0.0.9 || bad "$other doesn't follow the new primary"
"${COMPOSE[@]}" up -d --wait primary >/dev/null 2>&1 || bad "the old primary didn't come back"
# A session from before the kill may be gone: sign in again.
for _ in $(seq 60); do login primary && break; sleep 0.5; done
for _ in $(seq 120); do
  call primary GET /api/v1/cluster
  [ "$(jget 'next((n["role"] for n in d["nodes"] if n["thisNode"]), "")')" = replica ] && break
  sleep 0.5
done
[ "$(jget 'next((n["role"] for n in d["nodes"] if n["thisNode"]), "")')" = replica ] \
  || bad "the old primary didn't step down (status $RS: ${RB:0:300})"
await_dns 30000 primary after-failover.cluster3.test 10.0.0.9 || bad "the old primary doesn't follow the new one"
pass "promoted $new in $(printf '%s' "$election" | python3 -c "import json,sys; print(json.load(sys.stdin)['first_primary']['at'])") s; loss $loss; old primary follows"

step "i. rolling restart: each node in turn, at least two nodes answer DNS throughout"
"${PY[@]}" rolling 2 60 "${COMPOSE[@]}" -- primary:2153 replica-a:2253 replica-b:2353 >"$E/rolling.json" \
  || { cat "$E/rolling.json"; bad "fewer than two nodes answered during the rolling restart"; }
cat "$E/rolling.json"
pass

echo "== all checks passed"
