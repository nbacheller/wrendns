#!/usr/bin/env bash
# REQ: CLU-001, CLU-002, CLU-003, CLU-004, CLU-005, OPS-007, API-016, DNS-001, ADR-051, ADR-917,
# ADR-921, ADR-922, ADR-928, ADR-946 — the 3-node acceptance run (deploy/cluster3/README.md):
#   a. the three nodes join; the primary's /api/v1/cluster lists three connected nodes;
#   b. a config edit on the primary answers on all three nodes' DNS within 5 s;
#   c. a write on a replica's API is forwarded to the primary and reaches the other replica;
#   d. a secret set on the primary is readable on both replicas (a *_ref resolves), and no read
#      surface on any node (each answers 200), nor a log line, shows its value;
#   e. a router added on the primary appears on all nodes; the [discovery] first write goes
#      through with all three up, and a stopped member doesn't refuse it (ADR-928's rule); replica-b
#      then reads back a non-default [discovery] value (48 MiB);
#   f. queries sent to each node show up in the primary's query log, labelled by node, and in
#      the per-node top clients;
#   g. upstream #7 on the 2-CPU replica: with the primary paused, 20 concurrent reads each return
#      within 15 s, and /livez, /metrics and DNS keep answering; replica-a's runtime starts with
#      two workers; the primary is unpaused after;
#   h. failover with three nodes: an upstream is added on the lease holder (T24.37), which is killed, a survivor is promoted 5 to
#      40 s later, the other follows, DNS on both survivors keeps answering (0 SERVFAIL), an edit on
#      the new primary reaches the other survivor, the upstream added through the old primary is deleted on the
#      new one and stays deleted, and the killed node, started again, steps down;
#   i. a rolling restart of each node in turn keeps at least two nodes answering DNS throughout;
#   j. (T24.38) after a rolling restart in the owner's order (replicas, then the primary) every node
#      reports reachableVoters = voters for 1 minute with no "leaving this node" churn, and the
#      primary's death is still an election within the lease time, with no flapping after it.
# And, between a and b, a2: in manual failover each replica reports the other as up (relayed by the
# primary), then `set-failover auto` on the running primary is adopted with no restart: it holds a
# lease, keeps its role and its epoch, and no replica stands for 45 s.
# Automatic failover is turned on after the replicas join, under the running cluster (a2): the
# primary adopts it without a restart and no replica deposes it (T21.7, ADR-960).
#
# It never touches the single-node bundle (deploy/docker-desktop): its own compose project
# (telltale-cluster3), its own volumes, and host ports 2153-2353 (DNS), 8153-8353 (API), 9163-9363
# (metrics). Every credential is made here, in a temp directory that is removed at exit.
#
# Usage: deploy/cluster3/e2e.sh            (needs Docker with Compose v2, and python3)
#        J_WATCH_S=20 deploy/cluster3/e2e.sh   (a shorter watch in check j; the default is 60 s)
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
  # An interrupted check (g) can leave the primary paused: unpause first, then tear down.
  "${COMPOSE[@]}" unpause >/dev/null 2>&1
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

# The value of one unlabelled metric on a node's metrics port (empty when it isn't served).
metric() { # metrics-port name
  curl -s --max-time 2 "http://127.0.0.1:$1/metrics" | awk -v n="$2" '$1 == n {print $2}'
}

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

step "a2. automatic failover is turned on under the running cluster: no restart, no deposition"
# Manual mode first: a replica has a stream only to its primary, and reports the other replica up
# from the heartbeats the primary relays (T21.5 open (1)).
for n in replica-a replica-b; do
  ok=
  for _ in $(seq 60); do
    call "$n" GET /api/v1/cluster
    [ "$(jget 'next((str(c["ok"]) for c in d["checks"] if c["id"] == "peers_up"), "")')" = True ]       && [ "$(jget 'sum(1 for x in d["nodes"] if x["up"])')" = 3 ] && { ok=1; break; }
    sleep 1
  done
  [ -n "$ok" ] || bad "$n doesn't report all three nodes up in manual mode: $(jget '[(x["site"], x["up"], x["link"]) for x in d["nodes"]]')"
done
epoch0=$(metric "${MET[primary]}" telltale_cluster_epoch)
[ "$(metric "${MET[primary]}" telltale_cluster_primary)" = 1 ] || bad "the primary isn't primary before the switch"
"${COMPOSE[@]}" exec -T primary /usr/local/bin/telltale cluster set-failover auto -c /etc/telltale/telltale.toml >/dev/null   || bad "couldn't turn automatic failover on"
for n in "${NODES[@]}"; do
  ok=
  for _ in $(seq 60); do
    [ "$(metric "${MET[$n]}" telltale_cluster_failover_auto)" = 1 ] && { ok=1; break; }
    sleep 0.5
  done
  [ -n "$ok" ] || bad "$n never adopted automatic failover"
done
ok=
for _ in $(seq 40); do
  [ "$(metric "${MET[primary]}" telltale_cluster_lease_held)" = 1 ] && { ok=1; break; }
  sleep 0.5
done
[ -n "$ok" ] || bad "the running primary never held a lease after the switch"
# 45 s: longer than a replica's wait (15 s) plus a lease (15 s). The primary stays primary, in the
# same epoch, with its lease; the replicas never become primary.
for i in $(seq 45); do
  [ "$(metric "${MET[primary]}" telltale_cluster_primary)" = 1 ] || bad "the primary was deposed ($i s after the switch)"
  [ "$(metric "${MET[primary]}" telltale_cluster_epoch)" = "$epoch0" ] || bad "the epoch moved ($i s after the switch)"
  for n in replica-a replica-b; do
    [ "$(metric "${MET[$n]}" telltale_cluster_primary)" = 0 ] || bad "$n stood for election ($i s after the switch)"
  done
  sleep 1
done
[ "$(metric "${MET[primary]}" telltale_cluster_lease_held)" = 1 ] || bad "the primary's lease isn't held after 45 s"
pass "epoch $epoch0 kept; the primary holds its lease"

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
    call "$n" GET "$path"
    [ "$RS" = 200 ] || bad "$n answered $RS on $path (a read surface that isn't served proves nothing)"
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
put_json discovery.json '{"enabled":false,"worker_memory_mib":48}'
call primary PUT "/api/v1/discovery-settings/default?dryRun=true" "$E/discovery.json"
[ "$RS" = 200 ] || bad "the [discovery] first write (dry run, all three up) answered $RS: $RB"
"${COMPOSE[@]}" stop replica-b >/dev/null 2>&1
call primary PUT /api/v1/discovery-settings/default "$E/discovery.json"
[ "$RS" = 200 ] || bad "the [discovery] first write with replica-b stopped answered $RS: $RB (ADR-928 refuses only older or unreadable members)"
"${COMPOSE[@]}" up -d --wait replica-b >/dev/null 2>&1 || bad "replica-b didn't come back after the stop"
for _ in $(seq 120); do primary_linked replica-b && break; sleep 0.5; done
primary_linked replica-b || bad "replica-b doesn't see its primary again"
for _ in $(seq 60); do login replica-b && break; sleep 0.5; done
# A value that isn't the default (48 MiB; the default is 64), read on a replica: the read is not
# trivially true, since the default would not show 48.
call replica-b GET "/api/v1/config/entries?kind=discovery"
[ "$RS" = 200 ] || bad "replica-b's configuration read answered $RS: ${RB:0:300}"
has '"worker_memory_mib":48' || bad "replica-b doesn't read the [discovery] value it was given (48 MiB)"
pass "router on all three; first write accepted with all up and with replica-b stopped; replica-b reads 48 MiB"

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
# The runtime's own worker count, logged at start (runtime_workers). Its default follows the
# container's CPU quota (cgroup cpu.max), so the 2-CPU replica must start with two. The UDP workers
# (workers=) are a different count and are not asserted here.
logs=$("${COMPOSE[@]}" logs --no-color replica-a 2>&1)
workers=$(grep -o 'runtime_workers=[0-9]*' <<<"$logs" | sed -n 1p || true)
logs_p=$("${COMPOSE[@]}" logs --no-color primary 2>&1)
workers_p=$(grep -o 'runtime_workers=[0-9]*' <<<"$logs_p" | sed -n 1p || true)
echo "   replica-a: $workers; the primary: $workers_p"
[ "$workers" = runtime_workers=2 ] || bad "replica-a's runtime didn't start with 2 workers ($workers)"
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

step "h. failover with three nodes: the lease holder is killed, a survivor is promoted, the other follows"
for _ in $(seq 120); do
  call replica-a GET /api/v1/cluster
  [ "$(jget 'd["failover"]["reachableVoters"]')" = 3 ] && break; sleep 0.5
done
[ "$(jget 'd["failover"]["reachableVoters"]')" = 3 ] || bad "replica-a doesn't reach all three voters"
# The lease holder is whichever node the cluster has now: check (g) paused the primary for longer
# than its lease, and with automatic failover on that is a promotion (the lease lapsed). Wait for
# one node that is primary and holds its lease; the other two must not be primary.
killed=
for _ in $(seq 120); do
  for n in "${NODES[@]}"; do
    if [ "$(metric "${MET[$n]}" telltale_cluster_primary)" = 1 ] \
      && [ "$(metric "${MET[$n]}" telltale_cluster_lease_held)" = 1 ]; then killed=$n; fi
  done
  [ -n "$killed" ] && break
  sleep 0.5
done
[ -n "$killed" ] || bad "no node holds the lease before the kill"
survivors=()
fo=()
for n in "${NODES[@]}"; do
  [ "$n" = "$killed" ] && continue
  [ "$(metric "${MET[$n]}" telltale_cluster_primary)" = 0 ] || bad "$n is primary before the kill"
  survivors+=("$n")
  fo+=("$n" "http://127.0.0.1:${API[$n]}" "${DNS[$n]}" "$E_PY/jar-$n.json")
done
# The kill takes the lease holder, so the election below is the lease running out (CLU-005), not a
# replica dying.
# A survivor's session from before may be gone (a node that stepped down in check g): sign in again,
# so the poll reads the cluster's view and not a 401.
for n in "${survivors[@]}"; do
  login "$n" || bad "$n's administrator can't sign in before the kill"
done
# T24.37 (ADR-1016): an upstream added through the API on the lease holder, which is killed next.
put_json up-fo.json '{"url":"udp://192.0.2.37"}'
call "$killed" PUT /api/v1/upstreams/t2437-fo "$E/up-fo.json"
[ "$RS" = 200 ] || bad "adding an upstream on $killed answered $RS: $RB"
for n in "${survivors[@]}"; do
  for _ in $(seq 60); do call "$n" GET /api/v1/upstreams; has '"t2437-fo"' && break; sleep 0.5; done
  has '"t2437-fo"' || bad "$n doesn't list the upstream added on $killed"
done
docker kill "$(container "$killed")" >/dev/null
election=$("${PY[@]}" failover 40 20 "${fo[@]}")
echo "$election"
new=$(printf '%s' "$election" | python3 -c "import json,sys; print(json.load(sys.stdin)['first_primary']['who'] or '')")
[ -n "$new" ] || bad "no survivor was promoted"
first_at=$(printf '%s' "$election" | python3 -c "import json,sys; print(json.load(sys.stdin)['first_primary']['at'])")
# The lease runs 15 s (renewed every 5 s), so a promotion can't come within a few seconds of the kill,
# and it comes once the lease runs out, well inside the probe's window.
python3 -c "import sys; a=float(sys.argv[1]); sys.exit(0 if 5 <= a <= 40 else 1)" "$first_at" \
  || bad "the promotion came at $first_at s after the kill (expected 5 to 40 s, the lease running out)"
other=${survivors[0]}; [ "$new" = "${survivors[0]}" ] && other=${survivors[1]}
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
# T24.37 (ADR-1016): the entry the old primary's API added is the new primary's to delete (it answered
# 404 before), and it is gone on the other survivor.
call "$new" DELETE /api/v1/upstreams/t2437-fo?dryRun=true
[ "$RS" = 200 ] || bad "a dry-run delete on the new primary $new answered $RS: $RB"
call "$new" DELETE /api/v1/upstreams/t2437-fo
[ "$RS" = 200 ] || bad "deleting an upstream the old primary added, on the new primary $new, answered $RS: $RB"
for n in "$new" "$other"; do
  for _ in $(seq 60); do call "$n" GET /api/v1/upstreams; has '"t2437-fo"' || break; sleep 0.5; done
  ! has '"t2437-fo"' || bad "$n still lists the deleted upstream"
done
"${COMPOSE[@]}" up -d --wait "$killed" >/dev/null 2>&1 || bad "the old primary $killed didn't come back"
# A session from before the kill may be gone: sign in again.
for _ in $(seq 60); do login "$killed" && break; sleep 0.5; done
for _ in $(seq 120); do
  call "$killed" GET /api/v1/cluster
  [ "$(jget 'next((n["role"] for n in d["nodes"] if n["thisNode"]), "")')" = replica ] && break
  sleep 0.5
done
[ "$(jget 'next((n["role"] for n in d["nodes"] if n["thisNode"]), "")')" = replica ] \
  || bad "the old primary $killed didn't step down (status $RS: ${RB:0:300})"
await_dns 30000 "$killed" after-failover.cluster3.test 10.0.0.9 || bad "the old primary $killed doesn't follow the new one"
# T24.37: the old primary kept the upstream in its own store; following the new primary, it must not
# bring it back.
for _ in $(seq 60); do call "$killed" GET /api/v1/upstreams; has '"t2437-fo"' || break; sleep 0.5; done
! has '"t2437-fo"' || bad "the old primary $killed brought the deleted upstream back"
pass "$killed (the lease holder) killed; $new promoted at $first_at s after the kill; loss $loss; the old primary follows"

step "i. rolling restart: each node in turn, at least two nodes answer DNS throughout"
"${PY[@]}" rolling 2 60 "${COMPOSE[@]}" -- primary:2153 replica-a:2253 replica-b:2353 >"$E/rolling.json" \
  || { cat "$E/rolling.json"; bad "fewer than two nodes answered during the rolling restart"; }
cat "$E/rolling.json"
pass

step "j. replicas stay linked (T24.38): after a rolling restart (replicas, then the primary) every node reaches every voter for 3 minutes, with no link churn; the primary's death is still an election"
# The owner's upgrade order on 2026-11-18: the replicas first, then the primary. The bug: a replica
# that fell back to another replica while the primary restarted lost the voter link between the two
# replicas for good (one stream's end marked the peer disconnected and took the other's place in the
# outbox), so reachableVoters stayed at 2 and the replicas moved between the primary and each other.
cur=
for n in "${NODES[@]}"; do [ "$(metric "${MET[$n]}" telltale_cluster_primary)" = 1 ] && cur=$n; done
[ -n "$cur" ] || bad "no node is primary before the restart"
order=()
for n in "${NODES[@]}"; do [ "$n" = "$cur" ] || order+=("$n"); done
order+=("$cur")
for n in "${order[@]}"; do
  "${COMPOSE[@]}" stop "$n" >/dev/null 2>&1
  sleep 2
  "${COMPOSE[@]}" up -d --wait "$n" >/dev/null 2>&1 || bad "$n didn't come back after its restart"
  sleep 4
done
for n in "${NODES[@]}"; do
  for _ in $(seq 60); do login "$n" && break; sleep 0.5; done
done
# The cluster settles: every node reaches every voter and holds the primary's lease picture.
voters_ok() { # node: 0 when its failover view reaches every voter
  call "$1" GET /api/v1/cluster
  [ "$(jget 'd["failover"]["reachableVoters"] == d["failover"]["voters"] and d["failover"]["voters"] == 3')" = True ]
}
for n in "${NODES[@]}"; do
  for _ in $(seq 240); do voters_ok "$n" && break; sleep 0.5; done
  voters_ok "$n" || bad "$n doesn't reach all three voters after the rolling restart (${RB:0:300})"
done
churn() { "${COMPOSE[@]}" logs --no-color "$1" 2>&1 | grep -c 'leaving this node' || true; }
declare -A LEFT
for n in "${NODES[@]}"; do LEFT[$n]=$(churn "$n"); done
end=$(( $(now_ms) + ${J_WATCH_S:-60} * 1000 ))
samples=0
while [ "$(now_ms)" -lt "$end" ]; do
  for n in "${NODES[@]}"; do
    voters_ok "$n" || bad "$n lost a voter during the 3 minutes after the rolling restart (${RB:0:300})"
  done
  samples=$((samples + 1))
  sleep 5
done
for n in "${NODES[@]}"; do
  now_left=$(churn "$n")
  [ "$now_left" = "${LEFT[$n]}" ] || bad "$n left a node to move back to the primary $((now_left - LEFT[$n])) times in the 3 minutes (link churn)"
  call "$n" GET /api/v1/cluster
  [ "$(jget 'len(d["failover"]["unstableVoters"])')" = 0 ] || bad "$n reports a voter whose link comes and goes: $(jget 'd["failover"]["unstableVoters"]')"
done
echo "   $samples samples, every node reached 3 of 3 voters each time; no link churn"
# The primary dies: an election within the lease time, and nobody flaps afterwards.
killed=
for n in "${NODES[@]}"; do [ "$(metric "${MET[$n]}" telltale_cluster_primary)" = 1 ] && killed=$n; done
[ -n "$killed" ] || bad "no node is primary before the kill"
survivors=()
fo=()
for n in "${NODES[@]}"; do
  [ "$n" = "$killed" ] && continue
  survivors+=("$n")
  fo+=("$n" "http://127.0.0.1:${API[$n]}" "${DNS[$n]}" "$E_PY/jar-$n.json")
done
for n in "${survivors[@]}"; do LEFT[$n]=$(churn "$n"); done
docker kill "$(container "$killed")" >/dev/null
election=$("${PY[@]}" failover 40 20 "${fo[@]}")
echo "$election"
new=$(printf '%s' "$election" | python3 -c "import json,sys; print(json.load(sys.stdin)['first_primary']['who'] or '')")
[ -n "$new" ] || bad "no survivor was promoted after the restarts"
first_at=$(printf '%s' "$election" | python3 -c "import json,sys; print(json.load(sys.stdin)['first_primary']['at'])")
python3 -c "import sys; a=float(sys.argv[1]); sys.exit(0 if 5 <= a <= 40 else 1)" "$first_at"   || bad "the promotion came at $first_at s after the kill (expected 5 to 40 s)"
sleep 20
for n in "${survivors[@]}"; do
  now_left=$(churn "$n")
  [ "$now_left" = "${LEFT[$n]}" ] || bad "$n flapped after the election ($((now_left - LEFT[$n])) moves)"
done
"${COMPOSE[@]}" up -d --wait "$killed" >/dev/null 2>&1 || bad "the old primary $killed didn't come back"
pass "replicas then the primary restarted; 3 of 3 voters for 3 minutes; $killed killed, $new elected $first_at s later, no flapping"

echo "== all checks passed"
