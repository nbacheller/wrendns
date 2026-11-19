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
#   e2. (T24.41) a fake UniFi read with a stored key by the primary only: both replicas list its networks
#       (VLAN, domain), its clients and its state (labelled as read by the primary), the fake source saw
#       no poll from a replica, and a paused primary is named in missingNodes, not an error
#       (ONLY=routers stops after it);
#   f. queries sent to each node show up in the primary's query log, labelled by node, and in
#      the per-node top clients;
#   g. upstream #7 on the 2-CPU replica: with the primary paused, 20 concurrent reads each return
#      within 15 s, and /livez, /metrics and DNS keep answering; replica-a's runtime starts with
#      two workers; the primary is unpaused after;
#   h. failover with three nodes: an upstream is added on the lease holder (T24.37), which is killed, a survivor is promoted 5 to
#      40 s later, the other follows, DNS on both survivors keeps answering (0 SERVFAIL), an edit on
#      the new primary reaches the other survivor, the upstream added through the old primary is deleted on the
#      new one and stays deleted, and the killed node, started again, steps down;
#      T24.42 (inside h): a fake UniFi read with the stored key by the primary (the fake source's CGI logs
#      the key and the address of each read), every node's Secrets list shows all three members holding
#      the key with one stamp, the killed primary's replacement reads the fake UniFi with its replicated
#      copy within one interval plus the election while the other replica never polls, and after the old
#      primary is back all three members hold the key (ONLY=secrets runs a to e2 and h, and stops).
#   i. a rolling restart of each node in turn keeps at least two nodes answering DNS throughout;
#   c2. (FLT-901, T24.29) a content category chosen on a replica's API is stored by the primary, which
#       downloads its list from the fake source once; every node blocks the list's names from the
#       compiled snapshot, and the fake source saw no request from a replica.
#   j. (T24.40, ADR-1019) a cluster upgraded from an older version keeps its API entries: nodes on an
#      older image (OLD_IMAGE, default wrendns:lapse-base, a build before ADR-1016) take entries
#      through the API and fail over once, every node is then upgraded, and after two more failovers
#      the new primary dry-runs, edits and deletes the entries the old primary's API added, the others
#      stay served, and the edit and the delete stick. Skipped when OLD_IMAGE isn't there
#      (REQUIRE_UPGRADE=1 makes that a failure). ONLY=upgrade runs the bring-up, (a) and (j) alone.
#   k. (T24.38) after a rolling restart in the owner's order (replicas, then the primary) every node
#      reports reachableVoters = voters for 1 minute with no "leaving this node" churn, and the
#      primary's death is still an election within the lease time, with no flapping after it.
# rebrand:keep-start
#   l. (T33.2, ADR-1028) a rolling upgrade across the rename: every node on the pre-rename image
#      (PRE_RENAME_IMAGE, default telltale:pre-rename, built from the commit before the rename), then
#      each node on the renamed image, replicas first and the primary last, with DNS asked of all three
#      nodes throughout (at least two answer at every sample), no sign-in again (the old session cookie
#      still works on the new node), an API token made on the old primary still working, the cluster
#      whole after every step (the mTLS names of both versions are accepted), the entries made on the
#      old nodes served by all, and both metric names on a new node. Skipped when the old image isn't
#      there (REQUIRE_PRERENAME=1 makes that a failure). ONLY=prerename runs the bring-up, (a) and (l)
#      alone. Build the old image from a checkout of the base:
#      git archive <commit before the rename> | tar -x -C <dir>; docker build -t telltale:pre-rename <dir>
#      (--build-arg PROFILE=bench-fast --build-arg CARGO_FEATURES=e2e --build-arg WRENDNS_BUILD_CHANNEL=dev).
# rebrand:keep-end
# And, between a and b, a2: in manual failover each replica reports the other as up (relayed by the
# primary), then `set-failover auto` on the running primary is adopted with no restart: it holds a
# lease, keeps its role and its epoch, and no replica stands for 45 s.
# Automatic failover is turned on after the replicas join, under the running cluster (a2): the
# primary adopts it without a restart and no replica deposes it (T21.7, ADR-960).
#
# It never touches the single-node bundle (deploy/docker-desktop): its own compose project
# (wrendns-cluster3), its own volumes, and host ports 2153-2353 (DNS), 8153-8353 (API), 9163-9363
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
PROJECT=wrendns-cluster3
IMAGE=wrendns:cluster3-test
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

step() { echo "== $1 ($(date +%T))"; }
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
  "${COMPOSE[@]}" exec -T primary /usr/local/bin/wrendns cluster token create --ttl 30m --eligible \
    -c /etc/wrendns/wrendns.toml | tr -d '\r' | grep '^tt_join_'
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
    --advertise "https://$r:8443" -c /etc/wrendns/wrendns.toml >"$E/join-$r.log" 2>&1 \
    || { cat "$E/join-$r.log"; bad "$r couldn't join the cluster"; }
  "${COMPOSE[@]}" up -d --wait "$r" >/dev/null 2>&1 || bad "$r didn't come up healthy after joining"
done
SETUP=$("${COMPOSE[@]}" exec -T primary /usr/local/bin/wrendns auth setup-token -c /etc/wrendns/wrendns.toml \
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

if [ "${ONLY:-}" != upgrade ] && [ "${ONLY:-}" != prerename ]; then
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
epoch0=$(metric "${MET[primary]}" wrendns_cluster_epoch)
[ "$(metric "${MET[primary]}" wrendns_cluster_primary)" = 1 ] || bad "the primary isn't primary before the switch"
"${COMPOSE[@]}" exec -T primary /usr/local/bin/wrendns cluster set-failover auto -c /etc/wrendns/wrendns.toml >/dev/null   || bad "couldn't turn automatic failover on"
for n in "${NODES[@]}"; do
  ok=
  for _ in $(seq 60); do
    [ "$(metric "${MET[$n]}" wrendns_cluster_failover_auto)" = 1 ] && { ok=1; break; }
    sleep 0.5
  done
  [ -n "$ok" ] || bad "$n never adopted automatic failover"
done
ok=
for _ in $(seq 40); do
  [ "$(metric "${MET[primary]}" wrendns_cluster_lease_held)" = 1 ] && { ok=1; break; }
  sleep 0.5
done
[ -n "$ok" ] || bad "the running primary never held a lease after the switch"
# 45 s: longer than a replica's wait (15 s) plus a lease (15 s). The primary stays primary, in the
# same epoch, with its lease; the replicas never become primary.
for i in $(seq 45); do
  [ "$(metric "${MET[primary]}" wrendns_cluster_primary)" = 1 ] || bad "the primary was deposed ($i s after the switch)"
  [ "$(metric "${MET[primary]}" wrendns_cluster_epoch)" = "$epoch0" ] || bad "the epoch moved ($i s after the switch)"
  for n in replica-a replica-b; do
    [ "$(metric "${MET[$n]}" wrendns_cluster_primary)" = 0 ] || bad "$n stood for election ($i s after the switch)"
  done
  sleep 1
done
[ "$(metric "${MET[primary]}" wrendns_cluster_lease_held)" = 1 ] || bad "the primary's lease isn't held after 45 s"
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

step "c2. a category chosen on a replica is fetched by the primary only; every node blocks from the snapshot"
put_json cat.json '{"level":"enhanced","categories":["adult"]}'
call replica-a PUT /api/v1/groups/default/content "$E/cat.json"
[ "$RS" = 200 ] || bad "the category write on replica-a answered $RS (not forwarded): $RB"
for n in "${NODES[@]}"; do
  await_dns 90000 "$n" x.blocked-by-category.example 0.0.0.0 || bad "$n doesn't block the category's name"
done
call primary GET /api/v1/groups/default/content
[ "$(jget 'd["content"]["level"]')" = enhanced ] || bad "the primary doesn't hold the content a replica set: $RB"
FS=$("${COMPOSE[@]}" logs --no-color fake-source 2>&1)
asked=$(printf '%s\n' "$FS" | grep -c 'url:/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt' || true)
[ "$asked" -ge 1 ] || bad "the fake source was never asked for the list: $FS"
nodeip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(container "$1")" | tr -d '\r'; }
pip=$(nodeip primary)
printf '%s\n' "$FS" | grep -qF "$pip" || bad "the primary ($pip) didn't fetch the list: $FS"
for r in replica-a replica-b; do
  rip=$(nodeip "$r")
  printf '%s\n' "$FS" | grep -F 'url:' | grep -qF "[::ffff:$rip]" && bad "$r ($rip) downloaded a category list: $FS"
done
pass "$asked request(s), all from the primary"

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
    "${COMPOSE[@]}" exec -T "$n" /usr/local/bin/wrendns secrets status -c /etc/wrendns/wrendns.toml \
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

step "e2. a replica shows the primary's router data (T24.41): networks, clients and state, read by the primary only"
# A fake UniFi (the fake source serves its stat/sta and networkconf answers over plain http) read with a
# stored key: only the primary polls it. A replica's pages come from the primary through the cluster.
put_json router2.json '{"type":"unifi","url":"http://fake-source:8080","api_key_ref":"cluster3-router-key"}'
call primary PUT /api/v1/routers/fake-udm "$E/router2.json"
[ "$RS" = 200 ] || bad "the fake UniFi's write on the primary answered $RS: $RB"
for _ in $(seq 90); do
  call primary GET /api/v1/routers
  [ "$(jget 'next((r["status"]["state"] for r in d["items"] if r["name"] == "fake-udm"), "")')" = ok ] && break
  sleep 1
done
[ "$(jget 'next((r["status"]["state"] for r in d["items"] if r["name"] == "fake-udm"), "")')" = ok ] \
  || bad "the primary never read the fake UniFi: ${RB:0:600}"
for n in replica-a replica-b; do
  for _ in $(seq 60); do call "$n" GET /api/v1/networks && has vlan-30 && break; sleep 1; done
  [ "$RS" = 200 ] || bad "$n's /networks answered $RS"
  for want in LAN-c3 vlan-30 vlan-40; do has "$want" || bad "$n's /networks doesn't list $want: ${RB:0:600}"; done
  [ "$(jget 'next((i["vlan"] for i in d["items"] if i["name"] == "vlan-30"), 0)')" = 30 ] || bad "$n shows no VLAN 30 for vlan-30"
  [ "$(jget 'next((i["domain"] for i in d["items"] if i["name"] == "LAN-c3"), "")')" = lan.c3.test ] || bad "$n shows no domain for LAN-c3"
  call "$n" GET /api/v1/dhcp/leases
  [ "$RS" = 200 ] || bad "$n's /dhcp/leases answered $RS"
  has kids-tablet || bad "$n's /dhcp/leases doesn't list the primary's router clients: ${RB:0:400}"
  # A replica's router loop wakes every 15 s at most, so a router added on the primary shows there as
  # "this node, waiting" until the next tick: the state is polled for, not read once.
  for _ in $(seq 60); do
    call "$n" GET /api/v1/routers
    [ "$(jget 'next((r["status"]["state"] for r in d["items"] if r["name"] == "fake-udm"), "")')" = ok ] && break
    sleep 1
  done
  [ "$(jget 'next((r["status"]["state"] for r in d["items"] if r["name"] == "fake-udm"), "")')" = ok ] \
    || bad "$n doesn't show the primary's state of fake-udm: ${RB:0:600}"
  [ "$(jget 'next((r["status"]["devices"] for r in d["items"] if r["name"] == "fake-udm"), 0)')" -ge 3 ] \
    || bad "$n shows fewer than 3 devices for fake-udm"
  [ "$(jget 'next((r["status"].get("readBy", "") for r in d["items"] if r["name"] == "fake-udm"), "")')" != "" ] \
    || bad "$n doesn't label fake-udm's status as read by the primary"
  has "$SECRET" && bad "$n's /routers shows the router key's value"
done
FS=$("${COMPOSE[@]}" logs --no-color fake-source 2>&1)
pip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(container primary)" | tr -d '\r')
printf '%s\n' "$FS" | grep -F 'stat/sta' | grep -qF "$pip" || bad "the primary's read of the fake UniFi isn't in its log: ${FS:0:400}"
for r in replica-a replica-b; do
  rip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(container "$r")" | tr -d '\r')
  printf '%s\n' "$FS" | grep -F 'stat/sta' | grep -qF "[::ffff:$rip]" && bad "$r ($rip) polled the fake UniFi: ${FS:0:400}"
done
# With the primary away a replica answers from its own data, names the primary, and never errors.
docker pause "$(container primary)" >/dev/null
call replica-a GET /api/v1/networks
rs_n=$RS; has missingNodes && miss_n=yes || miss_n=no
call replica-a GET /api/v1/routers
rs_r=$RS; has missingNodes && miss_r=yes || miss_r=no
docker unpause "$(container primary)" >/dev/null
[ "$rs_n" = 200 ] && [ "$rs_r" = 200 ] || bad "a replica answered $rs_n/$rs_r while the primary was paused"
[ "$miss_n" = yes ] && [ "$miss_r" = yes ] || bad "a replica didn't name the paused primary ($miss_n/$miss_r)"
for _ in $(seq 120); do primary_linked replica-a && break; sleep 0.5; done
primary_linked replica-a || bad "replica-a doesn't see the primary again after the unpause"
call primary DELETE /api/v1/routers/fake-udm
[ "$RS" = 200 ] || [ "$RS" = 204 ] || bad "removing the fake UniFi answered $RS: $RB"
pass "both replicas list the router's networks, clients and state; only the primary polled; a paused primary is named, not an error"
[ "${ONLY:-}" != routers ] || { echo "== all checks passed (ONLY=routers: the bring-up and a to e2)"; exit 0; }

if [ "${ONLY:-}" != secrets ]; then
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

fi

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
    if [ "$(metric "${MET[$n]}" wrendns_cluster_primary)" = 1 ] \
      && [ "$(metric "${MET[$n]}" wrendns_cluster_lease_held)" = 1 ]; then killed=$n; fi
  done
  [ -n "$killed" ] && break
  sleep 0.5
done
[ -n "$killed" ] || bad "no node holds the lease before the kill"
survivors=()
fo=()
for n in "${NODES[@]}"; do
  [ "$n" = "$killed" ] && continue
  [ "$(metric "${MET[$n]}" wrendns_cluster_primary)" = 0 ] || bad "$n is primary before the kill"
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
# REQ: API-015, CLU-002, CLU-015 (T24.42): a stored key held by every full member, and used by the one
# that becomes primary. A fake UniFi (the fake source's CGI, which logs the key each read carried and
# where it came from) is read with the stored key by the primary, 30 s apart; every node's Secrets
# page lists all three members as holding it (applied, the same stamp); the primary is then killed.
declare -A NODE_IP
for n in "${NODES[@]}"; do
  NODE_IP[$n]=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(container "$n")" | tr -d '\r')
done
secrets_all_held() { # node: 0 when its Secrets list shows every full member holding the stored key, with one stamp
  call "$1" GET /api/v1/secrets
  [ "$RS" = 200 ] || return 1
  [ "$(jget 'sorted(n["state"] for i in d["items"] if i["name"] == "cluster3-router-key" for n in i["nodes"]) == ["applied"] * 3')" = True ] || return 1
  [ "$(jget 'len({(n["stamp"]["epoch"], n["stamp"]["seq"]) for i in d["items"] if i["name"] == "cluster3-router-key" for n in i["nodes"]}) == 1')" = True ] || return 1
  [ "$(jget 'sorted(m["kind"] + ":" + m["state"] for m in d["members"]) == ["full:answered"] * 3')" = True ]
}
put_json router3.json '{"type":"unifi","url":"http://fake-source:8080/cgi-bin/u","api_key_ref":"cluster3-router-key","interval_secs":30}'
call "$killed" PUT /api/v1/routers/fake-udm-h "$E/router3.json"
[ "$RS" = 200 ] || bad "the fake UniFi's write on $killed answered $RS: $RB"
polled_by() { # node: 0 when the fake source saw a read from that node's address carrying the stored key
  "${COMPOSE[@]}" logs --no-color fake-source 2>&1 | grep -F 'unifi key=' | grep -F "key=$SECRET " | grep -qF "from=[::ffff:${NODE_IP[$1]}]"
}
for _ in $(seq 90); do polled_by "$killed" && break; sleep 1; done
polled_by "$killed" || bad "the primary $killed never read the fake UniFi with the stored key: $("${COMPOSE[@]}" logs --no-color fake-source 2>&1 | tail -5)"
for n in "${NODES[@]}"; do
  for _ in $(seq 90); do secrets_all_held "$n" && break; sleep 1; done
  secrets_all_held "$n" || bad "$n's Secrets list doesn't show all three members holding the key: ${RB:0:700}"
  has "$SECRET" && bad "$n's Secrets list shows the key's value"
done
for n in "${survivors[@]}"; do
  polled_by "$n" && bad "the replica $n read the fake UniFi (only the primary polls)"
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
# T24.42: the newly elected primary reads the fake UniFi with its replicated copy of the key, within one
# interval (30 s) plus the election (the promotion was at $first_at s; the poll loop starts at once), and
# the other survivor, a replica, still does not poll.
promoted_at=$(date +%s)
polled_ok=
for _ in $(seq 90); do polled_by "$new" && { polled_ok=1; break; }; sleep 1; done
[ -n "$polled_ok" ] || bad "the new primary $new never read the fake UniFi with its replicated key within a minute and a half: $("${COMPOSE[@]}" logs --no-color fake-source 2>&1 | tail -5)"
echo "   $new read the fake UniFi $(( $(date +%s) - promoted_at )) s after the election result"
polled_by "$other" && bad "the replica $other read the fake UniFi after the failover (only the primary polls)"
call "$new" GET /api/v1/routers
[ "$(jget 'next((r["status"]["state"] for r in d["items"] if r["name"] == "fake-udm-h"), "")')" = ok ] \
  || bad "the new primary $new doesn't show a good read of the fake UniFi: ${RB:0:500}"
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
# T24.42: with the old primary back, every node's Secrets list shows all three members holding the key.
for n in "${NODES[@]}"; do
  for _ in $(seq 120); do secrets_all_held "$n" && break; sleep 1; done
  secrets_all_held "$n" || bad "after the failover $n's Secrets list doesn't show all three members holding the key: ${RB:0:700}"
done
call "$new" DELETE /api/v1/routers/fake-udm-h
[ "$RS" = 200 ] || [ "$RS" = 204 ] || bad "removing fake-udm-h on $new answered $RS: $RB"
pass "$killed (the lease holder) killed; $new promoted at $first_at s after the kill; loss $loss; the old primary follows; the new primary read the fake UniFi with its replicated key; every node lists all three members holding it"
[ "${ONLY:-}" != secrets ] || { echo "== all checks passed (ONLY=secrets: the bring-up, a to e2 and h)"; exit 0; }

step "i. rolling restart: each node in turn, at least two nodes answer DNS throughout"
"${PY[@]}" rolling 2 60 "${COMPOSE[@]}" -- primary:2153 replica-a:2253 replica-b:2353 >"$E/rolling.json" \
  || { cat "$E/rolling.json"; bad "fewer than two nodes answered during the rolling restart"; }
cat "$E/rolling.json"
pass

step "k. replicas stay linked (T24.38): after a rolling restart (replicas, then the primary) every node reaches every voter for 3 minutes, with no link churn; the primary's death is still an election"
# The owner's upgrade order on 2026-11-18: the replicas first, then the primary. The bug: a replica
# that fell back to another replica while the primary restarted lost the voter link between the two
# replicas for good (one stream's end marked the peer disconnected and took the other's place in the
# outbox), so reachableVoters stayed at 2 and the replicas moved between the primary and each other.
cur=
for n in "${NODES[@]}"; do [ "$(metric "${MET[$n]}" wrendns_cluster_primary)" = 1 ] && cur=$n; done
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
for n in "${NODES[@]}"; do [ "$(metric "${MET[$n]}" wrendns_cluster_primary)" = 1 ] && killed=$n; done
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

fi

# ---------------------------------------------------------------------------------------------
# T24.40 (ADR-1019): the owner's upgrade. Entries added through the API while every node ran a build
# without ADR-1016, a failover in that state, then every node upgraded: the primary then holds
# entries it serves but has no rows for, and used to answer a dry-run write with before: null and to
# publish a candidate without the other entries.
OLD_IMAGE=${OLD_IMAGE:-wrendns:lapse-base}

# Recreates one node on an image (its data volume stays) and waits until it is healthy.
# rebrand:keep-start
# An image from before the rename (its entrypoint is `telltale`) keeps its data in /var/lib/telltale and
# has its own health command: compose-prerename.yaml says so (T33.2, ADR-1028).
at_image() { # image node
  local files=(-f "$HERE_W/compose.yaml")
  if docker image inspect -f '{{json .Config.Entrypoint}}' "$1" 2>/dev/null | grep -q telltale; then
    files+=(-f "$HERE_W/compose-prerename.yaml")
  fi
  TT_IMAGE=$1 docker compose -p "$PROJECT" "${files[@]}" up -d --no-deps --no-build --force-recreate --wait "$2" >/dev/null 2>&1
}
# rebrand:keep-end

# Signs in to a node again (a recreated node's session may be gone).
relogin() { # node
  local _
  for _ in $(seq 90); do login "$1" && return 0; sleep 1; done
  return 1
}

# rebrand:keep-start
# A node's metric by its new name, or by the pre-rename one when the node runs the old image.
metric_any() { # port name-without-prefix
  local v
  v=$(metric "$1" "wrendns_$2")
  [ -n "$v" ] || v=$(metric "$1" "telltale_$2")
  echo "$v"
}

# The node that is primary and holds its lease, by either metric name; nodes named after the budget are skipped.
wait_primary_any() { # budget [excluded-node...]
  local budget=$1 n end
  shift
  end=$(( $(date +%s) + budget ))
  while [ "$(date +%s)" -lt "$end" ]; do
    for n in "${NODES[@]}"; do
      case " $* " in *" $n "*) continue ;; esac
      if [ "$(metric_any "${MET[$n]}" cluster_primary)" = 1 ] && [ "$(metric_any "${MET[$n]}" cluster_lease_held)" = 1 ]; then
        echo "$n"
        return 0
      fi
    done
    sleep 1
  done
  return 1
}

# The node that is primary and holds its lease (by either metric name: an image from before the rename
# calls them telltale_*), waiting up to budget seconds; nodes named after the budget are skipped.
wait_primary() { wait_primary_any "$@"; }
# rebrand:keep-end

# 0 once a node lists a list by name (present) or stops listing it (absent), within 30 s.
list_is() { # node present|absent name
  local _
  for _ in $(seq 60); do
    call "$1" GET /api/v1/lists
    if has "\"$3\""; then [ "$2" = present ] && return 0; else [ "$2" = absent ] && return 0; fi
    sleep 0.5
  done
  return 1
}

step "j. a cluster upgraded from an older version keeps its API entries (T24.40)"
if [ "${ONLY:-}" = prerename ]; then
  echo "SKIP: ONLY=prerename"
elif ! docker image inspect "$OLD_IMAGE" >/dev/null 2>&1; then
  if [ "${REQUIRE_UPGRADE:-}" = 1 ]; then bad "the older image $OLD_IMAGE is not here (build one from a commit before ADR-1016)"; fi
  echo "SKIP: the older image $OLD_IMAGE is not here (set OLD_IMAGE, or build wrendns:lapse-base from a commit before ADR-1016)"
else
  # Automatic failover on (check a2 did it in a full run; ONLY=upgrade skips a2): the failovers below
  # are leases running out.
  if [ "$(metric_any "${MET[primary]}" cluster_failover_auto)" != 1 ]; then
    "${COMPOSE[@]}" exec -T primary /usr/local/bin/wrendns cluster set-failover auto -c /etc/wrendns/wrendns.toml >/dev/null       || bad "couldn't turn automatic failover on"
    for _ in $(seq 60); do
      [ "$(metric_any "${MET[primary]}" cluster_lease_held)" = 1 ] && break
      sleep 0.5
    done
  fi
  # Every node on the older build, one at a time.
  for n in "${NODES[@]}"; do at_image "$OLD_IMAGE" "$n" || bad "$n didn't come up on $OLD_IMAGE"; done
  for n in "${NODES[@]}"; do relogin "$n" || bad "$n's administrator can't sign in on the older image"; done
  P=$(wait_primary 120) || bad "no primary on the older image"
  for _ in $(seq 120); do sees_connected "$P" 3 && break; sleep 0.5; done
  sees_connected "$P" 3 || bad "the older cluster isn't whole (primary $P)"
  # Entries added through the older primary's API: they replicate as part of the shared configuration
  # and the older build publishes no rows of them.
  put_json l-keep.json '{"url":"https://lists.example/keep.txt"}'
  put_json l-edit.json '{"url":"https://lists.example/before.txt"}'
  put_json l-gone.json '{"url":"https://lists.example/gone.txt"}'
  put_json rec-up.json '{"records":[{"type":"A","value":"10.0.0.40"}]}'
  for l in keep edit gone; do
    call "$P" PUT "/api/v1/lists/t2440-$l" "$E/l-$l.json"
    [ "$RS" = 200 ] || bad "adding list t2440-$l on the older primary $P answered $RS: $RB"
  done
  call "$P" PUT /api/v1/records/t2440.cluster3.test "$E/rec-up.json"
  [ "$RS" = 200 ] || bad "adding a record on the older primary $P answered $RS: $RB"
  for n in "${NODES[@]}"; do
    for l in keep edit gone; do list_is "$n" present "t2440-$l" || bad "$n doesn't list t2440-$l (older image)"; done
  done
  # A failover while every node is older: the survivor is promoted from replica with an older blob.
  docker kill "$(container "$P")" >/dev/null
  S=$(wait_primary 90 "$P") || bad "no survivor was promoted on the older image"
  for l in keep edit gone; do list_is "$S" present "t2440-$l" || bad "$S doesn't serve t2440-$l after the older failover"; done
  at_image "$OLD_IMAGE" "$P" || bad "$P didn't come back on the older image"
  # Now every node is upgraded, replicas first and the older failover's primary $S last.
  for n in "${NODES[@]}"; do
    [ "$n" = "$S" ] || at_image "$IMAGE" "$n" || bad "$n didn't come up on the new image"
  done
  at_image "$IMAGE" "$S" || bad "$S didn't come up on the new image"
  for n in "${NODES[@]}"; do relogin "$n" || bad "$n's administrator can't sign in after the upgrade"; done
  N1=$(wait_primary 120) || bad "no primary after the upgrade"
  # The first failover after the upgrade: the new primary must not lose what it serves.
  for l in keep edit gone; do list_is "$N1" present "t2440-$l" || bad "$N1 doesn't serve t2440-$l after the upgrade"; done
  call "$N1" PUT "/api/v1/lists/t2440-edit?dryRun=true" "$E/l-edit.json"
  [ "$RS" = 200 ] || bad "a dry-run write of an inherited list on $N1 answered $RS: $RB"
  [ "$(jget 'd["before"] is None')" = False ] || bad "the dry run on $N1 shows no 'before' for an entry it serves: $RB"
  # Which path ran: the node adopted what it serves (an older primary's version has no rows). A
  # promotion from replica takes the same code; the unit tests (clu_015_t24_40_*) cover that entry.
  "${COMPOSE[@]}" logs --no-color "$N1" 2>&1 | grep -qE "it adopted them as its own.*kinds=[a-z]+ [0-9]+"   || bad "$N1 served the inherited entries but its log doesn't say it adopted them as its own"
  docker kill "$(container "$N1")" >/dev/null
  N2=$(wait_primary 90 "$N1") || bad "no survivor was promoted after the upgrade"
  for n in "${NODES[@]}"; do
    [ "$n" = "$N1" ] || relogin "$n" || bad "$n's administrator can't sign in"
  done
  put_json l-edit2.json '{"url":"https://lists.example/after.txt"}'
  call "$N2" PUT "/api/v1/lists/t2440-edit?dryRun=true" "$E/l-edit2.json"
  [ "$RS" = 200 ] || bad "a dry-run write of an inherited list on the new primary $N2 answered $RS: $RB"
  [ "$(jget 'd["before"] is None')" = False ] || bad "the dry run on $N2 shows no 'before': $RB"
  call "$N2" PUT /api/v1/lists/t2440-edit "$E/l-edit2.json"
  [ "$RS" = 200 ] || bad "editing an inherited list on $N2 answered $RS: $RB"
  call "$N2" DELETE /api/v1/lists/t2440-gone
  [ "$RS" = 200 ] || bad "deleting an inherited list on $N2 answered $RS: $RB"
  T=
  for n in "${NODES[@]}"; do
    [ "$n" = "$N1" ] || [ "$n" = "$N2" ] || T=$n
  done
  for n in "$N2" "$T"; do
    list_is "$n" absent t2440-gone || bad "$n still lists the deleted t2440-gone"
    list_is "$n" present t2440-keep || bad "$n lost t2440-keep (another entry) after the edit and the delete"
    call "$n" GET /api/v1/lists
    has "after.txt" || bad "$n doesn't show the edit of t2440-edit"
  done
  call "$N2" GET /api/v1/records
  has "t2440.cluster3.test" || bad "$N2 lost the record added through the older primary"
  await_dns 10000 "$N2" t2440.cluster3.test 10.0.0.40 || bad "$N2 doesn't answer the inherited record"
  # The edit and the delete stick across another failover.
  at_image "$IMAGE" "$N1" || bad "$N1 didn't come back"
  relogin "$N1" || bad "$N1's administrator can't sign in"
  docker kill "$(container "$N2")" >/dev/null
  N3=$(wait_primary 90 "$N2") || bad "no survivor was promoted after the second failover"
  relogin "$N3" || bad "$N3's administrator can't sign in"
  list_is "$N3" absent t2440-gone || bad "$N3 brought the deleted t2440-gone back"
  list_is "$N3" present t2440-keep || bad "$N3 lost t2440-keep"
  call "$N3" GET /api/v1/lists
  has "after.txt" || bad "$N3 lost the edit"
  ! has "before.txt" || bad "$N3 serves the old value of the edited list"
  at_image "$IMAGE" "$N2" || bad "$N2 didn't come back"
  pass "older primary $P, older failover to $S, upgraded; $N1 then $N2 then $N3 primary; dry run, edit and delete kept"
fi

# rebrand:keep-start
# ---------------------------------------------------------------------------------------------
# T33.2 (ADR-1028): a rolling upgrade across the rename. The old nodes call themselves `telltale`
# (the command, the metrics, the session cookie, the mTLS names in their certificates); the new ones
# are `wrendns`. A cluster of both must stay whole and keep answering through the roll.
PRE_IMAGE=${PRE_RENAME_IMAGE:-telltale:pre-rename}

# Asks every node's DNS for a name every 0.3 s, one line per round: the time, then 1 (NOERROR with the
# address) or 0 for each node.
PROBE_PID=
probe_start() { # name ip
  rm -f "$E/probe.stop"
  (
    while [ ! -e "$E/probe.stop" ]; do
      line=$(now_ms)
      for n in "${NODES[@]}"; do
        if [ "$(dnsans "$n" "$1")" = "NOERROR $2" ]; then line="$line 1"; else line="$line 0"; fi
      done
      echo "$line"
      sleep 0.3
    done
  ) >"$E/probe.log" 2>/dev/null &
  PROBE_PID=$!
}
# The loop ends at its next round once the stop file exists (a kill of the subshell isn't reliable under
# Git Bash on Windows, and `wait` would then never return).
probe_stop() {
  [ -z "$PROBE_PID" ] || { : > "$E/probe.stop"; wait "$PROBE_PID" 2>/dev/null; }
  PROBE_PID=
}

step "l. a rolling upgrade from the pre-rename image keeps the cluster whole and DNS answering (T33.2)"
if ! docker image inspect "$PRE_IMAGE" >/dev/null 2>&1; then
  if [ "${REQUIRE_PRERENAME:-}" = 1 ]; then bad "the pre-rename image $PRE_IMAGE is not here (build it from the commit before the rename)"; fi
  echo "SKIP: the pre-rename image $PRE_IMAGE is not here (set PRE_RENAME_IMAGE, or build telltale:pre-rename from the commit before the rename)"
else
  # Automatic failover on, as in j: the primary's replacement below is a lease running out.
  if [ "$(metric_any "${MET[primary]}" cluster_failover_auto)" != 1 ]; then
    "${COMPOSE[@]}" exec -T primary /usr/local/bin/wrendns cluster set-failover auto -c /etc/wrendns/wrendns.toml >/dev/null \
      || bad "couldn't turn automatic failover on"
    for _ in $(seq 60); do
      [ "$(metric_any "${MET[primary]}" cluster_lease_held)" = 1 ] && break
      sleep 0.5
    done
  fi
  # Every node on the pre-rename image, one at a time.
  for n in "${NODES[@]}"; do at_image "$PRE_IMAGE" "$n" || bad "$n didn't come up on $PRE_IMAGE"; done
  for n in "${NODES[@]}"; do relogin "$n" || bad "$n's administrator can't sign in on the pre-rename image"; done
  P=$(wait_primary_any 120) || bad "no primary on the pre-rename image"
  for _ in $(seq 120); do sees_connected "$P" 3 && break; sleep 0.5; done
  sees_connected "$P" 3 || bad "the pre-rename cluster isn't whole (primary $P)"
  grep -q telltale_session "$E/jar-$P.json" || bad "the pre-rename node set no telltale_session cookie: this check needs the old image"
  # What the old nodes hold: a record, a list entry, and an API token made on the old primary.
  put_json l-rec.json '{"records":[{"type":"A","value":"10.0.0.77"}]}'
  call "$P" PUT /api/v1/records/l.cluster3.test "$E/l-rec.json"
  [ "$RS" = 200 ] || bad "adding a record on the pre-rename primary $P answered $RS: $RB"
  put_json l-list.json '{"url":"https://lists.example/t332.txt"}'
  call "$P" PUT /api/v1/lists/t332-keep "$E/l-list.json"
  [ "$RS" = 200 ] || bad "adding a list on the pre-rename primary $P answered $RS: $RB"
  put_json l-token.json '{"name":"t332","kind":"agent","scopes":["analytics:read","config:read"]}'
  call "$P" POST /api/v1/tokens "$E/l-token.json"
  TOK=$(jget 'd["token"]')
  [ -n "$TOK" ] || bad "no API token from the pre-rename primary ($RS): $RB"
  for n in "${NODES[@]}"; do
    await_dns 15000 "$n" l.cluster3.test 10.0.0.77 || bad "$n doesn't answer the record on the pre-rename image"
    list_is "$n" present t332-keep || bad "$n doesn't list t332-keep on the pre-rename image"
  done
  # The roll: replicas first, the primary last (the owner's order), DNS asked of every node throughout.
  probe_start l.cluster3.test 10.0.0.77
  for n in "${NODES[@]}"; do
    [ "$n" = "$P" ] && continue
    at_image "$IMAGE" "$n" || { probe_stop; bad "$n didn't come up on the renamed image"; }
    # No sign-in again: the session the old node gave still works on the new one.
    call "$n" GET /api/v1/lists
    [ "$RS" = 200 ] || { probe_stop; bad "$n answered $RS to the pre-rename session cookie after its upgrade: $RB"; }
    for _ in $(seq 120); do sees_connected "$P" 3 && break; sleep 0.5; done
    sees_connected "$P" 3 || { probe_stop; bad "the cluster isn't whole after $n moved to the renamed image (old primary $P sees $(connected_count "$P"))"; }
    [ -n "$(metric "${MET[$n]}" wrendns_cluster_primary)" ] && [ -n "$(metric "${MET[$n]}" telltale_cluster_primary)" ] \
      || { probe_stop; bad "$n doesn't export both metric names"; }
  done
  at_image "$IMAGE" "$P" || { probe_stop; bad "$P didn't come up on the renamed image"; }
  N1=$(wait_primary_any 120) || { probe_stop; bad "no primary after the roll"; }
  for n in "${NODES[@]}"; do
    call "$n" GET /api/v1/lists
    [ "$RS" = 200 ] || { probe_stop; bad "$n answered $RS to the pre-rename session cookie after the roll: $RB"; }
  done
  for _ in $(seq 120); do sees_connected "$N1" 3 && break; sleep 0.5; done
  sees_connected "$N1" 3 || { probe_stop; bad "the cluster isn't whole after the roll (primary $N1 sees $(connected_count "$N1"))"; }
  probe_stop
  rounds=$(awk 'END {print NR}' "$E/probe.log")
  thin=$(awk '{ if ($2 + $3 + $4 < 2) bad++ } END {print bad + 0}' "$E/probe.log")
  [ "$rounds" -ge 20 ] || bad "the DNS monitor made only $rounds samples"
  [ "$thin" = 0 ] || bad "DNS had fewer than two answering nodes in $thin of $rounds samples during the roll"
  # Every node runs the renamed image now; what the old nodes held is served by all of them.
  for n in "${NODES[@]}"; do
    [ "$(docker inspect -f '{{.Config.Image}}' "$(container "$n")")" = "$IMAGE" ] || bad "$n isn't on $IMAGE"
    list_is "$n" present t332-keep || bad "$n lost t332-keep in the roll"
    await_dns 10000 "$n" l.cluster3.test 10.0.0.77 || bad "$n lost the record in the roll"
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer $TOK" "http://127.0.0.1:${API[$n]}/api/v1/lists")
    [ "$code" = 200 ] || bad "the API token made on the old primary answered $code on $n"
  done
  # A write on the new primary reaches the others (the new nodes talk to each other as before).
  # (The session cookie survived the roll; a CSRF token is per process, so a write signs in once more.)
  relogin "$N1" || bad "$N1's administrator can't sign in after the roll"
  put_json l-rec2.json '{"records":[{"type":"A","value":"10.0.0.78"}]}'
  call "$N1" PUT /api/v1/records/l2.cluster3.test "$E/l-rec2.json"
  [ "$RS" = 200 ] || bad "a write on the new primary $N1 answered $RS: $RB"
  for n in "${NODES[@]}"; do await_dns 10000 "$n" l2.cluster3.test 10.0.0.78 || bad "$n doesn't answer the record written after the roll"; done
  pass "pre-rename image, then the renamed one (replicas first); $N1 primary; $rounds DNS samples, always two or more answering; sessions, token and entries kept"
fi
# rebrand:keep-end

echo "== all checks passed"
