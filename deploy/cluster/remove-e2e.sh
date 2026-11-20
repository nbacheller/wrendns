#!/usr/bin/env bash
# REQ: CLU-001 (ADR-155, GitHub issue #5) — removing a node from the cluster, on real processes:
# a primary and two replicas (r, s), plus a record (t) that joined and never ran.
#   1. a node that is up is refused without force (409 node_is_up), and the primary can't be
#      removed (409 node_is_primary); a dry run changes nothing;
#   2. r, still running, is removed with force: it is no longer listed, and it does NOT come
#      back as an ephemeral member while it keeps dialing (its certificate is still valid);
#   3. the removed list reaches the other replica (s) with the next version, and DNS keeps
#      answering on every node;
#   4. the stale record t is removed through the replica s (sent to the primary), audited with
#      the user and the entry node.
# Usage: deploy/cluster/remove-e2e.sh [path/to/wrendns]   (default: target/debug/wrendns)
set -euo pipefail
B=${1:-target/debug/wrendns}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P_PID= R_PID= S_PID=
cleanup() {
  for p in $P_PID $R_PID $S_PID; do kill "$p" 2>/dev/null && wait "$p" 2>/dev/null || true; done
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  # Annotations are readable without a token (job logs aren't).
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for n in p r s; do [ -f "$E/$n.log" ] && { echo "--- $n log"; tail -20 "$E/$n.log"; }; done
  [ "${KEEP:-}" = 1 ] && echo "logs kept in $E"
  exit 1
}

node_config() { # name dns-port api-port metrics-port cluster-port
  cat <<EOF
[node]
name = "$1"
data_dir = "$E/$1"
[[listen]]
proto = "udp"
addr = "127.0.0.1:$2"
[api]
listen = "127.0.0.1:$3"
[telemetry.metrics]
listen = "127.0.0.1:$4"
[cluster]
listen = "127.0.0.1:$5"
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["nowhere"]
[[record]]
name = "a.rm.test"
type = "A"
value = "10.0.0.1"
EOF
}
mkdir -p "$E/p" "$E/r" "$E/s" "$E/t"
node_config p 25701 28301 29301 28741 > "$E/p.toml"
node_config r 25702 28302 29302 28742 > "$E/r.toml"
node_config s 25703 28303 29303 28743 > "$E/s.toml"
node_config t 25704 28304 29304 28744 > "$E/t.toml"

cat > "$E/q.py" <<'PY'
import socket, struct, sys, random
def query(port, name, timeout=0.5):
    qid = random.randrange(65536)
    q = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    q += b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\0' + struct.pack('>HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(q, ('127.0.0.1', port)); r, _ = s.recvfrom(4096)
    except OSError:
        return None
    finally:
        s.close()
    return '.'.join(str(b) for b in r[-4:]) if struct.unpack('>H', r[6:8])[0] else ''
a = query(int(sys.argv[1]), sys.argv[2]); print(a if a is not None else 'TIMEOUT')
PY
q() { python3 "$E/q.py" "$@"; }
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
node_id() { "$B" cluster status -c "$E/$1.toml" | awk '$1 == "node" {print $2; exit}'; }

"$B" cluster init --name rm --advertise https://127.0.0.1:28741 -c "$E/p.toml" >/dev/null
T=$("$B" cluster token create --ttl 20m -c "$E/p.toml" 2>/dev/null)
"$B" run -c "$E/p.toml" > "$E/p.log" 2>&1 & P_PID=$!
for _ in $(seq 50); do [ "$(q 25701 a.rm.test)" = 10.0.0.1 ] && break; sleep 0.1; done
join() { # retries until the primary's cluster port is up
  for _ in $(seq 40); do "$B" cluster join "$T" "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "couldn't join: $*"
}
join --site r --advertise https://127.0.0.1:28742 -c "$E/r.toml"
join --site s --advertise https://127.0.0.1:28743 -c "$E/s.toml"
join --site t --advertise https://127.0.0.1:28744 -c "$E/t.toml"   # joins and never runs
"$B" run -c "$E/r.toml" > "$E/r.log" 2>&1 & R_PID=$!
"$B" run -c "$E/s.toml" > "$E/s.log" 2>&1 & S_PID=$!
R_ID=$(node_id r); S_ID=$(node_id s); T_ID=$(node_id t); P_ID=$(node_id p)
[ -n "$R_ID" ] && [ -n "$T_ID" ] && [ -n "$P_ID" ] || fail "couldn't read the node IDs"

# An admin on the primary (users reach every node), signed in on p and on s.
curl -sf -c "$E/pjar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$(cat "$E/p/setup-token")\",\"username\":\"admin\",\"password\":\"e2e-password-123\"}" \
  http://127.0.0.1:28301/api/v1/auth/setup >/dev/null || fail "couldn't set up the admin"
login() { # api-port jar -> CSRF token (retries while users replicate)
  for _ in $(seq 60); do
    t=$(curl -sf -c "$2" -H 'content-type: application/json' -d '{"username":"admin","password":"e2e-password-123"}' \
      "http://127.0.0.1:$1/api/v1/auth/login" 2>/dev/null | field 'd["csrfToken"]' 2>/dev/null) && [ -n "$t" ] && { echo "$t"; return 0; }
    sleep 0.5
  done
  return 1
}
PCSRF=$(login 28301 "$E/pjar") || fail "the admin can't sign in on p"
rm_node() { # api-port jar csrf node [query] -> HTTP status; the body in rm.json
  curl -s -o "$E/rm.json" -w '%{http_code}' --max-time 20 -b "$2" -X DELETE -H "x-csrf-token: $3" \
    "http://127.0.0.1:$1/api/v1/cluster/nodes/$4${5:+?$5}"
}
listed() { # api-port jar -> the node IDs the Cluster page lists
  curl -sf --max-time 10 -b "$2" "http://127.0.0.1:$1/api/v1/cluster" | field '" ".join(n["nodeId"] for n in d["nodes"])'
}
for _ in $(seq 120); do
  l=$(listed 28301 "$E/pjar" 2>/dev/null || true)
  case "$l" in *"$R_ID"*"$S_ID"* | *"$S_ID"*"$R_ID"*) break ;; esac
  sleep 0.5
done
case "$l" in *"$R_ID"*) ;; *) fail "r never showed in the member list: $l" ;; esac
case "$l" in *"$S_ID"*) ;; *) fail "s never showed in the member list: $l" ;; esac

echo "== 1. refusals and a dry run"
code=$(rm_node 28301 "$E/pjar" "$PCSRF" "$R_ID")
[ "$code" = 409 ] && grep -q 'node_is_up' "$E/rm.json" || fail "removing a node that is up answered $code: $(cat "$E/rm.json")"
code=$(rm_node 28301 "$E/pjar" "$PCSRF" "$P_ID" "force=true")
[ "$code" = 409 ] && grep -q 'node_is_primary' "$E/rm.json" || fail "removing the primary answered $code: $(cat "$E/rm.json")"
code=$(rm_node 28301 "$E/pjar" "$PCSRF" "nobody-has-this-id")
[ "$code" = 404 ] || fail "removing an unknown node answered $code: $(cat "$E/rm.json")"
code=$(rm_node 28301 "$E/pjar" "$PCSRF" "$R_ID" "force=true&dryRun=true")
[ "$code" = 200 ] && grep -q '"removed":false' "$E/rm.json" || fail "the dry run answered $code: $(cat "$E/rm.json")"
case "$(listed 28301 "$E/pjar")" in *"$R_ID"*) ;; *) fail "the dry run removed r" ;; esac
echo "ok"

echo "== 2. r, still running, is removed with force and stays removed"
code=$(rm_node 28301 "$E/pjar" "$PCSRF" "$R_ID" "force=true")
[ "$code" = 200 ] && grep -q '"removed":true' "$E/rm.json" && grep -q '"up":true' "$E/rm.json" \
  || fail "removing r answered $code: $(cat "$E/rm.json")"
# r keeps dialing with a certificate that is still valid; it must not come back.
for i in $(seq 12); do
  case "$(listed 28301 "$E/pjar")" in *"$R_ID"*) fail "r is listed again ${i}x3 s after its removal" ;; esac
  sleep 3
done
grep -q "member removed" "$E/p.log" || fail "the primary's log doesn't record the removal"
[ "$(q 25702 a.rm.test)" = 10.0.0.1 ] || fail "the removed node stopped answering DNS (it keeps its last configuration)"
echo "ok"

echo "== 3. the removed list reaches the other replica"
for _ in $(seq 120); do grep -q "$R_ID" "$E/s/cluster/removed.json" 2>/dev/null && break; sleep 0.5; done
grep -q "$R_ID" "$E/s/cluster/removed.json" || fail "s never learned that r was removed: $(cat "$E/s/cluster/removed.json" 2>&1)"
grep -q "$R_ID" "$E/s/cluster/nodes.json" && fail "s still lists r in its registry"
for p in 25701 25702 25703; do [ "$(q $p a.rm.test)" = 10.0.0.1 ] || fail "DNS on :$p doesn't answer"; done
echo "ok"

echo "== 4. a stale record is removed through a replica, audited with the entry node"
SCSRF=$(login 28303 "$E/sjar") || fail "the admin can't sign in on s"
# A record that never connected is listed as a down node once the primary has run for 90 s.
for _ in $(seq 300); do
  case "$(listed 28301 "$E/pjar")" in *"$T_ID"*) break ;; esac
  sleep 0.5
done
case "$(listed 28301 "$E/pjar")" in *"$T_ID"*) ;; *) fail "the record t isn't listed: $(listed 28301 "$E/pjar")" ;; esac
curl -sf -b "$E/pjar" "http://127.0.0.1:28301/api/v1/cluster" \
  | field '[n["up"] for n in d["nodes"] if n["nodeId"] == "'"$T_ID"'"][0]' | grep -q False \
  || fail "the stale record isn't shown as down"
code=$(rm_node 28303 "$E/sjar" "$SCSRF" "$T_ID")
[ "$code" = 200 ] && grep -q '"removed":true' "$E/rm.json" && grep -q '"up":false' "$E/rm.json" \
  || fail "removing the stale record through s answered $code: $(cat "$E/rm.json")"
case "$(listed 28301 "$E/pjar")" in *"$T_ID"*) fail "t is still listed" ;; esac
audit=$(curl -sf -b "$E/pjar" "http://127.0.0.1:28301/api/v1/audit?action=cluster.node.remove")
grep -q "$T_ID" <<<"$audit" && grep -q "$R_ID" <<<"$audit" || fail "the audit log is missing a removal: $audit"
grep -q " via " <<<"$audit" || fail "the forwarded removal isn't audited with the entry node: $audit"
echo "ok"
echo PASS
