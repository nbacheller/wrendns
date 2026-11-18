#!/usr/bin/env bash
# REQ: T24.21 (DSC-013, API-012, DSC-008, DNS-023) — the TelltaleDNS Home Assistant source
# against a real Home Assistant: a throwaway Home Assistant (deploy/ha-test/compose.yaml, never
# the owner's) is onboarded through its API, given a long-lived token made at test time, and seeded
# with fake devices (fixtures/telltale_seed). A TelltaleDNS node runs in a throwaway container on
# the same network. The script checks the device names and addresses the node reports, the names
# it answers in DNS, and the TelltaleDNS integration's sensors inside Home Assistant.
# T24.10 (API-005, ADR-961): the same node also answers Pi-hole's API, and the real Home Assistant
# Pi-hole integration (`pi_hole`) is configured against it: it reads the summary and switches
# blocking off and on through the node.
# Everything is torn down by a trap; no token is printed or left behind.
#
# Usage: deploy/ha-test/e2e.sh [path/to/telltale]        (default: target/debug/telltale)
#   TELLTALE_VOLUMES_FROM=wrendns-dev  runs the binary from that container's volumes instead; then
#                                 the path is the binary's path inside that container.
#   HA_TEST_PORT (18124), NODE_API_PORT (18053), NODE_DNS_PORT (18153): host ports on 127.0.0.1.
#   HA_TEST_PROJECT, HA_TEST_NODE: Compose project and node container names (default per run, PID-based);
#   HA_TEST_IMAGE: the Home Assistant image (default the stable channel, see compose.yaml).
set -euo pipefail
# Docker only: Git Bash must not rewrite paths for docker, but curl and the cookie jar need the
# MSYS paths as they are (a Windows curl can't write /tmp/... once conversion is off).
docker() { MSYS_NO_PATHCONV=1 command docker "$@"; }
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# Host paths for `docker run -v` (Docker Desktop on Windows needs C:\ paths from Git Bash).
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }
COMPOSE=(docker compose -f "$(hostpath "$ROOT/deploy/ha-test/compose.yaml")")
# One Compose project and one node container per run, so two runs on one host don't collide
# (REQ: T24.21). COMPOSE_PROJECT_NAME is read by `docker compose` before the file's name.
RUN_ID=$$
export COMPOSE_PROJECT_NAME=${HA_TEST_PROJECT:-telltale-hatest-$RUN_ID}
HA_PORT=${HA_TEST_PORT:-18124}
API_PORT=${NODE_API_PORT:-18053}
DNS_PORT=${NODE_DNS_PORT:-18153}
HA="http://127.0.0.1:$HA_PORT"
API="http://127.0.0.1:$API_PORT"
NODE=${HA_TEST_NODE:-telltale-hatest-node-$RUN_ID}
B=${1:-target/debug/telltale}
E=$(mktemp -d)
PY=
for p in python3 python; do
  if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import json' >/dev/null 2>&1; then PY=$p; break; fi
done
[ -n "$PY" ] || { echo "needs python3"; exit 2; }
field() { "$PY" -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
cleanup() {
  local rc=$?
  docker rm -f "$NODE" >/dev/null 2>&1 || true
  HA_TEST_PORT=$HA_PORT "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  rm -rf "$E"
  exit "$rc"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=ha-test::FAIL: $*"
  docker logs --tail 15 "$NODE" 2>&1 | sed 's/^/node: /' || true
  [ -n "${HAC:-}" ] && docker logs "$HAC" 2>&1 | grep -i "telltale" | tail -n 12 | cut -c1-240 | sed 's/^/ha: /' || true
  exit 1
}
trap 'fail "line $LINENO: $BASH_COMMAND"' ERR

# -- the binary -----------------------------------------------------------------------------
if [ -n "${TELLTALE_VOLUMES_FROM:-}" ]; then
  MOUNTS=(--volumes-from "$TELLTALE_VOLUMES_FROM")
  BIN_IN=$B
else
  BDIR=$(cd "$(dirname "$B")" && pwd)
  MOUNTS=(-v "$(hostpath "$BDIR/$(basename "$B")"):/usr/local/bin/telltale:ro")
  BIN_IN=/usr/local/bin/telltale
fi

echo "== 1. Home Assistant starts and is onboarded through its API"
HA_TEST_PORT=$HA_PORT "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
HA_TEST_PORT=$HA_PORT "${COMPOSE[@]}" up -d >/dev/null
HAC=$(HA_TEST_PORT=$HA_PORT "${COMPOSE[@]}" ps -q homeassistant)
for _ in $(seq 150); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$HA/api/onboarding")" = 200 ] && break
  sleep 2
done
[ "$(curl -s -o /dev/null -w '%{http_code}' "$HA/api/onboarding")" = 200 ] || fail "Home Assistant didn't answer"
# The test owner (an administrator, which rendering templates needs). The password is generated
# here and never printed.
HA_PASS=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
AUTH=$(curl -s -H 'content-type: application/json' \
  -d "{\"client_id\":\"$HA/\",\"name\":\"TelltaleDNS test\",\"username\":\"telltale-test\",\"password\":\"$HA_PASS\",\"language\":\"en\"}" \
  "$HA/api/onboarding/users" | field 'd["auth_code"]') || fail "creating the onboarding user"
ACCESS=$(curl -s -d "grant_type=authorization_code&code=$AUTH&client_id=$HA/" "$HA/auth/token" \
  | field 'd["access_token"]') || fail "exchanging the onboarding code"
for step in core_config analytics; do
  [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "authorization: Bearer $ACCESS" \
    -H 'content-type: application/json' -d '{}' "$HA/api/onboarding/$step")" = 200 ] || fail "onboarding step $step"
done
echo ok

echo "== 2. a long-lived token, made through the websocket API, kept in a file"
docker exec -e TT_ACCESS="$ACCESS" "$HAC" python3 -c '
import asyncio, os, aiohttp
async def main():
    async with aiohttp.ClientSession() as s:
        async with s.ws_connect("http://127.0.0.1:8123/api/websocket") as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": os.environ["TT_ACCESS"]})
            assert (await ws.receive_json())["type"] == "auth_ok"
            await ws.send_json({"id": 1, "type": "auth/long_lived_access_token",
                                "client_name": "telltale-ha-test", "lifespan": 365})
            r = await ws.receive_json()
            assert r["success"], "no long-lived token"
            print(r["result"], end="")
asyncio.run(main())' > "$E/ha-token" || fail "the long-lived token"
[ -s "$E/ha-token" ] || fail "the long-lived token is empty"
LLT=$(cat "$E/ha-token")
ha_get() { curl -s -H "authorization: Bearer $LLT" "$HA$1"; }
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $LLT" "$HA/api/config")" = 200 ] \
  || fail "the long-lived token doesn't authorize the API"
echo ok

echo "== 3. fake devices: the seed integration, and device_tracker states with addresses"
FLOW=$(curl -s -H "authorization: Bearer $LLT" -H 'content-type: application/json' \
  -d '{"handler":"telltale_seed","show_advanced_options":false}' "$HA/api/config/config_entries/flow" \
  | field 'd["flow_id"]') || fail "starting the seed flow"
[ "$(curl -s -H "authorization: Bearer $LLT" -H 'content-type: application/json' -d '{}' \
  "$HA/api/config/config_entries/flow/$FLOW" | field 'd["type"]')" = create_entry ] || fail "the seed flow didn't create its entry"
for _ in $(seq 30); do
  [ "$(ha_get /api/states/device_tracker.tablet | field 'd.get("state")')" = home ] && break
  sleep 1
done
[ "$(ha_get /api/states/device_tracker.tablet | field 'd.get("attributes",{}).get("ip")')" = 192.0.2.43 ] \
  || fail "the seeded devices didn't appear"
echo ok

echo "== 4. a TelltaleDNS node reads Home Assistant"
docker rm -f "$NODE" >/dev/null 2>&1 || true
NET=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$HAC")
mkdir -p "$E/secrets"
cp "$E/ha-token" "$E/secrets/ha-token"
cat > "$E/telltale.toml" <<TOML
[node]
name = "ha-test"
data_dir = "/var/lib/telltale"
[[listen]]
proto = "udp"
addr = "0.0.0.0:1053"
[api]
listen = "0.0.0.0:8053"
[telemetry.metrics]
listen = "127.0.0.1:9153"
[local]
device_domain = "home.arpa"
[[router]]
name = "home-assistant"
type = "home_assistant"
url = "http://homeassistant:8123"
api_key_file = "/run/secrets/ha-token"
TOML
docker run -d --name "$NODE" --network "$NET" \
  -p "127.0.0.1:$API_PORT:8053" -p "127.0.0.1:$DNS_PORT:1053/udp" \
  -v "$(hostpath "$E/telltale.toml"):/etc/telltale/telltale.toml:ro" \
  -v "$(hostpath "$E/secrets"):/run/secrets:ro" \
  "${MOUNTS[@]}" ubuntu:24.04 "$BIN_IN" run -c /etc/telltale/telltale.toml >/dev/null
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.2; done
SETUP=$(docker exec "$NODE" cat /var/lib/telltale/setup-token)
JAR="$E/jar"
CSRF=$(curl -sf -c "$JAR" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$SETUP\",\"username\":\"admin\",\"password\":\"ha-test-admin-$HA_PASS\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]') || fail "the node's admin setup"
# The integration's token: an agent token with the two read scopes the sensors need.
TOKEN_RESP=$(curl -s -b "$JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"name":"home-assistant","kind":"agent","scopes":["analytics:read","config:read"]}' \
  -w '\n%{http_code}' "$API/api/v1/tokens")
[ "$(printf '%s' "$TOKEN_RESP" | tail -n 1)" = 201 ] || fail "creating the agent token: HTTP $(printf '%s' "$TOKEN_RESP" | tail -n 1)"
AGENT=$(printf '%s' "$TOKEN_RESP" | head -n -1 | field 'd["token"]') || fail "the agent token's answer"
AUTHZ=(-H "authorization: Bearer $AGENT")
for _ in $(seq 300); do
  # The names reach DNS on the node's next pass after the poll, so wait for the DNS names too.
  n=$(curl -sf "${AUTHZ[@]}" "$API/api/v1/dhcp/leases" | field 'len([x for x in d["items"] if x.get("router") == "home-assistant" and x.get("dnsName")])' 2>/dev/null || echo 0)
  [ "$n" -ge 3 ] && break
  sleep 0.5
done
LEASES=$(curl -sf "${AUTHZ[@]}" "$API/api/v1/dhcp/leases") || fail "reading the leases"
printf '%s' "$LEASES" | "$PY" -c '
import json, sys
items = [x for x in json.load(sys.stdin)["items"] if x.get("router") == "home-assistant"]
want = {
    "aa:bb:cc:00:00:01": ("Porch Light", "192.0.2.31", "porch-light.home.arpa"),
    "aa:bb:cc:00:00:02": ("Living Room TV", "192.0.2.42", "living-room-tv.home.arpa"),
    "aa:bb:cc:00:00:03": ("Kitchen Tablet", "192.0.2.43", "kitchen-tablet.home.arpa"),
}
got = {x["mac"].lower(): x for x in items}
for mac, (name, ip, dns) in want.items():
    x = got.get(mac)
    if x is None:
        sys.exit(f"no device {mac}")
    if x.get("clientName") != name or x.get("ip") != ip or x.get("dnsName") != dns:
        sys.exit(f"device {mac} reported {x}, expected {name} {ip} {dns}")
if len(items) != 3:
    sys.exit(f"expected 3 named devices with addresses, got {len(items)}")
print("3 devices named and addressed as expected (the garage sensor has no address and is absent)")
' || fail "the node's device names and addresses"
echo ok

echo "== 5. the names answer in DNS"
for pair in kitchen-tablet.home.arpa:192.0.2.43 living-room-tv.home.arpa:192.0.2.42 porch-light.home.arpa:192.0.2.31; do
  name=${pair%%:*}
  ip=${pair##*:}
  got=$("$PY" -c '
import socket, struct, sys
name, port = sys.argv[1], int(sys.argv[2])
q = struct.pack(">HHHHHH", 0x1d1d, 0x0100, 1, 0, 0, 0)
for label in name.split("."):
    q += bytes([len(label)]) + label.encode()
q += b"\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(q, ("127.0.0.1", port))
data = s.recv(512)
rcode = data[3] & 0x0F
ancount = struct.unpack(">H", data[6:8])[0]
print(".".join(str(b) for b in data[-4:]) if rcode == 0 and ancount >= 1 else f"rcode={rcode}")
' "$name" "$DNS_PORT") || got="error"
  [ "$got" = "$ip" ] || fail "$name answered '$got', expected $ip"
done
echo ok

echo "== 6. the TelltaleDNS integration in Home Assistant"
FLOW=$(curl -s -H "authorization: Bearer $LLT" -H 'content-type: application/json' \
  -d '{"handler":"telltale","show_advanced_options":false}' "$HA/api/config/config_entries/flow" \
  | field 'd["flow_id"]') || fail "starting the TelltaleDNS flow"
RES=$(curl -s -H "authorization: Bearer $LLT" -H 'content-type: application/json' \
  -d "{\"url\":\"http://$NODE:8053\",\"token\":\"$AGENT\",\"verify_ssl\":true}" \
  "$HA/api/config/config_entries/flow/$FLOW")
[ "$(printf '%s' "$RES" | field 'd["type"]')" = create_entry ] \
  || fail "the integration's setup: $(printf '%s' "$RES" | field 'd.get("errors", d.get("reason"))')"
STATES=""
for _ in $(seq 120); do
  STATES=$(ha_get /api/states)
  n=$(printf '%s' "$STATES" | "$PY" -c 'import json,sys; print(sum(1 for s in json.load(sys.stdin) if s["entity_id"].startswith("sensor.ha_test_") and s["entity_id"].endswith("known_devices") and s["state"] == "3"))')
  [ "$n" -ge 1 ] && break
  sleep 1
done
printf '%s' "$STATES" | "$PY" -c '
import json, sys
states = {s["entity_id"]: s for s in json.load(sys.stdin) if s["entity_id"].startswith(("sensor.ha_test_", "binary_sensor.ha_test_"))}
def one(key):
    m = [s for e, s in states.items() if e.endswith(key)]
    if len(m) != 1:
        sys.exit(f"expected one {key} entity, found {len(m)}: {sorted(states)}")
    return m[0]
devices = one("known_devices")
attrs = devices["attributes"]
if devices["state"] != "3":
    sys.exit("known devices " + devices["state"] + ", expected 3")
if attrs.get("with_dns_name") != 3:
    sys.exit("names in DNS: " + repr(attrs))
if attrs.get("by_source") != {"home-assistant": 3}:
    sys.exit("sources: " + repr(attrs))
health = one("health")
if health["state"] not in ("healthy", "degraded", "severe"):
    sys.exit("health " + health["state"])
problem = one("problem")
want = "off" if health["state"] == "healthy" else "on"
if problem["state"] != want:
    sys.exit("the problem sensor is " + problem["state"] + ", expected " + want)
one("queries_24_h")
one("version")
print("known devices 3 (source home-assistant, 3 with DNS names), health " + health["state"])
' || fail "the integration's sensors"
echo ok

echo "== 7. the Home Assistant Pi-hole integration against the node's Pi-hole compatible API (T24.10)"
# Off by default: the integration can't use it until an admin turns it on.
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d '{"password":"x"}' "$API/api/auth")" = 404 ] \
  || fail "the Pi-hole API should answer 404 while it is off"
[ "$(curl -sf -b "$JAR" "$API/api/v1/pihole-api" | field 'd["enabled"]')" = False ] || fail "the Pi-hole API should be off by default"
# An admin makes the token (shown once, kept in a file here) and turns it on.
curl -sf -b "$JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' -d '{}' \
  "$API/api/v1/pihole-api/token" | field 'd["token"]' > "$E/pihole-token" || fail "making the Pi-hole API token"
[ -s "$E/pihole-token" ] || fail "the Pi-hole API token is empty"
PIT=$(cat "$E/pihole-token")
[ "$(curl -sf -b "$JAR" -H "x-csrf-token: $CSRF" -X PUT -H 'content-type: application/json' -d '{"enabled":true}' \
  "$API/api/v1/pihole-api" | field 'd["enabled"]')" = True ] || fail "turning the Pi-hole API on"
# Home Assistant's own flow: host, port, location, the token as the API key (it tries v6 first).
FLOW=$(curl -s -H "authorization: Bearer $LLT" -H 'content-type: application/json' \
  -d '{"handler":"pi_hole","show_advanced_options":false}' "$HA/api/config/config_entries/flow" \
  | field 'd["flow_id"]') || fail "starting the Pi-hole flow"
RES=$(curl -s -H "authorization: Bearer $LLT" -H 'content-type: application/json' \
  -d "{\"host\":\"$NODE\",\"port\":8053,\"location\":\"admin\",\"api_key\":\"$PIT\",\"ssl\":false,\"verify_ssl\":true}" \
  "$HA/api/config/config_entries/flow/$FLOW")
[ "$(printf '%s' "$RES" | field 'd["type"]')" = create_entry ] \
  || fail "the Pi-hole integration's setup: $(printf '%s' "$RES" | field 'd.get("errors", d.get("reason"))')"
# The integration read the node: its entities, the status on, the query count from step 5's lookups.
pihole_states() {
  ha_get /api/states | "$PY" -c '
import json, sys
want = sys.argv[1]
out = {}
for s in json.load(sys.stdin):
    e = s["entity_id"]
    if "pi_hole" in e and e.startswith(want):
        out[e] = s["state"]
print(json.dumps(out))' "$1"
}
SWITCH=""
for _ in $(seq 120); do
  SWITCH=$(pihole_states switch. | field 'next(iter(d), "")')
  [ -n "$SWITCH" ] && [ "$(ha_get "/api/states/$SWITCH" | field 'd.get("state")')" = on ] && break
  sleep 1
done
[ -n "$SWITCH" ] || fail "the Pi-hole integration made no switch: $(ha_get /api/states | field '[s["entity_id"] for s in d if "pi_hole" in s["entity_id"]]')"
[ "$(pihole_states binary_sensor. | field 'list(d.values())')" = "['on']" ] || fail "the Pi-hole status sensor: $(pihole_states binary_sensor.)"
pihole_states sensor. | "$PY" -c '
import json, sys
sensors = json.load(sys.stdin)
def num(suffix):
    m = [v for e, v in sensors.items() if e.endswith(suffix)]
    if len(m) != 1:
        sys.exit(f"expected one {suffix} sensor, found {len(m)}: {sorted(sensors)}")
    return float(m[0])
queries = num("dns_queries")
if queries < 3:
    sys.exit(f"dns queries {queries}, expected at least the 3 lookups of step 5")
num("ads_blocked")
num("domains_blocked")
print("the Pi-hole integration read the summary: %d queries" % queries)
' || fail "the Pi-hole integration's sensors"
# The switch drives blocking through the node: off (HA's v6 call is POST /api/dns/blocking) ...
ha_post() { curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $LLT" -H 'content-type: application/json' -d "$2" "$HA$1"; }
paused() { curl -sf "${AUTHZ[@]}" "$API/api/v1/blocking" | field 'len([p for n in d["items"] for p in n["pauses"] if p.get("group") is None])'; }
[ "$(paused)" = 0 ] || fail "blocking should start on"
code=$(ha_post /api/services/switch/turn_off "{\"entity_id\":\"$SWITCH\"}")
[ "$code" = 200 ] || fail "turning the Pi-hole switch off: HTTP $code"
for _ in $(seq 30); do [ "$(paused)" != 0 ] && break; sleep 1; done
[ "$(paused)" != 0 ] || fail "the Pi-hole switch did not pause blocking on the node"
for _ in $(seq 30); do [ "$(ha_get "/api/states/$SWITCH" | field 'd.get("state")')" = off ] && break; sleep 1; done
[ "$(ha_get "/api/states/$SWITCH" | field 'd.get("state")')" = off ] || fail "the switch should read off"
# ... "off with no timer" is the longest pause (60 minutes by default), never forever ...
curl -sf "${AUTHZ[@]}" "$API/api/v1/blocking" | "$PY" -c '
import json, sys
left = [p["secondsLeft"] for n in json.load(sys.stdin)["items"] for p in n["pauses"] if p.get("group") is None]
if not left or not (3500 <= max(left) <= 3600):
    sys.exit(f"expected about 3600 s left, got {left}")' || fail "a pause with no timer should last the longest pause"
# ... and on again.
[ "$(ha_post /api/services/switch/turn_on "{\"entity_id\":\"$SWITCH\"}")" = 200 ] || fail "turning the Pi-hole switch on"
for _ in $(seq 30); do [ "$(paused)" = 0 ] && break; sleep 1; done
[ "$(paused)" = 0 ] || fail "the Pi-hole switch did not resume blocking on the node"
# Home Assistant's own timed disable: a duration of 5 minutes is a 5 minute pause.
[ "$(ha_post /api/services/pi_hole/disable "{\"entity_id\":\"$SWITCH\",\"duration\":\"00:05:00\"}")" = 200 ] || fail "pi_hole.disable"
for _ in $(seq 30); do [ "$(paused)" != 0 ] && break; sleep 1; done
curl -sf "${AUTHZ[@]}" "$API/api/v1/blocking" | "$PY" -c '
import json, sys
left = [p["secondsLeft"] for n in json.load(sys.stdin)["items"] for p in n["pauses"] if p.get("group") is None]
if not left or not (200 <= max(left) <= 300):
    sys.exit(f"expected about 300 s left, got {left}")' || fail "pi_hole.disable for 5 minutes"
[ "$(ha_post /api/services/switch/turn_on "{\"entity_id\":\"$SWITCH\"}")" = 200 ] || fail "turning the Pi-hole switch on again"
for _ in $(seq 30); do [ "$(paused)" = 0 ] && break; sleep 1; done
# Every change is in the audit log as the Pi-hole API's token, and none holds the token.
AUD=$(curl -sf -b "$JAR" "$API/api/v1/audit?action=blocking.&limit=20") || fail "reading the audit log"
printf '%s' "$AUD" | PIT="$PIT" "$PY" -c '
import json, os, sys
text = sys.stdin.read()
items = json.loads(text)["items"]
acts = sorted({i["action"] for i in items if i["actor"] == "token:pihole-api"})
if acts != ["blocking.pause", "blocking.resume"]:
    sys.exit(f"audit actions by the Pi-hole token: {acts}")
if os.environ["PIT"] in text:
    sys.exit("the audit log holds the token")' || fail "the audit log of the Pi-hole API's changes"
# A rotated token locks the integration out: the node answers 401 to the old one.
curl -sf -b "$JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' -d '{}' \
  "$API/api/v1/pihole-api/token" >/dev/null || fail "rotating the Pi-hole API token"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d "{\"password\":\"$PIT\"}" "$API/api/auth")" = 401 ] \
  || fail "the old Pi-hole API token should be refused"
echo ok

echo PASS
