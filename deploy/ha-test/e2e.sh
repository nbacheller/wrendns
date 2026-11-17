#!/usr/bin/env bash
# REQ: T24.21 (DSC-013, API-012, DSC-008, DNS-023) — the TelltaleDNS Home Assistant source
# against a real Home Assistant: a throwaway Home Assistant (deploy/ha-test/compose.yaml, never
# the owner's) is onboarded through its API, given a long-lived token made at test time, and seeded
# with fake devices (fixtures/telltale_seed). A TelltaleDNS node runs in a throwaway container on
# the same network. The script checks the device names and addresses the node reports, the names
# it answers in DNS, and the TelltaleDNS integration's sensors inside Home Assistant.
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

echo PASS
