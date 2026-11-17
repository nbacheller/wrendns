#!/usr/bin/env bash
# REQ: T8.2, T8.3 — router integrations against fake UniFi OS and OPNsense APIs, and mDNS: a UniFi login
# (cookie) and its client list (connected, then the offline clients it knows: the reserved ones and the
# history within offline_days), OPNsense leases with an API key, the leases in the API, and a device named
# from the router in the query log. REQ: T22.1–T22.3 (DNS-023, API-012, API-013) — UniFi reservations and
# networks, a fake Home Assistant's device registry (a name you gave wins over the router's; a tracker
# supplies an address), the networks API, and the device names answered in DNS with their PTRs.
# Needs python3, dig, curl.
# Usage: deploy/routers-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
cd "$(dirname "$0")/.."
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P=
H=
cleanup() {
  local rc=$?
  for p in $P $H; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$E"
  exit "$rc"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  [ -f "$E/node.log" ] && tail -15 "$E/node.log"
  exit 1
}
trap 'fail "line $LINENO: \`$BASH_COMMAND\` failed"' ERR
API=http://127.0.0.1:26992
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

cat > "$E/fake.py" <<'EOF'
import base64, http.server, json, sys, threading, time
class UniFi(http.server.BaseHTTPRequestHandler):
    def reply(self, code, obj, headers=()):
        body = json.dumps(obj).encode()
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        creds = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/auth/login" and creds.get("username") == "telltale" and creds.get("password") == "s3cret":
            self.reply(200, {}, [("set-cookie", "TOKEN=abc123; Path=/; HttpOnly"), ("x-csrf-token", "x")])
        else:
            self.reply(401, {"error": "bad login"})
    def do_GET(self):
        if "TOKEN=abc123" not in (self.headers.get("cookie") or ""):
            return self.reply(401, {"meta": {"rc": "error", "msg": "api.err.LoginRequired"}})
        if self.path == "/proxy/network/api/s/default/stat/sta":
            self.reply(200, {"meta": {"rc": "ok"}, "data": [
                {"mac": "02:00:00:00:00:01", "ip": "127.0.0.1", "hostname": "laptop-77", "name": "Desk laptop"},
                {"mac": "02:00:00:00:00:02", "ip": "192.168.1.31", "hostname": "roku"}]})
        elif self.path == "/proxy/network/api/s/default/rest/user":
            # T22.2: an offline printer with a reservation, a reserved camera, and a known client without one.
            self.reply(200, {"meta": {"rc": "ok"}, "data": [
                {"mac": "02:00:00:00:00:05", "use_fixedip": True, "fixed_ip": "192.168.1.50", "name": "Office printer"},
                {"mac": "02:00:00:00:00:06", "use_fixedip": True, "fixed_ip": "192.168.1.51", "name": "Garage camera"},
                {"mac": "02:00:00:00:00:09", "last_ip": "192.168.1.60", "hostname": "gone-phone"}]})
        elif self.path == "/proxy/network/api/s/default/rest/networkconf":
            self.reply(200, {"meta": {"rc": "ok"}, "data": [
                {"name": "Default", "purpose": "corporate", "ip_subnet": "192.168.1.1/24", "dhcpd_enabled": True, "dhcpd_start": "192.168.1.6", "dhcpd_stop": "192.168.1.49", "domain_name": "home.arpa"},
                {"name": "IoT", "purpose": "corporate", "ip_subnet": "192.168.20.1/24", "vlan_enabled": True, "vlan": 20},
                {"name": "Internet", "purpose": "wan", "ip_subnet": "203.0.113.2/30"}]})
        elif self.path.startswith("/proxy/network/v2/api/site/default/clients/history?"):
            # What the console was asked for (its window), for the check below.
            open(sys.argv[1] + "/history.path", "w").write(self.path)
            now = int(time.time())
            self.reply(200, [
                {"mac": "02:00:00:00:00:04", "last_ip": "192.168.1.53", "name": "Old iPad", "last_seen": now - 3600},
                # Its address is the connected roku's: an offline client never takes a connected one's address.
                {"mac": "02:00:00:00:00:08", "last_ip": "192.168.1.31", "hostname": "stale", "last_seen": now - 7200},
                # Outside the default 30 days: the console may still send it, TelltaleDNS doesn't use it.
                {"mac": "02:00:00:00:00:07", "last_ip": "192.168.1.52", "name": "Long gone laptop", "last_seen": now - 90 * 86400}])
        else:
            self.reply(404, {"meta": {"rc": "error"}})
    def log_message(self, *a):
        pass
class OPN(UniFi):
    def do_GET(self):
        ok = self.headers.get("authorization") == "Basic " + base64.b64encode(b"key1:secret1").decode()
        if not ok:
            return self.reply(401, {"status": 401})
        if self.path == "/api/dnsmasq/leases/search":
            return self.reply(404, {})
        if self.path == "/api/kea/leases4/search":
            return self.reply(200, {"rows": [{"address": "192.168.1.40", "hwaddr": "02:00:00:00:00:03", "hostname": "printer"}]})
        self.reply(404, {})
class HA(UniFi):
    # T22.3: Home Assistant renders the template; the fake checks it asks for the registry.
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path != "/api/template" or self.headers.get("authorization") != "Bearer ha-token":
            return self.reply(401, {"message": "unauthorized"})
        if "device_attr(d, 'connections')" not in body.get("template", ""):
            return self.reply(400, {"message": "unexpected template"})
        self.reply(200, {
            "devices": [
                {"name_by_user": "Living room Roku", "name": "Roku Ultra", "macs": ["02:00:00:00:00:02"], "area": "Living room"},
                {"name_by_user": "", "name": "Shelly Plug S", "macs": ["02:00:00:00:00:09"], "area": ""},
                {"name_by_user": "Somewhere else", "name": "x", "macs": ["02:00:00:00:00:99"]}],
            "trackers": [{"mac": "02:00:00:00:00:09", "ip": "192.168.20.9"}]})
s1 = http.server.ThreadingHTTPServer(("127.0.0.1", 26981), UniFi)
s2 = http.server.ThreadingHTTPServer(("127.0.0.1", 26982), OPN)
s3 = http.server.ThreadingHTTPServer(("127.0.0.1", 26983), HA)
threading.Thread(target=s1.serve_forever, daemon=True).start()
threading.Thread(target=s3.serve_forever, daemon=True).start()
s2.serve_forever()
EOF
python3 "$E/fake.py" "$E" & H=$!
for _ in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:26982/ && break; sleep 0.1; done
echo -n s3cret > "$E/unifi-pass"
echo -n key1 > "$E/opn-key"
echo -n secret1 > "$E/opn-secret"
echo -n ha-token > "$E/ha-token"

cat > "$E/telltale.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25992"
[api]
listen = "127.0.0.1:26992"
[telemetry.metrics]
listen = "127.0.0.1:27992"
[telemetry.qlog]
flush_interval_secs = 1
[[record]]
name = "nas.routers.test"
type = "A"
value = "10.0.0.8"
[[router]]
name = "udm"
type = "unifi"
url = "http://127.0.0.1:26981"
username = "telltale"
password_file = "$E/unifi-pass"
[[router]]
name = "opnsense"
type = "opnsense"
url = "http://127.0.0.1:26982"
api_key_file = "$E/opn-key"
api_secret_file = "$E/opn-secret"
[[router]]
name = "ha"
type = "home_assistant"
url = "http://127.0.0.1:26983"
api_key_file = "$E/ha-token"
[local]
device_domain = "home.arpa"
[clients]
mdns = true
mdns_port = 25353
EOF
"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.1; done
for _ in $(seq 50); do [ "$(grep -c 'router integration: devices read' "$E/node.log")" -ge 2 ] && break; sleep 0.2; done
[ "$(grep -c 'router integration: devices read' "$E/node.log")" -ge 2 ] || fail "both routers weren't read"
for _ in $(seq 50); do grep -q 'Home Assistant: devices read' "$E/node.log" && break; sleep 0.2; done
grep -q 'Home Assistant: devices read' "$E/node.log" || fail "Home Assistant wasn't read"
# The device-name table is rebuilt every 10 s.
for _ in $(seq 150); do grep -q 'device names in DNS: updated.*names=[1-9]' "$E/node.log" && break; sleep 0.1; done
grep -q 'device names in DNS: updated.*names=[1-9]' "$E/node.log" || fail "no device names in DNS"

ST=$(cat "$E/data/setup-token")
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"routers-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]')
curl -sf -b "$E/jar" "$API/api/v1/dhcp/leases" | python3 -c '
import json, sys
items = {x["ip"]: x for x in json.load(sys.stdin)["items"]}
assert items["127.0.0.1"]["hostname"] == "Desk laptop" and items["127.0.0.1"]["source"] == "router", items
# REQ: T8.2 (ADR-166) — the connected device keeps its address; a name given to an offline client
# (the stale one, if any) does not take it.
assert items["192.168.1.31"]["mac"] == "02:00:00:00:00:02" and items["192.168.1.31"]["hostname"] != "stale", items["192.168.1.31"]
# REQ: T8.2 (ADR-166, ADR-942) — an offline client is listed, marked offline, and names nothing in
# DNS (checked below); its name still answers in the query log. Connected rows are marked offline false.
assert items["192.168.1.53"]["offline"] is True, "an offline client is listed, marked offline"
assert "dnsName" not in items["192.168.1.53"], "an offline client has no DNS name"
assert items["192.168.1.31"]["offline"] is False and items["127.0.0.1"]["offline"] is False, "connected rows"
assert items["192.168.1.51"]["hostname"] == "Garage camera", "a reserved camera (rest/user)"
assert "192.168.1.52" not in items, "a client last seen 90 days ago is outside offline_days (30)"
assert items["192.168.1.40"]["hostname"] == "printer", "Kea leases from OPNsense"
# T22.2: a reservation names an offline device; a known client without one does not.
assert items["192.168.1.50"]["hostname"] == "Office printer" and items["192.168.1.50"]["router"] == "udm", items
assert items["192.168.1.60"]["offline"] is True and "dnsName" not in items["192.168.1.60"], "no reservation, no DNS name (listed offline)"
# T22.3: the name given in Home Assistant wins over the router host name; the HA tracker
# gives the plug its address; a registry device without an address anywhere is skipped.
roku = items["192.168.1.31"]
assert roku["hostname"] == "Living room Roku" and roku["router"] == "ha", roku
assert items["192.168.20.9"]["hostname"] == "Shelly Plug S", items
# T22.1: the name each answers as.
assert roku["dnsName"] == "living-room-roku.home.arpa", roku
assert items["127.0.0.1"]["dnsName"] == "desk-laptop.home.arpa", items["127.0.0.1"]
print(f"leases: {len(items)} from the routers and Home Assistant")
' || fail "leases API"
# REQ: T8.2 (ADR-166) — the console is asked only for the window (30 days = 720 hours).
grep -q "withinHours=720" "$E/history.path" || fail "the history request didn't carry the window: $(cat "$E/history.path")"

# REQ: API-013 (T22.2) — the networks, their sizes, and the devices in them.
curl -sf -b "$E/jar" "$API/api/v1/networks" | python3 -c '
import json, sys
nets = {n["name"]: n for n in json.load(sys.stdin)["items"]}
assert set(nets) == {"Default", "IoT"}, nets
d, iot = nets["Default"], nets["IoT"]
assert (d["subnet"], d["gateway"], d["dhcpStart"], d["dhcpEnd"], d["domain"]) == ("192.168.1.0/24", "192.168.1.1", "192.168.1.6", "192.168.1.49", "home.arpa"), d
assert (d["addresses"], d["devices"], d["outsidePool"], d["router"]) == (254, 4, 2, "udm"), d
assert (iot["vlan"], iot["devices"]) == (20, 1), iot
print("networks: Default 4 devices (2 outside the pool), IoT 1")
' || fail "networks API"

# REQ: DNS-023 (T22.1) — device names and their PTRs answer in DNS.
ask() { dig +short -p 25992 @127.0.0.1 "$@"; }
[ "$(ask living-room-roku.home.arpa)" = "192.168.1.31" ] || fail "a Home Assistant name in DNS"
[ "$(ask office-printer.home.arpa)" = "192.168.1.50" ] || fail "a reservation in DNS"
[ "$(ask shelly-plug-s.home.arpa)" = "192.168.20.9" ] || fail "a tracker address in DNS"
[ "$(ask -x 192.168.1.31)" = "living-room-roku.home.arpa." ] || fail "the PTR"
# REQ: T8.2 (ADR-166) — an offline client's last address names nothing in DNS.
[ -z "$(ask old-ipad.home.arpa)" ] || fail "an offline client's name in DNS"
[ "$(ask nas.routers.test)" = "10.0.0.8" ] || fail "configured records still answer"
echo "dns: device names and PTRs answer"

# A device named from the router in the query log.
dig +short -p 25992 @127.0.0.1 nas.routers.test >/dev/null
sleep 2
curl -sf -b "$E/jar" "$API/api/v1/queries?name=nas.routers.test" | python3 -c '
import json, sys
rows = json.load(sys.stdin)["items"]
assert rows and rows[0]["clientName"] == "Desk laptop", rows[:1]
print("query log: the device is named Desk laptop")
' || fail "naming"

# REQ: T8.3 — a device that announces nas-box.local over mDNS (sent unicast here) is named so.
python3 - <<'EOF'
import socket
def wire(n):
    return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\0"
m = bytes([0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]) + wire("nas-box.local")
m += bytes([0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 127, 0, 0, 2])
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(m, ("127.0.0.1", 25353))
EOF
sleep 6
dig +short -b 127.0.0.2 -p 25992 @127.0.0.1 nas.routers.test >/dev/null
sleep 2
curl -sf -b "$E/jar" "$API/api/v1/queries?name=nas.routers.test" | python3 -c '
import json, sys
rows = [r for r in json.load(sys.stdin)["items"] if r["client"] == "127.0.0.2"]
assert rows and rows[0]["clientName"] == "nas-box", rows[:1]
print("query log: the mDNS device is named nas-box")
' || fail "mDNS naming"
echo "routers-e2e: ok"
