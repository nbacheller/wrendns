#!/usr/bin/env bash
# REQ: T8.2, T8.3 — router integrations against fake UniFi OS and OPNsense APIs, and mDNS: a UniFi login
# (cookie) and its client list (connected, then the offline clients it knows: the reserved ones and the
# history within offline_days), OPNsense leases with an API key, the leases in the API, and a device named
# from the router in the query log. REQ: T22.1–T22.3 (DNS-023, API-012, API-013) — UniFi reservations and
# networks, a fake Home Assistant's device registry (a name you gave wins over the router's; a tracker
# supplies an address), the networks API, and the device names answered in DNS with their PTRs.
# REQ: T25.10 (DSC-009, ADR-912) - the inventory's extra read-only reads against the same fakes: UniFi's
# client fields, `stat/device` (infrastructure, switch-port MAC tables, LLDP) and `POST stat/alluser`
# (history), Home Assistant's entity-less devices, and a second console that refuses `stat/device` and
# `stat/alluser` (403): the refusal is on the status, the other reads work, and nothing reaches the leases
# or DNS. The inventory file is read after a graceful stop (it is saved then).
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
        if self.path == "/proxy/network/api/s/default/stat/alluser":
            # T25.10: a query for clients seen within a window (it changes nothing); the fake notes the body.
            if "TOKEN=abc123" not in (self.headers.get("cookie") or ""):
                return self.reply(401, {"meta": {"rc": "error"}})
            open(sys.argv[1] + "/alluser.body", "w").write(json.dumps(creds))
            return self.reply(200, {"meta": {"rc": "ok"}, "data": [
                {"mac": "02:00:00:00:00:0a", "last_ip": "192.168.1.77", "name": "Old TV", "last_seen": int(time.time()) - 86400, "first_seen": 1700000000},
                {"mac": "02:00:00:00:00:0b", "last_ip": "192.168.1.78", "hostname": "ancient", "last_seen": int(time.time()) - 400 * 86400}]})
        if self.path == "/api/auth/login" and creds.get("username") == "telltale" and creds.get("password") == "s3cret":
            self.reply(200, {}, [("set-cookie", "TOKEN=abc123; Path=/; HttpOnly"), ("x-csrf-token", "x")])
        else:
            self.reply(401, {"error": "bad login"})
    def do_GET(self):
        if "TOKEN=abc123" not in (self.headers.get("cookie") or ""):
            return self.reply(401, {"meta": {"rc": "error", "msg": "api.err.LoginRequired"}})
        if self.path == "/proxy/network/api/s/default/stat/sta":
            self.reply(200, {"meta": {"rc": "ok"}, "data": [
                {"mac": "02:00:00:00:00:01", "ip": "127.0.0.1", "hostname": "laptop-77", "name": "Desk laptop",
                 "is_wired": True, "sw_mac": "aa:bb:cc:00:00:01", "sw_port": 3, "network": "Default", "vlan": 1, "first_seen": 1690000000},
                {"mac": "02:00:00:00:00:02", "ip": "192.168.1.31", "hostname": "roku",
                 "is_wired": False, "ap_mac": "aa:bb:cc:00:00:02", "network": "IoT", "vlan": 20}]})
        elif self.path == "/proxy/network/api/s/default/stat/device":
            # T25.10: a switch (a port with two MACs, a trunk with nine, an uplink) and an access point.
            trunk = [{"mac": "02:00:00:00:02:%02x" % i, "vlan": 1} for i in range(9)]
            self.reply(200, {"meta": {"rc": "ok"}, "data": [
                {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.2", "name": "USW-Pro", "type": "usw",
                 "uplink": {"port_idx": 24},
                 "lldp_table": [{"chassis_id": "aa:bb:cc:00:00:09", "chassis_name": "UCG", "port_id": "eth3", "local_port_idx": 24}],
                 "port_table": [
                     {"port_idx": 3, "mac_table": [{"mac": "02:00:00:00:00:01", "vlan": 1, "age": 20}, {"mac": "02:00:00:00:00:77", "vlan": 1, "static": True}]},
                     {"port_idx": 4, "mac_table": [{"mac": "02:00:00:00:00:42", "vlan": 20, "age": 5}]},
                     {"port_idx": 7, "mac_table": trunk},
                     {"port_idx": 24, "is_uplink": True, "mac_table": [{"mac": "02:00:00:00:00:55"}]}]},
                {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.3", "name": "AP-Lounge", "type": "uap"}]})
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
        if "area_devices" in body.get("template", ""):
            # T25.10: the second, fixed template: devices that have a MAC and no entity.
            open(sys.argv[1] + "/ha-entityless.template", "w").write(body["template"])
            return self.reply(200, {"devices": [
                {"name_by_user": "Hall hub", "name": "Hub", "macs": ["02:00:00:00:00:b1"], "area": "Hall"}]})
        if "device_attr(d, 'connections')" not in body.get("template", ""):
            return self.reply(400, {"message": "unexpected template"})
        self.reply(200, {
            "devices": [
                {"name_by_user": "Living room Roku", "name": "Roku Ultra", "macs": ["02:00:00:00:00:02"], "area": "Living room"},
                {"name_by_user": "", "name": "Shelly Plug S", "macs": ["02:00:00:00:00:09"], "area": ""},
                {"name_by_user": "Somewhere else", "name": "x", "macs": ["02:00:00:00:00:99"]}],
            "trackers": [{"mac": "02:00:00:00:00:09", "ip": "192.168.20.9"}]})
class Refusing(UniFi):
    # T25.10: a console whose key can't read devices or history: it answers 403 to both, and the
    # ordinary reads (clients, reservations, networks) still work.
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        creds = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/auth/login" and creds.get("username") == "telltale" and creds.get("password") == "s3cret":
            return self.reply(200, {}, [("set-cookie", "TOKEN=abc123; Path=/; HttpOnly"), ("x-csrf-token", "x")])
        if self.path.endswith("/stat/alluser"):
            return self.reply(403, {"meta": {"rc": "error", "msg": "api.err.NoPermission"}})
        self.reply(401, {"error": "bad login"})
    def do_GET(self):
        if "TOKEN=abc123" not in (self.headers.get("cookie") or ""):
            return self.reply(401, {"meta": {"rc": "error"}})
        if self.path.endswith("/stat/device"):
            return self.reply(403, {"meta": {"rc": "error", "msg": "api.err.NoPermission"}})
        if self.path.endswith("/stat/sta") or "/rest/" in self.path:
            return self.reply(200, {"meta": {"rc": "ok"}, "data": []})
        if "/clients/history" in self.path:
            return self.reply(200, [])
        self.reply(404, {"meta": {"rc": "error"}})
s1 = http.server.ThreadingHTTPServer(("127.0.0.1", 26981), UniFi)
s4 = http.server.ThreadingHTTPServer(("127.0.0.1", 26984), Refusing)
threading.Thread(target=s4.serve_forever, daemon=True).start()
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
name = "udm2"
type = "unifi"
url = "http://127.0.0.1:26984"
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
[discovery]
enabled = true
unifi_all_users_within_hours = 720
home_assistant_all_devices = true
[discovery.unifi_reads]
client_fields = true
all_users = true
devices = true
[[discovery.subnet]]
cidr = "192.168.1.0/24"
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

# REQ: T25.10 (DSC-009, ADR-912) - the extra reads. First what the status says about each read: the
# working console's three reads are ok, the refusing console's two are `refused`, and Home Assistant's
# entity-less read is ok.
for _ in $(seq 100); do
  n=$(curl -sf -b "$E/jar" "$API/api/v1/discovery/status" | field 'len(d["reads"])' 2>/dev/null || echo 0)
  [ "$n" -ge 6 ] && break
  sleep 0.2
done
curl -sf -b "$E/jar" "$API/api/v1/discovery/status" | python3 -c '
import json, sys
reads = {(r["router"], r["read"]): r for r in json.load(sys.stdin)["reads"]}
for k in [("udm", "devices"), ("udm", "all_users"), ("udm", "client_fields"), ("ha", "home_assistant_all_devices")]:
    assert reads[k]["state"] == "ok", (k, reads.get(k))
for k in [("udm2", "devices"), ("udm2", "all_users")]:
    assert reads[k]["state"] == "refused" and "403" in reads[k]["error"], (k, reads.get(k))
print("extra reads: udm ok x3, udm2 refused x2, Home Assistant ok")
' || fail "the extra reads' status"
# The query was a window of 720 hours, and the template was the fixed read-only one.
python3 -c "
import json
b = json.load(open('$E/alluser.body'))
assert b == {'type': 'all', 'conn': 'all', 'within': 720}, b
t = open('$E/ha-entityless.template').read()
assert 'device_entities' in t and 'service' not in t and 'set_state' not in t, t
print('stat/alluser asked for 720 hours; the Home Assistant template is the read-only one')
" || fail "the extra reads' requests"
# Nothing the extra reads found reaches the leases or DNS (ADR-910, ADR-912).
curl -sf -b "$E/jar" "$API/api/v1/dhcp/leases" | python3 -c '
import json, sys
items = json.load(sys.stdin)["items"]
ips = {x["ip"] for x in items}
macs = {x["mac"].lower() for x in items}
assert "192.168.1.77" not in ips, "a history address is in the leases"
assert "02:00:00:00:00:42" not in macs and "02:00:00:00:00:b1" not in macs, macs
' || fail "the leases must not hold what only the inventory reads found"
[ -z "$(ask old-tv.home.arpa)" ] || fail "a history name answers in DNS"
[ -z "$(ask hall-hub.home.arpa)" ] || fail "an entity-less Home Assistant name answers in DNS"
# The inventory is saved when the node stops: stop it, then read the file.
kill -TERM "$P"
for _ in $(seq 100); do kill -0 "$P" 2>/dev/null || break; sleep 0.1; done
P=
[ -f "$E/data/inventory.json" ] || fail "the inventory was not saved at shutdown"
python3 -c "
import json
inv = json.load(open('$E/data/inventory.json'))
def mac(b): return ':'.join('%02x' % x for x in b)
by = {mac(e['key']['value']): e for e in inv['entries'] if e['key']['kind'] == 'mac'}
laptop = by['02:00:00:00:00:01']
assert laptop['port'] == 'USW-Pro port 3' and laptop['network'] == 'Default' and laptop['vlan'] == 1, laptop
assert laptop['first_seen'] == 1690000000, laptop['first_seen']
roku = by['02:00:00:00:00:02']
assert roku['ap'] == 'AP-Lounge' and roku['network'] == 'IoT', roku
plug = by['02:00:00:00:00:42']
assert plug['port'] == 'USW-Pro port 4' and plug['vlan'] == 20 and plug['addrs'] == [], plug
assert '02:00:00:00:00:55' not in by and '02:00:00:00:00:77' not in by, 'an uplink or a static row gave a place'
assert not any(m.startswith('02:00:00:00:02:') for m in by), 'a trunk port gave places'
sw = by['aa:bb:cc:00:00:01']
assert sw['addrs'][0]['ip'] == '192.168.1.2' and sw['addrs'][0]['source'] == 'router' and sw['lldp'] == ['UCG eth3 on port 24'], sw
old = by['02:00:00:00:00:0a']
assert [(a['ip'], a['source']) for a in old['addrs']] == [('192.168.1.77', 'history')], old
assert old['names'][0]['kind'] == 'history' and old['names'][0]['label'] == 'Old TV', old
assert '02:00:00:00:00:0b' not in by, 'a client older than the window is in'
hub = by['02:00:00:00:00:b1']
assert hub['names'][0]['label'] == 'Hall hub' and hub['names'][0]['kind'] == 'ha_user' and hub['addrs'] == [], hub
print('inventory: places, AP, network, first seen, infrastructure with LLDP, history, entity-less Home Assistant')
" || fail "the saved inventory"
echo "routers-e2e: ok"
