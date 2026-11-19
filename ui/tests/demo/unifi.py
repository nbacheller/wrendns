#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A stub UniFi Network API for the screenshot demo (run.sh). REQ: API-013, DSC-901, DOC-002.

It answers the reads WrenDNS makes with an API key (`/proxy/network/api/s/default/...`): the
connected clients (`stat/sta`), the known clients (`rest/user`), the networks (`rest/networkconf`)
and the gateway's own devices (`stat/device`). Everything is made up: the devices are the demo's
(demo.toml, on loopback addresses), their MACs are invented (a real maker's prefix, so the
"what is this device" guess has something to go on, and random digits after it), and the key is
the throwaway one run.sh writes. Loopback only. usage: unifi.py <port>
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 25480
KEY = "demo-key-not-a-secret"
NOW = int(time.time())
DAY = 86_400

SWITCH = "02:00:5e:10:00:01"
AP = "02:00:5e:10:00:02"
# (mac, ip, UniFi alias, host name, wired?, switch port or None, network, vlan, first seen days ago)
CLIENTS = [
    ("f0:18:98:4a:21:0c", "127.0.1.11", "Mom's Phone", "moms-iphone", False, None, "Family", 0, 410),
    ("3c:22:fb:7e:90:14", "127.0.1.14", "", "macbook-guest", False, None, "Family", 0, 2),
    ("28:18:78:5d:c2:31", "127.0.4.30", "Dad's Laptop", "dads-surface", True, 3, "Work", 40, 220),
    ("f0:18:98:66:0b:a2", "127.0.2.10", "Ava's iPad", "avas-ipad", False, None, "Kids", 30, 180),
    ("d8:bb:c1:2e:47:5f", "127.0.2.12", "Gaming PC", "gaming-pc", True, 5, "Kids", 30, 95),
    ("b0:a7:37:19:e3:88", "127.0.3.20", "Living Room TV", "roku-living-room", True, 7, "IoT", 20, 300),
    ("44:61:32:8a:5c:01", "127.0.3.21", "Thermostat", "ecobee-hall", False, None, "IoT", 20, 512),
    ("5c:aa:fd:3b:17:e6", "127.0.3.22", "", "sonos-kitchen", False, None, "IoT", 20, 260),
]
NETWORKS = [
    ("Family", 0, "127.0.1.1/24", "127.0.1.100", "127.0.1.200"),
    ("Kids", 30, "127.0.2.1/24", "127.0.2.100", "127.0.2.200"),
    ("IoT", 20, "127.0.3.1/24", "127.0.3.100", "127.0.3.200"),
    ("Work", 40, "127.0.4.1/24", "127.0.4.100", "127.0.4.200"),
]


def sta():
    rows = []
    for mac, ip, alias, host, wired, port, net, vlan, days in CLIENTS:
        r = {"mac": mac, "ip": ip, "hostname": host, "is_wired": wired, "network": net,
             "first_seen": NOW - days * DAY, "last_seen": NOW - 5}
        if alias:
            r["name"] = alias
        if vlan:
            r["vlan"] = vlan
        if wired:
            r["sw_mac"], r["sw_port"] = SWITCH, port
        else:
            r["ap_mac"], r["essid"] = AP, "home-wifi"
        rows.append(r)
    return rows


def users():
    return [{"mac": mac, "name": alias or host, "hostname": host, "first_seen": NOW - days * DAY,
             "last_seen": NOW - 5, "use_fixedip": wired, **({"fixed_ip": ip} if wired else {})}
            for mac, ip, alias, host, wired, _p, _n, _v, days in CLIENTS]


def networks():
    out = []
    for name, vlan, subnet, start, stop in NETWORKS:
        n = {"name": name, "purpose": "corporate", "ip_subnet": subnet, "dhcpd_enabled": True,
             "dhcpd_start": start, "dhcpd_stop": stop, "domain_name": "home.arpa"}
        if vlan:
            n["vlan_enabled"], n["vlan"] = True, vlan
        out.append(n)
    return out


def devices():
    return [
        {"_id": "demo-switch-1", "mac": SWITCH, "name": "Office switch", "model": "USW-Lite-8-PoE",
         "type": "usw", "serial": "DEMO0001", "ip": "127.0.9.2"},
        {"_id": "demo-ap-1", "mac": AP, "name": "Hallway AP", "model": "U6-Lite", "type": "uap",
         "serial": "DEMO0002", "ip": "127.0.9.3"},
    ]


ROUTES = {"stat/sta": sta, "rest/user": users, "rest/networkconf": networks, "stat/device": devices,
          "stat/alluser": users}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (http.server's name)
        if self.headers.get("x-api-key") != KEY:
            self.send_error(401)
            return
        prefix = "/proxy/network/api/s/default/"
        path = self.path.split("?")[0]
        if path == "/proxy/network/v2/api/site/default/clients/history":
            body = b"[]"  # nobody is offline on the demo network
        else:
            fn = ROUTES.get(path[len(prefix):]) if path.startswith(prefix) else None
            if fn is None:
                self.send_error(404)
                return
            body = json.dumps({"meta": {"rc": "ok"}, "data": fn()}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
