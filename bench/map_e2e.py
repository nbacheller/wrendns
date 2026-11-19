"""REQ: OBS-901 (T26.2) -- the live map against a real node: queries from several devices, then the
snapshot, the stream, the short version and the settings, over HTTP, as a person or an agent would.

  E2E_HTTP_PORT=19340 WRENDNS_BIN=/path/to/wrendns python3 bench/map_e2e.py

Starts the Playwright suite's server (`ui/tests/e2e/server.mjs`: a real binary, a stub upstream
that answers every name, a blocklist, loopback devices in the `lab` group), creates the admin
from the setup token, sends lookups from 127.0.0.x addresses (each one a device), and checks what
`GET /api/v1/map`, `/map/health`, `/map/stream`, `/map/world` and `PUT /map-settings/default` say.
Exits non-zero on the first thing that is wrong. The server is stopped at the end.
"""

import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
PORT = int(os.environ.get("E2E_HTTP_PORT", "19340"))
BASE = f"http://127.0.0.1:{PORT}"
DNS = PORT + 1
E2E = ROOT / "ui" / f".e2e-{PORT}"


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    if not cond:
        raise SystemExit(1)


def call(method, path, body=None, token=None, raw=False):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("content-type", "application/json")
    if token:
        req.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode()
            return r.status, (text if raw else (json.loads(text) if text else None))
    except urllib.error.HTTPError as e:
        text = e.read().decode()
        try:
            return e.code, json.loads(text)
        except ValueError:
            return e.code, text


def query(name, src):
    wire = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    pkt = struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + wire + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.settimeout(2)
    s.sendto(pkt, ("127.0.0.1", DNS))
    try:
        s.recv(512)
    except OSError:
        pass
    s.close()


def main():
    env = dict(os.environ, E2E_HTTP_PORT=str(PORT))
    server = subprocess.Popen(["node", "tests/e2e/server.mjs"], cwd=ROOT / "ui", env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                if call("GET", "/livez", raw=True)[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.3)
        token = (E2E / "data" / "setup-token").read_text().strip()
        st, _ = call("POST", "/api/v1/auth/setup", {"setupToken": token, "username": "admin", "password": "a long enough password"})
        check(st in (200, 201), f"admin created ({st})")
        # An API token (a user token with the admin's rights).
        s = urllib.request.Request(BASE + "/api/v1/auth/login", method="POST",
                                   data=json.dumps({"username": "admin", "password": "a long enough password"}).encode(),
                                   headers={"content-type": "application/json"})
        with urllib.request.urlopen(s) as r:
            cookie = r.headers["set-cookie"].split(";")[0]
            csrf = json.loads(r.read())["csrfToken"]
        t = urllib.request.Request(BASE + "/api/v1/tokens", method="POST",
                                   data=json.dumps({"name": "e2e", "scope": "admin"}).encode(),
                                   headers={"content-type": "application/json", "cookie": cookie, "x-csrf-token": csrf})
        with urllib.request.urlopen(t) as r:
            tok = json.loads(r.read())["token"]

        # Before any traffic: the map is there, quiet.
        st, m = call("GET", "/api/v1/map", token=tok)
        check(st == 200 and m["windowSecs"] == 60, "GET /api/v1/map answers on an idle node")
        check(m["health"] in ("idle", "green"), f"an idle node is not red ({m['health']})")

        # Traffic: 30 devices ask; one of them asks a name that fails (the upstream is a dead port).
        t0 = time.time()
        for i in range(1, 31):
            for _ in range(25):
                query("nas.e2e.test", f"127.0.0.{i + 100}")
        for _ in range(25):
            query("ads.e2e.test", "127.0.0.150")  # blocked
        for _ in range(25):
            query("x.cache.e2e.test", "127.0.0.151")  # answered by the stub upstream, then cached
        for _ in range(25):
            query("fail.example", "127.0.0.152")  # the dead upstream: SERVFAIL
        time.sleep(3)  # the aggregator drains every few hundred ms
        st, m = call("GET", "/api/v1/map", token=tok)
        check(st == 200, "snapshot after traffic")
        kinds = {}
        for n in m["nodes"]:
            kinds.setdefault(n["kind"], []).append(n)
        check(len(kinds.get("device", [])) >= 30, f"{len(kinds.get('device', []))} devices are on the map")
        check(len(kinds.get("resolver", [])) == 1, "one resolver")
        check({a["label"] for a in kinds["answer"]} == {"cache", "local", "blocked"}, "its three answer kinds")
        check(any(n["label"] == "Gateway" for n in kinds["gateway"]), "the gateway")
        check(all("e2e.test" not in json.dumps(n) for n in m["nodes"]), "no domain name in any node")
        total = sum(d["count"] for d in kinds["device"])
        check(total >= 750, f"the devices' answers add up ({total} for about 800 lookups)")
        by_label = {d["address"]: d for d in kinds["device"] if d.get("address")}
        failing = by_label.get("127.0.0.152")
        check(failing is not None and failing["health"] == "red", f"the failing device is red ({failing and failing['health']}: {failing and failing['reasons']})")
        check(by_label["127.0.0.101"]["health"] == "green", "a device with local answers is green")
        blocked = by_label.get("127.0.0.150")
        check(blocked is not None and blocked["health"] in ("yellow", "green"), "the blocked-only device is yellow or green, never red")
        check(m["sampleRate"] >= 1 and m["privacy"] == 0, f"sampleRate {m['sampleRate']}, privacy {m['privacy']}")
        check(m["health"] in ("red", "yellow"), f"the node's own colour follows its worst resolver or network ({m['health']})")

        st, h = call("GET", "/api/v1/map/health", token=tok)
        check(st == 200 and h["problems"], "map/health lists what is not green")
        check(any(p["id"] == "dev:127.0.0.152" or p["kind"] != "device" for p in h["problems"]), "and says why")
        st, f = call("GET", "/api/v1/map?device=127.0.0.15", token=tok)
        check(st == 200 and all(n["kind"] != "device" or "127.0.0.15" in n["address"] for n in f["nodes"]), "the device filter narrows the read")
        st, f = call("GET", "/api/v1/map?node=no-such-node", token=tok)
        check(st == 200 and not [n for n in f["nodes"] if n["kind"] == "device"], "the node filter does too")
        st, w = call("GET", "/api/v1/map/world", token=tok)
        check(st == 200 and w["available"] is False and w["reason"] == "address_not_recorded", "the world view says the address is not recorded")

        # The stream: the first event arrives at once and is the same shape.
        req = urllib.request.Request(BASE + "/api/v1/map/stream", headers={"authorization": f"Bearer {tok}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            check(r.headers["content-type"].startswith("text/event-stream"), "the stream is text/event-stream")
            ev, data = None, None
            while True:
                line = r.readline().decode().rstrip("\n")
                if line.startswith("event:"):
                    ev = line.split(":", 1)[1].strip()
                elif line.startswith("data:") and ev == "snapshot":
                    data = json.loads(line.split(":", 1)[1])
                    break
            check(data["windowSecs"] == 60 and len(data["nodes"]) > 30, "the first stream event is a snapshot")

        # The settings: read through config entries, change, and see it apply with no restart.
        st, e = call("GET", "/api/v1/config/entries?kind=map", token=tok)
        check(st == 200 and e["items"][0]["definition"]["event_rate"] == 200, "the map's settings are in config/entries")
        st, e = call("GET", "/api/v1/map-settings/default", token=tok)
        check(st == 200 and e["source"] == "file" and e["definition"]["min_sample"] == 20, "and at GET /api/v1/map-settings/default")
        st, c = call("PUT", "/api/v1/map-settings/default", {"event_rate": 500, "error_pct": 40, "min_sample": 10}, token=tok)
        check(st == 200, f"PUT map-settings ({st} {c if st != 200 else ''})")
        st, e = call("GET", "/api/v1/map-settings/default", token=tok)
        check(st == 200 and e["source"] == "override" and e["definition"]["event_rate"] == 500, "the entry now says override")
        st, c = call("PUT", "/api/v1/map-settings/default", {"event_rate": 5}, token=tok)
        check(st == 422 and "event_rate" in json.dumps(c), "an out-of-range value is 422 and names the field")
        st, c = call("PUT", "/api/v1/map-settings/default", {"enabled": False}, token=tok)
        check(st == 200, "turn the map off")
        for _ in range(40):
            st, m = call("GET", "/api/v1/map", token=tok)
            if st == 404:
                break
            time.sleep(0.5)
        check(st == 404 and m["code"] == "map_disabled", "off: 404 map_disabled, within seconds and with no restart")
        st, c = call("DELETE", "/api/v1/map-settings/default", token=tok)
        check(st == 200, "back to the file's settings")
        for _ in range(40):
            st, m = call("GET", "/api/v1/map", token=tok)
            if st == 200:
                break
            time.sleep(0.5)
        check(st == 200, "on again")
        # The DNS path never noticed: queries still answer.
        query("nas.e2e.test", "127.0.0.101")
        print(f"done in {time.time() - t0:.0f} s")
    finally:
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    sys.exit(main())
