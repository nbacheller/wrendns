#!/usr/bin/env python3
"""Probes for deploy/cluster3/e2e.sh (Python 3 standard library only).

  probe.py dns PORT NAME                    one A query on 127.0.0.1:PORT -> "STATUS IP" (STATUS: NOERROR, NXDOMAIN, SERVFAIL, ..., TIMEOUT)
  probe.py login BASE JAR PASSFILE         first admin (setup token on stdin) or sign-in -> JAR (cookies and CSRF)
  probe.py req BASE JAR METHOD PATH [JSONFILE]   one API call -> first line the HTTP status, then the body
  probe.py jq JSONFILE EXPR                 print EXPR evaluated over the JSON document (variable d)
  probe.py load PORT NAME SECS RATE         a steady query loop -> "sent ok servfail timeout other"
  probe.py regression ...                   the upstream #7 check (see main)
  probe.py rolling ...                      the rolling restart with the answering-nodes monitor
  probe.py failover ...                     the failover loops and the promotion poll

Every probe is for the throwaway test cluster on 127.0.0.1. Credentials are read from files the
caller made in its temp directory; nothing here prints a secret.
"""
import http.client
import json
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HOST = "127.0.0.1"


# --- DNS ----------------------------------------------------------------------------------------

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def dns(port, name, timeout=1.0):
    """One A query over UDP. Returns (status, ip): status is a RCODE name or TIMEOUT."""
    qid = random.randrange(65536)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    q += struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (HOST, int(port)))
        r, _ = s.recvfrom(4096)
    except OSError:
        return "TIMEOUT", None
    finally:
        s.close()
    if len(r) < 12 or struct.unpack(">H", r[:2])[0] != qid:
        return "TIMEOUT", None
    rcode = RCODES.get(r[3] & 0x0F, "OTHER")
    answers = struct.unpack(">H", r[6:8])[0]
    if rcode == "NOERROR" and answers > 0:
        return rcode, ".".join(str(b) for b in r[-4:])
    return rcode, None


def load(port, name, secs, rate):
    """A steady query loop. Counts what came back, not whether the answer is right."""
    counts = {"sent": 0, "ok": 0, "servfail": 0, "timeout": 0, "other": 0}
    end = time.time() + secs
    gap = 1.0 / rate
    while time.time() < end:
        t0 = time.time()
        status, ip = dns(port, name, timeout=2.0)
        counts["sent"] += 1
        if status == "NOERROR" and ip:
            counts["ok"] += 1
        elif status == "SERVFAIL":
            counts["servfail"] += 1
        elif status == "TIMEOUT":
            counts["timeout"] += 1
        else:
            counts["other"] += 1
        time.sleep(max(0.0, gap - (time.time() - t0)))
    return counts


# --- HTTP API -----------------------------------------------------------------------------------

class Jar:
    """Cookies and the CSRF token, kept as a small JSON file per session. Cookies are sent as
    name=value pairs, so the Secure attribute of a plain-HTTP test cluster doesn't drop them."""

    def __init__(self, path):
        self.path = path
        try:
            with open(path) as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {"cookies": {}, "csrf": ""}

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f)


def call(base, jar, method, path, body=None, timeout=20.0):
    """Returns (status, body bytes). Status 0 when the connection failed or timed out."""
    headers = {}
    if jar is not None and jar.data["cookies"]:
        headers["cookie"] = "; ".join(f"{k}={v}" for k, v in jar.data["cookies"].items())
    if jar is not None and method != "GET" and jar.data["csrf"]:
        headers["x-csrf-token"] = jar.data["csrf"]
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers["content-type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers
    except (OSError, http.client.HTTPException, TimeoutError) as e:
        return 0, str(e).encode(), None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def absorb_cookies(jar, headers):
    if headers is None:
        return
    for value in headers.get_all("set-cookie") or []:
        pair = value.split(";", 1)[0]
        if "=" in pair:
            k, v = pair.split("=", 1)
            if v == "" or value.lower().find("max-age=0") >= 0:
                jar.data["cookies"].pop(k, None)
            else:
                jar.data["cookies"][k] = v


def login(base, jar_path, password_file, setup_token=None):
    jar = Jar(jar_path)
    with open(password_file) as f:
        password = f.read().strip()
    if setup_token:
        body = {"setupToken": setup_token, "username": "admin", "password": password}
        path = "/api/v1/auth/setup"
    else:
        body = {"username": "admin", "password": password}
        path = "/api/v1/auth/login"
    status, data, headers = call(base, None, "POST", path, body)
    if status in (200, 201):
        absorb_cookies(jar, headers)
        jar.data["csrf"] = json.loads(data)["csrfToken"]
        jar.save()
    return status


def req(base, jar_path, method, path, json_file=None):
    jar = Jar(jar_path) if jar_path not in ("-", "") else None
    body = None
    if json_file:
        with open(json_file, "rb") as f:
            body = f.read()
    status, data, headers = call(base, jar, method, path, body)
    if jar is not None:
        absorb_cookies(jar, headers)
        jar.save()
    return status, data


# --- scenarios ----------------------------------------------------------------------------------

def regression(args):
    """REQ: CLU-002, CLU-004 (upstream #7): with the primary paused, 20 concurrent reads at a
    replica each return within the bound, and its /livez, /metrics and DNS keep answering.
    args: API_BASE JAR DNS_PORT METRICS_BASE SECS BOUND_SECS"""
    api, jar, dns_port, metrics, secs, bound = args
    bound = float(bound)
    paths = [
        "/api/v1/clients",
        "/api/v1/config/entries",
        "/api/v1/discovery/status",
        "/api/v1/cluster",
    ]
    results = []
    lock = threading.Lock()

    # One loaded session, read-only: the 20 threads must not race a cookie file (a save between
    # two loads sent a request with no session).
    session = Jar(jar)

    def one(i):
        p = paths[i % len(paths)]
        t0 = time.time()
        status, _ = call(api, session, "GET", p)[:2]
        dt = time.time() - t0
        with lock:
            results.append((p, status, dt))

    dns_counts = {"sent": 0, "ok": 0, "servfail": 0, "timeout": 0, "other": 0}
    probes = {"livez": [0, 0], "metrics": [0, 0]}  # [answered, asked]
    stop = threading.Event()

    def dns_loop():
        c = load(dns_port, "ok.cluster3.test", float(secs), 20)
        dns_counts.update(c)

    def probe_loop():
        while not stop.is_set():
            for key, url in (("livez", "/livez"), ("metrics", "/metrics")):
                probes[key][1] += 1
                s, _ = call(metrics, None, "GET", url, timeout=5.0)[:2]
                if s == 200:
                    probes[key][0] += 1
            time.sleep(0.5)

    threads = [threading.Thread(target=dns_loop), threading.Thread(target=probe_loop)]
    for t in threads:
        t.start()
    time.sleep(0.5)
    workers = [threading.Thread(target=one, args=(i,)) for i in range(20)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(bound + 5)
    slow = [r for r in results if r[2] > bound]
    stop.set()
    for t in threads:
        t.join()
    worst = max((r[2] for r in results), default=0.0)
    print(json.dumps({
        "requests": len(results),
        "worst_seconds": round(worst, 2),
        "over_bound": len(slow),
        "statuses": sorted({str(r[1]) for r in results}),
        "dns": dns_counts,
        "livez": {"answered": probes["livez"][0], "asked": probes["livez"][1]},
        "metrics": {"answered": probes["metrics"][0], "asked": probes["metrics"][1]},
    }, sort_keys=True))
    ok = (
        len(results) == 20
        and not slow
        and probes["livez"][0] == probes["livez"][1] > 0
        and probes["metrics"][0] == probes["metrics"][1] > 0
        and dns_counts["timeout"] == 0
        and dns_counts["sent"] > 0
    )
    return 0 if ok else 1


def rolling(args):
    """REQ: CLU-004, CLU-005: restart each node in turn (`docker compose restart`) while a monitor
    asks every node's DNS about once a fifth of a second; at least MIN nodes must answer at every
    sample. args: MIN_ANSWERING SECONDS_PER_NODE COMPOSE_CMD(...) -- NAME:DNSPORT ..."""
    min_answering = int(args[0])
    per_node_wait = float(args[1])
    sep = args.index("--")
    compose = args[2:sep]
    nodes = [a.split(":") for a in args[sep + 1:]]
    samples = []
    stop = threading.Event()

    def monitor():
        while not stop.is_set():
            up = 0
            for _, port in nodes:
                if dns(port, "ok.cluster3.test", timeout=0.5)[0] == "NOERROR":
                    up += 1
            samples.append(up)
            time.sleep(0.2)

    t = threading.Thread(target=monitor)
    t.start()
    log = []
    for name, port in nodes:
        time.sleep(1.0)
        subprocess.run(compose + ["restart", name], check=True, stdout=subprocess.DEVNULL)
        came_back = False
        end = time.time() + per_node_wait
        while time.time() < end:
            if dns(port, "ok.cluster3.test", timeout=0.5)[0] == "NOERROR":
                came_back = True
                break
            time.sleep(0.2)
        log.append({"node": name, "back": came_back})
    time.sleep(1.0)
    stop.set()
    t.join()
    low = min(samples) if samples else 0
    print(json.dumps({"samples": len(samples), "min_answering": low, "restarts": log}, sort_keys=True))
    ok = low >= min_answering and all(x["back"] for x in log)
    return 0 if ok else 1


def failover(args):
    """REQ: CLU-005 (ADR-051, ADR-056): two survivors answer a steady loop while the cluster elects
    one of them, and a poll says which one reports itself primary.
    args: SECS RATE, then NAME API_BASE DNS_PORT JAR for each survivor (four arguments each)."""
    secs = float(args[0])
    rate = float(args[1])
    survivors = []
    rest = args[2:]
    for i in range(0, len(rest), 4):
        name, api, port, jar = rest[i:i + 4]
        survivors.append({"name": name, "api": api, "port": port, "jar": jar})
    loops = {}
    primary_seen = {}
    first_primary = {"at": None, "who": None}
    start = time.time()
    stop = threading.Event()

    def loop(s):
        loops[s["name"]] = load(s["port"], "ok.cluster3.test", secs, rate)

    def poll():
        while not stop.is_set():
            for s in survivors:
                status, data = req(s["api"], s["jar"], "GET", "/api/v1/cluster")
                if status != 200:
                    continue
                try:
                    me = [n for n in json.loads(data)["nodes"] if n.get("thisNode")]
                except (ValueError, KeyError):
                    continue
                primary = bool(me) and me[0].get("role") == "primary"
                primary_seen[s["name"]] = primary
                if primary and first_primary["who"] is None:
                    first_primary["who"] = s["name"]
                    first_primary["at"] = round(time.time() - start, 2)
            time.sleep(0.5)

    loopers = [threading.Thread(target=loop, args=(s,)) for s in survivors]
    poller = threading.Thread(target=poll)
    poller.start()
    for t in loopers:
        t.start()
    for t in loopers:
        t.join()
    stop.set()
    poller.join()
    print(json.dumps({
        "loops": loops,
        "first_primary": first_primary,
        "primary_seen": primary_seen,
    }, sort_keys=True))
    return 0


def main(argv):
    cmd = argv[1]
    if cmd == "dns":
        status, ip = dns(argv[2], argv[3])
        print(f"{status} {ip or '-'}")
        return 0
    if cmd == "login":
        status = login(argv[2], argv[3], argv[4], argv[5] if len(argv) > 5 else None)
        print(status)
        return 0 if status in (200, 201) else 1
    if cmd == "req":
        status, data = req(argv[2], argv[3], argv[4], argv[5], argv[6] if len(argv) > 6 else None)
        out = sys.stdout.buffer
        out.write(f"{status}\n".encode())
        out.write(data)
        out.write(b"\n")
        out.flush()
        return 0
    if cmd == "jq":
        with open(argv[2]) as f:
            d = json.load(f)
        out = eval(argv[3], {"d": d, "len": len, "str": str, "int": int, "sum": sum, "any": any, "all": all})
        print(json.dumps(out) if not isinstance(out, str) else out)
        return 0
    if cmd == "load":
        print(" ".join(str(v) for v in load(argv[2], argv[3], float(argv[4]), float(argv[5])).values()))
        return 0
    if cmd == "regression":
        return regression(argv[2:])
    if cmd == "rolling":
        return rolling(argv[2:])
    if cmd == "failover":
        return failover(argv[2:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
