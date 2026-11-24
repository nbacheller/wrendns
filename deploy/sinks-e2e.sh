#!/usr/bin/env bash
# REQ: OBS-010 — T7.12/T7.13 acceptance: a running node copies its query events to a
# JSON-lines file, a syslog collector (UDP, and T9.11: TLS with a private CA), and a batched
# webhook, and sends an alert (and nothing on the DNS path waits for any of them). T9.11: a
# webhook whose collector is down keeps its batches on disk and sends them when it's back.
# Needs python3, dig, curl, openssl.
# Usage: deploy/sinks-e2e.sh [path/to/wrendns]   (default: target/debug/wrendns)
set -euo pipefail
cd "$(dirname "$0")/.."
B=${1:-target/debug/wrendns}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P=
H=
S=
T=
L=
cleanup() {
  local rc=$?
  for p in $P $H $S $T $L; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$E"
  exit "$rc"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  [ -f "$E/node.log" ] && tail -15 "$E/node.log"
  # The TLS collector's own log (when it listened, each connection and handshake, with times).
  [ -f "$E/tls.log" ] && { echo "--- syslog TLS collector log"; tail -15 "$E/tls.log"; }
  exit 1
}
trap 'fail "line $LINENO: \`$BASH_COMMAND\` failed"' ERR

# A webhook collector (every POST body to posts/<n>, with its path) and a syslog collector.
cat > "$E/collect.py" <<'EOF'
import http.server, os, socket, sys, threading
out = sys.argv[1]
os.makedirs(out + "/posts", exist_ok=True)
n = [0]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        n[0] += 1
        with open(f"{out}/posts/{n[0]:04d}", "wb") as f:
            f.write(self.path.encode() + b"\n" + self.headers.get("content-type", "").encode() + b"\n" + body)
        self.send_response(204)
        self.end_headers()
    def log_message(self, *a):
        pass
def syslog():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 25515))
    with open(out + "/syslog", "ab", buffering=0) as f:
        while True:
            f.write(s.recv(65535) + b"\n")
threading.Thread(target=syslog, daemon=True).start()
http.server.ThreadingHTTPServer(("127.0.0.1", 25580), H).serve_forever()
EOF
python3 "$E/collect.py" "$E" & H=$!

# REQ: OBS-010 (T9.11) — a TLS syslog collector (RFC 5425) with a certificate from a private
# CA (what tls_ca trusts); octet-counted frames to syslog-tls.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=e2e-syslog-ca \
  -keyout "$E/ca.key" -out "$E/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj /CN=localhost -keyout "$E/key.pem" -out "$E/req.pem" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$E/ext.cnf"
openssl x509 -req -in "$E/req.pem" -CA "$E/ca.pem" -CAkey "$E/ca.key" -CAcreateserial -days 1 \
  -extfile "$E/ext.cnf" -out "$E/cert.pem" 2>/dev/null
cat > "$E/tls_syslog.py" <<'EOF'
import socket, ssl, sys, threading, time
out = sys.argv[1]
def log(m):
    with open(out + "/tls.log", "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')}.{int(time.time() * 1000) % 1000:03d} {m}\n")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(out + "/cert.pem", out + "/key.pem")
l = socket.socket()
l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", 25516))
l.listen()
log("listening")
open(out + "/tls.ready", "w").close()
def serve(c):
    try:
        with ctx.wrap_socket(c, server_side=True) as t, open(out + "/syslog-tls", "ab", buffering=0) as f:
            log("handshake done")
            while True:
                d = t.recv(65535)
                if not d:
                    log("closed by the node")
                    return
                f.write(d)
    except Exception as e:
        log(f"connection failed: {e!r}")
while True:
    c, _ = l.accept()
    log("accepted")
    threading.Thread(target=serve, args=(c,), daemon=True).start()
EOF
python3 "$E/tls_syslog.py" "$E" & T=$!
# A syslog sink over TCP or TLS connects when its first event arrives and does not queue: an
# event sent while the collector is not listening is dropped, and the next event reconnects
# (ADR-072; docs/running.md, "Syslog over TLS"). So the node must not start, and no event be
# made, before this collector listens. A busy runner can take over a second to start python.
for _ in $(seq 100); do [ -e "$E/tls.ready" ] && break; sleep 0.1; done
[ -e "$E/tls.ready" ] || fail "the syslog TLS collector did not start listening in 10 s"

cat > "$E/wrendns.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25994"
[api]
listen = "127.0.0.1:26994"
[telemetry.metrics]
listen = "127.0.0.1:27994"
[[record]]
name = "nas.sinks.test"
type = "A"
value = "10.0.0.9"
[[list]]
name = "ads"
rules = ["ads.sinks.test"]
# A list that can't be downloaded: the alert rule below reports it.
[[list]]
name = "unreachable"
url = "http://127.0.0.1:25599/list.txt"
[[client]]
name = "kitchen-tablet"
match = ["127.0.0.1"]

[[telemetry.sink]]
name = "file"
type = "file"
path = "$E/events.jsonl"
[[telemetry.sink]]
name = "syslog"
type = "syslog"
address = "udp://127.0.0.1:25515"
statuses = ["blocked"]
[[telemetry.sink]]
name = "syslog-tls"
type = "syslog"
address = "tls://localhost:25516"
tls_ca = "$E/ca.pem"
statuses = ["blocked"]
# REQ: OBS-010 (T9.11) — its collector starts later: batches wait on disk.
[[telemetry.sink]]
name = "late"
type = "webhook"
url = "http://127.0.0.1:25581/late"
flush_secs = 1
spill_max_bytes = "1MiB"
[[telemetry.sink]]
name = "collector"
type = "webhook"
url = "http://127.0.0.1:25580/ingest"
flush_secs = 1
# REQ: OBS-006 (T7.17) — query events as OpenTelemetry logs, and metrics over OTLP/HTTP.
[[telemetry.sink]]
name = "otel-logs"
type = "webhook"
url = "http://127.0.0.1:25580/v1/logs"
format = "otlp_logs"
flush_secs = 1
[telemetry.otlp]
endpoint = "http://127.0.0.1:25580"
interval_secs = 5

[alerts]
interval_secs = 5
[[alerts.destination]]
name = "hook"
type = "webhook"
url = "http://127.0.0.1:25580/alert"
[[alerts.rule]]
name = "Lists failing"
when = "list_failing"
for_secs = 0
to = ["hook"]
EOF
"$B" run -c "$E/wrendns.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:26994/api/v1/auth/status" && break; sleep 0.1; done
# The first snapshot waits for the unreachable list's fetch to give up (about 10 s).
for _ in $(seq 60); do [[ $(dig +time=1 -p 25994 @127.0.0.1 ads.sinks.test) == *'EDE: 15'* ]] && break; sleep 0.5; done
for _ in $(seq 5); do dig +short +time=1 -p 25994 @127.0.0.1 nas.sinks.test >/dev/null || true; done

# File: one JSON object per event, the API's query-row fields.
for _ in $(seq 50); do [ "$(grep -c 'nas.sinks.test' "$E/events.jsonl" 2>/dev/null)" -ge 5 ] 2>/dev/null && break; sleep 0.2; done
python3 - "$E/events.jsonl" <<'EOF' || fail "file sink"
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
nas = [r for r in rows if r["name"] == "nas.sinks.test"]
ads = [r for r in rows if r["name"] == "ads.sinks.test"]
assert len(nas) >= 5, sorted({(r["name"], r["status"]) for r in rows})
assert nas[0]["status"] == "local" and nas[0]["clientName"] == "kitchen-tablet", nas[0]
assert ads and ads[-1]["status"] == "blocked" and ads[-1]["list"] == "ads", [(r["status"], r.get("list")) for r in ads][-3:]
print(f"file sink: {len(rows)} events")
EOF

# Syslog: RFC 5424, blocked events only (statuses filter), severity notice (local0 → 133).
for _ in $(seq 50); do grep -q 'ads.sinks.test' "$E/syslog" 2>/dev/null && break; sleep 0.2; done
grep -q '^<133>1 .* wrendns - query - {.*"name":"ads.sinks.test"' "$E/syslog" || fail "syslog: $(head -c 300 "$E/syslog")"
! grep -q 'nas.sinks.test' "$E/syslog" || fail "syslog got an event its statuses filter excludes"
echo "syslog sink: ok"

# REQ: OBS-010 (T9.11) — syslog over TLS: octet-counted RFC 5424 frames.
# The collector listened before the node started. A blocked query now and then gives the sink a
# new event to connect with, should its first connection have failed (events are not queued).
for i in $(seq 50); do
  grep -q 'ads.sinks.test' "$E/syslog-tls" 2>/dev/null && break
  [ $((i % 10)) -eq 0 ] && { dig +short +time=1 -p 25994 @127.0.0.1 ads.sinks.test >/dev/null 2>&1 || true; }
  sleep 0.2
done
grep -Eq '^[0-9]+ <133>1 .* wrendns - query - \{.*"name":"ads.sinks.test"' "$E/syslog-tls" || fail "syslog over TLS: $(head -c 300 "$E/syslog-tls" 2>/dev/null)"
echo "syslog over TLS: ok"

# Webhook: newline-delimited JSON batches.
for _ in $(seq 50); do grep -lq 'ads.sinks.test' "$E"/posts/* 2>/dev/null && break; sleep 0.2; done
python3 - "$E/posts" <<'EOF' || fail "webhook sink"
import json, os, sys
d = sys.argv[1]
events = 0
for f in sorted(os.listdir(d)):
    path, ct, body = open(os.path.join(d, f)).read().split("\n", 2)
    if path == "/ingest":
        assert ct == "application/x-ndjson", ct
        events += len([json.loads(l) for l in body.splitlines() if l])
assert events >= 6, events
print(f"webhook sink: {events} events")
EOF

# OTLP: metrics every 5 s, and query events as log records.
for _ in $(seq 60); do grep -lq '^/v1/metrics' "$E"/posts/* 2>/dev/null && break; sleep 0.5; done
python3 - "$E/posts" <<'EOF' || fail "OTLP"
import json, os, sys
d = sys.argv[1]
metrics, logs = None, []
for f in sorted(os.listdir(d)):
    path, ct, body = open(os.path.join(d, f)).read().split("\n", 2)
    if path == "/v1/metrics":
        assert ct == "application/json", ct
        metrics = json.loads(body)
    elif path == "/v1/logs":
        logs += json.loads(body)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
assert metrics, "no OTLP metrics"
rm = metrics["resourceMetrics"][0]
names = {m["name"]: m for m in rm["scopeMetrics"][0]["metrics"]}
assert names["wrendns_queries_total"]["sum"]["isMonotonic"], names["wrendns_queries_total"]
assert "histogram" in names["wrendns_query_duration_seconds"]
assert any(a["key"] == "service.name" for a in rm["resource"]["attributes"])
attrs = [{a["key"]: a["value"].get("stringValue") for a in r["attributes"]} for r in logs]
assert any(a.get("dns.question.name") == "ads.sinks.test" and a.get("wrendns.status") == "blocked" for a in attrs), attrs[:3]
print(f"OTLP: {len(names)} metrics, {len(logs)} log records")
EOF

# Alert: the failing list, as JSON to the alert webhook.
# The list's failure is recorded once the fetcher's retries are over (about 40 s).
for _ in $(seq 180); do grep -lq '^/alert' "$E"/posts/* 2>/dev/null && break; sleep 0.5; done
python3 - "$E/posts" <<'EOF' || fail "alert"
import json, os, sys
d = sys.argv[1]
alerts = []
for f in sorted(os.listdir(d)):
    path, ct, body = open(os.path.join(d, f)).read().split("\n", 2)
    if path == "/alert":
        alerts.append(json.loads(body))
assert alerts, "no alert"
a = alerts[0]
assert a["rule"] == "Lists failing" and a["status"] == "firing" and a["subject"] == "unreachable", a
print("alert:", a["summary"])
EOF

# REQ: OBS-010 (T9.11) — the late collector: refused batches (after their retries, about 7 s)
# are kept on disk, then sent once it's up, and the spill file goes. A deadline, not a count of
# tries: on a loaded runner the retries take longer (CI 2026-11-20 gave up after 30 s). A query
# now and then keeps a batch going to the refused collector.
# The spill file is late-<12 hex of the endpoint's hash>.spill: print the ones that exist.
late_spill() { local f; for f in "$E"/data/sinks/late-*.spill; do [ -e "$f" ] && echo "$f"; done; return 0; }
late_spill_nonempty() { local f; for f in "$E"/data/sinks/late-*.spill; do [ -s "$f" ] && echo "$f"; done; return 0; }
deadline=$(( $(date +%s) + 120 ))
until [ -n "$(late_spill_nonempty)" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  dig +short +time=1 -p 25994 @127.0.0.1 ads.sinks.test >/dev/null 2>&1 || true
  sleep 1
done
if [ -z "$(late_spill_nonempty)" ]; then
  ls -la "$E/data/sinks" 2>&1 || true
  fail "no spill file for the late webhook (waited 120 s)"
fi
cat > "$E/late.py" <<'EOF'
import http.server, os, sys
out = sys.argv[1]
os.makedirs(out + "/late", exist_ok=True)
n = [0]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        n[0] += 1
        with open(f"{out}/late/{n[0]:04d}", "wb") as f:
            f.write(body)
        self.send_response(204)
        self.end_headers()
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", 25581), H).serve_forever()
EOF
python3 "$E/late.py" "$E" & L=$!
dig +short +time=1 -p 25994 @127.0.0.1 nas.sinks.test >/dev/null || true
for _ in $(seq 60); do grep -lq 'ads.sinks.test' "$E"/late/* 2>/dev/null && [ -z "$(late_spill)" ] && break; sleep 0.5; done
grep -lq 'ads.sinks.test' "$E"/late/* 2>/dev/null || fail "the kept batches never reached the late collector"
[ -z "$(late_spill)" ] || fail "spill file left after sending: $(late_spill)"
echo "webhook spill: $(cat "$E"/late/* | grep -c '"name"') events delivered late"

# DNS never waited: still answering.
[[ $(dig +short +time=1 -p 25994 @127.0.0.1 nas.sinks.test) == *10.0.0.9* ]] || fail "DNS stopped answering"
echo "sinks-e2e: ok"
