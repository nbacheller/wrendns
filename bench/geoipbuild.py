"""REQ: OBS-902, NFR-001 (T26.4, ADR-1008 addendum (h)) -- what a GeoIP download and build costs the
resolver's resident memory, in the resolver's own configuration, and whether it comes back.

  # A release-profile binary with the bench hook (it trusts the fake source's certificate, nothing
  # else changes: the production limits, mimalloc's default arena, the purge at once of main.rs):
  cargo build --profile bench-fast -p wrendns --features geoip-probe
  python3 bench/geoipbuild.py                       # real-sized file, the 64 MiB gate set-up
  python3 bench/geoipbuild.py --scale 2             # twice the real file
  python3 bench/geoipbuild.py --names 0 --fill 0    # the build alone, on an idle node

What it does, one node per run (`VmHWM` is per process):

  1. writes a gzip CSV in DB-IP's format: `--v4` IPv4 and `--v6` IPv6 ranges (300,000 each by
     default, about the real file) of random length over 20 x 20 country codes, so few merge and
     the tables are near their largest;
  2. serves it over HTTPS from 127.0.0.1 with a throwaway certificate (openssl) the node is told to
     trust (`WRENDNS_GEOIP_TEST_CA`);
  3. starts the node with `--names` blocked names (the first of `bench/lists/*.txt`, or synthetic
     names when the lists are not here), `[map] enabled`, telemetry on and `[map.geoip]` pointed at
     the source but off, waits for the filter, fills the cache with `--fill` unique misses
     (dnsperf at `--fill-rate`), and reads RSS: **idle** (the spec/00 section 5 set-up with the
     defaults: 1,000,000 names, up to 100,000 cache entries);
  4. turns `[map.geoip] enabled` on and reloads (SIGHUP; an opt-in fetches at once) while the
     source holds its answer; once the request is in and the reload has settled (3 s), resets the
     peak (`/proc/<pid>/clear_refs` 5), reads **after the reload**, lets the source answer,
     samples RSS every 50 ms until
     `<data_dir>/geoip/country.ttgeo` is published, and reads **peak** (`VmHWM`), **after** (2 s
     after the file appears) and **settled** (`--after` seconds later, 30 by default);
  5. with `--builds N`, builds again N - 1 times in the same process (a changed `source_url` is
     fetched at once) and reads settled after each, so memory a build leaves behind shows as a
     climb.

`--control` reloads with nothing changed and skips the builds: the reload's own cost and the node's
drift over the same time. The
download (the client collects the body in one buffer, at most `max_download`, 32 MiB) is inside the
measured window, as in production. Pass: settled - idle <= 1.5 MiB after the last build, and, with
the gate set-up and the real lists, settled <= `--gate` (128 MiB, ADR-1031). Synthetic names compile larger
than the real lists, so without `bench/lists/` only what the build adds is checked.
"""

import argparse
import gzip
import hashlib
import http.server
import json
import os
import pathlib
import random
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import bench
import gate

MIB = 1024


def write_csv(path, v4, v6, seed=0x6E0):
    """DB-IP's `start,end,CC` rows, sorted, of random length, mostly back to back (as the real
    file is: it covers the address space) with a gap before one row in ten."""
    rng = random.Random(seed)
    codes = [chr(65 + a) + chr(65 + b) for a in range(20) for b in range(20)]
    with gzip.open(path, "wt", compresslevel=6) as f:
        lo, step = 1 << 24, max(2, ((223 << 24) - (1 << 24)) // max(v4, 1))
        for _ in range(v4):
            if rng.random() < 0.1:
                lo += rng.randrange(1, step // 2 + 1)
            hi = lo + rng.randrange(0, step // 2 + 1)
            f.write(f"{v4_text(lo)},{v4_text(hi)},{rng.choice(codes)}\n")
            lo = hi + 1
        lo = 0x2001 << 112
        for _ in range(v6):
            if rng.random() < 0.1:
                lo += rng.randrange(1, 1 << 8) << 64
            hi = lo + (rng.randrange(1, 1 << 12) << 64) - 1
            f.write(f"{v6_text(lo)},{v6_text(hi)},{rng.choice(codes)}\n")
            lo = hi + 1


def v4_text(n):
    return socket.inet_ntoa(n.to_bytes(4, "big"))


def v6_text(n):
    return socket.inet_ntop(socket.AF_INET6, n.to_bytes(16, "big"))


def self_signed(d):
    cert, key = d / "source.pem", d / "source.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:FALSE"], check=True, capture_output=True)
    return cert, key


class Source:
    """HTTPS on 127.0.0.1 serving one file at any path; an answer waits while `go` is clear."""

    def __init__(self, port, body, cert, key):
        self.hits = 0
        self.go = threading.Event()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits += 1
                outer.go.wait()
                self.send_response(200)
                self.send_header("content-type", "application/gzip")
                self.send_header("content-length", str(len(body)))
                self.send_header("connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.go.set()
        self.httpd.shutdown()


def reload_with(st, old, new):
    text = st.cfg.read_text()
    st.cfg.write_text(re.sub(old, new, text, count=1))
    st.server.send_signal(signal.SIGHUP)


def hold_reload_release(st, src, old, new):
    """The reload (SIGHUP) asks the held source; once the request is in and the reload has
    settled, the peak is reset and the source answers. Returns RSS just before the answer."""
    src.go.clear()
    hits = src.hits
    reload_with(st, old, new)
    t0 = time.monotonic()
    while src.hits == hits:
        if time.monotonic() - t0 > 60 or st.server.poll() is not None:
            raise RuntimeError("the reload did not start a download in 60 s")
        time.sleep(0.05)
    time.sleep(3)
    pathlib.Path(f"/proc/{st.server.pid}/clear_refs").write_text("5")
    pre = status(st.server.pid)[0]
    src.go.set()
    return pre


def wait_build(st, db, before, src, top):
    """Until the database file changes; returns the highest RSS sampled."""
    t0 = time.monotonic()
    while not db.exists() or db.stat().st_mtime_ns == before:
        if time.monotonic() - t0 > 180 or st.server.poll() is not None:
            log = (st.data_dir / "server.log").read_text(errors="replace")
            raise RuntimeError(f"no database after 180 s; the source was asked {src.hits} time(s); "
                               f"the node's log:\n{log[-3000:]}")
        top = max(top, status(st.server.pid)[0])
        time.sleep(0.05)
    return top


def names_list(n, d):
    """The list file and whether its names are synthetic."""
    path = d / "names.txt"
    try:
        return gate.write_lines(path, gate.blocked_names(n)), False
    except SystemExit:
        rng = random.Random(0xB10C)
        words = ["ads", "track", "metric", "pixel", "cdn", "stat", "beacon", "tag", "click", "log"]
        names = [f"{rng.choice(words)}{i}-{rng.randrange(1 << 30):x}.{rng.choice(words)}{i % 997}.example"
                 for i in range(n)]
        print(f"bench/lists/ is not here: {n:,} synthetic names (the absolute gate is not checked)", flush=True)
    return gate.write_lines(path, names), True


def split(pid):
    """(anonymous, file-backed) resident MiB: the heap against the executable's pages."""
    try:
        text = pathlib.Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return 0.0, 0.0
    kib = {k: int(v) for k, v in re.findall(r"^(RssAnon|RssFile):\s+(\d+)", text, re.M)}
    return round(kib.get("RssAnon", 0) / MIB, 1), round(kib.get("RssFile", 0) / MIB, 1)


def status(pid):
    s = bench.proc_stats(pid) or {}
    return round((s.get("rss_kib") or 0) / MIB, 1), round((s.get("hwm_kib") or 0) / MIB, 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=str(bench.ROOT / "target/bench-fast/wrendns"))
    ap.add_argument("--v4", type=int, default=300_000)
    ap.add_argument("--v6", type=int, default=300_000)
    ap.add_argument("--scale", type=float, default=1.0, help="multiplies --v4 and --v6")
    ap.add_argument("--names", type=int, default=1_000_000, help="blocked names (0: no list)")
    ap.add_argument("--fill", type=int, default=100_000, help="unique misses sent to fill the cache (0: none)")
    ap.add_argument("--fill-rate", type=int, default=2_000,
                    help="misses a second (each is an upstream query; faster trips the watchdog on Docker Desktop)")
    ap.add_argument("--fill-seconds", type=int, default=75)
    ap.add_argument("--upstream", choices=["tcp", "udp"], default="tcp", help="how the node reaches the stub upstream")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--server-cpus", default="0-3")
    ap.add_argument("--settle", type=int, default=10, help="seconds before the idle reading")
    ap.add_argument("--after", type=int, default=30, help="seconds from 'after' to 'settled'")
    ap.add_argument("--gate", type=float, default=128.0)  # ADR-1031
    ap.add_argument("--port", type=int, default=6500, help="DNS; +1 upstream stub, +2 metrics, +9 the source")
    ap.add_argument("--builds", type=int, default=1, help="builds in one process (2nd and later: a changed source, SIGHUP)")
    ap.add_argument("--control", action="store_true",
                    help="no build: the same readings over the same time (the node's own drift)")
    ap.add_argument("--json", help="also write the result here")
    args = ap.parse_args()
    args.threads, args.clients, args.outstanding = 2, 4, 200
    bench.DNS_PORT, bench.STUB_PORT, bench.METRICS_PORT = args.port, args.port + 1, args.port + 2
    gate.URL = f"http://127.0.0.1:{bench.METRICS_PORT}"
    gate.TARGET = ("127.0.0.1", bench.DNS_PORT)
    v4, v6 = int(args.v4 * args.scale), int(args.v6 * args.scale)

    tmp = tempfile.TemporaryDirectory(prefix="wrendns-geoipbuild-")
    d = pathlib.Path(tmp.name)
    gz = d / "db.csv.gz"
    write_csv(gz, v4, v6)
    body = gz.read_bytes()
    cert, key = self_signed(d)
    src = Source(args.port + 9, body, cert, key)
    data = d / "node"
    data.mkdir()
    lst, synthetic = names_list(args.names, d) if args.names else (None, False)
    st = gate.Stack(args, data, lst)
    if args.upstream == "tcp":
        # A UDP upstream query binds a fresh socket (RFC 5452), about 50 ms each on Docker Desktop:
        # the fill would take hours. Over TCP the connection is reused; the cache holds the same.
        st.cfg.write_text(st.cfg.read_text().replace(f'url = "udp://127.0.0.1:{bench.STUB_PORT}"',
                                                     f'url = "tcp://127.0.0.1:{bench.STUB_PORT}"'))
    st.cfg.write_text(st.cfg.read_text() + "\n[map]\nenabled = true\n[map.geoip]\nenabled = false\n"
                      f'source_url = "https://127.0.0.1:{args.port + 9}/db.csv.gz"\n'
                      f'sha256 = "{hashlib.sha256(body).hexdigest()}"\n')
    os.environ["WRENDNS_GEOIP_TEST_CA"] = str(cert)
    r = {"synthetic_names": synthetic, "control": args.control, "v4": v4, "v6": v6, "compressed_mib": round(len(body) / 1048576, 2), "names": args.names,
         "bin": args.bin, "workers": args.workers}
    try:
        st.start()
        if lst:
            bench.wait_filter(f"{gate.URL}/metrics", st.server)
        if args.fill:
            import corpus
            miss, _ = corpus.generate("miss-heavy", d / "corpora")
            fill = gate.write_lines(d / "fill.txt", miss.read_text().splitlines()[:args.fill])
            gate.perf(fill, args.fill_seconds, args, max_qps=args.fill_rate, once=True)
        r["cache_entries"] = bench.metric_sum(f"{gate.URL}/metrics", "wrendns_cache_entries")
        time.sleep(args.settle)
        if "watchdog wrote its dump" in (data / "server.log").read_text(errors="replace"):
            raise RuntimeError("the watchdog restarted the node during the fill: lower --fill-rate")
        r["idle_mib"], r["start_peak_mib"] = status(st.server.pid)
        r["idle_anon_file_mib"] = split(st.server.pid)
        print(f"idle: {r['idle_mib']} MiB (start-up peak {r['start_peak_mib']}), {r['cache_entries']} cache entries,"
              f" source asked {src.hits} time(s)", flush=True)
        db = data / "geoip" / "country.ttgeo"
        r["settled_by_build"], top = [], 0.0
        if args.control:
            # The same reload with nothing changed: what a SIGHUP alone costs.
            st.server.send_signal(signal.SIGHUP)
            time.sleep(5)
            pathlib.Path(f"/proc/{st.server.pid}/clear_refs").write_text("5")
            r["pre_build_mib"] = status(st.server.pid)[0]
            t0 = time.monotonic()
            time.sleep(2)
        else:
            r["pre_build_mib"] = hold_reload_release(st, src, r"\[map\.geoip\]\nenabled = false",
                                                     "[map.geoip]\nenabled = true")
            t0 = time.monotonic()
            top = wait_build(st, db, None, src, top)
            time.sleep(2)
        r["build_s"] = round(time.monotonic() - t0 - 2, 2)
        r["after_mib"], r["peak_mib"] = status(st.server.pid)
        time.sleep(args.after)
        r["settled_mib"] = status(st.server.pid)[0]
        r["settled_anon_file_mib"] = split(st.server.pid)
        r["settled_by_build"].append(r["settled_mib"])
        r["db_mib"] = round(db.stat().st_size / 1048576, 2) if db.exists() else 0
        for k in range(2, 0 if args.control else args.builds + 1):
            before = db.stat().st_mtime_ns
            hold_reload_release(st, src, r"/db\d*\.csv\.gz", f"/db{k}.csv.gz")
            top = wait_build(st, db, before, src, top)
            time.sleep(2 + args.after)
            r["settled_by_build"].append(status(st.server.pid)[0])
        r["sampled_top_mib"] = top
        r["peak_all_builds_mib"] = status(st.server.pid)[1]
        r["settled_anon_file_last_mib"] = split(st.server.pid)
        r["source_hits"] = src.hits
    finally:
        st.close()
        src.close()
    r["peak_above_idle_mib"] = round(r["peak_mib"] - r["idle_mib"], 1)
    r["peak_above_pre_mib"] = round(r["peak_mib"] - r["pre_build_mib"], 1)
    r["settled_above_idle_mib"] = round(r["settled_by_build"][-1] - r["idle_mib"], 1)
    # The absolute gate only means something with the real lists (synthetic names compile larger)
    # and the full cache: then it is checked; otherwise only what the build adds is.
    # The miss-heavy corpus repeats a few names: 100,000 misses leave 99,908 entries, so 99 % counts as full.
    real_gate = (args.names >= 1_000_000 and args.fill >= 100_000 and r["cache_entries"]
                 and r["cache_entries"] >= 0.99 * args.fill and not synthetic)
    r["gate_mib"] = args.gate if real_gate else None
    ok = r["settled_above_idle_mib"] <= 1.5 and (not real_gate or r["settled_by_build"][-1] <= args.gate)
    r["pass"] = ok
    print(f"{v4:,} + {v6:,} rows ({r['compressed_mib']} MiB compressed, {r['db_mib']} MiB .ttgeo, {r['build_s']} s):"
          f" idle {r['idle_mib']} MiB, after the reload {r['pre_build_mib']}, peak {r['peak_mib']}"
          f" (+{r['peak_above_pre_mib']} over that, +{r['peak_above_idle_mib']} over idle), after {r['after_mib']},"
          f" settled {r['settled_mib']} ({r['settled_above_idle_mib']:+}; anon, file: {r['idle_anon_file_mib']} ->"
          f" {r['settled_anon_file_mib']}); after each build {r['settled_by_build']} -> {'PASS' if ok else 'FAIL'}",
          flush=True)
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(r, indent=2) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
