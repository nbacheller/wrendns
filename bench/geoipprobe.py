"""REQ: OBS-902, NFR-001 (T26.4, ADR-959 section 5) -- what a loaded GeoIP database costs in resident memory.

  # 1. A production-sized database (about 600,000 rows, 3 to 5 MiB), written by an ignored test that
  #    also does 2,000,000 lookups and prints the resident set before and after:
  GEOIP_PROBE_OUT=/tmp/geoip-db cargo test -p telltale obs_902_geoip_probe_database -- --ignored --nocapture
  # 2. The node, with and without it (the Pi profile: 2 workers):
  python3 bench/geoipprobe.py --geoip off
  python3 bench/geoipprobe.py --geoip on --db /tmp/geoip-db

Starts the stub upstream and a server the way `mapprobe.py` does. With `--geoip on` the database is
put in `<data_dir>/geoip/` first and `[map.geoip] enabled = true` is set (the file's month is the
current one, so nothing is fetched: the source is a closed local port as a second guard), so the
node opens it at its first look at the settings: that reads the whole file once, 8 KiB at a time,
to verify its checksum, and keeps only the handle. It then floods the node with lookups and reports
RSS at idle, after the flood and after a steady period. Run it once for each and take the
difference: the database is read by position through the page cache and never held, so the
difference is the code and a file handle, well under the 1.5 MiB the map's own gate allows.
"""

import argparse
import pathlib
import shutil
import sys
import tempfile
import time

import bench
import gate
import mapprobe

URL = gate.URL


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=str(bench.ROOT / "target/bench-fast/telltale"))
    ap.add_argument("--geoip", choices=["on", "off"], required=True)
    ap.add_argument("--db", default="/tmp/geoip-db", help="the directory the ignored test wrote country.ttgeo to")
    ap.add_argument("--workers", type=int, default=2, help="the Pi profile: 2 workers")
    ap.add_argument("--server-cpus", default="0-3")
    ap.add_argument("--rate", type=int, default=3000, help="lookups a second")
    ap.add_argument("--devices", type=int, default=2000, help="distinct source addresses")
    ap.add_argument("--flood", type=int, default=60, help="seconds of flood")
    ap.add_argument("--steady", type=int, default=60, help="seconds to sit after the flood")
    ap.add_argument("--settle", type=int, default=30)
    ap.add_argument("--port", type=int, default=6400, help="DNS port; the upstream stub is +1, metrics +2")
    args = ap.parse_args()
    args.threads = args.clients = args.outstanding = args.duration = 1
    global URL
    bench.DNS_PORT, bench.STUB_PORT, bench.METRICS_PORT = args.port, args.port + 1, args.port + 2
    URL = f"http://127.0.0.1:{bench.METRICS_PORT}"
    gate.URL = URL

    tmp = tempfile.TemporaryDirectory(prefix="telltale-geoip-")
    d = pathlib.Path(tmp.name)
    st = gate.Stack(args, d)
    extra = "[map]\nenabled = true\n"
    if args.geoip == "on":
        src = pathlib.Path(args.db) / "country.ttgeo"
        if not src.exists():
            sys.exit(f"{src} is missing: run the ignored test first (see the top of this file)")
        (d / "geoip").mkdir()
        shutil.copy(src, d / "geoip" / "country.ttgeo")
        extra += f'[map.geoip]\nenabled = true\nsource_url = "https://127.0.0.1:{args.port + 9}/never.csv.gz"\n'
    st.cfg.write_text(st.cfg.read_text() + "\n" + extra)
    try:
        st.start()
        time.sleep(args.settle)
        idle = mapprobe.rss_mib(st.server.pid)
        size = (d / "geoip" / "country.ttgeo").stat().st_size / 1048576 if args.geoip == "on" else 0
        print(f"geoip {args.geoip}: idle {idle[0]} MiB (peak {idle[1]}); database {size:.2f} MiB on disk", flush=True)
        socks = mapprobe.pool(args.devices)
        n = mapprobe.flood(socks, args.flood, args.rate, bench.DNS_PORT)
        time.sleep(2)
        after = mapprobe.rss_mib(st.server.pid)
        print(f"geoip {args.geoip}: after {n:,} lookups: {after[0]} MiB (peak {after[1]})", flush=True)
        t0 = time.monotonic()
        while time.monotonic() - t0 < args.steady:
            time.sleep(min(30, args.steady))
            now = mapprobe.rss_mib(st.server.pid)
            print(f"geoip {args.geoip}: {int(time.monotonic() - t0)} s after the flood: {now[0]} MiB (peak {now[1]})", flush=True)
        log = (d / "server.log").read_text(errors="replace")
        if args.geoip == "on":
            ok = "geoip:" not in log or "up to date" in log
            print(f"geoip on: the node's log mentions geoip only for a good reason: {ok}", flush=True)
    finally:
        st.close()


if __name__ == "__main__":
    sys.exit(main())
