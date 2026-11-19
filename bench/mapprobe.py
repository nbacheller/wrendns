"""REQ: OBS-901 (T26.2, ADR-958 section 2) -- what the live map's sampler costs in resident memory.

  python3 bench/mapprobe.py --map off     # baseline: [map] enabled = false
  python3 bench/mapprobe.py --map on      # the sampler on, at its worst case (event_rate = 2000)

Starts the stub upstream and a server the way `gate.py` does, on the Pi profile (2 workers), waits
for it to settle, then floods it with lookups from distinct source addresses (127.x.y.z, which
Linux delivers to 127.0.0.1) so the sampler's window fills to its key cap: at `event_rate = 2000`
it keeps up to 500 lookups per 250 ms, far more than the 1,024 keys a 5 s slot holds, so a flood
of 3,000 lookups a second from 14,000 distinct devices hits the cap in every slot. It then reports RSS at idle, right
after the flood, and after a steady period (the ADR asks for 5 minutes). Run it once with
`--map off` and once with `--map on` and take the difference: the gate is a delta of at most
1.5 MiB at the cap. Both runs get the same flood, so what the analytics keep per device cancels.
"""

import argparse
import pathlib
import socket
import struct
import sys
import tempfile
import time

import bench
import gate

URL = gate.URL


def query(name, qid):
    wire = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + wire + struct.pack(">HH", 1, 1)


def pool(n):
    """`n` sockets, each bound to an address of its own (a bind takes ~10 ms on Docker Desktop, so
    they are made once, by a few threads)."""
    import concurrent.futures
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, n + 256), hard))

    def one(i):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((f"127.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255 or 1}", 0))
        return s

    with concurrent.futures.ThreadPoolExecutor(16) as ex:
        return list(ex.map(one, range(1, n + 1)))


def flood(socks, seconds, rate, port):
    """`rate` lookups a second, rotating through the sockets (each a different device)."""
    sent, t0 = 0, time.monotonic()
    pkt = query("example.com", 0x1234)
    while time.monotonic() - t0 < seconds:
        due = int((time.monotonic() - t0) * rate)
        while sent < due and time.monotonic() - t0 < seconds:
            try:
                socks[sent % len(socks)].sendto(pkt, ("127.0.0.1", port))
            except OSError:
                pass
            sent += 1
        time.sleep(0.005)
    return sent


def rss_mib(pid):
    s = bench.proc_stats(pid) or {}
    return round((s.get("rss_kib") or 0) / 1024, 2), round((s.get("hwm_kib") or 0) / 1024, 2)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=str(bench.ROOT / "target/bench-fast/telltale"))
    ap.add_argument("--map", choices=["on", "off"], required=True)
    ap.add_argument("--workers", type=int, default=2, help="the Pi profile: 2 workers")
    ap.add_argument("--server-cpus", default="0-3")
    ap.add_argument("--rate", type=int, default=3000, help="lookups a second")
    ap.add_argument("--devices", type=int, default=14000, help="distinct source addresses (the cap needs > 12,288)")
    ap.add_argument("--flood", type=int, default=90, help="seconds of flood (the window is 60 s)")
    ap.add_argument("--steady", type=int, default=300, help="seconds to sit after the flood")
    ap.add_argument("--settle", type=int, default=30)
    ap.add_argument("--port", type=int, default=6300, help="DNS port; the upstream stub is +1, metrics +2")
    args = ap.parse_args()
    args.threads = args.clients = args.outstanding = args.duration = 1
    # Other work may share the host: private ports, so a server of someone else's isn't ours.
    global URL
    bench.DNS_PORT, bench.STUB_PORT, bench.METRICS_PORT = args.port, args.port + 1, args.port + 2
    URL = f"http://127.0.0.1:{bench.METRICS_PORT}"
    gate.URL = URL

    tmp = tempfile.TemporaryDirectory(prefix="telltale-map-")
    d = pathlib.Path(tmp.name)
    st = gate.Stack(args, d)
    extra = "[map]\nenabled = true\nevent_rate = 2000\n" if args.map == "on" else "[map]\nenabled = false\n"
    st.cfg.write_text(st.cfg.read_text() + "\n" + extra)
    try:
        st.start()
        time.sleep(args.settle)
        idle = rss_mib(st.server.pid)
        print(f"map {args.map}: idle {idle[0]} MiB (peak {idle[1]})", flush=True)
        socks = pool(args.devices)
        print(f"map {args.map}: {len(socks):,} devices ready", flush=True)
        n = flood(socks, args.flood, args.rate, bench.DNS_PORT)
        time.sleep(2)
        after = rss_mib(st.server.pid)
        dropped = bench.metric_sum(f"{URL}/metrics", "telltale_telemetry_dropped_total")
        print(f"map {args.map}: after {n:,} lookups from distinct devices: {after[0]} MiB (peak {after[1]}); "
              f"events dropped: {dropped}", flush=True)
        t0 = time.monotonic()
        while time.monotonic() - t0 < args.steady:
            time.sleep(min(60, args.steady))
            now = rss_mib(st.server.pid)
            print(f"map {args.map}: {int(time.monotonic() - t0)} s after the flood: {now[0]} MiB (peak {now[1]})",
                  flush=True)
    finally:
        st.close()


if __name__ == "__main__":
    sys.exit(main())
