"""REQ: NFR-001, OBS-901 (T26.2) -- an A/B of the cache-hit path between two binaries, for a host
where `bench.py run smoke` can't warm its 10,000-name cache (a UDP bind() of 10 ms makes the
warm-up miss at ~98 a second, so every number it prints is the host's).

  python3 bench/ab_hot.py --base /path/to/old/wrendns --new /path/to/new/wrendns [--rounds 7]

The corpus is only a few hundred names, so one warm-up pass fills the cache in seconds and the
run measures what `cache-hot` is for: cache hits through the workers and the event rings, with the
aggregator thread draining behind them. Each round starts a fresh server for each binary, in
alternating order, warms it, and takes a saturating run and a run at half of its rate. The
report is the median of each, and the spread, so a difference inside the noise reads as one.
"""

import argparse
import pathlib
import statistics
import sys
import tempfile
import time

import bench
import gate


def corpus(path, n):
    path.write_text("".join(f"hot{i}.bench.test A\n" for i in range(n)))
    return path


def one(binary, args, tmp, data):
    d = pathlib.Path(tempfile.mkdtemp(dir=tmp))
    a = argparse.Namespace(bin=binary, workers=args.workers, server_cpus=args.server_cpus,
                           threads=args.threads, clients=args.clients, outstanding=args.outstanding,
                           duration=args.duration)
    st = gate.Stack(a, d)
    try:
        st.start()
        time.sleep(2)
        gate.perf(data, args.warm, a, max_qps=100)  # the cache fills at the host's miss rate
        time.sleep(1)
        gate.perf(data, 3, a)
        full = gate.perf(data, args.duration, a)
        half = gate.perf(data, args.duration, a, max_qps=int(full["qps"] / 2))
        return full["qps"], half["latency_us"]["p99"], full["loss_pct"]
    finally:
        st.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True)
    ap.add_argument("--new", required=True)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--names", type=int, default=300)
    ap.add_argument("--warm", type=int, default=6, help="seconds of warm-up at 100 a second")
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--server-cpus", default="0-3")
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--outstanding", type=int, default=200)
    ap.add_argument("--port", type=int, default=6500, help="DNS port; the stub is +1, metrics +2")
    args = ap.parse_args()
    bench.DNS_PORT, bench.STUB_PORT, bench.METRICS_PORT = args.port, args.port + 1, args.port + 2
    gate.URL = f"http://127.0.0.1:{bench.METRICS_PORT}"
    gate.TARGET = ("127.0.0.1", bench.DNS_PORT)

    tmp = tempfile.mkdtemp(prefix="wrendns-ab-")
    data = corpus(pathlib.Path(tmp) / "hot.corpus", args.names)
    res = {"base": [], "new": []}
    for r in range(args.rounds):
        order = ["base", "new"] if r % 2 == 0 else ["new", "base"]
        for which in order:
            q, p99, loss = one(getattr(args, which), args, tmp, data)
            res[which].append((q, p99, loss))
            print(f"round {r + 1} {which}: {q:,.0f} qps (loss {loss}%), p99 at 50%: {p99} us", flush=True)
    for which, rows in res.items():
        qs, ps = [x[0] for x in rows], [x[1] for x in rows]
        print(f"{which}: median {statistics.median(qs):,.0f} qps (min {min(qs):,.0f}, max {max(qs):,.0f}), "
              f"median p99 at 50% {statistics.median(ps):,.0f} us")
    b, n = (statistics.median([x[0] for x in res[k]]) for k in ("base", "new"))
    print(f"new/base qps: {n / b:.3f}")


if __name__ == "__main__":
    sys.exit(main())
