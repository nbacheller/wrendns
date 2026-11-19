#!/usr/bin/env python3
"""Deterministic query-corpus generator for dnsperf (spec/09 §2).

Each corpus is defined by a name and a seed below, so the same command always produces
byte-identical files; the runner records each file's SHA-256 in the results JSON.

  cache-hot   10k names, Zipf s=1.0, after warmup (cache-hit path)
  miss-heavy  unique random subdomains (every query misses the cache)
  blocked     names drawn 100% from the blocklists in bench/lists/ (needs --lists)
  device-names  Zipf over dev-{i}.home.arpa A plus their PTRs (DNS-023); the device count
              is shared with `bench.py run --devices N` (default 1000)

realistic-home (24 h replay mix) needs blocking and the query-log distributions, so it
lands with the filter tasks (T2.x).
"""

import argparse
import bisect
import hashlib
import itertools
import pathlib
import random
import re
import sys

# REQ: NFR-001 — corpora are reproducible from these seeds.
CORPORA = {
    "cache-hot": {"seed": 0x7E11, "names": 10_000, "zipf_s": 1.0, "queries": 200_000},
    "miss-heavy": {"seed": 0x7E12, "queries": 500_000},
    "blocked": {"seed": 0x7E13, "queries": 200_000},
    # ~65% repeated popular names (cache hits), ~20% blocklisted, ~15% unique misses (09 §2).
    "realistic-home": {"seed": 0x7E14, "popular": 5_000, "trackers": 2_000, "queries": 300_000,
                       "mix": (0.65, 0.20)},
    # REQ: DNS-023 (T22.1) — the device-name table: names of the devices `bench.py run
    # --devices N` configures (Zipf s=1.0 over dev-0..dev-N-1), 90% A and 10% their PTRs.
    "device-names": {"seed": 0x7E15, "devices": 1_000, "zipf_s": 1.0, "queries": 200_000, "ptr_share": 0.10},
}

# REQ: DNS-023 — the devices `bench.py run --devices N` names, and the corpus asks for.
DEVICE_DOMAIN = "home.arpa"
# 250 addresses per /24 under 10.77.0.0/16 (.1 to .250), so at most 256 × 250.
MAX_DEVICES = 256 * 250


def device_name(i):
    return f"dev-{i}"


def device_ip(i):
    return f"10.77.{i // 250}.{i % 250 + 1}"


def device_ptr(i):
    return f"{i % 250 + 1}.{i // 250}.77.10.in-addr.arpa"

TLDS = [("com", 60), ("net", 12), ("org", 8), ("io", 5), ("de", 5), ("co.uk", 4), ("app", 3), ("tv", 3)]
ALPHABET = "abcdefghijklmnopqrstuvwxyz"
# Rough label-length distribution of popular registrable domains (5–12 chars dominate).
LABEL_LEN = [(3, 3), (4, 6), (5, 10), (6, 12), (7, 13), (8, 12), (9, 10), (10, 9), (11, 7), (12, 6), (14, 6), (18, 6)]
SUBDOMAINS = [("", 45), ("www", 20), ("api", 6), ("cdn", 6), ("static", 4), ("img", 4), ("m", 3), ("mail", 3), ("app", 3), ("edge", 3), ("telemetry", 3)]


def weighted(rng, table):
    return rng.choices([v for v, _ in table], weights=[w for _, w in table])[0]


def label(rng):
    return "".join(rng.choice(ALPHABET) for _ in range(weighted(rng, LABEL_LEN)))


def domain(rng):
    sub = weighted(rng, SUBDOMAINS)
    name = f"{label(rng)}.{weighted(rng, TLDS)}"
    return f"{sub}.{name}" if sub else name


def qtype(rng):
    # Home traffic is mostly A/AAAA with a few HTTPS lookups from modern browsers.
    return rng.choices(["A", "AAAA", "HTTPS"], weights=[62, 30, 8])[0]


def cache_hot(spec):
    rng = random.Random(spec["seed"])
    names = list(dict.fromkeys(domain(rng) for _ in range(spec["names"] * 2)))[: spec["names"]]
    types = [qtype(rng) for _ in names]
    # Zipf over ranks: P(k) ∝ 1/k^s.
    cdf = list(itertools.accumulate(1.0 / (k ** spec["zipf_s"]) for k in range(1, len(names) + 1)))
    total = cdf[-1]
    for _ in range(spec["queries"]):
        i = bisect.bisect_left(cdf, rng.random() * total)
        yield f"{names[i]} {types[i]}"


def miss_heavy(spec):
    rng = random.Random(spec["seed"])
    parents = [domain(rng) for _ in range(1000)]
    for n in range(spec["queries"]):
        # The counter keeps every name unique across the whole file.
        yield f"m{n:x}{label(rng)}.{rng.choice(parents)} A"


# A blocking rule's domain: hosts lines (`0.0.0.0 name`), plain names, `*.name`, and AdBlock
# `||name^` / `|name^`. Exceptions (`@@`), regexes, modifiers, and cosmetic rules are skipped:
# the corpus must contain only names the lists actually block.
DOMAIN_RE = re.compile(r"^(?:\|\|?|\*\.)?([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)\^?$")


def blocked_names(lists):
    files = sorted(lists.glob("*.txt")) if lists else []
    names = []
    for f in files:
        for line in f.read_text(errors="replace").splitlines():
            line = line.strip().lower()
            if not line or line.startswith(("#", "!", "@@", "[")):
                continue
            token = line.split()[-1] if " " in line or "\t" in line else line
            m = DOMAIN_RE.match(token)
            if m and not m.group(1).replace(".", "").isdigit():
                names.append(m.group(1))
    return names


def blocked(spec, lists):
    names = blocked_names(lists)
    if not names:
        sys.exit(f"blocked corpus needs domain lists (*.txt) in {lists}")
    rng = random.Random(spec["seed"])
    for _ in range(spec["queries"]):
        yield f"{rng.choice(names)} A"


def zipf_picker(rng, items, s=1.0):
    cdf = list(itertools.accumulate(1.0 / (k ** s) for k in range(1, len(items) + 1)))
    total = cdf[-1]
    return lambda: items[bisect.bisect_left(cdf, rng.random() * total)]


def realistic_home(spec, lists):
    rng = random.Random(spec["seed"])
    trackers_pool = blocked_names(lists)
    if not trackers_pool:
        sys.exit(f"realistic-home needs domain lists (*.txt) in {lists}")
    popular = list(dict.fromkeys(domain(rng) for _ in range(spec["popular"] * 2)))[: spec["popular"]]
    popular = [(n, qtype(rng)) for n in popular]
    trackers = rng.sample(trackers_pool, min(spec["trackers"], len(trackers_pool)))
    pick_popular = zipf_picker(rng, popular)
    pick_tracker = zipf_picker(rng, trackers)
    p_popular, p_blocked = spec["mix"]
    for n in range(spec["queries"]):
        r = rng.random()
        if r < p_popular:
            name, t = pick_popular()
            yield f"{name} {t}"
        elif r < p_popular + p_blocked:
            yield f"{pick_tracker()} {rng.choice(['A', 'A', 'AAAA'])}"
        else:
            yield f"u{n:x}.{label(rng)}.{weighted(rng, TLDS)} A"


def device_names(spec, devices):
    """REQ: DNS-023 — Zipf over the device names (rank k is dev-(k-1)), some asked by address."""
    n = devices or spec["devices"]
    if not 1 <= n <= MAX_DEVICES:
        sys.exit(f"device-names: --devices must be 1 to {MAX_DEVICES}")
    rng = random.Random(spec["seed"])
    pick = zipf_picker(rng, range(n), spec["zipf_s"])
    for _ in range(spec["queries"]):
        i = pick()
        if rng.random() < spec["ptr_share"]:
            yield f"{device_ptr(i)} PTR"
        else:
            yield f"{device_name(i)}.{DEVICE_DOMAIN} A"


def generate(name, out_dir, lists=None, devices=0):
    """Writes the corpus to `out_dir/<name>.txt`; `devices` sizes `device-names` (0: its default)."""
    spec = CORPORA[name]
    gens = {
        "cache-hot": lambda: cache_hot(spec),
        "miss-heavy": lambda: miss_heavy(spec),
        "blocked": lambda: blocked(spec, lists),
        "realistic-home": lambda: realistic_home(spec, lists),
        "device-names": lambda: device_names(spec, devices),
    }
    gen = gens[name]()
    path = out_dir / f"{name}.txt"
    out_dir.mkdir(parents=True, exist_ok=True)
    data = ("\n".join(gen) + "\n").encode()
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("corpora", nargs="*", default=["cache-hot", "miss-heavy"], choices=sorted(CORPORA))
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path(__file__).parent / "corpora")
    ap.add_argument("--lists", type=pathlib.Path, default=pathlib.Path(__file__).parent / "lists")
    ap.add_argument("--devices", type=int, default=0,
                    help=f"device-names: how many devices (default {CORPORA['device-names']['devices']})")
    args = ap.parse_args()
    for name in args.corpora:
        path, digest = generate(name, args.out, args.lists, args.devices)
        print(f"{name}: {path} sha256={digest}")


if __name__ == "__main__":
    main()
