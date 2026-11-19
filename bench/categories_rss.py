"""REQ: FLT-901 (T24.29, ADR-994 item 5) -- the memory a category selection costs, for the catalog's
`[measured]` table (`presets/categories/catalog.toml`) and design section 2.4.

  python3 bench/categories_rss.py --bin /target/categories-e2e/bench-fast/telltale \
      --content '{ level = "basic" }' --mem 128 --cpus 4

Runs one node in a Docker container limited to `--mem` MiB (and `--cpus`), with the category lists
served from a local HTTP server that fetches each real file once from the internet and caches it
(`--cache`), so the byte counts are the real ones. The node must be built with the cargo feature
`e2e` (`cargo build --profile bench-fast -p telltale --features e2e`): only that build can point the
catalog's two hosts at `TELLTALE_E2E_CATALOG_BASE`. The binary is read from the `--volumes-from`
container (`wrendns-dev`, where it was built), so no copy is needed.

Prints one JSON line: the source bytes the node downloaded, VmHWM (the peak resident set, which
includes the compile) and VmRSS (steady, after the lookup index is ready) in MiB, the compile seconds
from the log, whether the kernel killed the container (OOM), and the peak above the idle node
(`peak_above_idle_mib`, VmHWM minus the idle node's VmRSS measured with `--content '{}'` first).
Run it again with the same `--cache` and the real lists are not downloaded twice.
"""

import argparse
import http.server
import json
import pathlib
import re
import subprocess
import threading
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOSTS = ("https://raw.githubusercontent.com/", "https://cdn.jsdelivr.net/gh/")


def catalog_urls():
    """Every source URL in the catalog, keyed by what follows the host (the path the fake serves)."""
    out = {}
    for f in sorted((ROOT / "presets" / "categories").glob("*.toml")):
        for m in re.finditer(r'^\s*(?:url|meta_url)\s*=\s*"([^"]+)"', f.read_text(encoding="utf-8"), re.M):
            for h in HOSTS:
                if m.group(1).startswith(h):
                    out[m.group(1)[len(h):]] = m.group(1)
    return out


class Source(http.server.BaseHTTPRequestHandler):
    urls = {}
    cache = pathlib.Path(".")
    served = {}

    def do_GET(self):
        rest = self.path.lstrip("/")
        url = self.urls.get(rest)
        if url is None:
            self.send_error(404)
            return
        f = self.cache / re.sub(r"[^A-Za-z0-9._-]", "_", rest)
        if not f.exists():
            with urllib.request.urlopen(url, timeout=120) as r:
                f.write_bytes(r.read())
        body = f.read_bytes()
        Source.served[rest] = len(body)
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def sh(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check).stdout


def logs(name):
    r = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
    return r.stdout + r.stderr


def status(name):
    t = sh("docker", "exec", name, "cat", "/proc/1/status", check=False)
    kib = lambda k: int(m.group(1)) / 1024 if (m := re.search(rf"^{k}:\s+(\d+) kB", t, re.M)) else None
    return kib("VmHWM"), kib("VmRSS")


def run(a, content):
    name = f"tt-rss-{int(time.time())}"
    cfg = f"""[node]
data_dir = "/tmp/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:5300"
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["nowhere"]
[[group]]
name = "default"
content = {content}
"""
    sh("docker", "run", "-d", "--name", name, "--memory", f"{a.mem}m", "--memory-swap", f"{a.mem}m",
       "--cpus", str(a.cpus), "--volumes-from", a.volumes_from,
       "-e", f"TELLTALE_E2E_CATALOG_BASE=http://host.docker.internal:{a.port}/",
       "ubuntu:24.04", "bash", "-c",
       f"cat > /tmp/t.toml <<'EOF'\n{cfg}EOF\nexec {a.bin} run -c /tmp/t.toml")
    try:
        t0 = time.time()
        ready = None
        while time.time() - t0 < a.timeout:
            log = logs(name)
            state = json.loads(sh("docker", "inspect", name, "--format", "{{json .State}}"))
            if state["OOMKilled"] or not state["Running"]:
                return {"oom_killed": state["OOMKilled"], "exited": not state["Running"], "log_tail": log[-600:]}
            if "filter lookup index ready" in log or "filter snapshot active" in log or (content.strip() == "{}" and "serving the API" in log):
                ready = log
                break
            time.sleep(0.5)
        time.sleep(8)  # let start-up settle: the idle figure is the steady one
        hwm, rss = status(name)
        seconds = re.findall(r"filter snapshot compiled.*?seconds=([0-9.]+)", ready or "")
        return {"vmhwm_mib": hwm, "vmrss_mib": rss, "compile_seconds": seconds[:1], "oom_killed": False}
    finally:
        sh("docker", "rm", "-f", name, check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="the e2e-feature telltale binary, as seen in --volumes-from")
    ap.add_argument("--content", default='{ level = "basic" }', help="the default group's `content` (TOML)")
    ap.add_argument("--mem", type=int, default=1024, help="container memory limit, MiB")
    ap.add_argument("--cpus", type=float, default=4)
    ap.add_argument("--volumes-from", default="wrendns-dev")
    ap.add_argument("--cache", default=str(pathlib.Path.home() / ".cache" / "telltale-categories-rss"))
    ap.add_argument("--port", type=int, default=18947)
    ap.add_argument("--timeout", type=int, default=240)
    a = ap.parse_args()
    cache = pathlib.Path(a.cache)
    cache.mkdir(parents=True, exist_ok=True)
    Source.urls, Source.cache = catalog_urls(), cache
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", a.port), Source)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    idle = run(a, "{}")
    r = run(a, a.content)
    r["source_bytes"] = sum(Source.served.values())
    r["mem_mib"], r["cpus"], r["content"] = a.mem, a.cpus, a.content
    if idle.get("vmrss_mib") is not None and r.get("vmhwm_mib") is not None:
        r["idle_vmrss_mib"] = idle["vmrss_mib"]
        r["peak_above_idle_mib"] = round(r["vmhwm_mib"] - idle["vmrss_mib"], 1)
    print(json.dumps(r))


if __name__ == "__main__":
    main()
