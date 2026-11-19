#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# REQ: DOC-002 — the screenshots of the README (docs/images/, Day and Night: the dashboard, the
# network map, a device in the CMDB, the query log and the cluster) and of the site
# (site/assets/shots/: dashboard, traffic, queries, why), all on one made-up network, so no real
# network ever appears in them. It starts two stub upstreams (stub.py), a stub UniFi gateway
# (unifi.py), a three-node cluster on loopback (pi-01 from demo.toml creates it; pi-02 and k8s-a
# join with a token), sends synthetic traffic (traffic.py) and runs shots.spec.ts. Nothing here is
# real: every device, name, MAC and address is invented, and the only key is a throwaway string.
#
# One command, from the repository root (it builds nothing itself):
#
#   (cd ui && npm ci && npm run build) && cargo build -p wrendns && ui/tests/demo/run.sh
#
#   ui/tests/demo/run.sh [seconds]     # 840 (the default) fills the 15-minute charts
#
# Needs python3, curl, the debug binary (or WRENDNS_BIN), and the UI's Playwright browsers
# (npx playwright install chromium). Everything listens on 127.0.0.1 and lives in /tmp/wrendns-demo.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
bin=${WRENDNS_BIN:-$repo/target/debug/wrendns}
secs=${1:-840}
demo=/tmp/wrendns-demo

rm -rf "$demo"
mkdir -p "$demo/data" "$demo/pi-02" "$demo/k8s-a" "$demo/secrets"
chmod 700 "$demo/secrets"
# The stub gateway's made-up API key (unifi.py checks it): a file, as a real key would be.
printf 'demo-key-not-a-secret' > "$demo/secrets/unifi-key"
chmod 600 "$demo/secrets/unifi-key"
pids=""
cleanup() { [ -n "$pids" ] && kill $pids 2>/dev/null || true; }
trap cleanup EXIT INT TERM

wait_ready() { # <metrics port> <log>
  i=0
  until curl -fs -m1 -o /dev/null "http://127.0.0.1:$1/readyz"; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then echo "a node didn't start; see $2" >&2; exit 1; fi
    sleep 0.5
  done
}

python3 "$here/stub.py" 25401 8 30 & pids="$pids $!"
python3 "$here/stub.py" 25402 12 45 & pids="$pids $!"
python3 "$here/unifi.py" 25480 & pids="$pids $!"
WRENDNS_BOOTSTRAP_ADMIN_USER=admin WRENDNS_BOOTSTRAP_ADMIN_PASSWORD='correct horse battery' \
  "$bin" run -c "$here/demo.toml" > "$demo/server.log" 2>&1 & pids="$pids $!"
wait_ready 29154 "$demo/server.log"

# REQ: CLU-001 — the two replicas join pi-01 with a token, then start.
token=$("$bin" cluster token create --ttl 30m --eligible -c "$here/demo.toml" | grep '^tt_join_')
for node in pi-02:28444:29155 k8s-a:28445:29156; do
  # The UI names a node by its site, so each node is its own site here.
  name=${node%%:*}; rest=${node#*:}; port=${rest%%:*}; metrics=${rest#*:}
  "$bin" cluster join "$token" --site "$name" --eligible --advertise "https://127.0.0.1:$port" \
    -c "$here/demo-$name.toml" > "$demo/join-$name.log" 2>&1 \
    || { cat "$demo/join-$name.log" >&2; exit 1; }
  "$bin" run -c "$here/demo-$name.toml" > "$demo/$name.log" 2>&1 & pids="$pids $!"
  wait_ready "$metrics" "$demo/$name.log"
done

# A replica takes over by itself if pi-01 goes (the Cluster page says "automatic").
"$bin" cluster set-failover auto -c "$here/demo.toml" > /dev/null

# The traffic goes on while the pictures are taken (so rates are not zero); it stops at exit.
echo "sending ${secs}s of traffic to the three nodes before the screenshots"
DEMO_SERVERS=25353:6,25354:3,25355:1 python3 "$here/traffic.py" "$((secs + 900))" > "$demo/traffic.log" 2>&1 & pids="$pids $!"
sleep "$secs"
mkdir -p "$repo/docs/images"
cd "$repo/ui"
npx playwright test -c tests/demo/playwright.config.ts
