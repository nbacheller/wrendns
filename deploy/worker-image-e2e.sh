#!/usr/bin/env bash
# REQ: API-007, DSC-002 (ADR-988, ADR-989) — the sandboxed workers in the real image: the static
# musl binary with mimalloc as its allocator, a read-only root filesystem and no /tmp.
#   1. the discovery worker starts and passes its handshake under its memory limit (it is
#      supervised by the node: GET /api/v1/discovery/status shows it up, with a 64 MiB data limit);
#   2. a gravity.db upload and a Teleporter zip are previewed through POST /api/v1/import/pihole
#      (the import worker runs hardened under its 1 GiB limit and unpacks into the data directory).
# Before ADR-988 every musl release build answered the import with "<path>: <path>", and the
# discovery worker's memory limit bounded nothing (it started fine; its limit was not enforced).
# Usage: deploy/worker-image-e2e.sh [image]   (default: wrendns:dev; build it with
#   docker buildx build --platform linux/amd64 --load -t wrendns:dev .)
set -euo pipefail
IMG=${1:-wrendns:dev}
E=$(mktemp -d)
# The same directory as a path the docker CLI understands (a Windows shell needs a drive path).
EH=$(cygpath -m "$E" 2>/dev/null || echo "$E")
C=tt-worker-e2e
cleanup() {
  local rc=$?
  docker rm -f "$C" >/dev/null 2>&1 || true
  docker volume rm -f "$C-data" >/dev/null 2>&1 || true
  rm -rf "$E"
  exit "$rc"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  docker logs --tail 30 "$C" 2>&1 || true
  exit 1
}
trap 'fail "line $LINENO: \`$BASH_COMMAND\` failed"' ERR
# A Windows shell would rewrite /var/lib/... in docker arguments.
docker() { MSYS_NO_PATHCONV=1 command docker "$@"; }
command -v docker >/dev/null || { echo "needs docker"; exit 2; }
command -v python3 >/dev/null || { echo "needs python3"; exit 2; }
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

# Fixtures: a gravity.db (Pi-hole's group tables) and a Teleporter zip around it.
python3 - "$E" <<'PYEOF'
import sqlite3, sys, zipfile
d = sys.argv[1]
c = sqlite3.connect(d + "/gravity.db")
c.executescript("""
create table "group"(id integer primary key, enabled integer, name text, date_added integer, date_modified integer, description text);
create table adlist(id integer primary key, address text, enabled integer, date_added integer, date_modified integer, comment text);
create table adlist_by_group(adlist_id integer, group_id integer);
create table domainlist(id integer primary key, type integer, domain text, enabled integer, date_added integer, date_modified integer, comment text);
create table domainlist_by_group(domainlist_id integer, group_id integer);
create table client(id integer primary key, ip text, date_added integer, date_modified integer, comment text);
create table client_by_group(client_id integer, group_id integer);
insert into "group" values (0, 1, 'Default', 0, 0, 'd'), (1, 1, 'Kids', 0, 0, 'k');
insert into adlist values (1, 'https://lists.example/kids.txt', 1, 0, 0, 'kids');
insert into adlist_by_group values (1, 1);
insert into domainlist values (1, 1, 'denied.example', 1, 0, 0, 'deny');
insert into domainlist_by_group values (1, 0);
insert into client values (1, '192.168.1.50', 0, 0, 'tablet');
insert into client_by_group values (1, 1);
""")
c.commit()
c.close()
with zipfile.ZipFile(d + "/teleporter.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.write(d + "/gravity.db", "gravity.db")
PYEOF

cat > "$E/wrendns.toml" <<'EOF'
[node]
name = "worker-e2e"
[[listen]]
proto = "udp"
addr = "0.0.0.0:5353"
[api]
listen = "0.0.0.0:8053"
[discovery]
enabled = true
[[discovery.subnet]]
cidr = "192.168.1.0/24"
EOF
chmod 644 "$E/wrendns.toml"

# The image as it ships: read-only root, its one writable volume, the default user, no /tmp.
docker volume create "$C-data" >/dev/null
# (The config is copied into the volume rather than bind-mounted, so the script also works against a remote
# or Docker Desktop daemon.)
docker create --name "$C" --read-only -v "$C-data:/var/lib/wrendns"   -p 127.0.0.1:18053:8053 "$IMG" run -c /var/lib/wrendns/node.toml >/dev/null
docker cp "$EH/wrendns.toml" "$C:/var/lib/wrendns/node.toml" >/dev/null
docker start "$C" >/dev/null
API=http://127.0.0.1:18053
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.2; done
curl -s -o /dev/null "$API/api/v1/auth/status" || fail "the node didn't start"

docker cp "$C:/var/lib/wrendns/setup-token" "$EH/setup-token" >/dev/null
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$(cat "$E/setup-token")\",\"username\":\"admin\",\"password\":\"worker-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]') || fail "first-run setup"

echo "== 1. the discovery worker is up under its limit"
for _ in $(seq 60); do
  up=$(curl -sf -b "$E/jar" "$API/api/v1/discovery/status" | field 'any(w["up"] for w in d["workers"])') || up=False
  [ "$up" = True ] && break
  sleep 0.5
done
curl -sf -b "$E/jar" "$API/api/v1/discovery/status" > "$E/status.json"
[ "$up" = True ] || { cat "$E/status.json"; fail "the discovery worker isn't up"; }
[ "$(field 'd["workers"][0]["dataLimitMib"]' < "$E/status.json")" = 64 ] || fail "the worker's data limit isn't 64 MiB"

echo "== 2. the import worker reads a gravity.db and a Teleporter zip"
for f in gravity.db teleporter.zip; do
  code=$(curl -s -o "$E/plan.json" -w '%{http_code}' -b "$E/jar" -H "x-csrf-token: $CSRF" \
    -H 'content-type: application/octet-stream' --data-binary "@$E/$f" "$API/api/v1/import/pihole")
  [ "$code" = 200 ] || { cat "$E/plan.json"; fail "$f: the preview answered $code"; }
  grep -q 'planId' "$E/plan.json" || fail "$f: no plan in the answer"
  grep -q 'Kids' "$E/plan.json" || fail "$f: the Kids group isn't in the plan"
  echo "ok $f"
done
echo PASS
