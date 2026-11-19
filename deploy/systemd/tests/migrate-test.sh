#!/bin/sh
# REQ: OPS-004 (ADR-1028, spec/10 T33.2) -- deploy/systemd/migrate-from-telltale.sh on a fake
# root: a dry run changes nothing; the real run moves the directories, renames the config, carries
# the unit and its drop-in over, links the old paths and the old command, and a second run changes
# nothing. No root, no systemd, no real user database: the commands it calls are logged stand-ins.
#
# Usage: sh deploy/systemd/tests/migrate-test.sh        (run by CI with the other shell tests)
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../migrate-from-telltale.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

R="$T/root"
BIN="$T/fakebin"
LOG="$T/calls.log"
mkdir -p "$BIN" "$R/etc/telltale" "$R/var/lib/telltale" "$R/etc/systemd/system/telltale.service.d" \
  "$R/etc/systemd/resolved.conf.d" "$R/etc/keepalived" "$R/usr/local/bin"
: > "$LOG"

# Stand-ins for the commands that need root or systemd; each logs its call.
for c in usermod groupmod; do
  printf '#!/bin/sh\necho "%s $*" >> "%s"\n' "$c" "$LOG" > "$BIN/$c"
done
printf '#!/bin/sh\necho "systemctl $*" >> "%s"\n[ "$1" = is-active ] && exit 0\nexit 0\n' "$LOG" > "$BIN/systemctl"
# the old user and group exist; the new ones don't
printf '#!/bin/sh\n[ "$2" = telltale ] && exit 0\nexit 2\n' > "$BIN/getent"
chmod +x "$BIN"/*

cat > "$R/etc/telltale/telltale.toml" <<'EOF'
[node]
data_dir = "/var/lib/telltale"
[api]
tls = { cert = "/etc/telltale/cert.pem", key = "/etc/telltale/key.pem" }
EOF
echo cert > "$R/etc/telltale/cert.pem"
echo data > "$R/var/lib/telltale/state.db"
cat > "$R/etc/systemd/system/telltale.service" <<'EOF'
[Unit]
Description=TelltaleDNS resolver
[Service]
User=telltale
Group=telltale
ExecStart=/usr/local/bin/telltale run -c /etc/telltale/telltale.toml
Environment=TELLTALE_LOG=debug
StateDirectory=telltale
# my own edit
LimitNOFILE=1234
EOF
printf '[Service]\nEnvironment=TELLTALE_BOOTSTRAP_ADMIN_USER=admin\n' > "$R/etc/systemd/system/telltale.service.d/10-first-admin.conf"
echo "nameserver 1.1.1.1" > "$R/etc/resolv.conf.telltale-backup"
echo "[Resolve]" > "$R/etc/systemd/resolved.conf.d/telltale.conf"
printf 'script "/etc/keepalived/check-telltale.sh"\n' > "$R/etc/keepalived/keepalived.conf"
printf '#!/bin/sh\necho old binary\n' > "$R/usr/local/bin/telltale"
printf '#!/bin/sh\necho new binary\n' > "$R/usr/local/bin/wrendns"
chmod +x "$R/usr/local/bin/telltale" "$R/usr/local/bin/wrendns"

run_migrate() { PATH="$BIN:$PATH" WRENDNS_MIGRATE_ROOT="$R" sh "$SCRIPT" "$@"; }
snapshot() { (cd "$R" && find . | sort && find . -type f -exec cksum {} \; | sort) > "$1"; }

# --- detect ---
run_migrate --detect || fail "an old install wasn't detected"
ok "detects the old install"

# --- dry run changes nothing ---
snapshot "$T/before"
run_migrate --dry-run > "$T/dry.out"
snapshot "$T/after-dry"
cmp -s "$T/before" "$T/after-dry" || fail "the dry run changed files"
grep -q "would: mv" "$T/dry.out" || fail "the dry run didn't say what it would do"
grep -q -E "systemctl (stop|enable)" "$LOG" && fail "the dry run called systemctl to change something"
ok "a dry run changes nothing and says what it would do"

# --- the real run ---
run_migrate > "$T/run.out"
[ -f "$R/etc/wrendns/wrendns.toml" ] || fail "no /etc/wrendns/wrendns.toml"
[ -f "$R/var/lib/wrendns/state.db" ] || fail "the data didn't move"
[ -L "$R/etc/telltale" ] && [ -L "$R/var/lib/telltale" ] || fail "the old directories aren't links"
[ -f "$R/etc/telltale/telltale.toml" ] || fail "the old config path doesn't resolve through the link"
[ -f "$R/etc/wrendns/cert.pem" ] || fail "other files in /etc/telltale didn't move"
grep -q '/var/lib/wrendns' "$R/etc/wrendns/wrendns.toml" || fail "data_dir wasn't rewritten"
grep -q '/etc/wrendns/cert.pem' "$R/etc/wrendns/wrendns.toml" || fail "the certificate path wasn't rewritten"
grep -q telltale "$R/etc/wrendns/wrendns.toml" && fail "an old name is left in the config"
[ -f "$R/etc/wrendns/wrendns.toml.pre-wrendns" ] || fail "the original config wasn't kept"
U="$R/etc/systemd/system/wrendns.service"
[ -f "$U" ] || fail "no wrendns.service"
grep -q '^ExecStart=/usr/local/bin/wrendns run -c /etc/wrendns/wrendns.toml' "$U" || fail "ExecStart: $(grep ExecStart "$U")"
grep -q '^User=wrendns' "$U" && grep -q '^StateDirectory=wrendns' "$U" || fail "user or state directory"
grep -q '^Environment=WRENDNS_LOG=debug' "$U" || fail "the environment wasn't renamed"
grep -q '^LimitNOFILE=1234' "$U" || fail "a local edit to the unit was lost"
grep -q 'WRENDNS_BOOTSTRAP_ADMIN_USER=admin' "$R/etc/systemd/system/wrendns.service.d/10-first-admin.conf" \
  || fail "the drop-in wasn't carried over"
[ ! -e "$R/etc/systemd/system/telltale.service" ] || fail "the old unit is still installed"
[ -f "$R/etc/wrendns/pre-wrendns/telltale.service" ] || fail "no copy of the old unit"
[ -L "$R/usr/local/bin/telltale" ] || fail "telltale isn't a link to wrendns"
[ "$(readlink "$R/usr/local/bin/telltale")" = wrendns ] || fail "the telltale link points elsewhere"
grep -q "old binary" "$R/usr/local/bin/telltale.pre-wrendns" || fail "the old binary wasn't kept"
[ -f "$R/etc/systemd/resolved.conf.d/wrendns.conf" ] && [ -f "$R/etc/resolv.conf.wrendns-backup" ] \
  || fail "the resolver files weren't renamed"
grep -q "check-telltale.sh" "$T/run.out" || grep -q "keepalived.conf" "$T/run.out" || fail "keepalived wasn't mentioned"
grep -q "usermod -l wrendns" "$LOG" && grep -q "groupmod -n wrendns telltale" "$LOG" || fail "user/group rename not called"
grep -q "systemctl stop telltale" "$LOG" && grep -q "systemctl start wrendns" "$LOG" || fail "the service wasn't stopped and started"
grep -q "systemctl disable telltale" "$LOG" && grep -q "systemctl enable wrendns" "$LOG" || fail "the units weren't switched"
ok "the real run migrates paths, config, unit, drop-in, user, command and links"

# --- idempotent ---
if run_migrate --detect; then fail "still detects an old install after migrating"; fi
snapshot "$T/before2"
: > "$LOG"
run_migrate > "$T/run2.out"
snapshot "$T/after2"
cmp -s "$T/before2" "$T/after2" || fail "the second run changed files"
[ ! -s "$LOG" ] || fail "the second run called commands: $(cat "$LOG")"
ok "a second run changes nothing"

# --- refuses to overwrite ---
R2="$T/root2"
mkdir -p "$R2/etc/telltale" "$R2/etc/wrendns" "$R2/usr/local/bin"
echo a > "$R2/etc/telltale/telltale.toml"; echo b > "$R2/etc/wrendns/other"
if PATH="$BIN:$PATH" WRENDNS_MIGRATE_ROOT="$R2" sh "$SCRIPT" > "$T/refuse.out" 2>&1; then fail "it overwrote a full /etc/wrendns"; fi
grep -q "both" "$T/refuse.out" || fail "no explanation for the refusal"
[ -f "$R2/etc/telltale/telltale.toml" ] || fail "the refused run moved files"
ok "a full /etc/wrendns is never overwritten"
