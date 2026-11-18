#!/usr/bin/env bash
# REQ: CLU-005 (T24.26, ADR-990) — soaks a primary, an eligible replica and a witness under
# automatic failover and counts how often the primary's lease lapses. Throwaway: its own compose
# project (telltale-lapse) and volumes, nothing published on the host.
#
#   SOAK_S=1800 deploy/cluster3/lapse-soak.sh              # seconds to soak (default 600)
#   DISK_DEV=/dev/sdb WRITE_BPS=65536 deploy/cluster3/lapse-soak.sh   # throttle every node's disk writes
#   FSYNC_STALL_S=4 ...                                    # every 40 s, freeze one node's writes for N s
#                                                          # (docker pause of the node), as an SD card does
#
# Exit 0 with "lapses: 0" is a pass; the node logs are printed for any lapse, with the debug lines
# of the renewal rounds (round sent, answers with their `took_ms`, round ended with its grants).
set -euo pipefail
export MSYS_NO_PATHCONV=1
HERE=$(cd "$(dirname "$0")" && pwd)
HERE_W=$HERE
if command -v cygpath >/dev/null 2>&1; then HERE_W=$(cygpath -m "$HERE"); fi
C=(docker compose -p telltale-lapse -f "$HERE_W/compose-lapse.yaml")
SOAK_S=${SOAK_S:-600}
CFG=/etc/telltale/telltale.toml
TT=/usr/local/bin/telltale

if [ -n "${DISK_DEV:-}" ]; then
  # An override file that adds the throttle to every node.
  OV=$(mktemp)
  {
    echo "services:"
    for n in primary replica-a witness; do
      echo "  $n:"; echo "    blkio_config:"; echo "      device_write_bps:"
      echo "        - {path: $DISK_DEV, rate: '${WRITE_BPS:-65536}'}"
    done
  } > "$OV"
  OV_W=$OV; if command -v cygpath >/dev/null 2>&1; then OV_W=$(cygpath -m "$OV"); fi
  C+=(-f "$OV_W")
fi

cleanup() {
  local rc=$?; trap - EXIT; set +e
  "${C[@]}" unpause >/dev/null 2>&1
  "${C[@]}" down -v --remove-orphans >/dev/null 2>&1
  [ "${KEEP:-}" = 1 ] || docker image rm telltale:lapse-test >/dev/null 2>&1
  [ -n "${OV:-}" ] && rm -f "$OV"
  exit "$rc"
}
trap cleanup EXIT

echo "== bring-up"
# LAPSE_IMAGE: an image to soak as it is (for example the one built before a fix); else it is built.
BUILD=--build; [ -z "${LAPSE_IMAGE:-}" ] || BUILD=--no-build
"${C[@]}" up -d "$BUILD" --wait primary >/dev/null 2>&1 || { echo "FAIL: primary"; exit 1; }
tok() { "${C[@]}" exec -T primary $TT cluster token create --ttl 30m "$@" -c $CFG | tr -d '\r' | grep '^tt_join_'; }
"${C[@]}" run --rm -T --no-deps replica-a cluster join "$(tok --eligible)" --site replica-a --eligible \
  --advertise https://replica-a:8443 -c $CFG >/dev/null 2>&1 || { echo "FAIL: replica-a join"; exit 1; }
"${C[@]}" run --rm -T --no-deps witness cluster join "$(tok --witness)" --site witness --witness \
  --advertise https://witness:8443 -c $CFG >/dev/null 2>&1 || { echo "FAIL: witness join"; exit 1; }
"${C[@]}" up -d replica-a witness >/dev/null 2>&1
sleep 15
"${C[@]}" exec -T primary $TT cluster set-failover auto -c $CFG >/dev/null

echo "== soaking for ${SOAK_S}s"
end=$(( $(date +%s) + SOAK_S ))
while [ "$(date +%s)" -lt "$end" ]; do
  if [ -n "${FSYNC_STALL_S:-}" ]; then
    sleep 40
    # A node whose disk stalls answers nothing for the stall: pausing it is the same to its peers.
    n=$(printf '%s\n' primary replica-a witness | shuf -n1)
    "${C[@]}" pause "$n" >/dev/null 2>&1; sleep "$FSYNC_STALL_S"; "${C[@]}" unpause "$n" >/dev/null 2>&1
  else
    sleep 20
  fi
done

logs=$("${C[@]}" logs --no-color --no-log-prefix primary 2>&1 | tr -d '\r')
lapses=$(printf '%s\n' "$logs" | grep -c "lease lapsed" || true)
renewed=$(printf '%s\n' "$logs" | grep -c "lease is renewed again" || true)
slow=$("${C[@]}" logs --no-color 2>&1 | grep -c "ballot was slow" || true)
echo "lapses: $lapses  renewed again: $renewed  slow ballot stores (all nodes): $slow"
printf '%s
' "$logs" | grep -E "renewal round ended|vote answer" | tail -6 || true
if [ "$lapses" != 0 ]; then
  printf '%s\n' "$logs" | grep -E "lease lapsed|lease is renewed|lease renewal round ended|no vote answer" | tail -60
  exit 1
fi
