#!/usr/bin/env bash
# REQ: DSC-003 (T25.4, ADR-908) — the SNMP client against net-snmp `snmpd` in a container on an
# RFC 1918 Docker network of its own (172.30.251.0/24): v2c GET and a bounded walk, and v3 SHA
# with and without AES. Credentials are random, written to files, and never printed. Nothing
# here touches a real device.
set -euo pipefail
cd "$(dirname "$0")/.."

NET=tt-snmp-ci-net
NAME=tt-snmp-ci-agent
IP=172.30.251.10
WORK=$(mktemp -d)
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

rand() { head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20; }
printf '%s' "$(rand)" >"$WORK/community"
printf '%s' "$(rand)" >"$WORK/auth"
printf '%s' "$(rand)" >"$WORK/priv"
mkdir -p "$WORK/etc" "$WORK/var"
cat >"$WORK/etc/snmpd.conf" <<CONF
rocommunity $(cat "$WORK/community") 172.30.251.0/24
rouser ttauth authPriv
rouser ttnopriv authNoPriv
sysname tt-snmp-ci
syslocation ci
syscontact none
CONF
# net-snmp turns createUser lines into localized keys on its first start.
cat >"$WORK/var/snmpd.conf" <<CONF
createUser ttauth SHA "$(cat "$WORK/auth")" AES "$(cat "$WORK/priv")"
createUser ttnopriv SHA "$(cat "$WORK/auth")"
CONF
chmod 0755 "$WORK" "$WORK/etc" "$WORK/var"
chmod 0644 "$WORK/etc/snmpd.conf" "$WORK/var/snmpd.conf"

docker build -q -t tt-snmpd-ci deploy/snmpd-test >/dev/null
docker network create --subnet 172.30.251.0/24 "$NET" >/dev/null
docker run -d --name "$NAME" --network "$NET" --ip "$IP" \
  -v "$WORK/etc/snmpd.conf:/etc/snmp/snmpd.conf:ro" \
  -v "$WORK/var:/var/lib/net-snmp" tt-snmpd-ci >/dev/null

# Wait for the agent to be up (a bare UDP port gives no ready signal).
sleep 3
if [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != "true" ]; then
  docker logs "$NAME" >&2
  echo "snmp-e2e: the agent did not start" >&2
  exit 1
fi

export TT_SNMPD_ADDR="$IP:161"
export TT_SNMPD_SYSNAME=tt-snmp-ci
export TT_SNMPD_COMMUNITY_FILE="$WORK/community"
export TT_SNMPD_USER=ttauth
export TT_SNMPD_AUTH=SHA
export TT_SNMPD_AUTH_FILE="$WORK/auth"
export TT_SNMPD_PRIV_FILE="$WORK/priv"
cargo test -p wrendns-snmp --test snmpd_interop dsc_003_net_snmp_v2c -- --ignored
cargo test -p wrendns-snmp --test snmpd_interop dsc_003_net_snmp_auth_priv -- --ignored
export TT_SNMPD_USER=ttnopriv
cargo test -p wrendns-snmp --test snmpd_interop dsc_003_net_snmp_auth_no_priv -- --ignored
echo "snmp-e2e: ok"
