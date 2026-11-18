#!/usr/bin/env bash
# REQ: DSC-003 (T25.5, ADR-908, ADR-911): SNMPv3 USM interop against a throwaway net-snmp snmpd.
#
# The agent runs in a container on a Docker bridge network made for this script (172.30.247.0/24,
# an RFC 1918 range, isolated: no host networking, nothing published, not the owner's LAN). The
# USM users and their passwords are generated at run time into files in a private work directory,
# never printed and never committed. The users cover SHA and SHA-256, each at authNoPriv and
# authPriv (AES-128). The network, the container and the work directory are removed on exit,
# also on failure or interrupt.
#
# Where the tests run:
#   default                  `cargo` on PATH (CI): the runner joins the network by address only.
#   TT_V3_DEV=<container>    run cargo in that running dev container (it is connected to the
#                            network for the run and disconnected after). Then TT_V3_ROOT_HOST
#                            (default: the repo root) is the repo as the host sees it, and
#                            TT_V3_ROOT_DEV (default /src/.wt/snmpv3) is the same directory as
#                            the dev container sees it; TT_V3_DEV_ENV is a prefix of env
#                            assignments for the cargo command.
set -euo pipefail
cd "$(dirname "$0")/../../.."
ROOT=$(pwd)

NET=tt-snmpv3-e2e-net-$$
SUBNET=172.30.247.0/24
IP=172.30.247.10
NAME=tt-snmpv3-e2e-agent-$$
MADE_NET=
DEV=${TT_V3_DEV:-}
# A hard kill (SIGKILL) skips the trap and leaves generated passwords here: clear old ones.
rm -rf ./.v3e2e.* 2>/dev/null || true
WORK=$(mktemp -d ./.v3e2e.XXXXXX)
cleanup() {
  if [ -n "$DEV" ]; then docker network disconnect "$NET" "$DEV" >/dev/null 2>&1 || true; fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [ -n "$MADE_NET" ]; then docker network rm "$NET" >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM


rand() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }
for u in sha sha256; do
  printf '%s' "$(rand)" >"$WORK/$u.auth"
  printf '%s' "$(rand)" >"$WORK/$u.priv"
done
printf '%s' "$(rand)" >"$WORK/wrong"
mkdir -p "$WORK/etc" "$WORK/var"
cat >"$WORK/etc/snmpd.conf" <<CONF
rouser v3sha authPriv
rouser v3shanp authNoPriv
rouser v3s256 authPriv
rouser v3s256np authNoPriv
sysname tt-v3-e2e
syslocation v3-e2e
syscontact none
CONF
{
  echo "createUser v3sha SHA \"$(cat "$WORK/sha.auth")\" AES \"$(cat "$WORK/sha.priv")\""
  echo "createUser v3shanp SHA \"$(cat "$WORK/sha.auth")\""
  echo "createUser v3s256 SHA-256 \"$(cat "$WORK/sha256.auth")\" AES \"$(cat "$WORK/sha256.priv")\""
  echo "createUser v3s256np SHA-256 \"$(cat "$WORK/sha256.auth")\""
} >"$WORK/var/snmpd.conf"

docker build -q -t tt-snmpd-v3e2e deploy/snmpd-test >/dev/null
docker network create --subnet "$SUBNET" "$NET" >/dev/null
MADE_NET=1
docker create --name "$NAME" --network "$NET" --ip "$IP" tt-snmpd-v3e2e >/dev/null
MSYS_NO_PATHCONV=1 docker cp "$WORK/etc/snmpd.conf" "$NAME:/etc/snmp/snmpd.conf"
# net-snmp turns the createUser lines into localized keys on its first start.
MSYS_NO_PATHCONV=1 docker cp "$WORK/var/snmpd.conf" "$NAME:/var/lib/net-snmp/snmpd.conf"
docker start "$NAME" >/dev/null
sleep 3
if [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != "true" ]; then
  docker logs "$NAME" 2>&1 | grep -v createUser >&2 || true
  echo "v3-e2e: the agent did not start" >&2
  exit 1
fi

if [ -n "$DEV" ]; then
  docker network connect "$NET" "$DEV"
  DEVROOT=${TT_V3_ROOT_DEV:-/src/.wt/snmpv3}
  WORKDEV="$DEVROOT/$(basename "$WORK")"
else
  WORKDEV="$ROOT/$(basename "$WORK")"
fi

# Runs one named test with the environment for one user.
run_test() { # test-name user authproto authfile [privfile]
  # The range guard is the Rust assertion in snmpd_interop.rs (v3_agent), which checks the
  # TT_SNMPD_ADDR the test really receives; a shell check of a constant would prove nothing.
  local envs="TT_SNMPD_ADDR=$IP:161 TT_SNMPD_SYSNAME=tt-v3-e2e TT_SNMPD_USER=$2 TT_SNMPD_AUTH=$3 TT_SNMPD_AUTH_FILE=$WORKDEV/$4"
  if [ -n "${5:-}" ]; then envs="$envs TT_SNMPD_PRIV_FILE=$WORKDEV/$5"; fi
  envs="$envs TT_SNMPD_WRONG_FILE=$WORKDEV/wrong"
  local cmd="env $envs cargo test -j 4 -p telltale-snmp --test snmpd_interop $1 -- --ignored --exact"
  if [ -n "$DEV" ]; then
    MSYS_NO_PATHCONV=1 docker exec "$DEV" bash -c "${TT_V3_DEV_ENV:-} cd $DEVROOT && $cmd"
  else
    bash -c "$cmd"
  fi
}

run_test dsc_003_net_snmp_auth_no_priv v3shanp SHA sha.auth
run_test dsc_003_net_snmp_auth_priv v3sha SHA sha.auth sha.priv
run_test dsc_003_net_snmp_auth_no_priv v3s256np SHA-256 sha256.auth
run_test dsc_003_net_snmp_auth_priv v3s256 SHA-256 sha256.auth sha256.priv
run_test dsc_003_net_snmp_v3_walk v3s256 SHA-256 sha256.auth sha256.priv
run_test dsc_003_net_snmp_wrong_password_fails v3sha SHA sha.auth sha.priv
run_test dsc_003_net_snmp_unknown_user_fails v3sha SHA sha.auth sha.priv
echo "v3-e2e: ok"
