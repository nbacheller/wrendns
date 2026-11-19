#!/usr/bin/env bash
# REQ: OPS-014 (T23.3 AC14, ADR-903 §3) — the secrets store's key reaches the controller (or the
# allInOne pod) only: with `secretsKey.existingSecret` (or `generate`) its pod mounts the Secret
# read-only and sets WRENDNS_NODE_SECRETS_KEY_FILE; resolver pods get neither, whatever the
# settings, with persistence on and off. Without a Secret nothing is mounted (the key is made in
# the data directory), and with persistence off the controller is told its data isn't kept
# (WRENDNS_DATA_EPHEMERAL, health `secrets_ephemeral`).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
chart="$here/wrendns"
fail=0

render() { # <template> <helm --set arguments...>
  local t=$1
  shift
  helm template keytest "$chart" --show-only "templates/$t" "$@"
}

# check <label> <template> <want: yes|no> <pattern> <helm --set arguments...>
check() {
  local label=$1 t=$2 want=$3 pattern=$4 out got
  shift 4
  if ! out=$(render "$t" "$@" 2>&1); then
    echo "FAIL: $label: helm failed"
    echo "$out" | tail -5
    fail=1
    return
  fi
  if grep -q -- "$pattern" <<<"$out"; then got=yes; else got=no; fi
  if [ "$got" = "$want" ]; then
    echo "ok:   $label"
  else
    echo "FAIL: $label: wanted $want for '$pattern', got $got"
    fail=1
  fi
}

key=(--set secretsKey.existingSecret=tt-key)
scaled=(--set mode=scaled)
for persist in true false; do
  p=(--set "persistence.enabled=$persist")
  for name in WRENDNS_NODE_SECRETS_KEY_FILE /etc/wrendns-secrets-key secretName:\ tt-key; do
    check "persistence=$persist allInOne: $name" statefulset.yaml yes "$name" "${key[@]}" "${p[@]}"
    check "persistence=$persist scaled controller: $name" statefulset.yaml yes "$name" "${key[@]}" "${scaled[@]}" "${p[@]}"
    check "persistence=$persist resolver pods: no $name" resolvers.yaml no "$name" "${key[@]}" "${scaled[@]}" "${p[@]}"
    check "persistence=$persist generated, resolver pods: no $name" resolvers.yaml no "$name" --set secretsKey.generate=true "${scaled[@]}" "${p[@]}"
    check "persistence=$persist no Secret: nothing mounted ($name)" statefulset.yaml no "$name" "${p[@]}"
  done
  check "persistence=$persist resolver pods: no data-ephemeral flag" resolvers.yaml no WRENDNS_DATA_EPHEMERAL "${scaled[@]}" "${p[@]}"
done
check "the key is read-only" statefulset.yaml yes "mountPath: /etc/wrendns-secrets-key" "${key[@]}"
check "persistence off: the controller is told" statefulset.yaml yes WRENDNS_DATA_EPHEMERAL --set persistence.enabled=false
check "persistence on: not told" statefulset.yaml no WRENDNS_DATA_EPHEMERAL
check "generate: the Secret is made" secrets-key.yaml yes "secrets.key:" --set secretsKey.generate=true
check "generate: the controller mounts it" statefulset.yaml yes "secretName: keytest-wrendns-secrets-key" --set secretsKey.generate=true
# The generated key is `ttsk1:` and 43 base64url characters.
if out=$(render secrets-key.yaml --set secretsKey.generate=true 2>&1) &&
  v=$(sed -n 's/^  secrets.key: //p' <<<"$out" | base64 -d) &&
  grep -Eq '^ttsk1:[A-Za-z0-9]{42}A$' <<<"$v"; then
  echo "ok:   generated key format"
else
  echo "FAIL: generated key format"
  fail=1
fi
exit $fail
