#!/usr/bin/env bash
# REQ: OPS-003 (GitHub issue #2) — the install notes warn when service.dns.alsoServe is combined
# with externalTrafficPolicy Local and resolver pods (mode: scaled): a load balancer can announce
# the DNS IP from a node that runs only a resolver pod, and that node drops the extra port. The
# notes stay quiet in every setup where that can't happen.
#
# `helm template` doesn't print NOTES.txt and `helm install --dry-run` wants a cluster, so the
# notes are rendered from a temporary copy of the chart whose NOTES.txt is wrapped in a ConfigMap
# template: the chart's own text, rendered with the chart's own helpers, no cluster needed.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -r "$here/wrendns" "$tmp/chart"
{
  echo '{{- define "zz.notes" -}}'
  cat "$tmp/chart/templates/NOTES.txt"
  echo '{{- end -}}'
  cat <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: zz-notes
data:
  notes: |
{{ include "zz.notes" . | indent 4 }}
EOF
} > "$tmp/chart/templates/zz-notes.yaml"
rm "$tmp/chart/templates/NOTES.txt"
fail=0

# expect warn|quiet "label" <helm --set arguments...>
expect() {
  local want=$1 label=$2 out got
  shift 2
  if ! out=$(helm template notes-test "$tmp/chart" --show-only templates/zz-notes.yaml "$@" 2>&1); then
    echo "FAIL: $label: helm failed"
    echo "$out" | tail -5
    fail=1
    return
  fi
  if ! grep -q "WrenDNS is starting" <<<"$out"; then
    echo "FAIL: $label: the notes did not render"
    fail=1
    return
  fi
  if grep -q "service.dns.alsoServe puts the" <<<"$out"; then got=warn; else got=quiet; fi
  if [ "$got" = "$want" ]; then
    echo "ok:   $label ($got)"
  else
    echo "FAIL: $label: wanted $want, got $got"
    fail=1
  fi
}

scaled=(--set mode=scaled)
expect warn  "scaled, resolver pods, Local, alsoServe.cluster" "${scaled[@]}" --set service.dns.alsoServe.cluster=true
expect warn  "scaled, resolver pods, Local, alsoServe.api"     "${scaled[@]}" --set service.dns.alsoServe.api=true
expect quiet "scaled, no resolver pods"                        "${scaled[@]}" --set resolvers.replicas=0 --set service.dns.alsoServe.cluster=true
expect quiet "scaled, externalTrafficPolicy Cluster"           "${scaled[@]}" --set service.dns.externalTrafficPolicy=Cluster --set service.dns.alsoServe.cluster=true
expect quiet "scaled, alsoServe off (the default)"             "${scaled[@]}"
expect quiet "allInOne, the default mode"                      --set service.dns.alsoServe.cluster=true

exit "$fail"
