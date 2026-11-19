#!/bin/sh
# REQ: OPS-004 (ADR-1028) -- deploy/release/legacy-assets.sh publishes each binary under the
# pre-rename asset name too, byte for byte, and prints the names for the checksums step.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
for a in x86_64 aarch64 armv7; do printf 'binary %s\n' "$a" > "$T/wrendns-$a-linux"; done
out="$(sh "$HERE/../legacy-assets.sh" "$T")"
[ "$out" = "telltale-x86_64-linux telltale-aarch64-linux telltale-armv7-linux" ] || { echo "FAIL: printed '$out'" >&2; exit 1; }
for a in x86_64 aarch64 armv7; do
  cmp -s "$T/wrendns-$a-linux" "$T/telltale-$a-linux" || { echo "FAIL: $a differs" >&2; exit 1; }
done
(cd "$T" && sha256sum wrendns-* $out > SHA256SUMS)
[ "$(wc -l < "$T/SHA256SUMS")" -eq 6 ] || { echo "FAIL: SHA256SUMS has the wrong number of entries" >&2; exit 1; }
echo "ok: each binary is published under both names"
