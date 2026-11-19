#!/bin/sh
# REQ: OPS-004 (ADR-1028, spec/10 T33.2) -- for one release, the binaries are published under the
# pre-rename asset names too. A node still running the old `telltale self-update` looks for
# `telltale-<arch>-linux` in the release and in SHA256SUMS; without these it would find nothing
# and stay on the old version. The copies are the same bytes as the `wrendns-<arch>-linux` files.
#
# Usage: legacy-assets.sh <dist dir>   (prints the legacy file names, for the checksums step)
set -eu
d=${1:?usage: legacy-assets.sh <dist dir>}
out=
for a in x86_64 aarch64 armv7; do
  cp "$d/wrendns-$a-linux" "$d/telltale-$a-linux"
  out="$out telltale-$a-linux"
done
echo "${out# }"
