#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# REQ: OPS-004 (ADR-1075, T39.5) - builds one platform of the image workflow: a single
# `docker buildx bake` (deploy/image/docker-bake.hcl) that compiles the platform once and
# exports the image and the `bin` stage from that one compile. No later step builds again.
#
# Environment (all required unless marked): PLATFORM (linux/amd64), ARCH (amd64|arm64|armv7),
# OUT (output directory), PUSH (true|false), IMAGE (registry name, when PUSH=true), CACHE
# (gha|none, optional), PROFILE (optional), and the build identity (VERSION, REVISION,
# WRENDNS_BUILD_VERSION, WRENDNS_BUILD_COMMIT, WRENDNS_BUILD_DATE, WRENDNS_BUILD_CHANNEL,
# SOURCE_DATE_EPOCH), which bake reads from the environment.
# Writes: $OUT/image.tar, $OUT/bin/{wrendns,wrendns.debug}, the image wrendns:smoke-$ARCH in the
# local daemon, and (PUSH=true) $OUT/digest holding the pushed platform image's digest.
set -euo pipefail

: "${PLATFORM:?}" "${ARCH:?}" "${OUT:?}" "${PUSH:?}"
if [[ "$PUSH" == true ]]; then : "${IMAGE:?}"; fi
export PLATFORM ARCH OUT PUSH CACHE="${CACHE:-none}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT"
log="$OUT/bake.log"
meta="$OUT/metadata.json"

docker buildx bake -f "$here/docker-bake.hcl" --progress=plain --metadata-file "$meta" 2>&1 | tee "$log"

# The guard: the leg's log shows the compile once. (`Compiling wrendns v` is the workspace's own
# crate, which always compiles when anything does; `wrendns-core v` and the rest do not match.)
n="$(grep -c 'Compiling wrendns v' "$log" || true)"
echo "compile steps in the log for $ARCH: $n"
if [[ "$n" -gt 1 ]]; then
    echo "::error::$ARCH compiled $n times in one leg; the image and the binaries must come from one compile"
    exit 1
fi

test -s "$OUT/bin/wrendns" || { echo "::error::no wrendns binary for $ARCH"; exit 1; }
test -s "$OUT/bin/wrendns.debug" || { echo "::error::no debug file for $ARCH"; exit 1; }

if [[ "$PUSH" == true ]]; then
    python3 - "$meta" "$OUT/digest" <<'PY'
import json, sys
digest = json.load(open(sys.argv[1]))["image"]["containerimage.digest"]
assert digest.startswith("sha256:"), digest
open(sys.argv[2], "w").write(digest + "\n")
PY
    echo "pushed $IMAGE@$(cat "$OUT/digest")"
fi
