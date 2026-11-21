#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# REQ: NFR-005, NFR-001 (ADR-1075, T39.4) - prints the timestamp that stamps the Dockerfile's
# dependency layer (build argument DEPS_DATE_EPOCH): the commit time of the last commit that
# changed what the layer is built from. The layer's cache key then stays the same across commits
# that only change the workspace's own sources, which is the point of the layer; the final layers
# keep the commit's own time (SOURCE_DATE_EPOCH).
#
# The paths are the Dockerfile's `skeleton` stage inputs that carry content: the workspace and
# crate manifests, Cargo.lock, the toolchain pin and `.cargo/`. (The stub sources are empty and
# the `[[bench]]` names come from the manifests, so nothing else decides how the dependencies
# build. A file that appears or goes without a manifest change, such as a new build.rs, changes
# the layer's input and so misses its cache; the stamp then stays older, which costs nothing in
# correctness: the same commit still gives the same stamp and the same bytes.)
#
# Needs the history of those paths. In a shallow checkout the last commit that touched them is
# not known (git reports the checkout's one commit for every path), so the script says so on
# stderr and prints the commit's own time, which is what the build did before this argument
# existed. Run it from a full clone (`fetch-depth: 0`) to get the stable stamp.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
head_ct="$(git log -1 --format=%ct)"

if [[ "$(git rev-parse --is-shallow-repository)" == true ]]; then
    echo "deps-epoch: shallow checkout; using the commit time (the dependency layer will not be reused across commits)" >&2
    echo "$head_ct"
    exit 0
fi

ct="$(git log -1 --format=%ct -- Cargo.toml Cargo.lock rust-toolchain.toml .cargo 'crates/*/Cargo.toml')"
echo "${ct:-$head_ct}"
