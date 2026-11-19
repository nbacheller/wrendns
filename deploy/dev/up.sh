#!/usr/bin/env bash
# Start the developer container wrendns-dev2 from wrendns-dev:1 (Git Bash on Windows).
#
#   deploy/dev/up.sh            create volumes, build the image if missing, clone the repo once,
#                               start wrendns-dev2 (or start it again if it is stopped)
#   deploy/dev/up.sh --sync     git fetch the Windows repo (read-only mount) into the clone
#   deploy/dev/up.sh --rebuild  rebuild the image (docker build) before starting
#
# Environment:
#   TT_ORIGIN   clone source when the Windows repo is not mounted (default: the origin remote of
#               the Windows checkout, read on the host). Used only for the first clone.
#   TT_BRANCH   branch checked out on first clone (default: feat/ipam-integrations).
#
# Volumes (never removed by this script):
#   tt-src      /src          Linux clone of the repo at /src/wrendns; worktrees in /src/wrendns/.wt/
#   tt-cargo2   /root/.cargo/registry  crates.io index and sources (dedicated to wrendns-dev2)
#   tt-sccache  /sccache      sccache objects (used only when RUSTC_WRAPPER=sccache is set)
#   tt-target2  /target       CARGO_TARGET_DIR
# This script mounts no volume of the older wrendns-dev container (tt-target, tt-cargo). Do not point
# wrendns-dev2 at tt-cargo: that volume is the whole CARGO_HOME of wrendns-dev.
set -euo pipefail
# Git Bash rewrites /paths for docker; the dk wrapper turns that off for docker calls only,
# because native git on Windows needs the /e/... form the rewrite would break.
dk() { MSYS_NO_PATHCONV=1 docker "$@"; }

HERE="$(cd "$(dirname "$0")" && pwd)"
# The main checkout (C:/src/wrendns on Git Bash), even when this runs from a worktree.
COMMON="$(git -C "$HERE" rev-parse --path-format=absolute --git-common-dir)"
REPO_WIN="$(cd "$COMMON/.." && pwd -W)"
IMAGE=wrendns-dev:1
NAME=wrendns-dev2
BRANCH="${TT_BRANCH:-feat/ipam-integrations}"
MODE="${1:-up}"

if [[ "$MODE" == "--rebuild" || -z "$(dk image ls -q "$IMAGE")" ]]; then
  dk build -t "$IMAGE" "$HERE"
fi
for v in tt-src tt-cargo2 tt-sccache tt-target2; do
  dk volume inspect "$v" >/dev/null 2>&1 || dk volume create "$v" >/dev/null
done

# Mount of the Windows repo, read-only, used for sync and the first clone.
WIN_MOUNT=(-v "$REPO_WIN:/mnt/win:ro")

if [[ "$MODE" == "--sync" ]]; then
  if [[ "$(dk container inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true)" != "true" ]]; then
    echo "error: $NAME is not running. Start it with deploy/dev/up.sh first." >&2
    exit 1
  fi
  # The clone's remote "winrepo" is the Windows checkout (/mnt/win). The origin fetch is optional:
  # the container has no credentials for it, so a failure there must not fail the sync.
  dk exec "$NAME" bash -lc '
    cd /src/wrendns
    git fetch winrepo --prune
    git fetch origin --prune || echo "note: origin fetch skipped (no access from the container)"
    git status -sb | head -1
  '
  exit 0
fi

# First run: clone into the volume. Worktrees are created later inside the clone.
if ! dk run --rm -v tt-src:/src "${WIN_MOUNT[@]}" "$IMAGE" bash -c 'test -d /src/wrendns/.git' 2>/dev/null; then
  ORIGIN="${TT_ORIGIN:-$(git -C "$REPO_WIN" remote get-url origin 2>/dev/null || true)}"
  dk run --rm -v tt-src:/src "${WIN_MOUNT[@]}" -e "TT_BRANCH=$BRANCH" -e "TT_ORIGIN=$ORIGIN" "$IMAGE" bash -c '
    set -e
    git clone --no-hardlinks /mnt/win /src/wrendns
    cd /src/wrendns
    git remote rename origin winrepo
    if [ -n "$TT_ORIGIN" ]; then git remote add origin "$TT_ORIGIN"; fi
    git config core.autocrlf input
    git checkout -B "$TT_BRANCH" "winrepo/$TT_BRANCH" 2>/dev/null || git checkout "$TT_BRANCH"
    git log --oneline -1
  '
fi

if dk container inspect "$NAME" >/dev/null 2>&1; then
  dk start "$NAME" >/dev/null
else
  dk run -d --name "$NAME" --restart unless-stopped \
    -v tt-src:/src \
    -v tt-cargo2:/root/.cargo/registry \
    -v tt-sccache:/sccache \
    -v tt-target2:/target \
    "${WIN_MOUNT[@]}" \
    -w /src/wrendns \
    "$IMAGE" >/dev/null
fi
dk ps --filter "name=^${NAME}$" --format '{{.Names}} {{.Status}}'
