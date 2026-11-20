#!/bin/sh
# Installs Ubuntu packages on a CI runner without hanging on a stuck mirror (a bench-smoke
# job waited 40 minutes on `apt-get install dnsperf`, 2026-10-07): each attempt gets three
# minutes, and a failed or stuck one is tried again (three attempts).
#
#   sh .github/scripts/apt-install.sh dnsperf minisign
set -u
# Packages already present (always the case on the self-hosted runners, whose user has no sudo)
# are skipped; only the missing ones are installed.
missing=""
for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"; done
[ -z "$missing" ] && exit 0
set -- $missing
if [ "${RUNNER_ENVIRONMENT:-github-hosted}" = "self-hosted" ]; then
  echo "::error title=apt::$* missing on the self-hosted runner; install it on the runner host"
  exit 1
fi
for attempt in 1 2 3; do
  if timeout 180 sh -c "sudo apt-get update -qq && sudo apt-get install -y -qq $*"; then
    exit 0
  fi
  echo "::warning title=apt::installing $* failed or timed out (attempt $attempt of 3)"
  sleep 10
done
echo "::error title=apt::couldn't install $*"
exit 1
