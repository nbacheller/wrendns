#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# REQ: OPS-004 (ADR-1076, T39.9): read-only inspection of a build host before it runs the LXD runner
# containers described in docs/ci-runners.md.
#
# Usage:  sh deploy/ci-runners/inspect.sh [RUNNER_USER DIR_GLOB]
#   RUNNER_USER  the account that owns the self-hosted runner directories (optional)
#   DIR_GLOB     a shell pattern for the directory names under that account's home, for example
#                'actions-runner-*' (optional; the default is '*')
#
# This script only reads. It writes no file, changes no configuration, installs nothing, and starts,
# stops, restarts or enables no service. Commands that need root run as `sudo -n` (never a password
# prompt); when that fails, the check is skipped with a note. For runner directories it reports file
# names, owners and modes only, and never prints the contents of a credential file.
#
# It exits 0 after printing the report. A missing tool or permission is reported as a note, not a failure.

note() { printf '  note: %s\n' "$1"; }
section() { printf '\n== %s ==\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# PRIV is how a root-only read is run: '' when already root, 'sudo -n' when passwordless sudo works,
# 'none' otherwise.
PRIV=none
if [ "$(id -u 2>/dev/null)" = 0 ]; then
  PRIV=""
elif have sudo && sudo -n true >/dev/null 2>&1; then
  PRIV="sudo -n"
fi

# LXC is the LXD client that answers: 'lxc' for a user in the lxd group, 'sudo -n lxc' otherwise, or empty.
LXC=""
if have lxc; then
  if lxc version >/dev/null 2>&1; then
    LXC=lxc
  elif [ "$PRIV" != none ] && $PRIV lxc version >/dev/null 2>&1; then
    LXC="$PRIV lxc"
  fi
fi

IPT=""
if have iptables; then
  if [ "$PRIV" != none ]; then IPT="$PRIV iptables"; fi
fi

section "Host"
printf 'kernel: %s\n' "$(uname -sr 2>/dev/null)"
if [ -r /etc/os-release ]; then
  printf 'os: %s\n' "$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"')"
else
  note "no /etc/os-release: not a Linux distribution, or not the build host"
fi
if [ "$PRIV" = none ]; then
  note "passwordless sudo is not available: root-only checks are skipped"
else
  printf 'passwordless sudo: yes (used for root-only reads)\n'
fi

section "CPU (x86-64-v3 needs AVX, AVX2, BMI1, BMI2, FMA, F16C, MOVBE, LZCNT (shown as abm or lzcnt) and XSAVE)"
if [ -r /proc/cpuinfo ]; then
  printf 'logical CPUs: %s\n' "$(grep -c '^processor' /proc/cpuinfo)"
  flags=$(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2-)
  missing=""
  for f in avx avx2 bmi1 bmi2 fma f16c movbe xsave; do
    case " $flags " in
      *" $f "*) ;;
      *) missing="$missing $f" ;;
    esac
  done
  case " $flags " in
    *" abm "* | *" lzcnt "*) ;;
    *) missing="$missing lzcnt" ;;
  esac
  if [ -z "$flags" ]; then
    note "no x86 flags line in /proc/cpuinfo (not an x86 host?): x86-64-v3 cannot be judged"
  elif [ -z "$missing" ]; then
    printf 'x86-64-v3 flags: all present\n'
  else
    printf 'x86-64-v3 flags missing:%s\n' "$missing"
    printf 'jobs that need x86-64-v3 stay on GitHub-hosted runners on this host\n'
  fi
else
  note "/proc/cpuinfo is not readable"
fi

section "Memory"
if [ -r /proc/meminfo ]; then
  awk '/^(MemTotal|MemAvailable|SwapTotal|CommitLimit|Committed_AS):/ { printf "%-14s %8.1f GiB\n", $1, $2 / 1048576 }' /proc/meminfo
  note "Committed_AS is the memory promised to all processes; CommitLimit is the ceiling it is judged against"
else
  note "/proc/meminfo is not readable"
fi

section "Disk"
if have df && df -PT / >/dev/null 2>&1; then
  df -PT / | awk 'NR == 2 { printf "/ filesystem %s: size %.0f GiB, free %.0f GiB\n", $(NF-5), $(NF-4) / 1048576, $(NF-2) / 1048576 }'
else
  note "df is not available: disk checks are skipped"
fi

section "LXD"
if [ -n "$LXC" ]; then
  printf 'lxc client and server:\n'
  $LXC version 2>&1 | head -n 3 | sed 's/^/  /'
  printf 'firewall driver: %s\n' "$($LXC info 2>/dev/null | awk '$1 == "firewall:" { print $2 }')"
  printf 'storage pools:\n'
  $LXC storage list -f csv 2>&1 | sed 's/^/  /'
  printf 'networks:\n'
  $LXC network list -f csv 2>&1 | sed 's/^/  /'
  printf 'instances (name, state):\n'
  instances=$($LXC list -f csv -c ns 2>&1)
  if [ -n "$instances" ]; then
    printf '%s\n' "$instances" | sed 's/^/  /'
  else
    note "no instances"
  fi
  printf 'snapshots per instance:\n'
  $LXC list -f csv -c n 2>/dev/null | while IFS= read -r name; do
    [ -n "$name" ] || continue
    snaps=$($LXC info "$name" 2>/dev/null | awk '/^Snapshots:/ { f = 1; next } f && /^[^ \t]/ { f = 0 } f && NF { printf "%s ", $1 }')
    printf '  %s: %s\n' "$name" "${snaps:-none}"
  done
else
  if have lxc; then
    note "lxc is installed, but the LXD daemon did not answer (not initialised, or no access and no passwordless sudo)"
  else
    note "lxc not found: LXD is not installed or not on PATH; the LXD checks are skipped"
  fi
fi

section "Firewall"
if [ -n "$IPT" ]; then
  printf 'iptables: %s\n' "$($IPT -V 2>/dev/null | head -n 1)"
  policy=$($IPT -S FORWARD 2>/dev/null | head -n 1)
  printf 'FORWARD: %s\n' "${policy:-unreadable}"
  chain=$($IPT -S DOCKER-USER 2>/dev/null)
  if [ -z "$chain" ]; then
    note "DOCKER-USER is absent or unreadable"
  else
    printf 'DOCKER-USER: %s rules\n' "$(printf '%s\n' "$chain" | grep -c '^-A')"
    lxd_accept=$(printf '%s\n' "$chain" | grep -E -- '-[io] lxd' | grep -c 'ACCEPT')
    printf 'DOCKER-USER accept rules naming an lxd bridge: %s\n' "$lxd_accept"
  fi
else
  note "iptables is not available, or there is no root access: firewall checks are skipped"
fi

section "binfmt (arm emulation handlers)"
if [ -d /proc/sys/fs/binfmt_misc ]; then
  printf 'registered handlers: %s\n' "$(ls /proc/sys/fs/binfmt_misc 2>/dev/null | tr '\n' ' ')"
  for h in qemu-aarch64 qemu-arm; do
    if [ -r "/proc/sys/fs/binfmt_misc/$h" ]; then
      printf '%s: %s\n' "$h" "$(grep -E '^(enabled|flags)' "/proc/sys/fs/binfmt_misc/$h" | tr '\n' ' ')"
    else
      note "$h is not registered"
    fi
  done
else
  note "the binfmt_misc interface is absent: arm emulation cannot be checked"
fi

section "Runner directories"
if [ "$#" -lt 1 ]; then
  note "no runner user given (usage: inspect.sh RUNNER_USER DIR_GLOB): runner checks skipped"
else
  RU=$1
  PAT=${2:-*}
  home=$(getent passwd "$RU" 2>/dev/null | cut -d: -f6)
  [ -n "$home" ] || home=/home/$RU
  if [ ! -d "$home" ]; then
    note "no home directory found for user $RU"
  else
    printf 'runner user %s, home %s, pattern %s\n' "$RU" "$home" "$PAT"
    found=0
    for d in "$home"/$PAT; do
      [ -d "$d" ] || continue
      found=$((found + 1))
      printf '\ndirectory: %s\n' "${d##*/}"
      for f in .runner .credentials .credentials_rsaparams .env .path; do
        out=$(stat -c '%a %U:%G %n' "$d/$f" 2>/dev/null)
        if [ -z "$out" ] && [ "$PRIV" != none ]; then out=$($PRIV stat -c '%a %U:%G %n' "$d/$f" 2>/dev/null); fi
        if [ -n "$out" ]; then
          printf '  %s\n' "$out"
        else
          printf '  %s: absent or unreadable without root\n' "$f"
        fi
      done
      migrated=$(ls -A "$d" 2>/dev/null | grep '_migrated$')
      if [ -z "$migrated" ] && [ "$PRIV" != none ]; then migrated=$($PRIV ls -A "$d" 2>/dev/null | grep '_migrated$'); fi
      printf '  migrated credential files: %s\n' "$(printf '%s\n' "$migrated" | grep -c .)"
      if have systemctl; then
        unit=""
        for u in $(systemctl list-units --all --plain --no-legend 'actions.runner.*' 2>/dev/null | awk '{ print $1 }'); do
          wd=$(systemctl show -p WorkingDirectory --value "$u" 2>/dev/null)
          if [ "$wd" = "$d" ]; then unit=$u; break; fi
        done
        if [ -n "$unit" ]; then
          printf '  unit: %s, enabled: %s, active: %s\n' "$unit" \
            "$(systemctl is-enabled "$unit" 2>/dev/null)" "$(systemctl is-active "$unit" 2>/dev/null)"
        else
          note "no actions.runner.* systemd unit has this directory as its working directory"
        fi
      else
        note "systemctl is not available: unit state skipped"
      fi
      if have pgrep; then
        workers=0
        busy=0
        for p in $(pgrep -u "$RU" -x Runner.Worker 2>/dev/null); do
          workers=$((workers + 1))
          exe=$(readlink -f "/proc/$p/exe" 2>/dev/null)
          case "$exe" in
            "$d"/*) busy=$((busy + 1)) ;;
          esac
        done
        printf '  Runner.Worker processes for %s: %s, running from this directory: %s\n' "$RU" "$workers" "$busy"
        note "an unreadable process (another user's, without root) is counted as not matched"
      else
        note "pgrep is not available: job state skipped"
      fi
    done
    if [ "$found" -eq 0 ]; then
      if [ -r "$home" ] && [ -x "$home" ]; then
        note "no directory matches $home/$PAT"
      else
        note "$home cannot be read by this account, so directories matching $PAT could not be listed (run as a user who can read it)"
      fi
    fi
  fi
fi

printf '\nend of report (read-only: nothing was changed)\n'
exit 0
