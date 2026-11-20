#!/bin/sh
# Moves a native TelltaleDNS install to WrenDNS's names (REQ: OPS-004, spec/10 T33.2, ADR-1028).
#
#   sudo sh migrate-from-telltale.sh --dry-run     # say what would change, change nothing
#   sudo sh migrate-from-telltale.sh               # do it
#
# What it does, each step only when it still applies (running it again changes nothing):
#   - stops telltale.service (and starts wrendns.service again at the end if it was running);
#   - renames the `telltale` user and group to `wrendns` (same IDs, so file ownership holds);
#   - moves /var/lib/telltale to /var/lib/wrendns and /etc/telltale to /etc/wrendns, renames
#     telltale.toml to wrendns.toml, and rewrites the old paths inside the .toml files (the
#     originals are kept next to them as *.pre-wrendns);
#   - leaves /var/lib/telltale and /etc/telltale as symlinks, and telltale.toml as a symlink to
#     wrendns.toml, so anything that still names the old paths (keepalived checks, cron jobs,
#     scripts, `-c /etc/telltale/telltale.toml`) keeps working;
#   - installs wrendns.service from the old unit (your edits and drop-ins carry over, with TELLTALE_
#     variables renamed to WRENDNS_), disables telltale.service and keeps a copy of it;
#   - makes /usr/local/bin/telltale a symlink to wrendns (the old binary is kept as
#     telltale.pre-wrendns); the old name prints a deprecation warning and works for one release;
#   - renames the systemd-resolved drop-in and resolv.conf backup the old installer made;
#   - lists keepalived files that still name the old paths (they keep working through the links).
#
# The new binary must already be installed (deploy/systemd/install.sh does that, then calls this
# script). Environment (for tests): WRENDNS_MIGRATE_ROOT prefixes every path, WRENDNS_PREFIX is
# the binary prefix (default /usr/local).
#
# The old names below are deliberate: this file is kept out of scripts/rebrand.py.
set -eu

ROOT="${WRENDNS_MIGRATE_ROOT:-}"
PREFIX="${WRENDNS_PREFIX:-/usr/local}"
DRY=no
NO_START=no
DETECT=no
HERE="$(cd "$(dirname "$0")" && pwd)"

say() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run|-n) DRY=yes ;;
    --no-start) NO_START=yes ;;
    --detect) DETECT=yes ;;
    -h|--help) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
  shift
done

OLD_ETC="$ROOT/etc/telltale"
NEW_ETC="$ROOT/etc/wrendns"
OLD_DATA="$ROOT/var/lib/telltale"
NEW_DATA="$ROOT/var/lib/wrendns"
UNIT_DIR="$ROOT/etc/systemd/system"
OLD_UNIT="$UNIT_DIR/telltale.service"
NEW_UNIT="$UNIT_DIR/wrendns.service"
BIN="$ROOT$PREFIX/bin"

is_real_dir() { [ -d "$1" ] && [ ! -L "$1" ]; }

# True when something of the old install is still in its old place.
detect() {
  is_real_dir "$OLD_ETC" || is_real_dir "$OLD_DATA" || [ -f "$OLD_UNIT" ] \
    || { [ -f "$BIN/telltale" ] && [ ! -L "$BIN/telltale" ]; }
}

if [ "$DETECT" = yes ]; then detect; exit $?; fi

# Runs a command, or says it would.
run() {
  if [ "$DRY" = yes ]; then printf '    would: %s\n' "$*"; else "$@"; fi
}

# Replaces every old name in a file with the new one; keeps the original as <file>.pre-wrendns.
rewrite() {
  f=$1
  [ -f "$f" ] || return 0
  grep -q -i telltale "$f" 2>/dev/null || return 0
  if [ "$DRY" = yes ]; then printf '    would: rewrite the old names in %s\n' "$f"; return 0; fi
  [ -e "$f.pre-wrendns" ] || cp -p "$f" "$f.pre-wrendns"
  sed -e 's#/etc/telltale#/etc/wrendns#g' -e 's#/var/lib/telltale#/var/lib/wrendns#g' \
      -e 's#/run/telltale#/run/wrendns#g' -e 's#TELLTALE_#WRENDNS_#g' \
      -e 's#telltale\.toml#wrendns.toml#g' -e 's#/bin/telltale#/bin/wrendns#g' \
      -e 's#^User=telltale#User=wrendns#' -e 's#^Group=telltale#Group=wrendns#' \
      -e 's#^StateDirectory=telltale#StateDirectory=wrendns#' \
      -e 's#TelltaleDNS#WrenDNS#g' -e 's#telltale\.service#wrendns.service#g' \
      "$f.pre-wrendns" > "$f.new"
  mv -f "$f.new" "$f"
}

# Refuses (before anything is stopped or changed) when both an old directory and a non-empty new one exist.
preflight_dir() {
  old=$1 new=$2
  is_real_dir "$old" || return 0
  if [ -e "$new" ] && [ ! -L "$new" ] && [ -n "$(ls -A "$new" 2>/dev/null)" ]; then
    die "both $old and $new exist and $new isn't empty: look at them and move what you want to keep into $new, then run this again (nothing was changed)"
  fi
}

# Moves a real directory to its new place (an empty new one is replaced; a full one is an error).
move_dir() {
  old=$1 new=$2
  is_real_dir "$old" || return 0
  preflight_dir "$old" "$new"
  if [ -e "$new" ] && [ ! -L "$new" ]; then run rmdir "$new"; fi
  say "Moving $old to $new"
  run mv "$old" "$new"
  # a relative link: both directories share a parent, and it holds in a test root too
  run ln -s "$(basename "$new")" "$old"
}

if ! detect; then
  say "Nothing to migrate: no TelltaleDNS install found (or it was migrated already)."
  exit 0
fi

[ "$DRY" = yes ] && say "Dry run: nothing is changed."
if [ -z "$ROOT" ] && [ "$(id -u)" != 0 ] && [ "$DRY" = no ]; then die "run as root (sudo)"; fi

SYSTEMCTL=systemctl
command -v "$SYSTEMCTL" >/dev/null 2>&1 || SYSTEMCTL=true

preflight_dir "$OLD_DATA" "$NEW_DATA"
preflight_dir "$OLD_ETC" "$NEW_ETC"

# Other units an operator runs as the telltale user (a witness, a trial watchdog): found now, because
# the rename of the user needs them stopped, and they must run as wrendns afterwards.
OTHER_UNITS=""
if [ -d "$UNIT_DIR" ]; then
  for u in "$UNIT_DIR"/telltale-*.service; do
    [ -f "$u" ] || continue
    if grep -q -E '^(User|Group)=telltale' "$u" 2>/dev/null; then OTHER_UNITS="$OTHER_UNITS $u"; fi
  done
fi

WAS_ACTIVE=no
STOPPED_OTHERS=""
if "$SYSTEMCTL" is-active --quiet telltale 2>/dev/null; then WAS_ACTIVE=yes; fi
# If anything below fails, DNS must not stay down: start whichever unit exists (the old one until
# the new one is in place).
recover() {
  rc=$?
  if [ "$rc" != 0 ] && [ "$DRY" = no ] && [ "$WAS_ACTIVE" = yes ]; then
    printf 'error: the migration stopped part-way; starting the DNS service again\n' >&2
    if [ -f "$OLD_UNIT" ]; then "$SYSTEMCTL" start telltale 2>/dev/null || true
    else "$SYSTEMCTL" start wrendns 2>/dev/null || true; fi
    for o in $STOPPED_OTHERS; do "$SYSTEMCTL" start "$o" 2>/dev/null || true; done
  fi
}
trap recover EXIT
if [ "$WAS_ACTIVE" = yes ]; then
  say "Stopping telltale.service"
  run "$SYSTEMCTL" stop telltale
fi
for u in $OTHER_UNITS; do
  n=$(basename "$u")
  if "$SYSTEMCTL" is-active --quiet "$n" 2>/dev/null; then
    say "Stopping $n (it runs as the telltale user)"
    run "$SYSTEMCTL" stop "$n"
    STOPPED_OTHERS="$STOPPED_OTHERS $n"
  fi
done

# --- the user and group: renamed, so the IDs (and who owns every file) stay ---
if getent passwd telltale >/dev/null 2>&1 && ! getent passwd wrendns >/dev/null 2>&1; then
  say "Renaming the telltale user to wrendns"
  run usermod -l wrendns -d /var/lib/wrendns telltale
fi
if getent group telltale >/dev/null 2>&1 && ! getent group wrendns >/dev/null 2>&1; then
  run groupmod -n wrendns telltale
fi

# --- data and configuration ---
move_dir "$OLD_DATA" "$NEW_DATA"
move_dir "$OLD_ETC" "$NEW_ETC"
if [ -f "$NEW_ETC/telltale.toml" ] && [ ! -L "$NEW_ETC/telltale.toml" ]; then
  if [ -e "$NEW_ETC/wrendns.toml" ]; then
    note "$NEW_ETC has both telltale.toml and wrendns.toml: kept both; wrendns.toml is the one read"
  else
    say "Renaming telltale.toml to wrendns.toml"
    run mv "$NEW_ETC/telltale.toml" "$NEW_ETC/wrendns.toml"
    run ln -s wrendns.toml "$NEW_ETC/telltale.toml"
  fi
fi
if [ -d "$NEW_ETC" ]; then
  for f in "$NEW_ETC"/*.toml; do
    [ -f "$f" ] && [ ! -L "$f" ] && rewrite "$f"
  done
fi

# --- the unit: from the old one, so local edits carry over ---
if [ -f "$OLD_UNIT" ]; then
  say "Installing wrendns.service from telltale.service"
  if [ ! -f "$NEW_UNIT" ]; then
    if [ "$DRY" = yes ]; then note "would: write $NEW_UNIT"
    else cp -p "$OLD_UNIT" "$NEW_UNIT.new" && mv -f "$NEW_UNIT.new" "$NEW_UNIT"; fi
    rewrite "$NEW_UNIT"
    [ "$DRY" = yes ] || rm -f "$NEW_UNIT.pre-wrendns"
  fi
  if [ -d "$OLD_UNIT.d" ]; then
    run mkdir -p "$NEW_UNIT.d"
    for d in "$OLD_UNIT.d"/*.conf; do
      [ -f "$d" ] || continue
      target="$NEW_UNIT.d/$(basename "$d")"
      if [ "$DRY" = yes ]; then note "would: carry $d over to $target"
      else
        [ -e "$target" ] || cp -p "$d" "$target"
        rewrite "$target"
        rm -f "$target.pre-wrendns"
      fi
    done
  fi
  run "$SYSTEMCTL" disable telltale
  keep_dir="$NEW_ETC/pre-wrendns"
  run mkdir -p "$keep_dir"
  run mv "$OLD_UNIT" "$keep_dir/telltale.service"
  if [ -d "$OLD_UNIT.d" ]; then run mv "$OLD_UNIT.d" "$keep_dir/telltale.service.d"; fi
  run "$SYSTEMCTL" daemon-reload
  run "$SYSTEMCTL" enable wrendns
fi

# --- the command: the old name keeps working, with a deprecation warning ---
if [ -x "$BIN/wrendns" ]; then
  if [ -f "$BIN/telltale" ] && [ ! -L "$BIN/telltale" ]; then
    run mv "$BIN/telltale" "$BIN/telltale.pre-wrendns"
  fi
  if [ ! -e "$BIN/telltale" ]; then
    say "Linking $BIN/telltale to wrendns (deprecated name)"
    run ln -s wrendns "$BIN/telltale"
  fi
else
  note "$BIN/wrendns isn't installed yet: run deploy/systemd/install.sh, then this again"
fi

# --- what the old installer left for systemd-resolved ---
RD="$ROOT/etc/systemd/resolved.conf.d"
if [ -f "$RD/telltale.conf" ] && [ ! -e "$RD/wrendns.conf" ]; then run mv "$RD/telltale.conf" "$RD/wrendns.conf"; fi
if [ -f "$ROOT/etc/resolv.conf.telltale-backup" ] && [ ! -e "$ROOT/etc/resolv.conf.wrendns-backup" ]; then
  run mv "$ROOT/etc/resolv.conf.telltale-backup" "$ROOT/etc/resolv.conf.wrendns-backup"
fi

# --- other units that run as the telltale user: User= and Group= follow the rename ---
for u in $OTHER_UNITS; do
  say "Pointing $(basename "$u") at the wrendns user"
  if [ "$DRY" = yes ]; then note "would: change User=/Group= in $u"
  else
    [ -e "$u.pre-wrendns" ] || cp -p "$u" "$u.pre-wrendns"
    sed -e 's#^User=telltale#User=wrendns#' -e 's#^Group=telltale#Group=wrendns#' "$u.pre-wrendns" > "$u.new"
    mv -f "$u.new" "$u"
  fi
done
if [ -n "$OTHER_UNITS" ]; then run "$SYSTEMCTL" daemon-reload; fi

# --- anything else that names the old user, unit or command: listed, never edited ---
SCAN=""
for d in "$UNIT_DIR" "$ROOT/usr/local/sbin" "$ROOT/etc/cron.d" "$ROOT/etc/sudoers.d"; do
  [ -d "$d" ] && SCAN="$SCAN $d"
done
if [ -n "$SCAN" ]; then
  # shellcheck disable=SC2086
  others=$(grep -rlE '^(User|Group)=telltale|telltale\.service|-u telltale|sudo .*telltale|systemctl .*telltale' $SCAN 2>/dev/null \
    | grep -v -e '/wrendns\.service' -e '\.pre-wrendns$' || true)
  if [ -n "$others" ]; then
    say "These files still name the old user, unit or command; change them when it suits you (the user is wrendns now, the unit is wrendns.service):"
    printf '%s\n' "$others" | while read -r h; do note "$h"; done
  fi
fi

# --- keepalived and other things that call the old names: they keep working through the links ---
if [ -d "$ROOT/etc/keepalived" ]; then
  hits=$(grep -rl -i telltale "$ROOT/etc/keepalived" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    say "These keepalived files still name the old paths. They keep working (the old paths and the telltale command are links now); change them when it suits you:"
    printf '%s\n' "$hits" | while read -r h; do note "$h"; done
  fi
fi

# --- start again ---
if [ "$NO_START" = no ]; then
  for o in $STOPPED_OTHERS; do run "$SYSTEMCTL" start "$o"; done
fi
if [ "$WAS_ACTIVE" = yes ] && [ "$NO_START" = no ]; then
  if [ -x "$BIN/wrendns" ]; then
    say "Starting wrendns.service"
    run "$SYSTEMCTL" start wrendns
  else
    note "wrendns.service wasn't started: the binary isn't installed"
  fi
fi

say "Done. WrenDNS's paths are /etc/wrendns/wrendns.toml and /var/lib/wrendns; the old ones are links."
note "Roll back (as root): systemctl stop wrendns && systemctl disable wrendns; rm /var/lib/telltale /etc/telltale (the links); mv /var/lib/wrendns /var/lib/telltale; mv /etc/wrendns /etc/telltale; usermod -l telltale wrendns; groupmod -n telltale wrendns; rm /usr/local/bin/telltale && mv /usr/local/bin/telltale.pre-wrendns /usr/local/bin/telltale; mv /etc/telltale/pre-wrendns/telltale.service* /etc/systemd/system/; rm /etc/systemd/system/wrendns.service; systemctl daemon-reload && systemctl enable --now telltale. (docs/running.md has the same steps.)"
