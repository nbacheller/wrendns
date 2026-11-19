#!/bin/sh
# REQ: CLU-004 — starts keepalived on the configuration mounted at /etc/keepalived/keepalived.conf.
# keepalived refuses a configuration file that is executable, and a bind mount from a Windows or
# macOS host can show every file as executable, so the file is copied to a private 0644 path first.
set -eu
install -d -m 0755 /run/keepalived
install -m 0644 /etc/keepalived/keepalived.conf /run/keepalived/keepalived.conf
# REQ: CLU-004 (T24.32) — a configuration names an interface as `@iface:<address>@`: the one that
# carries that address. Docker numbers a container's interfaces by how it attached the networks, so
# the example finds the name from the address it gave the container on each network.
conf=/run/keepalived/keepalived.conf
for ip in $(grep -o '@iface:[0-9.]*@' "$conf" | sort -u | sed -e 's/^@iface://' -e 's/@$//'); do
  dev=$(ip -o -4 addr show | awk -v ip="$ip" '{ split($4, a, "/"); if (a[1] == ip) { print $2; exit } }')
  if [ -z "$dev" ]; then
    echo "no interface carries $ip" >&2
    exit 1
  fi
  sed -i "s/@iface:$ip@/$dev/g" "$conf"
done
exec /usr/sbin/keepalived -n -l -D -f "$conf"
