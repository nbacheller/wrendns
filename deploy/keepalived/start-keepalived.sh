#!/bin/sh
# REQ: CLU-004 — starts keepalived on the configuration mounted at /etc/keepalived/keepalived.conf.
# keepalived refuses a configuration file that is executable, and a bind mount from a Windows or
# macOS host can show every file as executable, so the file is copied to a private 0644 path first.
set -eu
install -d -m 0755 /run/keepalived
install -m 0644 /etc/keepalived/keepalived.conf /run/keepalived/keepalived.conf
exec /usr/sbin/keepalived -n -l -D -f /run/keepalived/keepalived.conf
