#!/bin/sh
# REQ: CLU-004, OPS-012, OPS-901 — the keepalived health check for one TelltaleDNS node (deploy/keepalived).
# It runs in the node's network namespace, so 127.0.0.1 is the node itself. One call does it: /readyz
# answers 200 only while the node's own UDP listener answers a DNS query (the node asks it itself,
# with the probe name, which the query log and the statistics never keep: nothing shows up in the
# log however often keepalived calls), and it answers 503 while the node is starting, shutting down,
# or in maintenance, so a node drained for maintenance hands its VIP to the peer.
# Exit 0 is healthy, anything else fails the check. It needs only wget (or `telltale health`,
# which does the same without a shell tool: use it where wget is missing).
if command -v telltale >/dev/null 2>&1; then
  exec telltale health --url http://127.0.0.1:8053/readyz
fi
exec wget -q -O /dev/null -T 3 http://127.0.0.1:8053/readyz
