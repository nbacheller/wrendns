#!/bin/sh
# REQ: CLU-004, OPS-012 — the keepalived health check for one TelltaleDNS node (deploy/keepalived).
# It runs in the node's network namespace, so 127.0.0.1 is the node itself. The node keeps the VIP
# only while both pass:
#   1. /readyz answers 200 (it is 503 while the node is starting or in maintenance, so a node
#      drained for maintenance hands its VIP to the peer);
#   2. a UDP query to the node's own listener gets an answer: the probe name is answered locally
#      as NXDOMAIN (the same probe the watchdog sends, crates/telltale/src/probes.rs).
# Exit 0 is healthy, anything else fails the check.
wget -q -O /dev/null -T 2 http://127.0.0.1:8053/readyz || exit 1
dig +time=2 +tries=1 @127.0.0.1 probe.telltale.invalid | grep -q 'status: NXDOMAIN' || exit 1
exit 0
