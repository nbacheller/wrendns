# REQ: CLU-004, OPS-001 — the VRRP side of the keepalived example (deploy/keepalived): keepalived
# and dig on Alpine, with the health check built in. It runs in the network namespace of its
# TelltaleDNS node (compose `network_mode: service:keepalived-*`), so the VIP it holds is the
# address the node's wildcard listener answers on. The base is pinned by tag.
FROM alpine:3.20
RUN apk add --no-cache keepalived bind-tools
COPY check-telltale.sh start-keepalived.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/check-telltale.sh /usr/local/bin/start-keepalived.sh
ENTRYPOINT ["/usr/local/bin/start-keepalived.sh"]
