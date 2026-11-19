# REQ: DSC-003 (T25.4) — a net-snmp agent for the interop tests (deploy/snmp-e2e.sh). Test only:
# it holds throwaway credentials made by the script and is never part of the image.
FROM alpine:3.20
RUN apk add --no-cache net-snmp
EXPOSE 161/udp
CMD ["snmpd", "-f", "-Lo", "-c", "/etc/snmp/snmpd.conf"]
