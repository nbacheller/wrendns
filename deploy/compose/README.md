# WrenDNS with Docker Compose (Raspberry Pi / any Linux)

```sh
docker compose up -d
docker compose exec wrendns wrendns auth setup-token   # then open http://<host>:8053/
```

- `compose.yaml`: host networking (real client IPs and MAC addresses), read-only root
  filesystem, only `NET_BIND_SERVICE`, a healthcheck, and `./data` for lists, the query log, and users.
- `wrendns.toml`: a starter config (DNS over TLS to Cloudflare and Quad9, one balanced
  blocklist, a 7-day query log). Edit it and reload with `docker compose kill -s HUP`.
- `WRENDNS_TAG=0.1.0 docker compose up -d` pins a release (default: `latest`, the newest stable release; `edge` follows main).
- `e2e.sh IMAGE` is the CI test of this bundle.

Port 53 busy, running unprivileged, SD-card tips: see "Raspberry Pi and Linux" in
[docs/running.md](../../docs/running.md#raspberry-pi-and-linux).

## Networks and VLANs

The bundle sets `WRENDNS_HOST_NETWORK=1` because it runs on the host network: the Networks page then lists the Pi's own networks (its LAN and any tagged VLAN interface) as "this node". Docker marks every container with `/.dockerenv`, and without the variable WrenDNS would treat the container as bridged and list none. Keep the variable if you copy the `network_mode: host` setup into your own file.
