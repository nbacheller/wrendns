# Failover with a VIP (keepalived)

Two WrenDNS nodes answer for one address (the VIP) with keepalived, so devices keep one DNS
server address and the other node takes over when the first stops answering. The runbook for a
real LAN, including moving a Pi-hole pair's VIP, is in [`docs/running.md`](../../docs/running.md)
("Failover with a VIP"); a pair on several VLANs is "Serving several networks" there. This directory is the Docker example and its proof (T24.4, and the second network, T24.32).

| File | What it is |
|---|---|
| `compose.yaml` | Two nodes, each with a keepalived sidecar that shares its network namespace, a witness (profile `witness`), on two internal bridges, `10.231.250.0/24` and `10.231.251.0/24` (the second is the pair's second VLAN; the witness is only on the first) |
| `Dockerfile` | The keepalived image: Alpine, keepalived, `dig` and `curl` for the checks and the test calls |
| `start-keepalived.sh` | Copies the mounted configuration to a private file (keepalived refuses an executable one), fills in `@iface:<address>@` with the interface that carries that address (Docker's interface order varies), and starts keepalived |
| `check-wrendns.sh` | The health check: one `/readyz` call, which answers 200 only while the node's own listener answers a DNS query (never logged or counted in the statistics) |
| `keepalived/node-a.conf`, `node-b.conf` | Two VRRP instances, one per network (VIPs `10.231.250.10` and `10.231.251.10`, `virtual_router_id` 53 and 54), both tracking the same health check; node a has the higher priority |
| `config/node-a.toml`, `config/node-b.toml`, `config/witness.toml` | The nodes' configuration: the wildcard listeners, the API, `[dns] nsid` and the cluster |
| `e2e.sh` | The proof: builds the image, runs the cluster, and checks the failover and maintenance |

## Run the proof

```sh
deploy/keepalived/e2e.sh                       # builds the image from this checkout, about five minutes
WRENDNS_IMAGE=<image> deploy/keepalived/e2e.sh  # or use an image you already have
```

It needs Docker with Compose v2 and Python 3. It checks, in order:

- the two nodes form a cluster, the witness joins it, and automatic failover is on;
- each node answers on its own address, and the answer names the node (the NSID option);
- the VIP is held by node a and answers as node a;
- the second network: each node answers on its own address there, both VIPs are held by node a, and
  the listeners answer UDP and TCP on the second VIP (the wildcard listener on a node with several
  networks);
- node a is killed (WrenDNS and keepalived together): the VIP moves to node b within 15 s and
  answers every query after that, the second VIP moves with it, and the cluster promotes node b;
- node a comes back: it takes both VIPs again and steps down to a replica;
- node a goes into maintenance through the API: `/readyz` answers 503, both VIPs move to node b, and
  node a keeps answering on its own addresses; ending maintenance brings the VIPs back.

The script removes its containers, network and (when it built it) image at exit. It doesn't publish a
host port and doesn't touch the LAN or any other compose project. The subnet is fixed in
`compose.yaml`, the node files and `e2e.sh` (both subnets); if either is already used, the script says so and stops.

## Use the example by hand

```sh
export WRENDNS_IMAGE=ghcr.io/nbacheller/wrendns:latest
docker compose -f deploy/keepalived/compose.yaml up -d
# Node a creates the cluster on its first start. Node b and the witness join it with tokens:
docker compose -f deploy/keepalived/compose.yaml exec wrendns-a wrendns cluster token create --ttl 30m --eligible -c /etc/wrendns/wrendns.toml
docker compose -f deploy/keepalived/compose.yaml stop wrendns-b
docker compose -f deploy/keepalived/compose.yaml run --rm --no-deps wrendns-b cluster join <token> --site wrendns-b --eligible --advertise https://10.231.250.12:8443 -c /etc/wrendns/wrendns.toml
docker compose -f deploy/keepalived/compose.yaml start wrendns-b
docker compose -f deploy/keepalived/compose.yaml exec wrendns-a wrendns cluster token create --ttl 30m --witness -c /etc/wrendns/wrendns.toml
docker compose -f deploy/keepalived/compose.yaml --profile witness run --rm --no-deps wrendns-witness cluster join <token> --witness --site witness --advertise https://10.231.250.13:8443 -c /etc/wrendns/wrendns.toml
docker compose -f deploy/keepalived/compose.yaml --profile witness up -d wrendns-witness
docker compose -f deploy/keepalived/compose.yaml exec wrendns-a wrendns cluster set-failover auto -c /etc/wrendns/wrendns.toml
```

The compose file doesn't publish ports. To reach the API or the DNS from the host, add `ports` to
the `keepalived-*` services (the sidecar owns the network namespace; the node has none of its own).

## Limits

- The keepalived sidecar owns the node's network namespace. Restart the pair together
  (`docker compose restart keepalived-a wrendns-a`): a restarted sidecar leaves its node listening in
  a namespace that no longer carries the VIP. On a host install (the runbook) there is no such pair.
- The VRRP adverts are not authenticated in this example. On a LAN, keep VRRP on the LAN interface.
- The VIP follows health, not the cluster. Configuration still comes from the cluster's primary, and
  the witness and automatic failover decide which node that is.
- Two Docker bridges stand in for two VLANs: one interface and one VRRP instance per network, as on a
  node with a tagged interface per VLAN. 802.1Q tagging itself is not exercised (it needs a switch).
- Only the bridge networks above are tested. The LAN variant (keepalived and WrenDNS on the host or a
  macvlan, with the VIP on the LAN subnet) is the runbook's; it has not been run on a LAN from here.
