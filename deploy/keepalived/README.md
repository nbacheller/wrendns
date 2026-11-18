# Failover with a VIP (keepalived)

Two TelltaleDNS nodes answer for one address (the VIP) with keepalived, so devices keep one DNS
server address and the other node takes over when the first stops answering. The runbook for a
real LAN, including moving a Pi-hole pair's VIP, is in [`docs/running.md`](../../docs/running.md)
("Failover with a VIP"). This directory is the Docker example and its proof (T24.4).

| File | What it is |
|---|---|
| `compose.yaml` | Two nodes, each with a keepalived sidecar that shares its network namespace, a witness (profile `witness`), on an internal bridge `10.231.250.0/24` |
| `Dockerfile` | The keepalived image: Alpine, keepalived, `dig` and `curl` for the checks and the test calls |
| `start-keepalived.sh` | Copies the mounted configuration to a private file (keepalived refuses an executable one) and starts keepalived |
| `check-telltale.sh` | The health check: one `/readyz` call, which answers 200 only while the node's own listener answers a DNS query (never logged or counted in the statistics) |
| `keepalived/node-a.conf`, `node-b.conf` | The VRRP instance on the VIP `10.231.250.10`; node a has the higher priority |
| `config/node-a.toml`, `config/node-b.toml`, `config/witness.toml` | The nodes' configuration: the wildcard listeners, the API, `[dns] nsid` and the cluster |
| `e2e.sh` | The proof: builds the image, runs the cluster, and checks the failover and maintenance |

## Run the proof

```sh
deploy/keepalived/e2e.sh                       # builds the image from this checkout, about five minutes
TELLTALE_IMAGE=<image> deploy/keepalived/e2e.sh  # or use an image you already have
```

It needs Docker with Compose v2 and Python 3. It checks, in order:

- the two nodes form a cluster, the witness joins it, and automatic failover is on;
- each node answers on its own address, and the answer names the node (the NSID option);
- the VIP is held by node a and answers as node a;
- node a is killed (TelltaleDNS and keepalived together): the VIP moves to node b within 15 s and
  answers every query after that, and the cluster promotes node b;
- node a comes back: it takes the VIP again and steps down to a replica;
- node a goes into maintenance through the API: `/readyz` answers 503, the VIP moves to node b, and
  node a keeps answering on its own address; ending maintenance brings the VIP back.

The script removes its containers, network and (when it built it) image at exit. It doesn't publish a
host port and doesn't touch the LAN or any other compose project. The subnet is fixed in
`compose.yaml`, the node files and `e2e.sh`; if it is already used, the script says so and stops.

## Use the example by hand

```sh
export TELLTALE_IMAGE=ghcr.io/paimonsoror/telltale:latest
docker compose -f deploy/keepalived/compose.yaml up -d
# Node a creates the cluster on its first start. Node b and the witness join it with tokens:
docker compose -f deploy/keepalived/compose.yaml exec telltale-a telltale cluster token create --ttl 30m --eligible -c /etc/telltale/telltale.toml
docker compose -f deploy/keepalived/compose.yaml stop telltale-b
docker compose -f deploy/keepalived/compose.yaml run --rm --no-deps telltale-b cluster join <token> --site telltale-b --eligible --advertise https://10.231.250.12:8443 -c /etc/telltale/telltale.toml
docker compose -f deploy/keepalived/compose.yaml start telltale-b
docker compose -f deploy/keepalived/compose.yaml exec telltale-a telltale cluster token create --ttl 30m --witness -c /etc/telltale/telltale.toml
docker compose -f deploy/keepalived/compose.yaml --profile witness run --rm --no-deps telltale-witness cluster join <token> --witness --site witness --advertise https://10.231.250.13:8443 -c /etc/telltale/telltale.toml
docker compose -f deploy/keepalived/compose.yaml --profile witness up -d telltale-witness
docker compose -f deploy/keepalived/compose.yaml exec telltale-a telltale cluster set-failover auto -c /etc/telltale/telltale.toml
```

The compose file doesn't publish ports. To reach the API or the DNS from the host, add `ports` to
the `keepalived-*` services (the sidecar owns the network namespace; the node has none of its own).

## Limits

- The keepalived sidecar owns the node's network namespace. Restart the pair together
  (`docker compose restart keepalived-a telltale-a`): a restarted sidecar leaves its node listening in
  a namespace that no longer carries the VIP. On a host install (the runbook) there is no such pair.
- The VRRP adverts are not authenticated in this example. On a LAN, keep VRRP on the LAN interface.
- The VIP follows health, not the cluster. Configuration still comes from the cluster's primary, and
  the witness and automatic failover decide which node that is.
- Only the bridge network above is tested. The LAN variant (keepalived and TelltaleDNS on the host or a
  macvlan, with the VIP on the LAN subnet) is the runbook's; it has not been run on a LAN from here.
