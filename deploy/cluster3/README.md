# A three-node cluster test (`deploy/cluster3`)

A throwaway TelltaleDNS cluster of three containers, from the same image as the Docker Desktop
bundle, that checks the cluster the way it runs in a home or a small site: a **primary** and two
**replicas**, one of them with two CPUs. It's the acceptance run for T21.5 (`spec/10`), and CI runs
it on every change to the cluster code.

It never touches the single-node bundle (`deploy/docker-desktop`, project `telltale-dev`, ports
1053 and 8053). This cluster has its own compose project (`telltale-cluster3`), its own volumes, and
its own ports, every one bound to `127.0.0.1` so nothing on the LAN can reach the test cluster:

| node | role | DNS | API / UI | metrics |
|---|---|---|---|---|
| `primary` | creates the cluster, serves the UI | 2153 | 8153 | 9163 |
| `replica-a` | joins with a token, eligible for promotion, **2 CPUs** | 2253 | 8253 | 9263 |
| `replica-b` | joins with a token, eligible for promotion | 2353 | 8353 | 9363 |

## Run it

```sh
deploy/cluster3/e2e.sh            # from the repository root, with Docker (Compose v2) and python3
KEEP=1 deploy/cluster3/e2e.sh     # keeps the test image and the temp directory for a look
```

It works from Windows Git Bash (Docker Desktop) and from Linux (CI). The first run builds the image
(3 to 6 minutes on a warm laptop; a cold CI runner takes longer, and the workflow allows 60 minutes;
later builds reuse the build cache). The checks take about 3 minutes. Every run tears the cluster
down (`docker compose down -v`) and removes the test image, unless `KEEP=1` is set; a failure prints
the last 40 lines of each node's log first.

Nothing secret is kept in the repository or in the image's configuration. Each run makes, in a
temporary directory it removes at exit: the admin password, the secret it writes, and the join token
(valid for 30 minutes). The node configurations in `config/` hold no secret.

## What it checks

Each check prints `== <name>` and then `ok` or `FAIL:` with the reason. The bracketed IDs are the
requirements each one covers.

Before the replicas join, automatic failover is turned on and the primary is restarted to run it
(`telltale cluster set-failover auto`, as `docs/running.md` describes). Every check after that runs
with failover on, so a check that pauses the primary for longer than its lease can promote a replica.

| check | what it proves | requirements |
|---|---|---|
| **a.** the three nodes join | both replicas join with a token and `--advertise`; the primary's `/api/v1/cluster` lists three connected nodes | CLU-001, CLU-005 |
| **b.** a config edit reaches every node | a record written on the primary answers on all three nodes' DNS within 5 s | CLU-003 |
| **c.** a write on a replica is forwarded | a record written on replica-a's API is on the primary and on replica-b | CLU-002 |
| **d.** secrets | a secret set on the primary is readable on both replicas (`secrets status` shows it readable); every read surface (secrets, config, cluster, system info, audit) answers 200 and shows no value, and so do the metrics and every node's log | CLU-015, ADR-917 |
| **e.** routers and `[discovery]` | a router (`api_key_ref` to that secret) added on the primary is listed by all three; the first `[discovery]` write passes as a dry run with all three up, and as a real write with replica-b stopped (ADR-928 refuses only older or unreadable members; ADR-948); replica-b then reads back the non-default value it was given (48 MiB; the default is 64) | API-016, ADR-921, ADR-922, ADR-928, CLU-010 |
| **f.** federated reads | queries sent to each node show up in the primary's query log, labelled with the node, and the top clients have a count for each node | CLU-002, OBS-008 |
| **g.** upstream #7 on the 2-CPU replica | the primary is paused for longer than its lease, so the cluster promotes a replica (the reads still answer). Twenty concurrent reads at replica-a (the clients list, config entries, discovery status, the cluster) each return within 15 s; `/livez` and `/metrics` keep answering; DNS on replica-a answers a steady loop with no timeouts; replica-a's runtime starts with two workers (`runtime_workers=2` in its log, from the container's CPU quota). The primary is unpaused after | CLU-004, CLU-002, ADR-946 |
| **h.** failover | the node that holds the lease (`telltale_cluster_lease_held` 1, `telltale_cluster_primary` 1) is killed, so the election is the lease running out; the promotion comes 5 to 40 s after the kill; the other survivor follows it; DNS on both survivors answers with no SERVFAIL, and no more than 1% of the queries go unanswered (the probe fails on any timeout); an edit on the new primary reaches the other survivor; the killed node, started again, steps down and follows | CLU-005, ADR-051, ADR-056, ADR-947 |
| **i.** rolling restart | each node is restarted in turn; a monitor asks every node's DNS five times a second, and at least two must answer at every sample | CLU-004 |

Two things the owner's wording named differently, and how the test handles them:

- Check **f** asks for the clients through `/api/v1/clients`. That endpoint lists the devices you
  configured, with no counts or node labels. The per-node view is the top clients statistic,
  `/api/v1/stats/top?kind=clients&scope=node:<name>`, which the test reads.
- Check **e** follows ADR-928 as decided: the gate refuses only a member that runs an older or an
  unreadable version. A stopped member is not refused, and a `dev` build can't be read by its peers.
  The test image stamps the release version (`TELLTALE_BUILD_VERSION=0.8.0`), as CI stamps a release
  build, so the gate can read the replicas. ADR-948 records the open question.

## Test-only settings

The three configurations in `config/` set `[api] allow_secrets_over_http = true`. The test reaches
the API over plain HTTP on a loopback port of a cluster that nobody else can reach, and secrets
over plain HTTP are otherwise refused. Never set it on a real node.

The nodes use `nowhere` (`udp://127.0.0.1:9`) as their only upstream, so unknown names fail
(SERVFAIL) and the test's names are local records. The router points at `127.0.0.1:9`, which
refuses connections; the test reads only the router's listing.

## Files

- `compose.yaml`: the three services (one image, built from the repository's `Dockerfile` with the
  bundle's build arguments and the release version stamped in); `replica-a` has `cpus: 2`. Every
  host port is published on `127.0.0.1`.
- `config/primary.toml`, `config/replica-a.toml`, `config/replica-b.toml`: the node configurations.
  The primary creates the cluster (`[cluster.init]`); the replicas' shared sections come from it.
- `probe.py`: the stdlib-only probes: a DNS client, an API session per node, the steady query loops,
  and the upstream #7, rolling-restart and failover measurements.
- `e2e.sh`: brings the cluster up, runs the checks, and tears it down (an interrupted run unpauses
  the primary before it removes the cluster).

## When it fails

- The log tails are printed. For more, `docker compose -p telltale-cluster3 -f deploy/cluster3/compose.yaml logs <node>`
  works while the cluster is up (`KEEP=1` keeps the temp directory and the image).
- A failure in **e** after a `dev` build is the gate, not a bug: see the note above and ADR-948.
- The test's own timing is the only fixed wait: the bounds in `e2e.sh` (5 s for DNS in **b**,
  15 s for the reads in **g**, 5 to 40 s for the promotion in **h**, two answering nodes in **i**)
  are the requirements, not allowances.

## Cost

About 3 minutes of checks, and about 3 more for the first build. Nothing is left behind: the
containers, their volumes and the test image are removed at exit (`docker builder prune -f` keeps
the build cache small on a laptop).
