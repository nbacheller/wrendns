# A three-node cluster test (`deploy/cluster3`)

A throwaway WrenDNS cluster of three containers, from the same image as the Docker Desktop
bundle, that checks the cluster the way it runs in a home or a small site: a **primary** and two
**replicas**, one of them with two CPUs. It's the acceptance run for T21.5 (`spec/10`), and CI runs
it on every change to the cluster code.

It never touches the single-node bundle (`deploy/docker-desktop`, project `wrendns-dev`, ports
1053 and 8053). This cluster has its own compose project (`wrendns-cluster3`), its own volumes, and
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
WRENDNS_IMAGE=<image> deploy/cluster3/e2e.sh   # runs a prebuilt image and skips the build
```

It works from Windows Git Bash (Docker Desktop) and from Linux (CI). The first run builds the image
(3 to 6 minutes on a warm laptop; a cold CI runner takes longer, and the workflow allows 60 minutes;
later builds reuse the build cache). The checks take about 3 minutes (check j adds its watch, 1 minute by default). Every run tears the cluster
down (`docker compose down -v`) and removes the test image it built, unless `KEEP=1` is set; a failure prints
the last 40 lines of each node's log first.

With `WRENDNS_IMAGE` set, `e2e.sh` runs that image and does not build: it prints `using the prebuilt image <image> (no build)`
and leaves the image in place at exit. The image must be built with the `e2e` cargo feature
(`--build-arg CARGO_FEATURES=e2e`, as the compose build does), because check c2 needs the fake category source.
Unset, the script builds `wrendns:cluster3-test` from this checkout as before.

### Registry variables

Compose files take the registry host from these variables. Each defaults to the public registry, so
with none of them set the files resolve to the same images as before. Set one to a pull-through mirror
host (for example `mirror.example:5000`) and only the registry host of the matching images changes.
Unset it again to return to the public registries.

| Variable | Default | Used for |
|---|---|---|
| `WRENDNS_HUB` | `docker.io` | Docker Hub images: `busybox` (this cluster's fake source) and `postgres`, `redis` (`ui/tests/oidc/compose.yml`) |
| `WRENDNS_GHCR` | `ghcr.io` | GitHub Container Registry images: Authentik (`ui/tests/oidc/compose.yml`), Home Assistant (`deploy/ha-test/compose.yaml`), and the published WrenDNS image in `deploy/keepalived/compose.yaml` |
| `WRENDNS_QUAY` | `quay.io` | Keycloak (`ui/tests/oidc/compose.yml`) |
| `WRENDNS_IMAGE` | `wrendns:cluster3-test` | This cluster's WrenDNS image. `e2e.sh` sets it to the image it builds, or to a prebuilt image you give it; the upgrade check (j) sets it per node |

`HA_TEST_IMAGE` still overrides the Home Assistant image as a whole (`deploy/ha-test/compose.yaml`), and
`WRENDNS_IMAGE` in `deploy/keepalived/compose.yaml` selects that test's image the same way.

Nothing secret is kept in the repository or in the image's configuration. Each run makes, in a
temporary directory it removes at exit: the admin password, the secret it writes, and the join token
(valid for 30 minutes). The node configurations in `config/` hold no secret.

## What it checks

Each check prints `== <name>` and then `ok` or `FAIL:` with the reason. The bracketed IDs are the
requirements each one covers.

Automatic failover is turned on after the replicas join, on the running primary, with no restart
(`wrendns cluster set-failover auto`, check **a2**). Every check after that runs with failover on,
so a check that pauses the primary for longer than its lease can promote a replica.

| check | what it proves | requirements |
|---|---|---|
| **a.** the three nodes join | both replicas join with a token and `--advertise`; the primary's `/api/v1/cluster` lists three connected nodes | CLU-001, CLU-005 |
| **a2.** automatic failover on a running cluster | in manual mode each replica reports the other as up (relayed by the primary); `set-failover auto` on the running primary is adopted by all three without a restart, the primary holds a lease, keeps its role and epoch, and no replica stands for 45 s (ADR-960) | CLU-005, CLU-001 |
| **b.** a config edit reaches every node | a record written on the primary answers on all three nodes' DNS within 5 s | CLU-003 |
| **c.** a write on a replica is forwarded | a record written on replica-a's API is on the primary and on replica-b | CLU-002 |
| **c2.** a content category chosen on a replica (FLT-901) | `PUT /api/v1/groups/default/content` on replica-a is forwarded to the primary, which stores it, downloads the category list from the test cluster's fake source (a BusyBox `httpd` that logs the address of each request, standing in for the list's host through a build with the `e2e` feature) and compiles it; all three nodes answer 0.0.0.0 for a name in the list, and the fake source saw requests from the primary only (a replica never downloads a category list) | FLT-901, CLU-003, ADR-994 |
| **d.** secrets | a secret set on the primary is readable on both replicas (`secrets status` shows it readable); every read surface (secrets, config, cluster, system info, audit) answers 200 and shows no value, and so do the metrics and every node's log | CLU-015, ADR-917 |
| **e.** routers and `[discovery]` | a router (`api_key_ref` to that secret) added on the primary is listed by all three; the first `[discovery]` write passes as a dry run with all three up, and as a real write with replica-b stopped (ADR-928 refuses only older or unreadable members; ADR-948); replica-b then reads back the non-default value it was given (48 MiB; the default is 64) | API-016, ADR-921, ADR-922, ADR-928, CLU-010 |
| **f.** federated reads | queries sent to each node show up in the primary's query log, labelled with the node, and the top clients have a count for each node | CLU-002, OBS-008 |
| **g.** upstream #7 on the 2-CPU replica | the primary is paused for longer than its lease, so the cluster promotes a replica (the reads still answer). Twenty concurrent reads at replica-a (the clients list, config entries, discovery status, the cluster) each return within 15 s; `/livez` and `/metrics` keep answering; DNS on replica-a answers a steady loop with no timeouts; replica-a's runtime starts with two workers (`runtime_workers=2` in its log, from the container's CPU quota). The primary is unpaused after | CLU-004, CLU-002, ADR-946 |
| **h.** failover | the node that holds the lease (`wrendns_cluster_lease_held` 1, `wrendns_cluster_primary` 1) is killed, so the election is the lease running out; the promotion comes 5 to 40 s after the kill; the other survivor follows it; DNS on both survivors answers with no SERVFAIL, and no more than 1% of the queries go unanswered (the probe fails on any timeout); an edit on the new primary reaches the other survivor; the killed node, started again, steps down and follows | CLU-005, ADR-051, ADR-056, ADR-947 |
| **i.** rolling restart | each node is restarted in turn; a monitor asks every node's DNS five times a second, and at least two must answer at every sample | CLU-004 |
| **e2.** a replica shows the primary's router data (T24.41) | a fake UniFi (served by the fake source over http, read with the stored key) is polled by the primary only; both replicas list its networks (VLAN 30, a domain), its clients and its state, labelled as read by the primary; with the primary paused a replica answers 200 and names it in `missingNodes` | API-013, API-016, API-010, CLU-002 |
| **h (T24.42).** every member holds the stored key, and the new primary uses it | in the failover check: a fake UniFi (the fake source's CGI, which logs the key each read carried and the address it came from) is read with the stored key by the primary only; every node's `GET /api/v1/secrets` lists all three members holding it, with one stamp; the primary is killed, and its replacement reads the fake UniFi with its replicated copy of the key within one interval plus the election while the other replica never polls; with the old primary back all three members hold the key. `ONLY=secrets` runs the bring-up, (a) to (e2) and (h), and stops | API-015, CLU-002, CLU-015, ADR-903, ADR-917 |
| **j.** upgrade from an older version (T24.40) | every node runs `OLD_IMAGE` (default `wrendns:lapse-base`, a build before ADR-1016) and takes entries through the API, fails over once, is upgraded, and after two more failovers the new primary dry-runs, edits and deletes the inherited entries: the others stay served and the edit and the delete stick. Skipped when `OLD_IMAGE` isn't there (`REQUIRE_UPGRADE=1` makes that a failure); `ONLY=upgrade` runs the bring-up, (a) and (j) alone. It runs after (k) | CLU-015 |
| **k.** replicas stay linked (T24.38) | after a rolling restart in the usual order (replicas, then the primary), every node reports `reachableVoters` = `voters` at every sample for 1 minute (`J_WATCH_S` changes it; the whole run takes about 7 minutes at the default) with no `leaving this node` log lines, and no `unstableVoters`; then the primary is killed: a survivor is elected within the lease time and neither survivor moves its link after it | CLU-001, CLU-005 |

### Check l: a rolling upgrade across the rename (T33.2)

<!-- rebrand:keep-start -->
Check **l** moves a running cluster from an image built before the rename to the renamed one, the
way an owner would upgrade: every node on the old image first, then each node on the new one,
replicas first and the primary last (it runs after **j**). Through the whole roll a monitor asks every
node's DNS every third of a second or so, and at least two of the three nodes must answer at every sample.
It also checks what must survive the rename: a session cookie made by the old node (`telltale_session`)
still signs in on the new one with no new sign-in, an API token made on the old primary still works,
the cluster is whole after every step (a node's certificate carries the cluster name of its version,
and each version accepts the other's), the record and the list entry made on the old nodes are
served by all three, a write on the new primary reaches the others, and a new node exports both
`wrendns_*` and `telltale_*` metrics.

The old image is not built by the run (it is another commit). Build it once from the commit before the
rename and tag it `telltale:pre-rename` (`PRE_RENAME_IMAGE` names another):

```sh
git archive <commit before the rename> | tar -x -C /tmp/pre-rename
docker build -t telltale:pre-rename --build-arg PROFILE=bench-fast --build-arg CARGO_FEATURES=e2e   --build-arg WRENDNS_BUILD_CHANNEL=dev /tmp/pre-rename
ONLY=prerename deploy/cluster3/e2e.sh        # the bring-up, (a) and (l) alone; REQUIRE_PRERENAME=1 fails when the image is missing
```

`compose-prerename.yaml` is the overlay a node on the old image needs: its command is `telltale`, it
keeps its data in `/var/lib/telltale` (the same volume the new image mounts at `/var/lib/wrendns`),
and its health command differs. `e2e.sh` adds it by itself for any image whose entrypoint is `telltale`.
<!-- rebrand:keep-end -->

Two things the task's wording named differently, and how the test handles them:

- Check **f** asks for the clients through `/api/v1/clients`. That endpoint lists the devices you
  configured, with no counts or node labels. The per-node view is the top clients statistic,
  `/api/v1/stats/top?kind=clients&scope=node:<name>`, which the test reads.
- Check **e** follows ADR-928 as decided: the gate refuses only a member that runs an older or an
  unreadable version. A stopped member is not refused. The test image is an unstamped local build,
  which reports `0.8.0-dev`; its peers read that as 0.8.0 (ADR-948, T21.6), so the gate reads every
  member.

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

- The log tails are printed. For more, `docker compose -p wrendns-cluster3 -f deploy/cluster3/compose.yaml logs <node>`
  works while the cluster is up (`KEEP=1` keeps the temp directory and the image).
- A failure in **e** after a build that reports no readable version (a bare `dev`, from a build made
  before T21.6) is the gate, not a bug: see the note above and ADR-948.
- The test's own timing is the only fixed wait: the bounds in `e2e.sh` (5 s for DNS in **b**,
  15 s for the reads in **g**, 5 to 40 s for the promotion in **h**, two answering nodes in **i**)
  are the requirements, not allowances.

## Cost

About 3 minutes of checks, and about 3 more for the first build. Nothing is left behind: the
containers, their volumes and the test image are removed at exit (`docker builder prune -f` keeps
the build cache small on a laptop).

## The lease-lapse soak (`lapse-soak.sh`, T24.26)

Two eligible nodes and a witness (a common Pi layout) under automatic failover, in their own
compose project (`wrendns-lapse`, `compose-lapse.yaml`), nothing published on the host. It soaks for
`SOAK_S` seconds (default 600) and counts "lease lapsed" in the primary's log; any lapse prints the
renewal-round debug lines. `DISK_DEV=/dev/sdd WRITE_BPS=8192` caps every node's disk writes (a slow
SD card); `FSYNC_STALL_S=4` pauses a random node for that long every 40 s; `LAPSE_IMAGE` soaks an
image that is already built (for example the one from before a fix). Run it under the same lock as
`e2e.sh`. In Docker the write cap slows the ballot store (the slow-store warning shows) but did not
reproduce a lapse; real Pi hardware is the real test.

The image builds with its own cache (`BUILD_CACHE_SCOPE=-cluster3`), apart from the default one that every
worktree shares: a shared cache can hold a crate built from another worktree's sources and fail with a
false compile error (`no method named ...`). Set `CLUSTER3_CACHE_SCOPE` (for example `-mybranch`) to keep
one worktree's cache apart from the others.
