# TelltaleDNS

> **This is a fork:** [`nbacheller/telltaledns`](https://github.com/nbacheller/telltaledns), based on [`paimonsoror/telltaledns`](https://github.com/paimonsoror/telltaledns). Everything below this box is upstream's README. The badges, releases, quick start and project site are upstream's too. The fork's work is on the [`feat/ipam-integrations`](https://github.com/nbacheller/telltaledns/tree/feat/ipam-integrations) branch and follows the same spec-driven process. Its decisions are numbered from ADR-901 in [`spec/11`](spec/11-decisions.md).
>
> **What the fork adds** (milestones in the [roadmap](spec/10-roadmap-and-tasks.md)):
> - **M22, network inventory and home integrations (done):**
>   - device names from a UniFi gateway and from Home Assistant;
>   - those names answered in DNS (`kitchen-tablet.home.arpa`, with reverse lookups);
>   - your networks and VLANs, with how full each one is;
>   - a Home Assistant integration for TelltaleDNS;
>   - a [Docker Desktop bundle](deploy/docker-desktop/README.md) to try it.
> - **M24, replacing Pi-hole (in progress):**
>   - Pi-hole's special names: iCloud Private Relay blocked by default, `resolver.arpa` with encrypted DNS discovery (DDR), and domain-needed;
>   - **Update lists now** (Pi-hole's "Update Gravity"), for every list or one row at a time, with when each list was last confirmed current;
>   - in the UI: special names and DDR, device names in DNS, DNS names and naming sources on the Clients page, and a **Networks** page (make a group from a network);
>   - **Import from Pi-hole** in Settings (admins only): upload a Teleporter export or `gravity.db`, see what would be imported and where each entry points, then apply it as one change; the importer also reads `dnsmasq.d` lines;
>   - **Failover with a VIP** (T24.4): keepalived moves one address between two nodes, which answer on the wildcard address, with a witness for automatic promotion; a [Docker example](deploy/keepalived/README.md) proves the failover and maintenance hand-over in CI, and the [runbook](docs/running.md#failover-with-a-vip-keepalived) covers moving a Pi-hole pair's VIP;
>   - rules and groups that match a device by the name your router gave it, ranked below any network you name so a device can't claim another's rules (T24.9, T24.24), and `telltale auth reset-password` for a forgotten password with the node stopped (T24.7);
>   - IPv6 device names: AAAA and `ip6.arpa` answers from the routers' leases (T24.8).
>   - List hygiene: failing lists say why and offer the fix, imported regex lists are recognised, and a list another list fully covers can be turned off (T24.27); the Lists page shows how much each list overlaps the others and proposes a prune plan (T24.28);
>   - Cluster leases: a renewal is no longer written to disk, so a slow SD card can't make the lease lapse (T24.26, to be confirmed on the Pis).
>   - **A device's policy** (T24.30): click a device on Clients, the map or Flow to see the group it lands in and why, and every list, service, schedule, quick rule and upstream that applies, each linked to where it is set.
>   - **Query log exclusions** (T24.35): keep chosen clients, domains or the node's own lookups out of the query log while they still count in the statistics; the Pi-hole importer brings Pi-hole's exclusions across; `GET /readyz` answers only when the DNS listener does, for keepalived and load balancers.
>   - **Map fixes** ([fork #25](https://github.com/nbacheller/telltaledns/issues/25)): legend icons at their proper size; a dead member of an upstream group that still answers is a warning, not a failure; an upstream with no route on this node (say, IPv6 on an IPv4-only host) says so.
>   - **One picker** (T24.34, [fork #26](https://github.com/nbacheller/telltaledns/issues/26)): search, multi-select, chips and full keyboard use wherever you choose from a list; the Query log filters by device name, several devices at once.
>   - **A simple upstream picker** (T24.36, [fork #27](https://github.com/nbacheller/telltaledns/issues/27)): tick public providers (Cloudflare, Google, Quad9, OpenDNS, AdGuard, Mullvad, CleanBrowsing), choose encrypted or plain and IPv4/IPv6, or add your own; the full editor stays under Advanced.
>   - **Edits after a failover** (T24.37): entries added through the API on one primary stay editable and deletable after another node takes over, and a deleted entry stays deleted.
> - **M23, secrets and integrations in the UI (in progress):** secrets store, write-only API, no credential on any read surface; secrets replicated to every full cluster member; a **Secrets** page, and credentials (alerts, routers) entered in the UI, write-only, while a secret file still wins; routers (UniFi, Home Assistant) added, checked and changed from a **Routers** page without a restart; backups that carry the secrets encrypted under a passphrase (T23.9); OIDC sign-in providers added and changed in the UI without a restart, and node-local settings (T23.10); event sinks and the OTLP export with their credentials in the secrets store, reloaded without a restart (T23.11).
> - **M25, network inventory beyond the gateway (in progress):** in so far: the inventory model, which merges devices by MAC; sandboxed discovery workers (a separate process with seccomp, no capabilities and not dumpable) and a `[discovery]` section; an SNMP library (v2c, and v3 with AES) and a read-only SNMP client with `telltale snmp walk` (T25.4) and SNMPv3 with AES (T25.5). Still to come:
>   - SNMP polling of your gateway and switches (which device is on which port);
>   - more UniFi reads;
>   - importing results from a scanner you run yourself.
> - **M26, live network map (in progress, [ADR-958](spec/11-decisions.md)):** its data API is in (T26.2: `GET /api/v1/map`, a stream, health colours, the MCP `network_health` tool), sampled off the DNS path at +0.6 MiB, and the **Network map** page (T26.3); the world view is next. An animated map of your network and of where its lookups go, coloured green, yellow or red by health, sampled off the DNS path. A world view is optional, with a country database you download only if you turn it on ([ADR-959](spec/11-decisions.md)).
> - **A three-node test cluster (T21.5, [`deploy/cluster3`](deploy/cluster3/README.md)):** a primary and two replicas in containers, checked in CI on every change to the cluster code; it found and fixed a replica that followed a dead primary after a promotion.
> - **Cluster alerts:** an alert and a health reason when a replica can't reach its primary (T24.5).
> - **Pi-hole compatible API** (T24.10): dashboards, phone apps and the Home Assistant Pi-hole integration can read the summary and pause or resume blocking. It is off by default and needs a token.
> - **OIDC without `chrono`** (T24.23): sign-in tokens are checked in-tree on `ring`; `openidconnect`, `oauth2`, `chrono` and `rsa` are gone, and `cargo deny` passes with no ignored advisory.
> - **Cluster:** automatic failover can be turned on in a running cluster (T21.7), and dev builds report a readable version (T21.6).
> - **Test harnesses:** a throwaway Home Assistant in Docker for the Home Assistant source ([`deploy/ha-test`](deploy/ha-test/README.md), in CI).
> - **M27, UI for everything (in progress, [ADR-956](spec/11-decisions.md)):** a UI control for every older setting too, with guarded admin controls for listeners, TLS, keys and cluster setup ([ADR-914](spec/11-decisions.md)). In so far: the guarded-changes framework (staged change, typed confirmation, a rollback countdown, Restart now under a supervisor; T27.13), every alert condition in the Alerts form (T27.1), and group rewrites (T27.4).
> - **M31, CMDB (planned, [fork #21](https://github.com/nbacheller/telltaledns/issues/21)):** one configuration item per device from every source, each source's record linked, a definitive source per attribute, and MACD lifecycle.
> - **M32, away from home (planned, [fork #28](https://github.com/nbacheller/telltaledns/issues/28)):** a cloud-hosted resolver on a free or low-cost Azure tier, with DoH/DoT setup generated per device for Windows, macOS, iOS and Android, and the same policy at home and away.
>
> **Every feature gets a UI control**, not only config, API or MCP. Fork issues are tracked [here](https://github.com/nbacheller/telltaledns/issues). Changes from upstream are merged regularly.
>
> **Upstream:** what the fork changed from upstream, the upstream issues it triaged, and how it syncs and watches upstream are in [`spec/upstream.md`](spec/upstream.md).

[![CI](https://github.com/paimonsoror/telltaledns/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/paimonsoror/telltaledns/actions/workflows/ci.yml?query=branch%3Amain)
[![CodeQL](https://github.com/paimonsoror/telltaledns/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/paimonsoror/telltaledns/security/code-scanning?query=branch%3Amain)
[![Release](https://img.shields.io/github/v/release/paimonsoror/telltaledns?sort=semver)](https://github.com/paimonsoror/telltaledns/releases/latest)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-025e8c?logo=dependabot)](https://github.com/paimonsoror/telltaledns/pulls?q=is%3Apr+author%3Aapp%2Fdependabot)

**See every question. Answer on your terms.**

Every connection on your network starts with a DNS lookup. TelltaleDNS answers it in microseconds, filters it by your rules per device, and shows you exactly who asked, what they asked, and why it answered the way it did. It runs on a Raspberry Pi, in Kubernetes, or on both as one cluster that keeps answering even when parts of it fail.

> A *telltale* is the strip of yarn sailors tie to a sail to see what the wind is really doing. DNS is your network's telltale: it reveals what every device is up to.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/dashboard-dark.jpg">
    <img alt="The TelltaleDNS dashboard: queries, blocked share, cache hits, upstream latency, and active clients as plain numbers with their change; one chart of queries and blocked over 15 minutes with a change marker; and the top domains, blocked names, and clients with their groups" src="docs/images/dashboard-light.jpg" width="900">
  </picture>
  <br>
  <sub>The dashboard on a demo network. Every device, name, and address in it is made up.</sub>
</p>

## Mission
Give everyone who runs a home or small network an honest, real-time view of what their devices are doing, and full control over it, without trading away speed, footprint, or reliability.

- **See:** every query is attributed to a device, explained, and timed per stage.
- **Decide:** your rules per device and group, enforced instantly at no performance cost.
- **Never fail:** DNS keeps answering from its last good config, whatever happens to the control plane.
- **Run anywhere:** the same artifact on a Pi, in a cluster, or both at once.

## What it does
- **Every answer explained.** The query log ties each query to a named device, times every stage, and says why it was answered that way. Names come from your router, from what devices announce over mDNS, or from the UI, and TelltaleDNS recognizes what each device is (a Roku player, a camera, a thermostat) from its maker and the names it asks for.
- **Your rules, per device.** Blocklists, groups for each network or VLAN, schedules, safe search, blocked services, rewrites, and quick rules. Before you save a change, see what it would have done to yesterday's real traffic.
- **Encrypted both ways.** DoT, DoH, and DoQ for your devices and to your upstreams, DNSSEC validation, and full recursion when you'd rather not forward at all.
- **Watch it work.** A dashboard for the whole cluster, one node, or one site. A heatmap of when your network asks, a flow from each group to its answers, answer times as a heatmap, every change marked on every chart, and which devices and names spent the error budget. Compare nodes side by side, see a device's rhythm and its day, and put it all on a wall display. Device anomalies and alerts; Prometheus metrics, OpenTelemetry, dnstap, and event sinks for your SIEM.
- **One cluster, many places.** A Pi and Kubernetes nodes share one config and one management plane. A witness lets a replica take over automatically, and the config can live in Git. Changes can reach a few canary nodes first and roll back by themselves if those start failing, and maintenance mode takes a node out of service without dropped queries or false alarms.
- **Private by design.** Privacy levels decide how much of each query is kept, from everything to counters only, and every change lands in an audit log.
- **Ready for agents.** A documented REST API with OpenAPI, `telltale ctl` for the shell, and MCP tools with plans and approval for AI agents.
- **Small and fast.** One static binary in an image of about 13 MiB, for amd64, arm64, and 32-bit Pi OS. It idles at about 14 MiB of memory, holds a million blocked names in 60 MiB, and sends 99.999 % of cached and blocked answers within 250 µs of the query arriving, under load from another machine ([measurements](docs/v1-gate.md)).
- **Verifiable.** Images are signed with cosign, each release binary carries its dependency list and an SBOM, and two builds of the same commit are identical ([how to check](docs/running.md#versions-and-updates)).

## Quick start
On a Raspberry Pi or any Linux host with Docker:
```sh
mkdir telltale && cd telltale
curl -fsSLO https://raw.githubusercontent.com/paimonsoror/telltaledns/main/deploy/compose/compose.yaml
curl -fsSLO https://raw.githubusercontent.com/paimonsoror/telltaledns/main/deploy/compose/telltale.toml
docker compose up -d
docker compose exec telltale telltale auth setup-token     # then open http://<host>:8053/
```
Kubernetes (Helm), a native systemd install, clustering, and moving from Pi-hole or Technitium are covered in [`docs/running.md`](docs/running.md).

**Status:** pre-1.0. Tagged [releases](https://github.com/paimonsoror/telltaledns/releases) are stable (`latest`), and `edge` is built from every commit on `main`. Releases before 1.0 can still change configuration keys and APIs, and their notes call out every such change; the [roadmap](spec/10-roadmap-and-tasks.md) shows what's next. Project site: **https://paimonsoror.github.io/telltaledns/**

| Read this | If you want |
|---|---|
| [FAQ](https://paimonsoror.github.io/telltaledns/faq.html) | Quick answers to what people ask most: replacing other setups, root-server resolving, blocking categories, per-device encrypted DNS, clusters |
| [`EXECUTIVE-SUMMARY.md`](EXECUTIVE-SUMMARY.md) | What TelltaleDNS is built around, and the projects that inspired it |
| [`docs/analysis.md`](docs/analysis.md) | Design notes: what we learned from Pi-hole and Technitium |
| [`spec/`](spec/00-overview.md) | The build specification (requirements, architecture, ADRs, roadmap) |
| [`AGENTS.md`](AGENTS.md) | Instructions for the agent or developer implementing it |

## Spec index
0. [Overview](spec/00-overview.md): vision, goals, release-gate metrics
1. [Requirements](spec/01-requirements.md): numbered P0/P1/P2 contract
2. [Architecture](spec/02-architecture.md): roles, crates, threading, data flow
3. [Resolution pipeline](spec/03-resolution-pipeline.md): listeners, cache, DNSSEC, recursion
4. [Upstreams](spec/04-upstreams.md): protocols, presets, strategies, custom plugins
5. [Filtering](spec/05-filtering.md): list syntax, FST/DFA snapshots, groups, schedules
6. [Observability](spec/06-observability.md): QueryEvent, metrics, query-log store, analytics
7. [API and UI](spec/07-api-and-ui.md)
8. [Deployment, config, security](spec/08-deployment-config-security.md): Helm, Pi, auth (local + OIDC)
9. [Testing and benchmarks](spec/09-testing-and-benchmarks.md)
10. [Roadmap and tasks](spec/10-roadmap-and-tasks.md)
11. [Decisions (ADRs)](spec/11-decisions.md)
12. [Clustering and HA](spec/12-clustering-and-ha.md)
13. [Agent API and MCP](spec/13-agent-api-and-mcp.md)

## Contributors
Thank you to everyone who helps make TelltaleDNS better, whether by reporting what they found running it for real, writing code, or improving the docs:

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/gregpakes"><img src="https://avatars.githubusercontent.com/u/102243?v=4?s=100" width="100px;" alt="Greg Pakes"/><br /><sub><b>Greg Pakes</b></sub></a><br /><a href="https://github.com/paimonsoror/telltaledns/commits?author=gregpakes" title="Code">💻</a> <a href="https://github.com/paimonsoror/telltaledns/issues?q=author%3Agregpakes" title="Bug reports">🐛</a> <a href="https://github.com/paimonsoror/telltaledns/commits?author=gregpakes" title="Tests">⚠️</a> <a href="https://github.com/paimonsoror/telltaledns/issues/38" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/JohnDepon"><img src="https://avatars.githubusercontent.com/u/44707713?v=4?s=100" width="100px;" alt="John Depon"/><br /><sub><b>John Depon</b></sub></a><br /><a href="https://github.com/paimonsoror/telltaledns/commits?author=JohnDepon" title="Code">💻</a> <a href="https://github.com/paimonsoror/telltaledns/commits?author=JohnDepon" title="Tests">⚠️</a> <a href="https://github.com/paimonsoror/telltaledns/commits?author=JohnDepon" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/tusc"><img src="https://avatars.githubusercontent.com/u/9438017?v=4?s=100" width="100px;" alt="Carlos Talbot"/><br /><sub><b>Carlos Talbot</b></sub></a><br /><a href="https://github.com/paimonsoror/telltaledns/commits?author=tusc" title="Code">💻</a> <a href="https://github.com/paimonsoror/telltaledns/commits?author=tusc" title="Tests">⚠️</a> <a href="https://github.com/paimonsoror/telltaledns/commits?author=tusc" title="Documentation">📖</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind are welcome: [open an issue](https://github.com/paimonsoror/telltaledns/issues) or a pull request.

### Built with Claude
TelltaleDNS is developed with [Claude Code](https://claude.com/claude-code), Anthropic's coding agent, working from this repository's specification under the maintainer's direction. Claude writes much of the code, tests, and documentation; the maintainer sets the priorities, decides what ships, and approves every release and rollout.

The history shows exactly where Claude took part: every commit it worked on carries a `Co-Authored-By: Claude` trailer, naming the model. `git log --grep "Co-Authored-By: Claude"` lists them.

## License
Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
