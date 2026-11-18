# 13 — Agent Interface: Agent-Ready API and MCP Server

## 1. Why
The owner expects AI agents to manage the platform and run analytics:
- "Why is the TV slow?"
- "Block whatever the new IoT camera keeps calling home to."
- "Weekly report of new domains per kid's device."
- "Fail over to the Pi and promote it."

Neither Pi-hole nor Technitium is designed for this. TelltaleDNS treats agents as a first-class client type with the same security model as humans: **least privilege, preview before change, full audit.**

## 2. Requirements
| ID | Pri | Requirement |
|---|---|---|
| AGT-001 | P0 | **Agent-ready REST API:** every operation in OpenAPI has a summary, a description, examples, and enum docs written for LLM consumption. Responses include units in field names (`latencyMs`, `ttlSeconds`). Errors are problem+json with actionable `hint`s. |
| AGT-002 | P0 | **Dry-run on every mutation:** `?dryRun=true` returns the computed config diff, a validation result, and an *impact estimate* (e.g., "would block 1,243 queries/day from 3 clients, based on the last 7 days"), without applying. |
| AGT-003 | P0 | **Idempotency:** `Idempotency-Key` header on all POST/PATCH/DELETE; replays return the original result for 24 h. |
| AGT-004 | P0 | **Agent principals:** API tokens with `kind=agent`, a human owner, scopes (`analytics:read`, `querylog:read`, `config:read`, `config:write:<area>`, `ops:pause`, `ops:cache`, `cluster:admin`; for network inventory `discovery:read` at the Viewer role, `ops:discovery` at the Operator role and `ops:discovery_test` at the Admin role, none of them default and none granted by a wildcard or `config:write:*`, DSC-013), an optional group restriction, rate limits, and expiry. Default scope set is read-only. |
| AGT-005 | P0 | **Audit attribution:** audit entries record `actor = agent:<token-name> (owner: <user>)`, the MCP client name/version when present, and the agent-supplied `reason` string (required on writes). |
| AGT-006 | P0 | **Built-in MCP server, read-only tools** (§3.1) over Streamable HTTP at `/mcp`, plus `telltale mcp --stdio` (a local stdio bridge that authenticates to a node with a token). |
| AGT-007 | P1 | **MCP write tools with plan/apply** (§3.2): a write tool returns a plan + `planId`. `apply_plan(planId)` executes it only if the config version hasn't changed and the plan hasn't expired (10 min). Optionally, a policy requires human approval: the plan appears in the UI "Pending agent changes" inbox (and via alert destinations) before apply succeeds. |
| AGT-008 | P0 | **MCP auth:** Bearer agent tokens. The OAuth 2.1 flow per the MCP authorization spec (protected-resource metadata at `/.well-known/oauth-protected-resource`) uses the configured OIDC provider as the authorization server (P1), so a user can connect an agent with SSO and consent to scopes. |
| AGT-009 | P0 | **Guardrails:** result-size caps with pagination cursors (default 200 rows / 32 KiB per tool result), privacy level enforcement identical to the UI, per-token rate limits, and a cluster-wide kill switch (`agents.enabled=false`). Tool descriptions state side effects explicitly. |
| AGT-010 | P1 | **MCP resources and prompts:** resources for cluster status, config (redacted), and the daily summary report; prompts for "investigate device", "weekly network report", "tune blocklists", and "upstream health review". |
| AGT-011 | P1 | **Scope-aware federation:** every analytics tool accepts `scope` (cluster/site/node) and reports `missingNodes`, matching `12 §6`. |
| AGT-012 | P2 | **Agent-friendly analytics query language:** a constrained, safe query DSL (`vqlog`) over the query log and rollups (filter, group by, top-K, percentiles, time bucket), with a cost estimate, exposed as one tool. This avoids dozens of narrow tools and never allows arbitrary SQL. |

## 3. MCP tool catalog
Implement with the official Rust MCP SDK (`rmcp`) or a minimal compliant implementation (tools/resources/prompts + Streamable HTTP; spec revision pinned in `Cargo.toml` and documented). **Tools are thin wrappers over the REST API handlers. No separate business logic.**

### 3.1 Read-only (P0)
| Tool | Purpose |
|---|---|
| `get_overview` | KPIs for a window: queries, blocked %, cache hit %, latency p50/p95/p99, active clients, node health |
| `top_items` | Top domains / blocked domains / clients / NXDOMAIN / upstreams for a window, optionally per client or group |
| `search_queries` | Query-log search (client, group, qname pattern, status, qtype, rcode, upstream, min latency, node, time range; each of qname, client, status, qtype, and rcode can be negated with its `...Not` flag), paginated; or the one query a trace ID names (`trace`, OBS-017) |
| `explain_decision` | `explain` for name + client + qtype: rules matched, winner, upstream route |
| `get_client_profile` | Device profile: identity, groups, traffic, top/new domains, latency, protocols |
| `latency_breakdown` | Percentiles by stage / upstream / client / qtype |
| `upstream_health` | Per-upstream health, breaker history, latency percentiles |
| `list_effectiveness` | Hits, unique contribution, overlap, dead lists |
| `find_anomalies` | New domains, NXDOMAIN storms, DGA-suspicious names, rate anomalies, per-domain volume anomalies, behavior drift, beaconing (OBS-013), with evidence, over a window; every node's, each with its ID and acknowledgement (OBS-014), optionally only unacknowledged |
| `health` | One level for the deployment (healthy, degraded, severe) and every reason with its node and where to look (OBS-015) |
| `shadow_lists` | Per list in shadow mode: what it would have blocked (queries, devices, top names), to judge it before enforcing (OBS-018) |
| `overblocking_suspects` | Blocked names someone seems to want (answered soon after a block, retry bursts), with the deciding lists (OBS-018) |
| `network_health` | The live map in short: counts of nodes by health (green, yellow, red, idle), the red and yellow nodes with their reasons (at most 50), and the five busiest flows, from a sample of recent lookups (`sampleRate`); no domain name ever; device names at privacy levels 0 and 1 only; optional `network`, `group`, `device`, `node` filters; `map_disabled` when `[map]` is off (`analytics:read`, OBS-901, ADR-958, ADR-970) |
| `upstream_checks` | Per node and upstream: DNSSEC verdicts, EDE codes returned, second-opinion outcomes, and the latest disagreements with both answers (OBS-019) |
| `probe_status` | Every node's synthetic probes of its own listeners (and extra targets): answering, latency, failures in a row, certificate days left (OBS-020) |
| `cache_advice` | Per node: hit rate, memory, the estimated extra hits a 25/50/100% larger cache would serve, peak use, and grow/shrink/ok advice (OBS-021) |
| `slo_status` | The service-level objectives: target, SLI and error budget left over the window, burn rates over 5m–3d, and whether the budget burns fast enough to warn (OBS-016) |
| `simulate_change` | What a change *would have done* to the logged queries over a window (default 24 h): newly blocked and newly allowed, by device and name, changed routes, with the rows read and whether the result is partial. Takes the same change kinds as the plan tools (block/allow a domain, add a list, assign a device, update a group) without creating a plan (OBS-024) |
| `identify_device` | What a device looks like: class and product (likely / possibly / unknown) with the evidence (MAC vendor, announced name, the domains it talks to), the suggested group, and any explicit override (OBS-025) |
| `list_networks` | The network inventory: the routers' LANs and VLANs (subnet, VLAN, gateway, DHCP pool, domain) and groups' networks, each with its group, size, known devices, and how full it is; then every device the routers, Home Assistant, and mDNS found, with its DNS name under `[local] device_domain` (API-013, DNS-023) |
| `get_discovery_status` | The network inventory's status (DSC-014): the designated node, each SNMP agent with its last poll and capabilities, each subnet's identity counts, the imports, and the `public` state; health reasons never mark DNS unhealthy (`discovery:read`, DSC-013) |
| `list_discovered_devices` | The inventory by MAC (IP-only entries as `ip:<addr>`): sources, addresses with aliases, names with their source label, VLAN and port, findings, mutes, and `missingNodes`; device-supplied fields are marked as device data (`discovery:read`, DSC-011, DSC-015) |
| `list_workloads` | The Kubernetes workloads named as devices (`namespace/kind/name`): group and where it came from, pods and addresses, 24-hour queries and blocks, last seen; by namespace or group (FLT-017) |
| `get_workload` | One workload's profile by name: the workload, its identity (class `workload`, certain), rhythm, and recent and slow queries across every pod address it held (FLT-017) |
| `rollout_status` | The current rollout (version, stage, canaries and what each runs, bake time left, guard readings), whether the cluster is pinned and to which version and why, and the kept versions with provenance and outcome (CLU-013) |
| `cluster_status` | Members, roles, epochs, lag, versions, primary reachability; each node's maintenance window when set (OPS-010) |
| `drill_report` | Failover drills, newest first (coverage, verdict counts), or one report: per device followed / stuck / quiet / elsewhere, unanswered queries, time to failover, returned or sticky; queries per node (CLU-014) |
| `get_config` | Config section (secrets redacted) + current version |
| `secrets_status` | Stored secrets' metadata (name, kind, stamp, who set it when, `usedBy`, per-node readability), the node's store state and key ID, and every credential field with its source; never a value (API-015, ADR-903 §5; `config:read`) |
| `pihole_api_status` | Whether the Pi-hole compatible API (T24.10, ADR-961) is on, whether a token has been made and when, when it was last used, and the longest pause it may start; never the token. There is no tool to turn it on or to make or rotate its token (`config:read`). |
| `search_cmdb_cis`, `get_cmdb_ci`, `list_cmdb_conflicts`, `list_cmdb_macd`, `get_cmdb_macd`, `get_cmdb_status` | The CMDB (M31, DSC-907): configuration items with merged values and the deciding source, source records, conflicts, change records (MACD) and the status; device-supplied strings are marked as device data; `missingNodes` (`cmdb:read`) |
| `test_resolution` | Resolve a name through a given upstream/group *without* caching or logging, to diagnose |

### 3.2 Write (P1, plan/apply)
`plan_block_domain`, `plan_allow_domain`, `plan_add_list`, `plan_update_group`, `plan_assign_client`, `plan_rename_client` (API-010), `plan_update_upstreams`, `plan_set_schedule`, `plan_set_ratelimit`, `plan_set_exclusions` (OBS-022), `plan_set_map` (OBS-901; `config:write:map`: the map's sampling rate and the thresholds that colour it), `plan_set_special_names` (DNS-019; `config:write:special`; `ddrName` is refused for agents, ADR-918), `plan_set_device_names` (DNS-023; `config:write:local`), `plan_pin_version` / `plan_unpin` (CLU-013; `cluster:admin`), `plan_failover_drill` (CLU-014; `ops:drill`, never a default scope; the preview lists the preconditions, the baseline, and the devices) → `apply_plan`, `discard_plan`. Plans that change filtering or policy carry an `impact` (OBS-024) when the agent passes `simulate` (a window, e.g. `"24h"`) or `[simulate] plans_by_default` is on, and the node could simulate within its budget; they say so when it couldn't.
Immediate low-risk ops (scope-gated, still audited, no plan): `pause_blocking` (max 60 min for agents), `resume_blocking`, `flush_cache`, `acknowledge_anomalies` (`ops:anomalies`; `undo` takes it back; OBS-014), `start_maintenance` / `end_maintenance` (`ops:maintenance`; agents at most 2 h, a reason required; OPS-010), `refresh_lists` (`config:write:lists`; downloads the enabled lists, or the ones named, now instead of on their schedule; `dryRun` says what it would download; a reason required; FLT-004). Pre-save checks (T9.12; change nothing, need the entry's write scope): `check_upstream`, `check_list`.
CMDB plans and ops (M31, DSC-907): `plan_cmdb_link`, `plan_cmdb_unlink`, `plan_cmdb_value` (`ops:cmdb`; the plan carries the diff, and **`apply_plan` refuses a CMDB plan presented with an agent token**: applying is a human action in the UI, as ADR-903 §5), and the immediate op `request_cmdb_macd` (`ops:cmdb`; creates one `requested` change record, at most 50 open and 10 an hour per token). No tool approves, merges, splits, clears a flag or edits precedence. `ops:cmdb` is in no default scope or wildcard.

Discovery plans and ops (M25, DSC-013): `plan_import_scan` (`content` at most 768 KiB, parsed at plan time, the raw content never stored) with `apply_plan` / `discard_plan` (the config-version check does not apply); immediate ops `test_snmp_agent` (`ops:discovery_test`, Admin role), and `delete_scan_import` and `mute_discovery_finding` (`ops:discovery`, Operator role). Each takes `dryRun` and a reason, and none of the discovery scopes is in `DEFAULT_SCOPES` or any wildcard.
`cluster_promote` is excluded from agents unless `cluster:admin` scope **and** human approval are both configured.
**Not for agents, whatever the scopes** (ADR-903 §5; 403 `agent_not_allowed`, no tool, no plan): setting or clearing a stored secret (`PUT`/`DELETE /api/v1/secrets/{name}`), a backup (`POST /api/v1/backup`), router checks (`POST /api/v1/checks/router*`), `[clients] mdns` (`PUT`/`DELETE /api/v1/clients-settings/default`; no scope reaches it, ADR-914), and the admin-only `ddr_name` of `[special]` (ADR-918). A value would otherwise sit in AGT-007 plan memory, the approval diff and the agent's transcript (as with OPS-011 and ADR-156). The same holds for writes of the `router`, `oidc_provider`, `sink` and `identify-settings` kinds when they come (T23.7, T23.10, T23.11, T23.13): admin-only, no agent scope. Also never for agents (ADR-914, ADR-907): the guarded settings (listeners, the API address and TLS, trusted proxies, the secrets key files, `secret_file_dirs`, `allow_secrets_over_http`, `allow_insecure_basic`, cluster init, join and leave, `[cluster.git]`, node identity and storage, the watchdog, data-file paths), the `otlp`, `agents` and `auth-policy` kinds, and the `discovery` configuration kind, and the Pi-hole import (T24.18, `import.pihole`). The routes are `GET /api/v1/guarded` (readable with `config:read`, no pending values or tokens) and, admin session only, `POST /api/v1/guarded/{id}/preview`, `POST /api/v1/guarded/{id}`, `POST /api/v1/guarded/pending/{id}/confirm` and `/cancel`; an agent gets 403 `agent_not_allowed` on every write, the plan store refuses guarded paths, and the codes the routes add (`guarded_only`, `guarded_change_pending`, `preview_stale`, `primary_unreachable`, `would_disconnect_you`, `would_lock_out_admins`, `no_supervisor`, `restarting`, `not_primary`, and the rest of ADR-977 §1) are listed in the OpenAPI problem schema.

### 3.3 Example interaction
> **User → agent:** "Why is the living-room TV slow tonight?"
> **Agent:** `get_client_profile(client="living-room-tv", window="-6h")` → p95 latency 840 ms (normally 30 ms), 92% of misses go to the `quad9-doh` upstream
> → `upstream_health(window="-6h")` → `quad9-doh` breaker flapping since 19:40
> → `plan_update_upstreams(group="default", strategy="fastest", reason="quad9 degraded")` → plan shows the diff + impact
> → the user approves in the UI → `apply_plan`.

## 4. Implementation notes
- Crate: `telltale-mcp` (depends on `telltale-api` service layer). It is mounted in the same axum router on every node, so any node is an MCP entry point (single management plane).
- Tool JSON Schemas are generated from the same Rust types as the OpenAPI document (`schemars`), so they cannot drift. A CI test diffs the tool catalog against a committed snapshot.
- Tests:
  - an MCP conformance test with the reference inspector/client in CI;
  - golden transcripts for §3.3-style flows using a scripted fake agent;
  - authorization tests proving each tool honors scopes and privacy levels.
- Footprint: the MCP layer is a feature flag (`mcp`, default **on**) adding ≤ 1 MiB to the binary.
