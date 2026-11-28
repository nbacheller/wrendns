# Configuration

WrenDNS reads one TOML file, `wrendns.toml`, plus optional overrides. Every key is optional: anything you leave out uses a built-in default. A fully commented example lives in [`examples/wrendns.toml`](examples/wrendns.toml).

## Validate before you deploy
```sh
wrendns config check wrendns.toml               # "config OK" or a list of errors
wrendns config check wrendns.toml node.toml     # later files override earlier ones
wrendns config check wrendns.toml --print       # show the effective config (defaults + files + env; credentials as <redacted>, --show-secrets to see them)
wrendns config check wrendns.toml --no-env      # ignore WRENDNS_* variables
```
Every problem is reported with the exact key path, and all problems are reported at once:
```
error: cache.bogus: unknown field `bogus`, expected one of `max_bytes`, `max_entries`, ...
error: upstream[1].url: unsupported scheme `ftp://` (expected one of: udp, tcp, tls, https, ...)
error: upstream_group[0].members[1]: unknown upstream `ghost`
```
Unknown keys are always errors, so typos never get silently ignored. Values containing control characters (newlines, tabs, ...) are rejected.

## Editor completion
```sh
wrendns config schema > wrendns.schema.json
```
Point your editor's TOML language server at the schema (e.g. with Taplo/Even Better TOML: `#:schema ./wrendns.schema.json` as the first line of the file).

## Precedence
From lowest to highest:
1. Built-in defaults
2. Config files, in the order given (tables merge key by key; **arrays such as `[[listen]]` replace** the earlier value entirely)
3. Environment variables `WRENDNS_<SECTION>_<KEY>`
4. Command-line flags

## Environment variables
Any scalar key can be set from the environment. Upper-case the path and join it with `_`:

| Variable | Sets |
|---|---|
| `WRENDNS_ROLE=resolver` | `node.role` (keys in `[node]` may skip the `NODE_` part) |
| `WRENDNS_CLUSTER_SITE=home-pi` | `cluster.site` |
| `WRENDNS_CACHE_MAX_TTL=3600` | `cache.max_ttl` |
| `WRENDNS_CACHE_MAX_BYTES=64MiB` | `cache.max_bytes` |
| `WRENDNS_TELEMETRY_MODE=ship` | `telemetry.mode` |
| `WRENDNS_TELEMETRY_QLOG_RETENTION_DAYS=7` | `telemetry.qlog.retention_days` |

- Values are converted to the key's type. Booleans accept `true/false/1/0/yes/no/on/off`. Lists accept a TOML array (`["a","b"]`) or comma-separated text (`a,b`).
- Arrays of tables (`[[listen]]`, `[[upstream]]`, ...) can't be set from the environment. Use a file.
- An invalid value is an error that names the variable: `cache.max_ttl (from WRENDNS_CACHE_MAX_TTL): expected an integer, got "soon"`.
- Unknown `WRENDNS_*` variables are logged as warnings and ignored. This is deliberate: Kubernetes injects `WRENDNS_PORT`, `WRENDNS_SERVICE_HOST`, and similar variables for any Service named `wrendns`.
- `WRENDNS_CONFIG`, `WRENDNS_NODE_CONFIG`, `WRENDNS_LOG`, and `WRENDNS_LOG_FORMAT` are reserved for the binary itself, as are `WRENDNS_BOOTSTRAP_ADMIN_USER`, `WRENDNS_BOOTSTRAP_ADMIN_PASSWORD`, and `WRENDNS_BOOTSTRAP_ADMIN_PASSWORD_HASH` (the first admin from a secret; see `docs/running.md`). Also known and never reported: `WRENDNS_SUPERVISOR` (set by the shipped unit, bundles and chart; see the guarded restart), `WRENDNS_IGNORE_GUARDED`, `WRENDNS_TOKEN` (for `wrendns ctl`), and `WRENDNS_LOG_DNSSEC_LIBRARY`.

## Sizes
Byte sizes accept an integer number of bytes or a string with a unit: `"32MiB"`, `"2 GiB"`, `"500MB"`. Binary units (KiB, MiB, GiB, TiB) are powers of 1024; decimal units (KB, MB, GB, TB) are powers of 1000.

## Credentials from stored secrets (`*_ref`)
A credential that can be read from a file can instead name a secret stored (encrypted) on the node: `api_key_ref`, `api_secret_ref` and `password_ref` on a `[[router]]`; `token_ref`, `password_ref` and `user_key_ref` (Pushover) on an `[[alerts.destination]]`; `client_secret_ref` on an `[[auth.oidc.provider]]`; `token_ref` on a `[[telemetry.sink]]`; `header_refs = { <header> = "<name>" }` in `[telemetry.otlp]`; `credentials_ref` and `webhook_secret_ref` in `[cluster.git]`. Each holds the secret's name (`^[a-z0-9][a-z0-9._-]{0,62}$`). Set one of the inline value, the `_file` and the `_ref` for a credential, not more; a header goes in `headers` or `header_refs`. A name with no secret stored behind it is a warning, not an error, and `<redacted>` as a credential's value is an error. See running.md, "Stored secrets", and [secrets.md](secrets.md).

## Sections
| Section | Purpose | Reference |
|---|---|---|
| `[node]` | role (`all`/`resolver`/`controller`), name, worker threads, data directory, `drain_delay_secs`, `maintenance_default_secs` (how long maintenance lasts when a request doesn't say; maintenance itself is node state, started from the Cluster page, `wrendns ctl maintenance`, or the API), `secrets_key_file` and `secrets_previous_key_file` (the node's secrets key in a file instead of `WRENDNS_SECRETS_KEY` or `<data_dir>/secrets.key`; see running.md, "Stored secrets", and secrets.md), `secret_file_dirs` (where a file holding a credential set through the UI or API may be; default `/run/secrets`, `/var/run/secrets`, `/etc/wrendns/secrets`; see running.md, "Who may point a credential somewhere") | `spec/02`, OPS-010, OPS-014, API-014 |
| `[cluster]` | cluster name, site label, primary eligibility | `spec/12` |
| `[cluster.rollout]` | staged rollouts: `canaries` (node IDs, `site:<name>`, or `ephemeral`; empty, the default, means changes reach every node at once), `bake_secs` (at least 5; 300), `servfail_pct` (5), `require_traffic`, `max_bake_secs` (3,600), `fail_on_disconnect` (true), `history` (versions kept for pinning; 20); shared across a cluster; also in Settings → Cluster | CLU-013, `docs/running.md` |
| `[[listen]]` | `udp`, `tcp`, `dot`, `doh`, `doh3` (DoH over HTTP/3), and `doq` listeners; `tls` cert/key for the encrypted ones (reloaded on change), DoH `path`, `proxy_protocol` (v2) on TCP-based listeners, `require_client_id` (answer only a known device key; on by default for a listener on a public address, and for a wildcard bind (`0.0.0.0`, `[::]`) only on a host that holds a public IPv4 address (re-read at every reload; a global IPv6 address alone does not gate it and the node warns; an unreadable interface list gates it), off otherwise, `true` or `false` overrides, and every `false` on a public or public-resolving listener warns at start and at reload, whether the file or the UI set it; DoT, DoH, DoH3 and DoQ only; an admin can also set it per listener in Settings, System, Listener access, and a file that sets it wins). Default: UDP + TCP on port 53, IPv4 and IPv6 | `spec/03` §1, DNS-002/003/020/901 |
| `[[upstream]]` | upstream resolvers; the URL scheme picks the protocol | `spec/04` |
| `[[upstream_group]]` | named sets of upstreams with a strategy (`failover`, `round_robin`, `weighted`, `fastest`, `parallel`). Queries that match no route use the group named `default` | `spec/04` §4 |
| `[[route]]` | conditional forwarding by domain suffix, client group, or query type | `spec/04` §1 |
| `[[record]]` | local records (A, AAAA, CNAME, PTR, TXT, MX, SRV; `*.` wildcards) | `docs/running.md` |
| `[local]` | hosts files to import, automatic PTRs, default TTL for local records | `docs/running.md` |
| `[[dns_provider]]` | DNS providers: accounts at a DNS host the node may one day write record sets in (CLD-904, CLD-919, T36.10b steps 1 to 3; **a provider is written to only through the write engine: dry run until the first successful test, an ownership ledger, per-entry limits; Azure DNS and Cloudflare have provider code (T36.10b step 4); a kind without code says so on Test**). `name`, `kind` (`azure_dns`, `cloudflare`, `route53`, `rfc2136`), `zone`, `credential_ref` (the name of a stored secret; no inline credential and no file field), the kind's own non-secret fields (Azure: `subscription`, `resource_group`, `tenant`, `client_id`; Route 53: `hosted_zone_id`; RFC 2136: `server`, `key_name`, `algorithm`), `delegated_to`, `dry_run` (default on, ended by the first successful Test) and the write limits `max_writes_per_hour` (30) and `max_writes_per_minute` (5). Shared across a cluster; the first entry waits until every member's build knows the table. Also `PUT /api/v1/dns-providers/{name}` (admins only; never an agent) and Settings → DNS providers; see DNS providers in `docs/running.md` | `docs/running.md`, CLD-904 |
| `[[location]]` | locations: parts of the network with a device-name subtree of their own (DSC-908 to DSC-916, T36.10a). `slug` (the DNS label), `label`, `networks` (CIDRs or `vlan:<id>`, none overlapping another location's), `nodes`, `domain` (default `[local] device_domain`), `visibility` (`shared`, or `private`: answered only to clients in its networks), `flat_names` (default on: the old `<device>.<device_domain>` names keep answering). A device's own `location` is a field of its `[[client]]`. Shared across a cluster, and the first entry waits until every member's build knows the table. Also `PUT /api/v1/locations/{slug}`; see Locations in `docs/running.md` | `docs/running.md`, DSC-908 |
| `[[list]]` | filter lists: a `url`, a local `path`, or inline `rules`; `kind` (`block`/`allow`), `format` (`auto`/`rpz`: a response policy zone), `match` (`subtree`/`exact`), `mode` (`enforce`/`shadow`: counted, never blocks), per-list refresh, size limit, and `stale_after_days` | `docs/running.md` |
| `[[group]]` | client groups (filter profiles): which lists apply, `content` (`level`, `categories`, `tiers`, `ads`: what to block by category, see Content categories and filter profiles in `docs/running.md`), `safe_search_engines`, priority, answer filtering, DNS64, `filter_aaaa` (no IPv6 addresses), `device_classes` (kinds of device suggested for the group) | `docs/running.md`, FLT-016, OBS-025 |
| `[[client]]` | known devices: name, how to recognize them (IP, CIDR, MAC, `id:`, `hostname:` for the name a router gave), groups, `kind` (what it is, over any guess), `location` (pin it to a `[[location]]` whatever its address, DSC-910) | `docs/running.md`, OBS-025, FLT-006 |
| `[clients]` | neighbor table on/off and refresh interval; which forwarders' EDNS MAC to trust; `infrastructure` networks for the masked-client-IP check | FLT-006, OPS-003 |
| `[filter]` | list refresh interval, download concurrency, timeout, retries, size limit; compile threads and memory; `stale_after_days` (when an unchanged URL list counts as stale); `entry_budget` (names all selected category sources may add, default 1,000,000) and `ads_tier` (which size of ad list the Ad Block category uses) | `spec/05` §3.4, OBS-023 |
| `[access]` | networks allowed to query (everyone else is refused) | `spec/08` §6 |
| `[discovery]` | the network inventory (off by default): `enabled`, `node` (the one node that runs it; blank: the primary or the standalone node; a node ID or its name), `worker_memory_mib` (32–128), `[discovery.unifi_reads]` (`client_fields`, `all_users`, `devices`: extra read-only UniFi reads, each off by default; DSC-009), `unifi_all_users_within_hours` (1–8,760; default 720), `home_assistant_all_devices` (default true: Home Assistant devices that have a MAC and no entity, into the inventory only), and `[[discovery.subnet]]` with `cidr` (private IPv4 only; a filter on addresses the inventory already has, never a range to scan). `[[discovery.snmp_credential]]` (`name`, `role` infrastructure or host, `version` v2c or v3, and the files that hold the secrets: `community_file`, `auth_password_file`, `priv_password_file`, with `user`, `auth_protocol` sha, sha-256, sha-384 or sha-512 and `priv_protocol` aes-128; an inline secret is not a key, and MD5, SHA-224, DES, AES-192 and AES-256 are refused) and `[[discovery.snmp_agent]]` (`name`, never an address; `address`, an RFC 1918 IPv4 literal; `port` 161; `credential`; `interval_secs` 60 to 86,400, default 300; `max_repetitions` 5 to 25, default 10; `tables` of arp, ifmib, bridge, lldp). An agent takes an infrastructure credential only ([SNMP setup](snmp-setup.md)). Refused: IPv6, `100.64.0.0/10` and every non-RFC 1918 range; enabling it needs `telemetry.qlog.privacy_level` 0 or 1. Admins change it in the UI (Settings → Network inventory), never an agent | DSC-001, DSC-004, DSC-007, `docs/design/network-inventory.md` |
| `[ratelimit]` | per-client query budget, action, exemptions, IPv4/IPv6 grouping | DNS-014 |
| `[exclusions]` | names and devices kept out of the query log, analytics, and exports (still answered and counted in metrics), with an on/off toggle; also in Settings → Query handling | OBS-022 |
| `[identify]` | device identification: `enabled`, `max_clients` (devices one node identifies, 1 to 65,536), `signatures_file` (more signatures in the catalog's shape); shared across a cluster | OBS-025, `docs/running.md` |
| `[kubernetes]` | Kubernetes workloads as devices: `enabled`, `namespaces` (empty: all) and `exclude_namespaces`, `default_group`, `label` (`wrendns.com/group`), and `[[kubernetes.map]]` rules (`namespace` glob, optional `kind` and `name`, `group`); shared across a cluster. Only a node in a pod with a service-account token watches; with the Helm chart, set it through the chart's `kubernetes.*` values | FLT-017, `docs/running.md` |
| `[drill]` | Scheduled failover drills: `schedule` (`off` or `monthly`), `nodes` (which nodes drill themselves), `group` or `clients` (neither: everyone), `for_secs` (15–300, default 30), `hour` (default 3) and `tz`, `mode` (`drop` or `refused`); shared across a cluster. The report goes out as the `drill_report` alert | CLU-014, `docs/running.md` |
| `[simulate]` | change simulation over the query log: `enabled`, `plans_by_default` (agents' plans simulate even when they don't ask), `max_secs` (1 to 300), `max_rows` (at least 1,000), `default_window` (at most `7d`); shared across a cluster; also in Settings → Query handling | OBS-024, `docs/running.md` |
| `[map]` | the live network map's sampler and thresholds: `enabled` (default on; off: no sampling and the map routes answer `404 map_disabled`), `event_rate` (lookups a second each node samples, 10 to 2,000, default 200), `min_sample` (sampled answers before something is coloured, 1 to 1,000, default 20), `warn_latency_ms` (what counts as slow; unset: `[slo] latency_ms`), `warn_slow_pct` (10), `warn_error_pct` (5), `error_pct` (25, at least `warn_error_pct`), `warn_blocked_pct` (60, devices only); shared across a cluster; set in **Settings → Query handling → Network map** (one field each, with a preview of the current map), with `PUT /api/v1/map-settings/default` (agent scope `config:write:map`, MCP `plan_set_map`) | OBS-901, ADR-958, ADR-970 |
| `[map.geoip]` | the optional country database for the world view (an admin's; an operator's or an agent's change is refused): `enabled` (default off: nothing is fetched), `source_url` (HTTPS, no credentials, query string or fragment; unset: DB-IP's IP to Country Lite for this month, CC BY 4.0), `sha256` (pin the download: only useful with a fixed mirror), `home_country` (two letters; where arcs start); each node that serves the console fetches its own copy into `<data_dir>/geoip/`, at most once a day; a write to `[map]` that leaves out `geoip` keeps it | OBS-902, NFR-001, ADR-959, ADR-1008 |
| `[dns]` | the advertised EDNS UDP size; `nsid` (answer RFC 5001 NSID with this node's name) | DNS-005, DNS-021 |
| `[special]` | localhost, Firefox canary, CHAOS, private reverse lookups | ADR-014 |
| `[cache]` | memory budget, TTL clamps, serve-stale (`stale_answer_client_timeout_ms = 0` answers an expired name at once and refreshes it in the background: status `refreshed`), prefetch; per node | `spec/03` §4, `docs/running.md` |
| `[telemetry]` | telemetry mode, query-log retention and privacy, Prometheus endpoint (`[telemetry.metrics]`, with `exemplars` for OpenMetrics), OTLP export of metrics and traces (`[telemetry.otlp]`: `traces_sample_every`, `traces_slow_ms`), device anomaly detection (`[telemetry.anomaly]`) | `spec/06`, OBS-013, OBS-017 |
| `[upstream_check]` | second opinions: one forwarded question in `sample_every` asked again of another upstream and compared (off by default) | `spec/04` §9, OBS-019 |
| `[probe]` | synthetic probes of every listener and extra targets: interval, timeout, certificate warning days | `spec/06` §9, OBS-020 |
| `[slo]` | service-level objectives: availability and latency targets, the latency threshold, the error budget's window | `spec/06` §8.2, OBS-016 |
| `[api]` | REST API listener (also serves `/metrics` and health probes) | `spec/07`, ADR-028 |
| `[auth]` | session lifetimes, HTTP Basic over plain HTTP, roles that must use two-factor sign-in; `[auth.oidc]` sign-in providers (Keycloak, Authentik, ...) with group-to-role rules and break-glass | `docs/running.md`, ADR-029 |
