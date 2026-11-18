# Upstream ledger — what the fork took, what it changed, and what it watches

Fork-only file. `nbacheller/telltaledns` is based on `paimonsoror/telltaledns`; this file records how far the fork has merged upstream, every intentional difference from upstream, the upstream issues the fork has triaged, and how the daily watch (`.github/workflows/upstream-watch.yml`) reports on new upstream work. Read it before any sync. The watch script reads the three machine-readable blocks below, so keep their format.

## Last sync

upstream-synced: 095b77f

- Upstream commit: `095b77f` (upstream `main` at the last sync; `test(cluster): wait for the member table ... [CLU-001]`).
- Fork merge: `64ef498` on `feat/upstream-sync`, 2026-11-18 (9 upstream commits: the query log's "not" filters, a cluster-wide support package, Bootstrap Icons, the Developers docs, the two-factor code box; ADR-986, ADR-987). It reaches `feat/ipam-integrations` when the owner merges the branch.
- Previous sync: `3868483`, merged as `e3a00a7` on `feat/ipam-integrations`, 2026-11-17 (14 upstream commits; ADR-942).
- Conflicts at this sync and the side kept: `deny.toml` (fork: no advisory ignored), `auth_setup.rs`, `auth_setup_tests.rs`, `schema.rs`, `config-schema.json`, `running.md`, `spec/08` (fork: loopback break-glass, ADR-944; upstream's start-up notice and its test dropped, ADR-987), `Login.svelte` and `Settings.svelte` (fork: same fix, `{"[0-9]{6}"}`), `net_tests.rs` (fork's wait; the same fix as upstream's), `federated.rs` (both: fork's `block_in_place` helper and map read, upstream's support and negated reads), `Queries.svelte` (both: the router-name client box beside upstream's "not" checkboxes), `1-ui.spec.ts` (both tests kept), `api.ts` (clean 3-way: the fork already had the NUL fix), `spec/10` and `spec/11` (both; upstream's M24 renumbered to M30, T22.2 to T29.2, ADR-986).

### How to sync

The fork's procedure, used for the 2026-11-17 merge:

1. `git fetch upstream main`. Read the upstream commits since the last sync: `git log --oneline upstream-synced..upstream/main`. The watch report lists them and flags the ones that touch a deviation below.
2. Branch `feat/upstream-sync` from `feat/ipam-integrations`. Trial-merge with `git merge --no-commit --no-ff upstream/main`, and list the conflicts. Resolve them by keeping every fork deviation below; never take upstream's side of a deviation path without an ADR.
3. Review. Upstream ADR numbers are kept as they are. Fork ADRs take 901 and up (ADR-906). If an upstream milestone or task ID collides with a fork one, the upstream one takes the next free fork number: upstream's M22 and M23 became M29 and M28 in the 2026-11-17 merge, and upstream's M24 became M30 (T24.x to T30.x) and its T22.2 became T29.2 in the 2026-11-18 merge (ADR-986). Fork task IDs are cited in code, tests and open branches, so they are not renamed. Record the rename in the merge message and in `spec/10`.
4. Recheck. The gates are `cargo test`, `cargo clippy` clean, the Playwright e2e, the cargo-deny check, and the image gate (`deploy/image/size.py`, 25 MiB per architecture, ADR-916). Run `make bench-smoke` if a hot-path crate changed.
5. Merge into `feat/ipam-integrations` with a merge commit that names the upstream SHA and the requirement IDs. Then update this file: the `upstream-synced:` line, the Last sync section, the `triaged` block, and any deviation that changed.

The merge goes through `feat/upstream-sync` so the owner sees the conflicts before the merge reaches the fork's branch.

## Deviations

Each deviation is an intentional difference from upstream. Each name is the key of a line in the machine-readable block below, except `milestone-renumbering`, which has no block line: the always-on `numbering` flag (spec/10, spec/11) covers those files. `shared-edits` lists the fork's edits to shared files, which no single ADR owns; the trial merge is the check there.

| Name | ADR(s) | What differs | Paths |
|---|---|---|---|
| image-gate | ADR-916, ADR-915 | The image gate is 25 MiB compressed per architecture; upstream's is 15 MiB. Cold code is optimized for size, and the UI is embedded only as gzip. | `Dockerfile`, `deploy/image/**`, `.github/workflows/image.yml`, `Cargo.toml`, `Cargo.lock` |
| secrets-store | ADR-903, ADR-917, ADR-919, ADR-926 | A write-only encrypted secrets store, referenced by `*_ref` names in configuration. Secrets replicate to full members outside configuration versions. Credentials are entered only through `SecretField`. Credential rules in the forms (ADR-926). | `crates/telltale/src/secrets*`, `crates/telltale/src/secrets/**`, `crates/telltale/src/secret_store_tests.rs`, `crates/telltale-api/src/secrets*`, `ui/src/**/Secret*`, `crates/telltale-config/src/secret_refs.rs`, `crates/telltale-config/src/credentials.rs`, `crates/telltale-store/src/state/secrets.rs`, `crates/telltale/src/credential_rules*.rs`, `crates/telltale/src/credential_tests.rs`, `crates/telltale/src/redact.rs`, `crates/telltale/tests/secrets_cluster.rs`, `deploy/helm/telltale/templates/secrets-key.yaml`, `deploy/helm/telltale/templates/cluster-secret.yaml`, `deploy/helm/secrets-key-test.sh`, `docs/secrets.md` |
| routers | ADR-921, ADR-922, ADR-903 §7 | `[[router]]` is a managed kind: admin-only, file-read-only through the API, named secrets only, with hot reload. Ephemeral pods read no router. | `crates/telltale/src/routers*.rs`, `crates/telltale/src/router_*.rs`, `ui/src/**/Routers*`, `crates/telltale-api/src/routers_api.rs`, `crates/telltale-upstream/src/router.rs`, `crates/telltale-upstream/tests/router.rs`, `ui/src/pages/Networks.svelte` |
| inventory-merge | ADR-910, ADR-912, ADR-913, ADR-923, ADR-924, ADR-925 | The network inventory merges devices by MAC, with address bindings that expire after two missed polls. Discovery is off by default. The extra UniFi reads (ADR-912) and the scan-result import (ADR-913) feed it. | `crates/telltale/src/discovery/inventory*.rs`, `crates/telltale/src/discovery/sources.rs`, `crates/telltale/src/discovery/store.rs`, `crates/telltale/src/devices.rs`, `ui/src/pages/NetworkInventory*.svelte`, `fuzz/fuzz_targets/inventory_merge.rs`, `docs/design/network-inventory.md` |
| discovery-workers | ADR-908, ADR-928, ADR-929, ADR-930 | SNMP and other discovery run in worker processes with a frame protocol, a debug-only fault job set, and a designated node. | `crates/telltale/src/discovery/**`, `crates/telltale-config/src/discovery.rs`, `crates/telltale/tests/discovery_workers.rs`, `fuzz/fuzz_targets/worker_frames.rs` |
| worker-seccomp | ADR-908, ADR-932, ADR-933, ADR-934 | Workers run with no capability, `no_new_privs`, a non-dumpable parent, and a seccomp filter on x86_64, aarch64 and 32-bit ARM; x32 and io_uring calls are refused. Other architectures fail closed. The systemd unit matches. | `crates/telltale-net/src/**`, `deploy/systemd/**` |
| telltale-snmp | ADR-907, ADR-908, ADR-909, ADR-911, ADR-931 | A new crate: SNMP v2c and v3 USM (AES privacy), read-only, with the `public` community only by per-subnet opt-in. | `crates/telltale-snmp/**`, `fuzz/fuzz_targets/snmp_*.rs` |
| pihole-import | ADR-939, ADR-940, ADR-941 | Pi-hole import (Teleporter export or `gravity.db`, and `dnsmasq.d`): the parse runs in a child with an empty environment; admins only; a preview plan, then one applied change. | `crates/telltale/src/pihole*.rs`, `crates/telltale/src/pihole/**`, `crates/telltale-api/src/pihole_import_api.rs`, `ui/src/lib/components/PiholeImport.svelte` |
| offline-clients | ADR-942 | `offline_days` 0 keeps the DHCP reservations' names; offline clients are not a current answer for discovery, DNS or networks. | `crates/telltale/src/devices.rs`, `crates/telltale/src/routers*.rs` |
| device-names-dns | ADR-901, ADR-902 | Device names answer in DNS (AAAA and PTR), built from the names TelltaleDNS already has, one label each; UniFi reservations and networks add naming sources. | `crates/telltale/src/device_dns.rs`, `ui/src/lib/components/DeviceNamesCard.svelte` |
| support-classify | OPS-011 | The support package classifies the fork's `[discovery]` and secret-reference fields; each new fork section must be classified. | `crates/telltale-support/src/classify.rs`, `crates/telltale/src/support.rs` |
| break-glass-loopback | ADR-944, ADR-987 | Break-glass local login is loopback-only unless `allowed_admin_networks` is set (an `Option`, so absent differs from `[]`), a proxied request is never break-glass, and `disable_local_login` hides the form and refuses it. Upstream's answer to #63 keeps the private-network default and documents it; the fork's key descriptions, `docs/running.md`, the users guide and `spec/08` say loopback, and upstream's start-up notice is not taken. | `crates/telltale/src/auth*.rs`, `crates/telltale/src/auth_setup*.rs`, `ui/src/pages/Login.svelte`, `site/guide-users.html` |
| home-assistant | M22, T22.x | The Home Assistant integration (a custom component and its tests), which upstream does not ship. | `integrations/home-assistant/**`, `.github/workflows/home-assistant.yml` |
| docker-desktop | M22 (T22.x) | A Docker Desktop bundle for trying the fork. | `deploy/docker-desktop/**` |
| milestone-renumbering | Sync 2026-11-17, ADR-986 (flagged as `numbering` by the watch, which covers spec/10 and spec/11) | Upstream's M22/M23 are M29/M28 here (2026-11-17), and upstream's M24 (T24.1, T24.2) is M30 (T30.1, T30.2) with upstream's T22.2 as T29.2 (2026-11-18), because the fork's M22 to M24 are its own. Fork tasks and ADRs use the fork's numbers. | `spec/10-roadmap-and-tasks.md`, `spec/11-decisions.md` |
| settings-kinds | ADR-914, ADR-918 | The shared settings sections (`[special]`, `[local]`, `[clients]` with mdns only): files win field by field, a request may leave out a file-set field, some fields are read-only. Bulk changes are admin-only with a typed confirmation. | `crates/telltale/src/settings_kinds*.rs` |
| problem-codes | ADR-927 | The UI maps the credential problem codes to sentences; the server's detail stays on the error. The file is the API client, shared with upstream, so an upstream change there can conflict. | `ui/src/lib/api.ts` |
| special-names | ADR-904 | iCloud Private Relay names are blocked by default (`block_icloud_private_relay`), a behaviour change for Pi-hole parity. | `crates/telltale-policy/src/special.rs` |
| lists-refresh | ADR-905, ADR-937 | `POST /api/v1/lists/refresh` (the page-wide and per-list Update now) and the Confirmed current column on the Lists page. | `crates/telltale-api/src/lists_api.rs`, `ui/src/pages/Lists.svelte` |
| shared-edits | — | The fork's edits to shared API, MCP, config schema and validation files. Upstream changes there are a conflict risk, not a deviation. | `crates/telltale-api/src/lib.rs`, `crates/telltale-api/src/mcp.rs`, `crates/telltale-api/src/config_api.rs`, `crates/telltale-config/src/schema.rs`, `crates/telltale-config/src/validate.rs` |
| dev-deploy | — | Development deployment bundles the fork keeps for local use. Upstream has none. | `deploy/dev/**` |
| fork-readme | DOC-006 | The fork block at the top of the README, above upstream's README. | `README.md` |

## Upstream issues

Every upstream issue the fork has triaged. "Fork action" is what the fork does; the upstream comment column is a link when the fork has posted one, else an em dash. Triage was read-only: nothing was posted except the #64 root-cause comment linked below.

| # | Title | Upstream | Kind | Fork affected | Fork action | Upstream comment |
|---|---|---|---|---|---|---|
| [#7](https://github.com/paimonsoror/telltaledns/issues/7) | Process deadlocks: DNS, API, metrics and cluster port stop answering while the service stays active | open, `investigating` | bug | yes | Fixed in the fork (T21.4, ADR-946): `call_one` and `gather` run their wait under `block_in_place` on a multi-thread runtime, and the async handlers route federated reads through `blocking()` (`crates/telltale-api/src/lib.rs`, `config_api.rs`). Regression tests `clu_004_*` in `crates/telltale/src/federated_wedge_tests.rs`; the first hangs without the fix. No worker floor: the Pi RSS can't be measured here and the fix doesn't need it. Mitigation (watchdog, debug files, OPS-012) is in the fork. Requirements CLU-004, OPS-012. | [root-cause comment](https://github.com/paimonsoror/telltaledns/issues/7#issuecomment-6954567842), [fix follow-up](https://github.com/paimonsoror/telltaledns/issues/7#issuecomment-6959114097) |
| [#64](https://github.com/paimonsoror/telltaledns/issues/64) | 2FA can't be enabled (pattern="[0-9]{6}" in Svelte) | closed 2026-11-18 (b334e0f) | bug | fixed in fork | None. Both sites use `pattern={"[0-9]{6}"}` (fork) and `{'[0-9]{6}'}` (upstream) alike; upstream's Playwright test and `6-markup.spec.ts` are in the fork beside `6-totp.spec.ts` (ADR-943, ADR-987). | [root-cause comment](https://github.com/paimonsoror/telltaledns/issues/64#issuecomment-6953817344) |
| [#63](https://github.com/paimonsoror/telltaledns/issues/63) | disable_local_login is ignored | open (b334e0f documents the private-network default, refs #63) | bug | fixed in fork | None. The fork's loopback default (ADR-944) is kept over upstream's documentation-only answer (ADR-987). Post the upstream comment only after the fix is verified. | [root-cause comment](https://github.com/paimonsoror/telltaledns/issues/63#issuecomment-6954567296) |
| [#65](https://github.com/paimonsoror/telltaledns/issues/65) | Clients: get names from external sources | open | enhancement | fixed in fork | None. T8.2 ([[router]] UniFi and OPNsense naming) is in the fork. Reply upstream with the config pointer once the owner agrees. | — (draft) |
| [#69](https://github.com/paimonsoror/telltaledns/issues/69) | Flaky UI e2e on the first attempt: obs_024 simulate a quick rule (again) and obs_035 wall | open | bug | yes | Upstream's cluster-test half (095b77f, the member-table wait) is in; the fork had the same fix. The two UI flakes are the fork's `feat/obs035-wall-flake` track (obs_024 was fork #11's second cause). | — |
| [#55](https://github.com/paimonsoror/telltaledns/issues/55) | Support package: collect every node's section with --cluster | closed 2026-11-18 (60f108b, ADR-172) | enhancement | fixed in fork (merged) | Merged at this sync (T30.2). The fork's `[discovery]` and secret-reference classification (support-classify) is in each node's part; check a cluster package on a fork cluster once (not run here: needs the three-node bundle). | — |
| [#58](https://github.com/paimonsoror/telltaledns/issues/58) | Query log search: add a negation option (does not contain) | closed 2026-11-18 (14b911c, 36ab36a, ADR-171) | enhancement | fixed in fork (merged) | Merged at this sync (T30.1). The fork's router-name client filter (`hostname:<label>`) negates through the same address set; the Queries page keeps both controls. Upstream's UI and API are in; MCP and federated forwarding come with the merge. | — |
| [#12](https://github.com/paimonsoror/telltaledns/issues/12) | Explore: an OpenWrt package | open | explore | yes | Track. Not blocked on x86_64, aarch64 or arm; mips and mipsel lose discovery (seccomp fails closed). | — (draft) |
| [#49](https://github.com/paimonsoror/telltaledns/issues/49) | Explore an OPNsense package (FreeBSD arm64/aarch64) | open | explore | yes | Track. DNS is not blocked; discovery would run unsandboxed without a Capsicum equivalent. | — (draft) |
| [#59](https://github.com/paimonsoror/telltaledns/issues/59) | TelltaleDNSListStale fires for inline lists 48 hours after every config edit | closed 2026-11-16 (735491a) | bug | fixed in fork | None. Test that inline lists show no last-success time (optional). | — |
| [#57](https://github.com/paimonsoror/telltaledns/issues/57) | Quick rules: add an Edit option | closed 2026-11-16 (fb4b9f6, FLT-005) | enhancement | fixed in fork | None. | — |
| [#56](https://github.com/paimonsoror/telltaledns/issues/56) | Lists: allow more characters in a list's name | closed (wontfix: a list name is a stable ID) | enhancement | n/a | None. The importer maps Pi-hole list names into the ID charset (T24.6, T24.18). | — |
| [#50](https://github.com/paimonsoror/telltaledns/issues/50) | Support package: export a redacted diagnostics bundle | closed 2026-11-16 (aa42fc0, 175bccf, 53d8204) | enhancement | fixed in fork | None. The fork classifies `[discovery]` (8ffed02). | — |
| [#43](https://github.com/paimonsoror/telltaledns/issues/43) | A replica attached to another replica never moves back; blob fetches get 404 | closed 2026-11-17 (7942dcd, d384448) | bug | fixed in fork | None. A cluster test for a replicated secrets blob from the primary is worth adding (CLU-015). | — |
| [#39](https://github.com/paimonsoror/telltaledns/issues/39) | Flaky e2e obs_033: a note added just after the minute turns | closed 2026-11-17 (5bda419) | bug | fixed in fork | None. | — |
| [#38](https://github.com/paimonsoror/telltaledns/issues/38) | Anomalies: mute a finding kind for one device | closed 2026-11-16 (23bc211) | enhancement | fixed in fork | None. | — |
| [#35](https://github.com/paimonsoror/telltaledns/issues/35) | A group with one upstream SERVFAILs any name slower than about 3x EWMA | closed 2026-11-16 (706feb6, UPS-006) | bug | fixed in fork | None. | — |
| [#30](https://github.com/paimonsoror/telltaledns/issues/30) | Top clients: show each device's queries split by status | closed 2026-11-16 (da5f99d, ce80a79, e733821) | enhancement | fixed in fork | None. | — |
| [#11](https://github.com/paimonsoror/telltaledns/issues/11) | Flaky UI e2e tests: obs_026 traffic map and obs_024 simulate a quick rule | closed 2026-11-15 (372d672) | bug | yes | Track obs_024 separately: it failed in 2 of about 25 runs with simulated count 0 (a different cause). Reproduce alone and after obs_022; if it is the qlog flush lag, poll the result or lower `flush_interval_secs` in `ui/tests/e2e/server.mjs`. Branch `fix/obs-024-flake`. | — (draft) |
| [#9](https://github.com/paimonsoror/telltaledns/issues/9) | UI: relabel circuit-breaker states in plain language | closed 2026-11-15 (cd699d1) | enhancement | fixed in fork | None. | — |
| [#6](https://github.com/paimonsoror/telltaledns/issues/6) | Top clients ignores router, mDNS and peer device names | closed 2026-11-14 (2e0df1d, CLU-002) | bug | fixed in fork | None. Worth a test that a discovery name reaches Top clients. | — |
| [#5](https://github.com/paimonsoror/telltaledns/issues/5) | No way to remove a node from the cluster | closed 2026-11-15 (d7e9f39) | bug | fixed in fork | None. | — |
| [#4](https://github.com/paimonsoror/telltaledns/issues/4) | A replica that loses the primary never dials the primary again | closed 2026-11-15 (86d94f8, 1016641, d384448) | bug | fixed in fork | None. | — |
| [#3](https://github.com/paimonsoror/telltaledns/issues/3) | Git-managed controller never takes over from an emergency primary | closed 2026-11-14 (cc61231, CLU-005) | bug | fixed in fork | None. | — |
| [#2](https://github.com/paimonsoror/telltaledns/issues/2) | alsoServe.cluster drops the cluster port when the LB is announced from a node without the controller | closed 2026-11-14 (00971de, OPS-003) | bug | fixed in fork | None. | — |

The fork's merge check for the closed-and-fixed rows was mechanical: every added line of each fix commit is still in the fork's file. `#59`, `#43` and `#6` sit next to heavy fork edits and are the best candidates for a closer read.

## Upstream pull requests

Open upstream PRs that touch a fork deviation, and what the fork does with them at the next sync.

| PR | Title | Touches | Fork plan | Upstream comment |
|---|---|---|---|---|
| [#66](https://github.com/paimonsoror/telltaledns/pull/66) | feat(routers): add and change routers in the UI, keys pasted and saved as files (ADR-171) | routers, secrets, managed kinds, agent scopes | The fork already ships this with a different design (ADR-903/917/919/921/922). If it merges as is: keep the fork's side in `routers.rs`, the router hunks of `api_backend.rs`, `server.rs`, `auth/agent.rs` (no `config:write:routers`), `managed.rs`, `forward.rs`, `config_api.rs`, `lib.rs`, `ConfigEditor.svelte`, `Clients.svelte`, OpenAPI and `api.ts`; keep ADR-171 verbatim with a fork ADR that supersedes it for the fork; adopt a binary-level e2e like `deploy/routers-ui-e2e.sh`, rewritten for `*_ref`. | [review](https://github.com/paimonsoror/telltaledns/pull/66#issuecomment-6960942714): API file paths can send any readable file to the router URL, a URL change reuses the saved key, write order, delete scope, keys lost on failover |
| [#67](https://github.com/paimonsoror/telltaledns/pull/67) | Feat/Unraid template | `deploy/unraid/**`, `docs/running.md`, `site/start.html` | No deviation path. Take it as is when it merges; check the template's ports and image name against the fork's image and Docker Desktop bundle. | — |
| [#68](https://github.com/paimonsoror/telltaledns/pull/68) | Feat/mikrotik router | routers, secrets, managed kinds, agent scopes, `config_api.rs`, `lib.rs`, `schema.rs`, `validate.rs` | Same family as #66: the fork's `[[router]]` design (ADR-903/917/919/921/922) wins in `routers.rs`, `router_secrets.rs`, `managed.rs`, `forward.rs`, `config_api.rs` and the shared files. A MikroTik source itself is worth taking as a router kind, rewritten for `*_ref`. | — |
| [#70](https://github.com/paimonsoror/telltaledns/pull/70) | fix(helm): only alert on lists that are failing, not merely old [FLT-004] | `deploy/helm/templates/monitoring.yaml`, `deploy/helm/tests/alerts.test.yml`, `docs/running.md` | No deviation path. Take it when it merges. | — |

## Watch

The workflow `.github/workflows/upstream-watch.yml` runs daily at 06:23 UTC and on demand, with the GitHub token only (`contents: read`, `issues: write`). It runs `.github/scripts/upstream_watch.py` from the fork's `feat/ipam-integrations` checkout. The workflow file is read from `main`, but the script and the ledger come from `feat/ipam-integrations`, so both branches need them. If the script is missing from `feat/ipam-integrations`, the job stops at a check step that says so. The checkout is pinned to a commit SHA and does not keep its token, and the script is retried up to three times.

What it does:

1. Fetches upstream `main` by URL (no remote is added) and reads the `upstream-synced:` line above.
2. Checks that the synced SHA is an ancestor of upstream `main`. If it is not (upstream rewrote its history, or the SHA is unknown), the report warns, lists no commits and still runs the trial merge.
3. Lists upstream commits since that SHA. A commit is flagged when a changed file matches a `deviations` glob, when it touches `spec/10` or `spec/11` (task and ADR number collisions), or when it touches `Cargo.toml`, `Cargo.lock` or `Dockerfile` (the image gate). Paths are read NUL-separated, so names with spaces or non-ASCII characters still match.
4. Trial-merges upstream into a scratch worktree without committing, then removes the worktree. Conflicted paths are listed. A merge that fails without conflicts (unrelated histories, a bad object) fails the run with the git error instead of reporting no conflicts.
5. Lists upstream issues updated in the last 7 days that are not in the `triaged` block, or whose `updated_at` differs from it.
6. Writes one markdown report to the fork issue titled **Upstream watch** (label `upstream`, created if missing). Only an issue with that title opened by the bot (`github-actions`) is used, so a same-titled issue from anyone else is ignored. Each table lists at most 100 rows, and the body stays under GitHub's size limit. Upstream titles and commit subjects are shortened and escaped, so they cannot mention users, link, or write the hash marker.
7. The hash of the report is the first line of the issue body (`<!-- watch-hash: ... -->`). When it changes, the workflow posts a comment first and then edits the body; a closed issue is reopened. An unchanged report refreshes only the "Last checked" line and sends no notification.

Known behaviour:

- The window is 7 days. An issue that ages out of it changes the report once, which posts one "0 new/changed issues" comment. Any comment on an upstream issue bumps its `updated_at`, so the issue is listed as changed again until it is triaged. Both are accepted; the `triaged` block is the fix.
- The numbering check follows ADR-906 (spec/11). Its proposed amendment, which would also cover requirement prefixes and milestone numbers, is not accepted yet.

What to do with the report:

- A **flagged** commit: read the deviation it names before the next sync. A deviation path changed upstream means a conflict is likely; plan the merge on `feat/upstream-sync`.
- A **conflict**: resolve it on `feat/upstream-sync`, keeping the deviation. Do not merge a conflicted path with upstream's side only.
- A **numbering** flag: upstream added a task or ADR number that the fork may also use. Rename the fork's, as in the 2026-11-17 merge, and note it in the merge message.
- An **image-gate** flag: run `deploy/image/size.py` on the sync branch and record the delta.
- A **new or changed issue**: triage it. Add it to the Upstream issues table and the `triaged` block below, with the `updated_at` that was seen. Fix it in the fork if the fork has the same bug, and comment upstream only when the fix is verified or the owner asks.
- A **warning** that the ledger SHA is not an ancestor: upstream's history was rewritten. Check the upstream history by hand, then set `upstream-synced:` to the SHA the fork really merged.
- After a sync or a triage, update the ledger in the same branch, so the next report is quiet.

Run it locally, read-only:

```bash
python .github/scripts/upstream_watch.py --dry-run
```

`--dry-run` prints the report and the intended issue action. It fetches upstream into the local object store, adds a temporary worktree for the trial merge (removed afterwards), and reads the fork issue. It writes nothing to GitHub and does not change the branch.

## Machine-readable blocks

The watch reads these. One deviation per line: `name<TAB>comma-separated globs`, relative to the repo root. One triaged issue per line: `number<TAB>updated_at`, as upstream reported it at triage.

```deviations
image-gate	Dockerfile,deploy/image/**,.github/workflows/image.yml,Cargo.toml,Cargo.lock
secrets-store	crates/telltale/src/secrets*,crates/telltale/src/secrets/**,crates/telltale/src/secret_store_tests.rs,crates/telltale-api/src/secrets*,ui/src/**/Secret*,crates/telltale-config/src/secret_refs.rs,crates/telltale-config/src/credentials.rs,crates/telltale-store/src/state/secrets.rs,crates/telltale/src/credential_rules*.rs,crates/telltale/src/credential_tests.rs,crates/telltale/src/redact.rs,crates/telltale/tests/secrets_cluster.rs,deploy/helm/telltale/templates/secrets-key.yaml,deploy/helm/telltale/templates/cluster-secret.yaml,deploy/helm/secrets-key-test.sh,docs/secrets.md
routers	crates/telltale/src/routers*.rs,crates/telltale/src/router_*.rs,ui/src/**/Routers*,crates/telltale-api/src/routers_api.rs,crates/telltale-upstream/src/router.rs,crates/telltale-upstream/tests/router.rs,ui/src/pages/Networks.svelte
inventory-merge	crates/telltale/src/discovery/inventory*.rs,crates/telltale/src/discovery/sources.rs,crates/telltale/src/discovery/store.rs,crates/telltale/src/devices.rs,ui/src/pages/NetworkInventory*.svelte,fuzz/fuzz_targets/inventory_merge.rs,docs/design/network-inventory.md
discovery-workers	crates/telltale/src/discovery/**,crates/telltale-config/src/discovery.rs,crates/telltale/tests/discovery_workers.rs,fuzz/fuzz_targets/worker_frames.rs
worker-seccomp	crates/telltale-net/src/**,deploy/systemd/**
telltale-snmp	crates/telltale-snmp/**,fuzz/fuzz_targets/snmp_*.rs
pihole-import	crates/telltale/src/pihole*.rs,crates/telltale/src/pihole/**,crates/telltale-api/src/pihole_import_api.rs,ui/src/lib/components/PiholeImport.svelte
offline-clients	crates/telltale/src/devices.rs,crates/telltale/src/routers*.rs
device-names-dns	crates/telltale/src/device_dns.rs,ui/src/lib/components/DeviceNamesCard.svelte
support-classify	crates/telltale-support/src/classify.rs,crates/telltale/src/support.rs
break-glass-loopback	crates/telltale/src/auth*.rs,crates/telltale/src/auth_setup*.rs,ui/src/pages/Login.svelte,site/guide-users.html
home-assistant	integrations/home-assistant/**,.github/workflows/home-assistant.yml
docker-desktop	deploy/docker-desktop/**
settings-kinds	crates/telltale/src/settings_kinds*.rs
problem-codes	ui/src/lib/api.ts
special-names	crates/telltale-policy/src/special.rs
lists-refresh	crates/telltale-api/src/lists_api.rs,ui/src/pages/Lists.svelte
shared-edits	crates/telltale-api/src/lib.rs,crates/telltale-api/src/mcp.rs,crates/telltale-api/src/config_api.rs,crates/telltale-config/src/schema.rs,crates/telltale-config/src/validate.rs
dev-deploy	deploy/dev/**
fork-readme	README.md
```

```triaged
2	2026-11-15T04:03:00Z
3	2026-11-15T04:03:00Z
4	2026-11-15T00:15:39Z
5	2026-11-15T04:03:01Z
6	2026-11-14T21:39:57Z
7	2026-11-17T19:50:06Z
9	2026-11-15T02:06:50Z
11	2026-11-15T15:45:32Z
12	2026-11-15T00:20:10Z
30	2026-11-16T03:07:22Z
35	2026-11-16T21:34:22Z
38	2026-11-16T12:47:41Z
39	2026-11-17T02:09:29Z
43	2026-11-17T02:42:24Z
49	2026-11-15T15:43:39Z
50	2026-11-16T12:47:42Z
55	2026-11-18T02:42:04Z
56	2026-11-16T13:02:55Z
57	2026-11-16T13:36:48Z
58	2026-11-18T01:53:51Z
59	2026-11-16T21:34:23Z
63	2026-11-18T01:54:15Z
64	2026-11-18T01:54:00Z
65	2026-11-18T02:42:20Z
69	2026-11-18T12:05:15Z
```
