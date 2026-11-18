# 11 — Architecture Decision Records

Format: Context → Decision → Consequences. New ADRs append here (`ADR-0NN`). The owner accepted every ADR proposed through ADR-096 on 2026-10-07; new ones start as Proposed. An agent must not contradict an accepted ADR without adding a superseding ADR and flagging it to the owner.

ADR numbers from 901 up belong to this fork (nbacheller/telltaledns); lower numbers follow upstream (paimonsoror/telltaledns).

## ADR-001 — Language: Rust (Accepted)
**Context:** Performance and footprint are paramount: a small, steady memory footprint on a Raspberry Pi and microsecond cache hits. That rules out garbage-collection pauses and runtime memory overhead, and we want memory safety at the same time.
**Decision:** Rust (stable, 2024 edition), tokio, rustls (ring or aws-lc-rs backend), quinn.
**Consequences:** No GC, static musl binaries, memory safety, and a mature DNS crate ecosystem (hickory). Compile times are slower and the contributor pool is smaller. `unsafe` is confined to `telltale-net`.

## ADR-002 — Custom hot-path wire handling; hickory for the long tail (Accepted)
**Context:** Full decode/encode per query costs allocations and µs. Cache hits only need the header, question, and TTL offsets.
**Decision:** `telltale-proto` handles the hot path zero-copy. `hickory-proto` is used for DNSSEC, zone files, and complex record handling.
**Consequences:** Two code paths, so cross-checking them against each other is part of fuzzing (differential fuzz: both parsers must agree on header, question, and EDNS).

## ADR-003 — FST + regex DFA snapshots, compiled off-path (Accepted)
**Context:** Pi-hole keeps lists in SQLite with a verdict cache, and Technitium keeps them as in-memory zones; both suit their designs. TelltaleDNS's goals (multi-million-name lists on a Pi, lookup cost independent of list size, no pause during updates) call for a compiled index.
**Decision:** Immutable, mmappable FST snapshots (reversed-label keys) + a multi-pattern lazy DFA, built in the background and swapped atomically.
**Consequences:** ~10× less memory per domain, O(|qname|) lookups, and instant reloads. Snapshots are immutable, so every edit triggers a recompile. To keep manual rule edits instant, a small **overlay** (a HashMap of manual rules) is consulted before the FST and folded into the next compile.
**Amendment (2026-10-07, review 02-07; owner's answer: remove):** the overlay was never used. Quick rules (ADR-067, `telltale-policy::quick`) are what make manual rule edits instant: they decide before the lists, and the matcher no longer has an overlay (no code constructed one outside tests). Rule edits that belong in a list are list edits, which recompile in the background. The paragraph above is kept as the record of what was first decided.

## ADR-004 — Container-first distribution, Kubernetes-first operations (Accepted)
**Context:** The owner prioritizes Kubernetes and also runs a Raspberry Pi. Native packaging and installers per distro are costly to build and keep working.
**Decision:** Tier-1 artifacts are the multi-arch OCI image + Helm chart, and the same image runs on the Pi with host networking. The static binary + systemd unit is Tier 2.
**Consequences:** One artifact to test. The Pi needs Docker/Podman (~50 MB extra), which is acceptable on Pi 3+. A Pi Zero can use the native binary.

## ADR-005 — Clustering: fenced primary/replica with optional witness, not Raft-by-default (Accepted)
**Context:** The reference topology has exactly two nodes (Pi + k8s). Raft needs 3 voters to tolerate one failure. DNS must never depend on consensus.
**Decision:** A replicated, signed change log from a single primary. Epoch-based fencing. Promotion is manual (2 nodes), witness-assisted, or quorum (≥ 3). Data-plane independence (CLU-004).
**Consequences:**
- Config writes pause during a primary outage in manual mode (DNS is unaffected).
- Orphaned writes are possible and surfaced, never silently merged.
- Much simpler than embedding openraft, and correct for 2 nodes.
- Revisit (ADR-0NN) if multi-writer is ever needed.

## ADR-006 — Telemetry: custom columnar segments + SQLite rollups (Accepted)
**Context:** Pi-hole keeps long-term history in SQLite, and Technitium hands per-query logs to database apps. TelltaleDNS wants 30-day searches in seconds on a Pi with no external database, and DuckDB/ClickHouse are too large for a Pi.
**Decision:** Hourly columnar segments with dictionary encoding, a block index + bloom filters, and zstd, plus SQLite rollups. Parquet export for external analysis.
**Consequences:** We own a storage format (versioned, fuzzed, with a migration tool). Search is fast via dictionary-first predicate evaluation. External SQL access goes through export or the API, not live SQL.

## ADR-007 — Plugins out-of-process (socket/exec) first, WASM later (Accepted)
**Context:** The owner needs custom upstreams. A plugin loaded into the resolver's process would share its memory and its fate: a crash or a leak there takes DNS down.
**Decision:** DNS-wire-over-socket plugins for upstreams in v1, with WASM (wasmtime, feature-gated) in v2.
**Consequences:** Plugin crashes can't take down DNS, there is a small IPC latency cost (~20–50 µs), and plugins can be written in any language.

## ADR-008 — Auth: local users + OIDC; no LDAP (Accepted)
**Context:** The owner requires basic auth and OIDC, and explicitly skips LDAP.
**Decision:** Local Argon2id users (session login + opt-in HTTP Basic for API/scrapers + tokens + TOTP) and OIDC (PKCE) with claim → role mapping, both P0.
**Consequences:** Smaller attack surface. LDAP users bridge through an OIDC IdP.

## ADR-010 — Agents as first-class clients via built-in MCP (Accepted)
**Context:** The owner expects agents to manage the platform and run analytics.
**Decision:**
- MCP tools are thin wrappers over the REST service layer, so the tool and API schemas come from one source.
- Agents get dedicated, scoped, read-only-by-default tokens.
- Writes use plan/apply with optional human approval.
- Every node exposes `/mcp`, so agents get the single management plane too.

**Consequences:** No separate logic to keep in sync. Agent writes are always previewable and attributable. The plan store adds a small table replicated with config.

## ADR-009 — UI: Svelte + uPlot embedded (Accepted)
**Decision:** A small SPA compiled to static assets and embedded via `rust-embed`. No Node runtime in the product.
**Consequences:** One binary. The UI build is part of CI (Node only at build time).

## ADR-011 — Project name and identifiers: TelltaleDNS (Accepted)
**Context:** "Vigil" was a working name and collides with an existing Rust project (a status-page monitor). The owner chose **TelltaleDNS** on 2026-10-02. A telltale shows what the wind is doing; DNS shows what the network is doing, which matches the observability-first mission.
**Decision:** The brand is `TelltaleDNS`. Machine identifiers use the short form `telltale`:
- binary/CLI `telltale`, crate prefix `telltale-*`, env vars `TELLTALE_*`
- paths `/var/lib/telltale` and `/etc/telltale`, config file `telltale.toml`
- Helm chart and image `telltale`, metrics prefix `telltale_`, backup archives `.ttbk`

Workspace crates set `publish = false`, so the short prefix can't collide on crates.io.
**Consequences:** Short, typeable identifiers. If crates are ever published or the registry name is taken, switch the published names to `telltaledns-*` without renaming internal crates. *Owner to confirm:* short `telltale` form vs. `telltaledns` everywhere.

## ADR-012 — Project site: hand-written static HTML + inline SVG on GitHub Pages (Accepted)
**Context:** The owner wants a GitHub Pages site for two audiences (non-technical and deeply technical), visual-first, including a standards page with diagrams per RFC (DOC-001..006). The project values a lightweight footprint and minimal tooling.
**Decision:**
- A `site/` directory of plain HTML pages, one shared CSS file, and inline SVG diagrams (hand-authored, or exported from Mermaid/Excalidraw sources committed beside them). No site generator and no Node build.
- A tiny optional JS file only for the theme toggle and tabs; every page works without it.
- The Standards page table is generated from `site/data/standards.json` at deploy time by a small script in the Pages workflow, which also fails if a ticked roadmap task cites an RFC missing from the file.
- Deployed by a GitHub Actions Pages workflow on push to `main`.

**Consequences:** Zero build dependencies and fast pages. The shared header/footer is duplicated across pages (acceptable at ~10 pages; revisit with a minimal generator past ~20). Pages must be enabled once in the repo settings (source: GitHub Actions).


**Addendum (2026-10-05, T6.10, Proposed):**
- **Navigation:** the header keeps five main pages. The reference pages (Configuration, Glossary, Standards, For nerds) go in one "Reference" menu. GitHub and the theme are icon buttons. Below 860 px the nav folds into a ☰ menu. The menu is built on `<details>`, so it works without JS; `site.js` only closes the ☰ menu on narrow screens and the Reference menu on Escape or an outside click. This replaces the wrapping row of nine links.
- **For nerds page (`nerds.html`):** generated from `site/data/architecture.json`. The build checks it against the repo and fails on any disagreement, and CI runs that check (`site/build.py --check`). The checks:
  - every crate under `crates/` is described, and nothing else is;
  - the listed public types exist in their crate;
  - ADR and requirement IDs exist in `spec/11`, `spec/01` and `spec/13`;
  - `code` paths exist;
  - stack entries name real dependencies.
- **Read from the repo, not the JSON:**
  - dependency arrows ("uses" and "used by") from the crates' `Cargo.toml` files;
  - line counts;
  - the budgets, from `spec/00` §5.
- **Interaction:** the map's crates are plain links to their descriptions further down. `assets/nerds.js` adds the side panel and edge highlighting.
- **Pages deploys:** they now also run on `crates/**`, `spec/**` and `Cargo.toml` changes, so the line counts and arrows stay current.
- **Contrast:** small accent-coloured text (section eyebrows) uses `--accent-text` (5.2:1) in the light theme.
## ADR-013 — Hedged upstream attempts and a faster breaker trip (Accepted)
**Context:** `spec/04` §4–5 retries the next upstream only after an attempt fails or times out (up to 400 ms), and opens a breaker only after ≥ 10 samples with > 50% errors. With one dead upstream that makes the first ~10 queries, and every exploration or half-open probe, wait a full timeout. That breaks T1.5's chaos criterion (p99 within 1.5× of healthy).
**Decision:**
- **Hedging:** if an attempt hasn't answered within its upstream's hedge delay (≈ 3 × EWMA + 10 ms, bounded to [20 ms, attempt timeout]; 100 ms before there is data), the next member starts in parallel. The first good answer wins.
- **Must-hedge cases:** exploration picks (`fastest` ε), half-open probes, members whose last attempt failed, and last-resort unhealthy members all start immediately alongside the next member, so they never add client latency.
- **Losers finish in the background** (detached, not aborted), so their real outcome (often a timeout) reaches the health tracker.
- **Breaker:** 3 consecutive failures also open it (in addition to the window rule).

**Consequences:** Measured in-process (debug build), one blackholed upstream out of two: 0 failures and p99 1.04–1.15× of baseline for failover, round_robin, fastest, and parallel. The cost is a few extra upstream queries while a member is degraded, and detached attempts holding a socket for up to one attempt timeout.

## ADR-014 — Access, rate-limit, and special-name defaults (Accepted)
**Context:** DNS-014, DNS-019, `spec/03` §3 step 4, and `spec/08` §6 name these behaviors but leave several defaults open.
**Decision:**
- **Access:** queries from outside `[access] allowed_networks` get REFUSED + EDE 18. The default list is RFC 1918, 100.64/10 (CGNAT, Tailscale), 169.254/16, 127/8, fc00::/7, fe80::/10, and ::1. Pod/service CIDR auto-detection waits for the Helm work (T4.1). Allowing `0.0.0.0/0` triggers a startup warning.
- **Rate limit:** token bucket of 1000 queries per 60 s per client (Pi-hole parity), with REFUSED + EDE 18 by default (or drop). IPv4 clients are counted per /32, IPv6 per /64 (a device's rotating privacy addresses share a bucket). Loopback is exempt.
- **Special names:**
  - `localhost`/`*.localhost` → 127.0.0.1 / ::1, authoritative (RFC 6761 §6.3).
  - `*.invalid` → NXDOMAIN (RFC 6761 §6.4).
  - `use-application-dns.net` → NXDOMAIN (Firefox DoH canary).
  - All CHAOS-class queries → REFUSED.
  - Reverse lookups for private ranges → NXDOMAIN unless a local record or an explicit `[[route]]` covers them (RFC 6303; Pi-hole `bogus-priv`).
  - `.local` is **not** intercepted, because many AD domains use it; mDNS names never reach unicast DNS anyway.

**Consequences:** Safe by default on a home network. Users exposing TelltaleDNS beyond RFC 1918 must widen `allowed_networks` deliberately. Each special-name rule can be turned off under `[special]`.

## ADR-015 — Image build, allocator tuning, and port 53 for non-root host networking (Accepted)
**Context:** OPS-001 and `spec/08` §2 require a static musl image that runs as 65532. T0.4 turned up three things the spec leaves open:
1. Compiling arm64/armv7 under QEMU with fat LTO takes hours on CI runners.
2. musl's allocator roughly halved cache-hit throughput in the bench harness (≈100–125k vs ≈190–210k qps for glibc). With mimalloc, transparent huge pages (THP; `madvise` mode on WSL and many distros) raised idle RSS from ≈6 MiB to ≈22 MiB, over the 20 MiB gate.
3. Docker doesn't give added capabilities to a non-root user (no ambient capabilities). The `spec/08` §3 Pi compose example (`network_mode: host` + `user: 65532` + `cap_add: [NET_BIND_SERVICE]`) therefore gets `EACCES` binding :53. With bridge networking, Docker sets `net.ipv4.ip_unprivileged_port_start=0` inside the container, so :53 works there with every capability dropped. Kubernetes pods get the same with containerd ≥ 2.0, or with the safe sysctl `net.ipv4.ip_unprivileged_port_start` in the pod securityContext.

**Decision:**
- The build stage runs on `$BUILDPLATFORM` and cross-compiles with `cargo zigbuild` (pinned zig 0.15.2 and cargo-zigbuild 0.23.4, checksums verified). Only the smoke test runs under QEMU.
- `mimalloc` is the global allocator (as `02` §3 already says), built with `no_thp`.
- The image keeps `USER 65532:65532`, with no file capabilities: file caps break exec when the capability is dropped and are ignored under `no_new_privs` (`allowPrivilegeEscalation: false`). For host networking on a Pi, the docs recommend the host sysctl `net.ipv4.ip_unprivileged_port_start=53` (one line in `/etc/sysctl.d/`), which keeps the container non-root. The fallback is `user: "0:0"` with `cap_drop: [ALL]` + `cap_add: [NET_BIND_SERVICE]`. The Helm chart (T4.1) sets the pod sysctl.

**Consequences:** CI image builds take minutes, not hours. musl matches glibc throughput, and idle RSS stays ≈6 MiB. The `spec/08` §3 compose example must change before the compose bundle ships (T4.3); the owner chooses between the sysctl and the root-with-one-capability fallback as the documented default.

## ADR-016 — List fetcher behavior and configuration (Accepted)
**Context:** FLT-004 and `spec/05` §3.4 step 1 define the fetcher's duties (conditional GETs, size caps, retries, stored sources) but not its configuration, scheduling, name resolution, or edge cases. T2.1 needed answers.

**Decision:**
- **Config:** `[[list]]` entries with a stable `name` (`[a-z0-9_-]{1,64}`, used in file names, metrics, and the API) and exactly one source: `url` (https; http allowed with a warning), `path`, or inline `rules`. Plus `kind` (`block`/`allow`), `match` (`subtree`/`exact`, FLT-002), `enabled`, and per-list `refresh_secs`/`max_bytes`. `[filter]` holds the defaults: refresh 24 h (minimum 15 min), concurrency 4, 120 s per attempt, 3 retries, 64 MiB. At most 1024 lists (the `05` §3.1 bitset width).
- **Location:** the fetcher lives in `telltale-filter::fetch` and runs only on `all`/`controller` nodes, starting after the DNS listeners are bound. HTTP/1.1 over rustls with the built-in Mozilla roots, one connection per download, `Accept-Encoding: identity` so the size cap is exact.
- **Retries:** network errors, timeouts, 5xx, 408, and 429 are retried with 2 s × 4ⁿ backoff (±25% jitter, capped at 60 s); other 4xx, oversize bodies, and bad redirects are not. Between refreshes, a failing list is retried after 5 min, doubling to 1 h (never later than its normal refresh).
- **Sanity:** an empty body or an HTML page (`<!doctype html`/`<html` at the start) counts as a failure, so captive portals and error pages served with 200 never replace a good list. Identical content (same BLAKE3) is "unchanged" even without validators.
- **Storage:** `lists/<name>.src.zst` (zstd level 3) plus `<name>.meta.json`, each written to a temp file and renamed into place. Inline rules are stored too, so the compiler and explain treat every source the same. Lists removed from the config are deleted; disabled lists keep their files.
- **Name resolution:** the system resolvers minus our own listeners (as UPS-009), falling back to the OS resolver, which may be TelltaleDNS itself. A download is an HTTP client, not a forwarder, so this can't loop.
- **Change signal:** a `watch` counter bumps only when stored content changes or a list is removed. The compiler (T2.3) subscribes to it.

**Consequences:** One small request per list per day once lists are cached. A broken upstream list or a captive portal never empties a blocklist. Gzip transfer and per-list custom headers/auth are left for later (P1) if users need them.

## ADR-017 — List parsing rules and synthetic golden fixtures (Accepted)
**Context:** FLT-001 and `spec/05` §2 list the syntaxes, but not how to tell them apart line by line or what to do with near-misses. `spec/09` §1 asks for golden tests on vendored copies of StevenBlack, HaGeZi Pro, OISD small, an AdGuard DNS filter, and Pi-hole regex samples. Several of those are GPL-licensed data (HaGeZi, AdGuard), which shouldn't be committed into an Apache-2.0/MIT repository.

**Decision:**
- **Per-line detection,** in order: blank/comment → cosmetic/HTML (`##`, `#@#`, `#?#`, `#$#`, `#%#`, `$$`, unsupported) → hosts (first token is an IP, zone IDs allowed) → AdBlock (`@@`, `|`, `||`, `/regex/`, or `name^[$mods]`) → Pi-hole regex (any regex metacharacter, `;querytype=`, `;invert`) → `*.name`/`.name` → plain name. Inline ` # comments` are stripped outside AdBlock lines.
- **Semantics for open cases:** `name^` without `||` = `||name^` (subtree). Leading `.name` = subdomains only, like `*.name` (the narrower reading of AdBlock's suffix match). In an allow-kind list, every non-exception rule allows. Explicit AdBlock anchors (`||`, `|`) beat the list's `match` mode.
- **Unsupported, not invalid** (counted, skipped): cosmetic rules, URL paths and `/regex/` containing `/`, wildcards inside names, IP rules (`||192.0.2.1^`, which belong to the response IP filter, FLT-015), unknown modifiers, and Pi-hole `;reply=`. A rule with any unsupported modifier is skipped entirely, never applied without it.
- **Invalid:** malformed names (empty or long labels, characters outside `[a-z0-9_-]` after IDNA), unknown query types, empty `$client`, negated `$denyallow`, `$denyallow` on allow rules, regexes that `regex-syntax` rejects (including backreferences and lookaround), and regexes over 1024 characters. Hyphens at label edges are accepted (DNS allows them).
- **Fixtures:** the committed golden fixtures are synthetic files that reproduce each format's real shape (headers, boilerplate, modifiers, malformed lines). The real lists are exercised by an ignored, network-dependent test (`tests/lists_online.rs`) that requires < 0.1% invalid lines; it currently reports 0 invalid lines on StevenBlack, HaGeZi Pro (adblock, wildcard, domains), OISD (small, big) and the AdGuard DNS filter.

**Consequences:** Real lists parse without spurious errors, and browser-only rules never widen DNS blocking. The golden tests stay license-clean. Real-list drift is caught by the online test rather than by snapshot diffs.

## ADR-018 — Filter snapshot layout and compile scheduling (Accepted)
**Context:** `spec/05` §3 describes FSTs with list bitsets, and `spec/02` §5 names per-group blobs (`filter-<group>.fst`, `regex-<set>.dfa`, `rules.idx`). T2.3 needed a concrete on-disk layout, a way to handle `*.name` scope and the four precedence tiers, a rule for when to compile, and an answer for mmap, which needs `unsafe` that only `telltale-net` may contain.

**Decision:**
- **Layout** (`snapshots/<version>/`): `subtree-<n>.fst`, `exact-<n>.fst`, `subdomains-<n>.fst` (reversed-label keys → list-set index), with one shard per compile thread recorded as `fst_shards` in the manifest. A key's shard is FNV-1a of its first two reversed labels (`com.example.`), so every suffix of a query name with two or more labels is in one shard, and a lookup reads at most two shards per scope; `listsets.bin`, interned entries of four list bitsets each (important-allow, important-block, allow, block), so one lookup yields every tier's lists and a group check is a bitset AND (§3.1); `modrules.fst` + `modrules.json` (§3.3); `regex.json` (patterns + metadata); `manifest.json` with list IDs, list options, source hashes, and the BLAKE3 + size of every blob. Group selection happens at query time through the bitsets, so there are no per-group blobs: one snapshot serves every group.
- **Regex:** patterns are stored, not serialized DFAs, and compile-checked at compile time with the same engine settings the matcher uses (case-insensitive, linear time). Resolvers build the regex set when loading; whether that fits the 500 ms cold-start budget gets measured in T2.4/T5.3.
- **Loading:** `Snapshot::open` reads blobs into memory and verifies each against the manifest. An mmap loader (a small safe wrapper in `telltale-net`) can replace it in T2.4 if RSS with large lists needs it.
- **When to compile:** at startup, when stored list content changes, and on reload when the enabled lists or their `kind`/`match` change, debounced by 2 s. It's skipped when the newest manifest already matches the inputs, and when no list has been downloaded yet. A failed compile keeps the previous snapshot. The 3 newest snapshots are kept.
- **CPU and memory:** compile threads run at nice 10 (set through `telltale_net::lower_thread_priority`), on a dedicated thread rather than tokio's blocking pool. With more than one thread, large lists are cut into line-aligned chunks for parallel parsing, and each worker builds one FST shard. `[filter] compile_threads` defaults to `0` = half the cores, between 1 and 4 (2 on a Pi 4). **This changes `spec/05` §3.4's "default 1 on Pi"**, because one Pi core can't meet the `00` §5 gate. `compile_memory` (128 MiB) bounds the sort before spilling.

**Consequences:** One snapshot format for every group and node, and only content-changed blobs ship in cluster sync. Measured on the owner's **Raspberry Pi 4** (4 GB, Cortex-A72 1.5 GHz; production Technitium running alongside, compile at nice 10), names from HaGeZi TIF: 2M names in 11.6 s on 1 thread, **6.4 s on 2** (gate ≤ 8 s met), and 4.7 s on 3, at 8.2–9.1 B/name; 1.5M names in 8.6 / 6.2 / 3.7 s. Peak RSS while compiling was 136–204 MiB. Sharding costs about 0.5 B/name per extra thread (still ≤ 10 B/name at 4 threads), and one thread writes one FST per scope, so it loses nothing. Whether compiling on 2 threads at nice 10 disturbs query latency on a Pi is T2.7's acceptance test.

## ADR-019 — Deterministic device anomaly detection (Accepted)
**Context:** The owner wants TelltaleDNS to notice when a device behaves differently: abnormal traffic, many queries to one domain, or IoT/appliance phone-homes, in a safe and deterministic way. OBS-009 already lists per-client rate anomalies, first-seen domains, NXDOMAIN storms, DGA scoring, and beaconing (P2), but has no per-domain volume, no drift baseline, and no rules on determinism, explainability, or acting on findings.

**Decision:** Add OBS-013 (P1) and `06` §7.1. Detection uses fixed-math streaming statistics (EWMA, MAD, Space-Saving top-K, cuckoo filters, inter-arrival histograms), timed by event timestamps so replays are reproducible. Every finding carries its evidence. A device must pass a learning period before it can alert. State is bounded and lives in the aggregator, off the query path. Findings only inform: alerts, UI, and MCP. Any response, such as quarantining a device, is a separate explicit, audited action. Beaconing moves from P2 to P1, because periodic phone-home is the motivating IoT case. Scheduled as T3.11, after the aggregator (T3.1).

**Alternatives considered:** ML models (isolation forests, autoencoders) can catch subtler patterns but aren't deterministic across versions, are hard to explain, and need training data a home network doesn't have. Rejected for v1; the evidence-carrying finding format leaves room for an optional, clearly labeled model-based detector later. Automatic blocking on anomalies was rejected: false positives would break devices silently, against the "DNS never surprises you" principle.

**Consequences:** Owners get actionable, explainable alerts ("plug contacted 37 new domains; usual 0–1") with no black box, at bounded cost. Detection quality depends on baselines, so the first week after install (or after a device appears) is quiet by design.

## ADR-020 — Query-time hash index over the snapshot FSTs (Accepted)
**Context:** T2.4 requires a filter lookup p99 ≤ 1 µs (no regex) on x86. Walking the snapshot FSTs byte by byte measured p50 0.65 µs and p99 1.65–1.8 µs on a native x86 machine (x86-64 laptop CPU) with 2.6M names. The walk is a chain of dependent compressed-node decodes, about 30 ns per byte, so tuning can't fix it. ADR-003 picked FSTs for size and O(|qname|) lookups; it didn't fix the query-time structure.

**Decision:** Keep FSTs as the snapshot and sync format (compact, content-addressed, ~9 B/name). Each resolver builds an in-memory index from them on load: one table per scope, in 64-byte buckets of 8 entries, each entry `48-bit fingerprint | 16-bit list-set ID`, with a seeded xxh3 hash (random seed per load) and a 75% load factor. A lookup is one probe per (scope, reversed suffix), almost always one cache line each, and the probes are independent memory reads. A false match needs a fingerprint collision inside one bucket: ~6e-14 per probe, about once per few thousand years of a busy resolver, and the seed changes on every load. Snapshots with more than 65,536 distinct list combinations use the FST walk. A new snapshot is served with the walk the moment it's loaded, and the indexed matcher is swapped in when ready (built at nice 10), so the index never delays a cold start or a list update.

**Consequences:** Measured with 2.6M real names and no regex: p50 0.32 µs and **p99 0.93–0.94 µs** on that host (0.61–0.64 µs on a second laptop), versus 1.65 µs for the walk. The cost is ~10 B/name of RAM on top of the FSTs (26.9 MiB for 2.6M names), built in ~0.9 s. At the `00` §5 RSS gate (1M names) that's ~10 MiB, within budget. Zero allocations per lookup in both modes (tested). The regex path adds ~0.2 µs with AdGuard's 29 regexes.

## ADR-021 — Groups, clients, and identification (Accepted)
**Context:** FLT-005/006 and `spec/03` §3 step 2 define groups and the identification chain, but not the configuration, the trust model for client-supplied identity, or how group lists meet the compiled snapshot.

**Decision:**
- **Config:** `[[group]] { name, lists?, priority }`, where omitted `lists` means every enabled list. A `default` group always exists; declaring one restricts what unknown devices get. `[[client]] { name, match = [IP | CIDR | MAC | "id:<client-id>"], groups = ["default"] }`, validated for unknown groups and lists and for a key that identifies two clients. `[clients] { neighbor_table = true, neighbor_refresh_secs = 60, trust_edns_mac_from = [] }`.
- **Chain:** client ID → EDNS MAC (only from `trust_edns_mac_from`: the option is client-supplied, so trusting it by default would let any device claim another's identity) → MAC from the kernel neighbor table (rtnetlink dump, IPv4 + IPv6, in `telltale-net`, refreshed only while some client is matched by MAC) → exact IP (IPv4-mapped IPv6 canonicalized) → most specific CIDR → `default`. Lookups are hash maps and a short sorted prefix list; a prefix trie can replace the list if CIDR counts grow.
- **Groups:** a device in several groups gets the union of their lists; other settings come from the highest-priority group. Per-client list masks are precomputed whenever the snapshot or the client config changes. The filter state records the client table it was built for, so a query racing a reload never pairs one table's identity with another's masks.
- **Routing:** client group names feed `[[route]] match_group`. Resolution now looks up the upstream group by the cache view chosen at selection time, rather than re-selecting without groups.
- **Deferred:** hostname-based matching (DHCP leases / rDNS, FLT-006), client IDs until the DoH/DoT listeners (T4.5), and per-group block mode, pause, and schedules (T2.6, FLT-009/010).

**Consequences:** Pi-hole-style per-device filtering, with MAC identification that survives DHCP and IPv6 privacy addresses on host-networked installs. Identification costs a few hash lookups per query and allocates nothing.

## ADR-022 — Block answers, CNAME inspection, and pause semantics (Accepted)
**Context:** FLT-007/008/009 list the block modes, CNAME deep inspection, and pause, but not the default mode, the TTL, how CNAME inspection meets the policy-neutral cache (`spec/03` §4), or what pausing means for a device in several groups.

**Decision:**
- **Block answers per group** (`block_mode`, `block_ips`, `block_ttl`, `ede`, `ede_text`), taken from the client's highest-priority group. Default `null_ip` (A → 0.0.0.0, AAAA → ::, other types → NODATA), matching Pi-hole and Technitium (the owner's current setup); TTL 60 s; EDE 15 with the list name. NXDOMAIN and NODATA answers carry an SOA with the block TTL; block answers are authoritative except REFUSED. This changes T2.4's interim NXDOMAIN default.
- **CNAME inspection** runs wherever an answer leaves the server: cache hits, fresh upstream answers, and stale answers. The cache stays policy-neutral and the check is per client. It walks the answer section's CNAME records without allocating; the first blocked target replaces the whole answer with the client's block answer, with EDE text `CNAME target blocked by list …`.
- **Pause:** global and per group, until a deadline, keyed by group name so it survives reloads. A client is paused when its highest-priority group is (consistent with block settings coming from that group). The fast path costs one atomic load when nothing is paused. The control surface is the API (T3.4).

**Consequences:** Block behavior matches the owner's current resolvers by default and is tunable per group. CNAME cloaking (trackers behind first-party CNAMEs) is caught, for cached answers too, at the cost of a records walk on answers that have CNAMEs.

## ADR-023 — Background work under load: priorities, thread counts, and deferred frees (Accepted)
**Context:** T2.7 requires a recompile during the `realistic-home` run to raise p99 by at most 10%, with zero errors. ADR-018 ran compiles at nice 10 on half the cores (1–4) and left this measurement to T2.7. On a test host (x86-64 laptop CPU, 6 cores / 12 threads, 2.7M names, 20k qps, `bench.py swap`), the first measurement showed large p99 spikes, and a long run crashed the server.

**Decision:**
- **Priority:** background threads (compile, index build, snapshot load, retire) use `SCHED_IDLE` on Linux instead of nice 10, through `telltale_net::background_thread()`. Nice 10 still received a share of CPU while workers were runnable.
- **Thread count:** `[filter] compile_threads = 0` (auto) now means half the cores (1–4) only while nothing is filtering yet. Once a snapshot has been published, a recompile (list refresh, reload) uses **one** thread. An explicit number applies to every compile. Even at idle priority, parallel compile threads compete with query workers for SMT siblings, memory bandwidth, and cache. On the homelab, 4 threads compiled in 2.1 s and raised p99 by 143%. One thread took 5.9 s and raised it by 7.5%, and the confirmation run with defaults measured −17.7% (within run-to-run noise). A refresh's result isn't waited for, so a slower compile costs nothing visible. ADR-018's first-compile timing, and with it T2.3's Pi gate, is unchanged.
- **Deferred frees:** swapped-out filter and routing state is dropped on a short-lived background thread after 2 s, so freeing tens of MB never lands on a worker mid-query.
- **No blocking work on runtime workers:** hashing, checking, and compressing a downloaded list runs on `spawn_blocking`. A reload with unchanged upstream config reuses the running router (health state, pooled connections, bootstrap cache).
- **`SIGUSR1`** refreshes every list now (FLT-004), and the bench uses it to trigger a list-driven recompile.

**Found while measuring:** prefetch (DNS-008) called `tokio::spawn` from the cache-hit path on UDP worker threads, which have no runtime context. The resulting panic killed the server once a hot entry reached the prefetch threshold. Prefetch now spawns on a runtime handle captured when the pipeline is built (regression test `dns_008_prefetch_from_a_non_runtime_thread`).

**Consequences:** A list refresh on a Pi 4 takes about 11.6 s for 2M names (1 thread) instead of 6.4 s, while the first compile keeps 2 threads. Users who prefer faster refreshes over latency can set `compile_threads`. The p99 measurement is noisy on a shared host: quiet-window p99 alone varied from 65 to 847 µs between rounds, so `bench.py swap` gates on the median over rounds with alternating order.

## ADR-024 — Explain: rule identity, line lookup, and surfaces (Accepted)
**Context:** FLT-013 says every decision records "list ID + rule ID" and that the API can explain "why was X blocked for client Y". `spec/05` §5 lists what explain returns: the client resolution, groups, schedule state, every matching rule across tiers with list name, line number and text, the winner, and the would-be upstream group. The snapshot (ADR-018) stores plain domain rules only as names in FSTs, with no line numbers. The API comes in M3 (T3.4).

**Decision:**
- **Rule identity.** A plain domain rule is identified by (list, listed name, scope, tier); modifier and regex rules by their index in the snapshot, which carries their line. That's what `Attribution` records on the query path (T2.4), and what the query log will store (T3.1). Line numbers aren't added to the snapshot: about 3–4 more bytes per name (+40%) for something only explain needs.
- **Line lookup on demand.** Explain re-parses the stored source of each list that matched (only those lists) and reports every line that produces the matched rule, so a name listed twice shows both lines. If the stored source's hash differs from the snapshot's (downloaded again since compiling), the lines refer to the newer copy and a note says so. A missing source gives the rule without lines, plus a note.
- **Every match, not just the winner.** `Matcher::matches` reports matches from every list, each marked whether the client's groups use it, in the exact precedence order `decide` uses. The first enabled match is, by test, `decide`'s answer for every mask. The query path's `decide` is the same code made generic over a result sink; an A/B of `matcher_bench` showed no change (p50 445 → 453 ns, p99 1085 → 1005 ns, medians of 4 alternating rounds).
- **Whole-pipeline answer.** Explain walks the pipeline's own stages on a real parsed query: allowed networks, ANY, special names, local records, identification, filter, pause, routing including RFC 6303 private PTRs. Its outcome is tested to agree with what the pipeline answers. Rate limiting depends on the moment, not the name, so it's left out. Schedules (FLT-010) are P1 and are added when they exist.
- **Surfaces.** `Pipeline::explain` returns a serializable `Explanation`, the response body for `GET /api/v1/explain` (T3.4) and the `explain_decision` MCP tool. Until then, `telltale explain` runs it offline from the config and data directory (newest snapshot, stored sources, kernel neighbor table), as text or `--json`.

**Consequences:** No snapshot growth and no query-path cost. Explaining a name that matches big lists costs a parse of those lists. Measured on the WSL laptop with 2.7M names: 0.15 s for a name in two lists totalling 6.5 MB, and 0.02 s for an unmatched name (peak RSS 54 MiB). A Pi 4 is several times slower. That's fine for an interactive "Why?" but not for bulk use. If the UI needs bulk explain (for example, annotating every row in a log view), the query log's stored attribution covers it without line text.

## ADR-025 — Compile memory peaks vs small memory limits (Accepted)
**Context:** `00` §1 targets a 128 MiB Kubernetes pod limit and small Pis (Pi Zero 2 W: 512 MiB). Steady-state RSS is well within budget: 25–35 MiB with the `09` §2 bench lists (430k names) and about 70 MiB with 2.7M names, roughly 20 B per name plus a ~17 MiB base. But compiling a snapshot is transient and much larger: peak RSS 106–109 MiB with the bench lists and **297 MiB with 2.7M names** (homelab and WSL measurements, 2026-10-03). `[filter] compile_memory` (128 MiB) bounds only the external sort; parsing, FST building, index building, and the old and new matchers coexisting (ADR-020, ADR-023) add to it. In a pod with a 128 MiB limit, a large list set gets the process OOM-killed mid-compile, taking DNS down with it, which violates "DNS never depends on anything else".

**Decision (proposed, for the owner):**
1. **Derive the compile budget from the memory limit.** When `compile_memory` is unset, read the cgroup v2 `memory.max` (or v1 `memory.limit_in_bytes`) and set the sort budget to about 25% of it, minus current RSS, with a floor of 16 MiB. Smaller budgets spill more and run slower, but stay inside the limit.
2. **Refuse rather than die.** Before compiling, estimate the peak from the number of input names (measured: about 115 B per name at 2.7M names and about 250 B at 430k, where the fixed base dominates). If it exceeds the remaining headroom under the limit, keep the current snapshot, log an error, and expose `telltale_filter_compile_skipped{reason="memory"}`, instead of risking an OOM kill.
3. **In a cluster, resolvers don't compile.** CLU-00x already ships snapshots from the controller; resolver pods only load them (steady state). So the 128 MiB target applies to resolver pods, and the controller (or a standalone node) needs the compile headroom. This goes into the Helm chart defaults (T4.4) and `docs/` sizing guidance.

**Alternatives considered:** Lowering the default `compile_memory` alone doesn't bound the other phases. mmap-loading snapshots (ADR-018) cuts steady RSS, not the compile peak. Compiling in a child process would isolate an OOM from DNS, but needs a second process in a `FROM scratch` image and complicates the single-binary model; keep it in reserve if (1)–(2) aren't enough.

**Consequences:** Until this is implemented (proposed for M4, with the Helm chart), standalone deployments need a memory limit of at least ~3× the steady-state RSS for their list set, or 256 MiB for list sets over ~1M names. `docs/` will say so with the measured numbers.

## ADR-026 — Event capture: byte rings, sizes, and precision (Accepted)
**Context:** `spec/06` §1–2 describes a fixed-size, ~128-byte `QueryEvent` with a 64-byte inline qname, per-worker rings of 65,536 slots (~8 MiB each), and HDR histograms with 3 significant digits. T3.1's AC is "drop counter 0 at 100k qps sustained on x86 with default ring sizes". The footprint priority and the M2 RSS budget (64 MiB with telemetry on) push back on several of those sizes.

**Decision:**
- **Variable-length records in a byte ring** (`rtrb::RingBuffer<u8>`, one per producing thread): a 61-byte header plus the full wire-format qname, lowercased, so ~85 bytes per typical query. A 64-byte inline name would truncate exactly the long names that DGA and anomaly detection (OBS-009/013) care about. A record is written with `push_entire_slice`: all of it or nothing, wait-free. A full ring drops the event and counts it per ring (`telltale_telemetry_dropped_total{ring}`); counters and the Prometheus histograms never drop.
- **Ring size:** `[telemetry] ring_slots` stays the knob, in events of ~128 bytes. The default drops from 65,536 to **4,096 (512 KiB per producing thread)**. With one aggregator pass every 25 ms, a fully loaded worker (~42k events/s, ~3.5 MB/s) fills it in ~170 ms, about 7× the drain period. With UDP workers plus Tokio workers each owning a ring, the spec default would have cost 8 MiB × threads (over 100 MiB on a 12-thread host).
- **Rings per producing thread, not per listener worker:** deferred answers complete on Tokio threads, so each thread that emits gets its ring on first use (one allocation and one short lock per thread lifetime), then never allocates (tested).
- **HDR precision: 2 significant digits** (1%) instead of 3. Each 1 µs–60 s histogram with `u32` counts is ~10 KiB instead of ~70 KiB. With per-client (256 + other), per-qtype, per-path, per-stage, and per-upstream histograms for the current and previous hour, that's at most ~7 MiB instead of ~45 MiB. Histograms allocate on first use.
- **Deferred to T3.2:** qname/client interning (only the segment store needs it; top-K holds names directly), and SQLite persistence of rollups (`06` §3). Until then, the minute and second windows (48 h and 15 min) and the hourly top-K and histograms (current and previous hour) are in memory only. Persistence lands with the store, its retention, and its write budget.
- **Upstream attribution:** `QueryEvent.upstream` stays 0 for now. Singleflight shares one answer between coalesced clients, so per-upstream analytics come from `UpstreamEvent`s (one per exchange, prefetches included), keyed by the upstream's stable config-order ID.

**Measured (test host, x86-64 laptop CPU, 4 UDP workers, dnsperf on the same host, 2026-10-03):**
- **AC met:** 99,991 qps of `cache-hot` sustained for 60 s: 5,999,502 queries, 5,999,502 events, **0 dropped**, 0% loss, RSS 41 MiB.
- Hot-path cost, A/B against the previous commit, 10 rounds in alternating order: p50 at 50% load 34 → 34 µs; p99 at 50% load 751 → 751 µs (medians); saturated `cache-hot` qps 169k → 163k (median, −3.7%, with overlapping run ranges of 149–183k vs 148–183k). An earlier 6-round A/B gave −2.4%. So the event path probably costs 2–4% of saturated cache-hit throughput, within this host's run-to-run spread, and nothing measurable at realistic load.
- Locally, 4 producers at 25k events/s each with the default ring and drain period: 0 drops (optimized build).

**Consequences:** Full names in every event. About 2–8 MiB of rings depending on thread count, and bounded aggregate memory (windows ~1 MiB, top-K ~1 MiB, histograms ≤ ~7 MiB). If a host's aggregator can't keep up (a slow Pi under a flood), events drop and are counted, and DNS is unaffected.

**Amended 2026-10-08 (review 04-01, 04-07; amendment Proposed):** the epoch (`Hub::ts_us` = epoch + monotonic elapsed) follows steps of the system clock: the aggregator thread re-anchors it when the wall clock and the epoch-derived time differ by a second or more (one clock read per drain; the query path reads one relaxed atomic). A Pi without an RTC is stepped by NTP after TelltaleDNS starts, which left every later event, query-log row, and rollup minute on the old offset until a restart. Steps are exported (`telltale_clock_steps_total`, `telltale_clock_last_step_seconds`). `QueryEvent.upstream` now records the upstream that answered (the owner's choice, review 04-07): the ID travels with the answer through singleflight, so coalesced clients all name the winner, and cached, local, and blocked answers stay 0. Per-upstream analytics still come from `UpstreamEvent`s, which count every exchange, prefetches included.

## ADR-027 — Query-log segment format and search (Accepted)
**Context:** `spec/06` §4 defines the query log: hourly columnar segments, blocks of up to 8192 rows, per-column encodings with zstd, a block index with a 1 KiB bloom over name and client IDs, a segment dictionary, dictionary-first search, and a small search pool with "1 thread on Pi by default". T3.2's AC: a search over a 50M-row synthetic dataset in ≤ 2 s on a Pi 4, with the format fuzzed. Measuring against that AC changed several details.

**Decision:**
- **Files:** `qlog/YYYY/MM/DD/HH-<node>-<part>.seg`. A new part starts after a restart, after a dropped block (a later block must never reference dictionary entries only the dropped block introduced), or when the segment dictionary reaches 65,536 names or clients. The cap bounds the writer's memory under floods of unique names.
- **Self-describing blocks:** each block carries the dictionary entries it introduces, so a segment still being written, or cut short by a crash, is readable by walking block headers. The footer (block index, name filter, trailer) is only a faster path, written when a part is finished.
- **Encoding:** every column is a varint (or byte) stream compressed with zstd level 3; the spec's per-column delta/RLE/frame-of-reference encodings are left to zstd. Measured at 13.9–14.4 B/row (spec: 10–20). Rows are sorted by time within a block.
- **Per-section length and checksum table in the block header**, so a search reads and verifies only the sections it needs: one positional read for one column, one read for several. Checksums are xxh3-64, which only detects corruption (nothing here is content-addressed). BLAKE3 over every section was a measurable share of a 30-day search on a Pi.
- **Blooms keyed by content hashes, not dictionary IDs**, so blocks are ruled out before any dictionary is read. The spec's 1 KiB block bloom stays for clients and unfinished segments, but it can't rule out names: blocks hold thousands of distinct names, about 60% false positives. So each finished segment also gets a **name filter** in its footer (~10 bits and 7 probes per name, ~0.8% false positives). An exact-name search over 30 days skips about 99% of segments after one small read.
- **Dictionary handling:** dictionaries are decompressed in bulk into one buffer and indexed in place (no allocation per name), read only when a name or client predicate needs them. Output rows resolve their few names sparsely, from just the dictionary blocks holding those IDs. Predicates run column at a time into a selection vector; the time column is skipped when a block lies inside the range.
- **Search threads:** up to 4 (default `min(cores, 4)`), each at the lowest CPU priority via a thread-start hook (`SCHED_IDLE` in the server and CLI), so a search only uses CPU that DNS doesn't. This changes `06` §4's "1 thread on Pi by default": on one Pi core, substring and latency searches over 50M rows take ~5 s. A persistent pool claims segments newest first; results merge in order; the pool stops as soon as the page is full.
- **Write path:** the builder runs on the aggregator thread (interning, privacy, rows; no I/O). A writer thread encodes, compresses, appends, writes footers, and runs retention every 10 minutes, fed by a bounded queue of 8 blocks. A full queue drops the block and counts it (`telltale_qlog_rows_dropped_total`). DNS never waits on the disk.
- **Privacy levels** apply at write time: 1 stores names as a one-label hash, so identical names still group together; 2 also zeroes clients; 3 writes nothing. Per-group levels (`06` §4) wait for group-level config.
- **Not yet:** `node` is 0 until cluster membership (T5.x); rows from several nodes in one hour aren't merged by time. SQLite rollup persistence (ADR-026) moves to T3.3 with the Prometheus/rollup work, which uses it, so `rusqlite` arrives with its first consumer.

**Measured:**
- Synthetic 50M rows over 720 hours: 40 Zipf clients, 20k Zipf domains plus 15% one-off tracking names (pessimistic: real homes have far fewer), 15.1M dictionary entries, 686 MiB.
- **Pi 4** (Technitium in production on the same Pi, search at nice 10, 4 threads, page cache warm), second round:

| Query | Time |
|---|---|
| exact rare name | 0.21 s |
| rare substring | 1.78 s |
| client + blocked, 1000 rows | 0.43 s |
| type filter with no matches (full column scan) | 0.75 s |
| latency ≥ 1 s (1000 rows across 590 segments) | 1.92 s |
| newest rows, last 2 hours | 0.03 s |

  **AC met with 4 idle-priority threads, with thin margins on the two heaviest queries.** On 1 thread the same two take ~5 s.
- x86 (laptop, 4 threads): every query ≤ 0.9 s.
- Fuzzing: `qlog_segment` (raw, checksum-repaired, and structure-aware modes), ~670k runs across three sessions, clean.

**Consequences:** Interactive search stays within 2 s on a Pi for a month of a busy home's queries, without stealing CPU from DNS. Heavier work (a multi-month substring scan, or a much higher share of unique names) degrades linearly. If that matters, the next step is a cross-segment name index (one dictionary per day or week), not more threads.

## ADR-028 — API listener, crate boundary, and the read-only first slice (Accepted)
**Context:** `spec/07` defines the API conventions and resource map but no listener: `06` §5 says only that `/metrics` is "also on the API port". T3.4 (API-001, API-002) is the skeleton, and the owner asked for a UI next for testing, which needs an API. API-003 (auth) is T3.5.

**Decision:**
- **Listener:** a new `[api]` section (`enabled = true`, `listen = "0.0.0.0:8053"`) on its own TCP listener, also serving `/metrics` and `/livez`, `/healthz`, `/readyz` (`06` §5). Port 8053 avoids 53/80/443, Pi-hole's 80, and Technitium's 5380/53443 (the owner runs Technitium on the same Pi). The metrics listener (9153) stays for scrapers.
- **Crate boundary:** `telltale-api` owns routes, request/response types, problem+json, time parsing, and the OpenAPI document. It reaches the server only through a `Backend` trait implemented by the binary (`api_backend.rs`) over the state that already exists for `/metrics`, the pipeline, the aggregates, the query log, and list status. So the API never depends on pipeline internals, and the trait is the seam a cluster proxy (federated scope) plugs into later.
- **OpenAPI:** `utoipa` 6 generates OpenAPI 3.1 from the handlers. Doc comments become summaries and descriptions, and a test fails if any operation lacks either (AGT-001). `docs/api/openapi.json` is committed, and a test fails when it drifts (`07` §1); regenerate with `UPDATE_OPENAPI=1`.
- **Conventions:** camelCase JSON with units in field names; `{"items": [...]}` for collections; cursor pagination on the query log (other collections are small and unpaged for now); `from`/`to` as RFC 3339 or relative offsets; errors as RFC 9457 problem+json with a stable `code` enum and a `hint`; `scope` accepted on analytics calls, where `cluster` and `node:local` mean this node and anything else is a 400 `unsupported_scope` until clustering.
- **Read-only until auth:** T3.4 ships GET endpoints only (system info, stats summary/timeseries/top/latency, query log, explain, lists, groups, clients, upstreams). Mutations, with dry-run and idempotency keys (AGT-002/003), come with T3.5 so nothing can be changed without authentication. Until then the listener answers only `[access] allowed_networks`, like `/metrics`.
- **Roadmap order:** at the owner's request (2026-10-04: "we will want a UI to help with testing"), T3.5 and T3.9 come next. T3.3 (Prometheus set, Grafana, SQLite rollups) moves after T3.9; none of the UI depends on it, since the dashboard reads the in-memory windows.

**Consequences:** The UI and agents have a documented, typed surface now. Every later endpoint follows the same pattern (types and doc comments in `telltale-api`, data from `Backend`).

## ADR-029 — Local sign-in details (Accepted)
**Context:** `spec/08` §6 and API-003 define local users (Argon2id), session cookies with CSRF, opt-in HTTP Basic, scoped API tokens, TOTP, lockout, RBAC, and a first-run setup token. Several details are left open.

**Decision:**
- **Storage:** users, recovery codes, sessions, and tokens in SQLite `<data_dir>/state.db` (rusqlite, bundled). Session IDs, token secrets, and recovery codes are stored only as BLAKE3 hashes (they are 256-bit random, so a slow hash adds nothing); passwords as Argon2id PHC strings with the `08` §6 parameters. If `state.db` can't be opened, the API stays off and DNS keeps answering (rule 5).
- **Cookie `Secure` flag:** set only when the request arrived over HTTPS (`X-Forwarded-Proto: https`), because the API has no TLS listener yet and browsers drop `Secure` cookies over plain HTTP, which would make sign-in impossible on a LAN. `HttpOnly; SameSite=Strict` always. Revisit when the API gets TLS (`08` §6 asks for `Secure` unconditionally).
- **CSRF:** a per-session random token returned at sign-in and by `GET /auth/status`, required as `X-CSRF-Token` on every non-GET request authenticated by the cookie. Tokens and Basic don't need it (they are not sent automatically by browsers).
- **Tokens:** `tt_<16-char id>_<43-char secret>`. Scope caps the owner's role (`read` → viewer, `write` → operator, `admin` → admin). The optional group scope from `08` §6 is deferred to the `family` role (P1).
- **Basic:** per-user opt-in; refused over plain HTTP unless `[auth] allow_insecure_basic`; verified results cached 60 s keyed by a salted BLAKE3 hash of the credentials, invalidated on any change to the user. Users with TOTP can't use Basic (it would bypass the second factor).
- **Password policy:** 10–256 characters, no composition rules (NIST SP 800-63B).
- **Lockout:** per username and per client address, 5 free failures, then 30 s × 2^n up to 15 minutes; in memory (a restart clears it). Unknown usernames take the same time as wrong passwords (a dummy Argon2 verify).
- **Sessions:** 7 days absolute, 1 day idle (configurable in `[auth]`); `last_seen` is written at most once a minute; a password change ends the user's other sessions; disabling or deleting a user ends all of theirs; hourly purge.
- **TOTP:** RFC 6238, SHA-1, 6 digits, 30 s, ±1 step; each step is accepted once (replay protection); ten recovery codes, single-use. `[auth] totp_required_roles` refuses password-only sign-in for those roles until TOTP is enrolled (403).
- **First admin:** the setup token is kept in `<data_dir>/setup-token` (mode 0600) and logged, so it survives restarts and `telltale auth setup-token` can print it; it is deleted once an admin exists. Deployments can instead set `TELLTALE_BOOTSTRAP_ADMIN_USER` with `..._PASSWORD` or `..._PASSWORD_HASH` (Argon2id PHC only; `telltale auth hash-password` makes one), applied only while no user exists.
- **What is open:** `/api/v1/auth/{status,setup,login}`, `/api/v1/openapi.json`, and the probes. Everything else, including `/metrics` on the API port, needs a sign-in. The dedicated metrics listener (`:9153`) stays unauthenticated and limited to `allowed_networks`, so existing scrapers keep working. The API listener also stays limited to `allowed_networks` (defense in depth).
- **AGT-002/003:** the auth endpoints don't take dry-run or idempotency keys: sign-in, sign-out, and token creation aren't meaningful to preview, and replaying a token creation must not mint a second secret silently. Configuration mutations will take both when they land.

**Consequences:** The API is safe to expose on the LAN, and the UI (T3.9) can build sign-in and first-run screens on `/auth/status`. TLS on the API listener and OIDC (API-004) are later tasks; until TLS, HTTP Basic needs a TLS-terminating proxy.

**Amended 2026-10-08 (review 06-01, 06-08; amendment Proposed):** at most four password checks (Argon2id, 19 MiB each) run at once; beyond that sign-in and uncached HTTP Basic answer 503 with `Retry-After: 1`, not counted as a failure, so a burst of sign-ins can't run the node out of memory (`02 §8`). HTTP Basic failures now count against the address as well as the username, and a success clears both, as the sign-in form does.

## ADR-030 — Web UI MVP: serving, security, and scope (Accepted)
**Context:** T3.9 (API-005) asks for a UI MVP: login, dashboard, query log + explain, groups, lists, upstreams, local DNS, and settings, ≤ 400 KiB gzipped, with a Playwright suite. ADR-009 fixes the stack (Svelte + uPlot, embedded). The API has no configuration mutations yet, no live tail (T3.7), and no OIDC (T3.6).

**Decision:**
- **Serving:** `telltale-api` embeds `ui/dist` with `rust-embed` (`allow_missing`, so Rust builds and tests work without Node; such a binary serves a one-paragraph page saying the UI isn't built). The API router's fallback serves the UI for everything outside `/api/`. Static files need no sign-in (they hold no data); every data call does.
- **Routing:** hash routes (`#/queries?client=...`), so the server only serves `/`, `/assets/*`, and `/favicon.svg`, and filters are bookmarkable without server-side SPA fallbacks.
- **Security:** CSP `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, plus `X-Frame-Options: DENY`, `nosniff`, and `Referrer-Policy: no-referrer` (`08` §6). The UI never uses inline scripts, `style` attributes, or `{@html}`; dynamic styles go through Svelte's `style:` directive (CSSOM, allowed by CSP). The Playwright suite fails on any console error, so CSP violations fail CI. HSTS waits for TLS on the API listener.
- **Size and caching:** `npm run build` writes a `.gz` beside each text asset (served on `Accept-Encoding: gzip`; amended by ADR-168: only the `.gz` is kept, and the server inflates it for a client that doesn't accept gzip) and fails over 400 KiB gzipped. Hashed `assets/*` are `immutable`; `index.html` is `no-cache`. The MVP is ~60 KiB gzipped.
- **Types:** `src/lib/api-types.ts` is generated from `docs/api/openapi.json` (openapi-typescript) and committed; CI fails if it is stale, so the UI breaks at type-check time, not at runtime, when the API changes.
- **Build:** Node is build-time only: a `node:24` stage on the build platform builds `dist/` once for all image architectures. CI's `ui` job runs svelte-check, the budget, and Playwright (headless Chromium) against a real binary with an inline blocklist and a local record (no internet needed).
- **MVP scope versus `07` §3:** shipped: first-run setup and sign-in (with TOTP and recovery codes), dashboard (KPIs, stacked queries by status, upstream exchanges, where time goes, top domains/blocked/clients, upstream share and health; every chart has a table view), query log (filter chips, URL filters, cursor paging, per-row timing bar, "Why?" drawer), explain page, clients (seen and configured), groups, lists, upstreams (breaker, latency), settings (password, TOTP, tokens, users, system), light/dark themes, 360 px layout. Deferred: OIDC sign-in (T3.6); editing groups, lists, upstreams, and local records, and the allow/block quick actions (need the configuration API with AGT-002/003); live tail via SSE (T3.7; the log polls with "Auto-refresh" meanwhile); a virtualized table (100-row pages for now); the schedules editor, presets gallery, client merge and profile pages, analytics, cluster page and scope selector (M5), and the audit log (T3.8). The TOTP enrollment shows an `otpauth://` link and the key rather than a QR code, to avoid a QR dependency. The latency tile shows the upstream p90 because the API exposes p50/p90/p99, not p95.

**Consequences:** The resolver ships its own UI in one binary with no runtime dependencies. Each new API feature can add its page incrementally; the suite and the type drift check keep the UI and API in step.

## ADR-031 — Prometheus metric set and SQLite rollups (Accepted)
**Context:** T3.3 completes the `06` §5 metric set (OBS-005, OBS-011), ships a Grafana dashboard, and persists rollups (`06` §3, moved here by ADR-027). Rule 4 forbids new hot-path work without a benchmark.

**Decision:**
- **Where series come from:** the per-thread counters (T1.9) stay as they are. Series that need per-event detail (`telltale_stage_duration_seconds`, `telltale_upstream_duration_seconds{upstream,protocol}`, `telltale_blocked_total{group,list}`, opt-in `telltale_client_queries_total{client}`) are built by the aggregator thread from query/upstream events into cumulative classic histograms (the same 50 µs–5 s buckets) and counters. Nothing new runs on the query path; the cost is that these series miss events dropped by a full ring, which `telltale_telemetry_dropped_total` already reports. The only hot-path change is one increment for `telltale_cache_prefetch_total`, under a lock already held. bench-smoke after the change: 191,533 qps cache-hot, 0% loss.
- **Bounded cardinality:** blocks are keyed by (group, list) with at most 4,096 pairs; per-client series are off by default and capped at `per_client_cap` (default changed 256 → 100 to match `06` §5), the rest summed as `client="other"`; upstream series follow the configured upstreams.
- **Label deviations from `06` §5:** no `node` label on every series: Prometheus already adds `instance`, and `node` is on `telltale_build_info` for joins; cluster-wide views will add it when nodes federate (M5). `qtype` stays in its own family (`telltale_queries_by_qtype_total`) instead of a third label on `telltale_queries_total`, keeping that family at 22 series instead of 286. `telltale_upstream_requests_total` gains `outcome` (`success`, `failure`) from the router's health counters (every attempt, including health probes) and replaces `telltale_upstream_failures_total`. `telltale_ratelimited_total` mirrors `queries_total{status="rate_limited"}`. The DNSSEC, cluster, and qlog-write-time series wait for their features.
- **Grafana:** `deploy/grafana/telltale-dashboard.json` is generated by `deploy/grafana/build.py` (CI checks it is current) and uses only exported metrics, with datasource/job/instance variables.
- **Rollups:** `<data_dir>/rollups.db` (separate from `state.db` so analytics writes never contend with sign-in): `rollup_minute` (7 days), `rollup_hour` (400 days), `rollup_day` (forever), `hour_top` (top 100 per kind per hour), `hour_latency` (percentile summaries per hour; HDR histograms are not stored, since percentiles of merged hours aren't needed yet and summaries are tiny). Counts are a versioned little-endian blob with column counts in the header, so later builds read old rows. A background task flushes completed minutes once a minute, re-writing the last 3 minutes for late events but never minutes from before the process started (so a restart can't overwrite saved data with a partial view); hour and day rows are recomputed from the rows below on every write (idempotent). Retention runs hourly. All SQLite work is on a blocking thread; open or write failures are logged and the API falls back to memory (rule 5).
- **API:** `step` gains `hour` and `day` (rollups); `step=minute` merges stored minutes with memory (memory wins); `stats/summary` sums hours for ranges beyond 48 hours. The dashboard UI adds 7- and 30-day ranges.

**Consequences:** Charts and summaries reach back 400 days and survive restarts with ~1 KiB per stored minute at most. Querying a past hour's top-K through the API is not exposed yet (stored for the analytics pages).

**Amended 2026-10-08 (review 04-04, 04-11; amendment Proposed):** the hourly top lists in `rollups.db` follow the query log's privacy level: names hashed exactly as the query log stores them at level 1 and above, no list of clients at level 2 and above (they were kept in plain text for 400 days at every level). A restart in the minute after an hour closes no longer loses that hour's lists: once the startup replay is over, the writer stores them if nothing is stored for the hour.

## ADR-032 — Live tail over Server-Sent Events (Accepted)
**Context:** OBS-008 / `06` §6: `GET /api/v1/queries/stream` (SSE) "or `/ws`", server-side filters (client, group, status set, qname glob, upstream, min latency, node), and a per-subscriber rate cap (default 500 events/s) with inline drop counts. Rule 4 forbids hot-path cost; rule 5 says telemetry can't affect DNS.

**Decision:**
- **SSE only, no WebSocket:** one-way delivery is all a tail needs; SSE works through proxies, reconnects by itself in browsers (`EventSource`), and authenticates with the session cookie (GET, so no CSRF header). A WebSocket can be added later if a use appears.
- **Source:** the aggregator thread's sink (beside the query-log writer) copies query events into a `tokio::sync::broadcast` channel (4,096 deep) only while a subscriber exists; otherwise the cost is one atomic load per event. The query path is unchanged. The query-log privacy level applies (1: names hashed, 2: clients hidden too, 3: no tail).
- **Per subscriber:** a task filters raw events (no allocation: names are compared via a reused buffer), applies a token bucket (`rate`, default 500/s, 1–2000), formats matches as the same `QueryRow` as `GET /queries`, and every second reports skipped matches as `event: dropped` `{dropped, reason: "rate"|"lag"}` (lag: it fell behind the broadcast channel or its own 256-item queue). Filters: `name` + `match` (substring, exact, suffix, glob; regex is rejected to keep per-event cost bounded), `client`, `group` (primary group), `status`, `qtype`, `upstream`, `minLatencyMs`. `node` waits for clustering. At most 16 concurrent streams per node (503 beyond). A comment every 15 s keeps idle connections open.
- **Measured** (bench-smoke on the dev box, two subscribers attached for the whole run: one unfiltered at the 500/s cap, one with a name filter matching nothing; two rounds in opposite order): cache-hot 196k and 169k qps with subscribers vs 143k and 166k without, 0% loss in all runs; p99 at 50% load 3.4/3.5 ms vs 2.6/4.0 ms (within this machine's noise); p50 at 50% load 655/367 µs vs 167/215 µs, a small but consistent median cost under heavy load from formatting on the aggregator and subscriber tasks sharing CPU with the load generator. Acceptable for an operator watching a live view; zero when nobody watches.
- **UI:** the query log's "Auto-refresh" polling becomes **Live** (EventSource with the page's filters; rows flushed every 250 ms; newest 500 kept; skipped count shown). Rcode and time filters don't apply to a live view and the page says so.

**Consequences:** "Watch it happen" works in the UI, from `curl -N`, and for agents. Subscriber tasks share the async runtime with upstream I/O, which is why the cap, the subscriber limit, and allocation-free filtering matter; if a home ever needs more, move subscribers to a dedicated thread.

## ADR-033 — Audit log: what, where, and how it is chained (Accepted)
**Context:** API-006 asks for an audit log of every config change (who, when, diff), replicated cluster-wide; `08` §6 makes it append-only and hash-chained; AGT-005 asks for agent attribution and a reason. Today the only mutations are sign-in administration and config reloads (config editing through the API comes later).

**Decision:**
- **Storage:** an `audit` table in `state.db` (migration 2): `seq`, `ts`, `actor`, `actor_kind` (`session`, `token`, `basic`, `system`), `remote`, `action`, `target`, `detail` (JSON), `reason`, `prev_hash`, `hash`. `hash = BLAKE3("telltale-audit-v1" ‖ prev_hash ‖ seq ‖ ts ‖ each field with a presence byte and length)`, genesis `prev_hash` = 32 zero bytes. SQLite triggers abort UPDATE and DELETE. Verification recomputes every hash and link and also checks that `seq` has no gaps; truncation at the end is caught by comparing the head hash with a copy kept elsewhere (documented).
- **What is recorded now:** `user.create|update|delete`, `user.password`, `user.totp.enable|disable`, `token.create|revoke`, `auth.login` (successful sign-ins), `auth.lockout` (the first lock of a username or address, not every failed attempt, so a password-guessing run can't flood the log), first-admin creation by setup token or bootstrap environment, and `config.reload` (the dotted paths of changed settings, never values: configs may hold secrets). Updates record `{field: {from, to}}`; passwords and secrets appear only as `"changed"`.
- **Attribution:** sessions and Basic record the username; API tokens record `token:<name> (owner: <user>)` (AGT-005); an optional `X-Telltale-Reason` header (trimmed to 500 characters) is stored as the reason (required for agents once plan/apply exists).
- **Failure handling:** the change happens first and the entry is appended after; if the append fails, the error is logged rather than undoing the change (the audit store is the same SQLite file, so this is rare). Moving to "write the entry in the same transaction" comes with the config-edit API, where it matters most.
- **Access:** admins only (`GET /api/v1/audit` with cursor paging and action-prefix/actor filters; `GET /api/v1/audit/verify`), the UI's Settings → Audit log, and `telltale audit list|verify` offline. No retention: entries are small and the log is append-only by design.
- **Deferred:** cluster replication (M5, with the config change log), MCP client name/version in entries (with the MCP server), signed head checkpoints.

**Consequences:** Sign-in administration and reloads are accountable now, and every future mutation endpoint gets auditing by calling `Auth::record` with a diff.

## ADR-034 — OIDC sign-in: library, flow, and account rules (Accepted)
**Context:** API-004 / `08` §6: Authorization Code + PKCE, discovery, multiple providers, claim → role mapping, JIT provisioning, optional verified email, back-channel and RP-initiated logout, ID-token validation with JWKS rotation, local sessions after sign-in, a canonical `public_url`, and `disable_local_login` with a break-glass admin from `allowed_admin_networks`. AC: integration tests against Keycloak and Authentik.

**Decision:**
- **Library (superseded by ADR-951, which replaces `openidconnect` and `oauth2` with an in-tree verifier on `ring`):** `openidconnect` 4 (the `02` §7 crate) without its bundled HTTP client. The binary supplies requests through the list fetcher's existing hyper + rustls client (system resolver, Mozilla roots, no redirects followed, 1 MiB, 15 s), so no second HTTP/TLS stack. Cost: ~0.6 MB gzip on the binary (RSA/EC/Ed25519 verification crates). `cargo deny` flags RUSTSEC-2023-0071 (`rsa`, Marvin timing attack): it concerns RSA *private-key* operations; TelltaleDNS only verifies ID-token signatures with providers' public keys and holds no RSA private key, so the advisory is ignored in `deny.toml` with that justification, to be revisited when a fixed `rsa` ships.
- **Flow:** `GET /api/v1/auth/oidc/{id}/start` (302 to the provider with PKCE S256, state, nonce) and `GET .../callback`. Flow state lives in memory for 10 minutes (max 1,000), keyed by `state` and bound to the starting browser by an HttpOnly `SameSite=Lax` cookie (Strict cookies aren't sent on the provider's redirect back), so a callback can't be replayed or completed in another browser. `returnTo` must be a UI hash route (no open redirect). Failures redirect to `/#/?loginError=...`.
- **Validation:** `openidconnect` checks signature (provider JWKS), issuer, audience, expiry, and nonce; allowed algorithms are the asymmetric ones (RS/PS 256–512, ES256/384, EdDSA), never HMAC. Discovery (with keys) is cached for an hour and refreshed once when a signature doesn't verify (key rotation). Custom claims (groups, nested `realm_access.roles`) are read from the verified token's payload; claim paths are dotted.
- **Accounts:** users are keyed by (provider, `sub`) (`state.db` migration 3) and created on first sign-in with an unusable password; the username comes from `preferred_username` (or `username_claim`, then `email`, then `sub`). A provider account is never attached to an existing local account by name (that would let a provider-side rename take over an account); a clash yields `name@provider`. The role is the highest any group maps to (`default_role` otherwise; none: refused), re-evaluated at every sign-in and audited when it changes. TOTP is the provider's job for these accounts. Disabled accounts stay disabled.
- **Sign-out:** RP-initiated with `client_id` and `post_logout_redirect_uri = <public_url>/` (from discovery's `end_session_endpoint`). No `id_token_hint`, to avoid storing ID tokens; Keycloak therefore asks for confirmation, and Authentik's default invalidation flow shows its own page. **Back-channel logout is deferred** (needs provider session IDs and a token endpoint for logout tokens; sessions are short and local).
- **Break-glass:** `disable_local_login` refuses password sign-in and HTTP Basic except for admins from `allowed_admin_networks` (default: private networks and loopback); `/auth/status` tells the UI whether to show the password form for this client.
- **Tests:** an in-process fake provider (discovery, JWKS, token endpoint, RS256 tokens) covers the flow in unit tests; `ui/tests/oidc/compose.yml` runs Keycloak 26.4 and Authentik 2025.10.1 with fixtures, and the `oidc` CI job runs the Playwright spec against both (admin, viewer, refused user, sign-out).
- **Proxies:** `[api] trusted_proxies` (default none): for requests from those addresses, the client is the rightmost `X-Forwarded-For` entry that isn't a trusted proxy (entries further left are client-controlled). Without it, everything behind an ingress shares the ingress address: one client's failed sign-ins would lock out everyone, and audit entries and break-glass checks would see the proxy. `X-Forwarded-Proto: https` keeps setting the cookie's `Secure` flag (ADR-029).
- **Resilience:** a provider that can't be set up (missing secret file) is logged and skipped; password sign-in and the API keep working.
- **Deferred:** back-channel logout, multiple redirect URIs per node (cluster nodes share `public_url` for now), OAuth for agents (AGT, P1).

**Consequences:** Homes and labs with an identity provider sign in with it; local passwords become optional. Each provider must be registered with the exact redirect URI.

## ADR-035 — Helm chart: allInOne first, client-IP proof in CI (Accepted)
**Context:** T4.1 / OPS-002/003 asks for `allInOne`, `scaled`, and `daemonSet` shapes, Services with `externalTrafficPolicy: Local`, PDB, HPA, probes, NetworkPolicy, ServiceMonitor, cert-manager, `existingSecret` everywhere; AC: `ct install` on kind and k3d arm64, DNS via the LB, and client IPs preserved in the query log in an e2e test. Clustering (M5) doesn't exist yet.

**Decision:**
- **Shapes:** only `allInOne` (one StatefulSet with a volume) until M5. `scaled` and `daemonSet` need a controller to distribute filter snapshots and share users/sessions; without it every replica would compile its own lists and keep its own sign-in state, so sign-in would break across replicas. `values.schema.json` refuses the other modes with that reason. HPA and PDB belong to `scaled` and come with it (a PDB on one replica only blocks node drains).
- **Ports:** in the pod's own network the container listens on 5353 and the Service maps 53 → 5353 (no capability needed). `hostNetwork: true` binds 53 on the node, which needs root: the container then runs as UID 0 with every capability dropped except `NET_BIND_SERVICE`, read-only root, no privilege escalation (Kubernetes doesn't grant ambient capabilities to non-root users).
- **Services:** one DNS Service with UDP and TCP 53 (mixed protocols, k8s ≥ 1.26), `externalTrafficPolicy: Local` by default, LB annotations passed through; `NOTES.txt` warns on `Cluster`. A separate API Service (ClusterIP by default; LoadBalancer or Ingress optional) and a ClusterIP metrics Service for the ServiceMonitor.
- **Probes:** startup and readiness on `/readyz` (listeners bound), liveness on `/livez`. No `preStop` sleep: the image has no shell, and the binary already drains on SIGTERM (readiness off first, OPS-007).
- **Secrets:** bootstrap admin from an existing Secret (env vars), any Secret mounted read-only under `/etc/telltale-secrets/<name>` (optional mounts let the pod start without them).
- **Monitoring:** ServiceMonitor, a PrometheusRule with five default alerts, and the Grafana dashboard ConfigMap (the same JSON as `deploy/grafana/`, kept identical by `build.py --check`).
- **cert-manager:** only through the Ingress (annotations); a DoT/DoH `Certificate` comes with those listeners (T4.5).
- **Proof:** `deploy/helm/e2e.sh` creates a kind or k3d cluster with MetalLB, installs the chart, queries through the LoadBalancer from the host (UDP and TCP), and asserts the query log recorded the host's own address on the cluster network, not a node or pod address. CI runs it on kind (amd64) and k3d (arm64), then `ct install` with `ci/*-values.yaml`. The script uses a private kubeconfig (it never changes the caller's current context) and gives k3d its own pod/service ranges so it also runs on a host that is itself a k3s node. Also verified on the owner's homelab (k3s + Cilium LB IPAM): real LAN clients appear with their own addresses.

**Consequences:** One-replica deployments are production-ready on any LoadBalancer implementation; HA within Kubernetes waits for clustering.

## ADR-036 — Guided UI: task-first names, help panels with diagrams, Simple/Advanced (Accepted)
**Context:** The owner (2026-10-04): Pi-hole is easy for non-experts; Technitium is powerful but assumes DNS expertise (zones, SOA, zone types). TelltaleDNS should offer the depth without demanding the expertise, and visual cues should help novices see what an option does. Recorded as API-011.

**Decision:**
- **Names by outcome, jargon as subtitle.** UI features are named for what they achieve; the DNS term appears underneath and in help: "Names on my network" (*local zone / records*), "Send a domain to another server" (*conditional forwarding*), "Block / allow lists" (*filter lists*), "Where answers come from" (*upstreams*). No separate "zones" concept in the UI: local names are grouped by domain, and SOA/NS are generated. Real zone features (import, secondary/transfer, serving a domain to other servers) live under Advanced on the same page.
- **One glossary, many readers.** `docs/help/topics.json` holds each topic: `id`, `title` (outcome), `term` (technical name), `summary` (one sentence), `when` (when you'd want it), `example` (home-network example), `caution` (what goes wrong if misused), `diagram` (kind, optional), `docs` (anchor). The UI imports it, the site renders it as a glossary page, and CI checks every help id used in the UI exists (and every topic is used or marked general). API descriptions stay in code (AGT-001) but use the same terms.
- **Help panels.** A "?" beside any setting opens a right-side panel with the topic in that fixed order (summary, diagram, when, example, caution, term, docs link). Keyboard and screen-reader accessible; no modal blocking the form.
- **Diagrams.** A `FlowDiagram` Svelte component draws inline SVG (no library, CSP-safe, a few KiB): a device, TelltaleDNS, and the possible destinations of a query (cache, local name, blocked, another server, upstream), with the path for this option highlighted and the user's own values filled in (`*.home.example → 10.50.5.122`). The same component illustrates help topics, previews changes before they're saved, and shows the Explain result ("this query went here, because of this rule"). Status colors and labels match the rest of the UI; every diagram has a text equivalent.
- **Simple / Advanced.** Each editing page has a Simple view (common fields, safe defaults) and an Advanced view (everything); the choice is remembered per user. Advanced never hides information that changes behavior: if an advanced field differs from its default, Simple shows a "customized in Advanced" note.
- **Previews and tests.** Every change shows a plain-language sentence plus diagram before saving (built on the API's dry-run, AGT-002), and each rule offers "Test a name" (explain).
- **Experts keep everything.** Config files, API, and CLI expose the full model; the UI never becomes the only way to do something.

**Consequences:** More UI content to write and keep current (one glossary file, checked in CI). The editing pages (T3.12 and later) are designed around this from the start; the read-only pages get help panels and diagrams in T3.11.

## ADR-037 — Masked-client-IP detector: what counts as infrastructure (Accepted)
**Context:** OPS-003 / `spec/08` §3.2: "the resolver detects when > 90% of queries come from ≤ 3 IPs inside the pod/node CIDRs and raises a UI banner". A pod doesn't know the pod or node CIDRs, and on a homelab the node network *is* the LAN, so "inside the node CIDR" would also match real devices.

**Decision:**
- **Window:** the aggregator keeps per-client counts for fixed 10-minute windows (≤ 256 clients each, off the query path). The detector reads the last complete window (or the current one before the first completes). At least 100 queries are needed to judge.
- **Infrastructure** = loopback; this host's default gateways from `/proc/net/route` and `/proc/net/ipv6_route` (inside a container that's the Docker bridge or the pod's gateway, where SNAT'd traffic appears; on a host network it's the LAN router, which matters when the router forwards everyone's DNS); node addresses in `TELLTALE_NODE_IPS` (the chart sets it from `status.hostIP`); and `[clients] infrastructure` networks for anything else (pod networks, other nodes).
- **Rule:** masked when the ≤ 3 heaviest clients that are infrastructure sent > 90% of the window's queries. A household whose traffic is dominated by a few real devices is never flagged, because they aren't infrastructure (conservative: a missed warning costs less than a false one).
- **Surfaces:** `clientIpsMasked` in `GET /api/v1/system/info` (share, sources, queries, window start), a UI banner linking to the docs (refreshed every minute), the gauge `telltale_client_ips_masked` with a chart alert after 30 minutes, and one log line per change. Evaluated only on API calls and scrapes.

**Consequences:** Multi-node clusters with `externalTrafficPolicy: Cluster` SNAT to *other* nodes' addresses, which are only recognized when listed in `[clients] infrastructure` (the chart's install notes already warn on `Cluster`).

## ADR-038 — Native installs: release assets, signing, install.sh, self-update, Compose defaults (Accepted)
**Context:** OPS-004 / `spec/08` §4 asks for a static binary with systemd unit and install script that "downloads + verifies (cosign/minisign)", `telltale self-update`, and the Compose bundle of §3.4. No release pipeline existed, and the §3.4 Compose example (`user: 65532` + `cap_add`) can't bind port 53: Docker doesn't give a non-root user ambient capabilities.

**Decision:**
- **Assets:** the image workflow's cached cross-build also exports the static musl binaries (`--target bin`) as `telltale-{x86_64,aarch64,armv7}-linux` plus `SHA256SUMS`. Every push to main replaces the `edge` prerelease; a `v*` tag creates a release and pushes image tags `X.Y.Z`, `X.Y`, `X`, `latest`.
- **Signing: minisign**, not cosign. Ed25519 over `SHA256SUMS`, verifiable offline with a 56-character public key (`deploy/release/telltale-release.pub`, also built into the binary), by `install.sh` (the `minisign` package, installed if missing) and by `self-update` (the `minisign-verify` crate: MIT, no dependencies). Cosign's keyless flow would need Sigstore's trust root and network access in both. The secret key is the repository secret `MINISIGN_SECRET_KEY`; without it releases aren't published (the job warns) rather than published unsigned.
- **install.sh:** POSIX `sh`, root, systemd required. Refuses on any signature or checksum mismatch and test-runs the binary before installing it; creates the `telltale` system user; never overwrites `/etc/telltale/telltale.toml` (the starter config is `deploy/compose/telltale.toml`, shared with Compose); swaps the binary atomically; asks (or `--disable-resolved-stub`) before turning off systemd-resolved's stub; waits for `/readyz`. Stable is the default channel; until a release is tagged it says to use `--edge`.
- **Unit:** a static `telltale` user (not `DynamicUser`, so the CLI can run as the same user against the same files), `StateDirectory=telltale`, `ProtectSystem=strict`, only `CAP_NET_BIND_SERVICE` (ambient and bounding), `@system-service` minus `@privileged`, netlink allowed (neighbor table), `MemoryMax=256M`.
- **self-update:** verifies the signature, compares this binary's SHA-256 with the release's (so "up to date" needs no version parsing and works for `edge`), downloads, checks the hash, runs `--version`, keeps `telltale.old`, renames atomically; `--restart` restarts the unit. Refused in containers. No key or URL override in production (the tests call the library with a fixture key).
- **Compose:** host network, read-only root, `cap_drop: [ALL]`, `cap_add: [NET_BIND_SERVICE]`, **as root** by default with `./data` bind-mounted (Docker creates it root-owned; a root process without `CAP_DAC_OVERRIDE` can't write the image's 65532-owned directory, which the e2e caught). Running unprivileged is documented: host sysctl `net.ipv4.ip_unprivileged_port_start=53` + `chown 65532 data`.
- **Health:** `telltale health [--url]` (an HTTP GET to `/readyz`) is the container healthcheck, since the image has no shell.
- **Tests:** CI job `native` runs the Compose bundle (host network, healthcheck, hardening) and `install.sh` against a locally served release signed with a throwaway key: DNS on 53 over UDP and TCP, runs as `telltale`, upgrade keeps the config, a swapped binary and a modified `SHA256SUMS` are both refused.

**Consequences:** The owner must add `MINISIGN_SECRET_KEY` once before the first binaries are published. The cluster-version check of `self-update` (spec §4) waits for clustering (T5.11).

## ADR-039 — DoT and DoH listeners, client IDs from certificates, PROXY v2 rules (Accepted)
**Context:** T4.5 (DNS-002/003) and T4.4 (DNS-020). The spec names SNI and DoH-path client IDs (`<clientid>.dns.example.com`) but not how the server knows which part of the name is the ID, how certificates are reloaded, or how PROXY headers are trusted.

**Decision:**
- **One connection path.** DoT is the TCP listener with a TLS acceptor (ALPN `dot`) in front; the TCP code now serves any stream, so pipelining, out-of-order answers, idle and in-flight limits are identical. DoH is hyper (HTTP/2 by ALPN `h2`, else HTTP/1.1; both already in the tree via axum) over the same TLS setup, calling the same `QueryHandler`. No new crates: rustls, tokio-rustls, hyper, hyper-util, rustls-webpki were already dependencies.
- **Client IDs come from the certificate.** If the leaf certificate has a wildcard name `*.X` and the SNI is `<label>.X`, the label is the client ID. No `server_name` setting to keep in sync with the certificate. The DoH path `/dns-query/<id>` wins over SNI. IDs are one DNS label, lowercased, carried inline in `RequestMeta` (a 64-byte `Copy` value, no allocation).
- **Certificate reload:** each TLS listener polls its two files' (mtime, length) every 10 s and swaps the `CertifiedKey` behind a `ResolvesServerCert`; new handshakes use it, open connections keep theirs; a failed read keeps the old one. Polling (not inotify) works with Kubernetes Secret symlink swaps and needs no new dependency.
- **DoH responses:** `Cache-Control: max-age` = min(answer/authority TTL, negative TTL), `max-age=0` without records. Requests the resolver never sees: wrong path or invalid client ID → 404, wrong media type → 415, other methods → 405 with `Allow`, bad base64url or shorter than a DNS header → 400, body over 64 KiB → 413. A handler `Drop` (e.g. rate limit) → 503.
- **PROXY protocol v2 only, and mandatory when enabled.** A listener with `proxy_protocol = true` reads a v2 header before TLS on every connection and closes connections without one (accepting both would let clients pick their address). v1 text headers are refused. `LOCAL` keeps the socket address. TLVs are skipped. There is no source allowlist: exposure must be limited by the network (documented).
- **Telemetry:** `Proto` gains `dot` and `doh` (metrics labels, query log, aggregates). Rollup rows carry a transport-column count (format version 2); version-1 rows still decode.
- **Helm:** `encrypted.dot` / `encrypted.doh` add ports to the same DNS LoadBalancer (so `externalTrafficPolicy: Local` keeps client IPs), with a certificate from an existing Secret or a cert-manager `Certificate`; pods listen on 8853/8443 unless on the host network.

**Consequences:** Clients must trust the certificate (a public CA, or a private one distributed to devices). DoQ and DoH3 remain skipped until their listeners (M7). *(Update: both shipped in M7, T7.7 and T7.8.)*

## ADR-040 — Config made through the API before clustering: managed entries in state.db (Accepted)
**Context:** API-002 (everything configurable through the API) and API-010 (name a device from the UI) need API writes now. Today the configuration is files only (on Kubernetes, the chart's values), and `spec/12` describes the end state: a change log held by the cluster primary, with GitOps mode refusing writes. Rewriting config files from the server would fight GitOps and lose comments.

**Decision:**
- **Managed entries, merged by name.** Entries written through the API are stored in `state.db` (`managed(kind, name, body JSON, updated, updated_by)`), starting with `client`. At every load (startup, `SIGHUP`, an API write) the effective config is the files plus the managed entries whose names the files don't use. The files are authoritative: file entries are read-only through the API (409), and the API can't create a name the files use.
- **Never breaks DNS.** If the merged config doesn't validate (a group a managed device names was removed from the file), the files alone are used and the reason is logged until it's fixed (rule 5). API writes are validated against the full resulting config before they're stored (422 with the field).
- **Write semantics that map onto the future change log:** one `config_version` counter in `state.db`, bumped by every write and returned as the `ETag` of `GET /clients` and in each response; `If-Match` refuses stale writes (412 `version_conflict`); `?dryRun=true` validates and reports (before/after, warnings, and an impact estimate: recent queries from the matched addresses, from the aggregator's current and previous hour) without storing; `Idempotency-Key` stores the first successful response for 24 h per user and replays it (a different request with the same key is 409). Writes need operator (or a `write` token) and are audited (`client.put`, `client.delete`) with their author.
- **Applying:** the API stores the entry, then asks the main loop to reload (the same path as `SIGHUP`, minus its own audit entry), and answers after the swap.
- **Names are resolved at read time** from the address (the query log stores addresses, not names; the old lookup by the client's index at query time mislabelled history after any client list change), so naming relabels history and live views at once.

**Consequences:** With clustering (M5), the managed table becomes change-log entries on the primary and replicates (CLU-003); GitOps mode will refuse these writes (`409 gitops_managed`). Other kinds (groups, records, routes; T3.12) reuse the same table and endpoints.

## ADR-041 — Importing zones: per-name local records, not a whole-zone authority (Accepted)
**Context:** A typical migration moves an internal `home.example` zone from Technitium (split-horizon: the same domain is public at a cloud DNS host). T6.4 (Technitium importer) covers zones as "local names and routes". Technitium is authoritative for the whole zone (unknown names get NXDOMAIN); TelltaleDNS local records are per name (unknown names go upstream).

**Decision:** `telltale import zone FILE` converts RFC 1035 zone files (Technitium export, BIND, PowerDNS) into `[[record]]` TOML for the supported types (A, AAAA, CNAME, PTR, TXT, MX, SRV), skips SOA/NS at the apex, and lists everything else in a header report; the output is validated as config before it's written. Imported names behave as per-name local records, so unimported names under the zone fall through to the upstreams (the owner chose this: public-only hosts keep working from inside). A "this server owns the whole zone" mode (NXDOMAIN for unknown names) belongs to T3.12's zone-lite view.

**Consequences:** The rest of T6.4 (forwarders and conditional forwarders → upstreams and routes, block/allow lists, and a Technitium API source) remains open. Moving a zone: import, add the records while keeping the route to the old server (local records win over routes, so anything missed still resolves there), compare answers name by name, then remove the route.

## ADR-042 — Names on my network and forwarded domains through the API (Accepted)
**Context:** T3.12 (API-011, DNS-010, UPS-007) needs local names and conditional forwarding editable from the UI and the API, following ADR-040's managed entries.

**Decision:**
- **Two more managed kinds:** `record` (an owner name and the set of its records; a write replaces the set) and `forward` (a domain and its servers). A forward expands at merge time into upstreams `forward:<domain>#n` (a bare address means `udp://`), a `failover` upstream group `forward:<domain>`, and a route for the domain with a DNSSEC negative trust anchor (internal domains are usually unsigned). The names are reserved for this purpose.
- **Files win:** a name with any file `[[record]]`, or a domain any file route matches exactly, is read-only (409). Validation runs the whole merge (files + every API entry + this change) through config validation and the local-record value parser, so a bad value is a 422 with the field, before anything is stored.
- **Zone-lite, not zones:** the UI groups names by their parent domain and never asks for SOA or NS. Per-name answers fall through to upstreams for unknown names (ADR-041); a whole-zone authority mode stays deferred.
- **Endpoints:** `GET /records`, `PUT`/`DELETE /records/{name}`, `GET /forwards`, `PUT`/`DELETE /forwards/{domain}`, with the device endpoints' dry-run, `If-Match`, idempotency, operator role, and audit (`record.put`, `forward.delete`, ...). The write path is shared code.
- **Applying** reuses the reload path; a forward change rebuilds the upstream router (health state of unchanged upstreams is rebuilt too, as on any upstream change).

**Consequences:** The UI covers the common cases without the config file. Hosts files stay file-only. The MCP tools for these writes come with T6.6 / M7.

## ADR-043 — Anomaly engine v1: concrete detectors, thresholds, and persistence (Accepted)
**Context:** T3.13 implements OBS-013 under ADR-019 and `spec/06` §7.1, which fix the principles (deterministic, explainable, learn first, bounded, alert-only) but not the statistics, thresholds, or how state survives restarts.

**Decision:**
- **Statistics:** exponentially weighted mean and mean absolute deviation (MAD-style) per baseline, `f32`, plain IEEE arithmetic only (no `exp`/`ln`), FNV-1a hashing, ordered maps, event-time windows (an hour closes when an event from a later hour arrives). Findings are byte-identical across runs and architectures (a golden file checked on x86-64 and arm64 in CI).
- **Detectors and bars** (sensitivity `normal` = 6 × spread; `low` 8, `high` 4): rate spike per hour of day (≥ 300/h, ≥ 2× usual, > usual + k·spread; spread ≥ max(10, 25% of usual)); domain volume per tracked (device, eTLD+1) pair (≥ 200/h, ≥ 3× usual, pair tracked ≥ 24 h; spread ≥ max(5, 25%)); drift (≥ 20 new registrable domains a day, > usual + k·spread; day one isn't part of the baseline); beacon (≥ 10 gaps of 30 s–1 h with σ ≤ max(5% of the period, 2 s) for 4 consecutive hours, only when the pair wasn't periodic during learning, which keeps TTL-driven refreshes quiet). A rate spike that domain findings explain (≥ 50% of the excess) is reported only as those. Alerted windows don't update their baseline.
- **eTLD+1** is approximated without the Public Suffix List: the last two labels, or three under common second-level suffixes (`co.uk`, `com.au`, ...); reverse names are skipped.
- **Bounds:** 16 tracked pairs, 128 learned fingerprints, 24 hourly baselines per device (≤ 4 KiB, tested); 1024 devices by default, least recently seen evicted (counted).
- **Persistence:** the whole engine as JSON in `<data_dir>/anomaly.json`, written hourly and on shutdown (temp file + rename); `float_roundtrip` keeps reloads bit-exact. Unreadable state just restarts learning.
- **Surfaces:** `GET /api/v1/analytics/anomalies?since=`, the Anomalies page, `telltale_anomalies_total{kind}` with a chart alert (`TelltaleDNSDeviceAnomaly`, info), and later the `find_anomalies` MCP tool (T6.6). Off at privacy level 3.

**Deferred:** the TTL-violation flag (events don't carry answer TTLs yet), per-group sensitivity, mute/acknowledge, and the alert-rule engine's own destinations (OBS-010).

## ADR-044 — Cluster channel v1: identity files, reusable join tokens, and peer trust (Accepted)
**Context:** T5.1 implements CLU-001 under `spec/12` §3, which fixes the shape (Ed25519 CA, join token with CA fingerprint + URLs + secret, 90-day node certificates, mTLS over HTTP/2 with protobuf, persistent streams, replicas dial out) but not the token format, how peers name each other in TLS, where identity lives, or whether a token is single-use.

**Decision:**
- **Token:** `tt_join_` + base64url(JSON `{v, cluster_id, cluster_name, ca_fp, urls, secret, exp}`) (the spec's `vgl_join_` predates the rename). Tokens are **reusable until they expire**, because `spec/12` §3 has every Kubernetes pod join with one long-lived token from a Secret. The primary stores only SHA-256 hashes of token secrets (`tokens.json`) and compares them in constant time.
- **Join:** the joining node pins the CA by fingerprint against the chain the server sends (CA included), so the secret is never sent to a server outside the cluster. The primary picks the certificate's names itself, ignoring names in the CSR.
- **Peer names:** every node certificate carries `cluster.telltale.invalid` and `<node-id>.node.telltale.invalid` (plus its advertise hosts). Peers verify against the cluster CA and the shared name, so trust doesn't depend on the address a peer was dialed at (LAN IP, ingress, NAT). The peer's node ID comes from its certificate, and its Hello must match it. Node ID = the first 16 hex digits of SHA-256(public key).
- **Identity on disk:** `<data_dir>/cluster/{cluster.json, ca.crt, node.crt, node.key, ca.key (primary only), tokens.json}`, keys mode 0600, atomic writes. `telltale cluster init|join` write it, and the server reads it at startup (a restart joins the channel).
- **Wire:** 4-byte big-endian length + prost `Frame{Hello|Heartbeat}`, 1 MiB frame limit, `POST /cluster/v1/stream` with a streaming body in both directions, heartbeats every 5 s, peer down after 15 s, reconnect with full-jitter backoff (1 s doubling to 30 s). `POST /cluster/v1/join` is the only route served without a client certificate.
- **Port:** `[cluster] listen`, default `0.0.0.0:8443` per `spec/12`. That is the same port our docs use for DoH, so `telltale config check` warns about the clash rather than changing either default.
- **Dependencies:** `prost` is new (pure Rust; frames only, no codegen step); `rcgen` moves from dev-only to runtime for issuing certificates.

**Deferred:** certificate renewal at 2/3 of life and CA rotation (with T5.4 promotion, since only the CA holder can issue), eligible-to-eligible streams, and ephemeral Kubernetes members joining from a Secret at startup (T5.10). The cluster health page and per-peer lag (T5.9); heartbeats carry `qps`, which is still 0.

## ADR-045 — Sign-in across cluster nodes: replicated identities, per-node sessions and OIDC callbacks (Accepted)
**Context:** `spec/12` §6 says users, RBAC, and OIDC config are part of the replicated config, so sign-in works on every node even with the primary down. It doesn't say where sessions live, how one OIDC client serves several nodes reached at different URLs, or what happens to users that already exist on a node that joins (the owner's homelab node has its own users, and the Pi got its own admin before clustering).

**Decision:**
- **Replicated from the primary (with T5.2, writes forwarded by T5.7):** local users (Argon2id hashes, roles, TOTP secrets), API-token hashes and scopes, OIDC provider settings and group-to-role rules, and the session-revocation list. So a break-glass local admin works on every node, even when the identity provider is down.
- **Per node, never replicated (CLU-006 node-local keys):**
  - `auth.oidc.public_url`, because each node is reached at its own URL, and each one is registered as a redirect URI on the same OIDC client (`<public_url>/api/v1/auth/oidc/{id}/callback`);
  - the OIDC client secret file, because secrets stay in each node's own Secret or file and never cross the cluster channel.
- **Sessions are per node.** Signing in to a second node with SSO is a silent redirect (the provider already has a session). There is no shared session-signing key to protect or rotate. Sign-out and revocation replicate, so revoking a user ends their sessions everywhere within one sync.
  - If the owner later puts one hostname in front of several nodes without sticky sessions, cluster-signed session tokens (signed with the cluster key) are the follow-up; that's not needed for the hybrid Pi + k8s setup.
- **Join merges identities once:** on its first sync, a joining node offers its local users and tokens to the primary.
  - A user that doesn't exist on the primary is added.
  - A name that exists on both keeps the primary's record, and the joiner's copy is listed under Conflicts. Nothing is silently dropped.
  - After that, the primary is the only source.

**Consequences:** the owner registers one extra redirect URI in Authentik per node (for the Pi, e.g. `https://dns.home.example`, or its LAN address). The Pi's OIDC needs its own copy of the client secret.

**Implementation (T9.1, 2026-10-06):**
- Users, recovery codes, and tokens travel as one JSON blob (`identities.json`) named by the signed manifest. Replicas take it in one transaction, keyed by user name; rows carry an `origin`: `cluster` or `local`.
- Changed from the decision above, to keep the change small: replicas **refuse** identity changes (409, naming the primary's site) instead of forwarding them.
- Changed from the decision above: users only on a replica **stay local** instead of being offered to the primary once. They keep working on that node; to share one, make it on the primary.
- A name on both nodes takes the primary's record (logged), as decided.
- The OIDC provider settings already replicate with the shared configuration. The session-revocation list isn't needed: deleting or disabling a user on the primary removes or blocks them everywhere on the next sync, and with them their sessions.

## ADR-046 — Version management: one build identity, a signed release index, and update status everywhere (Accepted)
**Context:** owner request 2026-10-04: the user should always know which version they run, which versions exist, and whether they're on the latest, the same way on every architecture and install type. Today an edge binary reports only `telltale 0.1.0` (the Pi shows exactly that), so two different builds look identical, and nothing tells the user an update exists.

**Decision:**
- **One build identity, stamped by CI into every artifact from the same commit** (the amd64, arm64 and armv7 binaries and the multi-arch image):
  - **version:** the tag's semver for releases; `<next>-edge.<run>` for main builds, e.g. `0.1.0-edge.47`;
  - **commit:** short SHA;
  - **build date**, and **channel** (`stable` or `edge`);
  - **target:** e.g. `aarch64-unknown-linux-musl`;
  - **install type:** `native`, `container` or `helm`, from an environment variable the systemd unit, Dockerfile and chart set.
  `telltale --version` prints all of it on one line. A local dev build says `dev` and its commit, so it's never mistaken for a release.
- **Where it shows:**
  - the UI footer and an About/Updates panel under Settings;
  - `GET /api/v1/system/info` (`build {...}`);
  - the metric `telltale_build_info{version,commit,channel,target} 1`;
  - each node's Hello on the cluster channel, so the Cluster page lists every node's version and flags mixed versions (CLU-010: N/N-1 only, replicas upgrade first);
  - an MCP tool later.
- **Which versions exist:** every release publishes a signed `releases.json` next to `SHA256SUMS`, signed with the same minisign key. It lists the channel, version, date, commit, notes URL, assets per architecture with hashes, and the oldest version it can upgrade from. The `edge` index lists the latest main build. Clients trust only a verified index, never the GitHub API's unsigned listing.
- **Latest or not:** a node fetches its channel's index once a day (`[updates] check = true` by default; off for air-gapped or privacy-strict sites; through the normal HTTP client, never blocking DNS) and compares semver within its channel; edge compares by run number.
  - **Status:** `up to date`, `update available <version> (<date>)`, `newer than the index` (a dev build), or `unknown` (check off or failing; the last success time is shown).
  - The status is in the UI, in system info, and in `telltale_update_available 0|1`, with an optional info-level alert.
- **How to update, per install type:** the panel shows the right step. Native: `sudo telltale self-update --restart`. Compose: `docker compose pull && docker compose up -d`. Helm: the chart version and `helm upgrade`, or bumping it in GitOps values. A cluster gets the replicas-first order.
  - The UI never self-updates a node: replacing the binary needs root, and container installs are the orchestrator's job.
- **Architecture independence:** one index serves all architectures; a node picks its asset by target. Versions and commits are identical across architectures because CI builds them all from one commit in one workflow (already true of `image.yml`). The image tag and the binary version always match.

**Consequences:** small CI changes (stamp the version; generate and sign `releases.json`), a `[updates]` config section, and the API/UI/metric fields. `telltale self-update` switches from reading `SHA256SUMS` to reading the index (same signature check).

**Addendum (2026-10-05, T6.9 implemented):**
- **Stamping:** `crates/telltale/build.rs` reads `TELLTALE_BUILD_{VERSION,COMMIT,DATE,CHANNEL}`. CI computes them once per run and passes the same `--build-arg`s to every buildx call, so all three architectures (and the image) carry one identity, which `image.yml` checks in each binary. Edge is `<Cargo version>-edge.<run number>`, a tag is its semver, and a PR build is `-pr.<run>` on channel `dev`.
- **Install type:** the image sets `TELLTALE_INSTALL=container`, the chart `helm`, and the systemd unit `native`. Without it, the binary guesses from `/.dockerenv` or the Kubernetes environment.
- **Release index:** `deploy/release/index.py` writes `releases.json` (channel, version, commit, date, notes, and per-target asset names and hashes from `SHA256SUMS`). It's signed and verified in the release job next to `SHA256SUMS`.
- **Update check:** nodes fetch `releases/download/edge/releases.json` (edge) or `releases/latest/download/releases.json` (stable), plus `.minisig`, and verify with the built-in key. Edge builds compare by run number, and a release sorts after its edge builds. The first check is 60 s after start, then daily, retrying hourly after a failure.
- **Not yet:** `self-update` still reads `SHA256SUMS` (it works and is verified the same way). Moving it onto the index is a follow-up, as is an MCP tool for update status.


## ADR-047 — Config replication v1: whole-version manifests, shared vs node-local sections (Accepted)
**Context:** T5.2 implements CLU-003 under `spec/02` §5 and `spec/12` §4. Those describe a change log of semantic ops (JSON-Patch) that replicas replay, with a full snapshot as fallback. They don't say which settings are node-local before T5.5, how UI/API-made entries (ADR-040) replicate, or what a replica does with its own lists and config file.

**Decision:**
- **Whole versions, not ops (for now).** Each change produces a new manifest `(epoch, seq)` naming the complete shared configuration as one blob (canonical JSON, a few KB) and the filter snapshot's blobs. A replica converges to the newest manifest from any state, including after a long partition, with no log to replay or compact. BLAKE3 content addressing keeps transfers incremental: a config change ships one small blob, and a list change ships only the FST shards that changed.
  - **Measured:** p95 190 ms over a simulated 50 ms RTT (the AC is 5 s). On two local processes, a primary edit was answered by the replica 0.39 s later.
  - The per-change log (author, op, timestamp) with orphan detection is still needed for fencing and conflicts (T5.4); it will ride alongside, recording what each version changed.
- **Shared vs node-local:** node-local = `config_version`, `node`, `cluster`, `listen`, `api`, `auth`, `telemetry`, `cache` (a superset of CLU-006's list: sign-in stays local until ADR-045 replicates identities). Everything else is the primary's *effective* configuration: files plus UI/API entries (ADR-040), so devices named on the primary reach every node.
  - A setting the replica doesn't recognize (a newer primary) fails validation, and the replica keeps its last version rather than dropping it silently.
  - T5.5 adds the explicit `node.toml` allow-list and the startup error for overriding shared keys.
- **Signing:** manifests are signed with the cluster CA's Ed25519 key and verified against the CA certificate every node already has. `spec/12` mentions a separate signing key rotated with the CA; this reuses the CA key until CA rotation (T5.4) needs the split.
- **Replica behavior once synced:**
  - its effective configuration = its own node-local sections + the primary's shared ones;
  - its own list fetcher stops, and it installs the primary's snapshot as `snapshots/<version>`;
  - it refuses API config writes with 409 `conflict` naming the primary, until T5.7 forwards them;
  - it records the applied manifest in `cluster/applied.json` and serves it at cold start without contacting the primary (CLU-004).
  - Until its first sync, a new replica runs on its own configuration (DNS keeps filtering while it joins).
- **Primary:** checks twice a second for a changed shared configuration (by hash) or a new snapshot, and republishes with `seq + 1`, persisted in `cluster/published.json`. Peers get the current manifest when their stream connects, and every new one at once. Replicas report their applied `seq` in a heartbeat sent immediately after applying, so lag is visible without waiting for the 5 s tick.

**Consequences:** with the Pi as primary, the homelab node's GitOps values for shared sections stop applying once it syncs. The Pi's config file (or UI) becomes the place to change shared settings, until write forwarding (T5.7) and a GitOps primary option are settled with the owner.

## ADR-048 — Config authority: the cluster, not whichever node is primary, decides where configuration comes from (Accepted)
**Context:** owner question 2026-10-04: in a mixed cluster (a Kubernetes node managed by GitOps plus a Pi edited by hand), nothing stops the wrong node from becoming primary, by `cluster init` on it, a promotion during an outage (T5.4), or a quorum election. That node would then replicate its own file over the GitOps one: every node follows a config nobody committed, and the next GitOps sync fights it. Recency or availability must not decide what the source of truth is; the operator does, once.

**Decision:**
- **The cluster records its config authority** in its signed cluster state, set at `cluster init`. It is either:
  - `gitops`, which names the source (e.g. `gitops-repo:charts/argocd-apps/values.yaml#telltaledns`); or
  - `api`: the primary's file plus UI/API edits, as today.

  The authority can only be changed by an explicit, audited `telltale cluster set-authority` run on the current primary, which bumps the epoch.
- **Each node declares how its own configuration is managed** with `[cluster] config_source = "gitops" | "file"` (the Helm chart sets `gitops`), and reports it in its Hello. The Cluster page shows it next to every node.
- **Only matching nodes may be primary.**
  - Under `gitops` authority, only `gitops` nodes are eligible to publish configuration: `cluster init` on a non-GitOps node refuses `--config-authority gitops`, and elections and promotions skip ineligible nodes.
  - Under `api`, any eligible node may be primary.
- **Emergency primaries never change configuration.** If every authority-matching node is down, an operator may still promote another node (`telltale cluster promote --emergency`). It keeps nodes coordinated (leases, certificates, alerts) but publishes nothing new.
  - Every node keeps serving the last authoritative version, the API stays read-only, and the UI says so ("GitOps primary unreachable since …").
  - When an authority-matching node returns it takes over again automatically; the emergency primary had no writes, so nothing is orphaned.
- **Manifests carry their provenance:** the authority, the source, and, for GitOps, the revision (commit) the primary loaded. A replica rejects a manifest whose authority differs from the cluster's. The UI shows "configuration from gitops-repo @ <commit>" on every node.
- **GitOps write rules** (OPS-005) apply cluster-wide: under `gitops` authority, API config writes on any node return `409 gitops_managed`. Operational actions (pause blocking, flush cache, list refresh) still work. Node-local settings stay in each node's own file in both modes.
- **Mixed architectures are supported.** Every replicated blob is architecture-independent: the FSTs, list sets written as explicit little-endian, and JSON. The cluster's anomaly golden-file check already runs on amd64 and arm64. A cross-architecture snapshot test (compile on amd64, load and match on arm64 and armv7) joins CI with T5.11.

**Consequences:**
- A misconfigured or recovering node can't silently take over the configuration.
- The price is that with a GitOps authority, configuration is frozen (never lost or wrong) while no GitOps node is up. That is the right trade for a homelab where the k8s node is the one being changed.
- Implemented with T5.4 (elections and promotion) and T5.7 (writes); until then the owner's cluster uses the convention of the homelab node as primary, set up by hand.

**Amended 2026-10-08 (review 05-04; amendment Proposed):** the takeover promised above now works by hand: `promote` is allowed over a running primary only when it is the emergency primary of the version this node applied and this node would publish; its newer epoch fences the emergency primary, which had no writes. The Cluster page offers it on a Git-managed replica. The automatic takeover is still open (an owner question).

## ADR-049 — Git as the cluster's config source: the primary fetches, the cluster distributes (Accepted)
**Context:** owner idea 2026-10-04, building on ADR-048: let nodes that aren't in Kubernetes (the Pi) also take their configuration from the Git repository, an "external control plane" every node sources from. Two shapes were weighed:
1. **Every node pulls Git.** Rejected as the default:
   - nodes poll on their own schedules, so they run different commits for a while and "which config is live?" has no single answer;
   - every node needs repository credentials, outbound internet, and a Git client;
   - a GitHub outage or rate limit hits each node separately;
   - the DNS server has to resolve the forge's name to fetch its own config.
2. **Git is the authority; the cluster distributes.** Chosen.

**Decision:**
- **A `git` config source.** On the primary, `[cluster.config] source = "git"` with `repo` (HTTPS), `ref` (branch or tag), `path` (a TelltaleDNS TOML file holding the *shared* sections), an optional `credentials_file` (read-only deploy key or token, never in the repo), and `poll` (default 60 s; a push webhook endpoint can trigger a fetch early).
- **The primary fetches; the cluster distributes.**
  - The primary fetches the file at the ref's current commit, over HTTPS through the bootstrap resolvers (as list downloads do, UPS-009).
  - It validates the file merged with each node's local sections and publishes the result as the usual signed manifest (ADR-047), recording provenance: repo, path, commit SHA, commit author, and commit time.
  - Replicas follow over the cluster channel unchanged, so every node converges to the same commit, lag is visible, and nodes keep the last good version when GitHub or the link is down (CLU-004).
- **Any Git-capable node can be primary.** Under ADR-048, a `gitops` authority now names the repository rather than a kind of node. Any eligible node that has the source configured and can reach it may publish: the Pi becomes a valid primary for a GitOps cluster, which removes most of ADR-048's frozen-config case. A node configured without the source stays ineligible.
- **Guardrails:**
  - **Pinned source:** `repo`, `ref` and `path` are pinned in the signed cluster state; changing them is a `cluster set-authority` operation.
  - **Optional commit signatures:** `require_signed = true` with an allowed-signers file (SSH or GPG keys) accepts only commits signed by those keys. Without it, anyone who can push to the repository controls DNS on every node, which is already true for Argo-managed nodes; this makes it explicit and enforceable. The UI and docs recommend it.
  - **Validate before publish:** a commit that fails validation is never published; the cluster stays on the last good commit and raises an alert naming the commit and the error.
  - **History only moves forward:** a force-pushed or rewound ref is refused unless `allow_rewind = true` (rollbacks are new commits).
  - **Bounded fetch:** size limit, timeout, TLS with system roots, no submodules, no LFS.
  - **No secrets in the repository:** config refers to secret files (as `client_secret_file` already does).
  - **Audit:** every published commit is in the audit log with its SHA and author.
- **Direct-pull fallback (off by default):** `[cluster.config] direct_fallback = true` lets a replica cut off from every primary for longer than `fallback_after` (default 1 h) fetch the same pinned source itself, with the same signature and validation rules. It applies the result locally only, and drops it when the cluster channel returns.
- **Repository layout:** the shared configuration lives in a plain file (e.g. `telltale/shared.toml`) instead of TOML embedded in Argo values. The k8s chart reads the same file (an Argo multi-source app, or the chart's `configFiles`), so one artifact feeds both the primary's Git source and Kubernetes. Each node's own settings stay in its local config or Helm values.
- **Writes:** under a Git source the API is read-only for shared configuration (`409 gitops_managed`, OPS-005). The UI offers "propose this change" as a patch or a link to the file on GitHub, never a direct commit (writing to the repository is out of scope for v1).

**Consequences:**
- Config changes for the whole cluster are Git commits, reviewed and versioned like the rest of the homelab.
- The cluster runs one fetcher, and every node shows which commit it serves.
- New: a small Git-over-HTTPS fetch (no Git binary), signature verification (SSH signatures via the existing crypto, GPG optional), and a webhook endpoint.
- Builds on T5.2 (replication) and T5.4 (authority and elections); it is T5.12.

**Implementation notes (T5.12, 2026-10-05):**
- **Configuration:** the settings are `[cluster.git]` (`repo`, `ref`, `path`, `credentials_file`, `poll_secs`, `require_signed`, `allowed_signers_file`, `allow_rewind`, `max_bytes`, `webhook_secret_file`), node-local, rather than `[cluster.config] source = "git"`.
- **Authority:**
  - A Git source makes the published authority `gitops`, so the existing `409 gitops_managed` and promotion rules apply.
  - A node with `[cluster.git]` counts as Git-managed (`config_source` reported as `gitops`).
- **Pinning:**
  - The manifest carries `source` (repo, ref, path, commit, author, time, subject, signer), and replicas store the pin.
  - A promoted node whose `[cluster.git]` differs refuses to fetch and says so; changing the source means changing it on the primary.
- **Transport:**
  - `telltale-git` speaks protocol v2 over smart HTTP: `ls-refs`, a commits-only fetch for the history check, a blob-less fetch for the tree, then the one blob. It handles packfiles with deltas, with `miniz_oxide` the only new dependency.
  - Plain `http://` is accepted only on loopback, for tests.
  - Verified against github.com and against real `git upload-pack` in tests.
- **First start:** before the first good commit, a Git primary publishes nothing, so a fresh primary never pushes an empty configuration. It serves the last version it applied.
- **Alerts:** `TelltaleDNSGitCommitRefused` and `TelltaleDNSGitSourceFailing`. Metrics: `telltale_cluster_git_*` and `telltale_cluster_config_commit`.
- **Deferred:**
  - the direct-pull fallback;
  - GPG signatures (SSH signatures only);
  - the UI's "propose this change";
  - the Helm chart reading the same `shared.toml` (use an Argo multi-source app meanwhile).

## ADR-050 — Network groups: groups match subnets, and groups are an analytics dimension (Accepted)
**Context:** owner request 2026-10-05: categorize devices by VLAN (Management 192.168.1.0/24, IOT .2, AUX .3, LAB .5, SONOS .6, Surveillance .7, Trust .10) and see, per category, what traffic each kind of device makes.
- **Today:** a subnet can only be matched by a `[[client]]` entry (`match = ["10.20.2.0/24"]`). That entry also *names* every device in it, so the query log would show "IOT" instead of each device.
- **Groups:** they carry filtering (their lists, block mode), but they're not a first-class dimension in analytics. Per-group data exists internally (time series and blocked counters) without a UI or API around it.

**Decision:**
- **`[[group]] networks`:** a group lists the IPs and CIDRs whose devices belong to it, e.g. `networks = ["10.20.2.0/24"]`. A device gets the group of the most specific matching network.
  - An explicit `[[client]]` entry with `groups` still wins.
  - A `[[client]]` entry *without* `groups` keeps its network's group: naming a device no longer moves it to `default`.
  - Networks must not overlap at the same prefix length (validation error naming both groups).
  - Groups without `lists` keep using every list, so grouping for visibility never changes filtering unless the owner says so.
- **Groups as a dimension everywhere:**
  - the dashboard gets a "Traffic by group" chart and a group filter for every widget (top domains, top blocked, top clients, latency);
  - the query log gets a group filter and a colored group chip per row;
  - the Groups page shows each group's networks, active devices, queries, block rate, and top domains and blocked names;
  - anomaly findings name the group;
  - the API gets `group=` on stats, top, and query endpoints;
  - each group has a color, used consistently in charts and chips;
  - metrics: `telltale_group_queries_total{group,status}` (bounded: groups are capped at 64), next to the existing `telltale_blocked_total{group,list}`.
- **Replication:** groups and networks are shared configuration (ADR-047), so every cluster node attributes devices the same way.
- **Later:** importing VLANs from a router (UniFi networks, OPNsense interfaces) into groups, with the router integrations (M8). The owner's UniFi connector makes this a natural follow-up.

**Consequences:** "which kinds of devices talk to what" becomes one click (e.g. IOT: 38% of queries, 21% blocked, top: amazon devices and Roku telemetry). Per-device names keep working inside each group. The owner's setup needs seven `[[group]]` entries in gitops-repo and nothing else.

## ADR-051 — Manual failover v1: roles and epochs, key sharing with eligible nodes, fencing, orphaned versions (Accepted)
**Context:** T5.4 implements CLU-005 under `spec/12` §5 and ADR-048. The owner's topology is two eligible nodes and no witness, so the `manual` mode comes first: T5.4 is split into **T5.4a** (manual promotion, fencing, conflicts, config authority) and **T5.4b** (witness and quorum election with leases, plus the `telltale-sim` partition checker). T5.1–T5.2 tied "primary" to "holds the CA key", which makes promotion impossible.

**Decision:**
- **Role is explicit:**
  - `cluster.json` gains `role` (`primary` or `replica`) and the `epoch` the role belongs to.
  - A node publishes only while it's `primary` in the highest epoch it has seen.
  - Every Hello, heartbeat and manifest carries the sender's epoch.
- **Signed member registry:** each manifest carries the node registry (ID, site, eligible, advertise URLs), signed with everything else. The primary records nodes as they join (`nodes.json`). Every node then knows every eligible node and its URLs, so replicas can find a new primary without a new token.
- **Eligible nodes hold the signing key** (`spec/12` §4).
  - The primary sends the CA key over the mTLS stream to peers that the registry marks eligible and that are connected with a certificate for that node ID.
  - It's stored owner-only like the primary's.
  - Non-eligible nodes (Kubernetes resolver pods, CLU-009) never receive it.
  - A promoted node can then sign manifests and issue certificates. Compromising an eligible node compromises the cluster, which is the same trust the spec gives eligible nodes. Rotation comes with the CA rotation in T5.4b.
- **Who dials whom:**
  - Replicas dial the current primary: the highest-epoch node known as primary first, then the other eligible URLs.
  - Eligible nodes also keep a stream to every other eligible node, so a returning old primary learns about a newer epoch right away.
- **Manual promotion:**
  - **How:** `telltale cluster promote` on an eligible node, or the Cluster page's "Promote this node" (admin; T5.7 adds TOTP confirmation).
  - **What it does:** sets `epoch = max seen + 1` and `role = primary`, then starts publishing at once without a restart. The first manifest of the new epoch records its **base**: the `(epoch, seq)` it had applied.
  - **Refused when:**
    - the node isn't eligible;
    - it lacks the key;
    - it's not authority-matching under ADR-048: a `gitops` cluster needs `config_source = "gitops"` on the node, unless `--emergency`.
  - **Emergency primaries** coordinate but publish no new configuration: every node keeps the last authoritative version.
- **Fencing:** a node that sees a higher epoch (in a Hello, heartbeat or manifest) stops publishing and becomes a replica of that epoch's primary at once. Snapshots and manifests from a lower epoch than a replica's applied one are rejected.
- **Orphaned versions** (`spec/12` §5 rule 3):
  - When a fenced old primary had published versions in its epoch after the new primary's base, it keeps the last one under `cluster/conflicts/` (manifest, config blob, and the changed paths compared with the new primary's version).
  - It shows them on the Cluster page under **Conflicts**, and in `GET /api/v1/cluster`. They are never applied silently.
  - Re-applying a conflict on the current primary arrives with write forwarding (T5.7); until then the page shows what changed, and the owner re-makes the change on the primary.
- **Config authority (ADR-048):**
  - `cluster init --config-authority gitops|api` is recorded in the signed registry (default `api`).
  - `[cluster] config_source = "gitops" | "file"` is node-local (the Helm chart sets `gitops`), reported in Hello, and shown per node on the Cluster page.
  - Under `gitops` authority, API config writes return `409 gitops_managed` on every node.

**Consequences:**
- With the owner's homelab node as the GitOps primary, the Pi becomes an *emergency* primary candidate: if k8s is down for long, promoting the Pi keeps the cluster coordinated while configuration stays frozen. ADR-049 (Git source) later makes the Pi a full candidate.
- Existing clusters migrate in place: the CA holder becomes `role = primary` at epoch 1, and eligible replicas receive the key on their next connection.

**Amended 2026-10-08 (review 05-01, 05-02; amendment Proposed):** standing is the primary's decision, not the member's. A join with the bootstrap secret (ADR-058) is always an ephemeral member, never eligible or a witness, so the key share never reaches a resolver pod; a Hello can't raise a known member's eligibility (a member the registry doesn't know is still taken at its word once). Fencing by epoch (Hello, heartbeat, and the election's view of the highest epoch) counts only voters in the signed registry, so a member that can't vote can't make the primary step down with an unsigned frame. A stricter follow-up would fence only on a verified, signed manifest.

## ADR-052 — Node-local overrides: node-only records, and warn (not refuse) on shared settings in a replica's file (Accepted)
**Context:** T5.5 (CLU-006). `spec/12` §4 says a node's own overrides allow listen addresses, cache size, query-log retention, worker count, site, and local-only records, and that overriding anything else is "rejected at startup with a clear error". ADR-047 already makes the node-local sections (`node`, `cluster`, `listen`, `api`, `auth`, `telemetry`, `cache`) stay with each node, and replaces everything else with the primary's.

**Decision:**
- **Node-only records:** `[[record]] node_only = true` keeps a record on the node whose file has it. A primary leaves it out of the shared configuration, and a replica keeps its own node-only records next to the cluster's.
- **Shared settings in a replica's file are ignored and reported, not refused.**
  - At every load the replica logs a warning naming the sections.
  - The Cluster page gains a failing `node_settings` check with the fix (remove them, or mark node-only records).
  - The spec's "reject at startup" would make a node's upgrade, or a cluster join, refuse to start over settings that have no effect. DNS would stop over a cosmetic problem, against rule 5 and CLU-004. The owner's Pi is exactly this case: its file predates joining.
- No separate `node.toml` file is needed: a node's own config file plays that role, and the node-local sections are already defined by ADR-047.

**Consequences:** the owner's Pi shows a failing `node_settings` check until its file is trimmed to node-local settings. Promoting to the spec's strict refusal stays possible later, as an opt-in `[cluster] strict_overrides = true`.

## ADR-053 — Federated reads v1: what's exact, what's approximate, and which scopes exist (Accepted)
**Context:** T5.6 (CLU-002, OBS-012). `spec/12` §6 says analytics reads fan out to the peers in `scope` and merge, with HDR histograms merged exactly, query logs k-way merged with per-node cursors, a 2 s per-peer timeout, and `missing_nodes`. It names the scopes `node:<id>`, `site:<name>` and `cluster`.

**Decision:**
- **Transport:** reads are RPCs over the existing cluster streams (frame types `RpcRequest`/`RpcResponse`, kind `api.read`, JSON body). No new port, connection, or certificate. Peers are asked concurrently with a 2 s deadline. A peer without a stream is reported missing at once.
- **Merges:**
  - counters sum per bucket, across every breakdown;
  - top lists add counts and error bounds per key (the true count stays within `[count − errorBound, count]`);
  - query-log pages interleave newest first, with a cursor (`fed:` + base64url JSON) that holds each node's "before" time, or nothing once that node has run out.
- **Latency is approximate in v1.** Each node sends its percentiles, and they are weighted by query count; the maximum is exact. Shipping histograms for an exact merge needs a serialized HDR format on the wire. It's deferred until a dashboard needs exact cluster-wide tails.
- **Scopes:** `cluster` (the default) and `node:local`. `node:<id>` and `site:<name>` still answer `400 unsupported_scope`. The live tail, configuration reads, and Explain stay local.
- **Edge cases (accepted):**
  - Rows that share the exact microsecond with a page's last row from the same node may be skipped on the next page.
  - A node that joins while someone is paging appears only from the next fresh search.
  - `missingNodes` reports the latest federated read on the node; concurrent reads may each see the other's list.
- **Failure:** a peer error, timeout, or undecodable answer drops that node from the result and names it in `missingNodes`. If this node's own query log is off, but peers answered, their rows are returned and this node is listed as missing. DNS answering is never involved (CLU-004).

**Consequences:** any node's UI is a full management view for reads. Exact cluster-wide latency, named-node/site scopes and a federated live tail are follow-ups.

## ADR-054 — Write forwarding v1: the entry node vouches for the user over mTLS (Accepted)
**Context:** T5.7 (CLU-002). `spec/12` §6 says a write on any node is forwarded to the primary with the user's identity, "signed by the receiving node", so the audit log shows both the user and the entry node. Users aren't replicated yet (ADR-045 is still to come), so a user exists only on the node they signed in to.

**Decision:**
- **What's forwarded:** the configuration writes the API offers (devices, local names, forwarded domains), including dry runs. They go to the primary as the RPC `api.write` over the existing cluster stream, with a 10 s deadline.
- **Who vouches:**
  - The entry node authenticates and authorizes the user with its own users and roles, exactly as for a local write.
  - The primary trusts the entry node's claim because the stream is mutually authenticated with the cluster CA: the peer ID comes from the certificate, never from the request.
  - No extra signature is added: the mTLS channel already proves which node sent it, and a member node is trusted to replicate configuration anyway.
- **What's recorded:**
  - The primary stores the entry as made by `<user> via <site>` and audits it with actor kind `cluster` and `remote = node <id>`.
  - The entry node audits it under the user's name, with the primary's answer.
- **Versions:** a replica reports the primary's configuration version (ETag; 1 s deadline, falling back to its own), so `If-Match` works through any node. The primary's answer, including its error code (409, 404, 400), is returned unchanged.
- **Unreachable primary:** the write is refused with 503 and a hint. It is never queued: a queued write could apply long after the user saw it fail.
- **Not forwarded:** under a GitOps authority, writes are refused on every node (409 `gitops_managed`, ADR-048). Promotion and the node's own users, tokens and sessions stay local until ADR-045 replicates identities.

**Consequences:** the owner can manage the cluster from the Pi's UI as well as the homelab node's, as long as both are on the API authority. Today's cluster is GitOps-managed, so there it stays read-only, by design.

**Amended 2026-10-08 (review 05-03; amendment Proposed):** "a member node is trusted to replicate configuration anyway" no longer covers every member since ADR-058. Forwarded writes and the reads that change the answering node (pause, resume, cache flush) are refused from members the registry marks ephemeral: they serve no UI, so no user's change arrives through them.

## ADR-055 — Query-log ship mode v1: closed segment files, delivered once, searched where they land (Accepted)
**Context:** T5.8 (CLU-007). `spec/12` §7 describes `ship` mode: raw events are streamed to a target in batches of columnar blocks, spilled to a 64 MiB buffer when the target is unreachable, and replayed; rollups are shipped as per-minute aggregates; `both` mode does both; receivers keep per-source-node segments.

**Decision:**
- **Unit of shipping: whole closed segment parts, not blocks.**
  - In ship mode the writer closes a part at least every `[telemetry.ship] interval_secs` (default 300 s).
  - The shipper sends each closed part (every part except the newest) to the target in 512 KiB chunks over the cluster channel (RPC `qlog.put`).
  - The receiver checks the whole file's BLAKE3, then files it unchanged under `qlog-nodes/<sender-id>/`. Nothing is re-encoded, and the sender's footer and bloom filters stay valid.
  - Only after the receiver confirms does the sender delete its copy. A lost confirmation means the file is sent again and overwritten, never duplicated.
- **Buffer:** the local log is the store-and-forward buffer, bounded by `buffer_bytes` (default 64 MiB) via the existing retention, which drops the oldest file first. No separate in-memory spill: a RAM disk under `data_dir` gives the memory variant without new code.
- **Exactly one copy:** a row is either in the sender's buffer or on the receiver. The receiver's search includes shipped logs, labelled by node, and federated reads reach the sender's unshipped rows, so a cluster-wide search sees each row once.
- **Target:** `[telemetry.ship] to` (a node ID or site), defaulting to the primary. A primary in ship mode with no other target keeps its log (logged once).
- **Deferred:**
  - **Rollup shipping.** Per-minute counts stay on each node: they're small, the dashboard already federates them, and shipping them only matters for ephemeral pods (T5.10). *Done in T9.3:* ship-mode nodes send their last 30 minutes of minutes every `interval_secs` (≤ 60 s); the target keeps them per node for 7 days (`shipped_minute`), and the cluster view adds only those of nodes that didn't answer live, so nothing counts twice.
  - **`both` mode.** It would need dedup between a live sender and its shipped copy. Not needed for the hybrid Pi + k8s setup.
- **Safety:**
  - Receivers accept only from cluster members (mTLS), only hex node IDs become paths, and segments over 256 MiB are refused.
  - Shipping is a background task, and receiving runs on blocking threads, so DNS is never involved (CLU-004).
  - The peer RPC handler is now installed whether or not the node runs the API, so a node without an API can still receive logs and answer federated reads.

**Consequences:** the owner's Pi can set `mode = "ship"` to move its query log to the homelab node's volume. Rows then appear with up to `interval_secs` of delay in the homelab node's own search; cluster-wide search shows them at once.

## ADR-056 — Automatic failover v1: one vote per epoch, voter-granted leases, pre-vote, a vote-only witness (Accepted)
**Context:** T5.4b (CLU-005). `spec/12` §5 has `witness` and `quorum` modes: a candidate needs a majority of eligible nodes plus witness for `epoch + 1`, and promotes only after the old primary's lease (15 s, renewed every 5 s) has expired; "a primary accepts writes only while it holds a valid lease". The AC is a simulator: 10k randomized partition schedules, never two writers in one epoch, orphaned writes always surfaced.

**Decision:**
- **One protocol for both modes** (`telltale_cluster::election`, pure, no I/O):
  - Voters are the eligible nodes plus witnesses, from the signed registry.
  - A voter grants each epoch once (persisted, fsync, before answering). It refuses a newer epoch while the lease it granted to another node runs (15 s on its own clock), and refuses candidates whose applied version is behind its own.
  - The primary renews with every voter every 5 s. It treats its lease as ending 15 s − 2 s after it *sent* the round a majority granted, so it stops publishing before any voter of that majority can elect someone else, for clock rates within ±1 %.
  - **Pre-vote:** a node first asks whether it *would* win. A node cut off from the cluster never inflates epochs, and never deposes a healthy primary when the partition heals.
  - `witness` and `quorum` are the same thing with different voters, so the mode is just `manual` or `auto`.
- **Mode:**
  - `telltale cluster set-failover auto|manual` on the primary. It's carried in the signed manifest, like the authority.
  - `auto` runs elections only with three or more voters, this node one of them; otherwise it behaves as `manual`, and the Cluster page's `failover` check says why.
  - Manual `promote` is refused while elections run, because it would bypass the votes.
- **Witness:**
  - `telltale cluster join <token> --witness --advertise <url>`, then `telltale cluster witness`.
  - It runs only the cluster channel and the vote handler: no DNS, lists, API or pipeline. It learns the registry and mode from verified manifests.
  - It never becomes primary and never receives the CA key.
- **Transport:**
  - Votes are the `elect.ask` RPC on cluster streams. The candidate is bound to the stream's certificate: a node can only ask for itself.
  - Voters keep a full mesh in `auto` mode: of each pair, the lower node ID dials.
- **Gating:**
  - `Cluster::may_publish()` is false for a primary without a valid lease. The publish loop waits, and API writes get 503 with a hint.
  - A primary starting in `auto` mode begins with publishing paused until its first renewal.
  - A restarted primary resumes its epoch if its own ballot is for itself; otherwise it takes part in a normal election.
  - Only nodes holding the CA key stand as candidates.
- **Under a `gitops` authority,** an elected node that isn't Git-managed becomes an emergency primary (ADR-048).

**Verification:**
- `tests/sim.rs` covers 2 + witness, 3, and 4 + witness voter sets under random asymmetric partitions, 0–15 % loss, heavy-tailed delays to 3 s, crashes with persisted ballots and histories, and ±1 % clock drift.
- It checks:
  - one primary per epoch;
  - never two writable primaries at the same real instant;
  - every write kept, or reported as orphaned;
  - a primary within 60 s of healing.
- Results at 10,000 schedules (release, in CI): 43,744 elections, 1.49 M writes, 176,933 orphaned and reported, worst recovery 24.75 s.
- It's mutation-checked: removing the lease check, or timing the lease from the reply instead of the request, is caught.
- `deploy/cluster/failover-e2e.sh` (real processes, CI): kill the primary, and the replica is elected in about 14 s with 100 % of DNS queries answered; the old primary returns and follows.

**Deferred:** CA rotation, the other part of T5.4b's title, is now T5.4c. Clocks are assumed not to jump by more than the margin; NTP slews rather than steps in normal operation.

**Amended 2026-10-08 (review 05-05; amendment Proposed):** the clock assumption above didn't hold for the hosts this runs on. A Raspberry Pi has no RTC: it starts on the time it shut down with, and NTP *steps* it, by minutes or hours, once DNS works. With leases as wall-clock times, a forward step made every lease a voter had granted look expired at once. So:
- Leases are timed on the **election clock** (`telltale_cluster::clock`): `CLOCK_BOOTTIME` on Linux (read through `rustix`, no `unsafe`), which never steps and counts time spent suspended; `Instant` elsewhere. Nothing on the wire changes: `Ask` and `Reply` carry no times.
- A ballot records which process's clock its lease is on (`clock`). A ballot from another process (a restart) or from an older build (wall clock, `clock = 0`) is taken as granting a full lease from now (`Ballot::adopt`), and stored that way at once so later reads don't extend it again. That is never shorter than promised, and costs at most 15 s of extra waiting after a voter restarts.
- The simulator restarts nodes on a new, unrelated clock (anywhere from far behind to far ahead) and adopts their ballots the same way. Mutation-checked: forgetting the lease on adoption is caught ("two writers") within 2,000 schedules.

**Consequences:** the owner's Pi + homelab cluster stays `manual` until a witness exists. A witness on any third device (for example the NAS) makes failover automatic, with the Pi as an emergency primary while the configuration authority is GitOps.

## ADR-057 — Node certificate renewal over the cluster channel, same key (Accepted)
**Context:** T5.4c (CLU-001). Node certificates last 90 days (ADR-044), and nothing renewed them, so a cluster would lose its links about 90 days after its nodes joined. The owner's cluster joined on 2026-10-04. `spec/12` §3 says certificates renew automatically; the CA rotation half of T5.4c is rarer, because the CA lasts 10 years.

**Decision:**
- **When:** each node checks every 6 hours (first one minute after start) and renews when fewer than 30 days remain, so two thirds of the lifetime has been used. It retries every 10 minutes on failure.
- **Same key:** the node sends a CSR for its existing key, so its node ID (derived from the key) never changes.
- **Who signs:**
  - A node holding the cluster key (the primary, eligible nodes) signs its own.
  - Others ask the primary with the `cert.renew` RPC on their stream.
  - The primary signs only when the CSR's key belongs to the peer the stream's certificate names. It takes the certificate's names (advertise hosts) from the signed registry, never from the request.
- **Checks before use:** the new certificate must name this node and verify against the cluster CA (Ed25519). It's written atomically.
- **Switch-over:** a certificate generation counter makes the dialer and the listener rebuild their TLS settings for the next connection. Open streams keep their session, since certificates are checked at handshake only.
- **CA rotation** (new CA, cross-signing, key re-share) stays in T5.4c, still open.

**Consequences:** clusters keep their links indefinitely while a CA holder is reachable at least once every 30 days. A witness or replica cut off from every CA holder for 90 days loses its certificate and must rejoin with a token.

## ADR-058 — Kubernetes resolver pods: a shared bootstrap secret with proof of possession, ephemeral members, sync-gated readiness (Accepted)
**Context:** T5.10 (CLU-009). `spec/12` §2 says resolver pods join with a long-lived token from a Secret, get a fresh identity per start, expire after `ephemeral_ttl` (10 min) without heartbeats, and display under their site. A join token pins the CA fingerprint, which only exists after the controller creates the cluster. So a chart can't put a token in a Secret without the controller writing to the Kubernetes API, which needs RBAC and a client library.

**Decision:**
- **Bootstrap secret instead of a pre-made token:**
  - The chart generates a random secret in a Secret (kept with `lookup` and `resource-policy: keep`, or the user's own via `existingSecret`), mounted in every pod.
  - The controller accepts it like a join token that never expires: `[cluster] bootstrap_secret_file`, re-read at every join, so rotations apply without a restart.
- **Proof of possession instead of trust on first use:**
  - A pod with `join_url` first calls `POST /cluster/v1/ca` with a fresh nonce.
  - It trusts the returned CA only if the server answers HMAC-SHA256(secret, nonce : CA fingerprint), proving it holds the same secret.
  - It then pins that CA and joins exactly as with a token.
  - A man in the middle without the secret can't pass this.
- **First start creates or joins:**
  - `[cluster.init]` (advertise URLs, authority) creates the cluster on the controller's first start, the same as `telltale cluster init`.
  - `join_url` joins on a pod's first start, retrying for 2 minutes. An ephemeral pod that can't join exits, so Kubernetes retries it (CrashLoopBackOff while the controller starts).
- **Ephemeral members:**
  - `[cluster] ephemeral = true` joins as ephemeral: never eligible, never a voter, no CA key.
  - The registry records `ephemeral`. The primary drops ephemeral members not connected and not heard from for `ephemeral_ttl_secs`, checked every minute. A pod that never connected is measured from when it joined, or from the controller's start.
  - The Cluster page groups them by site with counts (up, ready, q/s, behind).
- **Readiness:** an ephemeral node is ready only once it has applied the cluster's configuration. A new pod never serves an unfiltered answer, and the Service routes to it only after sync.
- **Helm `mode: scaled`:**
  - The allInOne StatefulSet becomes the controller and keeps its labels, so switching modes needs no reinstall.
  - Adds a resolver Deployment (`emptyDir` data, ship-mode query log, `maxUnavailable: 0`), a `-cluster` Service for the cluster port, the join Secret, and a NetworkPolicy rule for the cluster port.
  - The DNS Service selects every pod; the API and metrics Services select the controller.
  - `hostNetwork` with `scaled` is refused, since pods would compete for port 53; that's `daemonSet`, later.
- **Found on the way:** a replica's follower ignored a manifest that arrived before it subscribed, and waited for the primary's next change. It now processes the current one at start.

**Consequences:**
- `deploy/helm/scaled-e2e.sh` (CI, this build's binary on kind) proves the controller and two pods join and sync, a pod answers DNS, an outside node joins through the cluster port, and a deleted pod is replaced and expires.
- A pod restart is a new member, by design. A registry of long-gone pods is cleaned within `ttl + 1 min`.

**Amended 2026-10-08 (review 05-01, 05-06; amendment Proposed):** what makes a pod untrusted is now enforced by the primary: a join with the bootstrap secret is ephemeral whatever it asks for. The primary's `POST /cluster/v1/ca` proof answers anyone, so a weak secret could be brute-forced offline from collected proofs: a secret shorter than 32 bytes is warned about at startup (not refused, so existing deployments keep joining), and the docs ask for 32 random bytes or more. The chart generates 48 characters.

## ADR-059 — Version compatibility v1: a protocol window, a schema stamp, and refusal over guessing (Accepted)
**Context:** T5.11 (CLU-010). `spec/12` §9 says RPC carries a protocol version and manifests a schema version; nodes accept N and N−1; the primary refuses to emit features the oldest connected node doesn't support, and warns. Until now, peers needed the exact same protocol, and manifests carried no schema. The shared configuration is parsed strictly (`deny_unknown_fields`), so an older replica would reject a newer primary's new settings.

**Decision:**
- **Protocol window:** a stream is accepted when the peers' protocols differ by at most one. Frames are protobuf, and fields are only ever added, so unknown fields are ignored. `PROTOCOL` is raised only when a message changes meaning.
- **Schema stamp:** manifests carry `schema`, the configuration schema the primary writes (now 1; 0 means from before stamping). It's raised when the shared configuration gains settings an older build would reject.
- **No down-converting:** the primary does not try to strip settings an older replica wouldn't know. It publishes what it has.
  - A replica that can't read it keeps serving its last version, so DNS is unaffected.
  - The replica records a sync error naming both schemas and saying to upgrade.
  - Per-field feature gating is deferred: the documented upgrade order (replicas first) makes it rarely matter, and guessing which settings are safe to drop could silently change filtering.
- **Visibility:** each node's protocol is on the Cluster page, and a `versions` check fails while versions or protocols are mixed, with the upgrade order as the fix. Build versions become fully distinguishable with T6.9's stamped build identity; today edge builds all say 0.1.0.

**Verification:** `deploy/cluster/upgrade-e2e.sh` (CI) runs the published `edge` binary as N−1 against this build:
- both nodes on N−1;
- the replica on N following the N−1 primary;
- the primary on N;
- the replica back on N−1 following the N primary.

An edit reaches the replica at every stage, and a client with both servers configured gets an answer to every query.

**Addendum (2026-10-05):** the shared configuration leaves out top-level sections that are at their defaults, and a replica reads a missing section as the default. Without this, adding any new section (DNSSEC, ADR-060) broke N−1 replicas even when no one used it: CI's upgrade test caught it. A new setting now reaches an older replica only once someone actually sets it. That is the case the "no down-converting" rule is for.

## ADR-060 — DNSSEC validation v1: hickory's validator over our upstream groups, off by default (Accepted)
**Context:** T6.1 (DNS-011). `spec/03` §5 asks for:
- modes `off`, `validate` (the default once stable) and `validate_permissive`;
- DO=1 upstream, validation from the root trust anchor, and CD=1 clients getting unvalidated data;
- AD only when validated and the client asked;
- bogus answers as SERVFAIL with EDE 6;
- negative trust anchors;
- `hickory-proto`'s verification primitives behind a `Validator`.

In hickory 0.26 the chain-of-trust logic (`DnssecDnsHandle`, with NSEC/NSEC3 denial proofs, wildcard checks, NSEC3 iteration limits and a validation cache) lives in `hickory-net`. The primitives in `hickory-proto` alone would mean writing that ourselves.

**Decision:**
- **Use `hickory-net`'s `DnssecDnsHandle`** (`dnssec-ring`, `tokio`; it adds no TLS or HTTP stacks). It wraps a `DnsHandle` we implement over one of our upstream groups.
  - The question, and every DNSKEY and DS lookup the proof needs, go to the same upstreams with DO=1 and CD=1 (we check, so the upstream mustn't drop what it thinks is bogus).
  - There's one handle per group, so its validation cache lasts across queries.
  - It's wrapped as `telltale_upstream::dnssec::Validator`.
- **Verdict:** the weakest proof among the answer records, or among the authority records for NXDOMAIN and NODATA. Errors from the validator other than upstream failures count as bogus.
- **Serving:**
  - Secure gets AD for clients that asked; insecure and indeterminate get no AD.
  - Bogus becomes SERVFAIL with EDE 6, never a stale answer, and is never cached; in permissive mode it's served and counted.
  - RRSIG, NSEC and NSEC3 records are stripped for clients without DO.
  - Validation runs on cache misses only, and validated answers are cached with their AD bit. The cache key already separates DO and CD.
- **Negative trust anchors:** `[dnssec] negative_trust_anchors` plus every route with `dnssec_nta`.
- **Mode names and default:** `off`, `validate`, `permissive` (spec's `validate_permissive`). The default stays `off` until it has run on the owner's nodes for a while; then a follow-up makes `validate` the default.
- **Timing:** a cold chain (root, TLD and zone keys) takes several sequential lookups. Validation gets three times the query budget, so a slow first lookup still lands in the cache even if that client gave up.
- **Found on the way (all queries):** a truncated UDP answer's TCP retry shared the adaptive per-attempt timeout calibrated on small answers (about 3× average round trip), so large answers (DNSKEY sets with signatures, long TXT) timed out. The TCP retry now gets the configured timeout of its own.

**Verification:** unit tests for verdicts, NTA coverage and stripping. `deploy/dnssec-e2e.sh` (CI, real DNS tree, forwarding to 1.1.1.1 and 9.9.9.10) checks:
- ietf.org and cloudflare.com are secure with AD;
- google.com is insecure without AD;
- dnssec-failed.org is SERVFAIL with EDE 6, and answered with CD;
- signed NXDOMAIN and NODATA validate;
- verdicts are counted.

**Deferred:**
- RFC 5011 trust-anchor updates (the built-in root keys cover KSK-2017 and KSK-2024);
- aggressive NSEC caching (RFC 8198, with recursion);
- per-reason EDE codes (7, 9, 10, 12) instead of 6;
- the `dnssec` field in query events and the Settings UI.

## ADR-061 — Pi-hole import v1: a reviewed starting configuration, faithful group semantics (Accepted)
**Context:** T6.3 (API-007; `spec/08` §8) asks for an importer of Pi-hole v5 and v6 Teleporter archives covering adlists, domain lists, groups, clients, local DNS/CNAME records, upstreams, and conditional forwarding, with a report of every unmapped setting. The spec doesn't say whether the result is applied or reviewed, how Pi-hole's per-entry group assignments map onto our per-group list sets, or what happens to Pi-hole behaviors we don't have.

**Decision:**
- **Output, not apply:** `telltale import pihole PATH` writes TOML for review (like `import zone`, ADR-041), validated to load before it's written. Applying through the API (and the UI's import page) waits for T6.7's restore path.
- **Inputs:** v6 zip (`pihole.toml` and a `gravity.db` of the group tables), v5 tar.gz (JSON per table plus `setupVars.conf`, `pihole-FTL.conf`, `custom.list`, `dnsmasq.d`), a directory, or a bare `gravity.db`. Readers are ours: zip and tar.gz in about 200 lines on `miniz_oxide`, with CRC checks and size limits. SQLite goes through `rusqlite`, already in the tree. Archived databases are read from a private temporary copy.
- **Groups stay exact:** each group gets exactly the lists Pi-hole gave it, so `default` doesn't fall back to "every list". Domain entries become inline lists, one per (type, set of groups). Disabled groups get no lists. Clients in no group go to a `pihole-no-group` group with no lists, as Pi-hole blocks nothing for them.
- **Matching:**
  - exact entries use `match = "exact"`;
  - a regex our parser would read as a plain name is wrapped as `/regex/`;
  - entries our engine can't run are reported, not dropped silently.
- **Upstreams:** they go in the `default` upstream group with strategy `fastest`, matching Pi-hole's preference for the fastest server.
- **Conditional forwarding:** each rev server becomes its own upstream group and route. The route covers the domain and the network's reverse zones: non-octet prefixes are expanded, so a /23 is two /24 zones, never widened. It gets a negative trust anchor.
- **Devices:** DHCP reservations become named devices (MAC and IP join a matching client, or a new one named by the host name). The DHCP server is not imported.
- **Report:**
  - v6: every setting Pi-hole marks `### CHANGED` that isn't mapped;
  - v5: every unmapped key in `setupVars.conf` and `pihole-FTL.conf`, except the old install's own plumbing (interface, addresses, web server);
  - names only, never values, since they include password hashes.
- **Not imported:** clients matched by host name or interface (we match by address); the `IP` blocking modes; query history; passwords and tokens.

**Verification:**
- Unit tests on hand-written inputs in both formats.
- `deploy/pihole-import-e2e.sh` (CI) configures the official `pihole/pihole` images (v6 2026.09.0 = FTL v6.7.1, v5 2024.07.0) through their own tools, exports Teleporter archives, imports them, and serves the result: local names, a CNAME's TTL, exact and regex denies (`;querytype`), the blocking mode, and group scoping.
- Pi-hole-generated files aren't committed (their comments are Pi-hole's text, NFR-006).

**Consequences:**
- Merging into an existing configuration is manual (both define `default`).
- The importer's e2e showed that the first blocking snapshot waited for every list's first fetch, including retries, so an unreachable adlist delayed all blocking at first start. Fixed: the fetcher signals the compiler at most 10 s (`settle`) after the first update in a round, so lists that arrive together still compile once.

## ADR-062 — Technitium import v1: read the API, not the backup (Accepted)
**Context:** T6.4 (API-007, P1). `spec/08` §8 says "backup zip → blocked/allowed zones, block-list URLs, forwarders + protocols, Advanced Blocking app config → groups". Technitium's backup holds `dns.config`, zone files, and the allowed/blocked lists in its own versioned binary serialization. That format is undocumented and changes between releases. Its HTTP API returns the same data as documented JSON.

**Decision:**
- **Source:** `telltale import technitium URL` reads a running server through the API with an API token, which comes from `TECHNITIUM_TOKEN` or `--token-file`, never argv.
- **Calls, all read-only:**
  - `settings/get`;
  - `zones/list`, then `zones/records/get` per zone;
  - `allowed/export`, `blocked/export`;
  - `apps/list`, and `apps/config/get` for Advanced Blocking;
  - `dhcp/scopes/list` and `dhcp/scopes/get` (optional).
- **Output:** reviewed TOML like ADR-061, validated before it's written.
- **Mapping:**
  - **Forwarders** go in the `default` group: concurrent forwarding becomes `parallel` with the same fan-out, but only with two or more usable forwarders. `name (ip:port)` pins the address, with the name as TLS name.
  - **Forwarder zones:** forwarders by priority, a route, and an NTA unless every forwarder of the zone validated.
  - **Primary zones:** records of the types we serve, with their TTLs.
  - **Blocked and allowed zones** become subtree inline lists.
  - **Advanced Blocking groups** become groups. The catch-all network's group becomes `default`, and other networks become `networks` (ADR-050). URL lists are shared across groups by URL. Regexes are wrapped as `/re/`. Server-wide lists are added to every group, since Technitium applies both. Disabled groups get no lists. The bypass list becomes a group with no lists.
  - **Blocking answer:** NXDOMAIN, or custom addresses, become the group's `block_mode`.
  - **Rate limit:** the per-/32 limit (queries per minute) becomes `[ratelimit]`.
  - **Other settings:** `dnssecValidation` and `saveCache` carry over. DHCP reservations become named devices.
- **Not imported (reported):** secondary and stub zones; QUIC forwarders; forwarders with no address; listener- and host-based group selection; per-list answers; the DHCP server; encrypted listeners; recursion ACLs, TSIG, zone transfers, the proxy, and other apps. Listeners, logging, users, and tokens are not imported either.

**Verification:**
- Unit tests on hand-written API responses.
- `deploy/technitium-import-e2e.sh` (CI) runs against `technitium/dns-server:15.6.0`. It configures everything above through Technitium's API, installs Advanced Blocking from Technitium's store, and creates an API token. It then imports, serves the result, and checks the answers.

**Consequences:**
- Importing needs the old server running, which matches the migration path (import, compare, switch).
- A backup-zip reader can follow if the format gets documented.
- The e2e found a real-data bug: concurrent forwarding with a single usable forwarder produced an invalid `parallel` group. Fixed and tested.

## ADR-063 — Backups v1: a checked archive of config and local data, without the cluster key (Accepted)
**Context:** T6.7 (API-007, P0) asks for Teleporter parity: one archive with config and local data, optionally with query history. `spec/08` §8 sketches `telltale ctl backup create [--include-qlog]` writing a `.ttbk` (tar.zst + manifest + signature) restored onto a new primary. `ctl` (the API-wrapping CLI, API-008) doesn't exist yet. The spec doesn't say what the signature is signed with or whether cluster identity is included.

**Decision:**
- **Commands:** `telltale backup create | show | restore`, local commands that work on the data directory.
  - `create` is safe while the server runs: SQLite databases are copied consistently with `VACUUM INTO`, and query-log segments only grow, so the size seen at open is copied.
- **Contents:**
  - config files under `config/`;
  - `state.db` (users, tokens, UI-made entries, audit), with sessions and idempotency keys removed;
  - `rollups.db` and `anomaly.json`;
  - the query log (`qlog/`, `qlog-nodes/`) only with `--include-qlog`;
  - lists, snapshots, the cache, and `setup-token` are left out, since they're rebuilt or transient.
- **Format:** a tar stream compressed with zstd (frame checksum on), with `manifest.json` last. It holds the format version, source node and paths, and each entry's size and BLAKE3 hash. The file is written owner-only and renamed into place when complete.
- **No signature in v1:** a signature by the source node's key proves nothing to the fresh node it's restored onto, which doesn't know that key. Integrity comes from the manifest hashes and zstd's checksum. Confidentiality is the file's permissions, as with Pi-hole's Teleporter. Encryption with a passphrase is the natural next step.
- **No cluster identity by default:** `cluster/`, with the CA key, isn't included. A portable file with the CA key could impersonate the cluster. A restored member starts standalone, and the manifest records that it was a member so restore can say what to do.
- **Restore:**
  - streams into a staging directory under the data directory;
  - checks every entry against the manifest, and anything unexpected, a path outside `config/` or `data/`, or `..`, fails before any file is moved;
  - refuses to replace existing files without `--force`;
  - chowns restored files to the data directory's owner.

**Verification:**
- Unit tests: contents, permissions, round trip, session stripping, `--force`, corruption, path containment, and the query log.
- `deploy/backup-e2e.sh` (CI) backs up a running node with an admin and an API-made name, restores it onto a second node, and checks the following on that node:
  - the name answers;
  - the admin signs in, and the old session doesn't carry over;
  - the audit log is present;
  - damaged archives are refused.

**Consequences:**
- **Download:** `GET /api/v1/backup` (admin, audited `backup.create`, without the query log) and a Settings → System button. Restore through the API is deferred: restoring under a running server is risky.
- `--include-cluster-key` (for disaster recovery of a lone primary) and passphrase encryption are follow-ups.

## ADR-064 — Agent principals v1: scoped tokens, deny by default, a reason for every change (Accepted)
**Context:** T6.5 (AGT-001..005, AGT-009). `spec/13` §2 asks for:
- agent tokens with an owner, scopes, an optional group restriction, rate limits, and expiry;
- attribution `agent:<token> (owner: <user>)` with the client and a required reason;
- dry runs with impact estimates on every mutation;
- guardrails and a cluster-wide kill switch;
- an OpenAPI document written for agents and linted.

Tokens so far had a role-like `scope` (read/write/admin), and the audit log already recorded `token:<name> (owner: <user>)` (ADR-038).

**Decision:**
- **Agent tokens:** `POST /tokens` with `kind: "agent"`.
  - The scopes are AGT-004's list: `analytics:read`, `querylog:read`, `config:read`, `config:write:{clients,records,forwards}` (`*` for all), `ops:pause`, `ops:cache`, `cluster:admin`.
  - The default is `analytics:read` + `config:read`: read-only, without the query log.
  - Optional `group` and `ratePerMinute`.
  - Each scope needs a role from the creator (`config:write:*` and `ops:*` need operator, `cluster:admin` needs admin). A token's effective role is the lower of its owner's and its scopes'.
  - Stored in three new `tokens` columns (migration 5). User tokens are unchanged.
- **Deny by default:** one table maps method and path to a scope. Anything not in it is refused for agents: users, tokens, passwords, backups, the audit log, and routes added later until they're mapped. The role checks still apply on top.
- **Group restriction:** honored where a group view exists.
  - The query log and top lists: the middleware replaces the `group` parameter.
  - Devices: listed for the group only; writes only into, and only on devices already in, the group.
  - Everything else is refused for restricted tokens rather than shown unfiltered.
- **Every change needs a reason:** agents' non-GET requests without `X-Telltale-Reason` get 400.
- **Attribution:** the actor is `agent:<token> (owner: <user>) via <X-Telltale-Client>`, with kind `agent`.
- **Rate limits:** a per-token token bucket in memory, refilled per minute, default 120 (`[agents] rate_per_minute`). Over the limit: 429 with `Retry-After`. Per node, so a cluster allows N× in total; documented.
- **Kill switch:** `[agents] enabled`, a shared section, so it replicates to every node (and, since ADR-059's addendum, doesn't trouble N−1 replicas while unset). It's applied on start and every reload.
- **Impact estimates:** device, name, and forward changes return `recentQueries` and `impact`, a sentence with the numbers. They're counted from the in-memory top lists for the current and previous hour (a lower bound, cheap, no log scan). Promotion gets `?dryRun=true`, returning a `PromotePlan` (epoch, emergency, impact) from the same checks without acting.
- **Lint:** `.spectral.yaml` (spectral:oas plus operation summary, description, tags, operationId, success response, and parameter descriptions) runs in CI. Every response now has a description.

**Verification:**
- Unit tests:
  - the scope map denies by default;
  - scope parsing and the roles scopes imply;
  - the kill switch, rate limit, required reason, and group refusal;
  - the forced group parameter.
- API tests: agent tokens over HTTP (scopes, refusals, reason, attribution, kill switch); group-restricted tokens; the promote dry run.
- `deploy/agent-e2e.sh` (CI) on a running node:
  - a dry run of every mutation reports an impact and changes nothing;
  - a real change is attributed with its reason;
  - a reload with `enabled = false` stops the agent and not the admin.

**Consequences:**
- MCP (T6.6) builds on these principals.
- `ops:pause` and `ops:cache` exist ahead of their endpoints.
- Per-group analytics views beyond top lists would let restricted agents see more.
- OAuth for agents (AGT-008) stays P1.

**Amended 2026-10-08 (review 06-02, 06-09; amendment Proposed):** an agent's pre-save list check returns how many lines couldn't be used and why, not their text (the node would otherwise read any URL it can reach for the agent). Viewers list only their own plans; operators and admins see all.

## ADR-065 — MCP server v1: read-only tools over the REST routes, one implementation for two transports (Accepted)
**Context:** T6.6 (AGT-006, AGT-008 bearer part, AGT-009; ADR-010). `spec/13` §3.1 lists the read-only tools, and §4 suggests a `telltale-mcp` crate with schemas generated from the Rust types (`schemars`) and a catalog snapshot test. The AC asks for:
- an MCP conformance test;
- scope and privacy authorization tests;
- a scripted agent completing the "why is the TV slow" story.

**Decision:**
- **Where:** a module of `telltale-api` (`mcp.rs`), mounted at `/mcp` on every node's API listener behind the same authentication. A separate crate would add nothing at this size. `POST /mcp` takes JSON-RPC 2.0 (single or batch) and answers JSON (Streamable HTTP without SSE; `GET /mcp` is 405). Protocol `2025-06-18`, also answering `2025-03-26` and `2024-11-05`. Methods: `initialize`, `ping`, `tools/list`, `tools/call`. Notifications get 202.
- **Tools call REST in-process:** each tool builds one or more `GET /api/v1/...` requests and sends them through the REST router with the caller's own `Authorization`/cookie. Scopes, group restriction, rate limits (one per inner call), privacy levels, and the kill switch apply exactly as for REST, with no second authorization model. The REST problem+json becomes the tool's error text.
- **Catalog (read-only):** `get_overview`, `top_items`, `search_queries`, `explain_decision`, `get_client_profile` (the device, then its queries by IP), `latency_breakdown`, `upstream_health`, `list_effectiveness`, `find_anomalies`, `cluster_status`, `get_config` (one section).
  - Each description starts "Read-only.", and each tool carries `readOnlyHint`.
  - `test_resolution` is deferred: it needs resolution without cache or log, which the pipeline doesn't offer yet.
- **Schemas:** hand-written JSON Schemas, frozen in the committed `docs/api/mcp-tools.json` and diffed by a test (`UPDATE_MCP=1` to regenerate). Generating them from the REST parameter types would tie tool arguments to query-string shapes; the snapshot still prevents drift.
- **Guardrails:** results are capped at 32 KiB (with a note) and 200 rows. Each `initialize` starts a session (`Mcp-Session-Id`), and the client name/version from it is passed on as `X-Telltale-Client`, so agent actions are attributed to the MCP client (AGT-005).
- **stdio:** `telltale mcp --stdio` relays newline-delimited JSON-RPC between stdin/stdout and a node's `/mcp` with a token, so there's one implementation of the tools. The node address comes from `--url` or the config files; nothing but protocol goes to stdout.
- **Agents and `/mcp`:** `POST /mcp` needs no scope of its own and no reason header (the tools are read-only; the inner calls are checked). Group-restricted tokens may use it, since their inner calls are narrowed.

**Verification:**
- Unit tests: the catalog snapshot; side-effect statements and caps; arguments become queries.
- An API test: initialize with a session, list, call, scope error inside a tool, unknown method, no credentials.
- `deploy/mcp-e2e.sh` (CI) runs the official `@modelcontextprotocol/sdk` client against a live node. Over Streamable HTTP, the listed tools must match the committed catalog. The test then plays the "why is the TV slow?" story (device profile with recent queries, upstream health, explain on a blocked name), repeats it over `telltale mcp --stdio`, and checks that a token without `querylog:read` gets an error from `search_queries`.

**Consequences:**
- Write tools with plan/apply and approvals (§3.2) are P1.
- OAuth for MCP clients (AGT-008) is P1.
- MCP resources and prompts are later.
- An SSE stream (`GET /mcp`) would be needed only for server-initiated messages.

**Amended 2026-10-08 (review 06-04, 06-07; amendment Proposed):** the REST calls behind a tool carry the `/mcp` request's client address (`OnBehalfOf`, an extension only in-process requests can carry), so changes made through MCP are audited from the agent's address, not `0.0.0.0`. They don't take from the agent's rate-limit bucket again: the rate counts tool calls, and each message of a JSON-RPC batch, which holds at most 16 messages. A resource cut at 32 KiB says so.

## ADR-066 — CA rotation: two trusted CAs, three member-gated phases (Accepted)
**Context:** T5.4c (CLU-001, CLU-005). `spec/12` and the roadmap ask for:
- CA rotation: a new key, a cross-signed transition, node certificate renewal over the channel, and the old CA retired;
- re-sharing the key with eligible nodes.

ADR-057 already renews node certificates (same key) over the channel. A CA rotation changes the trust anchor every TLS handshake and every manifest signature depends on.

**Decision:**
- **Two trusted CAs instead of cross-signing:** during a rotation `ca.crt` is a bundle of both CAs. TLS trusts every certificate in it, so certificates from either CA verify. Manifest signatures and issued certificates are checked against any CA in the bundle. The bundle's first CA is the one that signs, and `ca.key` is always its key. Cross-signing adds nothing in a cluster whose members all receive the bundle.
- **Distribution:**
  - The primary's signed manifest carries `ca_bundle`. A node adopts a new bundle only if it keeps at least one CA the node already trusts, so trust moves step by step and a stolen CA alone can't replace it.
  - Witnesses follow manifests for this alone.
  - Eligible nodes get the next CA's key with the existing key share, now re-sent whenever it changes. A key that arrives before its CA is trusted is held (`ca-pending.key`) until a verified bundle includes it.
- **Phases, driven by the primary, each gated on every non-ephemeral registry member** (heartbeats now carry `trust_fp`, the CAs a node trusts, and `issuer_fp`, the CA of its certificate):
  1. `trust`: the bundle is old + new; the old CA signs.
  2. `switch`: once all trust both, the new key becomes `ca.key` (the old is kept as `ca-old.key`) and the bundle becomes new + old. Nodes see that their certificate isn't from the signing CA and renew within a minute (self-issued with the new key, or over `cert.renew`). A node whose `ca.key` doesn't match the signing CA asks the primary rather than sign with the old key.
  3. `finish`: once every certificate is from the new CA, the bundle is the new CA alone, and the old key and the rotation state are deleted.
- **Operator interface:** `telltale cluster rotate-ca` starts a rotation on the primary while it runs, and the running primary carries it out (it re-reads its identity every cycle). `--status` and a `ca_rotation` Cluster check show the phase and pending members. Each new CA's name carries a label, so the two trusted CAs never share a subject.
- **Fixed on the way:**
  - Configuration fetches used the TLS settings from start-up, so they'd fail after a rotation. They'd also present an old certificate after a renewal. They now read the current identity.
  - Witnesses never renewed their certificates (ADR-057 gap); they do now.
  - Cluster files were made owner-only only after being written, and two streams could collide on one temporary name. Each write now uses its own temporary name, and secrets are created owner-only.

**Verification:**
- Unit tests:
  - bundles: verify, issuer, order-independent fingerprint;
  - start: refuses a second rotation;
  - adoption: refuses unrelated trust, promotes a held key, switches, then retires.
- `deploy/cluster/rotate-e2e.sh` (CI) with a primary, an eligible replica, and a witness under DNS load:
  - all three phases complete, and every node ends trusting only the new CA, with a certificate from it;
  - the replica holds the new key, and no old, next, or pending key is left;
  - every query was answered during the rotation;
  - a configuration change replicates afterwards (signed with the new key), and a restarted replica reconnects and syncs.

**Consequences:**
- A member offline for the whole rotation must rejoin.
- Join tokens pin the CA fingerprint, so tokens from before a rotation stop working.
- A forced rotation (with members down) is a possible follow-up.

**Corrected 2026-10-08 (review 05-10):** "a stolen CA alone can't replace it" overstates the rule. The rule stops a CA the node doesn't trust from replacing trust; it doesn't contain a stolen *current* CA key, whose holder can rotate trust to a CA of their own in three manifests, exactly as the legitimate primary does. That is inherent (the key signs everything): a suspected compromise of the cluster key means re-creating the cluster, as `docs/running.md` now says.

## ADR-067 — Quick rules: their own layer, the most specific scope wins, expiry on the server (Accepted)
**Context:** T6.12 (owner request 2026-10-05) wants everyday per-person rules:
- unblock a game's server for one phone for two hours;
- block a site for the kids' devices until tomorrow.

The engine can already express device-scoped rules (`$client` in the manual-rules overlay, ADR-003), but the overlay uses the lists' four tiers (important allow > important block > allow > block). Those can't say "this device's rule beats its group's rule beats the lists": a group-wide allow would override a parent's block for one child. Nothing expires on its own.

**Decision:**
- **A quick rule:**
  - allow or block a domain and its subdomains;
  - for listed devices (by name, IP, or MAC, as `[[client]]` keys), listed groups, or everyone;
  - an optional expiry (an absolute time; the UI offers durations);
  - a note, who made it (user or agent), and when.
- **Storage:** in `state.db` as a managed entry of kind `rule` (ADR-040). In a cluster, rules travel with the shared configuration the primary publishes (ADR-047), and a replica's UI forwards the write to the primary (ADR-054). Rules are capped at 1,000 per cluster.
- **Matching:** quick rules are their own layer, checked before the lists:
  1. Among rules matching the query name (any suffix of it) whose scope includes the client, a device rule beats a group rule, which beats an everyone rule.
  2. Within one scope, the longer (more specific) domain wins, then allow beats block.
  3. A match decides allow or block outright. Otherwise the lists decide as before.

  CNAME inspection (FLT-007) uses the same decision, so a block also catches a CNAME to the blocked name.
- **Hot path:** the rules sit in a read-mostly table behind `ArcSwap`, keyed by the hash of each rule's reversed domain. A lookup probes the query's suffixes, at most one probe per label, with no allocation. With no rules it costs one branch.
- **Expiry:** each node ignores a rule from the moment its expiry passes, by its own clock (T6.11 shows clock offsets). A sweep every 5 s on the primary deletes expired rules and audit-logs each expiry. A replica never needs the sweep to stop applying a rule.
- **Explanations:** an answer decided by a quick rule is attributed to it ("allowed by a quick rule for Mom's phone, expires 21:30"). The query log records it, and "Why?" and explain show it above the list matches.
- **Agents:** the scope `config:write:rules`, with the usual reason header, dry run, and impact estimate (recent queries the rule would change).

**Consequences:**
- A new rule takes effect on the next query, with no list recompile.
- Cost: about 52 ns per query with 1,000 rules, about 4 ns with none (xxh3 suffix keys, measured 2026-10-05).
- Rules are deliberately simpler than list syntax: no regex, no query types. Anything fancier belongs in a list.
- Device scoping is only as good as recognising the device; the docs say so.
- Expiry depends on node clocks being roughly right. A node whose clock is off keeps or drops a rule early or late by that offset, and the Cluster page flags offsets of 2 s or more.
- **Mixed versions (CLU-010):** the config schema rejects unknown keys, and an empty `rule` list is left out of the shared configuration. So an N−1 replica follows the cluster as long as nobody has made a quick rule. Once one exists, the replica refuses that version and keeps serving its last good one until it's upgraded. Quick rules therefore wait for a cluster-wide upgrade, as any new shared section does.

## ADR-068 — One process per data directory: an exclusive lock held for the process's life (Accepted)
**Context:** T6.14 (owner request 2026-10-05). Scaling a single-volume Deployment (or starting a second `telltale run` with the same configuration) makes two processes share one data directory: the node identity and cluster certificates, `state.db`, the query-log segments, and the cache dump. Nothing stopped it, and the damage is silent: two nodes with one identity, interleaved query-log writes, and SQLite contention.

**Decision:**
- `telltale run` takes an exclusive advisory lock (`flock`, through `std::fs::File::try_lock`) on `<data_dir>/telltale.lock` before anything else touches the directory, and holds it until the process exits.
- If another process holds it, the new one retries for 10 s (a previous process may still be shutting down), then exits non-zero with an error. The error names the directory and the holder (pid, host or pod name, and start time, which the holder writes into the file), and points to `mode: scaled`.
- If the lock file can't be opened at all (a read-only or unusual file system), the node logs a warning and starts anyway: the lock protects against a mistake and must never stop DNS (CLU-004).
- `telltale backup restore` takes the same lock without waiting, so it refuses to restore under a running server.
- Read-only commands (`qlog search`, `explain`, `backup create`) don't take it.

**Consequences:**
- The operating system releases the lock when the process exits, even after a crash or `SIGKILL`, so there is no stale-lock cleanup.
- A rolling update of a single-volume Deployment would wait for the old pod forever. The chart uses a StatefulSet and the homelab Deployment uses `Recreate`, and the docs tell people with their own manifests to do the same.
- On network file systems `flock` may be emulated or local-only. That is acceptable for a guard against mistakes.

## ADR-069 — Editing upstreams, lists, and groups from the UI: overrides in state.db, the files untouched (Accepted)
**Context:** T7.5 (owner report 2026-10-06). On a node installed with `install.sh`, the upstreams and lists come in the starter `/etc/telltale/telltale.toml`. ADR-040 makes anything the files define read-only through the API ("files win"), so none of them could be changed in the UI. Rewriting the file isn't an option either: Docker and Kubernetes mount it read-only, and on Git-managed nodes the next deploy would replace it.

**Decision:**
- Upstreams, upstream groups, lists, and client groups made or changed through the API are managed entries in `state.db` (like ADR-040's), by name. An entry can:
  - add a new name;
  - **override** a file entry of the same name (the whole entry is replaced);
  - **hide** a file entry (a tombstone: the name is left out).
- The files are never rewritten. The UI marks each entry as *file*, *UI*, or *UI override of the file*, and "Revert to the file" deletes the override or tombstone.
- Every change is validated on the merged configuration before it's stored (a group can't lose its last upstream; a list can't be removed while a group uses it; the default upstream group must keep a member), with dry run, `If-Match`, idempotency, and audit as for the other managed kinds.
- In a cluster, the merged configuration is what the primary publishes (ADR-047), so changes reach every node.
- On a node whose configuration comes from Git (`config_source = "gitops"`), each change response carries the TOML to add to the repository or the Helm values to make it permanent ("Keep it in Git"), because an override lives only in that node's `state.db`.
- Devices, local names, forwarded domains, and quick rules keep ADR-040's rule (files win), since the starter config doesn't define them.

**Consequences:**
- A standalone node can be run entirely from the UI after `install.sh`.
- Two sources of truth for the same name are possible; the UI and the `GET` endpoints show which one is in effect (`source`: `file`, `api`, or `override`).
- A file change to an overridden entry has no effect until the override is reverted; the UI says so on the entry.

## ADR-070 — Agents' plans: a dry run kept in memory on the node that made it, applied with If-Match (Accepted)
**Context:** T7.1 (AGT-007). A `plan_*` MCP tool must show what a change would do and let the agent apply it later, only if nothing changed meanwhile and, with `[agents] require_approval`, only after an operator approves. The spec doesn't say where plans live, how long they last beyond "10 minutes", or how a cluster shares them.

**Decision:**
- A plan is the REST write (method, path, body) plus its dry-run answer, the config version it saw, the reason, and who asked (the caller's token or session). Plan tools call the REST dry run in-process with the agent's own credentials, so scopes, group restrictions, rate limits, and the kill switch apply unchanged.
- `apply_plan` replays the same write with `If-Match: <version>` and the plan ID as the `Idempotency-Key`. A 412 marks the plan `stale`. Only the caller that made a plan can apply or discard it.
- Plans live in the memory of the node that made them, at most 500, open for 10 minutes and listed for a day. They aren't stored or replicated: a restart drops them, and the agent plans again.
- With `[agents] require_approval = true` a new plan is `pending` until a person with the operator role approves or rejects it (`POST /api/v1/plans/{id}/approve|reject`, the "Agent changes" page). Agent tokens can never approve or reject. Both decisions are audited.
- Approval is checked when the plan is made: turning the setting on doesn't hold plans already made, and turning it off doesn't release pending ones.
- Immediate operations (`flush_cache`, `pause_blocking`, `resume_blocking`) have no plan, as `spec/13` §3.2 says; they're audited like any agent write.
- `plan_set_schedule` waits for schedules (FLT-010). Alert destinations for pending plans wait for OBS-010.

**Consequences:**
- Nothing new is persisted, and a plan can't outlive the configuration it was checked against.
- In a cluster, an operator approves on the node the agent used. Agents should use the node whose UI people use (normally the primary). If agents and people use different nodes, plans would need to move to the replicated `state.db`.

## ADR-954 — A replica reports how long it has been without its primary; `primary_unreachable` alerts on it (Accepted 2026-11-17)
**Context:** a replica that can't reach its primary keeps answering DNS from its last copy (CLU-004), but nothing said so: `node_down` only sees a node that's disconnected from the primary's view, and a replica that still reaches other members (after falling back to one of them) looks healthy while it is split off. Alerts are evaluated on the primary, so the primary has to learn the replica's view from the heartbeats it already receives (fork #2, T24.5).

**Decision:**
- A replica's heartbeat carries `primary_silent_s` (optional `uint64`, tag 40; tag 39 is the primary flag of ADR-947): how long it has gone without a heartbeat from its primary, when that is more than the `up` window (three heartbeats, 15 s); absent when it reaches the primary, is the primary, or is an older node. It is computed from the heartbeats already exchanged, on the cluster task, never on the DNS path. Older nodes ignore the tag (CLU-010).
- The cluster view carries it as `primarySilentSeconds` on each replica (its own value, or the peer's while the peer is `up`).
- The alert condition `primary_unreachable` fires for a replica whose silence is at least its rule's `threshold` in seconds (default 60; 15 to 86400), after `for_secs` as for every rule. One alert per replica; it clears when the replica reaches the primary again. Witnesses, resolver pods and nodes that aren't `up` are left out; so are nodes in maintenance.
- The health level adds a degraded reason `primary_unreachable` (link `#/cluster`) for a replica silent for 60 s. The health icon uses the fixed 60 s, as ADR-104 fixes its thresholds; the alert's `threshold` doesn't change the icon. (Conservative choice: the health path has no access to the alert rules; making it follow the rule is a follow-up if the defaults don't fit.)
- A replica that is disconnected from every member is `node_down`, not this condition; a replica that reaches another member is the silent split this condition exists for.
- Counting. The silence counts from the newest heartbeat this node has heard from any primary, kept after that primary leaves the member list, so a removed or replaced primary doesn't make a replica look silent since boot. Before any primary has been heard, it counts from this process's start: a replica that has never linked to a primary reports its uptime as the silence once that uptime passes 60 s. The alert and the health reason show this case as a plain `N s` with no separate label; it is kept so that a replica that never linked is surfaced rather than hidden. (Conservative choice.)
- Scope. The alert engine runs only on the primary, so a replica's silence reaches the alert through the heartbeats that replica sends to the primary or to a member that relays them. A replica's own silence is in its own view (health) and is not evaluated on the replica itself. A primary's own silence is not reported (it is the primary).
- Maintenance. Health and the alert both leave out a replica in a maintenance window (the health filter checks the node's maintenance field directly; `exclude_maintenance` also drops its reasons).

**Consequences:** one optional heartbeat field and one `ClusterNode` field; no new configuration key (the threshold is the rule's own). The UI shows the condition in the Alerts form (threshold, in seconds, is the field's help), the replica flag on the Cluster page with the `primary-unreachable` help topic, and the health reason. The timing is unit-tested at the boundary (`obs_010_t24_5_*`), and `clu_004` is the Playwright test.
## ADR-952 — The chrono and rsa advisories under the OIDC change (Accepted 2026-11-17, owner decision: accepted as implemented once a second independent security review found nothing HIGH or MEDIUM, which it did not)
**Context:** `deny.toml` ignored RUSTSEC-2026-0543 (chrono, unmaintained) and RUSTSEC-2023-0071 (rsa, timing side channel). Both arrived only through `openidconnect` (ADR-951 Context).

**Decision:** ADR-951 chose (b-ring), so neither crate is in the tree. Both ignores are removed in the same change: `deny.toml` now has `ignore = []` with a comment saying why. `cargo tree -i chrono`, `-i rsa` and `-i openidconnect` print nothing, and `cargo deny check` passes (advisories, bans, licenses and sources).

## ADR-951 — OIDC without chrono: an in-tree verifier on `ring`, replacing openidconnect and oauth2 (Accepted 2026-11-17, owner decision: accepted as implemented once a second independent security review found nothing HIGH or MEDIUM, which it did not)
**Context:** `openidconnect` 4.x and `oauth2` 5.x pull `chrono` (RUSTSEC-2026-0543, unmaintained, no patched version), which `deny.toml` ignored (fork #17, T24.23). `cargo tree -i chrono` showed `chrono` arriving only through `oauth2 v5.0.0` and `openidconnect v4.1.0`, and `openidconnect` only through `telltale-api`. `rsa v0.9.10` (RUSTSEC-2023-0071, ignored) also arrived only through `openidconnect`. `telltale-api` had its own `chrono` dev-dependency (`flow_tests.rs`). `ring 0.17.14` is already a normal dependency (via `rustls`, `rcgen`, `hickory-proto` and others), so the in-tree verifier adds no crate.

**Current behaviour** (`crates/telltale-api/src/auth/oidc.rs` before this change) that the replacement keeps:
- Discovery: the document's `issuer` must equal the configured issuer; a second fetch read `end_session_endpoint`. Cached for 1 h (`DISCOVERY_TTL`).
- Start and finish: authorization code with PKCE S256; random state and nonce; a flow lives 10 min (`FLOW_TTL`), at most 1000 (`MAX_FLOWS`), is single-use, and is bound to the browser cookie and the provider.
- Token exchange: `exchange_code` with the PKCE verifier, and HTTP Basic client authentication (openidconnect's default with a secret).
- ID token: nine algorithms (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA). A signature failure ran a full discovery refresh with no rate limit.
- MCP access tokens (`verify_access_token`): `iss` (trailing slash ignored), `aud` (string or array) equal to `mcp.audience`, `exp` and `nbf` with 60 s leeway, key chosen by `kid`, the nine algorithms.
- Config (`crates/telltale-config/src/validate.rs:1375-1380`): the issuer must start with `https://` or `http://`, and a plain-HTTP issuer already produces the warning "plain HTTP is only safe for local testing".
- Claims mapping (`identity`, `role_for`, `username_for`, the agent role cap, `oauth_principal`) is pure and unchanged by this ADR.

**Options:**
- (a) Keep `openidconnect` and `oauth2`. Rejected: `chrono` and the ignore stay.
- (b-ring) **Chosen.** An in-tree verifier on `ring`: JWK-to-key conversion (RSA `n`/`e`, EC `x`/`y` as an uncompressed point, OKP `x` for Ed25519), the JWS verification for the nine algorithms (`ring::signature`), the header rules, and all claim checks. No new crate. T24.23 asks for "a library without chrono, or a minimal flow on crates the tree already has", and `ring` is such a crate. The signature glue is the riskiest code, so it is kept small, has one module (`oidc/jose.rs`), and is pinned by tests for each family and each rejection.
- (b-p256) The same verifier on `rsa`, `p256` and `ecdsa`. Rejected: `rsa` stays, so RUSTSEC-2023-0071 stays.
- (c-9) `jsonwebtoken` 9.3.1. **Rejected after the review.** 9.x is a frozen line: `cargo info` shows 12.0.0 as the latest, two majors ahead, and 9.x gets no fixes. 9.3.1 also silently ignores a claim of the wrong JSON type: `validate()` skips `iss`, `aud` and `nbf` that fail to parse unless they are in `required_spec_claims` (`src/validation.rs:255-330`), so `"nbf":"9999999999"` is never checked. Its `Validation` allow-list also refuses every token when it mixes algorithm families (`src/decoding.rs:216-221`). Using it for the signature only would still leave the claim parsing in-tree, and it adds the `pem` and `simple_asn1` crates and a second `base64`.
- (c-10 / c-12) `jsonwebtoken` 10 or 12. Rejected. Its crypto backend is `aws-lc-rs` (a C build, large image) or RustCrypto (includes `rsa`, so RUSTSEC-2023-0071 stays). A `ring`-backed `CryptoProvider` (12.0.0 `src/crypto/mod.rs:83-97`) is possible, but then the crate contributes only the JWS parsing, which we write anyway, and it still adds a crate and its `CryptoProvider` glue.
- (d) Another OIDC client library. Not chosen. The two clients checked both list `chrono` as a normal dependency on crates.io. Other crates were not surveyed exhaustively; reopen only if a candidate is shown chrono-free.

**Recommendation:** (b-ring). It removes `openidconnect`, `oauth2`, `chrono` and `rsa` from the tree, adds no crate (`ring` becomes a direct edge of `telltale-api`), and keeps all OIDC policy (claims, nonce, state, discovery, key rotation) in `telltale-api`, pinned by tests.

**Decisions** (accepted by the owner 2026-11-17 as implemented; the in-tree verifier on `ring` is the decision, and `jsonwebtoken` is not used, for the reasons in (c-9) and (c-10 / c-12)):
1. Library: (b-ring), as above.
2. Parity: observable behaviour stays the same, except these tightenings: (i) ID tokens use the nine algorithms intersected with the provider's `id_token_signing_alg_values_supported` when it lists them (an empty intersection refuses every ID token); MCP access tokens keep the nine, as today; (ii) a signature failure or an unknown `kid` refetches the key set (not the discovery document), at most once per provider per 60 s, one fetch at a time per provider, and a failed fetch keeps the cached keys; (iii) `none` and HS* are never accepted; (iv) an ID token's audience must be exactly `client_id` (any other audience is refused, even alongside it).
3. HTTP issuers stay accepted, as today. The plain-HTTP warning already exists (`validate.rs:1377-1380`), so this ADR adds no startup warning. New rule: when the issuer is HTTPS, the discovery document's `authorization_endpoint`, `token_endpoint` and `jwks_uri` must be HTTPS, or the discovery is refused; an `end_session_endpoint` that isn't HTTPS is dropped. Discovery and key-set responses over 1 MiB are refused (the binary's fetch already caps at 1 MiB).
4. Clock skew (review finding 5): **ID tokens have no leeway on `exp`**, as openidconnect has today (`cur_time >= expiration` in `openidconnect-4.1.0/src/verification/mod.rs`, around line 823). The 60 s leeway the first draft proposed for `exp` would have loosened the check, so it is withdrawn. `iat` is required and may be at most 60 s in the future (openidconnect checks no `iat` by default, since `iat_verifier_fn` is `Ok`, `mod.rs:547`, so this tightens it). `nbf`, when present, may be at most 60 s in the future. MCP access tokens keep 60 s for `exp` and `nbf`, as today.
5. Keys: an RSA key whose modulus is under 2048 bits is refused when read (ring's verification minimum; Keycloak and Authentik default to 2048 or more). An EC key must be on the curve its algorithm names (P-256 for ES256, P-384 for ES384); an OKP key must be Ed25519. A JWK with `use` other than `sig` is ignored, and so is a JWK whose `alg` differs from the token's. Without a `kid` in the token, exactly one fitting key must exist (more than one is refused as ambiguous, as openidconnect does via `AmbiguousKeyId`). `docs/running.md` says so.
6. Client authentication (review finding 5): with a secret, HTTP Basic (`client_secret_basic`), with `client_id` and `client_secret` form-encoded first (RFC 6749 §2.3.1). If the provider lists `token_endpoint_auth_methods_supported` without `client_secret_basic` but with `client_secret_post`, the secret goes in the form body. If it lists neither, sign-in is refused with a config-level message. Without a secret (a public client), `client_id` goes in the body and no Basic header is sent. The openidconnect 4.1.0 source (`src/client.rs:341-348`) confirms Basic with a secret and the body `client_id` without one, so the spike's "confirm in source" step is done.
7. No new setting in this change. The Settings page, `[auth.oidc]` keys and help topics stay as they are.
8. Out of scope, unchanged: refresh tokens and userinfo are not implemented, and logout keeps using `end_session_endpoint` as today.

**Algorithm and key rules** (enforced in `oidc/jose.rs` before any signature is checked, in this order):
- The header must parse, and its `alg` must be one of the allowed algorithms. `none`, HS256/384/512 and anything else are refused before any key is looked at, so an allow-list is never compared with a key of another family.
- `typ`, when present, must be `JWT`, `application/jwt` or `application/jose` for an ID token. An access token also accepts `at+jwt` and `application/at+jwt`. A `typ` of `at+jwt` therefore can't pass as an ID token.
- `cty` of `JWT` (or `application/jwt`) is refused (nested JWTs). A `crit` header is refused (no critical extension is implemented).
- A key fits the token when: its type matches the algorithm (RSA for RS* and PS*, EC P-256 for ES256, EC P-384 for ES384, OKP Ed25519 for EdDSA); its `use` is absent or `sig`; its `alg`, when present, equals the token's; and, when the token has a `kid`, its `kid` equals it.
- No fitting key refuses the token and may trigger a refetch. A `kid` the key set doesn't hold does the same. More than one fitting key without a `kid` is refused as ambiguous, with no refetch. A fitting key whose signature doesn't verify refuses the token and may trigger a refetch.
- The payload must be a JSON object.

**ID-token checks** (in `finish`, after the signature):
- `iss` is a string equal to the configured issuer (exact match, as openidconnect does).
- `aud` is a string or an array of strings, every value equal to `client_id` (an empty array is refused).
- `azp`, when present, is a string equal to `client_id`; `azp` is required when `aud` has more than one value.
- `sub` is a non-empty string.
- `exp` is a whole-second JSON number, and `now < exp` (no leeway).
- `iat` is a whole-second JSON number, present, and not more than 60 s ahead of `now`.
- `nbf`, when present, is a whole-second JSON number, not more than 60 s ahead of `now`.
- `nonce` is a string equal to the flow's nonce.
- State is single-use, within the TTL, and bound to the browser; the PKCE verifier is sent with the token request.
- `at_hash` is not checked (the code flow does not use it, as today).
- Every date claim is strict: a string, a fraction or a negative value is refused, never skipped.

**Discovery and transport:** one discovery document per provider (cached 1 h) gives the endpoints, `end_session_endpoint` and the algorithm and client-auth lists. The key set is fetched from its `jwks_uri`. Requests don't follow redirects (the binary's fetch doesn't). Responses over 1 MiB are refused. The HTTPS rule is decision 3.

**JWKS refetch:** the key set is refetched after an unknown `kid` or a failed signature, at most once per provider per 60 s. One fetch runs at a time per provider (a per-provider async lock), so concurrent refetches collapse into one, and a request that waited uses the keys the first one fetched. A failed fetch keeps the cached keys and logs a warning.

**Access tokens (MCP):** the nine algorithms (not the discovery intersection, as today), the same key and header rules with the access-token `typ` set, and the existing `iss` (trailing slash ignored), `aud`, `exp` and `nbf` checks with 60 s leeway, unchanged. `iat` is not checked, as today.

**Negative and positive tests** (REQ API-004 and AGT-008; the names are the test functions in `oidc/verify_tests.rs` and `oidc/flow_tests.rs`). Each rejection is refused:
- bad signature (one flipped bit): `api_004_bad_signature_is_refused`; signed by a key whose `kid` is not published: `api_004_a_token_from_another_provider_is_refused`, `api_004_key_set_refetch_is_rate_limited_and_keeps_good_keys`;
- `aud` without `client_id`, `aud` array without `client_id`, an extra untrusted audience (`api_004_extra_untrusted_audience_rejected`), `aud` array of two without `azp`, and `azp` not `client_id`: `api_004_id_token_claims_are_checked_with_strict_types`, `api_004_tampered_claims_are_refused`;
- wrong `iss`, and a number as `iss`: `api_004_tampered_claims_are_refused`; discovery `issuer` not the configured one, and discovery with an HTTP endpoint for an HTTPS issuer: `api_004_discovery_must_name_the_configured_issuer_and_https_endpoints`, `api_004_scheme_downgrade_is_refused`;
- expired token, `nbf` in the future, `iat` more than 60 s ahead, a missing `iat`, `exp` and `nbf` as strings: `api_004_id_token_expiry_has_no_leeway_and_iat_and_nbf_allow_sixty_seconds`, `api_004_tampered_claims_are_refused`;
- nonce mismatch, nonce replay (a second use of the same state), state mismatch, and a state this browser didn't start: `api_004_tampered_claims_are_refused`, `api_004_state_mismatch_and_replay_are_refused`, and the existing `api_004_states_are_single_use_and_unknown_providers_404`. A missing `code_verifier` is refused by the fake provider's token endpoint, which requires it on every exchange;
- `alg=none`, and HS256 with the public key bytes as the secret: `api_004_forged_and_mistyped_headers_are_refused`, `api_004_none_and_hmac_tokens_are_never_accepted`;
- key-kind mismatch, EC key on the wrong curve, OKP key that isn't Ed25519, RSA key under 2048 bits, `use=enc` ignored, and a JWK `alg` that differs from the token's: `api_004_key_kind_and_curve_must_fit_the_algorithm`, `api_004_okp_key_must_be_ed25519_and_rsa_must_be_2048_bits`, `api_004_symmetric_and_encryption_keys_are_not_used`, `api_004_the_jwk_alg_must_equal_the_token_alg`;
- a provider that lists only RS256 in `id_token_signing_alg_values_supported`, and an ES256 token arrives: `api_004_the_provider_allow_list_refuses_other_algorithms`, `api_004_the_provider_allow_list_is_enforced_in_the_flow`;
- `typ=at+jwt`, `cty=JWT` and `crit`: `api_004_typ_cty_and_crit_are_checked`, `api_004_forged_and_mistyped_headers_are_refused`;
- a missing `kid` with two eligible keys: `api_004_a_missing_kid_with_two_eligible_keys_is_refused`;
- a token signed by provider B presented at provider A's callback: `api_004_a_token_from_another_provider_is_refused`;
- an oversized discovery or key-set response: `api_004_an_oversized_provider_response_is_refused`;
- JWKS rotation: a new `kid` is refused before the refetch and accepted after it: `api_004_a_new_kid_is_rejected_before_the_refetch_and_accepted_after_it`, `api_004_jwks_rotation_is_accepted_after_the_refetch`;
- the refetch rate limit, per provider, and one fetch for concurrent refetches: `api_004_key_set_refetch_is_rate_limited_and_keeps_good_keys`, `api_004_concurrent_refetches_collapse_into_one`;
- a failed refetch keeps the cached keys: `api_004_a_failed_key_set_refetch_keeps_the_cached_keys`;
- one positive test per signing family, RS256 through EdDSA: `api_004_each_signing_family_verifies` (all nine), `api_004_es256_and_eddsa_providers_sign_in` (end to end), and the RS256 sign-ins in the existing flow tests;
- a public client without a secret signs in: `api_004_public_client_signs_in_without_a_secret`; a provider that lists only `client_secret_post`: `api_004_client_secret_post_when_it_is_the_only_method`;
- MCP (AGT-008): another provider's key, `alg=none`, HS256 with the public key, an unknown `kid` with the rate limit, and the MCP provider's own token still working: `agt_008_mcp_token_negatives`. The existing `agt_008_mcp_oauth_access_tokens` covers the expiry, audience and forged-signature cases.

**Parity checklist** (review finding 9). These behave as before, and the tests named stay in place:
- groups: a dotted claim path (`realm_access.roles`), a string or an array, a leading `/` dropped, a string split on commas and spaces: `api_004_claims_to_identity_and_role` (body unchanged);
- `require_verified_email`: `email_verified` true or `"true"`: `role` in `oidc.rs`, unchanged;
- `roles` and `default_role`: the highest mapped role, else the default: `role_for`, unchanged;
- `mcp.provider` and `mcp.audience`, and the RFC 9728 metadata: `agt_008_mcp_oauth_access_tokens` (body unchanged);
- the `disable_local_login` break-glass for admins from `allowed_admin_networks` (`auth/mod.rs:745`): `api_004_disable_local_login_keeps_a_break_glass_admin` (body unchanged);
- per-provider caches for discovery and the key set, and multiple providers: `four_providers` covers four in one app;
- single-use state, the browser binding, safe return paths, the flow TTL and the flow cap, username collision (`name@provider`), JIT creation and the role audit, RP-initiated logout: `api_004_oidc_sign_in_end_to_end` (body unchanged), `api_004_return_paths_stay_inside_the_ui`.

The existing flow tests keep their bodies. What changed in `flow_tests.rs` is the fake identity provider (it now signs with ring, serves each provider by host, and can rotate keys, advertise algorithms, require `client_secret_post`, or downgrade a URL), the signing helper behind `access_token` and `sign_in`, and the `chrono` call in `agt_008` (now `std::time`).

**Fixtures:** `test-key.pem` (a 2048-bit PKCS#1 RSA key, the only RSA key ring can read here, since ring can't generate RSA keys) signs the RS* and PS* tokens. EC and Ed25519 keys are generated at test time with ring. The sub-2048-bit RSA case uses a synthetic 1024-bit JWK, which is refused when read, so it needs no key file. No new fixture is committed.

**Dependency footprint:** `ring` 0.17.14 becomes a direct edge of `telltale-api` (already in the tree; no new crate). Removed: `openidconnect` (with its subtree: `rsa`, `chrono`, `oauth2`, `num-bigint-dig`), `chrono` (the dev-dependency), and the `[profile.release.package]` entries for `openidconnect`, `oauth2`, `chrono`, `rsa` and `num-bigint-dig`. `Cargo.lock` goes from 458 to 389 packages. `cargo tree -i chrono`, `-i rsa`, `-i openidconnect` and `-i oauth2` print nothing, and `cargo deny check` passes with no ignore (ADR-952).

**Verification:** `cargo test -p telltale-api` (every test passes; 38 of them are OIDC); `cargo clippy -D warnings`; `cargo deny check`; `3-oidc` against Keycloak and Authentik (`OIDC_E2E`); the image delta (`deploy/image/size.py --oci`). The image delta and the `3-oidc` result are recorded in the T24.23 Done note.

**Consequences:** RUSTSEC-2026-0543 and RUSTSEC-2023-0071 leave `deny.toml` together (ADR-952). The verifier is ours to audit (about 540 lines in `oidc/jose.rs`, `claims.rs` and `metadata.rs`, plus the flow in `oidc.rs`), so the reviewer (Opus) should read `jose.rs` against the rules above. Tokens that the old code accepted and the new rules refuse: an ID token with an extra audience or a missing `iat`, a key under 2048 bits, an ambiguous key with no `kid`, `typ` `at+jwt` on an ID token, and a non-HTTPS endpoint under an HTTPS issuer. `docs/running.md` lists them.

**Review revisions** (the review of `docs/oidc-without-chrono`, 2026-11-17): HIGH 1, implemented (T24.23 steps 3 to 7). HIGH 2, the audience must be exactly `client_id`, with `api_004_extra_untrusted_audience_rejected`. HIGH 3, `jsonwebtoken` rejected and (b-ring) chosen, with the 9.x and 12.x facts above. MEDIUM 4, the algorithm check happens before key choice, with the one-key-per-family test. MEDIUM 5, clock skew and client authentication decided as above. MEDIUM 6, key and header rules added, with tests. MEDIUM 7, transport, size, concurrency and refetch-failure rules added, with tests. MEDIUM 8, the negative list is implemented. MEDIUM 9, the parity checklist above. LOW 10, the footprint is `ring` only, with no `pem`, `simple_asn1` or `base64` duplicate. LOW 11, the existing warning is referenced, with no new one. LOW 12, step 5 cites the right lines (`Cargo.toml`: `openidconnect` at `:26`, `chrono` as a dev-dependency at `:47`; `oauth2` was never a direct dependency of `telltale-api`). LOW 13, fixtures as above.

## ADR-947 — A promotion reaches every replica in the heartbeats; a key share repeats every 30 s (Accepted 2026-11-17)
**Context:** the three-node run (`deploy/cluster3`, T21.5) killed the primary. The replica elected in its place became primary, and the other replica followed the dead old primary (its configuration fetch went to `primary:8443`) and missed every later version. Two causes in `telltale-cluster`:
- a member's `primary` flag came only from its Hello, at connect time. A replica that connected before the election kept the old view, and `primary_urls` left the new primary's URL out as a replica's;
- the primary sent its key share once per stream. A peer that refused it (the flag was stale, so the sender wasn't "the primary" yet) never got another, so it could not be promoted later.

**Decision:**
- The heartbeat carries the sender's primary flag as an optional field (tag 39). A sender sets it at every heartbeat, and the receiver updates the member's flag. An older node sends no flag, and the flag a peer holds stays. Both directions are compatible without a protocol bump (CLU-010).
- The primary sends its key share to an eligible peer again every 30 s (`KEY_SHARE_RESEND`), unchanged. The acceptance check is unchanged: the sender must be the primary in the receiver's view, at the same epoch or a newer one.

**Alternatives rejected:**
- *A protocol version bump.* The field is optional both ways, so a bump would only force a mixed cluster to upgrade together.
- *Deriving the primary from the epoch.* A node's epoch alone doesn't say whether it holds the role now, and a former primary keeps the epoch it had.
- *Acknowledging key shares.* A wire change for a refusal that a resend already covers.

**Consequences:** a primary's heartbeat grows by two bytes, and an eligible peer gets about 2 KiB every 30 s. A replica takes a new primary from the next heartbeat after the promotion. Tests: `clu_005_a_promotion_reaches_a_replica_in_the_heartbeats`, `clu_005_a_key_share_is_sent_again_after_its_interval`, `clu_005_the_heartbeat_primary_flag_is_optional_both_ways`.

**Addendum (T21.5 review, 2026-11-17).** The three-node run also showed how an election starts. A node's election state is made when automatic failover turns on, and again when the voter set changes. Such a node had no lease to go by (none was granted yet), so its first try came at once: a replica stood 70 ms after the third voter joined and deposed a primary that had not renewed yet. A node that isn't the primary now waits one lease period (`LEASE_MS`, 15 s) before its first try (`Elector::defer_first_try`). The primary doesn't wait: it stands at once and takes its lease. Safety is unchanged (a voter still refuses a newer epoch while a lease it granted runs); the first election after a start is later, by up to 15 s. Tests: `clu_005_d_a_new_candidate_waits_a_lease_before_its_first_try`. The primary's key-share send is one decision (`key_share_send`: a changed frame at once, the same frame every 30 s), tested by `clu_005_c_the_key_share_is_sent_on_change_and_on_the_interval`. A repeat of the next CA key that the trust doesn't include yet doesn't rewrite `ca-pending.key` when the file already holds that key (`clu_005_b_a_pending_ca_key_is_written_once`).

## ADR-948 — The `[discovery]` first write, and members that are stopped or run a dev build (Accepted 2026-11-17, owner decision)
**Context:** ADR-928's title says "the first write waits for N−1 members". Its decision says the first write is refused with 409 `members_too_old` while a member runs a version older than `DISCOVERY_SINCE` (0.8.0), or one that can't be read. The three-node run checked both readings. With all three up, the first write passes when the replicas report 0.8.0. With replica-b stopped, the real first write also passes: the gate reads the version the cluster recorded for it, and a stopped member is neither older nor unreadable. A cluster of `dev` builds does refuse the first write, since a peer's `dev` is unreadable to the gate, and the refusal names both replicas. The run's image therefore stamps the release version (0.8.0), the way CI stamps a release build.

**Decision (proposed):** keep the gate as ADR-928's decision states it: members are judged by the version the cluster recorded for them, not by whether they are up. The test follows that. The title of ADR-928 says "waits", which this doesn't do.

**Open for the owner:**
- Should a stopped member block the first write until it is back (the title's reading)? That is a new rule: a member that's down would hold up a setting, and the first write has no later retry.
- Should a `dev` build report a readable version to its peers, so a dev cluster can use `[discovery]`? Today it can't, and the refusal is correct for the decision as written.

**Consequences:** no code change until the owner decides. The test pins the current behaviour (`deploy/cluster3/e2e.sh`, check e).

**Owner decision (2026-11-17):**
- A stopped member doesn't block the first write. Members are judged by the version the cluster recorded for them, as above. The title of ADR-928 is read as its decision.
- A build without a release stamp reports the crate version with a `-dev` suffix (for example `0.8.0-dev`) instead of `dev`, and peers and the gate read it as that version. A dev cluster can then use `[discovery]` without a release stamp. This is T21.6.

**Addendum (T21.5 review, 2026-11-17).** A `[discovery]` the primary sets with a value that isn't the default was refused by every replica whose own section was at its defaults. The section is left out of a node's serialization at its defaults (CLU-010), so the configuration merge didn't know the key and refused the whole version ("the primary sent a setting this version doesn't know"). The merge now always has the `discovery` key: at its default when the primary doesn't send one (so a cleared section resets the replicas, as the other shared sections do), and the primary's value when it does. Test: `clu_010_a_discovery_section_is_shared_both_ways` (`telltale-config`). Check (e) of the three-node run writes `worker_memory_mib = 48` and reads it back on replica-b, which is what found it.

## ADR-955 — The Home Assistant source test: a throwaway Home Assistant in its own Compose project, seeded by a test fixture (Accepted 2026-11-17)
**Context:** T24.21 (fork #12). The owner chose a test container, never the owner's Home Assistant. The bundle's `test-ha` profile (`deploy/docker-desktop/compose.yaml`) brings up its `homeassistant` service with `depends_on: telltale`, so starting it from the bundle's project would also drive the running `telltale-dev` container. Home Assistant's device registry has no REST or websocket call that gives a device a MAC connection, which is what TelltaleDNS reads (`/api/template`, `device_attr(d, 'connections')`).

**Decision:**
- **The container.** `deploy/ha-test/compose.yaml` is its own Compose project (`telltale-hatest`), with the integration under test and a fixture mounted. It publishes on `127.0.0.1` only. The bundle's `test-ha` profile stays as it is for manual use.
- **Onboarding and the token.** The script onboards the owner over `/api/onboarding/*`, exchanges the code, and makes a long-lived token over the websocket API (`auth/long_lived_access_token`) from inside the container. The token and the generated password go only to a file in a temporary directory that the trap removes; neither is printed.
- **Fake devices.** A test-only fixture integration (`deploy/ha-test/fixtures/telltale_seed`, never shipped) creates devices with MAC connections and an entity each, through its config flow. Addresses come from `device_tracker` states set over REST, the states TelltaleDNS matches on.
- **The node.** A TelltaleDNS build runs in a throwaway `ubuntu:24.04` container on the same network. Its binary comes from a bind mount (CI) or from another container's volumes (the dev container). The integration's token is an agent token with `analytics:read` and `config:read`.
- **Checks.** The names, MACs and addresses the node reports (a device with no address is absent), the names over DNS, and the integration's sensors (`known_devices`, `health`, `problem`, `queries_24_h`, `version`).

**Alternatives rejected:**
- *Starting the bundle's `test-ha` profile.* It would start `telltale` through `depends_on`, which touches the running dev container.
- *Writing the device registry as a file before first start.* It is undocumented for this purpose, and it breaks when the storage format changes.
- *Using Home Assistant's demo integration.* Its devices carry no MAC connections, so the template can't name them.

**Consequences:** the test needs a pulled Home Assistant image (about a few minutes on first run) and runs in CI as its own job (`.github/workflows/home-assistant.yml`, `ha-test`, 20 minutes). The fixture is a test-only integration that will need updating when Home Assistant changes its device or entity registry API.

## ADR-956 — Guarded changes: one framework for the settings that can lock an admin out (Accepted 2026-11-17, owner decisions)
**Context:** ADR-914 (Accepted) puts the security gates and bootstrap settings in a guarded tier with a dry run, a typed phrase, an audit record and, for addresses, a confirm-or-roll-back window. It names the pieces but not how they fit: where a guarded value is stored, how a restart interacts with a pending change, what a cluster does, or how the server proves a confirmation came through the new address. T27.14 to T27.17 each need the same machinery, so it is fixed once here, before any of them is built. The existing pieces it builds on: managed kinds and files-win (ADR-040, ADR-069, ADR-918), `node_managed` entries (T23.10, ADR-903 §6), agents' plans (ADR-070, in memory, replayed through REST), the live listener swap in `server.rs` `reload` (`Listeners::apply`), and the sign-in recency rule (T23.9, 10 minutes). Today there is no self-restart: a supervisor (systemd, Compose, Kubernetes) restarts the process, as for the watchdog (exit 70). The owner's decision of 2026-11-17 adds an explicit, supervised "Restart now" (section 4a); nothing restarts the node implicitly.

**Decision:**

**1. Which settings are guarded, and the mode of each.** A registry in `telltale-config/src/guarded.rs` lists every guarded setting once: `id`, the config paths it covers, `scope` (always `node`; see 5), `mode`, a pure `weakens(old, new) -> bool`, and the checks its dry run runs. A test fails if a path ADR-914 calls guarded is missing from it. The mode is how a change takes effect:

| Mode | Settings (`id`) | How it applies |
|---|---|---|
| `window` | `listen`, `api-address`, `api-tls`, `trusted-proxies` | Applied live as pending, kept only if confirmed through the new address (section 3). |
| `immediate` | `secret-file-dirs`, `allow-secrets-over-http`, `allow-insecure-basic`, `watchdog`, `file-paths` (`trust_anchors_file`, `signatures_file`, `hosts_files`, `[[zone]] file`) | Written, then applied by the same reload the API uses (a failed reload keeps the previous configuration, CLU-004). No window, because none of them can cut the admin off. Undone by the same form; the audit record holds the previous value. |
| `staged` | `secrets-key`, `node-identity` (`node.id`), `data-dir` (`node.data_dir`) | Written as `staged`, applied at the next start (section 4). The server restarts only on the admin's explicit "Restart now" (section 4a), never by itself. |
| `action` | `cluster-init`, `cluster-join`, `cluster-leave`, `cluster-git`, `restart-now` | An operation, not a value. Each has its own transactional steps (T27.16; `restart-now` is section 4a) but the same preview, phrase, audit and agent rules. |

**Data directory (`data-dir`, `staged`) and the settings that stay file-only.** (a) `node.data_dir` has a guarded control (owner decision 2026-11-17, which overrules the earlier "file-only" proposal; ADR-914's staged data directory stands, and ADR-914's sentence "never moves data" is reworded below: it moves data only when the admin opts into Copy state, and never `cluster/`). The danger is real: a new directory means an empty `state.db`, so every admin account and session is gone (`setup_required` reopens first-run setup, which anyone who can reach the API could complete), the cluster identity under `<data_dir>/cluster/` is lost (a member returns as a fresh standalone node) and the default `<data_dir>/secrets.key` is regenerated with the stored secrets unreadable. So the control is conservative:
- *Preview* (checks on the node, nothing written; the same checks run again at apply and again at start, before anything is copied or opened, so a path swapped for a symlink between preview and start is caught: `api_902_data_dir_path_checks_rerun_at_apply`): the new path is absolute, not a symlink (no component), not a path T23.2 denies, not equal to or inside the current directory (and the current one is not inside it), exists or can be created, and is writable by the node's user. *Persistence:* the node compares the target's mount with the current data directory's (`/proc/self/mountinfo` on Linux). A target on the container's writable layer, or on an `emptyDir`, while the current directory is on a separate volume, is a warning that the state is lost on recreate or reschedule; `TELLTALE_DATA_EPHEMERAL` set is a refusal (409 `data_dir_not_persistent`). A directory that already holds files shows which of the known files it has. The preview states in words: "Admin accounts, sessions, settings, the audit log, the cluster identity and the default `secrets.key` stay in <old path>. They do not carry over unless you copy them. With nothing copied, the node starts with no admin accounts and reopens first-run setup." *What does not carry over* is generated from one const, `DATA_DIR_FILES` in `telltale-config` (name, what it holds, whether Copy state copies it, whether it is safe to lose), which the preview, the help topic and `docs/recovery.md` all use, and a test fails if a file the node writes under `<data_dir>` is missing from it (`api_902_data_dir_file_list_is_complete`). It covers at least: `state.db` (accounts, sessions, settings, audit; copied), `secrets.key` (default key only; copied), `rollups.db` (history up to 400 days; not copied, starts empty), `maintenance.json` (an active maintenance window ends), `cluster/` including `applied.json` (identity; never copied, so the node starts without its cached cluster snapshot), `watchdog/restarts` (the restart-rate limit resets), `runs.json`, `anomaly.json`, `devices.json`, `annotations.jsonl`, `sinks/*.spill` (undelivered telemetry is dropped), `snapshots/`, `logs/`, `setup-token` and `guarded-probation`. It lists the commands to copy the rest by hand for the install (systemd, Compose volume, Kubernetes PVC; `state.db` with the node stopped or by the offline `telltale state backup`) and names what is not under the data directory (a `secrets_key_file` elsewhere, certificates) as unaffected.
- *Optional copy* (a checkbox, **off by default**, `copyState`): when on, the copy is made **at the start that applies the pointer**, before any state is opened (the old `state.db` is then closed, so a plain consistent copy, or SQLite's backup API, is exact). It therefore includes every write up to the restart (the change's own `settings.guarded` and `settings.guarded_restart` rows, admins and sessions created in between, secret rows re-encrypted in between); nothing taken at apply time is used. It copies only `state.db` and, when the default `<data_dir>/secrets.key` is in use, that key file (same mode, 0600, same owner, created with `O_EXCL`). It refuses (409 `target_not_empty` at preview and apply; at start the pointer is dropped) if the new directory already holds either, so it never overwrites. It never copies `cluster/` (a copy would duplicate the node's identity), the sidecar, logs or the query log. Copying a key file is a server-side file operation between two paths the preview named: no key material is in any request, response, log or audit row (API-014); the audit row, written after the copy into the old directory's `state.db`, lists file names only. If the copy fails part-way, the partial files are removed, the pointer is dropped and the node starts in the file's directory with audit `settings.guarded_rolled_back` (`failed_start`).
- *Consent:* the phrase as usual, plus, when the preview says the new directory will have no admin accounts (nothing copied, no `state.db` there and no bootstrap admin, below), a second explicit acknowledgement (`acknowledgeNoAdmins`, 409 `acknowledgement_required` without it). That case is **weakening** (first-run setup reopens), so the 10-minute sign-in applies. *Bootstrap environment:* when `TELLTALE_BOOTSTRAP_ADMIN_USER` with a password or hash is set (the "First admin" rule, applied only while no user exists), the new empty directory will get that admin at the first start, so the preview says "an admin named <name> will be created from the environment" (the name only, never the credential), the case is not "no admins" and is not weakening, and probation counts that account as the promised admin.
- *Where the pointer lives:* the `data-dir` entry is **local to the node and never replicated**. It is written to, and read only from, the `state.db` of the directory the file names (or the default). Start-up reads it first, follows it **one hop only**, then opens the target for everything else; a `data-dir` entry found inside the target is ignored with a warning. The sidecar `guarded-probation` also stays in the file-named directory. The node holds the lock on **both** directories while it runs. Every other guarded entry lives in the active (target) directory's `state.db`. The old directory must therefore stay while the pointer is in use; the preview recommends making the move permanent by setting `node.data_dir` in the file (and, for a Kubernetes install, mounting the volume there), and once the file names the new directory the pointer is ignored. A second `data-dir` change is written to the file-named directory, where start-up reads it.
- *Target missing later:* when the pointer is first applied the node records, in the pointer, an identifier of the target's `state.db` (a random state id stored inside it at creation) at the first healthy start. After that the target must exist and hold a `state.db` with that id. If it is missing, empty or a different database (an unmounted USB disk on a Pi, a volume not mounted, a fresh `emptyDir`), the node **starts in the file-named directory** with the health reason `data_dir_missing` and an audit row, and never creates the target after the first start. Only the probation start (before the first healthy start) may create it (`api_902_data_dir_missing_target_never_starts_fresh`).
- *Probation:* `data-dir` is healthy only when the new `state.db` opens, the API listener is bound, the DNS probe answers and, if the preview promised admin accounts (copied, already present, or from the bootstrap environment), at least one admin account exists (`setup_required` false). Otherwise two failed starts drop the pointer. An empty new directory the admin explicitly accepted is healthy.
- *One change at a time:* a `staged` entry is refused (409 `guarded_change_pending`) while another staged entry or a window change is pending on the node, so `data-dir` is never staged together with `secrets-key` or `node-identity`; `data-dir` is refused while `secrets_rotation_incomplete` holds (409 `rotation_incomplete`), because a copied `state.db` without `secrets_previous_key_file` would leave rows unreadable. Every `cluster-*` action is refused while `data-dir` is staged or on probation.
- *Cluster:* refused outright while the node is a cluster member (409 `clustered_node`); the supported path is to leave the cluster, move the data directory, then re-join (`cluster-leave`, T27.16). Nothing moves `cluster/`, so a pointer can never strand or lose the cluster identity on rollback.
- *Weakening:* only the no-admins case above.

(b) `[auth.oidc] disable_local_login` and `allowed_admin_networks`: each can lock every admin out, the case ADR-911's break-glass exists for, and a guarded change would need its own `would_lock_out_admins` dry run and recovery story; they stay in the file, shown read-only with this reason. A test (`api_902_lockout_settings_are_file_only`) fails if either appears in the registry; `api_902_data_dir_is_guarded_and_staged` fails if `node.data_dir` is missing from it or is not `staged`. Revisit (b) by a later ADR if the owner wants controls.

Why guarded at all: each is a setting that can lock every admin out (listeners, API address, TLS, proxies), put credentials on the wire or widen what a secret reference may read (the three `allow`/`dirs` settings), re-encrypt or lose the secret store (the key), or replace a node's configuration (cluster, identity, storage). `watchdog` and `file-paths` stay `immediate` (owner decision 2026-11-17). `watchdog` and `file-paths` are guarded because turning the watchdog off hides a hang, and a path lets the server read a file an admin names (T23.2's rules apply). `config_version` has no control (ADR-914).

**2. Where a guarded value lives.** In `node_managed` under the reserved kind `guarded`, one entry per node and setting (`node/<node-id>/guarded/<id>`), after T23.10. The generic managed-kind routes refuse that kind (409 `guarded_only`), so the only writer is the guarded module, after every check below. The file wins (ADR-040): a field the files set shows "set by file" with the path and an API write of it is 409 `set_by_file`. An entry is written only when the change is final (confirmed, applied, or staged), never while pending. The `data-dir` entry is the exception: it is local to the node and never replicated (see the data directory block). A backup restore brings the entries back and starts the node with them on probation (section 4).

**3. The two-request flow and the confirmation window.**
- **Preview** `POST /api/v1/guarded/{id}/preview` with `node` and `value`. It changes nothing and returns `previewId`, the `phrase` (`<node-id> <id>`, ADR-914), the effect in words, the nodes it reaches (always one), `weakening`, `restartRequired`, `wouldDisconnect`, the warnings (for example "the container's published ports are not changed", when the node sees it runs in Docker or Kubernetes) and the checks that failed. A preview is bound to the admin, node, setting, a hash of the value and the config version, and lives 5 minutes. A request with a changed value or version is 409 `preview_stale`.
- **Apply** `POST /api/v1/guarded/{id}` with `previewId`, `confirm` (the phrase, compared by the server) and a `reason`. The answer depends on the mode: 200 `applied` (`immediate`), 202 `staged` with `pendingRestart` (`staged`), 202 `pending` (`window`) or the action's own (`restart-now`: 202 `restarting`).
- **Window changes.** One pending change per node (409 `guarded_change_pending` otherwise). Until it is confirmed, a pending `trusted-proxies` list applies only to the confirm route's own address evaluation; every other use (break-glass `allowed_admin_networks`, loopback-only checks, rate limits, the audit source address) keeps the old list, so a newly trusted host cannot spoof `X-Forwarded-For` into those checks during the window. The node validates, binds the new sockets next to the old ones (a failed bind changes nothing and reports why), starts the window (`[api] confirm_window_secs`, default 120, 30 to 600, file-only) and answers 202 with `deadlineSecs` (the time left, measured on the node's monotonic clock, never a wall-clock time), `confirmToken` and the new address. The token is single-use, bound to the admin, node and change, and valid for the window. The UI puts it in the URL fragment of the new address (never sent to a server or a log) so the admin need not sign in again on a new origin.
- **Confirm** `POST /api/v1/guarded/pending/{id}/confirm`, with the token or a session of the same admin. Each registry row has a *proof hook* that returns the kind of proof the confirming request must carry: `new_socket` (`listen`: the request or the node's own probe arrived on the new socket, and the node's probe of the new DNS listener answers; `api-address`: the request arrived on the new socket), `new_cert` (`api-tls`: the handshake used the new certificate) or `proxy_list` (`trusted-proxies`: the request passes under the new list and the confirm step shows the client address the server now sees; no socket changes). A TLS-only change on the same address and port has no new socket, so the preview names a temporary parallel listener port (`proofPort`) that serves the new certificate for the window only; confirm arrives there. A row with no proof hook is not a `window` row. On success the node writes the `guarded` entry (through the primary on a replica, see 5), closes the old sockets and audits. A failed write rolls back.
- **Roll back** happens at expiry, on `POST .../cancel`, when the commit fails, or when a bind fails: the new sockets close, the old ones were never touched, nothing was written, and `settings.guarded_rolled_back` records the reason (`expired`, `cancelled`, `commit_failed`, `bind_failed`, `failed_start`). A wrong confirming request does not roll back (it is refused and counted); the window simply runs on.
- **`would_disconnect_you`** (409): a preview or apply that would leave the node with no API listener or no DNS listener once confirmed, or that removes the API listener the apply request itself came in on. Checked at preview and again at apply.
- **Recent sign-in and sessions.** All guarded routes need an interactive admin session. An agent token (any scopes) gets 403 `agent_not_allowed`; any other API token gets 403 `reauth_required` with a hint naming the file or CLI step (ADR-914). A weakening change also needs a sign-in within 10 minutes (`reauth_required`; for OIDC the sign-in is repeated at the provider with `max_age=0`), checked at apply. Failed confirmations (wrong phrase, wrong token) count: 5 in 10 minutes block guarded requests from that session (429).
- **Secrets in a request** (`cluster-join`'s bootstrap secret) follow the API-015 rule: HTTPS or loopback, write-only, never stored, never in the audit record, never in a preview.

**4. A change that needs a restart.** A `staged` entry is written to `state.db` immediately (it survives the restart that applies it) and listed by `GET /api/v1/guarded` as `pendingRestart`, shown "pending restart" with the way to restart for the install (systemd, Compose, Kubernetes) and, where section 4a allows it, a "Restart now" button. The server never restarts on its own; an admin, a supervisor or the explicit action does. Start-up reads staged entries from the `state.db` in the data directory that the file names (or the default); the `data-dir` pointer is followed one hop and nothing else is read from the target before that. One staged change at a time per node (409 `guarded_change_pending`, also while a window change is pending). A staged value that the file also sets is refused at preview ("set by file"). **Probation:** a node that starts with a staged or restored guarded entry marks it on probation. *Counter:* a small sidecar file `<data_dir>/guarded-probation` (mode 0600), not `state.db` (the failure may be that `state.db` will not open). Before any guarded value is applied at start-up the node writes the attempt count and the entry ids to it with an fsync and a rename; it deletes the file when the node is healthy. A start that finds the count at 2 drops the listed entries (written as dropped to `state.db` when it opens, and audited `settings.guarded_rolled_back`, `failed_start`) and starts from the file. A power loss counts as a failed start. *Healthy* is: the state opens, the API listener is bound, the node's own DNS probe answers, and (when the entry is `secrets-key`) the store is unlocked (`!secrets_locked`), within `max(confirm_window_secs, 180)` seconds (a constant floor, so a slow Pi compiling a large filter is not rolled back; a window setting of 30 does not shorten it). If the process exits or the watchdog fires first, twice in a row, the entries are dropped. *Re-encryption:* once any row has been re-encrypted under a new secrets key, dropping the entry must not return the node to the old key alone: the fallback keeps both paths (the new key as `secrets_previous_key_file`, so every row opens) and reports `secrets_rotation_incomplete`. *Confirmed entries:* a confirmed `window` entry (a `listen` or `api-address` on an interface that is not up yet at boot, a DHCP or VLAN address) also gets start-up protection: a bind failure for a guarded listener falls back, for that start only, to the file or previous value, with the health reason `guarded_bind_fallback` and audit `failed_start`, so the node never crash-loops on a missing address. The entry stays and is tried again on the next start. A restart inside a *window* change starts with the previous values: the pending change was in memory only (which is why `restart-now` is refused while one is pending, 4a).

**4a. Restart now (`restart-now`, `action`).** Owner decision 2026-11-17: a guarded change that needs a restart may offer "Restart now", but only where something will start the process again. The node never guesses: it exits only when it has a *supervisor* and the admin asks.
- *Detection.* At start the node computes `supervisor` once, from the environment only (no new config field), and **only from a declaration**: `TELLTALE_SUPERVISOR=systemd|docker|kubernetes|none`, set by the shipped systemd unit, Compose bundles and Helm chart (`none` always turns the action off). Nothing is guessed from `INVOCATION_ID`, `JOURNAL_STREAM`, `NOTIFY_SOCKET` or `KUBERNETES_SERVICE_HOST`: those are inherited by every child of a service (a terminal on a desktop, tmux under `systemd --user`, a CI runner), so detection would offer a button that exits a node nobody restarts (review 2026-11-17). A bare `docker run`, a hand-made unit or a pod without the variable has no supervisor. In every case the node cannot see the unit's `Restart=` line or the pod's owner, so a custom unit with `Restart=no`, a bare pod or a Job would stay down: the preview and the confirmation say "the node cannot check that your <supervisor> will start it again; if it does not, start it by hand", and the shipped unit, bundles and chart are the supported case. No supervisor means no button: the UI shows the manual steps, and the route answers 409 `no_supervisor`. `GET /api/v1/guarded` lists `supervisor` (kind and how it was found, or `none`) for each node.
- *Flow.* `restart-now` is a registry row of mode `action` with no config path, using the same two requests: preview (`POST /api/v1/guarded/restart-now/preview` with `node`; it lists the staged entries the restart will apply, the dropped-if-unhealthy rule, the expected outage in seconds, and for a cluster node what else it affects) and apply with its **own phrase** `<node-id> restart` and a reason. It needs an interactive admin session with a sign-in in the last 10 minutes (a restart is an outage, not a weakening, but a stolen session should not be able to bounce DNS); operator, viewer and every token get the refusals of section 3. **Agents and MCP are refused** (403 `agent_not_allowed`, no tool, no plan, no scope; the registry-against-catalog test covers it). It is rate-limited with the guarded limiter, and 5 failed phrases block the session as in section 3.
- *Mechanism.* Acceptance takes the node's **guarded-operation lock** atomically with the pending check and the audit write; while it is held every guarded route (preview, apply, confirm, cancel, `cluster-*`) answers 409 `restarting`, and a restart is refused (409 `guarded_change_pending`) while a window change, a `cluster-join` or another guarded operation holds it (`api_902_restart_excludes_other_guarded_operations`). After the checks the node audits, then drains (stops accepting new work, finishes in-flight queries up to a 5-second cap, flushes the state) and exits with code 75. A non-zero code is deliberate: systemd `Restart=on-failure` and Docker `on-failure` restart on it, and `always` and Kubernetes do either way. It is a normal shutdown path, not a crash: the watchdog's exit 70 and `failed_start` counting are separate, and the probation counter is incremented by the *start* that follows (section 4), not by the exit.
- *Audit and alert.* `settings.guarded_restart` (node, supervisor kind, the staged entry ids waiting, reason, actor, session, source address) is written before the exit, and the alert condition `guarded_setting_changed` fires with outcome `restarting`. A refusal (`no_supervisor`, a bad phrase, a pending window) is `settings.guarded_refused`. If the audit row cannot be written the restart is refused.
- *Interaction with the rollback window.* Refused while a `window` change is pending on the node (409 `guarded_change_pending`): a restart inside the window would drop the pending change from memory and, for an admin watching the countdown, look like a failure. Confirm or cancel it first. The restart has no countdown of its own; what protects a `staged` change is probation (above). The UI shows "restarting", waits for the node (polling the unauthenticated health endpoint, listing the staged entries) and, once it answers, shows `applied` or `rolled back (failed_start)` with the reason. If the node does not answer within `max(confirm_window_secs, 180)` seconds for each of the two start attempts, the UI says so and links `guarded-recovery` (the file, the CLI, `TELLTALE_IGNORE_GUARDED`). The session survives the restart because sessions live in `state.db`, unless `data-dir` moved to an empty directory, in which case the admin lands on setup.
- *Cluster.* Node-local like every guarded action: a restart of node X is previewed and confirmed for X only; there is no "restart all" and no rolling restart. Only the primary forwards it, with the same signed single-use assertion as section 5 (the assertion names the action; a replica's signature is refused; `api_902_forwarded_restart_from_replica_refused`), and X checks its own supervisor, phrase and recency. The preview warns when X is the primary (writes and config changes pause until it is back; replicas keep answering DNS from their snapshot, CLU-004) and when X is the only healthy resolver in its site by the cluster health view. A replica whose primary is unreachable may still be restarted: the staged entries are already in its `state.db`.
- *Failure.* If the drain does not finish within the cap the process exits anyway. DNS answers until the drain begins (CLU-004); nothing on the query path changes.

**5. Clusters.** (Owner decision 2026-11-17: only the primary forwards, accepted as written.) Every guarded setting is node-local: a change to one node never reaches another, and there is no "all nodes" apply (each node needs its own preview and phrase). `cluster-git` is the one cluster-wide setting; it is held by the primary and replicated like the other authority settings. Only the primary forwards a request for node X (ADR-914: "the primary forwards"; a replica that receives one answers 421 with the primary's URL and the UI sends it there). The request travels over the existing cluster channel (the ADR-946 pattern) with an assertion of the admin's identity, role and sign-in time, signed by the primary's cluster key, short-lived and **single-use** (it carries a nonce bound to the `previewId`, the node and the action; X keeps the used nonces for the assertion's lifetime and refuses a replay, `api_902_forwarded_restart_assertion_single_use`), which X checks itself; the forwarding node's own checks do not stand in for X's. X cannot see the admin's session, so it accepts the assertion only from the primary (the one member that already signs everything X trusts, ADR-005); a replica's signature on one is refused (test `api_902_forwarded_immediate_change_from_replica_refused`), so a compromised replica (other than a CA-holding one, see ADR-977 point 5) cannot turn on `allow-secrets-over-http` or widen `secret-file-dirs` on another node. A compromised primary can, as it can already replace that node's configuration. The pending change is held on X, and the confirmation must reach X's new address directly (the admin's browser, not the primary, so a primary can't confirm for the admin). Writing the entry goes through the primary (single writer, ADR-005): if X cannot reach the primary when the admin confirms, the confirmation is refused (409 `primary_unreachable`) and the window runs out and rolls back, so a node never runs a guarded value that no one will replicate. A standalone node or the primary writes locally. A target below the version that supports the kind ignores it (`clu_010`) and the preview says so. DNS keeps answering throughout (CLU-004): a forwarding or replication failure only fails the change.

**6. Audit and alerts.** `settings.guarded` once when a change is final (setting, node, mode, before and after with credentials redacted, reason, actor, session or break-glass, source address). `settings.guarded_rolled_back` with the reason code above. `settings.guarded_refused` (new) for a refused attempt past the role check: bad phrase, stale preview, `would_disconnect_you`, `reauth_required`, `no_supervisor`; it carries no values. `settings.guarded_restart` (new) for an accepted "Restart now" (4a). The alert condition `guarded_setting_changed` fires when a change is applied or staged and again on its outcome (`confirmed`, `rolled_back`), so a second channel sees a change an attacker with an admin session makes. Previews are not audited, but are rate-limited with the same limiter as writes.

**7. Agents and MCP.** Refused, not plan-only. Agent tokens get 403 `agent_not_allowed` on preview, apply, confirm and cancel; no `plan_*` tool exists, no `config:write:*` scope reaches a guarded setting, and ADR-070's plan store refuses guarded paths, so `apply_plan` can't replay one. `get_config` shows the settings redacted as before; `GET /api/v1/guarded` (what is set by file, what is pending) needs only `config:read`, and never returns a `previewId`, `confirmToken` or a pending value (only that a change is pending, its setting and its deadline); `api_902_listing_has_no_secrets_or_pending_values` checks it with an agent token. A test walks the registry against the MCP catalog and the plan tools and fails if one is reachable. This follows spec/13 §3.

**8. Failure and recovery.** The file always wins, and ADR-957 adds the CLI and environment escape hatches. Inside the framework: a failed bind, validation or reload changes nothing; an expired window restores the previous values; a restart inside the window starts with the previous values; a bad staged value is dropped after two failed starts.

**9. UI.** One `GuardedChange` component takes the setting's form and the registry entry and shows, in order: the preview (effect, nodes, warnings, a red "weakens security" mark), the phrase to type (paste is allowed; the server checks it), and then by mode the result: applied, "pending restart" with the restart steps (and a "Restart now" button when the node reports a supervisor, with its own preview, phrase and a plain note that the node cannot check that the supervisor restarts it), or the countdown (a bar driven by `deadlineSecs` from the server, not the browser clock; Confirm, Cancel, and the link to the new address that carries the token). On the new address the page opens on the confirm step, and a rolled-back change shows its reason on the old address. A weakening change shows the sign-in prompt first. `?` topic `guarded-settings`.

**10. Test plan.**
- *Unit:* the registry covers every guarded path; `weakens` is table-driven for every case in ADR-914; the phrase and preview binding; the window state machine under `tokio::time::pause` (expiry, cancel, double confirm, token reuse, wrong admin); the probation counter.
- *Integration (in-process node):* binds before release and keeps the old sockets until confirm; a bad bind and a bad reload change nothing; DNS answers all through (a UDP query in a loop); restart inside the window; every guarded route rejects an agent token, any other token, a viewer and an operator (table-driven over the registry); the generic kind routes refuse `guarded`; the plan store and MCP catalog hold no guarded path; audit rows and the alert event.
- *Cluster (two nodes):* forwarding with the signed assertion (a forged or stale assertion is refused), confirm directly at the target, `primary_unreachable`, N−1 ignores the entry.
- *Playwright (e2e server on two ports, T24.19's offsets):* phrase required, countdown and rollback, move the API port and confirm from the new address, a weakening change asks for sign-in, set-by-file lock, operator and viewer see no controls.
- *Review additions:* `api_902_forwarded_immediate_change_from_replica_refused`; `api_902_probation_after_partial_reencrypt_keeps_both_keys`; `api_902_probation_counter_survives_unopenable_state` (the sidecar); `api_902_confirmed_listener_bind_failure_falls_back_at_start`; `api_902_pending_proxy_list_not_used_for_break_glass`; `api_902_lockout_settings_are_file_only`; `api_902_listing_has_no_secrets_or_pending_values`; `api_902_test_row_absent_in_release` (the test-only rows compile only under the cargo feature `e2e`, never behind an environment variable alone).
- *Restart now:* `api_902_restart_now_needs_a_supervisor` (the detection table over environment combinations, the `none` override, Docker declared), `api_902_restart_now_refuses_agents_and_tokens`, `api_902_restart_now_own_phrase_and_audit` (the audit row is written before the exit; no audit, no restart), `api_902_restart_refused_while_window_pending`, `api_902_forwarded_restart_from_replica_refused`, `api_902_restart_exits_75_after_drain` (a test hook replaces the exit).
- *Data directory:* `api_902_data_dir_preview_lists_what_does_not_carry_over`, `api_902_data_dir_copy_is_optional_and_never_overwrites`, `api_902_data_dir_copy_never_copies_cluster_identity`, `api_902_data_dir_no_admins_needs_acknowledgement_and_sign_in`, `api_902_data_dir_pointer_read_before_state_opens`, `api_902_data_dir_probation_needs_admins_when_promised`.
- *Not tested here:* real systemd, Docker or Kubernetes restarts (documented, covered by the deploy checks).

**Alternatives rejected:**
- One window for every guarded setting: the `immediate` ones cannot cut the admin off, and a countdown on them trains people to click through.
- Staging address changes for a restart: the same lockout without the rollback, and a restart outside the window.
- A dead-man timer that needs only time to pass (apply, then keep unless an admin cancels): a locked-out admin cannot cancel.
- An implicit or automatic server-side restart: a crash loop on a bad value would have no way back. (An explicit, confirmed, audited "Restart now" only under a supervisor is accepted, 4a.)
- Detecting Docker's restart policy from inside: not visible, so the bundle declares it (`TELLTALE_SUPERVISOR`).
- Copying `cluster/` with the data directory: it duplicates a member's identity.
- Always copying state to a new data directory: it copies a live database and a key by default; it is opt-in.
- Reusing agents' plans: plans replay REST writes with the agent's credentials and keep the diff in the approval inbox and transcript, which is what ADR-914 keeps away from agents.
- Letting the primary confirm for a remote node: the check exists to prove the admin can reach that node.

**Consequences:**
- T27.14 to T27.17 only add a registry row, a dry-run check and an apply step each; the routes, state machine, audit and UI shell are T27.13.
- Needs T23.9 (recency) and T23.10 (`node_managed`) first; T27.13 records this and does not build either.
- Adds problem codes `guarded_only`, `guarded_change_pending`, `preview_stale` and `primary_unreachable` (with ADR-914's `would_disconnect_you`, `would_lock_out_admins`, `agent_not_allowed` and `reauth_required`), the audit action `settings.guarded_refused`, and routes under `/api/v1/guarded` (in the OpenAPI, none in MCP).
- `Listeners` gains stage, commit and abort (T27.14); the API server needs the same for its own sockets. Both are `telltale-net` and `telltale` code and need `make bench-smoke`.
- A guarded request on a node that is itself failing may be refused; the CLI and file remain.
- Amends ADR-914 in one place (only the primary forwards), recorded here because ADR-914 is Accepted; the owner accepted it 2026-11-17. The data directory stays staged, as ADR-914 says, and ADR-914's "never moves data" is reworded (ADR-914 section on `node.*`): the opt-in Copy state moves `state.db` and the default `secrets.key`, never `cluster/`.
- Adds problem codes `no_supervisor`, `target_not_empty`, `acknowledgement_required`, `clustered_node`, `restarting`, `rotation_incomplete` and `data_dir_not_persistent`, the health reason `data_dir_missing`, the audit action `settings.guarded_restart`, the environment variable `TELLTALE_SUPERVISOR` (set by the shipped bundles, unit and chart) and the exit code 75.
- `watchdog` and `file-paths` are `immediate` (owner decision); a later ADR could move them to `window`.

## ADR-957 — Lockout recovery for guarded settings: the file, an offline CLI and a start-up switch (Accepted 2026-11-17, owner decisions)
**Context:** ADR-956's window protects an admin who is still at the UI. It does not help when a confirmed value is wrong in a way found later (a certificate that expires, a proxy list that hides every client), when the primary is gone, or when no admin can sign in. ADR-914 says only "a node can always be recovered by editing its file and restarting". In a container the file is often a read-only ConfigMap, and a guarded entry lives in `state.db`, which the file cannot override unless it sets the same field.

**Decision:**
- **The file wins, always.** A guarded entry never overrides a field a file sets (ADR-040). Setting the field in the file and restarting is the first recovery, and the UI says so on every guarded form.
- **Offline CLI** (no UI: it is inherently offline, and the owner of the data directory runs it). `telltale guarded list -c <file>` prints each guarded entry on the node (staged, probation, active, including the `data-dir` pointer), `telltale guarded clear <id>|--all -c <file>` removes entries, and both open `state.db` directly, so the node must be stopped: the `data-dir` pointer is read and cleared in the file-named directory's `state.db`, every other entry in the active (target) directory's, and the command refuses if the node holds the lock on either. A clear is audited in `state.db` with the actor `cli:<os user>`, and the command prints what the node will use afterward (the file's values or the defaults), then says to restart. In a cluster it clears only that node's entries. A replica cannot publish a removal (ADR-005: the primary is the single writer, and it still holds `node/<id>/guarded/<setting>` and replicates it back), so a clear is also recorded locally as *suppressed until the primary's copy changes*: the node ignores that entry's replicated value while the primary's copy is the same one (compared by hash), logs the suppression at warn level and shows it in the UI and `guarded list`. On reconnect the node sends the primary a removal request authenticated by an offline-CLI token the clear wrote to `state.db` (single-use, bound to the node and entry, signed with the node's cluster key); the primary deletes the entry, and the suppression ends when the primary's copy is gone or changed. If the primary refuses, the suppression stays and the node says so.
- **Start-up switch.** `TELLTALE_IGNORE_GUARDED=1` makes the node start with every guarded entry ignored (not deleted), for places where running the CLI offline is awkward (Kubernetes: set the variable, let the pod restart). The node logs it at warn level, reports the health reason `guarded_ignored` and shows it in the UI until the variable is removed. It never ignores the file. It ignores a `data-dir` pointer too, so the node starts in the directory the file names.
- **Probation** (ADR-956 §4) is the automatic form: two failed starts drop the staged or restored entries.
- **Docs.** `docs/recovery.md` lists each symptom (cannot reach the UI after an address change, no DNS after a listener change, cannot sign in behind a proxy, store locked after a key change, a node that will not join, no admin accounts after a data directory move, a "Restart now" that did not bring the node back because nothing restarts it) with its fix, for systemd, Compose and Kubernetes, and every guarded form links to it. Help topic `guarded-recovery`.
- **Tests:** `api_902_cli_clear_removes_entries_and_audits`, `api_902_cli_refuses_while_node_runs`, `api_902_ignore_env_starts_from_file`, `api_902_staged_entry_probation_drops_after_two_failed_starts`, `api_902_cli_clear_survives_resync`, `api_902_cli_clear_data_dir_pointer`, `api_902_ignore_env_ignores_data_dir_pointer`, and a docs check that every guarded id appears in `docs/recovery.md`.

**Alternatives rejected:** an API or UI "reset guarded settings" (the UI may be the thing that is unreachable); an unauthenticated local socket (a second attack surface for the same goal); deleting entries on `TELLTALE_IGNORE_GUARDED` (a typo in the variable would destroy the state it was meant to protect).

**Consequences:** A new `guarded` subcommand and one environment variable, both documented in `docs/recovery.md`; a health reason `guarded_ignored` (with a UI link); the CLI/env tests join T27.13.

## ADR-946 — Federated reads run off the runtime workers: `block_in_place` under the blocking helper (Accepted 2026-11-17)
**Context:** upstream #7. `call_one` and `gather` in `crates/telltale/src/federated.rs` run a plain thread that blocks on the runtime. Called from a worker, the worker is held while the cluster stream's writer and reader tasks need workers to finish the call, so two concurrent reads to a peer that doesn't answer wedged a two-worker runtime. Several async handlers called a federated read directly on a worker.

**Decision:**
- **The wait.** `call_one` and `gather` run their future through `run_off_the_worker`: on a multi-thread runtime, `block_on` inside `block_in_place`, which hands the worker's queued tasks to another thread first, with no extra thread. A current-thread runtime has no other thread to take them, so its future runs on a scoped thread. `block_in_place` is a no-op off a runtime, so a blocking-pool caller takes the multi-thread path too.
- **The handlers.** A federated read in an async handler runs through `blocking()`. The `Backend` methods that can reach `call_one` or `gather` are `annotations`, `anomalies`, `blocking_pause`, `blocking_resume`, `blocking_state`, `cache_entries`, `cache_flush`, `cache_lookup`, `cache_stats`, `client_rhythm`, `clients`, `config_entries`, `config_version`, `exemplars`, `health`, `heatmap_network`, `identities`, `identity`, `kubernetes_workloads`, `latency`, `lists`, `list_hits`, `new_devices`, `overblocking`, `probes`, `queries`, `secrets_status`, `shadow_lists`, `timeseries`, `top`, `top_clients_rolling`, `top_in_group`, `top_range` and `upstream_checks`. Every async caller of one of them now uses `blocking()` or `spawn_blocking`. The ones that didn't were `clients`, `config_entries`, the ETag reads (`local_names`, `forwards`, `rules`, a config write's response), and a config write's group check, which reads the devices for a group-restricted agent only. The other `Backend` methods read local state and stay direct. `slo_parts`, a `Federated` helper that calls `gather` directly, has one async caller, the attribution handler, which runs it through `blocking()`.
- **No worker floor.** The optional floor of runtime workers is not added. The Pi-profile RSS can't be measured here, and the fix doesn't depend on the count: the regression test passes on two workers.

**Alternatives rejected:**
- *Refusing federated reads on a worker in debug builds.* It catches the mistake in tests, but a release build would still wedge.
- *Making the `Backend` methods async.* Every method and its local store would need async plumbing for no gain: `blocking()` is the existing pattern for backend reads.

**Consequences:** a federated read on a worker costs a hand-off rather than wedging the node. A new async caller of a federated read must use `blocking()`, and a new `Backend` method that reaches `call_one` or `gather` joins the list above.

## ADR-944 — Break-glass sign-in defaults to loopback, and a proxied request is never break-glass (Accepted 2026-11-17, owner decision)
**Context:** Upstream issue #63. The default `[auth.oidc] allowed_admin_networks` was the private networks plus loopback, so with `disable_local_login = true` any LAN device could try a password. The owner asked for a safer default. Two things make a loopback-only default need care: a reverse proxy on the same host is not in `[api] trusted_proxies`, so every proxied client arrives as `127.0.0.1` and would pass; and with Docker port publishing the peer is the bridge gateway, so an admin on the host is locked out of break-glass.

**Decision:**
- `allowed_admin_networks` is optional. Absent means loopback only (`127.0.0.0/8`, `::1`). Set means exactly that list, and `[]` allows nothing. The serde default distinguishes absent from set, so an explicit list is never overwritten by the default.
- A request that carries `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-IP` or `Forwarded` from a peer that is not a trusted proxy is never break-glass while the loopback default applies. Its address is the proxy's, so it can't be checked. This applies to form sign-in, HTTP Basic and the `/auth/status` `localLogin` flag. An explicit list skips this rule, because the operator chose those networks.
- In-process MCP calls (`OnBehalfOf`) keep the address they were made with and are checked against the same networks.
- Startup logs a WARN when `disable_local_login` is on and `allowed_admin_networks` is unset. It names the proxy and Docker cases. A trusted proxy in `[api] trusted_proxies` names the real client and is checked normally.
- Recovery: set `allowed_admin_networks` (for Docker, the bridge gateway's address) and restart. `docker exec` gives no password sign-in: the image has no browser or curl, and `telltale ctl` uses a token. Settings are file-only and need a restart, so no API can widen break-glass remotely.
- Migration: no file is rewritten. Operators who used the old private-network default and `disable_local_login` must set `allowed_admin_networks` explicitly; the startup WARN and `docs/running.md` say so.

**Consequences:** Break-glass from the LAN now needs one config line. Docker and proxy setups need a documented path (the bridge gateway in `allowed_admin_networks`, or the proxy listed). A proxy on the host that isn't listed locks its clients out of break-glass rather than letting them in. This is the conservative reading of the owner's request, and the owner can change the default by one line in `schema.rs` if they prefer private networks.

## ADR-943 — Svelte attribute quantifiers: `{n}` in a quoted attribute is written as a JS expression, and a guard keeps it that way (Accepted 2026-11-17, owner decision)
**Context:** Upstream issue #64, "2FA can't be enabled". Svelte 5 reads `{6}` inside a quoted attribute value as an expression, so `pattern="[0-9]{6}"` reached the browser as `[0-9]6` and no six-digit code matched. The TOTP enrolment (Settings) and the sign-in code (Login) both had the bug.

**Decision:**
- Every such attribute in `ui/src` is written as `pattern={"[0-9]{6}"}`, a string expression, so the braces reach the DOM unchanged.
- `ui/scripts/check-quantifiers.mjs` runs first in `npm run check`. It fails when any quoted attribute in a `.svelte` file, double- or single-quoted and across lines, contains `{digits}` or `{digits,digits}`. It is a source check, so it catches the pattern before a build.
- The Playwright suite enrols TOTP with a real RFC 6238 code and signs in with one, so a regression that breaks the pattern also fails the suite.

**Consequences:** A new quoted attribute with a quantifier fails `npm run check` until it is written as an expression.

## ADR-942 — UniFi offline clients on the fork's router model: `offline_days` 0 keeps the reservations (Accepted 2026-11-17)
**Context:** The upstream merge brought T8.2's offline clients (ADR-166): the console's client history and the configured clients, named by their last address, for `offline_days` (30 by default, 0 for connected clients only). The fork had already made a DHCP reservation (T22.2, ADR-902) name its device while it is offline, whatever the history says. Both can't hold at `offline_days = 0`.
**Decision (proposed; the conservative reading of both):**
- The history and the configured clients (`rest/user`) are read only while `offline_days` > 0. A dated row names a device only inside the window; an undated row can't be judged against it, so it is kept (`unifi_known` keeps it), as in ADR-166. The configured clients are read like the history rows: an alias without a reservation names its offline device too. The fork's earlier worry (a configured client's last address may belong to someone else by now) applies equally to the history rows, which are kept; the window and `offline_days` are the control for both.
- A reservation names its device at any `offline_days`, including 0. It is the router's configuration, not a history, and the fork's T22.2 behaviour is kept. The Routers form's help topic (`router-offline-clients`) says so.
- Offline devices stay out of "seen" (ADR-166), and the fork's reservations still count as seen (the T22.2 decision); a reservation is therefore not an offline device here.
- An offline client is not a current answer anywhere else either (sync review, 2026-11-17): it gives no address binding to discovery (ADR-910, ADR-924), publishes no DNS name, isn't counted in a network's devices, and is left out of `/dhcp/leases`, which has no offline marker yet (an owner decision, Open in spec/10 T8.2). It still names the device in the query log.
**Consequences:** `offline_days` = 0 means "no history names", not "no offline names". The owner may prefer the stricter reading (0 also drops reservations); that is a change to `unifi_reserved` in `routers.rs`, one line, and a test.
**Owner decision (2026-11-17):** `/dhcp/leases` and the UI list offline clients, marked `offline` (as upstream does); they stay out of DNS names, discovery's address bindings and a network's device count, as above. Built 2026-11-17 (spec/10 T8.2): `DhcpLease.offline` is always serialized; the offline row's `dnsName` is absent.

## ADR-945 — The leases list shows offline clients, marked `offline` (Accepted 2026-11-17)
**Context:** ADR-942 keeps an offline UniFi client out of DNS names, discovery's bindings and a network's device count, and left `/dhcp/leases` without it because the API had no marker. The owner chose to show it.
**Decision:** `GET /api/v1/dhcp/leases` lists every router lease, including the offline clients, each with `offline` (always present: `true` for an offline client, `false` for connected and reserved rows). An offline row has no `dnsName`. The listing is the only thing that changes: `device_dns`, discovery's `lease_observations` and `networks()`'s device count still skip offline rows. The UI marks them with an "offline" badge (Clients → Discovered, Networks → a network's devices).
**Alternatives rejected:** leaving them out (the owner's earlier reading, which hid a device the admin may want to see); a separate endpoint for offline clients (a second list the admin would have to join by hand).
**Consequences:** a client that gives an `offline` row has no last-seen time, since the lease carries only its end time. Adding one needs the router's history timestamp kept on the lease (later work).

## ADR-941 — The Pi-hole import's comparison: the sample, the resolver it asks, and when it stops (Accepted 2026-11-17)
**Context:** T24.6 asks for `telltale import pihole --compare`, which resolves a sample through the Pi-hole and TelltaleDNS and reports the differences. The task text doesn't say which names, which TelltaleDNS, or what happens when a server doesn't answer.

**Decision:**
- **Sample.** The imported local names and CNAME names, up to 20 exact deny entries, and the names given with `--sample`. A and AAAA are asked of both servers. At most 200 names.
- **The TelltaleDNS side.** The node's own resolver at `--telltale` (`127.0.0.1:53` by default). It answers from its running configuration, so before the import is applied the report shows what the node answers now, and the help says so.
- **Transport.** Plain UDP, two seconds a query, no retries. A server that doesn't answer five queries in a row is named in the report and isn't asked again; when neither answers, the comparison stops.
- **What counts as a difference.** The rcode, or the sorted addresses and names of the answer. TTLs are ignored.
- **Read-only.** It sends standard queries and nothing else. The import page's comparison (T24.18) is the same function.
- **Budget.** The whole comparison stops after 60 seconds, and the report says how many names it covered. A server that answers every other query never reaches the five-in-a-row limit, so the budget is what bounds the time. The addresses are the admin's to give (the admin already holds the configuration), so the UDP goes wherever the admin names.

**Alternatives rejected:**
- *Comparing the configuration offline.* It wouldn't show what a client gets over DNS (rewrites, blocking, the cache and the special names all act in the resolver).
- *TCP or DoT to the Pi-hole.* What the household's devices get is the UDP answer; the comparison should match that.
- *Retrying silent servers.* A wrong address would then cost minutes; five silent queries say it clearly.

**Consequences:**
- A comparison in the UI asks the TelltaleDNS address the admin gives, by default the node that serves the page. In a cluster, it's that node's resolver unless another address is given.
- The sample is a sample: a difference in a name that isn't in it goes unreported.

## ADR-940 — Importing a Pi-hole export: a plan, applied as one configuration change, admins only (Accepted 2026-11-17)
**Context:** T24.18 puts the Pi-hole import on the admin page: upload, preview, apply. An import replaces configuration in bulk, and the API writes configuration one entry at a time (ADR-069). ADR-040 makes the config files' names read-only through the API. ADR-914 says bulk changes are admin changes with a typed confirmation and an audit record.

**Decision:**
- **Who.** Admins only. An agent's token is refused by the auth layer (403 `forbidden`) and by the handler (`agent_not_allowed`); operators and viewers get 403. spec/13 §3 lists the import among the operations no agent may make.
- **Preview.** Changes nothing. It returns a plan: a `planId`, what would be added, changed or skipped (each with its reason and where it points: a URL or file, the servers, the members, the record values), the notes, and the comparison when asked (ADR-941). A plan is held in this node's memory for ten minutes (at most eight are kept), like an agent's plan (AGT-007). A restart discards them. A plan's ID is 32 random bytes, and only the admin who previewed it may apply or discard it; another admin gets 404.
- **Retries.** The three routes take `Idempotency-Key` as the configuration writes do (AGT-003): a retried apply or discard gets the first answer, a preview is keyed on a hash of its body and options, and a successful answer is kept under the admin's key for a day.
- **Apply.** The plan's writes go in one transaction (`put_managed_batch`), and the version moves once. Before the write, the merged configuration (the files plus the stored entries plus the plan) must load; the configuration version must still be the preview's, or the answer is 409 and the preview is run again. The node then reloads. If the change is stored but the reload fails, the audit record is written anyway, with `applied: false`, and the answer is 500 saying the change was saved, so the audit log never misses a change that happened.
- **Names.** An entry of a name that exists is replaced (`change`), as an API override replaces the file's (ADR-069); the file's entry comes back when the override is deleted. A name the config files define is `skip`ped for local names, conditional forwards and devices, because ADR-040 keeps those read-only through the API (the merge ignores a stored device of a name the files use, so writing one would store a dead row). A file list (a `file://` adlist in the export) is flagged in the notes, since it reads a file on this machine. A stored rate limit replaces the file's `[ratelimit]` section as a whole, and the item says so.
- **The default groups.** Pi-hole's lists join the default group's lists, and Pi-hole's upstreams join the default upstream group's members. Their other settings stay. An omitted list means every list (`lists` omitted), so the merge keeps it omitted.
- **Conditional forwards.** Each Pi-hole route is a forward entry with the servers of its group's upstreams. The `pihole-forward-N` upstreams and groups aren't written. A suffix is routed once: when a v5 `rev-server` and a dnsmasq `server=/domain/` name the same domain, the first is kept and the conflict is noted.
- **DNSSEC.** The mode is a file setting, not an API one, so it's reported as skipped with the line to add to the file.
- **Audit.** Applying is audited as `import.pihole` with the counts and the configuration version. A preview isn't written to the audit log.
- **The UI.** The apply needs the word `IMPORT` typed in. The page is a Settings tab that admins alone see. Its comparison takes the Pi-hole address, this node's address (default `127.0.0.1:53`) and extra sample names.

**Alternatives rejected:**
- *Writing the file.* The API can't write the configuration files (ADR-040), and the CLI already writes them for a person who reads the output.
- *One request per entry.* A failure in the middle would leave half an import in place, and each write re-checks the whole configuration.
- *Keeping plans in the state database.* An import is short-lived, like an agent's plan; a restart discards it, which is the safe side.

**Consequences:**
- Undoing an import means deleting the entries it added. The audit record lists the counts; the preview lists the names.
- A `change` replaces an entry of the same name: the import page says so before the apply.
- The plan's bodies are the entries the store keeps: a credential isn't part of a Pi-hole import, so no secret passes through it.

## ADR-939 — The Pi-hole import's worker: a child process with an empty environment (Accepted 2026-11-17)
**Context:** An uploaded Pi-hole export is untrusted input. A zip bomb, a malformed archive or a gravity.db built to crash the reader must not reach the DNS process (ADR-913 says why: a panic or an allocation failure in an in-process parser aborts DNS). ADR-913 names a worker mode (`telltale discovery-worker --import`) that lives on the M25 branch, not in this tree.

**Decision:**
- **The worker.** A hidden subcommand, `telltale pihole-import-worker PATH`, run by the server as a child process of the same binary. It reads the file, converts it with the importer (`pihole::convert`), and prints one JSON object. It has no configuration, no state database and no secrets.
- **Isolation.** `env_clear()`, stdin null, stdout piped, a 60-second timeout, and kill on drop. The worker starts with the discovery workers' spawn preparation (`telltale_net::worker::prepare_spawn`: no ambient capability, and this process not dumpable, so the worker can't read the server's memory). The worker applies the discovery workers' hardening first (`telltale_net::worker::harden`, ADR-933 and ADR-934: `RLIMIT_DATA` at 1 GiB, no capability, `no_new_privs`, the seccomp filter that refuses `bind`, `listen`, `ptrace`, `process_vm_*`, `io_uring` and x32 calls, not dumpable); if that fails, it prints the reason and converts nothing. The server reads the worker's stdout through `take(64 MiB + 1)`, so an answer over the cap stops the read there and kills the worker. The upload is written to a `0600` temporary file that's removed after the worker returns, on a blocking thread.
- **Limits.** The HTTP body limit is 64 MiB. The archive reader's limits apply (`archive.rs`: 256 MiB per entry (lowered by ADR-988's review, 2026-11-18) and in all, no zip64, no encrypted entries, CRC checked, no path is written). A gravity.db is opened read-only from a temporary copy.
- **Failures.** A file the importer can't read is 422 with the reason; a worker that stops, or takes too long, is 422 too, and DNS keeps answering.

**Alternatives rejected:**
- *Parsing in the server process.* A panic there aborts DNS; the worker's crash is contained.
- *Reusing ADR-913's `--import` worker now.* It isn't in this tree. The import reuses the discovery workers' hardening (`telltale_net::worker`), not their mode; when the M25 branch's `--import` mode lands, the two can share one mode.

**Consequences:**
- The `tokio` crate's `process` feature is enabled, which adds no crate. The image delta is the feature's code; not measured here (the release image build measures it).
- The worker runs the same binary, so it has the same version as the server.
- Preparing a spawn makes the server process not dumpable, as it already is once discovery's workers start: its core dumps and a debugger's attach are refused.
- Two previews run at once at most (the rest get 503 `unavailable` until one ends), so the memory of uploads and workers is bounded (review of T24.18, LOW 4).

## ADR-937 — Per-list "Update now" and a Confirmed current column on the Lists page (Accepted 2026-11-17)
**Context:** T24.17 (FLT-004, ADR-905) asks for an "Update now" in each row of the Lists status table, and a per-list freshness display. The API already takes `names` (ADR-905), so no server change is needed. The task doesn't say what an off list's row does (the server reports an off list as `skipped` and queues nothing), or what freshness an inline list has (inline rules have no download to confirm).
**Decision:**
- A row's **Update now** sends `POST /api/v1/lists/refresh` with `{"names": ["<that list>"]}`, the same request as the page-wide button. It shows for operators only (`can('operator')`), and is disabled while that list is refreshing, while any row's request is in flight, and when the list is off. The off row's tooltip says to turn the list on; the server is not asked.
- A refresh of one list reads "<name> updated" in the status line; the whole-set sentence ("every enabled list confirmed current …") stays for a refresh of every enabled list.
- **Confirmed current** (for every role) shows `ago(lastSuccessUnixSeconds)`, which reads "never" for an enabled download list that never downloaded. An off download list that never downloaded reads a muted "off" instead (nothing to confirm, and "never" would suggest a fault). An inline list reads "inline", since it has no download to confirm.
- The status line says "Downloading <name>…" from the click until the answer, so a row's request is never reported as done before it is answered. The whole-set wording is chosen by the refresh's scope (every enabled list, or one row), not by counting the lists.
- No dry-run control: `dryRun` stays for agents and `telltale ctl`.
**Consequences:** no API, OpenAPI, MCP or config change; the help topic `list-update-now` covers per-row updates. The per-row request is audited as `lists.refresh` with its names, like the page-wide one.

## ADR-934 — Worker spawn and filter hardening under the systemd unit: no ambient capability, no capset call without one, a non-dumpable parent, and the x32 and io_uring calls refused (Accepted 2026-11-17)
**Context:** The review of the T25.3 fixes (276315b) found four gaps in ADR-908's worker hardening.
- **N1 (HIGH).** The unit sets `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `SystemCallFilter=~@privileged`. A child inherits the ambient set, so the worker held `CAP_NET_BIND_SERVICE`, and `drop_worker_capabilities` called `capset`, which `@privileged` contains. A filtered call with no error number kills the process (SIGSYS), so every worker died on every systemd install.
- **N2 (MEDIUM).** The filter checked the native syscall numbers only. An x32 call (`nr | 0x40000000`) reached `bind` and bound a loopback port (demonstrated on WSL2, kernel 6.6). io_uring's bind and listen skip the filter on kernels 6.11 and later. A worker of the same uid could open `/proc/<parent>/mem` under Yama ptrace scope 0, because the parent is dumpable.
- **N3 (MEDIUM)** is ADR-933.

**Decision:**
- **Ambient cleared before exec.** `telltale_net::worker::prepare_spawn` makes every discovery worker spawn clear the child's ambient capability set between fork and exec. The call is `prctl(PR_CAP_AMBIENT_CLEAR_ALL)`, which takes no pointers. A non-root worker then execs with no capability.
- **`capset` only when a capability is held.** `drop_worker_capabilities` reads `CapPrm` and `CapEff` from `/proc/thread-self/status` and calls `capset` only when either is non-zero. A worker with none never calls it. A root worker (tests, or a container run as root) still drops its capabilities. An inheritable bit alone grants nothing, since there is no exec file capability and no ambient one.
- **Parent not dumpable.** `prepare_spawn` also makes the parent not dumpable (`PR_SET_DUMPABLE` 0), so a worker of the same uid can't open its `/proc/<pid>/mem` (EACCES without `CAP_SYS_PTRACE`). It is called before each spawn, so only a process that runs discovery changes. The costs: this process refuses core dumps and debugger attach. The supervisor is the only caller.
- **Review of the m25-b branch (N6, N7, N8, 2026-11-17).** Not dumpable makes the `/proc/self` files that belong to the owner (`/proc/self/io`, mode 0400) root-owned, so a non-root telltale (the systemd unit, the image, the chart) lost the host's write-rate metric, the SD-card wear signal on a Pi. Measured as uid 65534 (`/proc/self/io` refused, while `status`, `limits`, `maps`, `smaps`, `exe`, `fd`, `task` and the `/proc/self` owner stay readable by the process itself): `prepare_spawn` opens `/proc/self/io` before it makes the process not dumpable (`sys::pin_self_io`), and `telltale_net::self_io_text` re-reads that descriptor with `pread` at offset 0. The trade-off that remains for operators: once discovery runs, a non-root administrator can't read this process's `/proc/<pid>/io`, `environ`, `mem`, or attach a debugger or `strace` to it. Root still can (`CAP_SYS_PTRACE`). It is in `docs/running.md`. The non-root test `dsc_002_write_rate_survives_a_worker_spawn` (uid 65534, run from a root test binary by re-executing it) is the proof.
- **The parent-read test (N7).** `dsc_002_worker_cannot_read_its_parent` makes the middle process dumpable first, in both modes, because a process that changed uid at exec is already not dumpable and the shield would pass without `prepare_spawn`. The decisive check is that `prepare_spawn` clears the dumpable flag (any Yama setting). The open is an end-to-end control that runs only under Yama scope 0, where the worker can read a dumpable parent. Under scope 1 (the Ubuntu default and this container) Yama refuses the open either way, so the control is skipped and printed as skipped.
- **Filter.** The seccomp filter refuses every number at or above `0x40000000` (the x32 range) with EPERM, and also refuses `io_uring_setup`, `io_uring_enter` and `io_uring_register` with EPERM. The arch check and the native deny-list are unchanged, plus `arm` (ADR-933).
- **Tests** (`telltale-net` `worker::tests`): `dsc_002_worker_refuses_x32_and_io_uring`; `dsc_002_worker_without_capabilities_never_calls_capset` (the filter kills a `capset` call, and a worker with none survives; the control dies with SIGSYS); `dsc_002_worker_cannot_read_its_parent` (the middle process is made dumpable first; `prepare_spawn` must clear the flag; the open control runs only under Yama scope 0); `dsc_002_spawn_clears_ambient_capabilities` (as root: the raised ambient set is inherited without `prepare_spawn` and cleared with it).

**Alternatives rejected:**
- `SystemCallErrorNumber=EPERM` in the unit: the worker would get EPERM for `capset`, and `harden` fails closed. It would also change what every other filtered call in the unit returns. The capset skip fixes the cause and keeps the unit as it is.
- A second uid for the worker: the image, the chart and the unit run one user (ADR-908), and a second one adds deployment work for a read this kernel setting already blocks.
- Leaving the parent dumpable and relying on Yama: Yama 0 is common on hosts and in containers, and it is the case that was open.

**Consequences:** the systemd unit is not yet run on a systemd host (the review ran none either), so the `@privileged` claim rests on `systemd-analyze syscall-filter @privileged` listing `capset`, and on the kill test. The ambient and capset tests need root (they skip otherwise). The worker's `CapInh` can be non-zero under the unit, since systemd sets an inheritable bit for ambient capabilities; it grants nothing, and the test asserts the permitted, effective and ambient sets only.

## ADR-933 — The worker's seccomp filter covers 32-bit ARM, so a discovery worker runs on armv7 (Accepted 2026-11-17)
**Context:** `install_worker_seccomp` covered x86_64 and aarch64, and returned `Unsupported` elsewhere (fail closed, ADR-908). The image ships `linux/arm/v7` (`.github/workflows/image.yml`) and the release ships `telltale-armv7-linux`. On a 32-bit Pi, enabling discovery crash-looped the worker (`discovery_worker_failing`) and left the feature unusable. The review (N3) asked for a recorded decision.

**Decision:** write the filter for 32-bit ARM. `AUDIT_ARCH_ARM` (`0x40000028`) is the architecture check. The deny-list uses the ARM EABI numbers from `libc` (`bind` 282, `listen` 284, `ptrace` 26, the `process_vm_*` and io_uring calls at their generic numbers), and the x32 range check (ADR-934) applies to it too, where it does nothing. Everything else is as on the other architectures: the worker holds no capability, sets `no_new_privs`, and a call from another architecture kills it.

**Alternatives rejected:** keeping the refusal and naming the architecture in the health reason (leaves the feature unusable on the 32-bit Pi the image ships); a worker without a filter on armv7 (drops the "cannot share the DNS port" guarantee that the other architectures keep).

**Consequences:** the armv7 filter is type-checked and clippy-checked for `armv7-unknown-linux-gnueabihf` (the test binary included), and the filter's numbers come from `libc`'s ARM table. It has not run on armv7 hardware here. The owner's Pi check is an Open item in `spec/10` (T25.3).

## ADR-930 — The designated node, its names, and the audit of `[discovery]` (Accepted 2026-11-17)
**Context:** ADR-907 says `[discovery] node` names the node that runs discovery, else the primary or the standalone node, and never an ephemeral pod or a witness. It doesn't say what a name is matched against, or when the section is audited. T25.2 settles both.
**Decision:**
- `node` matches a member's cluster node ID or the node's configured name (`[node] name`, or the hostname). An operator who knows the name in the UI doesn't need the hash. A name that matches nothing runs nothing, and the status shows `designated: false` on every node.
- An ephemeral pod or a witness is never designated, even when named (`gate::designated`).
- The inventory thread and the workers start and stop at start-up and on every reload, from the same gate (`discovery::runtime::Runtime::reconcile`). An API change reaches the designated node through the reload it already triggers.
- `[discovery]` is audited as `discovery.config_changed` with `source = file`: at start when the files set the section, and on a file reload that changes it. Changes made through the API are audited by the API with their author (as for every managed kind). The start-up record reads the files' own copy (`Sources.file_config`), never the merged config, so a section the API set is not labelled as coming from the file (review of T25.3).
- Reconciles run in the order their reloads happened. Each reload takes a generation (`Runtime::next_generation`) where it is handled, and a reconcile whose generation is older than the newest applied one is skipped. Two quick reloads (on, then off) can't leave the inventory running when the configuration says off (`dsc_001_reconciles_apply_in_order`, review of T25.3).
**Alternatives rejected:** matching the node ID only (the hash is unreadable in the UI); auditing every reload whether or not the section changed (noise in the log every SIGHUP).
**Consequences:** a node renamed in the file is no longer designated by that name, and the status says so. The owner confirms the name rule while this ADR is Proposed.

## ADR-929 — Discovery worker protocol v1, its debug-only fault jobs, and the status API before T25.12 (Accepted 2026-11-17)
**Context:** T25.3 builds the worker processes of ADR-908 before the SNMP codec (T25.4) and the import parser (T25.11) exist. The worker needs a protocol that those tasks can build on, and a way for the tests to see a worker panic, hang or run out of memory without a test-only build of the server.
**Decision:**
- Frames are a u32 big-endian length (counting the kind byte), one kind byte, then the payload: kind 1 JSON (at most 1 MiB), kind 2 binary chunk (at most 512 KiB). The length is checked before any payload is read or allocated (`discovery::frames`).
- Messages are JSON objects tagged by `t`: `hello`, `job`, `result`. Protocol 1. A `hello` mismatch of protocol or build is answered with the worker's own `hello` and an exit code of 3; the parent raises `discovery_worker_version_mismatch` and starts nothing else.
- The `fault` job (`panic`, `hang`, `alloc`) exists only in debug builds, so the integration tests can run a real worker through a panic, a hang and an allocation past `RLIMIT_DATA`. A release worker answers it as an unknown op. The bench-only override of the pacing floor is T25.4's, with the pacing.
- The status API `GET /api/v1/discovery/status` (DSC-014) is added now, for the worker card and the health reasons. It shows whether the node runs the inventory and each worker's state. It is `discovery:read` (DSC-013) only from T25.12, so agents get 403 on it until then (`auth::agent`).
**Alternatives rejected:** a fault switch in an environment variable (the environment is cleared for the worker, and a variable the parent can't set would be a second channel); a test-only build (the systemd e2e needs the release binary).
- Review of T25.3 (2026-11-17), the parent's side: the stderr of a worker is read one line at a time and each line is kept to 400 bytes (the rest is read and dropped up to the newline), with control characters escaped before logging, so a worker can't grow this process's memory or forge a log line (ADR-908, CLU-004). A worker that reports a limit other than the one asked for (dumpable, another data limit, another `oom_score_adj`) is refused and restarts with backoff. A job's timeout is per op: a `ping` has 10 s, every other op 30 s (the SNMP walk budget of ADR-908); a new op names its own timeout in `supervisor::timeout_for`.
**Consequences:** the worker frame reader is the one piece of discovery code that reads bytes from a child process. Both readers are fuzzed by `worker_frames`: the synchronous one the worker uses and the async one the main process uses (`frames::read_frame_async`, which moved into `frames.rs` for that). The target fails if the two readers disagree on any input. The status API is read-only and unauthenticated only as far as every other status route is.

## ADR-928 — `[discovery]` as a managed kind: admin-only, no agent scope, and the first write waits for N−1 members (Accepted 2026-11-17)
**Context:** ADR-907 makes `[discovery]` a shared section written through the config entries API as the managed kind `discovery`, admin-only, with dry run, `If-Match` and audit, and says the first write waits while any member runs N−1 (CLU-010). It doesn't say where the kind lives, what the version threshold is, or whether later writes wait too.
**Decision:**
- The kind is `discovery` at `/api/v1/discovery-settings/default`. The path is `-settings` because `/api/v1/discovery` is the inventory's own read (T25.12).
- Every field is admin-only (`settings_kinds::admin_keys`): an operator's change is 403 naming the field, and an agent is 403 (`agent_not_allowed`). The auth table refuses the whole `/api/v1/discovery` prefix to agents until `discovery:read` exists.
- The first write (none stored through the API yet) is refused with 409 `members_too_old` while any member reports a version older than `DISCOVERY_SINCE` = 0.8.0, or one that can't be read. Later writes don't wait: the members already took the first.
- A forwarded write to a primary older than 0.8.0 is refused with 409 `upgrade_required` (as the other settings kinds are, CLU-010).
- Review of T25.2 (2026-11-17): an unreleased build reports `dev`, which no gate can read. This node's own `dev` counts as the crate's version (`forward::gate_version`), because the code it runs knows every kind it has, so a `dev` cluster's own node is not "too old". Another node's `dev` stays unreadable and is refused. Release builds carry their version (CI stamps it), so they pass.
- `DISCOVERY_SINCE` is 0.8.0, the release that carries the section, the same as `SETTINGS_KINDS_SINCE`. The gate is tested with the real build version through the real route (`dsc_001_current_build_passes_the_gate`).
**Alternatives rejected:** waiting on every write (a member that is upgraded and back would still need the first write to be accepted, so this only added a second wait); the threshold at 0.9.0 (the workspace is 0.8.0 until it ships, so every node, the node itself included, counted as too old and the first write could never succeed); a feature flag advertised by each member (it would need a new field in the membership record; the version already says what a member knows, and the gate is the same check the other kinds make).
**Consequences:** `DISCOVERY_SINCE` moves with the release that carries this section. The first write on a cluster with an older member is refused until that member is upgraded, which the UI says.

## ADR-932 — Credential file open: no followed symlink, no FIFO block, and the `libc` constants (Accepted 2026-11-17)
**Context:** The m25-snmp review (2026-11-17) found two races in `telltale-snmp`'s credential read. The path was canonicalized and then opened by name, so a link swapped in between pointed outside the secret directories. A FIFO was opened before its metadata was checked, so the open could block.
**Decision:**
- The file is opened with `O_NOFOLLOW | O_NONBLOCK` (`libc` 0.2, the constants only, through `OpenOptionsExt::custom_flags`, which is safe code). A final symlink fails the open, and a FIFO does not block.
- The metadata is read from the handle, and only a regular file of at most 4096 bytes is read.
- The canonical path is canonicalized again after the open. Its device and inode must match the handle's (Unix; off Unix the canonical path alone is the check).
- The read buffer is allocated for the cap (4097 bytes) up front, so a read never reallocates and leaves no unzeroized copy.
- The decoded v2c community is held in `Zeroizing`.
**Alternatives rejected:** a `std`-only check (`symlink_metadata` before the open) leaves the same race; an `openat` walk of each path component is more code than the risk needs for admin-owned secret directories.
**Consequences:**
- A swap of a directory on the path between the last identity check and the read is not detected. The secret directories are admin-owned (`[node] secret_file_dirs`), so this is accepted.
- `libc` is a dependency of `telltale-snmp` only. The lock already has it, so no new package enters the tree. The image delta is 0 bytes until T25.6 links the crate into `telltale`.
- Owner decision: accept or reject the `libc` constants.

## ADR-931 — SNMPv3 time window: only authenticated Reports move the clock; an authNoPriv Report answers an authPriv request (Accepted 2026-11-17)
**Context:** The m25-snmp review (2026-11-17) found that the ADR-908 amendment of the same day moved the one-per-minute resync limit from unauthenticated to authenticated Reports, and that an authPriv request could not be resynced at all. RFC 3414 §3.2.7a says a notInTimeWindow Report is sent at authNoPriv, and the agent checks the time before it decrypts the scopedPDU. The agent's Report therefore arrived at a level the client dropped, and it often carried request-ID 0. An agent that answers discovery with boots and time 0/0 (RFC 3414 §4 allows this) never worked at authPriv.
**Decision (proposed):**
- An unauthenticated Report never sets the agent's clock. Only a Report whose MAC verifies may.
- For an authPriv request, a Report at authNoPriv is accepted if its MAC verifies, and its request ID is 0 or the request's ID. Any other reply at authNoPriv is dropped.
- At most one authenticated time resync per agent per minute. The request is sent once more, with the new boots and time.
- The window follows RFC 3414 §3.2.7b: boots at 2^31 - 1 are stale, and equal boots more than 150 s behind are stale.
**Alternatives rejected:**
- Downgrading the request to authNoPriv after a failure: weakens the level the owner configured.
- Keeping an unauthenticated resync with a per-minute limit: a spoofed Report could still move the clock once a minute.
**Consequences:**
- The ADR-908 amendment (2026-11-17) that describes the resync is kept as written, and this ADR governs the rule. Owner decision: accept this ADR, which then supersedes the one-per-minute wording of ADR-908.
- Interop with the owner's net-snmp v3 agents is Open until the `TT_SNMPD_*` values are supplied.

## ADR-925 — Inventory thread and its inputs before `[discovery]`: off by default, the Home Assistant feed deferred (Accepted 2026-11-17)
**Context:** T25.1 builds the inventory thread (`telltale-inventory`) and its read-only sources. The switch that starts them is `[discovery]`, which is T25.2. Nothing in the server reads Home Assistant's raw answer after `routers.rs` folds it into the lease view, and the owner has not yet decided how a discovery node is chosen.
**Decision:**
- The thread's `spawn` exists and is tested through `tick`, but no startup path calls it. T25.2 wires it behind `[discovery] enabled` (default false) and the designated-node rule (DSC-001). `discovery/mod.rs` allows dead code for that reason.
- Sources wired in T25.1: the filtered kernel neighbour table, the routers' lease view (`devices::Leases`, class 1, a lease with a `router` name), and the passive mDNS lease view (a claim with no class, ADR-923; IP-only when no MAC, and attached to the MAC entry that holds the address otherwise). Home Assistant's named devices are a pure function (`sources::ha_observations`, tested on fixtures). Its live feed needs `routers.rs` to keep the last raw answer, and that stays Open until T25.10 (DSC-009) reads Home Assistant's registry anyway.
- `inventory_merge` is a fuzz target that includes `crates/telltale/src/discovery/inventory.rs` by path, so the fuzzer runs the same source the server builds, without a dependency on the binary crate.
**Alternatives rejected:** starting the thread now (an off-by-default feature would then run on every node); a separate `telltale-inventory` crate (the module needs `devices` and `routers`, which live in the binary crate, and the merge is small).
**Consequences:** the inventory is not visible to any API until T25.12. Nothing in `telltale` reads `inventory.json` yet. The Home Assistant feed is Open.

## ADR-924 — Inventory retention and expiry: two missed polls, per-entry caps, and the import rules (Accepted 2026-11-17)
**Context:** ADR-910 fixes the caps and says a host counts as absent only after two polls in a row miss it, without saying how a poll interval maps to time, or what an entry with no address left should do.
**Decision:**
- A source's binding expires when `seen + max_age < now`. `max_age` is twice the source's poll interval: 120 s for the neighbour table (polled every 60 s), 900 s for the routers and mDNS (their cadence is "every few minutes", `devices.rs`).
- An entry with no address, no import, and no change for `retention_days` (7) is removed. An entry with only a name and no address stays until that retention passes; names are not expired separately.
- Imports: an import past `[discovery.import] retention_days` (30) is removed with all its rows. Deleting an import removes its bindings, clears its ports when no other import holds the entry, drops import-only names, and removes entries left empty.
- Caps: the oldest MAC entry (by `last_seen`) goes at 4,096, the oldest IP-only entry at 1,024, and the oldest import goes first when the import count reaches 16 or the import rows pass 8,192. A single import over 4,096 rows is refused.
- A conflict flag clears on the sweep once no two entries claim the address.
- The import ports (open TCP) are kept on the entry, sorted and capped at 16. They are cleared when the last import holding the entry goes.
- Each source's record of an address is its own (per address, source and import). A claim from another source never refreshes it, so an import cannot keep a stale neighbour binding alive (T25.1 review).
- Mutes are capped at 1,024 (the oldest goes first) and pruned by the sweep for entries that are gone or for mutes that have expired.
- A stored `inventory.json` is checked on load: an import bit past 15 or a bit no kept import holds is dropped with its bindings and ports, and the 8,192-row cap is applied again. A file this version cannot read (a corrupt file, or another version) is moved to `inventory.json.bad` and the inventory starts empty, so the owner's data is kept, not overwritten.
**Alternatives rejected:** a fixed per-source TTL with no link to the poll interval (it would drop hosts on a slow router poll); per-row import expiry (more state for the same effect).
**Consequences:** a host the neighbour table drops for two minutes loses its neighbour binding, and it keeps its other bindings. A router that is slow to answer keeps its binding for 15 minutes.

## ADR-923 — Source classes for the sources ADR-910 leaves open: Home Assistant, mDNS, configured names (Accepted 2026-11-17)
**Context:** ADR-910 sets the precedence classes for UniFi and OPNsense (class 1), the neighbour table (class 2), SNMP ARP (class 3), imports (class 4) and UniFi history (class 5). It does not place Home Assistant, passive mDNS, SNMP identity or the configured client name. The first draft of this ADR put Home Assistant and mDNS at class 2. The T25.1 review (2026-11-17) found that an unauthenticated mDNS announcement would then make its address an SNMP destination (ADR-907), and that an identity answer would back its own eligibility.
**Decision:**
- Home Assistant trackers and passive mDNS announcements carry their addresses as claims with no class. They never make an address current, never make it an SNMP destination (ADR-907), and never win a conflict. They sort after the classed bindings, with imports. Both come from the device or its tracker, not from a router's own table.
- SNMP identity (sysName and printer names) and the configured client name (`[[client]]`) carry no class. SNMP identity carries names only. The configured name attaches to entries and never creates one. An SNMP ARP binding is class 3.
- A claim with no MAC whose address a MAC entry holds as a current binding attaches to that entry, with its names and ports. Any other claim with no MAC goes to the IP-only class (ADR-910).
- Name ranks follow ADR-910 exactly. A name's label is labelled with its source for ranks 6 and 7. A name replaces the earlier name of the same kind from the same origin (the `[[router]]` for router aliases), so a rename shows.
- Conflicts: the newest class 1–3 claim wins the address. A class 4, class 5 or unclassed claim never removes a current binding and raises no conflict: it is a claim, not a current owner. A current claim on an address another MAC entry holds as current flags both entries `ip_conflict`, with a hold of 900 seconds from that claim (`conflict_until`). A competing claim refreshes the hold, and the flag clears only after the hold has passed (the sweep checks the hold, not the owner count, because the displaced binding is gone from the address at once). IP-only entries take no part in conflicts.
- A claim with no MAC attaches to the MAC entry that holds its address as a current binding, or failing that, to the MAC entry that holds it from the same source (so a device's own mDNS record does not split off an IP-only duplicate when its router binding expires).
- Each source keeps its own record of an address (per address, source and import). A source refreshes only its own record, so another source's claim on the same address never keeps a stale binding alive (ADR-924).
- A randomised MAC (the locally administered bit set) gets `randomized` and never raises `new_device`.
**Alternatives rejected:** Home Assistant at class 1 (its trackers come from a template, not a router's table, so a stale tracker would outrank a live neighbour entry). Home Assistant and mDNS at class 2 (the first draft: an unauthenticated mDNS announcement would make its address SNMP-eligible).
**Consequences:** a device seen by Home Assistant and by the neighbour table has one current address, the neighbour's, and Home Assistant's stays a claim. The address that ADR-910's DNS opt-in (DSC-012) may use therefore comes only from classes 2 and 3; an mDNS-only address never supplies one. The owner confirms the classes at the T25.0 review. Until then this conservative choice stands.
## ADR-922 — Router hot reload: the live list, per-router state, debounced reads, and checks that never send a stored key to a new address (Accepted 2026-11-17)
**Context:** `routers::run` took the `[[router]]` list at start-up and returned at once when it was empty (T8.2). T23.7 needs a router added, changed, or removed through the API to take effect without a restart, with the others' names kept (CLU-004, 02 §8), and T23.8 needs a check of a draft that reads a router once.
**Decision:**
- **The live list.** The poll loop reads `Sources.config` each round. A reload (any node's configuration change, or a secret the store changes) wakes it at once (`Sources.routers_changed`).
- **Per-router state.** A router keeps its last answer while its settings are unchanged. A changed router is read again, debounced to at least 5 s after its last read; it keeps its last names until that read succeeds, unless its address or kind changed (another device: its names go at once), and its status reads `waiting` until then (review of T23.7). A removed router drops its answer, so its leases go with the next round. A router whose stored credential may have changed is read again, debounced the same way. The store is not asked on the loop (a lock held at start-up delayed the runtime's workers).
- **Failure isolation.** Each read runs on its own task and reports through a channel. A router that fails (refused, timed out, malformed, oversized) keeps its last answer and is retried within 15 s; the others are not delayed. DNS is never on this path.
- **Who reads.** A stored credential is read on the primary or a standalone node only; a replica gets its names through the peer leases (ADR-125). A file credential is read as before on every full member, and a resolver pod reads nothing.
- **Status.** Each router's last read (state, time, error without any password, devices, networks, and where it's read) is kept for `GET /api/v1/routers`.
- **Checks.** `POST /api/v1/checks/router` reads a draft once and saves nothing. It sends a stored credential only where it was saved for: the saved router's own secret, when the draft's address and TLS settings equal the saved router's, or the secret named for this router (`<kind>.<name>.<field>`) when either no router is saved under the draft's name (a new router) or the draft's address and TLS settings equal the saved router's, and no other entry of any kind (router, alert destination, sink, OIDC provider, Git source) uses it. Any other reference is dropped; the check runs without it and says so (`credentialSent: false`) (review of T23.8; review NEW-1 and NEW-2: a saved router's named key never goes to a new address, and a secret another kind uses is never sent for a router's name). Both checks are admin-only and refused to agents. `POST /api/v1/checks/router-certificate` makes one TLS handshake and returns the names, fingerprint, and PEM; it trusts nothing, and the PEM is saved only by the form.
**Consequences:**
- A stored key never goes to an address the admin didn't save it for, even by an admin's check.
- Residual (review NEW-1): a new router that reuses the name of a deleted router can have that router's leftover named secret sent to its new address, since no saved entry under the name records the old address. Deleting a router does not remove its secret; the admin can delete the secret itself.
- A router whose console renews its certificate fails until the new certificate is saved (ADR-120).
- The poll loop, its reads, and its failures are tested with local fake routers only (HTTP, and TLS on 127.0.0.1).
## ADR-921 — Router integrations as a managed kind: admin-only, file-read-only, named secrets, no file paths through the API (Accepted 2026-11-17)
**Context:** T23.7 makes `[[router]]` a kind the API and UI change (ADR-903 §2, §7; API-016). ADR-903 §2 says `router` follows ADR-040 (names the files define are read-only through the API) and §9 says every credential is entered through `SecretField`. It doesn't settle three details: who may write a router, whether an API body may name a file path, and how a certificate is entered, since `tls_ca` is a file and ADR-903 §1 says the router's CA "becomes an inline `tls_ca_pem` (T23.8)" without a field.
**Decision:**
- **Admin only.** Creating, changing, or removing a router is an admin's (403 for operators; agents never, by their forbidden list and scopes). A forwarded write without a role (an older node) is 409 `upgrade_required`, as credential writes are (ADR-903 §4).
- **Files win.** A name the files define is read-only here: `PUT` and `DELETE` are 409 `set_by_file` (ADR-040). The files' entry shows as `source: file`.
- **Named secrets only.** `api_key_ref`, `api_secret_ref`, and `password_ref` name stored secrets (422 `secret_missing` when none has the name). A body that names `api_key_file`, `api_secret_file`, `password_file`, or `tls_ca` is 422 `invalid_config`: the API takes no file paths for a router, because a path the API can set is a path an admin can point at any readable file (ADR-903 §4, the path rules). The files keep their paths.
- **The certificate as text.** `tls_ca_pem` holds PEM certificates (16 KiB at most; each must decode, and at least one is required; exclusive with `tls_ca`). The form saves the chain the console presents (its certificate and the CAs it sends), so a console signed by a private CA is trusted with its CA, and nothing else is trusted for that router: a router client trusts those certificates in its settings, not the public roots (ADR-120). Review of T23.7: a bare marker or a body that isn't base64 is refused.
- **Ephemeral pods read no router** (ADR-903 §7 and the Helm resolver pods' note in ADR-120): the controller, or the primary for a stored credential, reads them.
**Consequences:**
- A router made in the UI can't use a file: an operator who wants a file adds it to the configuration file (the UI says so).
- `tls_insecure_skip_verify` is not offered by the UI and is still file-only.
- The MCP surface gets `list_routers` (read-only). No MCP tool, and no agent scope, writes or checks a router (ADR-903 §5).

## ADR-919 — Secret fields in the UI: save writes the secret first, clear unlinks, and a file the configuration sets stays read-only (Accepted 2026-11-17)
**Context:** T23.6 adds the Integrations & secrets page and `SecretField`, the one control every credential is entered through (ADR-903 §9). The API has two rules that shape the form: a `*_ref` naming an unset secret is refused (422 `secret_missing`), and a delete of a secret a field still names is refused (409 `secret_in_use`). So a form can't save an entry and its new secret in one request, and can't delete a secret through an entry that still names it.
**Decision:**
- **Save writes the secret at once.** "Save secret" stores the value (`PUT /api/v1/secrets/{name}`) before the entry is applied, then sets the entry's `*_ref` in the draft. The stored value exists even if the entry is never applied; the Integrations & secrets page lists it as unused.
- **Clear unlinks; it doesn't delete.** "Clear" removes the reference from the draft, and the entry stops using the secret when it is applied. The state reads "will be cleared" until then, and Undo restores the reference. The stored value stays until someone deletes it on the Integrations & secrets page: a delete before the apply would be refused with 409 `secret_in_use`, and another entry may use the same secret.
- **Names.** A new secret is named `<kind>.<entry>.<field>`: for an alert destination's token, `alert.<entry>.token`, with the entry's name lowercased and slugged (runs of other characters become `-`) and cut so the whole name is at most 63 characters. An entry with no usable name has no default, so the field waits for a name and `alert..token` is never proposed. The name is editable before it is saved.
- **An existing secret is offered, not deleted.** An entry whose default name is already stored shows "already stored" with **Use it** (which links the entry) and **Replace**; it never shows Delete. On the Integrations & secrets page a typed name that is stored is a replacement: the name stays editable and the value goes under it.
- **A typed value holds Check and Apply.** A value typed into a field and neither saved nor discarded would otherwise be dropped without a word. The form disables Check and Apply until it is saved (**Save secret**) or discarded (**Discard**).
- **Writes carry the head.** Every secret write sends the secrets head's etag, as the page last read it, as `If-Match` (ADR-903 §2). A head that has moved is refused with 412: the page says so and reads the list again.
- **Unreadable and inline.** A stored secret this node can't read shows "can't read it" with **Replace**. A `*_file` the node can't read shows the reason beside "set by file". A value the file sets inline is read-only ("set inline").
- **Set by file.** A `*_file` the configuration sets is shown read-only with its path and, when this node can judge it, whether it's readable; the API refuses changes to it (ADR-903 §2). A `*_file` set through the API (not by the files) is not read-only: an admin's stored secret replaces it in the draft, and **Remove the path** drops it on an entry with no stored secret. A `*_ref` the files name is not reported as set by the file: `set_by_file` lists the inline value and the `*_file` path, as the server has always done, so an admin can still change the reference.
- **Plain HTTP.** The field explains a 403 `insecure_transport` (turn on HTTPS, or `[api] allow_secrets_over_http`), and warns before the save when the page itself is on plain HTTP from another host. The page can't tell whether the node allows plain HTTP for secrets, so the warning says the server *may* refuse.
- **No show toggle, no prefill.** The value input is a password field with `autocomplete="new-password"` and password-manager ignore attributes. ADR-903 §9 says `autocomplete="off"`; `new-password` is chosen because it tells a password manager that this is a new credential to store, not a login to fill, which is what the field takes; the owner should confirm it while this ADR is Proposed. After a save, a failure or a replacement the input is empty; the value is never returned by any API, so a page can't show it again.
- **Entries report file-set credentials.** `ConfigEntry.setByFile` lists the credential fields the configuration files set for an entry (`token_file`, an inline secret), for file-only entries too; before this it was empty for them, so a file's token looked editable.
**Alternatives rejected:**
- Deleting the secret when it is cleared: refused while the entry still names it, and a second entry may use it.
- Saving the entry and the secret in one request: the API takes them separately (the secret store has its own rules, ADR-903 §4), and a failed entry save would leave an unlinked value.
- A reveal or copy button: it would contradict write-only (ADR-903 §9).
**Consequences:**
- The form makes two requests for a new secret (the value, then the entry); a cancelled drawer leaves an unused secret, which the Integrations & secrets page shows.
- `SecretField` is reusable: the routers (T23.8) and the other forms (T24.16) pass the draft's `*_ref`, the `*_file` path and the role, and get the same states.
- Operators see status only: the Integrations & secrets tab and the field show the same states, with the controls left out.
- The image gate is unaffected unless the bundle grows past the budget (400 KiB gzipped; now about 252 KiB).
## ADR-917 — Replication details for stored secrets: orphans by epoch, a joining node's hand-over, the shadow table, and the reverse heal (Accepted 2026-11-17)
**Context:** ADR-903 §6 fixes what replicates (stamped rows over the cluster channel, tombstones, orphans, re-encryption under each member's key, the reverse heal). Building it left points it doesn't settle, which T23.5 had to decide.

**Decision:**
1. **Orphans without a base stamp.** A live cluster row that a member holds, that the current primary doesn't list, and whose stamp's epoch is older than the primary's, is an orphan: kept, flagged, never used, never deleted. ADR-903 §6 judges "stamped in an epoch after the new primary's base". The base isn't needed: the primary lists every cluster row it holds, so anything from an older epoch it doesn't list is one it never had, or its own orphan, and both are unusable. This judges more rows than the base rule would, and only ever toward "not used".
2. **A primary's orphans are not shared.** The primary's export leaves out its own orphan rows, and its head is computed over the rows it shares, so a member's head and the primary's agree when both hold the same shared rows.
3. **A stale row yields to the primary's listing.** A listed name whose row a member holds from an older epoch takes the primary's row, whatever the stamps say; the displaced row goes to the shadow table, not dropped.
4. **The shadow table** (migration 12, `secrets_shadow`, same columns as `secrets`; migration 13 keys it by `(name, origin)`). It holds one slot per name and origin: a `local` row a cluster row displaced, and a `cluster` row a newer listing displaced (a stale copy under point 3, or a tombstone that a later live listing replaces under point 10). A tombstone that stays a conflict is not displaced: it stays the row in `secrets`. A displacement never replaces a `local` shadow. Shadows are never used, appear in status as `shadows`, are sealed under the node key like the rows (rotation, the start-time re-encryption and the backup strip cover them), and come back as the local row when the cluster's rows are purged. The purge drops the `cluster` shadows. Reverse heal and heal-as-replica refuse while a local shadow exists: it is this node's own value, and it's recovered by hand (`docs/secrets.md`). A heal refuses while an orphan it can still read exists, and drops one it can't read (point 15).
5. **Joining.** ADR-903 §6 says a standalone node's rows "become cluster rows on the primary" at join. Implemented as `secrets.adopt`: a joining full member offers its own rows once per primary epoch; the primary takes the names it doesn't hold, stamped in its epoch, and reports the rest as conflicts. At `cluster init` the primary's own standalone rows become cluster rows in place, once.
6. **Heartbeats.** The fields are tags 33 to 38 of `Heartbeat`. `secrets_head` is the node's own head; `secrets_applied` is the primary head the node last verified and applied (its own head on the primary). Nodes without the tags read as "not reported" and are never fetched from.
7. **Reverse heal is all-or-nothing.** A locked primary whose rows are all the cluster's is refilled only from a replica that holds every one of its rows at the same stamp (tombstones included). A partial answer changes nothing.
8. **Removal purges.** The sync task purges a member's cluster rows once the cluster lists it as removed (`removed.json`), and the purge is audited as `secrets.purge`. A full member has no leave path (only resolver pods leave), so none purges on leave.
9. **Where the tests are.** The seeded partition and failover schedules are in `telltale`'s secrets module, over the store, not in `telltale-cluster/tests/sim.rs` (the election simulator), because the replicated state is the store's. The two-node tests run over the real mTLS channel in-process (`secrets_api_tests`), and the two-process test runs the built binary (`crates/telltale/tests/secrets_cluster.rs`).
10. **A listing doesn't undo a deletion, unless it's a later write.** A cluster tombstone of an older epoch that a newer primary lists as live stays a tombstone row on the replica, and the name is reported as a conflict (`Applied.conflicts`) and audited as `secret.conflict`, when the listed row's stamp is older than the tombstone's: a value the deletion superseded, held by a primary that never had the deletion. A listing stamped after the tombstone is a later write, possibly a re-creation in a later epoch: it is taken, and the tombstone goes to the cluster shadow slot (point 4). The stamps decide, not the epochs alone: checking the epoch alone kept a secret created again after an epoch change from ever reaching a replica (review N1). A same-epoch tombstone still yields to a higher stamp, as before. Before this point, the listing brought the revoked value back silently (review M4).
11. **An emergency primary's answer is not authoritative.** `FetchAns.authoritative` is `false` for an emergency primary (absent means `true`, so an older primary's answer reads as authoritative). A replica applies a non-authoritative answer by stamp only: it fills a name where it holds none, or an older cluster row, and displaces nothing and orphans nothing. An emergency primary's sync pass does no hand-over, refill or key replacement (ADR-903 section 4; review M1).
12. **Hand-over is audited and never re-creates a name.** Each name the primary takes is audited as `secret.adopt`, and each refusal as `secret.adopt_conflict`, with the joining peer. A name the cluster holds, live or deleted, is a conflict; a row the primary can't accept (an unknown kind, an invalid value) is a conflict rather than a silent skip (review M3). Gating adoption to one epoch of the joiner's join is not done: the registry records no join epoch, so it is open for the owner.
13. **A replica answers the reverse heal for the current primary.** A replica's registry lists only itself, so the primary's registry check can't pass there. A replica answers `secrets.fetch` only for the primary of the highest epoch, which is always a full member; a primary answers only full members (`!ephemeral && !witness && !removed`). Found by the two-node reverse heal test (review M5).
14. **Pulls are checked against the heartbeat.** A replica applies an answer only when its head is the head the heartbeat announced and its primary is in the heartbeat's epoch. An answer that runs ahead of the heartbeat is not backed off: the heartbeat is a pass behind the answer, so the next pass (a few seconds later) asks again, nothing is applied, and a run of such answers is logged at warn from the third (review L1; the code does this from 2026-11-17). A failed pull is backed off as before.
15. **A heal drops what no key can read.** A heal (heal-as-replica, or the primary's reverse heal) drops an orphan this node can't decrypt, with the other rows it can't read, and refuses while an orphan it can read exists: an orphan is no replica's row (the cluster doesn't list it, and an older epoch stamped it), so no fetch restores it, and keeping it locked the node for good when it had lost its key (review N2). The heal's audit record `secrets.heal` names the dropped orphans and gives the counts of rows and cluster shadows cleared (names and counts, never values), and the log says the same. A local shadow still refuses a heal (point 4). Recovery of a locked node whose local shadow is the blocker is the documented step in `docs/secrets.md`.

**Consequences:** No new crate. Two migrations (12 and 13). Everything the sync does to the store, the registry, the credentials or a file runs on a blocking thread (`tick`), so the runtime that serves DNS never waits on it (CLU-004; review M2); nothing reads the manifest, so pins and canary bakes don't gate replication. A heartbeat grows by a few dozen bytes when a node holds secrets. Plaintext intermediates on the channel are only partly zeroized: the answer and hand-over buffers cross the channel as `Vec<u8>` (review L2, partly).

**Alternatives rejected:** a base-stamp orphan rule (it needs the primary to record a base at promotion, and it misses rows the base rule would call fresh); deleting orphans (a row must never vanish without a tombstone); the shadow row in `secrets` under a second name (it breaks the one-row-per-name invariant every reader relies on).

**Status:** Accepted 2026-11-17. The owner accepted every ADR for the overnight run. Points 1 and 5 deviate from ADR-903 §6's wording. Points 10, 14 and 15 are the review fixes of 2026-11-17 (N1 to N3 of the second review), and point 10 supersedes the epoch-only rule of its first form.

## ADR-918 — Shared settings sections: field-level file precedence, what a request may leave out, and admin-only fields (Accepted 2026-11-17)
**Context:** T24.12 (`[special]`) and T24.13 (`[local]`, and `[clients]` with `mdns` only) make three one-entry sections changeable from the UI and API under ADR-914's tiers. The one-entry kinds so far (rate limit, exclusions, simulation) replace the file's whole section. For these, that would let an API value override a field the files set, which ADR-040 and ADR-914 forbid. ADR-914 didn't settle three details: which fields the files win over, what a request that leaves out a file-set field means, and what an empty `device_domain` means.
**Decision:**
- **Files win field by field.** The loader records the dotted keys (`special.ddr_name`, `local.device_domain`, `clients.mdns`) that the configuration files and environment set explicitly (`Config.file_set`). At merge time a stored field whose key is in that set is ignored, so the file's value applies. The UI shows it as "set by file".
- **Requests.** A `PUT` stores every editable field (fields left out take their defaults, as the other one-entry kinds do), except a file-set field left out, which keeps the file's value (as a credential does under ADR-903 §2). A `PUT` that sets a file-set field to another value is 409 `set_by_file` naming the field. Setting it to the file's own value changes nothing and is accepted.
- **Read-only fields.** `hosts_files` and `mdns_port` are shown in the entry and can't be set here: sending back the value the entry shows is accepted, another value is refused (422, naming the field).
- **`device_domain`.** An empty string or `null` means no device names (off). It isn't an invalid domain.
- **Admin-only fields** (`special.ddr_name`, `clients.mdns`). A change to one is checked on the server: an agent's is 403 `agent_not_allowed`; an operator's is 403 naming the field; a change forwarded from a node too old to say who made it is 409 `upgrade_required`. An agent can't write `[clients]` at all: no agent scope reaches `/api/v1/clients-settings/default`.
- **Plans.** The MCP plans for these sections fill the fields left out from the entry as it is now, as the other plans do.
**Alternatives rejected:**
- A stored partial section laid over the file: a file change would then leave an old API value hidden under a field the file no longer sets. Full sections are stored instead.
- Silently ignoring a file-set field in a request: the UI would show a value it can't set. A 409 naming the field says so.
- Treating `device_domain = ""` as invalid: the UI and agents both need a way to turn names off with the same form.
**Consequences:**
- `ConfigEntry` gains `setByFile` and `answering` (optional fields, so an older node's answers still read). `Explanation` gains `special` (optional).
- Environment-set keys count as file-set, so the UI says "set by file" for them too. A separate "set by environment" label is a follow-up.
- A file change takes effect on the next reload. A stored value for a field the file now sets is ignored at once, and kept in `state.db` until someone reverts it.
- **`[clients] mdns` takes effect after a restart (H1).** The mDNS listener starts once, at start-up (`restart_only_changes` lists it). A change is stored at once, but the dry run and the write say it takes a restart on every node, and device names follow mDNS only while the listener the node started with runs (`device_dns::run` takes the start-up value). Starting and stopping the listener on reload is a follow-up.
- **Set-by-file marks come from the files (M2).** The API marks a field from `file.file_set` (the loaded files), not from the configuration in effect: a merged configuration doesn't carry `file_set` (it isn't serialized). `plan_settings` checks against the files too, so the marks and the refusals agree.
- **Known divergence on a promoted primary (M2, not fixed here).** `overlay` lays the stored section over the files, skipping only the fields the node's own files set. On a promoted primary, a field the files set can keep the value the cluster version stored, not the node's own file value, so that node's effective value can differ from its file (the UI still marks the field "set by file"). The files-win rule is therefore not yet exact on that path. Fixing it (drop stored values for file-set keys when a node is promoted, or carry the node's own `file_set` through `overlay`) is a follow-up, and the next change to these sections on a promoted primary must not rely on the stored value.
- **Version gate (M3, CLU-010).** The settings kinds go only to a primary at 0.8.0 or later (`SETTINGS_KINDS_SINCE`). An older primary gets 409 `upgrade_required` from the replica before anything is forwarded, not an opaque failure.

## ADR-916 — The fork's image gate is 25 MiB compressed per architecture (Accepted 2026-11-16)
**Context:** `00` §5 and OPS-001 cap the image at 15 MiB compressed per architecture, from upstream's footprint priority. On 2026-11-16 the fork's merged work (the Pi-hole parity work, the upstream sync and M23 wave 1, about 17,500 lines) took amd64 from 14.76 to 15.13 MiB. Three cuts that drop nothing brought it back under (ADR-915), but M25 (an SNMP codec, `aes`, an XML parser), M26 (the map UI) and M27 (UI for every setting) will add more. The owner runs Pi 4/5 and Linux hosts, where 25 MiB pulls in seconds. Memory (RSS) is the budget that limits small hosts, and it is unchanged (`00` §5: idle ≤ 20 MiB, ≤ 64 MiB loaded).
**Decision:** the owner chose to raise the fork's gate to **25 MiB compressed per architecture** (`deploy/image/size.py` `LIMIT`, `make image-all`, the image workflow). Upstream's 15 MiB stays upstream's. Every task still reports its image delta (`deploy/image/size.py --oci`) in its Done note, so growth stays visible, and a milestone that adds more than 2 MiB says why. ADR-915's cuts are kept. The RSS budgets, the `FROM scratch` image, the static musl binary and the multi-arch matrix are unchanged.
**Alternatives rejected:** keeping 15 MiB (constant trimming work for little gain on the owner's hosts); 20 MiB (less room for M25–M27); no gate at all (growth goes unnoticed).
**Consequences:** Pi Zero-class devices, OpenWrt or OPNsense packages (upstream #12, #49) are a poorer fit. A change from upstream that relies on the 15 MiB headroom needs no special handling, since the fork's gate is looser. On an upstream sync, keep `LIMIT` at 25 MiB.

## ADR-914 — Which settings the UI may change, and how risky ones are guarded (Accepted 2026-11-16)
*How the guarded tier works is detailed in ADR-956 (framework) and ADR-957 (recovery), Accepted 2026-11-17.*

**Context:** On 2026-11-16 the owner made a standing rule: every setting, route and tool gets a UI control (spec/10, API-901). An audit of the fork against the UI found settings with no control at all:
- `[special]` (M24, ADR-904) and most of `[local]` (M22, ADR-901). Both are shared sections, not node-local (`telltale-config/src/shared.rs` `NODE_LOCAL`).
- `[clients] mdns`, which `[local] device_mdns` needs before it does anything.
- OTLP export (`[telemetry.otlp]`), which is node-local.
- `[agents] enabled`, the agents kill switch (AGT-009).
- The security gates and bootstrap settings: the secrets key files, `secret_file_dirs`, `allow_secrets_over_http`, `allow_insecure_basic`, the listeners and their TLS, `api.listen`/`api.tls`, `api.trusted_proxies`, cluster init, join and bootstrap, `[cluster.git]`, `node.*` identity and storage, the watchdog, and the file paths `trust_anchors_file`, `signatures_file`, `hosts_files` and `zone.file`.

The audit recommended showing the last group read-only. The owner chose admin controls instead (2026-11-16), on condition that the design is safe. The risks are concrete:
- a wrong listener, API address, TLS or proxy change locks every admin out of the UI, and a wrong DNS listener change takes the LAN's DNS down;
- a key typed into the store it protects is protected by nothing;
- a widened `secret_file_dirs` would undo T23.2's path rules, and `allow_secrets_over_http` or `allow_insecure_basic` puts credentials on the wire in clear;
- a cluster init or join replaces a node's configuration.

**Decision:**
- **Three tiers.** Every setting is in exactly one:
  1. **Ordinary:** a managed kind with the role the area already has (viewers read; operators or admins change), as for groups and upstreams.
  2. **Admin-only fields:** a field inside an ordinary kind that only an admin may change, enforced by the server. An operator's change is 403 naming the field, and the UI marks the field `admin: true` (the T23.2 pattern).
  3. **Guarded:** the security gates and bootstrap settings below. Admin role only, with the guardrails in the next point.
- **Rules for every tier.**
  - The file still wins over every UI value (ADR-040). A value set in a file is shown as "set by file" with the file's path, and an API write of it is 409 `set_by_file`. Removing it from the file uncovers the UI value, and the UI says so before that happens.
  - Role checks are on the server. The UI only hides or disables what the server would refuse.
  - A section that is node-local (`NODE_LOCAL`) becomes editable only through `node_managed` (T23.10), as an entry for the node it applies to (`node/<node-id>/<kind>`). Only that node applies it. An N−1 node ignores `node_managed`, so its own file stays in force.
  - A change that fails to apply keeps the previous configuration, and DNS keeps answering (CLU-004).
  - A change to `auth-policy` or the sign-in settings is refused (409 `would_lock_out_admins`) if no admin could still sign in afterwards (for example, TOTP made required for admins while no admin has enrolled).
- **Ordinary and admin-only kinds this ADR adds.**
  - `special`: a shared singleton kind (`/api/v1/special-names/default`) for all `[special]` fields. Operators change it. `ddr_name` is admin-only, because it is one name for the whole cluster tied to every member's certificates (T24.12).
  - `local`: a shared singleton kind (`/api/v1/local-settings/default`) for `device_domain`, `device_ttl`, `device_mdns`, `auto_ptr` and `default_ttl`. Operators change it. `hosts_files` is a path and is guarded (below). `device_inventory_addresses` (DSC-012) is admin-only (T24.13, T25.16).
  - `clients`: a shared singleton kind that takes only `mdns` in M24, admin-only, because turning it on opens multicast listening on every member. `mdns_port` stays file-only and is shown read-only. The other `[clients]` fields join the kind in T27.9 under the operator role.
  - `otlp`: a `node_managed` kind for `[telemetry.otlp]` (endpoint, headers through `header_refs`), admin-only like `sink` (T23.11).
  - `agents`: a shared singleton kind for `[agents]`. Turning agents **off** (`enabled = false`) needs the operator role; turning them **on** needs an admin. The server compares the old and new values, so an operator's write that turns agents on is 403. No agent scope writes this kind, so an agent can neither switch itself on nor off. `rate_per_minute` and `require_approval` are admin-only (T27.6).
- **The guarded tier.** Every guarded change:
  - is admin role only, checked on the server; agent tokens are refused whatever their scopes (403 `agent_not_allowed`, on the spec/13 §3 list), and there is no MCP tool, plan or `config:write:*` scope for it;
  - needs an interactive admin session; API tokens of any kind get 403 `reauth_required` with a hint naming the file or CLI step (as ADR-903 §8 does for passphrase backups);
  - has a dry run that says what the change does, which nodes it reaches and what it can break;
  - needs a typed confirmation: the request carries `confirm`, which must equal a phrase the dry run returns (the node ID and the setting, for example `pi-a listen`). The server checks it, so a script or a forged request can't skip it;
  - is audited as `settings.guarded` (who, node, setting, before and after with credentials redacted, the reason) and raises the one-off alert condition `guarded_setting_changed`;
  - is a `node_managed` entry on the node it applies to when the setting is node-local. A change to one node never reaches another.
- **Weakening changes.** These are flagged in red as weakening security, and need a sign-in within the last 10 minutes (403 `reauth_required`, T23.9) on top of the confirmation:
  - adding a directory to `secret_file_dirs`;
  - turning on `allow_secrets_over_http` or `allow_insecure_basic`;
  - adding a `trusted_proxies` entry;
  - turning off the watchdog;
  - removing or downgrading TLS on the API or on a DoT/DoH/DoQ listener, or moving `api.listen` from loopback-only to a wider address;
  - in `auth-policy` (T27.6), removing a role from `totp_required_roles`.

  Narrowing `secret_file_dirs` is not weakening, but the dry run lists every `*_file` reference the change would refuse.
- **Address and transport changes: confirm or roll back.** Changes to `[[listen]]` (addresses, ports, TLS), `api.listen`, `api.tls` and `api.trusted_proxies` are applied as pending:
  - The node applies the change and starts a confirmation window, 120 s by default (`[api] confirm_window_secs`, 30 to 600, file-only).
  - The change is kept only if the same admin confirms it within the window, with a request that arrives through the new address and transport. For a DNS listener change, the confirmation also needs the node's own probe of the new listener to answer.
  - Otherwise the node restores the previous values, audits `settings.guarded_rolled_back`, and the UI says why.
  - A restart inside the window starts with the previous values. A pending change is held in memory on the target node only. The `node_managed` entry is written and replicated only when the change is confirmed. For a change to another node, the primary forwards the pending change, and the confirmation must reach that node's new address directly. The response to the change carries a single-use `confirmToken`, bound to the admin, node and change and valid for the window, so the admin need not sign in again on the new origin.
  - While a change is pending, the node keeps the previous API and DNS sockets bound alongside the new ones; the old ones close only when the change is confirmed, and stay if it rolls back. If a bind fails, nothing changes. The server refuses (409 `would_disconnect_you`) a change that would leave a node with no API listener or no DNS listener once confirmed, or that removes the API listener the request came in on in the same request that is meant to confirm it.
- **The secrets key.** A key is never entered through the store it protects, or through any API body.
  - The UI shows the key's status: its source (environment, `secrets_key_file`, or `secrets.key` in the data directory), `key_id`, whether a previous key is configured, how many rows are still under it, and whether the store is locked or ephemeral.
  - **Rotation** is by pointing at a new key file the admin has already put on the node. The UI shows the steps (create the file with the format and permissions in `docs/secrets.md`, owned by the service user, mode 0600) and the offline alternative, `telltale secrets rotate-key` with the node stopped. The admin then enters the new file's path. The server checks that the file exists, is a regular file with mode 0600 owned by the service user, and holds a valid key, without ever returning its content. It then writes a guarded entry for that node: `secrets_previous_key_file` = the current key's path, `secrets_key_file` = the new path. Re-encryption runs as at start-up (`ops_014_previous_key_reencrypts_at_start`, crash-safe). When no rows remain under the previous key, the UI offers to clear `secrets_previous_key_file`.
  - A key from the environment is shown as "set by environment" and can't be rotated from the UI.
- **Cluster init, join and bootstrap.** These are explicit steps in a Cluster page wizard, each its own guarded change, never a field in a form:
  - "Make this node a primary" (`cluster.init`);
  - "Join a cluster" (`cluster.join_url` and the bootstrap secret). The secret is entered write-only, over HTTPS or loopback (the API-015 rule), used for that join and never stored. A failed join leaves the node as it was. The dry run says that the node's configuration will be replaced by the primary's;
  - "Leave the cluster";
  - `[cluster.git]` (repository, branch, path, authority). The dry run says when configuration authority moves to Git. The credentials stay T23.12's `SecretField`.
- **Other guarded settings.**
  - `node.*` identity and storage (node ID, data directory): staged for the node's next restart and shown as "pending restart". A node ID change is refused while the node is a cluster member. A data-directory change never moves data unless the admin opts into Copy state (ADR-956 section 1(a): `state.db` and the default `secrets.key` only, never `cluster/`), and the dry run says what does not carry over.
  - The watchdog (`[watchdog]`): guarded; turning it off is weakening.
  - The file paths `trust_anchors_file`, `signatures_file`, `hosts_files` and `[[zone]] file`: admin-only, confined by T23.2's path rules (the denied prefixes, the key files, every credential file the node uses, `secret_file_dirs`). The dry run parses the file and reports counts and line numbers, never its content.
  - `config_version` is the schema version, not a choice. It is shown read-only and is the one setting with no control.

**Alternatives rejected:**
- Read-only display of the security and bootstrap settings, with the CLI step shown (the audit's recommendation): the owner chose admin controls.
- Guarded changes for operators: each of these settings can lock people out, put credentials in clear, or replace a node's configuration.
- Agent scopes for guarded changes: a plan's diff and an agent's transcript would carry the change, and a prompt injection could open the node.
- Applying listener and API changes at once without a window: one typo locks every admin out until someone edits the file on the node.
- Setting the key through the API or the secret store: the store would hold its own key, and the key would cross the network.
- Confirmation in the UI only: a script or forged request would skip it. The phrase is checked by the server.

**Consequences:**
- Every setting but `config_version` has a UI control, and `docs/` and help topics say which tier each one is in.
- An admin can change listeners, TLS and proxies from the UI, and a mistake undoes itself within the window.
- Guarded changes need two requests (the change and the confirmation), and weakening ones need a recent sign-in, so they can't be done from a long-idle session.
- The files keep the last word, so a node can always be recovered by editing its file and restarting.
- On installs whose file (or environment) sets a guarded value, its control shows "set by file" and the command to hand it to the UI (remove the key from the file and restart); the docs say which install bundles set which guarded values. Key rotation from the UI works only when the key path is not set by file or environment.
- Adds the problem codes `would_disconnect_you`, `would_lock_out_admins`, the audit actions `settings.guarded` and `settings.guarded_rolled_back`, and the alert condition `guarded_setting_changed`. `reauth_required` comes from T23.9.
- Amends ADR-040 (UI values for the sections above) and AGT-009 (the kill switch's role rule). T23.12's "`[cluster.git]` itself stays file-only" becomes a guarded wizard step (T27.16).
- Tasks: T24.12 (`special`), T24.13 (`local`, `clients` mdns), T24.18 (Pi-hole import, admin-only), T25.16 (`device_inventory_addresses`), T23.11 (`otlp`), T27.6 (`agents`), T27.13 to T27.17 (the guarded tier).

## ADR-913 — Importing scan results the owner produced: nmap XML and a simple CSV (Accepted 2026-11-16)
**Context:** Only a scanner can find devices that no source sees. The owner runs one themselves, for example `nmap -sn -oX` or `nmap -sS -p … -oX` on a host on that VLAN.

TelltaleDNS has no XML parser, and the uploaded file is untrusted input. The usual risks are XXE, entity expansion and very large files. Two existing stores would also hold whole bodies:
- the plan store keeps up to 500 plans for 24 h with the whole body (`plans.rs:30`);
- the idempotency table writes the full request into `state.db` (`managed.rs:186`).

**Decision:**
- **Formats.** Nothing else is accepted:
  - nmap XML (`-oX`, nmaprun 1.0x);
  - CSV with the header `ip,mac,hostname`. `mac` and `hostname` are optional, each field may have one optional pair of double quotes, and the file is UTF-8.
- **Parser.** A hand-written restricted XML tokenizer in `crates/telltale/src/discovery/import/`, under the ADR-908 lints.
  - **Accepted:** the XML declaration, processing instructions (ignored), comments, and a `<!DOCTYPE …>` without an internal subset.
  - **Refused:**
    - a `[` internal subset, and external IDs;
    - CDATA;
    - a declared encoding other than UTF-8 (an optional BOM is allowed).
  - **Entities.** Only the five predefined entities and numeric character references are allowed. A numeric reference must be an XML `Char`, so `&#0;` and C0 controls other than tab, LF and CR are refused. No entity is ever defined or expanded.
  - **Limits:** depth 16, 200,000 elements, 32 attributes per element.
  - **Attribute values.** The 4 KiB cap applies to the attributes the reader uses. Over-long values on ignored elements, such as `--script` output, are skipped and counted, and they still count toward `max_bytes`.
  - **Truncation.** A file that ends before `</nmaprun>` (an interrupted scan) answers 422.
- **What is read.** Everything else is ignored.
  - `host/status[@state="up"]`;
  - `address` (`ipv4`, and `mac` with `vendor`);
  - `hostnames/hostname`: up to 4, each at most 253 B;
  - `ports/port[@protocol="tcp"]/state[@state="open"]`: up to 16 port numbers;
  - the top `osmatch@name`, cut to 64 B;
  - `nmaprun@start`, the scan time.
- **Where parsing runs.** In a separate, short-lived `telltale discovery-worker --import` process. It never receives credentials and exits after one parse.
  - It gets the same hardening as ADR-908: `/proc/self/exe`, the version handshake, `env_clear()`, `RLIMIT_DATA`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `oom_score_adj` 1000.
  - The body arrives as binary chunk frames of at most 512 KiB, and the parse has 10 s of wall clock.
  - A parse failure answers 422. A worker crash or timeout answers 503. DNS is unaffected.
- **Limits.**
  - The body is at most `max_bytes` (default 8 MiB, maximum 32 MiB) and at most `max_hosts` host rows (default 4,096).
  - The import route sets an explicit `DefaultBodyLimit` equal to `max_bytes`, and reads the body as a counted stream that is forwarded chunk by chunk. It never buffers the body as `Bytes`.
  - One import in progress per node.
  - At most 10 imports per hour (429 with `Retry-After`).
  - The last `keep` imports are kept (default 16).
- **What is merged.**
  - Rows whose address is in a configured `[[discovery.subnet]]` become source `import`, tagged with the import ID. A row with a MAC goes into class 4. A row without one goes into the IP-only class.
  - Rows outside every subnet, or at a refused address (ADR-907), are counted as dropped.
  - Imports never override class 1–3 bindings, never feed DNS or policy, and never make an address an SNMP destination (ADR-907, ADR-910).
  - Device strings are sanitised as in ADR-908.
- **Provenance.**
  - Each import records:
    - its ID and time;
    - the user or agent, and the reason;
    - the format and the scan's own start time;
    - counts: merged, IP-only, dropped, skipped over-long values.
  - `DELETE` removes an import's rows.
- **API and surfaces.**
  - `POST /api/v1/discovery/imports`:
    - `Content-Type: application/xml` or `text/csv`;
    - `?dryRun=true` parses and returns the summary and the first 20 rows, and keeps nothing;
    - `Idempotency-Key` and `X-Telltale-Reason`.
  - For imports, the idempotency replay record stores a SHA-256 of the body and the response, never the body.
  - On a non-designated node, an upload of at most 768 KiB is forwarded to the designated node. A larger one answers 413 `import_too_large_to_forward`, naming the node to upload to.
  - Humans need the operator role. Agents need `ops:discovery` and a reason. When `[agents] require_approval` is on, agent imports go through the plan.
  - Audited as `discovery.import` and `discovery.import_deleted`.
  - Also available in the UI, `ctl` and MCP (`plan_import_scan` → `apply_plan`).
- **Plans.**
  - `plan_import_scan` (content at most 768 KiB) parses in the import worker when the plan is made.
  - The plan stores only the parsed summary and at most 20 preview rows. The parsed rows sit in a separate bounded staging area: at most 2 open import plans per node, at most 4,096 rows each, dropped on apply, discard or expiry.
  - The raw content is never stored and never appears in `list_plans`.
- **Storage.** Parsed rows only, never the raw file. They live in the inventory file on the designated node, as the import-ID bitmask on each entry plus per-import counts. At most 8,192 import-derived rows in total; the oldest import is dropped first.

**Alternatives rejected:**
- `quick-xml` or `roxmltree`: a new dependency for a small, fixed subset of XML.
- Parsing in the SNMP worker: credentials and untrusted XML would share one process.
- Keeping raw bodies in plans or idempotency records: up to about 375 MiB in memory, above `MemoryMax=256M`, and agents could read the raw scan.
- Running nmap or scheduling scans: out of scope (ADR-907).
- Keeping raw uploads: size, and data that was never needed.
- Replicating imports to all full members: left as an owner question.

**Consequences:**
- The owner's scans show up within seconds and can be removed again.
- Results from a routed scanner have no MAC until another source binds the address.
- Imported addresses get no SNMP identity reads until a class 1–3 source sees them.
- Imports are lost when the designated node changes.

## ADR-912 — Extra read-only UniFi reads for the inventory (Accepted 2026-11-16)
**Context:** ADR-080 and ADR-902 read `stat/sta`, `rest/user` (reservations only) and `rest/networkconf`. UniFi also knows:
- offline and historical clients (`stat/alluser`);
- switch-port MAC tables with VLAN, and LLDP (`stat/device`);
- per-client `is_wired`, `sw_mac`, `sw_port`, `ap_mac`, `vlan`, `first_seen` and `last_seen`.

UniFi has no ARP endpoint. ADR-902 rejected known clients without a reservation as DNS names, because a stale address names the wrong device. `routers.rs` runs as `tokio::spawn` on the main multi-thread runtime (`server.rs:1100`), the same runtime that serves TCP, DoH and cache misses.

**Decision:**
- With `[discovery] unifi_reads` set, the designated discovery node makes these extra reads for each UniFi `[[router]]`, with the same key or session:
  - `client_fields`: more fields from the existing `stat/sta`/`rest/user` answers, at no extra request cost;
  - `all_users`: `POST stat/alluser` with `within = unifi_all_users_within_hours` (default 720, maximum 8,760);
  - `devices`: `GET stat/device`, for infrastructure identity, the port `mac_table` (VLAN, `static`, `age`), `lldp_table` and `uplink`.
- **Where they run.** The `all_users` and `devices` reads, and the parsing of the extra `client_fields`, run on the `telltale-inventory` thread's runtime. They reuse the router's session and credentials. `routers.rs` only shares the session and a copy of the raw answers it already holds. None of this work runs on the main runtime.
- Each read is optional. A refused or failed read is logged once per change.
- Caps: 4 MiB and 8,192 rows per read.
- Results go only into the inventory (ADR-910):
  - as class 1 (current clients), class 5 (history) and port locations;
  - never into `router_leases`, `peer_names` or `device_dns`;
  - counted against the 4,096-entry cap.

  Ports whose `mac_table` holds more than 8 MACs, or that are UniFi uplinks, give no location.
- **Home Assistant.** With `home_assistant_all_devices = true` (default true when discovery is on), a second fixed, read-only template runs on the inventory thread. It lists registry devices that have a `mac` connection and no entity (`name_by_user`, `name`, area). The answer is capped at 1 MiB. These names go into the inventory only. ADR-902's DNS-name template is unchanged.
- Amends the "Not done" of ADR-080 and ADR-902.

**Alternatives rejected:**
- Running the extra reads inside `routers.rs` on the main runtime: up to 4 MiB of JSON parsed next to DNS work.
- The Integration API: a second code path with fewer fields.
- The fingerprint map (`/v2/api/fingerprint_devices`): numeric IDs and an unofficial endpoint. Left Open.
- `stat/alluser` as DNS names: ADR-902's stale-address reasoning.

**Consequences:**
- One or two more requests per UniFi poll, on one node.
- On UniFi switches, wired static devices show their switch port without SNMP.
- The field names come from reverse-engineered docs and are checked against the owner's console in e2e.

## ADR-911 — Dependency `aes` 0.8 for SNMPv3 privacy (Accepted 2026-11-16)
**Context:** The owner asked for authPriv. RFC 3826 needs AES-128 in CFB-128 mode. `ring` exposes AES only inside AEADs and QUIC header protection. `cipher` 0.4.4, `inout`, `crypto-common` and `cpufeatures` 0.2.17 are already in `Cargo.lock`, pulled in through `crypto_box` and `chacha20`.

**Decision:**
- Add RustCrypto `aes` 0.8 (MIT/Apache-2.0) to `telltale-snmp` only.
- Write CFB-128 by hand, about 20 lines, instead of adding `cfb-mode`. The IV is engineBoots ‖ engineTime ‖ salt.
- PR justification line: "aes 0.8: SNMPv3 AES-128-CFB privacy (RFC 3826); ring exposes no raw AES block; cipher/cpufeatures already in tree; +12.4 KiB measured (x86_64 probe crate)."
- Gates:
  - `cargo deny check` passes, and `cargo tree -d` shows no duplicate versions;
  - the size delta is measured with `deploy/image/size.py --oci` on amd64, arm64 and arm/v7 (armv7 builds the software fixslice path, arm64 the ARMv8 path);
  - the RFC 3826 test vectors pass on all three.
- `aes` uses `unsafe` CPU intrinsics internally. As with `ring`, third-party crates fall outside AGENTS rule 7, which applies to workspace code.

**Alternatives rejected:**
- Hand-written AES: table lookups leak through cache timing, and hand-rolled crypto needs its own review.
- authNoPriv only: the owner asked for privacy. It stays the fallback if the size gate fails.
- `cfb-mode`: one more crate for 20 lines.

**Consequences:**
- About 12–20 KiB per architecture, to be measured.
- A Pi 4 has no AES instructions, so it uses constant-time software AES. At SNMP rates the cost is negligible.

## ADR-910 — Inventory merge model: keyed by MAC, address bindings with a time limit, never DNS policy (Accepted 2026-11-16)
**Context:** Sources disagree, and each has its own trust:
- UniFi current clients and reservations;
- OPNsense leases;
- Home Assistant names by MAC;
- the local neighbour table;
- SNMP ARP and bridge tables;
- SNMP identity;
- imported scans, which are claims from a file;
- passive mDNS.

Constraints:
- `devices::Names` is IPv4-keyed, and every peer pulls it every 60 s. A full inventory there would exceed `MAX_RPC` and silently break router-name sharing.
- `telltale_policy::Neighbors` decides MAC-based client matching.
- ADR-117 bounds `identify.rs` to 1,024 devices for 1 day.
- ADR-102 sets what is kept and shown at each privacy level. At level 2, nothing that identifies a client is kept.

**Decision:**
- **Model.**
  - The MAC is the key. An entry has:
    - `mac`;
    - up to 4 addresses, each with its source and `lastSeen`;
    - display names, each with source and rank;
    - the OUI vendor;
    - VLAN and network;
    - switch port and AP (from UniFi or the SNMP bridge table);
    - LLDP neighbours (up to 4);
    - an identity record: sysName, sysDescr, a vendor index into the PEN preset, and the printer name;
    - up to 16 open TCP ports, from imports;
    - a source bitmask;
    - an import-ID bitmask (16 bits, one per kept import);
    - `firstSeen` and `lastSeen`;
    - findings and mutes.
  - A result with no MAC goes into a separate IP-only class, keyed `ip:<addr>`. Examples: an import from a routed scanner, or an identity answer before any MAC is known.
    - Capped at 1,024 entries, oldest dropped first.
    - A MAC is never invented.
    - When a MAC source binds the address, the entry merges into the MAC entry.
  - Caps:
    - 4,096 MAC entries;
    - at most 8,192 import-derived rows in total, with the oldest import dropped first;
    - per-entry caps as in ADR-908.

    About 600 B per entry at worst.
- **Which address is current.** Precedence for a MAC's current address:
  1. UniFi `stat/sta`, OPNsense leases and UniFi reservations (ADR-902 rules).
  2. The local neighbour table, in states REACHABLE, STALE, DELAY or PROBE. A row is accepted only if the address lies in a configured subnet and `Neighbor.ifindex` is not a container or overlay interface: `lo`, `docker*`, `br-*`, `veth*`, `cni*`, `flannel*`, `cali*`, `vxlan*`, `tun*`, `tap*`, `wg*`, `tailscale*`, `zt*`.
  3. SNMP ARP from listed infrastructure agents.
  4. Imports.
  5. UniFi `stat/alluser` `last_ip`. This is history only, never current.

  Rules:
  - The most recent binding from the best class is primary. The others are kept as aliases and shown.
  - **Same address, different MAC:** the newest observation from classes 1–3 wins. An import or history never replaces a class 1–3 binding. The case is flagged `ip_conflict`.
  - A MAC with the locally administered bit set is flagged `randomized`. No stable-identity finding is raised for it.
  - Only class 1–3 bindings make an address an SNMP destination (ADR-907).
- **Display names** (inventory only), in rank order:
  1. the configured client name;
  2. Home Assistant `name_by_user`;
  3. the router alias or host name, in `[[router]]` order;
  4. a Home Assistant integration's name;
  5. passive mDNS;
  6. SNMP sysName or printer name;
  7. an import's host name.

  Ranks 6 and 7 are labelled with their source.
- **Containment.**
  - Inventory data never enters any of these: `router_leases`, `peer_names.routers`, `mdns_names`, `telltale_policy::Neighbors`, client matching, or `identify.rs`'s seen chain. This covers SNMP, imports, `stat/alluser`, `stat/device`, entityless Home Assistant devices and the neighbour-table source.
  - Device DNS names (ADR-901) are never created from it. The one exception is the opt-in below, which supplies an *address* and never a *name*.
  - Feeding policy would need its own ADR, because ARP spoofing lands in the gateway's table.
  - Passive mDNS naming under ADR-901 is unchanged.
- **Device addresses in DNS (opt-in).** With `[local] device_inventory_addresses = true` (default false), a MAC can get an address from the inventory. This applies when the MAC already has a name in DNS-023's sources but no address there. The address comes from class 2 or class 3 only, and only if it was:
  - seen in the last poll;
  - not flagged `ip_conflict`;
  - not flagged `randomized`.

  These bindings, `{mac, ip, name}` with at most 1,024 rows, reach other nodes in a new `Names.inventory` field. The field is `#[serde(default)]`, so it is N−1 safe, and it amends ADR-125. The bindings rank below every existing source in the `device_dns` order, which amends ADR-901's source order.
- **Findings.** Findings live on the entry, not in `AnomalyKind`, so ADR-161 is unchanged.
  - `default_community` (ADR-909).
  - `ip_conflict`.
  - `new_device`: the first time any source sees a MAC, after a 24 h learning period from first enable. It is raised through the existing new-device alert with `source = "inventory"`, so ADR-102 applies (off at privacy level 1 and above).

  When the inventory starts empty (a failover, or the file is missing), no `new_device` alerts are raised for 24 h. A mute applies to one entry and one kind, with an optional expiry, and is kept in the inventory file. Nothing blocks or moves a device.
- **Retention.**
  - Entries seen only by SNMP, the neighbour table or history age out `retention_days` after `lastSeen` (default 7).
  - Import rows age out `[discovery.import] retention_days` after their import (default 30).
  - An entry that another source still sees is never removed.
  - A host counts as absent only after two polls in a row miss it.
- **Storage.**
  - Held in `ArcSwap` on the designated node.
  - Persisted to `<data_dir>/inventory.json`: mode 0600, atomic rename. Written at most every 15 min and on shutdown. After a `public` pass or an import, at most once a minute.
  - Left out of backups.
  - Left out of support packages unless asked for with `--include-inventory`, which goes through ADR-156's pseudonymisation.
  - Not replicated as configuration.
- **Cluster read.** `Read::Discovery`, federated, with AGT-011 `missingNodes`:
  - A non-designated node asks the designated node for a filtered page of at most 500 rows.
  - Each answer is capped at 256 KiB (`MAX_RPC/4`). The server enforces the cap by trimming the page.
  - An N−1 node answers "unknown call" and is listed in `missingNodes`.
- **Privacy (ADR-102).**
  - At level 1, sysName and host names are hashed like client names.
  - At level 2 and above, `[discovery] enabled = true` is a validation error, because nothing that identifies a client may be kept. The other route, a Proposed amendment of ADR-102, is an owner question.

**Alternatives rejected:**
- Extending `Names` with the full inventory: it exceeds the RPC frame and spreads open ports to resolver pods.
- An IP-keyed inventory: it loses devices that move addresses.
- Feeding `Neighbors`: ARP spoofing would move devices between groups.
- New `AnomalyKind` variants: they clash with ADR-161's mute model, OBS-014 IDs and N−1 deserialisation.
- Feeding identify's seen chain: it breaks ADR-117's bounds.
- Storing every import row separately: up to 65,536 rows outside the caps.

**Consequences:**
- Clients → Discovered and the Networks counts see devices the routers don't list.
- After a failover to a new designated node, the inventory starts empty until the next polls, and imports must be uploaded again (ADR-913).
- With DSC-012 on, a spoofed MAC could claim a named device's address. ADR-902 already accepts the same exposure for leases.
- SNMP identity does not improve identify's class guesses in M25. Left Open.
- Closes T22.3's *Open* item "the neighbor table as a MAC → address source".

## ADR-909 — The `public` community for identity reads, by explicit per-subnet opt-in (Accepted 2026-11-16)
**Context:** Many printers and cheap devices answer v2c `public`. The owner approved trying it on 2026-11-16, with four conditions: an explicit per-subnet opt-in, off by default, audited, and with the IDS risk written down.

An IDS reads this traffic as credential guessing. Snort 1:1411 "SNMP public access udp" and the ET SNMP rules fire on it. UniFi IPS with "Block Source IP" could block the DNS host itself, and the whole LAN would lose DNS.

**Decision:**
- **The switch.**
  - `[[discovery.subnet]] snmp_try_public` defaults to `false`.
  - Setting it to `true` is a validation error unless both of these hold:
    - the same subnet sets `public_ids_acknowledged = true`, which confirms the DNS host is on the gateway's IPS allow list (UniFi: Security → Detection allow list);
    - the gateway is covered by a listed `snmp_agent`, or by a UniFi `[[router]]` that the designated node polls. The circuit breaker needs one of them.
  - Both fields are set through the admin-only `discovery` kind and audited. A setting made in a file shows as set by file and is covered by the startup audit (ADR-907).
- **Which hosts.**
  - Only addresses inside that subnet that have a current class 1–3 binding (ADR-907).
  - Only when the subnet has no `host_credential`, or that credential has just failed for this host.
  - Never infrastructure agents, which need a configured credential.
- **What is sent.** One v2c GET of sysName, sysDescr, sysObjectID and sysLocation, with community `public`. The code has no other built-in community string. No walks, no SET.
- **Limits.**
  - At most 1 host per second, and at most 1 retry.
  - One attempt per host per 7 days, and failed attempts count. The key is the MAC when known, otherwise the IP, so an address change doesn't reset it.
  - The limit survives restarts in the inventory file. That file is written at most once a minute after a pass.
- **Empty start.** When the inventory starts empty (a failover, or the file is missing), no `public` pass runs for 7 days.
- **Circuit breaker.** All `public` attempts stop for 24 h, and the stop is audited, if during a pass either of these happens:
  - three `sysUpTime` GETs in a row to the listed gateway agent go unanswered (they are sent every 10 s during the pass), or the UniFi poll fails;
  - the health reason `upstream_down` or `upstream_group_down` appears.

  The breaker never uses ICMP or TCP.
- **Audit and visibility.**
  - Each pass writes one audit summary: subnet, hosts tried, hosts that answered.
  - While any subnet has the switch on:
    - `config check` warns;
    - the UI shows a banner;
    - `GET /discovery` says so.
  - Answers are tagged `identitySource = "snmp-default-community"`.
  - A host that answers gets the `default_community` finding (ADR-910).

**Alternatives rejected:**
- A list of common communities: that is guessing.
- On by default: IDS self-blocking.
- Trying it on infrastructure agents: the owner configures those.
- A warning instead of the acknowledgement error: the failure takes DNS down for the LAN.
- A breaker based on reachability probes: that would be active probing (ADR-907).

**Consequences:**
- Printers and similar devices on an opted-in subnet are identified without per-device setup.
- The gateway's IDS logs may still show the attempts. The docs carry:
  - the risk text;
  - how to allow-list the host;
  - a note that a device answering `public` is itself a security finding.

## ADR-908 — SNMP poller: v2c and v3 USM, read-only, in a worker process (Accepted 2026-11-16)
**Context:** On the owner's network, the most valuable SNMP data is the gateway's ARP table: `ipNetToPhysicalTable` (1.3.6.1.2.1.4.35), falling back to `ipNetToMediaTable` (1.3.6.1.2.1.4.22). It gives a MAC for every address on every VLAN. Next in value:
- managed switches' forwarding tables per VLAN, mapped to ports;
- LLDP neighbours;
- the identity of printers and network gear.

The repo has no SNMP code. Constraints:
- The release build aborts on panic.
- `ring` covers HMAC-SHA-1/SHA-2 and the digests, but has no raw AES block.
- Many UniFi devices run Net-SNMP, and UniFi uses one v3 password for both auth and priv.
- Whether the UniFi gateway serves its ARP table over SNMP was unconfirmed when this was written. A test on 2026-11-16 confirmed it does, over v3 with SHA and AES (ADR-907, owner decisions).
- On systemd, the unit's default `OOMPolicy=stop` stops the whole unit when the kernel OOM-kills any process in it.
- On Kubernetes with cgroup v2, kubelet 1.28 and later sets `memory.oom.group=1`, so an OOM kills every process in the container.

**Decision:**
- **Crate.** A new crate, `telltale-snmp`.
  - Lints: `#![forbid(unsafe_code)]` and `#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::panic, clippy::unreachable)]`.
  - A hand-written minimal BER codec. Definite lengths only, a depth cap of 8, a message cap of 64 KiB and a cap of 256 varbinds per PDU.
  - Types: INTEGER, OCTET STRING, OID, NULL, IpAddress, Counter32, Gauge32, TimeTicks and Counter64, plus the noSuchObject, noSuchInstance and endOfMibView exceptions.
  - It is off the hot path and not on the AGENTS.md bench-smoke list.
- **PDUs.** It sends GET, GETNEXT and GETBULK, and receives Response and Report. The encoder has no SetRequest type, and no other write PDU type or tag constant. A CI grep test checks this.
- **v3 USM** (RFC 3414, RFC 7860, RFC 3826).
  - Engine discovery uses Report messages. Replies must match `msgID` and `requestID`. At most one unauthenticated time resync per agent per minute. *Superseded in part by the 2026-11-17 amendment below and ADR-931 (Proposed): only an authenticated Report moves the clock.*
  - *Amended 2026-11-17 (m25-snmp review):* unauthenticated Reports are never used for the clock. Discovery accepts only a noAuthNoPriv Report whose varbind is `usmStatsUnknownEngineIDs`. An authenticated notInTimeWindow Report takes the agent's clock, at most once per agent per minute, and the request is sent once more. Message and request IDs start at a random value on separate counters, so a spoofed datagram cannot guess them. A v3 reply must match the request's security level, engine ID and user. The cached engine is dropped after a failed exchange, so a forged engine ID cannot stay in place. The MAC is compared in constant time, and the community is compared the same way. *Credential files (2026-11-17, m25-snmp review):* the file is opened no-follow and non-blocking, and its identity is checked against the canonical path (ADR-932, Proposed). An authPriv request accepts an authNoPriv time-window Report with request ID 0 or the request's ID, when its MAC verifies (ADR-931, Proposed).
  - *Key handling (amended 2026-11-17):* Ku and Kul are held in `Zeroizing`, and the privacy key is zeroized, with `aes` built with its `zeroize` feature. `ring`'s digest and HMAC contexts keep password-derived state that cannot be zeroized; this is accepted, because they are dropped at the end of the round and never cached. The privacy salt is eight random octets per message (64 bits from `SystemRandom`), not RFC 3826's seeded counter: no counter state is kept across restarts, and the repeat chance under one key is negligible.
  - Ku is the 1 MiB password-to-key expansion. It is computed once per credential per poll round with `ring::digest`, held in a `Zeroizing` buffer, and dropped at the end of the round.
  - Kul, the key localised per engine, is one short hash. It is computed on demand and never cached.
  - Authentication: HMAC-SHA-96, and HMAC-SHA-256/384/512 truncated per RFC 7860 (`ring::hmac`).
  - Privacy: AES-128-CFB (ADR-911).
  - Security levels: authNoPriv and authPriv. `priv_password_*` defaults to the auth password.
  - Refused at config time, with a reason: MD5, SHA-224, DES, AES-192/256, and v3 noAuthNoPriv.
- **Worker process.** The designated node runs the poller in `telltale discovery-worker`.
  - **Binary.** The worker is started from `/proc/self/exe`, the inode that is actually running, not `current_exe()`. The image doesn't grow, and an upgraded file on disk is never started by mistake.
  - **Version handshake.** The first frame is a handshake: build ID plus protocol version. On a mismatch the worker is refused and the health reason `discovery_worker_version_mismatch` is raised.
  - **Environment.** Cleared with `env_clear()`. No arguments carry secrets. Jobs and credentials arrive on stdin only.
  - **Frames.** Each frame is a u32 big-endian length, a type byte, then the payload:
    - JSON control and result frames, at most 1 MiB, with large results split across frames;
    - binary chunk frames, at most 512 KiB.

    The main side reads frames on the `telltale-inventory` thread with a bounded, panic-free reader.
  - **Stderr.** Captured and logged with a rate limit, never inherited.
  - **Memory limit.** At start the worker sets `RLIMIT_DATA` to `worker_memory_mib` (default 64, range 32–128). An allocation failure then aborts only the worker, well below the cgroup limit. `RLIMIT_AS` is not used, because reserved virtual mappings would trip it.
  - **Other hardening at start.**
    - `oom_score_adj` is set to 1000.
    - `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` are set, so an abort never writes a core dump that holds Ku or passwords.
    - All of these go through one safe wrapper in `telltale-net`, with a `// SAFETY:` comment (AGENTS rule 7).
  - **Runtime.** It calls `background_thread()` and runs one current-thread runtime.
  - **Sockets.** It holds no listening sockets, only connected UDP client sockets. It exits on stdin EOF.
  - **Supervisor.** Restarts the worker with backoff: 1 s, doubling up to 5 min. Three crashes within 10 minutes raise `discovery_worker_failing` (degraded, never DNS). While the worker is down, results go stale and DNS is unaffected.
  - **systemd.** `deploy/systemd/telltale.service` sets `OOMPolicy=continue`, so a kernel OOM kill of the worker never stops the unit.
- **Infrastructure polling** (`[[discovery.snmp_agent]]`).
  - **Interval.** Each agent is polled every `interval_secs` (default 300, minimum 60).
  - **Pacing.**
    - One request in flight per agent.
    - At least 50 ms between requests and at most 20 requests/s per agent.
    - Timeout 1.5 s, with 2 retries.
    - A walk stops after 3 timeouts in a row or 30 s of wall clock.
  - **Sizes.** GETBULK `max_repetitions` is 5–25 (default 10). Each table is capped at 5,000 rows. One 64 KiB receive buffer per agent is reused.
  - **Replies.** A reply counts only if it comes from the address the request went to.
  - **Tables.**
    - `arp`: ipNetToPhysicalTable, else ipNetToMediaTable.
    - `ifmib`: ifTable and ifXTable names, plus `ipAddressTable`/`ipAddrTable` for the agent's own addresses.
    - `bridge`: `dot1qTpFdbTable`, else `dot1dTpFdbTable`, with ports mapped through `dot1dBasePortIfIndex`.
      - `dot1qTpFdbTable` is indexed by `dot1qFdbId`, which is not the VLAN ID. It is mapped to the VLAN ID through `dot1qVlanCurrentTable`'s `dot1qVlanFdbId`.
      - A port counts as an uplink or trunk, and its MACs give no location, if it has more than 8 learned MACs, or an LLDP neighbour that is itself a listed agent or a UniFi device.
      - Per-VLAN contexts (`community@vlan`, v3 `contextName`) are left Open.
    - `lldp`: the LLDP-MIB remote table (1.0.8802.1.1.2), at most 4 neighbours per port.
- **Capability record.**
  - On the first poll and on `snmp/test`, each listed table root gets one GETNEXT.
  - The record is kept and shown: tables answered, security level reached, engine ID, sysObjectID.
  - Capabilities are never assumed. A table that doesn't answer is skipped until the next test, and the skip is logged once.
- **Host identity reads.**
  - **Who.** An address inside a `[[discovery.subnet]]` that names a `host_credential`, and that has a current class 1–3 binding (ADR-907).
  - **What.** One GET of sysName, sysDescr, sysObjectID and sysLocation. If sysObjectID or the device class says printer, also a GET of `prtGeneralPrinterName`. No walks.
  - **How often.** At most once per host per `identity_interval_hours` (default 24, minimum 6). At most 5 hosts/s in total and 1,024 hosts per pass.
  - **Replies.** An answer from any address other than the one asked is dropped.
- **Credential roles.**
  - `[[discovery.snmp_credential]]` has `role = "infrastructure" | "host"`.
  - It is a validation error for a subnet to name an infrastructure credential, or for an agent to name a host credential. A device on the LAN therefore never receives the gateway's credential.
  - A v2c host credential warns: every host in the subnet learns the community in cleartext.
- **Untrusted strings.** Every string from a device:
  - is cut: sysName and sysLocation to 64 B, sysDescr and the printer name to 255 B;
  - has control characters removed (the `SafeString::new` rule);
  - is rendered as text only.

  MCP tool descriptions mark these fields as device-supplied data, not instructions.
- **Credentials (ADR-903).**
  - `community`, `auth_password` and `priv_password` each take either `*_file` or `*_ref`. Inline values are a validation error. Files win, as in ADR-903.
  - Refs are named `discovery.<credential-name>.<field>`, for example `discovery.infra-v3.auth_password`.
  - A missing ref on an API write answers 422 `secret_missing`. At load time a missing ref warns, and the agent or subnet is skipped.
  - They are write-only, added to `credentials::PATHS` and `API_PATHS`, held as `SecretValue` (redacting `Debug`, zeroized), never as `SafeString`, and sent to the worker only over stdin.
- **Diagnostic CLI.** `telltale snmp walk --agent <name> [--table arp|ifmib|bridge|lldp]`. It takes a configured agent name only, never an address, and prints rows with secrets redacted.

**Alternatives rejected:**
- An SNMP crate such as `snmp2` or `csnmp`: new dependencies with incomplete USM, and their panic behaviour isn't ours to control.
- The codec in `telltale-proto`: that is a hot-path crate.
- Polling in the main process, relying only on lints and fuzzing: one missed panic aborts DNS.
- Relying on `oom_score_adj` alone: systemd's `OOMPolicy=stop` and Kubernetes' `memory.oom.group` kill DNS with the worker.
- `current_exe()`: after an upgrade it can start a newer binary than the one running.
- Caching Kul per engine: the cache grows with every v3 host.
- MD5 and DES: weak, and `ring` has no MD5.
- An address-based `snmp/test`: it would be a destination chosen at request time.

**Consequences:**
- About 3–6 MiB more RSS while discovery is on. The worker is capped by `worker_memory_mib`.
- Sending v3 to a host exposes the password to offline guessing by that host: it chooses the engine ID and receives an HMAC over a known message. This is why credentials have roles. The docs say to give hosts a low-value, shared identity.
- v2c host credentials are cleartext on the subnet.
- When a switch shows a MAC on several ports at once (a loop, or a move in progress), the most recently seen port is recorded.
- On Kubernetes outside the host network, the SNMP source address is the node IP after SNAT. Device access lists must allow that address.

## ADR-907 — Network inventory scope: SNMP, gateway reads and imported scans; no built-in probing (Accepted 2026-11-16)
**Context:** On 2026-11-16 the owner asked what TelltaleDNS can learn about devices that never use DNS or DHCP. Some sources already exist:
- the routers' leases and networks (ADR-080, ADR-902);
- Home Assistant names by MAC (ADR-902);
- passive mDNS (ADR-081);
- the kernel neighbour table. Today it is used only for MAC client matching (`telltale_net::neighbors()`).

These are missing:
- the gateway's ARP table across VLANs;
- which switch port each MAC is on;
- the identity of printers and network gear;
- devices with static addresses that UniFi doesn't list.

Active probing is out of scope by owner decision (2026-11-16). That covers ICMP sweeps, TCP connect probes and ARP/mDNS solicitation. The owner's own scanner supplies that data, and TelltaleDNS imports its output.

This ADR keeps the read-only router posture of ADR-080 and ADR-902. ADR-091 (no DHCP server) is a separate decision and is not affected. ADR-081 is not affected either: mDNS stays passive. M22 ("Network inventory and home integrations") was the first inventory milestone, and M25 builds on it.

**Decision:**
- **What M25 adds.** Four inputs, all read-only:
  1. An SNMP poller (ADR-908) of infrastructure listed in the configuration. It reads:
     - gateway and router ARP tables;
     - IF-MIB;
     - the switches' BRIDGE/Q-BRIDGE forwarding tables per VLAN;
     - LLDP neighbours.

     It also reads the identity of hosts already in the inventory (sysName, sysDescr, sysObjectID, Printer MIB), using per-subnet credentials. The `public` community is never tried unless the owner opts in for that subnet (ADR-909).
  2. More read-only UniFi and Home Assistant API reads (ADR-912).
  3. Uploaded results of a scan the owner runs: nmap XML, or a simple `ip,mac,hostname` CSV (ADR-913).
  4. A merged inventory keyed by MAC across all sources (ADR-910).
- **What TelltaleDNS never does.** It never generates discovery traffic of its own:
  - no ICMP;
  - no TCP connect probes;
  - no ARP, NDP or mDNS solicitation;
  - no SSDP, NBNS or WS-Discovery;
  - no scheduling or launching of scans.

  The code has no target planner and no range iterator.
- **Where SNMP goes.** SNMP requests go to only two kinds of address:
  - each `[[discovery.snmp_agent]].address`;
  - addresses that have a current binding from class 1–3 and lie inside a configured `[[discovery.subnet]]` CIDR. Class 1–3 means router leases or UniFi current clients, the filtered local neighbour table, or SNMP ARP from a listed agent (ADR-910).

  Entries known only from imports, from the IP-only class or from UniFi `stat/alluser` history are never SNMP destinations. An address range is never walked. A subnet CIDR is a filter on inventory addresses, never a list of targets.
- **Destinations.** Every SNMP destination is an IPv4 literal inside RFC 1918. Host names are refused, so there is no resolution and no rebinding. Always refused:
  - loopback, `0.0.0.0/8` and `169.254.0.0/16`;
  - multicast, limited broadcast and subnet broadcast;
  - `100.64.0.0/10` (RFC 6598, which Tailscale uses);
  - every IPv6 address (M25 is IPv4 only, like the leases);
  - the host's own addresses;
  - anything outside RFC 1918.
- **Placement.** `[discovery]` is a shared section with one designated node:
  - `node = "<node-id>"`. If unset, the current primary, or the standalone node.
  - Never ephemeral resolver pods or witnesses.
  - Every other node reads the inventory through a federated `Read::Discovery` (ADR-910).
- **Isolation (CLU-004).**
  - Two worker processes re-executed from the running binary (ADR-908, ADR-913):
    - `telltale discovery-worker` handles SNMP I/O and the BER/USM codec;
    - `telltale discovery-worker --import` is a short-lived, credential-free process for import parsing.
  - A worker panic, hang, allocation failure or OOM cannot abort the DNS process, which builds with `panic = "abort"`.
  - The merge runs in the main process on one dedicated OS thread named `telltale-inventory`. It calls `telltale_net::background_thread()` and runs its own `new_current_thread()` runtime, like `kubernetes.rs`. The extra UniFi and Home Assistant reads also run there (ADR-912).
  - Nothing in discovery is `tokio::spawn`ed on the main runtime.
  - Results leave the thread only through `ArcSwap` stores.
  - The thread and the workers are not created while `enabled = false`, or on a node that isn't the designated one. Reload starts or stops them.
- **What remains in the main process.** The merge thread and the worker frame decoder still run in the main process, so a panic there aborts DNS. The only mitigations are:
  - the ADR-908 module lints (`indexing_slicing`, `arithmetic_side_effects`, `panic`, `unreachable`);
  - the `inventory_merge` and `worker_frames` fuzz targets.
- **Writes and audit.**
  - The section is edited through the config entries API as a managed kind, `discovery`: admin only, with dry run, `If-Match`, audit and secrets redacted.
  - No agent scope writes the `discovery` kind. Agents get 403.
  - A setting made in a file shows as "set by file" and can't be edited through the API.
  - At startup and on reload, a change to the effective `[discovery]` hash is audited as `discovery.config_changed (source=file)`.
  - These are audited too: scan imports, deleting an import, SNMP tests, finding mutes, and the `public` passes and circuit-breaker trips.
  - Humans need the operator role for imports, deleting imports and mutes. Agents need `ops:discovery`, which is an Operator-role scope.
  - `snmp/test` is admin only for humans. Agents need `ops:discovery_test`, an Admin-role scope.
  - Discovery never writes router or gateway configuration, never sends an SNMP SET, and never blocks or moves a device. Quarantine stays an explicit action (`06` §7).
- **N−1 (CLU-010).**
  - `[discovery]` and `[local] device_inventory_addresses` are serialized only when set, like ADR-903's `_ref` fields.
  - An N−1 replica refuses a version that holds them.
  - The API refuses the first write of `[discovery]` with 409 `members_too_old` while any full member runs N−1.
  - `config check` warns when the file sets the section in a mixed-version cluster.

**Alternatives rejected:**
- Built-in ICMP/TCP/ARP/mDNS probing: out of scope by owner decision. It also brings IDS self-blocking of the DNS host, neighbour-table overflow and conntrack pressure.
- `[discovery]` as node-local configuration: there would be no audited write path. ADR-161 rejected the same thing for mutes.
- SNMP on every node: each node has a different view of the network, and the traffic and IDS exposure would double.
- Host names as SNMP addresses: anyone who can change DNS records could redirect a credential.
- Identity reads to any inventory address: one CSV import could turn the reads into a sweep of a whole /16.

**Consequences:**
- TelltaleDNS now sends SNMP read requests on the LAN. They go to listed devices, and, with an identity credential, to hosts that a router, the neighbour table or a gateway ARP table currently sees.
- Devices that no source sees stay unknown until the owner imports a scan. Imported devices get no identity reads until a class 1–3 source binds their address.
- Amends ADR-080 and ADR-902: "read-only toward the gateway" now also covers SNMP reads. Nothing writes.
- Proposed amendment of ADR-906: the upstream-sync collision check also covers requirement prefixes (DSC) and milestone numbers (M25).
- ADR-081, ADR-091, ADR-117 and ADR-161 are unchanged.

**Owner decisions (2026-11-16):** the owner accepted the recommendations for questions 1–12 and 14–16 of the M25 design, and answered question 13 by a test. These ADRs (ADR-907 to ADR-913) stay Proposed until the owner accepts the ADRs themselves.
- **Accepted recommendations:**
  - **1a:** SNMP credentials as `*_file` first, once T23.1–T23.3 are in; `*_ref` in T25.8.
  - **2a:** The `aes` 0.8 crate with hand-written CFB-128 for v3 privacy (ADR-911).
  - **3a:** A hand-written restricted nmap XML parser (ADR-913).
  - **4a:** Imports kept on the scanning (designated) node; replication is a follow-up.
  - **5c:** Retention configurable, defaults 7 days (SNMP, neighbour and history-only entries) and 30 days (imports).
  - **6a:** Inventory addresses in DNS opt-in, off by default (DSC-012).
  - **7a:** `public` is a validation error without `public_ids_acknowledged` and a gateway agent or UniFi router (ADR-909).
  - **8a:** The primary is the designated node when `node` is unset.
  - **9a:** 30 days of `stat/alluser` history.
  - **10a:** Home Assistant devices without entities go in the inventory only.
  - **11a:** Open ports and OS guesses from imports kept, capped at 16 ports, behind `discovery:read`.
  - **12a:** No MD5 or DES.
  - **14a:** Imported addresses never get identity reads; only class 1–3 bindings are SNMP destinations.
  - **15a:** No discovery at privacy level 2 or above.
  - **16a:** Split agent scopes: `ops:discovery` (Operator) and `ops:discovery_test` (Admin).
- **Question 13, answered by a test (2026-11-16):**
  - The gateway (a UniFi gateway) serves `ipNetToPhysicalTable` over SNMPv3 with SHA and AES: 108 IPv4 and 81 IPv6 entries, 179 of them with a MAC. `ipNetToMediaTable` has 108. T25.6 stays as written for ARP (option a). M25 is IPv4 only, so the IPv6 rows are counted and ignored; they are a possible source for T24.8 (IPv6 device names) later.
  - The gateway has no BRIDGE, Q-BRIDGE or LLDP MIB. Some networks' switches and APs are not UniFi. Port mapping therefore needs SNMP agents on the switches themselves; the UniFi API (ADR-912's `devices` read) can't supply it on this network. T25.6 says so.
  - A gateway may also answer v1/v2c `public`. The SNMP setup docs flag that as a finding to turn off once v3 works.
  - A network printer that answers v2c `public` with the Printer MIB is the case the ADR-909 opt-in is for.

## ADR-906 — Fork ADR numbers: fork-only ADRs take the next free number from 901 up (Accepted 2026-11-16)
**Context:** This fork (nbacheller/telltaledns) and upstream (paimonsoror/telltaledns) both record decisions as ADRs. Upstream's numbering ended at ADR-164, so the fork's first five decisions after it (numbers 165 to 169) sat where upstream's next decisions would go, and one number could mean two decisions once a sync brought them together.
**Decision:**
- Fork-only ADRs take the next free number at or above 901, in order, and a number is never reused.
- Upstream's ADR numbers are kept as they are; the fork does not renumber them.
- On each upstream sync, check upstream's new ADR and requirement IDs against this file. If one of them lands on a fork ADR number, renumber the fork ADR (901 and up), never upstream's.
**Consequences:** On 2026-11-16 the fork's numbers 165 to 169 became 901 to 905, and every reference in code, spec, docs, site, UI, and bench was updated to match. Upstream's numbers stay below 901, so the two ranges do not meet.

## ADR-905 — Update lists now: one queued round per request, on the node that downloads lists (Accepted 2026-11-16)
**Context:** `spec/07` §2 promises `POST /lists/refresh`, but only `SIGUSR1` refreshed lists, and on a cluster replica nothing could (replicas don't download lists, CLU-003) while its Lists page showed every list as "pending". Pi-hole users expect "Update Gravity".
**Decision:**
- `POST /api/v1/lists/refresh` (body `{}`, `null`, or `{"names": [...]}`; `?dryRun=true`; `Idempotency-Key`) queues the enabled lists named, or every enabled list, on the node that downloads lists, and answers 202 with `queued`, `skipped` (disabled), `alreadyRefreshing`, `node` and `note`. An unknown name is 404 with the real names in the hint. A node that doesn't download lists (role `resolver`, or no fetcher) answers 409 `lists_not_here`. A dry run queues nothing and isn't audited (AGT-002); a key replays the first answer for 24 h and a reused key with another body is 409 (AGT-003). Audited as `lists.refresh`.
- **Rounds:** requests made before a round starts merge into it; a request made while lists download starts exactly one more round after it. Progress is per list, not a job: `refreshing` (queued or downloading) and `lastSuccessUnixSeconds` on `GET /lists`. No new change marker: `lists.refreshed` already marks a refresh that changed the snapshot (OBS-033).
- **Scope:** people need the operator role; agents reuse `config:write:lists` plus the reason header (saving a list already makes it download, so this grants nothing new). Group-restricted agent tokens are refused.
- **Cluster:** the primary downloads (CLU-003). A replica forwards `Write::ListsRefresh` (`by`, `names`, `dry_run`, `reason`), and the primary audits it with actor `"<user> via <entry site>"`, kind `cluster`, and the user's reason. An N−1 primary refuses the unknown write and the replica answers 503. Without a reachable primary, a node with its own fetcher uses it, otherwise 503; an emergency primary that followed a primary has no fetcher and answers 503 (list refresh paused, `spec/12` §5). A replica's `GET /lists` shows the primary's lists and download state (`Read::Lists`) with every node's hits added up (`Read::ListHits`, OBS-009); when the primary doesn't answer, `missingNodes` names it and the replica shows its own view. `ctl lists refresh --wait` stops only when the primary is among `missingNodes`: a replica that misses only its hits doesn't stop it. The primary is named as `missingNodes` names it (its pod, else its site, else its node ID; `ctl` also matches its site and node ID, so an empty site is never a blank name). `missingNodes` also names nodes whose hits are missing (OBS-009). In a mixed-version window an N−1 primary that answers `Read::Lists` but not `Read::ListHits` is in `missingNodes` too, so it stops `--wait`. This is deliberate: `missingNodes` doesn't say which read was missed, and the primary's own hits are missing, so the conservative stop is kept (the download state there was read, which is why the Lists page words its notice as "not confirmed from the primary" rather than "this node's own").
- **Surfaces:** the Lists page **Update now** (operators; progress, failures named, "last confirmed current" from the oldest enabled list); `telltale ctl lists refresh [names] [--dry-run] [--wait] [--reason]`, where `--wait` exits non-zero after 5 minutes or when the primary is unread; MCP `refresh_lists`, an immediate audited op with no plan (`spec/13` §3.2), like `flush_cache`: it changes no configuration and costs one conditional request per unchanged list.
**Consequences:** `SIGUSR1` still refreshes only the node that gets it. The fetcher's new lock is taken only when a download starts or ends, on a refresh request, and on a lists read; the query path is unchanged.

## ADR-904 — Pi-hole's special names: iCloud Private Relay blocked by default, resolver.arpa kept local with DDR, domain-needed opt-in (Accepted 2026-11-16)
**Context:** DNS-019, `spec/03` §3 step 4 (DDR promised at P1). Pi-hole users rely on three behaviours we lacked: Pi-hole answers iCloud Private Relay's names NXDOMAIN by default (Apple's documented opt-out for networks: devices then use the network's DNS, so filtering applies); it answers `resolver.arpa` locally (`designatedResolver`); and `domain-needed` keeps bare names off upstreams. RFC 9462 §6.5 says forwarders shouldn't forward `resolver.arpa`: an upstream's DDR answer names a resolver whose certificate can't cover our address.
**Decision:**
- **iCloud Private Relay:** `[special] block_icloud_private_relay`, default **true** (a behaviour change, for Pi-hole parity): exactly `mask.icloud.com` and `mask-h2.icloud.com` → NXDOMAIN (with SOA), all types, before local data and filtering; status `special`. A bool, like `block_firefox_canary`.
- **resolver.arpa:** always local, no switch. With `[special] ddr_name` (the host name in the listeners' certificate), `_dns.resolver.arpa` SVCB answers one record (RFC 9460/9461) per DoT, DoH, DoH3 and DoQ listener on this node, in listener order (priority 1, 2, …), TTL 300, AA: `alpn` (`dot`, `h2`, `h3`, `doq`), the listener's `port`, `ipv4hint`/`ipv6hint` only for a listener bound to a specific address, and `dohpath` = the listener path + `{?dns}` (default `/dns-query{?dns}`). **Left out:** listeners bound to loopback (no other device can reach them) and listeners with `proxy_protocol = true` (a direct connection fails without the PROXY v2 header); advertising nothing leaves a device on plain DNS, while advertising an unreachable resolver can leave it with none. The records are built with the policy, off the query path. Anything else in `resolver.arpa` → NOERROR, no data, SOA. `[special]` is shared but listeners are node-local, so each node advertises its own. Clients check that the certificate covers the IP they use (an IP SAN); documented, not checked.
- **domain-needed:** `[special] single_label_nxdomain`, default **false**. One-label names asked for **A, AAAA, or HTTPS** (dnsmasq's A/AAAA, plus HTTPS because browsers send it for the same bare names) → NXDOMAIN at the routing step: after local records, zones, device names, quick rules, the filter and rewrites, unless a `[[route]]` matches (the same test as RFC 6303 private PTRs). Other types (DS, NS, SOA, DNSKEY of a TLD, which validators ask) still go upstream.
- **Classifier:** one walk over the labels picks the top-level label; each rule compares only under its own TLD. No allocation (`02` §3).
- **Importer:** v6 `dns.domainNeeded`, `dns.specialDomains.iCloudPrivateRelay`, `mozillaCanary`; v5 `DNS_FQDN_REQUIRED`, `BLOCK_ICLOUD_PR`, `MOZILLA_CANARY` (the last two on unless an explicit `false`, any case, trimmed). Written only where Pi-hole differs from our defaults. `designatedResolver = false` has no equivalent (never forwarded, per RFC 9462); `bogusPriv` stays an import note.
**Alternatives rejected:** a string enum `icloud_private_relay = "block"|"allow"`; NXDOMAIN for `resolver.arpa` (RFC 9462 and Pi-hole use NODATA); the DDR target from the certificate's SAN (needs X.509 parsing in the policy crate); domain-needed for every type (breaks DS/NS of TLDs under DNSSEC); forwarding `resolver.arpa` when no `ddr_name` is set.
**Consequences:** Apple devices with Private Relay on show "Private Relay is turned off for this network" until an admin flips the switch. Windows 11, iOS 16+ and macOS 13+ discover encrypted DNS by themselves once `ddr_name` and an IP-SAN certificate are in place. Behind port mappings the advertised ports are the listeners' own (a per-node `ddr_port` is a possible follow-up), and a load balancer that adds PROXY headers gets no DDR (a possible opt-in later).

## ADR-903 — Secrets entered in the UI: a write-only encrypted store referenced by name, replicated to full members outside configuration versions, with files still winning (Accepted 2026-11-16)

**Context:** On 2026-11-16 the owner asked that anything configured today through a secret file can also be entered in the UI, and that the files keep working. The owner fixed four points:
1. A secret entered in the UI replicates to full cluster members over the mTLS cluster channel and is re-encrypted on each node. It never reaches ephemeral resolver pods.
2. Secrets are encrypted in `state.db` with a per-node key: `<data_dir>/secrets.key` (0600) by default, or one that comes from an environment variable or a mounted file.
3. A backup carries secrets only when they are encrypted with a passphrase given at backup time, and the backup says so when it leaves them out.
4. A `*_file` or inline value in the configuration files wins. The UI shows it as set by file and won't edit it.

The code this ADR changes is at commit `412add6`.

- **Where secrets live now.**
  - Most are files named by a `*_file` path and read when used: `routers.rs:112-119`, `alerts.rs:737-745,809-817`, `sinks.rs:719-725`, `gitsource.rs:205-210,419-422`, `auth_setup.rs:69-78`, `telltale-cluster/src/net.rs:1008-1015`.
  - The rest are inline values: `auth.oidc.provider[].client_secret` (`schema.rs:2745`), `upstream[].headers` (`schema.rs:520-522`) and `telemetry.otlp.headers` (`schema.rs:2388`).
  - `SafeString` prints the plain value in both `Debug` and `Serialize` (`telltale-config/src/types.rs:49-75`).
- **Existing leaks.**
  - `GET /api/v1/config/entries` returns `serde_json::to_value(e)` (`api_backend.rs:2895`), so upstream `headers` and exec `args` come back unredacted. On a replica the primary's body is passed through unchanged (`federated.rs:2439-2450`).
  - The write path copies bodies into these places:
    - the idempotency table (`config_api.rs:190,1850-1860`);
    - the audit `{before, after}` (`config_api.rs:1902-1913`);
    - a second audit entry on the primary for every forwarded write (`forward.rs:232-237`);
    - the `keepInGit` TOML (`api_backend.rs:5223-5260`);
    - the forward to the primary (`federated.rs:2412-2422`). `forward::Write` derives `Debug` with the raw body (`forward.rs:31`).
  - `telltale config check --print` prints inline secrets (`main.rs:1622-1623`).
  - The Git webhook returns the internal error (file path, I/O error) with its 401 to anyone (`api_backend.rs:3285-3289`). It also HMACs with `secret.trim()`, so an empty secret file gives an empty key that anyone can forge (`gitsource.rs:419-432`).
- **Existing exfiltration paths.**
  - An operator can point an alert destination's `token_file` at any file the process can read (for example `<data_dir>/cluster/ca.key` or `/proc/self/environ`) and its `url` at their own host (`alerts.rs:809-817`).
  - An operator, or an agent with `config:write:upstreams`, can create an `exec://` upstream (`validate.rs:19,1462-1468`). The plugin is spawned with the parent's whole environment and no `env_clear`/`env_remove` (`telltale-upstream/src/plugin.rs:55-62`). Self-update spawns the same way (`selfupdate.rs:101,201`).
  - The primary applies a forwarded write with only `by: String` and no role (`forward.rs:34-44,182-191`).
- **Precedents for secrets between nodes.**
  - ADR-045 replicates TOTP secrets, stored as plain BLOBs (`telltale-store/src/state/identity.rs:33,142`).
  - ADR-051 sends the CA key in `KeyShare` (`wire.rs:75-83`).
  - ADR-143 withholds identities from ephemeral members (`net.rs:2530-2545`). Witnesses are non-ephemeral but serve no DNS or UI (`node.rs:39,747-751`).
  - So ADR-045's "never cross the cluster channel" really covers only file secrets.
- **Ordering and versions.**
  - Configuration orders by `(epoch, seq)` with a `base` for orphan detection (`sync.rs:36-60`) and is fenced (`net.rs:645-647`).
  - Pins and canary rollouts gate everything in `ClusterManifest` (`spec/12` §4, CLU-013).
  - `ClusterManifest` has no `deny_unknown_fields`, and heartbeats are prost messages, so new optional fields are N-1-safe.
  - Config structs do use `deny_unknown_fields` (`schema.rs:3,1249`), and `with_shared` refuses unknown shared keys (`shared.rs:84-90`). An N-1 replica therefore refuses a version that uses a new field, the same limit ADR quick-rules records (`spec/11:1242`).
- **Startup-only readers.**
  - `[[router]]` (`server.rs:1099-1106`). `resolver_pod` there only lowers the log level, so pods do poll today (`routers.rs:724-738`).
  - OIDC. `Auth.oidc` is a `OnceLock`, `set_oidc` silently ignores every set after the first (`telltale-api/src/auth/mod.rs:315,404,465-467`), and in-flight flows live inside `Oidc.flows` (`oidc.rs:107,279`).
  - Sinks (`sinks.rs:66-72`). `Sink::record` takes `&mut self` (`ring.rs:527`) and `DROPS` is a `OnceLock` (`sinks.rs:52,112`).
  - Alerts, Git and the bootstrap secret re-read at use.
- **Settings only in files:** `[[router]]`, OIDC providers, sinks, `[cluster.git]`, `[identify]` and the Groups form's `device_classes`.
- **Spec inconsistency:** ADR-045's implementation note says OIDC provider settings replicate, but `auth` is in `NODE_LOCAL` (`shared.rs:15-26`).
- **Other code facts.**
  - The release profile aborts on panic (`Cargo.toml:46-51`).
  - `state.db` runs WAL with no `secure_delete` (`state.rs:250-254`).
  - `[api] tls` defaults to none (`schema.rs:2618-2625`).
  - The edition is 2024, so `std::env::remove_var` is `unsafe` (AGENTS rule 7).
- **Already linked:** `ring` 0.17.14 (direct in `crates/telltale`), `blake3` and `arc-swap` (direct), `argon2` 0.6.0 (`telltale-api`), `zeroize` 1.9.0 (transitive). The image is about 14.70–14.75 MiB against the 15 MiB gate.

**Decision:**

**1. Scope.**

| Field | Decision | Why |
|---|---|---|
| `router[].api_key` / `api_secret` / `password` (UniFi, OPNsense, Home Assistant token) | **In** (T23.3, T23.7–8) | The owner's main case. A router whose credential is stored polls on the primary (or a standalone node) only. The others get its names through ADR-125's peer leases, which keeps ADR-125's "not every node polls" rule. A router whose credential is a file keeps polling where it does today, except that ephemeral pods now skip it explicitly. |
| `alerts.destination[].token` / `password` | **In** (T23.6) | Read at each delivery, on the primary or a standalone node. |
| `cluster.git.credentials` / `webhook_secret` | **In** (T23.12) | Read at each poll or request. Replication means every Git-eligible primary has them. |
| `telemetry.sink[].token`, `telemetry.otlp.headers` | **In** (T23.11) | Telemetry never affects DNS (02 §8). On ephemeral pods a sink that needs a stored secret is skipped and logged once at info. |
| `auth.oidc.provider[].client_secret` | **In** (T23.10) | Only full members serve the UI. |
| `upstream[].headers`, `upstream[].tls_client_key` | **Later** | They sit on the answering path, and resolver pods would never have the value (decision 1, CLU-004). Inline and file values keep working, and T23.1 redacts them. |
| `upstream[].args`, URL and proxy userinfo | **Out** (redacted only) | Not credential fields by design. `exec://`/`unix://` become admin-only (T23.2). |
| `listen[].tls.key`, `api.tls.key` | **Later (P2), status only now** | A node's own identity, already hot-reloaded (`telltale-net/src/tls.rs:26-78`). Replicating one node's key is wrong, and a bad API key could lock out the UI. |
| `cluster.bootstrap_secret` | **Out, status only** | Pods need it before the channel is trusted (ADR-058). |
| `allowed_signers_file`, `trust_anchors_file`, `*.tls_ca`, `signatures_file` | **Not secrets** | A router's CA becomes an inline `tls_ca_pem` (T23.8). The others stay files. |

Non-secret settings that exist only in files are phased with the forms that need them:
- a `router` kind (T23.7);
- `oidc_provider` and `sink` kinds (T23.10–11);
- Git `*_ref` fields. `[cluster.git]` itself stays file-only, pinned by `set-authority` (ADR-049);
- `identify-settings` and `[[group]] device_classes` (T23.13).

**2. Data model.**
- **A new table, not `managed`.** Migration 11 creates:
  `secrets(name TEXT PRIMARY KEY, kind TEXT NOT NULL, key_id BLOB, nonce BLOB, ciphertext BLOB, stamp_epoch INTEGER NOT NULL, stamp_seq INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, origin TEXT NOT NULL, updated INTEGER NOT NULL, updated_by TEXT NOT NULL)`.
  - A row with `deleted=1` is a tombstone with no ciphertext.
  - Tombstones are kept for 90 days, and at most 512 of them, so offline members still learn of deletions.
  - The managed copy paths (`shared_part`, `config/entries`, `keepInGit`, audit) never see this table.
- **Stamps.** Every change is stamped `(epoch, seq)`. On a cluster that is the current epoch and a per-epoch counter, taken under `fence` and the lease check (`may_publish`, ADR-056). On a standalone node it is `(0, n)`. A stamp is never reused, delete-then-recreate included.
- **The secrets head** is `{stamp, digest}`. `digest` = BLAKE3 over the sorted `(name, kind, stamp, deleted)` list. It holds no value and no value hash.
- **Names** match `^[a-z0-9][a-z0-9._-]{0,62}$`. `kind` is `text` (`pem` is reserved).
- **Values.**
  - At most 8 KiB, UTF-8, trimmed.
  - Empty after trimming is refused, and `webhook_secret` needs at least 16 characters.
  - `text` refuses every control character (as `SafeString` does). `pem` will allow `\n`.
  - `"<redacted>"` is refused as a value.
- **Limits:** at most 128 live secrets, and at most 512 KiB of encoded values in one fetch (section 6).
- **References.** Each field gets a sibling `<field>_ref = "<name>"`:
  - `router[].api_key_ref` / `api_secret_ref` / `password_ref`;
  - `alerts.destination[].token_ref` / `password_ref`;
  - `auth.oidc.provider[].client_secret_ref`;
  - `telemetry.sink[].token_ref`;
  - `telemetry.otlp.header_refs = {"<Header>" = "<name>"}`;
  - `cluster.git.credentials_ref` / `webhook_secret_ref`.

  These fields are serialized only when set, so configurations without them still converge on N-1 replicas. The UI names a new secret `<kind>.<entry>.<field>`, while the configuration always holds the explicit name, so a Git-managed file can say `api_key_ref = "unifi"`.
- **Validation** (`validate.rs`):
  - At most one of inline, `_file` and `_ref` per field.
  - A missing `_ref` is a load **warning** (DNS never depends on the store) and a **422 `secret_missing`** on an API write.
  - `"<redacted>"` in a file is a load error.
- **Precedence, judged against the file layer and not the effective entry** (decision 4). The file layer is TOML, `TELLTALE_*` and CLI; on a replica, for a shared section, it is the primary's file layer as published.
  1. If the file layer sets the field inline or by `_file`, the source is `inline`/`file`. The UI shows "Set by file (`<path>`, read on each node)" and whether it is readable on this node. An API write that sets, drops or replaces it, whether by `_ref`, an ADR-069 override or a hidden entry, is refused with 409 `set_by_file`. An override that changes other fields gets the file's credential field carried over by the server.
  2. Otherwise a `_ref` gives `stored`.
  3. Otherwise the source is `none`.
- **Kinds.**
  - `router` and `oidc_provider` follow ADR-040: names defined in the files are read-only through the API.
  - Alert destinations keep ADR-069, constrained by rule 1.
- **One resolver.** `telltale::secrets::Credential::resolve(inline, file, ref) -> Resolved { value: SecretValue, source }` replaces the six read sites.
- **`SecretValue`.**
  - Its `Debug` and `Display` print `<redacted>`, it has no `Serialize`, and it is zeroized on drop.
  - The claim is limited to our own buffers: prost, TLS and stream buffers are not zeroized, and the docs say so.
- **Readable checks** open the file read-only with `O_NONBLOCK` and close it without reading. A file that isn't a regular file reports "not usable". `stat` alone can't tell readability.

**3. Encryption and the node key.**
- **Cipher.** ChaCha20-Poly1305 from `ring::aead`, so no new crate. It is fast on a Pi 4, which has no AES instructions.
- **Nonce:** 96 random bits from `SystemRandom` per encryption. With a few thousand writes per key this stays far below 2^32.
- **Associated data:** `"telltale-secret\x01" ‖ key_id ‖ kind ‖ name ‖ be64(stamp_epoch) ‖ be64(stamp_seq)`, with `kind` and `name` each preceded by its be16 length (note 39).
- **Key format.**
  - A key is 32 random bytes, written as `ttsk1:<base64url, no padding>`.
  - `key_id` is the first 8 bytes of `blake3::derive_key("telltale secrets key-id v1", key)`.
  - Subkeys are derived as `"telltale secrets aead v1"` and `"telltale secrets idempotency v1"`.
- **Key source, first match wins:**
  1. `TELLTALE_SECRETS_KEY`;
  2. `[node] secrets_key_file` (env `TELLTALE_NODE_SECRETS_KEY_FILE`; the only spelling documented);
  3. `<data_dir>/secrets.key`.

  The previous key comes from `TELLTALE_SECRETS_PREVIOUS_KEY` or `[node] secrets_previous_key_file`. Both variables join `RESERVED` (`env.rs:22-44`). Spawned processes (plugins, self-update) have them, `TELLTALE_BOOTSTRAP_ADMIN_PASSWORD*` and `TELLTALE_TOKEN` removed with `Command::env_remove`; no `unsafe`. The docs prefer a file, and on Kubernetes `secretKeyRef` over a literal `value`.
- **Creating the data-dir key.** `secrets.key` is generated only when the `secrets` table holds no rows and no tombstones.
  - It is created with `O_CREAT|O_EXCL`, mode 0600, written and fsynced, never renamed over an existing file.
  - A key file readable by others, or owned by another user, gives a warning. Group read by the process's own gid doesn't warn (kubelet with `fsGroup`).
- **Rotation.**
  - At start, rows under the previous `key_id` are re-encrypted in one transaction, followed by `wal_checkpoint(TRUNCATE)`.
  - `telltale secrets rotate-key` is offline and covers the data-dir key only. It writes `secrets.key.new`, re-encrypts, commits, checkpoints, then renames. A leftover `.new` file is tried by `key_id` at the next start.
- **Locked store.** The store is **locked** when:
  - a configured source (1 or 2) can't be read or parsed;
  - source 3 is missing while rows exist;
  - or no row decrypts under any available key.

  While locked:
  - nothing is generated, and secret writes return 503 `secrets_locked`;
  - status reads work, and health shows `secrets_locked` (degraded, OBS-015);
  - DNS and `/readyz` are unaffected.

  One exception: a **replica** whose rows are all `origin='cluster'` may generate a new key, drop those rows and refetch.
- **Row states.** A row whose `key_id` matches neither key is `unreadable`, and one that fails authentication is `corrupt`. Re-entering the value, or a sync, repairs it.
- **When a secret can't be read.** An integration that needs an unreadable secret reports "not configured: secret `<name>` can't be read on this node (<reason>)" and logs once until that changes. The metric is `telltale_secrets{state}`.
- **Threat model** (`docs/secrets.md`).
  - With the data-dir key, the store protects copies of `state.db` and backups, not someone who holds the whole data directory.
  - Admins are trusted not to misuse a stored secret, but cannot read one back (except through a passphrase backup, section 8).
  - Operators and agents can neither read nor redirect one.

**4. API and rules.**
- **Routes.**
  - `GET /api/v1/secrets[/{name}]` (operator; agents with `config:read`) returns metadata only:
    - `name`, `kind`, `set`, `stamp`, `updated`, `updatedBy`, `origin`;
    - `usedBy [{kind, name, field, source, node?}]`;
    - `nodes [{node, applied, unreadable}]`;
    - `credentials`: every credential field on this node with its source, its path and whether it is readable.

    On a replica this is proxied to the primary when one is reachable (as `config_entries` is). Otherwise it is local with `stale: true`.
  - `PUT /api/v1/secrets/{name}` takes `{"value", "kind"}`, and `DELETE /api/v1/secrets/{name}`. Both need **admin**, answer with metadata only, and carry `Cache-Control: no-store`.
    - `DELETE` of a referenced secret is 409 `secret_in_use`, listing users across nodes (section 6). If a full member's references are unknown (offline), it needs `?force=true`.
- **Transport.** `PUT /secrets` and a passphrase `POST /backup` are refused with 403 `insecure_transport` unless the request is HTTPS (`is_https`, including trusted proxies) or comes from loopback.
  - `[api] allow_secrets_over_http = true` (node-local, file only) lifts this.
  - The UI explains and links to `[api] tls = { self_signed = true }` (ADR-149).
- **Agents:** 403 `agent_not_allowed` on secret writes whatever the scopes.
- **AGT conformance.**
  - AGT-001: `value` is `writeOnly`.
  - AGT-002: `?dryRun=true` checks name, kind and size, reports `wouldCreate`/`wouldReplace` and the entries that would become configured, and stores nothing.
  - AGT-003: the stored request is `PUT /secrets/{name} ` plus the hex keyed BLAKE3 of the value under the idempotency subkey. The same key with a different value is 409.
  - AGT-005: audited as `secret.put|delete {name, kind, stamp, usedBy}`, never the value or its length.
  - `If-Match` takes the secrets head as an ETag.
- **On a replica**, writes are forwarded to the primary as a dedicated RPC kind `secret.put`/`secret.delete`, not a variant of `api.write`, so an N-1 primary refuses it by kind.
  - The value travels as `SecretValue`, and the request type's `Debug` redacts.
  - The forward carries `role` and `agent` (below), and logs only the operation and the name.
  - With no primary reachable, the answer is 409.
- **When writes are allowed.**
  - **Lease and fence:** a primary without a valid lease, or past the fence, refuses with 409.
  - **GitOps authority:** secret writes are allowed (secrets are state, never in Git, ADR-049); entry writes stay 409 `gitops_managed`.
  - **Emergency primary:** 409.
  - **Pin or canary rollout:** allowed. The secrets head travels outside `ClusterManifest` (section 6), so pins and rollouts neither hold it back nor bump `seq`.
- **Credential rules for entries** (T23.2):
  - Creating or changing any `*_file` or `*_ref`, or the destination fields of an entry that has any credential (inline, file or ref), needs admin. Destination fields are `url`, `proxy`, `host`, `tls_server_name`, `tls_ca`, `bootstrap` and the scheme.
  - The `router`, `oidc_provider` and `sink` kinds are admin-only.
  - Creating, or switching to, an `exec://` or `unix://` upstream needs admin, on writes and on `checks/upstream` alike.
  - API-set paths:
    - are canonicalized at write and at use;
    - must not be under `/proc`, `/sys`, `/dev`, `data_dir`, or any configured key, previous-key, bootstrap or TLS key path, and these denials apply to every API-settable path (`list[].path`, `tls_ca` included);
    - `*_file` must also sit under `[node] secret_file_dirs` (node file only; default `/run/secrets`, `/var/run/secrets`, `/etc/telltale/secrets`).
    - An existing API-set path outside these rules stops being read and reports the reason in `credential_issues`.
  - An admin write that changes the destination of an entry with a `_ref`, or points a `_ref` at a secret already used by a different kind, is audited as `credential.redirect` and raises the alert event `credential_redirected`.
  - Forwarded writes carry `role` and `agent`, and the primary re-checks every rule. A credential-affecting write forwarded without a role (an N-1 replica) is refused with 409 `upgrade_required`.
- **Redaction everywhere bodies are copied** (T23.1).
  - `telltale-config::credentials::PATHS` lists:
    - `upstream[].headers.*`, `upstream[].args[*]`;
    - URL userinfo passwords in `upstream[].url`, `upstream[].proxy` and `alerts.destination[].url`;
    - `auth.oidc.provider[].client_secret`, `telemetry.otlp.headers.*`.
  - It is applied by:
    - `config_entries` (again on a replica after decoding);
    - write responses, both audit sites (`config_api.rs:1902-1913`, `forward.rs:232-237`, `apply_ack`);
    - the stored idempotency response;
    - `keepInGit`, forward logging, `config check --print` (`--show-secrets` opts in);
    - `GET /cluster/compare`, every MCP read tool and resource, and the support package.
  - Values come back as `"<redacted>"`, and `ConfigEntry.redacted` lists the paths.
  - **The marker rule:** a PUT that sends `"<redacted>"` keeps the current value only when the entry's destination fields are unchanged. Otherwise it is 422 `credential_reentry_required`. With no current value it is 422 too. `POST /checks/*` never resolves markers.
  - **Idempotency.** The stored request is the keyed BLAKE3 of the canonical full body (node key, idempotency subkey), and the stored response is redacted. With the store locked, a write carrying an `Idempotency-Key` whose body holds a credential path is 503.
  - **Migration 10** purges existing idempotency rows. `state.db` gets `PRAGMA secure_delete=ON`, plus `wal_checkpoint(TRUNCATE)` after the migration, after rotation and after secret deletes.
  - A test fails when a field classed `secret` in `telltale-support/src/classify.rs` is in neither `PATHS` nor a reasoned allow-list (usernames). `*_ref` fields are class `name`.
- **The Git webhook** answers a generic 401 and logs the detail, and refuses empty secrets.
- **Delivery errors** keep hosts only, never URL queries. The Gotify token is percent-encoded (`alerts.rs:821-825`).

**5. MCP and agents.**
- **New read-only tools.** `secrets_status` wraps `GET /api/v1/secrets` (`config:read`). `list_routers` wraps `GET /api/v1/routers`.
- **No write tools** for secrets, or for the `router`, `oidc_provider`, `sink` or `identify-settings` kinds. These have no agent scope. A value would otherwise sit in AGT-007 plan memory, the approval diff and the agent's transcript, as with OPS-011 and ADR-156.
- **Plans meet the marker rule.** MCP plans that merge from `config/entries` (`mcp.rs:2321,2372`) carry `"<redacted>"`, so a plan that changes an upstream's destination fails at apply with `credential_reentry_required`, and the plan summary says so.
- **Agent forbidden list.** `POST /api/v1/backup`, `/checks/router*` and the secret writes join it (`agent.rs:590-598`).
- **spec/13 §3** records these exceptions.

**6. Replication** (CLU-015, decision 1).
- **The head travels in heartbeats, not in configuration.** The primary's `Heartbeat` (prost, new optional tags) carries `secrets_head {epoch, seq, digest}`. Nothing goes in `ClusterManifest`, so pins, canary bakes, `If-Match configVersion`, version history and lag are unaffected. N-1 nodes ignore the tags (CLU-010).
- **Fetching.** A full replica sends the RPC `secrets.fetch {since_digest}` when the head's digest differs from its own.
  - It sends it only to the node it holds as primary of the highest epoch it has seen, and ignores a head from a lower epoch (`spec/12` fencing rule 4).
  - Fetches happen at most once per head, back off from 30 s to 10 min on failure, and never run while the local store is locked.
  - Fetching never gates manifest application, `applied` or readiness (ADR-058).
- **The primary answers** only a peer that its **registry** records as `!ephemeral && !witness`.
  - The answer is `{head, items: [{name, kind, value?, stamp, deleted, updated, updated_by, held?}]}`.
  - A row the primary can't decrypt is sent as `held` (no value), and the replica keeps its own row with that stamp.
  - A locked primary, or one that generated a new key, answers `secrets_unavailable`, and replicas keep their set.
  - An emergency primary still answers.
  - The answer is protobuf `bytes`, capped at 900 KiB encoded and paged beyond that. It never touches the blob store, so no plaintext reaches anyone's disk.
- **The replica checks** that the answer's head equals the announced head and that the digest recomputed from the items matches. Otherwise it discards the answer.
- **Applying.**
  - The replica re-encrypts each value under its own key.
  - In one transaction it upserts `origin='cluster'` rows by stamp: a higher stamp wins, and a tombstone deletes.
  - It never deletes a name by its absence from the set.
- **Orphans.** Rows a demoted primary stamped in an epoch after the new primary's base are orphaned. They are not deleted, but listed under Conflicts as "re-enter on the current primary" and not used.
- **Origin.**
  - On the primary every row is authoritative and stored as `origin='cluster'`. At `cluster init` and at join, a standalone node's rows become cluster rows on the primary.
  - On a joining replica, local rows stay usable on that node, and are flagged `shadowed` when a cluster row of the same name arrives.
  - On removal (ADR-155) or leave, cluster rows are purged and the purge is audited.
- **Reverse heal.** A primary with unreadable rows fetches them from a registry-full replica holding the same stamp. The replica answers only the current primary.
- **Heartbeats from members** carry `secrets_applied` (head), `secrets_unreadable`, `credential_issues` (at most 32 paths) and `secret_refs`: the names this node's node-local fields reference, at most 128, sent on change and every 60 s. `DELETE` checks the union of these.
- **Ephemeral pods** hold no secrets, need no key, never generate `secrets.key` and never report `secrets_locked`.
- **Node-managed entries** (`oidc_provider`, `sink`) are configuration, not secrets, so they are versioned. `ClusterManifest` gains an optional `node_managed: BlobRef` holding references only, which N-1 nodes ignore.
  - Every member persists the last one it applied.
  - Each member validates and merges it separately from the shared part, under its own files, where file ids win. A failure drops only those entries, logs once, and leaves the shared part and DNS untouched (CLU-004).
  - A newly promoted primary publishes the inherited blob overlaid with its own rows, and seeds its managed rows from it.
  - A primary with a Git source carries the blob unchanged, and writes of these kinds there are 409 `gitops_managed`.
  - Ephemeral members skip entries that need a stored secret, with one info log.

**7. Hot reload.** Nothing here touches the query path.
- **Routers.**
  - `routers::run` reads the live `[[router]]` from `Sources` at each round, and no longer returns on an empty list. It recomputes `interval` each round.
  - Changed or removed routers are rebuilt or dropped, and unchanged routers keep their state.
  - A `Notify` on a router or secret change polls, debounced to at least 5 s.
  - Polling follows section 1's rule: stored credentials on the primary or a standalone node, file credentials as today, and ephemeral pods skip explicitly.
  - Failures are logged once until they change, and names stay as last read.
  - The release build aborts on panic, so `routers.rs` gets `clippy::unwrap_used`, `expect_used` and `indexing_slicing` denied, and malformed answers are tested.
- **OIDC.**
  - `Auth.oidc` becomes `ArcSwapOption<Oidc>`.
  - In-flight flows (PKCE verifier, nonce) and the discovery cache move into `Auth`, so a swap keeps sign-ins in progress.
  - Rebuilds run one at a time with a generation counter, and a stale result is discarded.
  - A provider whose discovery fails keeps its previous settings, or is left out with a reason.
  - Sessions and the break-glass admin are untouched.
- **Sinks.**
  - The drainer-owned `EventSinks` receives a new `Vec<Out>` through a channel `try_recv` once per batch.
  - `DROPS` becomes swappable.
  - Spill files are keyed by name plus a hash of the URL. A removed sink's thread is joined (2 s bound) before its name is reused, and its spill file is deleted.
  - OTLP headers are resolved per export batch.
- **Alerts and Git** use the resolver at use. The store keeps ciphertext in memory and decrypts at use.

**8. Backups** (amends ADR-063 and API-007).
- **Never in a backup:** the `secrets` table, its tombstones and the head. They are dropped like `sessions` and `idempotency` (`backup.rs:302`), and `sqlite_copy` vacuums. The node key is never included either.
- **With a passphrase** of at least 12 characters, the archive gains `data/secrets.enc`:
  - ChaCha20-Poly1305 over the JSON list `{name, kind, value, updated, updated_by}`;
  - the key from Argon2id v1.3, m = 19,456 KiB, t = 2, p = 1 (the same as password hashing), with a 16-byte salt and 32 bytes of output, parameters recorded;
  - a 12-byte random nonce;
  - associated data `"telltale-backup-secrets v1" ‖ backup_id`.

  One KDF runs at a time per process; a second request gets 429. Restore refuses m > 256 MiB or t > 10.
- **Manifest and version.** The manifest gains `secrets {included, count, omittedReason?, kdf, aead, nonce, backupId}`. `VERSION` becomes **2 only when `secrets.enc` is present**, so older builds refuse it; archives without secrets stay version 1.
- **Without a passphrase,** the CLI, the API header and the UI all say "N stored secrets were left out". The backup also warns when the configuration files or `managed` rows hold inline credentials, which are copied as they are.
- **Restore** (offline):
  - `--secrets-passphrase-file F`, a TTY prompt, or `--skip-secrets`. A version 2 archive with neither is refused before anything moves.
  - A wrong passphrase reports "wrong passphrase or damaged archive" and moves nothing.
  - The key is resolved from the same configuration (`-c`) and environment as the server. Restore refuses, rather than generating, when a configured source is unavailable, and prints the source and `key_id` it used.
  - Rows are re-stamped in the restoring node's current epoch, inside the staged `state.db`.
- **API.**
  - `POST /api/v1/backup` (admin; not agents; HTTPS rule from section 4) takes `{includeQlog?, passphrase?}` and answers with `X-Telltale-Backup-Secrets: included|omitted; count=N`.
  - With a passphrase it needs an interactive session signed in within the last 10 minutes; tokens get 403 `reauth_required`, with a hint to run `telltale backup create` on the node.
  - It is audited as `backup.create {secretsIncluded, count}`, and with secrets included it raises the alert event `secrets_exported`.
  - It takes no `Idempotency-Key`, because it changes no state.
  - `GET /api/v1/backup` stays and omits secrets.

**9. UI.**
- **Settings → "Integrations & secrets":**
  - stored secrets (name, used by, updated, by, readable per node, Replace, Clear);
  - credential fields set by file (path, readable on this node);
  - store state (key source, locked/unreadable/ephemeral);
  - orphaned rows.
- **`SecretField.svelte`:**
  - a write-only `type=password` input, never pre-filled, with `autocomplete="off"`, `spellcheck="false"`, `data-1p-ignore`, `data-lpignore` and no show toggle;
  - states: Not set, Set (updated, by), Set by file, Inline in the file, Unreadable on `<node>`, and Can't be set over plain HTTP.
- **Saving** is `PUT /secrets/<auto-name>`, then the entry with `_ref`. A failure in between leaves at most an unused secret, which the page lists.
- **Every "?"** has a help topic.

**10. What this amends.**
- **ADR-045:** the channel rule covers file secrets only, and its OIDC implementation note is corrected.
- **ADR-048 and OPS-005:** secret writes are allowed under GitOps authority.
- **ADR-049:** references by name.
- **ADR-063, API-007:** section 8.
- **ADR-069:** credential fields of alert destinations follow section 2 rule 1.
- **ADR-116 and CLU-013:** secrets are not configuration versions; pins and rollouts don't gate them.
- **ADR-120:** "key files at the same paths" or a stored secret. Stored-credential routers poll on the primary.
- **ADR-125:** confirmed for stored-credential routers.
- **ADR-156:** the credential table moves to `telltale-config`, and `*_ref` fields are class `name`.
- **T9.6:**
  - The criterion becomes "secret values pass only through `/api/v1/secrets`".
  - `config:write:alerts` no longer covers credential or destination fields of a destination that has a credential, so those `plan_*` alert changes get 403.
- **Also:** the comment at `config_api.rs:656-657`; spec/08 §3.3, §6 and §8; spec/12 §4 and §6; spec/13 §3.

**New direct dependencies.** No new crates are added.
- `zeroize` becomes a direct dependency of `crates/telltale`. It is already in the lock through RustCrypto, and it is needed for `SecretValue`.
- `argon2` becomes direct there too, for `backup.rs`. It is already linked through `telltale-api`.

**Alternatives rejected:**
- **Reusing `managed` for values:** every copy path would carry them.
- **A shared cluster key, `privacy.key` or the CA key:** one node's compromise would expose everyone's, and decision 2 says per-node keys.
- **Values as content-addressed blobs:** replicas write blobs to disk.
- **The secrets head in `ClusterManifest`:** every secret write would become a configuration version, gated by pins and rollouts.
- **Deletion by absence:** one primary that can't read its rows would wipe every replica.
- **A plain per-node counter as the version:** it goes backwards after failover.
- **Router secrets only on the polling node:** that breaks when the primary moves, and the owner chose replication.
- **Every full member polling every stored-credential router:** ADR-125 rejected it.
- **Secrets on ephemeral pods:** decision 1.
- **Upstream refs now:** pods answer most queries and would lack the value.
- **`*_secret` suffixes, or `*_file = "secret:<name>"`:** awkward names, overloaded paths.
- **Values in entry bodies:** that is the general write path again.
- **Plain HTTP allowed silently:** the value would cross the network in clear.
- **`env_clear()` for plugins:** it breaks plugins that need `PATH` or proxy variables. `env_remove` of the named variables plus admin-only `exec://` covers the risk, since a same-user process could read `secrets.key` anyway.
- **Argon2 at m = 64 MiB inside the DNS process:** it competes with NFR-001's working set.
- **The `chacha20poly1305`/`aes-gcm` crates:** `ring` already provides the cipher. **AES-256-GCM:** slower on a Pi.
- **MCP write tools, or operator role for secret writes:** both are exfiltration paths.
- **UI-made OIDC providers and sinks kept node-local:** each node would need its own write route, against the single management plane.

**Consequences:**
- **Who benefits.** Home and Pi users can run routers, alerts, Git, sinks and OIDC from the UI. File and Kubernetes Secret setups behave as before and win.
- **Timing.** A secret set on any node reaches every full member within one heartbeat plus one RPC. Resolver pods still need `*_file` mounts for sinks and OTLP.
- **Behavior changes** (T23.2):
  - Operators and agents can no longer change `*_file` paths, credential-bearing destinations, or `exec://`/`unix://` upstreams.
  - Existing API-set file paths outside `secret_file_dirs` stop being read.
  - Stored-credential routers poll on the primary only.
- **Mixed versions (CLU-010).** As with quick rules, an N-1 replica refuses a configuration version that uses a new `*_ref` or `tls_ca_pem` field, and keeps its last good version until it is upgraded. An API write that adds one warns, naming the older members. Credential-affecting writes forwarded by N-1 replicas are refused.
- **Plain HTTP.** Secret entry over plain HTTP from another host is refused unless `[api] allow_secrets_over_http` is set.
- **Helm.**
  - The default key lives in the data directory.
  - `secretsKey.existingSecret` is recommended.
  - `secretsKey.generate=true` (Helm `lookup`) is documented as unsafe under `helm template` or Argo CD.
  - With persistence off, stored secrets are lost at every restart, and the health reason `secrets_ephemeral` says so.
- **Unchanged:** the query path, and the crate list. Image growth is limited to 0.10 MiB for the milestone, recorded per task.
- **Old audit entries.** Entries written before T23.1 may hold upstream headers and can't be rewritten (hash chain). The release note says so.

**Owner decisions on the open questions (2026-11-16):**
1. The admin-only credential rules (T23.2) ship right away, with T23.1, not with the UI.
2. Upstream credentials (`headers`, `tls_client_key`) stay file or inline only, redacted everywhere; no task sends secrets to resolver pods.
3. OIDC providers and sinks made in the UI reach every full member as node-managed configuration; providers and sinks defined in files stay per node.
4. Entering a secret over plain HTTP from another host is refused unless `[api] allow_secrets_over_http = true`.
5. Agents get no write scope for router or `[identify]` fields for now (admin-only, as above). Revisit after T23.8.
6. Audit entries written before T23.1 stay as they are (the hash chain forbids rewriting); the release note warns about them.

**Implementation notes (T23.1, 2026-11-16; Proposed, for the owner):**
1. **Sites with nothing to redact.** `apply_ack` audits finding IDs and a count, never a configuration body, so it is unchanged. `compare.rs` (`GET /cluster/compare`) carries only numbers and node labels. The surfaces that do carry shared configuration are the pin and version diffs (`rollout/surface.rs`, also the 409 `cluster_pinned` body): both sides are redacted before the diff. `GET /upstreams`' `endpoint` goes through the URL redaction too.
2. **Checks and markers.** "Checks never resolve markers" is implemented as a refusal: `POST /checks/upstream` with `<redacted>` at a credential path is 422 `credential_reentry_required`, so a check never runs with a literal marker as a header.
3. **Destination comparison.** Absent, `null`, `""` and `[]` count as the same value; URLs are compared with their passwords replaced by the marker, so a changed user name or host is a changed destination. A URL's user information runs to the last `@` before any `?` or `#` (conservative: a stray `/` in a password is still redacted).
4. **The node key in T23.1.** `telltale::secrets` loads the key at start on full members, in a blocking task (DNS never waits for it). With no `secrets` table yet, the data-directory key is made whenever it is missing; T23.3 adds the empty-table condition and the locked state. A key file with any "other" permission bit or group write warns; the owner check needs the process's uid (no `libc` in the binary) and is left to T23.3. `zeroize` isn't used yet (it becomes direct in T23.3).
5. **Idempotency without a key.** With the key unavailable, a write carrying `Idempotency-Key` and a credential is 503 `secrets_locked` (the code is added now); one without a credential keeps a plain BLAKE3 of the request, which holds nothing secret.
6. **Delivery errors.** Besides percent-encoding the Gotify token, an HTTP error that quotes the request has the token replaced by the marker.
7. **Release notes.** `deploy/release/notes/v0.8.0.md` is started as a draft with the upgrade items (older audit entries, the purge, the new key), and `preflight.sh` refuses notes whose first line begins `_Draft`.

**Implementation notes (T23.1 review fixes, 2026-11-16; Proposed, for the owner):**
8. **Every URL field.** §4's table names three URL fields; the support package classes eleven more `url` (`upstream[].relay`, `list[].url`, `router[].url`, `cluster.git.repo`, `cluster.join_url`, `telemetry.otlp.endpoint`, `telemetry.ship.to`, `telemetry.sink[].url`, `updates.index_url`, `auth.oidc.public_url`, `auth.oidc.provider[].issuer`). All are in `PATHS` as URL passwords, and the completeness test now also fails for a `url`-class field missing from it. `list` is an entry kind for redaction and the marker rule, and `POST /checks/list` refuses markers like the upstream check. A URL that sends the marker keeps its password only while that URL itself is unchanged (it is replaced whole by the stored one), so a field that isn't a destination (`relay`) can't carry a stored password to a new host. The Cluster page's `repo` (and a Git error quoting it, and the `config.git` audit entry), `GET /lists`' `source` and fetch error (the walk found it once a list URL was planted), and a router's errors are redacted too.
9. **Markers and an N−1 primary.** A replica forwards a body that sends `<redacted>` back only to a primary whose advertised version is at least 0.8.0 (`forward::MARKERS_SINCE`); otherwise 409 `upgrade_required` (a new code, which T23.2 reuses for role-less forwards). A primary whose version is unknown counts as older. Resolving markers on the replica instead was rejected: the replica's copy can lag the primary's and would restore an outdated value.
10. **Plans.** `Plan.body` is shown redacted (`GET /plans`, `list_plans`, approve and reject); the body `apply_plan` replays is kept apart (`write_body`, never serialized). `telltale-api` now depends on `telltale-config` for the table (a workspace crate, no new dependency).
11. **Pin diffs.** Both sides are redacted before the diff; a credential that changed while reading the same redacted (a header's value, only a URL's password) is added as a `replace` with the marker as its value, so a pin that holds back only a credential change still shows one.
12. **Smaller points.** `keepInGit` text from an older primary that doesn't parse is replaced by its leading comments and a note, never passed through. A body whose credentials are all markers holds no credential (no 503 `secrets_locked` for it). A failed key load is retried after 30 s instead of kept until restart. `secrets.key` is written to `secrets.key.tmp` (`O_EXCL`, 0600, fsync), hard-linked into place (no replace), and the directory synced. The Gotify token is scrubbed from errors in its percent-encoded form too. Plugins inherit no `TELLTALE_*` variable but `TELLTALE_PLUGIN_SOCKET` and `TELLTALE_UPSTREAM` (environment configuration can carry credentials); the self-update keeps the named list, since the restarted server needs its own settings.

**Implementation notes (T23.2, 2026-11-16; Proposed, for the owner):**
13. **Credential files.** `alerts.destination[].token_file`/`password_file` and `upstream[].tls_client_key` (§1 classes the client key a secret) are the credential files: changing one is admin-only and an API-set one must be under `[node] secret_file_dirs`. `tls_ca`, `tls_client_cert` and `list[].path` get the denied places only. `credentials::API_PATHS` lists them, and `api_014_api_paths_cover_path_fields` holds it to the support package's path-like fields of those kinds.
14. **"Stops being read".** Done where the API's entries are merged (`managed::merge`, on the primary or a standalone node): a refused path is replaced by `/proc/telltale-refused/<field>`, where nothing can be read, so the list or alert fails as with a missing file (an upstream's is cleared instead: note 22). It is judged by that node's settings, and replicas receive the result with the shared configuration. A path an override keeps from the files' entry of the same name is the files' (an operator editing a file-defined email destination doesn't break its `password_file`). At write, only paths that change are checked; stored ones are judged at use. `credential_issues` is shown now as `ConfigEntry.credentialIssues` (and a warning at each reload); the heartbeat field (T23.5) and `GET /secrets`' `credentials` (T23.4) reuse `credential_rules::issues`.
15. **Redirect audit and alert.** Until `*_ref` exists (T23.3), `credential.redirect` covers an admin's destination change of any entry that holds a credential (a header or argument, a URL password, a credential file), not only one with a `_ref`; "a `_ref` pointed at a secret of another kind" comes with T23.3. The record is made where the change is applied (so a forwarded one gets it on the primary), with the user as a `system` actor, beside the usual `<kind>.put`; the dry run warns. `AlertWhen::CredentialRedirected` (`credential_redirected`) reads the last hour of those records, once each (a one-off condition). As with any new condition, an N−1 replica refuses a configuration version whose rule uses it.
16. **Programs.** Besides creating or switching to `exec://`/`unix://`, changing an existing plugin's `url` or `args` is admin-only (they are what runs); its weight or timeout stays an operator's. A forwarded domain's servers become upstreams, so an `exec://`/`unix://` server there is admin-only too (it was a way around the rule). `POST /checks/upstream` with a `tls_client_key` is admin-only as well, and a draft's paths are confined (the check reads them).
17. **Role-less forwards.** "Credential-affecting" is: any admin-only change, or an entry that holds or would hold a credential. Other writes from an N−1 replica still apply, so a rolling upgrade keeps working for them. A new replica forwarding to an N−1 primary isn't refused for these rules (the older primary never checked them; upgrading the primary first is already the advice).
18. **Who counts as admin.** The admin role and no agent token: an agent token is never admin here, even with `cluster:admin` and an admin owner (§3's threat model). The marker rule's 422 comes before the role rule's 403. Problem codes: `path_not_allowed` (422) is new, and `upgrade_required`'s title becomes "Upgrade needed" since it now also names an old replica.
19. **Paths.** Absolute only, no `..`, compared after following every symbolic link, a dangling one included (followed by hand, so a link can't wait for its target). The denied files are `[node] secrets_key_file` and `secrets_previous_key_file`, `[cluster] bootstrap_secret_file`, and `listen[].tls.key` and `[api] tls.key`; the data directory covers `secrets.key`, the cluster's certificates and `state.db`. `[node] secret_file_dirs` is read from this node's files and environment (`node` never leaves a node). The check is at write and at each reload, on the resolved path, but the configured string is read: a link swapped between reloads is followed (note 26).
20. **UI.** `ConfigEditor` fields take `admin` (always, or decided from the entry as read); the Alerts page shows the token and password files to operators read-only, and the address and CA once the destination holds a credential. Rows with a refused path show "<field> not read". The Upstreams page isn't marked yet (the API refuses the same changes with a 403 that names the field).

**Implementation notes (T23.2 review fixes, 2026-11-16; Proposed, for the owner):**
21. **Destination fields.** §4's list (`url`, `proxy`, `host`, `tls_server_name`, `tls_ca`, `bootstrap`) gains `tls_insecure_skip_verify` and `spki_pins` (turning certificate checks off, or swapping the pins, sends the credential to whoever is on the path, which is worse than a new CA) and an alert destination's `type` (it changes how the credential is sent). They count for the admin-only rule and for the marker rule alike; absent and `false` are the same value.
22. **Refused upstream paths (CLU-004).** Note 14's `/proc/telltale-refused/<field>` is kept for alert destinations and lists, which read their files when used. An upstream reads its TLS files when the router is built, and one it can't read fails the whole configuration (the node would start answering nothing, on every replica that restarts). So a refused `tls_ca`, `tls_client_cert` or `tls_client_key` of an upstream is cleared instead: the upstream runs on the system's roots, without a client certificate (its certificate and key are cleared together, since one without the other doesn't validate). No refused file is read and no credential is sent anywhere new; an mTLS server refuses the connection, and the group fails over. Dropping the upstream was rejected: it would empty groups (invalid) and drop routes.
23. **Paths that aren't a credential's.** `tls_ca`, `tls_client_cert` and `list[].path` may not name a credential file this node's own configuration uses (an upstream's client key, an alert destination's, router's, sink's or OIDC provider's file, the Git credentials and webhook secret), and a list's `path` may not be under `secret_file_dirs` (a secret that parses as a name becomes a rule `GET /explain` confirms, and a line that doesn't is quoted in the list's error). A CA or client certificate may still sit in a secrets directory, beside its key. `/var/run/secrets/kubernetes.io` (and `/run/secrets/kubernetes.io`) is denied for every API path, admins included: the default `secret_file_dirs` covers it, and the pod's service-account token is never a file an entry should read. The default directories are unchanged; denying the subtree is the conservative reading of the ADR's default.
24. **A promoted primary.** A primary promoted from replica builds on the last cluster version (ADR-051), so "the files' entry of that name" is judged against the node's own files (`managed::merge_on`), not that version: a path an older primary published as the API's is judged, not taken for the files'. Writes already compared against the node's own files (`Sources::file_config`).
25. **Deviation: replicas don't judge again (for the owner to accept).** §4 says paths are checked at write and at use. Here the node that merges the API's entries (the primary, or a standalone node) judges them with its own rules, and a replica uses what it receives: the shared configuration doesn't say which entries the API made, so a replica can't tell an API path from one in the primary's files (which are never confined), and judging every path there would break file-defined ones. A path that is fine on the primary can thus be in a replica's own data directory or key file when the two differ. Closing it needs the version to carry which entries are the API's; proposed with T23.5 (heartbeats carry `credential_issues`).
26. **Smaller points.** The `credential_redirected` alert names only the new address's scheme and host (a URL's path can hold a secret, and the alert goes to every destination of the rule); the audit record keeps the rest. The alert reads the last hour of the applying node's audit log, so a change applied just before a failover isn't alerted by the new primary (documented). A path is resolved and checked, but the configured string is what's read later, so a symbolic link swapped between reloads is followed; only someone who can write a secrets or listed directory can do that, which is outside §3's threat model (note 19).
27. **T23.2 is ticked with AC7 and AC8 open**, as T23.1 was: the Playwright test is written but hasn't run (no browser in the dev container), and no image was built to record the size delta. AGENTS.md rule 10 says done means the criteria pass in CI; the owner accepts the tick, or it is unticked until CI has run both.

**Implementation notes (T23.3, 2026-11-16; Proposed, for the owner):**
28. **One store per process.** `telltale::secrets::SecretStore` is made at start without I/O, loaded in a blocking task, and retried every 30 s while locked (a key mounted later unlocks it without a restart). It also owns T23.1's key slot, so the idempotency hashes and the store use the same key, and "made only for an empty table" covers both. A configured key that can't be read leaves no key for the idempotency hashes either (503 as before).
29. **The replica's self-heal** runs from that upkeep when the cluster says this node is a replica and the store is locked, only for the data-directory key (an unreadable `TELLTALE_SECRETS_KEY` or `secrets_key_file` is whoever configured it to fix, and generating beside it would hide the mistake) and only when every row is `origin='cluster'`. It drops the rows and starts over with a working key; fetching them again is T23.5's.
30. **`secrets_ephemeral` needs to be told.** A node can't tell an `emptyDir` from a volume, so the chart sets `TELLTALE_DATA_EPHEMERAL=1` (a reserved variable, not a configuration key) on the controller when `persistence.enabled` is false; any other deployment may set it. The reason shows only while secrets are stored, so a fresh install without persistence isn't degraded.
31. **The read sites.** `Credential::resolve` (inline first, then the file, then the reference: the files win even if a merge somehow kept two) replaces the routers' reads (UniFi, OPNsense, Home Assistant), alert tokens and email passwords, sink tokens, the Git credentials and webhook secret, and the OIDC client secret; OTLP `header_refs` are resolved per request. The cluster bootstrap secret (`telltale-cluster/src/net.rs`) keeps its plain file read: §1 makes it status only, and it lives in another crate.
32. **"The files win" at write and at merge.** §2's rule 1 is implemented for alert destinations, the only API kind with a stored field so far: an override that leaves a file-set credential out has it carried over; one that sets, replaces or removes it is 409 `set_by_file`; a `DELETE` that would hide a file-defined destination with a credential is refused too (the ADR's "a hidden entry"), a behavior change named in the release note. At merge, a file-set credential replaces whatever an override stored for it (an override saved before the files set it), so the merged entry keeps one source per field. The router, OIDC provider and sink kinds reuse `secret_refs::carry_file_credentials` when they arrive (T23.7, T23.10, T23.11). The file layer judged is this node's own files, as T23.2's paths are (note 24).
33. **References at write.** A `_ref` naming a secret this node doesn't store is 422 `secret_missing` (new code, with `set_by_file`). A `_ref` changed to a secret that an entry of another kind references in the effective configuration is audited as `credential.redirect` with `secretUsedBy` (note 15's deferred case); the alert names the field and the secret's name.
34. **Rotation.** `telltale secrets rotate-key` refuses while the data directory's lock is held (as `backup restore` does), re-encrypts the rows readable under the old key (others are left as they were and counted), and `recover_rotation` decides a leftover `secrets.key.new` by whether any row is under its `key_id`. Re-encryption keeps each row's stamp and takes a new nonce.
35. **Recovery gap (a decision for the owner).** A store locked because none of its rows decrypt, and holding rows made on this node, can't be cleared: §3 refuses every secret write while locked (deletes included), and no command discards unreadable rows. The conservative reading is kept (nothing is ever discarded on its own); `docs/secrets.md` says to keep a copy of the key. Proposed: an offline `telltale secrets forget --unreadable`, or letting T23.4's `DELETE /secrets/{name}` remove an unreadable row while locked.
36. **Helm's generated key** is `ttsk1:` + `randAlphaNum 42` + `A`: the last character keeps the trailing bits zero, as the decoder requires, for about 250 bits of entropy. The Secret keeps `helm.sh/resource-policy: keep`, and its file is mounted 0440 (group read through `fsGroup`, which the key check doesn't warn about).
37. **What isn't wiped.** `SecretValue`, the node keys and their subkeys are wiped on drop; copies handed to code that wants a `String` (the OIDC provider settings, the SMTP login) aren't, beyond §2's stated limit; the UniFi login body and the OPNsense key pair are. The metric is `telltale_secrets{state="readable|unreadable|corrupt"}`; the store's own state is in health, not a gauge.
38. **T23.3 is ticked with AC14–AC16 open**, as T23.1 and T23.2 were: the Helm template test is written and in CI but wasn't run (no `helm` in the dev container), `cargo deny` wasn't run (no `cargo-deny`; `Cargo.lock` gains no package), and no image was built for the size delta. `argon2` is a direct dependency as the task lists, but nothing in the binary crate uses it until T23.9.

**Review fixes (T23.3, 2026-11-16; Proposed, for the owner):**
39. **Associated data, `status`, and the key's edges.** (a) §3's associated data had no boundary between `kind` and `name`: the row (`text`, `x`) gave the same bytes as (`tex`, `tx`), so someone who can write `state.db` without the key could move a ciphertext to another name and have it decrypt. `kind` and `name` are now each preceded by their be16 length, and `open` treats a kind other than `text` or `pem` as corrupt. No value was stored under the old form (the write API is T23.4), so nothing needs migrating. (b) `telltale secrets status` writes nothing: it doesn't finish or drop a leftover `secrets.key.new` (a `rotate-key` running beside it would otherwise lose its new key, and every secret with it), doesn't re-encrypt, and creates no database; it reports the leftover file and counts rows under the previous key as readable. (c) `rotate-key` also refuses when the data directory's lock can't be taken at all (whether the server runs is then unknown). (d) A `secrets_previous_key_file` that no longer exists is a warning, not a locked store: the docs say to remove the previous key after rotating, and §3 locks only for sources 1 and 2. A previous key that exists but can't be read or parsed still locks (conservative). (e) The owner check (note 4's deferral): the process's uid is the owner of `/proc/self` (no `libc`); a key owned by another user warns, root excepted (it can read the file anyway, and kubelet's Secret mounts are root's), a slightly less strict reading of §3. (f) The replica's self-heal clears rows only when a new key fixes the lock (`secrets.key` missing, or none of the rows decrypts), not for a key file or database that can't be read.
40. **Locks and blocking.** `SecretStore::configure` took the settings' lock and then the store's, while a load holds the store's and then reads the settings: a reload that changed the key settings during a load hung both, and with them health, metrics and the API (CLU-004). `configure` now takes only the settings' lock and marks the store stale; the next use loads again. A reload's missing-reference warning runs in a blocking task. Left as it is: an API request that finds the store due for a retry (the `secret_missing` check, idempotency) loads it on that request's thread, at most once every 30 s while locked; health and metrics never load.
41. **Smaller points.** `wal_checkpoint(TRUNCATE)` reports whether it finished; when another connection kept it busy past the 5 s timeout, the server logs a warning and `rotate-key` prints a note (ciphertext may stay in `state.db-wal` until a later checkpoint). The `Idempotency-Key` 503 applies when the key itself can't be read; a key that opens none of the rows still keys the retry records, so a store locked that way doesn't refuse them (the docs say so; §4 is read that way). `<redacted>` is refused at load at every credential path (`credentials::PATHS`), URL passwords included, the error naming the field. A body that sends `null` or `""` for a credential key the files set is 409 `set_by_file`, not carried over. The backup still drops the `secrets_stamp` counter with the table (§8 keeps the store out of backups): a restored node starts its stamps again at (epoch, 1), which relies on T23.5's epochs and T23.9's re-stamping. The UniFi key and session cookie are wiped after a poll. `backup restore` still goes on when the data directory's lock can't be taken (outside T23.3; worth the same refusal).

**Implementation notes (T23.4, 2026-11-16; Proposed, for the owner):**
42. **Status codes.** A value, kind or name the rules refuse, and a 129th secret, are 400 `invalid_parameter` (T23.3's `StoreError::problem`), not 422: nothing about the configuration is invalid. Three codes are new: `insecure_transport` (403), `agent_not_allowed` (403) and `secret_in_use` (409). A primary without its lease and an emergency primary answer 409 as §4 says (entry writes answer 503 for a lapsed lease); dry runs are held to the same, and to the locked store (503).
43. **`set_by_file` on a secret write.** §4 lists it without saying when. Read conservatively: a `PUT` of the name the UI gives a credential (`<kind>.<entry>.<field>`, lowercased, `header:` as `header.`) is refused when this node's files set that credential inline or by file, since the secret would never be used. Any other name is accepted. The check reads the files of the node that applies the write (the primary): a replica's own file-set credentials (`auth.oidc`, `[cluster.git]` are node-local) aren't seen when it forwards (review of T23.4; proposed: the forwarding replica checks its own files first, or T23.5's heartbeats carry them).
44. **The webhook rule** (16 characters) applies when a `webhook_secret_ref` in the configuration names the secret at write time; a reference made later to a shorter secret isn't checked (a load warning could; proposed with T23.12). Like note 43 it sees the primary's references only: a replica's node-local `webhook_secret_ref` isn't consulted for a `PUT` (peers' references are fetched for deletes only); the same proposal covers it.
45. **`?force` and references.** `force` only goes past members whose references can't be read (offline, older, or not answering within 2 s); a known reference refuses even with it. A shared-configuration reference that a lagging member still holds counts too (conservative).
46. **References across nodes are asked at delete time.** Until heartbeats carry `secret_refs` (T23.5), the primary asks each full member of its registry (`!ephemeral && !witness`) over `api.read` (`Read::SecretRefs`); a node-local reference names its node. T23.5 switches this to the heartbeats' union.
47. **Transport.** "From loopback" is the connection's peer being a loopback address (`::ffff:127.0.0.1` from a `[::]` listener too) with no `X-Forwarded-For`/`Forwarded`/`X-Real-IP` header (a request a local proxy forwarded from afar isn't). `X-Forwarded-Proto: https` counts here only from a peer listed in `[api] trusted_proxies`; unlike `is_https`, loopback isn't implied, since a plain-HTTP proxy or relay on the same host would pass a remote client's header through (review of T23.4). A TLS proxy on the same host is listed as `127.0.0.1/32`. Reads aren't held to it (they carry no value). `[api] allow_secrets_over_http` is read from the node's files at each request (node-local, no restart). In-process MCP calls have no peer address, so they'd need HTTPS; there is no MCP write tool anyway.
48. **The head as an ETag** is `<epoch>.<seq>.<first 16 hex digits of the digest>`, sent on reads and write answers; `If-Match` takes it (412 `version_conflict`). The idempotency record of a `PUT` is `PUT /secrets/<name> kind=<kind> ` and the keyed BLAKE3 of the trimmed value (the kind included, so another kind with the same key is 409); an empty `Idempotency-Key` is no key; a `DELETE`'s is its request line (`?force` included), which holds nothing secret.
49. **Replicas and `GET`.** A replica shows the primary's list and head, with its own store, credential fields, node-local references and its own row per secret; without the primary (or with one too old to answer) its own view with `stale: true`. `nodes` lists only the nodes that answered until T23.5's heartbeats; replicas hold no rows yet, so a stored secret is the primary's only and integrations elsewhere report it not set.
50. **Forwarding.** The value crosses the cluster channel in the JSON body of `secret.put` (mTLS); the replica serialises it into one buffer sized up front (so it isn't reallocated) and moves that buffer into the call; from there the channel's buffers, like the HTTP and JSON layers' copies on the way in and `ctl`'s request body, aren't wiped (§2's stated limit; only buffers TelltaleDNS keeps are). The primary takes it only from a full member of its registry, checks every rule again, reads its epoch under the role-change lock (`Cluster::primary_epoch`, new in `telltale-cluster`: Primary with its lease) and stamps and stores the row after releasing it, so no SQLite write or fsync runs under the lock role changes take (a step-down in between leaves a row of the old epoch, which the new primary's epoch outranks: §2's orphans, the argument `publish_as` makes), and audits `<user> via <node>`. An older primary answers "unknown call": 409 `upgrade_required` naming its version.
51. **Agents.** `agent_not_allowed` covers `PUT`/`DELETE`/`POST` on `/api/v1/secrets*`, `POST /api/v1/backup` and `POST /api/v1/checks/router*` before any scope is looked at (the last two don't exist yet; the rule is in place for T23.7 and T23.9). Reading needs `config:read`; operators read too, viewers don't.
52. **Mixed versions** (T23.3's deferral): a write that adds a `*_ref` the entry didn't have warns, naming the members older than 0.8.0. Only alert destinations take references through the API so far.
53. **Not done here.** Note 35's recovery gap stays: a locked store refuses `DELETE` too. The image size delta (AC17) isn't measured (no image build here; one direct `zeroize` edge in `telltale-api`, no new crate in `Cargo.lock`).

**Merge review fixes (M23, 2026-11-16; Proposed, for the owner):**
54. **Amendment to §4: URL user names and secret query values (Proposed).** §4 replaces a URL's password with the marker and keeps the rest of the URL. Read literally, that leaks a token used as the user name (`https://ghp_…@github.com/org/repo.git`) and a list URL's token in its query (`https://lists.example/ads.txt?token=…`), which reach `GET /lists`, MCP reads, `ctl`, replica reads, Git audit rows and config entries. Proposed: a URL without a password has its user name replaced by the marker, and the values of query parameters named `token`, `key`, `apikey`, `api_key`, `access_token`, `auth`, `sig`, `signature` or `password` (names compared without case) are replaced too. A URL with a password keeps its user name as before. Round trips stay as §4 has them: a URL that sends the marker keeps its stored value while its destination is unchanged. The support package's `Url` class already drops the path and query.
55. **Idempotency record of `POST /lists/refresh`.** The record keeps the keyed fingerprint (`idempotency_request`) like the configuration writes, not the request text (§4).
56. **Primary's `GET /lists`** passes through the same redaction as a replica's read (`redact::lists`), so a URL written or normalised differently from the configured one is covered too.
57. **List fetches never send user information.** A list URL with `user:pass@` is refused as a fatal fetch error (the URL is not quoted); `Host` carries the host and port only. Basic auth isn't built, as no base64 dependency is wanted for it.
58. **Open serialization (OPS-014).** `State::open` runs its setup under a process-wide lock and sets the busy timeout first; `journal_mode=WAL` is retried on busy with a bounded backoff (50 × 20 ms), since SQLite doesn't always run the busy handler for it.

## ADR-902 — More naming sources: UniFi reservations and networks, Home Assistant through a template, and a fixed order when sources disagree (Accepted 2026-11-16)
**Context:** T22.2, T22.3 (API-012, API-013). ADR-080 left UniFi's offline known clients undone; Home Assistant knows curated names for IoT devices (by MAC, not IP); a home has a router *and* Home Assistant naming the same address. ADR-080's lease view kept whichever router was read last (a `HashMap` walk).
**Decision:**
- **UniFi:** after `stat/sta`, read `rest/user` and `rest/networkconf` with the same key or session. Only known clients with `use_fixedip` and a `fixed_ip` are kept (a last address may belong to someone else by now); a connected device's current address wins over its reservation. Networks: the ones with an `ip_subnet`, not WAN or VPN; the subnet from the gateway's address and prefix; the VLAN only when enabled; the pool only when DHCP is on. Both reads are optional: refused or failed, the connected clients still name devices, and one log line says what was skipped (again only when that changes).
- **Home Assistant** (`type = "home_assistant"`, `api_key_file` = a long-lived access token): its registry has no REST endpoint, and a WebSocket client would be a new dependency in the binary. One `POST /api/template` renders a fixed, read-only template (every device with an entity and a `mac` connection: `name_by_user`, `name`, its MACs, its area; every `device_tracker` with `mac` and `ip`). Rendering templates needs an administrator's token; the error says so. Addresses: the routers' answers for that MAC, else Home Assistant's trackers; a device with no address is skipped. Routers are polled before Home Assistant in each round so its devices find this round's addresses.
- **Order when two sources name one address:** a name a person gave in Home Assistant (`name_by_user`) → the routers' names, in `[[router]]` order → a Home Assistant integration's name (often the model: `Shelly Plus 1PM`). A better source without a name doesn't hide a worse one's. Each lease records the `[[router]]` that named it (`router`, optional in the peer wire form, so N-1 peers interoperate).
- **Networks API** is read on the node that reads the routers, like the leases (not federated). Agent tokens read `GET /api/v1/dhcp/leases` and `GET /api/v1/networks` with `config:read` (the inventory is no more sensitive than `/clients`, which already needs it).
**Alternatives rejected:** a WebSocket client for Home Assistant's registry (a new dependency on the binary for one read); Home Assistant's names always winning (its integrations' default names are model names, worse than a router's alias); known UniFi clients without a reservation (stale addresses would name the wrong device in DNS, T22.1).
**Consequences:** two more GETs per UniFi poll; one template render per Home Assistant poll (sub-second on a few thousand entities); names in the query log and DNS can now come from Home Assistant.

## ADR-901 — Device names in DNS: built off the path from the names TelltaleDNS already has, after configured data, one label each (Accepted 2026-11-16)
**Context:** T22.1 (DNS-023). People want DNS kept in step with DHCP leases (dnsmasq's and Technitium's DHCP do it) but ADR-091 keeps DHCP with the router. TelltaleDNS already holds the routers' leases, Home Assistant's names, mDNS names, and named devices, by address.
**Decision:**
- **Off by default.** `[local] device_domain` turns it on (`home.arpa`, RFC 8375, in the docs); `local` is refused (RFC 6762). `device_ttl` 60 s (names follow DHCP). mDNS names only with `device_mdns` and the listener on.
- **Sources and their order for an address:** a named device matched by exactly that address or by the lease's MAC (a CIDR client names a set of devices, so never) → a router's or Home Assistant's name (ADR-902's order) → an mDNS name; this node's routers first, then the peers' (CLU-002).
- **One label per name:** lowercase ASCII letters, digits, and hyphens, at most 63 bytes; apostrophes dropped, everything else separates words. No punycode: a name with no ASCII letters or digits is skipped.
- **Reserved labels:** `wpad` and `isatap` (how Windows finds a proxy and an IPv6 tunnel: a device that names itself so could take over other machines' traffic; dnsmasq and Windows DNS's global query block list refuse them) and `localhost` are never device names.
- **Collisions:** one label, one address: the better source, then the lower address, keeps it; the others get neither A nor PTR (half-registered names would point the PTR somewhere the A doesn't). Counted in the log line for each change.
- **Where it answers:** after `[[record]]` and hosts files, after a zone's own records, before the zone's NXDOMAIN or NODATA; never filtered, like other local data. An unknown name under the domain falls through as before (a route may send the domain to the router).
- **On the path:** a `LocalData` (the same allocation-free lookup as local records) behind an `ArcSwap` on the pipeline, rebuilt by a task every 10 s only when its inputs changed. The query path checks `Policy::device_dns` first: off, one branch; on, one lock-free load and the usual empty-map early return.
**Alternatives rejected:** a zone generated into the configuration (the configuration is signed, versioned, and replicated; leases change every few minutes); RFC 2136 dynamic updates from the router (UniFi doesn't send them); rebuilding on every lease change (the routers are read every few minutes; 10 s is soon enough and bounded).
**Consequences:** names appear within about 10 s of a router read; renaming a device in TelltaleDNS renames it in DNS; the PTRs make reverse lookups of private addresses answer for named devices (RFC 6303's NXDOMAIN still applies to the rest).
## ADR-172 — A cluster support package: each node redacts its own part under one key, with labels every node agrees on (Accepted)
**Context:** GitHub issue #55 (the later phase of #50, ADR-156): in a cluster the problem is often on another node, and a package of the node that answered covers only that one. ADR-156 settled the direction (each node redacts before its data leaves it, the asking node's key travels over the mutually authenticated stream) and left three points: how the key reaches the others, what an older peer does, and the size cap across nodes. One more came up in building it: ADR-156 numbers a name by when it is first met (`device-3`), so two nodes would give one device two labels, and the issue asks that a device have one name on every node.
**Decision:**
- `POST /api/v1/system/support-package` takes `cluster: true`; `telltale support-package --cluster`; a checkbox on the System page. It is the node that was asked that puts the package together. Admin only, no agent scope, no MCP tool, like the single-node package.
- That node makes a random 256-bit key for the package and sends it in a new read (`SupportCollect`) over the cluster stream to every reachable member. The key is held in memory for the call and never stored or logged. A member that is ephemeral (a resolver pod) may be asked but may not ask: the key lets its holder undo the address permutation, so only a member the cluster trusts with more than reads may hold one.
- Each node makes its normal package (collectors, redaction, classification, the same limits) under that key, but with **keyed labels**: a name's label is `device-` and eight hex digits of a keyed hash of the name (a few more if two names land on one label), not a number by first encounter. The same name is the same label on every node, in any order, and under another key it is another label. Addresses and MAC addresses were already a keyed permutation. A single-node package keeps its numbers.
- A node sends back its **part**: its files as text, its manifest, and the counts, gzip-compressed JSON. The cluster channel carries about a mebibyte per answer, so the node cuts its largest files until the compressed part fits 1,000,000 bytes (the manifest says what was cut), and the asking node reads it with a limit on the unpacked size.
- The asking node puts the parts side by side (`nodes/<node>/...` with each node's own `MANIFEST.json`) under a summary `MANIFEST.json` (`kind: cluster`) and a README. The size cap is the single-node 20 MiB divided into equal shares, one per reachable member; a part over its share, or a file whose path is not allowed, is left out and said so. A node that doesn't answer (45 s), is older than this feature (it doesn't know the read, so it answers an error), is busy making another package, or has no open stream is listed with a **fixed reason**: nothing a peer says is copied into the package. Real node names appear only at the `none` level; otherwise the asking node names a missing node with the same keyed labels.
- No pseudonym map: the names are replaced on the nodes they belong to, and a map would have to carry them over the network, so `keepMap` with `cluster` is refused (400) and `--keep-map` with `--cluster` is an error.
**Alternatives rejected:** numbering by first encounter and renaming at the asking node (the asking node would hold every node's names, which is what the design avoids); sending each node's data to the asking node to redact (the unredacted data would cross the network); a map the asking node assembles (same); a separate large-transfer channel for parts (the cap and the compression keep a part under a mebibyte, and a node that can't fit is listed, not hidden).
**Consequences:**
- A cluster package is made with one request, and a device reads the same in every node's files. The labels are hashes, so they say less about order than `device-3`; the manifest and README explain them.
- Two different names that hash to one label get different labels on the node that sees both, but another node that sees only one of them may give it the shorter label: a rare ambiguity, harmless to reading.
- An older node is listed as missing until it is upgraded; a rolling upgrade gives a partial package for a while, and says which nodes.
- Each part is redacted the same way a single-node package is (best effort for free text), and the README says so.
**Verification:** pure tests in `telltale-support` (labels the same in any order and under one key, different under another; a part survives the wire and a damaged or oversized one is refused; a part is cut to fit; the package lists present, missing, and over-share nodes; paths that escape a node's folder are refused; two nodes with one name get two folders), the request checks, and the existing single-node package tests unchanged.
## ADR-171 — The query log can be searched for what does not match: a "not" per filter, and a read an older peer doesn't know (Accepted)
**Context:** GitHub issue #58: a user asked for "does not contain" in the query log search. The name filter matches in five ways (contains, exactly, with subdomains, wildcard, regex) and the other filters (client, status, type, response code) are "is one of"; nothing says "everything except", and a regex can't (the engine runs in linear time and has no lookaround). The analysis queries already have `!=` and "not in".
**Decision:**
- Five filters can be turned around: name (each of its five matches), client, status, type, and response code. They are typed booleans (`nameNot`, `clientNot`, `statusNot`, `qtypeNot`, `rcodeNot`) on `GET /api/v1/queries`, the first four on `GET /api/v1/queries/stream`; `--not-name`, `--not-client`, `--not-status`, `--not-qtype` on `telltale qlog search`; the Query log page's Match menu ("does not contain", "is not", "is not, or under", "does not match wildcard", "does not match regex"), a "not" box beside Client, Type, and Rcode, and a "not" chip before the statuses. Group, upstream, and slowness are not turned around. The Live view honours them (not regex, which it never had).
- A flag without its filter is a 400 that names it (as `match` without `name` is), not ignored. The page drops such a flag from an old address instead of sending it. A negated `rcode` keeps the queries that got no response code.
- The store's `Filter` carries a `Not` (five flags). The name and client predicates are resolved against each segment's dictionary into a yes/no per name, so a negated one only flips that set: no extra work per row. What a negation gives up is skipping by bloom filter (a bloom says "maybe present", never "absent from every row"): a negated name or client reads every block the time range and the other filters leave, as "contains", wildcard, and regex already do. A block is skipped for a negated status or response code only when every value in it is excluded (the header masks). Limits, threads, and the idle priority are the existing ones; the docs say to give a time range on a long log.
- In a cluster, peers decode `QueryParams` and `TailParams` leniently, so an older peer would ignore the new flags and answer rows that were not negated into a negated search. A negated search is sent as a new read (`QueriesNegated`, `TailOpenNegated`) that an older peer doesn't know, so it is listed among the nodes not reached (as other newer reads are) and never answers wrongly.
- The address keeps the existing keys and adds the flags (`match=exact&nameNot=true`): an old link keeps meaning what it did, and an older page opening a new link shows the un-negated search.
**Not done:** negating group, upstream, or slowness; combining filters with OR; lookaround in regex.
**Consequences:**
- A negated name search costs about what a "contains" search does; a negated exact name no longer gets the one-block shortcut.
- The OpenAPI document, the UI types, and the MCP tool schema (`search_queries`) gain five optional booleans.
- During a rolling upgrade, a negated search of the whole cluster reaches only the upgraded nodes.

## ADR-170 — Crates off the DNS path are built for size (Accepted)
**Context:** After ADR-168 and ADR-169 the images were 13.39, 12.66, and 13.10 MiB of the 15 MiB gate. The 2026-11-17 review found that building the crates that are not on the DNS path with `opt-level = "s"` instead of 3 makes the binary smaller, and asked for a benchmark first, because performance ranks above footprint. The owner chose to take it if it was safe ("Yes", 2026-11-17) and to measure SQLite's C code at `-Os` separately.
**Measured (the build VM; release profile with fat LTO; binaries built from 938c9a9, stripped and gzipped as a stand-in for the layer):**
- **The off-path list** (26 package specs in the measurement, `rusqlite` among them): 13,116 to 12,746 KiB, -0.36 MiB. Of the 1,737 functions in the DNS-path crates (`telltale-proto`, `-net`, `-cache`, `-filter`, `-policy`, `-telemetry`, `-upstream`), 1,724 are identical in size and 13 differ: startup and configuration code (the preset deserializers, a once-cell initializer, a telemetry drain), none per query. Rotated `bench-smoke` with an identical-binary control, five rounds, cache-hot median: baseline 526k queries/s, control 500k (-5.0%), this list 510k (-3.2%), inside the control's spread. Miss-heavy: flat.
- **The same list plus `telltale-config`:** -1.0 MiB in all, but `ClientTable::identify` (per query) grew from 3,428 to 4,039 bytes, the query handler changed, and cache-hot throughput was 474k (-9.9%, median p50 95 µs against 55). Not taken.
- **SQLite's C code (`libsqlite3-sys`) at `-Os`:** a further -0.31 MiB, but on the rollup store's own tables and queries (`hour_top` and `rollup_minute`, in memory, a copy of the binary as control within 0.5%) the dashboard's week-wide top list was 10.5% slower, minute-blob range reads 11%, hourly point reads 22%, and bulk insert 38%. Not taken.
- **The `rusqlite` wrapper at `"s"`:** top list -0.8%, blobs -0.8%, bulk insert +0.5%, point reads +4.6% (the control's spread was about 4%). The saving is small and it is on that same query path. Not taken.
**Decision:** the 25 package specs in `[profile.release.package.*]` of the root `Cargo.toml` (the HTTP API and its OIDC, OpenAPI, and certificate parts, cluster replication, the git source, the support package, and the config-file parsers) are built with `opt-level = "s"`. `telltale-config`, `rusqlite`, `libsqlite3-sys`, and every crate that runs per query stay at the release profile's 3. `crates/telltale-config/tests/profile.rs` fails if a hot-path crate is added to the list, if an entry is not exactly `opt-level = "s"`, or if an entry no longer matches `Cargo.lock` (a `name@version` entry that a dependency update outdates is only a cargo warning, and the saving would be gone without anyone noticing).
**Consequences:**
- About 0.35 MiB less on every architecture (the size gate in CI prints the real numbers).
- The API, OIDC, and replication code is somewhat slower per call. It runs per request and per replication message, not per DNS query, and the dashboard's own queries run in SQLite, which is unchanged.
- A new crate on the DNS path is not on the list by default; one that is added to the list has to pass the test, which names the crates known to be hot.

## ADR-169 — A compact zoneinfo and SQLite without its unused modules (Accepted)
**Context:** ADR-168 left two low-risk cuts undecided. The owner chose both on 2026-11-17 ("do items 3 and 4 too") after T23.1 took the images to 13.83, 13.08, and 13.54 MiB. The review had measured them on amd64: a slim zoneinfo -0.25 MiB, SQLite without full-text search and the R-tree index -0.20 MiB. Neither is on the DNS path.
**Decision:**
- The image's zoneinfo is built by `zic -b fat` from the package's own `tzdata.zi` (Dockerfile) instead of copied from `/usr/share/zoneinfo`. Debian's package ships the database three times (the main directory, `posix/`, and `right/`, which carries leap seconds); the build writes it once, with each name a hard link to one file, and copies it with `cp -a` so the layer stores each file once. Measured with tar and gzip on the build VM (tzdata 2025b): 347 KB for the distribution's directory, 151 KB built this way. The build fails if a zone name the distribution's directory has is missing from it (the host's own `localtime` and `posixrules` links and the two extra trees aside). jiff is the only reader (schedule time zones, FLT-010). `crates/telltale-config/tests/zoneinfo.rs` builds a directory the same way from the host's `tzdata.zi` and checks that jiff reads every file, that every name is present, and that the offset, abbreviation, and daylight-saving flag agree with the host's directory for every zone (weekly) and for twelve zones with every kind of rule (every six hours), from 2020 to 2075.
- **`zic -b slim` was built, tested, and is not used.** It is 87 KB, 0.06 MiB smaller still, but jiff 0.2.37 refuses one of its 598 files: `America/Ojinaga` from tzdata 2025b ("expected last transition in TZif file to have DST offset matching the offset derived from the POSIX time zone transition rule"), so a schedule in that zone would be rejected as an unknown time zone. The first version of this change was slim; the test found it. The fat files, which are what distributions ship, are all accepted. If a later jiff accepts the slim file, the 0.06 MiB can be taken, and the test is the check.
- SQLite is built without FTS3, FTS5, the R-tree index, and the dbstat table, by `LIBSQLITE3_FLAGS` (`-U` flags, which the bundled SQLite's build script applies after its own `-D` defaults). The flags are in the repository's `.cargo/config.toml`, not in the Dockerfile, so `cargo test` runs against the SQLite the image ships and anyone building from source gets the same one. `crates/telltale-store/tests/sqlite_build.rs` asserts the four modules are gone and that foreign keys on by default, the JSON functions, STAT4, column metadata, and thread safety stay. No code here uses a virtual table, `MATCH`, or dbstat. A real image build confirmed it: none of the four option strings is in the shipped binary, and STAT4, column metadata, and the foreign-key default are.
**Not done:** a slim zoneinfo (above); dropping the other optional parts of the bundled build (load-extension support, soundex, API armor): they cost little and are harder to be sure of.
**Consequences:**
- About 0.4 MiB less on amd64. A real image build with the slim variant printed 13.32 MiB against 13.83; the fat variant adds about 0.06 MiB. The size gate in CI prints the real numbers.
- A zone that only a `posix/` or `right/` path named (nothing here uses one) is no longer in the image. A time zone added to the database later is picked up by rebuilding the image, as before.
- A SQLite file that defines a full-text or R-tree table still opens (SQLite looks a module up when the table is used); using such a table fails with "no such module".
- `spec/08` §2 says the image carries a compact zoneinfo.

## ADR-168 — A leaner image: the OpenAPI document compiled in, a gzip-only embedded UI, no CA bundle (Accepted)
**Context:** The image gate is 15 MiB compressed per architecture (NFR-001). At 13bb27d the images were 14.84, 14.16, and 14.82 MiB (amd64, arm64, armv7), so one more feature of the size of the domain icons (+0.11 MiB) would have failed the gate on amd64 and armv7. A measured review (2026-11-17: the compressed layer sizes the gate sums, three release builds on the build VM, the BuildKit CI uses) found where the bytes are. The binary is about 97% of the image. Of it, utoipa's OpenAPI document builder was about 0.6 MiB, and the 677 KB document was rebuilt at every request. The embedded UI cost about twice its gzip size, because the build kept a raw copy beside each `.gz` and the layer's compression can only shrink the raw one. And a CA bundle (0.12 MiB) that no code reads.
**Decision (the owner chose these, 2026-11-17):**
- `GET /api/v1/openapi.json` serves `docs/api/openapi.json`, compiled in with `include_str!`, not a document built from `ApiDoc` while running. `api_001_committed_openapi_matches_the_code` still builds it from the code (a test-only function) and keeps the file equal to it; `UPDATE_OPENAPI=1` regenerates the file.
- `npm run build` replaces each text file in `ui/dist` with its `.gz` when that is smaller (`ui/scripts/postbuild.mjs`). The server sends the stored file unchanged to a client that accepts gzip, and inflates it for any other (curl without `--compressed`, a probe) with `miniz_oxide`, which is already in the tree. A file with no `.gz` is served as stored, and a damaged `.gz` is refused (500), never served half-read. This amends ADR-030's size-and-caching bullet ("so no compression crate on the server"): the server now has an inflater, and no new crate.
- The image has no CA bundle (`/etc/ssl/certs/ca-certificates.crt`). Every TLS client (upstream DoT and DoH, list fetches, event sinks, SMTP) verifies against the Mozilla roots compiled in with `webpki-roots`; none reads the system store, and `rustls-native-certs` is not in the lockfile. A private CA is set with `tls_ca` as before, which doesn't depend on the bundle's path.
**Not done (reviewed):** zstd layers (about 2.1 MiB smaller, but Docker before 23.0 and containerd before 1.5 can't pull them, and Debian 12's `docker.io` is 20.10); removing `.eh_frame` (the watchdog's stack capture unwinds with it, ADR-163); the linker's identical-code-folding (the cross compiler rejects it); zopfli re-compression of the layer (pipeline and provenance cost); a smaller zoneinfo and SQLite without its unused full-text and R-tree modules (ADR-169); building crates off the DNS path for size (decided after a benchmark).
**Consequences:**
- The three changes took the images from 14.84, 14.16, and 14.82 MiB to 13.83, 13.08, and 13.54 (amd64, arm64, armv7; read from the size gate of the CI image job on 3027e71; measured per item on the build VM for amd64: OpenAPI -0.60, UI -0.29, CA bundle -0.12), and every future UI file costs about half what it did.
- Serving the OpenAPI document is faster: no 677 KB document is built per request. The served document can't differ from the committed one, and the drift test is what keeps the committed one equal to the code.
- A client that doesn't accept gzip costs one inflate of at most about 700 KB per request (rare: browsers always accept gzip).
- `spec/08` §2 no longer lists a CA bundle in the image.

## ADR-915 — Image size: optimize cold code for size, embed only the gzip UI, and ship only the tz database the code reads (Accepted 2026-11-16)
**Status note (upstream sync, 2026-11-17):** partly superseded by ADR-168 and ADR-169. The zoneinfo step described here (the fork's own tz database, shipped whole) is replaced by upstream's `zic -b fat` build, and the CA bundle that ADR-168 drops is no longer copied. The other cuts stand.
**Context:** NFR-001 (`01`, `00 §5`) caps the compressed image at 15 MiB per architecture (`deploy/image/size.py`). At 177ef45 the amd64 image measured 15.13 MiB, up from 14.76 MiB at 412add6. The new code (secrets, credential rules, lists refresh, federated paths, ctl, OpenAPI schemas) grew the stripped binary by 0.91 MiB. The dependency and UI changes added almost nothing. The binary is already at `opt-level = 3`, fat LTO, one codegen unit and `panic = "abort"`, so the remaining savings come from what is compiled at a lower opt-level and from what is embedded.

**Decision:** Reduce the image in the order of saving against risk, without dropping a feature and without touching the DNS hot path (`02 §3`):
1. **API and MCP code at `opt-level = "s"`.** `[profile.release.package.telltale-api]` takes opt-level `s`; the rest of the workspace keeps opt-level 3. `telltale-api` holds the handlers, OpenAPI and MCP code, which are cold next to the DNS path. Measured: amd64 15.13 to 14.58 MiB.
2. **Tz database without `right/`.** The image ships the TZif zones that `jiff` reads (schedules, FLT-010), without the `right/` leap-second zones, `tzdata.zi`, `*.tab` and `leap*` files. Measured: 14.58 to 14.39 MiB. Known effect: a schedule that names a `right/...` zone no longer resolves. Schedules use the ordinary zone names.
3. **Embed only the gzip of each text UI file.** `ui/scripts/postbuild.mjs` removes the raw copy of a text file once its `.gz` is written. The binary embeds the `.gz`. A client that accepts gzip gets it as before. Any other client gets the same bytes inflated on the request, with `miniz_oxide` (already in the lock file, so no new package). Binary files (PNG, ICO, WOFF2) stay raw. Measured: 14.39 to 14.16 MiB. The postbuild script also resolves its `dist` path on Windows, where it failed before.

Final amd64 image: 14.16 MiB (headroom 0.84 MiB under NFR-001, 0.69 MiB under the 14.85 MiB target).

**Consequences:**
- The API and MCP handlers run as size-optimized code. The DNS path crates keep opt-level 3, and their code is unchanged, so `make bench-smoke` is not required by rule 4 for these changes. The API latency at opt-level `s` was not benchmarked here and is a follow-up.
- A `right/...` zone name stops resolving in a schedule, with an error that names the zone. No feature is lost.
- The UI's raw text files are no longer in `ui/dist`. Tools that read `dist` directly (for example `vite preview`) must use `ui/dist/*.gz`, or run `npm run build` without the postbuild step.
- Not taken, recorded here for the owner: `telltale-config` at opt-level `s` (about 0.2 MiB more, with per-query helpers in the policy path, so it needs a benchmark first), `opt-level = "z"` (about 0.5 MiB more, slower API handling), dropping the system CA bundle (0.12 MiB, needs its own ADR because the spec says the image ships one), and trimming serde code for `Config` (0.1 to 0.2 MiB, a refactor).

## ADR-167 — Domain icons: a brand tile or a monogram, drawn locally and never fetched (Accepted)
**Context:** A user asked for icons left of domain names, from `https://icons.duckduckgo.com/ip3/<domain>.ico`. The owner declined any dependency on a third-party icon service (2026-11-16). Measured that day: the endpoint is unofficial (no published terms, uptime, or rate limit), serves ICO only, and answers a 404 with a grey placeholder for a subdomain or a name with no site (`api.github.com`, `time.nist.gov`); and every icon request tells the service which names are in the query log, which shows work names, internal names, and trackers. The UI's content security policy allows images only from `'self'` and `data:`, and at privacy level 1 and up names are hashed (ADR-102), so there would be nothing to look up. Fetching from the sites themselves, from the server, would connect a resolver host to names any client chooses, many of them blocked or malicious (an SSRF and egress risk; review 06-02 fixed one of this kind). A lab on a synthetic demo network, in light and dark and at 390 px, showed the design below on the real lists.
**Decision (the owner chose it on that lab, with rounded shapes, 2026-11-16):**
- The UI draws a mark left of a domain name in the dashboard's Top domains and Top blocked lists and in the query log's name column. All of it is drawn in the browser from data already in the UI: no request is made for an icon, the content security policy is unchanged, nothing about queries leaves the page, and the DNS path and the API are untouched.
- A name that belongs to a brand in the map gets the brand's tile: its colour and glyph from Simple Icons (CC0-1.0, pinned at 16.38.0; the marks are their owners' trademarks and only identify the name). The map is curated, from a list in `ui/scripts/brand-icons.mjs`: 107 of the 133 brands listed have a glyph, mapped from 228 domains and hosts (CDN names too: `nflxso.net` is Netflix). The longest matching suffix of a name, on whole labels, wins, so `notnetflix.com` is not Netflix. The script writes the committed data files (`brands.ts`, `map.data.ts`): a build never needs the network or the package.
- Every other name gets a monogram: the first letter of its owner's label, in a tint of a hue taken from a hash of the registrable domain (one lightness and one chroma for every hue, so none outweighs another; both themes). A name of the network itself (`.arpa`, `.lan`, `.local`, `.home`, `.internal`, `.svc`, one label) gets a quiet house. A name the privacy level hid (`h` and 16 hex digits) gets nothing, and must not pass for a name of the network.
- A blocked name wears the same mark with most of its colour drained. A near-black mark flips to a light tile in the dark theme.
- The glyphs are a separate lazy chunk (about 120 KB raw, 51 KiB gzipped), fetched when the first brand tile is needed. Monogram only and Off never fetch it.
- The choice is Settings → Account → Domain icons: a style (Brand and monogram, the default; Monogram only; Off) and a size (Default, 20 px; Small, 16 px). It is kept per user in the browser (`telltale.icons.<user>`), like the detail level: no server state, no API, no configuration, nothing in the cluster.
**Consequences:**
- The open set has dropped several large companies' marks (Microsoft, Amazon and AWS, LinkedIn, Slack, Disney+, Hulu, OpenAI, Xbox, Minecraft, Nintendo, Adobe, the BBC, Bing; 25 of the 133 listed brands), so their names wear a monogram. 20 of the 27 service presets get a brand tile. A name outside the map is a monogram, never a guess.
- The map is data we maintain: a brand is added to the list and the data regenerated. `docs/third-party-notices.md` carries the Simple Icons notice and the trademark disclaimer.
- Cost: about 6 KiB gzipped in the main chunk and the 51 KiB lazy chunk (the UI is 295.6 KiB of its 400 KiB budget); no server work.
- Other pages (Clients, a device, Analyze, Explain, Flow, the Traffic map, the Wall) don't carry the mark yet.

**Amended 2026-11-17 (the owner: "go on adding the bootstrap icons pack as well as long as it doesn't create too much overhead"):** a second pack, for the marks the first one dropped.
- [Bootstrap Icons](https://icons.getbootstrap.com) 1.13.2 (MIT) is the second choice: when Simple Icons has none of a brand's candidate slugs, the generator takes the Bootstrap glyph named with a `bi:` prefix in the list. Eleven of the 25 missing brands have one: Microsoft (also used for Office, Azure, and Edge names, which have no mark of their own), Teams, Windows, Xbox, Bing, Skype, LinkedIn, Amazon, Slack, OpenAI, Nintendo. Disney+, Hulu, Minecraft, Adobe, the BBC, Walmart, and AWS are in neither pack and stay monograms. A glyph with no colour gets a brand colour chosen by hand in the generator (`BOOTSTRAP`), and its path sits on a 16 grid, so the data carries the grid size when it isn't 24 and the component reads it.
- Overhead: none at run time, and the chunk is smaller. The generator now minifies path data with svgo to two decimals (a third of the bytes, under 1% difference at 16 and 20 px), which more than pays for the eleven added glyphs: the glyph data is 86.9 KiB raw and 35.4 KiB gzipped (it was about 118 and 51 for 107 glyphs). svgo, and both packs, are used only when the generator runs (`npm i --no-save`, pinned in the script, checked by it); nothing is added to `package.json`, to the build, or to the image.
- `docs/third-party-notices.md` carries the Bootstrap Icons licence; the developer page `site/dev-icons.html` has the recipe for adding a brand or a pack.

## ADR-166 — UniFi: name offline clients from the console's client history and configured clients (Accepted)
**Context:** T8.2, ADR-080 ("not done: UniFi's offline known clients"). `stat/sta` lists only connected clients, so a device that has since left (a phone off Wi-Fi, a laptop asleep) loses its name: its queries in the log and the top lists show a bare address, though UniFi still has its alias.
**Decision (proposed):**
- After `stat/sta`, each UniFi poll also reads the v2 client history (`/v2/api/site/{site}/clients/history?withinHours=<offline_days × 24>`, Network 7+, the clients the console remembers within the window, with their `last_ip`; it answers to an API key) and the configured clients (`/api/s/{site}/rest/user`: aliases and fixed addresses), with the same API key or login cookie.
- Both are best effort: a console that can't answer either (an older Network application has no v2 API) still gives its connected clients, and the failure is logged at debug only, so the router isn't marked as failing.
- A known client is used only if it has a name (an unnamed one adds nothing a bare address doesn't). Merged by MAC: a connected client keeps its address and takes a known name only when it has none. An offline client gets its last address, else its fixed one (only while `use_fixedip` is on: UniFi keeps `fixed_ip` after a reservation is turned off), and only if no connected client holds it; between offline clients claiming one address, the most recently seen wins.
- **Bounded (added in review; the first version asked for every remembered client, with no limit).** (1) `[[router]] offline_days` (default 30, 0 for connected clients only, at most 365): the window goes to the console as `withinHours`, and every row with a `last_seen` older than it is dropped (a row with no date can't be judged and stays). (2) At most 1,024 offline clients per poll, most recently seen first (`OFFLINE_MAX`): they ride in every node's answer to `devices.names` (about 130 bytes each, against the cluster channel's 1 MiB frame) and sit in memory on every node. (3) An offline client is marked (`Lease.offline`) and is **not "seen"**: it names an address in the query log, but device identification (ADR-117) doesn't count it. Counted there, a remembered device would never age out, and with `identify.max_clients` (1,024) the places taken by devices that aren't there could push out ones that are.
- The default is not written to the replicated configuration and the mark is not written for a connected client, so a node on a build before this one (the `[[router]]` section refuses unknown fields) still reads the shared configuration and the `devices.names` answers. Roll every node before setting `offline_days` in the shared configuration.
**Consequences:**
- Offline devices keep their UniFi names in the UI and the query log. Two more read-only requests per poll (every `interval_secs`, 300 by default), for the last 30 days only: a site with thousands of remembered clients no longer makes an answer that grows with its whole history. This turns on for every existing UniFi integration at the default; `offline_days = 0` restores the old behaviour.
- A stale last address can name a device UniFi doesn't see now (a guest that left, its address since leased to something unnamed TelltaleDNS can't tell apart). Names configured in TelltaleDNS and its own DHCP leases still win.

## ADR-165 — The last healthy member may use the rest of the budget (Accepted)
**Context:** GitHub issue #35 (0.7.0-edge). `spec/04` §4 caps each attempt at min(`timeout_ms` (400 ms by default), 3 × EWMA + 50 ms, 1 s). A forwarder's EWMA reflects its cached answers: about 6.5 ms for NextDNS over DoH on a home network, so the cap is about 70 ms. A name the forwarder has to resolve itself takes much longer: a carrier's Wi-Fi Calling gateway with TTL 0 took 900–1,200 ms at Cloudflare, Quad9 and NextDNS alike. In a group of one, that single attempt timed out at ~70 ms, `Group::resolve` had nothing left to try, and the client got SERVFAIL ("no upstream answered") after ~100 ms with 1.9 s of the budget unused. On two nodes in a day: 346 SERVFAILs (0.3 % of answers, enough to fire the availability SLO's ticket alert), 735 upstream timeouts, 2 upstream SERVFAILs; every lookup of the Wi-Fi Calling name failed. Larger groups do the same when every member is cut off. `timeout_ms` can't help: it only lowers the cap, and its 400 ms default is below these answers too.
**Decision:**
- The adaptive bound and `timeout_ms` are there to give up on one member and move to the next; hedging (ADR-013) already starts the next member before that. So the attempt on the **last member in the attempt order whose breaker is closed** may use the query's whole budget (`Upstream::timeout_for(true)`), bounded by what's left of it, as recursive upstreams already may (ADR-074). Earlier members keep their timeouts, and hedge delays are unchanged.
- Members whose breaker is open or half-open (last resorts and probes) never get it. An upstream that is really down costs up to the budget per query until three timeouts in a row open its breaker, and then fails as fast as before.
- No retry of a member that timed out: the one attempt waits longer, so the upstream isn't asked twice and no timeout is recorded against an upstream that was only slow.
**Consequences:** a slow name is answered in the time it takes, up to the budget, for single-upstream setups too. A blackholed sole upstream makes clients wait up to 2 s for SERVFAIL, not 70–400 ms, until its breaker opens (three queries). Serve-stale (1.8 s) is unchanged. The patient attempt is at most the 2 s budget, under the 3 s after which a silent pooled connection is closed (ADR-148). Tested by `ups_006_single_member_waits_for_a_slow_answer` and `ups_006_last_healthy_member_waits_for_a_slow_answer`.

## ADR-164 — Debug files for every build: link once with line tables, publish the split-off symbols beside the stripped binary (Accepted)
**Context:** GitHub issue #7. The release binary is stripped (`strip = true`), so a stack taken from a hung node (a `gdb` or `eu-stack` capture, or the watchdog's dump, ADR-163) is a list of addresses nobody can read. The owner promised the reporter "debug symbols with 0.7.0" (2026-11-14). Two things limit the options: the image must stay under 15 MiB compressed per architecture (NFR-001), and the binaries are built reproducibly with `cargo auditable` (NFR-005), whose dependency data (`.dep-v0`) must survive.
**Decision (proposed):**
- **One link, then a split.** The Dockerfile's build stage links with `strip = none` and `debug = "line-tables-only"` (the profile's environment overrides, in that build only), then uses `llvm-objcopy` from the pinned toolchain's `llvm-tools` component: `telltale.debug` gets the symbol table and the line tables (`--only-keep-debug`); the shipped binary is the same link output with the symbol table and debug sections removed, `.dep-v0` kept, and a `.gnu_debuglink` to the debug file's name and CRC. A second build with symbols would have a different layout, so its addresses wouldn't match the shipped binary; `-C split-debuginfo` keeps no symbol table and isn't supported for fat-LTO static musl builds through zig.
- **No build ID.** The zig linker writes none, so the pairing is the release it came from (same version, same architecture) and the debuglink's CRC, which `gdb` checks.
- **Published as** `telltale-<arch>-linux.debug.zst` (zstd level 10) for the three architectures, in every release and every edge build, under the signed `SHA256SUMS` like the binaries and their SBOMs (`verify.sh` checks that the lines exist). `releases.json` doesn't list them: a node never fetches one, and `self-update` takes only its own binary by name.
- **What it costs, measured on the build VM (2026-11-16, the real Docker build for amd64):**
  - The shipped binary is 34,754,048 bytes against 34,748,816 (5,232 more, 0.015%): `.text` is 4,864 bytes larger and everything after it shifts, because turning debug info on changes the linked layout a little (it also adds a one-byte `.debug_gdb_scripts` reference). It is **not byte-identical code**, so it was benchmarked rather than assumed: `bench-smoke` alternating baseline and split binary, ten runs each: cache-hot throughput median 530,993 against 526,753 qps (ranges 482k to 586k and 449k to 557k), cache-hot p50 45.5 against 33.0 µs, miss-heavy p50 217 against 223 µs. No difference beyond the run-to-run spread.
  - The debug file is 141 MB raw, 25.5 MB at zstd 10 (21.4 MB at 19). Three of them add about 75 MB to each edge publish.
  - The stripped binary no longer carries the `.comment` section (the compiler's identification string).
- **Reproducibility.** The nightly two-clean-builds check still compares the binary byte for byte; it reports as a warning if the two debug files differ.
- **Reading a stack:** `zstd -d telltale-<arch>-linux.debug.zst -o telltale.debug`, then `addr2line -e telltale.debug -f -C -i <address>` (docs/running.md). With line tables, an inlined call shows the line of its own source.
**Alternatives rejected:** shipping the unstripped binary (141 MB more in every image); full debug info (several times larger, and the line tables answer what a stack needs); a debuginfod server (a service to run); symbols only, no line tables (byte-identical code, and function names alone lose where inside a large function the thread waits).
**Consequences:** the Docker build adds a few seconds; the image workflow uploads 75 MB more; the release page gets three more files; a stack from any build can be read after the fact if its release's debug file is kept (edge builds are replaced on every push, so a dump from an edge build is read with that build's file while it is still published).
**Accepted 2026-11-16:** the owner answered "Push and accept" after seeing the numbers above, including that the code is not byte-identical and that the images were already within 0.34 MiB of the 15 MiB gate (this adds about 0.04 MiB).
**Verification (planned):** the A/B above; the split binary keeps `.dep-v0` and gains the debuglink; `addr2line` on the debug file resolves a frame the watchdog's e2e produces (ADR-163's `deploy/watchdog/e2e.sh` on a debug build); the edge image run publishes the three files and the size gate and SBOM checks still pass.

## ADR-163 — A watchdog restarts a node that stops answering and leaves evidence of why: a thread outside the runtime, two checks, a bounded dump (Accepted)
**Context:** GitHub issue #7. A 2-CPU node (an LXC container with a two-worker runtime) stopped answering DNS, the API, metrics and the cluster port while its service stayed `active`, and stayed that way until someone restarted it, about twelve minutes in the report. The cluster saw its link drop a minute after DNS stopped, as if the runtime's threads stuck one by one. There was no stack to read: the release binary is stripped (ADR-164 gives it a debug file), and nothing on the node looks while it hangs. systemd's `Restart=on-failure` only acts when the process exits, and `/livez` is served by the runtime that is stuck. The owner promised the reporter (2026-11-14) "a watchdog so a wedged node restarts itself and leaves a dump", and held 0.7.0 until it exists (2026-11-16).
**Decision (proposed):**
- **Where it runs.** One OS thread, `telltale-watchdog`, started once the listeners are bound, outside the Tokio runtime and apart from the UDP workers: a check that runs on what is stuck can't see it. It wakes every 5 s. It adds nothing to the query path: no new code in the pipeline, no allocation, locking, or I/O there (`02` §3).
- **Two checks.** (1) *The runtime runs a task:* the thread spawns a trivial task on the runtime's handle and waits up to 2 s for it. (2) *The listener answers:* a plain UDP socket sends the node's own first UDP listener (UDP never has a PROXY header) a query for `probe.telltale.invalid` (the name of OBS-020's probes, which special-name handling answers NXDOMAIN without an upstream, and which the telemetry thread keeps out of the query log and analytics; a wildcard bind is asked on loopback); any well-formed reply with the same ID passes. With no UDP listener, only the first check runs.
- **Wedged.** A check that has not passed for `stall_secs` (default 60, 20 to 600), counted from its last pass, or from the thread's start before its first one. A node that is still starting answers (the listeners are bound before the thread starts, and the lists compile in the background), so a long start doesn't count. One pass resets that check, and a stall that has been dumped is not dumped again until a check has passed.
- **What happens.** The thread writes the dump, logs at ERROR, flushes the log files, then, with `action = "restart"` (the default), exits the process with status 70 for the supervisor to restart (systemd `Restart=on-failure`, Compose `restart: unless-stopped`, a Kubernetes container). With `action = "dump"` it writes the dump and leaves the node running. Restarts are limited to `max_restarts_per_hour` (default 6), kept as timestamps in `<data_dir>/watchdog/restarts`; past the limit it writes the dump and does not exit, so a false positive can't become an endless loop. A node started by hand (`telltale run` in a terminal) just exits.
- **The dump.** `<data_dir>/watchdog/hang-<UTC time>.txt` (directory 0750, files 0640, the newest 5 kept): why (which check, for how long, when each last passed), the build (version, commit, target, build ID), uptime, the thread table from `/proc/self/task` (id, name, state, what it waits on, CPU time), memory and load, the query counters, the last 200 lines of the support log (ADR-156), the executable's mapping (to turn addresses into offsets), and each thread's stack (below). It holds no client data and no configuration. The support package includes the newest one.
- **Stacks.** Each thread reports its own stack: the watchdog sends every thread of the process a signal (`tgkill`), and the handler stores up to 64 return addresses in a fixed table without allocating or taking a lock. The dump lists the raw addresses; `addr2line -e telltale.debug <address>` resolves them with the debug file of ADR-164. The wait is bounded (5 s); a thread that doesn't answer is listed as not answering, which says it is stuck in the kernel. The only `unsafe` is in `telltale-net`, with `// SAFETY:` comments (NFR-003). The binaries need unwind tables for this (`-C force-unwind-tables`, size only, no runtime cost).
- **Settings.** A node-local `[watchdog]` section, restart-only like `[support]`: `enabled` (true), `stall_secs` (60), `action` (`restart` or `dump`), `max_restarts_per_hour` (6). Metrics: `telltale_watchdog_enabled`, `telltale_watchdog_check_age_seconds{check}` (seconds since each check last passed), and `telltale_watchdog_last_action_timestamp_seconds` (the last dump or restart, from the files, 0 for none). The log says at start-up when the previous run ended by the watchdog.
- **Not covered.** A node that serves some clients and not others; a hang that spares both the runtime and the UDP listener (the checks ask whether it answers, not whether it answers well); a stall under 60 s.
**Alternatives rejected:** systemd's `WatchdogSec` with `sd_notify` (only systemd; the checks would still be ours); `/livez` as the check (the stuck runtime serves it; a Kubernetes liveness probe already restarts a pod, but a systemd or Compose install has nothing); a task on the runtime as the checker (it can't see its own stall); `abort()` for a core dump (needs core limits and `systemd-coredump`, so most installs would leave nothing); running `gdb` or `eu-stack` from the node (the unit's seccomp filter forbids `ptrace`, and the image has no tools); frame pointers everywhere for cheap unwinding (a cost on the query path); a self-update of the policy from the cluster (this is a node's own safety net).
**Consequences:** one idle thread waking every 5 s; one probe query per 5 s counted in `telltale_queries_total` like OBS-020's; four more settings and three metrics; a real wedge costs a restart (a few seconds) instead of an outage until someone notices; the dump needs the build's debug file to read. A false positive restarts a healthy node once per hour at most six times: the checks only fail when nothing answered for a minute.
**Accepted 2026-11-16:** the owner answered "Push and accept" to the account of what was built, measured and left untested (stack capture on arm64 and armv7 is unproven: the ARM builds link, and the capture is bounded).
**Verification (planned):** the check loop with a stubbed clock and probes (a stall is counted from readiness, a pass resets it, the restart limit); a runtime whose workers are all blocked is seen as stalled and a healthy one is not; the UDP probe against a real listener, a silent socket and one that answers with the wrong ID; the dump's content and its permissions, keeping five; the stack capture in a test that blocks a thread and finds its own function's address; a real-binary run on the build VM, built with a `wedge-test` Cargo feature (never in a release build) that blocks every runtime worker some seconds after start: the watchdog writes the dump and the process exits with status 70 within `stall_secs` and one check, as a supervising shell loop sees, and the dump's stacks name the blocked function.

## ADR-162 — Editing a quick rule: replace it in place under its ID; the rule keeps its maker and its start (Accepted)
**Context:** GitHub issue #57 (a user's request). The Quick rules page lists each rule with **Remove** only, and the form only creates, under a new ID. Changing a rule's domain, scope, end or note meant removing it and making another, which leaves a gap with no rule in effect and loses who made it and when. `PUT /api/v1/rules/{id}` already creates or replaces, but it stamped the writer and the time on every write.
**Decision (proposed):**
- **No new operation.** Edit is `PUT /api/v1/rules/{id}` with the rule's own ID (dry run, `If-Match`, `Idempotency-Key`, audited as `rule.put` with the rule before and after, so the editor is the audit entry's actor). Rules from the config files stay read-only (409).
- **What a replace keeps.** The new rule keeps `createdBy` and `created` of the one it replaces, so the Quick rules page's *Made* column says who started the rule and the audit log says who changed it. A stored rule that has none (older data) takes the writer and now, as a new rule does. A client that re-puts a rule to refresh its start no longer does: it removes the rule and makes another.
- **The page.** **Edit** on a rule made through the UI or API opens the form below the row, filled in from a copy taken when Edit was pressed (the list reloads every 10 s and must not reset the form). The preview is a dry run under the same ID, so it simulates the replacement and not an addition. The durations gain **Keep the current end (…)**, first and selected when the rule has a live end time (sent as `expires`, so an edit that changes the note doesn't extend the rule), and **Until I remove it** is selected when it has none; any other duration counts from now. The confirmation is a notice on the page, not in the row, which the reload redraws (ADR-161's lesson).
- **No Edit** for a rule from a config file, an expired one (the sweep removes it within seconds), or one made through the API for several devices or groups, or devices and groups together (the form holds one scope, so saving would drop the rest silently). The row says to use the API.
**Alternatives rejected:** remove then make a new rule from the page (a gap with no rule, and the maker and the start are lost); refreshing `created` on an edit (it would hide who started the rule); `updated` and `updatedBy` fields (a new key in the shared configuration, which an older replica refuses, CLU-010, and the audit log already has the editor); a separate `PATCH` (replace is the contract today); a multi-select scope in the form (a larger change, left open).
**Consequences:** no configuration schema change and no mixed-version issue; one behaviour change for API clients, that a replace no longer refreshes `created`; the page has two forms when one is being edited, so the form's test IDs differ (`quick-rule-form` for a new rule, `quick-rule-edit-form` for an edit).
**Accepted 2026-11-16:** the owner answered "push it, accept ADR-162" after seeing the behaviour change (a replace no longer refreshes `created`) and the cases without an Edit.
**Verification:** a unit test that an edit keeps the maker and the start and that older data takes the writer; the e2e test `flt_005 edit a quick rule in place` (the form from the rule, the end kept, the old domain no longer allowed, one rule, the maker and start unchanged, the notice, Cancel).

## ADR-161 — Muting anomaly findings: a shared entry per standing rule, matched when the finding is created, recorded but not counted (Accepted)
**Context:** GitHub issue #38. Some smart TVs look up the PTR of every address in their /24 once an hour: about 225 NXDOMAIN answers in a minute, 87% of the device's queries, so each node they ask raises an `nxdomain_storm` finding every hour, `TelltaleDNSDeviceAnomaly` fires all day, and the Anomalies page is all TV. Acknowledging (OBS-014) clears one finding; the next hour brings another. What exists doesn't help: `ignore_domains` doesn't apply to `nxdomain_storm` and can't name a reverse zone; raising `nxdomain_per_minute` weakens the check for every device and is per node; `[exclusions]` for the reverse zone takes those lookups out of the query log and analytics for every device, so a device sweeping the same network would go unseen, which is the case the storm check exists for; an Alertmanager silence can't target a device (the metric carries only `kind`). Two facts about the code decide the shape: the `[telemetry]` section is node-local (`shared.rs`), and the TVs ask both nodes, so the contributor's `[[telemetry.anomaly.mute]]` would have to be written on every node; and the engine runs on the telemetry thread, which knows addresses, not device names or groups.
**Decision (proposed):**
- **The entry.** A top-level, shared `[[anomaly_mute]]`, managed like groups and schedules: `name` (unique, the key), `devices` (device names, addresses or networks) and `groups` (at least one of the two), `kinds` (at least one of the finding kinds; there is no "all": a blanket mute is `ignore`-ing the engine, and an explicit list keeps a new kind visible), `expires` (optional, RFC 3339; the same words as a quick rule's `devices`, `groups`, `expires`, `note`), `note` (up to 200 characters). Who made it and when is in the audit log, not in the entry. Files, the API, the UI, MCP and Git all write the same entry; in a Git-managed cluster the API, UI and MCP refuse with 409 `gitops_managed` and show the TOML to commit, as for other configuration. It travels with the cluster's shared settings (CLU-003), so a mute set on the primary reaches every node, including ones that were down.
- **Matching.** Device names and groups are resolved when the configuration applies, from the `[[client]]` entries (their addresses and networks) and the group's networks and the clients that name it, into a sorted list of address networks. The engine receives one compiled table (networks, a bit per kind, an optional end time) swapped in atomically, like exclusions, and looks a finding's device up once, when the finding is created: a lookup per finding, never per query. A name that matches nothing, an unknown kind, or an empty list is a 422 (the dry run says which). A MAC address is refused with a hint: the address changes with the lease, and the neighbour table isn't on the telemetry thread.
- **What muted means.** The finding is recorded as before, with `muted: true` and `mutedBy: <mute name>`, so it is listed (with **Show muted**) and available to the API and MCP. It is not counted in `telltale_anomalies_total{kind}`, the sidebar badge, the `anomaly` alert rule, or the health level, and it is counted in a new `telltale_anomalies_muted_total{kind}`. The decision is made at creation against the finding's window start: an `expires` in the past mutes nothing new, a finding created while the mute held stays muted after it ends, and replaying the same queries with the same mutes gives the same findings.
- **Surfaces.** `PUT` and `DELETE /api/v1/anomaly-mutes/{name}` (dry run, `If-Match`, `Idempotency-Key`, audited as `config.anomaly_mute`); the mutes are listed by `GET /api/v1/config/entries?kind=anomaly_mute`, as schedules and alerts are; `GET /api/v1/analytics/anomalies` gains `muted` and `mutedBy` on each finding and `muted=true` to include them (hidden by default, like acknowledged ones); MCP `list_anomaly_mutes`, `plan_set_anomaly_mute`, `plan_remove_anomaly_mute` (named like `plan_remove_local_name`), and `find_anomalies` takes `muted`. **Agent scope:** a mute can hide a compromised device, so it has its own write scope, `config:write:anomalies` (included in `config:write:*`), rather than riding on `ops:anomalies` (acknowledging, which changes no configuration) or `config:write:groups`. The Anomalies page gets **Mute for this device…** on a finding (the device and kind pre-filled; for 1 day, 1 week, 30 days or until removed, 1 week by default; a note; the preview, a dry run, before saving), a **Show muted** switch, and a list of mutes with **Remove**.
**Alternatives rejected:** `[[telemetry.anomaly.mute]]` (node-local: the TVs ask both nodes); a per-device `ignore_kinds` on `[[client]]` (no expiry, no note, and a device with no `[[client]]` entry can't have one); acknowledging on a schedule (a finding every hour is the problem); a mute that hides the finding entirely (nothing lost is a rule here: muted findings stay listed and counted apart); matching by MAC now (see above); muting a domain rather than a kind (a different decision, left open).
**Consequences:** one more shared section (older replicas skip it, CLU-010, and so don't mute until updated: they would still raise the finding, which is the safe direction); a lookup per finding on the telemetry thread; the muted counter's label set is the finding kinds, as `telltale_anomalies_total`'s.
**Implementation notes (2026-11-15):** the owner approved the shape ("shared top-level is right, go build it"). Two things were added that the proposal didn't say, for the owner to confirm: the `config:write:anomalies` agent scope above, and `chatty_loop` is a mutable kind like the others (it is informational and never counted, but a muted one is marked and listed the same). A device name must be a `[[client]]` with an IP or network in its `match`; a device known only by the router's DHCP or mDNS name is muted by its address. **Accepted 2026-11-16:** the owner answered "Go on all 5" to the list that named these two additions as the open confirmation, so the scope and the mutable `chatty_loop` stand as built.
**Verification (planned):** the engine with a mute table (muted and unmuted devices, expiry, kinds, counters, replay); the config checks (unknown kind, empty lists, names that match nothing, MAC refusal); the API and MCP (dry run, `If-Match`, 409 under Git, audit); the UI flow end to end; the cluster path (a mute set on the primary reaches a replica).

## ADR-160 — Top lists and active clients follow the dashboard's time range, by whole hours (Accepted)
**Context:** OBS-004 (community request 2026-11-15). The dashboard's range picker (15 min to 30 days) changes the charts and totals, but Top domains, Top blocked, Top clients, and the Active clients tile always showed the current clock hour, so they emptied every time the hour turned and never matched the range above them. Each closed hour's top lists are already stored in `hour_top` for 400 days.
**Decision:**
- `GET /stats/top` takes `from` (and `to`), parsed like the summary's. The window is every hour it overlaps, counted whole: the stored hours from `hour_top` (`top_range`) plus the current hour (and the previous one until it's stored) from memory, summed per key, counts and error bounds alike, reading twice the limit (at least 20) from each source, as the SLO attribution lists do (ADR-127). Hour granularity is said in the UI ("since 14:00") rather than hidden.
- `from` doesn't combine with `hour`, `client` (per-device domains live in memory only), or `group` (groups' lists aren't stored): 400 with a hint. The dashboard sends `from` unless a group is picked, and then says "this hour".
- `Summary.activeClients` is the length of the same list over the summary's range (limit 1000), so the tile and its change follow the range. Stored hours hold their busiest 100 clients, so past the last two hours it undercounts on networks with more than 100 devices an hour (documented).
- Federated: a `TopRange` read; each node sums its own hours and the lists merge by key (OBS-012). A peer one version behind doesn't know the read and is listed in `missingNodes`.
- MCP `top_items` takes `from` and `to`.
**Consequences:** One SQL aggregate over at most 720 hours × 100 rows per list and dashboard poll (three lists, plus two for the summary and its comparison). The meaning of `activeClients` changes from "this hour" to "the range's hours"; a client that wants this hour asks with `from=-1s`. Names that never reached an hour's top 100 don't add up across hours.

## ADR-159 — Top clients split by status: a payload on the Space-Saving entry (Accepted)
**Context:** OBS-004 (community request 2026-11-15). The dashboard's Top clients bar shows how many queries a device made, not what happened to them: a TV in second place could be mostly blocked telemetry or mostly cache hits, and finding out means a query-log search per device. The status chart already colours blocked, cached, and forwarded queries for the whole network.
**Decision:**
- `SpaceSaving<K, T = ()>` carries a payload per entry. `offer_with` updates it; an entry that replaces the minimum starts a fresh `T::default()`, so the payload covers the `count - error` occurrences since the key entered the list. Every other list keeps `T = ()` (zero-sized, no change in memory or work).
- The hour's client list and each group's client list carry `ClientStatus { blocked, cached, forwarded }` (three `u64`; 24 KB per hour for 1,000 clients). Cached takes in `stale` and `refreshed`, as the dashboard's status chart does. Other statuses aren't counted: they're the rest of `count`.
- `TopItem.byStatus` (`kind=clients`, with or without `group`); absent for other kinds. Federated reads add the splits per key; a peer one version behind sends none, and its queries stay in `count` only.
- Each closed hour's split is stored in `hour_top` as three more kinds, `clients_blocked`, `clients_cached`, and `clients_forwarded`, keyed like `clients` (its 100 kept clients; zero counts skipped; none at privacy level 2 and above, like `clients`), so a read over stored hours can add them per client. Today's top-list reads use the current or previous hour from memory; the stored rows are for range reads.
- The dashboard draws a top client's bar as segments in the status colours (`--s-blocked`, `--s-cached`, `--s-forwarded`, `--s-other` for the rest), with a legend and the numbers on hover.
**Consequences:** Up to 300 more `hour_top` rows an hour, usually far fewer (most clients have no blocked queries). One more field update on the aggregator thread per query (no hot-path change: workers only emit events). The hours rebuilt from the query log at start (privacy level 0) get the split too, since the replay goes through the same path. Grey can include the Space-Saving error bound, which on networks under 1,000 devices is zero.

## ADR-158 — The Clients page's list is the last hour, not the clock hour (Accepted)
**Context:** The Clients page's first tab, **Seen this hour**, read `/stats/top?kind=clients`, whose Space-Saving list starts again on the clock hour. A minute past the hour it held a minute of clients, and the label didn't say so: the owner found "seen this hour" meaningless and asked for "last hour" (2026-11-15). "Last hour" over the clock-hour list would have been wrong in the same way.
**Decision:**
- The aggregator keeps per client its queries in 5-minute slots over the last 13 (`telltale-telemetry::last_hour`): the slot in progress and the 12 before it, so the window always holds the full last hour (60–65 minutes) and a device seen 59 minutes ago is never left out. Updated on the telemetry thread with the other analytics (one hash update per query), never on the query path. At most 4,096 clients; a client leaves once its newest slot leaves the window, checked once per slot, and the table shrinks when a burst of clients has aged out.
- A live query a whole window older than the newest means the clock was set back: what was counted is dated in the future, so it is dropped and counting starts again (otherwise every new query would be ignored until the clock caught up). Not saved: after a restart the query-log replay that rebuilds the hourly lists (T6.16) refills it, through a path that never moves the window back.
- `GET /api/v1/stats/top?kind=clients&hour=rolling` reads it (a new `TopHour` for `/stats/top`; `/stats/latency` keeps `Hour`). Counts are exact (`errorBound` 0). `hour=rolling` with another kind is a 400. With `group`, the clients whose settings come from that group (their first group), so a group-restricted agent (AGT-004 adds its group) reads its own devices. MCP `top_items` takes `hour: rolling`.
- In a cluster every node sends all its clients (not just its top `limit`), so the merged counts stay exact; the list is cut afterwards. A peer one version behind doesn't know the read and is listed in `missingNodes`, and the Clients page says which nodes are left out.
- The tab is **Last hour** (heading "Seen in the last hour"); its id stays `seen`, so `#/clients?tab=seen` links keep working. The Traffic map's hour picker says **previous hour** (not "last hour") for the previous clock hour, so "last hour" means one thing in the UI.
**Consequences:** at the 4,096-client cap about 0.65 MB (80 bytes per client in a table of 8,192 buckets), given back as they age out; a home network's 50 devices take a few KB. In a large cluster each page load moves every node's client list (up to 4,096 rows each). This is a clients-only window: a rolling hour for the other top lists would need a Space-Saving sketch per slot (13 times their memory), so they stay per clock hour, as do the dashboard's active clients and a group's device count, which say "this hour".

## ADR-157 — A calmer dashboard, with the previous one an address away (Accepted)
**Context:** owner request 2026-11-15 after a user called the dashboard graphs "a tad cluttered" and liked Technitium's smoothed graphs with the exact number on hover, and the wide tables at the bottom on a small screen. The shipped page was 2,577 px tall on a phone: six tiles with rings, sparklines and change pills, a legend that wrapped into a table, a donut, and three full-width lists. A read-only look at the live query logs (2026-11-16) showed why the lists widen: on the homelab primary 358 distinct names over 30 characters carry 45k of the 61k queries of a day (Kubernetes services, pods' search-list expansions of one real name, 64-hex labels), and none on the Pi. Ten local variants were built on the real data and compared at desktop and phone width; the owner chose "Calm".
**Decision (proposed):**
- **Layout.** The six tiles become a row of plain numbers (queries, blocked %, cache hits, upstream p90, active clients, each with its change against the previous period) and a line for NXDOMAIN and SERVFAIL; the chart is the one card; the three lists sit open on the page. Advanced adds, without adding cards: the service level (OBS-016) as a strip under the numbers; the chart's other views, Groups and Upstream, beside Totals and Status; where time goes (OBS-030) and the upstreams as plain sections; devices by type (OBS-025) as a line under the clients; the cache number split into fresh and refreshed (DNS-007).
- **The chart.** Smoothed for the eye, exact for the reader: the range is cut into at most one bucket per 6 px (120 at most), each bucket's counts are the exact sums for its interval, drawn through as a monotone curve (it never overshoots); the newest, still-filling bucket is left off so the line doesn't dip. The legend is a row of range totals; hovering shows the interval and each series' exact value (a compact tooltip on a short chart); charts can share a cursor. The Table view (`spec/07` §3) and the change markers (OBS-033) stay. The value axis uses compact numbers (10K).
- **The lists.** Every row is one line, and what doesn't fit is a tap away: the count opens the full name with a Copy button and, where the display differs from the name, one sentence saying how. The display reads the name (heuristics on the name alone): `service.namespace.svc.cluster.local` is the service with its namespace as a tag; a pod's search-list expansions of one real name (`<real>.<ns>.svc.cluster.local`, `<real>.svc.cluster.local`, `<real>.cluster.local`) are one row tagged `search suffix ×N` whose detail lists the variants and whose link searches the real name; hash and UUID labels are shortened; `in-addr.arpa` and `ip6.arpa` names show as the address; a pod's own name shows as its workload's. A name that is still too long gives up its subdomain first, a single long label keeps its end, and a tag gives way before the name. The lists ask the API for 25 and show 10 after merging.
- **Loading.** The same calls as before, except the Advanced-only measures (latency by path and stage, the service level) are fetched only in the Advanced view, independently of the rest and one fetch at a time: the service level took about 12 s on a slow node, and the page must not wait for it.
- **The previous dashboard** stays, unchanged, as `DashboardLegacy`: `#/?view=legacy` shows it and remembers the choice in this browser (`localStorage`, `dashboard.view`); `#/?view=new` goes back. The only link to it is a quiet "Switch to the new dashboard" on the old page itself. It is not documented for users yet and is meant to be removed once nobody asks for it (the owner decides when).
- No API change.
**Alternatives rejected:** the other nine variants (Sentence, Lens, Share, Multiples, Console, Sections, Rail, Hero, Glance: kept in the lab branch for reference); a visible toggle between two dashboards (it publicises the old one and doubles what we maintain); wrapping long names onto two lines or scrolling the lists sideways (rows of different heights; a scroll bar inside a card on a phone); showing the full name in a tooltip only (a phone has no hover); normalising cluster search suffixes in the server's top lists (they waste three of the top-100 slots per real name; a data-quality improvement for a later ADR); the per-device status bar of issue #30 (it waits for the reporter's backend change, and the row is designed to take a thin bar under the name).
**Consequences:** a UI-only change (bundle 229.8 KiB gzipped, budget 400); about 600 lines of the old page stay until it is removed; the name rules are heuristics, so a namespace named like a top-level domain (`io`, `dev`) reads as part of the name, and the full name is always one tap away; the README and site screenshots are regenerated; the e2e suite is updated to the new structure and gains a test for the old page's address.
**Verification:** the e2e suite (the dashboard, service level, cache tile, groups, device naming, change markers, internal names, and the legacy address); `npm run check` clean; the size budget; no sideways scroll at 360 px; the demo network and the live cluster's name shapes looked at.

## ADR-156 — Support package: redaction that fails closed, keyed pseudonyms that keep structure, and a small log of the process's own (Accepted)
**Context:** OPS-011 (owner request 2026-11-15, GitHub issue #50). A person who hits a problem hand-copies configuration, logs, and cluster state and hand-redacts each, so they send too little to help or too much to be comfortable. Owner decisions: the default level is `strict` and fuller logs and the query-log sample are opt-in; the query-log sample is offered; it is not an MCP tool for now. What the code shows: the process writes its log to stderr only (`TELLTALE_LOG`, default INFO) and keeps none; the systemd unit runs as `telltale` without the journal group, container logs are outside the container, and the Helm chart's root filesystem is read-only, so no platform lets it read its own log back, while `data_dir` is writable everywhere. Secrets sit in the configuration two ways: `*_file` paths (credentials, passwords, tokens, the bootstrap secret) and inline values (an OIDC `client_secret`, DoH extra headers). On the Pi the INFO log was 232 lines, about 21 KB, in 24 hours (restarts included).
**Decision:**
- **The package.** `telltale-support-<node>-<UTC time>.tar.gz` (GitHub takes it as an attachment), built in memory and capped at 20 MiB (the largest files are truncated first, and the manifest says so). It uses our own ustar writer, `miniz_oxide`'s deflate, and a small CRC-32: no new dependency. `MANIFEST.json` and `README.txt` (what it is, the level, how to read it) at the root; `node/`, `config/`, `cluster/`, `health/`, `metrics/`, `stats/`, `logs/`, and `queries/` (only when asked).
- **Collectors.** Each section is a collector with a 5 s deadline and a byte cap; a slow or failing one shows as `missing` in the manifest instead of failing the package; the whole run is capped at 30 s. They read the running state through the readers the API uses, from a low-priority thread, never from the query path. No collector can reach the user, token, session, TOTP, or key stores: they take typed views only.
- **Secrets are removed by classification and fail closed.** Every configuration field has a class (`plain`, `address`, `name`, `url`, `path`, `secret`) in one table keyed by schema path. The configuration section is built by walking the config's JSON Schema (`schemars`, already a dependency) with the value. A field with no class is treated as `secret`, dropped, and listed in the manifest as unclassified, and a test walks the generated schema and fails when any property has no class, so a new field can't ship unclassified. `secret` fields are removed at every level, `none` included; a `*_file` field keeps its path but never the file's content; request headers and any key that looks like a credential are dropped as a second net.
- **Free text** (log lines, error strings, the event timeline, the query sample) goes through a redactor in two passes. First the known values from the configuration and the cluster registry (every name, zone, client, group, host name, URL host, address, node and cluster name, e-mail address, and every secret held inline) are replaced exactly, longest match first, with `regex-automata` (already a dependency). Then hand-written scanners catch the shapes: IPv4 and IPv6, MAC, e-mail, URLs, host-name-like tokens, home paths, PEM blocks, and long hex or base64 runs (24 or more characters, mixed) become `<token>`. This is best effort, and the package says so.
- **Pseudonyms.** A random 256-bit key per package, kept in memory (written, with the map, only to the `--keep-map` file). Names become `device-N`, `group-N`, `node-N`, `pod-N`, `ns-N`, `host-N`, `zone-N.example`, `user-N@example.invalid`, numbered by first encounter in a fixed traversal order, so the same input is the same pseudonym within a package; public domain names keep their last label (`site-N.com`). Addresses: loopback, unspecified, link-local, multicast, and a short list of well-known public resolvers stay as they are; the rest are permuted prefix-preservingly with a keyed BLAKE3 function (Crypto-PAn style), so addresses that share a /24 (or /64) still share one, and a private address (RFC 1918, ULA, CGNAT) keeps the bits that make it private. A MAC keeps its OUI (the make, not a person) and has the rest permuted.
- **Levels.** `strict` (default): the pseudonyms above, no query names anywhere (counts only), no local zone contents, no free text, WARN and ERROR log lines only. `standard`: the same, plus INFO log lines, top lists with pseudonymized names, and the query sample (`--query-sample N`, up to 1,000 rows, never at `strict`). `none`: real values (secrets still removed). `--reveal NAME` keeps one name readable. The manifest records the level, and per file the collector, size, truncation, and the redactions per category (counts, never values).
- **The log.** A `tracing` layer (`SupportLog`, in the `telltale` crate) takes events at INFO and above whatever `TELLTALE_LOG` says into a ring of 2,000 lines and, through a bounded channel (1,024) to a writer thread, into two files under `<data_dir>/logs/` of at most 1 MiB each (rotated when full; directory 0750, files 0640). A full channel drops and counts (the manifest reports the count); a failing write turns the files off and logs it once; with a read-only data directory only the ring remains. The files are on by default (owner, 2026-11-15); `[support] persist_logs = false` keeps only the ring. The lines are not redacted on disk (they carry client addresses): the redactor runs when a package is made, and the documentation says where they are.
- **Surfaces.** `telltale support-package [--level strict|standard|none] [--reveal NAME]... [--query-sample N] [--keep-map FILE] [--list] [-o FILE]`. `POST /api/v1/system/support-package` (admin; the options as the body; `?dryRun=true` returns the manifest only; the answer is the archive as an attachment; audited as `support.package` with the level, never the content). On the System page a section with the three levels explained, a preview of the manifest, and the download. **The pseudonym map is a second, short-lived download** (owner, 2026-11-15): with `keepMap: true` the answer carries the package's ID, and `GET /api/v1/system/support-package/{id}/map` (admin) returns it as plain text, one `pseudonym<TAB>original` pair per line. The node holds the map in memory only, never writes it to disk, removes it after the first download or after 10 minutes, and keeps one map at a time (a new package replaces it); the page tells the person it holds the real names and isn't for attaching to the issue; the download is audited like the package. The CLI's `--keep-map FILE` writes it to a file the person chooses. No agent scope and no MCP tool.
- **Cluster (a later phase).** `--cluster` asks each node over the cluster channel (`support.collect`; the entry node sends its key over the mTLS stream and each node redacts before answering), so unredacted data never leaves the node it is on.
**Alternatives rejected:** pattern-only redaction (fails open: a secret in a shape nobody listed leaks); an unredacted dump to review by hand (what people do now); uploading to a server (no infrastructure, and the privacy question); `tar` and `flate2` crates (a dependency for about 100 lines); reading the journal or the container log (not readable); random address pseudonyms (they lose the subnet structure triage needs); encrypting to a maintainer key (key custody; possible later).
**Consequences:** a small amount of disk writing for the log files (about 21 KB a day on the Pi at INFO, measured 2026-11-15; none with `persist_logs = false`); a classification table to keep current, enforced by a test; `none` still holds real names, so the page says so; free-text redaction is a best effort, not a guarantee, and the person is told to look the package over; the log files hold client addresses unredacted, mode 0640, which the documentation states.
**Verification (planned):** a fixture with every kind of secret planted, scanned for in raw, decompressed, base64, and URL-encoded forms at each level; the classification-completeness test; a fuzz target for the redactor (never panics, planted values never survive); determinism (same key and input, same bytes); a prefix-preservation property test for addresses; the size cap and truncation; the manifest's counts against a recount; log layer tests (ring bound, rotation, lines surviving a restart, a full channel dropping instead of blocking); `make bench-smoke` unchanged, since nothing runs on the query path.
**Decided by the owner (2026-11-15):** the UI offers the name map as a short-lived second download; the log files default to on. **Accepted 2026-11-16:** the owner asked for issue #50 to be built ("address issue 38 and issue 50") after being told that would be read as accepting this ADR as written; the decisions above stand. Built in phases: the log layer first, then the archive, redaction and pseudonyms, then the collectors and the three surfaces; `--cluster` stays a later phase.

## ADR-155 — Removing a node: a registry change plus a removed list that travels with every version (Accepted)
**Context:** GitHub issue #5 (v0.6.0). `spec/07` lists `DELETE /cluster/nodes/{id}`, but it was never built, and the registry (the primary's `nodes.json`) only dropped ephemeral members. A Pi replica rejoined from scratch got a new node ID and left its old record behind as a down, eligible voter: the Cluster page listed it (even as primary, its last state from a period as emergency primary), `failover.voters` counted it (four voters, three reachable), and `TelltaleDNSClusterPeerDown` fired for it for good. Two facts make removal more than deleting a row. A node removed while it still runs reconnects with its certificate (valid for up to 90 days), and `record_member` re-adds an unknown member as an ephemeral one. And an eligible node holds a copy of the cluster key (ADR-051), which no registry change can recall.
**Decision:**
- **The operation:** `DELETE /api/v1/cluster/nodes/{id}` (admin; agents `cluster:admin`), `telltale ctl remove-node <id>` and a Remove action on the Cluster page. The ID is the Cluster page's node ID, not a site or pod name (a destructive operation by a name that can match several nodes is a hazard). It runs on the primary; a replica's request goes there over the cluster channel (`cluster.remove`) and is audited as `cluster.node.remove` with the user and the entry node. It is allowed under a GitOps authority: membership isn't configuration (as maintenance, ADR-118). `?dryRun=true` runs every check and says what would happen (AGT-002).
- **Refused:** the primary (409 `node_is_primary`: promote another node first), an ID nobody has (404 `node_unknown`), a node that is up unless `force` (409 `node_is_up`), and, under automatic failover, a primary without its lease (503, like any publish).
- **What it does:** the ID goes onto the removed list first, then the record leaves the registry, and the member and stream entries are dropped. A crash between the two leaves a refused node that is still listed, and removing it again finishes. Voters are the registry's eligible nodes and witnesses, so the removed node stops voting at once.
- **The removed list** (`removed.json`, at most 512 IDs, oldest dropped first: node certificates last 90 days) travels in the signed manifest as a new optional field, omitted when empty and ignored by N−1. Every node refuses a stream from a listed ID: at its Hello, and for a stream that was open before, at its next frame. Replicas adopt it with the registry (an empty list from an older primary leaves theirs alone), and a promoted node keeps the one it has. So removal holds for a node that is still running, on every upgraded node, for as long as its certificate would have lasted; it can't renew without a stream.
- **The cluster key is not recalled.** The answer says when the node was eligible (`heldClusterKey`, and a note) and points at `telltale cluster rotate-ca` (T5.4c) for a node that is lost or can't be trusted. Removal doesn't rotate the CA: that is a multi-step change on every node, and for the usual case (a record whose machine is gone) there is nothing to protect. Rotating on every removal of an eligible node was rejected as heavy and surprising; a certificate revocation list was rejected because the removed list is the same thing keyed by what the stream authenticates (the node ID).
- **Failover:** removing a voter can leave fewer than three, which turns automatic failover into manual (ADR-056). The answer and the dry run say so (`automaticFailoverAfter`, a note); it isn't refused.
- **Agents:** not an MCP tool, like `cluster_promote` (`spec/13`): it needs `cluster:admin` and human approval. The REST route with its dry run is the agent surface.
**Consequences:** a node that rejoins needs a fresh token and an empty cluster directory (a new ID), as before. A removed node that still runs keeps dialing and being refused; the primary's event list says so (`disconnected: this node was removed from the cluster`), and its own log says the stream closed. A node one version behind doesn't know the list and accepts the removed node until it is upgraded: upgrade replicas first, as always. IDs are random from the node's key and never reused, so nothing needs undoing. Not covered: a removed node that holds the cluster key can still mint certificates for itself until the CA is rotated, as the answer says.
**Accepted** by the owner on 2026-11-15, with the choices above: removal by ID only through `telltale ctl remove-node` (not `telltale cluster remove`), `force` for a node that is up, no CA rotation by removal, no MCP tool, and the Cluster view listing registry members that haven't connected since the node started.

## ADR-154 — A Git-managed node takes over from an emergency primary through the election (Accepted)
**Context:** GitHub issue #3 (v0.6.0; a Kubernetes controller that is Git-managed plus native replicas, automatic failover, `config_authority = gitops`). While the controller is down a replica is elected and becomes an *emergency primary* (ADR-056, ADR-048): it coordinates on the last version and publishes nothing new. When the controller came back nothing moved the role: the takeover loop (ADR-048, review 05 q2) required `promote_plan(..).is_ok()`, and `promote_plan` refuses under automatic failover on purpose (ADR-056: a manual promote would bypass the votes). So the documented "takes over by itself after a minute" never happened with `failover = auto`, and a GitOps cluster stayed on an emergency primary that can't publish until someone ran a command that was also refused. The owner first accepted letting the takeover bypass that refusal (2026-11-14), then changed course the same day: a bare bypass leaves a primary that can't publish, because under `auto` a primary writes only while its election lease holds (`Cluster::may_publish`, ADR-056) and `promote` creates no election phase; the voters would also keep the lease they granted to the emergency primary.
**Decision:** under automatic failover the takeover is a handover plus an election, so ADR-056's rules (one vote per epoch, voter-granted leases, pre-vote, fencing) decide who is primary, as for any other failover.
- **The ask.** A node that can stand (not the primary, eligible, not a witness, holding the cluster key) and is Git-managed (`config_source = "gitops"`) sends the emergency primary the new `elect.handover` RPC once it has seen that primary up for the same 60 s as before. The asker is the stream's certificate, as for votes.
- **The answer.** The emergency primary agrees only if automatic failover runs, the authority is `gitops`, it is an emergency primary, and the asker is in the signed registry as eligible and not a witness, is Git-managed (from its Hello, ADR-049), and is up. Otherwise it says why. Agreeing starts the ADR-118 handover without a maintenance window: it stops renewing its lease and keeps serving DNS, stays ready, and keeps its alerts; it follows the new primary after the step-down. The ADR-118 give-up applies: no new primary within 60 s and it renews again (`handover_failed`). The asker waits 120 s before asking again.
- **The hold-back.** Under the `gitops` authority a node that isn't Git-managed doesn't stand while an eligible, Git-managed node is up (`Elector::standing`, the ADR-118 switch; it still votes). So when the controller is back, the election goes to it, and when the controller is down for good the replicas stand as before and one becomes the emergency primary. The hold-back is bounded: with no primary up for 60 s it ends and the node stands (an emergency primary beats none, e.g. when the Git-managed node is up but can't win).
- **Manual failover, and fewer than three voters,** are unchanged: the takeover is `promote` (ADR-048), as is a person's promotion.
- **Wire and state.** One new RPC kind on the existing stream; no new frame fields, nothing persisted. A node one version behind answers an unknown kind with an error, so the asker logs it and tries again later; the cluster is no worse off than before.
- **Trust.** Only a cluster member over mTLS can ask, and the registry (signed by the CA) decides whether it counts. A node that is eligible already holds the cluster key, so the ask widens nothing; the worst a misbehaving eligible node can do is make an emergency primary stop renewing for up to 60 s, which is an election and a re-election, and DNS never waits for it.
**Verification:** a simulation test (`clu_005_a_git_node_is_elected_when_the_emergency_primary_hands_over`) with one emergency primary, one Git-managed node and one that holds back: the Git-managed node is elected within one lease window, never while the old primary can write, the other node votes and never asks, and the old primary steps down. The randomized partition simulator already moves nodes in and out of `standing` (ADR-118), which is the switch the hold-back uses. Unit tests cover when a node defers, how long, when the primary agrees, and when a node can stand to take over. Not tested: a live cluster of Git-managed and native nodes (the failover drill in `deploy/cluster/` doesn't set the GitOps authority).
**Consequences:** with `failover = auto` and the `gitops` authority, a returning Git-managed node becomes primary again by itself about a minute after it is seen, plus an election (15 to 25 s of no config writes, DNS unaffected). If it can't win (no cluster key yet), the emergency primary keeps the role and is asked again every two minutes. A node that isn't Git-managed waits up to a minute longer to stand when the primary is lost while a Git-managed node is up. An emergency primary can still keep a cluster coordinated through a long Git-managed outage (certificate renewal waits for a primary), which `manual` doesn't do; the docs say so and let the owner of the cluster choose.
**Amends:** ADR-048 (the takeover under `auto`) and ADR-056 ("under a `gitops` authority an elected node that isn't Git-managed becomes an emergency primary": now only while no eligible, Git-managed node is up, or after the 60 s bound).
**Accepted** by the owner on 2026-11-15.

## ADR-153 — Stub zones: a recursive upstream with per-zone hints, a health check its servers answer (Accepted)
**Context:** DNS-022 (community request 2026-11-14). Conditional forwarding (DNS-017) asks the configured servers with RD=1 and returns their reply as is. A zone's own authoritative-only servers (BIND with `recursion no`, NSD, Knot, PowerDNS, internal AD-integrated or departmental masters) answer only their zones: for a delegated sub-domain they return a referral, which reaches the client as an empty NOERROR, and they REFUSE the active health check's `. NS`, so the upstream is benched and `upstream_down` flaps while every real lookup works. BIND solves this with stub zones; Unbound with `stub-zone`. The iterative resolver (ADR-074) already follows referrals with bailiwick and glue rules but always starts at the root, and the spec's `health_check_name` (spec/04 §5) was never built.
**Decision:**
- A stub zone is a `recursive://` upstream with `[upstream.recursive] stub_zone` and `stub_servers` (IP addresses, port 53). It sits in a group and is reached through a `[[route]]` like any upstream, so groups, strategies, breakers, views, the cache, and the API's forward model need nothing new.
- The resolver's `start()` picks, in order: the deepest cached cut strictly below the stub zone (a delegation its servers gave), else the stub's servers, else the root. A cached cut at or above the stub zone is the outside (public) view and never wins: the configured servers are used whatever the public delegation says (split horizon). A DS for the stub apex still goes to the parent.
- The servers are used as listed (BIND `static-stub`, Unbound's default `stub-prime: no`): the zone's NS set isn't fetched from them. Conservative: a NS set listing public or unreachable addresses can't take over, and nothing is learned that the operator didn't write. Priming the NS set (BIND `type stub`) is deferred until asked for.
- Stub names never trigger root priming, so a network with no route to the root still answers them at once. Names an answer leads outside the zone (a CNAME target, an out-of-zone server name) are resolved from the root by the same resolver, as `recursive://` does; the root never sees the stub zone's own names.
- Health: `Upstream::health_check()` probes a stub upstream for liveness only: its servers are asked the zone's SOA directly and any reply except SERVFAIL counts as up, REFUSED included (servers that host only the zones below a stub apex, such as per-/24 reverse zones under a /16 stub, refuse the apex itself; a server that answers SERVFAIL for its own zone is failing, so it doesn't count). `Upstream::stub_liveness()` is the one rule: the draft-upstream check `POST /checks/upstream` applies it too. Other upstreams ask `Upstream::health_question()` (`. NS`). Client lookups keep their usual accounting: a failed iterative resolution is a failed exchange, so serve-stale still applies to it.
- Managed forwards (ADR-040) take `stub: true`: the entry becomes one upstream `forward:<domain>#stub` (url `recursive://`, the stub fields) in the group `forward:<domain>`, with the same route and NTA as a forward. Servers must be IP addresses (`udp://` + address is accepted); anything else is refused with a hint. `GET /forwards` reports `stub` and the addresses. MCP `plan_forward_domain` takes `stub`; the UI's "Send a domain to another server" has a checkbox, named by what it means ("these servers only know this domain").
**Consequences:** Authoritative-only servers become usable as targets and stop flapping, and delegated sub-domains resolve. Ports other than 53, TSIG, and NS priming aren't supported. A stub zone's out-of-zone CNAME targets are resolved from the root rather than through the default group, which bypasses an encrypted forwarder for those names (documented). Plain forwards still health-check with `. NS`; making their check ask the route's apex is a separate change. A node one version behind refuses a configuration with the new keys (`deny_unknown_fields`), as with any new key: in a cluster, upgrade replicas first.

## ADR-152 — Internal names: their own top list, not hidden (Proposed)
**Context:** OBS-037. Once the kubelet points every pod at TelltaleDNS (FLT-017), the dashboard's top lists fill with the cluster's own names: Services asked constantly, and a pod's `ndots: 5` search list turns one lookup of `api.github.com` into three NXDOMAINs under `cluster.local` first. Reverse lookups of private addresses are the same kind of noise on any network. The only way to hide names was `[exclusions]` (OBS-022), which also drops them from the query log and exports, and so from the workload view's point. The owner chose a separate list, with private reverse lookups included (2026-10-19).
**Decision:**
- An internal name is a reverse name in the RFC 6303 private and local ranges (the same as `[special] private_ptr_nxdomain`), a name at or under `cluster.local` when `[kubernetes] enabled`, or one under a suffix in `[telemetry] internal_names` (at most 100; node-local like the rest of `[telemetry]`, so a replica one version behind never sees it).
- The aggregator counts an internal name in the hour's `internal` Space-Saving list (and the group's) instead of `domains` and `nxdomain`. The blocked list, the bad-answer lists, a device's own top domains, the time series, the query log, the live view, exports, and `/metrics` are unchanged: this sorts, it hides nothing.
- The check runs on the aggregator thread before privacy hashes the name (`Aggregates::record_private`): a few suffix lookups, no allocation. Top lists rebuilt from a privacy-hashed query log after a restart can't tell and count those names as domains.
- `GET /api/v1/stats/top?kind=internal` (with `group`; not with `client`), MCP `top_items` `kind: internal`, `hour_top` kind `internal`. A peer one version behind refuses the kind and is listed in `missingNodes`.
- The dashboard's Top domains card switches between **Internet** (the default) and **Internal**; the switch asks for one list at a time.
**Consequences:** The domains and NXDOMAIN lists change meaning for existing installs (less noise); history from before keeps both kinds in `domains`. A cluster domain other than `cluster.local` needs `[telemetry] internal_names` on each node: the chart doesn't write it, so a new chart still works with the previous image.

## ADR-151 — Failover drills: a maintenance window with a drop, a federated coverage report (Proposed)
**Context:** CLU-014 (owner request 2026-10-18). Routers hand devices two DNS servers (the Pi and the homelab's .112), but a stub resolver uses its first server until it stops answering, so on a healthy network nothing shows whether the second one works for every device; a passive "single-homed" finding would be guesswork. Design: `docs/design/failover-drills.md`.
**Decision:**
- **A drill is a maintenance window with a drop** (reuses OPS-010/ADR-118: readiness off, alerts muted, out of elections and the health level, the window file, forwarding, handover on the primary). For its targets (addresses or names, a group, or everyone) the node discards UDP queries after client identification and before rate limiting, and closes TCP, DoT, DoH and DoQ connections without an answer: the nearest thing to a dead node. Each counts as a new query status `drilled`.
- **Query path:** one relaxed load of the drill's end time (0: none); only during a drill, one `ArcSwap` load of the target set and a lookup. Never dropped: `[clients] infrastructure`, loopback, the node's own and other cluster nodes' addresses, and excluded devices (OBS-022).
- **Bounds:** 15 to 300 s, default 60; the cap is not configurable (a long drill is an outage). Ends on expiry or `DELETE`. A restart **cancels** a drill (unlike maintenance, which resumes).
- **Preconditions** (409 `drill_refused` with the reason): another node ready and answering in the last 5 minutes; no maintenance on the node and no drill anywhere in the cluster in the last 10 minutes; no pinned or baking rollout (CLU-013); health not `severe`; targets that resolve to a device seen on the node in the last hour (unless everyone). Not a configuration change: allowed under GitOps authority, audited, `operator` role; agents need the scope `ops:drill` (not in the defaults) and a reason.
- **Coverage:** a per-client seen table on the telemetry thread (baseline, affinity; 4,096 cap, persisted); a per-client window map on every node while any node drills (learned from the heartbeat's new `drill_id`), frozen 60 s after the end; the drilled node merges the parts (federated read, retried 5 minutes) into a saved report (last 50 kept) with verdicts `followed` (answered elsewhere after the first drop, by 5 s after the end) / `stuck` (≥ 3 dropped, no such answer) / `quiet` / `elsewhere`, time to failover, and `returned` vs sticky after 15 minutes.
- **Interfaces:** `POST/DELETE/GET /api/v1/nodes/{id}/drill` (`dryRun`), `GET /api/v1/drills[/{id}]`, `GET /api/v1/clients/affinity`; MCP `plan_failover_drill`, `drill_report`; the Cluster page's **Drill…** and Drills list; metrics; annotations `drill.started`/`drill.ended`. Never a health reason.
**Consequences:**
- The first real drill should be on the owner's own laptop for 30 s, then a group, then everyone; never run against the live Pi without the owner's go.
- Scheduled drills and a REFUSED mode were open questions; the owner said yes to both (below), and both are built.
- Devices that never queried during the window are `quiet`: a drill can't tell an idle device from one without DNS.

**Amendments at implementation (T15.2, 2026-10-19):**
- **Closing connections:** a new `Response::Close` in `telltale-net`. TCP and DoT close the connection; UDP drops; DoH and DoQ answer nothing but keep the connection, because HTTP/2 and QUIC multiplex other queries on it.
- **"Loopback" is the node itself:** `127.0.0.1` and `::1` are never dropped, nor held by FLT-017's analytics hold. Other 127.0.0.0/8 addresses are ordinary clients: the cluster e2e's stub resolvers bind them. Masking's infrastructure list (which has all of 127/8) is used without its loopback entries.
- **Who's in the report:** the targets seen on the node in the hour before (the baseline's targets), any device the node dropped, and any device another node answered during the window. A non-target the drilled node answered as usual is left out. A target with 1 or 2 unanswered queries and nothing elsewhere is `quiet`: too little to tell.
- **The window starts at once:** the drilled node calls every peer (`drill` peer call, 1 s deadline) before it drops anything, and the heartbeat's `drill_id` is the fallback. A new heartbeat flag `drills` tells an older peer (missing) from one that recorded nothing.
- **Returned:** checked from the drilled node's seen table (to the second) 15 minutes after the end.
- **Seen table size:** each entry keeps 7 daily counts for the affinity view, about 70 bytes rather than the design's 40 (under 300 KB at the 4,096 cap).
- **Markers:** `drill.started` and `drill.ended` are new marker kinds; a drill's maintenance window leaves no `maintenance.*` markers of its own.
- **Test hooks:** `TELLTALE_DRILL_GAP_SECS`, `TELLTALE_DRILL_RETURN_SECS`, and `TELLTALE_DRILL_RETRY_SECS` shorten the 10-minute gap, the 15-minute check, and the 5-minute retry for the cluster e2e. `TELLTALE_DRILL_IGNORE_HEALTH` passes the health check (shown as ignored in the checks): the e2e's nodes have no working upstream, so their health is severe.
- **CLI:** `telltale ctl drill start|stop|report` over the API (the design's local `telltale drill` subcommands are the same calls; only `ctl` is built).

**Owner decisions (2026-10-19, the open questions):**
- **Scheduled drills: yes.** `[drill] schedule = "monthly"` with `nodes` (the nodes that drill themselves), the targets (`group` or `clients`, else everyone), `for_secs` (default 30), `hour` (default 3) and `tz`, and `mode`. The day is in the first week, picked from the node's label and the month (FNV-1a), so it moves from month to month; the node tries once a minute through the hour, skips the month if a precondition fails all hour, and never drills within 7 days of another drill. The report goes out through a new one-off alert kind `drill_report` (any drill, scheduled or not, reports ended in the last 2 hours) to whatever destinations the rule names, email included. Shared configuration, so `nodes` says where it runs.
- **REFUSED mode: yes.** `mode: "refused"` (API, form, MCP, `ctl --refused`, `[drill] mode`): the node answers REFUSED with extended error 14 (Not Ready, "failover drill") at once, still counted as `drilled`. Drop stays the default; the preview says the REFUSED drill is faster but less realistic.
- **The live Pi: yes**, laptop first for 30 s, then a group, then everyone.

**After the first live drills (2026-10-19, owner go):**
- **What ran:** the laptop was skipped: on Wi-Fi its only DNS server is the homelab's 10.50.5.112, so the Pi never sees it (only the agent's own test lookups). The IOT group for 30 s; then everyone except the homelab server 10.50.5.2, for 30 s. The homelab server was left out because its only DNS server is the Pi and k3s's CoreDNS forwards through it, so dropping it would cut external DNS for the host and its pods.
- **Two verdict rules were too loose, and are tightened** (owner yes): an answer elsewhere counts as following only by 5 s after the end (`FOLLOW_GRACE_MS`): after that the drilled node answers again, so it proves nothing (the IOT drill had a "48.6 s failover" in a 30 s drill). And a target with nothing dropped is `quiet`, not `followed`, even when it asked another node (the second drill dropped nothing at all, yet said 5 followed and 100 % coverage). A device that asked the other node both before and after its first drop still follows, with no time. The windows still record 60 s after the end.
- **A drill on a resolver pod (owner go):** the pod left the EndpointSlice about 14 s after the start (`balancerSwitchMs` 12,652; 3 of the first 13 probes on .112 timed out, none after). Two changes (owner yes): the chart's readiness probe is every 2 s with 2 failures (about 4 s, for maintenance and real failures too), and **the primary relays**: a node reaches only the peers it has a stream to (a resolver pod only the primary; the Pi no resolver pod), so the report had missed every node but the drilled one and the primary, on the Pi's drills too. A new peer call `relay` on the primary passes a window notice or a read (part, list, report, active, seen) on to its peers that the caller didn't reach, and answers with theirs; never a start or end, never a relay. A node that learns of a drill this way has no heartbeat from the drilled node, so its window runs to the drill's end (the cutoff comes from the drilled node's own end), and it holds the one-drill-at-a-time rule until then plus the gap. An older primary refuses the call: the report is as before.

## ADR-150 — Kubernetes workloads as devices: a read-only pod watcher on the controller, a synthetic analytics key, groups from labels (Proposed)
**Context:** FLT-017 (owner request 2026-10-18). On the homelab k3s node, pods are clients like any other, but a pod address names nothing and changes on every rollout, so a Deployment's three replicas look like three short-lived devices and per-device analytics (baselines, rhythm, timeline, new-device status) restart each time. Nothing in the code talks to the Kubernetes API today, and the chart mounts no service-account token (ADR-120 keeps secrets off resolver pods). Design: `docs/design/kubernetes-workloads.md`.
**Decision:**
- A **workload** is `(namespace, kind, name)`, kind `deploy`/`sts`/`ds`/`job`/`cronjob`/`pod` (`rs` when a ReplicaSet lacks `pod-template-hash`), derived from the pod's `ownerReferences` alone; a Job whose name ends in `-<digits>` is a CronJob run (suffix stripped). Text form `ns/kind/name`. Host-network pods are skipped.
- **Watcher:** only the process that has a service-account token (the controller in `scaled`/`daemonSet`, the pod in `allInOne`) lists and watches `pods` and `namespaces` with the existing rustls HTTP client and a minimal `serde` struct: no Kubernetes client crate. Token re-read every 5 minutes; `410 Gone` or any error re-lists after a jittered 1–60 s backoff; a full re-list every 10 minutes. A node without the in-cluster environment logs one `info` line and does nothing.
- **Table:** `Workloads` in `telltale-policy`, an `ArcSwap` rebuilt (debounced 500 ms) on change, capped at 20,000 pod addresses. Node-local operational state like the neighbor table: no configuration version, no snapshot replication. The controller pushes it to peers on change (peer call `workloads.table`, debounced 2 s) and peers pull every 60 s; older peers answer "unknown call" and are skipped.
- **Query path:** `ClientTable::identify` consults the table after client ID, EDNS MAC and neighbor MAC, before IP/CIDR and the network group, only when the table is non-empty; a hit is `IdSource::Workload`. A workload wins over a `[[client]]` keyed by a pod address (stale after a rollout).
- **Groups:** pod label `telltaledns.io/group` > namespace label > first `[[kubernetes.map]]` rule (namespace glob, optional kind) > `[kubernetes] default_group` > the network group or `default`. The table stores group **names**; indices are resolved against the current `ClientTable` whenever either changes, so a configuration reload can't leave a stale index. An unknown group from a label is logged once per value and treated as unset; an unknown group in `[[kubernetes.map]]` is a validation error.
- **Analytics key:** the aggregator substitutes a synthetic address for the pod address, for analytics only, where an event is drained: the RFC 6666 discard prefix `100::/64` followed by the first 8 bytes of BLAKE3(`ns/kind/name`). (The design note said 12 hash bytes after `100::`; that would leave the discard prefix, so the prefix keeps all 64 bits.) The query log keeps the real pod address.
- **Names at read time** (extends ADR-125): pod addresses carry up to 8 `(workload, from, to)` intervals over 30 days, persisted to `<data_dir>/workloads.json` hourly and at shutdown; the query log, timeline and live tail name a row by the workload that held its address at the row's time. A deleted pod's address stays mapped for 30 s (in-flight queries), then moves to history.
- **Chart:** `kubernetes.enabled` (default `false`) mounts the token on the controller/allInOne pod only, creates a ClusterRole with `get/list/watch` on `pods` and `namespaces` and nothing else, and writes `[[forward]]` entries (cluster domain and optional pod/service reverse zones, with a DNSSEC NTA) to `kubernetes.clusterDns`, which the schema requires when enabled. `service.dns.clusterIP` fixes the DNS Service address for the kubelet's cluster DNS.
**Consequences:**
- One `ArcSwap` load and hash lookup per query when the table is non-empty, none otherwise; one lookup per event on the telemetry thread.
- The API server being unreachable leaves the last good table in place; `kubernetes_stale` makes health **degraded** after 15 minutes, and `telltale_kubernetes_*` metrics count errors. Answering is never affected (CLU-004).
- Pods are only seen as themselves when they query TelltaleDNS directly (cluster DNS pointed at it, or per-workload `dnsConfig`); through CoreDNS forwarding they all appear as CoreDNS.
- A CronJob's runs are one device; the run name is evidence.
- Non-goals: answering `cluster.local`, namespace egress allowlists, more than one Kubernetes API per controller.

**Amendments at implementation (T15.1, 2026-10-19):**
- **Another controller owns the pod** (an operator's custom resource; the design named only the built-in kinds): that owner is the workload, kind = its kind in lower case, so its pods stay one device across restarts. A map rule can't name such a kind (the validated list is the built-in ones); a namespace rule or a label covers it.
- **A pod first seen terminating** (or finished) is never added: it has no queries of its own to attribute. One seen running and then deleted keeps its addresses for the 30 s grace period.
- **The chart's forwarding** is TOML the chart appends to the values file (`[[upstream]] kubernetes-dns`, `[[upstream_group]] kubernetes`, a `[[route]]` with a DNSSEC NTA), not a separate file: layered files replace arrays, so a `[[upstream]]` in `config` would otherwise drop it. Reverse zones are the pod and service CIDRs rounded down to whole octets (IPv4 only). Kubernetes options go through the chart's values, not a `[kubernetes]` table in `config`.
- **Per-workload counts** (queries and blocks over 24 hours, last seen) are kept per node on the telemetry thread, only for events whose client is a workload key (at most 20,000 workloads), and summed across nodes for `GET /api/v1/kubernetes/workloads` (`Read::WorkloadCounts`; a node that doesn't answer is in `missingNodes`).
- **Time-aware filters:** `client=<workload>` on the query log, the vqlog `client` condition, and the device timeline match a pod address only while that workload held it (from the history). The query log searches the addresses (at most 64, `clientTruncated`) and then drops rows outside the workload's stretches, so a page can hold fewer rows than `limit`.
- **API-made map rules come first**, before the files' rules (first match wins), so "Add to group…" on one workload wins over a namespace glob in the files; they replace or hide a file rule with the same key (`namespace/kind/name`, `*` for any).
- **Simulation** replays with an empty workload table: a pod address takes the group its row was logged with (what the simulator already does for devices recognized by MAC), so changing a map rule isn't simulated.
- **Extra metrics:** `telltale_kubernetes_watching` (1 on the node that watches, which the alert needs) and `telltale_kubernetes_addresses_dropped`.
- **Rebuild debounce 50 ms, not 500 ms:** a Job's pod asks DNS within about a second of getting its address; at 500 ms its first queries counted under the address (seen on a kind cluster: a CronJob at zero queries). A rebuild of hundreds of pods costs well under a millisecond on the watcher's thread. A pod's first queries can still beat the table; the query log names them by the workload anyway (the address's first stretch starts at the pod's creation).
- **The analytics wait up to 2 s for an unknown address:** even at 50 ms, a CronJob run's queries (about a second after its pod is created) beat the watch event that carries its address, so each run counted as a new device under its bare address and the workload showed zero queries. While Kubernetes is on (from the node's start, before the first table arrives), the aggregator holds a query from an address the table doesn't name for up to 2 s (at most 8,192 records, about 2.5 MB), then counts it keyed by the table it finds. A table change lets everything out at once, so each address's records stay in order. The query log, the live tail and the exports are never held; only the aggregates and the anomaly engine wait. The cost on a node that also serves a LAN: its devices' dashboard numbers lag by up to 2 s while Kubernetes is enabled.
- **A restart of TelltaleDNS keeps the workload analytics:** the startup replay of the query log (OBS-004) keys each row by the saved history (the workload that held the address at the row's time), so the restored hours list workloads, not pod addresses. Each workload's 24-hour counts are saved hourly and at shutdown in `workload-counts.json`, beside `workloads.json` but separate, because counts are per node and the table travels to peers. They are folded back in at start. A crash loses at most the last hour's counts.
- **A map rule applies at once:** a configuration reload wakes the watcher, which rebuilds the table if `[kubernetes]` or the group names changed. Before, it waited for its next one-second tick, and a query right after "Add to group…" could still get the old group (found by the Playwright test). Other nodes get the rebuilt table by push, within a few seconds; the preview says so.
- **Table memory:** the first build took 544 KB of heap for 1,000 pods (AC 8 asks under 300 KB), mostly per-address history vectors with spare capacity, a sparse hash map, and a copy of the workload name per interval. The history is now a sorted array of exact-size lists, searched by binary search because it's never read on the query path. Names are shared strings, one per workload. Measured: 288 KB (`flt_017_table_and_history_for_1000_pods_under_300_kb`).
- **Test hook:** `TELLTALE_KUBERNETES_FIXTURE=<file>` makes a node watch a JSON file of pods and namespaces instead of an API server (the cluster e2e, the UI tests, demos).

**After the first live rollout (2026-10-19):**
- **The chart's route to CoreDNS is node-only.** Upstreams, groups and routes are shared settings, so the primary in the homelab's k3s cluster replicated `kubernetes-dns` (`udp://10.43.0.10`) to the Pi. The Pi can't reach a ClusterIP: every `cluster.local` lookup there timed out to SERVFAIL, and its health went **severe** ("no upstream in group kubernetes is answering"). The design never considered a cluster with members outside Kubernetes, and the Helm e2e has none. `node_only = true` (CLU-006, until now on `[[record]]` only) now also works on `[[upstream]]`, `[[upstream_group]]` and `[[route]]`, and the chart sets it on all three. The primary leaves them out of the shared part; a replica keeps its own and, if a shared upstream or group has the same name (an older primary, mid-rollout), uses its own instead. Validation refuses anything shared that points at a node-only entry: a shared group listing a node-only upstream, or a shared route, a client group's `upstreams`, or `upstream_check.reference` naming a node-only group. The conservative choice: a narrower `[kubernetes]`-only switch would hide the same problem for anyone forwarding to a network only one node reaches. Test: `flt_017_kubernetes_route_stays_on_the_nodes_in_the_cluster`.
- **Reverse zones and a node whose DNS is TelltaleDNS:** CoreDNS's `kubernetes` plugin passes reverse names it doesn't know (`fallthrough in-addr.arpa`) to its `forward`, the node's DNS servers. Once those include TelltaleDNS, an unknown pod-range PTR would loop. The homelab leaves `podCidr`/`serviceCidr` empty; the values comment says when to.
- **TelltaleDNS's own pods ask CoreDNS.** With the kubelet's cluster DNS pointed at TelltaleDNS, the chart's own pods (`ClusterFirst`) would ask their own Service first, so a restart of all of them depends on CoreDNS second answering after a timeout. `kubernetes.ownPodsUseClusterDns` (on by default) gives them `dnsPolicy: None` with `clusterDns` as their only server and the usual search list; it only applies with `kubernetes.enabled`, where `clusterDns` is required.

## ADR-149 — HTTPS on the API listener: your certificate or a self-signed one, plain HTTP redirected (Proposed)
**Context:** API-003 wants TLS for anything carrying passwords; ADR-029 left TLS on the API listener for later (the session cookie's `Secure` flag and HTTP Basic depend on HTTPS, which until now only a TLS proxy in front could give). The live review of 2026-10-14 (item 8) found the Pi's UI on plain HTTP: sign-in form passwords cross the LAN in the clear. The owner chose a self-signed certificate made on first start for the Pi, and a redirect for plain HTTP on the same port (2026-10-18).
**Decision:**
- `[api] tls = { self_signed = true }` makes an ECDSA P-256 certificate (every browser accepts the algorithm) on first start, for `localhost`, `127.0.0.1`, `::1`, the host's name and `<name>.local`, the listen address, and the addresses the host reaches the network from; kept in `<data_dir>/api-tls/` (the key readable by the user only) and reused. It never expires (rcgen's defaults); deleting the directory makes a new one. `{ cert, key }` uses the operator's PEM files, re-read within 10 s like the DNS listeners' (`CertStore`).
- The listener tells TLS from plain HTTP by a connection's first byte (0x16, a TLS handshake record). Plain requests get `307` to the same URL over `https://` (temporary, so turning TLS off again leaves no cached redirect), except `/livez`, `/readyz`, and `/healthz`, which keep answering plain health checks (`telltale health`, the Compose healthcheck). HTTP/1.1 only, as before.
- Requests over the listener's TLS carry a marker extension (`TlsConnection`) that `is_https` honours from any peer, so the session cookie is `Secure` and HTTP Basic works, exactly as behind a trusted TLS proxy.
- HSTS (`max-age=31536000`) only with the operator's own certificate: with HSTS a browser offers no way past a certificate warning, and a self-signed certificate is one until it's trusted.
- If the certificate can't be made or loaded, the API stays off (logged) rather than serving plain HTTP; DNS keeps answering. Changing `[api] tls` needs a restart (the API listener starts once), and a reload says so.
- `telltale ctl` and `telltale mcp --stdio` use `https://` when the config has `[api] tls`, trust the node's own self-signed certificate, and take `--ca-file` for another node's.
- The listener checks (OBS-020) include the web UI (`proto = "api"`): a `GET /livez` over HTTPS, and its certificate's expiry, SHA-256 fingerprint, and names, with the same health reasons, alert rule, and metric as the DNS listeners' certificates. It never counts toward `not_serving` (that's about DNS). Every listener's certificate now shows its fingerprint and names too.
**Consequences:** sign-ins on a home network are encrypted with no setup beyond one line, at the cost of a browser warning (or importing the certificate once). The Helm chart is unchanged: in Kubernetes an ingress terminates TLS. The cookie's `Secure` flag stays conditional (ADR-029): plain HTTP without `[api] tls` still works.

## ADR-148 — Stream upstream connections: handshakes outlive their query, silent connections are closed, every connection is counted (Proposed)
**Context:** the live review of 2026-10-14 (item 5): about 2 % of DoT attempts to Quad9 failed (network errors, about twice the timeouts), hidden by retries, and forwarded answers took 51 ms at p90 with a 10 ms round trip. UPS-008 asks for pooling with an idle timeout, and `spec/04` §5 lists the pool size and TLS handshake count among the exported metrics, which didn't exist; nothing showed how often connections opened or why they ended. Two gaps were found in the pool: a new connection was opened inside the query's attempt timeout (about 3 × the EWMA + 50 ms, often under 100 ms), so a handshake slower than that was abandoned with the query and the next query started another; and a connection dropped silently along the way (no FIN, no reset) stayed the least-loaded one in the pool, so every query on it timed out until TCP gave up, possibly for minutes. The owner asked for the item to be fixed (2026-10-18).
**Decision:**
- A pool opens a connection in a task of its own: the query's timeout still applies to the query, but the handshake finishes and the connection joins the pool for the next one.
- A pooled connection with a query waiting 3 s or more, and nothing at all received in those 3 s, is closed (`unanswered`); queries still waiting on it get a closed channel and retry once on a new connection (the T10.9 retry). 3 s is longer than any attempt timeout (at most 1 s), so a single slow answer on a quiet connection isn't mistaken for a dead connection. Waiters that gave up are dropped 3 s after their query went out, so a connection can idle out again.
- New metrics per stream upstream (TCP, DoT, DoH, and UDP's TCP fallback): connections opened (`ok`/`failed`), the time spent opening them, TLS handshakes `full`/`resumed`, pooled connections closed by reason (`idle`, `server`, `write_failed`, `unanswered`, `unused`), retries on a fresh connection, and open pooled connections.
- Not done yet: RFC 7828 (edns-tcp-keepalive, to learn the server's idle timeout) and keeping a connection warm with periodic queries. The new metrics show whether servers close idle connections first (`reason="server"`) and how often a quiet upstream reconnects, which decides whether either is worth it.
**Consequences:** a silently dropped connection costs its queries at most about 3 s once, instead of a timeout per query until TCP gives up; a slow handshake is paid once, not once per query. Connection churn and session resumption can be read from metrics. Each connection with queries waiting wakes every 500 ms to check; an idle one doesn't.

## ADR-147 — A list that shrank a lot waits for the same content again (Proposed)
**Context:** FLT-004 keeps a list's last good copy when a download fails, and refuses bodies that can't be a list (empty, HTML, mostly invalid lines, over the size cap). A body that *is* a list but much shorter passed every check: in the live review of 2026-10-14, hagezi-tif went from 2.55M to 1.53M lines over ten days, unnoticed. A truncated mirror or a source caught mid-rewrite would have dropped blocking the same way. The owner chose to add a guard (2026-10-18).
**Decision:**
- `[filter] max_shrink_percent` (default 50, 0–100; 100 = off). A URL list's download that differs from the stored copy and has lost more than that share of its lines is *held*: not stored, not compiled; the stored copy, its validators, and its schedule stay (a held download isn't a failure, so there's no early retry); its hash is kept in the list's metadata and the reason is the list's error on the Lists page and in the log.
- The next download with the same hash is accepted (the next scheduled refresh, or a manual one: "Refresh now" is the way to accept a shrink at once). Different content is judged afresh against the stored copy.
- Not held: stored copies under 1,000 lines (their size swings with a few edits), `path` and inline lists (they shrink because someone edited them), and a changed source URL.
**Consequences:** a list that genuinely shrinks a lot takes one refresh interval longer to apply (the stored, larger copy keeps blocking meanwhile, the safe direction). A source that keeps serving different truncated bodies is never accepted while each one stays below the threshold, which is the point. Gradual shrinking (like tif's, a few percent a day) isn't caught; the Lists page's line counts remain the way to notice that.

## ADR-146 — Supply chain: auditable binaries, SBOMs from them, keyless image signatures, reproducible builds (Proposed)
**Context:** T10.10 (NFR-005: `cargo-deny`, `cargo-auditable`, a CycloneDX SBOM, cosign-signed images, reproducible builds). `cargo-deny` already ran in CI and the binaries were already minisign-signed (ADR-046); the rest was missing. Two clean builds of the same tree differed: C code linked into the binary (mimalloc) embeds `__TIME__`, and the build date stamped into `--version` was the time of the build.
**Decision:**
- Release binaries are built with `cargo auditable` (pinned, checksum-verified like the other build tools): a compressed dependency list in a `.dep-v0` section, which CI checks is present in every binary.
- The SBOM is read from the binary, not from `Cargo.lock`: `syft` (pinned) writes one CycloneDX JSON per binary (`telltale-<arch>-linux.cdx.json`), checked to list the crates it should, published with the release, and covered by the minisign-signed `SHA256SUMS`.
- Images are signed by digest with cosign, keyless (the image workflow's GitHub OIDC identity; Fulcio certificate, Rekor log), on every push to `edge` and every release tag; the workflow verifies the signature it made, and `deploy/release/verify.sh` checks it for stable releases. No signing key to keep.
- Builds are reproducible from the commit: the build date is the commit's time, and `SOURCE_DATE_EPOCH` (the commit's Unix time) is passed to the Docker build, so compilers take `__DATE__`/`__TIME__` from it and BuildKit stamps layers with it. A nightly job builds the amd64 release binary twice without cache and fails if they differ.
**Consequences:** `--version`'s "built" date is the commit's date. Reproducing a published binary needs the same build arguments the workflow passes (all derived from the commit and the run: version, commit, date, channel, `SOURCE_DATE_EPOCH`). The image job needs `id-token: write`. The nightly reproducibility check costs two uncached builds (about 20 minutes each on a runner).

## ADR-145 — A recompiled filter goes live before its FSTs are written (Proposed)
**Context:** T10.3 (FLT-003, `00` §5: a 2M-name recompile within 8 s on a Pi 4). On the Pi the one-thread recompile took 11.8 s, 8.1 s of it building the domain FSTs (the `fst` crate's builder, about 4 µs a name on one core); two threads cost more p99 during the compile, so the owner kept one thread (2026-10-17) and chose this change. The FSTs are the snapshot's on-disk form (cold start, replication, the walk fallback); queries are answered from the hash index (ADR-020), which `load` used to build from the FSTs after the compile.
**Decision (owner, 2026-10-17: "I'll follow your recommendation"):**
- The compile merges the sorted records twice. The first pass computes each name's list set as before and fills the lookup index directly; with the modifier and regex tables (written first) it makes a matcher over a *pending* snapshot (no FSTs), which the server serves at once. The second pass writes the FSTs and `listsets.bin` exactly as before, and the snapshot directory is finished as before.
- When the finished snapshot is loaded, it reuses the pending matcher's index (same version, same list-set table) instead of building another; the FST pages are released at once.
- The 8 s gate is measured to when the recompiled filter answers (`CompileTimings::ready`); the total compile is reported too.
- If the second pass fails (a full disk), the previous filter is put back, so a node never serves a filter it has no snapshot of.
- Not for: a pinned cluster (the pin is served), or a snapshot past the index's 65,536 list sets (it waits for the FSTs and uses the walk, as before). Replicas still get the finished snapshot, after the second pass, as before.
**Consequences:** a list change answers about 40 % sooner on the Pi; the compile does a second merge pass after that (more CPU in all, at `SCHED_IDLE`), and holds the index while writing the FSTs (the compile's peak grows by the index, about 11 bytes a name). The index is sized from the record count, not the distinct names (a few percent larger when lists overlap). While pending, `Snapshot::domain_hits` (a test and explain helper over the FSTs) returns nothing; explain itself goes through the index.

## ADR-144 — Memory: purge freed memory at once, release code pages after one-off work (Proposed)
**Context:** T10.2 (NFR-001, `00` §5: ≤ 20 MiB idle, ≤ 64 MiB with 1M names and 100k cache entries). With the shipped musl build the node measured 22.7 MiB idle and 71.4 MiB loaded. Two things held memory nothing used: mimalloc's 10 ms purge delay kept a compile's freed pages (a 170 MiB peak, about 5 MiB after), and about 15 MiB of the 25 MiB of code stayed resident after running once at start-up, plus the kernel's fault-around neighbours.
**Decision:**
- mimalloc's `purge_delay` is set to 0 at the start of `run`: freed pages go back to the OS right away. The query path doesn't allocate (NFR-002), so the extra `madvise` calls land on misses, compiles, and background work.
- 15 s after start-up, and after each filter index build, a background thread drops this process's mappings of the executable's read-only pages that hold no private (copy-on-write) copies (`MADV_DONTNEED`). The pages stay in the page cache; code that runs again maps them back with a minor fault. Writable mappings and any with anonymous pages are never touched.
- Both live in `telltale-net` (the only crate allowed `unsafe`), using the `libmimalloc-sys` already linked (no new crate).
**Consequences:** idle 13.7 MiB, loaded 60.0 MiB, compile peak 97.5 MiB (shipped build, `bench/memprobe.py`). The first query after a trim may take a few minor faults (microseconds each) for code that was dropped. RSS creeps back up by the code periodic work touches (about 1 MiB over 3 minutes in the probe). Off Linux both are no-ops.

## ADR-143 — Cluster members are trusted by the registry, never by their word (Proposed)
**Context:** T10.7 security review (`docs/security-review.md`, findings C1, C3–C6). A member the registry didn't list (a resolver pod that left or expired, then reconnected with its still-valid certificate) was taken at its word: its Hello's eligibility was recorded, so it could get the cluster key, and its epoch could fence the primary. Pods also received every user's password hash and TOTP secret, and could ask other nodes to run simulations.
**Decision:**
- A member the registry doesn't know comes back as a plain **ephemeral** member: not eligible, not a witness, no key share, no epoch announcements, and it expires again when it stops being heard from. A cluster from before registries (taken at its word before) has to re-join such nodes; every release since v0.1 records members at join.
- Vote requests are answered only for candidates the registry lists as eligible and not witnesses.
- RPC answers count only on the stream of the peer that was asked (C2); request IDs start at a random value.
- The users-and-tokens blob isn't served to ephemeral or unknown members, and pods (`[cluster] ephemeral`) don't fetch it and drop any copy an older version gave them. Pods serve no API (the chart's API Service selects only the controller), so nothing users do changes.
- Peers the registry doesn't list are treated as ephemeral for forwarded writes, maintenance, rollouts, and simulations; ephemeral members can't run simulations, and a peer's simulation can't name a list file this node doesn't read, turn on link-local downloads, or exceed this node's window and limits.
- The primary accepts at most 30 joins a minute (`429` past that). A sender may have 4 unfinished shipped segments; a segment for an hour outside retention (or more than a day ahead) is acknowledged and dropped (an error would stall the sender); only registry members can ship.
**Consequences:** before rolling this out, each live node's registry must list every node (a read-only check), or the change could demote one. A pod scale-out of more than 30 in a minute takes a little longer.

## ADR-142 — Account changes need a signed-in session (Proposed)
**Context:** T10.7 security review (finding A1). Any credential (an API token, an agent token, HTTP Basic) could change its account's password and two-factor sign-in, and create or revoke the account's tokens. A leaked token could then take the account over, or mint tokens that outlive its own revocation.
**Decision (owner, 2026-10-17: "Signed-in sessions only"):**
- `POST /auth/password`, `POST /auth/totp/{setup,enable,disable}`, `POST /tokens`, `DELETE /tokens/{id}`, and `POST /displays` answer `403` unless the request comes from a signed-in session (cookie and CSRF token). Revoking a display (`DELETE /displays/{id}`) stays open to admin tokens: it only takes access away.
- The current password in those requests is checked like a sign-in (A2): the bounded concurrent checks, failures counted, and the account locked after five.
- A password changed or an account disabled on the primary ends that user's sessions on replicas too, and drops cached Basic results (A3).
- A token made in two writes (an agent's or a display's) is deleted if the second write fails (A4).
**Consequences:** scripts that minted tokens with a token must sign in first (`POST /auth/login`, then the cookie and `X-CSRF-Token`); the shipped e2e scripts already did.

## ADR-141 — Wall layouts for the screen's size and shape (Proposed)
**Context:** T14.15 (OBS-035; owner request 2026-10-17: "various sized screens ... we will not be using the available real estate"). One panel at a time wasted ultrawide, portrait, and large screens.
**Decision:**
- Screen classes from the wall's size in CSS pixels (so a 4K TV at 2× scaling is 1920 × 1080): `compact` (shorter side < 600), `portrait` (height > 1.2 × width), `large` (≥ 2560 × 1300), `ultrawide` (width ≥ 2.1 × height), else `standard`; the previous class is kept while a 4 % change would still give it (no flipping at a boundary).
- Per class, candidate templates (fractions of the panel area, the hero first, most slots first); `chooseLayout` takes the first one where every slot gets a panel at least its minimum size (`PANEL_MIN`): the hero the first panel that fits (the small-first panels saved), small slots (< 30 % of the area) the `kpi` and `slo` panels first; leftovers rotate in a slot they fit (the hero first). Pure and deterministic; tested across sizes for fit, overlap, fill, and placement.
- Owner's choices (2026-10-17, "proceed with your recommendations"): a large screen shows everything at once (no rotation); a new `kpi` panel ("right now": queries per second, blocked share, from cache, the health word, from `/stats/summary` and `/system/health`); the tail as a strip except on a large screen, where it's a column.
- `?layout=auto|single|grid|<class>`; one animation loop for every panel (`FrameHub`), stopping in a hidden tab; panels size to their slot (the SLO rings, the flow's labels hidden under 600 px).
- Default: display sessions may also read `GET /api/v1/system/health` (the tile's health word; what the header icon shows a viewer).
**Consequences:** a large screen polls every panel's data at once (as the dashboard would); the class comes from the whole wall while slots come from the panel area, so a large screen's tail column doesn't change its class.

## ADR-140 — Wall displays: a display token exchanged for a wall-only session (Proposed)
**Context:** T14.13 (OBS-035; T14.9's design §8). A wall on an unattended screen needed a sign-in that lasts without leaving a person's account there. The owner chose a display token over longer viewer sessions or nothing (2026-10-17), and to keep the live tail on the wall.
**Decision:**
- A display token is a token row with the pseudo agent scope `display` (`DISPLAY_SCOPE`) and optional `display_networks` (CIDRs). Admins make, list, and revoke them (`POST|GET /api/v1/displays`, `DELETE /api/v1/displays/{id}`; Settings → Users → Wall displays); they replicate with the other tokens, so every node accepts one.
- Its link is `#/display?code=tt_<id>_<secret>`: the code stays in the fragment (never in server logs). `POST /api/v1/auth/display` exchanges it for a session cookie marked with the token (`sessions.display_token`), from an allowed address; failures count toward the address's sign-in lockout.
- A display session acts as `viewer` named `display:<name>`, with no idle limit, until the token's expiry (default 400 days) or revocation (the session ends with the token); its networks are checked on every request; it may only GET `/auth/me`, `/system/info`, `/stats/*`, `/queries/stream`, `/annotations`, and POST `/auth/logout` (`display_allows`). The code is never an API token. The UI shows only the wall to it. Making, opening, and revoking are audited (`display.create`, `display.open`, `display.revoke`).
- Defaults: the pseudo agent scope (an older node in a mixed cluster reads it as an agent scope allowing nothing, so a display token can't act as a read token there); sessions survive the owner's password change (they belong to the token; disabling the owner ends them); the token's owner is the admin who made it (deleting that user deletes it).
**Consequences:** the wall's reads include the live tail (device and name), as for a viewer; a leaked link opens only that from the allowed networks until revoked.

## ADR-139 — A device's last identity change is kept and drawn on its timeline (Proposed)
**Context:** T14.12 (OBS-034, OBS-025; T14.8's deferral). The timeline had no way to say "this is when it started looking like a Roku".
**Decision:** each identification pass compares a device's new identity with its last: a different signature (`productId`) or class is a change; a score or level wobble, a first guess, or an unavailable previous identity isn't. The last change's time and the previous product (else class) are kept per device in `devices.json` (`changed_s`, `previous`) and shown as `DeviceIdentity.changedAt` / `previous`; the device timeline adds an `identity` event when `changedAt` is in its window. Only the last change, not a history (defaults: one change per device keeps `devices.json` bounded; a history would be a new store).
**Consequences:** a device that flips between two guesses shows only the latest flip; in a cluster the merged (most confident) identity's change is the one drawn.

## ADR-138 — Chatty loops are an informational finding (Proposed)
**Context:** T14.11 (OBS-036; T14.5's design §8). The 2.5 s NTP loop that overspent nothing but puzzled the owner is too fast for the beacon detector (30 s to 1 h) by design. The owner chose an informational finding (2026-10-17) over counting it like other findings or adding none.
**Decision:**
- At each hour's close a tracked pair whose hour has ≥ 120 gaps with ≥ 80 % in one rhythm bin from 1 s to 25 s (bins 1–8) is a `chatty_loop` finding, on devices past learning, once per streak: an hour that isn't chatty resets it. The evidence: the hour's queries, the typical gap (the 16-gap mean, else the bin's middle), the bin's share, and the rhythm strip (kept like a beacon's).
- `Kind::informational()` and `AnomalyFinding.informational`: the sidebar badge and the `anomaly` alert rule skip it; a new alert `when = "chatty_loop"` takes only these. Health never counted anomalies.
- Defaults: bins 1–8 (bursts under 1 s are A+AAAA pairs, not loops; 25–38 s overlaps the beacon range); learned devices only, like every detector; no per-domain baseline (a loop is a loop whether it's usual or not).
**Consequences:** the golden fixture is unchanged (its devices have no such loop); `telltale_anomalies_total{kind="chatty_loop"}` counts them.

## ADR-137 — An expired SERVFAIL is never served stale (Proposed)
**Context:** M14 follow-up (owner request 2026-10-17; found in T14.1). SERVFAIL is cached for 5 s (RFC 9520, `spec/03` §4), but the serve-stale path treated an expired SERVFAIL like any expired answer: with `stale_max_age = 3600` and `stale_answer_client_timeout_ms = 0` (the owner's 2026-10-10 settings), an hourly reverse lookup that failed once got the same SERVFAIL back for up to an hour, counted as `refreshed`, even after the upstream would have answered. Serving a stale failure gives the client nothing RFC 8767 is for.
**Decision:** an expired SERVFAIL entry is a miss (removed, asked upstream again), and `get_stale` never returns one. Fresh SERVFAILs are still served for their 5 s. Every other answer keeps serve-stale as before.
**Consequences:** a failing name is asked upstream at most every 5 s per node instead of being answered stale for an hour; bad answers that were `refreshed` SERVFAILs move to `forwarded` (or go away). The availability SLO stops counting the same failure many times.

## ADR-135 — The wall display: a kiosk layout over the existing reads (Proposed)
**Context:** T14.9 (OBS-035; design `docs/design/wall-display.md`). The pack's views, composed for a wall monitor; the screenshot that makes people try the project.
**Decision:**
- `#/wall` renders without the sidebar and header (signed in like any page), one panel at a time from `?panels=` in its order, `?every=` seconds each, with the live tail (`/queries/stream`) as a ticker of the newest 50. No new endpoints, metrics, or storage.
- Motion: tile tweens (600 ms, by key), up to 60 particles on the flow, a sliding progress hairline; none of it with `prefers-reduced-motion` or `?motion=off`; the animation loop stops while the tab is hidden.
- Defaults taken at the start (owner: accept all defaults, 2026-10-16): wall-specific panels over the same layout modules (the map, flow, and heatmap are pages, not components) and the latency heatmap component with a `wall` prop; the map shows the busiest names only; a click anywhere exits; the SLO needle on a log scale to 14.4 (replaced 2026-10-17 by the burn rate in words, toned amber from 1× and red from 6×: the needle read as a minus sign beside the number); the helpers in `ui/src/lib/wall.ts` checked by the Playwright spec importing them (no unit runner); rotation checked with a real 5 s timer; the Pi CPU figure, the demo screenshot and GIF left to do; a **Wall** link on the dashboard in the Advanced view. A viewer role or kiosk session (design §8) is an auth change for its own ADR, proposed to the owner.
- Owner request 2026-10-17: the Wall entry is an icon button in the header, between pause and the theme (Advanced view), not a link on the dashboard.
**Consequences:** the wall polls what the pages poll (top lists every 5 s, flow 10 s, SLO and latency 30 s, heatmap 5 min) plus one tail stream, so a wall costs about as much as a dashboard left open.

## ADR-134 — The device timeline: bounded vqlog reads folded into lanes, cached (Proposed)
**Context:** T14.8 (OBS-034; design `docs/design/device-day-timeline.md`). The owner found the 2.5 s NTP loop of 10.20.2.14 by hand; nothing showed one device's day with what happened around it.
**Decision:**
- `GET /api/v1/clients/{id}/timeline` runs three vqlog reads for the device (queries by registrable domain and status, slow answers by domain, every query with p99, per bin of whole minutes) and folds them into lanes (the top 30 by queries, `other`), a latency lane, and events: first-seen domains (OBS-009), the device's anomaly findings, and blocked bursts (≥ 10 blocked in a bin), with the change markers (OBS-033). Cached 30 s per request.
- Defaults taken at the start (owner: accept all defaults, 2026-10-16): vqlog on the entry node (its log and the rows shipped to it), not a new `Read::ClientTimeline`; vqlog's bounds (2M rows, 100k groups, 25 s) in place of 500k rows and 5 s; the latency lane included; identity changes not yet events (they need `changedAt`); agents `querylog:read`; level 1 lanes without domain, level 2 `422 privacy_level`; `id` an address; the deep link `#/clients?device=…&view=timeline` with a device drawer (Rhythm, Timeline); a table of lanes × at most 24 columns; `coverageFrom` from `retention_days`; MCP `device_timeline` at 24 bins and 10 lanes.
**Consequences:** a request scans the device's rows three times (block-pruned by client), at most once per 30 s for the same view; the answer for a 7-day, 2,016-bin, 50-lane request is about 50 × 3 × 2,016 numbers.

## ADR-131 — The rhythm strip: a log-spaced gap histogram beside the beacon detector (Proposed)
**Context:** T14.5 (OBS-031; design `docs/design/beacon-rhythm-strip.md`). The beacon detector measured inter-arrival regularity but nobody could see it; a 2.5 s NTP loop (too fast to be a beacon) was invisible.
**Decision:**
- Each tracked (device, eTLD+1) pair counts this hour's gaps in milliseconds into 24 log-spaced bins (bin 0 under 1 s, then ratio ~1.5 to ≥ 7,290 s; saturating `u16`) and keeps a decayed copy folded at each hour's close (`floor(previous / 2) + hour`). The 16-gap buffer and the beacon rules are unchanged, so the golden fixture is byte-identical; the strip shows more than the detector judges.
- `GET /api/v1/clients/{id}/rhythm` (federated `Read::ClientRhythm`, bins summed by domain), the Clients page's Rhythm drawer, the strip on beacon findings (`AnomalyFinding.rhythm`), MCP `get_client_profile.rhythm`.
- Defaults taken at the start (owner: accept all defaults, 2026-10-16): no level-1 mode with `domain: null` (the engine is off from level 1), so the read answers `422 privacy_level` from level 1; the beacon's snapshot kept beside the findings (`Engine::beacon_rhythms`, bounded like the findings) instead of inside `Finding`; the API's `recent` is the stored copy plus this hour; `u16` bins (1.63 MiB at 1,024 devices × 16 pairs, under the design's 2 MiB line), so the per-device state bound becomes T3.13's 4 KiB plus 1,664 B (`RHYTHM_BYTES`); `period` in words from the 16-gap mean when it agrees with the dominant bin, shown at ≥ 50 %; the Clients page gains a Rhythm drawer (it had none); cells shaded by share of the row's busiest bin, ink `--hm-ink`; agents `analytics:read`. A "chatty periodic" finding (design §8) is left as a proposal.
**Consequences:** one `partition_point` over 23 bounds and one increment per query to a tracked pair, on the telemetry thread; `anomaly.json` grows by the same 1,664 B per device (older files load with empty bins).

## ADR-128 — Node comparison: robust statistics on the entry node, honest about small bases (Proposed)
**Context:** T14.2 (OBS-028; design `docs/design/node-comparison.md`). The owner's cluster has two nodes of very different size (a Pi and the Kubernetes pods): a SERVFAIL share alone blames the smaller one for the same failures on a tenth of the traffic.
**Decision:**
- `GET /api/v1/cluster/compare` reads every non-witness node's buckets at once through the existing scoped timeseries read and computes on the entry node: no new RPC, no new storage, and older peers answer too. p50/p99 come from the latency histograms (OBS-030); a node with under 100 answers isn't compared on latency.
- Three or more nodes: robust z against the *other* nodes' median and MAD (MAD floored at 0.0005 for ratios, 10 % of the median for latency), odd at |z| ≥ 3 when the node's own Wilson 95 % interval also leaves that median out. Two nodes: odd when the intervals don't overlap *and* the gap clears the same floored threshold, on the worse node only. A `note`, not odd, for about the same bad count (within 3, or a third) on under a third of the others' base.
- `oddSince` is the change point of the node's cumulative excess over the others' pooled per-bucket rate (the latest minimum of the running sum), kept only when the node is still odd from there.
- Defaults taken at the start (owner: accept all defaults, 2026-10-16): the leave-one-out median, the interval guard for three or more nodes, and the floor for two (without it the design's AC 2 first case would be odd, since its intervals don't overlap); the change point in place of "walk back until it stops being odd" (which lands on the window's start whenever the whole window is odd); `400` (not `heatmap_window`) for a window too long for its step; sparklines of at most 240 points; agents `analytics:read`, MCP `compare_nodes`; the Cluster page polls it every 60 s on every tab for the tab's "N odd". Not a health reason or alert rule (design §8) until the owner has watched it.
**Consequences:** one comparison costs one timeseries read per node (as many as the dashboard's node picker would); everything is rounded, so the same data gives byte-identical JSON. The verdicts are only as good as each node's buckets: a pod that restarted reads only its new minutes (its shipped minutes count for the whole cluster's view, not per node).

## ADR-132 — Query flow: four exact joint counters, no proportional splits (Proposed)
**Context:** T14.6 (OBS-032; design `docs/design/query-flow-sankey.md`). The buckets had marginals (by group, status, rcode) but no joints, so a flow diagram would have had to guess. The owner decided four stages (2026-10-16).
**Decision:**
- Each minute bucket counts `group_status` for every answer, and either `status_upstream` + `upstream_rcode` (an upstream on the event) or `status_rcode` (none): every link in the diagram is a counter incremented for exactly that pair.
- Defaults taken at the start (owner: accept all defaults, 2026-10-16): `status_rcode` counts only the answers that asked no upstream (the design's AC had it count every answer, which can't then be split exactly for a status that sometimes asks an upstream); minute buckets only, as T14.4; a federated read says `partial` (not which node) for buckets without joints; a device from vqlog over the last 24 hours, whose own row cap sets `truncated` (in place of the design's 200k); a backend privacy-level read refuses `client` at level 2; the layout's invariants are checked by Playwright on the drawn SVG (the UI has no unit-test runner); `group_status` is kept in the rollups (the dashboard's traffic-by-group chart could read it later: a follow-up, unchanged here). Agents read it with `analytics:read`, a device's flow included (counts by group, decision, upstream and code, no names: like the device heatmap).
**Consequences:** a sorted array of at most ~100 keys per minute bucket with answers, two or three binary-search increments per event; no names involved, so nothing for the privacy levels to hide except the device mode.

## ADR-130 — The latency heatmap: per-minute bucket counts and an exemplar ring (Proposed)
**Context:** T14.4 (OBS-030; design `docs/design/latency-heatmap.md`). Percentiles per hour hide a DoT cold-start tail or one slow PTR; the Prometheus histogram has the shape but the UI didn't draw it (owner, 2026-10-16).
**Decision:**
- The aggregator counts each answer into its `BUCKETS_US` bucket per path and per upstream, in minute buckets only (not the per-second ones), allocated with the minute's first answer; stored as section `L`; hours sum minutes.
- The exemplar sink keeps its last 512 choices in a ring (at most one per path and bucket a second, as for OpenMetrics).
- Defaults taken at the start (owner: accept all defaults, 2026-10-16): the real 16 bounds plus overflow (17 rows; the design's 14 was a miscount); the paths the histogram has (`synthesized` holds blocked answers); a federated read says `partial` (not which node) when some buckets lack the counts; the Upstreams page gets a card with an upstream picker (it has no drawer); no per-client heatmap (design §8: the device timeline T14.8 gets a latency lane); the aggregator's cost is measured with the counts switched off and on.
**Consequences:** about 300 B per minute bucket with answers (≈ 0.9 MB for 48 hours) plus 68 B per upstream used; one bucket index and an increment per event; exemplars are a live aid, older ones are gone.

## ADR-129 — The rhythm heatmap reads the buckets and the hourly top lists; nothing new stored (Proposed)
**Context:** T14.3 (OBS-029; design `docs/design/rhythm-heatmap.md`). The owner saw a 10 am–2 pm burst only with a script (2026-10-16). ADR-123 left a per-minute heatmap "possible later, behind a benchmark".
**Decision:**
- Three variants: the network (exact, from the time buckets), a device and a name (from each hour's top-100 list: exact while listed, `covered: false` where it wasn't). No new per-device or per-name storage.
- Defaults taken at the start of the task (owner: accept all defaults, 2026-10-16): a device or a name has hour slots only (its lists are hourly), and a finer grain is `422 heatmap_window`; 15-minute and minute slots reach back 7 days (the minute rollups' retention), not the design's 30 days for 15 minutes; a device is given by address; `measure=blocked` for the network and names only (a device's blocked queries aren't kept per hour); the current hour (and the previous one until stored) from memory; a name needs privacy level 0 and a device level 1 or lower (`422 privacy_level`); the dashboard thumbnail (design §8) is left out; the query log link opens from the cell's start (the log takes no end time).
- The browser lays the slots out in local time; the API answers UTC starts.
- The benchmark ADR-123 waited for: 7 days of minutes read and summed in under 150 ms on the build VM, and a minute-grain answer under 200 KB.
**Consequences:** devices and names outside the busiest 100 in an hour show as hatched, not zero; a new rollup kind would be needed for exact per-device grids.

## ADR-127 — Error-budget attribution: exact per-bucket maps, bad-only hourly top lists (Proposed)
**Context:** T14.1 (OBS-027; design `docs/design/error-budget-attribution.md`). The Service level card says how much budget is left, not who spent it; the owner needed a script to learn that one laptop's PTR name and the pre-10-13 AXFR SERVFAILs had (2026-10-16).
**Decision:**
- Exact where cardinality is bounded: bad answers per bucket by status, by upstream (owner 2026-10-16: exact, not a top list), and slow answers by response code; from the hour and day rollups for the whole window (400 days).
- Approximate where it isn't: bad-only Space-Saving top lists per hour (32 entries, 20 stored) of names and clients, with the error bound shown.
- Counted only on bad answers, on the telemetry thread; a bucket's maps are allocated with its first bad answer.
- Owner decisions at task start (2026-10-16): `slow_by_rcode` added (the latency objective's rcode split); a resolver pod that isn't live counts from the primary's shipped minutes for 7 days and is listed as partial; the current hour (and the previous until stored) comes from memory; statuses are stored by label.
- Rejected: the query log as the source (7 days on a Pi, the window is 30); per-name or per-client Prometheus series (cardinality).
**Consequences:** a few hundred bytes per bucket that saw a bad answer; client and name counts are upper bounds; older builds' hours have a timeline only.

## ADR-136 — The site's decisions are an index plus pages of 50 (Proposed)
**Context:** `decisions.html` rendered every ADR in full on one page and reached the 500 KiB page budget (DOC-005) with ADR-126; T14.7's ADR-133 took it to 502 KiB, and M14 adds eight more (owner chose to split it, 2026-10-16).
**Decision:**
- `decisions.html` is the index: one row per ADR (number, title, status, areas, its first sentence), still searchable and filterable, linking to the record.
- The records are on `decisions-1.html` (ADR-001 to 050), `decisions-2.html` (051 to 100), and so on (`ADRS_PER_PAGE` in `site/build.py`), with the same explorer within the page and links between the pages.
- Links to a record go to its page (`decisions-3.html#adr-133`). The index keeps each row's `id`, so an old `decisions.html#adr-NNN` lands on that row without JavaScript, and with it goes on to the record.
- Rejected: raising the budget for this one page (it would keep growing).
**Consequences:** the index is 80 KiB and each part about 200 KiB; search on the index covers titles and first sentences, full-text search works within a part page.

## ADR-133 — Change markers: a bounded per-node annotation file, federated, with notes (Proposed)
**Context:** T14.7 (OBS-033; design `docs/design/change-markers.md`). Lining a change up with a graph meant reading timestamps across logs (owner, 2026-10-16); every later M14 chart overlays these markers.
**Decision:**
- Each node appends one JSON line per event to `<data_dir>/annotations.jsonl` from the background task that knows about it, never the query path or the telemetry thread; no fsync; 20,000 lines and 90 days; a failed write is logged once an hour and changes nothing else.
- Owner decisions at task start (2026-10-16; details in the design, §9): `seq` is the cluster's sequence, else `state.db`'s version; only the primary or a standalone node knows a change's `source` and `actor` (a replica writes `gitops` or `cluster`); `config.applied` only when configuration sections changed; the UI merges one kind and `seq` across nodes; `lists.refreshed` only where lists compile; notes need the operator role (agents `ops:annotate`); reads page back with `before`.
- Notes: `POST /api/v1/annotations`, 1–200 characters, up to 7 days back, append-only (405), audited `annotation.note`, not configuration, not replicated.
- Prometheus: new `telltale_config_seq` and `telltale_annotations_total{kind}`; Grafana annotations from `changes()`.
- Rejected: the audit table as the source (primary-only, misses restarts and breakers); Grafana's annotation API (credentials).
**Consequences:** at most a few MB per node; a replica's marker doesn't say who (the primary's does); markers don't outlive an ephemeral data directory.

## ADR-126 — Zone transfers are refused, never forwarded (Proposed)
**Context:** AXFR and IXFR had no special handling, so they were forwarded like any query. An upstream resolver can't serve a zone transfer, so each one came back SERVFAIL, was cached, and counted against the availability objective (OBS-016). On a real network, an old Technitium's catalog-zone sync (AXFR every 5 minutes) was most of a day's SERVFAILs and overspent the 30-day error budget. Each attempt also sent a private zone name to the public upstream.
**Decision:**
- AXFR (252) and IXFR (251) get `REFUSED` with EDE 21 (Not Supported, "zone transfers aren't served") from the early checks, after the allowed-networks check and the ANY answer. Status `special`. Nothing is forwarded or cached.
- REFUSED, not NOTIMP: the opcode is implemented, and this server declines to serve the zone (RFC 5936 §2.2.1). REFUSED isn't SERVFAIL, so the availability objective doesn't count it.
- Explain says the same.
**Consequences:** stray zone-transfer attempts cost one integer comparison and a short answer, and stop spending the error budget. TelltaleDNS serves no zones today. If it ever serves its local records as a zone, transfers would need a decision of their own (TSIG, an allow-list).

## ADR-125 — Every node names a device the same way: device names are shared across the cluster (Proposed)
**Context:** each node names the clients in its own query-log rows, anomaly findings, and identities, from the client catalog (replicated), then its routers' DHCP clients (`[[router]]`), then mDNS. The last two are node-local. Usually only one node can read the router (the one with its API key mounted), and a pod can't hear the LAN's mDNS. On the homelab (owner report, 2026-10-12) the cluster query log named `10.50.5.2` "k8s" in the primary's rows and showed the bare address in the resolver pods' rows. The top lists hid the gap because their merge keeps any node's name.
**Decision:**
- Every node asks each reachable peer for the device names that peer learned itself (cluster call `devices.names`: its router and mDNS tables) once a minute. It keeps the merged answer as a fallback after its own sources. The order stays: a configured name, this node's router, this node's mDNS, the peers' routers, then the peers' mDNS. Among peers, the primary's answer wins, then node ID order.
- A node answers with only what it learned itself, never what it got from peers, so a name a router forgot doesn't keep circulating. When no peer answers, the last table stays. A peer on an older build answers "unknown call" and is skipped.
- As a backstop, the federated query log names any row a peer sent without a client name, using the node assembling the page. A row's own name always stays.
- Rejected: mounting the router credentials in every pod. Each node would poll the router, the secret would spread, and mDNS would still be missing.
**Consequences:** a resolver pod's rows, findings, and device identities use the same names as the primary within a minute of start (or of a router change). The table is a few hundred entries a minute over the existing mTLS channel. Nothing touches the DNS path (CLU-004). `GET /api/v1/dhcp/leases` still lists only the node's own sources.

## ADR-124 — SQLite never needs a temp file (Proposed)
**Context:** the image runs with a read-only root filesystem, no shell, and `/var/lib/telltale` as its only writable path (OPS-001, `08` §1). When a sort, a temporary table, or a `VACUUM` outgrows SQLite's memory budget, SQLite looks for a temp directory (`/var/tmp`, `/usr/tmp`, `/tmp`, then the working directory), finds none it can write, and fails the statement with "disk I/O error" (SQLITE_IOERR_GETTEMPPATH) without any file operation failing. On the homelab primary (2026-10-12) a cluster chart's shipped-minutes read did exactly that every 15 s once `shipped_minute` passed about 2 MB: `ORDER BY start` over a table keyed `(node, start)` was a full scan and a spilled sort, so cluster charts silently lost the minutes of nodes that weren't live.
**Decision:**
- Every connection to `state.db` and `rollups.db`, and the backup's copies, sets `PRAGMA temp_store = MEMORY`: temporary data stays in memory, whatever the filesystem allows.
- `shipped_minute` gets an index on `start`, so the range read follows the index in time order: no sort, and it reads only the requested range instead of all 7 days.
- Rejected: an `emptyDir` at `/tmp` in the chart. It would fix Kubernetes only (not Docker or Compose with a read-only root), and an unbounded disk-backed sort is worse than a bounded one in memory.
**Consequences:** a large sort or `VACUUM` uses memory instead of a temp file. These databases are small (state.db well under 1 MB, rollups.db a few MB), and the index removes the one sort that grew with the data. The index is created on start, in place, for existing databases.

## ADR-123 — The traffic map is a treemap of the existing top lists (Proposed)
**Context:** the owner asked for a page that shows, at a glance and live, what people on the network are reaching, with allowed and blocked names in different colours, on a branch that could be dropped if it cost performance (2026-10-11). A true heatmap (names × minutes) would need a count per name per minute, which nothing keeps today and which would add work to every query.
**Decision:**
- A **Traffic map** page (Monitor section) draws a squarified treemap of `GET /api/v1/stats/top` for `domains` and `blocked` (100 each, this hour or the last, every node). `domains` counts every query, so a name's answered queries are its `domains` count less its `blocked` count, and a remainder within the sketch's error bound is dropped. Tile area is queries; blue is allowed, red is blocked; the shade is the tile against the biggest of its colour (square root, so small tiles stay visible).
- **Grouping:** *Services* (default) folds names into the blocked-services catalog's services (`GET /api/v1/services`, longest matching suffix) and falls back to the base domain; *Sites* uses the base domain (the last two labels, three under a country code's `co`/`com`/`net`/`org`/... level, a stand-in for the public suffix list the UI doesn't ship); *Names* shows them as asked. The choice is remembered in the browser.
- **Live:** it refreshes every 5 s; counts growing since the previous refresh are the page's own differences (same hour only), and the five tiles growing fastest get a ring. Selecting a tile opens its names in the query log.
- Nothing new on the server: no new counters, no new endpoint, one optional `hour` on the UI's existing `top` call.
**Consequences:** the map covers the busiest 100 names and 100 blocked names only, with Space-Saving's approximate counts; a new hour starts every tile again, so it looks sparse just after the hour. Background lookups (phones, apps, monitors) can dominate it; exclusions (OBS-022) keep them out. A per-minute heatmap stays possible later, behind a benchmark.

## ADR-122 — The site's navigation by what the reader wants, and a Guides section (Proposed)
**Context:** the project site's header had grown to eight top-level links plus a Reference menu, one link per feature page, and it had no task guides. How to set things up (configuration styles, clustering, Kubernetes, and more) lived only in `docs/running.md`, a 2,700-line file on GitHub (owner, 2026-10-11).
**Decision:**
- The header is **Get started** plus three menus: **Features** (what it does: Overview, Tour, How it works, Groups and VLANs, Monitoring and alerts, AI agents, Performance), **Guides** (how to do something), and **Reference** (unchanged). The logo goes to the Overview. One menu is open at a time; Escape or a click elsewhere closes it. Below 760px everything folds into ☰. It's built on `<details>`, so it works without JavaScript.
- **Guides** start from a task, show each configuration style side by side where more than one works (web UI, config file, Git, API), and link into the configuration reference and `docs/running.md` for detail rather than copying it. The build's link check covers them.
- **Phase 1:** a guides page and three guides: *Choose how you manage settings* (the four styles, how the layers stack, shared vs per-node settings, and where each setting lives), *Build a cluster*, and *Run on Kubernetes*. **Phase 2** (2026-10-11): *Upgrades, backups, and moving in*; *Block, allow, and explain*; *Groups, devices, and VLANs*; *Encrypted DNS and upstreams*; *Change things safely*; *Monitoring and alerts*; and *Users and sign-in*. The Guides menu groups them under **Set up** and **Day to day**, and each guide links to the previous and next one. Feature pages link to their guide.
**Consequences:** guides are hand-written HTML and can drift from the code. Each one states only what the docs or the code say, and the docs stay the detailed source. Feature pages keep their URLs, so existing links still work.
**Amendment (owner, 2026-10-19):** a **Kubernetes** page, a hub that says what running on Kubernetes gives you (the chart, one IP, resolver pods, a Pi in the same cluster, workloads, drills, canaries, monitoring, agents) and links to the feature pages and the guide for each. The Overview gains a "Starts on a Pi. Grows into Kubernetes." fork to Get started and to it. It first sat beside Get started at the top of the header, but a platform name broke the pattern of one action and three menus by what the reader wants, so it moved into Features under an **On Kubernetes** heading ("Kubernetes overview", then "Kubernetes workloads"). Failover drills stays in the general list (it works on any cluster, the Pi included).

## ADR-121 — Long pages get tabs; a tab never hides trouble (Proposed)
**Context:** the Cluster page had grown to about ten panels, Settings → System to eight (node housekeeping mixed with how queries are handled), and Clients to three tables, one of them a router's whole client list (57 rows on the owner's network). The owner asked for tabs as a quality-of-life change (2026-10-11).
**Decision:**
- One component (`Tabs`, `TabPanel`) for every tabbed page. The tab is in the address (`?tab=`), so links, reloads, and Back keep it. WAI-ARIA tabs: `role=tablist/tab/tabpanel`, the open tab alone in the Tab order, arrow keys, Home, and End. On a phone, the tab bar scrolls sideways.
- **A tab never hides trouble.** A tab shows a count or a word, and in warning colours when something needs attention: failing checks and conflicts (Health), a version baking or a pin (Rollouts), failures in the last hour (Events). A pin stays loud on every tab (ADR-116): a note above the tabs links to the full banner. Health conditions link to the right tab (`cluster_pinned` and `rollout_stuck` go to `#/cluster?tab=rollouts`).
- **Pages:**
  - **Cluster:** the summary stays above the tabs. The tabs are **Nodes** (topology, the node table, Maintenance…), **Health** (checks, conflicts, machines), **Rollouts**, and **Events**.
  - **Settings:** a new **Query handling** tab (Cache, Rate limit, Kept out of the log, Change simulation), apart from **System** (information, listener checks, version and updates, backup).
  - **Clients:** **Seen this hour** · **Devices** · **Discovered**, each with its size.
- Only the open tab renders, so a closed tab loads and polls nothing new.
- Pages of two or three short panels (Dashboard, Alerts, Upstreams, Lists, Local DNS, Cache, Rules) stay as they are. Groups (groups, schedules) is the next candidate once these have been used for a while.
**Consequences:** UI paths in the docs change ("Settings → Query handling → Rate limit"). Earlier ADRs and design notes keep the paths of their time. No API or MCP change.

## ADR-120 — Router integrations verify self-signed consoles by the name in their certificate (Proposed)
**Context:** a UniFi console's own certificate is self-signed and names `unifi.local` (plus `localhost` and loopback), never the address it's reached at. The documented `tls_ca` setup therefore always failed ("certificate not valid for name 10.30.3.1", checked against the owner's console on 2026-10-11), leaving `tls_insecure_skip_verify` as the only working option. With verification off, anything on the network could pose as the console and receive the API key.
**Decision:**
- `[[router]] tls_server_name`: the name the certificate is checked against (and sent as SNI) instead of the URL's host. With the console's certificate as `tls_ca`, only that certificate is trusted, and it's verified.
- Validation: a host name; only for `https://` URLs; an error together with `tls_insecure_skip_verify` (it would do nothing). The `tls_insecure_skip_verify` warning points at the alternative.
- Implemented as `fetch::Client::with_server_name`, which applies to every request that client makes; each router gets its own client.
**Consequences:**
- When the console renews its certificate (about once a year), the saved copy no longer matches. Polls fail and are logged once, and names stay as last read. DNS is never affected. Save the new certificate.
- `[[router]]` is shared configuration, so every node needs the key and certificate files at the same paths. Helm resolver pods don't mount `secretMounts`: each logs one warning, and the controller (which serves the UI) reads the router. *(Amended 2026-10-18, live review finding 1: on an ephemeral member, the resolver pod, that message and a failed OIDC setup are logged as info, not warning/error; the secrets still stay off resolver pods.)*

## ADR-119 — Expired answers given at once are `refreshed`, a cache answer; `stale` keeps meaning failure (Proposed)
**Context:** the 2026-10-10 live review found a steady-state cache hit rate of about 6%: most repeat questions arrive just after their answer expired (devices cache too). The owner chose Pi-hole's behavior, an expired answer given at once while it's refreshed (RFC 8767 with a zero client response timer, `[cache] stale_answer_client_timeout_ms = 0`), with Technitium's 10 s TTL floor. Those answers were `stale`, the status that also says "upstreams failed or were slow", and counted on the upstream latency path, so the change would hide upstream trouble and make upstream latency look faster than it is. The owner asked that general users see one cache number and advanced users the split.
**Decision:**
- A new query status `refreshed`, appended to the status list (stored values keep their meaning; older builds read it from the query log as `dropped` and ignore its rollup column): an expired entry answered without waiting while the spawned resolution refreshes it. Latency path `cache`. `stale` stays the fallback after a wait, or when overloaded.
- A zero wait doesn't wait at all (a zero-length timer would let an answer arriving within its tick win, which made the outcome depend on timing).
- *Amended 2026-10-11:* the 2026-10-11 live review measured the cache path, now mostly refreshed answers, at p50 78 µs and p99 ~450 µs on the homelab, and p99 658 µs on the Pi. Fresh hits had been 25 µs and 50–90 µs, and the budget is 250 µs added latency for a cache hit (`00`, release gates). Lab A/B on the build VM showed the cost was starting the refresh before the answer went out: it wakes an idle runtime worker. It appeared only at low load (20 q/s: p50 ~110 µs, p99 248 µs; 3,000 q/s: p99 63 µs). So:
  - With a zero wait, the expired entry is answered on the synchronous path, like a hit. It no longer goes through a task, a full-size buffer, a re-parse, and a second lookup per answer.
  - It's refreshed through the prefetch path (one shared upstream resolution per name). On a UDP worker thread, refreshes (and DNS-008 prefetches) are queued and started by `QueryHandler::sent` once the batch's answers are out.
  - Result on the VM at 20, 200, and 3,000 q/s: p50 25 µs and p99 50 µs, the same as a fresh hit.
  - If the refresh can't start (overloaded), the answer is still given, as `stale`.
  - DNS64 clients, and an entry evicted between the two lookups, keep the deferred path. TCP, DoT, DoH, and DoQ start the refresh at once: they run on the runtime, which is already awake.
- One number for everyone: the dashboard's cache tile, `GET /stats/summary` `cacheHitPercent`, the Cache page, and Grafana's "Answered from cache" all count fresh, refreshed, and stale answers. The split is in the Advanced view (`Summary.refreshed`; the status chart's `refreshed` series), in `CacheNodeStats`/`CachePoint` `answeredPercent` beside the fresh `hitPercent`, and in Grafana's "Answered from cache" panel (answered vs fresh only).
**Consequences:** the cache's own counters still call a refreshed answer a miss (and count it in `stale_served`); `answeredPercent` adds them back. With a zero wait, an expired answer is `refreshed` even when the background refresh then fails; upstream failures show in the upstream metrics and health. The homelab and the Pi run it since 2026-10-10 (gitops-repo <commit> and the Pi's own file: `[cache]` is per node).

## ADR-118 — Maintenance mode: not ready, still answering, out of alerts and elections (Proposed)
**Context:** the owner picked node maintenance mode (OPS-010, 2026-10-09). Swapping a Pi's SD card or draining a Kubernetes node today means killing the process: balancers notice late, `node_down` and `probe_failing` alerts fire for a planned event, and the health icon goes red. Design doc: `docs/design/maintenance-mode.md`.
**Decision:**
- Maintenance is **operational node state, not configuration**: `<data_dir>/maintenance.json { until_ms, reason, by }`, set through `POST /api/v1/nodes/{id}/maintenance` (operator; forwarded to the target node over the cluster channel as an RPC, like a tail session, not through the primary), `telltale ctl maintenance start|end`, the Cluster page, and the MCP tools `start_maintenance`/`end_maintenance` (`ops:maintenance`; agents at most 2 h). Audited `node.maintenance.start|end`. Allowed under a GitOps authority (ADR-103's rule: it changes no configuration).
- **What changes on the node:** `/readyz` answers 503 (the same `ready` flag shutdown clears; nothing else on the DNS side), heartbeats carry `maintenance_until` (a new optional field, ignored by N−1), the node declines to be a candidate (pre-vote) while in maintenance. **What doesn't:** every listener keeps answering; the cache, lists, replication, the query log, probes, and the API keep running.
- **A primary in maintenance hands over when it can** (owner 2026-10-09: "follow your lead"). With automatic failover and another eligible node or quorum reachable, starting maintenance on the primary performs a **handover** (`handover = true`, the default; the form shows it): the primary stops renewing its lease and declines candidacy, so a replica is elected within the normal lease window (writes unavailable for the usual 15–30 s, as in any failover), and the old primary follows as a replica for the rest of the window. With manual failover, or no other eligible node, maintenance is allowed and the primary keeps publishing; the UI and CLI say "promote another node first if you're taking it offline".
- **What changes elsewhere:** the primary's alert evaluation skips the node (`node_down`, `sync_lag`, `probe_failing`, `cert_expiring`, `disk_full`, `not_serving` for it), and firing alerts about it resolve with "(maintenance)"; the health level ignores the node's reasons and lists it under `maintenance`; the Cluster page's checks (load balance, serving) skip it. A once-only alert rule `maintenance` tells destinations when a node enters (and resolves when it leaves).
- **Bounded and persistent:** default 1 h, at most 24 h (validated); the file is read at start, so a node rebooted mid-window comes back **not ready** until the window ends or someone ends it. That is the point: the operator, not a reboot, says when it's back.
- **Readiness has one meaning per pod.** In Kubernetes the pod's readiness probe serves every Service that selects it, so a controller pod in maintenance also leaves the API Service; the UI stays reachable through any other node (CLU-002) or a port-forward. Documented; no second probe.
**Consequences:** clients that still ask a node in maintenance (a router's secondary DNS entry, hard-coded devices) get normal answers, so nothing breaks when the balancer is slow to notice. A node that's really failing while in maintenance stays quiet until the window ends: the window is short by default for that reason. A standalone node in maintenance has no cluster to tell; only readiness, the UI banner, and the alert rule apply.
**Amended 2026-10-09 (T13.4 implementation; amendment accepted by the owner 2026-10-09):** built as decided, with these changes, each the conservative reading:
- **The startup probe leaves maintenance out.** The chart's `startupProbe` also asked `/readyz`, so a pod restarted inside its window failed it and was killed after 120 s, over and over: the opposite of "comes back not ready". `/readyz?startup=1` answers ready once listeners are bound and the configuration is applied, maintenance or not; both chart probes use it (a template change, no new values). Older binaries ignore the parameter. The readiness probe keeps plain `/readyz`. Docker Compose's healthcheck shows the container unhealthy during maintenance (documented; Compose doesn't restart for it).
- **Readiness is composed** (`crate::readiness`: bound, synced, stopping, maintenance): *serving* (bound, synced, not stopping) is what heartbeats' `ready`, probes, and the health level's `not_serving` read, so a node in maintenance counts as serving everywhere (also on N−1 peers); *ready* adds maintenance and is what `/readyz` answers, with the reason as JSON.
- **Heartbeats** carry `maintenance_until_ms`, `maintenance_reason`, `maintenance_by`, and `maintenance_since_ms` (tags 20–23; the health list and the Cluster page show who). A member's window is kept while it's silent, so a node stopped during its window stays in maintenance until `until`.
- **The handover gives up after 60 s** (four lease windows) if no other node was elected: the primary renews again and the event log says `handover_failed`, so a handover that can't complete never leaves the cluster without a writable primary for the rest of the window. A handover starts only when another eligible node (in the registry, not a witness, not in maintenance) is connected and a majority of voters is reachable.
- **`handover` answers `declined`** when the request said `handover: false` (with the promote-first note), besides `started`, `not_needed`, and `unavailable`.
- **Problem codes:** `maintenance_too_long` and a new `maintenance_invalid` (no usable reason, or under a minute), both 422 as the task's AC asks; `node_unreachable` (503) also covers a node too old to know maintenance; `node_unknown` (404).
- **The RPC** (`maint.set` / `maint.clear`) carries the requested length, not an `until`: the target computes the window on its own clock. It also carries when it was sent; a target drops a request more than 30 s old, so a paused process that resumes never acts on a request the user saw fail.
- **SERVFAIL share:** the alert task reads the time buckets of the nodes not in maintenance (a scoped federated read), so `servfail_rate` leaves out exactly the maintenance node's share. SLOs are unchanged.
- **The health answer** also leaves nodes in maintenance out of `missingNodes` (a stopped node in its window is expected to be silent).
- **Chart alerts:** the node rules use `unless on(instance) (last_over_time(telltale_node_maintenance_until_seconds[1d]) > time())` instead of `telltale_node_maintenance == 1`, so a node that stops reporting during its window (powered off for the SD card) stays quiet until the window ends; the peer-down rule uses the new per-peer `telltale_cluster_peer_maintenance_until_seconds{node,site}`. `deploy/prometheus/` holds only the SLO rules, so nothing changed there.
- **Election:** `Elector::standing` (false in maintenance: no pre-vote, and a candidacy in progress stands down instead of winning) and `Elector::stepping_down` (a leader skips renewals). The simulator puts nodes in and out of maintenance at random (surviving restarts) and checks that a node in maintenance is never elected and that a primary handing over can't write past one lease; both checks were mutation-tested.

## ADR-117 — Device identification from shipped signatures: vendor, names, and the domains a device talks to (Proposed)
**Context:** the owner picked device identification (OBS-025, 2026-10-09): a new address on the network is a number, and naming it (API-010) means knowing what it is first. Everything needed is already observed: the MAC (neighbor table, EDNS MAC, router leases), announced names (mDNS, router DHCP), and the registrable domains the device queries (the anomaly engine's learned set and the per-client top domains). Design doc: `docs/design/device-identification.md`.
**Decision:**
- **Deterministic scoring over a shipped catalog, no model.** `presets/devices.toml` holds signatures (`id`, `name`, `class`, `vendors`, `domains` with weights, `hostname_patterns`); `presets/oui.bin` holds the IEEE MA-L/MA-M registry compacted (3- and 4.5-byte prefixes → vendor index), built by `presets/build-oui.py` from IEEE's public CSV, never from another project's `manuf` file. A device's score for a signature is `0.6 × (matched domain weight ÷ total) + 0.25 × vendor + 0.15 × hostname`; the best signature is reported as `likely` (≥ 0.6), `possibly` (≥ 0.35), else `unknown` with the vendor alone. Every result carries its evidence (which domains, the vendor string, the matched name). Same inputs, same answer, on every node and architecture (f32, fixed ordering), like ADR-019.
- **Off the query path, bounded.** A background task every 10 minutes scores the devices seen in the last day (`max_clients`, 1,024), using the aggregator's per-client top domains and, for devices it doesn't hold, one idle-priority query-log top-K per device. Results live in memory and `<data_dir>/devices.json`; nothing runs at privacy level 1 or above (names are hashed).
- **Suggests, never acts.** The class maps to a group only when a group declares `[[group]] device_classes = [...]`; the UI then offers "Add to IOT?" through the existing Add-to-group action and plans. `[[client]] kind = "camera"` (or `"unknown"`) is an explicit override that wins and replicates with the configuration. New-device alerts and anomaly findings quote the guess.
- **One shared section** `[identify] { enabled, max_clients, signatures_file }` (extra signatures in the same TOML shape; the shipped catalog can't be removed, only added to). The catalog updates with releases only: no network fetch of signatures.
- Federated reads merge per device by highest confidence; `GET /api/v1/clients` gains `identity`, `GET /api/v1/clients/{id}/identity` gives the evidence, MCP `identify_device`, `telltale_devices_by_class{class}`.
**Amended (T13.3, 2026-10-09; still Proposed):**
- **Vendor words match whole words**, not any substring: "Ring" must not match "Sage Electronic Engineering". Case-insensitive, word boundaries at non-alphanumerics.
- **A tie with another kind of device is `possibly`, never `likely`.** Apple's devices share their domains; without a name, an Apple MAC talking to `apple.com` would otherwise be "likely an Apple TV" only because `apple-appletv` sorts first. The runner-up is reported.
- **A private (locally administered) MAC has no vendor and no prefix shown** (phones' private Wi-Fi addresses).
- **Passes on demand:** besides every 10 minutes (the first a minute after start), a pass runs when the API asks for identities older than 15 seconds (never waiting for it; a pass costs milliseconds): the UI and tests don't wait 10 minutes for a new device. It runs on a dedicated background-priority thread, not the async runtime.
- **`GET /api/v1/clients/identities`** (every device seen, federated and merged) is added next to `GET /api/v1/clients/{id}/identity`: the "seen this hour" table and the Advanced dashboard's "Devices by type" need identities for unnamed devices, which `GET /api/v1/clients` (named devices) doesn't list. Agent scope `analytics:read`.
- **Devices seen:** the aggregator's per-client top domains (this hour and the last), its top clients, and the router and mDNS leases; at most 8 query-log reads per pass for devices without domains, each refreshed after 6 hours. Per device at most 20 domains of at most 40 bytes (≤ 1 KiB, tested).
- **`devices.json`** is written hourly and at shutdown (atomically), not on every pass, to spare SD cards.
- **The OUI table** is 643 KB raw, 383 KB gzipped (25,439 vendors, 6,628 MA-M and 40,316 MA-L prefixes; vendor names normalized and capped at 32 bytes), a little over the ~300 KiB estimate.
**Consequences:** about 300 KiB of compressed data in the binary (measured before merge against the 15 MiB image gate). Devices behind a NAT or a Kubernetes LB without client IPs score as one. Signatures are a maintenance commitment; the catalog is deliberately small (common home devices) and ships in v1 so the owner's own network can test it (owner 2026-10-09). No "not this" feedback beyond the override in v1.

## ADR-116 — Staged rollouts: targeted delivery of canary versions, a guard from heartbeats, and pins instead of rewinds (Proposed)
**Context:** the owner picked canary rollouts with an SLO guard and one-click rollback (CLU-013, 2026-10-09). Today the primary publishes every version to every node at once; a bad list or upstream change reaches the Pi and the pods together. Versions are signed and ordered by `(epoch, seq)`, orphan detection and fencing depend on that order, and N−1 replicas apply whatever newer manifest they see. Design doc: `docs/design/staged-rollouts.md`.
**Decision:**
- **Two heads, targeted delivery.** The primary keeps a `stable` head (what every node should run) and, during a rollout, a `canary` head. A canary manifest is sent only to canary peers, and a reconnecting peer is answered with the head for its set; the `rollout` field in the manifest is for display and for the replica to know what it runs. Older replicas therefore never see canary versions and need no code: **N−1 nodes are non-canary**. Who is a canary: `[cluster.rollout] canaries` (node IDs, `site:<name>`, or `ephemeral`). **Off until set** (owner 2026-10-09): the default is an empty list, so nothing changes for existing clusters; `[cluster.rollout]` is a shared one-of section managed like `[exclusions]` (ADR-111: `PUT /api/v1/cluster/rollout-settings`, Settings → Cluster → *Staged rollouts* with the canary picker listing the cluster's nodes and sites, Revert to the file, the TOML to commit under GitOps). A change to this section itself never goes through a rollout.
- **The primary applies at once, as today, and counts as a canary for the guard.** Decoupling what the primary serves from what it publishes would be a second architecture; in the reference topology the primary is the Kubernetes controller, and the Pi is a plain replica that waits. Recorded as the limitation it is.
- **The guard reads what heartbeats already carry** (serving stats every 5 s, probe status, readiness, apply errors) over `bake_secs` (300): fail at once on an apply error, a canary not ready, or a canary's listener probes failing; at the end, fail if the canaries' SERVFAIL share rose above `max(before + 2 points, servfail_pct)` with at least 50 answers, or an objective burns at the fast rate on a canary. Too little traffic passes (`require_traffic = false`): quiet networks shouldn't block changes. Pass promotes the stable head; `promote` and `abort` are always available to an operator.
- **A rollback is a pin, never a rewind.** `seq` stays monotonic (fencing and orphan detection rely on it). Pinning to version N makes the primary publish N's blobs (config + filter, already in the blob store) as the stable head, apply them to itself the way an emergency primary serves an inherited version, and refuse configuration writes with `409 cluster_pinned` and the JSON diff between N and the current source. The pin travels in the manifest, so a new primary after a failover stays pinned; Git polling continues and publishes nothing. **Unpin** resumes from the current source (a new rollout if guarded). Reverting the *source* to N (rewriting managed entries, or Git) is deferred: the operator sees the diff and fixes the configuration.
- **Kept versions:** the primary keeps the last `history` (20) manifests in `<cluster dir>/versions.json` and protects their blobs from pruning; `GET /api/v1/cluster/versions` lists them with provenance, stage, and outcome; any of them can be pinned.
- Alerts `rollout_failed` (once per version) and `cluster_pinned` (while pinned); health degraded `cluster_pinned`; events on the Cluster page timeline; MCP `rollout_status` (read), `plan_pin_version`/`plan_unpin` (`cluster:admin`, plan/apply), `cluster_promote`'s approval rule unchanged.
**Consequences:** during a bake the cluster deliberately runs two configurations; the Cluster page shows which nodes run which. An emergency primary never starts a rollout (it publishes nothing new). A canary set that's empty or all offline makes the rollout wait, not pass; `abort` or an empty `canaries` setting ends it. Simulating a 300 s bake in CI needs `bake_secs` to accept small values (tests use 5).
**Amended (T13.2, 2026-10-10; still Proposed):**
- **No SLO burn in the guard.** `slo::burning` works on the cluster's merged minute rollups, not per canary, so a burn can't be pinned on a version; the SERVFAIL share over the canaries already measures what the objectives do. Deferred.
- **SERVFAIL is judged during the bake, not only at its end:** as soon as the canaries and the primary have 50 answers since the version went out, a share over `max(before + 2 points, servfail_pct)` fails it, so a bad version is pinned seconds after it went out and the waiting nodes never get it (AC 2: in the e2e, 5 s into a 20 s bake). A pass still waits for the end of the bake.
- **Heartbeat fields after all** (the design said none were needed): `rollouts` (tag 24, this node takes part; an older node is never sent a canary version, even when named), `sync_error` (25) and `probe_failing` (26) (the primary had no per-peer apply error or probe state), and `canary_of` (27: while a node runs a canary version, the stable `seq` it would replace, so configuration lag, `sync_lag`, and the behind alerts count stable versions only and the nodes waiting out a bake aren't "behind"). All optional; older nodes send and ignore them.
- **Promotion publishes the canary's content as a new `seq`** without the `rollout` field, instead of re-sending the canary manifest: no node keeps a manifest marked canary after the bake, and the plain replicas never apply the canary's `seq` (AC 1).
- **Commands run on the primary's publish loop** (a queue the API feeds; a replica's request travels the cluster channel as the RPC `rollout.call` and is audited on both nodes). State lives in `<cluster dir>/rollout.json` (the bake, the pin), `versions.json`, and `pinned.json` (the pinned manifest the primary serves itself) rather than in `published.json`.
- **A restart of the primary during a bake starts the rollout over** (the version baking is marked superseded and the content goes to the canaries again). After the publisher starts it waits up to 60 s for a canary to connect before a change goes to every node, so a restart doesn't skip staging.
- **Canaries all offline: changes reach every node** after that minute (design §4; the Consequences above said "wait"), logged as "rollout skipped: no canary online" and shown on the Cluster page. Canaries set with none online for 10 minutes is the health condition `rollout_stuck` (degraded): changes are going out without a bake.
- **Users, tokens, the member list, and acknowledged anomalies wait for a bake to end** before they're published (a version for everyone would carry the canary's configuration).
- **The pinned filter** is installed as `snapshots/pinned-<version>` beside the compiled snapshots; while pinned, list refreshes still download and compile on the primary but no other snapshot is served or published (`filter_pin`). Unpinning serves the newest compiled snapshot again.
- **CLI under `telltale ctl`** (`rollout status|promote|abort`, `versions`, `pin`, `unpin`): the commands need the running node and an API token, as maintenance does; `telltale cluster` stays offline.
- **Agents pin only with approval:** `plan_pin_version` and `plan_unpin` refuse unless `[agents] require_approval = true`, as `spec/13` asks for promotion.
- **Problem bodies gain `diff`** (JSON Patch) for `cluster_pinned`; it crosses write forwarding.
- **Version provenance** is "this node's configuration" or "Git commit …", not the user or agent behind each change (the audit log has those). A node promoted to primary starts its own history (plus the version it was running), so versions only the old primary kept can't be pinned there. Deferred: per-change provenance in the history.
- **Found and fixed on the way:** a node outside Kubernetes couldn't apply the controller's configuration in the Helm scaled e2e. Blob fetches went to the primary's first advertised URL (the in-cluster Service name) instead of the URL the node's stream uses. They now prefer the stream's URL. This would also have hit a Raspberry Pi joining the homelab.
- Metrics also include `telltale_cluster_rollouts_total{outcome}`, which the chart's `TelltaleDNSRolloutFailed` uses; `TelltaleDNSClusterPinned` fires after an hour.

## ADR-115 — Change simulation: the serving snapshot plus a side snapshot, decided again over the query log, off the query path (Proposed)
**Context:** the owner picked change simulation (OBS-024, 2026-10-09). AGT-002 promises an *impact estimate* on every dry run; today a dry run reports the diff and validation only. Shadow lists (ADR-109) already re-decide live queries on the telemetry thread; the query log holds the recent past. Design doc: `docs/design/change-simulation.md`.
**Decision:**
- **One engine, three doors.** `simulate=<window>` on any existing dry run (`?dryRun=true&simulate=24h`) adds an `impact` object to that response, so plans (which are dry runs) and the UI's change preview get it with no new body shape; `POST /api/v1/simulate` takes a whole candidate shared configuration (for GitOps, `telltale config simulate`); MCP `simulate_change` wraps the first for the plan tools' change kinds. Dry runs without `simulate` are unchanged. **Plans simulate only on request** (owner 2026-10-09, to save compute): a `plan_*` tool simulates when the agent passes `simulate`, or when `[simulate] plans_by_default = true`; the UI's preview is a button, never automatic.
- **`[simulate]` is a shared one-of section** managed like `[exclusions]` (ADR-111): `enabled`, `plans_by_default`, `max_secs`, `max_rows`, `default_window`; Settings → System → *Change simulation*; `PUT /api/v1/simulate-settings`; GitOps says what to commit. Shared rather than node-local so the toggles are one place to look; the bounds suit a Pi and a pod alike.
- **Decisions, not resolution.** The simulation re-decides each logged query under the candidate state and compares the outcome with the one recorded: blocked ↔ allowed, local/rewrite/AAAA-filter changes, and the route (upstream group). Nothing is fetched from upstreams, no cache, no DNSSEC, no latency.
- **No full recompile.** Group, device, quick-rule, schedule, and block-mode changes reuse the serving snapshot with recomputed masks. A change that adds or edits lists compiles **only the changed lists** into a side snapshot (one idle-priority thread, the compiler's memory cap) and merges `Matcher::matches` from both snapshots by the existing precedence (exact > deepest suffix > regex > lowest list ID). `$badfilter` across the two snapshots isn't honored (reported as an approximation). This keeps a Pi with 2.7M names from a 300 MiB compile peak (ADR-025) for every preview.
- **Bounded.** One simulation at a time per node (`409 simulation_busy`), `max_secs` (20) and `max_rows` (2,000,000) with `partial: true` when hit, default window 24 h, maximum 7 days. Rows come from the query log's column reader newest first; the aggregation is counts and Space-Saving top-K per outcome, by device and by name. Privacy level 1 and above hashes names, so name-dependent simulations answer `unavailable` with that reason.
- **Where it runs:** on every node in scope that holds a log (local, or shipped logs it receives) as an RPC with its own deadline (`max_secs + 5`), merged at the entry node like other federated reads; resolver pods in ship mode are covered by the controller's copy of their rows.
- The result is deterministic for the same log and candidate (fixed ordering, no wall clock). Agents need `querylog:read` plus the write scope of the change, as for pre-save checks; simulations aren't audited (dry runs aren't).
**Consequences:** a preview can take seconds on a Pi; the UI asks for it on a button, plans compute it only when asked (or when the toggle says so) and continue without it when the node is busy or the window empty. The estimate is about the past: a new list's effect on names nobody has asked for yet is zero by construction, and the response says so.
**Amended (T13.1, 2026-10-09; still Proposed):**
- **Compared with the configuration in effect, decided again; not with the recorded status.** Comparing the candidate's decision with what the log recorded counts everything the change doesn't cause: blocking paused at the time, CNAME-target blocks (decided on the upstream's answer, which a replay doesn't have), lists that updated since, rate limits. Both sides now run the same steps over the same rows, so a change that affects nothing reports zeros (AC 1). Pauses aren't replayed on either side.
- **Refused rows are replayed** (the design skipped them): a query refused because no upstream group serves it went through quick rules and the filter first, so a block for it is a real difference; one refused by `allowed_networks` is refused again on both sides. Rate-limited, malformed, and dropped rows are still skipped (counted unchanged).
- **The field is `simulation`, not `impact`.** `ConfigChange.impact` and `ClientChange.impact` already exist (the dry run's one-sentence AGT-002 estimate); renaming them would break clients. The roadmap's "`impact`" means this object.
- **No `has_qlog` heartbeat bit.** The entry node sends `sim.run` to every reachable peer; a node without a log of its own (ship mode, query log off) answers an empty tally. One RPC more per peer, no wire change, and N−1 nodes simply answer an error and are listed in `missingNodes`. The request carries both configurations' shared parts, so each node applies its own node-local settings (privacy level, data directory) and refuses what its own privacy level forbids. Deadline `max_secs + 30` s (peers may download a changed list first), not `+ 5`.
- **`simulate=auto`** is what MCP plan tools send by default: it simulates only when `plans_by_default` is on, and is silently skipped for a token without `querylog:read`. `simulate=true` means `default_window`. `simulateUntil` moves the window's end back. Problem codes `simulation_busy` (409, `Retry-After: 5`) and `simulation_window` (422).
- **Privacy level 1, device-only changes:** a change to `[[client]]` alone is replayed by address and logged group: a device's queries are unchanged when its new groups decide alike (the same settings apart from name, networks, priority, color), else `undetermined` (a new counter), since hashed names can't be decided again.
- **Aggregation:** exact counts in bounded maps (50,000 names per kind, 4,096 devices, then `other`; note `names_capped`) instead of Space-Saving: simpler, exact under the bounds, and mergeable across nodes by addition.
- **Scopes:** a dry run with `simulate` from an agent needs `querylog:read`; a token restricted to one group can't simulate (it would read every device's queries). `POST /api/v1/simulate` needs `querylog:read` and `config:read`, and no `X-Telltale-Reason` (it changes nothing). An agent sees "a list couldn't be downloaded" without the reason (AGT-009, as for `check_list`). Settings: agent scope `config:write:simulate`.

## ADR-114 — AAAA filtering per group, after blocking, before rewrites and upstreams (Proposed)
**Context:** the owner picked per-group AAAA filtering (FLT-016, from Pi-hole's feature requests): devices on a network with broken IPv6 wait on AAAA answers before falling back to IPv4.
**Decision:** `[[group]] filter_aaaa` answers the group's AAAA questions NOERROR with no records (no SOA: clients just ask again, cheaply). Placed after local data, zones, quick rules, schedules, list rewrites, and the filter decision, so configured local IPv6 addresses still answer and blocked names still get their block answer; before rewrites, safe search, the cache, and upstreams, so nothing is fetched for it. Status `special`; explain reports it. Rejected with `dns64` (contradictory). HTTPS records are left alone: stripping `ipv6hint` would mean rewriting RDATA on the query path, and the request was for AAAA.
**Consequences:** the cost is one comparison for non-AAAA queries and a group lookup for AAAA. Browsers that use HTTPS-record IPv6 hints may still try IPv6; documented.

## ADR-113 — NSID from the node's name, only when asked, appended to our OPT (Proposed)
**Context:** the owner picked NSID (DNS-021, from Technitium #1932): behind one address (a load balancer, resolver pods, the homelab's .112), there's no way to tell which node answered.
**Decision:** `[dns] nsid` (default off: any allowed client sees the name) adds an NSID option with this node's name (`[node] name`, else the host name, a pod's name in Kubernetes) to answers whose query carried the NSID option. It's added in `finish`, which every answer path goes through, by appending to our OPT record when it's the message's last record and fits; otherwise the answer goes out unchanged. The name lives in the reloadable policy, so `[dns]` being shared turns it on cluster-wide while each node names itself. `id.server`/`hostname.bind` (RFC 4892) stay REFUSED for now.
**Consequences:** queries without NSID pay one option scan of their OPT (usually empty); bench-smoke unchanged.

## ADR-112 — Stale lists: content unchanged for 30 days, URL lists only (Proposed)
**Context:** the owner picked stale-list detection (OBS-023, from Technitium #2198 and Pi-hole's "adlists that haven't changed in a long time"): a list whose maintainer stopped still downloads with HTTP 200 and the same body, so nothing fails.
**Decision:** a URL list is stale when its `last_changed` (the body's BLAKE3 changed; identical downloads don't count) is at least `stale_after_days` ago: `[filter]` default 30 days (a conservative value: the popular lists update daily or weekly), per list too, 0 = never. Exposed as `ListInfo.staleDays`, health reason `list_stale` (degraded, like a failing list), alert rule `list_stale`, and a line on the Lists page. Files and inline rules are never stale (they change when you change them).
**Consequences:** a list that's fine but rarely updated needs `stale_after_days = 0`; documented.

## ADR-111 — Exclusions applied by the aggregator, a shared one-of section managed like the rate limit (Proposed)
**Context:** the owner picked "keep names and devices out of the log and stats" (OBS-022, Pi-hole's most-voted logging request) and asked for a toggle in the settings and in GitOps.
**Decision:**
- One shared section, `[exclusions] { enabled, names, clients }`, outside `[telemetry]` (which stays with each node) so a cluster excludes the same everywhere. `enabled` is the toggle that keeps the lists.
- Applied on the aggregator thread when events are drained: a match is dropped before the analytics and every sink (query log, tail, anomalies, event sinks, shadow lists, exemplars, traces), and counted (`telltale_queries_excluded_total`). The hot-path `Metrics` counters still count it, so Prometheus totals stay complete and DNS cost is zero. The startup replay skips them too.
- Managed like `[ratelimit]` (ADR-069's one-of kind, now shared code): `PUT/DELETE /api/v1/exclusions/default` checked and applied, Settings → System with Revert to the file, MCP `plan_set_exclusions`, scope `config:write:exclusions`; under a GitOps authority, refused with the TOML to commit.
**Consequences:** the dashboard's totals no longer match Prometheus when exclusions are on (documented). Excluded queries can't be searched later. Up to 1,000 names and 1,000 clients (validated) keep the per-event check cheap.

**Note (2026-10-09):** the owner also picked "alert when a new device joins"; that exists already (alert rule `new_device`, OBS-010/T9.5, cluster-wide), so nothing was built. It's off at privacy level 1 and above.

## ADR-110 — Exemplars and traces from query events; trace IDs the query log can find (Proposed)
**Context:** the owner asked (2026-10-08) for OpenMetrics exemplars on the latency histograms and sampled/slow queries as OTLP traces (OBS-017), without costing DNS performance. The latency histogram is counted on the query path in per-thread atomics; nothing there knows a query's identity, and adding it would cost every query.
**Decision:**
- Exemplars and traces are built on the telemetry thread from the query events it already drains (a `Sink`), never on the query path. An exemplar slot per (path, bucket) is replaced at most once a second, so the per-event cost is a bucket lookup and a comparison; the trace ID is hashed only when a slot is refreshed or a query is traced.
- **Trace ID = start time ‖ keyed hash of the query-log row**, not a random ID: `ts_us` (8 bytes) ‖ BLAKE3 keyed with the cluster's privacy key over `ts_us`, `client`, `qtype`, `name` as the query log returns them (after the privacy level). No storage change: the query log finds it by searching that microsecond and recomputing the ID per row, on any node (the key is the cluster's) and across a mixed-version cluster (the route checks after federation). A random ID would need a new query-log column; an unkeyed hash would let anyone with an ID confirm a guessed name. It's not random as W3C recommends; the time it reveals is already in the exemplar.
- OpenMetrics is served only when the scraper asks (`Accept`), by converting our 0.0.4 exposition (one writer, two formats). Prometheus asks for it by default, so it's verified against Prometheus 3.5 and the strict `prometheus_client` parser, with `[telemetry.metrics] exemplars = false` as the way back.
- Traces reuse the OTLP endpoint (JSON, like metrics and logs; no new dependency), off by default (`traces_sample_every`, `traces_slow_ms`). Spans come from the event's timings only: a server span and an upstream client span placed at the query's end (the event has the wait's length, not its start). Bounded queue (4,096), dropped and failed counted.
- Only `telltale_query_duration_seconds` gets exemplars: upstream exchanges have no query name (their histogram stays as is).
**Consequences:** an exemplar is a recent example per bucket, not the worst one. Trace IDs of queries before a privacy-key change (joining a cluster) no longer match their rows. Privacy level 3 still sends traces (hashed names, no clients), like event sinks.

## ADR-109 — Shadow lists decided again on the telemetry thread; over-blocking from retries and quick allows (Proposed)
**Context:** the owner asked (2026-10-08) for shadow mode for lists (count what a list would block for a week without enforcing it) and an over-blocking view (blocked names that are retried or allowed right after), within the no-performance-cost condition (OBS-018).
**Decision:**
- A shadow list is compiled into the same snapshot (no second compile, no extra memory beyond its names) and left out of every enforcing mask, so the query path is unchanged: it never consults shadow lists at all.
- The would-be decision is made **off the query path**: a telemetry-thread sink re-runs `Matcher::decide` for answered queries with the group's mask plus its shadow lists. This costs a filter lookup (about 0.3–1 µs) per answered query on the telemetry thread, and only while some list is in shadow mode. If the thread falls behind, events drop (counted) and DNS is unaffected. The group comes from the event (the primary group); a device whose own client entry names extra groups is judged by its primary group only.
- Over-blocking evidence uses only what the events already carry: retry bursts (10 blocked queries in 60 s from one device; ad libraries do this too, so it's ranked low) and `allowed_after_block` (the same device answered within 10 minutes of a block: a pause or a quick allow; ranked ×10). Thresholds are fixed for now (conservative, not in the request).
- Bounded state: recent blocks 8,192, suspects 512, devices 4,096 per shadow list and 64 per suspect, 256 tracked names per list. Since start, per node; reads merge every node's.
- Names follow the privacy level (hashed at 1+); devices aren't counted at 2+.
**Consequences:** counts reset on restart (Prometheus keeps `telltale_list_shadow_hits_total` history). Turning a list from shadow to enforce is an ordinary list change (API, UI, MCP plans).

## ADR-108 — Upstream truth checks: sampled second opinions compared by RCODE and addresses (Proposed)
**Context:** the owner asked (2026-10-08) for upstream truth checks: sampled comparison with a second upstream, and per-upstream DNSSEC-failure and EDE breakdowns (OBS-019), without costing DNS performance.
**Decision:**
- Second opinions are **off by default** (`sample_every = 0`): the second upstream sees the sampled names, a privacy choice the owner should make per network. A sample below 1 in 100 warns.
- They run after the client's answer, in their own task, at most 8 at once (more are skipped, never queued), from the asynchronous upstream path only. Sampling is one atomic counter.
- The comparison is deliberately coarse: response code plus the set of A/AAAA addresses. `filtered` (one side resolves, the other gives nothing or a sinkhole) is the signal that matters; `different_addresses` is expected from CDNs and shown as such, not as an alarm. TTLs, record order, and other types are ignored.
- The second opinion comes from the `reference` group when set (its strategy picks the member), else from another member of the answering group: comparing upstreams the user already trusts with the same question. A one-member group gets none unless a reference is set.
- EDE codes and DNSSEC verdicts are counted for every upstream answer (no sampling): a scan of the answer's records for the OPT, a lock only when an EDE is present, and an atomic increment per verdict. The (upstream, code) map is capped at 2,048 pairs.
- Counts are since start, per node; nothing alerts or changes health on its own (no thresholds the owner has agreed to yet).
**Consequences:** second opinions add upstream traffic (1/N) and a little upstream load. The second exchange is ordinary upstream traffic: it updates that upstream's health and appears in dnstap's forwarder messages.

## ADR-107 — Synthetic probes through the upstream client, kept out of the analytics (Proposed)
**Context:** the owner asked (2026-10-08) for synthetic probes of every listener and protocol, plus listener certificate expiry (OBS-020). `/readyz` only says the sockets are bound; nothing checked that a listener answers, and only the cluster certificate's expiry was exported.
**Decision:**
- Each node probes its own listeners (so in a cluster every node is checked, resolver pods included) with the upstream client it already has for every protocol: a probe is a real client of the listener. Wildcard binds are asked on loopback. TLS verification is off (the probe connects by IP); expiry comes from the certificate file instead.
- The question is `probe.telltale.invalid` A: RFC 6761 makes `.invalid` NXDOMAIN, which the special-name handling answers without an upstream, so a probe tests TelltaleDNS and not the internet. Any well-formed answer is a success (a REFUSED from tight `allowed_networks` still proves the listener answers).
- Probe queries pay the normal query path, so they're counted by the counters (a few per minute), but the telemetry thread drops their events before the analytics, the query log, and the exports (a byte comparison per event there; nothing on the query path). They skip dnstap's forwarder observer (`UpstreamOptions::observe`); dnstap's client-side tap still sees them.
- PROXY-protocol listeners are skipped (the client doesn't send the header) and say so.
- Health (conservative, not in the request): two failures in a row degrade, so one dropped UDP packet doesn't; a node whose every listener fails is `not_serving` (and softened like it in a cluster); a certificate within `cert_warn_days` (14) degrades, an expired one is severe.
- Extra targets (`[probe] targets`, by IP) cover the path devices use: a load balancer's address. Hostnames are refused (no resolver to trust for the probe's own name).
**Consequences:** a new upstream client per probe per round (connection setup included, which is part of what's tested). An extra target that isn't TelltaleDNS answers with whatever it answers, which still counts as answering.

## ADR-106 — Cache sizing from a sampled ghost list of evicted keys (Proposed)
**Context:** the owner asked (2026-10-08) for cache sizing advice from a ghost list (OBS-021), without costing DNS performance. The memory gate (T10.2) is failing, so the estimate itself must stay small; a full ghost list (one record per evicted key) would cost tens of bytes per cached answer.
**Decision:**
- Spatial sampling (SHARDS, Waldspurger et al., FAST '15): only keys whose fingerprint has bits 32–35 clear (1 in 16; the shard uses the high bits and the map the low ones, so the sample is spread over every shard). A sampled key's reuse distance is exact, so the counts scaled by 16 estimate the whole cache.
- Distance in evictions, compared with the shard's live entry count: S3-FIFO isn't LRU, so "N more entries would have held it" is an approximation, good enough to separate "1% more hits" from "nothing to gain"; the advice says "estimated".
- A key counts only if its answer would still have been fresh when it came back (expiry on the entry's own clock), so a bigger cache isn't credited with answers it would have had to fetch again.
- Recorded in `insert` (an upstream answer arrived) and eviction only: the lookup path, hit or miss, is unchanged. Memory: about 50 bytes per sampled ghost, at most 2 × live/16 + 16 per shard (~3 bytes per cached answer).
- Advice thresholds (conservative, not in the request): grow when a step adds ≥ 1 percentage point of hits (the smallest such step); shrink only with no evictions after 100,000 lookups and a peak under half the budget (to the peak plus half, at least 4 MiB); nothing before 10,000 lookups.
**Consequences:** counts restart with the process. The peak is the sum of shard peaks (an upper bound), which only makes "shrink" less likely. Each cluster node judges its own cache.

## ADR-105 — Service-level objectives from the time buckets, with multi-window burn rates (Proposed)
**Context:** the owner asked (2026-10-08) for SLOs with burn-rate alerts, an error-budget card in the UI, and the burn folded into the health level (OBS-016). The data was there (per-minute and per-hour counts by RCODE, latency histograms on `/metrics`), but nothing turned it into objectives, and the time buckets had no latency information.
**Decision:**
- Two objectives, configured in `[slo]` (on by default): availability, responses that aren't SERVFAIL (99.9%), and latency, timed queries answered within `latency_ms` (99% within 250 ms). The event sets match the Prometheus series exactly: availability over `telltale_responses_total` (every RCODE), latency over `telltale_query_duration_seconds_count` (every status but `dropped`), so the UI and Prometheus agree. DNSSEC failures and broken authoritative servers count as SERVFAIL: that's what devices saw.
- `latency_ms` must be a bucket bound of `telltale_query_duration_seconds` (1 … 5000 ms), so a recording rule can compute the same SLI from `le`. The aggregator counts answers slower than it per time bucket (`slow`); the rollups store it as a tagged section after the named groups, which older builds skip.
- The status is a pure function over the federated time buckets (minutes for 6 hours, hours for the window), in `telltale-api` (`slo::status`), shared by the route, the alert rule, and health. Nothing new runs on the query path.
- Warnings use the SRE workbook's multi-window, multi-burn-rate pairs, tuned for a 30-day window: fast 14.4× (1h and 5m), slow 6× (6h and 30m), ticket 1× (3d and 6h). Fast and slow degrade the health level (`slo_burn`) and fire `slo_burn` rules; ticket is shown only.
- Conservative choice (not in the request): a pair needs ≥ 50 answers in its short window and ≥ 10 bad answers in its long one, so one SERVFAIL among 20 answers at night on a home network doesn't page. The Prometheus alerts carry the same minimums.
- Prometheus gets `telltale_slo_objective_ratio{slo}` and `telltale_slo_latency_threshold_seconds`; the chart's `prometheusRule.slo` values render recording rules and alerts, and `deploy/prometheus/build.sh` renders the same group as a plain rules file. The chart's values must be kept equal to `[slo]` by hand (the chart can't read the nodes' configuration).
**Consequences:** the SLO read costs one federated round of time buckets (minutes for 6 hours, ~720 hour rows). Hours stored before this release have no slow count, so the latency objective reads them as all quick until they age out of the window. A target of 100% is refused (no budget).

## ADR-104 — One health level: healthy, degraded, severe (Proposed)
**Context:** the owner asked (2026-10-08) for a health icon next to the navigation's project links, with three states: healthy, degraded (e.g. a cluster node down, clients rate-limited), and severe (an upstream not answering, the system not working). The signals exist (circuit breakers, the cluster view, the query counters, list state, host samples), but nothing combined them, and some (upstream health, readiness) were only ever read on the node answering the API.

**Decision (owner's answers, 2026-10-08):**
- `GET /api/v1/system/health` (and the MCP tool `health`) returns `level` and `reasons` (`level`, stable `code`, `summary`, `node`, a UI `link`). In a cluster every node is asked for its own conditions (a federated read, like the dashboard); the answering node adds the cluster's (peers unreachable or behind). A peer that doesn't answer is listed in `missingNodes`.
- **Severe:** every upstream of a group not answering (open or half-open breaker); no node serving DNS; SERVFAIL for 25% or more of the last 5 minutes' queries (at least 50).
- **Degraded:** one upstream down while its group still answers (the owner's call: one upstream down is degraded); a node unreachable, not serving while others serve, or behind on configuration for a minute; a list failing to download; any query rate-limited in the last 5 minutes (a device asking faster than `[ratelimit]` allows); SERVFAIL 5% or more; a data disk over 90% full.
- Device anomalies don't count (the owner's call: otherwise findings would have to be acknowledged to get the icon green).
- No extra hysteresis: every condition already has a window (the breaker's, 5 minutes, the 15 s heartbeat), so a single failed lookup doesn't change the level.
- The UI polls every 30 s. The icon changes shape as well as color (circle ✓, triangle !, octagon ×), so it reads without color; on phones, where the sidebar is hidden, a dot on the menu button shows when the level isn't healthy.

**Consequences:** a health read costs one federated round (bounded by the 2 s deadline) and a few local reads; nothing touches the query path. Thresholds are fixed for now; making them configurable is a follow-up if the defaults don't fit.

## ADR-103 — Acknowledged anomalies travel with the configuration (Proposed)
**Context:** the owner asked (2026-10-08) for a way to acknowledge anomaly findings and have the whole cluster honor it. Findings were per node (each node learns from the queries it answers), the Anomalies page and badge showed only the node answering the API, and the anomaly alert rule, evaluated on the primary, saw only the primary's findings. Ephemeral resolver pods serve no UI, so their findings were never visible at all.

**Decision:**
- Findings are federated: `GET /analytics/anomalies` gathers every node's, merges the same finding seen by several nodes (one entry, `nodes` lists them), and the alert rule therefore sees them all.
- Each finding has a stable ID: its window start (8 hex digits) and an FNV-1a hash of kind, device, domain, and window length (8 hex digits). Every node computes the same ID, and the ID says how old the finding is, so acknowledgements can be pruned without looking findings up.
- Acknowledgements live in `state.db` (`anomaly_acks`: ID, who, when, note, window start). The primary records them; a replica forwards the write over the cluster channel (as configuration writes are, ADR-054) and records it locally at once so its own pages show it. The primary publishes the whole set as a blob in every manifest (`anomaly_acks`, ignored by older builds), next to users and tokens (ADR-045); replicas replace their copy with it, so a node that was down catches up when it reconnects. An emergency primary passes on the set it inherited.
- Acknowledging isn't a configuration change: it's allowed in a GitOps-managed cluster, like pausing blocking. It needs the operator role (agents: `ops:anomalies`, an immediate op without a plan) and is audited as `anomaly.ack` / `anomaly.unack`.
- Kept 60 days from the finding's window, at most 10,000, so the published document stays small.
- Acknowledged findings stay in the list (hidden unless "Show acknowledged") and keep their evidence; the badge counts only unacknowledged ones, and anomaly alerts skip them.

**Consequences:** an acknowledgement is a new configuration version (seq), like a user change: replicas apply it with a reload, and the Cluster page's timeline shows the version. Acknowledging while the primary is unreachable fails with 503 on a replica, like other writes.

## ADR-102 — Privacy levels cover everything kept or shown (Proposed)
**Context:** review 04-04 and 04-05. `spec/06` §4 defines privacy levels 0–3 ("Pi-hole parity"), and §7.1 says anomaly findings honour them. The levels were applied to the query log, the live tail, and event sinks, but not to `rollups.db`'s hourly top lists, the in-memory analytics the API serves (top lists, a device's page, first-seen domains, anomaly findings), or the anomaly engine. Level 1's hash is unsalted, so anyone holding a log can confirm a guessed name.

**Decision (the owner chose Pi-hole's reading, 2026-10-08):**
- The levels govern everything kept or shown. The aggregator thread applies them once, before the in-memory analytics see an event (`Hub::set_privacy`): names hashed exactly as the query log stores them at 1 and above, client addresses dropped at 2 and above. The query log, tail, and sinks keep applying the level themselves, so nothing is hashed twice; `rollups.db` takes its top lists from the analytics and drops the client list at 2 and above.
- The anomaly engine is off at 1 and above, as it was at 3: its findings name domains and devices, and the DGA score would read hashed names as random. New-device alerts come from it, so they stop too. The masked-client detector is off at 2 and above, where every query looks like one client.
- Counts, graphs, and latency percentiles work at every level.

- Level 1's hash is keyed (review 04-05, owner's choice of a per-cluster key): each node creates a random key in `<data_dir>/privacy.key`; a primary publishes its key in every manifest (`privacy_key`, ignored by older builds) and the other nodes, resolver pods included, adopt it, so names hash the same everywhere and shipped logs group with the primary's. An emergency primary passes on the key it inherited. Logs written before the change keep their unkeyed hashes.

## ADR-101 — A snapshot keeps at most `[filter] max_regexes` regex rules, 1,000 by default (Proposed)
**Context:** Code review of v0.2.0, finding 02-08 (owner's answer, 2026-10-07: a cap, with the overflow reported). Regex rules are tried on every query that no exact or suffix rule settles, and nothing bounded their number. Measured with `matcher_bench` on synthetic patterns sharing a prefix: 200 cost 0.4 µs per query at the median, 1,000 cost 1.1 µs, 1,500 cost 1.6 µs (41 MiB), and 2,000 grew past 5.9 GiB of memory within two minutes. The cause inside the regex engine's automaton wasn't pinned down.

**Decision:** The compiler keeps the first `max_regexes` rules, in list order then line order (default 1,000, `0` = no limit, at most 100,000), and reports the rest as rejected regexes: per list in the manifest (`regex_skipped`), on the Lists page and `GET /api/v1/lists`, as `telltale_list_regex_skipped{list}`, and in the log and `telltale lists compile`. The default sits below the measured cliff with room for lists whose patterns are heavier than the synthetic ones.

**Consequences:** A list shipping more regexes than the limit loses its tail silently to DNS but loudly to operators; raising the limit is the operator's call, with the measurements in `docs/running.md`. If the engine's behaviour is later understood or fixed, the default can rise. `bench-smoke` doesn't yet include the 1,000- and 2,000-pattern points the review asked for.

## ADR-100 — The advertised EDNS payload size is `[dns] edns_payload` (Proposed)
**Context:** Code review of v0.2.0, finding 01-12 (owner's answer, 2026-10-07: a configuration key). DNS-005 says "a configurable advertised UDP payload size (default 1232)", but the value was a constant in the pipeline's settings and no key reached it. The config has no section for answer behaviour, and the spec doesn't name one.

**Decision:** A new `[dns]` section with one key for now, `edns_payload` (default 1232, 512 to 4096: the UDP workers' send buffer is 4,096 bytes, `crates/telltale-net/src/sys.rs`). It needs a restart (listed with the other restart-only sections); other answer-shaping settings can join the section later.

**Consequences:** Operators on a jumbo-frame or fragmentation-safe network can raise the size; the default and the DNS Flag Day reasoning are unchanged. Upstream-facing payload sizes (`edns_payload` per upstream, `spec/04`) are separate and untouched.

## ADR-099 — Connection limits per listener, and per client address (Proposed)
**Context:** Code review of v0.2.0, pass 01 (owner's answer to question 2, 2026-10-07: a per-address cap of 32, configurable). Every stream listener capped connections globally at 1,024 and nothing per client, so one host could take every slot (TCP, DoT, DoH) until a restart; the QUIC listeners had no cap at all (01-02). The spec doesn't say how a client is told apart, or what a balancer does to the count.

**Decision:**
- `[[listen]] max_connections` (default 1,024) and `max_connections_per_address` (default **32**, `0` = no limit) on `tcp`, `dot`, `doh`, `doh3`, and `doq` listeners. Over a limit, a connection is refused or closed at once and counted (`telltale_{tcp,doh,doq}_rejected_total` for the overall limit, `…_rejected_per_address_total` for the per-address one).
- The address counted is the **client's**: after the PROXY protocol v2 header when `proxy_protocol` is on (a balancer's own address is never counted for everyone), and after the QUIC handshake for `doq` and `doh3` (before it, the source address can be spoofed, which would let an attacker spend a victim's budget). An IPv4 client is one address; an IPv6 client is its **/64**, because a host rotates through its prefix; IPv4-mapped IPv6 addresses count as IPv4.
- No address is exempt (loopback included): a limit of 32 is far above what a client needs, and operators who proxy many clients through one address set the limit higher or `0`.

**Consequences:**
- Behind a load balancer that hides client addresses (no PROXY protocol, source NAT, Kubernetes `externalTrafficPolicy: Cluster`), every client shares one count, so the default 32 can starve legitimate TCP/DoT/DoH clients. `docs/running.md` says so next to the key; the Helm chart's default exposure (`externalTrafficPolicy: Local`) keeps client addresses.
- Changing a limit restarts that listener (the existing replace-on-change rule); open connections finish first.
- The count is one short lock per accepted connection, off the UDP path.

## ADR-098 — DNSSEC: library limits are indeterminate; bogus names are logged while trying validation (Proposed)
**Context:** Running `[dnssec] mode = "permissive"` on the live cluster (2026-10-07) counted 14 bogus answers in five minutes. hickory 0.26's validator returns an error both for a broken proof and for its own limit ("exceeded max validation depth", logged at ERROR); TelltaleDNS treated every non-network error as bogus, so `validate` mode would have answered SERVFAIL for such names. Its log named none of them. On `prod.ftl.netflix.com` (unsigned zone, CNAMEs) hickory repeats NS and DS lookups for the same name until the limit. Raising the limit from 26 to 40 overflowed a runtime thread's stack in a debug build.

**Decision:**
- The depth limit stays at hickory's default (26). Hitting it is **indeterminate**: the answer is fetched again unvalidated and served without AD, in both modes. Other validation errors stay bogus.
- In permissive mode every bogus answer is logged at INFO with its name, type, and EDE code (`DNSSEC: bogus answer served (permissive mode)`), so a trial shows which names would fail.
- hickory's `hickory_net::dnssec` log target is off: TelltaleDNS counts and logs each verdict itself (that module warned on every unsigned NODATA).

- **Unsigned zones proven by TelltaleDNS (T10.9).** The trial also showed hickory judging names in unsigned zones bogus when reached through CNAMEs (`www.netflix.com`, `www.amazon.com`, `www.bbc.co.uk`: EDE 10), though it validated the parent's denial of their DS correctly. Before accepting a bogus verdict, an error, or a validation that timed out, TelltaleDNS proves the zone unsigned itself: walking down from the domain under the TLD, the first zone apex (it has its own SOA, from an ordinary query) whose DS the parent validly denies (secure NSEC, or NSEC3 opt-out, which validates as insecure) is unsigned. If every owner in the answer and the question is in such a zone, the answer is insecure. Proven zones are remembered for 15 minutes (at most 4,096), and questions under them aren't handed to hickory again (which also avoids its NS/DS loop).
- Only the DS denial is trusted: whether a name is an apex comes from an unvalidated query, but a signed zone's DS can't be validly denied, so a spoofed apex answer can't make a signed zone insecure. A name inside a signed zone that isn't a cut (`www.isc.org`) is skipped because it has no SOA of its own.
- **Correction (2026-10-07, review 03-01):** the paragraph above is wrong for every name in a signed zone except its apex. A validated denial of a DS proves only that the name has no DS, and every ordinary name in a signed zone has none; the SOA comes from an unvalidated query, so a forger supplies it. Together they let a spoofed answer under a signed zone pass as insecure (and be remembered for 15 minutes). The denial must also show that the name is a delegation: the NSEC owned by the name (or the NSEC3 whose owner is the name's hash) lists NS and lists neither SOA nor DS (RFC 4035 §5.2, RFC 5155 §8.9; the check hickory applies in its own insecure-delegation case). An NSEC3 opt-out denial is still read as unsigned, as hickory has already checked it. The SOA query stays as a cheap pre-filter, never as evidence. The text above is kept as the record of what was first decided.
- **Deadline and limits (2026-10-07, review 03-05, owner's answer: give up at twice the query budget and serve the conservative verdict).** A validation holds one of the pipeline's in-flight permits (`spec/02` §8.4), and the proof walk could run for far longer than the client's budget (up to 3 × budget for the lookup, then up to 12 more queries of one budget each). Now the whole validation, the lookup and any unsigned-zone proof, ends within **two query budgets**; the lookup may use three quarters of that, so a lookup that loops (the Netflix case) is cut off in time for the proof to rescue it, and each step of the proof gets only what the deadline leaves. At most **8 proofs run at once**; one that finds no slot is "not proven". A name whose zone could not be proven unsigned is not walked again for **one minute**. All three can only make the answer more conservative: not proven means the bogus verdict stands, or, if the lookup produced no answer, stale or SERVFAIL as for any upstream failure. The cold-chain allowance for the lookup drops from three budgets to one and a half.

**Consequences:**
- Switching to `validate` can't SERVFAIL a name only because hickory gave up or misjudged an unsigned CNAME chain. Checked live (Quad9, 2026-10-07): in `validate` mode the Netflix, Amazon, BBC, and Apple names resolve (insecure), `isc.org` and `example.com` validate with AD, and `dnssec-failed.org` is refused (SERVFAIL); repeat questions are answered from the cache.
- A bogus verdict costs a few DS and SOA queries the first time a zone is seen (cached after). The first question under a looping name can still take about 1.5 s.
- hickory reports a negative answer whose proof isn't secure as an error carrying the proof (`DnsError::Nsec`); for a DS, `Insecure` is an NSEC3 opt-out denial, read as unsigned like a secure one.
- **Open (cold starts):** right after a start, Quad9 was seen closing DoT connections with queries unanswered (logged as `upstream connection ended why="closed by the server"`); a validation that loses `. DNSKEY` that way caches failures and calls signed zones bogus for a while. The pool now retries such a query once on a fresh connection, which fixed most cases in testing but not every one. Until the cause is known, `permissive` stays the recommended mode.

## ADR-097 — Releases: one workflow, checked before and verified after; main moves on at once (Proposed)
**Context:** T9.26 (OPS-004, owner request 2026-10-07: cut v0.1.0, and make releases deterministic for future agents). Tag builds already published signed binaries, versioned images, and a chart (ADR-038, ADR-046), but cutting one was a manual tag push, nothing checked the version against `Cargo.toml` or the chart, nothing confirmed the result, and edge builds kept the released version's number.

**Decision:**
- A `release` workflow (manual, input `X.Y.Z`) runs `deploy/release/preflight.sh`: X.Y.Z with no suffix, equal to `Cargo.toml`'s and the chart's version, a new tag, a notes file `deploy/release/notes/vX.Y.Z.md`, and a passing CI run on `main`'s head. Only then does it tag `main`'s head.
- A tag pushed with the workflow's token starts no workflows, so the release workflow starts the image workflow on the tag itself (`workflow_dispatch`). The image workflow's publish jobs run for pushes and dispatches on `main` or `v*` tags.
- The tag's build ends with `verify` (`deploy/release/verify.sh`): signatures, the binary's version and channel, "latest release", the four image tags as one multi-arch image, and the chart's version and appVersion. The release is done when it passes.
- Right after tagging, `main` moves to the next version (default: next minor) with `deploy/release/bump.sh`, because semver sorts `X.Y.Z-edge.N` below `X.Y.Z`. The workflow then starts CI and edge for that commit.
- A published tag is never moved or reused; a broken release is followed by a patch release.
- Release notes are hand-written per version; GitHub's generated changelog is appended.

**Consequences:**
- Releases are one button with the same checks every time; `docs/releasing.md` is the procedure for maintainers and agents.
- The workflow pushes one commit to `main` per release. If branch protection is added later, the bump step needs an exception or becomes a pull request.

## ADR-096 — A client group's own upstream group (Accepted)
**Context:** T9.25 (UPS-007, owner request 2026-10-06). UPS-007 already routes by client group (`[[route]] match_group`), but that lives in routing, not on the group, and the UI had no way to set it. The spec doesn't say how it ranks against domain routes, which group wins for a device in several, or what removing an upstream group a group uses does.

**Decision:**
- `[[group]] upstreams = "<upstream group>"`, validated like a route's `upstream_group`. The router turns it into a route for the group's clients that matches any name, placed after the explicit `[[route]]` entries. Precedence: a domain route (deeper suffix), then an explicit route of equal depth (a `match_group` route, which comes first), then the group's `upstreams`, then `default`.
- A device in several groups: the derived routes are ordered by group priority (highest first), then configuration order, so its highest-priority group with `upstreams` decides.
- Removing an upstream group that a client group or a route still uses is refused with a hint, rather than clearing the choice. Clearing it would quietly send, say, the kids' questions to `default` instead of a family resolver. Reverting an API override of the files' entry is allowed (the group stays).

**Consequences:**
- No hot-path cost: routes are consulted only on a cache miss, and the cache is already keyed by upstream group, so groups never share answers from different resolvers.
- `[[route]] match_group` stays for narrower cases (one group's `TXT` questions, say).

## ADR-095 — `$dnsrewrite` in lists: AdGuard's precedence, a supported subset (Accepted)
**Context:** T2.3 kept `$dnsrewrite` rules in the snapshot but didn't apply them (T7.20 put rewrites in the configuration). AdGuard-format lists and personal rule sets use them for local names, safe-search CNAMEs, and blanking names out. Without them those lists lose part of their meaning.

**Decision:**
- **Values supported:**
  - an address, either family (A/AAAA);
  - a name (CNAME);
  - `NXDOMAIN`, `REFUSED`, or `SERVFAIL`;
  - the full form for `NOERROR` with A, AAAA, or CNAME, and any rcode with an empty answer.
  Other record types (MX, TXT, SRV, HTTPS, …) make the line unsupported (counted, skipped), so a list author's intent is never half-applied.
- **Precedence, as AdGuard does it:**
  - a matching rewrite wins over blocking;
  - an exception (`@@…$dnsrewrite`, with or without a value) turns rewrites off for the names it covers;
  - `$client`, `$dnstype`, and `$denyallow` narrow a rewrite like any rule;
  - schedules and quick rules still come first.
- **Combining:** an rcode wins, then the first CNAME, then every address of the asked family. When the name is rewritten only for the other family, the answer is an empty NOERROR.
- **On the query path:** a matcher flag skips everything when no list has rewrites. Otherwise the modifier index is walked once more for the name. The answer has TTL 60, is attributed to the list in the event, and a CNAME is resolved through the normal path (cache, upstreams, filtering of the target).

**Consequences:**
- AdGuard-style lists and personal rules work as their authors meant.
- Configuration rewrites (`[[group.rewrite]]`) stay the per-group tool. List rewrites follow the lists a group uses.

## ADR-094 — Local zones answer SOA and NS at their apex; no zone transfers (Accepted)
**Context:** T7.22's zones answered their records, but not `SOA` or `NS` at the apex. Their negative answers carried a placeholder SOA owned by the question name. Tools (`dig SOA`, monitoring checks, some resolvers' zone-cut detection) expect real ones.

**Decision:**
- **From the zone file:** if it has SOA and NS at its apex, they're served as written. Relative names are completed with the origin.
- **Otherwise, made up** as Unbound does for local zones:
  - NS `localhost.`;
  - SOA `localhost. hostmaster.<zone>`;
  - serial = load time;
  - refresh 3600, retry 600, expire 86400;
  - MINIMUM = `negative_ttl`.
- **Negative answers** (NXDOMAIN and NODATA) carry that SOA owned by the apex, with TTL `negative_ttl` (RFC 2308).
- **Not done:** zone transfers (AXFR/IXFR). They need TSIG and secondary servers, which home and lab installs rarely have. The zone file, or Git, is the source to copy instead.

**Consequences:**
- `dig SOA`/`NS` and negative caching downstream behave as with any authoritative server.
- The made-up `localhost.` name server can't be queried from outside, which is the point: these zones are served by the resolver itself.

## ADR-093 — DNS stamps: enforce their certificate hashes (Accepted)
**Context:** T7.24 parsed DoH/DoT/DoQ stamps but skipped their hashes. A stamp's hashes are SHA-256 digests of the `tbsCertificate` of certificates in the server's chain: the publisher's way of saying "only these CAs (or this certificate) may vouch for it". dnscrypt-proxy enforces them.

**Decision:**
- Hashes are parsed. Each must be 32 bytes, or the stamp is malformed.
- When a stamp has hashes, the normal verification runs first, then some certificate in the presented chain must match one. With `tls_insecure_skip_verify` the match is still required, as for SPKI pins.
- No opt-out switch. Someone who doesn't want the pinning uses the plain URL instead of the stamp, which is clearer than a flag that silently weakens what the stamp says.
- Failures name the cause.

**Consequences:**
- Stamps mean what they say.
- When a provider rotates its intermediate CA before republishing the stamp, that upstream fails until the stamp is updated. A group with another member fails over meanwhile.
- No built-in preset uses stamps.

## ADR-092 — Aggressive NSEC (RFC 8198): NSEC ranges per upstream group, NSEC3 later (Accepted)
**Context:** ADR-086 deferred RFC 8198. The owner asked for the deferred features that make TelltaleDNS a more complete DNS product. Unbound and BIND both do this by default, and on a home network the root zone's NSEC records cover the steady trickle of made-up TLDs (`.lan`, `.home`, `.localdomain`).

**Decision:**
- **What's kept:** after the validator proves a negative answer secure, its NSEC records are cached, keyed by owner in canonical order, per upstream group. Each is kept only if:
  - it's proven secure;
  - it's inside the zone of the SOA that came with it;
  - it's signed by that zone.
  The SOA and all RRSIGs are kept too.
- **How long:** the NSEC's TTL, capped by the SOA's negative TTL (RFC 8198 §5.4). At most 20,000 ranges and 2,000 zones per group; past that, the ones expiring first go.
- **Answering on a miss, before going upstream:**
  - **NXDOMAIN** when one range covers the name and one covers the wildcard at the closest encloser (RFC 4035 §5.4).
  - **NODATA** when an NSEC at the name lacks the type and CNAME, and isn't a delegation (unless the question is DS).
  - **Nothing** below a delegation's or a DNAME's owner. The child zone, or the alias, decides there.
- **The answer:** NXDOMAIN or NODATA with the SOA and NSEC records, plus their signatures for DO clients, and AD as for any secure answer. TTLs are counted down to the earliest expiry. It's counted as synthesized, not as a validation.
- **Switch:** `[dnssec] aggressive_nsec`, on by default, as in Unbound.
- **Deferred — NSEC3:** synthesis needs the zone's hash parameters and a hash per lookup, and opt-out spans prove nothing for unsigned delegations. Worth doing with measurements.

**Consequences:**
- Repeated junk lookups under NSEC-signed zones (the root above all) stop reaching upstreams, and are answered in microseconds instead of a round trip.
- Answers still carry their proof, so a validating client downstream can check them.
- A config reload starts the cache empty, like the validator's own cache.

## ADR-091 — No DHCP server: routers hand out addresses (Accepted)
**Context:** T7.19 added an optional DHCPv4 server (OPS-008, ADR-078). The owner (2026-10-06): most people let their router serve DHCP, and DHCP sits outside what a DNS product should own. Keeping it means a privileged port (67), a lease state machine, and a failover question in clusters, all for few users.

**Decision:**
- The server goes: the code, `[dhcp]`, its end-to-end test, and its documentation. OPS-008 is descoped, and ADR-078 is superseded.
- Device names keep coming from outside DHCP sources:
  - routers' DHCP clients (`[[router]]`: UniFi, OPNsense);
  - mDNS announcements;
  - the importers, which still turn Pi-hole's and Technitium's DHCP reservations into named devices.
- `GET /api/v1/dhcp/leases` stays: these are the router's DHCP leases. It drops `reserved` and `source = dhcp`.
- A configuration that still has `[dhcp]` fails to load with the usual unknown-field error rather than being ignored. Neither of the owner's nodes used it.

**Consequences:**
- About 1,100 lines and a privileged port are gone. The scope stays DNS.
- Anyone who wants TelltaleDNS to serve DHCP needs their router, or dnsmasq beside it.

## ADR-090 — DoH load from h2load; restart counts in the data directory (Accepted)
**Context:** T9.13 picks up the deferrals of T0.3 (DoT/DoH load, a realistic profile) and T6.14 (restart counts, Grafana panels).

**Decision:**
- **Transports bench:** dnsperf (`-m tcp|dot`) measures TCP and DoT.
  - DoH uses h2load, a bench-only tool that isn't shipped. dnsperf's DoH client ran at about 40 ms a query against a listener that answers curl in 175 µs, so it would have measured itself.
  - DoH requests are GETs built from the same corpus, so the names match the other transports.
  - The existing `realistic-home` corpus stays with the swap test. The new mode uses cache hits, because the Python stub upstream would saturate first and hide the transports' cost.
- **Restart counts:** `<data_dir>/runs.json` holds `starts`, `unclean`, and `running`. A start increments `starts`, and adds to `unclean` if `running` is still set, then sets `running`. A clean stop clears it, even when startup fails.
  - It's written only by the process holding the data-directory lock.
  - An unreadable file starts over, rather than failing startup.
  - These are counters, so `increase()` over a range works across restarts. The heartbeat-observed `restarts` column in the cluster view stays as it is (what peers saw).
- **Grafana:** new rows for transports (queries by protocol, TLS/DoH/DoQ/PROXY problems) and the process (uptime, restarts, unclean starts, OOM kills, CPU, temperature, data-disk free). Every expression is checked with `promtool check rules` in the Prometheus image.

**Consequences:**
- What DoT and DoH cost compared with UDP is measured, and repeatable on any machine with h2load.
- A crash loop shows up as a number on the dashboard instead of a short uptime.

## ADR-089 — vqlog `or` and rollup windows; pre-save checks (Accepted)
**Context:** T9.12 picks up ADR-082's "not done" (`or`, rollup-backed long windows) and the pre-save checks deferred from T7.5.

**Decision:**
- **`or`:** `and` binds tighter. A parenthesized group is one term of the `and` list, one level deep. A bare `or` makes the whole stage one group, and mixing it with parentheses is refused as ambiguous rather than guessed. The plan keeps the plain conditions (still pushed into the index search) and adds `any_of` groups checked per row. At most 32 alternatives in all; `in (…)` covers many values of one field.
- **Rollup windows:**
  - **When:** a query whose `from` is older than `retention_days`, or any query while the query log is off, is answered from the rollups when it fits them.
  - **What fits:** `count` only, no `or`, buckets of whole hours, and at most one of status, qtype (the named ones), rcode, proto, and group, used as the key, the filter, or both. The rollups keep each breakdown on its own, so two can't be combined.
  - **Levels:** day buckets use the day rollups; everything else uses the hour rollups.
  - **Labels:** `source` says which store answered. A query that doesn't fit runs over the log as before, with a `note` saying the log only covers `retention_days`.
  - **Not chosen:** answering partly from each store. Its numbers would mix two sources, with no line between them.
- **Pre-save checks:** `POST /api/v1/checks/upstream` and `/checks/list` take the same body as the PUT.
  - The upstream check builds the upstream through the normal router (a configuration holding only it) and asks for `. NS` within 5 s. The list check downloads with `[filter]`'s limits, or takes inline rules, and parses as the compiler does.
  - `path` lists aren't checked: reading server files on request would be a new capability.
  - Both need the operator role and the entry's write scope (they reach out from the node), and both are audited. The paths sit under `/checks/` so they can't collide with an upstream or list named `test`.

**Consequences:**
- An agent can ask "blocked per day for six months" and get exact counts.
- Questions that need names or clients stay limited to what the log keeps, and the answer says so.
- A typo in an upstream URL or a dead list URL shows up before it's saved.

## ADR-088 — DNS64 exclusions and reverse names; syslog over TLS; a webhook spill (Accepted)
**Context:** T9.10 and T9.11 pick up the deferrals of T7.21 (DNS64) and T7.13 (event sinks).

**Decision:**
- **DNS64 exclusion set (RFC 6147 §5.1.4):** `dns64_exclude` on the group takes networks of either family. An excluded AAAA counts as missing. With all of a name's AAAA records excluded, AAAA records are made up for it. With some left, the excluded ones are removed, along with signatures, since the set they signed changed; DNS64 already never applies to CD clients. An excluded A record is never made into AAAA. `::ffff:0:0/96` is always excluded, as the RFC recommends.
- **DNS64 reverse names (§5.3.1):** a PTR question for an address inside the client group's /96 gets a CNAME to the embedded IPv4 address's `in-addr.arpa` name, resolved like a safe-search target. A private IPv4 address keeps RFC 6303's local NXDOMAIN, so it never goes upstream. Of the RFC's two options, the CNAME was chosen over making up a PTR record: it needs no state and shows where the answer comes from.
- **Syslog over TLS (RFC 5425):** `tls://host:port`, with octet-counted frames as on TCP, rustls with the public roots plus `tls_ca`, and the certificate checked against the host in the address. No client certificates (none asked for yet).
- **Webhook spill:** off unless `spill_max_bytes` is set (at least 1 MiB).
  - Refused batches are appended as JSON lines to `<data_dir>/sinks/<name>.spill`, with the send offset in a `.pos` file, so a restart doesn't resend what was sent. The file is compacted when it needs room and removed when it's empty.
  - Replay runs up to 20 batches after a delivered batch or on a quiet tick, and stops at the first failure. Events that arrive meanwhile wait in the sink's normal buffer.

**Consequences:**
- IPv6-only networks get working reverse names and can route around unreachable IPv6 ranges.
- A SIEM can take events over TLS.
- A collector outage no longer loses events, up to the cap. The disk writes happen only during an outage, on the sink's own thread.

## ADR-087 — Upstream follow-ups: DoH GET, UDP over SOCKS5, DNSCrypt relays, per-client ECS (Accepted)
**Context:** T9.9 picks up the deferrals of T7.8 (DoH), T7.16 (proxies), T7.23 (ECS), and T7.24 (DNSCrypt).

**Decision:**
- **DoH GET:** `doh_method = "get"` puts the query in `?dns=` (base64url, no padding) with ID 0; POST stays the default (smaller requests, no URL length concerns).
- **UDP through SOCKS5:** a `udp://` upstream with a `socks5://` proxy uses UDP ASSOCIATE (RFC 1928 §7). Up to four associations are kept for reuse; one whose control connection or relay fails is dropped. The TCP retry for a truncated answer goes through the proxy too. HTTP proxies still refuse `udp://` in the configuration check.
- **Anonymized DNSCrypt:** `relay` (a relay stamp, type 0x81, or `ip:port`) on a DNSCrypt upstream prefixes every packet with the anonymized-DNSCrypt header (8 × 0xff, 0x0000, the server's address as IPv6, its port), the certificate query included, over UDP and TCP. One relay per upstream; choosing relays at random from a list is left to configuring several upstreams in a group.
- **Per-client ECS (`ecs = "client"`):** the client's source address cut to /24 or /56 (RFC 7871 §11.1). Gaps resolved conservatively:
  - nothing is sent for non-public sources (private, loopback, link-local, CGNAT, ULA);
  - ECS options sent by clients are still never forwarded or echoed, so a downstream forwarder never caches an answer as if it were scoped;
  - the cache key gains the packed subnet (8 bytes per key, 0 when unused), but only for groups that have a `"client"` member, which is a flag checked once per miss;
  - entries are keyed by the source prefix, not the upstream's SCOPE: never shared more widely than the subnet sent, at the cost of fewer hits;
  - scoped entries aren't written to the cache file, whose format has no subnet.

**Consequences:**
- DNSCrypt users get the anonymity dnscrypt-proxy's relays give, and SOCKS5 users keep UDP's latency.
- `ecs = "client"` multiplies cache entries by the number of client subnets; it's meant for resolvers with public clients, and does nothing on a home network.

## ADR-086 — Recursion and DNSSEC follow-ups: priming, hedging, EDE reasons, an anchors file; RFC 5011 and 8198 deferred (Accepted)
**Amended by:** ADR-092. RFC 8198 (aggressive NSEC) was implemented later; RFC 5011 stays deferred.
**Context:** T9.8 picks up the deferrals of T6.3 (DNSSEC) and T7.15 (recursion).

**Decision:**
- **Root priming (RFC 8109):** on first use, the hints are asked for `. NS`; the answer's glue (or, without it, lookups of the names) becomes the cached root zone cut, renewed when it expires (TTL capped at a day). A failed attempt waits a minute before the next.
- **Hedged queries:** a server that hasn't answered after 1.5 × its smoothed RTT (at least 150 ms; 400 ms when unknown) is joined by the next server; the first usable answer wins. It costs at most one extra query per slow step, inside the 96-query budget.
- **EDE reasons:** a bogus answer's RRSIGs give the code: none for the records that answer → 10, all expired → 7, all not yet valid → 8 (serial-number time comparison), else 6. The library's validator doesn't expose its reason, so this reads the signatures it returns.
- **Trust anchors:** both current root KSKs (20326, 38696) ship built in (a test pins them). `[dnssec] trust_anchors_file` replaces them with a file of DNSKEY records; a bad file keeps the built-in ones.
- **Deferred — RFC 5011** automated trust-anchor updates: they need a persistent state machine with a 30-day hold-down for a root KSK change that happens every several years, which builds already carry. The anchors file covers the gap.
- **Deferred — RFC 8198** aggressive NSEC caching: it needs a cache of validated NSEC/NSEC3 ranges next to the library's validator and answer synthesis on the query path; worth doing with measurements, not as a follow-up.

**Consequences:**
- Recursive lookups ride out a slow server and a moved root server.
- SERVFAILs say why a signature failed.
- Validation survives the root key rollover with no action.

## ADR-085 — Alert email: a small built-in SMTP submission client (Accepted)
**Context:** T9.4 (OBS-010 lists email as a destination; deferred in T7.12). The owner has no relay of their own.

**Decision:**
- A minimal client in the binary (`smtp.rs`, written from RFC 5321/3207/4954/5322) over the rustls stack already shipped, instead of a mail library: one message per connection, STARTTLS (`smtp://`, 587) or implicit TLS (`smtps://`, 465), AUTH PLAIN or LOGIN, the public roots plus `tls_ca`, base64 text bodies, RFC 2047 subjects.
- A password is only sent encrypted: STARTTLS can't fall back to plain, and `smtp+insecure://` (for local catchers) refuses a username in the configuration check.
- Validation: CI runs a scripted SMTP server (STARTTLS with a private CA, implicit TLS, a wrong password reported as 535); Mailpit was checked by hand as an independent implementation; real delivery is the owner's choice of provider (a Gmail app password needs no relay).
- Not done: HTML mail, DKIM (the provider signs), a queue (a failed alert is logged like any destination).

**Consequences:** email works with any provider that offers SMTP submission, for about 30 KiB of code and no new dependency.

## ADR-084 — WASM upstream plugins: deferred, and wasmi rather than wasmtime if built (Accepted)
**Context:** M8 lists WASM upstream plugins; `04` §3 and ADR-007 name wasmtime behind a feature flag. T7.16 shipped the out-of-process plugins (`unix://` and `exec://`, DNS wire format), which already let any language implement an upstream.

**Measured (2026-10-06):** stripped, LTO, `panic = "abort"` release binaries of a program that compiles one module, against an empty program, on x86_64 Linux:

| Engine | Adds (raw) | Adds (gzip -9) |
|---|---|---|
| wasmtime 49 (Cranelift JIT, component model) | 9.4 MiB | 3.3 MiB |
| wasmi 2.0 (interpreter, pure Rust) | 1.7 MiB | 0.6 MiB |

The release binaries are 19–23 MiB raw today, and the image budget is 15 MiB compressed (OPS-001).

**Decision:**
- Don't build WASM plugins now. There's no user request; the process plugins cover the use case; and a sandboxed host networking API is a design of its own.
- If they're built, use **wasmi** behind an off-by-default `wasm` feature. It costs about a fifth of wasmtime's size, is pure Rust (no JIT, so it runs on armv7 and under seccomp profiles that forbid executable memory), and is fast enough for a per-query function that mostly waits on the network.
- Revisit on a concrete request, for example a resolver protocol that people want to ship as one file.

**Consequences:**
- M8 closes without code here.
- The plugin story stays the process boundary: crash isolation, and any language.

## ADR-083 — io_uring UDP: measured, not adopted (Accepted)
**Context:** M8 lists io_uring; `02` §3 calls it "a P2 experiment behind a feature flag". The UDP listener already batches with `recvmmsg`/`sendmmsg` on one `SO_REUSEPORT` socket per worker, so the syscall cost per query is already amortized.

**Measured (2026-10-06):** a standalone spike, not in the repo: one server thread doing the same per-datagram work both ways (64-slot `RecvMsg`/`SendMsg` io_uring ring vs 64-message `recvmmsg`/`sendmmsg`), loopback, WSL2 kernel 6.18, 8 cores, alternating 5-second rounds.
- With 4 client threads: 530.8k vs 526.3k answered per round (io_uring −0.9%).
- With 7 client threads (server about 90% CPU): 456.8k vs 471.6k (+3%).
- The spread between rounds was about ±15%, so neither difference is meaningful.

**Decision:** keep `recvmmsg`/`sendmmsg`; don't add an io_uring listener or feature. Reasons:
- No measured gain.
- More `unsafe` in the hot path (buffers that must outlive submissions).
- A second listener to test.
- io_uring is often unavailable where TelltaleDNS runs: Docker's default seccomp profile blocks it, and some distributions disable it (`kernel.io_uring_disabled`).

Revisit if a profile on real hardware shows syscalls dominating at the owner's target rates. Multishot receive with provided buffers would be the variant to try.

**Consequences:**
- One UDP code path.
- The M8 item is closed with data rather than code.

## ADR-082 — vqlog: a pipe language compiled to qlog searches, aggregated in memory (Accepted)
**Context:** T8.4, AGT-012: "a constrained, safe query DSL (`vqlog`) over the query log and rollups (filter, group by, top-K, percentiles, time bucket), with a cost estimate, exposed as one tool". The spec doesn't fix the syntax, the limits, or the scope.

**Decision:**
- Syntax: stages separated by `|` — `from`, `where` (conditions joined by `and`; `in (…)` lists instead of `or`), `bucket`, `by`, `stats`, `top`, `sort`, `limit`. A fixed grammar parsed into a plan in `telltale-api` (syntax errors are 400s with hints); no expressions, functions, or joins. The name kept from the spec (`vqlog`) although the product was renamed.
- Execution reads the query log only, not the rollups: rollups can't filter by name or client, and percentiles over them would be approximations of approximations. The conditions the qlog index can use are pushed into the search (time, one name, one client, group, statuses, qtypes, rcodes, one upstream, minimum latency); every condition is also checked on each row. Grouping is exact, in memory; percentiles are exact (nearest rank).
- Cost: a header-only estimate (segments, blocks, and rows that could match, using the same block skipping as search) before the scan, returned with every answer; `dryRun` returns only that. Above 100 million estimated rows the query is refused. The scan stops at 2 million matches, 100,000 groups, or 25 seconds and reports `truncated` with the reason; results then cover the newest queries.
- Access: `querylog:read` (it reads per-device, per-name rows); not group-aware, so group-restricted agents can't use it. Scope: this node's log plus the logs shipped to it (CLU-007), so the primary of a shipping cluster sees everything; `missingNodes` as elsewhere.
- Not done: `or` between fields, rollup-backed long windows, per-cluster fan-out with mergeable sketches, a UI editor.

**Consequences:**
- One MCP tool answers most analytics questions with exact numbers and a visible cost; the narrow tools stay for the common ones.
- Long windows on busy networks are slow (it scans), and the limits say so instead of degrading DNS (search threads run at background priority).

## ADR-081 — mDNS device naming: passive, A records of `<name>.local` (Accepted)
**Context:** T8.3 (M8 "mDNS client naming"; API-010 lists mDNS as a naming source). Many devices announce their host name over mDNS (RFC 6762) whether or not anyone asks.

**Decision:**
- `[clients] mdns` (off by default): join 224.0.0.251 on the mDNS port (5353, address and port reuse) and read A records owned by a two-label `<name>.local` in the answer and additional sections of responses others send. Never send queries or responses (no probing, no load on the network). IPv4 only, like the DHCP and router names.
- The latest name per address is kept in memory (4096 at most, the oldest tenth dropped when full) and published every 5 s; device names fall back to configured clients, DHCP leases, router leases, then mDNS.
- Service instance names (`Living Room._airplay._tcp.local`), link-local and unspecified addresses are ignored.
- Not done: asking (`QU` queries to fill the gaps), IPv6 (AAAA owners would need the neighbor table to match clients), persisting across restarts, showing the names in the leases API.

**Consequences:**
- Devices get readable names without a router integration or DHCP, on networks where TelltaleDNS can hear multicast.

## ADR-080 — Router integrations: read-only polling of UniFi and OPNsense (Accepted)
**Context:** T8.2 (M8 "router integrations"; API-010 lists DHCP leases as a naming source). Most homes run DHCP on the router, so TelltaleDNS's own DHCP (T7.19) doesn't see those leases.

**Decision:**
- `[[router]]` entries are polled read-only (`interval_secs`, 300; 15 s after a failure). UniFi: `stat/sta` (connected clients) with an API key (`X-API-KEY`), or a local user's login (UniFi OS `/api/auth/login` and `/proxy/network/...`, falling back to the classic `/api/login`); the UniFi alias wins over the host name. OPNsense: the lease search of Dnsmasq, then Kea, then ISC, with the API key and secret (basic auth).
- The result replaces that router's part of a lease view next to the DHCP server's; device names fall back to configured clients, then DHCP leases, then router leases. `GET /api/v1/dhcp/leases` lists both with a `source`.
- Self-signed consoles: `tls_ca` (the console's certificate), or `tls_insecure_skip_verify` with a configuration warning. Secrets come from files.
- Not done: OPNsense static mappings without a lease, pfSense, OpenWrt. (UniFi's offline known clients: ADR-166.)

**Consequences:**
- Device names appear on networks where the router runs DHCP, with no change on the router beyond a read-only account or key.

## ADR-079 — DNSCrypt with RustCrypto's crypto_box; stamps map to existing transports (Accepted)
**Context:** T7.24 (UPS-003; `04` §2). DNSCrypt v2 needs X25519 and libsodium's box constructions; `02` §7 lists no crate for them. Stamps may name DNSCrypt, DoH, DoT, or DoQ servers.

**Decision:**
- New dependency `crypto_box` 0.9 (RustCrypto; its SalsaBox and ChaChaBox are libsodium's `crypto_box` and `crypto_box_curve25519xchacha20poly1305`, on the `curve25519-dalek` already in the tree) and `ed25519-dalek` (already in the tree) for certificates. The IETF XChaCha20-Poly1305 AEAD is a different construction and wouldn't interoperate. The detached API is used and the tag written first (libsodium's `_easy` layout); verified live against five providers' servers.
- One X25519 key per upstream for its lifetime (like dnscrypt-proxy's default); a fresh random nonce per query; ISO 7816-4 padding to 64 bytes, at least 256 over UDP; TCP when the answer is truncated.
- Certificates: TXT records of the provider name fetched in clear, each checked with the stamp's Ed25519 key (`verify_strict`) and its validity dates; the newest construction, then the highest serial, wins; refreshed after an hour or at expiry.
- DoH/DoT/DoQ stamps become those transports (host name as the TLS name, an address in the stamp pinned); the stamp's certificate hashes aren't enforced yet.
- Not supported: anonymized DNSCrypt relays, DNSCrypt stamps' `props` flags (DNSSEC, no-log, no-filter are informational).

**Consequences:**
- Users of dnscrypt-proxy's server list can paste stamps directly.
- About 100 KiB more in the binary.

## ADR-078 — DHCPv4: authoritative, broadcast replies, leases name devices (Superseded)
**Superseded by:** ADR-091. The DHCP server was removed on 2026-10-06; this record stays for history.
**Context:** T7.19 (OPS-008; `08` §7). The spec lists the options, static leases, and a lease file, but not the server's stance toward clients asking for foreign addresses, how replies reach clients without an address, or how leases "feed client naming".

**Decision:**
- A module of the binary (`crates/telltale/src/dhcp.rs`), its own task and socket (socket2: `SO_BROADCAST`, `SO_REUSEADDR`, optional `SO_BINDTODEVICE`), never on the DNS path.
- Authoritative for its subnet (like `dhcp-authoritative` in dnsmasq): REQUEST for an address this client may not have (someone else's, outside the pool, another subnet) gets NAK; INIT-REBOOT for a free pool address is granted. Offers are held 60 s; DECLINEd addresses are skipped for 10 minutes; no ping-before-offer.
- Replies (RFC 2131 §4.1): to `giaddr:67` via a relay, to `ciaddr:68` when the client has an address, else broadcast to `255.255.255.255:68` (no raw-socket unicast to an unconfigured client: broadcast is allowed and needs no extra capability).
- Options 1, 3, 6 (default: the server's address), 15, 28, 42, 51, 54, 58, 59, 119 (RFC 3397, uncompressed; split per RFC 3396 when long).
- Leases persist to `<data_dir>/dhcp-leases.json` after every change; the live view (address → lease) is published on the pipeline, so device names fall back to the lease host name (a configured client name wins), and `GET /api/v1/dhcp/leases` reads it.
- In a cluster, one node runs it (documented); other nodes don't see its leases yet.

**Consequences:**
- A Pi can replace the router's DHCP; unnamed devices get readable names immediately.
- Without failover, a second DHCP node needs split pools (not supported in config yet).

## ADR-077 — dnstap: a sampled copy of the wire messages, off by default (Accepted)
**Context:** T7.18 (OBS-007; `06` §5). dnstap needs the query and response messages, which query events don't carry (`02` §3: no allocation on the hot path).

**Decision:**
- The tap is a `OnceLock` on the pipeline set at startup: with dnstap off, the query path pays one atomic load. With it on, one query in `sample_every` (a relaxed counter) is copied, both messages, into a bounded channel with `try_send`; full means dropped and counted. Measured with bench-smoke: no change with it off (within WSL run-to-run noise).
- The writer thread speaks bidirectional Frame Streams (READY, ACCEPT, START; STOP at the end) to a Unix socket or TCP reader, reconnects with backoff (1 s to 30 s), and writes `CLIENT_QUERY` and `CLIENT_RESPONSE` (address, family, transport including DoT/DoH/DoQ, times, messages; identity = node name, version = TelltaleDNS version). Protobuf is encoded by hand: the schema is small and fixed.
- Deferred: `FORWARDER_QUERY`/`FORWARDER_RESPONSE` (they'd need a tap in the upstream exchange), and the client's port (not on the event path).

**Consequences:**
- At `sample_every = 1` every query costs two small allocations and a channel send; the docs say to sample on busy resolvers.

## ADR-076 — OTLP over HTTP with JSON, metrics converted from our exposition (Accepted)
**Context:** T7.17 (OBS-006; `06` §5). The spec asks for "the same metric set via OTLP/HTTP" and optional QueryEvent logs, without an encoding or a mapping.

**Decision:**
- OTLP/HTTP with the JSON encoding (the protobuf JSON mapping: 64-bit integers as strings). No OpenTelemetry SDK and no generated protobuf types: the binary stays small, and every OTLP/HTTP receiver accepts JSON.
- Metrics are converted from our own Prometheus exposition every `interval_secs`: counters → cumulative monotonic sums (start time = process start), gauges → gauges, histograms → explicit-bucket histograms (per-bucket counts from the cumulative ones). Names and labels are kept as in `/metrics`, so dashboards and docs apply to both.
- Query events as logs are an event-sink format (`otlp_logs`, ADR-072): batching, buffering, and retries are the sink's. Body: a one-line summary; attributes use OpenTelemetry DNS-style keys where they exist (`dns.question.name`, `client.address`), `telltale.*` otherwise.
- No OTLP/gRPC.

**Consequences:**
- Collectors that convert back to Prometheus see `_total` already in counter names (most keep it as is).
- A counter reset (restart) shows as a new start time, as OTLP expects.

## ADR-075 — Proxies, socket plugins, pins, and client certificates (Accepted)
**Context:** T7.16 (UPS-010, UPS-011; `04` §2, §6). The spec names the features but not where a proxied hostname is resolved, how an `exec://` plugin learns its socket, how plugins restart, or how pins interact with `tls_insecure_skip_verify`.

**Decision:**
- Proxies (SOCKS5 with RFC 1929 credentials, HTTP CONNECT) carry `tcp://`, `tls://`, and `https://` upstreams; others are a configuration error. A hostname URL goes to the proxy by name (SOCKS5 ATYP 3, `CONNECT host:port`), so no bootstrap is needed and no lookup leaks (Tor). Proxy addresses are IP literals (or `localhost`). UDP through SOCKS5 (UDP ASSOCIATE) stays P2.
- Socket plugins speak RFC 7766 framing over a Unix socket, on the same pipelined connection pool as TCP upstreams. `exec://` plugins get `TELLTALE_PLUGIN_SOCKET` (`<data_dir>/plugins/<upstream>.sock`) and `TELLTALE_UPSTREAM` in their environment, `args` as arguments, stdin closed, stdout and stderr logged per line; they restart with backoff (1 s doubling to 60 s, reset after a minute up) and are killed when their upstream is dropped (each reload rebuilds upstreams, so a reload restarts plugins).
- Pins are base64 SHA-256 of the leaf's `SubjectPublicKeyInfo`, checked after the normal WebPKI verification; with `tls_insecure_skip_verify` only the pin is checked. `tls_ca` adds roots for one upstream; `tls_client_cert`/`tls_client_key` (PEM) enable mTLS. Files are read at load and reload.
- Deferred: DoH GET, the WASM upstream ABI (P2).

**Consequences:**
- Tor users point an encrypted upstream at the Tor SOCKS port with a hostname URL and nothing else.
- A plugin that needs state across reloads must keep it itself (it's restarted on configuration changes).

## ADR-074 — Our own iterative resolver, conservative defaults (Accepted)
**Context:** T7.15 (DNS-012, UPS-012; `03` §6). `02` §2 allows building on `hickory-recursor`. The spec fixes the limits (16 CNAME hops, 32 referrals) and asks for QNAME minimization, 0x20 (configurable), SRTT server selection, glue in bailiwick, and RFC 8198, but not the defaults, the timeouts, or how the resolver meets the per-query budget.

**Decision:**
- `telltale-recursor` is our own iterative resolver on `telltale-proto` (no new dependencies): exact control over minimization, bailiwick rules, and limits, and nothing added to the image beyond its code.
- It's a transport of `telltale-upstream` (`recursive://`), so groups, hedging, health, the answer cache, and DNSSEC validation (which then fetches DNSKEY and DS through it) work unchanged. Its attempt timeout is at least 3 s (not the 1 s cap of forwarders); the query's overall budget (2 s) still bounds a client's wait, and zone cuts learned meanwhile stay cached, so a retry continues from there.
- Defaults: QNAME minimization on, relaxed (RFC 9156 §2.3: the full name after NXDOMAIN or failure on a minimized query; at most 10 minimized steps); 0x20 off (a few authoritative servers don't echo case; when on, such servers are remembered and asked plainly); IPv6 off (many home networks lack an IPv6 route); root hints built in, no priming query.
- Bailiwick: answers only for names under the zone being asked; glue only for server names under the referring zone; upward or sideways referrals are lame. A server name inside its own zone without glue is skipped.
- Caches: zone cuts with addresses and server-name addresses (20,000 entries each, TTLs clamped to 30 s..1 day), server SRTT (EWMA). Final answers are cached by the answer cache only.
- Limits: 16 CNAME/DNAME hops, 32 referrals per lookup, 4 nested lookups for server names, 96 queries per client question, 4 servers tried per question, 1.2 s per server at most.
- RFC 8198 (aggressive NSEC) is deferred: it needs validated NSEC records kept below the validator.

**Consequences:**
- The common "Pi-hole + unbound" setup becomes one upstream; imports from Technitium without forwarders use it directly.
- A cold resolution in a zone with slow or broken servers can exceed the 2 s budget the first time (the client gets SERVFAIL or a stale answer; the next query succeeds from the learned cuts).

## ADR-073 — DGA scoring and NXDOMAIN storms: fixed formulas, shipped bigrams, absolute storm bar (Accepted)
**Context:** T7.14 (OBS-009; `06` §7). The spec names the signals (entropy, consonant runs, bigram log-likelihood) and the storm rule shape ("> X/min and > Y%") but not the weights, thresholds, the bigram source, or how findings are grouped.

**Decision:**
- The bigram table is 27 × 27 signed bytes (`presets/bigrams.bin`, `round(4 × log2 P(next | previous))` with start and end symbols) built from the public-domain dwyl/english-words list, embedded in the binary.
- The score of a registrable domain's own label (8 to 63 characters, not `xn--`) is `0.7 × max(bigram, mix) + 0.2 × consonants + 0.1 × entropy`, each clamped to 0..1: bigram = (mean bits per letter pair − 6) / 2; mix = (letter/digit switches − 2) / 4; consonants = (longest run − 5) / 3; entropy = (normalized entropy − 0.85) / 0.15. Calibrated on ~200 real service domains (none reach 0.2) and random-letter and hex labels (0.8 to 1.0). Logs come from tables, so the score is identical on every architecture.
- Only first-seen domains of devices past their learning period are scored for findings; a `dga` finding needs at least 2 at or above the sensitivity's threshold (0.75, 0.6, 0.5) in one hour, and is one finding per device-hour with samples.
- An NXDOMAIN storm is absolute (no baseline): at least `nxdomain_per_minute` (30) NXDOMAIN answers and `nxdomain_percent` (50 %) of the device's queries in a calendar minute; once per device per hour.
- The first-seen feed starts after a device's first day (its initial learning would flood it) and keeps the last 2000 entries, persisted with the engine.
- List overlap is counted at compile time (pairs of lists per shared name); `hits` are this node's counts since start, not 24 h / 7 d windows from the query log.

**Consequences:**
- Dictionary-word DGAs and short generated labels aren't caught; some vendor IDs may score high (the UI shows the score, not a verdict).
- A restart resets list hits; overlap is exact for the active snapshot.

## ADR-072 — Event sinks: one bounded buffer per sink, API-shaped JSON, no disk spill (Accepted)
**Amended by:** ADR-088. Syslog over TLS and a capped disk spill for webhook sinks were added later.
**Context:** T7.13 (OBS-010; `06` §5). The spec asks for JSON-lines, syslog, and webhook sinks "with retry and a disk spill cap", but not the event format, how a slow sink is kept off the query path, or how retries are bounded.

**Decision:**
- An event is the API's query row (`QueryRow`: the same fields and names as `GET /api/v1/queries`, names resolved when the event is written, the query log's privacy level applied), so a sink's output and the API's agree.
- The aggregator thread formats each event once and offers it to every sink with `try_send` on a bounded channel (`max_buffer`); each sink writes from its own thread. A full buffer drops the event, counted and logged once a minute. DNS and the query log never wait for a sink.
- The webhook posts batches (`batch` events or `flush_secs`), retries a failed batch twice (1 s, 2 s), then drops it. Events buffer in memory only; the "disk spill cap" isn't implemented: the query log already keeps every event on disk.
- Syslog is RFC 5424 over UDP or TCP (RFC 6587 octet counting); TLS isn't implemented yet. Severity is *notice* for blocks and *informational* otherwise.
- Sinks are started once at startup (like the query log's writer); a reload doesn't change them.

**Consequences:**
- A collector outage loses events beyond the buffer; the query log, which sinks don't replace, still has them.
- Syslog over TLS needs a forwarder (rsyslog, Vector) until it's added.

## ADR-071 — MCP over OAuth: JWT access tokens from the OIDC provider, for existing users only (Accepted)
**Context:** T7.4 (AGT-008, P1). MCP clients sign in with OAuth 2.1: the server publishes RFC 9728 metadata naming an authorization server, and accepts that server's access tokens. The spec says to use the configured OIDC provider but not how tokens become principals, or which tokens are accepted.

**Decision:**
- One provider is the authorization server for MCP (`[auth.oidc] mcp_provider`). TelltaleDNS is only a resource server: client registration, consent screens, and refresh are the provider's.
- Accepted tokens are JWTs signed with the provider's published keys (asymmetric algorithms only), with its issuer, the audience `mcp_audience` (default `<public_url>/mcp`), and a current expiry (60 s leeway). There's no introspection, so opaque tokens are refused.
- The token's `sub` must match a user who has signed in to the web UI with that provider (ADR-034). An unknown subject is refused rather than creating an account, because access tokens rarely carry the group claims that decide roles.
- The principal is an agent of that user: the TelltaleDNS scopes in `scope` or `scp` (or the read-only default when there are none), never above the user's stored role; audited as `agent:oauth:<azp> (owner: <user>)`. Rate limits, the kill switch, plans, and approvals apply as for agent tokens.
- An unauthenticated or refused `/mcp` request gets `WWW-Authenticate: Bearer resource_metadata="…"` (and `error="invalid_token"` when a token was sent).

**Consequences:**
- Assistants connect with SSO and the user's consent, and no long-lived token is stored in the assistant.
- Each request verifies a signature (keys cached with discovery, refreshed on rotation); no per-token cache is kept.
- Providers that only issue opaque access tokens need a token per agent instead, until introspection is added.

## ADR-926 — Credential rules in the forms: judged from the saved entry, and a draft that needs an admin is held (Accepted 2026-11-17)

**Context:** T24.16 puts ADR-903 §4's admin rules in every form (API-014). The server already refuses each change; the forms must show the owner who may make it and why, and must not let an operator fill in a change that will be refused. Two details are open: a form's lock can only use what is saved, and the upstream headers and arguments have no field in the form until T27.3.

**Decision:**
1. **Locks are judged from the saved entry.** A field's `admin` rule reads the entry as it was read, and the credential paths it keeps (`ConfigEntry.redacted`: headers, arguments, a password in an address). A draft's own value doesn't make a field read-only, since a field that locks while it's being typed can't be corrected. A draft that switches to a program address (`exec://`, `unix://`), or changes a saved program entry's arguments, instead holds Check and Apply with the reason (`ConfigEditor` `adminOnly`, which is given the saved entry, or none for a new one), and the server refuses it too. A saved program entry changed only in its weight, timeout or other fields is not held.
2. **The rules as the forms apply them.**
   - Upstreams: `url` is an admin's when the entry keeps a credential or runs a program (saved); `tls_server_name` when it keeps one. "Keeps a credential" is the server's `holds_credential`: a redacted path, a credential file (`tls_client_key`), or a stored reference (`*_ref`, `*_refs`).
   - Alerts: `type` is an admin's when the destination holds a credential (the existing `url`, `tls_ca` and secret rules are unchanged).
   - Names on my network, forwards: a server that is `exec://` or `unix://` is an admin's, and Save is off for an operator.
   - Every kept credential shows the badge "kept: re-enter to change" in its row.
3. **Headers and arguments.** They have no field in the upstream form until T27.3. A change of the address that the server refuses for a kept header says which field, and that the form can't enter it: use `telltale ctl` or the configuration file. No headers field is added here, so the message is the resolution this task owes (T24.16's "or the message above").

**Consequences:**
- A form can be stale about a rule the server adds later. The server stays the authority: every refusal still comes back as a problem code, and its message reads as a sentence (ADR-927).
- An operator who pastes an `exec://` address sees the reason and a disabled Save, not a refusal after the fact.

## ADR-927 — Problem codes read as sentences in the UI; the server's detail stays on the error (Accepted 2026-11-17)

**Context:** T24.16 asks that `ApiError` give readable messages for the credential codes (`path_not_allowed`, `set_by_file`, `credential_reentry_required`, `upgrade_required`, `secret_missing`, `secret_in_use`, `secrets_locked`, `insecure_transport`, `lists_not_here`). Until now `ApiError.message` was the server's `detail`, which names the field well but reads as a log line. Two places (`SecretField`, `SecretsPanel`) matched the detail's text to recognise a secret that is in use elsewhere.

**Decision:**
1. The problem `code` is the contract. `ui/src/lib/api.ts` maps each listed code to a sentence, which becomes `ApiError.message`. The server's text stays on `ApiError.detail`, unchanged.
2. A code with no sentence reads as the server's detail, as before.
3. Recognition of a case by its text uses `detail`, never the sentence (`secret_in_use` "can't be read now").
4. The field a detail names (its first backquoted token, never the `<redacted>` marker) is quoted in the sentence, so the owner sees which setting to change. A `credential_reentry_required` sentence follows the detail's case: a check never uses a stored value (Test it), no stored value to keep, or the destination changed. A header or an argument's hint is not shown beside its sentence, since the sentence already says how to enter it.
5. The Routers page's credential input (`CredentialInput.svelte`, T23.8's open item) is replaced by `SecretField` and removed. Its Playwright tests use the field's `data-mode` and its save button.

**Consequences:**
- A sentence is text the owner reads, so changing one is a UI change: the Playwright test `api_015 errors read as sentences` names each code and the words it must show.
- The sentences are in English only, as the rest of the UI is.

## ADR-958 — The live network map: a sampled, bounded window on the aggregator thread, SVG drawn from a rate snapshot (Accepted 2026-11-17)
**Context:** M26 (fork #14, OBS-901, OBS-902). The owner wants an animated map of the network (gateway, networks and VLANs, devices, TelltaleDNS nodes, upstreams) and of where answers point, coloured green, yellow or red, built on existing data, with nothing added to the DNS path (02 §3, CLU-004), the UI inside its 400 KiB budget, and every control in the UI. This ADR fixes the design the M26 tasks build. The GeoIP database is ADR-959. Facts checked in the code: the aggregator thread already drains the worker rings and fans out to subscribers (live tail, sinks) through bounded queues, after the exclusions and the privacy level have been applied (ADR-102); `QueryEvent` carries client, group, status, rcode, upstream, `t_total_us` and `answers` (a count), but **no answer address**; ADR-132's flow counters are per minute and have no per-device joint; the health level (ADR-104) and the SLO (`[slo] latency_ms`) exist; `GET /api/v1/networks` and the device identities give the networks and names; M25's switch and port data is not built yet.

**Decision:**

1. **Data model.** A snapshot is `nodes` and `edges`, all derived, none stored.
   - Node kinds: `gateway` (one; the router integration's status), `network` (a VLAN or subnet from `/api/v1/networks`, else the groups' networks, else one `other`), `device` (a client address with its inventory name, ADR-901/910), `resolver` (one per TelltaleDNS node, including resolver pods), `answer` (three terminal kinds per resolver: `cache`, `local`, `blocked`), `upstream`, and in the world view `region` (a country, ADR-959) plus an optional marker per geolocatable upstream.
   - An edge `from → to` has `qps` (a 60 s window), `count`, `slowPct`, `errPct`, `blockedPct` and a `health`. Edges: device → resolver, resolver → upstream, resolver → each answer kind; network and gateway edges are structural (no rate). A node carries `health`, `reasons[]` (stable `code`, `summary`, as ADR-104) and `qps`.
   - Bounds: at most 200 device nodes drawn per snapshot (the busiest; the rest fold into one `+N more` node per network), 2,048 edges, 64 regions. `truncated: true` says so.
2. **Where it is computed.** A **map sampler** is one more subscriber of the aggregator thread's fan-out, but fed from the **post-privacy stage next to the in-memory analytics**, not from the tail: ADR-102 has the aggregator apply the privacy level once (`Hub::set_privacy`) before the analytics see an event, while the tail and sinks apply the level themselves, so they are pre-privacy paths. The sampler therefore never sees a client key the level hides and has no filter of its own to get wrong. It costs the DNS path nothing: no new ring, no new counter, no lock a worker takes.
   - **Sampling.** Every ~250 ms it takes the events queued for it and keeps at most `event_rate / 4` of them. The selector is **counter-based** (every Nth event, N from the previous tick's rate, with a carried remainder), so it is deterministic and testable, and each kept event is **weighted by N**. A snapshot's `sampleRate` says how thin the counters are.
   - **Drops.** The subscriber queue is bounded. Events it cannot accept are **counted** (a plain counter on the aggregator side) and added to the tick's total before N is computed and to the weights, so an overflow thins the sample but does not bias it down; a snapshot with drops reports `dropped` and the UI shows "sampled" with it. A rare failure can still be missed under overload; that is the stated limit of an estimate.
   - **`min_sample` counts real events.** The `idle` and confidence checks (section 4) use the **unweighted sampled count** (events actually kept), never the weighted one, so one kept SERVFAIL at N = 50 is one event, not fifty.
   - **Window and memory.** 12 slots of 5 s (60 s) of counters keyed by (device, resolver, answer kind, upstream). One entry is a 16-byte client key, two `u16` ids, a kind byte, and five `u32` fields (sampled count, weighted count, slow, error, blocked): about 48 bytes, about 80 bytes with hash-map overhead. A slot holds at most **1,024 keys** (the rest count under `other`), so the counters are at most 12 x 1,024 x 80 B, about 960 KiB in the worst case, **capped explicitly at 1 MiB in total** (a flood stops adding entries at the cap). A ring of the last 20 sampled lookups for each of the 64 busiest edges adds about 40 KiB. T26.2 measures the RSS delta under the **Pi profile** (one run at idle, one after the key cap is hit by a flood of distinct devices, steady for 5 minutes) and the Done note records both; the gate is a delta of at most 1.5 MiB at the cap, and a result above it changes the key cap, not the gate. `event_rate` defaults to 200 per second per node (10 to 2,000). With `[map] enabled = false` the sampler isn't subscribed and the routes answer `404 map_disabled`.
3. **Nothing on the hot path.** The only worker-side change allowed is the answer address for the world view (OBS-902): a 17-byte `answer: Option<Addr>` the worker **copies** from the cache entry (computed when the entry is inserted, on the miss path, never parsed on a hit) into the event. It ships only if the ring record does not grow and `make bench-smoke` is within its noise band (see the test plan). The record is `Record`, a `QueryEvent` or an `UpstreamEvent` by value with an inline name of up to 255 bytes in the query variant, so the slot is set by the larger variant: T26.2 step 1 records `size_of::<Record>()` and `size_of::<QueryEvent>()` before and after in its Done note (a `size_of` assertion test pins them), and the keep-or-drop decision is made on those numbers. Otherwise T26.5 ships with upstream markers only, **labelled as the upstreams' location and not where answers point** (step 1 of T26.2). Blocked and local answers carry no address (they are synthesized).
4. **Health classification** (one pure function, table-tested; thresholds in `[map]`, defaults from ADR-104 and `[slo]`):
   - A device, edge or upstream with fewer than `min_sample` (default 20) **sampled (unweighted)** answers in the window is `idle` (grey; not a health state).
   - **Red:** SERVFAIL or timeout share ≥ `error_pct` (25, ADR-104's severe line); an upstream whose breaker is open; a resolver that is unreachable (a cluster peer missing from the read) or not serving.
   - **Yellow:** SERVFAIL share ≥ `warn_error_pct` (5); slow share (answers over `warn_latency_ms`, default `[slo] latency_ms`) ≥ `warn_slow_pct` (10); a breaker half-open; any rate-limited query from a device; a device's blocked share ≥ `warn_blocked_pct` (60, devices only); a device with an open unacknowledged anomaly finding (only when the privacy level is 0 and the engine is on, ADR-102); the gateway when its router integration reports an error.
   - **Green:** none of those. A network or resolver node takes the worst of its children, plus its own ADR-104 level for a resolver (severe → red, degraded → yellow); it shows "n red, m yellow".
   - **Structural nodes.** The gateway is green when its router integration is healthy, yellow on an error (above), and grey (`idle`, reason `not_configured`) when there is no integration; it is never red, because the DNS path does not depend on it. A `network` node takes the worst of its devices (grey when none has enough samples). An `answer` node (`cache`, `local`, `blocked`) takes the slow share of its edge and is never red from the blocked share (blocking is the intended outcome). The classification table and its tests cover each of these.
   - Colour is never alone: the shape and the words change too (circle ✓, triangle !, octagon ×, as ADR-104).
   - Settings are the shared section `[map]` (`enabled`, `event_rate`, `min_sample`, `warn_latency_ms`, `warn_slow_pct`, `warn_error_pct`, `error_pct`, `warn_blocked_pct`; `[map.geoip]` is ADR-959), a one-of kind like `[exclusions]`: `GET/PUT/DELETE /api/v1/map-settings/default`, scope `config:write:map`, MCP `plan_set_map`, Settings → Monitoring. Operators change thresholds and the rate; the GeoIP controls are admin-only. A GitOps authority refuses the write and shows the TOML (ADR-914). Out-of-range values are `422` with the field named.
5. **API** (viewer reads; all in OpenAPI; errors as problem+json):
   - `GET /api/v1/map`: the snapshot above, with `generatedAt`, `windowSecs`, `sampleRate`, `privacy` (the strictest level in force), `truncated`, `partial`, `missingNodes`. Optional filters `network`, `group`, `device`, `node` narrow it on the server.
   - `GET /api/v1/map/stream`: SSE, one `snapshot` event every 2 s (the same body) and a `ping` every 15 s. One shared ticker builds **one unfiltered snapshot** for all subscribers and **stops when none remain**; the `network`, `group`, `device` and `node` filters apply to `GET /api/v1/map` only, and the UI filters the stream's snapshot client-side (a view keeps its URL filters either way); at most 8 subscribers per node (`429 map_streams_busy`). The UI closes the stream when the tab is hidden. Pulses are not per-event: the UI derives them from each edge's rate (below), so the stream stays small and a peer node's flows animate like local ones.
   - `GET /api/v1/map/world`: `{available, reason?, updatedAt, regions[{cc, name, qps, count, slowPct, health}], markers[], unlocated{count, reason}}`; `available: false` with `reason` `geoip_off`, `geoip_missing` or `address_not_recorded` when it cannot be drawn.
   - MCP read tool `network_health` (scope `read:stats`): counts by health, the red and yellow nodes with their reasons (at most 50), and the five busiest flows; no device names at privacy level 2 or above.
6. **Cluster.** Every node samples its own events. The answering node gathers each full member's local map by the federated read (ADR-104's 2 s deadline, run through `blocking()` as ADR-946 requires). **A ticker never waits on a peer:** a separate gather task polls each peer on its own schedule with that deadline and keeps a per-peer **last-good result** with its age; the snapshot builder only reads those, and a peer whose last-good result is older than 3 intervals (6 s) counts as missing and sets `partial`. One dead peer costs at most one blocked pool thread per interval and never stalls the stream, sums the weighted counts of the same edge, merges a device that asked several nodes by its client key, and lists each node as its own `resolver`; a node that does not answer is a red `resolver` with reason `unreachable` and appears in `missingNodes`. Resolver pods are included. For the world view a node returns its top 256 answer prefixes (/24 for IPv4, /48 for IPv6) with counts, and the answering node resolves countries, so only nodes that serve the UI need the database.
7. **Privacy** (ADR-102). The privacy level is **one global setting** (`telemetry.qlog.privacy_level`), applied once by the aggregator before the sampler sees an event (section 2). The map follows the same rule as the discovery feature, which refuses to enable at level 2 and above, and the rest is simple. Level 0 and 1: devices are shown by address and inventory name (clients are not hidden at 1); **no domain name appears anywhere in the map**, and the click-through to queries follows the level's own rules (hashed at 1). Level 2: devices are not shown; the sampler receives no client key (a test asserts it, not only that the output hides it), so each network has one `device` node named "devices hidden by privacy", with no click-through, and flows are per resolver, upstream and answer kind. Level 3: no per-event data, so the map shows network and resolver totals from the counters only, and the world view counts everything as unlocated, reason `privacy`. Anomaly-based yellow is off at level 1 and above. The snapshot's `privacy` field (the level in force) lets the UI say why a part is missing. The MCP `network_health` tool (scope `read:stats`) returns device names at levels 0 and 1, as ADR-102 allows; the tool's description says so and the tool is in the `obs_901_roles` test.
8. **Rendering.** Inline **SVG**, no graph or map library, a deterministic layered layout in TypeScript (columns: gateway and networks, devices, resolvers and answer kinds, upstreams; devices ordered by network then rate; no force simulation). Canvas was rejected: the DOM is what Playwright and screen readers can read. World view: an equirectangular dot grid from a 1-bit land mask (about 2 KB) with country centroids (about 6 KB), no remote tiles, fonts or scripts (CSP `connect-src 'self'`); a remote tile source is not offered. The 400 KiB budget (`ui/scripts/postbuild.mjs`) is for **every file in `dist/` together**, lazy chunks included, and that is also what lands in the image (ADR-916). So the rule is: the map chunk, with its data, is at most 30 KiB gzipped **and the build's total stays at most 400 KiB**. T26.3 records the `dist` gzip total (the postbuild summary) before and after in its Done note, and the world data (land mask, centroids, country names) is a separate file whose own gzip size is recorded (target at most 12 KiB) and counts in the chunk. At most 150 edges animate (the busiest), and on a small host (the Pi profile, or `navigator.hardwareConcurrency` of 4 or fewer) at most 60; the rest are drawn static. A Playwright check animates 150 edges and asserts a median frame time under 33 ms in the e2e browser (a documented noise band, not a Pi measurement).
9. **Animation and accessibility.** A pulse is a CSS-animated dash along an edge: density from the edge's `qps` (1 dash per ~0.5 qps, at most 6 per edge), width from `log(qps)`, colour and shape from `health`, with a seed per edge so a refresh does not restart it. It runs on `animation-play-state`, set to `paused` when `document.hidden` and when the user pauses it. With `prefers-reduced-motion: reduce` nothing moves: the dashes are static, the rate is a label on the edge, and no control turns motion back on. An always-available **table view** (`<table>`: from, to, qps, share slow, share failing, health in words) is the accessible equivalent; the SVG sits in a `role="group"` (a `figure`) with an `aria-label` and a text summary, **not** `role="img"` (that makes its children presentational, so the node buttons would not be exposed); each node is a focusable `role="button"` with an `aria-label` that gives its state in words, Tab reaches it and Enter opens its panel, and a Playwright keyboard test covers it. Colours pass WCAG AA in both themes (NFR-008).
10. **Interaction.** A node click opens a side panel with its numbers and links: a device → Queries filtered to it, Explain, Anomalies for it, its device page; an upstream → Upstreams; a resolver → Cluster; a network → Networks. Filters (network, group, device search, node, health) are in the URL so a view can be linked; they narrow the server read (`network`, `group`, `device`, `node`) as well as the drawing.
11. **Choices made where the issue left room** (the most conservative; the owner can overrule): a fixed 60 s window and 2 s refresh; the world view places upstreams (markers) as well as answers, as a toggleable layer (answering the issue's open question); arcs start at a marker "Your network" below the map unless `[map.geoip] home_country` is set; errors have no address, so a region's colour comes from the slow share, and failed lookups are counted as "no location" rather than drawn; M25's switch and port data is drawn as a device's parent only when the inventory already carries it (a conditional step of T26.3, not a blocker).

**Test plan.** Unit: the classification, table-driven at every boundary (`min_sample`, each threshold, half-open, rate-limited, anomaly, rollup, privacy collapse); the sampler is unbiased (a synthetic stream at 5x the cap, with the counter-based selector, so the run is deterministic; each edge's estimate is within 5%), unbiased under overload (a queue forced to drop a share of the stream still estimates within 5% because drops are counted), bounded (a flood of distinct devices stays at the 1 MiB entry cap and counts `other`), idle with no events, and a single sampled SERVFAIL with N >= 20 is not red (`min_sample` on real events); `obs_901_privacy_levels` asserts that **no client key reaches sampler state** at levels 2 and 3; the cluster merge (same edge on two nodes, a device on both, a missing node). API: OpenAPI, MCP and schema snapshots regenerated; the federated read with a dead peer; roles (viewer reads, operator thresholds, admin GeoIP); the 429 on a ninth stream; the ticker stops at zero subscribers; a dead peer does not delay a tick (the interval stays 2 s with `partial` set). Performance: `make bench-smoke` shows no regression; the aggregator-throughput check is an **A/B of 7 alternating runs (sampler on, off) compared by their medians**, passing when the on-median is within **5%** of the off-median (the noise band of this harness; the measured run-to-run spread is recorded with the result, and the gate does not claim a 2% resolution the harness lacks); the RSS delta is measured as in section 2 (at most 1.5 MiB at the key cap, Pi profile); the animation frame-time check of section 8. Playwright (the e2e server has no real traffic, so snapshot answers are mocked with `page.route`, plus one run on the node's own queries): layout, keyboard (Tab to a node, Enter opens the panel), each colour state with its shape and words, filters, click-through, the table view, `reducedMotion: 'reduce'` (no running animation), a hidden tab (animations paused, the stream closed), the "off" and "needs database" states of the world view, and the settings tests of T26.6.

**Alternatives rejected:** counting per device on the workers (a hot-path cost); a force-directed layout or a graph library (bundle size, and moving nodes are hard to read and to test); canvas (no DOM for tests or screen readers); per-event pulses over the stream (bandwidth, and a peer's events would not arrive); remote map tiles (CSP, privacy, an outside dependency); a stored history (the existing heatmaps and flow already keep it).

**Consequences:** the map is an estimate under load (the sample rate is shown) and shows at most the 200 busiest devices; a quiet device is grey, not green; the world view depends on the answer-address field and a downloaded database and degrades to a clear message without either. Where a choice is between memory and disk (the owner's note on the footprint: more disk cache is fine, RAM is the budget), the map keeps its window small in memory and puts anything large on disk (ADR-959).

## ADR-959 — The GeoIP database: DB-IP Country Lite, downloaded on an admin's opt-in, verified, kept on disk, never on the query path (Accepted 2026-11-17)
**Context:** OBS-902 needs the country of an answer address. NFR-001 and the owner's rule forbid shipping a database in the image; ADR-916's gate is for the image, and RSS is the hard budget on small hosts. The owner's note (2026-11-17) is that where it matters the footprint can use more disk cache rather than RAM.

**Decision:**
1. **Source and licence.** DB-IP "IP to Country Lite", CSV (`start,end,country`), published monthly under **CC BY 4.0**: using it needs attribution, and we don't redistribute it (each install downloads it from the publisher). The world view's footer, `docs/third-party-notices.md` and the site page carry "IP geolocation by DB-IP.com" with the licence link. Default URL `https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz` (this month, else last month: on the 1st the new file may not be published, so a 404 for this month makes one more request for the previous month before the attempt counts as failed). DB-IP's terms are **re-checked at each release** (a line in the release checklist). The URL is a setting an admin can change to their own HTTPS mirror. **Rejected:** MaxMind GeoLite2 (an account and key, an EULA that forces deletion on update), IP2Location Lite (an account), a bundled copy (NFR-001), an online lookup API (it would send answer addresses to a third party), an ASN database (a later addition if wanted).
2. **Opt-in, admin-only, UI-controlled.** `[map.geoip] enabled = false` by default: nothing is fetched until an admin turns it on in Settings → Monitoring (`source_url`, optional pinned `sha256`, `home_country`). Status and last update are shown to every role; the toggle, the URL, **Update now** and **Delete database** are admin-only (not agent-writable; ADR-914's guard, audited as `map.geoip.*`). The setting is shared; each full member that serves the UI fetches its own copy, started at a per-node jitter of up to 6 h so a cluster doesn't hit the publisher at once. Resolver pods never fetch.
3. **Download.** A background task (never a worker, never on the query path) with the list downloader's rules: HTTPS only, at most 3 redirects, each to HTTPS, the same address restrictions as list sources, a 30 s connect and 120 s total limit, at most 32 MiB compressed and 96 MiB uncompressed, one attempt at a time. It checks at most once a day and fetches only when the stored month is older than the current one. A failure backs off 1 h doubling to 24 h and shows its code, never a response body.
4. **Verification.** The publisher gives no signature, so: TLS to the configured host; the gzip CRC; every line parses as `start,end,CC` with a two-letter code; after sorting, no overlaps; at least 100,000 rows, at least 150 distinct countries, both address families present; the row count within 30% of the database it would replace; and the pinned `sha256` when set. The monthly file changes digest every month, so a pin is only useful with a **fixed mirror URL** whose content the admin controls; with the default URL the field should stay empty, and the UI and docs say so. A failure keeps the current database, reports `verification_failed` with the reason code, and retries the next day. These checks guard against a truncated or tampered-with file rather than prove authenticity, and the docs say so.
5. **Storage and lookup.** `<data_dir>/geoip/country.ttgeo`, a compact file the node builds from the CSV: a header (magic, version, source month, row counts, a checksum), a sorted IPv4 table (start `u32`, country `u16`) and a sorted IPv6 table (the first 64 bits, country `u16`; ranges are cut to /64, which is conservative). The tables have no end column, so **the builder stores an explicit gap row (country `0`, "unassigned") wherever one range ends before the next begins**; without it an address in a gap would resolve to the previous country. The golden gap test stays. Written to a temporary file, fsynced, then renamed; the previous file is kept as `.prev` until the next success. About 1 to 5 MiB; at most 16 MiB or it is refused. **Nothing is held on the heap:** a lookup is a binary search with positional reads (`pread`, via `std::os::unix::fs::FileExt` or `seek_read` on Windows) through the OS page cache, **not a memory map**, which would need `unsafe` outside `telltale-net` (AGENTS rule 7). It is done only when the API builds a world answer (at most 256 prefixes), **inside `blocking()`** when called from an async handler, and never for a query, so the resident set is untouched and the disk cache does the work. A file that fails its checksum is ignored (`geoip_missing`) and fetched again.
6. **Status and states.** `GET /api/v1/map/geoip`: `enabled`, `state` (`off`, `downloading`, `ready`, `failed`), `sourceMonth`, `updatedAt`, `rows`, `sizeBytes`, `nextCheckAt`, `lastError` (a code). A database older than 90 days still works and is flagged "old". Turning the toggle off stops fetching and leaves the file; the world view then says "GeoIP is off"; **Delete database** removes it.
7. **No new heavy dependency.** Decompression uses a gzip decoder already linked, or `miniz_oxide` after `cargo-deny`; the image delta is reported and must be near zero (T26.4 AC).
8. **Test plan.** A local fake HTTPS source (with a **test-only loopback allowance**, off in release builds and set only by the test harness, as the lists tests have, because the real address restrictions block 127.0.0.1) serves good, truncated, overlapping, too-small, wrong-checksum and redirecting files (`obs_902_*`); the off state makes no request; the database is rewritten atomically after a crash during write; lookups match a golden table at range edges, gaps, IPv4, IPv6 and a v4-mapped address; the lookup holds no table in memory (the heap does not grow with the file); Playwright covers the toggle, the status, the read-only view for operators and viewers, the admin actions (**Update now** runs a fetch against the fake source and shows the new status; **Delete database** asks for confirmation, removes the file and shows `geoip_missing`; both absent or disabled for operators and viewers), and the world view in both states.

**Consequences:** a fresh install shows the world view as unavailable until an admin opts in; country accuracy is DB-IP Lite's (country level, good for a picture, not for compliance); a mirror lets an air-gapped site use the feature.

## ADR-960 — Turning on automatic failover under a running cluster: the primary adopts it live, a replica stands only after a lease it saw lapses, replicas relay each other's health (Accepted 2026-11-17)
**Context:** T21.5's three-node run found that `set-failover auto` on a running cluster was unsafe (T21.5 open (a)): the replicas adopt `auto` from the signed records, while the primary kept running in manual mode and renewed no lease, so a replica could be elected and depose a healthy primary. The CLI warned and `docs/running.md` said to turn it on before the replicas join. The owner decided on 2026-11-17 that the running primary adopts the mode with no restart and that a replica never stands against a primary that has not yet held a lease (T21.7). The same run showed that replicas in manual mode report each other as not heard from (T21.5 open (1)), because a replica has a stream only to its primary until automatic failover starts the replica mesh.

**Decision:**
1. **The primary adopts `auto` live.** The election task reloads `cluster.json` as soon as its modification time changes (a `stat` per 250 ms tick on the cluster task, never on the DNS path), and at least every 5 s as before. When automatic failover becomes active on a node that is the primary (`Primary` or `Emergency`, epoch above 0, holding the cluster key), its elector starts as `Leader` of the epoch it already has (`Elector::resume`), with no election and no new epoch, and renews with every voter at its next tick (`renew_now`), not after a full interval. The lease starts at zero: publishing pauses until a majority grants the first renewal (about one round trip; `Cluster::begin_lease`, which pauses without the "lease lapsed" warning that is for a lease that was held and lost). The same applies whenever the elector is rebuilt on a primary (a voter joins or leaves, a restart): it resumes its epoch rather than standing again. Safety is unchanged: a voter refuses a renewal at an epoch older than its ballot or at an epoch it gave to another candidate, and the primary then steps down as in any election; the grant of a renewal at the primary's own epoch is the existing `Ballot::decide` rule.
2. **A replica stands only after a lease it saw lapses.** A server node calls `Elector::stand_only_after_a_lease`: it may start a pre-vote only if it has seen a lease from another primary, that is, its stored ballot names another candidate with a lease, or it has granted a non-pre vote or renewal to another candidate since the elector was made (`lease_seen`), or its stored ballot is for itself (it was the primary) and it has learned of a newer epoch (an election needs a lease, and a deposed primary's own old lease refuses its successor's renewals for a lease period; found by `deploy/cluster/failover-e2e.sh` step 4). The lapse itself is the existing check that the lease it granted is no longer running (`lease_held_by_other`), and the first-try wait of one lease period (ADR-947 addendum) stays. So a primary that never held a lease under `auto` is never deposed, and a cluster whose primary is already down when `auto` is turned on elects nobody (conservative choice: promote by hand, as `docs/running.md` says). `Elector::new` keeps standing allowed (`lease_seen` true), so the protocol simulator and a first election from nothing are unchanged.
3. **Replicas relay each other's health.** The heartbeat carries `peers` (tag 41, repeated `PeerHealth { node_id, age_ms, ready, applied_seq }`, at most 64): the members the sender heard within the `up` window and how long ago. A receiver keeps, for each named member other than itself and the sender, the newest report as `heard_ms` on its own clock. A member it has no fresh stream to is shown **up** with link `relayed` while a report is within the `up` window; a member it hears directly is never taken on a relay's word. Older nodes ignore the tag and send none. The registry-only "down" rows (ADR-155) skip a relayed member. No new connection and no new protocol version (CLU-010).
4. **Docs and CLI.** The `set-failover` warning and the ordering note in `docs/running.md` are removed; the command says that no restart is needed.

**Alternatives rejected:**
- *A replica reading the primary's mode from the records and refusing to stand while the primary is manual.* The primary's `auto` and the replicas' arrive in the same record, so there is no moment a replica can tell the two apart.
- *Making the replica mesh run in manual mode too.* It adds streams to clusters that chose manual failover; the relay costs a few bytes in a heartbeat.
- *Taking a fresh lease for granted at adoption.* A ballot a voter still holds for another candidate may run; the first round is the proof, and the pause is one round trip.

**Review fixes (2026-11-17):** (a) a node with no running election (manual mode) refuses real votes for a new epoch (it still grants a renewal to the primary it follows in its current epoch, which lets a primary that just adopted `auto` get its lease and publish the record that turns the replicas to `auto`) and answers pre-votes, so a primary that has just left `auto` and writes freely cannot be raced by a replica that a manual-mode voter would otherwise grant; (b) each rebuilt elector numbers its rounds from a process-wide generation, and a leader counts a grant only if it carries the led epoch, so a delayed reply to a predecessor never counts; (c) the standing rule is looser than "a lease from the current primary": any stored ballot for another candidate with a lease counts, however old. This is safe because votes still decide, and is the conservative reading; (d) a primary that cannot lead under `auto` (not eligible or no cluster key) logs a warning and stops publishing, as no replica has seen a lease; (e) relayed rows can come from any member's heartbeat and affect only the view and `peers_up`, never elections, so they are not limited to voters.

**Consequences:** `set-failover auto` is safe at any time. A primary pauses publishing for about one round trip when it adopts the mode. A replica that joins or restarts takes over only after its first renewal from the primary (at most 5 s later; the older scripts `deploy/cluster/failover-e2e.sh` and `gitops-failover-e2e.sh` wait for it before they kill the primary). A replica that has never seen a lease (a cluster that has only just turned `auto` on, with its primary down) waits for one. A heartbeat grows by about 40 bytes per member heard. Tests: `clu_005_t21_7_a_running_primary_adopts_auto_and_is_not_deposed`, `clu_005_t21_7_a_replica_stands_only_after_a_lease_it_saw_lapses`, `clu_005_t21_7_a_stored_ballot_counts_as_a_lease_seen`, `clu_001_a_replica_learns_that_another_replica_is_up_from_the_primarys_heartbeats`, the Playwright test `clu_005 the failover mode changes on the Cluster page without a restart`, and `deploy/cluster3/e2e.sh` check a2.

## ADR-961 — The Pi-hole compatible API: v6 and v5, read plus blocking on/off, one token, off by default (Accepted 2026-11-17)
**Context:** T24.10 (fork #7, API-002, API-005, AGT-001). The owner wants dashboards, phone apps and the Home Assistant Pi-hole integration to work against TelltaleDNS unchanged, with **read and enable/disable only** (owner decision 2026-11-17), behind a token, off by default. Clean room: this ADR is written from Pi-hole's public API documentation and from what the Home Assistant `pi_hole` integration and its `hole` library (MIT) actually request, read from the `ghcr.io/home-assistant/home-assistant:stable` image on 2026-11-17. No Pi-hole code was read or copied.

**What the Home Assistant integration calls.** It probes v6 first (`POST {base}/api/auth` with `{"password": ...}`), and falls back to v5 (`GET {base}/{location}/api.php?summaryRaw&auth=<token>`; `location` is `admin` by default) when v6 fails with anything but a 401. v6 then reads `/api/stats/summary`, `/api/stats/top_domains?blocked=true|false&count=10`, `/api/stats/top_clients?count=10`, `/api/stats/upstreams`, `/api/dns/blocking` and `/api/info/version`, each with the session in `X-FTL-SID` (and `X-FTL-CSRF`); it switches blocking with `POST /api/dns/blocking` `{"blocking": bool, "timer": seconds|null}`; it signs out with `DELETE /api/auth`. v5 reads `summaryRaw`, `versions` (no token), and switches with `enable=True` and `disable=<seconds|True>`. A v5 probe with a wrong token must get `[]`.

**Decision:**
1. **Both dialects, one token.** v6 is primary (current Pi-hole, tried first by Home Assistant); v5 `admin/api.php` is served too, because phone apps and older dashboards still use it and Home Assistant falls back to it. The **same token** is the v6 `password` and the v5 `auth` value, so one credential works for either.
2. **Endpoint set (nothing else exists; every other path stays the problem+json 404 of the API):**
   - v6: `POST /api/auth` (sign in), `GET /api/auth` (the session's state), `DELETE /api/auth` (sign out); `GET /api/stats/summary`, `GET /api/stats/top_domains`, `GET /api/stats/top_clients`, `GET /api/stats/upstreams`, `GET /api/info/version`, `GET /api/dns/blocking`, `POST /api/dns/blocking`.
   - v5 at `/admin/api.php`: `summaryRaw`, `summary`, `status`, `topItems`, `enable`, `disable[=seconds]` (token), and `versions` / `version` (no token, as in Pi-hole v5, because the Home Assistant integration asks for them without one; they return only our version string).
   - Of these only `POST /api/dns/blocking`, `enable` and `disable` write, and they only start or end a pause of everyone's blocking. Lists, rules, groups, settings and the other pause options stay on `/api/v1`.
3. **Auth mapping.**
   - The token is `random_secret()` (32 random bytes, URL-safe base64), **shown once** when an admin issues or rotates it, and stored as its **BLAKE3 hash** (the same scheme as API tokens: the secret has 256 bits, so a fast hash is safe). Comparison is **constant time** (`crypto::ct_eq`).
   - v6: `POST /api/auth` with the token as `password` opens a **session** held in memory: a random `sid`, a `csrf` value, `validity` 300 s that every use renews, at most 32 sessions (the oldest is dropped). The `sid` comes in `X-FTL-SID` or the `sid` query parameter, **never a cookie**. Rotating the token, turning the API off, or a restart ends every session.
   - v5: `auth=<token>` on each request. Without a valid token the answer is `[]` (as Pi-hole), HTTP 401 for a write.
   - **Failed attempts** (a wrong password, token or sid) count against the client address in the same lockout as sign-in (5 free, then 30 s doubling to 15 minutes; the first lock is audited as `auth.lockout`), answered 429 `rate_limiting`. A success clears the count.
   - **A correct credential is never locked out.** The presented credential is tested first and a correct one goes through even from a locked address, so a stale client behind the same address (NAT, a proxy, the Docker bridge) cannot lock out the right one; the lock applies to failures only. A session ends 24 hours after sign-in however often it is used (a sid in the query string is as exposed as v5's `auth`; the docs say so).
   - **Off, or no token set:** `/api/...` paths answer the API's normal 404 and `/admin/api.php` answers as any unknown page does (the web UI), so a scanner learns nothing, and nothing is audited.
4. **Which of our numbers back each field** (a 24 hour window, summed from the same buckets as `GET /api/v1/stats/summary`, cluster-wide when clustered):
   - `queries.total` / `dns_queries_today`: all queries. `queries.blocked` / `ads_blocked_today` and `percent_blocked`: the `blocked` status. `queries.cached`: `cached` + `stale` + `refreshed`. `queries.forwarded`: `forwarded`. `queries.types`: the query-type counts. `queries.status`: `GRAVITY` = blocked, `FORWARDED`, `CACHE`; `queries.replies`: by response code (`NXDOMAIN`, `SERVFAIL`, `REFUSED`; `NOERROR` is `IP`; the rest `OTHER`).
   - `gravity.domains_being_blocked`: the active snapshot's blocked names (`filter_names`). `clients.active`: the busiest clients of the window (`top_range`, at most 1,000); `clients.total` / `clients_ever_seen`: the same count over 30 days (at most 10,000), refreshed every 10 minutes. `queries.unique_domains`: the distinct names among the 1,000 most queried (a floor on busy networks; the real count is not kept).
   - `top_domains`, `top_clients`, `upstreams` come from `top_range` (domains, blocked, clients) and the upstream list (`requests` as `count`, the smoothed latency as `statistics.response`). The statistics (not the blocking status) are cached for 10 s, so Home Assistant's several reads cost one aggregation.
   - `dns/blocking`: `disabled` while any node has an everyone-pause (the longest `secondsLeft` as `timer`), else `enabled`; `unknown` when no node answers. A pause of one group does not make it `disabled`.
   - `versions`: our version as `core`, `web` and `ftl` current; the latest versions are empty and no update is ever offered.
5. **Pause is the same pause.** The handlers call the same function as `POST /api/v1/blocking/pause` / `resume` (one shared core, so the validation, the cluster fan-out, the change marker and the audit entry are identical), with the actor `token:pihole-api` and the client address. `timer` seconds become whole minutes, rounded up. **Pi-hole's "disable with no timer" (forever) is not offered:** it pauses for the setting `maxPauseMinutes` (default **60**, 1 to 1,440, an admin may raise it in Settings), like an agent's cap (spec/13 §3.2): a credential in a URL or a phone must not be able to leave filtering off for good. A longer `timer` is cut to it. The answer reports the real `timer`.
6. **Listener, networks, CSRF, sessions, audit.**
   - **Same API listener**, no new socket. The paths above are added next to `/api/v1`; `[access] allowed_networks` (the listener's `only_allowed` layer) applies to them first, as to every API path. The compatibility paths are outside the sign-in session machinery: they accept no cookie, so a browser's ambient credentials never apply, and there is **no CSRF surface** (a forged cross-site request cannot carry the token or sid). When `X-FTL-CSRF` is sent it must match the session's `csrf`, else 401; it is never required, because a header-bearer client holds no cookie.
   - v5 puts the token in a URL, which a proxy or access log may keep. v5 is the legacy dialect; the docs say to prefer v6 and to rotate the token if it was logged. The token is the only credential in it and it can do nothing but read the statistics and pause blocking up to `maxPauseMinutes`.
   - **Audit** (`GET /api/v1/audit`): `pihole_api.enable`, `.disable`, `.token_rotate`, `.token_revoke`, `.settings`; every pause or resume made through it is the ordinary `blocking.pause` / `blocking.resume` entry with `via: pihole-api`; a write attempt refused for no or a wrong token or session (not while the API is off: that is a plain 404 and no audit, so a node that never turned it on has no new write path) is `pihole_api.denied` (at most one per client network per minute, an IPv6 client by its /64, and at most 10 in all per minute, written off the async threads, so a scanner cannot fill the log). `resume` ends every pause, group pauses included (that only restores blocking). The token is a static credential, not a user sign-in: it keeps working with `disable_local_login = true` (ADR-944) and outside `allowed_admin_networks` (only `allowed_networks` applies), and it can only read and pause. Reads and sign-ins are not audited one by one (Home Assistant reads every five minutes); the lockout is.
7. **Admin surface (admins only; agents never write it)**: `GET /api/v1/pihole-api` (`enabled`, `tokenSet`, `tokenCreatedUnixSeconds`, `lastUsedUnixSeconds`, `maxPauseMinutes`; agents with `config:read` and the MCP tool `pihole_api_status` may read it, it holds no secret), `PUT /api/v1/pihole-api` (`enabled`, `maxPauseMinutes`), `POST /api/v1/pihole-api/token` (issue or rotate; the response is the only time the token is shown; `Cache-Control: no-store`), `DELETE /api/v1/pihole-api/token` (revoke). Settings → Pi-hole has the control, a copy button for the token and the two example addresses. No agent scope writes it (the token is a credential, as with secrets).
8. **Storage.** One row in the node's `state.db` (migration 14): `enabled` (default 0), the token's hash, when it was made, when it was last used, `max_pause_minutes`. **It is per node and not replicated** (a conservative choice, recorded as a gap: replicating a credential needs ADR-903's secret rules): in a cluster an admin turns it on where Home Assistant should look, and the pause it makes still reaches every node. Nothing on the DNS path reads it (CLU-004).

**Test plan.** Unit (`telltale-api`): off, no token, and a wrong token refuse every path and the write is audited once; the token is shown once and stored only as a hash; v6 sign-in, sid renewal, expiry, rotation ending sessions; lockout after repeated wrong passwords; summary fields from a fixed backend; `disable` and `POST /api/dns/blocking` call the same backend pause as `/api/v1/blocking/pause` (the same audit action and arguments), timer rounding and the `maxPauseMinutes` cap; v5 `[]` for a wrong token and `versions` without one. Playwright: Settings → Pi-hole turns it on, shows the token once, the compatible endpoint answers with it, rotation invalidates the old one. Integration: `deploy/ha-test/e2e.sh` configures the real Home Assistant Pi-hole integration against a throwaway node, reads its summary sensors, and switches blocking off and on.

**Alternatives rejected:** serving only v6 (phone apps and Home Assistant's fallback need v5); a separate listener (a second port to firewall and a second allowed-networks story); accepting the signed-in session or an agent token on these paths (a different credential model than what the clients can send); "disable forever" (see 5); an unauthenticated `status` (Pi-hole v5 has one; here every read except `versions` needs the token); replicating the token across a cluster now (needs the secrets rules).

**Consequences:** one more credential to rotate, off until an admin asks for it; statistics shown to a Pi-hole client are the same ones a viewer sees (domains and client addresses at the node's privacy level); `unique_domains` and `clients_ever_seen` are bounded counts and say so in the docs.


## ADR-965 — Backups with stored secrets: the archive format, the restore's key and re-stamping, the bounds the spec left open (Accepted 2026-11-18)
**Context:** T23.9 (API-007; ADR-903 §8, which amends ADR-063) puts the stored secrets into a backup under a passphrase. ADR-903 §8 fixes the cipher, the key derivation and its recorded parameters, the manifest block, version 2, the refusals and the CLI flags. It leaves open a few details; each is the most conservative reading, recorded here for the owner.

**Decision:**
1. **Cost bounds.** Restore refuses a recorded cost over m = 256 MiB, t = 10 (ADR-903) and **p = 8** (new: the spec bounds two of the three parameters, and lanes multiply the time and the threads), an algorithm other than Argon2id v1.3, a zero cost, and a salt outside 8 to 64 bytes. The check runs before any derivation and before anything moves; `--skip-secrets` and `backup show` don't need it (a hostile manifest can still be skipped or listed).
2. **Plaintext.** The JSON list holds `updated` as **Unix seconds** (the store's own unit; the API's RFC 3339 is a presentation). Restore keeps `updated` and `updated_by`, stores the rows as `local` and unorphaned, and stamps them from the start of **epoch 0** with the database's own counter (`next_secret_stamp(0)`: never a stamp the database holds). A restored node is standalone (the cluster identity isn't in a backup), so epoch 0 is its current epoch; a node that joins a cluster later goes through T23.5's adoption as any standalone node with local secrets does.
3. **What goes in.** Every live row this node can read, cluster rows included (a replica's backup carries what it holds). A row stored under another key, damaged, or orphaned by a failover is **left out and warned about** ("N stored secret(s) couldn't be read"), not an error: the backup of everything else still has to be makeable. A locked store, though, refuses a backup with a passphrase (the CLI and `503 secrets_locked` on the API): it would silently drop every secret.
4. **No secrets, no `secrets.enc`.** A passphrase with nothing readable to put in makes **no file and stays version 1** (older builds restore it); the manifest's `secrets` block is written in every backup from this build (`included: false`, `count` = how many the node stored, `omittedReason`: `no passphrase`, `none stored`, or none readable). Archives from before this build have no block and read as none.
5. **Version and block must agree.** A manifest whose version, `secrets.included` and `secrets.enc` entry don't match is refused as damaged.
6. **Restore's key.** The key comes from the key settings (`secrets_key_file`, `secrets_previous_key_file`), the process environment and, when neither names one, `<data-dir>/secrets.key` (made if absent, as the server does for an empty store). The settings are those of `-c` when it is given and otherwise those of **the archive's own configuration files** (staged, and loaded the way the server will load them once they are restored): ADR-903 §8 resolves the key "from the same configuration as the server", and a `sudo` drops `TELLTALE_NODE_SECRETS_KEY`, so the restored files are the only place the unit's settings are. Staged files that don't load stop the restore (give `-c`, or `--skip-secrets`). A configured key that can't be read (or isn't valid) is an error before anything moves: nothing is generated in its place. `-c` stays optional: a fresh machine has no configuration yet, and the archive's files stand in for it. A key the restore makes is **given the data directory's owner** (restore usually runs as root for the `telltale` service user, which couldn't read a root-owned key and would come up locked), and a key made for a restore that then fails before any file moves is removed again. The restore prints the key's source and `key_id`, never the key. The staged `state.db` receives the rows and its WAL is truncated before it is moved, so no ciphertext or plaintext stays in a sidecar file.
7. **Passphrase sources (CLI).** `--secrets-passphrase-file` (the first line), `--secrets-passphrase-stdin` (the first line; a terminal is refused) and `--secrets-passphrase-prompt` (the terminal, echo turned off with `stty`, twice when creating). Never an argument or an environment variable. No terminal-handling crate is added (`unsafe` is only for `telltale-net`, and nothing in the lock file does it): a platform where `stty` can't turn echo off refuses the prompt and says to use a file. Restore asks only when the backup needs one.
8. **One derivation at a time.** A process-wide slot (a flag, not a queue): a backup or a restore that finds it taken fails at once (the API: `429 rate_limited`, `Retry-After: 2`). The slot is held for the derivation only, not the whole backup. A request checks the flag first, before it reads and decrypts the secrets or copies the databases, so a burst is refused cheaply; the slot itself is still taken at the derivation (a race loses there, with the same answer).
9. **Warnings.** The inline-credential warning counts entries of the configuration files (upstreams, lists and alert destinations by their credential paths, and the routers, OIDC providers, sinks, OTLP headers and Git credentials the settings pages hold) and the `managed` rows of the backed-up `state.db`, counting only a credential held in the entry itself (not a `*_ref` or `*_file`). It names counts, never a value.
10. **The rest of the archive is bound to the passphrase (amends ADR-903 §8).** The associated data is `"telltale-backup-secrets v2" ‖ backup_id ‖ binding`, where `binding` is a BLAKE3 hash (derive-key mode, context `telltale-backup-binding v1`) over the manifest's `format`, `version` and `node` and the `(path, size, blake3)` of every entry but `secrets.enc`, sorted by path, each field length-prefixed. The manifest's own hashes are held in the same file and anyone can recompute them, so without this someone who can edit a stored `.ttbk` but doesn't know the passphrase could point a configuration file's `router[].url` at their own host while keeping its `api_key_ref`, and the owner's restore would then hand them the secret: the redirect ADR-903 §4 guards against on the API. Now any change to the configuration, the databases or the entry list, or to the node's name, makes the cipher fail as "wrong passphrase or damaged archive" (`--skip-secrets` still restores an edited archive: it holds no secret). The `v1` of the prefix was never released (this task's branch only), so no archive with the old prefix exists; the format stays version 2.
11. **Terminal prompt.** A drop guard turns the echo back on when the prompt returns, errors or unwinds; a process killed by a signal mid-prompt can't (no signal handling without a new crate, §7), so the docs say to run `stty echo`.

**Verification:** the AC tests in `crates/telltale/src/backup/secret_tests.rs` and `backup_api_tests.rs`; Playwright `api_007 passphrase backup from settings`.

**Not changed, noted:** the request body holding the passphrase (hyper's buffers, then the parsed `Bytes`) isn't wiped: the copy in the parser's hands is out of this code's reach, and the passphrase is wiped everywhere this code owns it. The creation cost is ADR-903's modest one (17 to 29 ms a guess on x86) for a file that can be attacked offline, with a 12-character minimum and no strength check; restore already accepts up to 256 MiB, so the cost can be raised for new backups (for example m = 64 MiB, t = 3) once the Pi 4 figure below is measured, with no format change.

**Open:** the Pi 4 derivation time and peak memory aren't measured (no Pi on the build host). On the x86 build host (one core, release build) the derivation takes 17 to 29 ms and the process peaks at 21.6 MiB, so the Pi 4 figure is the owner's to record (`telltale backup create --secrets-passphrase-file` with `time -v`); the parameters stay ADR-903's (m = 19,456 KiB, t = 2, p = 1) until it is measured.

## ADR-966 — The backup endpoint's recent sign-in, transport and alert (Accepted 2026-11-18)
**Context:** ADR-903 §8 names the API's rules (admin, HTTPS, a session signed in within 10 minutes for a passphrase backup, header, audit, alert event) without saying how "signed in within 10 minutes" is known, what an OIDC session does, how the UI recovers from the refusal, or where the alert event comes from. T27.13's guarded changes reuse the recency rule, so it is one helper.

**Decision:**
1. **The helper.** `Auth::recent_sign_in(principal, now)` (`RECENT_SIGN_IN_SECS = 600`): the session's `created` time, read from `state.db`, is within 10 minutes. A session's activity doesn't extend it (`last_seen` is not used), a display session never qualifies, and an API token, an agent token or HTTP Basic never has one: `403 reauth_required` (a new problem code) with a hint naming `telltale backup create` for those. An OIDC session counts from the creation of its local session, which is the callback that followed the provider's sign-in: a silent provider round trip (the provider's own session still valid) makes a fresh local session without the user typing anything, so the rule is weaker for single sign-on than for a password. The provider's `auth_time` isn't checked and no `max_age` is sent; doing that is a follow-up with the OIDC verifier (ADR-951), recorded here rather than silently assumed. The 403 comes before the backup is made, so nothing is audited for a refusal.
2. **Which requests.** The recent sign-in is for a **passphrase** backup only (what leaves the node is the secrets); without a passphrase an admin token or any admin session is enough, as `GET` always was. Agents are refused for every `POST /api/v1/backup` (`agent_not_allowed`, by the agent route policy and again in the handler); `GET` was never in their scopes either.
3. **Transport.** The HTTPS-or-loopback rule of ADR-903 §4 (`transport_ok`) applies to every `POST` (the passphrase is in the body), not to `GET`. `[api] allow_secrets_over_http` lifts it as for secrets.
4. **The body.** `{includeQlog?, passphrase?}`, unknown fields refused; the parser's error never quotes the input (a mistyped passphrase could be in it). An empty body is `{}`. A passphrase under 12 characters is `400`. `includeQlog` is `400` when the query log is over 256 MiB (the API builds the archive in memory; the CLI has no limit).
5. **The answer.** The file, `Cache-Control: no-store`, `X-Telltale-Backup-Secrets: included|omitted; count=N` (on `GET` too: always `omitted`) and, when there are some, `X-Telltale-Backup-Warnings` (items joined by ` | `, ASCII). No `Idempotency-Key`: it changes no state.
6. **The audit record** `backup.create {bytes, secretsIncluded, count, includeQlog}` is written for `GET` as well. It never holds the passphrase, a value or a name.
7. **The alert.** `AlertWhen::SecretsExported` (`secrets_exported`), a one-off condition like `credential_redirected`: it reads the applying node's last hour of `backup.create` records with `secretsIncluded` true, once per record, naming who and how many, never which. Alerts are evaluated on the primary (or a standalone node) from that node's own audit log, so **a replica refuses a passphrase `POST /api/v1/backup` with `409 conflict`** and a hint to use the primary (the secrets are replicated, the content is the same); a backup without a passphrase is made anywhere, as before. As with any new condition, an N-1 replica refuses a configuration version whose rule uses it. A backup made by the CLI isn't audited (it runs outside the server) and raises nothing.
8. **The UI.** Settings → System → Backup (admins): a passphrase and a confirmation (12 characters, typed twice), an option for the query history, the omitted-secrets notice after a download, and, on `reauth_required`, a password prompt (and the authenticator code when two-factor sign-in asks) that signs in again, which replaces the session with a fresh one, then makes the backup that was waiting. Nothing typed is kept: the fields are cleared when the request goes. A single-sign-on account has no password: the page says to sign out and in again.

## ADR-967 — OIDC providers in the UI: an admin-only node-managed kind with its own routes, applied by one task, never on the answering path (Accepted 2026-11-18)

**Context:** T23.10 makes `[[auth.oidc.provider]]` editable in the UI (API-016, ADR-903 §6-7). ADR-903 fixes the broad shape: an `oidc_provider` kind, admin-only, the file's ID wins, the client secret by name (`client_secret_ref`), `Auth.oidc` an `ArcSwapOption`, flows and the discovery cache kept across a rebuild, one rebuild at a time with a generation counter, a provider whose discovery fails keeps its previous settings or is left out with a reason, sessions and the break-glass admin untouched. It leaves open where a UI provider lives in the configuration (the whole `auth` section is node-local, and `public_url` must stay so), how a node without `public_url` behaves, how the read surface looks, what happens to the sessions of a removed provider, and when a rebuild runs.

**Decision:**
1. **The kind.** `ManagedKind::OidcProvider`, stored in `managed` by ID. `PUT` and `DELETE /api/v1/oidc-providers/{id}` and one read, `GET /api/v1/oidc-providers`, all **admin-only**: an operator is 403, an agent is refused (the read and the writes have no scope, so the agent default, `Need::Forbidden`, applies), and a forwarded write without a role (an older node) is 409 `upgrade_required`, as for routers (ADR-921). There is **no MCP tool**: the read is admin-only and the kind is configuration of a security gate (ADR-903 §5).
2. **Bodies are references only.** The body is `[[auth.oidc.provider]]` without `client_secret` and `client_secret_file` (422 if either is set: a path the API can set is a path an admin can point at any readable file, ADR-921's reason; an inline secret would sit in the audit log and the blob). `client_secret_ref` names a stored secret (422 `secret_missing`), and redirecting it at another kind's secret is audited as `credential.redirect` like the other kinds. The provider's own rules (ID, issuer, client ID, `openid` scope) are the file validator's, shared through `telltale_config::oidc_provider_errors`.
3. **Merged apart from `[auth.oidc] provider`.** The UI's providers land in `OidcConfig.managed_provider`, a field that is never serialized (`#[serde(skip)]`, `#[schemars(skip)]`, so the schema, `shared_part` and the config reference are unchanged). They are not in `provider` because `validate_config` demands a `public_url` for any provider: a node without one would otherwise reject the whole merged configuration and fall back to the files, losing every UI change (CLU-004). The files win by ID; a bad stored entry is dropped alone with a warning. `references()` and so `usedBy` and `secret_in_use` count both lists.
4. **A node without `public_url` shows the provider as inactive.** `public_url` stays in each node's file (it is how that node is reached, ADR-045). `GET /api/v1/oidc-providers` says `active: false` with the reason, and the UI shows a banner; nothing is registered with the service on that node. `mcp_provider` (OAuth for MCP, AGT-008) can still name only a file provider.
5. **One applier task.** `auth_setup::run` waits for `Sources.oidc_changed` (fired after every configuration reload, every stored-secret write or delete, and every pull of replicated secrets), waits 250 ms for the rest of a burst, resolves each provider's secret on a blocking thread (inline, its file, or the store) and calls `Auth::reload_oidc`. A provider whose secret can't be read is left out alone with the reason; the rest are served. It never runs on a request path, a reload or the DNS path. A provider whose discovery couldn't be read is tried again after 60 s, doubling to 10 minutes, until it can be (or the configuration moves on).
6. **Discovery is read only when needed.** A provider that is new or has a new issuer is read when it is applied; one whose issuer is unchanged reuses the cache (keyed by ID and issuer), so a role-rule or secret change never reaches the provider. If the read fails, an unchanged issuer keeps the previous settings of that ID (reported `active` with the reason, say after a restart while the provider is down); a **changed issuer fails closed**: the old issuer is not trusted on, and the provider is left out (`inactive`, the reason, tried again later), as is a new ID. At start the service is built from the configuration without waiting for a provider (as before); the first applier pass reads discovery in the background.
7. **Sessions, users and tokens.** A provider the configuration no longer names (neither served nor skipped) has its sessions deleted (`delete_provider_sessions`, `sessions.oidc_provider`), on every node when its removal arrives. The users it created stay and can sign in again if the provider returns. A provider that is only inactive here (no `public_url`, an unreadable secret) keeps its sessions. A removal that happens while a node is down is not swept at the next start, so authentication itself refuses (`active_user`): a user whose `oidc_provider` this node's configuration does not name (an in-memory lookup kept by the rebuilds, off the DNS path) can use neither a session nor an API token, until the provider returns; this covers the tokens such a user minted for MCP clients. **Issuers:** `users.oidc_issuer` and `sessions.oidc_issuer` (migration 15) record the issuer a link or session was made at (users replicate it). A rebuild that repoints a provider to another issuer deletes that provider's sessions of the old issuer at once, even if the new one cannot be read; a user linked at another issuer than the provider has now is not mapped (403, an admin deletes the user so the person signs in as a new one), because a `sub` is unique only within one issuer; a sign-in started before the change is refused at its callback (flows are kept by ID and issuer). Rows from before migration 15 have no issuer; every rebuild settles them (`reconcile_provider_issuer`) for each provider the configuration names, served or skipped (a skipped entry carries its issuer, so a provider whose new secret can't be read is still swept): with no earlier issuer known in this process (the first rebuild after the upgrade) they take the current issuer, which replicates, and when the rebuild sees the issuer change they belong to the old one (their sessions end, the users keep the old issuer). A repoint made while the node is down, before its first rebuild after the upgrade, can't be told apart from the current issuer: the rows adopt it (accepted; the window is one start-up).
8. **Resolver pods.** An ephemeral member holds no stored secrets and serves no sign-in: it skips UI providers that name a secret, with one info log (ADR-903 §6).
9. **UI.** Settings → Sign-in (admins only; an operator sees no tab and the server refuses the reads and writes): cards with the provider's source (`Set by file` is read-only), status, reason, secret source and readability, roles and redirect URI; a form whose secret is a `SecretField` (named `oidc.<id>.client_secret`, "Save the provider" waits for a typed secret); help topics `oidc-providers`, `oidc-role-rules` and `oidc-public-url`.

**Consequences:** a provider is added, changed or removed without a restart and without touching DNS; the file's provider can't be shadowed; a node with no `public_url` is safe; and a removed provider ends its sessions. The cost is one more field in `OidcConfig` that is not part of the file schema, and that `mcp_provider` and `disable_local_login` (guarded, T27.x) still follow the file only. **Rejected:** merging into `provider` and relaxing the `public_url` rule (the rule protects file configurations, and a per-provider rule would still reject the node), an inline `client_secret` in the body (it would travel in audit and blob), an agent read (nothing an agent needs, and the admin-only read keeps the kind consistent), and reading discovery at every reload (a provider outage would then block unrelated changes).

## ADR-968 — Node-managed entries replicate as one more blob of the signed version, seeded into a promoted primary's own rows once (Accepted 2026-11-18)

**Context:** ADR-903 §6 says node-managed entries (`oidc_provider` now, `sink` and `otlp` with T23.11) are configuration, so they are versioned: `ClusterManifest.node_managed` holds references only, every member persists, validates and merges it apart from the shared part under its own files, a failure drops only those entries, and a promoted primary publishes the inherited blob overlaid with its own rows and seeds its managed rows from it. It leaves open the blob's format, when a promoted node's rows stop being overlaid by the stale blob, how a Git source and pins treat it, and what an older node does.

**Decision:**
1. **The blob.** `node-managed.json`: `{"version": 1, "entries": [{"kind", "name", "body"}]}`, sorted by kind and name so equal rows give equal hashes, with `client_secret` and `client_secret_file` removed from every body on export (a stored value that predates the rule never leaves the node) and any entry that still carries one refused on import. A document of a newer version, or one that does not parse, drops all its entries with one log line (`upgrade this node`); an entry of a kind this build does not know is skipped; a provider that does not validate is dropped alone. The manifest field is `#[serde(default, skip_serializing_if = "Option::is_none")]`, so an older replica ignores it and an older primary's manifest reads (CLU-010).
2. **Publishing.** The primary exports its `managed` rows of the node-managed kinds and re-reads them only when `config_version` moves (the loop runs twice a second). A change of the blob is a new version (`Published.node_managed`, history entries and pins carry the blob). An emergency primary passes on the blob it inherited, and a pinned one the pinned version's.
3. **Applying.** Nothing is stored on a replica: its last applied manifest names the blob, which is already in the blob store, so it survives a restart with the manifest. `merged()` overlays it after `with_shared`, under the node's own files (the file's ID wins; a resolver pod skips entries that need a stored secret). A replica never writes these rows; writes are forwarded to the primary as every managed write.
4. **Promotion.** A primary that follows a version it inherited (`base`) seeds its rows from the blob **once**: entries it has no row for become its rows (its own rows win, which is the "overlaid with its own rows" of ADR-903), and a marker `node-managed-seeded` in the cluster directory keeps the blob's hash. While the marker matches, the inherited blob is not overlaid again, so an entry deleted after the promotion does not come back from the stale copy. If seeding fails, the blob stays overlaid (the safe default: nothing is lost) and the next pass tries again. A replica never writes these rows, so any it holds are left from an earlier time as primary: they are **deleted when the node is a replica** (`node_managed::clear_stale`, which also removes the marker), and a later promotion seeds from the blob it inherits alone (blob wins). A provider the cluster removed or repointed meanwhile therefore does not come back.
5. **Git.** A primary with a Git source carries the rows unchanged (writes of these kinds are 409 `gitops_managed` on every node, as all managed writes), and applies them itself on top of the commit's configuration.
6. **Standalone nodes** have no manifest; their rows are applied by the ordinary merge.

**Consequences:** the secret travels only by the existing secrets replication (ADR-903 §6), the provider list by the signed manifest (so pins, rollouts and history cover it), and a bad blob costs only its own entries. **Rejected:** a second channel for these rows (a new thing to authenticate and order), carrying the secret in the blob (a plaintext file on every disk), and re-seeding on every pass (it would resurrect deleted entries).

## ADR-969 — `telltale snmp walk` before the agent list exists: the lookup is the only seam, an address is refused as a name, and ownership is tested by binding (Accepted 2026-11-18)
**Context:** T25.4 (DSC-003, ADR-908 "Diagnostic CLI") asks for `telltale snmp walk --agent <name>`, which takes a configured agent name only. `[[discovery.snmp_agent]]` and `[[discovery.snmp_credential]]` are T25.6 and T25.8 and ship with their own UI (standing rule), so the config has no agent to find yet. Adding the schema in T25.4 would add settings without their UI controls, help topics and Playwright tests.

**Decision:**
1. **One seam.** `snmp_cli::lookup(cfg, name)` is the only place that turns a name into an `AgentSpec` (address, credential files). Until T25.6 it finds none and says so. Everything after it is built and tested: the destination check (ADR-907), the credential read from `*_file` under `[node] secret_file_dirs`, the table roots with their fallbacks, the bounded walk (rows, time, pacing) and the printing. T25.6 replaces the body of `lookup` and nothing else.
2. **An address is not a name.** `--agent` values that parse as an IP address or a socket address are refused before the lookup. The command line has no other way to give a destination (`--agent`, `--table`, `--config` only).
3. **Table groups.** `arp`: ipNetToPhysicalTable, else ipNetToMediaTable. `ifmib`: ifTable, ifXTable, and ipAddressTable else ipAddrTable. `bridge`: dot1qTpFdbTable else dot1dTpFdbTable, and dot1dBasePortIfIndex. `lldp`: lldpRemTable. The first root of a group that answers a row wins; the others are not read.
4. **The host's own address** (a refused destination, ADR-907) is found by binding a UDP socket to it: a bind that succeeds means the address is local. No new dependency and no interface listing.
5. **Output.** Rows print as `OID = TYPE: value`; device strings are cut at 255 bytes with control characters replaced (ADR-908 "Untrusted strings"). No credential is read into the output path.

**Alternatives rejected:** adding `[[discovery.snmp_agent]]` to the schema now (settings without UI); accepting `--address` for a quick test (it would let the command reach any host, against ADR-907).

**Consequences:** the subcommand reports "no agent configured" until T25.6; `telltale` links `telltale-snmp` (binary +13,440 bytes, stripped release, measured below in T25.4's Done note).

## ADR-970 — The map's sampler as built: inline on the aggregator thread, a flat window, no answer address yet (Accepted 2026-11-18)
**Context:** T26.2 (OBS-901) built ADR-958. Measuring it on the real aggregator and a real node changed four details of how the design is realised and settled the question ADR-958 left open (the answer address). Nothing here changes what the map shows; it is recorded because the ADR said otherwise or said nothing.

**Decision:**
1. **The answer address is not recorded; `/map/world` returns `address_not_recorded`.** ADR-958 section 3 ships the field "only if the ring record does not grow". It does: the wire record's fixed part goes from 61 to 78 bytes (a typical record from about 85 to about 102 bytes, 20% more per event, so each worker ring holds about 17% fewer events), and the copy would run on every cache miss in the workers' own code. `size_of::<QueryEvent>()` is 64 and `size_of::<Record>()` is 320 now (pinned by `obs_901_record_sizes_are_pinned`, with `MAX_RECORD` 316 and the name's 256), so a field cannot hide in padding. The conservative reading (AGENTS rule 4: nothing on the hot path without a benchmark that proves it) is not to add it, so T26.5 ships with upstream markers labelled "upstream locations, not where answers point". `GET /api/v1/map/world` answers `available: false, reason: address_not_recorded` and counts every lookup as unlocated (`geoip_off` and `geoip_missing` are T26.4's, and the response already has them). The owner can overrule by adding the field in a later task that measures it.
2. **The sampler runs inline on the aggregator thread, with no queue between.** ADR-958 section 2 describes a bounded subscriber queue whose overflow is counted. The aggregator already folds each event into the analytics in the same pass, and the counter-based selector is one increment for every event it skips, so a queue would add a copy per event and nothing that needs bounding. The "drops" that exist are the **worker rings' own** (`RingStats.dropped`): the aggregator hands the sampler the rings' running total after each drain (`Sampler::tick`), and the delta joins the tick's total before N is computed and scales the weights of the next tick (Q16 fixed point, with the fraction carried, so the estimate stays unbiased: `obs_901_sampler_overload`, 20% of a stream lost, within 5%). A burst inside a tick doubles N at once (at most twice the per-tick cap is kept). The sampler lock is held for a drain by the aggregator and for a window read by the API; a worker never takes it.
3. **A flat window, not a hash table.** Each 5 s slot is a `Vec` of at most 1,024 rows, grown through 64, 256 and 1,024, searched linearly: at most `event_rate` (2,000) lookups a second are kept, so a scan costs a few microseconds on the aggregator thread. The first build used a `HashMap` per slot and measured **+4.9 MiB** RSS at the cap (a table keeps a load factor, doubles, and left freed tables in the allocator), far over the gate; the flat window costs about 590 KiB at the cap and measured **+0.6 MiB** (below). The key adds a sixth counter, `limited` (rate-limited lookups), to the five of ADR-958, for the device rule "any rate-limited query".
4. **Defaults and names.** `[map] enabled = true` (the sampler costs 0.1 MiB at idle and 0.6 MiB at its cap, and a map that needs turning on first is a map nobody sees; the owner can flip it). `warn_latency_ms` is optional: unset follows `[slo] latency_ms`. ADR-958 calls the read scope `read:stats`; the scope that exists is `analytics:read`, so `GET /api/v1/map*` and the MCP `network_health` need that (a token with only `config:read` is refused). The MCP tool reads a new `GET /api/v1/map/health` (counts, up to 50 red and yellow nodes with reasons, the five busiest flows), so the tool and the route are one thing. The write scope is `config:write:map` and the MCP plan tool `plan_set_map`; operators write, viewers read, an agent needs the scope and gives a reason; a GitOps authority refuses the write and shows the TOML (the same path as `[exclusions]`).
5. **What the colours cover** (the pieces ADR-958 left to the table): `idle` is decided after the facts (an open breaker or an unreachable node is red, a half-open breaker yellow, with no samples at all); a resolver takes its own ADR-104 level and the worst of what is **downstream** of it (its upstreams and answer kinds), not of its devices, so one failing device does not colour the resolver; a network takes the worst of **all** its devices, including the ones folded into `+N more`; the gateway is grey without a router integration, green when healthy, yellow on an error, never red. At privacy level 2 the sampler holds no client key, so the networks cannot be told apart per device: the map shows **one** `devices hidden by privacy` node under an "All networks" node (not one per network, which would need the address ADR-102 hides). At level 3 the window keeps resolver totals only (no group, answer kind or upstream). The anomaly's yellow is level 0 only, as the ADR says; the open findings come from the node that found them and are those of the last 24 hours nobody acknowledged and no mute matched.

**Measured** (this host, 24 CPUs shared with other work; the host's UDP `bind()` takes 10 to 20 ms, which makes `make bench-smoke` print the host's numbers, see the Done note of T26.2):
- *Aggregator throughput*, 7 alternating runs, medians (`obs_901_sampler_throughput_ab`, release): sampler on over off 1.018, 0.996 and 1.003 (spreads 2% to 15%), and 0.961 and 0.972 on busier runs; all inside the 5% band.
- *RSS, Pi profile (2 workers)* (`bench/mapprobe.py`): idle 19.3 to 19.4 MiB with the map off, 19.3 to 19.6 with it on; after 270,000 lookups from 14,000 distinct devices at 3,000 a second, steady for 2 to 5 minutes: **39.2 and 39.7 MiB off, 39.7 and 40.4 MiB on**, so the delta at the key cap is **+0.6 MiB** (range 0.0 to 1.2), under the 1.5 MiB gate.
- *Cache-hit path A/B* (`bench/ab_hot.py`, 7 alternating rounds, 4 workers): median 666,752 qps without the change and 700,630 with it (1.05; the spread is 530,000 to 890,000 either way).

**Consequences:** the map's memory is at most about 0.6 MiB and bounded; a deployment that wants the world view's answer addresses needs the field, decided separately; a very high rate of distinct devices (more than 1,024 keys in 5 s) counts the rest under `other`, which the snapshot shows as resolver totals without a device.

**Review amendments (2026-11-18):**
6. **A rise in the privacy level purges the sampler.** `Sampler::set_privacy` to 2 or more empties every slot, its overflow count and the recent-lookup list, so no client key outlives the switch (the build also treats every key as hidden at 2 or more). `Hub::set_privacy` reaches the sampler at once; a sampler made later starts at the level in force.
7. **A new sampler starts from the rings' drop total as it is then** (`Sampler::new(settings, dropped_now)`), so turning the map on after an overload does not count the whole history as one tick's drops.
8. **Readers copy, then sum.** `map_window` copies the slots in the window under the lock (`Sampler::freeze`) and sums and sorts them outside it, so a reader never holds the aggregator back for more than a copy. The routes serve an unfiltered `GET /map` and `/map/health` from the ticker's last snapshot when it is younger than 2 s, run at most 4 other builds at a time, and a stream is told `map_disabled` (and ends) when the map goes off. One user or token holds at most 2 of the 8 streams.
9. **Two deviations from ADR-958, kept on purpose.** (a) The overload weight scale is the tick's total over its offered answerable lookups, where the total includes the rings' drops of every kind (upstream exchanges, probes and excluded queries too); under overload on miss-heavy load the weights can be a little high. The error is bounded by the 64x cap and by the share of non-lookup records, and the unbiased test (`obs_901_sampler_overload`) holds for lookup-only load; the records' kinds are not known for events a ring dropped, so no better ratio exists. (b) The recent-lookup list is one ring of 1,280 lookups, not "the last 20 of each of the 64 busiest edges": the edges are only known when a snapshot is built, so a per-edge list would need a key and a list per device on the aggregator thread. Under a flood of distinct clients the busiest edges' lists can be short.
10. **Measured again** (`obs_901_sampler_throughput_ab_unique_clients`, release: 60,000 distinct clients at `event_rate = 2000`, the slots full): sampler on over off 0.983 (spreads 2.3% and 3.2%); the four-client run 0.996.

## ADR-971 — Mixed versions: an older peer is a missing node, and `[map]` writes follow the settings-kinds guard (Accepted 2026-11-18)
**Context:** the map reads each peer's part over the cluster channel (`Read::MapPart`) and `[map]` is a shared section written through a new managed kind (`ManagedKind::Map`). During a rolling upgrade some members will not know either (CLU-010).

**Decision:**
1. A peer that does not know `Read::MapPart` answers with an error, so its part never arrives and, after three intervals (6 s), it is a **missing node**: a red `resolver` with reason `unreachable`, `partial: true`, `missingNodes` naming it. This is the honest reading for the map ("this node's flows are not in it") and it ends with the upgrade. The reason text says the node did not answer the read; it does not claim the node is down. A peer that does know the read and has its map off answers `null`, which is also missing after 6 s.
2. A replica's `[map]` write is forwarded to the primary only if the primary runs at least the version that knows the kind (`SETTINGS_KINDS_SINCE`, 0.8.0, the same guard as `[special]`, `[local]` and `[clients]`): 409 `upgrade_required` otherwise. Unlike `[discovery]`, the first write is **not** refused while any member runs an older version: `[map]` is replicated as a shared section only when it differs from its default (`shared::shared_part`), and an older replica that cannot read it keeps its own sampler as it was, so the worst case is a replica that samples with its own settings until it is upgraded. (A replica that refuses an unknown shared section falls back to its own file, as for every shared section, CLU-010.)
3. The gather task that fills the per-peer cache starts on the first read of the map, polls every peer once per 2 s interval (one task per peer, never two at once, 2 s deadline) and stops after 10 s with no read, so a cluster nobody looks at pays nothing; the cache holds the last good part and its age, and the snapshot only reads it.

**Consequences:** during an upgrade the map shows the not-yet-upgraded nodes as red resolvers; the Cluster page's own version column says why. Tests: `obs_901_dead_peer_keeps_tick`, `obs_901_peer_cache_rules`, `obs_901_map_part_read_round_trips`.

**Review amendments (2026-11-18):**
4. **The grace of a peer not heard from starts with the gather task, not with the cache.** `PeerCache::restart` is called when a read starts the gather, so the first read after an idle spell shows every peer pending (left out, not red, and the snapshot is not `partial`) for 6 s while the first round lands; an old part counts as pending in the same window. After it, a peer with no fresh part is missing, whether or not a poll is running (a connected peer that never answers must go red).
5. **A member this node has no stream to but the cluster's health relay reports up** (a replica in manual failover sees only the primary; ADR-960) is an `idle` resolver with the reason `not_reachable_from_here`, not red: `MapParts.unseen`, not `missing`, and the snapshot is not `partial`. A member the relay does not report up stays a red `unreachable`.
6. **A peer inside its grace is `pending`, and the map is `partial`.** (Replaces the "not `partial`" of amendment 4.) `PeerCache::view` returns peers that are connected but not heard from, inside the grace, in `MapParts.pending`; the snapshot shows each as an `idle` resolver with the reason `pending` and sets `partial: true` (`missingNodes` stays for the red ones only). A cold one-shot read (an agent's `network_health` call after an idle spell) therefore never looks like a whole, healthy single-node network; asking again after a few seconds gets the peers. The federated backend also passes `unseen` through (it dropped it before).
7. A cached snapshot (under 2 s old) is no longer served once the map is off (`settings` is checked first), and a new stream's first frame skips the empty end-of-stream marker of an earlier map-off. Not changed: after a rise of the privacy level a cached snapshot can still be served for at most 2 s (the sampler purges at once, so the next build is clean); accepted as LOW.

## ADR-972 — Offline password reset: the node stopped, the password from stdin or a terminal, sessions ended, audited (Accepted 2026-11-18)
**Context:** T24.7 (fork #4, API-003). When no admin can sign in there is no way back in today: the setup token exists only before the first admin, and a bootstrap hash is read only while no user exists. The reset has to work with no running API, which is the one place where API-901's UI rule doesn't apply (an inherently offline command, the reason is "nobody can sign in").

**Decision:**
1. **`telltale auth reset-password <user> [-c config]`** opens `<data_dir>/state.db` directly (the same open as `telltale run`). It takes the data directory's lock (CLU-008) **without waiting**: a running node holds it, so the command refuses with the holder's pid and host and changes nothing. Stopping the node first is the only supported path (a container: stop it, run the command in a one-off container on the same volume).
2. **A cluster replica refuses.** Its users come from the primary (CLU-003), so a local change would be overwritten by the next sync. The message says to reset on the primary.
3. **The new password** comes from stdin as one line (a pipe, a file, or a here-string), or, from a terminal, is typed twice with echo off through `stty`. If echo can't be turned off (no `stty`, as in the image), the command refuses and shows the pipe form; it never echoes. The password is held in a zeroizing buffer and never logged. The same password rules as the UI apply (`valid_password`).
4. **Effect:** the password is replaced (Argon2id, as everywhere), the user's **UI sessions end** (`delete_user_sessions`), and TOTP, roles, and other sessions of other users are untouched. API tokens and HTTP Basic are not revoked (they are a separate credential and an admin revokes them from the UI); the docs say so.
5. **Audit:** `user.password` by the system actor `auth reset-password`, with `{"by":"offline reset","sessionsEnded":n}`, target the username. The audit log is the only trace, so it's written before the command returns.
6. **No UI control.** The command is inherently offline (the owner's API-901 exception), with this one-line reason; the help topic `password-reset` sits on the sign-in page and points at the docs (`docs/running.md`, "Forgot the password").

**Alternatives rejected:** a default or printed temporary password (a secret printed to a log or a terminal history); a file option for the password (a file of a secret on disk, and a path the command has to trust); waiting for the lock (the reset would race the server, which keeps `state.db` open and caches sessions in memory); an in-place reset while the node runs (no API is reachable without a sign-in, which is the case being solved).

**Consequences:** a person with shell access to the node can always reset a password (they could already read `state.db` and the key files, so nothing new is granted); a running node must be stopped, which is the cost of the lock; the password never appears in shell history when it comes from a pipe of a variable, but a literal in the command line does: the docs show the variable form.

**Test plan.** `api_003_reset_password_offline_ends_sessions_and_audits` (sessions of that user end and only those, the old password fails, the new one verifies, the audit entry is written, an unknown user is refused) and `api_003_reset_password_refuses_a_running_node` (a held lock refuses and changes nothing).

## ADR-973 — Router names as device matches: `hostname:<label>` keys, a group's `router_names`, read off the query path (Accepted 2026-11-18, owner decision on the precedence)
**Context:** T24.9 (fork #6, API-010). A router that hands out addresses (UniFi, OPNsense, and Home Assistant as a `[[router]]`) names each device by its DHCP host name, and that name survives an address change. Rules and groups can match only by IP, CIDR, MAC or client ID (FLT-006 deferred hostname matching in T2.5). The owner asked for the router's name to be a match, in the Clients, Groups, rules and query log.

**Decision:**
1. **Key form.** A match key `hostname:<label>` in `[[client]] match`, a rule device `devices = ["hostname:<label>"]`, and a group's `router_names = ["<label>", …]` (`GroupConfig`). A label is 1–63 of `a-z`, `0-9`, `-`, with no leading or trailing `-`, lowercased on parse; `Kitchen Tablet` is `kitchen-tablet`, the same rule device names in DNS use (`device_label`). The UI converts a name with the same rule. A label that isn't one is a validation error, so an IP, a CIDR, a MAC and an `id:` can't be confused with it.
2. **Source.** The leases the node reads from its routers (own, then peers, CLU-002). An offline entry gives no name (ADR-166), and a lease without a usable label gives none. mDNS names aren't used: the name a router gave is the one this matches. Home Assistant's name, as a `[[router]]` answer, counts as a router's (API-012).
3. **Precedence** in `ClientTable::identify`: client ID, EDNS MAC, neighbor MAC, Kubernetes workload, exact IP, **router name** (a `[[client]]` with the key; else the group whose `router_names` has it, taking the device as a network does), most specific CIDR, `default`. *(Superseded by ADR-976: the router name now ranks below CIDR.)* An exact address always wins over the name the router gave that address.
4. **Off the query path.** The device-name task (every 10 s, DNS-023) rebuilds the address → label map from the leases and stores it in one shared `RouterNames` (an `ArcSwap`), the same handle the client table and the quick rules read. A query reads it only when some client, group or rule uses a router name (one `ArcSwap` load and one or two hash lookups; nothing otherwise). A reload builds an empty map in the new table, so names come back within one tick (at most 10 s); the device task re-applies them to each new policy. This is stale by up to 10 s by design, like device names.
5. **Rules** with `hostname:<label>` match when the device's current router name is that label (read at query time through the same handle, only when a rule uses one). A rule device by name or address is unchanged.
6. **Query log.** `client=hostname:<label>` (API `GET /api/v1/queries`, the UI's **Client by → router name** filter) resolves to the addresses the router gave that label **now**, through the same path as a workload's addresses (FLT-017), at most 64. No address → no row. History from before the name changed isn't recovered: a row keeps the address it was logged with (the name is read at read time, as ever).
7. **UI.** ClientChip gets "Also recognize it by its router name" (adds or removes that one key beside the device's other keys; other `hostname:` keys are kept); the Groups editor gets **Router names** (in simple view); the quick rule form gets **Device by: router name**; the query log gets **Client by**. The help topic `device-name` says so.
8. **Conflicts.** Two devices with one router name (two Androids) both match it, by design: the name is the key. A client key beats a group's router name for the same name, and a group's router name applies only to a device no client names.

**Hot path.** No allocation or lock on a query that doesn't use a router name: `identify` tests two `HashMap::is_empty` (one branch each) and `QuickRules::decide` tests an `Option`. A query that does use one reads one `ArcSwap` and hashes the label. `make bench-smoke` on this host (Docker Desktop, a 10–20 ms UDP bind) fails its loss gate on both the base commit and this change alike (cache-hot loss 32%); the 50% load points agree (p50 119 µs on both, p99 23–27 ms), so no regression is shown, and the verdict needs quiet hardware.

**Alternatives rejected:** a separate `[[router_match]]` table (a second place to keep the device's groups in step with its `[[client]]`); matching in the DNS device-name table (that table answers the names TelltaleDNS gives, which may differ from the router's); recovering names from history (a name the router no longer gives shouldn't match now); passing the name through the group API (groups are read as config entries, so the field is in the config schema and the editor reads it there).

**Consequences:** a router name is one more match that can change when a router's lease changes; that is the point, and the Clients page shows the name the router gave so people can see it. Two integrations' names for one device (UniFi's and Home Assistant's) are one name: the router order (own before peers) decides which address keeps it. Not done: history matching, and matching a Pi-hole import's device names (the importer doesn't read router names).

**Review amendments (small-auth-names track, 2026-11-18; ADR-973 amended in place).** (a) **Spoofing.** A host name is chosen by the device, so a device on the network can claim a router name; the docs (`running.md` "A router name can be claimed") and the `device-name` help topic say so and recommend MAC or address keys where it matters. *(Superseded by ADR-976: the name now ranks below CIDR.)* Precedence is unchanged: a router name still ranks above CIDR, so a device on a restricted network that names itself after a looser client takes that client's identity. Ranking the name below CIDR, or flagging name matches in the UI, is left to the owner as an Open question: it changes the precedence in point 3, which the owner has not set. The explain output already carries `router_name`. (b) **Reload.** The device-name task remembers the policy it gave the names to by a `Weak` handle, not by its address, so a freed policy's address can't be reused into a stale "already given". (c) **Case.** A group's `router_names` are lowercased on validation and on indexing, as the `hostname:` keys are. (d) **Scope.** Router names match IPv4 leases only (`router_names()` keys on `IpAddr::V4`); IPv6 clients are never matched by one.

**Test plan.** `flt_006_router_names_match_clients_and_groups` (precedence, group membership, the names' cleared state), `flt_006_quick_rule_by_router_name`, `flt_006_router_names_are_labels` (config), `flt_006_router_names_from_leases` (offline, label, own before peers), `flt_006_identification_chain`, Playwright `api_010 match a client by router name` (the client, the group, the rule and the query-log filter, with the server's filter checked).

**Owner decision (2026-11-18).** A router name ranks **below** CIDR: client ID, EDNS MAC, neighbor MAC, Kubernetes workload, exact IP, most specific CIDR (a `[[client]]` or a group's network), then router name, then `default`. A device on a restricted network can't take a looser client's identity by naming itself after it; the name decides only for a device no address, network or MAC names. This replaces point 3's order and closes amendment (a)'s open question. Built in T24.24 (ADR-976).

## ADR-974 — The parallel race test is judged by outcome; per-query UDP binds in Docker Desktop stay as they are (Accepted 2026-11-18, owner decision on the open point)
**Context:** Fork #20. `ups_005_parallel_races_and_first_answer_wins` failed every time in the wrendns-dev container when the upstream test binary ran in parallel (the parallel group took 200 ms or more; the fast member answers in 5 ms), and passed alone and in CI. Measured in wrendns-dev: `UdpSocket::bind` sleeps about 10 ms (300 binds take 3.1 s of wall time with about 15 ms of CPU), one at a time across the kernel. Two processes each with seven threads both hit a worst case near 180 ms, so the queue is kernel-wide, not per process. Every test in the binary binds sockets (each fake server, each per-query client socket), so a parallel group's two member sockets queue behind the siblings' binds, and the test's 150 ms bound measured that queue. `bench/README.md` records the same cost for Docker Desktop, where the server also binds a fresh socket per UDP upstream query.

**Decision:**
1. The race test is judged by outcome and a bound the product itself sets: the first good answer is the fast member's, and the group returns before the slow member's own attempt could end (`attempt_timeout`, 1 s). A group that waited for the slow member could not return before that cap. The slow member's timeout is set above the cap, so only the group can stop waiting. 2. The fast member's reply is stamped by the fake just before it is sent. The test also requires the group to return within 150 ms of that stamp. This gap has no socket bind in it, so it keeps the 150 ms check's sensitivity to the group's own latency without measuring the bind queue. It does not catch a fan-out delay shorter than the 1 s bound: a hedge of a few hundred ms before the second launch still passes both checks, and separating that from bind cost in this environment needs a quiet-hardware benchmark (open).
3. `ups_006_single_member_waits_for_a_slow_answer` checks its 150 ms budget against 500 ms, not 280 ms. Its slow answer arrives at 600 ms, so a group that ignored the budget still fails.
Checked: the correct group passes 20 of 20 parallel runs; a group that waits for every member fails at 1.00 s.
4. The product is not changed. The group already returns on the first good answer and detaches the other attempts (ADR-013). Each UDP query keeps a fresh socket and a random source port (RFC 5452).

**Consequences:** In Docker Desktop each UDP upstream query still waits for its socket bind, so cache misses top out near 100 a second (`bench/README.md`). Removing the bind from the query path (for example, a stock of pre-bound sockets, each used once, so the source port stays random per query) changes the upstream hot path and needs the owner's decision and a benchmark on quiet hardware (T24.22). **Open, not decided here.**

**Alternatives rejected:** raising the 150 ms bound (it measures the environment, and the owner asked for the cause to be fixed); reusing a socket per upstream (weakens source-port randomness, RFC 5452); running the parallel test alone or with `--test-threads=1` (hides the race and leaves the bind cost in the product's tests unexamined).

**Evidence:** wrendns-dev runs of `target/.../upstream` before and after (issue #20); the `bench/README.md` note on Docker's bind cost.

**Owner decision (2026-11-18).** Accepted as built (no product change). The pre-bound one-use socket stock is T24.25: built behind a benchmark on quiet hardware (with T24.22), and merged only if it beats the current path on Linux and in Docker.

## ADR-975 — Failover with a VIP: keepalived beside each node in its network namespace, a readiness and DNS health check, the wildcard listener, and a witness for two-node promotion (Accepted 2026-11-18)
**Context:** T24.4 (fork #1; CLU-004, OPS-001). A Pi-hole pair moves one VIP between its two hosts with keepalived, so devices keep one DNS address. TelltaleDNS needs the same behaviour, and its DNS must never depend on a discovery, cluster or API failure (CLU-004). The task asks for a Docker example with keepalived for a two-node pair, the listener on the wildcard address so the VIP answers, a runbook for moving a Pi-hole pair's VIP, and a witness package for two-node clusters. It has no UI. Where the text leaves room, the conservative choice is recorded below.

**Decision:**
1. **No new TelltaleDNS mechanism.** The VIP is held by keepalived, not by the node. The DNS listeners bind the wildcard address (the default `0.0.0.0` and `::`; the example sets `[[listen]]` explicitly), so the node that holds the VIP answers on it, and each node also answers on its own address. A listener bound to a single address does not answer the VIP; the runbook says so.
2. **Health check = readiness plus a DNS answer.** keepalived keeps the VIP only while `/readyz` answers 200 and the node answers the probe name `probe.telltale.invalid` on its own listener (the watchdog's probe, answered locally as NXDOMAIN). `/readyz` answers 503 in maintenance (OPS-010), so a node in maintenance hands the VIP to its peer while it keeps answering the queries that still arrive.
3. **keepalived shares the node's network namespace in a container** (`network_mode: service:keepalived-*`), so the VIP lands where the node listens. On a host install, keepalived runs on the host beside the node. The sidecar needs `NET_ADMIN`, `NET_BROADCAST`, `NET_RAW`, `SETUID` and `SETGID` (keepalived runs its check as root). The node runs as its image user, with `net.ipv4.ip_unprivileged_port_start=0` set on the shared namespace, as the Pi docs set it on the host. Restarting the sidecar restarts the pair (the runbook).
4. **Node identity by NSID.** Answers name the node in the NSID option (`[dns] nsid`), which stays per node inside a cluster; a shared local record would be the same on both nodes once the primary's configuration applies.
5. **Witness package.** A `telltale-witness` service in the example's compose file, behind the `witness` profile: a vote-only `cluster witness` with its own address on the network and no DNS, API or VIP. It joins with a witness token from the primary (CLU-005). The VIP moves on health whatever the cluster decides.
6. **Unicast VRRP** on the Docker bridge (`unicast_src_ip`, `unicast_peer`); the LAN runbook may use multicast.
7. **Proof, not a claim:** `deploy/keepalived/e2e.sh` (CI job `keepalived`) builds the image, forms the cluster, checks each node and the VIP, kills the master, checks the takeover (within 15 s, every later query answered by the peer) and the promotion, restarts the master (the VIP back, a replica), and runs a maintenance hand-over through the API.

**Gaps and conservative choices (for the owner):**
- VRRP in the example is **unauthenticated** (keepalived's `auth_type PASS` is deprecated). The runbook says to keep VRRP on the LAN interface and not to route it. Authenticated VRRP is an owner decision if the LAN is not trusted. The runbook offers a dedicated VLAN or an `iptables` rule that drops VRRP from anyone but the peer, as the interim limit.
- The example's subnet is `10.231.250.0/24`: not the owner's LAN, and not another compose project's network. The script stops if a Docker network already uses it. Changing it means changing `compose.yaml`, both node files and `e2e.sh`.
- The e2e makes an admin with the setup token and signs in with a session. The API refuses HTTP Basic unless `allowBasicApi` is set, and the example does not set it.
- The LAN variant of the example (keepalived and TelltaleDNS on a host or a macvlan, with the LAN VIP) is documented as a runbook and has not been run on a LAN.

**Alternatives rejected:**
- A VRRP implementation inside TelltaleDNS: keepalived is the proven one, and a second VRRP speaker in the DNS process would add a privileged path beside the query path.
- Host networking in the example: it would touch the real network. The isolated bridge tests the same mechanism.
- A macvlan network in `compose.yaml`: it ties the example to one LAN. The runbook covers the LAN.
- Multicast VRRP in the example: Docker bridges don't reliably carry it, and unicast is what is tested.

**Test plan:** `deploy/keepalived/e2e.sh` on the isolated bridge, run locally (five complete local runs with the final checks, and the hosted runs, with the same checks: the takeover took 3.2 to 6.8 s, with 0 to 2 probes lost before the first answer; the promotion to epoch 2, the VIP back on the primary, and the maintenance hand-over all passed), and the `keepalived` CI workflow on every change to the example, the sources or the Dockerfile.

**Consequences:** an operator who wants a VIP runs keepalived beside TelltaleDNS (or in the example's sidecar), and restarts them together. No code, dependency or hot-path change, so no image delta. The example's keepalived image is a separate 33 MB image, used only by the example and its checks.

## ADR-976 — Router name ranks below CIDR in `identify`; a group's network also takes the device first (Accepted 2026-11-18, owner decision: any named network wins)
**Context:** T24.24, ADR-973's owner decision (2026-11-18): a router name ranks below the most specific CIDR and above `default`.
**Decision:** `ClientTable::identify` tries the name after the exact IP and the most specific `[[client]]` CIDR. "CIDR" also covers a group's `networks`, which the owner paragraph names; when one holds the device (`net` is set) the name is not consulted, so a name can't move a device out of a network's group. The name still decides for a device in no network. Quick rules by router name are unchanged. This is the conservative reading of "a group's network".
**Hot path:** the same branches in a different order; one extra `Option::is_none` test before the name lookup, nothing allocated.
**Consequence:** a `[[client]]` keyed only by `hostname:` does not match a device inside a group network; key it by address or MAC there.

**Owner decision (2026-11-18).** Accepted as built: any network a `[[client]]` or a group names beats a router name, so a device inside a named network is never identified by its router name. Router names identify only devices outside every named network.

## ADR-977 — Guarded changes as built: the codes, the limits and the framework's seams (Accepted 2026-11-18, owner decision: the CA-holder residual is accepted; per-node assertion keys are T27.19)

**Context:** T27.13 (API-902; ADR-914, ADR-956, ADR-957). The task fixes the behaviour; a few details it left open were decided conservatively while building it.

**Decision:**
1. **Problem codes.** The framework adds 409 `guarded_only`, `guarded_change_pending`, `preview_stale`, `primary_unreachable`, `would_disconnect_you`, `would_lock_out_admins`, `no_supervisor`, `target_not_empty`, `acknowledgement_required`, `clustered_node`, `restarting`, `rotation_incomplete` and `data_dir_not_persistent`, and 421 `not_primary` for a request that names another node and arrives at a replica (the detail names the primary). 403 `reauth_required` and `agent_not_allowed` are the existing codes. The last four are used by T27.14 to T27.17 rows; they exist now so the problem list does not change as rows are added.
2. **Rate limits.** Guarded previews and applies share one limiter of 30 requests a minute per session; failed confirmations are counted separately (5 in 10 minutes block the session, 429), as ADR-956 says.
3. **Framework hooks.** `crates/telltale/src/guarded` carries `#![allow(dead_code)]` for the hooks that only the T27.14 to T27.17 rows and the test rows use (a window row's sockets, the bind fallback, `CheckCx`). Remove the allow when those rows land.
4. **Test rows and hooks** (`e2e.rs`, the test registry rows) compile only under the cargo feature `e2e`; `TT_E2E_RESTART_HOOK` and `TT_E2E_CONFIRM_WINDOW_SECS` are read only in that build, so no environment variable changes a release binary (`api_902_test_row_absent_in_release`).
5. **Names in phrases (revised by the review of 2026-11-18).** A node goes by its **node ID** in a phrase, a preview, a stored entry (`<node-id>/<setting>`), a forwarded request and the sender check; a standalone node goes by its configured name (or hostname). The site label is a display label only: it is not unique (every pod of the Helm chart is in site `k8s`), so keying on it would share an entry between nodes, let the primary change or restart itself when the admin picked another pod, and let a replica in the primary's site pass the sender check. A target accepts an assertion only when the connection's mTLS-authenticated node ID is the primary's node ID that it knows. (The assertion is still signed with the cluster key, as every manifest is; per-node signing keys are not added.) **Residual (corrected 2026-11-18, owner to accept):** the node ID in the mTLS certificate is a SAN signed by the cluster CA, and a replica that is eligible to become primary holds `ca.key` (`node.rs`), so such a replica can mint a certificate carrying the primary's node ID and then forge an assertion. The sender check therefore stops a replica that holds only the cluster *signing* key, a non-eligible replica, and a mistaken or stale sender; it does **not** stop a compromised CA-holding replica. The residual is the cluster's existing trust in a CA holder (which can already join, impersonate and sign manifests as the primary), not a new one. Closing it needs a per-node assertion key registered with the primary's manifest; that is deferred and listed for the owner.
6. **The window's proof listener** serves only the confirm route, the web UI's own files (`GET`/`HEAD` of paths outside `/api`, `/mcp`, `/metrics`, `/admin`, `/auth`, `/.well-known`) and `GET /api/v1/auth/status` (the page's first read, which signs nothing in), and speaks TLS exactly when the main API listener does (the new certificate for a `new_cert` row, through `Host::proof_socket_with`), tagging requests `TlsConnection`. It has no sign-in or session route, and never serves a page in the clear when the API is HTTPS-only (API-003, ADR-149).
7. **The confirm route** judges a request that carries a `confirmToken` by the token alone (a session cookie sent along is ignored, since cookies are not port-scoped and a stale one would fail a valid token); a bearer token or Basic credentials are still checked and an agent's is refused. A `proxy_list` proof needs the request's peer to be one of the new proxies and the client address under the new list to differ from the peer.
8. **A replica's staged entry** is read from the node-managed blob the replica last applied (a replica has no row of its own); the probation state, the local clear and the dropped-after-two-failed-starts decision are node-local notes in `state.db` keyed by the entry's value digest (`guarded.replica_states`, `guarded.suppressed`), so the primary's copy is never touched. An offline `telltale guarded clear` on a replica queues a removal (`guarded.removals`) that the node sends to the primary (`KIND_ENTRY`, audited there as `settings.guarded_cleared`) as soon as it is started and connected; the local suppression then ends.
9. **A replica's `immediate` change** is answered `applied` only after the primary's version carrying the entry has reached the replica (up to 20 s, `Host::wait_applied`); otherwise 503 `unavailable` says the primary recorded it and it applies when it arrives.
10. **The bind fallback at start** is wired: a start that fails to bind a listener (`AddrNotAvailable`, `AddrInUse`, `PermissionDenied`) while a confirmed (`active`) `window`/`new_socket` entry of the node exists sets those entries aside for that start, rebuilds the configuration and starts once more on a fresh runtime (`guarded::serve_with_fallback`).
11. **The restart warning** counts resolvers of the node's own site that are up and not witnesses ("a site's only healthy resolver"). A node that is running but unhealthy with a staged entry keeps it until someone restarts it: the server never restarts on its own (`docs/recovery.md`).
12. **Plans naming a config path** (review item 11) are not extended: no REST route maps onto a dotted config path until T27.14 to T27.17 add the rows, and those tasks add the refusal with their route; `is_guarded_path` keeps refusing `/api/v1/guarded*`.

**Consequences:** no new dependency; no hot-path change (`telltale-proto`, `-net`, `-cache`, `-filter`, `-policy`, `-telemetry` are untouched); image delta not measured on this host (no image build; code only, no `Cargo.lock` change).

**Owner decision (2026-11-18).** The residual in point 5 is accepted: a compromised replica that holds `ca.key` can forge a guarded assertion, as it can already impersonate the primary in other ways. Per-node assertion keys, registered at join so that a certificate alone isn't enough, are T27.19.

## ADR-978 — A guarded entry is never part of the replicated shared part, and the sidecar stays in the file-named directory (Accepted 2026-11-18)

**Context:** ADR-956 §2 and §6 say the entry is `node_managed` and that the probation counter must survive a `state.db` that will not open.

**Decision:** The `guarded` kind is exported in the node-managed blob like the other node kinds, but a node reads only entries whose node part is its own name and ignores the rest. The probation sidecar `guarded-probation` is written beside the file-named `data_dir` (not a pointer target) and is fsynced before any guarded value applies. An entry the CLI cleared on a replica is suppressed locally until the primary's copy changes (ADR-957).

**Consequences:** an N-1 node that does not know the kind ignores it (`clu_010_guarded_entry_ignored_by_n_minus_1`). A replica reads its own entries from the blob it applied under its node ID (ADR-977 points 5 and 8).

## ADR-979 — The network map page as built: stream when unfiltered, poll when a server filter is set, no domain names so Explain opens with the device only (Accepted 2026-11-18)
**Context:** T26.3 (OBS-901) built the map page on the T26.2 API (ADR-958, ADR-970). Four points were left open by the ADRs or differ from them; each takes the most conservative reading and is recorded for the owner.

**Decision:**
1. **Stream when unfiltered, poll when a server filter is set.** ADR-958 section 5 says the stream is unfiltered and "the UI filters the stream's snapshot client-side", while the task text says the filters are "sent to the server". Both hold: with no `network`, `group`, `device` or `node` filter the page uses the stream (and filters the `health` choice on its side); with any of the four set it polls `GET /api/v1/map` with them every 2 s (paused while the tab is hidden), so the server's view (every device, not only the 200 busiest that the stream carries) is what is drawn. The page also polls when the stream is refused (`429 map_streams_busy`, or three failed reconnects) and tries the stream again when the tab comes back. A client-side filter (`filterSnapshot`) exists for the state filter and is tested as a pure function; it is not applied on top of a server-narrowed read, so the two can never disagree.
2. **Explain opens with the device, not a name.** The map never shows a domain name (ADR-958 section 7), so a click-through to Explain can only carry the device: `#/explain?client=<address>`, which fills the device field and leaves the name for the person to type. Anomalies opens `#/anomalies?client=<address>`, a new device filter on that page (it shows one device's findings and a "Show all devices" link). Queries opens `#/queries?client=<address>` as before. At privacy level 2 and above a device has no address and no click-through.
3. **A device's switch and port are drawn only when the snapshot carries them.** `MapNode` has no `via` or `port` field today (M25's inventory data is not part of the map API), so nothing is drawn for them in a real snapshot. The page reads optional `via` and `port` strings on a node and shows "Connected through <via>, port <port>" in the node's panel when present (a mocked test covers it). Adding the fields to the API is a change to T26.2's schema, left to a later task; step 9 of T26.3 is therefore met as the task words it ("only when the inventory carries it") and recorded as not exercised against a real node.
4. **Colour, shape and words.** The four states are a circle with a check (OK), a triangle (Warning), an octagon with a cross (Failing) and a dashed circle (Idle), each with its word on the node, in the node's accessible label, in the legend and in the table view. Node outlines, shapes and pulses take the existing `--ok`, `--warn`, `--bad`, `--muted` tokens and their `-strong` forms; a Playwright test measures the contrast of every one against the node's surface in both themes (3:1 for shapes, outlines and pulses; 4.5:1 for text).

**Alternatives rejected:** filtering the unfiltered stream for every filter (a device outside the 200 busiest could not be found); sending the stream's filters to the server (ADR-958 fixes the stream as one shared snapshot for all subscribers); a free-text domain box on the map's Explain link (the map holds no names); drawing `via` from `/api/v1/clients` (an extra read per refresh for a field the API does not yet join to the map's devices).

**Consequences:** while a server filter is set the page polls (a read every 2 s, served from the ticker's snapshot when unfiltered and built on demand, at most 4 at a time, otherwise), which the T26.2 route already bounds. The page's code is a lazy chunk of 10.8 KiB gzipped (script 9.8 and styles 1.2), the `dist` total moves from 341.9 to 353.5 KiB gzipped (+11.6 KiB), no new dependency and no image-size change beyond those bytes; no hot-path crate was touched, so `make bench-smoke` was not run.

## ADR-980 — SNMPv3: the HMAC key copy is not zeroized, passwords need 8 octets, rediscovery cannot move the clock back (Accepted 2026-11-18)

**Context:** The review of T25.5 (DSC-003, ADR-908, ADR-931) found three points the code did not settle.

**Decision:**
1. **HMAC key state.** `ring::hmac::Key` keeps key-equivalent padded state and does not zeroize it on drop. The crate builds one per MAC and drops it at once. The localized key `Kul` and `Ku` stay in `Zeroizing`. The ring copy is **accepted**: the process holds the plaintext password in a `SecretValue` anyway, ring offers no zeroizing key, and a hand-written HMAC would replace a reviewed implementation with ours.
2. **Password minimum.** Passwords under 8 octets are refused (RFC 3414 §11.2; net-snmp does the same): `Agent::new`, `UsmUser::derive` and `usm::check_password` return a refusal with the reason `Refused::ShortPassword`, which the T25.8 credential form shows.
3. **Rediscovery.** The agent keeps the engine as last seen in an authenticated message (`trusted`). A discovery Report (unauthenticated) for the same engine ID that is behind it (RFC 3414 §3.2.7b window) is refused (`usm::discovery_allowed`), so a spoofer cannot rewind the clock through rediscovery. A forward move (a reboot) is taken. A different engine ID drops the trusted copy.
4. **Agent clock behind the estimate (fix a, 2026-11-18).** The client's estimate of the agent clock runs ahead of an agent whose clock is slow or was paused, so an authenticated reply or Report could be more than 150 s behind the estimate for good, and rediscovery brought back the same trusted engine and estimate (a lock-out). `Engine` now keeps `latest`, the boots and time of the last authenticated message (RFC 3414 latestReceivedEngineTime; discovery never sets it). In the same-boots, behind-the-window case `Engine::window` returns `Resync` when `latest` is set for those boots and the message time is later than it, as RFC 3414 §3.2.7b specifies, and `Stale` otherwise. A replay or a clock older than anything already received stays refused, so the clock never goes back past the last authenticated value. `resync` and in-window messages update `latest` (`note_received` only moves forward). Option (b), clearing the trusted engine after N stale results, was not chosen: it would let repeated unauthenticated noise erase the rewind protection. Remaining limit: an agent whose clock really is behind its last authenticated time stays refused until it catches up (indistinguishable from a replay).

**Not done:** counting unauthenticated Report OIDs as an operator hint (review item 13, optional). A wrong password and an unknown user both show as a timeout, deliberately: an unauthenticated Report must never drive behavior, and showing it risks an oracle for user names. Open for T25.8 if the owner wants it.

**Test plan:** `dsc_003_rediscovery_cannot_move_the_clock_back`, `dsc_003_empty_password_has_no_key` (short passwords), `dsc_003_rfc3414_sha256_key_vector`, `dsc_003_slow_agent_clock_resyncs_but_never_below_the_latest_received` (unit), `dsc_003_agent_clock_behind_the_estimate_recovers` and `dsc_003_agent_clock_never_goes_back_past_the_last_authenticated_value` (loopback; the estimate is aged 400 s through the hidden `Agent::age_engine_estimate`).

**Consequences:** passwords under 8 octets in existing credentials stop working. No dependency, no hot-path change, no image delta.

**Note at merge (2026-11-18).** Since review round 4, `discovery_allowed` reads `latest` through `window`: an unauthenticated same-ID discovery behind the estimate but later than the last authenticated time is accepted for one exchange (it never sets `latest` or `trusted`, and never goes below `latest`). Item 3's "behind it is refused" means behind the last authenticated time.

## ADR-982 — Group rewrites as lines, and the block-response fields shown in Simple (Accepted 2026-11-18)
**Context:** T27.4 (FLT-014, API-901) adds the `rewrite[]` editor and the group fields `block_ips`, `block_ttl`, `ede`, `ede_text` and `rebinding_allow` to the Groups form. Two choices were not fixed by the spec: how a list of `{domain, answer}` pairs is edited, and whether the block-response fields sit under Advanced. The owner's rule that Simple "never hides something that changes behavior" (ADR-036, API-011) decides the second.

**Decision:**
1. `rewrite[]` is edited as lines, one per line: `name answer` (two whitespace-separated words). The form checks each line with the server's rules (`validate.rs` `rewrites`): the name, `*.` for a wildcard, the answer as an address or a name, and no name rewritten twice in the group. A bad line stops Check and is named; the server's check stays authoritative.
2. `rebinding_allow` and `block_ips` are plain line lists with the same kind of check. `block_ttl` is a number with the server's 0 to 86400 bounds (the form enforces them with `min`/`max`).
3. `block_ips`, `block_ttl`, `ede` and `ede_text` are shown in Simple, not Advanced, because they change what a blocked name gets back. `block_mode` moves to Simple with them, so the block answer is in one place. `rebinding_protection` keeps its Advanced placement: moving it is the owner's call under the same rule (Open).
4. No server change: the config schema, the OpenAPI document and the MCP catalog already carry these fields, so nothing is regenerated.

**Consequences:** a rewrite is a short text line, easy to paste and to read in Git. The form and the server can disagree only on a rare edge the server reports on Check. The Groups page gets a longer form; the block fields are grouped with the block answer.

**Alternatives rejected:** a row editor with two inputs per rewrite (more code for the same data, with no gain for a list that is usually short); keeping the block fields under Advanced (it hides behavior from Simple users, against the rule above).

**Test plan:** Playwright `flt_014 add a rewrite to a group` (a malformed line, a duplicate, a valid rewrite answered by DNS and shown by Explain, then removed) and `flt_014 group block ttl and ede` (the TTL bound in the form, the TTL and EDE code in a blocked answer, the saved values read back).

**Open:** whether `rebinding_protection`, `dns64` and `filter_aaaa` (Advanced today, and each changes behavior) should also move to Simple under the owner's rule.

## ADR-983 — IPv6 device names: addresses ride on the IPv4 lease, usable ones only, one device per address (Accepted 2026-11-18)
**Context:** T24.8 (fork #5; DNS-023). Routers know devices by IPv4 address and MAC, and the device-name table (ADR-901) is keyed by IPv4 address. UniFi also reports each connected client's IPv6 addresses (`ipv6_addresses` in `stat/sta`). The owner wants AAAA and `ip6.arpa` PTR answers for those devices, with the IPv4 rules for names, offline clients and labels (ADR-166, ADR-901). ADR-973 keeps router-name matching IPv4-only.
**Decision:**
- **The addresses ride on the lease.** `Lease.ipv6` (up to 4, sorted, deduplicated; empty is not written, so the wire form to older peers is unchanged and an older peer's answer is a device with none) is filled in `routers::rebuild` from every router's answer for the lease's MAC, so a Home Assistant name takes the addresses UniFi reports for the same MAC. A device with no IPv4 lease (an IPv6-only client) is not named: the key of the lease table, the label rules and the collision rule are all per IPv4 address, and changing that would change every consumer (identify, discovery, the API). The SNMP `ipNetToPhysicalTable` source waits for M25's poller.
- **Usable addresses only** (`devices::usable_ipv6`): link-local (`fe80::/10`, the same on every link), loopback, multicast, unspecified and IPv4-mapped addresses never name a device; global and unique-local addresses do. At most four per device (privacy extensions make a device carry several); the lowest four by value, so the same input gives the same table. That choice is arbitrary: UniFi does not mark temporary (privacy) addresses, so a device with more than four may publish rotating addresses and drop a stable one (accepted; a stability preference needs a source that reports it). A rotated address the router still lists can answer for a short time (TTL 60 s).
- **Same rules as IPv4.** An offline client (ADR-166) has no addresses and no name. A name that loses a label collision (ADR-901) loses its addresses too (no half-registered name). One IPv6 address names one device: the device that wins the ranking keeps it, others get neither the AAAA nor the PTR for it.
- **Built off the path.** `device_dns::names` returns `Named { name, ip, v6 }`; `LocalData::from_device_names` takes `IpAddr`s and adds A or AAAA and the PTR (`in-addr.arpa` or `ip6.arpa`) for each. The query path is unchanged: the same `LocalData` lookup, behind the same single branch and lock-free load, with more entries.
- **API and UI.** `GET /api/v1/dhcp/leases` lists `ipv6` (omitted when empty); the Clients Discovered table and the Networks device list show it; help topic `device-ipv6`.
**Alternatives rejected:** keying the table by MAC (a larger change to every consumer, and mDNS has no MAC); publishing link-local addresses (they answer the same on every link, so a name would point at the wrong device from another network); publishing every address a device reports (privacy addresses rotate, and a long AAAA list slows clients that try each one).
**Consequences:** a dual-stack device answers AAAA within about 10 s of a router read; an IPv6-only device is still unnamed (open until the SNMP source or an IPv6-keyed table); router names for `hostname:` matching stay IPv4-only (ADR-973).

## ADR-984 — Event sinks and the OTLP export as admin-only node-managed kinds, merged apart from their file sections (Accepted 2026-11-18)

**Context:** T23.11 (API-016, OBS-010, OBS-006; ADR-903 §6-7, ADR-914) makes `[[telemetry.sink]]` and the OTLP destination changeable from the UI and API. ADR-903 fixes the broad shape (a `sink` and an `otlp` kind through `node_managed`, `token_ref` and `header_refs`, files win, resolver pods skip what needs a stored secret) and T23.10's ADR-967 and ADR-968 built the machinery for OIDC providers (rows in `managed`, one more blob in the signed manifest, a merge apart from the shared part). It leaves open how a sink or the export sits beside the file's `[telemetry]`, which fields the API may set, how the files win for a one-entry kind, who reads, and what an agent sees.

**Decision:**
1. **Two kinds.** `ManagedKind::Sink` (`PUT` and `DELETE /api/v1/sinks/{name}`; rows `sink` by name) and `ManagedKind::Otlp` (`PUT` and `DELETE /api/v1/otlp/default`; one row, `otlp`/`default`). Both are in `node_managed::KINDS`, so they replicate in `node-managed.json` (ADR-968), are seeded into a promoted primary once, validated entry by entry (a bad one is dropped alone, CLU-004) and ignored by a node that predates them (CLU-010). **Writes are admin-only**: an operator is 403, an agent is refused (no scope; the agent default `Need::Forbidden` for writes), and a forwarded write without a role (an older node) is 409 `upgrade_required`, as for routers and providers.
2. **Reads are for every signed-in role.** `GET /api/v1/sinks` and `GET /api/v1/otlp` carry names, settings, status and the dropped count, never a value (an operator sees telemetry read-only, the owner's AC). An agent with `config:read` may read them, and the MCP tool `list_event_sinks` is the same two reads; no tool or scope writes them (ADR-903 §5). `GET /api/v1/config/entries?kind=sink` also lists the sinks (the files' as `file`, the UI's as `added`), so the generic entry editor (`ConfigEditor`, with the new `fileReadOnly` and per-field `showIf`) is the sinks' form; the OTLP card is its own component because its headers are a map.
3. **Merged apart, never into the files' lists.** `TelemetryConfig.managed_sink` and `managed_otlp` (both `#[serde(skip)]`, `#[schemars(skip)]`, so the schema, `shared_part` and the config reference are unchanged); `all_sinks()` and `otlp_effective()` are the readers (secret references, the credential table, the sinks applier, the OTLP exports, `/metrics`). A node-managed entry is never validated with the files' lists, so a bad one cannot make the merged configuration fall back to the files. **The files win:** a sink named in the files is read-only (409 `set_by_file`; a blob entry of that name is left out); the OTLP export is the files' whenever they set an `endpoint`, `headers` or `header_refs` (409 `set_by_file`, the whole destination), otherwise the UI's `endpoint`, `interval_secs` and `header_refs` apply over the files' trace settings. `interval_secs` alone in a file does not count as setting a destination.
4. **References only; no path the API can set.** The body of a sink has the `[[telemetry.sink]]` fields except `token_file` and `tls_ca` (422: a path the API can set is a path an admin can point at any readable file, ADR-921's reason), and `token_ref` names a stored secret (422 `secret_missing`; a reference moved to a secret another kind uses is audited as `credential.redirect`). The OTLP body has `endpoint`, `interval_secs` and `header_refs` only: inline `headers` and the trace settings are 422 (an inline value would sit in the audit log and the blob; traces are read at start). **No password in any URL** (`url`, `address`, `endpoint`; 422), so nothing in a body or a blob needs redaction. The blob's secret check (`SECRET_FIELDS`) adds `token_file`, `tls_ca` and `headers` to `client_secret` and `client_secret_file`: exported without them, refused when found. Header names exclude those the export sets itself (`content-type`, `content-length`, `host`, `user-agent`, `transfer-encoding`, `connection`).
5. **A file sink is a file name.** `path` is 1-64 characters of letters, digits, `.`, `_`, `-`, not hidden, not ending `.spill`, `.pos` or `.tmp`, and not ending `.<digits>` (a file rotates to `a.1`, `a.2`, so another sink's file can't be named like that); it is written under each node's `<data_dir>/sinks/` (resolved at merge, per node, so a replica never receives the primary's directory). The list and the entry editor show the bare name.
6. **Bounds.** At most 16 sinks made in the UI, `max_buffer` at most 100,000 (a bounded channel allocates its capacity: 16 sinks at the limit are about 50 MiB of channel, not 0.5 GiB) and `spill_max_bytes` at most 1 GiB, so a body cannot make a node allocate without limit. The files' own values are not bounded by these.
7. **Resolver pods.** A sink that names a stored secret, and an OTLP export with `header_refs`, are not started on an ephemeral member, with one info log; the lists say why (`running: false` and `reason`; OTLP `active: false`). The merge still carries the entry (so the UI shows it), and the applier is what skips it.
8. **The restart-only list shrinks.** `restart_only_changes` compares `[telemetry]` without the sinks, the OTLP destination, interval and headers (which now apply on reload), so a reload no longer warns "takes effect after a restart" for them. The trace settings, dnstap, ring and query-log settings are still read at start.

**Also:** a sink that arrives by a replicated blob or a stored row meets the same limits as the API's (file name, sizes, no password in an address, at most 16), and is dropped alone when it doesn't (CLU-004). The Telemetry tab is shown from operator up, as the owner's acceptance criterion says ("an operator sees telemetry read-only"); the server lets a viewer read the two lists, and the tab stays operator-gated like the Integrations tab (a viewer sees no settings tabs); widening it is a one-line change if the owner wants it.

**Consequences:** sinks and the export follow every source of configuration (a file and SIGHUP, an API write, a replicated blob) without a restart; the schema is unchanged; the secrets never leave the store. **Rejected:** writing into `telemetry.sink` (a bad entry would fail the whole merge, as ADR-967 found for providers), letting the API set `token_file` or `tls_ca` (it would make the API a reader of any file; a private-CA syslog collector therefore stays a file setting), taking inline OTLP headers (the audit log and the blob would hold them), and a per-header file-versus-UI merge for OTLP (a half-file destination is harder to explain than "the file sets it").

**Not done (Open, for the owner):** trace settings (`traces_sample_every`, `traces_slow_ms`) are not editable in the UI and are read at start; a private CA for a syslog-over-TLS sink is file-only; a mixed-version cluster has no 409 for sink and OTLP writes sent to a primary that predates them (it refuses an unknown kind, as it does for OIDC providers today).

## ADR-985 — Sinks are started and stopped by a manager off the query path; the aggregator takes the new list once per batch (Accepted 2026-11-18)

**Context:** T23.11 asks for sinks that change while the node runs, with DNS never blocked or slowed (NFR-007, AGENTS rule 5, ADR-903 §7). Before it, `sinks::start` built the sinks once, `DROPS` was a `OnceLock`, and a sink's spill file was keyed by name alone. The aggregator's sink list (`EventSinks.outs`) is touched only by the aggregator thread, which also feeds the query log.

**Decision:**
1. **A manager, not a lock.** `sinks::Manager` owns the running sinks (each a thread and a bounded channel, `max_buffer`) and is driven by one applier task (`sinks::run`), woken by every configuration reload (a file, an API write, a replicated blob) and debounced by 250 ms. `apply` runs on a blocking thread, never on a request path, a reload or the aggregator. It diffs the wanted sinks against the running ones (settings, node name and data directory), keeps the unchanged, retires the removed and changed ones, starts the new ones, and sends the aggregator the new `Vec<Out>` through a std `mpsc` channel.
2. **The aggregator reads it with `try_recv`, once per batch**, in `Sink::tick` (the aggregator calls `tick` after every drain). No lock, no allocation per event, no wait: `telltale-telemetry` and the `Sink` trait are unchanged, and an `EventSinks` always exists (with no sinks it returns at once from `record`). A sink that stays keeps what has been reported of its drops.
3. **Retiring.** A `Control` (stop flag, remove flag) tells a thread to send what it holds and end: a file or syslog sink writes what is queued; a webhook sends everything queued in chunks of `batch`, **one try each and no wait between tries**, and what it cannot send is dropped and counted (for a removed sink) or kept on disk (for a sink being replaced that keeps its spill). The threads notice a stop within a second (every wait is at most 1 s). `apply` waits for them up to **2 s** before it starts the new ones (so two threads never share one sink's kept batches); a thread still sending after that is left to end after its attempt (`stragglers`). Events the aggregator offers a stopping sink in that window are counted as dropped once its queue is gone.
4. **Kept batches belong to a name and a URL.** `<data_dir>/sinks/<name>-<12 hex of BLAKE3(url)>.spill`. A sink whose key changes or that is removed has its files deleted when its thread ends (the `remove` flag), so a name re-used for another collector never replays the old one's events (the AC). Files from before this change (`<name>.spill`) are renamed to the hashed name by the sink of that name when it starts.
5. **Drops only grow.** The manager keeps one counter per sink name for the life of the process, shared by every incarnation of the sink and kept while it is removed, so `telltale_sink_dropped_total{sink}` is monotonic across reloads, changes, removal and return. `drops()` (for `/metrics`) reads the manager's swappable list.
6. **A sink that cannot be built is left out alone** (a bad CA file, no path, an unusable address, no HTTP client), with its reason in `GET /api/v1/sinks`, and the rest start. The building (TLS config, client) is done before the thread starts, so the reason is known to the API.
7. **Credentials are read per batch** (already so for `token_ref` and `token_file`; OTLP's `header_refs` per export): a rotated secret needs no reload. The OTLP metrics task re-reads the configuration every interval and on a wake-up (`otlp_changed`), so an endpoint added, changed or removed applies at once; it starts its interval over on a change.
8. **Performance:** nothing is added to the hot path. The per-event work in `EventSinks::record` is unchanged; the swap is one `try_recv` per 25 ms batch. `telltale-telemetry`, `telltale-proto`, `telltale-net`, `telltale-cache`, `telltale-filter` and `telltale-policy` are unchanged.
9. **A stopping writer has a deadline.** A webhook told to stop has `RETIRE_WAIT` (2 s) in all: past it, what is still queued goes to the kept batches (no network) or is counted dropped. When the manager gives up on a thread it sets `abandoned`: that thread never touches the kept batches again and never deletes them, so it can't corrupt or remove the files of the sink that replaced it. A request already in flight ends within its own timeout; the straggler holds at most the batch it is sending.
10. **One configuration per export round.** The metrics and trace loops read the address and the headers from the same configuration snapshot each round, so a collector that has just been changed never gets the old one's address with the new one's credentials, and an export turned off sends nothing.

**Consequences:** a sink or the export is added, changed or removed without a restart and without touching DNS; the aggregator never waits for a sink; the metric never resets. The cost is that a changed sink restarts (its in-memory buffer is flushed with one try and the rest is counted as dropped), and a stop takes up to 2 s to finish on a collector that is down. **Rejected:** a lock around `outs` (the aggregator would contend with the applier), swapping the whole sink list inside the telemetry crate (a hot-path crate for a cold change), joining without a limit (a dead collector would hold the applier for a webhook's 15 s timeout), and resetting the counter on a change (a Prometheus counter that falls is read as a restart).

## ADR-986 — Sync 2026-11-18: upstream's M24 and its T22.2 take the fork's numbering, M30 and T29.2 (Accepted 2026-11-18)
**Context:** the sync of upstream `095b77f` brought a milestone "M24 — Query-log negation and a cluster-wide support package" (tasks T24.1, T24.2) and a task T22.2 (a second icon pack) under upstream's M22. The fork already has M24 (Replacing Pi-hole, T24.1 to T24.25, referenced in code, tests, ADRs, the README and by the wave-o tracks that are changing the fork now) and M22 (home integrations, with its own T22.2). The sync procedure says to rename on a collision. At the 2026-11-17 sync the upstream milestones that collided (M22, M23) took the fork's free numbers (M29, M28): the tree and `spec/10` show that.
**Decision:**
- Upstream's M24 is M30 here: T30.1 (the "not" filters, ADR-171) and T30.2 (the cluster support package, ADR-172). Upstream's T22.2 (Bootstrap Icons) is T29.2, under the icons milestone M29 (upstream's M22).
- Upstream ADR numbers are unchanged (ADR-170, 171, 172). Upstream's code comments and commit messages cite ADRs, not task IDs, so no code reference changes; the one prose mention (`site/dev-gates.html`, "tasks like T24.1") is only an example and is left as upstream wrote it.
- The ledger (`spec/upstream.md`, milestone-renumbering) gains the new rows. M30 is the next free milestone number; the next upstream milestone that collides takes M31.
**Alternatives rejected:** renaming the fork's M24 (about 25 tasks cited by number across code, tests, ADRs, the README and open branches: a rename now would break every in-flight track's references and its merge into the spec).
**Consequences:** an upstream reader looking for T24.1 finds the fork's Pi-hole special names; the milestone line of M30 says "upstream M24".

## ADR-987 — Break-glass default stays loopback; upstream's #63 answer (document the private-network default) is not taken (Accepted 2026-11-18)
**Context:** upstream's b334e0f (refs #63) keeps `allowed_admin_networks` defaulting to private networks and loopback, says so in the key's description, `docs/running.md`, the users guide and `spec/08`, and logs the open networks at start-up. The fork's owner decided the other way (ADR-944): absent means loopback only, a proxied request is never break-glass, and a warning is logged while the list is unset. `allowed_admin_networks` is `Option<Vec<Cidr>>` here and `Vec<Cidr>` upstream.
**Decision:**
- Keep ADR-944 whole. From b334e0f the fork takes the two-factor code box (already fixed here the same way, `pattern={"[0-9]{6}"}`), the Playwright two-factor test and `6-markup.spec.ts` (kept beside the fork's `6-totp.spec.ts`), and the wording that disable_local_login is a way in for when the provider is down.
- Not taken: the default-list wording (`schema.rs`, `docs/config-schema.json`, `docs/running.md`, the users guide, `spec/08`), upstream's list-based start-up `break_glass_notice` and its test (the fork has its own `break_glass_notice(bool, Option<&[Cidr]>)`: a warning when the list is unset, the loopback default, or empty, and an info line when it lists networks; tested by `api_004_break_glass_notice_covers_unset_empty_and_listed`), and the ADR-944-contradicting prose in the key descriptions. Those stay or are rewritten to the loopback default.
**Consequences:** the fork's documentation and schema say loopback; a later upstream sync that touches these lines conflicts again, and `break-glass-loopback` in the ledger lists the paths. If upstream moves to loopback, drop this ADR.

## ADR-988 — Workers start with mimalloc's arena reservation off, so `RLIMIT_DATA` counts what a worker holds (Accepted 2026-11-18)
**Context:** the Pi-hole import worker (ADR-939) answered `{"ok":false,"error":"<path>: <path>"}` in every musl build, and the discovery workers (ADR-908, ADR-933, ADR-934) ran under a limit that bounded nothing. Cause, from `strace`: the binary's global allocator is mimalloc (`main.rs`). At its first allocation, before `main`, mimalloc reserves a 1 GiB arena with one `mmap(PROT_READ|PROT_WRITE, MAP_NORESERVE)`. Linux counts a private writable mapping against `RLIMIT_DATA` (`VmData`) when it is made, touched or not. After `harden` set `RLIMIT_DATA` to 1 GiB, `VmData` was 1026 MiB: the next `mmap` that needed a new range failed (`mprotect ... = -1 ENOMEM` twice), SQLite's `sqlite3_open_v2` returned a null handle, and rusqlite reported it as the bare path. The discovery worker (64 MiB) did not fail, for the opposite reason: every allocation fell inside the arena that was already mapped, which the limit never sees, so its limit allowed about 1 GiB. The glibc debug build maps the same arena (checked: `VmData` 1026 MiB), but its tests never opened a database after hardening.
**Decision:**
1. `telltale_net::worker::prepare_spawn` sets `MIMALLOC_ARENA_RESERVE=0` (KiB) in the worker's environment, after the caller's `env_clear`. mimalloc then makes no arena: each 32 MiB segment comes from the kernel on demand (mapped `PROT_NONE` and committed as used where `vm.overcommit_memory` is 0; mapped read-write at once where it is 1, as on wrendns-dev, where a new discovery worker shows 6.2 MiB of `VmData` before its handshake), so `VmData` is what the worker holds and `RLIMIT_DATA` is a real bound, enforced in steps of one 32 MiB segment. This rests on mimalloc's internals and the overcommit setting. Every spawner of a worker already calls `prepare_spawn` (the discovery supervisor, the import preview); the integration tests of `discovery_workers.rs` now do too. The worker's environment is no longer empty but has exactly this one variable (`dsc_002_worker_env_is_empty` expects `env_vars == 1`).
2. `harden` refuses to run, with a message naming the variable, when `VmData` plus 4 MiB is already above the limit it was asked for. A worker started without `prepare_spawn` (by hand, or by a spawner that forgot) says why; it no longer fails later inside a C library. The limit itself stays exactly the requested size (the supervisor checks `data_bytes == memory_mib << 20`).
3. The limits do not change: the import worker keeps 1 GiB (ADR-939), the discovery workers `[discovery] worker_memory_mib` (32 to 128, default 64). `RLIMIT_AS` stays unused (ADR-908).
4. The main process is not touched: its allocator keeps the arena (the hot path and the memory budget are unchanged; the change is in `telltale-net`'s worker module, which the query path does not call).
**Measured (musl `bench-fast` build, wrendns-dev):** with the variable, a 9 MiB gravity.db of 300,000 domain rows is converted in 0.2 s at 238 MiB peak RSS, under the 1 GiB limit; the discovery worker passes its handshake and ping at 32 and 64 MiB; the debug-only `alloc` fault job still aborts the worker at its 32 MiB limit (`dsc_002_worker_rlimit_aborts_alone`), which shows the limit now bounds. Without the variable: `VmData` 1026 MiB and the import fails as reported.
**Alternatives rejected:** setting the limit to `VmData` now plus the budget (keeps the arena, so up to 1 GiB plus the budget is allowed: a hostile input is not bounded, and the reported limit stops matching the request); `mi_option_set(arena_reserve)` in the worker's `main` (too late, the arena exists before `main`); removing the limit (the owner's rule is to keep one); `RLIMIT_AS` with a larger value (the arena counts there too, and a measured value would depend on the thread count and the build); a second allocator for workers (a dependency and an image-size cost for one variable).
**Consequences:** a worker's real memory use is now bounded by its limit, so a worker that used up to 1 GiB of arena before may now abort at its limit: the defaults were chosen for the work (ADR-908), and a worker that aborts is restarted by the supervisor and reported. The worker's environment is `MIMALLOC_ARENA_RESERVE=0` and nothing else. A future change of the global allocator must keep this property or replace the variable.
**Test plan:** `api_007_import_worker_reads_gravity_db_under_its_limit` and `api_007_import_worker_unpacks_teleporter_in_its_scratch_dir` (`crates/telltale/tests/pihole_import_worker.rs`: they spawn the built binary under the real 1 GiB limit and fail on the old code in debug and release builds), `dsc_002_worker_without_allocator_env_refuses_clearly`, `dsc_002_prepare_spawn_sets_allocator_env`, `dsc_002_vm_data_is_readable`, and the CI job `worker-image` (the musl image: discovery handshake with a 64 MiB limit, import of a gravity.db and a Teleporter zip, read-only root).

## ADR-989 — The import's scratch files live in a private directory under the data directory (Accepted 2026-11-18)
**Context:** the image is `FROM scratch` and has no `/tmp`. The import wrote the upload with `std::env::temp_dir()` (the server) and the worker unpacked a Teleporter archive's `gravity.db` there too (SQLite reads files, not memory); with the worker's empty environment `temp_dir()` is `/tmp`. In the image the preview answered 500 "can't store the upload".
**Decision:** each preview makes `<data_dir>/import-tmp/<pid>-<time>-<n>` (the parent, `import-tmp`, and the directory at mode 0700), writes the upload there (mode 0600) and starts the worker with `--scratch <that directory>`, where it unpacks the database. The whole directory is removed when the preview ends (`Drop`). The parent is swept of directories older than an hour (left by a crash). The data directory is the one path every install can write (the image's volume, the unit's `StateDirectory`, the chart's PVC). If it cannot be written, the preview falls back to the system's temporary directory rather than failing. The worker's `--scratch` is optional; without it (the CLI `telltale import pihole`, which runs in the operator's own shell) the system's temporary directory is used.
**Alternatives rejected:** adding `/tmp` to the image (a writable path outside the volume breaks the read-only-root rule of `08 §2`); a tmpfs mount in the chart and the compose bundle (every deployment would need it, and the native unit would not); the worker choosing its own directory (it has an empty environment and no knowledge of the data directory).
**Consequences:** `import-tmp` appears under the data directory while a preview runs and is empty otherwise. `telltale import pihole` of an archive still needs a temporary directory, which exists wherever a shell does.
**Test plan:** `api_007_upload_scratch_is_private_and_removed`, `api_007_upload_scratch_falls_back_to_temp_dir`, `api_007_import_worker_unpacks_teleporter_in_its_scratch_dir`, and the `worker-image` CI job (the previews run in the image with a read-only root and no `/tmp`).

**Review amendments (2026-11-18):** the fallback to the system temporary directory creates only a fresh `telltale-import-<random>` directory (mode 0700, fails if it exists) and never changes the mode of, or sweeps, the temporary directory itself; the stale sweep runs only under `<data_dir>/import-tmp` and only on names `up-<pid>-<time>-<n>-<random>`. Scratch names carry a random suffix. An archive entry is capped at 256 MiB (was 512) so inflating (which doubles its buffer) stays under the 1 GiB limit and the user gets the clear refusal, not an abort. Previews are already limited to two at once (`PREVIEWS`). The upload's removal on drop is synchronous and accepted: the directory is one upload and one file.

## ADR-991 — List failures are read from the error text and fixed with the existing list endpoints; the per-list limit offered is capped at 128 MiB (Accepted 2026-11-18)
**Context:** the first real import (40 lists) left lists failing for reasons a person can fix: one over `max_list_bytes` (64 MiB), one whose address returns 404, a GitHub page URL (an HTML page), and a regex list that is not an adlist. The error text said what happened but the Lists page offered no way to act on it. Pruning lists that add nothing was asked for with it.
**Decision:** (1) the importer rewrites GitHub `blob`/`raw` page URLs to `raw.githubusercontent.com` and skips regex-named lists, both with a preview note. (2) The Lists page reads the download error (`larger than the N-byte limit`, `the server says it is M bytes`, `HTTP 404`/`410`) and offers fixes through `PUT`/`DELETE /api/v1/lists/{name}` and `POST /api/v1/lists/refresh`, so no new API operation (and no new MCP tool: agents already have these) is added. (3) The limit offered is the announced size plus 25 percent, or double the old limit when the size is unknown, rounded up to whole MiB and never above 128 MiB. The ceiling is a judgment from the memory figures in ADR-020/ADR-023 (about 20 bytes a name running and about three times that while compiling): 128 MiB of hosts lines is millions of names, already past what a 512 MiB Pi compiles. `max_list_bytes` itself still allows up to 1 GiB for someone who sets it in the file. (4) A list is called redundant when its Unique count is 0 and its largest overlap holds all its names, in one other enabled, enforcing list of the same kind (identical lists: only the later-sorting one is offered); the offer is to turn it off or remove it, never an automatic change.
**Alternatives rejected:** a structured error field on `ListInfo` (an OpenAPI change, and replicas merging lists from an older primary would lose it; the text is stable and tested); raising `[filter] max_list_bytes` for everyone (one bad address could then fill memory on every list); pruning single rules from a list (a downloaded list is replaced at the next refresh, and the snapshot keeps overlap counts, not which names overlap).
**Consequences:** the error text is now an interface for the UI: `too_big` in `telltale-filter` keeps its wording (`flt_004_size_cap_keeps_last_good`). Owner to confirm the 128 MiB ceiling.
**Test plan:** `t24_27_*` unit tests, the Playwright test `t24_27 list failures offer a fix`.

## ADR-997 — An upstream's source address: `source` is an address or a network, resolved per node (Accepted 2026-11-18)
**Context:** T24.31 (UPS-013). A group's queries (UPS-007) can already go to their own upstream group; some DNS filters key a policy on the address a query comes from, and a node on several networks may need to choose which one it uses. Addresses differ per node, but an upstream is shared configuration. (Owner correction 2026-11-18: a gateway's content filtering works on traffic, so this is not needed for that.)
**Decision:**
1. `[[upstream]] source` is an address (`198.51.100.252`, `198.51.100.252:0`, `[fd00::2]`) or a network (`198.51.100.0/24`). A shared upstream names a **network**: each node uses the address it holds in it (up interfaces first, global before link-local, then the lowest). An address is for one node (single-node setups). Interface names were rejected: they are not stable across hosts and say nothing about the network a filter sees.
2. Applies to `udp://`, `tcp://`, `tls://` and `https://`; refused with a `proxy` (the proxy opens the connection) and on other schemes. The port must be 0: a fixed port would give up RFC 5452 source-port randomness.
3. The socket is bound before connect (UDP: per query, as before; TCP: `TcpSocket::bind` then connect). Each upstream owns its connection pool, and the source is part of the upstream, so a pooled connection is never reused from another address.
4. **The hard refusal is on the write only.** `PUT /upstreams/{name}` (and `dryRun`, and the MCP plan tools) resolve `source` against the node's interface addresses (`getifaddrs`, in `telltale-net`, the only `unsafe`) and answer 422 before storing a source the node holds none of; `telltale config check` and **Test it** report it as a warning or error text. Start, reload and a replica's apply never refuse it (that would take DNS down for every upstream, on a restart or on a pod without the network: CLU-004, OPS-009): the upstream is built with its source unresolved, its queries fail fast with `UpstreamInfo.sourceProblem` and the degraded health reason `upstream_source_lost`, and the others serve. An unresolved or lost source is looked up again at most every 5 seconds, so it recovers by itself (a VLAN that comes up after start, a DHCP address that changes). A `getifaddrs` failure is reported with its OS error. IPv6 link-local sources are refused (no scope id). A hostname upstream is reached over the first address of the source's IP version, and having none is the upstream's problem.
5. The API's `SystemInfo.addresses` lists the node's addresses and networks for the UI's suggestions (node-local, read off the query path).
**Consequences:** in a cluster a network a node has no address in degrades that node's upstream only (its health shows `upstream_source_lost`); name a network, not one node's address. Binding an address doesn't choose the egress interface: the operator adds a source-based routing rule (docs/running.md runbook). Bootstrap lookups are not bound to the source. A pooled connection outlives a removed address until it closes. No cost on a query that sets no source.
**Test plan:** `ups_013_*` (`telltale-upstream/tests/source.rs`: UDP and TCP leave from the bound address, a foreign stored source starts degraded while other upstreams serve, a lost one is a problem, family mismatch, an IPv6 source with a v4-only hostname; `source.rs` unit tests for the network choice); the Playwright upstream-source test.



## ADR-994 — Content categories and filter profiles are in scope; a profile is a group (Accepted 2026-11-18, owner decisions)
**Context:** the owner asked (2026-11-18, with two screenshots of UniFi's content filtering) to organise blocking into categories (groups such as "Adult and Sensitive Content", "AI & Crypto", "Business & Professional", "Culture & Entertainment", "Networking Infrastructure", "New or Risky Domains", "Security & Threat Protection", each with checkboxes and an "n of m" count) and to manage them in named filter profiles (a list with Name, Source, Filter Scope, Safe Search and Schedule, and an editor with Source, Ad Block, Safe Search per engine, Filtering Off, Enhanced or Basic, and a category picker with Search, Select All and Deselect All). A later message added that adding devices from the profile is wanted too. The scope note in `spec/10` (quick rules, around line 272) said "Not parental controls: no screen time, no content categories".
**Decision:**
1. **Scope.** Content categories are in scope as FLT-901; filter profiles as FLT-902. The note is amended: *no screen time* (per-device time budgets) stays out; *no content categories* is withdrawn. Schedules (FLT-010) stay time windows.
2. **A profile is a group.** No parallel object. Source = `group.networks` plus managed clients whose `groups` include the profile (ADR-973/976 keys); Schedule = `group.schedules`; safe search and `youtube_restrict` as today, with new `safe_search_engines`; services = `blocked_services` (FLT-012); filtering = new `group.content = { level = off|basic|enhanced, categories, tiers, ads }`. The Groups page becomes the profile list and editor; every existing advanced field stays under "Advanced".
3. **A category is a named selection of catalog sources; a source becomes a managed list** (ADR-040) named `cat-<source-id>`, created only while a group uses it, fetched once and shared by every group that selects it, with a read-only `owners` set. **Category lists are never part of a group's "every enabled list" default.**
4. **Only categories with a real maintained, openly licensed source are offered** (ADR-995); the rest are listed as not offered, never as empty checkboxes.
5. **Cost is shown before it is paid.** Sources above 500,000 entries are "heavy"; a running total of distinct sources uses the 12 bytes per domain target (`spec/05` §2) against `[filter] entry_budget` (default 1,000,000, the NFR number; a Settings control). A source above 500,000 entries is *heavy*; several (NRD 7 days, full TIF) pass the default budget alone and are labelled *heavy, over the default budget*. A selection is refused when the node's baseline RSS plus the estimated snapshot plus the compile peak passes 50 % of the node's memory limit, the baseline RSS being 32 MiB provisional until step 2 measures it (Open: the 50 %), where the compile peak is `min(sum of source bytes x a measured factor, merge budget)` and the merge budget is `min(128 MiB, 25 % of the memory limit)`. Heavy sources refresh at most every 24 hours and the fetch streams to disk.
6. **Defaults are off.** A new install downloads no category list and every group is `level = "off"`.
7. **Failure isolation.** Category lists and the catalog never affect answering: an unknown category id (version skew, ADR-059) is ignored and reported; a failed download leaves the last good snapshot (FLT-004).
8. **Roles and agents.** Viewer reads the catalog; operator edits a group's `content`; agents read and plan (`config:write:groups`). **`plan_set_group_content` is plan-only for agents whatever `require_approval` is.** Content plans are always created `pending` (an exception to ADR-070, which has an approval state only when the setting is on; `plan_pin_version` refuses planning when it is off, a different rule, not copied): an agent's `apply_plan` on an unapproved content plan is 403 `agent_not_allowed`, and an operator-approved plan applies. REST is gated the same way: `PUT /groups/{id}/content`, and `PUT /groups/{id}` when `content` changes, answer 403 `agent_not_allowed` to an agent token (test `flt_901_agent_rest_put_content_403`). A heavy or over-budget selection is also refused at planning time for agents.
9. **Reserved names.** The `cat-` list-name prefix belongs to the server: a file- or API-defined list named `cat-*` is a validation error.
10. **Cluster.** The primary fetches and compiles category lists; replicas receive the snapshot (`spec/12`). A replica never downloads a category list.
**Alternatives rejected:** a separate "profile" object beside groups (two ways to say the same thing, and clients, schedules, safe search and rewrites already hang off groups); bundling lists in the binary (licences, image size ADR-916, stale data); a category as a regex or keyword classifier (no maintained open source, false positives, hot-path cost); one list per category written by hand (we would be the maintainer); offering Block List Project (archived 2026-10).
**Consequences:** a per-engine safe-search field is added; the Lists page shows category-owned lists read-only; the config schema, OpenAPI and MCP snapshot change; `docs/third-party-notices.md` gains the sources; no screen time. Design: `docs/design/content-categories.md`. Task: T24.29.
**Test plan:** `docs/design/content-categories.md` §9.

**Owner decisions (2026-11-18).** All ten recommendations in `docs/design/content-categories.md` §12 are accepted:
1. Offer the seven UniFi-style groups plus Privacy and Ads.
2. Basic is Adult, Malware, Phishing and Scam.
3. Nothing is selected by default.
4. UT1 comes later, through the mirror once its licence is read.
5. No OISD.
6. An authored AI-services bundle, and no crypto bundle.
7. Ad Block is one checkbox, with the tier in Settings.
8. Newly registered domains at 7 days only.
9. A category over 50 % of a small node's limit is refused.
10. A device's several profiles combine as a union. Bon-Appetit is an Extended Adult tier, off by default.

**Measured the same day:** UniFi's content filter is DNS-level. The gateway sinkholes filtered names and intercepts outbound port-53 queries, but queries to an internal resolver are not intercepted. So a device that uses TelltaleDNS is filtered only by TelltaleDNS's categories, or by the gateway when TelltaleDNS forwards to it from that device's VLAN (T24.31 source address, T24.32 direct way). The owner chose both.

## ADR-995 — The category catalog: `presets/categories/*.toml`, sources with licence and cadence, downloaded at runtime (Accepted 2026-11-18, owner decisions)
**Context:** ADR-994 needs a catalog that is data (like `presets/services/*.toml`, FLT-012), with sources checked for licence, maintenance and size. Sources were checked on 2026-11-18 by fetching repository metadata, licences and file headers (`docs/design/content-categories.md` §2.1).
**Decision:**
1. **Format.** One TOML file per catalog group, compiled into the binary, with five tables: `[[group]]` (id, name, order); `[[category]]` (id, name, group, one-line description for the info icon, `sources`, optional `tiers` and `default_tier`, `kind = "list" | "service"`); `[[source]]` (id, name, maintainer, url, `format = "domains" | "adblock" | "hosts"`, SPDX licence, licence_url, optional attribution, homepage, cadence, entries and bytes from the file header at catalog build, optional `max_bytes`, `weight = "light" | "heavy"` computed above 500,000 entries, optional `resolve = "meta-json"` when the file name changes, and then a fixed `url_prefix` per source: scheme, host, repository path and file-name pattern, e.g. `https://raw.githubusercontent.com/Bon-Appetit/porn-domains/` and `block.<hash>.txt`; a resolved URL outside the prefix is refused and the source reports `resolve_refused`; `cadence = "daily" | "low"`; `tiers` of kind `exclusive` or `additive`; per-source `checked` date and `archived` as recorded); `[[preset]]` (id such as `basic`, `categories`); `[[not_offered]]` (name, group, reason, alternative).
2. **Sources (first release):** HaGeZi `dns-blocklists` and `nrd` (GPL-3.0; adult, gambling, piracy, social, fake stores, DoH/VPN/proxy bypass, dynamic DNS, URL shorteners, hosting, threat feeds, pop-up ads, ad tiers, native trackers, NRD 7 days, DGA 7 days, risky TLDs), StevenBlack `hosts` alternates (MIT; fake news), Perflyst `PiHoleBlocklist` (MIT; smart-TV and app trackers), Bon-Appetit `porn-domains` (CC BY-SA 4.0; optional). Not in the catalog: Block List Project (archived); OISD (`sjhgvr/oisd`, GPL-3.0, pushed 2026-11-18; an earlier draft said "no licence terms found", which was wrong; a candidate Adult alternative, design Q4b); UT1 via the `olbat/ut1-blacklists` mirror (CC BY-SA 4.0 per its README, 80 per-category `domains` files, not archived, pushed 2026-11-11; the licence on the UT1 site is unread and the mirror is not the maintainer's host; Open, design Q4; no archive source type is needed).
2b. **Ad tiers** name HaGeZi's `adblock/` files, so the default tier's URL equals the bundles' existing `hagezi-pro` list (dedup and adoption by URL, design section 6.3); T24.29 edits the two bundle files to drop that list and set `content.ads`.
3. **Admission rule.** A source needs an SPDX licence read from the repository, a push within 90 days, a repository that is not archived, and a URL on the maintainer's host (raw GitHub or jsDelivr for the same repository). **An upstream-run mirror is not admitted** in the first release (Open, design Q4: admit it once its licence file is recorded and the UT1 site's licence is read). The cargo tests (`flt_901_catalog_*`) check **recorded** metadata only: SPDX id, `licence_url`, a recorded `checked` date within 90 days of `catalog_version`, `archived = false` as recorded; they never use the network. The live check against the GitHub API is `scripts/check-catalog.py`, run by the weekly job, which opens an issue when a source goes stale.
4. **Never bundled.** Lists are downloaded at runtime by the primary (replicas receive the compiled snapshot, `spec/12`). The binary carries the catalog (metadata), never list content. The domains-only format is preferred (smallest, cheapest to parse).
5. **Licences and attribution.** The UI shows maintainer, licence and a link for each source, and the CC BY-SA attribution line; `docs/third-party-notices.md` lists them. HaGeZi's GPL-3.0 covers the lists as data fetched by the user; no HaGeZi code is used (AGENTS.md rule 6).
6. **Refresh and cadence.** Each source's cadence sets the list's `refresh_secs` (HaGeZi publishes `Expires: 8 hours`, so the catalog says 8 hours for light sources and 24 hours for heavy ones, which change daily and run to 40 MB); the conditional GET and stale-list rules (OBS-023) apply as to any list.
7. **Versioning.** The catalog carries `catalog_version`. A new category in a newer binary is unknown to older nodes (ignored and reported, ADR-994 §7). Removing or renaming a category id needs an alias entry for one release.
**Alternatives rejected:** fetching the catalog at runtime (a second thing that can fail, and an injection path for URLs: the catalog is code-reviewed data); one big merged list (no per-category choice); bundling a snapshot (licence, size, staleness).
**Consequences:** counts in the catalog go stale between releases; the UI shows the live count after download and the catalog value before. A source URL that moves needs a release (or the user's own list). Risk for the owner: GPL-3.0 on a dataset is recorded here, not resolved by legal review.
**Test plan:** `flt_901_catalog_*` (design section 9), a fuzz target for the catalog parser, `flt_901_meta_json_url_outside_prefix_refused`, `flt_901_cat_prefix_reserved`, `flt_901_catalog_recorded_metadata_fresh`, and a weekly job running `scripts/check-catalog.py` (licence, recency and `archived` flag against the GitHub API; not a cargo test).

**Owner decisions (2026-11-18).** Accepted with ADR-994's decisions.

## ADR-998 — UniFi device and group sync: explicit links, MAC identity, a three-way merge per link, and a definitive side chosen per link (Accepted 2026-11-18, owner decisions)
**Context:** The owner asked (2026-11-18) that devices and policies sync between TelltaleDNS and UniFi in both directions: a device added to a group in UniFi joins the same group in TelltaleDNS, and the reverse. The owner's reading is that UniFi's content filtering acts on traffic and applies whatever DNS a client uses, so TelltaleDNS filters DNS and adds per-device visibility while UniFi enforces at the IP level, and the sync keeps the two consistent. What the repository does today (`routers.rs`, ADR-080, ADR-902, ADR-912, T25.10): TelltaleDNS reads UniFi (`stat/sta`, `rest/user`, `rest/networkconf`, the v2 `clients/history`, and with T25.10 `stat/alluser` and `stat/device`) with an API key (`x-api-key` on `/proxy/network/api/s/<site>/...`) or a session cookie, and **never writes**. A TelltaleDNS device is a `[[client]]` (`name`, `match` keys with the MAC among them, an ordered `groups` list); a group is a `[[group]]`. No UniFi object is linked to either.

**What the research found (public sources only; no request was made to any gateway).** Ubiquiti's own help pages (`help.ui.com`) refused this tool (HTTP 403), so each claim below says where it comes from.
- *From third-party descriptions of the public API (a Go SDK status table and the unifly project's API notes):* the Network **Integration API v1** lives at `/proxy/network/integration/v1/sites/{siteId}/...`, authenticates with `X-API-KEY`, and covers devices, clients, networks, WLANs, firewall zones, firewall policies, ACL rules, DNS records, traffic matching lists, hotspot vouchers, VPN, RADIUS, WAN, DPI categories and applications, with CRUD on several of them. The controller serves its own OpenAPI 3.1 document (reported at `/proxy/network/api-docs/integration.json`), which is the authoritative list.
- *Not found in v1:* a **client or device group** object, a **content-filter profile** object, and any statement of which key role may write. Traffic matching lists hold IPs, ports and domains, not MACs.
- *Classic (session) API, from memory of its long-standing shape and not re-confirmed here:* `rest/user` holds the known clients (MAC, `name`, `note`, `usergroup_id`, `use_fixedip`, `fixed_ip`, `network_id`) and accepts `PUT`; `rest/usergroup` is the **bandwidth-limit profile** a client has exactly one of, not a general membership group; `rest/firewallgroup` holds address, port and IPv6 groups whose members are **IP addresses, CIDRs and ports, not MACs**; `cmd/stamgr` blocks, unblocks and forgets clients. Session writes on a UniFi OS console need a CSRF token (`x-csrf-token`) that the existing read code does not carry.
- *The newer "device groups":* the Policy Engine (UniFi Network 9.4, August 2025) has Objects: devices, device groups and networks, usable as the source or destination of policies and traffic rules. Ubiquiti's article names them but this review could not read it, and no public API document for them was found. I recall a v2 endpoint family (`/proxy/network/v2/api/site/<site>/...`, for example `network-members-group`, `firewall-policies`, `trafficrules`, `content-filtering`) behind the UI, but that is an unconfirmed recollection of an undocumented interface that Ubiquiti can change in any release.
- *Content filtering:* the settings page is Settings → CyberSecure → Content Filter; a policy is scoped to networks or client devices; third-party write-ups (and, in a search snippet, Ubiquiti's own help article) describe it as a **DNS-level** feature that redirects DNS traffic to the gateway, with categories supplied by a partner (a later review found Ubiquiti's own article naming Cloudflare; the earlier partner was CleanBrowsing, so the name is not relied on). **This contradicts the owner's premise that it filters traffic regardless of DNS.** If it redirects DNS, the two filters do **not** simply stack: turning UniFi Content Filter on for a device group likely **hijacks that group's port-53 traffic to the gateway, so those devices' queries may stop reaching TelltaleDNS** and TelltaleDNS loses filtering, attribution and query logs for exactly the devices that were linked. A client using DoH bypasses both. Treat this as a **likely conflict, to be disproved by the owner's test (Q4), not as stacking**; see decision 15. The owner should confirm which it is on the gateway (the page's own help text, or its behaviour for a client with a hard-coded resolver) before product text claims "IP-level" enforcement.
- *Key and role:* keys are made under Settings → Control Plane → Integrations (the existing error text says so). Third-party guides say a key takes the permissions of the account that made it and has no read-only scope; one says writes need a full admin. Ubiquiti's own statement of the minimum role was **not found**, and UniFi has **no role scoped to one object**: any role that can edit a device group can most likely edit the whole firewall, and a Home Assistant issue (home-assistant/home-assistant.io#40330) reports that only a super admin or owner can create a Network API key, so a narrow-role key may not be possible at all. **Say plainly: the write credential can probably change the whole Network application; the protection is on the TelltaleDNS side** (two switches, one function, audit before the request, preview, admin-only), not in UniFi. If keys need a super admin, the fallback is a dedicated **session-only local user** (password through M23, CSRF handled, no MFA on that account, a long random password) and the owner must accept that exposure (decision Q11 of T25.18). The build verifies the real minimum with the owner's help (Q6).
- *Not confirmed anywhere:* which UniFi object holds a device group's members (MACs or client IDs) and whether any API exposes it with write access on the owner's gateway version; whether member lists include offline clients; any change timestamp on membership; the API rate limits; whether UniFi's own audit log records an integration key's writes.

**Decision (design; nothing is built until the owner accepts this ADR and ADR-999).**
1. **A link, created by an admin, never matched by name.** A `[[group_link]]` joins one TelltaleDNS group to one UniFi object: `id`, `group`, `router` (a `[[router]]` of type `unifi`), `site`, `kind`, `unifi_id` (the object's stable ID, with its name kept only for display), `mode`, `create_missing_devices`, `include_private_macs`, `enabled`. One TelltaleDNS group has at most one link per router, and a UniFi object is linked at most once. The admin picks the UniFi object from a list read from the gateway; a same-name object may be suggested, never linked. Unlinking deletes nothing on either side. A renamed UniFi object keeps its link (by ID); a deleted one puts the link in `broken` and changes nothing.
2. **Object kinds behind one interface.** The sync talks to a `GroupBackend` (read the members of one object, add or remove one MAC). The first backend is the Policy Engine **device group**, if the build's capability check (T25.18 step 1) finds a way to read and write its members; it is the object a traffic rule or firewall policy uses, which is what the owner's wish points at. Other kinds are *not* in the first build: `usergroup` (a client has one, so a TelltaleDNS device in two groups cannot be mirrored, and it is a bandwidth profile) and `firewallgroup` (IP members, so a device would have to hold a reservation). A kind may be added only by a later ADR.
3. **Identity is the MAC, lower-case and colon-separated.** TelltaleDNS side: a `[[client]]` whose `match` has a MAC. A client with only an IP, a CIDR or an `id:` key is **not syncable** and is listed as skipped with that reason, never removed and never matched by its last IP. **Editing a synced client so that it no longer has a MAC key makes it unsyncable, which reads as a removal from the group and is copied to the other side per mode; the client edit dialog and the preview say so, and a link in a write mode holds that round for the admin (the same hold as a first-run conflict, rule 6, not the mass-change guard) rather than applying it silently; the edit dialog shows the warning and a Playwright test `dsc_016 edit to ip-only warns in client dialog` plus the AC `dsc_016_edit_to_ip_only_holds_write_mode_round` cover it.** UniFi side: a member's MAC. A UniFi member with no TelltaleDNS client is *unmatched*: with `create_missing_devices` (default on, always shown in the preview) the sync creates a `[[client]]` named from the UniFi alias, else the hostname, else the MAC, with `match = [mac]` and `groups = [<group>]`; **for an existing client a synced add appends the group last in the ordered `groups` list (order is precedence, so the sync never reorders) and a synced removal removes only that entry** (`dsc_016_synced_group_appended_last_removal_only_that_entry`); with it off the device is listed and skipped. The sync never deletes a `[[client]]` and never deletes or forgets a UniFi client.
4. **Private (randomised) MACs.** A MAC whose locally-administered bit is set is *private* (the same test DSC-012 already uses). Phones keep one private MAC per Wi-Fi network by default and change it when the network is forgotten or when the user picks a rotating mode; UniFi and TelltaleDNS see the same per-network MAC, so a stable one syncs like any other. A rotated MAC is a *new* device to both sides. Rules: an existing TelltaleDNS device that carries a private MAC syncs normally; the sync **never auto-creates** a TelltaleDNS device from a private MAC unless `include_private_macs` is on (default off; the preview lists them as "private MAC, skipped"); a device that disappears is never read as a removal (rule 8); the preview marks private MACs so the admin sees that a membership may not follow the person's next MAC. A stale private MAC in a group is shown, not pruned, with a count.
5. **Direction is set per link, and is the definitive side.** `unifi_definitive` (UniFi's membership is the truth: changes flow UniFi to TelltaleDNS, and a TelltaleDNS-side change to the group is overwritten at the next round, with the overwrite recorded), `telltale_definitive` (the reverse; needs write access), or `two_way`. New links start `unifi_definitive`, the only mode that needs no write access, and in **preview-only** state until an admin applies the first preview. **The applied state lives in `state.db` (per link: the applied preview id, the mode and the `writes_enabled` value it was applied under), never in configuration.** Therefore (a) a link that arrives through a TOML edit, `[cluster.git]`, a restore or a peer starts **preview-only and `held`** whatever mode it names; and (b) **entering a write mode (`telltale_definitive`, `two_way`) or turning `writes_enabled` from off to on puts every affected link into `held` until an admin applies a fresh preview of the UniFi-side writes**; the preview of the earlier mode does not carry over. Tests `dsc_016_file_created_link_starts_preview_only`, `dsc_017_mode_change_to_write_needs_new_preview`.
6. **The merge is three-way, over sets of MACs.** Each link keeps a *baseline* B, the membership both sides agreed at the last successful round. With U (UniFi now) and T (TelltaleDNS now), both restricted to syncable MACs: an addition is a MAC in a side but not in B; a removal is a MAC in B but missing from that side. `two_way` applies each side's additions and removals to the other. A change on both sides to the same MAC in the same way is a no-op. Because B is a set, one MAC cannot be both added on one side and removed on the other, so **last-writer-wins is not needed for membership** and is not used: neither UniFi nor TelltaleDNS gives the sync a readable timestamp for a membership change (UniFi's was not found; TelltaleDNS's audit log has one, but the sync sees state, not events). Last-writer-wins applies only to a *per-device attribute* if one is ever synced (the display name; not in the first build). **Conflicts** are the cases B cannot settle: no baseline (first run, restore, failover to a node without it), a baseline older than `baseline_max_age` (default 30 days), the mass-change guard (rule 9), and a linked object that moved. Each is listed in a conflict view with per-row choices (take UniFi, take TelltaleDNS, keep both, skip); "keep both" (the union) is the default suggestion.
7. **Echo and loop prevention.** A round is read, diff, write, **re-read, verify**, and only then is B advanced. The sync's own writes appear on the next read as changes already in B, so they produce no diff. TelltaleDNS changes the sync makes carry `origin = sync:<link id>` in the change record and the audit, and a change event with that origin never triggers a round. Rounds are timer-driven (`interval_secs`, default 60, minimum 30) plus one on a UI request; there is no event feedback path. If one MAC flips more than three times in an hour on a link, the link is paused with `flapping` and an alert (something else, such as another controller or a UniFi auto-assignment, is writing the same set).
8. **Deletes and absence.** A MAC removed from a group on one side is removed from the other (per mode). A device that is *deleted* (a UniFi client forgotten, a `[[client]]` removed) counts as a removal from the group only. Absence from a connected-clients list is never a removal: UniFi members are read from the group object, not inferred from `stat/sta`. If the read comes back unparseable, or cut off, the round is aborted, not applied. If it is parseable but **empty when B was not** (a legitimately emptied group), the round is **held as an admin-confirmed preview** (the admin may apply the emptying), not aborted for ever.
9. **Mass-change guard.** A round that would remove more than `max(5, 20%)` of a link's members from either side, or change more than `max_changes_per_round` (default 50), is *held*: shown as a preview that an admin must apply. The first round of every link (no baseline) is additive only: removals are never applied without an explicit tick in the preview.
10. **Outages.** UniFi unreachable, a 401 or 403, or a refused write: the round does nothing, the link is `stale` with the reason (the router's status shows it too), TelltaleDNS keeps enforcing its current membership, and an alert fires after `stale_alert_rounds` (default 5). On recovery the three-way diff against B is safe however long the gap. TelltaleDNS-side problems (telemetry, storage, API, cluster) never affect DNS answering (CLU-004); a failed config write just fails the round. The sync runs off the main runtime, on its own thread like the inventory (ADR-912), and nothing it does is on the query path.
11. **What policy syncs: group membership only.** TelltaleDNS's categories and lists are DNS-name sets; UniFi's content-filter categories come from a partner's taxonomy and, per the research, may be DNS-level themselves. A mapping between them would look like parity and would not be: a TelltaleDNS "adult" list and a partner's "adult" category differ in members, update cadence and failure behaviour, and a UniFi category block may be a different layer from a TelltaleDNS block. **Mapping categories would mislead and is not built.** What is useful, and cheap, is the shared group: the admin builds UniFi policies against the same device group in UniFi, TelltaleDNS applies its DNS policy to the same devices, and a device's effective policy page (T24.30) shows the TelltaleDNS side. The sync never creates, edits or reads UniFi policies, rules or content-filter profiles in the first build; a later task may show, read-only, which UniFi policies use a linked group (Open, T25.18).
12. **Safety.** Every first sync and every held round starts with a **dry-run preview** that lists each change by side and device, flags private and skipped MACs and unmatched devices, and shows each affected device's change in effective policy (the T24.30 resolver); apply takes the preview's id and is refused if either side changed since (`409 preview_stale`). Limits: one write request per second, 50 membership changes per round, reads no more often than `interval_secs`, one in-flight round per link. **Audit:** one audit record per applied change on the TelltaleDNS side (`group_link.member_add` and `.member_remove`: device, MAC, link, before and after, `actor = sync:<id>` and the admin who approved the preview), and one per UniFi write, written **before** the request and completed after it (a write cannot be unaudited); on UniFi's side the write carries a marker in the object's note or description where the object has one ("managed by TelltaleDNS link <id>"), and whether UniFi's own admin log shows it is to be checked (open). **Kill switch:** `[unifi_sync] enabled` (default false; an admin turns it on, an operator or an agent may only turn it off; cluster-wide; effective on the next round with no restart) and a separate `writes_enabled` (default false) that must also be true for any UniFi write; each link also pauses. **Credential:** a separate write credential (ADR-999). **Agents and MCP:** read tools and plan tools only; applying a preview, and any link whose mode writes to UniFi, is a human admin action (no agent scope applies it, as ADR-903 §5 does for secrets). **Agents also cannot cause a gateway write indirectly:** any agent-originated change (`origin = agent:*`: `plan_assign_client`, `plan_update_group`, `plan_rename_client`, a client edit, a deleted `[[client]]`) that alters the membership of a group linked in a write mode, or turns an unlinked group into one, is refused at apply with `403 agent_not_allowed` and a reason naming the link; a plan reply says `propagates_to_unifi`, and the admin makes that change by hand. Test `dsc_017_agent_membership_change_never_reaches_unifi`.
13. **Cluster.** One node runs the sync: the **primary** (spec/12: the one eligible node that accepts config writes), because the sync's TelltaleDNS-side changes are config writes and must not be proxied from a replica. The gate refuses an ephemeral pod or a witness (as `gate::designated` does, ADR-930). The write credential reaches full members through M23's replication (ADR-903), so a promoted node has it. The links and `[unifi_sync]` are shared configuration. The baselines are node-local in `state.db` and also sent best-effort over the cluster channel; a promoted node without a current baseline starts the link *held* with no baseline: additive only, removals need the admin. A node that loses the primary role stops at the next round boundary.
14. **Relation to the CMDB (M31, fork #21, T31.1).** The CMDB's "definitive source per attribute" is this ADR's per-link direction seen from the CI: for a linked group, the attribute *member of group* has two sources (TelltaleDNS configuration, UniFi). `unifi_definitive` is "UniFi is the definitive source for this attribute for CIs in this group", `telltale_definitive` the reverse, `two_way` is "no definitive source: merge". The conflict view here is shaped like T31.3's (value per source, the definitive value, the disagreement) so M31 can absorb it. **Until M31 exists the link holds the direction and nothing depends on M31.** When T31.3 lands, the direction is read as the precedence for that attribute, and a MACD (T31.4) may replace the preview's approval for a new device. This ADR does not decide M31's model; it only must not contradict it.

15. **The UniFi Content Filter may bypass TelltaleDNS for a linked group.** Because UniFi's filter likely redirects DNS to the gateway (rule 11's research), enabling it on a device group that is synced to a TelltaleDNS group may stop those queries reaching TelltaleDNS. The docs (`docs/unifi-sync.md`), the help topic `unifi-group-sync` and the link dialog carry the warning "UniFi Content Filter on this group may bypass TelltaleDNS"; product text claims neither stacking nor IP-level enforcement until the owner's Q4 test (do queries to TelltaleDNS still arrive, for a device in the group, with the UniFi filter on?) settles it. The sync itself never reads or changes UniFi's filter.

**Alternatives rejected:** matching groups by name (a rename silently relinks, and a typo can join a group); one-way polling only (the owner asked for both directions); last-writer-wins for membership (no readable timestamps, and a set has no such conflict); a two-way sync with no baseline (it cannot tell a deletion from an addition, so it would resurrect or destroy members); mapping content-filter categories (misleads, see 11); writing UniFi policies or firewall rules from TelltaleDNS (a much larger write surface; its own ADR if ever); creating a UniFi group from a TelltaleDNS group (a second write class; Open); syncing `usergroup` or firewall address groups (cardinality and IP identity); matching devices by IP when a client has no MAC (a stale address names the wrong device, the reason ADR-902 refused it).
**Consequences:** a new managed kind `group_links`, a `[unifi_sync]` singleton, a sync thread on the primary, a write-capable UniFi client (ADR-999), a Groups-page control, new help topics, and a spec/10 task, T25.18. A TelltaleDNS operator who can edit a linked group's membership can, in a write mode, change which devices a UniFi firewall policy applies to, and a UniFi admin can move a device out of a restrictive TelltaleDNS group; both show in the preview, the audit and the effective policy page, and link creation and write modes are admin-only. Until the build's capability check finds a usable device-group interface the task stays at step 1, and the owner is told.
**Test plan:** in T25.18, against a fake UniFi only (never the owner's gateway): the merge function by property tests (convergence, idempotence, no removal without a baseline, no oscillation), the echo and flapping rules, outages, the guard, the preview-then-apply flow, audit-before-write, the kill switches, the cluster gate, the credential never appearing in any output, and the Playwright flow.

**Owner decisions (2026-11-18).** All recommendations for Q1–Q11 are accepted:
- ADR-998 and ADR-999 are accepted, with the read direction shipping first.
- A new link defaults to `unifi_definitive`, preview-only, `create_missing_devices` on and `include_private_macs` off.
- Writes use a dedicated local UniFi user with the narrowest role that works.
- A round that removes more than 5 members or 20 % of a link is held.
- Operators may change a linked group's membership; links and modes stay admin-only.
- Each link uses the first `unifi` router and one site.
- The build comes after T25.10. For step 1, the owner supplies the gateway's OpenAPI JSON when asked.

**Q4 measured:** UniFi content filtering is DNS-level (sinkhole 203.0.113.250 and port-53 interception). Queries to an internal resolver are not intercepted, and nothing is blocked by IP or SNI. The product wording must say "DNS-level".

## ADR-999 — UniFi write access: one operation, one credential, off by default, audited before it is sent (Accepted 2026-11-18, owner decisions)
**Context:** Everything TelltaleDNS does to UniFi today is a read (ADR-080, ADR-902, ADR-912), through a `[[router]]` credential that an admin may well have created read-only. ADR-998 needs the first write: changing the members of one linked group on the gateway. A gateway is the home's firewall; a bug or a stolen credential here is worse than one in a DNS resolver.
**Decision:**
1. **One write class.** The only UniFi write TelltaleDNS may make is *set the members of one linked group object* (add or remove one MAC at a time, on the object a link names). No client edit, forget, block or reservation; no firewall policy, zone, ACL, traffic rule, content-filter profile, network, WLAN, device or setting; no object creation or deletion. This is enforced in one function, `unifi_write::member_op`, that builds the request from a `MemberOp` value (link, MAC, add or remove) and refuses any other path or method; no other code holds the write credential or an HTTP client for it. A test checks the function against a list of paths it must refuse.
2. **A separate credential, off by default. Credential use is exclusive:** the write credential is used **only** by `member_op` (the write) and by the Check button below; the **verify re-read after a write uses the read credential**, as does every other read. The one stated exception, the **Check button**, makes **one GET of the linked object** with the write credential (to show what it can reach) and nothing else; `dsc_017_write_credential_never_used_to_read` allows exactly that call and fails on any other. `[[router]]` gains `write_api_key_ref` (or `write_username` and `write_password_ref` for a console that only offers a session; the CSRF token is then handled, and the key is preferred). The existing read credential is never used to write, and a write credential is never used to read inventory. Values are **write-only secrets through the M23 store** (ADR-903): entered with `SecretField`, never shown, never returned by any route, backup (without a passphrase), support package, MCP tool, audit record or log (`api_014_planted_credential_never_returned` is extended to it). A `*_file` value wins, as elsewhere. Only an admin can set or clear it; no agent scope can.
3. **Least privilege, as far as UniFi allows.** Public sources say an API key inherits its creator's permissions and has no read-only scope, so the credential is a **dedicated local UniFi user** made for this purpose (not the owner's account, not SSO) whose role is the narrowest the gateway's version accepts for editing the chosen group (Network application only; no Protect or Access, no user management, no console settings). The docs explain how to make it, and the Check button reports what the credential can do by that one GET of the target object (the exception in 2), plus the account's role only if that same GET's response carries it (no second call). **"Least privilege" is limited by UniFi:** there is no object-scoped role, so the credential can probably change the whole Network application and a key may need a super admin to create (ADR-998 research); the protection is TelltaleDNS's own controls, a session-only local user is the fallback, and the owner must accept the exposure (Q11). Replication of the write credential is **limited to nodes that can become primary** (not witnesses or ephemeral pods). The real minimum role is not confirmed (ADR-998; T25.18 decision Q6) and the build records what it finds.
4. **Two switches and a gate on the node.** `[unifi_sync] enabled` and `writes_enabled` must both be true, and the node must be the primary. Turning either off stops writes at the next round boundary with no restart. A UniFi write is refused if its link is not in a write mode, is paused, is `held`, or the preview it belongs to was not applied by an admin. **Entering a write mode, or turning `writes_enabled` from off to on, puts every affected link into `held` until an admin applies a fresh preview of the UniFi-side writes** (applied state is kept in `state.db`, ADR-998 decision 5); the first write of a link is therefore always previewed (`dsc_017_mode_change_to_write_needs_new_preview`).
5. **Audited before it is sent.** The audit record is written first (`outcome = pending`) and completed with the result; if the audit store cannot be written, no request is sent. One record per membership change, with the link, MAC, direction, before and after, the approving admin and the preview id. Rate: at most one write request a second, and 50 changes per round.
6. **Connection.** The write goes over the same pinned TLS settings as the router's reads (`tls_ca`, the trusted console certificate of T23.8) and refuses plain HTTP to anything but loopback in tests. Redirects are not followed. A 401, 403, 404, 409 or 5xx stops the round (no retry storm), is shown on the link, and is alerted after the configured number of rounds.
7. **Verification and rollback.** After a write the sync re-reads the object **with the read credential**; the baseline advances only if the read shows the change. The audit's before-values allow *Undo last round* (an admin action that is itself a preview and an audited write).
8. **Tests never touch a real gateway.** The write client takes its base URL from the router entry only; test builds and CI use a local fake (loopback), and a guard in the test support refuses a non-loopback address. The owner's gateway, Pi-holes, VIP and Home Assistant are never contacted by a test or by CI.
**Alternatives rejected:** reusing the read credential (a read-only key would silently become a write key); a general "UniFi client" that can write anything (a bug could change the firewall); writes without a preview or without a prior audit record; letting an agent apply (ADR-903 §5, ADR-914).
**Consequences:** "TelltaleDNS never writes to the gateway" stops being true for linked groups with `writes_enabled`; docs, the Routers page text and `docs/security` say so. The read-only direction (`unifi_definitive`) needs no write credential and is the safe first step. The owner may accept ADR-998 and refuse ADR-999: the sync then ships read-only (UniFi to TelltaleDNS) and the write directions stay off.
**Test plan:** in T25.18 (`dsc_017_*`), against the fake.

**Owner decision (2026-11-18).** Accepted. The exposure in Q11 is accepted only with the read direction shipped first.

## ADR-990 — A lease renewal is not stored; only a vote is (Accepted 2026-11-18; cause unproven until the Pis confirm it)

**Context.** A voter kept its lease in the `ballot.json` it fsyncs before answering. Every renewal (each 5 s, from the primary to every voter, and the primary's own grant) moved `lease_until_ms`, so each renewal cost an fsync on the election lock. On the owner's SD-card Pis the primary lost its lease every 10 to 20 minutes. The cause is **not established**: a slow fsync is one candidate (a store of 2 s or more makes an answer miss the 2 s ask deadline, and two missed rounds in a row end the 13 s lease), and the model in `tests/lapse.rs` shows that this mechanism lapses the old policy and not the new one, but nothing yet shows the Pis' stores are that slow. Other candidates: the vote RPC queued behind large transfers on the primary's streams, and something the primary runs every 10 to 20 minutes. The stored `lease_until_ms` is on the process's election clock, and a restarted node does not use it: `Ballot::adopt` gives it a full lease from its own start.
**Decision.** (1) A ballot is stored when its epoch, candidate or clock changes, or when a lease first appears (`Ballot::must_persist_since`); a renewal extends the lease in memory only. (2) A new elector takes the running elector's ballot when there is one; otherwise a stored ballot's lease is taken to run a full lease from now (`Ballot::for_new_elector`), never shorter than what was promised, because the stored value is older than the last renewal. (3) A node with no election (manual mode) still stores every renewal it grants: it has no memory to hold the lease, and only a transition window uses it. (4) Diagnostics: debug lines for renewal rounds and each answer's time, an info line and the `lease_renewed` event when a lapsed lease returns, a warning when a ballot store takes 500 ms or more.
**Alternatives rejected:** storing less often (every Nth renewal): still a stall, and a harder argument for safety; a longer lease or more rounds before a lapse: hides the stall and delays failover; moving the fsync to a blocking thread: the answer still waits for it, and the election lock would be held across an await.
**Consequences:** a voter's disk is written at votes, not every 5 s (less wear on SD cards). Safety is unchanged: a restart already gives a full lease, a rebuilt elector never shortens one, and one vote per epoch is still stored before it is answered. Not addressed: the vote RPC shares a stream with large transfers (an equally likely cause, not ruled out), and a lapse right after adopting `auto`. The change is justified by the model and by fewer writes, not by a measurement on the Pis: the slow-store warning and the renewal-round debug lines are there to confirm or reject it.
**Test plan:** `clu_005_t24_26_a_renewal_is_not_stored`, `clu_005_t24_26_the_primarys_own_renewal_is_not_stored`, `clu_005_t24_26_a_new_elector_never_shortens_a_lease`; `clu_005_t24_26_a_two_second_store_lapses_the_base_and_not_the_fix` (`tests/lapse.rs`: the real `Elector` with a store taking 2 to 4 s; the base policy lapses, the fixed one does not; no hardware); the partition simulator; `deploy/cluster3/e2e.sh`; `deploy/cluster3/lapse-soak.sh`.

## ADR-1011 — A witness is a voter: the cluster view says so and the checks skip it for configuration, secrets and DNS (Accepted 2026-11-18)
**Context:** A witness (ADR-056, `telltale cluster witness`) runs the cluster channel and the election only: no configuration, no secrets, no DNS. The cluster view built every member the same way, so a witness showed "version 0, 13 behind", secrets "not reported", "not ready", uptime 0, an amber topology box, and counted in the Health and Compare tabs. An unreachable witness mattered, though: with three voters, losing one leaves two, and automatic failover needs a majority.
**Decision:**
1. The view keeps `witness: true` as the marker (the role string stays `replica`, so no consumer of `role` changes) and clears the fields that mean nothing for it (`configSeq`, `configLag`, `behindSeconds`, `secrets`, `ready`, load and cache). It adds `vote` (`lastReplySecondsAgo`, `lastGrantSecondsAgo`, `votedEpoch`), taken from the last reply the witness gave this node's vote request or lease renewal; absent times mean this node has not asked it (manual failover, or a node that is not the primary).
2. A witness's heartbeat carries its process start and uptime (fields every peer already reads; nothing added to the wire, so older peers show 0 as before). Its version is already in its Hello.
3. Checks, health reasons, alerts, the peer-lag metric and the rollout skip a witness for configuration, secrets and DNS (`in_sync`, `serving`, `sync_lag`, canary choice, rollout samples). An unreachable witness still fails `peers_up` and raises `node_down` (health reason and alert), which the health reason had suppressed.
4. The UI shows "witness, votes only", "not applicable" for the three, and the vote state; the topology draws it green while up and red when down.
**Alternatives rejected:** a new `role: "witness"` string (every `role` comparison, the promote form and older clients would need to learn it); hiding the witness from the page (the owner needs to see its vote and that it is up); asking the witness for its ballot over a new RPC (a wire change for a number the primary already learns from the replies it gets).
**Consequences:** the view is a little different for a witness in the API (`vote`, cleared fields); `docs/api/openapi.json` and the UI types are regenerated. No DNS path change.

## ADR-992 — List overlap is counted while the lists are compiled, by name and by side, and the prune plan is computed from those counts (Accepted 2026-11-18)
**Context:** the owner asked (2026-11-18, through AskUserQuestion: "Overlap report + disable") for each list on the Lists page to show how many of its entries no other enabled list has and which lists cover the rest, and for a Prune action that previews the lists adding little or nothing at a threshold the admin sets (for example under 1 % unique) and turns them off after a confirmation, with undo. Much of the count existed already (OBS-009, T7.14: `unique` and a pair matrix in the compile's manifest, `GET /api/v1/lists`' `overlap`). Three gaps made it unsafe to act on: (1) a name a block list and an allow list both hold counted as shared, so an exception list made the block list it excepts look redundant; (2) regexes and modifier rules (`$dnstype`, `$client`, ...) are not in the name FSTs, so a list made of them showed 0 unique and was "redundant"; (3) nothing said which lists a group uses by name, or that a shadow list covers nothing because it never blocks.
**Decision:**
1. **Where it is computed.** In `merge_domains` (`telltale-filter/src/compile/mod.rs`), the pass that already walks every distinct name once, in sorted order, with that name's list set in hand. Never on a query, never from the FSTs afterwards (a snapshot is not re-read for this). It is recomputed on every compile, because it is a by-product of the compile; it is stored in the snapshot's manifest (`stats.per_list[].unique`, `.rules`, `stats.overlap`), so a node that starts from a snapshot has the numbers without compiling. A snapshot written before this change has no `rules` (serde default 0) and the old, side-less counts until the next compile.
2. **Sides.** A name's holders are split into the block side (`Block`, `ImportantBlock`) and the allow side (`Allow`, `ImportantAllow`). `unique` counts a name for a list when it is the only holder on a side; the pair counters count a name once per pair of holders on the same side. A block list is therefore compared with block lists only: an allow list (or an `@@` rule) never makes a block list look covered. A list that is the sole holder on both sides of one name counts it once.
3. **Rules.** Modifier rules and kept regexes are counted per list as `rules` and treated as unique by the plan (`adds = (unique + rules) / entries`). Overlap is by name, so a wildcard another list covers (`||example.com^` already blocks `ads.example.com`) is not seen either; both only err toward keeping a list.
4. **Cost, measured** (`cargo run --profile bench-fast -p telltale-filter --example compile_bench -- synthetic 2000000 1 40`: 40 lists, 2.5 million entries, 1.57 million distinct names, one thread, shared 24-core host under other work, so run-to-run noise was about 0.3 s): peak RSS 146 MiB with the pair counting, 146 MiB without it, 146-147 MiB before this change. Merge phase 1.2 to 1.9 s in every variant (before: 1.13 to 1.89 s; after: 1.31 to 1.79 s; counting off: 1.21 to 1.71 s), so the cost is inside the noise. The counters are a triangle of `n(n-1)/2` `u64` for up to 128 lists (40 lists: 6 KiB; at most 64 KiB), a map beyond that (one entry per pair that shares a name, so at most `n(n-1)/2` entries); the previous per-pair hash map is gone, which removes a hash per pair of holders of every shared name. On a Pi 4 (about 4 to 5 times slower per core) the same per-name work stays a small share of the merge. Nothing is added to the query path: the matcher, the snapshot readers and the cache are unchanged, and `make bench-smoke` is the check (see the task's Done note).
5. **Which lists the plan may turn off.** Enabled block lists in `enforce` mode with entries in the snapshot, that no group names in its own `lists`. Allow lists (an exception list adds nothing by design), shadow lists (they block nothing; the owner turns them off or enforces them), lists not compiled yet (no numbers), and lists a group names (that group may not use the list that covers them: the overlap is global, not per group) are always kept, with the reason in the answer. A group whose `lists` is absent uses every enabled list and does not hold any list in place. Per-group overlap (what a list adds within the lists one group uses) is not built; if wanted it is a refinement of the same counts per list subset (Open).
6. **The plan is a set, not a ranking.** Lists whose own loss `unique + rules + names shared with shadow lists` is at most the threshold percent of their entries are considered least-adding first; one is added only if, with it, every list in the set still loses at most the threshold counting the names it shares with the others in the set. Two lists that mirror each other are never both proposed. `losesAtMost` for the plan is the sum of each list's own loss plus the names each pair of the set shares: an upper bound (a name whose every holder is turned off is shared by at least one pair of them), never an estimate. The threshold is 0 to 50 percent (default 1): above half, "adds little" stops meaning anything.
7. **API** (agent-ready, AGT-001/002; ADR-993 for the apply): `GET /api/v1/lists/overlap` (rows), `GET /api/v1/lists/prune-plan?thresholdPercent=` (the plan; changes nothing), MCP tool `list_overlap` (both reads); `POST /api/v1/lists/prune` is a person's. All three read the primary's numbers on a replica (the primary compiles).
**Alternatives rejected:** computing overlap from the FSTs on request (a full scan of millions of names per request, and per request on every replica); a per-list-pair name sample (a bound is needed for safety, a sample is not one); counting block against allow lists as shared (see context); treating regexes as covered when a list's other names are (unsound); a threshold above 50 (two near-identical lists could both look removable at 100); proposing lists a group names and warning instead (the warning is easy to miss and the harm is silent).
**Consequences:** `GET /api/v1/lists` changes meaning slightly: `unique` and `overlap` no longer count block/allow sharing, and `rules` is new. The Lists page shows "adds N %" and "N % also in X" per list. The compile's work grows by two small side lookups per distinct name (no allocation).
**Test plan:** `flt_004_unique_counts_the_same_side_only`, `flt_004_pair_counts_dense_and_sparse_agree`, the extended `flt_003_compile_*` overlap assertions (`crates/telltale-filter/src/compile/tests.rs`), `flt_004_prune_*` and `flt_004_overlap_rows_*` (`crates/telltale-api/src/lists_overlap.rs`), `compile_bench synthetic 2000000 1 40`.

## ADR-993 — Prune turns lists off through the list edit path and is never for agents (Accepted 2026-11-18)
**Context:** the owner chose "Overlap report + disable": a Prune action previews, then disables after a confirmation, and undo is one click; disabled lists stay in the configuration. Agents and the MCP may read and plan; applying needs a person (AGT rules).
**Decision:**
1. **Apply.** `POST /api/v1/lists/prune {thresholdPercent?, names, snapshotVersion, configVersion}` (operator): `names` and both versions are required, the ones the person previewed (the plan returns `snapshotVersion` and `configVersion`). It recomputes the plan on the server and changes nothing (409, "preview again") if either version differs, a compile is pending, or a name is no longer in the plan. The plan itself treats a cover as a cover only while that list is currently enabled, enforcing and a block list (a list turned off by an earlier prune, or deleted, covers nothing even if the last compile's overlap still names it), and proposes nothing while the overlap names a list that is off or gone (`compilePending`). Each list is written back through the same managed-write path as `PUT /api/v1/lists/{name}` with its current definition and `enabled = false`, checked against the configuration version read before the definitions (then the version each write returned), so an edit in between fails the write and is never overwritten (so credentials read back as `<redacted>` keep their stored value, ADR-903; a list from the config files becomes an override with `enabled = false`; a GitOps cluster gets the usual `keepInGit` guidance from the single-list write). The lists are written one after another; if one fails, the ones already off stay off and the error's hint names them. Audit: each list's write is recorded as `list.put` (before and after, as the PUT route does) as it succeeds, and one `lists.prune` entry (target: the lists, detail: the threshold, the lists, the loss bound) follows; a prune that stops part-way records `lists.prune` with `partial: true` and the lists already off.
2. **Undo.** No new endpoint: the UI's notice ("N lists turned off. Undo") rewrites each list with `enabled = true` through the ordinary list edit (the same edit as turning one on in Manage lists), and an operator can do that any time. Undo has no version check (it is the ordinary last-write list edit), and a list defined in the config files stays an API override with `enabled = true` after Undo, so later edits to it in the files are masked until the override is removed in Manage lists (Open: remove the override when the only difference is `enabled`). Nothing is deleted, so nothing is lost: the list's source, rules and settings stay, and a list that was off is downloaded again when it is on (a disabled list is not fetched).
3. **Agents.** The plan is a read (`config:read`; MCP `list_overlap`). `POST /api/v1/lists/prune` is in `never_for_agents` (`agent_not_allowed`), whatever the token's scopes: turning off a block list changes what every device is protected from, and the plan an agent would apply was computed from numbers it cannot judge (regexes, group intent). An agent proposes; a person applies in the UI or with a user token.
4. **UI.** Lists page, operators only: "Prune…" opens a panel with the threshold (0 to 50), a preview table (list, names, unique, adds, could lose, also in), the lists that stay with their reasons, and a two-step "Turn off N lists" with a confirmation. A panel in the page, not a modal: it stays beside the table the numbers come from.
**Alternatives rejected:** a plan object with an ID and an expiry like `guarded` changes (ADR-956: this changes no guarded setting; the names re-check against the live plan does the same job for a bound of one request); deleting lists (loses the source and cannot be undone); one atomic multi-list write (the write path is per entry; a half-finished prune leaves valid configuration and says which lists are off); letting agent tokens apply with `config:write:lists` (see 3).
**Consequences:** a prune on a cluster replica forwards each write to the primary like any list edit. Several lists turned off one after another can cost one recompile each if the writes are far apart; they coalesce when close together.
**Test plan:** `flt_004_prune_lists_over_http` (`crates/telltale-api/src/tests.rs`: plan, stale names refused with nothing written, the apply writes `enabled: false` with the stored definition, audited, agent refused with `agent_not_allowed`, viewer refused); Playwright `flt_004 prune lists that add little, then undo`.
## ADR-1000 — Serving several networks: routed by default, directly on a VLAN when the owner wants it; what changes in the node (Proposed 2026-11-18)
**Context:** T24.32. Owner decision 2026-11-18: the VLANs reach TelltaleDNS routed through the gateway now; document and build what being directly on each VLAN needs, for later. Measured on the owner's network from the IoT VLAN (203.0.113.0/24): the Pi-hole VIP 192.0.2.249:53 and TelltaleDNS on 192.0.2.12:1053 answer through the gateway; the Pis' extra 198.51.100.x and 203.0.113.x addresses on the untagged eth0 time out (an untagged alias address is on the native VLAN's wire, so nothing on a tagged VLAN can reach it); the IoT DHCP hands out the gateway 203.0.113.1 as DNS.

**Checked against the code:**
1. **Listeners.** UDP (`IP_PKTINFO`, the reply comes from the address that was asked) and TCP on `0.0.0.0` and `::` answer on every interface address and on a VIP. New tests ask for three local addresses and check the reply's source (`dns_001_wildcard_bind_answers_every_local_address_from_that_address`, `dns_001_tcp_wildcard_accepts_on_every_local_address`), and the keepalived e2e proves it on a second network and a second VIP. Nothing to change.
2. **Neighbor table.** `rtnetlink` `RTM_GETNEIGH` with `AF_UNSPEC` dumps every interface, so a node on a tagged VLAN sees that VLAN's neighbors. Nothing to change. The table is keyed by address alone: two directly attached networks with overlapping subnets would collide. Documented, not handled (a home does not do that).
3. **mDNS naming joined the group on `0.0.0.0`**, which the kernel resolves to the default route's interface: a node on VLAN interfaces heard only one network. **Changed:** it joins on every up, multicast-capable, non-loopback interface with an IPv4 address (not containers, bridges or overlays, ADR-910), at most 16, and reads the interfaces again every 60 s so a VLAN interface that comes up later is joined. New `telltale_net::ipv4_interfaces` (`getifaddrs`, in `telltale-net`, where `unsafe` is allowed). mDNS is link-local, so a routed VLAN's names still come from the router's leases.
4. **The Networks page listed only router-reported and group networks**, so a node directly on a VLAN with no router integration showed none of its own networks. **Changed:** `GET /api/v1/networks` adds `source: "interface"` rows for the node's private IPv4 networks (named after the interface, with the VLAN ID from `/proc/net/vlan/config`), unless a router already reported the same subnet; not in a pod (`KUBERNETES_SERVICE_HOST`), where the pod network is not a LAN. The page badges them "this node". `source` is a free string, so the OpenAPI shape is unchanged; the description gained the value.
5. **MAC identification across a router.** The query path identifies a client by MAC (`[[client]] mac`, `IdSource::NeighborMac`) from the kernel neighbor table only. A device behind a router has no entry of its own (the table shows the router's MAC for the router's address), so a MAC-keyed client never matched a routed device, although the UniFi leases know its MAC. The device identity (`identify.rs`) already fell back to the leases; the policy did not. **Changed:** the refresh task (off the query path, every few seconds, only while a client is MAC-keyed) now adds, for addresses the kernel table does not hold, the MAC from this node's router leases (the device's IPv4 and its reported IPv6 addresses; offline leases, empty and all-zero MACs are left out); the kernel's entry wins. The lookup on the query path is the same one `ArcSwap` load and hash lookup. This extends the router leases of ADR-125 to MAC matching and is an owner-visible behavior change: a MAC-keyed `[[client]]` now matches a device on another network when a `[[router]]` reports its lease on this node (the gap below says which nodes).

**Decision:**
1. **Routed is the default way** (each network's DHCP hands out the VIP; the gateway's firewall allows UDP and TCP 53 to it). Client IPs are kept because the gateway routes without NATing DNS; the DHCP must hand out the VIP and not the gateway, or the gateway's own forwarder is the only client TelltaleDNS sees (ADR-037's masked-client detector says so).
2. **Direct is documented and built, not required:** a tagged interface and a VRRP instance per VLAN; no default gateway on the VLAN interfaces; the same health check drives every instance, so a failing node gives up every VIP.
3. The four code changes above (3 to 5, with the e2e), each with tests; nothing on the DNS hot path.

**Gaps and conservative choices (for the owner):**
- A replica does not fill the MAC map from peer leases (ADR-125 carries names and MACs to replicas in `Names`, but the MAC map is built from this node's own `router_leases`). A MAC-keyed client therefore matches a routed device on the node that polls the router, and on a node that polls its own. Extending it to peer leases is a one-line change in the same task if the owner wants it; left out because a MAC from a peer's lease is a MAC the peer saw, one more thing a stale peer can get wrong.
- The Networks page counts devices from router leases and mDNS. A directly attached VLAN with no router shows 0 devices from the neighbor table, because the neighbor table is not the page's source (ADR-910: it feeds the inventory, which has its own page).
- Overlapping subnets on two directly attached interfaces are not supported.
- The e2e's second network is a second Docker bridge with one interface per network, which proves one interface and one VRRP instance per VLAN. It does not run 802.1Q tagging (that needs a switch or the kernel's `8021q` module on the host); the tagged-interface setup is documented from Debian's NetworkManager and has **not** been run on the test Pis, switch or gateway.

- **Review fixes:** the node lists no own network inside a container that is not on the host network (`/.dockerenv` or `/run/.containerenv` present, unless `TELLTALE_HOST_NETWORK` is set), since a bridged `eth0` is a container network. A failed neighbor-table read keeps the last good kernel entries and merges the leases into them. "This node" is the node answering the API.

**Alternatives rejected:** an untagged alias address per VLAN on the Pis' `eth0` (the measured failure); macvlan per VLAN in the example (ties it to one LAN); making the node read VLAN IDs from the switch (the node has no business talking to the switch); joining mDNS on every interface including containers (names of container addresses are not devices).

**Test plan:** `dns_001_groups_vlan_interfaces_and_vips`, `dns_001_prefix_from_netmask`, `dns_001_reads_the_real_interfaces` (telltale-net); `dns_001_wildcard_bind_answers_every_local_address_from_that_address`, `dns_001_tcp_wildcard_accepts_on_every_local_address`; `dns_001_mdns_joins_every_vlan_interface`; `api_013_a_node_on_several_networks_lists_each`, `api_013_vlan_config_parses_only_rows`; `flt_006_routed_devices_get_their_mac_from_router_leases`; Playwright `api_013 networks page lists router networks` (the this-node badge); `deploy/keepalived/e2e.sh` with the second network and VIP.

**Consequences:** a node on several networks hears mDNS on each, lists each, and matches MAC-keyed clients behind a router. No new dependency (`libc` is already in `telltale-net`), no image delta beyond a few hundred bytes of code.

