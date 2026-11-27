# Unbound parity: an audit of the recursive resolver (issue #114)

**Requirements:** DNS-011, DNS-012, DNS-022, UPS-012 (existing); reserved for the proposed tasks: DNS-902 to DNS-910, FLT-906, API-903 (M40 in `spec/10`). **Spec sections:** `spec/03` §4 (cache), §5 (DNSSEC), §6 (recursion). **Status:** audit only; no code changes. Written 2026-11-25 against `main` at `2a529f4f`.

## 1. What this is

Issue #114 asks for WrenDNS to replace NLnet Labs Unbound as a validating recursive resolver, for a home that runs Pi-hole with Unbound or Unbound alone. This page goes through Unbound's feature set, area by area, as `unbound.conf(5)` groups its options, and says for each item what WrenDNS does today, with the file that shows it, how large the gap is, and what to do.

**Method.** Every "WrenDNS today" cell was checked in the code or the spec, and cites the file. "Not found" means a search of `crates/` and `spec/` for the feature and its RFC number found nothing. The Unbound column describes Unbound's documented behaviour; where I am not sure of an Unbound detail (a default, or the release that added it), the cell says so rather than guess. No Unbound code was read (clean-room rule, AGENTS rule 6): only its public documentation and the RFCs.

**Where the resolver lives.**
- `crates/wrendns-recursor/src/lib.rs`: the iterative resolver: QNAME minimisation, referrals, CNAME chasing, hedging, priming, stub zones, limits.
- `crates/wrendns-recursor/src/net.rs`: one query to one authoritative server (UDP, TCP on truncation, 0x20).
- `crates/wrendns-recursor/src/msg.rs`: classifying a response (answer, referral, NODATA, NXDOMAIN, lame) and the bailiwick and glue rules.
- `crates/wrendns-recursor/src/cache.rs`: zone cuts, server-name addresses, per-server smoothed RTT.
- `crates/wrendns-upstream/src/dnssec.rs` and `nsec.rs`: DNSSEC validation (hickory-net's validating handle, `dnssec-ring` feature) and the RFC 8198 NSEC cache.
- `crates/wrendns-cache/`: the answer cache (wire format, S3-FIFO, serve-stale, prefetch signal, persistence).
- `crates/wrendns-net/`: client-facing listeners (UDP, TCP, DoT, DoH, DoH3, DoQ, PROXY v2).
- `crates/wrendns-config/src/schema.rs`: the configuration (`RecursiveConfig`, `CacheConfig`, `DnssecConfig`, `AccessConfig`, `RateLimitConfig`, `DnstapConfig`).

**Legend.** Gap: **0** none, **S** small (days), **M** medium (one to two weeks), **L** large. Recommendation: **parity** (nothing to do), **already better**, **build** (a task in §4), **will not do** (with the reason).

**A structural difference first.** Unbound is a resolver with a message cache and an RRset cache. WrenDNS is a filtering resolver whose recursive resolver is one upstream type (`url = "recursive://"`, UPS-012): final answers go to the server's answer cache, keyed per upstream view so groups don't share answers (`spec/03` §4), while the recursor keeps only zone cuts, server addresses and RTTs (`crates/wrendns-recursor/src/cache.rs`, module comment). Several Unbound options (filtering, local data, access control, views) therefore map to WrenDNS features outside the recursor, and the tables say where.

## 2. The audit

### 2.1 Iteration and hardening

| Feature | Unbound | WrenDNS today | Gap | Recommendation |
|---|---|---|---|---|
| QNAME minimisation (RFC 9156) | `qname-minimisation: yes` (default), relaxed; `qname-minimisation-strict` for strict mode | Relaxed mode, on by default, asked as `A`, at most 10 minimised steps (`MAX_MINIMIZE`), falls back to the full name on errors or NXDOMAIN (`crates/wrendns-recursor/src/lib.rs`, `lookup`; `RecursiveConfig::qname_minimization`) | 0 | parity for unsigned answers: keep the fallback to the full name after NXDOMAIN, as Unbound's relaxed mode and ADR-074 do, because some servers answer NXDOMAIN (with AA and SOA) for empty non-terminals; stopping early on a DNSSEC-proven NXDOMAIN is an ADR question in T40.1 (see the RFC 8020 row); no strict mode (will not do: it breaks broken zones for little gain) |
| 0x20 case randomisation | `use-caps-for-id` (off by default), `caps-whitelist` for servers that don't echo case | `case_randomization` (off by default); a reply with changed case is ignored while the real one is awaited; servers that never echo the case are remembered and asked plainly (`net.rs` `ask`/`udp`, `cache.rs` `no_case`) | 0 | already better: no per-server allowlist to maintain |
| Random source port and ID (RFC 5452) | `outgoing-port-permutation`, `outgoing-range` | A fresh socket bound to port 0 per query (the OS picks the port) and a random ID (`net.rs` `udp`, `ask`) | 0 | parity. The port's randomness is the kernel's ephemeral-port choice, not WrenDNS's own |
| Bailiwick of answer records | always on | Answer records accepted only at or under the zone being asked (`msg.rs` `chain`); negative evidence likewise (`negative`) | 0 | parity |
| `harden-glue` | yes (default): glue only in the referring zone's bailiwick | Glue used only for server names under the referring zone (`msg.rs` `classify`, "Glue only for server names the referring zone is authoritative for") | 0 | parity |
| `harden-referral-path` | off by default (documented as experimental); validates the referral path | Not found | S | will not do: Unbound itself leaves it off; DNSSEC covers the threat |
| `harden-dnssec-stripped` | yes: a zone that should be signed but answers unsigned is bogus | With `[dnssec] mode = "validate"`, the chain of trust is checked from the root; an answer with no RRSIG in a signed zone is bogus, with EDE 10 (`dnssec.rs` `bogus_reason`, `RRSIGS_MISSING`) | 0 | parity when validating (validation is off by default: `DnssecMode`) |
| `harden-below-nxdomain` (RFC 8020) | yes: names under a DNSSEC-proven NXDOMAIN are NXDOMAIN without asking | Partial. With validation on, the aggressive NSEC cache answers names under a proven NXDOMAIN when a covering range is cached (`nsec.rs`, and `nsec3.rs` for NSEC3-signed zones, T40.6). The recursor itself can't tell a proven NXDOMAIN from an unsigned one, because validation runs above it (`lib.rs` module docs), so a minimised NXDOMAIN always makes it ask the full name (`lib.rs`, "Relaxed mode: NXDOMAIN or anything odd"). For unsigned answers this matches Unbound, which applies the rule only to DNSSEC-proven NXDOMAIN | S | decide in T40.1's ADR: whether a minimised NXDOMAIN that the validator proves stops the walk, and how the validator's result reaches the recursor. An unsigned NXDOMAIN keeps the full-name fallback: some servers answer NXDOMAIN, with AA and SOA, for empty non-terminals (the breakage RFC 8020 and RFC 9156 describe), and stopping there would lose the names below them |
| `harden-algo-downgrade` | off by default: require every advertised algorithm | Depends on hickory-net; I did not find a setting for it, and hickory has a TODO about RRSIG stripping (`hickory-net` 0.26.3 `src/dnssec/mod.rs`) | S | will not do: Unbound's default is off too, and RFC 6840 §5.11 allows any one algorithm |
| `harden-large-queries`, `harden-short-bufsize` | off / yes | The client-side parser refuses bad packets (DNS-019, `spec/03` §2); the recursor always advertises 1232 (`net.rs` `wire_query`) | 0 | parity |
| `harden-unknown-additional`, `val-clean-additional` | yes / yes: drop unvouched additional records | The recursor's answer to the pipeline holds only the answer and authority sections; no additional section is ever passed on (`msg.rs` `encode`) | 0 | already better (nothing to clean) |
| `unwanted-reply-threshold` | 0 (off): count unwanted replies, flush caches past a threshold | Stray and spoofed replies are ignored while the real one is awaited (`net.rs` `udp`), but they are not counted | S | build (T40.3): count them as a metric; the cache-flush defence stays out (it is off by default in Unbound and flushing hurts more than it helps at home) |
| `do-not-query-localhost`, `do-not-query-address` | yes: never send queries to 127.0.0.0/8 and ::1; a list of more | **Not found.** Any address from glue or an NS lookup is queried, only IPv6 is filtered out when `ipv6 = false` (`lib.rs` `delegation`, `usable`). A public zone delegating to a loopback or private address makes WrenDNS send queries there | S | **build (T40.1), first**: refuse loopback, unspecified and link-local by default; private ranges configurable (allowed only inside stub zones by default) |
| `private-address`, `private-domain` (DNS rebinding) | strip private addresses from public answers | Response IP filtering (FLT-015, `spec/01`) blocks answers in configured networks | 0 | parity |
| Limits on work | `max-query-restarts`, `target-fetch-policy`, `max-sent-count` and similar (exact names vary by release) | 16 CNAME/DNAME hops, 32 referrals, 4 nested server-name lookups, 96 queries per question, at most 4 servers asked at each delegation step (`MAX_TRIES`, `lib.rs`) | 0 | parity |
| `outgoing-interface` | choose the source address of queries to authoritatives | `source` (UPS-013) works for `udp`, `tcp`, `tls`, `https` upstreams; the recursor binds the unspecified address (`net.rs` `udp`) | S | build (T40.2): honour `source` on `recursive://` |
| `do-ip4`, `do-ip6`, `prefer-ip6` | yes, yes, no | `ipv6` (off by default) adds the root's IPv6 addresses and allows IPv6 servers (`lib.rs` `Settings::with_ipv6`) | 0 | parity (no `prefer-ip6`: the RTT order decides) |
| Root hints | built in, or `root-hints` file | Built in (`ROOT_HINTS_V4`, `ROOT_HINTS_V6`) with RFC 8109 priming, renewed daily (`lib.rs` `prime`) | 0 | parity; a hints file is not offered. Will not do: priming keeps the hints current, and a private root can probably be given as a stub zone for `.` (not verified) |
| Server selection | RTT banding, infra cache (see §2.5) | Smoothed RTT, unknown servers tried in random order, hedging to the next server when one is slower than usual (`lib.rs` `ask`; `cache.rs` `order`) | 0 | already better on hedging (Unbound has no hedged queries as far as I know) |

### 2.2 DNSSEC

| Feature | Unbound | WrenDNS today | Gap | Recommendation |
|---|---|---|---|---|
| Validation (RFC 4033 to 4035) | `module-config: "validator iterator"` | `[dnssec] mode` is `off` (the default), `validate` or `validate_permissive`; for forwarded and recursive answers alike (`schema.rs` `DnssecMode`; `dnssec.rs`) | 0 | parity |
| `val-permissive-mode` | log bogus, serve anyway | `validate_permissive` (`DnssecMode`) | 0 | parity |
| Root trust anchors | `auto-trust-anchor-file` (RFC 5011), `trust-anchor-file`, `trust-anchor` | KSK-2017 and KSK-2024 built in; `trust_anchors_file` replaces them (DNSKEY records in zone-file form, Unbound's `root.key` accepted) (`dnssec.rs` `with_anchors_file`; `schema.rs` `DnssecConfig`) | 0 | parity for static anchors |
| RFC 5011 automated rollover | yes, with `add-holddown`, `del-holddown`, `keep-missing` | **Built (T40.5, DNS-906, ADR-1108; the box is open until its checks pass in CI).** It was not found when this audit was written; `spec/03` §5 lists it as P1; ADR-086 deferred it | M | **build (T40.5)**: the built-in anchors cover the next rollover only for a node that is updated; a node left alone for years needs 5011 |
| Trust anchors for other zones | `trust-anchor` for any zone | Only root anchors; the file is read as root keys (`with_anchors_file`) | S | will not do now: island-of-trust zones are rare at home; revisit with T40.5 |
| Negative trust anchors (RFC 7646) | `domain-insecure`, `unbound-control insecure_add` at run time | `negative_trust_anchors` and `dnssec_nta = true` on a route (`schema.rs` `DnssecConfig`, `Route`); `covers` checks the subtree (`dnssec.rs`); edited in the UI (`ui/src/lib/components/DnssecCard.svelte`) | 0 | parity (a change goes through the configuration, which applies without a restart) |
| Algorithms | whatever its crypto library offers (OpenSSL or Nettle; Ed448 with OpenSSL) | hickory-proto 0.26.3 `Algorithm::is_supported`: RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519. **No Ed448** (algorithm 16) | S | will not do until the crypto crate offers it: ring has no Ed448. A zone signed only with Ed448 should validate as insecure (RFC 6840 §5.2); I did not test what hickory does |
| NSEC3 iteration limits (RFC 9276) | `val-nsec3-keysize-iterations`; recent releases treat high counts as insecure (the exact threshold has changed across releases; not sure of the current one) | hickory defaults, not configured by WrenDNS: above 100 iterations insecure, above 500 bogus (`hickory-net` `src/dnssec/mod.rs`, `nsec3_iteration_limits`; WrenDNS calls `DnssecDnsHandle::with_trust_anchor` only, `dnssec.rs`) | S | build (T40.1): set the soft limit to RFC 9276's recommendation (insecure above 0 to 150; choose and record in the task's ADR) |
| Aggressive NSEC (RFC 8198) | `aggressive-nsec: yes` (default in recent releases) | NSEC and NSEC3 (T40.6, ADR-1105), per upstream group, on by default (`nsec.rs`, `nsec3.rs`; `aggressive_nsec`) | M | parity (built in T40.6) |
| `val-bogus-ttl` | 60 s | Bogus becomes SERVFAIL, cached for `servfail_ttl` (5 s by default, RFC 9520) and never served stale (`spec/03` §4) | 0 | parity (a shorter, configurable time) |
| Extended DNS errors for validation | yes (`ede: yes`) | EDE 6, 7, 8, 10 from the RRSIGs (`dnssec.rs` `bogus_reason`); EDE 3 on stale answers (`spec/03` §4) | 0 | parity |
| Trust anchor signalling (RFC 8145), root key sentinel (RFC 8509) | `trust-anchor-signaling: yes`, `root-key-sentinel: yes` | Not found | S | will not do: they serve measurement of the root rollover, not the home user; revisit if ICANN asks resolvers for them before the next rollover |
| `prefetch-key` | fetch DNSKEYs early when a validation needs them | Not found; hickory's validation cache holds proofs per group for their TTLs (`dnssec.rs` module comment) | S | will not do until measured: one DNSKEY miss per zone per TTL; measure the cost in T40.3's metrics first |
| `ignore-cd-flag`, CD handling | off | CD=1 returns unvalidated data and the cache key separates CD (`spec/03` §4, §5) | 0 | parity |

### 2.3 Cache

| Feature | Unbound | WrenDNS today | Gap | Recommendation |
|---|---|---|---|---|
| Message cache and RRset cache | `msg-cache-size`, `rrset-cache-size`, slabs | One wire-format message cache, sized in bytes and entries, 64 shards, S3-FIFO (`crates/wrendns-cache/src/lib.rs`; `CacheConfig::max_bytes`, `max_entries`); no RRset cache (an RRset learnt for one question is not reused for another type) | 0 | already better for hits (no re-encoding, `spec/03` §4); the missing RRset sharing is a deliberate trade, not a gap |
| `cache-min-ttl`, `cache-max-ttl` | 0, 86400 | `min_ttl`, `max_ttl` (`CacheConfig`) | 0 | parity |
| `cache-max-negative-ttl`, `cache-min-negative-ttl` | 3600, 0 | `negative_ttl_max` (`CacheConfig`); no minimum | 0 | parity (a minimum is not worth a setting) |
| Negative caching (RFC 2308) | yes | Yes, SOA MINIMUM honoured (DNS-006, `spec/03` §4) | 0 | parity |
| `serve-expired` (RFC 8767) | `serve-expired`, `serve-expired-ttl`, `serve-expired-reply-ttl`, `serve-expired-client-timeout` | `serve_stale`, `stale_max_age`, `stale_answer_ttl` (30 s), `stale_answer_client_timeout_ms` (1800 ms), EDE 3 (`CacheConfig`; DNS-007) | 0 | parity |
| `prefetch` | at 10% of TTL left | `prefetch`, `prefetch_threshold_pct` (10), `prefetch_min_hits` (3) (`CacheConfig`; DNS-008) | 0 | already better (hit threshold avoids refreshing one-off names) |
| Keeping the cache across a restart | `unbound-control dump_cache` and `load_cache`, by hand | `persist` writes `cache.bin` at shutdown and loads it at start (`crates/wrendns-cache/src/persist.rs`; DNS-009); cluster warm-up of hot names (`warm_names`, CLU-011) | 0 | already better (automatic) |
| Infrastructure caches across a restart | not kept as far as I know | Zone cuts and RTTs are memory only (`crates/wrendns-recursor/src/cache.rs`) | 0 | parity |
| In-flight deduplication | yes (mesh) | Singleflight keyed like the cache (`crates/wrendns-cache/src/singleflight.rs`) | 0 | parity |
| `cachedb` (Redis) | optional module | Not found | L | will not do: the cluster's warm-up covers the shared-cache use, and an external store conflicts with "DNS never depends on anything else" (AGENTS rule 5) |

### 2.4 Forwarding, stub and authoritative zones

| Feature | Unbound | WrenDNS today | Gap | Recommendation |
|---|---|---|---|---|
| `forward-zone` (with `forward-first`, `forward-tls-upstream`) | per zone | `[[route]]` to any upstream group (DNS-017), with UDP, TCP, DoT, DoH, DoH3, DoQ, DNSCrypt upstreams (`schema.rs` `Upstream`, `Route`); "forward first" is a `failover` group mixing a forwarder with `recursive://` | 0 | already better (more transports, health checks, strategies) |
| `stub-zone` | `stub-addr`, `stub-host`, `stub-prime`, `stub-first`, `stub-tls-upstream` | `stub_zone` and `stub_servers` on a `recursive://` upstream, routed with `[[route]]`; one zone per upstream; servers as IP addresses only (`schema.rs` `RecursiveConfig`; `lib.rs` `stub_for`; DNS-022) | S | will not do now: `stub-host` (names), `stub-prime` and `stub-first` have no request behind them; multiple zones work as multiple upstreams |
| `auth-zone` (serve or fetch a zone, `for-upstream`, `for-downstream`) | AXFR/HTTP fetch, ZONEMD | Local zones from a zone file or the configuration, per group (DNS-018, `schema.rs` `ZoneConfig`); no transfer in, no ZONEMD | M | build only as part of T40.8 (the root zone); public authoritative service is M34 (#30) |
| Local copy of the root zone (RFC 8806) | `auth-zone` for `.` with `for-upstream`, ZONEMD check (RFC 8976) | Not found | L | **build (T40.8)**, off by default: privacy (the root sees nothing) and a faster cold start |

### 2.5 The infrastructure cache and transport toward authoritative servers

| Feature | Unbound | WrenDNS today | Gap | Recommendation |
|---|---|---|---|---|
| Per-server RTT | `infra-host-ttl` (900 s), `infra-cache-numhosts`, RTT banding | Smoothed RTT (EWMA 0.3), timeouts counted as twice the timeout, kept with no lifetime; the whole table is cleared at 20,000 servers (`cache.rs` `record`) | S | build (T40.2): give entries a lifetime so a server that was down gets retried with a fresh estimate |
| Down servers and probing | `infra-keep-probing`, back-off on timeouts | A server that timed out sorts last until its average recovers; nothing probes it (`cache.rs` `order`) | S | build (T40.2) |
| Lameness | lame servers remembered per zone (`infra-lame-ttl` in older releases; not sure of current behaviour) | A lame answer moves to the next server but isn't remembered, and its RTT is recorded as a success first (`lib.rs` `try_server`: `record` before `classify`), so a fast lame server stays first | S | **build (T40.1)**: count lame answers as failures for that zone |
| EDNS fallback | detects servers that mishandle EDNS and retries without it | Every query carries EDNS with 1232 bytes (`net.rs` `wire_query`); FORMERR or NOTIMP is "lame" and moves on (`msg.rs` `classify`); if every server rejects EDNS the question fails | S | build (T40.2): one retry without EDNS, remembered per server |
| EDNS buffer size | `edns-buffer-size: 1232` | 1232 sent; 4096-byte receive buffer (`net.rs`) | 0 | parity |
| TCP on truncation | yes | Yes, with twice the timeout (`net.rs` `ask`, RFC 7766) | 0 | parity |
| TCP after repeated UDP timeouts | Unbound shrinks EDNS size and can fall back on fragmentation trouble; not sure it switches to TCP on timeouts alone | Not found | S | build (T40.2): after two UDP timeouts from a server that answered before, try TCP once |
| TCP connection reuse to authoritatives | `max-reuse-tcp-queries`, `tcp-reuse-timeout` | A new connection per truncated answer (`net.rs` `tcp`) | S | will not do now: truncation is rare at 1232 bytes; revisit if T40.3's metrics say otherwise |
| Encrypted queries to authoritatives (RFC 9539) | not sure it is implemented; Unbound has TLS toward forwarders (`tls-upstream`) | Not found (issue #114 says the same) | L | will not do now: few authoritative servers offer it; revisit after T40.7 |
| DNS cookies toward authoritatives (RFC 7873) | not sure current releases send client cookies | Not found: the recursor's EDNS has no cookie (`net.rs` `wire_query`, `EdnsOut` has only size, DO and EDE) | S | build (T40.7, client side) |
| Rate limits toward zones | `ratelimit`, `ratelimit-for-domain` | Not found; work per question is capped (96 queries) and clients are rate limited (DNS-014) | M | will not do: the per-client limit and per-question cap bound what one client can send; a home resolver is not an amplifier for random-subdomain floods at Unbound's scale |
| ECS toward authoritatives (RFC 7871) | `subnetcache` module, opt-in per zone | The recursor's own queries carry no ECS (`net.rs` `wire_query`); for forwarders, `ecs` is `strip`, a subnet, or `client` (DNS-015, `schema.rs` `Upstream::ecs`). I did not check whether `ecs` on a `recursive://` upstream is refused or ignored | S | will not do for recursion (WrenDNS never leaks ECS by default, DNS-015); T40.1 makes the configuration refuse `ecs` on `recursive://` if it doesn't already |

### 2.6 Local data, RPZ, access control and views

| Feature | Unbound | WrenDNS today | Gap | Recommendation |
|---|---|---|---|---|
| `local-data`, `local-data-ptr` | records; PTR on request | `[[record]]` (A, AAAA, CNAME, PTR, TXT, MX, SRV), wildcards, hosts files, `auto_ptr`; a local name with no record of the type is NODATA (`crates/wrendns-policy/src/local.rs`; DNS-010) | 0 | parity (no NS, CAA or arbitrary types in `[[record]]`; `[[zone]]` files take more) |
| `local-zone` `static` | NXDOMAIN or NODATA for names without data | `[[zone]]`: names it doesn't have get NXDOMAIN (`ZoneConfig`) | 0 | parity |
| `transparent`, `typetransparent` | local data, else resolve normally | `[[record]]` without a zone: names not local fall through (`local.rs` module comment); per type: NODATA for other types (so `typetransparent` has no direct match) | S | will not do: no request for it |
| `redirect` | the zone apex's data for every name below | A wildcard record answers names below but not the apex (`[[record]]` with `*.`); a rewrite (`[[rewrite]]` with `*.`, FLT-014) does the same | 0 | parity with two entries (apex and wildcard) |
| `refuse`, `deny`, `always_refuse`, `always_nxdomain`, `always_nodata`, `always_null`, `noview`, `inform`, `inform_deny` | per zone | Block rules with the group's `block_mode` (`null_ip`, `nxdomain`, `nodata`, `refused`, `custom_ip`; `schema.rs` `BlockMode`); per-rule rcodes via `$dnsrewrite` (`spec/05` §2); every query is logged (OBS-003). No silent drop (`deny`) | 0 | parity in a different shape |
| Default local zones (localhost, private reverse zones, `onion`, `test`, `invalid` and the others in RFC 6761 and 6303) | built in | Special names (DNS-019, `crates/wrendns-policy/src/special.rs`): `localhost`, `*.invalid`, private reverse zones, `resolver.arpa`, CHAOS refused, and more (`spec/03` §3 step 4). I did not compare the lists name by name | S | build (T40.10): compare with RFC 6761 and RFC 6303 and record the difference in the "Coming from Unbound" section |
| RPZ (response policy zones) | `rpz` module: QNAME, client IP, response IP, NSDNAME, NSIP triggers; zone files or AXFR | Not found: list formats are hosts, plain, wildcard, AdBlock and regex (`spec/05` §2) | M | **build (T40.9)**: RPZ files as a list source, QNAME triggers and the actions that map to WrenDNS's; response-IP triggers mapped to FLT-015 where they fit; NSDNAME and NSIP will not do (they need the recursor's path in the filter) |
| `access-control` | `allow`, `deny` (drop), `refuse`, `allow_snoop`, `allow_setrd`, `deny_non_local`, `refuse_non_local`, per netblock | `[access] allowed_networks`; others get REFUSED (`schema.rs` `AccessConfig`). No drop, no snoop. I did not check how RD=0 queries from clients are handled | S | will not do here: public listeners are T36.2 (DNS-901), which is where silent drop matters |
| Views, tags (`view:`, `access-control-view`, `define-tag`, `local-zone-tag`) | per client netblock | Client groups (FLT-005) chosen by address, MAC, client ID; per group: lists, upstream routes, split-horizon zones (`ZoneConfig::groups`), rewrites, DNS64 (`spec/03` §3) | 0 | already better (devices, not only netblocks) |
| Rate limiting of clients | `ip-ratelimit`, `ip-ratelimit-factor`, backoff | Token bucket per client, IPv4 and IPv6 prefix grouping, REFUSED or drop, exemptions (`schema.rs` `RateLimitConfig`; DNS-014) | 0 | parity |
| DNS64 (RFC 6147) | `dns64` module, `dns64-prefix`, `dns64-synthall`, `dns64-ignore-aaaa` | Per group: `dns64`, `dns64_prefix`, `dns64_exclude` (`schema.rs`; DNS-016) | 0 | parity |

### 2.7 EDNS options toward clients

| Feature | Unbound | WrenDNS today | Gap | Recommendation |
|---|---|---|---|---|
| DNS cookies, server side (RFC 7873, RFC 9018) | `answer-cookie` (added in a recent release; not sure which), `cookie-secret` | Parsed (`crates/wrendns-proto/src/edns.rs` `cookie`), never answered: `.cookie()` is used only in a test | M | **build (T40.7)**: RFC 9018 server cookies with a secret shared by the cluster, so any node accepts a cookie another issued; on the query path, so a benchmark is required |
| Padding (RFC 7830, RFC 8467) | `pad-responses`, `pad-queries` (for TLS) | Not found (`opt::PADDING` is defined in `crates/wrendns-proto/src/consts.rs` and used nowhere) | S | build (T40.7): pad answers on DoT, DoH, DoH3 and DoQ to clients that pad; pad queries to `tls://` and `https://` upstreams |
| NSID (RFC 5001) | `nsid` | `[dns] nsid` (DNS-021, `schema.rs` `DnsConfig`) | 0 | parity |
| Extended DNS errors (RFC 8914) | `ede`, `ede-serve-expired` | Blocked, stale, failed and bogus answers (DNS-013; `spec/03` §7) | 0 | already better (names the list and rule that blocked) |
| TCP keepalive (RFC 7828) | `edns-tcp-keepalive` | Not found; TCP idle timeout is 10 s (`crates/wrendns-net/src/tcp.rs`) | S | build (T40.7) |
| `hide-identity`, `hide-version`, `identity`, `version` | answer or hide `id.server` and `version.bind` | CHAOS class refused (`refuse_chaos`, on by default; `crates/wrendns-policy/src/special.rs`); NSID names the node when asked | 0 | parity |

### 2.8 Transports toward clients

| Feature | Unbound | WrenDNS today | Gap | Recommendation |
|---|---|---|---|---|
| UDP and TCP with pipelining (RFC 7766) | yes | Yes: up to 64 queries in flight per connection, out-of-order answers, idle timeout, connection caps per listener and per address (`crates/wrendns-net/src/tcp.rs`) | 0 | parity |
| DoT (RFC 7858) | `tls-service-key`, `tls-port` | `proto = "dot"`, certificates reloaded on change (DNS-002, `schema.rs` `Listener`) | 0 | parity |
| DoH (RFC 8484) | `https-port`, HTTP/2 | HTTP/2 and HTTP/3, GET and POST, client IDs in the path (DNS-003, DNS-004; `crates/wrendns-net/src/doh.rs`, `doh3.rs`) | 0 | already better (HTTP/3) |
| DoQ (RFC 9250) | added in a recent release (not sure which) | `proto = "doq"` (DNS-004; `crates/wrendns-net/src/doq.rs`) | 0 | parity |
| PROXY protocol v2 | `proxy-protocol-port` | `proxy_protocol` on TCP-based listeners (DNS-020; `crates/wrendns-net/src/proxy.rs`) | 0 | parity (WrenDNS does not take it on UDP) |
| `interface-automatic` | answer from the address asked | `IP_PKTINFO`/`IPV6_RECVPKTINFO` on wildcard binds (`spec/03` §1) | 0 | parity |

### 2.9 Operations: remote control, statistics, dnstap, modules

| Feature | Unbound | WrenDNS today | Gap | Recommendation |
|---|---|---|---|---|
| Remote control (`unbound-control`) | `reload`, `stats`, `flush`, `flush_zone`, `flush_type`, `flush_bogus`, `flush_negative`, `flush_infra`, `dump_cache`, `load_cache`, `lookup`, `list_forwards`, `list_stubs`, `list_local_zones`, `insecure_add`, `forward_add`, `local_data` and more | `wrendns ctl` over the API: `flush` by name or subtree, `explain`, `upstreams`, `lists`, `simulate`, and raw `get`/`post`/`put`/`delete` (`crates/wrendns/src/ctl.rs`); `POST /api/v1/cache/flush`, `GET /api/v1/cache/lookup`, `GET /api/v1/cache/entries` (`crates/wrendns-api/src/cache_api.rs`); the configuration API covers forwards, stubs, local data and NTAs | M | build (T40.4): flush by type, flush negative or bogus answers, flush the recursor's zone cuts and RTTs, and a lookup trace (below); on-demand dump and load will not do (persistence is automatic) |
| Lookup tracing (`unbound-control lookup`, `verbosity`) | shows the delegation point and servers | Explain (FLT-013) explains the filter's decision; nothing shows the recursor's path (zone cuts, servers asked, their answers) | M | **build (T40.3)**: a trace in Explain ("Why?"), the API, `wrendns ctl` and MCP |
| Statistics (`extended-statistics`) | per-thread counters, histograms, RRset and message cache counts, validation counts | `/metrics`, OTLP, per-upstream latency, cache and DNSSEC counters (OBS-004, OBS-005; `dnssec.rs` `Stats`). Inside the recursor only `cached_zones()` exists, and nothing outside the crate reads it | S | build (T40.3): queries to authoritatives, timeouts, lame answers, case mismatches, unwanted replies, cuts cached |
| dnstap | client, resolver and forwarder messages | `CLIENT_QUERY`/`CLIENT_RESPONSE`, and with `forwarder = true` `FORWARDER_QUERY`/`FORWARDER_RESPONSE` (`crates/wrendns/src/dnstap.rs`); no `RESOLVER_QUERY`/`RESOLVER_RESPONSE` for recursion | S | build (T40.3) |
| Python and dynamic-library modules, `ipsecmod`, `ipset` | optional modules | `exec://` and `unix://` plugin upstreams (UPS-011); no in-pipeline scripting; no ipset | L | will not do: scripting on the query path conflicts with the hot-path rule (AGENTS rule 4) and the plugin upstreams cover custom resolution; ipset is a firewall's job |
| Configuration importer | n/a | Pi-hole and Technitium importers (API-007; `crates/wrendns/src/pihole_import.rs`, `technitium.rs`); none for `unbound.conf`. `docs/running.md` still says "a built-in recursive resolver is on the post-1.0 list" in the Pi-hole import section, which is out of date | M | **build (T40.10)**: an `unbound.conf` importer and the "Coming from Unbound" section of `docs/running.md` (issue #114's "done when") |

### 2.10 Settings without a UI control (a rule gap found on the way)

The recursive upstream's own options, `qname_minimization`, `case_randomization` and `ipv6` (`schema.rs` `RecursiveConfig`), have no field in the Upstreams page's form (`ui/src/pages/Upstreams.svelte`, `upstreamFields`: address, TLS server name, source, timeout). Stub zones have one (`ui/src/pages/LocalDns.svelte`). The owner's rule (API-901) says every setting ships with a UI control; this is a pre-existing gap and becomes part of T40.1, since that task adds settings to the same section.

## 3. What WrenDNS already does better

- **Hedged queries** to a second server when the first is slow (`lib.rs` `ask`).
- **0x20 without an allowlist**: servers that don't echo the case are found and remembered (`net.rs`, `cache.rs`).
- **Cache persistence** across restarts and **cluster warm-up**, automatic (DNS-009, CLU-011).
- **Prefetch with a hit threshold** (DNS-008).
- **Per-device policy** instead of netblock views, and **filtering** built in, with EDE naming the rule (FLT-005, DNS-013).
- **More client transports**: DoH over HTTP/3, and every listener behind PROXY v2 on TCP (DNS-004, DNS-020).
- **More forwarder transports** and health-checked groups mixing recursion with forwarders (UPS-001 to UPS-012).
- **No additional section** passed from authoritative answers, so nothing to clean (`msg.rs` `encode`).

## 4. Proposed tasks, in order

The order follows the owner's priorities (performance, then observability, then breadth) and puts the two safety fixes first. Each task lists its reserved requirement ID; the rows go into `spec/01` when the task starts. Every task that adds a setting, route or tool ships its UI control, help topic and Playwright test (API-901), and every task that touches the recursor or the query path adds a test against a local authoritative fixture (`crates/wrendns-recursor/tests/recursor.rs`) and a `make bench-smoke` run.

1. **T40.1 Recursor hardening** (DNS-902; S). No queries to loopback, unspecified or link-local addresses (private ranges only inside stub zones unless allowed); lame answers counted as failures for the zone; whether a DNSSEC-proven NXDOMAIN to a minimised query is final (RFC 8020) decided in the task's ADR, with an unsigned NXDOMAIN still followed by the full name; NSEC3 iteration limits set per RFC 9276; `ecs` refused on `recursive://`; UI fields for `qname_minimization`, `case_randomization`, `ipv6` and the new settings.
2. **T40.2 Infrastructure cache and transport fallbacks** (DNS-903; S to M). RTT entries with a lifetime and probing of servers that were down; one retry without EDNS on FORMERR or NOTIMP, remembered per server; TCP after repeated UDP timeouts; `source` honoured on `recursive://`.
3. **T40.3 Seeing the recursor** (DNS-904; M). Metrics inside the recursor (queries to authoritatives, timeouts, lame, case mismatches, unwanted replies, cuts cached); dnstap `RESOLVER_QUERY`/`RESOLVER_RESPONSE`; a lookup trace (zone cuts, servers asked, outcomes) in Explain, the API, `wrendns ctl` and MCP.
4. **T40.4 Cache and recursor controls** (DNS-905; S). Flush by type, flush negative or bogus answers, flush the recursor's zone cuts and RTTs; through the API, `wrendns ctl`, MCP and the Cache page.
5. **T40.5 RFC 5011 trust anchor rollover** (DNS-906; M). Follow root key changes with hold-down timers and the revoke bit, state in the data directory, a health reason when the anchors change or a hold-down is running, the anchors and their states on the DNSSEC card; built-in anchors remain the starting point; a file anchor disables it.
6. **T40.6 Aggressive NSEC3** (DNS-907; M). NSEC3 ranges in the RFC 8198 cache (ADR-092's "later").
7. **T40.7 Cookies, padding and keepalive** (DNS-908; M). RFC 9018 server cookies with a cluster-shared secret, client cookies from the recursor; RFC 8467 padding on encrypted listeners and toward encrypted upstreams; RFC 7828 keepalive on TCP and DoT.
8. **T40.8 A local copy of the root zone** (DNS-909; L). RFC 8806 with ZONEMD (RFC 8976), fetched and refreshed by SOA, off by default, falling back to normal recursion when the copy is missing or fails its check.
9. **T40.9 RPZ as a list source** (FLT-906; M). RPZ zone files from a file or URL, QNAME triggers with NXDOMAIN, NODATA, PASSTHRU, DROP and local CNAME actions mapped to WrenDNS's; response-IP triggers mapped to FLT-015 where they fit; NSDNAME and NSIP triggers counted as unsupported.
10. **T40.10 Coming from Unbound** (API-903, DNS-910; M). An `unbound.conf` importer (sandboxed like the Pi-hole importer) that maps forward and stub zones, local zones and data, `domain-insecure`, trust anchor files, cache TTLs, prefetch, serve-expired, QNAME minimisation, `use-caps-for-id`, `do-ip6`, `private-address` and access control, and reports every option it can't map; the "Coming from Unbound" section of `docs/running.md` with the option-by-option table from this audit; the special-name list compared with RFC 6761 and RFC 6303; the out-of-date "post-1.0" line in the Pi-hole import section fixed.
11. **T40.11 DNSSEC validation on by default for `recursive://`** (DNS-011, DNS-012; S). Owner decision 2026-11-25, planned after T40.1 and T40.5: validation on by default for recursive upstreams, with an ADR, an upgrade note in the release notes and a UI indication; an explicit `mode` in an existing configuration wins.

**Recorded as not wanted** (reasons in the tables): strict QNAME minimisation, `harden-referral-path`, `harden-algo-downgrade`, Ed448 (until ring has it), RFC 8145 and RFC 8509 signalling, `prefetch-key` (until measured), trust anchors for zones other than the root, `cachedb`, `stub-host`/`stub-prime`/`stub-first`, TCP connection reuse toward authoritatives (until measured), RFC 9539 (for now), outbound per-zone rate limits, ECS in recursion, `typetransparent`, access-control drop and snoop (T36.2's scope), Python and dynamic modules, ipset, a root hints file.

## 5. Open questions for the owner

- 0x20 case randomisation: `case_randomization` keeps Unbound's default (off) unless the owner decides otherwise. WrenDNS already copes with servers that don't echo the case, so this is a choice, not a risk.
- Decided 2026-11-25 (owner): DNSSEC validation becomes the default for `recursive://` upstreams, as a planned task after the hardening and DNSSEC work, not now. It is T40.11 in `spec/10` (prerequisites T40.1 and T40.5): an ADR, an upgrade note in the release notes and a UI indication. Until it lands, validation stays off by default (`spec/03` §5).
- T40.8 fetches the root zone: from the root servers that allow AXFR, or over HTTPS from IANA? The task's ADR decides; both are public.
