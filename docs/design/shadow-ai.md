# Shadow AI detection (M37) — design

Status: design only (T37.1, cloud #4). ADR-1055 to ADR-1059 **Accepted 2026-11-19** with the owner's decisions (below); ADR-1060 (the node side) Accepted 2026-11-19 and amended the same day per the owner decisions on cloud writes (third round, below): Block and Allow are signed policy changes, replacing the subscribed cloud lists. Revised again 2026-11-19 after the security review of the cloud-write design: the node itself enforces the class map's scope rules (tenant `*`, the protected-parent denylist, a hold on large additions), revocation drops what a compromised content key signed, and policy changes are signed on the node's own page (hosted.md, ADR-1060 to ADR-1062). No code is written by T37.1. Revised 2026-11-19 for the owner's decision that **Shadow AI is a commercial feature of WrenDNS Cloud, shipped hosted-only** (ADR-1052's proprietary service). Requirement IDs are reserved now so test names can trace from the first task: in the open node, **OBS-904** the name-class counters export and **FLT-903** class rules over a content-signed class map; in the service, **CLD-906** detection and findings, **CLD-907** the alert and the digest, **CLD-908** the catalog, **CLD-909** AI policy and its lists; **FLT-904** stays reserved for Warn, a later phase. (Free on every branch on 2026-11-19; recheck when the rows are written.)

Shadow AI is the use of AI services that the network's owner hasn't approved. This feature shows which devices, and through the CMDB which people, reach which AI services, and lets the owner allow, monitor or block them per group. DNS is a good vantage point because every AI service starts with a lookup, and WrenDNS already knows the device, its group, the time and the device's identity. It is also a limited one: DNS tells you *which known service* a device reached and roughly *when and how much*, not *what was typed*, and for most vendors not *which account*. The design says so wherever a user could otherwise assume coverage it doesn't have.

**Where it runs.** Everything that is Shadow AI (the catalog, detection, confidence, findings, policy, the pages, alerts, the digest and its API) runs in WrenDNS Cloud, in the service's separate repository (ADR-1052 §2). The open AGPL node gains two small, generic, documented pieces that know nothing about AI and are useful for other hosted analytics too: a **name-class counters export** (per device, per opaque class number, 5-minute activity bitmaps, sent over the existing outbound tunnel, ADR-1047) and **class rules** (per group, block or allow the names of opaque class numbers in a **class map** that MySummitKeep signs with its content key and delivers over the platform channel, ADR-1062). Enforcement reaches the node as ordinary group policy: a Block or Allow set in the portal is a **signed policy change**, confirmed with the editor's change-signing passkey and verified, authorized and applied on the node like every cloud change (ADR-1060, ADR-1061, ADR-1063). There is no subscription to make on the node. A self-hosted node without the cloud keeps everything it has today, including the free `ai` category and the nine `presets/services/ai.toml` services; it gets no Shadow AI.

"Shadow" already means something in WrenDNS: a list in **shadow mode** (`ListMode::Shadow`, OBS-018) is compiled and counted but never blocks. The node has no Shadow AI screen, so the two never appear side by side; in the cloud the watch-only policy is called **Monitor**, and the help topic says it is unrelated to the node's shadow-mode lists.

## Owner decisions (2026-11-19)

Final. They replace the list of open decisions in the first draft, and ADR-1055 to ADR-1059 record them.

1. **Catalog:** in-house, written from vendor documentation (ADR-1055). It lives in the service's private repository, not in this one.
2. **Commercial and hosted-only:** detection, policy evaluation, findings, reports and the catalog live in WrenDNS Cloud and are computed from data the node sends. The open node gains only a generic, documented telemetry export over the tunnel, with no Shadow AI logic or catalog, and enforcement comes back as ordinary group policy through the existing configuration path (since the third round: as changes signed by the editor, ADR-1060 point 3). It needs WrenDNS Cloud. The cloud's evidence store **amends ADR-1052 §3** (below, ADR-1059). The "catalog subscription" and "delayed open" packaging of the first draft is removed.
3. **Default on new installs:** off until an admin turns it on and acknowledges a monitoring notice; then every group starts at Monitor (ADR-1058).
4. **Privacy level 1:** full per-device findings, matched before hashing, after an extra acknowledgement; the level-1 description, the docs and the privacy notes say that Shadow AI findings are an exception. Level 2 and above: off (ADR-1058; amends ADR-102 for this export).
5. **When a device "used" a service:** a use-role hostname in at least 2 active 5-minute periods or on 2 days, on merged evidence, or endpoint-agent confirmation; built-in assistants shown as "OS assistant present"; the ambient-hostname lab before the first release, with the owner's own devices only with a go-ahead (ADR-1056).
6. **Risk information:** vendor-stated facts, dated and linked; no score (ADR-1055).
7. **Approved tenants:** only where the vendor's hostnames split them; elsewhere the product says so plainly (ADR-1057).
8. **Default alert:** every first use per device (each device's first likely use of each unapproved service), quiet for the first day after a fresh start, with first-seen kept by the cloud, plus rate limiting and grouping so a new install doesn't flood (ADR-1056, "The alert").
9. **Minors:** the operator's responsibility; not marketed for children; parents pointed to categories and groups (ADR-1058).
10. **No Warn in v1:** the modes are Off, Allow, Monitor and Block; Warn is a later phase (ADR-1057, "Later: Warn").

## Goals and non-goals

### Goals

1. **Know what is in use.** For each group and device: which AI services, of which kind, first and last use, active time per day, and whether it looks interactive or automated, with the evidence behind every statement.
2. **Govern it per group.** Allow, Monitor or Block per kind of service, with per-service overrides, per-device exceptions on the node and approved tenants where the vendor's hostnames make that possible.
3. **Be honest about what DNS cannot see.** Every page and report says what is not visible: tenants that share hostnames, AI inside other SaaS, devices bypassing the network's DNS, and periods when the cloud received no data. An empty page must never read as "no AI use".
4. **Cost nothing on the query path, and nothing on a node that doesn't use it.** The export runs on the telemetry thread; blocking is ordinary list membership. With the export off nothing is built or registered, and the idle memory gate (ADR-1031, 32 MiB) is untouched.
5. **DNS never depends on the cloud** (AGENTS rule 5, CLU-004). A cloud outage, a cancelled subscription or a lost tunnel never changes a DNS answer by itself.
6. **Respect privacy and the law.** Off until an admin turns it on and acknowledges a monitoring notice; only names in the tenant's class map leave the node, as numbers; no content, prompts or filenames ever; exclusions honoured.
7. **Agent-ready.** The service's API is agent-ready (AGT-001..005) with read tools for agents; policy changes by agents are plans a human applies (ADR-994 §8).

### Non-goals

- **No Shadow AI logic or catalog in the open node.** The export and class rules are generic. The only Shadow AI wording on the node is what owner decision 4 requires: the level-1 privacy description, the level-1 acknowledgement and the docs' privacy notes, which say what WrenDNS Cloud's Shadow AI does with the export.
- **No query log in the cloud.** Names outside the tenant's class map never leave the node; nothing finer than a 5-minute period is sent.
- **No TLS inspection, no proxy, no header injection.** OpenAI's and Anthropic's tenant restrictions need a proxy that adds headers after decrypting traffic. WrenDNS does not decrypt and will not start.
- **No content inspection.** No prompts, responses, file contents or filenames, from DNS or from the endpoint agent.
- **No probing.** Local LLM servers are found passively or from imported scans only (ADR-907).
- **No risk score.** Vendor-stated, dated, linked facts only (ADR-1055).
- **No third-party categorisation feed**, open or commercial (ADR-1055).
- **The cloud never writes a node's configuration on its own.** A Block or Allow reaches the node only as a change signed by an editor's passkey and checked against the editor's node role (ADR-1061, ADR-1063); catalog content signed by the content key can change which names a class holds, never which classes a group blocks or allows (ADR-1060 point 3).
- **No Warn in v1.**
- **No ECH stripping and no RDATA rewriting** (see the threat model).
- **Not marketed for monitoring children** (owner decision 9).

## User stories

1. **A household.** An adult runs a two-node cluster at home, linked to WrenDNS Cloud with the Shadow AI add-on. In the portal they turn Shadow AI on and acknowledge the notice; at home, on the node's own UI on the LAN, they turn on the export (admin work that ADR-1049 point 3 keeps off hosted names by default) and check that cloud sync is on with class rules allowed (M36). Every group starts at Monitor. After a week the portal shows: "study-laptop (192.0.2.21) used Example Chat on 5 days, about 3 h in all. Likely." and "living-room-speaker (192.0.2.40) reaches Example Voice AI. OS assistant present." They set Adults to Allow for the assistant they chose and Block for the rest of the chat kind, and confirm with their signing passkey; within seconds the change is Applied on the node, the Adults group's class rules block those names, and the portal shows Accepted once every node has it. Their phones show "Private Relay: opted out by this network" (the default special-names switch), so they stay fully visible; a visitor's laptop with its own DoH resolver set by IP shows "partial: query rate dropped", so its absence from the page proves nothing.
2. **A small business.** An office of 25 staff on Business, with an approved coding assistant on a business plan whose hosts are separate from the personal plan's, and the company's own cloud model resource. The owner sets the Staff group to Monitor for chat assistants, Allow for the approved coding plan and the company's model resource, and Block for personal coding plans. Each first likely use of an unapproved service by a staff laptop alerts once, grouped: "3 devices in Staff used Example Chat for the first time: laptop-07, laptop-12, phone-03. Likely." The weekly digest lists the services used, new ones first. The page says plainly that WrenDNS can't tell the company's chat workspace from a personal account on services whose hostnames are shared.
3. **A managed-service provider.** An MSP runs WrenDNS at a dozen client sites, each site a cluster in the MSP's Business tenant. The portal's cross-site view lists services in use per site and group, new services this week and visibility gaps; per-device detail stays per site and needs the site's Shadow AI permission. They have an agent draft each client's monthly review through the service's read tools; any policy change it proposes waits as a plan for a human. (A reseller model spanning several customers' own tenants is an open question.)

## Architecture

```
 LAN devices ──DNS──▶ node (AGPL) ───────────────────────────────▶ answers (never wait for the cloud)
                       │ telemetry thread: name-class counters
                       │   (class map = opaque numbers, from the cloud)
                       ▼
                 primary: OR-merge members' bitmaps, bounded buffer
                       │  up the tunnel (ADR-1047): export batches,
                       │  requests for the class map
                       ▼
                 WrenDNS Cloud (proprietary, separate repository)
                   catalog ─▶ class map, signed by the content key
                   ingest ─▶ evidence store ─▶ findings, first-seen
                   policy ─▶ alert, digest, portal pages, API
                       │  platform channel: the signed class map the node
                       │  asked for, its version in heartbeat acks;
                       │  user channel: Block and Allow as changes signed
                       │  by the editor's passkey (ADR-1061)
                       ▼
                 node: class rules compiled into the snapshot like any list
```

### What the node sends (ADR-1060)

The **name-class counters export** (OBS-904) is a node feature in `[cloud.export]`, off by default, admin-only and guarded (ADR-1047 point 4), with a UI card under Settings → WrenDNS Cloud that shows exactly what is sent, including a "show the last batch" view. It knows nothing about AI. Its inputs are the drained `QueryEvent`s on the telemetry thread and a **class map** the node requested and verified against the content key (scope `class_map`, ADR-1062; the same map for every tenant, its hash published per `catalog_version`): a list of name patterns (exact names and `||name^` subtrees only, no regex) each mapped to an opaque `u16` class number, each class with up to 4 opaque `u8` tags (the cloud uses them for kinds), with no names of services, kinds, vendors or anything else. A tenant's own local entries are not in it: they arrive as `class_local` entries, signed changes like any policy. The node compiles the map into a small FST (reversed name to class number), the same structure as the snapshot's, and matches each event's name once (a suffix match: up to one probe per label, typically 2 to 4).

Per (device, class, UTC day) it keeps:

- a **288-bit day bitmap** (36 B, one bit per 5-minute period with at least one lookup);
- the lookup count (saturating `u16`) and how many of those lookups the node blocked;
- **rhythm bins**: 8 counters of the gap between lookups, on the anomaly engine's edges (`RHYTHM_EDGES_MS`), so the cloud can tell steady machine traffic from human bursts.

For each device with at least one class-map match in the last 7 days (and no other device) it also sends a **directory entry** (only when it changes): an opaque **device pseudonym** (a keyed hash of the node's stable device key, the CMDB CI id, else the MAC, else the address; the key stays on the node, so the cloud never learns MACs), the display name, the group, the device class and OS family from identification, identity certainty (address only, randomised MAC as flagged by the inventory, ADR-910, or a shared address), the CMDB `owner` when one is set by hand, and the device's current LAN address if it is private (RFC 1918 or ULA; the latest value only, overwritten, never a history; a public or relay-reported address is never sent). For the same devices only, a **quiet-while-present span** when one starts and ends: the node itself sees that the device is still present (a lease renewal, a neighbour-table entry or an inventory sighting) while its lookups have fallen below 10% of its own 7-day median for that hour for at least 2 hours, and sends the span's start and end, rounded to 5 minutes, with the bypass sign if one was seen (a DoH bootstrap name, or the canary or Private Relay names with their switch off). No hourly lookup counts and no presence timeline leave the node: an hourly presence record of every device would be a location history of the household, which ADR-1052 rejected. Per batch: the node's `[special]` switch states (`block_firefox_canary`, `block_icloud_private_relay`) and the privacy level.

**Bounded.** At most 4,096 (device, class) pairs in memory (about 80 B each, about 0.33 MiB), at most 64 classes per device and 1,024 devices per class; a device past its cap counts the rest as "more classes, not tracked", and pairs already sent are evicted first. The class map is capped at 12,000 patterns and 2,000 classes; the node refuses a larger map, a map whose content envelope names any tenant but `*` (so "one map for everyone" is checked on the node, not promised by the cloud), a pattern on a public suffix (the Public Suffix List including its private section), a subtree under a protected parent or a shared-infrastructure domain (the validator's denylist, which the node ships as generic data), and anything but exact names and subtrees, and keeps the last good map. A version that adds more than 1,000 patterns to the map the node holds is held for 72 hours with a notice, unless an admin releases or refuses it sooner (ADR-1062 point 3).

**In a cluster.** Clients usually get both resolvers by DHCP and split their lookups, and Kubernetes runs several resolver pods, so one node's view of a device is partial. The primary pulls each member's changed bitmaps, resolver pods included, on the export interval through the federated read (ADR-053), OR-merges them (the same period seen by two nodes counts once) and sends one batch for the cluster. The cloud also OR-merges on arrival, so a batch sent twice, or a failover that resends, counts once. An emergency (publish-nothing) primary (ADR-048) keeps collecting and sends nothing until a normal primary is back.

**What the privacy level does** (owner decision 4, ADR-1058):

| Level | What the export does |
|---|---|
| 0 | as above |
| 1 | the same, **matched before the name is hashed** (catalog classes only; tenant-defined patterns stay hashed and unmatched), with clear device names, after an extra acknowledgement on the node. This is the one exception to "level 1 hashes every name kept or shown" (ADR-102); the level-1 description in the UI and the docs and the privacy notes say "Shadow AI findings are an exception" |
| 2 and 3 | off: the export refuses to turn on and stops if the level is raised; the cloud page says "Shadow AI needs privacy level 0 or 1" |

**Changing the level while the export is on.** Lowering 1 to 0 changes nothing that is sent. Raising 0 to 1 pauses the export (nothing sent, nothing counted) until an admin gives the level-1 acknowledgement. Raising to 2 or 3 stops it at once and discards the unsent tracker and buffer; the portal says "the export stopped: privacy level raised on <cluster>", keeps what it already holds only to its retention, and offers "Purge this cluster's Shadow AI data" (as the node's own logs are not rewritten when the level rises, ADR-102).

**Groups and devices that leave nothing.** `[exclusions]` drops an event before every sink, the export included. `[exclusions.log]` keeps events out of the query log and the event sinks (OBS-903); the export is an off-node per-device record like an event sink, so it honours `[exclusions.log]` too (counts on the node's own dashboard are unaffected). The export also has `groups` (default: all), set on the node; and the cloud's reply to a batch may name groups to omit (a group on Off, or every group when Shadow AI is off), which the node honours from the next interval. That reply can only narrow what is sent, never widen it. The node never sends a name that is not in the class map, never a time finer than a 5-minute period, and never an answer.

### Policy on the node: class rules over the signed class map (ADR-1060)

A **class rule** (FLT-903) is an ordinary, generic group setting: `{group, action: block | allow, classes: [u16], tags: [u8]}` (tags in block rules only). For each group the node compiles a **block set**, the patterns of the named classes and tags from the class map plus the group's `class_local` entries, and an **allow set**, only the exact names of the named classes: a subtree in an allowed class is ignored and reported, and a name that a security or threat list blocks is dropped and reported ("allow ignored: on a threat list"), so an Allow can never open a hole past a security list. Both are compiled into the snapshot like lists, so replicas and resolver pods enforce them without receiving content (ADR-994 point 10). The Lists page shows them as "class rules of <group>", with the class map's version and the diff of each change; Explain names the class rule and its signer.

**How a Block or Allow reaches the node.** The portal compiles a group's modes into the classes and tags to block and the classes to allow, and shows the editor the change in words ("Block Example Chat and 11 other chat services for Adults; allow Example Assistant"). The editor confirms on the node's own signing page, which shows the class-rule change as the node reads it (hosted.md, "Where a change is signed"), and the change is verified, merged and applied on the primary like every cloud change (ADR-1061, ADR-1063), under the editor's node role. It needs `[cloud.sync]` on, with `class_rule` and `class_local` in its allowlist (turned on once, at home); there is no per-group subscription. A Git-managed cluster gets the TOML lines to commit instead.

**What content can and cannot do.** The class map is platform content: a new `catalog_version` can add a hostname to a class, or a new service to a kind's tag, so a group that blocks a kind keeps blocking it as the catalog grows. It can never change which classes or tags a group blocks or allows, and Allow names classes only, never tags, so content can widen a Block but never an Allow. The map's caps, the refusal of public suffixes and protected parents, the tenant `*` rule, the hold on large additions, the diffs on the node and the published hash of each `catalog_version` apply, all enforced on the node. Platform-signed lists are never accepted as allow sources. If the content key is revoked as compromised, the node drops every map it signed after the manifest's `compromised_after` time and returns to the last map signed by a valid key (ADR-1062 point 2); this is the one case in which the freeze rule gives way.

### Latency

| Path | Typical | Bound |
|---|---|---|
| A lookup to the cloud | the export interval: every 5 minutes, plus up to 60 s of jitter | the buffer's catch-up after an outage |
| First lookup to a Likely finding | about 5 to 15 minutes after the **second** active period (the use rule needs two); on the second day for use on two days | as above |
| Finding to alert | the next evaluation, every 5 minutes, then the grouping window (up to 15 minutes, "The alert") | rate limits |
| A Block in the portal to the node's answer | a few seconds after the editor signs: delivery over the tunnel, the merge, the snapshot compile | queued as Pending while home is offline, until the change's expiry; the cloud resolver can take it at once with "Apply to roaming now" (ADR-1064) |
| A catalog change to the node's class map | about 20 to 60 s: the next heartbeat acknowledgement, the signed map fetched and verified, the compile | the hourly poll while heartbeats fail |
| Digest | weekly, at the tenant's hour | — |

### Offline behaviour (DNS never depends on the cloud)

| Event | DNS | Export | Policy | What is shown |
|---|---|---|---|---|
| Tunnel or cloud down | unaffected | batches wait on the primary, at most 7 days or 4 MiB on disk, oldest dropped first | class rules keep working on the last good class map; portal changes queue as Pending with their expiry | node: `cloud_unreachable` (degraded, existing). Cloud: "no data from <cluster> since <time>"; findings in that window say "evidence incomplete" |
| Data arrives late | — | merged when it arrives (OR-merge is idempotent) | — | late first uses alert with "first seen <time>, reported late"; older than 7 days, they go to the digest only |
| Data lost (outage over 7 days, or a member down longer than its tracker holds) | — | that share of the day is missing | — | the gap is shown; a missing period is never read as "no use" |
| Subscription cancelled, add-on removed or tenant unlinked | unaffected | stops | the class map is **frozen**, never emptied: the node keeps the last good copy and class rules, which are the tenant's own configuration, stay; the node's Lists page says "class map no longer updated" and offers "Convert to local lists" or "Remove class rules" | the evidence is purged within 30 days (ADR-1059) |
| Shadow AI turned off in the portal | unaffected | the cloud tells the node to stop in its reply to the next batch; the node stops | class rules stay until an editor removes them (a signed change) or an admin does on the node; the class map frozen as above | the purge starts at once and completes within 30 days; turning it on again is a fresh start |
| Export turned off on the node | unaffected | stops at once | unchanged | cloud: "the export is off on <cluster>" |

Because frozen class rules keep blocking what they blocked, cancelling never silently unblocks a group and never breaks DNS; an admin can always remove class rules or convert them to local lists on the node without the cloud.

## The catalog (ADR-1055)

### Taxonomy

Each entry has a `kind`. What DNS can attribute differs by kind:

| Kind | Examples (hostnames illustrative; each entry is verified from the vendor's own documentation) | Attribution by DNS |
|---|---|---|
| `chat` | consumer chat assistants on the web and in apps | good for the service, poor for the tenant |
| `api` | model APIs and SDK endpoints; cloud forms such as `<resource>.openai.azure.com`, `bedrock-runtime.<region>.amazonaws.com` | good; the strongest "automated" signal |
| `coding` | coding assistants and IDE plug-ins | good; GitHub Copilot separates plans by host |
| `embedded` | AI features inside other SaaS (an office suite's assistant, a chat or notes product's AI) | none or shared; listed for awareness only |
| `model_hosting` | model and file hosting, model registries and their CDNs | a download is evidence of a local model, a page view is not AI use |
| `agent` | agent and automation platforms | weak: most of their traffic is not AI |
| `local` | self-hosted LLM servers on the LAN | not a domain entry; a later phase (see "Later") |

### Entry schema

Files in the service's repository, one per kind, code-reviewed, with a `catalog_version`. An entry:

```toml
[[service]]
id = "example-chat"                 # stable; renamed ids keep an alias for one release
name = "Example Chat"
vendor = "Example AI, Inc."
kind = "chat"
aliases = []
ai_only = true                      # false for platforms where most traffic is not AI
dns_visibility = "dedicated"        # dedicated | shared | none
tenant_split = "none"               # hostname | header_only | none
rules = [
  { pattern = "||chat.example.com^",   role = "app" },
  { pattern = "||api.example.com^",    role = "api" },
  { pattern = "||files.example.com^",  role = "upload" },
  { pattern = "||static.example.com^", role = "static" },
  { pattern = "||example.com^",        role = "vendor" },
]
ambient = [                         # contacted without user action, per OS family (lab-measured, T37.5)
  { host = "assist.example.com", os = "windows", since = "11 24H2", assistant = true },
]
enterprise_option = { exists = true, url = "https://example.com/enterprise" }  # https, vendor domain only
[service.tiers.consumer]
trains_on_inputs = "default_on"     # default_on | user_choice | opt_in | off | unknown
retention = "as stated by the vendor"
region = "US"
jurisdiction = "US"
evidence = ["https://example.com/privacy", "https://example.com/network-requirements"]
checked = "2026-11-19"
```

- **Roles.** `app`, `api`, `upload`, `auth`, `static`, `download`, `vendor` (marketing, docs, status, careers), `dependency` (needed for the service to work, blocked only with it). Only `app`, `api` and `upload` count as **use**; `vendor` alone reads "visited the site". A `vendor` subtree rule (`||vendor.example^`) is allowed only on the registrable domain of an `ai_only = true` vendor; a multi-product vendor's entry (Gemini under Google, Copilot under Microsoft, Meta AI, Grok) lists exact names only, and its `vendor` rules are never blocked.
- **Ambient, per OS family.** An `ambient` host is recorded with the OS family (and the version it was measured on) and whether it is a built-in **assistant** host. It lowers confidence only on devices of that family (from the directory's OS family); on other devices it counts normally.
- **URLs.** `evidence` and `enterprise_option.url` are the only URLs in an entry. They are shown in the portal as links that show their domain and never reach the node. The validator accepts only `https://` URLs on the entry's vendor domains or a fixed allowlist (for example `docs.github.com`, `learn.microsoft.com`).
- **`tenant_split = "hostname"`** carries `enterprise_hosts` and `consumer_hosts` (GitHub Copilot's `*.individual.`, `*.business.` and `*.enterprise.githubcopilot.com`) or a `tenant_pattern` (Azure OpenAI's per-resource subdomain). Hosts every plan shares (sign-in, telemetry, the GitHub API) are `dependency` rules of each plan's entry, so "Allow Business, Block Individual" never blocks what Business needs. Copilot's per-plan hosts are enforced by GitHub's subscription-based network routing (enforced since 4 November 2024; extended to the coding agent from 27 February 2026); older IDE plug-ins that predate it reach the shared hosts, and the help topic says so. `header_only` records that the vendor offers tenant restriction only by a proxy-injected header (ChatGPT's `ChatGPT-Allowed-Workspace-Id`, Anthropic's `anthropic-allowed-org-ids`), so the portal can say so.
- **Facts, not scores** (owner decision 6). `tiers` hold what the vendor states, with the date and the link. The portal shows "Example AI states (2026-11-19, link): consumer chats may be used for training unless you opt out". Examples the first catalog must capture correctly: OpenAI's API and business plans are not trained on by default, with 30-day abuse-monitoring retention for most endpoints; Anthropic's consumer plans are used for training when the user allows it, a choice announced on 28 August 2025 that existing users had to make by 8 October 2025, with retention up to five years when allowed and 30 days otherwise (recorded as `trains_on_inputs = "user_choice"`, since the vendor's page does not state the toggle's default); DeepSeek's policy stores data on servers in the PRC.

### Validator (refuses a catalog)

- A rule whose domain is a public suffix, checked against the Public Suffix List **including its private section** (so `vercel.app`, `workers.dev`, `pages.dev`, `github.io`, `netlify.app`, `herokuapp.com` and `hf.space` are refused as subtrees), or a registrable domain on the **shared-infrastructure denylist** (CDN and cloud fronts such as `cloudfront.net`, `azureedge.net`, `azurefd.net`, `blob.core.windows.net`, `windows.net`, `challenges.cloudflare.com`, `cloudflare.com`).
- A subtree rule on a **protected parent**, by family: Google (`google.com`, `googleapis.com`, `gstatic.com`, `googleusercontent.com`), Microsoft (`microsoft.com`, `cloud.microsoft`, `office.com`, `live.com`, `bing.com`, `azure.com`, `windows.net`), GitHub (`github.com`, `githubusercontent.com`), Apple (`apple.com`, `icloud.com`), Amazon (`amazon.com`, `amazonaws.com`), Meta (`facebook.com`, `fbcdn.net`, `instagram.com`, `whatsapp.net`), X (`x.com`, `twimg.com`). Under these, only exact names or specific subtrees (`generativelanguage.googleapis.com`). The tests include one refused entry per family.
- A `vendor` subtree rule on anything but an `ai_only = true` vendor's registrable domain.
- A hostname outside the vendor's own registrable domains without a recorded justification.
- A display URL that is not `https://` on the entry's vendor domains or the fixed allowlist.
- An entry with no `evidence`. (A `checked` date more than 90 days older than `catalog_version` only **warns**: the portal shows "facts not rechecked since <date>".)
- More than 2,000 services or 12,000 rules (the node's class-map cap).

The same validator runs on a tenant's **local entries** (an internal tool or a service the catalog lacks), added in the portal with the same schema and `source = "local"`. They are user policy, not catalog content: each reaches the node as a `class_local` entry in a change signed by a tenant admin's passkey (ADR-1060 point 1), never in the shared class map. Because a local entry can name any hostname, it is also the easiest way to turn Shadow AI into monitoring of non-AI sites, so: at most 50 local entries and 200 patterns per tenant; adding one is a tenant admin's signed change, in the event log and the node's audit, never an agent's; `class_local` entries are **tenant-defined** (a generic flag, no metadata), the node lists those patterns separately on its Export card, and **at privacy level 1 the node does not match tenant-defined patterns** (owner decision 4's exception covers the catalog's AI services, not arbitrary names; at level 1 a tenant-defined pattern stays hashed like any other name).

### Sources and licensing

- **In-house, authored from vendor documentation** (owner decision 1). Each entry cites the vendor's network or allowlist page and its privacy or retention page. The catalog is MySummitKeep's data in the service's private repository (ADR-1052 §2), under the service's terms; it is not in this repository and not AGPL. The node receives only the compiled class map (numbers and opaque tags, no metadata), signed by the content key, under the service's terms.
- **No usable open feed exists.** UT1's `ai` category (via the olbat mirror) is about 75 flat registrable domains with no kinds or metadata, and its licence is unconfirmed at the source (the mirror says CC BY-SA 4.0); it is used only as a list of names to investigate by the weekly job, never copied. AdGuard's HostlistsRegistry is GPL-3.0 and is ruled out by the clean-room rule (AGENTS rule 6) and ADR-1033 §5; it is not used even as a reference. The AI-content blocklists (uBlock-style lists against AI-generated sites) target a different thing. NextDNS has no AI category.
- **Commercial feeds are not used.** Cisco Talos and Umbrella have a Generative AI content category, DNSFilter and Sophos have one, Microsoft Defender for Cloud Apps catalogues more than a thousand generative AI apps scored on 90+ risk factors, Cloudflare Gateway has a Technology › Artificial Intelligence subcategory (ID 184), and OEM URL databases (zvelo, Webshrinker, BrightCloud) license per lookup or per database. Their terms normally forbid redistribution and a per-query lookup would send customers' names to another party. They set the scale a business buyer compares against: ours starts at 150 to 250 services and grows.
- **The open node is unchanged.** `presets/services/ai.toml`, ChatGPT's entry in `messaging.toml` and the `ai` category stay as they are, as the free node's basic AI blocking. No migration and no aliases are needed. A group may use both; the cloud counts the node's own blocks from the export's blocked count.

### Keeping it current

- **Continuous publishing.** A reviewed catalog change is compiled into the class map (one map for every tenant), signed by the content key (only from reviewed catalog commits, by a pipeline with its own identity) and reaches nodes within about a minute (the heartbeat path); there is no release cadence to wait for, except that a version adding more than 1,000 patterns is held on each node for 72 hours. A change can add names to a service or a kind's tag that a group already blocks; it never changes a group's mode and never widens an Allow.
- **The weekly job** (in the service's repository; recorded-metadata tests never touch the network): resolves every rule and flags NXDOMAIN or dead names; fetches each evidence URL, extracts and normalises its main text (scripts, navigation, dates and tracking parameters removed) and diffs that, opening one grouped issue per week for vendors whose network or privacy page changed in substance; cross-checks candidate names from UT1's `ai` list and a watchlist and opens a "candidate entries" issue. Nothing enters the catalog without a person's review.
- **A bad change** is rolled back by republishing the previous `catalog_version`'s content under a new sequence number (nodes refuse an older sequence, ADR-1062); the node treats a new class map like any update (signature and caps checked, last good kept on failure).

### Size

About 150 to 250 services and 1,000 rules at first release; about 1,000 services and 6,000 rules at enterprise breadth. On the node: the class map's FST about 15 to 150 KB; each group's class-rule sets at 12 bytes per domain in the snapshot (ADR-1017), at most about 72 KB per group at 1,000 services. The node's image grows only by the export and class rules (code), expected well under 0.1 MB.

## Detection in the cloud (ADR-1056)

### Inputs

The cloud ingests export batches (untrusted input, ADR-1047 point 10: a tenant may run a modified node, so every field is bounded and checked, and a batch only ever affects its own tenant), maps class numbers back to (service, role) with the tenant's class-map version, and OR-merges day bitmaps per (tenant, device pseudonym, service, role, day).

### Signals

| Signal | What DNS shows | Strength | Design |
|---|---|---|---|
| First use | the first lookup of a catalog hostname by a device or group | strong for catalogued services | requires a use role; first-seen kept by the cloud; quiet for the first day after a fresh start |
| Volume | lookups, which follow the TTL, not requests | weak as a count | reported as **active time**: distinct 5-minute periods and active days, "about". Never "N prompts" or "N requests". |
| Interactive or automated | roles, device class, time-of-day spread, rhythm | medium from roles, weak from rhythm | classified in order: roles (api-only with no static or auth suggests automated); device class (server or headless versus laptop or phone); activity at the service spread across all hours over 7 days (from the device's own day bitmaps for the service, not from any wider activity record); the rhythm bins at the service's hostname. Shown as "looks like automated API use" with the evidence. `coding` is its own kind, so IDE use is not called automated. |
| Outside the approved list | service level always; tenant level only with `tenant_split = "hostname"` | strong at service level | the rest reads "tenant not visible to DNS" |
| Visibility | the Firefox canary and Private Relay names (classes in the map) read against the node's `[special]` switch states, DoH bootstrap names, the node's quiet-while-present spans | medium, as a coverage signal | a per-device visibility state; see below and the threat model |

**Visibility state, under the shipped defaults.** WrenDNS answers `use-application-dns.net` and `mask.icloud.com`/`mask-h2.icloud.com` with NXDOMAIN by default (`block_firefox_canary`, `block_icloud_private_relay`; DNS-019, ADR-904). With a switch on, a canary or Private Relay lookup means the network told that device to stay on this resolver, and the device shows **"opted out by this network"**, at full visibility. Only with the switch off does the same lookup set **partial**. DoH bootstrap names set partial in either case. Clients that reach a resolver by a hard-coded IP address make no telling lookup at all; only a quiet-while-present span (or, later, the endpoint agent) can notice them. A cloud-side data gap is a fourth state, **"no data"**, shown with its window.

### Confidence

Deterministic and explainable, like ADR-019. Each finding carries its evidence and a level in words:

- **Confirmed**: the endpoint agent saw the URL or an upload (a later phase, after T24.39).
- **Likely**: `app`, `api` or `upload` hostnames in at least 2 active 5-minute periods, or on at least 2 days, on the merged bitmaps.
- **Possible**: one period, or `auth` or `static` hostnames only.
- **Visited**: `vendor` hostnames only.

**OS assistant present.** Built-in assistants (the Edge Copilot sidebar, Windows Copilot, Gemini as Android's assistant, Apple Intelligence's ChatGPT extension, Meta AI inside WhatsApp) reach AI hosts both at idle and when used. Their `ambient` hosts, recorded per OS family, put the device in a separate state, **"OS assistant present"**, shown on the device and the service but never counted as use. Use of the same service is still found from its non-ambient `app`, `api` or `upload` hosts, or from ambient hosts only when the day bitmap shows activity well above that OS family's measured idle pattern (T37.5 records the idle number of periods per day). Where the lab cannot separate idle from use for a host, the help topic says so rather than guessing.

Lowered by: an `ambient` hostname on a device of the OS family it was measured on; uncertain identity (address only, a randomised MAC, a shared address behind NAT, a guest network or a VPN concentrator); a device class suggesting OS background traffic. Visibility gaps never raise or lower a finding; they qualify claims of absence.

A device "used" a service only at Likely or better (owner decision 5). Example finding: "laptop-07 (192.0.2.10, owner: set in the CMDB) used Example Chat for the first time: chat.example.com and its static host in 3 periods between 09:10 and 09:40. Not approved for the Staff group. Likely."

### False positives the design guards against

Browser prefetch and preconnect; link previews built on the device by messengers; OS and browser assistants contacting AI hosts at start-up; reading a vendor's marketing or docs; shared CDN and challenge hosts (never catalogued); AI inside SaaS (never counted); model-hosting pages and third-party Spaces (`model_hosting`, `ai_only = false`, a page view is not use); automation platforms (`ai_only = false`, Monitor display only, never in a one-click "block all AI").

### Naming the device and the person

Findings are keyed by the device pseudonym; the display name, group and CMDB `owner` come from the latest directory entry **at read time**, so renames follow. A person is named only from the CMDB `owner` attribute, which is set by hand on the node; WrenDNS never infers a person from a host or router name. Nothing is written back to the node's CMDB (DSC-901).

### The alert

`shadow_ai_first_use` (CLD-907), on by default once Shadow AI is on: **each device's first Likely use of each service that isn't approved for its group** (owner decision 8). First-seen per (device, service) and per (group, service) is a row in the cloud's store, so a node restart, a failover or a resent batch never fires it again.

So that a new install or a sudden change doesn't flood:

1. **Quiet first day.** After a fresh start (the tenant's first Shadow AI day, a cluster newly linked to a tenant that has it, or turning it back on, since turning it off purges first-seen) first-seen rows are recorded for 24 hours and nothing alerts; the first day ends with one **baseline** message ("Baseline: 14 devices use 6 AI services. Open in WrenDNS Cloud.").
2. **Grouping.** First uses are collected for up to 15 minutes per (group, service) and sent as one message naming up to 5 devices and a count ("3 devices in Staff used Example Chat for the first time: laptop-07, laptop-12, phone-03. Likely.").
3. **Bursts.** When more than 10 devices first-use the same service within an hour (an OS update rolling out an assistant, a new app pushed to every laptop), the alert becomes one service-level message for that hour ("Example Voice AI: first use on 23 devices in the last hour. This often follows an OS update; check 'OS assistant present'."), and the rest go to the digest.
4. **Rate limits.** At most 10 messages per hour and 50 per day per destination; past that, one hourly summary ("12 more first uses, see the page") until the next day.
5. **Late data.** First uses reported late say so; older than 7 days they go to the digest only.
6. **Mutes** per service, group, device or kind, with an expiry; Allow and Block groups never alert (Block counts blocked attempts in the digest).

7. **Who receives what.** An alert names devices, so it goes only to people who could see the same thing in the portal: email only to tenant members who hold the Shadow AI permission. Third-party destinations (Slack-compatible and generic webhooks, ntfy) get the service, the group, a device count and a link by default; device names in them are a tenant admin's opt-in, with the line "device names will be stored by <destination>". No message, by any destination, carries the CMDB owner, an address or the evidence; those stay behind the link. The digest follows the same rules.

`shadow_ai_visibility` (off by default) for a `visibility_gap` finding. Messages lead with the device and the plain fact (brand voice, no exclamation marks).

## Policy modes (ADR-1057)

Per group, per kind, with per-service overrides; set in the portal:

| Mode | DNS answer | Detection | Shown as |
|---|---|---|---|
| **Off** | unchanged | none for this group: the cloud names it in its batch replies and the node stops sending its devices (anything that arrives first is discarded) | — |
| **Allow** (approved) | unchanged; names in the group's allow list | counted as approved use | "Approved" |
| **Monitor** | unchanged | findings, page, digest, alert | "Not approved" |
| **Block** | blocked by the group's class rules (the group's block response, EDE 15) | blocked attempts counted | "Blocked" |

- **Compilation in the cloud, signed by the editor.** For each group the cloud computes the classes and tags to block (kinds and services on Block, minus services on Allow, minus approved tenants, `dependency` classes only with their service, `vendor` classes only for `ai_only` entries) and the classes to allow (approved services' exact names and approved tenants), and turns a change of mode into a class-rule change that the editor signs (ADR-1060 point 3). No lists are created, so `MAX_LISTS` (1024) is untouched.
- **"Block all AI"** blocks the `ai_only = true` kinds and services only.
- **Per-device exceptions** stay on the node as ordinary device-scoped quick rules (ADR-067); the portal links to them through the remote UI.
- **Approved tenants** are offered only where `tenant_split = "hostname"` (owner decision 7); elsewhere the portal says "the tenant isn't visible to DNS" and points to the vendor's proxy-based control.
- **Explain** on the node names the class rule that decided an answer ("class rule of Staff, class 214, signed by <editor> in WrenDNS Cloud"); the portal's service page names the policy line behind it.
- **Where a change can't apply.** When `[cloud.sync]` is off on a cluster or doesn't allow class rules, the portal says "sync is off on <cluster>" with the steps to turn it on at home; when the editor has no signing passkey enrolled on that cluster, it says how to enrol one at home. A Git-managed cluster gets the TOML lines to commit instead (`gitops_managed`). A conflict with an edit made at home is parked in the portal (ADR-1063 point 5).

### Later: Warn

Warn (block until the user acknowledges a notice, through the browser add-on or `/unblock`, T24.39) is not in v1 (owner decision 10). The first draft's design stays the starting point and gets its own design note when T24.39 exists: Warn only for `chat` and `agent`, holding only browser names; a node-side acknowledgement overlay, checked after the security lists; a Monitor fallback for devices without the add-on. Hosted-only adds a question that note must answer: the overlay would be a node mechanism driven by class rules, and must keep working when the cloud is unreachable. FLT-904 stays reserved for it.

## Defaults (ADR-1058)

Off on a new tenant and on every node (owner decision 3). Turning it on takes two admin actions, neither of them an agent's:

1. **In the portal**, a tenant admin turns Shadow AI on and acknowledges the monitoring notice: what is recorded, that it is sent to and kept by WrenDNS Cloud, that the operator is responsible for telling the people monitored, and a link to the notice template.
2. **On the node** (on the LAN, or over a hosted name only under ADR-1049 point 3, since a cloud in the middle must not be able to turn on its own export), an admin turns on the export, which shows what will be sent. At privacy level 1 it needs an extra acknowledgement: "At privacy level 1 this node hashes names in its own logs. Shadow AI is an exception: names in the class map are matched before hashing, and per-device findings with device names are sent to WrenDNS Cloud." Both acknowledgements are recorded with who and when, on the node (audit) and in the cloud.

Once on, every group the node reports starts at **Monitor**, and so does any group added later. Nothing is blocked until an operator chooses it.

## UI

Every control ships with its UI, help topic and Playwright test in the same task (the fork's "UI for every feature" rule): node controls in the node's UI, cloud controls in the portal.

**On the node (AGPL):**
- **Settings → WrenDNS Cloud → Export:** on or off, the groups exported, the level-1 acknowledgement, the class map's version, size and class count, its full pattern list (the names are not secret, ADR-1055) with the diff of each change and the tenant-defined patterns marked, last batch time and size, the buffer's fill, "show the last batch" (the decoded batch, so an operator can see exactly what leaves), and the exclusions that apply.
- **Lists:** each group's class rules with the class map's version, last change, the diff since the last version, the signer of the last change, "frozen" when the map is no longer updated, "Convert to local lists" and "Remove class rules".
- **Group editor:** the group's class rules (read-only summary with their origin, "set in WrenDNS Cloud, signed by <editor>"), with a link to Changes from the cloud.

**In the portal (the service):**
- **Shadow AI page:** a header with the window, the visibility summary ("31 devices seen, 2 with partial visibility; no data from cluster home-2 since 14:20") and the limits text ("WrenDNS sees which AI services a device reaches by name. It can't see prompts, files, or which account is used for most services. Read more"). Sections: **services in use** (service, kind, groups, devices, active time, trend, first seen, status per group, confidence; "new first"); **a service's detail** (vendor-stated facts with dates and links, hostnames and roles, whether tenants are visible to DNS, devices using it with confidence and evidence, the policy per group); **a device's view** (its services, confidence and evidence, visibility state, CMDB owner); **the catalog** (search, kinds, roles, tenant visibility, facts); **local entries**.
- **Policy:** per group, the mode per kind, per-service overrides (searchable), approved tenants (only where hostnames split), the signing prompt and each change's state (Pending, Applied, Accepted, Conflict, Rejected, Expired).
- **Settings → Shadow AI:** on or off with the notice, retention, alert destinations (email to tenant members with the Shadow AI permission; Slack-compatible webhook, generic webhook and ntfy with counts and a link unless device names are opted in), mutes, the digest's day and hour, export and purge per device or per CMDB owner.
- **Cross-site view** (Business): services per cluster and group, new services, visibility gaps.
- **Help topics:** "What Shadow AI can and can't see", "Policy modes", "Approved tenants", "Confidence levels", "Visibility and bypass", "Telling people you monitor AI use" (with the notice template), "What the node sends", "The AI catalog".

The per-device views need the tenant's **Shadow AI** permission (granted by a tenant admin); other members see service and group counts only.

## Agent and API

The service's API (`https://dns.wrendns.com/api/v1/shadow-ai/...`, OpenAPI published) with tenant-scoped tokens; the read scope `shadow_ai:read` is in no default grant because it names devices and people; every read of a device's history is in the tenant's event log. Read tools, served by the portal's MCP endpoint with the same names and shapes as the node's tools (spec/13 conventions):

| Tool | Purpose |
|---|---|
| `shadow_ai_summary` | services in use by group and kind over a window, with counts, active time, trend, visibility summary, data gaps and the limits text |
| `shadow_ai_findings` | findings with confidence and evidence, filtered by cluster, group, device, service, kind, level and window |
| `get_ai_catalog` | the catalog or one entry: kinds, hostnames and roles, tenant split, vendor-stated facts with dates and links, catalog version |

Plans (applied by a person only, ADR-994 §8's rule: applying a plan is a change the editor signs with a signing passkey, so no agent can sign one): `plan_ai_policy` (a group's modes, overrides, approved tenants), `plan_ai_local_entry` (a tenant admin's). Immediate op: `acknowledge_shadow_ai` (mark a finding reviewed). Turning Shadow AI on, the notice, retention, export and purge are not for agents. On the node, the export's status is in the existing MCP read tool `cloud_status`; turning the export on is not for agents (spec/13 §3.2's list).

## Privacy and legal

### The node's privacy levels (ADR-1058)

As in "What the node sends": level 0 and level 1 send per-device findings (at level 1 matched before hashing, after the extra acknowledgement; ADR-102 is amended for this one export), level 2 and above send nothing. The node's own query log at level 0 already records every lookup, including AI services' names, for its own retention; the docs say so and point to `[exclusions.log]` and the query log's retention for operators who want less kept on the node.

### What the cloud keeps, and for how long (ADR-1059, amending ADR-1052 §3)

ADR-1052 §3 says the cloud keeps no query log at rest and no per-device address log, hourly counters only. By the owner's decision of 2026-11-19, **for tenants that turn Shadow AI on**, the cloud also keeps per-device Shadow AI evidence:

| Data | Kept | Notes |
|---|---|---|
| Daily evidence rows: (device pseudonym, service, role, day) with the merged 288-bit bitmap, lookup and blocked counts, rhythm bins | 90 days by default; the tenant may set 7 to 365 | only names in the class map, as services; nothing finer than 5 minutes |
| Findings (derived from the rows) | as the rows | recomputed, never kept longer than their evidence |
| First-seen rows per (device, service) and (group, service): the first-seen and last-seen dates only | the tenant's evidence retention after the last use (90 days by default) | never longer than the evidence they summarise; a use after that is a first use again and alerts again |
| The device directory (pseudonym, name, group, class, OS family, identity certainty, CMDB owner, latest private LAN address) | until 30 days after the device's last evidence row expires, or when the node reports it removed | only devices with class-map matches; the latest values only; no address history; never a public or relay-reported address |
| Quiet-while-present spans (start, end, bypass sign) | as the evidence rows | for `visibility_gap`; no hourly counts or presence timeline are received |
| Alerts and digests sent: time, destination, kind and counts | 1 year, in the tenant's event log | as ADR-1052's event log |
| Their bodies (device names) | as the evidence rows | so a message never outlives its evidence |
| Notice acknowledgements (who, when, which text) | the tenant's life plus 1 year | the operator's evidence of notice |

Never kept: names outside the tenant's class map, query timestamps, answers, public or roaming addresses, content. **Processor only:** MySummitKeep uses a tenant's Shadow AI data only to provide that tenant's Shadow AI; never across tenants, never to curate the catalog, train a model, benchmark or market, and never sold or shared beyond the subprocessor list. Turning Shadow AI off, removing the add-on, unlinking or deleting the tenant starts a purge of every Shadow AI row at once that completes within 30 days (ADR-1052's rule for deleted tenants), and the database's point-in-time backups (7 days) age out after that. A tenant admin can export (JSON) and purge every row for one device, or for every device whose CMDB `owner` is one person, from the portal, first-seen rows and message bodies included; a purge is in the event log and is not an agent operation. The node's buffer is left out of node backups.

**Size.** A row is about 80 B of data, about 120 B stored. A household (15 devices, about 8 services) holds about 10,000 rows over 90 days, about 1.3 MB; an office of 25 staff about 4 MB; 1,000 such tenants a few GB, small next to hosted.md's cost model. Ingest is one small batch per cluster every 5 minutes.

### Notice and employee-monitoring law

The terms already say the operator is responsible for "the laws that apply to monitoring the devices and people on your network" (terms §3). Shadow AI is monitoring of people's internet use, and with hosted-only it is also data that reaches MySummitKeep as the tenant's processor (ADR-1052 §3, under a DPA). The docs and the turn-on notice say plainly that notice, and sometimes consultation, may be required, with examples (not legal advice):

- **New York** (Civil Rights Law §52-c, since May 2022): employers who monitor employees' internet access or use must give written notice on hiring, get an acknowledgement and post the notice; the Attorney General enforces it with civil penalties.
- **Connecticut** (§31-48d, rewritten by Public Act 26-73 from 1 October 2026, which repeals and substitutes the section): prior written notice of the types of electronic monitoring, now also naming the specific locations where it occurs, posted there, and given to employees hired on or after 1 October 2026 before they start. **Delaware** (19 Del. C. §705) requires prior notice of electronic monitoring.
- **California** (CCPA as amended by CPRA, employee data in scope since 1 January 2023): a covered business gives a notice at collection naming the categories of personal information and the purposes, which covers network-activity monitoring of employees.
- **UK** (ICO, "Employment practices and data protection: monitoring workers", October 2023): workers must in most cases be told before monitoring starts and why; consent is rarely a valid basis; a DPIA is expected for intrusive monitoring.
- **Germany** (BetrVG §87(1) No. 6): technical equipment objectively capable of monitoring conduct or performance needs the works council's agreement where one exists.
- **EU** generally: GDPR transparency (Art. 13) and, where national law adds rules, Art. 88; MySummitKeep as processor under Art. 28 (the DPA).

The notice template: "This network records which AI services each device reaches by name, and when, and sends that record to WrenDNS Cloud, which keeps it for <N> days. It does not record what you type or upload." It has optional fields for the places monitoring occurs and the date given (Connecticut) and a line on the categories and purposes (CCPA/CPRA). Counsel reviews it, the vendor-facts wording and the data model before Shadow AI is sold (ADR-1033 item 6).

**Documents that change before launch** (T37.11): privacy.md §3 ("none of the software's data is sent to MySummitKeep") already gains a hosted-service section for linked nodes (ADR-1052 §6); it gains Shadow AI's data, retention and the level-1 exception. The node's privacy-level description and the docs' privacy notes gain "Shadow AI findings are an exception at level 1". The DPA and subprocessor list name the mail sender used for alerts and the digest.

### Minors (owner decision 9)

The operator's responsibility. Shadow AI is not marketed for children and its stories are about adults' devices. A household may use it on its own network; the docs point parents to the node's `ai` category, groups and schedules for children's devices, which block without building a per-child usage record. Because hosted-only means per-device records of minors' devices **can now reach MySummitKeep** (as the tenant's processor), counsel reviews COPPA and GDPR Art. 8 for Shadow AI before launch, together with ADR-1052 §6's review.

## The threat model

### Evasion: what makes AI use invisible

| Path | Effect | Response |
|---|---|---|
| Browser DoH or DoT to a public resolver | lookups never reach WrenDNS | with `block_firefox_canary` on (the default) Firefox stays on this resolver and the device shows "opted out by this network"; otherwise the canary and known DoH bootstrap names set "partial"; blocking bypass stays the node's existing "DoH, VPN, Tor and proxy bypass" category; never automatic |
| Resolvers hard-coded by IP (Android Private DNS set by address, apps with built-in DoH to an IP) | no telling lookup at all | only a quiet-while-present span can notice (for devices already in the directory); blocking outbound 853 and known DoH addresses at the router is documented, not done by WrenDNS |
| VPN, Tor, iCloud Private Relay | the device or its Safari traffic disappears | with `block_icloud_private_relay` on (the default) Apple devices turn Private Relay off here and stay visible; otherwise its names set "partial"; a quiet-while-present span sets "blind since"; a `visibility_gap` finding only under the conditions below; a blind spot, never proof of use |
| Mobile data, roaming | off the network | out of scope at home; WrenDNS Cloud's roaming resolver (M36) sends roaming devices' lookups through the home node, so they are counted like LAN lookups where the tenant uses it |
| ECH (RFC 9849, keys in HTTPS records, RFC 9460) | hides SNI from on-path observers, not the name from the resolver asked | **no change**: WrenDNS already sees the name. Stripping ECH keys would rewrite RDATA on the hot path (ADR-114 leaves HTTPS records' `ipv6hint` as is for the same reason) and weaken users' privacy for nothing. Blocked names already get NODATA for HTTPS records. |
| AI inside a sanctioned SaaS | rides the host app's names | `embedded` entries say "not visible to DNS" |
| A personal account on a shared-hostname service | indistinguishable from the company's | stated on the page; the vendor's proxy-based tenant control is the remedy |
| API calls through a cloud function or an approved proxy | only the proxy's name is seen | out of scope; the proxy's own logs |
| Changing the device's MAC or name | breaks the per-device history | the CMDB's reconciliation; pseudonyms derive from the CI id when the CMDB is on |
| A local model on the device | no lookups after the download | the `download` role shows the download |
| The export turned off, or the node at level 2 | nothing reaches the cloud | the cloud shows "the export is off" or "needs privacy level 0 or 1" for that cluster |

**When `visibility_gap` is raised.** A device going quiet is normal (sleep, leaving the house), so a gap needs both: (1) proof the device is **still present** (the node's quiet-while-present span, judged on the node from a lease renewal, a neighbour-table entry or an inventory sighting, so no presence timeline leaves it); and (2) a **known bypass sign** for that device: a DoH bootstrap name, or the canary or Private Relay names with their switch off. The finding states only those facts ("laptop-07 is on the network but has sent almost no lookups here since 14:20; it looked up a public DoH resolver's name at 14:18"). It never mentions AI use or links the gap to an earlier finding.

### Threats to the feature itself

- **A wrong accusation.** The costliest error. Roles, the ambient flag, confidence in words, evidence on every finding, people only from the CMDB, and Likely as the alert threshold.
- **False assurance.** Visibility per device, data gaps per cluster and the limits text on every page, digest and tool.
- **A compromised or mistaken cloud turning the export into surveillance.** The class map decides which names leave the node, so a hostile map could ask about any name. Limits: the node refuses public suffixes, protected parents, a map for anything but tenant `*`, and anything but exact names and subtrees, holds a version that adds more than 1,000 patterns, caps the map at 12,000 patterns, shows every change to the map's size and records it in the audit log, and "show the last batch" lets an operator see what leaves; the node never sends names, only numbers, but numbers paired with a hostile map are as revealing. Transparency: the node shows the map's full pattern list and the diff of every change, with tenant-defined patterns marked; the catalog's part of the map is the same for every tenant, and the service publishes its hash per `catalog_version` on wrendns.com so a node can show "catalog part matches the published version" and a pattern aimed at one tenant stands out; at level 1 tenant-defined patterns are not matched. The residual risk is stated in "What the node sends" and is part of trusting the service; the export is off unless an admin on the LAN turns it on.
- **An operator using Shadow AI to watch non-AI sites.** Local entries are capped, logged, shown on the node and not matched at level 1 (see the validator); the notice template says "AI services", and the help topic says that monitoring other sites is outside the notice.
- **Alerts leaking to third parties.** Webhook, Slack-compatible and ntfy destinations get counts and a link unless device names are opted in; no message carries the CMDB owner, an address or evidence ("The alert", point 7).
- **A compromised cloud changing answers.** A Block or Allow needs an editor's signature and the editor's node role (ADR-1061); a compromised back end can delay or drop one, not create it. A stolen content key, or a compromised service misusing the Key Vault sign operation, can change which names a class or tag holds within the caps (so a kind-level Block covers more), never a public suffix, a protected parent or the node's own names, never one tenant's map alone, never an Allow, and never which classes a group blocks; every change is a diff on the node, the catalog part's hash is published, and revocation drops what the key signed after its `compromised_after` time. Shadow AI changes are signed on the node's own page like any other, and the remaining display gap of ADR-1061 point 7 (changes signed in the portal while home is unreachable) applies to them as to any other.
- **A modified node lying to the cloud.** Every batch is untrusted input (ADR-1047 point 10): bounded, checked against the tenant's class map, and able to affect only its own tenant's findings.
- **Exposure of usage records.** They are sensitive (who uses which assistant when): the Shadow AI permission, a read scope in no default grant, every read of a device's history logged, retention limits, purge per device and per owner, a DPA, and counsel review.
- **Agent misuse.** Read tools only by scope; policy as plans; no agent can turn Shadow AI or the export on.
- **Defamation or accuracy claims about vendors.** Vendor-stated, dated, linked facts; no scores; counsel review before sale.
- **A flood of spoofed sources.** Caps per device and per class on the node, pairs already sent evicted first, and the cloud's per-tenant ingest limits.

## Performance and memory

On the node, against ADR-1031 (idle ≤ 32 MiB, loaded ≤ 128 MiB) and the 25 MiB image gate:

| Item | Cost | Notes |
|---|---|---|
| Query path | none | the export is on the telemetry thread; class rules are ordinary list membership |
| Class map | about 15 to 150 KB mapped | built only while the export is on |
| Tracker | at most 4,096 pairs × about 80 B ≈ 0.33 MiB | caps per device and per class |
| Snapshot | class-rule sets per group with rules, about 12 KB to 72 KB each | names shared across groups are stored per group |
| Buffer on the primary | at most 4 MiB on disk | only while the cloud is unreachable |
| Upload | one compressed batch per cluster every 5 minutes, a few KB | control frames on the existing tunnel (ADR-1047), no new connection or stream budget |
| Telemetry thread | a suffix match per event (up to one probe per label), expected under 1 µs | only while on; bench-smoke and drain rate on a Pi |
| Image | code only, expected under 0.1 MB | reported per task |

The Pi's loaded figure from the GeoIP gate run was 60 to 65 MiB; the export adds at most about 0.5 MiB when on and nothing when off. At level 1 the match runs before the aggregator applies `Hub::set_privacy`, still on the telemetry thread, never on the query path. Each node task runs `make bench-smoke` (`wrendns-telemetry` and `wrendns-filter` are in its set) and reports its RSS and image deltas.

## Packaging (ADR-1059)

- **Commercial and hosted-only** (owner decision 2). Shadow AI is part of WrenDNS Cloud: a paid **add-on for the Cloud and Cloud Plus tiers** and **included in Business** (the design's placement; final tier placement and every price are the owner's). It needs a linked cluster (M36) and works only while the tenant pays; when it stops, DNS and the lists keep working as "Offline behaviour" describes.
- **Open, AGPL, free:** the name-class counters export and class rules (generic node features that any hosted analytics or managed policy can use), and everything the node already has, including the `ai` category and the nine `ai.toml` services for basic AI blocking.
- **Not sold:** any risk score, any feed from a third party, anything that makes DNS depend on the cloud (AGENTS rule 5).
- **Market position.** Cloudflare One is **free for up to 50 users** and its Gateway DNS policies can block the Technology › Artificial Intelligence subcategory (ID 184), so a small office already has a free, cloud-hosted DNS-level AI block; its Shadow AI report needs the gateway and, for the full analytics, TLS inspection. DNSFilter and Sophos sell a Generative AI DNS category; Microsoft Defender for Cloud Apps catalogues more than a thousand generative AI apps with risk scores. WrenDNS does not win on "block AI for free". Its edge is a self-hosted resolver that keeps answering without the cloud, only catalogued names leaving the network and only as numbers, per-device evidence tied to the CMDB, Monitor rather than only block, and honest limits; its gap is catalog breadth. The add-on is priced against "free from Cloudflare" for blocking and against Defender-class tools for discovery.

## Phased delivery

**Phase 0 — the node (AGPL), after M36's T36.4 and T36.5** (the tunnel and enrolment; built and tested against the fake broker), **and for T37.3 also T36.15, T36.16 and T36.18** (signed changes, sync and the platform channel): the name-class counters export (T37.2) and class rules over the signed class map (T37.3). Useful for any hosted analytics; nothing about AI.

**Phase 1 — the service, after M36's T36.9** (the portal), for the owner's tenant first: the catalog, validator, weekly job and the class-map compile (T37.4); the ambient lab (T37.5, before the first release); ingest, detection and findings with retention, export and purge (T37.6); policy and the group lists (T37.7); the portal pages, the turn-on flow and the alert (T37.8); the digest (T37.9); the API and MCP (T37.10).

**Phase 2 — sale, with M36's phase 2** (billing, the privacy policy and DPA): legal and launch readiness (T37.11).

**Later:** endpoint-agent confirmation (T37.12, after T24.39); local model servers from imported scans (T37.13); Warn (T37.14, after T24.39, its own design note); candidates for services outside the catalog (T37.15, its own design note, because it would send names outside the class map).

## Open questions

1. Final tier placement and prices of the add-on (the design assumes an add-on for Cloud and Cloud Plus, included in Business).
2. Which real iOS and Android devices the ambient lab uses (VMs cannot reproduce Apple Intelligence or Android's assistant), and whether the owner's own devices may be used, with a go-ahead (owner decision 5).
3. Does the digest become a general WrenDNS Cloud digest, or stay Shadow AI only in v1?
4. Does the cross-site view need an MSP-level tenant spanning several customers' tenants (a reseller model), which hosted.md doesn't have?
5. Who curates the catalog: the owner alone, or contributors with review?
6. A hosted MCP endpoint on the portal is new for M36 too; does it land with T37.10 or as an M36 task?
7. Answered by the owner decisions on cloud writes: every synced kind is edited in the portal with signed changes (M36), so non-AI managed policy needs no Shadow AI mechanism.

## Sources

Repository: `presets/services/ai.toml`, `presets/services/messaging.toml`, `presets/categories/ai-crypto.toml`, `crates/wrendns-config/src/schema.rs` (`ListMode::Shadow`), `crates/wrendns-config/src/validate.rs` (`MAX_LISTS`), `crates/wrendns-filter/src/snapshot.rs`, `crates/wrendns/src/shadow.rs`, `crates/wrendns-telemetry/src/anomaly.rs`, `docs/design/content-categories.md`, `docs/design/cmdb.md`, `docs/design/hosted.md`, `docs/design/network-inventory.md`, `docs/running.md` (Device anomalies, Alerts), `docs/legal/privacy.md`, `docs/legal/terms.md`, spec/05, spec/13, `brand/README.md`, ADR-019, ADR-048, ADR-067, ADR-102, ADR-114, ADR-907, ADR-910, ADR-994, ADR-995, ADR-1017, ADR-1031, ADR-1033, ADR-1047, ADR-1049, ADR-1052; issues cloud #4, #29, cloud #3.

Web (checked 2026-11-19):

- GitHub Copilot allowlist and plan hosts: https://docs.github.com/en/copilot/reference/allowlist-reference
- ChatGPT Enterprise network controls: https://help.openai.com/en/articles/20001323-corporate-network-controls-in-chatgpt-enterprise
- Claude tenant restrictions: https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions and https://claude.com/docs/government/tenant-admin/tenant-restrictions
- Microsoft 365 Copilot network requirements: https://learn.microsoft.com/en-us/microsoft-365/copilot/microsoft-365-copilot-requirements
- Defender for Cloud Apps and generative AI: https://learn.microsoft.com/en-us/security/security-for-ai/discover, https://learn.microsoft.com/en-us/defender-cloud-apps/risk-score, https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/discover-monitor-and-protect-the-use-of-generative-ai-apps/3999228
- Cisco Umbrella and Talos Generative AI category: https://www.cisco.com/c/en/us/support/docs/security/umbrella/225009-understand-new-generative-ai-content.html, https://blog.talosintelligence.com/2024-changes-to-content-and-threat-categories/
- Cloudflare Shadow AI: https://blog.cloudflare.com/shadow-ai-analytics/, https://developers.cloudflare.com/cloudflare-one/policies/gateway/domain-categories
- DNSFilter Generative AI category: https://www.dnsfilter.com/newsroom/dnsfilter-adds-comprehensive-protection-against-generative-ai, https://dnsfilter.com/blog/thoughts-on-new-gen-ai-category
- Sophos DNS Protection GenAI category: https://www.sophos.com/en-us/blog/sophos-dns-genai
- OEM databases: https://www.dnsfilter.com/blog/webshrinker-website-categorization, https://www.sophos.com/en-us/oem/ai-url-analysis
- UT1 mirror: https://github.com/olbat/ut1-blacklists; AdGuard HostlistsRegistry (GPL-3.0): https://github.com/AdguardTeam/HostlistsRegistry; NextDNS AI category request: https://help.nextdns.io/t/h7yggbh/parental-control-add-ai-category
- Vendor data policies: https://developers.openai.com/api/docs/guides/your-data, https://openai.com/business-data/, https://www.anthropic.com/news/updates-to-our-consumer-terms, https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html
- Cloud endpoints: https://docs.aws.amazon.com/bedrock/latest/userguide/endpoints.html, https://learn.microsoft.com/azure/ai-services/cognitive-services-custom-subdomains
- Ollama: https://docs.ollama.com/faq
- Cloudflare One free plan (50 users) and Gateway's Artificial Intelligence subcategory (ID 184): https://www.cloudflare.com/plans/zero-trust-services/, https://blog.cloudflare.com/teams-plans, https://developers.cloudflare.com/cloudflare-one/traffic-policies/domain-categories/
- GitHub Copilot subscription-based routing: https://github.blog/changelog/2024-11-04-copilot-subscription-based-network-routing-is-now-enforced, https://github.blog/changelog/2026-03-02-network-configuration-changes-for-copilot-coding-agent-now-in-effect/, https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-organization/manage-access/manage-network-access
- Anthropic consumer terms (28 August 2025, decision by 8 October 2025): https://www.anthropic.com/news/updates-to-our-consumer-terms
- Connecticut Public Act 26-73 (SB 472): https://prdext2.cga.ct.gov/2026/act/Pa/pdf/2026PA-00073-R00SB-00472-PA.PDF, https://daypitney.com/expanded-connecticut-electronic-monitoring-law-takes-effect
- CCPA/CPRA notice at collection: https://cppa.ca.gov/regulations/, https://oag.ca.gov/privacy/ccpa
- Public Suffix List (private section): https://publicsuffix.org/list/
- New York §52-c: https://www.nysenate.gov/legislation/laws/CVR/52-C*2, https://www.mofo.com/resources/insights/211115-new-york-enacts-employee-monitoring-notification-law
- Connecticut §31-48d: https://law.justia.com/codes/connecticut/2022/title-31/chapter-557/section-31-48d/, https://www.ebglaw.com/insights/publications/reminder-changes-to-connecticuts-electronic-monitoring-statute-now-in-effect; Delaware §705: https://delcode.delaware.gov/title19/c007/sc01/
- ICO monitoring workers: https://ico.org.uk/media/for-organisations/uk-gdpr-guidance-and-resources/employment-information/employment-practices-and-data-protection-monitoring-workers-1-0.pdf
- BetrVG §87(1) No. 6: https://www.luther-lawfirm.com/en/newsroom/blog/detail/dauerbrenner-software-vs-mitbestimmung-87-abs-1-nr-6-betrvg, https://www.goerg.de/en/insights/publications/20-03-2024/it-co-determination-updates

## Owner decisions, second round (2026-11-19)

- **Enforcement:** the cloud publishes `ai-block-<group>` and `ai-allow-<group>` lists that a LAN admin subscribes each group to once; the cloud never changes node configuration (ADR-1060 accepted). *Superseded by the third round.*
- **Tiers:** Shadow AI is a paid add-on for Cloud and Cloud Plus, and included in Business. Prices are set later.

## Owner decisions, third round: cloud writes (2026-11-19)

With the owner's decisions on cloud writes for M36 (`docs/design/hosted.md`, "Owner decisions on cloud writes"):

- **D. Shadow AI Block and Allow become ordinary signed policy changes,** replacing the subscribed lists: each is confirmed with the editor's change-signing passkey and verified, authorized, merged and audited on the node (ADR-1060 amended; ADR-1061, ADR-1063). There is no per-group subscription.
- **The catalog arrives over the platform channel,** signed by MySummitKeep's content key, which can change which names a class holds but never user policy (ADR-1062).
- **Design choices for the owner to confirm:** one class map for every tenant, with tenant local entries as signed `class_local` entries; opaque class tags so a kind-level Block follows the catalog, while Allow names classes only (ADR-1060 points 1 to 3); "Convert to local lists" and "Remove class rules" on cancellation (point 5).
