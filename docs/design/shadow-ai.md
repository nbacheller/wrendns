# Shadow AI detection (M37) — design

Status: design only (T37.1, fork #42). ADR-1055 to ADR-1059, all Proposed 2026-11-19. No code is written by T37.1. Requirement IDs are reserved now so test names can trace from the first task, and are written into `spec/01` when the owner accepts the design: **OBS-904** Shadow AI detection, findings and visibility; **OBS-905** the scheduled digest; **FLT-903** the AI policy per group (Off, Allow, Monitor, Block); **FLT-904** Warn and its acknowledgement overlay. (Free on every branch on 2026-11-19; recheck at acceptance.)

Shadow AI is the use of AI services that the network's owner hasn't approved. This feature shows which devices, and through the CMDB which people, reach which AI services, and lets the owner allow, monitor, warn about or block them per group. DNS is a good vantage point because every AI service starts with a lookup, and WrenDNS already knows the device, its group, the time, the content categories (T24.29) and the device's rhythm (the anomaly engine). It is also a limited one: DNS tells you *which known service* a device reached and roughly *when and how much*, not *what was typed*, and for most vendors not *which account*. The design says so wherever a user could otherwise assume coverage it doesn't have.

"Shadow" already means something in WrenDNS: a list in **shadow mode** (`ListMode::Shadow`, OBS-018) is compiled and counted but never blocks. To keep the two apart, the feature is called **Shadow AI** and its watch-only policy is called **Monitor**. The list mode keeps its name; its UI label becomes "Shadow (try a list)" so the two never appear side by side as the same word.

## Goals and non-goals

### Goals

1. **Know what is in use.** For each group and device: which AI services, of which kind, first and last use, active time per day, and whether it looks interactive or automated, with the evidence behind every statement.
2. **Govern it per group.** Allow, Monitor, Warn or Block per kind of service, with per-service overrides, per-device exceptions and sanctioned tenants where the vendor's hostnames make that possible.
3. **Be honest about what DNS cannot see.** Every page and report says what is not visible: tenants that share hostnames, AI inside other SaaS, devices bypassing the network's DNS. An empty page must never read as "no AI use".
4. **Cost nothing on the query path.** Detection runs on the telemetry thread. Blocking uses the existing filter snapshot. The idle memory gate (ADR-1031, 32 MiB) is untouched when the feature is off.
5. **Respect privacy and the law.** Off until an admin turns it on and acknowledges a monitoring notice; off at privacy level 1 and above; exclusions honoured; no content, prompts or filenames ever recorded.
6. **Useful to a household, a small business and an MSP**, with the same node features for all three and the paid part limited to timeliness and hosted convenience (ADR-1052).
7. **Agent-ready.** Read tools in the MCP catalog; policy changes as plans only (AGT-001..005, ADR-994 §8).

### Non-goals

- **No TLS inspection, no proxy, no header injection.** OpenAI's and Anthropic's tenant restrictions need a proxy to add headers after decrypting traffic. WrenDNS does not decrypt and will not start.
- **No content inspection.** No prompts, responses, file contents or filenames, from DNS or from the endpoint agent.
- **No probing.** Local LLM servers are found passively or from imported scans only (ADR-907).
- **No risk score.** Vendor-stated, dated, linked facts only (ADR-1055).
- **No third-party categorisation feed in the node**, open or commercial (ADR-1055).
- **No automatic new blocking from a catalog update.** An update can add names to a kind the operator already blocks; it never changes a group's policy.
- **No ECH stripping and no RDATA rewriting** (see the threat model).
- **Not marketed for monitoring children.** The software has no age rule of its own: privacy.md §3 expects minors on operators' networks and makes the operator responsible for monitoring law, and ADR-067 already sells parental blocking. How Shadow AI's docs position children is an owner decision (see "Minors").

## User stories

1. **A household.** An adult runs a two-node cluster at home and works from home on a personal laptop. They want to know which AI services the adults' devices and the smart-home gear talk to, and to keep their own work on the one assistant they pay for. They turn Shadow AI on (acknowledging the notice), leave every group on Monitor, and see after a week: "study-laptop (192.0.2.21) used Example Chat on 5 days, about 3 h in all. Likely." and "living-room-speaker (192.0.2.40) reaches Example Voice AI. OS assistant present." They set the Adults group to Allow for the assistant they chose and Block for the rest of the chat kind. Their phones show "Private Relay: opted out by this network" (the default special-names switch), so they stay fully visible; a visitor's laptop with its own DoH resolver set by IP shows "partial: query rate dropped", so its absence from the page proves nothing.
2. **A small business.** An office of 25 staff, a sanctioned GitHub Copilot Business subscription and an Azure OpenAI resource. The owner sets the Staff group to Warn for chat assistants, Allow for the sanctioned Copilot plan (its `business.githubcopilot.com` hosts) and the resource `example-res.openai.azure.com`, and Block for personal Copilot plans. Staff laptops have the browser add-on (T24.39); opening a chat assistant shows a short notice ("This network's policy asks you to use the company assistant. Continue for 8 hours?"), and the acknowledgement is logged. The weekly digest lists the services used, new ones first. The page says plainly that WrenDNS can't tell the company's ChatGPT workspace from a personal account.
3. **An MSP.** A managed-service provider runs WrenDNS at a dozen client sites. At each site the same node features apply. Through WrenDNS Cloud Business (later phase, opt-in per site) the MSP gets a cross-site view of counts: services in use per site and group, new services this week and visibility gaps, with no device or person names leaving the site. They use the MCP read tools to have an agent draft each client's monthly review; any policy change it proposes waits as a plan for a human.

## The catalog

### Taxonomy

Each entry has a `kind`. What DNS can attribute differs by kind:

| Kind | Examples (hostnames illustrative; each entry is verified from the vendor's own documentation at build) | Attribution by DNS |
|---|---|---|
| `chat` | consumer chat assistants on the web and in apps | good for the service, poor for the tenant |
| `api` | model APIs and SDK endpoints; cloud forms such as `<resource>.openai.azure.com`, `bedrock-runtime.<region>.amazonaws.com` | good; the strongest "automated" signal |
| `coding` | coding assistants and IDE plug-ins | good; GitHub Copilot separates plans by host |
| `embedded` | AI features inside other SaaS (an office suite's assistant, a chat or notes product's AI) | none or shared; listed for awareness only |
| `model_hosting` | model and file hosting, model registries and their CDNs | a download is evidence of a local model, a page view is not AI use |
| `agent` | agent and automation platforms | weak: most of their traffic is not AI |
| `local` | self-hosted LLM servers on the LAN | not a domain entry; matched in the inventory and CMDB |

### Entry schema (ADR-1055)

Files `presets/ai/<kind>.toml`, compiled into the binary, code-reviewed, with a `catalog_version` (ADR-995's model). An entry:

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
ambient = [                         # contacted without user action, per OS family (lab-measured, T37.3)
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
- **Ambient, per OS family.** An `ambient` host is recorded with the OS family (and the version it was measured on) and whether it is a built-in **assistant** host. It lowers confidence only on devices of that family (from device identification); on other devices it counts normally.
- **URLs.** `evidence` and `enterprise_option.url` are the only URLs in an entry. The node never fetches them; the UI renders them as links that show their domain. The validator accepts only `https://` URLs on the entry's vendor domains or a fixed allowlist (for example `docs.github.com`, `learn.microsoft.com`), so a stolen catalog key cannot ship a phishing link.
- **`tenant_split = "hostname"`** carries `enterprise_hosts` and `consumer_hosts` (GitHub Copilot's `*.individual.`, `*.business.` and `*.enterprise.githubcopilot.com`) or a `tenant_pattern` (Azure OpenAI's per-resource subdomain). Hosts every plan shares (sign-in, telemetry, the GitHub API) are `dependency` rules of each plan's entry, so "Allow Business, Block Individual" never blocks what Business needs. Copilot's per-plan hosts are enforced by GitHub's subscription-based network routing (enforced since 4 November 2024; extended to the coding agent from 27 February 2026); older IDE plug-ins that predate it reach the shared hosts, and the help topic says so. `header_only` records that the vendor offers tenant restriction only by a proxy-injected header (ChatGPT's `ChatGPT-Allowed-Workspace-Id`, Anthropic's `anthropic-allowed-org-ids`), so the UI can say so.
- **`kind = "local"`** entries carry `ports` and `mdns_patterns` instead of rules (see detection).
- **Facts, not scores.** `tiers` hold what the vendor states, with the date and the link. The UI shows "Example AI states (2026-11-19, link): consumer chats may be used for training unless you opt out". Examples the first catalog must capture correctly: OpenAI's API and business plans are not trained on by default, with 30-day abuse-monitoring retention for most endpoints; Anthropic's consumer plans are used for training when the user allows it, a choice announced on 28 August 2025 that existing users had to make by 8 October 2025, with retention up to five years when allowed and 30 days otherwise (recorded as `trains_on_inputs = "user_choice"`, since the vendor's page does not state the toggle's default); DeepSeek's policy stores data on servers in the PRC.

### Validator (refuses a catalog, at build and for any update)

- A rule whose domain is a public suffix, checked against the Public Suffix List **including its private section** (so `vercel.app`, `workers.dev`, `pages.dev`, `github.io`, `netlify.app`, `herokuapp.com` and `hf.space` are refused as subtrees), or a registrable domain on the catalog's **shared-infrastructure denylist** (CDN and cloud fronts such as `cloudfront.net`, `azureedge.net`, `azurefd.net`, `blob.core.windows.net`, `windows.net`, `challenges.cloudflare.com`, `cloudflare.com`).
- A subtree rule on a **protected parent**, by family: Google (`google.com`, `googleapis.com`, `gstatic.com`, `googleusercontent.com`), Microsoft (`microsoft.com`, `cloud.microsoft`, `office.com`, `live.com`, `bing.com`, `azure.com`, `windows.net`), GitHub (`github.com`, `githubusercontent.com`), Apple (`apple.com`, `icloud.com`), Amazon (`amazon.com`, `amazonaws.com`), Meta (`facebook.com`, `fbcdn.net`, `instagram.com`, `whatsapp.net`), X (`x.com`, `twimg.com`). Under these, only exact names or specific subtrees (`generativelanguage.googleapis.com`). The validator's tests include one refused entry per family (a Gemini entry with `||google.com^` among them).
- A `vendor` subtree rule on anything but an `ai_only = true` vendor's registrable domain.
- A hostname outside the vendor's own registrable domains without a recorded justification.
- A URL (`evidence`, `enterprise_option.url`) that is not `https://` on the entry's vendor domains or the fixed allowlist.
- An entry with no `evidence`. (A `checked` date more than 90 days older than `catalog_version` only **warns**: the build passes and the UI shows "facts not rechecked since <date>"; only missing evidence refuses.)
- More than the entry cap (2,000 services, 12,000 rules).

### Sources and licensing (ADR-1055)

- **In-house, authored from vendor documentation.** Each entry cites the vendor's network or allowlist page and its privacy or retention page. Where the data lives and under which licence depends on the packaging decision (ADR-1059): under the recommended option the release catalog is in this repository, AGPL, and the edits between releases are curated in the private cloud repository and published here at each release (delayed open); MySummitKeep, LLC can also license it commercially (ADR-1033).
- **No usable open feed exists.** UT1's `ai` category (via the olbat mirror) is about 75 flat registrable domains with no kinds or metadata, and its licence is unconfirmed at the source (the mirror says CC BY-SA 4.0); it is used only as a list of names to investigate by the weekly job, never copied. AdGuard's HostlistsRegistry is GPL-3.0 and is ruled out by the clean-room rule (AGENTS rule 6) and ADR-1033 §5; it is not used even as a reference. The AI-content blocklists (uBlock-style lists against AI-generated sites) target a different thing. NextDNS has no AI category.
- **Commercial feeds are not used in the node.** Cisco Talos and Umbrella have a Generative AI content category, DNSFilter and Sophos have one, Microsoft Defender for Cloud Apps catalogues more than a thousand generative AI apps (Microsoft's "Discover AI apps and data" page) scored on 90+ risk factors, Cloudflare Gateway has a Technology › Artificial Intelligence subcategory (ID 184), and OEM URL databases (zvelo, Webshrinker, BrightCloud) license per lookup or per database. Their terms normally forbid redistribution, a per-query lookup would send customers' names to a third party (privacy.md §3), and none fits the AGPL node. They set the scale a business buyer compares against: ours starts at 150 to 250 services and grows.
- **Supersedes** `presets/services/ai.toml` and ChatGPT's entry in `messaging.toml`. The `ai` category id and every existing service id (`claude`, `chatgpt` and so on) keep working through aliases (ADR-995 §7), so no configuration changes. An alias expands to **every** new entry that covers a name the old service covered: `chatgpt` expands to the chat app, the API and the upload entries, because today's `||openai.com^` also blocked `api.openai.com`; the existing `copilot` id means Microsoft Copilot (not GitHub Copilot) and keeps that meaning. T37.2's migration test compiles every existing id before and after and requires the blocked name set to be a superset. `||anthropic.com^` and `||x.ai^` become `vendor` rules: blocking is unchanged, reporting becomes more accurate.

### Keeping it current

- **Release cadence.** Each WrenDNS release carries the catalog of its day.
- **The weekly job** (a sibling of `scripts/check-catalog.py`, recorded-metadata tests never touch the network): resolves every rule and flags NXDOMAIN or dead names; fetches each evidence URL, extracts and normalises its main text (scripts, navigation, dates and tracking parameters removed) and diffs that, opening one grouped issue per week for vendors whose network or privacy page changed in substance, never one per noisy page; cross-checks candidate names from UT1's `ai` list and a project watchlist and opens a "candidate entries" issue. Nothing enters the catalog without a person's review.
- **The signed update channel** (ADR-1059, a later task): between releases a node may load a newer signed `ai-catalog` bundle. It is data only (patterns and metadata, no URLs the node will fetch), signed with a **dedicated catalog minisign key** separate from the release key (ADR-038, ADR-046), with a monotonic `catalog_version` (no rollback), a schema gate and the same validator. The primary fetches it and replicas receive it with the configuration (ADR-994 §10); a failure keeps the last good catalog (FLT-004). An admin can also upload the file by hand, for offline sites. ADR-1059 **amends ADR-995** for this one bundle: ADR-995 rejected runtime catalogs as "a second thing that can fail, and an injection path for URLs"; the bundle carries no URL the node fetches and only validator-checked display links, fails closed to the compiled catalog, is bounded by the validator, and never turns on blocking that the operator hadn't already chosen for that kind or service. The fetch is a new outbound connection **to MySummitKeep** (the node's IP and a subscription identifier), so privacy.md §3 gains a "Catalog updates" bullet before T37.13 ships, and the channel is off unless an admin turns it on. Entitlement is checked by the distribution server; the AGPL node code only verifies the signature and the version, with no licence check to remove.
- **Local entries.** An admin can add `[[ai_service]]` entries in the configuration (same schema, `source = "local"`), for an internal tool or a service the catalog lacks, and can suggest it upstream through an issue. Nothing is sent from the node.

### Size

About 150 to 250 services and 1,000 rules at first release; about 1,000 services and 6,000 rules at enterprise breadth. Measured at 12 bytes per domain in the snapshot (ADR-1017): about 12 KB at first release, about 72 KB at 1,000 services. Embedded TOML: about 0.15 MB, growing to about 0.8 MB (zstd-compressed if the image delta matters); both under 4 % of the 25 MiB image gate.

## Detection

### Where it runs (ADR-1056)

A new **Shadow AI sink** on the telemetry thread, built like the OBS-018 shadow sink (`crates/wrendns/src/shadow.rs`) and fed by the same drained `QueryEvent`s. It has its own small compiled **attribution map** (an FST from reversed name to a `u16` service-and-role index), built only while the feature is on, looks up each event's name (a suffix match, so up to one probe per label, typically 2 to 4), and keeps bounded state per device and service. Nothing is added to the query path and `QueryEvent` does not grow. Blocking and Warn use the ordinary filter snapshot (see policy). Rejected: reusing a shadow-mode list (attribution only at list level, and every event re-decided), and tagging the service on the query path (new work per query, AGENTS rule 4).

The sink sees what the other analytics see: `[exclusions]` drops an event before every sink, so an excluded device or name is invisible to Shadow AI (the page says so); `[exclusions.log]` keeps events for analytics, so Shadow AI still sees them.

**Bounded against floods.** Besides the 4,096-pair cap, at most 64 services per device and 1,024 devices per service are tracked; a device past its cap keeps its existing pairs and counts the rest as "more services, not tracked". Pairs that already reached Likely, or whose day bitmap has been sent to the primary (below), are evicted last, so a flood from spoofed source addresses cannot erase evidence that has already been merged.

### In a cluster (ADR-1056)

Clients usually get both resolvers by DHCP and split their lookups, and Kubernetes runs several resolver pods, so one node's view of a device is partial. Findings are therefore made on the **primary** from merged evidence:

- Each node's sink keeps, per (device key, service, day), a **288-bit day bitmap** (36 B, one bit per 5-minute period) plus the role bits seen. Bitmaps OR-merge, so the same period seen by two nodes counts once and nothing is double-counted.
- The primary pulls each member's changed bitmaps on the alert interval through the same federated read the alerts use (ADR-994 §10), and computes confidence, active time (set bits × 5 minutes), first use and the alert there. A member that misses a pull sends its bitmaps on the next one; a member down longer than its tracker holds loses only its share of that day.
- **First seen** per (group, service) and per (device, service) is a row in the primary's store, replicated to eligible nodes like other state, never an in-memory tracker entry: a restart, an eviction or a failover does not fire the alert again.
- An **emergency (publish-nothing) primary** (ADR-048) keeps collecting and merging but fires no Shadow AI alert and records no first-seen row until a normal primary is back; a newly promoted primary waits one full pull from every reachable member before it fires.
- A single node is the same model with one member.

### Signals

| Signal | What DNS shows | Strength | Design |
|---|---|---|---|
| First use | the first lookup of a catalog hostname by a device or group | strong for catalogued services | requires a use role (below); quiet for the first day after a fresh start |
| Volume | lookups, which follow the TTL, not requests | weak as a count | reported as **active time**: distinct 5-minute periods and active days, "about". Never "N prompts" or "N requests". |
| Interactive or automated | roles, device class, time-of-day spread, rhythm | medium from roles, weak from rhythm | classified in order: roles (api-only with no static or auth suggests automated); device class from identification (server or headless versus laptop or phone); activity outside the device's usual hours over 7 days; rhythm from the anomaly engine's bin arithmetic (`rhythm_bin`, `RHYTHM_EDGES_MS`) at the service's hostname, not its registrable domain. Shown as "looks like automated API use" with the evidence. `coding` is its own kind, so IDE use is not called automated. |
| New service never seen | catalog hits plus the first-seen domains feed | strong in the catalog, weak outside | candidates (below) |
| Outside the sanctioned list | service level always; tenant level only with `tenant_split = "hostname"` | strong at service level | the rest reads "tenant not visible to DNS" |
| Visibility | the Firefox canary and Private Relay names read against the `[special]` switches, DoH bootstrap names, a drop in the device's query rate, the endpoint agent | medium, as a coverage signal | a per-device visibility state; see below and the threat model |

**Visibility state, under the shipped defaults.** WrenDNS answers `use-application-dns.net` and `mask.icloud.com`/`mask-h2.icloud.com` with NXDOMAIN by default (`block_firefox_canary`, `block_icloud_private_relay`; DNS-019, ADR-904). With a switch on, a canary or Private Relay lookup means the network told that device to stay on this resolver, and the device shows **"opted out by this network"**, at full visibility. Only with the switch off does the same lookup set **partial**. DoH bootstrap names (a public resolver's DoH hostname) set partial in either case. Clients that reach a resolver by a hard-coded IP address (Android Private DNS set by address, apps with built-in DoH) make no telling lookup at all; only the rate-drop detector or the endpoint agent can notice them.

### Confidence

Deterministic and explainable, like ADR-019. Each finding carries its evidence and a level in words:

- **Confirmed**: the endpoint agent saw the URL or an upload.
- **Likely**: `app`, `api` or `upload` hostnames in at least 2 active 5-minute periods, or on at least 2 days, counted on the primary's merged day bitmaps (see "In a cluster").
- **Possible**: one period, or `auth` or `static` hostnames only.
- **Visited**: `vendor` hostnames only.
- **Candidate**: not in the catalog; heuristics only.

**OS assistant present.** Built-in assistants (the Edge Copilot sidebar, Windows Copilot, Gemini as Android's assistant, Apple Intelligence's ChatGPT extension, Meta AI inside WhatsApp) reach AI hosts both at idle and when used. Their `ambient` hosts, recorded per OS family, put the device in a separate state, **"OS assistant present"**, shown on the device and the service but never counted as use. Use of the same service is still found from its non-ambient `app`, `api` or `upload` hosts, or from ambient hosts only when the day bitmap shows activity well above that OS family's measured idle pattern (T37.3 records the idle number of periods per day). Where the lab cannot separate idle from use for a host, the help topic says so rather than guessing.

Lowered by: an `ambient` hostname on a device of the OS family it was measured on (contacted by an OS or browser without the user, measured in a lab before the catalog ships, T37.3); uncertain identity (address only, a randomised MAC flagged by the inventory, ADR-910, or a shared address behind NAT, a guest network or a VPN concentrator); a device class suggesting OS background traffic. Visibility gaps never raise or lower a finding; they qualify claims of absence.

A device "used" a service only at Likely or better. Example finding: "laptop-07 (192.0.2.10, owner: set in the CMDB) used Example Chat for the first time: chat.example.com and its static host in 3 periods between 09:10 and 09:40. Not sanctioned for the Staff group. Likely."

### False positives the design guards against

Browser prefetch and preconnect; link previews built on the device by messengers; OS and browser assistants contacting AI hosts at start-up; reading a vendor's marketing or docs; shared CDN and challenge hosts (never catalogued); AI inside SaaS (never counted); Hugging Face pages and third-party Spaces (`model_hosting`, `ai_only = false`, a page view is not use); automation platforms (`ai_only = false`, Monitor display only, never in a one-click "block all AI").

### Naming the device and the person

The finding stores the stable key at detection time: the CMDB CI id when the CMDB is on, else the MAC, else the address with a time. The device's name and the CMDB `owner` are resolved **at read time**, so renames follow. The group comes from `explain::resolve_identity`. A person is named only from the CMDB `owner` attribute, which is set by hand; WrenDNS never infers a person from a host or router name. Findings never write to the CMDB (DSC-901).

### Unknown AI services (candidates)

A low-confidence list built from the first-seen domains feed and name heuristics (labels with `gpt`, `llm`, `chat`, `copilot`, `agent`; the `.ai` TLD, which is Anguilla's and widely used, so weak). Shown on the page under "Possibly AI, not in the catalog", never alerting, with "Add to local catalog" and "Not AI" (remembered). Nothing leaves the node.

### Local LLM servers

- **DNS from the host itself (v1):** a LAN device resolving a model registry or a model CDN (`download` role in `model_hosting`) is rated "a model was downloaded here".
- **Imported scans (v1, M25 decision 11a):** the catalog's `local` entries list ports, verified per product before shipping. Ollama's default port 11434 is distinctive and Ollama binds to loopback unless `OLLAMA_HOST` is set, so seeing it from the network also raises "an unauthenticated model API is exposed to your network". Generic ports (8000, 8080, 3000, 7860) are low confidence unless DNS corroborates.
- **Later:** passive mDNS service types would need ADR-081 amended (it ignores service instances); SNMP's TCP listener table is outside the infrastructure-only poller. Both are deferred for low yield.
- **Never probe** (ADR-907). Findings are informational, attached to the device's CI, and name their source.

### The hot-path budget

Zero new work per query. On the telemetry thread, only while the feature is on: a suffix match per drained event, up to one FST probe per label (typically 2 to 4 probes, expected under a microsecond in all), plus a bit set for catalog hits. With the feature off the attribution map is not built and the sink is not registered. The task runs `make bench-smoke` (wrendns-telemetry is in its set) and measures the drain rate with the sink on and off on a Pi; a sink that cannot keep up drops its own work, never events for other sinks, and the page says counts are best effort under load.

## The endpoint-agent add-ons

The browser and endpoint agent (T24.39, #29) is the only WrenDNS component that can see past the hostname. It adds, under every limit #29 already sets (off for every group by default, turned on per group by an admin; a recording notice on the device; private windows not recorded; `history:read` in no default grant; every read audited; off at privacy level 1 and above unless allowed per group):

- **URL path class.** For catalogued AI hosts only: the path mapped by catalog patterns to a class (chat, project, settings, upload, API console), never the full path, never query strings. A Likely finding with an agent hit becomes **Confirmed**.
- **Upload events.** From `webRequest`: service, host, method, a size bucket (under 100 KB, under 1 MB, under 10 MB, larger) and the MIME type when present in headers. **Never content, never prompts, never filenames.** No content scripts read page text.
- **Tenant where the URL carries it.** Catalog `url_tenant_pattern` or an admin's own URL patterns (for example a workspace segment in the path). The agent never reads cookies or scrapes the signed-in account.
- **Visibility.** The agent reports whether the browser uses its own DoH, closing the browser half of the visibility gap.
- **The Warn interstitial** (next section).

The native device agent (all apps) stays deferred, as #29 recommends; without it, app traffic that bypasses the network's DNS is invisible.

## Policy modes and the Warn flow

### Modes (ADR-1057)

Per group, per kind, with per-service overrides and per-device exceptions:

| Mode | DNS answer | Detection | Shown as |
|---|---|---|---|
| **Off** | unchanged | none for this group | — |
| **Allow** (sanctioned) | unchanged | counted as sanctioned use | "Sanctioned" |
| **Monitor** | unchanged | findings, page, digest, alert | "Not sanctioned" |
| **Warn** | blocked until acknowledged, then allowed for a set time | as Monitor, plus acknowledgements | "Warn" |
| **Block** | blocked (the group's block response, EDE 15) | blocked attempts counted | "Blocked" |

```toml
# sketch; final names in T37.4
[groups.staff.ai]
mode = "monitor"                                   # default for every kind
kinds = { chat = "warn", api = "monitor", coding = "monitor", agent = "monitor" }
services = { "github-copilot-business" = "allow", "github-copilot-individual" = "block" }
sanctioned_tenants = ["example-res.openai.azure.com"]
warn_ack_hours = 8
warn_without_agent = "monitor"                     # monitor | block
```

- **Compilation.** Kind-level lists `ai-<kind>` (at most five domain kinds) plus one small list per service that some group names individually; `embedded` and `local` have no rules. A group's Block or Warn on a kind subscribes it to that kind's list; per-service Allow becomes a group-scoped allow that wins (spec/05 precedence); a sanctioned tenant is an exact or subtree allow. This keeps far below `MAX_LISTS` (1024) at any catalog size, where one list per service would not. Monitor needs no list.
- **`dependency` rules** are blocked only with their service, never on their own; `vendor` rules are blocked with Block only for `ai_only = true` entries, and never counted as use. A multi-product vendor's entry blocks its exact AI names and nothing of the vendor's other products.
- **"Block all AI" in the picker** blocks the `ai_only = true` kinds and services only.
- **Per-device exceptions** are ordinary device-scoped quick rules (ADR-067), so the most specific scope wins and they expire on the server.
- **Explain** and the device's Policy panel (T24.30) show the AI policy line that decided an answer.

### Warn

There is no HTTPS block page (spec/00: a page on HTTPS sites needs a locally trusted CA on every client), so Warn cannot be a DNS answer alone.

**Where Warn is allowed.** Warn is valid only for the `chat` and `agent` kinds (and services of those kinds). For `api`, `coding` and `model_hosting` it is a validation error with the reason: their traffic comes from SDKs, IDE plug-ins, desktop and mobile apps and scripts, none of which can show an interstitial, so Warn would just break them. Even in a `chat` Warn, only the entry's `app` and `upload` names are held; `api`, `auth`, `static` and `dependency` names stay answered, so a native app that reaches the service by its API name keeps working and is reported as Monitor would report it. The help topic says plainly: "Warn shows a notice in browsers with the add-on. Desktop and phone apps are not held; they are reported."

1. The service's `app` and `upload` names are blocked for the device, with EDE 15 and extra text naming the AI policy.
2. **With the browser add-on (T24.39):** the extension sees the navigation fail, asks the node "is `<host>` blocked for me, and why?", learns it is a Warn, and shows an interstitial with the group's message, the vendor-stated facts and the sanctioned alternative. "Continue for 8 hours" records an **acknowledgement** (device, service, time, expiry; no free text unless the group asks for a reason) through the device-scoped token (never an admin token), rate limited. The extension then retries the navigation; the node answers the service's names with a short TTL (the group's `block_ttl` is capped at 10 s for Warn names) so the client's cache does not hold the block, and the help topic tells users to reload if a page still fails.
3. **From any browser:** the `/unblock` landing page (T24.39) offers the same acknowledgement when the user opens it.
4. **Devices without the add-on:** an unexplained block would only look broken, so `warn_without_agent` decides: **Monitor** (recommended default) or Block. The page lists which devices in a Warn group have no add-on. The fallback is per device; on a device with the add-on, apps other than its browser are covered by the rule above (only browser names are held).
5. Acknowledgements show on the page and in the digest. An admin can set Warn to require approval instead (T24.39's "ask for access"), which turns it into a request.

**The acknowledgement overlay (not quick rules).** Acknowledgements are kept in their own small table, not as quick rules: quick rules are capped at 1,000 per cluster and shared with the operator's own (ADR-067), a service spans several registrable domains, each quick rule publishes a new configuration version, a Git-managed cluster refuses UI-made configuration (409 `gitops_managed`), and a quick-rule allow decides before every list, so it would also override threat lists. The overlay is:

- keyed by (device key, service), with an expiry; at most one row per pair, so its size is bounded by devices × Warn services (capped at 10,000 rows, oldest expired first);
- **state, not configuration**: written on the primary and replicated like other runtime state (the same path as quick-rule expiry and leases), so it works on a Git-managed cluster and publishes no configuration version;
- covering only the catalog entry's exact `app` and `upload` names; consulted only when a Warn list decided the answer (other queries never reach it), as one lookup in a small read-mostly map swapped atomically like the snapshot, so no snapshot is recompiled per acknowledgement; T37.9 benchmarks that branch (AGENTS rule 4);
- checked **after** the security lists: a threat-list or security-category block still wins over an acknowledgement (spec/05's order: security first, then the AI Warn list, then the overlay).

### Defaults for a new install (ADR-1058)

The feature is **off** on a new install and costs nothing. Turning it on is an admin's action and shows a one-time notice: what is recorded, that the operator is responsible for telling the people monitored, a link to the notice template. Once on, every group starts at **Monitor**, the issue's suggestion, with no blocking until an operator chooses it.

## UI

Every control ships with its UI, help topic and Playwright test in the same task (the fork's "UI for every feature" rule).

- **Shadow AI page** (top-level, under Insights): a header with the window, the visibility summary ("31 devices seen, 2 with partial visibility") and the limits text ("WrenDNS sees which AI services a device reaches by name. It can't see prompts, files, or which account is used for most services. Read more"). Sections:
  - **Services in use:** service, kind, groups, devices, active time, trend (sparkline), first seen, status per group (Sanctioned, Not sanctioned, Warn, Blocked), confidence. Sort by "new first".
  - **A service's detail:** the vendor-stated facts with dates and links, the hostnames and their roles, whether tenants are visible to DNS, devices using it with confidence and evidence, acknowledgements, and the policy per group with "Change policy".
  - **A device's view:** the same as a tab on the device's detail (Clients and the CMDB CI page), with its visibility state.
  - **Possibly AI, not in the catalog:** candidates with "Add to local catalog" and "Not AI".
  - **Local model servers:** the hosts with evidence and its source.
- **Group editor:** an "AI services" section with the mode per kind, per-service overrides (searchable), sanctioned tenants (only offered where `tenant_split = "hostname"`; elsewhere a line that the tenant isn't visible to DNS, pointing to the vendor's proxy-based control), Warn settings, and the cost line.
- **Settings → Shadow AI:** on or off, the notice acknowledgement, retention, the catalog version and its source (release or update), the update channel (later), local entries.
- **Alert rule `shadow_ai`:** fires once per service per group on the first Likely-or-better use of a service that isn't sanctioned for that group, evaluated on the primary from merged evidence with first-seen kept in the primary's store (see "In a cluster"), quiet for the first day after a fresh start (like `new_device`); a subject is the service and group. `shadow_ai_visibility` (off by default) for a `visibility_gap` finding. Mutes follow `[[anomaly_mute]]` with a service selector. Messages lead with the device and the plain fact (brand voice): "Example Chat used in Staff for the first time, by laptop-07. Likely. Open in WrenDNS."
- **The weekly digest:** new. A scheduled summary sent to chosen existing alert destinations: email (the `email` destination over SMTP already exists, so no new dependency or secret), Slack-compatible, webhook (JSON), and ntfy, Gotify and Pushover as a short text with a link to the page (their message limits cut the rest). Shadow AI is its first section: new services, services by active time, groups by unsanctioned use, acknowledgements, devices with visibility gaps and candidates; other sections (top blocked, new devices) can follow later. Per-device detail is in the digest, not the alert.
- **Help topics:** "What Shadow AI can and can't see", "Policy modes and Warn", "Sanctioned tenants", "Confidence levels", "Visibility and bypass", "Telling people you monitor AI use" (with the notice template), "Local model servers", "The AI catalog and its updates".

## Agent and MCP tools

Read tools (scope `shadow_ai:read`, in no default grant, because they name devices and people). For people signed in to the UI, per-device and per-person findings need the **operator** role or the dedicated `shadow_ai` permission an admin grants a Viewer; a plain Viewer sees service and group counts only:

| Tool | Purpose |
|---|---|
| `shadow_ai_summary` | services in use by group and kind over a window, with counts, active time, trend, visibility summary and the limits text |
| `shadow_ai_findings` | findings with confidence and evidence, filtered by group, device, service, kind, level and window |
| `get_ai_catalog` | the catalog or one entry: kinds, hostnames and roles, tenant split, vendor-stated facts with dates and links, catalog version and source |
| `ai_candidates` | the "possibly AI" list |

Plans (scope `config:write:groups`, applied by a human only, ADR-994 §8): `plan_ai_policy` (a group's mode per kind or service, sanctioned tenants, Warn settings), `plan_ai_local_entry`. Immediate op: `acknowledge_shadow_ai` (mark a finding reviewed, like `acknowledge_anomalies`). Turning the feature on, the notice acknowledgement, retention and the update channel are not for agents. Every tool goes through the same API (`/api/v1/shadow-ai/...`, OpenAPI regenerated), with `missingNodes` on federated reads.

## Privacy and legal

### Levels and exclusions (ADR-1058)

- **Off at privacy level 1 and above.** The analytics see names after the level is applied (`Hub::set_privacy`, ADR-102); a keyed hash of a full name cannot be suffix-matched, and matching before the hash would reveal exactly which services a device uses, which level 1 promises to hide. The issue's "hashed names at level 1" is not workable and is corrected here. At level 1 the page reads "Shadow AI needs privacy level 0". Per-group service counts with no device at level 1 are an open question.
- **Exclusions** apply as above; an excluded device is never in Shadow AI.
- **The query log holds the same names.** At level 0 the query log already records every lookup by every device, including AI services' names, for its own retention. Shadow AI's gated scope and audited reads protect its summaries, not the underlying names; the docs and the turn-on notice say so, and point to `[exclusions.log]` and the query log's retention for operators who want less kept.
- **Retention:** findings and daily usage rows 90 days by default (7 to 365), acknowledgements 1 year; the in-memory tracker is bounded (see performance). Stored on the node, replicated like other analytics settings.
- **Backups.** Today a backup encrypts only stored secrets. Shadow AI rows (findings, day bitmaps, first-seen, acknowledgements) are **left out of a backup unless a passphrase is given**, in which case they are encrypted with the secrets (T37.5 owns this; the backup docs gain a line).
- **Access and deletion requests.** An admin can **export** (JSON) and **purge** every Shadow AI row for one device key, or for every device whose CMDB `owner` is one person, from the device's tab, the CMDB CI page or `POST /api/v1/shadow-ai/{export,purge}`; a purge is audited and replicated, and is not an agent operation (T37.7).
- **The endpoint agent's data** follows #29's rules; upload events carry no content and no filenames.

### Notice and employee-monitoring law

The terms already say the operator is responsible for "the laws that apply to monitoring the devices and people on your network" (terms §3), and privacy.md §3 says none of the node's data reaches MySummitKeep. Shadow AI is monitoring of people's internet use, so the docs and the turn-on notice say plainly that notice, and sometimes consultation, may be required, with examples (not legal advice):

- **New York** (Civil Rights Law §52-c, since May 2022): employers who monitor employees' internet access or use must give written notice on hiring, get an acknowledgement and post the notice; the Attorney General enforces it with civil penalties.
- **Connecticut** (§31-48d, rewritten by Public Act 26-73 from 1 October 2026, which repeals and substitutes the section): prior written notice of the types of electronic monitoring, now also naming the specific locations where it occurs, posted there, and given to employees hired on or after 1 October 2026 before they start. **Delaware** (19 Del. C. §705) requires prior notice of electronic monitoring.
- **California** (CCPA as amended by CPRA, employee data in scope since 1 January 2023): a covered business gives a notice at collection naming the categories of personal information and the purposes, which covers network-activity monitoring of employees.
- **UK** (ICO, "Employment practices and data protection: monitoring workers", October 2023): workers must in most cases be told before monitoring starts and why; consent is rarely a valid basis; a DPIA is expected for intrusive monitoring.
- **Germany** (BetrVG §87(1) No. 6): technical equipment objectively capable of monitoring conduct or performance needs the works council's agreement where one exists.
- **EU** generally: GDPR transparency (Art. 13) and, where national law adds rules, Art. 88.

The product ships two notice templates, a help topic, and the turn-on acknowledgement. The template shown matches what is turned on:

- **DNS only:** "This network records which AI services each device reaches by name, and when. It does not record what you type or upload."
- **With the browser add-on's Shadow AI data (T37.10):** "This network records which AI services each device reaches by name, and when. In browsers with the WrenDNS add-on it also records the kind of page used (for example chat or settings) and, for uploads, their approximate size and file type. It never records what you type, the files' contents or their names."

Both have optional fields for the places monitoring occurs and the date given (Connecticut), and a line on the categories and purposes (CCPA/CPRA). Counsel reviews this before Shadow AI is sold in any paid form (ADR-1033 item 6).

### Minors

The legal pages set no age rule for the software: terms §1 covers only who may make a Support Payment, privacy.md §2.4 covers only the Site, payments and support, and privacy.md §3 expects data "about minors who use devices on your network" to stay on the operator's node, with the operator responsible for monitoring law. Quick rules (ADR-067) are already documented for parental blocking ("block a video site on the kids' tablets", `docs/running.md`). The stance for Shadow AI is an owner decision; the design assumes the recommendation:

- **Recommended: the operator's responsibility; parental use through categories.** Shadow AI is not marketed for children and its stories are about adults' devices. A household may use it on its own network; the docs point parents to the `ai` category, groups and schedules for children's devices, which block without building a per-child usage record.
- **Alternative: "not for monitoring minors"**, a docs-only statement, since nothing in the terms enforces it.

Either way, the **MSP counts view** (T37.15) is where MySummitKeep first receives anything derived from users, and so where COPPA and GDPR Art. 8 must be reviewed (ADR-1052 §6); counts with no device or person keep that exposure small, and counsel reviews it before launch.

## The threat model

### Evasion: what makes AI use invisible

| Path | Effect | Response |
|---|---|---|
| Browser DoH or DoT to a public resolver | lookups never reach WrenDNS | with `block_firefox_canary` on (the default) Firefox stays on this resolver and the device shows "opted out by this network"; otherwise the canary, known DoH bootstrap names and the endpoint agent set "partial"; blocking bypass stays the existing "DoH, VPN, Tor and proxy bypass" category; never automatic |
| Resolvers hard-coded by IP (Android Private DNS set by address, apps with built-in DoH to an IP) | no telling lookup at all | only the rate-drop detector or the endpoint agent can notice; blocking outbound 853 and known DoH addresses at the router is documented, not done by WrenDNS |
| VPN, Tor, iCloud Private Relay | the device or its Safari traffic disappears | with `block_icloud_private_relay` on (the default) Apple devices turn Private Relay off here and stay visible; otherwise its names set "partial"; a **rate-drop detector** (new: the engine detects spikes only) sets "blind since"; a `visibility_gap` finding only under the conditions below; a blind spot, never proof of use |
| Mobile data, roaming | off the network | out of scope at home; WrenDNS Cloud's roaming resolver (M36) brings roaming devices back under their group's policy where the tenant uses it |
| Hard-coded resolvers in apps | lookups bypass the network | the same rate-drop signal; blocking outbound 53 and 853 at the router is documented, not done by WrenDNS |
| ECH (RFC 9849, keys in HTTPS records, RFC 9460) | hides SNI from on-path observers, not the name from the resolver asked | **no change**: WrenDNS already sees the name. Stripping ECH keys would rewrite RDATA on the hot path (ADR-114 leaves HTTPS records' `ipv6hint` as is for the same reason) and weaken users' privacy for nothing. Blocked names already get NODATA for HTTPS records. |
| AI inside a sanctioned SaaS | rides the host app's names | `embedded` entries say "not visible to DNS"; the browser agent's path class can help where the URL differs |
| A personal account on a shared-hostname service | indistinguishable from the company's | stated on the page; the vendor's proxy-based tenant control is the remedy |
| API calls through a cloud function or a sanctioned proxy | only the proxy's name is seen | out of scope; the proxy's own logs |
| Changing the device's MAC or name | breaks the per-device history | the CMDB's reconciliation; findings keyed by CI |
| A local model on the device | no lookups after the download | the `download` role and imported scans |

**When `visibility_gap` is raised.** A device going quiet is normal (sleep, leaving the house), so a gap needs both: (1) proof the device is **still present**: a current DHCP lease renewal, a neighbour-table or ARP entry, or a fresh inventory sighting (M25) during the quiet period; and (2) a **known bypass sign** for that device: a DoH bootstrap name, the canary or Private Relay names with their switch off, or the endpoint agent reporting the browser's own DoH. The finding states only those facts ("laptop-07 is on the network but has sent almost no lookups here since 14:20; it looked up a public DoH resolver's name at 14:18"). It never mentions AI use or links the gap to an earlier finding.

### Threats to the feature itself

- **A wrong accusation.** The costliest error. Roles, the ambient flag, confidence in words, evidence on every finding, people only from the CMDB, and "Likely" as the alert threshold.
- **False assurance.** Visibility per device and the limits text on every page, digest and tool.
- **A tampered catalog update.** Data only, a dedicated key, no rollback, the validator, no automatic new blocking, the compiled catalog as the fallback (ADR-1059).
- **Exposure of usage records.** They are sensitive (who uses which assistant when): a scope in no default grant, every read of a device's AI history audited, off at privacy level 1+, retention limits, left out of any backup without a passphrase, per-device export and purge. The query log holds the same names at level 0, and the docs say so.
- **Agent misuse.** Read tools only by scope; policy as plans; no agent can turn the feature on.
- **Defamation or accuracy claims about vendors.** Vendor-stated, dated, linked facts; no scores; counsel review before sale.
- **The Warn token.** Device-scoped, rate limited, can only allow its own device for its group's `warn_ack_hours`, and only the catalog entry's `app` and `upload` names, never past a security list.
- **A flood of spoofed sources.** Caps per device and per service, and merged or Likely pairs evicted last, so evidence already sent to the primary survives.
- **A stolen catalog key.** Display links are limited to https on vendor domains or the allowlist; the validator refuses big-tech subtrees; an update never changes a policy.

## Performance and memory

Against ADR-1031 (idle ≤ 32 MiB, loaded ≤ 128 MiB) and the 25 MiB image gate:

| Item | Cost | Notes |
|---|---|---|
| Query path | none, except one overlay lookup on answers a Warn list decided | Block and Warn are ordinary list membership; the overlay branch is benchmarked in T37.9 |
| Filter snapshot | about 12 KB at first release, 72 KB at 1,000 services | at most 5 kind lists plus individually named services |
| Attribution map | about 60 to 150 KB mapped at 6,000 names | built with the snapshot, shipped to replicas as one content-addressed blob |
| Catalog metadata | about 0.1 MiB at first release, 0.6 MiB at 1,000 services | parsed lazily, only when a group has an AI mode other than Off or the page or API is used; nothing at start-up when the feature is off |
| Tracker | at most 4,096 (device, service) pairs × about 128 B ≈ 0.5 MiB | first and last seen, today's 288-bit (36 B) day bitmap, role bits, rhythm bins; caps per device and per service; merged pairs evicted first, the least recent otherwise |
| Acknowledgement overlay | at most 10,000 rows × about 64 B ≈ 0.6 MiB | only with Warn in use |
| Store | daily rows per pair (36 B bitmap, role bits, first and last seen), 90 days: at most about 25 MiB on disk on the primary, a few days' unmerged rows on members | batched writes from the telemetry thread |
| Image | about 0.15 MB, growing to about 0.8 MB | zstd if needed |
| Telemetry thread | a suffix match per event (up to one FST probe per label), expected under 1 µs | only while on; bench-smoke and drain-rate measurement on a Pi |

The Pi's loaded figure from the GeoIP gate run was 60 to 65 MiB; Shadow AI adds at most about 2 MiB when on (about 1.5 MiB without Warn), and nothing when off. Each task reports its RSS and image deltas.

## Packaging and pricing (ADR-1059)

- **Core, free, AGPL** (ADR-1052 §1: everything on customer hardware is AGPL in this repository): the catalog in each release, detection, every policy mode including Warn, the page, the alert, the digest, the MCP tools, local entries, candidates and the endpoint add-ons. A household gets the whole feature. The node stays fully usable without any subscription.
- **Paid: the catalog subscription.** The signed update channel between releases (weekly target), with an update commitment (new services within a stated time after a request, vendor-fact changes reviewed weekly). The repository is public, so what the subscription can sell depends on where the edits between releases live. This is an owner decision (ADR-1059 point 3):
  - **(a) Recommended: delayed open.** The edits between releases are curated in the private cloud repository (ADR-1052 §2). The update bundle is licensed under the subscription terms; at each release the catalog of that day is published in this repository under the AGPL, so every release stays complete and nobody loses anything they had. A subscriber gets weeks of lead time on new services and fact changes, which a mirror of the public repository does not. This needs an explicit amendment to ADR-1052 §1 for **data delivered to customer hardware between releases** (the code stays AGPL, and so does every released catalog). A subscriber could still re-share a bundle; the terms forbid it, and the value lost is only the lead time.
  - **(b) A mirrorable support commitment.** Every edit lands in the public repository as it is made, the signed channel is a convenience anyone could rebuild, and the subscription is priced as support for the curation (a commitment and a contact), not as access. No ADR is amended.
  - Either way the subscription is included in Cloud Plus and Business, and sold per cluster per year for self-hosted sites. Prices are the owner's (idea: about $20 a year per cluster standalone, which under (b) reads as a donation-level support price).
- **Paid, later: the MSP view in WrenDNS Cloud Business.** An opt-in, per-cluster upload of **counts only** (services per group and kind, new services, visibility gaps; no device names, people, addresses or hostnames beyond the catalog id) to the tenant's portal, for cross-site review. This changes privacy.md §3 for those who opt in (a hosted-service section, ADR-1052 §6), is where COPPA and GDPR Art. 8 are reviewed, and runs in the separate cloud repository (ADR-1052 §2).
- **Not sold:** any risk score, any feed from a third party, any feature that needs the cloud for DNS (AGENTS rule 5).
- **Market position.** Cloudflare One is **free for up to 50 users** and its Gateway DNS policies can block the Technology › Artificial Intelligence subcategory (ID 184), so a small office already has a free, cloud-hosted DNS-level AI block; its Shadow AI report needs the gateway and, for the full analytics, TLS inspection. DNSFilter and Sophos sell a Generative AI DNS category; Microsoft Defender for Cloud Apps catalogues more than a thousand generative AI apps with risk scores. WrenDNS does not win on "block AI for free" (Cloudflare already gives that away). Its edge is the self-hosted node with no third party seeing the names, per-device evidence tied to the CMDB, Monitor and Warn rather than only block, honest limits and a free core; its gap is catalog breadth, which the subscription addresses. The subscription therefore has to be priced against "free from Cloudflare" for blocking and against Defender-class tools for discovery.

## Phased delivery

**Phase 1 — the MVP (DNS only, no new dependencies):** the catalog with roles and the validator, migrated from `ai.toml` with aliases (T37.2); the ambient-hostname lab measurement before release (T37.3); Allow, Monitor and Block per group and kind (T37.4); the sink, findings, confidence and visibility state (T37.5); the page, the `shadow_ai` alert and help topics (T37.6); the API and MCP read tools (T37.7); the privacy defaults, the notice templates, backup exclusion and per-device export and purge (T37.5, T37.6, T37.7; T37.14's product half); the in-cluster merge on the primary (T37.5).

**Phase 2:** the weekly digest (T37.8); candidates and local entries (T37.12); local LLM signals (T37.11); the rate-drop detector and `visibility_gap` (part of T37.5 if it fits, else here).

**Phase 3 (after T24.39):** Warn with the add-on and `/unblock` (T37.9); the endpoint add-ons: path class, uploads, URL tenants (T37.10).

**Phase 4 (paid):** the signed catalog update channel (T37.13); the MSP view in WrenDNS Cloud (T37.15).

## Open questions

1. Should level 1 get per-group service counts with no device, matched before the hash? It reveals per-group service use, less than level 0 but more than level 1 promises today.
2. Which real iOS and Android devices the ambient lab uses (VMs cannot reproduce Apple Intelligence or Android's assistant), and whether the owner's own devices may be used, with a go-ahead.
3. Does the weekly digest become a general WrenDNS digest (other sections) or stay Shadow AI only in v1?
4. Is a reason required on Warn acknowledgements for business groups?
5. Should the catalog subscription be sold before counsel's review of the vendor-facts wording? (Recommended: no.)
6. Does the MSP view need an MSP-level tenant spanning several customers' tenants (a reseller model), which hosted.md doesn't have?
7. Who curates: the owner alone, or contributors with review? The commitment in the subscription depends on it.
8. Should the agent's upload size buckets be configurable per group, or fixed?

## Owner decisions

Asked together at the start of M37, with "accept all recommendations", ordered by how much they block. The returned list in T37.1's report has the options; the recommendations are what this design assumes:

1. **Catalog source:** in-house, authored from vendor documentation, compiled into each release; no third-party feed. (Blocks T37.2.)
2. **Packaging and the catalog's licence between releases:** every node feature free and AGPL; the subscription is the signed update channel with (a) delayed-open curation in the private cloud repository and an amendment to ADR-1052 §1 for data between releases, or (b) a mirrorable support commitment. Recommended (a). (Decides where T37.2's curation lives.)
3. **Defaults:** off on a new install, turned on by an admin with a notice acknowledgement; every group then at Monitor. (Blocks T37.5.)
4. **Privacy level 1:** off at level 1 and above. (Blocks T37.5.)
5. **When a device "used" a service:** a use-role hostname in at least 2 active 5-minute periods or on 2 days, on evidence merged across the cluster on the primary, or agent confirmation; built-in assistants shown as "OS assistant present"; the ambient lab (with real iOS and Android devices) before the first release with detection. (Blocks T37.3 and T37.5.)
6. **Risk information:** vendor-stated, dated, linked facts; a stale date warns, it never blocks a release; no score. (Blocks T37.2's schema.)
7. **Tenants:** offered only where the vendor's hostnames separate them; plainly stated elsewhere. (Blocks T37.4.)
8. **The alert:** once per service per group on the first Likely use of an unsanctioned service, first-seen kept on the primary; per-device detail in the digest; `visibility_gap` off by default and only with presence and a bypass sign. (Blocks T37.6.)
9. **Minors:** the operator's responsibility, with parental use pointed to categories and groups, not marketed for children; or a docs-only "not for monitoring minors". Recommended the first. (Blocks T37.6's notice and T37.14.)
10. **Warn:** only for `chat` and `agent`, holding only browser names; through the add-on or `/unblock`; acknowledgements in their own replicated overlay checked after the security lists; Monitor fallback without the add-on. (Blocks T37.9, phase 3.)

## Sources

Repository: `presets/services/ai.toml`, `presets/services/messaging.toml`, `presets/categories/ai-crypto.toml`, `crates/wrendns-config/src/services.rs`, `crates/wrendns-config/src/schema.rs` (`ListMode::Shadow`), `crates/wrendns-config/src/validate.rs` (`MAX_LISTS`), `crates/wrendns-filter/src/snapshot.rs`, `crates/wrendns/src/shadow.rs`, `crates/wrendns-telemetry/src/anomaly.rs`, `docs/design/content-categories.md`, `docs/design/cmdb.md`, `docs/design/hosted.md`, `docs/design/network-inventory.md`, `docs/running.md` (Device anomalies, Alerts), `docs/legal/privacy.md`, `docs/legal/terms.md`, `spec/13`, `brand/README.md`, ADR-019, ADR-038, ADR-046, ADR-067, ADR-081, ADR-102, ADR-114, ADR-907, ADR-910, ADR-994, ADR-995, ADR-1017, ADR-1031, ADR-1033, ADR-1052; issues #42, #29, #41.

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
