# Shadow AI detection (M37) — design

Status: design only (T37.1, fork #42). ADR-1055 to ADR-1059, all Proposed 2026-11-19. No code is written by T37.1. Requirements (a new OBS-9xx for detection and FLT-9xx for the AI policy) go into `spec/01` when the owner accepts the design.

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
- **Not a tool for monitoring minors.** WrenDNS is for adults operating their own networks (terms §1 and §3). Parental controls already exist through categories; Shadow AI is not marketed for children and its docs say so.

## User stories

1. **A household.** An adult runs a two-node cluster at home. They want to know whether anything in the house talks to AI services and to keep the family's homework laptop on one assistant they chose. They turn Shadow AI on (acknowledging the notice), leave every group on Monitor, and see after a week: "homework-laptop (192.0.2.21) used ChatGPT on 5 days, about 3 h in all. Likely." They set the laptop's group to Allow for the assistant they chose and Block for the rest of the chat kind. A tablet with Private Relay on shows "partial visibility", so they know its absence from the page proves nothing.
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
ambient = []                        # hostnames contacted without user action (lab-measured)
enterprise_option = { exists = true, url = "https://example.com/enterprise" }
[service.tiers.consumer]
trains_on_inputs = "default_on"     # default_on | opt_in | off | unknown
retention = "as stated by the vendor"
region = "US"
jurisdiction = "US"
evidence = ["https://example.com/privacy", "https://example.com/network-requirements"]
checked = "2026-11-19"
```

- **Roles.** `app`, `api`, `upload`, `auth`, `static`, `download`, `vendor` (marketing, docs, status, careers), `dependency` (needed for the service to work, blocked only with it). Only `app`, `api` and `upload` count as **use**; `vendor` alone reads "visited the site".
- **`tenant_split = "hostname"`** carries `enterprise_hosts` and `consumer_hosts` (GitHub Copilot's `*.individual.`, `*.business.` and `*.enterprise.githubcopilot.com`) or a `tenant_pattern` (Azure OpenAI's per-resource subdomain). `header_only` records that the vendor offers tenant restriction only by a proxy-injected header (ChatGPT's `ChatGPT-Allowed-Workspace-Id`, Anthropic's `anthropic-allowed-org-ids`), so the UI can say so.
- **`kind = "local"`** entries carry `ports` and `mdns_patterns` instead of rules (see detection).
- **Facts, not scores.** `tiers` hold what the vendor states, with the date and the link. The UI shows "Example AI states (2026-11-19, link): consumer chats may be used for training unless you opt out". Examples the first catalog must capture correctly: OpenAI's API and business plans are not trained on by default, with 30-day abuse-monitoring retention for most endpoints; Anthropic's consumer plans train by default unless the user opts out (from September 2025), with retention up to five years when training is allowed; DeepSeek's policy stores data on servers in the PRC.

### Validator (refuses a catalog, at build and for any update)

- A rule whose domain is a public suffix, or a registrable domain on the catalog's **shared-infrastructure denylist** (CDN and cloud fronts such as `cloudfront.net`, `azureedge.net`, `azurefd.net`, `blob.core.windows.net`, `challenges.cloudflare.com`).
- A subtree rule on a **protected parent** (`googleapis.com`, `microsoft.com`, `cloud.microsoft`, `office.com`, `github.com`, `githubusercontent.com`, `apple.com`, `amazonaws.com`, `azure.com`). Under these, only exact names or specific subtrees (`generativelanguage.googleapis.com`).
- A hostname outside the vendor's own registrable domains without a recorded justification.
- An entry with no `evidence`, or a `checked` date more than 90 days older than `catalog_version`.
- More than the entry cap (2,000 services, 12,000 rules).

### Sources and licensing (ADR-1055)

- **In-house, authored from vendor documentation.** Each entry cites the vendor's network or allowlist page and its privacy or retention page. The data is ours, in this repository, AGPL like the code; MySummitKeep, LLC can also license it commercially (ADR-1033).
- **No usable open feed exists.** UT1's `ai` category (via the olbat mirror) is about 75 flat registrable domains with no kinds or metadata, and its licence is unconfirmed at the source (the mirror says CC BY-SA 4.0); it is used only as a list of names to investigate by the weekly job, never copied. AdGuard's HostlistsRegistry is GPL-3.0 and is ruled out by the clean-room rule (AGENTS rule 6) and ADR-1033 §5; it is not used even as a reference. The AI-content blocklists (uBlock-style lists against AI-generated sites) target a different thing. NextDNS has no AI category.
- **Commercial feeds are not used in the node.** Cisco Talos and Umbrella have a Generative AI content category, DNSFilter and Sophos have one, Microsoft Defender for Cloud Apps catalogues over 1,000 generative AI apps scored on 90+ factors, and OEM URL databases (zvelo, Webshrinker, BrightCloud) license per lookup or per database. Their terms normally forbid redistribution, a per-query lookup would send customers' names to a third party (privacy.md §3), and none fits the AGPL node. They set the scale a business buyer compares against: ours starts at 150 to 250 services and grows.
- **Supersedes** `presets/services/ai.toml` and ChatGPT's entry in `messaging.toml`. The `ai` category id and every existing service id (`claude`, `chatgpt` and so on) keep working through aliases (ADR-995 §7), so no configuration changes. `||anthropic.com^` and `||x.ai^` become `vendor` rules: blocking is unchanged, reporting becomes more accurate.

### Keeping it current

- **Release cadence.** Each WrenDNS release carries the catalog of its day.
- **The weekly job** (a sibling of `scripts/check-catalog.py`, recorded-metadata tests never touch the network): resolves every rule and flags NXDOMAIN or dead names; fetches each evidence URL and diffs a hash, opening an issue when a vendor's network or privacy page changes; cross-checks candidate names from UT1's `ai` list and a project watchlist and opens a "candidate entries" issue. Nothing enters the catalog without a person's review.
- **The signed update channel** (ADR-1059, a later task): between releases a node may load a newer signed `ai-catalog` bundle. It is data only (patterns and metadata, no URLs the node will fetch), signed with a **dedicated catalog minisign key** separate from the release key (ADR-038, ADR-046), with a monotonic `catalog_version` (no rollback), a schema gate and the same validator. The primary fetches it and replicas receive it with the configuration (ADR-994 §10); a failure keeps the last good catalog (FLT-004). An admin can also upload the file by hand, for offline sites. This answers ADR-995's rejection of runtime catalogs ("a second thing that can fail, and an injection path for URLs"): it carries no URLs, it fails closed to the compiled catalog, the validator bounds what it can add, and it never turns on blocking that the operator hadn't already chosen for that kind or service.
- **Local entries.** An admin can add `[[ai_service]]` entries in the configuration (same schema, `source = "local"`), for an internal tool or a service the catalog lacks, and can suggest it upstream through an issue. Nothing is sent from the node.

### Size

About 150 to 250 services and 1,000 rules at first release; about 1,000 services and 6,000 rules at enterprise breadth. Measured at 12 bytes per domain in the snapshot (ADR-1017): about 12 KB at first release, about 72 KB at 1,000 services. Embedded TOML: about 0.15 MB, growing to about 0.8 MB (zstd-compressed if the image delta matters); both under 4 % of the 25 MiB image gate.

## Detection

### Where it runs (ADR-1056)

A new **Shadow AI sink** on the telemetry thread, built like the OBS-018 shadow sink (`crates/wrendns/src/shadow.rs`) and fed by the same drained `QueryEvent`s. It has its own small compiled **attribution map** (an FST from reversed name to a `u16` service-and-role index), looks up each event's name once, and keeps bounded state per device and service. Nothing is added to the query path and `QueryEvent` does not grow. Blocking and Warn use the ordinary filter snapshot (see policy). Rejected: reusing a shadow-mode list (attribution only at list level, and every event re-decided), and tagging the service on the query path (new work per query, AGENTS rule 4).

The sink sees what the other analytics see: `[exclusions]` drops an event before every sink, so an excluded device or name is invisible to Shadow AI (the page says so); `[exclusions.log]` keeps events for analytics, so Shadow AI still sees them.

### Signals

| Signal | What DNS shows | Strength | Design |
|---|---|---|---|
| First use | the first lookup of a catalog hostname by a device or group | strong for catalogued services | requires a use role (below); quiet for the first day after a fresh start |
| Volume | lookups, which follow the TTL, not requests | weak as a count | reported as **active time**: distinct 5-minute periods and active days, "about". Never "N prompts" or "N requests". |
| Interactive or automated | roles, device class, time-of-day spread, rhythm | medium from roles, weak from rhythm | classified in order: roles (api-only with no static or auth suggests automated); device class from identification (server or headless versus laptop or phone); activity outside the device's usual hours over 7 days; rhythm from the anomaly engine's bin arithmetic (`rhythm_bin`, `RHYTHM_EDGES_MS`) at the service's hostname, not its registrable domain. Shown as "looks like automated API use" with the evidence. `coding` is its own kind, so IDE use is not called automated. |
| New service never seen | catalog hits plus the first-seen domains feed | strong in the catalog, weak outside | candidates (below) |
| Outside the sanctioned list | service level always; tenant level only with `tenant_split = "hostname"` | strong at service level | the rest reads "tenant not visible to DNS" |
| Visibility | DoH bootstrap names, the Firefox canary, Private Relay names, a drop in the device's query rate | medium, as a coverage signal | a per-device visibility state; see the threat model |

### Confidence

Deterministic and explainable, like ADR-019. Each finding carries its evidence and a level in words:

- **Confirmed**: the endpoint agent saw the URL or an upload.
- **Likely**: `app`, `api` or `upload` hostnames in at least 2 active 5-minute periods, or on at least 2 days.
- **Possible**: one period, or `auth` or `static` hostnames only.
- **Visited**: `vendor` hostnames only.
- **Candidate**: not in the catalog; heuristics only.

Lowered by: an `ambient` hostname (contacted by an OS or browser without the user, measured in a lab before the catalog ships, T37.3); uncertain identity (address only, a randomised MAC flagged by the inventory, ADR-910, or a shared address behind NAT, a guest network or a VPN concentrator); a device class suggesting OS background traffic. Visibility gaps never raise or lower a finding; they qualify claims of absence.

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

Zero new work per query. On the telemetry thread: one FST lookup per drained event (expected under a microsecond), plus a counter update for catalog hits. The task runs `make bench-smoke` (wrendns-telemetry is in its set) and measures the drain rate with the sink on and off on a Pi; a sink that cannot keep up drops its own work, never events for other sinks, and the page says counts are best effort under load.

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
- **`dependency` rules** are blocked only with their service, never on their own; `vendor` rules are blocked with Block but not counted as use.
- **"Block all AI" in the picker** blocks the `ai_only = true` kinds and services only.
- **Per-device exceptions** are ordinary device-scoped quick rules (ADR-067), so the most specific scope wins and they expire on the server.
- **Explain** and the device's Policy panel (T24.30) show the AI policy line that decided an answer.

### Warn

There is no HTTPS block page (spec/00: a page on HTTPS sites needs a locally trusted CA on every client), so Warn cannot be a DNS answer alone.

1. The service's names are blocked for the device, with EDE 15 and extra text naming the AI policy.
2. **With the browser add-on (T24.39):** the extension sees the navigation fail, asks the node "is `<host>` blocked for me, and why?", learns it is a Warn, and shows an interstitial with the group's message, the vendor-stated facts and the sanctioned alternative. "Continue for 8 hours" creates a device-scoped quick rule allowing that service for `warn_ack_hours`, through the device-scoped token (never an admin token), rate limited, and records an **acknowledgement** (device, service, time; no free text unless the group asks for a reason).
3. **From any browser:** the `/unblock` landing page (T24.39) offers the same acknowledgement when the user opens it.
4. **Devices without the add-on:** an unexplained block would only look broken, so `warn_without_agent` decides: **Monitor** (recommended default) or Block. The page lists which devices in a Warn group have no add-on.
5. Acknowledgements show on the page and in the digest. An admin can set Warn to require approval instead (T24.39's "ask for access"), which turns it into a request.

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
- **Alert rule `shadow_ai`:** fires once per service per group on the first Likely-or-better use of a service that isn't sanctioned for that group, quiet for the first day after a fresh start (like `new_device`); a subject is the service and group. `shadow_ai_visibility` (off by default) for a `visibility_gap` finding. Mutes follow `[[anomaly_mute]]` with a service selector. Messages lead with the device and the plain fact (brand voice): "Example Chat used in Staff for the first time, by laptop-07. Likely. Open in WrenDNS."
- **The weekly digest:** new. A scheduled summary sent to chosen alert destinations (email first; Slack-compatible and webhook as text). Shadow AI is its first section: new services, services by active time, groups by unsanctioned use, acknowledgements, devices with visibility gaps and candidates; other sections (top blocked, new devices) can follow later. Per-device detail is in the digest, not the alert.
- **Help topics:** "What Shadow AI can and can't see", "Policy modes and Warn", "Sanctioned tenants", "Confidence levels", "Visibility and bypass", "Telling people you monitor AI use" (with the notice template), "Local model servers", "The AI catalog and its updates".

## Agent and MCP tools

Read tools (scope `shadow_ai:read`, Viewer; in no default grant, because they name devices and people):

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
- **Retention:** findings and daily usage rows 90 days by default (7 to 365), acknowledgements 1 year; the in-memory tracker is bounded (see performance). Stored on the node, replicated like other analytics settings, never in an unencrypted backup.
- **The endpoint agent's data** follows #29's rules; upload events carry no content and no filenames.

### Notice and employee-monitoring law

The terms already say the operator is responsible for "the laws that apply to monitoring the devices and people on your network" (terms §3), and privacy.md §3 says none of the node's data reaches MySummitKeep. Shadow AI is monitoring of people's internet use, so the docs and the turn-on notice say plainly that notice, and sometimes consultation, may be required, with examples (not legal advice):

- **New York** (Civil Rights Law §52-c, since May 2022): employers who monitor employees' internet access or use must give written notice on hiring, get an acknowledgement and post the notice; the Attorney General enforces it with civil penalties.
- **Connecticut** (§31-48d, replaced by Public Act 26-73 from 1 October 2026) and **Delaware** (19 Del. C. §705) require prior notice of electronic monitoring.
- **UK** (ICO, "Employment practices and data protection: monitoring workers", October 2023): workers must in most cases be told before monitoring starts and why; consent is rarely a valid basis; a DPIA is expected for intrusive monitoring.
- **Germany** (BetrVG §87(1) No. 6): technical equipment objectively capable of monitoring conduct or performance needs the works council's agreement where one exists.
- **EU** generally: GDPR transparency (Art. 13) and, where national law adds rules, Art. 88.

The product ships a short notice template ("This network records which AI services each device reaches by name, and when. It does not record what you type or upload."), a help topic, and the turn-on acknowledgement. Counsel reviews this before Shadow AI is sold in any paid form (ADR-1033 item 6).

### Minors

WrenDNS is for adults (terms §1, privacy.md §2.4). Shadow AI is not marketed for monitoring children. A household may still use it on its own network, as the operator's responsibility; the docs point parents to categories and profiles for children's devices.

## The threat model

### Evasion: what makes AI use invisible

| Path | Effect | Response |
|---|---|---|
| Browser DoH or DoT to a public resolver | lookups never reach WrenDNS | visibility state from the Firefox canary, known DoH bootstrap names and the endpoint agent; blocking bypass stays the existing "DoH, VPN, Tor and proxy bypass" category; never automatic |
| VPN, Tor, iCloud Private Relay | the device or its Safari traffic disappears | Private Relay names and a **rate-drop detector** (new: the engine detects spikes only) set "partial" or "blind since"; a `visibility_gap` finding when visibility is lost right after AI use; a blind spot, never proof of use |
| Mobile data, roaming | off the network | out of scope at home; WrenDNS Cloud's roaming resolver (M36) brings roaming devices back under their group's policy where the tenant uses it |
| Hard-coded resolvers in apps | lookups bypass the network | the same rate-drop signal; blocking outbound 53 and 853 at the router is documented, not done by WrenDNS |
| ECH (RFC 9849, keys in HTTPS records, RFC 9460) | hides SNI from on-path observers, not the name from the resolver asked | **no change**: WrenDNS already sees the name. Stripping ECH keys would rewrite RDATA on the hot path (ADR-114 leaves HTTPS records' `ipv6hint` as is for the same reason) and weaken users' privacy for nothing. Blocked names already get NODATA for HTTPS records. |
| AI inside a sanctioned SaaS | rides the host app's names | `embedded` entries say "not visible to DNS"; the browser agent's path class can help where the URL differs |
| A personal account on a shared-hostname service | indistinguishable from the company's | stated on the page; the vendor's proxy-based tenant control is the remedy |
| API calls through a cloud function or a sanctioned proxy | only the proxy's name is seen | out of scope; the proxy's own logs |
| Changing the device's MAC or name | breaks the per-device history | the CMDB's reconciliation; findings keyed by CI |
| A local model on the device | no lookups after the download | the `download` role and imported scans |

### Threats to the feature itself

- **A wrong accusation.** The costliest error. Roles, the ambient flag, confidence in words, evidence on every finding, people only from the CMDB, and "Likely" as the alert threshold.
- **False assurance.** Visibility per device and the limits text on every page, digest and tool.
- **A tampered catalog update.** Data only, a dedicated key, no rollback, the validator, no automatic new blocking, the compiled catalog as the fallback (ADR-1059).
- **Exposure of usage records.** They are sensitive (who uses which assistant when): a scope in no default grant, every read of a device's AI history audited, off at privacy level 1+, retention limits, never in an unencrypted backup.
- **Agent misuse.** Read tools only by scope; policy as plans; no agent can turn the feature on.
- **Defamation or accuracy claims about vendors.** Vendor-stated, dated, linked facts; no scores; counsel review before sale.
- **The Warn token.** Device-scoped, rate limited, can only allow its own device for its group's `warn_ack_hours`.

## Performance and memory

Against ADR-1031 (idle ≤ 32 MiB, loaded ≤ 128 MiB) and the 25 MiB image gate:

| Item | Cost | Notes |
|---|---|---|
| Query path | none | Block and Warn are ordinary list membership |
| Filter snapshot | about 12 KB at first release, 72 KB at 1,000 services | at most 5 kind lists plus individually named services |
| Attribution map | about 60 to 150 KB mapped at 6,000 names | built with the snapshot, shipped to replicas as one content-addressed blob |
| Catalog metadata | about 0.1 MiB at first release, 0.6 MiB at 1,000 services | parsed lazily, only when a group has an AI mode other than Off or the page or API is used; nothing at start-up when the feature is off |
| Tracker | at most 4,096 (device, service) pairs × about 128 B ≈ 0.5 MiB | first and last seen, 24 hourly active-period counters, role bits, rhythm bins; the least recent pair evicted |
| Store | daily rows per pair, 90 days: at most about 25 MiB on disk | batched writes from the telemetry thread |
| Image | about 0.15 MB, growing to about 0.8 MB | zstd if needed |
| Telemetry thread | one FST lookup per event, expected under 1 µs | bench-smoke and drain-rate measurement on a Pi |

The Pi's loaded figure from the GeoIP gate run was 60 to 65 MiB; Shadow AI adds at most about 1.5 MiB when on, and nothing when off. Each task reports its RSS and image deltas.

## Packaging and pricing (ADR-1059)

- **Core, free, AGPL** (ADR-1052 §1: everything on customer hardware is AGPL in this repository): the catalog in each release, detection, every policy mode including Warn, the page, the alert, the digest, the MCP tools, local entries, candidates and the endpoint add-ons. A household gets the whole feature. The node stays fully usable without any subscription.
- **Paid: the catalog subscription.** The signed update channel between releases (weekly target), with an update commitment (new services within a stated time after a request, vendor-fact changes reviewed weekly). Because the repository is public, the subscription sells **timeliness and the commitment**, not exclusivity: each release still carries the catalog of its day. Included in Cloud Plus and Business; for self-hosted sites, a standalone per-cluster yearly subscription. Prices are the owner's (idea: about $20 a year per cluster standalone).
- **Paid, later: the MSP view in WrenDNS Cloud Business.** An opt-in, per-cluster upload of **counts only** (services per group and kind, new services, visibility gaps; no device names, people, addresses or hostnames beyond the catalog id) to the tenant's portal, for cross-site review. This changes privacy.md §3 for those who opt in (a hosted-service section, ADR-1052 §6) and runs in the separate cloud repository (ADR-1052 §2).
- **Not sold:** any risk score, any feed from a third party, any feature that needs the cloud for DNS (AGENTS rule 5).
- **Market position.** Cloudflare One's Shadow AI report needs its gateway and, for the full analytics, TLS inspection; DNSFilter and Sophos sell a Generative AI DNS category; Microsoft Defender for Cloud Apps catalogues over 1,000 apps with scores. WrenDNS's edge is the self-hosted node, per-device evidence tied to the CMDB, honest limits and a free core; its gap is catalog breadth, which the subscription addresses.

## Phased delivery

**Phase 1 — the MVP (DNS only, no new dependencies):** the catalog with roles and the validator, migrated from `ai.toml` with aliases (T37.2); the ambient-hostname lab measurement before release (T37.3); Allow, Monitor and Block per group and kind (T37.4); the sink, findings, confidence and visibility state (T37.5); the page, the `shadow_ai` alert and help topics (T37.6); the API and MCP read tools (T37.7); the privacy defaults and the notice (T37.14's product half).

**Phase 2:** the weekly digest (T37.8); candidates and local entries (T37.12); local LLM signals (T37.11); the rate-drop detector and `visibility_gap` (part of T37.5 if it fits, else here).

**Phase 3 (after T24.39):** Warn with the add-on and `/unblock` (T37.9); the endpoint add-ons: path class, uploads, URL tenants (T37.10).

**Phase 4 (paid):** the signed catalog update channel (T37.13); the MSP view in WrenDNS Cloud (T37.15).

## Open questions

1. Should level 1 get per-group service counts with no device, matched before the hash? It reveals per-group service use, less than level 0 but more than level 1 promises today.
2. Which OSes and browsers does the ambient lab measure, and on whose devices (lab VMs, or the owner's with go-ahead)?
3. Does the weekly digest become a general WrenDNS digest (other sections) or stay Shadow AI only in v1?
4. Is a reason required on Warn acknowledgements for business groups?
5. Should the catalog subscription be sold before counsel's review of the vendor-facts wording? (Recommended: no.)
6. Does the MSP view need an MSP-level tenant spanning several customers' tenants (a reseller model), which hosted.md doesn't have?
7. Who curates: the owner alone, or contributors with review? The commitment in the subscription depends on it.
8. Should the agent's upload size buckets be configurable per group, or fixed?

## Owner decisions

Asked together at the start of M37, with "accept all recommendations". The returned list in T37.1's report has the options; the recommendations are what this design assumes:

1. **Packaging:** all node features free and AGPL; the signed update channel and its commitment as the subscription; the MSP counts view in WrenDNS Cloud Business later.
2. **Catalog source:** in-house, authored from vendor documentation, compiled into each release; the signed update channel later; no third-party feed.
3. **Defaults:** off on a new install, turned on by an admin with a notice acknowledgement; every group then at Monitor.
4. **Privacy level 1:** off at level 1 and above.
5. **Warn:** needs the browser add-on or `/unblock`; without the add-on a Warn group falls back to Monitor; no plain-HTTP block page.
6. **When a device "used" a service:** a use-role hostname in at least 2 active periods or on 2 days, or agent confirmation; vendor pages alone read "visited".
7. **Tenants:** offered only where the vendor's hostnames separate them; plainly stated elsewhere.
8. **Risk information:** vendor-stated, dated, linked facts; no score.
9. **The ambient lab measurement before the catalog ships.**
10. **The alert:** once per service per group on the first Likely use of an unsanctioned service; per-device detail in the digest.

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
- New York §52-c: https://www.nysenate.gov/legislation/laws/CVR/52-C*2, https://www.mofo.com/resources/insights/211115-new-york-enacts-employee-monitoring-notification-law
- Connecticut §31-48d: https://law.justia.com/codes/connecticut/2022/title-31/chapter-557/section-31-48d/, https://www.ebglaw.com/insights/publications/reminder-changes-to-connecticuts-electronic-monitoring-statute-now-in-effect; Delaware §705: https://delcode.delaware.gov/title19/c007/sc01/
- ICO monitoring workers: https://ico.org.uk/media/for-organisations/uk-gdpr-guidance-and-resources/employment-information/employment-practices-and-data-protection-monitoring-workers-1-0.pdf
- BetrVG §87(1) No. 6: https://www.luther-lawfirm.com/en/newsroom/blog/detail/dauerbrenner-software-vs-mitbestimmung-87-abs-1-nr-6-betrvg, https://www.goerg.de/en/insights/publications/20-03-2024/it-co-determination-updates
