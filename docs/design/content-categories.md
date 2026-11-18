# Content categories and filter profiles: design notes (T24.29)

**Requirements:** FLT-901 (categories), FLT-902 (profiles) (Proposed; added to `spec/01`). **ADRs:** ADR-994 (scope and mapping), ADR-995 (catalog format and sources). **Task:** T24.29 in `spec/10`.
**Owner request:** 2026-11-18, with two screenshots of UniFi's content filtering (a category picker with groups and "n of m" counts, and a profile list and editor). Design only; no code in this change.

*Decision* means build it this way; amend the ADR if you can't. *Open* means the owner decides (listed in section 12). Read `spec/05` (groups, lists, safe search, services), ADR-040 (managed entries), ADR-973/976 (group sources), ADR-910 (randomised MACs) and `docs/design/network-inventory.md` first.

## 1. What it is, and what changed

The upstream scope note in `spec/10` (the quick-rules task, around line 272) said "Not parental controls: no screen time, no content categories". ADR-994 replaces the second half: **content categories are now in scope**. Screen time (per-device time budgets) stays out. A schedule (FLT-010) stays a time window, not a budget.

Two features, one model:

1. **Categories (FLT-901).** A catalog of named categories, grouped like UniFi's ("Adult & Sensitive Content", "Networking Infrastructure", ...), each backed by one or more maintained open lists. A group turns categories on; the lists behind them are downloaded once and shared.
2. **Profiles (FLT-902).** A named bundle of: who it applies to, ad block, safe search per engine, a filtering level (Off, Basic, Enhanced), a category selection and schedules. **A profile is a group.** No new object is invented: the Groups page becomes the profile list and editor, and the existing advanced fields stay behind an "Advanced" section.

## 2. The catalog, as data

`presets/categories/*.toml`, compiled into the binary like `presets/services/*.toml` (FLT-012), one file per catalog group. Format in ADR-995. A category has an id, a name, a catalog group, a one-line description (the info icon), and a list of **sources**. A source is a URL with a format, a licence, a cadence and size facts. Lists are never bundled: they are downloaded at runtime, on the node, from the maintainer's own host.

Only categories with a real, maintained source are offered. The rules for "real":

- the source is published openly, with a licence we can read over HTTPS;
- it has been updated within 90 days (checked at catalog build time, see T24.29 step 1);
- the repository is not archived.

A category failing these is **listed as not offered** (section 4), never as an empty or disabled checkbox.

### 2.1 Verified sources (checked 2026-11-18 by fetching the repository, licence and file listing)

| Source | Licence | Updated | Offered as |
|---|---|---|---|
| HaGeZi `dns-blocklists` | GPL-3.0 | daily (pushed 2026-11-18); each file says `Expires: 8 hours` | the main source: adult, gambling, piracy, social, fake stores, DoH/VPN bypass, dynamic DNS, URL shorteners, hosting, threat feeds (TIF), pop-up ads, ad and tracker tiers, per-vendor native trackers |
| HaGeZi `nrd` | GPL-3.0 | daily (pushed 2026-11-18); `Expires: 8 hours` | newly registered domains (NRD) and entropy NRD/DGA lists |
| StevenBlack `hosts` | MIT | pushed 2026-11-15 | `alternates/fakenews-only` (fake news) |
| Perflyst `PiHoleBlocklist` | MIT | pushed 2026-09-09 (older than 90 days is not reached: 70 days; re-check at build) | `SmartTV.txt`, `android-tracking.txt`, `AmazonFireTV.txt`, `SessionReplay.txt` (smart-TV and app trackers) |
| Bon-Appetit `porn-domains` | CC BY-SA 4.0 | daily (pushed 2026-11-18) | optional second adult source (438,863 domains; the file name changes, so the URL is found through `meta.json`) |
| OISD `nsfw.oisd.nl` | not stated on oisd.nl | hours | **not in the catalog** (no licence terms found); a person can add it as an ordinary list |
| Block List Project | Unlicense | **archived**, last push 2026-10-27 | **not in the catalog** (archived: not maintained; its category lists are also very large: malware 58.9 MB, porn 21.3 MB in AdGuard syntax) |
| Universite Toulouse Capitole "UT1" blacklists | believed CC BY-SA 4.0 (**unverified**: the site answered "en maintenance" and `Retry-After: 3600` on 2026-11-18) | the archive was modified 2026-11-17 | **Open**: the broadest real category set (about 60 categories: adult, gambling, dating, games, forums, social, shopping, ...), but one `tar.gz` of several hundred MB; needs an archive source type and a licence check (decision Q4) |

The formats: HaGeZi publishes AdBlock syntax (`adblock/`), hosts (default), domains-only (`wildcard/*-onlydomains.txt`), dnsmasq, RPZ and others. The catalog names the **domains-only** (`wildcard/`) file where one exists: it is the smallest (HaGeZi NSFW is 1.39 MB there against 1.64 MB in AdBlock syntax) and the cheapest to parse. Where a domains-only file doesn't exist, the AdBlock file is used. Every format named is already read by the list parsers (FLT-001).

### 2.2 Licences and attribution

Lists are **downloaded at runtime by the user's node and never bundled** in the binary, the image, the repository or the site, so their licences' redistribution terms (GPL-3.0 for HaGeZi, CC BY-SA for Bon-Appetit) don't apply to TelltaleDNS's own licence. The clean-room rule (AGENTS.md rule 6) is about code; a list is data the user chooses to fetch, the same as the `hagezi-pro` list already in the bundles.

What we owe anyway, shown in the UI and written in `docs/third-party-notices.md`:

- each source row in the Categories view shows **name, maintainer, licence and a link** (the "Sources" line under a category, the info popover, and a full table in a "Sources and licences" drawer);
- CC BY-SA sources (Bon-Appetit) show "Licensed CC BY-SA 4.0, (c) Bon-Appetit contributors" next to the checkbox, since attribution is the licence's one condition for use. Nothing is redistributed, so share-alike has nothing to apply to; the note says so;
- HaGeZi's README asks that NRD and other lists are used "as-is", with no guarantees: the NRD category description says so.
- a **catalog licence check** in CI (T24.29 step 1) fails a source with no recorded SPDX id.

### 2.3 Sizes, and which categories blow the budget

The budget (`spec/00` §5): RSS with 1M blocklist domains + 100k cache entries ≤ 64 MiB; the snapshot is ≤ 12 bytes per unique domain and mmapped (`spec/05` §2). A Pi 4 (2 to 8 GiB) is not tight; a 128 MiB Kubernetes pod or a Pi Zero 2 W (512 MiB) is. Entry counts below are from each file's own header on 2026-11-18; the memory column is entries x 12 bytes (an estimate to be **measured** in T24.29 step 2, and a build-time compile peak is separate: the external sort is bounded at 128 MiB on the controller).

| Category source | Entries | About (x 12 B) | Weight |
|---|---|---|---|
| HaGeZi NSFW | 85,282 | 1.0 MiB | light |
| HaGeZi anti-piracy | 62,383 | 0.7 MiB | light |
| HaGeZi gambling mini / medium / full | 51,679 / 102,937 / 669,823 | 0.6 / 1.2 / 7.7 MiB | light / light / **heavy** |
| HaGeZi social networks | 8,197 | 0.1 MiB | light |
| HaGeZi fake stores and scams | 18,807 | 0.2 MiB | light |
| HaGeZi DoH only / DoH + VPN + Tor + proxy bypass | 3,570 / 16,631 | under 0.2 MiB | light |
| HaGeZi dynamic DNS / URL shorteners / hosting | 1,516 / 9,765 / 1,168 | under 0.2 MiB | light |
| HaGeZi pop-up ads | 88,356 | 1.0 MiB | light |
| HaGeZi TIF mini / medium / full | 189,474 / 413,269 / 2,245,686 | 2.2 / 4.7 / 25.7 MiB | light / light / **heavy** |
| HaGeZi ad and tracker tiers: light, pro, pro++ , ultimate | (pro: 252,767 in the file header) | about 3 MiB for pro | light |
| HaGeZi native trackers, per vendor | 64 to 934 each | negligible | light |
| StevenBlack fake news | about 2,000 (59,664 bytes) | negligible | light |
| Bon-Appetit porn domains | 438,863 | 5.0 MiB | light |
| HaGeZi NRD 7 days | 2,438,879 | 27.9 MiB | **heavy** |
| HaGeZi NRD, 14 days (7 + 8-14) | about 5.4 million | about 62 MiB | **over budget** |
| HaGeZi NRD 21 / 28 / 35 days | up to about 13.7 million | up to about 157 MiB | **over budget** |
| HaGeZi entropy NRD/DGA 7 / 14 / 30 days | 552,899 / 1,189,239 / 2,776,494 | 6.3 / 13.6 / 31.8 MiB | light / heavy / **heavy** |

Decision: a source is **heavy** above 500,000 entries and **over budget** when the sum of every enabled source, across all groups, passes the `[filter] entry_budget` (default 1,000,000, the NFR number, a soft limit). The UI shows a running total ("Selected: 612,400 entries, about 7 MiB") and a bar. A heavy source asks for a confirmation that states the cost; an over-budget selection is **allowed with a warning on a node with enough memory** (the node reports its memory limit: cgroup limit in a container, total RAM otherwise), and **refused** when estimated snapshot size plus compile peak exceeds 50 % of that limit (the number is Open, Q8). NRD is offered at 7 days only ("New or Risky Domains": newly registered, last 7 days) and flagged heavy; longer windows are **not offered** until measurement shows a Pi 4 stays in budget. Full TIF and full gambling are offered as the "Extended" tier of their category, off by default, flagged heavy.

Each list also has the existing `max_list_bytes` cap (64 MiB). HaGeZi `nrd7` in domains-only form is 40.2 MB, under the cap; `dga30` is 64.3 MB, over it, so the catalog carries a per-source `max_bytes` where it differs from the default (the field exists on lists).

## 3. Categories not offered

UniFi's seven groups map to what we can back with an open, maintained, licensed list:

| UniFi-style group | Offered categories | **Not offered** (no open maintained source) |
|---|---|---|
| Adult and Sensitive Content | Adult (porn), Gambling, Piracy | Alcohol and tobacco, drugs and vaping (the only open lists are in Block List Project, archived), weapons, violence and gore (partial overlap in the NSFW lists only), dating (only in UT1, Q4), sex education, health |
| AI & Crypto | Cryptojacking is under Security | AI services and chatbots, cryptocurrency exchanges and wallets: no open list; **possible as authored bundles** (hand-written `presets/services/*.toml`, our own data) if the owner wants them (Q5) |
| Business & Professional | none | Business services, job search, finance, education, government, real estate, travel, shopping: no open list (UT1 has some, Q4) |
| Culture & Entertainment | Social networks, Fake news, (authored bundles that already exist: video streaming, music, gaming, messaging) | News, sports, music (open list), video (open list), games (open list), forums, blogs, lifestyle, religion |
| Networking Infrastructure | DoH, VPN, Tor and proxy bypass; Dynamic DNS; URL shorteners; Hosting providers; Most abused TLDs | Remote-access tools, cloud storage, CDN categories (a category that blocks a CDN breaks the web) |
| New or Risky Domains | Newly registered (7 days), DGA-like (7 days), Risky TLDs, Fake stores | Parked domains, newly seen (a "first seen" list: we have `first-seen domains` in analytics, T7.14; not a blocking source) |
| Security & Threat Protection | Malware, phishing, C2, scam and cryptojacking (threat feeds, three sizes) | Spyware (inside the threat feeds, not separately), ransomware (same) |

The Categories view ends with a collapsed "Not available" section naming these, so a person who looks for "Dating" learns why it isn't there ("no maintained open list; see ...") instead of finding a checkbox that does nothing. (A small data file, `presets/categories/not-offered.toml`, carries it.)

## 4. How a category maps onto the existing model

### 4.1 Lists, sources and groups

- A catalog **source** becomes a **managed list** (ADR-040, the same machinery as T7.5) named `cat-<source-id>`, with a new read-only field `owners`. One list can back several categories (HaGeZi TIF backs "Malware", "Phishing" and "Scam"), so ownership is a set: `owners = ["malware", "phishing"]`.
- A source list exists on a node only while **at least one group has a category using it** (the **materialisation rule**). The category list is fetched once; each group references it by name, so it is shared. Turning off the last category that uses it deletes the managed list and its stored file (`lists/cat-*.src.zst`).
- **The "every enabled list" default must not pick them up.** Today a group whose `lists` is omitted uses every enabled list (`schema.rs` `GroupConfig.lists`). A category list is never part of that default: effective lists of a group = (its `lists`, or every enabled non-category list when omitted) plus the lists of its enabled categories. Test `flt_901_category_lists_not_in_default`. Without this, turning on "Adult" for one profile would block it for the default group.
- A group's category selection is a new field `[group.content]` (ADR-995 §4): `level = "off" | "basic" | "enhanced"`, `categories = [ids]`, `tiers = { gambling = "extended" }`. It is a **group field**, so it is a managed entry like the group's other fields (T7.5), edited by the API, validated against the catalog and the lists limits, and replicated with the group.
- **Allow rules still win** (spec/05 precedence): a quick rule or an allow list unblocks a domain a category blocks. The explain view names the category: "blocked by category Adult (list cat-hagezi-nsfw)". The block record carries the list id as today (FLT-013); the category name is looked up from the owners set at read time, so nothing is added to the hot path.
- **Hot path.** Nothing changes per query: categories turn into list membership bitsets at compile time. The group-to-lists mapping is compiled into the snapshot as today. Safe search per engine is a compile-time filter on the engine table (section 6). `make bench-smoke` runs anyway in the build task because `telltale-filter` and `telltale-policy` change.

### 4.2 Relationship to ADR-040, files-win and GitOps

A group defined in a config file has its `content` field in the file; the API refuses to change it (409 `set_by_file`, like any file field) and the UI shows "set by file". The catalog sources are managed lists the **server** creates and owns; a person cannot edit a category list's URL (it comes from the catalog) but can refresh it, put it in `shadow` mode (OBS-018) and see its statistics on the Lists page. A file may also name a category list in `lists` directly by its `cat-` name: validation error ("use `content.categories`").

### 4.3 List overlap (T24.28)

T24.28 (`feat/t24.28-list-overlap`, ADR-992 expected) measures how much of one list another covers. At the time of writing the branch holds no ADR-992 and no task text beyond its name, so this design **uses only the idea** and states its needs for when it lands:

- the Categories view shows, for a selected source, "N entries, M also in the lists you already use" when T24.28's per-list overlap API exists (a column, hidden if the API is missing);
- two categories sharing a source (TIF) show no double count in the entry total: the total is the union of distinct sources, not the sum over categories;
- the catalog check in CI reports pairwise overlap between sources of different categories, to catch a category that is a subset of another (a reason to merge them).

T24.29 step 8 reads ADR-992 before building the overlap column and amends this section if its API differs.

### 4.4 `blocked_services` stays

FLT-012 bundles (a named service, e.g. TikTok: all the domains the app needs) remain a separate, hand-authored feature: a *service* is one app's domains, a *category* is a maintained list of a kind of site. The profile editor offers both ("Services" is a section next to Categories). Authored bundles that already exist (video, music, gaming, social, messaging) appear in the category picker **as read-only "Services" entries under Culture & Entertainment** so the picker is one place; selecting one writes `blocked_services`, not `content.categories`.

### 4.5 Cluster replication

Group fields replicate (ADR-047, ADR-054: a replica's UI forwards writes to the primary). The catalog is compiled into the binary, so it is the same on every node of one version; the N / N-1 rule (ADR-059) means a replica one version behind may not know a new category id: it **ignores unknown ids and reports them** (health reason `category_unknown`, degraded, naming the ids), and never fails the snapshot (rule 5: DNS never depends on anything else). Each node downloads category lists itself, as it does for lists today; a source that fails on one node shows on that node's list health.

## 5. The UI: a Categories view

Location: **Lists page, new tab "Categories"**, and reached from the profile editor's category picker (the same component). Grouped like the screenshot.

- A section per catalog group, with a **group checkbox** (checked, unchecked or indeterminate) and an **"n of m"** count ("2 of 4"). A click on the group checkbox selects or clears all its categories in this profile.
- A row per category: checkbox, name, an **info icon** (popover with the description, the entry count and the weight), and a **"Source" line** (e.g. "HaGeZi NSFW, GPL-3.0, updated 3 h ago") that opens the licence drawer.
- Heavy sources show a "Heavy: about 28 MiB" badge; selecting one opens a confirmation. A running total and a bar sit in the footer ("Selected: n entries, about x MiB, budget y").
- Tiers (Standard, Extended) are a small segmented control on the rows that have them (gambling, threats).
- A **search box**, **Select all** and **Deselect all** (these act on the visible rows, so a search then Select all selects the matches).
- Per-profile selection: the view always shows one profile's selection, chosen at the top ("Selection for: Kids"). Opened from the profile editor, it is already that profile. Opened from the Lists tab with no profile it is **read-only: a catalog browser** plus a "Use in a profile" button.
- "Not available" collapsed section (section 3).
- On the existing Lists page, a category's lists appear in the table with an **"Owned by category: Adult"** chip, their URL and the delete / edit actions disabled (a tooltip says why), refresh and shadow still enabled. A "Categories" filter chip lists only them.
- Every control has a help topic (`categories`, `category-sources`, `filter-profiles`) and a Playwright test in the same task (the standing UI rule).

## 6. Filter profiles

### 6.1 The list

The Groups page becomes a table: **Name, Source, Filter Scope, Safe Search, Schedule**. Chips with a "+N" overflow in the last three, like the screenshot.

- Source: the profile's networks and devices ("IoT VLAN", "Maya's iPad", "+3").
- Filter Scope: "Ad block", "Basic" or "Enhanced (14 of 31)", or "Off".
- Safe Search: the engines on ("Google", "YouTube", "+1").
- Schedule: the schedule names.
- The page keeps what it has: pause, priority, block mode, upstream group, lists, rewrites and the rest, under an **Advanced** section of the editor ("Advanced settings" links straight to today's form). Nothing is removed.

### 6.2 The editor, field by field, and the model

| UniFi editor field | Maps to | Status |
|---|---|---|
| **Name** | `group.name` | exists |
| **Source**: networks/VLANs and devices (multi-select with icons) | `group.networks` (CIDRs; the picker lists the Networks page's named networks), and for a device a managed `[[client]]` entry whose `groups` includes the profile (keyed by MAC, IP, client ID, Kubernetes workload or router name: ADR-973/976) | model exists; **picker is new** |
| **Ad Block** (checkbox) | membership of the category `ads` (catalog group "Privacy and Ads"), tier chosen in Settings (default `pro`, the list the bundles already ship) | **new** (named list set) |
| **Safe Search** per engine: Google, Bing, YouTube | `group.safe_search_engines = ["google","bing","youtube"]` (new); `safe_search = true` alone means every engine, as today | **gap**: today one switch |
| **Filtering: Off, Enhanced, Basic** | `group.content.level` | **new** |
| Enhanced = the category picker | `group.content.categories` | **new** |
| Basic = adult and malicious only | the catalog's `[[preset]] id = "basic"`, expanded at compile time (adult, malware, phishing, scam) | **new** (preset) |
| **Schedule** | `group.schedules` (FLT-010, weekly windows, T7.10); the editor links to the schedule grid | exists |
| warning for a private (randomised) MAC | from inventory `randomized` (ADR-910) | **new in UI**, data exists |

### 6.3 Gaps, designed

**Per-engine safe search.** `presets/safesearch.toml` already has engines with ids (`google`, `youtube`, `bing`, `duckduckgo`, `yandex`, `pixabay`). Add `safe_search_engines: Vec<engine-id>` to the group. Compile rule: if the list is non-empty it **is** the set of engines (and `safe_search` is implied true); if it is empty, `safe_search = true` means all engines (so every existing config means the same). Validation: unknown engine ids are an error naming the valid ones. The YouTube level (`youtube_restrict`) stays. The UI shows Google, Bing, YouTube first (as UniFi does) and the other three under "More engines". No hot-path change: the engine table is filtered when the group's rewrite map is compiled (the evaluation point, pipeline step 5, is unchanged).

**Ad block as a named list set.** An `ads` category in the catalog group "Privacy and Ads" with tiers `light`, `pro` (default), `pro-plus` and `ultimate` (each a HaGeZi list, tiers are alternatives: exactly one is active). The profile's checkbox sets `content.ads = true`; the tier is a Settings value (`[filter] ads_tier`, default `pro`), so the profile editor stays a checkbox. Existing groups using hand-added ad lists keep them; nothing is converted.

**Basic and Enhanced presets.** `level = "basic"` expands to the catalog preset (`basic`: Adult, Malware, Phishing, Scam; owner can change the members, Q2). `level = "enhanced"` uses `categories`. `level = "off"` is the default and means no category applies (the categories selection is kept so switching back doesn't lose it). A level change is a data change, no code path per level.

**Private-MAC warning.** The inventory already records `randomized` (the locally administered bit, ADR-910) and the OUI table returns no vendor for it. The device picker marks a device whose only key is a randomised MAC with a warning icon: "This device uses a private Wi-Fi address. The profile may not follow it if the address changes." Wording, when selected: it's a **warning, not a block**, with advice (turn off Private Wi-Fi Address for this network on the device, or give it a DHCP reservation and select by IP/name). Where the device is also known by a router name or a reservation, no warning is shown, since the selection then keys on that. A device whose key is a MAC and `randomized` shows the warning; one selected by `hostname:` or by IP does not.

**Devices picker.** Reads the Clients page and the inventory (`GET /api/v1/discovery/devices`, DSC-011, federated) plus named clients (`/clients`); a result row has an icon (device class: phone, tablet, TV, ... from identification), a name, the key kind, and the warning icon. Networks come from the Networks page (named networks). The multi-select is searchable and shows selected items as chips. It writes `group.networks` and the clients' `groups` in **one transaction** (a batch of managed entries with one `config_version` bump) and shows what changes first ("3 devices move from Default to Kids"; "Maya's iPad is already in Teens: with several groups the lists are the union and the settings come from the higher priority").

### 6.4 "The ability to add devices is nice as well"

Request of 2026-11-18, the same day. Adding a device is part of this view in two places: **in the profile's Source picker** ("Add device..." at the bottom: pick a discovered device, or type a name and MAC or IP, which creates the managed `[[client]]` entry (API-010) in the profile), and the Clients page's existing "Name a device". Both write the same managed client. Test: a device added from the picker appears on the Clients page in the group.

## 7. API

Under `/api/v1` (agent-ready, AGT-001..005; every change supports `?dryRun=true`, `If-Match`, a reason header):

| Route | Purpose |
|---|---|
| `GET /categories` | the catalog: groups, categories, descriptions, sources with licence, format, entries, weight, tiers, `notOffered[]`; per-node state of each source (downloaded, size, last change) |
| `GET /categories/budget?groups=...` | entries and an estimate of memory for a proposed selection, per group and total (distinct sources), with the node's memory limit |
| `GET /groups/{id}/content` , `PUT /groups/{id}/content` | the group's `level`, `categories`, `tiers`, `ads`; the PUT validates against the catalog and the budget, answers 422 with the field, and with `dryRun` the impact (newly blocked share of the last 24 h of queries from the group's devices, as for rules) |
| `GET /groups` , `PUT /groups/{id}` | gains `content` and `safeSearchEngines`; the `source` summary the list view needs (`sources: [{kind, label, icon, randomized}]`), computed on the server so the table needs one call |
| `GET /lists` | each list gains `owners: [categoryId]`; owned lists refuse edit and delete (409 `owned_by_category`) |
| `GET /profiles/devices` | the picker's data: networks and devices with icon, key kind, `randomized`, current group |

OpenAPI regenerated (`UPDATE_OPENAPI=1`). Config schema (`UPDATE_SCHEMA=1`): `[[group]] content = {level, categories, tiers, ads}`, `safe_search_engines`, `[filter] entry_budget`, `ads_tier`. Roles: **viewer** reads the catalog; **operator** changes a group's `content` (it is a group edit, ADR in `spec/08` §RBAC: operators manage lists, clients and groups); the category lists the server creates are made by the server under the operator's request, with no further role.

## 8. MCP

Read tools: `categories_list` (the catalog with the node's state and budget), `get_group_content`. Plan tool: `plan_set_group_content` (scope `config:write:groups`; dry run, impact estimate, a reason). **Applying needs the same roles as editing lists and groups**: an agent plans, an operator applies, in the existing plan and approve flow (ADR-070); an agent with `config:write:groups` and `config:write:lists` may apply under the existing agent rules. Not given to agents: nothing new, but a selection with a heavy or over-budget source is refused for agents (`agent_not_allowed`: the owner confirms the cost). `spec/13` §3 catalog and the committed MCP snapshot (`UPDATE_MCP=1`) are updated.

## 9. Tests

| Area | Tests (names; REQ IDs in the names) |
|---|---|
| Catalog | `flt_901_catalog_parses`, `flt_901_catalog_has_licence_and_url_for_every_source`, `flt_901_no_empty_categories`, `flt_901_not_offered_have_reasons`, `flt_901_source_ids_unique`, `flt_901_bytes_cap_covers_source_size` |
| Mapping | `flt_901_category_lists_not_in_default`, `flt_901_shared_source_fetched_once`, `flt_901_last_user_removed_deletes_list`, `flt_901_allow_rule_beats_category`, `flt_901_explain_names_category`, `flt_901_unknown_category_ignored_and_reported` |
| Levels | `flt_902_basic_expands_preset`, `flt_902_off_keeps_selection`, `flt_902_enhanced_uses_categories`, `flt_902_preset_change_flows_on_update` |
| Safe search | `flt_902_safe_search_engines_subset`, `flt_902_safe_search_true_means_all`, `flt_902_unknown_engine_422` |
| Budget | `flt_901_budget_union_not_sum`, `flt_901_heavy_requires_confirm`, `flt_901_over_budget_refused_on_small_node` |
| Sources | `flt_902_picker_marks_randomised_mac`, `flt_902_source_write_is_one_transaction`, `flt_902_device_in_two_profiles_notice` |
| API/MCP | `api_001_committed_openapi`, `agt_006_committed`, `flt_901_put_content_validates`, `flt_901_agent_heavy_refused` |
| Cluster | `clu_901_content_replicates`, and the three-node test: select a category on the replica's UI, the primary stores it, every node downloads and blocks (fake HTTPS source, no internet) |
| Fuzz | the catalog parser (NFR-004) |
| UI (Playwright, new file `ui/e2e/categories.spec.ts`) | group checkbox and "n of m", indeterminate state, search then Select all, info popover shows source and licence, heavy confirmation, owned chip on the Lists page, profile list chips with "+N", editor saves each field, randomised-device warning, add-a-device from the picker, "Not available" section |
| Docs | help topics, `docs/running.md`, `docs/third-party-notices.md`, `spec/trace.py --check`, `site/build.py --check` |
| Bench | `make bench-smoke` (touches `telltale-filter` and `telltale-policy`) and a Pi-class measurement of RSS with the default selection, then with NRD 7 |

Network tests use a local fake HTTPS source only; no test touches a real list host or the home network.

## 10. Defaults and safety

Nothing is on by default: a new install has no category lists downloaded and every group at `level = "off"`. Selecting a category is explicit and shows the cost first. A category block is a **DNS block**, with the limits `docs` already state (no pages, mobile data and VPN bypass it, devices cache answers). The Categories help topic repeats them and does not promise child safety.

## 11. Order of build (the task's steps)

See T24.29. In short: catalog data and parser, then mapping and compile, then the group fields (`content`, `safe_search_engines`), then API and MCP, then the Categories view, then the profile list and editor and device picker, then docs and measurements.

## 12. Owner decisions the build needs

Asked by the orchestrator before T24.29 starts; each has a recommended answer.

1. **Which catalog groups to offer.** Recommended: the seven UniFi-style groups plus "Privacy and Ads", with the categories in section 3's "offered" column.
2. **Basic preset members.** Recommended: Adult, Malware, Phishing, Scam.
3. **Defaults.** Recommended: nothing selected, every group Off; the Kids example in the docs shows Basic plus Safe Search.
4. **UT1 archive source** (the broadest real category set, CC BY-SA 4.0 believed, site in maintenance): recommended: not in T24.29; open a follow-up once the licence is read and an archive source type exists.
5. **Authored bundles for AI services and crypto** (our own `presets/services` files, as FLT-012 does): recommended yes for AI (ChatGPT, Claude, Gemini, Copilot, Perplexity ...), no for crypto.
6. **Ads and tracking as categories.** Recommended: yes, as one "Ad Block" checkbox (tier in Settings), plus per-vendor native trackers under the same group.
7. **NRD windows.** Recommended: 7 days only, flagged heavy; entropy NRD/DGA at 7 days offered; longer windows after a Pi 4 measurement.
8. **The refusal rule for a small node** (refuse when snapshot plus compile peak passes 50 % of the memory limit). Recommended: 50 %.
9. **One profile per device or several** (UniFi allows one). Recommended: keep the existing union rule, and show the notice in the picker.
10. **Bon-Appetit as a second adult source** (CC BY-SA, attribution): recommended off by default, offered as an "Extended" tier of Adult.
