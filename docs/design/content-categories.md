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

`presets/categories/*.toml`, compiled into the binary like `presets/services/*.toml` (FLT-012), one file per catalog group. Format in ADR-995. A category has an id, a name, a catalog group, a one-line description (the info icon), and a list of **sources**. A source is a URL with a format, a licence, a cadence and size facts. Lists are never bundled: they are downloaded at runtime, by the primary (replicas receive the compiled snapshot), from the maintainer's own host.

Only categories with a real, maintained source are offered. The rules for "real":

- the source is published openly, with a licence we can read over HTTPS;
- it has been updated within 90 days (checked at catalog build time, see T24.29 step 1);
- the repository is not archived;
- the URL is on the maintainer's own host (raw GitHub or jsDelivr for the same repository). **An upstream-run mirror is not admitted** in T24.29 (ADR-995 §3): a mirror can lag, change or disappear without the maintainer's say. Open: Q4.

Recency and archived status are facts about the world. The Rust tests check only the **recorded** values (`licence`, `licence_url`, a recorded `checked` date within 90 days of `catalog_version`, `archived = false` as recorded); the live check against the GitHub API is a script (`scripts/check-catalog.py`) run by the weekly job, which opens an issue. No cargo test touches the internet.

A category failing these is **listed as not offered** (section 4), never as an empty or disabled checkbox.

### 2.1 Verified sources (checked 2026-11-18 by fetching the repository, licence and file listing)

| Source | Licence | Updated | Offered as |
|---|---|---|---|
| HaGeZi `dns-blocklists` | GPL-3.0 | daily (pushed 2026-11-18); each file says `Expires: 8 hours` | the main source: adult, gambling, piracy, social, fake stores, DoH/VPN bypass, dynamic DNS, URL shorteners, hosting, threat feeds (TIF), pop-up ads, ad and tracker tiers, per-vendor native trackers |
| HaGeZi `nrd` | GPL-3.0 | daily (pushed 2026-11-18); `Expires: 8 hours` | newly registered domains (NRD) and entropy NRD/DGA lists |
| StevenBlack `hosts` | MIT | pushed 2026-11-15 | `alternates/fakenews-only` (fake news) |
| Perflyst `PiHoleBlocklist` | MIT | pushed 2026-09-09 (70 days old on 2026-11-18, so it passes the 90-day rule only until about 2026-12-08). **Low cadence:** the catalog marks it `cadence = "low"`; when it goes stale its categories move to "Not available" for the next release, and the smart-TV category keeps HaGeZi's per-vendor native trackers as its fallback | `SmartTV.txt`, `android-tracking.txt`, `AmazonFireTV.txt`, `SessionReplay.txt` (smart-TV and app trackers) |
| Bon-Appetit `porn-domains` | CC BY-SA 4.0 | daily (pushed 2026-11-18) | optional second adult source (438,863 domains, the `lines` value in `meta.json`, not a file header; the file name changes, so the URL is found through `meta.json` and checked against a fixed prefix, ADR-995 §1) |
| OISD (`sjhgvr/oisd`) | GPL-3.0 (LICENSE in the repository; every list header links to it) | pushed 2026-11-18 | **Open (Q4b)**: not in the first release only because HaGeZi already covers each category and OISD's `domainswild2_nsfw.txt` (496,377 entries, 8.7 MB) would double the adult count. Recorded as a candidate for an alternative Adult source or the Extended Adult tier. (An earlier draft said "no licence terms found"; that was wrong.) |
| Block List Project | Unlicense | **archived**, last push 2026-10-27 | **not in the catalog** (archived: not maintained; its category lists are also very large: malware 58.9 MB, porn 21.3 MB in AdGuard syntax) |
| Universite Toulouse Capitole "UT1" blacklists, via the GitHub mirror `olbat/ut1-blacklists` (not run by the university) | CC BY-SA 4.0 per the mirror's README (`blacklists/cc-by-sa-4-0.pdf` and `LICENSE.pdf` are in the repository); **the licence on the UT1 site itself is not yet verified** (the site answered "en maintenance" on 2026-11-18) | mirror pushed 2026-11-11, not archived; the university's own tarball was modified 2026-11-17 | **Open (Q4)**: 80 categories, each a separate `blacklists/<cat>/domains` file that can be fetched on its own (for example `ai`, `bitcoin`, `dating`, `drugs`, `jobsearch`, `financial`, `shopping`, `sports`, `press`, `forums`, `blog`, `games`, `remote-control`, `violence`, `sexual_education`; `dating/domains` is 198 KB). No archive source type is needed (UT1's own tarball is 26.6 MB, not several hundred). Not admitted in T24.29 only because the admission rule wants the maintainer's host (section 2) and the site licence is unread |

The formats: HaGeZi publishes AdBlock syntax (`adblock/`), hosts (default), domains-only (`wildcard/*-onlydomains.txt`), dnsmasq, RPZ and others. The catalog names the **domains-only** (`wildcard/`) file where one exists: it is the smallest (HaGeZi NSFW is 1.39 MB there against 1.64 MB in AdBlock syntax) and the cheapest to parse. Where a domains-only file doesn't exist, the AdBlock file is used. Every format named is already read by the list parsers (FLT-001).

### 2.2 Licences and attribution

Lists are **downloaded at runtime by the user's node and never bundled** in the binary, the image, the repository or the site, so their licences' redistribution terms (GPL-3.0 for HaGeZi, CC BY-SA for Bon-Appetit) don't apply to WrenDNS's own licence. The clean-room rule (AGENTS.md rule 6) is about code; a list is data the user chooses to fetch, the same as the `hagezi-pro` list already in the bundles.

What we owe anyway, shown in the UI and written in `docs/third-party-notices.md`:

- each source row in the Categories view shows **name, maintainer, licence and a link** (the "Sources" line under a category, the info popover, and a full table in a "Sources and licences" drawer);
- CC BY-SA sources (Bon-Appetit) show "Licensed CC BY-SA 4.0, (c) Bon-Appetit contributors" next to the checkbox, since attribution is the licence's one condition for use. Nothing is redistributed, so share-alike has nothing to apply to; the note says so;
- HaGeZi's README asks that NRD and other lists are used "as-is", with no guarantees: the NRD category description says so.
- a **catalog licence check** in CI (T24.29 step 1) fails a source with no recorded SPDX id.

### 2.3 Sizes, and which categories blow the budget

The budget (`spec/00` §5): RSS with 1M blocklist domains + 100k cache entries ≤ 64 MiB; the snapshot is ≤ 12 bytes per unique domain and mmapped (`spec/05` §2). A Pi 4 (2 to 8 GiB) is not tight; a 128 MiB Kubernetes pod or a Pi Zero 2 W (512 MiB) is. Entry counts below are from each file's own header on 2026-11-18; the memory column is entries x 12 bytes (an estimate to be **measured** in T24.29 step 2). The compile peak is separate: the external sort is bounded at 128 MiB on the controller, and **that bound is scaled to the node** (the merge budget, below).

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
| HaGeZi TIF mini / medium / full | 189,474 / 413,269 / 2,245,686 | 2.2 / 4.7 / 25.7 MiB | light / light / **heavy, over the default budget by itself** |
| HaGeZi ad and tracker tiers: light, pro, pro++ , ultimate | (pro: 252,767 in the file header) | about 3 MiB for pro | light |
| HaGeZi native trackers, per vendor | 64 to 934 each | negligible | light |
| StevenBlack fake news | about 2,000 (59,664 bytes) | negligible | light |
| Bon-Appetit porn domains | 438,863 | 5.0 MiB | light |
| HaGeZi NRD 7 days | 2,438,879 | 27.9 MiB | **heavy, over the default budget by itself** |
| HaGeZi NRD, 14 days (7 + 8-14) | about 5.4 million | about 62 MiB | **over budget** |
| HaGeZi NRD 21 / 28 / 35 days | up to about 13.7 million | up to about 157 MiB | **over budget** |
| HaGeZi entropy NRD/DGA 7 / 14 / 30 days | 552,899 / 1,189,239 / 2,776,494 | 6.3 / 13.6 / 31.8 MiB | heavy / heavy, over the default budget / heavy, over the default budget |

Decision: a source is **heavy** above 500,000 entries. A selection is **over budget** when the sum of the *distinct* enabled sources, across all groups, passes `[filter] entry_budget` (default 1,000,000, the NFR number, a soft limit). Several single sources (NRD 7 days at 2.44 M, full TIF at 2.25 M, entropy 30 days at 2.78 M) pass the default budget on their own, so they are labelled **heavy, over the default budget** and need the confirmation plus a node with the memory for them; a person with a large node raises `entry_budget` in Settings (a control, help topic `category-budget`, step 5). The UI shows a running total ("Selected: 612,400 entries, about 7 MiB") and a bar. A heavy source asks for a confirmation that states the cost; an over-budget selection is **allowed with a warning on a node with enough memory** (the node reports its memory limit: cgroup limit in a container, total RAM otherwise), and **refused** when the estimated snapshot size plus the compile peak exceeds 50 % of that limit (the number is Open, Q8). **The compile peak is an estimate, not the fixed 128 MiB**: `min(sum of the selected sources' bytes x a factor measured in step 2, merge budget)`, where the **merge budget** (the external-sort memory bound) is scaled to the node, `min(128 MiB, 25 % of the memory limit)`, so a 128 MiB pod sorts in 32 MiB chunks (more passes, same result) and a selection is not refused merely because the fixed bound is bigger than half the pod. **The test includes the process's own baseline**: a selection is refused when `baseline RSS + snapshot + compile peak > 50 % of the limit`, where the baseline RSS is the resident size of a node with no category list (the NFR budget is 64 MiB for 1 M domains and 100 k cache entries, `spec/00`; step 2 measures it and replaces the provisional **32 MiB** used here for a Pi-class node). Worked example (with the figures measured in 2.4, corrected by the review): on a 128 MiB pod the 50 % line is 64 MiB and the merge budget is `min(128, 25 % x 128) = 32 MiB`. The default Basic selection is adult, malware, phishing and scam plus the default threat tier (TIF mini): about 267,000 distinct names, a snapshot of about 3.1 MiB, 4.45 MiB of source and a compile peak estimate of `min(4.45 x 5.0, 32) + 28 = 50 MiB`, so 32 + 3.1 + 50 = about 85 MiB, over 64: it is **refused** on a 128 MiB pod, and the measurement agrees that it does not fit under the line (Basic ran in a 128 MiB container at a peak of 71 MiB, 56 %). It passes from 192 MiB (the line is 96 MiB). NRD 7 days adds a 29 MiB snapshot and a compile peak that reaches the merge budget plus the fixed part: it is refused on 128 and on 256 MiB (measured 159 MiB at 256 MiB, over the 128 MiB line) and allowed with a warning on 512 MiB. The tests read the figures from the catalog's `measured` table. Test `flt_901_over_budget_refused_on_small_node` runs with an injected memory limit of 128 MiB and asserts this outcome (Basic and NRD 7 days refused, Basic passes at 192 MiB); `flt_901_over_budget_allowed_with_warning_on_512_mib` asserts the second. NRD is offered at 7 days only ("New or Risky Domains": newly registered, last 7 days) and flagged heavy; longer windows are **not offered** until measurement shows a Pi 4 stays in budget. Full TIF and full gambling are offered as the "Extended" tier of their category, off by default, flagged heavy.

Each list also has the existing `max_list_bytes` cap (64 MiB = 67,108,864 bytes, `schema.rs`). HaGeZi `nrd7` in domains-only form is 40.2 MB, under the cap; `dga30` is 64,295,810 bytes (61.3 MiB), also under it but with under 5 % headroom, so it would be refused the first time the list grows. The catalog carries a per-source `max_bytes` (the recorded size plus 50 %, at most 256 MiB) where a source is close to the default; the field exists on lists. Test `flt_901_bytes_cap_covers_source_size` fails when the recorded size is over 90 % of the cap.

**Download, bandwidth and disk on a Pi 4 (heavy sources).** HaGeZi says `Expires: 8 hours`, but NRD 7 days (40,223,891 bytes) and full TIF (40,248,653 bytes) change every day, so conditional GETs rarely save anything: at 8 hours that is about 120 MB a day per heavy source, plus a rewrite of `lists/*.src.zst` on an SD card. Decisions: (1) a **heavy source refreshes no more often than every 24 hours** (`refresh_secs = 86400`, set by the catalog; the header's 8 hours stays for light sources); (2) **the fetch streams to disk** through the zstd encoder and is never buffered (the existing list fetch is checked in step 2, and fixed if it buffers up to the cap); (3) step 2 **records download bytes per day, disk bytes written per day, and the fetch's peak RSS**, for the default Basic selection and for NRD 7 days, and writes them in this section. A heavy source's confirmation dialog states the daily download size.

**Measured (T24.29 step 2, 2026-11-18).** Stand-in for a Pi 4: the bench-fast release binary (fat LTO off, so a few percent larger than the image's) in a container limited to `--memory 1g --cpus 4` (and 256 MiB and 128 MiB for the small-node rows), fed by a local HTTP server that serves the real HaGeZi, Perflyst and StevenBlack files cached on 2026-11-18, so the byte counts below are the real ones. RSS is read from `/proc/<pid>/status` every 100 ms (VmRSS, and VmHWM for the peak). A stand-in has more memory bandwidth than a Pi 4: the compile seconds are indicative, the bytes are not.

| Selection | Names in the snapshot | Snapshot bytes per name | Steady RSS | Peak RSS (HWM) | Compile (4 threads) |
|---|---|---|---|---|---|
| nothing selected | 0 | n/a | 15.8 MiB | 32.8 MiB (start-up) | n/a |
| Basic (NSFW + TIF mini) | 274,697 | 11.65 | 31 MiB | 74 MiB (63 MiB on one thread) | 0.4 s |
| Enhanced, every light category + Ad Block pro (29 lists) | 652,723 | 11.73 | 56 MiB | 129 MiB | 0.5 s |
| NRD 7 days + adult, malware, phishing, scam | 2,702,446 | 10.38 | 65 MiB | 220 MiB at 1 GiB; 159 MiB at 256 MiB; 125 MiB at 128 MiB | 1.9 s; 1.6 s; 12.3 s |

- **Bytes per domain.** 10.4 to 11.7 on real lists (a larger list shares more suffixes), so the catalog keeps the spec's **12**. The snapshot on disk is 3.2 MB (Basic), 7.7 MB (Enhanced) and 28 MB (NRD) for the same selections.
- **Compile peak.** Re-measured by review with the committed harness `bench/categories_rss.py` (an `e2e`-feature build, a container limited to `--memory` and `--cpus 4`, the real files served from a local fake, VmHWM read from `/proc/1/status`; `--content` takes the group's selection). Peak resident set (VmHWM), in MiB:

  | Selection | Source | Names | 128 MiB | 256 MiB | 1 GiB |
  |---|---|---|---|---|---|
  | Basic | 4.45 MiB | 267k | 71.3 (58.4 on one CPU) | n/a | 72.9 |
  | Enhanced, 17 list categories and ad block pro | 14.6 MiB | about 650k | n/a | n/a | 115.2 |
  | NRD 7 days, adult, malware, phishing, scam | 42.8 MiB | 2.7M | 125 (earlier run) | 159 | 216.1 |

  Taking the model's baseline (32 MiB) and the snapshot (12 bytes a name) off, the compile peak is 37.8 MiB for Basic, 75.7 MiB for Enhanced and 153 MiB for NRD 7 days (the sort capped at 128 MiB). The first measurement's "2.8 to 5 times" and its factor of 4.0 under-counted the small selections, which carry a fixed part (parser buffers, the compile threads, the FST writers): the model is now `min(source bytes x 5.0, merge budget) + 28 MiB`, which gives 50, 101 and 156 MiB, so each estimate is at least the measurement. The merge budget is the lesser of `compile_memory` and a quarter of the node's memory limit, applied to the compile's sort itself (`categories::merge_budget`, used by the list worker). **Basic does not pass the rule on a 128 MiB pod**: it ran there (no OOM) at 71 MiB, which is over the 64 MiB line, and the estimate is 85 MiB. One compile thread cut Basic's peak to 58-60 MiB (47 % of 128 MiB) in the same container, so a node of 256 MiB or less compiling on one thread, or a line of 55 % on such a node, would let Basic pass; that is an owner decision (ADR-1017, Proposed) and is not done.
- **`entry_budget` stays 1,000,000 and the heavy threshold 500,000.** At 12 bytes a name, 1M names is 12 MiB of snapshot, and the measured steady RSS with 2.7M names is 65 MiB, under the 64 MiB NFR figure at 1M names by a wide margin; the limit that matters on a small node is the compile peak, which the refusal rule covers.
- **Download bytes a day.** Basic: 4.8 MB a fetch (NSFW 1.39 MB, TIF mini 3.41 MB), every 8 hours = 14.4 MB a day. NRD 7 days: 40.2 MB once a day (24 hour refresh) = 40.2 MB a day. Basic plus NRD: about 55 MB a day. Conditional GETs save nothing on daily-changing lists, so these are upper bounds.
- **Disk written a day.** The stored sources are zstd: Basic 1.8 MB a fetch (5.3 MB a day), NRD 14.4 MB a day. Each recompile writes a snapshot: Basic 3.2 MB, NRD 28 MB, kept three deep (the existing rule); with a changed list that is about 10 MB a day for Basic and 28 MB plus the Basic recompiles for NRD. On an SD card that is under 100 MB a day for the heaviest selection.
- **The fetch streams to disk.** The fetch peak RSS is the same with and without the 40.2 MB NRD file (about 43 to 46 MiB at the moment the fetches finish, against 42.5 MiB for Basic alone), so the body is never held: `flt_901_fetch_streams_to_disk` also holds the peak to one 64 KiB block plus one chunk. The long-pole is the compile, not the fetch.

## 3. Categories not offered

UniFi's seven groups map to what we can back with an open, maintained, licensed list:

| UniFi-style group | Offered categories | **Not offered** (no open maintained source) |
|---|---|---|
| Adult and Sensitive Content | Adult (porn), Gambling, Piracy | Alcohol and tobacco, drugs and vaping (Block List Project, archived; UT1 has `drugs` via the mirror, Q4), weapons, violence and gore (UT1 `violence` via the mirror, Q4), dating (UT1 `dating`, Q4), sex education (UT1 `sexual_education`, Q4), health |
| AI & Crypto | Cryptojacking is under Security | AI services and chatbots, cryptocurrency exchanges and wallets: no list from a maintainer's own host (UT1 has `ai` and `bitcoin` via the mirror, Q4); **possible as authored bundles** (hand-written `presets/services/*.toml`, our own data) if the owner wants them (Q5) |
| Business & Professional | none | Business services, job search, finance, education, government, real estate, travel, shopping: none on a maintainer's own host; UT1 has `jobsearch`, `financial`, `shopping` and others, only via the olbat mirror (Q4) |
| Culture & Entertainment | Social networks, Fake news, (authored bundles that already exist: video streaming, music, gaming, messaging) | News, sports, music, video, games, forums, blogs, lifestyle, religion: none on a maintainer's own host; UT1 has `press`, `sports`, `games`, `forums`, `blog` via the olbat mirror (Q4) |
| Networking Infrastructure | DoH, VPN, Tor and proxy bypass; Dynamic DNS; URL shorteners; Hosting providers; Most abused TLDs (**blocks whole top-level domains**: HaGeZi's `spam-tlds-onlydomains.txt` lists TLDs, which also hold many legitimate sites; off by default, never in Basic, and its description and confirmation say so) | Remote-access tools (since 2026-11-26 offered in the aggregate group, from blocklist.packettale.com: `curated-category-lists.md` section 3.3), cloud storage, CDN categories (a category that blocks a CDN breaks the web) |
| New or Risky Domains | Newly registered (7 days), DGA-like (7 days), Risky TLDs, Fake stores | Parked domains, newly seen (a "first seen" list: we have `first-seen domains` in analytics, T7.14; not a blocking source) |
| Security & Threat Protection | Malware, phishing, C2, scam and cryptojacking (threat feeds, three sizes) | Spyware (inside the threat feeds, not separately), ransomware (same) |

An earlier draft's "no open list" wording was wrong for most rows: the olbat mirror of UT1 has an openly licensed file for many of them. Each not-offered reason therefore reads one of two ways: **"no open maintained list known"** or **"only available through a third-party mirror of UT1 (licence on the UT1 site not yet verified); see Q4"**. The Categories view ends with a collapsed "Not available" section naming these, so a person who looks for "Dating" learns why it isn't there ("no maintained open list; see ...") instead of finding a checkbox that does nothing. (A small data file, `presets/categories/not-offered.toml`, carries it.)

## 4. How a category maps onto the existing model

### 4.1 Lists, sources and groups

- A catalog **source** becomes a **managed list** (ADR-040, the same machinery as T7.5) named `cat-<source-id>`, with a new read-only field `owners`. One list can back several categories (HaGeZi TIF backs "Malware", "Phishing" and "Scam"), so ownership is a set: `owners = ["malware", "phishing"]`.
- **Sources are deduplicated by URL** (after normalising scheme and host case), not by id, so one URL is never fetched twice. A catalog source whose URL equals a list the person already has (the bundles ship `hagezi-pro` as an ordinary enabled list) is **adopted, not duplicated**: see section 6.3 (Ad block).
- A source list exists on a node only while **at least one group has a category using it** (the **materialisation rule**). The category list is fetched once; each group references it by name, so it is shared. Turning off the last category that uses it deletes the managed list and its stored file (`lists/cat-*.src.zst`).
- **The "every enabled list" default must not pick them up.** Today a group whose `lists` is omitted uses every enabled list (`schema.rs` `GroupConfig.lists`). A category list is never part of that default: effective lists of a group = (its `lists`, or every enabled non-category list when omitted) plus the lists of its enabled categories. Test `flt_901_category_lists_not_in_default`. Without this, turning on "Adult" for one profile would block it for the default group.
- A group's category selection is a new field `[group.content]` (ADR-995 §4): `level = "off" | "basic" | "enhanced"`, `categories = [ids]`, `tiers = { gambling = "extended" }`. It is a **group field**, so it is a managed entry like the group's other fields (T7.5), edited by the API, validated against the catalog and the lists limits, and replicated with the group.
- **Allow rules still win** (spec/05 precedence): a quick rule or an allow list unblocks a domain a category blocks. The explain view names the category: "blocked by category Adult (list cat-hagezi-nsfw)". The block record carries the list id as today (FLT-013); the category name is looked up from the owners set at read time, so nothing is added to the hot path.
- **Hot path.** Nothing changes per query: categories turn into list membership bitsets at compile time. The group-to-lists mapping is compiled into the snapshot as today. Safe search per engine is a compile-time filter on the engine table (section 6). `make bench-smoke` runs anyway in the build task because `wrendns-filter` and `wrendns-policy` change.

### 4.2 Relationship to ADR-040, files-win and GitOps

A group defined in a config file has its `content` field in the file; the API refuses to change it (409 `set_by_file`, like any file field) and the UI shows "set by file". The catalog sources are managed lists the **server** creates and owns; a person cannot edit a category list's URL (it comes from the catalog) but can refresh it, put it in `shadow` mode (OBS-018) and see its statistics on the Lists page. **The `cat-` prefix is reserved** (a file wins over the API, ADR-040, so an unreserved name would let a person shadow the server's list with any URL). A list defined in a file or through the API with a name starting `cat-` is a validation error (422 for the API, a startup validation error for a file: "`cat-` is reserved for category lists"), and so is naming a category list in a group's `lists` ("use `content.categories`"). Test `flt_901_cat_prefix_reserved`.

### 4.3 List overlap (T24.28)

T24.28 (`feat/t24.28-list-overlap`, ADR-992 expected) measures how much of one list another covers. At the time of writing the branch holds no ADR-992 and no task text beyond its name, so this design **uses only the idea** and states its needs for when it lands:

- the Categories view shows, for a selected source, "N entries, M also in the lists you already use" when T24.28's per-list overlap API exists (a column, hidden if the API is missing);
- two categories sharing a source (TIF) show no double count in the entry total: the total is the union of distinct sources, not the sum over categories;
- the catalog check in CI reports pairwise overlap between sources of different categories, to catch a category that is a subset of another (a reason to merge them).

T24.29 step 8 reads ADR-992 before building the overlap column and amends this section if its API differs.

### 4.4 `blocked_services` stays

FLT-012 bundles (a named service, e.g. TikTok: all the domains the app needs) remain a separate, hand-authored feature: a *service* is one app's domains, a *category* is a maintained list of a kind of site. The profile editor offers both ("Services" is a section next to Categories). Authored bundles that already exist (video, music, gaming, social, messaging) appear in the category picker **as read-only "Services" entries under Culture & Entertainment** so the picker is one place; selecting one writes `blocked_services`, not `content.categories`.

### 4.5 Cluster replication

Group fields replicate (ADR-047, ADR-054: a replica's UI forwards writes to the primary). The catalog is compiled into the binary, so it is the same on every node of one version; the N / N-1 rule (ADR-059) means a replica one version behind may not know a new category id: it **ignores unknown ids and reports them** (health reason `category_unknown`, degraded, naming the ids), and never fails the snapshot (rule 5: DNS never depends on anything else). **The primary fetches and compiles; replicas receive the snapshot** (`spec/12`: replicas apply the snapshots the primary compiled and fetch blobs by hash, and list refresh pauses while the primary is down; CLU-004 keeps every node answering from its last snapshot). A replica never downloads a category list; a source that fails shows on the primary's list health. Version skew is about **configuration validation** on a replica that doesn't know a category id (it ignores and reports it), not about downloads.

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

**Per-engine safe search.** `presets/safesearch.toml` already has engines with ids (`google`, `youtube`, `bing`, `duckduckgo`, `yandex`, `pixabay`). Add `safe_search_engines: Vec<engine-id>` to the group. Compile rule: if the list is non-empty it **is** the set of engines (and `safe_search` is implied true); if it is empty, `safe_search = true` means all engines (so every existing config means the same). Validation: unknown engine ids are an error naming the valid ones. The YouTube level (`youtube_restrict`) stays. **Interaction:** `youtube_restrict` applies to YouTube's names whenever it is set, as today, independent of the engine list; if `safe_search_engines` is non-empty and excludes `youtube` while `youtube_restrict` is set, the YouTube level still applies and the editor shows a note ("YouTube restriction is on although YouTube is not in the Safe Search engines"). Test `flt_902_youtube_restrict_independent_of_engines`. The UI shows Google, Bing, YouTube first (as UniFi does) and the other three under "More engines". No hot-path change: the engine table is filtered when the group's rewrite map is compiled (the evaluation point, pipeline step 5, is unchanged).

**Ad block as a named list set.** An `ads` category in the catalog group "Privacy and Ads" with tiers `light`, `pro` (default), `pro-plus` and `ultimate` (each a HaGeZi list; the `ads` tiers are alternatives: exactly one is active). The profile's checkbox sets `content.ads = true`; the tier is a Settings value (`[filter] ads_tier`, default `pro`; a Settings control, step 5), so the profile editor stays a checkbox. **The `ads` tier sources name the `adblock/` files** (`adblock/light.txt`, `adblock/pro.txt`, `adblock/pro.plus.txt`, `adblock/ultimate.txt`), an exception to the domains-only preference in section 2.1, so that the default tier's URL equals the one the bundles already use (`https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt`) and dedup by URL matches. **Migration:** the bundles ship `hagezi-pro` as an ordinary enabled list, which every group gets through the "every enabled list" default, so a new checkbox would neither switch ads off when cleared nor avoid a second download. Rules, by where the list is defined (files win, ADR-040, so the server never renames or removes a file list): (a) **a matching list defined through the API or the store** is **adopted**: it becomes owned by the category (`owners = ["ads"]`, renamed once to its `cat-` name with an alias), leaves the default set and follows the checkbox; the migration writes `content.ads = true` into every API-managed group that had omitted `lists` **or that named the adopted list in `lists`** (the name is removed from `lists`, because a category list may not be named there), and the plan's impact says so; (b) **a matching list defined in a file** is not adopted and not renamed: the category does not download the tier a second time (dedup by URL), the checkbox shows "provided by list `hagezi-pro` (set by file)" and is read-only, and groups keep using the file list through the default as before; (c) **T24.29 edits the two bundle files** (`deploy/compose/wrendns.toml`, `deploy/docker-desktop/wrendns.toml`): the `[[list]]` `hagezi-pro` entry is dropped and the default group's `content.ads = true` is set, so a bundle gets the category list with no double fetch and a live checkbox; (d) a user-added list with a different URL is left alone. Tests `flt_901_ads_adopts_existing_list_by_url` and `flt_901_ads_unchecked_stops_ad_blocking`.

**Tier meaning.** A category's `tiers` are of one of two kinds, stated in the catalog: `exclusive` (the ads tiers: exactly one file is active) or `additive` (a larger list on top of the standard one). Gambling's three files map to **Standard = medium (102,937 entries), Extended = full (669,823, heavy)**, with the mini file (51,679) a third tier "Light"; these are exclusive and the default is Standard. Adult's "Extended" (Bon-Appetit) is `additive`: it adds to HaGeZi NSFW and does not replace it. The threat tiers are exclusive (mini, medium, full). Test `flt_901_tier_kinds`.

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
| `GET /groups/{id}/content` , `PUT /groups/{id}/content` | the group's `level`, `categories`, `tiers`, `ads`; the PUT validates against the catalog and the budget, answers 422 with the field, answers **403 `agent_not_allowed` to an agent token** (the only path an agent can trigger is the server replaying an operator-approved plan), and with `dryRun` the impact (newly blocked share of the last 24 h of queries from the group's devices, as for rules) |
| `GET /groups` , `PUT /groups/{id}` (an agent token that changes `content` here gets the same 403 `agent_not_allowed` as `PUT /groups/{id}/content`, section 8) | gains `content` and `safeSearchEngines`; the `source` summary the list view needs (`sources: [{kind, label, icon, randomized}]`), computed on the server so the table needs one call |
| `GET /lists` | each list gains `owners: [categoryId]`; owned lists refuse edit and delete (409 `owned_by_category`) |
| `GET /profiles/devices` | the picker's data: networks and devices with icon, key kind, `randomized`, current group |

`[filter] entry_budget` and `[filter] ads_tier` are edited in Settings (Filtering section) through the settings API, with help topic `category-budget`. OpenAPI regenerated (`UPDATE_OPENAPI=1`). Config schema (`UPDATE_SCHEMA=1`): `[[group]] content = {level, categories, tiers, ads}`, `safe_search_engines`, `[filter] entry_budget`, `ads_tier`. Roles: **viewer** reads the catalog; **operator** changes a group's `content` (it is a group edit, ADR in `spec/08` §RBAC: operators manage lists, clients and groups); the category lists the server creates are made by the server under the operator's request, with no further role **for a person**. For an agent the rule is stricter (section 8): an agent never applies a content change on its own, through MCP or through REST.

## 8. MCP

Read tools: `categories_list` (the catalog with the node's state and budget), `get_group_content`. Plan tool: `plan_set_group_content` (scope `config:write:groups`; dry run, impact estimate, a reason). **It is plan-only for agents, whatever `[agents] require_approval` is set to**, as `plan_pin_version` is: a content change makes the server create lists and download them (tens of megabytes a day), which an agent holding only `config:write:groups` must not trigger on its own. **Content plans are always created `pending`, whatever `require_approval` is** (a deliberate exception to ADR-070, which has an approval state only when the setting is on; `plan_pin_version` instead refuses planning when the setting is off, which would leave an agent unable to propose anything, so that precedent is not copied): an operator approves the pending plan in the UI, and an agent's `apply_plan` on a plan no operator has approved answers 403 `agent_not_allowed`. **REST is gated the same way**: `PUT /groups/{id}/content`, and `PUT /groups/{id}` whenever `content` changes, answer 403 `agent_not_allowed` to an agent token. A selection with a heavy or over-budget source is also refused at planning time for agents (`agent_not_allowed`: the owner confirms the cost). `spec/13` §3 catalog and the committed MCP snapshot (`UPDATE_MCP=1`) are updated.

## 9. Tests

| Area | Tests (names; REQ IDs in the names) |
|---|---|
| Catalog | `flt_901_catalog_parses`, `flt_901_catalog_has_licence_and_url_for_every_source`, `flt_901_no_empty_categories`, `flt_901_not_offered_have_reasons`, `flt_901_source_ids_unique`, `flt_901_bytes_cap_covers_source_size`, `flt_901_catalog_recorded_metadata_fresh` (recorded `checked` within 90 days of `catalog_version`, `archived = false` as recorded, no network), `flt_901_meta_json_url_outside_prefix_refused`, `flt_901_cat_prefix_reserved`, `flt_901_tier_kinds`. The live GitHub check is `scripts/check-catalog.py`, run by the weekly job only |
| Mapping | `flt_901_category_lists_not_in_default`, `flt_901_shared_source_fetched_once`, `flt_901_last_user_removed_deletes_list`, `flt_901_allow_rule_beats_category`, `flt_901_explain_names_category`, `flt_901_unknown_category_ignored_and_reported` |
| Levels | `flt_902_basic_expands_preset`, `flt_902_off_keeps_selection`, `flt_902_enhanced_uses_categories`, `flt_902_preset_change_flows_on_update` |
| Safe search | `flt_902_safe_search_engines_subset`, `flt_902_safe_search_true_means_all`, `flt_902_unknown_engine_422`, `flt_902_youtube_restrict_independent_of_engines` |
| Budget | `flt_901_budget_union_not_sum`, `flt_901_heavy_requires_confirm`, `flt_901_over_budget_refused_on_small_node` (injected memory limit of 128 MiB), `flt_901_over_budget_allowed_with_warning_on_256_mib`, `flt_901_compile_peak_estimate_scales_merge_budget`, `flt_901_ads_adopts_existing_list_by_url`, `flt_901_ads_unchecked_stops_ad_blocking`, `flt_901_heavy_refresh_not_under_24h`, `flt_901_fetch_streams_to_disk` |
| Sources | `flt_902_picker_marks_randomised_mac`, `flt_902_source_write_is_one_transaction`, `flt_902_device_in_two_profiles_notice` |
| API/MCP | `api_001_committed_openapi`, `agt_006_committed`, `flt_901_put_content_validates`, `flt_901_agent_heavy_refused`, `flt_901_agent_apply_unapproved_content_plan_403`, `flt_901_agent_apply_approved_content_plan_ok`, `flt_901_agent_rest_put_content_403`, `flt_901_content_plan_pending_when_approval_off` |
| Cluster | `clu_901_content_replicates`, and the three-node test: select a category on the replica's UI, the primary stores it, fetches and compiles, and every node blocks from the snapshot; **the fake source records no request from a replica** (fake HTTPS source, no internet) |
| Fuzz | the catalog parser (NFR-004) |
| UI (Playwright, new file `ui/e2e/categories.spec.ts`) | group checkbox and "n of m", indeterminate state, search then Select all, info popover shows source and licence, heavy confirmation (with the daily download size), Settings `entry_budget` and `ads_tier` controls and the `category-budget` help topic, owned chip on the Lists page, profile list chips with "+N", editor saves each field, randomised-device warning, add-a-device from the picker, "Not available" section |
| Docs | help topics, `docs/running.md`, `docs/third-party-notices.md`, `spec/trace.py --check`, `site/build.py --check` |
| Bench | `make bench-smoke` (touches `wrendns-filter` and `wrendns-policy`) and a Pi-class measurement of RSS with the default selection, then with NRD 7 |

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
4. **UT1 through the `olbat/ut1-blacklists` mirror.** It is not archived (pushed 2026-11-11), its README states CC BY-SA 4.0, and it has 80 categories, each a separate `domains` file (no archive source type is needed). The admission rule wants the maintainer's host, and the licence on the UT1 site itself is not yet read. Is an upstream-run mirror admissible once its licence file is recorded? Recommended: yes, as a follow-up after the UT1 site's licence is read, not in the first T24.29 release; the categories it would back (dating, drugs, jobsearch, shopping, sports, press, forums, games, ai, bitcoin, violence, ...) stay in "Not available" with the mirror reason until then.
4b. **OISD** (GPL-3.0, LICENSE in the repository, pushed 2026-11-18): an alternative Adult source or part of the Extended Adult tier? Recommended: no, HaGeZi already covers it; revisit if HaGeZi's NSFW list is judged too small.
5. **Authored bundles for AI services and crypto** (our own `presets/services` files, as FLT-012 does; the alternative to UT1's `ai` and `bitcoin` files, Q4): recommended yes for AI (ChatGPT, Claude, Gemini, Copilot, Perplexity ...), no for crypto.
6. **Ads and tracking as categories.** Recommended: yes, as one "Ad Block" checkbox (tier in Settings), plus per-vendor native trackers under the same group.
7. **NRD windows.** Recommended: 7 days only, flagged heavy; entropy NRD/DGA at 7 days offered; longer windows after a Pi 4 measurement.
8. **The refusal rule for a small node** (refuse when snapshot plus compile peak passes 50 % of the memory limit). Recommended: 50 %.
9. **One profile per device or several** (UniFi allows one). Recommended: keep the existing union rule, and show the notice in the picker.
10. **Bon-Appetit as a second adult source** (CC BY-SA, attribution): recommended off by default, offered as an "Extended" tier of Adult.

For lists that WrenDNS itself assembles for the hosted service, `docs/design/curated-category-lists.md` (ADR-1087, Proposed) takes Q4, Q4b and Q10 further: UT1 and Bon-Appetit are candidates for separate attributed lists, held until UT1's licence page and fetch location and Bon-Appetit's inputs are answered and their maintainers say yes, and OISD stays out.
