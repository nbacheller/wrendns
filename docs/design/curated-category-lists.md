# Curated category lists: design notes

**Status:** design only, for the owner's review. **ADR:** ADR-1087 (Proposed 2026-11-24). **Milestone:** M36 (WrenDNS Cloud, fork #41, `docs/design/hosted.md`), tasks T36.28 to T36.34 in `spec/10`, all after the public 1.0 release. **Requirements:** builds on FLT-901, FLT-902, FLT-004, FLT-013, OBS-023, NFR-004, NFR-005 and NFR-006; reserves **FLT-905** (the node's side) and **CLD-918** (the service's side), whose rows are added to `spec/01` when the build starts (section 11, open question 14). No code is written by this change.

**This document is not legal advice.** It records what the research of 2026-11-24 found, what the owner decided, and the questions a lawyer must answer before anything here is offered for money. Where it says a source is "allowed", that is the research's reading of the source's own licence text, not a legal opinion.

*Decision* means build it this way; amend ADR-1087 if you can't. *Open* means someone named in section 11 decides. Read `docs/design/content-categories.md` (the catalog), ADR-994 and ADR-995, and `docs/design/hosted.md` (the service, the platform channel and the open-core boundary) first.

**Owner decisions, 2026-11-24 (binding):**

1. **Sources.** Merge only permissive sources (MIT, Apache-2.0, CC0, Unlicense, CC BY) into lists WrenDNS owns. Keep GPL and CC BY-SA sources (HaGeZi, AdGuard DNS filter, EasyList/EasyPrivacy, UT1, Bon-Appetit) as separate, unmerged, attributed lists under their own licence, and write to their maintainers for a clear yes for hosted commercial use.
2. **Delivery** (applied only inside the hosted resolver, or also published as downloadable files for self-hosted nodes) is decided after a legal review. This design keeps both open and says what each requires (section 7).
3. **Now:** a design document and an ADR for the owner's review. The build belongs with the hosted-service milestone (fork #41, `docs/design/hosted.md`), after the public 1.0 release.

**The research** (2026-11-24): six researchers' reports and two sceptical licence checkers' verdicts, kept outside the repository with the owner. Where a checker's verdict differs from a researcher's claim, the checker's verdict is used here. No fact in this document comes from anywhere else; what the research did not establish is written as an open question.

## 1. Purpose, non-goals, and what changes

### 1.1 Purpose

WrenDNS assembles and maintains its own per-category filter lists ("assembled lists") from public sources, for the subscribers of the planned hosted service and possibly for self-hosted nodes. An assembled list is one file per category and tier, with a record of which source contributed each domain, a generated attribution page, a signed manifest and a build that can be repeated from its pinned inputs.

Three things motivate it. The catalog has many "Not available" rows (`presets/categories/not-offered.toml`) that permissive sources can now fill (dating, AI services, crypto, typosquatting, stalkerware, scam). A paid service needs lists whose licence allows hosted commercial use, which the copyleft compilations the catalog uses today do not state plainly. And a subscriber who reports a wrong block expects the service to fix it, which needs a list the service controls.

### 1.2 Non-goals

- **No change for self-hosters who never subscribe.** The catalog of ADR-995 stays: a node downloads each source from its maintainer at runtime, and nothing in this design removes a source from it.
- **No built-in crawler or classifier.** Categories are built from published lists and from WrenDNS's own reviewed entries, never from crawling sites or from a model that guesses a site's category (ADR-994 rejected a keyword classifier).
- **No copyleft data inside a WrenDNS-owned list.** Not merged, not used as a signal to confirm or rank permissive entries (section 5.5), not used as an allowlist.
- **No new DNS path.** The node's query path is unchanged: an assembled list is a list (FLT-001 format, domains only), compiled into the same snapshot (FLT-003).
- **No promise of child safety.** As in `content-categories.md` section 10: a category block is a DNS block, with its limits.

### 1.3 What changes against today's position

ADR-995 point 4 and `content-categories.md` section 2.2 rest on one fact: **the user's node downloads each source from its maintainer, and WrenDNS never redistributes a list.** On that basis the catalog treats the lists' redistribution terms (GPL-3.0 for HaGeZi, CC BY-SA 4.0 for Bon-Appetit) as not applying to WrenDNS, and ADR-995 records "GPL-3.0 on a dataset" as a risk for the owner, not resolved by legal review.

Assembling and serving lists is a different act, in four ways:

1. **WrenDNS makes copies.** The build fetches each source and stores it. Today only the user's node does.
2. **WrenDNS makes a new work from others' work.** Merging, de-duplicating and re-categorising is the act that share-alike licences reach ("Adapted Material" in CC BY-SA 4.0 section 1, a "work based on" the Program in GPL-3.0). A permissive licence still asks for its notice to travel with copies.
3. **WrenDNS uses the data for money.** Non-commercial terms, which do not matter to a user's own home node, exclude a source from a paid service whatever its copyright status.
4. **WrenDNS may distribute.** Under the "downloadable files" model the assembled lists are copies handed to others; under the "hosted only" model they are used inside a service that answers queries. Which obligations each act triggers is the core of the legal review (section 7.3).

This is why the owner's first decision splits sources into two kinds: permissive sources, which WrenDNS may merge into lists it owns, and copyleft sources, which stay separate files under their own licence so their terms cover only themselves.

## 2. The category set

### 2.1 From the existing catalog

The catalog has eight groups (seven UniFi-style plus Privacy and Ads, ADR-994 owner decision 1; Business & Professional has no offered category), 27 categories (21 backed by lists, 6 by WrenDNS's own authored service bundles) and 23 "Not available" rows. The table maps each to candidate sources from the research and marks it:

- **P**: buildable from permissive sources alone (a merged, WrenDNS-owned list).
- **C**: needs a separate copyleft list (no permissive source, or the permissive ones are too thin to stand alone).
- **N**: no usable source; own curation or a maintainer's permission is needed.
- **thin**: the permissive sources exist but are small; a WrenDNS-curated set of reviewed entries is needed before the category is worth offering on its own.

Sizes are the counts the research recorded on 2026-11-24 (file headers or line counts), before de-duplication. Source numbers (S01 and so on) refer to the table in section 3.

| Group | Category (catalog id) | Permissive candidates (merged) | Copyleft candidates (separate) | Mark |
|---|---|---|---|---|
| Adult and Sensitive Content | Adult (`adult`) | ShadowWhisperer Adult (S03, 213,982); Sinfonietta pornography (S07, 61,195 lines); StevenBlack porn extension, `tiuxo` input only (S08); v2fly `category-porn` (S04, about 6,165 lines with includes) | HaGeZi NSFW (S15); UT1 `adult` (S24, 4,600,371, heavy); Bon-Appetit (S25, held) | P |
| | Gambling (`gambling`) | ShadowWhisperer Gambling (S03, 9,689); Sinfonietta gambling (S07, 2,694); StevenBlack gambling extension (S08) | HaGeZi gambling tiers (S15); UT1 `gambling` (S24, 47,823) | P, thin against HaGeZi's 102,937 medium tier |
| | Piracy (`piracy`) | none | HaGeZi anti-piracy (S15); UT1 `warez` (S24, 1,561) | C |
| | Dating (`dating`, today a service bundle) | ShadowWhisperer Dating (S03, 1,439) | UT1 `dating` (S24, 10,564) | P, thin |
| | Alcohol and tobacco (not offered) | none | none | N |
| | Drugs and vaping (not offered) | none (Block List Project's lists are excluded, S31) | UT1 `drogue` (S24, 1,067) | C |
| | Weapons (not offered) | none | UT1 `dangerous_material` (S24, 54) | N |
| | Violence and gore (not offered) | ShadowWhisperer Shock (S03, 99); Sinfonietta snuff (S07, 23) | UT1 `agressif` (S24, 396) | P, thin |
| | Sex education (not offered) | none | UT1 `sexual_education` (S24) | C |
| | Health (not offered) | none | none | N |
| AI & Crypto | AI services and chatbots (`ai`, today a service bundle) | nullgen `ai-blocklist` (S05, 103 vendors, 211 hostnames); ShadowWhisperer AI (S03, 150); v2fly `category-ai-chat` (S04); `tbpatj/blocklists` (S06, 21,194, Extended tier only) | UT1 `ai` (S24, 80) | P |
| | Cryptocurrency exchanges and wallets (not offered) | ShadowWhisperer Cryptocurrency (S03, 1,283); v2fly `category-cryptocurrency` (S04, 122) | UT1 `bitcoin` (S24) | P, thin; the owner declined a crypto bundle on 2026-11-18 (open question 5) |
| Business & Professional | Business services; Education and government; Real estate and travel (not offered) | none | none | N |
| | Job search; Finance (not offered) | none | UT1 `jobsearch` (60,741), `financial` (S24) | C |
| | Shopping (not offered) | v2fly `category-ecommerce` (S04, 53) | UT1 `shopping` (S24, 36,971) | C (the permissive set is too thin) |
| Culture & Entertainment | Social networks (`social`) | v2fly per-network files (S04); Sinfonietta social (S07, 3,809); StevenBlack social extension (S08) | HaGeZi social (S15); AdGuard services (S21); UT1 `social_networks` (S24, 716) | P |
| | Fake news (`fakenews`) | StevenBlack fakenews extension, upstream feed paused (S08, 2,187) | UT1 `fakenews` (S24, 1,118) | P, thin and contested (the research calls it politically contested and low quality) |
| | Video, Music, Games, Messaging (service bundles) | WrenDNS's own bundles (FLT-012) stay; v2fly `category-media` (178), `category-games` (S04) could add names | AdGuard services (S21) | P (own data plus S04) |
| | News; Lifestyle and religion (not offered) | none | none | N |
| | Sports; Forums and blogs (not offered) | none | UT1 `sports`, `forums`, `blog` (S24) | C |
| Networking Infrastructure | DoH, VPN, Tor and proxy bypass (`bypass`) | ShadowWhisperer Tunnels (S03, 1,026); v2fly `category-vpnservices` (S04, 39) | HaGeZi DoH/VPN/proxy bypass (S15); UT1 `vpn` (6,039), `doh` (3,016) (S24) | P, thin against HaGeZi's 16,631 |
| | Dynamic DNS (`dyndns`) | ShadowWhisperer Dynamic (S03, 1,463) | HaGeZi DynDNS (S15) | P |
| | URL shorteners (`shorteners`) | ShadowWhisperer UrlShortener (S03, 5,981) | HaGeZi URL shorteners (S15); UT1 `shortener` (S24) | P (opt-in only: the research rates both as opinion lists with a high false-positive risk) |
| | Hosting providers (`hosting`) | ShadowWhisperer Free (S03, 1,875; its README warns it breaks sites) | HaGeZi hosters (S15) | C (the permissive list is not safe to offer) |
| | Remote-access tools (not offered) | ShadowWhisperer Remote (S03, 176) | UT1 `remote-control` (S24) | P, thin |
| | Cloud storage and CDN (not offered) | not offered by design: a CDN category breaks the web | | N |
| Privacy and Ads | Ad block (`ads`) | none maintained: `lightswitch05/hosts` is stale (S33), and the permissively labelled compilations carry non-commercial inputs (S26, S29, S30) | HaGeZi Multi tiers (S16, held); AdGuard DNS filter (S20); EasyList/EasyPrivacy (S23) | C |
| | Pop-up ads (`popup-ads`) | none | HaGeZi pop-up ads (S15) | C |
| | Smart-TV trackers (`smart-tv`) | Perflyst SmartTV and AmazonFireTV (S02) | HaGeZi native vendor lists (S15) | P, thin |
| | App and session-replay trackers (`app-trackers`) | Perflyst android-tracking and SessionReplay (S02); AdGuard CNAME-disguised trackers (S01) | AdGuard DNS filter (S20) | P |
| | Device and OS trackers (`native-trackers`) | none maintained (WindowsSpyBlocker's data is from 2022, S34) | HaGeZi native vendor lists (S15) | C |
| New or Risky Domains | Newly registered (`nrd`), DGA-like (`dga`) | none | HaGeZi NRD and DGA are built on a subscription feed whose terms are unread (S18) | N (the research's alternative: generate NRD from zone files under WrenDNS's own contract; open question 11) |
| | Fake stores and scams (`fake-stores`) | ShadowWhisperer Scam (S03, 6,185); Scam Blocklist (S12, 2,142) | HaGeZi fake stores (S15) | P, thin |
| | Risky top-level domains (`abused-tlds`) | none | HaGeZi's list relies on reputation data with non-commercial terms (S19) | N (about 445 TLDs: small enough to curate ourselves) |
| | Parked domains; Newly seen; NRD 14 days and longer (not offered) | none | none | N |
| | Typosquatting (new candidate) | ShadowWhisperer Typo (S03, 73,943; quality varies) | none | P, opt-in |
| Security & Threat Protection | Malware (`malware`) | ShadowWhisperer Malware (S03, 29,527); CERT Polska (S10); abuse.ch Feodo and SSL Blacklist (S11, mostly IP addresses) | HaGeZi TIF (S17) | P, thin against TIF's 189,474 mini tier |
| | Phishing (`phishing`) | CERT Polska Warning List (S10, about 127,000; Polish-centric) | HaGeZi TIF (S17) | P (custom terms, open question 2) |
| | Scam (`scam`) | Scam Blocklist (S12); ShadowWhisperer Scam (S03); CERT Polska (S10) | HaGeZi TIF (S17) | P |
| | Spyware and ransomware (not offered) | stalkerware: AssoEchap (S09, 929, CC BY 4.0); ransomware: none | HaGeZi TIF (S17) | P for a new Stalkerware category; N for ransomware |
| | Cryptojacking (inside the threat feeds today) | NoCoin (S13, 312) | HaGeZi TIF (S17) | P, thin |

What this shows: **security, adult, gambling, dating, AI, social, scam and several networking categories can be built from permissive sources alone.** Ad blocking, pop-up ads, piracy, device trackers and most of Business and Culture need a separate copyleft list. NRD, DGA, risky TLDs, alcohol, weapons, health, news and lifestyle have no usable source and need WrenDNS's own curation (section 4.6) or a maintainer's permission. The thin categories are offered only after WrenDNS's own reviewed entries make them worth a checkbox (ADR-994 point 4 still holds: no checkbox that does almost nothing).

### 2.2 Against the commercial services

From the research notes (names only; none of these services publishes its category data, except AdGuard's services, which are GPL-3.0):

| Service | Category set |
|---|---|
| ControlD | 20 filters (ads and trackers, adult, AI, clickbait, crypto, dating, drugs, dynamic DNS, file hosting, gambling, games, government, IoT telemetry, malware, new domains, phishing, social, torrents, URL shorteners, VPN and DNS), part hand-curated, part community lists, not saying which |
| NextDNS | parental-control categories (porn, violence, piracy and others), per-service toggles, security toggles (threat feeds, NRD, DDNS, parked domains, TLDs, cryptojacking) |
| Cloudflare Gateway | 14 security categories and about 25 content groups with over 100 subcategories, from an undisclosed vendor |
| Cisco Umbrella | about 100 content categories plus security categories (the research could not open the full list) |
| DNSFilter | 36 content categories and about 7 threat categories |
| CleanBrowsing | three tiers (Family, Adult, Security), no taxonomy |
| Quad9 | threat blocking only |
| AdGuard DNS | filter lists plus parental-control services (the only vendor whose category data is public) |

WrenDNS's catalog (8 groups, 27 categories) sits between ControlD's 20 filters and DNSFilter's 36. The content categories the large vendors buy from paid classifiers (business, news, health, religion, real estate, travel and the other lifestyle categories) have no open source; WrenDNS should not claim them. The research's suggested taxonomy (security, privacy, content, plus per-service toggles and an intensity dial) matches the catalog's existing shape, so no regrouping is proposed.

## 3. The source table

Every source the research considered. **Licence** is as verified (the checker's reading where there is one). **Status** is the research's reading for a paid hosted service: `allowed`, `allowed-with-conditions`, `not-allowed` or `unclear`; **By** says whether it is a checker's verdict or a researcher's claim (a checker wins). **Admitted as** is this design's proposal under the owner's decisions:

- `merged-permissive`: may be merged into a WrenDNS-owned list, once admitted by the process in section 4;
- `separate-copyleft`: a separate, unmerged, attributed list under its own licence, offered only after its maintainer's written yes and the legal review;
- `held`: a separate-copyleft candidate that is not built until a named question is answered;
- `guard only`: used inside the build (section 5.5), never part of any output;
- `excluded`, with the reason.

| No. | Source | Licence | Evidence | Status | By | Conditions and notes | Admitted as |
|---|---|---|---|---|---|---|---|
| S01 | AdGuard CNAME-disguised trackers | MIT | <https://github.com/AdguardTeam/cname-trackers/blob/master/LICENSE> | allowed | checker | The data file has no licence line: the repository's MIT notice travels with it. | merged-permissive |
| S02 | Perflyst PiHoleBlocklist | MIT | <https://github.com/Perflyst/PiHoleBlocklist/blob/master/LICENSE> | allowed | checker | MIT notice. Low cadence (last push 2026-09-09); already in the catalog. | merged-permissive |
| S03 | ShadowWhisperer BlockLists | Unlicense | <https://github.com/ShadowWhisperer/BlockLists/blob/master/LICENSE> | allowed | checker | README: lists come from "a custom script and manual additions"; names no third-party lists. Single maintainer; the repository history is compressed now and then, so the build keeps its own pinned copies. The Free, Junk, Marketing and Risk lists are not used (its own notes say they break sites). | merged-permissive |
| S04 | v2fly domain-list-community | MIT | <https://github.com/v2fly/domain-list-community/blob/master/LICENSE> | allowed | checker | MIT notice. A routing taxonomy that "does NOT endorse, claim or imply that a domain should be blocked"; needs a parser for `include:` and attributes; thin on Western long-tail sites. | merged-permissive |
| S05 | nullgen-inc ai-blocklist | CC0-1.0 | <https://github.com/nullgen-inc/ai-blocklist/blob/main/README.md> | allowed | checker | The repository's `lists/` files only, not the vendor API behind the generator (terms unread). | merged-permissive |
| S06 | tbpatj/blocklists | MIT | <https://github.com/tbpatj/blocklists/blob/main/LICENSE> | allowed-with-conditions | checker | MIT notice. Broad and noisy: an Extended tier only. | merged-permissive |
| S07 | Sinfonietta hostfiles | MIT | <https://github.com/Sinfonietta/hostfiles/blob/master/LICENSE> | allowed-with-conditions | checker | MIT notice; no upstreams documented; last push 2026-09-09 (near the 90-day line). | merged-permissive |
| S08 | StevenBlack/hosts extensions (gambling, social, fakenews, porn) | MIT | <https://github.com/brijrajparmar27/host-sources> | allowed-with-conditions | checker | Each extension is one upstream file with its licence in `update.json`. Taken from each original: Sinfonietta and `bigdargon/hostsVN` (MIT), `marktron/fakenews` (MIT, feed paused), `tiuxo/hosts` (CC BY 4.0, attribution). **Not taken:** `brijrajparmar27/host-sources` (no licence stated, although `update.json` says CC BY 4.0) and the `Clefspeare13/pornhosts` copy frozen in 2021 (its repository is blocked). Not to be confused with the unified base (S26). | merged-permissive (per upstream) |
| S09 | AssoEchap stalkerware-indicators | CC BY 4.0 | <https://github.com/AssoEchap/stalkerware-indicators#license> | allowed-with-conditions | checker | Attribution, no share-alike. README statement only (no LICENSE file). The checker asks for written confirmation for a paid service. | merged-permissive (after written confirmation) |
| S10 | CERT Polska Warning List | custom (CERT Polska data usage policy) | <https://cert.pl/en/warning-list/> | allowed | checker | "may be used by any user for any purpose, including commercial purposes", no warranty. Naming the source must not imply endorsement or partnership, and the CERT Polska and NASK-PIB names and logos may not be used in a misleading way. Keep a copy of the policy text. Custom terms, not one of the five licence families the owner named. | merged-permissive (open question 2) |
| S11 | abuse.ch Feodo Tracker, SSL Blacklist, YARAify | CC0 | <https://abuse.ch/terms-of-use/> | allowed | checker | CC0 for these three feeds only (Terms section 3.4). Mostly IP addresses: few domains. | merged-permissive (domain entries only) |
| S12 | Scam Blocklist (`durablenapkin/scamblocklist`) | MIT | <https://github.com/durablenapkin/scamblocklist/blob/master/LICENSE> | allowed-with-conditions | checker | MIT notice. Its resources include a consumer authority's site "and by extension" a list under the Dandelicence (a custom licence with extra conditions), so some entries may derive from it; the other resources are research aids, not merged lists. | merged-permissive (after the maintainer's answer) |
| S13 | NoCoin adblock list | MIT | <https://github.com/hoshsadiq/adblock-nocoin-list/blob/master/LICENSE> | allowed-with-conditions | checker | MIT notice; 312 domains; names no upstreams; low activity (push 2026-09-12). | merged-permissive |
| S14 | Majestic Million | CC BY 3.0 | <https://majestic.com/reports/majestic-million> | allowed-with-conditions | checker | Attribution. Used only as the popularity guard inside the build, never republished. | guard only |
| S15 | HaGeZi dns-blocklists: content, networking and native lists (NSFW, gambling, anti-piracy, social, fake stores, pop-up ads, DoH/VPN bypass, DynDNS, URL shorteners, hosters, native vendor trackers) | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/README.md> | allowed-with-conditions | checker | "A copy of the license is included in this repository and has to accompany any redistribution." "Some inputs come from third-party sources with their own licenses or terms of use"; `sources.md` lists about 233 inputs without per-source licences. The README disclaimer adds a terms layer with no commercial ban. The checker calls NSFW and gambling the safer scope. | separate-copyleft |
| S16 | HaGeZi Multi tiers (Light, Normal, Pro, Pro++, Ultimate; the catalog's ad tiers) | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/FAQ.md> | allowed-with-conditions | checker | Inputs include the `pgl.yoyo.org` list (terms forbid money-making use), 1Hosts Lite (non-commercial upstreams), `big.oisd.nl` and the AdGuard DNS filter. The maintainer says "None of them is copied over one to one"; the checkers leave the residual risk to a lawyer. | held (lawyer question 8, the maintainer's answer) |
| S17 | HaGeZi Threat Intelligence Feeds (TIF) | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/sources.md> | allowed-with-conditions | checker | Security inputs with their own terms: DandelionSprout AntiMalwareDomains (Dandelicence), KADhosts (CC BY-SA 4.0), a UT1 mirror, NetAPI compromised domains. | separate-copyleft |
| S18 | HaGeZi NRD and DGA | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/FAQ.md> | allowed-with-conditions | checker | The base data is a Stamus Labs subscription feed ("This is a subscription landing page"); its terms are unread. | excluded: unclear until answered |
| S19 | HaGeZi Most Abused TLDs | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/sources.md> | allowed-with-conditions | checker | Relies on Cloudflare Radar, Netcraft and Spamhaus reputation data. About 445 TLDs. | excluded: unclear until answered (own curation instead) |
| S20 | AdGuard DNS filter (AdGuardSDNSFilter) | GPL-3.0 | <https://filters.adtidy.org/extension/chromium/filters/15.txt> | allowed-with-conditions | checker | **A compilation** (a researcher said it was not): the EasyList and EasyPrivacy sections (taken under their GPL option) plus regional lists whose licences are unverified (AdBlockID, ABPindo, filterslists-KO, PersianBlocker, hostsVN, hufilter, Frellwits Swedish hosts, EasyList China, Dutch, Germany, Italy, Hebrew). | separate-copyleft (after the regional inputs are read) |
| S21 | AdGuard HostlistsRegistry `services/*.yml` and safe-search rules | GPL-3.0 | <https://github.com/AdguardTeam/HostlistsRegistry/blob/main/README.md> | allowed-with-conditions | checker | `services/` is hand-written by AdGuard; `filters/` re-hosts other vendors' lists under their own licences and is not used. Reuse the data, not AdGuard's branding. Safe-search targets are vendor-documented facts WrenDNS already has (FLT-011). | separate-copyleft (`services/` only) |
| S22 | AdGuard Filters (AdguardFilters) | GPL-3.0 | <https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE> | allowed-with-conditions | checker | Mostly browser (cosmetic and URL) rules; inherited rules are not itemised. | excluded: little DNS-level data beyond S20 |
| S23 | EasyList and EasyPrivacy | GPL-3.0-or-later or CC BY-SA 3.0 | <https://easylist.to/pages/licence.html> | allowed-with-conditions | checker | Taken under the GPL-3.0-or-later option, to match the other GPL lists. Credit "The EasyList authors". Only EasyList, EasyPrivacy, EasyList Germany and EasyList Italy are covered; Fanboy lists are not. The repository has no LICENSE file, so a copy of the licence page is kept as evidence. Hostnames must be extracted from browser syntax. | separate-copyleft |
| S24 | UT1 blacklists (Université Toulouse Capitole), `olbat/ut1-blacklists` mirror | CC BY-SA 4.0 | <https://github.com/olbat/ut1-blacklists/blob/master/README.md> | allowed-with-conditions | checker | Attribution to UT1 and Université Toulouse Capitole, a licence link, an indication of changes, share-alike. No root LICENSE (the licence texts are PDFs under `blacklists/`). The university's site answered 503, so its own licence page is unread. Some lists must not be used (`examen_pix`, `tricheur_pix`, `liste_bu`). The adult list has 4,600,371 entries. A mirror is not admitted today (ADR-995 point 3, `content-categories.md` Q4). | separate-copyleft (after the UT1 site's licence and the university's yes) |
| S25 | Bon-Appetit porn-domains | CC BY-SA 4.0 | <https://github.com/Bon-Appetit/porn-domains/blob/main/LICENSE> | unclear | researcher | A requested credit line. The output "combines external sources with reviewed custom entries"; `blocklist/block-sources.csv` lists 100+ repositories, including GPL-3.0 and unlicensed ones, so the CC BY-SA label cannot clear rights in the inputs. Not checked by a checker. | held (the maintainer's answer on the inputs; lawyer question 8) |
| S26 | StevenBlack/hosts unified base | MIT | <https://github.com/StevenBlack/hosts/blob/master/data/mvps.org/update.json> | not-allowed | checker | **Overturned:** the MIT label covers the project, but the base merges MVPS hosts (CC BY-NC-SA 4.0), `someonewhocares.org` (non-commercial), the `pgl.yoyo.org` list and KADhosts. | excluded: non-commercial upstreams |
| S27 | OISD big and small | GPL-3.0 | <https://oisd.nl/faq> | unclear | checker | About 150 inputs (`oisd.nl/includedlists/big`), including `vokins/yhosts`, reported as CC BY-NC-ND 4.0. The owner decided "No OISD" on 2026-11-18 (ADR-994). | excluded: unclear until answered; owner decision |
| S28 | oisd NSFW | GPL-3.0 | <https://oisd.nl/faq> | allowed-with-conditions | checker | Inputs include UT1 (via Firebog), HaGeZi NSFW, StevenBlack porn-only and several unlicensed lists. | excluded: owner decision ("No OISD") |
| S29 | 1Hosts (Lite, Pro, Xtra) | MPL-2.0 | <https://github.com/badmojr/1Hosts/blob/master/-data/lists/assets.txt> | not-allowed | checker | **Overturned:** its credits list MVPS (CC BY-NC-SA 4.0), `someonewhocares.org` (non-commercial), the `pgl.yoyo.org` list, OpenPhish, Disconnect and many unlicensed lists. MPL-2.0 is also not one of the five permissive families. | excluded: non-commercial upstreams |
| S30 | GoodbyeAds | MIT | <https://github.com/jerryn70/GoodbyeAds/blob/master/Docs/Sources.md> | not-allowed | checker | **Overturned:** upstreams are "always merged and included", several CC BY-NC-ND, CC BY-NC-SA, non-commercial, All Rights Reserved or unlicensed. Stale since 2024-11. | excluded: non-commercial upstreams |
| S31 | The Block List Project | Unlicense | <https://github.com/blocklistproject/Lists/blob/main/config/lists.yml> | not-allowed | checker | **Overturned:** archived 2026-10-27; list headers say MIT; its ads, malware, porn and tracking lists pull `zachlagden/Pi-hole-Optimized-Blocklists`, which includes the `pgl.yoyo.org` list (no money-making use) and Phishing Army (CC BY-NC 4.0), plus GPL-3.0 and CC BY-SA 4.0 data. | excluded: archived; non-commercial upstreams |
| S32 | Frogeye first-party trackers | MIT | <https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt> | unclear | checker | MIT covers the generator; the plain file has no header. Inputs are EasyPrivacy, AdGuard tracker lists and the Cisco Umbrella ranking. | excluded: unclear until answered |
| S33 | `lightswitch05/hosts` | Apache-2.0 | <https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt> | allowed | checker | Apache header on each file; last commit 2023-11-17. | excluded: unmaintained (fails the 90-day rule) |
| S34 | WindowsSpyBlocker | MIT | <https://github.com/crazy-max/WindowsSpyBlocker/blob/master/LICENSE> | allowed | checker | The data was last updated 2022-05-16. | excluded: unmaintained data |
| S35 | `pgl.yoyo.org` ad server list | no licence stated | <https://pgl.yoyo.org/adservers/> | not-allowed | checker | A researcher found no licence; the checkers found its licence page forbids use "in any manner that could possibly be construed as making anybody any money". | excluded: terms forbid commercial use |
| S36 | NoTrack blocklists | GPL-3.0 | <https://github.com/notracking/hosts-blocklists> | not-allowed | researcher | A researcher said "no licence"; the checker found the GitLab LICENSE is GPL v3. Abandoned: no submissions since May 2023, last commit 2023-06-26. | excluded: unmaintained |
| S37 | Disconnect tracker protection lists | CC BY-NC-SA 4.0 | <https://github.com/disconnectme/disconnect-tracking-protection/blob/master/LICENSE> | not-allowed | researcher | NonCommercial; a paid service needs a commercial licence from Disconnect. | excluded: non-commercial |
| S38 | MVPS hosts | CC BY-NC-SA 4.0 | <https://creativecommons.org/faq/> | not-allowed | researcher | Header: "License info for commercial purposes contact" the maintainer (confirmed by the checker in S26). | excluded: non-commercial |
| S39 | `someonewhocares.org` hosts | custom (non-commercial terms) | <https://www.spamhaus.org/organization/dnsblusage/> | not-allowed | researcher | "You are free to copy and distribute this file for non-commercial uses" (header, confirmed by the checker in S26). | excluded: non-commercial |
| S40 | NextDNS blocklists repository | no licence stated | <https://github.com/nextdns/blocklists> | unclear | researcher | An index of third-party lists, no data. | excluded: no licence, no data |
| S41 | abuse.ch URLhaus and ThreatFox | custom (abuse.ch Terms of Use) | <https://abuse.ch/terms-of-use/> | not-allowed | researcher | Commercial use "may require a paid subscription, which will be managed by Spamhaus" (terms changed 2025-11-04, updated 2026-10-21); downstream READMEs still say CC0. The checker confirms the CC0 grant does not extend to them (S11). | excluded: terms forbid commercial use without a subscription |
| S42 | OpenPhish community feed | custom (OpenPhish Terms of Use) | <https://openphish.com/terms.html> | not-allowed | researcher | Non-commercial only; bans derivatives and third-party disclosure. | excluded: terms forbid commercial use |
| S43 | PhishTank | custom (PhishTank Terms of Use) | <https://phishtank.org/terms.php> | allowed-with-conditions | checker | "Data" is free for commercial use; "Content" is personal use only. An application key and a descriptive User-Agent are required. The terms page carries a CC BY-SA 2.5 notice whose scope is ambiguous. | excluded: unclear until answered |
| S44 | Phishing.Database | MIT | <https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE> | allowed-with-conditions | checker | The feeds the domains come from are not named anywhere; files now served from another host; last push 2026-10-02. | excluded: unclear until answered (provenance in writing) |
| S45 | Phishing Army | custom (no data licence) | <https://phishing.army/license/> | unclear | researcher | Ingests OpenPhish (non-commercial). Two researchers differ (`allowed-with-conditions` and `unclear`); no checker verdict. | excluded: non-commercial upstreams |
| S46 | malware-filter project (urlhaus-filter, phishing-filter, botnet-filter) | CC0 and MIT (per list; phishing-filter CC BY-SA 4.0, tracking-filter CC BY-NC-SA 4.0) | <https://github.com/curbengh/malware-filter/blob/main/LICENSE> | not-allowed | researcher | Built from URLhaus (abuse.ch's commercial terms, S41) and upstreams not verified. | excluded: terms forbid commercial use upstream |
| S47 | Maltrail trails | custom (Maltrail Trails Community Data License 1.0) | <https://github.com/stamparm/trails/blob/main/LICENSE.md> | not-allowed | researcher | The 2026 data licence forbids use in services. | excluded: terms forbid commercial use |
| S48 | `stamparm/ipsum` and blackbook | Unlicense | <https://github.com/stamparm/ipsum/blob/master/LICENSE> | unclear | researcher | `ipsum` is IP addresses; blackbook is archived (2025-06-12) and derived from URLhaus. | excluded: archived; not domain data |
| S49 | DigitalSide Threat-Intel | MIT | <https://github.com/davidonzo/Threat-Intel/blob/master/LICENSE> | unclear | researcher | Stale since 2024-10; 0 entries when fetched. | excluded: unmaintained |
| S50 | CoinBlockerLists | AGPL (claimed) | <https://zerodot1.gitlab.io/CoinBlockerListsWeb/> | unclear | researcher | Licence file and data not reachable. | excluded: unclear until answered |
| S51 | Spamhaus DROP and DBL | custom (Spamhaus Fair Use and commercial subscription terms) | <https://www.spamhaus.org/blocklists/domain-blocklist/> | not-allowed | researcher | Commercial use needs a subscription. | excluded: terms forbid commercial use |
| S52 | Shallalist | no licence stated | <http://www.shallalist.de/> | not-allowed | researcher | Discontinued, offline since about 2022. | excluded: unmaintained; no licence |
| S53 | Mullvad dns-blocklists | GPL-3.0 | <https://github.com/mullvad/dns-blocklists/blob/main/LICENSE.md> | unclear | researcher | Outputs merge oisd NSFW, HaGeZi gambling, URLhaus and others, with nothing separating Mullvad's own part. A reference only. | excluded: compilation |
| S54 | Ultimate Hosts Blacklist | MIT | <https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/blob/master/LICENSE> | unclear | researcher | A merge of hundreds of upstreams with their own licences. Two researchers differ (`allowed-with-conditions` and `unclear`); no checker verdict. | excluded: compilation whose upstreams are not read |
| S55 | anudeepND/blacklist | MIT | <https://github.com/anudeepND/blacklist> | allowed-with-conditions | researcher | A compilation; its upstreams are not read; the coinminer list is discontinued. | excluded: unclear until its upstreams are read |
| S56 | anudeepND/whitelist | MIT | <https://github.com/anudeepND/whitelist/blob/master/LICENSE> | allowed-with-conditions | checker | Archived (last push 2024-03-19); an allowlist of domain names, data "borrowed" from forums. | excluded: archived (open question 15) |
| S57 | T145/black-mirror | AGPL-3.0 | <https://raw.githubusercontent.com/T145/black-mirror/master/LICENSE.txt> | not-allowed | researcher | A compilation of upstreams with their own terms. Its manifest shape (per-source licence ids) is a model for section 6.1. | excluded: compilation |
| S58 | Sefinek Blocklist Collection | CC BY-NC-ND 4.0 | <https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/main/LICENSE> | not-allowed | researcher | Non-commercial, no derivatives. | excluded: non-commercial |
| S59 | The Firebog | no licence stated | <https://firebog.net> | unclear | researcher | An index of lists. | excluded: no licence (discovery only) |
| S60 | FilterLists directory | MIT | <https://github.com/collinbarrett/FilterLists/blob/main/LICENSE> | allowed | checker | Directory data; for discovery and screening only, read from the repository's JSON (the hosted API's terms are unread). | excluded: not a list (discovery only) |
| S61 | AdGuard HostlistCompiler | GPL-3.0 | <https://github.com/AdguardTeam/HostlistCompiler/blob/master/LICENSE> | allowed-with-conditions | checker | A tool with no data. GPL code would break the commercial licence (AGENTS.md rule 6, ADR-1033). | excluded: code, not data (not used) |
| S62 | AdGuard DeadDomainsLinter | MIT | <https://github.com/AdguardTeam/DeadDomainsLinter/blob/master/README.md> | allowed-with-conditions | checker | A tool that depends on an AdGuard web service with unchecked terms. WrenDNS writes its own pruner (section 5.6). | excluded: tool, not data (not used) |
| S63 | Tranco list | no licence stated | <https://tranco-list.eu/> | unclear | researcher | No licence for the list itself; its inputs include Chrome UX Report (CC BY-SA 4.0) and Cloudflare Radar (CC BY-NC 4.0). | excluded: unclear until answered |
| S64 | Cisco Umbrella Popularity List (Top 1M) | no licence stated | <https://s3-us-west-1.amazonaws.com/umbrella-static/index.html> | unclear | researcher | The best popularity signal for DNS, per the research; no terms. | excluded: unclear until answered |
| S65 | Cloudflare Gateway domain categories | no licence stated | <https://developers.cloudflare.com/cloudflare-one/traffic-policies/domain-categories/> | not-allowed | researcher | Category names only, no downloadable data. | excluded: no data (taxonomy reference only) |
| S66 | laylavish uBlockOrigin-HUGE-AI-Blocklist | CC0-1.0 | <https://github.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/blob/main/LICENSE> | allowed | checker | Last push 2025-10-02; aimed at hiding AI-generated imagery in search results. | excluded: unmaintained |

### 3.1 Overturned claims, and the rule that follows

Five sources the researchers rated usable were overturned by the checkers, all for the same reason: **a permissive label on an aggregated list hides upstreams with non-commercial or no terms.**

- **StevenBlack unified hosts (S26):** "MIT", but the base merges MVPS hosts (CC BY-NC-SA 4.0) and `someonewhocares.org` (non-commercial). Only the extensions, taken from their originals, survive (S08).
- **1Hosts (S29):** "MPL-2.0", but its credits list MVPS, `someonewhocares.org`, the `pgl.yoyo.org` list, OpenPhish and unlicensed lists.
- **GoodbyeAds (S30):** "MIT", but its own `Sources.md` names NC, ND, All Rights Reserved and unlicensed inputs that are "always merged and included".
- **The Block List Project (S31):** "Unlicense" (and "MIT" in the headers), but archived, and fed by lists that include the `pgl.yoyo.org` list and Phishing Army (CC BY-NC 4.0).
- **AdGuard DNS filter (S20):** said not to be a compilation; it is one, with regional inputs whose licences are unread.

The checkers also corrected details the other way: NoTrack is GPL v3, not unlicensed (S36), and EasyList's dual licence makes it usable under its GPL option (S23). And the HaGeZi lists, rated allowed with conditions, turn out to take non-commercial data as inputs to the ad tiers (S16) and a subscription feed for NRD (S18).

**The rule (ADR-1087 point 3):** a source that is a compilation of other lists is admitted only after its own list of upstreams has been read and every upstream on it meets the admission rule for the kind of list it would join. A compilation that does not publish its upstreams is not admitted. A source that says it is original work (S03, S07, S13) is admitted on that statement, recorded with its quote, and re-read at every re-check.

## 4. Admission of a source

### 4.1 The rule

A source is admitted to a **merged, WrenDNS-owned list** only when all of these hold, each recorded with its evidence (section 6.1):

1. **Licence family.** Its licence is MIT, Apache-2.0, CC0-1.0, Unlicense, or CC BY (3.0 or 4.0), read from the source's own LICENSE file or licence statement, with the SPDX id recorded. Custom permissive terms (CERT Polska, S10) are admitted only when the owner says so (open question 2). Anything else is copyleft, non-commercial or unclear, and goes to 4.1b or is excluded.
2. **Commercial use.** Nothing in the licence, the source's terms of use or its README forbids commercial or hosted use. A non-commercial term anywhere excludes the source.
3. **Upstreams.** If it is a compilation, the rule in section 3.1: its upstream list is read and every upstream passes points 1 and 2. If it says it is original, that statement is recorded.
4. **Maintained.** A push within 90 days and not archived (the catalog's rule, ADR-995 point 3). A source with a low cadence may stay while it passes; one that fails is dropped at the next build (section 4.4).
5. **Fetchable as data.** An `https` URL on the maintainer's own host (or raw GitHub or jsDelivr for the same repository), with a fixed URL prefix (ADR-995 point 1), in a format the pipeline normalises (section 5.2).
6. **Two people.** Admission needs a second reader of the licence evidence (section 4.2).

**4.1b A separate copyleft list** (GPL-3.0, CC BY-SA, or a dual licence taken under its GPL option) meets points 2 to 6 and, in addition, has the maintainer's written yes for hosted commercial use (owner decision 1) and a lawyer's answer to the questions in section 7.3 that apply to its licence. Until both exist it is `held`.

### 4.2 Who checks what

| Step | Who | Recorded |
|---|---|---|
| Propose a source | anyone (an issue labelled `curation`) | name, URL, the categories it would serve, why |
| Read the licence, the terms and the README, and for a compilation its upstream list | a maintainer of WrenDNS | SPDX id, licence URL, the quote, the terms URL and quote, the upstream list URL and each upstream's licence, retrieved date, the SHA-256 of each file read |
| Second reading | a second person, not the first reader | agrees or disagrees, with the reason; a disagreement goes to the owner |
| Ask the maintainer (copyleft, custom terms, or where the research asks for a written confirmation) | the owner (letters in section 6.6) | the question sent, the answer, its date, kept with the record |
| Admit | the owner | a commit to the source registry naming the record, reviewed like code |

The registry is data, reviewed like code (ADR-995 rejected a catalog fetched at runtime for the same reason). Where it lives depends on the delivery model (open question 8).

### 4.3 Re-checks

- **Weekly, automatic:** the existing `catalog-check` job's checks (licence id against the GitHub API, last push, `archived`, header entry count; `scripts/check-catalog.py`) extended to every registry source, plus a hash of each source's LICENSE file and README licence section compared with the recorded hash, and for a compilation the hash of its upstream list. Any change opens an issue labelled `curation`, as the job does for the catalog today.
- **Every 90 days, by a person:** the full reading in 4.2 again for every admitted source, recorded with the new date. A source not re-read within 90 days is dropped from the next build.
- **On demand:** a maintainer's objection (section 6.5), a report that a source added something it should not have (section 10), or a change found by the weekly job.

### 4.4 When a licence changes or a repository is archived

- **The licence or terms change** (the weekly job sees a different LICENSE hash or SPDX id): the next build **does not fetch** the source and keeps its last admitted snapshot out of the output too; the source is re-read. If the new terms still pass, it is re-admitted with a new record. If not, it is dropped. Entries it alone contributed leave the output at the next build; that is a removal the diff review (section 10.2) shows.
- **A compilation adds an upstream** (its upstream list hash changes): the source is held as above until the new upstream is read.
- **The repository is archived or stops being updated past 90 days:** dropped at the next build, after the same diff review. A frozen snapshot is never kept as a "last good" input, because nobody would fix it or honour a removal request (the research's point about archived projects).
- **A maintainer objects or opts out:** section 6.5; the source is dropped at the next build and stays out.
- **What a subscriber sees:** the category's attribution page lists the change and its date; if a category falls below its minimum size (ADR-994 point 4: no checkbox that does almost nothing) it moves to "Not available" with the reason, as the catalog does today.

### 4.5 Licences already settled by the decision

Merged-permissive outputs carry their own licence: WrenDNS's choice for its own work (open question 13), plus the notices of every MIT and CC BY input (section 6). A copyleft output keeps its source's licence unchanged. MPL-2.0 is not one of the five permissive families; no admitted source uses it today (1Hosts, S29, is excluded for its upstreams).

### 4.6 WrenDNS's own entries

For thin categories and for categories with no source (alcohol, weapons, risky TLDs and the others marked N in section 2.1), WrenDNS may add its own reviewed entries. They are a source like any other in the registry (`wrendns-reviewed`, licence chosen by the owner, open question 13), each entry with who added it, why, and when it is next reviewed. They are never copied from an excluded or copyleft source, and a reviewer may not use an excluded source to find them. This is curation work the project takes on (ADR-994 rejected "one list per category written by hand" for the catalog; the owner reopens that only for the assembled lists, open question 6).

## 5. The pipeline

### 5.1 Fetch

- Each admitted source has a **pinned URL** under its fixed prefix. The fetch records, per file: the URL, the final URL after redirects (which must stay under the prefix), the HTTP status, `ETag` and `Last-Modified`, the retrieved time (UTC), the byte count and the **SHA-256**. A redirect outside the prefix, a TLS failure or a body over the source's `max_bytes` fails that source for this build; the build continues with its last admitted snapshot only if that snapshot is younger than the source's cadence allows (OBS-023's stale rule), otherwise without it.
- Fetched bytes are untrusted input (section 10.4): streamed to disk with a size cap, never executed, parsed by the normaliser only.
- **Inputs are kept** content-addressed by hash, so a build can be repeated (section 5.10). How long, and whether keeping copies of copyleft inputs needs anything, is open (lawyer question 13, open question 9).

### 5.2 Normalise

Every format the catalog reads (`domains`, `hosts`, `adblock`) plus the two new ones the research found: v2fly's `domain:`/`full:`/`include:` lines with attributes (S04), and the ShadowWhisperer `Wild_*` variants (S03). Output is one registrable-or-deeper domain per line:

- lower case; IDN converted to A-labels; a trailing dot removed; `www.` twins in hosts files folded into one entry (subtree match covers both, FLT-002);
- hosts-file addresses other than the sink (`0.0.0.0`, `127.0.0.1`, `::`, `::1`) refused for that line (a hosts entry that points elsewhere is a redirect, not a block);
- AdBlock rules kept only when they are a plain `||domain^` with no modifiers; cosmetic, URL-path, `$`-modified and exception rules are dropped and counted (the research: cosmetic rules do not translate to DNS);
- v2fly `keyword:` and `regexp:` lines dropped (they are routing hints, not domains), `include:` expanded inside the same repository only;
- lines that are IP addresses, CIDRs, or not valid names (RFC 1035 length rules) are dropped and counted.

The counts of dropped lines per reason are part of the build report; a source whose dropped share jumps between builds is flagged (section 10.2).

### 5.3 Validate

- The name has at least two labels and is not a public suffix by itself (the Public Suffix List, kept pinned like an input), except in the risky-TLD category, which is a TLD list by definition and is built from WrenDNS's own entries only.
- The name is not in the **critical set** (section 5.5) and not under a protected parent (the protected-parent and shared-infrastructure denylist that `hosted.md` already gives the class-map validator).
- Per source and per category, the size is within the caps of section 10.2.

### 5.4 De-duplicate

Within a category and tier, a name listed by several sources is one entry with all of them in its provenance (5.7). A name covered by a shorter suffix already in the same list is dropped (subtree match makes it redundant, FLT-002), and its provenance is merged into the parent's. Across categories, a name may sit in several categories; that is expected (a scam site is also a fake store) and not de-duplicated.

### 5.5 Allowlists and the popularity guard

- **Allowlist sources.** WrenDNS's own allowlist (`wrendns-allow`, reviewed entries with a reason each, licence chosen by the owner) applied last, and **persistent**: a domain on it stays out even when an upstream re-adds it (the research's practice from the Block List Project and 1Hosts). Third-party allowlists are admitted under the same rule as sources: the only one the research checked, `anudeepND/whitelist` (S56), is archived and excluded. Copyleft lists are never used as an allowlist for a permissive output.
- **The critical set.** Names that are never blocked by an assembled list whatever a source says: operating-system and app-store update and connectivity-check names, captive-portal checks, certificate revocation and time services, the major platform roots the research names (Apple, Microsoft, Google and Meta, after oisd's practice), and the service's own names. Kept by hand, reviewed every 90 days.
- **The popularity guard.** A ranking of the most popular registrable domains, used inside the build only and never republished. The only ranking the research cleared is the **Majestic Million** (S14, CC BY 3.0, attribution); Tranco (S63) and Cisco Umbrella (S64) are unclear until answered. Rule (the numbers are a proposal, open question 4): a name among the top 10,000 enters a category only if **two independent admitted sources** list it in that category, or a reviewer has approved it in WrenDNS's reviewed entries for that category. So a large adult site is still in Adult (several sources list it), and a news site that one source wrongly put in Adult is held for review instead of blocked for every subscriber. Two sources are independent when neither is a known input of the other (recorded in the registry).
- **No copyleft signal.** The guard and the "two sources" count use admitted permissive sources and WrenDNS's own reviewed entries only. A HaGeZi or UT1 list never confirms, ranks or removes an entry in a WrenDNS-owned list, so a merged output never depends on copyleft data (lawyer question 3 asks whether that separation holds).

### 5.6 Dead-domain pruning

From the research's practice (oisd prunes every 5 days; the Block List Project scanned weekly; AdGuard's linter confirms with DNS): weekly, a name that gives **NXDOMAIN** for its registrable domain on two runs a week apart is removed and logged. Timeouts and SERVFAIL never count (they are the resolver's problem, not the name's). Queries go through the service's own recursive resolver (DNS-012), not a public one, so the list is not handed to a third party. Threat categories (malware, phishing, scam, stalkerware, cryptojacking) are not pruned for 30 days after a name is first added, because threat domains are often parked and revived. A pruned name that a source still lists is not re-added until it resolves again. Removals are part of the diff review.

### 5.7 Per-domain provenance

Every entry records **which sources contributed it**, so Explain can say why a name is blocked (section 9) and a removal request can be traced to its source.

- **In the build:** each source has a small number (at most 64 per category); an entry carries a set of them. Distinct sets are few (most names come from one or two sources), so the build interns each set once and gives the entry a set index.
- **Stored outside the snapshot (Decision).** The node's snapshot stays as it is: at most 12 bytes per domain (`spec/05` §2, ADR-018), with keys mapped to list-set indexes. Provenance is a **separate file per output**, an FST map from the reversed-label key to the source-set index (the same structure the snapshot already uses for list sets), plus a small table of the sets. Its size is estimated at about the snapshot's 12 bytes per domain (a key plus a value of one or two bytes) and is **measured in T36.30 before it is fixed**; it is never loaded into the query path: Explain opens it (mmapped) when it explains a block, and a node that has no provenance file still blocks the same names.
- **Rejected:** a 12-byte provenance record inside the snapshot per domain (it would double the snapshot memory on a small node, where the compile peak already decides what fits, `content-categories.md` section 2.4); provenance only on the service with no copy on the node (Explain would need the network to answer, against rule 5: DNS and its explanations never depend on anything else).
- **In the hosted resolver:** the same file beside the resolver's snapshot.

### 5.8 Build outputs

For each build `YYYY-MM-DD.N`:

- **One file per category and tier** of WrenDNS-owned lists, domains-only format, sorted, LF line ends, a header comment naming the category, tier, build version, licence, and the URL of its attribution page. A tier is `exclusive` or `additive` as the catalog defines them (ADR-995 point 1).
- **One file per copyleft source, kept apart** (owner decision 1): the source normalised to domains (5.2) and validated (5.3), with nothing added and nothing removed except names the critical set and protected parents refuse, which the file's header lists as removed. Its header names the source, its licence, its URL and the retrieved hash; the licence text travels beside it (GPL-3.0's own condition, S15). It is never merged with another file, not even another copyleft one; a category that uses it lists it as its own source line.
- **The provenance file** per WrenDNS-owned output (5.7).
- **`manifest.json`**: the build version and sequence number, the pipeline's own version and commit, every input (5.1's record), every output (name, entries, bytes, SHA-256, licence), the registry commit, the allowlist and critical-set commits, the guard ranking's hash, and the counts of the build report.
- **`ATTRIBUTION` and `NOTICE` files** (section 6).
- **The build report:** per source and category, added, removed, held and dropped counts with reasons; the large-diff flags (section 10.2).

### 5.9 Versioning and signing

- **Versions** are `YYYY-MM-DD.N` with a monotonic **sequence number**; a consumer refuses an older sequence than it holds (rollback protection, as `hosted.md`'s content envelopes do).
- **Signing reuses what the project has (Decision).** For hosted delivery and for a subscriber's node over the tunnel, the platform channel's **content key** with scope `lists` signs the manifest (ADR-1062; the scope already exists and `hosted.md` says the node never accepts platform-signed lists as allow sources). For downloadable files, the manifest's `SHA256SUMS` is signed with **minisign**, the scheme the releases use (ADR-1034), and the node verifies it with the same code that verifies `SHA256SUMS` for self-update. **Which key signs downloadable lists is open** (open question 7): the recommendation is a separate minisign key for lists, named in the platform key manifest, so a leak of one cannot sign the other.
- The content key signs only from the pipeline's own identity, the only principal allowed to call its sign operation, after the review step of section 10.2 (the same rule `hosted.md` sets for the class map).

### 5.10 Reproducibility

A build is a pure function of: the pinned inputs (by hash), the registry, allowlist and critical-set commits, the guard ranking's hash, the Public Suffix List's hash and the pipeline's version. Sorting, normalisation and set interning are deterministic, so **two builds from the same manifest give byte-identical outputs**. A `verify` mode rebuilds from a manifest and the stored inputs and compares hashes; it runs on every build and on a schedule against an older build. The dead-domain pruning results are themselves an input recorded in the manifest (a list of pruned names with their dates), so a rebuild does not need the same DNS answers.

### 5.11 Where it runs

Two places were considered:

| | CI on a schedule (GitHub Actions) | A job in the hosted service |
|---|---|---|
| Signing key | the content key cannot leave Key Vault (ADR-1062); a minisign key would sit in CI as the release key does | the pipeline identity calls Key Vault directly |
| Copies of copyleft inputs | in CI caches and logs of a public repository | in the service's private storage |
| Dead-domain checks | from CI runners' networks | from the service's own resolver |
| Review step (10.2) | a pull request per build | the service's review queue |
| Reproducibility | anyone can rebuild from a published manifest | the same, if the manifest is published |

**Recommendation:** the build runs as a scheduled job in the hosted service (daily for light sources, as the catalog's 8-hour and 24-hour refreshes allow, never more often than its sources change), and a public CI job runs `verify` against the published manifest when the delivery model publishes one. Whether the pipeline's code is in this repository (AGPL) or in the service's repository depends on the delivery model (open question 8): under downloadable files, publishing it is what makes the build reproducible by others.

### 5.12 Size and memory budgets

The catalog's existing model applies unchanged (`presets/categories/catalog.toml` `[measured]`; `content-categories.md` section 2.3): 12 bytes per domain in the snapshot; a source above 500,000 entries is **heavy**; `[filter] entry_budget` 1,000,000 (soft); the compile peak is `min(source bytes x 5.0, merge budget) + 28 MiB`; a selection is refused when baseline RSS plus snapshot plus compile peak passes 50 % of the node's memory limit.

- **Each output records `entries` and `bytes`** like a catalog source, so the node's budget rule and the Categories view's running total need no change.
- **The permissive outputs are light.** The permissive adult sources add up to under 300,000 names before de-duplication (S03 213,982, S07 61,195, S04 about 6,165), about 3.4 MiB at 12 bytes; every other permissive category in section 2.1 is far smaller.
- **Some copyleft lists are heavy or over the default budget on their own:** UT1 `adult` has 4,600,371 entries (about 53 MiB at 12 bytes, over the default budget by itself), HaGeZi TIF full and NRD as before. Under the downloadable model these are offered only as `heavy, over the default budget` with the existing confirmation; open question 10 asks whether UT1 `adult` is offered at all.
- **Provenance files** add about 12 bytes per domain on disk (5.7), not in RSS.
- **The build job** uses the external sort the node already has, with a merge budget of 128 MiB, and records its peak RSS per build.
- **Caps per output** (section 10.2) stop a list from growing past its recorded size plus a margin without review.

## 6. Licence compliance

### 6.1 The per-source record

One record per source in the registry, kept with its evidence:

| Field | Example |
|---|---|
| `id`, `name`, `project` (the maintainer named by project, not by person) | `shadowwhisperer-adult`, "ShadowWhisperer Adult", "ShadowWhisperer BlockLists" |
| `url`, `url_prefix`, `format` | as in the catalog |
| `spdx` (or `LicenseRef-<name>` for custom terms) | `Unlicense` |
| `licence_url`, `licence_quote`, `licence_sha256` | the file read, the operative sentence, the hash of the file |
| `terms_url`, `terms_quote` (when the source has terms beside its licence) | |
| `commercial` | `yes` / `no` / `unclear`, with the quote that decides it |
| `compilation` | `no` (with the quote saying it is original) or the upstream list URL, its hash, and each upstream's licence |
| `attribution` | the exact text the licence asks for, or empty |
| `notice` | the copyright and permission notice to reproduce (MIT, Apache-2.0) |
| `kind` | `merged-permissive`, `separate-copyleft`, `guard` |
| `permission` | the maintainer's written answer, its date and where it is kept, when one was asked |
| `checked`, `checked_by`, `second_reader`, `next_check` | dates and people (people by role in public outputs) |
| `retrieved`, `sha256` | per build, in the manifest |

The research's own suggestion (per-source SPDX id, licence URL and quote, attribution text, a commercial flag, the retrieved date and the hash) is this record; T145's manifest shape (S57) is the model for the file.

### 6.2 The ATTRIBUTION page per category

Generated by every build, one page per category and version, from the records:

- the category, its tier, the build version and date;
- **every source that contributed at least one entry**, by project, with its licence, a licence link, its attribution text where the licence asks for one, the number of entries it contributed and whether WrenDNS modified it ("normalised to domains, de-duplicated, filtered by the WrenDNS allowlist", the indication of changes CC BY and CC BY-SA ask for);
- the separate copyleft lists the category can use, each with its licence and its own attribution;
- the disclaimer the sources ask for (no warranty; HaGeZi's "as-is" wording; CERT Polska's no-endorsement condition);
- the address for objections (6.5).

The page is published on the project site (a site page, DOC-006) and shown in the UI (section 9). The models the research names are StevenBlack's upstream table and Phishing Army's sources page.

### 6.3 NOTICE handling

- A WrenDNS-owned output's `NOTICE` reproduces every MIT and Apache-2.0 notice and every CC BY attribution of its contributing sources, generated from the records, and travels with every copy (downloadable files) and is linked from the attribution page (hosted).
- A copyleft file carries its own licence text beside it and nothing else is added to it.
- `docs/third-party-notices.md` gains a section "Assembled category lists" that explains the two kinds and links the attribution pages; its existing section on catalog lists stays true for the catalog.

### 6.4 The separate-file rule for share-alike and GPL sources

A GPL-3.0 or CC BY-SA source is **never merged** with any other source, permissive or copyleft. It is one output file under its own licence, normalised and validated only (5.8). It is not used as a signal for a permissive output (5.5). The node and the hosted resolver may apply several files to one group, which makes them a collection side by side, not a single work; whether that holds in law is lawyer question 3. A subscriber chooses copyleft lists separately in the UI (section 9), and each shows its own licence.

### 6.5 Objections and opt-out

- A role address at wrendns.com for list maintainers and anyone named by a list (proposed `lists@wrendns.com`; the owner sets it), published on every attribution page and the site.
- **A maintainer's opt-out** takes their source out of the next build and keeps it out; no argument is needed. The attribution page records the date.
- **An objection to an entry** (a business that says it is wrongly listed) is a false-positive report (section 8) with its own queue.
- Answers within a stated time (open question 12 sets it); every objection and its outcome is logged.

### 6.6 Maintainers to write to

By project. The owner sends; each letter asks a short, answerable question and says what WrenDNS will do with the data, under which delivery model, and how it will credit them.

| Project | Ask |
|---|---|
| HaGeZi | (1) Yes or no to hosted commercial use of the content, networking and TIF lists as separate GPL-3.0 files (S15, S17), in a hosted resolver and, if chosen, as downloadable files. (2) Whether the Multi tiers (S16) carry anything from the `pgl.yoyo.org` list, 1Hosts, oisd or other non-commercial inputs, or only signals. (3) The terms of the subscription feed behind NRD and DGA (S18). (4) The attribution text wanted. |
| AdGuard | (1) Hosted commercial use of the DNS filter (S20) and of `services/` in HostlistsRegistry (S21) as separate GPL-3.0 files. (2) The licences of the regional inputs of the DNS filter (S20). (3) What use of the AdGuard name is acceptable in the attribution. |
| EasyList | Confirmation that hostnames extracted from EasyList and EasyPrivacy may be used under the GPL-3.0-or-later option in a hosted service and in separate files, and the attribution form ("The EasyList authors"). |
| UT1 (Université Toulouse Capitole) | (1) The licence on the university's own site (it was unreachable). (2) Hosted commercial use as separate CC BY-SA 4.0 files. (3) Whether to fetch from the mirror or the university's tarball. (4) The attribution text. (5) Whether the university claims a database right beyond the licence (lawyer question 2). |
| Bon-Appetit | The rights in the compiled output given the unlicensed inputs in `block-sources.csv` (S25), and hosted commercial use under CC BY-SA 4.0 with the requested credit line. |
| AssoEchap | Written confirmation of CC BY 4.0 for a paid service, and the attribution text (S09). |
| CERT Polska | That merging the Warning List into a WrenDNS-owned list, and distributing it if chosen, is within "any purpose", and how they wish to be named without implying endorsement (S10). |
| Scam Blocklist (`durablenapkin/scamblocklist`) | Whether any entries were copied from the Dandelicence list (S12). |
| ShadowWhisperer | Confirmation that the lists are original work as the README says, and whether a credit is wanted (S03; none is required). |
| Phishing.Database, PhishTank, Frogeye, Tranco, Cisco Umbrella | Only if the owner wants these sources: their provenance (S44), the Data and redistribution terms and the CC BY-SA 2.5 notice (S43), the data licence (S32), the ranking's licence (S63, S64). |

## 7. Delivery

### 7.1 The two models

| | **A. Hosted only** | **B. Hosted and downloadable** |
|---|---|---|
| What happens | The assembled lists are applied inside WrenDNS Cloud's resolver (T36.12) for subscribers' roaming queries. Nothing is handed to anyone. | As A, plus signed files published for nodes to download: subscribers' own nodes (over the platform channel or wrendns.com) and, if the owner chooses, any self-hosted node. |
| The subscriber's home node | Keeps the catalog's sources downloaded from their maintainers (ADR-995). **Home and away can differ** for the same category id; the UI says which source set answered. Sending the assembled list to the subscriber's node over the tunnel is a copy handed over, so it belongs to model B legally (lawyer question 6). | Uses the same assembled list at home and away, so a category means the same thing everywhere. |
| Legal acts | Copies made and kept by WrenDNS for its own service; per-query answers to subscribers; a public attribution page. | All of A, plus distribution of copies: permissive outputs with their notices; copyleft files under their own licence with the licence text (and, for GPL-3.0, its source-offer duty for the data as distributed). |
| Main legal questions | 3, 4, 5, 7, 8, 11, 12, 13, 14 | all of them, especially 3, 6, 7, 11 |
| Technical needs | the pipeline, provenance and attribution; delivery to the cloud resolver's snapshot; provenance for the resolver's Explain; reports in the portal | all of A, plus public hosting of signed files, the node's "assembled by WrenDNS" catalog source with signature checks (FLT-905), and a published manifest for `verify` |
| Who benefits | roaming subscribers only | subscribers at home and away; self-hosters if offered |
| Risk the research names | "lower risk, not zero" | share-alike and GPL obligations are live for every copy |

### 7.2 Built either way

The source registry and admission (section 4); the pipeline with provenance, outputs, manifest and `verify` (section 5); signing with the content key (5.9); the attribution pages and NOTICE (section 6); the objection address; the false-positive reports (section 8); the review step and caps (section 10); the portal's category picker showing "assembled by WrenDNS" and separate copyleft lists (section 9). Model B adds the node's catalog source kind, public hosting and the minisign key.

### 7.3 Questions for a lawyer

1. **US copyright in a domain list.** Under *Feist v. Rural* (facts are not protected; a compilation is protected only for original selection and arrangement), is a maintainer's categorised domain list protected at all? Does merging, de-duplicating and re-categorising several lists copy any protected selection?
2. **The EU database right.** Under Directive 96/9/EC, does extracting or re-using a substantial part of an EU-made list (UT1, CERT Polska) infringe the maker's sui generis right, absent a licence? Does CC BY-SA 4.0 (which licenses sui generis rights in section 4) cover it fully? Who qualifies as the maker, and does it matter that WrenDNS's operator is a US company serving EU subscribers?
3. **Share-alike reach on merged lists.** If permissive lists are merged into one de-duplicated list, and a GPL-3.0 or CC BY-SA 4.0 list is applied beside it as a separate file to the same subscriber, is the result a collection (each keeps its licence) or an adaptation (CC BY-SA section 1, "Adapted Material"; section 4 on databases)? Does the separation in 5.5 (no copyleft data used as a signal, allowlist or ranking for a permissive output) keep the merged list outside the copyleft terms?
4. **Network use of GPL-3.0 data.** Is answering DNS queries from a GPL-3.0 list in a hosted resolver "conveying" it? Does the AGPL-3.0's section 13 (the resolver itself is AGPL software, possibly modified) reach the data it loads?
5. **CC BY-SA data used inside a service.** Is answering a query from a CC BY-SA 4.0 list "Sharing" in the licence's sense (making material available to the public)? If not, which conditions still apply (attribution on a public page)?
6. **Delivery to a subscriber's own node.** Is sending a signed list to a subscriber's node over the tunnel distribution, and to whom are the obligations owed? For GPL-3.0 data, what is the "Corresponding Source" of a normalised domain list?
7. **GPL data and the commercial licence.** Does shipping or serving GPL-3.0 data files next to WrenDNS's AGPL and commercially licensed software (ADR-1033) affect the commercial licence (GPL-3.0 section 5, "aggregate")? Must the service's proprietary code stay clear of anything the GPL data could reach?
8. **Compilations with non-commercial inputs.** Where a GPL compilation takes non-commercial lists as inputs but says nothing is copied one to one (HaGeZi Multi tiers, S16), or a CC BY-SA compilation includes unlicensed inputs (Bon-Appetit, S25), what is the residual risk for a paid service, and is the compiler's written yes enough when the upstream terms bind independently?
9. **Custom terms.** Is CERT Polska's "any purpose, including commercial purposes" enough to merge and, under model B, distribute? For PhishTank, what does the "Data" versus "Content" split allow, and what does the CC BY-SA 2.5 notice on its terms page cover?
10. **Public-domain tools on data.** Are the Unlicense (which speaks of "software") and CC0 effective dedications of a domain list in the US and the EU, including any database right?
11. **Attribution form.** Is a per-category attribution page, linked from the UI, from Explain and from each file's header, a "reasonable manner" under CC BY and CC BY-SA 4.0 section 3(a)? For MIT data merged into a list, is a generated NOTICE file beside the list enough for "included in all copies or substantial portions"?
12. **Labelling and liability.** Putting a business's domain in "Scam", "Phishing" or "Fake news" in a paid service: what notice, appeal and disclaimer are needed? (The research's nearest precedent is a 2017 DMCA notice that removed a domain from EasyList.)
13. **Keeping input copies.** Is storing every fetched input by hash, for audit and reproducibility, a problem for any licence or term in section 3, and for how long may they be kept?
14. **Popularity rankings used internally.** Does using the Majestic Million (CC BY 3.0) only inside the build, never republished, need attribution, and would Tranco's inputs (CC BY-NC 4.0) make its internal use commercial use?

**This document is not legal advice, and none of these questions is answered here.**

## 8. False positives and reports

- **Allowlist sources** are in 5.5: WrenDNS's own reviewed allowlist (licence chosen by the owner, open question 13) and the critical set; no third-party allowlist is admitted today (`anudeepND/whitelist`, S56, is archived; a one-time reviewed import is open question 15). Allowlists are applied last and persist against upstream re-adds.
- **How a subscriber reports one.** From Explain or the query log on the node, and from the portal: "Report a wrong block" on a blocked name, which sends the name, the category, the build version, the provenance (which sources listed it), the subscriber's note and, only with the subscriber's consent, nothing else (no device, no address: the privacy levels of ADR-102 apply). A subscriber can also report a missing block ("this should be in Adult"). Reports go to the service's queue; the subscriber sees each report's state (received, accepted, refused with the reason, fixed in build N).
- **Triage.** A reviewer checks the name against the category's description. An accepted wrong block goes into the WrenDNS allowlist for that category (or all categories), with the report as its reason, and leaves at the next build; an urgent one (a critical or widely used name) triggers an out-of-cycle build. A refused report says why.
- **Back upstream.** Each source's report channel is in the registry (the research lists them: GitHub issues with labels, web forms, a "Remove Request" template, e-mail). For an accepted wrong block, the reviewer files a report with every source that listed the name, citing the evidence, under the project's name, never the subscriber's (open question 12). The WrenDNS allowlist entry stays until the source has removed the name for two builds. Missing blocks found by subscribers go to the permissive sources as suggestions, never to copyleft sources as WrenDNS data.
- **Self-hosters** (model B) report the same way from the node; the node only sends what the subscriber confirms.
- **No SLA** is promised at first (the research found none anywhere); the portal states the expected time once the owner sets it (open question 12).

## 9. The catalog and the UI

The assembled lists join the existing catalog (ADR-995) as sources of a new kind, so the Categories view (`content-categories.md` section 5), the profile editor and Explain stay one place. Every surface this design adds needs its UI control or view, help topic and Playwright test in the same task (the standing rule):

| Surface | Where | Control or view | Task |
|---|---|---|---|
| A category's "Assembled by WrenDNS" source | Categories view source line and info popover; Lists page owned chip | the source row names "Assembled by WrenDNS", the build version, the date, the entry count, the licence, and links to the attribution page; a "Signature verified" or "Signature failed" state | T36.32 (FLT-905) |
| Separate copyleft lists | Categories view, per category | each as its own source line with its licence and attribution, a checkbox to use it in this profile, off by default, and a "held" state with the reason when it is not yet offered | T36.32 |
| Choice between the assembled list and the maintainers' own lists (model B, self-hosted) | Categories view, per category; Settings default | a segmented control "Assembled by WrenDNS / From each maintainer" | T36.34 |
| The attribution page | Categories view "Sources and licences" drawer; the site; the portal | the generated page for the category's current build, readable offline from the build's files on the node | T36.31 (site and portal), T36.32 (node) |
| Provenance in "why was this blocked" | Explain (FLT-013), the query log's detail panel, the device policy panel (ADR-996) | "Blocked by category Adult (Assembled by WrenDNS, build 2027-01-15.1); listed by ShadowWhisperer Adult and Sinfonietta" with links to those sources' attribution entries | T36.32 |
| Home versus away (model A) | Explain on the node and in the portal; the device policy panel | a line saying which source set answered: the catalog's maintainers' lists at home, the assembled list in the cloud resolver | T36.31, T36.32 |
| Report a wrong block, report a missing block | Explain, the query log's detail panel, the portal | a button and a short form, then a "My reports" view with each report's state | T36.33 |
| A held update | the Lists page (owned list), health panel | "Update held for review: 3,412 names added (cap 1,000)"; admin release or refuse, as the class-map hold in `hosted.md` | T36.31, T36.32 |
| Health reasons | health panel and `GET /api/v1/health` | `curated_signature_invalid` (severe; the last good list stays), `curated_stale` (degraded), `curated_held` (info) | T36.32 |
| The objection address and opt-out | the site's attribution pages and a "For list maintainers" page | a public page, not a node control | T36.31 |
| The review queue, the registry and admission records | the service's admin console (service repository) | the review step of 10.2 and the admission records of 4.2 | T36.29, T36.30 |

API and MCP: `GET /categories` gains, per source, `kind` (`maintainer`, `assembled`, `copyleft-separate`), `build`, `signature` and `attributionUrl`; Explain's block reason gains `provenance: [sourceId]`; reports are `POST /api/v1/reports` (operator) with a read for their state. No write tool for agents: a report is a person's statement (`spec/13` §3.2 is unchanged).

## 10. Security and abuse

### 10.1 A poisoned upstream

The threat: a source (compromised, sold, or hostile) adds a major domain (a bank, a search engine, an OS update host), and every subscriber loses it at the next build. Or a source drops thousands of real threats at once.

- The **critical set** and protected parents refuse such a name outright (5.3, 5.5); the refusal is logged per source and a source that hits the critical set is flagged for re-reading (4.3).
- The **popularity guard** holds any top-10,000 name that only one source lists (5.5).
- **Provenance** tells a reviewer at once which source added a name, so one bad source can be dropped without touching the others.

### 10.2 Caps on growth, and review of large diffs

Proposed numbers (open question 3):

- **Per source:** an update that adds more than 10 % of the source's previous size and more than 1,000 names, or removes more than 20 %, is **held**: the build uses the source's previous snapshot and the diff goes to review.
- **Per output:** a build that adds more than 1,000 names to a category, the same number `hosted.md` uses to hold a class-map version for 72 hours, needs a reviewer's approval before it is signed. Removals over 20 % also need it.
- **What the reviewer sees:** the diff by source, the popularity ranks of added names, the names that hit the guard, and a sample. Approval is recorded in the manifest (who, when).
- **On the node:** `hosted.md` holds a platform-signed version that adds more than 1,000 patterns for 72 hours, with a notice, which an admin may release or refuse sooner. ADR-1087 point 9 applies that hold to signed `lists` content explicitly. A held list keeps the last good one; nothing is ever emptied (FLT-004).

### 10.3 Signing and rollback

The manifest's signature, sequence number and expiry are checked before a list is compiled; an older sequence, a wrong scope, another tenant's object or expired content is refused (ADR-1062). Platform-signed lists are never allow sources, so a compromised pipeline can block names but never unblock one. Revoking the content key drops what it signed after its `compromised_after` time (ADR-1062).

### 10.4 The supply-chain position of fetched data

- Fetched lists are **untrusted input to a parser**, never code. The normaliser runs with size and time caps, in a job with no secrets other than its own storage (the signer is a separate step that receives only the outputs and the manifest), and its parsers are fuzzed (NFR-004).
- Every input is pinned by hash in the manifest; a rebuild from the manifest must give the same outputs (5.10), so a changed input cannot hide.
- Sources are fetched only over HTTPS from their fixed prefixes, with redirects kept under the prefix (ADR-995 point 1).
- The pipeline's own dependencies follow NFR-005 (`cargo-deny`, SBOM) if it is Rust, or the equivalent for its language; GPL tools are not used (S61, AGENTS.md rule 6).
- Dead-domain checks go through the service's own resolver (5.6), so the list is not sent to third parties.

## 11. Phasing, acceptance criteria and open questions

### 11.1 Phases (tasks in `spec/10`, M36, all after the public 1.0)

| Task | Phase | Acceptance criteria (summary; full text in `spec/10`) |
|---|---|---|
| **T36.28** Legal review and maintainer letters (owner steps) | 0 | The lawyer's written answers to section 7.3's questions; the letters of section 6.6 sent and their answers recorded; the owner's choice of delivery model recorded as an amendment to ADR-1087. |
| **T36.29** Source registry and admission | 1 | Every source in section 3 has a record (6.1); admission needs a second reader; `scripts/check-catalog.py` (or its successor) checks the registry weekly and opens an issue on a licence-file hash change; a compilation without a read upstream list cannot be admitted (a test). |
| **T36.30** The build pipeline | 2 | Fetch, normalise, validate, de-duplicate, allowlists, guard, pruning, provenance and outputs as section 5; two builds from one manifest are byte-identical; a copyleft source never reaches a WrenDNS-owned output and never changes one (a test that removes every copyleft input and compares); the provenance file's bytes per domain measured and recorded. |
| **T36.31** Signing, review, attribution and hosted delivery (model A) | 3 | The content key signs only after review; growth caps hold as 10.2; attribution pages and NOTICE generated per build and published on the site; the cloud resolver applies the assembled lists; Explain in the portal shows provenance and which source set answered. |
| **T36.32** The node's side: assembled sources, provenance, attribution view (FLT-905) | 4 | The catalog source kind with signature checks; Explain names the contributing sources; the UI surfaces in section 9 with help topics and Playwright tests; no change to the query path (`make bench-smoke`). |
| **T36.33** False-positive reports and upstream flow | 5 | Report a wrong or missing block from the node and the portal; the reviewer's queue; an accepted report reaches the allowlist and the next build, and a report is filed with every source that listed the name. |
| **T36.34** Downloadable files for self-hosted nodes (model B; only if chosen) | 6 | Signed files on wrendns.com with their NOTICE and licence texts; minisign verification on the node; the per-category choice between assembled and maintainers' lists; a public `verify` job rebuilds from the published manifest. |

### 11.2 Open questions

| No. | Question | Who answers |
|---|---|---|
| 1 | Delivery: hosted only (A), or also downloadable (B)? | the owner, after the lawyer (T36.28) |
| 2 | Is CERT Polska's custom permissive policy admitted as "permissive" for merging (S10)? | the owner, after lawyer question 9 |
| 3 | The growth caps of 10.2 (10 % and 1,000 names per source, 1,000 names per output, 20 % removals). | the owner |
| 4 | The popularity guard: top 10,000, Majestic Million only while Tranco and Umbrella are unanswered, two independent sources. | the owner |
| 5 | Offer a permissive Cryptocurrency category, given the 2026-11-18 decision against a hand-written crypto bundle? | the owner |
| 6 | WrenDNS's own reviewed entries for thin and empty categories (4.6): which categories, and who curates? Replace the authored AI and Dating service bundles with assembled lists, or keep both? How does an assembled AI category sit beside Shadow AI's hosted-only catalog (ADR-1055)? | the owner |
| 7 | One signing key for downloadable lists or a separate minisign lists key named in the platform key manifest (5.9)? | the owner |
| 8 | Where the pipeline's code and the registry live: this repository (AGPL) or the service's repository? | the owner, with question 1 |
| 9 | How long input copies are kept (5.1). | the owner, after lawyer question 13 |
| 10 | Is UT1 `adult` (4.6 million entries) offered at all, and only hosted? | the owner |
| 11 | Sources the research flagged but did not cover: NetAPI Top 1M (CC BY 4.0 per HaGeZi's `sources.md`, not opened), anti-AD, hostsVN, AdAway, Tiuxo as standalone sources, StevenBlack's own data and FadeMind, and NRD from zone files under WrenDNS's own contract. Research them? | the owner orders the research |
| 12 | The objection address, the answer time for objections and reports, and whether reports upstream go under the project's name. | the owner |
| 13 | The licence of WrenDNS's own outputs, reviewed entries and allowlist (for example CC0 or CC BY 4.0). | the owner, after lawyer questions 3 and 10 |
| 14 | The requirement rows: FLT-905 (node side) and CLD-918 (service side) are reserved here; their rows are added to `spec/01` when T36.29 starts, as the hosted rows are (the CLD section's note). | the owner, at the start of the build |
| 15 | A one-time reviewed import of `anudeepND/whitelist` (MIT, archived) into the WrenDNS allowlist? | the owner |
| 16 | Which tiers of the service get assembled lists and which copyleft lists (`hosted.md`, "Tiers")? Do self-hosters who do not subscribe get model B files? | the owner |
| 17 | HaGeZi, AdGuard, EasyList, UT1, Bon-Appetit, AssoEchap, CERT Polska and Scam Blocklist: the answers asked in 6.6. | each maintainer |
| 18 | The lawyer's answers to section 7.3, questions 1 to 14. | a lawyer |
