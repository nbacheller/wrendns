# Curated category lists: design notes

**Status:** design only, for the owner's review. **ADR:** ADR-1087 (Proposed 2026-11-24). **Milestone:** M36 (WrenDNS Cloud, fork #41, `docs/design/hosted.md`), tasks T36.28 to T36.34 in `spec/10`, all after the public 1.0 release. **Requirements:** builds on FLT-901, FLT-902, FLT-004, FLT-013, OBS-023, NFR-004, NFR-005 and NFR-006; reserves **FLT-905** (the node's side) and **CLD-918** (the service's side), whose rows are added to `spec/01` when the build starts (section 11, open question 14). No code is written by this change.

**This document is not legal advice.** It records what the research of 2026-11-24 found, what the owner decided, and the questions a lawyer must answer before anything here is offered for money. Where it says a source is "allowed", that is the research's reading of the source's own licence text, not a legal opinion.

*Decision* means build it this way; amend ADR-1087 if you can't. *Open* means someone named in section 11 decides. Read `docs/design/content-categories.md` (the catalog), ADR-994 and ADR-995, and `docs/design/hosted.md` (the service, the platform channel and the open-core boundary) first.

**Owner decisions, 2026-11-24 (binding):**

1. **Sources.** Merge only permissive sources (MIT, Apache-2.0, CC0, Unlicense, CC BY) into lists WrenDNS owns. Keep GPL and CC BY-SA sources (HaGeZi, AdGuard DNS filter, EasyList/EasyPrivacy, UT1, Bon-Appetit) as separate, unmerged, attributed lists under their own licence, and write to their maintainers for a clear yes for hosted commercial use.
2. **Delivery** (applied only inside the hosted resolver, or also published as downloadable files for self-hosted nodes) is decided after a legal review. This design keeps both open and says what each requires (section 7).
3. **Now:** a design document and an ADR for the owner's review. The build belongs with the hosted-service milestone (fork #41, `docs/design/hosted.md`), after the public 1.0 release.

**Owner decisions, 2026-11-24, second batch (binding):**

1. **Growth caps** (open question 3, closed): the caps of 10.2 are accepted as proposed.
2. **Popularity guard** (open question 4, closed): accepted as proposed, top 10,000 and two independent sources (5.5). What the second reading found about the rankings is in 3.2, and one item stays open there (open question 20).
3. **Signing key** (open question 7, closed): a separate minisign lists key, named in the platform key manifest, not the release key (5.9).
4. **Allowlist import** (open question 15, closed): a one-time reviewed import of `anudeepND/whitelist` into the WrenDNS allowlist, yes (5.5).
5. **Cryptomining** (open question 5, closed): a cryptomining-only category (browser miners and mining pools). No category for exchanges, wallets or crypto news, consistent with the decision of 2026-11-18.
6. **UT1 `adult`** (open question 10, closed): offered only as a separate attributed list under its own licence, and only after UT1's maintainers answer yes to hosted commercial use. The WrenDNS Adult category is built from permissive sources.
7. **Further research** (open question 11, closed): ordered and done on 2026-11-24 (the second reading, 3.2).

All other open questions stay open (11.2).

**The research** (2026-11-24): six researchers' reports and two sceptical licence checkers' verdicts, kept outside the repository with the owner. Where a checker's verdict differs from a researcher's claim, the checker's verdict is used here. A second run the same day (the second reading, 3.2: four readers and fifteen checkers) is kept with the first. No fact in this document comes from anywhere else; what the research did not establish is written as an open question.

## 1. Purpose, non-goals, and what changes

### 1.1 Purpose

WrenDNS assembles and maintains its own per-category filter lists ("assembled lists") from public sources, for the subscribers of the planned hosted service and possibly for self-hosted nodes. An assembled list is one file per category and tier, with a record of which source contributed each domain, a generated attribution page, a signed manifest and a build that can be repeated from its pinned inputs.

Three things motivate it. The catalog has many "Not available" rows (`presets/categories/not-offered.toml`) that permissive sources could fill (dating, AI services, crypto, typosquatting, and stalkerware once its maintainer confirms its licence). A paid service needs lists whose licence allows hosted commercial use, which the copyleft compilations the catalog uses today do not state plainly. And a subscriber who reports a wrong block expects the service to fix it, which needs a list the service controls.

### 1.2 Non-goals

- **No change for self-hosters who never subscribe.** The catalog of ADR-995 stays: a node downloads each source from its maintainer at runtime, and nothing in this design removes a source from it.
- **No built-in crawler or classifier.** Categories are built from published lists and from WrenDNS's own reviewed entries, never from crawling sites or from a model that guesses a site's category (ADR-994 rejected a keyword classifier).
- **No copyleft data inside a WrenDNS-owned list.** Not merged, not used as a signal to confirm or rank permissive entries (section 5.5), not used as an allowlist.
- **No new DNS path.** The node's query path is unchanged: an assembled list is a list (FLT-001 format, domains only), compiled into the same snapshot (FLT-003).
- **No promise of child safety.** As in `content-categories.md` section 10: a category block is a DNS block, with its limits.

### 1.3 What changes against today's position

ADR-995 point 4 and `content-categories.md` section 2.2 rest on one fact: **the user's node downloads each source from its maintainer, and WrenDNS never redistributes a list.** On that basis the catalog treats the lists' redistribution terms (GPL-3.0 for HaGeZi, CC BY-SA 4.0 for Bon-Appetit) as not applying to WrenDNS, and ADR-995 records "GPL-3.0 on a dataset" as a risk for the owner, not resolved by legal review.

**The hosted design already goes past that fact.** `hosted.md` ("The roaming resolver", "Path: home relay first") and ADR-1064 point 4 have the cloud resolver, which answers a paying tenant's roaming devices while their home is unreachable, compile the tenant's public list sources itself with the node's compiler and use the result when its hash matches the primary's; otherwise it fetches the compiled blob from home and keeps it, encrypted per tenant. For a tenant whose catalog selection includes HaGeZi (GPL-3.0) or Bon-Appetit (CC BY-SA 4.0), MySummitKeep's service therefore already fetches, compiles, keeps and answers from copies of copyleft lists for money. Neither document discusses the licence side of that; lawyer question 15 asks about it, and it is open point 19 in section 11.2. This design does not change it.

Assembling and serving lists goes further again, in four ways:

1. **WrenDNS makes copies for its own product.** The build fetches each source and stores it, for every subscriber at once, not per tenant from that tenant's own selection.
2. **WrenDNS may make a new work from others' work.** Merging, de-duplicating and re-categorising may be the act that share-alike licences reach ("Adapted Material" in CC BY-SA 4.0 section 1, a "work based on" the Program in GPL-3.0); whether a merged domain list is an adaptation or a collection is lawyer question 3. A permissive licence still asks for its notice to travel with copies.
3. **WrenDNS uses the data for money.** The catalog treats non-commercial terms as not reaching a user's own home node (ADR-995); this design excludes any source with a non-commercial term from a paid service, whatever its copyright status (lawyer question 1 asks what copyright reaches at all).
4. **WrenDNS may distribute.** Under the "downloadable files" model the assembled lists are copies handed to others; under the "hosted only" model they are used inside a service that answers queries. Which obligations each act triggers is the core of the legal review (section 7.3).

This is why the owner's first decision splits sources into two kinds: permissive sources, which WrenDNS may merge into lists it owns, and copyleft sources, which stay separate files under their own licence. The working assumption is that a separate file keeps each copyleft licence to its own file; whether that holds is lawyer question 3.

## 2. The category set

### 2.1 From the existing catalog

The catalog has eight groups (seven UniFi-style plus Privacy and Ads, ADR-994 owner decision 1; Business & Professional has no offered category), 27 categories (21 backed by lists, 6 by WrenDNS's own authored service bundles) and 23 "Not available" rows. The table maps each to candidate sources from the research and marks it:

- **P**: buildable from permissive sources alone (a merged, WrenDNS-owned list), counting only sources admitted as `merged-permissive` in section 3, not `held` ones.
- **C**: needs a separate copyleft list (no permissive source, or the permissive ones are too thin to stand alone), and at least one copyleft candidate is `separate-copyleft`, waiting only on the steps of 4.1b.
- **H**: held: every candidate that could make the category worth offering is `held` in section 3, waiting on a named question (an unread licence or upstream list, a licence outside the owner's five families, a maintainer's answer).
- **N**: no usable source; own curation or a maintainer's permission is needed.
- **thin**: the permissive sources exist but are small; a WrenDNS-curated set of reviewed entries is needed before the category is worth offering on its own.

Sizes are the counts the research recorded on 2026-11-24 (file headers or line counts), before de-duplication. Source numbers (S01 and so on) refer to the table in section 3; a source marked "held" in a cell is not counted for the mark.

| Group | Category (catalog id) | Permissive candidates (merged) | Copyleft candidates (separate) | Mark |
|---|---|---|---|---|
| Adult and Sensitive Content | Adult (`adult`) | ShadowWhisperer Adult (S03, 213,982); Sinfonietta pornography (S07, 61,195 lines); v2fly `category-porn` (S04, about 6,165 lines with includes); bigdargon `hostsVN` adult slice (S68, held); the `tiuxo` input of StevenBlack's porn extension is excluded (S08) | HaGeZi NSFW (S15, held); UT1 `adult` (S24, 4,600,371, heavy, held; a separate list only after UT1 answers yes, decided 2026-11-24); Bon-Appetit (S25, held) | P |
| | Gambling (`gambling`) | ShadowWhisperer Gambling (S03, 9,689); Sinfonietta gambling (S07, 2,694); `hostsVN` gambling slice (S68, held); arfshl (S82, held) | HaGeZi gambling tiers (S15, held); UT1 `gambling` (S24, 47,823, held) | P, thin against HaGeZi's 102,937 medium tier |
| | Piracy (`piracy`) | none admitted: pedro-nsy's piracy list (S75) is held, its entries partly from GPL code | HaGeZi anti-piracy (S15, held); UT1 `warez` (S24, 1,561, held) | H |
| | Dating (`dating`, today a service bundle) | ShadowWhisperer Dating (S03, 1,439) | UT1 `dating` (S24, 10,564, held) | P, thin |
| | Alcohol and tobacco (not offered) | none | none | N |
| | Drugs and vaping (not offered) | none (Block List Project's lists are excluded, S31) | UT1 `drogue` (S24, 1,067, held) | H |
| | Weapons (not offered) | none | UT1 `dangerous_material` (S24, 54, held) | N |
| | Violence and gore (not offered) | ShadowWhisperer Shock (S03, 99); Sinfonietta snuff (S07, 23) | UT1 `agressif` (S24, 396, held) | P, thin |
| | Sex education (not offered) | none | UT1 `sexual_education` (S24, held) | H |
| | Health (not offered) | none | none | N |
| AI & Crypto | AI services and chatbots (`ai`, today a service bundle) | nullgen `ai-blocklist` (S05, 103 vendors, 211 hostnames); ShadowWhisperer AI (S03, 150); v2fly `category-ai-chat` (S04); `tbpatj/blocklists` (S06, 21,194, Extended tier only) | UT1 `ai` (S24, 80, held) | P |
| | Cryptocurrency exchanges, wallets and news (not offered) | none used: the owner decided on 2026-11-24, as on 2026-11-18, that there is no such category, so ShadowWhisperer Cryptocurrency (S03) and v2fly `category-cryptocurrency` (S04) are not used for one | none | N (declined) |
| Business & Professional | Business services; Education and government; Real estate and travel (not offered) | none | none | N |
| | Job search; Finance (not offered) | none | UT1 `jobsearch` (60,741), `financial` (S24, held) | H |
| | Shopping (not offered) | v2fly `category-ecommerce` (S04, 53) | UT1 `shopping` (S24, 36,971, held) | H (the permissive set is too thin to stand alone) |
| Culture & Entertainment | Social networks (`social`) | v2fly per-network files (S04); Sinfonietta social (S07, 3,809); Fanboy Social (S84, held); StevenBlack social extension (S08, held) | HaGeZi social (S15, held); AdGuard services (S21); UT1 `social_networks` (S24, 716, held) | P |
| | Fake news (`fakenews`) | none: the StevenBlack fakenews extension's only input, `marktron/fakenews`, is marked paused (S08), which fails the 90-day rule (4.1 point 4) | UT1 `fakenews` (S24, 1,118, held) | H, thin and contested (the research calls it politically contested and low quality) |
| | Video, Music, Games, Messaging (service bundles) | WrenDNS's own bundles (FLT-012) stay; v2fly `category-media` (178), `category-games` (S04) could add names | AdGuard services (S21) | P (own data plus S04) |
| | News; Lifestyle and religion (not offered) | none | none | N |
| | Sports; Forums and blogs (not offered) | none | UT1 `sports`, `forums`, `blog` (S24, held) | H |
| Networking Infrastructure | DoH, VPN, Tor and proxy bypass (`bypass`) | ShadowWhisperer Tunnels (S03, 1,026); v2fly `category-vpnservices` (S04, 39); reflect4 (S69, about 250) | HaGeZi DoH/VPN/proxy bypass (S15, held); UT1 `vpn` (6,039), `doh` (3,016) (S24, held) | P, thin against HaGeZi's 16,631 |
| | Dynamic DNS (`dyndns`) | ShadowWhisperer Dynamic (S03, 1,463); `antidynamicdns.txt` (S70, about 620 rules) | HaGeZi DynDNS (S15, held) | P |
| | URL shorteners (`shorteners`) | ShadowWhisperer UrlShortener (S03, 5,981) | HaGeZi URL shorteners (S15, held); UT1 `shortener` (S24, held) | P (opt-in only: the research rates both as opinion lists with a high false-positive risk) |
| | Hosting providers (`hosting`) | ShadowWhisperer Free (S03, 1,875; its README warns it breaks sites) | HaGeZi hosters (S15, held) | H (the permissive list is not safe to offer) |
| | Remote-access tools (not offered) | ShadowWhisperer Remote (S03, 176) | UT1 `remote-control` (S24, held) | P, thin |
| | Cloud storage and CDN (not offered) | not offered by design: a CDN category breaks the web | | N |
| Privacy and Ads | Ad block (`ads`) | none maintained: `lightswitch05/hosts` is stale (S33), and the permissively labelled compilations carry non-commercial inputs (S26, S29, S30) | EasyList/EasyPrivacy (S23); HaGeZi Multi tiers (S16, held); AdGuard DNS filter (S20, held) | C (EasyList and EasyPrivacy only) |
| | Pop-up ads (`popup-ads`) | none | HaGeZi pop-up ads (S15, held) | H |
| | Smart-TV trackers (`smart-tv`) | Perflyst SmartTV and AmazonFireTV (S02) | HaGeZi native vendor lists (S15, held) | P, thin |
| | App and session-replay trackers (`app-trackers`) | Perflyst android-tracking and SessionReplay (S02); AdGuard CNAME-disguised trackers (S01); no-google, its analytics, doubleclick and android files only (S67) | AdGuard DNS filter (S20, held) | P |
| | Device and OS trackers (`native-trackers`) | none maintained (WindowsSpyBlocker's data is from 2022, S34) | HaGeZi native vendor lists (S15, held) | H |
| New or Risky Domains | Newly registered (`nrd`), DGA-like (`dga`) | none | HaGeZi NRD and DGA are built on a subscription feed whose terms are unread (S18) | N (the research's alternative: generate NRD from zone files under WrenDNS's own contract; open question 11) |
| | Fake stores and scams (`fake-stores`) | ShadowWhisperer Scam (S03, 6,185); Scam Blocklist (S12, 2,142, held) | HaGeZi fake stores (S15, held) | P, thin |
| | Risky top-level domains (`abused-tlds`) | none | HaGeZi's list relies on reputation data with non-commercial terms (S19) | N (about 445 TLDs: small enough to curate ourselves) |
| | Parked domains; Newly seen; NRD 14 days and longer (not offered) | none | none | N |
| | Typosquatting (new candidate) | ShadowWhisperer Typo (S03, 73,943; quality varies) | none | P, opt-in |
| Security & Threat Protection | Malware (`malware`) | ShadowWhisperer Malware (S03, 29,527); abuse.ch Feodo and SSL Blacklist (S11, mostly IP addresses); CERT Polska (S10, held) | HaGeZi TIF (S17, held) | P, thin against TIF's 189,474 mini tier |
| | Phishing (`phishing`) | CERT Polska Warning List (S10, about 127,000; Polish-centric; held, open question 2); DNSBunker CTI (S78), NetAPI compromised domains (S76), chainapsis (S79) and spmedia (S80), all held on a named question (3.2) | HaGeZi TIF (S17, held) | H (N until open question 2 or one of those questions is answered) |
| | Scam (`scam`) | ShadowWhisperer Scam (S03); Scam Blocklist (S12, held); CERT Polska (S10, held) | HaGeZi TIF (S17, held) | P, thin until S12 or S10 is admitted |
| | Spyware and ransomware (not offered) | stalkerware: AssoEchap (S09, 929, CC BY 4.0, held for written confirmation); ransomware: none | HaGeZi TIF (S17, held) | H for a new Stalkerware category; N for ransomware |
| | Cryptomining (decided 2026-11-24: browser miners and mining pools; cryptojacking in the threat feeds today) | NoCoin (S13, about 313 domains, browser miners only); no permissive source for mining pools was found (3.2) | HaGeZi TIF (S17, held); UT1 crypto lists (S24, held); CoinBlockerLists (S50, AGPL, held) | P, thin: browser miners only until WrenDNS's own reviewed pool entries exist (4.6) |

What this shows: **adult, AI, social, app trackers, dynamic DNS, URL shorteners and the service bundles can be built from permissive sources alone; gambling, dating, violence, cryptomining, remote access, bypass, smart-TV trackers, fake stores, scam and malware can too, but thinly; typosquatting only as opt-in.** Ad blocking is the only category with a separate copyleft list that waits on nothing beyond 4.1b (EasyList and EasyPrivacy, S23). Phishing, stalkerware, piracy, pop-up ads, hosting providers, device trackers, fake news and most of Business and Culture are **held**: every candidate that would make them worth offering waits on a named question (CERT Polska's custom terms, AssoEchap's written confirmation, the upstreams of the HaGeZi compilations, the UT1 licence page and fetch location). NRD, DGA, risky TLDs, alcohol, weapons, health, news and lifestyle have no usable source and need WrenDNS's own curation (section 4.6) or a maintainer's permission. The second reading (3.2) adds permissive candidates only for Google analytics hosts (S67), DoH bypass (S69) and dynamic DNS (S70) and changes no other mark: every other new candidate is held on a named question. The thin categories are offered only after WrenDNS's own reviewed entries make them worth a checkbox (ADR-994 point 4 still holds: no checkbox that does almost nothing).

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
- `separate-copyleft`: a separate, unmerged, attributed list under its own licence, offered only after its maintainer's written yes and the legal review (4.1b);
- `held`: a candidate of either kind that waits, beyond those steps, on a named question (an unread licence or upstream list, a licence outside the owner's five families, a maintainer's answer on its inputs or its licence); it is not built and not counted in section 2.1 until the question is answered;
- `guard only`: used inside the build (section 5.5), never part of any output;
- `excluded`, with the reason.

S01 to S66 come from the first reading; S67 to S92 from the second reading (3.2). Every licence statement in S67 to S92 is a reading made on 2026-11-24 at the URL in the row ("reads as"), not a legal conclusion.

| No. | Source | Licence | Evidence | Status | By | Conditions and notes | Admitted as |
|---|---|---|---|---|---|---|---|
| S01 | AdGuard CNAME-disguised trackers | MIT | <https://github.com/AdguardTeam/cname-trackers/blob/master/LICENSE> | allowed | checker | The data file has no licence line: the repository's MIT notice travels with it. | merged-permissive |
| S02 | Perflyst PiHoleBlocklist | MIT | <https://github.com/Perflyst/PiHoleBlocklist/blob/master/LICENSE> | allowed | checker | MIT notice. Low cadence (last push 2026-09-09); already in the catalog. | merged-permissive |
| S03 | ShadowWhisperer BlockLists | Unlicense | <https://github.com/ShadowWhisperer/BlockLists/blob/master/LICENSE> | allowed | checker | README: lists come from "a custom script and manual additions"; names no third-party lists. Single maintainer; the repository history is compressed now and then, so the build keeps its own pinned copies. The Free, Junk, Marketing and Risk lists are not used (its own notes say they break sites). Second reading (checker): LICENSE re-read, still the Unlicense; the README says lists come from "a custom script and manual additions" and "I will not merge other lists"; the script's inputs are not published, so originality rests on the maintainer's word (the question in 6.6 stays open); last push 2026-11-18. | merged-permissive |
| S04 | v2fly domain-list-community | MIT | <https://github.com/v2fly/domain-list-community/blob/master/LICENSE> | allowed | checker | MIT notice. A routing taxonomy that "does NOT endorse, claim or imply that a domain should be blocked"; needs a parser for `include:` and attributes; thin on Western long-tail sites. | merged-permissive |
| S05 | nullgen-inc ai-blocklist | CC0-1.0 | <https://github.com/nullgen-inc/ai-blocklist/blob/main/README.md> | allowed | checker | The repository's `lists/` files only, not the vendor API behind the generator (terms unread). | merged-permissive |
| S06 | tbpatj/blocklists | MIT | <https://github.com/tbpatj/blocklists/blob/main/LICENSE> | allowed-with-conditions | checker | MIT notice. Broad and noisy: an Extended tier only. | merged-permissive |
| S07 | Sinfonietta hostfiles | MIT | <https://github.com/Sinfonietta/hostfiles/blob/master/LICENSE> | allowed-with-conditions | checker | MIT notice; no upstreams documented; last push 2026-09-09 (near the 90-day line). Second reading (reader, not second-checked): the 61,000-line porn list states no inputs and no originality, so 4.1 point 3 is not met on its face; one question in 6.6, and the first reading's admission stands until it is answered. | merged-permissive |
| S08 | StevenBlack/hosts extensions (gambling, social, fakenews, porn) | MIT (repository); each upstream's licence as labelled in its `update.json` | <https://github.com/StevenBlack/hosts/tree/master/extensions> | allowed-with-conditions | checker | Each extension is one upstream file with its licence label in `update.json`. The labels are StevenBlack's, not read at the upstreams: `bigdargon/hostsVN` (MIT), `tiuxo/hosts` (CC BY 4.0), `marktron/fakenews` (MIT, `"pause": true`), Sinfonietta (MIT). The checker found one label false (`brijrajparmar27/host-sources`: "CC BY 4.0" in `update.json`, no licence at the source), so no label is taken on trust. Sinfonietta is taken from its own repository as S07, not through StevenBlack. **Not taken:** `brijrajparmar27/host-sources` (no licence stated), the `Clefspeare13/pornhosts` copy frozen in 2021 (its repository is blocked) and `marktron/fakenews` (paused: fails 4.1 point 4, as S33, S34 and S66 do). Not to be confused with the unified base (S26). Second reading (readers): `bigdargon/hostsVN` read at its own repository (S68); `tiuxo/hosts` reads as CC BY 4.0 at <https://github.com/tiuxo/hosts/blob/master/LICENSE>, but was last pushed 2025-11-07 (about 382 days) and states no inputs; `Clefspeare13/pornhosts` stays unreadable (blocked 2021-10-11); `brijrajparmar27/host-sources` has no licence and a "personal use only" remark in its README (<https://github.com/brijrajparmar27/host-sources/blob/master/README.md>). | held: `hostsVN` (S68, one question); excluded: `tiuxo` (unmaintained), `marktron/fakenews`, `brijrajparmar27`, `Clefspeare13` |
| S09 | AssoEchap stalkerware-indicators | CC BY 4.0 | <https://github.com/AssoEchap/stalkerware-indicators#license> | allowed-with-conditions | checker | Attribution, no share-alike. README statement only (no LICENSE file). The checker asks for written confirmation for a paid service. Second reading (checker, in a grouped entry): README statement only, no LICENSE file; last push 2026-11-02. | held: until AssoEchap's written confirmation (6.6), then merged-permissive |
| S10 | CERT Polska Warning List | custom (CERT Polska data usage policy) | <https://cert.pl/en/warning-list/> | allowed | checker | "may be used by any user for any purpose, including commercial purposes", no warranty. Naming the source must not imply endorsement or partnership, and the CERT Polska and NASK-PIB names and logos may not be used in a misleading way. Keep a copy of the policy text. Custom terms, not one of the five licence families the owner named. | held (open question 2; lawyer question 9) |
| S11 | abuse.ch Feodo Tracker, SSL Blacklist, YARAify | CC0 | <https://abuse.ch/terms-of-use/> | allowed | checker | CC0 for these three feeds only (Terms section 3.4). Mostly IP addresses: few domains. | merged-permissive (domain entries only) |
| S12 | Scam Blocklist (`durablenapkin/scamblocklist`) | MIT | <https://github.com/durablenapkin/scamblocklist/blob/master/LICENSE> | allowed-with-conditions | checker | MIT notice. Its resources include a consumer authority's site "and by extension" a list under the Dandelicence (a custom licence with extra conditions), so some entries may derive from it; the other resources are research aids, not merged lists. | held: until the maintainer's answer on the Dandelicence list (6.6), then merged-permissive |
| S13 | NoCoin adblock list | MIT | <https://github.com/hoshsadiq/adblock-nocoin-list/blob/master/LICENSE> | allowed-with-conditions | checker | MIT notice; about 313 domains; names no upstreams; low activity (push 2026-09-12). Second reading (checker): MIT re-read at the repository's LICENSE; no inputs named in the README, the headers or the last 100 commit messages; `hosts.txt`'s own header reads "Last modified: 05 March 2025", so its data changes rarely; browser miners only, no mining pools. | merged-permissive |
| S14 | Majestic Million | CC BY 3.0 | <https://majestic.com/reports/majestic-million> | allowed-with-conditions | checker | Attribution. Used only as the popularity guard inside the build, never republished. Second reading (reader, not second-checked): the page reads as CC BY 3.0, but the site terms (<https://majestic.com/company/terms>) read as barring commercial use of site materials without a licence, so whether the grant stands for a paid service is unresolved. | guard only, held until Majestic confirms (6.6) |
| S15 | HaGeZi dns-blocklists: content, networking and native lists (NSFW, gambling, anti-piracy, social, fake stores, pop-up ads, DoH/VPN bypass, DynDNS, URL shorteners, hosters, native vendor trackers) | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/README.md> | allowed-with-conditions | checker | "A copy of the license is included in this repository and has to accompany any redistribution." "Some inputs come from third-party sources with their own licenses or terms of use"; `sources.md` lists about 233 inputs without per-source licences. The README disclaimer adds a terms layer with no commercial ban. The checker calls NSFW and gambling the safer scope, and says "a lawyer should judge whether the GPL output is clean of those inputs". A compilation whose upstreams are unread fails 4.1 point 3, which 4.1b requires. Second reading (checker): `sources.md` declares no adult input (the NSFW list reads as HaGeZi's own data) and no native-vendor input; the gambling inputs include `arkynx/blocklists`, which has no licence (S83), besides MIT, BSD-3-Clause, Unlicense, GPL-3.0 and CC BY-SA inputs; the piracy inputs are UT1 `warez` (CC BY-SA 4.0) and pedro-nsy (S75); `sources.md` says only that every source has its own licence. GPL-3.0 inputs read at their LICENSE files: `omerdduran/turk-adfilter`, `marco-acorte/antispam-it`, `dibdot/DoH-IP-blocklists`, `uBlockOrigin/uAssets`. | held (upstreams to be read; the maintainer's answer, 6.6; lawyer question 8) |
| S16 | HaGeZi Multi tiers (Light, Normal, Pro, Pro++, Ultimate; the catalog's ad tiers) | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/FAQ.md> | allowed-with-conditions | checker | Inputs include the `pgl.yoyo.org` list (terms forbid money-making use), 1Hosts Lite (non-commercial upstreams), `big.oisd.nl` and the AdGuard DNS filter. The maintainer says "None of them is copied over one to one"; the checkers leave the residual risk to a lawyer. Second reading (checker): `sources.md` calls the top-1M rankings (Umbrella, BuiltWith, DomCop, Majestic and others) "the main selection signal" for the Multi tiers and says some reputation data is used but not linked. | held (lawyer question 8, the maintainer's answer) |
| S17 | HaGeZi Threat Intelligence Feeds (TIF) | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/sources.md> | allowed-with-conditions | checker | Security inputs with their own terms: DandelionSprout AntiMalwareDomains (Dandelicence), KADhosts (CC BY-SA 4.0), a UT1 mirror (licence not verified), NetAPI compromised domains. A compilation whose upstreams are unread fails 4.1 point 3. Second reading (checker): the Stamus Labs subscription feed is also a signal inside the TIF tiers; upstreams read at their own files: DNSBunker CTI and TweetFeed (CC0-1.0, S78 and S77, both held), NetAPI (CC BY 4.0 label, S76 held), chainapsis (Apache-2.0, S79), spmedia (MIT, S80), validin-phish-feed (S81, excluded), CERT Polska (S10), KADhosts (CC BY-SA 4.0), MetaMask (DBAD 1.2, outside the families), PhishDestroy (MIT file, README "aggregated from 13+ sources" and "non-commercial"), DandelionSprout (S85). | held (upstreams to be read; the maintainer's answer, 6.6; lawyer question 8) |
| S18 | HaGeZi NRD and DGA | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/FAQ.md> | allowed-with-conditions | checker | The base data is a Stamus Labs subscription feed ("This is a subscription landing page"); its terms are unread. | excluded: unclear until answered |
| S19 | HaGeZi Most Abused TLDs | GPL-3.0 | <https://github.com/hagezi/dns-blocklists/blob/main/sources.md> | allowed-with-conditions | checker | Relies on Cloudflare Radar, Netcraft and Spamhaus reputation data. About 445 TLDs. | excluded: unclear until answered (own curation instead) |
| S20 | AdGuard DNS filter (AdGuardSDNSFilter) | GPL-3.0 | <https://filters.adtidy.org/extension/chromium/filters/15.txt> | allowed-with-conditions | checker | **A compilation** (a researcher said it was not): the EasyList and EasyPrivacy sections (taken under their GPL option) plus regional lists whose licences are unverified (AdBlockID, ABPindo, filterslists-KO, PersianBlocker, hostsVN, hufilter, Frellwits Swedish hosts, EasyList China, Dutch, Germany, Italy, Hebrew). Second reading (reader, not second-checked; sources named in <https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/configuration.json>): about 100 sources; EasyList China, Dutch and Hebrew read as having no stated terms; PersianBlocker AGPL-3.0; AdBlockID, filterslists-KO and Frellwits GPL-3.0; ABPindo and Liste FR share-alike; hostsVN MIT (S68); hufilter CC BY 4.0 (S74); AdGuard Filters' inherited rules are not itemised (its filter policy page was not fetched). 4.1 point 3 fails while those inputs stay. | held (the unclear inputs answered or dropped; AdGuard's answer, 6.6) |
| S21 | AdGuard HostlistsRegistry `services/*.yml` and safe-search rules | GPL-3.0 | <https://github.com/AdguardTeam/HostlistsRegistry/blob/main/README.md> | allowed-with-conditions | checker | `services/` is hand-written by AdGuard; `filters/` re-hosts other vendors' lists under their own licences and is not used. Reuse the data, not AdGuard's branding. Safe-search targets are vendor-documented facts WrenDNS already has (FLT-011). | separate-copyleft (`services/` only) |
| S22 | AdGuard Filters (AdguardFilters) | GPL-3.0 | <https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE> | allowed-with-conditions | checker | Mostly browser (cosmetic and URL) rules; inherited rules are not itemised. | excluded: little DNS-level data beyond S20 |
| S23 | EasyList and EasyPrivacy | GPL-3.0-or-later or CC BY-SA 3.0 | <https://easylist.to/pages/licence.html> | allowed-with-conditions | checker | Taken under the GPL-3.0-or-later option, to match the other GPL lists. Credit "The EasyList authors". Only EasyList, EasyPrivacy, EasyList Germany and EasyList Italy are covered; Fanboy lists are not. The repository has no LICENSE file, so a copy of the licence page is kept as evidence. Hostnames must be extracted from browser syntax. | separate-copyleft |
| S24 | UT1 blacklists (Université Toulouse Capitole), `olbat/ut1-blacklists` mirror | CC BY-SA 4.0 | <https://github.com/olbat/ut1-blacklists/blob/master/README.md> | allowed-with-conditions | checker | Attribution to UT1 and Université Toulouse Capitole, a licence link, an indication of changes, share-alike. No root LICENSE (the licence texts are PDFs under `blacklists/`). The university's site answered 503, so its own licence page is unread. Some lists must not be used (`examen_pix`, `tricheur_pix`, `liste_bu`). The adult list has 4,600,371 entries. A mirror is not admitted today (ADR-995 point 3, `content-categories.md` Q4), so 4.1 point 5 is not met either. | held (the UT1 site's licence page and the fetch location, then the university's yes, 6.6); `adult` only as a separate attributed list, and only after UT1 answers yes to hosted commercial use (owner decision, 2026-11-24) |
| S25 | Bon-Appetit porn-domains | CC BY-SA 4.0 | <https://github.com/Bon-Appetit/porn-domains/blob/main/LICENSE> | unclear | researcher | A requested credit line. The output "combines external sources with reviewed custom entries"; `blocklist/block-sources.csv` lists 100+ repositories, including GPL-3.0 and unlicensed ones, so the CC BY-SA label cannot clear rights in the inputs. Not checked by a checker. | held (the maintainer's answer on the inputs; lawyer question 8) |
| S26 | StevenBlack/hosts unified base | MIT | <https://github.com/StevenBlack/hosts/blob/master/data/mvps.org/update.json> | not-allowed | checker | **Overturned:** the MIT label covers the project, but the base merges MVPS hosts (CC BY-NC-SA 4.0), `someonewhocares.org` (non-commercial), the `pgl.yoyo.org` list and KADhosts. Second reading (reader): the data directory still lists them beside the MIT-labelled files and `pgl.yoyo.org` has no licence field in its `update.json`; the hand-kept `data/StevenBlack/hosts` (3,332 lines) names no provenance and takes outside contributions. | excluded: non-commercial upstreams |
| S27 | OISD big and small | GPL-3.0 | <https://oisd.nl/faq> | unclear | checker | About 150 inputs (`oisd.nl/includedlists/big`), including `vokins/yhosts`, reported as CC BY-NC-ND 4.0. The owner decided "No OISD" on 2026-11-18 (ADR-994). | excluded: unclear until answered; owner decision |
| S28 | oisd NSFW | GPL-3.0 | <https://oisd.nl/faq> | allowed-with-conditions | checker | Inputs include UT1 (via Firebog), HaGeZi NSFW, StevenBlack porn-only and several unlicensed lists. | excluded: owner decision ("No OISD") |
| S29 | 1Hosts (Lite, Pro, Xtra) | MPL-2.0 | <https://github.com/badmojr/1Hosts/blob/master/-data/lists/assets.txt> | not-allowed | checker | **Overturned:** its credits list MVPS (CC BY-NC-SA 4.0), `someonewhocares.org` (non-commercial), the `pgl.yoyo.org` list, OpenPhish, Disconnect and many unlicensed lists. MPL-2.0 is also not one of the five permissive families. | excluded: non-commercial upstreams |
| S30 | GoodbyeAds | MIT | <https://github.com/jerryn70/GoodbyeAds/blob/master/Docs/Sources.md> | not-allowed | checker | **Overturned:** upstreams are "always merged and included", several CC BY-NC-ND, CC BY-NC-SA, non-commercial, All Rights Reserved or unlicensed. Stale since 2024-11. | excluded: non-commercial upstreams |
| S31 | The Block List Project | Unlicense | <https://github.com/blocklistproject/Lists/blob/main/config/lists.yml> | not-allowed | checker | **Overturned:** archived 2026-10-27; list headers say MIT; its ads, malware, porn and tracking lists pull `zachlagden/Pi-hole-Optimized-Blocklists`, which includes the `pgl.yoyo.org` list (no money-making use) and Phishing Army (CC BY-NC 4.0), plus GPL-3.0 and CC BY-SA 4.0 data. | excluded: archived; non-commercial upstreams |
| S32 | Frogeye first-party trackers | MIT | <https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt> | unclear | checker | MIT covers the generator; the plain file has no header. Inputs are EasyPrivacy, AdGuard tracker lists and the Cisco Umbrella ranking. | excluded: unclear until answered |
| S33 | `lightswitch05/hosts` | Apache-2.0 | <https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt> | allowed | checker | Apache header on each file; last commit 2023-11-17. | excluded: unmaintained (fails the 90-day rule) |
| S34 | WindowsSpyBlocker | MIT | <https://github.com/crazy-max/WindowsSpyBlocker/blob/master/LICENSE> | allowed | checker | The data was last updated 2022-05-16. | excluded: unmaintained data |
| S35 | `pgl.yoyo.org` ad server list | custom (`pgl.yoyo.org` licence page: no money-making use) | <https://pgl.yoyo.org/license/> | not-allowed | checker | A researcher found no licence; the checkers found its licence page forbids use "in any manner that could possibly be construed as making anybody any money". | excluded: terms forbid commercial use |
| S36 | NoTrack blocklists | GPL-3.0 | <https://github.com/notracking/hosts-blocklists> | not-allowed | researcher | A researcher said "no licence"; the checker found the GitLab LICENSE is GPL v3. Abandoned: no submissions since May 2023, last commit 2023-06-26. | excluded: unmaintained |
| S37 | Disconnect tracker protection lists | CC BY-NC-SA 4.0 | <https://github.com/disconnectme/disconnect-tracking-protection/blob/master/LICENSE> | not-allowed | researcher | NonCommercial; a paid service needs a commercial licence from Disconnect. | excluded: non-commercial |
| S38 | MVPS hosts | CC BY-NC-SA 4.0 | <https://github.com/StevenBlack/hosts/blob/master/data/mvps.org/update.json> | not-allowed | researcher | Header: "License info for commercial purposes contact" the maintainer (confirmed by the checker in S26). | excluded: non-commercial |
| S39 | `someonewhocares.org` hosts | custom (non-commercial terms) | <https://github.com/StevenBlack/hosts/blob/master/data/someonewhocares.org/update.json> | not-allowed | researcher | "You are free to copy and distribute this file for non-commercial uses" (header, confirmed by the checker in S26). | excluded: non-commercial |
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
| S50 | CoinBlockerLists | AGPL (claimed) | <https://zerodot1.gitlab.io/CoinBlockerListsWeb/> | unclear | researcher | Licence file and data not reachable. Second reading (reader): the project page (<https://zerodot1.gitlab.io/CoinBlockerListsWeb/>) reads as AGPL, version unconfirmed; the repository and data returned a login redirect or a bot challenge, so a pipeline cannot fetch them (4.1 point 5) and the last-commit date is unverified. | excluded: unclear until answered (AGPL: at most a separate list, after 4.1b) |
| S51 | Spamhaus DROP and DBL | custom (Spamhaus Fair Use and commercial subscription terms) | <https://www.spamhaus.org/blocklists/domain-blocklist/> | not-allowed | researcher | Commercial use needs a subscription. | excluded: terms forbid commercial use |
| S52 | Shallalist | no licence stated | <http://www.shallalist.de/> | not-allowed | researcher | Discontinued, offline since about 2022. | excluded: unmaintained; no licence |
| S53 | Mullvad dns-blocklists | GPL-3.0 | <https://github.com/mullvad/dns-blocklists/blob/main/LICENSE.md> | unclear | researcher | Outputs merge oisd NSFW, HaGeZi gambling, URLhaus and others, with nothing separating Mullvad's own part. A reference only. | excluded: compilation |
| S54 | Ultimate Hosts Blacklist | MIT | <https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/blob/master/LICENSE> | unclear | researcher | A merge of hundreds of upstreams with their own licences. Two researchers differ (`allowed-with-conditions` and `unclear`); no checker verdict. | excluded: compilation whose upstreams are not read |
| S55 | anudeepND/blacklist | MIT | <https://github.com/anudeepND/blacklist> | allowed-with-conditions | researcher | A compilation; its upstreams are not read; the coinminer list is discontinued. | excluded: unclear until its upstreams are read |
| S56 | anudeepND/whitelist | MIT | <https://github.com/anudeepND/whitelist/blob/master/LICENSE> | allowed-with-conditions | checker | Archived (last push 2024-03-19); an allowlist of domain names, data "borrowed" from forums. | admitted only as a one-time reviewed import into `wrendns-allow` (owner decision, 2026-11-24): each name reviewed first, never re-fetched; not a live source |
| S57 | T145/black-mirror | AGPL-3.0 | <https://raw.githubusercontent.com/T145/black-mirror/master/LICENSE.txt> | not-allowed | researcher | A compilation of upstreams with their own terms. Its manifest shape (per-source licence ids) is a model for section 6.1. | excluded: compilation |
| S58 | Sefinek Blocklist Collection | CC BY-NC-ND 4.0 | <https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/main/LICENSE> | not-allowed | researcher | Non-commercial, no derivatives. | excluded: non-commercial |
| S59 | The Firebog | no licence stated | <https://firebog.net> | unclear | researcher | An index of lists. | excluded: no licence (discovery only) |
| S60 | FilterLists directory | MIT | <https://github.com/collinbarrett/FilterLists/blob/main/LICENSE> | allowed | checker | Directory data; for discovery and screening only, read from the repository's JSON (the hosted API's terms are unread). | excluded: not a list (discovery only) |
| S61 | AdGuard HostlistCompiler | GPL-3.0 | <https://github.com/AdguardTeam/HostlistCompiler/blob/master/LICENSE> | allowed-with-conditions | checker | A tool with no data. The project's licence rule bars GPL code, to keep the commercial licence clear (AGENTS.md rule 6, ADR-1033). | excluded: code, not data (not used) |
| S62 | AdGuard DeadDomainsLinter | MIT | <https://github.com/AdguardTeam/DeadDomainsLinter/blob/master/README.md> | allowed-with-conditions | checker | A tool that depends on an AdGuard web service with unchecked terms. WrenDNS writes its own pruner (section 5.6). | excluded: tool, not data (not used) |
| S63 | Tranco list | no licence stated | <https://tranco-list.eu/> | unclear | researcher | No licence for the list itself; its inputs include Chrome UX Report (CC BY-SA 4.0) and Cloudflare Radar (CC BY-NC 4.0). Second reading (reader, not second-checked): no licence or terms page (`/faq`, `/about`, `/terms` and `/license` return 404 on 2026-11-24), no licence in the repository, only a request to cite the paper; inputs are Umbrella, Majestic (CC BY 3.0), CrUX (Tranco labels it CC BY-SA 4.0, while Google reads CC BY 4.0, S71), Cloudflare Radar (CC BY-NC 4.0) and Farsight (terms unread). | excluded: unclear until answered |
| S64 | Cisco Umbrella Popularity List (Top 1M) | no licence stated | <https://s3-us-west-1.amazonaws.com/umbrella-static/index.html> | unclear | researcher | The best popularity signal for DNS, per the research; no terms. Second reading (reader, not second-checked): the page and the download state no licence, terms or attribution request (checked 2026-11-24). | excluded: unclear until answered |
| S65 | Cloudflare Gateway domain categories | no licence stated | <https://developers.cloudflare.com/cloudflare-one/traffic-policies/domain-categories/> | not-allowed | researcher | Category names only, no downloadable data. | excluded: no data (taxonomy reference only) |
| S66 | laylavish uBlockOrigin-HUGE-AI-Blocklist | CC0-1.0 | <https://github.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/blob/main/LICENSE> | allowed | checker | Last push 2025-10-02; aimed at hiding AI-generated imagery in search results. | excluded: unmaintained |

| S67 | nickspaargaren/no-google | Unlicense | <https://github.com/nickspaargaren/no-google/blob/master/LICENSE> | allowed-with-conditions | checker | Reads as the Unlicense ("for any purpose, commercial or non-commercial"); last push 2026-11-24; hand-curated by pull request, no inputs named, but it never says it is original, so it stands at S07's level. The framagit mirror is a stale copy, not an upstream and not a fetch location. An opinion list ("purge Google"): only its analytics, doubleclick and android files are taken. | merged-permissive for those files only, with a second reader and the maintainer's word that the domains are original |
| S68 | bigdargon/hostsVN | MIT | <https://github.com/bigdargon/hostsVN/blob/master/LICENSE> | allowed-with-conditions | checker; two readers disagreed | The StevenBlack reader read "unclear-ask-maintainer" (no originality statement, no inputs listed); the AdGuard reader read "merge". The checker read MIT at the repository, not archived, last push 2026-11-11, and build scripts that read only the repository's own files (no outside feed), but still no originality statement (S07's level). **The more cautious position is recorded.** Slices: Vietnamese gambling (about 4,054 domains), adult (about 1,961) and ad servers; the `threat` extension is not taken (its entries cite outside reports). The licence part of S08's and S20's hold on `hostsVN` is cleared. | held: one question to the maintainer (6.6), then merged-permissive |
| S69 | clsfo/reflect4-blocklist | CC0-1.0 | <https://github.com/clsfo/reflect4-blocklist/blob/main/LICENSE> | allowed | checker | CC0 read in the file; not archived, last push 2026-11-17. Only `reflect4_domains.txt` (about 250 domains, no header); the README says it is "updated regularly by scraping search engine results" and names no other input. DoH and VPN bypass. | merged-permissive (that file only; pin its path) |
| S70 | iam-py-test/my_filters_001 | CC0-1.0 | <https://github.com/iam-py-test/my_filters_001/blob/main/LICENSE> | allowed | checker | CC0 read in the file; last push 2026-11-23. Only `antidynamicdns.txt` (about 620 rules, changed 2026-05-14), built from providers' own published names; its comment links point to support pages and issues, not copied lists. The repository's other lists (antimalware, antipup and the lists generated from them) have untraced inputs and are not taken. | merged-permissive (that file only; pin its path) |
| S71 | Chrome UX Report (CrUX) top lists | CC BY 4.0 (stated by Google) | <https://developer.chrome.com/docs/crux/methodology> | allowed-with-conditions | checker | Reads "CrUX datasets by Google are licensed under a Creative Commons Attribution 4.0 International License"; Google is the only upstream. Tranco labels CrUX CC BY-SA 4.0 (S63): a conflict recorded, not resolved; Google's statement is the owner's. Origin-level ranks in buckets (1k, 10k, 100k, 1M), so a coarse guard only. Access is through BigQuery, whose terms were not opened; the `zakird/crux-top-lists` mirror has no licence and is not a source. Needs attribution to Google, a licence link and a note of changes. | guard only (the one ranking confirmed today, 3.2) |
| S72 | NetAPI Top 1M | CC BY 4.0 (per NetAPI) | <https://netapi.com/top-1-mln-websites/> | unclear | checker | **Overturned** (the reader said merge). The page and ToS 4.3 (<https://netapi.com/tos/>) read as CC BY 4.0 for commercial use with a credit link; it is built from Majestic (CC BY 3.0) and CrUX (CC BY 4.0) and also from an unnamed "DNS query popularity" signal whose provider and terms are not stated, so 4.1 point 3 is not met. It derives from Majestic and CrUX, so it is not independent of either. | held: ask NetAPI where the DNS signal comes from; not in the guard until answered |
| S73 | Cloudflare Radar domain rankings | CC BY-NC 4.0 | <https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/> | not-allowed | reader | The docs read "made available under the CC BY-NC 4.0 license" (a search summary says a French About page gives CC BY 4.0; the English page was not readable). Only the top 100 are ordered. | excluded: non-commercial |
| S74 | hufilter | CC BY 4.0 | <https://github.com/hufilter/hufilter/blob/master/LICENSE> | unclear | checker | **Overturned** (the reader said merge). CC BY 4.0 reads in LICENSE, README and the DNS header; last push 2026-11-16. But its `security` section is "Imported from" `FakesiteListHUN/FakeWebshopListHUN`, which has no licence (last push 2025-05-09); nothing says the work is original; the site's legal page (<https://hufilter.hu/legal>) is a separate terms layer that can change without notice; the built DNS file has about 92 hostnames, not 239. Hungary only. | held: the maintainer to say which sections are original (ads, trackers and annoyances would read as mergeable, `security` dropped) |
| S75 | pedro-nsy/nsy-dns-blocklist | MIT | <https://github.com/pedro-nsy/nsy-dns-blocklist/blob/main/LICENSE> | unclear | checker | **Overturned** (the reader said merge). The repository reads as MIT, last push 2026-11-14. But `piracy-streaming.txt` (1,186 entries) takes its video-host names from ResolveURL (a GPL-2.0 LICENSE file; plugin headers GPL-3.0-or-later) and from a discontinued NextDNS piracy list whose repository now returns 404; names are "checked against" NextDNS and AdGuard definitions, and some VPN names come from AppGoblin's traffic data (terms unread). The other lists may be mergeable once those are answered. | held: ask which entries came from which source; the piracy list at best a separate copyleft list |
| S76 | NetAPI compromised domains | CC BY 4.0 (per NetAPI) | <https://netapi.com/compromised-urls/> | unclear | checker | **Overturned** (the reader said merge). The page and ToS 4.3 read as CC BY 4.0 with merging allowed. But 126,209 of 283,878 domains (about 44.5%) are CERT Polska's Warning List, under CERT Polska's own terms (S10), not NetAPI's; 156,613 rows are sinkholed domains whose sinkhole-nameserver list has no stated origin; the plain-text file has no header. Other NetAPI data falls under ToS 4.2 (internal use). | held: NetAPI to say where the sinkhole list comes from and that CERT rows pass through under CERT's terms; those rows follow S10 |
| S77 | TweetFeed | CC0-1.0 | <https://github.com/0xDanielLopez/TweetFeed/blob/master/LICENSE> | unclear | checker | **Overturned** (the reader said merge). CC0 reads in LICENSE, README and the site terms. But the "corroborated" lists derive from abuse.ch (S41, excluded), USOM and IPsum, whose terms are unread; the source posts stay under X's terms (unread); its own terms forbid calling an IOC confirmed malicious on its presence, and its README calls the lists "unvetted". | held: the maintainer to confirm the raw lists hold nothing from abuse.ch, USOM or IPsum and how X's terms apply; if admitted, raw lists only, behind the guard |
| S78 | DNSBunker CTI | CC0-1.0 | <https://github.com/DNSBunker/CTI/blob/main/LICENSE> | unclear | checker | **Overturned** (the reader said merge). CC0 reads in the file, the README ("also commercially") and the list headers; about 523,000 domains, last commit 2026-11-24. But no input is named and it does not say it is original; intake looks automated (354,583 added in 24 hours; issue #5 reports about 980,000 removals in one update); the visible history starts 2026-11-20 though the repository dates from 2026-06-14; about 72% of its domains are also in HaGeZi TIF (S17), whose `sources.md` lists CTI as an input. Its sibling `DNSBunker_DNSBL` is a separate repository (GPL-2.0 per a reader; the checker could not open it) and is not taken. | held: the maintainer to say where the domains come from |
| S79 | chainapsis/phishing-block-list | Apache-2.0 | <https://github.com/chainapsis/phishing-block-list/blob/main/LICENSE> | unclear | checker | In a group whose merge verdict was overturned. The README says reports to CosmoShield "are synced with this repository once a day"; CosmoShield's terms returned HTTP 403 and are unread. Last push 2026-11-20. | held: Chainapsis to confirm CosmoShield's terms |
| S80 | spmedia Crypto Scam and Phishing feed | MIT | <https://github.com/spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed/blob/main/LICENSE> | allowed-with-conditions | checker | In the same overturned group. The checker's note reads it as clean (MIT, the author named in the header, last push 2026-11-22, no input or non-commercial wording found), but the group's verdict was overturned and it was not checked as an item of its own. Scam and phishing, not mining. | held: a check of this source alone |
| S81 | MikhailKasimov/validin-phish-feed | MIT (label) | <https://www.validin.com/terms/> | not-allowed | checker | In the same overturned group. The repository reads as MIT (last push 2026-11-19), but every list is headed as Validin Threat Intelligence Platform output with Validin references, and Validin's terms read as limiting its output to the customer's own internal security use and barring distribution and derivative works; a repository's MIT label cannot grant what a contributor may not hold. | excluded unless Validin gives written permission (6.6) |
| S82 | arfshl/anti-gambling-domains | BSD-3-Clause | <https://github.com/arfshl/anti-gambling-domains/blob/main/LICENSE> | allowed-with-conditions | checker | In the overturned gambling group. Reads as BSD-3-Clause, which is not one of the five families (4.1 point 1); last push 2026-11-24; the README says "based on self exploration on internet" and that the list is already in HaGeZi's gambling filters. The checker's note reads it as clean, but the group verdict was overturned. | held: the owner admits BSD-3-Clause by name (open question 22) and a check of this source alone |
| S83 | Other gambling inputs of HaGeZi: bet-blocker, alexsannikov/adguardhome-filters, mtxadmin/ublock, arkynx/blocklists | MIT (bet-blocker, alexsannikov, mtxadmin); none (arkynx) | <https://github.com/bet-blocker/bet-blocker/blob/main/LICENSE> | unclear | checker | **Overturned** (the reader said merge for five): bet-blocker last pushed 2025-03-11 and states no provenance; alexsannikov's README says it is generated from StevenBlack's gambling extension (hostsVN and Sinfonietta, S68 and S07) plus undocumented additions, so it adds nothing traceable; mtxadmin is a uBlock list whose rules are "based on colleagues' findings" cited per rule, unread (rate limit stopped the check); `arkynx/blocklists` has no licence at all (<https://raw.githubusercontent.com/arkynx/blocklists/main/README.md>). | excluded: bet-blocker (unmaintained), alexsannikov (redundant), arkynx (no licence); held: mtxadmin until its `from` references are read |
| S84 | Fanboy lists (Social, Annoyance, Cookie Monster, Age Gate) | CC BY 3.0 (header only) | <https://secure.fanboy.co.nz/fanboy-social.txt> | unclear | reader | Each list header reads "License: http://creativecommons.org/licenses/by/3.0/"; no LICENSE file in a repository, and the EasyList licence page (<https://easylist.to/pages/licence.html>) says subscriptions other than four named ones may be under other conditions; whether rules were copied from EasyList is not stated. Adblock syntax. Read once, not second-checked. | held: the maintainer to confirm |
| S85 | DandelionSprout adfilt (Anti-Malware and others) | Dandelicence v1.4 (custom) | <https://github.com/DandelionSprout/adfilt/blob/master/LICENSE.md> | unclear | reader, with a checker's note | Commercial use reads as allowed ("with or without commercial purpose") on conditions: removal on request and share-alike for content taken from share-alike projects. A checker read its section 8 as forbidding sale of near-unmodified content as standalone paid products in limited quantity. Outside the five families, like S10. Also an input of S12 and S17. Read once, not second-checked. | held: the owner's ruling on custom licences (open question 2) and lawyer question 9 |
| S86 | matomo-org/referrer-spam-list | a README sentence only | <https://github.com/matomo-org/referrer-spam-list/blob/master/README.md> | unclear | checker | No LICENSE file; the README says "Public Domain (no copyright)" for community contributions. Referrer spam is of little use for DNS blocking. | excluded: not useful for DNS; the sentence is outside the five families |
| S87 | jamiemansfield/minecraft-hosts | CC0-1.0 | <https://github.com/jamiemansfield/minecraft-hosts/blob/master/LICENSE.txt> | allowed | reader | CC0 in three places; about 10 domains of Minecraft launcher telemetry; last push 2026-04-06 (about 232 days). | excluded: unmaintained and tiny |
| S88 | Other StevenBlack data inputs: FadeMind/hosts.extras, AdAway hosts.txt, mitchellkrogza/Badd-Boyz-Hosts | mixed | <https://raw.githubusercontent.com/FadeMind/hosts.extras/master/README.md> | not-allowed | reader | FadeMind: the README says the `add.*` files are mirrors under GPLv3+ (hostsfile.org says GPL), repository archived 2025-05-27. AdAway (<https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt>): the header reads CC BY 3.0, the repository's LICENSE.md and README say GPL, its history shows imports from unread lists, `hosts.txt` last changed 2023-04-29. Badd-Boyz-Hosts: MIT LICENSE.md, but the data header and README say "free to copy and distribute this file for non-commercial uses"; last push 2023-05-07. Read once, not second-checked. | excluded: GPL mirror and archived; conflicting licence and stale; non-commercial |
| S89 | anti-AD and Cats-Team/AdRules | MIT label (anti-AD); a permissive LICENSE for the tool only (AdRules) | <https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/LICENSE> | not-allowed | reader | The S26 to S31 pattern again. anti-AD's build script pulls EasyList and EasyPrivacy, AdGuard filter 224 (GPL-3.0), AWAvenue (GPL-3.0), cjxlist (LGPL-3.0 per the API), ACL4SSR (CC BY-SA 4.0), yhosts (no licence) and a URLhaus-derived feed. AdRules' README (<https://raw.githubusercontent.com/Cats-Team/AdRules/master/README.md>) says the data keeps its upstreams' licences (GPL-3.0, MIT, CC BY-SA 4.0) and its `Source.md` returned 404. Read once, not second-checked. | excluded: compilations with copyleft or unread upstreams |
| S90 | Other registry lists read and not usable: Big List of Hacked Malware Web Sites, MajkiIT/polish-ads-filter, and the GPL-3.0 or unlicensed lists of AdGuard's registry | mixed | <https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/LICENSE> | not-allowed | reader | The Big List reads as MIT but was last committed 2022-06-07; MajkiIT reads as CC BY-NC-SA 4.0; AWAvenue, Turkish-Ad-Hosts, EasyList Lithuania and uAssets read as GPL-3.0 with upstreams unread; four more repositories have no licence file. The registry's `filters.json` has no licence field at all (<https://adguardteam.github.io/HostlistsRegistry/assets/filters.json>): discovery only. Read once, not second-checked. | excluded: unmaintained, non-commercial, copyleft with upstreams unread, or no licence |
| S91 | Other cryptomining lists: keraf/NoCoin, anudeepND/blacklist `CoinMiner.txt`, MinerBlock, CoinEater, ilmoi/mining-pools-aggregator, Crypto-Census, CoinBlockerLists mirrors | mixed | <https://raw.githubusercontent.com/anudeepND/blacklist/master/README.md> | not-allowed | reader | keraf/NoCoin reads as MIT, archived, last push 2020-09-10; `CoinMiner.txt` reads as MIT-labelled, marked "Discontinued", last changed 2021-06-12, 5,939 domains of unstated provenance; MinerBlock and CoinEater read as MIT, stale, extension code; the pool aggregators have no licence; the CoinBlockerLists mirrors read as GPL-3.0 and are years old. Read once, not second-checked. | excluded: archived, discontinued, stale, unlicensed or copyleft |
| S92 | HaGeZi inputs with no stated terms: kushari.org `mal.txt`, the Phishing-Database `phishing` hub repository, the Turkish authority's page | none found | <https://raw.githubusercontent.com/hagezi/dns-blocklists/main/sources.md> | not-allowed | reader | The `mal.txt` header names only a maintainer; the hub repository has no LICENSE (the main Phishing.Database repository is MIT, S44); the authority's page is script-rendered and gave no text. Read once, not second-checked. | excluded: no licence found |

### 3.1 Overturned claims, and the rule that follows

Five sources the researchers rated usable were overturned by the checkers, all for the same reason: **a permissive label on an aggregated list hides upstreams with non-commercial or no terms.**

- **StevenBlack unified hosts (S26):** "MIT", but the base merges MVPS hosts (CC BY-NC-SA 4.0) and `someonewhocares.org` (non-commercial). Only the extensions' upstreams may survive, each taken from its original once its licence is read there (S08, held).
- **1Hosts (S29):** "MPL-2.0", but its credits list MVPS, `someonewhocares.org`, the `pgl.yoyo.org` list, OpenPhish and unlicensed lists.
- **GoodbyeAds (S30):** "MIT", but its own `Sources.md` names NC, ND, All Rights Reserved and unlicensed inputs that are "always merged and included".
- **The Block List Project (S31):** "Unlicense" (and "MIT" in the headers), but archived, and fed by lists that include the `pgl.yoyo.org` list and Phishing Army (CC BY-NC 4.0).
- **AdGuard DNS filter (S20):** said not to be a compilation; it is one, with regional inputs whose licences are unread.

The checkers also corrected details the other way: NoTrack is GPL v3, not unlicensed (S36), and the checkers read EasyList's dual licence as usable under its GPL option (S23). And the HaGeZi lists, rated allowed with conditions, turn out to take non-commercial data as inputs to the ad tiers (S16) and a subscription feed for NRD (S18). StevenBlack's extensions (S08) show the same risk one level down: their licence labels are StevenBlack's records of the upstreams, and one of them is not backed by its source.

**The rule (ADR-1087 point 3):** a source that is a compilation of other lists is admitted only after its own list of upstreams has been read and every upstream on it meets the admission rule for the kind of list it would join, its licence read at the upstream itself, not from the compiler's label. A compilation that does not publish its upstreams is not admitted. The rule applies to both kinds: a copyleft compilation whose upstreams are unread (S15, S16, S17, S20, S25) is `held`, not offered as a separate list. A source that says it is original work (S03, S07, S13) is admitted on that statement, recorded with its quote, and re-read at every re-check.

**The second reading overturned nine more favourable claims** (3.2), for the same reason or a close one; a checker's "why" is the one line each:

- **hufilter (S74):** its `security` section imports an unlicensed list, and nothing says the rest is original.
- **pedro-nsy (S75):** the piracy list takes names from GPL code (ResolveURL) and from a NextDNS list that is gone.
- **NetAPI compromised domains (S76):** the CC BY label covers a list that is about 44.5% CERT Polska's, under CERT's own terms.
- **TweetFeed (S77):** the "corroborated" lists derive from abuse.ch, USOM and IPsum, and the posts stay under X's terms.
- **NetAPI Top 1M (S72):** an unnamed "DNS query popularity" input has no stated terms.
- **DNSBunker CTI (S78):** CC0, but no inputs named, a rewritten history and a 72% overlap with a copyleft compilation.
- **The TIF-adjacent group (S79 to S81, S86):** one feed is Validin output redistributed under an MIT label, one syncs reports from a source whose terms returned 403, one has only a README sentence.
- **The gambling group (S82, S83):** one list is a copy of StevenBlack's extension, one cites unread sources per rule, one is BSD-3-Clause, outside the families.
- **HaGeZi's copyleft upstreams (S15 to S17):** the group verdict contradicted itself (custom licences cannot be "separate-copyleft"), missed an unlicensed gambling input, and left out the subscription feed and rankings used as signals.

### 3.2 The second reading (2026-11-24)

Ordered by the owner (open question 11, now closed) and done the same day: four readers (StevenBlack's extensions and base data; AdGuard's registry and DNS filter; HaGeZi's upstreams; cryptomining and popularity rankings) and fifteen checkers, one for each favourable reading. The rules applied: a checker's corrected verdict governs; a source is admitted for merging only if a checker confirmed it, and then only for the files and with the caveats the checker names; a favourable reading with no checker would be recorded as "read once, not second-checked: held" (none was left without one). The cautious and "unclear" readings were not second-checked and are marked "read once" in section 3.

**Where the second reading leaves the sources**

- **Admitted for merging (a checker confirmed):** S67 no-google (analytics, doubleclick and android files only), S69 reflect4 (`reflect4_domains.txt`), S70 my_filters_001 (`antidynamicdns.txt` only); S03 and S13 were re-confirmed. **Guard only:** S71 CrUX.
- **Held on a named question:** S68 hostsVN, S72 NetAPI Top 1M, S74 hufilter, S75 pedro-nsy, S76 NetAPI compromised domains, S77 TweetFeed, S78 DNSBunker CTI, S79 chainapsis, S80 spmedia, S82 arfshl, S83 mtxadmin, S84 Fanboy, S85 DandelionSprout, and S14 Majestic (no longer clear). S15 to S17 and S20 stay held with more of their upstreams read.
- **Separate copyleft, waiting on the maintainer and the lawyer:** unchanged (S21, S23); UT1 `adult` (S24) is now a separate list only after UT1 answers yes (decision of 2026-11-24).
- **Excluded:** S73, S81, S86 to S92, `tiuxo` (S08), and S83's bet-blocker, alexsannikov and arkynx.

**Two readers disagreed.** `bigdargon/hostsVN` was read in two groups: the StevenBlack reader read "unclear-ask-maintainer" (no originality statement, no inputs listed), the AdGuard reader read "merge". The checker confirmed MIT and that the build scripts read only the repository's own files, but found the same missing originality statement as S07 has. The more cautious position is recorded: S68 is held until the maintainer's one-line answer.

**The popularity rankings** (all read 2026-11-24):

| Ranking | Read as | Status |
|---|---|---|
| Chrome UX Report (S71) | CC BY 4.0, stated by Google (<https://developer.chrome.com/docs/crux/methodology>); a checker confirmed it; origin-level buckets (1k, 10k, 100k, 1M); BigQuery terms unread; Tranco's CC BY-SA label disagrees | confirmed, guard only |
| Majestic Million (S14) | the page reads CC BY 3.0 (<https://majestic.com/reports/majestic-million>); the site terms read as barring commercial use without a licence (<https://majestic.com/company/terms>); the first reading's checker cleared the page, the second reader left it unresolved | unresolved until Majestic answers |
| NetAPI Top 1M (S72) | CC BY 4.0 per NetAPI; derived from Majestic and CrUX plus an unnamed DNS signal; a checker overturned the merge claim | held |
| Tranco (S63) | no licence or terms found (<https://tranco-list.eu/>); inputs include CC BY-NC 4.0 data | not usable |
| Cisco Umbrella (S64) | no licence, terms or attribution text on the page or the download (<https://s3-us-west-1.amazonaws.com/umbrella-static/index.html>) | not usable until Cisco answers |
| Cloudflare Radar (S73) | CC BY-NC 4.0 (<https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/>) | excluded |

**What this means for the accepted guard (decision of 2026-11-24).** The guard has two ingredients: one ranking for the top-10,000 test, and for a name in it, two independent admitted list sources or a reviewer's approval (5.5). The second ingredient is about list sources, so the rule needs one ranking, not two, to run. One ranking is confirmed today, CrUX; it is coarse and at origin level, so the build maps origins to registrable domains and treats the 10,000 bucket as the top tier. **Fewer than two rankings are confirmed:** Majestic is unresolved, and NetAPI derives from Majestic and CrUX, so it would be independent of neither. No second ranking is assumed; if the owner wants two rankings to agree before a name is guarded, that cannot be done today (open question 20). For the list sources, a category with one admitted source can promote no top-10,000 name without a reviewer: cryptomining (S13 only) and scam (S03 only, until S12 or S10 is admitted) are in that position. Independence is recorded for sources that state their inputs (S03, S13); for S07, S67 and S68, which state none, it can only be not contradicted.

**Cryptomining (decision of 2026-11-24).** Only NoCoin (S13) can feed it today: about 313 domains of browser miners, no mining pools, low activity (its `hosts.txt` header is dated 2025-03-05). The other lists read are archived, discontinued, stale, unlicensed or copyleft (S50, S91); the larger candidates, HaGeZi TIF and UT1's crypto lists, are copyleft and held. No permissive source for mining pools was found, so pools need WrenDNS's own reviewed entries (4.6). With S13 as the only source, every top-10,000 name in the category needs a reviewer. The category is thin and is offered only when its reviewed entries make it worth a checkbox (ADR-994 point 4).

**Gaps (not reached, not guessed)**

- Unreachable or blocked: `unchecky.com` (connection failed); the `Clefspeare13/pornhosts` repository (blocked by GitHub 2021-10-11); CoinBlockerLists' repository and data (login redirect, bot challenge); CosmoShield's terms (HTTP 403); the English page of Cloudflare Radar's About; the Turkish authority's page (script-rendered); Stamus Labs' subscription page (not opened).
- Terms not opened: the MVPS and `someonewhocares.org` pages (StevenBlack's labels and the first reading only); KADhosts; AdAway's imported lists; Google Cloud and BigQuery terms for CrUX; Farsight (a Tranco input); Cisco's licence for the free list; X's terms, USOM and IPsum (TweetFeed); ResolveURL's other plugin files, AppGoblin, NextDNS services and WebStreamr (pedro-nsy); the report behind some hostsVN `threat` entries.
- Not read: AdGuard's filter policy page (what AdguardFilters inherits); Cats-Team's `Source.md` (404); anti-AD's other upstreams at their own repositories; the cjxlist licence text (LGPL-3.0 from the API only); HaGeZi's issue tracker and any maintainer statement on hosted use; mtxadmin's source files (API rate limit); per-entry provenance inside the permissive repositories; HaGeZi's regional and ad inputs beyond their labels.
- Not covered by the run: NRD from zone files under WrenDNS's own contract (named in the closed open question 11).
- Method: GitHub's unauthenticated rate limit was reached during the run, so some dates came from commit feeds; the Hungarian pages of hufilter were read through a fetch summary; the readings marked "read once" had no second reader.

## 4. Admission of a source

### 4.1 The rule

A source is admitted to a **merged, WrenDNS-owned list** only when all of these hold, each recorded with its evidence (section 6.1):

1. **Licence family.** Its licence is MIT, Apache-2.0, CC0-1.0, Unlicense, or CC BY (3.0 or 4.0), read from the source's own LICENSE file or licence statement, with the SPDX id recorded. For an upstream of a compilation, the licence is read at the upstream's own repository or site, not from the compiler's label for it. Anything else is copyleft, non-commercial or unclear, and goes to 4.1b or is excluded. Custom permissive terms (CERT Polska, S10) are outside owner decision 1 and stay `held`; this design proposes that the owner may admit such a licence by name (ADR-1087 point 13, open question 2).
2. **Commercial use.** Nothing in the licence, the source's terms of use or its README forbids commercial or hosted use. A non-commercial term anywhere excludes the source.
3. **Upstreams.** If it is a compilation, the rule in section 3.1: its upstream list is read and every upstream passes points 1 and 2. If it says it is original, that statement is recorded.
4. **Maintained.** A push within 90 days and not archived (the catalog's rule, ADR-995 point 3). A source with a low cadence may stay while it passes; one that fails is dropped at the next build (section 4.4).
5. **Fetchable as data.** An `https` URL on the maintainer's own host (or raw GitHub or jsDelivr for the same repository), with a fixed URL prefix (ADR-995 point 1), in a format the pipeline normalises (section 5.2).
6. **Two people.** Admission needs a second reader of the licence evidence (section 4.2).

**4.1b A separate copyleft list** (GPL-3.0, CC BY-SA, or a dual licence taken under its GPL option) meets points 2 to 6, point 3 included (a copyleft compilation's upstreams are read like a permissive one's), and, in addition, has the maintainer's written yes for hosted commercial use (owner decision 1) and a lawyer's answer to the questions in section 7.3 that apply to its licence. Until both exist it is not offered; a candidate that also fails one of points 2 to 6 is `held` until that is fixed.

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

### 4.5 Output licences under the owner's decision

Merged-permissive outputs carry their own licence: WrenDNS's choice for its own work (open question 13), plus the notices of every MIT and CC BY input (section 6); whether WrenDNS may licence a merged output at all is lawyer questions 1 and 10. A copyleft output keeps its source's licence unchanged. MPL-2.0 is not one of the five permissive families; no admitted source uses it today (1Hosts, S29, is excluded for its upstreams).

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
- The name is not in the **critical set** (section 5.5) and not under a protected parent (the protected-parent and shared-infrastructure denylist that `hosted.md` already gives the class-map validator). In the categories the **platform-root set** covers (5.5), the name is not one of its roots.
- Per source and per category, the size is within the caps of section 10.2.

### 5.4 De-duplicate

Two steps, at two places in the pipeline:

- **Exact names, here.** Within a category and tier, a name listed by several sources is one entry with all of them in its provenance (5.7). A name's provenance is only the sources that list that exact name.
- **Subtrees, last.** After the allowlist, the critical and platform-root sets, the popularity guard (5.5) and pruning (5.6) have run, a name covered by a shorter suffix that is still in the same list is dropped (subtree match makes it redundant, FLT-002). Its sources are **not** added to the parent's provenance: the parent keeps only the sources that listed the parent itself, and the dropped child is recorded in the build report as "covered by" the parent, with its own sources. So Explain never says a source "listed" a name it did not list, and a child entry cannot help its parent pass the guard.

Across categories, a name may sit in several categories; that is expected (a scam site is also a fake store) and not de-duplicated.

### 5.5 Allowlists and the popularity guard

- **Allowlist sources.** WrenDNS's own allowlist (`wrendns-allow`, reviewed entries with a reason each, licence chosen by the owner) applied after every source's entries are merged, so it wins over all of them, and **persistent**: a domain on it stays out even when an upstream re-adds it (the research's practice from the Block List Project and 1Hosts). Third-party allowlists are admitted under the same rule as sources: the only one the research checked, `anudeepND/whitelist` (S56), is archived, so it is used once: a one-time reviewed import into `wrendns-allow` (owner decision, 2026-11-24), each name reviewed first, never re-fetched. Copyleft lists are never used as an allowlist for a permissive output.
- **The critical set.** Infrastructure names that are never blocked by an assembled list, in any category, whatever a source says: operating-system and app-store update and connectivity-check names, captive-portal checks, certificate revocation and time services, and the service's own names. Kept by hand, reviewed every 90 days. It holds no platform's main names, so it never stops a category whose purpose is to block a platform.
- **The platform-root set, scoped by category.** The major platform roots the research names (Apple, Microsoft, Google and Meta; the research gives this as oisd's practice for a general ad and tracker list) are refused as entries only in the ad, tracker and threat categories (`ads`, `popup-ads`, `smart-tv`, `app-trackers`, `native-trackers`, `malware`, `phishing`, `scam`, `fake-stores`, cryptojacking, stalkerware and typosquatting), where blocking one would be a mistake. The refusal is for the root names themselves (for example `google.com`, `facebook.com`); their subdomains, such as an ad or tracking host, stay blockable. It does not apply in Social, AI or any other category whose purpose is to block a platform's own service, where those roots are core entries. The scope per category is kept with the set, by hand, reviewed every 90 days.
- **The popularity guard (owner decision, 2026-11-24).** A ranking of the most popular domains, used inside the build only and never republished. The second reading (3.2) confirms one ranking today, the **Chrome UX Report** (S71, CC BY 4.0 by Google, coarse buckets with a top-10,000 tier); the Majestic Million (S14) is unresolved, NetAPI Top 1M (S72) is held, and Tranco (S63), Cisco Umbrella (S64) and Cloudflare Radar (S73) are unusable until answered. Rule (accepted as proposed: top 10,000, two independent sources): a name among the top 10,000 enters a category only if **two independent admitted sources** list that exact name in that category, or a reviewer has approved it in WrenDNS's reviewed entries for that category. The guard runs on exact names, before the subtree step of 5.4, so a source that lists only a child name never counts towards its parent. So a large adult site is still in Adult (several sources list it), and a news site that one source wrongly put in Adult is held for review instead of blocked for every subscriber. Two sources are independent when neither is a known input of the other (recorded in the registry).
- **No copyleft signal.** The guard and the "two sources" count use admitted permissive sources and WrenDNS's own reviewed entries only. A HaGeZi or UT1 list never confirms, ranks or removes an entry in a WrenDNS-owned list, so a merged output never depends on copyleft data (lawyer question 3 asks whether that separation holds).

### 5.6 Dead-domain pruning

From the research's practice (oisd prunes every 5 days; the Block List Project scanned weekly; AdGuard's linter confirms with DNS): weekly, a name that gives **NXDOMAIN** for its registrable domain on two runs a week apart is removed and logged. Timeouts and SERVFAIL never count (they are the resolver's problem, not the name's). Queries go through the service's own recursive resolver (DNS-012), not a public one, so the list is not handed to a third party. Threat categories (malware, phishing, scam, stalkerware, cryptojacking) are not pruned for 30 days after a name is first added, because threat domains are often parked and revived. A pruned name that a source still lists is not re-added until it resolves again. Removals are part of the diff review.

### 5.7 Per-domain provenance

Every entry records **which sources listed that exact name** (5.4: a covered child's sources stay in the build report, not in its parent's provenance), so Explain can say why a name is blocked (section 9) and a removal request can be traced to its source.

- **In the build:** each source has a small number (at most 64 per category); an entry carries a set of them. Distinct sets are few (most names come from one or two sources), so the build interns each set once and gives the entry a set index.
- **Stored outside the snapshot (Decision).** The node's snapshot stays as it is: at most 12 bytes per domain (`spec/05` §2, ADR-018), with keys mapped to list-set indexes. Provenance is a **separate file per output**, an FST map from the reversed-label key to the source-set index (the same structure the snapshot already uses for list sets), plus a small table of the sets. Its size is estimated at about the snapshot's 12 bytes per domain (a key plus a value of one or two bytes) and is **measured in T36.30 before it is fixed**; it is never loaded into the query path: Explain opens it (mmapped) when it explains a block, and a node that has no provenance file still blocks the same names.
- **Rejected:** a 12-byte provenance record inside the snapshot per domain (it would double the snapshot memory on a small node, where the compile peak already decides what fits, `content-categories.md` section 2.4); provenance only on the service with no copy on the node (Explain would need the network to answer, against rule 5: DNS and its explanations never depend on anything else).
- **In the hosted resolver:** the same file beside the resolver's snapshot.

### 5.8 Build outputs

For each build `YYYY-MM-DD.N`:

- **One file per category and tier** of WrenDNS-owned lists, domains-only format, sorted, LF line ends, a header comment naming the category, tier, build version, licence, and the URL of its attribution page. A tier is `exclusive` or `additive` as the catalog defines them (ADR-995 point 1).
- **One file per copyleft source, kept apart** (owner decision 1): the source normalised to domains (5.2) and validated (5.3), with nothing added and nothing removed except names the critical set and protected parents refuse (and, in the categories it covers, the platform-root set), which the file's header lists as removed. Its header names the source, its licence, its URL and the retrieved hash; the licence text travels beside it (HaGeZi's README asks for that with any redistribution, S15). It is never merged with another file, not even another copyleft one; a category that uses it lists it as its own source line.
- **The provenance file** per WrenDNS-owned output (5.7).
- **`manifest.json`**: the build version and sequence number, the pipeline's own version and commit, every input (5.1's record), every output (name, entries, bytes, SHA-256, licence), the registry commit, the allowlist, critical-set and platform-root-set commits, the guard ranking's hash, and the counts of the build report.
- **`ATTRIBUTION` and `NOTICE` files** (section 6).
- **The build report:** per source and category, added, removed, held and dropped counts with reasons; the large-diff flags (section 10.2).

### 5.9 Versioning and signing

- **Versions** are `YYYY-MM-DD.N` with a monotonic **sequence number**; a consumer refuses an older sequence than it holds (rollback protection, as `hosted.md`'s content envelopes do).
- **Signing reuses what the project has (Decision).** For hosted delivery and for a subscriber's node over the tunnel, the platform channel's **content key** with scope `lists` signs the manifest (ADR-1062; the scope already exists and `hosted.md` says the node never accepts platform-signed lists as allow sources). For downloadable files, the manifest's `SHA256SUMS` is signed with **minisign**, the scheme the releases use (ADR-1034), and the node verifies it with the same code that verifies `SHA256SUMS` for self-update. **Which key signs downloadable lists (owner decision, 2026-11-24):** a separate minisign lists key, named in the platform key manifest, not the release key, so a leak of one cannot sign the other.
- The content key signs only from the pipeline's own identity, the only principal allowed to call its sign operation, after the review step of section 10.2 (the same rule `hosted.md` sets for the class map).

### 5.10 Reproducibility

A build is a pure function of: the pinned inputs (by hash), the registry, allowlist, critical-set and platform-root-set commits, the guard ranking's hash, the Public Suffix List's hash and the pipeline's version. Sorting, normalisation and set interning are deterministic, so **two builds from the same manifest give byte-identical outputs**. A `verify` mode rebuilds from a manifest and the stored inputs and compares hashes; it runs on every build and on a schedule against an older build. The dead-domain pruning results are themselves an input recorded in the manifest (a list of pruned names with their dates), so a rebuild does not need the same DNS answers.

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
- **Some copyleft lists are heavy or over the default budget on their own:** UT1 `adult` has 4,600,371 entries (about 53 MiB at 12 bytes, over the default budget by itself), HaGeZi TIF full and NRD as before. Under the downloadable model these are offered only as `heavy, over the default budget` with the existing confirmation; UT1 `adult` is offered only as a separate attributed list under its own licence, and only after UT1's maintainers answer yes to hosted commercial use (owner decision, 2026-11-24); the WrenDNS Adult category is built from permissive sources.
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
| `kind`, `status` | `merged-permissive`, `separate-copyleft`, `guard`; `admitted`, `held` (with the question it waits on), or `excluded` (with the reason) |
| `permission` | the maintainer's written answer, its date and where it is kept, when one was asked |
| `checked`, `checked_by`, `second_reader`, `next_check` | dates and people (people by role in public outputs) |
| `retrieved`, `sha256` | per build, in the manifest |

The research's own suggestion (per-source SPDX id, licence URL and quote, attribution text, a commercial flag, the retrieved date and the hash) is this record; T145's manifest shape (S57) is the model for the file.

### 6.2 The ATTRIBUTION page per category

Generated by every build, one page per category and version, from the records:

- the category, its tier, the build version and date;
- **every source that contributed at least one entry**, by project, with its licence, a licence link, its attribution text where the licence asks for one, the number of entries it contributed and whether WrenDNS modified it ("normalised to domains, de-duplicated, filtered by the WrenDNS allowlist", meant as the indication of changes the research reads CC BY and CC BY-SA as asking for; whether its form suffices is lawyer question 11);
- the separate copyleft lists the category can use, each with its licence and its own attribution;
- the disclaimer the sources ask for (no warranty; HaGeZi's "as-is" wording; CERT Polska's no-endorsement condition);
- the address for objections (6.5).

The page is published on the project site (a site page, DOC-006) and shown in the UI (section 9). The models the research names are StevenBlack's upstream table and Phishing Army's sources page.

### 6.3 NOTICE handling

- A WrenDNS-owned output's `NOTICE` reproduces every MIT and Apache-2.0 notice and every CC BY attribution of its contributing sources, generated from the records, and travels with every copy (downloadable files) and is linked from the attribution page (hosted).
- A copyleft file carries its own licence text beside it and nothing else is added to it.
- `docs/third-party-notices.md` gains a section "Assembled category lists" that explains the two kinds and links the attribution pages; its existing section on catalog lists stays true for the catalog.

### 6.4 The separate-file rule for share-alike and GPL sources

A GPL-3.0 or CC BY-SA source is **never merged** with any other source, permissive or copyleft. It is one output file under its own licence, normalised and validated only (5.8). It is not used as a signal for a permissive output (5.5). The node and the hosted resolver may apply several files to one group. The working assumption is that this keeps them a collection side by side, not a single work; that assumption is lawyer question 3, and nothing here is built on it before the answer. A subscriber chooses copyleft lists separately in the UI (section 9), and each shows its own licence.

### 6.5 Objections and opt-out

- A role address at wrendns.com for list maintainers and anyone named by a list (proposed `lists@wrendns.com`; the owner sets it), published on every attribution page and the site.
- **A maintainer's opt-out** takes their source out of the next build and keeps it out; no argument is needed. The attribution page records the date.
- **An objection to an entry** (a business that says it is wrongly listed) is a false-positive report (section 8) with its own queue.
- Answers within a stated time (open question 12 sets it); every objection and its outcome is logged.

### 6.6 Maintainers to write to

By project. The owner sends; each letter asks a short, answerable question and says what WrenDNS will do with the data, under which delivery model, and how it will credit them.

| Project | Ask |
|---|---|
| HaGeZi | (1) Yes or no to hosted commercial use of the content, networking and TIF lists as separate GPL-3.0 files (S15, S17), in a hosted resolver and, if chosen, as downloadable files, and of the catalog's HaGeZi lists in the cloud resolver as `hosted.md` already plans (section 1.3). (2) For each of those lists, which of the inputs in `sources.md` it takes, and under which licence or terms each is used (S15, S17: they stay held until the upstreams are read); whether the Multi tiers (S16) carry anything from the `pgl.yoyo.org` list, 1Hosts, oisd or other non-commercial inputs, or only signals. (3) The terms of the subscription feed behind NRD and DGA (S18). (4) The attribution text wanted. |
| AdGuard | (1) Hosted commercial use of the DNS filter (S20) and of `services/` in HostlistsRegistry (S21) as separate GPL-3.0 files. (2) The licences of the regional inputs of the DNS filter (S20). (3) What use of the AdGuard name is acceptable in the attribution. |
| EasyList | Confirmation that hostnames extracted from EasyList and EasyPrivacy may be used under the GPL-3.0-or-later option in a hosted service and in separate files, and the attribution form ("The EasyList authors"). |
| UT1 (Université Toulouse Capitole) | (1) The licence on the university's own site (it was unreachable). (2) Hosted commercial use as separate CC BY-SA 4.0 files (the gate for offering `adult` at all, decided 2026-11-24). (3) Whether to fetch from the mirror or the university's tarball. (4) The attribution text. (5) Whether the university claims a database right beyond the licence (lawyer question 2). |
| Bon-Appetit | The rights in the compiled output given the unlicensed inputs in `block-sources.csv` (S25), and hosted commercial use under CC BY-SA 4.0 with the requested credit line. |
| AssoEchap | Written confirmation of CC BY 4.0 for a paid service, and the attribution text (S09). |
| CERT Polska | That merging the Warning List into a WrenDNS-owned list, and distributing it if chosen, is within "any purpose", and how they wish to be named without implying endorsement (S10). |
| Scam Blocklist (`durablenapkin/scamblocklist`) | Whether any entries were copied from the Dandelicence list (S12). |
| ShadowWhisperer | Confirmation that the lists are original work as the README says, and whether a credit is wanted (S03; none is required). |
| Majestic | Does the CC BY 3.0 grant on the Million page stand for internal use in a paid service, given the site terms (S14)? |
| Google (CrUX) | Does CC BY 4.0 on the CrUX datasets cover the BigQuery export and its coarse `rank` field (S71)? |
| NetAPI (Top 1M) | Where does the "DNS query popularity" signal come from, and under what terms (S72)? |
| NetAPI (compromised domains) | Where does the sinkhole-nameserver list come from, and are the CERT Polska rows passed through under CERT Polska's terms and not CC BY (S76)? |
| hufilter | Which sections of the built list are your own work, given that `security` imports an unlicensed list (S74)? |
| pedro-nsy | Which entries of each list came from which source (ResolveURL, the NextDNS list, AppGoblin, others) (S75)? |
| TweetFeed | Do `domains.txt` and the CSV feeds hold nothing derived from abuse.ch, USOM or IPsum (S77)? |
| DNSBunker (CTI) | Where do the domains come from (certificate logs, third-party feeds, your own lists), and do any carry terms (S78)? |
| Chainapsis | Under what terms does CosmoShield provide the reports that sync into the list (S79)? |
| Validin | May the Validin-derived feed redistributed in `validin-phish-feed` be used in a paid service (S81)? Only if the owner wants it. |
| bigdargon (hostsVN), Sinfonietta, nickspaargaren (no-google) | Is the list your own work, or which lists are its inputs (S68, S07, S67)? |
| mtxadmin | Which source lists do the `from` references name, and under what licences (S83)? |
| Fanboy | Do the lists carry CC BY 3.0 throughout, with no rules copied from EasyList or other share-alike lists (S84)? |
| Phishing.Database, PhishTank, Frogeye, Tranco, Cisco Umbrella | Only if the owner wants these sources: their provenance (S44), the Data and redistribution terms and the CC BY-SA 2.5 notice (S43), the data licence (S32), the ranking's licence (S63, S64). |

## 7. Delivery

### 7.1 The two models

| | **A. Hosted only** | **B. Hosted and downloadable** |
|---|---|---|
| What happens | The assembled lists are applied inside WrenDNS Cloud's resolver (T36.12), which answers a subscriber's roaming devices **only while their home is unreachable** (`hosted.md`, ADR-1064); while home is reachable the home node answers roaming queries too, with its own lists. Nothing is handed to anyone. | As A, plus signed files published for nodes to download: subscribers' own nodes (over the platform channel or wrendns.com) and, if the owner chooses, any self-hosted node. |
| The subscriber's home node | Keeps the catalog's sources downloaded from their maintainers (ADR-995), and answers at home and, while reachable, away. **Answers can differ while home is down** for the same category id; the UI says which source set answered. Sending the assembled list to the subscriber's node over the tunnel is treated as model B until lawyer question 6 is answered. | Uses the same assembled list at home and away, so a category means the same thing everywhere. |
| The cloud resolver's lists today | `hosted.md` and ADR-1064 point 4 already have the cloud resolver compile the tenant's own public catalog sources with the node's compiler and use the result only when its hash matches the primary's (else the blob from home), so that it answers exactly as home would. Model A breaks that equality for every category whose assembled list replaces the catalog's sources. How the two coexist is open (open question 19): either the assembled list replaces the hash-matched compile for the categories the tenant chose "Assembled by WrenDNS" for, and ADR-1064 point 4 and `hosted.md` are amended to say so, or the cloud resolver keeps ADR-1064 point 4 unchanged and applies assembled lists only for categories the home node has no source for. Either way it is an amendment to `hosted.md` and ADR-1064, made when T36.28 records the delivery model, not by this design. | The home node holds the assembled list, so its compiled hash is what the cloud resolver matches (ADR-1064 point 4 unchanged). |
| Legal acts | Copies made and kept by WrenDNS for its own service; per-query answers to subscribers; a public attribution page. | All of A, plus distribution of copies: permissive outputs with their notices; copyleft files under their own licence with the licence text, and possibly, for GPL-3.0, a duty to offer the "Corresponding Source" of the data as distributed, whatever that means for a domain list (lawyer question 6). |
| Main legal questions | 3, 4, 5, 7, 8, 11, 12, 13, 14, 15 | all of them, especially 3, 6, 7, 11 |
| Technical needs | the pipeline, provenance and attribution; delivery to the cloud resolver's snapshot and the amendment of ADR-1064 point 4 (open question 19); provenance for the resolver's Explain; the home-versus-away line; reports in the portal | all of A, plus public hosting of signed files, the node's "assembled by WrenDNS" catalog source with signature checks (FLT-905), and a published manifest for `verify` |
| Who benefits | roaming subscribers while their home is down | subscribers at home and away; self-hosters if offered |
| Risk the research names | "lower risk, not zero" | the research expects share-alike and GPL obligations to apply to every copy handed over (lawyer questions 3 and 6) |

### 7.2 Built either way

The source registry and admission (section 4); the pipeline with provenance, outputs, manifest and `verify` (section 5); signing with the content key (5.9); the attribution pages and NOTICE (section 6); the objection address; the false-positive reports (section 8); the review step and caps (section 10); the portal's category picker showing "assembled by WrenDNS" and separate copyleft lists (section 9); on the node, only the home-versus-away line for roaming queries the cloud resolver answered and a link to the attribution page (T36.32 part 1). Model B adds the node's catalog source kind with signature checks, the 72-hour hold, the provenance file on the node and the node's copyleft source lines (T36.32 part 2), public hosting and the minisign key (T36.34).

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
15. **The hosted compile of catalog lists that `hosted.md` already plans.** The cloud resolver of ADR-1064 point 4 fetches and compiles a paying tenant's public catalog sources itself (HaGeZi under GPL-3.0, Bon-Appetit or UT1 under CC BY-SA 4.0, when the tenant selected them), keeps compiled blobs fetched from home, and answers from them while home is unreachable. Does that make MySummitKeep a licensee with duties under those licences (questions 4 and 5 for this case), does any source's terms forbid it, and does ADR-995's position (the user's node downloads, WrenDNS never redistributes) still hold for the tenant's home node once the service does this?

**This document is not legal advice, and none of these questions is answered here.** Where the document states how a licence applies, it states a working assumption tied to one of these questions, not a conclusion.

## 8. False positives and reports

- **Allowlist sources** are in 5.5: WrenDNS's own reviewed allowlist (licence chosen by the owner, open question 13), the critical set and the platform-root set in its categories; no third-party allowlist is admitted today (`anudeepND/whitelist`, S56, is archived; a one-time reviewed import into the WrenDNS allowlist is decided, 2026-11-24). Allowlists are applied after every source's entries are merged, so they win over all of them, and persist against upstream re-adds.
- **How a subscriber reports one.** From Explain or the query log on the node, and from the portal: "Report a wrong block" on a blocked name, which sends the name, the category, the build version, the provenance (which sources listed it), the subscriber's note and, only with the subscriber's consent, nothing else (no device, no address: the privacy levels of ADR-102 apply). A subscriber can also report a missing block ("this should be in Adult"). Reports go to the service's queue; the subscriber sees each report's state (received, accepted, refused with the reason, fixed in build N).
- **Triage.** A reviewer checks the name against the category's description. An accepted wrong block goes into the WrenDNS allowlist for that category (or all categories), with the report as its reason, and leaves at the next build; an urgent one (a critical or widely used name) triggers an out-of-cycle build. A refused report says why.
- **Back upstream.** Each source's report channel is in the registry (the research lists them: GitHub issues with labels, web forms, a "Remove Request" template, e-mail). For an accepted wrong block, the reviewer files a report with every source that listed the name, citing the evidence, under the project's name, never the subscriber's (open question 12). The WrenDNS allowlist entry stays until the source has removed the name for two builds. Missing blocks found by subscribers go to the permissive sources as suggestions, never to copyleft sources as WrenDNS data.
- **Self-hosters** (model B) report the same way from the node; the node only sends what the subscriber confirms.
- **No SLA** is promised at first (the research found none anywhere); the portal states the expected time once the owner sets it (open question 12).

## 9. The catalog and the UI

Under model A the assembled lists live in the cloud resolver and the portal's category picker (T36.31); the node only shows which source set answered a roaming query while home was down, and links to the attribution page. Under model B they also join the node's catalog (ADR-995) as sources of a new kind, so the Categories view (`content-categories.md` section 5), the profile editor and Explain stay one place. Every surface this design adds needs its UI control or view, help topic and Playwright test in the same task (the standing rule). "Part 2" of T36.32 is built only if T36.28 chooses model B:

| Surface | Where | Control or view | Task |
|---|---|---|---|
| A category's "Assembled by WrenDNS" source | the portal's category picker (model A); the node's Categories view source line and info popover and the Lists page owned chip (model B) | the source row names "Assembled by WrenDNS", the build version, the date, the entry count, the licence, and links to the attribution page; on the node, a "Signature verified" or "Signature failed" state | T36.31 (portal), T36.32 part 2 (node, FLT-905) |
| Separate copyleft lists | the portal's category picker; the node's Categories view (model B), per category | each as its own source line with its licence and attribution, a checkbox to use it in this profile, off by default, and a "held" state with the reason when it is not yet offered | T36.31 (portal), T36.32 part 2 (node) |
| Choice between the assembled list and the maintainers' own lists (model B, self-hosted) | Categories view, per category; Settings default | a segmented control "Assembled by WrenDNS / From each maintainer" | T36.34 |
| The attribution page | the site; the portal; the node's Categories view "Sources and licences" drawer | the generated page for the category's current build; on the node a link to the site page (model A) or the page read offline from the build's files (model B) | T36.31 (site and portal), T36.32 part 1 (node link), part 2 (offline copy) |
| Provenance in "why was this blocked" | Explain (FLT-013) in the portal; on the node, Explain, the query log's detail panel and the device policy panel (ADR-996) (model B) | "Blocked by category Adult (Assembled by WrenDNS, build 2027-01-15.1); listed by ShadowWhisperer Adult and Sinfonietta" with links to those sources' attribution entries | T36.31 (portal), T36.32 part 2 (node) |
| Home versus away (model A) | Explain and the query log on the node for roaming queries the cloud resolver answered while home was down (their events are shipped home, CLU-007); Explain in the portal; the device policy panel | a line saying which source set answered: the catalog's maintainers' lists at home, the assembled list in the cloud resolver, with the category and build | T36.31, T36.32 part 1 |
| Report a wrong block, report a missing block | Explain, the query log's detail panel, the portal | a button and a short form, then a "My reports" view with each report's state | T36.33 |
| A held update | the service's review queue; on the node, the Lists page (owned list) and health panel (model B) | "Update held for review: 3,412 names added (cap 1,000)"; admin release or refuse, as the class-map hold in `hosted.md` | T36.31, T36.32 part 2 |
| Health reasons | health panel and `GET /api/v1/health` (model B) | `curated_signature_invalid` (severe; the last good list stays), `curated_stale` (degraded), `curated_held` (info) | T36.32 part 2 |
| The objection address and opt-out | the site's attribution pages and a "For list maintainers" page | a public page, not a node control | T36.31 |
| The review queue, the registry and admission records | the service's admin console (service repository) | the review step of 10.2 and the admission records of 4.2 | T36.29, T36.30 |

API and MCP: `GET /categories` gains, per source, `kind` (`maintainer`, `assembled`, `copyleft-separate`), `build`, `signature` and `attributionUrl`; Explain's block reason gains `provenance: [sourceId]`; reports are `POST /api/v1/reports` (operator) with a read for their state. No write tool for agents: a report is a person's statement (`spec/13` §3.2 is unchanged).

## 10. Security and abuse

### 10.1 A poisoned upstream

The threat: a source (compromised, sold, or hostile) adds a major domain (a bank, a search engine, an OS update host), and every subscriber loses it at the next build. Or a source drops thousands of real threats at once.

- The **critical set** and protected parents refuse such a name outright in every category, and the **platform-root set** in the ad, tracker and threat categories (5.3, 5.5); the refusal is logged per source and a source that hits either set is flagged for re-reading (4.3).
- The **popularity guard** holds any top-10,000 name that only one source lists by its exact name (5.5); a source that lists only a child name does not count towards the parent (5.4).
- **Provenance** tells a reviewer at once which source added a name, so one bad source can be dropped without touching the others.

### 10.2 Caps on growth, and review of large diffs

Numbers accepted by the owner on 2026-11-24:

- **Per source:** an update that adds more than 10 % of the source's previous size and more than 1,000 names, or removes more than 20 %, is **held**: the build uses the source's previous snapshot and the diff goes to review.
- **Per output:** a build that adds more than 1,000 names to a category, the same number `hosted.md` uses to hold a class-map version for 72 hours, needs a reviewer's approval before it is signed. Removals over 20 % also need it.
- **What the reviewer sees:** the diff by source, the popularity ranks of added names, the names that hit the guard, and a sample. Approval is recorded in the manifest (who, when).
- **On the node (model B):** `hosted.md` holds a platform-signed version that adds more than 1,000 patterns for 72 hours, with a notice, which an admin may release or refuse sooner. ADR-1087 point 9 applies that hold to signed `lists` content explicitly. A held list keeps the last good one; nothing is ever emptied (FLT-004).

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
| **T36.29** Source registry and admission | 1 | Every source in section 3 has a record (6.1) with the status section 3 gives it; admission needs a second reader; `scripts/check-catalog.py` (or its successor) checks the registry weekly and opens an issue on a licence-file hash change; a compilation without a read upstream list cannot be admitted, as either kind (a test); a `held` record cannot reach a build until its question is recorded as answered (a test). |
| **T36.30** The build pipeline | 2 | Fetch, normalise, validate, de-duplicate, allowlists, critical and platform-root sets, guard, pruning, provenance and outputs as section 5; two builds from one manifest are byte-identical; a copyleft source never reaches a WrenDNS-owned output and never changes one (a test that removes every copyleft input and compares); a source that lists only a child name adds nothing to its parent's provenance or guard count (a test); the provenance file's bytes per domain measured and recorded. |
| **T36.31** Signing, review, attribution and hosted delivery (model A) | 3 | The content key signs only after review; growth caps hold as 10.2; attribution pages and NOTICE generated per build and published on the site; the cloud resolver applies the assembled lists while home is unreachable, as `hosted.md` and ADR-1064 are amended for open question 19; Explain in the portal shows provenance and which source set answered. |
| **T36.32** The node's side (FLT-905): part 1 always, part 2 only under model B | 4 | Part 1: the home-versus-away line for roaming queries the cloud resolver answered and the link to the attribution page, with help topics and Playwright tests. Part 2 (only if T36.28 chooses model B): the catalog source kind with signature checks and the 72-hour hold; Explain names the contributing sources; the node's copyleft source lines and the offline attribution drawer. Both: no change to the query path (`make bench-smoke`). |
| **T36.33** False-positive reports and upstream flow | 5 | Report a wrong or missing block from the node and the portal; the reviewer's queue; an accepted report reaches the allowlist and the next build, and a report is filed with every source that listed the name. |
| **T36.34** Downloadable files for self-hosted nodes (model B; only if chosen) | 6 | Signed files on wrendns.com with their NOTICE and licence texts; minisign verification on the node; the per-category choice between assembled and maintainers' lists; a public `verify` job rebuilds from the published manifest. |

### 11.2 Open questions

| No. | Question | Who answers |
|---|---|---|
| 1 | Delivery: hosted only (A), or also downloadable (B)? | the owner, after the lawyer (T36.28) |
| 2 | Owner decision 1 names five licence families. Does the owner accept the proposal in ADR-1087 point 13, that a custom licence may be admitted for merging by name, and if so, is CERT Polska's data usage policy admitted (S10, held until then; it decides whether Phishing is buildable)? | the owner, after lawyer question 9 |
| 3 | **Decided 2026-11-24: accepted as proposed.** The growth caps of 10.2 (10 % and 1,000 names per source, 1,000 names per output, 20 % removals). | decided |
| 4 | **Decided 2026-11-24: accepted as proposed.** The popularity guard: top 10,000, two independent sources. What the second reading found about the rankings is open question 20. | decided |
| 5 | **Decided 2026-11-24:** a cryptomining-only category (browser miners and mining pools); no category for exchanges, wallets or crypto news. | decided |
| 6 | WrenDNS's own reviewed entries for thin and empty categories (4.6): which categories, and who curates? Replace the authored AI and Dating service bundles with assembled lists, or keep both? How does an assembled AI category sit beside Shadow AI's hosted-only catalog (ADR-1055)? | the owner |
| 7 | **Decided 2026-11-24:** a separate minisign lists key, named in the platform key manifest (5.9). | decided |
| 8 | Where the pipeline's code and the registry live: this repository (AGPL) or the service's repository? | the owner, with question 1 |
| 9 | How long input copies are kept (5.1). | the owner, after lawyer question 13 |
| 10 | **Decided 2026-11-24:** UT1 `adult` only as a separate attributed list under its own licence, and only after UT1's maintainers answer yes to hosted commercial use; the WrenDNS Adult category is built from permissive sources. | decided |
| 11 | **Done 2026-11-24 (3.2); closed.** Not covered by that run: NRD from zone files under WrenDNS's own contract. Sources the research flagged but did not cover: the upstreams of StevenBlack's extensions read at their own repositories (`bigdargon/hostsVN` and `tiuxo/hosts`, S08, held until then; the only research basis today is StevenBlack's `update.json` labels), NetAPI Top 1M (CC BY 4.0 per HaGeZi's `sources.md`, not opened), anti-AD, AdAway, StevenBlack's own data and FadeMind, the upstreams of HaGeZi's content, networking and TIF lists (S15, S17, held) and of the AdGuard DNS filter (S20, held), and NRD from zone files under WrenDNS's own contract. Research them? (`marktron/fakenews` is not on this list: its feed is paused.) | done |
| 12 | The objection address, the answer time for objections and reports, and whether reports upstream go under the project's name. | the owner |
| 13 | The licence of WrenDNS's own outputs, reviewed entries and allowlist (for example CC0 or CC BY 4.0). | the owner, after lawyer questions 3 and 10 |
| 14 | The requirement rows: FLT-905 (node side) and CLD-918 (service side) are reserved here; their rows are added to `spec/01` when T36.29 starts, as the hosted rows are (the CLD section's note). | the owner, at the start of the build |
| 15 | **Decided 2026-11-24: yes.** A one-time reviewed import of `anudeepND/whitelist` (MIT, archived) into the WrenDNS allowlist (5.5). | decided |
| 16 | Which tiers of the service get assembled lists and which copyleft lists (`hosted.md`, "Tiers")? Do self-hosters who do not subscribe get model B files? | the owner |
| 17 | HaGeZi, AdGuard, EasyList, UT1, Bon-Appetit, AssoEchap, CERT Polska and Scam Blocklist: the answers asked in 6.6. | each maintainer |
| 18 | The lawyer's answers to section 7.3, questions 1 to 15. | a lawyer |
| 19 | **An amendment to `hosted.md` and ADR-1064 (not made here).** Under model A, how do the assembled lists sit beside ADR-1064 point 4, under which the cloud resolver compiles the tenant's own catalog sources and uses the result only when its hash matches the primary's? Either they replace that compile for the categories the tenant chose "Assembled by WrenDNS" for (home and away then differ while home is down, and point 4 is amended to allow it), or point 4 stays and assembled lists apply only to categories the home node has no source for (section 7.1). Separately, the licence side of the compile `hosted.md` already plans for copyleft catalog lists (section 1.3, lawyer question 15) is recorded in `hosted.md` once answered. | the owner, with question 1 and after lawyer question 15 |
| 20 | The popularity guard's ranking (the decision of row 4 stands). Only one ranking is confirmed, CrUX (S71); Majestic (S14) waits on Majestic's answer and NetAPI (S72) on NetAPI's. Run the guard on CrUX alone, or wait for a second confirmed ranking before the guard is built? | the owner, after Majestic's and NetAPI's answers |
| 21 | The maintainers the second reading adds to 6.6 (Majestic, Google, NetAPI, hufilter, pedro-nsy, TweetFeed, DNSBunker, Chainapsis, Validin, and the maintainers of hostsVN, Sinfonietta, no-google, mtxadmin and Fanboy): the answers asked. | each maintainer |
| 22 | BSD-3-Clause (arfshl, S82) and the Dandelicence (S85) are outside the five families, like CERT Polska's terms (row 2). Admit either by name? | the owner, after lawyer question 9 |
