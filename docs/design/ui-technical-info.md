# Showing technical information clearly: the map, its panels and device details

Owner request 2026-11-19: "Can we clean up the way these sorts of things are displayed? Make suggestions as to how we make this sort of technical information cleaner." This is the reviewed proposal (a read-only audit of the code on 2026-11-19), with the owner's decisions. Tasks: spec/10 M35.

## Owner decisions (2026-11-19, AskUserQuestion)

1. **Recent lookups name what was looked up, in the panel only.** The node panel (opened by a click) shows the last few names with allowed or blocked and their age, under the same privacy-level rules as the query log; the map drawing itself stays free of domain names. This amends ADR-958 section 7.
2. **Answers are a share bar on each node** ("62% cache, 8% blocked"); the per-node cache, local and blocked boxes go, and the last column is Upstreams only.
3. **Network names come from the CMDB's network CIs** (UniFi's name by default, a manual name if set), with the interface and subnet as secondary text; this lands with T31.7 (the CMDB names what the UI shows, DSC-901 as amended).
4. **Names already imported with HTML codes are repaired once, automatically,** on upgrade, for API-managed entries (audited as a system change); names in configuration files are reported, never rewritten.

**Status (2026-11-19):** A1 and A6 (T35.1, ADR-1032), A2 (T35.2) and A3 (T35.3) are built; the rest is T35.4 to T35.7.

## The proposal

This is a read-only review: nothing was edited or run. Every point below was re-checked in the code on `feat/ipam-integrations`. Paths are relative to `C:/src/wrendns`.

**The root cause.** The node panel prints the API's raw shape: reason codes, counters, enum values, and summaries written for a different view. The panel is an inline `<aside class="card nodepanel">` at `ui/src/pages/Map.svelte:440-487`, not `Drawer.svelte`. Almost all of the data needed is already in the snapshot or one API call away, so most of the fix is UI-only.

---

### (A) Bugs to fix now (data)

**A1. "Alex&#039;s PC": an HTML entity is saved in the name.** Backend, S.
- **Cause:** the Pi-hole importer copies `client.comment` as given: `one_line(&text(c,"comment"))` at `crates/telltale/src/pihole.rs:1602`. `one_line` (`pihole.rs:331-337`) only replaces control characters. Pi-hole's PHP admin stores comments escaped with `htmlspecialchars`, so `&#039;` is saved into the name. Svelte prints text literally, so the entity shows on screen.
- **Fix:** add one helper that decodes `&amp; &lt; &gt; &quot; &#39; &#039; &#xNN;` once, then strips control characters. Use it on the importer's human-text columns only: client comment, group name and description, adlist and domain comments. Never use it on domain or regex columns.
- **Existing names:** add a repair note that offers the fix, or the owner renames the one device.
- **Safety:** I checked that `ui/src` has no `{@html}` or `innerHTML`, so a decoded `<` stays inert. Add a lint rule that forbids `{@html}`.
- **Unexplained:** the map label comes from `device_name()` (`api_backend.rs:89-125`, which calls `identify(ip, None, None, …)`). The policy line comes from `policy_view.rs:137-140` (`identify` with `subject.mac`). Both read `clients.client(id).name`, yet the screenshot shows the policy line clean. That points to two different client records, possibly one keyed by MAC and one by IP. Check `GET /api/v1/clients` before fixing.

**A2. Compact policy shows "the lists below" and then nothing; Upstream names no upstream.** UI, S.
- **Cause:** compact mode keeps only sections that have items, but renders only `{s.title}. {s.summary}` and never the items (`ui/src/lib/components/PolicyPanel.svelte:76-81`). The summaries were written for the full view: `"Group {} names the lists below."` (`crates/telltale/src/policy_view.rs:311`) and `"Where this device's queries are forwarded."` (`:641`).
- **The data is there:** the upstream items carry the group name (`policy_view.rs:602-637`).
- **Fix:** in compact mode, render up to 3 item labels as links, then "+N more".
- **Also (backend, S):** make each server summary stand alone, so the API and MCP output read well too.

**A3. Upstreams show internal ids ("forward:168.192.in…", "forward:example…").**
- **Cause:**
  - The ids are built by `managed.rs:539-541` (`forward:{domain}`), and stub zones add `#stub` (`:544-546`).
  - The map uses them directly: `label: name.clone()` with `address: None` (`crates/telltale-api/src/map.rs:1056-1065`).
  - The Upstreams page already hides these names (`ui/src/pages/Upstreams.svelte:113`, `api_backend.rs:3771`).
- **Fix (recommended: backend, S):** a display-label function in `map.rs`:
  - `forward:<x>.in-addr.arpa` becomes "Reverse lookups, 192.168.x.x".
  - `forward:home.example` becomes "home.example names".
  - `#stub` adds "(stub zone)".
  - Fill `address` with the server IP.
  - Use the same function for the policy route detail (`policy_view.rs:631`, `goes to {group}`).
- Doing this on the server fixes the MCP `network_health` output as well. A UI-only formatter would leave the raw ids there.

**A4. The anomaly reason doesn't say which anomaly and has no link.**
- **Cause:**
  - The text is fixed: "an open anomaly finding nobody has acknowledged" (`map.rs:519-524`).
  - The backend passes on only `f.client` (`api_backend.rs:2780-2789`), and throws away the finding's `id`, `kind`, `detail` and window.
  - The UI prints the code in bold as a label: `<b>{r.code.replace(/_/g,' ')}</b>` (`Map.svelte:456`).
- **Stopgap (UI, S):** the panel reads `api.anomalies('-1d', false)`, filters by `sel.address`, shows the newest finding's kind and time, and links to `#/anomalies?client=…`.
- **Proper fix (backend, M):** add an optional `anomalies: Vec<{client,id,kind,since}>` to `MapPart` with `#[serde(default)]`. Peers one version behind keep working (N-1). Regenerate OpenAPI.
- Keep `domain` out of this line (ADR-958 §7, see F1).

**A5. Networks show interface names (eth0, eth0.100, wlan0).**
- **Cause:** the map labels come from `b.networks()` (`crates/telltale-api/src/map_api.rs:145-153`). An interface row is used only when no router reported that subnet (`api_backend.rs:3249-3272`). On a replica, `Federated::networks()` should merge in the primary's UniFi names (T24.41).
- **So:** eth0 here means one of three things: an older build is running, this is the primary with an empty UniFi read, or UniFi does not report 192.0.2.0/24.
- **Check first:** `GET /api/v1/networks` on the node the browser uses. This is a deploy or data check, S.

**A6. "IoT - Google -? (2)".**
- **Cause:** ` (2)` comes from the importer's `unique()` (`pihole.rs:828-835`). The `?` is most likely already in Pi-hole's stored comment.
- **Fix (backend, S):** tell colliding names apart with the last octets of the MAC or IP, and list names that contain `?` or U+FFFD in the import report.
- **Related (UI, S):** `trunc()` slices UTF-16 code units (`Map.svelte:218`), so it can split an emoji in half. Truncate by grapheme instead.

---

### (B) The node panel

**The new order:**
1. Name and status badge.
2. One sentence on what is going on.
3. A short facts list.
4. Policy.
5. Recent lookups.
6. One primary action and secondary links.
7. A collapsed **Details** block with every raw value.

Everything in it is available in the API, except the A4 anomaly detail and the A1 name fix.

**Before (today, `Map.svelte:442-482`):**
```
Alex&#039;s PC                                   Close
[Warning] device in eth0, group Adults
192.0.2.10
0.53/s over the window (32 answers, 32 sampled).
 • anomaly: an open anomaly finding nobody has acknowledged
Policy
Group Adults from the device's own groups
Recognized by [MAC] aa:bb:… as Alex's PC at 192.0.2.10 (?)
 • Block response. A blocked name is answered 0.0.0.0 / :: (TTL 60 s, EDE 15).
 • Lists. Group Adults names the lists below.
 • SafeSearch and YouTube. Search engines are not restricted.
 • Upstream. Where this device's queries are forwarded.
Full policy
Flows
 Alex's PC → node-b: 0.53/s, 0% slow, 0% failing, healthy
Recent lookups
 9:28:26 AM: forwarded, 10 ms   (x5)
(Show its queries) (Explain a name for it) (Anomalies for it) (Device page)
```

**After:**
```
Alex's PC                               [▲ Degraded]   ✕
Adults group · LAN (eth0)

1 open anomaly: a burst of NXDOMAIN answers at 9:12 AM, not yet
reviewed.                                          Review it

Address        192.0.2.10
Lookups        32 in the last minute, all through node-b, none slow
Recognized by  its hardware address, so its rules follow it if
               the IP changes

Policy
Group          Adults, set on this device
Blocking       Blocked sites get an empty address and don't load
Lists          StevenBlack · OISD · +3
SafeSearch     Off
Upstream       cloudflare; home.example names go to the router
See all rules for Alex's PC

Recent         5 lookups, all looked up online, 8-12 ms, last 12 s ago

[ Recent lookups ]   Why was something blocked? · Anomalies (1) · Open device

▸ Details   (IP, MAC, matched key, 0.53/s · 32 counted · 32 sampled · 60 s
             window, block mode nullip · TTL 60 s · EDE 15, reason codes and
             thresholds, raw status of each lookup, node id)
```

**Rewritten lines, with where each comes from:**

| Today | After | Source |
|---|---|---|
| `Warning` | `Degraded`: one word everywhere. Today the panel says `HEALTH_SHORT.yellow='Warning'` while the summary and table say `HEALTH_WORDS.yellow='degraded'` (`ui/src/lib/map.ts:32-39`). The brand book uses "Degraded". `OK`→`Healthy`, `Idle`→`Quiet`. | `map.ts:39` |
| `device in eth0, group Adults` | `Adults group · LAN (eth0)`. Drop the kind word on devices. | `Map.svelte:449` |
| `0.53/s over the window (32 answers, 32 sampled).` | `32 lookups in the last minute, all through node-b, none slow`. Say "estimated" only when `sampled < count`. The minute comes from `snap.windowSecs`; the flow facts come from `selEdges`. This also replaces the Flows block (`Map.svelte:463-469`) when a device has one healthy flow. | `Map.svelte:452-454` |
| `anomaly: an open anomaly finding…` | No code prefix for any reason. Each reason becomes a sentence with a link. The same applies to slow, high_blocked and error, whose "(yellow from 10%)" thresholds (`map.rs:480-516`) move to Details. | `Map.svelte:456` |
| `Group Adults from the device's own groups` | `Adults, set on this device`. Reword `groupFromText`: network → "because it's on LAN"; router_name → "from the name your router gives it"; default → "the default rules; nothing sets a group". | `PolicyPanel.svelte:58-62`, `policy.ts:4-10` |
| `Recognized by MAC aa:bb:… as Alex's PC at 192.0.2.10 (?)` | `its hardware address, so its rules follow it if the IP changes`. In compact mode drop "as / at", which repeat the header, and move the MAC to Details. Reword `matchedByText`: ip → "its IP address (can change with DHCP)". | `PolicyPanel.svelte:63-70`, `policy.ts:12-21` |
| `Block response. A blocked name is answered 0.0.0.0 / :: (TTL 60 s, EDE 15).` | `Blocked sites get an empty address and don't load`. NXDOMAIN → "the name looks like it doesn't exist"; custom IP → "sent to your block page". Key off the item label (`policy_view.rs:190`). | `policy_view.rs:185` |
| `Lists. Group Adults names the lists below.` | `StevenBlack · OISD · +3` (A2) | `policy_view.rs:311` |
| `SafeSearch and YouTube. Search engines are not restricted.` | `Off`. When on: `On for Google, Bing, DuckDuckGo; YouTube restricted`. | `policy_view.rs:406` |
| `Upstream. Where this device's queries are forwarded.` | `cloudflare; home.example names go to the router` (A2 + A3) | `policy_view.rs:641` |
| `Full policy` | `See all rules for Alex's PC` | `PolicyPanel.svelte:82` |
| `9:28:26 AM: forwarded, 10 ms` ×5 | One folded line (needs no ADR). Translate statuses in one shared map: forwarded → looked up online, cached → from cache, stale → old answer reused, servfail → failed, rate_limited → slowed down. Keep the raw value in `title`. | `Map.svelte:471-474`; `MapRecent` has no name by design (`map.rs:125`) |
| 4 equal pills | One primary button in `sky-strong`, the rest as text links. Labels: `Recent lookups`, `Why was something blocked?`, `Anomalies (n)` (hidden at 0), `Open device`. | `map.ts:406-417`; `.pill-link` uses `--accent` green |

**Layout notes:**
- The status badge goes on the title row.
- Lift the `.facts` grid from `HostCard.svelte:179-190` into `app.css` so both panels share it.
- Set IPs and MACs in mono with a copy button.
- No accent bar on `h2`/`h3`. The `.card-head h2::before` bar and `.notice` left border go against "no colored left-border cards".
- Below 1100px, open the panel as a side sheet using `Drawer.svelte`, which brings focus on open and Esc to close. Today it stacks under the whole map (`Map.svelte:496-506`).

---

### (C) The map

**C1. Answer boxes repeat per node (9 boxes).** UI, M.
- **Cause:** `map.rs:1077-1100` builds `ans:{node}:{kind}` for cache, local and blocked per resolver.
- **Recommended:** stop drawing them. Each node box gets a thin share bar and one line, e.g. `62% cache · 8% blocked`. The shares come from the `ans:*` nodes' qps, already in the snapshot.
- **Result:** the last column becomes "Upstreams" only.
- **Alternative:** merge them into 3 "outcome" boxes across nodes.
- **ADR:** add a one-line note on ADR-958 §1/§8 that the drawing aggregates what the data keeps per node.

**C2. Words.**
- **Column titles:** `Resolvers` → `Nodes` (the brand: a resolver is a node) and `Answers and upstreams` → `Upstreams` (`map.ts:68`). Drop `text-transform: uppercase` (`Map.svelte:540`) for sentence case.
- **Summary** (`map.ts:384-397`):
  - Before: "30 nodes, 3 networks, 8 devices, 3 resolvers, 6 upstreams. 0 failing, 3 degraded, 3 healthy, 24 idle."
  - After: "8 devices on 3 networks, answered by 3 nodes through 6 upstreams. 3 need a look: node-a, node-b, node-c. Nothing is failing."
  - Name up to 3, as links. Keep the long form for `aria-label`.

**C3. Quiet nodes.** UI, S.
- **Today:** 24 of 30 boxes say "Idle · 0.00/s" with dashed borders. The rate is always printed (`Map.svelte:388`) and the dash comes from `.node.idle rect`.
- **After:**
  - A solid hairline, muted ink, the word "Quiet", and no rate.
  - Make the structural tracks solid as well.
  - Add a "Show quiet devices (24)" toggle, kept in the URL.
  - Never hide quiet upstreams or networks.

**C4. Labels.** UI, S.
- **Tooltip:** always draw `<title>{label}</title>`. Today it is drawn only when the node has reasons (`Map.svelte:384`), so a healthy "Google Video Playe…" can never be read in full.
- **Fit:** wrap to 2 lines (NODE_H 30 → 40) before cutting. If it still doesn't fit, cut the middle and keep the tail, which tells duplicates apart.
- **Networks:** label them with the router name or VLAN, with `eth0.100 · 198.51.100.0/24` in mono as secondary text. Join `api.networks()`, which already carries subnet, vlan and source; A5 decides whether real names appear.
- **Upstreams:** use the A3 labels.

**C5. Legibility.** UI, S.
- **Scaling:** the 1000px SVG scales down when the 320px panel opens (`max-width:100%`), so labels drop to about 9px. Never scale below 1; let `.mapscroll` scroll instead. Set labels at 13px and state text at 12px.
- **Legend:** turn it into counted filter chips in the header: `[3 healthy] [3 degraded] [0 failing] [24 quiet]`.

**C6. Keyboard and selection.** UI, S–M.
- **Order:** draw nodes in column order. The snapshot puts devices before the gateway, so Tab order jumps around.
- **Focus:** draw a separate 2px focus ring instead of the current `outline:none` plus a thicker border (`Map.svelte:623-630`).
- **Selected:** `sky-soft` fill with a `sky-strong` border.

**Map mockup (after):**
```
Network map                         Live, every 2 s   [Map|Table]   Pause motion
[✓ 3 healthy] [▲ 3 degraded] [⬣ 0 failing] [○ 24 quiet]  Network▾ Group▾ Node▾ [search]
8 devices on 3 networks, answered by 3 nodes through 6 upstreams.
3 need a look: node-a, node-b, node-c. Nothing is failing.

 Gateway       Networks              Devices              Nodes                    Upstreams
┌──────────┐  ┌──────────────────┐  ┌────────────────┐   ┌─────────────────────┐   ┌───────────────────┐
│✓ UniFi   │──│✓ LAN             │──│▲ Alex's PC   │──▶│▲ node-b       0.5/s   │──▶│✓ cloudflare       │
│  gateway │  │  eth0 ·          │  │  0.5/s         │   │ ▇▇▇▇▇▇▁▁▂           │   │  tls://1.1.1.1    │
└──────────┘  │  192.0.2.0/24 │  ├────────────────┤   │ 62% cache · 8% block│   ├───────────────────┤
              ├──────────────────┤  │✓ Google Video  │   └─────────────────────┘   │✓ home.example   │
              │○ IoT VLAN  quiet │  │  Player (2)    │   ┌─────────────────────┐   │  names · router   │
              │  eth0.100        │  └────────────────┘   │▲ node-a …             │   ├───────────────────┤
              └──────────────────┘  Show 24 quiet devices└─────────────────────┘   │○ Reverse lookups  │
                                                                                   │  192.168.x.x quiet│
                                                                                   └───────────────────┘
Wider, denser pulses mean more lookups a second. 60-second window.
```

---

### (D) Rules for showing technical information (for brand/README.md "Voice" or a UI guide)

1. **Lead with the thing's name, then what happened, then why**, in one sentence. Codes, enum values and ids never lead a line. Example: `node-b stopped using cloudflare after 5 failures`, not `breaker_open: …`.
2. **One word per state, everywhere:** Healthy, Degraded, Failing, Quiet. Every enum (health, query status, matched-by, group-from, block mode) is translated in one module, `ui/src/lib/words.ts`, shared by Map, Explain, Queries, Clients and StatusBadge. The raw value goes in `title` and Details.
3. **Two layers.**
   - The first screen says what a person needs.
   - A closed **Details** block holds the exact values: IP, MAC, TTL, EDE, rate, counted, sampled, window, thresholds, ids. These are set in mono on `surface-sunken`, with a copy button.
   - Nothing is removed. It moves.
4. **No line points at something that isn't drawn** ("below", "these"). A summary has to stand alone in whichever view shows it, including the API and MCP output.
5. **Never show an internal id** (`forward:…`, `#stub`, `ans:…`, `res:…`) as a label. Every id has a display name, made once on the server so the UI and MCP agree.
6. **Don't spell out the normal case.** Leave out zeros ("0% slow, 0% failing") and defaults ("sampled" when nothing was thinned, SafeSearch when it is off) in compact views. Say "none slow" or say nothing.
7. **Mono only for values a person might copy:** domains, IPs, MACs, records, TTLs. Never for prose or names.
8. **Name things fully.** Truncation keeps the tail and always has a tooltip. Never cut a name with no way to read it in full.
9. **Every warning names its subject and links to where it is resolved.** Show a count on the action ("Anomalies (1)") and hide the action when the count is 0.
10. **One primary action per panel**, in `sky-strong`. The rest are text links.
11. **Imported text is normalized at ingest and never decoded at display.** The UI only ever interpolates text; no `{@html}`.

---

### (E) Proposed task split

| Task | Scope | Backend? | Timing |
|---|---|---|---|
| **T-a Import name hygiene** | A1 decode helper, plus a repair note or plan with a UI button. A6 meaningful duplicate suffixes and a report of names that lost characters. Proposed ADR: "names normalized at ingest". | Yes, S–M | Before the rebrand; independent |
| **T-b Shared words module** | `ui/src/lib/words.ts`: health words (one set), query status, matchedBy and groupFrom rewording. Adopt it in Map, StatusBadge (`StatusBadge.svelte:34`), Queries, and Explain (`ExplainView.svelte:93` raw `neighbor_mac`, `:116-122`, `:135`). | No | Before the rebrand; its copy should follow the new voice |
| **T-c Policy panel compact fix** | A2 render items in compact mode, rewritten section lines, no repeated name and IP. Server summaries made self-contained (`policy_view.rs:185,311,406,641`). | UI S; summaries S backend (shared with API/MCP, so update the OpenAPI examples) | Before the rebrand; the most visible fix |
| **T-d Display labels for upstreams and networks** | A3 `upstreamLabel` and `address` in `map.rs`, the policy route detail. Network nodes carry subnet, vlan and router name. A5 is a deploy check first. | Yes, S | Before the rebrand |
| **T-e Node panel redesign** | Section B: header, lead sentence, facts list, Details expander, folded flows and recent lookups, one primary action, side sheet under 1100px. A4 stopgap (UI anomaly lookup). | No (the A4 proper fix is backend M, can follow) | With the rebrand; uses the new tokens, fonts and `sky-strong` |
| **T-f Map redesign** | Section C: node share bars instead of answer boxes (plus an ADR-958 note), Quiet styling and toggle, labels and tooltips, summary sentence, chips legend, no scale-down, keyboard order and focus ring. | No | With the rebrand; depends on T-b and T-d |
| **T-g Anomaly reference in the map** | The A4 proper fix: `MapPart.anomalies`, `MapReason.link`, N-1 test, OpenAPI. | Yes, M | After T-e |
| **T-h Brand guide rules** | Section D added to `brand/README.md`, plus docs/ and site/ text for the changed wording. | No | With the rebrand |

**Requirements on every task:**
- Each user-visible text change needs `docs/` updated, plus `site/` where a page covers it.
- T-c, T-d and T-g change API text or fields, so they need OpenAPI regenerated and the MCP output checked.
- None of these touches the hot path.

---

### (F) Open questions for the owner (to ask through the question tool)

1. **Domain names in the panel's recent lookups?** Today ADR-958 §7 says no domain appears anywhere in the map.
   - **Recommended:** keep the map free of names, fold the five rows into one line, and make "Recent lookups" the primary action into Queries. Queries already applies the privacy level.
   - Showing names would need a Proposed ADR amending ADR-958 §7.
2. **Answer boxes: share bars on each node, or 3 merged outcome boxes?**
   - **Recommended:** share bars. They remove 9 boxes and a column of lines. Record it as an ADR-958 drawing note.
3. **Should people be able to name networks**, e.g. a "Main LAN" label on the Networks page (backend M, with a UI control in the same task)?
   - **Recommended:** first check why UniFi names are not reaching the map (A5). Add a label override only if the router names are missing or poor.
4. **Fixing names already imported with HTML codes:** an automatic one-off repair, or a one-click "Fix" note on Health/Clients?
   - **Recommended:** the one-click note, applied as a plan for API-managed clients. For file-defined clients, show the file and line to edit, so WrenDNS never rewrites the owner's file.
