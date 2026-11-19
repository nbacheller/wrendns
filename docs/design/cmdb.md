# CMDB (M31) — design

Status: design only (T31.1, fork #21). Requirements DSC-901..907; ADR-1004 (model, reconciliation, definitive sources, MACD) and ADR-1005 (storage, API, MCP, federation, retention), both Proposed. No code is written by T31.1.

## What it is

One **configuration item (CI)** for each real thing on the owner's network, built from every source that reports on it. The CMDB keeps each source's record as reported, links it to its CI, lets the owner say which source is **definitive** for each attribute, and records changes (move, add, change, delete) through a **MACD** lifecycle. M25's inventory (keyed by MAC, ADR-910) is the first matching rule and a source of records, not something the CMDB replaces.

## What it is not

- **Not DNS policy.** CMDB data never feeds DNS answers, client matching, `Neighbors`, `identify`, filtering or device names in DNS (ADR-910's containment, extended). A manual CMDB name stays in the CMDB (owner decision 6).
- **Read-only towards devices and gateways.** No SNMP SET, no UniFi, OPNsense or Home Assistant write, no probe. A MACD marked done changes nothing on the network; it records that a change was seen or confirmed. Any write to a gateway needs its own ADR (T25.18 is the place for that).
- **Not on the DNS path.** It runs on its own thread on the designated node and reads sources off the query path (CLU-004, DSC-002).
- **Not a ticketing system.** One lifecycle, four states, no assignment, no SLA.

## Consistency with the designs in flight

| Design | How the CMDB fits |
|---|---|
| M25 inventory (T25.1, ADR-910, ADR-923, ADR-924) | The inventory's MAC merge is reconciliation rule R2 and uses the same normalisation code. Its source classes, name ranks, freshness and retention become the **default precedence and freshness** of the matching attributes (below). The inventory keeps serving Clients → Discovered unchanged; the CMDB reads the same feeds through a source sink beside it. Containment is kept. |
| T25.6 poller (ADR-908) | SNMP ARP, bridge, LLDP and identity rows are the `snmp:<agent>` source. The poller only gains a second output (records to the sink); no new I/O. |
| T24.29 filter profiles (ADR-994) | A profile is a group, so a device's `member_of` relation points at a group id and the CI page shows the profile by name. The CMDB reads group membership; it never writes it. |
| T24.30 effective policy | The CI page's **Policy** panel calls `GET /api/v1/clients/{id}/policy`. The CMDB computes no policy. A device CI maps to a client through its MAC, addresses or client ID (the keys ADR-973 and ADR-976 use). No match, no panel. |
| T25.18 UniFi sync design (ADR-998, ADR-999, Proposed, branch `feat/t25.18-unifi-sync-design`) | The `[[group_link]]` **keeps the direction**: `unifi_definitive`, `telltale_definitive` or `two_way` (a three-way set merge with no definitive side). The CMDB never decides it and its precedence never drives the sync (ADR-998 §14 says the direction is read from CMDB precedence once T31.3 lands; ADR-1004 §6 declines that, see owner question 13). `member_of` is a **set** with the sources `config` (the group's `[[client]]` membership) and `unifi:<router>` (the router adapter's read of the linked group object, when T25.18's backend exists). The CMDB shows the link as a **read-only, mirrored rule** (link id, group, router, mode with `two_way` shown as `merge`, last round, state) on the CI page and in the conflict view; it is never authoritative and has no edit control. Membership from either source is display only: it never reaches filtering, client matching or DNS (DSC-901). The sync writes group membership through configuration, which T24.30 reads; the CMDB reads configuration and the router, nothing else. The sync runs on the **primary** (ADR-998 §13), the CMDB on the **designated node** (ADR-1005 §1); with a named designated node they can differ, so the CMDB reads the links and their status from shared configuration and the router adapter, never from the sync's node-local `state.db`. |

## Model

### CI types

| Type | Is | Created by | Key (match) |
|---|---|---|---|
| `device` | A physical or virtual thing: laptop, phone, camera, switch, AP, printer, server, workload | the first record that cannot be attached to a device | serial, a source's stable device key (Home Assistant device id, SNMP chassis id), the `has_interface` of a matched interface, manual link, proposed hostname+network |
| `interface` | One network interface. **A MAC is an interface, not a device.** Two kinds: `nic` (a client's or device's own interface) and `port` (a switch or AP port) | every MAC-keyed record (`nic`); a switch or AP port record (`port`) | `nic`: MAC. `port`: (device CI, normalised port id), never the MAC, because ports often share one MAC or have none |
| `network` | A subnet or VLAN | `[[router]]` networks, `[[discovery.subnet]]`, manual | CIDR + VLAN |
| `node` | A TelltaleDNS node | cluster membership | node id |
| `service` | A listener or a service: a node's DNS, DoH, API; a Kubernetes Service | config, cluster, Kubernetes, manual | node + port, or namespace + name |
| `upstream` | A configured upstream resolver | config | upstream name |

By default one new MAC makes one interface CI inside one device CI ("one MAC, one device until told otherwise"). A laptop with Wi-Fi and Ethernet becomes one device with two interfaces when a serial, a Home Assistant device id or a manual link says so. Merging moves interfaces; the losing device id stays as an alias that redirects for 90 days.

### Relations

Stored as typed edges between CI ids, each with its own source and first and last seen, so they have provenance and can conflict like attributes.

| Relation | From → to | Source of truth in practice |
|---|---|---|
| `has_interface` | device → interface | reconciliation, manual |
| `on_network` | interface → network | router and SNMP VLAN data; address inside a CIDR |
| `attached_to` | `nic` interface → `port` interface (a switch or AP port) | SNMP bridge and LLDP, UniFi `stat/device` |
| `member_of` | device → group (policy) | a **set** with two sources: `config` (read through the T24.30 resolver) and `unifi:<router>` (the linked group's members, T25.18). Read-only; a union, never in conflict. The link's direction (`unifi_definitive`, `telltale_definitive`, `merge` for `two_way`) is shown as a mirrored read-only field |
| `runs_on` | service → device or node | config, cluster, Kubernetes |
| `uses_upstream` | node or group → upstream | config; read-only |

### Port identity

A `port` interface CI is keyed by (device CI, normalised port id). Sources name a port differently, so each source record carries the raw id and a normaliser makes the key:

| Source | Raw id | Normalised port id |
|---|---|---|
| SNMP | `ifName`, else `ifDescr`, else `if<ifIndex>` | lower-case, spaces and `-` removed (`Gi1/0/5` becomes `gi1/0/5`, `Port 5` becomes `port5`) |
| UniFi `stat/device` | `port_idx` | `port<idx>` |
| LLDP | remote `portId` (interface name subtype) | as SNMP |

A **port alias** table (device CI, source, raw id, port CI) joins ids that differ in naming. An alias is learned only from evidence on the same device (an SNMP `ifName` whose trailing number equals the UniFi `port_idx` on a device matched by serial or manual link, or an LLDP pair); otherwise a person sets it in the CI page. A source port with no alias to an existing port makes its own port CI marked `unmapped_port`; that is shown, never a conflict and never a MACD. A client's `port` value is the port CI id, so a UniFi `port_idx` against an SNMP `ifName` is the same value once aliased and cannot look like a permanent conflict. Port CIs are created only for devices with a class 1 to 3 source and count against the CI cap.

### Source records

A source record is what one source said about one thing, kept as it said it.

| Field | Meaning |
|---|---|
| `source` | kind and instance: `unifi:<router>`, `opnsense:<router>`, `home_assistant:<router>`, `snmp:<agent>`, `import:<id>`, `neighbor`, `lease`, `mdns`, `pihole_import`, `queries`, `k8s`, `config`, `cluster`, `manual` |
| `source_key` | the thing's identity in that source (UniFi `_id`, an SNMP ifIndex plus agent, an import row, the config name) |
| `ci_type` | what the source thinks it is |
| `attrs` | up to 24 typed attributes, each value cut to 255 B and stripped of control characters (DSC-015) |
| `first_seen`, `last_seen`, `last_changed` | times |
| `state` | `present`, or `absent` after two missed complete batches (ADR-924) |
| `ci`, `link` | the CI it is linked to; `link` is `auto:<rule>`, `manual` or `none` |

**CI registry row.** Beside its keys, each CI keeps `first_seen`, a CI-level `last_seen` (the latest of its records, so it outlives a derived record's 7-day expiry) and `days_seen` (a count of distinct days a presence source saw it, capped at 32, advanced at most once a day). `delete` detection reads these, not the records, and they replicate with the registry so a new designated node has them after a failover.

**Write volume.** A record is written only when its content (a hash of its attributes) changes. A record's `last_seen` lives in memory and is flushed in one batched transaction every 15 minutes, and only for rows whose stored value is more than 6 hours old (or on shutdown, or when the record turns absent). A stable network therefore writes about four small updates a day per record, not a rewrite of every record every minute, which matters on a Pi's SD card (WAL, ADR-1005 §2). The acceptance bound is in T31.2.

### Attributes and the catalog

An attribute has a type, a cardinality (`single`: one winner; `set`: the union, never in conflict), the sources that can report it, whether a manual value is allowed, a default precedence and whether a change is **detected** (raises a MACD). The catalog is code (one table), shown in the UI.

| CI type | Attribute | Card. | Default precedence (first wins) | Detect | History |
|---|---|---|---|---|---|
| device | `name` | single | manual, config client name, Home Assistant user name, router alias (in `[[router]]` order), Home Assistant integration name, mdns, SNMP sysName, import host name (ADR-910 ranks) | no | yes |
| device | `role` (router, switch, ap, printer, phone, ...) | single | manual, SNMP sysObjectID and capabilities, UniFi device type, `queries` class, import | change, infrastructure only | yes |
| device | `vendor`, `model` | single | manual, UniFi, SNMP, Home Assistant, OUI | change, infrastructure only (a swap) | yes |
| device | `serial`, `firmware`, `os` | single | manual, SNMP, UniFi, Home Assistant, import | `serial`: yes | yes |
| device | `location` | single | manual, Home Assistant area, SNMP sysLocation | no | yes |
| device | `member_of` (group ids) | set | `config`, `unifi:<router>`: a union | no | no |
| device | `owner`, `criticality`, `notes`, `tags`, `protected` | single / set | manual only | no | no |
| device | `last_seen`, `present` | derived | any presence source | disappearance only | no |
| interface | `mac` | single | the key | no | no |
| interface | `addresses` | set | ADR-910 classes: routers and reservations, neighbour table, SNMP ARP, import, history | no (DHCP churn) | no |
| interface | `vlan`, `network` | single | UniFi, SNMP Q-BRIDGE, address inside a CIDR | yes (wired and infrastructure) | yes |
| interface | `port` (`attached_to`, a port CI id; see Port identity) | single | SNMP bridge, UniFi | yes (wired; never an AP-connected client) | yes |
| interface | `ap` | single | UniFi | no (roaming is not a change) | no |
| network | `name`, `cidr`, `vlan_id`, `gateway` | single | UniFi, OPNsense, config subnet, manual | yes | yes |
| node | `name`, `address`, `role`, `version` | single | cluster | no | yes |
| service | `name`, `protocol`, `port`, `runs_on` | single | config, cluster, Kubernetes, manual | no | yes |
| upstream | `name`, `address`, `protocol` | single | config | no | yes |

`manual` is first by default for every attribute that allows it: a person's statement beats a machine's. The owner can change any row in the UI.

**History** is kept only for rows marked yes: single-valued, non-derived attributes. Sets, derived values and `ap`, `addresses` and `last_seen` never write history rows (DHCP churn and roaming would fill the cap and push out useful rows). History is also replicated, so this bound matters twice.

## Reconciliation

Rules run in order on every ingested batch, and **each level is resolved on its own**: the interface level (which interface CI is this record?) and the device level (which device CI?). Mixing them would let a MAC (an interface) and a serial (a device) point at different devices and have the first rule hide the disagreement.

**Interface level** (a record with a MAC or a port id): **R1** manual link or unlink, then **R2** MAC. A port record resolves by (device CI, normalised port id) and the alias table (Port identity).

**Device level:** **R1** manual link or unlink, **R3** serial, **R4** the source's own stable *device* key, then the `has_interface` of the interface CI found above. **R5** hostname plus network proposes only.

1. **R1 Manual.** A manual link or unlink is a pin and always wins at either level. An unlink writes a "never match" pin for that record and rule, so it is not re-linked on the next batch.
2. **R2 MAC.** The normalised MAC (the same code as the inventory's merge) selects the `nic` interface CI. A locally administered (randomised) MAC matches but never raises an `add` MACD (ADR-910). A MAC identifies an interface: `interface.mac` is its key, so a new MAC is always a new interface CI.
3. **R3 Serial.** An SNMP entPhysicalSerialNum, a UniFi device serial or a Home Assistant device serial selects the device CI and joins interfaces to it.
4. **R4 Stable device key.** A key that survives a MAC change, scoped to its instance: a Home Assistant device id, an SNMP chassis id (`lldpLocChassisId` or `entPhysicalUUID`), a UniFi *infrastructure device* id. It selects the **device** CI. If the record's MAC is new, a **new interface CI** is created under that device (`has_interface`); R4 never moves an existing interface to a new MAC. **A UniFi client `_id` (`rest/user`) is not a key**: UniFi keys a client by MAC, so a new MAC gets a new `_id`, and a phone that changed its MAC is a new interface until a person, a serial or one of these keys joins it to its device.
5. **R5 Hostname plus network.** A non-generic host name and the same network, with one candidate and no MAC conflict, **proposes** a link. It is never applied alone; it appears as a MACD of kind `change` ("merge these?") for a person to confirm (owner question 12).

**Disagreement.** Within a level the first rule that finds exactly one CI links, and two or more is not guessed. Across levels, when the interface found by R2 belongs to device A and R3 or R4 finds device B, nothing is linked at the device level: the record stays on its interface's device and a merge proposal (a MACD `change`, "these two devices may be one") is raised with both ids and the rule that pointed at each. A manual merge or a serial the person confirms resolves it (`dsc_903_level_disagreement_proposes_merge`).

A record with no key (an IP-only import row, an mDNS answer) attaches through a class 1–3 address binding as in ADR-923, else becomes its own `unconfirmed` device CI. A manual **merge** moves the records and leaves an alias; a manual **split** moves chosen records to a new CI and pins them.

## Definitive sources

For each CI and attribute the **merged value** is the value of the first source in the precedence list that has a fresh value. Resolution order:

1. A per-CI **attribute pin**: a source or a manual value fixed for this CI and attribute.
2. A per-CI **override list** (a source order for the whole CI).
3. A **scoped rule** (`type`, `attribute`, `scope = group:<id> | network:<id>`).
4. The **type and attribute rule** (the owner's setting, `[[cmdb.precedence]]`).
5. The built-in default in the table above.

**Freshness** per source kind: two poll intervals for polled sources (ADR-924: neighbour 2 min, routers and mDNS 15 min), the retention window for imports (30 days) and the Pi-hole import, never stale for `config`, `cluster` and `manual`.

**When the definitive source goes silent:** the default is `silent = "next"`: the value falls to the next fresh source and shows a **fallback** badge with the definitive source's last value and its age. The alternative `silent = "hold"` keeps the last value, marked stale, for `hold_days` (default 7) and then falls back. When `next` finds **no fresh next source**, the value is held at its last value marked **stale** (as `hold` does) until a source is fresh again; it never shows empty. A source instance silent for more than 24 hours raises one `source_silent` finding (not a MACD) per instance.

**Conflicts.** For a `single` attribute, a conflict exists when at least one fresh, non-definitive source holds a different value after normalisation (case-folded names, canonical MACs, normalised CIDRs). The conflict view lists CI, attribute, the definitive value and source, the differing values and sources, and for how long. Actions: **Accept** (pin that source for this CI and attribute), **Keep** (mute, with an optional expiry), **Raise a MACD** (a `change` asking someone to fix it at the source). Sets never conflict, and `member_of` is a set: a T25.18 link's direction is **not** a precedence rule. The conflict view shows a linked group as a read-only, mirrored line (link, mode, state; `two_way` shown as `merge`) with no Accept, Keep or edit control, and CMDB precedence never drives the sync.

**Caps.** 1,024 conflict mutes (oldest first, as ADR-924 does) and 64 pins plus override-list entries per CI; past a cap the API answers 409 with the cap named.

## MACD

A MACD record: `id`, `kind` (`move`, `add`, `change`, `delete`), `ci`, `attribute` (when it applies), `from` and `to` values, `origin` (`detected:<source>`, `user:<name>`, `agent:<token> (owner: <user>)`), `observed` (true when it already happened), `state`, `reason` (required for agents, AGT-005), timestamps, approver and comment, and a closure reason.

States: `requested`, `approved`, `done`, `rejected`.

```
requested -> approved -> done
    |           |
    +-> rejected <+        (closure reason: rejected, expired, reverted, superseded)
```

- **Observed changes** (detected from sources) are born `requested`, and **approving one moves it straight to `done`** (it already happened; approval means "expected"). Rejecting marks the change *unexpected* and leaves it flagged on the CI.
- **Baseline: the acknowledged value.** The detector keeps, per CI, attribute and **source**, an *acknowledged value*. Detection compares that source's own record value with it, never the merged value. Approve advances the acknowledged value to the new one; **reject also advances it** (and sets the flag), so the same condition does not raise a new record on every settle period. A new record is raised only when the source's value changes again. The flag is cleared by an operator action (**Clear flag**, `POST /cis/{id}/attributes/{name}/clear-flag`, audited), not by time.
- **A change of deciding source is not a change.** Detection runs on each source's own value, so the definitive source going silent, `silent = "next"` falling to a source that names a port or VLAN differently, or the definitive source returning, flips the merged value without raising a `move` or writing a history row for it. A history row is written when a source's value changes, and a merged-value flip caused by the deciding source changing is shown as a fallback badge only.
- **Planned changes** (a person or agent asks for one) are `requested`; an approver moves them to `approved`; they become `done` when a source later reports the expected end state (verified) or when an operator closes them. An approved plan not verified after `plan_expiry_days` (default 30) closes as `rejected` with reason `expired`.
- A detected `requested` change whose condition no longer holds before anyone decided it closes as `rejected` with reason `reverted` (shown as "Withdrawn").
- **Detected kinds**, all after the 24 h learning period, only from class 1–3 presence sources or the catalog's *Detect* column, debounced (`detect_settle_secs`, default 600, and two consecutive batches), one open record per CI and attribute (it updates rather than duplicates):
  - `add`: a new non-randomised device seen by a class 1–3 source. Imports, mDNS-only and `queries`-only records never raise one (they become `unconfirmed` CIs).
  - `move`: a wired `port`, `vlan` or `network` change on an interface, or an infrastructure device's network change. AP roaming and address changes never do.
  - `change`: `serial`, `model` or `role` of an infrastructure device (a swap), a network's CIDR, a merge proposal (R5), and a conflict a person raised.
  - `delete`: a device whose registry row has a class 1–3 presence source, `days_seen` of at least 3 and a CI-level `last_seen` older than `disappear_after_days` (default 14). These come from the registry (see Source records), so the 7-day expiry of a derived record does not defeat the 14-day threshold.
  - Open detected records are capped at 200; past the cap new ones are counted, not stored, and the status says so.
- **Who approves.** Viewers cannot. Operators approve detected changes and planned changes on CIs not marked `protected`; admins approve everything and set `protected` and the precedence rules. Agents never approve; with the scope `ops:cmdb` they may *create* a `requested` record (that is their plan), at most **50 open agent-made records per token** and 10 creations an hour per token, past which the API answers 429 with the count. `protected` and the precedence rules are admin-only; an operator's attempt to set or change `protected`, or a manual value on a protected CI's protected attribute, is refused with 403. `[cmdb] require_second_approver` (default false; a home is often one admin) forbids approving your own request.
- **Alerts.** A record `requested` for `unconfirmed_alert_hours` (default 24) raises one event through the existing sinks (ADR-984) with `source = "cmdb"` and sets the metric `telltale_cmdb_macd_open{state="requested"}`; ADR-102 applies.
- **History and audit.** Every transition is a row (who, when, comment) and a `cmdb.macd.*` audit entry. Each CI keeps the history of its merged values for the catalog rows marked in the History column (attribute, old, new, deciding source, time); sets, derived values, `ap`, `addresses` and `last_seen` are never recorded.

## Limits, failover and backups

- **CI cap (16,384).** A registry row alone is not authored data. A CI is *authored* only when it has a manual value, a manual link, unlink, pin or override, or an open MACD record. At the cap the oldest *unconfirmed or derived-only* CIs (no present record, nothing authored) are evicted first; when everything left is authored, a new CI is refused and counted (`telltale_cmdb_dropped_total{kind="ci"}`) and the status says so. A randomised MAC makes two CIs, so this is expected to run.
- **Failover.** The designated node is the one `[discovery] node` names, else the primary or standalone node. With **no node named**, a lost designated node fails over and the new one has the replicated authored data. With a **named node down**, nothing runs (ADR-930): there is no failover, CMDB writes answer 503 with a hint and reads are unavailable until an admin clears or changes the name. DNS is unaffected either way.
- **Backups.** Authored CMDB data (the registry with MACs and names, manual values, links, MACD, history) is identifying, and this reverses DSC-008's rule for it. A backup includes it only with a passphrase; asking for it in an unencrypted backup is a validation error, and an unencrypted backup omits it. Derived data is never in a backup.
- **Agents.** Plan tools never apply: applying a CMDB plan is a human action in the UI, and `apply_plan` refuses a CMDB plan presented with an agent token (ADR-903 §5's rule).

## UI (every item has a control, a help topic and a Playwright test)

- **Devices → CMDB** (beside Clients): a CI list with type filter, search by name, MAC, address or serial, source chips, and badges (unconfirmed, conflict, fallback, open MACD).
- **CI page:** header with merged name and type; **Attributes** (merged value, deciding source chip, pin and override controls, manual value editor); **Sources** side by side as columns, one per linked record, with differing values highlighted; **Relations**; **History**; **MACD** for this CI; the **Policy** panel (T31.5, from T24.30).
- **Conflicts** page; **Changes** page (the MACD inbox: filter by state and kind, approve, reject, bulk approve of detected `add` with a count and preview); **Settings → CMDB** (enable, thresholds, the precedence table ordered per type and attribute, scoped rules).
- Link, unlink, merge and split work from the CI page and show a preview of the records that would move. The CI page also has **Clear flag** on a rejected change, a **port alias** editor on a device's ports, and the mirrored read-only T25.18 link line on a device's groups.

## Test plan

Names, with the tasks holding the acceptance criteria: `dsc_901_*` scope and containment (no CMDB value reaches policy; nothing writes to a device); `dsc_902_*` model, caps and normalisation; `dsc_903_*` each reconciliation rule per level, ambiguity, level disagreement, port keys and aliases, unlink pins, merge and split, alias redirect, MAC rotation (a new MAC is a new interface); `dsc_904_*` precedence resolution order, freshness, silent definitive (`next` and `hold`), conflicts; `dsc_905_*` MACD state machine, detection and debounce, learning period, caps, approval rights, expiry; `dsc_906_*` store, retention, replication and failover, backups, privacy levels; `dsc_907_*` API, scopes, MCP, plan-only writes, federation `missingNodes`. Playwright files `cmdb-*.spec.ts` for the pages. A property test: reconciling the same batches in any order yields the same links.

## Owner decisions for the milestone

**Owner decisions (2026-11-19, asked one by one through AskUserQuestion):** the design's recommendation was taken for questions 1 to 13, 15 and 16 (all six CI types with `node`, `service` and `upstream` read-only; manual first, then ADR-910's order; wired port, VLAN and network moves only, `delete` after 14 days with at least 3 days seen; operators approve detected changes and unprotected plans, admins the rest, agents never, one approver; done only records; a manual CMDB name never names a device in DNS; like discovery for privacy; MACD 365 days (cap 10,000) and value history 90 days (cap 20,000); authored data replicates and a backup carries it only with a passphrase; fall back with a badge when the definitive source is silent, `hold` per rule; the unconfirmed alert after 24 h; hostname plus network proposes only; the `[[group_link]]` keeps its direction and the CMDB mirrors it read-only; Kubernetes CIs only when the feature is on; the CMDB runs on the node `[discovery]` designates). **Question 14 departs from the recommendation: the Pi-hole importer is not a CMDB source** (no `pihole_import` source kind; imported Pi-hole clients reach the CMDB only through the configuration they become, as the `config` source).

Asked together at the start of M31 with an "accept all recommendations" option. The orchestrator asks; this design recommends.

1. **v1 CI types.** Recommended: all six, with `node`, `service` and `upstream` read-only from configuration and the cluster. Alternative: devices, interfaces and networks first.
2. **Default precedence.** Recommended: the table above (manual first; ADR-910's name ranks for `device.name`; ADR-910's classes for addresses).
3. **Detection scope.** Recommended: wired port, VLAN and network moves only; `delete` after 14 days and at least 3 days seen. Alternative: include AP changes (noisy).
4. **Approval.** Recommended: operators approve detected changes and unprotected plans, admins approve the rest, agents never, no second approver by default.
5. **What "done" does.** Recommended: nothing on the network and no configuration change; it records. A MACD may not apply a configuration plan in v1.
6. **Manual values and DNS.** Recommended: a manual CMDB name never names a device in DNS.
7. **Privacy.** Recommended: like discovery, `[cmdb] enabled = true` is a validation error at privacy level 2 and above, and names are hashed at level 1. Alternative: a Proposed amendment to ADR-102.
8. **Retention.** Recommended: MACD records 365 days (cap 10,000), value history 90 days (cap 20,000 rows), source records follow ADR-924 and the import retention.
9. **Authored data, failover and backups.** Recommended: manual values, links, overrides, the CI registry (MACs and names), MACD and history replicate to full members as a hot standby; source records are node-local, rebuilt after a failover with a 24 h learning period. **This reverses DSC-008's rule that inventory data stays out of backups for the CMDB's authored data**: it is identifying (MACs, names, owners). Therefore a backup includes CMDB data only with a passphrase (an unencrypted backup omits it; asking for it without a passphrase is a validation error). Failover happens only when no node is named in `[discovery] node`: with a named node down nothing runs, the CMDB answers 503 until the name is cleared or changed, and DNS is unaffected.
10. **Definitive silent.** Recommended: fall back to the next fresh source with a visible badge (`next`); `hold` is a per-rule option.
11. **Unconfirmed alert.** Recommended: 24 h, through the existing event sinks, off at privacy level 1 and above like the new-device alert.
12. **Hostname plus network.** Recommended: propose only, never auto-link.
13. **T25.18 and the CMDB.** Recommended: the `[[group_link]]` keeps its direction (`unifi_definitive`, `telltale_definitive`, `two_way`) for good; the CMDB mirrors it read-only and never drives the sync, so ADR-998 §14's "the direction is read from CMDB precedence" is amended by the T25.18 owner to "the CMDB displays the link". `member_of` is a set with the sources `config` and `unifi:<router>`. Alternative: the CMDB becomes authoritative for the direction (rejected: it would let CMDB data steer a write to the gateway and reach filtering, against DSC-901).
14. **Pi-hole importer.** Recommended: a one-shot `pihole_import` source (client names and group comments) at the lowest rank, fresh for 30 days. **Owner, 2026-11-19: no.** The importer is not a CMDB source; what it imports reaches the CMDB only as configuration (`config`).
15. **Kubernetes.** Recommended: workloads and Services become `device` (kind workload) and `service` CIs only when the Kubernetes feature is on. Alternative: leave Kubernetes out of v1.
16. **Where the CMDB runs.** Recommended: on the node `[discovery]` designates (the inventory is in process there), even when discovery itself is off. The T25.18 sync runs on the primary; the two can differ when a node is named.
