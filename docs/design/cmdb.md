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
| T25.18 UniFi sync design (the branch had no commits when this was drafted; read from its task and the owner's note) | "A definitive side per linked group" is one case of the CMDB's per-attribute precedence: a precedence rule scoped to a group (`scope = group:<id>`) whose sources are `[config, unifi]` or `[unifi, config]`. T25.18 should store its choice in that shape so T31.3 can adopt it without changing its meaning (owner question 13). |

## Model

### CI types

| Type | Is | Created by | Key (match) |
|---|---|---|---|
| `device` | A physical or virtual thing: laptop, phone, camera, switch, AP, printer, server, workload | the first record that cannot be attached to a device | serial, Home Assistant device id, manual link, proposed hostname+network |
| `interface` | One network interface. **A MAC is an interface, not a device** | every MAC-keyed record | MAC |
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
| `attached_to` | interface → interface (a switch or AP port) | SNMP bridge and LLDP, UniFi `stat/device` |
| `member_of` | device → group (policy) | read from the configuration through the T24.30 resolver; read-only |
| `runs_on` | service → device or node | config, cluster, Kubernetes |
| `uses_upstream` | node or group → upstream | config; read-only |

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

### Attributes and the catalog

An attribute has a type, a cardinality (`single`: one winner; `set`: the union, never in conflict), the sources that can report it, whether a manual value is allowed, a default precedence and whether a change is **detected** (raises a MACD). The catalog is code (one table), shown in the UI.

| CI type | Attribute | Card. | Default precedence (first wins) | Detect |
|---|---|---|---|---|
| device | `name` | single | manual, config client name, Home Assistant user name, router alias (in `[[router]]` order), Home Assistant integration name, mdns, SNMP sysName, import host name (ADR-910 ranks) | no |
| device | `role` (router, switch, ap, printer, phone, ...) | single | manual, SNMP sysObjectID and capabilities, UniFi device type, `queries` class, import | change, infrastructure only |
| device | `vendor`, `model` | single | manual, UniFi, SNMP, Home Assistant, OUI | change, infrastructure only (a swap) |
| device | `serial`, `firmware`, `os` | single | manual, SNMP, UniFi, Home Assistant, import | `serial`: yes |
| device | `location` | single | manual, Home Assistant area, SNMP sysLocation | no |
| device | `owner`, `criticality`, `notes`, `tags`, `protected` | single / set | manual only | no |
| device | `last_seen`, `present` | derived | any presence source | disappearance only |
| interface | `mac` | single | the key | no |
| interface | `addresses` | set | ADR-910 classes: routers and reservations, neighbour table, SNMP ARP, import, history | no (DHCP churn) |
| interface | `vlan`, `network` | single | UniFi, SNMP Q-BRIDGE, address inside a CIDR | yes (wired and infrastructure) |
| interface | `port` (`attached_to`) | single | SNMP bridge, UniFi | yes (wired; never an AP-connected client) |
| interface | `ap` | single | UniFi | no (roaming is not a change) |
| network | `name`, `cidr`, `vlan_id`, `gateway` | single | UniFi, OPNsense, config subnet, manual | yes |
| node | `name`, `address`, `role`, `version` | single | cluster | no |
| service | `name`, `protocol`, `port`, `runs_on` | single | config, cluster, Kubernetes, manual | no |
| upstream | `name`, `address`, `protocol` | single | config | no |

`manual` is first by default for every attribute that allows it: a person's statement beats a machine's. The owner can change any row in the UI.

## Reconciliation

Rules run in order on every ingested batch. The first rule that finds exactly one CI links the record; a rule that finds two or more does not guess.

1. **R1 Manual.** A manual link or unlink is a pin and always wins. An unlink writes a "never match" pin for that record and rule, so it is not re-linked on the next batch.
2. **R2 MAC.** The normalised MAC (the same code as the inventory's merge) selects the interface CI. A locally administered (randomised) MAC matches but never raises an `add` MACD (ADR-910).
3. **R3 Serial.** An SNMP entPhysicalSerialNum, a UniFi device serial or a Home Assistant device serial selects the device CI and joins interfaces to it.
4. **R4 Router client id.** A source's own stable key, scoped to its instance (a UniFi client `_id`), re-finds the same record after its MAC or address changed.
5. **R5 Hostname plus network.** A non-generic host name and the same network, with one candidate and no MAC conflict, **proposes** a link. It is never applied alone; it appears as a MACD of kind `change` ("merge these?") for a person to confirm (owner question 12).

A record with no key (an IP-only import row, an mDNS answer) attaches through a class 1–3 address binding as in ADR-923, else becomes its own `unconfirmed` device CI. Records that match two CIs are left unlinked and raise a merge proposal. A manual **merge** moves the records and leaves an alias; a manual **split** moves chosen records to a new CI and pins them.

## Definitive sources

For each CI and attribute the **merged value** is the value of the first source in the precedence list that has a fresh value. Resolution order:

1. A per-CI **attribute pin**: a source or a manual value fixed for this CI and attribute.
2. A per-CI **override list** (a source order for the whole CI).
3. A **scoped rule** (`type`, `attribute`, `scope = group:<id> | network:<id>`).
4. The **type and attribute rule** (the owner's setting, `[[cmdb.precedence]]`).
5. The built-in default in the table above.

**Freshness** per source kind: two poll intervals for polled sources (ADR-924: neighbour 2 min, routers and mDNS 15 min), the retention window for imports (30 days) and the Pi-hole import, never stale for `config`, `cluster` and `manual`.

**When the definitive source goes silent:** the default is `silent = "next"`: the value falls to the next fresh source and shows a **fallback** badge with the definitive source's last value and its age. The alternative `silent = "hold"` keeps the last value, marked stale, for `hold_days` (default 7) and then falls back. A source instance silent for more than 24 hours raises one `source_silent` finding (not a MACD) per instance.

**Conflicts.** For a `single` attribute, a conflict exists when at least one fresh, non-definitive source holds a different value after normalisation (case-folded names, canonical MACs, normalised CIDRs). The conflict view lists CI, attribute, the definitive value and source, the differing values and sources, and for how long. Actions: **Accept** (pin that source for this CI and attribute), **Keep** (mute, with an optional expiry), **Raise a MACD** (a `change` asking someone to fix it at the source). Sets never conflict.

## MACD

A MACD record: `id`, `kind` (`move`, `add`, `change`, `delete`), `ci`, `attribute` (when it applies), `from` and `to` values, `origin` (`detected:<source>`, `user:<name>`, `agent:<token> (owner: <user>)`), `observed` (true when it already happened), `state`, `reason` (required for agents, AGT-005), timestamps, approver and comment, and a closure reason.

States: `requested`, `approved`, `done`, `rejected`.

```
requested -> approved -> done
    |           |
    +-> rejected <+        (closure reason: rejected, expired, reverted, superseded)
```

- **Observed changes** (detected from sources) are born `requested`, and **approving one moves it straight to `done`** (it already happened; approval means "expected"). Rejecting marks the change *unexpected* and leaves it flagged on the CI.
- **Planned changes** (a person or agent asks for one) are `requested`; an approver moves them to `approved`; they become `done` when a source later reports the expected end state (verified) or when an operator closes them. An approved plan not verified after `plan_expiry_days` (default 30) closes as `rejected` with reason `expired`.
- A detected `requested` change whose condition no longer holds before anyone decided it closes as `rejected` with reason `reverted` (shown as "Withdrawn").
- **Detected kinds**, all after the 24 h learning period, only from class 1–3 presence sources or the catalog's *Detect* column, debounced (`detect_settle_secs`, default 600, and two consecutive batches), one open record per CI and attribute (it updates rather than duplicates):
  - `add`: a new non-randomised device seen by a class 1–3 source. Imports, mDNS-only and `queries`-only records never raise one (they become `unconfirmed` CIs).
  - `move`: a wired `port`, `vlan` or `network` change on an interface, or an infrastructure device's network change. AP roaming and address changes never do.
  - `change`: `serial`, `model` or `role` of an infrastructure device (a swap), a network's CIDR, a merge proposal (R5), and a conflict a person raised.
  - `delete`: a device with a class 1–3 presence source, seen on at least 3 distinct days, unseen by every source for `disappear_after_days` (default 14).
  - Open detected records are capped at 200; past the cap new ones are counted, not stored, and the status says so.
- **Who approves.** Viewers cannot. Operators approve detected changes and planned changes on CIs not marked `protected`; admins approve everything and set `protected` and the precedence rules. Agents never approve; with the scope `ops:cmdb` they may *create* a `requested` record (that is their plan). `[cmdb] require_second_approver` (default false; a home is often one admin) forbids approving your own request.
- **Alerts.** A record `requested` for `unconfirmed_alert_hours` (default 24) raises one event through the existing sinks (ADR-984) with `source = "cmdb"` and sets the metric `telltale_cmdb_macd_open{state="requested"}`; ADR-102 applies.
- **History and audit.** Every transition is a row (who, when, comment) and a `cmdb.macd.*` audit entry. Each CI keeps the history of its merged values (attribute, old, new, deciding source, time).

## UI (every item has a control, a help topic and a Playwright test)

- **Devices → CMDB** (beside Clients): a CI list with type filter, search by name, MAC, address or serial, source chips, and badges (unconfirmed, conflict, fallback, open MACD).
- **CI page:** header with merged name and type; **Attributes** (merged value, deciding source chip, pin and override controls, manual value editor); **Sources** side by side as columns, one per linked record, with differing values highlighted; **Relations**; **History**; **MACD** for this CI; the **Policy** panel (T31.5, from T24.30).
- **Conflicts** page; **Changes** page (the MACD inbox: filter by state and kind, approve, reject, bulk approve of detected `add` with a count and preview); **Settings → CMDB** (enable, thresholds, the precedence table ordered per type and attribute, scoped rules).
- Link, unlink, merge and split work from the CI page and show a preview of the records that would move.

## Test plan

Names, with the tasks holding the acceptance criteria: `dsc_901_*` scope and containment (no CMDB value reaches policy; nothing writes to a device); `dsc_902_*` model, caps and normalisation; `dsc_903_*` each reconciliation rule, ambiguity, unlink pins, merge and split, alias redirect, MAC rotation; `dsc_904_*` precedence resolution order, freshness, silent definitive (`next` and `hold`), conflicts; `dsc_905_*` MACD state machine, detection and debounce, learning period, caps, approval rights, expiry; `dsc_906_*` store, retention, replication and failover, backups, privacy levels; `dsc_907_*` API, scopes, MCP, plan-only writes, federation `missingNodes`. Playwright files `cmdb-*.spec.ts` for the pages. A property test: reconciling the same batches in any order yields the same links.

## Owner decisions for the milestone

Asked together at the start of M31 with an "accept all recommendations" option. The orchestrator asks; this design recommends.

1. **v1 CI types.** Recommended: all six, with `node`, `service` and `upstream` read-only from configuration and the cluster. Alternative: devices, interfaces and networks first.
2. **Default precedence.** Recommended: the table above (manual first; ADR-910's name ranks for `device.name`; ADR-910's classes for addresses).
3. **Detection scope.** Recommended: wired port, VLAN and network moves only; `delete` after 14 days and at least 3 days seen. Alternative: include AP changes (noisy).
4. **Approval.** Recommended: operators approve detected changes and unprotected plans, admins approve the rest, agents never, no second approver by default.
5. **What "done" does.** Recommended: nothing on the network and no configuration change; it records. A MACD may not apply a configuration plan in v1.
6. **Manual values and DNS.** Recommended: a manual CMDB name never names a device in DNS.
7. **Privacy.** Recommended: like discovery, `[cmdb] enabled = true` is a validation error at privacy level 2 and above, and names are hashed at level 1. Alternative: a Proposed amendment to ADR-102.
8. **Retention.** Recommended: MACD records 365 days (cap 10,000), value history 90 days (cap 20,000 rows), source records follow ADR-924 and the import retention.
9. **Authored data and failover.** Recommended: manual values, links, overrides, the CI registry, MACD and history replicate to full members as a hot standby and go into backups; source records are node-local, rebuilt after a failover with a 24 h learning period.
10. **Definitive silent.** Recommended: fall back to the next fresh source with a visible badge (`next`); `hold` is a per-rule option.
11. **Unconfirmed alert.** Recommended: 24 h, through the existing event sinks, off at privacy level 1 and above like the new-device alert.
12. **Hostname plus network.** Recommended: propose only, never auto-link.
13. **T25.18 and the CMDB.** Recommended: T25.18 stores a linked group's definitive side in the shape of a scoped precedence rule so T31.3 adopts it; if T25.18 ships first it keeps its own setting and T31.3 reads it as a scoped rule.
14. **Pi-hole importer.** Recommended: a one-shot `pihole_import` source (client names and group comments) at the lowest rank, fresh for 30 days.
15. **Kubernetes.** Recommended: workloads and Services become `device` (kind workload) and `service` CIs only when the Kubernetes feature is on. Alternative: leave Kubernetes out of v1.
16. **Where the CMDB runs.** Recommended: on the node `[discovery]` designates (the inventory is in process there), even when discovery itself is off.
