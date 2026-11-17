# Network inventory (M25) — design

Status: design for M25 (DSC-001..015; ADR-907..913, 923..925). The model and merge are built (T25.1). The SNMP poller, imports, the API, the UI and the MCP tools come in later tasks.

## What it is

One list of the devices on the owner's networks, keyed by MAC, built from what the network already knows and from scans the owner ran and uploaded. It tells the owner what a device is, where it is, and when it was last seen. It is for looking, not for controlling.

## What it is not

- **No probing.** TelltaleDNS never sweeps a range, never sends ICMP, TCP connect probes, ARP or NDP solicitations, or mDNS queries, and never schedules a scan (ADR-907). Scans come from the owner's own tools and are uploaded.
- **Not DNS policy.** Inventory data never names a device in DNS (except the opt-in address rule, DSC-012, which supplies an address and never a name), never feeds client matching (`telltale_policy::Neighbors`), and never changes `identify`'s seen chain (ADR-910).
- **Off by default.** `[discovery]` (T25.2) switches it on. It runs on one designated node (`spec/12` §11).

## Sources

| Source | Class | Gives |
|---|---|---|
| UniFi clients and reservations, OPNsense leases, `[[router]]` answers | 1 | MAC, IPv4, name |
| Neighbour table (kernel), filtered | 2 | MAC, IPv4 (REACHABLE, STALE, DELAY, PROBE; configured subnets; container and overlay interfaces skipped) |
| Home Assistant trackers and names | claim (no class, ADR-923) | MAC, name (a person's name ranks above an integration's); the address is a claim |
| Passive mDNS | claim (no class, ADR-923) | IPv4, name (IP-only when no MAC; attached to the MAC entry that holds the address otherwise) |
| SNMP ARP (T25.6) | 3 | MAC, IPv4 |
| SNMP identity (T25.7) | — | sysName and printer names (no address) |
| Imported scans (T25.11) | 4 | MAC or IPv4, host name, open TCP ports |
| UniFi `stat/alluser` `last_ip` (T25.10) | 5 | IPv4, history only |

A MAC's current address is the best class, then the newest. Classes 1–3 are current bindings; SNMP may only poll a class 1–3 address (ADR-907). Home Assistant and mDNS addresses are claims, never current, so they never make an address an SNMP destination.

## The merge

- **Keyed by MAC.** Up to four address bindings per entry, the first is current, the rest are shown as aliases.
- **IP-only entries** (`ip:<addr>`) hold results with no MAC, up to 1,024. When a MAC arrives for the address, the entry merges into the MAC entry.
- **Same address, two MACs.** The newest class 1–3 claim wins the address. Both entries are flagged `ip_conflict`. An import or history claim never takes a class 1–3 binding.
- **Randomised MACs** (the locally administered bit) are flagged and raise no `new_device` alert.
- **Names** are ranked: the configured client name, Home Assistant's user name, the router alias, a Home Assistant integration's name, mDNS, SNMP sysName or printer name, then an import's host name. The last two are labelled with their source. Device-supplied strings are cut and stripped of control characters (DSC-015).
- **Learning period.** For 24 hours after the first enable, and after an empty start, no `new_device` alert is raised. A device first seen in that time is treated as known.

## Limits and retention

| Item | Limit | Rule |
|---|---|---|
| MAC entries | 4,096 | Least recently seen goes first |
| IP-only entries | 1,024 | Least recently seen goes first |
| Import rows | 8,192 in total | Oldest import goes first; 16 imports at most; 4,096 rows per import |
| Bindings per entry | 4 | Worst class and oldest go first |
| Retention | 7 days | An entry with no address or import, unseen for 7 days, is removed |
| Import retention | 30 days | An import past 30 days is removed with its rows |
| Source expiry | 2 poll intervals | A source that stops reporting an address drops it (neighbour 2 min, routers and mDNS 15 min) |

Caps and retention are fixed in T25.1. `[discovery.import] retention_days` makes the import retention a setting in T25.2.

## Storage

`<data_dir>/inventory.json`:

- written atomically (a 0600 temporary file, synced, then renamed);
- at most every 15 minutes, and every minute after an import or a `public` pass;
- left out of backups and support packages (support packages need `--include-inventory`, which pseudonymises, ADR-156);
- not replicated as configuration.

A missing or unreadable file starts an empty inventory with a new learning period.

## Threads and failure

The merge runs on its own OS thread, `telltale-inventory`, with a current-thread runtime and idle priority. It never runs on the query runtime, and DNS never waits for it (DSC-002, CLU-004). A failed source logs once and keeps its last data. Nothing here blocks or moves a device.

## Privacy

At privacy level 1 and above, names are hashed like client names (ADR-102). At level 2 and above `[discovery] enabled = true` is refused (T25.2), because nothing that identifies a client may be kept.

## Where the data goes

- Clients → Discovered (T25.12) reads `GET /api/v1/discovery/devices`, keyed by inventory ID, with source chips, ports, VLAN, vendor, identity and findings.
- Networks utilisation counts inventory addresses on the designated node (T25.15).
- The MCP tools `get_discovery_status` and `list_discovered_devices` (T25.13).

The owner's walkthrough and help are in T25.14. The decisions are in `spec/11` ADR-907 to ADR-913 and ADR-923 to ADR-925.
