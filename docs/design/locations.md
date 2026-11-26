# Locations and DNS-provider integrations (T36.10) — design

Status: design only, for #110 and T36.10 (sub-tasks T36.10a0 to T36.10f in `spec/10`). It covers the self-hosted node only. The hosted service's side (managed names, the broker-seen address, the cloud zone) is in `docs/design/hosted.md` and is not designed here. The decisions already taken are ADR-1081 (locations), ADR-1082 (certificates), ADR-1083 (dynamic DNS), ADR-1084 (the provider table) and ADR-1085 (the ACME crate), with requirements DSC-908 to DSC-915, CLD-903 and CLD-904. This note grounds them in the code as it is on `main`, names the places where the code and those records disagree, and proposes the rest. The owner decided the eight questions this note raised on 2026-11-26; they are listed in the decisions section at the end and recorded in ADR-1095 (location names; amends ADR-1081), ADR-1096 (what a location's integrations never hand out; amends ADR-1082 and ADR-1083) and a dated amendment to ADR-1084 (the provider set). Points the owner has not decided are listed there as still open.

## 1. What exists today

### Local records and device names

- **Answer order.** `Pipeline::local_answer` (`crates/wrendns/src/pipeline.rs`) answers configured local data first (`[[record]]`, hosts files, `crates/wrendns-policy/src/local.rs` `LocalData`), then the authoritative zones the client's groups see, then the device-name table. All of this runs **before the cache and the upstreams** (DNS-010), so a local answer is never cached and a name the node answers never leaves it.
- **Device names (DNS-023, ADR-901).** `crates/wrendns/src/device_dns.rs` builds a `LocalData` every 10 s, off the query path, from named `[[client]]` entries with one address, the routers' DHCP clients (`[[router]]`, this node's and the peers', CLU-002), Home Assistant, and, with `device_mdns`, mDNS names. Names are `<label>.<[local] device_domain>` (`crates/wrendns-config/src/schema.rs` `LocalConfig`), with a PTR per address and AAAA from the router-reported IPv6 addresses (ADR-983). The pipeline loads the table with one lock-free `ArcSwap` load.
- **Collisions today (ADR-901).** When two devices make the same label, one keeps it, ranked named device, then router or Home Assistant name, then mDNS, then the lowest address; the others get no A and no PTR. Offline router clients publish nothing (ADR-166). `wpad`, `isatap` and `localhost` are never device labels.
- **Split horizon today.** There is one form of it: an authoritative zone may list `groups`, and only clients in those groups see it (DNS-018, `schema.rs`, "Only these groups see this zone"). There is no split horizon by network or by location, and the device-name table is one table for every client.
- **Private reverse names.** With `[special] private_ptr_nxdomain`, reverse names in private space that nothing local answers get NXDOMAIN locally (RFC 6303, `crates/wrendns-policy/src/special.rs`).

### Networks, router reads and the CMDB

- **Router networks.** `routers::unifi_networks` (`crates/wrendns/src/routers.rs`) reads UniFi's `rest/networkconf`: each LAN network's subnet, VLAN ID (1 to 4094, when enabled), gateway and DHCP range. **WAN and VPN networks are skipped**, so no WAN address is read anywhere in the tree today.
- **Router leases.** A lease (`crates/wrendns/src/devices.rs` `Lease`) carries MAC, IPv4, hostname, the router that named it, an offline flag and up to four IPv6 addresses. It carries no VLAN and no network name; a device's network is found by its address.
- **The node's own networks.** `crates/wrendns/src/own_networks.rs` lists the networks a node is directly on (tagged VLAN interfaces), for the Networks page.
- **The CMDB (DSC-901 to DSC-907).** Network CIs are keyed by CIDR and VLAN (`crates/wrendns/src/cmdb/adapters.rs` `from_networks`, key `network:<cidr>|<vlan>`), from router reads, this node's interfaces and `[[discovery.subnet]]`. A device keeps one CI across a MAC or address change by the reconciliation rules (DSC-903). **Containment (DSC-901): CMDB data never reaches DNS answers, client matching, filtering or device names.** The CMDB runs on the node `[discovery]` designates; its authored data replicates (DSC-906, `crates/wrendns/src/cmdb/replication.rs`).

### Secrets

- `crates/wrendns/src/secrets.rs` and `secrets/` (OPS-014, API-014, ADR-903): one 32-byte node key, an encrypted SQLite table, values printed `<redacted>` and wiped on drop. `secrets/credential.rs` is the one place a credential is read (inline, `*_file` or stored `*_ref`; the files win). Names are `^[a-z0-9][a-z0-9._-]{0,62}$` (`crates/wrendns-config/src/secret_refs.rs`).
- **Limits that matter here:** at most 128 stored secrets (`store.rs` `MAX_SECRETS`), at most 8 KiB per value (`value.rs` `MAX_VALUE`), and the only kind accepted is `text`, one line; `pem` is reserved and refused (`value.rs` `Kind::parse`).
- **Replication (CLU-015, ADR-917).** `secrets/sync.rs`: the primary serves its rows over the mTLS cluster channel only, a full replica pulls when the heartbeat's head differs and re-encrypts under its own key. Nothing here gates DNS (CLU-004).
- Support bundles redact by a classification table (`crates/wrendns-support/src/classify.rs`; `local.device_domain` is `Scan`).

### Guarded changes and audit

- **Guarded changes (API-902, ADR-914, ADR-956).** `crates/wrendns/src/guarded/` with the registry in `crates/wrendns-config/src/guarded.rs`: a preview bound to the change, a typed phrase, sign-in recency, a confirmation window, audit and alert, a per-node lock. Rows include `listen`, `api-tls`, `secrets-key` and the cluster rows. A certificate change on the API listener is therefore already a guarded change.
- **Audit (API-006, ADR-033).** `crates/wrendns-store/src/state/audit.rs`: append-only and hash-chained (BLAKE3), SQLite triggers refuse UPDATE and DELETE, `detail` never holds secrets, `reason` is required of agents (AGT-005).
- **Agents.** MCP read tools and `plan_*` tools that only plan; a human applies (`crates/wrendns-api/src/mcp.rs`).

### Certificates and TLS

- **DoT and DoH.** `crates/wrendns-net/src/tls.rs`: PEM cert and key from files, re-read when either file changes, new handshakes get the new certificate with no restart, a failed reload keeps the previous one. **A wildcard name on the certificate turns the SNI label into a client ID** (FLT-006): with `*.dns.example.net`, SNI `kids-tablet.dns.example.net` is client `kids-tablet`.
- **API listener.** `crates/wrendns/src/api_tls.rs` (API-003, ADR-149): the operator's PEM files, re-read within 10 s, or a self-signed certificate kept in `<data_dir>/api-tls/`.
- **Expiry.** The probes degrade health when a listener certificate expires within `cert_warn_days`.
- **ACME: none.** There is no ACME client in the tree. The crates that exist and help: `rcgen` (keys and CSRs), `ring` (ECDSA, SHA-256, HMAC), `rustls` and `hyper` clients with `webpki-roots` (`crates/wrendns-filter/src/fetch/http.rs`). The cluster PKI (`crates/wrendns-cluster/src/pki.rs`) issues node certificates for the cluster channel only.

### Cluster replication of configuration

- `crates/wrendns/src/replication.rs` and `crates/wrendns-config/src/shared.rs` (CLU-003, CLU-006, CLU-010, ADR-047): the primary publishes a signed manifest of its shared configuration; replicas fetch, validate the merged result and reload. Sections at their defaults are not sent, so an older replica never sees a section nobody uses.
- **An older replica refuses a shared section it does not know** ("the primary sent a setting this version doesn't know; upgrade this node", `with_shared`) and keeps serving its last applied version. `Config` has `deny_unknown_fields`.
- API-made entries live in `state.db` as managed kinds (`crates/wrendns/src/managed.rs`, `settings_kinds.rs`); the files win field by field (ADR-040, ADR-914).

### Where the code and the records disagree

These are the findings that change the design. Each is resolved below, decided by the owner (decision N in the decisions section), or listed there as still open.

1. **DSC-908 said a node that predates `[[location]]` reads it as absent.** It cannot: a released replica refuses an unknown shared section and holds its last version (`shared.rs`). Decided (decision 5): the first location is gated on every member's build (§2.6), and DSC-908 is reworded.
2. **ADR-1081 point 3 and DSC-910 put the location and its manual override on the CMDB record**, but DSC-901 forbids CMDB data reaching device names. The location comes from the address and the configured networks without the CMDB (§2.3). Decided (decision 1): the override is a `location` field on `[[client]]`, DSC-901 stays, and DSC-910 is reworded.
3. **ADR-1081 point 4 (neither colliding name answers) differed from ADR-901 (the best-ranked device keeps it).** Decided (decision 3): ADR-901's ranking everywhere, every collision listed on the Locations page; this replaces ADR-1081 point 4.
4. **ADR-1083 assumes the router read stores a WAN address in the CMDB.** It does not; WAN networks are skipped. T36.10e must add a WAN read (§4.6). Still open: the amendment of ADR-1083 and the rewording of DSC-915.
5. **DSC-912 asks for the answer to be keyed by location in the cache.** Local answers are not cached (they are answered before the cache), so no cache change is needed; the location test sits in the local-answer step. Still open: the rewording of DSC-912 and ADR-1081 point 6.
6. **The secret store takes only one-line text up to 8 KiB.** A certificate chain and key need the reserved `pem` kind (§3.4). Decision 5 gates the first `pem` secret like the first location.

## 2. Locations

### 2.1 The Location object

A `[[location]]` table, shared (replicated with the cluster configuration), also editable as a managed kind through the API (the files win, ADR-040):

| Field | Type | Rules |
|---|---|---|
| `slug` | string | `^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`, unique in the cluster, not a reserved label (`wpad`, `isatap`, `localhost`, `_acme-challenge`), not equal to any device label in the same parent domain. It is the DNS label. |
| `label` | string | Display name, at most 64 characters, untrusted text (escaped in the UI). |
| `networks` | list | Each entry is a CIDR (IPv4 or IPv6) or `vlan:<id>` (1 to 4094). At least one. No CIDR may overlap another location's (a validation error naming both). |
| `nodes` | list of node names | The nodes that serve the location. Empty means every node. |
| `domain` | string, optional | The parent domain. Defaults to `[local] device_domain`. Lowercase, no trailing dot, at most 200 octets so composed names stay under 253. |
| `visibility` | `shared` or `private` | Default `shared` (today's behaviour: every client sees device names). |
| `certificate` | bool | Opt in to the `*.<slug>.<domain>` wildcard (§3). Default false. |
| `flat_names` | bool | Keep answering the old `<device>.<device_domain>` names for devices in this location (§2.5). Default true (decision 2). |
| `public_name` | table, optional | Dynamic DNS for the location's WAN address (§4.6): `name`, `provider`, `ttl`. |

Validation runs when the files load and on every API write; a refused table names the bad field and the last good configuration stays in force (DSC-908). The first location is also refused while a cluster member runs a build that does not know locations (§2.6, decision 5). A location with no `domain` while `device_domain` is unset is refused ("set `[local] device_domain` or the location's `domain`").

### 2.2 Networks and VLANs

- A CIDR maps straight to the location.
- A `vlan:<id>` entry is resolved to CIDRs from the router network reads (`routers::unifi_networks`, `Network.vlan`) and this node's own VLAN interfaces (`own_networks.rs`). These are router reads, not CMDB data, so DSC-901 holds. A VLAN that no read reports matches nothing; the Locations page shows it as "VLAN 30: no network reported", and health stays green.
- The resolved map (prefix to location) is rebuilt in the same 10 s task that rebuilds the device table (`device_dns::run`), never on the query path.
- Overlap between a CIDR and a VLAN's resolved CIDR in another location is reported on the page and the more specific prefix wins; equal prefixes are a conflict and neither applies until fixed.

### 2.3 A device's location, and moves

- **Derivation.** A device's location is the location whose networks contain its current IPv4 address (the address the device table already names it by). Its IPv6 addresses follow the IPv4 address's location, as AAAA records follow it today (ADR-983).
- **No CMDB read.** The derivation uses the configuration and the router reads only. The CMDB shows the location (a badge, grouping) and keeps the identity, but does not decide the name (DSC-901 stays as written).
- **Moves (DSC-910).** When a router reports the device at an address in another location, the next rebuild (within 10 s of the router read) composes the new name; the old name stops answering at the same moment. The CMDB keeps one CI because reconciliation keys on the MAC and the source's stable device key (DSC-903), not on the address. A move is shown as a MACD "move" record the CMDB already raises (DSC-905); nothing new is needed there.
- **Manual override (decision 1).** A device can be pinned to a location regardless of its address (a laptop that docks on a lab VLAN but belongs to Home). The override is a `location` field on the device's `[[client]]` entry, which the device table already reads; it names a location's slug, wins over the address until it is removed, and is an ordinary audited configuration write (through the API, with a reason). A `location` that names no configured location is a validation error. The CMDB shows the override but never sets it (DSC-901 stays).
- **Names stay labels.** The device label is the same label as today (`device_label`, the ranking of ADR-901). Only the suffix changes.

### 2.4 Naming and answering rules

- **Forward.** A device in a location answers as `<label>.<slug>.<domain>`. A device on no location's network keeps `<label>.<device_domain>` (DSC-909). With no `[[location]]` table, the code path and answers are today's, byte for byte (DSC-908, AC (4) of T36.10a).
- **Node names.** A node in a location's `nodes` also answers as `<node>.<slug>.<domain>` for its listener addresses, so the UI has a name under the location's wildcard.
- **Reverse.** Each address has one PTR, the forward name (DSC-909). A device with a flat alias (§2.5) still has only one PTR, the location name.
- **Shared.** A shared location's names answer to every client `[access]` allows, from one table.
- **Private (DSC-911, owner answer in ADR-1081).** A private location's names, and their PTRs, answer only to a client whose source address is in one of that location's networks. Built as one `LocalData` per private location plus one shared table; the query path matches the qname suffix against the private suffixes (a small sorted list in the snapshot), and only then looks up the client's address in the prefix table. No allocation, lock or I/O (DSC-912); `make bench-smoke` covers it.
- **What a non-member gets (decision 4).** The node owns each location's subtree `<slug>.<domain>` and answers NXDOMAIN locally (with the same SOA it uses for a zone's NXDOMAIN) for any name in it that is not a device, a node, or a published record of that location, whether the name is private or simply unknown. That way device names never reach an upstream resolver, and a private name looks exactly like an unknown one to an outsider.
- **Precedence.** Unchanged: `[[record]]`, hosts files and zones win over device names; a location name never overrides a configured record.
- **Not policy.** Locations decide which names exist and who sees them; they never change whether a query is blocked (ADR-1081 point 6). `explain` and the trace name the location whose table answered (DSC-912).

### 2.5 Conflicts and migration from one `device_domain`

- **Conflicts inside a location (decision 3).** ADR-901's ranking everywhere: a named device, then the router's (or Home Assistant's) name, then mDNS, then the lowest address keeps the name, and the others get no A and no PTR for it. Every collision is listed on the Locations page, so turning locations on never drops a name that answers today without showing it. This replaces ADR-1081 point 4.
- **Name clashes across forms.** A location slug equal to a device label under the same parent domain (`home` as a device and `home` as a location under `example.net`) is refused at validation; a device that later takes that label is a collision the location wins, reported.
- **Migration (decision 2).** Today a NAS is `nas.home.arpa`. With a `home` location and the default parent, it becomes `nas.home.home.arpa`. To avoid breaking bookmarks, scripts and SSH known-hosts:
  1. With `flat_names = true`, which is the default, the old name keeps answering (A and AAAA, no PTR) for devices in the location. The Locations page counts how many queries still use flat names per location over 7 days, so the operator can see when nobody does.
  2. When devices in two locations compose the same flat label (two locations' `nas` cannot both own `nas.home.arpa`), the flat name follows the same ADR-901 ranking as every other collision (decision 3 applies everywhere), and the collision is listed on the Locations page.
  3. A private location's flat names follow the private rule too, so they do not leak to other networks.
  4. Turning `flat_names` off is an ordinary audited write.
- An operator who wants `nas.home.example.net` without a middle label sets the location's `domain` to `example.net` and slug `home`; there is no slug-less form, which keeps one rule.

### 2.6 Replication and rolling upgrades

- `[[location]]` is a shared section. Because an older replica refuses unknown shared sections (§1, finding 1), the API and the file loader refuse the first location while any member's heartbeat reports a build that does not know the section, with "node X runs version Y, which does not know locations; upgrade it first". The same gate applies to the first `[[dns_provider]]` and the first secret of the `pem` kind. Decided (decision 5); DSC-908 is reworded.
- Locations are not node-local; `nodes` says which nodes serve a location, and each node reads its own membership from the shared table.

## 3. Certificates

### 3.1 What is issued

- **Shared names (ADR-1082).** The cluster's own names and, for each location with `certificate = true`, one certificate for `*.<slug>.<domain>` and `<slug>.<domain>`. One issuer node (the primary by default) orders them.
- **Per-node names.** Each node's `<node>.<domain>` is issued by that node with its own key, never replicated (ADR-1082 point 4).

### 3.2 Why wildcards only

A certificate for `nas.home.example.net` would put `nas` in the public certificate transparency logs, for ever, for anyone to search. A wildcard puts only the location label there. So the node never orders a certificate for a device name: the order builder accepts only names of the form `*.<slug>.<domain>`, `<slug>.<domain>`, the cluster's configured names and the node's own name, and refuses anything else with a reason. CT logs therefore show the parent domain, location slugs and node names, never device names.

### 3.3 The order, DNS-01 and renewal

1. The issuer creates (or loads) the ACME account key, an ECDSA P-256 key generated with `ring`.
2. It creates the order, and for each authorization writes the `_acme-challenge.<slug>.<domain>` TXT value through the location's provider (§4), or through the delegated name when the provider entry says `delegated_to`.
3. **Propagation check.** It queries the zone's authoritative servers directly, found by an NS lookup from the public root through the node's recursor or upstreams, not through its own local data (the node owns the location subtree locally and would answer itself). It waits until every authoritative server returns the value, up to 10 minutes, then tells the CA.
4. It finalizes with a CSR made by `rcgen`, with a fresh ECDSA P-256 key per certificate.
5. It deletes the TXT record whatever the outcome (an audited write), and records the order's result.
- **Renewal** is timed by ARI where the CA offers it, else at two thirds of the lifetime, so the 45-day certificates expected from 2028 renew about 15 days before expiry (ADR-1085 point 5). The first run uses Let's Encrypt staging; switching to production is an admin setting with a test order.
- **Rate limits.** One order in flight per name set; at most one new order per name set per day after a failure, doubling to a week; the issuer counts its orders against the CA's published limits for new orders (ADR-1082 context) and refuses a "Renew now" that would exceed them, saying when it can run.

### 3.4 Storage and distribution

- The ACME account key, each shared certificate's key and its chain are stored secrets of a new kind `pem` (the kind `value.rs` reserves). Names are system-reserved: `acme.account`, `cert.<slug>.key`, `cert.<slug>.chain`, `cert.cluster.key`, `cert.cluster.chain`. An admin cannot create or overwrite a name with the `acme.` or `cert.` prefix through the secrets API; they are written only by the issuer.
- Sizes: an ECDSA chain with two intermediates is about 3 to 4 KiB, under the 8 KiB value limit. Each location certificate uses two of the 128 secrets; a cluster with 10 certificate locations uses 23. The issuer refuses `certificate = true` when the store would pass 100 secrets, leaving room for credentials.
- Distribution is the existing secret sync (CLU-015): every full member gets them. A member in the location's `nodes` writes the key and chain to `<data_dir>/acme/<slug>/` (0600, written to a temporary file and renamed), and the existing reload in `tls.rs` and `api_tls.rs` picks them up with no restart. Members not serving the location hold the secret but do not write the files.
- **Using the certificate.** A listener or the API uses it when its `tls` names `acme = "<slug>"` instead of `cert`/`key` paths. Changing the API listener to it goes through the existing `api-tls` guarded row; a DoT or DoH listener through the `listen` row.
- **SNI client IDs.** Because a wildcard certificate makes the SNI label a client ID (`tls.rs`, FLT-006), a DoT or DoH listener given the location wildcard reads `dns.home.example.net` as client `dns`. That only matters if an `id:` match key is `dns`; the UI warns when a location wildcard is set on a DNS listener and a client uses a location slug or node name as its `id:` key.
- **Local services (decision 7).** Exporting the wildcard key to another device (a NAS) would let that device impersonate every name in the location, including the WrenDNS UI. So the key is not exportable at first: only WrenDNS's own listeners use it. No API route, UI control, MCP tool or `ctl` command returns or downloads it, and a support package never contains it. A guarded, audited download is a later opt-in task, not part of T36.10d.

### 3.5 Failure behaviour

- A failed order or renewal is a health reason only: warning 30 days before expiry, severe 7 days before (CLD-903). It never affects query answering (CLU-004); the ACME task runs on its own thread off the DNS runtime, as the secret sync does.
- The previous certificate stays in force until a new one is installed; a failed reload keeps it (`tls.rs`).
- If the issuer node is down, the shared certificates stay valid until they expire; when the primary changes, the new primary becomes the issuer and resumes from the stored account key.
- A provider credential that stopped working, a delegation CNAME that no longer resolves, or an authoritative server that never shows the TXT are each named in the reason.

## 4. DNS-provider integrations

### 4.1 The table

```toml
[[dns_provider]]
name = "azure-home"            # referred to by locations and the ACME issuer
kind = "azure_dns"             # one of the registered kinds
zone = "example.net"
credential_ref = "azure-home"  # a stored secret; never an inline value (ADR-1084 point 2)
# kind-specific, non-secret fields:
subscription = "<subscription id>"
resource_group = "<group>"
tenant = "<tenant id>"
client_id = "<application id>"
# optional: the challenge is delegated (section 4.4)
delegated_to = "home.acme-validation.example.org"
dry_run = false
```

- Shared section (every full member may become the issuer), admin-only, edited as a managed kind, refused by the gate in §2.6 until every member knows it.
- `credential_ref` only; `credential` and `credential_file` are not accepted for this table, so a credential never sits in a file that could reach a support bundle. The secret's value is the provider's own format (a client secret, an API token, an access key pair as `id:secret`).
- One `[[dns_provider]]` per account and zone. A location names its provider in `public_name.provider` and, for its certificate, in `certificate_provider` (defaulting to the provider whose `zone` contains the location's domain).

### 4.2 The trait

In a new module `crates/wrendns/src/dns_provider/` (it needs the secret store and the HTTP client, which live in the binary crate):

```rust
// Every method runs on a blocking-safe task off the DNS runtime.
trait DnsProvider: Send + Sync {
    fn kind(&self) -> &'static str;
    /// What the credential can change: zones and record names, as the provider reports it.
    async fn scope(&self) -> Result<Scope, ProviderError>;
    async fn list(&self, name: &Fqdn, rtype: RType) -> Result<Vec<RecordValue>, ProviderError>;
    /// Make the record set exactly `values` with `ttl`; idempotent.
    async fn ensure(&self, name: &Fqdn, rtype: RType, ttl: u32, values: &[RecordValue]) -> Result<Change, ProviderError>;
    async fn delete(&self, name: &Fqdn, rtype: RType) -> Result<Change, ProviderError>;
}
```

- Record types are limited to TXT, A and AAAA (CLD-904); `ensure` refuses any other type and any name outside the entry's `zone`.
- A registry maps `kind` to a constructor; adding a provider is one module, one registry line, its help entry and its recorded-API tests.
- **Ownership.** The node only changes record sets it created or that the operator listed. It keeps a ledger in `state.db` (name, type, provider, the value it last wrote, when) and refuses to overwrite a record set it did not create unless the operator adopts it in the UI (an audited write). This stops a mistyped name from replacing a record someone else manages.
- **Errors** carry the provider's status and a short reason, never the request headers or the credential; a `ProviderError` is formatted through the same redaction as `SecretValue`.

### 4.3 The first providers, and why (decision 6)

| Kind | Why | Narrowest scope | Signing |
|---|---|---|---|
| `azure_dns` | The owner's own zones are there; AC (1) of T36.10 renews through it. | Azure RBAC on one record set: a role assignment on the `_acme-challenge.<slug>` TXT record set (and the dynamic DNS A/AAAA record set), not on the zone. Microsoft documents record-set-level role assignment (https://learn.microsoft.com/azure/dns/dns-protect-zones-recordsets, "Record set level Azure RBAC": the scope is `.../dnszones/<zone>/<type>/<name>`). The record set must exist first; the helper shows the `az role assignment create --scope` command. The credential is scoped to that single record set (decision 6). | OAuth2 client credentials to Entra ID, then the Azure DNS REST API. |
| `cloudflare` | A very common DNS host for self-hosters, with a documented API. | An API token limited to one zone with DNS edit. Cloudflare cannot limit a token to one record, so the helper recommends delegation (§4.4) when the zone holds anything else of value. | Bearer token. |
| `route53` | Widely used; IAM can limit `ChangeResourceRecordSets` to named records and types. | An IAM policy on one hosted zone with the `route53:ChangeResourceRecordSetsNormalizedRecordNames` and `RecordTypes` conditions. The helper shows the policy JSON. | A small hand-rolled Signature Version 4 on `ring`, checked against AWS's published test vectors (ADR-1084 point 6). |
| `rfc2136` | Dynamic update (RFC 2136) signed with TSIG (RFC 8945) serves any self-run authoritative server (BIND, Knot, PowerDNS and others) with no vendor API. | A TSIG key that the server's update policy limits to the one name and type (for example a BIND `update-policy` grant on `_acme-challenge.<slug>.<domain>` TXT). The server does not report a key's scope, so "test and show scope" reports that the key is accepted for the configured name, and the helper shows the server-side policy to set. | TSIG HMAC-SHA256 on `ring`; the key is the stored secret. |
| GoDaddy (no kind) | Named in ADR-1084; a common registrar. | A GoDaddy key acts on the whole account, so no GoDaddy key is stored. GoDaddy zones are served by delegation of the challenge name only (§4.4): the operator creates one CNAME at GoDaddy by hand, once. | — |
| `delegated` | Any provider without a usable API (GoDaddy, Network Solutions and others, ADR-1084). | Nothing at the provider: the operator creates one CNAME by hand, once. | — |

Delegation covers the `_acme-challenge` name only. With no stored GoDaddy key the node cannot write an A or AAAA record in a GoDaddy zone, so dynamic DNS (§4.6) and public names (§5) for such a zone are not available directly; whether they are offered through a CNAME into a zone at an API provider is not decided (see the decisions section).

The helper for every kind shows, before any secret is entered, exactly which permission to grant and where, and the "test and show scope" action (CLD-904) then reports what the credential can actually change. A credential broader than needed (a zone-wide Azure role, a Cloudflare token for several zones) is accepted with a warning shown on the provider card until it is narrowed.

### 4.4 CNAME delegation of `_acme-challenge`

For a provider that cannot scope a token, or has no API:
1. The operator picks a validation zone they control at a provider that can scope narrowly (or a separate zone used for nothing else), and adds a `[[dns_provider]]` for it.
2. The helper shows the exact record to create at the main provider: `_acme-challenge.<slug>.<domain>. CNAME <slug>.<validation zone>.`
3. The node verifies the CNAME through the public authoritative servers (§3.3 step 3) and shows it as verified before it uses it.
4. The CA follows the CNAME; the node writes the TXT only in the validation zone. A leaked credential can then change only that zone.

### 4.5 Audit, rate limits and dry run

- **Audit.** Every write (ensure, delete, adopt) is an audit entry: `dns_provider.ensure` and so on, target `<provider>/<name>/<type>`, detail with the old and new values and the change ID the provider returned, never the credential. Writes made by the ACME issuer or dynamic DNS are actor `system` with the cause (`acme order <id>`, `wan change`).
- **Who can write.** Admin only. No agent token can write through the table, and there is no `plan_` tool for it (ADR-1084 point 4). MCP has read tools only: provider status and scope, without secrets.
- **Rate limits, per provider entry.** A token bucket (default 30 writes an hour, 5 a minute); a provider's own 429 or throttling answer backs off by its `Retry-After` or doubling to 15 minutes. Dynamic DNS adds its own limit (§4.6). Limits are configuration fields with bounds.
- **Dry run.** `dry_run = true` on an entry, or `?dry_run=true` on an API call, computes the change (old and new values, the API call it would make, with the credential replaced by `<redacted>`) and records it as an audit entry marked dry run, without calling the provider's write endpoint; read calls still run so the preview is real. New entries start with `dry_run = true` until the first successful test.
- **Off the DNS path.** Provider calls run on their own task; a failure is a health reason only (CLU-004).

### 4.6 Dynamic DNS for a location's WAN address

ADR-1083 and DSC-915 decide the rules; this section adds what the code needs.
- **New read.** T36.10e adds the WAN address read: UniFi's gateway entry in `stat/device` (its WAN interfaces' addresses), and the equivalent for the other router kinds where they expose it. The address is stored with the router's other reads; the CMDB shows it on the router's CI.
- One writer, the CMDB's designated node (ADR-1083 point 4); a debounce of 2 minutes; at most one update a minute per record, TTL 60 s by default.
- Refused, with the reason on the panel: 100.64.0.0/10, RFC 1918, loopback, link-local, documentation and other reserved ranges; for IPv6, anything outside global unicast.
- IPv4 and IPv6 are separate records and separate decisions.
- The public name is answered locally too, from the value the node last wrote, so a LAN client resolves it without the upstream round trip and agrees with the public answer.

## 5. What is never published publicly by default

Nothing leaves the node to a public DNS host unless an operator configured that exact record. In particular, by default:
- no device name, location name or node name is written to any provider;
- no private, CGNAT, link-local or loopback address is written anywhere (dynamic DNS refuses them, §4.6);
- no PTR for any address;
- no CMDB data, no MAC, no router data other than the WAN address a location chose to publish;
- `_acme-challenge` TXT records exist only while an order is open and are deleted after;
- no certificate names a device (§3.2);
- the public listener answers only known device keys (DNS-901, ADR-1090), and the hosted relay never carries local records, CMDB or location names (`docs/design/hosted.md`).

**Publishing a chosen local name publicly** (#110's third use) is a separate opt-in per name, off by default, admin only, audited, with dry run, built after dynamic DNS (DSC-917, T36.10f). A publicly published local name may not point at a private, CGNAT, link-local or reserved address (decision 8): the same ranges dynamic DNS refuses (§4.6), checked when the name is saved and again before every write, with the reason shown.

## 6. API, MCP and UI

### API (OpenAPI regenerated; dry run, `Idempotency-Key` and a reason on every write)

- `GET/POST /api/v1/locations`, `GET/PUT/DELETE /api/v1/locations/{slug}`: the table, plus for each location the resolved networks, its devices with their composed names, collisions, flat-name use and certificate state. Scope `config:read` to read; writes need Operator, except `certificate` and `public_name`, which are admin only (they cause writes outside the node).
- `GET /api/v1/clients/{id}` gains `location` and `locationName`.
- `GET/POST /api/v1/dns-providers`, `GET/PUT/DELETE /api/v1/dns-providers/{name}`, `POST /api/v1/dns-providers/{name}/test` (scope report), `GET /api/v1/dns-providers/{name}/records` (the ledger), `POST .../records/adopt`. Admin only; secrets never in a response.
- `GET /api/v1/certificates`, `POST /api/v1/certificates/{name}/renew` (a guarded write with dry run, CLD-903).
- `GET /api/v1/locations/{slug}/public-name`: last update, current address, refusal reason.

### MCP

- Read: `list_locations`, `get_location` (devices and names), `get_device_location`, `list_dns_providers` (status and scope, no secret), `list_certificates`, `get_dynamic_dns_status`.
- Plan only, applied by a human: `plan_set_location` (create or update; not the `certificate` or `public_name` fields) and `plan_set_device_location` (the override). `plan_renew_certificate` as a guarded MCP write (T36.10d).
- No write or plan tool for the provider table.

### UI pages, in words

- **Locations** (new page under Network): one card per location with its label, slug, visibility, networks (with "no network reported" for an unresolved VLAN), serving nodes, parent domain and the names it composes (a searchable table of device, address, name), collisions and flat-name use. Edit opens a form with the network picker (CIDRs and the VLANs the routers report). A preview shows which devices would be renamed before saving.
- **Clients list, network inventory, CMDB**: a location badge and a location filter (the existing searchable picker, UI-901); the CMDB groups by location; the map groups by location (DSC-914).
- **Settings → DNS providers**: a card per provider with kind, zone, scope result, dry-run state, last write and errors; Add walks through the kind's scope instructions before the secret field; the records ledger with Adopt.
- **Certificates card** (Settings → Certificates and on each location): names, issuer node, expiry, next renewal, last error, staging or production, Renew now (guarded).
- **Dynamic DNS panel** on a location: current WAN address, published value, last update, refusal reason.

### Help

Help topics `locations`, `location-private-names`, `dns-providers`, `dns-provider-delegation`, `certificates-acme`, `dynamic-dns`, each linked from its control (`ui/src/lib/help.ts`, `npm run check:help`); user docs in `docs/configuration.md`, `docs/running.md` and `docs/secrets.md`, and the site page (DOC-006).

## 7. Requirements, ADRs and build tasks

### Requirement IDs

Already in `spec/01`: DSC-908 to DSC-915, CLD-903, CLD-904. Rows added with the owner decisions of 2026-11-26:

| ID | For | State |
|---|---|---|
| DSC-916 | Flat-name migration: `flat_names`, its per-location switch (on by default) and the 7-day use count (§2.5). | Row in `spec/01` (decision 2). |
| DSC-917 | Publishing a chosen local name publicly: per-name opt-in, off by default, audited, never to a private, CGNAT, link-local or reserved address (ADR-1083 point 7 asked for its own row). | Row in `spec/01` (decision 8). |
| CLD-919 | Provider writes: ownership ledger and adopt, dry run, per-entry rate limits, the propagation check (§4.2, §4.5, §3.3). | Reserved; the row is written when these design points are decided (still open). |
| CLD-920 | Certificate storage: the `pem` secret kind, system-reserved names, the file install for serving nodes, the key not exportable (§3.4). | Row in `spec/01` (decisions 5 and 7); the 100-secret ceiling is not in the row (still open). |

Wording changes to existing rows: DSC-908 (rolling upgrade, decision 5), DSC-909 (collision rule, decision 3; the location from configuration and router reads, not the CMDB, decision 1), DSC-910 (where the override lives, decision 1), DSC-911 (subtree answer, decision 4) and CLD-904 (the provider set, decision 6) are made. DSC-912 (drop the cache sentence, finding 5) and DSC-915 (the new WAN read, finding 4) are still open.

### ADRs

1. **ADR-1095, location names** (Accepted 2026-11-26): the override's home, the collision rule, the subtree answer, flat names, the upgrade gate (decisions 1 to 5). Amends ADR-1081.
2. **ADR-1096, what a location's integrations never hand out** (Accepted 2026-11-26): the wildcard key is not exportable (decision 7) and a public local name never points at a non-public address (decision 8). Amends ADR-1082 and ADR-1083.
3. **The provider set** (decision 6) is a dated amendment to ADR-1084. The rest of the provider-table additions (the ledger and adopt, dry run, rate limits) is still open, with CLD-919.
4. **Still to write:** certificate storage and use beyond decision 7 (the reserved names, the per-location file install, the order builder's wildcard-only rule; amends ADR-1082); dynamic DNS's WAN read (amends ADR-1083); the rest of public publishing, when T36.10f starts.

### Build tasks, sizes and order

Sizes: S about a day, M two to four days, L a week or more, for one agent with review.

| Order | Task | Size | Depends on |
|---|---|---|---|
| 1 | **T36.10a0** The upgrade gate for new shared sections and the `pem` secret kind with reserved names (DSC-908, CLD-920 in part). | S | — |
| 2 | **T36.10a** Locations core as `spec/10` says, with the amendments above (DSC-908 to DSC-913, DSC-916). | L | a0 |
| 3 | **T36.10b** Provider table, the first providers (Azure DNS, Cloudflare, Route 53, RFC 2136 with TSIG), delegation (GoDaddy and others), ledger, dry run, rate limits (CLD-904, reserved CLD-919). | L | a0 |
| 4 | **T36.10c** Locations page, badges, filters, help (DSC-914). | M | a |
| 5 | **T36.10d** ACME DNS-01 with hot reload (CLD-903, CLD-920). | L | b, a |
| 6 | **T36.10e** WAN read and dynamic DNS (DSC-915). | M | b, a |
| 7 | **T36.10f** Publishing chosen local names (DSC-917). | M | e |

a and b can run in parallel after a0 (they touch different modules; both touch `spec/01` and the OpenAPI document, so they merge one after the other). c follows a and, as `spec/10` says, not in parallel with the M38 pages.

## 8. Test plan

**The fake provider.** An in-process `FakeProvider` implementing the trait, registered as kind `fake` only in test builds: an in-memory zone, a configurable scope, injected failures (401, 403, 429 with `Retry-After`, 5xx, timeouts), latency, and a call log. With it:
- `cld_904_*`: ensure is idempotent, delete removes only owned record sets, a name outside the zone and a type other than TXT, A, AAAA are refused, the secret is absent from logs, errors, the API, the audit entry and the support package (grep of each output for the secret's value).
- `cld_919_*`: dry run makes no write call and writes a dry-run audit entry; the bucket refuses the 31st write in an hour; a 429 backs off by `Retry-After`; an unowned record set is not overwritten until adopted.
- An agent token gets 403 on every provider write route, and the MCP catalog has no provider write tool.

**Recorded provider APIs.** Each first provider's create, update and delete run against a local HTTP server that replays recorded or hand-written answers taken from the provider's public documentation, with no live credential in CI (CLD-904 AC). Route 53's signer is checked against AWS's published Signature Version 4 test vectors. The `rfc2136` provider runs against an in-process DNS server that checks the TSIG signature and refuses an update outside the key's allowed name and type; TSIG signing is checked against messages signed by an independent implementation and recorded in the test tree.

**The fake ACME server.** An in-process RFC 8555 server for tests (directory, nonce, account, order, authorization, `dns-01` challenge, finalize, certificate, ARI `renewalInfo`), signing with `rcgen` and checking the TXT by reading the fake provider's zone. With it, `cld_903_*`: issue a wildcard; renew when ARI says so; the listener's next handshake presents the new certificate with no restart and no dropped query (a query loop across the reload); a renewal failure raises the 30-day warning and the 7-day severe reason on a fake clock and leaves answers unchanged; the order builder refuses a device name. An optional nightly job runs the same flow against Pebble in a container.

**Locations.** `dsc_908_*` to `dsc_916_*`:
- with no `[[location]]` the answers for a fixed corpus are byte-identical to `main` (golden test);
- validation: bad slug, overlap, reserved label, slug equal to a device label, missing domain;
- a device on a location's network answers `<label>.<slug>.<domain>` with a matching PTR; moved to another location's address (a fake router read), it answers the new name within one rebuild and the CMDB still has one CI;
- private: a client in the location gets the answer, a client outside gets the same NXDOMAIN and SOA as an unknown name, for A, AAAA and PTR; nothing is forwarded upstream for a name in the subtree (a counting fake upstream);
- flat names on (the default) and off; a flat label two locations compose goes to the ADR-901 winner and is listed; a collision inside a location keeps the ADR-901 winner and lists the others;
- a name in a location's subtree that is not a device, node or published record gets NXDOMAIN locally and is not forwarded;
- the `[[client]] location` override wins over the address and clears when removed; an unknown slug is refused;
- the wildcard key is in no API response, MCP result, `ctl` output or support package;
- the upgrade gate refuses the first location while a fake member reports an older build;
- `make bench-smoke` for `wrendns-policy` and `wrendns-cache`, and an allocation-counter test on the private-name path.

**Dynamic DNS.** `dsc_915_*` with the fake provider and a fake router read: one WAN change makes one update after the debounce; a flapping address is rate limited; CGNAT, private and reserved addresses are refused with the reason; no read publishes nothing; only the CMDB node writes.

**UI.** Playwright specs named by requirement (`dsc_914 ...`, `cld_904 ...`, `cld_903 ...`) against stubbed API routes (stub, then `goto`, then `reload`, as the existing specs do): the Locations page lists, edits and previews renames; badges and filters on the clients list, inventory and CMDB; the provider card never shows a secret after save; Renew now asks for the guarded confirmation.

**Gates.** Image delta of `instant-acme` (with the `ring` backend, not `aws-lc-rs`, if its features allow) and of the provider modules against 25 MiB per architecture; RSS against 32 and 128 MiB (ADR-1031); `cargo-deny` before merge (ADR-1085).

## Decisions

Owner decision, 2026-11-26, on the eight questions this note asked through the question tool. Records: ADR-1095 (decisions 1 to 5), the dated amendment to ADR-1084 (decision 6), ADR-1096 (decisions 7 and 8); requirement rows DSC-908 to DSC-911, DSC-916, DSC-917, CLD-904 and CLD-920 in `spec/01`; tasks T36.10a0 to T36.10f in `spec/10`.

1. **The manual override.** A device's manual location override is a `location` field on its `[[client]]` entry. The rule that CMDB data never reaches device names (DSC-901) stays; DSC-910 is reworded (§2.3).
2. **Flat names.** The old names `<device>.<device_domain>` keep answering for devices in a location, with a per-location switch (`flat_names`) that is on by default and a 7-day use count on the Locations page (§2.5, DSC-916).
3. **Collisions.** Name collisions inside a location follow ADR-901's ranking everywhere (a named device, then the router's name, then mDNS, then the lowest address), with every collision listed on the Locations page. This replaces ADR-1081 point 4 (§2.5, DSC-909).
4. **The subtree.** The node owns each location's subtree and answers NXDOMAIN locally for names in it that are not devices, nodes or published records (§2.4, DSC-911).
5. **The upgrade gate.** The API and the loader refuse the first location (and the first DNS provider and the first secret of the `pem` kind) while any cluster member runs a build that does not know them, naming the member. DSC-908 is reworded (§2.6).
6. **The first providers.** Azure DNS, Cloudflare, Route 53 and RFC 2136 dynamic update with TSIG. GoDaddy is supported by delegation of the challenge name only, with no stored GoDaddy key. Azure DNS credentials are scoped to a single record set (Microsoft documents record-set-level role assignment: https://learn.microsoft.com/azure/dns/dns-protect-zones-recordsets). This amends ADR-1084 (§4.3, CLD-904).
7. **The wildcard key.** A location's wildcard certificate key is not exportable at first: WrenDNS's own listeners only. A guarded, audited download is a later opt-in task (§3.4, CLD-920).
8. **Public names.** A publicly published local name may not point at a private, CGNAT, link-local or reserved address (§5, DSC-917).

Reading of decision 5: "its secret kind" is read as the new `pem` secret kind, which this note gated together with `[[dns_provider]]` (§2.6); the provider's own credential is an ordinary `text` secret, which every build already knows.

### Still open

Not decided by the owner; the body above states them as proposals:
- DSC-912's cache sentence and ADR-1081 point 6 (finding 5), and DSC-915's WAN read with its ADR-1083 amendment (finding 4).
- The provider-write details: the ownership ledger and adopt, dry run by default on new entries, the per-entry rate limits and the propagation check (reserved CLD-919, §3.3, §4.2, §4.5).
- Certificate storage details beyond decision 7: the system-reserved names, the per-location file install, the 100-secret ceiling and the order builder's wildcard-only rule (§3.2, §3.4).
- Dynamic DNS and public names for a zone whose provider has no stored key (GoDaddy, Network Solutions): whether a CNAME into a zone at an API provider is offered (§4.3).
- The later guarded, audited download of a wildcard key (decision 7): its own task, design and record when it is wanted.
- What the Locations page and the CMDB show for collisions beyond the list decision 3 requires (the CMDB listing this note first proposed).
