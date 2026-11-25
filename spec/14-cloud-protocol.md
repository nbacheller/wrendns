# 14 — The Cloud Tunnel Protocol (node to WrenDNS Cloud)

> **DRAFT for the owner's review (2026-11-25). Not accepted; nothing in it is built.** This is the first half of T36.4 (`spec/10`). It writes down the protocol that ADR-1047, ADR-1048 and the hosted design (`docs/design/hosted.md`) already decided, and it decides nothing those records leave open. Every point that still needs a choice is marked **Open (Qn)** and listed in §15, "Open questions for the owner". The wire schema (message names, field numbers) is not fixed by this draft: names in it are working names. T36.4 stays unticked until the owner has answered §15, the CLD-901 requirement row exists in `spec/01`, and the tunnel client is built and tested against the fake broker.

## 0. Scope, sources and conventions

**Scope.** The protocol between one full member of a linked WrenDNS cluster (the *node*) and the WrenDNS Cloud *broker* over the outbound tunnel: transport, framing, hello, version negotiation, heartbeats, stream types, limits, reconnect, errors and the security rules both sides follow. It also lists every control frame that later tasks (T36.5 to T37.3) put on the tunnel, with the task that defines its fields. It does not cover the portal's own web pages, the OIDC issuer (the node already speaks OIDC to it, ADR-1049, ADR-1065), the SCIM server, or what happens inside a relayed TLS session (that is the node's ordinary DoT, DoH, UI, API and MCP).

**Sources, in order of authority.** ADR-1047 (the tunnel, SNI passthrough, relayed streams, heartbeats, budgets, untrusted input), ADR-1048 (node cloud identity, enrolment, the tunnel CA, leases, removal), ADR-1049 (authorization on the node), ADR-1050 (names and the roaming path), ADR-1051 (certificates), ADR-1052 (the open-core boundary: this document is the protocol the separate service implements), ADR-1065 (the portal's issuer stays the one identity nodes trust); then `docs/design/hosted.md`, sections "The tunnel", "How the node treats a relayed stream", "Enrolment", "Cluster-aware routing", "Failure modes"; then ADR-039 (PROXY v2 and client IDs), ADR-044 (the cluster channel's framing, which the control stream reuses), ADR-057 (renewal with the same key) and `spec/12` §9 (CLU-010, protocol versioning). Where this draft and an ADR disagree, the ADR wins and this draft is wrong.

**Notation.** A bracket after a statement names its source, for example [ADR-1047 p2] for ADR-1047 point 2 or [hosted: Enrolment] for a section of the design. A statement with no source and no "Open" mark is a restatement of one nearby, never a new rule.

**Names.** `<suffix>` is the tenant-name domain (the owner chose `wrendns.net`, hosted.md "Owner decisions"); `<slug>` a tenant's cluster slug; `<node>` a node name. Addresses in examples are documentation ranges (RFC 5737, RFC 3849).

## 1. Parties and terms

| Term | Meaning |
|---|---|
| Node | A **full member** of a linked cluster. Only full members dial; resolver pods and witnesses never do [ADR-1047 p1; ADR-1027]. |
| Broker | The cloud program that terminates tunnels and routes public TCP connections into them by TLS SNI, without decrypting them [ADR-1047 p2]. |
| Edge | The one stable dual-stack public address pair for every tenant name and for `tunnel.<suffix>` [ADR-1050 p6; ADR-1052 p4]. |
| Tunnel | One mutually authenticated HTTP/2-over-TLS connection from a node to `tunnel.<suffix>:443` [ADR-1047 p1]. One per full member. |
| Control stream | The one HTTP/2 stream of a tunnel that carries length-prefixed control frames [ADR-1047 p2]. |
| Relayed stream | One HTTP/2 stream carrying the bytes of one public TCP connection the broker accepted, preceded by a PROXY v2 header the broker writes [ADR-1047 p2]. |
| Helper | The certificate helper that completes DNS-01 for CSRs nodes send over the tunnel [ADR-1051 p1]. |
| Cloud resolver | The multi-tenant DoH and DoT resolver that answers roaming devices while home is unreachable [ADR-1064]. |
| Policy service | The mirror, editor, signing page, queue and parked conflicts of cloud writes [ADR-1061, ADR-1063]. |
| Up / down | Up is node to cloud; down is cloud to node. |

## 2. Transport and framing

### 2.1 TLS and mutual authentication
- The node opens TCP to `tunnel.<suffix>`, port 443, at the edge address, and speaks TLS [ADR-1047 p1]. Which TLS versions are allowed (1.3 only, or 1.2 as well) is **Open (Q3)**.
- **The broker's certificate** for `tunnel.<suffix>` is issued by the cloud's **private tunnel CA**, never a WebPKI CA. The node pins that CA's public key and one backup key, both delivered at enrolment (§4). A rollover to a new CA key is announced in the broker's hello (§3), signed by the current CA key, at least 30 days ahead [ADR-1048 p2]. The encoding of the pins and of the rollover announcement is **Open (Q4)**.
- **The node's certificate** is its cloud client certificate (about 30 days, carrying tenant, cluster and node IDs) for its own Ed25519 cloud key in `<data_dir>/cloud/` [ADR-1048 p1]. The broker checks it on every connection and refuses a denied serial [ADR-1048 p6].
- **Cipher suites.** Raspberry Pi 4 lacks the ARMv8 crypto extensions, so ChaCha20-Poly1305 is preferred there; both suites are benchmarked [hosted: The tunnel]. How a node states that preference (client suite order only, or a setting) is **Open (Q3)**.
- No new runtime crate: `h2`, `hyper` and `rustls` are already linked [ADR-1047 p1; AGENTS rule 8].

### 2.2 The HTTP/2 connection
- One HTTP/2 connection per tunnel. Every public connection the broker accepts for that node becomes **one HTTP/2 stream** [ADR-1047 p2]. Control messages travel on **one control stream** [ADR-1047 p2].
- In HTTP/2 only the client of a connection opens streams, and the node is the TCP and TLS client here. How the broker gets a new stream per public connection (the node acting as the HTTP/2 server on its own outbound connection, the node keeping a pool of idle streams open, or an "open a stream" control frame the node answers) is not decided anywhere: **Open (Q1)**.
- The request line of the control stream and of relayed streams (method, `:path`, `:authority`; ADR-044 uses `POST /cluster/v1/stream` for its channel) and the ALPN value of the tunnel are **Open (Q2)**.

### 2.3 Relayed streams: the stream preface
- Each relayed stream **starts with a PROXY protocol v2 header** written by the broker, carrying the caller's address and port and the TLS SNI, then carries the raw bytes of the public connection in both directions [ADR-1047 p2]. The bytes are the caller's TLS session with the node: TLS ends on the node, so the broker sees ciphertext, the SNI, timing and volume [hosted: Trust boundaries].
- The node hands the stream to its own TLS acceptors **in-process**, as an in-memory stream with a "relayed" context flag and the header's fields. It is never a real socket, and no listener needs `proxy_protocol = true`; ADR-039's PROXY rule for sockets is unchanged [ADR-1047 p4].
- Only PROXY v2 is defined (v1 text headers are not part of this protocol; ADR-039 already refuses them on sockets). Which PROXY v2 TLVs carry the SNI, the relay correlation ID [hosted: How the node treats a relayed stream] and the broker's "source equals the tenant's own tunnel address" mark (T36.7 AC 8), or whether any of them travel in a control frame instead, is **Open (Q5)**. What the node does with a `LOCAL` command on a relayed stream (there is no socket address to fall back to) is **Open (Q6)**.
- The header is untrusted input to the node; §12.2 lists what the node checks.

### 2.4 The control stream: framing
- Control frames use the cluster channel's framing: a **4-byte big-endian length, then one prost-encoded frame** [ADR-1047 p2; ADR-044 "Wire"]. A frame longer than **1 MiB** is refused [ADR-044; hosted: The tunnel].
- The message schema (whether the tunnel reuses the cluster channel's `Frame` type or has its own, the `oneof` layout and the field numbers) is **Open (Q7)**. §6.3 lists the frames by working name.
- Some payloads named by later tasks can exceed one 1 MiB frame: a signed change may be up to 1 MiB before its assertion [ADR-1061; hosted: The user channel], the class map holds up to 12,000 patterns (T37.2), and full cloud-view digests and compiled list blobs have no stated size. Whether they are chunked, carried on a stream of their own, or capped below the frame limit is **Open (Q8)**.

### 2.5 QUIC later
QUIC (`quinn` is linked) is added later as the preferred transport with HTTP/2 as the fallback [ADR-1047 p1]. This draft defines the HTTP/2 transport only. How a node chooses between them, and whether the framing above carries over unchanged, are left to that later change.

## 3. Hello and version negotiation

- **Both sides send a hello** at the start of the control stream: the node's (who it is, what it speaks, as in ADR-044) and the broker's, which carries any tunnel CA rollover announcement signed by the current CA key [ADR-1048 p2: "a rollover ... is announced in the hello message"; this draft reads that as a broker hello]. ADR-044 has the node's hello name the node and checks it against the certificate; the same rule is the obvious reading here, since the client certificate already carries tenant, cluster and node IDs [ADR-1048 p1], but which hello fields must equal certificate fields, and what the broker does on a mismatch, is **Open (Q9)**.
- **Versions: N and N-1.** The tunnel protocol is versioned, and each side accepts its own version N and the previous one, N-1 [T36.4; CLU-010 in `spec/12` §9]. How the version is carried (an integer in each hello, as the cluster RPC's `protocol_version`), who picks the version for a connection, whether optional features are named separately from the version, and what a side sends before closing on an unsupported version are **Open (Q10)**.
- Because every frame from a node is untrusted input (§12.1), the broker never relies on a node's stated version or features to decide what it may do; they decide only which encoding to use.

## 4. Node identity and enrolment (references to ADR-1048)

This protocol relies on, and does not change, these points of ADR-1048. Their frames are T36.5's.

| Step | What happens | Source |
|---|---|---|
| Link | An admin on the primary starts linking from Settings → WrenDNS Cloud or `wrendns cloud link`. The node calls the portal outbound for an RFC 8628 device code (10 minutes, single use, rate limited); a tenant admin enters it at `dns.wrendns.com/link` on a confirmation page that names the requesting cluster, its nodes, its source address and rough region and its version. Headless and Kubernetes installs use a `wren_enrol_...` token from a secret file instead. | ADR-1048 p3 |
| Binding | The polling node receives the tenant ID, the slug, the hosted issuer's URL and the tunnel CA's public key and backup key. Each slug is bound to one cluster. | ADR-1048 p2, p4; hosted: Enrolment |
| Keys | Each full member makes its own Ed25519 cloud key, mode 0600, node-local, never replicated, never a stored secret. | ADR-1048 p1 |
| Certificate | The cloud CA issues a client certificate of about 30 days carrying tenant, cluster and node IDs. | ADR-1048 p1 |
| Members | The primary countersigns each member's first certificate request over the cluster channel, so joining the cluster is enough to bring a member online. | ADR-1048 p3 |
| Renewal | Over the tunnel at two thirds of the certificate's life, with the same key (as ADR-057). | ADR-1048 p1 |
| Long offline | A node offline past expiry renews with its cloud key plus a fresh countersignature from the current primary, within 180 days of expiry, unless removed; after that it links again. | ADR-1048 p1 |
| Linking is guarded | Linking and unlinking are admin-only guarded settings, never for agents, audited on both sides. | ADR-1048 p5 |

Not settled by ADR-1048, and needed by this protocol:
- A member with no cloud certificate yet cannot open an mTLS tunnel. By which path its countersigned first request reaches the cloud (through the primary's tunnel, or an endpoint that needs no client certificate, as `POST /cluster/v1/join` is for the cluster) is **Open (Q11)**.
- How the "expired certificate plus countersignature" renewal authenticates at the TLS layer (the broker accepting an expired client certificate for one frame only, or a separate endpoint) is **Open (Q11)**.

## 5. Heartbeats

- **Cadence:** every **20 s**, below the 4-minute idle timeout of Azure's and most middleboxes' defaults [ADR-1047 p5; hosted: The tunnel].
- **Fields of every node heartbeat** [ADR-1047 p5]:

| Field | Meaning | Notes |
|---|---|---|
| `node_id` | the sending node | must match the client certificate; the broker believes the certificate, not the field (§12.1) |
| `cluster_id` | its cluster | as above |
| `role` | the node's cluster role as it claims it | never believed alone (below) |
| `epoch` | the fencing epoch the node holds (`spec/12` §5) | never believed alone |
| `ready` | whether the node is ready to serve | an unready node is not routed to [ADR-1047 p7] |
| `version` | the WrenDNS version | a string from the node: length-limited and escaped wherever shown [ADR-1047 p10] |
| `maintenance` | whether the node is in maintenance (ADR-118) | a node in maintenance is not routed to [ADR-1047 p7] |

- **The primary's lease.** The primary's heartbeat also carries a lease `{cluster_id, node_id, epoch, expires}` signed with the primary's cloud key. The broker routes `<slug>.<suffix>` to it only when a majority of the tenant's connected tunnels report the same primary and epoch (for a one-node cluster, the node itself) [ADR-1048 p6; hosted: Cluster-aware routing]. The lease's lifetime, the signature's encoding and its domain-separation string are **Open (Q12)**.
- **Added by later tasks:** the group IDs that the node's signed group rules name, so the cloud sends membership updates only for those groups (T36.24).
- **Heartbeat acknowledgements (down)** carry version hints for the platform channel [hosted: The platform channel] and the current class-map version (T37.3). Whether every heartbeat is acknowledged, and the acknowledgement's other contents, are **Open (Q13)**.
- **Liveness.** The node raises the health reason `cloud_unreachable`, degraded and never severe, after 60 s without the cloud [T36.4; ADR-1047 p9]. When each side declares the other gone (ADR-044 uses three missed heartbeats for the cluster) is **Open (Q13)**.

## 6. Stream types and multiplexing

### 6.1 Data streams
| Type | What it carries | Where it is routed from | Budget class |
|---|---|---|---|
| Relayed DNS | DoT (853) and DoH (443) for the DNS site `<slug>-dns.<suffix>` and its DoT labels `<dot-label>.<slug>-dns.<suffix>` | broker, by SNI; unknown DoT labels and unknown slugs are refused at the broker before any byte reaches a node | DNS |
| Relayed UI | the node's UI, API and MCP at `<slug>.<suffix>` (primary first, sticky) and `<node>.<slug>.<suffix>` (that node); verified custom names later (phase 2) | broker, by SNI | UI |

Sources: ADR-1047 p2, p6, p7; ADR-1050 p1 and its ADR-1064 amendment; hosted: Device keys and the open-resolver gate. Routing is by SNI only, to the tunnel whose client certificate holds that slug, never by a header [hosted: threat model, "Cross-tenant routing"].

Whether the budget class of a stream is decided by the broker and signalled to the node, or decided by the node from the SNI in the PROXY header (the DNS site and the UI names are distinct sites since ADR-1064, but the design describes DNS streams as "DoT and DoH to `/dns-query`", which the node sees only after decrypting), is **Open (Q14)**.

### 6.2 Routing rules the broker applies (summary)
- `<slug>.<suffix>`: the connected member holding a valid primary lease confirmed by a majority, else a ready replica in a stable order (lowest node ID); re-routed only when the target disconnects, turns unready, enters maintenance, or a new lease is seen [ADR-1047 p7].
- `<node>.<slug>.<suffix>`: always that node [ADR-1047 p7].
- The DNS site: the home node while a ready member is connected, else the cloud resolver; when home returns, idle connections to the cloud resolver are closed within 5 minutes [ADR-1064; T36.8].
- How the broker handles two tunnels from the same node at once (a reconnect that overlaps the old connection) is **Open (Q15)**.

### 6.3 Control frames
Working names only (§2.4, Q7). "Defined by" is the task that fixes the frame's fields and tests; T36.4 defines only the first group.

| Frame (working name) | Dir | What it carries | Defined by | Source |
|---|---|---|---|---|
| `NodeHello` | up | node identity, protocol versions | T36.4 | ADR-1047 p2 |
| `BrokerHello` | down | protocol version, any signed tunnel CA rollover | T36.4 | ADR-1048 p2 |
| `Heartbeat` | up | §5 fields, the primary's lease | T36.4, T36.5 | ADR-1047 p5, ADR-1048 p6 |
| `HeartbeatAck` | down | version hints, class-map version | T36.4, T36.18, T37.3 | hosted: The platform channel |
| `CloudCertRenew` / `CloudCert` | up / down | renewal of the node's cloud certificate with the same key; long-offline renewal with the primary's countersignature | T36.5 | ADR-1048 p1 |
| `MemberRemoved` | up (primary) | a member removed from the registry, sent at once | T36.5 | ADR-1048 p6 |
| `Disconnect` | up | the node has deleted its cloud key | T36.5 | ADR-1048 p6 |
| `CertRequest` / `CertChain` | up / down | the node's TLS CSR for its hosted names; the chain from the helper | T36.7 | ADR-1051 p1 |
| `IssuanceLog` | down (on request) | the helper's signed issuance log, for the CT watch | T36.7 | ADR-1051 p6 |
| `DeviceKeyRegistered` / `DeviceKeyRevoked` | up | device-key ID, DoT label, and for the cloud resolver the SHA-256 of the DoH key; never the key | T36.8 | ADR-1050 p5 |
| `DynamicDnsUpdate` | up (primary) | a location's IPv6 address (IPv4 is the tunnel source the broker sees) | T36.11 | hosted: Managed names and dynamic DNS |
| `ProposedChange` | down | an unsigned patch the node only displays on its signing page; changes nothing | T36.15 | ADR-1061 p1, ADR-1047 p3 |
| `CloudChange` | down | a signed change (envelope and assertion) | T36.15 | ADR-1061 |
| `SignerRequest` | down | a pending portal signing passkey; pending until confirmed on the LAN | T36.15 | hosted: The user channel |
| `SignerSuspended` | down | a signer suspended by a tenant admin (removes power only) | T36.15 | hosted: The user channel |
| `ChangeResult` | up | Applied, Conflict (with home's version) or Rejected (with the reason), then Accepted | T36.15, T36.16 | ADR-1063 |
| `CloudView` / `CloudViewDigest` / `AcceptedStatement` | up (primary) | the signed cloud-view delta after each stable version, the hourly full digest, the signed Accepted statement | T36.16 | ADR-1063 |
| `PlatformContent` / `KeyManifest` / `Timestamp` | down | signed content, the key manifest (also fetched from wrendns.com), the hourly freshness statement | T36.18 | ADR-1062 |
| `ListBlobRequest` / `ListBlob` | down / up | the cloud resolver fetching a compiled list blob from home | T36.12 | ADR-1064 |
| `RoamingEvents` | down | query events the cloud resolver answered, shipped home through a bounded buffer after the privacy level | T36.12 | ADR-1052 p3 |
| `MembershipUpdate` | down | organization, group, subject, add or remove, SCIM event ID, sequence | T36.24 | ADR-1069 |
| `SubjectDisabled` / `SubjectRelinked` | down | deprovisioning and re-link notices (remove power only) | T36.24 | ADR-1069 |
| `ClassMapRequest` | up | the node asking for the class map | T37.2 | ADR-1060 |
| `ExportBatch` / `ExportReply` | up / down | one counters batch per cluster every 5 minutes; the reply's acknowledgement and groups to omit | T37.2 | ADR-1060 |

Every down frame that changes anything on the node is signed by a key the node trusts, except the power-reducing notices (`SignerSuspended`, `SubjectDisabled`, `SubjectRelinked`, a membership remove) and a membership add, which counts only under a group rule a node admin signed [ADR-1047 p3; hosted: Cloud writes]. `ProposedChange` changes nothing by itself.

## 7. Flow control and limits

### 7.1 On the node [ADR-1047 p6; hosted: The tunnel]
- **DNS budget:** at most **128** concurrent relayed DNS streams, with HTTP/2 stream windows of **4 to 16 KiB**.
- **UI budget:** at most **32** concurrent relayed UI, API and MCP streams, with windows of **64 to 256 KiB**.
- A stream past its budget is **refused with a counted reason, never queued** (T36.4's `_streams_refused_total{budget}`, §13). T36.4 AC 11: DNS stream 129 is refused while UI streams still open.
- **Frame limit:** 1 MiB (§2.4).
- **Memory targets:** at most +2 MiB RSS idle and +12 MiB with both budgets full, measured against ADR-1031's 32 and 128 MiB gates [ADR-1047 p6].
- **Isolation from DNS:** the tunnel runs as its own task with bounded queues and no lock shared with the DNS pipeline; a UI burst must not show in DNS p99 [ADR-1047 p9; `spec/02` §3, §8].

Not settled: how a window within each range is chosen (fixed, adaptive, or a setting); the connection-level window; the HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` and `SETTINGS_MAX_FRAME_SIZE` each side advertises; the budget, if any, for the control stream's own queue; idle timeouts for relayed streams; and the HTTP/2 error a refused stream gets: **Open (Q16)**.

### 7.2 At the broker
- A per-node bandwidth cap, configurable from 2 to 5 Mbit/s, to protect home uplinks and the broker [hosted: The remote UI].
- Per-tenant caps on streams, bandwidth and connections [hosted: threat model, "Reconnect storms, floods"].
- Unknown slugs and unknown DoT labels are refused before any byte reaches a node [hosted: Device keys and the open-resolver gate].
- Dynamic DNS updates are rate limited (one a minute, TTL 60 s), and private or reserved addresses are refused [hosted: Managed names and dynamic DNS].

## 8. Reconnect and backoff

- The node reconnects with **full-jitter backoff from 1 s to a 5-minute cap**, longer than ADR-044's 30 s, so a broker restart does not cause a thundering herd [ADR-1047 p5].
- This draft reads "from 1 s" as ADR-044's shape: the cap for attempt *n* (counting from 0) is `min(300 s, 1 s × 2^n)`, and the wait is drawn uniformly from 0 to that cap. Confirming that reading, when the attempt count resets (after a successful hello, or only after a connection has stayed up for a while), and whether the broker may tell a node to wait longer (a drain before a planned restart, or a retry-after on overload) are **Open (Q17)**.
- What a node does when the broker refuses its certificate (a denied serial after Remove node, or an expired certificate past the grace): it keeps DNS unaffected and shows `cloud_certificate_expired` (degraded) for expiry [hosted: Failure modes]; whether it stops dialling, and the health reason for a denied serial, are **Open (Q18)**.
- Reconnecting never touches DNS answering; nothing on the answer path waits on the tunnel [ADR-1047 p9; CLU-004].

## 9. Removal, revocation and closing

- **Remove node** in the portal closes that node's tunnel and denies its certificate serial at once [ADR-1048 p6].
- **Disconnect** on the node deletes the cloud key and tells the cloud (`Disconnect`) [ADR-1048 p6].
- **Registry removal:** when a member is removed from the cluster registry (ADR-143), the primary tells the cloud at once (`MemberRemoved`); the cloud denies that node's serial, closes its tunnel, and the helper revokes its TLS certificates for the tenant's names. T36.5 AC 4: within 5 s [ADR-1048 p6].
- **Suspension** of a tenant refuses its relay at the broker; certificate renewal through the helper continues (the home keep-alive) [ADR-1051 p2].
- Whether the broker sends a reason before closing a tunnel (removed, suspended, revoked, version unsupported, overloaded) and how (a control frame, or an HTTP/2 `GOAWAY` with debug data) is **Open (Q19)**.

## 10. What the node never sends

Over the tunnel, in any frame, a node never sends [sources in brackets]:
- **Any private key:** its cloud key, its TLS keys for hosted names (T36.7 AC 2 tests this on the fake broker's capture), its cluster keys [ADR-1048 p1; ADR-1051 p1].
- **Any stored secret or credential:** passwords and their hashes, TOTP secrets, API tokens, OIDC client secrets, DNS-provider credentials, alert destinations' secrets, list sources' credentials [ADR-1052 p3; ADR-1063 point 1; hosted: Two-way sync].
- **A device key.** Only its ID, its DoT label and, for tenants whose roaming devices the cloud resolver may answer, its SHA-256 [ADR-1050 p5; ADR-1064 p5].
- **The query log, the live tail, the CMDB or discovery data as such, the audit log's contents** [ADR-1047 p8; ADR-1049 p7]. The cloud keeps no query log at rest [ADR-1052 p3]. The one exception is T37.2's name-class counters export, off by default, admin-only and guarded: its batches carry (a) per (device pseudonym, class, UTC day) counters, in which a queried name never appears, only the number of its class in the tenant's class map; and (b) a **device directory entry** for each device with a class-map match in the last 7 days, and no other: a pseudonym keyed on the node, display name, group, device class, OS family, identity certainty, the CMDB owner and the latest private LAN address, nothing more; plus quiet-while-present spans, the `[special]` switch states and the privacy level. So device names, those CMDB fields and a private LAN address do cross the tunnel when the export is on; with it off, none do [ADR-1060 point 1; T37.2].
- **MAC, IP or hostname matchers** in the cloud view. Device bindings there are by opaque device ID, display name and device-key ID only [ADR-1063 point 1; hosted: Two-way sync]. (This is about the synced cloud view; the export's directory entry above does carry a display name and the latest private LAN address, never a MAC or a matcher.)
- **Local records, unless the tenant opted them in separately;** guarded settings; users, tokens, roles and signers' private parts; upstreams and forwards; node-managed and `node_only` entries [ADR-1063 point 1].
- **Anything that would let the cloud act as a cluster member:** no cluster-channel frame, no forwarded write, no role vouching [ADR-1048 p7].

The relayed streams carry the node's own TLS sessions with users and devices; the node sends those bytes, but the cloud cannot read them, because the TLS keys never leave the node [ADR-1047; hosted: Trust boundaries]. Up frames that do carry tenant data (the cloud view, export batches) are defined by their tasks, redacted as API-014 requires.

## 11. Error codes and counted reasons

The records name these codes. Their wire encoding (strings or numbers, in which frame, and how they map onto HTTP/2 `RST_STREAM` and `GOAWAY` codes) is **Open (Q20)**.

| Code | Where | Meaning | Source |
|---|---|---|---|
| `relay_header_refused` | node, per stream | a PROXY header failed §12.2's checks; counted in T36.4's `_relay_header_refused_total` (§13) | hosted: How the node treats a relayed stream; T36.4 |
| budget refusal `{budget}` = `dns` or `ui` | node, per stream | a relayed stream past its budget; counted in T36.4's `_streams_refused_total{budget}` (§13) | ADR-1047 p6 |
| `cloud_unreachable` | node health | the cloud is gone for more than 60 s; degraded, never severe | ADR-1047 p9 |
| `cloud_certificate_expired` | node health | the node's cloud certificate has expired; degraded | hosted: Failure modes |
| `gitops_managed` | `ChangeResult` | a Git-managed cluster rejects cloud edits | hosted: Two-way sync |
| change refusal reasons | `ChangeResult` | every refusal of a signed change has a reason code, audited | T36.15 |
| DoH 404 / DoT REFUSED with an extended DNS error | inside a relayed DNS stream | unknown, revoked or missing device ID, identical within a transport | ADR-1050 p5 |

The values in the budget label (`dns`, `ui`) are this draft's reading of "separate DNS and UI budgets" and are part of Q20.

## 12. Security considerations

### 12.1 Every frame from a node is untrusted input to the cloud
The node is AGPL, so a tenant may run a modified one [ADR-1047 p10]. The service therefore:
- escapes and length-limits every string from a node wherever the portal shows it (T36.9: a heartbeat string with markup is shown escaped);
- checks every CSR name by name against the tenant's slug and its bound cluster [ADR-1051 p1];
- checks dynamic DNS updates against the tenant's records and ranges [hosted: Every frame from a node];
- never believes a `role` or `epoch` claim alone: routing to the primary needs the signed lease and a majority (§5) [ADR-1048 p6];
- takes the node's identity from its client certificate, never from a field;
- validates and caps every compiled list blob and cloud view before the cloud resolver uses them, with per-tenant memory and CPU limits [ADR-1064; hosted: The roaming resolver].

### 12.2 Every byte the broker writes is untrusted input to the node
The PROXY header is the cloud's claim, not a fact, so the node uses its address only to describe and limit, never to authorize [ADR-1047 p4; hosted: How the node treats a relayed stream]:
- A relayed stream is **always remote:** never loopback, never inside `allowed_admin_networks`, never break-glass (ADR-944), whatever its socket address.
- **Identity by key or label only:** it never matches an IP or MAC client rule (ADR-976), never satisfies a wall display's network binding, is never inside `[access] allowed_networks`. A relayed stream with neither a DoH key nor a DoT label is a browser or an agent and must sign in.
- **Header sanity:** the node refuses a relayed stream whose PROXY address is private (RFC 1918, RFC 4193), loopback, link-local, shared address space (RFC 6598) or inside the tenant's own LAN ranges, and counts it as `relay_header_refused`. Which data the node uses as "the tenant's own LAN ranges" is **Open (Q21)**; whether other special-purpose ranges (RFC 6890: documentation, benchmarking, `0.0.0.0/8`, multicast, reserved, IPv4-mapped and NAT64 forms of refused addresses) are also refused is **Open (Q22)**.
- **What the address is for:** rate limits, lockout, the audit log and the query log, marked as reported by the relay, with the relay correlation ID. Step-up lockout is also kept **per account** (10 failed second-factor attempts in 15 minutes lock that account's relayed sign-in for 15 minutes), because the broker could rotate addresses.
- **Refused over the relay unless an admin opts in** (guarded settings): local password sign-in, HTTP Basic, the setup token, sessions created on the LAN, secret writes, guarded settings, backups, user and token management and the `[cloud]` settings. Remote MCP is off by default. Admin and guarded work over hosted names has ADR-1049 point 3's further conditions.
- **Down frames** are untrusted input too: a node accepts membership updates and notices only for its own tenant and a rule's organization and ignores a sequence number it has already seen (T36.24); signed changes and platform content pass their own verification (ADR-1061, ADR-1062) whatever the tunnel says.

### 12.3 The cloud commands nothing
No unsigned command exists, except the power-reducing notices and membership adds bounded by a node-signed group rule (§6.3). Policy changes need an editor's signature and pass the node's own checks; platform content needs the content or release key and runs only actions the owner turned on at home; guarded settings are never reachable from the cloud [ADR-1047 p3; hosted: threat model, "The cloud commands the node"].

### 12.4 What a stolen key or a compromised broker gets
- **A stolen cloud key** lets an attacker pose as the node and receive relayed streams, but they are TLS to the node's own certificate, so without the node's TLS key the attacker gets ciphertext only. Cloud certificates are short-lived and revocable from both sides [hosted: threat model].
- **A removed or stolen member** loses its tunnel within seconds (§9) and cannot capture the cluster name with an unsigned primary claim (§5).
- **A compromised broker** sees SNI, timing, volume and roaming devices' addresses, can deny service, and can write false PROXY headers, which §12.2 contains. A broker that also mints certificates for hosted names is the whole-cloud compromise of hosted.md's blast radius, which the CT watch reports and which then blocks remote access [ADR-1051 p6].
- **A home device on the cloud path** (a second resolver, IPv6 router advertisements, a guest VLAN) is detected from the broker's mark on relayed streams whose source equals the tenant's own tunnel address (T36.7 AC 8; how the mark travels is Q5).

### 12.5 DNS never depends on the tunnel
Nothing on the answer path reads cloud state or waits on the tunnel. Losing the cloud is degraded health only [ADR-1047 p9; CLU-004; AGENTS rule 5].

## 13. Observability on the node
From T36.4: the health reason `cloud_unreachable` (degraded after 60 s), event markers, the metrics `wrendns_cloud_tunnel_up`, `_reconnects_total`, `_streams`, `_streams_refused_total{budget}` and `_relay_header_refused_total`, and the MCP read tool `cloud_status`. T36.4 and hosted.md write the names after the first in this short form; whether the full prefix is `wrendns_cloud_` or `wrendns_cloud_tunnel_` is part of Q20.

## 14. Test vectors

The message schema is open (Q7), so this section fixes vectors only where the encoding is already defined by an external standard or by an accepted record. Vectors for hello, heartbeat, lease and every control frame are added when Q7, Q10 and Q12 are answered; each will give the frame's fields, its exact bytes with the 4-byte length prefix, and, for signed objects, the key, the signed bytes and the signature. Every vector lives as a file under the fake broker's test tree in T36.4, and both the node and the service run it.

### 14.1 PROXY v2 headers (format: the PROXY protocol specification, version 2)
Addresses are documentation ranges. The 12-byte signature is `0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a`.

**V1. IPv4, TCP, no TLVs.** Caller 203.0.113.7 port 51514, edge 198.51.100.10 port 853.
```
0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a  21 11 00 0c
cb 00 71 07  c6 33 64 0a  c9 3a  03 55
```
`21` = version 2, PROXY; `11` = TCP over IPv4; `00 0c` = 12 bytes of addresses and ports. Under the rule as written (§12.2) the node accepts the address; see Q22 for documentation ranges.

**V2. IPv6, TCP, no TLVs.** Caller 2001:db8::7 port 51514, edge 2001:db8:100::a port 853.
```
0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a  21 21 00 24
20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 07
20 01 0d b8 01 00 00 00 00 00 00 00 00 00 00 0a
c9 3a  03 55
```

**V3. IPv4 with the SNI in a `PP2_TYPE_AUTHORITY` TLV (illustrative only; Q5).** Same caller, edge port 443, SNI `example.wrendns.net` (19 bytes).
```
0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a  21 11 00 22
cb 00 71 07  c6 33 64 0a  c9 3a  01 bb
02 00 13  65 78 61 6d 70 6c 65 2e 77 72 65 6e 64 6e 73 2e 6e 65 74
```
`00 22` = 34 = 12 + 3 (TLV type and length) + 19.

**V4. A `LOCAL` command.** `0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a 20 00 00 00`. Expected result: Q6.

### 14.2 Header sanity (§12.2)
| Reported caller address | Expected | Rule |
|---|---|---|
| 10.1.2.3, 172.16.0.1, 192.168.1.20 | refused, `relay_header_refused` | RFC 1918 (T36.4 AC 7) |
| fd12:3456:789a::1 | refused | RFC 4193 |
| 127.0.0.1, ::1 | refused | loopback |
| 169.254.10.1, fe80::1 | refused | link-local |
| 100.64.0.1 | refused | RFC 6598 |
| an address inside the tenant's own LAN ranges | refused | Q21 |
| 203.0.113.7, 2001:db8::7 | accepted under the rule as written | Q22 |
| ::ffff:192.168.1.20 | Q22 | IPv4-mapped form of a refused address |
| a public address equal to a LAN client rule's address | accepted, but no client-rule match | T36.4 AC 7 |

### 14.3 Control-stream framing (ADR-044)
An opaque 2-byte payload `08 01` is framed as `00 00 00 02 08 01`. A length field above 1 MiB (`00 10 00 01` = 1,048,577) is refused without reading the payload. Whether a length of 0 is valid is part of Q7.

### 14.4 Backoff (§8, as this draft reads it; Q17)
| Attempt *n* | Cap `min(300 s, 2^n s)` | Wait drawn from |
|---|---|---|
| 0 | 1 s | 0 to 1 s |
| 1 | 2 s | 0 to 2 s |
| 4 | 16 s | 0 to 16 s |
| 8 | 256 s | 0 to 256 s |
| 9 and later | 300 s | 0 to 300 s |

### 14.5 Behaviour tests the fake broker must run (from T36.4 and T36.5)
These are not byte vectors but are fixed by accepted acceptance criteria: a browser connection by SNI reaches the node's UI and the node logs the real client address; break-glass over the relay is refused even when the socket address is loopback; killing the broker changes no DNS answer and no p99, and health goes degraded after 60 s, never severe; DNS stream 129 is refused with a counted reason while UI streams still open; a removed or modified node claiming `role = primary` with a higher epoch and no majority does not get the cluster name; the TLS private key never appears in any tunnel frame.

## 15. Open questions for the owner

None of these is decided by ADR-1047 to ADR-1052, ADR-1065 or hosted.md. Each is needed before the tunnel client can be built. They are listed for the owner to answer, together, through the question tool; this draft makes no recommendation part of the protocol until then.

1. **Q1. Stream direction.** How does the broker get a new HTTP/2 stream for each public connection, when the node is the HTTP/2 client? (a) the node acts as the HTTP/2 server on the connection it dialled (roles reversed after TLS); (b) the node keeps a small pool of idle streams open for the broker to use; (c) the broker sends an "open" control frame and the node opens the stream.
2. **Q2. Request line and ALPN.** The method, `:path` and `:authority` of the control stream and of relayed streams, and the tunnel's ALPN value.
3. **Q3. TLS versions and suites.** TLS 1.3 only, or 1.2 allowed; how a Pi 4 states its ChaCha20-Poly1305 preference.
4. **Q4. Pins and rollover encoding.** How the tunnel CA key and backup key are stored on the node and compared, how the signed rollover announcement is encoded, and what the node does if neither pinned key nor an announced key matches.
5. **Q5. Per-stream metadata.** Which PROXY v2 TLVs carry the SNI, the relay correlation ID and the "source equals the tenant's tunnel address" mark, or whether they travel in a control frame.
6. **Q6. PROXY `LOCAL` on a relayed stream.** Refused, or treated as something else.
7. **Q7. Message schema.** Reuse the cluster channel's `Frame` type or a separate tunnel type; the `oneof` layout and field numbers; whether a zero-length frame is valid.
8. **Q8. Payloads over 1 MiB.** Chunking, a stream of their own, or a cap below the frame limit, for signed changes with their assertions, class maps, cloud-view digests and list blobs.
9. **Q9. Hello against the certificate.** Which hello fields must equal the client certificate's tenant, cluster and node IDs, and what happens on a mismatch.
10. **Q10. Version negotiation.** How N and N-1 are carried and chosen, whether optional features are named separately, and what is sent before closing on an unsupported version.
11. **Q11. A member's first certificate, and renewal after expiry.** By which path a new member's countersigned first request reaches the cloud without a client certificate, and how the expired-certificate renewal of ADR-1048 point 1 authenticates at the TLS layer.
12. **Q12. The lease.** Its lifetime, its signature encoding and its domain-separation string.
13. **Q13. Heartbeat acknowledgements and liveness.** Whether every heartbeat is acknowledged and what else an acknowledgement carries; after how many missed heartbeats each side declares the other gone.
14. **Q14. Budget classification.** Whether the broker classifies a stream as DNS or UI and tells the node, or the node classifies it from the SNI.
15. **Q15. Overlapping tunnels.** What the broker does with two tunnels from the same node during a reconnect.
16. **Q16. HTTP/2 settings and refusals.** How windows are chosen within the 4–16 KiB and 64–256 KiB ranges, the connection window, the advertised concurrent-stream and frame-size settings, idle timeouts, the control stream's queue bound, and the error a refused stream gets.
17. **Q17. Backoff details.** Confirm the doubling reading of §8; when the attempt count resets; whether the broker may ask a node to wait longer (drain, retry-after).
18. **Q18. A refused certificate.** Whether a node whose serial is denied stops dialling, and the health reason it shows.
19. **Q19. Close reasons.** Whether and how the broker tells a node why it closed a tunnel.
20. **Q20. Error-code encoding.** Strings or numbers, where they travel, the mapping onto HTTP/2 error codes, the budget label values (`dns`, `ui`) and the full metric names of §13.
21. **Q21. "The tenant's own LAN ranges".** Which node data defines them for the header check (for example the CMDB's networks, the locations' networks, `allowed_admin_networks`, or a list in `[cloud]`).
22. **Q22. Other special-purpose addresses.** Whether the header check also refuses documentation, benchmarking, `0.0.0.0/8`, multicast and reserved ranges, and the IPv4-mapped and NAT64 forms of refused addresses.

## 16. References
ADR-039, ADR-044, ADR-057, ADR-118, ADR-143, ADR-944, ADR-976, ADR-1027, ADR-1031, ADR-1047 to ADR-1052, ADR-1060 to ADR-1065, ADR-1069 (`spec/11`); `spec/02` §3 and §8; `spec/12` §5 and §9; `spec/13` §3.2; `docs/design/hosted.md`; T36.4 to T36.24 and T37.2, T37.3 (`spec/10`); RFC 1918, RFC 4193, RFC 5737, RFC 3849, RFC 6598, RFC 6890, RFC 8628, RFC 9113 (HTTP/2); the PROXY protocol specification, version 2 (HAProxy).
