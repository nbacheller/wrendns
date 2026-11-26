# 14 — The Cloud Tunnel Protocol (node to WrenDNS Cloud)

> **Accepted 2026-11-26; nothing in it is built.** This is the first half of T36.4 (`spec/10`). It writes down the protocol that ADR-1047, ADR-1048 and the hosted design (`docs/design/hosted.md`) decided, and the owner's answers to the 22 questions an earlier draft of this document left open (Owner decision, 2026-11-26: every recommended answer of `docs/design/cloud-protocol-answers.md` accepted; recorded as ADR-1098, whose point *n* answers question Q*n*). **Still a draft in exactly two places:** (a) the field numbers inside each message and the byte vectors of hello, heartbeat, lease and the other control frames (§2.4, §14) are written with the tunnel client in T36.4, under the rules of §2.4; (b) the facts listed in §15, "To verify when building", are implementation checks, not statements of fact, until T36.4 checks them. T36.4 stays unticked until the tunnel client is built and tested against the fake broker; its requirement row is CLD-901 (`spec/01`).

## 0. Scope, sources and conventions

**Scope.** The protocol between one full member of a linked WrenDNS cluster (the *node*) and the WrenDNS Cloud *broker* over the outbound tunnel: transport, framing, hello, version negotiation, heartbeats, stream types, limits, reconnect, errors and the security rules both sides follow. It also lists every control frame that later tasks (T36.5 to T37.3) put on the tunnel, with the task that defines its fields. It does not cover the portal's own web pages, the OIDC issuer (the node already speaks OIDC to it, ADR-1049, ADR-1065), the SCIM server, or what happens inside a relayed TLS session (that is the node's ordinary DoT, DoH, UI, API and MCP).

**Sources, in order of authority.** ADR-1047 (the tunnel, SNI passthrough, relayed streams, heartbeats, budgets, untrusted input), ADR-1048 (node cloud identity, enrolment, the tunnel CA, leases, removal), ADR-1098 (the protocol decisions of 2026-11-26), ADR-1049 (authorization on the node), ADR-1050 (names and the roaming path), ADR-1051 (certificates), ADR-1052 (the open-core boundary: this document is the protocol the separate service implements), ADR-1065 (the portal's issuer stays the one identity nodes trust); then `docs/design/hosted.md`, sections "The tunnel", "How the node treats a relayed stream", "Enrolment", "Cluster-aware routing", "Failure modes"; then ADR-039 (PROXY v2 and client IDs), ADR-044 (the cluster channel's framing, which the control stream reuses), ADR-057 (renewal with the same key) and `spec/12` §9 (CLU-010, protocol versioning). `docs/design/cloud-protocol-answers.md` holds the reasoning behind ADR-1098 and is not itself normative. Where this document and an ADR disagree, the ADR wins and this document is wrong.

**Notation.** A bracket after a statement names its source, for example [ADR-1047 p2] for ADR-1047 point 2, [ADR-1098 p5] for the owner's answer to Q5, or [hosted: Enrolment] for a section of the design. A statement with no source is a restatement of one nearby, never a new rule. "To verify (Cn)" points to check *n* of §15.

**Names.** `<suffix>` is the tenant-name domain (the owner chose `wrendns.net`, hosted.md "Owner decisions"); `<slug>` a tenant's cluster slug; `<node>` a node name. Addresses in examples are documentation ranges (RFC 5737, RFC 3849).

## 1. Parties and terms

| Term | Meaning |
|---|---|
| Node | A **full member** of a linked cluster. Only full members dial; resolver pods and witnesses never do [ADR-1047 p1; ADR-1027]. |
| Broker | The cloud program that terminates tunnels and routes public TCP connections into them by TLS SNI, without decrypting them [ADR-1047 p2]. |
| Edge | The one stable dual-stack public address pair for every tenant name and for `tunnel.<suffix>` [ADR-1050 p6; ADR-1052 p4]. |
| Tunnel | One mutually authenticated HTTP/2-over-TLS connection from a node to `tunnel.<suffix>:443` [ADR-1047 p1]. One per full member. The node is the TCP and TLS client and the HTTP/2 **server** (§2.2). |
| Control stream | The one HTTP/2 stream of a tunnel that carries length-prefixed control frames [ADR-1047 p2]. |
| Relayed stream | One HTTP/2 stream carrying the bytes of one public TCP connection the broker accepted, preceded by a PROXY v2 header the broker writes [ADR-1047 p2]. |
| Blob stream | One HTTP/2 stream carrying one large object by its hash, offered on the control stream (§2.5) [ADR-1098 p8]. |
| Helper | The certificate helper that completes DNS-01 for CSRs nodes send over the tunnel [ADR-1051 p1]. |
| Cloud resolver | The multi-tenant DoH and DoT resolver that answers roaming devices while home is unreachable [ADR-1064]. |
| Policy service | The mirror, editor, signing page, queue and parked conflicts of cloud writes [ADR-1061, ADR-1063]. |
| Up / down | Up is node to cloud; down is cloud to node. |

## 2. Transport and framing

### 2.1 TLS and mutual authentication
- The node opens TCP to `tunnel.<suffix>`, port 443, at the edge address, and speaks TLS [ADR-1047 p1].
- **TLS 1.3 only** (RFC 8446). The node's client config allows TLS 1.3 alone (in `rustls`, `with_protocol_versions(&[&rustls::version::TLS13])`, as the DoQ and DoH3 tests already do), and the broker refuses TLS 1.2 [ADR-1098 p3].
- **Cipher suites.** Raspberry Pi 4 lacks the ARMv8 crypto extensions, so ChaCha20-Poly1305 is preferred there; both suites are benchmarked [hosted: The tunnel]. When the CPU has no AES instructions (`std::arch::is_aarch64_feature_detected!("aes")` on arm64, `is_x86_feature_detected!("aes")` on x86-64), the node's client `CryptoProvider` lists `TLS13_CHACHA20_POLY1305_SHA256` first; otherwise it keeps the provider's default order. There is no setting. `cloud_status` shows the negotiated suite [ADR-1098 p3].
- **The broker follows the client's suite order.** This is a rule of the protocol, whatever the broker's TLS library does by default (C1) [ADR-1098 p3].
- **The broker's certificate** for `tunnel.<suffix>` is issued by the cloud's **private tunnel CA**, never a WebPKI CA, and the broker sends the CA certificate in its chain. The node pins that CA's key and one backup key, both delivered at enrolment (§4), as described in §2.1.1 [ADR-1048 p2; ADR-1098 p4].
- **The node's certificate** is its cloud client certificate (about 30 days, carrying tenant, cluster and node IDs) for its own Ed25519 cloud key in `<data_dir>/cloud/` [ADR-1048 p1]. The broker checks it on every connection and refuses a denied serial with a TLS alert (§8.2) [ADR-1048 p6; ADR-1098 p18].
- No new runtime crate: `h2`, `hyper` and `rustls` are already linked [ADR-1047 p1; AGENTS rule 8].

#### 2.1.1 The tunnel CA pins and their rollover [ADR-1048 p2; ADR-1098 p4]
- **What is pinned:** the tunnel CA's **public key**, not its certificate. The node stores the DER `SubjectPublicKeyInfo` (SPKI) of the current key and of the backup key, and compares SHA-256 hashes of SPKI DER (the `pin-sha256` form of RFC 7469 §2.4). It keeps the keys themselves, not only their hashes, because it needs the current key to verify a rollover announcement.
- **Where:** `<data_dir>/cloud/tunnel-ca.json`, `{current_spki, backup_spki, pending: [{spki, not_before}]}`, written atomically, mode 0600 like the rest of `<data_dir>/cloud/`. The file holds no secret, but it decides whom the node trusts.
- **Verification:** a custom `ServerCertVerifier`, like `PinnedCa` in the cluster channel. It finds the certificate in the broker's chain whose SPKI matches a pin, builds a one-root store from that certificate, and runs WebPKI path validation of the leaf for `tunnel.<suffix>`, including the leaf's dates.
- **Rollover announcement:** the field `ca_rollover` of `BrokerHello` (§3), `CaRollover { signed: bytes, sig: bytes }`. `signed` is a prost-encoded `{seq, new_spki, new_backup_spki, not_before, issued}`; `sig` is Ed25519 by the **current** CA key over `"wrendns-tunnel-ca-rollover-v1" || 0x00 || signed`. The node parses `signed` only after the signature verifies. It accepts an announcement only when `not_before` is at least 30 days after `issued` and `seq` is above any announcement it has already accepted, and then stores the new key as pending. From `not_before`, the node accepts both the old and the new key. After its first successful connection under the new key, the new key becomes current, the old key is dropped, and the announced backup becomes the backup.
- **Backup:** the cloud keeps the backup key offline. A broker certificate chained to the backup key is accepted at once, with no announcement; that is the recovery path when the current key is lost or compromised. The cloud then announces a new backup, signed with the key now in use.
- **No match:** the node refuses the connection, raises the health reason **`cloud_tunnel_untrusted`** (degraded; DNS unaffected) and writes the event to the audit log. It keeps retrying with backoff (§8), because a new pin can reach it only on a connection it already trusts. The fix is to link again.

### 2.2 The HTTP/2 connection [ADR-1047 p2; ADR-1098 p1, p2]
- One HTTP/2 connection per tunnel. **After TLS the HTTP/2 roles are reversed: the node is the HTTP/2 server on the connection it dialled, and the broker is the HTTP/2 client.** The broker opens the control stream first, then one stream for each public connection it accepts for that node, and the blob streams of §2.5. The node never opens a stream. (In HTTP/2 only the client opens streams and sends the connection preface, RFC 9113 §3.4 and §5.1.1; the reversal lets the broker open a stream the moment a caller connects, with no extra round trip.) On the node, `hyper`'s HTTP/2 server serves the connection over its TLS client stream; the fake broker runs `hyper`'s HTTP/2 client over its TLS server stream. TLS identity is unaffected: the node verifies the pinned tunnel CA and the broker verifies the node's client certificate.
- **ALPN:** `wrendns-tunnel/1` alone, never `h2` (a peer that negotiated `h2` would expect to be the HTTP/2 client). A misdirected client, such as a browser that reached `tunnel.<suffix>` at the shared edge address, fails at the handshake with `no_application_protocol` (RFC 7301 §3.2).
- **Request lines** (all with `:scheme https` and `:authority tunnel.<suffix>`):

| Stream | Method and `:path` | Bodies |
|---|---|---|
| Control | `POST /tunnel/v1/control`, the broker's first stream | both bodies stream control frames (§2.4) for the life of the connection, as the cluster channel's `POST /cluster/v1/stream` |
| Relayed | `POST /tunnel/v1/relay` | the request body starts with the PROXY v2 header (§2.3) and then carries the caller's bytes; the response body carries the node's bytes. The node answers `200` once the header has passed its checks (§12.2), or a refusal (§7.1) |
| Blob, node to cloud | `GET /tunnel/v1/blob/<sha256>` | the node's response body is the object |
| Blob, cloud to node | `PUT /tunnel/v1/blob/<sha256>` | the broker's request body is the object |

- No stream carries request headers beyond the pseudo-headers; per-stream facts travel in the PROXY header (§2.3). A fixed `:path` per stream type lets the node route a request without reading its body.

### 2.3 Relayed streams: the stream preface [ADR-1047 p2, p4; ADR-1098 p5, p6]
- Each relayed stream **starts with a PROXY protocol v2 header** written by the broker, carrying the caller's address and port and the per-stream facts below, then carries the raw bytes of the public connection in both directions [ADR-1047 p2]. The bytes are the caller's TLS session with the node: TLS ends on the node, so the broker sees ciphertext, the SNI, timing and volume [hosted: Trust boundaries].
- The node hands the stream to its own TLS acceptors **in-process**, as an in-memory stream with a "relayed" context flag and the header's fields. It is never a real socket, and no listener needs `proxy_protocol = true`; ADR-039's PROXY rule for sockets is unchanged [ADR-1047 p4].
- Only PROXY v2 is defined (v1 text headers are not part of this protocol; ADR-039 already refuses them on sockets). The header is at most 1,024 bytes, the cap the node's PROXY reader already applies.
- **Per-stream facts, in TLVs of the stream's own header** (TLV types of the PROXY protocol specification, version 2; C2):

| Fact | TLV | Value |
|---|---|---|
| The caller's TLS SNI | `PP2_TYPE_AUTHORITY` (`0x02`) | the exact `server_name` from the caller's ClientHello, ASCII, 1 to 253 bytes. **Required.** |
| The relay correlation ID [hosted: How the node treats a relayed stream] | `PP2_TYPE_UNIQUE_ID` (`0x05`) | 16 random bytes from the broker |
| The broker's marks | one custom TLV, `0xE0` (`PP2_TYPE_MIN_CUSTOM`) | 1 byte of flags: bit 0 means "the source equals the tenant's own tunnel address" (T36.7 AC 8); the other bits are sent as 0 and ignored on receipt |

- Each of these TLVs appears at most once. A header without AUTHORITY, or with a known TLV repeated, is refused as `relay_header_refused`. TLV types not in the table are skipped, as the node's PROXY reader skips them today (C2). `PP2_TYPE_CRC32C` is not used: the tunnel's TLS already protects the bytes.
- **The SNI is checked against the ClientHello.** After the inner TLS handshake, the node compares the server name it saw in the caller's ClientHello with the AUTHORITY TLV and closes the stream on a mismatch, counted as `relay_header_refused` (reason `sni_mismatch`). Once the handshake completes, the broker cannot have altered the ClientHello undetected, because the handshake transcript covers it. The TLV is used only to classify the stream before TLS (§6.1).
- **`LOCAL` is refused.** A `LOCAL` command, or a `PROXY` command with family `AF_UNSPEC` or `AF_UNIX`, ends the stream as `relay_header_refused` (reason `local_command`). A relayed stream has no socket address to fall back to, and the broker checks liveness on the control stream (§5), so it never needs `LOCAL`.
- The header is untrusted input to the node; §12.2 lists what the node checks.

### 2.4 The control stream: framing and schema [ADR-1047 p2; ADR-044; ADR-1098 p7]
- Control frames use the cluster channel's framing: a **4-byte big-endian length, then one prost-encoded frame** [ADR-1047 p2; ADR-044 "Wire"]. A frame longer than **1 MiB** is refused without reading its payload [ADR-044; hosted: The tunnel].
- **The tunnel has its own message type,** `TunnelFrame { oneof body }`, in its own module, apart from the cluster `Frame`. The two share only the framing code (the length prefix, the 1 MiB cap and the decode loop, made generic over the message type). No cluster-channel frame can be decoded on the tunnel at all [ADR-1048 p7].
- **Tag blocks.** `oneof` tags are assigned in blocks by task, so later tasks never collide; tags 1 to 15 encode in one byte and go to the frequent frames:

| Tags | Task | Frames |
|---|---|---|
| 1 to 15 | T36.4 | `NodeHello` 1, `BrokerHello` 2, `Heartbeat` 3, `HeartbeatAck` 4, `Close` 5, `BlobOffer` 6, `BlobDone` 7; 8 to 15 reserved |
| 16 to 31 | T36.5 | certificates, members, disconnect |
| 32 to 47 | T36.7, T36.8 | certificates for hosted names, device keys |
| 48 to 63 | T36.11, T36.12 | dynamic DNS, list blobs, roaming events |
| 64 to 95 | T36.15, T36.16, T36.18 | changes, cloud view, platform content |
| 96 to 127 | T36.24, T37.2, T37.3 | memberships, notices, class map, export |

```proto
// spec/14 §2.4, the tunnel's top-level message (proto3). Tags decided by ADR-1098 point 7.
// The messages' own fields are numbered with the tunnel client in T36.4, under the evolution rule below.
message TunnelFrame {
  oneof body {
    NodeHello    node_hello    = 1;
    BrokerHello  broker_hello  = 2;
    Heartbeat    heartbeat     = 3;
    HeartbeatAck heartbeat_ack = 4;
    Close        close         = 5;
    BlobOffer    blob_offer    = 6;
    BlobDone     blob_done     = 7;
    // 8 to 15 reserved for T36.4; 16 and up assigned by block (table above).
  }
}
```

- **Evolution:** fields are only ever added, never renumbered; a removed field's number is reserved; the protocol version (§3) is raised only when a message changes meaning.
- **A zero-length frame is invalid:** the receiver closes with `Close{protocol_error}` (§9). A frame with a nonzero length whose `body` decodes as unset (a frame type from a newer peer, skipped by prost as an unknown field) is **ignored and counted**, so N and N-1 still interoperate.
- **The normative schema is the proto3 text in this section.** The node writes its prost structs by hand, as ADR-044 does (no code generation step). The service is written from this document and its test vectors, never from the node's code [ADR-1052 p2]; the vectors of §14, run by both sides, check that the two agree. §6.3 lists every frame.

### 2.5 Large objects travel by reference [ADR-1098 p8]
- The 1 MiB cap holds for every control frame. Large objects travel **by reference, on a blob stream of their own**, as the cluster channel moves blobs (`GET /cluster/v1/blob/<hash>`).
- The sender puts `BlobOffer { kind, sha256, size }` on the control stream. Because only the broker opens streams (§2.2), the broker opens the blob stream in both directions: `GET /tunnel/v1/blob/<sha256>` to fetch from the node, `PUT /tunnel/v1/blob/<sha256>` to deliver to it.
- The receiver checks `size` against that kind's own cap before it reads anything, hashes as it reads, and refuses a mismatch. It acknowledges with `BlobDone { sha256, ok, reason }`.
- **The same kinds always go by reference, whatever their size:** `CloudChange` and `ProposedChange` (up to 1 MiB of patch plus the envelope and assertion, ADR-1061), `CloudView` deltas and digests, `ListBlob`, `PlatformContent` (which carries the class map), `RoamingEvents` batches and `ExportBatch`. Every other frame stays inline, with its own cap well below 1 MiB. Each kind's cap is fixed by the task that defines the kind.
- Blob streams count against neither the DNS nor the UI budget: at most 2 concurrent blob streams in each direction, with a 64 KiB window (§7.1).

### 2.6 QUIC later
QUIC (`quinn` is linked) is added later as the preferred transport with HTTP/2 as the fallback [ADR-1047 p1]. This document defines the HTTP/2 transport only. Over QUIC both endpoints can open bidirectional streams (RFC 9000 §2.1), so the role reversal of §2.2 is needed only for HTTP/2; `Close` (§9) is a control frame so that it carries over. How a node chooses between the transports, and whether the framing above carries over unchanged, are left to that later change.

## 3. Hello and version negotiation [ADR-1048 p2; ADR-1098 p9, p10]

- **Both sides send a hello** at the start of the control stream. ADR-1048 point 2's "a rollover ... is announced in the hello message" is the broker's hello.
- **`NodeHello { tenant_id, cluster_id, node_id, instance, protocol, min_protocol, features }`.** `tenant_id`, `cluster_id` and `node_id` must all equal the client certificate's values. On a mismatch the broker sends `Close{identity_mismatch}`, writes the event to the tenant's event log, routes nothing to the tunnel and closes it. The broker never uses these fields for anything else: identity comes from the certificate (§12.1). `instance` is new at each process start, as the cluster `Hello`'s (ADR-1018), and serves §6.2's overlap rule.
- **`BrokerHello { protocol, tenant_id, slug, ca_rollover }`** carries the version the broker chose, the tenant ID and slug the broker holds for this certificate, and any rollover announcement (§2.1.1). The node checks `tenant_id` and `slug` against its own binding and, on a mismatch, closes the tunnel and raises `cloud_tunnel_untrusted`.
- **Versions: N and N-1.** The tunnel protocol is versioned, and each side accepts its own version N and the previous one, N-1 [T36.4; CLU-010 in `spec/12` §9]. `NodeHello.protocol` is the node's N and `min_protocol` its N-1. **The broker picks** the highest version both support and sends it in `BrokerHello.protocol`; it is the side that serves every node version at once during a rollout.
- **Features** are named, versioned frame groups the node implements, for example `certs-v1`, `changes-v1`, `export-v1`. The broker sends a group's frames only to a node that lists it. Adding a feature never raises the protocol version. Each task that adds a group names it.
- **Unsupported version:** the broker sends `BrokerHello { protocol: 0 }`, then `Close { reason: version_unsupported, supported_min, supported_max }`, and closes. The node raises **`cloud_version_unsupported`** (degraded; the panel says to update the node) and retries at the backoff cap (§8).
- Because every frame from a node is untrusted input (§12.1), the broker never relies on a node's stated version or features to decide what it may do; they decide only which encoding to use and which frames to send.

## 4. Node identity and enrolment (references to ADR-1048)

This protocol relies on, and does not change, these points of ADR-1048. Their frames are T36.5's.

| Step | What happens | Source |
|---|---|---|
| Link | An admin on the primary starts linking from Settings → WrenDNS Cloud or `wrendns cloud link`. The node calls the portal outbound for an RFC 8628 device code (10 minutes, single use, rate limited); a tenant admin enters it at `dns.wrendns.com/link` on a confirmation page that names the requesting cluster, its nodes, its source address and rough region and its version. Headless and Kubernetes installs use a `wren_enrol_...` token from a secret file instead. | ADR-1048 p3 |
| Binding | The polling node receives the tenant ID, the slug, the hosted issuer's URL and the tunnel CA's public key and backup key (§2.1.1). Each slug is bound to one cluster. | ADR-1048 p2, p4; hosted: Enrolment |
| Keys | Each full member makes its own Ed25519 cloud key, mode 0600, node-local, never replicated, never a stored secret. | ADR-1048 p1 |
| Certificate | The cloud CA issues a client certificate of about 30 days carrying tenant, cluster and node IDs. | ADR-1048 p1 |
| Members | The primary countersigns each member's first certificate request over the cluster channel, so joining the cluster is enough to bring a member online. | ADR-1048 p3 |
| Renewal | Over the tunnel at two thirds of the certificate's life, with the same key (as ADR-057). | ADR-1048 p1 |
| Long offline | A node offline past expiry renews with its cloud key plus a fresh countersignature from the current primary, within 180 days of expiry, unless removed; after that it links again. | ADR-1048 p1 |
| Linking is guarded | Linking and unlinking are admin-only guarded settings, never for agents, audited on both sides. | ADR-1048 p5 |

**A new member's first certificate goes through the primary's tunnel, countersigned** [ADR-1098 p11]. The member makes its cloud key and sends a request signed with that key to the primary over the cluster channel. The primary countersigns it and sends `MemberCertRequest` up its own tunnel; the cloud CA issues the certificate, `CloudCert` comes back down to the primary, and the primary passes it to the member over the cluster channel. The countersignature is Ed25519 with the primary's cloud key over `"wrendns-tunnel-countersign-v1" || 0x00 || signed`, where `signed` is `{tenant_id, cluster_id, node_id, member_spki, issued, expires}` and `expires` is at most 10 minutes after `issued`. The cloud checks it against the primary's current certificate and its majority-confirmed lease (§5). No endpoint on the broker accepts a client without a certificate.

**Renewal after expiry uses a renew-only tunnel** [ADR-1098 p11]. Within the 180-day grace, the broker's client verifier accepts an **expired** certificate whose serial is not denied and marks the connection renew-only; TLS still proves possession of the key through CertificateVerify. On a renew-only connection the broker accepts only `NodeHello`, then one `CloudCertRenew` that carries a fresh countersignature; it routes nothing and closes once it has answered. A one-node cluster countersigns its own request, as its own primary. For a member of a larger cluster, the primary's countersignature can also arrive through the primary's tunnel, as for a first certificate.

## 5. Heartbeats [ADR-1047 p5; ADR-1048 p6; ADR-1098 p12, p13]

- **Cadence:** every **20 s**, below the 4-minute idle timeout of Azure's and most middleboxes' defaults [ADR-1047 p5; hosted: The tunnel].
- **Fields of every node heartbeat** [ADR-1047 p5]:

| Field | Meaning | Notes |
|---|---|---|
| `seq` | the heartbeat's sequence number | echoed by the acknowledgement [ADR-1098 p13] |
| `node_id` | the sending node | must match the client certificate; the broker believes the certificate, not the field (§12.1) |
| `cluster_id` | its cluster | as above |
| `role` | the node's cluster role as it claims it | never believed alone (below) |
| `epoch` | the fencing epoch the node holds (`spec/12` §5) | never believed alone |
| `ready` | whether the node is ready to serve | an unready node is not routed to [ADR-1047 p7] |
| `version` | the WrenDNS version | a string from the node: length-limited and escaped wherever shown [ADR-1047 p10] |
| `maintenance` | whether the node is in maintenance (ADR-118) | a node in maintenance is not routed to [ADR-1047 p7] |

- **The primary's lease** [ADR-1048 p6; ADR-1098 p12]. The primary's heartbeat also carries `Lease { signed: bytes, sig: bytes }`. `signed` is a prost-encoded `{tenant_id, cluster_id, node_id, epoch, issued, expires}`, times in Unix seconds (ADR-1048 point 6's `{cluster_id, node_id, epoch, expires}` with the tenant, against replay across tenants, and the issue time). `sig` is Ed25519 by the primary's cloud key over `"wrendns-tunnel-lease-v1" || 0x00 || signed`. The broker verifies `sig` with the public key in the tunnel's own client certificate before it parses `signed`, and refuses a lease whose `node_id` is not the certificate's.
  - **Lifetime:** 60 s (three heartbeats), re-signed in every heartbeat of the primary. The broker treats a lease as valid until `min(expires, received + 60 s)`. It refuses a lease whose `expires` is already past, or more than 5 minutes ahead of the broker's clock, so a node with a bad clock cannot hold the name indefinitely. It keeps the highest confirmed epoch for each cluster and never routes to a lease with a lower epoch.
  - The broker routes `<slug>.<suffix>` to the lease holder only when a majority of the tenant's connected tunnels report the same primary and epoch (for a one-node cluster, the node itself) [ADR-1048 p6; hosted: Cluster-aware routing].
- **Added by later tasks:** the group IDs that the node's signed group rules name, so the cloud sends membership updates only for those groups (T36.24).
- **Every heartbeat is acknowledged** (down): `HeartbeatAck { seq, broker_time, platform_hints, class_map_version }`, where `seq` echoes the heartbeat, `platform_hints` are the version hints of the platform channel [hosted: The platform channel] and `class_map_version` is the current class map's (T37.3). The node uses it for the round trip and the clock offset shown in `cloud_status`.
- **Liveness: gone after three missed intervals (60 s)** on each side, as ADR-044 uses three intervals for the cluster. The node closes the tunnel, reconnects with backoff (§8), and raises the health reason `cloud_unreachable`, degraded and never severe, once 60 s have passed since its last acknowledgement [T36.4; ADR-1047 p9]. The broker stops routing to a node 60 s after its last heartbeat, and at once on a connection error or when the node turns unready or enters maintenance.
- **HTTP/2 PING** keep-alive on the node's server connection, every 20 s with a 20 s timeout, as the cluster channel sets its keep-alive. It catches a dead TCP path even while the control stream's writer is backed up.

## 6. Stream types and multiplexing

### 6.1 Data streams
| Type | What it carries | Where it is routed from | Budget class |
|---|---|---|---|
| Relayed DNS | DoT (853) and DoH (443) for the DNS site `<slug>-dns.<suffix>` and its DoT labels `<dot-label>.<slug>-dns.<suffix>` | broker, by SNI; unknown DoT labels and unknown slugs are refused at the broker before any byte reaches a node | DNS |
| Relayed UI | the node's UI, API and MCP at `<slug>.<suffix>` (primary first, sticky) and `<node>.<slug>.<suffix>` (that node); verified custom names later (phase 2) | broker, by SNI | UI |
| Blob | one large object (§2.5) | the broker, after a `BlobOffer` | its own limit |

Sources: ADR-1047 p2, p6, p7; ADR-1050 p1 and its ADR-1064 amendment; hosted: Device keys and the open-resolver gate. Routing is by SNI only, to the tunnel whose client certificate holds that slug, never by a header [hosted: threat model, "Cross-tenant routing"].

**The node classifies each relayed stream** from the AUTHORITY TLV (§2.3) before it reads further [ADR-1098 p14]:
- `<slug>-dns.<suffix>` and any one label under it: the **DNS** budget;
- `<slug>.<suffix>` and `<node>.<slug>.<suffix>` (and verified custom names in phase 2): the **UI** budget;
- any other name: refused as `relay_header_refused` (reason `unknown_name`).

On a relayed UI-name stream the node does not serve `/dns-query`; roaming DNS uses the DNS site only (ADR-1064). The budget lives only on the node, which enforces it; a broker that lies in the TLV is caught by the ClientHello check (§2.3) and can only deny service, which it could do anyway.

### 6.2 Routing rules the broker applies (summary)
- `<slug>.<suffix>`: the connected member holding a valid primary lease confirmed by a majority, else a ready replica in a stable order (lowest node ID); re-routed only when the target disconnects, turns unready, enters maintenance, or a new lease is seen [ADR-1047 p7].
- `<node>.<slug>.<suffix>`: always that node [ADR-1047 p7].
- The DNS site: the home node while a ready member is connected, else the cloud resolver; when home returns, idle connections to the cloud resolver are closed within 5 minutes [ADR-1064; T36.8].
- **Overlapping tunnels: the newest wins** [ADR-1098 p15]. When a second tunnel authenticates with the same tenant, cluster and node, the broker routes new streams only to the new tunnel, sends the old one `Close{superseded}` and lets its relayed streams finish for at most 30 s before closing it. When two different `instance` IDs (§3) keep replacing each other (more than 3 times in 10 minutes), the broker records `duplicate_node` in the tenant's event log, and the portal shows that two processes are using one cloud key.

### 6.3 Control frames
"Defined by" is the task that fixes the frame's fields and tests; T36.4 defines only the first group. Tags follow the blocks of §2.4. "By ref." marks the kinds that always travel as blobs (§2.5): their frame on the control stream is a `BlobOffer` of that kind.

| Frame | Dir | What it carries | Defined by | Source |
|---|---|---|---|---|
| `NodeHello` | up | tenant, cluster and node IDs, instance, protocol and min_protocol, features (§3) | T36.4 | ADR-1047 p2, ADR-1098 p9, p10 |
| `BrokerHello` | down | the chosen protocol, tenant ID and slug, any signed tunnel CA rollover (§2.1.1) | T36.4 | ADR-1048 p2, ADR-1098 p4, p9, p10 |
| `Heartbeat` | up | §5 fields, the primary's lease | T36.4, T36.5 | ADR-1047 p5, ADR-1048 p6, ADR-1098 p12 |
| `HeartbeatAck` | down | seq, broker time, platform hints, class-map version | T36.4, T36.18, T37.3 | hosted: The platform channel, ADR-1098 p13 |
| `Close` | both | reason, retry_after_s, message; for `version_unsupported` also supported_min and supported_max (§9) | T36.4 | ADR-1098 p10, p17, p19 |
| `BlobOffer` / `BlobDone` | both | a large object's kind, hash and size; its acknowledgement (§2.5) | T36.4 | ADR-1098 p8 |
| `CloudCertRenew` / `CloudCert` | up / down | renewal of the node's cloud certificate with the same key; long-offline renewal with the primary's countersignature on a renew-only tunnel (§4) | T36.5 | ADR-1048 p1, ADR-1098 p11 |
| `MemberCertRequest` | up (primary) | a new member's countersigned first certificate request; answered by `CloudCert` (§4) | T36.5 | ADR-1048 p3, ADR-1098 p11 |
| `MemberRemoved` | up (primary) | a member removed from the registry, sent at once | T36.5 | ADR-1048 p6 |
| `Disconnect` | up | the node has deleted its cloud key | T36.5 | ADR-1048 p6 |
| `CertRequest` / `CertChain` | up / down | the node's TLS CSR for its hosted names; the chain from the helper | T36.7 | ADR-1051 p1 |
| `IssuanceLog` | down (on request) | the helper's signed issuance log, for the CT watch | T36.7 | ADR-1051 p6 |
| `DeviceKeyRegistered` / `DeviceKeyRevoked` | up | device-key ID, DoT label, and for the cloud resolver the SHA-256 of the DoH key; never the key | T36.8 | ADR-1050 p5 |
| `DynamicDnsUpdate` | up (primary) | a location's IPv6 address (IPv4 is the tunnel source the broker sees) | T36.11 | hosted: Managed names and dynamic DNS |
| `ProposedChange` (by ref.) | down | an unsigned patch the node only displays on its signing page; changes nothing | T36.15 | ADR-1061 p1, ADR-1047 p3 |
| `CloudChange` (by ref.) | down | a signed change (envelope and assertion) | T36.15 | ADR-1061 |
| `SignerRequest` | down | a pending portal signing passkey; pending until confirmed on the LAN | T36.15 | hosted: The user channel |
| `SignerSuspended` | down | a signer suspended by a tenant admin (removes power only) | T36.15 | hosted: The user channel |
| `ChangeResult` | up | Applied, Conflict (with home's version) or Rejected (with the reason), then Accepted | T36.15, T36.16 | ADR-1063 |
| `CloudView` (by ref.) / `CloudViewDigest` (by ref.) / `AcceptedStatement` | up (primary) | the signed cloud-view delta after each stable version, the hourly full digest, the signed Accepted statement | T36.16 | ADR-1063 |
| `PlatformContent` (by ref.) / `KeyManifest` / `Timestamp` | down | signed content, the key manifest (also fetched from wrendns.com), the hourly freshness statement | T36.18 | ADR-1062 |
| `ListBlobRequest` / `ListBlob` (by ref.) | down / up | the cloud resolver fetching a compiled list blob from home | T36.12 | ADR-1064 |
| `RoamingEvents` (by ref.) | down | query events the cloud resolver answered, shipped home through a bounded buffer after the privacy level | T36.12 | ADR-1052 p3 |
| `MembershipUpdate` | down | organization, group, subject, add or remove, SCIM event ID, sequence | T36.24 | ADR-1069 |
| `SubjectDisabled` / `SubjectRelinked` | down | deprovisioning and re-link notices (remove power only) | T36.24 | ADR-1069 |
| `ClassMapRequest` | up | the node asking for the class map | T37.2 | ADR-1060 |
| `ExportBatch` (by ref.) / `ExportReply` | up / down | one counters batch per cluster every 5 minutes; the reply's acknowledgement and groups to omit | T37.2 | ADR-1060 |

Every down frame that changes anything on the node is signed by a key the node trusts, except the power-reducing notices (`SignerSuspended`, `SubjectDisabled`, `SubjectRelinked`, a membership remove) and a membership add, which counts only under a group rule a node admin signed [ADR-1047 p3; hosted: Cloud writes]. `ProposedChange` changes nothing by itself.

**Signing domains.** Every signature this protocol defines is Ed25519 over `domain || 0x00 || signed`, where `signed` is the exact bytes sent and is parsed only after the signature verifies, in the `wrendns-<object>-v1` family of ADR-1061, ADR-1062 and ADR-1063: `wrendns-tunnel-ca-rollover-v1` (§2.1.1), `wrendns-tunnel-countersign-v1` (§4) and `wrendns-tunnel-lease-v1` (§5) [ADR-1098 p4, p11, p12]. The domains keep a signature by one key valid for one kind of object only.

## 7. Flow control and limits

### 7.1 On the node [ADR-1047 p6; hosted: The tunnel; ADR-1098 p16]
- **DNS budget:** at most **128** concurrent relayed DNS streams.
- **UI budget:** at most **32** concurrent relayed UI, API and MCP streams.
- **Blob limit:** at most **2** concurrent blob streams in each direction (§2.5).
- A stream past its budget is **refused with a counted reason, never queued** (`wrendns_cloud_tunnel_streams_refused_total{budget}`, §13). T36.4 AC 11: DNS stream 129 is refused while UI streams still open.
- **Frame limit:** 1 MiB (§2.4).
- **Memory targets:** at most +2 MiB RSS idle and +12 MiB with both budgets full, measured against ADR-1031's 32 and 128 MiB gates [ADR-1047 p6].
- **Isolation from DNS:** the tunnel runs as its own task with bounded queues and no lock shared with the DNS pipeline; a UI burst must not show in DNS p99 [ADR-1047 p9; `spec/02` §3, §8].
- **ADR-1047 point 6's window ranges** (4 to 16 KiB for DNS, 64 to 256 KiB for UI) are read as **bounds on memory per stream**: 16 KiB inbound for every stream, and an outbound queue sized by class (C3). 128 × 16 KiB + 32 × 256 KiB is 10 MiB, within the +12 MiB target.
- **HTTP/2 settings and constants.** Fixed constants, measured in T36.4 against the RSS targets above and changed only after a measurement; there is no setting:

| Item | Value |
|---|---|
| Node's receive window per stream (`SETTINGS_INITIAL_WINDOW_SIZE`) | 16 KiB for every stream |
| Node's connection receive window | 1 MiB (a hard bound on inbound bytes buffered across all streams) |
| Node's send buffer per stream (its own bounded queue between the inner TLS session and the stream) | DNS 16 KiB, UI 256 KiB, blob 64 KiB |
| Broker's receive windows (for the node's sends) | DNS 16 KiB, UI 256 KiB, raised per stream with `WINDOW_UPDATE` |
| `SETTINGS_MAX_CONCURRENT_STREAMS` from the node | 165 = 128 DNS + 32 UI + 1 control + 4 blob (a hard ceiling; the per-class budgets are enforced above it) |
| `SETTINGS_MAX_FRAME_SIZE`, both sides | 16,384, the default (RFC 9113 §6.5.2) |
| `SETTINGS_MAX_HEADER_LIST_SIZE` | 8 KiB |
| `SETTINGS_ENABLE_PUSH` from the broker | 0 |
| Idle timeout of relayed streams | none at tunnel level: the inner DoT, DoH and UI servers' own idle and handshake timeouts apply, because the stream is handed to the same acceptors |
| Control stream queue | 16 frames each way, as the cluster channel. When it is full, heartbeats are dropped and counted, never queued: the next heartbeat replaces a dropped one |
| A refused stream | an HTTP response, not `RST_STREAM`: `503` for a budget refusal, `400` for a header refusal, each with a `wrendns-reason` header (§11); the broker then closes the caller's connection |

`REFUSED_STREAM` (RFC 9113 §8.7) is not used for a refusal: it means "not processed, safe to retry", which is wrong for a header refusal.

### 7.2 At the broker
- A per-node bandwidth cap, configurable from 2 to 5 Mbit/s, to protect home uplinks and the broker [hosted: The remote UI].
- Per-tenant caps on streams, bandwidth and connections [hosted: threat model, "Reconnect storms, floods"].
- Unknown slugs and unknown DoT labels are refused before any byte reaches a node [hosted: Device keys and the open-resolver gate].
- Dynamic DNS updates are rate limited (one a minute, TTL 60 s), and private or reserved addresses are refused [hosted: Managed names and dynamic DNS].

## 8. Reconnect and backoff

### 8.1 Backoff [ADR-1047 p5; ADR-1098 p17]
- The node reconnects with **full-jitter backoff from 1 s to a 5-minute cap**, longer than ADR-044's 30 s, so a broker restart does not cause a thundering herd [ADR-1047 p5].
- The cap for attempt *n* (counting from 0) is `min(300 s, 1 s × 2^n)`; the wait is drawn uniformly from 0 to that cap, with a floor of 200 ms, as the cluster channel's backoff.
- **Reset:** the attempt count resets only after a tunnel has stayed up, with the hellos exchanged, for at least 60 s, the cluster channel's rule. A completed hello alone does not reset it, so a broker that accepts and then drops the connection cannot cause a tight loop.
- **The broker may ask for a longer wait** with `Close { retry_after_s }`, for a drain before a planned restart (the broker spreads the values) and for overload. The node waits `max(its own backoff draw, retry_after_s)`, with `retry_after_s` clamped to 300 s. A broker can deny service anyway, so honouring the field gives it no new power, and the clamp keeps ADR-1047's 5-minute cap.
- Reconnecting never touches DNS answering; nothing on the answer path waits on the tunnel [ADR-1047 p9; CLU-004].

### 8.2 A refused certificate [hosted: Failure modes; ADR-1098 p18]
- The broker refuses at the TLS layer with the standard alerts (RFC 8446 §6.2): `certificate_revoked` for a denied serial, `certificate_expired` for a certificate past the 180-day grace. Within the grace, an expired certificate gets a renew-only tunnel (§4). The node can trust the alert, because in TLS 1.3 it has already verified the pinned broker before it sends its own certificate.
- **Denied serial:** the node stops automatic dialling and raises **`cloud_node_removed`** (degraded; DNS unaffected). The panel says the node was removed from the cloud and offers "Link again" and "Retry now". The node then tries once a day, in case the removal was a mistake that was undone in the portal.
- **Past the grace:** `cloud_certificate_expired` (degraded), the same stop and daily retry, and the panel says to link again.
- **Expired within the grace, and no countersignature available** (the primary is unreachable): normal backoff, and `cloud_certificate_expired` stays raised.

## 9. Removal, revocation and closing

- **Remove node** in the portal closes that node's tunnel and denies its certificate serial at once [ADR-1048 p6].
- **Disconnect** on the node deletes the cloud key and tells the cloud (`Disconnect`) [ADR-1048 p6].
- **Registry removal:** when a member is removed from the cluster registry (ADR-143), the primary tells the cloud at once (`MemberRemoved`); the cloud denies that node's serial, closes its tunnel, and the helper revokes its TLS certificates for the tenant's names. T36.5 AC 4: within 5 s [ADR-1048 p6].
- **Suspension** of a tenant refuses its relay at the broker; certificate renewal through the helper continues (the home keep-alive) [ADR-1051 p2].
- **Close reasons** [ADR-1098 p19]. Before closing, the side that closes sends `Close { reason, retry_after_s, message }` on the control stream, then HTTP/2 `GOAWAY` with `NO_ERROR`, lets in-flight streams finish for up to 30 s, and closes TLS with `close_notify`. `message` is at most 256 bytes, for display only, and is shown escaped. The broker's reasons are `removed`, `suspended`, `superseded`, `identity_mismatch`, `version_unsupported`, `draining`, `overloaded` and `protocol_error`; revocation and expiry are TLS alerts (§8.2). The node closes with `Close{shutdown}`, or with `Disconnect` (T36.5). The reason travels in the protocol's own frame because GOAWAY's debug data carries no semantic value (RFC 9113 §6.8), and the frame carries over to QUIC.

## 10. What the node never sends

Over the tunnel, in any frame or blob, a node never sends [sources in brackets]:
- **Any private key:** its cloud key, its TLS keys for hosted names (T36.7 AC 2 tests this on the fake broker's capture), its cluster keys [ADR-1048 p1; ADR-1051 p1].
- **Any stored secret or credential:** passwords and their hashes, TOTP secrets, API tokens, OIDC client secrets, DNS-provider credentials, alert destinations' secrets, list sources' credentials [ADR-1052 p3; ADR-1063 point 1; hosted: Two-way sync].
- **A device key.** Only its ID, its DoT label and, for tenants whose roaming devices the cloud resolver may answer, its SHA-256 [ADR-1050 p5; ADR-1064 p5].
- **The query log, the live tail, the CMDB or discovery data as such, the audit log's contents** [ADR-1047 p8; ADR-1049 p7]. The cloud keeps no query log at rest [ADR-1052 p3]. The one exception is T37.2's name-class counters export, off by default, admin-only and guarded: its batches carry (a) per (device pseudonym, class, UTC day) counters, in which a queried name never appears, only the number of its class in the tenant's class map; and (b) a **device directory entry** for each device with a class-map match in the last 7 days, and no other: a pseudonym keyed on the node, display name, group, device class, OS family, identity certainty, the CMDB owner and the latest private LAN address, nothing more; plus quiet-while-present spans, the `[special]` switch states and the privacy level. So device names, those CMDB fields and a private LAN address do cross the tunnel when the export is on; with it off, none do [ADR-1060 point 1; T37.2].
- **MAC, IP or hostname matchers** in the cloud view. Device bindings there are by opaque device ID, display name and device-key ID only [ADR-1063 point 1; hosted: Two-way sync]. (This is about the synced cloud view; the export's directory entry above does carry a display name and the latest private LAN address, never a MAC or a matcher.)
- **Local records, unless the tenant opted them in separately;** guarded settings; users, tokens, roles and signers' private parts; upstreams and forwards; node-managed and `node_only` entries [ADR-1063 point 1].
- **Anything that would let the cloud act as a cluster member:** no cluster-channel frame (the tunnel's own message type cannot carry one, §2.4), no forwarded write, no role vouching [ADR-1048 p7].

The relayed streams carry the node's own TLS sessions with users and devices; the node sends those bytes, but the cloud cannot read them, because the TLS keys never leave the node [ADR-1047; hosted: Trust boundaries]. Up frames and blobs that do carry tenant data (the cloud view, export batches) are defined by their tasks, redacted as API-014 requires.

## 11. Error codes and counted reasons [ADR-1098 p20]

**Encoding.** Every reason code is a lowercase snake_case string of at most 64 bytes, in `Close.reason`, `BlobDone.reason`, `ChangeResult` and the `wrendns-reason` response header, matching the node's existing codes (`gitops_managed`, `version_conflict`, health reasons). An unknown code is shown as "unknown (<code>)" and is never acted on. Stream refusals are HTTP statuses with the reason header (§7.1). `RST_STREAM` with `CANCEL` is used when either side abandons a relayed connection mid-stream. HTTP/2 error codes (`PROTOCOL_ERROR`, `FLOW_CONTROL_ERROR`, `ENHANCE_YOUR_CALM` and the rest) are left to the HTTP/2 layer for HTTP/2 faults. A deliberate close is `Close` plus `GOAWAY NO_ERROR` (§9).

| Code | Where | Meaning | Source |
|---|---|---|---|
| `relay_header_refused{reason}` | node, per stream (`400`) | a PROXY header failed §2.3's or §12.2's checks; counted in `wrendns_cloud_tunnel_relay_header_refused_total{reason}`. `reason` is one of `private`, `loopback`, `link_local`, `shared`, `lan`, `special`, `local_command`, `sni_mismatch`, `unknown_name`, `malformed` | hosted: How the node treats a relayed stream; T36.4; ADR-1098 p20 |
| budget refusal `{budget}` = `dns`, `ui` or `blob` | node, per stream (`503`) | a stream past its budget or limit; counted in `wrendns_cloud_tunnel_streams_refused_total{budget}` | ADR-1047 p6; ADR-1098 p20 |
| `cloud_unreachable` | node health | the cloud is gone for more than 60 s; degraded, never severe | ADR-1047 p9 |
| `cloud_certificate_expired` | node health | the node's cloud certificate has expired; degraded | hosted: Failure modes |
| `cloud_tunnel_untrusted` | node health | no pinned or announced key matches the broker, or the broker's hello names another tenant or slug; degraded | ADR-1098 p4, p9 |
| `cloud_version_unsupported` | node health | the broker supports neither of the node's versions; degraded | ADR-1098 p10 |
| `cloud_node_removed` | node health | the broker refused the node's serial as denied; degraded | ADR-1098 p18 |
| `removed`, `suspended`, `superseded`, `identity_mismatch`, `version_unsupported`, `draining`, `overloaded`, `protocol_error`, `shutdown` | `Close.reason` | why a side closed the tunnel (§9) | ADR-1098 p19 |
| `duplicate_node` | the tenant's event log | two instances keep replacing each other's tunnel (§6.2) | ADR-1098 p15 |
| `gitops_managed` | `ChangeResult` | a Git-managed cluster rejects cloud edits | hosted: Two-way sync |
| change refusal reasons | `ChangeResult` | every refusal of a signed change has a reason code, audited | T36.15 |
| DoH 404 / DoT REFUSED with an extended DNS error | inside a relayed DNS stream | unknown, revoked or missing device ID, identical within a transport | ADR-1050 p5 |

## 12. Security considerations

### 12.1 Every frame from a node is untrusted input to the cloud
The node is AGPL, so a tenant may run a modified one [ADR-1047 p10]. The service therefore:
- escapes and length-limits every string from a node wherever the portal shows it (T36.9: a heartbeat string with markup is shown escaped);
- checks every CSR name by name against the tenant's slug and its bound cluster [ADR-1051 p1];
- checks dynamic DNS updates against the tenant's records and ranges [hosted: Every frame from a node];
- never believes a `role` or `epoch` claim alone: routing to the primary needs the signed lease and a majority (§5) [ADR-1048 p6];
- takes the node's identity from its client certificate, never from a field; a hello whose IDs differ is closed (§3);
- never grants anything for a stated version or feature (§3);
- checks every blob's size against its kind's cap before reading and its hash while reading (§2.5);
- validates and caps every compiled list blob and cloud view before the cloud resolver uses them, with per-tenant memory and CPU limits [ADR-1064; hosted: The roaming resolver].

### 12.2 Every byte the broker writes is untrusted input to the node
The PROXY header is the cloud's claim, not a fact, so the node uses its address only to describe and limit, never to authorize [ADR-1047 p4; hosted: How the node treats a relayed stream]:
- A relayed stream is **always remote:** never loopback, never inside `allowed_admin_networks`, never break-glass (ADR-944), whatever its socket address.
- **Identity by key or label only:** it never matches an IP or MAC client rule (ADR-976), never satisfies a wall display's network binding, is never inside `[access] allowed_networks`. A relayed stream with neither a DoH key nor a DoT label is a browser or an agent and must sign in.
- **Header sanity** [ADR-1047 p4; ADR-1098 p21, p22]. The node refuses a relayed stream whose PROXY address is any of the following, and counts it as `relay_header_refused` with the reason in brackets:
  - private, RFC 1918 and RFC 4193 (`private`); loopback (`loopback`); link-local (`link_local`); shared address space, RFC 6598 (`shared`);
  - **inside the tenant's own LAN ranges** (`lan`): the union of (1) every prefix on this node's own interfaces, read as the node already reads them, automatic and kept up to date, and (2) **`[cloud] lan_networks`**, a replicated, admin-only list for sites whose prefixes are not on this node's interfaces (another site of a multi-site cluster, a routed VLAN), empty by default, with its UI control in Settings → WrenDNS Cloud, a help entry and a test. Loopback and link-local prefixes are ignored here, because other rules already refuse them. A configured entry shorter than /8 for IPv4 or /32 for IPv6 is refused when the config is validated, so a mistyped `0.0.0.0/0` cannot refuse every stream. The panel shows the effective list. `[access] allowed_networks`, `allowed_admin_networks`, group networks and the CMDB's networks are not used: they describe who may use the node or are edited for other reasons, and can be broader than the LAN;
  - **any other special-purpose address** (`special`): every address that the IANA IPv4 and IPv6 Special-Purpose Address Registries (RFC 6890 and its updates) mark as not globally reachable, plus multicast. That includes, on top of the ranges above, `0.0.0.0/8`, `192.0.0.0/24` (except the registry's globally reachable entries), `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255`, `::/128`, `64:ff9b:1::/48`, `100::/64`, `2001:db8::/32` and `ff00::/8`. The table is data, copied from the two registries with their access date in a comment and checked by a unit test per row; the implementer takes each row's flag from the registries, not from this list (C4);
  - **embedded IPv4 forms** are checked against the IPv4 rules, with the IPv4 rule's reason: `::ffff:0:0/96` (IPv4-mapped) and `64:ff9b::/96` (RFC 6052 NAT64) are unwrapped and the embedded address is checked.
- **What the address is for:** rate limits, lockout, the audit log and the query log, marked as reported by the relay, with the relay correlation ID (§2.3). Step-up lockout is also kept **per account** (10 failed second-factor attempts in 15 minutes lock that account's relayed sign-in for 15 minutes), because the broker could rotate addresses.
- **Refused over the relay unless an admin opts in** (guarded settings): local password sign-in, HTTP Basic, the setup token, sessions created on the LAN, secret writes, guarded settings, backups, user and token management and the `[cloud]` settings (`lan_networks` included). Remote MCP is off by default. Admin and guarded work over hosted names has ADR-1049 point 3's further conditions.
- **Down frames** are untrusted input too: a node accepts membership updates and notices only for its own tenant and a rule's organization and ignores a sequence number it has already seen (T36.24); signed changes and platform content pass their own verification (ADR-1061, ADR-1062) whatever the tunnel says; a blob is checked by size and hash (§2.5).

### 12.3 The cloud commands nothing
No unsigned command exists, except the power-reducing notices and membership adds bounded by a node-signed group rule (§6.3). Policy changes need an editor's signature and pass the node's own checks; platform content needs the content or release key and runs only actions the owner turned on at home; guarded settings are never reachable from the cloud [ADR-1047 p3; hosted: threat model, "The cloud commands the node"]. `Close.retry_after_s` only lengthens a wait, clamped to the 5-minute cap (§8.1).

### 12.4 What a stolen key or a compromised broker gets
- **A stolen cloud key** lets an attacker pose as the node and receive relayed streams, but they are TLS to the node's own certificate, so without the node's TLS key the attacker gets ciphertext only. Cloud certificates are short-lived and revocable from both sides [hosted: threat model]. A copied key that runs beside the real node shows as `duplicate_node` (§6.2).
- **A removed or stolen member** loses its tunnel within seconds (§9) and cannot capture the cluster name with an unsigned primary claim (§5).
- **A compromised broker** sees SNI, timing, volume and roaming devices' addresses, can deny service, and can write false PROXY headers, which §12.2 contains; a false AUTHORITY TLV is caught by the ClientHello check (§2.3). A broker that also mints certificates for hosted names is the whole-cloud compromise of hosted.md's blast radius, which the CT watch reports and which then blocks remote access [ADR-1051 p6].
- **A home device on the cloud path** (a second resolver, IPv6 router advertisements, a guest VLAN) is detected from the broker's mark on relayed streams whose source equals the tenant's own tunnel address (T36.7 AC 8; bit 0 of TLV `0xE0`, §2.3), and over IPv6 is refused as `lan` by the header check (§12.2).

### 12.5 DNS never depends on the tunnel
Nothing on the answer path reads cloud state or waits on the tunnel. Losing the cloud is degraded health only [ADR-1047 p9; CLU-004; AGENTS rule 5].

## 13. Observability on the node
From T36.4, with the full names of ADR-1098 point 20: the health reasons `cloud_unreachable` (degraded after 60 s), `cloud_tunnel_untrusted`, `cloud_version_unsupported`, `cloud_node_removed` and `cloud_certificate_expired` (all degraded); event markers; the metrics `wrendns_cloud_tunnel_up`, `wrendns_cloud_tunnel_reconnects_total`, `wrendns_cloud_tunnel_streams{budget}` (a gauge), `wrendns_cloud_tunnel_streams_refused_total{budget}` (`dns`, `ui`, `blob`) and `wrendns_cloud_tunnel_relay_header_refused_total{reason}` (the fixed set of §11); and the MCP read tool `cloud_status` (including the negotiated suite, §2.1, and the round trip and clock offset, §5). Later cloud metrics use `wrendns_cloud_<area>_`, for example `wrendns_cloud_cert_`. Dropped heartbeats (§7.1) and ignored unknown frames (§2.4) are counted; their metric names are given with the client in T36.4, in the `wrendns_cloud_tunnel_` family.

## 14. Test vectors

This section fixes vectors where the encoding is defined by an external standard or by an accepted record. Vectors for hello, heartbeat, lease and every control frame are written with the tunnel client in T36.4, once the messages' field numbers exist (§2.4); each gives the frame's fields, its exact bytes with the 4-byte length prefix, and, for signed objects, the key, the signed bytes and the signature. Every vector lives as a file under the fake broker's test tree in T36.4, and both the node and the service run it.

**The address table under test** [ADR-1098 p22]. The header check is a pure function over a table. Production uses the full table of §12.2, which refuses the documentation ranges. The fake broker's tests build the check with the documentation ranges removed, so V1 to V5 can keep using RFC 5737 and RFC 3849 addresses as §0 requires; a separate unit test shows that the production table refuses `203.0.113.7` and `2001:db8::7` (reason `special`).

### 14.1 PROXY v2 headers (format: the PROXY protocol specification, version 2)
Addresses are documentation ranges. The 12-byte signature is `0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a`.

**V1. IPv4, TCP, no TLVs.** Caller 203.0.113.7 port 51514, edge 198.51.100.10 port 853.
```
0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a  21 11 00 0c
cb 00 71 07  c6 33 64 0a  c9 3a  03 55
```
`21` = version 2, PROXY; `11` = TCP over IPv4; `00 0c` = 12 bytes of addresses and ports. Expected: refused, `relay_header_refused` (`malformed`), because the AUTHORITY TLV is required (§2.3).

**V2. IPv6, TCP, no TLVs.** Caller 2001:db8::7 port 51514, edge 2001:db8:100::a port 853.
```
0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a  21 21 00 24
20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 07
20 01 0d b8 01 00 00 00 00 00 00 00 00 00 00 0a
c9 3a  03 55
```
Expected: refused (`malformed`), as V1. The address block alone is the IPv6 layout the reader must parse.

**V3. IPv4 with the SNI in a `PP2_TYPE_AUTHORITY` TLV.** Same caller, edge port 443, SNI `example.wrendns.net` (19 bytes).
```
0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a  21 11 00 22
cb 00 71 07  c6 33 64 0a  c9 3a  01 bb
02 00 13  65 78 61 6d 70 6c 65 2e 77 72 65 6e 64 6e 73 2e 6e 65 74
```
`00 22` = 34 = 12 + 3 (TLV type and length) + 19. Expected, under the test table: accepted, the **UI** budget (`<slug>.<suffix>` with slug `example`, §6.1); under the production table: refused (`special`).

**V4. A `LOCAL` command.** `0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a 20 00 00 00`. Expected: refused, `relay_header_refused` (`local_command`) (§2.3).

**V5. IPv4 with all three TLVs of §2.3.** Caller 203.0.113.7 port 51514, edge 198.51.100.10 port 853, SNI `example-dns.wrendns.net` (23 bytes), correlation ID `00 01 ... 0f`, the broker's mark with bit 0 set.
```
0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a  21 11 00 3d
cb 00 71 07  c6 33 64 0a  c9 3a  03 55
02 00 17  65 78 61 6d 70 6c 65 2d 64 6e 73 2e 77 72 65 6e 64 6e 73 2e 6e 65 74
05 00 10  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
e0 00 01  01
```
`00 3d` = 61 = 12 + (3 + 23) + (3 + 16) + (3 + 1). Expected, under the test table: accepted, the **DNS** budget (`<slug>-dns.<suffix>`, §6.1), with the correlation ID recorded and the "source equals the tenant's tunnel address" mark set; under the production table: refused (`special`). The same header with any of the three TLVs repeated is refused (`malformed`).

### 14.2 Header sanity (§12.2)
| Reported caller address | Expected | Rule |
|---|---|---|
| 10.1.2.3, 172.16.0.1, 192.168.1.20 | refused (`private`) | RFC 1918 (T36.4 AC 7) |
| fd12:3456:789a::1 | refused (`private`) | RFC 4193 |
| 127.0.0.1, ::1 | refused (`loopback`) | loopback |
| 169.254.10.1, fe80::1 | refused (`link_local`) | link-local |
| 100.64.0.1 | refused (`shared`) | RFC 6598 |
| an address inside a prefix on one of the node's interfaces, or inside `[cloud] lan_networks` | refused (`lan`) | the tenant's LAN ranges |
| 0.0.0.1, 198.18.0.1, 224.0.0.251, 240.0.0.1, 255.255.255.255, ff02::1 | refused (`special`) | special-purpose registries, multicast |
| 203.0.113.7, 2001:db8::7 | refused (`special`) in production; accepted under the test table | documentation ranges |
| ::ffff:192.168.1.20, 64:ff9b::c0a8:114 | refused (`private`) | IPv4-mapped and NAT64 forms, unwrapped |
| a public address equal to a LAN client rule's address | accepted, but no client-rule match | T36.4 AC 7 |

### 14.3 Control-stream framing (ADR-044)
An opaque 2-byte payload `08 01` is framed as `00 00 00 02 08 01`. A length field above 1 MiB (`00 10 00 01` = 1,048,577) is refused without reading the payload. A length of 0 (`00 00 00 00`) is invalid and the receiver closes with `Close{protocol_error}` (§2.4).

### 14.4 Backoff (§8.1)
| Attempt *n* | Cap `min(300 s, 2^n s)` | Wait drawn from |
|---|---|---|
| 0 | 1 s | 0 to 1 s, at least 200 ms |
| 1 | 2 s | 0 to 2 s, at least 200 ms |
| 4 | 16 s | 0 to 16 s, at least 200 ms |
| 8 | 256 s | 0 to 256 s, at least 200 ms |
| 9 and later | 300 s | 0 to 300 s, at least 200 ms |

With `Close { retry_after_s: 600 }` the node waits `max(draw, 300 s)`. The count resets only after 60 s up with the hellos exchanged.

### 14.5 Behaviour tests the fake broker must run (from T36.4, T36.5 and ADR-1098)
These are not byte vectors but are fixed by accepted acceptance criteria and records: a browser connection by SNI reaches the node's UI and the node logs the real client address; break-glass over the relay is refused even when the socket address is loopback; killing the broker changes no DNS answer and no p99, and health goes degraded after 60 s, never severe; DNS stream 129 is refused with a counted reason while UI streams still open; a removed or modified node claiming `role = primary` with a higher epoch and no majority does not get the cluster name; the TLS private key never appears in any tunnel frame or blob. From ADR-1098: a broker chain under neither pin is refused with `cloud_tunnel_untrusted`; a rollover announced less than 30 days ahead, or with a lower `seq`, is ignored; a chain under the backup key is accepted at once; a hello whose IDs differ from the certificate's gets `Close{identity_mismatch}`; an unsupported version gets `BrokerHello{protocol: 0}` and `Close{version_unsupported}`; an AUTHORITY TLV that differs from the ClientHello's server name closes the stream (`sni_mismatch`); a second tunnel from the same node supersedes the first; an expired certificate within the grace gets a renew-only tunnel that routes nothing, which the fake broker shows by moving its clock forward; a denied serial stops dialling with `cloud_node_removed`; a blob whose size exceeds its kind's cap is refused before any byte is read.

## 15. To verify when building

The owner's answers rest on these facts about standards and libraries, which the answers document did not confirm. Each is an implementation check for T36.4: confirm it and record the result in T36.4's note, or, if it is false, stop and bring the affected point back to the owner as a change to ADR-1098. None of them is stated as fact elsewhere in this document.

1. **C1. The broker's suite order.** Whether `rustls` servers follow the client's suite order by default (`ServerConfig::ignore_client_order` defaulting to `false`) in the current release. The protocol rule (§2.1) holds either way; the check decides whether the broker must set the option explicitly. The fake broker sets it explicitly.
2. **C2. PROXY v2 TLVs.** The TLV type numbers used in §2.3 (`PP2_TYPE_AUTHORITY` `0x02`, `PP2_TYPE_UNIQUE_ID` `0x05` with its 128-byte maximum, `PP2_TYPE_MIN_CUSTOM` `0xE0`) and how the PROXY protocol specification says unknown TLVs must be handled. §2.3 skips them, as the node's reader does today; if the specification requires anything else, §2.3 follows the specification.
3. **C3. Per-stream receive windows.** Whether `hyper` or `h2` lets the receiving side give one stream a larger receive window than another (they are believed to expose `initial_stream_window_size` per connection only). §7.1's reading of ADR-1047 point 6 rests on "no"; if the libraries can, the decided constants still hold until a measurement in T36.4 says otherwise, and any change is a new decision.
4. **C4. The special-purpose registries.** Each row's "globally reachable" flag in the IANA IPv4 and IPv6 Special-Purpose Address Registries, copied with the access date; the list in §12.2 is a summary, not the source.

Also left to T36.4, under rules already decided, with no owner decision needed: the field numbers inside each message and the frame vectors (§2.4, §14), the metric names for dropped heartbeats and ignored frames (§13), and the measurement of §7.1's constants against the RSS targets.

## 16. References
ADR-039, ADR-044, ADR-057, ADR-118, ADR-143, ADR-944, ADR-976, ADR-1018, ADR-1027, ADR-1031, ADR-1047 to ADR-1052, ADR-1060 to ADR-1065, ADR-1069, ADR-1098 (`spec/11`); `spec/02` §3 and §8; `spec/12` §5 and §9; `spec/13` §3.2; `docs/design/hosted.md`; `docs/design/cloud-protocol-answers.md` (the reasoning behind ADR-1098); T36.4 to T36.24 and T37.2, T37.3 (`spec/10`); CLD-901 (`spec/01`); RFC 1918, RFC 3849, RFC 4193, RFC 5737, RFC 6052, RFC 6598, RFC 6890, RFC 7301, RFC 7469, RFC 8215, RFC 8446, RFC 8628, RFC 9000, RFC 9113 (HTTP/2); the IANA IPv4 and IPv6 Special-Purpose Address Registries; the PROXY protocol specification, version 2 (HAProxy).
