# The cloud tunnel protocol: recommended answers to spec/14's open questions

> **ACCEPTED 2026-11-26.** Owner decision, 2026-11-26: every answer on this page is accepted as recommended; the six marked **real** were each put to the owner and accepted, and the other sixteen were accepted as a group. The record is ADR-1098 in `spec/11-decisions.md` (its point *n* answers Q*n*), and the normative text is now in `spec/14-cloud-protocol.md`. This page keeps the reasoning and is not changed further; where it and `spec/14` differ, `spec/14` wins. The facts this page says it did not check are listed in `spec/14` §15, "To verify when building". The original note follows.

> **RECOMMENDATIONS, NOT DECISIONS.** This page proposes an answer to each open question in `spec/14-cloud-protocol.md` §15 (Q1 to Q22) for the owner's review. Nothing here is part of the protocol, and `spec/14` is unchanged, until the owner answers through the question tool. Once the owner has answered, the chosen answers are written into `spec/14` and this page is marked as superseded. Date: 2026-11-25.

## How to read this page

Each section gives a **recommendation**, **why**, the **main alternative**, and a **tradeoff** mark:

- **real**: reasonable people would choose differently, and the choice is costly to change later (wire format, trust model, what crosses the tunnel).
- **minor**: a different choice would also work and could be changed later without much cost.
- **none**: one answer follows plainly from the accepted records.

The answers stay inside ADR-1047 to ADR-1052 and ADR-1065 (`spec/11-decisions.md`) and `docs/design/hosted.md`. The guiding rules: choose the simplest design that is safe by default and can be tested on a Raspberry Pi; add no runtime crate (ADR-1047 point 1); follow a standard where one exists. Where I am not sure what a standard or a crate does, the section says so.

Node code these answers rely on:

| What | Where |
|---|---|
| Cluster channel framing: 4-byte big-endian length, prost `Frame`, 1 MiB cap, `PROTOCOL` and `protocol_compatible` (N and N-1) | `crates/wrendns-cluster/src/wire.rs` |
| Cluster channel transport: `POST /cluster/v1/stream` with a streaming body both ways, blobs on `GET /cluster/v1/blob/<hash>`, `Channel::new(16)` frame queue, HTTP/2 keep-alive, backoff that doubles to 30 s and resets after 60 s up | `crates/wrendns-cluster/src/net.rs` |
| TLS: `rustls` 0.23 with the `ring` provider, `with_safe_default_protocol_versions()` (TLS 1.2 and 1.3), ALPN `h2`, the CA pinned by the SHA-256 of the whole CA certificate (`PinnedCa`, `pki::fingerprint`) | `crates/wrendns-cluster/src/net.rs`, `crates/wrendns-cluster/src/pki.rs`, the `rustls` features in each `Cargo.toml` |
| Signed objects sent as their exact bytes plus a signature (`Signed { json, sig }`) | `crates/wrendns-cluster/src/sync.rs` |
| PROXY v2 reader: v2 only, 1024-byte cap, `LOCAL` keeps the socket address, TLVs skipped | `crates/wrendns-net/src/proxy.rs` |
| DoT and DoH acceptors with their own idle and handshake timeouts | `crates/wrendns-net/src/tcp.rs`, `crates/wrendns-net/src/doh.rs` |
| The node's interface addresses and prefixes | `crates/wrendns-net/src/ifaddrs.rs` |
| Metric naming: `wrendns_<subsystem>_<name>`, counters ending in `_total` (for example `wrendns_cluster_peer_up`, `wrendns_cluster_rollouts_total`) | `crates/wrendns-cluster/src/`, `crates/wrendns/src/` |
| Domain-separation strings of the form `wrendns-<object>-v1`, signed as `domain || 0x00 || bytes` | ADR-1061, ADR-1062 point 3, ADR-1063 point 9, ADR-1069 point 3 |

## Q1. Stream direction

**Recommendation.** After TLS, the roles are reversed: **the node is the HTTP/2 server** on the connection it dialled, and the broker is the HTTP/2 client. The broker opens one stream for the control channel and one stream for each public connection. The node serves the connection with `hyper::server::conn::http2::Builder::serve_connection` over its `tokio_rustls` client stream. hyper takes any `AsyncRead + AsyncWrite`, so this needs no new crate. The fake broker in the test tree does the reverse: it runs `hyper::client::conn::http2::handshake` over its server-side TLS stream.

**Why.** In HTTP/2, only the client opens streams, and the client sends the connection preface (RFC 9113 §3.4, §5.1.1). The broker must open a stream whenever a caller connects, without waiting for the node. With the roles reversed, that is an ordinary HTTP/2 request, and the node's existing stack (a `service_fn` per request) handles it. The caller's first bytes (its TLS ClientHello) go out at once, with no extra round trip. TLS identity is unaffected: the node still verifies the pinned tunnel CA, and the broker still verifies the node's client certificate. With QUIC later, both endpoints can open bidirectional streams (RFC 9000 §2.1), so the reversal is needed only for the HTTP/2 transport. I believe Cloudflare's tunnel client does the same over HTTP/2, but I have not checked its source, so the recommendation does not rely on that.

**Main alternative.** (c): the broker sends an "open" control frame, and the node opens the stream as the HTTP/2 client. This keeps normal roles, but it adds one tunnel round trip to every public connection, the broker has to buffer the caller's ClientHello in the meantime, and every connection depends on the control stream. Option (b), a pool of idle streams opened by the node, has to be sized, ties up budget slots while idle, and still fails when a burst outgrows the pool.

**Tradeoff: real.** This is the shape of the wire protocol, and the broker is built around it.

## Q2. Request line and ALPN

**Recommendation.**
- **ALPN:** `wrendns-tunnel/1` alone. It is never `h2`, because the HTTP/2 roles are reversed (Q1), and a client that negotiated `h2` would expect to be the HTTP/2 client.
- **Control stream:** `POST`, `:scheme https`, `:authority tunnel.<suffix>`, `:path /tunnel/v1/control`, opened by the broker as the first stream. Both bodies stream frames for the life of the connection, as the cluster channel's `POST /cluster/v1/stream` does.
- **Relayed streams:** `POST`, `:authority tunnel.<suffix>`, `:path /tunnel/v1/relay`. The request body starts with the PROXY v2 header and then carries the caller's bytes. The response body carries the node's bytes. The node sends `200` once the PROXY header has passed its checks, or a refusal (Q20).
- **Large objects:** `GET` and `PUT /tunnel/v1/blob/<sha256>` (Q8).
- Each stream carries nothing in its request headers beyond the pseudo-headers. Per-stream facts travel in the PROXY header (Q5).

**Why.** A private ALPN value makes a misdirected client (a browser that reached `tunnel.<suffix>`) fail at the handshake with `no_application_protocol` (RFC 7301 §3.2), and it names the protocol's major version. That matters because `tunnel.<suffix>` shares its edge address with every tenant name (ADR-1050 point 6). `POST` with streaming bodies in both directions already works in this codebase (`net.rs`). A fixed `:path` per stream type lets the node route a request without reading its body.

**Main alternative.** Use HTTP/2 `CONNECT` (RFC 9113 §8.5) for relayed streams, which is HTTP's own byte-tunnel method. `CONNECT` carries only `:authority`, so the stream type would have to be carried somewhere else, and hyper's server treats `CONNECT` through an upgrade path rather than as a plain streaming body. Extended CONNECT (RFC 8441) exists to start another protocol (WebSockets) on a stream. It needs `SETTINGS_ENABLE_CONNECT_PROTOCOL` and a `:protocol` value, and it adds nothing here, because there is no protocol to start. For the ALPN, the other choice is plain `h2`, which works but hides the role reversal.

**Tradeoff: minor.** Both ends can accept two ALPN values or two paths for one release.

## Q3. TLS versions and suites

**Recommendation.**
- **TLS 1.3 only** (RFC 8446), with `with_protocol_versions(&[&rustls::version::TLS13])`, as the DoQ and DoH3 tests already do (`crates/wrendns-net/tests/doq.rs`). The broker refuses TLS 1.2.
- **Suite order:** when the CPU has no AES instructions, the node's client `CryptoProvider` lists `TLS13_CHACHA20_POLY1305_SHA256` first. The node checks with `std::arch::is_aarch64_feature_detected!("aes")` on arm64 and `is_x86_feature_detected!("aes")` on x86-64 (both in std, so no crate). Otherwise it keeps `ring`'s default order. There is no setting. `cloud_status` shows the negotiated suite.
- The broker follows the client's suite order. As I understand it, rustls servers do this by default (`ServerConfig::ignore_client_order` defaults to `false`), but I have not checked that against the current rustls release. The broker is a separate program, so spec/14 should state the rule rather than rely on one library's default.

**Why.** Both ends belong to WrenDNS, so there is no legacy peer that needs TLS 1.2. TLS 1.3 removes renegotiation and the legacy key exchanges, and it protects the client certificate (RFC 8446 §4.4.2: the client's Certificate is sent encrypted). Ed25519 client certificates work in TLS 1.3. A Pi 4's Cortex-A72 lacks the ARMv8 crypto extensions (hosted.md, The tunnel), so ChaCha20-Poly1305 is the faster suite there, and runtime detection picks it with no configuration. T36.4 benchmarks both suites, as hosted.md asks.

**Main alternative.** A `[cloud] tunnel_cipher = "auto" | "aes" | "chacha"` setting, which would need a UI control, a help entry and tests under the UI rule, for a choice that detection already makes correctly. Allowing TLS 1.2 as well, as the cluster channel does, gains nothing between two components we both control.

**Tradeoff: none.**

## Q4. Pins and rollover encoding

**Recommendation.**
- **What is pinned:** the tunnel CA's **public key**, not its certificate. The node stores the DER `SubjectPublicKeyInfo` of the current key and of the backup key. It compares SHA-256 hashes of SPKI DER, the `pin-sha256` form of RFC 7469 §2.4. The node keeps the keys themselves, not only their hashes, because it needs the current key to verify a rollover announcement.
- **Where:** `<data_dir>/cloud/tunnel-ca.json` `{current_spki, backup_spki, pending: [{spki, not_before}]}`, written atomically, mode 0600 like the rest of `<data_dir>/cloud/`. The file holds no secret, but it decides who the node trusts.
- **Verification:** a custom `ServerCertVerifier`, like `PinnedCa` in `net.rs`. It finds the certificate in the broker's chain whose SPKI matches a pin, builds a one-root `RootCertStore` from that certificate, and runs WebPKI path validation of the leaf for `tunnel.<suffix>`, including the leaf's dates. The broker sends the CA certificate in its chain, as the cluster listener does.
- **Rollover announcement:** a field of `BrokerHello`, `CaRollover { signed: bytes, sig: bytes }`. `signed` is a prost-encoded `{seq, new_spki, new_backup_spki, not_before, issued}`. `sig` is Ed25519 by the **current** CA key over `"wrendns-tunnel-ca-rollover-v1" || 0x00 || signed`. The node parses `signed` only after the signature verifies, the way `sync.rs` handles `Signed`. The node accepts an announcement only when `not_before` is at least 30 days after `issued` and `seq` is above any announcement it has already accepted. It then stores the new key as pending. From `not_before`, the node accepts both the old and the new key. After its first successful connection under the new key, the new key becomes current, the old key is dropped, and the announced backup becomes the backup.
- **Backup:** the cloud keeps the backup key offline. A broker certificate chained to the backup key is accepted at once, with no announcement. That is the recovery path when the current key is lost or compromised. The cloud then announces a new backup, signed with the key now in use.
- **No match:** the node refuses the connection and raises the health reason `cloud_tunnel_untrusted` (degraded; DNS unaffected). It keeps retrying with backoff, because a new pin can reach it only on a connection it already trusts. The fix is to link again. This event goes in the audit log.

**Why.** ADR-1048 point 2 pins the CA's key and a backup key, specifically so that renewing a certificate never breaks a pin. A pin on the key survives re-issuing the CA certificate with the same key, which a pin on the whole certificate (ADR-044's `ca_fp` and `pki::fingerprint`) would not. Sending the signed bytes exactly as signed, verified before parsing, avoids the problem of canonical protobuf encoding, and the cluster channel already works this way. The domain string follows the `wrendns-*-v1` family.

**Main alternative.** Pin the SHA-256 of the whole CA certificate, as the cluster join token does. That is simpler, but it breaks whenever the CA certificate is re-issued, and ADR-1048 rejected that kind of pin for the broker's leaf.

**Tradeoff: real.** This is the node's trust anchor for the cloud, and enrolled nodes keep the format.

## Q5. Per-stream metadata

**Recommendation.** Everything travels in the PROXY v2 header of the stream it describes, using the TLV types of the PROXY protocol specification (version 2, §2.2.1 and §2.2.7, as I read them):

| Fact | TLV | Value |
|---|---|---|
| The caller's TLS SNI | `PP2_TYPE_AUTHORITY` (`0x02`) | the exact `server_name` from the caller's ClientHello, ASCII, 1 to 253 bytes |
| The relay correlation ID | `PP2_TYPE_UNIQUE_ID` (`0x05`) | 16 random bytes from the broker (the specification allows up to 128) |
| The broker's marks | one custom TLV, `0xE0` (`PP2_TYPE_MIN_CUSTOM`) | 1 byte of flags: bit 0 means "source equals the tenant's own tunnel address" (T36.7 AC 8); the other bits are 0 and are ignored on receipt |

- Each of these TLVs appears at most once. A header with AUTHORITY missing, or a known TLV repeated, is refused as `relay_header_refused`. Unknown TLV types are skipped, as `proxy.rs` skips them today, and I believe the specification expects receivers to ignore them. The 1024-byte header cap in `proxy.rs` stays.
- After the TLS handshake, the node compares the SNI it saw in the ClientHello with the AUTHORITY TLV and closes the stream on a mismatch, counted as `relay_header_refused`. The ClientHello is the caller's own message, and once the handshake completes the broker cannot have altered it undetected, because the handshake transcript covers it. The TLV is used only to classify the stream before TLS (Q14).
- `PP2_TYPE_CRC32C` is not used, because the tunnel's TLS already protects the bytes.

**Why.** ADR-1047 point 2 says the stream starts with a PROXY v2 header carrying the address, the port and the SNI. The standard already defines a TLV for the SNI and one for a connection ID, so one parser covers everything about a stream. A control frame would have to be matched to its stream later, which creates an ordering race.

**Main alternative.** Request headers on the relayed stream's `POST` (for example `wrendns-correlation`). They are easy to read in hyper, but the facts would then be split between the HTTP/2 headers and the PROXY header, and that departs from ADR-1047's preface. A per-stream control frame is the worst of the three, because of the ordering race.

**Tradeoff: real.** This is the wire format of every relayed stream.

## Q6. PROXY `LOCAL` on a relayed stream

**Recommendation.** Refuse it. A `LOCAL` command, or a `PROXY` command with family `AF_UNSPEC` or `AF_UNIX`, ends the stream as `relay_header_refused`. Vector V4 then expects "refused".

**Why.** ADR-039's "`LOCAL` keeps the socket address" exists for a balancer's health checks on a real socket. A relayed stream has no socket address to fall back to (ADR-1047 point 4), and the broker checks its health on the control stream (Q13), so it never needs `LOCAL`. Refusing it also means a relayed stream always has an address for rate limits and lockout.

**Main alternative.** Treat `LOCAL` as a broker probe: answer it, then close. That adds a second health path and a case to test, and gains nothing.

**Tradeoff: none.**

## Q7. Message schema

**Recommendation.**
- **A separate tunnel type** `TunnelFrame { oneof body }`, in its own module, apart from the cluster `Frame`. The tunnel reuses only the framing code: the 4-byte length, `MAX_FRAME` and the decode loop, made generic over the message type.
- **`oneof` layout:** numbers are assigned in blocks by task, so that later tasks never collide. Tags 1 to 15 encode in one byte, so the frequent frames get them.
  - 1 to 15, T36.4: `NodeHello` 1, `BrokerHello` 2, `Heartbeat` 3, `HeartbeatAck` 4, `Close` 5, `BlobOffer` 6, `BlobDone` 7; 8 to 15 reserved.
  - 16 to 31, T36.5: certificates, members, disconnect.
  - 32 to 47, T36.7 and T36.8: certificates for hosted names, device keys.
  - 48 to 63, T36.11 and T36.12: dynamic DNS, list blobs, roaming events.
  - 64 to 95, T36.15, T36.16 and T36.18: changes, cloud view, platform content.
  - 96 to 127, T36.24, T37.2 and T37.3: memberships, notices, class map, export.
- **Evolution:** the rule `wire.rs` already states. Fields are only ever added and never renumbered. A removed field's number is reserved. `PROTOCOL` is raised only when a message changes meaning (Q10).
- **Zero-length frame:** invalid. The receiver closes with `Close{protocol_error}`. A frame with a nonzero length whose `body` decodes as unset (a frame type from a newer peer, which prost skips as an unknown field) is **ignored and counted**, so N and N-1 still interoperate.
- **The normative schema** is a proto3 text block in `spec/14`. The node writes its prost structs by hand, as ADR-044 does (no codegen step). The service is written from `spec/14` and the test vectors, never from the node's code (ADR-1052 point 2). The byte vectors in `spec/14` §14, run by both sides, check that the two agree.

**Why.** ADR-1048 point 7 says no cluster-channel frame ever crosses the tunnel. With a separate type, a `KeyShare` or an `RpcRequest` cannot be decoded on the tunnel at all, so nobody has to remember to refuse it. Number blocks per task let T36.5 to T37.3 add frames in parallel without conflicts. Without the zero-length rule, an empty frame would look like an unknown frame from a newer peer.

**Main alternative.** Add the tunnel frames as new variants of the cluster `Frame`. That needs less code, but then the cluster's own frames could arrive on the tunnel, and the two protocols would have to version together.

**Tradeoff: real.** Field numbers are permanent.

## Q8. Payloads over 1 MiB

**Recommendation.** Keep the 1 MiB cap on every control frame. Large objects travel **by reference, on a stream of their own**, the way the cluster channel moves blobs (`GET /cluster/v1/blob/<hash>`; `wire.rs`: "blobs go over their own requests"):
- The sender puts `BlobOffer { kind, sha256, size }` on the control stream. Because only the broker opens streams (Q1), the broker opens the blob stream in both directions: `GET /tunnel/v1/blob/<sha256>` to fetch from the node, and `PUT /tunnel/v1/blob/<sha256>` to deliver to the node.
- The receiver checks `size` against that kind's own cap before it reads anything, hashes as it reads, and refuses a mismatch. It acknowledges with `BlobDone { sha256, ok, reason }`.
- **Which kinds go by reference: always the same kinds, whatever their size.** `CloudChange` and `ProposedChange` (1 MiB of patch plus the envelope and assertion, ADR-1061), `CloudView` deltas and digests, `ListBlob`, `PlatformContent` (the class map), `RoamingEvents` batches and `ExportBatch`. Everything else stays inline, with its own cap well below 1 MiB.
- Blob streams count against neither the DNS nor the UI budget. They have their own limit of 2 concurrent streams in each direction, with a window of 64 KiB.

**Why.** A signed change can be larger than 1 MiB by design (ADR-1061's 1 MiB cap is on the patch before its assertion), and the other kinds have no fixed size. On a separate stream, a 20 MiB list blob cannot hold up heartbeats behind it (Q13). HTTP/2 flow control limits that stream's memory on its own, and the receiver can refuse by size before reading. Assigning each kind a fixed path means there is no size threshold to get wrong.

**Main alternative.** Split large objects into `Chunk { id, index, total, bytes }` frames on the control stream. This keeps one stream and adds no paths, but a large transfer blocks heartbeats and every other control frame behind it, and chunks need reassembly buffers and their own timeouts.

**Tradeoff: real.** This shapes how every later task's large frames are carried.

## Q9. Hello against the certificate

**Recommendation.** `NodeHello` carries `tenant_id`, `cluster_id` and `node_id`, and **all three must equal the client certificate's values**. On a mismatch, the broker sends `Close{identity_mismatch}`, writes the event to the tenant's event log, routes nothing to the tunnel, and closes it. The broker never uses these fields for anything else: identity comes from the certificate (§12.1). `BrokerHello` carries the `tenant_id` and slug that the broker holds for this certificate. The node checks them against its own binding and, on a mismatch, closes the tunnel and raises `cloud_tunnel_untrusted`.

**Why.** This is ADR-044's rule ("the peer's node ID comes from its certificate, and its Hello must match it"), and the cluster code already does it. The check catches a modified or misconfigured node early, and the broker-side check catches a routing bug on the cloud side.

**Main alternative.** Leave the identity fields out of the hello, since the certificate is authoritative. Then nothing can mismatch, but a bug on either side shows up later and less clearly.

**Tradeoff: none.**

## Q10. Version negotiation

**Recommendation.**
- **Carried:** `NodeHello { protocol, min_protocol, features: [string] }`, where `protocol` is the node's N and `min_protocol` is N-1. `BrokerHello { protocol }` is the version the **broker chose**: the highest version both sides support.
- **Who picks:** the broker. It is the side that serves every node version at once during a rollout (CLU-010's N and N-1).
- **Features:** a list of named, versioned frame groups the node implements, for example `certs-v1`, `changes-v1`, `export-v1`. The broker sends a group's frames only to a node that lists it. Adding a feature never raises `protocol`.
- **Unsupported version:** the broker sends `BrokerHello { protocol: 0 }`, then `Close { reason: version_unsupported, supported_min, supported_max }`, and closes. The node raises `cloud_version_unsupported` (degraded; the panel says to update the node) and retries at the backoff cap (Q17).

**Why.** An integer version in each hello is what the cluster channel does (`wire::PROTOCOL`, `protocol_compatible`). Because unknown frames are ignored (Q7), a frame sent to a node that cannot handle it is silently lost, for example a change that would then sit Pending for ever. The features list lets the broker know what a node handles without parsing its version string, which is untrusted (§12.1). Feature names only choose an encoding. They grant nothing (§3).

**Main alternative.** Carry the major version in the ALPN (`wrendns-tunnel/2`, `wrendns-tunnel/1`) and let TLS negotiate it. This is standard and needs no round trip, but every feature added in a later task would then need either a new ALPN value or a features list anyway.

**Tradeoff: minor.**

## Q11. A member's first certificate, and renewal after expiry

**Recommendation.**
- **First certificate: through the primary's tunnel.** The member makes its cloud key and sends a request signed with that key to the primary over the cluster channel. The primary countersigns it and sends `MemberCertRequest` up its own tunnel. The cloud CA issues the certificate, `CloudCert` comes back down to the primary, and the primary passes it to the member over the cluster channel. The countersignature is Ed25519 with the primary's cloud key over `"wrendns-tunnel-countersign-v1" || 0x00 || signed`, where `signed` is `{tenant_id, cluster_id, node_id, member_spki, issued, expires}` and `expires` is at most 10 minutes after `issued`. The cloud checks it against the primary's current certificate and the majority-confirmed lease (Q12).
- **Renewal after expiry: a renew-only tunnel.** Within the 180-day grace, the broker's client verifier accepts an **expired** certificate whose serial is not denied, and marks the connection renew-only. TLS still proves possession of the key through CertificateVerify. On a renew-only connection, the broker accepts only `NodeHello`, then one `CloudCertRenew` that carries a fresh countersignature. It routes nothing and closes once it has answered. A one-node cluster countersigns its own request, as its own primary. For a member of a larger cluster, the primary's countersignature can also arrive through the primary's tunnel, as for a first certificate.

**Why.** Neither path opens anything on the broker to a client without a certificate. `POST /cluster/v1/join` is the cluster's one unauthenticated route, and the tunnel does not need one: at first certificate the primary is online and linking, and an expired certificate is still a key the cloud knows. The renew-only mode is the only path that works for a one-node cluster that comes back after more than 30 days (hosted.md, Failure modes). It is testable with the fake broker by moving its clock forward.

**Main alternative.** An enrolment endpoint on `tunnel.<suffix>` that needs no client certificate and authenticates only by the countersignature in the request body. This is one uniform path for both cases, but it adds an unauthenticated parser and a flooding target to the broker.

**Tradeoff: real.** This is the trust model of enrolment and recovery.

## Q12. The lease

**Recommendation.**
- **Lifetime:** 60 seconds (three heartbeats), re-signed in every heartbeat of the primary. The broker treats a lease as valid until `min(expires, received + 60 s)`. It refuses a lease whose `expires` is already past, or more than 5 minutes ahead of the broker's clock, so a Pi with a bad clock cannot hold the name indefinitely. The broker also keeps the highest confirmed epoch for each cluster and never routes to a lease with a lower epoch.
- **Encoding:** `Lease { signed: bytes, sig: bytes }`. `signed` is a prost-encoded `{tenant_id, cluster_id, node_id, epoch, issued, expires}`, with times in Unix seconds. `sig` is Ed25519 by the primary's cloud key over `"wrendns-tunnel-lease-v1" || 0x00 || signed`. The broker verifies `sig` with the public key in the tunnel's own client certificate before it parses `signed`, and refuses a lease whose `node_id` is not the certificate's.

**Why.** Three missed heartbeats is the liveness rule (Q13), so a lease that outlives it would keep the cluster name on a primary the broker has already lost. Exact bytes plus a signature, verified before parsing, is the pattern `sync.rs` uses. The domain string keeps a lease signature from being valid as any other cloud-key signature, such as the countersignature in Q11. Including `tenant_id` blocks replay across tenants.

**Main alternative.** A JSON lease canonicalised with JCS (RFC 8785), like the change envelope (ADR-1061). That is consistent with the user channel, but it needs a canonicaliser on both sides for an object that never leaves the tunnel.

**Tradeoff: minor.** The ADR fixes the trust model, and the lifetime is a constant.

## Q13. Heartbeat acknowledgements and liveness

**Recommendation.**
- **Every heartbeat is acknowledged.** `HeartbeatAck { seq, broker_time, platform_hints, class_map_version }`, where `seq` echoes the heartbeat. The node uses it for the round trip and the clock offset shown in `cloud_status`.
- **Gone after three missed intervals (60 s)** on each side, as ADR-044 uses three intervals for the cluster. The node closes the tunnel, reconnects with backoff, and raises `cloud_unreachable` once 60 s have passed since its last acknowledgement. The broker stops routing to a node 60 s after its last heartbeat. It stops routing at once on a connection error, or when the node turns unready or enters maintenance.
- **HTTP/2 PING** keep-alive on the node's server connection, every 20 s with a 20 s timeout, as the cluster channel sets `keep_alive_interval`. This catches a dead TCP path even while the control stream's writer is backed up.

**Why.** With an acknowledgement, "the cloud is gone" is something the node observes directly rather than infers from silence. The 60 s matches T36.4's `cloud_unreachable` threshold exactly, so there is one timer. The acknowledgement is the natural place for the version hints the design already puts there.

**Main alternative.** Acknowledge only when the hints change, and rely on PING alone for liveness. That sends fewer bytes, but it makes two liveness signals that can disagree.

**Tradeoff: none.**

## Q14. Budget classification

**Recommendation.** **The node classifies each stream** from the AUTHORITY TLV (Q5) before reading further:
- `<slug>-dns.<suffix>` and any one label under it: the **DNS** budget.
- `<slug>.<suffix>` and `<node>.<slug>.<suffix>` (verified custom names in phase 2): the **UI** budget.
- Any other name: refused as `relay_header_refused`.

On a relayed UI-name stream, the node does not serve `/dns-query`. Roaming DNS uses the DNS site only (ADR-1064).

**Why.** Since ADR-1064, DNS names and UI names are separate sites, so the SNI alone decides the class. hosted.md's "DoT and DoH to `/dns-query`" predates that amendment. The budget then lives only on the node, which enforces it, so there is no broker label to trust or test. A broker that lies in the TLV is caught by the ClientHello check (Q5), and a lying broker can only deny service, which it could do anyway.

**Main alternative.** The broker classifies and adds a flag to its custom TLV. That is redundant with the SNI, and it would be one more broker claim for the node to check.

**Tradeoff: none.**

## Q15. Overlapping tunnels

**Recommendation.** **The newest tunnel wins.** When a second tunnel authenticates with the same tenant, cluster and node, the broker routes new streams only to the new tunnel. It sends the old tunnel `Close{superseded}` and lets the old tunnel's relayed streams finish, for at most 30 s, before closing it. `NodeHello` carries an `instance` ID, new at each process start, as the cluster `Hello` does (ADR-1018). When two different instance IDs keep replacing each other (more than 3 times in 10 minutes), the broker records `duplicate_node` in the tenant event log, and the portal shows that two processes are using one cloud key.

**Why.** A reconnect usually means the old path is already dead, so waiting for it only delays recovery. The newest tunnel is the one that just proved it holds the key. The instance ID separates "the same node reconnected" from "a copied key is running somewhere else", and the cluster channel already has this field.

**Main alternative.** Keep the first tunnel and refuse the second until the first is gone. A stolen key could then not steal routing from a healthy node, but every reconnect after a silent path failure would wait up to 60 s (Q13). The key-theft case is already covered by revocation and the CT watch.

**Tradeoff: minor.**

## Q16. HTTP/2 settings and refusals

**Recommendation.** Fixed constants, measured in T36.4 against the RSS targets (+2 MiB idle, +12 MiB with both budgets full) and changed only after a measurement. No setting.

| Item | Value |
|---|---|
| Node's receive window per stream (`SETTINGS_INITIAL_WINDOW_SIZE`) | 16 KiB for every stream (callers send small requests) |
| Node's connection receive window | 1 MiB (a hard bound on inbound bytes buffered across all streams) |
| Node's send buffer per stream (its own bounded queue between the inner TLS session and the stream) | DNS 16 KiB, UI 256 KiB, blob 64 KiB |
| Broker's receive windows (for the node's sends) | DNS 16 KiB, UI 256 KiB, raised per stream with `WINDOW_UPDATE` (the broker's own implementation) |
| `SETTINGS_MAX_CONCURRENT_STREAMS` from the node | 165 = 128 DNS + 32 UI + 1 control + 4 blob (a hard ceiling; the per-class budgets are enforced above it) |
| `SETTINGS_MAX_FRAME_SIZE`, both sides | 16,384, the default (RFC 9113 §6.5.2) |
| `SETTINGS_MAX_HEADER_LIST_SIZE` | 8 KiB |
| `SETTINGS_ENABLE_PUSH` from the broker | 0 |
| Idle timeout of relayed streams | none at tunnel level: the inner DoT, DoH and UI servers' own idle and handshake timeouts apply (`tcp.rs`, `doh.rs`), because the stream is handed to the same acceptors |
| Control stream queue | 16 frames each way, as the cluster channel (`Channel::new(16)` in `net.rs`). When it is full, heartbeats are dropped and counted, never queued: the next heartbeat replaces a dropped one |
| A refused stream | an HTTP response, not `RST_STREAM`: `503` for a budget refusal, `400` for a header refusal, each with a `wrendns-reason` header (Q20), and the broker closes the caller's connection |

**Why.** As far as I know, neither hyper's nor h2's API lets the receiving side give one stream a larger receive window than another (they expose `initial_stream_window_size` per connection and release only consumed capacity). I have not confirmed that against the current h2 source. ADR-1047 point 6's per-class windows are therefore read here as **bounds on memory per stream**: 16 KiB inbound for every stream, and a class-sized outbound queue. 128 × 16 KiB + 32 × 256 KiB is 10 MiB, within the +12 MiB target. The 1 MiB connection window caps what a misbehaving broker can make the node buffer. A response status is simple to send from a hyper `service_fn` and carries the reason, while `REFUSED_STREAM` (RFC 9113 §8.7) means "not processed, safe to retry", which is wrong for a header refusal.

**Main alternative.** Use h2 directly with a per-stream flow-control layer, to honour the window ranges literally in both directions. That is more code on the node, for traffic that is mostly small requests inbound. Making the windows adaptive (hyper's `adaptive_window`) would make memory harder to predict on a Pi.

**Tradeoff: minor.** HTTP/2 settings are exchanged on every connection and can change in any release.

## Q17. Backoff details

**Recommendation.**
- **Confirm the doubling reading:** the cap for attempt *n* (from 0) is `min(300 s, 1 s × 2^n)`. The wait is uniform from 0 to the cap, with a floor of 200 ms, as `net.rs` uses.
- **Reset:** only after a tunnel has stayed up, with the hello exchanged, for at least 60 s, which is the cluster channel's rule (`net.rs`: "it was up for a while"). A completed hello alone does not reset it, so a broker that accepts and then drops the connection cannot cause a tight loop.
- **The broker may ask for a longer wait:** `Close { retry_after_s }`, used for a drain before a planned restart (the broker spreads the values) and for overload. The node waits `max(its own backoff draw, retry_after_s)`, with `retry_after_s` clamped to 300 s. A broker can deny service anyway, so honouring the field gives it no new power, and the clamp keeps ADR-1047's 5-minute cap.

**Why.** This is ADR-1047 point 5 with ADR-044's shape, and the code already does it. The reset rule prevents a known failure loop.

**Main alternative.** Ignore broker hints. That is simpler, but a planned restart then causes a herd of reconnects at 0 to 1 s.

**Tradeoff: none.**

## Q18. A refused certificate

**Recommendation.**
- The broker refuses at the TLS layer with the standard alerts (RFC 8446 §6.2): `certificate_revoked` for a denied serial, and `certificate_expired` for a certificate past the 180-day grace. Within the grace period an expired certificate gets a renew-only tunnel (Q11). The node can trust the alert, because in TLS 1.3 it has already verified the pinned broker before it sends its own certificate.
- **Denied serial:** the node stops automatic dialling and raises **`cloud_node_removed`** (degraded; DNS unaffected; the panel says the node was removed from the cloud and offers "Link again" and "Retry now"). It then tries once a day, in case the removal was a mistake that was undone in the portal.
- **Past the grace:** `cloud_certificate_expired` (degraded), the same stop and daily retry, and the panel says to link again.
- **Expired within the grace, and no countersignature available** (the primary is unreachable): normal backoff, and `cloud_certificate_expired` stays raised.

**Why.** TLS alerts are the standard signal, need no extra protocol, and surface in rustls as a received alert the node can match. A removed node that keeps dialling gains nothing and keeps sending its source address to the cloud. "Retry now" and the daily retry let an undone removal recover without a restart.

**Main alternative.** Complete the handshake with the denied certificate and send `Close{node_removed}` on the control stream. That carries more detail, but the broker then has to accept a revoked identity far enough to talk to it.

**Tradeoff: minor.**

## Q19. Close reasons

**Recommendation.** Before closing, the side that closes sends a `Close { reason, retry_after_s, message }` control frame, then HTTP/2 `GOAWAY` with `NO_ERROR`, lets in-flight streams finish for up to 30 s, and closes TLS with `close_notify`. `message` is at most 256 bytes, for display only, and is shown escaped. The reasons are `removed`, `suspended`, `superseded`, `identity_mismatch`, `version_unsupported`, `draining`, `overloaded` and `protocol_error`. Revocation and expiry are TLS alerts (Q18). The node closes with `Close{shutdown}` or the `Disconnect` frame (T36.5).

**Why.** RFC 9113 §6.8 says GOAWAY's debug data is for diagnostics only and carries no semantic value, so the reason belongs in the protocol's own frame. A frame also keeps the reason when QUIC is added later. The node can show the reason in its panel and choose its backoff from it.

**Main alternative.** Close silently and let the portal show the reason. The node's admin would then see only "unreachable".

**Tradeoff: minor.**

## Q20. Error-code encoding

**Recommendation.**
- **Strings:** lowercase snake_case of at most 64 bytes, in `Close.reason`, `BlobDone.reason`, `ChangeResult` and the `wrendns-reason` response header. This matches the node's existing codes (`gitops_managed`, `version_conflict`, health reasons). An unknown code is shown as "unknown (<code>)" and is never acted on.
- **HTTP/2 mapping:** stream refusals are HTTP statuses with a reason header (Q16). `RST_STREAM CANCEL` is used when either side abandons a relayed connection mid-stream. HTTP/2 error codes (`PROTOCOL_ERROR`, `FLOW_CONTROL_ERROR`, `ENHANCE_YOUR_CALM`, and the rest) are left to the HTTP/2 layer for HTTP/2 faults. A deliberate close is `Close` plus `GOAWAY NO_ERROR` (Q19).
- **Budget label values:** `dns` and `ui`, plus `blob` for the blob limit.
- **Metric names:** the full prefix is `wrendns_cloud_tunnel_`: `wrendns_cloud_tunnel_up`, `wrendns_cloud_tunnel_reconnects_total`, `wrendns_cloud_tunnel_streams{budget}` (a gauge), `wrendns_cloud_tunnel_streams_refused_total{budget}` and `wrendns_cloud_tunnel_relay_header_refused_total{reason}`. `reason` takes a fixed set of values: `private`, `loopback`, `link_local`, `shared`, `lan`, `special`, `local_command`, `sni_mismatch`, `unknown_name`, `malformed`. Later cloud metrics use `wrendns_cloud_<area>_`, for example `wrendns_cloud_cert_`.

**Why.** Strings cost little at these rates, read well in logs and the audit, and need no shared enum table between two repositories. The short names in T36.4 and hosted.md all follow `wrendns_cloud_tunnel_up`, so `_tunnel_` is their stem. This matches `wrendns_cluster_peer_up` and `wrendns_cluster_rollouts_total`. A small fixed `reason` label tells the owner why streams are refused without making the label set unbounded.

**Main alternative.** Protobuf enums for reasons. They are smaller and checked by the compiler, but prost keeps an unknown enum value as an `i32`, so both sides need the same table, which the separate repositories make awkward. For metrics, the alternative is `wrendns_cloud_` with no `tunnel`, which is shorter but leaves no room for the other cloud subsystems.

**Tradeoff: minor.**

## Q21. "The tenant's own LAN ranges"

**Recommendation.** The union of:
1. **every prefix on this node's own interfaces** (`ifaddrs.rs`), automatic and up to date; and
2. **`[cloud] lan_networks`**, a replicated, admin-only list for sites whose prefixes are not on this node's interfaces (another site of a multi-site cluster, a routed VLAN). It is empty by default and ships with its UI control in Settings → WrenDNS Cloud, a help entry and a test, under the UI rule.

Loopback and link-local prefixes are ignored here, because other rules already refuse them. A configured entry shorter than /8 for IPv4 or /32 for IPv6 is refused when the config is validated, so a mistyped `0.0.0.0/0` cannot refuse every stream. The panel shows the effective list.

**Why.** At home IPv4 is usually private and already refused, so this rule mostly matters for **IPv6**, where a LAN uses public prefixes that change with the ISP's delegation. Interface prefixes follow those changes without configuration, and they can be tested on a Pi. `[access] allowed_networks` and `allowed_admin_networks` describe who may use the node, not what the LAN is: they are often broad, and `allowed_networks` can be the whole internet. Group networks are narrower but optional and incomplete. A home device that reaches the cloud path over IPv6 is refused by this rule rather than silently relayed. The node can name that case in its "a device at home is using the cloud path" notice, because the refused address is in a LAN prefix.

**Main alternative.** Also include the groups' `networks` and the CMDB's networks. That covers more without the list, but it ties a security check to data an operator edits for other reasons, and that data can be broader than the LAN.

**Tradeoff: minor.**

## Q22. Other special-purpose addresses

**Recommendation.** Yes. Refuse every address that the IANA IPv4 and IPv6 Special-Purpose Address Registries (RFC 6890 and its updates) mark as **not globally reachable**, plus multicast. Check **embedded IPv4 forms** against the IPv4 rules:
- IPv4: `0.0.0.0/8`, `192.0.0.0/24` (except the registry's globally reachable entries), `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255`, on top of RFC 1918, RFC 6598, loopback and link-local, which spec/14 already lists.
- IPv6: `::/128`, `::ffff:0:0/96` (IPv4-mapped: unwrap and check the IPv4 address), `64:ff9b::/96` (RFC 6052 NAT64: check the embedded IPv4 address), `64:ff9b:1::/48` (RFC 8215, local use), `100::/64`, `2001:db8::/32`, `ff00::/8`, on top of RFC 4193, loopback and link-local.
- The table is data, copied from the two IANA registries with their access date in a comment, and checked by a unit test per row. I am not certain every row's "globally reachable" flag is as I list it here, so the implementer copies the flags from the registries rather than from this page.
- **Test vectors:** the check is a pure function over a table. Production uses the full table. The fake broker's tests build the check with the documentation ranges removed, so vectors V1 to V3 can keep using RFC 5737 and RFC 3849 addresses, as `spec/14` §0 requires. A separate unit test shows that the production table refuses `203.0.113.7` and `2001:db8::7`.

**Why.** No real caller comes from these ranges. An address from them in a PROXY header means a broker bug or a forged header, which is what §12.2 is for. Without unwrapping, `::ffff:192.168.1.20` would pass the private-address rule in its IPv6 form. Using the registries keeps the rule standard instead of a hand-picked list.

**Main alternative.** Keep the rule as written (private, loopback, link-local, RFC 6598, LAN) and add only the IPv4-mapped unwrapping. That needs no table to maintain, but a broker could then report `0.0.0.0` or a multicast address as a caller.

**Tradeoff: minor.**
