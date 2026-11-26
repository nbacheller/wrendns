//! Node-to-node messages (REQ: CLU-001, CLU-010; `spec/12` §3): protobuf (`prost`), each frame
//! a 4-byte big-endian length then the encoded [`Frame`]. Fields are only ever added (never
//! renumbered), so version N and N-1 interoperate: unknown fields are ignored.

use prost::Message;

/// The protocol version this build speaks (CLU-010). Raised when a message changes meaning,
/// not when fields are added.
pub const PROTOCOL: u32 = 1;

/// Whether a peer's protocol works with ours: N and N-1 interoperate (`spec/12` §9), so a
/// rolling upgrade never splits the cluster. Further apart, the stream is refused.
pub fn protocol_compatible(peer: u32) -> bool {
    peer.abs_diff(PROTOCOL) <= 1
}
/// Largest frame accepted (snapshot manifests arrive later; blobs go over their own requests).
pub const MAX_FRAME: usize = 1 << 20;

/// The first message on a stream, both ways.
#[derive(Clone, PartialEq, Message)]
pub struct Hello {
    #[prost(uint32, tag = "1")]
    pub protocol: u32,
    #[prost(string, tag = "2")]
    pub cluster_id: String,
    #[prost(string, tag = "3")]
    pub node_id: String,
    #[prost(string, tag = "4")]
    pub version: String,
    #[prost(string, tag = "5")]
    pub site: String,
    #[prost(bool, tag = "6")]
    pub eligible: bool,
    #[prost(string, repeated, tag = "7")]
    pub advertise: Vec<String>,
    /// The highest epoch this node has seen (CLU-005).
    #[prost(uint64, tag = "8")]
    pub epoch: u64,
    /// The config version it has applied (CLU-003).
    #[prost(uint64, tag = "9")]
    pub applied_seq: u64,
    #[prost(bool, tag = "10")]
    pub primary: bool,
    /// How this node's own configuration is managed: `gitops` or `file` (ADR-048).
    #[prost(string, tag = "11")]
    pub config_source: String,
    /// The Git commit of the configuration it serves (ADR-049).
    #[prost(string, tag = "12")]
    pub source_commit: String,
    /// REQ: CLU-005 (T24.38, ADR-1018) — a random id of the sending process, new at each start:
    /// a link that ends and comes back with another id was a restart, not a flapping link.
    /// Empty from a peer older than this field (prost skips unknown tags, so older peers ignore it).
    #[prost(string, tag = "13")]
    pub instance: String,
    /// REQ: DSC-908 (ADR-1096 point 5) - the gated shared sections and secret kinds this build
    /// knows (`gate::own_features`). Empty from a build older than this field: it knows none.
    #[prost(string, repeated, tag = "14")]
    pub features: Vec<String>,
}

/// A federated read (CLU-002, T5.6): `kind` names the call, `body` carries its arguments
/// (JSON). Answered on the same stream with the same `id`.
#[derive(Clone, PartialEq, Message)]
pub struct RpcRequest {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(string, tag = "2")]
    pub kind: String,
    #[prost(bytes = "vec", tag = "3")]
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RpcResponse {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// Empty on success.
    #[prost(string, tag = "2")]
    pub error: String,
    #[prost(bytes = "vec", tag = "3")]
    pub body: Vec<u8>,
}

/// The cluster CA key, from the primary to an eligible node (ADR-051).
#[derive(Clone, PartialEq, Message)]
pub struct KeyShare {
    #[prost(string, tag = "1")]
    pub ca_key_pem: String,
    /// During a CA rotation, the new CA's key (T5.4c).
    #[prost(string, tag = "2")]
    pub next_ca_key_pem: String,
}

/// Sent every few seconds both ways; its absence marks a peer down.
#[derive(Clone, PartialEq, Message)]
#[allow(clippy::struct_excessive_bools)] // independent wire flags, each with its own tag
pub struct Heartbeat {
    /// Sender's clock (Unix ms), for lag display only.
    #[prost(uint64, tag = "1")]
    pub ts_ms: u64,
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
    #[prost(uint64, tag = "3")]
    pub applied_seq: u64,
    /// Queries per second over the last minute (CLU-008).
    #[prost(uint64, tag = "4")]
    pub qps: u64,
    /// The `ts_ms` of the last heartbeat received from this peer, echoed back, and how long
    /// ago it arrived: the peer computes the round-trip time from them.
    #[prost(uint64, tag = "5")]
    pub echo_ms: u64,
    #[prost(uint32, tag = "6")]
    pub echo_delay_ms: u32,
    /// Serving DNS: listeners bound and not shutting down.
    #[prost(bool, tag = "7")]
    pub ready: bool,
    /// SERVFAIL answers per thousand over the last minute.
    #[prost(uint32, tag = "8")]
    pub servfail_permille: u32,
    /// Upstream p90 this hour, in microseconds.
    #[prost(uint64, tag = "9")]
    pub p90_us: u64,
    #[prost(uint64, tag = "10")]
    pub uptime_s: u64,
    /// The Git commit of the configuration it serves (ADR-049), if the cluster's config
    /// comes from Git.
    #[prost(string, tag = "11")]
    pub source_commit: String,
    /// The CAs it trusts, as [`crate::pki::trust_fp`] (CA rotation readiness, T5.4c).
    #[prost(string, tag = "12")]
    pub trust_fp: String,
    /// The fingerprint of the CA that issued its certificate (T5.4c).
    #[prost(string, tag = "13")]
    pub issuer_fp: String,
    /// The machine it runs on, sampled every 15 s (T6.11). Absent from older nodes.
    #[prost(message, optional, boxed, tag = "14")]
    pub host: Option<Box<HostStats>>,
    /// REQ: CLU-008 (T6.14) — where it runs in Kubernetes (the downward API's node and pod
    /// names); empty outside Kubernetes or from older nodes.
    #[prost(string, tag = "15")]
    pub kube_node: String,
    #[prost(string, tag = "16")]
    pub pod: String,
    /// When this process started (Unix ms): a change means it restarted.
    #[prost(uint64, tag = "17")]
    pub started_ms: u64,
    /// Its cache: entries, and hits per thousand lookups over the last minute.
    #[prost(uint64, optional, tag = "18")]
    pub cache_entries: Option<u64>,
    #[prost(uint32, optional, tag = "19")]
    pub cache_hit_permille: Option<u32>,
    /// REQ: OPS-010 (T13.4) — when its maintenance window ends (Unix ms, its clock); 0 when it
    /// isn't in maintenance, and from older nodes. The reason, who started it, and when.
    #[prost(uint64, tag = "20")]
    pub maintenance_until_ms: u64,
    #[prost(string, tag = "21")]
    pub maintenance_reason: String,
    #[prost(string, tag = "22")]
    pub maintenance_by: String,
    #[prost(uint64, tag = "23")]
    pub maintenance_since_ms: u64,
    /// REQ: CLU-013 (T13.2) — it takes part in staged rollouts (it can be a canary). False
    /// from older nodes, which are only ever sent stable versions.
    #[prost(bool, tag = "24")]
    pub rollouts: bool,
    /// REQ: CLU-013 — why it couldn't apply the newest version, if it couldn't (the rollout
    /// guard reads it). Empty from older nodes.
    #[prost(string, tag = "25")]
    pub sync_error: String,
    /// REQ: CLU-013 — one of its own listener probes is failing (the rollout guard reads it).
    #[prost(bool, tag = "26")]
    pub probe_failing: bool,
    /// REQ: CLU-013 — while it runs a canary version: the stable version (`seq`) that one
    /// would replace, so nodes still on stable don't count as behind during a bake. 0 otherwise
    /// (and from older nodes).
    #[prost(uint64, tag = "27")]
    pub canary_of: u64,
    /// REQ: CLU-008 — the queries it answered over the last minute: `qps` rounds down, so a
    /// node under 1 q/s showed 0. Absent from older nodes (read as `qps` × 60).
    #[prost(uint64, optional, tag = "28")]
    pub queries_last_minute: Option<u64>,
    /// REQ: CLU-014 (ADR-151) — it understands failover drills (false from older nodes, which
    /// a drill report lists as missing).
    #[prost(bool, tag = "29")]
    pub drills: bool,
    /// REQ: CLU-014 — the drill it runs, if any: its ID, start, and end (Unix ms, its clock);
    /// every node records a window for it while it lasts.
    #[prost(string, tag = "30")]
    pub drill_id: String,
    #[prost(uint64, tag = "31")]
    pub drill_since_ms: u64,
    #[prost(uint64, tag = "32")]
    pub drill_until_ms: u64,
    /// REQ: CLU-015 (ADR-903 §6) — the newest secrets head this node holds (the primary's is the
    /// cluster's). Absent from older nodes, which ignore the tags.
    #[prost(message, optional, tag = "33")]
    pub secrets_head: Option<SecretsHeadMsg>,
    /// REQ: CLU-015 — the head of this node's own store after it applied the primary's rows.
    #[prost(message, optional, tag = "34")]
    pub secrets_applied: Option<SecretsHeadMsg>,
    /// REQ: CLU-015 — live secrets this node can't read (encrypted under a key it doesn't have).
    #[prost(uint32, tag = "35")]
    pub secrets_unreadable: u32,
    /// REQ: CLU-015 — secrets the primary holds but couldn't decrypt for this answer ("held").
    #[prost(uint32, tag = "36")]
    pub secrets_held: u32,
    /// REQ: CLU-015 — configuration paths this node refuses to read as credentials (at most 32).
    #[prost(string, repeated, tag = "37")]
    pub credential_issues: Vec<String>,
    /// REQ: CLU-015 — names its node-local fields reference (at most 128), so `DELETE` checks them.
    #[prost(string, repeated, tag = "38")]
    pub secret_refs: Vec<String>,
    /// REQ: OBS-010 (T24.5, fork #2) — for a replica: how long it has gone without a heartbeat
    /// from its primary, in seconds (absent when it reaches the primary or is the primary, and
    /// from older nodes, which ignore the tag).
    #[prost(uint64, optional, tag = "40")]
    pub primary_silent_s: Option<u64>,
    /// REQ: CLU-005 (ADR-051) — whether the sender is the primary now. A Hello says it only when a
    /// stream opens, so a promotion after that is seen only here. Absent from older nodes (`None`):
    /// the flag a peer already holds stays.
    #[prost(bool, optional, tag = "39")]
    pub primary: Option<bool>,
    /// REQ: CLU-001 (ADR-960) — the members the sender has heard from within the `up` window, and
    /// how long ago. A replica in manual failover has a stream only to its primary, so this is how
    /// it learns that the other replicas are up. Absent from older nodes, which ignore the tag.
    #[prost(message, repeated, tag = "41")]
    pub peers: Vec<PeerHealth>,
}

/// REQ: CLU-001 (ADR-960) — what a node tells its peers about another member it hears from (a relay).
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PeerHealth {
    #[prost(string, tag = "1")]
    pub node_id: String,
    /// How long ago the sender last heard it, in milliseconds.
    #[prost(uint64, tag = "2")]
    pub age_ms: u64,
    #[prost(bool, tag = "3")]
    pub ready: bool,
    #[prost(uint64, tag = "4")]
    pub applied_seq: u64,
}

/// REQ: CLU-015 (ADR-903 §6) — a secrets head on the wire: the highest stamp and the BLAKE3
/// digest of the sorted `(name, kind, stamp, deleted)` list. Holds no value.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct SecretsHeadMsg {
    #[prost(uint64, tag = "1")]
    pub epoch: u64,
    #[prost(uint64, tag = "2")]
    pub seq: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub digest: Vec<u8>,
}

/// REQ: CLU-008 (T6.11) — the resources of the machine a node runs on, for monitoring and
/// triage. Each value is optional: absent means the node couldn't read it (another OS, a
/// locked-down container), never zero. Sizes are bytes; ratios are permille.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct HostStats {
    /// When it was sampled (the sender's clock, Unix ms).
    #[prost(uint64, tag = "1")]
    pub ts_ms: u64,
    #[prost(uint64, optional, tag = "2")]
    pub mem_total: Option<u64>,
    /// `MemAvailable`: what can be used without swapping.
    #[prost(uint64, optional, tag = "3")]
    pub mem_available: Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    pub swap_total: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    pub swap_free: Option<u64>,
    /// The container's memory limit (cgroup), when it has one.
    #[prost(uint64, optional, tag = "6")]
    pub cgroup_mem_limit: Option<u64>,
    #[prost(uint64, optional, tag = "7")]
    pub cgroup_mem_current: Option<u64>,
    /// Processes the kernel killed in this cgroup for lack of memory, ever.
    #[prost(uint64, optional, tag = "8")]
    pub oom_kills: Option<u64>,
    /// This process's resident memory.
    #[prost(uint64, optional, tag = "9")]
    pub process_rss: Option<u64>,
    #[prost(uint32, optional, tag = "10")]
    pub cpus: Option<u32>,
    /// Load averages over 1, 5, and 15 minutes, times 1000.
    #[prost(uint32, optional, tag = "11")]
    pub load1_milli: Option<u32>,
    #[prost(uint32, optional, tag = "12")]
    pub load5_milli: Option<u32>,
    #[prost(uint32, optional, tag = "13")]
    pub load15_milli: Option<u32>,
    /// Host CPU busy over the last sample interval.
    #[prost(uint32, optional, tag = "14")]
    pub cpu_permille: Option<u32>,
    /// The container's CPU quota in thousandths of a core (`cpu.max`), when limited.
    #[prost(uint32, optional, tag = "15")]
    pub cgroup_cpu_quota_milli: Option<u32>,
    /// Share of the last interval the container was throttled by its quota.
    #[prost(uint32, optional, tag = "16")]
    pub throttled_permille: Option<u32>,
    /// The filesystem holding the data directory.
    #[prost(uint64, optional, tag = "17")]
    pub disk_total: Option<u64>,
    #[prost(uint64, optional, tag = "18")]
    pub disk_free: Option<u64>,
    #[prost(uint64, optional, tag = "19")]
    pub qlog_bytes: Option<u64>,
    #[prost(uint64, optional, tag = "20")]
    pub snapshot_bytes: Option<u64>,
    /// Bytes this process wrote to storage per second over the last interval.
    #[prost(uint64, optional, tag = "21")]
    pub write_bytes_per_s: Option<u64>,
    #[prost(uint64, optional, tag = "22")]
    pub host_uptime_s: Option<u64>,
    /// The hottest thermal zone, in thousandths of a degree Celsius.
    #[prost(int32, optional, tag = "23")]
    pub temp_millic: Option<i32>,
    #[prost(string, tag = "24")]
    pub os: String,
    #[prost(string, tag = "25")]
    pub kernel: String,
    #[prost(string, tag = "26")]
    pub arch: String,
    #[prost(uint32, optional, tag = "27")]
    pub open_fds: Option<u32>,
    #[prost(uint32, optional, tag = "28")]
    pub max_fds: Option<u32>,
    #[prost(uint32, optional, tag = "29")]
    pub threads: Option<u32>,
    /// Sources that couldn't be read (e.g. `cgroup`, `thermal`), so "absent" can be explained.
    #[prost(string, repeated, tag = "30")]
    pub unavailable: Vec<String>,
}

/// A signed cluster manifest (CLU-003, `crate::sync`): the primary sends it on connect and
/// whenever it changes.
#[derive(Clone, PartialEq, Message)]
pub struct ManifestMsg {
    #[prost(bytes = "vec", tag = "1")]
    pub json: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub sig: Vec<u8>,
}

/// One message on a stream.
#[derive(Clone, PartialEq, Message)]
pub struct Frame {
    #[prost(oneof = "Body", tags = "1, 2, 3, 4, 5, 6")]
    pub body: Option<Body>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
// A frame is built, encoded and dropped at once; boxing the heartbeat would change every call site.
#[allow(clippy::large_enum_variant)]
pub enum Body {
    #[prost(message, tag = "1")]
    Hello(Hello),
    #[prost(message, tag = "2")]
    Heartbeat(Heartbeat),
    #[prost(message, tag = "3")]
    Manifest(ManifestMsg),
    #[prost(message, tag = "4")]
    KeyShare(KeyShare),
    #[prost(message, tag = "5")]
    RpcRequest(RpcRequest),
    #[prost(message, tag = "6")]
    RpcResponse(RpcResponse),
}

/// A frame with its length prefix.
pub fn encode(f: &Frame) -> Vec<u8> {
    let body = f.encode_to_vec();
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Splits complete frames off the front of `buf` (incomplete bytes stay for the next read).
pub fn decode_all(buf: &mut Vec<u8>) -> Result<Vec<Frame>, String> {
    let mut out = Vec::new();
    while let Some(len) = buf.first_chunk::<4>().map(|b| u32::from_be_bytes(*b)) {
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > MAX_FRAME {
            return Err(format!("frame of {len} bytes is over the limit"));
        }
        if buf.len() < 4 + len {
            break;
        }
        let f = Frame::decode(&buf[4..4 + len]).map_err(|e| format!("bad frame: {e}"))?;
        buf.drain(..4 + len);
        out.push(f);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-010 — N and N-1 interoperate both ways; two versions apart don't.
    #[test]
    fn clu_010_protocols_one_version_apart_interoperate() {
        assert!(protocol_compatible(PROTOCOL));
        assert!(protocol_compatible(PROTOCOL + 1));
        assert!(protocol_compatible(PROTOCOL - 1));
        assert!(!protocol_compatible(PROTOCOL + 2));
    }

    // REQ: DSC-908 - the announced features round-trip, and a Hello from a build older than the
    // field decodes with none (it knows no gated feature).
    #[test]
    fn dsc_908_hello_features_round_trip_and_default_to_none() {
        let h = Hello {
            features: vec!["pem_secrets".into()],
            ..Hello::default()
        };
        assert_eq!(Hello::decode(&h.encode_to_vec()[..]).unwrap(), h);
        let old = Hello {
            version: "1.1.0-edge.40".into(),
            ..Hello::default()
        };
        let back = Hello::decode(&old.encode_to_vec()[..]).unwrap();
        assert_eq!(back.features, Vec::<String>::new());
    }

    #[test]
    fn clu_010_frames_round_trip_in_pieces() {
        let hello = Frame {
            body: Some(Body::Hello(Hello {
                source_commit: String::new(),
                protocol: PROTOCOL,
                cluster_id: "c".into(),
                node_id: "n1".into(),
                version: "0.1.0".into(),
                site: "k8s".into(),
                eligible: true,
                advertise: vec!["https://10.0.0.1:8443".into()],
                epoch: 3,
                applied_seq: 9,
                primary: false,
                config_source: String::new(),
                instance: "0123456789abcdef".into(),
                features: Vec::new(),
            })),
        };
        let hb = Frame {
            body: Some(Body::Heartbeat(Heartbeat {
                source_commit: String::new(),
                ts_ms: 1,
                epoch: 3,
                applied_seq: 9,
                qps: 42,
                ..Heartbeat::default()
            })),
        };
        let mut wire = encode(&hello);
        wire.extend(encode(&hb));
        // Fed byte by byte, frames come out whole and in order.
        let mut buf = Vec::new();
        let mut got = Vec::new();
        for b in wire {
            buf.push(b);
            got.extend(decode_all(&mut buf).unwrap());
        }
        assert_eq!(got, [hello, hb]);
        assert_eq!(buf, Vec::<u8>::new());
        // A huge length is refused before any allocation.
        let mut bad = (u32::MAX).to_be_bytes().to_vec();
        assert!(decode_all(&mut bad).is_err());
    }

    /// REQ: CLU-005 (ADR-051) — the heartbeat's primary flag is optional both ways: an older node's
    /// heartbeat decodes with no flag (so a peer keeps the one it holds), and an older node skips it.
    #[test]
    fn clu_005_the_heartbeat_primary_flag_is_optional_both_ways() {
        let old = Heartbeat {
            epoch: 2,
            ..Heartbeat::default()
        }
        .encode_to_vec();
        assert_eq!(Heartbeat::decode(&old[..]).unwrap().primary, None);
        let new = Heartbeat {
            epoch: 2,
            primary: Some(true),
            ..Heartbeat::default()
        };
        let back = Heartbeat::decode(&new.encode_to_vec()[..]).unwrap();
        assert_eq!(back.primary, Some(true));
        // A flag set to false is still sent (present, not the default): it says "stepped down".
        let stepped = Heartbeat {
            primary: Some(false),
            ..Heartbeat::default()
        };
        assert_eq!(
            Heartbeat::decode(&stepped.encode_to_vec()[..])
                .unwrap()
                .primary,
            Some(false)
        );
    }

    /// REQ: CLU-010 (T6.14) — a heartbeat from an older node (no pod, start time, or cache
    /// fields) decodes with them empty, and an older node skips them.
    #[test]
    fn clu_010_t614_fields_are_optional_both_ways() {
        let old = Heartbeat {
            qps: 3,
            ..Heartbeat::default()
        }
        .encode_to_vec();
        let hb = Heartbeat::decode(&old[..]).unwrap();
        assert_eq!(
            (hb.pod.as_str(), hb.started_ms, hb.cache_entries),
            ("", 0, None)
        );
        let new = Heartbeat {
            qps: 3,
            kube_node: "k3s-1".into(),
            pod: "wrendns-resolver-7d9f".into(),
            started_ms: 1_759_000_000_000,
            cache_entries: Some(1200),
            cache_hit_permille: Some(812),
            ..Heartbeat::default()
        };
        let back = Heartbeat::decode(&new.encode_to_vec()[..]).unwrap();
        assert_eq!(back, new);
    }

    /// REQ: CLU-008, CLU-010 — the exact per-minute count is optional both ways: absent from an
    /// older node, and it survives a round trip.
    #[test]
    fn clu_008_queries_last_minute_is_optional_both_ways() {
        let old = Heartbeat {
            qps: 3,
            ..Heartbeat::default()
        }
        .encode_to_vec();
        assert_eq!(
            Heartbeat::decode(&old[..]).unwrap().queries_last_minute,
            None
        );
        let new = Heartbeat {
            qps: 0,
            queries_last_minute: Some(22),
            ..Heartbeat::default()
        };
        assert_eq!(Heartbeat::decode(&new.encode_to_vec()[..]).unwrap(), new);
    }

    /// REQ: OPS-010, CLU-010 (T13.4) — the maintenance fields are optional both ways: an older
    /// node's heartbeat decodes as "not in maintenance", and they survive a round trip.
    #[test]
    fn ops_010_maintenance_fields_are_optional_both_ways() {
        let old = Heartbeat {
            qps: 3,
            ..Heartbeat::default()
        }
        .encode_to_vec();
        let hb = Heartbeat::decode(&old[..]).unwrap();
        assert_eq!(
            (hb.maintenance_until_ms, hb.maintenance_reason.as_str()),
            (0, "")
        );
        let new = Heartbeat {
            maintenance_until_ms: 1_760_025_600_000,
            maintenance_since_ms: 1_760_022_000_000,
            maintenance_reason: "SD card swap".into(),
            maintenance_by: "alice via pi".into(),
            ..Heartbeat::default()
        };
        assert_eq!(Heartbeat::decode(&new.encode_to_vec()[..]).unwrap(), new);
    }

    /// REQ: CLU-015, CLU-010 (ADR-903 §6) — the secrets fields are optional both ways: an older
    /// node's heartbeat decodes with no head, and a node that doesn't know them (N-1) decodes
    /// ours and ignores them, the other fields unchanged.
    #[test]
    fn clu_015_n_minus_1_ignores_fields() {
        // What an N-1 node knows: the tags up to 32, nothing more.
        #[derive(Clone, PartialEq, Message)]
        struct HeartbeatN1 {
            #[prost(uint64, tag = "2")]
            epoch: u64,
            #[prost(uint64, tag = "3")]
            applied_seq: u64,
            #[prost(uint64, tag = "4")]
            qps: u64,
            #[prost(uint64, tag = "32")]
            drill_until_ms: u64,
        }
        let new = Heartbeat {
            epoch: 4,
            applied_seq: 9,
            qps: 7,
            drill_until_ms: 11,
            secrets_head: Some(SecretsHeadMsg {
                epoch: 4,
                seq: 12,
                digest: vec![7; 32],
            }),
            secrets_applied: Some(SecretsHeadMsg {
                epoch: 4,
                seq: 12,
                digest: vec![7; 32],
            }),
            secrets_unreadable: 2,
            secrets_held: 1,
            credential_issues: vec!["upstream[0].tls_ca".into()],
            secret_refs: vec!["router.unifi.api_key".into()],
            ..Heartbeat::default()
        };
        let bytes = new.encode_to_vec();
        let n1 = HeartbeatN1::decode(&bytes[..]).unwrap();
        assert_eq!(
            (n1.epoch, n1.applied_seq, n1.qps, n1.drill_until_ms),
            (4, 9, 7, 11)
        );
        // And an N-1 heartbeat (no secrets fields) decodes with them empty.
        let old = HeartbeatN1 {
            epoch: 1,
            applied_seq: 0,
            qps: 0,
            drill_until_ms: 0,
        }
        .encode_to_vec();
        let back = Heartbeat::decode(&old[..]).unwrap();
        assert_eq!(back.secrets_head, None);
        assert_eq!(back.secrets_applied, None);
        assert_eq!((back.secrets_unreadable, back.secrets_held), (0, 0));
        assert!(back.credential_issues.is_empty() && back.secret_refs.is_empty());
        // The new one round-trips.
        assert_eq!(Heartbeat::decode(&bytes[..]).unwrap(), new);
    }

    #[test]
    fn clu_010_unknown_fields_are_ignored() {
        // A newer peer's Heartbeat with an extra field 99 still decodes.
        let mut body = Heartbeat {
            source_commit: String::new(),
            ts_ms: 5,
            epoch: 1,
            applied_seq: 2,
            qps: 3,
            ..Heartbeat::default()
        }
        .encode_to_vec();
        body.extend_from_slice(&[0x98, 0x06, 0x07]); // field 99, varint 7
        assert_eq!(Heartbeat::decode(&body[..]).unwrap().qps, 3);
    }
}
