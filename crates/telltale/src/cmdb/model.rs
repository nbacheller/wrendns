//! REQ: DSC-902 (T31.2, ADR-1004 sections 2, 3 and 5) - the CMDB's data model: CI types, source
//! records as the sources reported them, the normalisers that make keys comparable, and the caps.
//! No I/O and no clock: callers pass the time. Nothing here reaches DNS answers, client matching,
//! `identify`, policy or device names in DNS (DSC-901).

use std::collections::BTreeMap;

use serde_json::Value;
use telltale_store::cmdb::RecordWrite;

/// CIs of all types, ports included (ADR-1005 section 3).
pub(crate) const MAX_CIS: i64 = 16_384;
/// Source records in total (ADR-1005 section 3).
pub(crate) const MAX_RECORDS: i64 = 65_536;
/// Source records one CI keeps at most.
pub(crate) const MAX_RECORDS_PER_CI: i64 = 8;
/// Attributes one record keeps at most (DSC-015).
pub(crate) const MAX_ATTRS: usize = 24;
/// A value is cut to this many bytes (DSC-015).
pub(crate) const VALUE_MAX: usize = 255;
/// Entries one list value keeps at most.
pub(crate) const LIST_MAX: usize = 16;
/// Batches the sink holds before it drops the oldest (ADR-1005 section 3).
pub(crate) const SINK_BATCHES: usize = 64;
/// `last_seen` is written back only when the stored value is this old (ADR-1005 section 3).
pub(crate) const FLUSH_STALE_SECS: i64 = 6 * 3600;
/// How often `last_seen` is flushed.
pub(crate) const FLUSH_EVERY_SECS: i64 = 15 * 60;
/// A merge alias redirects this long (ADR-1004 section 2).
pub(crate) const ALIAS_SECS: i64 = 90 * 86_400;
/// An `unconfirmed` CI with no present record and no authored data is removed after this long
/// (ADR-1005 section 5).
pub(crate) const UNCONFIRMED_SECS: i64 = 30 * 86_400;
/// `days_seen` stops counting here (ADR-1005 section 3).
pub(crate) const DAYS_SEEN_CAP: i64 = 32;
/// A record absent for this many complete batches leaves `present` (ADR-924).
pub(crate) const ABSENT_AFTER: u8 = 2;
/// The learning period after an empty start (ADR-910).
pub(crate) const LEARNING_SECS: i64 = 24 * 3600;

/// The caps (ADR-1005 section 3). The defaults are the constants above; a test sets smaller ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Caps {
    pub(crate) cis: i64,
    pub(crate) records: i64,
    pub(crate) per_ci: i64,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            cis: MAX_CIS,
            records: MAX_RECORDS,
            per_ci: MAX_RECORDS_PER_CI,
        }
    }
}

/// What a source record, a CI or a link is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RecKind {
    /// A host or an infrastructure device, with or without a MAC.
    Device,
    /// A switch or access point port (an interface CI of kind `port`).
    Port,
    Network,
    Node,
    Service,
    Upstream,
}

impl RecKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Port => "port",
            Self::Network => "network",
            Self::Node => "node",
            Self::Service => "service",
            Self::Upstream => "upstream",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "device" => Self::Device,
            "port" => Self::Port,
            "network" => Self::Network,
            "node" => Self::Node,
            "service" => Self::Service,
            "upstream" => Self::Upstream,
            _ => return None,
        })
    }

    /// The CI type its records link to.
    pub(crate) const fn ci_type(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Port => "interface",
            Self::Network => "network",
            Self::Node => "node",
            Self::Service => "service",
            Self::Upstream => "upstream",
        }
    }
}

/// One record as an adapter hands it over: what the source said, as it said it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Record {
    /// The kind and instance: `unifi:<router>`, `snmp:<agent>`, `neighbor`, ... (ADR-1004 section 3).
    pub(crate) source: String,
    /// The thing's identity in that source.
    pub(crate) key: String,
    pub(crate) kind: RecKind,
    pub(crate) attrs: BTreeMap<String, Value>,
    /// Unix seconds.
    pub(crate) seen: i64,
}

impl Record {
    pub(crate) fn new(source: &str, key: &str, kind: RecKind, seen: i64) -> Self {
        Self {
            source: source.to_owned(),
            key: key.to_owned(),
            kind,
            attrs: BTreeMap::new(),
            seen,
        }
    }

    /// Sets a text attribute.
    pub(crate) fn text(&mut self, name: &str, value: impl Into<String>) -> &mut Self {
        self.attrs
            .insert(name.to_owned(), Value::String(value.into()));
        self
    }

    /// Sets a text attribute when there is one.
    pub(crate) fn opt_text(&mut self, name: &str, value: Option<impl Into<String>>) -> &mut Self {
        if let Some(v) = value {
            self.text(name, v);
        }
        self
    }

    /// Sets a number attribute.
    pub(crate) fn num(&mut self, name: &str, value: i64) -> &mut Self {
        self.attrs.insert(name.to_owned(), Value::from(value));
        self
    }

    /// Sets a list attribute.
    pub(crate) fn list(&mut self, name: &str, values: Vec<String>) -> &mut Self {
        self.attrs.insert(
            name.to_owned(),
            Value::Array(values.into_iter().map(Value::String).collect()),
        );
        self
    }
}

/// What a source adapter pushes to the sink (ADR-1005 section 4).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SourceBatch {
    /// The source instance the records are from. A complete batch lists everything the instance
    /// reports now, so a record it leaves out is missed.
    pub(crate) source: String,
    pub(crate) complete: bool,
    pub(crate) records: Vec<Record>,
    /// Unix seconds.
    pub(crate) at: i64,
}

/// The source's kind: the part of `unifi:<router>` before the colon.
pub(crate) fn kind_of(source: &str) -> &str {
    source.split(':').next().unwrap_or(source)
}

/// The precedence class of a source's addresses (ADR-910, ADR-923): 1 to 3 are current bindings
/// (the routers, the neighbour table, an SNMP agent's ARP), 4 and 5 claims, 9 none.
pub(crate) fn class_of(source: &str) -> u8 {
    match kind_of(source) {
        "unifi" | "opnsense" | "lease" => 1,
        "neighbor" => 2,
        "snmp" => 3,
        "import" => 4,
        _ => 9,
    }
}

/// A presence source: one whose records say the thing is on the network now (class 1 to 3).
pub(crate) fn is_presence(source: &str) -> bool {
    class_of(source) <= 3
}

/// The rank of a source's name in ADR-910's order (lower wins): the configured name, Home
/// Assistant's, a router's alias, mDNS, SNMP, an import.
pub(crate) fn name_rank(source: &str) -> u8 {
    match kind_of(source) {
        "manual" => 0,
        "config" => 1,
        "cluster" | "k8s" => 2,
        "home_assistant" => 3,
        "unifi" | "opnsense" | "lease" => 4,
        "mdns" => 5,
        "snmp" => 6,
        "import" => 7,
        _ => 9,
    }
}

// -- normalisers -------------------------------------------------------------------------------

/// A MAC as `aa:bb:cc:dd:ee:ff`: the same parser the inventory's merge uses (R2 shares its
/// normalisation, ADR-1004 section 4). The all-zero and the broadcast MAC are not keys.
pub(crate) fn norm_mac(s: &str) -> Option<String> {
    let m = crate::discovery::sources::parse_mac(s)?;
    if m == [0; 6] || m == [0xff; 6] {
        return None;
    }
    Some(
        m.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Whether a MAC has the locally administered bit set (a randomised address, ADR-910).
pub(crate) fn mac_is_randomized(mac: &str) -> bool {
    crate::discovery::sources::parse_mac(mac).is_some_and(crate::discovery::inventory::is_randomized)
}

/// A serial, trimmed and lower-cased. Placeholders and short values are not keys.
pub(crate) fn norm_serial(s: &str) -> Option<String> {
    let t: String = s
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_ascii_lowercase();
    const JUNK: [&str; 8] = [
        "none",
        "unknown",
        "n/a",
        "na",
        "default string",
        "to be filled by o.e.m.",
        "not specified",
        "0",
    ];
    if t.len() < 4 || JUNK.contains(&t.as_str()) || t.chars().all(|c| c == '0') {
        return None;
    }
    Some(t)
}

/// A host name for rule R5: lower-case, without its domain. Generic names are not keys: two
/// phones called `iphone` on one VLAN are not one device (ADR-1004 alternatives).
pub(crate) fn norm_host(s: &str) -> Option<String> {
    let t = s.trim().to_ascii_lowercase();
    let first = t.split('.').next().unwrap_or("").trim();
    const GENERIC: [&str; 14] = [
        "iphone",
        "ipad",
        "android",
        "localhost",
        "unknown",
        "device",
        "host",
        "laptop",
        "desktop",
        "phone",
        "tablet",
        "pc",
        "esp",
        "wlan0",
    ];
    if first.len() < 3
        || GENERIC.contains(&first)
        || !first.chars().any(char::is_alphabetic)
        || first.chars().any(char::is_control)
    {
        return None;
    }
    Some(first.to_owned())
}

/// A network name or VLAN, for matching (case-folded).
pub(crate) fn norm_net(s: &str) -> Option<String> {
    let t = s.trim().to_ascii_lowercase();
    (!t.is_empty() && !t.chars().any(char::is_control)).then_some(t)
}

/// A port id as every source's normaliser makes it (docs/design/cmdb.md, Port identity): lower
/// case, with spaces, `-` and `_` removed. `Gi1/0/5` is `gi1/0/5`, `Port 5` is `port5`.
pub(crate) fn norm_port(s: &str) -> Option<String> {
    let t: String = s
        .chars()
        .filter(|c| !c.is_control() && !c.is_whitespace() && *c != '-' && *c != '_')
        .collect::<String>()
        .to_ascii_lowercase();
    (!t.is_empty()).then_some(t)
}

/// The trailing number of a port id (`gi1/0/5` is 5, `port12` is 12).
pub(crate) fn trailing_number(s: &str) -> Option<u32> {
    let digits: String = s
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().ok()
}

/// Control characters removed and the text cut to `max` bytes on a character boundary (DSC-015).
pub(crate) fn sanitize(raw: &str, max: usize) -> String {
    crate::discovery::inventory::sanitize(raw, max)
}

/// One value, cleaned: text and lists of text, cut; numbers and booleans as they are; anything
/// else (an object, `null`) is dropped.
fn clean(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) => Some(Value::String(sanitize(s, VALUE_MAX))),
        Value::Number(_) | Value::Bool(_) => Some(v.clone()),
        Value::Array(a) => Some(Value::Array(
            a.iter()
                .filter_map(|x| x.as_str().map(|s| Value::String(sanitize(s, VALUE_MAX))))
                .take(LIST_MAX)
                .collect(),
        )),
        _ => None,
    }
}

/// A record cleaned and reduced to what the store keeps: its keys, its addresses and its content
/// hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Prepared {
    pub(crate) write: RecordWrite,
    /// The hash of `(source, key)`, for the in-memory index.
    pub(crate) key_hash: u64,
    /// Attributes dropped over the 24-attribute cap.
    pub(crate) cut: usize,
}

/// The hash of `(source, key)`.
pub(crate) fn key_hash(source: &str, key: &str) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(source.as_bytes());
    h.update(&[0x1f]);
    h.update(key.as_bytes());
    first8(h.finalize().as_bytes())
}

fn first8(b: &[u8; 32]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(b.get(..8).unwrap_or(&[0u8; 8]));
    u64::from_le_bytes(a)
}

fn text_attr<'a>(attrs: &'a BTreeMap<String, Value>, name: &str) -> Option<&'a str> {
    attrs.get(name).and_then(Value::as_str)
}

/// Cleans a record and extracts its keys (the normalisers above). The content hash covers the type
/// and the attributes, never a time, so a record that says the same thing again writes nothing.
/// `None` for a record with no source or key text, a port without its owner, or a natural-key type
/// (network, node, service, upstream) without its key.
pub(crate) fn prepare(rec: &Record) -> Option<Prepared> {
    let source = sanitize(&rec.source, 96);
    let skey = sanitize(&rec.key, VALUE_MAX);
    if source.is_empty() || skey.is_empty() {
        return None;
    }
    let mut cut = 0usize;
    let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
    for (k, v) in &rec.attrs {
        let name = sanitize(k, 48);
        if name.is_empty() {
            continue;
        }
        if attrs.len() >= MAX_ATTRS {
            cut = cut.saturating_add(1);
            continue;
        }
        if let Some(c) = clean(v) {
            attrs.insert(name, c);
        }
    }
    let kind = rec.kind;
    let mac = (kind == RecKind::Device)
        .then(|| text_attr(&attrs, "mac").and_then(norm_mac))
        .flatten();
    let serial = (kind == RecKind::Device)
        .then(|| text_attr(&attrs, "serial").and_then(norm_serial))
        .flatten();
    // A device key is already scoped by its adapter (`<scope>|<id>`), and a natural key (a
    // network, a node, a service, an upstream) is prefixed with its type.
    let devkey = match kind {
        RecKind::Device => text_attr(&attrs, "device_key")
            .map(|s| sanitize(s, VALUE_MAX))
            .filter(|s| !s.is_empty()),
        RecKind::Port => None,
        _ => Some(sanitize(text_attr(&attrs, "key")?, VALUE_MAX)).filter(|s| !s.is_empty()),
    };
    if !matches!(kind, RecKind::Device | RecKind::Port) && devkey.is_none() {
        return None;
    }
    let host = (kind == RecKind::Device)
        .then(|| text_attr(&attrs, "hostname").and_then(norm_host))
        .flatten();
    let net = text_attr(&attrs, "network").and_then(norm_net);
    let (owner, port) = if kind == RecKind::Port {
        (
            text_attr(&attrs, "owner")
                .map(|s| sanitize(s, VALUE_MAX))
                .filter(|s| !s.is_empty()),
            text_attr(&attrs, "port_id").and_then(norm_port),
        )
    } else {
        (None, None)
    };
    if kind == RecKind::Port && (owner.is_none() || port.is_none()) {
        return None;
    }
    let class = class_of(&source);
    let addrs: Vec<(String, u8)> = match attrs.get("addresses") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
            .map(|ip| (ip.to_string(), class))
            .collect(),
        _ => Vec::new(),
    };
    let body = serde_json::to_string(&attrs).ok()?;
    let mut h = blake3::Hasher::new();
    h.update(kind.as_str().as_bytes());
    h.update(&[0x1f]);
    h.update(body.as_bytes());
    let hash = first8(h.finalize().as_bytes());
    Some(Prepared {
        key_hash: key_hash(&source, &skey),
        write: RecordWrite {
            source,
            skey,
            ty: kind.as_str().to_owned(),
            attrs: body,
            hash,
            seen: rec.seen,
            mac,
            serial,
            devkey,
            host,
            net,
            owner,
            port,
            addrs,
        },
        cut,
    })
}

/// The scope of a device key: the part before the last `|` (`unifi:home|abc` is `unifi:home`).
pub(crate) fn devkey_scope(key: &str) -> &str {
    key.rsplit_once('|').map_or(key, |(s, _)| s)
}

/// Whether a text is a CI id (`ci_` and 32 hex digits).
pub(crate) fn is_ci_id(s: &str) -> bool {
    s.strip_prefix("ci_")
        .is_some_and(|h| h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A new CI id: random 128 bits, never derived from a MAC (ADR-1004 section 2).
pub(crate) fn new_ci_id() -> String {
    let n: u128 = rand::random();
    ci_text(n)
}

/// A CI id as a number, for the in-memory index.
pub(crate) fn ci_num(id: &str) -> Option<u128> {
    u128::from_str_radix(id.strip_prefix("ci_")?, 16).ok()
}

/// A number as a CI id.
pub(crate) fn ci_text(n: u128) -> String {
    format!("ci_{n:032x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-902 - MACs in any common spelling are one key, and the null MAC is none.
    #[test]
    fn dsc_902_mac_spellings_are_one_key() {
        for s in ["AA:BB:CC:DD:EE:01", "aa-bb-cc-dd-ee-01", " aa:bb:cc:dd:ee:01 "] {
            assert_eq!(norm_mac(s).as_deref(), Some("aa:bb:cc:dd:ee:01"), "{s}");
        }
        assert_eq!(norm_mac("00:00:00:00:00:00"), None);
        assert_eq!(norm_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(norm_mac("zigbee-1234"), None);
        assert!(mac_is_randomized("da:a1:19:00:00:01"));
        assert!(!mac_is_randomized("a8:03:2a:00:00:01"));
    }

    /// REQ: DSC-902 - serials, host names and ports normalise as the design's table says.
    #[test]
    fn dsc_902_serials_hosts_and_ports_normalise() {
        assert_eq!(norm_serial(" ABC-1234 ").as_deref(), Some("abc-1234"));
        assert_eq!(norm_serial("None"), None);
        assert_eq!(norm_serial("000000"), None);
        assert_eq!(norm_serial("ab"), None);
        assert_eq!(norm_host("Kitchen-Hub.lan").as_deref(), Some("kitchen-hub"));
        assert_eq!(norm_host("iPhone"), None, "a generic name is no key");
        assert_eq!(norm_host("12345"), None);
        assert_eq!(norm_port("Gi1/0/5").as_deref(), Some("gi1/0/5"));
        assert_eq!(norm_port("Port 5").as_deref(), Some("port5"));
        assert_eq!(trailing_number("gi1/0/5"), Some(5));
        assert_eq!(trailing_number("port12"), Some(12));
        assert_eq!(trailing_number("lo"), None);
    }

    /// REQ: DSC-902, DSC-015 - values are cut to 255 bytes with control characters removed, a
    /// record keeps at most 24 attributes, and the same content hashes the same whatever the time.
    #[test]
    fn dsc_902_records_are_bounded_and_hash_by_content() {
        let mut r = Record::new("unifi:home", "abc", RecKind::Device, 100);
        r.text("A_name", format!("x{}y{}", '\u{7}', "y".repeat(400)));
        for i in 0..40 {
            r.text(&format!("a{i:02}"), "v");
        }
        let p = prepare(&r).unwrap();
        let attrs: serde_json::Value = serde_json::from_str(&p.write.attrs).unwrap();
        assert_eq!(attrs.as_object().unwrap().len(), MAX_ATTRS);
        assert!(p.cut >= 17);
        let name = attrs["A_name"].as_str().unwrap();
        assert!(name.len() <= VALUE_MAX && !name.contains('\u{7}'));
        let mut later = r.clone();
        later.seen = 999_999;
        assert_eq!(prepare(&later).unwrap().write.hash, p.write.hash);
        later.text("a00", "changed");
        assert_ne!(prepare(&later).unwrap().write.hash, p.write.hash);
    }

    /// REQ: DSC-902 - a record with no source or key is refused, a port needs its owner, a
    /// network needs its natural key; ids are random and never derived from a MAC.
    #[test]
    fn dsc_902_malformed_records_are_refused_and_ids_are_random() {
        assert!(prepare(&Record::new("", "k", RecKind::Device, 1)).is_none());
        assert!(prepare(&Record::new("neighbor", "", RecKind::Device, 1)).is_none());
        assert!(prepare(&Record::new("snmp:a", "p1", RecKind::Port, 1)).is_none());
        assert!(prepare(&Record::new("config", "n", RecKind::Network, 1)).is_none());
        let a = new_ci_id();
        let b = new_ci_id();
        assert_ne!(a, b);
        assert!(is_ci_id(&a) && ci_num(&a).map(ci_text).as_deref() == Some(a.as_str()));
    }
}
