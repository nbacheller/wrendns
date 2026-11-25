//! Semantic validation beyond what serde enforces. Collects *every* problem, each with its path.

use std::collections::HashSet;

use crate::ConfigError;
use crate::schema::{CONFIG_VERSION, Config, HttpVersion, Strategy};

/// URL schemes accepted for upstreams (`spec/04` §2).
pub const UPSTREAM_SCHEMES: &[&str] = &[
    "udp",
    "tcp",
    "tls",
    "https",
    "h3",
    "quic",
    "sdns",
    "recursive",
    "unix",
    "exec",
];

/// Accumulates errors and warnings during validation.
struct Report<'a> {
    errors: &'a mut Vec<ConfigError>,
    warnings: Vec<String>,
}

impl Report<'_> {
    fn err(&mut self, path: impl Into<String>, msg: impl std::fmt::Display) {
        self.errors.push(ConfigError::new(path, msg));
    }
    fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

/// Returns warnings; pushes errors.
pub(crate) fn validate(cfg: &Config, errors: &mut Vec<ConfigError>) -> Vec<String> {
    let mut r = Report {
        errors,
        warnings: Vec::new(),
    };
    node(cfg, &mut r);
    listeners(cfg, &mut r);
    let upstreams = upstreams(cfg, &mut r);
    let groups = groups(cfg, &upstreams, &mut r);
    routes(cfg, &groups, &mut r);
    lists(cfg, &mut r);
    clients(cfg, &mut r);
    router_names(cfg, &mut r);
    rules(cfg, &mut r);
    services(cfg, &mut r);
    categories(cfg, &mut r);
    schedules(cfg, &mut r);
    anomaly_mutes(cfg, &mut r);
    watchdog(cfg, &mut r);
    alerts(cfg, &mut r);
    slo(cfg, &mut r);
    probes(cfg, &mut r);
    // REQ: OPS-010 (T13.4) — a minute to a day, like the API's bounds.
    if !(60..=86_400).contains(&cfg.node.maintenance_default_secs) {
        r.err(
            "node.maintenance_default_secs",
            "from 60 to 86400 seconds (a minute to a day)",
        );
    }
    upstream_check(cfg, &mut r);
    sinks(cfg, &mut r);
    routers(cfg, &mut r);
    device_names(cfg, &mut r);
    special_names(cfg, &mut r);
    rewrites(cfg, &mut r);
    zones(cfg, &mut r);
    otlp(cfg, &mut r);
    exclusions(cfg, &mut r);
    simulate(cfg, &mut r);
    map(cfg, &mut r);
    identify(cfg, &mut r);
    kubernetes(cfg, &mut r);
    drill(cfg, &mut r);
    rollout(cfg, &mut r);
    cache_and_telemetry(cfg, &mut r);
    dnssec(cfg, &mut r);
    auth(cfg, &mut r);
    cluster(cfg, &mut r);
    secret_references(cfg, &mut r);
    discovery(cfg, &mut r);
    cmdb(cfg, &mut r);
    r.warnings
}

// REQ: UPS-011 (T7.16) — TLS settings only for TLS upstreams; both halves of a client
// certificate; pins that look like base64 SHA-256.
/// REQ: API-016 (review of T23.7, ADR-921) — whether `pem` holds at least one PEM certificate
/// that decodes: the BEGIN marker alone isn't one (a body that isn't base64 fails at poll time).
fn valid_pem_certificate(pem: &str) -> bool {
    use rustls_pki_types::pem::PemObject;
    let mut any = false;
    for c in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
        if c.is_err() {
            return false;
        }
        any = true;
    }
    any
}

fn upstream_tls(u: &crate::schema::Upstream, s: &str, p: &str, r: &mut Report<'_>) {
    let tls = matches!(s, "tls" | "https" | "h3" | "quic");
    for (set, what) in [
        (!u.spki_pins.is_empty(), "spki_pins"),
        (u.tls_ca.is_some(), "tls_ca"),
        (u.tls_client_cert.is_some(), "tls_client_cert"),
    ] {
        if set && !tls {
            r.err(
                format!("{p}.{what}"),
                "only for TLS upstreams (tls://, https://, h3://, quic://)",
            );
        }
    }
    if u.tls_client_cert.is_some() != u.tls_client_key.is_some() {
        r.err(
            format!("{p}.tls_client_key"),
            "set both tls_client_cert and tls_client_key",
        );
    }
    for (j, pin) in u.spki_pins.iter().enumerate() {
        let ok = pin.len() == 44
            && pin.ends_with('=')
            && pin[..43]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
        if !ok {
            r.err(
                format!("{p}.spki_pins[{j}]"),
                "a base64 SHA-256 (44 characters, ending in =)",
            );
        }
    }
}

// REQ: OBS-010 (T7.13) — event sinks: unique names and what each kind needs.
// REQ: DNS-018 (T7.22) — zones: a valid, unique apex; known groups; records under it.
fn zones(cfg: &Config, r: &mut Report<'_>) {
    let mut apexes = HashSet::new();
    let lower = |s: &str| s.trim_end_matches('.').to_ascii_lowercase();
    for (i, z) in cfg.zone.iter().enumerate() {
        let apex = lower(&z.name);
        if apex.is_empty() || apex.split('.').any(str::is_empty) {
            r.err(format!("zone[{i}].name"), "a domain, e.g. home.example.com");
        }
        let key = (apex.clone(), {
            let mut g: Vec<String> = z
                .groups
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            g.sort();
            g
        });
        if !apexes.insert(key) {
            r.err(
                format!("zone[{i}].name"),
                "the same zone twice for the same groups",
            );
        }
        if z.file.is_none() && z.record.is_empty() {
            r.err(format!("zone[{i}]"), "give a file or records");
        }
        for (j, g) in z.groups.iter().enumerate() {
            if g.as_str() != "default" && !cfg.group.iter().any(|x| x.name == *g) {
                r.err(
                    format!("zone[{i}].groups[{j}]"),
                    format!("no group `{}`", g.as_str()),
                );
            }
        }
        for (j, rec) in z.record.iter().enumerate() {
            let n = lower(rec.name.trim_start_matches("*."));
            if n != apex && !n.ends_with(&format!(".{apex}")) {
                r.err(
                    format!("zone[{i}].record[{j}].name"),
                    format!("not under {apex}"),
                );
            }
        }
    }
}

// REQ: FLT-014, FLT-015 (T7.20) — rewrites and rebinding exceptions are names; a rewrite's
// answer is an address or a name.
fn rewrites(cfg: &Config, r: &mut Report<'_>) {
    let name_ok = |s: &str| {
        let s = s.trim_end_matches('.');
        !s.is_empty()
            && s.len() <= 253
            && s.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
    };
    for (i, g) in cfg.group.iter().enumerate() {
        for (j, a) in g.rebinding_allow.iter().enumerate() {
            if !name_ok(a) {
                r.err(
                    format!("group[{i}].rebinding_allow[{j}]"),
                    "a domain, e.g. plex.direct",
                );
            }
        }
        // REQ: DNS-016 (T7.21)
        // REQ: DNS-016 (T9.10)
        if !g.dns64 && !g.dns64_exclude.is_empty() {
            r.err(
                format!("group[{i}].dns64_exclude"),
                "only with `dns64 = true`",
            );
        }
        // REQ: FLT-016 (T12.5) — DNS64 makes up AAAA answers; filtering them contradicts it.
        if g.dns64 && g.filter_aaaa {
            r.err(
                format!("group[{i}].filter_aaaa"),
                "not with `dns64 = true` (DNS64 makes AAAA answers; this removes them)",
            );
        }
        if let Some(p) = g.dns64_prefix
            && (!p.addr.is_ipv6() || p.prefix != 96)
        {
            r.err(
                format!("group[{i}].dns64_prefix"),
                "an IPv6 /96, e.g. 64:ff9b::/96",
            );
        }
        let mut seen = HashSet::new();
        for (j, w) in g.rewrite.iter().enumerate() {
            let d = w.domain.trim_start_matches("*.");
            if !name_ok(d) {
                r.err(
                    format!("group[{i}].rewrite[{j}].domain"),
                    "a domain, or *.domain for every name under it",
                );
            } else if !seen.insert(w.domain.to_ascii_lowercase()) {
                r.err(
                    format!("group[{i}].rewrite[{j}].domain"),
                    "rewritten twice in this group",
                );
            }
            if w.answer.parse::<std::net::IpAddr>().is_err() && !name_ok(&w.answer) {
                r.err(
                    format!("group[{i}].rewrite[{j}].answer"),
                    "an IP address or a domain",
                );
            }
        }
    }
}

// REQ: DNS-023 (T22.1) — device names in DNS: a domain name of at least one label, not mDNS's
// own `local`, and a TTL a DHCP change can outlive.
fn device_names(cfg: &Config, r: &mut Report<'_>) {
    let l = &cfg.local;
    if let Some(d) = &l.device_domain {
        let d = d.trim_end_matches('.');
        if !host_name_ok(d, 200) {
            r.err(
                "local.device_domain",
                "a domain name, e.g. home.arpa (RFC 8375) or lan",
            );
        } else if d.eq_ignore_ascii_case("local") {
            r.err(
                "local.device_domain",
                "`local` belongs to mDNS (RFC 6762); use home.arpa",
            );
        }
    }
    if !(1..=86_400).contains(&l.device_ttl) {
        r.err("local.device_ttl", "1 to 86400 seconds");
    }
    if l.device_mdns && !cfg.clients.mdns {
        r.warn("local.device_mdns: no effect without [clients] mdns = true");
    }
}

/// Letters, digits, and hyphens in labels of 1 to 63 bytes, at most `max` bytes in all.
fn host_name_ok(d: &str, max: usize) -> bool {
    !d.is_empty()
        && d.len() <= max
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

// REQ: DNS-019 (ADR-904) — DDR's target is the host name the encrypted listeners' certificates
// carry; without such a listener on this node there is nothing to advertise.
fn special_names(cfg: &Config, r: &mut Report<'_>) {
    let Some(name) = &cfg.special.ddr_name else {
        return;
    };
    let name = name.trim_end_matches('.');
    if !host_name_ok(name, 253) || !name.contains('.') {
        r.err(
            "special.ddr_name",
            "the host name in the encrypted listeners' certificates, e.g. dns.example.com",
        );
    } else if !cfg.listen.iter().any(|l| l.proto.needs_tls()) {
        r.warn(
            "special.ddr_name: this node has no dot, doh, doh3, or doq listener to advertise; _dns.resolver.arpa gets no data",
        );
    }
}

// REQ: API-016 (T23.7, ADR-921) — the certificate as text: one source of trust, at most
// 16 KiB, and a PEM certificate.
fn router_pem(p: &str, x: &crate::schema::RouterConfig, r: &mut Report<'_>) {
    if let Some(pem) = &x.tls_ca_pem {
        if x.tls_ca.is_some() {
            r.err(
                format!("{p}.tls_ca_pem"),
                "exclusive with tls_ca: give the certificate one way",
            );
        }
        if pem.len() > 16 * 1024 {
            r.err(format!("{p}.tls_ca_pem"), "at most 16 KiB");
        } else if !valid_pem_certificate(pem) {
            r.err(
                format!("{p}.tls_ca_pem"),
                "a PEM certificate (the text between -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----)",
            );
        }
        if x.tls_insecure_skip_verify {
            r.err(
                format!("{p}.tls_ca_pem"),
                "has no effect with tls_insecure_skip_verify (the certificate isn't checked)",
            );
        }
    }
}

// REQ: T8.2 — router integrations: unique names, http(s) URLs, the credentials each kind needs.
fn routers(cfg: &Config, r: &mut Report<'_>) {
    let mut names = HashSet::new();
    for (i, x) in cfg.router.iter().enumerate() {
        let p = format!("router[{i}]");
        if x.name.is_empty() || !names.insert(x.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        if !(x.url.starts_with("https://") || x.url.starts_with("http://")) {
            r.err(
                format!("{p}.url"),
                "an https:// URL, e.g. https://192.168.1.1",
            );
        }
        // REQ: OPS-014 (ADR-903 §2) — each credential from a file or a stored secret.
        let key = x.api_key_file.is_some() || x.api_key_ref.is_some();
        let api_secret = x.api_secret_file.is_some() || x.api_secret_ref.is_some();
        let password = x.password_file.is_some() || x.password_ref.is_some();
        match x.kind {
            crate::RouterKind::Unifi => {
                if !key && (x.username.is_none() || !password) {
                    r.err(
                        p.clone(),
                        "UniFi needs api_key_file (or api_key_ref), or username and password_file (or password_ref)",
                    );
                }
            }
            crate::RouterKind::Opnsense => {
                if !key || !api_secret {
                    r.err(
                        p.clone(),
                        "OPNsense needs api_key_file and api_secret_file (or their _ref)",
                    );
                }
            }
            // REQ: API-012 (T22.3) — a long-lived access token, and nothing UniFi- or
            // OPNsense-only.
            crate::RouterKind::HomeAssistant => {
                if !key {
                    r.err(
                        p.clone(),
                        "Home Assistant needs api_key_file (a file holding a long-lived access token) or api_key_ref",
                    );
                }
                if x.username.is_some() || password || api_secret || x.site.is_some() {
                    r.err(
                        p.clone(),
                        "Home Assistant takes api_key_file or api_key_ref only (not username, a password, an API secret, or site)",
                    );
                }
            }
        }
        if x.interval_secs < 30 {
            r.err(format!("{p}.interval_secs"), "at least 30 seconds");
        }
        router_pem(&p, x, r);
        if x.offline_days > 365 {
            r.err(
                format!("{p}.offline_days"),
                "at most 365 days (0: only the connected clients)",
            );
        }
        if x.tls_insecure_skip_verify {
            r.warn(format!("{p}.tls_insecure_skip_verify: the router's certificate isn't checked (prefer tls_ca, with tls_server_name if the certificate doesn't name the address)"));
        }
        if let Some(n) = &x.tls_server_name {
            let host_name = !n.is_empty()
                && n.len() <= 253
                && n.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                });
            if !host_name {
                r.err(
                    format!("{p}.tls_server_name"),
                    "a host name, e.g. unifi.local",
                );
            } else if !x.url.starts_with("https://") {
                r.err(format!("{p}.tls_server_name"), "only for an https:// url");
            } else if x.tls_insecure_skip_verify {
                r.err(
                    format!("{p}.tls_server_name"),
                    "has no effect with tls_insecure_skip_verify (the certificate isn't checked)",
                );
            }
        }
    }
}

/// A domain name for a suffix list (a leading `*.` and a trailing dot are allowed).
fn suffix_name_ok(n: &str) -> bool {
    let bare = n.trim().trim_start_matches("*.").trim_end_matches('.');
    !bare.is_empty()
        && bare.len() <= 253
        && bare.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

// REQ: OBS-022 (T12.1) — excluded names are domain names (a leading `*.` is allowed); at most
// 1,000 of each, so the per-event check stays cheap.
fn exclusions(cfg: &Config, r: &mut Report<'_>) {
    let x = &cfg.exclusions;
    for (i, n) in x.names.iter().enumerate() {
        if !suffix_name_ok(n) {
            r.err(
                format!("exclusions.names[{i}]"),
                format!("`{n}` isn't a domain name (e.g. connectivitycheck.gstatic.com)"),
            );
        }
    }
    for (what, n) in [("names", x.names.len()), ("clients", x.clients.len())] {
        if n > 1000 {
            r.err(format!("exclusions.{what}"), "at most 1,000");
        }
    }
    // REQ: OBS-903 (T24.35, ADR-1014) — what stays out of the query log only: domains (exact, or
    // `*.` for everything under), clients as an address, a network, or a device name.
    for (i, d) in x.log.domains.iter().enumerate() {
        if !suffix_name_ok(d) {
            r.err(
                format!("exclusions.log.domains[{i}]"),
                format!("`{d}` isn't a domain name (e.g. localhost or *.lan)"),
            );
        }
    }
    for (i, c) in x.log.clients.iter().enumerate() {
        let c = c.trim();
        let looks_numeric = c.contains('/') || c.parse::<std::net::IpAddr>().is_ok();
        if (looks_numeric && crate::Cidr::parse(c).is_err())
            || c.is_empty()
            || c.len() > 128
            || c.chars().any(char::is_control)
        {
            r.err(
                format!("exclusions.log.clients[{i}]"),
                format!("`{c}` isn't an address, a network, or a device name"),
            );
        }
    }
    for (what, n) in [
        ("domains", x.log.domains.len()),
        ("clients", x.log.clients.len()),
    ] {
        if n > 1000 {
            r.err(format!("exclusions.log.{what}"), "at most 1,000");
        }
    }
    // REQ: OBS-037 — internal names are domain names too, at most 100.
    let names = &cfg.telemetry.internal_names;
    for (i, n) in names.iter().enumerate() {
        if !suffix_name_ok(n) {
            r.err(
                format!("telemetry.internal_names[{i}]"),
                format!("`{n}` isn't a domain name (e.g. lan or home.arpa)"),
            );
        }
    }
    if names.len() > 100 {
        r.err("telemetry.internal_names", "at most 100");
    }
}

// REQ: OBS-024 (T13.1) — bounds a Pi and a pod can both keep; a window of at most 7 days.
fn simulate(cfg: &Config, r: &mut Report<'_>) {
    let s = &cfg.simulate;
    if !(1..=300).contains(&s.max_secs) {
        r.err("simulate.max_secs", "from 1 to 300 seconds");
    }
    if s.max_rows < 1000 {
        r.err("simulate.max_rows", "at least 1000");
    }
    match crate::schema::window_secs(&s.default_window) {
        Some(w) if w <= 7 * 86_400 => {}
        Some(_) => r.err("simulate.default_window", "at most 7 days (7d)"),
        None => r.err(
            "simulate.default_window",
            format!(
                "`{}`: a number and m, h, or d (e.g. 24h)",
                &*s.default_window
            ),
        ),
    }
}

// REQ: CLU-013 (T13.2) — rollout bounds, and canaries that can name a node.
fn rollout(cfg: &Config, r: &mut Report<'_>) {
    let o = &cfg.cluster.rollout;
    if o.bake_secs < 5 {
        r.err("cluster.rollout.bake_secs", "at least 5 seconds");
    }
    if o.max_bake_secs < o.bake_secs {
        r.err("cluster.rollout.max_bake_secs", "at least bake_secs");
    }
    if !(0.0..=100.0).contains(&o.servfail_pct) {
        r.err("cluster.rollout.servfail_pct", "a percentage, 0 to 100");
    }
    if !(1..=200).contains(&o.history) {
        r.err("cluster.rollout.history", "from 1 to 200 versions");
    }
    for (i, c) in o.canaries.iter().enumerate() {
        let c = c.as_str().trim();
        let ok = c == "ephemeral"
            || c.strip_prefix("site:")
                .is_some_and(|s| !s.trim().is_empty())
            || (!c.is_empty() && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        if !ok {
            r.err(
                format!("cluster.rollout.canaries[{i}]"),
                format!("`{c}`: a node ID, `site:<name>`, or `ephemeral`"),
            );
        }
    }
}

// REQ: FLT-017 (T15.1) — map rules name groups that exist and kinds WrenDNS knows; the
// default group exists; namespace names are plain. A label value naming a missing group is
// only logged at runtime (the cluster's labels aren't configuration).
// REQ: CLU-014 — a scheduled drill names its nodes, a length of 15 to 300 s, an hour, a known
// zone and group, and not both a group and devices.
fn drill(cfg: &Config, r: &mut Report<'_>) {
    let d = &cfg.drill;
    if !(15..=300).contains(&d.for_secs) {
        r.err(
            "drill.for_secs",
            "15 to 300 seconds: longer, a drill is an outage",
        );
    }
    if d.hour > 23 {
        r.err("drill.hour", "an hour of the day, 0 to 23");
    }
    if let Some(tz) = &d.tz
        && let Err(e) = crate::schedule::time_zone(Some(tz.as_str()))
    {
        r.err("drill.tz", e);
    }
    if let Some(g) = &d.group {
        let known = g.as_str() == "default" || cfg.group.iter().any(|x| x.name == *g);
        if !known {
            r.err("drill.group", format!("unknown group `{g}`"));
        }
        if !d.clients.is_empty() {
            r.err("drill.clients", "set `group` or `clients`, not both");
        }
    }
    if d.schedule == crate::schema::DrillSchedule::Monthly && d.nodes.is_empty() {
        r.err(
            "drill.nodes",
            "name the nodes that drill themselves (sites, pod names, or node IDs)",
        );
    }
}

fn kubernetes(cfg: &Config, r: &mut Report<'_>) {
    let k = &cfg.kubernetes;
    let groups: HashSet<&str> = cfg
        .group
        .iter()
        .map(|g| g.name.as_str())
        .chain(["default"])
        .collect();
    if !k.default_group.is_empty() && !groups.contains(k.default_group.as_str()) {
        r.err(
            "kubernetes.default_group",
            format!("unknown group `{}`", k.default_group),
        );
    }
    if k.label.is_empty() || k.label.contains(char::is_whitespace) {
        r.err("kubernetes.label", "a label key such as wrendns.com/group");
    }
    let plain = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'*'))
    };
    for (key, list) in [
        ("namespaces", &k.namespaces),
        ("exclude_namespaces", &k.exclude_namespaces),
    ] {
        for (i, n) in list.iter().enumerate() {
            if !plain(n) || n.contains('*') {
                r.err(
                    format!("kubernetes.{key}[{i}]"),
                    "a namespace name (lowercase letters, digits, and dashes)",
                );
            }
        }
    }
    let mut keys = HashSet::new();
    for (i, m) in k.map.iter().enumerate() {
        let p = format!("kubernetes.map[{i}]");
        if !plain(&m.namespace) {
            r.err(
                format!("{p}.namespace"),
                "a namespace or a glob such as `media*` or `*`",
            );
        }
        if !m.kind.is_empty() && !crate::schema::WORKLOAD_KINDS.contains(&m.kind.as_str()) {
            r.err(
                format!("{p}.kind"),
                format!(
                    "one of {} (or leave it out for any)",
                    crate::schema::WORKLOAD_KINDS.join(", ")
                ),
            );
        }
        if !m.name.is_empty() && !plain(&m.name) {
            r.err(format!("{p}.name"), "a workload name (no `/` or spaces)");
        }
        if !groups.contains(m.group.as_str()) {
            r.err(format!("{p}.group"), format!("unknown group `{}`", m.group));
        }
        if !keys.insert(m.key()) {
            r.err(p, format!("a second rule for `{}`", m.key()));
        }
    }
}

// REQ: OBS-025 (T13.3) — a device kind belongs to one group at most; bounded device counts.
fn identify(cfg: &Config, r: &mut Report<'_>) {
    if !(1..=65_536).contains(&cfg.identify.max_clients) {
        r.err("identify.max_clients", "from 1 to 65536");
    }
    let mut owner: std::collections::BTreeMap<crate::DeviceClass, &str> =
        std::collections::BTreeMap::new();
    for (i, g) in cfg.group.iter().enumerate() {
        for c in &g.device_classes {
            if *c == crate::DeviceClass::Unknown {
                r.err(
                    format!("group[{i}].device_classes"),
                    "`unknown` can't be suggested for a group",
                );
            } else if let Some(other) = owner.insert(*c, g.name.as_str())
                && other != g.name.as_str()
            {
                r.err(
                    format!("group[{i}].device_classes"),
                    format!(
                        "`{}` is claimed by group `{other}` too: a kind of device can belong to one group",
                        c.as_str()
                    ),
                );
            }
        }
    }
}

// REQ: OBS-006 (T7.17) — OTLP: an http(s) endpoint, a sane interval.
fn otlp(cfg: &Config, r: &mut Report<'_>) {
    otlp_one(&cfg.telemetry.otlp, r);
    // REQ: OBS-007 (T7.18)
    let d = &cfg.telemetry.dnstap;
    if d.socket.is_some() && d.address.is_some() {
        r.err("telemetry.dnstap", "set socket or address, not both");
    }
    if let Some(a) = &d.address {
        let hp = a.strip_prefix("tcp://").unwrap_or(a);
        if !hp
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok())
        {
            r.err("telemetry.dnstap.address", "use tcp://host:port");
        }
    }
    if d.sample_every == 0 {
        r.err("telemetry.dnstap.sample_every", "at least 1 (every query)");
    }
    if d.buffer < 100 {
        r.err("telemetry.dnstap.buffer", "at least 100");
    }
}

/// The OTLP export's own rules (the endpoint, the interval, the trace settings).
fn otlp_one(o: &crate::OtlpConfig, r: &mut Report<'_>) {
    if let Some(e) = &o.endpoint
        && !(e.starts_with("http://") || e.starts_with("https://"))
    {
        r.err(
            "telemetry.otlp.endpoint",
            "an http:// or https:// URL, e.g. http://otel-collector:4318",
        );
    }
    if o.interval_secs < 5 {
        r.err("telemetry.otlp.interval_secs", "at least 5 seconds");
    }
    // REQ: OBS-017 (T11.6) — traces go to the same collector.
    if o.endpoint.is_none() {
        for (field, on) in [
            ("traces_sample_every", o.traces_sample_every > 0),
            ("traces_slow_ms", o.traces_slow_ms > 0),
        ] {
            if on {
                r.err(
                    format!("telemetry.otlp.{field}"),
                    "traces are sent to the OTLP collector: set telemetry.otlp.endpoint too",
                );
            }
        }
    }
}

fn sinks(cfg: &Config, r: &mut Report<'_>) {
    let mut names = HashSet::new();
    for (i, s) in cfg.telemetry.sink.iter().enumerate() {
        let p = format!("telemetry.sink[{i}]");
        if s.name.is_empty() || !names.insert(s.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        sink_one(s, &p, r);
    }
}

/// One sink's own settings (everything but the uniqueness of its name).
fn sink_one(s: &crate::SinkConfig, p: &str, r: &mut Report<'_>) {
    use crate::SinkKind;
    const STATUSES: &[&str] = &[
        "cached",
        "forwarded",
        "stale",
        "refreshed",
        "local",
        "special",
        "blocked",
        "refused",
        "rate_limited",
        "malformed",
        "servfail",
        "dropped",
    ];
    match s.kind {
        SinkKind::File => {
            if s.path.as_ref().is_none_or(|x| x.is_empty()) {
                r.err(format!("{p}.path"), "a file sink needs `path`");
            }
            if s.max_bytes.bytes() < 1024 * 1024 {
                r.err(format!("{p}.max_bytes"), "at least 1 MiB");
            }
        }
        SinkKind::Syslog => {
            let a = s.address.as_ref().map_or("", |x| x.as_str());
            let ok = a
                .strip_prefix("udp://")
                .or_else(|| a.strip_prefix("tcp://"))
                .or_else(|| a.strip_prefix("tls://"))
                .is_some_and(|hp| {
                    hp.rsplit_once(':')
                        .is_some_and(|(h, port)| !h.is_empty() && port.parse::<u16>().is_ok())
                });
            if !ok {
                r.err(
                    format!("{p}.address"),
                    "use udp://host:port, tcp://host:port, or tls://host:port",
                );
            }
            // REQ: OBS-010 (T9.11)
            if s.tls_ca.is_some() && !a.starts_with("tls://") {
                r.err(format!("{p}.tls_ca"), "only for tls:// syslog addresses");
            }
            if s.facility > 23 {
                r.err(format!("{p}.facility"), "a syslog facility from 0 to 23");
            }
        }
        SinkKind::Webhook => {
            let u = s.url.as_ref().map_or("", |x| x.as_str());
            if !(u.starts_with("https://") || u.starts_with("http://")) {
                r.err(
                    format!("{p}.url"),
                    "a webhook sink needs an http:// or https:// `url`",
                );
            }
            if s.batch == 0 || s.batch > 10_000 {
                r.err(format!("{p}.batch"), "from 1 to 10000");
            }
            if s.flush_secs == 0 {
                r.err(format!("{p}.flush_secs"), "at least 1");
            }
            // REQ: OBS-010 (T9.11)
            if s.spill_max_bytes.is_some_and(|b| b.bytes() < 1024 * 1024) {
                r.err(format!("{p}.spill_max_bytes"), "at least 1 MiB");
            }
        }
    }
    if s.spill_max_bytes.is_some() && s.kind != SinkKind::Webhook {
        r.err(format!("{p}.spill_max_bytes"), "only for webhook sinks");
    }
    if s.format == crate::SinkFormat::OtlpLogs && s.kind != SinkKind::Webhook {
        r.err(format!("{p}.format"), "otlp_logs is for webhook sinks");
    }
    if s.max_buffer < 100 {
        r.err(format!("{p}.max_buffer"), "at least 100");
    }
    for (j, st) in s.statuses.iter().enumerate() {
        if !STATUSES.contains(&st.as_str()) {
            r.err(
                format!("{p}.statuses[{j}]"),
                format!(
                    "unknown status `{}` (one of {})",
                    st.as_str(),
                    STATUSES.join(", ")
                ),
            );
        }
    }
}

/// REQ: OBS-010 (T24.43, ADR-1045) — a `pushover` destination: an empty address is Pushover's
/// own, a self-hosted proxy is https (http only to this machine, for tests), both secrets are
/// set, and the priorities are within what is offered.
fn pushover_destination(d: &crate::schema::AlertDestination, p: &str, r: &mut Report<'_>) {
    let u = d.url.as_str();
    if !u.is_empty() && !pushover_url_ok(u) {
        r.err(
            format!("{p}.url"),
            "use an https:// URL (http:// only to 127.0.0.1, localhost or [::1])",
        );
    }
    let has = |f: &Option<crate::SafeString>, rf: &Option<crate::SafeString>| {
        f.as_ref().is_some_and(|x| !x.trim().is_empty())
            || rf.as_ref().is_some_and(|x| !x.trim().is_empty())
    };
    if !has(&d.token_file, &d.token_ref) {
        r.err(
            format!("{p}.token_ref"),
            "pushover needs the application token: token_file or token_ref",
        );
    }
    if !has(&d.user_key_file, &d.user_key_ref) {
        r.err(
            format!("{p}.user_key_ref"),
            "pushover needs the user or group key: user_key_file or user_key_ref",
        );
    }
    for (field, v) in [
        ("priority_firing", d.priority_firing),
        ("priority_resolved", d.priority_resolved),
    ] {
        if v.is_some_and(|v| !(-2..=1).contains(&v)) {
            r.err(
                format!("{p}.{field}"),
                "from -2 to 1 (2, emergency, is not offered)",
            );
        }
    }
}

/// REQ: OBS-010 (T24.43) — a Pushover address: https, or http to this machine.
fn pushover_url_ok(u: &str) -> bool {
    if u.starts_with("https://") {
        return true;
    }
    let Some(rest) = u.strip_prefix("http://") else {
        return false;
    };
    let auth = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // A username or password in the address hides the real host (`localhost:80@evil.example`).
    if auth.contains(['@', '\\']) {
        return false;
    }
    let (host, port) = match auth.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((h, r)) => (
                format!("[{h}]"),
                r.strip_prefix(':').or(r.is_empty().then_some("")),
            ),
            None => return false,
        },
        None => match auth.split_once(':') {
            Some((h, pt)) => (h.to_owned(), Some(pt)),
            None => (auth.to_owned(), Some("")),
        },
    };
    port.is_some_and(|pt| pt.bytes().all(|b| b.is_ascii_digit()))
        && ["127.0.0.1", "localhost", "[::1]"].contains(&host.as_str())
}

// REQ: OBS-010 (T7.12) — alerts: unique names, rules sent to destinations that exist,
// http(s) URLs, a sane interval and threshold.
fn alerts(cfg: &Config, r: &mut Report<'_>) {
    let a = &cfg.alerts;
    if a.interval_secs < 5 {
        r.err("alerts.interval_secs", "at least 5 seconds");
    }
    let mut names = HashSet::new();
    for (i, d) in a.destination.iter().enumerate() {
        let p = format!("alerts.destination[{i}]");
        if d.name.is_empty() || !names.insert(d.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        let u = d.url.as_str();
        if d.kind == crate::schema::AlertKind::Email {
            // REQ: OBS-010 (T9.4)
            if !(u.starts_with("smtp://")
                || u.starts_with("smtps://")
                || u.starts_with("smtp+insecure://"))
            {
                r.err(
                    format!("{p}.url"),
                    "use smtp://host:587 (STARTTLS), smtps://host:465 (TLS), or smtp+insecure://host:port (a local catcher)",
                );
            }
            if d.from.as_ref().is_none_or(|f| !f.as_str().contains('@')) {
                r.err(format!("{p}.from"), "the sender's email address");
            }
            if d.to.is_empty() || d.to.iter().any(|t| !t.as_str().contains('@')) {
                r.err(format!("{p}.to"), "one or more email addresses");
            }
            // REQ: OPS-014 (ADR-903 §2) — the password from a file or a stored secret.
            if d.username.is_some() != (d.password_file.is_some() || d.password_ref.is_some()) {
                r.err(
                    format!("{p}.password_file"),
                    "username and password_file (or password_ref) go together",
                );
            }
            if d.username.is_some() && u.starts_with("smtp+insecure://") {
                r.err(
                    format!("{p}.url"),
                    "a password is never sent unencrypted: use smtp:// or smtps://",
                );
            }
        } else if d.kind == crate::schema::AlertKind::Pushover {
            pushover_destination(d, &p, r);
        } else if !(u.starts_with("https://") || u.starts_with("http://")) {
            r.err(format!("{p}.url"), "use an http:// or https:// URL");
        }
    }
    let mut rules = HashSet::new();
    for (i, x) in a.rule.iter().enumerate() {
        let p = format!("alerts.rule[{i}]");
        if x.name.is_empty() || !rules.insert(x.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        if x.to.is_empty() {
            r.err(format!("{p}.to"), "name at least one destination");
        }
        for (j, t) in x.to.iter().enumerate() {
            if !a.destination.iter().any(|d| d.name == *t) {
                r.err(
                    format!("{p}.to[{j}]"),
                    format!("no destination `{}`", t.as_str()),
                );
            }
        }
        if x.when == crate::schema::AlertWhen::CertExpiring {
            // REQ: OBS-020 (T11.3) — days, not a percentage.
            if let Some(t) = x.threshold
                && !(1.0..=365.0).contains(&t)
            {
                r.err(format!("{p}.threshold"), "days from 1 to 365");
            }
        } else if x.when == crate::schema::AlertWhen::PrimaryUnreachable {
            // REQ: OBS-010 (T24.5, fork #2) — seconds without reaching the primary.
            if let Some(t) = x.threshold
                && !(15.0..=86_400.0).contains(&t)
            {
                r.err(format!("{p}.threshold"), "seconds from 15 to 86400");
            }
        } else if let Some(t) = x.threshold
            && !(0.0..=100.0).contains(&t)
        {
            r.err(format!("{p}.threshold"), "a percentage from 0 to 100");
        }
    }
}

/// REQ: OBS-020 (T11.3) — a probe target's address: `scheme://IP:port[/path]` with a scheme a
/// probe speaks (the path for `https://` and `h3://` only). `Err` says what's wrong.
pub fn probe_target(t: &str) -> Result<(&str, std::net::SocketAddr, Option<&str>), &'static str> {
    let (scheme, rest) = t
        .split_once("://")
        .ok_or("use scheme://IP:port, e.g. udp://10.50.5.112:53")?;
    if !matches!(scheme, "udp" | "tcp" | "tls" | "https" | "h3" | "quic") {
        return Err("the scheme is udp, tcp, tls, https, h3, or quic");
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    if path.is_some() && !matches!(scheme, "https" | "h3") {
        return Err("only https:// and h3:// targets take a path");
    }
    let addr = authority
        .parse::<std::net::SocketAddr>()
        .map_err(|_| "an IP address and port, e.g. 10.50.5.112:53 or [fd00::53]:53")?;
    Ok((scheme, addr, path))
}

// REQ: OBS-019 (T11.4) — second opinions: a reference group that exists, a bounded history,
// and a warning when the sample is large enough to add noticeable upstream traffic.
fn upstream_check(cfg: &Config, r: &mut Report<'_>) {
    let c = &cfg.upstream_check;
    if let Some(g) = &c.reference {
        match cfg.upstream_group.iter().find(|x| x.name == *g) {
            None => r.err(
                "upstream_check.reference",
                format!("no upstream group `{}`", g.as_str()),
            ),
            // REQ: CLU-006 — the setting is shared; a node-only group is on one node only.
            Some(x) if x.node_only => r.err(
                "upstream_check.reference",
                format!(
                    "upstream group `{}` is node_only; pick a shared group",
                    g.as_str()
                ),
            ),
            Some(_) => {}
        }
    }
    if !(1..=1000).contains(&c.keep) {
        r.err("upstream_check.keep", "from 1 to 1000");
    }
    if (1..100).contains(&c.sample_every) {
        r.warn(format!(
            "upstream_check.sample_every = {}: one forwarded question in {} is asked twice (more upstream traffic, and the second upstream sees those names)",
            c.sample_every, c.sample_every
        ));
    }
}

// REQ: OBS-020 (T11.3) — probes: a sane schedule and timeout, targets by IP.
fn probes(cfg: &Config, r: &mut Report<'_>) {
    let p = &cfg.probe;
    if p.interval_secs < 5 {
        r.err("probe.interval_secs", "at least 5 seconds");
    }
    if !(100..=10_000).contains(&p.timeout_ms) {
        r.err("probe.timeout_ms", "from 100 to 10000 milliseconds");
    }
    if p.timeout_ms / 1000 >= p.interval_secs {
        r.err("probe.timeout_ms", "shorter than interval_secs");
    }
    for (i, t) in p.targets.iter().enumerate() {
        if let Err(why) = probe_target(t) {
            r.err(format!("probe.targets[{i}]"), why);
        }
    }
    if !(1..=365).contains(&p.cert_warn_days) {
        r.err("probe.cert_warn_days", "from 1 to 365 days");
    }
}

// REQ: OBS-016 (T11.1) — objectives below 100% (a 100% target leaves no budget to burn), a
// threshold Prometheus can compute too, a window the rollups hold.
fn slo(cfg: &Config, r: &mut Report<'_>) {
    let s = &cfg.slo;
    for (key, t) in [
        ("slo.availability_target", s.availability_target),
        ("slo.latency_target", s.latency_target),
    ] {
        if !(50.0..100.0).contains(&t) {
            r.err(
                key,
                "a percentage from 50 up to (not including) 100, e.g. 99.9",
            );
        }
    }
    if !crate::schema::SLO_LATENCY_MS.contains(&s.latency_ms) {
        r.err(
            "slo.latency_ms",
            format!(
                "one of {} (the /metrics histogram's bucket bounds)",
                crate::schema::SLO_LATENCY_MS
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    if !(1..=90).contains(&s.window_days) {
        r.err("slo.window_days", "from 1 to 90 days");
    }
}

// REQ: FLT-010 (T7.10) — schedules: unique names, known lists and services for their
// action, readable windows, and groups that name schedules that exist.
fn schedules(cfg: &Config, r: &mut Report<'_>) {
    use crate::schema::ScheduleAction;
    let mut names = HashSet::new();
    for (i, s) in cfg.schedule.iter().enumerate() {
        let p = format!("schedule[{i}]");
        if s.name.is_empty() || !names.insert(s.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        match s.action {
            ScheduleAction::EnableLists if s.lists.is_empty() => {
                r.err(
                    format!("{p}.lists"),
                    "`enable_lists` needs at least one list",
                );
            }
            ScheduleAction::BlockServices if s.services.is_empty() => {
                r.err(
                    format!("{p}.services"),
                    "`block_services` needs at least one service",
                );
            }
            _ => {}
        }
        for (j, l) in s.lists.iter().enumerate() {
            if !cfg.list.iter().any(|x| x.name == *l) {
                r.err(
                    format!("{p}.lists[{j}]"),
                    format!("no list `{}`", l.as_str()),
                );
            }
        }
        for (j, x) in s.services.iter().enumerate() {
            if crate::services::find(x.as_str()).is_none() {
                r.err(
                    format!("{p}.services[{j}]"),
                    format!("no service `{}` (see `wrendns services list`)", x.as_str()),
                );
            }
        }
        if s.window.is_empty() {
            r.err(format!("{p}.window"), "needs at least one window");
        }
        for (j, w) in s.window.iter().enumerate() {
            if let Err(e) = crate::schedule::parse_window(w) {
                r.err(format!("{p}.window[{j}]"), e);
            }
        }
        if let Some(tz) = &s.tz
            && let Err(e) = crate::schedule::time_zone(Some(tz.as_str()))
        {
            r.err(format!("{p}.tz"), e);
        }
    }
    for (i, g) in cfg.group.iter().enumerate() {
        for (j, s) in g.schedules.iter().enumerate() {
            if !cfg.schedule.iter().any(|x| x.name == *s) {
                r.err(
                    format!("group[{i}].schedules[{j}]"),
                    format!("no schedule `{}`", s.as_str()),
                );
            }
        }
    }
}

// REQ: OBS-038 (ADR-161) — anomaly mutes: unique names, at least one device or group and one
// kind, devices and groups that exist and have addresses, a readable end time.
/// REQ: OPS-012 (ADR-163) — the watchdog's limits.
fn watchdog(cfg: &Config, r: &mut Report<'_>) {
    let w = &cfg.watchdog;
    if !(20..=600).contains(&w.stall_secs) {
        r.err(
            "watchdog.stall_secs",
            "use 20 to 600 seconds: a busy node still answers within a few seconds, and a longer wait only delays the restart",
        );
    }
    if w.max_restarts_per_hour > 60 {
        r.err(
            "watchdog.max_restarts_per_hour",
            "use 0 to 60 (0 never restarts)",
        );
    }
}

fn anomaly_mutes(cfg: &Config, r: &mut Report<'_>) {
    if cfg.anomaly_mute.len() > crate::schema::MAX_ANOMALY_MUTES {
        r.err(
            "anomaly_mute",
            format!("at most {} anomaly mutes", crate::schema::MAX_ANOMALY_MUTES),
        );
    }
    let mut names = HashSet::new();
    for (i, m) in cfg.anomaly_mute.iter().enumerate() {
        let p = format!("anomaly_mute[{i}]");
        if !names.insert(m.name.as_str()) {
            r.err(format!("{p}.name"), format!("`{}` is used twice", m.name));
        }
        for (field, msg) in crate::mute::problems(cfg, m) {
            r.err(format!("{p}.{field}"), msg);
        }
    }
}

// REQ: FLT-012 (T7.9) — blocked services exist; `svc-` list names are theirs.
fn services(cfg: &Config, r: &mut Report<'_>) {
    for (i, g) in cfg.group.iter().enumerate() {
        for (j, s) in g.blocked_services.iter().enumerate() {
            if crate::services::find(s.as_str()).is_none() {
                r.err(
                    format!("group[{i}].blocked_services[{j}]"),
                    format!("no service `{}` (see `wrendns services list`)", s.as_str()),
                );
            }
        }
    }
    for (i, l) in cfg.list.iter().enumerate() {
        if l.name.as_str().starts_with(crate::services::PREFIX) {
            r.err(
                format!("list[{i}].name"),
                format!(
                    "names starting with `{}` are kept for blocked services",
                    crate::services::PREFIX
                ),
            );
        }
    }
}

// REQ: FLT-901, FLT-902 (T24.29, ADR-994, ADR-995) — the `cat-` prefix is the catalog's, a group's
// content and safe-search engines name things that exist. A category ID this version does not
// know is not an error (a newer node may have written it: it is ignored and reported).
fn categories(cfg: &Config, r: &mut Report<'_>) {
    let cat = crate::categories::catalog();
    for (i, l) in cfg.list.iter().enumerate() {
        let name = l.name.as_str();
        if !crate::categories::is_category_list(name) {
            continue;
        }
        let p = format!("list[{i}]");
        if l.url.is_some() || l.path.is_some() || !l.rules.is_empty() {
            r.err(
                format!("{p}.name"),
                format!(
                    "names starting with `{}` are kept for category lists, which take their source from the catalog (only `mode` can be set on one)",
                    crate::categories::PREFIX
                ),
            );
        } else if l.kind != crate::schema::ListKind::Block
            || !l.enabled
            || l.refresh_secs.is_some()
            || l.max_bytes.is_some()
            || l.stale_after_days.is_some()
        {
            r.err(
                &p,
                "a category list can only be set to `mode` (enforce or shadow)",
            );
        } else if cat.source_of_list(name).is_none() {
            r.warn(format!(
                "{p}: no catalog source for `{name}` in this version; ignored"
            ));
        }
    }
    let engines: Vec<&str> = crate::safesearch::engines()
        .iter()
        .map(|e| e.id.as_str())
        .collect();
    for (i, g) in cfg.group.iter().enumerate() {
        let p = format!("group[{i}]");
        for (j, e) in g.safe_search_engines.iter().enumerate() {
            if !engines.contains(&e.as_str()) {
                r.err(
                    format!("{p}.safe_search_engines[{j}]"),
                    format!("no engine `{e}` (use {})", engines.join(", ")),
                );
            }
        }
        let Some(c) = &g.content else { continue };
        for (j, id) in c.categories.iter().enumerate() {
            if let Some(known) = cat.category(id) {
                if known.kind == crate::categories::CategoryKind::Service {
                    r.err(
                        format!("{p}.content.categories[{j}]"),
                        format!("`{id}` is a bundle of services: use `blocked_services` instead"),
                    );
                }
            } else {
                r.warn(format!(
                    "{p}.content.categories[{j}]: no category `{id}` in this version; ignored"
                ));
            }
        }
        for (id, tier) in &c.tiers {
            match cat.category(id) {
                Some(k) if k.tier_from.is_some() => r.err(
                    format!("{p}.content.tiers.{id}"),
                    "the size of Ad Block is `[filter] ads_tier`",
                ),
                Some(k) if !k.tier.iter().any(|t| t.id == *tier) => r.err(
                    format!("{p}.content.tiers.{id}"),
                    format!("`{id}` has no tier `{tier}`"),
                ),
                _ => {}
            }
        }
    }
    if cfg.filter.entry_budget == 0 {
        r.err("filter.entry_budget", "must be at least 1");
    }
}

// REQ: FLT-005 (T6.12, ADR-067) — quick rules: a real domain, known groups, devices that are
// named devices or addresses, a readable expiry, unique IDs, and at most MAX_RULES.
fn rules(cfg: &Config, r: &mut Report<'_>) {
    let groups: HashSet<&str> = cfg
        .group
        .iter()
        .map(|g| g.name.as_str())
        .chain(["default"])
        .collect();
    if cfg.rule.len() > crate::schema::MAX_RULES {
        r.err(
            "rule",
            format!("at most {} quick rules", crate::schema::MAX_RULES),
        );
    }
    let devices: HashSet<String> = cfg
        .client
        .iter()
        .map(|c| c.name.to_ascii_lowercase())
        .collect();
    let mut ids = HashSet::new();
    for (i, rule) in cfg.rule.iter().enumerate() {
        let p = format!("rule[{i}]");
        if rule.id.is_empty() || !ids.insert(rule.id.as_str()) {
            r.err(
                format!("{p}.id"),
                format!("must be unique and not empty (`{}`)", rule.id),
            );
        }
        let d = rule.domain.trim_end_matches('.');
        if d.is_empty()
            || d.len() > 253
            || d.split('.').any(|l| l.is_empty() || l.len() > 63)
            || d.contains(['*', '/', ' '])
        {
            r.err(
                format!("{p}.domain"),
                format!(
                    "`{}` isn't a domain name (subdomains are included; no wildcards)",
                    rule.domain
                ),
            );
        }
        for (j, dev) in rule.devices.iter().enumerate() {
            let known = devices.contains(&dev.to_ascii_lowercase());
            let address = crate::Cidr::parse(dev).is_ok();
            // REQ: FLT-005 (T24.9, ADR-973) — a router's name for the device.
            let router_name = matches!(MatchKey::parse(dev), Ok(MatchKey::Hostname(_)));
            if !known && !address && !router_name {
                r.err(
                    format!("{p}.devices[{j}]"),
                    format!("`{dev}` is neither a device name, an IP or CIDR, nor hostname:<router name>"),
                );
            }
        }
        for (j, g) in rule.groups.iter().enumerate() {
            if !groups.contains(g.as_str()) {
                r.err(format!("{p}.groups[{j}]"), format!("unknown group `{g}`"));
            }
        }
        if let Some(e) = &rule.expires
            && crate::types::parse_rfc3339(e).is_none()
        {
            r.err(
                format!("{p}.expires"),
                format!("`{e}` isn't an RFC 3339 time like 2026-10-05T21:30:00Z"),
            );
        }
    }
}

// REQ: CLU-001 — the cluster port can't share an address with a listener (both default to
// 8443 for DoH and the cluster channel).
fn cluster(cfg: &Config, r: &mut Report<'_>) {
    if !matches!(cfg.cluster.config_source.as_str(), "file" | "gitops") {
        r.err("cluster.config_source", "must be `file` or `gitops`");
    }
    // REQ: CLU-009 — automatic cluster creation and joining (Helm).
    let c = &cfg.cluster;
    if let Some(init) = &c.init {
        if init.advertise.is_empty() {
            r.err(
                "cluster.init.advertise",
                "needs at least one URL peers can reach",
            );
        }
        if !matches!(init.config_authority.as_str(), "api" | "gitops") {
            r.err("cluster.init.config_authority", "must be `api` or `gitops`");
        }
        if c.join_url.is_some() {
            r.err(
                "cluster.join_url",
                "a node either creates a cluster (init) or joins one",
            );
        }
    }
    if c.join_url.is_some() && c.bootstrap_secret_file.is_none() {
        r.err(
            "cluster.join_url",
            "needs bootstrap_secret_file (the shared join secret)",
        );
    }
    if c.ephemeral && c.join_url.is_none() {
        r.warn("cluster.ephemeral only applies when joining with join_url");
    }
    if c.ephemeral_ttl_secs < 60 {
        r.err("cluster.ephemeral_ttl_secs", "must be at least 60");
    }
    // REQ: CLU-003 (ADR-049) — the Git config source.
    if let Some(g) = &c.git {
        let repo = g.repo.as_str();
        let local_http = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| repo.starts_with(p));
        if !repo.starts_with("https://") && !local_http {
            r.err(
                "cluster.git.repo",
                "must be an https:// URL (plain http only on this host, for testing)",
            );
        }
        let path = g.path.as_str();
        if path.is_empty() || path.starts_with('/') || path.split('/').any(|p| p == "..") {
            r.err(
                "cluster.git.path",
                "must be a file inside the repository, e.g. wrendns/shared.toml",
            );
        }
        if g.git_ref.as_str().is_empty() {
            r.err("cluster.git.ref", "must name a branch, tag, or commit");
        }
        if g.poll_secs < 5 {
            r.err("cluster.git.poll_secs", "must be at least 5");
        }
        if g.require_signed && g.allowed_signers_file.is_none() {
            r.err(
                "cluster.git.allowed_signers_file",
                "require_signed needs the allowed signers",
            );
        }
    }
    let Ok(addr) = cfg.cluster.listen.as_str().parse::<std::net::SocketAddr>() else {
        r.err(
            "cluster.listen",
            "must be an address and port, e.g. 0.0.0.0:8443",
        );
        return;
    };
    for (i, l) in cfg.listen.iter().enumerate() {
        if matches!(
            l.proto,
            crate::ListenProto::Tcp | crate::ListenProto::Dot | crate::ListenProto::Doh
        ) && l.addr.port() == addr.port()
        {
            r.warn(format!(
                "cluster.listen: listen[{i}] also uses TCP port {}; the cluster port opens only after `wrendns cluster init|join`, and will then fail to bind",
                addr.port()
            ));
        }
    }
}

// REQ: API-003
fn auth(cfg: &Config, r: &mut Report<'_>) {
    let a = &cfg.auth;
    if a.session_ttl_hours == 0 || a.session_ttl_hours > 24 * 366 {
        r.err("auth.session_ttl_hours", "must be 1 to 8784 (a year)");
    }
    if a.session_idle_hours == 0 || a.session_idle_hours > a.session_ttl_hours {
        r.err(
            "auth.session_idle_hours",
            "must be at least 1 and at most auth.session_ttl_hours",
        );
    }
    if a.allow_insecure_basic {
        r.warn("auth.allow_insecure_basic: passwords sent with HTTP Basic cross the network in the clear");
    }
    // REQ: API-003 (ADR-149)
    if let Some(t) = &cfg.api.tls {
        match (t.self_signed, &t.cert, &t.key) {
            (true, None, None) | (false, Some(_), Some(_)) => {}
            (true, _, _) => r.err(
                "api.tls",
                "self_signed = true makes its own certificate: leave out cert and key",
            ),
            (false, _, _) => r.err(
                "api.tls",
                "set self_signed = true, or both cert and key (PEM files)",
            ),
        }
    }
    // REQ: API-003 (T24.44, ADR-1053) — the plain-HTTP redirect listener only makes sense next
    // to HTTPS, and must not take the API's own address.
    if let Some(addr) = cfg.api.http_redirect {
        if cfg.api.tls.is_none() {
            r.err(
                "api.http_redirect",
                "needs [api] tls: it sends browsers to the HTTPS address, so there must be one",
            );
        }
        if addr.port() == 0 {
            r.err("api.http_redirect", "the port must be 1 to 65535");
        }
        if addrs_clash(addr, cfg.api.listen) {
            r.err("api.http_redirect", "must differ from [api] listen");
        }
    }
    // REQ: API-902 (ADR-956 §3) — the confirmation window of a guarded address change.
    if !(30..=600).contains(&cfg.api.confirm_window_secs) {
        r.err("api.confirm_window_secs", "must be 30 to 600 seconds");
    }
    oidc(&a.oidc, r);
}

// REQ: API-004
fn oidc(o: &crate::OidcConfig, r: &mut Report<'_>) {
    let url = o.public_url.as_str();
    if !o.provider.is_empty() {
        let ok = (url.starts_with("https://") || url.starts_with("http://"))
            && url.split_once("://").is_some_and(|(_, rest)| {
                !rest.is_empty() && !rest.trim_end_matches('/').contains('/')
            });
        if !ok {
            r.err(
                "auth.oidc.public_url",
                "required with providers: the address people open the UI at, like https://dns.example.com (no path)",
            );
        } else if url.starts_with("http://") {
            r.warn("auth.oidc.public_url: plain HTTP; providers may refuse http redirect URIs except for localhost");
        }
    }
    // REQ: AGT-008 (T7.4) — MCP sign-in uses one of the configured providers.
    if !o.mcp_provider.is_empty() && !o.provider.iter().any(|p| p.id == o.mcp_provider) {
        r.err(
            "auth.oidc.mcp_provider",
            format!(
                "`{}` isn't the id of an [[auth.oidc.provider]]",
                o.mcp_provider.as_str()
            ),
        );
    }
    if o.disable_local_login && o.provider.is_empty() {
        r.err(
            "auth.oidc.disable_local_login",
            "needs at least one [[auth.oidc.provider]]: otherwise only break-glass admins could sign in",
        );
    }
    let mut ids = HashSet::new();
    for (n, p) in o.provider.iter().enumerate() {
        let at = format!("auth.oidc.provider[{n}]");
        provider(p, &at, r);
        if !ids.insert(p.id.as_str()) {
            r.err(
                format!("{at}.id"),
                format!("duplicate provider `{}`", p.id.as_str()),
            );
        }
    }
}

/// One provider's own settings (the checks that don't look at the rest of the configuration).
fn provider(p: &crate::OidcProvider, at: &str, r: &mut Report<'_>) {
    let id = p.id.as_str();
    if id.is_empty()
        || id.len() > 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        r.err(format!("{at}.id"), "1-32 lowercase letters, digits, or -");
    }
    let issuer = p.issuer.as_str();
    if !(issuer.starts_with("https://") || issuer.starts_with("http://")) {
        r.err(format!("{at}.issuer"), "must be an http(s) URL");
    } else if issuer.starts_with("http://") {
        r.warn(format!(
            "{at}.issuer: plain HTTP is only safe for local testing"
        ));
    }
    if p.client_id.is_empty() {
        r.err(format!("{at}.client_id"), "must not be empty");
    }
    if !p.scopes.iter().any(|s| s.as_str() == "openid") {
        r.err(format!("{at}.scopes"), "must include `openid`");
    }
    if p.role.is_empty() && p.default_role.is_none() {
        r.warn(format!(
            "{at}: no [[...role]] rules and no default_role: nobody can sign in with `{id}`"
        ));
    }
}

/// REQ: API-016 (T23.11) — the problems with one event sink on its own (a sink made in the UI),
/// as messages: the rules `validate_config` applies to a file's sinks, minus the uniqueness of
/// its name across the list.
pub fn sink_errors(s: &crate::SinkConfig) -> Vec<String> {
    let mut errors = Vec::new();
    let mut report = Report {
        errors: &mut errors,
        warnings: Vec::new(),
    };
    if s.name.is_empty() {
        report.err("sink.name", "must not be empty");
    }
    sink_one(s, "sink", &mut report);
    if let Some(n) = s.token_ref.as_ref()
        && !crate::secret_refs::valid_name(n.as_str())
    {
        report.err("sink.token_ref", "not a valid stored secret name");
    }
    if s.token_ref.is_some() && s.token_file.is_some() {
        report.err(
            "sink.token_ref",
            "set one of token_file, token_ref, not both",
        );
    }
    errors.iter().map(ToString::to_string).collect()
}

/// REQ: API-016 (T23.11) — the problems with an OTLP export on its own (the one made in the UI),
/// as messages.
pub fn otlp_errors(o: &crate::OtlpConfig) -> Vec<String> {
    let mut errors = Vec::new();
    let mut report = Report {
        errors: &mut errors,
        warnings: Vec::new(),
    };
    otlp_one(o, &mut report);
    for (h, n) in &o.header_refs {
        if o.headers.contains_key(h) {
            report.err(
                format!("telemetry.otlp.header_refs.{h}"),
                "the header is in `headers` too: set it in one of them",
            );
        }
        if !crate::secret_refs::valid_name(n.as_str()) {
            report.err(
                format!("telemetry.otlp.header_refs.{h}"),
                "not a valid stored secret name",
            );
        }
        if h.is_empty()
            || !h
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            report.err(
                format!("telemetry.otlp.header_refs.{h}"),
                "a header name: letters, digits, `-` or `_`",
            );
        }
    }
    errors.iter().map(ToString::to_string).collect()
}

/// REQ: API-016 (T23.10) — the problems with one OIDC provider on its own (a provider made in
/// the UI), as messages; warnings are left out. The rules are the ones `validate_config`
/// applies to a file's providers, minus `public_url` (a node without one shows the provider as
/// inactive) and the duplicate check across the list.
pub fn provider_errors(p: &crate::OidcProvider) -> Vec<String> {
    let mut errors = Vec::new();
    let mut report = Report {
        errors: &mut errors,
        warnings: Vec::new(),
    };
    provider(p, "provider", &mut report);
    errors.iter().map(ToString::to_string).collect()
}

fn node(cfg: &Config, r: &mut Report<'_>) {
    if cfg.config_version != CONFIG_VERSION {
        r.err(
            "config_version",
            format!(
                "unsupported version {} (this build supports {CONFIG_VERSION})",
                cfg.config_version
            ),
        );
    }
    if cfg.node.workers > 1024 {
        r.err("node.workers", "must be at most 1024 (0 = auto)");
    }
    if cfg.node.data_dir.is_empty() {
        r.err("node.data_dir", "must not be empty");
    }
}

fn listeners(cfg: &Config, r: &mut Report<'_>) {
    if cfg.listen.is_empty() {
        r.err("listen", "at least one listener is required");
    }
    let mut seen = HashSet::new();
    for (i, l) in cfg.listen.iter().enumerate() {
        let p = format!("listen[{i}]");
        if !seen.insert((l.proto, l.addr)) {
            r.err(
                &p,
                format!("duplicate listener {:?} on {}", l.proto, l.addr),
            );
        }
        if l.proto.needs_tls() && l.tls.is_none() {
            r.err(
                format!("{p}.tls"),
                "required for dot, doh, doh3, and doq listeners",
            );
        }
        if !l.proto.needs_tls() && l.tls.is_some() {
            r.err(
                format!("{p}.tls"),
                "only valid for dot, doh, doh3, and doq listeners",
            );
        }
        if let Some(path) = &l.path {
            if !l.proto.is_http() {
                r.err(format!("{p}.path"), "only valid for doh and doh3 listeners");
            } else if !path.starts_with('/') {
                r.err(format!("{p}.path"), "must start with `/`");
            }
        }
        if l.proxy_protocol && !l.proto.is_tcp_based() {
            r.err(
                format!("{p}.proxy_protocol"),
                "only valid for tcp, dot, and doh listeners",
            );
        }
        // REQ: DNS-901 (T36.2) — the known-ID gate needs a place to carry the key. Only `true` is
        // an error there: `false` and unset leave a udp or tcp listener as it is.
        if l.require_client_id == Some(true) && !l.proto.needs_tls() {
            r.err(
                format!("{p}.require_client_id"),
                "only valid for dot, doh, doh3, and doq listeners (a plain udp or tcp query carries no client ID)",
            );
        }
        // REQ: DNS-901 (T36.2, ADR-1090 point 1, spec/08 §6) — the startup check: a listener
        // that is not gated and is bound outside `[access] allowed_networks` is protected only
        // by `allowed_networks`. A wildcard bind is not warned about here (ADR-1090 point 1; the
        // node logs a line for an encrypted one at bind). udp and tcp cannot be gated: their text names no flag.
        if !l.gated() {
            let outside = !l.addr.ip().is_unspecified()
                && !cfg
                    .access
                    .allowed_networks
                    .iter()
                    .any(|n| n.contains(l.addr.ip().to_canonical()));
            if !l.proto.needs_tls() {
                if outside {
                    r.warn(format!(
                        "{p}: {:?} listener on address {} outside [access] allowed_networks; only allowed_networks keeps it from being an open resolver (udp and tcp cannot carry a device key)",
                        l.proto,
                        l.addr.ip()
                    ));
                }
            } else if outside {
                r.warn(format!(
                    "{p}: {:?} listener on address {} with require_client_id = {}; only [access] allowed_networks keeps it from being an open resolver",
                    l.proto,
                    l.addr.ip(),
                    if l.require_client_id == Some(false) {
                        "false"
                    } else {
                        "unset"
                    }
                ));
            }
        }
        if l.proto == crate::ListenProto::Udp {
            if l.max_connections.is_some() {
                r.err(
                    format!("{p}.max_connections"),
                    "not valid for udp listeners",
                );
            }
            if l.max_connections_per_address.is_some() {
                r.err(
                    format!("{p}.max_connections_per_address"),
                    "not valid for udp listeners",
                );
            }
        }
        if l.max_connections == Some(0) {
            r.err(format!("{p}.max_connections"), "must be at least 1");
        }
    }
}

/// REQ: DNS-022 — a stub zone needs both its name and its servers.
fn stub_zone(u: &crate::schema::Upstream, p: &str, r: &mut Report<'_>) {
    match (&u.recursive.stub_zone, u.recursive.stub_servers.is_empty()) {
        (Some(z), _) if z.is_empty() || z.len() > 253 || z.contains(' ') => r.err(
            format!("{p}.recursive.stub_zone"),
            format!("invalid domain `{z}`"),
        ),
        (Some(_), true) => r.err(
            format!("{p}.recursive.stub_servers"),
            "give the stub zone's servers, e.g. [\"10.0.0.53\"]",
        ),
        (None, false) => r.err(
            format!("{p}.recursive.stub_zone"),
            "name the zone `stub_servers` serve, e.g. \"corp.example\"",
        ),
        _ => {}
    }
}

/// REQ: UPS-003 (T9.9) — relays carry DNSCrypt only.
fn relay(u: &crate::schema::Upstream, scheme: &str, p: &str, r: &mut Report<'_>) {
    let Some(relay) = &u.relay else { return };
    let relay = relay.as_str();
    if scheme != "sdns" {
        r.err(
            format!("{p}.relay"),
            "only for DNSCrypt (sdns://) upstreams",
        );
    } else if !relay.starts_with("sdns://") && relay.parse::<std::net::SocketAddr>().is_err() {
        r.err(
            format!("{p}.relay"),
            "a relay stamp (sdns://…) or ip:port, e.g. 203.0.113.7:443",
        );
    }
}

/// Validates upstreams and returns the set of their names.
/// REQ: UPS-013 (T24.31, ADR-997) — `source` only where it binds, not through a proxy, and
/// readable as an address or a network.
fn source_errors(u: &crate::schema::Upstream, scheme: &str, p: &str, r: &mut Report<'_>) {
    let Some(src) = &u.source else { return };
    if !matches!(scheme, "udp" | "tcp" | "tls" | "https") {
        r.err(
            format!("{p}.source"),
            "only for udp://, tcp://, tls://, and https:// upstreams",
        );
    } else if u.proxy.is_some() {
        r.err(
            format!("{p}.source"),
            "not with a proxy (the proxy opens the connection, from its own address)",
        );
    } else if let Err(e) = crate::parse_source(src) {
        r.err(format!("{p}.source"), e);
    }
}

fn upstreams<'c>(cfg: &'c Config, r: &mut Report<'_>) -> HashSet<&'c str> {
    let mut names = HashSet::new();
    for (i, u) in cfg.upstream.iter().enumerate() {
        let p = format!("upstream[{i}]");
        if u.name.is_empty() {
            r.err(format!("{p}.name"), "must not be empty");
        } else if !names.insert(u.name.as_str()) {
            r.err(
                format!("{p}.name"),
                format!("duplicate upstream name `{}`", u.name),
            );
        }
        match u.url.split_once("://").map(|(s, _)| s) {
            Some(s) if UPSTREAM_SCHEMES.contains(&s) => {
                if u.http_version != HttpVersion::Auto && s != "https" {
                    r.err(
                        format!("{p}.http_version"),
                        "only valid for https:// upstreams",
                    );
                }
                if s != "https" && s != "h3" && !u.headers.is_empty() {
                    r.err(format!("{p}.headers"), "only valid for DoH upstreams");
                }
                // REQ: UPS-011 (T7.16)
                upstream_tls(u, s, &p, r);
                if s != "exec" && !u.args.is_empty() {
                    r.err(format!("{p}.args"), "only valid for exec:// upstreams");
                }
                if (s == "unix" || s == "exec") && !u.url.as_str()[s.len() + 3..].starts_with('/') {
                    r.err(
                        format!("{p}.url"),
                        format!("use an absolute path, e.g. `{s}:///run/plugin`"),
                    );
                }
                // REQ: DNS-015 (T7.23)
                if let Some(e) = &u.ecs
                    && !matches!(e.as_str(), "strip" | "client")
                    && crate::Cidr::parse(e).is_err()
                {
                    r.err(
                        format!("{p}.ecs"),
                        "`strip` (the default: never sent), `client` (each public client's /24 or /56), or a subnet to send instead, e.g. 203.0.113.0/24",
                    );
                }
                // REQ: UPS-010 (T7.16)
                // REQ: UPS-010 (T9.9) — udp:// only through a SOCKS5 proxy's UDP relay.
                let socks = u
                    .proxy
                    .as_ref()
                    .is_some_and(|x| x.as_str().starts_with("socks5://"));
                if u.proxy.is_some()
                    && !matches!(s, "tcp" | "tls" | "https")
                    && !(s == "udp" && socks)
                {
                    r.err(format!("{p}.proxy"), "only for tcp://, tls://, and https:// upstreams, or udp:// through a socks5:// proxy (use tcp:// with an HTTP proxy or Tor)");
                }
                relay(u, s, &p, r);
                source_errors(u, s, &p, r);
                // REQ: DNS-012 (T7.15)
                if s != "recursive" && u.recursive != crate::schema::RecursiveConfig::default() {
                    r.err(
                        format!("{p}.recursive"),
                        "only valid for recursive:// upstreams",
                    );
                }
                if s == "recursive" && !matches!(u.url.as_str(), "recursive://" | "recursive:///") {
                    r.err(
                        format!("{p}.url"),
                        "write it as `recursive://` (it starts at the root servers)",
                    );
                }
                stub_zone(u, &p, r);
            }
            Some(s) => r.err(
                format!("{p}.url"),
                format!(
                    "unsupported scheme `{s}://` (expected one of: {})",
                    UPSTREAM_SCHEMES.join(", ")
                ),
            ),
            None => r.err(
                format!("{p}.url"),
                "must include a scheme, e.g. `udp://9.9.9.9` or `https://dns.quad9.net/dns-query`",
            ),
        }
        if u.weight == 0 {
            r.err(format!("{p}.weight"), "must be at least 1");
        }
        if u.timeout_ms == 0 || u.timeout_ms > 10_000 {
            r.err(format!("{p}.timeout_ms"), "must be between 1 and 10000");
        }
        if u.pool_size == 0 {
            r.err(format!("{p}.pool_size"), "must be at least 1");
        }
        if u.tls_insecure_skip_verify {
            r.warn(format!(
                "{p}.tls_insecure_skip_verify: certificate verification is DISABLED for upstream `{}`",
                u.name
            ));
        }
    }
    if cfg.upstream.is_empty() {
        r.warn("upstream: none configured; only local, blocked, and cached answers can be served (on a cluster replica, the primary's upstreams apply)");
    }
    names
}

/// Validates upstream groups and returns the set of their names.
fn groups<'c>(cfg: &'c Config, upstreams: &HashSet<&str>, r: &mut Report<'_>) -> HashSet<&'c str> {
    let mut groups = HashSet::new();
    for (i, g) in cfg.upstream_group.iter().enumerate() {
        let p = format!("upstream_group[{i}]");
        if g.name.is_empty() {
            r.err(format!("{p}.name"), "must not be empty");
        } else if !groups.insert(g.name.as_str()) {
            r.err(
                format!("{p}.name"),
                format!("duplicate upstream group `{}`", g.name),
            );
        }
        if g.members.is_empty() {
            r.err(format!("{p}.members"), "must list at least one upstream");
        }
        for (j, m) in g.members.iter().enumerate() {
            if !upstreams.contains(m.as_str()) {
                r.err(
                    format!("{p}.members[{j}]"),
                    format!("unknown upstream `{m}`"),
                );
            } else if !g.node_only && cfg.upstream.iter().any(|u| u.name == *m && u.node_only) {
                // REQ: CLU-006, FLT-017 — other nodes wouldn't have it.
                r.err(
                    format!("{p}.members[{j}]"),
                    format!("upstream `{m}` is node_only, so this group must be node_only too"),
                );
            }
        }
        if g.strategy == Strategy::Parallel
            && (g.parallel_fanout < 2 || usize::from(g.parallel_fanout) > g.members.len())
        {
            r.err(
                format!("{p}.parallel_fanout"),
                "must be between 2 and the number of members for strategy `parallel`",
            );
        }
    }
    if !cfg.upstream.is_empty() && !groups.contains("default") {
        r.warn(
            "upstream_group: no group named `default`; queries that match no route have no upstream",
        );
    }
    groups
}

fn routes(cfg: &Config, groups: &HashSet<&str>, r: &mut Report<'_>) {
    // REQ: CLU-006, FLT-017 — a node-only group exists on its own node only, so nothing the
    // cluster shares may name it.
    let node_only = |g: &str| {
        cfg.upstream_group
            .iter()
            .any(|x| x.name.as_str() == g && x.node_only)
    };
    let shared_err = |g: &str| format!("upstream group `{g}` is node_only, so this must be too");
    // REQ: UPS-007 (T9.25) — a client group's own upstream group.
    for (i, g) in cfg.group.iter().enumerate() {
        if let Some(u) = &g.upstreams {
            if !groups.contains(u.as_str()) {
                r.err(
                    format!("group[{i}].upstreams"),
                    format!("unknown upstream group `{u}`"),
                );
            } else if node_only(u) {
                r.err(
                    format!("group[{i}].upstreams"),
                    format!("upstream group `{u}` is node_only; a client group is shared, so use a route with node_only = true"),
                );
            }
        }
    }
    for (i, route) in cfg.route.iter().enumerate() {
        let p = format!("route[{i}]");
        if !groups.contains(route.upstream_group.as_str()) {
            r.err(
                format!("{p}.upstream_group"),
                format!("unknown upstream group `{}`", route.upstream_group),
            );
        } else if !route.node_only && node_only(&route.upstream_group) {
            r.err(
                format!("{p}.upstream_group"),
                shared_err(&route.upstream_group),
            );
        }
        if route.match_suffix.is_empty()
            && route.match_group.is_empty()
            && route.match_qtype.is_empty()
        {
            r.err(
                &p,
                "needs at least one of match_suffix, match_group, match_qtype",
            );
        }
        for (j, s) in route.match_suffix.iter().enumerate() {
            if s.is_empty() || s.len() > 253 || s.contains(' ') {
                r.err(
                    format!("{p}.match_suffix[{j}]"),
                    format!("invalid domain `{s}`"),
                );
            }
        }
    }
}

/// Most lists one snapshot can hold: list-ID bitsets are 1024 bits wide (`spec/05` §3.1).
pub const MAX_LISTS: usize = 1024;

/// A list name is a file-name-safe ID.
pub fn valid_list_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

// REQ: FLT-004 — list sources and fetch limits.
fn lists(cfg: &Config, r: &mut Report<'_>) {
    if cfg.list.len() > MAX_LISTS {
        r.err("list", format!("at most {MAX_LISTS} lists are supported"));
    }
    let mut names = HashSet::new();
    for (i, l) in cfg.list.iter().enumerate() {
        let p = format!("list[{i}]");
        let name = l.name.as_str();
        if !valid_list_name(name) {
            r.err(
                format!("{p}.name"),
                "use 1-64 lowercase letters, digits, `-` or `_`",
            );
        } else if !names.insert(name) {
            r.err(format!("{p}.name"), format!("duplicate list name `{name}`"));
        }
        let sources = usize::from(l.url.is_some())
            + usize::from(l.path.is_some())
            + usize::from(!l.rules.is_empty());
        // REQ: FLT-901 (ADR-994 item 9) — `cat-` lists take their source from the catalog; an
        // entry of that name can only set `mode`. Checked in `categories`.
        if sources != 1 && !crate::categories::is_category_list(name) {
            r.err(&p, "set exactly one of `url`, `path`, or `rules`");
        }
        // REQ: OBS-018 (T11.5) — only a block list has blocks to count.
        if l.mode == crate::schema::ListMode::Shadow && l.kind != crate::schema::ListKind::Block {
            r.err(
                format!("{p}.mode"),
                "shadow is for block lists (an allow list has nothing to count)",
            );
        }
        if let Some(url) = &l.url {
            match url.split_once("://") {
                Some(("https", rest)) if !rest.is_empty() => {}
                Some(("http", rest)) if !rest.is_empty() => r.warn(format!(
                    "{p}.url: plain http can be tampered with in transit; prefer https"
                )),
                _ => r.err(
                    format!("{p}.url"),
                    "must start with `https://` or `http://`",
                ),
            }
        }
        if let Some(path) = &l.path
            && path.is_empty()
        {
            r.err(format!("{p}.path"), "must not be empty");
        }
        if let Some(s) = l.refresh_secs
            && s < 900
        {
            r.err(
                format!("{p}.refresh_secs"),
                "must be at least 900 (15 minutes)",
            );
        }
        if let Some(b) = l.max_bytes
            && !(1024..=1 << 30).contains(&b.bytes())
        {
            r.err(format!("{p}.max_bytes"), "must be between 1KiB and 1GiB");
        }
    }
    let f = &cfg.filter;
    if f.refresh_secs < 900 {
        r.err("filter.refresh_secs", "must be at least 900 (15 minutes)");
    }
    if !(1..=16).contains(&f.fetch_concurrency) {
        r.err("filter.fetch_concurrency", "must be between 1 and 16");
    }
    if f.fetch_timeout_secs < 5 {
        r.err("filter.fetch_timeout_secs", "must be at least 5");
    }
    if f.fetch_retries > 10 {
        r.err("filter.fetch_retries", "must be at most 10");
    }
    if !(1024..=1 << 30).contains(&f.max_list_bytes.bytes()) {
        r.err("filter.max_list_bytes", "must be between 1KiB and 1GiB");
    }
    if f.max_invalid_percent > 100 {
        r.err("filter.max_invalid_percent", "must be between 0 and 100");
    }
    if f.max_shrink_percent > 100 {
        r.err("filter.max_shrink_percent", "must be between 0 and 100");
    }
    if f.max_regexes > 100_000 {
        r.err(
            "filter.max_regexes",
            "must be at most 100000 (0 = no limit)",
        );
    }
    if f.compile_threads > 64 {
        r.err("filter.compile_threads", "must be at most 64 (0 = auto)");
    }
    if f.compile_memory.bytes() < 16 << 20 {
        r.err("filter.compile_memory", "must be at least 16MiB");
    }
}

/// A client `match` key, parsed (FLT-006).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MatchKey {
    Ip(std::net::IpAddr),
    Cidr(crate::Cidr),
    Mac([u8; 6]),
    ClientId(String),
    /// REQ: FLT-006 (T24.9, ADR-973) — the device name a router gave it (a label).
    Hostname(String),
}

/// REQ: API-010 (T24.9, ADR-973) — a router name in label form: 1–63 of `a-z`, `0-9`, `-`,
/// no leading or trailing `-` (`Kitchen Tablet` is `kitchen-tablet`).
pub(crate) fn router_label_ok(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl MatchKey {
    /// Parses `192.168.1.20`, `10.0.5.0/24`, `aa:bb:cc:dd:ee:ff` (or `-` separated), or
    /// `id:<client-id>` (1–63 of `a-z0-9-`, the DoH path / SNI label form).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(id) = s.strip_prefix("id:") {
            let id = id.to_ascii_lowercase();
            if id.is_empty()
                || id.len() > 63
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(format!("client ID `{id}`: use 1-63 of a-z, 0-9, -"));
            }
            return Ok(Self::ClientId(id));
        }
        // REQ: FLT-006 (T24.9, ADR-973) — `hostname:<label>`: a router's name for the device.
        if let Some(h) = s.strip_prefix("hostname:") {
            let h = h.to_ascii_lowercase();
            if !router_label_ok(&h) {
                return Err(format!(
                    "router name `{h}`: use the label form, 1-63 of a-z, 0-9 and -, as the name shows on the Clients page (Kitchen Tablet is kitchen-tablet)"
                ));
            }
            return Ok(Self::Hostname(h));
        }
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if s.contains('/') {
            return crate::Cidr::parse(s).map(Self::Cidr);
        }
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            for (i, p) in parts.iter().enumerate() {
                mac[i] = u8::from_str_radix(p, 16)
                    .ok()
                    .filter(|_| p.len() == 2)
                    .ok_or_else(|| format!("invalid MAC `{s}`"))?;
            }
            return Ok(Self::Mac(mac));
        }
        Err(format!("`{s}` is not an IP, CIDR, MAC, or id:<client-id>"))
    }
}

// REQ: DSC-001 (T25.2, ADR-907) — `[discovery]`: private IPv4 subnets only (IPv6, 100.64/10 and
// every other non-RFC 1918 range are refused), a worker memory limit in 32–128 MiB, a node name
// when one is set, and no enable at privacy level 2 or more (the inventory names devices).
fn discovery(cfg: &Config, r: &mut Report<'_>) {
    let d = &cfg.discovery;
    if let Some(n) = &d.node
        && n.as_str().trim().is_empty()
    {
        r.err("discovery.node", "name a node, or leave it out");
    }
    if !(crate::discovery::WORKER_MEMORY_MIN_MIB..=crate::discovery::WORKER_MEMORY_MAX_MIB)
        .contains(&d.worker_memory_mib)
    {
        r.err(
            "discovery.worker_memory_mib",
            "from 32 to 128 (MiB per discovery worker)",
        );
    }
    // REQ: DSC-009 (ADR-912) — the `stat/alluser` window.
    if !(crate::discovery::ALL_USERS_MIN_HOURS..=crate::discovery::ALL_USERS_MAX_HOURS)
        .contains(&d.unifi_all_users_within_hours)
    {
        r.err(
            "discovery.unifi_all_users_within_hours",
            "from 1 to 8,760 (hours, up to one year)",
        );
    }
    for (i, s) in d.subnets.iter().enumerate() {
        let path = format!("discovery.subnet[{i}].cidr");
        if !matches!(s.cidr.addr, std::net::IpAddr::V4(_)) {
            r.err(
                path,
                format!("`{}`: IPv6 isn't read yet (M25 is IPv4 only)", s.cidr),
            );
            continue;
        }
        if !crate::discovery::is_rfc1918_network(&s.cidr) {
            r.err(
                path,
                format!("`{}` isn't a private (RFC 1918) network: only 10/8, 172.16/12 and 192.168/16 are read", s.cidr),
            );
            continue;
        }
        if d.subnets[..i].iter().any(|o| o.cidr == s.cidr) {
            r.warn(format!("discovery.subnet: `{}` is listed twice", s.cidr));
        }
        for (net, what) in crate::discovery::OVERLAP_WARNINGS {
            if let Ok(n) = crate::Cidr::parse(net)
                && crate::discovery::overlaps(&s.cidr, &n)
            {
                r.warn(format!(
                    "discovery.subnet `{}` overlaps {what} ({net}): pod and service addresses would be read",
                    s.cidr
                ));
            }
        }
    }
    if d.enabled && cfg.telemetry.qlog.privacy_level >= 2 {
        r.err(
            "discovery.enabled",
            "the network inventory needs client addresses, which telemetry.qlog.privacy_level 2 and 3 hide: set it to 0 or 1 first",
        );
    }
    snmp_credentials(cfg, r);
    snmp_agents(cfg, r);
}

// REQ: DSC-901, DSC-906 (T31.2, ADR-1005 sections 1 and 12) — `[cmdb]`: each threshold in its range,
// and no enable at privacy level 2 or more (the CMDB names devices and holds their addresses, as
// the network inventory does; at level 1 names are hashed).
fn cmdb(cfg: &Config, r: &mut Report<'_>) {
    use crate::cmdb as c;
    let d = &cfg.cmdb;
    let ranges: [(&str, u32, u32, u32, &str); 6] = [
        (
            "cmdb.disappear_after_days",
            d.disappear_after_days,
            c::DISAPPEAR_MIN_DAYS,
            c::DISAPPEAR_MAX_DAYS,
            "from 1 to 365 (days)",
        ),
        (
            "cmdb.detect_settle_secs",
            d.detect_settle_secs,
            c::SETTLE_MIN_SECS,
            c::SETTLE_MAX_SECS,
            "from 60 to 86,400 (seconds)",
        ),
        (
            "cmdb.unconfirmed_alert_hours",
            d.unconfirmed_alert_hours,
            c::ALERT_MIN_HOURS,
            c::ALERT_MAX_HOURS,
            "from 1 to 720 (hours)",
        ),
        (
            "cmdb.plan_expiry_days",
            d.plan_expiry_days,
            c::PLAN_MIN_DAYS,
            c::PLAN_MAX_DAYS,
            "from 1 to 365 (days)",
        ),
        (
            "cmdb.history_days",
            d.history_days,
            c::HISTORY_MIN_DAYS,
            c::HISTORY_MAX_DAYS,
            "from 1 to 730 (days)",
        ),
        (
            "cmdb.macd_retention_days",
            d.macd_retention_days,
            c::MACD_MIN_DAYS,
            c::MACD_MAX_DAYS,
            "from 1 to 1,825 (days)",
        ),
    ];
    for (path, value, lo, hi, text) in ranges {
        if !(lo..=hi).contains(&value) {
            r.err(path, text);
        }
    }
    if d.enabled && cfg.telemetry.qlog.privacy_level >= 2 {
        r.err(
            "cmdb.enabled",
            "the CMDB needs client addresses and names, which telemetry.qlog.privacy_level 2 and 3 hide: set it to 0 or 1 first",
        );
    }
}

// REQ: DSC-004, DSC-007 (T25.6, ADR-908, ADR-1001) — `[[discovery.snmp_credential]]`: a label name,
// one version's fields, supported protocols only (the refused ones are named with their reason),
// and secrets as files (an inline value is an unknown key, so it fails to load).
#[allow(clippy::too_many_lines)] // one flat check of each credential field
fn snmp_credentials(cfg: &Config, r: &mut Report<'_>) {
    use crate::discovery::{CredentialRole, SnmpVersion, valid_label};
    use wrendns_snmp::usm::{AuthProto, PrivProto};
    let d = &cfg.discovery;
    if d.snmp_credentials.len() > crate::discovery::MAX_AGENTS {
        r.err(
            "discovery.snmp_credential",
            format!("at most {} credentials", crate::discovery::MAX_AGENTS),
        );
    }
    let mut seen: Vec<&str> = Vec::new();
    for (i, c) in d.snmp_credentials.iter().enumerate() {
        let p = format!("discovery.snmp_credential[{i}]");
        let name = c.name.as_str();
        if !valid_label(name) {
            r.err(
                format!("{p}.name"),
                "1 to 64 letters, digits, `.`, `_` or `-`, and not an IP address",
            );
        } else if seen.contains(&name) {
            r.err(format!("{p}.name"), format!("`{name}` is listed twice"));
        }
        seen.push(name);
        let blank = |v: &Option<crate::SafeString>| v.as_ref().is_none_or(|s| s.trim().is_empty());
        let files = [
            ("community_file", &c.community_file),
            ("auth_password_file", &c.auth_password_file),
            ("priv_password_file", &c.priv_password_file),
        ];
        for (field, v) in files {
            if let Some(path) = v.as_ref().filter(|s| !s.trim().is_empty()) {
                let dirs: Vec<&std::path::Path> = cfg
                    .node
                    .secret_file_dirs
                    .iter()
                    .map(|d| std::path::Path::new(d.as_str()))
                    .collect();
                let file = std::path::Path::new(path.as_str());
                let inside = file.is_absolute()
                    && !file
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    && dirs.iter().any(|d| file.starts_with(d));
                if !inside {
                    r.warn(format!(
                        "{p}.{field}: `{path}` isn't under [node] secret_file_dirs, so the poller will refuse to read it"
                    ));
                }
            }
        }
        match c.version {
            SnmpVersion::V2c => {
                if blank(&c.community_file) {
                    r.err(
                        format!("{p}.community_file"),
                        "a v2c credential names the file that holds its community",
                    );
                }
                for (field, set) in [
                    ("user", !blank(&c.user)),
                    ("auth_protocol", !blank(&c.auth_protocol)),
                    ("auth_password_file", !blank(&c.auth_password_file)),
                    ("priv_protocol", !blank(&c.priv_protocol)),
                    ("priv_password_file", !blank(&c.priv_password_file)),
                ] {
                    if set {
                        r.err(format!("{p}.{field}"), "only a v3 credential has this");
                    }
                }
                if c.role == CredentialRole::Host {
                    r.warn(format!(
                        "{p}: a v2c host credential sends its community in clear text to every host in the subnet"
                    ));
                } else {
                    r.warn(format!(
                        "{p}: SNMPv2c sends the community in clear text on the LAN; use v3 where the device has it"
                    ));
                }
            }
            SnmpVersion::V3 => {
                if !blank(&c.community_file) {
                    r.err(
                        format!("{p}.community_file"),
                        "only a v2c credential has this",
                    );
                }
                if blank(&c.user) {
                    r.err(format!("{p}.user"), "a v3 credential names its USM user");
                }
                match c.auth_protocol.as_ref().map(crate::SafeString::as_str) {
                    None | Some("") => r.err(
                        format!("{p}.auth_protocol"),
                        "name `sha`, `sha-256`, `sha-384` or `sha-512` (noAuthNoPriv is refused)",
                    ),
                    Some(a) => {
                        if let Err(why) = AuthProto::parse(a) {
                            r.err(format!("{p}.auth_protocol"), why.reason());
                        }
                    }
                }
                if blank(&c.auth_password_file) {
                    r.err(
                        format!("{p}.auth_password_file"),
                        "name the file that holds the authentication password",
                    );
                }
                match c.priv_protocol.as_ref().map(crate::SafeString::as_str) {
                    None | Some("") => {
                        if !blank(&c.priv_password_file) {
                            r.err(
                                format!("{p}.priv_password_file"),
                                "a privacy password needs `priv_protocol = \"aes-128\"`",
                            );
                        }
                    }
                    Some(a) => {
                        if let Err(why) = PrivProto::parse(a) {
                            r.err(format!("{p}.priv_protocol"), why.reason());
                        }
                    }
                }
            }
        }
    }
}

// REQ: DSC-004 (T25.6, ADR-907, ADR-908, ADR-1001) — `[[discovery.snmp_agent]]`: a label that is
// not an address, an RFC 1918 IPv4 literal, a listed infrastructure credential, an interval of 60 s
// or more, and 5 to 25 repetitions.
fn snmp_agents(cfg: &Config, r: &mut Report<'_>) {
    use crate::discovery::{CredentialRole, valid_label};
    let d = &cfg.discovery;
    if d.snmp_agents.len() > crate::discovery::MAX_AGENTS {
        r.err(
            "discovery.snmp_agent",
            format!("at most {} agents", crate::discovery::MAX_AGENTS),
        );
    }
    let mut names: Vec<&str> = Vec::new();
    let mut addrs: Vec<(std::net::Ipv4Addr, u16)> = Vec::new();
    for (i, a) in d.snmp_agents.iter().enumerate() {
        let p = format!("discovery.snmp_agent[{i}]");
        let name = a.name.as_str();
        if !valid_label(name) {
            r.err(
                format!("{p}.name"),
                "1 to 64 letters, digits, `.`, `_` or `-`, and not an IP address (the CLI and the API take a name only)",
            );
        } else if names.contains(&name) {
            r.err(format!("{p}.name"), format!("`{name}` is listed twice"));
        }
        names.push(name);
        match a.address.as_str().parse::<std::net::Ipv4Addr>() {
            Ok(ip) if crate::discovery::is_rfc1918_addr(ip) => {
                if addrs.contains(&(ip, a.port)) {
                    r.warn(format!("{p}.address: `{ip}` is listed twice"));
                }
                addrs.push((ip, a.port));
            }
            Ok(ip) => r.err(
                format!("{p}.address"),
                format!("`{ip}` isn't a private (RFC 1918) address: only 10/8, 172.16/12 and 192.168/16 are polled"),
            ),
            Err(_) => r.err(
                format!("{p}.address"),
                "an IPv4 address as a literal (a host name or an IPv6 address is refused)",
            ),
        }
        if a.port == 0 {
            r.err(format!("{p}.port"), "1 to 65535");
        }
        match d
            .snmp_credentials
            .iter()
            .find(|c| c.name.as_str() == a.credential.as_str())
        {
            None => r.warn(format!(
                "{p}.credential: no `[[discovery.snmp_credential]]` named `{}`, so this agent is skipped",
                a.credential
            )),
            Some(c) if c.role != CredentialRole::Infrastructure => r.err(
                format!("{p}.credential"),
                format!(
                    "`{}` is a host credential: an agent takes an infrastructure credential, so a device on the LAN never receives the gateway's",
                    a.credential
                ),
            ),
            Some(_) => {}
        }
        if !(crate::discovery::AGENT_INTERVAL_MIN_SECS..=crate::discovery::AGENT_INTERVAL_MAX_SECS)
            .contains(&a.interval_secs)
        {
            r.err(format!("{p}.interval_secs"), "from 60 to 86400 seconds");
        }
        if !(crate::discovery::MAX_REPETITIONS_MIN..=crate::discovery::MAX_REPETITIONS_MAX)
            .contains(&a.max_repetitions)
        {
            r.err(format!("{p}.max_repetitions"), "from 5 to 25");
        }
        if a.tables.is_empty() {
            r.err(
                format!("{p}.tables"),
                "name at least one of arp, ifmib, bridge, lldp",
            );
        }
        let distinct: std::collections::HashSet<_> = a.tables.iter().collect();
        if distinct.len() != a.tables.len() {
            r.warn(format!("{p}.tables: a table is listed twice"));
        }
    }
    // A host credential used by no subnet is allowed (T25.7 adds the subnets' side).
}

/// REQ: API-010 (T24.9, ADR-973) — the groups' router names: label form, and one group each.
fn router_names(cfg: &Config, r: &mut Report<'_>) {
    let mut seen = std::collections::HashMap::new();
    for (i, g) in cfg.group.iter().enumerate() {
        check_router_names(g, &format!("group[{i}]"), &mut seen, r);
    }
}

/// REQ: API-010 (T24.9, ADR-973) — a group's router names: label form, and one group each.
fn check_router_names<'a>(
    g: &'a crate::GroupConfig,
    p: &str,
    seen: &mut std::collections::HashMap<String, &'a str>,
    r: &mut Report<'_>,
) {
    // REQ: API-010 (ADR-973) — case doesn't matter, as in a `hostname:` key: `KIDS` is `kids`.
    for (j, n) in g.router_names.iter().enumerate() {
        let label = n.to_ascii_lowercase();
        if !router_label_ok(&label) {
            r.err(
                format!("{p}.router_names[{j}]"),
                format!("`{n}`: use the label form, 1-63 of a-z, 0-9 and - (Kitchen Tablet is kitchen-tablet)"),
            );
        } else if let Some(other) = seen.insert(label, g.name.as_str()) {
            r.err(
                format!("{p}.router_names[{j}]"),
                format!("`{n}` is already a router name of group `{other}`"),
            );
        }
    }
}

// REQ: FLT-005, FLT-006 — groups, clients, identification.
#[allow(clippy::too_many_lines)] // one pass over the groups, one check after another
fn clients(cfg: &Config, r: &mut Report<'_>) {
    let lists: HashSet<&str> = cfg.list.iter().map(|l| l.name.as_str()).collect();
    let mut groups = HashSet::from(["default"]);
    let mut declared = HashSet::new();
    let mut networks: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    for (i, g) in cfg.group.iter().enumerate() {
        let p = format!("group[{i}]");
        if g.name.is_empty() {
            r.err(format!("{p}.name"), "must not be empty");
        } else if !declared.insert(g.name.as_str()) {
            r.err(format!("{p}.name"), format!("duplicate group `{}`", g.name));
        }
        groups.insert(g.name.as_str());
        for (j, l) in g.lists.iter().flatten().enumerate() {
            if crate::categories::is_category_list(l.as_str()) {
                r.err(
                    format!("{p}.lists[{j}]"),
                    format!(
                        "`{l}` is a category list: use `content.categories` (or `content.ads`)"
                    ),
                );
            } else if !lists.contains(l.as_str()) {
                r.err(format!("{p}.lists[{j}]"), format!("unknown list `{l}`"));
            }
        }
        // REQ: FLT-008
        match (g.block_mode, g.block_ips.is_empty()) {
            (crate::BlockMode::CustomIp, true) => {
                r.err(
                    format!("{p}.block_ips"),
                    "required for block_mode = \"custom_ip\"",
                );
            }
            (crate::BlockMode::CustomIp, false) | (_, true) => {}
            (_, false) => r.warn(format!(
                "{p}.block_ips: only used with block_mode = \"custom_ip\""
            )),
        }
        if g.block_ttl > 86_400 {
            r.err(format!("{p}.block_ttl"), "must be at most 86400");
        }
        // REQ: FLT-005 (ADR-050)
        if let Some(c) = &g.color
            && !(c.len() == 7
                && c.starts_with('#')
                && c.as_str()[1..].bytes().all(|b| b.is_ascii_hexdigit()))
        {
            r.err(format!("{p}.color"), "must be a color like #3b82f6");
        }
        for (j, n) in g.networks.iter().enumerate() {
            if let Some(other) = networks.insert(n.to_string(), g.name.as_str()) {
                r.err(
                    format!("{p}.networks[{j}]"),
                    format!("{n} is already a network of group `{other}`"),
                );
            }
        }
    }
    if cfg.group.len() > 63 {
        r.err("group", "at most 63 groups (plus `default`)");
    }
    let mut names = HashSet::new();
    let mut keys: std::collections::HashMap<MatchKey, usize> = std::collections::HashMap::new();
    for (i, c) in cfg.client.iter().enumerate() {
        let p = format!("client[{i}]");
        if c.name.is_empty() {
            r.err(format!("{p}.name"), "must not be empty");
        } else if !names.insert(c.name.to_ascii_lowercase()) {
            r.err(
                format!("{p}.name"),
                format!("duplicate client `{}`", c.name),
            );
        }
        if c.match_keys.is_empty() {
            r.err(
                format!("{p}.match"),
                "needs at least one IP, CIDR, MAC, id:, or hostname:",
            );
        }
        for (j, k) in c.match_keys.iter().enumerate() {
            match MatchKey::parse(k) {
                Err(e) => r.err(format!("{p}.match[{j}]"), e),
                Ok(key) => {
                    if let Some(other) = keys.insert(key, i) {
                        r.err(
                            format!("{p}.match[{j}]"),
                            format!("`{k}` already identifies client[{other}]"),
                        );
                    }
                }
            }
        }
        for (j, g) in c.groups.iter().enumerate() {
            if !groups.contains(g.as_str()) {
                r.err(format!("{p}.groups[{j}]"), format!("unknown group `{g}`"));
            }
        }
    }
    for (i, route) in cfg.route.iter().enumerate() {
        for g in &route.match_group {
            if !groups.contains(g.as_str()) {
                r.warn(format!(
                    "route[{i}].match_group: no group `{g}` is configured"
                ));
            }
        }
    }
    if cfg.clients.neighbor_refresh_secs < 5 {
        r.err("clients.neighbor_refresh_secs", "must be at least 5");
    }
}

/// REQ: DNS-011 (T27.11, ADR-1006) — a negative trust anchor is a domain name. A malformed one would
/// match no name, so the operator would think a domain is exempt when it isn't.
fn dnssec(cfg: &Config, r: &mut Report<'_>) {
    for (i, a) in cfg.dnssec.negative_trust_anchors.iter().enumerate() {
        if !valid_domain_name(a.as_str()) {
            r.err(
                format!("dnssec.negative_trust_anchors[{i}]"),
                "must be a domain name, such as lab.example",
            );
        }
    }
}

/// A DNS name: labels of letters, digits, `-` and `_` (not at a label's edge for `-`), each at most
/// 63 bytes, at most 253 in all, with an optional trailing dot. The root (empty) is not accepted.
fn valid_domain_name(name: &str) -> bool {
    let n = name.strip_suffix('.').unwrap_or(name);
    if n.is_empty() || n.len() > 253 {
        return false;
    }
    n.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

fn cache_and_telemetry(cfg: &Config, r: &mut Report<'_>) {
    let c = &cfg.cache;
    if c.min_ttl > c.max_ttl {
        r.err("cache.min_ttl", "must not exceed cache.max_ttl");
    }
    if c.prefetch && !(1..=99).contains(&c.prefetch_threshold_pct) {
        r.err("cache.prefetch_threshold_pct", "must be between 1 and 99");
    }
    if c.max_bytes.bytes() < 1024 * 1024 {
        r.err("cache.max_bytes", "must be at least 1MiB");
    }

    let rl = &cfg.ratelimit;
    if rl.enabled && (rl.queries == 0 || rl.window_secs == 0) {
        r.err(
            "ratelimit",
            "queries and window_secs must be at least 1 when enabled",
        );
    }
    if rl.ipv4_prefix == 0 || rl.ipv4_prefix > 32 {
        r.err("ratelimit.ipv4_prefix", "must be between 1 and 32");
    }
    if rl.ipv6_prefix == 0 || rl.ipv6_prefix > 128 {
        r.err("ratelimit.ipv6_prefix", "must be between 1 and 128");
    }
    if !(512..=4096).contains(&cfg.dns.edns_payload) {
        r.err(
            "dns.edns_payload",
            "must be between 512 and 4096 (the UDP workers' send buffer is 4096 bytes)",
        );
    }
    if cfg.access.allowed_networks.is_empty() {
        r.err(
            "access.allowed_networks",
            "empty: nobody could query (use [\"0.0.0.0/0\", \"::/0\"] to allow everyone)",
        );
    }
    if cfg.access.allowed_networks.iter().any(|n| n.prefix == 0) {
        r.warn("access.allowed_networks: allows every address; WrenDNS is an open resolver if reachable from the internet");
    }

    if cfg
        .auth
        .oidc
        .allowed_admin_networks
        .as_ref()
        .is_some_and(|v| v.iter().any(|n| n.prefix == 0))
    {
        r.warn("auth.oidc.allowed_admin_networks: allows every address to sign in with a password while disable_local_login is on");
    }

    let t = &cfg.telemetry;
    if !t.ring_slots.is_power_of_two() || t.ring_slots < 1024 {
        r.err(
            "telemetry.ring_slots",
            "must be a power of two and at least 1024",
        );
    }
    if t.qlog.privacy_level > 3 {
        r.err("telemetry.qlog.privacy_level", "must be 0, 1, 2, or 3");
    }
    if t.qlog.retention_days == 0 {
        r.err("telemetry.qlog.retention_days", "must be at least 1");
    }
    if t.ship.interval_secs < 10 {
        r.err("telemetry.ship.interval_secs", "must be at least 10");
    }
    if t.ship.buffer_bytes.bytes() < 1 << 20 {
        r.err("telemetry.ship.buffer_bytes", "must be at least 1 MiB");
    }
    if t.qlog.flush_interval_secs == 0 {
        r.err("telemetry.qlog.flush_interval_secs", "must be at least 1");
    }
    // REQ: OBS-003 (T27.5) — the same upper bounds the settings form shows (tuning.ts), so a
    // direct API write meets them too.
    if t.qlog.retention_days > 3650 {
        r.err("telemetry.qlog.retention_days", "at most 3650 days");
    }
    if t.qlog.flush_interval_secs > 3600 {
        r.err("telemetry.qlog.flush_interval_secs", "at most 3600 seconds");
    }
    // REQ: OBS-013 (T27.5) — the anomaly settings and the per-client series' cap are bounded like
    // the form's fields (tuning.ts): a zero or a huge value is refused, not stored.
    let a = &t.anomaly;
    if !(1..=90).contains(&a.learning_days) {
        r.err("telemetry.anomaly.learning_days", "from 1 to 90 days");
    }
    if !(1..=100_000).contains(&a.max_clients) {
        r.err("telemetry.anomaly.max_clients", "from 1 to 100000 devices");
    }
    if !(1..=100_000).contains(&a.nxdomain_per_minute) {
        r.err(
            "telemetry.anomaly.nxdomain_per_minute",
            "from 1 to 100000 answers a minute",
        );
    }
    if !(1..=100).contains(&a.nxdomain_percent) {
        r.err(
            "telemetry.anomaly.nxdomain_percent",
            "from 1 to 100 percent",
        );
    }
    if !(1..=10_000).contains(&t.metrics.per_client_cap) {
        r.err(
            "telemetry.metrics.per_client_cap",
            "from 1 to 10000 devices",
        );
    }
}

/// REQ: OPS-014 (ADR-903 §2) — references to stored secrets: at most one of a credential's inline
/// value, `_file` and `_ref`; the names a secret may have; a header in `headers` or `header_refs`,
/// not both. And (REQ: API-014) no credential in the files reads `<redacted>`: that is what a
/// redacted copy shows (`config check --print`, the TOML to keep in Git), never a value.
fn secret_references(cfg: &Config, r: &mut Report<'_>) {
    use crate::credentials::MARKER;
    use crate::secret_refs::{fields_of, valid_name};
    const NAME: &str = "a stored secret's name: lowercase letters, digits, `.`, `_` or `-`, starting with a letter or digit, at most 63";
    fn set(v: &serde_json::Value, k: &str) -> bool {
        match v.get(k) {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::String(s)) => !s.is_empty(),
            Some(_) => true,
        }
    }
    fn each<T: serde::Serialize>(list: &[T]) -> Vec<serde_json::Value> {
        list.iter()
            .filter_map(|x| serde_json::to_value(x).ok())
            .collect()
    }
    let mut check = |kind: &str, at: &str, v: &serde_json::Value| {
        for f in fields_of(kind) {
            let keys: Vec<&str> = f.inline.into_iter().chain([f.file, f.reference]).collect();
            if keys.iter().filter(|k| set(v, k)).count() > 1 {
                r.err(
                    format!("{at}.{}", f.reference),
                    format!("set one of {}, not more", keys.join(", ")),
                );
            }
            if let Some(n) = v.get(f.reference).and_then(serde_json::Value::as_str)
                && !valid_name(n)
            {
                r.err(format!("{at}.{}", f.reference), NAME);
            }
        }
    };
    for (i, v) in each(&cfg.router).iter().enumerate() {
        check("router", &format!("router[{i}]"), v);
    }
    for (i, v) in each(&cfg.alerts.destination).iter().enumerate() {
        check("alert_destination", &format!("alerts.destination[{i}]"), v);
    }
    for (i, v) in each(&cfg.auth.oidc.provider).iter().enumerate() {
        check("oidc_provider", &format!("auth.oidc.provider[{i}]"), v);
    }
    for (i, v) in each(&cfg.telemetry.sink).iter().enumerate() {
        check("sink", &format!("telemetry.sink[{i}]"), v);
    }
    if let Some(g) = &cfg.cluster.git
        && let Ok(v) = serde_json::to_value(g)
    {
        check("git", "cluster.git", &v);
    }
    let o = &cfg.telemetry.otlp;
    for (h, n) in &o.header_refs {
        if o.headers.contains_key(h) {
            r.err(
                format!("telemetry.otlp.header_refs.{h}"),
                "the header is in `headers` too: set it in one of them",
            );
        }
        if !valid_name(n) {
            r.err(format!("telemetry.otlp.header_refs.{h}"), NAME);
        }
    }
    // Every credential path (`credentials::PATHS`): values, headers, arguments and URL passwords.
    if let Ok(v) = serde_json::to_value(cfg) {
        for p in crate::credentials::marker_paths(&v) {
            r.err(
                p,
                format!(
                    "`{MARKER}` is what a redacted copy shows, not a value: set the credential itself"
                ),
            );
        }
    }
}

// REQ: OBS-901 (T26.2, ADR-958 section 4) — the map's bounds: a rate a Pi can keep up with, and
// thresholds that are percentages in an order that means something.
fn map(cfg: &Config, r: &mut Report<'_>) {
    let m = &cfg.map;
    if !(10..=2000).contains(&m.event_rate) {
        r.err("map.event_rate", "from 10 to 2000 lookups per second");
    }
    if !(1..=1000).contains(&m.min_sample) {
        r.err("map.min_sample", "from 1 to 1000 answers");
    }
    if let Some(ms) = m.warn_latency_ms
        && !(1..=60_000).contains(&ms)
    {
        r.err("map.warn_latency_ms", "from 1 to 60000 milliseconds");
    }
    for (name, v) in [
        ("warn_slow_pct", m.warn_slow_pct),
        ("warn_error_pct", m.warn_error_pct),
        ("error_pct", m.error_pct),
        ("warn_blocked_pct", m.warn_blocked_pct),
    ] {
        if !(1..=100).contains(&v) {
            r.err(format!("map.{name}"), "a percent from 1 to 100");
        }
    }
    if m.error_pct < m.warn_error_pct {
        r.err(
            "map.error_pct",
            "at least warn_error_pct (red can't come before yellow)",
        );
    }
    map_geoip(&m.geoip, r);
}

// REQ: OBS-902 (T26.4, ADR-959) - the GeoIP source is HTTPS, a pin is a SHA-256, and the home
// country is a two-letter code.
fn map_geoip(g: &crate::MapGeoipConfig, r: &mut Report<'_>) {
    if let Some(u) = &g.source_url {
        let u = u.as_str();
        let host_ok = u
            .strip_prefix("https://")
            .and_then(|rest| rest.split(['/', '?', '#']).next())
            .is_some_and(|h| !h.is_empty() && !h.contains('@'));
        // The URL is shown to every role: a query string or fragment could carry a token.
        if !host_ok || u.contains('?') || u.contains('#') {
            r.err(
                "map.geoip.source_url",
                "an https:// URL with a host, no credentials and no query string",
            );
        }
    }
    if let Some(d) = &g.sha256
        && !(d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        r.err("map.geoip.sha256", "64 hexadecimal digits (a SHA-256)");
    }
    if let Some(c) = &g.home_country
        && !(c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
    {
        r.err(
            "map.geoip.home_country",
            "a two-letter country code such as NL",
        );
    }
}

/// REQ: API-003 (T24.44) - two listen addresses clash when they share a port and either the
/// addresses are equal or one is the unspecified address (0.0.0.0 or [::], which covers the
/// other).
#[must_use]
pub fn addrs_clash(a: std::net::SocketAddr, b: std::net::SocketAddr) -> bool {
    a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::{valid_domain_name, valid_pem_certificate};

    /// REQ: DNS-011 (T27.11) — negative trust anchors are domain names: a trailing dot is fine, a
    /// label that starts or ends with `-`, an empty label, the root, and spaces are not.
    #[test]
    fn dns_011_trust_anchor_must_be_a_domain_name() {
        assert!(valid_domain_name("lab.example"));
        assert!(valid_domain_name("lab.example."));
        assert!(valid_domain_name("my_host.internal"));
        assert!(!valid_domain_name(""));
        assert!(!valid_domain_name("."));
        assert!(!valid_domain_name("lab..example"));
        assert!(!valid_domain_name("-lab.example"));
        assert!(!valid_domain_name("lab-.example"));
        assert!(!valid_domain_name("lab example"));
        assert!(!valid_domain_name(&format!("{}.example", "a".repeat(64))));
    }

    /// REQ: API-016 (review of T23.7, ADR-921) — a router's certificate must be PEM that decodes to
    /// at least one certificate: the BEGIN marker alone, or a body that isn't base64, is refused.
    #[test]
    fn api_016_pem_check_needs_a_certificate() {
        // The base64 of a small DER sequence: the PEM decodes, whatever the certificate inside.
        assert!(valid_pem_certificate(
            "-----BEGIN CERTIFICATE-----\nMAMCAQU=\n-----END CERTIFICATE-----\n"
        ));
        assert!(!valid_pem_certificate("MIIBfake"));
        assert!(!valid_pem_certificate(
            "-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----\n"
        ));
        assert!(!valid_pem_certificate(
            "-----BEGIN CERTIFICATE-----\nMAMCAQU=\n"
        ));
        assert!(!valid_pem_certificate(""));
    }
}
