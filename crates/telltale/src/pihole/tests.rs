use super::*;

// Shapes as Pi-hole exports them (v5.18 Teleporter JSON, v6.7 gravity.db and pihole.toml),
// written by hand for these tests.
const GROUPS: &str = r#"[{"id":0,"enabled":1,"name":"Default","description":"The default group"},
 {"id":1,"enabled":1,"name":"Kids","description":"children's devices"},
 {"id":2,"enabled":0,"name":"IoT","description":"switched off"}]"#;
const ADLISTS: &str = r#"[{"id":1,"address":"https:\/\/raw.githubusercontent.com\/StevenBlack\/hosts\/master\/hosts","enabled":1,"comment":"Migrated from \/etc\/pihole\/adlists.list"},
 {"id":2,"address":"https://lists.example/kids.txt","enabled":1,"comment":"kids list"},
 {"id":3,"address":"https://lists.example/off.txt","enabled":0,"comment":"disabled list"},
 {"id":4,"address":"https://lists.example/nobody.txt","enabled":1,"comment":""}]"#;
const ADLIST_GROUPS: &str =
    r#"[{"adlist_id":1,"group_id":0},{"adlist_id":3,"group_id":0},{"adlist_id":2,"group_id":1}]"#;
const CLIENTS: &str = r#"[{"id":1,"ip":"192.168.1.50","comment":"Kids tablet"},
 {"id":2,"ip":"10.0.5.0\/24","comment":"guest net"},
 {"id":3,"ip":"AA:BB:CC:DD:EE:02","comment":"TV"},
 {"id":4,"ip":"laptop.lan","comment":"by name"},
 {"id":5,"ip":":eth1","comment":"by interface"},
 {"id":6,"ip":"192.168.1.60","comment":""}]"#;
const CLIENT_GROUPS: &str = r#"[{"client_id":2,"group_id":0},{"client_id":3,"group_id":0},
 {"client_id":4,"group_id":0},{"client_id":5,"group_id":0},{"client_id":1,"group_id":1},{"client_id":1,"group_id":0}]"#;
const DOMAIN_GROUPS: &str = r#"[{"domainlist_id":1,"group_id":0},{"domainlist_id":2,"group_id":0},
 {"domainlist_id":3,"group_id":0},{"domainlist_id":4,"group_id":0},{"domainlist_id":5,"group_id":0},
 {"domainlist_id":6,"group_id":1},{"domainlist_id":7,"group_id":0}]"#;

fn v5_entries() -> archive::Entries {
    let mut e = archive::Entries::new();
    let mut put = |k: &str, v: &str| {
        e.insert(k.to_owned(), v.as_bytes().to_vec());
    };
    put("group.json", GROUPS);
    put("adlist.json", ADLISTS);
    put("adlist_by_group.json", ADLIST_GROUPS);
    put("client.json", CLIENTS);
    put("client_by_group.json", CLIENT_GROUPS);
    put("domainlist_by_group.json", DOMAIN_GROUPS);
    put(
        "whitelist.exact.json",
        r#"[{"id":1,"type":0,"domain":"allowed.example","enabled":1}]"#,
    );
    put(
        "blacklist.exact.json",
        r#"[{"id":2,"type":1,"domain":"denied.example","enabled":1},
            {"id":5,"type":1,"domain":"disabled.example","enabled":0},
            {"id":6,"type":1,"domain":"kidsonly.example","enabled":1}]"#,
    );
    put(
        "whitelist.regex.json",
        r#"[{"id":3,"type":2,"domain":"(^|\\.)good\\.example$","enabled":1}]"#,
    );
    // Without "type": inferred from the file. 7 has no regex metacharacters.
    put(
        "blacklist.regex.json",
        r#"[{"id":4,"domain":"^ad[0-9]+\\.example$;querytype=A","enabled":1},
            {"id":7,"domain":"tracker","enabled":1}]"#,
    );
    put(
        "setupVars.conf",
        "PIHOLE_INTERFACE=eth0\nWEBPASSWORD=0123abcd\nDNS_BOGUS_PRIV=true\nPIHOLE_DNS_2=127.0.0.1#5335\nPIHOLE_DNS_1=9.9.9.9\nPIHOLE_DNS_3=2620:fe::fe\nREV_SERVER=true\nREV_SERVER_CIDR=192.168.1.0/24\nREV_SERVER_TARGET=192.168.1.1\nREV_SERVER_DOMAIN=lan\nDNSSEC=true\nDHCP_ACTIVE=true\n",
    );
    put(
        "pihole-FTL.conf",
        "#; comment\nPRIVACYLEVEL=0\nRATE_LIMIT=500/60\nBLOCKINGMODE=NXDOMAIN\nPRIVACYLEVEL=1\n",
    );
    put(
        "custom.list",
        "192.168.1.10 nas.lan\nfd00::10 nas.lan\n192.168.1.10 nas.lan\n",
    );
    put(
        "05-pihole-custom-cname.conf",
        "cname=media.lan,nas.lan\ncname=tv.lan,box.lan,nas.lan,300\n",
    );
    put(
        "04-pihole-static-dhcp.conf",
        "dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.50,kids-tablet\ndhcp-host=aa:bb:cc:dd:ee:09,192.168.1.90,printer,infinite\n",
    );
    e
}

fn strs(v: &[telltale_config::SafeString]) -> Vec<&str> {
    v.iter().map(telltale_config::SafeString::as_str).collect()
}

fn load(toml: &str) -> telltale_config::Config {
    match telltale_config::Loader::new()
        .toml_str("import", toml)
        .load()
    {
        Ok(l) => l.config,
        Err(e) => panic!("{e:?}\n{toml}"),
    }
}

// REQ: UPS-006 (fork #25) — the preview notes an IPv6 upstream, with the hint to drop it when the
// hosts have no IPv6, and says nothing of the IPv4 ones.
#[test]
fn ups_006_pihole_import_notes_ipv6_upstreams() {
    let src = Source::from_entries(v5_entries()).unwrap();
    let im = convert(&src, "teleporter.tar.gz").unwrap();
    let v6: Vec<&String> = im.notes.iter().filter(|n| n.contains("IPv6")).collect();
    assert_eq!(v6.len(), 1, "{:?}", im.notes);
    assert!(v6[0].contains("2620:fe::fe") && v6[0].contains("no IPv6 route"));
    assert!(v6[0].contains("pihole-3"), "{}", v6[0]);
}

// REQ: API-007 — a v5 Teleporter archive becomes a configuration that loads, with groups,
// clients, lists, records, upstreams, and conditional forwarding carried over.
#[test]
#[allow(clippy::too_many_lines)] // one archive, checked section by section
fn api_007_pihole_v5_teleporter() {
    let src = Source::from_entries(v5_entries()).unwrap();
    let im = convert(&src, "teleporter.tar.gz").unwrap();
    assert_eq!(im.version, "v5");
    let cfg = load(&im.toml);

    let ups: Vec<(&str, &str)> = cfg
        .upstream
        .iter()
        .map(|u| (u.name.as_str(), u.url.as_str()))
        .collect();
    assert_eq!(
        ups,
        [
            ("pihole-1", "udp://9.9.9.9:53"),
            ("pihole-2", "udp://127.0.0.1:5335"),
            ("pihole-3", "udp://[2620:fe::fe]:53"),
            ("pihole-forward-1", "udp://192.168.1.1:53"),
        ]
    );
    let route = &cfg.route[0];
    assert_eq!(strs(&route.match_suffix), ["lan", "1.168.192.in-addr.arpa"]);
    assert!(route.dnssec_nta);
    assert_eq!(cfg.dnssec.mode, telltale_config::DnssecMode::Validate);
    assert_eq!(
        (cfg.ratelimit.queries, cfg.ratelimit.window_secs),
        (500, 60)
    );

    let recs: Vec<(&str, &str, &str, Option<u32>)> = cfg
        .record
        .iter()
        .map(|r| (r.name.as_str(), r.rtype.as_str(), r.value.as_str(), r.ttl))
        .collect();
    assert_eq!(
        recs,
        [
            ("nas.lan", "A", "192.168.1.10", None),
            ("nas.lan", "AAAA", "fd00::10", None),
            ("media.lan", "CNAME", "nas.lan", None),
            ("tv.lan", "CNAME", "nas.lan", Some(300)),
            ("box.lan", "CNAME", "nas.lan", Some(300)),
        ]
    );

    let list = |n: &str| cfg.list.iter().find(|l| l.name.as_str() == n).unwrap();
    assert_eq!(
        list("pihole-1-hosts").url.as_deref(),
        Some("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
    );
    assert!(!list("pihole-3-off").enabled);
    assert!(
        !cfg.list
            .iter()
            .any(|l| l.name.as_str().starts_with("pihole-4")),
        "unused adlist"
    );
    let allow = list("pihole-allow-exact");
    assert_eq!(
        (allow.kind, allow.match_mode),
        (ListKind::Allow, ListMatch::Exact)
    );
    let deny = list("pihole-deny-regex");
    assert_eq!(
        strs(&deny.rules),
        ["^ad[0-9]+\\.example$;querytype=A", "/tracker/"]
    );
    assert_eq!(strs(&list("pihole-deny-exact").rules), ["denied.example"]);
    assert_eq!(
        strs(&list("pihole-deny-exact-2").rules),
        ["kidsonly.example"]
    );

    let group = |n: &str| cfg.group.iter().find(|g| g.name.as_str() == n).unwrap();
    let names = |g: &telltale_config::GroupConfig| -> Vec<String> {
        g.lists.iter().flatten().map(ToString::to_string).collect()
    };
    assert_eq!(
        names(group("default")),
        [
            "pihole-1-hosts",
            "pihole-3-off",
            "pihole-allow-exact",
            "pihole-deny-exact",
            "pihole-allow-regex",
            "pihole-deny-regex"
        ]
    );
    assert_eq!(
        names(group("Kids")),
        ["pihole-2-kids", "pihole-deny-exact-2"]
    );
    assert_eq!(
        names(group("IoT")),
        Vec::<String>::new(),
        "switched-off group"
    );
    assert_eq!(
        group("Kids").block_mode,
        telltale_config::BlockMode::Nxdomain
    );
    assert_eq!(names(group("pihole-no-group")), Vec::<String>::new());

    let client = |n: &str| cfg.client.iter().find(|c| c.name.as_str() == n).unwrap();
    let kids = client("Kids tablet");
    // The DHCP reservation added the tablet's MAC.
    assert_eq!(
        strs(&kids.match_keys),
        ["192.168.1.50", "aa:bb:cc:dd:ee:01"]
    );
    assert_eq!(strs(&kids.groups), ["default", "Kids"]);
    assert!(client("TV").groups.is_empty(), "default only");
    assert_eq!(strs(&client("TV").match_keys), ["aa:bb:cc:dd:ee:02"]);
    assert_eq!(strs(&client("192.168.1.60").groups), ["pihole-no-group"]);
    assert_eq!(
        strs(&client("printer").match_keys),
        ["aa:bb:cc:dd:ee:09", "192.168.1.90"]
    );
    assert_eq!(
        cfg.client.len(),
        5,
        "host-name and interface clients aren't importable"
    );

    let notes = im.notes.join("\n");
    for want in [
        "laptop.lan",
        ":eth1",
        "127.0.0.1#5335",
        "DHCP server",
        "IoT",
        "DNS_BOGUS_PRIV",
        "PRIVACYLEVEL",
        "WEBPASSWORD",
    ] {
        assert!(notes.contains(want), "missing {want} in:\n{notes}");
    }
    // Secrets never appear, only setting names.
    assert!(!im.toml.contains("0123abcd"));
    let (_, report) = telltale_policy::LocalData::from_config(&cfg);
    assert_eq!(report.errors, Vec::<String>::new());
}

// REQ: API-007 — v6: settings from pihole.toml, groups from the archived gravity.db.
#[test]
#[allow(clippy::too_many_lines)] // one archive, checked section by section
fn api_007_pihole_v6_teleporter() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("gravity.db");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(
        r#"CREATE TABLE "group"(id INT, enabled NUM, name TEXT, date_added INT, date_modified INT, description TEXT);
CREATE TABLE adlist(id INT, address TEXT, enabled NUM, date_added INT, date_modified INT, comment TEXT, date_updated INT, number INT, invalid_domains INT, status INT, abp_entries INT, type INT);
CREATE TABLE adlist_by_group(adlist_id INT, group_id INT);
CREATE TABLE domainlist(id INT, type INT, domain TEXT, enabled NUM, date_added INT, date_modified INT, comment TEXT);
CREATE TABLE domainlist_by_group(domainlist_id INT, group_id INT);
CREATE TABLE client(id INT, ip TEXT, date_added INT, date_modified INT, comment TEXT);
CREATE TABLE client_by_group(client_id INT, group_id INT);
INSERT INTO "group" VALUES (0,1,'Default',0,0,'The default group'),(1,1,'Kids',0,0,'');
INSERT INTO adlist VALUES (1,'https://lists.example/hosts',1,0,0,'',0,0,0,0,0,0),(2,'https://lists.example/allow.txt',1,0,0,'',0,0,0,0,0,1),(3,'file:///etc/pihole/local.txt',1,0,0,'',0,0,0,0,0,0);
INSERT INTO adlist_by_group VALUES (1,0),(2,0),(3,1);
INSERT INTO domainlist VALUES (1,1,'denied.example',1,0,0,''),(2,3,'(^|\.)bad\.example$',1,0,0,''),(3,3,'(?<=x)lookbehind',1,0,0,'');
INSERT INTO domainlist_by_group VALUES (1,0),(1,1),(2,1),(3,0);
INSERT INTO client VALUES (1,'192.168.1.50',0,0,'Tablet');
INSERT INTO client_by_group VALUES (1,1);"#,
    )
    .unwrap();
    drop(c);
    let toml = r#"[dns]
  upstreams = [
    "1.1.1.1",
    "[2606:4700::1111]#53"
  ] ### CHANGED, default = []
  hosts = [ "192.168.1.10 nas.lan nas" ] ### CHANGED, default = []
  cnameRecords = [ "media.lan,nas.lan" ] ### CHANGED, default = []
  revServers = [ "true,192.168.0.0/23,192.168.0.1#5353,", "false,10.9.0.0/16,10.9.0.1,old" ] ### CHANGED, default = []
  dnssec = true ### CHANGED, default = false
  bogusPriv = true

  [dns.blocking]
    mode = "NULL"

  [dns.rateLimit]
    count = 0 ### CHANGED, default = 1000
    interval = 60

[dhcp]
  active = true ### CHANGED, default = false
  hosts = [ "aa:bb:cc:dd:ee:01,192.168.1.50,tablet" ] ### CHANGED, default = []

[webserver.api]
  pwhash = "$BALLOON-SHA256$secret" ### CHANGED, default = ""

[misc]
  privacylevel = 1 ### CHANGED, default = 0
"#;
    let mut entries = archive::Entries::new();
    entries.insert("etc/pihole/pihole.toml".into(), toml.as_bytes().to_vec());
    entries.insert("etc/pihole/gravity.db".into(), std::fs::read(&db).unwrap());
    let src = Source::from_entries(entries).unwrap();
    let im = convert(&src, "teleporter.zip").unwrap();
    assert_eq!(im.version, "v6");
    let cfg = load(&im.toml);

    assert_eq!(cfg.upstream[1].url.as_str(), "udp://[2606:4700::1111]:53");
    assert_eq!(cfg.upstream[2].url.as_str(), "udp://192.168.0.1:5353");
    assert_eq!(
        strs(&cfg.route[0].match_suffix),
        ["0.168.192.in-addr.arpa", "1.168.192.in-addr.arpa"],
        "a /23 is two reverse zones; no domain given"
    );
    assert_eq!(
        cfg.route.len(),
        1,
        "the switched-off forward isn't imported"
    );
    assert!(!cfg.ratelimit.enabled);
    assert_eq!(cfg.dnssec.mode, telltale_config::DnssecMode::Validate);
    assert_eq!(cfg.record.len(), 3, "nas.lan, nas, media.lan");

    let list = |n: &str| cfg.list.iter().find(|l| l.name.as_str() == n).unwrap();
    assert_eq!(
        list("pihole-2-allow").kind,
        ListKind::Allow,
        "a v6 allowlist"
    );
    assert_eq!(
        list("pihole-3-local").path.as_deref(),
        Some("/etc/pihole/local.txt")
    );
    // One entry in two groups is one list both groups use.
    let kids = cfg
        .group
        .iter()
        .find(|g| g.name.as_str() == "Kids")
        .unwrap();
    assert_eq!(
        kids.lists
            .as_ref()
            .unwrap()
            .iter()
            .map(telltale_config::SafeString::as_str)
            .collect::<Vec<_>>(),
        ["pihole-3-local", "pihole-deny-exact", "pihole-deny-regex"]
    );
    let tablet = &cfg.client[0];
    assert_eq!(
        strs(&tablet.match_keys),
        ["192.168.1.50", "aa:bb:cc:dd:ee:01"]
    );
    assert_eq!(strs(&tablet.groups), ["Kids"]);

    let notes = im.notes.join("\n");
    for want in [
        "webserver.api.pwhash",
        "misc.privacylevel",
        "lookbehind",
        "10.9.0.0/16",
        "DHCP server",
    ] {
        assert!(notes.contains(want), "missing {want} in:\n{notes}");
    }
    assert!(
        !notes.contains("bogusPriv"),
        "unchanged settings aren't listed"
    );
    assert!(
        !im.toml.contains("BALLOON"),
        "values of unmapped settings never appear"
    );
}

/// REQ: DNS-019, API-007 (ADR-904) — Pi-hole's domain-needed, iCloud Private Relay, and
/// Firefox canary settings carry over (v6 `pihole.toml`, v5 `setupVars.conf` and
/// `pihole-FTL.conf`); left at Pi-hole's defaults, no `[special]` section is written.
#[test]
fn dns_019_pihole_special_names() {
    let v6 = |toml: &str| {
        let mut e = archive::Entries::new();
        e.insert("etc/pihole/pihole.toml".into(), toml.as_bytes().to_vec());
        convert(&Source::from_entries(e).unwrap(), "pihole.toml").unwrap()
    };
    let im = v6(r#"[dns]
  upstreams = [ "9.9.9.9" ] ### CHANGED, default = []
  domainNeeded = true ### CHANGED, default = false

  [dns.specialDomains]
    mozillaCanary = true
    iCloudPrivateRelay = false ### CHANGED, default = true
    designatedResolver = true
"#);
    let cfg = load(&im.toml);
    assert!(cfg.special.single_label_nxdomain);
    assert!(!cfg.special.block_icloud_private_relay);
    assert!(cfg.special.block_firefox_canary);
    let notes = im.notes.join("\n");
    for mapped in ["domainNeeded", "iCloudPrivateRelay"] {
        assert!(!notes.contains(mapped), "{mapped} is imported:\n{notes}");
    }

    let im = v6(
        "[dns]\n  upstreams = [ \"9.9.9.9\" ] ### CHANGED, default = []\n  domainNeeded = false\n",
    );
    assert!(!im.toml.contains("[special]"), "defaults: nothing to write");
    assert_eq!(
        load(&im.toml).special,
        telltale_config::SpecialConfig::default()
    );

    let v5 = |setup: &str, ftl: &str| {
        let mut e = archive::Entries::new();
        e.insert("setupVars.conf".into(), setup.as_bytes().to_vec());
        e.insert("pihole-FTL.conf".into(), ftl.as_bytes().to_vec());
        convert(&Source::from_entries(e).unwrap(), "teleporter.tar.gz").unwrap()
    };
    let im = v5(
        "PIHOLE_DNS_1=9.9.9.9\nDNS_FQDN_REQUIRED=true\n",
        "BLOCK_ICLOUD_PR=false\nMOZILLA_CANARY=false\n",
    );
    let cfg = load(&im.toml);
    assert!(cfg.special.single_label_nxdomain);
    assert!(!cfg.special.block_icloud_private_relay);
    assert!(!cfg.special.block_firefox_canary);
    let notes = im.notes.join("\n");
    for mapped in ["DNS_FQDN_REQUIRED", "BLOCK_ICLOUD_PR", "MOZILLA_CANARY"] {
        assert!(!notes.contains(mapped), "{mapped} is imported:\n{notes}");
    }
    let im = v5(
        "PIHOLE_DNS_1=9.9.9.9\nDNS_FQDN_REQUIRED=false\n",
        "BLOCK_ICLOUD_PR=true\n",
    );
    assert!(!im.toml.contains("[special]"));
    // These default to on: anything but an explicit `false` keeps the block.
    let im = v5(
        "PIHOLE_DNS_1=9.9.9.9\n",
        "BLOCK_ICLOUD_PR=yes\nMOZILLA_CANARY=FALSE \n",
    );
    let cfg = load(&im.toml);
    assert!(cfg.special.block_icloud_private_relay);
    assert!(!cfg.special.block_firefox_canary);
}

#[test]
fn api_007_reverse_zones() {
    assert_eq!(reverse_zones("10.0.0.0/8").unwrap(), ["10.in-addr.arpa"]);
    assert_eq!(
        reverse_zones("192.168.1.77/24").unwrap(),
        ["1.168.192.in-addr.arpa"]
    );
    assert_eq!(reverse_zones("172.16.0.0/12").unwrap().len(), 16);
    assert_eq!(
        reverse_zones("172.16.0.0/12").unwrap()[15],
        "31.172.in-addr.arpa"
    );
    assert_eq!(
        reverse_zones("fd00:1::/32").unwrap(),
        ["1.0.0.0.0.0.d.f.ip6.arpa"]
    );
    assert_eq!(reverse_zones("fd00::/63").unwrap().len(), 2);
    assert!(reverse_zones("10.0.0.0/4").is_err());
    assert!(reverse_zones("nope").is_err());
}

#[test]
fn api_007_not_a_pihole() {
    assert!(convert(&Source::default(), "x").is_err());
    assert!(
        Source::from_entries(archive::Entries::from([(
            "etc/pihole/gravity.db".into(),
            b"junk".to_vec()
        )]))
        .is_err()
    );
}

// REQ: API-007 (T24.6) — dnsmasq.d lines: `address=` answers and blocks, `server=/domain/`
// forwards, `host-record=` and `cname=` records; the rest is named in the report.
#[test]
fn api_007_pihole_dnsmasq_lines() {
    let mut e = v5_entries();
    e.insert(
        "etc/dnsmasq.d/99-custom.conf".into(),
        b"# a comment\naddress=/tv.lan/192.168.1.40\naddress=/ads.example/0.0.0.0\naddress=/v6.lan/fd00::40\nserver=/corp.example/10.9.0.53#5353\nserver=/bare.example/\nserver=192.168.1.1\nhost-record=printer.lan,192.168.1.70,fd00::70\ncname=alias.lan,nas.lan\ndomain-needed\nforeign-directive=1\n".to_vec(),
    );
    let src = Source::from_entries(e).unwrap();
    let im = convert(&src, "teleporter.tar.gz").unwrap();
    let cfg = load(&im.toml);

    let recs: Vec<(&str, &str, &str)> = cfg
        .record
        .iter()
        .map(|r| (r.name.as_str(), r.rtype.as_str(), r.value.as_str()))
        .collect();
    for want in [
        ("tv.lan", "A", "192.168.1.40"),
        ("v6.lan", "AAAA", "fd00::40"),
        ("printer.lan", "A", "192.168.1.70"),
        ("printer.lan", "AAAA", "fd00::70"),
        ("alias.lan", "CNAME", "nas.lan"),
    ] {
        assert!(recs.contains(&want), "{want:?} missing from {recs:?}");
    }

    let route = cfg
        .route
        .iter()
        .find(|r| strs(&r.match_suffix).contains(&"corp.example"))
        .expect("the dnsmasq server= forward");
    let group = cfg
        .upstream_group
        .iter()
        .find(|g| g.name.as_str() == route.upstream_group.as_str())
        .unwrap();
    let up = cfg
        .upstream
        .iter()
        .find(|u| group.members.iter().any(|m| m.as_str() == u.name.as_str()))
        .unwrap();
    assert_eq!(up.url.as_str(), "udp://10.9.0.53:5353");

    // The blocking address= line is a deny list in the default group, which also covers
    // every group Pi-hole had.
    let block = cfg
        .list
        .iter()
        .find(|l| l.name.as_str() == "pihole-dnsmasq-address")
        .expect("the address= block list");
    assert_eq!(strs(&block.rules), ["ads.example"]);
    let default = cfg
        .group
        .iter()
        .find(|g| g.name.as_str() == "default")
        .unwrap();
    let lists = default.lists.clone().unwrap_or_default();
    assert!(
        strs(&lists).contains(&"pihole-dnsmasq-address"),
        "{default:?}"
    );

    assert!(im.samples.iter().any(|s| s == "tv.lan"), "{:?}", im.samples);
    let notes = im.notes.join("\n");
    assert!(notes.contains("server=/bare.example/"), "{notes}");
    assert!(notes.contains("subdomains"), "{notes}");
    assert!(notes.contains("foreign-directive"), "{notes}");
    assert!(!notes.contains("domain-needed"), "{notes}");
}

// REQ: API-007 (T24.6) — a domain named by a v5 reverse server and by a dnsmasq `server=/domain/`
// is routed once: the first route keeps it, and the conflict is noted.
#[test]
fn api_007_pihole_forward_named_twice_is_routed_once() {
    let mut e = v5_entries();
    e.insert(
        "setupVars.conf".into(),
        b"PIHOLE_DNS_1=192.168.1.1\nREV_SERVER=true\nREV_SERVER_CIDR=192.168.1.0/24\nREV_SERVER_TARGET=192.168.1.1\nREV_SERVER_DOMAIN=lan\n".to_vec(),
    );
    e.insert(
        "etc/dnsmasq.d/01-pihole.conf".into(),
        b"server=/lan/192.168.1.1\n".to_vec(),
    );
    let src = Source::from_entries(e).unwrap();
    let im = convert(&src, "teleporter.tar.gz").unwrap();
    let cfg = load(&im.toml);
    let routed = cfg
        .route
        .iter()
        .filter(|r| r.match_suffix.iter().any(|s| s.as_str() == "lan"))
        .count();
    assert_eq!(routed, 1, "{}", im.toml);
    assert!(
        im.notes.join("\n").contains("named twice"),
        "{:?}",
        im.notes
    );
}

// REQ: API-007 (T24.6) — a broken `pihole.toml` is reported by line and message, never with the
// line's text, which can be a password hash or a TOTP secret.
#[test]
fn api_007_pihole_toml_error_hides_the_line() {
    let err = v6_settings("pwhash = \"secret-hash-xyz\"\n[dns\n")
        .err()
        .unwrap_or_default();
    assert!(!err.contains("secret-hash-xyz"), "{err}");
    assert!(err.contains("pihole.toml"), "{err}");
}
