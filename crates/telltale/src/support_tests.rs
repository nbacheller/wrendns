// REQ: OPS-011 (ADR-156) — the whole package, through a real backend over test sources: the files
// each level has, a planted secret and a planted name gone from every file, a dry run with no
// archive, the map held for one download, and one package at a time.

use super::*;
use telltale_support::archive::read_tar_gz;

/// Packages share the process's log and its busy flag: one test at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn backend(toml: &str) -> ApiBackend {
    let src = crate::http::tests::sources();
    let cfg = telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    src.config.store(Arc::new(cfg));
    ApiBackend { src: Arc::new(src) }
}

fn req(level: &str, sample: u32, keep_map: bool) -> SupportPackageRequest {
    SupportPackageRequest {
        level: Some(level.to_owned()),
        reveal: Vec::new(),
        query_sample: sample,
        keep_map,
    }
}

fn paths(out: &SupportPackageOutput) -> Vec<String> {
    read_tar_gz(&out.archive)
        .unwrap()
        .into_iter()
        .map(|e| e.path)
        .collect()
}

fn everything(out: &SupportPackageOutput) -> String {
    read_tar_gz(&out.archive)
        .unwrap()
        .into_iter()
        .map(|e| format!("== {}\n{}", e.path, String::from_utf8_lossy(&e.data)))
        .collect::<Vec<_>>()
        .join("\n")
}

const TOML: &str = r#"
[node]
name = "home-pi"
[[client]]
name = "Living-TV"
match = ["192.168.1.20"]
[[upstream]]
name = "doh"
url = "https://dns.acme-dns.net/dns-query/abc123secretprofile"
headers = { Authorization = "Bearer hunter2hunter2" }
"#;

#[test]
fn ops_011_a_strict_package_has_its_files_and_nothing_it_shouldnt() {
    let _s = serial();
    let b = backend(TOML);
    support_log::global().push("2026-11-16T04:56:32.000Z  WARN upstream failed for 192.168.1.20 (Living-TV): Bearer hunter2hunter2".to_owned());
    support_log::global().push(
        "2026-11-16T04:56:33.000Z  INFO chatter from home-pi that strict leaves out".to_owned(),
    );
    let out = build(&b, &req("strict", 0, false), false).unwrap();
    assert!(
        out.file_name.starts_with("telltale-support-") && out.file_name.ends_with(".tar.gz"),
        "{}",
        out.file_name
    );
    assert!(
        !out.file_name.contains("home-pi"),
        "a strict file name has no node name: {}",
        out.file_name
    );
    let p = paths(&out);
    for want in [
        "MANIFEST.json",
        "README.txt",
        "config/effective.json",
        "node/host.json",
        "node/info.json",
        "logs/node.log",
        "metrics/metrics.txt",
    ] {
        assert!(p.iter().any(|x| x == want), "{want} missing in {p:?}");
    }
    for no in ["stats/top.json", "queries/sample.json"] {
        assert!(
            !p.iter().any(|x| x == no),
            "{no} must not be in a strict package"
        );
    }
    let all = everything(&out);
    for gone in [
        "hunter2hunter2",
        "abc123secretprofile",
        "192.168.1.20",
        "Living-TV",
        "home-pi",
        "acme-dns",
        "chatter",
    ] {
        assert!(!all.contains(gone), "{gone} survived at strict:\n{all}");
    }
    assert!(
        all.contains("upstream failed"),
        "the warning stays, redacted:\n{all}"
    );
    assert_eq!(out.manifest["level"], "strict");
    assert!(out.id.is_none());
}

#[test]
fn ops_011_standard_adds_info_lines_the_top_lists_and_the_query_sample() {
    let _s = serial();
    let b = backend(TOML);
    support_log::global()
        .push("2026-11-16T04:56:33.000Z  INFO standard keeps this line".to_owned());
    let out = build(&b, &req("standard", 5, false), false).unwrap();
    let all = everything(&out);
    assert!(all.contains("standard keeps this line"), "{all}");
    let listed: Vec<&str> = out.manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["path"].as_str())
        .collect();
    for want in ["stats/top.json", "queries/sample.json"] {
        assert!(
            listed.contains(&want),
            "{want} not in the manifest: {listed:?}"
        );
    }
    for gone in ["hunter2hunter2", "Living-TV"] {
        assert!(!all.contains(gone), "{gone} survived at standard");
    }
}

#[test]
fn ops_011_none_keeps_real_values_but_never_secrets() {
    let _s = serial();
    let b = backend(TOML);
    support_log::global().push("2026-11-16T04:56:34.000Z  WARN none keeps Living-TV at 192.168.1.20 and drops hunter2hunter2".to_owned());
    let out = build(&b, &req("none", 0, false), false).unwrap();
    let all = everything(&out);
    assert!(
        all.contains("Living-TV") && all.contains("192.168.1.20"),
        "{all}"
    );
    assert!(!all.contains("hunter2hunter2"), "{all}");
    assert!(out.file_name.contains("home-pi"), "{}", out.file_name);
}

#[test]
fn ops_011_a_dry_run_has_the_manifest_and_no_archive() {
    let _s = serial();
    let out = build(&backend(TOML), &req("strict", 0, true), true).unwrap();
    assert_eq!(out.archive, Vec::<u8>::new());
    assert!(out.id.is_none(), "a dry run holds no map");
    assert!(
        out.manifest["files"]
            .as_array()
            .is_some_and(|f| f.len() >= 6),
        "{}",
        out.manifest
    );
}

#[test]
fn ops_011_the_map_is_held_for_one_download_of_that_package() {
    let _s = serial();
    let out = build(&backend(TOML), &req("strict", 0, true), false).unwrap();
    let id = out.id.clone().expect("keepMap holds a map");
    assert_eq!(take_map("not-the-id"), None, "a wrong ID takes nothing");
    let map = take_map(&id).expect("the right ID gets it");
    assert!(
        map.contains("\tLiving-TV\n") && map.contains("\t192.168.1.20\n"),
        "{map}"
    );
    assert_eq!(take_map(&id), None, "once");
    // A newer package replaces the map.
    let first = build(&backend(TOML), &req("strict", 0, true), false)
        .unwrap()
        .id
        .unwrap();
    let second = build(&backend(TOML), &req("strict", 0, true), false)
        .unwrap()
        .id
        .unwrap();
    assert_eq!(take_map(&first), None);
    assert!(take_map(&second).is_some());
}

#[test]
fn ops_011_one_package_at_a_time() {
    let _s = serial();
    let _hold = BusyGuard::take().expect("nothing else is running");
    let e = build(&backend(TOML), &req("strict", 0, false), false).unwrap_err();
    assert_eq!(e.code, Code::Conflict);
    assert!(e.hint.is_some());
}

#[test]
fn ops_011_a_map_expires_after_ten_minutes() {
    let _s = serial();
    *held() = Some(Held {
        id: "x".to_owned(),
        text: "device-1\tpi\n".to_owned(),
        made: Instant::now(),
    });
    let later = Instant::now() + MAP_TTL + Duration::from_secs(1);
    assert_eq!(take_map_at("x", later), None, "expired");
    assert_eq!(take_map("x"), None, "and gone");
    *held() = Some(Held {
        id: "x".to_owned(),
        text: "t".to_owned(),
        made: Instant::now(),
    });
    let soon = Instant::now() + Duration::from_secs(60);
    assert_eq!(
        take_map_at("x", soon).as_deref(),
        Some("t"),
        "still good after a minute"
    );
}

#[test]
fn ops_011_a_slow_collector_is_left_behind_and_the_rest_carry_on() {
    let _s = serial();
    let me = Arc::new(backend(TOML));
    let started = Instant::now();
    let slow = gather_for(Duration::from_millis(60), &me, started, |_| {
        std::thread::sleep(Duration::from_millis(600));
        Value::Null
    });
    let why = slow.unwrap_err();
    assert!(why.starts_with("timed out"), "{why}");
    // The next one still runs.
    let fast = gather_for(
        Duration::from_secs(2),
        &me,
        started,
        |_| json!({ "ok": true }),
    );
    assert_eq!(fast.unwrap()["ok"], true);
    // And a package whose collector timed out names it as missing instead of failing.
    let mut known = Known::new();
    known.add(Category::Device, "pi-box");
    let mut pkg = telltale_support::package::Package::new(
        telltale_support::package::Options {
            level: Level::Strict,
            key: [1; 32],
            reveal: Vec::new(),
            created_unix: 0,
            created: "t".to_owned(),
            max_bytes: MAX_BYTES,
        },
        &known,
    )
    .unwrap();
    file(
        &mut pkg,
        "x.json",
        "slow",
        Err("timed out after 5 s".to_owned()),
    );
    let done = pkg.finish();
    assert_eq!(
        done.manifest.files[0].note.as_deref(),
        Some("timed out after 5 s")
    );
}
