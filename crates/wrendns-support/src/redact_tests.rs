// REQ: OPS-011 (ADR-156) — the redactor: every shape replaced at strict, only secrets and
// credentials at none, whole-word matching, nothing scanned twice, and no panic on anything.

use super::*;

fn red(level: Level) -> Redactor {
    Redactor::new(level, Pseudonyms::new([5; 32]))
}

#[test]
fn ops_011_strict_replaces_every_shape() {
    let mut r = red(Level::Strict);
    let input = "client 192.168.1.20:53 from aa:bb:cc:dd:ee:ff wrote someone@gmail.com via \
                 https://user:hunter2@dns.quad9.net:853/dns-query?token=abc123 see \
                 /home/alice/.cache/x.log key 0123456789abcdef0123456789abcdef0123 host nas.lan error: 10.1.2.3.";
    let out = r.text(input);
    for gone in [
        "192.168.1.20",
        "aa:bb:cc",
        "someone@",
        "gmail",
        "hunter2",
        "dns.quad9.net",
        "alice",
        "abc123",
        "0123456789abcdef",
        "nas.lan",
        "10.1.2.3",
    ] {
        assert!(!out.contains(gone), "{gone} survived: {out}");
    }
    for kept in [
        ":53",
        ":853",
        "<credentials>@",
        "<query>",
        "/dns-query",
        ".cache/x.log",
        "<token>",
        "error:",
    ] {
        assert!(out.contains(kept), "{kept} missing: {out}");
    }
    assert!(out.ends_with('.'), "{out}");
    let c = &r.counts().0;
    for kind in [
        "address",
        "mac",
        "email",
        "host",
        "path",
        "token",
        "url-credentials",
        "url-query",
    ] {
        assert!(c.get(kind).copied().unwrap_or(0) >= 1, "{kind}: {c:?}");
    }
}

#[test]
fn ops_011_the_same_value_is_the_same_pseudonym() {
    let mut r = red(Level::Strict);
    let out = r.text("10.0.0.5 and 10.0.0.5 again; nas.lan, nas.lan");
    let parts: Vec<&str> = out.split_whitespace().collect();
    assert_eq!(parts[0], parts[2], "{out}");
    assert_ne!(parts[0], "10.0.0.5");
    assert_eq!(parts[4].trim_end_matches(','), parts[5], "{out}");
}

#[test]
fn ops_011_known_names_are_replaced_as_whole_words_only() {
    let mut known = Known::new();
    known.add(Category::Node, "pi");
    known.add(Category::Device, "Living-TV");
    let mut r = red(Level::Strict);
    r.set_known(&known).unwrap();
    let out = r.text("pipeline ok; PI is down; living-tv asked; spi and pi-hole");
    assert!(
        out.starts_with("pipeline ok; node-1 is down; device-1 asked; spi and node-1"),
        "{out}"
    );
}

#[test]
fn ops_011_what_a_pass_made_is_not_scanned_again() {
    let mut known = Known::new();
    known.add(Category::Device, "tv");
    let mut r = red(Level::Strict);
    r.set_known(&known).unwrap();
    // `device-1` has a digit and a letter, but it is not a token; `tv` is replaced once.
    assert_eq!(r.text("the tv asked"), "the device-1 asked");
}

#[test]
fn ops_011_known_secrets_are_removed_at_every_level() {
    for level in [Level::Strict, Level::Standard, Level::Off] {
        let mut known = Known::new();
        known.add_secret("s3cr3t-value-123");
        let mut r = red(level);
        r.set_known(&known).unwrap();
        let out = r.text("password=s3cr3t-value-123, again S3CR3T-VALUE-123!");
        assert!(!out.to_lowercase().contains("s3cr3t"), "{level:?}: {out}");
        assert_eq!(out, "password=<secret>, again <secret>!", "{level:?}");
    }
}

#[test]
fn ops_011_none_keeps_values_but_never_secrets_or_credentials() {
    let mut r = red(Level::Off);
    let input = "192.168.1.5 someone@gmail.com dns.quad9.net /home/alice/x \
                 https://u:p@host.example.net/x?token=abc&a=b \
                 -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY----- \
                 abcdef0123456789abcdef0123456789";
    let out = r.text(input);
    for kept in [
        "192.168.1.5",
        "someone@gmail.com",
        "dns.quad9.net",
        "/home/alice/x",
        "host.example.net",
        "a=b",
    ] {
        assert!(out.contains(kept), "{kept} was removed: {out}");
    }
    for gone in [
        "u:p@",
        "abc&",
        "MIIE",
        "BEGIN PRIVATE",
        "abcdef0123456789abcdef0123456789",
    ] {
        assert!(!out.contains(gone), "{gone} survived: {out}");
    }
    assert!(
        out.contains("<credentials>@")
            && out.contains("token=<secret>")
            && out.contains("<pem-removed>")
    );
}

#[test]
fn ops_011_an_ipv6_literal_and_a_network_move_but_keep_their_shape() {
    let mut r = red(Level::Strict);
    let out = r.text("[fd12:3456::5]:853 and 10.1.0.0/16 and 2a01:4f8::1 and fe80::1 and 8.8.8.8");
    assert!(
        !out.contains("fd12:3456") && !out.contains("10.1.0.0") && !out.contains("2a01:4f8"),
        "{out}"
    );
    assert!(out.contains("]:853") && out.contains("/16"), "{out}");
    assert!(
        out.contains("fe80::1") && out.contains("8.8.8.8"),
        "special addresses stay: {out}"
    );
}

#[test]
fn ops_011_times_versions_and_file_names_are_left_alone() {
    let mut r = red(Level::Strict);
    let line = "2026-11-16T05:14:08.745Z  INFO starting version=0.7.0-edge.232 commit=23bc211 \
                /var/lib/wrendns/wrendns.log server.rs:123:45 at 12:30:45 on github.com via ghcr.io";
    assert_eq!(r.text(line), line);
}

#[test]
fn ops_011_a_pem_block_goes_whole() {
    let mut r = red(Level::Strict);
    let out =
        r.text("before -----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE----- after");
    assert_eq!(out, "before <pem-removed> after");
    // No end marker: everything to the end goes.
    assert_eq!(
        r.text("x -----BEGIN RSA PRIVATE KEY-----\nAAAA"),
        "x <pem-removed>"
    );
}

#[test]
fn ops_011_counts_since_a_snapshot_say_what_one_text_cost() {
    let mut r = red(Level::Strict);
    r.text("10.0.0.1");
    let before = r.counts().clone();
    r.text("10.0.0.2 and 10.0.0.3 and aa:bb:cc:dd:ee:ff");
    let d = r.counts().since(&before);
    assert_eq!(d.get("address"), Some(&2));
    assert_eq!(d.get("mac"), Some(&1));
}

/// A tiny xorshift generator for the fuzz-style test.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a>(&mut self, of: &[&'a str]) -> &'a str {
        of[usize::try_from(self.next() % of.len() as u64).unwrap_or(0)]
    }
}

#[test]
fn ops_011_arbitrary_text_never_panics_and_a_planted_secret_never_survives() {
    const SECRET: &str = "Zq9-planted-SECRET-77";
    let pieces = [
        SECRET,
        "10.0.0.7",
        "::1",
        "[",
        "]",
        "]:",
        "http://",
        "https://u:p@h:1/x?y=z#f",
        "://",
        "@",
        "..",
        ".",
        "-----BEGIN ",
        "-----END ",
        "é",
        "ß",
        "日本",
        "\u{0}",
        "\t",
        "\n",
        " ",
        "/home/",
        "/",
        ":",
        "::",
        "aa:bb:cc:dd:ee:ff",
        "1.2.3.4/33",
        "a.b",
        "x.y.z.example.com",
        "0123456789abcdef0123456789abcdef",
        "=",
        "\"",
        "'",
        "<",
        ">",
        "%25",
        "😀",
        "-",
        "_",
    ];
    for level in [Level::Strict, Level::Standard, Level::Off] {
        let mut known = Known::new();
        known.add_secret(SECRET);
        known.add(Category::Device, "tv-room");
        let mut r = red(level);
        r.set_known(&known).unwrap();
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..3_000 {
            let n = 1 + rng.next() % 14;
            let mut s = String::new();
            for _ in 0..n {
                s.push_str(rng.pick(&pieces));
            }
            let out = r.text(&s);
            assert!(!out.contains(SECRET), "{level:?}: {s:?} -> {out:?}");
            // Idempotent on its own output where nothing needs to move again: never panics.
            let _ = r.text(&out);
        }
    }
}

#[test]
fn ops_011_url_paths_keep_words_and_lose_ids() {
    let line =
        "GET https://dns.acme-dns.net/dns-query/abc123secretprofile/v1/lists/42/Hosts.txt done";
    let mut strict = red(Level::Strict);
    let out = strict.text(line);
    assert!(
        out.contains("/dns-query/<id>/v1/lists/<id>/<id> done"),
        "{out}"
    );
    assert!(
        !out.contains("abc123secretprofile") && !out.contains("acme-dns"),
        "{out}"
    );
    // At none the path is as it is (tokens aside).
    let mut open = red(Level::Off);
    assert!(
        open.text(line)
            .contains("/dns-query/abc123secretprofile/v1/lists/42/Hosts.txt")
    );
}
