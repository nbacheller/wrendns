//! REQ: OPS-011 (ADR-156) — free text (log lines, error strings, the event timeline) goes through a
//! redactor in two passes. First, the values the configuration and the cluster registry name
//! (every device, group, node, pod, namespace, zone, host, e-mail address) and every secret held
//! inline are replaced exactly, longest first, with one multi-pattern search. Then hand-written
//! scanners catch the shapes: addresses, MACs, e-mail, URLs (credentials and queries), host names,
//! home paths, PEM blocks, and long token-looking runs. It is best effort, and the package says so.
//!
//! What a pass produces is never scanned again (a pseudonym `10.4.7.9` is not an address to move).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use regex_automata::meta::Regex;

use crate::Level;
use crate::pseudo::{Category, Pseudonyms, mac_text};

/// What was replaced, by kind: counts only, never values.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counts(pub BTreeMap<&'static str, u32>);

impl Counts {
    fn bump(&mut self, kind: &'static str) {
        *self.0.entry(kind).or_insert(0) += 1;
    }

    /// What was added since `before`.
    #[must_use]
    pub fn since(&self, before: &Self) -> BTreeMap<String, u32> {
        self.0
            .iter()
            .filter_map(|(k, v)| {
                let d = v - before.0.get(k).copied().unwrap_or(0);
                (d > 0).then(|| ((*k).to_owned(), d))
            })
            .collect()
    }
}

/// The values to replace exactly.
#[derive(Debug, Default, Clone)]
pub struct Known {
    names: Vec<(String, Category)>,
    secrets: Vec<String>,
}

/// Names too common to hide (they'd turn ordinary words into pseudonyms).
fn generic(name: &str) -> bool {
    name.chars().count() < 2
        || [
            "default",
            "all",
            "none",
            "any",
            "unknown",
            "local",
            "localhost",
            "true",
            "false",
            "wrendns",
            "home",
            "site",
            "cluster",
            "node",
        ]
        .contains(&name.to_ascii_lowercase().as_str())
}

impl Known {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A name the package must not show as it is.
    pub fn add(&mut self, cat: Category, value: &str) {
        let v = value.trim();
        if !generic(v) {
            self.names.push((v.to_owned(), cat));
        }
    }

    /// A secret held inline (a client secret, a header value): removed wherever it appears.
    pub fn add_secret(&mut self, value: &str) {
        let v = value.trim();
        if v.chars().count() >= 6 {
            self.secrets.push(v.to_owned());
        }
    }
}

#[derive(Debug, Clone)]
enum Target {
    Name(Category),
    Secret,
}

#[derive(Debug)]
struct Matcher {
    re: Regex,
    targets: Vec<Target>,
}

/// The redactor and the pseudonyms it uses, for one package.
#[derive(Debug)]
pub struct Redactor {
    level: Level,
    pseudo: Pseudonyms,
    matcher: Option<Matcher>,
    counts: Counts,
}

enum Seg<'a> {
    Plain(&'a str),
    Done(String),
}

/// `s` as a pattern that matches it literally.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Is `text[start..end]` a whole word (not the middle of a longer one)?
fn whole(text: &str, start: usize, end: usize) -> bool {
    let first = text[start..end].chars().next().is_some_and(word);
    let last = text[start..end].chars().next_back().is_some_and(word);
    let before = text[..start].chars().next_back().is_some_and(word);
    let after = text[end..].chars().next().is_some_and(word);
    !(first && before || last && after)
}

fn is_delim(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '<' | '>' | '=' | '|' | '{' | '}'
        )
}

/// File extensions: `server.rs`, `wrendns.log`, `state.db` are not host names.
const FILE_LABELS: &[&str] = &[
    "log", "toml", "json", "yaml", "yml", "rs", "db", "txt", "gz", "tar", "sh", "so", "md", "conf",
    "cfg", "lock", "tmp", "pem", "crt", "key", "html", "js", "ts", "css", "svg", "png", "jpg",
    "csv", "sql", "wal", "shm", "bin", "exe", "py", "service", "socket", "timer", "target", "fst",
    "idx", "seg", "dat", "old", "bak", "pid", "sock", "zst", "lz4", "xz", "zip", "rules", "list",
    "hosts", "wasm", "map", "ini", "env", "proto", "lib", "dll", "dylib", "a", "o", "d",
];

/// Domains that name this software or are reserved for examples: nothing to hide in them.
const KEEP_DOMAINS: &[&str] = &[
    "wrendns.com",
    "wrendns.com",
    "github.com",
    "githubusercontent.com",
    "ghcr.io",
    "example",
    "example.com",
    "example.org",
    "example.net",
    "example.invalid",
    "localhost",
];

fn keep_domain(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    KEEP_DOMAINS
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
}

/// A host name (`nas.lan`, `dns.quad9.net`), as `(name, ":port")`.
fn host_like(core: &str) -> Option<(&str, &str)> {
    let (name, port) = match core.rsplit_once(':') {
        Some((n, p)) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            (n, &core[n.len()..])
        }
        _ => (core, ""),
    };
    let name = name.trim_end_matches('.');
    let labels: Vec<&str> = name.split('.').collect();
    let last = labels.last()?;
    let ok = labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        && last.len() >= 2
        && last.bytes().all(|b| b.is_ascii_alphabetic())
        && name.bytes().any(|b| b.is_ascii_alphabetic());
    let file = FILE_LABELS.contains(&last.to_ascii_lowercase().as_str());
    (ok && !file && !keep_domain(name)).then_some((name, port))
}

/// A run that looks like a key or token: 24 or more of base64 or hex characters, with both letters
/// and digits (a long word or a plain number is left alone).
fn token_like(piece: &str) -> bool {
    piece.len() >= 24
        && piece
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'_' | b'=' | b'-'))
        && piece.bytes().any(|b| b.is_ascii_digit())
        && piece.bytes().any(|b| b.is_ascii_alphabetic())
}

fn credential_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    [
        "token",
        "key",
        "secret",
        "pass",
        "auth",
        "sig",
        "credential",
        "session",
        "code",
    ]
    .iter()
    .any(|w| k.contains(w))
}

/// `scheme://...` at the start of `s`: how many bytes the URL takes.
fn url_extent(s: &str) -> Option<usize> {
    let scheme = s.find("://")?;
    let head = &s[..scheme];
    let ok = (1..=16).contains(&head.len())
        && head.starts_with(|c: char| c.is_ascii_alphabetic())
        && head
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'));
    if !ok {
        return None;
    }
    let end = s
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>' | ')'))
        .unwrap_or(s.len());
    Some(end)
}

/// `core` without trailing sentence punctuation, and that punctuation.
fn split_tail(tok: &str) -> (&str, &str) {
    let mut end = tok.trim_end_matches(['.', ',', ';', '!', '?']).len();
    if tok[..end].ends_with(':') && !tok[..end].ends_with("::") {
        end -= 1;
    }
    (&tok[..end], &tok[end..])
}

impl Redactor {
    #[must_use]
    pub fn new(level: Level, pseudo: Pseudonyms) -> Self {
        Self {
            level,
            pseudo,
            matcher: None,
            counts: Counts::default(),
        }
    }

    #[must_use]
    pub fn level(&self) -> Level {
        self.level
    }

    #[must_use]
    pub fn counts(&self) -> &Counts {
        &self.counts
    }

    /// The pseudonym map (`pseudonym<TAB>original` lines).
    #[must_use]
    pub fn map(&self) -> String {
        self.pseudo.map()
    }

    /// Sets the values the first pass replaces. Fails (with a reason) only if there are too many
    /// for one search.
    pub fn set_known(&mut self, known: &Known) -> Result<(), String> {
        let mut rows: Vec<(String, Target)> = known
            .secrets
            .iter()
            .map(|s| (s.clone(), Target::Secret))
            .collect();
        if self.level != Level::Off {
            rows.extend(
                known
                    .names
                    .iter()
                    .map(|(n, c)| (n.clone(), Target::Name(*c))),
            );
        }
        // Longest first: at one position the first pattern that matches wins.
        rows.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        rows.dedup_by(|a, b| a.0.eq_ignore_ascii_case(&b.0));
        if rows.is_empty() {
            self.matcher = None;
            return Ok(());
        }
        let patterns: Vec<String> = rows
            .iter()
            .map(|(v, _)| format!("(?i:{})", escape(v)))
            .collect();
        let re = Regex::builder()
            .build_many(&patterns)
            .map_err(|e| format!("too many names to search for: {e}"))?;
        self.matcher = Some(Matcher {
            re,
            targets: rows.into_iter().map(|(_, t)| t).collect(),
        });
        Ok(())
    }

    /// A counted pseudonym for a name in `cat` (`Off` keeps the name).
    pub fn name(&mut self, cat: Category, value: &str) -> String {
        if self.level == Level::Off || value.is_empty() {
            return value.to_owned();
        }
        self.counts.bump(cat.label());
        self.pseudo.name(cat, value)
    }

    /// `text` redacted at this package's level.
    pub fn text(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for seg in self.known_pass(text) {
            match seg {
                Seg::Done(s) => out.push_str(&s),
                Seg::Plain(p) => self.shapes(p, &mut out),
            }
        }
        out
    }

    fn known_pass<'a>(&mut self, text: &'a str) -> Vec<Seg<'a>> {
        let hits: Vec<(usize, usize, usize)> = match &self.matcher {
            Some(m) => {
                m.re.find_iter(text)
                    .map(|h| (h.start(), h.end(), h.pattern().as_usize()))
                    .collect()
            }
            None => return vec![Seg::Plain(text)],
        };
        let mut segs = Vec::new();
        let mut at = 0;
        for (start, end, which) in hits {
            let Some(target) = self
                .matcher
                .as_ref()
                .and_then(|m| m.targets.get(which))
                .cloned()
            else {
                continue;
            };
            // A name matches as a whole word; a secret matches wherever it is.
            if start < at || (matches!(target, Target::Name(_)) && !whole(text, start, end)) {
                continue;
            }
            if start > at {
                segs.push(Seg::Plain(&text[at..start]));
            }
            let original = &text[start..end];
            segs.push(Seg::Done(match target {
                Target::Secret => {
                    self.counts.bump("secret");
                    "<secret>".to_owned()
                }
                Target::Name(cat) => {
                    self.counts.bump(cat.label());
                    self.pseudo.name(cat, original)
                }
            }));
            at = end;
        }
        if at < text.len() {
            segs.push(Seg::Plain(&text[at..]));
        }
        segs
    }

    /// The second pass over a stretch the first left alone: PEM blocks, then token by token.
    fn shapes(&mut self, text: &str, out: &mut String) {
        let mut rest = text;
        while let Some(i) = rest.find("-----BEGIN ") {
            self.tokens(&rest[..i], out);
            let block = &rest[i..];
            let end = block
                .find("-----END ")
                .and_then(|j| block[j + 9..].find("-----").map(|k| j + 9 + k + 5))
                .unwrap_or(block.len());
            out.push_str("<pem-removed>");
            self.counts.bump("pem");
            rest = &block[end..];
        }
        self.tokens(rest, out);
    }

    fn tokens(&mut self, text: &str, out: &mut String) {
        let mut at = 0;
        while at < text.len() {
            let rest = &text[at..];
            let Some(c) = rest.chars().next() else { break };
            if is_delim(c) {
                out.push(c);
                at += c.len_utf8();
                continue;
            }
            let len = url_extent(rest)
                .unwrap_or_else(|| rest.find(is_delim).unwrap_or(rest.len()))
                .max(c.len_utf8());
            self.token(&rest[..len], out);
            at += len;
        }
    }

    fn token(&mut self, tok: &str, out: &mut String) {
        let (core, tail) = split_tail(tok);
        let done = if self.level == Level::Off {
            self.try_url(core).or_else(|| self.try_token(core))
        } else {
            self.try_url(core)
                .or_else(|| self.try_email(core))
                .or_else(|| self.try_mac(core))
                .or_else(|| self.try_ip(core))
                .or_else(|| self.try_path(core))
                .or_else(|| self.try_host(core))
                .or_else(|| self.try_token(core))
        };
        out.push_str(done.as_deref().unwrap_or(core));
        out.push_str(tail);
    }

    /// An address, counted when it moved.
    fn addr(&mut self, ip: IpAddr) -> IpAddr {
        let moved = self.pseudo.ip(ip);
        if moved != ip {
            self.counts.bump("address");
        }
        moved
    }

    fn try_ip(&mut self, core: &str) -> Option<String> {
        if let Some(inner) = core.strip_prefix('[') {
            let (addr, tail) = inner.split_once(']')?;
            let ip: Ipv6Addr = addr.split('%').next()?.parse().ok()?;
            let moved = self.addr(IpAddr::V6(ip));
            return Some(format!("[{moved}]{tail}"));
        }
        let (head, prefix) = match core.split_once('/') {
            Some((h, p)) if p.parse::<u8>().is_ok() => (h, Some(p.parse::<u8>().ok()?)),
            Some(_) => return None,
            None => (core, None),
        };
        let (addr, port) = match head.rsplit_once(':') {
            Some((a, p))
                if a.contains('.') && p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() =>
            {
                (a, &head[a.len()..])
            }
            _ => (head, ""),
        };
        let ip: IpAddr = if let Ok(v4) = addr.parse::<Ipv4Addr>() {
            IpAddr::V4(v4)
        } else {
            let bare = addr.split('%').next()?;
            if !(bare.contains("::") || bare.matches(':').count() == 7) {
                return None;
            }
            IpAddr::V6(bare.parse().ok()?)
        };
        let moved = match prefix {
            Some(p) => {
                let n = self.pseudo.network(ip, p);
                if n != ip {
                    self.counts.bump("address");
                }
                n
            }
            None => self.addr(ip),
        };
        Some(match prefix {
            Some(p) => format!("{moved}/{p}{port}"),
            None => format!("{moved}{port}"),
        })
    }

    fn try_mac(&mut self, core: &str) -> Option<String> {
        let b = core.as_bytes();
        if b.len() != 17 {
            return None;
        }
        let sep = b[2];
        if sep != b':' && sep != b'-' {
            return None;
        }
        let mut mac = [0u8; 6];
        for (i, slot) in mac.iter_mut().enumerate() {
            if i > 0 && b[i * 3 - 1] != sep {
                return None;
            }
            *slot = u8::from_str_radix(core.get(i * 3..i * 3 + 2)?, 16).ok()?;
        }
        self.counts.bump("mac");
        let text = mac_text(self.pseudo.mac(mac));
        Some(if sep == b'-' {
            text.replace(':', "-")
        } else {
            text
        })
    }

    fn try_email(&mut self, core: &str) -> Option<String> {
        let (local, domain) = core.rsplit_once('@')?;
        let local_ok = !local.is_empty()
            && local.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
            });
        host_like(domain).filter(|_| local_ok)?;
        self.counts.bump("email");
        Some(self.pseudo.email(core))
    }

    fn try_host(&mut self, core: &str) -> Option<String> {
        let (name, port) = host_like(core)?;
        self.counts.bump("host");
        Some(format!("{}{port}", self.pseudo.host(name)))
    }

    /// `/home/alice/...` and `/Users/alice/...`: the person's name goes.
    fn try_path(&mut self, core: &str) -> Option<String> {
        let rest = core
            .strip_prefix("/home/")
            .or_else(|| core.strip_prefix("/Users/"))?;
        let (user, tail) = rest.split_once('/').unwrap_or((rest, ""));
        if user.is_empty() {
            return None;
        }
        let root = &core[..core.len() - rest.len()];
        self.counts.bump("path");
        let user = self.pseudo.name(Category::User, user);
        let tail = if tail.is_empty() {
            String::new()
        } else {
            format!("/{}", self.pieces(tail))
        };
        Some(format!("{root}{user}{tail}"))
    }

    /// Long token-looking runs, piece by piece across `/`, `.`, and the like (a JWT's parts).
    fn try_token(&mut self, core: &str) -> Option<String> {
        let out = self.pieces(core);
        (out != core).then_some(out)
    }

    /// `s` with each long token-looking run between separators replaced.
    fn pieces(&mut self, s: &str) -> String {
        let sep = |c: char| matches!(c, '/' | '.' | ':' | '&' | '?' | '=' | '@' | '#');
        let mut out = String::with_capacity(s.len());
        let mut run = String::new();
        for c in s.chars() {
            if sep(c) {
                self.flush_run(&mut run, &mut out);
                out.push(c);
            } else {
                run.push(c);
            }
        }
        self.flush_run(&mut run, &mut out);
        out
    }

    fn flush_run(&mut self, run: &mut String, out: &mut String) {
        if token_like(run) {
            self.counts.bump("token");
            out.push_str("<token>");
        } else {
            out.push_str(run);
        }
        run.clear();
    }

    /// A URL for the configuration view: credentials, path and query go (a webhook's or a DNS
    /// provider's profile ID sits in the path); the scheme, the host (a pseudonym), and the port
    /// stay. At `none` it's the text redactor's: credentials and secrets only.
    pub fn url(&mut self, s: &str) -> String {
        let Some((scheme, rest)) = s.split_once("://") else {
            return self.text(s);
        };
        if self.level == Level::Off {
            return self.text(s);
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, after) = rest.split_at(end);
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        if userinfo.is_some() {
            self.counts.bump("url-credentials");
        }
        let creds = if userinfo.is_some() {
            "<credentials>@"
        } else {
            ""
        };
        let host = self.url_host(hostport);
        let tail = if after.is_empty() || after == "/" {
            after.to_owned()
        } else {
            self.counts.bump("url-path");
            "/<path>".to_owned()
        };
        format!("{scheme}://{creds}{host}{tail}")
    }

    /// Free text (a note, a domain list): omitted at `strict`, redacted like a log line otherwise.
    pub fn free(&mut self, s: &str) -> String {
        if self.level == Level::Strict {
            self.counts.bump("free");
            "<omitted>".to_owned()
        } else {
            self.text(s)
        }
    }

    /// A URL: credentials always go; at `strict` and `standard` the host is replaced and the query
    /// is dropped; at `none` only credential-looking query values go.
    fn try_url(&mut self, core: &str) -> Option<String> {
        if url_extent(core)? != core.len() {
            return None;
        }
        let (scheme, rest) = core.split_once("://")?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, after) = rest.split_at(end);
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        if userinfo.is_some() {
            self.counts.bump("url-credentials");
        }
        let creds = if userinfo.is_some() {
            "<credentials>@"
        } else {
            ""
        };
        let hostport = if self.level == Level::Off {
            hostport.to_owned()
        } else {
            self.url_host(hostport)
        };
        let (path, query) = match after.find(['?', '#']) {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, ""),
        };
        let path = if self.level == Level::Off {
            self.pieces(path)
        } else {
            self.path_words(path)
        };
        Some(format!(
            "{scheme}://{creds}{hostport}{path}{}",
            self.url_query(query)
        ))
    }

    /// A URL path at `strict` and `standard`: words stay (`/dns-query`, `/api/v1`), and anything
    /// with a digit or a capital (an ID, a token, a profile, a user) becomes `<id>`.
    fn path_words(&mut self, path: &str) -> String {
        path.split('/')
            .map(|seg| {
                let word = seg.len() <= 32
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || matches!(b, b'-' | b'_' | b'.'));
                let version = seg.len() <= 4
                    && seg
                        .strip_prefix('v')
                        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
                if seg.is_empty() || word || version {
                    seg.to_owned()
                } else {
                    self.counts.bump("url-path");
                    "<id>".to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    fn url_host(&mut self, hostport: &str) -> String {
        if let Some(inner) = hostport.strip_prefix('[') {
            if let Some((addr, tail)) = inner.split_once(']')
                && let Ok(ip) = addr.parse::<Ipv6Addr>()
            {
                return format!("[{}]{tail}", self.addr(IpAddr::V6(ip)));
            }
            return "<host>".to_owned();
        }
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                (h, &hostport[h.len()..])
            }
            _ => (hostport, ""),
        };
        if host.is_empty() {
            return hostport.to_owned();
        }
        let shown = match host.parse::<IpAddr>() {
            Ok(ip) => self.addr(ip).to_string(),
            Err(_) if keep_domain(host) => host.to_owned(),
            Err(_) => {
                self.counts.bump("host");
                self.pseudo.host(host)
            }
        };
        format!("{shown}{port}")
    }

    fn url_query(&mut self, query: &str) -> String {
        if query.is_empty() {
            return String::new();
        }
        if self.level != Level::Off {
            self.counts.bump("url-query");
            return format!("{}<query>", &query[..1]);
        }
        let Some(body) = query.strip_prefix('?') else {
            return query.to_owned();
        };
        let (params, fragment) = body.split_once('#').unwrap_or((body, ""));
        let kept: Vec<String> = params
            .split('&')
            .map(|kv| match kv.split_once('=') {
                Some((k, _)) if credential_key(k) => {
                    self.counts.bump("secret");
                    format!("{k}=<secret>")
                }
                _ => kv.to_owned(),
            })
            .collect();
        let frag = if fragment.is_empty() {
            String::new()
        } else {
            format!("#{fragment}")
        };
        format!("?{}{frag}", kept.join("&"))
    }
}

#[cfg(test)]
#[path = "redact_tests.rs"]
mod tests;
