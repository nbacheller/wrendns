//! Safe search (REQ: FLT-011, `spec/05` §4; T7.11): which names have a safe-search target.
//!
//! The table is data (`presets/safesearch.toml`) compiled into the binary. A group with
//! `safe_search = true` gets queries for an engine's domains answered as a CNAME to the
//! engine's safe-search name (the pipeline resolves the target and adds its addresses).

use std::sync::OnceLock;

use serde::Deserialize;

use crate::schema::YoutubeRestrict;

const TABLE: &str = include_str!("../../../presets/safesearch.toml");

/// One search engine (or video site).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engine {
    pub id: String,
    pub name: String,
    /// The safe-search name answers point to.
    pub target: String,
    /// YouTube's moderate restriction (`youtube_restrict = "moderate"`).
    #[serde(default)]
    pub moderate: Option<String>,
    /// Names it applies to; `*` is a country domain.
    pub domains: Vec<String>,
}

#[derive(Deserialize)]
struct File {
    engine: Vec<Engine>,
}

/// Every engine. A broken table is a build-time mistake the tests catch: it yields none.
pub fn engines() -> &'static [Engine] {
    static ENGINES: OnceLock<Vec<Engine>> = OnceLock::new();
    ENGINES.get_or_init(|| {
        toml::from_str::<File>(TABLE)
            .map(|f| f.engine)
            .unwrap_or_default()
    })
}

fn engines_for(name: &str) -> Option<&'static Engine> {
    engines()
        .iter()
        .find(|e| e.domains.iter().any(|p| matches(p, name)))
}

/// A country domain: one or two labels of up to three letters (`de`, `co.uk`, `com.au`).
fn country_domain(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    (1..=2).contains(&labels.len())
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.len() <= 3 && l.bytes().all(|b| b.is_ascii_lowercase()))
}

fn matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.strip_prefix(prefix).is_some_and(country_domain),
        None => pattern == name,
    }
}

/// The safe-search target for `name` (lowercase, no trailing dot), or `None`. YouTube follows
/// `youtube` (`off` leaves it alone).
pub fn target(name: &str, youtube: YoutubeRestrict) -> Option<&'static str> {
    target_in::<&str>(name, youtube, &[])
}

/// REQ: FLT-902 (T24.29) — like [`target`], for a group that covers only some engines: an
/// empty `engines` means every engine (`safe_search = true` alone), otherwise only the engines
/// named. The caller adds `youtube` when the group's `youtube_restrict` is set to something other
/// than its default, so YouTube's level applies whatever the list says.
pub fn target_in<S: AsRef<str>>(
    name: &str,
    youtube: YoutubeRestrict,
    engines: &[S],
) -> Option<&'static str> {
    let e = engines_for(name)?;
    if !engines.is_empty() && !engines.iter().any(|x| x.as_ref() == e.id) {
        return None;
    }
    if e.id == "youtube" {
        return match youtube {
            YoutubeRestrict::Off => None,
            YoutubeRestrict::Moderate => e.moderate.as_deref().or(Some(e.target.as_str())),
            YoutubeRestrict::Strict => Some(e.target.as_str()),
        };
    }
    Some(e.target.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: FLT-011 — the table parses; engines' names map to their targets; look-alikes
    /// don't.
    #[test]
    fn flt_011_safe_search_targets() {
        assert!(engines().len() >= 6);
        let s = YoutubeRestrict::Strict;
        assert_eq!(
            target("www.google.com", s),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(
            target("www.google.co.uk", s),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(target("google.de", s), Some("forcesafesearch.google.com"));
        assert_eq!(
            target("google.evil.example", s),
            None,
            "not a country domain"
        );
        assert_eq!(target("mail.google.com", s), None, "only search");
        assert_eq!(target("www.youtube.com", s), Some("restrict.youtube.com"));
        assert_eq!(
            target("www.youtube.com", YoutubeRestrict::Moderate),
            Some("restrictmoderate.youtube.com")
        );
        assert_eq!(target("www.youtube.com", YoutubeRestrict::Off), None);
        assert_eq!(target("www.bing.com", s), Some("strict.bing.com"));
        assert_eq!(target("duckduckgo.com", s), Some("safe.duckduckgo.com"));
        assert_eq!(target("example.com", s), None);
    }

    /// REQ: FLT-902 — a group's engine list is the set of engines; empty means all.
    #[test]
    fn flt_902_safe_search_engines_subset() {
        let s = YoutubeRestrict::Strict;
        let google = ["google".to_owned()];
        assert_eq!(
            target_in("www.google.com", s, &google),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(target_in("www.bing.com", s, &google), None);
        assert_eq!(target_in("www.youtube.com", s, &google), None);
        assert_eq!(
            target_in("www.bing.com", s, &[] as &[String]),
            Some("strict.bing.com")
        );
    }
}
