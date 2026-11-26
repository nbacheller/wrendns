// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DSC-908, CLD-920 (ADR-1096 point 5; T36.10a0) — the compatibility gate for new shared
//! sections and secret kinds.
//!
//! A released replica refuses a shared section it does not know and keeps its last applied
//! version, so the first entry of a new section (or the first secret of a new kind) must wait
//! until every member runs a build that knows it. Each member's heartbeat carries its build
//! version; [`Feature::since`] is the table of when each gated feature arrived. One check
//! ([`check`]) serves the API and the file loader; it is pure and off the query path.

use std::fmt;

use crate::net::Member;

/// A shared section or secret kind that older builds do not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// The `[[location]]` table (DSC-908).
    Locations,
    /// The `[[dns_provider]]` table (CLD-904).
    DnsProviders,
    /// The `pem` secret kind (CLD-920).
    PemSecrets,
}

impl Feature {
    /// Every gated feature.
    pub const ALL: [Feature; 3] = [Self::Locations, Self::DnsProviders, Self::PemSecrets];

    /// The first build version that knows the feature: the table of when each arrived.
    pub const fn since(self) -> (u64, u64, u64) {
        match self {
            Self::Locations | Self::DnsProviders | Self::PemSecrets => (1, 1, 0),
        }
    }

    /// How the refusal names it ("which does not know ...").
    pub const fn what(self) -> &'static str {
        match self {
            Self::Locations => "locations",
            Self::DnsProviders => "DNS providers",
            Self::PemSecrets => "secrets of the `pem` kind",
        }
    }
}

/// The numeric part of a build version (`1.2.3`, `1.2.3-rc.1`, `v1.2.3`); `None` when unreadable.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut it = core.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

/// Whether a build of `version` knows `f`. An empty or unreadable version (a peer older than the
/// version field, or one that has not reported yet) is taken as not knowing it.
pub fn knows(version: &str, f: Feature) -> bool {
    parse_version(version).is_some_and(|v| v >= f.since())
}

/// A member whose build does not know the feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocker {
    pub node: String,
    pub version: String,
}

/// Why a gated change is held back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub feature: Feature,
    pub blockers: Vec<Blocker>,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(first) = self.blockers.first() else {
            return Ok(());
        };
        let runs = if first.version.is_empty() {
            "an unknown version".to_owned()
        } else {
            format!("version {}", first.version)
        };
        write!(
            f,
            "node {} runs {runs}, which does not know {}; upgrade it first",
            first.node,
            self.feature.what()
        )?;
        let more = self.blockers.len() - 1;
        if more > 0 {
            write!(
                f,
                " ({more} more member{} too)",
                if more == 1 { "" } else { "s" }
            )?;
        }
        Ok(())
    }
}

/// REQ: DSC-908 (ADR-1096 point 5) — `Ok` once every member's build knows `f`; otherwise a
/// [`Refusal`] naming the members that do not. `members` are `(node ID, build version)` of the
/// peers (this node's own build is the one asking, so it knows). Named in node-ID order.
pub fn check<'a>(
    members: impl IntoIterator<Item = (&'a str, &'a str)>,
    f: Feature,
) -> Result<(), Refusal> {
    let mut blockers: Vec<Blocker> = members
        .into_iter()
        .filter(|(_, v)| !knows(v, f))
        .map(|(n, v)| Blocker {
            node: n.to_owned(),
            version: v.to_owned(),
        })
        .collect();
    if blockers.is_empty() {
        return Ok(());
    }
    blockers.sort_by(|a, b| a.node.cmp(&b.node));
    Err(Refusal {
        feature: f,
        blockers,
    })
}

/// [`check`] over the cluster's members, as this node sees them.
pub fn check_members(members: &[Member], f: Feature) -> Result<(), Refusal> {
    check(
        members
            .iter()
            .map(|m| (m.node_id.as_str(), m.version.as_str())),
        f,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsc_908_versions_compare_numerically() {
        assert_eq!(parse_version("1.10.0"), Some((1, 10, 0)));
        assert_eq!(parse_version("v1.1.0-rc.1"), Some((1, 1, 0)));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("1.1"), None);
        assert!(knows("1.1.0", Feature::Locations));
        assert!(knows("1.10.2", Feature::Locations));
        assert!(knows("2.0.0", Feature::PemSecrets));
        assert!(!knows("1.0.9", Feature::Locations));
        assert!(!knows("", Feature::Locations));
        assert!(!knows("garbage", Feature::DnsProviders));
    }

    #[test]
    fn dsc_908_gate_names_the_member_and_its_version() {
        let ms = [("pi-b", "1.0.0"), ("pi-a", "1.1.0")];
        let r = check(ms, Feature::Locations).unwrap_err();
        assert_eq!(
            r.to_string(),
            "node pi-b runs version 1.0.0, which does not know locations; upgrade it first"
        );
        let ms = [("pi-b", "1.0.0"), ("pi-a", "")];
        let r = check(ms, Feature::DnsProviders).unwrap_err();
        assert!(
            r.to_string()
                .starts_with("node pi-a runs an unknown version"),
            "{r}"
        );
        assert!(r.to_string().contains("(1 more member too)"), "{r}");
    }

    #[test]
    fn dsc_908_gate_drops_away_once_every_member_knows() {
        let ms = [("a", "1.1.0"), ("b", "1.2.0")];
        for f in Feature::ALL {
            assert!(check(ms, f).is_ok());
        }
        assert!(check([], Feature::PemSecrets).is_ok());
    }
}
