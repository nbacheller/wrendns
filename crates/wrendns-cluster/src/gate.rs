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
    /// The `access` settings kind, the cluster-wide allowed networks (DNS-014, T27.14h).
    Access,
    /// The `dnstap_settings` kind, the whole `[telemetry.dnstap]` section (OBS-007, API-905, T40.13).
    Dnstap,
    /// A list with `format = "rpz"` (FLT-906, T40.9): an older member reads the unknown field as
    /// a refusal of the whole lists section (or, were it lenient, a zone file as plain lines).
    RpzLists,
    /// The peer read of a node's root trust anchors (DNS-906, T40.5). Nothing is replicated: an
    /// older member does not know the read, and is listed as not supporting it.
    Rfc5011,
    /// `compression = "gzip"` in the OTLP export entry; a build that does not know the field
    /// refuses the whole entry (OBS-006, issue #155).
    OtlpCompression,
    /// The DNS-provider write engine's ownership ledger and its test, records and adopt actions
    /// (CLD-919, T36.10b step b3): the ledger rows ride the node-managed blob and the actions are
    /// forwarded writes, which an older primary does not know.
    DnsProviderLedger,
    /// The API URL a member announces and the per-node read of its web UI and API settings
    /// (API-902, T27.14g0, ADR-1113). Nothing is replicated: an older member announces no URL and
    /// does not know the read, so a card says so plainly instead of asking it.
    MemberApiAddress,
    /// The `delegated` DNS-provider kind (CLD-904, T36.10b step b5, ADR-1115): a build that does
    /// not know the kind refuses the whole `[[dns_provider]]` section, so the first delegated
    /// entry waits for every member to announce it, though they all know the table.
    DnsProviderDelegation,
}

impl Feature {
    /// Every gated feature.
    pub const ALL: [Feature; 11] = [
        Self::Locations,
        Self::DnsProviders,
        Self::PemSecrets,
        Self::Access,
        Self::Dnstap,
        Self::RpzLists,
        Self::Rfc5011,
        Self::OtlpCompression,
        Self::DnsProviderLedger,
        Self::MemberApiAddress,
        Self::DnsProviderDelegation,
    ];

    /// The name a build announces the feature under (wire: Hello `features`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Locations => "locations",
            Self::DnsProviders => "dns_providers",
            Self::PemSecrets => "pem_secrets",
            Self::Access => "access",
            Self::Dnstap => "dnstap",
            Self::RpzLists => "rpz_lists",
            Self::Rfc5011 => "rfc5011",
            Self::OtlpCompression => "otlp_compression",
            Self::DnsProviderLedger => "dns_provider_ledger",
            Self::MemberApiAddress => "member_api_address",
            Self::DnsProviderDelegation => "dns_provider_delegation",
        }
    }

    /// How the refusal names it ("which does not know ...").
    pub const fn what(self) -> &'static str {
        match self {
            Self::Locations => "locations",
            Self::DnsProviders => "DNS providers",
            Self::PemSecrets => "secrets of the `pem` kind",
            Self::Access => "the allowed networks",
            Self::Dnstap => "the dnstap settings",
            Self::RpzLists => "lists in the RPZ format",
            Self::Rfc5011 => "the trust anchor read",
            Self::OtlpCompression => "gzip compression of the OpenTelemetry export",
            Self::DnsProviderLedger => "the DNS-provider ownership ledger",
            Self::MemberApiAddress => "the web UI and API address read",
            Self::DnsProviderDelegation => "delegated DNS providers",
        }
    }
}

/// The gated features this build knows, as it announces them in its Hello. A build from before
/// this field announces none, so a development build of the same version number (`1.1.0-edge.N`,
/// `-pr.N`, `-dev`), which refuses the feature, is refused here too.
pub fn own_features() -> Vec<String> {
    ANNOUNCED.iter().map(|f| f.name().to_owned()).collect()
}

/// The features this build handles end to end. `DnsProviders` joined the list in the commit that
/// brought its table (T36.10b): a build cut before then does not know it, and announcing it would
/// let the gate pass a section such a member refuses. `Locations` joined with T36.10a.
const ANNOUNCED: [Feature; 11] = [
    Feature::Locations,
    Feature::DnsProviders,
    Feature::PemSecrets,
    Feature::Access,
    Feature::Dnstap,
    Feature::RpzLists,
    Feature::Rfc5011,
    Feature::OtlpCompression,
    Feature::DnsProviderLedger,
    Feature::MemberApiAddress,
    Feature::DnsProviderDelegation,
];

/// Whether a peer that announced `features` knows `f`. An empty list (a peer older than the
/// field, or one that has not reported yet) knows none.
pub fn knows(features: &[String], f: Feature) -> bool {
    features.iter().any(|n| n == f.name())
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
/// [`Refusal`] naming the members that do not. `members` are `(node ID, build version, announced
/// features)` of the peers (this node's own build is the one asking, so it knows). Named in
/// node-ID order.
pub fn check<'a>(
    members: impl IntoIterator<Item = (&'a str, &'a str, &'a [String])>,
    f: Feature,
) -> Result<(), Refusal> {
    let mut blockers: Vec<Blocker> = members
        .into_iter()
        .filter(|(_, _, feats)| !knows(feats, f))
        .map(|(n, v, _)| Blocker {
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

/// [`check`] over the cluster's members as this node sees them, plus every `registered` member
/// ID (the identity registry, minus this node and removed nodes) not among them: one that has not
/// connected since this process started has not reported, and counts as not knowing.
pub fn check_members(members: &[Member], registered: &[String], f: Feature) -> Result<(), Refusal> {
    let none: Vec<String> = Vec::new();
    check(
        members
            .iter()
            .map(|m| {
                (
                    m.node_id.as_str(),
                    m.version.as_str(),
                    m.features.as_slice(),
                )
            })
            .chain(
                registered
                    .iter()
                    .filter(|id| !members.iter().any(|m| &m.node_id == *id))
                    .map(|id| (id.as_str(), "", none.as_slice())),
            ),
        f,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feats(f: &[Feature]) -> Vec<String> {
        f.iter().map(|f| f.name().to_owned()).collect()
    }

    #[test]
    fn dsc_908_a_peer_knows_what_it_announces_and_nothing_else() {
        assert!(knows(&own_features(), Feature::PemSecrets));
        assert!(knows(&own_features(), Feature::Locations));
        assert!(knows(&feats(&[Feature::Locations]), Feature::Locations));
        assert!(!knows(&feats(&[Feature::Locations]), Feature::PemSecrets));
        assert!(!knows(&[], Feature::Locations));
    }

    // REQ: DSC-908, CLD-904 - a build announces what it handles, and only that: the tables of
    // locations (T36.10a) and DNS providers (T36.10b) are in this build, so it claims them; a member
    // cut before they landed announces neither and is counted as not knowing them.
    #[test]
    fn dsc_908_a_build_announces_only_the_features_it_handles() {
        let own = own_features();
        assert_eq!(
            own,
            vec![
                "locations".to_owned(),
                "dns_providers".to_owned(),
                "pem_secrets".to_owned(),
                "access".to_owned(),
                "dnstap".to_owned(),
                "rpz_lists".to_owned(),
                "rfc5011".to_owned(),
                "otlp_compression".to_owned(),
                "dns_provider_ledger".to_owned(),
                "member_api_address".to_owned(),
                "dns_provider_delegation".to_owned()
            ]
        );
        assert!(knows(&own, Feature::Locations));
        assert!(knows(&own, Feature::DnsProviders));
        assert!(Feature::ALL.iter().all(|f| knows(&own, *f)));
    }

    #[test]
    fn dsc_908_gate_names_the_member_and_its_version() {
        let all = feats(&Feature::ALL);
        let ms = [
            ("pi-b", "1.0.0", &[][..]),
            ("pi-a", "1.1.0", all.as_slice()),
        ];
        let r = check(ms, Feature::Locations).unwrap_err();
        assert_eq!(
            r.to_string(),
            "node pi-b runs version 1.0.0, which does not know locations; upgrade it first"
        );
        let ms = [("pi-b", "1.0.0", &[][..]), ("pi-a", "", &[][..])];
        let r = check(ms, Feature::DnsProviders).unwrap_err();
        assert!(
            r.to_string()
                .starts_with("node pi-a runs an unknown version"),
            "{r}"
        );
        assert!(r.to_string().contains("(1 more member too)"), "{r}");
    }

    // REQ: DSC-908 - development builds of 1.1.0 refuse the feature yet carry the version
    // number, so the number must never decide.
    #[test]
    fn dsc_908_development_builds_without_the_field_are_refused() {
        for v in [
            "1.1.0-edge.40",
            "1.1.0-dev",
            "1.1.0-pr.3",
            "1.1.0",
            "v1.1.0-rc.1",
        ] {
            let r = check([("old", v, &[][..])], Feature::PemSecrets).unwrap_err();
            assert_eq!(r.blockers[0].version, v);
        }
    }

    #[test]
    fn dsc_908_gate_drops_away_once_every_member_knows() {
        let all = feats(&Feature::ALL);
        let ms = [
            ("a", "1.1.0", all.as_slice()),
            ("b", "1.2.0", all.as_slice()),
        ];
        for f in Feature::ALL {
            assert!(check(ms, f).is_ok());
        }
        assert!(check([], Feature::PemSecrets).is_ok());
    }

    // REQ: DSC-908 - a registered member that never connected counts as not knowing.
    #[test]
    fn dsc_908_a_registered_member_that_never_reported_blocks() {
        let r = check_members(&[], &["node-c".to_owned()], Feature::PemSecrets).unwrap_err();
        assert_eq!(r.blockers[0].node, "node-c");
        assert!(r.to_string().contains("unknown version"), "{r}");
        assert!(check_members(&[], &[], Feature::PemSecrets).is_ok());
    }
}
