// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DNS-906 (T40.5) — this node's root trust anchors as the API and the health summary show
//! them. The state itself is `wrendns_upstream::rfc5011::Rollover`.

use wrendns_api::model::{TrustAnchorKey, TrustAnchorStatus};
use wrendns_upstream::rfc5011::{Mode, Rollover};

/// This node's anchors. Keys are listed only while the node follows the root (a file or no
/// validation has no keys of its own to show).
pub(crate) fn status(r: &Rollover) -> TrustAnchorStatus {
    let s = r.status();
    let following = s.mode == Mode::Following;
    TrustAnchorStatus {
        node: None,
        mode: s.mode.label().to_owned(),
        keys: if following {
            s.anchors
                .iter()
                .map(|a| TrustAnchorKey {
                    key_tag: a.key_tag,
                    algorithm: a.algorithm,
                    flags: a.flags,
                    state: a.state.label().to_owned(),
                    since_s: (a.since > 0).then_some(a.since),
                    trusted_at_s: a.trusted_at,
                })
                .collect()
        } else {
            Vec::new()
        },
        last_reading_s: if following { s.last_reading } else { None },
        next_reading_s: s.next_reading,
        last_error: if following { s.last_error } else { None },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrendns_upstream::rfc5011::{KeyEntry, KeyState};

    /// REQ: DNS-906 - the view shows a pending key with the end of its hold-down, and nothing
    /// for a node that does not follow the root.
    #[test]
    fn dns_906_the_view_shows_keys_only_while_following() {
        let key = |state, since| KeyEntry {
            algorithm: 8,
            flags: 257,
            public: vec![1, 2, 3, 4],
            state,
            since,
        };
        let r = Rollover::from_keys(vec![key(KeyState::Valid, 0), {
            let mut k = key(KeyState::AddPend, 1_000);
            k.public = vec![9, 9, 9, 9];
            k
        }]);
        r.set_mode(Mode::Following);
        let v = status(&r);
        assert_eq!(v.mode, "following");
        assert_eq!(v.keys.len(), 2);
        let built_in = v.keys.iter().find(|k| k.state == "valid").unwrap();
        assert_eq!(built_in.since_s, None, "never changed: no date");
        let pending = v.keys.iter().find(|k| k.state == "add_pend").unwrap();
        assert_eq!(pending.since_s, Some(1_000));
        assert_eq!(pending.trusted_at_s, Some(1_000 + 30 * 86_400));
        r.set_mode(Mode::File);
        let v = status(&r);
        assert_eq!((v.mode.as_str(), v.keys.len()), ("file", 0));
        r.set_mode(Mode::Off);
        assert_eq!(status(&r).mode, "off");
    }
}
