// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, API-901 (T27.14f; ADR-914, ADR-956, ADR-977 point 7 as amended 2026-11-27, ADR-1098) -
//! the `trusted-proxies` guarded row: `[api] trusted_proxies`, the hosts whose `X-Forwarded-For` the
//! node believes.
//!
//! A `window` row proved by `proxy_list`. Nothing is bound: staging only records the new list, which
//! the confirm route alone uses to judge the confirming request (the list in force keeps serving
//! break-glass networks, loopback checks, rate limits and the audit source until the change is
//! confirmed). Confirming writes the entry and reloads the node, and a reload swaps the live list
//! (`Auth::set_trusted_proxies`); an unconfirmed change never reaches it, so a rollback has nothing to
//! undo. Adding an entry weakens (`wrendns_config::guarded::proxies_added`). The value is
//! `{"proxies": ["10.0.0.0/8", "203.0.113.7"]}`.

use std::net::IpAddr;
use std::sync::Arc;

use serde_json::{Value, json};
use wrendns_api::BoxFuture;
use wrendns_api::problem::{Code, Problem};
use wrendns_config::{Cidr, Config};

use super::engine::{Applier, CheckCx, Checked, Staged, WindowGuard};
use super::host::Host;

/// The trusted proxies row's behaviour on a node.
pub(crate) struct TrustedProxies;

fn bad(why: impl Into<String>) -> Problem {
    Problem::new(Code::InvalidConfig, why)
}

/// The list in a value: `{"proxies": [text, ...]}`, each entry an address or a network. A field other
/// than `proxies`, an entry that is not an address or network, and two entries for one network are
/// refused.
pub(crate) fn parse(v: &Value) -> Result<Vec<Cidr>, Problem> {
    let Value::Object(o) = v else {
        return Err(bad("the value must be an object with a `proxies` list"));
    };
    if let Some(k) = o.keys().find(|k| k.as_str() != "proxies") {
        return Err(bad(format!("`{k}` isn't a trusted-proxies field")));
    }
    let Some(Value::Array(list)) = o.get("proxies") else {
        return Err(bad("`proxies` must be a list of addresses or networks"));
    };
    let mut out: Vec<Cidr> = Vec::with_capacity(list.len());
    for (i, e) in list.iter().enumerate() {
        let Value::String(s) = e else {
            return Err(bad(format!("`proxies[{i}]` must be text")));
        };
        let c = Cidr::parse(s).map_err(|e| bad(format!("`proxies[{i}]`: {e}")))?;
        if out.iter().any(|x| x.network() == c.network()) {
            return Err(bad(format!(
                "`proxies[{i}]`: `{}` is listed twice",
                c.network()
            )));
        }
        out.push(c);
    }
    Ok(out)
}

fn pairs(list: &[Cidr]) -> Vec<(IpAddr, u8)> {
    list.iter().map(|c| (c.addr, c.prefix)).collect()
}

fn holds(list: &[Cidr], ip: IpAddr) -> bool {
    list.iter()
        .any(|c| wrendns_api::auth::in_network(ip, c.addr, c.prefix))
}

fn words(list: &[Cidr]) -> String {
    if list.is_empty() {
        "no proxy".to_owned()
    } else {
        list.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Applier for TrustedProxies {
    fn current(&self, cfg: &Config) -> Value {
        json!({"proxies": cfg.api.trusted_proxies.iter().map(ToString::to_string).collect::<Vec<_>>()})
    }

    fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
        let new = parse(cx.value)?;
        let old = &cx.cfg.api.trusted_proxies;
        let mut warnings = Vec::new();
        for c in &new {
            let already = old.iter().any(|o| o.network() == c.network());
            if already {
                continue;
            }
            if c.prefix == 0 {
                warnings.push(format!(
                    "`{c}` trusts every host: any client could then put any address in X-Forwarded-For and be believed (sign-in lockouts, the break-glass networks and the audit log would all take its word)."
                ));
            } else if c.includes_public() {
                warnings.push(format!(
                    "`{c}` includes public addresses: a host there could choose the address the node sees for its requests. List only your own proxy or ingress."
                ));
            }
        }
        // The address the node sees for this request today, and what the new list does to it.
        let seen = cx.caller.peer.and(cx.caller.remote);
        if let Some(peer) = cx.caller.peer {
            let (was, will) = (holds(old, peer), holds(&new, peer));
            if was && !will {
                warnings.push(format!(
                    "This request came in through {peer}, which the new list leaves out. The node would then see {peer} as your address, and the change could not be confirmed from this browser: it rolls back when the window ends."
                ));
            } else if !was && will {
                warnings.push(format!(
                    "Your own address ({peer}) is inside the new list, so the node would believe an X-Forwarded-For header from it. The change passes its check only for a request that arrives through a proxy that sets the header; a direct request from {peer} does not."
                ));
            }
        }
        warnings.push(format!(
            "Until you confirm, the new list is used only to judge the confirming request. Everything else on {} (sign-in lockouts, the break-glass networks, the audit log) keeps the list in force today.",
            cx.node
        ));
        Ok(Checked {
            effect: format!(
                "Sets the trusted proxies on {} to {} (today: {}). It takes effect at once, and is kept only if you confirm it within the window; otherwise it is dropped.",
                cx.node,
                words(&new),
                words(old)
            ),
            warnings,
            seen_client: seen.map(|a| a.to_string()),
            ..Checked::default()
        })
    }

    fn overlay(&self, cfg: &mut Config, value: &Value) {
        if let Ok(list) = parse(value) {
            cfg.api.trusted_proxies = list;
        }
    }

    fn stage(
        &self,
        host: Arc<dyn Host>,
        node: String,
        value: Value,
        _access: Option<Value>,
        _facts: Option<wrendns_config::HostFacts>,
    ) -> BoxFuture<Result<Staged, Problem>> {
        Box::pin(std::future::ready(parse(&value).map(|list| {
            // The same digest the stored entry has, for a replica to wait until it came back.
            let digest = super::hex(
                blake3::hash(&serde_json::to_vec(&value).unwrap_or_default()).as_bytes(),
            );
            Staged {
                pending_proxies: Some(pairs(&list)),
                guard: Arc::new(ProxiesGuard {
                    host,
                    node,
                    digest,
                    list,
                }),
                proof_addr: None,
                new_address: None,
                dns_probes: Vec::new(),
            }
        })))
    }
}

/// What stays pending while a proxy list waits: nothing is open, so aborting is nothing to undo, and
/// committing reloads the node (which puts the stored list in force) and checks that it did.
struct ProxiesGuard {
    host: Arc<dyn Host>,
    node: String,
    digest: String,
    list: Vec<Cidr>,
}

impl WindowGuard for ProxiesGuard {
    fn commit(&self) -> BoxFuture<Result<(), Problem>> {
        let host = Arc::clone(&self.host);
        let (node, digest) = (self.node.clone(), self.digest.clone());
        let want: Vec<Cidr> = self.list.iter().map(Cidr::network).collect();
        Box::pin(async move {
            // On a replica the entry comes back through the primary; the wait keeps the answer honest.
            let _ = host
                .wait_applied(
                    &node,
                    wrendns_config::guarded::TRUSTED_PROXIES,
                    Some(digest),
                )
                .await;
            if !host.reload().await {
                return Err(Problem::unavailable(
                    "the node couldn't apply the new proxy list",
                ));
            }
            // A configuration file that sets the list wins over the entry: then nothing changed.
            let have: Vec<Cidr> = host
                .running_config()
                .api
                .trusted_proxies
                .iter()
                .map(Cidr::network)
                .collect();
            let same = have.len() == want.len() && want.iter().all(|w| have.contains(w));
            if same {
                Ok(())
            } else {
                Err(Problem::unavailable(
                    "the node is not running the new proxy list (a configuration file may set it)",
                ))
            }
        })
    }

    fn abort(&self) -> BoxFuture<()> {
        // The new list was never in force: nothing to put back.
        Box::pin(std::future::ready(()))
    }
}

#[cfg(test)]
mod tests {
    use wrendns_api::auth::Actor;
    use wrendns_api::guarded::GuardedCaller;

    use super::super::host::StubHost;
    use super::*;

    fn caller(peer: Option<&str>, seen: Option<&str>) -> GuardedCaller {
        GuardedCaller {
            actor: Actor {
                name: "admin".to_owned(),
                kind: "session",
                remote: None,
                reason: None,
            },
            username: "admin".to_owned(),
            session: None,
            signed_in_at: None,
            arrived_on: None,
            remote: seen.map(|s| s.parse().unwrap()),
            remote_under_pending: None,
            peer: peer.map(|s| s.parse().unwrap()),
            tls: false,
        }
    }

    fn cfg_with(list: &[&str]) -> Config {
        let mut c = Config::default();
        c.api.trusted_proxies = list.iter().map(|s| Cidr::parse(s).unwrap()).collect();
        c
    }

    fn check(cfg: &Config, value: &Value, c: &GuardedCaller) -> Result<Checked, Problem> {
        let options = Value::Null;
        TrustedProxies.check(&CheckCx {
            cfg,
            node: "pi-a",
            value,
            options: &options,
            caller: c,
            host: &StubHost::default(),
            access: None,
        })
    }

    // REQ: API-902 (T27.14f) - the value is `{"proxies": [...]}`: a bad entry, a duplicate network, a
    // field that is not `proxies` and a value that is not an object are refused, with the entry named.
    #[test]
    fn api_902_trusted_proxies_refusal_table() {
        let c = caller(None, None);
        let cfg = Config::default();
        for bad in [
            json!(["10.0.0.0/8"]),
            json!({}),
            json!({"proxies": "10.0.0.0/8"}),
            json!({"proxies": [1]}),
            json!({"proxies": ["not-an-ip"]}),
            json!({"proxies": ["10.0.0.0/33"]}),
            json!({"proxies": ["10.0.0.0/8", "10.1.2.3/8"]}),
            json!({"proxies": ["10.0.0.0/8"], "extra": 1}),
            json!({"proxies": ["10.0.0.0/8/9"]}),
            json!({"proxies": [""]}),
        ] {
            assert!(check(&cfg, &bad, &c).is_err(), "{bad}");
        }
        let e = check(&cfg, &json!({"proxies": ["10.0.0.0/8", "nope"]}), &c).unwrap_err();
        assert!(e.detail.contains("proxies[1]"), "{}", e.detail);
        for good in [
            json!({"proxies": []}),
            json!({"proxies": ["10.0.0.0/8", "fd00::/8", "192.0.2.7"]}),
        ] {
            assert!(check(&cfg, &good, &c).is_ok(), "{good}");
        }
    }

    // REQ: API-902 (T27.14f) - the review shows the address the node sees today (only for a request that
    // reached the node itself), warns about a public range, `0.0.0.0/0` and `::/0`, and about a list
    // that drops the proxy the request came through.
    #[test]
    fn api_902_trusted_proxies_review_warnings_and_seen_address() {
        let cfg = cfg_with(&["10.0.0.2"]);
        let through = caller(Some("10.0.0.2"), Some("192.168.1.20"));
        let c = check(&cfg, &json!({"proxies": ["10.0.0.2"]}), &through).unwrap();
        assert_eq!(c.seen_client.as_deref(), Some("192.168.1.20"));
        assert!(!c.warnings.iter().any(|w| w.contains("leaves out")));
        let c = check(&cfg, &json!({"proxies": []}), &through).unwrap();
        assert!(
            c.warnings
                .iter()
                .any(|w| w.contains("10.0.0.2, which the new list leaves out"))
        );
        // A request the primary relayed has no peer: no "seen as" line.
        let relayed = caller(None, Some("192.168.1.20"));
        assert!(
            check(&cfg, &json!({"proxies": []}), &relayed)
                .unwrap()
                .seen_client
                .is_none()
        );
        // Public ranges and the two "everything" ranges.
        let direct = caller(Some("192.168.1.20"), Some("192.168.1.20"));
        let empty = Config::default();
        for (entry, word) in [
            ("203.0.113.0/24", "public addresses"),
            ("0.0.0.0/0", "every host"),
            ("::/0", "every host"),
        ] {
            let c = check(&empty, &json!({"proxies": [entry]}), &direct).unwrap();
            assert!(c.warnings.iter().any(|w| w.contains(word)), "{entry}");
        }
        let c = check(&empty, &json!({"proxies": ["10.0.0.0/8"]}), &direct).unwrap();
        assert!(!c.warnings.iter().any(|w| w.contains("public")));
        // An address already listed warns no more.
        let c = check(
            &cfg_with(&["0.0.0.0/0"]),
            &json!({"proxies": ["0.0.0.0/0"]}),
            &direct,
        )
        .unwrap();
        assert!(!c.warnings.iter().any(|w| w.contains("every host")));
        // The admin's own address inside the new list.
        let c = check(&empty, &json!({"proxies": ["192.168.1.0/24"]}), &direct).unwrap();
        assert!(c.warnings.iter().any(|w| w.contains("Your own address")));
    }

    // REQ: API-902 (T27.14f) - the stored value enters the merged configuration; an unreadable one
    // leaves it alone; `current` reads back what the node runs, in the same shape.
    #[test]
    fn api_902_trusted_proxies_overlay_and_current() {
        let mut cfg = Config::default();
        TrustedProxies.overlay(&mut cfg, &json!({"proxies": ["10.0.0.0/8", "192.0.2.7"]}));
        assert_eq!(cfg.api.trusted_proxies.len(), 2);
        TrustedProxies.overlay(&mut cfg, &json!({"proxies": [7]}));
        assert_eq!(cfg.api.trusted_proxies.len(), 2);
        assert_eq!(
            TrustedProxies.current(&cfg),
            json!({"proxies": ["10.0.0.0/8", "192.0.2.7/32"]})
        );
    }

    // REQ: API-902 (T27.14f) - staging records the new list for the confirm route and binds nothing;
    // a commit succeeds only when the node then runs that list, and an abort does nothing.
    #[tokio::test]
    async fn api_902_trusted_proxies_stage_and_commit() {
        let value = json!({"proxies": ["10.0.0.0/8"]});
        let ok = Arc::new(StubHost::default());
        *ok.cfg.lock().unwrap() = Some(Arc::new(cfg_with(&["10.0.0.0/8"])));
        let staged = TrustedProxies
            .stage(ok.clone(), "pi-a".to_owned(), value.clone(), None, None)
            .await
            .unwrap();
        assert_eq!(
            staged.pending_proxies,
            Some(vec![("10.0.0.0".parse().unwrap(), 8)])
        );
        assert!(staged.proof_addr.is_none() && staged.dns_probes.is_empty());
        assert!(staged.guard.commit().await.is_ok());
        staged.guard.abort().await;
        // The node still runs another list (a file sets it): the commit is refused.
        let other = Arc::new(StubHost::default());
        let staged = TrustedProxies
            .stage(other, "pi-a".to_owned(), value, None, None)
            .await
            .unwrap();
        assert!(staged.guard.commit().await.is_err());
        // A bad value stages nothing.
        assert!(
            TrustedProxies
                .stage(
                    Arc::new(StubHost::default()),
                    "pi-a".to_owned(),
                    json!({"proxies": ["x"]}),
                    None,
                    None
                )
                .await
                .is_err()
        );
    }
}
