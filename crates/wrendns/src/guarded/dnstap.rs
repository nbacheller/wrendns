// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: OBS-007, API-905, API-902 (T40.13; ADR-1107 point 4, ADR-956) - the `dnstap` guarded row.
//!
//! The dnstap output copies clients' addresses and names out of the process. A change that copies
//! more of them than before (the tap turned on, another socket or address, the upstream or recursor
//! exchanges added, sampling more often: `wrendns_config::guarded::dnstap_widened`) goes through the
//! guarded flow: the preview, the typed phrase, a sign-in within 10 minutes and the
//! `settings.guarded` audit record. `staged`: the tap and its writer are read once, when the node
//! starts. The value is the whole `[telemetry.dnstap]` section; a field left out takes its default.
//! A change that only narrows is an ordinary admin write (`PUT /api/v1/dnstap-settings/default`).

use serde_json::Value;
use wrendns_api::problem::{Code, Problem};
use wrendns_config::{Config, DnstapConfig};

use super::engine::{Applier, CheckCx, Checked};

/// The most a `buffer` set through the API or the web UI may be (the queue is allocated at its
/// full size when the node starts).
pub(crate) use crate::settings_kinds::DNSTAP_BUFFER_MAX as BUFFER_MAX;

/// The dnstap row's behaviour on a node.
pub(crate) struct Dnstap;

/// The section a value names, with a field left out at its default. `restart_needed` is the read-only
/// field the settings entry shows; it is accepted and never stored.
pub(crate) fn parse(v: &Value) -> Result<DnstapConfig, Problem> {
    let bad = |why: String| Problem::new(Code::InvalidConfig, why);
    let Value::Object(o) = v else {
        return Err(bad("the dnstap value must be an object".to_owned()));
    };
    let mut o = o.clone();
    o.remove("restart_needed");
    if let Some(k) = o.keys().find(|k| {
        !matches!(
            k.as_str(),
            "socket" | "address" | "sample_every" | "buffer" | "forwarder" | "resolver"
        )
    }) {
        return Err(bad(format!("`{k}` isn't a dnstap field")));
    }
    // An empty reader is no reader.
    for k in ["socket", "address"] {
        if o.get(k)
            .is_some_and(|x| x.is_null() || x.as_str().is_some_and(|s| s.trim().is_empty()))
        {
            o.remove(k);
        }
    }
    for k in ["sample_every", "buffer", "forwarder", "resolver"] {
        if o.get(k).is_some_and(Value::is_null) {
            o.remove(k);
        }
    }
    serde_json::from_value::<DnstapConfig>(Value::Object(o)).map_err(|e| bad(e.to_string()))
}

/// The mode of an entry an ordinary admin write stored (a change that copies no more than the node
/// would run): unlike a reviewed one it was never confirmed with the phrase, so it is applied only
/// while it still copies no more than the files do ([`unconfirmed_widens`]).
pub(crate) const NARROWED: &str = "narrowed";

/// The fields of `[telemetry.dnstap]` the files set (`own.file_set` names them). The reader is one
/// choice, a socket or an address: a file that sets either one sets both.
pub(crate) fn file_fields(own: &Config) -> Vec<&'static str> {
    let set = |k: &str| {
        own.file_set
            .iter()
            .any(|f| f.strip_prefix("telemetry.dnstap.") == Some(k))
    };
    let reader = set("socket") || set("address");
    [
        "socket",
        "address",
        "sample_every",
        "buffer",
        "forwarder",
        "resolver",
    ]
    .into_iter()
    .filter(|k| {
        if matches!(*k, "socket" | "address") {
            reader
        } else {
            set(k)
        }
    })
    .collect()
}

/// REQ: OBS-007, API-905 (T40.13, review) - whether an entry that was never confirmed with the phrase
/// (an ordinary narrowing) would, laid over `own`'s files as they are now, copy more than the files
/// do. The files may have changed since it was written (the tap taken out, a feed or a socket added),
/// and such an entry may never turn into a widening: it is then not applied.
pub(crate) fn unconfirmed_widens(own: &Config, value: &Value) -> bool {
    let mut cfg = own.clone();
    if let Ok(d) = parse(value) {
        cfg.telemetry.dnstap = d;
    }
    keep_file_fields(&mut cfg, own);
    wrendns_config::guarded::dnstap_widened(
        &json_of(&own.telemetry.dnstap),
        &json_of(&cfg.telemetry.dnstap),
    )
}

/// REQ: OBS-007, API-905 (T40.13, review) - whether an entry of `mode` is not to be applied over
/// `own`'s files as they are now. An ordinary narrowing is not applied while it would copy more than
/// the files. A confirmed one (the phrase) confirmed only what it says: the files lay their own
/// fields over it (`keep_file_fields`), and files never widen a confirmed entry. So it is not applied
/// when the merged section copies more than the entry confirmed AND more than the files alone do
/// (a file reader that displaces the entry's, or a feed or a sampling the file added).
pub(crate) fn not_applied(own: &Config, mode: &str, value: &Value) -> bool {
    if mode == NARROWED {
        return unconfirmed_widens(own, value);
    }
    let Ok(d) = parse(value) else { return false };
    let mut cfg = own.clone();
    cfg.telemetry.dnstap = d.clone();
    keep_file_fields(&mut cfg, own);
    let merged = json_of(&cfg.telemetry.dnstap);
    wrendns_config::guarded::dnstap_widened(&json_of(&d), &merged)
        && wrendns_config::guarded::dnstap_widened(&json_of(&own.telemetry.dnstap), &merged)
}

/// REQ: OBS-007, API-905 (T40.13) - whether `value` changes a field the files set (a value that
/// leaves the files' fields as they are is not locked by them).
pub(crate) fn changes_file_field(file: &Config, value: &Value) -> bool {
    let Ok(new) = parse(value) else {
        // `check` says what is wrong with it.
        return false;
    };
    let (want, have) = (json_of(&new), json_of(&file.telemetry.dnstap));
    file_fields(file)
        .into_iter()
        .any(|k| want.get(k) != have.get(k))
}

/// Puts the fields the files set back as the files have them, after a value was laid over.
pub(crate) fn keep_file_fields(cfg: &mut Config, own: &Config) {
    let mut now = json_of(&cfg.telemetry.dnstap);
    let theirs = json_of(&own.telemetry.dnstap);
    if let Value::Object(o) = &mut now {
        for k in file_fields(own) {
            match theirs.get(k) {
                Some(v) => {
                    o.insert(k.to_owned(), v.clone());
                }
                None => {
                    o.remove(k);
                }
            }
        }
    }
    if let Ok(d) = serde_json::from_value::<DnstapConfig>(now) {
        cfg.telemetry.dnstap = d;
    }
}

fn json_of(d: &DnstapConfig) -> Value {
    serde_json::to_value(d).unwrap_or(Value::Null)
}

fn describe(d: &DnstapConfig) -> String {
    match (&d.socket, &d.address) {
        (None, None) => "no tap".to_owned(),
        (s, a) => {
            let target = s
                .as_ref()
                .or(a.as_ref())
                .map_or_else(String::new, ToString::to_string);
            format!(
                "copying to {target}, one query in {}, up to {} held, upstream exchanges {}, recursor exchanges {}",
                d.sample_every,
                d.buffer,
                if d.forwarder { "on" } else { "off" },
                if d.resolver { "on" } else { "off" },
            )
        }
    }
}

impl Applier for Dnstap {
    fn current(&self, cfg: &Config) -> Value {
        json_of(&cfg.telemetry.dnstap)
    }

    fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
        let new = parse(cx.value)?;
        // The ceiling is for what the API and the card set: a larger value the file already has,
        // sent back as read, is no new setting.
        if u64::from(new.buffer) > BUFFER_MAX && new.buffer != cx.cfg.telemetry.dnstap.buffer {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!("`buffer`: at most {BUFFER_MAX}"),
            ));
        }
        // The same for a socket: an absolute path (a file that has a relative one still loads).
        if let Some(sock) = &new.socket
            && !sock.starts_with('/')
            && new.socket != cx.cfg.telemetry.dnstap.socket
        {
            return Err(Problem::new(
                Code::InvalidConfig,
                "`socket`: use an absolute path (for example /run/dnstap.sock)",
            ));
        }
        if let Some(a) = &new.address
            && !wrendns_config::dnstap_address_ok(a)
            && new.address != cx.cfg.telemetry.dnstap.address
        {
            return Err(Problem::new(
                Code::InvalidConfig,
                "`address`: use tcp://host:port, with a host name or an IP address (an IPv6 one in brackets)",
            ));
        }
        let mut c = cx.cfg.clone();
        c.telemetry.dnstap = new.clone();
        if let Err(errs) = wrendns_config::validate_config(&c) {
            let dnstap: Vec<String> = errs
                .iter()
                .filter(|e| e.path.starts_with("telemetry.dnstap"))
                .map(ToString::to_string)
                .collect();
            if !dnstap.is_empty() {
                return Err(Problem::new(Code::InvalidConfig, dnstap.join("; ")));
            }
        }
        let widened =
            wrendns_config::guarded::dnstap_widened(&self.current(cx.cfg), &json_of(&new));
        let mut warnings = vec![format!(
            "dnstap is read when a node starts: this takes effect after {} restarts. Other nodes keep their own dnstap settings.",
            cx.node
        )];
        if widened {
            warnings.push(
                "This copies more of the clients' queries (their addresses and names) out of the process than before.".to_owned(),
            );
        }
        Ok(Checked {
            effect: format!(
                "Sets the dnstap output on {} to: {}. It takes effect at the node's next start.",
                cx.node,
                describe(&new)
            ),
            restart_required: true,
            warnings,
            weakening: widened,
            ..Checked::default()
        })
    }

    fn overlay(&self, cfg: &mut Config, value: &Value) {
        if let Ok(d) = parse(value) {
            cfg.telemetry.dnstap = d;
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wrendns_api::auth::Actor;
    use wrendns_api::guarded::GuardedCaller;

    use super::*;

    fn caller() -> GuardedCaller {
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
            remote: None,
            remote_under_pending: None,
            tls: false,
        }
    }

    fn check(cfg: &Config, value: &Value) -> Result<Checked, Problem> {
        let (options, c) = (Value::Null, caller());
        Dnstap.check(&CheckCx {
            cfg,
            node: "pi-a",
            value,
            options: &options,
            caller: &c,
            host: &super::super::host::StubHost::default(),
            access: None,
        })
    }

    // REQ: OBS-007, API-905 (T40.13) - a field left out takes its default; an unknown field, a
    // value that is not an object and both a socket and an address are refused.
    #[test]
    fn obs_007_dnstap_value_parses() {
        let d = parse(&json!({"socket": "/run/dnstap.sock"})).unwrap();
        assert_eq!(d.sample_every, 1);
        assert_eq!(d.buffer, 10_000);
        assert!(!d.forwarder && !d.resolver);
        // An empty or null reader is none; the read-only field is accepted and dropped.
        let off = parse(&json!({"socket": "", "address": null, "restart_needed": true})).unwrap();
        assert!(off.socket.is_none() && off.address.is_none());
        assert!(parse(&json!({"nope": 1})).is_err());
        assert!(parse(&json!([1])).is_err());
        assert!(parse(&json!({"sample_every": "x"})).is_err());
        let cfg = Config::default();
        assert!(
            check(
                &cfg,
                &json!({"socket": "/a", "address": "tcp://192.0.2.5:6000"})
            )
            .is_err()
        );
        assert!(check(&cfg, &json!({"address": "192.0.2.5"})).is_err());
        assert!(check(&cfg, &json!({"sample_every": 0})).is_err());
        assert!(check(&cfg, &json!({"buffer": 50})).is_err());
    }

    // REQ: OBS-007, API-905 (T40.13) - the dry run says it weakens exactly when the copy widens, that
    // it is read at the next start, and what it sets.
    #[test]
    fn obs_007_dnstap_dry_run_judges_widening() {
        let cfg = Config::default();
        let on = check(&cfg, &json!({"socket": "/run/dnstap.sock"})).unwrap();
        assert!(on.weakening && on.restart_required);
        assert!(on.effect.contains("/run/dnstap.sock") && on.effect.contains("next start"));
        assert!(
            on.warnings
                .iter()
                .any(|w| w.contains("addresses and names"))
        );
        // Nothing changes: not a widening.
        let same = check(&cfg, &json!({})).unwrap();
        assert!(!same.weakening);
        // From a running tap: off, sampling less often and a feed off narrow.
        let mut running = Config::default();
        running.telemetry.dnstap = parse(&json!({
            "socket": "/run/dnstap.sock", "sample_every": 2, "forwarder": true
        }))
        .unwrap();
        for narrow in [
            json!({}),
            json!({"socket": "/run/dnstap.sock", "sample_every": 5, "forwarder": true}),
            json!({"socket": "/run/dnstap.sock", "sample_every": 2}),
        ] {
            let c = check(&running, &narrow).unwrap();
            assert!(!c.weakening, "{narrow}");
        }
        for wider in [
            json!({"socket": "/run/other.sock", "sample_every": 2, "forwarder": true}),
            json!({"socket": "/run/dnstap.sock", "sample_every": 1, "forwarder": true}),
            json!({"socket": "/run/dnstap.sock", "sample_every": 2, "forwarder": true, "resolver": true}),
        ] {
            assert!(check(&running, &wider).unwrap().weakening, "{wider}");
        }
    }

    // REQ: OBS-007, API-905 (T40.13) - the buffer ceiling is for what the API and the card set: a
    // larger value the file already has, sent back as read, is accepted.
    #[test]
    fn obs_007_dnstap_buffer_ceiling_for_api_values_only() {
        let cfg = Config::default();
        let over = json!({"socket": "/a", "buffer": 1_000_001});
        assert!(check(&cfg, &over).is_err());
        assert!(check(&cfg, &json!({"socket": "/a", "buffer": 1_000_000})).is_ok());
        let mut file = Config::default();
        file.telemetry.dnstap = parse(&over).unwrap();
        assert!(check(&file, &over).is_ok(), "the file's own value");
        assert!(check(&file, &json!({"socket": "/a", "buffer": 2_000_000})).is_err());
    }

    // REQ: OBS-007, API-905 (T40.13) - the stored value enters the merged configuration; an
    // unreadable one leaves the configuration alone.
    #[test]
    fn obs_007_dnstap_overlay() {
        let mut cfg = Config::default();
        Dnstap.overlay(
            &mut cfg,
            &json!({"address": "tcp://192.0.2.5:6000", "sample_every": 4}),
        );
        assert_eq!(
            cfg.telemetry.dnstap.address.as_deref(),
            Some("tcp://192.0.2.5:6000")
        );
        assert_eq!(cfg.telemetry.dnstap.sample_every, 4);
        Dnstap.overlay(&mut cfg, &json!({"sample_every": "x"}));
        assert_eq!(cfg.telemetry.dnstap.sample_every, 4);
        assert_eq!(Dnstap.current(&cfg)["sample_every"], 4);
    }
}
