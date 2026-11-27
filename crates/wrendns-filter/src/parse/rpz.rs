// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: FLT-906 (T40.9, ADR-1110) - a response policy zone (RPZ) read as a list.
//!
//! The text is a DNS master file. Only QNAME triggers become rules:
//!
//! | record | rule |
//! |---|---|
//! | `name CNAME .` | block `name` (the name only) with `$dnsrewrite=NXDOMAIN` |
//! | `name CNAME *.` | the same with `$dnsrewrite=NOERROR;;` (the name exists, no data) |
//! | `name CNAME rpz-passthru.` | allow `name`, and an exception that turns this zone's rewrites off for it |
//! | `name CNAME rpz-drop.` | block with `$dnsrewrite=REFUSED` (ADR-1110: the client gets an immediate refusal, never silence) |
//! | `name CNAME target.` | rewrite to the CNAME `target` |
//! | `name A` / `AAAA` | rewrite to the address |
//! | `*.name <action>` | the same, for the names below `name` (not `name` itself) |
//!
//! A plain `name` trigger covers the name only (RPZ semantics), `*.name` the subtree below it.
//! Response-IP (`*.rpz-ip`), NSDNAME, NSIP and client-IP triggers, `rpz-tcp-only.`, and every
//! other record type are counted as unsupported, not errors. SOA, NS and DNSSEC records of the
//! zone itself, `$TTL` and `$ORIGIN` are accepted and ignored (the origin is only used to cut
//! it from absolute owner names).
//!
//! Records may span lines in parentheses and omit their owner (the previous one is used); a
//! rule's line number is the first line of its record.

use super::modifiers::Modifiers;
use super::name::normalize;
use super::{Action, ParseStats, Pattern, Rule, Scope, sample};

/// Parses a whole zone, calling `sink(first_line_of_record, rule)` for every rule.
pub(super) fn parse(data: &[u8], mut sink: impl FnMut(u32, Rule)) -> ParseStats {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let data = data.strip_suffix(b"\n").unwrap_or(data);
    let mut stats = ParseStats::default();
    if data.is_empty() {
        return stats;
    }
    let mut zone = State::default();
    // The record being gathered across lines: its first line, its text, and the open `(`.
    let mut open: Option<(u32, String, i32)> = None;
    for (i, raw) in data.split(|&b| b == b'\n').enumerate() {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        let line_no = u32::try_from(i + 1).unwrap_or(u32::MAX);
        let text = String::from_utf8_lossy(raw);
        stats.lines += 1;
        let (body, depth) = strip_comment(&text);
        if let Some((first, mut acc, mut open_depth)) = open.take() {
            // A continuation line of a parenthesised record.
            stats.ignored += 1;
            acc.push(' ');
            acc.push_str(&body);
            open_depth += depth;
            if open_depth > 0 {
                open = Some((first, acc, open_depth));
            } else {
                finish(&mut zone, first, &acc, &mut stats, &mut sink);
            }
            continue;
        }
        if body.trim().is_empty() {
            if text.trim().is_empty() {
                stats.blank += 1;
            } else {
                stats.comments += 1;
            }
            continue;
        }
        if depth > 0 {
            open = Some((line_no, body, depth));
            continue;
        }
        finish(&mut zone, line_no, &body, &mut stats, &mut sink);
    }
    if let Some((first, acc, _)) = open {
        // An unclosed parenthesis at the end: read what there is.
        finish(&mut zone, first, &acc, &mut stats, &mut sink);
    }
    stats
}

#[derive(Default)]
struct State {
    /// The last owner name written (a line starting with white space reuses it).
    owner: Option<String>,
    /// The zone's name, from `$ORIGIN` or the owner of its SOA, lowercase without a final dot.
    origin: Option<String>,
}

/// The line without its `;` comment (outside quotes), and its `(` minus its `)`.
fn strip_comment(line: &str) -> (String, i32) {
    let mut out = String::with_capacity(line.len());
    let mut quoted = false;
    let mut escaped = false;
    let mut depth = 0;
    for c in line.chars() {
        if escaped {
            escaped = false;
            out.push(c);
            continue;
        }
        match c {
            '\\' => {
                escaped = true;
                out.push(c);
            }
            '"' => {
                quoted = !quoted;
                out.push(c);
            }
            ';' if !quoted => break,
            '(' if !quoted => {
                depth += 1;
                out.push(' ');
            }
            ')' if !quoted => {
                depth -= 1;
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    (out, depth)
}

/// Reads one complete record (or directive) and counts its outcome.
fn finish(
    zone: &mut State,
    line_no: u32,
    body: &str,
    stats: &mut ParseStats,
    sink: &mut impl FnMut(u32, Rule),
) {
    let inherits = body.starts_with([' ', '\t']);
    let mut tokens = tokenize(body);
    if tokens.is_empty() {
        stats.comments += 1;
        return;
    }
    if !inherits && tokens[0].starts_with('$') {
        directive(zone, &tokens, line_no, body, stats);
        return;
    }
    let owner = if inherits {
        let Some(o) = zone.owner.clone() else {
            stats.invalid += 1;
            sample(
                stats,
                line_no,
                body,
                "record without an owner name".into(),
                false,
            );
            return;
        };
        o
    } else {
        tokens.remove(0)
    };
    zone.owner = Some(owner.clone());
    // [ttl] [class] type rdata..., the ttl and class in either order.
    let mut i = 0;
    while i < tokens.len() && i < 2 && (is_ttl(&tokens[i]) || is_class(&tokens[i])) {
        i += 1;
    }
    let Some(rtype) = tokens.get(i).map(|t| t.to_ascii_uppercase()) else {
        stats.invalid += 1;
        sample(stats, line_no, body, "record without a type".into(), false);
        return;
    };
    let rdata = &tokens[i + 1..];
    let owner_l = owner.to_ascii_lowercase();
    match rtype.as_str() {
        "SOA" => {
            // The zone's own name, for cutting it from absolute owners.
            if zone.origin.is_none() && owner_l.ends_with('.') && owner_l != "." {
                zone.origin = Some(owner_l.trim_end_matches('.').to_owned());
            }
            stats.ignored += 1;
        }
        "NS" | "RRSIG" | "NSEC" | "NSEC3" | "NSEC3PARAM" | "DNSKEY" | "DS" => stats.ignored += 1,
        "CNAME" | "A" | "AAAA" => {
            let outcome = record(zone, &owner_l, &rtype, rdata);
            match outcome {
                Outcome::Rule(rule) => {
                    stats.rules += 1;
                    if rule.action == Action::Allow {
                        // A passthru also turns off the zone's rewrites for its names (the
                        // matcher lets a rewrite win over blocking, not over this exception).
                        let mut off = rule.clone();
                        off.modifiers.dnsrewrite = Some(String::new());
                        sink(line_no, off);
                    }
                    sink(line_no, rule);
                }
                Outcome::Ignored => stats.ignored += 1,
                Outcome::Unsupported(why) => {
                    stats.unsupported += 1;
                    sample(stats, line_no, body, why, true);
                }
                Outcome::Invalid(why) => {
                    stats.invalid += 1;
                    sample(stats, line_no, body, why, false);
                }
            }
        }
        other => {
            stats.unsupported += 1;
            sample(
                stats,
                line_no,
                body,
                format!("`{other}` records are not applied (only CNAME, A and AAAA)"),
                true,
            );
        }
    }
}

fn directive(
    zone: &mut State,
    tokens: &[String],
    line_no: u32,
    body: &str,
    stats: &mut ParseStats,
) {
    match tokens[0].to_ascii_uppercase().as_str() {
        "$TTL" => stats.ignored += 1,
        "$ORIGIN" => {
            if let Some(o) = tokens.get(1).filter(|o| o.ends_with('.')) {
                zone.origin = Some(o.to_ascii_lowercase().trim_end_matches('.').to_owned());
            }
            stats.ignored += 1;
        }
        d => {
            stats.unsupported += 1;
            sample(
                stats,
                line_no,
                body,
                format!("`{d}` is not supported"),
                true,
            );
        }
    }
}

enum Outcome {
    Rule(Rule),
    Ignored,
    Unsupported(String),
    Invalid(String),
}

/// Whitespace-separated tokens, a quoted string kept as one.
fn tokenize(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in body.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn is_class(t: &str) -> bool {
    matches!(t.to_ascii_uppercase().as_str(), "IN" | "CH" | "HS" | "CS")
}

/// `3600`, `1h`, `1w2d`: a number, optionally with unit letters.
fn is_ttl(t: &str) -> bool {
    t.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && t.bytes().all(|b| {
            b.is_ascii_digit() || matches!(b.to_ascii_lowercase(), b's' | b'm' | b'h' | b'd' | b'w')
        })
}

/// A CNAME, A or AAAA record as a rule.
fn record(zone: &State, owner: &str, rtype: &str, rdata: &[String]) -> Outcome {
    let Some(value) = rdata.first() else {
        return Outcome::Invalid("record without data".into());
    };
    let (trigger, kind) = trigger_of(zone, owner);
    let Some(trigger) = (match kind {
        Kind::Apex => None,
        Kind::Qname => Some(trigger),
        Kind::Other(what) => {
            return Outcome::Unsupported(format!("{what} triggers are not applied"));
        }
    }) else {
        return Outcome::Ignored;
    };
    let (scope, name) = match trigger.strip_prefix("*.") {
        Some(rest) => (Scope::Subdomains, rest.to_owned()),
        None if trigger == "*" => {
            return Outcome::Unsupported("a wildcard for the whole zone is not applied".into());
        }
        None => (Scope::Exact, trigger),
    };
    let name = match normalize(&name) {
        Ok(n) => n,
        Err(e) => return Outcome::Invalid(format!("`{name}`: {e}")),
    };
    let (action, rewrite) = match rtype {
        "CNAME" => match value.to_ascii_lowercase().as_str() {
            "." => (Action::Block, Some("NXDOMAIN".to_owned())),
            "*." => (Action::Block, Some("NOERROR;;".to_owned())),
            "rpz-passthru." => (Action::Allow, None),
            "rpz-drop." => (Action::Block, Some("REFUSED".to_owned())),
            "rpz-tcp-only." => {
                return Outcome::Unsupported("`rpz-tcp-only.` is not applied".into());
            }
            t if t.starts_with("rpz-") && t.ends_with('.') => {
                return Outcome::Unsupported(format!("action `{t}` is not applied"));
            }
            t => {
                let target = target_name(zone, t);
                if crate::rewrite::parse(&target).is_none() {
                    return Outcome::Invalid(format!("CNAME target `{value}` is not a name"));
                }
                (Action::Block, Some(target))
            }
        },
        "A" => match value.parse::<std::net::Ipv4Addr>() {
            Ok(a) => (Action::Block, Some(a.to_string())),
            Err(_) => return Outcome::Invalid(format!("`{value}` is not an IPv4 address")),
        },
        _ => match value.parse::<std::net::Ipv6Addr>() {
            Ok(a) => (Action::Block, Some(a.to_string())),
            Err(_) => return Outcome::Invalid(format!("`{value}` is not an IPv6 address")),
        },
    };
    Outcome::Rule(Rule {
        action,
        pattern: Pattern::Domain { name, scope },
        modifiers: Modifiers {
            dnsrewrite: rewrite,
            ..Modifiers::default()
        },
    })
}

/// A relative CNAME target is under the zone's origin, as in any zone file.
fn target_name(zone: &State, t: &str) -> String {
    match (t.strip_suffix('.'), &zone.origin) {
        (Some(abs), _) => abs.to_owned(),
        (None, Some(o)) => format!("{t}.{o}"),
        (None, None) => t.to_owned(),
    }
}

enum Kind {
    /// The zone's own name (`@`).
    Apex,
    Qname,
    /// A trigger type the list does not apply (`rpz-ip`, `rpz-nsdname`, `rpz-nsip`, `rpz-client-ip`).
    Other(&'static str),
}

/// The trigger part of an owner name (the zone's origin cut off) and what kind it is.
fn trigger_of(zone: &State, owner: &str) -> (String, Kind) {
    if owner == "@" {
        return (String::new(), Kind::Apex);
    }
    let mut name = owner;
    if let Some(abs) = owner.strip_suffix('.') {
        name = abs;
        if let Some(o) = &zone.origin {
            if abs == o {
                return (String::new(), Kind::Apex);
            }
            if let Some(rel) = abs
                .strip_suffix(o.as_str())
                .and_then(|r| r.strip_suffix('.'))
            {
                name = rel;
            }
        }
    }
    let last = name.rsplit('.').next().unwrap_or(name);
    let other = match last {
        "rpz-ip" => Some("response-IP"),
        "rpz-nsdname" => Some("NSDNAME"),
        "rpz-nsip" => Some("NSIP"),
        "rpz-client-ip" => Some("client-IP"),
        _ => None,
    };
    match other {
        Some(what) => (String::new(), Kind::Other(what)),
        None => (name.to_owned(), Kind::Qname),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> (Vec<String>, ParseStats) {
        let mut out = Vec::new();
        let stats = parse(text.as_bytes(), |line, r| out.push(format!("L{line} {r}")));
        (out, stats)
    }

    const SAMPLE: &str = "\
$TTL 300
$ORIGIN rpz.example.net.
@ IN SOA ns.rpz.example.net. admin.example.net. ( 1 ; serial
        3600 600 86400 300 )
  IN NS ns.rpz.example.net.
nx.example.com CNAME .
nodata.example.com CNAME *.
ok.example.com CNAME rpz-passthru.
drop.example.com CNAME rpz-drop.
local.example.com CNAME portal.example.net.
walled.example.com A 192.0.2.7
walled6.example.com AAAA 2001:db8::7
*.wild.example.com CNAME .
; a comment

32.7.2.0.192.rpz-ip CNAME .
ns.bad.example.rpz-nsdname CNAME .
tcp.example.com CNAME rpz-tcp-only.
note.example.com TXT \"hello\"
";

    // REQ: FLT-906 - one rule per QNAME action, mapped to the existing rewrite machinery.
    #[test]
    fn flt_906_each_action_becomes_a_rule() {
        let (rules, stats) = run(SAMPLE);
        assert_eq!(
            rules,
            [
                "L6 block exact nx.example.com $dnsrewrite=NXDOMAIN",
                "L7 block exact nodata.example.com $dnsrewrite=NOERROR;;",
                "L8 allow exact ok.example.com $dnsrewrite=",
                "L8 allow exact ok.example.com",
                "L9 block exact drop.example.com $dnsrewrite=REFUSED",
                "L10 block exact local.example.com $dnsrewrite=portal.example.net",
                "L11 block exact walled.example.com $dnsrewrite=192.0.2.7",
                "L12 block exact walled6.example.com $dnsrewrite=2001:db8::7",
                "L13 block subdomains wild.example.com $dnsrewrite=NXDOMAIN",
            ]
        );
        assert_eq!(stats.rules, 8, "a passthru is one record");
        // Response-IP, NSDNAME, rpz-tcp-only and TXT are counted, not errors.
        assert_eq!(
            (stats.unsupported, stats.invalid),
            (4, 0),
            "{:?}",
            stats.samples
        );
        assert!(
            stats
                .samples
                .iter()
                .any(|s| s.reason.contains("response-IP")),
            "{:?}",
            stats.samples
        );
        assert_eq!(stats.lines, 19);
    }

    // REQ: FLT-906 - a wildcard covers the names below, never the name itself.
    #[test]
    fn flt_906_wildcard_is_subdomains_only() {
        let (rules, _) = run("*.example.com CNAME .\nexample.com CNAME .\n");
        assert_eq!(
            rules,
            [
                "L1 block subdomains example.com $dnsrewrite=NXDOMAIN",
                "L2 block exact example.com $dnsrewrite=NXDOMAIN",
            ]
        );
    }

    // REQ: FLT-906 - the zone's own name is cut from absolute owners, and an owner left out
    // reuses the previous one.
    #[test]
    fn flt_906_origin_and_inherited_owner() {
        let text = "\
rpz.example.net. 300 IN SOA ns.rpz.example.net. a.example.net. 1 2 3 4 5
bad.example.com.rpz.example.net. IN CNAME .
	IN A 192.0.2.1
";
        let (rules, stats) = run(text);
        assert_eq!(
            rules,
            [
                "L2 block exact bad.example.com $dnsrewrite=NXDOMAIN",
                "L3 block exact bad.example.com $dnsrewrite=192.0.2.1",
            ]
        );
        assert_eq!(stats.invalid, 0);
    }

    #[test]
    fn flt_906_bad_records_are_invalid_not_fatal() {
        let (rules, stats) = run("a.example.com A not-an-ip\nb.example.com CNAME .\n$INCLUDE x\n");
        assert_eq!(rules, ["L2 block exact b.example.com $dnsrewrite=NXDOMAIN"]);
        assert_eq!((stats.invalid, stats.unsupported), (1, 1));
    }

    #[test]
    fn flt_906_empty_and_crlf() {
        assert_eq!(run("").1, ParseStats::default());
        let (rules, _) = run("\u{feff}x.example.com CNAME .\r\n");
        assert_eq!(rules.len(), 1);
    }
}
