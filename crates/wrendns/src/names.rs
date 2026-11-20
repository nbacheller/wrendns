//! REQ: API-007, DSC-901 (T35.1, ADR-1032) — names are normalised once, where they enter.
//!
//! Pi-hole's admin page stores comments escaped with PHP's `htmlspecialchars`, so a client
//! commented `Alex's PC` is saved as `Alex&#039;s PC`; a router, a UniFi console or Home
//! Assistant can hand over the same. The web UI prints text literally (and never `{@html}`, which
//! a lint forbids), so the codes showed on screen. One helper decodes them, exactly once, at the
//! point a human-text column or a device name is read; stored entries are not touched here (the
//! one-off repair in `names_repair` does that, once).

/// The longest entity body looked at (`#x10FFFF` is eight characters).
const MAX_ENTITY: usize = 10;

/// `s` with the HTML entities decoded once: the named `&amp; &lt; &gt; &quot; &apos;` and numeric
/// `&#NN;` / `&#xNN;` references. What a reference decodes to is never decoded again
/// (`&amp;#039;` becomes `&#039;`). An unknown or malformed reference stays as written.
pub(crate) fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let decoded = rest[1..]
            .char_indices()
            .take(MAX_ENTITY + 1)
            .find(|(_, c)| *c == ';')
            .and_then(|(end, _)| entity(&rest[1..=end]).map(|c| (c, end + 2)));
        if let Some((c, used)) = decoded {
            out.push(c);
            rest = &rest[used..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

/// The character `body;` stands for (`body` is what lies between `&` and `;`).
fn entity(body: &str) -> Option<char> {
    match body {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let digits = body.strip_prefix('#')?;
            let code = match digits.strip_prefix(['x', 'X']) {
                Some(hex) if !hex.is_empty() => u32::from_str_radix(hex, 16).ok()?,
                None if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                    digits.parse().ok()?
                }
                _ => return None,
            };
            char::from_u32(code)
        }
    }
}

/// One line of human text: entities decoded once, then control characters stripped (a tab or a
/// line break becomes a space, any other control character goes), then trimmed.
pub(crate) fn clean_text(s: &str) -> String {
    decode_entities(s)
        .chars()
        .filter_map(|c| match c {
            '\t' | '\n' | '\r' => Some(' '),
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Whether decoding changes `s`, which is to say it holds an HTML entity.
pub(crate) fn has_entities(s: &str) -> bool {
    s.contains('&') && decode_entities(s) != s
}

/// REQ: API-007 (A6) — whether a name lost characters on its way here: a control character was
/// stripped, or the text holds `U+FFFD` or a `?` standing where a character was already replaced upstream
/// (Pi-hole's PHP stores a character it can't encode as `?`). Listed in the import report.
pub(crate) fn lost_characters(raw: &str, cleaned: &str) -> bool {
    let controls = |s: &str| {
        s.chars()
            .filter(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
            .count()
    };
    controls(&decode_entities(raw)) > 0
        || controls(raw) > 0
        || cleaned.contains('\u{FFFD}')
        || replaced_by_question_mark(cleaned)
}

/// A `?` that stands where a character was: at the start, or after a character that is not a
/// letter or digit (`Google -?`, `??`). A `?` closing a word (`Who's there?`) is a question.
fn replaced_by_question_mark(s: &str) -> bool {
    let mut prev: Option<char> = None;
    for c in s.chars() {
        if c == '?' && prev.is_none_or(|p| !p.is_alphanumeric()) {
            return true;
        }
        prev = Some(c);
    }
    false
}

/// The part of an address that tells two devices of one name apart: the last two octets of an
/// IPv4 address (`1.20`), the last two groups of an IPv6 address, the last two bytes of a MAC
/// (`ee:ff`); any other key (a network, a client ID) as written.
pub(crate) fn tail(key: &str) -> String {
    let key = key.trim();
    if let Ok(ip) = key.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}", o[2], o[3])
            }
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("{:x}:{:x}", s[6], s[7])
            }
        };
    }
    let parts: Vec<&str> = key.split([':', '-']).collect();
    if parts.len() == 6 && parts.iter().all(|p| p.len() == 2) {
        return format!("{}:{}", parts[4], parts[5]).to_ascii_lowercase();
    }
    key.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: API-007 (T35.1) — the decode table: each input and what it becomes, once.
    #[test]
    fn api_007_t35_1_decode_entities_table() {
        let table: &[(&str, &str)] = &[
            ("Alex&#039;s PC", "Alex's PC"),
            ("Alex&#39;s PC", "Alex's PC"),
            ("Alex&#x27;s PC", "Alex's PC"),
            ("Alex&#X27;s PC", "Alex's PC"),
            ("Tom &amp; Jerry", "Tom & Jerry"),
            ("&lt;b&gt;bold&lt;/b&gt;", "<b>bold</b>"),
            ("say &quot;hi&quot;", "say \"hi\""),
            ("it&apos;s", "it's"),
            ("caf&#233;", "caf\u{e9}"),
            ("smile &#x1F600;", "smile \u{1F600}"),
            // Decoded exactly once: a double-escaped name loses one layer, not two.
            ("Alex&amp;#039;s PC", "Alex&#039;s PC"),
            ("&amp;amp;", "&amp;"),
            ("&amp;lt;", "&lt;"),
            // Left as written: unknown, malformed, unterminated, out of range.
            ("a &nbsp; b", "a &nbsp; b"),
            ("a & b", "a & b"),
            ("a &amp b", "a &amp b"),
            ("&#;", "&#;"),
            ("&#x;", "&#x;"),
            ("&#xZZ;", "&#xZZ;"),
            ("&#12a;", "&#12a;"),
            ("&#55296;", "&#55296;"),
            ("&#1114112;", "&#1114112;"),
            ("&AMP;", "&AMP;"),
            ("&", "&"),
            ("&&amp;", "&&"),
            ("", ""),
            ("plain", "plain"),
            // Multi-byte text around an entity.
            ("\u{e9}&amp;\u{e9}", "\u{e9}&\u{e9}"),
        ];
        for (input, want) in table {
            assert_eq!(&decode_entities(input), want, "decode {input:?}");
        }
    }

    // REQ: API-007 (T35.1) — control characters go after the decode, and the text is trimmed.
    #[test]
    fn api_007_t35_1_clean_text_strips_controls_after_decoding() {
        let table: &[(&str, &str)] = &[
            ("Alex&#039;s PC", "Alex's PC"),
            ("  padded  ", "padded"),
            ("two\nlines", "two lines"),
            ("tab\there", "tab here"),
            // A reference that decodes to a control character is stripped too.
            ("bell&#7;ring", "bellring"),
            ("nul&#0;byte", "nulbyte"),
            ("line&#10;break", "line break"),
            ("\u{1b}[31mred", "[31mred"),
            ("Alex&amp;#039;s", "Alex&#039;s"),
        ];
        for (input, want) in table {
            assert_eq!(&clean_text(input), want, "clean {input:?}");
        }
    }

    #[test]
    fn api_007_t35_1_has_entities_and_lost_characters() {
        assert!(has_entities("Alex&#039;s PC"));
        assert!(!has_entities("Alex's PC"));
        assert!(!has_entities("a & b"));
        assert!(!has_entities("&nbsp;"));
        assert!(lost_characters("Google -?", "Google -?"));
        assert!(lost_characters("bad\u{7}", "bad"));
        assert!(lost_characters("x&#7;y", "xy"));
        assert!(lost_characters("caf\u{FFFD}", "caf\u{FFFD}"));
        assert!(!lost_characters("Alex&#039;s PC", "Alex's PC"));
        assert!(!lost_characters("two\nlines", "two lines"));
    }

    #[test]
    fn api_007_t35_1_tails_tell_devices_apart() {
        assert_eq!(tail("192.0.2.23"), "2.23");
        assert_eq!(tail("AA:BB:CC:DD:EE:0F"), "ee:0f");
        assert_eq!(tail("aa-bb-cc-dd-ee-0f"), "ee:0f");
        assert_eq!(tail("fd00::1:2"), "1:2");
        assert_eq!(tail("10.0.5.0/24"), "10.0.5.0/24");
        assert_eq!(tail("id:kids"), "id:kids");
    }
}
