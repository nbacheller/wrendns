//! The pre-rename metric names (ADR-1028, spec/10 T33.2; REQ: OBS-005).
//!
//! For one release `/metrics` answers every `wrendns_*` family and, after it, the same samples
//! under `telltale_*`, so a dashboard or an alert rule that hasn't moved yet keeps working. The
//! bundled Grafana dashboards, recording rules and alerts already use `wrendns_*`.

const NEW: &str = "wrendns_";
const OLD: &str = "telltale_";

/// `text` (Prometheus text format, new names) followed by a copy of each `wrendns_*` family under
/// the old name. Only a line's metric name changes: label values, help text and values don't.
#[must_use]
pub fn with_legacy_names(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    out.push_str(text);
    if !text.is_empty() && !text.ends_with('\n') {
        out.push('\n');
    }
    for line in text.lines() {
        let (head, rest) = if let Some(r) = line.strip_prefix("# HELP ") {
            ("# HELP ", r)
        } else if let Some(r) = line.strip_prefix("# TYPE ") {
            ("# TYPE ", r)
        } else {
            ("", line)
        };
        if let Some(tail) = rest.strip_prefix(NEW) {
            out.push_str(head);
            out.push_str(OLD);
            out.push_str(tail);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: OBS-005 — both names are exported, and only the name changes.
    #[test]
    fn obs_005_both_metric_names() {
        let text = "# HELP wrendns_queries_total DNS queries.\n# TYPE wrendns_queries_total counter\nwrendns_queries_total{proto=\"udp\",note=\"wrendns_x\"} 3\n# HELP other_metric Kept out.\nother_metric 1\n";
        let both = with_legacy_names(text);
        assert!(
            both.starts_with(text),
            "the new names come first, unchanged"
        );
        assert!(both.contains("# HELP telltale_queries_total DNS queries.\n"));
        assert!(both.contains("# TYPE telltale_queries_total counter\n"));
        assert!(both.contains("telltale_queries_total{proto=\"udp\",note=\"wrendns_x\"} 3\n"));
        assert_eq!(
            both.matches("other_metric 1").count(),
            1,
            "other families aren't copied"
        );
        assert_eq!(with_legacy_names(""), "");
    }
}
