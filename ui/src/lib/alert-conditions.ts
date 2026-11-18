// REQ: OBS-010 (T27.1), API-901 — every `when` an alert rule accepts (the server's `AlertWhen`,
// telltale-config). The Alerts form offers this list; the Rust test `obs_010_alert_conditions_match_ui`
// fails when the enum gains or loses a value this list doesn't have. Keep the order: the
// conditions the form offered first, then the ones added by T27.1.
export const alertConditions: string[] = [
  'upstream_down',
  'node_down',
  'sync_lag',
  'primary_unreachable',
  'list_failing',
  'list_stale',
  'servfail_rate',
  'anomaly',
  'new_device',
  'disk_full',
  'plan_pending',
  'update_available',
  'maintenance',
  'credential_redirected',
  'secrets_exported',
  'slo_burn',
  'probe_failing',
  'cert_expiring',
  'rollout_failed',
  'cluster_pinned',
  'chatty_loop',
  'drill_report',
];
