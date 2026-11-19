<script lang="ts">
  // REQ: OBS-901 (T26.6, ADR-958 section 4) — the live map's switch, sampling rate and thresholds:
  // one field per `[map]` setting (a `data-setting` mark each), a live preview that reclassifies the
  // current map with the values being typed, and the plain words about what each threshold does.
  // Operators change them; viewers read them (the editor shows no Edit). The server checks every
  // bound and names the field it refuses.
  import { api } from '../api';
  import ConfigEditor, { type Field } from './ConfigEditor.svelte';
  import HelpButton from './HelpButton.svelte';
  import type { Snapshot } from '../map';
  import { fromSettings, previewSentence, reclassify } from '../map-thresholds';

  // The current map, read once for the preview (a 404 `map_disabled` or no data: no preview).
  let snap = $state<Snapshot | null>(null);
  $effect(() => {
    api
      .map()
      .then((s) => (snap = s))
      .catch(() => (snap = null));
  });

  const fields: Field[] = [
    { key: 'enabled', label: 'Run the network map', type: 'bool', initial: true,
      help: 'Off: nothing is sampled and the map answers "map disabled". It never changes an answer either way.' },
    { key: 'event_rate', label: 'Lookups sampled per second (each node)', type: 'number', placeholder: '200',
      help: '10 to 2,000. Above this a node samples every Nth lookup and the map says "sampled, 1 in N"; its rates are then estimates. A Pi is comfortable at the default.' },
    { key: 'min_sample', label: 'Answers needed before colouring', type: 'number', placeholder: '20',
      help: '1 to 1,000, counted from real sampled answers in the last 60 s. Fewer: the node is Idle (grey), never green.' },
    { key: 'warn_latency_ms', label: 'Slow above (milliseconds)', type: 'number', placeholder: 'the latency objective',
      help: '1 to 60,000. An answer slower than this is slow. Empty: follows the latency objective ([slo] latency_ms, on the dashboard\'s Service level card).' },
    { key: 'warn_slow_pct', label: 'Warning when this % of answers are slow', type: 'number', placeholder: '10', help: '1 to 100.' },
    { key: 'warn_error_pct', label: 'Warning when this % are SERVFAIL or time out', type: 'number', placeholder: '5', help: '1 to 100.' },
    { key: 'error_pct', label: 'Failing when this % are SERVFAIL or time out', type: 'number', placeholder: '25',
      help: '1 to 100, and at least the warning value: red can\'t come before yellow.' },
    { key: 'warn_blocked_pct', label: 'Device warning when this % of its answers are blocked', type: 'number', placeholder: '60',
      help: '1 to 100. Devices only: a network full of blocked ads is the filter working, so this is high by default.' },
  ];

  const summary = (d: Record<string, unknown>) =>
    `${d.enabled === false ? 'off' : 'on'}; ${String(d.event_rate)} lookups/s sampled, ${String(d.min_sample)} answers to colour; slow above ${d.warn_latency_ms ? `${String(d.warn_latency_ms)} ms` : 'the latency objective'}; warning at ${String(d.warn_slow_pct)}% slow, ${String(d.warn_error_pct)}% errors, ${String(d.warn_blocked_pct)}% blocked; failing at ${String(d.error_pct)}% errors`;

  const note = (v: Record<string, unknown>) => previewSentence(snap ? reclassify(snap, fromSettings(v)) : null);
</script>

<ConfigEditor kind="map" path="map-settings" singleton title="Network map" noun="network map settings" {fields} {summary} {note} help="map-thresholds" />
<p class="muted small" data-testid="map-settings-note">
  The <a href="#/map">network map</a> is drawn from a sample of lookups and coloured by these thresholds; a change applies to every node within a few seconds.
  The preview under the fields recolours the map as it is now. A server that isn't busy enough to reach the minimum answers shows Idle.<HelpButton id="map-thresholds" />
</p>
