<script lang="ts">
  // REQ: API-005, OBS-011 (GitHub issue #9) — an upstream's health in plain words (Healthy,
  // Benched, Probing); the circuit breaker's own state is the tooltip.
  import StatusBadge from './StatusBadge.svelte';
  import { breakerLabel, breakerTitle } from '../breaker';
  let { value }: { value: string | null | undefined } = $props();
</script>

<StatusBadge {value} label={breakerLabel(value)} title={breakerTitle(value)} />
