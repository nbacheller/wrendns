<script lang="ts">
  // REQ: API-005, CLU-002, OBS-033 (ADR-157) — the heading with the view controls, the note form,
  // and the partial-results notice.
  import type { DashData } from './data.svelte';
  import DashControls from './DashControls.svelte';
  import ChangesControls from '../components/ChangesControls.svelte';
  import ErrorNote from '../components/ErrorNote.svelte';
  import HelpButton from '../components/HelpButton.svelte';

  let { d, title = 'Dashboard' }: { d: DashData; title?: string } = $props();
</script>

<div class="page-head">
  <h1>{title}<HelpButton id="how-it-works" /></h1>
  <DashControls {d} />
</div>
<ChangesControls part="body" advanced={d.advanced} />
<ErrorNote error={d.error} />
{#if d.summary?.missingNodes?.length}
  <div class="notice warn small">Partial results: {d.summary.missingNodes.join(', ')} didn't answer, so these numbers cover the other cluster nodes.</div>
{/if}
