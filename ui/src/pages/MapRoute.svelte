<script lang="ts">
  // REQ: OBS-901 (T26.3) — the Network map is a lazy-loaded chunk: its code (the layout, the
  // drawing and its styles) loads when the route is first opened, so the rest of the console
  // doesn't carry it (ADR-958 section 8, the 400 KiB budget).
  const page = import('./Map.svelte');
</script>

{#await page then m}
  {@const Page = m.default}
  <Page />
{:catch error}
  <div class="page"><p role="alert">The Network map page didn't load: {String(error)}</p></div>
{/await}
