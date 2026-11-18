<script lang="ts">
  // REQ: OBS-902 (T26.5) - the World view is a lazy-loaded chunk: its code and its baked-in map
  // data (land mask, country points) load when the route is first opened, so the rest of the
  // console doesn't carry them (ADR-958 section 8, the 400 KiB budget).
  const page = import('./World.svelte');
</script>

{#await page then m}
  {@const Page = m.default}
  <Page />
{:catch error}
  <div class="page"><p role="alert">The World view page didn't load: {String(error)}</p></div>
{/await}
