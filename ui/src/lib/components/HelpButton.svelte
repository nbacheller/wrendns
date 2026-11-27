<script lang="ts">
  // REQ: API-011, ADR-036 — the "?" beside a setting: opens a side panel with the topic in a
  // fixed order (summary, diagram, when, example, caution, term, docs). It never blocks the
  // form underneath (Escape or ✕ closes it).
  import { tick } from 'svelte';
  import { docsUrl, glossary, loadTopics, topic } from '../help';
  import Drawer from './Drawer.svelte';
  import FlowDiagram from './FlowDiagram.svelte';

  let { id }: { id: string } = $props();
  // The glossary is fetched from the node once, when the first "?" mounts (ADR-1020 amendment).
  const all = $derived($glossary);
  let failed = $state(false);
  let box = $state<HTMLElement>();
  const t = $derived(all ? (topic(all, id) ?? { id, title: id, term: '', summary: 'No help text for this yet.', when: '', example: '', caution: '' }) : undefined);
  let open = $state(false);

  function load() {
    failed = false;
    return loadTopics().then(() => true, () => ((failed = true), false));
  }
  // The Retry button leaves the page once the text arrives: keep keyboard focus in the dialog.
  function retry() {
    load().then(async (ok) => {
      if (!ok) return;
      await tick();
      box?.focus();
    });
  }
  $effect(() => {
    load();
  });
</script>

<button
  type="button"
  class="help-btn"
  aria-label={t ? `Help: ${t.title}` : 'Help'}
  title={t?.title ?? 'Help'}
  data-help={id}
  onclick={(e) => {
    e.preventDefault();
    e.stopPropagation();
    open = true;
    if (failed) load();
  }}>?</button
>

{#if open}
  <Drawer title={t?.title ?? 'Help'} onclose={() => (open = false)}>
    <div class="help" data-testid="help-panel" tabindex="-1" bind:this={box}>
      {#if !t}
        {#if failed}
          <p class="notice warn" role="alert">The help text could not be loaded.</p>
          <button type="button" onclick={retry}>Retry</button>
        {:else}
          <p class="muted" role="status">Loading help…</p>
        {/if}
      {:else}
      <p class="lead">{t.summary}</p>
      {#if t.diagram}<FlowDiagram highlight={t.diagram} />{/if}
      {#if t.when}<h3>When you'd use it</h3><p>{t.when}</p>{/if}
      {#if t.example}<h3>Example</h3><p>{t.example}</p>{/if}
      {#if t.caution}<h3>Careful</h3><p class="notice warn">{t.caution}</p>{/if}
      {#if t.items?.length}
        <h3>Each one</h3>
        <ul class="help-items">
          {#each t.items as it (it.name)}<li><code>{it.name}</code>: {it.line}</li>{/each}
        </ul>
      {/if}
      {#if t.term}<p class="muted small">The DNS term for this is <b>{t.term}</b>.</p>{/if}
      {#if docsUrl(t)}<p><a href={docsUrl(t)} target="_blank" rel="noreferrer">Full documentation</a></p>{/if}
      {/if}
    </div>
  </Drawer>
{/if}

<style>
  .help-btn {
    display: inline-grid;
    place-items: center;
    width: 20px;
    height: 20px;
    min-height: 20px;
    flex: none;
    margin-left: 6px;
    padding: 0;
    border-radius: 50%;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--muted);
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    cursor: pointer;
    vertical-align: middle;
  }
  .help-btn:hover,
  .help-btn:focus-visible {
    color: var(--accent);
    border-color: var(--accent);
  }
  .help {
    outline: none;
  }
  .help .lead {
    font-size: 1.05em;
  }
  .help-items {
    padding-left: 18px;
    font-size: 0.95em;
  }
  .help h3 {
    margin: 16px 0 4px;
    font-size: 14px;
  }
</style>
