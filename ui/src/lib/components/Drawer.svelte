<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  let { title, onclose, children }: { title: string; onclose: () => void; children: Snippet } = $props();
  let panel = $state<HTMLElement | undefined>();

  $effect(() => {
    panel?.focus();
  });

  function key(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose();
  }
</script>

<svelte:window onkeydown={key} />

<div class="backdrop" role="presentation" onclick={onclose}></div>
<div class="drawer" role="dialog" aria-modal="true" aria-label={title} tabindex="-1" bind:this={panel}>
  <header>
    <h2>{title}</h2>
    <button class="icon-btn" onclick={onclose} aria-label="Close"><Icon name="x" /></button>
  </header>
  <div class="body">{@render children()}</div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    /* The page behind washes out to the page colour: no dark scrim (airy, T33.6). */
    background: color-mix(in srgb, var(--bg) 60%, transparent);
    z-index: 20;
  }
  .drawer {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    width: min(640px, 100vw);
    background: var(--bg);
    border-left: 1px solid var(--border);
    box-shadow: var(--shadow-float);
    z-index: 21;
    display: flex;
    flex-direction: column;
    /* The panel takes focus only to hold it for the dialog: it isn't a control, and a ring round it
       reads as a coloured edge. Its controls keep their own ring. */
    outline: none;
    /* Opened from a "?" inside a page heading, it would otherwise take the heading's size and
       weight: the body text's own type (Figtree, body-sm), whatever it sits in. */
    font: var(--type-body-sm-weight) var(--type-body-sm-size) / var(--type-body-sm-line) var(--brand-font-sans);
    letter-spacing: normal;
    text-transform: none;
    text-align: left;
    white-space: normal;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-3) var(--space-4);
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  header h2 {
    margin: 0;
    word-break: break-all;
  }
  .body {
    overflow-y: auto;
    padding: var(--space-4);
    display: grid;
    gap: var(--space-4);
    align-content: start;
  }
</style>
