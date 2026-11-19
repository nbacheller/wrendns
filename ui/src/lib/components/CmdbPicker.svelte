<script lang="ts">
  // REQ: DSC-903 (T31.2) — choose a device: search by name, MAC, serial or id, then pick one. Used by
  // the Move and Merge controls; nothing here changes anything.
  import { api, type S } from '../api';
  import ErrorNote from './ErrorNote.svelte';

  let {
    label,
    exclude = '',
    onpick,
    oncancel,
  }: {
    label: string;
    /** A device that is not offered (the one the change starts from). */
    exclude?: string;
    onpick: (ci: S['CmdbCi']) => void;
    oncancel: () => void;
  } = $props();

  let q = $state('');
  let results = $state<S['CmdbCi'][]>([]);
  let error = $state<unknown>(null);
  let seq = 0;

  $effect(() => {
    const text = q.trim();
    const mine = ++seq;
    const t = setTimeout(async () => {
      try {
        const page = await api.cmdbCis({ type: 'device', q: text || undefined, limit: 20 });
        if (mine === seq) {
          results = page.items.filter((c) => c.id !== exclude);
          error = null;
        }
      } catch (e) {
        if (mine === seq) error = e;
      }
    }, 150);
    return () => clearTimeout(t);
  });
</script>

<div class="card" data-testid="cmdb-picker">
  <label>
    {label}
    <input type="search" bind:value={q} aria-label="Search for a device" placeholder="name, MAC, serial or id" />
  </label>
  <ErrorNote {error} />
  <ul class="plain" aria-label="Devices found">
    {#each results as c (c.id)}
      <li>
        <button class="link" onclick={() => onpick(c)} data-testid="cmdb-pick" data-ci={c.id}>
          {c.name ?? c.id}
        </button>
        <span class="muted small"><code>{c.id.slice(0, 7)}…{c.id.slice(-4)}</code> · {c.sources.join(', ') || 'no source'}</span>
      </li>
    {:else}
      <li class="muted small">No device matches.</li>
    {/each}
  </ul>
  <button onclick={oncancel}>Cancel</button>
</div>
