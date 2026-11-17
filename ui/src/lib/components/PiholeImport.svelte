<script lang="ts">
  // REQ: API-007 (T24.18, ADR-940, ADR-941) — Settings → Import from Pi-hole, admins only: upload a
  // Teleporter export or a gravity.db, see what would be added, changed or skipped (and, with a Pi-hole
  // address, a sample resolved through both servers), then apply the preview as one change. Nothing
  // changes until the apply; the apply is typed and audited.
  import { api, type PiholeApplied, type PiholePreview } from '../api';
  import { dateTime } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let file = $state<File | null>(null);
  let compareOn = $state(false);
  let piholeAddr = $state('');
  let ourAddr = $state('');
  let busy = $state<'' | 'preview' | 'apply' | 'discard'>('');
  let error = $state<unknown>(null);
  let preview = $state<PiholePreview | null>(null);
  let applied = $state<PiholeApplied | null>(null);
  let confirmText = $state('');
  let showAll = $state(false);
  let fileInput = $state<HTMLInputElement | null>(null);

  // The preview lists the first fifty items unless asked for all of them.
  const shown = $derived(preview ? (showAll ? preview.items : preview.items.slice(0, 50)) : []);
  const differ = (p: PiholePreview) => (p.compare ? p.compare.names - p.compare.agree : 0);

  function pick(e: Event) {
    file = (e.currentTarget as HTMLInputElement).files?.[0] ?? null;
  }

  async function runPreview(e: SubmitEvent) {
    e.preventDefault();
    if (!file) return;
    busy = 'preview';
    error = null;
    applied = null;
    preview = null;
    confirmText = '';
    showAll = false;
    try {
      const q: { compare?: string; telltale?: string } = {};
      if (compareOn && piholeAddr.trim()) {
        q.compare = piholeAddr.trim();
        if (ourAddr.trim()) q.telltale = ourAddr.trim();
      }
      preview = await api.piholePreview(file, q);
    } catch (err) {
      error = err;
    } finally {
      busy = '';
    }
  }

  async function apply() {
    if (!preview || confirmText !== 'IMPORT') return;
    busy = 'apply';
    error = null;
    try {
      applied = await api.piholeApply(preview.planId);
      preview = null;
      file = null;
      if (fileInput) fileInput.value = '';
    } catch (err) {
      // A stale preview (409) or an expired plan (404) is said in the error; the preview stays until discarded.
      error = err;
    } finally {
      busy = '';
    }
  }

  async function discard() {
    if (!preview) return;
    busy = 'discard';
    error = null;
    try {
      await api.piholeDiscard(preview.planId);
      preview = null;
      confirmText = '';
    } catch (err) {
      error = err;
    } finally {
      busy = '';
    }
  }
</script>

<section class="card" data-testid="pihole-import">
  <h2>Import from Pi-hole<HelpButton id="pihole-import" /></h2>
  <p class="muted">
    Upload a Teleporter export (in Pi-hole: Settings → Teleporter → Export; a .zip from v6, a .tar.gz from v5) or a
    gravity.db. The file is read and checked, and nothing changes until you apply the preview.
  </p>
  <form class="stack" onsubmit={runPreview}>
    <label class="field">Pi-hole export
      <input
        type="file"
        required
        accept=".zip,.gz,.tgz,.db,.sqlite,.sqlite3,application/zip,application/gzip,application/octet-stream"
        bind:this={fileInput}
        onchange={pick}
        data-testid="pihole-file"
      />
    </label>
    <label class="check">
      <input type="checkbox" bind:checked={compareOn} data-testid="pihole-compare-toggle" />
      Compare a sample with a Pi-hole<HelpButton id="pihole-compare" />
    </label>
    {#if compareOn}
      <label class="field">Pi-hole address
        <input type="text" placeholder="192.168.1.251" autocomplete="off" bind:value={piholeAddr} data-testid="pihole-address" />
      </label>
      <label class="field">TelltaleDNS address (this node's resolver)
        <input type="text" placeholder="127.0.0.1:53" autocomplete="off" bind:value={ourAddr} data-testid="pihole-telltale-address" />
      </label>
    {/if}
    <div>
      <button type="submit" disabled={!file || busy !== ''} data-testid="pihole-preview">
        {busy === 'preview' ? 'Reading the export…' : 'Preview import'}
      </button>
    </div>
  </form>
  <ErrorNote error={error} />

  {#if applied}
    <div class="notice" role="status" data-testid="pihole-applied">
      Applied: {applied.added} added, {applied.changed} changed, {applied.skipped} skipped. Configuration version {applied.configVersion}.
      The Upstreams, Lists, Groups and Local DNS pages show the new entries.
    </div>
  {/if}

  {#if preview}
    <div class="stack" data-testid="pihole-preview-result">
      <h3>Preview of {preview.source === 'v6' ? 'a Pi-hole v6' : 'a Pi-hole v5'} export</h3>
      <p class="muted small">{preview.counts}</p>
      <p data-testid="pihole-summary">
        <strong>{preview.summary.add}</strong> to add · <strong>{preview.summary.change}</strong> to change ·
        <strong>{preview.summary.skip}</strong> skipped
      </p>

      {#if preview.notes.length}
        <details>
          <summary>What didn't carry over, and notes ({preview.notes.length})</summary>
          <ul>
            {#each preview.notes as n}<li>{n}</li>{/each}
          </ul>
        </details>
      {/if}

      <div class="table-wrap">
        <table>
          <thead><tr><th>Action</th><th>Kind</th><th>Name</th><th>Reason</th></tr></thead>
          <tbody>
            {#each shown as item (item.kind + item.name)}
              <tr data-testid="pihole-item">
                <td>{item.action}</td>
                <td>{item.kind}</td>
                <td>{item.name}</td>
                <td>{item.reason}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if preview.itemsTotal > shown.length}
        <button type="button" class="ghost" onclick={() => (showAll = true)}>Show all {preview.itemsTotal} items</button>
      {/if}

      {#if preview.compare}
        <div data-testid="pihole-compare-result">
          <h4>Sample through both servers<HelpButton id="pihole-compare" /></h4>
          <p data-testid="pihole-compare-summary">
            Compared {preview.compare.names} names: {preview.compare.agree} agree, {differ(preview)} differ.
          </p>
          {#if preview.compare.differences.length}
            <div class="table-wrap">
              <table>
                <thead><tr><th>Name</th><th>Type</th><th>Pi-hole</th><th>TelltaleDNS</th></tr></thead>
                <tbody>
                  {#each preview.compare.differences as d (d.name + d.qtype)}
                    <tr>
                      <td>{d.name}</td>
                      <td>{d.qtype}</td>
                      <td>{d.pihole.rcode} {d.pihole.values.join(', ')}</td>
                      <td>{d.telltale.rcode} {d.telltale.values.join(', ')}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
          {#each preview.compare.errors as e}
            <div class="notice" role="note">{e}</div>
          {/each}
        </div>
      {/if}

      <div class="stack">
        <label class="field">Type IMPORT to apply this preview
          <input type="text" autocomplete="off" bind:value={confirmText} data-testid="pihole-confirm" />
        </label>
        <div class="row">
          <button type="button" onclick={apply} disabled={confirmText !== 'IMPORT' || busy !== ''} data-testid="pihole-apply">
            {busy === 'apply' ? 'Applying…' : 'Apply this import'}
          </button>
          <button type="button" class="ghost" onclick={discard} disabled={busy !== ''} data-testid="pihole-discard">Discard</button>
        </div>
        <p class="muted small">
          The plan expires {dateTime(preview.expiresUnixSeconds)}. Applying writes the adds and changes as one configuration change, audited
          as import.pihole. Names the config files define are skipped.
        </p>
      </div>
    </div>
  {/if}
</section>
