<script lang="ts">
  // REQ: DSC-903 (T31.2, ADR-1004 section 4, rule R1) — a manual link, unlink, merge or split, shown as
  // a preview first: the records that would move (a dry run, nothing written), then Apply. The reason
  // goes with the pin and the audit entry (X-Wrendns-Reason). Cancel drops it.
  import { api, type S } from '../api';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    op,
    id,
    body,
    title,
    ondone,
    oncancel,
  }: {
    op: 'link' | 'unlink' | 'merge' | 'split';
    id: string;
    body: Record<string, unknown>;
    title: string;
    ondone: (result: S['CmdbChange']) => void;
    oncancel: () => void;
  } = $props();

  let preview = $state<S['CmdbChange'] | null>(null);
  let error = $state<unknown>(null);
  let busy = $state(false);
  let reason = $state('');

  // The preview is a dry run of exactly what Apply sends.
  $effect(() => {
    const o = op;
    const i = id;
    const b = body;
    preview = null;
    error = null;
    busy = true;
    api
      .cmdbChange(o, i, b, true)
      .then((p) => {
        preview = p;
      })
      .catch((e) => {
        error = e;
      })
      .finally(() => {
        busy = false;
      });
  });

  async function apply() {
    busy = true;
    error = null;
    try {
      const r = await api.cmdbChange(op, id, body, false, reason.trim() || undefined);
      ondone(r);
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  const short = (c: string | null | undefined) => (c ? `${c.slice(0, 7)}…${c.slice(-4)}` : 'a new device');
</script>

<section class="card" data-testid="cmdb-preview" aria-label="Preview of the change">
  <h3>{title}<HelpButton id="cmdb-changes" /></h3>
  <ErrorNote {error} />
  {#if preview}
    {#if preview.moves.length > 0}
      <p class="small">These records would move:</p>
      <div class="table-wrap">
        <table class="compact" data-testid="cmdb-moves">
          <thead><tr><th>Source</th><th>Key</th><th>From</th><th>To</th><th>Why</th></tr></thead>
          <tbody>
            {#each preview.moves as m (m.source + '/' + m.key)}
              <tr>
                <td>{m.source}</td>
                <td><code>{m.key}</code></td>
                <td><code>{short(m.from)}</code></td>
                <td><code>{short(m.to)}</code></td>
                <td class="small">{m.why}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <p class="small muted">No record moves.</p>
    {/if}
    {#each preview.notes as n (n)}<p class="small" data-testid="cmdb-note">{n}</p>{/each}
    <label>
      Why (kept with the change, optional)
      <input type="text" bind:value={reason} maxlength="300" aria-label="Why" placeholder="Same laptop on Wi-Fi and Ethernet" />
    </label>
  {/if}
  <div class="row actions">
    <button class="primary" onclick={apply} disabled={busy || !preview} data-testid="cmdb-apply">Apply</button>
    <button onclick={oncancel} disabled={busy} data-testid="cmdb-cancel">Cancel</button>
  </div>
</section>
