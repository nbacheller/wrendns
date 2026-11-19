<script lang="ts">
  // REQ: OPS-011, OPS-012 (T27.11, ADR-1006) — two switches for this node on Settings → System, admins
  // only: "Keep support logs on disk" (`[support] persist_logs`) and "Check for new builds" (`[updates]
  // check`). Each is a node-managed setting, saved after a check, and applies after a restart.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let node = $state('');
  let support = $state<S['NodeSection'] | null>(null);
  let updates = $state<S['NodeSection'] | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');
  let preview = $state<{ kind: 'support' | 'updates'; change: S['ConfigChange']; body: Record<string, unknown> } | null>(null);
  let busy = $state(false);

  const admin = $derived(can('admin'));

  async function load() {
    try {
      const ns = await api.nodeSettings();
      node = ns.node;
      support = ns.sections.find((s) => s.section === 'support') ?? null;
      updates = ns.sections.find((s) => s.section === 'updates') ?? null;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void load();
  });

  const path = (k: 'support' | 'updates') => (k === 'support' ? 'support-settings' : 'updates-settings');

  async function check(kind: 'support' | 'updates', body: Record<string, unknown>) {
    busy = true;
    notice = '';
    try {
      const change = await api.putEntry(path(kind), node, body, true);
      preview = { kind, change, body };
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!preview) return;
    busy = true;
    try {
      await api.putEntry(path(preview.kind), node, preview.body, false);
      notice = 'Saved. It takes effect when this node restarts.';
      preview = null;
      await load();
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  const fileSet = (s: S['NodeSection'] | null, k: string) => s?.setByFile.includes(k) ?? false;
</script>

<section class="card" data-testid="node-switches">
  <h2>This node's logs and updates<HelpButton id="support-logs" /></h2>
  <ErrorNote {error} />
  {#if notice}<p class="notice ok small" role="status">{notice}</p>{/if}
  {#if !admin}
    <p class="muted small">Admins change these switches.</p>
  {/if}
  {#if support}
    <label class="check">
      <input
        type="checkbox"
        role="switch"
        aria-label="Keep support logs on disk"
        data-testid="support-persist-logs"
        checked={support.fields.persist_logs === true}
        disabled={!admin || busy || fileSet(support, 'persist_logs')}
        onchange={(e) => check('support', { persist_logs: (e.currentTarget as HTMLInputElement).checked })}
      />
      Keep support logs on disk
      {#if fileSet(support, 'persist_logs')}<span class="muted small" data-testid="set-by-file">Set by the configuration file: change it there.</span>{/if}
      {#if support.pendingRestart}<span class="badge warn">pending restart</span>{/if}
    </label>
  {/if}
  {#if updates}
    <HelpButton id="update-check" />
    <label class="check">
      <input
        type="checkbox"
        role="switch"
        aria-label="Check for new builds"
        data-testid="updates-check"
        checked={updates.fields.check === true}
        disabled={!admin || busy || fileSet(updates, 'check')}
        onchange={(e) => check('updates', { check: (e.currentTarget as HTMLInputElement).checked })}
      />
      Check for new builds once a day
      {#if fileSet(updates, 'check')}<span class="muted small" data-testid="set-by-file">Set by the configuration file: change it there.</span>{/if}
      {#if updates.pendingRestart}<span class="badge warn">pending restart</span>{/if}
    </label>
  {/if}
  {#if preview}
    <div class="preview" data-testid="node-switches-preview">
      <p><b>What this will do:</b> {preview.change.impact || 'Takes effect after a restart of this node.'}</p>
      {#each preview.change.warnings as w (w)}<p class="small warn-text">{w}</p>{/each}
      <div class="row">
        <button type="button" class="primary" disabled={busy} onclick={apply}>Apply</button>
        <button type="button" onclick={() => (preview = null)}>Cancel</button>
      </div>
    </div>
  {/if}
</section>
