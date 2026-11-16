<script lang="ts">
  // REQ: FLT-005 (T6.12, ADR-067) — quick rules: what's in effect (with a countdown), who made
  // it and why, removing one, and making a new one.
  // REQ: FLT-005 (T20.1, ADR-162) — editing one in place, under its ID.
  import { api, type S } from '../lib/api';
  import { can } from '../lib/session.svelte';
  import { poll } from '../lib/poll';
  import { duration, endsAt, logDate } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import QuickRuleForm from '../lib/components/QuickRuleForm.svelte';

  let rules = $state<S['RuleInfo'][]>([]);
  let error = $state<unknown>(null);
  let removing = $state('');
  /** The rule being edited: a copy taken when Edit was pressed, so the list's reloads don't reset the form. */
  let editing = $state<S['RuleInfo'] | null>(null);
  /** What the last edit did. It sits on the page, not in the row: the row is redrawn when the list reloads. */
  let edited = $state('');
  const writable = $derived(can('operator'));

  async function load() {
    try {
      rules = (await api.rules()).items;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 10000));

  async function remove(id: string) {
    removing = id;
    edited = '';
    try {
      await api.deleteRule(id);
      await load();
    } catch (e) {
      error = e;
    } finally {
      removing = '';
    }
  }
  /** The form holds one device or one group (or everyone), so a rule with more is changed through the API. */
  const fitsForm = (r: S['RuleInfo']) => r.devices.length + r.groups.length <= 1;
  function edit(r: S['RuleInfo']) {
    edited = '';
    editing = $state.snapshot(r);
  }
  async function afterEdit(message: string) {
    editing = null;
    // The message names the saved rule (its domain may have changed), so it isn't named again here.
    edited = `Rule updated. ${message}`;
    await load();
  }
  const whom = (r: S['RuleInfo']) =>
    r.devices.length ? r.devices.join(', ') : r.groups.length ? `group ${r.groups.join(', ')}` : 'everyone';
</script>

<div class="page">
  <div class="page-head">
    <h1>Quick rules<HelpButton id="quick-rules" /></h1>
  </div>
  <p class="muted small">
    Allow or block a site for one device, a group, or everyone, for a while or for good. Quick rules decide before any
    list: a device's rule beats its group's, which beats everyone's.
  </p>
  <ErrorNote {error} />
  {#if edited}<div class="notice ok small" role="status" data-testid="rule-edited">{edited}</div>{/if}

  {#if writable}
    <section class="card">
      <h2>New rule</h2>
      <QuickRuleForm onsaved={() => load()} />
    </section>
  {/if}

  <section class="card">
    <h2>In effect</h2>
    {#if rules.length === 0}
      <p class="empty">No quick rules. Make one here, or from "Why?" in the query log.</p>
    {:else}
      <div class="table-wrap">
        <table data-testid="rules-table">
          <thead>
            <tr><th>Rule</th><th>For</th><th>Ends</th><th>Note</th><th>Made</th><th></th></tr>
          </thead>
          <tbody>
            {#each rules as r (r.id)}
              <tr>
                <td>
                  <span class="badge {r.action === 'allow' ? 'ok' : 'bad'}">{r.action}</span>
                  <span class="mono">{r.domain}</span>
                </td>
                <td>{whom(r)}</td>
                <td class="small">
                  {#if r.expiresInSeconds == null}never{:else if r.expiresInSeconds === 0}expired{:else}in {duration(r.expiresInSeconds)}<div class="muted">at {endsAt(r.expires)}</div>{/if}
                </td>
                <td class="small">{r.note ?? ''}</td>
                <td class="small muted">{r.createdBy ?? (r.source === 'file' ? 'config file' : '')}{#if r.created}<div>{logDate(r.created)}</div>{/if}</td>
                <td>
                  {#if r.source === 'api' && writable}
                    {#if fitsForm(r) && r.expiresInSeconds !== 0}
                      <button class="link" disabled={editing?.id === r.id} onclick={() => edit(r)}>Edit</button>
                    {/if}
                    <button class="link" disabled={removing === r.id} onclick={() => remove(r.id)}>Remove</button>
                    {#if !fitsForm(r)}<div class="muted small">Several devices or groups: change it through the API.</div>{/if}
                  {:else if r.source === 'file'}
                    <span class="muted small">in the config file</span>
                  {/if}
                </td>
              </tr>
              {#if editing?.id === r.id}
                <tr data-testid="rule-edit-row">
                  <td colspan="6">
                    <h3>Edit rule</h3>
                    <QuickRuleForm rule={editing} onsaved={afterEdit} oncancel={() => (editing = null)} />
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>
