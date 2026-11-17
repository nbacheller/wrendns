<script lang="ts" module>
  // REQ: API-002 (T7.5, ADR-069) — add, change, remove, or revert upstreams, upstream groups,
  // lists, and groups from the UI. Each change is previewed (dry run: what it does, warnings)
  // before it's applied; on a Git-managed node the result says what to add to Git.
  export type Field = {
    key: string;
    label: string;
    type: 'text' | 'number' | 'select' | 'multi' | 'lines' | 'bool';
    options?: string[];
    /** How `select`/`multi` options read (CLU-013: node IDs by their site or pod). */
    optionLabels?: Record<string, string>;
    placeholder?: string;
    help?: string;
    /** Only in the Advanced view. */
    advanced?: boolean;
    /** The value a new entry starts with. */
    initial?: unknown;
    /** `lines` fields kept as text while editing and converted on Check (T9.7: schedule
     *  windows as `weekdays 21:00-07:00`). `fromText` throws to report a bad line. */
    toText?: (v: unknown) => string;
    fromText?: (s: string) => unknown;
    /** REQ: API-014 (T23.2) — only an admin changes it (a file holding a credential, or where
     *  one is sent): shown read-only to others. A function decides from the entry as it was
     *  read (`{}` for a new one). */
    admin?: boolean | ((original: Record<string, unknown>) => boolean);
  };
</script>

<script lang="ts">
  import { untrack } from 'svelte';
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { currentMode } from '../mode.svelte';
  import Drawer from './Drawer.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import KeepInGit from './KeepInGit.svelte';
  import HelpButton from './HelpButton.svelte';
  import SimulationCard from './SimulationCard.svelte';

  let {
    kind,
    path,
    title,
    noun,
    fields,
    summary,
    onchanged,
    help,
    rowAction,
    formAction,
    singleton = false,
    role,
    note,
    draft = null,
  }: {
    kind: 'upstream' | 'upstream_group' | 'list' | 'group' | 'alert_destination' | 'alert_rule' | 'schedule' | 'ratelimit' | 'exclusions' | 'simulate' | 'rollout';
    path: 'upstreams' | 'upstream-groups' | 'lists' | 'groups' | 'alerts/destinations' | 'alerts/rules' | 'schedules' | 'ratelimit' | 'exclusions' | 'simulate-settings' | 'cluster/rollout-settings';
    title: string;
    noun: string;
    fields: Field[];
    summary: (def: Record<string, unknown>) => string;
    onchanged?: () => void;
    help?: string;
    /** A button on each row (T9.6: "Send test"); `run` returns what to show. */
    rowAction?: { label: string; run: (name: string) => Promise<{ ok: boolean; text: string }> };
    /** A button in the form that tries the draft before saving (T9.12: "Test it"). */
    formAction?: { label: string; run: (body: Record<string, unknown>) => Promise<{ ok: boolean; text: string }> };
    /** One entry that always exists (the rate limit): no Add, and no Remove, only Revert to the file. */
    singleton?: boolean;
    /** Who may change it (CLU-013: the rollout settings are an admin's). */
    role?: 'operator' | 'admin';
    /** A sentence about the draft, under the fields (CLU-013: who gets a change first). */
    note?: (values: Record<string, unknown>) => string;
    /** REQ: FLT-005 (T24.15) — open a new entry with these values filled in ("Make a group from
     *  this network"). A new object each time it should open; operators only. `onused` runs once it
     *  has been taken (the page clears the URL so a reload or Back doesn't reopen it). */
    draft?: { name?: string; values: Record<string, unknown>; onused?: () => void } | null;
  } = $props();
  let formOut = $state<{ ok: boolean; text: string } | null>(null);
  async function runFormAction() {
    if (!formAction || !editing) return;
    formOut = { ok: true, text: 'Testing…' };
    try {
      formOut = await formAction.run(body());
    } catch (err) {
      formOut = { ok: false, text: err instanceof Error ? err.message : String(err) };
    }
  }
  let actionOut = $state<{ name: string; ok: boolean; text: string } | null>(null);
  async function runAction(name: string) {
    if (!rowAction) return;
    actionOut = { name, ok: true, text: 'Sending…' };
    try {
      actionOut = { name, ...(await rowAction.run(name)) };
    } catch (err) {
      actionOut = { name, ok: false, text: err instanceof Error ? err.message : String(err) };
    }
  }

  let entries = $state<S['ConfigEntry'][]>([]);
  let entriesLoaded = $state(false);
  let error = $state<unknown>(null);
  let editing = $state<{ name: string; isNew: boolean; values: Record<string, unknown> } | null>(null);
  // The entry as it was read, for fields only an admin changes (T23.2).
  let original = $state<Record<string, unknown>>({});
  const isAdmin = $derived(can('admin'));
  function locked(f: Field): boolean {
    if (isAdmin || !f.admin) return false;
    return typeof f.admin === 'function' ? f.admin(original) : true;
  }
  // Text of fields with `toText`/`fromText`, while editing.
  let texts = $state<Record<string, string>>({});
  let preview = $state<S['ConfigChange'] | null>(null);
  let result = $state<S['ConfigChange'] | null>(null);
  let busy = $state(false);
  let formError = $state<unknown>(null);
  const writable = $derived(can(role ?? 'operator'));
  const advanced = $derived(currentMode() === 'advanced');
  const shown = $derived(fields.filter((f) => advanced || !f.advanced));

  async function load() {
    try {
      entries = (await api.configEntries(kind)).items;
      error = null;
    } catch (e) {
      error = e;
    } finally {
      entriesLoaded = true;
    }
  }
  $effect(() => {
    void kind;
    void load();
  });

  const badge: Record<string, [string, string]> = {
    file: ['config file', ''],
    added: ['added here', 'ok'],
    override: ['overrides the file', 'warn'],
    hidden: ['hidden', 'bad'],
  };

  function open(e?: S['ConfigEntry'], fill: Record<string, unknown> = {}, name = '') {
    preview = null;
    result = null;
    formError = null;
    formOut = null;
    const def = (e?.definition ?? {}) as Record<string, unknown>;
    original = { ...def };
    const initial = e ? {} : Object.fromEntries(fields.filter((f) => f.initial !== undefined).map((f) => [f.key, f.initial]));
    editing = { name: e?.name ?? name, isNew: !e, values: { ...initial, ...def, ...fill } };
    texts = Object.fromEntries(fields.filter((f) => f.toText).map((f) => [f.key, f.toText!(editing!.values[f.key])]));
  }
  // REQ: FLT-005 (T24.15) — a draft from another page opens a new entry, once per draft object. The
  // name is made unused among the loaded entries (`iot` becomes `iot-2` when `iot` exists).
  let draftTaken: unknown = null;
  function freeName(base: string): string {
    const taken = new Set(entries.map((e) => e.name.toLowerCase()));
    if (!base || !taken.has(base.toLowerCase())) return base;
    for (let i = 2; ; i++) {
      const candidate = `${base}-${i}`;
      if (!taken.has(candidate)) return candidate;
    }
  }
  $effect(() => {
    const d = draft;
    if (!d || !entriesLoaded || d === draftTaken) return;
    draftTaken = d;
    untrack(() => {
      if (writable) open(undefined, d.values, freeName(d.name ?? ''));
      d.onused?.();
    });
  });
  // REQ: FLT-005 (T24.15) — a new entry never replaces an existing one of the same name.
  function nameTaken(name: string): boolean {
    const n = name.trim().toLowerCase();
    return !!editing?.isNew && entries.some((e) => e.name.toLowerCase() === n);
  }

  // The body: the fields shown, with empty ones left out (the defaults apply); other fields of
  // an existing entry are kept as they were.
  function body(): Record<string, unknown> {
    const v = { ...editing!.values };
    delete v.name;
    for (const f of fields) if (f.fromText) v[f.key] = f.fromText(texts[f.key] ?? '');
    for (const f of fields) {
      const x = v[f.key];
      if (x === '' || x === null || x === undefined || (Array.isArray(x) && x.length === 0 && f.type !== 'multi')) delete v[f.key];
    }
    return v;
  }

  function sameNameError(): Error {
    return new Error(`A ${noun} called ${editing!.name.trim()} already exists. Pick another name.`);
  }
  async function check(e: SubmitEvent) {
    e.preventDefault();
    if (!editing) return;
    if (nameTaken(editing.name)) {
      formError = sameNameError();
      preview = null;
      return;
    }
    busy = true;
    formError = null;
    try {
      preview = await api.putEntry(path, editing.name.trim(), body(), true);
    } catch (err) {
      formError = err;
      preview = null;
    } finally {
      busy = false;
    }
  }
  async function apply() {
    if (!editing) return;
    if (nameTaken(editing.name)) {
      formError = sameNameError();
      return;
    }
    busy = true;
    try {
      result = await api.putEntry(path, editing.name.trim(), body(), false);
      preview = null;
      await load();
      onchanged?.();
      if (!result.keepInGit) editing = null;
      // Saved and kept for Git: it exists now, so a second save is an update, not a new name.
      else if (editing) editing = { ...editing, isNew: false };
    } catch (err) {
      formError = err;
    } finally {
      busy = false;
    }
  }
  async function remove(e: S['ConfigEntry']) {
    busy = true;
    error = null;
    try {
      result = await api.deleteEntry(path, e.name);
      await load();
      onchanged?.();
      if (result.keepInGit) editing = { name: e.name, isNew: false, values: {} };
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }
  // REQ: OBS-024 — kinds whose changes move decisions can be replayed over the query log.
  const replayable = $derived(['upstream', 'upstream_group', 'list', 'group', 'schedule'].includes(kind));
  async function simulateDraft(): Promise<S['Simulation'] | null | undefined> {
    if (!editing) return null;
    return (await api.putEntry(path, editing.name.trim(), body(), true, 'true')).simulation;
  }
  const lines = (v: unknown) => (Array.isArray(v) ? v.join('\n') : '');
  const toLines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean);
</script>

<section class="card" data-testid={`editor-${kind}`}>
  <div class="head">
    <h2>{title}{#if help}<HelpButton id={help} />{:else}<HelpButton id="config-sources" />{/if}</h2>
    {#if writable && !singleton}<button onclick={() => open()}>Add {noun}</button>{/if}
  </div>
  <ErrorNote {error} />
  {#if entries.length === 0}
    <p class="empty">None yet.</p>
  {:else}
    <div class="table-wrap">
      <table class="compact">
        <tbody>
          {#each entries as e (e.name)}
            {@const [label, cls] = badge[e.source] ?? [e.source, '']}
            <tr data-testid="entry-row">
              <td>
                <strong>{e.name}</strong><span class="badge {cls}">{label}</span>
                <!-- REQ: API-014 (T23.2) — a stored path the node refuses to read. -->
                {#each e.credentialIssues ?? [] as i (i.field)}
                  <span class="badge bad" title={i.reason} data-testid="credential-issue">{i.field} not read</span>
                {/each}
              </td>
              <td class="small muted">{e.definition ? summary(e.definition as Record<string, unknown>) : 'left out of the configuration'}</td>
              {#if writable}
                <td class="actions">
                  {#if rowAction && e.source !== 'hidden'}
                    <button class="link small" onclick={() => runAction(e.name)}>{rowAction.label}</button>
                  {/if}
                  {#if e.source !== 'hidden'}<button class="link small" onclick={() => open(e)}>Edit</button>{/if}
                  {#if e.source === 'override' || e.source === 'hidden'}
                    <button class="link small" disabled={busy} onclick={() => remove(e)}>Revert to the file</button>
                  {:else if !singleton}
                    <button class="link small danger" disabled={busy} onclick={() => remove(e)}>Remove</button>
                  {/if}
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if actionOut}
    <p class="notice small {actionOut.ok ? 'ok' : 'bad'}" role="status" data-testid="row-action-result">
      <strong>{actionOut.name}</strong>: {actionOut.text}
    </p>
  {/if}
</section>

{#if editing}
  <Drawer title={editing.isNew ? `Add ${noun}` : `${noun}: ${editing.name}`} onclose={() => (editing = null)}>
    {#if result?.keepInGit}
      <p class="notice ok small">{result.applied ? 'Saved.' : ''}</p>
      <KeepInGit toml={result.keepInGit} />
      <button onclick={() => (editing = null)}>Done</button>
    {:else}
      <form class="form" onsubmit={check}>
        <label>
          Name
          <input class="mono" bind:value={editing.name} required readonly={!editing.isNew} aria-label="Name" />
        </label>
        {#each shown as f (f.key)}
          <label>
            {f.label}
            {#if f.type === 'select'}
              <select bind:value={editing.values[f.key]} aria-label={f.label} disabled={locked(f)}>
                <option value={undefined}>(default)</option>
                {#each f.options ?? [] as o (o)}<option value={o}>{o}</option>{/each}
              </select>
            {:else if f.type === 'multi'}
              <!-- Values chosen earlier that aren't offered now (a node gone) stay visible. -->
              {@const chosen = (editing.values[f.key] as string[] | undefined) ?? []}
              <span class="multi" role="group" aria-label={f.label}>
                {#each [...new Set([...(f.options ?? []), ...chosen])] as o (o)}
                  {@const arr = (editing.values[f.key] as string[] | undefined) ?? []}
                  <label class="check"
                    ><input
                      type="checkbox"
                      checked={arr.includes(o)}
                      onchange={(ev) =>
                        (editing!.values[f.key] = (ev.currentTarget as HTMLInputElement).checked
                          ? [...arr, o]
                          : arr.filter((x) => x !== o))}
                    />{f.optionLabels?.[o] ?? o}</label
                  >
                {/each}
              </span>
            {:else if f.type === 'lines' && f.fromText}
              <textarea
                rows="4"
                class="mono"
                placeholder={f.placeholder}
                aria-label={f.label}
                bind:value={texts[f.key]}
              ></textarea>
            {:else if f.type === 'lines'}
              <textarea
                rows="4"
                class="mono"
                placeholder={f.placeholder}
                aria-label={f.label}
                value={lines(editing.values[f.key])}
                oninput={(ev) => (editing!.values[f.key] = toLines((ev.currentTarget as HTMLTextAreaElement).value))}
              ></textarea>
            {:else if f.type === 'bool'}
              <input type="checkbox" role="switch" bind:checked={editing.values[f.key] as boolean} aria-label={f.label} />
            {:else if f.type === 'number'}
              <!-- step="any": thresholds such as 0.5 % are allowed. -->
              <input type="number" step="any" bind:value={editing.values[f.key]} placeholder={f.placeholder} aria-label={f.label} />
            {:else}
              <input class="mono" bind:value={editing.values[f.key]} placeholder={f.placeholder} aria-label={f.label} readonly={locked(f)} />
            {/if}
            {#if locked(f)}<span class="muted small" data-testid="admin-only">Only an admin can change this.</span>{/if}
            {#if f.help}<span class="muted small">{f.help}</span>{/if}
          </label>
        {/each}
        {#if note}<p class="small" data-testid="editor-note">{note(editing.values)}</p>{/if}
        <ErrorNote error={formError} />
        {#if preview}
          <div class="preview" data-testid="entry-preview">
            <p><b>What this will do:</b> {preview.impact || 'Changes the configuration as shown.'}</p>
            {#each preview.warnings as w (w)}<p class="small warn-text">{w}</p>{/each}
            {#if replayable}<SimulationCard run={simulateDraft} />{/if}
          </div>
          <div class="row">
            <button type="button" class="primary" disabled={busy} onclick={apply}>Apply</button>
            <button type="button" onclick={() => (preview = null)}>Change it</button>
          </div>
        {:else}
          <div class="row">
            <button class="primary" disabled={busy || !editing.name.trim()}>Check</button>
            {#if formAction}<button type="button" onclick={runFormAction}>{formAction.label}</button>{/if}
          </div>
        {/if}
        {#if formOut}
          <p class="notice small {formOut.ok ? 'ok' : 'bad'}" data-testid="form-action-result" role="status">
            {formOut.text}
          </p>
        {/if}
      </form>
    {/if}
  </Drawer>
{/if}

<style>
  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }
  .head h2 {
    margin: 0;
  }
  .badge {
    margin-left: 8px;
  }
  .actions {
    text-align: right;
    white-space: nowrap;
  }
  .actions button + button {
    margin-left: 10px;
  }
  .form {
    display: grid;
    gap: 12px;
  }
  .form label {
    display: grid;
    gap: 4px;
  }
  .multi {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 14px;
  }
  .check {
    display: inline-flex !important;
    align-items: center;
    gap: 6px;
  }
  .preview {
    border: 1px dashed var(--border);
    border-radius: 8px;
    padding: 10px 12px;
  }
  .preview p {
    margin: 0 0 4px;
  }
  .warn-text {
    color: var(--warn-strong, var(--warn));
  }
  .row {
    display: flex;
    gap: 8px;
  }
  .danger {
    color: var(--bad);
  }
</style>
