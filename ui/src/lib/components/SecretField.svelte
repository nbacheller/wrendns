<script lang="ts" module>
  // REQ: API-015, API-014 (T23.6, ADR-903 §9) — the only way a credential is entered. Write-only:
  // the value goes to `PUT /api/v1/secrets/{name}` once and is never shown, read back or pre-filled
  // again (the answer carries metadata only). Shown in one of these states:
  //   unset    nothing stored under the name; a value can be saved (admins)
  //   set      stored; a replacement can be typed (admins), or it can be cleared
  //   replace  a new value is being typed over a stored one (admins)
  //   clear    the entry stops using the secret when it is applied (undo until then)
  //   missing  an entry names a secret that isn't stored: enter it again
  //   file     the configuration file sets the value (read-only; the file wins, ADR-903 §2)
  // Used by the Alerts destinations (ConfigEditor, `type: 'secret'`), the Integrations & secrets
  // page's stored-secret form, and later by the routers (T23.8) and the other forms (T24.16).
  export const SECRET_NAME = /^[a-z0-9][a-z0-9._-]{0,62}$/;
</script>

<script lang="ts">
  import { ApiError, api, type S } from '../api';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    label,
    testid = 'secret-field',
    help,
    reference,
    onreference,
    defaultName = '',
    filePath,
    fileFromConfig = false,
    fileReadable,
    fileReason,
    canSet,
    kind = 'text',
    onsaved,
    onremoved,
  }: {
    /** The field's label, as the form names it (`Token`, `Password`). */
    label: string;
    /** `data-testid` of the wrapper (tests and the Playwright suite find fields by it). */
    testid?: string;
    /** A sentence about this field, under its label (the `?` topic is `secret-field`). */
    help?: string;
    /** The secret an entry's `*_ref` names, as the form draft holds it (`undefined`: none). When
     *  the field is standalone (the Integrations & secrets page), leave it out. */
    reference?: string;
    /** Called with the name the draft should reference, or `undefined` to unlink it. */
    onreference?: (name: string | undefined) => void;
    /** The name a new secret is saved under when nothing is referenced yet. */
    defaultName?: string;
    /** The `*_file` path the configuration sets (or the API set), if any. */
    filePath?: string;
    /** True when the configuration files set the path: it wins and is read-only here. */
    fileFromConfig?: boolean;
    /** Whether this node can read the file (judged without reading it). */
    fileReadable?: boolean;
    /** Why this node can't read the file. */
    fileReason?: string | null;
    /** Only an admin may set or clear (the server enforces it). */
    canSet: boolean;
    /** The value kind on the wire (`text`; `pem` is reserved). */
    kind?: string;
    onsaved?: (name: string) => void;
    /** Standalone only: the secret was deleted from this field. */
    onremoved?: (name: string) => void;
  } = $props();

  // The stored secrets as this node knows them (names, stamps and users; never values).
  let all = $state<S['SecretMeta'][]>([]);
  let loaded = $state(false);
  let loadError = $state<unknown>(null);
  // Typed name when nothing is referenced yet (standalone fields always type one).
  let typedName = $state('');
  let value = $state('');
  let replacing = $state(false);
  let clearedName = $state<string | undefined>(undefined);
  let busy = $state(false);
  let error = $state<unknown>(null);
  // The secret's name is in use elsewhere: a force is offered when only unknown members block it.
  let forceable = $state(false);
  // The server refused plain HTTP (403 insecure_transport): the field says how to fix it.
  let refused = $state(false);

  const insecure = typeof location !== 'undefined' && location.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);

  async function reload() {
    try {
      all = (await api.secrets()).items;
      loaded = true;
      loadError = null;
    } catch (e) {
      loadError = e;
    }
  }
  $effect(() => {
    void reload();
  });

  const nameInput = $derived((typedName.trim() || defaultName).trim());
  // The name a save writes: the referenced one, else the typed one.
  const target = $derived(reference ?? nameInput);
  const meta = $derived(all.find((s) => s.name === target));
  const mode = $derived.by((): 'file' | 'clear' | 'set' | 'missing' | 'replace' | 'unset' => {
    if (fileFromConfig && filePath) return 'file';
    if (!reference && clearedName) return 'clear';
    if (reference) {
      if (!loaded) return 'set';
      return meta?.set ? (replacing ? 'replace' : 'set') : 'missing';
    }
    if (meta?.set) return replacing ? 'replace' : 'set';
    return 'unset';
  });
  const editable = $derived(canSet && mode !== 'file');
  const valid = $derived(SECRET_NAME.test(target));

  function explain(e: unknown) {
    error = e;
    refused = e instanceof ApiError && e.code === 'insecure_transport';
    forceable = e instanceof ApiError && e.code === 'secret_in_use' && /can't be read now/.test(e.message);
  }

  async function save() {
    if (busy || !value.trim()) return;
    if (!valid) {
      error = new Error('A secret needs a name: lowercase letters, digits, dots, underscores or dashes, starting with a letter or digit.');
      return;
    }
    busy = true;
    error = null;
    refused = false;
    try {
      await api.putSecret(target, value, kind);
      value = '';
      replacing = false;
      await reload();
      if (!reference) onreference?.(target);
      onsaved?.(target);
    } catch (e) {
      // The value stays out of the page on failure too: it's cleared with the form's reset.
      value = '';
      explain(e);
    } finally {
      busy = false;
    }
  }

  function clear() {
    clearedName = reference;
    onreference?.(undefined);
  }
  function undo() {
    if (clearedName) onreference?.(clearedName);
    clearedName = undefined;
  }

  // Standalone fields delete the secret itself (the server refuses while an entry names it).
  async function remove(force = false) {
    busy = true;
    error = null;
    forceable = false;
    try {
      const r = await api.deleteSecret(target, force);
      await reload();
      onremoved?.(r.secret.name);
    } catch (e) {
      explain(e);
    } finally {
      busy = false;
    }
  }
  const stamped = $derived(meta?.updated ? new Date(meta.updated).toLocaleString() : '');
</script>

<div class="secret-field" data-testid={testid} data-mode={mode}>
  <div class="head">
    <span class="label">{label}</span>
    <HelpButton id="secret-field" />
    {#if mode === 'set' || mode === 'replace'}<span class="badge ok">set</span>{/if}
    {#if mode === 'missing'}<span class="badge bad">not set</span>{/if}
    {#if mode === 'file'}<span class="badge warn">set by file</span>{/if}
    {#if mode === 'clear'}<span class="badge warn">will be cleared</span>{/if}
  </div>

  {#if help}<p class="muted small">{help}</p>{/if}
  {#if refused}
    <p class="notice bad small" data-testid="secret-refused">
      The server takes a secret only over HTTPS, or from the node itself, so this value wasn't saved. Turn on HTTPS,
      for example <code>[api] tls = {'{'} self_signed = true {'}'}</code>, or, on a network you trust, allow plain HTTP with
      <code>[api] allow_secrets_over_http = true</code>.
    </p>
  {/if}
  {#if insecure && canSet && mode !== 'file'}
    <p class="notice warn small" data-testid="secret-plain-http">
      This page is on plain HTTP, and the server takes a secret only over HTTPS (or from the node itself).
      Turn on HTTPS, for example <code>[api] tls = {'{'} self_signed = true {'}'}</code>, or allow plain HTTP on a network you trust with <code>[api] allow_secrets_over_http = true</code>.
    </p>
  {/if}

  {#if mode === 'file'}
    <p class="small" data-testid="secret-file">
      Set by the configuration file: <code class="mono">{filePath}</code>
      {#if fileReadable === false}
        <span class="bad-text">(this node can't read it{fileReason ? `: ${fileReason}` : ''})</span>
      {:else if fileReadable}
        <span class="muted">(read on each node)</span>
      {/if}.
      The file wins over any stored secret, so it can only be changed there.
    </p>
  {:else if mode === 'set' || mode === 'missing' || mode === 'clear'}
    <p class="small" data-testid="secret-status">
      {#if mode === 'set'}
        Stored as <code class="mono">{target}</code>. Its value is never shown.
        {#if stamped}<span class="muted">Set {stamped}{meta?.updatedBy ? ` by ${meta.updatedBy}` : ''}.</span>{/if}
      {:else if mode === 'missing'}
        <span class="bad-text">Refers to <code class="mono">{target}</code>, which isn't stored. Enter it again.</span>
      {:else}
        <span data-testid="secret-cleared">The entry stops using <code class="mono">{clearedName}</code> when you apply. The stored value stays until you delete it on Settings → Integrations &amp; secrets.</span>
      {/if}
    </p>
    {#if editable && mode === 'set'}
      <div class="row">
        <button type="button" class="link small" onclick={() => (replacing = true)}>Replace</button>
        {#if reference !== undefined && onreference}
          <button type="button" class="link small danger" onclick={clear}>Clear</button>
        {:else}
          <button type="button" class="link small danger" disabled={busy} onclick={() => remove(false)}>Delete</button>
        {/if}
      </div>
    {:else if editable && mode === 'clear'}
      <div class="row"><button type="button" class="link small" onclick={undo}>Undo</button></div>
    {/if}
  {:else if fileFromConfig === false && filePath}
    <p class="small muted" data-testid="secret-api-file">
      This entry reads <code class="mono">{filePath}</code>, set through the API. Saving a stored secret replaces that path.
    </p>
  {/if}

  {#if editable && (mode === 'unset' || mode === 'missing' || mode === 'replace')}
    <div class="entry" data-testid="secret-entry">
      {#if mode !== 'replace' && !reference}
        <label class="name">
          <span class="muted small">Stored as</span>
          <input class="mono" aria-label={`${label} name`} placeholder={defaultName || 'name'} bind:value={typedName} autocomplete="off" data-1p-ignore data-lpignore="true" />
        </label>
      {/if}
      <label class="value">
        <span class="muted small">{mode === 'replace' ? 'New value' : 'Value'}</span>
        <input
          type="password"
          aria-label={label}
          bind:value={value}
          autocomplete="new-password"
          autocapitalize="off"
          autocorrect="off"
          spellcheck="false"
          data-1p-ignore
          data-lpignore="true"
          data-form-type="other"
          onkeydown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              void save();
            }
          }}
        />
      </label>
      <div class="row">
        <button type="button" class="primary small" disabled={busy || !value.trim() || !valid} onclick={save}>
          {mode === 'replace' ? 'Save new value' : 'Save secret'}
        </button>
        {#if mode === 'replace'}<button type="button" class="link small" onclick={() => { replacing = false; value = ''; }}>Cancel</button>{/if}
      </div>
      {#if target && !valid}<p class="small bad-text">Use lowercase letters, digits, dots, underscores or dashes.</p>{/if}
    </div>
  {:else if !canSet && mode !== 'file' && mode !== 'set' && mode !== 'clear'}
    <p class="small muted" data-testid="secret-admin-only">Only an admin can set a stored secret.</p>
  {:else if !canSet && mode === 'set'}
    <p class="small muted" data-testid="secret-admin-only">Only an admin can replace or clear it.</p>
  {/if}

  {#if loadError}<p class="small muted">The stored secrets can't be listed right now.</p>{/if}
  <ErrorNote error={error} />
  {#if forceable && editable}
    <div class="row">
      <button type="button" class="danger small" disabled={busy} onclick={() => remove(true)}>Delete anyway</button>
    </div>
  {/if}
</div>

<style>
  .secret-field {
    display: grid;
    gap: 6px;
  }
  .head {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .label {
    font-weight: 600;
  }
  .entry,
  .name,
  .value {
    display: grid;
    gap: 4px;
  }
  .row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
  }
  .bad-text {
    color: var(--bad);
  }
  .danger {
    color: var(--bad);
  }
</style>
