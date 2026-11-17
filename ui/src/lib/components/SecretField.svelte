<script lang="ts" module>
  // REQ: API-015, API-014 (T23.6, ADR-903 §9, ADR-919) — the only way a credential is entered. Write-only:
  // the value goes to `PUT /api/v1/secrets/{name}` once and is never shown, read back or pre-filled
  // again (the answer carries metadata only). Shown in one of these states:
  //   unset       nothing stored under the name; a value can be saved (admins)
  //   exists      an entry (no reference yet) names a secret that is stored: use it, or replace it
  //   set         stored and referenced; a replacement can be typed (admins), or it can be cleared
  //   replace     a new value is being typed over a stored one (admins); standalone, a typed name
  //               that's stored is a replacement too
  //   clear       the entry stops using the secret when it is applied (undo until then)
  //   missing     an entry names a secret that isn't stored: enter it again
  //   unreadable  stored, but this node can't read it (another key made it, or it's damaged)
  //   file        the configuration file sets the path (read-only; the file wins, ADR-903 §2)
  //   inline      the configuration file sets the value inline (read-only)
  // Used by the Alerts destinations (ConfigEditor, `type: 'secret'`), the Integrations & secrets
  // page's stored-secret form, and later by the routers (T23.8) and the other forms (T24.16).
  export const SECRET_NAME = /^[a-z0-9][a-z0-9._-]{0,62}$/;

  // ADR-919: a new secret is `<kind>.<entry>.<field>`, the entry's name lowercased and slugged, and
  // the whole name at most 63 characters (the entry part is cut to fit). An unnamed entry has no
  // default name (`''`), so a secret is never saved as `alert..token`.
  export function secretNameFor(kind: string, entry: string, field: string): string {
    const slug = entry.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    if (!slug) return '';
    const room = 63 - kind.length - field.length - 2;
    const cut = slug.slice(0, Math.max(0, room)).replace(/-+$/, '');
    return cut ? `${kind}.${cut}.${field}` : '';
  }
</script>

<script lang="ts">
  import { untrack } from 'svelte';
  import { ApiError, api, type S } from '../api';
  import ErrorNote from './ErrorNote.svelte';
  import { secretsHead } from '../secrets-head.svelte';
  import HelpButton from './HelpButton.svelte';

  type Mode = 'file' | 'inline' | 'clear' | 'unreadable' | 'exists' | 'set' | 'replace' | 'missing' | 'unset';

  let {
    label,
    testid = 'secret-field',
    help,
    reference,
    onreference,
    defaultName = '',
    nameLabel,
    filePath,
    fileFromConfig = false,
    fileReadable,
    fileReason,
    inline = false,
    canSet,
    kind = 'text',
    startReplacing = false,
    ondirty,
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
    /** The label of the name input (standalone: `Secret name`). */
    nameLabel?: string;
    /** The `*_file` path the configuration sets (or the API set), if any. */
    filePath?: string;
    /** True when the configuration files set the path: it wins and is read-only here. */
    fileFromConfig?: boolean;
    /** Whether this node can read the file (judged without reading it). */
    fileReadable?: boolean;
    /** Why this node can't read the file. */
    fileReason?: string | null;
    /** True when the configuration files set the value inline: read-only here. */
    inline?: boolean;
    /** Only an admin may set or clear (the server enforces it). */
    canSet: boolean;
    /** The value kind on the wire (`text`; `pem` is reserved). */
    kind?: string;
    /** Standalone: open straight into a replacement (the table's Replace). */
    startReplacing?: boolean;
    /** True while a value is typed and not saved (or discarded): the form can't be applied then. */
    ondirty?: (dirty: boolean) => void;
    onsaved?: (name: string) => void;
    /** Standalone only: the secret was deleted from this field. */
    onremoved?: (name: string) => void;
  } = $props();

  // The stored secrets as this node knows them (names, stamps and users; never values), the
  // secrets head's etag (sent as If-Match on a write) and this node's name.
  let all = $state<S['SecretMeta'][]>([]);
  let here = $state('');
  let loaded = $state(false);
  // The head this field last read (the shared head moving past it means a sibling wrote).
  let seenHead: string | undefined = undefined;
  let loadError = $state<unknown>(null);
  // The name typed in the name input; undefined until it's typed (the default shows).
  let typedName = $state<string | undefined>(undefined);
  let value = $state('');
  let replacing = $state(untrack(() => startReplacing));
  let clearedName = $state<string | undefined>(undefined);
  let busy = $state(false);
  let error = $state<unknown>(null);
  // The secret's name is in use elsewhere: a force is offered when only unknown members block it.
  let forceable = $state(false);
  // The server refused plain HTTP (403 insecure_transport): the field says how to fix it.
  let refused = $state(false);

  const insecure = typeof location !== 'undefined' && location.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  const nameText = $derived(nameLabel ?? `${label} name`);

  async function reload() {
    try {
      const r = await api.secrets();
      all = r.items;
      secretsHead.etag = r.head.etag;
      seenHead = r.head.etag;
      here = r.store.node;
      loaded = true;
      loadError = null;
    } catch (e) {
      loadError = e;
    }
  }
  // The list is read on mount and again when the name is typed into (the name may be stored
  // elsewhere since), so the field says whether the name is already stored.
  $effect(() => {
    void reload();
  });
  // A sibling field wrote (the shared head moved): this field's list is stale, so it reloads too.
  $effect(() => {
    const e = secretsHead.etag;
    if (loaded && e !== seenHead) void reload();
  });

  const shownName = $derived(typedName ?? defaultName);
  const nameInput = $derived(shownName.trim());
  // The name a save writes: the referenced one, else the typed one.
  const target = $derived(reference ?? nameInput);
  const meta = $derived(all.find((s) => s.name === target));
  // Stored, but this node holds no readable copy (another key made it, or the row is damaged).
  const unreadableHere = $derived(Boolean(meta?.set && meta.nodes.find((n) => n.node === here)?.unreadable));
  const mode = $derived.by((): Mode => {
    if (fileFromConfig && filePath) return 'file';
    if (inline) return 'inline';
    if (!reference && clearedName) return 'clear';
    if (reference) {
      if (!loaded) return 'set';
      if (!meta?.set) return 'missing';
      if (unreadableHere && !replacing) return 'unreadable';
      return replacing ? 'replace' : 'set';
    }
    if (meta?.set) {
      if (unreadableHere && !replacing) return 'unreadable';
      if (replacing) return 'replace';
      // An entry that doesn't use the stored secret is offered it, never a delete (ADR-919).
      // Standalone, a stored name is replaced by the value typed under it.
      return onreference ? 'exists' : 'replace';
    }
    return 'unset';
  });
  const editable = $derived(canSet && mode !== 'file' && mode !== 'inline');
  const valid = $derived(SECRET_NAME.test(target));
  // Typed and not yet saved: the owner of the form holds Check and Apply until it's saved or discarded.
  const dirty = $derived(value.trim() !== '');
  $effect(() => {
    const d = dirty;
    ondirty?.(d);
    return () => ondirty?.(false);
  });

  function explain(e: unknown) {
    error = e;
    refused = e instanceof ApiError && e.code === 'insecure_transport';
    forceable = e instanceof ApiError && e.code === 'secret_in_use' && /can't be read now/.test(e.message);
    if (e instanceof ApiError && e.status === 412) {
      // Another admin changed the stored secrets since this page read them: show the list again.
      error = new Error('Someone else changed the stored secrets since this page was read. The list is reloaded: check it, then save again.');
      void reload();
    }
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
    const name = target;
    try {
      await api.putSecret(name, value, kind, false, secretsHead.etag);
      value = '';
      replacing = false;
      typedName = undefined;
      await reload();
      if (!reference) onreference?.(name);
      onsaved?.(name);
    } catch (e) {
      // The value stays out of the page on failure too: it's cleared here, not kept for a retry.
      value = '';
      explain(e);
    } finally {
      busy = false;
    }
  }

  // Clear unlinks the entry; the stored value stays until someone deletes it (ADR-919).
  function clear() {
    clearedName = reference;
    onreference?.(undefined);
  }
  function undo() {
    if (clearedName) onreference?.(clearedName);
    clearedName = undefined;
  }
  function useIt() {
    onreference?.(target);
  }

  // Standalone fields delete the secret itself (the server refuses while an entry names it).
  async function remove(force = false) {
    busy = true;
    error = null;
    forceable = false;
    try {
      const r = await api.deleteSecret(target, force, secretsHead.etag);
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
    {#if mode === 'unreadable'}<span class="badge bad" data-testid="secret-unreadable-badge">can't read it</span>{/if}
    {#if mode === 'file'}<span class="badge warn">set by file</span>{/if}
    {#if mode === 'inline'}<span class="badge warn">set inline</span>{/if}
    {#if mode === 'exists'}<span class="badge warn">already stored</span>{/if}
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
  {#if insecure && canSet && mode !== 'file' && mode !== 'inline'}
    <!-- The page can't tell whether the node allows plain HTTP for secrets, so it says "may". -->
    <p class="notice warn small" data-testid="secret-plain-http">
      This page is on plain HTTP, and the server may refuse a secret sent over it (it takes one only over HTTPS, or from the
      node itself). Turn on HTTPS, for example <code>[api] tls = {'{'} self_signed = true {'}'}</code>, or allow plain HTTP on a
      network you trust with <code>[api] allow_secrets_over_http = true</code>.
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
  {:else if mode === 'inline'}
    <p class="small" data-testid="secret-inline">Set inline in the configuration file. Change it there; the value is never shown here.</p>
  {:else if mode === 'unreadable'}
    <p class="small" data-testid="secret-unreadable">
      Stored as <code class="mono">{target}</code>, but this node (<strong>{here}</strong>) can't read it:
      {meta?.health === 'corrupt' ? 'the stored value is damaged' : 'another key made it'}. Replace it to make it readable here.
    </p>
  {:else if mode === 'exists'}
    <p class="small" data-testid="secret-exists">
      A secret named <code class="mono">{target}</code> is already stored. Use it for this entry, or replace its value.
    </p>
  {:else if mode === 'missing'}
    <p class="small" data-testid="secret-status"><span class="bad-text">Refers to <code class="mono">{target}</code>, which isn't stored. Enter it again.</span></p>
  {:else if mode === 'clear'}
    <p class="small" data-testid="secret-status"><span data-testid="secret-cleared">The entry stops using <code class="mono">{clearedName}</code> when you apply. The stored value stays until you delete it on Settings → Integrations &amp; secrets.</span></p>
  {:else if mode === 'set' || mode === 'replace'}
    <p class="small" data-testid="secret-status">
      Stored as <code class="mono">{target}</code>. Its value is never shown.
      {#if stamped}<span class="muted">Set {stamped}{meta?.updatedBy ? ` by ${meta.updatedBy}` : ''}.</span>{/if}
    </p>
  {/if}

  {#if editable && mode === 'set'}
    <div class="row">
      <button type="button" class="link small" onclick={() => (replacing = true)}>Replace</button>
      {#if onreference}<button type="button" class="link small danger" onclick={clear}>Clear</button>{/if}
    </div>
  {:else if editable && mode === 'exists'}
    <div class="row">
      <button type="button" class="primary small" onclick={useIt}>Use it</button>
      <button type="button" class="link small" onclick={() => (replacing = true)}>Replace</button>
    </div>
  {:else if editable && mode === 'unreadable'}
    <div class="row">
      <button type="button" class="link small" onclick={() => (replacing = true)}>Replace</button>
      {#if onreference}<button type="button" class="link small danger" onclick={clear}>Clear</button>{/if}
    </div>
  {:else if editable && mode === 'clear'}
    <div class="row"><button type="button" class="link small" onclick={undo}>Undo</button></div>
  {/if}

  {#if !fileFromConfig && filePath && mode !== 'file'}
    <p class="small muted" data-testid="secret-api-file">
      This entry reads <code class="mono">{filePath}</code>, set through the API. Saving a stored secret replaces that path.
      {#if editable && mode === 'unset' && onreference}
        <button type="button" class="link small danger" onclick={() => onreference?.(undefined)}>Remove the path</button>
      {/if}
    </p>
  {/if}

  {#if editable && (mode === 'unset' || mode === 'missing' || mode === 'replace')}
    <div class="entry" data-testid="secret-entry">
      {#if !reference && (mode === 'unset' || (mode === 'replace' && !onreference))}
        <label class="name">
          <span class="muted small">{nameText}</span>
          <input
            class="mono"
            aria-label={nameText}
            placeholder={defaultName || 'name'}
            value={shownName}
            oninput={(e) => (typedName = (e.currentTarget as HTMLInputElement).value)}
            onfocus={() => void reload()}
            autocomplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
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
        {#if dirty}<button type="button" class="link small" onclick={() => (value = '')}>Discard</button>{/if}
        {#if replacing}
          <button type="button" class="link small" onclick={() => { replacing = false; value = ''; }}>Cancel</button>
        {/if}
        {#if !onreference && meta?.set}
          <button type="button" class="link small danger" disabled={busy} onclick={() => remove(false)}>Delete</button>
        {/if}
      </div>
      {#if target && !valid}<p class="small bad-text">Use lowercase letters, digits, dots, underscores or dashes.</p>{/if}
    </div>
  {:else if !canSet && mode !== 'file' && mode !== 'inline' && mode !== 'set' && mode !== 'clear'}
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
