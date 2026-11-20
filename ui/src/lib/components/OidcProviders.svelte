<script lang="ts">
  // REQ: API-016 (T23.10, ADR-903 §6, ADR-967) — Settings → Sign-in (admins): the OIDC providers
  // people sign in with. A provider added, changed or removed here applies on every node within
  // seconds, with no restart; a provider the configuration file defines is read-only ("set by
  // file"); the client secret goes through SecretField (write-only, stored by name); a node whose
  // file has no `public_url` shows every provider as inactive, with the reason.
  import { api, ApiError, type S } from '../api';
  import { poll } from '../poll';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import SecretField, { secretNameFor } from './SecretField.svelte';
  import { href } from '../router.svelte';

  type Entry = S['OidcProviderEntry'];
  type Role = 'viewer' | 'operator' | 'admin';

  let items = $state<Entry[]>([]);
  let publicUrl = $state('');
  let loaded = $state(false);
  let error = $state<unknown>(null);
  let notice = $state('');

  const secretLabel: Record<string, string> = {
    stored: 'stored',
    file: 'set by file',
    inline: 'set inline in the file',
    none: 'none (a public client)',
  };

  async function load() {
    try {
      const r = await api.oidcProviders();
      items = r.items;
      publicUrl = r.publicUrl;
      loaded = true;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 10_000));
  // A change reaches this node's service within a second or so: read the status again then, so the card
  // doesn't say "not applied yet" until the next poll.
  const reloadSoon = () => {
    setTimeout(() => void load(), 1_500);
  };

  // ---- the editor: one provider, a new one or the one being changed
  type Form = {
    original: string | null;
    id: string;
    name: string;
    issuer: string;
    client_id: string;
    client_secret_ref: string | undefined;
    scopes: string;
    username_claim: string;
    groups_claim: string;
    rules: { group: string; role: Role }[];
    default_role: '' | Role;
    require_verified_email: boolean;
  };
  let form = $state<Form | null>(null);
  let formError = $state('');
  let busy = $state(false);
  let confirmDelete = $state<string | null>(null);
  // A secret typed and not yet saved: Save the provider waits for it (as the routers do).
  let secretDirty = $state(false);

  function blank(): Form {
    return {
      original: null,
      id: '',
      name: '',
      issuer: 'https://',
      client_id: '',
      client_secret_ref: undefined,
      scopes: 'openid profile email',
      username_claim: 'preferred_username',
      groups_claim: 'groups',
      rules: [],
      default_role: '',
      require_verified_email: false,
    };
  }

  function openAdd() {
    form = blank();
    formError = '';
    notice = '';
  }

  function openEdit(e: Entry) {
    form = {
      original: e.id,
      id: e.id,
      name: e.name === e.id ? '' : e.name,
      issuer: e.issuer,
      client_id: e.clientId,
      client_secret_ref: e.secret ?? undefined,
      scopes: e.scopes.join(' '),
      username_claim: e.usernameClaim,
      groups_claim: e.groupsClaim,
      rules: e.roles.map((r) => ({ group: r.group, role: r.role as Role })),
      default_role: (e.defaultRole as Role | undefined) ?? '',
      require_verified_email: e.requireVerifiedEmail,
    };
    formError = '';
    notice = '';
  }

  function closeForm() {
    form = null;
    formError = '';
    secretDirty = false;
  }

  /** The request body the form sends: the fields of `[[auth.oidc.provider]]`, the secret by name. */
  function bodyOf(f: Form): Record<string, unknown> {
    const b: Record<string, unknown> = {
      issuer: f.issuer.trim(),
      client_id: f.client_id.trim(),
      scopes: f.scopes.split(/[\s,]+/).filter(Boolean),
      username_claim: f.username_claim.trim() || 'preferred_username',
      groups_claim: f.groups_claim.trim() || 'groups',
      role: f.rules.filter((r) => r.group.trim()).map((r) => ({ group: r.group.trim(), role: r.role })),
      require_verified_email: f.require_verified_email,
    };
    if (f.name.trim()) b.name = f.name.trim();
    if (f.default_role) b.default_role = f.default_role;
    if (f.client_secret_ref) b.client_secret_ref = f.client_secret_ref;
    return b;
  }

  const idOk = (n: string) => /^[a-z0-9-]{1,32}$/.test(n);
  // Add never replaces a provider: an ID another one holds is refused before anything is stored.
  const idTaken = $derived.by(() => {
    if (form === null || form.original !== null) return false;
    const id = form.id.trim().toLowerCase();
    return items.some((i) => i.id === id);
  });

  async function save() {
    if (!form) return;
    formError = '';
    const id = form.id.trim().toLowerCase();
    if (idTaken) {
      formError = `A provider with the ID ${id} exists. Change it, or choose another ID.`;
      return;
    }
    if (!idOk(id)) {
      formError = 'The ID is 1 to 32 lower-case letters, digits, or dashes.';
      return;
    }
    if (!/^https?:\/\//.test(form.issuer.trim())) {
      formError = 'The issuer starts with https:// (http:// only for a provider on this machine).';
      return;
    }
    if (!form.client_id.trim()) {
      formError = 'Enter the client ID that the provider gave this server.';
      return;
    }
    if (!form.scopes.split(/[\s,]+/).includes('openid')) {
      formError = 'The scopes must include openid.';
      return;
    }
    busy = true;
    try {
      await api.putOidcProvider(id, bodyOf(form));
      notice = `Saved ${id}. It applies on every node within seconds, with no restart.`;
      closeForm();
      await load();
      reloadSoon();
    } catch (e) {
      formError = e instanceof ApiError ? e.message : 'The provider could not be saved.';
    } finally {
      busy = false;
    }
  }

  async function remove(id: string) {
    busy = true;
    try {
      await api.deleteOidcProvider(id);
      notice = `Removed ${id}. Its sign-in button is gone, and the sessions it opened have ended.`;
      confirmDelete = null;
      await load();
      reloadSoon();
    } catch (e) {
      notice = e instanceof ApiError ? e.message : 'The provider could not be removed.';
    } finally {
      busy = false;
    }
  }

  function addRule() {
    form?.rules.push({ group: '', role: 'viewer' });
  }
  function dropRule(i: number) {
    form?.rules.splice(i, 1);
  }
</script>

<section class="card" data-testid="signin-tab">
  <h2>Sign in with a provider<HelpButton id="oidc-providers" /></h2>
  <p class="muted">
    Keycloak, Authentik, Google, or any OpenID Connect provider. People sign in with their account there, and the groups it reports decide their role. A
    provider you add, change or remove here applies on every node within seconds, with no restart. Password sign-in for the break-glass admin
    is not touched.
  </p>
  <ErrorNote {error} />
  {#if notice}<p class="notice" role="status" data-testid="oidc-notice">{notice}</p>{/if}
  {#if loaded && !publicUrl}
    <p class="notice warn" role="status" data-testid="oidc-no-public-url">
      This node has no <code>public_url</code> in its <code>[auth.oidc]</code> section, so every provider is inactive here. Set it in this node's configuration file
      to the address people open the UI at (it is different on each node).<HelpButton id="oidc-public-url" />
    </p>
  {/if}
  <div class="row-actions">
    <button type="button" class="btn primary" data-testid="oidc-add" onclick={openAdd} disabled={form !== null}>Add a provider</button>
  </div>

  {#if form}
    <div class="card inner" data-testid="oidc-editor" role="group" aria-label={form.original ? `Edit ${form.original}` : 'Add a provider'}>
      <h3>{form.original ? `Change ${form.original}` : 'Add a provider'}</h3>
      <div class="grid">
        <label>
          <span>ID</span>
          <input bind:value={form.id} disabled={form.original !== null} placeholder="keycloak" autocomplete="off" aria-label="ID" />
          {#if idTaken}<span class="small bad-text" role="alert" data-testid="oidc-id-taken">A provider with the ID {form.id.trim().toLowerCase()} exists. Change it, or choose another ID.</span>{/if}
        </label>
        <label>
          <span>Button label (optional)</span>
          <input bind:value={form.name} placeholder="Keycloak" autocomplete="off" aria-label="Button label" />
        </label>
        <label>
          <span>Issuer</span>
          <input bind:value={form.issuer} placeholder="https://id.example.com/realms/home" autocomplete="off" aria-label="Issuer" />
        </label>
        <label>
          <span>Client ID</span>
          <input bind:value={form.client_id} placeholder="wrendns" autocomplete="off" aria-label="Client ID" />
        </label>
        <label>
          <span>Scopes</span>
          <input bind:value={form.scopes} autocomplete="off" aria-label="Scopes" />
        </label>
        <label>
          <span>Username claim</span>
          <input bind:value={form.username_claim} autocomplete="off" aria-label="Username claim" />
        </label>
        <label>
          <span>Groups claim</span>
          <input bind:value={form.groups_claim} autocomplete="off" aria-label="Groups claim" />
        </label>
      </div>

      <h4>Client secret</h4>
      <p class="small muted">
        Entered once, stored encrypted on the node and replicated to the other nodes, and never shown again. Leave it empty for a public client (PKCE only).
        <a href={href('/settings', { tab: 'secrets' })}>Stored secrets</a> lists them.
      </p>
      {#if form.id.trim() && !idTaken}
        <SecretField
          label="Client secret"
          testid="oidc-secret"
          reference={form.client_secret_ref}
          defaultName={secretNameFor('oidc', form.id, 'client_secret')}
          canSet={true}
          ondirty={(d) => (secretDirty = d)}
          onreference={(n) => form && (form.client_secret_ref = n)}
        />
      {:else if !idTaken}
        <p class="small muted">Enter an ID first: the stored secret is named after the provider.</p>
      {/if}
      {#if secretDirty}<p class="notice warn small" role="status" data-testid="oidc-secret-unsaved">Save or discard the secret you typed first; Save the provider waits for it.</p>{/if}

      <h4>Roles <HelpButton id="oidc-role-rules" /></h4>
      <p class="small muted">A person gets the highest role that any of their groups maps to.</p>
      {#each form.rules as rule, i (i)}
        <div class="rule" data-testid="oidc-rule">
          <input bind:value={rule.group} placeholder="dns-admins" autocomplete="off" aria-label={`Group ${i + 1}`} />
          <select bind:value={rule.role} aria-label={`Role for group ${i + 1}`}>
            <option value="viewer">viewer</option>
            <option value="operator">operator</option>
            <option value="admin">admin</option>
          </select>
          <button type="button" class="btn" aria-label={`Remove rule ${i + 1}`} onclick={() => dropRule(i)}>Remove</button>
        </div>
      {/each}
      <div class="row-actions">
        <button type="button" class="btn" data-testid="oidc-add-rule" onclick={addRule}>Add a group</button>
      </div>
      <div class="grid">
        <label>
          <span>Role for everyone else</span>
          <select bind:value={form.default_role} aria-label="Role for everyone else">
            <option value="">None: people in no mapped group can't sign in</option>
            <option value="viewer">viewer</option>
            <option value="operator">operator</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <label class="check">
          <input type="checkbox" bind:checked={form.require_verified_email} />
          <span>Only people whose email the provider has verified</span>
        </label>
      </div>
      {#if form.rules.every((r) => !r.group.trim()) && !form.default_role}
        <p class="small warn-text" role="status">No group is mapped and there is no default role: nobody could sign in with this provider.</p>
      {/if}

      {#if formError}<p class="bad-text" role="alert">{formError}</p>{/if}
      <div class="row-actions">
        <button type="button" class="btn primary" data-testid="oidc-save" onclick={save} disabled={busy || idTaken || secretDirty}>Save the provider</button>
        <button type="button" class="btn" onclick={closeForm}>Cancel</button>
      </div>
    </div>
  {/if}

  {#if loaded && items.length === 0 && !error}
    <p class="empty" data-testid="oidc-empty">No providers yet. Add one to let people sign in with an account they already have.</p>
  {/if}

  {#each items as e (e.id)}
    <div class="card inner provider" data-testid="oidc-card" role="group" aria-label={e.id}>
      <div class="card-head">
        <h3>{e.name}</h3>
        <span class="mono small">{e.id}</span>
        {#if e.source === 'file'}<span class="badge warn" data-testid="oidc-file">Set by file</span>{:else}<span class="badge">From the UI</span>{/if}
        {#if e.active}
          <span class="badge ok" data-testid="oidc-state">Active</span>
        {:else}
          <span class="badge bad" data-testid="oidc-state">Inactive on this node</span>
        {/if}
      </div>
      <p class="mono small">{e.issuer}</p>
      {#if e.reason}<p class={e.active ? 'small warn-text' : 'small bad-text'} data-testid="oidc-reason">{e.reason}</p>{/if}
      <ul class="facts small">
        <li>Client ID: <span class="mono">{e.clientId}</span></li>
        <li>
          Client secret: {secretLabel[e.secretSource] ?? e.secretSource}
          {#if e.secretSource === 'stored'}
            (<span class="mono">{e.secret}</span>)
            {#if e.secretReadable === false}<span class="badge bad" data-testid="oidc-secret-issue">can't be read on this node</span>{:else}<span class="badge ok">readable</span>{/if}
          {/if}
        </li>
        <li>
          Roles:
          {#if e.roles.length}
            {e.roles.map((r) => `${r.group} → ${r.role}`).join(', ')}
          {:else}
            none mapped
          {/if}
          {#if e.defaultRole}; everyone else: {e.defaultRole}{/if}
        </li>
        {#if e.redirectUri}<li>Redirect URI to register with the provider: <span class="mono" data-testid="oidc-redirect">{e.redirectUri}</span></li>{/if}
      </ul>
      {#if e.source === 'file'}
        <p class="small muted">The configuration file defines this provider, so it's read-only here.</p>
      {:else}
        <div class="row-actions">
          <button type="button" class="btn" data-testid="oidc-edit" onclick={() => openEdit(e)} disabled={form !== null}>Change</button>
          {#if confirmDelete === e.id}
            <button type="button" class="btn danger" data-testid="oidc-delete-confirm" onclick={() => remove(e.id)} disabled={busy}>Yes, remove {e.id}</button>
            <button type="button" class="btn" onclick={() => (confirmDelete = null)}>Keep it</button>
          {:else}
            <button type="button" class="btn danger" data-testid="oidc-delete" onclick={() => (confirmDelete = e.id)}>Remove</button>
          {/if}
        </div>
      {/if}
    </div>
  {/each}
</section>

<style>
  .row-actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin: 0.5rem 0;
  }
  .grid {
    display: grid;
    gap: 0.75rem;
    grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
  }
  label {
    display: grid;
    gap: 0.25rem;
  }
  label.check {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .rule {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin: 0.25rem 0;
  }
  .rule input {
    flex: 1 1 12rem;
  }
  .inner {
    margin-top: 0.75rem;
  }
  .provider .card-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .facts {
    list-style: none;
    padding: 0;
    margin: 0.25rem 0;
    display: grid;
    gap: 0.25rem;
  }
  .bad-text {
    color: var(--bad);
  }
  .warn-text {
    color: var(--warn);
  }
</style>
