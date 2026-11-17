<script lang="ts">
  // REQ: API-015, OPS-014 (T23.6, ADR-903 §4, §9) — Settings → Integrations & secrets: this node's
  // secrets store (its key's source and ID, locked or ephemeral and why), every stored secret with
  // the fields that use it and the nodes that hold it, and every credential field of this node's
  // configuration with where its value comes from. Operators see all of it; only admins set, replace
  // or delete, and no value is ever shown.
  import { ApiError, api, type S } from '../api';
  import { can } from '../session.svelte';
  import { dateTime } from '../format';
  import { poll } from '../poll';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import SecretField from './SecretField.svelte';

  let status = $state<S['SecretsStatus'] | null>(null);
  let error = $state<unknown>(null);
  const isAdmin = $derived(can('admin'));

  async function load() {
    try {
      status = await api.secrets();
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 15_000));

  // The secret being replaced (or added under a name) in the form below the table.
  let target = $state('');
  let rowError = $state<{ name: string; error: unknown } | null>(null);
  let rowBusy = $state('');

  async function remove(name: string, force = false) {
    rowError = null;
    rowBusy = name;
    try {
      await api.deleteSecret(name, force, status?.head.etag);
      await load();
    } catch (e) {
      rowError = { name, error: e };
    } finally {
      rowBusy = '';
    }
  }
  const forceable = (e: unknown) =>
    e instanceof ApiError && e.code === 'secret_in_use' && /can't be read now/.test(e.message);

  const stores: Record<string, [string, string]> = {
    ready: ['ready', 'ok'],
    starting: ['starting', ''],
    locked: ['locked', 'bad'],
    ephemeral: ['ephemeral', 'warn'],
  };
  const storeBadge = (state: string): [string, string] => stores[state] ?? [state, ''];
  // Where the key came from: the environment's value is not a path, so it reads as such.
  const keyFrom = (src: string | null | undefined) => (!src ? 'none' : src === 'the environment' ? 'set by environment' : src);
  const sourceLabel: Record<string, string> = { stored: 'stored', inline: 'set in the file', file: 'set by file' };
  const when = (iso: string | null | undefined) => (iso ? dateTime(Date.parse(iso) / 1000) : '');
  const usedText = (u: S['SecretUse']) => `${u.kind} ${u.name} · ${u.field}${u.node ? ` (on ${u.node})` : ''}`;
</script>

<div class="secrets" data-testid="secrets-panel">
  <ErrorNote {error} />
  {#if status}
    {#if status.stale}
      <p class="notice warn small" data-testid="secrets-stale">
        The primary couldn't be asked, so this list is this node's own copy.
      </p>
    {/if}

    <section class="card" data-testid="secrets-store">
      <h2>Secrets store<HelpButton id="stored-secrets" /></h2>
      <p>
        <span class="badge {storeBadge(status.store.state)[1]}" data-testid="secrets-state">{storeBadge(status.store.state)[0]}</span>
        on <strong>{status.store.node}</strong>
        {#if status.store.reason}<span class="small muted"> · {status.store.reason}</span>{/if}
      </p>
      <dl class="facts small">
        <dt>Key</dt>
        <dd data-testid="secrets-key-source">{keyFrom(status.store.keySource)}</dd>
        <dt>Key ID</dt>
        <dd class="mono">{status.store.keyId ?? '—'}</dd>
        {#if status.store.previousKeyId}
          <dt>Previous key</dt>
          <dd class="mono" data-testid="secrets-previous-key">{status.store.previousKeyId} (rows move to the current key at start)</dd>
        {/if}
      </dl>
      {#if status.store.state === 'locked'}
        <p class="notice bad small">
          Stored secrets can't be used on this node, so integrations that need one report “not configured”. DNS is unaffected.
          Put the node's key back (the environment variable, the key file, or <code>secrets.key</code> in the data directory).
        </p>
      {/if}
      {#if status.store.dataEphemeral}
        <p class="notice warn small">
          The data directory isn't kept across restarts, so stored secrets would be lost at the next one.
          Keep it on a volume, or keep the secrets in the configuration files.
        </p>
      {/if}
      <p class="small muted">
        The key itself is never shown. To rotate it, stop the node and run <code>telltale secrets rotate-key</code> (offline).
      </p>
    </section>

    <section class="card" data-testid="secrets-stored">
      <h2>Stored secrets</h2>
      {#if status.items.length === 0}
        <p class="empty">No stored secrets yet.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Name</th><th>Set</th><th>Used by</th><th>Held by</th><th></th></tr>
            </thead>
            <tbody>
              {#each status.items as s (s.name)}
                <tr data-testid="secret-row">
                  <td>
                    <strong class="mono">{s.name}</strong>
                    <div class="muted small">{s.kind}</div>
                  </td>
                  <td class="small">
                    {#if s.set}
                      {when(s.updated)}{s.updatedBy ? ` by ${s.updatedBy}` : ''}
                    {:else}
                      <span class="bad-text">not stored</span>
                    {/if}
                  </td>
                  <td class="small">
                    {#each s.usedBy as u (usedText(u))}
                      <div>{usedText(u)}</div>
                    {:else}
                      <span class="muted">nothing</span>
                    {/each}
                  </td>
                  <td class="small">
                    {#each s.nodes as n (n.node)}
                      <div>
                        {n.node}{#if n.unreadable}<span class="badge bad">can't read it</span>{:else if !n.applied}<span class="badge warn">not yet</span>{/if}
                      </div>
                    {:else}
                      <span class="muted">no node</span>
                    {/each}
                  </td>
                  <td class="actions">
                    {#if isAdmin && s.set}
                      <button class="link small" onclick={() => (target = s.name)}>Replace</button>
                      <button class="link small danger" disabled={rowBusy === s.name} onclick={() => remove(s.name)}>Delete</button>
                    {/if}
                  </td>
                </tr>
                {#if rowError?.name === s.name}
                  <tr>
                    <td colspan="5">
                      <ErrorNote error={rowError.error} />
                      {#if forceable(rowError.error)}
                        <button class="danger small" onclick={() => remove(s.name, true)}>Delete anyway</button>
                      {/if}
                    </td>
                  </tr>
                {/if}
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <section class="card" data-testid="secrets-form">
      <h2>{target ? `Replace ${target}` : 'Add a secret'}</h2>
      {#if isAdmin}
        <p class="small muted">
          A value goes in once and is kept encrypted with this node's key; it's never shown again. Entries name it with a
          <code>*_ref</code> field, such as <code>token_ref = "ntfy"</code>.
        </p>
        {#key target}
          <!-- The name stays editable: a stored name is replaced by the value typed under it. -->
          <SecretField label="Value" nameLabel="Secret name" testid="secret-form" canSet={isAdmin} defaultName={target}
            kind="text" startReplacing={target !== ''}
            onsaved={() => {
              target = '';
              void load();
            }}
            onremoved={() => void load()} />
        {/key}
      {:else}
        <p class="small muted" data-testid="secrets-read-only">Only an admin sets, replaces or deletes a stored secret. You can see where each one is used.</p>
      {/if}
    </section>

    <section class="card" data-testid="secrets-credentials">
      <h2>Credential fields on this node</h2>
      {#if status.credentials.length === 0}
        <p class="empty">No credential fields are set.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Entry</th><th>Field</th><th>Source</th><th>This node</th></tr></thead>
            <tbody>
              {#each status.credentials as c (`${c.kind}/${c.entry}/${c.field}`)}
                <tr data-testid="credential-row">
                  <td><strong>{c.entry}</strong> <span class="muted small">{c.kind}</span></td>
                  <td class="mono small">{c.field}</td>
                  <td class="small">
                    <span class="badge">{sourceLabel[c.source] ?? c.source}</span>
                    {#if c.at}<div class="mono small muted">{c.at}</div>{/if}
                  </td>
                  <td class="small">
                    {#if c.readable}
                      <span class="badge ok">readable</span>
                    {:else}
                      <span class="badge bad">not readable</span>
                      {#if c.reason}<div class="muted small">{c.reason}</div>{/if}
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {:else if !error}
    <p class="empty">Loading…</p>
  {/if}
</div>

<style>
  .secrets {
    display: grid;
    gap: 16px;
  }
  .facts {
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    gap: 4px 14px;
    margin: 8px 0;
  }
  .facts dt {
    color: var(--muted);
  }
  .facts dd {
    margin: 0;
    /* A key file's path or a key ID has no spaces; let it wrap at phone width. */
    overflow-wrap: anywhere;
  }
  .actions {
    text-align: right;
    white-space: nowrap;
  }
  .actions button + button {
    margin-left: 10px;
  }
  .bad-text {
    color: var(--bad);
  }
  .danger {
    color: var(--bad);
  }
</style>
