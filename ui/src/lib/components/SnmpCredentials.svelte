<script lang="ts">
  // REQ: DSC-004, DSC-007 (T25.6, ADR-908, ADR-1001) — the SNMP credentials the agents use. A credential
  // names FILES under this node's secret directories (`[node] secret_file_dirs`): the community or
  // password is never typed here and never shown (T25.8 adds stored secrets). Inline values don't
  // exist: the form has no field for one. Admins edit (the page's Check and Apply save the list);
  // everyone reads. A v2c community crosses the LAN in clear text, so the form says so, and the
  // protocols the client refuses (MD5, SHA-224, DES, AES-192, AES-256, no authentication) are not
  // offered.
  import { type AgentDraft, type CredDraft, blankCred } from '../snmp';
  import HelpButton from './HelpButton.svelte';

  let {
    credentials = $bindable(),
    agents,
    writable,
    fileSet,
  }: {
    credentials: CredDraft[];
    agents: AgentDraft[];
    writable: boolean;
    /** The configuration files set the list: it is read-only here. */
    fileSet: boolean;
  } = $props();

  const canEdit = $derived(writable && !fileSet);
  let draft = $state<CredDraft | null>(null);
  let index = $state(-1);
  let formError = $state('');
  const usedBy = (name: string) => agents.filter((a) => a.credential === name).map((a) => a.name);

  function add() {
    draft = blankCred();
    index = -1;
    formError = '';
  }
  function edit(i: number) {
    draft = { ...credentials[i] };
    index = i;
    formError = '';
  }
  function cancel() {
    draft = null;
    formError = '';
  }
  function remove(i: number) {
    credentials = credentials.filter((_, j) => j !== i);
  }
  function keep() {
    if (!draft) return;
    const d: CredDraft = { ...draft, name: draft.name.trim() };
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(d.name) || /^\d+\.\d+\.\d+\.\d+$/.test(d.name)) {
      return void (formError = 'A name is letters, digits, "." "_" or "-", up to 64, and is not an address.');
    }
    if (credentials.some((c, j) => j !== index && c.name === d.name)) return void (formError = `There is already a credential named ${d.name}.`);
    if (d.version === 'v2c' && !d.community_file.trim()) return void (formError = 'Name the file that holds the community.');
    if (d.version === 'v3') {
      if (!d.user.trim()) return void (formError = 'Name the v3 user.');
      if (!d.auth_password_file.trim()) return void (formError = 'Name the file that holds the authentication password.');
    }
    credentials = index < 0 ? [...credentials, d] : credentials.map((c, j) => (j === index ? d : c));
    draft = null;
    formError = '';
  }
  const level = (c: CredDraft) => (c.version === 'v2c' ? 'v2c' : c.priv_protocol ? 'v3 authPriv' : 'v3 authNoPriv');
</script>

<div data-testid="inventory-credentials">
  <h3>SNMP credentials<HelpButton id="snmp-setup" /></h3>
  <p class="muted small">
    Each credential names the files that hold its secrets, under this node's secret directories. A secret is never typed or shown here.
  </p>
  {#if fileSet}<p class="muted small" data-testid="set-by-file">(the credentials are set by file)</p>{/if}
  {#if credentials.length === 0}
    <p class="muted small" data-testid="credentials-empty">No SNMP credential is configured.</p>
  {:else}
    <table>
      <thead><tr><th>Credential</th><th>Use</th><th>Level</th><th>Used by</th>{#if canEdit}<th></th>{/if}</tr></thead>
      <tbody>
        {#each credentials as c, i (c.name)}
          <tr data-testid="credential-{c.name}">
            <td>{c.name}</td>
            <td>{c.role === 'host' ? 'Hosts (identity reads)' : 'Infrastructure (agents)'}</td>
            <td>
              {level(c)}
              {#if c.version === 'v2c'}<span class="badge warn" title="The community crosses the LAN in clear text">clear text</span>{/if}
            </td>
            <td class="small">{usedBy(c.name).join(', ') || '–'}</td>
            {#if canEdit}
              <td class="actions">
                <button class="link" onclick={() => edit(i)} aria-label={`Edit credential ${c.name}`}>Edit</button>
                <button class="link" onclick={() => remove(i)} aria-label={`Delete credential ${c.name}`}>Delete</button>
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  {#if canEdit && !draft}
    <div class="row actions"><button onclick={add} data-testid="credential-add">Add a credential</button></div>
  {/if}

  {#if draft}
    <div class="card" data-testid="credential-form">
      <h4>{index < 0 ? 'Add a credential' : `Edit ${credentials[index]?.name}`}</h4>
      <label>
        Name
        <input type="text" bind:value={draft.name} aria-label="Credential name" placeholder="gateway-v3" />
      </label>
      <label>
        Use
        <select bind:value={draft.role} aria-label="Credential use">
          <option value="infrastructure">Infrastructure: agents (the gateway and switches)</option>
          <option value="host">Hosts: identity reads of devices in a subnet</option>
        </select>
      </label>
      <label>
        SNMP version
        <select bind:value={draft.version} aria-label="SNMP version">
          <option value="v3">v3: authentication, and privacy with AES</option>
          <option value="v2c">v2c: a community string</option>
        </select>
      </label>
      {#if draft.version === 'v2c'}
        <p class="notice warn small" data-testid="v2c-warning">A v2c community crosses the LAN in clear text, and every device on the path can read it. Use v3 where the device has it.</p>
        <label>
          File that holds the community
          <input type="text" bind:value={draft.community_file} aria-label="Community file" placeholder="/run/secrets/snmp-community" />
        </label>
      {:else}
        <label>
          User
          <input type="text" bind:value={draft.user} aria-label="SNMP user" />
        </label>
        <label>
          Authentication
          <select bind:value={draft.auth_protocol} aria-label="Authentication protocol">
            <option value="sha">SHA (HMAC-SHA-96)</option>
            <option value="sha-256">SHA-256</option>
            <option value="sha-384">SHA-384</option>
            <option value="sha-512">SHA-512</option>
          </select>
        </label>
        <label>
          File that holds the authentication password (8 characters or more)
          <input type="text" bind:value={draft.auth_password_file} aria-label="Authentication password file" placeholder="/run/secrets/snmp-auth" />
        </label>
        <label>
          Privacy
          <select bind:value={draft.priv_protocol} aria-label="Privacy protocol">
            <option value="aes-128">AES-128 (authPriv)</option>
            <option value="">None (authNoPriv)</option>
          </select>
        </label>
        {#if draft.priv_protocol}
          <label>
            File that holds the privacy password (blank: the authentication password is used for both)
            <input type="text" bind:value={draft.priv_password_file} aria-label="Privacy password file" />
          </label>
        {/if}
        <p class="muted small">MD5, SHA-224, DES, AES-192, AES-256 and no authentication are refused: they are broken, or the client doesn't carry them.</p>
      {/if}
      {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
      <div class="row actions">
        <button class="primary" onclick={keep} data-testid="credential-keep">{index < 0 ? 'Add to the list' : 'Keep the change'}</button>
        <button class="link" onclick={cancel}>Cancel</button>
      </div>
      <p class="muted small">Nothing is saved until you press Check and Apply below.</p>
    </div>
  {/if}
</div>
