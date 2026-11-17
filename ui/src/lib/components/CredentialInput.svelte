<script lang="ts">
  // REQ: API-016 (T23.8, ADR-903 §9) — a credential entered through the UI. It is write-only: the
  // value goes to the encrypted store once and is never shown or filled in again (no show toggle,
  // no pre-fill). The form keeps only the stored secret's name. Until T23.6's SecretField lands,
  // this is the same contract in a local component (Open in spec/10, T23.8).
  import { api, ApiError } from '../api';

  let {
    label,
    secretName,
    stored,
    fileSet = null,
    readable = null,
    issue = null,
    disabled = false,
    onsaved,
  }: {
    label: string;
    /** The name the value is stored under (`unifi.lab.api_key`). */
    secretName: string;
    /** The name the entry refers to now, if any (`api_key_ref`). */
    stored: string | undefined;
    /** The configuration file's path, when a file sets it (read-only here). */
    fileSet?: string | null;
    readable?: boolean | null;
    issue?: string | null;
    disabled?: boolean;
    onsaved: (name: string) => void;
  } = $props();

  let value = $state('');
  let busy = $state(false);
  let error = $state('');
  let saved = $state(false);

  async function save() {
    const v = value;
    if (!v.trim()) {
      error = 'Enter the value first.';
      return;
    }
    busy = true;
    error = '';
    try {
      await api.putSecret(secretName, v.trim());
      value = '';
      saved = true;
      onsaved(secretName);
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'The value could not be stored.';
    } finally {
      busy = false;
    }
  }
</script>

<div class="cred" data-testid="credential-input">
  <span class="cred-label">{label}</span>
  {#if fileSet}
    <p class="small muted" data-testid="credential-file">Set by the configuration file (<span class="mono">{fileSet}</span>). It is read on each node and can't be changed here.</p>
  {:else}
    {#if stored}
      <p class="small">
        Stored as <span class="mono" data-testid="credential-name">{stored}</span>
        {#if readable === false}<span class="badge bad">can't be read here</span>{:else if readable === true}<span class="badge ok">readable</span>{/if}
      </p>
      {#if issue}<p class="small warn-text" role="status">{issue}</p>{/if}
    {:else}
      <p class="small muted">Not set.</p>
    {/if}
    <div class="cred-row">
      <input
        type="password"
        aria-label={`${label}: new value`}
        autocomplete="new-password"
        autocapitalize="off"
        spellcheck="false"
        bind:value
        disabled={disabled || busy}
        placeholder={stored ? 'Enter a new value to replace it' : 'Enter the value'}
      />
      <button type="button" class="btn" onclick={save} disabled={disabled || busy || !value.trim()}>
        {stored ? 'Replace the value' : 'Store the value'}
      </button>
    </div>
    {#if saved && !error}<p class="small muted" role="status">Stored. The form doesn't show the value.</p>{/if}
    {#if error}<p class="small bad-text" role="alert">{error}</p>{/if}
  {/if}
</div>

<style>
  .cred {
    display: grid;
    gap: 0.25rem;
  }
  .cred-label {
    font-weight: 600;
  }
  .cred-row {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .cred-row input {
    flex: 1 1 14rem;
    min-width: 0;
  }
  .warn-text {
    color: var(--warn, #8a5a00);
  }
  .bad-text {
    color: var(--bad, #b00020);
  }
</style>
