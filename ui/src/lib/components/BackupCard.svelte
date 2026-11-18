<script lang="ts">
  // REQ: API-007 (T23.9, ADR-903 §8) — Settings → System → Backup. A backup leaves the stored
  // secrets out unless a passphrase is given; with one they are encrypted into the file. A backup
  // with a passphrase needs a sign-in from the last 10 minutes, so a 403 `reauth_required` opens a
  // password prompt and the backup is made again. Nothing typed here is kept: the fields are
  // cleared once the request is sent.
  import { api, ApiError, type BackupResult } from '../api';
  import { session, signedIn } from '../session.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  const MIN = 12;
  let withSecrets = $state(false);
  let includeQlog = $state(false);
  let passphrase = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let error = $state<unknown>(null);
  let result = $state<BackupResult | null>(null);
  // The recent-sign-in prompt: the request waits here with its passphrase until the password is given.
  let reauth = $state(false);
  let password = $state('');
  let totp = $state('');
  let needTotp = $state(false);
  let pending: { includeQlog: boolean; passphrase?: string } | null = null;

  const tooShort = $derived(withSecrets && passphrase.length > 0 && [...passphrase].length < MIN);
  const mismatch = $derived(withSecrets && confirm.length > 0 && confirm !== passphrase);
  const ready = $derived(!withSecrets || ([...passphrase].length >= MIN && confirm === passphrase));

  /** Hands a blob to the browser as a download. */
  function save(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  async function send(body: { includeQlog: boolean; passphrase?: string }) {
    busy = true;
    error = null;
    result = null;
    try {
      const r = await api.backup(body);
      save(r.blob, r.name);
      result = r;
      pending = null;
      reauth = false;
      passphrase = '';
      confirm = '';
      password = '';
      totp = '';
      needTotp = false;
    } catch (e) {
      if (e instanceof ApiError && e.code === 'reauth_required' && body.passphrase) {
        // Keep the request (it holds the passphrase) in memory only until the password is given.
        pending = body;
        reauth = true;
        error = null;
      } else {
        // A terminal outcome other than the wait for a password: nothing typed stays (ADR-966 §8).
        pending = null;
        reauth = false;
        passphrase = '';
        confirm = '';
        error = e;
      }
    } finally {
      busy = false;
    }
  }

  function make() {
    void send({ includeQlog, passphrase: withSecrets ? passphrase : undefined });
  }

  /** Signs in again (a fresh session), then makes the backup that was waiting. */
  async function signInAgain() {
    const user = session.user?.username;
    if (!user || !pending) return;
    busy = true;
    error = null;
    try {
      const r = await api.login({ username: user, password, totp: totp || undefined });
      signedIn(r);
      password = '';
      totp = '';
      const body = pending;
      busy = false;
      await send(body);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'totp_required') {
        needTotp = true;
      } else {
        error = e;
      }
      busy = false;
    }
  }

  function cancelReauth() {
    pending = null;
    reauth = false;
    passphrase = '';
    confirm = '';
    password = '';
    totp = '';
    needTotp = false;
  }

  const plural = (n: number) => `${n} stored secret${n === 1 ? '' : 's'}`;
</script>

<section class="card" data-testid="backup-card">
  <h2>Backup<HelpButton id="backup" /></h2>
  <p>
    One file with your settings, users and API tokens, the devices and names you added here, the audit log, and
    statistics history. Restore it on a new machine with <code>telltale backup restore FILE</code>.
  </p>

  <label class="check">
    <input type="checkbox" bind:checked={withSecrets} data-testid="backup-with-secrets" />
    Include the stored secrets, encrypted with a passphrase
  </label>
  {#if withSecrets}
    <div class="fields" data-testid="backup-passphrase-fields">
      <label class="small">Passphrase (at least {MIN} characters)
        <input type="password" autocomplete="new-password" bind:value={passphrase} aria-label="Backup passphrase" />
      </label>
      <label class="small">Repeat the passphrase
        <input type="password" autocomplete="new-password" bind:value={confirm} aria-label="Repeat the backup passphrase" />
      </label>
      {#if tooShort}<div class="notice warn small" data-testid="backup-short">Use at least {MIN} characters.</div>{/if}
      {#if mismatch}<div class="notice warn small" data-testid="backup-mismatch">The two passphrases differ.</div>{/if}
      <p class="muted small">
        Keep the passphrase somewhere other than the backup: without it the secrets can't be restored (everything else
        can). It is never stored or sent anywhere but to this node, once.
      </p>
    </div>
  {/if}
  <label class="check">
    <input type="checkbox" bind:checked={includeQlog} data-testid="backup-qlog" />
    Include the query history (can be large; over 256 MiB, run <code>telltale backup create --include-qlog</code> on the server)
  </label>

  {#if reauth}
    <div class="notice warn" role="alert" data-testid="backup-reauth">
      <strong>Confirm it's you.</strong> A backup with secrets needs a sign-in from the last 10 minutes.
      <div class="fields">
        <label class="small">Password for {session.user?.username}
          <input type="password" autocomplete="current-password" bind:value={password} aria-label="Your password" />
        </label>
        {#if needTotp}
          <label class="small">Authenticator code
            <input bind:value={totp} inputmode="numeric" autocomplete="one-time-code" aria-label="Authenticator code" />
          </label>
        {/if}
      </div>
      <div class="row">
        <button class="primary" disabled={busy || !password} onclick={signInAgain} data-testid="backup-reauth-go">
          {busy ? 'Working…' : 'Sign in again and make the backup'}
        </button>
        <button disabled={busy} onclick={cancelReauth}>Cancel</button>
      </div>
      <div class="muted small">
        Signed in with a single sign-on provider? Sign out, sign in again, and retry. API tokens can't do this:
        run <code>telltale backup create --secrets-passphrase-file FILE</code> on the node.
      </div>
    </div>
  {:else}
    <p>
      <button class="primary" disabled={busy || !ready} onclick={make} data-testid="backup-make">
        {busy ? 'Working…' : withSecrets ? 'Download a backup with secrets' : 'Download a backup'}
      </button>
    </p>
  {/if}
  <ErrorNote {error} />

  {#if result}
    <div class="notice ok" role="status" data-testid="backup-result">
      <strong>{result.name}</strong> was downloaded.
      {#if result.secrets === 'included'}
        <div data-testid="backup-secrets-included">
          {plural(result.count)} {result.count === 1 ? 'is' : 'are'} in it, encrypted with your passphrase.
        </div>
      {:else if result.count > 0}
        <div data-testid="backup-secrets-omitted">
          {plural(result.count)} {result.count === 1 ? 'was' : 'were'} left out. Tick “Include the stored secrets” to
          carry {result.count === 1 ? 'it' : 'them'}, or enter {result.count === 1 ? 'it' : 'them'} again after a restore.
        </div>
      {/if}
      {#each result.warnings as w (w)}
        <div class="small" data-testid="backup-warning">{w}</div>
      {/each}
    </div>
  {/if}
  <p class="muted small">
    It holds password hashes, so keep it private. Making one is recorded in the audit log, and with secrets it raises
    the <code>secrets_exported</code> alert.
  </p>
</section>

<style>
  .check {
    display: flex;
    gap: 8px;
    align-items: flex-start;
    margin: 6px 0;
  }
  .fields {
    display: grid;
    gap: 8px;
    max-width: 420px;
    margin: 8px 0;
  }
  .row {
    display: flex;
    gap: 8px;
    margin-top: 8px;
    flex-wrap: wrap;
  }
</style>
