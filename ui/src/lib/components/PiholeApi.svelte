<script lang="ts">
  // REQ: API-005 (T24.10, ADR-961) — Settings → Pi-hole → Pi-hole compatible API, admins only: turn on
  // the part of Pi-hole's API that dashboards, phone apps and the Home Assistant Pi-hole integration
  // use (statistics, and blocking off for a while and on again). Off by default; the token is made
  // here, shown once, and kept only as a hash.
  import { api, type S } from '../api';
  import { ago, dateTime } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let status = $state<S['PiholeApiStatus'] | null>(null);
  let error = $state<unknown>(null);
  let busy = $state(false);
  let token = $state<string | null>(null);
  let copied = $state(false);
  let armed = $state<'' | 'rotate' | 'revoke'>('');
  let maxText = $state('');

  async function load() {
    try {
      status = await api.piholeApi();
      maxText = String(status.maxPauseMinutes);
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => void load());

  // The address Home Assistant and apps use: this page's own.
  const host = location.hostname;
  const port = location.port || (location.protocol === 'https:' ? '443' : '80');
  const origin = location.origin;

  async function run(f: () => Promise<void>) {
    busy = true;
    armed = '';
    try {
      await f();
      error = null;
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  // Turning it on makes the first token when there is none: the token is shown once, below.
  const toggle = () =>
    run(async () => {
      if (!status) return;
      if (status.enabled) {
        status = await api.setPiholeApi({ enabled: false });
        return;
      }
      if (!status.tokenSet) {
        const made = await api.newPiholeToken();
        token = made.token;
        copied = false;
      }
      status = await api.setPiholeApi({ enabled: true });
    });

  const rotate = () =>
    run(async () => {
      const made = await api.newPiholeToken();
      token = made.token;
      copied = false;
      status = made.status;
    });

  const revoke = () =>
    run(async () => {
      status = await api.revokePiholeToken();
      token = null;
    });

  const saveMax = (e: SubmitEvent) => {
    e.preventDefault();
    return run(async () => {
      status = await api.setPiholeApi({ maxPauseMinutes: Number(maxText) });
      maxText = String(status.maxPauseMinutes);
    });
  };

  async function copy() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      copied = true;
    } catch {
      copied = false;
    }
  }
</script>

<section class="card" data-testid="pihole-api">
  <h2>Pi-hole compatible API<HelpButton id="pihole-api" /></h2>
  <p class="muted small">
    Lets tools that talk to Pi-hole (the Home Assistant Pi-hole integration, phone apps, dashboards) read TelltaleDNS's
    statistics and turn blocking off for a while and back on. Nothing else: lists, rules and settings are not reachable through
    it. It is off until you turn it on, and it needs the token made here.
  </p>
  <ErrorNote {error} />
  {#if status}
    <label class="switch">
      <input type="checkbox" role="switch" checked={status.enabled} disabled={busy} onchange={toggle} data-testid="pihole-api-toggle" />
      {status.enabled ? 'On' : 'Off'}
    </label>
    {#if token}
      <div class="notice ok" data-testid="pihole-api-token">
        <p><strong>The token</strong>: copy it now. It is shown only this once, and only its hash is kept.</p>
        <p class="mono small token" data-testid="pihole-api-token-text">{token}</p>
        <button type="button" class="small" onclick={copy}>{copied ? 'Copied' : 'Copy the token'}</button>
      </div>
    {/if}
    <p class="small" data-testid="pihole-api-state">
      {#if status.tokenSet}
        Token made {status.tokenCreatedUnixSeconds ? dateTime(status.tokenCreatedUnixSeconds) : ''}; last used
        {status.lastUsedUnixSeconds ? ago(status.lastUsedUnixSeconds) : 'never'}.
      {:else}
        No token yet: turning it on makes one.
      {/if}
    </p>
    {#if status.enabled}
      <div class="how small" data-testid="pihole-api-how">
        <p>
          In Home Assistant's Pi-hole integration: host <code>{host}</code>, port <code>{port}</code>, location <code>admin</code>,
          and the token as the API key (or password). Phone apps: this server's address, <code>{origin}</code>, with the token as
          the web password or API token.
        </p>
      </div>
    {/if}
    <div class="row">
      <button class="small" disabled={busy} onclick={() => (armed === 'rotate' ? rotate() : (armed = 'rotate'))} data-testid="pihole-api-rotate">
        {armed === 'rotate' ? 'Really? The old token stops working' : status.tokenSet ? 'Make a new token' : 'Make a token'}
      </button>
      {#if status.tokenSet}
        <button class="small danger" disabled={busy} onclick={() => (armed === 'revoke' ? revoke() : (armed = 'revoke'))} data-testid="pihole-api-revoke">
          {armed === 'revoke' ? 'Really? This turns it off' : 'Remove the token'}
        </button>
      {/if}
    </div>
    <form class="row" onsubmit={saveMax}>
      <label class="small">
        Longest pause (minutes)
        <input bind:value={maxText} inputmode="numeric" size="6" data-testid="pihole-api-max" />
      </label>
      <button class="small" disabled={busy || maxText === String(status.maxPauseMinutes)} data-testid="pihole-api-max-save">Save</button>
      <span class="muted small">Pi-hole's "disable" with no timer pauses for this long, and a longer timer is cut to it. 1 to 1,440; default 60.</span>
    </form>
  {/if}
</section>

<style>
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 12px;
    align-items: end;
    margin-top: 8px;
  }
  .token {
    word-break: break-all;
  }
  .how {
    margin: 8px 0;
  }
</style>
