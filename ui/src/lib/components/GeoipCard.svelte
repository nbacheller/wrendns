<script lang="ts">
  // REQ: OBS-902, NFR-001 (T26.4, ADR-959) - the GeoIP database the world view places answers with,
  // as a card in Settings -> Query handling. Everyone who can see the map sees its status; only an
  // admin turns it on, sets the source, fetches now or deletes it. Nothing is downloaded until the
  // toggle is on, and the database is never bundled: each node that serves the console fetches its
  // own copy, once a day at most, in the background.
  import { api, ApiError, type S } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  type Status = S['GeoipStatus'];
  type Geo = { enabled?: boolean; source_url?: string | null; sha256?: string | null; home_country?: string | null };

  let status = $state<Status | null>(null);
  let map = $state<Record<string, unknown> | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');
  let busy = $state(false);
  const isAdmin = $derived(can('admin'));

  const geoOf = (m: Record<string, unknown> | null): Geo => ((m?.geoip as Geo | undefined) ?? {});
  const current = $derived(geoOf(map));

  async function load() {
    try {
      status = await api.geoip();
      error = null;
    } catch (e) {
      // A resolver pod keeps no database: the card says so instead of showing an error.
      if (e instanceof ApiError && e.status === 404) status = null;
      else error = e;
    }
    try {
      map = ((await api.geoipSettings()).definition as Record<string, unknown> | null) ?? {};
    } catch {
      // Shown through the status call's error, if it fails too.
    }
  }
  // Every 10 s, every 3 s while a download runs or is about to.
  const downloading = $derived(status?.state === 'downloading');
  const waiting = $derived(downloading || (status?.enabled === true && status.state === 'missing'));
  $effect(() => poll(load, waiting ? 3_000 : 10_000));

  // ---- the form (admin)
  let enabled = $state(false);
  let url = $state('');
  let sha = $state('');
  let home = $state('');
  let dirty = $state(false);
  let seeded = $state(false);
  // Seed the form from what is in effect, once, and again after a save or when nothing is being edited.
  $effect(() => {
    if (map && (!seeded || !dirty)) {
      enabled = current.enabled === true;
      url = current.source_url ?? '';
      sha = current.sha256 ?? '';
      home = current.home_country ?? '';
      seeded = true;
    }
  });
  const touch = () => (dirty = true);

  async function save() {
    if (!map) return;
    busy = true;
    notice = '';
    try {
      const geoip: Geo = { enabled };
      if (url.trim()) geoip.source_url = url.trim();
      if (sha.trim()) geoip.sha256 = sha.trim().toLowerCase();
      if (home.trim()) geoip.home_country = home.trim().toUpperCase();
      await api.putGeoipSettings({ ...map, geoip });
      dirty = false;
      notice = enabled ? 'Saved. This node starts fetching the database in the background.' : 'Saved. Nothing is fetched while this is off.';
      error = null;
      await load();
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  async function updateNow() {
    busy = true;
    notice = '';
    try {
      status = await api.geoipUpdate();
      error = null;
      notice = 'Fetching now. The state below follows it.';
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  let confirmDelete = $state(false);
  async function remove() {
    busy = true;
    notice = '';
    try {
      status = await api.geoipDelete();
      confirmDelete = false;
      error = null;
      notice = 'Deleted. The world view says the database is missing until an admin presses Update now.';
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  const STATE_WORDS: Record<string, string> = {
    off: 'Off: nothing is fetched',
    missing: 'On, with no database on this node yet',
    downloading: 'Downloading',
    ready: 'Ready',
    failed: 'The last fetch failed',
  };
  // What each error code means, in words (never a response body).
  const ERROR_WORDS: Record<string, string> = {
    not_found: "the source doesn't have the file (404)",
    http_error: 'the source answered with an error',
    redirect_refused: 'the source redirected to plain HTTP, which is refused',
    too_many_redirects: 'the source redirected too many times',
    too_large: 'the file is larger than the 32 MiB (compressed) or 96 MiB (uncompressed) limit',
    tls_failed: "the source's certificate or TLS handshake was not accepted",
    dns_failed: "the source's host name did not resolve",
    timeout: 'the download took longer than 2 minutes',
    corrupt_download: 'the file is truncated or its checksum is wrong',
    malformed_row: 'a row of the file is not start,end,country',
    overlapping_ranges: 'ranges in the file overlap',
    too_few_rows: 'the file has too few rows to be the database',
    too_few_countries: 'the file has too few countries',
    missing_family: 'the file lacks IPv4 or IPv6 ranges',
    size_changed: 'the file differs from the database it replaces by more than 30%',
    digest_mismatch: "the file's SHA-256 is not the pinned one",
    write_failed: "the database couldn't be written to the data directory",
    not_https: 'the source is not an HTTPS URL',
    address_refused: 'the source is a link-local or cloud-metadata address',
    download_failed: 'the download failed',
  };
  const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '');
  const size = (b: number) => (b >= 1048576 ? `${(b / 1048576).toFixed(1)} MiB` : `${Math.max(1, Math.round(b / 1024))} KiB`);
</script>

<section class="card geoip" data-testid="geoip-card" aria-label="GeoIP database">
  <div class="card-head">
    <h2>GeoIP database<HelpButton id="geoip" /></h2>
  </div>
  <p class="small">
    The world view places answers with a country database. It is never bundled with TelltaleDNS: it is downloaded (about 5 MB) only after an
    admin turns this on, by each node that serves the console, in the background and at most once a day.
  </p>
  <ErrorNote {error} />
  {#if notice}<p class="notice small" role="status" data-testid="geoip-notice">{notice}</p>{/if}

  {#if status}
    <dl class="sys" data-testid="geoip-status" data-state={status.state}>
      <dt>State</dt>
      <dd data-testid="geoip-state">{STATE_WORDS[status.state] ?? status.state}</dd>
      {#if status.sourceMonth}<dt>Source month</dt><dd data-testid="geoip-month">{status.sourceMonth}{status.old ? ' (old: more than 90 days)' : ''}</dd>{/if}
      {#if status.updatedAt}<dt>Built here</dt><dd data-testid="geoip-updated">{when(status.updatedAt)}</dd>{/if}
      {#if status.sizeBytes > 0}<dt>On disk</dt><dd data-testid="geoip-size">{size(status.sizeBytes)}, {status.rows.toLocaleString()} rows</dd>{/if}
      {#if status.nextCheckAt && status.enabled}<dt>Next check</dt><dd data-testid="geoip-next">{when(status.nextCheckAt)}</dd>{/if}
      {#if status.lastError}
        <dt>Last error</dt>
        <dd class="warn-text" data-testid="geoip-error"><code>{status.lastError}</code>: {ERROR_WORDS[status.lastError] ?? 'not accepted'}. The previous database, if there is one, is kept.</dd>
      {/if}
    </dl>
  {:else if !error}
    <p class="muted small" data-testid="geoip-none">This node keeps no GeoIP database (a resolver node never fetches one).</p>
  {/if}

  {#if status && isAdmin && seeded}
    <form class="geoform" onsubmit={(e) => { e.preventDefault(); void save(); }} aria-label="GeoIP settings">
      <label class="check">
        <input type="checkbox" bind:checked={enabled} onchange={touch} data-testid="geoip-toggle" />
        Download the country database
      </label>
      <label>
        Source URL <span class="muted small">(optional; HTTPS only)</span>
        <input type="text" inputmode="url" bind:value={url} oninput={touch} placeholder="https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz" data-testid="geoip-url" autocomplete="off" />
      </label>
      <label>
        Pinned SHA-256 <span class="muted small">(optional)</span>
        <input type="text" bind:value={sha} oninput={touch} placeholder="64 hexadecimal digits" data-testid="geoip-sha" autocomplete="off" spellcheck="false" />
      </label>
      <p class="muted small">
        The publisher's monthly file changes digest every month, so a pin is only useful with a fixed mirror URL whose content you control; with the
        default source leave it empty. Without a URL, this month's file is fetched, or last month's if it isn't published yet. The checks guard
        against a truncated or tampered file, they don't prove who made it.
      </p>
      <label>
        Home country <span class="muted small">(optional: where arcs start; two letters)</span>
        <input type="text" bind:value={home} oninput={touch} maxlength="2" placeholder="NL" data-testid="geoip-home" autocomplete="off" />
      </label>
      <div class="row">
        <button type="submit" class="primary" disabled={busy || !dirty} data-testid="geoip-save">Save</button>
        <button type="button" disabled={busy || !status.enabled || status.state === 'downloading'} onclick={updateNow} data-testid="geoip-update">Update now</button>
        {#if !confirmDelete}
          <button type="button" disabled={busy || status.sizeBytes === 0 || status.state === 'downloading'} onclick={() => (confirmDelete = true)} data-testid="geoip-delete">Delete database</button>
        {:else}
          <span class="row" role="group" aria-label="Confirm deleting the database">
            <span class="small">Delete the database on this node? The world view stops placing answers until you fetch it again.</span>
            <button type="button" class="danger" disabled={busy} onclick={remove} data-testid="geoip-delete-confirm">Delete it</button>
            <button type="button" onclick={() => (confirmDelete = false)} data-testid="geoip-delete-cancel">Keep it</button>
          </span>
        {/if}
      </div>
    </form>
  {:else if status && !isAdmin}
    <p class="small" data-testid="geoip-readonly">
      {current.enabled ? 'On' : 'Off'}{current.source_url ? `, source ${current.source_url}` : ''}{current.home_country ? `, home country ${current.home_country}` : ''}.
      Only an admin changes this, fetches the database or deletes it.
    </p>
  {/if}
  <p class="small muted" data-testid="geoip-attribution">
    IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP.com</a>, IP to Country Lite, under
    <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>.
  </p>
</section>

<style>
  .geoip {
    display: grid;
    gap: 10px;
    align-content: start;
  }
  .geoform {
    display: grid;
    gap: 10px;
  }
  .geoform label {
    display: grid;
    gap: 4px;
  }
  .geoform label.check {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .geoform input[type='text'] {
    max-width: 38rem;
  }
  .sys {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 16px;
    margin: 0;
  }
  .sys dt {
    color: var(--muted);
  }
  .sys dd {
    margin: 0;
    word-break: break-word;
  }
  .warn-text {
    color: var(--warn-strong);
  }
</style>
