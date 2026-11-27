<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: DNS-904 (T40.3), FLT-013 — how the built-in resolver walks to the answer: where it began,
  // then each query to each authoritative server with its outcome and time. The trace is only
  // built when this button asks for it.
  import { api, type S } from '../api';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let { name, qtype }: { name: string; qtype: string } = $props();

  let trace = $state<S['RecursorTrace'] | null>(null);
  let error = $state<unknown>(null);
  let busy = $state(false);

  async function run() {
    busy = true;
    try {
      trace = await api.recursorTrace({ name, qtype });
      error = null;
    } catch (e) {
      trace = null;
      error = e;
    } finally {
      busy = false;
    }
  }

  const ms = (us: number) => `${(us / 1000).toFixed(1)} ms`;
</script>

<div class="trace" data-testid="recursor-trace">
  <div class="row">
    <button type="button" onclick={run} disabled={busy} data-testid="trace-run">Trace the lookup</button>
    <HelpButton id="recursor-trace" />
    <span class="muted small">Resolves the name again with the built-in resolver and shows each server it asked.</span>
  </div>
  <ErrorNote {error} />
  {#if trace}
    <p data-testid="trace-summary">
      <strong>{trace.rcode ?? 'Failed'}</strong>
      via {trace.upstream}{trace.error ? `: ${trace.error}` : `, ${trace.answers} ${trace.answers === 1 ? 'record' : 'records'}`}
      <span class="muted small">({ms(trace.totalMicros)})</span>
    </p>
    <table>
      <thead>
        <tr><th>#</th><th>Server</th><th>Asked</th><th>Of zone</th><th>Result</th><th>Time</th></tr>
      </thead>
      <tbody>
        {#each trace.steps as s, i (i)}
          <tr data-testid="trace-step">
            <td>{i + 1}</td>
            {#if s.kind === 'start'}
              <td colspan="2">Starts at {s.zone} <span class="muted small">from the {s.outcome} ({s.detail})</span></td>
              <td class="mono">{s.zone}</td>
              <td></td>
              <td></td>
            {:else}
              <td class="mono">{s.server} <span class="muted small">{s.transport}</span></td>
              <td class="mono">{s.qname} {s.qtype}</td>
              <td class="mono">{s.zone}</td>
              <td data-testid="trace-outcome">{s.outcome}{s.detail ? ` → ${s.detail}` : ''}</td>
              <td>{ms(s.micros)}</td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .trace {
    display: grid;
    gap: 8px;
    margin-top: 8px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th,
  td {
    text-align: left;
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
    word-break: break-all;
  }
  th {
    color: var(--muted);
    font-weight: 500;
  }
</style>
