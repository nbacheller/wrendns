<script lang="ts">
  // REQ: OBS-016, OBS-020, OBS-019, OBS-013, OBS-003, OBS-005 (T27.5, ADR-1007) — a tuning section's
  // form, shown where its data is. The disclosure loads the form when it opens, so a page that only
  // reads the data doesn't fetch the settings.
  import ConfigEditor from './ConfigEditor.svelte';
  import HelpButton from './HelpButton.svelte';
  import { TUNING, type TuningKey } from '../tuning';
  import { guarded, watchGuarded } from '../guarded.svelte';

  let { which }: { which: TuningKey } = $props();
  const spec = $derived(TUNING[which]);
  let open = $state(false);
  // REQ: OBS-007, API-905 (T40.13) - a dnstap change confirmed through the guarded review is staged for
  // the next start: the card says "restart needed" while the node lists it as pending a restart.
  const restartNeeded = $derived(which === 'dnstap' && !!guarded.node?.pendingRestart.includes(spec.guardedId ?? ''));
  $effect(() => (which === 'dnstap' && open ? watchGuarded(3_000) : undefined));
</script>

<details class="tuning" data-testid={`tuning-${which}`} ontoggle={(e) => (open = e.currentTarget.open)}>
  <summary>
    {spec.summary}
    {#if which === 'slo'}<HelpButton id="slo" />
    {:else if which === 'probe'}<HelpButton id="probes" />
    {:else if which === 'upstream_check'}<HelpButton id="upstream-checks" />
    {:else if which === 'anomaly'}<HelpButton id="anomaly-settings" />
    {:else if which === 'qlog'}<HelpButton id="qlog-settings" />
    {:else if which === 'dnstap'}<HelpButton id="dnstap-settings" />
    {:else}<HelpButton id="metrics-settings" />{/if}
  </summary>
  {#if open}
    <ConfigEditor
      kind={spec.kind}
      path={spec.path}
      singleton
      title={spec.title}
      noun={spec.noun}
      fields={spec.fields}
      summary={spec.describe}
      note={spec.note ? () => spec.note! : undefined}
      role={spec.role}
      guardedId={spec.guardedId}
      validate={spec.validate}
    />
    {#if which === 'dnstap' && restartNeeded}
      <p class="notice small" data-testid="dnstap-restart-needed">Restart needed: a dnstap change confirmed here is read when {guarded.node?.node ?? 'the node'} starts again.</p>
    {/if}
  {/if}
</details>

<style>
  .tuning {
    margin: 8px 0 12px;
  }
  .tuning > summary {
    cursor: pointer;
    color: var(--muted);
  }
</style>
