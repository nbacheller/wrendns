<script lang="ts">
  // REQ: OBS-016, OBS-020, OBS-019, OBS-013, OBS-003, OBS-005 (T27.5, ADR-1007) — a tuning section's
  // form, shown where its data is. The disclosure loads the form when it opens, so a page that only
  // reads the data doesn't fetch the settings.
  import ConfigEditor from './ConfigEditor.svelte';
  import HelpButton from './HelpButton.svelte';
  import { TUNING, type TuningKey } from '../tuning';

  let { which }: { which: TuningKey } = $props();
  const spec = $derived(TUNING[which]);
  let open = $state(false);
</script>

<details class="tuning" data-testid={`tuning-${which}`} ontoggle={(e) => (open = e.currentTarget.open)}>
  <summary>
    {spec.summary}
    {#if which === 'slo'}<HelpButton id="slo" />
    {:else if which === 'probe'}<HelpButton id="probes" />
    {:else if which === 'upstream_check'}<HelpButton id="upstream-checks" />
    {:else if which === 'anomaly'}<HelpButton id="anomaly-settings" />
    {:else if which === 'qlog'}<HelpButton id="qlog-settings" />
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
      role={spec.role}
    />
  {/if}
</details>

<style>
  .tuning {
    margin: 8px 0 12px;
  }
  .tuning > summary {
    cursor: pointer;
    color: var(--muted, inherit);
  }
</style>
