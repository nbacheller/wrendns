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
  // The node this card is on is the first in the listing, not the one picked in the Guarded settings picker.
  const restartNeeded = $derived(which === 'dnstap' && !!guarded.nodes[0]?.pendingRestart.includes(spec.guardedId ?? ''));
  // A saved value the config file displaces stays saved but a restart does not apply it.
  const displaced = $derived(which === 'dnstap' && !!guarded.nodes[0]?.settings.find((s) => s.id === spec.guardedId)?.displacedByFile);
  // An ordinary saved value the file now outgrows is removed at the node's next start.
  const dropped = $derived(which === 'dnstap' && !!guarded.nodes[0]?.settings.find((s) => s.id === spec.guardedId)?.droppedAtNextStart);
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
      <p class="notice small" data-testid="dnstap-restart-needed">Restart needed: a dnstap change confirmed here is read when {guarded.nodes[0]?.node ?? 'the node'} starts again.</p>
    {/if}
    {#if which === 'dnstap' && displaced}
      <p class="notice small" data-testid="dnstap-displaced">Saved, not applied: the config file sets another reader, or a feed or sampling that copies more, so this node runs the file's dnstap settings. The saved value is applied again when the file changes back, or remove it to follow the file.</p>
    {/if}
    {#if which === 'dnstap' && dropped}
      <p class="notice small" data-testid="dnstap-dropped">Saved, not applied: the config file changed so this would copy more than the file; it is removed at this node's next start. Save it again after the file changes.</p>
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
