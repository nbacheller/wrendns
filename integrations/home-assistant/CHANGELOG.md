# Changelog

## 0.2.0: the integration is now WrenDNS (breaking)

TelltaleDNS is now **WrenDNS** (spec/10 T33.2, ADR-1026). The integration's domain changed with it, so Home Assistant treats this as a **new integration**. Nothing is migrated for you: the old entry, its entities and anything that names them stop working until you move them over.

### What changed

| Before | Now |
|---|---|
| Integration domain `telltale`, folder `custom_components/telltale` | `wrendns`, `custom_components/wrendns` |
| Event `telltale_anomaly` | `wrendns_anomaly` |
| Actions `telltale.pause_blocking`, `telltale.resume_blocking`, `telltale.quarantine_device`, `telltale.release_device`, `telltale.acknowledge_anomalies` | `wrendns.pause_blocking`, `wrendns.resume_blocking`, `wrendns.quarantine_device`, `wrendns.release_device`, `wrendns.acknowledge_anomalies` |
| Entity IDs `sensor.telltale_*`, `switch.telltale_*`, `binary_sensor.telltale_*` | `sensor.wrendns_*`, `switch.wrendns_*`, `binary_sensor.wrendns_*` |
| Device and integration name "TelltaleDNS" | "WrenDNS" |
| Icon: none | the WrenDNS app icon (`brand/icon.png` and `brand/icon@2x.png`, from `brand/logos` in the repository) |

The node's own names change too, for the node this integration talks to: the `telltale_*` metrics are still exported next to `wrendns_*` for one release, and the API accepts the `X-Telltale-Reason` and `X-Telltale-Client` headers as well as `X-Wrendns-Reason` and `X-Wrendns-Client`. The integration sends both for this release, so it works against a node of either version.

### Migrating

1. **Note what uses the old names.** In Home Assistant, search your automations, scripts, scenes, dashboards and templates for `telltale` (the event `telltale_anomaly`, the `telltale.` actions and the `telltale_` entity IDs).
2. **Install the new integration.** Copy `custom_components/wrendns` into `config/custom_components/` and **delete the old `custom_components/telltale` folder**. Restart Home Assistant.
3. **Add WrenDNS.** Settings, Devices & services, Add integration, WrenDNS. Enter the node's address and the same API token as before (the token keeps working; the node's API did not change). Set the options again (pause minutes, quarantine group, anomaly events).
4. **Remove the old entry.** On the old "TelltaleDNS" card, open the menu and choose Delete. Its entities go with it.
5. **Rename in your automations.** Replace `telltale_anomaly` with `wrendns_anomaly`, `telltale.` actions with `wrendns.`, and `telltale_` entity IDs with `wrendns_`. Entity IDs follow the entity's name, so a renamed entity may have a numeric suffix if the old one still exists: finish step 4 first.
6. **Check.** Developer tools, Events: listen for `wrendns_anomaly`. Developer tools, Actions: `wrendns.pause_blocking` is listed.

The long-term statistics of the old sensors belong to the old entities, so they are gone with them when you delete the old entry; the new sensors start their own.

## 0.1.0

The first version: sensors, blocking switches, the anomaly event and the quarantine actions, under the domain `telltale`.
