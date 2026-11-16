# TelltaleDNS for Home Assistant

A custom integration that connects Home Assistant to [TelltaleDNS](../../README.md). It lets you:

- see what your network asks DNS;
- pause blocking for everyone or one group;
- act on **device anomalies**: a camera that suddenly contacts 30 new domains, or a plug that phones home every five minutes.

TelltaleDNS spots the behavior. Home Assistant can then do something physical about it: notify you, cut a smart plug's power, or move the device into a quarantine group where every name is blocked.

It talks to TelltaleDNS's REST API with an API token, and runs outside the DNS binary, so it can never slow DNS down.

> This lives in the `nbacheller/telltaledns` fork next to the server code it's tested against. To install it through HACS, it needs a repository of its own (HACS installs from a repository's root). Until then, copy it by hand as below.

## Install

1. Copy `custom_components/telltale` into your Home Assistant's `config/custom_components/` folder (with the Samba, SSH, or File editor add-on), then restart Home Assistant.
2. In TelltaleDNS, open **Settings → Users → API tokens** and create an **agent** token with the scopes you want:

   | Scope | For |
   |---|---|
   | `analytics:read` | the sensors (required) |
   | `config:read` | per-group switches, known devices, networks |
   | `ops:pause` | the blocking switches and the pause/resume actions (agents can pause for at most 60 minutes) |
   | `ops:anomalies` | acknowledging findings |
   | `config:write:clients` | quarantine and release |

   Each scope is optional except the first. A missing scope disables only that feature, and Home Assistant says which scope is needed when you try it. Every change the integration makes goes into TelltaleDNS's audit log, with a reason starting "Home Assistant:".
3. In Home Assistant, go to **Settings → Devices & services → Add integration → TelltaleDNS**. Enter the address of any node (`http://192.0.2.53:8053`) and the token. A cluster is one entry, whichever node you point at.

**Options** (on the integration's card):

- how many minutes a blocking switch pauses for (default 30);
- the quarantine group's name (default `quarantine`);
- whether new anomalies fire events.

## What you get

| Entity | What |
|---|---|
| Sensors | queries, blocked, and blocked share over the last 24 hours; cache hits; active devices; upstream latency (p90); health (`healthy` / `degraded` / `severe`, with the reasons); open anomalies (with the findings); known devices (from your routers, Home Assistant, and mDNS); networks (with each one's subnet, VLAN, and how full it is); version |
| Binary sensor | **Problem**: on while TelltaleDNS isn't healthy |
| Switches | **Blocking** for everyone, and **Blocking (group)** for each client group. Off pauses for the configured minutes; TelltaleDNS turns blocking back on by itself when the pause ends. |
| Event | `telltale_anomaly`, once per new finding: `id`, `kind` (`rate_spike`, `domain_volume`, `drift`, `beacon`, `nxdomain_storm`, `dga`), `client`, `client_name`, `domain`, `detail`, `observed`, `baseline`, `informational`. Muted findings don't fire. Findings that already existed when Home Assistant started aren't replayed. |
| Actions | `telltale.pause_blocking`, `telltale.resume_blocking`, `telltale.quarantine_device`, `telltale.release_device`, `telltale.acknowledge_anomalies` |

The known-devices and networks sensors appear only if the TelltaleDNS build has them (this fork) and the token has `config:read`.

## Quarantine

`telltale.quarantine_device` takes a device's name, IP, or MAC address and puts it in the quarantine group. When TelltaleDNS knows the device's MAC (from your router or Home Assistant), the quarantine follows the device even if its address changes. `telltale.release_device` puts it back in the groups it had, or removes the device entry the quarantine created.

Create the group in TelltaleDNS first, with a schedule that blocks everything all the time. Local names such as `nas.home.arpa` still answer:

```toml
[[group]]
name = "quarantine"
schedules = ["quarantine-always"]

[[schedule]]
name = "quarantine-always"
action = "block_all"
window = [{ days = ["daily"], start = "00:00", end = "24:00" }]
```

## Example automations

Tell me when a device starts acting strangely, with a button to quarantine it. The button carries the device's address, which is the first word of the event's `client`:

```yaml
automation:
  - alias: TelltaleDNS anomaly
    triggers:
      - trigger: event
        event_type: telltale_anomaly
        event_data:
          informational: false
    actions:
      - action: notify.mobile_app_my_phone
        data:
          title: "{{ trigger.event.data.client_name or trigger.event.data.client }} is acting up"
          message: "{{ trigger.event.data.kind }}: {{ trigger.event.data.detail }}"
          data:
            actions:
              - action: "TELLTALE_QUARANTINE|{{ trigger.event.data.client.split(' ')[0] }}"
                title: Quarantine it
  - alias: TelltaleDNS quarantine from the notification
    triggers:
      - trigger: event
        event_type: mobile_app_notification_action
    conditions:
      - condition: template
        value_template: "{{ trigger.event.data.action.startswith('TELLTALE_QUARANTINE|') }}"
    actions:
      - action: telltale.quarantine_device
        data:
          device: "{{ trigger.event.data.action.split('|')[1] }}"
          reason: "Quarantined from a phone notification"
```

Cut a camera's power if it beacons somewhere new:

```yaml
automation:
  - alias: Camera beaconing → power off
    triggers:
      - trigger: event
        event_type: telltale_anomaly
        event_data:
          kind: beacon
          client_name: garage-camera
    actions:
      - action: switch.turn_off
        target:
          entity_id: switch.garage_camera_plug
```

Pause blocking for the kids' tablets for 15 minutes from a dashboard button:

```yaml
action: telltale.pause_blocking
data:
  group: kids
  minutes: 15
  reason: "Homework site needs it"
```

## Keep DNS reachable from Home Assistant

If Home Assistant itself resolves through TelltaleDNS:

- reach TelltaleDNS by its IP address in this integration;
- give Home Assistant a second resolver.

A broken rule or a long pause then can't cut Home Assistant off from the thing it controls.

## Tests

```sh
pip install pytest-homeassistant-custom-component
cargo build -p telltale              # from the repository root: the tests run the real server
pytest                               # in this folder
```

The tests do three things:

- run the integration against a real TelltaleDNS node: setup, entities, switches, actions, quarantine, and the blocked answer;
- render the fork's Home Assistant registry template through Home Assistant's real `/api/template` endpoint;
- run a TelltaleDNS process that reads a Home Assistant test server and answers the names in DNS.
