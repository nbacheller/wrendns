# SNMP setup: the gateway and the switches

WrenDNS can read what your network devices already know: the gateway's ARP table (which MAC address sits behind each IP address, on every VLAN), a managed switch's forwarding table (which port and VLAN a device is on) and the neighbours each switch port sees (LLDP). It only reads. The client has no way to send a write request (`SetRequest`), it asks one thing at a time (at least 50 ms between requests, so at most 20 a second), and it ends a poll that gets no answer.

This page is the checklist for the devices. The settings are in **Settings, Network inventory** (administrators change them; everyone can read them), or in the file under `[discovery]` (see [configuration](configuration.md#sections)).

## 1. Prepare the secret files

A credential never holds a password. It names a **file** that holds it, under a directory listed in `[node] secret_file_dirs` (by default `/run/secrets`, `/var/run/secrets` and `/etc/wrendns/secrets`). Docker and Kubernetes secrets already land there. A file outside those directories is refused when it is read, and the agent shows "skipped". The file holds the password and nothing else; a trailing newline is ignored.

## 2. UniFi gateway (UCG, UDM, USG)

1. In the UniFi Network application, find the **SNMP** settings (the menu differs between versions and models, so follow Ubiquiti's documentation for yours) and turn on **SNMPv3**.
2. Create a user and a password of 8 characters or more. UniFi uses one password for both authentication and privacy, which is what WrenDNS does when you leave the privacy password file empty. Choose **SHA** authentication and **AES** privacy.
3. Limit who may ask. If the device has an access list, allow only the address of the DNS host. On Kubernetes outside the host network, devices see the node's address after source translation: allow that address.
4. In WrenDNS add a credential with version **v3**, the user, `sha` (or `sha-256`), the authentication password file, and privacy `aes-128`. Add the gateway as an agent with that credential, leave **arp** and **ifmib** on, and press **Test**.

The gateway serves `ipNetToPhysicalTable` (and the older `ipNetToMediaTable`) and the interface tables. It has no bridge or LLDP tables, so **Test** shows those as "no answer (skipped)", and the poller leaves them alone until you press Test again. IPv6 neighbours are counted and left out; the inventory is IPv4 only.

**Turn off v1/v2c.** Many gateways still answer SNMP v1/v2c with the community `public`. Once v3 works, switch the old versions off: anyone on the LAN can read a device that answers `public`, and v2c sends its community in clear text.

## 3. Managed switches

UniFi's API never reports the ports of a switch that isn't UniFi. They need SNMP of their own, each as its own agent with its own credential.

1. On the switch, enable SNMPv3: create a user with SHA authentication and AES (128-bit) privacy, and give it read-only access to the standard MIBs (the bridge, Q-BRIDGE, IF-MIB and LLDP tables). The commands differ between vendors, switch operating systems and models; follow the vendor's SNMPv3 documentation for yours.
2. Allow only the DNS host's address, as the model's access-list or SNMP source setting allows.
3. Add the switch as an agent with `bridge` and `lldp` (and `ifmib` for port names). **Test** shows which of `dot1qTpFdbTable` (Q-BRIDGE) or `dot1dTpFdbTable` (BRIDGE) answered, whether `dot1dBasePortIfIndex` maps its ports, and whether the VLAN table `dot1qVlanCurrentTable` is there.

How a device is placed on a port:

- A forwarding entry's FDB ID is **not** a VLAN ID. It is mapped to a VLAN through the switch's VLAN table. Without that table the VLAN is left blank, never guessed.
- A port that leads to another switch or the gateway gives no location: a port with more than 8 learned MACs is an uplink, and so is a port whose LLDP neighbour is another listed agent or a UniFi device. Otherwise a device would show on every switch it passes through.
- Where a MAC shows on several ports at once (a loop, or a move in progress), the most recent sighting is kept.

## 4. What the poller does and shows

- Each agent is polled every `interval_secs` (60 s or more, 300 s by default), one at a time. A walk stops at 5,000 rows or 30 seconds, and a poll at 100 seconds or after three timeouts in a row.
- The first poll (and every **Test**) probes each table with one request; the answer, the security level reached, the v3 engine ID and the device's sysObjectID are the capability record, shown on the page. A table that did not answer is skipped, and logged once, until the next test.
- An ARP entry becomes a current address of the device only inside a `[[discovery.subnet]]` you listed. It expires when no poll has refreshed it for twice the slowest agent's interval (15 minutes at least).
- Everything a device says (names, descriptions, the sysObjectID) is cut to 64 or 255 bytes, has its control characters removed and is shown as text only.
- A poll that fails never affects DNS. The page shows why; three failed polls in a row raise the degraded health reason `discovery_agent_failing`. Metrics: `wrendns_discovery_agent_up`, `_polls_total`, `_poll_failures_total`, `_last_success_timestamp_seconds`, `_poll_duration_seconds`, `_table_rows` and `_table_answered`.

## 5. In the file

```toml
[node]
secret_file_dirs = ["/run/secrets"]

[discovery]
enabled = true

[[discovery.subnet]]
cidr = "192.168.1.0/24"

[[discovery.snmp_credential]]
name = "gateway-v3"
version = "v3"
user = "wrendns"
auth_protocol = "sha"                      # sha, sha-256, sha-384 or sha-512
auth_password_file = "/run/secrets/snmp-auth"
priv_protocol = "aes-128"                  # leave out for authNoPriv
# priv_password_file = "/run/secrets/snmp-priv"   # default: the authentication password

[[discovery.snmp_agent]]
name = "gateway"
address = "192.168.1.1"                # an RFC 1918 IPv4 literal; never a host name
credential = "gateway-v3"
interval_secs = 300
tables = ["arp", "ifmib"]                  # arp, ifmib, bridge, lldp
```

MD5, SHA-224, DES, AES-192, AES-256 and no authentication are refused when the file loads, with the reason. An inline `community` or password is not a key at all and fails the load. `wrendns snmp walk --agent gateway --table arp` prints a table from a configured agent for a quick look; it takes the agent's name and never an address.

## Test

`POST /api/v1/discovery/snmp/test` with `{"agent": "<name>"}` (administrators; agents need the `ops:discovery_test` scope and a reason) does the same as the **Test** button. `?dryRun=true` lists the OIDs it would query and sends nothing. A test of an agent waits 60 seconds after the last one. It runs on the designated node; a cluster replica forwards it to the primary.
