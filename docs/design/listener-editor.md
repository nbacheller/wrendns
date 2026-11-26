# The guarded listener editor: design notes (rest of T27.14)

**Requirements:** API-902, DNS-001, DNS-901, CLU-004, CLU-006, API-901. **ADRs:** ADR-914, ADR-956,
ADR-957, ADR-977, ADR-978, ADR-1090 (points 8 to 10), ADR-107 (probes). **Task:** T27.14 in `spec/10`,
the part still open after the `listen-access` row was built (2026-11-25).

*Decision* means build it this way; amend the note (and record an ADR, AGENTS rule 3) if you can't.
*Open* means the owner decides first; the open points are listed in section 9 and asked through the
question tool, not answered here.

## 0. What exists, and what this note adds

Built and merged:
- **The framework** (T27.13, ADR-956, ADR-977): the registry (`crates/wrendns-config/src/guarded.rs`),
  the engine with preview, phrase, apply, the window's state machine, confirm, cancel, expiry,
  forwarding through the primary, the audit and the alert (`crates/wrendns/src/guarded/engine.rs`),
  the `Host` trait with `proof_socket`, `proof_socket_with` and a `probe_dns` hook that is `true` by
  default and has no production body (`host.rs`, `prod.rs`), start-up protection
  (`serve_with_fallback`, probation) and the UI shell (`GuardedChange.svelte`, `GuardedCard.svelte`,
  `GuardedConfirm.svelte`).
- **`listen-access`** (ADR-1090 point 8): an `immediate` row for `listen.require_client_id`, keyed per
  listener by `proto://addr`, with its applier (`appliers.rs` `ListenAccess`), the Listener access card
  and `ListenerGate.svelte`.
- **`Listeners::apply`** (`crates/wrendns/src/server.rs`): it binds additions first and closes
  removals after, so a changed address has no gap. A stream listener whose settings changed on the
  same protocol and address is closed and then bound again. One failing listener never stops the
  others. ADR-1090 point 10's fail-closed rule applies: a gate turned on that cannot be applied closes
  the old ungated socket. The result is published per encrypted listener (`gate_host::publish`).
- **The probes** (ADR-107, `probes.rs`): every listener is asked `probe.wrendns.invalid` over its own
  protocol, by the node, through the upstream client. A wildcard bind is asked on loopback.
  PROXY-protocol listeners and gated listeners are skipped.
- **Planned rows** in `PLANNED`: `listen`, `api-address`, `api-tls`, `trusted-proxies`, all `window`.

This note designs the four `window` rows, with most of the detail on `listen`, because the engine's
proof today is an HTTP request arriving on a new API socket, and a DNS listener cannot be proved that
way.

## 1. What an admin can change, and what stays in the file

### 1.1 The `listen` row's value (decision)

One value per node: the whole list of the node's DNS listeners, which the stored entry replaces as a
list. Each entry:

| Field | In the editor | Notes |
|---|---|---|
| `proto` | yes | `udp`, `tcp`, `dot`, `doh`, `doh3`, `doq`. |
| `addr` (IP and port) | yes | Any IP the host could hold, or a wildcard (`0.0.0.0`, `[::]`). |
| `tls.cert`, `tls.key` | yes, for `dot`, `doh`, `doh3`, `doq` | Paths to PEM files already on the node (1.2). |
| `path` | yes, for `doh`, `doh3` | Part of the URL clients use; default `/dns-query`. |
| `max_connections`, `max_connections_per_address` | yes, under "Advanced" | Resource limits; not for `udp`. |
| `require_client_id` | no, shown read-only | Owned by `listen-access` (ADR-1090 point 8). It is read-only here, with a link to Listener access. |
| `proxy_protocol` | no, shown read-only | Stays file-only (1.3). |

**Set by file.** The file wins (ADR-040, ADR-956 §2). `explicit_paths` counts `listen` as set when any
`[[listen]]` table is present, so a file with any `[[listen]]` locks the whole editor. The card then
shows "Set by file: <path>. Edit the file and reload to change the listeners." The Helm chart writes
`[[listen]]` itself, so on Kubernetes the editor is always read-only, and that is correct there:
Service ports and pod ports belong to the chart. The Compose bundle and the systemd install set no
`[[listen]]` by default, so the defaults apply (UDP and TCP on port 53, IPv4 and IPv6) and the editor
works.

Because a file that sets any `[[listen]]` locks the editor, a listener made in the editor can never have
`proxy_protocol` on and never carries a file's `require_client_id`. The two file-only fields therefore
never mix with UI-made listeners.

### 1.2 The certificate source (decision)

The only source in this task is **files on the node**. The admin enters the paths, and the preview
checks them:
- Each path is absolute, is a regular file, is not a symlink, and is not a path the T23.2 rules deny.
- The certificate parses, the key matches it, and the preview shows the names and the expiry.
- A certificate that expires within `cert_warn_days` (14) or is already expired is a warning.
- The node's user can read both files.

The preview never returns file contents.

Two helpers fill the paths, and both are only shortcuts:
- "Use the web UI's certificate" fills in `api.tls` `cert` and `key` when those are files.
- When `api.tls` is `self_signed`, the shortcut fills in the generated files under `<data_dir>/api-tls/`,
  and the preview warns that DoT and DoH clients reject a self-signed certificate (Android Private DNS
  among them).

Not in this task, with reasons:
- **Uploading a certificate and key through the UI.** That would put a private key in a request body
  and in `state.db`. No accepted ADR covers listener keys as stored secrets (ADR-903 covers credential
  references, and ADR-914 keeps key material off the API).
- **Certificates WrenDNS issues itself** (ACME, T36.10d, ADR-1082). When that lands it adds a third
  source, "the cluster's certificate", to this same field. Until then the field holds paths only.

### 1.3 What stays file-only, with reasons (decision)

- **`proxy_protocol`.** A listener with it on believes the source address in the PROXY header from any
  sender (there is no list of trusted senders). Turning it on from the UI would let every client choose
  its own address, past `[access] allowed_networks`, per-client policy and the rate limits. It also makes
  the listener unprovable, because ADR-107 skips PROXY listeners. It is shown read-only with that reason,
  in the same form as ADR-956 §1(b).
- **`require_client_id`.** This field is not file-only, but it is not this row's. It is shown with its
  effective value ("on, by default, because the address is public") and links to Listener access.
- **`[api] confirm_window_secs`.** Already file-only (`FILE_ONLY`), because a change can't lengthen its
  own window.
- **Allowed networks.** There is no per-listener allow list. `[access] allowed_networks` is one list in
  the shared part of the configuration (not node-local), so a node's listener row cannot own it. Today it
  has no UI control at all. The card shows it read-only under the listener table with a note. Where it
  gets a control is open (section 9, question 4).

## 2. The confirmation window for a listener change

### 2.1 Why the API proof does not fit (decision)

For `api-address`, the confirming HTTP request arriving on the new socket proves that the admin can
reach it (`Proof::NewSocket`, `c.arrived_on == proof_addr`). A DNS listener is not an HTTP socket, and
the API does not move. ADR-956 §3 already allows the other form for this row: "the request **or the
node's own probe** arrived on the new socket, and the node's probe of the new DNS listener answers".
ADR-914 says the same: "For a DNS listener change, the confirmation also needs the node's own probe of
the new listener to answer."

### 2.2 The proof for `listen` (decision, with an open extension)

A `listen` change is confirmed when both of these hold:

1. **Intent.** The same admin sends `POST /api/v1/guarded/pending/{id}/confirm` with the single-use
   token or their own session, on any of the node's API sockets. The API did not change, so no new
   origin is needed. The token rule, the wrong-admin refusal and the five-failure block are unchanged.
2. **Proof, by the node's own probe.** For every socket the change binds or rebinds:
   - **Who sends it:** the node itself, from the engine, with the probe client of ADR-107 (the upstream
     client, certificate checks off, because it connects by IP).
   - **Where it goes:** to `probes::reachable(addr)`, which is the listener's own address, or loopback
     for a wildcard bind. The source is the kernel's choice for that destination, so the probe stays on
     the host.
   - **What it asks:** `probe.wrendns.invalid` A over the listener's own protocol.
   - **What counts as an answer:**
     - On an ungated listener, any well-formed DNS answer (ADR-107; a REFUSED from `allowed_networks`
       counts).
     - On a gated listener, the gate's own refusal: HTTP 404 on DoH and DoH3, REFUSED with extended
       error 18 on DoT and DoQ (ADR-1090 point 4). That refusal also proves the gate is on, which is the
       state the preview promised.
     - ADR-1090 point 6 makes the periodic probes skip gated listeners. This one-off proof probe is not
       a periodic probe: it sends at most one query every 5 seconds per socket during the window, well
       under the refusal limit of 20 a minute per address. Its refusals are counted in
       `wrendns_client_id_refused_total` like any other, and the help topic says so.
   - **When it runs:** once right after the bind, then every 5 seconds while the window is open (so the
     confirm step shows a live result), and once more inside the confirm request. A confirm is accepted
     only if every probe answers at that moment. A failing probe refuses the confirm (403, "the node's
     own query to <proto>://<addr> got no answer: <error>"), and the window runs on, as for any wrong
     confirmation (ADR-956 §3). It is not counted toward the session's failure block, because the
     admin did nothing wrong.
   - **Removal-only changes:** nothing new is bound, so the probes go to every listener that stays. The
     proof is then that what remains still answers.

**What the probe cannot see.** It proves that the socket is bound, that TLS, HTTP/2 or QUIC works, that
the pipeline answers, and that the gate is in the promised state. It cannot see a firewall, a router's
DHCP option, or a container's published ports. The preview says so in words (2.6), and the confirm
step shows **evidence from other hosts**: the number of distinct client addresses, other than the
node's own, whose queries arrived on each new socket during the window. Collecting it is described in
2.4. Whether that evidence is only shown, or is also required before Confirm is enabled, is open
(section 9, question 1). This note recommends showing it without requiring it.

**Engine change.** `Staged` gains `dns_probes: Vec<DnsProbe>` (protocol, address to ask, path, and
whether a refusal by the gate is the expected answer). For a row whose `Staged` carries probes and no
`proof_addr`, `confirm_inner` judges `proved` as "every probe answers" and skips the `arrived_on` test.
The `setting == "listen"` special case in `confirm_inner` goes away: the staged value says what to
prove. `api-address` keeps `proof_addr` and needs no probe.

### 2.3 Stage, commit and abort in `Listeners` (decision)

The engine runs on the API's runtime, and `Listeners` is owned by the server's reload loop. The
production `Host` therefore reaches `Listeners` through a command channel next to the existing reload
channel: `ListenerCmd::{Stage(list, reply), Abort(reply)}`. `Listeners` gains:

```text
staged: Option<StagedSet>   // sockets bound for a pending change, none of them in `udp`/`streams`
```

- **Stage(new list).** The node works out the difference against the running set:
  - **Added** (a protocol and address not running): bound now, next to the old sockets, with the gate
    the host facts give now (`bound_form`), and held in `staged`. The live handler serves them, so
    queries sent there during the window get real answers.
  - **Removed:** not touched. The old sockets keep answering for the whole window.
  - **Changed** (same protocol and address, other settings: a new certificate path, DoH path or limit):
    the new settings cannot be bound on a port the old socket holds. The new settings are bound on a
    temporary **proof port** (an ephemeral port on the same IP, or on loopback for a wildcard), which
    is probed in place of the real one. That is the same device ADR-956 §3 uses for an API TLS change
    on the same address. The preview names the port (`proofPort`).
  - **Overlap on the same port** (a wildcard and a specific address of one family, for example
    `0.0.0.0:853` to `10.0.0.53:853`): UDP sockets set `SO_REUSEPORT`, so the specific socket binds next
    to the wildcard, and the kernel should deliver to the more specific socket (a process test checks
    both, since this depends on the kernel). TCP sockets set only `SO_REUSEADDR`, so on Linux
    the bind fails while the other one listens. A TCP-based overlap is staged like a changed listener,
    on a proof port.
  - **A failed bind changes nothing.** Everything staged so far is closed, and stage answers with the
    address and the OS error (for example "dot 203.0.113.9:853: Cannot assign requested address (the
    address is not on any interface)"). The engine audits `settings.guarded_rolled_back`
    (`bind_failed`), as it already does.
- **Adoption, not a second bind.** When `apply(listen)` reaches a listener whose `bound_form` equals a
  staged socket, it **moves the staged socket into the running set** instead of binding again. That
  makes commit independent of order: on a replica, the entry comes back through the primary and the
  replicated reload may run `apply` before the engine's `guard.commit()` returns. Either path adopts the
  same sockets, and `apply` then closes the removed listeners as it does today. That close is the
  moment the old sockets go.
- **Commit** is `write_entry`, then the reload that the entry triggers (adoption, removals closed,
  changed listeners swapped from their proof port to the real port), then `guard.commit()`. The last
  step checks that every staged socket was adopted or is a proof-port socket, closes the proof ports,
  and fails if anything is left. A changed listener's swap is today's close-and-bind on the real port:
  a gap of a few milliseconds on that one TCP-based listener, as a reload has today, and never on UDP.
  If that bind fails, `apply` binds the old settings again and commit answers `commit_failed`. The
  engine then removes the entry and runs the reload again, which puts the previous list back.
- **Abort** (expiry, cancel, a failed commit before the write) closes every staged and proof-port socket
  and touches nothing else. Nothing was written.
- **A reload during the window** (SIGHUP, another API change, a replicated change) runs `apply` on the
  running configuration, which still holds the old list, and leaves `staged` alone. If the reload finds
  that the file now sets `[[listen]]`, the file has taken over: the pending change is rolled back as
  `cancelled`, with the detail "the file now sets the listeners". If the reload needs an address that a
  staged socket holds, that listener reports the bind error as it would today, and the pending change
  runs on.
- **A restart inside the window** starts with the previous list, because the pending change was held in
  memory only (ADR-956 §4).
- **Bench.** `Listeners` and the adoption path are `wrendns` code and the evidence counter (2.4) is
  `wrendns-net` code, so `make bench-smoke` runs before the merge (ADR-956 consequences).

### 2.4 Evidence from other hosts (decision on how it is collected)

Each staged socket is bound with a thin wrapper around the shared handler. The wrapper does one relaxed
atomic load of an "observe" flag, and while the flag is set it adds the peer to a small fixed table of
at most 64 entries (IPv6 by /64, the node's own addresses excluded). The table is read by the confirm
step and dropped at commit or abort. An adopted socket keeps the wrapper with the flag cleared, so the
steady-state cost is that one load. `make bench-smoke` must show it within budget. If it doesn't, the
evidence is dropped, and the proof (2.2) does not depend on it.

### 2.5 Automatic rollback (decision)

The rollback reasons of ADR-956 apply unchanged:
- `expired`: no confirm in the window.
- `cancelled`: the admin cancelled, or the file took over (2.3).
- `bind_failed`: at stage.
- `commit_failed`: the write failed, or the sockets couldn't be kept.
- `failed_start`: a confirmed entry whose bind fails at start falls back for that start only, with
  `guarded_bind_fallback`, through `serve_with_fallback`. This covers a VIP or DHCP address that is not
  up yet.

A rollback closes only what the change opened. The old sockets were never closed before the commit, so
DNS keeps answering throughout (CLU-004). `api_902_bad_listener_rolls_back_and_dns_keeps_answering`
proves it with a UDP query loop.

### 2.6 The rules that can't be broken (decision)

Each rule is checked at preview, again at apply, and again at confirm against the configuration then in
force.

1. **Never lock the admin out of the UI.** The `listen` row never touches an API socket. The preview
   refuses a listener whose port, on an overlapping address of the same family, is the port of
   `api.listen`, `api.http_redirect`, `[telemetry.metrics] listen`, `cluster.listen`, or a proof port
   of the pending window. This is a failed check with the conflicting setting named, for example "port
   8053 is the web UI's ([api] listen)".
2. **Never leave port 53 unanswered.** For each address family in which the running set has a UDP
   listener on port 53, the confirmed set must still have one, and the same holds for TCP. Failing that
   is 409 `would_disconnect_you`, with the detail "this leaves no UDP listener on port 53 for IPv4".
   This is stricter than ADR-956 §3's "no DNS listener", which still applies as well: an empty list is
   refused. Moving DNS off port 53 altogether stays possible, but only in the file. A node that does not
   run port 53 today (behind a balancer on 5353, for instance) is not held to the rule.
3. **A removed address is said out loud.** Removing an address the running set answers on is allowed,
   because the window cannot help after the commit. The preview warns: "Clients that send queries to
   10.0.0.53 stop getting answers when you confirm. Point them (your router's DHCP DNS option) at the new
   address first; you can add the new listener now and remove the old one in a later change." The
   editor's default flow is **add first, remove later**: the Review button of a change that both adds
   and removes offers "Add only, keep the old listeners" as the first choice.
4. **The gate never fails open.** A socket is never bound with a weaker gate than the value in force
   says (ADR-1090 point 10). A changed listener rebound after a failed swap gets its old gate, never
   "off".
5. **Warnings** (from the roadmap):
   - In Docker or Kubernetes (`WRENDNS_SUPERVISOR`), "published ports and Service ports are not changed".
   - An address that is on no local interface: "the bind will fail unless the address is floating (a
     VIP); bind the wildcard, or allow non-local binds".
   - A certificate that is expired or close to expiry.
   - A new listener that is gated by default (section 4).

### 2.7 A node with no browser at its API (open)

The confirm has to reach the target node itself (ADR-956 §5): the primary cannot confirm for the admin.
For a `listen` change the node's API address does not change, so the UI opens the node's own API URL
(from the cluster's member list), with the token in the `#fragment`. When the admin's browser cannot
open that URL, the change cannot be confirmed and rolls back at expiry. That safe failure is the default.
This happens on a replica whose API listens on loopback or on a cluster-only network, or a pod behind a
shared Service where the request may land on another pod. The case where `[api] enabled = false` is
simpler: the node has no guarded routes at all, so the file and the offline CLI are its only path.

The preview says, before apply: "You confirm this at <url>. If your browser can't open it, the change
rolls back after <n> seconds." Before apply, the UI also tries `GET <url>/livez` from the browser in
`no-cors` mode, which tells only whether a connection was made. If it fails, the UI says the change will
roll back and keeps Apply enabled. Whether to go further for `listen` only, for example by accepting a
confirm relayed by the primary, is open (section 9, question 2). That needs an amendment to ADR-956 §5,
which rejected exactly that.

## 3. Cluster behaviour (decision)

- **Per node.** `listen` is node-local (`NODE_LOCAL`), so each node has its own entry,
  `node/<node-id>/guarded/listen`, written only at confirm and only through the primary (ADR-956 §§2
  and 5). The entry is never part of the shared part (ADR-978). There is no "all nodes" apply. Each node
  gets its own preview, its own phrase (`<node> listen`) and its own window.
- **Forwarding.** A change made at the primary's UI for node X travels with the signed single-use
  assertion. The window, the staged sockets and the probes all live on X, and the confirm goes to X's
  API (2.7).
- **Replication of the stored value.** On a replica, `write_entry` goes through the primary and comes
  back in the replicated blob. Adoption (2.3) makes the order of that reload and the engine's commit
  irrelevant. A replica that can't reach the primary at confirm answers `primary_unreachable`, and the
  window runs out and rolls back (ADR-956 §5). It never runs a value nobody replicates.
- **A node that fails to apply.** At runtime, the only apply after confirm is the adoption, which cannot
  fail to bind. At a later start, a confirmed entry whose address isn't there (a VIP held by the other
  node, a VLAN interface that isn't up) falls back for that start only (`guarded_bind_fallback`, audit
  `failed_start`), and the entry stays for the next start. A restored entry starts on probation, and two
  failed starts drop it (ADR-956 §4). A node below the version that knows the row ignores the entry
  (`clu_010`), and the preview says so.
- **Floating addresses.** A keepalived-style VIP exists on one node at a time. The preview of a listener
  on an address that is on no local interface warns as in 2.6, so the admin binds the wildcard on every
  node that might hold the VIP. The probe of a wildcard runs on loopback, so it passes on a backup node
  too.
- **Witness nodes** serve no DNS. The editor isn't shown for them, and a preview for one fails the
  check "a witness serves no DNS".
- **Restart warnings** are not needed: a `listen` change never restarts anything. The preview does warn
  when X is the only healthy resolver in its site (the cluster health view). If something goes wrong in
  the window, the old sockets are still there, but the warning sets expectations.

## 4. The gate default and weakening (decision, one rule open)

`require_client_id` stays with `listen-access` (ADR-1090 point 8). Moving or adding a listener changes
which address the default is judged on, so the `listen` row has to take the default into account.

- **The default resolves on the new address.** The preview and stage use `wrendns_config::default_gate`
  with fresh host facts (`gate_host::read()`), as `listen-access` does. Each new listener line in the
  preview says what its gate will be and why. For example: "dot://203.0.113.9:853: answers only a known
  device key (default: the address is public)". Or: "dot://0.0.0.0:853: open to the allowed networks
  (default: the host has no public IPv4 address; it has a global IPv6 address, so it can be reached from
  the internet)".
- **An explicit setting does not follow a moved listener.** `listen-access` keys its lines by
  `proto://addr`, so a listener at a new address starts on its default. Re-deciding the gate on the new
  address is the safer choice, because the new address may be public where the old one was not. A
  single commit that wrote two entries would also not be atomic across replication. The preview names
  each explicit setting that is dropped: "Listener access for dot://10.0.0.53:853 was set to off;
  dot://10.0.0.54:853 starts on its default (off)". Stale lines in the `listen-access` entry are ignored
  by its overlay, which matches by `proto://addr`. The next Listener access save sends the current list
  and clears them.
- **Order of overlays.** `listen` is overlaid before `listen-access`, so the gate lines apply to the list
  the node runs. The overlay walks the registry rows in a fixed order with `listen` first, and is not
  left to the order of the stored entries.
- **No `listen-access` change during a `listen` window.** The pair is mutually exclusive on a node:
  `listen-access` is refused with 409 `guarded_change_pending` while a `listen` change is pending, and the
  reverse cannot happen because `immediate` changes are applied at once. A gate change during the window
  would change the gate of sockets that are already staged, so the preview would no longer describe them.
- **The host changes during the window.** If the host's public-IPv4 fact changes between stage and
  confirm, the gate a staged socket was bound with may no longer be the default. The confirm compares the
  staged gates with a fresh reading and refuses with 409 `preview_stale` ("this host's addresses changed
  since the preview: cancel and review the change again"). The window runs on until it is cancelled or
  expires.
- **New listeners gated by default** get the warning of ADR-1090 point 8: "devices without a device key
  are refused on this listener". After the commit, the health reason `listener_gate_default` appears for
  them, as for any listener on its default.
- **Weakening.** The row's `weakens` cannot see host facts (the `listen-access` row has the same
  limitation), so the applier's `check` sets `Checked.weakening`. A change weakens when any of these
  holds:
  - (a) TLS is removed or downgraded on an address that stays served: `tls_removed_or_downgraded`,
    ADR-914.
  - (b) An encrypted listener whose effective gate is on is replaced by one whose effective gate is off.
    "Replaced" means the same protocol, with the old one removed or changed in the same change. This
    covers moving a gated DoT listener from a public address to a wildcard on a host that has only a
    global IPv6 address.
  - (c) The change adds a socket that a public address reaches and that answers without a device key.
    This is open (section 9, question 3).

  A weakening change gets the red mark and needs a sign-in within the last 10 minutes.

## 5. API, UI, help and audit

### 5.1 API (decision)

- The routes are the framework's: `POST /api/v1/guarded/listen/preview`, `POST /api/v1/guarded/listen`,
  `POST /api/v1/guarded/pending/{id}/confirm`, and `.../cancel`. Agents and every token are refused as
  for any guarded row. The OpenAPI document gains the row's value schema. There is no MCP tool.
- **Value:** `{"listeners": [{"proto", "addr", "tls": {"cert", "key"} | null, "path" | null,
  "maxConnections" | null, "maxConnectionsPerAddress" | null}]}`. An unknown field is refused, and so are
  `proxyProtocol` and `requireClientId` (they are not this row's), each with a sentence naming where the
  field is set.
- **Preview** returns the framework's fields plus a `listeners` diff: for each line, `added`, `removed`,
  `changed` or `kept`, the effective gate and why, the certificate's names and expiry, `proofPort` for a
  changed or overlapping line, and the dropped explicit gate settings.
- **New read route:** `GET /api/v1/guarded/pending/{id}`, which takes the confirm token or the same
  admin's session (the confirm route's own checks). It returns `deadlineSecs` and, per staged socket, the
  last probe (`answered`, `refused_by_gate`, or `no_answer` with the error, and the time) and the
  evidence counter. `GET /api/v1/guarded` keeps returning only that a change is pending, its setting
  and its deadline (ADR-956 §7), because probe lines name the pending addresses.
- **Plans** keep refusing the path. ADR-977 point 12 is done here: a plan step naming `listen` (or a
  path inside it) is refused with `guarded_only`.

### 5.2 UI (decision)

**Settings → System → Listeners** (a card above Listener access, admins only; operators and viewers see
the table without controls):
1. A table with one row per listener: protocol, address, port, certificate (file name and expiry),
   device key (the effective gate, read-only, linking to Listener access), PROXY (read-only), and the
   status from the probes ("answering, 3 ms", "not probed: device key required", "closed"). Below it,
   `[access] allowed_networks` is listed read-only, with the note from section 9, question 4.
2. Per row, **Edit** and **Remove**, plus **Add listener** under the table. Edits go into a draft. The
   table marks draft rows "new", "changed" or "to remove", and nothing reaches the server until Review.
   The add and edit form has:
   - protocol (a select);
   - address (text, validated as an IP; placeholders `0.0.0.0` and `[::]`);
   - port (the protocol's standard port prefilled: 53, 853, 443);
   - for TLS protocols, the certificate and key paths with the "Use the web UI's certificate" shortcut;
   - for DoH, the path;
   - under "Advanced", the two limits.
3. **Review change** opens `GuardedChange` with the draft as the value. The review step shows:
   - the diff as a list, each line with its gate sentence;
   - the warnings, the dropped gate settings and the red mark when weakening;
   - "You confirm this at <url>" with the reachability result (2.7);
   - the phrase field (`<node> listen`).

   When the draft both adds and removes, the review step offers **Add only (recommended)** and **Add
   and remove**.
4. **The countdown** is the framework's bar, with a live block for each staged socket: "dot://
   203.0.113.9:853: the node's own query was refused by the device key gate (expected)", "seen from 2
   other hosts". It also shows test commands with the address filled in, ready to copy and run from a
   client: `dig @<ip> -p <port> example.com`, `kdig +tls @<ip> -p 853 example.com`, and
   `curl -H 'accept: application/dns-message' https://<ip>/dns-query?dns=...`. **Confirm** is enabled when
   every probe answers (or, under question 1's option B, also when evidence arrived). **Cancel** sits next
   to it.
5. The outcome uses `reasonText` for the rollback reasons, plus the new detail "the file now sets the
   listeners".

**Texts:**
- Card intro: "The addresses and ports this node answers DNS on. A change is tried next to the
  current listeners and kept only when you confirm it; if you don't, the old ones stay and the new ones
  close."
- Review effect: "Adds DoT on 203.0.113.9:853. Keeps every current listener until you confirm. Removes
  UDP and TCP on 10.0.0.53:53 when you confirm."
- Proof line: "Before you can confirm, the node asks each new listener a test question itself. This
  proves the listener works on this machine. It doesn't prove that your devices can reach it: a
  firewall, your router or your container's published ports may still be in the way."
- Set by file: "Set by file: /etc/wrendns/wrendns.toml. Edit the file and reload to change the
  listeners."
- PROXY read-only: "Set in the file only: a PROXY listener trusts the address in each connection's
  header, so turning it on here would let any client choose its own address."

### 5.3 Help (decision)

- New topic `listeners`: what a listener is; the window and the two-step move; what the node's own probe
  proves and what it doesn't; port 53; the certificate files; the PROXY reason; Docker and Kubernetes;
  floating addresses; recovery (the file wins; `wrendns guarded clear listen`; `WRENDNS_IGNORE_GUARDED`).
- `listener-keys` gains a paragraph saying a moved listener starts on its default.
- `guarded-settings` gains a line saying a DNS listener change is proved by the node's own probe.
- `check:help` covers the new `HelpButton` ids.
- Docs: `docs/running.md` (listeners), `docs/recovery.md` (the `listen` entry), `site/guide-settings.html`.

### 5.4 Audit and alerts (decision)

These are the framework's records with nothing new:
- `settings.guarded` at confirm, with `before` and `after` as listener lists (paths only, no secrets
  involved) and the reason.
- `settings.guarded_rolled_back` with the reason code.
- `settings.guarded_refused` for `would_disconnect_you`, a stale preview, a bad phrase or a reauth.
- `guarded_setting_changed` when the change goes pending and again on its outcome.

A probe failure at confirm is not audited: it is a refused confirm and the window runs on. The log
names it at info level.

## 6. The other three rows (summary; the roadmap and ADR-956 §3 hold the rules)

- **`api-address`** (`api.listen`, proof `new_socket`). The API server gains the same stage, commit and
  abort for its socket. Stage binds the new address as a proof listener; it already serves only the
  confirm route and the UI files (ADR-977). At commit, the proof listener's router is **swapped to the
  full app** (the service holds the router behind an `ArcSwap`), the old listener stops accepting and
  drains, and the redirect target (`http_redirect`) and the probes move to the new address. Nothing
  rebinds. `restart_only_changes` keeps saying that a *file* edit of `api.listen` needs a restart. Only
  the guarded window moves it live. Weakening: loopback-only to a wider address. Preview checks: a port
  clash with a DNS listener (the mirror of 2.6 rule 1), the address on a local interface, and the
  Docker and Kubernetes warning. The UI's link carries the token to `<scheme>://<new address>/#...`.
- **`api-tls`** (`api.tls`, proof `new_cert`). On the same address and port, a temporary parallel
  listener on `proofPort` serves the new certificate (`proof_socket_with` exists). At commit, the main
  listener's certificate store is replaced in place (the `CertStore` reload that the file watcher
  already uses), so nothing rebinds. Moving from HTTP to HTTPS on the same port needs the main listener
  to switch from plain to TLS. It is done as a swap of the accept loop behind the same socket, not a
  rebind. Weakening: TLS removed, or a provided certificate replaced by a self-signed one.
- **`trusted-proxies`** (`api.trusted_proxies`, proof `proxy_list`). The engine already has the proof
  and the pending-list rule (the new list applies only to the confirm route until confirmed). This row
  adds the applier, the form (a list of CIDRs), and the confirm step's "the server now sees your address
  as <addr>". Weakening: an entry added.

**`would_disconnect_you` for the API.** ADR-914 refuses a change "that removes the API listener the
request came in on in the same request that is meant to confirm it". ADR-956 §3 shortens that to "that
removes the API listener the apply request itself came in on". Read literally, ADR-956 §3 would refuse
every `api-address` move, because `api.listen` is one address and every apply arrives on it. This note
follows ADR-914's reading: the confirm must arrive on the new socket, so the old one is never the
confirming request's. That reading is section 9, question 5.

## 7. Test plan

**Unit** (`wrendns-config`, the `wrendns` appliers):
- The `listen` row agrees with `PLANNED` (mode, paths, `proof: NewSocket`).
- Value parsing refuses unknown fields, `proxyProtocol` and `requireClientId`.
- The check table:
  - port clashes with each internal port;
  - the port-53 rule per family and transport (pure, over config values: CI can't bind 53);
  - an empty list;
  - a witness;
  - certificate path rules;
  - a set-by-file lock.
- The weakening table (a), (b), and (c) as decided, over `HostFacts` fixtures (public IPv4, private
  only, global IPv6 only, unreadable).
- The gate lines and dropped explicit settings in the preview text.
- The overlay order, `listen` before `listen-access`.
- `listen-access` is refused while a `listen` window is pending.
- `preview_stale` at confirm when the facts change.

**Process tests that bind real sockets** (an in-process node on `127.0.0.1` and `[::1]` with ephemeral
ports, `tokio::time::pause` for the window):
- AC 1: `api_902_listener_change_binds_before_release` and `api_902_old_listener_kept_until_confirmed`.
- AC 2: `api_902_bad_listener_rolls_back_and_dns_keeps_answering`, with a UDP query loop across the
  stage, a failed bind, expiry and a confirmed change. Not one query may be lost on a listener that
  stays.
- AC 4: `api_902_would_disconnect_refused` for no DNS listener and no port 53.
- AC 6: `api_902_listener_change_on_another_node_confirmed_at_that_node` (two nodes).
- New:
  - `api_902_listener_proof_is_the_nodes_own_probe`: confirm refused while a probe fails, accepted once
    it answers.
  - `api_902_gated_listener_proved_by_its_refusal`.
  - `api_902_changed_listener_probed_on_proof_port_then_swapped`.
  - `api_902_reload_in_window_keeps_staged_sockets`.
  - `api_902_replicated_reload_adopts_staged_sockets`.
  - `api_902_file_taking_over_cancels_the_window`.
  - `api_902_restart_in_window_starts_with_old_listeners`.
  - `api_902_confirmed_listener_bind_failure_falls_back_at_start`, which exists for the framework and
    gets a real `listen` entry here.
  - `api_902_listener_evidence_counts_other_hosts`.
- The `api-address`, `api-tls` and `trusted-proxies` ACs (3 and 5) as the roadmap lists them.
- `make bench-smoke`, with the result in the Done note.

**Playwright** (the e2e server on two ports, T24.19's offsets; 1-ui runs in serial mode; stub routes,
then `goto`, then `reload`):
- `api_902 listener change rolls back without confirmation`: add a TCP listener on the second offset
  port, see the countdown and the probe line, let it expire, and see "rolled back (expired)" with the
  table unchanged.
- `api_902 listener add confirmed with the node's probe`: the confirm button waits for the probe line.
- `api_902 listener editor is read-only when set by file`.
- `api_902 listener removal warns about clients`, with the Add-only choice.
- `api_902 operator sees listeners without controls`.
- Plus the roadmap's `api_902 move the api to a new port and confirm` and `api_902 trusted proxy add
  asks for sign-in`.

**Not tested here:** a real firewall, Docker published ports, keepalived. Those are covered by the
warnings and the docs, and by the three-node CI where it applies.

## 8. Build tasks, in merge order

Each task merges on its own with its UI, help and tests (API-901). Sizes: S is up to a day of agent
work, M two to three days, L about a week.

1. **T27.14a `Listeners` stage, commit, abort and adoption** (M). `server.rs` `StagedSet`, the command
   channel, adoption in `apply`, proof-port staging for changed and overlapping TCP listeners, abort.
   There is no row yet: the e2e `e2e-window` test row drives it through a test applier. Process tests
   for binding before release, keeping until commit, reload in the window and adoption. `make
   bench-smoke`. Nothing user-visible.
2. **T27.14b The DNS probe proof in the engine** (S). `Staged.dns_probes`; `confirm_inner` judges
   probes for a row without `proof_addr`; the probe loop every 5 s; `GET /api/v1/guarded/pending/{id}`;
   `GuardedChange` shows probe lines for any row that has them (the e2e row exercises them). The
   `setting == "listen"` special case is removed. Unit and process tests. The evidence counter (2.4)
   lands here behind its bench result.
3. **T27.14c The `listen` row and the Listeners card** (L). Registry row, applier (check, weakening,
   warnings, the port-53 and clash rules, gate lines, overlay order, the `listen-access` exclusion,
   `preview_stale`), the card, the editor, the review and countdown blocks, help `listeners`, docs,
   Playwright, OpenAPI. ACs 1, 2, 4 and 6. The `PLANNED` row moves into `REAL`.
4. **T27.14d The API server's stage and commit, and the `api-address` row** (L). The router swap, the
   drain, the redirect and probe follow-up, the row and form, help `api-address`, AC 3's first test and
   the Playwright port move.
5. **T27.14e The `api-tls` row** (M). After d: in-place certificate swap, the plain-to-TLS accept-loop
   switch, the form with the same certificate checks as 1.2, AC 3's second test.
6. **T27.14f The `trusted-proxies` row** (M). After b, independent of c to e: applier, form, the "seen
   as" line, help `trusted-proxies`, AC 5, Playwright sign-in.

When f and e are merged, the `#![allow(dead_code)]` on `crates/wrendns/src/guarded` comes off (ADR-977
point 3), and T27.14's box is ticked.

## 9. Open points for the owner

These are asked through the question tool, each with options and a recommendation:
1. Whether the confirm requires evidence from another host, or only shows it.
2. A node whose API the browser can't open: keep ADR-956 §5, or relay the confirm for `listen`.
3. Whether adding an unguarded socket reachable from a public address counts as weakening (rule c).
4. Where `[access] allowed_networks` gets its control; no per-listener list.
5. The reading of `would_disconnect_you` for an API address move.
