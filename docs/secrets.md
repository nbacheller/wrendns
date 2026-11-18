# Stored secrets

TelltaleDNS reads a credential (a router's API key, an alert destination's token, an OIDC client secret, a sink's token, OTLP headers, the Git source's credentials) from one of three places: inline in the configuration files, a file named by a `*_file` setting, or a **stored secret** named by the matching `*_ref` setting. This page is about the third: what protects a stored secret, who holds its key, how to rotate the key, and how to recover when something goes wrong. How to use them is in [Running TelltaleDNS](running.md#stored-secrets).

## What a stored secret is

- **Write-only.** A value goes in once and never comes back out: no API, UI page, MCP tool, log line or support package returns it, and a backup carries it only encrypted under a passphrase you choose. Status reads show its name, when and by whom it was set, and whether this node can read it.
- **Encrypted per node.** Each value is encrypted in `state.db` with ChaCha20-Poly1305 under a key that belongs to this node, with a random 96-bit nonce. The ciphertext is bound to the key's ID, the secret's kind and name, and the stamp of its last change, so a row copied over another one (or given another stamp) fails to decrypt and is reported `corrupt`.
- **Kept in memory as ciphertext.** The node decrypts a value only when an integration uses it, and wipes its own copy afterwards. That covers TelltaleDNS's own buffers; what the HTTP, TLS and protobuf libraries copy while sending a request isn't wiped.
- **The files win.** A credential set inline or by file in the configuration files is used, and the API can't replace it (409 `set_by_file`).
- **Entered by admins, over HTTPS.** Only an admin sets or clears one (`PUT`/`DELETE /api/v1/secrets/<name>`, or `telltale ctl secrets set`), never an agent token, and only over HTTPS or on the node itself, unless `[api] allow_secrets_over_http` says otherwise ([Running TelltaleDNS](running.md#setting-a-stored-secret)). The value crosses the HTTP and JSON layers on its way in, and in a cluster the mTLS channel to the primary; those copies aren't wiped either.
- **Limits.** At most 128 stored secrets, each a single line of up to 8 KiB (no line breaks, tabs or other control characters), and never the text `<redacted>`. Names are lowercase letters, digits, `.`, `_` and `-`, up to 63, starting with a letter or digit.

## Threat model

| Who | Can they read a stored secret? |
|---|---|
| Someone with a copy of `state.db` or a backup | No. `state.db` holds only ciphertext, and a backup never copies the secrets table: its secrets travel only in `secrets.enc`, encrypted under a passphrase (see Backups below). Anyone with that file *and* the passphrase can read them, so keep the two apart. |
| Someone with the whole data directory (`state.db` and `secrets.key`) | **Yes**, with the default data-directory key. Keep the key elsewhere (below) if the volume itself may leak. |
| A process running as the TelltaleDNS user | Yes: it can read the key wherever it is. Plugins (`exec://` upstreams) and the self-update are started without the key variables, but a same-user process can still read `secrets.key`; that's why only admins can create a plugin upstream. |
| An admin | Can set, replace and clear a secret, and point a reference at one, but can't read one back. |
| An operator or an agent token | Can neither read nor redirect one: changing a `*_ref`, or where an entry with a credential sends it, is an admin's change. |

## Custody: where the key lives

The key is 32 random bytes, written `ttsk1:` followed by 43 base64url characters. Its `key_id` (shown in logs and status) is derived from it and safe to share. The node uses the first of:

1. **`TELLTALE_SECRETS_KEY`**, an environment variable. On Kubernetes, use `valueFrom.secretKeyRef`, never a literal `value:` in the manifest.
2. **`[node] secrets_key_file`** (or `TELLTALE_NODE_SECRETS_KEY_FILE`): a file, typically a mounted Kubernetes Secret or Docker secret. The Helm chart's `secretsKey.existingSecret` sets this up on the controller only.
3. **`<data_dir>/secrets.key`**, created on a full member's first start while no secret is stored: mode 0600, written whole, never replaced. A key file other users can read, one they can change, or one owned by another user (root aside) is warned about at start (group read is fine: Kubernetes `fsGroup` mounts need it).

Prefer 2 for anything beyond a single box: the key then lives apart from the data it protects, and a copied volume holds only ciphertext. Keep a copy of the key somewhere safe (a password manager); without it the stored secrets can't be recovered.

**Resolver pods** (ephemeral cluster members) hold no stored secrets, need no key and never make one. **In a cluster**, every full member has its own key, and one member's key opens nothing on another's `state.db`.

## Replication in a cluster

Full members share stored secrets; resolver pods and witnesses never hold one. The design is ADR-903 section 6.

- **Stamps.** Every change is stamped `(epoch, seq)`: the cluster's epoch and a counter within it, taken under the primary's lease. A stamp is never reused. A higher stamp is a later change.
- **Head.** A member's secrets head is its newest stamp and a BLAKE3 digest over the sorted `(name, kind, stamp, deleted)` list. It holds no value and no value hash. It travels in heartbeats, not in configuration versions, so pins and canary rollouts neither hold it back nor bump a version.
- **Fetch.** A replica whose head differs from the primary's (the primary of the highest epoch it has heard of) pulls the primary's rows: a page at a time, each page under 900 KiB, over the mTLS cluster channel. It checks that every page carries the same head and that the rows recompute it, and discards the whole answer otherwise. A fetch is tried at most once per head and backs off from 30 seconds to 10 minutes after a failure. Nothing about it gates manifest application, readiness or DNS.
- **Re-encryption.** A replica encrypts each value under its own key with the same stamp. Its files hold no plaintext, which the tests check.
- **Deletes** are tombstones, which replicate like values.
- **Held rows.** A row the primary holds but can't decrypt is sent without a value. The replica keeps its own copy as it is, and the Cluster page counts it as held.
- **Orphans.** A failover can strand a write: an old primary may have stamped a change that never reached the new one. When a replica holds such a row (from an earlier epoch) and the current primary doesn't list it, the row is kept, marked orphaned, and never used (the integration reports "not configured", and the message says to enter the secret again on the current primary). Nothing is deleted by absence. The one exception is a heal: a replica that has lost its key drops an orphan it can't decrypt, and the audit record `secrets.heal` names it (a readable orphan refuses the heal).
- **Shadows.** A row a cluster row displaces is kept in a shadow table, one slot per name and origin, and never used. A standalone node's own row (`local`) and an older cluster copy (or a deletion that a later live write displaced) each have their slot, so a stale copy never replaces a local one. A local shadow comes back when the cluster's rows are purged; the purge drops the cluster copies. Shadows are encrypted like rows: rotation and the start-up re-encryption cover them, and no backup holds them.
- **Reverse heal.** A primary whose data-directory key went missing (its rows are all the cluster's) takes its rows back from a replica that holds every one of them at the same stamp, and refuses a partial answer. A replica answers it only for the primary of the highest epoch, since a replica's registry lists only itself.
- **Deletions and conflicts.** A newer primary that lists a deleted name as live, with a stamp older than the deletion, is a value the deletion superseded: the replica keeps the deletion, reports the name as a conflict and audits it as `secret.conflict`. A listing stamped after the deletion is a later write (possibly a re-creation in a later epoch), and it replaces the deletion.
- **Emergency primary.** Its answer is marked `authoritative: false`. A replica fills missing or older cluster rows from it by stamp and changes nothing else; the emergency primary's own sync pass hands nothing over and refills nothing (ADR-903 section 4).
- **Joining.** A joining node offers its rows once per primary epoch. Each name the primary takes is audited as `secret.adopt`. A name the cluster holds (live or deleted), or a row it can't accept, is a conflict, audited as `secret.adopt_conflict`.
- **Removal.** A member the cluster removes purges the cluster's rows, and its own shadowed rows come back. The purge is audited as `secrets.purge`.

Only `secrets.fetch` and `secrets.adopt` carry values, and only over the cluster channel: between full members, in memory. Nothing is written to a blob, a file or a log line.

## Rotation

**The data-directory key** (`secrets.key`): stop TelltaleDNS, then

```sh
telltale secrets rotate-key -c /etc/telltale/telltale.toml
```

It writes the new key to `secrets.key.new`, re-encrypts every stored secret under it in one transaction, truncates the write-ahead log (so no ciphertext under the old key is left in `state.db` or its WAL), and renames the new key over `secrets.key`. If it's interrupted, the next start finishes it (the re-encryption had committed) or drops the unused new key (it hadn't). It refuses while the node runs, and when the data directory's lock can't be taken at all (whether the node runs is then unknown).

**A key from the environment or a file:** put the new key in `TELLTALE_SECRETS_KEY` (or the file), put the old one in `TELLTALE_SECRETS_PREVIOUS_KEY` (or `[node] secrets_previous_key_file`), and restart. The node re-encrypts every secret under the new key at start, in one transaction, and logs that the previous key can be removed. Then remove it, and the setting (a `secrets_previous_key_file` that no longer exists is only a warning).

## Status

```sh
telltale secrets status -c /etc/telltale/telltale.toml
```

shows the store's state, the key's source and `key_id`, each stored secret (without its value) and whether this node can read it, and every credential field of the configuration with its source and whether it's readable here (files are opened, not read). It exits 1 while the store is locked. It changes nothing, so it's safe beside a running node or a `rotate-key`: it never makes a key or a database, never finishes or drops a leftover `secrets.key.new` (it says one is there), and never re-encrypts (secrets under the previous key are counted as readable, and the next start re-encrypts them). The metric `telltale_secrets{state}` counts the stored secrets that are `readable`, `unreadable` (encrypted with a key this node doesn't have) or `corrupt`.

## Recovery

The store is **locked** when the configured key can't be read or isn't a key, when `secrets.key` is missing while secrets are stored, or when no stored secret decrypts with the key. While it's locked:

- secret writes are refused (503 `secrets_locked`), and so is an `Idempotency-Key` write that sets a credential while the key itself can't be read (a key that's there but opens none of the stored secrets still keys the retry records);
- integrations that name a stored secret report "not configured: secret `<name>` can't be read on this node (...)";
- health is **degraded** with `secrets_locked`, and the log says why;
- DNS, `/readyz`, file-based credentials and everything else keep working;
- the node tries again every 30 seconds, so fixing the key unlocks it without a restart.

What to do:

| Situation | Fix |
|---|---|
| `secrets_key_file` not mounted yet, or unreadable | Mount it (or fix its permissions); the node picks it up within 30 seconds. |
| `secrets.key` deleted or lost | Put the saved copy back. TelltaleDNS never makes a new key while secrets are stored, so nothing is overwritten. |
| The wrong key is configured | Configure the right one; or, if the old key is known, give it as the previous key and the node re-encrypts under the new one. |
| The key is gone for good | The stored secrets can't be recovered. A cluster member whose secrets all came from the primary drops them and makes a new key by itself, to receive them again; it drops the orphans it can't read too, and names them in the audit record `secrets.heal`. A primary in that state takes them back from a replica that holds every one of them at the same stamp (its store stays locked until one does). Elsewhere the store stays locked while it holds secrets nothing can read (it never discards them on its own); file-based credentials keep working meanwhile. Keep a copy of the key so this never happens. |
| The key is gone for good, and the node holds a **local shadow** (the value it had before it joined a cluster, displaced by the cluster's copy) | A heal never drops a local value, so it stays locked until the shadow is removed by hand. The local value can't be read without the lost key, so nothing is recovered by keeping it. Stop TelltaleDNS, copy `state.db` (with its `-wal` file) aside, then run `DELETE FROM secrets_shadow WHERE origin = 'local';` against `state.db` with any SQLite client, and start it again. Then the node heals as usual: it drops the rows it can't read and fetches the cluster's secrets again (audited as `secrets.heal`). The deletion itself isn't audited, so note it in your own records. Enter the local secret again if it is still needed. |
| One secret `unreadable` or `corrupt` | Set it again; nothing else is affected. |
| Data directory not kept (Helm `persistence.enabled: false`) | Health says `secrets_ephemeral` while secrets are stored: they're lost at every restart. Turn persistence on, or use files. |

**Backups** never copy the secrets table or the key. With a passphrase (`telltale backup create --secrets-passphrase-file F`, or the passphrase in Settings → System → Backup) the secrets are encrypted into the backup under a key made from it (Argon2id, then ChaCha20-Poly1305) and a restore (`--secrets-passphrase-file`) stores them under the new node's own key, taken from `-c` and the environment as the server reads it. Without a passphrase the command and the page say how many were left out, and after a restore you set them again (or keep using files). Making a backup with secrets through the API needs a sign-in from the last 10 minutes, is audited as `backup.create {secretsIncluded, count}`, and raises the alert `secrets_exported`. Details: [docs/running.md](running.md#stored-secrets-in-a-backup).
