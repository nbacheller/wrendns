# Stored secrets

TelltaleDNS reads a credential (a router's API key, an alert destination's token, an OIDC client secret, a sink's token, OTLP headers, the Git source's credentials) from one of three places: inline in the configuration files, a file named by a `*_file` setting, or a **stored secret** named by the matching `*_ref` setting. This page is about the third: what protects a stored secret, who holds its key, how to rotate the key, and how to recover when something goes wrong. How to use them is in [Running TelltaleDNS](running.md#stored-secrets).

## What a stored secret is

- **Write-only.** A value goes in once and never comes back out: no API, UI page, MCP tool, log line, support package or backup returns it. Status reads show its name, when and by whom it was set, and whether this node can read it.
- **Encrypted per node.** Each value is encrypted in `state.db` with ChaCha20-Poly1305 under a key that belongs to this node, with a random 96-bit nonce. The ciphertext is bound to the key's ID, the secret's kind and name, and the stamp of its last change, so a row copied over another one (or given another stamp) fails to decrypt and is reported `corrupt`.
- **Kept in memory as ciphertext.** The node decrypts a value only when an integration uses it, and wipes its own copy afterwards. That covers TelltaleDNS's own buffers; what the HTTP, TLS and protobuf libraries copy while sending a request isn't wiped.
- **The files win.** A credential set inline or by file in the configuration files is used, and the API can't replace it (409 `set_by_file`).
- **Entered by admins, over HTTPS.** Only an admin sets or clears one (`PUT`/`DELETE /api/v1/secrets/<name>`, or `telltale ctl secrets set`), never an agent token, and only over HTTPS or on the node itself, unless `[api] allow_secrets_over_http` says otherwise ([Running TelltaleDNS](running.md#setting-a-stored-secret)). The value crosses the HTTP and JSON layers on its way in, and in a cluster the mTLS channel to the primary; those copies aren't wiped either.
- **Limits.** At most 128 stored secrets, each a single line of up to 8 KiB (no line breaks, tabs or other control characters), and never the text `<redacted>`. Names are lowercase letters, digits, `.`, `_` and `-`, up to 63, starting with a letter or digit.

## Threat model

| Who | Can they read a stored secret? |
|---|---|
| Someone with a copy of `state.db` or a backup | No. `state.db` holds only ciphertext, and backups leave the secrets table out entirely. |
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
| The key is gone for good | The stored secrets can't be recovered. A cluster replica whose secrets all came from the primary drops them and makes a new key by itself, to receive them again. Elsewhere the store stays locked while it holds secrets nothing can read (it never discards them on its own); file-based credentials keep working meanwhile. Keep a copy of the key so this never happens. |
| One secret `unreadable` or `corrupt` | Set it again; nothing else is affected. |
| Data directory not kept (Helm `persistence.enabled: false`) | Health says `secrets_ephemeral` while secrets are stored: they're lost at every restart. Turn persistence on, or use files. |

**Backups** never include stored secrets or the key. After restoring a backup onto a new machine, set the secrets again (or keep using files).
