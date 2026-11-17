//! REQ: API-015, OPS-014, CLU-010 (ADR-167 §4) — the server side of `/api/v1/secrets`: status
//! reads (metadata only), and writes on the node that owns the set: a standalone node, or the
//! cluster's primary. A replica forwards a write over the cluster channel as its own RPC kind,
//! `secret.put` / `secret.delete` (not a variant of `api.write`), so a primary too old to know it
//! refuses it by kind instead of misreading it.
//!
//! The rules, checked where the write is applied (so again on the primary for a forwarded one):
//! - admins only, never an agent token, and never a write that arrived without a role;
//! - the name, kind and value rules (ADR-167 §2), at most 128 secrets, and a webhook secret of at
//!   least 16 characters;
//! - 409 `set_by_file` for the name the UI would give a credential the configuration files set;
//! - `If-Match` against the secrets head (412);
//! - on a cluster, only on a primary whose lease holds, stamped in its epoch under the lock role
//!   changes take; an emergency primary refuses (409). A configuration managed in Git, a pin and
//!   a staged rollout don't: secrets aren't configuration versions;
//! - a delete is refused (409 `secret_in_use`) while any field names the secret on any full
//!   member, and while a full member's references can't be read, unless `?force=true`.
//!
//! Nothing here touches the query path (CLU-004): store reads and writes run on blocking threads.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use telltale_api::auth::{Actor, Role};
use telltale_api::problem::{Code, Problem};
use telltale_api::secrets_api::{
    CredentialField, SecretChange, SecretMeta, SecretNode, SecretOp, SecretStamp, SecretText,
    SecretUse, SecretWrite, SecretsHead, SecretsStatus, SecretsStore,
};
use telltale_cluster::net::{Cluster, NotPrimary};

use crate::http::Sources;
use crate::secrets::store::{MAX_SECRETS, RowHealth, StoreError, StoreState};
use crate::secrets::value::{Kind, SecretValue, ValueError};

/// The RPC kinds of a forwarded secret write. An older primary answers "unknown call".
pub(crate) const KIND_PUT: &str = "secret.put";
pub(crate) const KIND_DELETE: &str = "secret.delete";
/// A write validates, encrypts and stores on the primary before answering.
const DEADLINE: Duration = Duration::from_secs(10);
/// How long a delete waits for a member's references.
const REFS_DEADLINE: Duration = Duration::from_secs(2);
/// The shortest webhook secret (ADR-167 §2).
const MIN_WEBHOOK: usize = 16;

/// Entry kinds whose sections never leave their node (`telltale_config::shared::NODE_LOCAL`):
/// OIDC providers and sinks (`auth`, `telemetry`), OTLP, and the Git source (`cluster`).
const NODE_LOCAL_KINDS: &[&str] = &["oidc_provider", "sink", "otlp", "git"];

/// This node's name as the Cluster page shows it (a pod's name, its site, or its ID), or the
/// node's name when it isn't in a cluster.
pub(crate) fn label(src: &Sources) -> String {
    if let Some(c) = &src.cluster {
        let pod = c.local_state().pod;
        if !pod.is_empty() {
            return pod;
        }
        let m = &c.identity.meta;
        return if m.site.is_empty() {
            m.node_id.clone()
        } else {
            m.site.clone()
        };
    }
    let n = crate::http::node_name(&src.config.load());
    if n.is_empty() { "this node".into() } else { n }
}

/// REQ: API-015 — the references this node's configuration makes to stored secrets, with the
/// secret each names; those in node-local sections name this node (in a cluster).
fn ref_names(src: &Sources) -> Vec<(String, SecretUse)> {
    let cfg = src.config.load();
    let me = src.cluster.as_ref().map(|_| label(src));
    telltale_config::secret_refs::references(&cfg)
        .into_iter()
        .map(|r| {
            let node = me.clone().filter(|_| NODE_LOCAL_KINDS.contains(&r.kind));
            (
                r.name,
                SecretUse {
                    kind: r.kind.to_owned(),
                    name: r.entry,
                    field: r.field,
                    source: "stored".into(),
                    node,
                },
            )
        })
        .collect()
}

/// REQ: API-015 — the references this node's configuration makes, with the secret each names
/// (what a delete on the primary asks every member for).
pub(crate) fn refs(src: &Sources) -> Vec<(String, SecretUse)> {
    ref_names(src)
}

fn hex(b: &[u8]) -> String {
    crate::secrets::hex(b)
}

fn head(src: &Sources) -> SecretsHead {
    let (stamp, digest) = src.secrets.head();
    let digest = hex(&digest);
    SecretsHead {
        epoch: stamp.epoch,
        seq: stamp.seq,
        etag: SecretsHead::etag_of(stamp.epoch, stamp.seq, &digest),
        digest,
    }
}

fn rfc3339(s: u64) -> String {
    telltale_api::time::format_us(s.saturating_mul(1_000_000))
}

/// REQ: API-015 (ADR-167 §4) — this node's view: its store, its rows (never a value), who uses
/// each, and its credential fields. Loads the store first (a blocking thread).
pub(crate) fn status(src: &Sources) -> SecretsStatus {
    let _ = src.secrets.keys();
    let me = label(src);
    let st = src.secrets.status();
    let uses = ref_names(src);
    let mut items: Vec<SecretMeta> = st
        .secrets
        .iter()
        .filter(|s| !s.deleted)
        .map(|s| SecretMeta {
            name: s.name.clone(),
            kind: s.kind.clone(),
            set: true,
            stamp: SecretStamp {
                epoch: s.stamp.epoch,
                seq: s.stamp.seq,
            },
            updated: Some(rfc3339(s.updated)),
            updated_by: Some(s.updated_by.clone()),
            origin: Some(s.origin.clone()),
            health: Some(s.health.as_str().to_owned()),
            used_by: uses
                .iter()
                .filter(|(n, _)| *n == s.name)
                .map(|(_, u)| u.clone())
                .collect(),
            nodes: vec![SecretNode {
                node: me.clone(),
                applied: true,
                unreadable: s.health != RowHealth::Readable,
            }],
        })
        .collect();
    // Names a reference uses that aren't stored: `set: false`, so the UI can offer to set them.
    for (n, u) in &uses {
        if items.iter().any(|i| i.name == *n && i.set) {
            continue;
        }
        match items.iter_mut().find(|i| i.name == *n) {
            Some(i) => {
                if !i.used_by.contains(u) {
                    i.used_by.push(u.clone());
                }
            }
            None => items.push(SecretMeta {
                name: n.clone(),
                kind: "text".into(),
                set: false,
                stamp: SecretStamp::default(),
                updated: None,
                updated_by: None,
                origin: None,
                health: None,
                used_by: vec![u.clone()],
                nodes: Vec::new(),
            }),
        }
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    SecretsStatus {
        stale: false,
        head: head(src),
        store: SecretsStore {
            node: me.clone(),
            state: st.state.as_str().to_owned(),
            reason: st.reason.clone(),
            key_source: st.key_source.clone(),
            key_id: st.key_id.clone(),
            previous_key_id: st.previous_key_id.clone(),
            data_ephemeral: st.data_ephemeral,
        },
        items,
        credentials: credentials(src, &me),
    }
}

/// This node's credential fields, as status reads show them.
fn credentials(src: &Sources, me: &str) -> Vec<CredentialField> {
    let cfg = src.config.load();
    crate::secrets::credential::fields(&cfg, Some(&src.secrets))
        .into_iter()
        .map(|f| CredentialField {
            kind: f.kind.to_owned(),
            entry: f.entry,
            field: f.field,
            source: f.source.as_str().to_owned(),
            at: f.at,
            readable: f.readable.is_ok(),
            reason: f.readable.err(),
            node: me.to_owned(),
        })
        .collect()
}

/// REQ: API-015, CLU-002 — a replica's answer: the primary's list and head, with this node's
/// store, credential fields, node-local references and its own copy of each row.
pub(crate) fn merge_with_primary(primary: SecretsStatus, local: SecretsStatus) -> SecretsStatus {
    let mut out = primary;
    for li in local.items {
        let mine: Vec<SecretUse> = li
            .used_by
            .into_iter()
            .filter(|u| u.node.is_some())
            .collect();
        match out.items.iter_mut().find(|i| i.name == li.name) {
            Some(i) => {
                for u in mine {
                    if !i.used_by.contains(&u) {
                        i.used_by.push(u);
                    }
                }
                for n in li.nodes {
                    if !i.nodes.iter().any(|x| x.node == n.node) {
                        i.nodes.push(SecretNode {
                            applied: li.stamp == i.stamp,
                            ..n
                        });
                    }
                }
            }
            // A node-local reference to a name the primary doesn't store.
            None if !mine.is_empty() && !li.set => out.items.push(SecretMeta {
                used_by: mine,
                ..li
            }),
            None => {}
        }
    }
    out.items.sort_by(|a, b| a.name.cmp(&b.name));
    out.store = local.store;
    out.credentials = local.credentials;
    out.stale = false;
    out
}

/// The name the UI gives a credential field's secret: `<kind>.<entry>.<field>`, lowercased, with
/// anything a name can't hold as `-`.
fn ui_name(kind: &str, entry: &str, field: &str) -> String {
    format!("{kind}.{entry}.{}", field.replace(':', "."))
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// REQ: OPS-014 (ADR-167 §2 rule 1, decision 4) — the configuration files set this credential:
/// the secret the UI would store for it is refused, since it would never be used.
fn set_by_file(src: &Sources, name: &str) -> Option<Problem> {
    let cfg = src.file_config.load();
    let hit = crate::secrets::credential::fields(&cfg, None)
        .into_iter()
        .filter(|f| {
            matches!(
                f.source,
                crate::secrets::Source::Inline | crate::secrets::Source::File
            )
        })
        .find(|f| ui_name(f.kind, &f.entry, &f.field) == name)?;
    let at = hit
        .at
        .as_deref()
        .map_or_else(|| "inline".to_owned(), |p| format!("`{p}`"));
    Some(
        Problem::new(
            Code::SetByFile,
            format!(
                "the configuration files set {} `{}`'s {} ({at}), and they win: a stored secret `{name}` would never be used",
                hit.kind, hit.entry, hit.field
            ),
        )
        .hint("Change it in the configuration files, or remove it there first and then store it here."),
    )
}

/// REQ: API-015 — the refusals that don't depend on the store's content.
fn refuse_role(w: &SecretWrite) -> Option<Problem> {
    if let Some(a) = &w.agent {
        return Some(Problem::new(
            Code::AgentNotAllowed,
            format!("agent token `{a}` can't set or clear stored secrets, whatever its scopes"),
        ));
    }
    match w.role {
        Some(Role::Admin) => None,
        Some(r) => Some(Problem::new(
            Code::Forbidden,
            format!(
                "setting or clearing a stored secret needs the admin role; you have {}",
                r.as_str()
            ),
        )),
        None => Some(Problem::new(
            Code::UpgradeRequired,
            "the node this came through didn't say who made the change",
        )),
    }
}

fn not_primary(n: NotPrimary) -> Problem {
    match n {
        NotPrimary::Replica => Problem::new(Code::Conflict, "this node isn't the primary any more")
            .hint("Retry: the entry node sends it to the current primary."),
        NotPrimary::Emergency => Problem::new(
            Code::Conflict,
            "this node is an emergency primary: it keeps the cluster running but changes nothing, stored secrets included",
        )
        .hint("Set the secret once a Git-managed node is primary again (the Cluster page says when)."),
        NotPrimary::NoLease => Problem::new(
            Code::Conflict,
            "this primary can't reach a majority of voters, so it isn't taking changes",
        )
        .hint("DNS keeps answering. Changes resume when a majority of voters is reachable again; see the Cluster page."),
    }
}

/// What a delete checks besides this node's own references: every other full member's.
#[derive(Debug, Default)]
pub(crate) struct PeerRefs {
    /// `(node, its references: (secret, field))`.
    pub(crate) known: Vec<(String, Vec<(String, SecretUse)>)>,
    /// Full members whose references couldn't be read (offline, or too old to say).
    pub(crate) unknown: Vec<String>,
}

/// REQ: API-015 (ADR-167 §4, §6) — asks every other full member (the registry's members that are
/// neither ephemeral nor witnesses) for its references, each within 2 s.
pub(crate) async fn peer_refs(cluster: &Cluster) -> PeerRefs {
    let me = cluster.identity.meta.node_id.clone();
    let members = cluster.members();
    let reachable = cluster.reachable_peers();
    let mut out = PeerRefs::default();
    for n in cluster.identity.registry() {
        if n.ephemeral || n.witness || n.node_id == me {
            continue;
        }
        // As the Cluster page names it: its site (live, or as registered), else its ID.
        let name = members
            .iter()
            .find(|m| m.node_id == n.node_id)
            .map(|m| m.site.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| Some(n.site.clone()).filter(|s| !s.is_empty()))
            .unwrap_or_else(|| n.node_id.clone());
        if !reachable.contains(&n.node_id) {
            out.unknown.push(name);
            continue;
        }
        match crate::federated::peer_secret_refs(cluster, &n.node_id, REFS_DEADLINE).await {
            // Node-local references name their node; shared ones are the cluster's.
            Ok(r) => out.known.push((name, r)),
            Err(_) => out.unknown.push(name),
        }
    }
    out
}

/// The references to `name`, as `kind entry.field (node)` lines.
fn describe(uses: &[SecretUse]) -> String {
    uses.iter()
        .map(|u| match &u.node {
            Some(n) => format!("{} `{}` {} (on {n})", u.kind, u.name, u.field),
            None => format!("{} `{}` {}", u.kind, u.name, u.field),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn invalid(e: ValueError) -> Problem {
    Problem::invalid(e.to_string())
}

/// REQ: API-015 — applies a write on this node (standalone, or the primary). `peers`: the other
/// members' references, for a delete in a cluster (read before, outside any lock).
#[allow(clippy::too_many_lines)] // the rules in order, then the change
pub(crate) fn apply(
    src: &Sources,
    w: SecretWrite,
    peers: &PeerRefs,
) -> Result<SecretChange, Problem> {
    static WRITES: std::sync::Mutex<()> = std::sync::Mutex::new(());
    if let Some(p) = refuse_role(&w) {
        return Err(p);
    }
    let name = w.name.trim().to_owned();
    if !telltale_config::secret_refs::valid_name(&name) {
        return Err(invalid(ValueError::Name));
    }
    // REQ: CLU-015 (ADR-167 §4) — only a primary whose lease holds (dry runs too); a GitOps
    // authority, a pin and a rollout don't matter: secrets aren't configuration versions.
    if let Some(c) = &src.cluster {
        c.as_primary(|_| ()).map_err(not_primary)?;
    }
    // One secret write at a time, so `If-Match` and the in-use check hold until the change is
    // made (taken before the role-change lock inside `as_primary`, never after it).
    let _one = WRITES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Load the store (and see it locked) before judging anything else.
    let _ = src.secrets.keys();
    let st = src.secrets.status();
    match st.state {
        StoreState::Locked | StoreState::Starting => {
            return Err(StoreError::Locked(st.reason.unwrap_or_else(|| "no key".into())).problem());
        }
        StoreState::Ephemeral => return Err(StoreError::Ephemeral.problem()),
        StoreState::Ready => {}
    }
    let current = head(src);
    if let Some(e) = &w.expect
        && *e != current.etag
    {
        return Err(Problem::new(
            Code::VersionConflict,
            format!(
                "the stored secrets changed since `{e}` (now `{}`)",
                current.etag
            ),
        )
        .hint("Read GET /api/v1/secrets again and retry with its ETag."));
    }
    let existing = st.secrets.iter().find(|s| s.name == name && !s.deleted);
    let mine: Vec<SecretUse> = ref_names(src)
        .into_iter()
        .filter(|(n, _)| *n == name)
        .map(|(_, u)| u)
        .collect();
    let mut used_by = mine;
    for (_, r) in &peers.known {
        for (n, u) in r {
            if *n == name && !used_by.contains(u) {
                used_by.push(u.clone());
            }
        }
    }
    let now = crate::pipeline::unix_now();
    let origin = if src.cluster.is_some() {
        "cluster"
    } else {
        "local"
    };
    let mut warnings = Vec::new();
    match w.op {
        SecretOp::Put { kind, value } => {
            let kind = Kind::parse(kind.trim()).map_err(invalid)?;
            let value = SecretValue::new(kind, value.into_inner()).map_err(invalid)?;
            if let Some(p) = set_by_file(src, &name) {
                return Err(p);
            }
            if used_by.iter().any(|u| u.field == "webhook_secret_ref")
                && value.expose().chars().count() < MIN_WEBHOOK
            {
                return Err(Problem::invalid(format!(
                    "`{name}` is the Git source's webhook secret: it needs at least {MIN_WEBHOOK} characters"
                ))
                .hint("Use a long random value, and the same in the Git host's webhook."));
            }
            let live = st.secrets.iter().filter(|s| !s.deleted).count();
            if existing.is_none() && live >= MAX_SECRETS {
                return Err(StoreError::Full.problem());
            }
            if used_by.is_empty() {
                warnings.push(format!(
                    "no field names `{name}` yet: set an entry's `*_ref` to it to use it"
                ));
            }
            let would_replace = existing.is_some();
            if w.dry_run {
                return Ok(SecretChange {
                    applied: false,
                    dry_run: true,
                    would_create: !would_replace,
                    would_replace,
                    would_delete: false,
                    secret: meta_of_existing(existing, &name, kind.as_str(), &used_by),
                    used_by,
                    head: current,
                    warnings,
                });
            }
            let store = |epoch: u64| {
                src.secrets
                    .put(&name, kind, &value, epoch, &w.by, origin, now)
            };
            let info = match &src.cluster {
                Some(c) => c.as_primary(store).map_err(not_primary)?,
                None => store(0),
            }
            .map_err(|e| e.problem())?;
            drop(value);
            tracing::info!(name = %name, stamp = ?info.stamp, "stored secret set");
            Ok(SecretChange {
                applied: true,
                dry_run: false,
                would_create: !would_replace,
                would_replace,
                would_delete: false,
                secret: meta_of(&info, &label(src), &used_by),
                used_by,
                head: head(src),
                warnings,
            })
        }
        SecretOp::Delete { force } => {
            let Some(old) = existing else {
                return Err(
                    Problem::not_found(format!("no secret named `{name}` is stored"))
                        .hint("GET /api/v1/secrets lists them."),
                );
            };
            if !used_by.is_empty() {
                return Err(Problem::new(
                    Code::SecretInUse,
                    format!("`{name}` is still used by {}", describe(&used_by)),
                )
                .hint("Point those fields at another secret (or a file), or remove them, then delete it."));
            }
            if !peers.unknown.is_empty() && !force {
                return Err(Problem::new(
                    Code::SecretInUse,
                    format!(
                        "these members' references to stored secrets can't be read now: {} (offline, or too old to say)",
                        peers.unknown.join(", ")
                    ),
                )
                .hint("Bring them back first, or repeat with ?force=true if none of them names this secret."));
            }
            if !peers.unknown.is_empty() {
                warnings.push(format!(
                    "deleted without knowing the references of: {}",
                    peers.unknown.join(", ")
                ));
            }
            let kind = old.kind.clone();
            if w.dry_run {
                return Ok(SecretChange {
                    applied: false,
                    dry_run: true,
                    would_create: false,
                    would_replace: false,
                    would_delete: true,
                    secret: meta_of_existing(Some(old), &name, &kind, &used_by),
                    used_by,
                    head: current,
                    warnings,
                });
            }
            let store = |epoch: u64| src.secrets.delete(&name, epoch, &w.by, now);
            let info = match &src.cluster {
                Some(c) => c.as_primary(store).map_err(not_primary)?,
                None => store(0),
            }
            .map_err(|e| e.problem())?
            .ok_or_else(|| Problem::not_found(format!("no secret named `{name}` is stored")))?;
            tracing::info!(name = %name, stamp = ?info.stamp, "stored secret deleted");
            Ok(SecretChange {
                applied: true,
                dry_run: false,
                would_create: false,
                would_replace: false,
                would_delete: true,
                secret: meta_of(&info, &label(src), &used_by),
                used_by,
                head: head(src),
                warnings,
            })
        }
    }
}

fn meta_of(
    info: &crate::secrets::store::SecretInfo,
    node: &str,
    used_by: &[SecretUse],
) -> SecretMeta {
    SecretMeta {
        name: info.name.clone(),
        kind: info.kind.clone(),
        set: !info.deleted,
        stamp: SecretStamp {
            epoch: info.stamp.epoch,
            seq: info.stamp.seq,
        },
        updated: Some(rfc3339(info.updated)),
        updated_by: Some(info.updated_by.clone()),
        origin: Some(info.origin.clone()),
        health: (!info.deleted).then(|| info.health.as_str().to_owned()),
        used_by: used_by.to_vec(),
        nodes: if info.deleted {
            Vec::new()
        } else {
            vec![SecretNode {
                node: node.to_owned(),
                applied: true,
                unreadable: info.health != RowHealth::Readable,
            }]
        },
    }
}

fn meta_of_existing(
    existing: Option<&crate::secrets::store::SecretInfo>,
    name: &str,
    kind: &str,
    used_by: &[SecretUse],
) -> SecretMeta {
    match existing {
        Some(i) => SecretMeta {
            nodes: Vec::new(),
            ..meta_of(i, "", used_by)
        },
        None => SecretMeta {
            name: name.to_owned(),
            kind: kind.to_owned(),
            set: false,
            stamp: SecretStamp::default(),
            updated: None,
            updated_by: None,
            origin: None,
            health: None,
            used_by: used_by.to_vec(),
            nodes: Vec::new(),
        },
    }
}

/// REQ: API-015 — a write applied here: the other members' references read first (a delete in a
/// cluster), then the rules and the change on a blocking thread.
pub(crate) async fn write_here(src: Arc<Sources>, w: SecretWrite) -> Result<SecretChange, Problem> {
    let peers = match (&src.cluster, &w.op) {
        (Some(c), SecretOp::Delete { .. }) if c.is_primary() => peer_refs(c).await,
        _ => PeerRefs::default(),
    };
    tokio::task::spawn_blocking(move || apply(&src, w, &peers))
        .await
        .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))))
}

/// REQ: AGT-003 (ADR-167 §4) — an `Idempotency-Key` record's request: the request line, then the
/// value's keyed BLAKE3 under the node key's idempotency subkey (never the value).
pub(crate) fn idempotency(
    src: &Sources,
    request: &str,
    value: Option<&SecretText>,
) -> Result<Vec<u8>, Problem> {
    let Some(v) = value else {
        return Ok(request.as_bytes().to_vec());
    };
    let keys = src
        .secrets
        .keys()
        .map_err(|e| StoreError::Locked(e).problem())?;
    let digest = keys
        .current
        .idempotency_digest(v.expose().trim().as_bytes());
    Ok(format!("{request} {digest}").into_bytes())
}

/// A secret write as it crosses the cluster channel (to the primary).
#[derive(Serialize)]
struct ForwardOut<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    /// The value, for the primary to encrypt under its own key. The channel is mTLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
    dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expect: Option<&'a str>,
    force: bool,
    by: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<Role>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<&'a str>,
}

/// The same, received. Its `Debug` never shows the value.
#[derive(Debug, Deserialize)]
struct ForwardIn {
    name: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    value: Option<SecretText>,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    expect: Option<String>,
    #[serde(default)]
    force: bool,
    by: String,
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    agent: Option<String>,
}

/// REQ: API-015, CLU-010 (ADR-167 §4) — a replica sends the write to the primary as
/// `secret.put` / `secret.delete`, logging only the operation and the name. With no primary
/// reachable the answer is 409; a primary that doesn't know the kind (older than this version)
/// gives 409 `upgrade_required`.
pub(crate) async fn forward(
    cluster: Arc<Cluster>,
    w: SecretWrite,
) -> Result<SecretChange, Problem> {
    let Some(primary) = cluster.reachable_primary() else {
        return Err(Problem::new(
            Code::Conflict,
            "this node is a cluster replica and can't reach the primary, which keeps the stored secrets",
        )
        .hint("Retry when the primary is back, or set it on the primary; DNS keeps working meanwhile."));
    };
    let (kind_rpc, op) = match &w.op {
        SecretOp::Put { .. } => (KIND_PUT, "put"),
        SecretOp::Delete { .. } => (KIND_DELETE, "delete"),
    };
    let (kind, value, force) = match &w.op {
        SecretOp::Put { kind, value } => (Some(kind.as_str()), Some(value.expose()), false),
        SecretOp::Delete { force } => (None, None, *force),
    };
    let out = ForwardOut {
        name: &w.name,
        kind,
        value,
        dry_run: w.dry_run,
        expect: w.expect.as_deref(),
        force,
        by: &w.by,
        role: w.role,
        agent: w.agent.as_deref(),
    };
    let body = zeroize::Zeroizing::new(
        serde_json::to_vec(&out).map_err(|e| Problem::internal(e.to_string()))?,
    );
    tracing::debug!(%primary, op, name = %w.name, "forwarding a secret write to the primary");
    let reply = cluster
        .call(&primary, kind_rpc, body.to_vec(), DEADLINE)
        .await;
    drop(body);
    match reply {
        Ok(r) => crate::forward::decode_answer(&r),
        Err(e) if e.contains("unknown call") => {
            let version = cluster
                .members()
                .into_iter()
                .find(|m| m.node_id == primary)
                .map_or_else(|| "version unknown".to_owned(), |m| m.version);
            Err(Problem::new(
                Code::UpgradeRequired,
                format!("the primary ({version}) is too old to keep stored secrets"),
            )
            .hint("Upgrade the primary first, or set the secret on a node that is primary and up to date."))
        }
        Err(e) => Err(
            Problem::unavailable(format!("the primary didn't take the change: {e}"))
                .hint("Retry; if it keeps failing, check the Cluster page."),
        ),
    }
}

/// REQ: API-015, CLU-002 — a forwarded secret write, applied here (the primary) for `peer`, and
/// audited with the user and the node it came through. Only from a full member: ephemeral
/// resolver pods and witnesses serve no UI.
pub(crate) async fn handle(
    src: Arc<Sources>,
    local: telltale_api::Shared,
    cluster: Arc<Cluster>,
    peer: String,
    kind: String,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let full = cluster
        .identity
        .registry()
        .iter()
        .any(|n| n.node_id == peer && !n.ephemeral && !n.witness);
    if !full {
        return Err("only a full member can forward secret writes".into());
    }
    let f: ForwardIn = serde_json::from_slice(&zeroize::Zeroizing::new(body))
        .map_err(|e| format!("bad secret write: {}", e.classify_text()))?;
    let op = if kind == KIND_PUT { "put" } else { "delete" };
    tracing::debug!(%peer, op, name = %f.name, "a forwarded secret write");
    if !cluster.is_primary() {
        return crate::forward::encode_answer::<SecretChange>(Err(not_primary(
            NotPrimary::Replica,
        )));
    }
    let via = cluster
        .members()
        .into_iter()
        .find(|m| m.node_id == peer)
        .map(|m| m.site)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.clone());
    let secret_op = if kind == KIND_PUT {
        let Some(value) = f.value else {
            return crate::forward::encode_answer::<SecretChange>(Err(Problem::invalid(
                "the forwarded write has no value",
            )));
        };
        SecretOp::Put {
            kind: f.kind.unwrap_or_else(|| "text".into()),
            value,
        }
    } else {
        SecretOp::Delete { force: f.force }
    };
    let by = f.by;
    let name = f.name;
    let r = local
        .secret_write(SecretWrite {
            name: name.clone(),
            op: secret_op,
            dry_run: f.dry_run,
            expect: f.expect,
            by: format!("{by} via {via}"),
            role: f.role,
            agent: f.agent,
        })
        .await;
    if let (Ok(c), Some(auth)) = (&r, src.auth.get())
        && c.applied
    {
        let actor = Actor {
            name: format!("{by} via {via}"),
            kind: "cluster",
            remote: Some(format!("node {peer}")),
            reason: None,
        };
        auth.record(
            &actor,
            &format!("secret.{op}"),
            &name,
            &telltale_api::secrets_api::audit_detail(c),
        );
    }
    crate::forward::encode_answer(r)
}

/// The problem's text without the input it quotes (a parser error can quote a value).
trait ClassifyText {
    fn classify_text(&self) -> String;
}

impl ClassifyText for serde_json::Error {
    fn classify_text(&self) -> String {
        format!(
            "{:?} at line {} column {}",
            self.classify(),
            self.line(),
            self.column()
        )
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    // REQ: OPS-014 — the name the UI gives a credential field's secret.
    #[test]
    fn api_015_ui_names() {
        assert_eq!(
            ui_name("router", "unifi", "api_key"),
            "router.unifi.api_key"
        );
        assert_eq!(
            ui_name("otlp", "default", "header:Api-Key"),
            "otlp.default.header.api-key"
        );
        assert_eq!(
            ui_name("alert_destination", "My Hook", "token"),
            "alert_destination.my-hook.token"
        );
    }
}
