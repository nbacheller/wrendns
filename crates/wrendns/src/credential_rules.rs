//! REQ: API-014, CLU-010 (T23.2, ADR-903 §4) — who may point a credential somewhere, and where a
//! path set through the UI or API may point.
//!
//! - **Admin only:** changing a file that holds a credential (`token_file`, `password_file`,
//!   `tls_client_key`) or a reference to a stored secret (`*_ref`); changing where an entry that
//!   holds a credential sends it (`url` and its scheme, `proxy`, `host`, `tls_server_name`,
//!   `tls_ca`, `bootstrap`, `tls_insecure_skip_verify`, `spki_pins`, a destination's `type`); and
//!   creating, or switching to, an upstream that runs a program
//!   (`exec://`, `unix://`), or changing its program or arguments. Agents never count as admins
//!   here, whatever their scopes.
//! - **Paths** set through the API are canonicalized (symlinks followed) and may not be under
//!   `/proc`, `/sys`, `/dev`, the data directory, or any configured key, previous-key, bootstrap
//!   or TLS key file, nor the Kubernetes service-account directory; a file holding a credential
//!   must also be under `[node] secret_file_dirs`, and a path that isn't one may not name a
//!   credential file this node's own configuration uses (a list's `path` may not be under
//!   `secret_file_dirs` at all: its lines are shown back as rules and errors). A stored path that
//!   breaks these rules is no longer read ([`confine`]) and is reported in its entry's
//!   `credentialIssues`. A path an override keeps from the node's own files' entry of the same
//!   name is the files', not the API's.
//! - **Forwarded writes** carry the role; the primary checks again. A change that touches a
//!   credential, forwarded by an older node that doesn't say who made it, is refused (409
//!   `upgrade_required`).
//! - **An admin's change of where a credential goes** is audited as `credential.redirect` and
//!   raises the alert event `credential_redirected`.

use std::path::{Component, Path, PathBuf};

use serde_json::{Value, json};
use wrendns_api::auth::Role;
use wrendns_api::problem::{Code, Problem};
use wrendns_config::credentials::{
    API_PATHS, destination_change, entry_prefix, holds_credential, program_change,
    reference_changes, url_shown,
};
use wrendns_config::{Config, SafeString};

use crate::managed::{Entries, Named, Ovr};

/// Where a refused path is pointed instead, so nothing reads it: no file can exist there.
pub(crate) const REFUSED: &str = "/proc/wrendns-refused";

/// The audit action of an admin's change of where a credential goes.
pub(crate) const REDIRECT_ACTION: &str = "credential.redirect";

/// The prefixes and files no API-set path may be under (with why), and where files holding a
/// credential may be.
#[derive(Debug, Clone, Default)]
pub(crate) struct PathRules {
    denied: Vec<(PathBuf, &'static str)>,
    secret_dirs: Vec<PathBuf>,
    /// The credential files this node's own configuration names: no path that isn't a
    /// credential's may name one (a CA or list read from it would show its content back).
    credential_files: Vec<PathBuf>,
    /// REQ: DSC-004 (review of T25.6) - the files the node's SNMP credentials name. No other field
    /// may name one, and an SNMP credential may not name any of `credential_files`: a file naming
    /// another stored secret's file would send it as a v2c community in clear text.
    snmp_files: Vec<PathBuf>,
}

/// REQ: API-014 (review of T23.2, ADR-903 note 21) — the Kubernetes service-account token (and
/// its CA and namespace): inside the default `/var/run/secrets`, but the pod's API credential,
/// never a file an entry set through the UI or API reads, an admin's included.
const KUBERNETES_SECRETS: &[&str] = &[
    "/var/run/secrets/kubernetes.io",
    "/run/secrets/kubernetes.io",
];

/// The credential files `node`'s configuration names (its files and environment).
fn credential_files(node: &Config) -> Vec<PathBuf> {
    let mut out: Vec<&str> = Vec::new();
    for u in &node.upstream {
        out.extend(u.tls_client_key.as_deref());
    }
    for d in &node.alerts.destination {
        out.extend(d.token_file.as_deref());
        out.extend(d.password_file.as_deref());
    }
    for r in &node.router {
        out.extend(r.api_key_file.as_deref());
        out.extend(r.api_secret_file.as_deref());
        out.extend(r.password_file.as_deref());
    }
    for s in &node.telemetry.sink {
        out.extend(s.token_file.as_deref());
    }
    for p in &node.auth.oidc.provider {
        out.extend(p.client_secret_file.as_deref());
    }
    if let Some(g) = &node.cluster.git {
        out.extend(g.credentials_file.as_deref());
        out.extend(g.webhook_secret_file.as_deref());
    }
    out.into_iter()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

impl PathRules {
    /// This node's rules, from its own configuration (the node-local sections).
    pub(crate) fn of(node: &Config) -> Self {
        let mut denied: Vec<(PathBuf, &'static str)> = vec![
            (PathBuf::from("/proc"), "the kernel's process files"),
            (PathBuf::from("/sys"), "the kernel's system files"),
            (PathBuf::from("/dev"), "device files"),
        ];
        let mut add = |p: &str, why: &'static str| {
            if !p.trim().is_empty() {
                denied.push((PathBuf::from(p.trim()), why));
            }
        };
        add(
            node.node.data_dir.as_str(),
            "the data directory: the state database, keys and certificates",
        );
        add(node.node.secrets_key_file.as_str(), "the secrets key");
        add(
            node.node.secrets_previous_key_file.as_str(),
            "the previous secrets key",
        );
        if let Some(f) = &node.cluster.bootstrap_secret_file {
            add(f.as_str(), "the cluster's bootstrap secret");
        }
        for l in &node.listen {
            if let Some(t) = &l.tls {
                add(t.key.as_str(), "a listener's TLS key");
            }
        }
        if let Some(k) = node.api.tls.as_ref().and_then(|t| t.key.as_ref()) {
            add(k.as_str(), "the API's TLS key");
        }
        for k in KUBERNETES_SECRETS {
            add(k, "the Kubernetes service account's token");
        }
        let secret_dirs = node
            .node
            .secret_file_dirs
            .iter()
            .filter(|d| !d.trim().is_empty())
            .map(|d| PathBuf::from(d.as_str()))
            .collect();
        Self {
            denied,
            secret_dirs,
            credential_files: credential_files(node),
            snmp_files: node
                .discovery
                .snmp_credentials
                .iter()
                .flat_map(|c| {
                    [
                        &c.community_file,
                        &c.auth_password_file,
                        &c.priv_password_file,
                    ]
                })
                .filter_map(|f| f.as_ref())
                .map(|f| f.as_str().trim())
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
                .collect(),
        }
    }

    /// REQ: API-014 (T23.2; review: a path that isn't a credential's) — [`Self::check`] for the
    /// field `field` of an entry of `kind` ([`API_PATHS`]): a path that isn't a credential's may
    /// not name one of this node's credential files, and a list's `path` may not be under
    /// `secret_file_dirs`.
    pub(crate) fn check_field(
        &self,
        kind: &str,
        field: &str,
        path: &str,
        credential: bool,
    ) -> Result<(), String> {
        self.check(path, credential)?;
        if credential {
            return Ok(());
        }
        let real = resolve(path)?;
        if self
            .credential_files
            .iter()
            .chain(self.snmp_files.iter())
            .any(|f| forms(f).contains(&real))
        {
            return Err(format!(
                "`{path}` is a file holding a credential in this node's configuration, which `{field}` may not name"
            ));
        }
        if kind == "list"
            && field == "path"
            && let Some(d) = self
                .secret_dirs
                .iter()
                .find(|d| forms(d).iter().any(|r| real.starts_with(r)))
        {
            return Err(format!(
                "`{path}` is in `{}` ([node] secret_file_dirs, where credentials are kept), which a list's path may not name",
                d.display()
            ));
        }
        Ok(())
    }

    /// REQ: DSC-004 (review of T25.6) - the path rules for the credential files of the `discovery`
    /// section's SNMP credentials that `after` sets differently from `before`: each must pass
    /// [`Self::check`] as a credential's, and none may name another credential's file.
    pub(crate) fn check_snmp_credentials(
        &self,
        before: &Value,
        after: &Value,
    ) -> Result<(), String> {
        const FIELDS: [&str; 3] = ["community_file", "auth_password_file", "priv_password_file"];
        let list = |v: &Value| v.get("snmp_credential").and_then(Value::as_array).cloned();
        let old = list(before).unwrap_or_default();
        for cred in list(after).unwrap_or_default() {
            let name = cred.get("name");
            let was = old.iter().find(|o| o.get("name") == name);
            for f in FIELDS {
                let v = cred.get(f);
                let Some(path) = v.and_then(Value::as_str).filter(|s| !s.trim().is_empty()) else {
                    continue;
                };
                if was.and_then(|o| o.get(f)) == v {
                    continue;
                }
                self.check(path, true)?;
                let real = resolve(path)?;
                if self
                    .credential_files
                    .iter()
                    .any(|c| forms(c).contains(&real))
                {
                    return Err(format!(
                        "`{path}` is a file holding another credential in this node's configuration, which `{f}` may not name"
                    ));
                }
            }
        }
        Ok(())
    }

    /// `Ok` when `path` may be read (`credential`: the file holds one); otherwise why not.
    pub(crate) fn check(&self, path: &str, credential: bool) -> Result<(), String> {
        if path.starts_with(REFUSED) {
            return Err("a path set earlier was refused: set another one".to_owned());
        }
        let real = resolve(path)?;
        for (root, why) in &self.denied {
            if forms(root).iter().any(|r| real.starts_with(r)) {
                return Err(format!(
                    "`{path}` is in `{}` ({why}), which no path set through the UI or API may name",
                    root.display()
                ));
            }
        }
        if credential
            && !self
                .secret_dirs
                .iter()
                .any(|d| forms(d).iter().any(|r| real.starts_with(r)))
        {
            let dirs: Vec<String> = self
                .secret_dirs
                .iter()
                .map(|d| format!("`{}`", d.display()))
                .collect();
            return Err(format!(
                "`{path}` isn't in [node] secret_file_dirs ({}), where a file holding a credential set through the UI or API must be",
                if dirs.is_empty() {
                    "none set".to_owned()
                } else {
                    dirs.join(", ")
                }
            ));
        }
        Ok(())
    }
}

/// A root as written and as it resolves (`/var/run` is often `/run`).
fn forms(p: &Path) -> Vec<PathBuf> {
    let mut v = vec![p.to_path_buf()];
    if let Ok(c) = follow(p, 0)
        && c != p
    {
        v.push(c);
    }
    v
}

/// `path` with every symlink followed. A relative path, or one with `..`, is refused.
fn resolve(path: &str) -> Result<PathBuf, String> {
    let p = Path::new(path.trim());
    if !p.is_absolute() {
        return Err(format!("`{path}` must be an absolute path"));
    }
    if p.components().any(|c| c == Component::ParentDir) {
        return Err(format!("`{path}` must not contain `..`"));
    }
    follow(p, 0).map_err(|e| format!("`{path}`: {e}"))
}

/// Symlinks a path may go through, as the kernel allows.
const MAX_LINKS: u8 = 40;

/// `p` (absolute) with every symlink followed: the longest part that exists is canonicalized and
/// the rest appended; a link that leads nowhere yet (dangling) is followed by hand, so it can't
/// point into a denied place before its target exists.
fn follow(p: &Path, depth: u8) -> Result<PathBuf, String> {
    if depth > MAX_LINKS {
        return Err("too many symbolic links".to_owned());
    }
    let mut existing = p.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(c) = std::fs::canonicalize(&existing) {
            let mut out = c;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return Ok(out);
        }
        if let Ok(target) = std::fs::read_link(&existing) {
            let mut next = match existing.parent() {
                Some(parent) if target.is_relative() => parent.join(target),
                _ => target,
            };
            for r in rest.iter().rev() {
                next.push(r);
            }
            return follow(&lexical(&next), depth + 1);
        }
        match (
            existing.file_name().map(ToOwned::to_owned),
            existing.parent(),
        ) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                existing = parent.to_path_buf();
            }
            _ => return Ok(lexical(p)),
        }
    }
}

/// `p` with `.` and `..` taken out by their names (a link target's `..` steps out of the link's
/// directory).
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// One write to an entry, as the rules see it (`kind` as the API names it).
pub(crate) struct WriteCheck<'a> {
    pub(crate) kind: &'static str,
    pub(crate) name: &'a str,
    /// The entry in effect now (unredacted), if any.
    pub(crate) before: Option<&'a Value>,
    /// The files' entry of that name, if any.
    pub(crate) file: Option<&'a Value>,
    /// What is stored, with `<redacted>` already replaced; `None` deletes.
    pub(crate) after: Option<&'a Value>,
    pub(crate) role: Option<Role>,
    pub(crate) agent: Option<&'a str>,
}

fn noun(kind: &str) -> &'static str {
    match kind {
        "upstream" => "upstream",
        "alert_destination" => "alert destination",
        _ => "list",
    }
}

/// REQ: API-014, CLU-010 (T23.2) — a forwarded domain's servers become upstreams: a server that
/// runs a program (`exec://`, `unix://`) is an admin's, as with `PUT /upstreams`.
pub(crate) fn check_forward_servers(
    domain: &str,
    servers: &[String],
    role: Option<Role>,
    agent: Option<&str>,
) -> Result<(), Problem> {
    let Some(bad) = servers
        .iter()
        .find(|s| wrendns_config::credentials::runs_program(s))
    else {
        return Ok(());
    };
    match role {
        Some(Role::Admin) if agent.is_none() => Ok(()),
        None => Err(Problem::new(
            Code::UpgradeRequired,
            format!(
                "sending `{domain}` to `{bad}` runs a program on the node, and the node the change was made on is too old to say who made it"
            ),
        )
        .hint("Upgrade that node first, or make the change on the primary.")),
        Some(_) => Err(Problem::new(
            Code::Forbidden,
            format!(
                "only an admin can send `{domain}` to `{bad}`: an `exec://` or `unix://` server runs a program, or talks to a socket, on the node"
            ),
        )
        .hint("Ask an admin to make this change.")),
    }
}

/// REQ: API-014, CLU-010 (T23.2) — the credential rules for one write. `Ok(Some(detail))`: an
/// admin changes where a credential goes, to audit as [`REDIRECT_ACTION`].
pub(crate) fn check_write(c: &WriteCheck<'_>, rules: &PathRules) -> Result<Option<Value>, Problem> {
    let (Some(_), Some(after)) = (entry_prefix(c.kind), c.after) else {
        return Ok(None);
    };
    let mut admin_only: Vec<String> = reference_changes(c.kind, c.before, after)
        .into_iter()
        .map(|f| format!("`{f}` names a file or a stored secret holding a credential"))
        .collect();
    let held = c.before.is_some_and(|b| holds_credential(c.kind, b));
    let moved = c
        .before
        .and_then(|b| destination_change(b, after))
        .filter(|_| held);
    if let Some(f) = moved {
        admin_only.push(format!(
            "`{f}` changes where the entry's credential is sent"
        ));
    }
    if c.kind == "upstream" && program_change(c.before, after) {
        admin_only.push(
            "an `exec://` or `unix://` upstream runs a program, or talks to a socket, on the node"
                .to_owned(),
        );
    }
    let touches = !admin_only.is_empty() || held || holds_credential(c.kind, after);
    let Some(role) = c.role else {
        if !touches {
            return Ok(None);
        }
        return Err(Problem::new(
            Code::UpgradeRequired,
            format!(
                "this change to {} `{}` touches a credential, and the node it was made on is too old to say who made it",
                noun(c.kind),
                c.name
            ),
        )
        .hint("Upgrade that node first, or make the change on the primary."));
    };
    let admin = role == Role::Admin && c.agent.is_none();
    if !admin && !admin_only.is_empty() {
        let (who, hint) = if c.agent.is_some() {
            (
                "an agent token can't",
                "Ask an admin to make this change in the UI; agents never change where a credential goes or which file holds it.",
            )
        } else {
            (
                "the operator role can't",
                "Ask an admin to make this change.",
            )
        };
        return Err(Problem::new(
            Code::Forbidden,
            format!(
                "only an admin can make this change to {} `{}` ({who}): {}",
                noun(c.kind),
                c.name,
                admin_only.join("; ")
            ),
        )
        .hint(hint));
    }
    for (k, field, credential) in API_PATHS {
        if *k != c.kind {
            continue;
        }
        let v = after.get(*field);
        let Some(path) = v.and_then(Value::as_str).filter(|s| !s.trim().is_empty()) else {
            continue;
        };
        // Unchanged, or kept from the files' entry: not set through the API now.
        if c.before.and_then(|b| b.get(*field)) == v || c.file.and_then(|f| f.get(*field)) == v {
            continue;
        }
        rules
            .check_field(c.kind, field, path, *credential)
            .map_err(|why| {
                Problem::new(Code::PathNotAllowed, format!("`{field}`: {why}")).hint(if *credential {
                    "Put the file in a directory listed in [node] secret_file_dirs (by default /run/secrets, /var/run/secrets or /etc/wrendns/secrets), outside the data directory."
                } else {
                    "Name a file outside /proc, /sys, /dev and the data directory, and not a key or credential file (a list's file outside [node] secret_file_dirs)."
                })
            })?;
    }
    Ok(moved.map(|f| {
        let shown = |v: Option<&Value>| match v {
            Some(Value::String(s)) => Value::String(url_shown(s)),
            Some(other) => other.clone(),
            None => Value::Null,
        };
        json!({
            "kind": c.kind,
            "name": c.name,
            "field": f,
            "from": shown(c.before.and_then(|b| b.get(f))),
            "to": shown(after.get(f)),
        })
    }))
}

/// REQ: API-014 (T23.2) — a draft that a check builds and runs (`POST /checks/upstream`): its
/// paths are held to the same rules, since the check reads them.
pub(crate) fn check_draft_paths(
    kind: &str,
    draft: &Value,
    rules: &PathRules,
) -> Result<(), Problem> {
    for (k, field, credential) in API_PATHS {
        if *k != kind {
            continue;
        }
        if let Some(path) = draft
            .get(*field)
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
        {
            rules
                .check_field(kind, field, path, *credential)
                .map_err(|why| Problem::new(Code::PathNotAllowed, format!("`{field}`: {why}")))?;
        }
    }
    Ok(())
}

/// A stored path the rules refuse: it isn't read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Issue {
    pub(crate) kind: &'static str,
    pub(crate) name: String,
    pub(crate) field: &'static str,
    pub(crate) reason: String,
}

/// The slot of an [`API_PATHS`] field in the effective configuration's entry `name`.
fn slot<'a>(
    cfg: &'a mut Config,
    kind: &str,
    name: &str,
    field: &str,
) -> Option<&'a mut Option<SafeString>> {
    match kind {
        "upstream" => {
            let u = cfg.upstream.iter_mut().find(|u| u.name.as_str() == name)?;
            match field {
                "tls_ca" => Some(&mut u.tls_ca),
                "tls_client_cert" => Some(&mut u.tls_client_cert),
                "tls_client_key" => Some(&mut u.tls_client_key),
                _ => None,
            }
        }
        "alert_destination" => {
            let d = cfg
                .alerts
                .destination
                .iter_mut()
                .find(|d| d.name.as_str() == name)?;
            match field {
                "token_file" => Some(&mut d.token_file),
                "password_file" => Some(&mut d.password_file),
                "tls_ca" => Some(&mut d.tls_ca),
                _ => None,
            }
        }
        "list" => {
            let l = cfg.list.iter_mut().find(|l| l.name.as_str() == name)?;
            (field == "path").then_some(&mut l.path)
        }
        _ => None,
    }
}

/// `(kind, name, the API's definition, the files' entry of that name)` for every entry the API
/// stored of a kind with paths.
fn api_entries(file: &Config, e: &Entries) -> Vec<(&'static str, String, Value, Option<Value>)> {
    fn of<T: Named + serde::Serialize>(
        kind: &'static str,
        stored: &[(String, Ovr<T>)],
        files: &[T],
        out: &mut Vec<(&'static str, String, Value, Option<Value>)>,
    ) {
        for (name, o) in stored {
            if let Ovr::Set(t) = o {
                let file = files
                    .iter()
                    .find(|f| f.name() == name.as_str())
                    .and_then(|f| serde_json::to_value(f).ok());
                if let Ok(v) = serde_json::to_value(t) {
                    out.push((kind, name.clone(), v, file));
                }
            }
        }
    }
    let mut out = Vec::new();
    of("upstream", &e.upstreams, &file.upstream, &mut out);
    of(
        "alert_destination",
        &e.alert_destinations,
        &file.alerts.destination,
        &mut out,
    );
    of("list", &e.lists, &file.list, &mut out);
    out
}

/// REQ: API-014 (T23.2, ADR-903 §4) — the stored paths the rules refuse, judged by `file`'s node
/// settings. Paths an entry keeps from the files' entry of the same name are the files'. `file`
/// is this node's own configuration files, never a cluster version built on them (a path that
/// version carries isn't the files').
pub(crate) fn issues(file: &Config, e: &Entries) -> Vec<Issue> {
    let rules = PathRules::of(file);
    let mut out = Vec::new();
    for (kind, name, api, from_file) in api_entries(file, e) {
        for (k, field, credential) in API_PATHS {
            if *k != kind {
                continue;
            }
            let v = api.get(*field);
            let Some(path) = v.and_then(Value::as_str).filter(|s| !s.trim().is_empty()) else {
                continue;
            };
            if from_file.as_ref().and_then(|f| f.get(*field)) == v {
                continue;
            }
            if let Err(reason) = rules.check_field(kind, field, path, *credential) {
                out.push(Issue {
                    kind,
                    name: name.clone(),
                    field,
                    reason: format!("{reason}; it isn't read"),
                });
            }
        }
    }
    out
}

/// REQ: API-014 (T23.2) — "stops being read": every refused path in the merged `cfg` is taken
/// out of reach. A list's or alert destination's is pointed at [`REFUSED`], where nothing can be
/// read, so that list or alert fails as with a missing file. An upstream's is cleared instead
/// (REQ: CLU-004, review of T23.2): the router reads an upstream's TLS files when it is built,
/// and one it can't read fails the whole configuration, so the node would answer no DNS. The
/// upstream then runs without that file: the system's roots instead of the CA, no client
/// certificate (its certificate and key go together). Returns the refusals. `file` is this node's own files ([`issues`]).
pub(crate) fn confine(cfg: &mut Config, file: &Config, e: &Entries) -> Vec<Issue> {
    let found = issues(file, e);
    for i in &found {
        let refused = if i.kind == "upstream" {
            None
        } else {
            match SafeString::new(format!("{REFUSED}/{}", i.field)) {
                Ok(r) => Some(r),
                Err(_) => continue,
            }
        };
        if let Some(slot) = slot(cfg, i.kind, &i.name, i.field) {
            *slot = refused;
        }
        // A client certificate is used with its key: one without the other doesn't validate.
        if i.kind == "upstream" && i.field.starts_with("tls_client_") {
            for f in ["tls_client_cert", "tls_client_key"] {
                if let Some(slot) = slot(cfg, i.kind, &i.name, f) {
                    *slot = None;
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-004 (review of T25.6) - an SNMP credential's file must be in `secret_file_dirs`
    /// and may not name another credential's file (it would go out as a community in clear text).
    #[test]
    fn dsc_004_snmp_credential_files_follow_the_path_rules() {
        let rules = PathRules {
            denied: Vec::new(),
            secret_dirs: vec![PathBuf::from("/run/secrets")],
            credential_files: vec![PathBuf::from("/run/secrets/ntfy-token")],
            snmp_files: Vec::new(),
        };
        let before = json!({"snmp_credential": []});
        let with = |f: &str| json!({"snmp_credential": [{"name": "c", "community_file": f}]});
        assert!(
            rules
                .check_snmp_credentials(&before, &with("/run/secrets/community"))
                .is_ok()
        );
        assert!(
            rules
                .check_snmp_credentials(&before, &with("/run/secrets/ntfy-token"))
                .is_err()
        );
        assert!(
            rules
                .check_snmp_credentials(&before, &with("/etc/hostname"))
                .is_err()
        );
        // Unchanged is not re-checked.
        let kept = with("/etc/hostname");
        assert!(rules.check_snmp_credentials(&kept, &kept).is_ok());
    }

    /// Every path field the rules know has a slot to refuse it in.
    #[test]
    fn api_014_every_api_path_can_be_refused() {
        let mut cfg: Config = toml::from_str(
            r#"
[[upstream]]
name = "u"
url = "tls://9.9.9.9"
[[alerts.destination]]
name = "d"
type = "ntfy"
url = "https://ntfy.sh/t"
[[list]]
name = "l"
path = "/etc/l.txt"
"#,
        )
        .unwrap();
        for (kind, field, _) in API_PATHS {
            let name = match *kind {
                "upstream" => "u",
                "alert_destination" => "d",
                _ => "l",
            };
            assert!(
                slot(&mut cfg, kind, name, field).is_some(),
                "{kind}.{field}"
            );
        }
    }

    /// A node with `toml` (its data directory a fresh one, returned) and the API's upstream `u`.
    fn node_with_api_upstream(toml: &str, api: &str) -> (Config, Entries, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut file: Config = toml::from_str(toml).unwrap();
        file.node.data_dir = SafeString::new(dir.path().to_str().unwrap()).unwrap();
        let api = api.replace("{data}", dir.path().to_str().unwrap());
        let u: wrendns_config::Upstream = toml::from_str(&api).unwrap();
        let e = Entries {
            upstreams: vec![("u".to_owned(), Ovr::Set(u))],
            ..Entries::default()
        };
        (file, e, dir)
    }

    const NODE: &str = r#"
[[upstream]]
name = "q"
url = "udp://9.9.9.9"
[[upstream_group]]
name = "default"
members = ["q", "u"]
"#;

    /// REQ: API-014, CLU-004 (review of T23.2) — a stored upstream path the rules refuse (a
    /// client key outside `secret_file_dirs`, a CA in the data directory) is cleared, not
    /// pointed at a file that can't be read: the router still builds, so the node starts and
    /// reloads and answers DNS. Pointed at [`REFUSED`] it wouldn't.
    #[tokio::test]
    async fn api_014_refused_upstream_path_keeps_dns_answering() {
        let (file, e, _dir) = node_with_api_upstream(
            NODE,
            r#"
name = "u"
url = "tls://9.9.9.9"
tls_server_name = "dns.quad9.net"
tls_ca = "{data}/ca.pem"
tls_client_cert = "/etc/wrendns/client.pem"
tls_client_key = "/etc/wrendns/client.key"
"#,
        );
        let found = issues(&file, &e);
        let fields: Vec<&str> = found.iter().map(|i| i.field).collect();
        assert_eq!(fields, ["tls_ca", "tls_client_key"], "{found:?}");
        let cfg = crate::managed::merge(&file, &e).unwrap();
        let u = cfg
            .upstream
            .iter()
            .find(|u| u.name.as_str() == "u")
            .unwrap();
        assert_eq!(
            (&u.tls_ca, &u.tls_client_cert, &u.tls_client_key),
            (&None, &None, &None),
            "{u:?}"
        );
        assert!(
            crate::server::build_dynamic(&cfg, None).is_ok(),
            "the node starts"
        );
        // What T23.2 did first: the whole configuration failed, so no DNS at all.
        let mut old = cfg.clone();
        if let Some(u) = old.upstream.iter_mut().find(|u| u.name.as_str() == "u") {
            u.tls_ca = Some(SafeString::new(format!("{REFUSED}/tls_ca")).unwrap());
        }
        assert!(crate::server::build_dynamic(&old, None).is_err());
    }

    /// REQ: API-014 (review of T23.2) — a primary promoted from replica builds on the last
    /// cluster version (ADR-051). A path an older primary published as the API's is in that
    /// version too; it is still judged against this node's own files, not taken for the files'.
    #[test]
    fn api_014_promoted_primary_judges_published_paths() {
        let (own, e, _dir) = node_with_api_upstream(
            NODE,
            r#"
name = "u"
url = "tls://9.9.9.9"
tls_client_cert = "/etc/wrendns/client.pem"
tls_client_key = "/etc/wrendns/client.key"
"#,
        );
        // The version: the node's files plus the API's upstream as the old primary published it.
        let mut version = own.clone();
        if let Some(Ovr::Set(u)) = e.upstreams.first().map(|(_, o)| o) {
            version.upstream.push(u.clone());
        }
        let key = |c: &Config| {
            c.upstream
                .iter()
                .find(|u| u.name.as_str() == "u")
                .and_then(|u| u.tls_client_key.clone())
        };
        // Taking the version for the files would keep reading it.
        assert!(key(&crate::managed::merge(&version, &e).unwrap()).is_some());
        let cfg = crate::managed::merge_on(&version, &own, &e).unwrap();
        assert_eq!(key(&cfg), None);
        assert_eq!(issues(&own, &e).len(), 1);
    }

    /// REQ: API-014 (review of T23.2) — a path that isn't a credential's can't read one: a list
    /// can't be read from `secret_file_dirs` (its lines come back as rules and errors), a CA or
    /// list can't name a credential file this node's files use, and nothing set through the API
    /// reads the Kubernetes service-account token, an admin's credential file included.
    #[test]
    fn api_014_non_credential_paths_kept_from_secrets() {
        let secrets = tempfile::tempdir().unwrap();
        let s = secrets.path().display().to_string();
        std::fs::write(secrets.path().join("smtp"), "pw").unwrap();
        let node: Config = toml::from_str(&format!(
            r#"
[node]
secret_file_dirs = ["{s}", "/var/run/secrets"]
[[alerts.destination]]
name = "mail"
type = "webhook"
url = "https://hook.example/"
token_file = "{s}/smtp"
"#
        ))
        .unwrap();
        let r = PathRules::of(&node);
        let smtp = format!("{s}/smtp");
        assert!(r.check_field("list", "path", &smtp, false).is_err());
        let err = r
            .check_field("list", "path", &format!("{s}/other.txt"), false)
            .unwrap_err();
        assert!(err.contains("secret_file_dirs"), "{err}");
        let err = r
            .check_field("upstream", "tls_ca", &smtp, false)
            .unwrap_err();
        assert!(err.contains("holding a credential"), "{err}");
        // A CA or a client certificate may sit beside its key in a secrets directory.
        assert!(
            r.check_field("upstream", "tls_ca", &format!("{s}/ca.pem"), false)
                .is_ok()
        );
        // The credential file itself stays usable as one.
        assert!(
            r.check_field("alert_destination", "token_file", &smtp, true)
                .is_ok()
        );
        let sa = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        assert!(
            r.check_field("alert_destination", "token_file", sa, true)
                .is_err()
        );
        assert!(r.check_field("list", "path", sa, false).is_err());
        assert!(
            r.check_field("list", "path", "/etc/wrendns/allow.txt", false)
                .is_ok()
        );
    }

    #[test]
    fn api_014_relative_and_dotdot_paths_refused() {
        let r = PathRules::default();
        assert!(r.check("etc/x", false).is_err());
        assert!(
            r.check("/run/secrets/../../proc/self/environ", false)
                .is_err()
        );
        assert!(r.check("/etc/wrendns/ca.pem", false).is_ok());
        assert!(r.check("/etc/wrendns/ca.pem", true).is_err(), "no dirs");
    }
}
