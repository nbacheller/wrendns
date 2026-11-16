//! REQ: API-014, CLU-010 (T23.2, ADR-167 §4) — who may point a credential somewhere, and where a
//! path set through the UI or API may point.
//!
//! - **Admin only:** changing a file that holds a credential (`token_file`, `password_file`,
//!   `tls_client_key`) or a reference to a stored secret (`*_ref`); changing where an entry that
//!   holds a credential sends it (`url` and its scheme, `proxy`, `host`, `tls_server_name`,
//!   `tls_ca`, `bootstrap`); and creating, or switching to, an upstream that runs a program
//!   (`exec://`, `unix://`), or changing its program or arguments. Agents never count as admins
//!   here, whatever their scopes.
//! - **Paths** set through the API are canonicalized (symlinks followed) and may not be under
//!   `/proc`, `/sys`, `/dev`, the data directory, or any configured key, previous-key, bootstrap
//!   or TLS key file; a file holding a credential must also be under `[node] secret_file_dirs`. A
//!   stored path that breaks these rules is no longer read ([`confine`]) and is reported in its
//!   entry's `credentialIssues`. A path an override keeps from the files' entry of the same name
//!   is the files', not the API's.
//! - **Forwarded writes** carry the role; the primary checks again. A change that touches a
//!   credential, forwarded by an older node that doesn't say who made it, is refused (409
//!   `upgrade_required`).
//! - **An admin's change of where a credential goes** is audited as `credential.redirect` and
//!   raises the alert event `credential_redirected`.

use std::path::{Component, Path, PathBuf};

use serde_json::{Value, json};
use telltale_api::auth::Role;
use telltale_api::problem::{Code, Problem};
use telltale_config::credentials::{
    API_PATHS, destination_change, entry_prefix, holds_credential, program_change,
    reference_changes, url_shown,
};
use telltale_config::{Config, SafeString};

use crate::managed::{Entries, Named, Ovr};

/// Where a refused path is pointed instead, so nothing reads it: no file can exist there.
pub(crate) const REFUSED: &str = "/proc/telltale-refused";

/// The audit action of an admin's change of where a credential goes.
pub(crate) const REDIRECT_ACTION: &str = "credential.redirect";

/// The prefixes and files no API-set path may be under (with why), and where files holding a
/// credential may be.
#[derive(Debug, Clone, Default)]
pub(crate) struct PathRules {
    denied: Vec<(PathBuf, &'static str)>,
    secret_dirs: Vec<PathBuf>,
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
        }
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
        .find(|s| telltale_config::credentials::runs_program(s))
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
        rules.check(path, *credential).map_err(|why| {
            Problem::new(Code::PathNotAllowed, format!("`{field}`: {why}")).hint(if *credential {
                "Put the file in a directory listed in [node] secret_file_dirs (by default /run/secrets, /var/run/secrets or /etc/telltale/secrets), outside the data directory."
            } else {
                "Name a file outside /proc, /sys, /dev and the data directory, and not a key file."
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
                .check(path, *credential)
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

/// REQ: API-014 (T23.2, ADR-167 §4) — the stored paths the rules refuse, judged by `file`'s node
/// settings. Paths an entry keeps from the files' entry of the same name are the files'.
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
            if let Err(reason) = rules.check(path, *credential) {
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

/// REQ: API-014 (T23.2) — "stops being read": every refused path in the merged `cfg` is pointed
/// at [`REFUSED`], where nothing can be read, so the upstream, list or alert fails as with a
/// missing file. Returns the refusals.
pub(crate) fn confine(cfg: &mut Config, file: &Config, e: &Entries) -> Vec<Issue> {
    let found = issues(file, e);
    for i in &found {
        if let (Some(slot), Ok(refused)) = (
            slot(cfg, i.kind, &i.name, i.field),
            SafeString::new(format!("{REFUSED}/{}", i.field)),
        ) {
            *slot = Some(refused);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn api_014_relative_and_dotdot_paths_refused() {
        let r = PathRules::default();
        assert!(r.check("etc/x", false).is_err());
        assert!(
            r.check("/run/secrets/../../proc/self/environ", false)
                .is_err()
        );
        assert!(r.check("/etc/telltale/ca.pem", false).is_ok());
        assert!(r.check("/etc/telltale/ca.pem", true).is_err(), "no dirs");
    }
}
