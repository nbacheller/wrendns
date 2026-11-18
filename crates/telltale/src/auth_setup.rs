//! Sign-in plumbing for the server and CLI (REQ: API-003, `spec/08` §6): opens
//! `<data_dir>/state.db`, creates the bootstrap admin from deployment secrets, keeps the
//! first-run setup token in `<data_dir>/setup-token`, and ends stale sessions.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use telltale_api::auth::{Auth, Role, Settings, crypto};
use telltale_config::{Config, UserRole};
use telltale_store::state::State;
use tracing::{error, info, warn};

const SETUP_TOKEN_FILE: &str = "setup-token";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn data_dir(cfg: &Config) -> PathBuf {
    PathBuf::from(cfg.node.data_dir.as_str())
}

fn settings(cfg: &Config) -> Settings {
    let a = &cfg.auth;
    Settings {
        session_ttl_secs: u64::from(a.session_ttl_hours) * 3600,
        session_idle_secs: u64::from(a.session_idle_hours) * 3600,
        allow_insecure_basic: a.allow_insecure_basic,
        totp_required_roles: a.totp_required_roles.iter().map(|r| role(*r)).collect(),
        setup_token_file: Some(data_dir(cfg).join(SETUP_TOKEN_FILE)),
        disable_local_login: a.oidc.disable_local_login,
        admin_networks: a
            .oidc
            .break_glass_networks()
            .iter()
            .map(|c| (c.addr, c.prefix))
            .collect(),
        break_glass_default: a.oidc.allowed_admin_networks.is_none(),
        trusted_proxies: cfg
            .api
            .trusted_proxies
            .iter()
            .map(|c| (c.addr, c.prefix))
            .collect(),
    }
}

fn role(r: UserRole) -> Role {
    match r {
        UserRole::Viewer => Role::Viewer,
        UserRole::Operator => Role::Operator,
        UserRole::Admin => Role::Admin,
    }
}

/// REQ: API-004 — OIDC providers from `[auth.oidc]`, reaching them with the same HTTPS client
/// as list downloads (system resolver, Mozilla roots, no redirects, 1 MiB, 15 s).
fn oidc(
    cfg: &Config,
    store: &crate::secrets::SecretStore,
) -> io::Result<Option<telltale_api::auth::oidc::Oidc>> {
    use telltale_api::auth::oidc::{Fetch, Oidc, OidcSettings, ProviderSettings};
    let o = &cfg.auth.oidc;
    if o.provider.is_empty() {
        return Ok(None);
    }
    let mut providers = Vec::new();
    for p in &o.provider {
        // REQ: OPS-014 (ADR-903 §2) — inline, its file, or the store.
        let client_secret = crate::secrets::Credential::of(
            p.client_secret_file.as_ref(),
            p.client_secret_ref.as_ref(),
        )
        .with_inline(p.client_secret.as_ref())
        .resolve(Some(store))
        .map_err(|e| io::Error::other(format!("provider `{}`: {e}", p.id)))?
        .map(|r| r.value.expose().to_owned());
        providers.push(ProviderSettings {
            id: p.id.to_string(),
            name: if p.name.is_empty() {
                p.id.to_string()
            } else {
                p.name.to_string()
            },
            issuer: p.issuer.to_string(),
            client_id: p.client_id.to_string(),
            client_secret,
            scopes: p.scopes.iter().map(ToString::to_string).collect(),
            username_claim: p.username_claim.to_string(),
            groups_claim: p.groups_claim.to_string(),
            roles: p
                .role
                .iter()
                .map(|r| (r.group.to_string(), role(r.role)))
                .collect(),
            default_role: p.default_role.map(role),
            require_verified_email: p.require_verified_email,
        });
    }
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])
            .map_err(io::Error::other)?;
    let fetch: Fetch = Arc::new(move |req| {
        let client = client.clone();
        Box::pin(async move {
            match tokio::time::timeout(Duration::from_secs(15), client.request(req, 1 << 20)).await
            {
                Ok(Ok(r)) => Ok(r),
                Ok(Err(e)) => Err(e.message),
                Err(_) => Err("timed out".to_owned()),
            }
        })
    });
    info!(providers = providers.len(), "OIDC sign-in enabled");
    // REQ: AGT-008 (T7.4) — MCP clients sign in through one provider.
    let mcp = (!o.mcp_provider.is_empty()).then(|| telltale_api::auth::oidc::McpOAuth {
        provider: o.mcp_provider.to_string(),
        audience: if o.mcp_audience.is_empty() {
            format!("{}/mcp", o.public_url.as_str().trim_end_matches('/'))
        } else {
            o.mcp_audience.to_string()
        },
    });
    Ok(Some(Oidc::new(
        OidcSettings {
            public_url: o.public_url.to_string(),
            providers,
            mcp,
        },
        fetch,
    )))
}

fn open_state(cfg: &Config) -> io::Result<State> {
    let dir = data_dir(cfg);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("state.db");
    State::open(&path).map_err(|e| io::Error::other(format!("{}: {e}", path.display())))
}

/// Writes `token` readable by the owner only.
fn write_secret(path: &Path, token: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(token.as_bytes())?;
    f.write_all(b"\n")
}

/// Opens the auth service for the server. Blocking (Argon2 for a bootstrap password).
pub(crate) fn open(cfg: &Config, store: &crate::secrets::SecretStore) -> io::Result<Arc<Auth>> {
    let auth = Arc::new(Auth::new(Arc::new(open_state(cfg)?), settings(cfg)));
    // REQ: API-004 (ADR-944) — the break-glass default is loopback only; say so at startup.
    let o = &cfg.auth.oidc;
    if o.disable_local_login && o.allowed_admin_networks.is_none() {
        warn!(
            "[auth.oidc] disable_local_login is on and allowed_admin_networks is not set: password sign-in is allowed only from loopback (127.0.0.1, ::1). A reverse proxy on this host must be listed in [api] trusted_proxies, a Docker port publish arrives from the bridge gateway (sign in with docker exec, or set allowed_admin_networks), and an explicit list replaces this default."
        );
    }
    // A broken provider setup (say, a missing secret file) leaves password sign-in working.
    match oidc(cfg, store) {
        Ok(Some(o)) => auth.set_oidc(o),
        Ok(None) => {}
        // REQ: CLU-009 (ADR-120) — a Helm resolver pod has the chart's whole configuration but
        // not its secrets, by design: nobody signs in there (its API has no Service port), so
        // a missing secret isn't an error on it (2026-10-14 review: an error per pod start).
        Err(e) if cfg.cluster.ephemeral => {
            info!("OIDC sign-in isn't set up on this resolver pod (people sign in elsewhere): {e}");
        }
        Err(e) => error!("OIDC sign-in disabled: {e}"),
    }
    bootstrap_from_env(&auth);
    let setup = auth
        .setup_required()
        .map_err(|p| io::Error::other(p.detail))?;
    // REQ: API-003, CLU-003 (review 06 q1) — a cluster member that isn't the primary takes its
    // users from the primary (T9.1) and refuses identity changes, so it has no setup to do
    // (resolver pods used to log a working setup token each).
    let member_not_primary = telltale_cluster::node::Identity::load(&data_dir(cfg))
        .ok()
        .flatten()
        .is_some_and(|id| !id.is_primary());
    if setup && member_not_primary {
        info!("no users yet: they come from the cluster's primary once this node syncs");
    } else if setup {
        // Reuse a token from an earlier start so the one already copied keeps working.
        let file = data_dir(cfg).join(SETUP_TOKEN_FILE);
        let token = std::fs::read_to_string(&file)
            .ok()
            .map(|t| t.trim().to_owned())
            .filter(|t| t.len() >= 32)
            .unwrap_or_else(crypto::random_secret);
        if let Err(e) = write_secret(&file, &token) {
            warn!(file = %file.display(), "could not save the setup token: {e}");
        }
        auth.set_setup_token(token.clone());
        // REQ: API-003 (review 06 q1) — the token itself stays out of the log: on Kubernetes
        // logs go wherever the cluster's collector sends them.
        warn!(
            file = %file.display(),
            "no users yet: create the first admin in the web UI with the setup token; `telltale auth setup-token` prints it (or read the file)"
        );
    }
    Ok(auth)
}

/// `TELLTALE_BOOTSTRAP_ADMIN_USER` + `..._PASSWORD` or `..._PASSWORD_HASH`: the first admin
/// from a Kubernetes Secret. Ignored once any user exists.
fn bootstrap_from_env(auth: &Auth) {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let Some(user) = var("TELLTALE_BOOTSTRAP_ADMIN_USER") else {
        return;
    };
    let password = var("TELLTALE_BOOTSTRAP_ADMIN_PASSWORD");
    let hash = var("TELLTALE_BOOTSTRAP_ADMIN_PASSWORD_HASH");
    match auth.bootstrap_admin(user.trim(), password.as_deref(), hash.as_deref(), now()) {
        Ok(Some(u)) => info!(user = %u.username, "created the bootstrap admin"),
        Ok(None) => {}
        Err(p) => error!("bootstrap admin `{user}` not created: {}", p.detail),
    }
}

/// Removes audit entries older than `days`, and records the trim with its checkpoint.
fn trim_audit(auth: &Auth, days: u32) {
    let before = now().saturating_sub(u64::from(days) * 86_400);
    match auth.state().audit_trim(before) {
        Ok((0, _)) => {}
        Ok((removed, checkpoint)) => {
            let (seq, hash) = checkpoint.unwrap_or_default();
            let hex = crypto::hex(&hash);
            auth.record(
                &telltale_api::auth::Actor::system("audit retention"),
                "audit.trim",
                "audit",
                &serde_json::json!({ "removed": removed, "days": days, "checkpointSeq": seq, "checkpointHash": hex }),
            );
            info!(removed, days, "audit log: removed entries past retention");
        }
        Err(e) => warn!("audit log retention: {e}"),
    }
}

/// Ends expired and idle sessions every hour.
pub(crate) fn spawn_purge(auth: Arc<Auth>, audit_days: u32) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let a = Arc::clone(&auth);
            if let Ok(Err(p)) = tokio::task::spawn_blocking(move || a.purge_sessions(now())).await {
                warn!("purging sessions: {}", p.detail);
            }
            // REQ: API-006 (review 06 q2) — audit retention.
            if audit_days > 0 {
                let a = Arc::clone(&auth);
                let _ = tokio::task::spawn_blocking(move || trim_audit(&a, audit_days)).await;
            }
        }
    })
}

/// `telltale auth setup-token`: prints the first-run token, or says setup is done.
pub(crate) fn print_setup_token(cfg: &Config) -> io::Result<bool> {
    let state = open_state(cfg)?;
    if state
        .user_count()
        .map_err(|e| io::Error::other(e.to_string()))?
        > 0
    {
        eprintln!("setup is done: sign in with an admin account");
        return Ok(false);
    }
    let file = data_dir(cfg).join(SETUP_TOKEN_FILE);
    match std::fs::read_to_string(&file) {
        Ok(t) => {
            writeln!(io::stdout().lock(), "{}", t.trim())?;
            Ok(true)
        }
        Err(e) => {
            eprintln!(
                "no setup token yet ({}: {e}); start the server first",
                file.display()
            );
            Ok(false)
        }
    }
}

/// `telltale audit verify`: checks the hash chain (REQ: API-006). `Ok(false)` if broken.
pub(crate) fn verify_audit(cfg: &Config) -> io::Result<bool> {
    let v = open_state(cfg)?
        .audit_verify()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut out = io::stdout().lock();
    match v.first_bad {
        None => writeln!(
            out,
            "ok: {} entries, head {}",
            v.entries,
            crypto::hex(&v.head)
        )?,
        Some(seq) => writeln!(
            out,
            "BROKEN at entry {seq} of {}: the audit log was changed outside TelltaleDNS",
            v.entries
        )?,
    }
    Ok(v.first_bad.is_none())
}

/// `telltale audit list`: newest first.
pub(crate) fn list_audit(cfg: &Config, limit: usize, action: Option<&str>) -> io::Result<bool> {
    let rows = open_state(cfg)?
        .audit_page(None, limit, action, None)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut out = io::stdout().lock();
    for e in rows {
        let when = telltale_api::time::format_us(e.ts.saturating_mul(1_000_000));
        let reason = e
            .reason
            .map(|r| format!("  reason: {r}"))
            .unwrap_or_default();
        writeln!(
            out,
            "{:>6}  {when}  {} ({})  {}  {}  {}{reason}",
            e.seq, e.actor, e.actor_kind, e.action, e.target, e.detail
        )?;
    }
    Ok(true)
}
/// `telltale auth hash-password`: reads a password from stdin, prints an Argon2id PHC hash
/// for `TELLTALE_BOOTSTRAP_ADMIN_PASSWORD_HASH`.
pub(crate) fn hash_password() -> io::Result<bool> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let pw = line.trim_end_matches(['\r', '\n']);
    if let Err(p) = telltale_api::auth::valid_password(pw) {
        eprintln!("error: {}", p.detail);
        return Ok(false);
    }
    match crypto::hash_password(pw) {
        Ok(h) => {
            writeln!(io::stdout().lock(), "{h}")?;
            Ok(true)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Ok(false)
        }
    }
}

/// REQ: API-003 (ADR-972) — `telltale auth reset-password <user>`: sets a local user's password
/// on the node itself, for when nobody can sign in. Needs the node stopped: it refuses while
/// `telltale run` holds the data directory's lock, and on a cluster replica (its users come from
/// the primary). The new password comes from stdin (a pipe or a file, one line), or from a
/// terminal typed twice with echo off. The user's UI sessions end, and the reset is audited.
pub(crate) fn reset_password(cfg: &Config, username: &str) -> io::Result<bool> {
    let dir = data_dir(cfg);
    // A directory without a `state.db` is the wrong one (a mistyped `-c`), not an empty node:
    // refuse, and create nothing.
    if !dir.join("state.db").is_file() {
        eprintln!(
            "error: no TelltaleDNS state in {}: check the data directory in the config (-c)",
            dir.display()
        );
        return Ok(false);
    }
    // REQ: CLU-008 (ADR-068) — the same one-process rule as the server: a running node holds it.
    let _lock = match crate::datadir::lock(&dir, Duration::ZERO) {
        Ok(lock) => lock,
        Err(crate::datadir::LockError::Held(holder)) => {
            eprintln!(
                "error: TelltaleDNS is running on this data directory ({holder}). Stop it first: a password is reset with the node stopped"
            );
            return Ok(false);
        }
        Err(crate::datadir::LockError::Io(e)) => return Err(e),
    };
    // An identity that can't be read is refused, not taken for a primary: a replica's users are
    // overwritten by the next sync, so a reset there would be lost.
    let member_not_primary = match telltale_cluster::node::Identity::load(&dir) {
        Ok(id) => id.is_some_and(|id| !id.is_primary()),
        Err(e) => {
            eprintln!(
                "error: this node's cluster identity can't be read ({e}); the reset is refused until it can"
            );
            return Ok(false);
        }
    };
    if member_not_primary {
        eprintln!(
            "error: this node takes its users from the cluster's primary; reset the password there"
        );
        return Ok(false);
    }
    let Some(password) = read_new_password()? else {
        eprintln!(
            "error: this terminal can't hide what you type (no `stty`). Pipe the password on stdin instead: printf '%s\\n' \"$NEW_PASSWORD\" | telltale auth reset-password {username}"
        );
        return Ok(false);
    };
    if let Err(p) = telltale_api::auth::valid_password(&password) {
        eprintln!("error: {}", p.detail);
        return Ok(false);
    }
    let state = Arc::new(open_state(cfg)?);
    match reset_in(state, settings(cfg), username, &password, now()) {
        Ok(ended) => {
            writeln!(
                io::stdout().lock(),
                "password reset for {username}; {ended} sign-in session(s) ended"
            )?;
            Ok(true)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Ok(false)
        }
    }
}

/// The offline reset itself: hashes `password`, stores it for `username`, ends that user's UI
/// sessions, and records the reset in the audit log. Returns how many sessions ended.
pub(crate) fn reset_in(
    state: Arc<State>,
    settings: Settings,
    username: &str,
    password: &str,
    now: u64,
) -> Result<u64, String> {
    let auth = Auth::new(state, settings);
    let user = auth
        .state()
        .user_by_name(username)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no user named `{username}`"))?;
    let hash = crypto::hash_password(password)?;
    auth.state()
        .set_password(user.id, &hash, now)
        .map_err(|e| e.to_string())?;
    let ended = auth
        .state()
        .delete_user_sessions(user.id, None)
        .map_err(|e| e.to_string())?;
    // REQ: API-003 (ADR-972) — the entry is written before the command returns. A failed write
    // is an error (the command exits non-zero), not a silent gap: the password has changed, and
    // the message says so.
    let who = telltale_api::auth::Actor::system("auth reset-password");
    let detail = serde_json::json!({ "by": "offline reset", "sessionsEnded": ended }).to_string();
    auth.state()
        .audit_append(&telltale_store::state::NewAudit {
            ts: now,
            actor: &who.name,
            actor_kind: who.kind,
            remote: who.remote.as_deref(),
            action: "user.password",
            target: &user.username,
            detail: &detail,
            reason: who.reason.as_deref(),
        })
        .map_err(|e| {
            format!("the password was changed, but its audit entry could not be written: {e}")
        })?;
    Ok(ended)
}

/// Reads the new password: one line from a pipe or file, or from a terminal typed twice with
/// echo off. `None` when a terminal's echo can't be turned off (nothing is shown then).
fn read_new_password() -> io::Result<Option<zeroize::Zeroizing<String>>> {
    use std::io::IsTerminal as _;
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        let mut line = zeroize::Zeroizing::new(String::new());
        stdin.read_line(&mut line)?;
        return Ok(Some(zeroize::Zeroizing::new(
            line.trim_end_matches(['\r', '\n']).to_owned(),
        )));
    }
    let Some(first) = read_hidden("New password: ")? else {
        return Ok(None);
    };
    let Some(second) = read_hidden("Repeat it: ")? else {
        return Ok(None);
    };
    if first.as_str() != second.as_str() {
        return Err(io::Error::other("the two passwords differ"));
    }
    Ok(Some(first))
}

/// One hidden line from the terminal. `None` when echo can't be turned off here.
fn read_hidden(prompt: &str) -> io::Result<Option<zeroize::Zeroizing<String>>> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    if !set_terminal(false) {
        eprintln!();
        return Ok(None);
    }
    // Echo and the interrupt keys come back on every exit from here, an error included.
    let _restore = TerminalRestore;
    let mut line = zeroize::Zeroizing::new(String::new());
    let read = io::stdin().read_line(&mut line);
    eprintln!();
    read?;
    // With the interrupt key off, Ctrl-C arrives as a character: it cancels the reset.
    if line.contains('\u{3}') {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "cancelled; no password was changed",
        ));
    }
    Ok(Some(zeroize::Zeroizing::new(
        line.trim_end_matches(['\r', '\n']).to_owned(),
    )))
}

/// Turns the terminal back to echo and the interrupt keys when dropped.
struct TerminalRestore;

impl Drop for TerminalRestore {
    fn drop(&mut self) {
        set_terminal(true);
    }
}

/// Turns the terminal's echo and interrupt keys (Ctrl-C) on or off through `stty` (the image has
/// none: then `false`). Off, Ctrl-C reaches the prompt as a character, so a cancelled reset
/// can't leave the terminal with echo off.
fn set_terminal(on: bool) -> bool {
    let mode: &[&str] = if on {
        &["echo", "isig"]
    } else {
        &["-echo", "-isig"]
    };
    std::process::Command::new("stty")
        .args(mode)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
#[path = "auth_setup_tests.rs"]
mod tests;
