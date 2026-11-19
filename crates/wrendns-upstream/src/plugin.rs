//! Plugin upstreams (REQ: UPS-011, `spec/04` §6; T7.16): any program that speaks DNS over a
//! stream (RFC 7766 framing: a 2-byte length, then the message) on a Unix socket.
//! - `unix:///run/my-plugin.sock`: WrenDNS connects to a socket someone else serves.
//! - `exec:///usr/local/bin/my-plugin` (with `args`): WrenDNS starts the program, tells it
//!   where to listen (`WRENDNS_PLUGIN_SOCKET`), restarts it with backoff when it exits, and
//!   logs its output. It's stopped when the upstream goes away (a reload or shutdown).
//!
//! A plugin can't take the resolver down: it's another process, every exchange has the
//! upstream's timeout, and a dead plugin is just a failing upstream (health, breaker, the
//! group's other members).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

/// Supervises one plugin process; dropping it stops the process.
#[derive(Debug)]
pub(crate) struct Supervisor {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort(); // the child is killed with its handle (kill_on_drop)
        }
    }
}

/// The plugin's command line and environment. REQ: OPS-014, API-014 (ADR-903 §3) — it inherits
/// the server's environment, but no `WRENDNS_*` variable (they can carry configuration with
/// credentials, `WRENDNS_UPSTREAM_*` headers or an OIDC `client_secret`, besides the secrets
/// keys, the bootstrap admin's password, and an API token: `wrendns_config::NEVER_INHERITED`)
/// except the two it is given.
fn command(
    program: &std::path::Path,
    args: &[String],
    socket: &std::path::Path,
    name: &str,
) -> Command {
    command_from(
        program,
        args,
        socket,
        name,
        std::env::vars_os().map(|(k, _)| k),
    )
}

/// [`command`] with the names of the environment it would inherit given (tests).
fn command_from(
    program: &std::path::Path,
    args: &[String],
    socket: &std::path::Path,
    name: &str,
    inherited: impl Iterator<Item = std::ffi::OsString>,
) -> Command {
    let mut c = Command::new(program);
    for v in wrendns_config::NEVER_INHERITED {
        c.env_remove(v);
    }
    for k in inherited {
        if k.to_str()
            .is_none_or(|k| k.starts_with(wrendns_config::ENV_PREFIX))
        {
            c.env_remove(k);
        }
    }
    c.args(args)
        .env("WRENDNS_PLUGIN_SOCKET", socket)
        .env("WRENDNS_UPSTREAM", name)
        // REQ: UPS-011 (ADR-1028) — the names the pre-rename release documented, for this release
        // only: a plugin written for them keeps working until its author moves to the new ones.
        .env("TELLTALE_PLUGIN_SOCKET", socket) // rebrand:keep
        .env("TELLTALE_UPSTREAM", name) // rebrand:keep
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    c
}

/// Starts `program args` with `WRENDNS_PLUGIN_SOCKET=socket`, restarting it when it exits
/// (1 s, doubling to 60 s; back to 1 s after a minute of running). Without a Tokio runtime
/// (config checks), nothing is started.
pub(crate) fn supervise(
    name: &str,
    program: PathBuf,
    args: Vec<String>,
    socket: PathBuf,
) -> Supervisor {
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return Supervisor { task: None };
    };
    let name = name.to_owned();
    let task = rt.spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            if let Some(dir) = socket.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::remove_file(&socket);
            let started = Instant::now();
            let child = command(&program, &args, &socket, &name).spawn();
            match child {
                Ok(mut child) => {
                    info!(upstream = %name, program = %program.display(), "plugin started");
                    for (out, err) in [(child.stdout.take().map(Either::Out), false), (child.stderr.take().map(Either::Err), true)] {
                        if let Some(o) = out {
                            let n = name.clone();
                            tokio::spawn(async move { o.forward(&n, err).await });
                        }
                    }
                    let status = child.wait().await;
                    warn!(upstream = %name, ?status, "plugin exited; restarting in {}s", backoff.as_secs());
                }
                Err(e) => warn!(upstream = %name, program = %program.display(), error = %e, "plugin can't start"),
            }
            if started.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    });
    Supervisor { task: Some(task) }
}

enum Either {
    Out(tokio::process::ChildStdout),
    Err(tokio::process::ChildStderr),
}

impl Either {
    /// The plugin's output, line by line, in our log.
    async fn forward(self, name: &str, err: bool) {
        let mut lines: Box<dyn tokio::io::AsyncBufRead + Unpin + Send> = match self {
            Self::Out(o) => Box::new(BufReader::new(o)),
            Self::Err(e) => Box::new(BufReader::new(e)),
        };
        let mut line = String::new();
        loop {
            line.clear();
            match lines.read_line(&mut line).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    let l = line.trim_end();
                    if err {
                        warn!(upstream = %name, "plugin: {l}");
                    } else {
                        info!(upstream = %name, "plugin: {l}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    /// REQ: OPS-014, API-014 (ADR-903 §3) — a plugin is started without the secrets keys, the
    /// bootstrap password, or the API token, and with its own socket and name.
    #[test]
    fn ops_014_plugin_env_has_no_secrets_key() {
        let c = command_from(
            std::path::Path::new("/usr/local/bin/plugin"),
            &["--flag".to_owned()],
            std::path::Path::new("/run/wrendns/p.sock"),
            "plug",
            [
                "PATH",
                "WRENDNS_AUTH_OIDC_PROVIDER",
                "WRENDNS_PLUGIN_SOCKET",
                "HTTPS_PROXY",
            ]
            .into_iter()
            .map(std::ffi::OsString::from),
        );
        let envs: Vec<(String, Option<String>)> = c
            .as_std()
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for k in [
            "WRENDNS_SECRETS_KEY",
            "WRENDNS_SECRETS_PREVIOUS_KEY",
            "WRENDNS_BOOTSTRAP_ADMIN_PASSWORD",
            "WRENDNS_BOOTSTRAP_ADMIN_PASSWORD_HASH",
            "WRENDNS_TOKEN",
            // Any other WRENDNS_* variable too (configuration that may hold a credential).
            "WRENDNS_AUTH_OIDC_PROVIDER",
        ] {
            assert!(
                envs.contains(&(k.to_owned(), None)),
                "{k} removed: {envs:?}"
            );
        }
        for k in ["PATH", "HTTPS_PROXY"] {
            assert!(!envs.iter().any(|(e, _)| e == k), "{k} inherited: {envs:?}");
        }
        assert!(envs.contains(&("WRENDNS_UPSTREAM".to_owned(), Some("plug".to_owned()))));
        assert!(envs.contains(&(
            "WRENDNS_PLUGIN_SOCKET".to_owned(),
            Some("/run/wrendns/p.sock".to_owned())
        )));
        assert!(envs.contains(&("TELLTALE_UPSTREAM".to_owned(), Some("plug".to_owned())))); // rebrand:keep
        assert!(envs.contains(&(
            "TELLTALE_PLUGIN_SOCKET".to_owned(), // rebrand:keep
            Some("/run/wrendns/p.sock".to_owned())
        )));
    }
}
