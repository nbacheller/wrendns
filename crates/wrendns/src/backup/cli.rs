//! REQ: API-007 (T23.9, ADR-903 §8) — the passphrase of `wrendns backup create | restore`: from a
//! file, from standard input, or typed at a terminal (not shown). Never an argument or a
//! variable: those end up in `ps`, shell history and `/proc`.

use std::io::{self, BufRead as _, IsTerminal as _, Read as _, Write as _};
use std::path::PathBuf;

use zeroize::Zeroizing;

/// Where the passphrase comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    File(PathBuf),
    Stdin,
    Prompt,
}

/// A passphrase from a file or a stream: the first line, without its line ending.
fn first_line(mut r: impl io::Read) -> io::Result<Zeroizing<String>> {
    let mut text = Zeroizing::new(String::new());
    r.by_ref().take(64 * 1024).read_to_string(&mut text)?;
    let line = text.lines().next().unwrap_or_default();
    Ok(Zeroizing::new(line.to_owned()))
}

/// Turns the terminal's echo back on when dropped.
struct Echo<'a>(&'a dyn Fn(&str) -> bool);

impl Drop for Echo<'_> {
    fn drop(&mut self) {
        (self.0)("echo");
    }
}

/// Reads one line from the terminal without showing it (`stty -echo`, restored after, by a drop
/// guard; after an interrupt, `stty echo` does it).
fn prompt_hidden(label: &str) -> Result<Zeroizing<String>, String> {
    let tty = std::fs::File::open("/dev/tty")
        .map_err(|_| "there is no terminal to ask on: use --secrets-passphrase-file".to_owned())?;
    let stty = |arg: &str| {
        std::process::Command::new("stty")
            .arg(arg)
            .stdin(
                tty.try_clone()
                    .map_or_else(|_| std::process::Stdio::null(), std::process::Stdio::from),
            )
            .status()
            .is_ok_and(|s| s.success())
    };
    if !stty("-echo") {
        return Err(
            "couldn't turn the terminal's echo off: use --secrets-passphrase-file".to_owned(),
        );
    }
    // Echo comes back whichever way this returns or unwinds. (A process killed by a signal
    // mid-prompt can't run it: `stty echo` restores the terminal, as the prompt says.)
    let echo = Echo(&stty);
    eprint!("{label}");
    let _ = io::stderr().flush();
    let mut line = Zeroizing::new(String::new());
    let read = io::BufReader::new(&tty).read_line(&mut line);
    drop(echo);
    eprintln!();
    read.map_err(|e| e.to_string())?;
    let t = line.trim_end_matches(['\r', '\n']).to_owned();
    Ok(Zeroizing::new(t))
}

/// The passphrase from `source`. `confirm`: a terminal asks twice.
pub(crate) fn read(source: &Source, confirm: bool) -> Result<Zeroizing<String>, String> {
    let p = match source {
        Source::File(path) => std::fs::File::open(path)
            .and_then(first_line)
            .map_err(|e| format!("{}: {e}", path.display()))?,
        Source::Stdin => {
            if io::stdin().is_terminal() {
                return Err("standard input is a terminal, which would show the passphrase: use --secrets-passphrase-prompt, or pipe it in".to_owned());
            }
            first_line(io::stdin().lock()).map_err(|e| format!("standard input: {e}"))?
        }
        Source::Prompt => {
            let a = prompt_hidden("Backup passphrase: ")?;
            if confirm {
                let b = prompt_hidden("Again: ")?;
                if *a != *b {
                    return Err("the two passphrases differ".to_owned());
                }
            }
            a
        }
    };
    if p.is_empty() {
        return Err("the passphrase is empty".to_owned());
    }
    Ok(p)
}

/// REQ: API-007 (T23.9, ADR-903 §8) — `wrendns backup create`: with a passphrase the stored
/// secrets are read from this node's `state.db` (beside a running server; nothing is written)
/// and sealed into the archive.
pub(crate) fn create(
    files: &[PathBuf],
    cfg: &wrendns_config::Config,
    include_qlog: bool,
    out: &std::path::Path,
    source: Option<&Source>,
) -> Result<(), String> {
    let export = match source {
        Some(src) => {
            let pass = read(src, true)?;
            super::check_passphrase(&pass)?;
            if super::kdf_busy() {
                return Err(super::BackupError::Busy.to_string());
            }
            let store = crate::secrets::SecretStore::read_only(cfg, crate::secrets::cli::env());
            store.load_now();
            let super::Exported {
                rows,
                unreadable,
                pem_kept,
            } = store.export_rows().map_err(|why| {
                format!("the stored secrets can't be read, so none can be backed up ({why}); fix the node's key (docs/secrets.md) or back up without a passphrase")
            })?;
            Some(super::SecretsExport {
                passphrase: pass,
                rows,
                unreadable,
                pem_kept,
            })
        }
        None => None,
    };
    let c = super::create_with(files, cfg, include_qlog, out, export.as_ref())
        .map_err(|e| e.to_string())?;
    eprintln!(
        "wrote {} ({} files, {} KiB). It holds password hashes: keep it private.",
        c.path.display(),
        c.entries,
        c.bytes.div_ceil(1024)
    );
    for w in &c.warnings {
        eprintln!("warning: {w}");
    }
    if c.secrets.included {
        eprintln!(
            "{} stored secret(s) are in it, encrypted with the passphrase. Without the passphrase they can't be restored: keep it somewhere other than the backup.",
            c.secrets.count
        );
    } else if c.secrets.count > 0 {
        eprintln!(
            "{} stored secret(s) were left out (no passphrase given). Give --secrets-passphrase-file, --secrets-passphrase-stdin or --secrets-passphrase-prompt to include them; otherwise enter them again after a restore.",
            c.secrets.count
        );
    }
    Ok(())
}

/// REQ: API-007 (T23.9, ADR-903 §8) — `wrendns backup restore`.
pub(crate) fn restore(
    file: &std::path::Path,
    data_dir: Option<&std::path::Path>,
    config_dir: Option<&std::path::Path>,
    force: bool,
    key_cfg: Option<&wrendns_config::Config>,
    skip_secrets: bool,
    source: Option<&Source>,
) -> Result<(), String> {
    use super::SecretsMode;
    // The passphrase is asked for only when the backup needs one.
    let needs = super::show(file)?.has_secrets();
    let mode = match source {
        _ if skip_secrets => SecretsMode::Skip,
        Some(src) if needs => SecretsMode::Passphrase(read(src, false)?),
        _ => SecretsMode::Unspecified,
    };
    let keys = super::RestoreKeys {
        cfg: key_cfg,
        env: &crate::secrets::process_env,
    };
    let r = super::restore_with(file, data_dir, config_dir, force, &mode, &keys)?;
    eprintln!(
        "restored {} files from {} (node {}, WrenDNS {}): data in {}, config in {}",
        r.files,
        file.display(),
        r.manifest.node,
        r.manifest.telltale_version, // rebrand:keep
        r.data_dir.display(),
        r.config_dir.display()
    );
    if let Some(s) = &r.secrets {
        eprintln!(
            "{} stored secret(s) restored under this node's key from {} (key_id {}).",
            s.count, s.key_source, s.key_id
        );
    }
    if r.secrets_skipped > 0 {
        eprintln!(
            "{} stored secret(s) in the backup were skipped: enter them again in Settings.",
            r.secrets_skipped
        );
    } else if r.secrets.is_none() && r.manifest.secrets.as_ref().is_some_and(|s| s.count > 0) {
        eprintln!(
            "note: the backup was made without its {} stored secret(s): enter them again in Settings.",
            r.manifest.secrets.as_ref().map_or(0, |s| s.count)
        );
    }
    if std::path::Path::new(&r.manifest.data_dir) != r.data_dir {
        eprintln!(
            "note: the restored config files say data_dir = {}; set it to {} (or add a file that does).",
            r.manifest.data_dir,
            r.data_dir.display()
        );
    }
    if r.manifest.cluster_member {
        eprintln!(
            "note: the backup came from a cluster member; cluster identity isn't in backups. Start this node, then `wrendns cluster init` or join it again (docs: Clusters)."
        );
    }
    Ok(())
}

/// `wrendns backup show`.
pub(crate) fn show(file: &std::path::Path) -> Result<(), String> {
    let m = super::show(file)?;
    let mut out = io::stdout().lock();
    let total: u64 = m.entries.iter().map(|e| e.size).sum();
    let _ = writeln!(
        out,
        "WrenDNS {} backup of node `{}`, taken {} (unix), format {}, {} files, {} KiB, checksums OK",
        m.telltale_version, // rebrand:keep
        m.node,
        m.created,
        m.version,
        m.entries.len(),
        total.div_ceil(1024)
    );
    match &m.secrets {
        Some(s) if s.included => {
            let k = s.kdf.as_ref();
            let _ = writeln!(
                out,
                "stored secrets: {} encrypted with a passphrase ({} {} MiB, {} passes, {} lane(s); {}); restore needs it or --skip-secrets",
                s.count,
                k.map_or("?", |k| k.alg.as_str()),
                k.map_or(0, |k| k.m_kib / 1024),
                k.map_or(0, |k| k.t),
                k.map_or(0, |k| k.p),
                s.aead.as_deref().unwrap_or("?")
            );
        }
        Some(s) => {
            let _ = writeln!(
                out,
                "stored secrets: none in the backup ({} on the node left out: {})",
                s.count,
                s.omitted_reason.as_deref().unwrap_or("not included")
            );
        }
        None => {
            let _ = writeln!(
                out,
                "stored secrets: none (made before backups could carry them)"
            );
        }
    }
    for e in &m.entries {
        let _ = writeln!(out, "  {:>10}  {}", e.size, e.path);
    }
    Ok(())
}
