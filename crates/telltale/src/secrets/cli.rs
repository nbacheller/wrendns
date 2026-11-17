//! REQ: OPS-014 (ADR-903 §3) — `telltale secrets status` and `telltale secrets rotate-key`, run on
//! the node itself with the same configuration (`-c`) and environment as the server. Both work
//! offline: `status` reads the table and the key without making one; `rotate-key` replaces the
//! data-directory key (stop TelltaleDNS first).

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use telltale_config::Config;
use telltale_store::state::{SecretRow, State};
use zeroize::Zeroizing;

use super::credential::{FieldStatus, fields};
use super::store::{EnvFn, RowHealth, SecretStore, open, recover_rotation, seal};
use super::{KeyPaths, KeySource, NEW_KEY_FILE, NodeKey, hex, sync_dir, write_new_key};

/// `telltale secrets status`: the store's state, its key (source and ID, never the key), each
/// stored secret without its value, and every credential field with its source and whether this
/// node can read it.
///
/// REQ: OPS-014 — it writes nothing (no interrupted rotation finished or dropped, nothing
/// re-encrypted, no database or key made), so running it beside the server or a `rotate-key`
/// can't race them; what the next start would do is reported instead.
pub(crate) fn status(cfg: &Config, var: EnvFn, out: &mut dyn Write) -> std::io::Result<bool> {
    let store = SecretStore::read_only(cfg, var);
    store.load_now();
    let s = store.status();
    match &s.reason {
        Some(why) => writeln!(out, "store: {} ({why})", s.state.as_str())?,
        None => writeln!(out, "store: {}", s.state.as_str())?,
    }
    match (&s.key_source, &s.key_id) {
        (Some(src), Some(id)) => writeln!(out, "key: {src} (key_id {id})")?,
        _ => writeln!(out, "key: none")?,
    }
    if let Some(p) = &s.previous_key_id {
        writeln!(
            out,
            "previous key: key_id {p} ({} stored secret(s) under it, re-encrypted at the next start)",
            s.under_previous
        )?;
    }
    let paths = KeyPaths::of(cfg);
    if !paths.ephemeral && paths.data_dir.join(NEW_KEY_FILE).exists() {
        writeln!(
            out,
            "note: {} is left from an unfinished rotation (or one running now); the next start finishes or drops it",
            paths.data_dir.join(NEW_KEY_FILE).display()
        )?;
    }
    let tombstones = s.secrets.iter().filter(|x| x.deleted).count();
    writeln!(
        out,
        "stored secrets: {} ({} readable, {} unreadable, {} corrupt), {tombstones} deletion record(s)",
        s.live(),
        s.count(RowHealth::Readable),
        s.count(RowHealth::Unreadable),
        s.count(RowHealth::Corrupt),
    )?;
    for x in s.secrets.iter().filter(|x| !x.deleted) {
        writeln!(
            out,
            "  {:<32} {:<5} {:<10} {:<8} updated {} by {} (stamp {}.{})",
            x.name,
            x.kind,
            x.health.as_str(),
            x.origin,
            crate::alerts::time_text(x.updated),
            x.updated_by,
            x.stamp.epoch,
            x.stamp.seq
        )?;
    }
    let f = fields(cfg, Some(&store));
    if !f.is_empty() {
        writeln!(out, "credential fields:")?;
        for x in &f {
            writeln!(out, "  {}", field_line(x))?;
        }
    }
    Ok(s.reason.is_none())
}

fn field_line(f: &FieldStatus) -> String {
    let what = match (f.source, &f.at) {
        (super::Source::Inline, _) => format!("{} in the configuration", f.source.as_str()),
        (super::Source::File, Some(p)) => format!("file {p}"),
        (super::Source::Stored, Some(n)) => format!("stored secret `{n}`"),
        _ => "inline in the configuration".to_owned(),
    };
    let ok = match &f.readable {
        Ok(()) => "readable on this node".to_owned(),
        Err(e) => format!("NOT readable: {e}"),
    };
    format!("{} `{}` {}: {what}, {ok}", f.kind, f.entry, f.field)
}

/// What a rotation did.
#[derive(Debug)]
pub(crate) struct Rotated {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) reencrypted: usize,
    /// Rows left as they were: not readable under the old key either.
    pub(crate) skipped: usize,
}

/// How far a rotation goes (tests stop it where a crash would).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Until {
    /// After `secrets.key.new` is written, before re-encrypting.
    NewKeyWritten,
    /// After the re-encryption commits, before the rename.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "a test stops a rotation here, where a crash would"
        )
    )]
    Committed,
    Done,
}

/// REQ: OPS-014 (ADR-903 §3) — `telltale secrets rotate-key`: a new data-directory key. It is
/// written to `secrets.key.new` (0600, synced), every row is re-encrypted under it in one
/// transaction, the WAL is truncated, and the new key is renamed over `secrets.key`. A crash at
/// any point leaves a store the next start reads: a leftover `secrets.key.new` is tried by
/// `key_id` ([`recover_rotation`]). Only the data-directory key: a key from the environment or
/// `[node] secrets_key_file` is rotated by giving the old one as the previous key.
pub(crate) fn rotate_key(cfg: &Config, var: &EnvFn, until: Until) -> Result<Rotated, String> {
    let paths = KeyPaths::of(cfg);
    let env = |k: &str| var(k);
    if paths.ephemeral {
        return Err("a resolver pod holds no secrets and has no key to rotate".to_owned());
    }
    if !paths.uses_data_key(&env) {
        return Err("this node's key comes from TELLTALE_SECRETS_KEY or [node] secrets_key_file: rotate it by setting the new key there and the old one as TELLTALE_SECRETS_PREVIOUS_KEY or [node] secrets_previous_key_file, then restarting (docs/secrets.md)".to_owned());
    }
    let key_path = paths.data_key();
    if !key_path.exists() {
        return Err(format!(
            "{}: no key yet (the first start makes one)",
            key_path.display()
        ));
    }
    // Offline only: the server keeps the ciphertext in memory and would write under the old key.
    // A lock that can't be taken at all is refused too: whether the server runs is unknown.
    let _lock = match crate::datadir::lock(&paths.data_dir, std::time::Duration::ZERO) {
        Ok(l) => l,
        Err(crate::datadir::LockError::Held(holder)) => {
            return Err(format!(
                "TelltaleDNS is running on {} ({holder}); stop it first",
                paths.data_dir.display()
            ));
        }
        Err(crate::datadir::LockError::Io(e)) => {
            return Err(format!(
                "{}: the data directory's lock can't be taken ({e}), so whether TelltaleDNS is running is unknown; nothing was changed",
                paths.data_dir.display()
            ));
        }
    };
    let db = paths.data_dir.join("state.db");
    let state = State::open(&db).map_err(|e| format!("{}: {e}", db.display()))?;
    let rows = state.secret_rows().map_err(|e| e.to_string())?;
    // REQ: CLU-015 (ADR-917 point 4) — shadows are sealed under the same key: they are rotated
    // with the rows, and count when a rotation is recovered.
    let shadows = state.secret_shadows().map_err(|e| e.to_string())?;
    let all: Vec<SecretRow> = rows.iter().chain(shadows.iter()).cloned().collect();
    if let Some(note) = recover_rotation(&paths.data_dir, &all) {
        eprintln!("note: {note}");
    }
    let old = read_key(&key_path)?;
    let text = NodeKey::generate()?;
    let new_path = paths.data_dir.join(NEW_KEY_FILE);
    write_new_key(&new_path, &text)?;
    sync_dir(&paths.data_dir)?;
    let new = NodeKey::parse(&text, KeySource::DataDir(new_path.clone()))?;
    let mut redone: Vec<SecretRow> = Vec::new();
    let mut redone_shadows: Vec<SecretRow> = Vec::new();
    let mut skipped = 0;
    if until != Until::NewKeyWritten {
        for (src, out) in [(&rows, &mut redone), (&shadows, &mut redone_shadows)] {
            for r in src.iter().filter(|r| !r.deleted) {
                let Ok(v) = open(&old, r) else {
                    skipped += 1;
                    continue;
                };
                let s = seal(&new, &r.kind, &r.name, r.stamp, &v)?;
                out.push(SecretRow {
                    key_id: s.key_id,
                    nonce: s.nonce,
                    ciphertext: s.ciphertext,
                    ..r.clone()
                });
            }
        }
        let clean = state
            .replace_secret_rows(&redone, &redone_shadows)
            .map_err(|e| e.to_string())?;
        if !clean {
            eprintln!(
                "note: the write-ahead log couldn't be truncated (another connection was busy): ciphertext under the old key may stay in state.db-wal until the next checkpoint"
            );
        }
    }
    let done = Rotated {
        from: hex(&old.key_id()),
        to: hex(&new.key_id()),
        reencrypted: redone.len(),
        skipped,
    };
    if until == Until::Done {
        std::fs::rename(&new_path, &key_path)
            .map_err(|e| format!("{}: {e}", key_path.display()))?;
        sync_dir(&paths.data_dir)?;
    }
    Ok(done)
}

fn read_key(path: &Path) -> Result<NodeKey, String> {
    let text = std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    NodeKey::parse(&text, KeySource::DataDir(path.to_path_buf()))
}

/// The process environment, for the commands.
pub(crate) fn env() -> EnvFn {
    Arc::new(super::process_env)
}
