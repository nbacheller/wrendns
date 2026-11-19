//! REQ: DSC-003 — SNMP credential sources (ADR-908 "Credentials"). A community or a USM
//! password is either a `*_file` confined to `[node] secret_file_dirs`, or a `*_ref` to a
//! stored secret. An inline value is refused. The `*_ref` lookup lives with the secret store,
//! which this crate does not depend on; the caller resolves it.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::secret::SecretValue;

/// The largest credential file read (a password is far smaller).
pub const MAX_CREDENTIAL_FILE: u64 = 4096;

/// Where a credential comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    File(PathBuf),
    Ref(String),
}

/// Why a credential source is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredError {
    /// The value was given inline. Inline values are never accepted.
    InlineRefused,
    /// Both a file and a reference, or neither.
    NotExactlyOne,
    /// The file is outside every configured credential directory, or cannot be resolved.
    OutsideSecretDirs,
    /// The file cannot be read, or is too large.
    Unreadable,
}

/// Chooses the source from the three fields a configuration entry may set.
pub fn source_from_fields(
    file: Option<&str>,
    inline: Option<&str>,
    reference: Option<&str>,
) -> Result<CredentialSource, CredError> {
    if inline.is_some() {
        return Err(CredError::InlineRefused);
    }
    match (file, reference) {
        (Some(f), None) => Ok(CredentialSource::File(PathBuf::from(f))),
        (None, Some(r)) => Ok(CredentialSource::Ref(r.to_owned())),
        _ => Err(CredError::NotExactlyOne),
    }
}

/// Reads a credential file. The path, once resolved (symlinks included), must lie under one of
/// `secret_dirs`. The file is opened once: its metadata is checked on that handle, and the read
/// is capped at one byte past `MAX_CREDENTIAL_FILE`, so a file swapped or grown between a check
/// and the read cannot exceed the cap. The bytes are held in `Zeroizing` until they move into
/// the `SecretValue`. A trailing newline is removed.
pub fn read_file(path: &Path, secret_dirs: &[PathBuf]) -> Result<SecretValue, CredError> {
    let resolved = fs::canonicalize(path).map_err(|_| CredError::OutsideSecretDirs)?;
    let allowed = secret_dirs
        .iter()
        .filter_map(|d| fs::canonicalize(d).ok())
        .any(|d| resolved.starts_with(&d));
    if !allowed {
        return Err(CredError::OutsideSecretDirs);
    }
    // The open refuses a final symlink (O_NOFOLLOW) and never blocks on a FIFO (O_NONBLOCK). The
    // metadata is read from the handle before any byte is read, so a FIFO or a device is refused
    // before it is read.
    let file = open_no_follow(&resolved).map_err(|_| CredError::Unreadable)?;
    let meta = file.metadata().map_err(|_| CredError::Unreadable)?;
    if !meta.is_file() || meta.len() > MAX_CREDENTIAL_FILE {
        return Err(CredError::Unreadable);
    }
    // A directory on the path may have been swapped after the canonical check. The handle must
    // still be the object that the path names now.
    let now = fs::canonicalize(path).map_err(|_| CredError::Unreadable)?;
    if now != resolved {
        return Err(CredError::OutsideSecretDirs);
    }
    let path_meta = fs::metadata(&now).map_err(|_| CredError::Unreadable)?;
    if !same_object(&meta, &path_meta) {
        return Err(CredError::OutsideSecretDirs);
    }
    // The buffer is sized for the cap up front, so reading never reallocates and leaves no old
    // copy of the secret behind.
    let cap = usize::try_from(MAX_CREDENTIAL_FILE.saturating_add(1)).unwrap_or(usize::MAX);
    let mut bytes = Zeroizing::new(Vec::with_capacity(cap));
    file.take(MAX_CREDENTIAL_FILE.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| CredError::Unreadable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CREDENTIAL_FILE {
        return Err(CredError::Unreadable);
    }
    while bytes.last().is_some_and(|&b| b == b'\n' || b == b'\r') {
        bytes.pop();
    }
    Ok(SecretValue::new(std::mem::take(&mut *bytes)))
}

/// Opens a credential file without following a final symlink, and without blocking on a FIFO
/// (ADR-932).
#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

/// Whether an open file and a path name the same object (device and inode).
#[cfg(unix)]
fn same_object(open: &fs::Metadata, named: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    open.dev() == named.dev() && open.ino() == named.ino()
}

/// Off Unix the canonical path is the check: there is no device and inode to compare.
#[cfg(not(unix))]
fn same_object(_open: &fs::Metadata, _named: &fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsc_003_inline_credentials_are_refused() {
        assert_eq!(
            source_from_fields(Some("/x"), Some("public"), None),
            Err(CredError::InlineRefused)
        );
        assert_eq!(
            source_from_fields(None, Some("pw"), None),
            Err(CredError::InlineRefused)
        );
        assert_eq!(
            source_from_fields(None, None, None),
            Err(CredError::NotExactlyOne)
        );
        assert_eq!(
            source_from_fields(Some("/a"), None, Some("discovery.x.y")),
            Err(CredError::NotExactlyOne)
        );
        assert_eq!(
            source_from_fields(Some("/a/community"), None, None),
            Ok(CredentialSource::File(PathBuf::from("/a/community")))
        );
    }

    #[test]
    fn dsc_003_credential_files_are_confined_to_secret_dirs() {
        let base = std::env::temp_dir().join(format!("tt-snmp-creds-{}", std::process::id()));
        let inside = base.join("secrets");
        let outside = base.join("elsewhere");
        assert!(fs::create_dir_all(&inside).is_ok());
        assert!(fs::create_dir_all(&outside).is_ok());
        let ok_file = inside.join("community");
        let bad_file = outside.join("community");
        assert!(fs::write(&ok_file, "ttcomm\n").is_ok());
        assert!(fs::write(&bad_file, "ttcomm\n").is_ok());
        let dirs = vec![inside.clone()];
        let got = read_file(&ok_file, &dirs);
        assert_eq!(
            got.map(|s| s.expose().to_vec()).ok(),
            Some(b"ttcomm".to_vec())
        );
        assert_eq!(
            read_file(&bad_file, &dirs).err(),
            Some(CredError::OutsideSecretDirs)
        );
        // A file that does not exist is refused the same way, so the error names no path.
        assert_eq!(
            read_file(&inside.join("missing"), &dirs).err(),
            Some(CredError::OutsideSecretDirs)
        );
        let _ = fs::remove_dir_all(&base);
    }
}
