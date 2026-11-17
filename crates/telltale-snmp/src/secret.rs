//! REQ: DSC-003 — a secret held for SNMP. It redacts its `Debug` output, is zeroized when it
//! is dropped, and has no `Display` or `Serialize` (ADR-903 section 9, ADR-908). The T23.3 type
//! in the main crate is not in this branch, so the crate defines its own (see the T25.4 note).

use std::fmt;

use zeroize::Zeroize;

/// A secret value: a community string or a USM password.
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsc_003_secret_debug_is_redacted() {
        let s = SecretValue::new(b"hunter2-community".to_vec());
        let shown = format!("{s:?}");
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("redacted"));
        assert_eq!(s.expose(), b"hunter2-community");
    }
}
