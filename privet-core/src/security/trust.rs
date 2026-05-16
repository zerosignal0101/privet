use std::collections::HashSet;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::error::SecurityError;

/// Manages trusted peer fingerprints and pairing verification codes.
#[derive(Debug)]
pub struct TrustStore {
    trusted: HashSet<String>,
    store_path: PathBuf,
}

impl TrustStore {
    pub fn load_or_create(store_path: PathBuf) -> Result<Self, SecurityError> {
        let trusted = if store_path.exists() {
            let json = std::fs::read_to_string(&store_path)
                .map_err(|e| SecurityError::Certificate(format!("read trust store: {e}")))?;
            serde_json::from_str::<HashSet<String>>(&json)
                .map_err(|e| SecurityError::Certificate(format!("parse trust store: {e}")))?
        } else {
            HashSet::new()
        };

        Ok(Self { trusted, store_path })
    }

    pub fn is_trusted(&self, fingerprint: &str) -> bool {
        self.trusted.contains(fingerprint)
    }

    pub fn trust(&mut self, fingerprint: String) -> Result<(), SecurityError> {
        self.trusted.insert(fingerprint);
        self.save()
    }

    pub fn untrust(&mut self, fingerprint: &str) -> Result<(), SecurityError> {
        self.trusted.remove(fingerprint);
        self.save()
    }

    pub fn trusted_fingerprints(&self) -> Vec<String> {
        self.trusted.iter().cloned().collect()
    }

    /// Generate a 6-digit verification code from a fingerprint.
    /// Both parties compute the same code from the same fingerprint.
    pub fn pairing_code(fingerprint: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(fingerprint.as_bytes());
        hasher.update(b"privet-pairing-v1");
        let hash = hasher.finalize();
        let code = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 1_000_000;
        format!("{code:06}")
    }

    fn save(&self) -> Result<(), SecurityError> {
        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SecurityError::Certificate(format!("create trust dir: {e}")))?;
        }
        let json = serde_json::to_string_pretty(&self.trusted)
            .map_err(|e| SecurityError::Certificate(format!("serialize trust store: {e}")))?;
        std::fs::write(&self.store_path, json)
            .map_err(|e| SecurityError::Certificate(format!("write trust store: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_code_deterministic() {
        let fp = "abc123def456";
        assert_eq!(TrustStore::pairing_code(fp), TrustStore::pairing_code(fp));
    }

    #[test]
    fn pairing_code_different_fingerprints() {
        let code1 = TrustStore::pairing_code("fp1");
        let code2 = TrustStore::pairing_code("fp2");
        assert_ne!(code1, code2);
    }

    #[test]
    fn pairing_code_six_digits() {
        let code = TrustStore::pairing_code("test");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
