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

    /// Generate a 6-digit verification code from both local and peer fingerprints.
    /// Both parties compute the same code by sorting the two fingerprints.
    pub fn pairing_code(local_fingerprint: &str, peer_fingerprint: &str) -> String {
        let mut hasher = Sha256::new();
        // Sort so both sides arrive at the same combined input
        let (first, second) = if local_fingerprint < peer_fingerprint {
            (local_fingerprint, peer_fingerprint)
        } else {
            (peer_fingerprint, local_fingerprint)
        };
        hasher.update(first.as_bytes());
        hasher.update(second.as_bytes());
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
        let local = "abc123def456";
        let peer = "789012345678";
        assert_eq!(
            TrustStore::pairing_code(local, peer),
            TrustStore::pairing_code(local, peer)
        );
        // Must be symmetric: swapping args gives same code
        assert_eq!(
            TrustStore::pairing_code(local, peer),
            TrustStore::pairing_code(peer, local),
            "pairing_code must be symmetric"
        );
    }

    #[test]
    fn pairing_code_different_pairs() {
        let code1 = TrustStore::pairing_code("local1", "peer1");
        let code2 = TrustStore::pairing_code("local2", "peer2");
        assert_ne!(code1, code2);
    }

    #[test]
    fn pairing_code_six_digits() {
        let code = TrustStore::pairing_code("local_test", "peer_test");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
