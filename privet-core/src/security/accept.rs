use std::collections::HashSet;
use std::path::PathBuf;

use crate::error::SecurityError;

/// Manages peer fingerprints that are trusted AND auto-accept transfers.
/// This is a subset of TrustStore: a device must be trusted first before
/// it can be auto-accepted. AcceptStore controls whether the receiver
/// automatically accepts incoming transfers without prompting the user.
#[derive(Debug)]
pub struct AcceptStore {
    accepted: HashSet<String>,
    store_path: PathBuf,
}

impl AcceptStore {
    pub fn load_or_create(store_path: PathBuf) -> Result<Self, SecurityError> {
        let accepted = if store_path.exists() {
            let json = std::fs::read_to_string(&store_path)
                .map_err(|e| SecurityError::Certificate(format!("read accept store: {e}")))?;
            serde_json::from_str::<HashSet<String>>(&json)
                .map_err(|e| SecurityError::Certificate(format!("parse accept store: {e}")))?
        } else {
            HashSet::new()
        };

        Ok(Self { accepted, store_path })
    }

    pub fn is_accepted(&self, fingerprint: &str) -> bool {
        self.accepted.contains(fingerprint)
    }

    pub fn accept(&mut self, fingerprint: String) -> Result<(), SecurityError> {
        self.accepted.insert(fingerprint);
        self.save()
    }

    pub fn unaccept(&mut self, fingerprint: &str) -> Result<(), SecurityError> {
        self.accepted.remove(fingerprint);
        self.save()
    }

    pub fn accepted_fingerprints(&self) -> Vec<String> {
        self.accepted.iter().cloned().collect()
    }

    fn save(&self) -> Result<(), SecurityError> {
        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SecurityError::Certificate(format!("create accept dir: {e}")))?;
        }
        let json = serde_json::to_string_pretty(&self.accepted)
            .map_err(|e| SecurityError::Certificate(format!("serialize accept store: {e}")))?;
        std::fs::write(&self.store_path, json)
            .map_err(|e| SecurityError::Certificate(format!("write accept store: {e}")))?;
        Ok(())
    }
}
