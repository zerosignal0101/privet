use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::peer::PeerId;

/// Local device identity: key pair + certificate + derived PeerId
#[derive(Clone, Debug)]
pub struct DeviceIdentity {
    pub peer_id: PeerId,
    pub device_name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
    pub cert_dir: PathBuf,
}

impl DeviceIdentity {
    /// Generate a new device identity with self-signed certificate.
    pub fn generate(device_name: String, cert_dir: PathBuf, validity_years: u32) -> Result<Self, crate::error::SecurityError> {
        let (cert_pem, key_pem, fingerprint) =
            super::cert::generate_self_signed(&device_name, validity_years)?;

        let peer_id = PeerId(Uuid::new_v4());

        Ok(Self {
            peer_id,
            device_name,
            cert_pem,
            key_pem,
            fingerprint,
            cert_dir,
        })
    }

    /// Load existing identity from disk, or generate if not present.
    pub fn load_or_generate(
        device_name: String,
        cert_dir: PathBuf,
        validity_years: u32,
    ) -> Result<Self, crate::error::SecurityError> {
        let cert_path = cert_dir.join("device.crt");
        let key_path = cert_dir.join("device.key");
        let id_path = cert_dir.join("identity.json");

        if cert_path.exists() && key_path.exists() && id_path.exists() {
            match Self::load_from_disk(&cert_dir) {
                Ok(id) => return Ok(id),
                Err(e) => {
                    tracing::warn!("Failed to load identity, regenerating: {e}");
                }
            }
        }

        let identity = Self::generate(device_name, cert_dir, validity_years)?;
        identity.save_to_disk()?;
        Ok(identity)
    }

    fn load_from_disk(cert_dir: &std::path::Path) -> Result<Self, crate::error::SecurityError> {
        let cert_pem = std::fs::read_to_string(cert_dir.join("device.crt"))
            .map_err(|e| crate::error::SecurityError::Certificate(format!("read cert: {e}")))?;
        let key_pem = std::fs::read_to_string(cert_dir.join("device.key"))
            .map_err(|e| crate::error::SecurityError::Certificate(format!("read key: {e}")))?;
        let id_json = std::fs::read_to_string(cert_dir.join("identity.json"))
            .map_err(|e| crate::error::SecurityError::Certificate(format!("read identity: {e}")))?;

        let stored: StoredIdentity = serde_json::from_str(&id_json)
            .map_err(|e| crate::error::SecurityError::Certificate(format!("parse identity: {e}")))?;

        // Verify cert matches stored fingerprint
        let fingerprint = super::cert::fingerprint_from_pem(&cert_pem)?;
        if fingerprint != stored.fingerprint {
            return Err(crate::error::SecurityError::FingerprintMismatch {
                expected: stored.fingerprint,
                got: fingerprint,
            });
        }

        Ok(Self {
            peer_id: stored.peer_id,
            device_name: stored.device_name,
            cert_pem,
            key_pem,
            fingerprint,
            cert_dir: cert_dir.to_owned(),
        })
    }

    fn save_to_disk(&self) -> Result<(), crate::error::SecurityError> {
        std::fs::create_dir_all(&self.cert_dir)
            .map_err(|e| crate::error::SecurityError::Certificate(format!("create dir: {e}")))?;

        std::fs::write(self.cert_dir.join("device.crt"), &self.cert_pem)
            .map_err(|e| crate::error::SecurityError::Certificate(format!("write cert: {e}")))?;
        std::fs::write(self.cert_dir.join("device.key"), &self.key_pem)
            .map_err(|e| crate::error::SecurityError::Certificate(format!("write key: {e}")))?;

        let stored = StoredIdentity {
            peer_id: self.peer_id,
            device_name: self.device_name.clone(),
            fingerprint: self.fingerprint.clone(),
        };
        let json = serde_json::to_string_pretty(&stored)
            .map_err(|e| crate::error::SecurityError::Certificate(format!("serialize identity: {e}")))?;
        std::fs::write(self.cert_dir.join("identity.json"), json)
            .map_err(|e| crate::error::SecurityError::Certificate(format!("write identity: {e}")))?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    peer_id: PeerId,
    device_name: String,
    fingerprint: String,
}
