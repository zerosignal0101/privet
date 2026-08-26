use crate::cert::{conn_auth_decision, pin, ConnAuthAction};
use crate::trust::{TrustState, TrustStore};
use crate::PairingError;

pub fn conn_auth(
    peer_spki: &[u8],
    peer_device_fingerprint: &str,
    trust: &dyn TrustStore,
) -> Result<ConnAuthAction, PairingError> {
    let d = pin(peer_spki, peer_device_fingerprint, trust)?;
    Ok(conn_auth_decision(d))
}

#[derive(Debug, Clone)]
pub struct KeyMismatchAlert {
    pub device_fingerprint: String,
    pub trust_state: TrustState,
    pub presented_spki: Vec<u8>,
    pub stored_spki: Vec<u8>,
}

pub fn build_alert(
    peer_spki: &[u8],
    peer_device_fingerprint: &str,
    trust: &dyn TrustStore,
) -> Result<KeyMismatchAlert, PairingError> {
    let stored = trust.get(peer_device_fingerprint)?;
    let stored_spki = stored
        .as_ref()
        .map(|r| r.peer_spki.clone())
        .unwrap_or_default();
    let state = stored.map(|r| r.trust_state).unwrap_or(TrustState::Unknown);
    Ok(KeyMismatchAlert {
        device_fingerprint: peer_device_fingerprint.to_string(),
        trust_state: state,
        presented_spki: peer_spki.to_vec(),
        stored_spki,
    })
}

impl KeyMismatchAlert {
    pub fn user_message(&self) -> String {
        format!(
            "Device [{}] presents a different identity key — possibly impersonation or the peer has reset its identity. Re-pair or revoke?",
            self.device_fingerprint
        )
    }
}
