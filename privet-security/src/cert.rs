use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::trust::{TrustState, TrustStore};
use crate::PairingError;

pub fn extract_spki(cert_der: &[u8]) -> Result<Vec<u8>, PairingError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| PairingError::Protocol(format!("cert parse: {e}")))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| PairingError::Protocol(format!("spki encode: {e}")))?;
    Ok(spki_der)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinDecision {
    Unknown,
    Trusted,
    Revoked,
    KeyMismatch { stored_spki: Vec<u8> },
}

pub fn pin(
    peer_spki: &[u8],
    peer_device_id: &str,
    store: &dyn TrustStore,
) -> Result<PinDecision, PairingError> {
    match store.get(peer_device_id)? {
        None => Ok(PinDecision::Unknown),
        Some(r) => match r.trust_state {
            TrustState::Trusted => {
                if r.peer_spki == peer_spki {
                    Ok(PinDecision::Trusted)
                } else {
                    Ok(PinDecision::KeyMismatch {
                        stored_spki: r.peer_spki.clone(),
                    })
                }
            }
            TrustState::Revoked => Ok(PinDecision::Revoked),
            TrustState::Unknown => Ok(PinDecision::Unknown),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnAuthAction {
    AcceptCodeless,
    TriggerPairing,
    Reject,
    FailClosedAlert,
}

pub fn conn_auth_decision(d: PinDecision) -> ConnAuthAction {
    match d {
        PinDecision::Trusted => ConnAuthAction::AcceptCodeless,
        PinDecision::Unknown => ConnAuthAction::TriggerPairing,
        PinDecision::Revoked => ConnAuthAction::Reject,
        PinDecision::KeyMismatch { .. } => ConnAuthAction::FailClosedAlert,
    }
}
