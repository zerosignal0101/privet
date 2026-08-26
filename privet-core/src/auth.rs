//! conn_auth 编排：提取 peer SPKI + TLS exporter -> SessionInputs；钉扎分支。
use privet_security::cert::{extract_spki, ConnAuthAction};
use privet_security::conn_auth::{build_alert, conn_auth};
use privet_security::constants::{EXPORTER_LEN, PAIRING_BINDING_LABEL, PAIRING_CONTEXT_STRING};
use privet_security::session::SessionInputs;
use privet_security::trust::TrustStore;
use privet_transport::Connection;

use crate::Result;

/// 从连接提取 SessionInputs（peer SPKI 来自证书；exporter 来自 TLS）。
pub fn peer_session_inputs(
    conn: &dyn Connection,
    code: String,
    peer_device_fingerprint: String,
    peer_device_name: String,
) -> Result<SessionInputs> {
    let cert_der = conn
        .peer_cert_der()
        .ok_or_else(|| crate::CoreError::Internal("peer cert unavailable".into()))?;
    let peer_spki = extract_spki(&cert_der)?;
    let exporter_bytes = conn.export_keying_material(
        PAIRING_BINDING_LABEL.as_bytes(),
        Some(PAIRING_CONTEXT_STRING.as_bytes()),
    )?;
    let mut exporter = [0u8; EXPORTER_LEN];
    let n = exporter_bytes.len().min(EXPORTER_LEN);
    exporter[..n].copy_from_slice(&exporter_bytes[..n]);
    Ok(SessionInputs {
        code,
        peer_device_fingerprint,
        peer_device_name,
        peer_spki,
        exporter,
    })
}

/// 钉扎分支计划。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPlan {
    /// 已配对 + SPKI 一致 -> 免码直连。
    AcceptCodeless,
    /// 未知 -> 触发配对。
    TriggerPairing,
    /// Revoked -> 静默拒。
    Reject,
    /// SPKI 不符 -> 失败关闭告警。
    FailClosedAlert,
}

pub fn decide_auth(
    peer_spki: &[u8],
    peer_device_fingerprint: &str,
    trust: &dyn TrustStore,
) -> Result<AuthPlan> {
    let action = conn_auth(peer_spki, peer_device_fingerprint, trust)?;
    Ok(match action {
        ConnAuthAction::AcceptCodeless => AuthPlan::AcceptCodeless,
        ConnAuthAction::TriggerPairing => AuthPlan::TriggerPairing,
        ConnAuthAction::Reject => AuthPlan::Reject,
        ConnAuthAction::FailClosedAlert => {
            let _alert = build_alert(peer_spki, peer_device_fingerprint, trust)?;
            AuthPlan::FailClosedAlert
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use privet_security::trust::{InMemoryTrustStore, PeerTrust, TrustStore};

    fn fake_inputs() -> SessionInputs {
        SessionInputs {
            code: "123456".into(),
            peer_device_fingerprint: "dev1".into(),
            peer_device_name: "peer".into(),
            peer_spki: vec![1, 2, 3],
            exporter: [0u8; 32],
        }
    }

    #[test]
    fn plan_unknown_triggers_pairing() {
        let trust = InMemoryTrustStore::new();
        let inputs = fake_inputs();
        let plan = decide_auth(&inputs.peer_spki, &inputs.peer_device_fingerprint, &trust).unwrap();
        assert_eq!(plan, AuthPlan::TriggerPairing);
    }

    #[test]
    fn plan_trusted_codeless() {
        let trust = InMemoryTrustStore::new();
        let inputs = fake_inputs();
        trust
            .commit_peer(PeerTrust {
                device_fingerprint: inputs.peer_device_fingerprint.clone(),
                peer_spki: inputs.peer_spki.clone(),
                peer_device_name: "p".into(),
                share_with_peers: false,
                first_paired_ts: 1,
                last_seen_ts: 1,
            })
            .unwrap();
        let plan = decide_auth(&inputs.peer_spki, &inputs.peer_device_fingerprint, &trust).unwrap();
        assert_eq!(plan, AuthPlan::AcceptCodeless);
    }

    #[test]
    fn plan_key_mismatch_fail_closed() {
        let trust = InMemoryTrustStore::new();
        let inputs = fake_inputs();
        trust
            .commit_peer(PeerTrust {
                device_fingerprint: inputs.peer_device_fingerprint.clone(),
                peer_spki: vec![9, 9, 9],
                peer_device_name: "p".into(),
                share_with_peers: false,
                first_paired_ts: 1,
                last_seen_ts: 1,
            })
            .unwrap();
        let plan = decide_auth(&inputs.peer_spki, &inputs.peer_device_fingerprint, &trust).unwrap();
        assert_eq!(plan, AuthPlan::FailClosedAlert);
    }
}
