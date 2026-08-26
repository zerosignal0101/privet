//! Identity -> TlsMaterial -> QuicTransport/TcpTransport 拼装
use std::sync::Arc;

use privet_crypto::identity::Identity;
use privet_transport::tls::TlsMaterial;
use privet_transport::{QuicTransport, TcpTransport};

use crate::config::EngineConfig;
use crate::Result;

/// 从 Identity 拼装 TLS 材料：证书 DER + PKCS8 私钥。
pub fn build_tls_material(identity: &Identity) -> Result<TlsMaterial> {
    let stored = identity.to_stored()?;
    Ok(TlsMaterial::new(
        identity.cert_der().to_vec(),
        stored.signing_key_pkcs8.to_vec(),
    ))
}

/// 构造 QUIC + TCP 传输（共享同一 TLS 材料 = 同一身份证书）。
pub fn build_transports(
    config: &EngineConfig,
    material: TlsMaterial,
) -> Result<(Arc<QuicTransport>, Arc<TcpTransport>)> {
    let quic = Arc::new(QuicTransport::new(
        material.clone(),
        config.transport.clone(),
    ));
    let tcp = Arc::new(TcpTransport::new(material, config.transport.clone()));
    Ok((quic, tcp))
}
