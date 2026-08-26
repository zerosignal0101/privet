use std::sync::Arc;

use privet_crypto::identity::Identity;
use privet_transport::tls::TlsMaterial;
use privet_transport::{QuicTransport, TcpTransport};

use crate::config::EngineConfig;
use crate::Result;

pub fn build_tls_material(identity: &Identity) -> Result<TlsMaterial> {
    let stored = identity.to_stored()?;
    Ok(TlsMaterial::new(
        identity.cert_der().to_vec(),
        stored.signing_key_pkcs8.to_vec(),
    ))
}

pub fn build_transports(
    config: &EngineConfig,
    material: TlsMaterial,
) -> Result<(Arc<QuicTransport>, Arc<TcpTransport>)> {
    config
        .pairing
        .validate()
        .map_err(crate::CoreError::Internal)?;
    let mut transport_config = config.transport.clone();
    transport_config.pairing_exporter = Some(privet_transport::config::PairingExporterLabel {
        label: config.pairing.pairing_binding_label.as_bytes().to_vec(),
        context: privet_security::constants::PAIRING_CONTEXT_STRING
            .as_bytes()
            .to_vec(),
    });
    let quic = Arc::new(QuicTransport::new(
        material.clone(),
        transport_config.clone(),
    ));
    let tcp = Arc::new(TcpTransport::new(material, transport_config));
    Ok((quic, tcp))
}
