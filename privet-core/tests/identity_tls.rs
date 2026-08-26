use privet_core::identity_tls::{build_tls_material, build_transports};
use privet_core::EngineConfig;
use privet_crypto::identity::Identity;

#[test]
fn tls_material_from_identity() {
    let id = Identity::generate().unwrap();
    let mat = build_tls_material(&id).unwrap();
    assert!(!mat.cert_chain.is_empty());
    assert!(!mat.key_pkcs8.is_empty());
}

#[test]
fn transports_build_from_config() {
    let id = Identity::generate().unwrap();
    let mat = build_tls_material(&id).unwrap();
    let cfg = EngineConfig::default();
    let (quic, tcp) = build_transports(&cfg, mat).unwrap();
    let _ = (quic, tcp);
}
