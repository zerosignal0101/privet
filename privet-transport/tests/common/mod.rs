/// 生成 throwaway 自签 Ed25519 证书 + 密钥（测试用）。
pub fn test_tls_material() -> privet_transport::tls::TlsMaterial {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let params = CertificateParams::new(vec![]).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    privet_transport::tls::TlsMaterial::new(cert.der().to_vec(), kp.serialize_der())
}
