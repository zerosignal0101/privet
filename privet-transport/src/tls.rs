
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{Result, TransportError};

#[derive(Clone)]
pub struct TlsMaterial {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key_pkcs8: Vec<u8>,
}

impl TlsMaterial {
    pub fn new(cert_der: Vec<u8>, key_pkcs8: Vec<u8>) -> Self {
        Self {
            cert_chain: vec![CertificateDer::from(cert_der)],
            key_pkcs8,
        }
    }
}

fn ensure_ring_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
struct AcceptAnyClientCert;

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

pub fn build_server_config(mat: &TlsMaterial) -> Result<rustls::ServerConfig> {
    if mat.cert_chain.is_empty() {
        return Err(TransportError::TlsMaterial("empty cert chain".into()));
    }
    ensure_ring_provider();
    let key = PrivateKeyDer::Pkcs8(mat.key_pkcs8.clone().into());
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyClientCert))
        .with_single_cert(mat.cert_chain.clone(), key)
        .map_err(|e| TransportError::TlsMaterial(e.to_string()))
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

pub fn build_client_config(mat: &TlsMaterial) -> Result<rustls::ClientConfig> {
    ensure_ring_provider();
    let key = PrivateKeyDer::Pkcs8(mat.key_pkcs8.clone().into());
    let client = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_client_auth_cert(mat.cert_chain.clone(), key)
        .map_err(|e| TransportError::TlsMaterial(e.to_string()))?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tls_material() -> TlsMaterial {
        use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
        let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec![]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        TlsMaterial::new(cert.der().to_vec(), kp.serialize_der())
    }

    #[test]
    fn builds_server_and_client_config_from_test_cert() {
        let mat = test_tls_material();
        let server = build_server_config(&mat).expect("server config");
        let client = build_client_config(&mat).expect("client config");
        let _ = server.max_fragment_size;
        let _ = client.resumption;
    }

    #[test]
    fn rejects_empty_cert() {
        let mat = TlsMaterial {
            cert_chain: vec![],
            key_pkcs8: vec![1, 2, 3],
        };
        assert!(build_server_config(&mat).is_err());
    }
}