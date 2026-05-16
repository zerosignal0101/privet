use rcgen::{CertificateParams, DnType, KeyPair, IsCa, BasicConstraints};
use sha2::{Digest, Sha256};

/// Generate a self-signed certificate and key pair.
/// Returns (cert_pem, key_pem, fingerprint_hex).
pub fn generate_self_signed(
    device_name: &str,
    validity_years: u32,
) -> Result<(String, String, String), crate::error::SecurityError> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, device_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "privet");

    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(
        2024 + validity_years as i32,
        1,
        1,
    );

    // Self-signed CA so it can sign other certs if needed later
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let key_pair = KeyPair::generate()
        .map_err(|e| crate::error::SecurityError::Certificate(format!("generate key: {e}")))?;

    let cert = params.self_signed(&key_pair)
        .map_err(|e| crate::error::SecurityError::Certificate(format!("self-sign cert: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let fingerprint = fingerprint_from_der(cert.der());

    Ok((cert_pem, key_pem, fingerprint))
}

/// Compute SHA-256 fingerprint from DER-encoded certificate bytes.
pub fn fingerprint_from_der(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute fingerprint from PEM-encoded certificate.
pub fn fingerprint_from_pem(pem: &str) -> Result<String, crate::error::SecurityError> {
    let certs = rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| crate::error::SecurityError::Certificate(format!("parse pem: {e}")))?;

    let cert_der = certs
        .first()
        .ok_or_else(|| crate::error::SecurityError::Certificate("no cert in pem".into()))?;

    Ok(fingerprint_from_der(cert_der.as_ref()))
}
