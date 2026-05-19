use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls;

use crate::error::SecurityError;
use crate::security::cert::fingerprint_from_der;
use crate::security::identity::DeviceIdentity;

/// Build a rustls ServerConfig that requires mTLS (client cert required).
pub fn build_server_config(
    identity: &DeviceIdentity,
    _trusted_fingerprints: &[String],
) -> Result<Arc<rustls::ServerConfig>, SecurityError> {
    let (cert_chain, key) = load_cert_and_key(identity)?;

    let client_verifier = Arc::new(PrivetClientVerifier {});

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| SecurityError::Tls(format!("build server config: {e}")))?;

    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig for connecting to a peer.
pub fn build_client_config(
    identity: &DeviceIdentity,
    _trusted_fingerprints: &[String],
) -> Result<Arc<rustls::ClientConfig>, SecurityError> {
    let (cert_chain, key) = load_cert_and_key(identity)?;

    let server_verifier = Arc::new(PrivetServerVerifier {});

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|e| SecurityError::Tls(format!("build client config: {e}")))?;

    Ok(Arc::new(config))
}

fn load_cert_and_key(
    identity: &DeviceIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), SecurityError> {
    let cert_chain = rustls_pemfile::certs(&mut identity.cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| SecurityError::Certificate(format!("parse cert pem: {e}")))?;

    let key = rustls_pemfile::private_key(&mut identity.key_pem.as_bytes())
        .map_err(|e| SecurityError::Certificate(format!("parse key pem: {e}")))?
        .ok_or_else(|| SecurityError::Certificate("no private key found".into()))?;

    Ok((cert_chain, key))
}

/// Build a rustls ServerConfig for TCP+TLS with mandatory client cert.
/// Unlike the QUIC server config, this requires the client to present a
/// certificate, preventing MITM from connecting without one.
pub fn build_tcp_server_config(
    identity: &DeviceIdentity,
) -> Result<Arc<rustls::ServerConfig>, SecurityError> {
    let (cert_chain, key) = load_cert_and_key(identity)?;

    let client_verifier = Arc::new(PrivetTcpClientVerifier {});

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| SecurityError::Tls(format!("build tcp server config: {e}")))?;

    Ok(Arc::new(config))
}

// --- Custom mTLS client cert verifier for server side ---

#[derive(Debug)]
struct PrivetClientVerifier;

impl rustls::server::danger::ClientCertVerifier for PrivetClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true // Require client cert — reject MITM without one
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let _fp = fingerprint_from_der(end_entity.as_ref());
        // Accept all certs — trust/pairing is handled at the app layer.
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let prov = rustls::crypto::CryptoProvider::get_default()
            .expect("crypto provider not installed");
        let crypto = &prov.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, crypto)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let prov = rustls::crypto::CryptoProvider::get_default()
            .expect("crypto provider not installed");
        let crypto = &prov.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, crypto)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

/// Same as PrivetClientVerifier but with mandatory client auth.
/// Used for TCP+TLS where we want to reject clients without certs.
#[derive(Debug)]
struct PrivetTcpClientVerifier;

impl rustls::server::danger::ClientCertVerifier for PrivetTcpClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true // Require client cert — reject MITM without one
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Accept all certs at the TLS layer — trust verified at app layer
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let prov = rustls::crypto::CryptoProvider::get_default()
            .expect("crypto provider not installed");
        let crypto = &prov.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, crypto)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let prov = rustls::crypto::CryptoProvider::get_default()
            .expect("crypto provider not installed");
        let crypto = &prov.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, crypto)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

// --- Custom server cert verifier for client side ---

#[derive(Debug)]
struct PrivetServerVerifier;

impl rustls::client::danger::ServerCertVerifier for PrivetServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let _fp = fingerprint_from_der(end_entity.as_ref());
        // Accept any self-signed cert — trust handled at the app layer.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let prov = rustls::crypto::CryptoProvider::get_default()
            .expect("crypto provider not installed");
        let crypto = &prov.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, crypto)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let prov = rustls::crypto::CryptoProvider::get_default()
            .expect("crypto provider not installed");
        let crypto = &prov.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, crypto)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::io::duplex;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::security::identity::DeviceIdentity;

    #[tokio::test]
    async fn test_tls_handshake_over_duplex() {
        let dir = tempfile::tempdir().unwrap();

        let client_id = DeviceIdentity::generate(
            "tls-test-client".into(),
            dir.path().join("client-id"),
            10,
        )
        .expect("client identity");
        let server_id = DeviceIdentity::generate(
            "tls-test-server".into(),
            dir.path().join("server-id"),
            10,
        )
        .expect("server identity");

        let server_cfg = super::build_tcp_server_config(&server_id).expect("server config");
        let client_cfg = super::build_client_config(&client_id, &[]).expect("client config");

        let (client_stream, server_stream) = duplex(64 * 1024);

        let acceptor = TlsAcceptor::from(server_cfg);
        let connector = TlsConnector::from(client_cfg);

        let server_name = rustls::pki_types::ServerName::try_from("privet")
            .expect("server name");

        let server_handle = tokio::spawn(async move {
            acceptor.accept(server_stream).await
        });

        let start = std::time::Instant::now();
        let client_result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            connector.connect(server_name, client_stream),
        )
        .await;

        let elapsed = start.elapsed();

        match client_result {
            Ok(Ok(_tls_stream)) => {
                eprintln!(
                    "TLS duplex handshake completed in {}ms",
                    elapsed.as_millis()
                );
            }
            Ok(Err(e)) => {
                panic!("TLS client handshake failed: {e}");
            }
            Err(_) => {
                panic!(
                    "TLS client handshake timed out after {}ms",
                    elapsed.as_millis()
                );
            }
        }

        let _ = server_handle.await.expect("server task panicked");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_tls_handshake_over_tcp() {
        let dir = tempfile::tempdir().unwrap();

        let client_id = DeviceIdentity::generate(
            "tcp-tls-client".into(),
            dir.path().join("tcp-tls-client-id"),
            10,
        )
        .expect("client identity");
        let server_id = DeviceIdentity::generate(
            "tcp-tls-server".into(),
            dir.path().join("tcp-tls-server-id"),
            10,
        )
        .expect("server identity");

        let server_cfg = super::build_tcp_server_config(&server_id).expect("server config");
        let client_cfg = super::build_client_config(&client_id, &[]).expect("client config");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let acceptor = TlsAcceptor::from(server_cfg);
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            acceptor.accept(stream).await
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect");

        let connector = TlsConnector::from(client_cfg);
        let server_name = rustls::pki_types::ServerName::try_from("privet")
            .expect("server name");

        let start = std::time::Instant::now();
        let client_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            connector.connect(server_name, stream),
        )
        .await;

        let elapsed = start.elapsed();

        match client_result {
            Ok(Ok(_tls_stream)) => {
                eprintln!(
                    "TLS TCP loopback handshake completed in {}ms",
                    elapsed.as_millis()
                );
            }
            Ok(Err(e)) => {
                panic!("TLS TCP handshake failed: {e}");
            }
            Err(_) => {
                panic!(
                    "TLS TCP handshake timed out after {}ms",
                    elapsed.as_millis()
                );
            }
        }

        let _ = server_handle.await.expect("server task panicked");
    }

    /// Test: TCP connect → wait N seconds → TLS handshake.
    /// If this fails with os error 10053, the delay triggers Windows security software.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_tls_handshake_with_delays() {
        let dir = tempfile::tempdir().unwrap();

        let client_id = DeviceIdentity::generate(
            "delay-client".into(), dir.path().join("dc"), 10,
        ).unwrap();
        let server_id = DeviceIdentity::generate(
            "delay-server".into(), dir.path().join("ds"), 10,
        ).unwrap();

        let server_cfg = super::build_tcp_server_config(&server_id).unwrap();
        let client_cfg = super::build_client_config(&client_id, &[]).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let acceptor = TlsAcceptor::from(server_cfg);
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Server also delays before TLS
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            acceptor.accept(stream).await
        });

        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        eprintln!("TCP connected, waiting 2s before TLS...");

        // Wait before starting TLS handshake — simulates the engine path delay
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        eprintln!("Starting TLS handshake...");

        let start = std::time::Instant::now();
        let client_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TlsConnector::from(client_cfg).connect(
                rustls::pki_types::ServerName::try_from("privet").unwrap(),
                tcp_stream,
            ),
        )
        .await;

        let elapsed = start.elapsed();

        match client_result {
            Ok(Ok(_)) => eprintln!("TLS with delay succeeded in {}ms", elapsed.as_millis()),
            Ok(Err(e)) => panic!("TLS with delay FAILED after {}ms: {e}", elapsed.as_millis()),
            Err(_) => panic!("TLS with delay TIMED OUT after {}ms", elapsed.as_millis()),
        }

        server_handle.await.unwrap().unwrap();
    }
}
