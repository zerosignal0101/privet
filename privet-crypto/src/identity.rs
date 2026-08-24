//! Ed25519 设备身份 + 自签 X.509 证书。

use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::constants::CERT_VALIDITY_YEARS;
use crate::error::CryptoError;
use crate::hash::fingerprint_hex;

pub struct Identity {
    signing_key: SigningKey,
    spki_der: Vec<u8>,
    cert_der: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Self, CryptoError> {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| CryptoError::Certificate(e.to_string()))?;
        let pkcs8 = kp.serialize_der();
        let signing_key = SigningKey::from_pkcs8_der(&pkcs8)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let spki_der = kp.public_key_der();
        let cert_der = build_self_signed_cert(&kp)?;
        Ok(Self {
            signing_key,
            spki_der,
            cert_der,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }
    pub fn fingerprint(&self) -> String {
        fingerprint_hex(&self.spki_der)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        self.signing_key.sign(msg)
    }

    pub fn verify(spki_der: &[u8], msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        use ed25519_dalek::Verifier;
        let vk = VerifyingKey::from_public_key_der(spki_der)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        vk.verify(msg, sig)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    /// 序列化为可存储形态（PKCS8 私钥 + SPKI + 证书 + device_id）。
    pub fn to_stored(&self) -> Result<crate::keystore::StoredIdentity, CryptoError> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let pkcs8 = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| CryptoError::Encoding(e.to_string()))?;
        Ok(crate::keystore::StoredIdentity {
            // 私钥 drop 时清零
            signing_key_pkcs8: Zeroizing::new(pkcs8.as_bytes().to_vec()),
            spki_der: self.spki_der.clone(),
            cert_der: self.cert_der.clone(),
        })
    }

    /// 从存储形态重建身份。PKCS8 派生公钥解码自存储 SPKI 后须与签名密钥公钥一致（防御）。
    pub fn from_stored(s: &crate::keystore::StoredIdentity) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_pkcs8_der(s.signing_key_pkcs8.as_ref())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let stored_vk = VerifyingKey::from_public_key_der(&s.spki_der)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if stored_vk.to_bytes() != signing_key.verifying_key().to_bytes() {
            return Err(CryptoError::InvalidKey("stored SPKI mismatch".into()));
        }
        Ok(Self {
            signing_key,
            spki_der: s.spki_der.clone(),
            cert_der: s.cert_der.clone(),
        })
    }
}

fn build_self_signed_cert(kp: &rcgen::KeyPair) -> Result<Vec<u8>, CryptoError> {
    use rcgen::CertificateParams;
    let mut params =
        CertificateParams::new(vec![]).map_err(|e| CryptoError::Certificate(e.to_string()))?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(365 * CERT_VALIDITY_YEARS);
    let cert = params
        .self_signed(kp)
        .map_err(|e| CryptoError::Certificate(e.to_string()))?;
    Ok(cert.der().to_vec())
}
