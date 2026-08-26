
use std::time::Duration;

use privet_protocol::{Beacon, Goodbye, Probe};
use prost::Message;

use crate::constants::{BEACON_TTL};
use crate::error::{DiscoveryError, Result};

const TAG_BEACON: u8 = 1;
const TAG_PROBE: u8 = 2;
const TAG_GOODBYE: u8 = 3;

pub fn message_tag(bytes: &[u8]) -> Option<u8> {
    bytes.first().copied()
}

pub fn encode_beacon(b: &Beacon) -> Result<Vec<u8>> {
    Ok(b.encode_to_vec())
}
pub fn decode_beacon(bytes: &[u8]) -> Result<Beacon> {
    Beacon::decode(bytes).map_err(DiscoveryError::Decode)
}
pub fn encode_beacon_tagged(b: &Beacon) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + b.encoded_len());
    out.push(TAG_BEACON);
    b.encode(&mut out).expect("in-memory encode");
    Ok(out)
}
pub fn decode_beacon_tagged(bytes: &[u8]) -> Result<Beacon> {
    if bytes.first() != Some(&TAG_BEACON) {
        return Err(DiscoveryError::Decode(prost::DecodeError::new(
            "not a beacon tag",
        )));
    }
    Beacon::decode(&bytes[1..]).map_err(DiscoveryError::Decode)
}

pub fn encode_probe(p: &Probe) -> Result<Vec<u8>> {
    Ok(p.encode_to_vec())
}
pub fn decode_probe(bytes: &[u8]) -> Result<Probe> {
    Probe::decode(bytes).map_err(DiscoveryError::Decode)
}
pub fn encode_probe_tagged(p: &Probe) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + p.encoded_len());
    out.push(TAG_PROBE);
    p.encode(&mut out).expect("in-memory encode");
    Ok(out)
}
pub fn decode_probe_tagged(bytes: &[u8]) -> Result<Probe> {
    if bytes.first() != Some(&TAG_PROBE) {
        return Err(DiscoveryError::Decode(prost::DecodeError::new(
            "not a probe tag",
        )));
    }
    Probe::decode(&bytes[1..]).map_err(DiscoveryError::Decode)
}

pub fn encode_goodbye(g: &Goodbye) -> Result<Vec<u8>> {
    Ok(g.encode_to_vec())
}
pub fn decode_goodbye(bytes: &[u8]) -> Result<Goodbye> {
    Goodbye::decode(bytes).map_err(DiscoveryError::Decode)
}
pub fn encode_goodbye_tagged(g: &Goodbye) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + g.encoded_len());
    out.push(TAG_GOODBYE);
    g.encode(&mut out).expect("in-memory encode");
    Ok(out)
}
pub fn decode_goodbye_tagged(bytes: &[u8]) -> Result<Goodbye> {
    if bytes.first() != Some(&TAG_GOODBYE) {
        return Err(DiscoveryError::Decode(prost::DecodeError::new(
            "not a goodbye tag",
        )));
    }
    Goodbye::decode(&bytes[1..]).map_err(DiscoveryError::Decode)
}

pub fn validate_beacon(b: &Beacon, now_ms: u64) -> Result<()> {
    if b.device_fingerprint.len() != 2 * 32
        || !b.device_fingerprint.chars().all(|c| c.is_ascii_hexdigit())
    {
        println!("bad device_fingerprint: {}", b.device_fingerprint);
        return Err(DiscoveryError::BeaconInvalid(format!(
            "bad device_fingerprint: {}",
            b.device_fingerprint
        )));
    }
    if b.nonce.is_empty() {
        return Err(DiscoveryError::BeaconInvalid("empty nonce".into()));
    }
    if now_ms > b.ts_ms && now_ms - b.ts_ms > BEACON_TTL.as_millis() as u64 {
        return Err(DiscoveryError::BeaconExpired);
    }
    if b.ts_ms > now_ms && b.ts_ms - now_ms > BEACON_TTL.as_millis() as u64 {
        return Err(DiscoveryError::BeaconExpired);
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct BeaconView {
    pub device_name: String,
    pub platform: String,
    pub proto_version: u32,
    pub capabilities: Vec<String>,
    pub device_fingerprint: String,
    pub quic_port: u16,
    pub tcp_port: u16,
    pub nonce: Vec<u8>,
    pub ts_ms: u64,
}

impl BeaconView {
    pub fn from_beacon(b: &Beacon) -> Self {
        Self {
            device_name: b.device_name.clone(),
            platform: b.platform.clone(),
            proto_version: b.proto_version,
            capabilities: b.capabilities.clone(),
            device_fingerprint: b.device_fingerprint.clone(),
            quic_port: b.quic_port as u16,
            tcp_port: b.tcp_port as u16,
            nonce: b.nonce.clone(),
            ts_ms: b.ts_ms,
        }
    }
}

#[allow(dead_code)]
fn _ttl_hint() -> Duration {
    BEACON_TTL
}

#[cfg(test)]
mod tests {
    use super::*;
    use privet_protocol::{Beacon, Goodbye, Probe};

    fn sample_beacon(ts_ms: u64) -> Beacon {
        Beacon {
            device_name: "alice".into(),
            platform: "linux".into(),
            proto_version: 1,
            capabilities: vec!["quic".into()],
            device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            quic_port: 47808,
            tcp_port: 47810,
            nonce: b"0123456789abcdef".to_vec(),
            ts_ms,
        }
    }

    #[test]
    fn beacon_roundtrip() {
        let b = sample_beacon(1_700_000_000_000);
        let bytes = encode_beacon(&b).unwrap();
        let got = decode_beacon(&bytes).unwrap();
        assert_eq!(got.device_name, "alice");
        assert_eq!(got.device_fingerprint, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert_eq!(got.quic_port, 47808);
        assert_eq!(got.nonce, b"0123456789abcdef");
    }

    #[test]
    fn validate_accepts_fresh_beacon() {
        let b = sample_beacon(1_700_000_000_000);
        assert!(validate_beacon(&b, 1_700_000_000_000).is_ok());
    }

    #[test]
    fn validate_rejects_expired_beacon() {
        let b = sample_beacon(1_700_000_000_000);
        assert!(validate_beacon(&b, 1_700_000_000_000 + 31_000).is_err());
    }

    #[test]
    fn validate_rejects_bad_device_fingerprint_length() {
        let mut b = sample_beacon(1_700_000_000_000);
        b.device_fingerprint = "deadbe".into(); // 6 hex = 3 bytes != 4
        assert!(validate_beacon(&b, 1_700_000_000_000).is_err());
    }

    #[test]
    fn probe_and_goodbye_roundtrip() {
        let p = Probe {
            nonce: b"n1".to_vec(),
            ts_ms: 42,
        };
        assert_eq!(decode_probe(&encode_probe(&p).unwrap()).unwrap().ts_ms, 42);
        let g = Goodbye {
            device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        };
        assert_eq!(
            decode_goodbye(&encode_goodbye(&g).unwrap())
                .unwrap()
                .device_fingerprint,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
    }
}
