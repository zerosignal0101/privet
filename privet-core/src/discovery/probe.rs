//! Identity probe: verify a device's fingerprint via QUIC/TCP+TLS handshake.
//!
//! Unlike the old TCP ping (`0x00` marker byte), this actually establishes a
//! connection, performs the Hello/HelloAck handshake, and verifies that the
//! remote TLS certificate fingerprint matches the expected identity.

use std::net::SocketAddr;
use std::time::Duration;

use crate::known_device::KnownDeviceStore;
use crate::peer::{PeerId, PeerInfo};

/// Default timeout for probing a single device address.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Result of probing a single device address.
#[derive(Clone, Debug)]
pub struct ProbedDevice {
    /// The fingerprint of the probed device.
    pub fingerprint: String,
    /// The peer ID of the probed device.
    pub peer_id: PeerId,
    /// The device name.
    pub device_name: String,
    /// The subnet where the device was found.
    pub subnet: String,
    /// The address that responded (with correct identity).
    pub address: SocketAddr,
    /// Whether the probe succeeded AND identity matched.
    pub is_online: bool,
}

impl ProbedDevice {
    /// Convert a probed device into a PeerInfo for use in the discovery system.
    pub fn to_peer_info(&self, is_trusted: bool) -> PeerInfo {
        PeerInfo {
            id: self.peer_id.clone(),
            name: self.device_name.clone(),
            addresses: vec![self.address],
            fingerprint: self.fingerprint.clone(),
            is_trusted,
            last_seen: std::time::SystemTime::now(),
            platform: None,
            version: None,
        }
    }
}

/// Get all known device entries that have addresses on the given subnets.
/// Returns a flat list of `(fingerprint, subnet, addr)` tuples with owned strings
/// so the caller can release the store lock before iterating.
pub fn known_device_targets(
    store: &KnownDeviceStore,
    current_subnets: &[String],
) -> Vec<(String, String, SocketAddr)> {
    let mut targets = Vec::new();
    for subnet in current_subnets {
        let devices = store.get_devices_for_network(subnet);
        for device in &devices {
            if let Some(entry) = device.networks.get(subnet) {
                for addr_str in &entry.addresses {
                    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                        targets.push((device.fingerprint.clone(), subnet.clone(), addr));
                    }
                }
            }
        }
    }
    targets
}
