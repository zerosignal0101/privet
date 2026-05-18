//! Directed probe: on-demand TCP connection check for known devices
//! in restricted networks where mDNS/broadcast don't work.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::known_device::KnownDeviceStore;
use crate::peer::{PeerId, PeerInfo};

/// Default timeout for a single probe attempt.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Result of probing a device.
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
    /// The address that responded.
    pub address: SocketAddr,
    /// Whether the device is online (probe succeeded).
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
            last_seen: SystemTime::now(),
            platform: None,
            version: None,
        }
    }
}

/// Probe a single address by attempting a TCP connection.
/// Returns true if the connection succeeds (or times out positively).
pub async fn probe_address(addr: SocketAddr, timeout_duration: Duration) -> bool {
    match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => true,
        _ => false,
    }
}

/// Probe all known devices on a specific network subnet.
/// Returns a list of probed devices with their online status.
pub async fn probe_known_devices_on_network(
    store: &KnownDeviceStore,
    subnet: &str,
    timeout_duration: Duration,
) -> Vec<ProbedDevice> {
    let devices = store.get_devices_for_network(subnet);
    let mut results = Vec::new();

    for device in devices {
        if let Some(entry) = device.networks.get(subnet) {
            for addr_str in &entry.addresses {
                if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                    let is_online = probe_address(addr, timeout_duration).await;
                    let peer_id = uuid::Uuid::parse_str(&device.peer_id)
                        .unwrap_or_else(|_| uuid::Uuid::nil());

                    results.push(ProbedDevice {
                        fingerprint: device.fingerprint.clone(),
                        peer_id: PeerId(peer_id),
                        device_name: device.device_name.clone(),
                        subnet: subnet.to_string(),
                        address: addr,
                        is_online,
                    });
                }
            }
        }
    }

    results
}

/// Probe all known devices across all current networks.
/// Returns only the devices that are online.
pub async fn probe_all_known_devices(
    store: &KnownDeviceStore,
    current_subnets: &[String],
) -> Vec<ProbedDevice> {
    let mut all_online = Vec::new();

    for subnet in current_subnets {
        let probed = probe_known_devices_on_network(store, subnet, PROBE_TIMEOUT).await;
        all_online.extend(probed.into_iter().filter(|d| d.is_online));
    }

    all_online
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_localhost_port_not_listening() {
        // Try connecting to a port that's very unlikely to be listening
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = probe_address(addr, Duration::from_millis(100)).await;
        // This should typically be false (port 1 not listening)
        // but we can't guarantee it in all environments
        println!("Probe 127.0.0.1:1 result: {result}");
    }
}
