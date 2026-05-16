use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::error::DiscoveryError;

const BEACON_INTERVAL: Duration = Duration::from_secs(2);

/// UDP beacon: broadcast presence on port 53531.
pub struct Beacon {
    socket: UdpSocket,
    port: u16,
    device_name: String,
    listen_port: u16,
}

impl Beacon {
    pub fn new(port: u16, device_name: String, listen_port: u16) -> Result<Self, DiscoveryError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| DiscoveryError::Beacon(format!("bind: {e}")))?;
        socket.set_broadcast(true)
            .map_err(|e| DiscoveryError::Beacon(format!("set broadcast: {e}")))?;

        Ok(Self {
            socket,
            port,
            device_name,
            listen_port,
        })
    }

    /// Send a beacon broadcast announcing this device.
    pub fn announce(&self) -> Result<(), DiscoveryError> {
        let msg = BeaconMessage {
            device_name: self.device_name.clone(),
            listen_port: self.listen_port,
        };
        let data = serde_json::to_vec(&msg)
            .map_err(|e| DiscoveryError::Beacon(format!("serialize: {e}")))?;

        let addr = format!("255.255.255.255:{}", self.port);
        self.socket
            .send_to(&data, addr)
            .map_err(|e| DiscoveryError::Beacon(format!("send: {e}")))?;

        Ok(())
    }

    /// Listen for beacon broadcasts from other devices.
    pub fn listen(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), DiscoveryError> {
        self.socket
            .recv_from(buf)
            .map_err(|e| DiscoveryError::Beacon(format!("recv: {e}")))
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BeaconMessage {
    pub device_name: String,
    pub listen_port: u16,
}
