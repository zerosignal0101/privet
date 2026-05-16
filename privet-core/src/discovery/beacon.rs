use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use crate::error::DiscoveryError;
use crate::peer::PeerId;

/// Interval between beacon announcements.
pub const BEACON_INTERVAL: Duration = Duration::from_secs(2);

/// Message broadcast by the UDP beacon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconMessage {
    pub peer_id: uuid::Uuid,
    pub device_name: String,
    pub listen_port: u16,
    pub fingerprint: String,
}

/// A UDP beacon that announces this device's presence and listens for peers.
pub struct Beacon {
    socket: UdpSocket,
    beacon_port: u16,
    msg: BeaconMessage,
}

impl Beacon {
    /// Create a new beacon bound to `0.0.0.0:{beacon_port}` with broadcast enabled.
    pub async fn new(
        beacon_port: u16,
        peer_id: PeerId,
        device_name: String,
        listen_port: u16,
        fingerprint: String,
    ) -> Result<Self, DiscoveryError> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{beacon_port}"))
            .await
            .map_err(|e| DiscoveryError::Beacon(format!("bind: {e}")))?;
        socket
            .set_broadcast(true)
            .map_err(|e| DiscoveryError::Beacon(format!("set broadcast: {e}")))?;

        let msg = BeaconMessage {
            peer_id: peer_id.0,
            device_name,
            listen_port,
            fingerprint,
        };

        Ok(Self {
            socket,
            beacon_port,
            msg,
        })
    }

    /// Broadcast our presence to the beacon port on `255.255.255.255`.
    pub async fn announce(&self) -> Result<(), DiscoveryError> {
        let data = serde_json::to_vec(&self.msg)
            .map_err(|e| DiscoveryError::Beacon(format!("serialize: {e}")))?;

        let addr = format!("255.255.255.255:{}", self.beacon_port);
        self.socket
            .send_to(&data, &addr)
            .await
            .map_err(|e| DiscoveryError::Beacon(format!("send: {e}")))?;

        Ok(())
    }

    /// Send our beacon message to a specific address (useful for testing).
    pub async fn send_to(&self, target: SocketAddr) -> Result<(), DiscoveryError> {
        let data = serde_json::to_vec(&self.msg)
            .map_err(|e| DiscoveryError::Beacon(format!("serialize: {e}")))?;

        self.socket
            .send_to(&data, target)
            .await
            .map_err(|e| DiscoveryError::Beacon(format!("send_to: {e}")))?;

        Ok(())
    }

    /// Receive the next beacon message, filtering out self-broadcasts.
    ///
    /// Returns the deserialized [`BeaconMessage`] and the sender's socket address.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(BeaconMessage, SocketAddr), DiscoveryError> {
        loop {
            let (len, src) = self
                .socket
                .recv_from(buf)
                .await
                .map_err(|e| DiscoveryError::Beacon(format!("recv: {e}")))?;

            let msg: BeaconMessage = serde_json::from_slice(&buf[..len])
                .map_err(|e| DiscoveryError::Beacon(format!("deserialize: {e}")))?;

            // Filter out our own broadcasts by comparing peer_id
            if msg.peer_id == self.msg.peer_id {
                continue;
            }

            return Ok((msg, src));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerId;
    use uuid::Uuid;

    #[test]
    fn beacon_message_serde_roundtrip() {
        let msg = BeaconMessage {
            peer_id: Uuid::new_v4(),
            device_name: "test-device".into(),
            listen_port: 53530,
            fingerprint: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2".into(),
        };

        let bytes = serde_json::to_vec(&msg).expect("serialize");
        let deserialized: BeaconMessage = serde_json::from_slice(&bytes).expect("deserialize");

        assert_eq!(msg.peer_id, deserialized.peer_id);
        assert_eq!(msg.device_name, deserialized.device_name);
        assert_eq!(msg.listen_port, deserialized.listen_port);
        assert_eq!(msg.fingerprint, deserialized.fingerprint);
    }

    #[test]
    fn beacon_message_json_size() {
        let msg = BeaconMessage {
            peer_id: Uuid::nil(),
            device_name: "short-name".into(),
            listen_port: 53530,
            fingerprint: "ab".repeat(32),
        };

        let bytes = serde_json::to_vec(&msg).expect("serialize");
        // Should be well under the typical 1500-byte MTU
        assert!(bytes.len() < 200, "beacon message too large: {}", bytes.len());
    }

    #[tokio::test]
    async fn beacon_self_filter() {
        let port = pick_test_port();
        let peer_id = PeerId(Uuid::new_v4());

        let beacon = Beacon::new(
            port,
            peer_id,
            "self".into(),
            9999,
            "ffff".into(),
        )
        .await
        .expect("create beacon");

        // Send our own message to the same port — the recv loop should skip it.
        beacon.send_to(format!("127.0.0.1:{port}").parse().unwrap()).await.unwrap();

        // Try to recv with a short timeout. Since we're the only sender
        // and self-filtering discards our own message, recv should block.
        // We use tokio::time::timeout to confirm no message is returned.
        let mut buf = vec![0u8; 2048];
        let result = tokio::time::timeout(Duration::from_millis(300), beacon.recv(&mut buf)).await;

        match result {
            Ok(Ok((msg, _))) => panic!("expected self-filter to drop our own message, got {msg:?}"),
            Ok(Err(e)) => panic!("unexpected error: {e}"),
            Err(_) => { /* timeout = expected, message was filtered */ }
        }
    }

    #[tokio::test]
    async fn beacon_send_recv() {
        let port_a = pick_test_port();
        let port_b = pick_test_port();
        let peer_a = PeerId(Uuid::new_v4());
        let peer_b = PeerId(Uuid::new_v4());

        // Beacon A listens on port_a, will also send to B
        let beacon_a = Beacon::new(
            port_a,
            peer_a,
            "alice".into(),
            53530,
            "aaaa".into(),
        )
        .await
        .expect("create beacon A");

        // Beacon B listens on port_b
        let beacon_b = Beacon::new(
            port_b,
            peer_b,
            "bob".into(),
            53531,
            "bbbb".into(),
        )
        .await
        .expect("create beacon B");

        // A sends a direct message to B's port
        let target: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
        beacon_a.send_to(target).await.unwrap();

        // B receives it
        let mut buf = vec![0u8; 2048];
        let (msg, src) = beacon_b.recv(&mut buf).await.expect("B recv");

        assert_eq!(msg.peer_id, peer_a.0);
        assert_eq!(msg.device_name, "alice");
        assert_eq!(msg.listen_port, 53530);
        assert_eq!(src.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    /// Allocate a unique port per test invocation.
    fn pick_test_port() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static PORT: AtomicU16 = AtomicU16::new(21000);
        PORT.fetch_add(1, Ordering::Relaxed)
    }
}
