pub mod beacon;
pub mod mdns;
pub mod probe;
pub mod scanner;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use mdns_sd::ServiceEvent;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::DiscoveryConfig;
use crate::error::DiscoveryError;
use crate::peer::{PeerId, PeerInfo};
use crate::security::identity::DeviceIdentity;

pub(crate) const DISCOVERY_PEER_TTL: Duration = Duration::from_secs(15);

/// Events emitted by the discovery subsystem.
#[derive(Debug)]
pub(crate) enum DiscoveryEvent {
    PeerDiscovered(PeerInfo),
    PeerLost(PeerId),
}

/// Coordinates beacon broadcast/listen and mDNS discovery.
/// Spawns background tasks and emits [`DiscoveryEvent`]s via an mpsc channel.
pub(crate) struct DiscoveryManager {
    event_tx: mpsc::UnboundedSender<DiscoveryEvent>,
}

impl DiscoveryManager {
    pub(crate) fn new() -> (Self, mpsc::UnboundedReceiver<DiscoveryEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { event_tx: tx }, rx)
    }

    /// Start all enabled discovery mechanisms.
    /// Returns a list of [`JoinHandle`]s that the caller should abort on shutdown.
    pub(crate) async fn start(
        &self,
        config: &DiscoveryConfig,
        identity: &DeviceIdentity,
        listen_port: u16,
    ) -> Vec<JoinHandle<()>> {
        let mut handles = Vec::new();

        if config.enable_beacon {
            match self.start_beacon(config.beacon_port, identity, listen_port).await {
                Ok(mut h) => handles.append(&mut h),
                Err(e) => tracing::warn!("Failed to start UDP beacon: {e}"),
            }
        }

        if config.enable_mdns {
            match self.start_mdns(identity, listen_port) {
                Ok(mut h) => handles.append(&mut h),
                Err(e) => tracing::warn!("Failed to start mDNS: {e}"),
            }
        }

        // Peer expiry watcher (placeholder for TTL-based expiry)
        if config.enable_beacon || config.enable_mdns {
            let expiry = tokio::spawn(async {
                loop {
                    tokio::time::sleep(DISCOVERY_PEER_TTL).await;
                }
            });
            handles.push(expiry);
        }

        handles
    }

    async fn start_beacon(
        &self,
        beacon_port: u16,
        identity: &DeviceIdentity,
        listen_port: u16,
    ) -> Result<Vec<JoinHandle<()>>, DiscoveryError> {
        let beacon: Arc<beacon::Beacon> = Arc::new(
            beacon::Beacon::new(
                beacon_port,
                identity.peer_id,
                identity.device_name.clone(),
                listen_port,
                identity.fingerprint.clone(),
            )
            .await?,
        );

        let mut handles = Vec::new();

        // --- Announce task: broadcast our presence every 2s ---
        let b = Arc::clone(&beacon);
        let announce = tokio::spawn(async move {
            loop {
                if let Err(e) = b.announce().await {
                    tracing::warn!("Beacon announce error: {e}");
                }
                tokio::time::sleep(beacon::BEACON_INTERVAL).await;
            }
        });
        handles.push(announce);

        // --- Listen task: receive broadcasts from other peers ---
        let b = Arc::clone(&beacon);
        let tx = self.event_tx.clone();
        let listen = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match b.recv(&mut buf).await {
                    Ok((msg, src)) => {
                        let peer_id = PeerId(msg.peer_id);
                        let peer_addr = SocketAddr::new(src.ip(), msg.listen_port);

                        let info = PeerInfo {
                            id: peer_id,
                            name: msg.device_name,
                            addresses: vec![peer_addr],
                            fingerprint: msg.fingerprint,
                            is_trusted: false,
                            last_seen: SystemTime::now(),
                            platform: None,
                            version: None,
                        };

                        if tx.send(DiscoveryEvent::PeerDiscovered(info)).is_err() {
                            break; // receiver dropped
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Beacon recv error: {e}");
                    }
                }
            }
        });
        handles.push(listen);

        Ok(handles)
    }

    fn start_mdns(
        &self,
        identity: &DeviceIdentity,
        listen_port: u16,
    ) -> Result<Vec<JoinHandle<()>>, DiscoveryError> {
        let mdns = Arc::new(mdns::MdnsDiscovery::new());
        if !mdns.is_available() {
            return Ok(Vec::new()); // silently skip
        }

        let mut handles = Vec::new();

        // --- Register our service ---
        let instance_name = identity.peer_id.to_string();
        let short_id = &instance_name[..8.min(instance_name.len())];
        let hostname = format!("privet-{short_id}.local.");

        let fp_prefix = &identity.fingerprint[..16.min(identity.fingerprint.len())];
        let props: [(&str, &str); 3] = [
            ("fp", fp_prefix),
            ("v", env!("CARGO_PKG_VERSION")),
            ("name", &identity.device_name),
        ];

        if let Err(e) = mdns.register(&instance_name, &hostname, listen_port, &props) {
            tracing::warn!("mDNS register error: {e}");
        }

        // --- Browse for peers ---
        let mut rx = match mdns.browse() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("mDNS browse error: {e}");
                return Ok(handles);
            }
        };

        let tx = self.event_tx.clone();
        let local_peer_id = identity.peer_id;
        let browse = tokio::spawn(async move {
            // Keep mdns alive by moving it into the task
            let _keep = mdns;

            while let Some(event) = rx.recv().await {
                if let Err(e) = handle_mdns_event(event, &tx, local_peer_id) {
                    tracing::warn!("mDNS event handler: {e}");
                }
            }
        });
        handles.push(browse);

        Ok(handles)
    }
}

fn handle_mdns_event(
    event: ServiceEvent,
    tx: &mpsc::UnboundedSender<DiscoveryEvent>,
    local_peer_id: PeerId,
) -> Result<(), DiscoveryError> {
    match event {
        ServiceEvent::ServiceResolved(info) => {
            // Fullname is "{instance_name}.{service_type}."
            let fullname = info.get_fullname();
            let peer_id_str = fullname.split('.').next().unwrap_or("");
            let peer_id = PeerId(
                uuid::Uuid::parse_str(peer_id_str)
                    .map_err(|e| DiscoveryError::Mdns(format!("parse peer_id: {e}")))?,
            );

            // Skip our own service
            if peer_id == local_peer_id {
                return Ok(());
            }

            let fingerprint = info
                .get_property_val_str("fp")
                .unwrap_or("")
                .to_owned();

            let version = info.get_property_val_str("v").map(|v| v.to_owned());

            // Use "name" TXT property if present, otherwise fall back to hostname
            let name = info
                .get_property_val_str("name")
                .map(|n| n.to_owned())
                .unwrap_or_else(|| {
                    info.get_hostname()
                        .trim_end_matches(".local.")
                        .to_owned()
                });

            let addresses: Vec<SocketAddr> = info
                .get_addresses()
                .iter()
                .map(|ip| SocketAddr::new(*ip, info.get_port()))
                .collect();

            let peer_info = PeerInfo {
                id: peer_id,
                name,
                addresses,
                fingerprint,
                is_trusted: false,
                last_seen: SystemTime::now(),
                platform: None,
                version,
            };

            if !peer_info.addresses.is_empty() {
                let _ = tx.send(DiscoveryEvent::PeerDiscovered(peer_info));
            }
        }
        ServiceEvent::ServiceRemoved(_service_type, fullname) => {
            if let Some(instance) = fullname.split('.').next() {
                if let Ok(uuid) = uuid::Uuid::parse_str(instance) {
                    let lost_id = PeerId(uuid);
                    if lost_id != local_peer_id {
                        let _ = tx.send(DiscoveryEvent::PeerLost(lost_id));
                    }
                }
            }
        }
        _ => {
            // Ignore SearchStarted, SearchStopped, ServiceFound
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerId;
    use uuid::Uuid;

    #[test]
    fn beacon_peer_info_construction() {
        let peer_id = PeerId(Uuid::new_v4());
        let info = PeerInfo {
            id: peer_id,
            name: "test-device".into(),
            addresses: vec!["192.168.1.100:53530".parse().unwrap()],
            fingerprint: "abcd".into(),
            is_trusted: false,
            last_seen: SystemTime::now(),
            platform: None,
            version: None,
        };

        assert_eq!(info.id, peer_id);
        assert_eq!(info.display_fingerprint(), "abcd");
        assert!(info.primary_address().is_some());
        assert_eq!(info.primary_address().unwrap().port(), 53530);
    }

    #[test]
    fn discovery_peer_ttl_positive() {
        assert!(DISCOVERY_PEER_TTL.as_secs() > 0);
    }
}
