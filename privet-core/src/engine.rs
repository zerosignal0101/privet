use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::task::JoinHandle;
use quinn::Endpoint;

use crate::config::PrivetConfig;
use crate::discovery::{DiscoveryEvent, DiscoveryManager};
use crate::error::{PrivetError, Result};
use crate::peer::{PeerId, PeerInfo};
use crate::security::identity::DeviceIdentity;
use crate::security::tls;
use crate::security::trust::TrustStore;
use crate::session::{SessionId, SessionState, TransferProgress, TransferSession};
use crate::transport::endpoint;

/// Events emitted by the engine for the UI / CLI / FFI layer.
#[derive(Clone, Debug)]
pub enum PrivetEvent {
    PeerDiscovered(PeerInfo),
    PeerLost(PeerId),
    PairRequest { peer: PeerInfo, code: String },
    TransferProgress { session_id: SessionId, progress: TransferProgress },
    TransferComplete { session_id: SessionId },
    TransferFailed { session_id: SessionId, error: String },
    IncomingTransfer { session_id: SessionId, peer: PeerInfo, files: crate::session::FileManifest },
    NetworkChanged,
}

/// The top-level engine that orchestrates all subsystems.
pub struct PrivetEngine {
    config: PrivetConfig,
    identity: DeviceIdentity,
    trust_store: Mutex<TrustStore>,
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    sessions: RwLock<HashMap<SessionId, TransferSession>>,
    event_tx: mpsc::UnboundedSender<PrivetEvent>,
    event_rx: Mutex<Option<mpsc::UnboundedReceiver<PrivetEvent>>>,
    endpoint: RwLock<Option<Arc<Endpoint>>>,
    listener_handle: RwLock<Option<JoinHandle<()>>>,
    discovery_handles: RwLock<Vec<JoinHandle<()>>>,
}

impl PrivetEngine {
    /// Create a new engine with the given configuration.
    pub async fn new(config: PrivetConfig) -> Result<Self> {
        let cert_dir = config
            .security
            .cert_dir
            .clone()
            .unwrap_or_else(|| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("privet")
                    .join("certs")
            });

        let identity = DeviceIdentity::load_or_generate(
            config.device_name.clone(),
            cert_dir,
            config.security.cert_validity_years,
        )?;

        let trust_path = config
            .security
            .cert_dir
            .as_ref()
            .map(|d| d.join("trusted.json"))
            .unwrap_or_else(|| PathBuf::from("trusted.json"));

        let trust_store = TrustStore::load_or_create(trust_path)?;

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            identity,
            trust_store: Mutex::new(trust_store),
            peers: Arc::new(RwLock::new(HashMap::new())),
            sessions: RwLock::new(HashMap::new()),
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            endpoint: RwLock::new(None),
            listener_handle: RwLock::new(None),
            discovery_handles: RwLock::new(Vec::new()),
        })
    }

    /// Start the engine: bind QUIC endpoint and begin listening.
    pub async fn start(&self) -> Result<()> {
        let trusted = self.trust_store.lock().await.trusted_fingerprints();
        let server_config = tls::build_server_config(&self.identity, &trusted)?;
        let rustls_server: Arc<rustls::ServerConfig> = server_config;

        let listen_addr: SocketAddr = format!("0.0.0.0:{}", self.config.transport.listen_port)
            .parse()
            .map_err(|e: std::net::AddrParseError| PrivetError::Transport(
                crate::error::TransportError::Quic(e.to_string())
            ))?;

        let ep = Arc::new(endpoint::build_server_endpoint(
            &self.config.transport,
            rustls_server,
            listen_addr,
        )?);

        let ep_clone = Arc::clone(&ep);
        let event_tx = self.event_tx.clone();
        let download_dir = self.config.download_dir.clone();
        let chunk_size = self.config.transport.chunk_size;
        let identity = self.identity.clone();
        let trusted_fingerprints = self.trust_store.lock().await.trusted_fingerprints();
        let auto_accept = self.config.auto_accept_trusted;

        let listener = async move {
            loop {
                match ep_clone.accept().await {
                    Some(incoming) => {
                        match incoming.await {
                            Ok(conn) => {
                                let event_tx = event_tx.clone();
                                let download_dir = download_dir.clone();
                                let identity = identity.clone();
                                let trust_fps = trusted_fingerprints.clone();
                                tokio::spawn(async move {
                                    let receiver = crate::transfer::receiver::Receiver::new(
                                        conn,
                                        download_dir,
                                        chunk_size,
                                        identity.fingerprint.clone(),
                                        identity.device_name.clone(),
                                        trust_fps,
                                        auto_accept,
                                    );
                                    if let Err(e) = receiver.receive(&event_tx).await {
                                        tracing::error!("receive error: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!("incoming connection failed: {e}");
                            }
                        }
                    }
                    None => break,
                }
            }
        };

        *self.listener_handle.write().await = Some(tokio::spawn(listener));
        *self.endpoint.write().await = Some(ep);

        // --- Start discovery subsystems ---
        let enable_disc = self.config.discovery.enable_beacon || self.config.discovery.enable_mdns;
        if enable_disc {
            let (discovery, mut discovery_rx) = DiscoveryManager::new();
            let handles = discovery
                .start(
                    &self.config.discovery,
                    &self.identity,
                    self.config.transport.listen_port,
                )
                .await;
            *self.discovery_handles.write().await = handles;

            let peers = Arc::clone(&self.peers);
            let event_tx = self.event_tx.clone();
            tokio::spawn(async move {
                while let Some(event) = discovery_rx.recv().await {
                    match event {
                        DiscoveryEvent::PeerDiscovered(info) => {
                            let mut map = peers.write().await;
                            map.insert(info.id, info.clone());
                            drop(map);
                            let _ = event_tx.send(PrivetEvent::PeerDiscovered(info));
                        }
                        DiscoveryEvent::PeerLost(id) => {
                            peers.write().await.remove(&id);
                            let _ = event_tx.send(PrivetEvent::PeerLost(id));
                        }
                    }
                }
            });

            tracing::info!(
                "discovery started (beacon={}, mdns={})",
                self.config.discovery.enable_beacon,
                self.config.discovery.enable_mdns
            );
        }

        tracing::info!(
            "privet engine started on port {}",
            self.config.transport.listen_port
        );

        Ok(())
    }

    /// Shut down the engine.
    pub async fn shutdown(&self) -> Result<()> {
        if let Some(handle) = self.listener_handle.write().await.take() {
            handle.abort();
        }
        for handle in self.discovery_handles.write().await.drain(..) {
            handle.abort();
        }
        if let Some(ep) = self.endpoint.write().await.take() {
            ep.close(0u32.into(), b"shutdown");
        }
        Ok(())
    }

    /// Subscribe to engine events.
    pub async fn subscribe_events(&self) -> mpsc::UnboundedReceiver<PrivetEvent> {
        self.event_rx
            .lock()
            .await
            .take()
            .expect("events can only be subscribed once")
    }

    /// Get discovered peers.
    pub async fn discovered_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Send files to a peer, with trust check and pairing flow.
    pub async fn send_files(&self, peer_id: &PeerId, paths: Vec<PathBuf>) -> Result<SessionId> {
        let peers = self.peers.read().await;
        let peer = peers
            .get(peer_id)
            .ok_or_else(|| PrivetError::PeerNotFound(peer_id.to_string()))?;

        let addr = peer
            .primary_address()
            .ok_or_else(|| PrivetError::PeerNotFound(peer_id.to_string()))?;

        self.send_files_to_addr(addr, paths).await
    }

    /// Send files to a peer by address (IP:port), bypassing discovery.
    pub async fn send_files_to_addr(
        &self,
        addr: SocketAddr,
        paths: Vec<PathBuf>,
    ) -> Result<SessionId> {
        let trusted = self.trust_store.lock().await.trusted_fingerprints();
        let client_config = tls::build_client_config(&self.identity, &trusted)?;
        let listen_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let ep = endpoint::build_client_endpoint(
            &self.config.transport,
            client_config,
            listen_addr,
        )?;

        let conn = ep
            .connect(addr, "privet")
            .map_err(|e| crate::error::TransportError::Quic(format!("connect: {e}")))?
            .await
            .map_err(|e| crate::error::TransportError::Quic(format!("handshake: {e}")))?;

        let sender = crate::transfer::sender::Sender::new(
            conn,
            self.config.transport.chunk_size,
            self.identity.fingerprint.clone(),
            self.identity.device_name.clone(),
        );

        let auto_accept = self.config.auto_accept_trusted;

        let (session_id, peer_fingerprint) = match sender.send(&paths, &self.event_tx, &trusted, auto_accept).await {
            Ok(result) => result,
            Err(e) => {
                let _ = self.event_tx.send(PrivetEvent::TransferFailed {
                    session_id: SessionId::new(),
                    error: e.to_string(),
                });
                return Err(e);
            }
        };

        // Check trust for pairing flow
        let trusted = self.trust_store.lock().await.trusted_fingerprints();
        if !trusted.iter().any(|fp| fp == &peer_fingerprint) {
            let code = TrustStore::pairing_code(&self.identity.fingerprint, &peer_fingerprint);
            let peer_info = PeerInfo {
                id: PeerId(uuid::Uuid::nil()),
                name: self.identity.device_name.clone(),
                addresses: vec![addr],
                fingerprint: peer_fingerprint.clone(),
                is_trusted: false,
                last_seen: std::time::SystemTime::now(),
                platform: None,
                version: None,
            };
            let _ = self.event_tx.send(PrivetEvent::PairRequest {
                peer: peer_info,
                code,
            });
        }

        // Track the session
        {
            let mut sessions = self.sessions.write().await;
            if let Some(entry) = sessions.get_mut(&session_id) {
                entry.state = SessionState::Completed;
                entry.progress = TransferProgress {
                    total_bytes: 0,
                    bytes_transferred: 0,
                    current_speed_bps: 0.0,
                    per_file: vec![],
                };
            }
        }

        Ok(session_id)
    }

    /// Send files to a peer resolved by display name.
    pub async fn send_files_to_name(&self, name: &str, paths: Vec<PathBuf>) -> Result<SessionId> {
        let peer = self
            .resolve_peer_by_name(name)
            .await
            .ok_or_else(|| PrivetError::PeerNotFound(name.to_owned()))?;
        self.send_files(&peer.id, paths).await
    }

    /// Resolve a peer by display name from the discovered peers list.
    pub async fn resolve_peer_by_name(&self, name: &str) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().find(|p| p.name == name).cloned()
    }

    /// Accept an incoming transfer.
    pub async fn accept_transfer(&self, _session_id: &SessionId) -> Result<()> {
        Ok(())
    }

    /// Reject an incoming transfer.
    pub async fn reject_transfer(&self, _session_id: &SessionId) -> Result<()> {
        Ok(())
    }

    /// Cancel an active transfer.
    pub async fn cancel_transfer(&self, _session_id: &SessionId) -> Result<()> {
        Ok(())
    }

    /// Trust a peer by fingerprint.
    pub async fn trust_peer(&self, fingerprint: &str) -> Result<()> {
        self.trust_store
            .lock()
            .await
            .trust(fingerprint.to_owned())?;
        Ok(())
    }

    /// Remove trust from a peer by fingerprint.
    pub async fn untrust_peer(&self, fingerprint: &str) -> Result<()> {
        self.trust_store
            .lock()
            .await
            .untrust(fingerprint)?;
        Ok(())
    }

    /// Get trusted peers' fingerprints.
    pub async fn trusted_fingerprints(&self) -> Vec<String> {
        self.trust_store.lock().await.trusted_fingerprints()
    }

    /// Get a specific session by ID.
    pub async fn get_session(&self, session_id: &SessionId) -> Option<TransferSession> {
        self.sessions.read().await.get(session_id).cloned()
    }

    /// List all active sessions.
    pub async fn list_sessions(&self) -> Vec<TransferSession> {
        self.sessions.read().await.values().cloned().collect()
    }

    /// Get the device identity.
    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// Get the config.
    pub fn config(&self) -> &PrivetConfig {
        &self.config
    }
}

