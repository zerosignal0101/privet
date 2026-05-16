use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::task::JoinHandle;
use quinn::Endpoint;

use crate::config::PrivetConfig;
use crate::error::{PrivetError, Result};
use crate::peer::{PeerId, PeerInfo};
use crate::security::identity::DeviceIdentity;
use crate::security::tls;
use crate::security::trust::TrustStore;
use crate::session::{SessionId, TransferProgress, TransferSession};
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
    peers: RwLock<HashMap<PeerId, PeerInfo>>,
    sessions: RwLock<HashMap<SessionId, TransferSession>>,
    event_tx: mpsc::UnboundedSender<PrivetEvent>,
    event_rx: Mutex<Option<mpsc::UnboundedReceiver<PrivetEvent>>>,
    endpoint: RwLock<Option<Arc<Endpoint>>>,
    listener_handle: RwLock<Option<JoinHandle<()>>>,
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
            peers: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            endpoint: RwLock::new(None),
            listener_handle: RwLock::new(None),
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

        let listener = async move {
            loop {
                match ep_clone.accept().await {
                    Some(incoming) => {
                        match incoming.await {
                            Ok(conn) => {
                                let event_tx = event_tx.clone();
                                let download_dir = download_dir.clone();
                                tokio::spawn(async move {
                                    let receiver = crate::transfer::receiver::Receiver::new(
                                        conn,
                                        download_dir,
                                        chunk_size,
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

    /// Send files to a peer.
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
        );

        sender.send(&paths, &self.event_tx).await
    }

    /// Accept an incoming transfer.
    pub async fn accept_transfer(&self, _session_id: &SessionId) -> Result<()> {
        // In current implementation, transfers are auto-accepted.
        // This will be extended to support manual acceptance in Phase 3.
        Ok(())
    }

    /// Reject an incoming transfer.
    pub async fn reject_transfer(&self, _session_id: &SessionId) -> Result<()> {
        // TODO: Send Reject message on control stream
        Ok(())
    }

    /// Cancel an active transfer.
    pub async fn cancel_transfer(&self, _session_id: &SessionId) -> Result<()> {
        // TODO: Send Cancel message on control stream
        Ok(())
    }

    /// Trust a peer.
    pub async fn trust_peer(&self, fingerprint: &str) -> Result<()> {
        self.trust_store
            .lock()
            .await
            .trust(fingerprint.to_owned())?;
        Ok(())
    }

    /// Get trusted peers' fingerprints.
    pub async fn trusted_fingerprints(&self) -> Vec<String> {
        self.trust_store.lock().await.trusted_fingerprints()
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
