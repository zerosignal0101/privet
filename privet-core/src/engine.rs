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
use crate::storage::records::{TransferLog, TransferRecord};
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
    /// Trust store behind Arc — shared with Receiver so trust is checked
    /// dynamically (reads the latest store, not a start-time snapshot).
    trust_store: Arc<tokio::sync::Mutex<TrustStore>>,
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    sessions: RwLock<HashMap<SessionId, TransferSession>>,
    event_tx: mpsc::UnboundedSender<PrivetEvent>,
    event_rx: Mutex<Option<mpsc::UnboundedReceiver<PrivetEvent>>>,
    endpoint: RwLock<Option<Arc<Endpoint>>>,
    listener_handle: RwLock<Option<JoinHandle<()>>>,
    discovery_handles: RwLock<Vec<JoinHandle<()>>>,
    transfer_log: Option<TransferLog>,
    tcp_listener_handle: RwLock<Option<JoinHandle<()>>>,
}

impl PrivetEngine {
    /// Create a new engine with the given configuration.
    pub async fn new(config: PrivetConfig) -> Result<Self> {
        tracing::debug!("PrivetEngine::new: device_name={}", config.device_name);

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
        tracing::debug!("PrivetEngine::new: cert_dir={:?}", cert_dir);

        let identity = DeviceIdentity::load_or_generate(
            config.device_name.clone(),
            cert_dir,
            config.security.cert_validity_years,
        )?;
        tracing::debug!("PrivetEngine::new: identity loaded, fingerprint={}", identity.fingerprint);

        let trust_path = config
            .security
            .cert_dir
            .as_ref()
            .map(|d| d.join("trusted.json"))
            .unwrap_or_else(|| PathBuf::from("trusted.json"));

        let trust_store = TrustStore::load_or_create(trust_path)?;
        tracing::debug!("PrivetEngine::new: trust_store loaded");

        // Initialize transfer log
        let log_dir = config
            .log_dir
            .clone()
            .unwrap_or_else(|| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("privet")
                    .join("logs")
            });
        std::fs::create_dir_all(&log_dir).ok();
        let transfer_log = TransferLog::open(&log_dir.join("transfers.jsonl")).ok();

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        tracing::info!("PrivetEngine::new: engine created");
        Ok(Self {
            config,
            identity,
            trust_store: Arc::new(tokio::sync::Mutex::new(trust_store)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            sessions: RwLock::new(HashMap::new()),
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            endpoint: RwLock::new(None),
            listener_handle: RwLock::new(None),
            discovery_handles: RwLock::new(Vec::new()),
            transfer_log,
            tcp_listener_handle: RwLock::new(None),
        })
    }

    /// Start the engine: bind QUIC endpoint and begin listening.
    pub async fn start(&self) -> Result<()> {
        tracing::debug!("PrivetEngine::start: binding endpoint");
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
        let trust_store = self.trust_store.clone();
        let trust_store_tcp = trust_store.clone();
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
                                let trust_store = trust_store.clone();
                                tokio::spawn(async move {
                                    let receiver = crate::transfer::receiver::Receiver::new(
                                        conn,
                                        download_dir,
                                        chunk_size,
                                        identity.fingerprint.clone(),
                                        identity.device_name.clone(),
                                        trust_store,
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

        // --- Start TCP fallback listener ---
        if self.config.transport.enable_tcp_fallback {
            let tcp_addr = listen_addr;
            let tcp_ev = self.event_tx.clone();
            let tcp_dl = self.config.download_dir.clone();
            let tcp_ck = self.config.transport.chunk_size;
            let tcp_id = self.identity.clone();
            let tcp_ts = trust_store_tcp.clone();
            let tcp_aa = auto_accept;
            let tcp_handle = tokio::spawn(async move {
                match tokio::net::TcpListener::bind(tcp_addr).await {
                    Ok(listener) => {
                        tracing::info!("TCP fallback listening on {tcp_addr}");
                        loop {
                            match listener.accept().await {
                                Ok((stream, addr)) => {
                                    let ev = tcp_ev.clone();
                                    let dl = tcp_dl.clone();
                                    let id = tcp_id.clone();
                                    let tf = tcp_ts.lock().await.trusted_fingerprints();
                                    tokio::spawn(async move {
                                        if let Err(e) =
                                            crate::transfer::tcp_transport::receive_tcp(
                                                stream, dl, tcp_ck, &id, &tf, tcp_aa, &ev,
                                            )
                                            .await
                                        {
                                            tracing::error!("TCP recv error from {addr}: {e}");
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::error!("TCP accept error: {e}");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("TCP fallback listener bind: {e}");
                    }
                }
            });
            *self.tcp_listener_handle.write().await = Some(tcp_handle);
        }

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
        if let Some(handle) = self.tcp_listener_handle.write().await.take() {
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
    /// Tries QUIC first, then TCP fallback if configured.
    pub async fn send_files_to_addr(
        &self,
        addr: SocketAddr,
        paths: Vec<PathBuf>,
    ) -> Result<SessionId> {
        let trusted = self.trust_store.lock().await.trusted_fingerprints();
        let auto_accept = self.config.auto_accept_trusted;

        // Try QUIC first
        let quic_result = self.try_send_quic(addr, &paths, &trusted, auto_accept).await;

        let (session_id, peer_fingerprint) = match quic_result {
            Ok(r) => r,
            Err(quic_err) => {
                let is_tcp_candidate = matches!(
                    &quic_err,
                    PrivetError::Transport(crate::error::TransportError::Quic(_))
                ) || matches!(&quic_err, PrivetError::ConnectionTimeout);

                if is_tcp_candidate && self.config.transport.enable_tcp_fallback {
                    tracing::info!("QUIC failed ({quic_err}), trying TCP fallback to {addr}");
                    match crate::transfer::tcp_transport::send_files_tcp(
                        addr,
                        paths.clone(),
                        self.config.transport.chunk_size,
                        &self.identity,
                        &trusted,
                        auto_accept,
                        &self.event_tx,
                    )
                    .await
                    {
                        Ok(tcp_result) => {
                            self.log_transfer(tcp_result.0, &tcp_result.1, &paths, true)
                                .await;
                            self.emit_pairing_if_needed(&tcp_result.1, &addr).await;
                            self.track_session(tcp_result.0).await;
                            return Ok(tcp_result.0);
                        }
                        Err(tcp_err) => {
                            let _ = self.event_tx.send(PrivetEvent::TransferFailed {
                                session_id: SessionId::new(),
                                error: tcp_err.to_string(),
                            });
                            return Err(tcp_err);
                        }
                    }
                }

                let _ = self.event_tx.send(PrivetEvent::TransferFailed {
                    session_id: SessionId::new(),
                    error: quic_err.to_string(),
                });
                return Err(quic_err);
            }
        };

        // Log
        self.log_transfer(session_id, &peer_fingerprint, &paths, true)
            .await;

        // Pairing flow
        self.emit_pairing_if_needed(&peer_fingerprint, &addr).await;

        // Track session
        self.track_session(session_id).await;

        Ok(session_id)
    }

    /// Try QUIC transport: connect and send. Returns (session_id, peer_fingerprint).
    async fn try_send_quic(
        &self,
        addr: SocketAddr,
        paths: &[PathBuf],
        trusted: &[String],
        auto_accept: bool,
    ) -> Result<(SessionId, String)> {
        let client_config = tls::build_client_config(&self.identity, trusted)?;
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

        sender.send(paths, &self.event_tx, trusted, auto_accept).await
    }

    /// Log a completed transfer to the JSONL transfer log.
    async fn log_transfer(
        &self,
        session_id: SessionId,
        peer_fingerprint: &str,
        paths: &[PathBuf],
        completed: bool,
    ) {
        if let Some(log) = &self.transfer_log {
            let _ = log.append(&TransferRecord {
                session_id,
                direction: crate::session::TransferDirection::Sending,
                peer_fingerprint: peer_fingerprint.to_owned(),
                files: paths.iter().map(|p| p.to_string_lossy().to_string()).collect(),
                total_bytes: 0,
                bytes_transferred: 0,
                completed,
            });
        }
    }

    /// Emit PairRequest event if the peer is not yet trusted.
    async fn emit_pairing_if_needed(&self, peer_fingerprint: &str, addr: &SocketAddr) {
        let trusted = self.trust_store.lock().await.trusted_fingerprints();
        if !trusted.iter().any(|fp| fp == peer_fingerprint) {
            let code =
                TrustStore::pairing_code(&self.identity.fingerprint, peer_fingerprint);
            let peer_info = PeerInfo {
                id: PeerId(uuid::Uuid::nil()),
                name: self.identity.device_name.clone(),
                addresses: vec![*addr],
                fingerprint: peer_fingerprint.to_owned(),
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
    }

    /// Mark session as completed in the sessions map.
    async fn track_session(&self, session_id: SessionId) {
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

