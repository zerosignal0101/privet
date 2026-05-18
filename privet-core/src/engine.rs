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
use crate::known_device::KnownDeviceStore;
use crate::network::NetworkInfo;
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
    /// Emitted when an incoming transfer arrives from a trusted peer that is NOT
    /// in the auto-accept list. The UI/CLI should call `accept_transfer` or
    /// `reject_transfer` with the session_id.
    AwaitingAccept {
        session_id: SessionId,
        peer: PeerInfo,
        files: crate::session::FileManifest,
    },
    /// Emitted when an incoming pairing request arrives. The UI/CLI should call
    /// `trust_peer`, `trust_and_accept_peer`, or `reject_pairing`.
    AwaitingPairing {
        session_id: SessionId,
        peer: PeerInfo,
        code: String,
    },
    /// Emitted when a known device is probed and found online on the current network.
    KnownDeviceProbed {
        peer: PeerInfo,
    },
    NetworkChanged,
}

/// Decision for a pairing request from an unknown peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairDecision {
    /// Trust the device identity only.
    Trust,
    /// Trust the device and auto-accept all future transfers.
    TrustAndAccept,
    /// Reject the pairing request.
    Reject,
}

/// Extract the peer's TLS certificate fingerprint from a TlsStream.
macro_rules! tls_peer_fingerprint {
    ($stream:expr) => {{
        let (_, session) = $stream.get_ref();
        session
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| crate::security::cert::fingerprint_from_der(cert.as_ref()))
    }};
}


/// The top-level engine that orchestrates all subsystems.
pub struct PrivetEngine {
    config: PrivetConfig,
    identity: DeviceIdentity,
    /// Trust store behind Arc — shared with Receiver so trust is checked dynamically.
    trust_store: Arc<tokio::sync::Mutex<TrustStore>>,
    /// Accept store — which trusted devices auto-accept transfers.
    accept_store: Arc<tokio::sync::Mutex<crate::security::accept::AcceptStore>>,
    /// Known device store — device-to-network/IP mappings for directed discovery.
    known_device_store: Arc<tokio::sync::Mutex<KnownDeviceStore>>,
    /// Oneshot channels for pending incoming transfer decisions (session_id → sender).
    pending_incoming: Arc<RwLock<HashMap<SessionId, tokio::sync::oneshot::Sender<bool>>>>,
    /// Oneshot channels for pending pairing decisions (peer_fingerprint → sender).
    pending_pairing: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<PairDecision>>>>,
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

        // Load accept store
        let accept_path = config
            .security
            .cert_dir
            .as_ref()
            .map(|d| d.join("accepted.json"))
            .unwrap_or_else(|| PathBuf::from("accepted.json"));
        let accept_store = crate::security::accept::AcceptStore::load_or_create(accept_path)?;
        tracing::debug!("PrivetEngine::new: accept_store loaded");

        // Load known device store
        let known_device_path = config
            .security
            .cert_dir
            .as_ref()
            .map(|d| d.join("known_devices.json"))
            .unwrap_or_else(|| PathBuf::from("known_devices.json"));
        let known_device_store = KnownDeviceStore::load_or_create(known_device_path)?;
        tracing::debug!("PrivetEngine::new: known_device_store loaded");

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
            accept_store: Arc::new(tokio::sync::Mutex::new(accept_store)),
            known_device_store: Arc::new(tokio::sync::Mutex::new(known_device_store)),
            pending_incoming: Arc::new(RwLock::new(HashMap::new())),
            pending_pairing: Arc::new(RwLock::new(HashMap::new())),
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
        tracing::info!("PrivetEngine::start: security_mode={:?}, download_dir={:?}",
            self.config.security_mode, self.config.download_dir);
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
        let security_mode = self.config.security_mode;
        let accept_store = self.accept_store.clone();
        let pending_incoming = self.pending_incoming.clone();
        let pending_pairing = self.pending_pairing.clone();
        let accept_store_tcp = accept_store.clone();
        let pending_incoming_tcp = pending_incoming.clone();
        let pending_pairing_tcp = pending_pairing.clone();

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
                                let accept_store = accept_store.clone();
                                let pending_incoming = pending_incoming.clone();
                                let pending_pairing = pending_pairing.clone();
                                tokio::spawn(async move {
                                    let receiver = crate::transfer::receiver::Receiver::new(
                                        conn,
                                        download_dir,
                                        chunk_size,
                                        identity.fingerprint.clone(),
                                        identity.device_name.clone(),
                                        trust_store,
                                        security_mode,
                                        accept_store,
                                        pending_incoming,
                                        pending_pairing,
                                    );
                                    if let Err(e) = receiver.receive(&event_tx).await {
                                        tracing::warn!("receive finished: {e}");
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

        // --- Start TCP fallback listener (with TLS) ---
        if self.config.transport.enable_tcp_fallback {
            let tcp_addr = listen_addr;
            let tcp_ev = self.event_tx.clone();
            let tcp_dl = self.config.download_dir.clone();
            let tcp_ck = self.config.transport.chunk_size;
            let tcp_id = self.identity.clone();
            let tcp_ts = trust_store_tcp.clone();
            let tcp_sm = security_mode;
            let tcp_accept_store = accept_store_tcp.clone();
            let tcp_pending_incoming = pending_incoming_tcp.clone();
            let tcp_pending_pairing = pending_pairing_tcp.clone();
            let tcp_handle = tokio::spawn(async move {
                // Build TLS server config once (mandatory client auth)
                let tls_server_cfg = match crate::security::tls::build_tcp_server_config(&tcp_id) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("TCP TLS config build error: {e}");
                        return;
                    }
                };

                let tcp_listener = endpoint::reuseable_tcp_listener(tcp_addr);
                match tcp_listener {
                    Ok(listener) => {
                        tracing::info!("TCP fallback listening on {tcp_addr} (TLS)");
                        loop {
                            match listener.accept().await {
                                Ok((stream, addr)) => {
                                    let ev = tcp_ev.clone();
                                    let dl = tcp_dl.clone();
                                    let id = tcp_id.clone();
                                    let ts = tcp_ts.clone();
                                    let aa = tcp_sm;
                                    let ck = tcp_ck;
                                    let as_ = tcp_accept_store.clone();
                                    let pi = tcp_pending_incoming.clone();
                                    let pp = tcp_pending_pairing.clone();
                                    let acceptor = tokio_rustls::TlsAcceptor::from(tls_server_cfg.clone());
                                    tokio::spawn(async move {
                                        // Wrap with TLS
                                        let tls_stream = match acceptor.accept(stream).await {
                                            Ok(s) => s,
                                            Err(e) => {
                                                tracing::error!("TCP TLS handshake error from {addr}: {e}");
                                                return;
                                            }
                                        };

                                        // Extract peer's TLS certificate fingerprint for MITM check
                                        let tls_fp = tls_peer_fingerprint!(&tls_stream);

                                        let tf = ts.lock().await.trusted_fingerprints();
                                        if let Err(e) =
                                            crate::transfer::tcp_transport::receive_tcp(
                                                tls_stream, dl, ck, &id, &tf, &aa,
                                                tls_fp.as_deref(), as_, &*pi, &*pp, &ev,
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
            let known_device_store = self.known_device_store.clone();
            tokio::spawn(async move {
                while let Some(event) = discovery_rx.recv().await {
                    match event {
                        DiscoveryEvent::PeerDiscovered(info) => {
                            // Auto-record discovered device to known device store
                            if let Some(addr) = info.primary_address() {
                                let subnet = crate::network::subnet_from_addr(
                                    &addr.ip(),
                                    crate::network::default_prefix_len(match addr.ip() {
                                        std::net::IpAddr::V4(ref v4) => v4,
                                        std::net::IpAddr::V6(_) => {
                                            // skip IPv6 for now
                                            let mut map = peers.write().await;
                                            map.insert(info.id, info.clone());
                                            drop(map);
                                            let _ = event_tx.send(PrivetEvent::PeerDiscovered(info));
                                            continue;
                                        }
                                    }),
                                );
                                let mut store = known_device_store.lock().await;
                                let _ = store.add_or_update_device(
                                    info.fingerprint.clone(),
                                    info.id.clone(),
                                    info.name.clone(),
                                    subnet,
                                    addr,
                                    None,
                                );
                            }

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
            drop(ep);
        }
        // Short sleep to let the UDP socket be released before a rebind.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
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

        // Try QUIC first
        let quic_result = self.try_send_quic(addr, &paths, &trusted, &self.config.security_mode).await;

        let (session_id, peer_fingerprint, peer_device_name) = match quic_result {
            Ok(r) => r,
            Err(quic_err) => {
                let is_tcp_candidate = matches!(
                    &quic_err,
                    PrivetError::Transport(crate::error::TransportError::Quic(_))
                ) || matches!(&quic_err, PrivetError::ConnectionTimeout);

                if is_tcp_candidate && self.config.transport.enable_tcp_fallback {
                    tracing::info!("QUIC failed ({quic_err}), trying TCP+TLS fallback to {addr}");
                    // Connect TCP, then wrap with TLS for MITM protection
                    let tcp_stream = match crate::transport::tcp_fallback::connect_tcp(addr).await {
                        Ok(s) => s,
                        Err(e) => {
                            let msg = format!("TCP connect failed: {e}");
                            let _ = self.event_tx.send(PrivetEvent::TransferFailed {
                                session_id: SessionId::new(),
                                error: msg.clone(),
                            });
                            return Err(PrivetError::Transport(e));
                        }
                    };
                    let tls_client_cfg = match crate::security::tls::build_client_config(
                        &self.identity,
                        &trusted,
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            let msg = format!("TLS client config error: {e}");
                            let _ = self.event_tx.send(PrivetEvent::TransferFailed {
                                session_id: SessionId::new(),
                                error: msg.clone(),
                            });
                            return Err(PrivetError::Security(e));
                        }
                    };
                    let connector = tokio_rustls::TlsConnector::from(tls_client_cfg);
                    let tls_name = match rustls::pki_types::ServerName::try_from("privet") {
                        Ok(n) => n,
                        Err(_) => {
                            let msg: String = "invalid TLS server name".into();
                            let _ = self.event_tx.send(PrivetEvent::TransferFailed {
                                session_id: SessionId::new(),
                                error: msg.clone(),
                            });
                            return Err(PrivetError::Security(
                                crate::error::SecurityError::Tls(msg),
                            ));
                        }
                    };
                    let tls_stream = match connector.connect(tls_name, tcp_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            let msg = format!("TLS handshake failed: {e}");
                            let _ = self.event_tx.send(PrivetEvent::TransferFailed {
                                session_id: SessionId::new(),
                                error: msg.clone(),
                            });
                            return Err(PrivetError::Security(
                                crate::error::SecurityError::Tls(msg),
                            ));
                        }
                    };
                    let tls_fp = tls_peer_fingerprint!(&tls_stream);
                    match crate::transfer::tcp_transport::send_files_tcp(
                        tls_stream,
                        addr,
                        paths.clone(),
                        self.config.transport.chunk_size,
                        &self.identity,
                        &trusted,
                        &self.config.security_mode,
                        tls_fp.as_deref(),
                        &self.event_tx,
                    )
                    .await
                    {
                        Ok(tcp_result) => {
                            let tcp_session = tcp_result.0;
                            let tcp_fp = tcp_result.1;
                            let tcp_name = tcp_result.2;
                            self.log_transfer(tcp_session, &tcp_fp, &paths, true)
                                .await;
                            self.record_to_known_devices(&tcp_fp, &addr, &tcp_name).await;
                            self.emit_pairing_if_needed(&tcp_fp, &addr).await;
                            self.track_session(tcp_session).await;
                            return Ok(tcp_session);
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

        // Auto-record to known device store
        self.record_to_known_devices(&peer_fingerprint, &addr, &peer_device_name).await;

        // Pairing flow
        self.emit_pairing_if_needed(&peer_fingerprint, &addr).await;

        // Track session
        self.track_session(session_id).await;

        Ok(session_id)
    }

    /// Try QUIC transport: connect and send. Returns (session_id, peer_fingerprint, peer_device_name).
    async fn try_send_quic(
        &self,
        addr: SocketAddr,
        paths: &[PathBuf],
        trusted: &[String],
        security_mode: &crate::config::SecurityMode,
    ) -> Result<(SessionId, String, String)> {
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

        sender.send(paths, &self.event_tx, trusted, security_mode).await
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

    /// Record a successful connection to the known device store.
    /// Called after a successful send to automatically remember the peer's IP.
    async fn record_to_known_devices(&self, peer_fingerprint: &str, addr: &SocketAddr, peer_device_name: &str) {
        let subnet = crate::network::subnet_from_addr(
            &addr.ip(),
            crate::network::default_prefix_len(match addr.ip() {
                std::net::IpAddr::V4(ref v4) => v4,
                std::net::IpAddr::V6(_) => return, // skip IPv6 for now
            }),
        );

        // Use the device name from HelloAck, falling back to discovered peers or fingerprint
        let device_name = if !peer_device_name.is_empty() {
            peer_device_name.to_owned()
        } else {
            let peers = self.peers.read().await;
            peers.values()
                .find(|p| p.fingerprint == peer_fingerprint)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| peer_fingerprint[..8.min(peer_fingerprint.len())].to_string())
        };

        let peer_id = {
            let peers = self.peers.read().await;
            peers.values()
                .find(|p| p.fingerprint == peer_fingerprint)
                .map(|p| p.id.clone())
                .unwrap_or_else(|| PeerId(uuid::Uuid::nil()))
        };

        let mut store = self.known_device_store.lock().await;
        if let Err(e) = store.add_or_update_device(
            peer_fingerprint.to_owned(),
            peer_id,
            device_name,
            subnet,
            *addr,
            None,
        ) {
            tracing::warn!("Failed to record known device: {e}");
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
    /// Falls back to known device store if the peer is not discovered via mDNS/beacon.
    pub async fn send_files_to_name(&self, name: &str, paths: Vec<PathBuf>) -> Result<SessionId> {
        // First, try discovered peers
        if let Some(peer) = self.resolve_peer_by_name(name).await {
            return self.send_files(&peer.id, paths).await;
        }

        // Fallback: look up in known device store for current network
        let networks = self.current_networks();
        let store = self.known_device_store.lock().await;

        for net_info in &networks {
            if let Some(device) = store.get_device_by_name(name) {
                if let Some(entry) = device.networks.get(&net_info.subnet) {
                    if let Some(addr_str) = entry.addresses.first() {
                        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                            drop(store);
                            return self.send_files_to_addr(addr, paths).await;
                        }
                    }
                }
            }
        }

        Err(PrivetError::PeerNotFound(name.to_owned()))
    }

    /// Resolve a peer by display name from the discovered peers list.
    pub async fn resolve_peer_by_name(&self, name: &str) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().find(|p| p.name == name).cloned()
    }

    /// Accept an incoming transfer.
    pub async fn accept_transfer(&self, session_id: &SessionId) -> Result<()> {
        tracing::debug!("[engine] accept_transfer called for session {}", session_id.0);
        let mut map = self.pending_incoming.write().await;
        tracing::debug!("[engine] pending_incoming keys: {:?}",
            map.keys().map(|k| k.0).collect::<Vec<_>>());
        let tx = map.remove(session_id)
            .ok_or_else(|| {
                tracing::error!("[engine] accept_transfer: session {} NOT found in pending_incoming", session_id.0);
                PrivetError::SessionNotFound(session_id.0.to_string())
            })?;
        let _ = tx.send(true);
        tracing::debug!("[engine] accept_transfer: sent true via oneshot for session {}", session_id.0);
        Ok(())
    }

    /// Reject an incoming transfer.
    pub async fn reject_transfer(&self, session_id: &SessionId) -> Result<()> {
        tracing::debug!("[engine] reject_transfer called for session {}", session_id.0);
        let mut map = self.pending_incoming.write().await;
        let tx = map.remove(session_id)
            .ok_or_else(|| {
                tracing::error!("[engine] reject_transfer: session {} NOT found in pending_incoming", session_id.0);
                PrivetError::SessionNotFound(session_id.0.to_string())
            })?;
        let _ = tx.send(false);
        tracing::debug!("[engine] reject_transfer: sent false via oneshot for session {}", session_id.0);
        Ok(())
    }

    /// Cancel an active transfer.
    pub async fn cancel_transfer(&self, _session_id: &SessionId) -> Result<()> {
        Ok(())
    }

    /// Trust a peer by fingerprint.
    /// If there is a pending pairing request for this fingerprint,
    /// it will be resolved with PairDecision::Trust.
    pub async fn trust_peer(&self, fingerprint: &str) -> Result<()> {
        self.trust_store.lock().await.trust(fingerprint.to_owned())?;
        if let Some(tx) = self.pending_pairing.write().await.remove(fingerprint) {
            let _ = tx.send(PairDecision::Trust);
        }
        Ok(())
    }

    /// Trust a peer and auto-accept all future transfers from them.
    pub async fn trust_and_accept_peer(&self, fingerprint: &str) -> Result<()> {
        self.trust_store.lock().await.trust(fingerprint.to_owned())?;
        self.accept_store.lock().await.accept(fingerprint.to_owned())?;
        if let Some(tx) = self.pending_pairing.write().await.remove(fingerprint) {
            let _ = tx.send(PairDecision::TrustAndAccept);
        }
        Ok(())
    }

    /// Reject a pairing request from a peer.
    pub async fn reject_pairing(&self, fingerprint: &str) -> Result<()> {
        if let Some(tx) = self.pending_pairing.write().await.remove(fingerprint) {
            let _ = tx.send(PairDecision::Reject);
        }
        Ok(())
    }

    /// Remove trust from a peer by fingerprint.
    /// Also removes from the accept store since accept ⊆ trust.
    pub async fn untrust_peer(&self, fingerprint: &str) -> Result<()> {
        self.trust_store.lock().await.untrust(fingerprint)?;
        let _ = self.accept_store.lock().await.unaccept(fingerprint);
        Ok(())
    }

    /// Get trusted peers' fingerprints.
    pub async fn trusted_fingerprints(&self) -> Vec<String> {
        self.trust_store.lock().await.trusted_fingerprints()
    }

    /// Get accepted peers' fingerprints.
    pub async fn accepted_fingerprints(&self) -> Vec<String> {
        self.accept_store.lock().await.accepted_fingerprints()
    }

    /// Remove a peer from the accept store.
    pub async fn unaccept_peer(&self, fingerprint: &str) -> Result<()> {
        self.accept_store.lock().await.unaccept(fingerprint)?;
        Ok(())
    }

    /// Get a specific session by ID.
    pub async fn get_session(&self, session_id: &SessionId) -> Option<TransferSession> {
        self.sessions.read().await.get(session_id).cloned()
    }

    /// List all active sessions.
    pub async fn list_sessions(&self) -> Vec<TransferSession> {
        self.sessions.read().await.values().cloned().collect()
    }

    /// Detect current networks and return their info.
    pub fn current_networks(&self) -> Vec<NetworkInfo> {
        crate::network::detect_current_networks_smart()
    }

    /// Probe known devices on the current network(s).
    /// Returns a list of probed devices that are online.
    /// Emits `KnownDeviceProbed` events for each online device.
    pub async fn probe_known_devices(&self) -> Vec<PeerInfo> {
        let networks = self.current_networks();
        let subnets: Vec<String> = networks.iter().map(|n| n.subnet.clone()).collect();

        if subnets.is_empty() {
            return Vec::new();
        }

        let store = self.known_device_store.lock().await;
        let probed = crate::discovery::probe::probe_all_known_devices(&store, &subnets).await;
        drop(store);

        let trusted = self.trust_store.lock().await.trusted_fingerprints();
        let mut online_peers = Vec::new();

        for device in probed {
            let is_trusted = trusted.iter().any(|fp| fp == &device.fingerprint);
            let peer_info = device.to_peer_info(is_trusted);

            // Add to discovered peers
            let mut map = self.peers.write().await;
            map.insert(peer_info.id, peer_info.clone());
            drop(map);

            // Emit event
            let _ = self.event_tx.send(PrivetEvent::KnownDeviceProbed {
                peer: peer_info.clone(),
            });

            online_peers.push(peer_info);
        }

        online_peers
    }

    /// Add a known device IP mapping manually.
    pub async fn add_known_device_ip(
        &self,
        fingerprint: String,
        peer_id: PeerId,
        device_name: String,
        subnet: String,
        addr: SocketAddr,
        label: Option<String>,
    ) -> Result<()> {
        self.known_device_store.lock().await.add_device_ip(
            fingerprint, peer_id, device_name, subnet, addr, label,
        )?;
        Ok(())
    }

    /// Remove a network IP mapping for a known device.
    pub async fn remove_known_device_ip(
        &self,
        fingerprint: &str,
        subnet: &str,
        addr: &str,
    ) -> Result<()> {
        self.known_device_store.lock().await.remove_device_ip(fingerprint, subnet, addr)?;
        Ok(())
    }

    /// Remove a network entry for a known device.
    pub async fn remove_known_device_network(
        &self,
        fingerprint: &str,
        subnet: &str,
    ) -> Result<()> {
        self.known_device_store.lock().await.remove_device_network(fingerprint, subnet)?;
        Ok(())
    }

    /// Set a human-readable label for a network entry.
    pub async fn set_network_label(
        &self,
        fingerprint: &str,
        subnet: &str,
        label: String,
    ) -> Result<()> {
        self.known_device_store.lock().await.set_network_label(fingerprint, subnet, label)?;
        Ok(())
    }

    /// Get all known devices.
    pub async fn known_devices(&self) -> Vec<crate::known_device::KnownDevice> {
        self.known_device_store.lock().await.get_devices().to_vec()
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


