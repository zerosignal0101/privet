use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::RwLock;

use crate::engine::PairDecision;
use crate::config::SecurityMode;
use crate::error::{PrivetError, TransportError};
use crate::known_device::KnownDeviceStore;
use crate::protocol::control;
use crate::protocol::data::{self, Chunk, StreamFileEntry, StreamHeader};
use crate::protocol::handshake::{self, Accept, ControlMessage, HelloAck, ResumePoint};
use crate::session::SessionId;
use crate::transfer::progress::ProgressTracker;

/// Send Cancel on the control stream and wait for the sender to acknowledge
/// (keeps the connection alive so the Cancel message is delivered before close).
async fn send_cancel_and_wait(
    ctrl_send: &mut quinn::SendStream,
    ctrl_recv: &mut quinn::RecvStream,
    session_id: SessionId,
    reason: &str,
) {
    let cancel = ControlMessage::Cancel(handshake::Cancel {
        session_id,
        reason: reason.to_owned(),
    });
    if let Ok(data) = handshake::serialize(&cancel) {
        if control::write_control_frame(ctrl_send, &data).await.is_ok() {
            let _ = ctrl_send.finish();
        }
    }
    // Wait for sender to close after reading Cancel (timeout to avoid blocking forever)
    let mut buf = [0u8; 1];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), ctrl_recv.read(&mut buf)).await;
}

/// Receive files from a peer over an accepted QUIC connection.
pub struct Receiver {
    conn: quinn::Connection,
    remote_addr: std::net::SocketAddr,
    download_dir: PathBuf,
    chunk_size: u32,
    fingerprint: String,
    device_name: String,
    /// The receiver's configured listen port (e.g. 53530), used to build the
    /// `listen_addr` advertised in HelloAck.
    listen_port: u16,
    trust_store: Arc<tokio::sync::Mutex<crate::security::trust::TrustStore>>,
    security_mode: SecurityMode,
    accept_store: Arc<tokio::sync::Mutex<crate::security::accept::AcceptStore>>,
    known_device_store: Arc<tokio::sync::Mutex<KnownDeviceStore>>,
    pending_incoming: Arc<RwLock<HashMap<SessionId, oneshot::Sender<bool>>>>,
    pending_pairing: Arc<RwLock<HashMap<String, oneshot::Sender<PairDecision>>>>,
    cancel_signals:
        Arc<RwLock<HashMap<SessionId, std::sync::Arc<std::sync::atomic::AtomicBool>>>>,
    session_meta: Arc<RwLock<HashMap<SessionId, crate::engine::SessionMeta>>>,
}

impl Receiver {
    pub fn new(
        conn: quinn::Connection,
        download_dir: PathBuf,
        chunk_size: u32,
        fingerprint: String,
        device_name: String,
        listen_port: u16,
        trust_store: Arc<tokio::sync::Mutex<crate::security::trust::TrustStore>>,
        security_mode: SecurityMode,
        accept_store: Arc<tokio::sync::Mutex<crate::security::accept::AcceptStore>>,
        known_device_store: Arc<tokio::sync::Mutex<KnownDeviceStore>>,
        pending_incoming: Arc<RwLock<HashMap<SessionId, oneshot::Sender<bool>>>>,
        pending_pairing: Arc<RwLock<HashMap<String, oneshot::Sender<PairDecision>>>>,
        cancel_signals: Arc<
            RwLock<HashMap<SessionId, std::sync::Arc<std::sync::atomic::AtomicBool>>>,
        >,
        session_meta: Arc<RwLock<HashMap<SessionId, crate::engine::SessionMeta>>>,
    ) -> Self {
        let remote_addr = conn.remote_address();
        Self {
            conn,
            remote_addr,
            download_dir,
            chunk_size,
            fingerprint,
            device_name,
            listen_port,
            trust_store,
            security_mode,
            accept_store,
            known_device_store,
            pending_incoming,
            pending_pairing,
            cancel_signals,
            session_meta,
        }
    }

    /// Record the peer as a known device after trust is established.
    /// Uses the peer's advertised listen address (from Hello) if available,
    /// falling back to the connection's remote address.
    async fn record_known_device(
        &self,
        fingerprint: String,
        device_name: &str,
        listen_addr: Option<std::net::SocketAddr>,
    ) {
        let addr = listen_addr.unwrap_or(self.remote_addr);
        let subnet = crate::network::subnet_from_addr(
            &addr.ip(),
            crate::network::default_prefix_len(match addr.ip() {
                std::net::IpAddr::V4(ref v4) => v4,
                std::net::IpAddr::V6(_) => return,
            }),
        );
        let mut store = self.known_device_store.lock().await;
        let _ = store.add_or_update_device(
            fingerprint,
            crate::peer::PeerId(uuid::Uuid::nil()),
            device_name.to_owned(),
            subnet,
            addr,
            None,
        );
    }

    /// Send a Reject on the control stream and wait for the sender to close.
    /// This ensures the sender reads the Reject (not a CONNECTION_CLOSE race).
    async fn send_reject_and_wait(
        ctrl_send: &mut quinn::SendStream,
        ctrl_recv: &mut quinn::RecvStream,
        session_id: SessionId,
        reason: &str,
    ) -> Result<(), PrivetError> {
        let reject = ControlMessage::Reject(handshake::Reject {
            session_id,
            reason: reason.to_owned(),
        });
        let data = handshake::serialize(&reject)?;
        if control::write_control_frame(ctrl_send, &data).await.is_ok() {
            let _ = ctrl_send.finish();
        }
        // Drain the sender's Offer (and any subsequent data) then wait for the
        // sender to close. This ensures the Reject is delivered before we drop
        // our end, avoiding a "connection lost" race on the sender side.
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                ctrl_recv.read(&mut buf),
            ).await {
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(_)) => continue,
            }
        }
        Ok(())
    }

    pub async fn receive(
        &self,
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    ) -> Result<(SessionId, String, String, Vec<crate::storage::records::TransferFileRecord>, Option<std::net::SocketAddr>), PrivetError> {
        let (mut ctrl_send, mut ctrl_recv) = self.conn.accept_bi()
            .await.map_err(|e| TransportError::ConnectionLost(format!("accept-bi: {e}")))?;

        tracing::info!("[quic-recv] incoming QUIC connection from {} (session via Hello)", self.remote_addr);

        // 1. Receive Hello
        let hello_data = control::read_control_frame(&mut ctrl_recv)
            .await
            .map_err(|e| PrivetError::Transport(TransportError::ConnectionLost(format!("read-hello: {e}"))))?;
        let hello = match handshake::deserialize(&hello_data)? {
            ControlMessage::Hello(h) => h,
            other => return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Hello".into(), got: format!("{other:?}"),
            }.into()),
        };
        let peer_fingerprint = hello.fingerprint.clone();
        let _peer_device_name = hello.device_name.clone();
        // Build the peer's listening address from the connection's remote IP
        // (the IP the sender connected from) and their advertised listen port.
        let peer_listen_addr = hello.listen_port
            .map(|port| std::net::SocketAddr::new(self.remote_addr.ip(), port));
        if peer_listen_addr.is_some() {
            tracing::debug!("[quic-recv] hello listen_port={:?} → peer_listen_addr={:?}",
                hello.listen_port, peer_listen_addr);
        }

        // 2. TLS fingerprint verification (MITM protection)
        // Verify the peer's TLS certificate fingerprint matches the Hello claim.
        // Extract the fingerprint eagerly and drop the Box<dyn Any> before any .await.
        let tls_fp = {
            let tls_identity = self.conn.peer_identity()
                .ok_or_else(|| PrivetError::Security(
                    crate::error::SecurityError::NotTrusted("no peer certificate presented".into())
                ))?;
            let certs = tls_identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok_or_else(|| PrivetError::Security(
                    crate::error::SecurityError::NotTrusted("unexpected peer identity type".into())
                ))?;
            let cert = certs.first()
                .ok_or_else(|| PrivetError::Security(
                    crate::error::SecurityError::NotTrusted("peer certificate chain is empty".into())
                ))?;
            crate::security::cert::fingerprint_from_der(cert.as_ref())
        };
        if tls_fp != peer_fingerprint {
            return Err(PrivetError::Security(crate::error::SecurityError::NotTrusted(
                format!("TLS cert fingerprint '{tls_fp}' != Hello claim '{peer_fingerprint}'"))));
        }

        // 3. Send HelloAck immediately (sender needs our fingerprint for trust check)
        let hello_ack = ControlMessage::HelloAck(HelloAck {
            version: handshake::PROTOCOL_VERSION, accepted: true,
            fingerprint: self.fingerprint.clone(),
            device_name: self.device_name.clone(),
            listen_port: Some(self.listen_port),
        });
        control::write_control_frame(&mut ctrl_send, &handshake::serialize(&hello_ack)?).await?;

        // 4. Pairing flow: if peer not trusted, wait for user decision
        let is_trusted = self.trust_store.lock().await.trusted_fingerprints().iter().any(|fp| fp == &peer_fingerprint);
        if !is_trusted && self.security_mode != SecurityMode::AllowAll {
            // Check if there's already a pending pairing for this peer
            // (e.g. from a previous connection that the sender retried).
            let already_pending = self.pending_pairing.read().await.contains_key(&peer_fingerprint);

            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending_pairing.write().await.insert(peer_fingerprint.clone(), tx);

            // Only emit AwaitingPairing once per peer to avoid duplicate prompts.
            if !already_pending {
                let code = crate::security::trust::TrustStore::pairing_code(&self.fingerprint, &peer_fingerprint);
                // Use peer's advertised listen address if available, fall back to connection remote address.
                let pairing_addr = peer_listen_addr.unwrap_or(self.remote_addr);
                tracing::debug!("[receiver] AwaitingPairing: name={} addr={:?} fp={}",
                    hello.device_name, pairing_addr, peer_fingerprint);
                let _ = event_tx.send(crate::engine::PrivetEvent::AwaitingPairing {
                    session_id: SessionId(uuid::Uuid::nil()),
                    peer: crate::peer::PeerInfo {
                        id: crate::peer::PeerId(uuid::Uuid::nil()),
                        name: hello.device_name.clone(), addresses: vec![pairing_addr],
                        fingerprint: peer_fingerprint.clone(), is_trusted: false,
                        last_seen: std::time::SystemTime::now(), platform: Some(hello.platform.clone()), version: None,
                    }, code,
                });
            }

            match rx.await.unwrap_or(PairDecision::Reject) {
                PairDecision::Trust => {
                    let _ = self.trust_store.lock().await.trust(peer_fingerprint.clone());
                    self.record_known_device(peer_fingerprint.clone(), &hello.device_name, peer_listen_addr).await;
                }
                PairDecision::TrustAndAccept => {
                    let _ = self.trust_store.lock().await.trust(peer_fingerprint.clone());
                    let _ = self.accept_store.lock().await.accept(peer_fingerprint.clone());
                    self.record_known_device(peer_fingerprint.clone(), &hello.device_name, peer_listen_addr).await;
                }
                PairDecision::Reject => {
                    // Send a Reject, then wait for the sender to close so the
                    // Reject is delivered before the connection drops.
                    let _ = Self::send_reject_and_wait(
                        &mut ctrl_send, &mut ctrl_recv,
                        SessionId(uuid::Uuid::nil()),
                        "pairing required",
                    ).await;
                    return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
                }
            }
            self.pending_pairing.write().await.remove(&peer_fingerprint);

            // Sender likely rejected this connection (PairingRequired).
            // Check if the connection is still alive before trying to read Offer.
            // Note: close_reason() can race with CONNECTION_CLOSE delivery, so
            // also handle the read error gracefully below.
            if self.conn.close_reason().is_some() {
                tracing::info!("[quic-recv] pairing resolved but sender closed connection, returning Ok");
                return Ok((SessionId(uuid::Uuid::nil()), peer_fingerprint.clone(), String::new(), Vec::new(), peer_listen_addr));
            }

            // Try to read Offer — will fail if sender closed the connection.
            let offer_data = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                control::read_control_frame(&mut ctrl_recv),
            ).await;
            match offer_data {
                Ok(Ok(data)) => {
                    // Sender sent a Reject instead of Offer.
                    if let Ok(ControlMessage::Reject(rej)) = handshake::deserialize(&data) {
                        tracing::info!("[quic-recv] sender rejected: {}", rej.reason);
                        return Ok((SessionId(uuid::Uuid::nil()), peer_fingerprint.clone(), String::new(), Vec::new(), peer_listen_addr));
                    }
                    // Sender retried with Offer on this same connection
                    return self.handle_offer(data, &hello, &peer_fingerprint, ctrl_send, ctrl_recv, event_tx, peer_listen_addr).await;
                }
                _ => {
                    tracing::info!("[quic-recv] pairing resolved but no Offer (connection dead or timeout), returning Ok");
                    return Ok((SessionId(uuid::Uuid::nil()), peer_fingerprint.clone(), String::new(), Vec::new(), peer_listen_addr));
                }
            }
        }

        // AllowAll: silently trust unknown peers
        if !is_trusted && self.security_mode == SecurityMode::AllowAll {
            tracing::info!("[quic-recv] AllowAll: silently trusting peer {}", &peer_fingerprint[..16]);
            let _ = self.trust_store.lock().await.trust(peer_fingerprint.clone());
        }

        // 5. Read Offer
        let offer_data = control::read_control_frame(&mut ctrl_recv).await?;
        // Sender may have sent a Reject instead (pairing needed on its side)
        if let Ok(ControlMessage::Reject(rej)) = handshake::deserialize(&offer_data) {
            tracing::info!("[quic-recv] sender rejected: {}", rej.reason);
            return Ok((SessionId(uuid::Uuid::nil()), peer_fingerprint.clone(), String::new(), Vec::new(), peer_listen_addr));
        }
        let (session_id, fp, device_name, file_records, peer_addr) = self.handle_offer(offer_data, &hello, &peer_fingerprint, ctrl_send, ctrl_recv, event_tx, peer_listen_addr).await?;
        Ok((session_id, fp, device_name, file_records, peer_addr))
    }

    async fn handle_offer(
        &self,
        offer_data: Vec<u8>,
        hello: &handshake::Hello,
        peer_fingerprint: &str,
        mut ctrl_send: quinn::SendStream,
        mut ctrl_recv: quinn::RecvStream,
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
        peer_listen_addr: Option<std::net::SocketAddr>,
    ) -> Result<(SessionId, String, String, Vec<crate::storage::records::TransferFileRecord>, Option<std::net::SocketAddr>), PrivetError> {
        let peer_device_name = hello.device_name.clone();
        let offer = match handshake::deserialize(&offer_data)? {
            ControlMessage::Offer(o) => o,
            other => return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Offer".into(), got: format!("{other:?}"),
            }.into()),
        };
        let session_id = offer.session_id;

        // Register cancel signal and metadata so cancel_transfer can interrupt and clean up
        let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.cancel_signals
            .write()
            .await
            .insert(session_id, cancel_flag.clone());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();
        let file_records: Vec<crate::storage::records::TransferFileRecord> = offer.files.files.iter()
            .map(|f| crate::storage::records::TransferFileRecord {
                path: f.relative_path.clone(),
                size: f.size,
                is_dir: f.is_dir,
                relative_path: Some(f.relative_path.clone()),
            })
            .collect();
        self.session_meta.write().await.insert(
            session_id,
            crate::engine::SessionMeta {
                direction: crate::session::TransferDirection::Receiving,
                file_relative_paths: offer.files.files.iter()
                    .map(|f| f.relative_path.clone())
                    .collect(),
                peer_name: hello.device_name.clone(),
                peer_fingerprint: peer_fingerprint.to_owned(),
                peer_address: peer_listen_addr.map(|a| a.to_string()),
                files: file_records,
                total_bytes: offer.total_size,
                started_at: now,
            },
        );

        // Trust check: reject untrusted unless AllowAll
        let is_trusted = self.trust_store.lock().await.trusted_fingerprints().iter().any(|fp| fp == peer_fingerprint);
        if !is_trusted && self.security_mode != SecurityMode::AllowAll {
            let _ = Self::send_reject_and_wait(
                &mut ctrl_send, &mut ctrl_recv,
                session_id,
                "pairing required: peer not trusted",
            ).await;
            return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
        }

        let addr_for_events = peer_listen_addr.unwrap_or(self.remote_addr);

        // Notify app layer of incoming transfer (after trust check — only for accepted transfers)
        let _ = event_tx.send(crate::engine::PrivetEvent::IncomingTransfer {
            session_id,
            peer: crate::peer::PeerInfo {
                id: crate::peer::PeerId(uuid::Uuid::nil()),
                name: hello.device_name.clone(),
                addresses: vec![addr_for_events],
                fingerprint: peer_fingerprint.to_owned(),
                is_trusted: true,
                last_seen: std::time::SystemTime::now(),
                platform: Some(hello.platform.clone()),
                version: None,
            },
            files: crate::session::FileManifest {
                files: offer.files.files.iter().map(|f| crate::session::FileEntry {
                    relative_path: f.relative_path.clone(), size: f.size,
                    modified: f.modified_secs.map(|s| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)),
                    sha256: f.sha256.clone(), is_dir: f.is_dir,
                }).collect(),
                total_size: offer.total_size,
            },
        });

        // AwaitAccept flow: determine if user prompt is needed
        match self.security_mode {
            SecurityMode::AllowAll | SecurityMode::TrustRequired => {
                tracing::debug!("[quic-recv] AllowAll/TrustRequired: auto-accepting session {}", session_id.0);
                // AllowAll: auto-accept all; TrustRequired: trusted = auto-accept
            }
            SecurityMode::Strict => {
                if !self.accept_store.lock().await.is_accepted(peer_fingerprint) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending_incoming.write().await.insert(session_id, tx);
            tracing::debug!("[quic-recv] AwaitingAccept: inserted session {} into pending_incoming", session_id.0);
            let _ = event_tx.send(crate::engine::PrivetEvent::AwaitingAccept {
                session_id,
                peer: crate::peer::PeerInfo {
                    id: crate::peer::PeerId(uuid::Uuid::nil()), name: hello.device_name.clone(),
                    addresses: vec![addr_for_events], fingerprint: peer_fingerprint.to_owned(),
                    is_trusted: true, last_seen: std::time::SystemTime::now(),
                    platform: Some(hello.platform.clone()), version: None,
                },
                files: crate::session::FileManifest {
                    files: offer.files.files.iter().map(|f| crate::session::FileEntry {
                        relative_path: f.relative_path.clone(), size: f.size,
                        modified: f.modified_secs.map(|s| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)),
                        sha256: f.sha256.clone(), is_dir: f.is_dir,
                    }).collect(),
                    total_size: offer.total_size,
                },
            });
            tracing::debug!("[quic-recv] AwaitingAccept: waiting for user decision (session {})...", session_id.0);
            if !rx.await.unwrap_or(false) {
                tracing::debug!("[quic-recv] AwaitingAccept: user REJECTED session {}", session_id.0);
                let _ = Self::send_reject_and_wait(
                    &mut ctrl_send, &mut ctrl_recv,
                    session_id,
                    "transfer rejected by user",
                ).await;
                return Err(PrivetError::TransferRejected("transfer rejected by user".into()));
            }
            tracing::debug!("[quic-recv] AwaitingAccept: user ACCEPTED session {}", session_id.0);
            self.pending_incoming.write().await.remove(&session_id);
        }
            }
        }

        // Disk space pre-check
        if fs_available_space(&self.download_dir)? < offer.total_size {
            let _ = Self::send_reject_and_wait(
                &mut ctrl_send, &mut ctrl_recv,
                session_id,
                &format!("disk full: need {}, have {}", offer.total_size, fs_available_space(&self.download_dir)?),
            ).await;
            return Err(PrivetError::DiskFull { needed: offer.total_size, available: fs_available_space(&self.download_dir)? });
        }

        // Resume map
        let file_entries: Vec<crate::session::FileEntry> = offer.files.files.iter().map(|f| crate::session::FileEntry {
            relative_path: f.relative_path.clone(), size: f.size,
            modified: f.modified_secs.map(|s| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)),
            sha256: f.sha256.clone(), is_dir: f.is_dir,
        }).collect();
        let raw_map = crate::transfer::resume::check_resume(&self.download_dir, &file_entries);
        let resume_map: std::collections::HashMap<String, ResumePoint> = raw_map
            .into_iter().map(|(path, bytes)| (path, ResumePoint { bytes_received: bytes })).collect();

        // Send Accept
        control::write_control_frame(&mut ctrl_send, &handshake::serialize(&ControlMessage::Accept(Accept { session_id, resume_map }))?).await?;

        // Build top-level directory rename map for folder-level dedup.
        // If a top-level directory already exists in the download dir, rename
        // the entire folder (e.g. "colors" → "colors (1)") instead of
        // renaming individual files inside the existing folder.
        let dir_rename_map = {
            let rel_paths: Vec<&str> = offer.files.files.iter()
                .map(|f| f.relative_path.as_str())
                .collect();
            let raw = crate::transfer::receiver::build_top_dir_rename_map(
                rel_paths.iter().copied(),
                &self.download_dir,
            );
            // Convert from HashMap<&str, String> to HashMap<String, String>
            raw.into_iter().map(|(k, v)| (k.to_owned(), v)).collect::<std::collections::HashMap<String, String>>()
        };
        let rename_ref = if dir_rename_map.is_empty() { None } else { Some(&dir_rename_map) };

        // Create directories for directory marker entries (no data stream for these)
        let mut actual_dests: Vec<PathBuf> = Vec::new();
        for file_entry in &offer.files.files {
            if file_entry.is_dir && file_entry.size == 0 {
                let rel_path = if let Some(map) = rename_ref {
                    let ref_map: std::collections::HashMap<&str, String> =
                        map.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
                    crate::transfer::receiver::adjust_path(&file_entry.relative_path, &ref_map)
                } else {
                    std::borrow::Cow::Borrowed(file_entry.relative_path.as_str())
                };
                let dir_path = self.download_dir.join(&*rel_path);
                tokio::fs::create_dir_all(&dir_path).await?;
                actual_dests.push(dir_path);
            }
        }

        // Receive data streams (directory markers have no data stream)
        let data_file_count = offer.files.files.iter().filter(|f| !f.is_dir).count();
        let total_size = offer.total_size;
        let tracker = std::sync::Arc::new(std::sync::Mutex::new(ProgressTracker::new(total_size)));
        let mut files_received = 0usize;
        while files_received < data_file_count {
            // Check local cancel flag first
            if cancel_flag.load(std::sync::atomic::Ordering::SeqCst) {
                send_cancel_and_wait(&mut ctrl_send, &mut ctrl_recv, session_id, "cancelled by user").await;
                let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                    session_id, error: "cancelled by user".into(),
                    direction: crate::session::TransferDirection::Receiving,
                });
                return Err(PrivetError::TransferCancelled);
            }

            // Wait for the next data stream from the sender.
            // If accept_uni() fails, check if we have a Cancel message on the
            // control stream (intentional cancel) or just a dropped connection.
            let mut data_stream = match self.conn.accept_uni().await {
                Ok(stream) => stream,
                Err(_) => {
                    if let Ok(data) = control::read_control_frame(&mut ctrl_recv).await {
                        if let Ok(ControlMessage::Cancel(_)) = handshake::deserialize(&data) {
                            // Acknowledge by finishing our send half
                            let _ = ctrl_send.finish();
                            let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                                session_id, error: "sender cancelled the transfer".into(),
                                direction: crate::session::TransferDirection::Receiving,
                            });
                            return Err(PrivetError::TransferCancelled);
                        }
                    }
                    // No Cancel message — sender disconnected or network error
                    let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                        session_id, error: "sender disconnected".into(),
                        direction: crate::session::TransferDirection::Receiving,
                    });
                    return Err(PrivetError::Transport(TransportError::ConnectionLost(
                        "sender disconnected".into(),
                    )));
                }
            };

            let header_data = match control::read_control_frame(&mut data_stream).await {
                Ok(d) => d,
                Err(_) => {
                    let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                        session_id, error: "sender disconnected".into(),
                        direction: crate::session::TransferDirection::Receiving,
                    });
                    return Err(PrivetError::Transport(TransportError::ConnectionLost(
                        "sender disconnected".into(),
                    )));
                }
            };
            let stream_header: StreamHeader = data::deserialize_stream_header(&header_data)?;
            files_received += stream_header.files.len();
            let dests = receive_stream_files(
                &mut data_stream, &stream_header, &self.download_dir,
                &tracker, event_tx, session_id, total_size,
                Some(&cancel_flag), rename_ref,
            ).await;
            let dests = match dests {
                Ok(d) => d,
                Err(PrivetError::TransferCancelled) => {
                    send_cancel_and_wait(&mut ctrl_send, &mut ctrl_recv, session_id, "cancelled by user").await;
                    let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                        session_id, error: "cancelled by user".into(),
                        direction: crate::session::TransferDirection::Receiving,
                    });
                    return Err(PrivetError::TransferCancelled);
                }
                Err(e) => {
                    // Before propagating a transport error, check if a Cancel
                    // message arrived on the control stream (sender cancelled
                    // while we were in the middle of receiving chunk data).
                    if let Ok(data) = control::read_control_frame(&mut ctrl_recv).await {
                        if let Ok(ControlMessage::Cancel(_)) = handshake::deserialize(&data) {
                            let _ = ctrl_send.finish();
                            let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                                session_id, error: "sender cancelled the transfer".into(),
                                direction: crate::session::TransferDirection::Receiving,
                            });
                            return Err(PrivetError::TransferCancelled);
                        }
                    }
                    // Network error — notify the UI so the tile doesn't stay stuck
                    let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                        session_id, error: "sender disconnected".into(),
                        direction: crate::session::TransferDirection::Receiving,
                    });
                    return Err(e);
                }
            };
            actual_dests.extend(dests);
        }

        // Clean up session tracking (transfer completed normally)
        self.cancel_signals.write().await.remove(&session_id);
        self.session_meta.write().await.remove(&session_id);

        // Build file_records from actual paths, deriving relative path from download_dir
        let actual_file_records: Vec<crate::storage::records::TransferFileRecord> = actual_dests.iter().map(|p| {
            let meta = std::fs::metadata(p).ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let relative_path = p.strip_prefix(&self.download_dir).ok()
                .and_then(|r| r.to_str())
                .map(|s| s.replace('\\', "/"));
            crate::storage::records::TransferFileRecord {
                path: p.to_string_lossy().to_string(),
                size,
                is_dir,
                relative_path,
            }
        }).collect();

        // Complete → Verified
        let complete_data = control::read_control_frame(&mut ctrl_recv).await?;
        let _complete = handshake::deserialize(&complete_data)?;
        let verified = ControlMessage::Verified(handshake::Verified { session_id, sha256: vec![0; 32] });
        control::write_control_frame(&mut ctrl_send, &handshake::serialize(&verified)?).await?;
        ctrl_send.finish().map_err(|e| TransportError::ConnectionLost(format!("finish: {e}")))?;

        let mut buf = [0u8; 1];
        let _ = ctrl_recv.read(&mut buf).await;
        let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id, direction: crate::session::TransferDirection::Receiving });
        tracing::info!("[quic-recv] transfer complete for session {session_id}");
        Ok((session_id, peer_fingerprint.to_owned(), peer_device_name.clone(), actual_file_records, peer_listen_addr))
    }
}

async fn receive_stream_files(
    data_stream: &mut quinn::RecvStream, stream_header: &StreamHeader,
    download_dir: &PathBuf, tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    session_id: SessionId, total_size: u64,
    cancel_flag: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
    // Pre-computed top-level directory rename map for folder-level dedup.
    // When a top-level directory already exists in download_dir, this map
    // maps its original name to a unique variant (e.g. "colors" → "colors (1)").
    rename_map: Option<&std::collections::HashMap<String, String>>,
) -> Result<Vec<PathBuf>, PrivetError> {
    let mut actual_dests = Vec::new();
    for file_entry in &stream_header.files {
        // Adjust path if top-level directory was renamed
        let adjusted_rel = if let Some(map) = rename_map {
            let rel = file_entry.relative_path.as_str();
            let ref_map: std::collections::HashMap<&str, String> =
                map.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            crate::transfer::receiver::adjust_path(rel, &ref_map)
        } else {
            std::borrow::Cow::Borrowed(file_entry.relative_path.as_str())
        };

        // Directory marker: create directory, no data to read
        if file_entry.is_dir && file_entry.total_size == 0 {
            let dir_path = download_dir.join(&*adjusted_rel);
            tokio::fs::create_dir_all(&dir_path).await?;
            actual_dests.push(dir_path);
            continue;
        }

        // Use atomic create_new (O_CREAT|O_EXCL) to avoid FUSE caching races
        let dest;
        let mut file;
        let is_resume = file_entry.start_offset > 0;
        if is_resume {
            // Resume: exact path required (previous partial transfer)
            dest = download_dir.join(&*adjusted_rel);
            if let Some(parent) = dest.parent() { tokio::fs::create_dir_all(parent).await?; }
            file = tokio::fs::OpenOptions::new().write(true).open(&dest).await?;
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(file_entry.start_offset)).await?;
        } else {
            // New file: atomically create with unique name
            let base = download_dir.join(&*adjusted_rel);
            let pair = open_file_atomic(&base).await
                .map_err(PrivetError::Io)?;
            dest = pair.0;
            file = pair.1;
        }

        let result = receive_stream_one_file(
            data_stream, file_entry, dest.clone(), file,
            tracker, event_tx, session_id, total_size,
            cancel_flag, is_resume,
        ).await;

        match result {
            Ok(()) => actual_dests.push(dest),
            Err(e) => {
                // Only clean up non-resume files (resume files keep partial progress)
                if !is_resume {
                    let _ = tokio::fs::remove_file(&dest).await;
                    tracing::debug!("[quic-recv] error, cleaned up partial file {:?}: {e}", dest);
                }
                return Err(e);
            }
        }
    }
    Ok(actual_dests)
}

/// Receive chunk data for a single file from a QUIC stream.
async fn receive_stream_one_file(
    data_stream: &mut quinn::RecvStream,
    file_entry: &StreamFileEntry,
    _dest: std::path::PathBuf,
    mut file: tokio::fs::File,
    tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    session_id: SessionId, total_size: u64,
    cancel_flag: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
    _is_resume: bool,
) -> Result<(), PrivetError> {
    let expected_bytes = file_entry.total_size.saturating_sub(file_entry.start_offset);
    let mut written: u64 = 0;
    while written < expected_bytes {
        if let Some(flag) = cancel_flag {
            if flag.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(PrivetError::TransferCancelled);
            }
        }
        let chunk_header_data = control::read_control_frame(data_stream).await
            .map_err(|_| PrivetError::Transport(TransportError::ConnectionLost(
                "sender disconnected".into(),
            )))?;
        let chunk: Chunk = data::deserialize_chunk(&chunk_header_data)?;
        let mut buf = vec![0u8; chunk.length as usize];
        data_stream.read_exact(&mut buf).await
            .map_err(|_| PrivetError::Transport(TransportError::ConnectionLost(
                "sender disconnected".into(),
            )))?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &buf).await?;
        written += chunk.length as u64;
        let (tx, sp) = { let mut t = tracker.lock().unwrap(); t.record(chunk.length as u64); (t.bytes_transferred(), t.speed_bps()) };
        let _ = event_tx.send(crate::engine::PrivetEvent::TransferProgress {
            session_id, progress: crate::session::TransferProgress { total_bytes: total_size, bytes_transferred: tx, current_speed_bps: sp, per_file: vec![] },
            direction: crate::session::TransferDirection::Receiving,
        });
    }
    tokio::io::AsyncWriteExt::flush(&mut file).await?;
    Ok(())
}

pub(crate) fn fs_available_space(_path: &PathBuf) -> std::io::Result<u64> { Ok(u64::MAX) }

/// Detect top-level directory conflicts and build a rename map.
/// If a top-level directory in the file list already exists in `download_dir`,
/// computes a unique name (e.g. "colors (1)") and maps the original name to it.
/// This avoids mixing files from different transfers into the same folder.
/// Only existing directories are renamed — individual files are not affected
/// (they use `open_file_atomic` for file-level dedup instead).
pub(crate) fn build_top_dir_rename_map<'a>(
    files: impl IntoIterator<Item = &'a str>,
    download_dir: &std::path::Path,
) -> std::collections::HashMap<&'a str, String> {
    let mut map = std::collections::HashMap::new();
    let mut seen = std::collections::HashSet::new();

    for path in files {
        let top = match path.split('/').next() {
            Some(t) if !t.is_empty() => t,
            _ => continue,
        };
        if !seen.insert(top) {
            continue; // already checked
        }
        let candidate = download_dir.join(top);
        // Only rename existing directories — regular files use open_file_atomic dedup
        if !candidate.is_dir() {
            continue;
        }
        // Find unique name
        for i in 1..1000 {
            let new_name = format!("{} ({})", top, i);
            if !download_dir.join(&new_name).exists() {
                map.insert(top, new_name);
                break;
            }
        }
    }

    map
}

/// Apply a top-level directory rename map to a relative path.
/// Returns the adjusted path if the top-level directory was renamed.
pub(crate) fn adjust_path<'a>(
    relative_path: &'a str,
    rename_map: &std::collections::HashMap<&'a str, String>,
) -> std::borrow::Cow<'a, str> {
    let top = match relative_path.split('/').next() {
        Some(t) if !t.is_empty() => t,
        _ => return std::borrow::Cow::Borrowed(relative_path),
    };
    match rename_map.get(top) {
        Some(new_top) => {
            let suffix = &relative_path[top.len()..]; // includes leading '/' or empty
            std::borrow::Cow::Owned(format!("{}{}", new_top, suffix))
        }
        None => std::borrow::Cow::Borrowed(relative_path),
    }
}

/// Atomically create a new file with a unique name using O_CREAT|O_EXCL.
/// If the base path already exists, appends " (1)", " (2)" etc.
/// Returns the opened file and the path chosen.
/// This avoids TOCTOU races and handles FUSE caching quirks on Android.
pub(crate) async fn open_file_atomic(
    base: &std::path::Path,
) -> std::io::Result<(std::path::PathBuf, tokio::fs::File)> {
    if let Some(parent) = base.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let stem = base.file_stem().and_then(|s| s.to_str()).unwrap_or("file").to_owned();
    let ext = base.extension().and_then(|s| s.to_str()).unwrap_or("").to_owned();
    for i in 0..1000 {
        let candidate = if i == 0 { base.to_path_buf() } else {
            let name = if ext.is_empty() { format!("{stem} ({i})") } else { format!("{stem} ({i}).{ext}") };
            base.with_file_name(name)
        };
        match tokio::fs::OpenOptions::new()
            .create_new(true).write(true).open(&candidate).await
        {
            Ok(f) => return Ok((candidate, f)),
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("no unique name found after 1000 tries for {}", stem),
    ))
}
