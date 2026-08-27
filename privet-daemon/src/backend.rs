use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use privet_core::ops::{PeerTarget, ServeHandle};
use privet_core::{Engine, EngineEvent};
use privet_ipc::*;
use privet_security::session::PairingOutcome;
use tokio::sync::{Mutex, Notify};

use crate::config::{collision_from_dto, collision_to_dto};
use crate::events::EventBroker;

pub struct BackendError { pub code: String, pub message: String }

impl BackendError {
    fn invalid(message: impl Into<String>) -> Self { Self { code: "invalid_request".into(), message: message.into() } }
}

impl From<privet_core::CoreError> for BackendError {
    fn from(error: privet_core::CoreError) -> Self {
        Self { code: error.error_code().into(), message: error.to_string() }
    }
}

pub struct DaemonBackend {
    pub engine: Arc<Engine>,
    serve: Mutex<Option<ServeHandle>>,
    quic_addr: SocketAddr,
    tcp_addr: SocketAddr,
    session_id: String,
    pub events: Arc<EventBroker>,
    pub shutdown: Arc<Notify>,
}

impl DaemonBackend {
    pub fn new(engine: Arc<Engine>, serve: ServeHandle, events: Arc<EventBroker>, shutdown: Arc<Notify>) -> Self {
        Self {
            quic_addr: serve.quic_addr,
            tcp_addr: serve.tcp_addr,
            session_id: uuid::Uuid::new_v4().to_string(),
            engine,
            serve: Mutex::new(Some(serve)),
            events,
            shutdown,
        }
    }

    pub async fn handle(&self, request: Request) -> std::result::Result<ResponsePayload, BackendError> {
        match request {
            Request::Ping => Ok(ResponsePayload::Pong { protocol_version: IPC_PROTOCOL_VERSION }),
            Request::GetStatus => {
                let identity = self.engine.identity_info();
                Ok(ResponsePayload::Status(DaemonStatus {
                    protocol_version: IPC_PROTOCOL_VERSION,
                    daemon_version: env!("CARGO_PKG_VERSION").into(),
                    session_id: self.session_id.clone(),
                    device_fingerprint: identity.device_fingerprint,
                    quic_addr: self.quic_addr.to_string(),
                    tcp_addr: self.tcp_addr.to_string(),
                    active_transfers: self.engine.active_transfer_ids(),
                }))
            }
            Request::GetIdentity => {
                let identity = self.engine.identity_info();
                Ok(ResponsePayload::Identity(IdentityDto {
                    device_fingerprint: identity.device_fingerprint,
                    device_name: identity.name,
                }))
            }
            Request::ListPeers => Ok(ResponsePayload::Peers(
                self.engine.discover_snapshot().into_iter().map(peer_dto).collect()
            )),
            Request::RefreshPeers => { self.engine.discover_refresh().await?; Ok(ResponsePayload::Ack) }
            Request::ListTrusted => Ok(ResponsePayload::Trusted(
                self.engine.list_trusted()?.into_iter().map(trusted_dto).collect()
            )),
            Request::GeneratePairingCode => {
                let code = self.engine.generate_pairing_code()?;
                Ok(ResponsePayload::PairingCode {
                    code,
                    validity_secs: self.engine.engine_config().pairing.code_validity_secs,
                })
            }
            Request::Pair { peer, code } => {
                let (quic, tcp) = self.resolve_pairing_peer(peer)?;
                match self.engine.pair_initiate_with_ports(quic, tcp, code).await? {
                    PairingOutcome::Paired { peer_device_fingerprint, .. } => {
                        Ok(ResponsePayload::PairingResult {
                            paired: true,
                            device_fingerprint: Some(peer_device_fingerprint),
                        })
                    }
                    PairingOutcome::Failed { reason } => Err(BackendError {
                        code: "pairing_failed".into(),
                        message: reason.to_string(),
                    }),
                }
            }
            Request::RevokePeer { device_fingerprint, reason } => {
                self.engine.revoke_peer(&device_fingerprint, &reason)?;
                Ok(ResponsePayload::Ack)
            }
            Request::ForgetPeer { device_fingerprint } => {
                self.engine.forget_peer(&device_fingerprint)?;
                Ok(ResponsePayload::Ack)
            }
            Request::Send { paths, device_fingerprint, as_name } => {
                if paths.is_empty() { return Err(BackendError::invalid("paths must not be empty")); }
                let transfer_id = new_transfer_id();
                let queued_id = transfer_id.clone();
                let engine = self.engine.clone();
                let events = self.events.clone();
                let error_id = transfer_id.clone();
                tokio::spawn(async move {
                    if let Err(error) = engine.send_with_id(
                        paths,
                        &PeerTarget::ByDeviceFingerprint(device_fingerprint),
                        None,
                        as_name.as_deref(),
                        transfer_id,
                    ).await {
                        publish_start_error_for_id(&events, error_id, error).await;
                    }
                });
                Ok(ResponsePayload::TransferQueued { transfer_id: queued_id })
            }
            Request::ResumeTransfer { transfer_id } => {
                let queued_id = transfer_id.clone();
                let engine = self.engine.clone();
                let events = self.events.clone();
                let error_id = transfer_id.clone();
                tokio::spawn(async move {
                    if let Err(error) = engine.resume_send(&transfer_id).await {
                        publish_start_error_for_id(&events, error_id, error).await;
                    }
                });
                Ok(ResponsePayload::TransferQueued { transfer_id: queued_id })
            }
            Request::ResendTransfer { transfer_id } => {
                let new_id = new_transfer_id();
                let queued_id = new_id.clone();
                let engine = self.engine.clone();
                let events = self.events.clone();
                let error_id = new_id.clone();
                tokio::spawn(async move {
                    if let Err(error) = engine.resend_with_id(&transfer_id, new_id).await {
                        publish_start_error_for_id(&events, error_id, error).await;
                    }
                });
                Ok(ResponsePayload::TransferQueued { transfer_id: queued_id })
            }
            Request::AcceptTransfer { transfer_id, accept } => {
                if !self.engine.resolve_offer(&transfer_id, accept) {
                    return Err(BackendError::invalid("transfer offer is not pending"));
                }
                Ok(ResponsePayload::Ack)
            }
            Request::CancelTransfer { transfer_id } => { self.engine.cancel_transfer(&transfer_id).await?; Ok(ResponsePayload::Ack) }
            Request::PauseTransfer { transfer_id } => { self.engine.pause_transfer(&transfer_id).await?; Ok(ResponsePayload::Ack) }
            Request::ContinueTransfer { transfer_id } => { self.engine.resume_transfer(&transfer_id).await?; Ok(ResponsePayload::Ack) }
            Request::ListHistory { peer, limit } => {
                let rows = self.engine.history(peer.as_deref(), u64::from(limit.clamp(1, 1000)))?;
                Ok(ResponsePayload::History(rows.into_iter().map(history_dto).collect()))
            }
            Request::GetHistoryDetail { transfer_id } => {
                let row = self
                    .engine
                    .history_detail(&transfer_id)?
                    .ok_or_else(|| BackendError::invalid("transfer not found"))?;
                Ok(ResponsePayload::HistoryDetail(history_detail_dto(row)))
            }
            Request::DeleteHistory { transfer_id } => {
                self.engine.delete_history(&transfer_id)?;
                Ok(ResponsePayload::Ack)
            }
            Request::GetRuntimeConfig => Ok(ResponsePayload::RuntimeConfig(self.runtime_config())),
            Request::SetRuntimeConfig(patch) => {
                if let Some(value) = patch.accept_all_trusted { self.engine.runtime().set_accept_all_trusted(value); }
                if let Some(value) = patch.collision_policy { self.engine.runtime().set_on_collision(collision_from_dto(value)); }
                if let Some(value) = patch.save_dir {
                    if value.as_os_str().is_empty() {
                        return Err(BackendError::invalid("save_dir must not be empty"));
                    }
                    std::fs::create_dir_all(&value).map_err(|error| BackendError {
                        code: "io".into(),
                        message: format!("create save_dir: {error}"),
                    })?;
                    self.engine.runtime().set_save_dir(value);
                }
                let config = self.runtime_config();
                self.events.publish(Event::RuntimeConfigChanged(config.clone())).await;
                Ok(ResponsePayload::RuntimeConfig(config))
            }
            Request::SubscribeEvents { after_sequence } => {
                let (events, oldest_available, latest) = self.events.replay_after(after_sequence).await;
                Ok(ResponsePayload::EventReplay { events, oldest_available, latest })
            }
            Request::Shutdown => {
                self.events.publish(Event::DaemonStopping).await;
                if let Some(serve) = self.serve.lock().await.take() { serve.shutdown().await; }
                self.engine.shutdown().await?;
                Ok(ResponsePayload::Ack)
            }
        }
    }

    fn runtime_config(&self) -> RuntimeConfigDto {
        RuntimeConfigDto {
            accept_all_trusted: self.engine.runtime().accept_all_trusted(),
            collision_policy: collision_to_dto(self.engine.runtime().on_collision()),
            save_dir: self.engine.runtime().save_dir(),
        }
    }

    fn resolve_pairing_peer(&self, peer: PairingPeer) -> std::result::Result<(SocketAddr, SocketAddr), BackendError> {
        let (ip, quic_port, tcp_port) = match peer {
            PairingPeer::Endpoint { ip, quic_port, tcp_port } => (
                ip.parse::<IpAddr>().map_err(|_| BackendError::invalid("invalid peer IP"))?,
                quic_port,
                tcp_port,
            ),
            PairingPeer::Discovered { device_fingerprint } => {
                let peer = self.engine.discover_snapshot().into_iter()
                    .find(|peer| peer.device_fingerprint == device_fingerprint)
                    .ok_or_else(|| BackendError::invalid("peer is not currently discovered"))?;
                let candidate = peer.candidates.into_iter().max_by_key(|candidate| candidate.last_seen_ms)
                    .ok_or_else(|| BackendError::invalid("peer has no candidate address"))?;
                (candidate.ip, candidate.quic_port, candidate.tcp_port)
            }
        };
        Ok((SocketAddr::new(ip, quic_port), SocketAddr::new(ip, tcp_port)))
    }
}

pub fn map_event(event: EngineEvent) -> Event {
    match event {
        EngineEvent::DeviceDiscovered { device_fingerprint, device_name } => Event::DeviceDiscovered { device_fingerprint, device_name },
        EngineEvent::DeviceLost { device_fingerprint } => Event::DeviceLost { device_fingerprint },
        EngineEvent::PairingRequested { device_fingerprint } => Event::PairingRequested { device_fingerprint },
        EngineEvent::PairingResult { device_fingerprint, success, error } => Event::PairingResult { device_fingerprint, success, error },
        EngineEvent::TransferPreparing { transfer_id } => Event::TransferPreparing { transfer_id },
        EngineEvent::TransferPreparingProgress { transfer_id, scanned_bytes, total_bytes } => Event::TransferPreparingProgress { transfer_id, scanned_bytes, total_bytes },
        EngineEvent::TransferOffered { transfer_id, file_count, total_bytes } => Event::TransferOffered { transfer_id, file_count, total_bytes },
        EngineEvent::TransferProgress { transfer_id, verified_bytes, total_bytes } => Event::TransferProgress { transfer_id, verified_bytes, total_bytes },
        EngineEvent::TransferReconnecting { transfer_id, attempt, backoff_ms } => Event::TransferReconnecting { transfer_id, attempt, backoff_ms },
        EngineEvent::TransferResumed { transfer_id } => Event::TransferResumed { transfer_id },
        EngineEvent::TransferPaused { transfer_id, reason } => Event::TransferPaused { transfer_id, reason: format!("{reason:?}").to_lowercase() },
        EngineEvent::TransferCompleted { transfer_id } => Event::TransferCompleted { transfer_id },
        EngineEvent::TransferCancelled { transfer_id } => Event::TransferCancelled { transfer_id },
        EngineEvent::TransferFailed { transfer_id, error_code, retryable, part_kept } => Event::TransferFailed { transfer_id, error_code, retryable, part_kept },
        EngineEvent::IncomingConnection { device_fingerprint } => Event::IncomingConnection { device_fingerprint },
    }
}

fn new_transfer_id() -> String {
    format!("t-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

async fn publish_start_error_for_id(
    events: &EventBroker,
    transfer_id: String,
    error: privet_core::CoreError,
) {
    events.publish(Event::TransferFailed {
        transfer_id,
        error_code: error.error_code().into(),
        retryable: false,
        part_kept: false,
    }).await;
}

fn peer_dto(peer: privet_discovery::peer::PeerRecord) -> PeerDto {
    PeerDto {
        device_fingerprint: peer.device_fingerprint,
        device_name: peer.device_name,
        state: format!("{:?}", peer.state).to_lowercase(),
        last_beacon_ms: peer.last_beacon_ms,
        candidates: peer.candidates.into_iter().map(|candidate| CandidateAddressDto {
            ip: candidate.ip.to_string(),
            quic_port: candidate.quic_port,
            tcp_port: candidate.tcp_port,
            last_seen_ms: candidate.last_seen_ms,
        }).collect(),
    }
}

fn trusted_dto(peer: privet_storage::trust::TrustRecord) -> TrustedPeerDto {
    TrustedPeerDto {
        device_fingerprint: peer.device_fingerprint,
        device_name: peer.peer_device_name,
        trust_state: peer.trust_state,
        spki_hex: hex::encode(peer.peer_spki),
        first_paired_ts: peer.first_paired_ts,
        last_seen_ts: peer.last_seen_ts,
        revoked_ts: peer.revoked_ts,
        revocation_reason: peer.revocation_reason,
    }
}

fn history_dto(row: privet_storage::history::HistoryRow) -> HistoryEntryDto {
    HistoryEntryDto {
        transfer_id: row.transfer_id,
        direction: row.direction,
        peer_device_fingerprint: row.peer_device_fingerprint,
        peer_name: row.peer_name,
        root_name: row.root_name,
        file_count: row.file_count,
        total_bytes: row.total_bytes,
        status: row.status,
        started_ts: row.started_ts,
        finished_ts: row.finished_ts,
    }
}

fn history_detail_dto(row: privet_storage::history::HistoryDetailRow) -> HistoryDetailDto {
    let files = row
        .files
        .iter()
        .map(|f| {
            let absolute_path = if row.direction == "send" {
                f.source_path.clone()
            } else {
                let mut path = std::path::PathBuf::new();
                if let Some(dir) = &row.save_dir {
                    path.push(dir);
                }
                if let Some(root) = &row.root_name {
                    path.push(root);
                }
                path.push(&f.relative_path);
                Some(path.to_string_lossy().into_owned())
            };
            HistoryFileDto {
                relative_path: f.relative_path.clone(),
                absolute_path,
                size: f.size,
                status: f.status.clone(),
            }
        })
        .collect();
    HistoryDetailDto {
        transfer_id: row.transfer_id,
        direction: row.direction,
        peer_device_fingerprint: row.peer_device_fingerprint,
        peer_name: row.peer_name,
        root_name: row.root_name,
        status: row.status,
        started_ts: row.started_ts,
        finished_ts: row.finished_ts,
        files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use privet_storage::history::{HistoryDetailRow, HistoryFileRow};

    #[test]
    fn history_detail_dto_maps_send_source_path() {
        let row = HistoryDetailRow {
            transfer_id: "t1".into(),
            direction: "send".into(),
            peer_device_fingerprint: None,
            peer_name: Some("peer".into()),
            root_name: Some("docs".into()),
            status: "completed".into(),
            started_ts: 1,
            finished_ts: Some(2),
            save_dir: None,
            files: vec![HistoryFileRow {
                relative_path: "a.txt".into(),
                source_path: Some("/home/u/docs/a.txt".into()),
                size: 10,
                status: "completed".into(),
            }],
        };
        let dto = history_detail_dto(row);
        assert_eq!(dto.files[0].absolute_path.as_deref(), Some("/home/u/docs/a.txt"));
    }

    #[test]
    fn history_detail_dto_maps_receive_landed_path() {
        let row = HistoryDetailRow {
            transfer_id: "t2".into(),
            direction: "receive".into(),
            peer_device_fingerprint: None,
            peer_name: None,
            root_name: Some("docs".into()),
            status: "completed".into(),
            started_ts: 1,
            finished_ts: Some(2),
            save_dir: Some("/tmp/s".into()),
            files: vec![HistoryFileRow {
                relative_path: "a.txt".into(),
                source_path: None,
                size: 10,
                status: "completed".into(),
            }],
        };
        let dto = history_detail_dto(row);
        let expected = std::path::PathBuf::from("/tmp/s").join("docs").join("a.txt");
        assert_eq!(dto.files[0].absolute_path.as_deref(), Some(expected.to_string_lossy().as_ref()));
    }

    #[test]
    fn history_detail_dto_receive_without_root_uses_save_dir_only() {
        let row = HistoryDetailRow {
            transfer_id: "t3".into(),
            direction: "receive".into(),
            peer_device_fingerprint: None,
            peer_name: None,
            root_name: None,
            status: "completed".into(),
            started_ts: 1,
            finished_ts: None,
            save_dir: Some("/tmp/s".into()),
            files: vec![HistoryFileRow {
                relative_path: "a.txt".into(),
                source_path: None,
                size: 10,
                status: "completed".into(),
            }],
        };
        let dto = history_detail_dto(row);
        let expected = std::path::PathBuf::from("/tmp/s").join("a.txt");
        assert_eq!(dto.files[0].absolute_path.as_deref(), Some(expected.to_string_lossy().as_ref()));
    }
}
