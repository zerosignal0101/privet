use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const IPC_PROTOCOL_VERSION: u32 = 1;
pub const MAX_IPC_MESSAGE_BYTES: usize = 1024 * 1024;
pub type RequestId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientMessage {
    pub protocol_version: u32,
    pub request_id: RequestId,
    pub request: Request,
}

impl ClientMessage {
    pub fn new(request: Request) -> Self {
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: uuid::Uuid::new_v4().to_string(),
            request,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Response(ResponseMessage),
    Event(EventMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResponseMessage {
    pub request_id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<ResponsePayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

impl ResponseMessage {
    pub fn success(request_id: RequestId, payload: ResponsePayload) -> Self {
        Self { request_id, payload: Some(payload), error: None }
    }

    pub fn error(request_id: RequestId, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            request_id,
            payload: None,
            error: Some(ErrorPayload { code: code.into(), message: message.into() }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EventMessage {
    pub sequence: u64,
    pub event: Event,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    Ping,
    GetStatus,
    GetIdentity,
    ListPeers,
    RefreshPeers,
    ListTrusted,
    GeneratePairingCode,
    Pair { peer: PairingPeer, code: String },
    RevokePeer { device_fingerprint: String, reason: String },
    ForgetPeer { device_fingerprint: String },
    Send { paths: Vec<PathBuf>, device_fingerprint: String, as_name: Option<String> },
    ResumeTransfer { transfer_id: String },
    ResendTransfer { transfer_id: String },
    AcceptTransfer { transfer_id: String, accept: bool },
    CancelTransfer { transfer_id: String },
    PauseTransfer { transfer_id: String },
    ContinueTransfer { transfer_id: String },
    ListHistory { peer: Option<String>, limit: u32 },
    GetHistoryDetail { transfer_id: String },
    DeleteHistory { transfer_id: String },
    GetRuntimeConfig,
    SetRuntimeConfig(RuntimeConfigPatch),
    SubscribeEvents { after_sequence: Option<u64> },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PairingPeer {
    Discovered { device_fingerprint: String },
    Endpoint { ip: String, quic_port: u16, tcp_port: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfigPatch {
    pub accept_all_trusted: Option<bool>,
    pub collision_policy: Option<CollisionPolicyDto>,
    pub save_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollisionPolicyDto { Rename, Skip, Overwrite }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ResponsePayload {
    Pong { protocol_version: u32 },
    Ack,
    Status(DaemonStatus),
    Identity(IdentityDto),
    Peers(Vec<PeerDto>),
    Trusted(Vec<TrustedPeerDto>),
    PairingCode { code: String, validity_secs: u64 },
    PairingResult { paired: bool, device_fingerprint: Option<String> },
    TransferQueued { transfer_id: String },
    Transfer(TransferSummaryDto),
    History(Vec<HistoryEntryDto>),
    HistoryDetail(HistoryDetailDto),
    RuntimeConfig(RuntimeConfigDto),
    EventReplay { events: Vec<EventMessage>, oldest_available: Option<u64>, latest: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DaemonStatus {
    pub protocol_version: u32,
    pub daemon_version: String,
    pub session_id: String,
    pub device_fingerprint: String,
    pub quic_addr: String,
    pub tcp_addr: String,
    pub active_transfers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityDto { pub device_fingerprint: String, pub device_name: String }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidateAddressDto {
    pub ip: String,
    pub quic_port: u16,
    pub tcp_port: u16,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerDto {
    pub device_fingerprint: String,
    pub device_name: String,
    pub state: String,
    pub last_beacon_ms: u64,
    pub candidates: Vec<CandidateAddressDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustedPeerDto {
    pub device_fingerprint: String,
    pub device_name: String,
    pub trust_state: String,
    pub spki_hex: String,
    pub first_paired_ts: i64,
    pub last_seen_ts: i64,
    pub revoked_ts: Option<i64>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransferSummaryDto { pub transfer_id: String, pub file_count: u64, pub total_bytes: u64 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryEntryDto {
    pub transfer_id: String,
    pub direction: String,
    pub peer_device_fingerprint: Option<String>,
    pub peer_name: Option<String>,
    pub root_name: Option<String>,
    pub file_count: u64,
    pub total_bytes: u64,
    pub status: String,
    pub started_ts: i64,
    pub finished_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryFileDto {
    pub relative_path: String,
    pub absolute_path: Option<String>,
    pub size: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryDetailDto {
    pub transfer_id: String,
    pub direction: String,
    pub peer_device_fingerprint: Option<String>,
    pub peer_name: Option<String>,
    pub root_name: Option<String>,
    pub status: String,
    pub started_ts: i64,
    pub finished_ts: Option<i64>,
    pub files: Vec<HistoryFileDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeConfigDto {
    pub accept_all_trusted: bool,
    pub collision_policy: CollisionPolicyDto,
    pub save_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "name", content = "data", rename_all = "snake_case")]
pub enum Event {
    DeviceDiscovered { device_fingerprint: String, device_name: String },
    DeviceLost { device_fingerprint: String },
    PairingRequested { device_fingerprint: String },
    PairingResult { device_fingerprint: String, success: bool, error: Option<String> },
    TransferPreparing { transfer_id: String },
    TransferPreparingProgress { transfer_id: String, scanned_bytes: u64, total_bytes: u64 },
    TransferOffered { transfer_id: String, file_count: u64, total_bytes: u64 },
    TransferProgress { transfer_id: String, verified_bytes: u64, total_bytes: u64 },
    TransferReconnecting { transfer_id: String, attempt: u32, backoff_ms: u64 },
    TransferResumed { transfer_id: String },
    TransferPaused { transfer_id: String, reason: String },
    TransferCompleted { transfer_id: String },
    TransferCancelled { transfer_id: String },
    TransferFailed { transfer_id: String, error_code: String, retryable: bool, part_kept: bool },
    IncomingConnection { device_fingerprint: String },
    RuntimeConfigChanged(RuntimeConfigDto),
    DaemonStopping,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_is_stable() {
        let message = ClientMessage {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "req-1".into(),
            request: Request::Pair {
                peer: PairingPeer::Endpoint { ip: "127.0.0.1".into(), quic_port: 47808, tcp_port: 47810 },
                code: "123456".into(),
            },
        };
        let encoded = serde_json::to_vec(&message).unwrap();
        let decoded: ClientMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn get_history_detail_round_trip_is_stable() {
        let request = Request::GetHistoryDetail { transfer_id: "t-1".into() };
        let message = ClientMessage { protocol_version: IPC_PROTOCOL_VERSION, request_id: "req-1".into(), request };
        let encoded = serde_json::to_vec(&message).unwrap();
        let decoded: ClientMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn history_detail_dto_round_trip_is_stable() {
        let dto = HistoryDetailDto {
            transfer_id: "t-1".into(),
            direction: "receive".into(),
            peer_device_fingerprint: None,
            peer_name: Some("p".into()),
            root_name: Some("docs".into()),
            status: "completed".into(),
            started_ts: 1,
            finished_ts: Some(2),
            files: vec![HistoryFileDto {
                relative_path: "a.txt".into(),
                absolute_path: Some("C:\\received\\docs\\a.txt".into()),
                size: 10,
                status: "completed".into(),
            }],
        };
        let payload = ResponsePayload::HistoryDetail(dto);
        let encoded = serde_json::to_vec(&payload).unwrap();
        let decoded: ResponsePayload = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }
}
