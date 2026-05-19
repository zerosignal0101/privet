use std::ffi::CString;
use std::os::raw::c_int;

/// C-compatible event structure for passing events to Dart/Flutter.
///
/// Flat fields cover the common case (progress, complete, failed).
/// Complex payloads (peer info, file manifest) are serialized as JSON
/// in `extra_json` — the caller must free it with `privet_free_string`.
#[repr(C)]
pub struct CEvent {
    pub event_type: c_int,
    /// UUID string (37 bytes = 36 UUID chars + NUL terminator), or all zeros if N/A.
    pub session_id: [u8; 37],
    /// UUID string (37 bytes = 36 UUID chars + NUL terminator), or all zeros if N/A.
    pub peer_id: [u8; 37],
    /// 0.0–100.0 for progress events, 0.0 otherwise.
    pub progress_percent: f64,
    pub speed_bps: f64,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    /// 0 = Sending, 1 = Receiving, 255 = N/A
    pub direction: u8,
    /// JSON-encoded extra payload (must be freed with `privet_free_string`).
    /// Null if no extra data.
    pub extra_json: *mut std::os::raw::c_char,
}

// Event type constants
pub const EVENT_PEER_DISCOVERED: c_int = 0;
pub const EVENT_PEER_LOST: c_int = 1;
pub const EVENT_PAIR_REQUEST: c_int = 2;
pub const EVENT_TRANSFER_PROGRESS: c_int = 3;
pub const EVENT_TRANSFER_COMPLETE: c_int = 4;
pub const EVENT_TRANSFER_FAILED: c_int = 5;
pub const EVENT_INCOMING_TRANSFER: c_int = 6;
pub const EVENT_NETWORK_CHANGED: c_int = 7;
pub const EVENT_AWAITING_ACCEPT: c_int = 8;
pub const EVENT_AWAITING_PAIRING: c_int = 9;
pub const EVENT_KNOWN_DEVICE_PROBED: c_int = 10;

/// Encode a UUID as a 37-byte fixed buffer (36 UUID chars + NUL terminator).
pub fn uuid_to_bytes(id: &uuid::Uuid) -> [u8; 37] {
    let mut buf = [0u8; 37];
    let s = id.hyphenated().to_string();
    let bytes = s.as_bytes();
    // UUID string is always 36 chars (8-4-4-4-12), copy all of them
    let len = bytes.len().min(36);
    buf[..len].copy_from_slice(&bytes[..len]);
    // buf[len] is already 0 (NUL terminator)
    buf
}

/// Encode a Rust string as a heap-allocated C string (caller frees with `privet_free_string`).
/// Returns null if serialization fails.
pub fn json_to_cstring<T: serde::Serialize>(val: &T) -> *mut std::os::raw::c_char {
    match serde_json::to_string(val) {
        Ok(json) => CString::new(json)
            .map(|cs| cs.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

impl CEvent {
    /// Convert a PrivetEvent into a CEvent suitable for FFI.
    pub fn from_privet_event(event: &privet_core::PrivetEvent) -> Self {
        let mut ce = CEvent {
            event_type: 0,
            session_id: [0u8; 37],
            peer_id: [0u8; 37],
            progress_percent: 0.0,
            speed_bps: 0.0,
            bytes_transferred: 0,
            total_bytes: 0,
            direction: 255, // N/A by default
            extra_json: std::ptr::null_mut(),
        };

        match event {
            privet_core::PrivetEvent::PeerDiscovered(peer) => {
                ce.event_type = EVENT_PEER_DISCOVERED;
                ce.peer_id = uuid_to_bytes(peer.id.as_uuid());
                ce.extra_json = json_to_cstring(peer);
            }
            privet_core::PrivetEvent::PeerLost(id) => {
                ce.event_type = EVENT_PEER_LOST;
                ce.peer_id = uuid_to_bytes(id.as_uuid());
            }
            privet_core::PrivetEvent::PairRequest { peer, code } => {
                ce.event_type = EVENT_PAIR_REQUEST;
                ce.peer_id = uuid_to_bytes(peer.id.as_uuid());
                ce.extra_json = json_to_cstring(&serde_json::json!({
                    "peer": peer,
                    "code": code,
                }));
            }
            privet_core::PrivetEvent::TransferProgress { session_id, progress, direction } => {
                ce.event_type = EVENT_TRANSFER_PROGRESS;
                ce.session_id = uuid_to_bytes(&session_id.0);
                ce.progress_percent = progress.percent();
                ce.speed_bps = progress.current_speed_bps;
                ce.bytes_transferred = progress.bytes_transferred;
                ce.total_bytes = progress.total_bytes;
                ce.direction = match direction {
                    privet_core::session::TransferDirection::Sending => 0,
                    privet_core::session::TransferDirection::Receiving => 1,
                };
            }
            privet_core::PrivetEvent::TransferComplete { session_id, direction } => {
                ce.event_type = EVENT_TRANSFER_COMPLETE;
                ce.session_id = uuid_to_bytes(&session_id.0);
                ce.direction = match direction {
                    privet_core::session::TransferDirection::Sending => 0,
                    privet_core::session::TransferDirection::Receiving => 1,
                };
            }
            privet_core::PrivetEvent::TransferFailed { session_id, error, direction } => {
                ce.event_type = EVENT_TRANSFER_FAILED;
                ce.session_id = uuid_to_bytes(&session_id.0);
                ce.extra_json = json_to_cstring(&serde_json::json!({ "error": error }));
                ce.direction = match direction {
                    privet_core::session::TransferDirection::Sending => 0,
                    privet_core::session::TransferDirection::Receiving => 1,
                };
            }
            privet_core::PrivetEvent::IncomingTransfer { session_id, peer, files } => {
                ce.event_type = EVENT_INCOMING_TRANSFER;
                ce.session_id = uuid_to_bytes(&session_id.0);
                ce.peer_id = uuid_to_bytes(peer.id.as_uuid());
                ce.extra_json = json_to_cstring(&serde_json::json!({
                    "peer": peer,
                    "files": files,
                }));
            }
            privet_core::PrivetEvent::NetworkChanged => {
                ce.event_type = EVENT_NETWORK_CHANGED;
            }
            privet_core::PrivetEvent::AwaitingAccept { session_id, peer, files } => {
                ce.event_type = EVENT_AWAITING_ACCEPT;
                ce.session_id = uuid_to_bytes(&session_id.0);
                ce.peer_id = uuid_to_bytes(peer.id.as_uuid());
                ce.extra_json = json_to_cstring(&serde_json::json!({
                    "peer": peer,
                    "files": files,
                }));
            }
            privet_core::PrivetEvent::AwaitingPairing { session_id, peer, code } => {
                ce.event_type = EVENT_AWAITING_PAIRING;
                ce.session_id = uuid_to_bytes(&session_id.0);
                ce.peer_id = uuid_to_bytes(peer.id.as_uuid());
                ce.extra_json = json_to_cstring(&serde_json::json!({
                    "peer": peer,
                    "code": code,
                }));
            }
            privet_core::PrivetEvent::KnownDeviceProbed { peer } => {
                ce.event_type = EVENT_KNOWN_DEVICE_PROBED;
                ce.peer_id = uuid_to_bytes(peer.id.as_uuid());
                ce.extra_json = json_to_cstring(peer);
            }
        }

        ce
    }
}
