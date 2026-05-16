use std::os::raw::c_int;

/// C-compatible event structure for passing events to Dart.
#[repr(C)]
pub struct CEvent {
    pub event_type: c_int,
    pub session_id: [u8; 36],
    pub peer_id: [u8; 36],
    pub progress_percent: f64,
    pub speed_bps: f64,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
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
