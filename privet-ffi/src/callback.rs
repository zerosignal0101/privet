use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

/// Thread-safe event queue. The Rust event loop pushes JSON-serialized
/// events here; the Dart side polls them via `privet_poll_event`.
fn event_queue() -> &'static Mutex<VecDeque<String>> {
    static QUEUE: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Push a PrivetEvent into the poll queue as JSON.
pub fn emit_event(event: privet_core::PrivetEvent) {
    let event_type_name = match &event {
        privet_core::PrivetEvent::PeerDiscovered(_) => "PeerDiscovered",
        privet_core::PrivetEvent::PeerLost(_) => "PeerLost",
        privet_core::PrivetEvent::PairRequest { .. } => "PairRequest",
        privet_core::PrivetEvent::TransferProgress { .. } => "TransferProgress",
        privet_core::PrivetEvent::TransferComplete { .. } => "TransferComplete",
        privet_core::PrivetEvent::TransferFailed { .. } => "TransferFailed",
        privet_core::PrivetEvent::IncomingTransfer { session_id, .. } => {
            tracing::debug!("[callback] emit IncomingTransfer session={}", session_id.0);
            "IncomingTransfer"
        }
        privet_core::PrivetEvent::NetworkChanged => "NetworkChanged",
        privet_core::PrivetEvent::AwaitingAccept { session_id, .. } => {
            tracing::debug!("[callback] emit AwaitingAccept session={}", session_id.0);
            "AwaitingAccept"
        }
        privet_core::PrivetEvent::AwaitingPairing { .. } => "AwaitingPairing",
        privet_core::PrivetEvent::KnownDeviceProbed { .. } => "KnownDeviceProbed",
    };
    tracing::debug!("[callback] emit_event type={}", event_type_name);
    // Convert the event to a CEvent for consistent serialization, then push JSON to queue.
    let ce = super::types::CEvent::from_privet_event(&event);
    // The extra_json is already serialized. We push a JSON map containing
    // all flat fields plus the extra payload, so the Dart side can parse
    // it uniformly.
    let json = serde_json::json!({
        "event_type": ce.event_type,
        "session_id": std::str::from_utf8(&ce.session_id)
            .unwrap_or("")
            .trim_end_matches('\0'),
        "peer_id": std::str::from_utf8(&ce.peer_id)
            .unwrap_or("")
            .trim_end_matches('\0'),
        "progress_percent": ce.progress_percent,
        "speed_bps": ce.speed_bps,
        "bytes_transferred": ce.bytes_transferred,
        "total_bytes": ce.total_bytes,
        "direction": ce.direction,
        "extra_json": if ce.extra_json.is_null() {
            None
        } else {
            let s = unsafe { std::ffi::CStr::from_ptr(ce.extra_json) }
                .to_string_lossy()
                .into_owned();
            // Free the extra_json string since we've copied it.
            unsafe { let _ = std::ffi::CString::from_raw(ce.extra_json); }
            Some(s)
        },
    });
    let json_str = json.to_string();
    let mut q = event_queue().lock().unwrap();
    q.push_back(json_str);
}

/// Poll the next pending event. Returns a JSON CString (caller frees with
/// `privet_free_string`) or null if the queue is empty.
pub fn poll_event() -> *mut std::os::raw::c_char {
    let mut q = event_queue().lock().unwrap();
    match q.pop_front() {
        Some(json) => std::ffi::CString::new(json)
            .map(|cs| cs.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}
