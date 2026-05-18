use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int};

use crate::runtime;

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Initialize the privet engine with a JSON config string.
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_init(config_json: *const c_char) -> c_int {
    tracing::debug!("privet_init called");
    privet_core::init();

    let config_str = unsafe {
        if config_json.is_null() {
            tracing::error!("privet_init: config_json is null");
            return -1;
        }
        CStr::from_ptr(config_json)
    };

    let config: privet_core::PrivetConfig = match serde_json::from_str(
        config_str.to_str().unwrap_or(""),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("privet_init: config parse error: {e}");
            return -1;
        }
    };

    let rt = runtime::get_runtime();
    let engine = match rt.block_on(privet_core::PrivetEngine::new(config)) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("privet_init: engine creation failed: {e}");
            return -1;
        }
    };

    {
        let mut guard = runtime::get_engine().lock().unwrap();
        *guard = Some(engine);
    }

    tracing::info!("privet_init: engine created successfully");
    runtime::start_event_loop();
    0
}

/// Initialize the privet engine with defaults (only requires device_name).
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_init_with_defaults(device_name: *const c_char) -> c_int {
    tracing::debug!("privet_init_with_defaults called");
    privet_core::init();

    let name = unsafe {
        if device_name.is_null() {
            tracing::error!("privet_init_with_defaults: device_name is null");
            return -1;
        }
        match CStr::from_ptr(device_name).to_str() {
            Ok(s) => s.to_owned(),
            Err(e) => {
                tracing::error!("privet_init_with_defaults: device_name invalid: {e}");
                return -1;
            }
        }
    };

    let config = privet_core::PrivetConfig::default_with_name(name);

    let rt = runtime::get_runtime();
    let engine = match rt.block_on(privet_core::PrivetEngine::new(config)) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("privet_init_with_defaults: engine creation failed: {e}");
            return -1;
        }
    };

    {
        let mut guard = runtime::get_engine().lock().unwrap();
        *guard = Some(engine);
    }

    tracing::info!("privet_init_with_defaults: engine created successfully");
    runtime::start_event_loop();
    0
}

/// Start the engine (begin listening for connections + discovery).
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_start() -> c_int {
    tracing::debug!("privet_start called");
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => {
            tracing::error!("privet_start: engine not initialized");
            return -1;
        }
    };

    match rt.block_on(engine.start()) {
        Ok(()) => {
            tracing::info!("privet_start: engine started successfully");
            0
        }
        Err(e) => {
            tracing::error!("privet_start: engine start failed: {e}");
            -1
        }
    }
}

/// Stop the engine.
#[unsafe(no_mangle)]
pub extern "C" fn privet_stop() {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    if let Some(engine) = guard.as_ref() {
        let _ = rt.block_on(engine.shutdown());
    }
}

// ---------------------------------------------------------------------------
// Event polling (instead of callback — NativeCallable.listener can't be
// safely called from Rust/Tokio threads on all platforms).
// ---------------------------------------------------------------------------

/// Poll the next pending event. Returns a JSON CString (caller must free
/// with `privet_free_string`) or null if no event is pending.
/// Call this periodically from a Dart timer (e.g. every 50 ms).
#[unsafe(no_mangle)]
pub extern "C" fn privet_poll_event() -> *mut c_char {
    crate::callback::poll_event()
}

// ---------------------------------------------------------------------------
// Sending files
// ---------------------------------------------------------------------------

/// Send files to a peer by address (IP:port string, e.g. "192.168.1.5:53530").
/// `paths_json` is a JSON array of file path strings.
/// Returns 0 on success, -1 on failure.
/// On success, writes the session ID (hyphenated UUID) into `out_session_id`
/// (must be at least 37 bytes including NUL terminator).
#[unsafe(no_mangle)]
pub extern "C" fn privet_send_files_to_addr(
    addr: *const c_char,
    paths_json: *const c_char,
    out_session_id: *mut c_char,
) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let addr_str = unsafe {
        if addr.is_null() {
            return -1;
        }
        match CStr::from_ptr(addr).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    let addr: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return -1,
    };

    let paths_str = unsafe {
        if paths_json.is_null() {
            return -1;
        }
        match CStr::from_ptr(paths_json).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    let paths: Vec<std::path::PathBuf> = match serde_json::from_str(paths_str) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    match rt.block_on(engine.send_files_to_addr(addr, paths)) {
        Ok(session_id) => {
            if !out_session_id.is_null() {
                let id_str = session_id.to_string();
                let bytes = id_str.as_bytes();
                let len = bytes.len().min(35);
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_session_id as *mut u8, len);
                    *out_session_id.add(len) = 0; // NUL terminate
                }
            }
            0
        }
        Err(_) => -1,
    }
}

/// Send files to a peer by display name.
/// `paths_json` is a JSON array of file path strings.
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_send_files_to_name(
    name: *const c_char,
    paths_json: *const c_char,
    out_session_id: *mut c_char,
) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let name_str = unsafe {
        if name.is_null() {
            return -1;
        }
        match CStr::from_ptr(name).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let paths_str = unsafe {
        if paths_json.is_null() {
            return -1;
        }
        match CStr::from_ptr(paths_json).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    let paths: Vec<std::path::PathBuf> = match serde_json::from_str(paths_str) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    match rt.block_on(engine.send_files_to_name(name_str, paths)) {
        Ok(session_id) => {
            if !out_session_id.is_null() {
                let id_str = session_id.to_string();
                let bytes = id_str.as_bytes();
                let len = bytes.len().min(35);
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_session_id as *mut u8, len);
                    *out_session_id.add(len) = 0;
                }
            }
            0
        }
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// Transfer control
// ---------------------------------------------------------------------------

/// Accept an incoming transfer.
/// `session_id_str` is a hyphenated UUID string.
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_accept_transfer(session_id_str: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let sid = match parse_session_id(session_id_str) {
        Some(s) => s,
        None => return -1,
    };

    match rt.block_on(engine.accept_transfer(&sid)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Reject an incoming transfer.
#[unsafe(no_mangle)]
pub extern "C" fn privet_reject_transfer(session_id_str: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let sid = match parse_session_id(session_id_str) {
        Some(s) => s,
        None => return -1,
    };

    match rt.block_on(engine.reject_transfer(&sid)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Cancel an active transfer.
#[unsafe(no_mangle)]
pub extern "C" fn privet_cancel_transfer(session_id_str: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let sid = match parse_session_id(session_id_str) {
        Some(s) => s,
        None => return -1,
    };

    match rt.block_on(engine.cancel_transfer(&sid)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// Trust / pairing
// ---------------------------------------------------------------------------

/// Trust a peer by fingerprint string.
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_trust_peer(fingerprint: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let fp = unsafe {
        if fingerprint.is_null() {
            return -1;
        }
        match CStr::from_ptr(fingerprint).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    match rt.block_on(engine.trust_peer(fp)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Remove trust from a peer by fingerprint string.
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_untrust_peer(fingerprint: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let fp = unsafe {
        if fingerprint.is_null() {
            return -1;
        }
        match CStr::from_ptr(fingerprint).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    match rt.block_on(engine.untrust_peer(fp)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Trust a peer and auto-accept all future transfers from them.
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_trust_and_accept_peer(fingerprint: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let fp = unsafe {
        if fingerprint.is_null() {
            return -1;
        }
        match CStr::from_ptr(fingerprint).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    match rt.block_on(engine.trust_and_accept_peer(fp)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Reject a pending pairing request from a peer.
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_reject_pairing(fingerprint: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let fp = unsafe {
        if fingerprint.is_null() {
            return -1;
        }
        match CStr::from_ptr(fingerprint).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    match rt.block_on(engine.reject_pairing(fp)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Remove a peer from the auto-accept list (keeps trust).
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_unaccept_peer(fingerprint: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let fp = unsafe {
        if fingerprint.is_null() {
            return -1;
        }
        match CStr::from_ptr(fingerprint).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    match rt.block_on(engine.unaccept_peer(fp)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Get the list of discovered peers as a JSON string.
/// Caller must free the returned string with `privet_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn privet_get_peers() -> *mut c_char {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let peers = rt.block_on(engine.discovered_peers());
    let json = match serde_json::to_string(&peers) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(json).unwrap_or_default().into_raw()
}

/// Get the list of trusted fingerprints as a JSON string.
/// Caller must free the returned string with `privet_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn privet_get_trusted_fingerprints() -> *mut c_char {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let fps = rt.block_on(engine.trusted_fingerprints());
    let json = match serde_json::to_string(&fps) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(json).unwrap_or_default().into_raw()
}

/// Get the list of accepted (auto-accept) fingerprints as a JSON string.
/// Caller must free the returned string with `privet_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn privet_get_accepted_fingerprints() -> *mut c_char {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let fps = rt.block_on(engine.accepted_fingerprints());
    let json = match serde_json::to_string(&fps) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(json).unwrap_or_default().into_raw()
}

/// Get the list of active sessions as a JSON string.
/// Caller must free the returned string with `privet_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn privet_get_sessions() -> *mut c_char {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let sessions = rt.block_on(engine.list_sessions());
    let json = match serde_json::to_string(&sessions) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(json).unwrap_or_default().into_raw()
}

/// Get the device identity as a JSON string (fingerprint, device_name).
/// Caller must free the returned string with `privet_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn privet_get_identity() -> *mut c_char {
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let identity = engine.identity();
    let json = match serde_json::to_string(&serde_json::json!({
        "fingerprint": identity.fingerprint,
        "device_name": identity.device_name,
    })) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(json).unwrap_or_default().into_raw()
}

// ---------------------------------------------------------------------------
// Known devices / network awareness
// ---------------------------------------------------------------------------

/// Get the list of current networks as a JSON string.
/// Each network has "subnet", "interface_name", "local_ips" fields.
/// Caller must free the returned string with `privet_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn privet_get_current_networks() -> *mut c_char {
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let networks = engine.current_networks();
    let json = match serde_json::to_string(&networks) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(json).unwrap_or_default().into_raw()
}

/// Probe known devices on the current network(s).
/// Returns a JSON string of probed PeerInfo list.
/// Caller must free the returned string with `privet_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn privet_probe_known_devices() -> *mut c_char {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let peers = rt.block_on(engine.probe_known_devices());
    let json = match serde_json::to_string(&peers) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(json).unwrap_or_default().into_raw()
}

/// Get the list of known devices as a JSON string.
/// Caller must free the returned string with `privet_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn privet_get_known_devices() -> *mut c_char {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let devices = rt.block_on(engine.known_devices());
    let json = match serde_json::to_string(&devices) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };

    CString::new(json).unwrap_or_default().into_raw()
}

/// Add a known device IP mapping.
/// `args_json` is a JSON object with keys:
///   "fingerprint", "peer_id", "device_name", "subnet", "addr" (IP:port), "label" (optional)
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_add_known_device_ip(args_json: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let args_str = unsafe {
        if args_json.is_null() { return -1; }
        match CStr::from_ptr(args_json).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let args: serde_json::Value = match serde_json::from_str(args_str) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let fingerprint = match args["fingerprint"].as_str() {
        Some(s) => s.to_owned(),
        None => return -1,
    };
    let peer_id_str = args["peer_id"].as_str().unwrap_or("");
    let peer_id = match uuid::Uuid::parse_str(peer_id_str) {
        Ok(u) => privet_core::PeerId(u),
        Err(_) => privet_core::PeerId(uuid::Uuid::nil()),
    };
    let device_name = args["device_name"].as_str().unwrap_or("").to_owned();
    let subnet = match args["subnet"].as_str() {
        Some(s) => s.to_owned(),
        None => return -1,
    };
    let addr: SocketAddr = match args["addr"].as_str().and_then(|s| s.parse().ok()) {
        Some(a) => a,
        None => return -1,
    };
    let label = args["label"].as_str().map(|s| s.to_owned());

    match rt.block_on(engine.add_known_device_ip(fingerprint, peer_id, device_name, subnet, addr, label)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Remove a known device network IP mapping.
/// `args_json` is a JSON object with keys: "fingerprint", "subnet", "addr" (optional)
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_remove_known_device_ip(args_json: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let args_str = unsafe {
        if args_json.is_null() { return -1; }
        match CStr::from_ptr(args_json).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let args: serde_json::Value = match serde_json::from_str(args_str) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let fingerprint = match args["fingerprint"].as_str() {
        Some(s) => s,
        None => return -1,
    };
    let subnet = match args["subnet"].as_str() {
        Some(s) => s,
        None => return -1,
    };
    let addr = args["addr"].as_str().unwrap_or("");

    match rt.block_on(engine.remove_known_device_ip(fingerprint, subnet, addr)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Set a network label for a known device.
/// `args_json` is a JSON object with keys: "fingerprint", "subnet", "label"
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_set_network_label(args_json: *const c_char) -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    let args_str = unsafe {
        if args_json.is_null() { return -1; }
        match CStr::from_ptr(args_json).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let args: serde_json::Value = match serde_json::from_str(args_str) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let fingerprint = match args["fingerprint"].as_str() {
        Some(s) => s,
        None => return -1,
    };
    let subnet = match args["subnet"].as_str() {
        Some(s) => s,
        None => return -1,
    };
    let label = match args["label"].as_str() {
        Some(s) => s.to_owned(),
        None => return -1,
    };

    match rt.block_on(engine.set_network_label(fingerprint, subnet, label)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// Free a string previously returned by privet (e.g. from `privet_get_peers`).
/// Also safe to call on `CEvent.extra_json` pointers.
#[unsafe(no_mangle)]
pub extern "C" fn privet_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a C string as a SessionId UUID.
fn parse_session_id(s: *const c_char) -> Option<privet_core::SessionId> {
    let cstr = unsafe {
        if s.is_null() {
            return None;
        }
        CStr::from_ptr(s)
    };
    let uuid = uuid::Uuid::parse_str(cstr.to_str().ok()?).ok()?;
    Some(privet_core::SessionId(uuid))
}
