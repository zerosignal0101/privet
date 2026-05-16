use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use crate::runtime;

/// Initialize the privet engine with a JSON config string.
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn privet_init(config_json: *const c_char) -> c_int {
    privet_core::init();

    let config_str = unsafe {
        if config_json.is_null() {
            return -1;
        }
        CStr::from_ptr(config_json)
    };

    let config: privet_core::PrivetConfig = match serde_json::from_str(config_str.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let rt = runtime::get_runtime();
    let engine = match rt.block_on(privet_core::PrivetEngine::new(config)) {
        Ok(e) => e,
        Err(_) => return -1,
    };

    let mut guard = runtime::get_engine().lock().unwrap();
    *guard = Some(engine);
    0
}

/// Start the engine (begin listening for connections).
#[unsafe(no_mangle)]
pub extern "C" fn privet_start() -> c_int {
    let rt = runtime::get_runtime();
    let guard = runtime::get_engine().lock().unwrap();
    let engine = match guard.as_ref() {
        Some(e) => e,
        None => return -1,
    };

    match rt.block_on(engine.start()) {
        Ok(()) => 0,
        Err(_) => -1,
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

/// Get the list of discovered peers as a JSON string.
/// Caller must free the returned string with privet_free_string.
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

/// Register a callback for events from the engine.
#[unsafe(no_mangle)]
pub extern "C" fn privet_register_event_callback(cb: extern "C" fn(crate::types::CEvent)) {
    crate::callback::register_callback(cb);
}

/// Free a string previously returned by privet.
#[unsafe(no_mangle)]
pub extern "C" fn privet_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}
