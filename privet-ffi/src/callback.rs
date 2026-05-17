use std::sync::atomic::{AtomicPtr, Ordering};

use super::types::CEvent;

/// Stored callback function pointer. The AtomicPtr holds the address of a
/// function — we store the function pointer itself cast to a raw pointer.
static EVENT_CALLBACK: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

/// Register a C-compatible callback that will be invoked for each engine event.
pub fn register_callback(cb: unsafe extern "C" fn(CEvent)) {
    EVENT_CALLBACK.store(cb as *mut (), Ordering::SeqCst);
}

/// Convert a PrivetEvent to a CEvent and invoke the registered callback.
pub fn emit_event(event: privet_core::PrivetEvent) {
    let ptr = EVENT_CALLBACK.load(Ordering::SeqCst);
    if ptr.is_null() {
        return;
    }
    let cb: unsafe extern "C" fn(CEvent) = unsafe { std::mem::transmute(ptr) };
    let ce = CEvent::from_privet_event(&event);
    unsafe {
        cb(ce);
    }
}
