use std::sync::atomic::{AtomicPtr, Ordering};

use super::types::CEvent;

static EVENT_CALLBACK: AtomicPtr<extern "C" fn(CEvent)> = AtomicPtr::new(std::ptr::null_mut());

pub fn register_callback(cb: extern "C" fn(CEvent)) {
    EVENT_CALLBACK.store(cb as *mut extern "C" fn(CEvent), Ordering::SeqCst);
}

pub fn emit_event(event: CEvent) {
    let cb = EVENT_CALLBACK.load(Ordering::SeqCst);
    if !cb.is_null() {
        unsafe {
            (*cb)(event);
        }
    }
}
