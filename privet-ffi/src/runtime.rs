use std::sync::OnceLock;

use tokio::runtime::Runtime;

use privet_core::PrivetEngine;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static ENGINE: OnceLock<std::sync::Mutex<Option<PrivetEngine>>> = OnceLock::new();

pub fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Runtime::new().expect("failed to create tokio runtime")
    })
}

pub fn get_engine() -> &'static std::sync::Mutex<Option<PrivetEngine>> {
    ENGINE.get_or_init(|| std::sync::Mutex::new(None))
}

/// Start the event dispatch loop: subscribes to PrivetEngine events and
/// forwards each one to the C callback via `callback::emit_event`.
/// Must be called after engine is created and callback is registered.
pub fn start_event_loop() {
    let rt = get_runtime();
    let rx = {
        let guard = get_engine().lock().unwrap();
        match guard.as_ref() {
            Some(engine) => rt.block_on(engine.subscribe_events()),
            None => return,
        }
    };

    // Spawn a task that continuously reads events and dispatches them.
    rt.spawn(async move {
        use tokio::sync::mpsc;
        let mut rx: mpsc::UnboundedReceiver<privet_core::PrivetEvent> = rx;
        while let Some(event) = rx.recv().await {
            crate::callback::emit_event(event);
        }
    });
}
