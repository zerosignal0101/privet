use std::sync::OnceLock;

use tokio::runtime::Runtime;

use privet_core::PrivetEngine;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static ENGINE: OnceLock<std::sync::Mutex<Option<std::sync::Arc<PrivetEngine>>>> = OnceLock::new();

pub fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Runtime::new().expect("failed to create tokio runtime")
    })
}

/// Get an engine reference by cloning its Arc.
/// Returns None if the engine hasn't been initialized yet.
pub fn get_engine() -> Option<std::sync::Arc<PrivetEngine>> {
    ENGINE
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap()
        .clone()
}

/// Replace the engine with a new one (for restarts).
pub fn set_engine(engine: PrivetEngine) {
    let mut guard = ENGINE
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap();
    *guard = Some(std::sync::Arc::new(engine));
}

/// Start the event dispatch loop: subscribes to PrivetEngine events and
/// forwards each one to the C callback via `callback::emit_event`.
/// Must be called after engine is created and callback is registered.
pub fn start_event_loop() {
    let rt = get_runtime();
    let engine = get_engine().expect("start_event_loop called before engine init");
    let rx = rt.block_on(engine.subscribe_events());

    // Spawn a task that continuously reads events and dispatches them.
    rt.spawn(async move {
        use tokio::sync::mpsc;
        let mut rx: mpsc::UnboundedReceiver<privet_core::PrivetEvent> = rx;
        while let Some(event) = rx.recv().await {
            crate::callback::emit_event(event);
        }
    });
}
