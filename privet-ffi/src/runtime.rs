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
