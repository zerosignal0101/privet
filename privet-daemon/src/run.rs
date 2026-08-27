//! Shared daemon body used by both the `privetd` binary (main.rs) and the
//! embedded cdylib (lib.rs). The embedded path cannot rely on a process signal
//! to stop, so shutdown is also signalled through a process-wide atomic flag
//! ([request_shutdown]).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use privet_core::ops::ServeOptions;
use privet_core::{AcceptPolicy, Engine, OfferResolver};
use privet_ipc::LocalListener;
use tokio::sync::Notify;

use crate::backend::{map_event, DaemonBackend};
use crate::config;
use crate::config::DaemonConfig;
use crate::events::EventBroker;
use crate::server;

/// Set by [request_shutdown] to stop an embedded daemon without a signal.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Asks a running daemon (in the same process) to shut down cleanly.
// (The binary compiles run.rs too but never calls the embed API, so silence
// its dead-code warning.)
#[allow(dead_code)]
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Clears the shutdown flag so the embedded daemon can be restarted.
#[allow(dead_code)]
pub fn reset_shutdown() {
    SHUTDOWN.store(false, Ordering::Relaxed);
}

/// Loads the config, binds the unix socket, starts the engine, and serves IPC
/// until a Shutdown arrives (from an IPC request, SIGINT, or [request_shutdown]).
pub async fn run(config_path: Option<PathBuf>, ipc_override: Option<PathBuf>) -> Result<(), String> {
    let mut config = DaemonConfig::load(config_path.as_deref())?;
    if let Some(endpoint) = ipc_override {
        config.ipc_endpoint = Some(endpoint);
    }
    std::fs::create_dir_all(&config.data_dir).map_err(|error| format!("create data dir: {error}"))?;
    std::fs::create_dir_all(&config.save_dir).map_err(|error| format!("create save dir: {error}"))?;

    let listener = LocalListener::bind(config.endpoint()).map_err(|error| error.to_string())?;
    let mut engine = Engine::new(config.engine_config());
    engine.start().await.map_err(|error| error.to_string())?;
    let resolver = Arc::new(OfferResolver::new());
    let serve = engine
        .serve(ServeOptions {
            save_dir: config.save_dir.clone(),
            accept_all_trusted: config.accept_all_trusted,
            on_collision: config::collision_from_dto(config.collision_policy),
            accept_policy: AcceptPolicy::Resolver(resolver.clone()),
        })
        .await
        .map_err(|error| error.to_string())?;
    engine.runtime().set_base_accept_policy(AcceptPolicy::Resolver(resolver));

    let mut engine_events = engine.subscribe();
    let engine = Arc::new(engine);
    let broker = Arc::new(EventBroker::new());
    let event_broker = broker.clone();
    tokio::spawn(async move {
        loop {
            match engine_events.recv().await {
                Ok(event) => {
                    event_broker.publish(map_event(event)).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "engine event subscriber lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let shutdown = Arc::new(Notify::new());
    let backend = Arc::new(DaemonBackend::new(engine.clone(), serve, broker, shutdown.clone()));

    // Binary: stop on SIGINT.
    let signal_backend = backend.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = signal_backend.handle(privet_ipc::Request::Shutdown).await;
            signal_backend.shutdown.notify_waiters();
        }
    });
    // Embedded: stop when the host process asks via [request_shutdown].
    let flag_backend = backend.clone();
    tokio::spawn(async move {
        while !SHUTDOWN.load(Ordering::Relaxed) {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        let _ = flag_backend.handle(privet_ipc::Request::Shutdown).await;
        flag_backend.shutdown.notify_waiters();
    });

    server::run(listener, backend).await.map_err(|error| error.to_string())
}

/// Runs the daemon to completion on the calling thread. Blocks until the daemon
/// shuts down; Ok(()) means a clean stop. Used by the embedded cdylib.
#[allow(dead_code)]
pub fn run_blocking(config_path: Option<PathBuf>, ipc_override: Option<PathBuf>) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("build tokio runtime: {error}"))?;
    runtime.block_on(run(config_path, ipc_override))
}
