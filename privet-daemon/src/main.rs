mod backend;
mod config;
mod events;
mod server;

use std::path::PathBuf;
use std::sync::Arc;

use backend::{map_event, DaemonBackend};
use config::DaemonConfig;
use events::EventBroker;
use privet_core::ops::ServeOptions;
use privet_core::{AcceptPolicy, Engine, OfferResolver};
use privet_ipc::LocalListener;
use tokio::sync::Notify;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    if let Err(error) = run().await {
        tracing::error!(%error, "daemon stopped with an error");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let (config_path, endpoint_override) = parse_args()?;
    let mut config = DaemonConfig::load(config_path.as_deref())?;
    if let Some(endpoint) = endpoint_override { config.ipc_endpoint = Some(endpoint); }
    std::fs::create_dir_all(&config.data_dir).map_err(|error| format!("create data dir: {error}"))?;
    std::fs::create_dir_all(&config.save_dir).map_err(|error| format!("create save dir: {error}"))?;

    let listener = LocalListener::bind(config.endpoint()).map_err(|error| error.to_string())?;
    let mut engine = Engine::new(config.engine_config());
    engine.start().await.map_err(|error| error.to_string())?;
    let resolver = Arc::new(OfferResolver::new());
    let serve = engine.serve(ServeOptions {
        save_dir: config.save_dir.clone(),
        accept_all_trusted: config.accept_all_trusted,
        on_collision: config::collision_from_dto(config.collision_policy),
        accept_policy: AcceptPolicy::Resolver(resolver.clone()),
    }).await.map_err(|error| error.to_string())?;
    engine.runtime().set_base_accept_policy(AcceptPolicy::Resolver(resolver));

    let mut engine_events = engine.subscribe();
    let engine = Arc::new(engine);
    let broker = Arc::new(EventBroker::new());
    let event_broker = broker.clone();
    tokio::spawn(async move {
        loop {
            match engine_events.recv().await {
                Ok(event) => { event_broker.publish(map_event(event)).await; }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "engine event subscriber lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let shutdown = Arc::new(Notify::new());
    let backend = Arc::new(DaemonBackend::new(engine.clone(), serve, broker, shutdown.clone()));
    let signal_backend = backend.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = signal_backend.handle(privet_ipc::Request::Shutdown).await;
            signal_backend.shutdown.notify_waiters();
        }
    });
    server::run(listener, backend).await.map_err(|error| error.to_string())
}

fn parse_args() -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
    let mut config = None;
    let mut endpoint = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config") => config = Some(args.next().map(PathBuf::from).ok_or("--config needs a path")?),
            Some("--ipc") => endpoint = Some(args.next().map(PathBuf::from).ok_or("--ipc needs a path")?),
            Some("--help") | Some("-h") => {
                println!("privetd [--config PATH] [--ipc PATH]");
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {}", arg.to_string_lossy())),
        }
    }
    Ok((config, endpoint))
}
