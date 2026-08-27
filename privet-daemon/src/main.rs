mod backend;
mod config;
mod events;
mod run;
mod server;

use std::path::PathBuf;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let (config_path, endpoint_override) = parse_args().unwrap_or_else(|error| {
        eprintln!("privetd: {error}");
        std::process::exit(2);
    });
    if let Err(error) = run::run(config_path, endpoint_override).await {
        tracing::error!(%error, "daemon stopped with an error");
        std::process::exit(1);
    }
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
