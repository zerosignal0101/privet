mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "privet", version, about = "Fast LAN file transfer with QUIC")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Config file path
    #[arg(long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Send files to a peer
    Send(commands::send::SendArgs),
    /// Receive files (supports daemon mode)
    Receive(commands::receive::ReceiveArgs),
    /// Discover peers on the LAN
    Discover(commands::discover::DiscoverArgs),
    /// Show active transfers
    Status,
    /// Manage trusted peers and pairing
    Pair(commands::pair::PairArgs),
}

#[tokio::main]
async fn main() {
    privet_core::init();

    let cli = Cli::parse();

    // Initialize logging
    let level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();

    let config = load_config(&cli.config);

    if let Err(e) = run_command(cli.command, config).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn load_config(_config_path: &Option<String>) -> privet_core::PrivetConfig {
    let device_name = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "privet-device".to_owned());

    privet_core::PrivetConfig::default_with_name(device_name)
}

async fn run_command(
    command: Commands,
    config: privet_core::PrivetConfig,
) -> privet_core::Result<()> {
    match command {
        Commands::Send(args) => commands::send::run(args, config).await,
        Commands::Receive(args) => commands::receive::run(args, config).await,
        Commands::Discover(args) => commands::discover::run(args, config).await,
        Commands::Pair(args) => commands::pair::run(args, config).await,
        Commands::Status => {
            println!("No active transfers (daemon not yet implemented)");
            Ok(())
        }
    }
}
