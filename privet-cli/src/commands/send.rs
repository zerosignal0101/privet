use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;

use privet_core::PrivetConfig;

#[derive(Args)]
pub struct SendArgs {
    /// Files to send
    pub files: Vec<PathBuf>,

    /// Target peer address (IP:port)
    #[arg(short, long)]
    pub to: String,

    /// Peer name (alternative to --to, resolves via discovery)
    #[arg(long)]
    pub name: Option<String>,
}

pub async fn run(args: SendArgs, config: PrivetConfig) -> privet_core::Result<()> {
    if args.files.is_empty() {
        eprintln!("No files specified");
        std::process::exit(1);
    }

    let engine = privet_core::PrivetEngine::new(config).await?;

    let addr: SocketAddr = args.to.parse().map_err(|e: std::net::AddrParseError| {
        privet_core::PrivetError::PeerNotFound(format!("invalid address '{}': {e}", args.to))
    })?;

    println!("Sending {} file(s) to {addr}...", args.files.len());

    let session_id = engine.send_files_to_addr(addr, args.files).await?;

    println!("Transfer complete! Session: {session_id}");
    Ok(())
}
