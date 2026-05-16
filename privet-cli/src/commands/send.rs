use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;

use privet_core::PrivetConfig;

#[derive(Args)]
pub struct SendArgs {
    /// Files to send
    pub files: Vec<PathBuf>,

    /// Target peer address (IP:port)
    #[arg(long = "to-ip", short = 't')]
    pub to_ip: Option<String>,

    /// Target peer name (resolved via discovery)
    #[arg(long = "to-name")]
    pub to_name: Option<String>,
}

pub async fn run(args: SendArgs, config: PrivetConfig) -> privet_core::Result<()> {
    if args.files.is_empty() {
        eprintln!("No files specified");
        std::process::exit(1);
    }

    // Validate that exactly one of --to-ip or --to-name is provided
    let has_ip = args.to_ip.is_some();
    let has_name = args.to_name.is_some();
    match (has_ip, has_name) {
        (true, false) => {
            // Direct address send
            let addr: SocketAddr = args.to_ip.as_ref().unwrap().parse().map_err(|e: std::net::AddrParseError| {
                privet_core::PrivetError::PeerNotFound(format!(
                    "invalid address '{}': {e}",
                    args.to_ip.as_ref().unwrap()
                ))
            })?;

            let engine = privet_core::PrivetEngine::new(config).await?;
            println!("Sending {} file(s) to {addr}...", args.files.len());
            let session_id = engine.send_files_to_addr(addr, args.files).await?;
            println!("Transfer complete! Session: {session_id}");
        }
        (false, true) => {
            // Name-based send via discovery
            let name = args.to_name.as_ref().unwrap();
            let engine = privet_core::PrivetEngine::new(config).await?;
            let mut events = engine.subscribe_events().await;
            engine.start().await?;

            println!("Looking for peer '{name}' via discovery (timeout: 6s)...");

            // Wait up to 6 seconds for the peer to appear
            let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
            let mut found = false;

            while tokio::time::Instant::now() < deadline {
                if let Some(privet_core::PrivetEvent::PeerDiscovered(peer)) = events.recv().await {
                    if peer.name == *name {
                        println!("Found peer '{}' at {}", peer.name, peer.primary_address().map_or("?".into(), |a| a.to_string()));
                        found = true;
                        println!("Sending {} file(s)...", args.files.len());
                        let session_id = engine.send_files(&peer.id, args.files.clone()).await?;
                        println!("Transfer complete! Session: {session_id}");
                        break;
                    }
                }
            }

            if !found {
                // One last check in case we missed the event
                let peers = engine.discovered_peers().await;
                if let Some(peer) = peers.iter().find(|p| p.name == *name) {
                    found = true;
                    println!("Sending {} file(s) to '{}'...", args.files.len(), name);
                    let session_id = engine.send_files(&peer.id, args.files.clone()).await?;
                    println!("Transfer complete! Session: {session_id}");
                }
            }

            if !found {
                eprintln!("Peer '{name}' not found via discovery");
                std::process::exit(1);
            }

            engine.shutdown().await?;
        }
        _ => {
            eprintln!("Either --to-ip <addr:port> or --to-name <name> must be provided");
            std::process::exit(1);
        }
    }

    Ok(())
}
