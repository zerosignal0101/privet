use std::time::Duration;

use clap::Args;

use privet_core::PrivetConfig;

#[derive(Args)]
pub struct DiscoverArgs {
    /// Discovery timeout in seconds
    #[arg(short, long, default_value = "6")]
    pub timeout: u64,

    /// Subnet to scan (CIDR notation, e.g., 10.20.1.0/24)
    #[arg(long)]
    pub subnet: Option<String>,
}

pub async fn run(args: DiscoverArgs, config: PrivetConfig) -> privet_core::Result<()> {
    let listen_port = config.transport.listen_port;
    let engine = privet_core::PrivetEngine::new(config).await?;
    let mut events = engine.subscribe_events().await;
    engine.start().await?;

    println!("Discovering peers for {} seconds...", args.timeout);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);

    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(privet_core::PrivetEvent::PeerDiscovered(peer)) => {
                        let addr = peer.primary_address()
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| "unknown".into());
                        println!(
                            "  Peer: {}  |  addr: {:<21}  |  fp: {}  |  trusted: {}",
                            peer.name,
                            addr,
                            peer.display_fingerprint(),
                            if peer.is_trusted { "✓" } else { " " },
                        );
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    let peers = engine.discovered_peers().await;
    println!("\nDiscovered {} peer(s)", peers.len());

    if let Some(cidr) = &args.subnet {
        println!("\nScanning subnet {cidr}...");
        // Scanner scan is not yet wired into the engine event loop;
        // run it as a standalone probe.
        let scanner = privet_core::discovery::scanner::SubnetScanner::new(
            listen_port,
            Duration::from_millis(500),
        );
        match scanner.scan(cidr).await {
            Ok(addrs) => {
                if addrs.is_empty() {
                    println!("  No hosts found");
                } else {
                    for addr in &addrs {
                        println!("  Found: {addr}");
                    }
                }
            }
            Err(e) => eprintln!("Scan error: {e}"),
        }
    }

    engine.shutdown().await?;
    Ok(())
}
