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

    /// Auto-accept transfer from untrusted peers (skip pairing)
    #[arg(long)]
    pub auto_accept: bool,

    /// Non-interactive mode: fail immediately if pairing is required
    #[arg(long)]
    pub non_interactive: bool,
}

pub async fn run(args: SendArgs, mut config: PrivetConfig) -> privet_core::Result<()> {
    if args.files.is_empty() {
        eprintln!("No files specified");
        std::process::exit(1);
    }

    if args.auto_accept {
        config.auto_accept_trusted = true;
    }

    let has_ip = args.to_ip.is_some();
    let has_name = args.to_name.is_some();
    match (has_ip, has_name) {
        (true, false) => {
            let addr: SocketAddr = args.to_ip.as_ref().unwrap().parse().map_err(|e: std::net::AddrParseError| {
                privet_core::PrivetError::PeerNotFound(format!(
                    "invalid address '{}': {e}",
                    args.to_ip.as_ref().unwrap()
                ))
            })?;

            let engine = privet_core::PrivetEngine::new(config).await?;
            let mut events = engine.subscribe_events().await;
            println!("Sending {} file(s) to {addr}...", args.files.len());

            let session_id = match engine.send_files_to_addr(addr, args.files.clone()).await {
                Ok(id) => id,
                Err(privet_core::PrivetError::Security(
                    privet_core::error::SecurityError::PairingRequired,
                )) => {
                    handle_pairing_required(&engine, &mut events, args.non_interactive).await?;
                    engine.send_files_to_addr(addr, args.files).await?
                }
                Err(e) => return Err(e),
            };
            println!("Transfer complete! Session: {session_id}");
        }
        (false, true) => {
            let name = args.to_name.as_ref().unwrap();
            let engine = privet_core::PrivetEngine::new(config).await?;
            let mut events = engine.subscribe_events().await;
            engine.start().await?;

            println!("Looking for peer '{name}' via discovery (timeout: 6s)...");

            let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
            let mut found = false;

            while tokio::time::Instant::now() < deadline {
                if let Some(privet_core::PrivetEvent::PeerDiscovered(peer)) = events.recv().await {
                    if peer.name == *name {
                        println!("Found peer '{}' at {}", peer.name, peer.primary_address().map_or("?".into(), |a| a.to_string()));
                        found = true;
                        println!("Sending {} file(s)...", args.files.len());
                        let session_id = match engine.send_files(&peer.id, args.files.clone()).await {
                            Ok(id) => id,
                            Err(privet_core::PrivetError::Security(
                                privet_core::error::SecurityError::PairingRequired,
                            )) => {
                                handle_pairing_required(&engine, &mut events, args.non_interactive).await?;
                                engine.send_files(&peer.id, args.files.clone()).await?
                            }
                            Err(e) => return Err(e),
                        };
                        println!("Transfer complete! Session: {session_id}");
                        break;
                    }
                }
            }

            if !found {
                let peers = engine.discovered_peers().await;
                if let Some(peer) = peers.iter().find(|p| p.name == *name) {
                    found = true;
                    println!("Sending {} file(s) to '{}'...", args.files.len(), name);
                    let session_id = match engine.send_files(&peer.id, args.files.clone()).await {
                        Ok(id) => id,
                        Err(privet_core::PrivetError::Security(
                            privet_core::error::SecurityError::PairingRequired,
                        )) => {
                            handle_pairing_required(&engine, &mut events, args.non_interactive).await?;
                            engine.send_files(&peer.id, args.files.clone()).await?
                        }
                        Err(e) => return Err(e),
                    };
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

/// Handle a PairingRequired error by waiting for the PairRequest event
/// and prompting the user to trust, trust+accept, or reject.
async fn handle_pairing_required(
    engine: &privet_core::PrivetEngine,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<privet_core::PrivetEvent>,
    non_interactive: bool,
) -> privet_core::Result<()> {
    if non_interactive {
        eprintln!("Error: Peer not trusted. Use `privet pair --trust <fingerprint>` first.");
        std::process::exit(1);
    }

    // Wait for PairRequest event from the engine (emitted before the error was returned)
    let (peer, code) = loop {
        match events.recv().await {
            Some(privet_core::PrivetEvent::PairRequest { peer, code }) => {
                break (peer, code);
            }
            Some(_) => continue,
            None => {
                eprintln!("Error: Event stream closed before pairing info received.");
                std::process::exit(1);
            }
        }
    };

    println!("\nPeer requires pairing:");
    println!("  Device: {}", peer.name);
    println!("  Fingerprint: {}", peer.fingerprint);
    println!("  Verification code: {code}");
    let choice = super::prompt_choice("  Options", "T=Trust, A=Trust+Accept, R=Reject");
    match choice {
        'T' | 't' => {
            engine.trust_peer(&peer.fingerprint).await?;
            println!("  Trusted. Retrying send...");
        }
        'A' | 'a' => {
            engine.trust_and_accept_peer(&peer.fingerprint).await?;
            println!("  Trusted and auto-accepted. Retrying send...");
        }
        _ => {
            engine.reject_pairing(&peer.fingerprint).await?;
            eprintln!("  Pairing rejected. Cannot send.");
            std::process::exit(1);
        }
    }
    Ok(())
}
