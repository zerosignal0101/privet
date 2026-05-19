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

    /// Security mode: allow-all, trust-required (default), strict
    #[arg(long)]
    pub security_mode: Option<String>,

    /// Shortcut for --security-mode allow-all
    #[arg(long)]
    pub auto_accept: bool,

    /// Non-interactive mode: fail immediately if pairing is required
    #[arg(long)]
    pub non_interactive: bool,

    /// Force TCP fallback (skip QUIC)
    #[arg(long)]
    pub force_tcp: bool,
}

pub async fn run(args: SendArgs, mut config: PrivetConfig) -> privet_core::Result<()> {
    if args.files.is_empty() {
        eprintln!("No files specified");
        std::process::exit(1);
    }

    if let Some(ref mode) = args.security_mode {
        config.security_mode = match mode.as_str() {
            "allow-all" | "allow_all" => privet_core::SecurityMode::AllowAll,
            "trust-required" | "trust_required" => privet_core::SecurityMode::TrustRequired,
            "strict" => privet_core::SecurityMode::Strict,
            other => {
                eprintln!("Error: invalid security mode '{other}'. Use: allow-all, trust-required, strict");
                std::process::exit(1);
            }
        };
    } else if args.auto_accept {
        config.security_mode = privet_core::SecurityMode::AllowAll;
    }

    if args.force_tcp {
        config.transport.force_tcp_fallback = true;
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

            let session_id = send_to_addr_with_progress(
                &engine, &mut events, addr, args.files.clone(), args.non_interactive,
            ).await?;
            println!("\nTransfer complete! Session: {session_id}");
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
                        let session_id = send_to_peer_with_progress(
                            &engine, &mut events, &peer.id, args.files.clone(), args.non_interactive,
                        ).await?;
                        println!("\nTransfer complete! Session: {session_id}");
                        break;
                    }
                }
            }

            if !found {
                let peers = engine.discovered_peers().await;
                if let Some(peer) = peers.iter().find(|p| p.name == *name) {
                    found = true;
                    println!("Sending {} file(s) to '{}'...", args.files.len(), name);
                    let session_id = send_to_peer_with_progress(
                        &engine, &mut events, &peer.id, args.files.clone(), args.non_interactive,
                    ).await?;
                    println!("\nTransfer complete! Session: {session_id}");
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

/// Send files to an IP address with progress display and Ctrl+C handling.
async fn send_to_addr_with_progress(
    engine: &privet_core::PrivetEngine,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<privet_core::PrivetEvent>,
    addr: SocketAddr,
    files: Vec<PathBuf>,
    non_interactive: bool,
) -> privet_core::Result<privet_core::SessionId> {
    loop {
        let sid = privet_core::SessionId::new();
        let send_future = engine.send_files_to_addr(addr, files.clone(), sid);
        tokio::pin!(send_future);

        let result = loop {
            tokio::select! {
                result = &mut send_future => {
                    break result;
                }
                event = events.recv() => {
                    match event {
                        Some(privet_core::PrivetEvent::TransferProgress { progress, .. }) => {
                            print!("{}", super::format_progress_line(&progress));
                            use std::io::Write;
                            let _ = std::io::stdout().flush();
                        }
                        Some(privet_core::PrivetEvent::TransferComplete { .. }) => {
                            // Handled by send returning Ok - nothing extra needed
                        }
                        Some(privet_core::PrivetEvent::TransferFailed { error, .. }) => {
                            tracing::debug!("send progress: transfer failed event: {error}");
                        }
                        _ => {}
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\nCancelling transfer...");
                    let _ = engine.cancel_transfer(&sid).await;
                    println!("Transfer cancelled.");
                    std::process::exit(0);
                }
            }
        };

        match result {
            Ok(session_id) => return Ok(session_id),
            Err(privet_core::PrivetError::Security(
                privet_core::error::SecurityError::PairingRequired,
            )) => {
                handle_pairing_required(engine, events, non_interactive).await?;
                continue; // retry the send
            }
            Err(e) => return Err(e),
        }
    }
}

/// Send files to a discovered peer ID with progress display and Ctrl+C handling.
async fn send_to_peer_with_progress(
    engine: &privet_core::PrivetEngine,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<privet_core::PrivetEvent>,
    peer_id: &privet_core::PeerId,
    files: Vec<PathBuf>,
    non_interactive: bool,
) -> privet_core::Result<privet_core::SessionId> {
    loop {
        let send_future = engine.send_files(peer_id, files.clone());
        tokio::pin!(send_future);

        let result = loop {
            tokio::select! {
                result = &mut send_future => {
                    break result;
                }
                event = events.recv() => {
                    match event {
                        Some(privet_core::PrivetEvent::TransferProgress { progress, .. }) => {
                            print!("{}", super::format_progress_line(&progress));
                            use std::io::Write;
                            let _ = std::io::stdout().flush();
                        }
                        _ => {}
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\nCancelling transfer...");
                    // For send_files we don't have the session_id easily,
                    // but we can use cancel_all or just exit
                    println!("Shutting down...");
                    std::process::exit(0);
                }
            }
        };

        match result {
            Ok(session_id) => return Ok(session_id),
            Err(privet_core::PrivetError::Security(
                privet_core::error::SecurityError::PairingRequired,
            )) => {
                handle_pairing_required(engine, events, non_interactive).await?;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
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
