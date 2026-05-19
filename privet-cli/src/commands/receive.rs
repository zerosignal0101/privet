use std::path::PathBuf;

use clap::Args;

use privet_core::PrivetConfig;

#[derive(Args)]
pub struct ReceiveArgs {
    /// Output directory for received files
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Run as daemon (background mode)
    #[arg(long)]
    pub daemon: bool,

    /// Security mode: allow-all, trust-required (default), strict
    #[arg(long)]
    pub security_mode: Option<String>,

    /// Shortcut for --security-mode allow-all (auto-accept all transfers)
    #[arg(long)]
    pub auto_accept_trusted: bool,

    /// Non-interactive mode: reject all pairing requests and non-auto-accepted transfers
    #[arg(long)]
    pub non_interactive: bool,
}

pub async fn run(args: ReceiveArgs, mut config: PrivetConfig) -> privet_core::Result<()> {
    if let Some(dir) = args.output {
        config.download_dir = dir;
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
    } else if args.auto_accept_trusted {
        config.security_mode = privet_core::SecurityMode::AllowAll;
    }

    let engine = privet_core::PrivetEngine::new(config.clone()).await?;
    engine.start().await?;

    println!("Listening for incoming transfers on port {}...", config.transport.listen_port);
    println!("Download directory: {}", config.download_dir.display());

    let mut events = engine.subscribe_events().await;

    let mode = if args.non_interactive {
        "non-interactive"
    } else {
        "interactive"
    };
    println!("Waiting for incoming transfers... (mode: {mode}, Ctrl+C to stop)");

    let mut active_session: Option<privet_core::SessionId> = None;

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(privet_core::PrivetEvent::AwaitingPairing { session_id: _, peer, code }) => {
                if args.non_interactive {
                    println!("\nPairing request from {} (non-interactive, rejecting)", peer.name);
                    engine.reject_pairing(&peer.fingerprint).await?;
                } else {
                    println!("\nPairing request from {}", peer.name);
                    println!("  Fingerprint: {}", peer.fingerprint);
                    println!("  Verification code: {code}");
                    let choice = super::prompt_choice(
                        "  Options",
                        "T=Trust, A=Trust+Accept, R=Reject",
                    );
                    match choice {
                        'T' | 't' => {
                            engine.trust_peer(&peer.fingerprint).await?;
                            println!("  Trusted.");
                        }
                        'A' | 'a' => {
                            engine.trust_and_accept_peer(&peer.fingerprint).await?;
                            println!("  Trusted and auto-accepted.");
                        }
                        _ => {
                            engine.reject_pairing(&peer.fingerprint).await?;
                            println!("  Rejected.");
                        }
                    }
                }
            }
            Some(privet_core::PrivetEvent::AwaitingAccept { session_id, peer, files }) => {
                if args.non_interactive {
                    println!("\nIncoming transfer from {} (non-interactive, rejecting)", peer.name);
                    engine.reject_transfer(&session_id).await?;
                } else {
                    println!("\nIncoming transfer from {}", peer.name);
                    println!("  Session: {session_id}");
                    println!("  Files: {} ({})", files.files.len(), super::format_size(files.total_size));
                    let choice = super::prompt_choice("  Accept?", "A=Accept, R=Reject");
                    match choice {
                        'A' | 'a' => {
                            engine.accept_transfer(&session_id).await?;
                            println!("  Accepted.");
                        }
                        _ => {
                            engine.reject_transfer(&session_id).await?;
                            println!("  Rejected.");
                        }
                    }
                }
            }
            Some(privet_core::PrivetEvent::IncomingTransfer { session_id, peer, files }) => {
                println!("\nIncoming transfer from {}", peer.name);
                println!("  Session: {session_id}");
                println!("  Files: {} ({})", files.files.len(), super::format_size(files.total_size));
            }
            Some(privet_core::PrivetEvent::TransferProgress { session_id, progress, .. }) => {
                active_session = Some(session_id);
                print!("{}", super::format_progress_line(&progress));
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
            Some(privet_core::PrivetEvent::TransferComplete { .. }) => {
                println!("\n  Transfer complete");
            }
            Some(privet_core::PrivetEvent::TransferFailed { error, .. }) => {
                println!("\n  Transfer failed: {error}");
            }
            Some(event) => {
                tracing::debug!("Event: {event:?}");
            }
            None => break,
        }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down...");
                if let Some(sid) = active_session.take() {
                    let _ = engine.cancel_transfer(&sid).await;
                    println!("Active transfer cancelled.");
                }
                break;
            }
        }
    }

    engine.shutdown().await?;
    Ok(())
}
