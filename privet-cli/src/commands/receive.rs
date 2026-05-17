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

    /// Auto-accept transfers from trusted peers
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
    config.auto_accept_trusted = args.auto_accept_trusted;

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

    loop {
        match events.recv().await {
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
            Some(privet_core::PrivetEvent::TransferProgress { session_id: _, progress }) => {
                print!(
                    "\r  [{:.1}%] {:.1} MB/s  {:.1}/{:.1} MB",
                    progress.percent(),
                    progress.current_speed_bps / 1_000_000.0,
                    progress.bytes_transferred as f64 / 1_000_000.0,
                    progress.total_bytes as f64 / 1_000_000.0,
                );
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
            Some(privet_core::PrivetEvent::TransferComplete { session_id }) => {
                println!("\n  Transfer complete: {session_id}");
            }
            Some(privet_core::PrivetEvent::TransferFailed { session_id, error }) => {
                println!("\n  Transfer failed: {session_id}: {error}");
            }
            Some(event) => {
                tracing::debug!("Event: {event:?}");
            }
            None => break,
        }
    }

    engine.shutdown().await?;
    Ok(())
}
