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

    // Subscribe to events and print them
    let mut events = engine.subscribe_events().await;

    println!("Waiting for incoming transfers... (Ctrl+C to stop)");

    loop {
        match events.recv().await {
            Some(privet_core::PrivetEvent::IncomingTransfer { session_id, peer, files }) => {
                println!("\nIncoming transfer from {}", peer.name);
                println!("  Session: {session_id}");
                println!("  Files: {} ({})", files.files.len(), format_size(files.total_size));
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

fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{b:.1} GB")
    } else if b >= MB {
        format!("{b:.1} MB")
    } else if b >= KB {
        format!("{b:.1} KB")
    } else {
        format!("{b} B")
    }
}
