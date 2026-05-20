use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::SystemTime;

use clap::Args;

use privet_core::session::TransferDirection;
use privet_core::storage::records::TransferRecordState;
use privet_core::{PrivetConfig, PrivetEngine, PrivetError, SessionId, PrivetEvent};
use privet_core::error::SecurityError;

#[derive(Args)]
pub struct HistoryArgs {
    /// Maximum number of records to show
    #[arg(short, long, default_value = "20")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,

    /// Show verbose output (per-file details)
    #[arg(short, long)]
    pub verbose: bool,

    /// Delete a transfer record by session ID
    #[arg(long)]
    pub delete: Option<String>,

    /// Resend files from a transfer record
    #[arg(long)]
    pub resend: Option<String>,

    /// Target peer address for --resend
    #[arg(long = "to-ip")]
    pub to_ip: Option<String>,

    /// Target peer name for --resend (resolves via discovery)
    #[arg(long = "to-name")]
    pub to_name: Option<String>,

    /// Force TCP fallback (skip QUIC)
    #[arg(long)]
    pub force_tcp: bool,
}

pub async fn run(args: HistoryArgs, mut config: PrivetConfig) -> privet_core::Result<()> {
    if args.force_tcp {
        config.transport.force_tcp_fallback = true;
    }
    let engine = PrivetEngine::new(config).await?;

    // Handle --delete
    if let Some(sid_str) = &args.delete {
        let sid: SessionId = sid_str.parse().map_err(|e| {
            PrivetError::SessionNotFound(format!("invalid session id: {e}"))
        })?;
        engine.delete_transfer_record(&sid)?;
        println!("Deleted record for session {sid}");
        return Ok(());
    }

    // Handle --resend
    if let Some(sid_str) = &args.resend {
        return run_resend(&engine, sid_str, &args).await;
    }

    // Default: list history
    let records = engine.transfer_history(args.limit, args.offset);
    if records.is_empty() {
        println!("No transfer history");
        return Ok(());
    }

    if args.verbose {
        // Verbose multi-line format
        for record in &records {
            let dir_label = match record.direction {
                TransferDirection::Sending => "Send",
                TransferDirection::Receiving => "Receive",
            };
            let state_label = match &record.state {
                TransferRecordState::Completed => "Completed",
                TransferRecordState::Failed => "Failed",
                TransferRecordState::Cancelled => "Cancelled",
                TransferRecordState::Rejected => "Rejected",
            };
            let peer = if !record.peer_name.is_empty() {
                record.peer_name.as_str()
            } else if !record.peer_fingerprint.is_empty() {
                &record.peer_fingerprint[..8.min(record.peer_fingerprint.len())]
            } else {
                "unknown"
            };
            println!("Session: {}", record.session_id);
            println!("  Direction: {dir_label}");
            println!("  Peer: {peer}");
            if !record.peer_fingerprint.is_empty() {
                println!("  Fingerprint: {}", record.peer_fingerprint);
            }
            println!("  State: {state_label}");
            println!("  Total: {} ({})", super::format_size(record.total_bytes), record.total_bytes);
            println!("  Transferred: {} ({})", super::format_size(record.bytes_transferred), record.bytes_transferred);
            if let Some(ts) = record.started_at {
                println!("  Started: {}", format_timestamp(ts));
            }
            if let Some(ts) = record.completed_at {
                println!("  Completed: {}", format_timestamp(ts));
            }
            if let Some(ref err) = record.error {
                if !err.is_empty() {
                    println!("  Error: {err}");
                }
            }
            if !record.files.is_empty() {
                println!("  Files:");
                for f in &record.files {
                    let path = PathBuf::from(&f.path);
                    let name = path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| f.path.clone());
                    println!("    - {} ({})", name, super::format_size(f.size));
                }
            }
            println!();
        }
    } else {
        // Compact table format
        println!("{:<8} {:<3} {:<20} {:<5} {:<10} {:<12} {:<9}",
            "ID", "Dir", "Peer", "Files", "Size", "Time", "State");
        println!("{}", "-".repeat(72));

        for record in &records {
            let dir_icon = match record.direction {
                TransferDirection::Sending => "S",
                TransferDirection::Receiving => "R",
            };
            let short_id = &record.session_id.to_string()[..8.min(record.session_id.to_string().len())];
            let peer = if !record.peer_name.is_empty() {
                &record.peer_name[..20.min(record.peer_name.len())]
            } else if !record.peer_fingerprint.is_empty() {
                &record.peer_fingerprint[..8.min(record.peer_fingerprint.len())]
            } else {
                "?"
            };
            let file_count = record.files.len();
            let size = super::format_size(record.total_bytes);
            let time = record.completed_at
                .map(format_timestamp)
                .unwrap_or_else(|| "?".to_string());
            let state = match &record.state {
                TransferRecordState::Completed => "done",
                TransferRecordState::Failed => "failed",
                TransferRecordState::Cancelled => "cancelled",
                TransferRecordState::Rejected => "rejected",
            };

            println!("{short_id:<8} {dir_icon:<3} {peer:<20} {file_count:<5} {size:<10} {time:<12} {state:<9}");
            if let Some(ref err) = record.error {
                if !err.is_empty() {
                    println!("         Error: {err}");
                }
            }
        }
    }

    println!("\nShowing {} record(s) (offset: {}, total: {})",
        records.len(), args.offset, engine.transfer_history(0, 0).len());

    Ok(())
}

async fn run_resend(
    engine: &PrivetEngine,
    sid_str: &str,
    args: &HistoryArgs,
) -> privet_core::Result<()> {
    let sid: SessionId = sid_str.parse().map_err(|e| {
        PrivetError::SessionNotFound(format!("invalid session id: {e}"))
    })?;

    let record = engine.transfer_record(&sid)
        .ok_or_else(|| PrivetError::SessionNotFound(sid_str.to_owned()))?;

    // Check file existence
    let mut existing_files = Vec::new();
    let mut missing_files = Vec::new();
    for file_record in &record.files {
        let path = PathBuf::from(&file_record.path);
        if path.is_absolute() && path.exists() {
            existing_files.push(path);
        } else {
            missing_files.push(file_record.path.clone());
        }
    }

    if !missing_files.is_empty() {
        eprintln!("Warning: {} file(s) not found:", missing_files.len());
        for f in &missing_files {
            eprintln!("  - {f}");
        }
    }

    if existing_files.is_empty() {
        eprintln!("Error: No files available to send");
        std::process::exit(1);
    }

    // Expand paths (handle directories if any)
    let expanded = privet_core::session::expand_paths(&existing_files);
    let expanded_files = expanded.files;

    // Show resume info
    let resume_msg = if existing_files.len() < record.files.len() {
        format!("Sending {} of {} file(s):", existing_files.len(), record.files.len())
    } else {
        format!("Resending {} file(s):", existing_files.len())
    };
    println!("{resume_msg}");
    for f in &existing_files {
        println!("  {}", f.display());
    }

    // Resolve target
    let has_ip = args.to_ip.is_some();
    let has_name = args.to_name.is_some();

    let addr: SocketAddr;
    let addr_label: String;

    match (has_ip, has_name) {
        (true, _) => {
            let addr_str = args.to_ip.as_ref().unwrap();
            addr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
                PrivetError::PeerNotFound(format!("invalid address: {e}"))
            })?;
            addr_label = addr.to_string();
        }
        (false, true) => {
            let name = args.to_name.as_ref().unwrap();
            // Discover peer by name
            engine.start().await?;
            let mut events = engine.subscribe_events().await;
            println!("Looking for peer '{name}' via discovery (timeout: 6s)...");

            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(6);
            let mut found_addr: Option<SocketAddr> = None;

            while tokio::time::Instant::now() < deadline {
                if let Some(PrivetEvent::PeerDiscovered(peer)) = events.recv().await {
                    if peer.name == *name {
                        if let Some(pa) = peer.primary_address() {
                            found_addr = Some(pa);
                            break;
                        }
                    }
                }
            }

            if found_addr.is_none() {
                let peers = engine.discovered_peers().await;
                found_addr = peers.iter()
                    .find(|p| p.name == *name)
                    .and_then(|p| p.primary_address());
            }

            match found_addr {
                Some(a) => {
                    addr = a;
                    addr_label = format!("{name} ({addr})");
                }
                None => {
                    eprintln!("Error: Peer '{name}' not found via discovery");
                    std::process::exit(1);
                }
            }
        }
        (false, false) => {
            eprintln!("Error: --resend requires --to-ip <addr:port> or --to-name <name>");
            std::process::exit(1);
        }
    }

    // Send with progress and Ctrl+C handling
    engine.start().await?;
    let mut events = engine.subscribe_events().await;
    println!("Resending to {addr_label}...");

    let sid = SessionId::new();
    let send_result = {
        let send_future = engine.send_files_to_addr(addr, expanded_files.clone(), sid);
        tokio::pin!(send_future);

        let result = loop {
            tokio::select! {
                result = &mut send_future => {
                    break result;
                }
                event = events.recv() => {
                    if let Some(PrivetEvent::TransferProgress { progress, .. }) = event {
                        print!("{}", super::format_progress_line(&progress));
                        use std::io::Write;
                        let _ = std::io::stdout().flush();
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\nCancelling resend...");
                    let _ = engine.cancel_transfer(&sid).await;
                    println!("Resend cancelled.");
                    std::process::exit(0);
                }
            }
        };
        result
    };

    match send_result {
        Ok(id) => {
            println!("\nResend complete! Session: {id}");
        }
        Err(PrivetError::Security(
            SecurityError::PairingRequired,
        )) => {
            eprintln!("Error: Peer not trusted. Use `privet pair --trust <fingerprint>` first.");
            std::process::exit(1);
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

fn format_timestamp(unix_secs: u64) -> String {
    let duration = std::time::Duration::from_secs(unix_secs);
    let sys_time = SystemTime::UNIX_EPOCH + duration;

    let now = SystemTime::now();
    let diff = now.duration_since(sys_time).ok();

    // Show relative time for recent records
    if let Some(d) = diff {
        if d.as_secs() < 60 {
            return "just now".to_string();
        }
        if d.as_secs() < 3600 {
            return format!("{}m ago", d.as_secs() / 60);
        }
        if d.as_secs() < 86400 {
            return format!("{}h ago", d.as_secs() / 3600);
        }
        if d.as_secs() < 604800 {
            return format!("{}d ago", d.as_secs() / 86400);
        }
    }

    // For older records, show date using basic math from epoch
    let secs_from_epoch = unix_secs;
    const SECS_PER_DAY: u64 = 86400;
    let days = secs_from_epoch / SECS_PER_DAY;
    let time_secs = secs_from_epoch % SECS_PER_DAY;
    let hours = time_secs / 3600;
    let mins = (time_secs % 3600) / 60;

    // Convert days to date (simple linear approximation, accurate enough for display)
    let year = 1970 + (days as f64 / 365.25) as u64;
    let y_days = days - ((year - 1970) * 365 + ((year - 1969) / 4));
    let month = (y_days as f64 / 30.44) as u64;
    let day = y_days - (month * 30);

    format!("{:04}-{:02}-{:02} {:02}:{:02}", year, month + 1, day + 1, hours, mins)
}
