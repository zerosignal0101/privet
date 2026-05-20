use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use privet_core::{PrivetConfig, SessionId};
use sha2::{Digest, Sha256};

/// Generate a random binary file of `size` bytes in `dir`.
fn generate_test_file(dir: &Path, name: &str, size: usize) -> (PathBuf, String) {
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    let mut hasher = Sha256::new();

    let chunk_size = 64 * 1024;
    let mut remaining = size;
    let mut seed = size as u64;

    while remaining > 0 {
        let n = remaining.min(chunk_size);
        let buf: Vec<u8> = (0..n)
            .map(|i| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                ((seed >> 32) as u8).wrapping_add(i as u8)
            })
            .collect();
        file.write_all(&buf).unwrap();
        hasher.update(&buf);
        remaining -= n;
    }

    file.flush().unwrap();
    let hash = format!("{:x}", hasher.finalize());
    (path, hash)
}

/// Each test gets a unique port from this counter.
static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(16000);

fn pick_port() -> u16 {
    NEXT_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn sha256_file(path: &Path) -> String {
    let data = std::fs::read(path).unwrap();
    let hash = Sha256::digest(&data);
    format!("{hash:x}")
}

/// Helper: expand paths (handles directories) then send to addr.
async fn send_files(
    engine: &privet_core::PrivetEngine,
    addr: SocketAddr,
    paths: Vec<PathBuf>,
) -> Result<privet_core::SessionId, privet_core::PrivetError> {
    let expanded = privet_core::session::expand_paths(&paths);
    let sid = SessionId::new();
    engine.send_files_to_addr(addr, expanded.files, sid).await
}

/// Generate a directory tree with test files.
/// `structure` is a list of `(relative_path, file_size)` pairs.
/// Returns: (dir_path, HashMap<relative_path, (path, hash, size)>)
fn generate_dir_tree(
    base_dir: &Path,
    name: &str,
    structure: &[(&str, usize)],
) -> (PathBuf, HashMap<String, (PathBuf, String, u64)>) {
    let dir = base_dir.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let mut files = HashMap::new();

    for (rel_path, size) in structure {
        // Create parent directories if needed
        let full_path = dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        if *size > 0 {
            let (path, hash) = generate_test_file(&dir, rel_path, *size);
            let rel = rel_path.replace('\\', "/");
            files.insert(rel.clone(), (path, hash, *size as u64));
        } else {
            // size 0 = empty directory marker
            std::fs::create_dir_all(&full_path).unwrap();
        }
    }
    (dir, files)
}

// --- Test cases ---

#[tokio::test]
async fn e2e_1kb() { run_transfer(1024).await; }

#[tokio::test]
async fn e2e_64kb() { run_transfer(64 * 1024).await; }

#[tokio::test]
async fn e2e_64kb_plus1() { run_transfer(64 * 1024 + 1).await; }

#[tokio::test]
async fn e2e_1mb() { run_transfer(1024 * 1024).await; }

#[tokio::test]
async fn e2e_10mb() { run_transfer(10 * 1024 * 1024).await; }

// ---------------------------------------------------------------------------
// Pairing / trust test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_pairing_rejects_untrusted() {
    privet_core::init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&recv_dir).unwrap();
    let send_dir = temp_dir.path().join("send");
    std::fs::create_dir_all(&send_dir).unwrap();

    let port = pick_port();
    let (file_path, _) = generate_test_file(&send_dir, "pair_test.bin", 4096);

    let cert_dir = temp_dir.path().join("certs");
    std::fs::create_dir_all(&cert_dir).unwrap();

    // --- Start receiver (auto_accept so receiver side does not block) ---
    let mut recv_config = PrivetConfig::default_with_name("pair-recv".into());
    recv_config.transport.listen_port = port;
    recv_config.download_dir = recv_dir.clone();
    recv_config.security.cert_dir = Some(cert_dir.join("recv"));
    recv_config.security_mode = privet_core::SecurityMode::AllowAll;
    let recv_engine = privet_core::PrivetEngine::new(recv_config)
        .await
        .expect("recv engine");
    recv_engine.start().await.expect("recv start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // --- Start sender (no trust, auto_accept = false) ---
    let mut send_config = PrivetConfig::default_with_name("pair-send".into());
    send_config.transport.listen_port = 0;
    // TrustRequired is the default; no need to set explicitly
    send_config.security.cert_dir = Some(cert_dir.join("send"));
    let send_engine = privet_core::PrivetEngine::new(send_config)
        .await
        .expect("send engine");
    let mut send_events = send_engine.subscribe_events().await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // --- Attempt 1: should fail because peer is not trusted ---
    eprintln!("[pairing] attempting transfer without trust...");
    let err = send_files(&send_engine, addr, vec![file_path.clone()])
        .await
        .expect_err("expected PairingRequired error");

    match &err {
        privet_core::PrivetError::Security(privet_core::error::SecurityError::PairingRequired) => {
            eprintln!("[pairing] got expected error: {err}");
        }
        other => panic!("expected PairingRequired, got: {other}"),
    }

    // --- Capture PairRequest event to obtain the peer's fingerprint ---
    let mut peer_fingerprint = None;
    let mut pairing_code = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = send_events.recv() => {
                match event {
                    Some(privet_core::PrivetEvent::PairRequest { peer, code }) => {
                        eprintln!(
                            "[pairing] received PairRequest — fp={}, code={code}",
                            peer.display_fingerprint()
                        );
                        peer_fingerprint = Some(peer.fingerprint.clone());
                        pairing_code = Some(code);
                        break;
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    let peer_fp = peer_fingerprint.expect("did not receive PairRequest event within timeout");
    let code = pairing_code.expect("pairing code missing");

    // Verify the pairing code is symmetric — computed from both fingerprints
    let local_fp = &send_engine.identity().fingerprint;
    let expected_code =
        privet_core::security::trust::TrustStore::pairing_code(local_fp, &peer_fp);
    assert_eq!(code, expected_code, "pairing code mismatch");
    assert_eq!(code.len(), 6, "pairing code must be 6 digits");
    // Must also match when args are swapped (symmetry)
    assert_eq!(
        privet_core::security::trust::TrustStore::pairing_code(&peer_fp, local_fp),
        expected_code,
        "pairing code must be symmetric"
    );
    eprintln!("[pairing] verified code={code} for fingerprint");

    // --- Trust the peer ---
    send_engine
        .trust_peer(&peer_fp)
        .await
        .expect("trust_peer");

    let trusted = send_engine.trusted_fingerprints().await;
    assert!(trusted.contains(&peer_fp), "fingerprint should be trusted now");

    // --- Attempt 2: should succeed after trusting ---
    eprintln!("[pairing] retrying transfer after trust...");
    send_files(&send_engine, addr, vec![file_path.clone()])
        .await
        .expect("send should succeed after trust");
    eprintln!("[pairing] transfer succeeded after trust");

    // --- Attempt 3: untrust and verify rejection ---
    eprintln!("[pairing] untrusting peer...");
    send_engine
        .untrust_peer(&peer_fp)
        .await
        .expect("untrust_peer");

    let trusted_after = send_engine.trusted_fingerprints().await;
    assert!(!trusted_after.contains(&peer_fp), "fingerprint should no longer be trusted");

    let err = send_files(&send_engine, addr, vec![file_path])
        .await
        .expect_err("expected PairingRequired after untrust");
    match &err {
        privet_core::PrivetError::Security(privet_core::error::SecurityError::PairingRequired) => {
            eprintln!("[pairing] got expected error after untrust: {err}");
        }
        other => panic!("expected PairingRequired after untrust, got: {other}"),
    }
    eprintln!("[pairing] untrust verified — transfer correctly rejected");

    // Allow receiver to finish writing
    tokio::time::sleep(Duration::from_millis(200)).await;
    recv_engine.shutdown().await.expect("recv shutdown");

    // Verify file from the trusted transfer arrived correctly
    let received_path = recv_dir.join("pair_test.bin");
    assert!(received_path.exists(), "received file missing");
}

#[tokio::test]
async fn e2e_pairing_code_deterministic() {
    // Verify that both sides compute the same code for the same fingerprint.
    // We simulate this by having sender and receiver exchange fingerprints
    // via an actual transfer attempt that fails at the trust check.
    privet_core::init();

    let port = pick_port();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let send_dir = temp_dir.path().join("send");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&send_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();
    let (file_path, _) = generate_test_file(&send_dir, "code_test.bin", 1024);
    let cert_dir = temp_dir.path().join("certs");
    std::fs::create_dir_all(&cert_dir).unwrap();

    // Receiver without auto_accept — both sides will emit PairRequest
    let mut rc = PrivetConfig::default_with_name("code-recv".into());
    rc.transport.listen_port = port;
    rc.download_dir = recv_dir.clone();
    // TrustRequired is the default; rely on that
    rc.security.cert_dir = Some(cert_dir.join("recv"));
    let recv_engine = privet_core::PrivetEngine::new(rc).await.expect("recv");
    recv_engine.start().await.expect("recv start");
    let mut recv_events = recv_engine.subscribe_events().await;

    let mut sc = PrivetConfig::default_with_name("code-send".into());
    sc.transport.listen_port = 0;
    // TrustRequired is the default; rely on that
    sc.security.cert_dir = Some(cert_dir.join("send"));
    let send_engine = privet_core::PrivetEngine::new(sc).await.expect("send");
    let mut send_events = send_engine.subscribe_events().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let _ = send_files(&send_engine, addr, vec![file_path]).await;

    // Give events time to be dispatched
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Collect PairRequest code from sender side
    let send_code = collect_pair_code(&mut send_events, Duration::from_secs(3)).await;
    // Collect AwaitingPairing code from receiver side
    let recv_code = collect_awaiting_pairing_code(&mut recv_events, Duration::from_secs(3)).await;

    eprintln!(
        "[pairing] sender code={send_code:?} receiver code={recv_code:?}"
    );

    // Both sides must have received pairing codes
    assert!(send_code.is_some(), "sender did not receive PairRequest");
    assert!(recv_code.is_some(), "receiver did not receive AwaitingPairing");

    // The codes must match (both derived from the same fingerprint pair)
    assert_eq!(
        send_code, recv_code,
        "pairing codes from both sides must match"
    );

    recv_engine.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Multi-file transfer tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_multifile_small_batch() {
    // 5 small files (≤64KB each) → should be multiplexed onto one stream
    run_multifile_transfer(&[1024, 2048, 4096, 8192, 16384]).await;
}

#[tokio::test]
async fn e2e_multifile_mixed() {
    // 3 small files + 1 large → small files batched, large gets own stream
    run_multifile_transfer(&[1024, 2048, 4096, 512 * 1024]).await;
}

#[tokio::test]
async fn e2e_multifile_parallel() {
    // 3 files above small threshold → each gets its own stream, sent in parallel
    run_multifile_transfer(&[65 * 1024, 128 * 1024, 256 * 1024]).await;
}

#[tokio::test]
async fn e2e_multifile_many_small() {
    // 50 zeroable files (1KB each) → batched into ceil(50/16) = 4 streams.
    // This tests that small-file multiplexing handles many files correctly.
    let sizes: Vec<usize> = vec![1024; 50];
    run_multifile_transfer(&sizes).await;
}

#[tokio::test]
async fn e2e_multifile_concurrency_cap() {
    // 20 files above small threshold (100KB each) → each gets its own batch → 20 batches.
    // With MAX_CONCURRENT_STREAMS = 8, at most 8 run in parallel; the rest wait.
    // This verifies the semaphore does not deadlock and all files complete correctly.
    let sizes: Vec<usize> = vec![100 * 1024; 20];
    run_multifile_transfer(&sizes).await;
}

// ---------------------------------------------------------------------------
// Phase 4: Resume and Resilience tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_resume_partial_transfer() {
    // Verify that a partially received file can be resumed.
    privet_core::init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let send_dir = temp_dir.path().join("send");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&send_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();

    let port = pick_port();
    let file_name = "resume_test.bin";
    let file_size = 256 * 1024; // 256KB

    let (file_path, source_hash) = generate_test_file(&send_dir, file_name, file_size);

    // Create a partial file (100KB) in the receive directory to trigger resume
    let partial_path = recv_dir.join(file_name);
    let partial_size = 100 * 1024;
    let src_data = std::fs::read(&file_path).unwrap();
    std::fs::write(&partial_path, &src_data[..partial_size]).unwrap();

    // Copy mtime from source so resume matching succeeds
    let src_mtime = std::fs::metadata(&file_path).unwrap().modified().unwrap();
    let pf = std::fs::OpenOptions::new()
        .write(true)
        .open(&partial_path)
        .unwrap();
    let times = std::fs::FileTimes::new().set_modified(src_mtime);
    let _ = pf.set_times(times);

    let cert_dir = temp_dir.path().join("certs");
    // Start receiver
    let mut recv_config = PrivetConfig::default_with_name("resume-recv".into());
    recv_config.transport.listen_port = port;
    recv_config.download_dir = recv_dir.clone();
    recv_config.security_mode = privet_core::SecurityMode::AllowAll;
    recv_config.security.cert_dir = Some(cert_dir.clone());
    let recv_engine = privet_core::PrivetEngine::new(recv_config)
        .await
        .expect("recv engine");
    recv_engine.start().await.expect("recv start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    {
        let mut send_config = PrivetConfig::default_with_name("resume-send".into());
        send_config.transport.listen_port = 0;
        send_config.security_mode = privet_core::SecurityMode::AllowAll;
        send_config.security.cert_dir = Some(cert_dir);
        let engine = privet_core::PrivetEngine::new(send_config)
            .await
            .expect("send engine");
        send_files(&engine, addr, vec![file_path])
            .await
            .expect("send with resume");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    recv_engine.shutdown().await.expect("shutdown");

    // Verify: complete file with correct hash
    assert!(partial_path.exists(), "resume file missing");
    let actual_size = std::fs::metadata(&partial_path).unwrap().len();
    assert_eq!(
        file_size as u64, actual_size,
        "size mismatch after resume: expected {file_size}, got {actual_size}"
    );
    let actual_hash = sha256_file(&partial_path);
    assert_eq!(
        source_hash, actual_hash,
        "hash mismatch after resume\n  src: {source_hash}\n  got: {actual_hash}"
    );
    eprintln!("[resume] PASS — partial file resumed correctly");
}

// ---------------------------------------------------------------------------
// Transfer log test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_transfer_log_created() {
    // Verify that a transfer log record is created on successful send.
    privet_core::init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let log_dir = temp_dir.path().join("logs");
    let send_dir = temp_dir.path().join("send");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&send_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();

    let port = pick_port();
    let (file_path, _) = generate_test_file(&send_dir, "log_test.bin", 4096);

    let cert_dir = temp_dir.path().join("certs");
    // Receiver
    let mut rc = PrivetConfig::default_with_name("log-recv".into());
    rc.transport.listen_port = port;
    rc.download_dir = recv_dir.clone();
    rc.security_mode = privet_core::SecurityMode::AllowAll;
    rc.security.cert_dir = Some(cert_dir.clone());
    rc.log_dir = Some(log_dir.clone());
    let recv_engine = privet_core::PrivetEngine::new(rc).await.expect("recv");
    recv_engine.start().await.expect("recv start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Sender
    let mut sc = PrivetConfig::default_with_name("log-send".into());
    sc.transport.listen_port = 0;
    sc.security_mode = privet_core::SecurityMode::AllowAll;
    sc.security.cert_dir = Some(cert_dir);
    sc.log_dir = Some(log_dir.clone());
    let send_engine = privet_core::PrivetEngine::new(sc).await.expect("send");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    send_files(&send_engine, addr, vec![file_path])
        .await
        .expect("send");

    tokio::time::sleep(Duration::from_millis(200)).await;
    recv_engine.shutdown().await.expect("shutdown");

    // Check that a log file was created and contains at least one record
    let log_file = log_dir.join("transfers.jsonl");
    assert!(log_file.exists(), "transfer log file should exist");
    let contents = std::fs::read_to_string(&log_file).expect("read log");
    assert!(!contents.is_empty(), "transfer log should not be empty");
    // Parse the first record to verify it's valid JSON
    let record: serde_json::Value = contents
        .lines()
        .next()
        .map(|l| serde_json::from_str(l).expect("valid JSON"))
        .expect("at least one log record");
    assert_eq!(
        record["state"], "Completed",
        "log record should mark transfer as Completed"
    );
    eprintln!("[transfer-log] PASS — log file created with valid record");
}

// ---------------------------------------------------------------------------
// TCP fallback test — connected to engine TCP listener via raw TCP+TLS
// Works on Linux, may hang on Windows due to socket2 SO_REUSEADDR interaction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_tcp_fallback_engine() {
    privet_core::init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let send_dir = temp_dir.path().join("send");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&send_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();

    let port = pick_port();
    let file_name = "tcp_fallback_test.bin";
    let file_size = 4096;
    let (file_path, source_hash) = generate_test_file(&send_dir, file_name, file_size);
    let cert_dir = temp_dir.path().join("certs");
    std::fs::create_dir_all(&cert_dir).unwrap();

    // Receiver with TCP fallback
    let mut rc = PrivetConfig::default_with_name("tcp-engine-recv".into());
    rc.transport.listen_port = port;
    rc.transport.enable_tcp_fallback = true;
    rc.download_dir = recv_dir.clone();
    rc.security_mode = privet_core::SecurityMode::AllowAll;
    rc.security.cert_dir = Some(cert_dir.join("recv"));
    rc.log_dir = Some(temp_dir.path().join("logs").join("recv"));
    let recv = privet_core::PrivetEngine::new(rc).await.expect("recv engine");
    recv.start().await.expect("recv start");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Sender with force_tcp_fallback
    let mut sc = PrivetConfig::default_with_name("tcp-engine-send".into());
    sc.transport.listen_port = 0;
    sc.transport.enable_tcp_fallback = true;
    sc.transport.force_tcp_fallback = true;
    sc.security_mode = privet_core::SecurityMode::AllowAll;
    sc.security.cert_dir = Some(cert_dir.join("send"));
    sc.log_dir = Some(temp_dir.path().join("logs").join("send"));
    let send = privet_core::PrivetEngine::new(sc).await.expect("send engine");

    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    send_files(&send, addr, vec![file_path])
        .await
        .expect("TCP fallback send");

    recv.shutdown().await.expect("recv shutdown");

    let received_path = recv_dir.join(file_name);
    assert!(received_path.exists(), "TCP fallback file missing");
    let actual_hash = sha256_file(&received_path);
    assert_eq!(source_hash, actual_hash, "TCP fallback hash mismatch");
    eprintln!("[tcp-fallback-engine] PASS");
}

/// Generate multiple files, send them in a single transfer, and verify they all arrived.
async fn run_multifile_transfer(sizes: &[usize]) {
    privet_core::init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let send_dir = temp_dir.path().join("send");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&send_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();

    let port = pick_port();

    // Generate all files and record their expected hashes
    let mut file_paths = Vec::new();
    let mut expected: Vec<(String, u64, String)> = Vec::new(); // (name, size, hash)
    for (i, &size) in sizes.iter().enumerate() {
        let name = format!("multi_{i}_{size}.bin");
        let (path, hash) = generate_test_file(&send_dir, &name, size);
        eprintln!("[multi] generated {name} ({size}B) hash={hash}");
        file_paths.push(path);
        expected.push((name, size as u64, hash));
    }

    // Start receiver
    eprintln!("[multi] starting receiver on port {port}...");
    let cert_dir = temp_dir.path().join("certs");
    let recv_handle = {
        let mut config = PrivetConfig::default_with_name("multi-recv".into());
        config.transport.listen_port = port;
        config.download_dir = recv_dir.clone();
        config.security_mode = privet_core::SecurityMode::AllowAll;
        config.security.cert_dir = Some(cert_dir.clone());
        let engine = privet_core::PrivetEngine::new(config)
            .await
            .expect("recv engine");
        engine.start().await.expect("recv start");
        engine
    };

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send all files at once
    eprintln!("[multi] sending {} file(s)...", file_paths.len());
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    {
        let mut config = PrivetConfig::default_with_name("multi-send".into());
        config.transport.listen_port = 0;
        config.security_mode = privet_core::SecurityMode::AllowAll;
        config.security.cert_dir = Some(cert_dir);
        let engine = privet_core::PrivetEngine::new(config)
            .await
            .expect("send engine");
        send_files(&engine, addr, file_paths)
            .await
            .expect("multi-file send");
        eprintln!("[multi] send complete");
    }

    // Shutdown
    tokio::time::sleep(Duration::from_millis(300)).await;
    recv_handle.shutdown().await.expect("recv shutdown");
    eprintln!("[multi] receiver stopped");

    // Verify each file
    for (name, expected_size, expected_hash) in &expected {
        let received_path = recv_dir.join(name);
        assert!(
            received_path.exists(),
            "file missing: {}",
            received_path.display()
        );
        let actual_size = std::fs::metadata(&received_path).unwrap().len();
        assert_eq!(
            *expected_size, actual_size,
            "size mismatch for {name}: expected {expected_size}, got {actual_size}"
        );
        let actual_hash = sha256_file(&received_path);
        assert_eq!(
            *expected_hash, actual_hash,
            "hash mismatch for {name}\n  src: {expected_hash}\n  got: {actual_hash}"
        );
        eprintln!("[multi] verified {name} OK");
    }

    eprintln!("[multi] PASS — {} file(s) verified", expected.len());
}

/// Drain events until we find a PairRequest and return its code.
async fn collect_pair_code(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<privet_core::PrivetEvent>,
    timeout: Duration,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(privet_core::PrivetEvent::PairRequest { code, .. }) => return Some(code),
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    None
}

/// Drain events until we find an AwaitingPairing and return its code.
async fn collect_awaiting_pairing_code(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<privet_core::PrivetEvent>,
    timeout: Duration,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(privet_core::PrivetEvent::AwaitingPairing { code, .. }) => return Some(code),
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Directory transfer tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_directory_nested_structure() {
    // Send a directory with nested files and subdirectories.
    // Verify the full tree is recreated on the receiver.
    privet_core::init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let send_dir = temp_dir.path().join("send");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&send_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();

    let port = pick_port();

    // Create directory tree:
    // mydir/
    //   readme.txt (512B)
    //   src/
    //     main.rs (1KB)
    //     lib.rs (2KB)
    //   docs/
    //     guide.md (768B)
    //   empty_dir/  (empty, should be preserved)
    let (_dir_path, files) = generate_dir_tree(&send_dir, "mydir", &[
        ("readme.txt", 512),
        ("src/main.rs", 1024),
        ("src/lib.rs", 2048),
        ("docs/guide.md", 768),
        ("empty_dir/", 0),
    ]);
    eprintln!("[dir-nested] generated {} files in mydir/", files.len());

    let cert_dir = temp_dir.path().join("certs");
    // Start receiver
    let mut recv_config = PrivetConfig::default_with_name("dir-recv".into());
    recv_config.transport.listen_port = port;
    recv_config.download_dir = recv_dir.clone();
    recv_config.security_mode = privet_core::SecurityMode::AllowAll;
    recv_config.security.cert_dir = Some(cert_dir.clone());
    let recv_engine = privet_core::PrivetEngine::new(recv_config)
        .await
        .expect("recv engine");
    recv_engine.start().await.expect("recv start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send the entire directory (separate sender engine)
    let dir_path = send_dir.join("mydir");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    {
        let mut send_config = PrivetConfig::default_with_name("dir-send".into());
        send_config.transport.listen_port = 0;
        send_config.security_mode = privet_core::SecurityMode::AllowAll;
        send_config.security.cert_dir = Some(cert_dir);
        let send_engine = privet_core::PrivetEngine::new(send_config)
            .await
            .expect("send engine");
        send_files(&send_engine, addr, vec![dir_path])
            .await
            .expect("directory send");
        eprintln!("[dir-nested] send complete");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    recv_engine.shutdown().await.expect("shutdown");

    // Verify each file arrived with correct path under recv_dir/mydir/
    for (rel_path, (_src_path, src_hash, _size)) in &files {
        let received_path = recv_dir.join("mydir").join(rel_path);
        assert!(
            received_path.exists(),
            "file missing: {}",
            received_path.display()
        );
        let actual_hash = sha256_file(&received_path);
        assert_eq!(
            *src_hash, actual_hash,
            "hash mismatch for {}: src={} got={}",
            rel_path, src_hash, actual_hash
        );
        eprintln!("[dir-nested] verified {rel_path} OK");
    }

    // Verify empty directory is preserved
    let empty_dir = recv_dir.join("mydir").join("empty_dir");
    assert!(empty_dir.exists(), "empty directory should exist");
    assert!(empty_dir.is_dir(), "empty_dir should be a directory");
    eprintln!("[dir-nested] verified empty_dir/ OK");

    eprintln!("[dir-nested] PASS — {} files + 1 empty dir verified", files.len());
}

#[tokio::test]
async fn e2e_directory_mixed_with_files() {
    // Send a mix of individual files AND a directory.
    privet_core::init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let send_dir = temp_dir.path().join("send");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&send_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();

    let port = pick_port();

    // Create individual root-level files
    let (root_txt, root_txt_hash) = generate_test_file(&send_dir, "root.txt", 256);
    let (root_bin, root_bin_hash) = generate_test_file(&send_dir, "data.bin", 512);

    // Create a subdirectory with files
    let (_dir_path, sub_files) = generate_dir_tree(&send_dir, "subdir", &[
        ("inner.txt", 128),
        ("deep/nested.md", 256),
    ]);
    let subdir_path = send_dir.join("subdir");

    eprintln!("[dir-mixed] generated files");

    let cert_dir = temp_dir.path().join("certs");
    // Start receiver
    let mut recv_config = PrivetConfig::default_with_name("mixed-recv".into());
    recv_config.transport.listen_port = port;
    recv_config.download_dir = recv_dir.clone();
    recv_config.security_mode = privet_core::SecurityMode::AllowAll;
    recv_config.security.cert_dir = Some(cert_dir.clone());
    let recv_engine = privet_core::PrivetEngine::new(recv_config)
        .await
        .expect("recv engine");
    recv_engine.start().await.expect("recv start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send root files + directory together (separate sender engine)
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    {
        let mut send_config = PrivetConfig::default_with_name("mixed-send".into());
        send_config.transport.listen_port = 0;
        send_config.security_mode = privet_core::SecurityMode::AllowAll;
        send_config.security.cert_dir = Some(cert_dir);
        let send_engine = privet_core::PrivetEngine::new(send_config)
            .await
            .expect("send engine");
        send_files(&send_engine, addr, vec![root_txt, root_bin, subdir_path])
            .await
            .expect("mixed send");
        eprintln!("[dir-mixed] send complete");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    recv_engine.shutdown().await.expect("shutdown");

    // Verify root files
    let recv_root_txt = recv_dir.join("root.txt");
    assert!(recv_root_txt.exists(), "root.txt missing");
    assert_eq!(sha256_file(&recv_root_txt), root_txt_hash, "root.txt hash");
    eprintln!("[dir-mixed] verified root.txt OK");

    let recv_root_bin = recv_dir.join("data.bin");
    assert!(recv_root_bin.exists(), "data.bin missing");
    assert_eq!(sha256_file(&recv_root_bin), root_bin_hash, "data.bin hash");
    eprintln!("[dir-mixed] verified data.bin OK");

    // Verify subdirectory files
    for (rel_path, (_src_path, src_hash, _size)) in &sub_files {
        let received_path = recv_dir.join("subdir").join(rel_path);
        assert!(
            received_path.exists(),
            "subdir file missing: {}",
            received_path.display()
        );
        assert_eq!(
            &sha256_file(&received_path),
            src_hash,
            "hash mismatch for subdir/{}",
            rel_path
        );
        eprintln!("[dir-mixed] verified subdir/{rel_path} OK");
    }

    eprintln!("[dir-mixed] PASS — root files + subdir verified");
}

#[tokio::test]
async fn e2e_directory_empty_dir_marker() {
    // Send a directory that contains ONLY empty subdirectories (no files).
    privet_core::init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let send_dir = temp_dir.path().join("send");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&send_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();

    let port = pick_port();

    // Create empty directory
    let empty_dir = send_dir.join("empties");
    std::fs::create_dir_all(&empty_dir.join("a")).unwrap();
    std::fs::create_dir_all(&empty_dir.join("b").join("c")).unwrap();

    let cert_dir = temp_dir.path().join("certs");
    // Start receiver
    let mut recv_config = PrivetConfig::default_with_name("empty-recv".into());
    recv_config.transport.listen_port = port;
    recv_config.download_dir = recv_dir.clone();
    recv_config.security_mode = privet_core::SecurityMode::AllowAll;
    recv_config.security.cert_dir = Some(cert_dir.clone());
    let recv_engine = privet_core::PrivetEngine::new(recv_config).await.expect("recv");
    recv_engine.start().await.expect("recv start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    {
        let mut send_config = PrivetConfig::default_with_name("empty-send".into());
        send_config.transport.listen_port = 0;
        send_config.security_mode = privet_core::SecurityMode::AllowAll;
        send_config.security.cert_dir = Some(cert_dir);
        let send_engine = privet_core::PrivetEngine::new(send_config).await.expect("send");
        send_files(&send_engine, addr, vec![empty_dir])
            .await
            .expect("empty dir send");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    recv_engine.shutdown().await.expect("shutdown");

    // Verify empty directories were created
    assert!(recv_dir.join("empties").exists(), "empties/ should exist");
    assert!(recv_dir.join("empties").is_dir(), "empties/ should be a dir");
    assert!(recv_dir.join("empties").join("a").exists(), "empties/a/ should exist");
    assert!(recv_dir.join("empties").join("a").is_dir(), "empties/a/ should be a dir");
    assert!(recv_dir.join("empties").join("b").exists(), "empties/b/ should exist");
    assert!(recv_dir.join("empties").join("b").join("c").exists(), "empties/b/c/ should exist");
    eprintln!("[dir-empty] PASS — empty directories recreated");
}

// --- Core transfer helper ---

async fn run_transfer(file_size: usize) {
    privet_core::init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let send_dir = temp_dir.path().join("send");
    let recv_dir = temp_dir.path().join("recv");
    std::fs::create_dir_all(&send_dir).unwrap();
    std::fs::create_dir_all(&recv_dir).unwrap();

    let port = pick_port();
    let file_name = format!("test_{file_size}.bin");

    eprintln!("[{file_size}B] port={port} generating file...");
    let (file_path, source_hash) = generate_test_file(&send_dir, &file_name, file_size);

    // Start receiver
    eprintln!("[{file_size}B] starting receiver...");
    let cert_dir = temp_dir.path().join("certs");
    let recv_handle = {
        let mut config = PrivetConfig::default_with_name("test-recv".into());
        config.transport.listen_port = port;
        config.download_dir = recv_dir.clone();
        config.security_mode = privet_core::SecurityMode::AllowAll;
        config.security.cert_dir = Some(cert_dir.clone());
        let engine = privet_core::PrivetEngine::new(config).await.expect("receiver engine");
        engine.start().await.expect("receiver start");
        engine
    };

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send
    eprintln!("[{file_size}B] sending...");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    {
        let mut config = PrivetConfig::default_with_name("test-sender".into());
        config.transport.listen_port = 0;
        config.security_mode = privet_core::SecurityMode::AllowAll;
        config.security.cert_dir = Some(cert_dir);
        let engine = privet_core::PrivetEngine::new(config).await.expect("sender engine");
        send_files(&engine, addr, vec![file_path])
            .await
            .expect("send files");
        eprintln!("[{file_size}B] send complete");
    }

    // Shutdown
    eprintln!("[{file_size}B] shutting down receiver...");
    recv_handle.shutdown().await.expect("shutdown");
    eprintln!("[{file_size}B] receiver stopped");

    // Verify
    let received_path = recv_dir.join(&file_name);
    assert!(received_path.exists(), "file missing: {}", received_path.display());

    let expected_size = file_size as u64;
    let actual_size = std::fs::metadata(&received_path).unwrap().len();
    assert_eq!(expected_size, actual_size, "size mismatch");

    let received_hash = sha256_file(&received_path);
    assert_eq!(source_hash, received_hash, "hash mismatch\n  src: {source_hash}\n  got: {received_hash}");

    eprintln!("[{file_size}B] PASS");
}
