use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use privet_core::PrivetConfig;
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
    let recv_handle = {
        let mut config = PrivetConfig::default_with_name("test-recv".into());
        config.transport.listen_port = port;
        config.download_dir = recv_dir.clone();

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
        let engine = privet_core::PrivetEngine::new(config).await.expect("sender engine");
        engine
            .send_files_to_addr(addr, vec![file_path])
            .await
            .expect("send_files_to_addr");
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
