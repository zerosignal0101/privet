//! WP-R12: an interrupted send must be resumable even when its recorded source
//! paths are gone.
//!
//! The reported bug: on Android every picked file is a `content://` document, so
//! the send flow stages a copy into the app cache and hands the daemon *that*
//! copy. The staging copy is deleted when the transfer reaches a terminal state
//! (failure and cancellation included), but the engine records the send's
//! absolute paths in `StoredSendIntent.paths` and marks the interrupted send
//! `status = "partial"`. Resuming rebuilt the file list from those recorded
//! paths, so `prepare_paths` hit `std::fs::metadata` on a deleted file and the
//! whole resume died as a bare `CoreError::Io`.
//!
//! These tests pin both directions: a resume that supplies fresh sources for the
//! same file set succeeds under the *same* transfer id, and a structurally
//! mismatching override is refused without touching anything.

use std::time::Duration;
use tempfile::TempDir;

use privet_core::ops::{PeerTarget, ServeOptions};
use privet_core::{Engine, EngineConfig, EngineEvent};
use privet_transfer::CollisionPolicy;
use privet_transport::TransportMode;

/// Big enough that the transfer is still mid-flight when the cancel lands.
const BIG_BYTES: usize = 64 * 1024 * 1024;
/// Payload for the multi-file cases, where only the file set matters. Still
/// large enough that the two-file send is mid-flight when the cancel lands.
const SMALL_BYTES: usize = 64 * 1024 * 1024;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
}

fn engine(dir: &TempDir, name: &str) -> Engine {
    let mut cfg = EngineConfig {
        device_name: name.into(),
        db_path: dir.path().join(format!("{name}.db")),
        save_dir: dir.path().join(name),
        identity_path: Some(dir.path().join(format!("{name}.bin"))),
        ..Default::default()
    };
    cfg.transport.mode = TransportMode::Quic;
    // Ephemeral ports: tests in this binary run concurrently and a dev privetd
    // may already hold the fixed defaults.
    cfg.discovery.udp_port = 0;
    cfg.transport.quic_port = 0;
    cfg.transport.tcp_port = 0;
    std::fs::create_dir_all(cfg.save_dir.as_path()).ok();
    Engine::new(cfg)
}

/// Pair the receiver with the sender's identity so an auto-accept receiver takes
/// the transfer without prompting.
fn pair_receiver(dir: &TempDir, sender: &Engine) {
    let spki = sender.identity().spki_der().to_vec();
    let fp = sender.identity().fingerprint();
    let conn = privet_storage::migration::open_and_migrate(dir.path().join("recv.db")).unwrap();
    privet_storage::trust::insert_paired(
        &conn,
        &privet_storage::trust::PeerTrust {
            device_fingerprint: &fp,
            peer_spki: &spki,
            peer_device_name: "alice",
            share_with_peers: false,
            first_paired_ts: 100,
            last_seen_ts: 100,
        },
        &privet_storage::trust::PeerAddress {
            subnet_cidr: "127.0.0.0/8",
            gateway_ip: None,
            addr: "127.0.0.1",
            quic_port: 0,
            tcp_port: 0,
            source: "self",
            last_seen_ts: 100,
        },
    )
    .unwrap();
}

struct Harness {
    dir: TempDir,
    sender: std::sync::Arc<Engine>,
    receiver: Engine,
    serve: privet_core::ops::ServeHandle,
    save: std::path::PathBuf,
}

impl Harness {
    /// Two real engines, a real QUIC serve, and the receiver paired.
    async fn start() -> Harness {
        let dir = TempDir::new().unwrap();
        let sender = std::sync::Arc::new(engine(&dir, "send"));
        let mut receiver = engine(&dir, "recv");
        pair_receiver(&dir, &sender);

        receiver.start().await.unwrap();
        let save = dir.path().join("recv");
        std::fs::create_dir_all(save.join(".privet")).ok();
        let serve = receiver
            .serve(ServeOptions {
                save_dir: save.clone(),
                accept_all_trusted: true,
                on_collision: CollisionPolicy::Rename,
                accept_policy: privet_core::AcceptPolicy::AutoAccept,
            })
            .await
            .unwrap();

        Harness {
            dir,
            sender,
            receiver,
            serve,
            save,
        }
    }

    fn target_addr(&self) -> std::net::SocketAddr {
        let mut addr = self.serve.quic_addr;
        addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        addr
    }

    async fn shutdown(self) {
        self.serve.shutdown().await;
        let _ = self.receiver.shutdown().await;
    }
}

/// Send [src] under [tid], wait until bytes are actually flowing, then cancel on
/// the RECEIVER — the reported scenario. Returns the receiver-cancelled send's
/// outcome, which the engine treats as a success that stays `partial`.
///
/// The wait for progress gates on the first progress event so the cancel cannot
/// race ahead of the data.
async fn send_then_cancel_midflight(h: &Harness, sources: Vec<std::path::PathBuf>, tid: &str) {
    let mut events = h.sender.subscribe();
    let send_engine = h.sender.clone();
    let target_addr = h.target_addr();
    let tid_owned = tid.to_string();
    let task = tokio::spawn(async move {
        send_engine
            .send_with_id(
                sources,
                &PeerTarget::ByAddr(target_addr),
                None,
                None,
                tid_owned,
            )
            .await
    });

    let mut reached_flight = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        let ev = match tokio::time::timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Ok(ev)) => ev,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Err(_) => continue,
        };
        if let EngineEvent::TransferProgress { transfer_id, .. } = ev {
            if transfer_id == tid {
                reached_flight = true;
                break;
            }
        }
    }
    assert!(
        reached_flight,
        "transfer should reach mid-flight before cancel"
    );

    h.receiver.cancel_transfer(tid).await.unwrap();

    // A cancellation is not a failure: the send task resolves Ok, and the send
    // is recorded as `partial` (resumable).
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("send task timeout")
        .expect("send task join failed")
        .expect("cancelled send must not surface as an error");

    assert_eq!(
        h.sender
            .history(None, 10)
            .unwrap()
            .iter()
            .find(|r| r.direction == "send" && r.transfer_id == tid)
            .expect("sender recorded the send")
            .status,
        "partial",
        "an interrupted send must be recorded as partial, so it can be resumed"
    );
}

#[tokio::test]
async fn resume_without_override_after_source_gone_fails_with_bare_io() {
    // THE REPRODUCTION of the reported bug, kept as a permanent test so the
    // no-override contract cannot be broken silently.
    //
    // The recorded paths are gone (this is what the app's send-cache cleanup
    // does to a staging copy), so the only behaviour available to a resume that
    // supplies no override is the bare `io` error the user saw.
    init_tracing();
    let h = Harness::start().await;
    let src = h.dir.path().join("big.bin");
    std::fs::write(&src, vec![7u8; BIG_BYTES]).unwrap();

    let tid = "t-repro-io";
    send_then_cancel_midflight(&h, vec![src.clone()], tid).await;

    // The staging copy is cleaned up on a terminal state — failure and
    // cancellation included — while the history row keeps pointing at it.
    std::fs::remove_file(&src).unwrap();
    assert!(!src.exists());

    let err = match h.sender.resume_send(tid).await {
        Ok(_) => panic!("a resume whose recorded paths are gone must not succeed"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        matches!(err, privet_core::CoreError::Io(_)),
        "expected a bare Io error, got: {msg}"
    );
    // This is the exact code the daemon publishes on TransferFailed and the app
    // renders as "Transfer Failed io".
    assert_eq!(
        err.error_code(),
        "io",
        "the reported symptom is the bare `io` error code"
    );
    assert_eq!(
        msg, "io: No such file or directory (os error 2)",
        "the reported symptom is a bare `io` error naming no file: {msg}"
    );

    h.shutdown().await;
}

/// Collects `verified_bytes` for [tid] from [events] until the transfer reports
/// a terminal state.
///
/// The first progress value on a resume is the sender's *baseline*: chunks the
/// receiver already verified and is therefore skipping. The increases after it
/// are the chunks that actually crossed the wire this time, so the sum of the
/// increases is the number of bytes the resume really sent — which is what makes
/// "less than the whole file" a checkable claim rather than an assumption.
async fn collect_progress_until_terminal(
    events: &mut tokio::sync::broadcast::Receiver<EngineEvent>,
    tid: &str,
) -> Vec<u64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut out = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let ev = match tokio::time::timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Ok(ev)) => ev,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Err(_) => continue,
        };
        match ev {
            EngineEvent::TransferProgress {
                transfer_id,
                verified_bytes,
                ..
            } if transfer_id == tid => {
                out.push(verified_bytes);
            }
            EngineEvent::TransferCompleted { transfer_id } if transfer_id == tid => break,
            EngineEvent::TransferFailed {
                transfer_id,
                error_code,
                ..
            } if transfer_id == tid => {
                panic!("resumed transfer failed during the test: {error_code}");
            }
            _ => {}
        }
    }
    out
}

/// Brings a harness to the exact reported state: a send interrupted mid-flight,
/// whose recorded source path is gone. Returns the transfer id and the original
/// relative name.
async fn interrupted_send(
    h: &Harness,
    tid: &str,
    files: &[(&str, usize)],
) -> Vec<std::path::PathBuf> {
    let sources: Vec<std::path::PathBuf> = files
        .iter()
        .map(|(name, size)| {
            let p = h.dir.path().join(name);
            std::fs::write(&p, vec![7u8; *size]).unwrap();
            p
        })
        .collect();
    send_then_cancel_midflight(h, sources.clone(), tid).await;
    // The send cache deletes the staging copy on a terminal state (cancellation
    // included) while the history row keeps pointing at it.
    for p in &sources {
        std::fs::remove_file(p).unwrap();
        assert!(!p.exists(), "the recorded source must be gone");
    }
    sources
}

/// The end-to-end proof for the reported bug.
///
/// A real two-daemon run: interrupt a send mid-flight, delete the source (what
/// the app's send cache does to a staging copy), re-stage it from the original
/// reference, and resume. The resumed transfer must be the **same transfer id**
/// (the receiver's partial state is reused, not restarted), must complete, and
/// must deliver bytes equal to the original.
#[tokio::test]
async fn resume_with_override_completes_same_transfer_from_fresh_source() {
    init_tracing();
    let h = Harness::start().await;
    let payload = vec![7u8; BIG_BYTES];
    let src = h.dir.path().join("big.bin");
    std::fs::write(&src, &payload).unwrap();

    let tid = "t-resume-override";
    send_then_cancel_midflight(&h, vec![src.clone()], tid).await;

    // The staging copy is cleaned up on a terminal state; the history row still
    // points at it. Re-staging from the original reference produces a NEW path
    // with the SAME relative name and the SAME content — which is exactly what
    // the app's ResendStager hands the engine.
    std::fs::remove_file(&src).unwrap();
    let restaged_dir = h.dir.path().join("restage");
    std::fs::create_dir_all(&restaged_dir).unwrap();
    let restaged = restaged_dir.join("big.bin");
    std::fs::write(&restaged, &payload).unwrap();
    assert_ne!(restaged, src, "the override must be a different path");

    let mut events = h.sender.subscribe();
    let outcome = tokio::time::timeout(
        Duration::from_secs(90),
        h.sender
            .resume_send_with_paths(tid, Some(vec![restaged.clone()])),
    )
    .await
    .expect("resume timeout")
    .expect("a matching override must let the resume succeed");
    let progress = collect_progress_until_terminal(&mut events, tid).await;

    // The same transfer id: the receiver kept its partial state instead of the
    // transfer being restarted from scratch under a new id.
    assert_eq!(
        outcome.transfer_id, tid,
        "the resume must reuse the same transfer id"
    );
    assert_eq!(outcome.file_count, 1);
    assert_eq!(outcome.total_bytes, BIG_BYTES as u64);

    // Non-vacuous "less than the whole file crossed the wire": the resume opened
    // with a non-zero baseline (chunks the receiver already had) and the bytes
    // newly verified during it are fewer than the whole file.
    let baseline = progress
        .first()
        .copied()
        .expect("a resumed transfer must report progress");
    let newly_sent: u64 = progress
        .iter()
        .zip(progress.iter().skip(1))
        .map(|(a, b)| b.saturating_sub(*a))
        .sum();
    assert!(
        baseline > 0,
        "the resume must start from a non-zero baseline, proving the receiver's \
         already-verified chunks were skipped (progress={progress:?})"
    );
    assert!(
        newly_sent < BIG_BYTES as u64,
        "the resume must send less than the whole file: baseline={baseline} \
         newly_sent={newly_sent} total={} (progress={progress:?})",
        BIG_BYTES
    );
    println!(
        "RESUME-SIGNAL transfer_id={tid} total_bytes={} baseline_bytes={baseline} \
         newly_sent_bytes={newly_sent} progress_events={} progress={progress:?}",
        BIG_BYTES,
        progress.len()
    );
    assert_eq!(
        progress.last().copied(),
        Some(BIG_BYTES as u64),
        "the resumed transfer must verify every byte in the end"
    );

    // Content equality on the received bytes.
    let landed = h.save.join("big.bin");
    let received = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if landed.exists() {
                break std::fs::read(&landed).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("landed-file timeout");
    assert_eq!(
        received.len(),
        payload.len(),
        "the resumed transfer must deliver every byte"
    );
    assert!(
        received == payload,
        "the received bytes must equal the original file's bytes"
    );

    // And the history row is upgraded to completed on the same id.
    let row = h
        .sender
        .history(None, 20)
        .unwrap()
        .into_iter()
        .find(|r| r.direction == "send" && r.transfer_id == tid)
        .expect("sender recorded the send");
    assert_eq!(row.status, "completed");

    h.shutdown().await;
}

/// A structurally mismatching override must be refused, and the refusal must
/// name the file that disagrees.
///
/// Each case gets a fresh interrupted transfer, because a refusal must leave the
/// transfer exactly as it was — the receiver is still holding a partial file
/// under this id and a rejected resume must not disturb it.
#[tokio::test]
async fn structurally_mismatching_override_is_refused_and_changes_nothing() {
    init_tracing();
    let h = Harness::start().await;

    // --- an EXTRA file the send never recorded ---
    let tid_extra = "t-mismatch-extra";
    interrupted_send(&h, tid_extra, &[("big.bin", BIG_BYTES)]).await;
    let restage = h.dir.path().join("restage");
    std::fs::create_dir_all(&restage).unwrap();
    let good = restage.join("big.bin");
    std::fs::write(&good, vec![7u8; BIG_BYTES]).unwrap();
    let intruder = restage.join("extra.bin");
    std::fs::write(&intruder, vec![1u8; 16]).unwrap();
    let before_extra = receiver_state(&h);
    let err = refusal(&h, tid_extra, vec![good.clone(), intruder.clone()]).await;
    assert!(
        err.contains("extra.bin"),
        "the refusal must name the disagreeing file, got: {err}"
    );
    assert_eq!(
        receiver_state(&h),
        before_extra,
        "a refused resume must not change what the receiver holds"
    );
    assert_still_partial(&h, tid_extra).await;

    // --- a DIFFERENT SIZE for a recorded file ---
    let tid_size = "t-mismatch-size";
    interrupted_send(&h, tid_size, &[("big2.bin", BIG_BYTES)]).await;
    let wrong = restage.join("big2.bin");
    std::fs::write(&wrong, vec![7u8; BIG_BYTES - 1]).unwrap();
    let before_size = receiver_state(&h);
    let err = refusal(&h, tid_size, vec![wrong.clone()]).await;
    assert!(
        err.contains("big2.bin") && err.contains("bytes"),
        "the refusal must name the file and the size disagreement, got: {err}"
    );
    assert_eq!(receiver_state(&h), before_size);
    assert_still_partial(&h, tid_size).await;

    // --- a SUBSET: a recorded file the override does not cover ---
    //
    // This needs a two-file send, because an *empty* override is "no override"
    // and falls back to the recorded paths. Resuming half of a send would drop
    // the other half's chunks from a transfer the receiver is already filling.
    let tid_missing = "t-mismatch-missing";
    interrupted_send(
        &h,
        tid_missing,
        &[("partA.bin", SMALL_BYTES), ("partB.bin", SMALL_BYTES)],
    )
    .await;
    let only_a = restage.join("partA.bin");
    std::fs::write(&only_a, vec![7u8; SMALL_BYTES]).unwrap();
    let before_missing = receiver_state(&h);
    let err = refusal(&h, tid_missing, vec![only_a.clone()]).await;
    assert!(
        err.contains("partB.bin") && err.contains("missing"),
        "the refusal must name the missing recorded file, got: {err}"
    );
    assert_eq!(receiver_state(&h), before_missing);
    assert_still_partial(&h, tid_missing).await;

    // --- the matching override for that same two-file send IS accepted ---
    // Proves the refusal above was about the structural mismatch, not about
    // multi-file resumes being impossible.
    std::fs::write(&restage.join("partB.bin"), vec![7u8; SMALL_BYTES]).unwrap();
    let outcome = tokio::time::timeout(
        Duration::from_secs(90),
        h.sender.resume_send_with_paths(
            tid_missing,
            Some(vec![only_a.clone(), restage.join("partB.bin")]),
        ),
    )
    .await
    .expect("resume timeout")
    .expect("the matching two-file override must be accepted");
    assert_eq!(outcome.transfer_id, tid_missing);
    assert_eq!(outcome.file_count, 2);

    h.shutdown().await;
}

/// Everything the receiver currently holds, so a refusal can be shown to change
/// nothing.
fn receiver_state(h: &Harness) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![h.save.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push((
                    p.to_string_lossy().to_string(),
                    entry.metadata().map(|m| m.len()).unwrap_or(0),
                ));
            }
        }
    }
    out.sort();
    out
}

/// Resume with [paths] and return the refusal message, failing the test if the
/// resume is accepted.
async fn refusal(h: &Harness, tid: &str, paths: Vec<std::path::PathBuf>) -> String {
    match h.sender.resume_send_with_paths(tid, Some(paths)).await {
        Ok(outcome) => panic!(
            "a mismatching override must be refused, but the resume was accepted \
             (transfer_id={})",
            outcome.transfer_id
        ),
        Err(e) => e.to_string(),
    }
}

/// After a refusal the transfer must still be exactly as resumable as it was.
async fn assert_still_partial(h: &Harness, tid: &str) {
    let row = h
        .sender
        .history(None, 50)
        .unwrap()
        .into_iter()
        .find(|r| r.transfer_id == tid)
        .expect("the transfer is still in history");
    assert_eq!(
        row.status, "partial",
        "a refused resume must leave the transfer resumable"
    );
}
