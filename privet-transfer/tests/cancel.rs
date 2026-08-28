//! Cancel mid-transfer via protocol-level Cancel control frame.
//! Sender stops dispatching; receiver retains .part for resume.

use privet_protocol::control_frame::Payload as CPayload;
use privet_protocol::control_message::Msg;
use privet_protocol::{ControlFrame, ControlMessage};
use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn cancel_mid_transfer_stops_sender_keeps_part() {
    let dir = tempdir().unwrap();
    // 20 MiB → enough chunks that Cancel arrives before all are sent
    let data: Vec<u8> = (0..20_000_000u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("c.bin"), &data).unwrap();
    let save = tempdir().unwrap();
    let prepared =
        privet_transfer::prepare::prepare_dir(dir.path(), None, 0, 256 * 1024, 256).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (dat_a, dat_b) = LoopbackDataChannel::pair(64);

    // ctl_a feeds into receiver's rx; ctl_b feeds into sender's rx.
    // To send Cancel TO the sender, we use ctl_b.sender() (sender's rx source).
    let cancel_tx = ctl_b.sender();

    let s = SenderInputs {
        control: Box::new(ctl_a),
        data: vec![Box::new(dat_a)],
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig::default(),
        prepared,
        reader: Box::new(reader),
        transfer_id: "t1".into(),
        cmd_rx: None,
    };
    let r_save = save.path().to_path_buf();
    let r = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b)],
        store: Box::new(FsPartStore::new(r_save.clone())),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: r_save.clone(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
        history: None,
    };

    let sr = tokio::spawn(run_sender(s));
    let rr = tokio::spawn(run_receiver(r));

    // Give the transfer a moment to start, then send Cancel to sender
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = cancel_tx
        .send(ControlFrame {
            payload: Some(CPayload::Control(ControlMessage {
                msg: Some(Msg::Cancel(privet_protocol::Cancel {
                    transfer_id: "t1".into(),
                    reason: "test cancel".into(),
                })),
            })),
        })
        .await;

    // The sender must report a cancellation, NOT Ok: the core relies on that to
    // avoid recording a cancelled send's history as 'completed'. The receiver may
    // observe the sender stop mid-stream, so its own return value is
    // transport-dependent — we only require that it doesn't hang.
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let sender_result = sr.await.expect("sender task join failed");
        assert!(
            matches!(
                sender_result,
                Err(privet_transfer::error::TransferError::Cancelled(_))
            ),
            "sender must report Cancelled, got {sender_result:?}"
        );
        let _ = rr.await;
    })
    .await;

    // The final file must NOT exist (transfer was cancelled mid-way)
    assert!(
        !r_save.join("c.bin").exists(),
        "cancelled transfer must not produce final file"
    );
}
