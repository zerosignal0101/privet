
use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::{InMemoryEventSink, TransferEvent};
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use privet_transfer::state::{TransferFailed, TransferState};
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn legal_transitions_succeed() {
    use TransferState::*;
    assert!(TransferState::transition(&Preparing, Offered).is_ok());
    assert!(TransferState::transition(&Offered, Scheduled).is_ok());
    assert!(TransferState::transition(&Scheduled, Transferring).is_ok());
    assert!(TransferState::transition(&Transferring, SendingDone).is_ok());
    assert!(TransferState::transition(&SendingDone, Verified { ok: true }).is_ok());
    assert!(TransferState::transition(&Verified { ok: true }, Completed).is_ok());
    assert!(TransferState::transition(&Transferring, Cancelled).is_ok());
    assert!(TransferState::transition(
        &Transferring,
        Failed(TransferFailed {
            error_code: "x",
            error_message: "".into(),
            retryable: false,
            part_kept: false,
        })
    )
    .is_ok());
}

#[test]
fn illegal_transition_returns_err() {
    use TransferState::*;
    assert!(TransferState::transition(&Completed, Transferring).is_err());
    assert!(TransferState::transition(&Completed, Offered).is_err());
    assert!(TransferState::transition(&Offered, Completed).is_err());
}

#[tokio::test]
async fn sender_emits_state_changed_events() {
    let dir = tempdir().unwrap();
    let data: Vec<u8> = (0..2_000_000u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("f.bin"), &data).unwrap();
    let save = tempdir().unwrap();
    let prepared =
        privet_transfer::prepare::prepare_dir(dir.path(), None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (dat_a, dat_b) = LoopbackDataChannel::pair(64);
    let (sink_a, mut rx_a) = InMemoryEventSink::new();
    let s = SenderInputs {
        control: Box::new(ctl_a),
        data: vec![Box::new(dat_a)],
        events: Box::new(sink_a),
        config: TransferEngineConfig::default(),
        prepared,
        reader: Box::new(reader),
        transfer_id: "t1".into(),
        cmd_rx: None,
    };
    let r = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b)],
        store: Box::new(FsPartStore::new(save.path().to_path_buf())),
        events: Box::new(privet_transfer::events::NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save.path().to_path_buf(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
        history: None,
    };
    let _sr = tokio::spawn(run_sender(s));
    let _rr = tokio::spawn(run_receiver(r));

    let mut events: Vec<TransferEvent> = Vec::new();
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_secs(5), rx_a.recv()).await {
        events.push(e);
    }

    let states: Vec<&TransferState> = events
        .iter()
        .filter_map(|e| match e {
            TransferEvent::StateChanged { state, .. } => Some(state),
            _ => None,
        })
        .collect();
    assert!(
        states.contains(&&TransferState::Transferring),
        "must emit StateChanged(Transferring): {states:?}"
    );
    assert!(
        states.contains(&&TransferState::SendingDone),
        "must emit StateChanged(SendingDone): {states:?}"
    );
    assert!(
        states.contains(&&TransferState::Completed),
        "must emit StateChanged(Completed): {states:?}"
    );
}
