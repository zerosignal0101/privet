//! 通道夹具（三态测、丢包、乱序、RTO 用）。
use privet_protocol::{
    control_frame::Payload as CPayload, data_frame::Payload as DPayload, ChunkHeader, ControlFrame,
    ControlMessage, DataFrame,
};
use privet_transfer::channel::{
    LatchControlChannel, LoopbackControlChannel, LoopbackDataChannel, LossyControlChannel,
    LossyDataChannel, ReorderDataChannel,
};
use privet_transfer::{ControlChannel, DataChannel};
use std::time::Duration;

fn ctl_cancel(id: &str) -> ControlFrame {
    ControlFrame {
        payload: Some(CPayload::Control(ControlMessage {
            msg: Some(privet_protocol::control_message::Msg::Cancel(
                privet_protocol::Cancel {
                    transfer_id: id.into(),
                    reason: "u".into(),
                },
            )),
        })),
    }
}

fn data_chunk(off: u64, len: u64) -> DataFrame {
    DataFrame {
        payload: Some(DPayload::ChunkHeader(ChunkHeader {
            file_id: "f".into(),
            segment_id: 0,
            chunk_index: off,
            offset: off * 10,
            length: len,
        })),
    }
}

#[tokio::test]
async fn control_loopback_roundtrip() {
    let (mut a, mut b) = LoopbackControlChannel::pair(16);
    a.send(ctl_cancel("t1")).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), b.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(got.payload, Some(CPayload::Control(_))));
}

#[tokio::test]
async fn data_loopback_roundtrip_with_raw() {
    let (mut a, mut b) = LoopbackDataChannel::pair(16);
    a.send(data_chunk(0, 5), Some(b"hello")).await.unwrap();
    let (f, raw) = tokio::time::timeout(Duration::from_secs(2), b.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(f.payload, Some(DPayload::ChunkHeader(_))));
    assert_eq!(raw.unwrap().as_ref(), b"hello");
}

#[tokio::test]
async fn lossy_control_drops_first_n() {
    let (mut a, b_inner) = LoopbackControlChannel::pair(16);
    let mut b = LossyControlChannel::drop_first(Box::new(b_inner), 2);
    a.send(ctl_cancel("1")).await.unwrap();
    a.send(ctl_cancel("2")).await.unwrap();
    a.send(ctl_cancel("3")).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), b.recv())
        .await
        .unwrap()
        .unwrap();
    match got.payload {
        Some(CPayload::Control(m)) => match m.msg {
            Some(privet_protocol::control_message::Msg::Cancel(c)) => {
                assert_eq!(c.transfer_id, "3")
            }
            _ => panic!(),
        },
        _ => panic!(),
    }
}

#[tokio::test]
async fn lossy_data_drops_first_n() {
    let (mut a, b_inner) = LoopbackDataChannel::pair(16);
    let mut b = LossyDataChannel::drop_first(Box::new(b_inner), 1);
    a.send(data_chunk(0, 1), Some(b"a")).await.unwrap();
    a.send(data_chunk(1, 1), Some(b"b")).await.unwrap();
    let (f, _) = tokio::time::timeout(Duration::from_secs(2), b.recv())
        .await
        .unwrap()
        .unwrap();
    match f.payload {
        Some(DPayload::ChunkHeader(h)) => assert_eq!(h.chunk_index, 1),
        _ => panic!(),
    }
}

#[tokio::test]
async fn reorder_data_emits_out_of_order() {
    let (mut a, b_inner) = LoopbackDataChannel::pair(16);
    let mut b = ReorderDataChannel::buffer_and_reverse(Box::new(b_inner), 3);
    for i in 0..3u64 {
        a.send(data_chunk(i, 1), Some(&[i as u8])).await.unwrap();
    }
    let mut idxs = Vec::new();
    for _ in 0..3 {
        let (f, _) = tokio::time::timeout(Duration::from_secs(2), b.recv())
            .await
            .unwrap()
            .unwrap();
        match f.payload {
            Some(DPayload::ChunkHeader(h)) => idxs.push(h.chunk_index),
            _ => panic!(),
        }
    }
    assert_eq!(idxs, vec![2, 1, 0]);
}

#[tokio::test]
async fn latch_control_holds_first_k_until_k_plus_1() {
    let (mut a, b_inner) = LoopbackControlChannel::pair(16);
    let mut b = LatchControlChannel::hold_first(Box::new(b_inner), 2);
    a.send(ctl_cancel("m1")).await.unwrap();
    a.send(ctl_cancel("m2")).await.unwrap();
    let blocked = tokio::time::timeout(Duration::from_millis(200), b.recv()).await;
    assert!(blocked.is_err(), "should block until latch released");
    a.send(ctl_cancel("m3")).await.unwrap();
    let mut got = Vec::new();
    for _ in 0..3 {
        got.push(
            tokio::time::timeout(Duration::from_secs(2), b.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let ids: Vec<String> = got
        .iter()
        .map(|f| match &f.payload {
            Some(CPayload::Control(m)) => match &m.msg {
                Some(privet_protocol::control_message::Msg::Cancel(c)) => c.transfer_id.clone(),
                _ => String::new(),
            },
            _ => String::new(),
        })
        .collect();
    assert_eq!(ids, vec!["m1", "m2", "m3"]);
}
