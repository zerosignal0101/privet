//! 传送编排：输入构造 + 重写包装 + recovery + 重连循环

use std::net::SocketAddr;

use privet_protocol::DataFrame;
use privet_transfer::{
    FsPartStore, ReceiverInputs, SenderInputs, StreamControlChannel, StreamDataChannel,
    TransferEngineConfig,
};
use privet_transport::{send_data, Stream, Transport, TransportMode};
use tokio::sync::broadcast;

use crate::adapters::transfer_sink::CoreTransferEventSink;
use crate::connection::{
    acquire_control, acquire_data, connect_peer, hello_exchange, ControlRole, DataRole,
};
use crate::reconnect::{reconnect_event, resumed_event, Backoff};
use crate::EngineEvent;
use privet_crypto::identity::Identity;

/// 构造 receiver 输入（受信控制流 + 数据流 + 真 PartStore + 事件桥接）。
pub fn receiver_inputs(
    control: Box<dyn Stream>,
    data: Box<dyn Stream>,
    store: FsPartStore,
    cfg: TransferEngineConfig,
    event_tx: broadcast::Sender<EngineEvent>,
    registry: Option<std::sync::Arc<privet_transfer::control::TransferRegistry>>,
    accept_policy: privet_transfer::control::AcceptPolicy,
) -> ReceiverInputs {
    ReceiverInputs {
        control: Box::new(StreamControlChannel::new(control)),
        data: vec![Box::new(StreamDataChannel::new(data))],
        store: Box::new(store),
        events: Box::new(CoreTransferEventSink::new(event_tx)),
        config: cfg,
        accept_policy,
        registry,
    }
}

/// 构造 sender 输入。
#[allow(clippy::too_many_arguments)]
pub fn sender_inputs(
    control: Box<dyn Stream>,
    data: Box<dyn Stream>,
    cfg: TransferEngineConfig,
    event_tx: broadcast::Sender<EngineEvent>,
    prepared: privet_transfer::PreparedSet,
    reader: Box<dyn privet_transfer::ChunkReader>,
    transfer_id: String,
    cmd_rx: Option<tokio::sync::mpsc::Receiver<privet_transfer::TransferCommand>>,
) -> SenderInputs {
    SenderInputs {
        control: Box::new(StreamControlChannel::new(control)),
        data: vec![Box::new(StreamDataChannel::new(data))],
        events: Box::new(CoreTransferEventSink::new(event_tx)),
        config: cfg,
        prepared,
        reader,
        transfer_id,
        cmd_rx,
    }
}

/// 受信控制流 + 数据流上发送传送（return Ok when done）。
pub async fn send_over_connection(
    control: Box<dyn Stream>,
    data: Box<dyn Stream>,
    prepared: privet_transfer::PreparedSet,
    cfg: TransferEngineConfig,
    event_tx: broadcast::Sender<EngineEvent>,
    transfer_id: String,
    cmd_rx: Option<tokio::sync::mpsc::Receiver<privet_transfer::TransferCommand>>,
) -> crate::Result<()> {
    let reader = Box::new(privet_transfer::MappedChunkReader::from_prepared(&prepared));
    let inputs = sender_inputs(
        control,
        data,
        cfg,
        event_tx,
        prepared,
        reader,
        transfer_id,
        cmd_rx,
    );
    Ok(privet_transfer::run_sender(inputs).await?)
}

/// 受信控制流 + 数据流上接收传送。
pub async fn receive_over_connection(
    control: Box<dyn Stream>,
    data: Box<dyn Stream>,
    store: FsPartStore,
    cfg: TransferEngineConfig,
    event_tx: broadcast::Sender<EngineEvent>,
    registry: Option<std::sync::Arc<privet_transfer::control::TransferRegistry>>,
    accept_policy: privet_transfer::control::AcceptPolicy,
) -> crate::Result<()> {
    let inputs = receiver_inputs(control, data, store, cfg, event_tx, registry, accept_policy);
    Ok(privet_transfer::run_receiver(inputs).await?)
}

// ===== 重连循环 =====

use crate::CoreError;
use privet_transfer::TransferError;

#[allow(clippy::too_many_arguments)]
/// 发送方重连循环：连接断 -> 退避 -> 重连 -> resume。耗尽 -> 返回 Err(TransportLost)。
/// `backoff` 可注自定义退避表（测试用短表）。
/// 在 acquire_control/acquire_data/send_data 阶段若得 TransportError 也重试。
pub async fn send_with_reconnect(
    quic: &dyn Transport,
    tcp: Option<&dyn Transport>,
    addr: SocketAddr,
    mode: TransportMode,
    local: &Identity,
    device_name: &str,
    prepared: privet_transfer::PreparedSet,
    cfg: TransferEngineConfig,
    event_tx: broadcast::Sender<EngineEvent>,
    transfer_id: String,
    backoff: &mut Backoff,
    _cmd_rx: Option<tokio::sync::mpsc::Receiver<privet_transfer::TransferCommand>>,
) -> crate::Result<()> {
    loop {
        let conn = match connect_peer(quic, tcp, addr, mode, None).await {
            Ok(c) => c,
            Err(_) => {
                if !next_backoff_or_exhausted(backoff, &transfer_id, &event_tx).await {
                    return Err(CoreError::Transfer(TransferError::TransportLost));
                }
                continue;
            }
        };
        let mut ctrl = match acquire_control(conn.as_ref(), ControlRole::Initiator).await {
            Ok(c) => c,
            Err(e) => {
                if retry_on_transport_lost(&e, backoff, &transfer_id, &event_tx).await {
                    continue;
                }
                return Err(e);
            }
        };
        // Hello 交换（重连后重建 TLS 协议状态）。
        if let Err(e) = hello_exchange(ctrl.as_mut(), local, 1, device_name).await {
            if retry_on_transport_lost(&e, backoff, &transfer_id, &event_tx).await {
                continue;
            }
            return Err(e);
        }
        let mut data = match acquire_data(conn.as_ref(), DataRole::Initiator).await {
            Ok(d) => d,
            Err(e) => {
                if retry_on_transport_lost(&e, backoff, &transfer_id, &event_tx).await {
                    continue;
                }
                return Err(e);
            }
        };
        // QUIC：写空 DataFrame 触发 STREAM frame，让对端 accept_uni 解析。
        if let Err(e) = send_data(data.as_mut(), &DataFrame { payload: None }, None).await {
            if retry_on_transport_lost(&CoreError::Transport(e), backoff, &transfer_id, &event_tx)
                .await
            {
                continue;
            }
            return Err(CoreError::Transfer(TransferError::TransportLost));
        }
        let reader = Box::new(privet_transfer::MappedChunkReader::from_prepared(&prepared));
        let inputs = sender_inputs(
            ctrl,
            data,
            cfg.clone(),
            event_tx.clone(),
            prepared.clone(),
            reader,
            transfer_id.clone(),
            None,
        );
        match privet_transfer::run_sender(inputs).await {
            Ok(()) => {
                let _ = event_tx.send(resumed_event(&transfer_id));
                return Ok(());
            }
            Err(TransferError::TransportLost) | Err(TransferError::Transport(_)) => {
                // TransportLost 与 Transport(String) 均视为可重连（前者 run_sender
                // 显式匹配，后者如 control recv 错误也应触发退避而非直接失败）。
                if !next_backoff_or_exhausted(backoff, &transfer_id, &event_tx).await {
                    return Err(CoreError::Transfer(TransferError::TransportLost));
                }
                continue;
            }
            Err(e) => return Err(CoreError::Transfer(e)),
        }
    }
}

/// 退避或耗尽：返回 true=有退避（继续重试），false=耗尽。
async fn next_backoff_or_exhausted(
    backoff: &mut Backoff,
    transfer_id: &str,
    event_tx: &broadcast::Sender<EngineEvent>,
) -> bool {
    match backoff.next_backoff() {
        Some(d) => {
            // 重连日志（原实现静默；诊断连接死亡次数）
            tracing::warn!(
                transfer_id,
                attempt = backoff.attempt(),
                backoff_secs = d.as_secs(),
                "transport lost; reconnecting"
            );
            let _ = event_tx.send(reconnect_event(transfer_id, backoff.attempt(), d));
            tokio::time::sleep(d).await;
            true
        }
        None => {
            // 退避耗尽日志（原仅返回 false，逐次重连不可见）
            tracing::warn!(transfer_id, "transport lost; backoff exhausted");
            false
        }
    }
}

/// transport 级（连接断）是否可重试？是则退避并返回 true。
async fn retry_on_transport_lost(
    error: &CoreError,
    backoff: &mut Backoff,
    transfer_id: &str,
    event_tx: &broadcast::Sender<EngineEvent>,
) -> bool {
    if matches!(error, CoreError::Transport(_)) {
        return next_backoff_or_exhausted(backoff, transfer_id, event_tx).await;
    }
    false
}

// ===== 崩溃恢复 =====
use std::path::Path;

/// 启动时扫描 staging 目录的 .part/.part.meta + 孤儿对账。
/// 仅扫描 staging 目录，不碰用户子目录。
pub fn recover_partial_transfers(
    save_dir: &Path,
    conn: &rusqlite::Connection,
) -> crate::Result<()> {
    privet_storage::staging::orphan_reconcile(save_dir, conn)?;
    let staging = save_dir.join(privet_storage::STAGING_DIR_NAME);
    if let Ok(rd) = std::fs::read_dir(&staging) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                let _ = privet_storage::staging::cleanup_staging_dir(&p);
            }
        }
    }
    Ok(())
}
