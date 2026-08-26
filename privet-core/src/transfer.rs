
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
    acquire_control, acquire_data, connect_peer_with_ports, hello_exchange, ControlRole, DataRole,
};
use crate::reconnect::{reconnect_event, resumed_event, Backoff};
use crate::EngineEvent;
use privet_crypto::identity::Identity;

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

#[allow(clippy::too_many_arguments)]
pub fn sender_inputs(
    control: Box<dyn Stream>,
    data: Box<dyn Stream>,
    cfg: TransferEngineConfig,
    event_tx: broadcast::Sender<EngineEvent>,
    prepared: privet_transfer::PreparedSet,
    reader: Box<dyn privet_transfer::ChunkReader>,
    transfer_id: String,
    cmd_rx: Option<privet_transfer::SharedCommandReceiver>,
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
    let cmd_rx = cmd_rx.map(|receiver| {
        std::sync::Arc::new(tokio::sync::Mutex::new(receiver))
    });
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


use crate::CoreError;
use privet_transfer::TransferError;

#[allow(clippy::too_many_arguments)]
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
    cmd_rx: Option<tokio::sync::mpsc::Receiver<privet_transfer::TransferCommand>>,
) -> crate::Result<()> {
    send_with_reconnect_endpoints(
        quic,
        tcp,
        addr,
        addr,
        mode,
        local,
        device_name,
        prepared,
        cfg,
        event_tx,
        transfer_id,
        backoff,
        cmd_rx,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_with_reconnect_endpoints(
    quic: &dyn Transport,
    tcp: Option<&dyn Transport>,
    quic_addr: SocketAddr,
    tcp_addr: SocketAddr,
    mode: TransportMode,
    local: &Identity,
    device_name: &str,
    prepared: privet_transfer::PreparedSet,
    cfg: TransferEngineConfig,
    event_tx: broadcast::Sender<EngineEvent>,
    transfer_id: String,
    backoff: &mut Backoff,
    cmd_rx: Option<tokio::sync::mpsc::Receiver<privet_transfer::TransferCommand>>,
) -> crate::Result<()> {
    let cmd_rx = cmd_rx.map(|receiver| {
        std::sync::Arc::new(tokio::sync::Mutex::new(receiver))
    });
    loop {
        let conn = match connect_peer_with_ports(quic, tcp, quic_addr, tcp_addr, mode, None).await {
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
            cmd_rx.clone(),
        );
        match privet_transfer::run_sender(inputs).await {
            Ok(()) => {
                let _ = event_tx.send(resumed_event(&transfer_id));
                return Ok(());
            }
            Err(TransferError::TransportLost) | Err(TransferError::Transport(_)) => {
                if !next_backoff_or_exhausted(backoff, &transfer_id, &event_tx).await {
                    return Err(CoreError::Transfer(TransferError::TransportLost));
                }
                continue;
            }
            Err(e) => return Err(CoreError::Transfer(e)),
        }
    }
}

async fn next_backoff_or_exhausted(
    backoff: &mut Backoff,
    transfer_id: &str,
    event_tx: &broadcast::Sender<EngineEvent>,
) -> bool {
    match backoff.next_backoff() {
        Some(d) => {
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
            tracing::warn!(transfer_id, "transport lost; backoff exhausted");
            false
        }
    }
}

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

use std::path::Path;

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
