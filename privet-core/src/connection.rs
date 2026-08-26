//! 连接生命周期：connect_with_fallback + Listener accept + 控制流获取 + Hello/HelloAck
use std::net::SocketAddr;

use privet_crypto::identity::Identity;
use privet_protocol::{control_frame::Payload, ControlFrame, Hello, HelloAck};
use privet_transport::frame_io::{recv_control, send_control};
use privet_transport::{connect_with_fallback, Connection, Stream, Transport, TransportMode};

use crate::Result;

/// 连接发起（QUIC 优先 + TCP 降级）。
pub async fn connect_peer(
    quic: &dyn Transport,
    tcp: Option<&dyn Transport>,
    addr: SocketAddr,
    mode: TransportMode,
    bind_source: Option<SocketAddr>,
) -> Result<Box<dyn Connection>> {
    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        connect_with_fallback(quic, tcp, addr, addr, mode, bind_source),
    )
    .await
    .map_err(|_| crate::CoreError::Internal("connect timeout".into()))??;
    Ok(conn)
}

/// 控制流角色：发起方 open（QUIC open_bi）／应答方 accept（QUIC accept_bi）。
pub enum ControlRole {
    Initiator,
    Responder,
}

/// 获取控制流（trait 多态，无需 downcast）。
/// 发起方 open_control / 应答方 accept_control；QUIC 异步开/收双向流，TCP 返回共享 stream_id 0。
pub async fn acquire_control(conn: &dyn Connection, role: ControlRole) -> Result<Box<dyn Stream>> {
    match role {
        ControlRole::Initiator => Ok(conn.open_control().await?),
        ControlRole::Responder => Ok(conn.accept_control().await?),
    }
}

/// 数据流角色：发起方（sender）开单向流 open_uni；应答方（receiver）收单向流 accept_uni。
/// QUIC 单向流仅单侧可用（sender 仅 send_all，receiver 仅 recv_exact），故 sender/receiver 必须分别 open/accept。
/// TCP 单连接多路（stream_id 1 共享），open_data_stream 即可（不区分角色）。
pub enum DataRole {
    Initiator,
    Responder,
}

/// 获取数据流（trait 多态，无需 downcast）。
/// 发起方 open_data_stream / 应答方 accept_data_stream；QUIC 单向流，TCP 共享 stream_id 1。
pub async fn acquire_data(conn: &dyn Connection, role: DataRole) -> Result<Box<dyn Stream>> {
    match role {
        DataRole::Initiator => Ok(conn.open_data_stream().await?),
        DataRole::Responder => Ok(conn.accept_data_stream().await?),
    }
}

fn hello_frame(local: &Identity, proto_ver: u32, device_name: &str) -> ControlFrame {
    ControlFrame {
        payload: Some(Payload::Hello(Hello {
            proto_version: proto_ver,
            device_fingerprint: local.fingerprint(),
            device_name: device_name.into(),
            platform: std::env::consts::OS.into(),
            capabilities: vec![
                "quic".into(),
                "tcp".into(),
                "folder".into(),
                "resume".into(),
            ],
        })),
    }
}

/// 发起方 Hello 交换：发 Hello，收 HelloAck。
pub async fn hello_exchange(
    control: &mut dyn Stream,
    local: &Identity,
    proto_ver: u32,
    device_name: &str,
) -> Result<HelloAck> {
    send_control(control, &hello_frame(local, proto_ver, device_name)).await?;
    let ack_frame = tokio::time::timeout(std::time::Duration::from_secs(5), recv_control(control))
        .await
        .map_err(|_| crate::CoreError::Internal("hello timeout".into()))??;
    match ack_frame.payload {
        Some(Payload::HelloAck(a)) => Ok(a),
        _ => Err(crate::CoreError::Internal("expected HelloAck".into())),
    }
}

/// 应答方 Hello 交换：收 Hello，回 HelloAck。
pub async fn hello_exchange_responder(
    control: &mut dyn Stream,
    local: &Identity,
    proto_ver: u32,
    device_name: &str,
    platform: &str,
) -> Result<Hello> {
    let hello_frame =
        tokio::time::timeout(std::time::Duration::from_secs(5), recv_control(control))
            .await
            .map_err(|_| crate::CoreError::Internal("hello timeout".into()))??;
    let hello = match hello_frame.payload {
        Some(Payload::Hello(h)) => h,
        _ => return Err(crate::CoreError::Internal("expected Hello".into())),
    };
    let ack = ControlFrame {
        payload: Some(Payload::HelloAck(HelloAck {
            proto_version: proto_ver,
            platform: platform.into(),
            device_fingerprint: local.fingerprint(),
            capabilities: vec![
                "quic".into(),
                "tcp".into(),
                "folder".into(),
                "resume".into(),
            ],
            ok: true,
            error: String::new(),
            device_name: device_name.into(),
        })),
    };
    send_control(control, &ack).await?;
    Ok(hello)
}
