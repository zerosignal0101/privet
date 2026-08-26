use std::net::SocketAddr;

use privet_crypto::identity::Identity;
use privet_protocol::{control_frame::Payload, ControlFrame, Hello, HelloAck};
use privet_transport::frame_io::{recv_control, send_control};
use privet_transport::{connect_with_fallback, Connection, Stream, Transport, TransportMode};

use crate::Result;

pub async fn connect_peer(
    quic: &dyn Transport,
    tcp: Option<&dyn Transport>,
    addr: SocketAddr,
    mode: TransportMode,
    bind_source: Option<SocketAddr>,
) -> Result<Box<dyn Connection>> {
    connect_peer_with_ports(quic, tcp, addr, addr, mode, bind_source).await
}

/// Connect using the independently advertised QUIC and TCP endpoints.
pub async fn connect_peer_with_ports(
    quic: &dyn Transport,
    tcp: Option<&dyn Transport>,
    quic_addr: SocketAddr,
    tcp_addr: SocketAddr,
    mode: TransportMode,
    bind_source: Option<SocketAddr>,
) -> Result<Box<dyn Connection>> {
    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        connect_with_fallback(quic, tcp, quic_addr, tcp_addr, mode, bind_source),
    )
    .await
    .map_err(|_| crate::CoreError::Internal("connect timeout".into()))??;
    Ok(conn)
}

pub enum ControlRole {
    Initiator,
    Responder,
}

pub async fn acquire_control(conn: &dyn Connection, role: ControlRole) -> Result<Box<dyn Stream>> {
    match role {
        ControlRole::Initiator => Ok(conn.open_control().await?),
        ControlRole::Responder => Ok(conn.accept_control().await?),
    }
}

pub enum DataRole {
    Initiator,
    Responder,
}

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
