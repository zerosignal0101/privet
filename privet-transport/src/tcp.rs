
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};

use privet_protocol::error::FrameError;
use privet_protocol::framing::{
    decode_tcp_frame, encode_tcp_frame, CONTROL_STREAM_ID, DATA_STREAM_ID,
};

use crate::config::TransportConfigPrivet;
use crate::constants::TCP_STREAM_CHANNEL_CAP;
use crate::error::{Result, TransportError};
use crate::tls::{build_client_config, build_server_config, TlsMaterial};
use crate::transport::{
    CloseReason, Connection, Listener, Stream, Transport, TransportKind, TransportMode,
};

// ===== TcpTransport =====

pub struct TcpTransport {
    material: TlsMaterial,
    #[allow(dead_code)]
    config: TransportConfigPrivet,
}

impl TcpTransport {
    pub fn new(material: TlsMaterial, config: TransportConfigPrivet) -> Self {
        Self { material, config }
    }
}

// ===== PrivetTcpStream =====

pub struct TcpStreamPrivet {
    writer: Arc<Mutex<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>>,
    stream_id: u8,
    rx: Arc<Mutex<mpsc::Receiver<BytesMut>>>,
    leftover: BytesMut,
}

#[async_trait]
impl Stream for TcpStreamPrivet {
    async fn send_all(&mut self, buf: &[u8]) -> Result<()> {
        let frame = privet_protocol::framing::encode_tcp_frame(self.stream_id, buf)?;
        let mut w = self.writer.lock().await;
        w.write_all(&frame).await?;
        w.flush().await?;
        Ok(())
    }

    async fn recv_exact(&mut self, n: usize) -> Result<BytesMut> {
        while self.leftover.len() < n {
            let mut rx = self.rx.lock().await;
            match rx.recv().await {
                Some(chunk) => self.leftover.extend_from_slice(&chunk),
                None => return Err(TransportError::Closed("tcp stream ended".into())),
            }
        }
        Ok(self.leftover.split_to(n))
    }

    async fn reset(self: Box<Self>, _code: u32) {
    }
}


pub struct TcpConnectionPrivet {
    writer: Arc<Mutex<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>>,
    control_rx: Arc<Mutex<mpsc::Receiver<BytesMut>>>,
    data_rx: Arc<Mutex<mpsc::Receiver<BytesMut>>>,
    _reader: tokio::task::JoinHandle<()>,
    peer_cert: Option<Vec<u8>>,
    exporter: Option<Vec<u8>>,
    captured_label: Option<Vec<u8>>,
    captured_context: Option<Vec<u8>>,
}

impl TcpConnectionPrivet {
    fn from_stream<S>(
        stream: S,
        peer_cert: Option<Vec<u8>>,
        exporter: Option<Vec<u8>>,
        captured_label: Option<Vec<u8>>,
        captured_context: Option<Vec<u8>>,
    ) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let writer: Arc<Mutex<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>> =
            Arc::new(Mutex::new(Box::new(write_half)));
        let (control_tx, control_rx) = mpsc::channel::<BytesMut>(TCP_STREAM_CHANNEL_CAP);
        let (data_tx, data_rx) = mpsc::channel::<BytesMut>(TCP_STREAM_CHANNEL_CAP);

        let writer_for_reader = writer.clone();
        let reader = tokio::spawn(async move {
            let mut accum: Vec<u8> = Vec::new();
            let mut buf = [0u8; 8192];
            let mut read_half = read_half;
            loop {
                match read_half.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => accum.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
                'parse: loop {
                    // Parse all complete frames
                    let mut parsed: Vec<(u8, Vec<u8>)> = Vec::new();
                    let mut parse_end = 0;
                    loop {
                        let mut slice = &accum[parse_end..];
                        match decode_tcp_frame(&mut slice) {
                            Ok((sid, payload)) => {
                                let frame_end = accum.len() - slice.len();
                                parsed.push((sid, payload.to_vec()));
                                parse_end = frame_end;
                            }
                            Err(FrameError::UnexpectedEof) => break,
                            Err(_) => return,
                        }
                    }
                    if parsed.is_empty() {
                        break 'parse;
                    }
                    // Dispatch: control send, data try_send; re-encode unsent data
                    let mut rebuilt: Vec<u8> = Vec::new();
                    let mut had_control = false;
                    let mut any_data_blocked = false;
                    for (sid, payload) in &parsed {
                        if *sid == CONTROL_STREAM_ID {
                            had_control = true;
                            if control_tx
                                .send(BytesMut::from(payload.as_slice()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        } else {
                            if data_tx
                                .try_send(BytesMut::from(payload.as_slice()))
                                .is_err()
                            {
                                any_data_blocked = true;
                                if let Ok(encoded) = encode_tcp_frame(DATA_STREAM_ID, payload) {
                                    rebuilt.extend_from_slice(&encoded);
                                }
                            }
                        }
                    }
                    rebuilt.extend_from_slice(&accum[parse_end..]);
                    accum = rebuilt;
                    if !had_control && any_data_blocked {
                        break 'parse;
                    }
                }
            }
            drop(writer_for_reader);
        });

        Self {
            writer,
            control_rx: Arc::new(Mutex::new(control_rx)),
            data_rx: Arc::new(Mutex::new(data_rx)),
            _reader: reader,
            peer_cert,
            exporter,
            captured_label,
            captured_context,
        }
    }
}

#[async_trait]
impl Connection for TcpConnectionPrivet {
    fn control_stream(&self) -> Result<Box<dyn Stream>> {
        Ok(Box::new(TcpStreamPrivet {
            writer: self.writer.clone(),
            stream_id: CONTROL_STREAM_ID,
            rx: self.control_rx.clone(),
            leftover: BytesMut::new(),
        }))
    }

    async fn open_control(&self) -> Result<Box<dyn Stream>> {
        self.control_stream()
    }

    async fn accept_control(&self) -> Result<Box<dyn Stream>> {
        self.control_stream()
    }

    async fn open_data_stream(&self) -> Result<Box<dyn Stream>> {
        Ok(Box::new(TcpStreamPrivet {
            writer: self.writer.clone(),
            stream_id: DATA_STREAM_ID,
            rx: self.data_rx.clone(),
            leftover: BytesMut::new(),
        }))
    }

    async fn accept_data_stream(&self) -> Result<Box<dyn Stream>> {
        self.open_data_stream().await
    }

    fn max_data_streams(&self) -> usize {
        1
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Tcp
    }

    fn peer_cert_der(&self) -> Option<Vec<u8>> {
        self.peer_cert.clone()
    }

    fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> std::result::Result<Vec<u8>, TransportError> {
        match (&self.captured_label, &self.captured_context, &self.exporter) {
            (Some(cl), Some(cc), Some(e))
                if cl == label && cc.as_slice() == context.unwrap_or_default() =>
            {
                Ok(e.clone())
            }
            _ => Err(TransportError::Unavailable("no tcp exporter".into())),
        }
    }

    async fn close(self: Box<Self>, _reason: CloseReason) {
        // clean close — shutdown writer (reader will pick up EOF and abort)
        let mut w = self.writer.lock().await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut **w).await;
        drop(w);
        self._reader.abort();
    }
}

// ===== TcpListenerPrivet =====

pub struct TcpListenerPrivet {
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    exporter_label: Vec<u8>,
    exporter_context: Vec<u8>,
}

#[async_trait]
impl Listener for TcpListenerPrivet {
    async fn accept(&self) -> Result<Box<dyn Connection>> {
        let (tcp, _) = self.listener.accept().await?;
        {
            let s = socket2::SockRef::from(&tcp);
            let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
            let _ = s.set_tcp_keepalive(&ka);
        }
        let stream = self.acceptor.accept(tcp).await?;
        let peer_cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec());
        // capture TLS exporter for transcript binding
        let label = self.exporter_label.as_slice();
        let context = self.exporter_context.as_slice();
        let mut exporter_out = [0u8; 32];
        let (exporter, captured_label, captured_context) =
            match stream
                .get_ref()
                .1
                .export_keying_material(&mut exporter_out, label, Some(context))
            {
                Ok(out) => (
                    Some(out.to_vec()),
                    Some(label.to_vec()),
                    Some(context.to_vec()),
                ),
                Err(_) => (None, None, None),
            };
        Ok(Box::new(TcpConnectionPrivet::from_stream(
            stream,
            peer_cert,
            exporter,
            captured_label,
            captured_context,
        )))
    }

    async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(
        &self,
        addr: SocketAddr,
        mode: TransportMode,
        bind_source: Option<SocketAddr>,
    ) -> Result<Box<dyn Connection>> {
        if mode == TransportMode::Quic {
            return Err(TransportError::Unavailable(
                "TcpTransport cannot do Quic".into(),
            ));
        }
        let socket = match bind_source {
            Some(src) => {
                let s = tokio::net::TcpSocket::new_v4()?;
                s.bind(SocketAddr::new(src.ip(), 0))?;
                s
            }
            None => tokio::net::TcpSocket::new_v4()?,
        };
        let tcp = socket.connect(addr).await?;
        // set keepalive on the connected socket
        {
            let s = socket2::SockRef::from(&tcp);
            let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
            let _ = s.set_tcp_keepalive(&ka);
        }
        let client_cfg = build_client_config(&self.material)?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let server_name = rustls::pki_types::ServerName::try_from("privet")
            .map_err(|_| TransportError::Config("invalid SNI".into()))?;
        let stream = tls.connect(server_name, tcp).await?;
        let peer_cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec());
        // capture TLS exporter for transcript binding (TCP fallback pairing)
        let exporter_spec = self.config.pairing_exporter.clone().unwrap_or_else(|| {
            crate::config::PairingExporterLabel {
                label: b"privet-pairing-binding".to_vec(),
                context: b"privet-pairing-v1".to_vec(),
            }
        });
        let label = exporter_spec.label.as_slice();
        let context = exporter_spec.context.as_slice();
        let mut exporter_out = [0u8; 32];
        let (exporter, captured_label, captured_context) =
            match stream
                .get_ref()
                .1
                .export_keying_material(&mut exporter_out, label, Some(context))
            {
                Ok(out) => (
                    Some(out.to_vec()),
                    Some(label.to_vec()),
                    Some(context.to_vec()),
                ),
                Err(_) => (None, None, None),
            };
        Ok(Box::new(TcpConnectionPrivet::from_stream(
            stream,
            peer_cert,
            exporter,
            captured_label,
            captured_context,
        )))
    }

    async fn bind(&self, addr: SocketAddr) -> Result<Box<dyn Listener>> {
        let listener = TcpListener::bind(addr).await?;
        let acceptor =
            tokio_rustls::TlsAcceptor::from(Arc::new(build_server_config(&self.material)?));
        let exporter = self.config.pairing_exporter.clone().unwrap_or_else(|| {
            crate::config::PairingExporterLabel {
                label: b"privet-pairing-binding".to_vec(),
                context: b"privet-pairing-v1".to_vec(),
            }
        });
        Ok(Box::new(TcpListenerPrivet {
            listener,
            acceptor,
            exporter_label: exporter.label,
            exporter_context: exporter.context,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportConfigPrivet;

    #[tokio::test]
    async fn tcp_captures_peer_cert() {
        use crate::tls::TlsMaterial;
        use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

        let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec![]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let mat = TlsMaterial::new(cert.der().to_vec(), kp.serialize_der());

        let tcp = TcpTransport::new(mat.clone(), TransportConfigPrivet::default());
        let listener: Box<dyn crate::transport::Listener> =
            tcp.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().await.unwrap();

        let cli_tcp = TcpTransport::new(mat, TransportConfigPrivet::default());
        let accept = async { listener.accept().await.unwrap() };
        let connect = async {
            cli_tcp
                .connect(addr, TransportMode::Tcp, None)
                .await
                .unwrap()
        };
        let (_srv, cli_conn) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(accept, connect)
        })
        .await
        .unwrap();

        assert!(
            cli_conn.peer_cert_der().is_some(),
            "tcp client must see server cert"
        );
    }
}
