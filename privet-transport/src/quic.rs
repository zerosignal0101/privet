
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use quinn::{Endpoint, RecvStream, SendStream, TransportConfig};

use crate::config::{Congestion, TransportConfigPrivet};
use crate::constants::STREAM_POOL_SIZE;
use crate::error::{Result, TransportError};
use crate::tls::{build_client_config, build_server_config, TlsMaterial};
use crate::transport::{
    CloseReason, Connection, Listener, Stream, Transport, TransportKind, TransportMode,
};

const DUMMY_SNI: &str = "privet";

pub struct QuicTransport {
    material: TlsMaterial,
    config: TransportConfigPrivet,
    client_endpoints: tokio::sync::Mutex<Vec<(std::net::IpAddr, Endpoint)>>,
}

fn apply_transport_config(tcfg: &mut TransportConfig, cfg: &TransportConfigPrivet) {
    tcfg.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        cfg.idle_timeout.as_millis() as u32,
    ))));
    tcfg.max_concurrent_bidi_streams(quinn::VarInt::from_u32(cfg.stream_pool_size as u32));
    tcfg.max_concurrent_uni_streams(quinn::VarInt::from_u32(cfg.stream_pool_size as u32));
    use quinn::congestion::ControllerFactory;
    let factory: Arc<dyn ControllerFactory + Send + Sync> = match cfg.congestion {
        Congestion::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
        Congestion::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
    };
    tcfg.congestion_controller_factory(factory);
}

impl QuicTransport {
    pub fn new(material: TlsMaterial, config: TransportConfigPrivet) -> Self {
        Self {
            material,
            config,
            client_endpoints: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    fn make_server_config(&self) -> Result<quinn::ServerConfig> {
        let tls = build_server_config(&self.material)?;
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| TransportError::TlsMaterial(e.to_string()))?;
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        let mut tcfg = quinn::TransportConfig::default();
        apply_transport_config(&mut tcfg, &self.config);
        scfg.transport = Arc::new(tcfg);
        Ok(scfg)
    }

    fn make_client_config(&self) -> Result<quinn::ClientConfig> {
        let tls = build_client_config(&self.material)?;
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| TransportError::TlsMaterial(e.to_string()))?;
        let mut tcfg = quinn::TransportConfig::default();
        apply_transport_config(&mut tcfg, &self.config);
        let mut cc = quinn::ClientConfig::new(Arc::new(quic_client));
        cc.transport_config(Arc::new(tcfg));
        Ok(cc)
    }
}

pub struct QuicStreamPrivet {
    send: Option<SendStream>,
    recv: Option<RecvStream>,
}

#[async_trait]
impl Stream for QuicStreamPrivet {
    async fn send_all(&mut self, buf: &[u8]) -> Result<()> {
        let s = self
            .send
            .as_mut()
            .ok_or(TransportError::Closed("no send half".into()))?;
        s.write_all(buf).await?;
        Ok(())
    }

    async fn recv_exact(&mut self, n: usize) -> Result<BytesMut> {
        let r = self
            .recv
            .as_mut()
            .ok_or(TransportError::Closed("no recv half".into()))?;
        let mut buf = BytesMut::zeroed(n);
        r.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn reset(self: Box<Self>, code: u32) {
        let v = quinn::VarInt::from_u32(code);
        if let Some(mut s) = self.send {
            let _ = s.reset(v);
        }
        if let Some(mut r) = self.recv {
            let _ = r.stop(v);
        }
    }
}

pub struct QuicConnectionPrivet {
    conn: quinn::Connection,
}

#[async_trait]
impl Connection for QuicConnectionPrivet {
    fn control_stream(&self) -> Result<Box<dyn Stream>> {
        Err(TransportError::Unavailable(
            "QUIC control via open_control/accept_control".into(),
        ))
    }

    async fn open_control(&self) -> Result<Box<dyn Stream>> {
        let (send, recv) = self.conn.open_bi().await?;
        let _ = send.set_priority(1);
        Ok(Box::new(QuicStreamPrivet {
            send: Some(send),
            recv: Some(recv),
        }))
    }

    async fn accept_control(&self) -> Result<Box<dyn Stream>> {
        let (send, recv) = self.conn.accept_bi().await?;
        Ok(Box::new(QuicStreamPrivet {
            send: Some(send),
            recv: Some(recv),
        }))
    }

    async fn accept_data_stream(&self) -> Result<Box<dyn Stream>> {
        let recv = self.conn.accept_uni().await?;
        Ok(Box::new(QuicStreamPrivet {
            send: None,
            recv: Some(recv),
        }))
    }

    async fn open_data_stream(&self) -> Result<Box<dyn Stream>> {
        let send = self.conn.open_uni().await?;
        Ok(Box::new(QuicStreamPrivet {
            send: Some(send),
            recv: None,
        }))
    }

    fn max_data_streams(&self) -> usize {
        STREAM_POOL_SIZE
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Quic
    }

    fn peer_cert_der(&self) -> Option<Vec<u8>> {
        let id = self.conn.peer_identity()?;
        id.downcast::<Vec<rustls::pki_types::CertificateDer>>()
            .ok()
            .and_then(|mut v| v.pop())
            .map(|c| c.to_vec())
    }

    fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> std::result::Result<Vec<u8>, TransportError> {
        // quinn 0.11: export_keying_material(output, label, context) -> Result<(), ExportKeyingMaterialError>
        let mut output = vec![0u8; 32];
        self.conn
            .export_keying_material(&mut output, label, context.unwrap_or(b""))
            .map_err(|e| TransportError::Unavailable(format!("{:?}", e)))?;
        Ok(output)
    }

    async fn close(self: Box<Self>, reason: CloseReason) {
        let code = match reason {
            CloseReason::Normal => quinn::VarInt::from_u32(0),
            CloseReason::Error(_) => quinn::VarInt::from_u32(1),
            CloseReason::Application(c) => quinn::VarInt::from_u32(c),
        };
        self.conn.close(code, &[]);
    }
}

pub struct QuicListenerPrivet {
    endpoint: Endpoint,
}

#[async_trait]
impl Listener for QuicListenerPrivet {
    async fn accept(&self) -> Result<Box<dyn Connection>> {
        let conn = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::Closed("listener dropped".into()))?
            .await?;
        Ok(Box::new(QuicConnectionPrivet { conn }))
    }

    async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn connect(
        &self,
        addr: SocketAddr,
        mode: TransportMode,
        bind_source: Option<SocketAddr>,
    ) -> Result<Box<dyn Connection>> {
        if mode == TransportMode::Tcp {
            return Err(TransportError::Unavailable(
                "QuicTransport cannot do Tcp".into(),
            ));
        }
        let client_cfg = self.make_client_config()?;
        let endpoint = match bind_source {
            Some(src) => {
                let mut guard = self.client_endpoints.lock().await;
                if let Some((_, ep)) = guard.iter().find(|(ip, _)| *ip == src.ip()) {
                    ep.clone()
                } else {
                    let ep = Endpoint::client(SocketAddr::new(src.ip(), 0))
                        .map_err(TransportError::Io)?;
                    guard.push((src.ip(), ep.clone()));
                    ep
                }
            }
            None => Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(TransportError::Io)?,
        };
        let server_name = DUMMY_SNI;
        let conn = endpoint
            .connect_with(client_cfg, addr, server_name)
            .map_err(TransportError::QuicConnect)?
            .await?;
        Ok(Box::new(QuicConnectionPrivet { conn }))
    }

    async fn bind(&self, addr: SocketAddr) -> Result<Box<dyn Listener>> {
        let scfg = self.make_server_config()?;
        let endpoint = Endpoint::server(scfg, addr).map_err(TransportError::Io)?;
        Ok(Box::new(QuicListenerPrivet { endpoint }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_material() -> TlsMaterial {
        use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
        let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec![]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        TlsMaterial::new(cert.der().to_vec(), kp.serialize_der())
    }

    #[tokio::test]
    async fn quic_exporter_roundtrip() {
        let mat = test_material();
        let srv_cfg = TransportConfigPrivet::default();
        let srv = QuicTransport::new(mat.clone(), srv_cfg);
        let listener = srv.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().await.unwrap();

        let cli = QuicTransport::new(test_material(), TransportConfigPrivet::default());

        let accept = async {
            let conn = listener.accept().await.unwrap();
            let e = conn
                .export_keying_material(b"privet-pairing-binding", Some(b"privet-pairing-v1"))
                .expect("exporter");
            assert_eq!(e.len(), 32);
            conn
        };

        let connect = async {
            let conn = cli.connect(addr, TransportMode::Quic, None).await.unwrap();
            let e = conn
                .export_keying_material(b"privet-pairing-binding", Some(b"privet-pairing-v1"))
                .expect("exporter");
            assert_eq!(e.len(), 32);
            conn
        };

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (_a, _c) = tokio::join!(accept, connect);
        })
        .await
        .unwrap();
    }
}
