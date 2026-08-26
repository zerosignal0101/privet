use std::time::Duration;

use privet_core::connection::{
    acquire_control, connect_peer, hello_exchange, hello_exchange_responder, ControlRole,
};
use privet_core::identity_tls::{build_tls_material, build_transports};
use privet_crypto::identity::Identity;
use privet_transport::{Transport, TransportMode};

#[tokio::test]
async fn hello_exchange_over_quic() {
    let cfg = privet_core::EngineConfig::default();

    let srv_id = Identity::generate().unwrap();
    let cli_id = Identity::generate().unwrap();
    let (srv_quic, _srv_tcp) =
        build_transports(&cfg, build_tls_material(&srv_id).unwrap()).unwrap();
    let (cli_quic, cli_tcp) = build_transports(&cfg, build_tls_material(&cli_id).unwrap()).unwrap();

    let listener = srv_quic.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    let accept = async {
        let conn = listener.accept().await.unwrap();
        let mut ctrl = acquire_control(conn.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        let hello = hello_exchange_responder(ctrl.as_mut(), &srv_id, 1, "srv", "windows")
            .await
            .unwrap();
        (conn, hello)
    };
    let connect = async {
        let conn = connect_peer(
            cli_quic.as_ref(),
            Some(cli_tcp.as_ref()),
            addr,
            TransportMode::Quic,
            None,
        )
        .await
        .unwrap();
        let mut ctrl = acquire_control(conn.as_ref(), ControlRole::Initiator)
            .await
            .unwrap();
        let ack = hello_exchange(ctrl.as_mut(), &cli_id, 1, "cli")
            .await
            .unwrap();
        (conn, ack)
    };
    let ((_srv_conn, hello), (_cli_conn, ack)) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(accept, connect)
        })
        .await
        .unwrap();

    assert!(ack.ok, "HelloAck must be ok");
    assert_eq!(hello.proto_version, 1, "Hello must carry proto_version");
}
