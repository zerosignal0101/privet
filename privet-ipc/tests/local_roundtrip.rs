#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use privet_ipc::codec::{read_message, write_message};
use privet_ipc::{
    ClientMessage, Event, EventMessage, IpcClient, LocalEndpoint, LocalListener, Request,
    ResponseMessage, ResponsePayload, ServerMessage, IPC_PROTOCOL_VERSION,
};

#[tokio::test]
async fn client_multiplexes_response_and_event_over_unix_socket() {
    let temp = tempfile::tempdir().unwrap();
    let endpoint = LocalEndpoint::new(temp.path().join("runtime/privet.sock"));
    let listener = LocalListener::bind(endpoint.clone()).unwrap();
    assert_eq!(
        std::fs::metadata(endpoint.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let request: ClientMessage = read_message(&mut stream).await.unwrap();
        assert_eq!(request.protocol_version, IPC_PROTOCOL_VERSION);
        assert_eq!(request.request, Request::Ping);

        write_message(
            &mut stream,
            &ServerMessage::Event(EventMessage {
                sequence: 1,
                event: Event::DaemonStopping,
            }),
        )
        .await
        .unwrap();
        write_message(
            &mut stream,
            &ServerMessage::Response(ResponseMessage::success(
                request.request_id,
                ResponsePayload::Pong {
                    protocol_version: IPC_PROTOCOL_VERSION,
                },
            )),
        )
        .await
        .unwrap();
    });

    let client = IpcClient::connect(&endpoint).await.unwrap();
    let mut events = client.subscribe();
    assert_eq!(
        client.call(Request::Ping).await.unwrap(),
        ResponsePayload::Pong {
            protocol_version: IPC_PROTOCOL_VERSION,
        }
    );
    assert_eq!(events.recv().await.unwrap().sequence, 1);
    server.await.unwrap();
}

#[test]
fn live_socket_prevents_second_daemon() {
    let temp = tempfile::tempdir().unwrap();
    let endpoint = LocalEndpoint::new(temp.path().join("privet.sock"));
    let _listener = LocalListener::bind(endpoint.clone()).unwrap();
    let error = LocalListener::bind(endpoint).err().unwrap();
    assert!(error.to_string().contains("already listening"));
}

#[test]
fn stale_socket_path_is_recovered() {
    let temp = tempfile::tempdir().unwrap();
    let endpoint = LocalEndpoint::new(temp.path().join("privet.sock"));
    std::fs::write(endpoint.path(), b"stale").unwrap();
    let listener = LocalListener::bind(endpoint.clone()).unwrap();
    assert!(endpoint.path().exists());
    drop(listener);
    assert!(!endpoint.path().exists());
}
