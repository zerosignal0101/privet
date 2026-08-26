use std::sync::Arc;

use privet_ipc::codec::{read_message, write_message};
use privet_ipc::{ClientMessage, LocalListener, ResponseMessage, ServerMessage, IPC_PROTOCOL_VERSION};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use crate::backend::DaemonBackend;

pub async fn run(listener: LocalListener, backend: Arc<DaemonBackend>) -> privet_ipc::Result<()> {
    #[cfg(unix)]
    let listener = listener;
    #[cfg(windows)]
    let mut listener = listener;
    loop {
        tokio::select! {
            _ = backend.shutdown.notified() => return Ok(()),
            accepted = listener.accept() => {
                let stream = accepted?;
                tokio::spawn(serve_connection(stream, backend.clone()));
            }
        }
    }
}

async fn serve_connection<S>(stream: S, backend: Arc<DaemonBackend>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (output_tx, mut output_rx) =
        mpsc::channel::<(ServerMessage, Option<oneshot::Sender<()>>)>(128);
    let writer_task = tokio::spawn(async move {
        while let Some((message, flushed)) = output_rx.recv().await {
            if write_message(&mut writer, &message).await.is_err() { break; }
            if let Some(flushed) = flushed { let _ = flushed.send(()); }
        }
    });

    let mut live = backend.events.subscribe();
    let event_output = output_tx.clone();
    let event_task = tokio::spawn(async move {
        loop {
            match live.recv().await {
                Ok(event) => {
                    if event_output.send((ServerMessage::Event(event), None)).await.is_err() { break; }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    loop {
        let message = match read_message::<_, ClientMessage>(&mut reader).await {
            Ok(message) => message,
            Err(_) => break,
        };
        if message.protocol_version != IPC_PROTOCOL_VERSION {
            let response = ResponseMessage::error(
                message.request_id,
                "incompatible_protocol",
                format!("daemon supports IPC protocol {IPC_PROTOCOL_VERSION}"),
            );
            if output_tx.send((ServerMessage::Response(response), None)).await.is_err() { break; }
            continue;
        }
        let is_shutdown = matches!(&message.request, privet_ipc::Request::Shutdown);
        let task_backend = backend.clone();
        let task_output = output_tx.clone();
        tokio::spawn(async move {
            let request_id = message.request_id;
            let response = match task_backend.handle(message.request).await {
                Ok(payload) => ResponseMessage::success(request_id, payload),
                Err(error) => ResponseMessage::error(request_id, error.code, error.message),
            };
            if is_shutdown {
                let (flushed_tx, flushed_rx) = oneshot::channel();
                if task_output.send((ServerMessage::Response(response), Some(flushed_tx))).await.is_ok() {
                    let _ = flushed_rx.await;
                    task_backend.shutdown.notify_waiters();
                }
            } else {
                let _ = task_output.send((ServerMessage::Response(response), None)).await;
            }
        });
    }

    event_task.abort();
    drop(output_tx);
    let _ = writer_task.await;
}
