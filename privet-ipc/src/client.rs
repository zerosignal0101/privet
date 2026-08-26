use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, oneshot, Mutex};

use crate::codec::{read_message, write_message};
use crate::endpoint::{connect, LocalEndpoint, LocalStream};
use crate::error::{IpcError, Result};
use crate::protocol::{ClientMessage, EventMessage, Request, ResponseMessage, ResponsePayload, ServerMessage};

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<ResponseMessage>>>>;

pub struct IpcClient {
    writer: Arc<Mutex<tokio::io::WriteHalf<LocalStream>>>,
    pending: Pending,
    events: broadcast::Sender<EventMessage>,
    timeout: Duration,
    reader_task: tokio::task::JoinHandle<()>,
}

impl IpcClient {
    pub async fn connect(endpoint: &LocalEndpoint) -> Result<Self> {
        let stream = connect(endpoint).await?;
        let (mut reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(writer));
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let (events, _) = broadcast::channel(256);
        let reader_pending = pending.clone();
        let reader_events = events.clone();
        let reader_task = tokio::spawn(async move {
            loop {
                match read_message::<_, ServerMessage>(&mut reader).await {
                    Ok(ServerMessage::Response(response)) => {
                        if let Some(tx) = reader_pending.lock().await.remove(&response.request_id) {
                            let _ = tx.send(response);
                        }
                    }
                    Ok(ServerMessage::Event(event)) => { let _ = reader_events.send(event); }
                    Err(_) => {
                        reader_pending.lock().await.clear();
                        break;
                    }
                }
            }
        });
        Ok(Self {
            writer,
            pending,
            events,
            timeout: Duration::from_secs(30),
            reader_task,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventMessage> { self.events.subscribe() }

    pub async fn call(&self, request: Request) -> Result<ResponsePayload> {
        let message = ClientMessage::new(request);
        let request_id = message.request_id.clone();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id.clone(), tx);
        if let Err(error) = write_message(&mut *self.writer.lock().await, &message).await {
            self.pending.lock().await.remove(&request_id);
            return Err(error);
        }
        let response = tokio::time::timeout(self.timeout, rx)
            .await
            .map_err(|_| IpcError::Timeout)?
            .map_err(|_| IpcError::Closed)?;
        match (response.payload, response.error) {
            (Some(payload), None) => Ok(payload),
            (None, Some(error)) => Err(IpcError::Remote { code: error.code, message: error.message }),
            _ => Err(IpcError::Protocol("response must contain exactly one of payload or error".into())),
        }
    }
}

impl Drop for IpcClient {
    fn drop(&mut self) { self.reader_task.abort(); }
}
