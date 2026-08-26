use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use privet_ipc::{Event, EventMessage};
use tokio::sync::{broadcast, Mutex};

const REPLAY_CAPACITY: usize = 1024;

pub struct EventBroker {
    next: AtomicU64,
    replay: Mutex<VecDeque<EventMessage>>,
    live: broadcast::Sender<EventMessage>,
}

impl EventBroker {
    pub fn new() -> Self {
        let (live, _) = broadcast::channel(512);
        Self { next: AtomicU64::new(1), replay: Mutex::new(VecDeque::new()), live }
    }

    pub async fn publish(&self, event: Event) -> EventMessage {
        let message = EventMessage {
            sequence: self.next.fetch_add(1, Ordering::SeqCst),
            event,
        };
        let mut replay = self.replay.lock().await;
        replay.push_back(message.clone());
        while replay.len() > REPLAY_CAPACITY { replay.pop_front(); }
        drop(replay);
        let _ = self.live.send(message.clone());
        message
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventMessage> { self.live.subscribe() }

    pub async fn replay_after(&self, after: Option<u64>) -> (Vec<EventMessage>, Option<u64>, u64) {
        let replay = self.replay.lock().await;
        let oldest = replay.front().map(|event| event.sequence);
        let latest = replay.back().map(|event| event.sequence).unwrap_or(0);
        let events = replay
            .iter()
            .filter(|event| match after {
                Some(sequence) => event.sequence > sequence,
                None => true,
            })
            .cloned()
            .collect();
        (events, oldest, latest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replay_is_ordered_and_exclusive_of_cursor() {
        let broker = EventBroker::new();
        broker.publish(Event::DaemonStopping).await;
        broker.publish(Event::DaemonStopping).await;
        broker.publish(Event::DaemonStopping).await;

        let (events, oldest, latest) = broker.replay_after(Some(1)).await;
        assert_eq!(oldest, Some(1));
        assert_eq!(latest, 3);
        assert_eq!(events.iter().map(|event| event.sequence).collect::<Vec<_>>(), vec![2, 3]);
    }
}
