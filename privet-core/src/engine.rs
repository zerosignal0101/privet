use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use privet_crypto::identity::Identity;
use privet_crypto::keystore::KeyStore;
use privet_crypto::pake::Spake2Backend;
use privet_discovery::engine::DiscoveryEngine as DiscEngine;
use privet_security::commit::ProofStore;
use privet_security::trust::TrustStore;
use privet_transfer::FsPartStore;
use tokio::sync::{broadcast, Notify};

use crate::adapters::trust_store::StorageTrustStore;
use crate::config::EngineConfig;
use crate::events::{EngineEvent, EventSubscriber};

pub struct Engine {
    pub(crate) config: EngineConfig,
    pub(crate) identity: Arc<Identity>,
    pub(crate) quic: Arc<privet_transport::QuicTransport>,
    pub(crate) tcp: Arc<privet_transport::TcpTransport>,
    pub(crate) discovery: Option<Arc<DiscEngine>>,
    pub(crate) db: Arc<std::sync::Mutex<rusqlite::Connection>>,
    pub(crate) trust: Arc<StorageTrustStore>,
    pub(crate) pake: Arc<Spake2Backend>,
    #[allow(dead_code)]
    pub(crate) store: Arc<FsPartStore>,
    #[allow(dead_code)]
    peer_pool: Arc<crate::peers::PeerPool>,
    pub(crate) pending_pair_code: Arc<std::sync::Mutex<Option<privet_security::code::PairingCode>>>,
    pub(crate) event_tx: broadcast::Sender<EngineEvent>,
    cancelled: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    pub(crate) registry: Arc<crate::TransferRegistry>,
    pub(crate) offer_resolver: Arc<crate::OfferResolver>,
    pub(crate) runtime: Arc<crate::RuntimeSettings>,
    pub(crate) discovery_forwarder: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        let identity = match &config.identity_path {
            Some(path) => {
                let ks = privet_crypto::keystore::FileKeyStore::new(path.clone());
                match ks.load() {
                    Ok(Some(stored)) => {
                        Arc::new(Identity::from_stored(&stored).expect("identity from keystore"))
                    }
                    _ => {
                        let id = Arc::new(Identity::generate().expect("identity"));
                        if let Ok(stored) = id.to_stored() {
                            let _ = ks.store(&stored);
                        }
                        id
                    }
                }
            }
            None => Arc::new(Identity::generate().expect("identity")),
        };
        let material = crate::identity_tls::build_tls_material(&identity).expect("tls material");
        let (quic, tcp) =
            crate::identity_tls::build_transports(&config, material).expect("transports");
        let db = privet_storage::migration::open_and_migrate(&config.db_path).expect("db");
        let db = Arc::new(std::sync::Mutex::new(db));
        let trust = Arc::new(StorageTrustStore::new(db.clone()));
        let store = Arc::new(FsPartStore::new(config.save_dir.clone()));
        let (event_tx, _) = broadcast::channel(256);
        let init_save_dir = config.save_dir.clone();
        Self {
            config,
            identity,
            quic,
            tcp,
            discovery: None,
            db,
            trust,
            pake: Arc::new(Spake2Backend),
            store,
            peer_pool: Arc::new(crate::peers::PeerPool::new()),
            pending_pair_code: Arc::new(std::sync::Mutex::new(None)),
            event_tx,
            cancelled: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            registry: Arc::new(crate::TransferRegistry::new()),
            offer_resolver: Arc::new(crate::OfferResolver::new()),
            runtime: Arc::new(crate::RuntimeSettings::new(
                false,
                crate::AcceptPolicy::AutoAccept,
                privet_transfer::CollisionPolicy::Rename,
                init_save_dir,
            )),
            discovery_forwarder: std::sync::Mutex::new(None),
        }
    }

    pub fn subscribe(&self) -> EventSubscriber {
        self.event_tx.subscribe()
    }

    #[allow(dead_code)]
    pub(crate) fn event_sender(&self) -> broadcast::Sender<EngineEvent> {
        self.event_tx.clone()
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn engine_config(&self) -> &EngineConfig {
        &self.config
    }

    #[allow(dead_code)]
    pub fn trust(&self) -> &dyn TrustStore {
        self.trust.as_ref()
    }

    #[allow(dead_code)]
    pub fn proof_store(&self) -> &dyn ProofStore {
        self.trust.as_ref()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn db_conn(&self) -> crate::Result<std::sync::MutexGuard<'_, rusqlite::Connection>> {
        self.db
            .lock()
            .map_err(|_| crate::CoreError::Internal("db lock poisoned".into()))
    }

    pub async fn start(&mut self) -> crate::Result<()> {
        tracing::info!(device_fingerprint = %&self.identity.fingerprint(), "engine starting");
        if let Ok(db) = privet_storage::migration::open_and_migrate(&self.config.db_path) {
            let _ = crate::transfer::recover_partial_transfers(&self.config.save_dir, &db);
        }
        if self.config.discovery.udp_port != 0 {
            let info = crate::discovery::build_local_device_info(
                self.identity.as_ref(),
                &self.config,
                self.config.transport.quic_port,
                self.config.transport.tcp_port,
                self.config.discovery.udp_port,
            );
            let engine =
                crate::discovery::start_discovery(info, self.config.discovery.clone()).await?;
            self.discovery = Some(engine);
            if let Some(d) = self.discovery.as_ref() {
                let d = d.clone();
                let event_tx = self.event_tx.clone();
                let cancelled = self.cancelled.clone();
                let db = self.db.clone();
                let h = tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_millis(1000));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tick.tick().await;
                        if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                            break;
                        }
                        let fp_map = db
                            .lock()
                            .ok()
                            .map(|conn| crate::discovery::trusted_fp_map(&conn))
                            .unwrap_or_default();
                        for e in crate::discovery::drain_peer_events_named(&d, &fp_map) {
                            let _ = event_tx.send(e);
                        }
                        if let Ok(conn) = db.lock() {
                            let now = (d.now_ms() / 1000) as i64;
                            crate::discovery::refresh_trusted_on_beacon(&d, &conn, &fp_map, now);
                        }
                    }
                });
                *self.discovery_forwarder.lock().unwrap() = Some(h);
            }
            self.discover_probe_known().await?;
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> crate::Result<()> {
        tracing::info!("engine shutting down");
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(h) = self
            .discovery_forwarder
            .lock()
            .ok()
            .and_then(|mut g| g.take())
        {
            h.abort();
        }
        if let Some(d) = &self.discovery {
            let _ = d.stop().await;
        }
        self.shutdown_notify.notify_waiters();
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn shutdown_notify(&self) -> Arc<Notify> {
        self.shutdown_notify.clone()
    }

    pub fn transfer_registry(&self) -> &crate::TransferRegistry {
        &self.registry
    }

    pub fn active_transfer_ids(&self) -> Vec<String> {
        self.registry.active_ids()
    }

    pub fn offer_resolver(&self) -> &crate::OfferResolver {
        &self.offer_resolver
    }

    pub fn offer_resolver_arc(&self) -> std::sync::Arc<crate::OfferResolver> {
        self.offer_resolver.clone()
    }

    pub fn runtime(&self) -> &std::sync::Arc<crate::RuntimeSettings> {
        &self.runtime
    }

    pub async fn cancel_transfer(&self, tid: &str) -> crate::Result<()> {
        if self.registry.send(tid, crate::TransferCommand::Cancel) {
            Ok(())
        } else {
            Err(crate::CoreError::Internal(format!(
                "transfer {tid} not active"
            )))
        }
    }

    pub async fn pause_transfer(&self, tid: &str) -> crate::Result<()> {
        if self.registry.send(tid, crate::TransferCommand::Pause) {
            Ok(())
        } else {
            Err(crate::CoreError::Internal(format!(
                "transfer {tid} not active"
            )))
        }
    }

    pub async fn resume_transfer(&self, tid: &str) -> crate::Result<()> {
        if self.registry.send(tid, crate::TransferCommand::Resume) {
            Ok(())
        } else {
            Err(crate::CoreError::Internal(format!(
                "transfer {tid} not active"
            )))
        }
    }

    pub fn resolve_offer(&self, tid: &str, accept: crate::AcceptDecision) -> bool {
        self.offer_resolver.resolve(tid, accept)
    }
}
