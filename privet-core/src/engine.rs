//! Engine 完整装配：Identity + transports + discovery + db + trust/proof + pake + store + peer_pool + 事件总线 + 取消标志。
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
    /// 传输控制注册表：transfer_id -> 命令通道。
    pub(crate) registry: Arc<crate::TransferRegistry>,
    /// offer 裁决器：transfer_id -> 接受/拒绝。
    pub(crate) offer_resolver: Arc<crate::OfferResolver>,
    /// 运行时可变配置：acceptor 每连接读取；IPC SetConfig 写入。
    pub(crate) runtime: Arc<crate::RuntimeSettings>,
    /// discovery 事件转发任务句柄（shutdown 时 abort）。
    pub(crate) discovery_forwarder: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Engine {
    /// 构造引擎（生成 identity + TLS 材料 + 传输 + DB + 存储适配器）。
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
        // serve() 会按 ServeOptions 重新 seed；此初值仅在 serve 未调用时兜底。
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
            // serve() 会按 ServeOptions 重新 seed；此初值仅在 serve 未调用时兜底。
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

    /// 引擎配置（供 IPC backend 等外部使用）。
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

    /// 数据库连接（供 IPC backend 等外部使用）。
    pub fn db_conn(&self) -> crate::Result<std::sync::MutexGuard<'_, rusqlite::Connection>> {
        self.db
            .lock()
            .map_err(|_| crate::CoreError::Internal("db lock poisoned".into()))
    }

    /// 启动 I/O：崩溃恢复 + discovery（若配 udp_port）。
    pub async fn start(&mut self) -> crate::Result<()> {
        tracing::info!(device_fingerprint = %&self.identity.fingerprint(), "engine starting");
        // 崩溃恢复
        if let Ok(db) = privet_storage::migration::open_and_migrate(&self.config.db_path) {
            let _ = crate::transfer::recover_partial_transfers(&self.config.save_dir, &db);
        }
        // discovery（若配 udp_port）。
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
            // discovery peer 事件 -> EngineEvent 转发（修 drain_peer_events 死路径）。
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
                        // 先算 fp_map（trusted_fp_map），再用于事件解析 + 地址刷新，
                        // 使 device_discovered 事件携带真实 UUID 而非 fp_prefix
                        let fp_map = db
                            .lock()
                            .ok()
                            .map(|conn| crate::discovery::trusted_fp_map(&conn))
                            .unwrap_or_default();
                        for e in crate::discovery::drain_peer_events_named(&d, &fp_map) {
                            let _ = event_tx.send(e);
                        }
                        // beacon 命中已信任设备 -> best-effort 刷新地址簿。
                        if let Ok(conn) = db.lock() {
                            let now = (d.now_ms() / 1000) as i64;
                            crate::discovery::refresh_trusted_on_beacon(&d, &conn, &fp_map, now);
                        }
                    }
                });
                *self.discovery_forwarder.lock().unwrap() = Some(h);
            }
            // 启动时单播探测已知设备地址。
            self.discover_probe_known().await?;
        }
        Ok(())
    }

    /// 优雅关停（&self 因仅原子+notify，Arc<Engine> 可调用）。
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

    /// 传输控制注册表。
    pub fn transfer_registry(&self) -> &crate::TransferRegistry {
        &self.registry
    }

    /// offer 裁决器。
    pub fn offer_resolver(&self) -> &crate::OfferResolver {
        &self.offer_resolver
    }

    /// 返回 offer 裁决器的 Arc 克隆（供 daemon 构造 AcceptPolicy::Resolver）。
    pub fn offer_resolver_arc(&self) -> std::sync::Arc<crate::OfferResolver> {
        self.offer_resolver.clone()
    }

    /// 运行时可变配置：acceptor 每连接读取；IPC SetConfig 写入。
    pub fn runtime(&self) -> &std::sync::Arc<crate::RuntimeSettings> {
        &self.runtime
    }

    /// 取消活跃传输。返回 Err(Internal("not active")) 即无此 tid。
    pub async fn cancel_transfer(&self, tid: &str) -> crate::Result<()> {
        if self.registry.send(tid, crate::TransferCommand::Cancel) {
            Ok(())
        } else {
            Err(crate::CoreError::Internal(format!(
                "transfer {tid} not active"
            )))
        }
    }

    /// 暂停活跃传输。
    pub async fn pause_transfer(&self, tid: &str) -> crate::Result<()> {
        if self.registry.send(tid, crate::TransferCommand::Pause) {
            Ok(())
        } else {
            Err(crate::CoreError::Internal(format!(
                "transfer {tid} not active"
            )))
        }
    }

    /// 恢复暂停的传输。
    pub async fn resume_transfer(&self, tid: &str) -> crate::Result<()> {
        if self.registry.send(tid, crate::TransferCommand::Resume) {
            Ok(())
        } else {
            Err(crate::CoreError::Internal(format!(
                "transfer {tid} not active"
            )))
        }
    }

    /// 裁决一个待决的传输接受/拒绝。返回 false = 无待决 offer。
    pub fn resolve_offer(&self, tid: &str, accept: crate::AcceptDecision) -> bool {
        self.offer_resolver.resolve(tid, accept)
    }
}
