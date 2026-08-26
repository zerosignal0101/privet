//! Engine 高层操作（P6 前端入口）：读类查询 + send/serve/pair/discover 编排。
//! 模块级编排函数见 connection/auth/pairing/transfer/discovery；此文件把它们绑到 Engine 持有的组件。
use privet_storage::{history, trust};

use serde::{Deserialize, Serialize};

use crate::Engine;

/// 本机身份公开信息（无密钥）。
pub struct IdentityInfo {
    pub device_fingerprint: String,
    pub name: String,
}

impl Engine {
    /// 本机身份信息（device_fingerprint / 显示名 / 指纹前缀 8 hex）。
    pub fn identity_info(&self) -> IdentityInfo {
        IdentityInfo {
            device_fingerprint: self.identity().fingerprint(),
            name: self.engine_config().device_name.clone(),
        }
    }

    /// 全部信任记录（Trusted + Revoked）。
    pub fn list_trusted(&self) -> crate::Result<Vec<trust::TrustRecord>> {
        let db = self.db_conn()?;
        Ok(trust::list_all(&db)?)
    }

    /// 历史查询（peer=Some 过滤；limit 行数）。
    pub fn history(
        &self,
        peer: Option<&str>,
        limit: u64,
    ) -> crate::Result<Vec<history::HistoryRow>> {
        let db = self.db_conn()?;
        Ok(history::list_history(&db, peer, limit as i64)?)
    }

    /// 解析对端：device_fingerprint -> 信任+地址簿 recent_n\[0\]；ByAddr 直用。`via` 覆盖 IP（保留端口）。
    pub fn resolve_peer(
        &self,
        target: &PeerTarget,
        via: Option<std::net::IpAddr>,
    ) -> crate::Result<PeerAddr> {
        let db = self.db_conn()?;
        match target {
            PeerTarget::ByAddr(addr) => Ok(PeerAddr {
                addr: *addr,
                device_fingerprint: None,
                peer_name: None,
                quic_port: addr.port(),
                tcp_port: addr.port()
            }),
            PeerTarget::ByDeviceFingerprint(id) => {
                let rec = trust::get_trust(&db, id)
                    .map_err(crate::CoreError::Storage)?
                    .ok_or_else(|| crate::CoreError::NotPaired(id.clone()))?;
                if rec.trust_state != "Trusted" {
                    return Err(crate::CoreError::NotPaired(id.clone()));
                }
                let recs =
                    privet_storage::addresses::recent_known(&db, id, privet_storage::RECENT_N)
                        .map_err(crate::CoreError::Storage)?;
                let a = recs.first().ok_or_else(|| {
                    crate::CoreError::NotPaired(format!("{id}: no known address"))
                })?;
                let ip = via.unwrap_or_else(|| {
                    a.addr
                        .parse()
                        .unwrap_or_else(|_| "0.0.0.0".parse().unwrap())
                });
                let port = a.quic_port;
                let addr: std::net::SocketAddr = format!("{ip}:{port}").parse().map_err(|_| {
                    crate::CoreError::Internal(format!("bad peer addr {ip}:{port}"))
                })?;
                Ok(PeerAddr {
                    addr,
                    device_fingerprint: Some(id.clone()),
                    peer_name: Some(rec.peer_device_name.clone()),
                    quic_port: a.quic_port,
                    tcp_port: a.tcp_port
                })
            }
        }
    }
}

/// 对端定位（device_fingerprint 查地址簿，或直连 host:port）。
#[derive(Debug, Clone)]
pub enum PeerTarget {
    ByDeviceFingerprint(String),
    ByAddr(std::net::SocketAddr),
}

/// 解析后的对端地址。
#[derive(Debug, Clone)]
pub struct PeerAddr {
    pub addr: std::net::SocketAddr,
    pub device_fingerprint: Option<String>,
    pub peer_name: Option<String>,
    pub quic_port: u16,
    pub tcp_port: u16,
}

/// verified-success 后 upsert + inc_success 真实地址。
fn record_verified_address(
    db: &rusqlite::Connection,
    device_fingerprint: &str,
    ip: std::net::IpAddr,
    quic_port: u16,
    tcp_port: u16,
    now_secs: i64,
) -> crate::Result<()> {
    let subnet_cidr = subnet_for_peer(ip).unwrap_or_else(|| "0.0.0.0/0".to_string());
    let addr_str = ip.to_string();
    let pa = privet_storage::trust::PeerAddress {
        subnet_cidr: &subnet_cidr,
        gateway_ip: None,
        addr: &addr_str,
        quic_port,
        tcp_port,
        source: "self",
        last_seen_ts: now_secs,
    };
    privet_storage::addresses::upsert_address(db, device_fingerprint, &pa)
        .map_err(crate::CoreError::Storage)?;
    privet_storage::addresses::inc_success(db, device_fingerprint, &subnet_cidr, &addr_str, now_secs)
        .map_err(crate::CoreError::Storage)?;
    Ok(())
}

/// 取对端 IP 所落本机接口的子网 CIDR；无匹配返回 None。
pub(crate) fn subnet_for_peer(ip: std::net::IpAddr) -> Option<String> {
    let std::net::IpAddr::V4(v4) = ip else {
        return None;
    };
    let bits = u32::from(v4);
    for (addr, prefix, _, _) in privet_discovery::netinfo::enumerate_interfaces() {
        if let std::net::IpAddr::V4(a) = addr {
            let p = prefix.min(32);
            let mask = if p == 0 { 0 } else { !0u32 << (32 - p) };
            if u32::from(a) & mask == bits & mask {
                return Some(format!("{a}/{p}"));
            }
        }
    }
    None
}

/// 准备多路径文件集：文件用 prepare_single_file，目录用 prepare_dir，合并 files+dirs。
pub fn prepare_paths(
    paths: &[std::path::PathBuf],
    root_name: Option<&str>,
    chunk_size: u32,
    seg_max_chunks: u32,
) -> crate::Result<privet_transfer::PreparedSet> {
    let mut files: Vec<privet_transfer::prepare::PreparedFile> = Vec::new();
    let mut dirs: Vec<privet_protocol::DirEntry> = Vec::new();
    let mut total_bytes = 0u64;
    let mut next_offset = 0u64;
    for p in paths {
        let meta = std::fs::metadata(p).map_err(crate::CoreError::Io)?;
        if meta.is_dir() {
            let sub = privet_transfer::prepare_dir(
                p,
                root_name,
                next_offset,
                chunk_size,
                seg_max_chunks,
            )?;
            next_offset += sub.files.len() as u64;
            total_bytes += sub.summary.total_bytes;
            files.extend(sub.files);
            dirs.extend(sub.dirs);
        } else {
            let parent = p.parent().unwrap_or(std::path::Path::new("."));
            let rel = p.file_name().and_then(|s| s.to_str()).unwrap_or("file");
            let pf = privet_transfer::prepare_single_file(
                parent,
                rel,
                next_offset,
                chunk_size,
                seg_max_chunks,
            )?;
            next_offset += 1;
            total_bytes += pf.size;
            files.push(pf);
        }
    }
    let summary = privet_protocol::FileSetSummary {
        root_name: root_name.unwrap_or("").to_string(),
        file_count: files.len() as u64,
        total_bytes,
        dir_count: dirs.len() as u64,
    };
    Ok(privet_transfer::PreparedSet {
        root_name: root_name.map(|s| s.to_string()),
        files,
        dirs,
        summary,
    })
}

// ===== send + serve + ServeHandle =====

use std::sync::Arc;

use privet_security::cert::extract_spki;
use privet_security::code::Now;
use privet_transfer::CollisionPolicy;
use privet_transport::{Connection, Transport};

use crate::auth::{decide_auth, peer_session_inputs, AuthPlan};
use crate::connection::{
    acquire_control, acquire_data, hello_exchange_responder, ControlRole, DataRole,
};
use crate::pairing::{run_pairing_responder, StreamPairingChannel, SystemPairingClock};
use crate::transfer::receive_over_connection;
use crate::EngineEvent;

/// 发送结果。
pub struct SendOutcome {
    pub transfer_id: String,
    pub file_count: u64,
    pub total_bytes: u64,
}

/// 入站接收选项。
#[derive(Clone)]
pub struct ServeOptions {
    pub save_dir: std::path::PathBuf,
    pub accept_all_trusted: bool,
    pub on_collision: CollisionPolicy,
    /// 接受策略：CLI 嵌入 = AutoAccept；守护进程 = Resolver。
    pub accept_policy: crate::AcceptPolicy,
}

/// 入站服务句柄（持监听 addr + 取消）。
pub struct ServeHandle {
    pub quic_addr: std::net::SocketAddr,
    pub tcp_addr: std::net::SocketAddr,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ServeHandle {
    /// 优雅关停：置取消 + 等任务退出。
    pub async fn shutdown(mut self) {
        self.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
    }
}

// ===== 续传意图持久化 =====

/// 发送意图的 DB 持久化格式（不透明 JSON blob，storage 层不解析）。
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredSendIntent {
    pub paths: Vec<String>,
    pub chunk_size: u32,
    pub segment_max_chunks: u32,
    pub peer_target: StoredPeerTarget,
}

#[derive(Serialize, Deserialize)]
pub(crate) enum StoredPeerTarget {
    DeviceFingerprint(String),
    Addr(String),
}

impl From<&PeerTarget> for StoredPeerTarget {
    fn from(t: &PeerTarget) -> Self {
        match t {
            PeerTarget::ByDeviceFingerprint(id) => StoredPeerTarget::DeviceFingerprint(id.clone()),
            PeerTarget::ByAddr(a) => StoredPeerTarget::Addr(a.to_string()),
        }
    }
}

impl Engine {
    /// 发送：准备 -> 连接 -> Hello -> 鉴权（已信任免码直发）-> send_with_reconnect -> 写发送历史。
    /// 发起时持久化 Partial 行 + send_intent blob，供 `privet resume <tid>` 续传。
    pub async fn send(
        &self,
        paths: Vec<std::path::PathBuf>,
        target: &PeerTarget,
        via: Option<std::net::IpAddr>,
        as_name: Option<&str>,
    ) -> crate::Result<SendOutcome> {
        let pa = self.resolve_peer(target, via)?;
        let cfg = self.engine_config().transfer.clone();
        let clock = SystemPairingClock;
        let now = clock.now_ms() as i64;
        let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let transfer_id = format!("t-{short_id}");

        // ByDeviceId 时校验信任状态；ByAddr 直发。
        if let Some(did) = &pa.device_fingerprint {
            let db = self.db_conn()?;
            let rec = privet_storage::trust::get_trust(&db, did)
                .map_err(crate::CoreError::Storage)?
                .ok_or_else(|| crate::CoreError::NotPaired(did.clone()))?;
            if rec.trust_state != "Trusted" {
                return Err(crate::CoreError::NotPaired(did.clone()));
            }
        }

        // 在 prepare_paths（BLAKE3 全文件哈希，大文件耗时数秒）之前就先持久化
        // send_intent 意图 + 空 partial 行，确保中断时起码有记录可续传。
        {
            let intent = StoredSendIntent {
                paths: paths
                    .iter()
                    .map(|p| {
                        std::fs::canonicalize(p)
                            .map(|a| a.to_string_lossy().into_owned())
                            .unwrap_or_else(|_| p.to_string_lossy().into_owned())
                    })
                    .collect(),
                chunk_size: cfg.default_chunk_size,
                segment_max_chunks: cfg.segment_max_chunks,
                peer_target: StoredPeerTarget::from(target),
            };
            let blob = serde_json::to_string(&intent)
                .map_err(|e| crate::CoreError::Internal(format!("send intent serde: {e}")))?;
            let db = self.db_conn()?;
            privet_storage::history::insert_history(
                &db,
                &privet_storage::history::NewTransfer {
                    transfer_id: &transfer_id,
                    direction: privet_storage::history::TransferDirection::Send,
                    peer_device_fingerprint: pa.device_fingerprint.as_deref(),
                    peer_name: pa.peer_name.as_deref(),
                    root_name: as_name,
                    file_count: 0,
                    total_bytes: 0,
                    status: privet_storage::history::TransferStatus::Partial,
                    started_ts: now,
                    save_dir: None,
                    send_intent: &blob
                },
            )
            .map_err(crate::CoreError::Storage)?;
        }

        // 现在做 prepare（BLAKE3 哈希，大文件可能耗时 > 5 秒）；若中断，上述 partial 行可续。
        let prepared = prepare_paths(
            &paths,
            as_name,
            cfg.default_chunk_size,
            cfg.segment_max_chunks,
        )?;
        let file_count = prepared.summary.file_count;
        let total_bytes = prepared.summary.total_bytes;

        // 更新 partial 行中的实际计数（prepare 后已知）。
        {
            let db = self.db_conn()?;
            privet_storage::history::update_send_counts(
                &db,
                &transfer_id,
                file_count,
                total_bytes,
                prepared.root_name.as_deref().or(as_name),
            )
            .map_err(crate::CoreError::Storage)?;
        }

        // 共用发送尾段（registry + send_with_reconnect + complete_history）。
        self.do_send_inner(cfg, prepared, pa, transfer_id, file_count, total_bytes)
            .await
    }

    /// 按 transfer_id 手动续传中断的发送
    /// 从 DB 读 persist 的 send_intent blob → 重建 prepared → 同上 transfer_id 重连 → receiver 自动续传。
    pub async fn resume_send(&self, transfer_id: &str) -> crate::Result<SendOutcome> {
        // 1. 查续传意图
        let row = {
            let db = self.db_conn()?;
            privet_storage::history::get_send_intent_row(&db, transfer_id)
                .map_err(crate::CoreError::Storage)?
        };
        let row = row.ok_or_else(|| {
            crate::CoreError::Internal(format!("transfer {transfer_id} not found"))
        })?;

        // 2. 校验状态
        if row.direction != "send" {
            return Err(crate::CoreError::Internal(format!(
                "transfer {transfer_id} is not a send (resume requires send direction)"
            )));
        }
        if row.status != "partial" {
            return Err(crate::CoreError::Internal(format!(
                "transfer {transfer_id} is not resumable: status={}",
                row.status
            )));
        }
        let blob = row.send_intent.ok_or_else(|| {
            crate::CoreError::Internal(format!(
                "transfer {transfer_id} has no send intent (not resumable)"
            ))
        })?;

        // 3. 反序列化 intent
        let intent: StoredSendIntent = serde_json::from_str(&blob)
            .map_err(|e| crate::CoreError::Internal(format!("send intent deser: {e}")))?;

        // 4. 重建 PreparedSet（same tid + same paths → receiver 自动续传）
        let root_name = row.root_name.as_deref();
        let paths: Vec<std::path::PathBuf> =
            intent.paths.iter().map(std::path::PathBuf::from).collect();
        let prepared = prepare_paths(
            &paths,
            root_name,
            intent.chunk_size,
            intent.segment_max_chunks,
        )?;
        let file_count = prepared.summary.file_count;
        let total_bytes = prepared.summary.total_bytes;

        // 5. 重建对端目标（PeerTarget -> resolve_peer -> 查地址簿最新 addr）
        let target = match &intent.peer_target {
            StoredPeerTarget::DeviceFingerprint(id) => PeerTarget::ByDeviceFingerprint(id.clone()),
            StoredPeerTarget::Addr(a) => {
                let addr: std::net::SocketAddr = a.parse().map_err(|e| {
                    crate::CoreError::Internal(format!("stored peer addr parse: {e}"))
                })?;
                PeerTarget::ByAddr(addr)
            }
        };
        let pa = self.resolve_peer(&target, None)?;

        // 6. 发送（行已在，complete_history 会 UPDATE 到 completed）
        let cfg = self.engine_config().transfer.clone();
        self.do_send_inner(
            cfg,
            prepared,
            pa,
            transfer_id.to_string(),
            file_count,
            total_bytes,
        )
        .await
    }

    /// 内部发送尾段（registry + send_with_reconnect + complete_history）。
    /// 为 send 和 resume_send 共用，避免重复。
    async fn do_send_inner(
        &self,
        cfg: privet_transfer::TransferEngineConfig,
        prepared: privet_transfer::PreparedSet,
        pa: PeerAddr,
        transfer_id: String,
        file_count: u64,
        total_bytes: u64,
    ) -> crate::Result<SendOutcome> {
        let mut backoff = crate::reconnect::Backoff::new();
        let cmd_rx = self.registry.register(&transfer_id);
        let send_result = crate::transfer::send_with_reconnect(
            self.quic.as_ref(),
            Some(self.tcp.as_ref()),
            pa.addr,
            self.engine_config().transport.mode,
            self.identity(),
            &self.engine_config().device_name,
            prepared.clone(),
            cfg,
            self.event_tx.clone(),
            transfer_id.clone(),
            &mut backoff,
            Some(cmd_rx),
        )
        .await;
        self.registry.unregister(&transfer_id);
        send_result?;

        // verified-success：pinning 已通过（连接成功），upsert + inc_success 真实地址。
        if let Some(did) = &pa.device_fingerprint {
            let now = SystemPairingClock.now_ms() as i64 / 1000;
            if let Ok(db) = self.db_conn() {
                let _ = record_verified_address(
                    &db,
                    did,
                    pa.addr.ip(),
                    pa.quic_port,
                    pa.tcp_port,
                    now,
                );
            }
        }

        // 行已在 send / resume_send 建好，complete_history -> UPDATE status='completed'
        let clock = SystemPairingClock;
        let now = clock.now_ms() as i64;
        let files: Vec<privet_storage::history::FileRow> = prepared
            .files
            .iter()
            .map(|f| privet_storage::history::FileRow {
                file_id: &f.file_id,
                relative_path: &f.relative_path,
                size: f.size,
                hash_type: "blake3".into(),
                hash_value: Some(&f.file_hash),
                status: "completed",
            })
            .collect();
        {
            let db = self.db_conn()?;
            privet_storage::history::complete_history(&db, &transfer_id, &files, now)
                .map_err(crate::CoreError::Storage)?;
        }

        Ok(SendOutcome {
            transfer_id,
            file_count,
            total_bytes,
        })
    }

    /// 入站服务：绑 QUIC+TCP 监听（config 端口，0=ephemeral）-> 双 acceptor 任务。每连接 -> handle_inbound。
    pub async fn serve(&self, opts: ServeOptions) -> crate::Result<ServeHandle> {
        let quic_addr: std::net::SocketAddr = format!("0.0.0.0:{}", self.engine_config().transport.quic_port)
            .parse()
            .unwrap();
        let tcp_addr: std::net::SocketAddr = format!("0.0.0.0:{}", self.engine_config().transport.tcp_port)
            .parse()
            .unwrap();
        let ql = self.quic.bind(quic_addr).await?;
        let tl = self.tcp.bind(tcp_addr).await?;
        let quic_addr = ql.local_addr().await?;
        let tcp_addr = tl.local_addr().await?;

        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut tasks = Vec::new();

        // serve 启动时把 ServeOptions seed 进运行时设置；acceptor 每连接读取当前值，
        // 使 IPC SetConfig 可立即改变入站行为（accept_all_trusted / on_collision / save_dir）。
        let runtime = self.runtime.clone();
        runtime.set_accept_all_trusted(opts.accept_all_trusted);
        runtime.set_base_accept_policy(opts.accept_policy.clone());
        runtime.set_on_collision(opts.on_collision);
        runtime.set_save_dir(opts.save_dir.clone());

        // QUIC acceptor 任务（顺序处理，一行连接处理完再 accept 下一）。
        let device_name = self.engine_config().device_name.clone();
        let platform = self.engine_config().platform.clone();
        tasks.push(tokio::spawn({
            let cancel = cancel.clone();
            let identity = self.identity.clone();
            let trust = self.trust.clone();
            let cfg = self.engine_config().transfer.clone();
            let event_tx = self.event_tx.clone();
            let registry = self.registry.clone();
            let runtime = runtime.clone();
            let device_name = device_name.clone();
            let pending = self.pending_pair_code.clone();
            let pake = self.pake.clone();
            async move {
                loop {
                    if cancel.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let conn = match tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        ql.accept(),
                    )
                    .await
                    {
                        Ok(Ok(c)) => c,
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "quic accept error");
                            continue;
                        }
                        Err(_) => continue,
                    };
                    let _ = handle_inbound(
                        conn,
                        identity.as_ref(),
                        trust.as_ref(),
                        cfg.clone(),
                        event_tx.clone(),
                        pending.as_ref(),
                        pake.as_ref(),
                        registry.clone(),
                        runtime.clone(),
                        &device_name,
                        &platform
                    )
                    .await;
                }
            }
        }));

        // TCP acceptor 任务（同理，顺序处理）。
        let device_name = self.engine_config().device_name.clone();
        let platform = self.engine_config().platform.clone();
        tasks.push(tokio::spawn({
            let cancel = cancel.clone();
            let identity = self.identity.clone();
            let trust = self.trust.clone();
            let cfg = self.engine_config().transfer.clone();
            let event_tx = self.event_tx.clone();
            let registry = self.registry.clone();
            let runtime = runtime.clone();
            let device_name = device_name.clone();
            let platform = platform.clone();
            let pending = self.pending_pair_code.clone();
            let pake = self.pake.clone();
            async move {
                loop {
                    if cancel.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let conn = match tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        tl.accept(),
                    )
                    .await
                    {
                        Ok(Ok(c)) => c,
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "tcp accept error");
                            continue;
                        }
                        Err(_) => continue,
                    };
                    let _ = handle_inbound(
                        conn,
                        identity.as_ref(),
                        trust.as_ref(),
                        cfg.clone(),
                        event_tx.clone(),
                        pending.as_ref(),
                        pake.as_ref(),
                        registry.clone(),
                        runtime.clone(),
                        &device_name,
                        &platform
                    )
                    .await;
                }
            }
        }));

        Ok(ServeHandle {
            quic_addr,
            tcp_addr,
            cancel,
            tasks,
        })
    }
}

/// 入站单连接处理（serve 的每连接子任务）。
///
/// 接受策略 / 冲突策略 / 落地目录均从 `runtime` 每连接读取，使 IPC SetConfig
/// 能在 serve 运行期即时改变入站行为。
#[allow(clippy::too_many_arguments)]
async fn handle_inbound(
    conn: Box<dyn Connection>,
    identity: &privet_crypto::identity::Identity,
    trust: &dyn privet_security::trust::TrustStore,
    cfg: privet_transfer::TransferEngineConfig,
    event_tx: tokio::sync::broadcast::Sender<EngineEvent>,
    pending: &std::sync::Mutex<Option<privet_security::code::PairingCode>>,
    pake: &privet_crypto::pake::Spake2Backend,
    registry: std::sync::Arc<crate::TransferRegistry>,
    runtime: std::sync::Arc<crate::RuntimeSettings>,
    device_name: &str,
    platform: &str,
) -> crate::Result<()> {
    let mut ctrl = acquire_control(conn.as_ref(), ControlRole::Responder).await?;
    let hello = hello_exchange_responder(ctrl.as_mut(), identity, 1, device_name, platform).await?;
    let cert = conn
        .peer_cert_der()
        .ok_or_else(|| crate::CoreError::Internal("peer cert unavailable".into()))?;
    let peer_spki = extract_spki(&cert)?;
    let plan = decide_auth(&peer_spki, &hello.device_fingerprint, trust)?;
    match plan {
        AuthPlan::AcceptCodeless => {
            tracing::info!("inbound: trusted peer, codeless accept");
            // 每连接读运行时设置（IPC SetConfig 可即时改变）。
            let accept_policy = runtime.effective_accept_policy();
            let on_collision = runtime.on_collision();
            let save_dir = runtime.save_dir();
            let data = acquire_data(conn.as_ref(), DataRole::Responder).await?;
            let mut store_cfg = cfg.clone();
            store_cfg.on_collision = on_collision;
            store_cfg.save_dir = save_dir.clone();
            let recv = receive_over_connection(
                ctrl,
                data,
                privet_transfer::FsPartStore::new(save_dir),
                store_cfg,
                event_tx,
                Some(registry),
                accept_policy,
            )
            .await;
            // 短暂延迟，让发送方完成 ack 后再关连接（防 TransportLost）。
            if recv.is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            recv
        }
        AuthPlan::TriggerPairing => {
            tracing::info!("inbound: unknown peer, trigger pairing");
            let code = pending
                .lock()
                .map_err(|_| crate::CoreError::Internal("code lock".into()))?
                .as_ref()
                .map(|c| c.code().to_string());
            match code {
                Some(code) => {
                    let inputs = peer_session_inputs(
                        conn.as_ref(),
                        code,
                        hello.device_fingerprint.clone(),
                        hello.device_name.clone(),
                    )?;
                    let mut ch = StreamPairingChannel::new(ctrl);
                    let clock = SystemPairingClock;
                    let pr = run_pairing_responder(identity, &inputs, &mut ch, &clock, trust, pake)
                        .await;
                    let _ = pr?;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    Ok(())
                }
                None => {
                    let _ = event_tx.send(EngineEvent::PairingResult {
                        device_fingerprint: hello.device_fingerprint,
                        success: false,
                        error: Some("no pending pairing".into()),
                    });
                    Ok(())
                }
            }
        }
        AuthPlan::Reject | AuthPlan::FailClosedAlert => {
            tracing::warn!("inbound: rejected/fail-closed");
            let _ = event_tx.send(EngineEvent::PairingResult {
                device_fingerprint: hello.device_fingerprint,
                success: false,
                error: Some("rejected".into()),
            });
            Ok(())
        }
    }
}

/// 设置待配对码（serve 的 TriggerPairing 分支用）。
impl Engine {
    /// 发起配对：连接 -> Hello -> peer_session_inputs（带 code）-> run_pairing_initiator。
    pub async fn pair_initiate(
        &self,
        addr: std::net::SocketAddr,
        code: String,
    ) -> crate::Result<privet_security::session::PairingOutcome> {
        let conn = crate::connection::connect_peer(
            self.quic.as_ref(),
            Some(self.tcp.as_ref()),
            addr,
            self.engine_config().transport.mode,
            None,
        )
        .await?;
        let mut ctrl =
            crate::connection::acquire_control(conn.as_ref(), ControlRole::Initiator).await?;
        let ack = crate::connection::hello_exchange(
            ctrl.as_mut(),
            self.identity(),
            1,
            &self.engine_config().device_name,
        )
        .await?;
        let inputs =
            crate::auth::peer_session_inputs(conn.as_ref(), code, ack.device_fingerprint, ack.device_name)?;
        let mut ch = StreamPairingChannel::new(ctrl);
        let clock = SystemPairingClock;
        let trust: &dyn privet_security::trust::TrustStore = self.trust.as_ref();
        let proof: &dyn privet_security::commit::ProofStore = self.trust.as_ref();
        let outcome = crate::pairing::run_pairing_initiator(
            self.identity(),
            &inputs,
            &mut ch,
            &clock,
            trust,
            proof,
            self.pake.as_ref(),
        )
        .await;
        // bootstrap：配对成功时记录实际情况地址。
        if let Ok(privet_security::session::PairingOutcome::Paired { peer_device_fingerprint, .. }) =
            &outcome
        {
            let now = SystemPairingClock.now_ms() as i64 / 1000;
            if let Ok(db) = self.db_conn() {
                let _ = record_verified_address(
                    &db,
                    peer_device_fingerprint,
                    addr.ip(),
                    addr.port(),
                    addr.port(),
                    now,
                );
            }
        }
        outcome
    }

    /// 设置待配对码（serve 的 TriggerPairing 分支用）。
    pub fn set_pending_pair_code(&self, code: privet_security::code::PairingCode) {
        let mut g = self.pending_pair_code.lock().expect("pending code lock");
        *g = Some(code);
    }

    /// 当前可见对端快照（无 discovery 则空）。
    pub fn discover_snapshot(&self) -> Vec<privet_discovery::peer::PeerRecord> {
        match &self.discovery {
            Some(d) => d.peers(),
            None => Vec::new(),
        }
    }

    /// 主动刷新（发 Probe / 单播已知设备 / 触发 mDNS browse）。无 discovery 则空操作。
    pub async fn discover_refresh(&self) -> crate::Result<()> {
        if let Some(d) = &self.discovery {
            d.refresh().await.map_err(crate::CoreError::Discovery)?;
        }
        self.discover_probe_known().await?;
        Ok(())
    }

    /// 对地址簿中已知（已信任）设备的近邻地址单播 Probe（受限网络可达性）。
    /// 仅在 known.probe_known=true 时执行；所有模式（含 TrustedOnly）生效。
    pub async fn discover_probe_known(&self) -> crate::Result<()> {
        let Some(d) = &self.discovery else {
            return Ok(());
        };
        if !self.engine_config().discovery.known.probe_known {
            return Ok(());
        }
        let port = self.engine_config().discovery.udp_port;
        let rows = {
            let db = self.db_conn()?;
            privet_storage::addresses::list_known(&db, privet_storage::RECENT_N)
                .map_err(crate::CoreError::Storage)?
        };
        for (device_fingerprint, a) in rows {
            let trusted = {
                let db = self.db_conn()?;
                privet_storage::trust::get_trust(&db, &device_fingerprint)
                    .map_err(crate::CoreError::Storage)?
                    .is_some_and(|r| r.trust_state == "Trusted")
            };
            if !trusted {
                continue;
            }
            if let Ok(ip) = a.addr.parse::<std::net::IpAddr>() {
                d.send_probe_to(std::net::SocketAddr::new(ip, port)).await;
            }
        }
        Ok(())
    }

    /// 排空 discovery peer 事件 -> EngineEvent（forwarder 周期调用；保留供测试直接调用）。
    pub fn drain_peer_events(&self) -> Vec<EngineEvent> {
        let fp_map = self
            .db
            .lock()
            .ok()
            .map(|conn| crate::discovery::trusted_fp_map(&conn))
            .unwrap_or_default();
        match &self.discovery {
            Some(d) => crate::discovery::drain_peer_events_named(d, &fp_map),
            None => Vec::new(),
        }
    }
}
