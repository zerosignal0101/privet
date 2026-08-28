use privet_storage::{history, trust};

use serde::{Deserialize, Serialize};

use crate::Engine;

pub struct IdentityInfo {
    pub device_fingerprint: String,
    pub name: String,
}

impl Engine {
    pub fn identity_info(&self) -> IdentityInfo {
        IdentityInfo {
            device_fingerprint: self.identity().fingerprint(),
            name: self.engine_config().device_name.clone(),
        }
    }

    pub fn list_trusted(&self) -> crate::Result<Vec<trust::TrustRecord>> {
        let db = self.db_conn()?;
        Ok(trust::list_all(&db)?)
    }

    pub fn history(
        &self,
        peer: Option<&str>,
        limit: u64,
    ) -> crate::Result<Vec<history::HistoryRow>> {
        let db = self.db_conn()?;
        Ok(history::list_history(&db, peer, limit as i64)?)
    }

    pub fn history_detail(
        &self,
        transfer_id: &str,
    ) -> crate::Result<Option<history::HistoryDetailRow>> {
        let db = self.db_conn()?;
        Ok(history::get_history_detail(&db, transfer_id)?)
    }

    pub fn delete_history(&self, transfer_id: &str) -> crate::Result<()> {
        let db = self.db_conn()?;
        Ok(history::delete_history_entry(&db, transfer_id)?)
    }

    pub fn revoke_peer(&self, device_fingerprint: &str, reason: &str) -> crate::Result<()> {
        let now_ms = SystemPairingClock.now_ms();
        self.trust().revoke(device_fingerprint, reason, now_ms)?;
        Ok(())
    }

    pub fn forget_peer(&self, device_fingerprint: &str) -> crate::Result<()> {
        self.trust().forget(device_fingerprint)?;
        Ok(())
    }

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

#[derive(Debug, Clone)]
pub enum PeerTarget {
    ByDeviceFingerprint(String),
    ByAddr(std::net::SocketAddr),
}

#[derive(Debug, Clone)]
pub struct PeerAddr {
    pub addr: std::net::SocketAddr,
    pub device_fingerprint: Option<String>,
    pub peer_name: Option<String>,
    pub quic_port: u16,
    pub tcp_port: u16,
}

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

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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
use privet_transfer::receiver::ReceivedFileRecord;
use privet_transfer::CollisionPolicy;
use privet_transport::{Connection, Transport};

use crate::auth::{decide_auth, peer_session_inputs_with_config, AuthPlan};
use crate::connection::{
    acquire_control, acquire_data, hello_exchange_responder, ControlRole, DataRole,
};
use crate::pairing::{StreamPairingChannel, SystemPairingClock};
use crate::transfer::receive_over_connection;
use crate::EngineEvent;

pub struct SendOutcome {
    pub transfer_id: String,
    pub file_count: u64,
    pub total_bytes: u64,
}

#[derive(Clone)]
pub struct ServeOptions {
    pub save_dir: std::path::PathBuf,
    pub accept_all_trusted: bool,
    pub on_collision: CollisionPolicy,
    pub accept_policy: crate::AcceptPolicy,
}

pub struct ServeHandle {
    pub quic_addr: std::net::SocketAddr,
    pub tcp_addr: std::net::SocketAddr,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ServeHandle {
    pub async fn shutdown(mut self) {
        self.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
    }
}


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
    pub async fn send(
        &self,
        paths: Vec<std::path::PathBuf>,
        target: &PeerTarget,
        via: Option<std::net::IpAddr>,
        as_name: Option<&str>,
    ) -> crate::Result<SendOutcome> {
        let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let transfer_id = format!("t-{short_id}");
        self.send_with_id(paths, target, via, as_name, transfer_id).await
    }

    /// Send paths using a caller-allocated transfer ID.
    ///
    /// Daemon clients use this to receive an ID before the potentially long
    /// preparation and network phases begin, making cancellation and event
    /// correlation possible immediately.
    pub async fn send_with_id(
        &self,
        paths: Vec<std::path::PathBuf>,
        target: &PeerTarget,
        via: Option<std::net::IpAddr>,
        as_name: Option<&str>,
        transfer_id: String,
    ) -> crate::Result<SendOutcome> {
        let pa = self.resolve_peer(target, via)?;
        let cfg = self.engine_config().transfer.clone();
        let clock = SystemPairingClock;
        let now = clock.now_ms() as i64;

        if let Some(did) = &pa.device_fingerprint {
            let db = self.db_conn()?;
            let rec = privet_storage::trust::get_trust(&db, did)
                .map_err(crate::CoreError::Storage)?
                .ok_or_else(|| crate::CoreError::NotPaired(did.clone()))?;
            if rec.trust_state != "Trusted" {
                return Err(crate::CoreError::NotPaired(did.clone()));
            }
        }

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

        let prepared = prepare_paths(
            &paths,
            as_name,
            cfg.default_chunk_size,
            cfg.segment_max_chunks,
        )?;
        let file_count = prepared.summary.file_count;
        let total_bytes = prepared.summary.total_bytes;

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

        // Persist the per-file rows up-front so a partial/interrupted send still
        // lists its files (with source paths) in history — the resend flow
        // rebuilds the file set from these rows, and before this a partial send
        // had no file rows at all ("Files not found on disk" on resend).
        // `complete_history` upgrades them to "completed" once the transfer
        // finishes; if it never does, the rows stay as the "failed" sentinel but
        // still carry the source paths a resend needs.
        {
            let db = self.db_conn()?;
            let files: Vec<privet_storage::history::FileRow> = prepared
                .files
                .iter()
                .map(|f| privet_storage::history::FileRow {
                    file_id: &f.file_id,
                    relative_path: &f.relative_path,
                    size: f.size,
                    hash_type: Some("blake3"),
                    hash_value: Some(&f.file_hash),
                    status: "failed",
                    source_path: f.abs_path.to_str(),
                })
                .collect();
            privet_storage::history::insert_send_files(&db, &transfer_id, &files)
                .map_err(crate::CoreError::Storage)?;
        }

        self.do_send_inner(cfg, prepared, pa, transfer_id, file_count, total_bytes)
            .await
    }

    pub async fn resume_send(&self, transfer_id: &str) -> crate::Result<SendOutcome> {
        let row = {
            let db = self.db_conn()?;
            privet_storage::history::get_send_intent_row(&db, transfer_id)
                .map_err(crate::CoreError::Storage)?
        };
        let row = row.ok_or_else(|| {
            crate::CoreError::Internal(format!("transfer {transfer_id} not found"))
        })?;

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
        let blob = row.send_intent.filter(|b| !b.trim().is_empty()).ok_or_else(|| {
            crate::CoreError::Internal(format!(
                "transfer {transfer_id} has no send intent (not resumable)"
            ))
        })?;

        let intent: StoredSendIntent = serde_json::from_str(&blob)
            .map_err(|e| crate::CoreError::Internal(format!("send intent deser: {e}")))?;

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

    /// Start a new transfer from the paths and peer stored in a previous send-history row.
    pub async fn resend(&self, transfer_id: &str) -> crate::Result<SendOutcome> {
        let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let new_transfer_id = format!("t-{short_id}");
        self.resend_with_id(transfer_id, new_transfer_id).await
    }

    /// Resend a history item under a caller-allocated new transfer ID.
    pub async fn resend_with_id(
        &self,
        transfer_id: &str,
        new_transfer_id: String,
    ) -> crate::Result<SendOutcome> {
        let row = {
            let db = self.db_conn()?;
            privet_storage::history::get_send_intent_row(&db, transfer_id)
                .map_err(crate::CoreError::Storage)?
        }
        .ok_or_else(|| crate::CoreError::Internal(format!("transfer {transfer_id} not found")))?;
        if row.direction != "send" {
            return Err(crate::CoreError::Internal(format!(
                "transfer {transfer_id} is not a send"
            )));
        }
        let intent: StoredSendIntent = serde_json::from_str(
            row.send_intent
                .as_deref()
                .ok_or_else(|| crate::CoreError::Internal("history row has no send intent".into()))?,
        )
        .map_err(|error| crate::CoreError::Internal(format!("send intent deserialize: {error}")))?;
        let paths = intent.paths.into_iter().map(std::path::PathBuf::from).collect();
        let target = match intent.peer_target {
            StoredPeerTarget::DeviceFingerprint(id) => PeerTarget::ByDeviceFingerprint(id),
            StoredPeerTarget::Addr(address) => PeerTarget::ByAddr(
                address.parse().map_err(|error| {
                    crate::CoreError::Internal(format!("stored peer address: {error}"))
                })?,
            ),
        };
        self.send_with_id(
            paths,
            &target,
            None,
            row.root_name.as_deref(),
            new_transfer_id,
        )
        .await
    }

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
        let quic_addr = std::net::SocketAddr::new(pa.addr.ip(), pa.quic_port);
        let tcp_addr = std::net::SocketAddr::new(pa.addr.ip(), pa.tcp_port);
        let send_result = crate::transfer::send_with_reconnect_endpoints(
            self.quic.as_ref(),
            Some(self.tcp.as_ref()),
            quic_addr,
            tcp_addr,
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
        // A cancelled/declined send is NOT a completion. `run_sender` already
        // emitted `transfer_cancelled`, and the history row — inserted as
        // 'partial' at send-start — must stay 'partial' so the transfer can be
        // resumed (mirroring the receiver's own 'partial' row). Returning Ok
        // here also stops the daemon from publishing a spurious
        // `transfer_failed` on a cancellation the user already saw.
        match send_result {
            Err(crate::CoreError::Transfer(
                privet_transfer::TransferError::Cancelled(_)
                | privet_transfer::TransferError::Declined(_),
            )) => {
                return Ok(SendOutcome {
                    transfer_id,
                    file_count,
                    total_bytes,
                });
            }
            other => other?,
        }

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
                // Borrow the path directly: to_string_lossy() would return a
                // temporary Cow whose reference cannot outlive the closure.
                source_path: f.abs_path.to_str(),
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

        let runtime = self.runtime.clone();
        runtime.set_accept_all_trusted(opts.accept_all_trusted);
        runtime.set_base_accept_policy(opts.accept_policy.clone());
        runtime.set_on_collision(opts.on_collision);
        runtime.set_save_dir(opts.save_dir.clone());

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
            let pairing_cfg = self.engine_config().pairing.clone();
            let db = self.db.clone();
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
                        &platform,
                        &pairing_cfg,
                        db.clone(),
                    )
                    .await;
                }
            }
        }));

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
            let pairing_cfg = self.engine_config().pairing.clone();
            let db = self.db.clone();
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
                        &platform,
                        &pairing_cfg,
                        db.clone(),
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

/// Handle one authorized inbound connection for the daemon-owned engine.
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
    pairing_cfg: &privet_security::PairingConfig,
    db: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
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
            let accept_policy = runtime.effective_accept_policy();
            let on_collision = runtime.on_collision();
            let save_dir = runtime.save_dir();
            let data = acquire_data(conn.as_ref(), DataRole::Responder).await?;
            let mut store_cfg = cfg.clone();
            store_cfg.on_collision = on_collision;
            store_cfg.save_dir = save_dir.clone();
            // Persist receive history (partial on offer, completed with file
            // rows before the terminal event). The closures capture the DB, the
            // landing dir and the peer identity from the hello exchange.
            let history = {
                let peer_fp = hello.device_fingerprint.clone();
                let peer_name = hello.device_name.clone();
                let save_dir_str = save_dir.to_string_lossy().into_owned();
                let db_offer = db.clone();
                let db_complete = db.clone();
                let on_offer =
                    move |transfer_id: &str,
                          root_name: Option<String>,
                          file_count: u64,
                          total_bytes: u64| {
                        let now = now_secs();
                        match db_offer.lock() {
                            Ok(conn) => {
                                let r = history::insert_history(
                                    &conn,
                                    &history::NewTransfer {
                                        transfer_id,
                                        direction: history::TransferDirection::Receive,
                                        peer_device_fingerprint: Some(&peer_fp),
                                        peer_name: Some(&peer_name),
                                        root_name: root_name.as_deref(),
                                        file_count,
                                        total_bytes,
                                        status: history::TransferStatus::Partial,
                                        started_ts: now,
                                        save_dir: Some(&save_dir_str),
                                        send_intent: "{}",
                                    },
                                );
                                if let Err(e) = r {
                                    tracing::warn!(transfer_id, error = %e, "receive history: offer insert failed");
                                }
                            }
                            Err(e) => tracing::warn!(transfer_id, error = %e, "receive history: db lock"),
                        }
                    };
                let on_complete = move |transfer_id: &str, records: Vec<ReceivedFileRecord>| {
                    let now = now_secs();
                    match db_complete.lock() {
                        Ok(conn) => {
                            let files: Vec<history::FileRow<'_>> = records
                                .iter()
                                .map(|r| history::FileRow {
                                    file_id: &r.file_id,
                                    relative_path: &r.relative_path,
                                    size: r.size,
                                    hash_type: r.hash_type.as_deref(),
                                    hash_value: r.hash_value.as_deref(),
                                    status: &r.status,
                                    source_path: None,
                                })
                                .collect();
                            if let Err(e) = history::complete_history(&conn, transfer_id, &files, now) {
                                tracing::warn!(transfer_id, error = %e, "receive history: complete failed");
                            }
                        }
                        Err(e) => tracing::warn!(transfer_id, error = %e, "receive history: db lock"),
                    }
                };
                let db_fileset = db.clone();
                // The receiver only learned the file manifest after the offer
                // (FileSetBatch), so persist the per-file rows here — before
                // data flows — instead of only in complete_history. A partial/
                // interrupted receive then lists its files (with the landing
                // path) in history, mirroring insert_send_files on the send
                // side; complete_history upgrades the rows on success.
                let on_fileset = move |transfer_id: &str, entries: Vec<privet_protocol::FileEntry>| {
                    let files: Vec<history::FileRow<'_>> = entries
                        .iter()
                        .map(|e| history::FileRow {
                            file_id: &e.file_id,
                            relative_path: &e.relative_path,
                            size: e.size,
                            hash_type: if e.hash_type.is_empty() {
                                None
                            } else {
                                Some(e.hash_type.as_str())
                            },
                            hash_value: if e.hash_value.is_empty() {
                                None
                            } else {
                                Some(e.hash_value.as_str())
                            },
                            status: "failed",
                            source_path: None,
                        })
                        .collect();
                    match db_fileset.lock() {
                        Ok(conn) => {
                            if let Err(e) = history::insert_send_files(&conn, transfer_id, &files) {
                                tracing::warn!(transfer_id, error = %e, "receive history: fileset insert failed");
                            }
                        }
                        Err(e) => tracing::warn!(transfer_id, error = %e, "receive history: db lock"),
                    }
                };
                Some(privet_transfer::ReceiveHistory {
                    on_offer: Box::new(on_offer),
                    on_fileset: Box::new(on_fileset),
                    on_complete: Box::new(on_complete),
                })
            };
            let recv = receive_over_connection(
                ctrl,
                data,
                privet_transfer::FsPartStore::new(save_dir),
                store_cfg,
                event_tx,
                Some(registry),
                accept_policy,
                history,
            )
            .await;
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
                .take();
            match code {
                Some(mut code) => {
                    let inputs = match peer_session_inputs_with_config(
                        conn.as_ref(),
                        code.code().to_string(),
                        hello.device_fingerprint.clone(),
                        hello.device_name.clone(),
                        pairing_cfg,
                    ) {
                        Ok(inputs) => inputs,
                        Err(error) => {
                            if let Ok(mut slot) = pending.lock() {
                                *slot = Some(code);
                            }
                            return Err(error);
                        }
                    };
                    let mut ch = StreamPairingChannel::new(ctrl);
                    let clock = SystemPairingClock;
                    let pr = privet_security::session::run_responder_checked(
                        identity,
                        &inputs,
                        &mut code,
                        &mut ch,
                        &clock,
                        trust,
                        pake,
                    )
                    .await;
                    if !code.is_consumed()
                        && code.check_valid(clock.now_ms()).is_ok()
                    {
                        if let Ok(mut slot) = pending.lock() {
                            *slot = Some(code);
                        }
                    }
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

impl Engine {
    pub async fn pair_initiate(
        &self,
        addr: std::net::SocketAddr,
        code: String,
    ) -> crate::Result<privet_security::session::PairingOutcome> {
        self.pair_initiate_with_ports(addr, addr, code).await
    }

    /// Pair using the peer's independently advertised transport endpoints.
    pub async fn pair_initiate_with_ports(
        &self,
        quic_addr: std::net::SocketAddr,
        tcp_addr: std::net::SocketAddr,
        code: String,
    ) -> crate::Result<privet_security::session::PairingOutcome> {
        if quic_addr.ip() != tcp_addr.ip() {
            return Err(crate::CoreError::Internal(
                "QUIC and TCP pairing endpoints must use the same peer IP".into(),
            ));
        }
        let conn = crate::connection::connect_peer_with_ports(
            self.quic.as_ref(),
            Some(self.tcp.as_ref()),
            quic_addr,
            tcp_addr,
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
        let inputs = crate::auth::peer_session_inputs_with_config(
            conn.as_ref(),
            code,
            ack.device_fingerprint,
            ack.device_name,
            &self.engine_config().pairing,
        )?;
        let mut ch = StreamPairingChannel::new(ctrl);
        let clock = SystemPairingClock;
        let trust: &dyn privet_security::trust::TrustStore = self.trust.as_ref();
        let proof: &dyn privet_security::commit::ProofStore = self.trust.as_ref();
        let outcome = crate::pairing::run_pairing_initiator_with_config(
            self.identity(),
            &inputs,
            &mut ch,
            &clock,
            trust,
            proof,
            self.pake.as_ref(),
            &self.engine_config().pairing,
        )
        .await;
        if let Ok(privet_security::session::PairingOutcome::Paired { peer_device_fingerprint, .. }) =
            &outcome
        {
            let now = SystemPairingClock.now_ms() as i64 / 1000;
            if let Ok(db) = self.db_conn() {
                let _ = record_verified_address(
                    &db,
                    peer_device_fingerprint,
                    quic_addr.ip(),
                    quic_addr.port(),
                    tcp_addr.port(),
                    now,
                );
            }
        }
        outcome
    }

    pub fn set_pending_pair_code(&self, code: privet_security::code::PairingCode) {
        let mut g = self.pending_pair_code.lock().expect("pending code lock");
        *g = Some(code);
    }

    /// Generate and install a decimal code using this engine's pairing policy.
    pub fn generate_pairing_code(&self) -> crate::Result<String> {
        let clock = SystemPairingClock;
        let cfg = &self.engine_config().pairing;
        let code = privet_security::code::PairingCode::generate_decimal_with_policy(
            &clock,
            cfg.code_validity_secs,
            cfg.max_code_attempts,
        )?;
        let display = code.code().to_string();
        self.set_pending_pair_code(code);
        Ok(display)
    }

    pub fn discover_snapshot(&self) -> Vec<privet_discovery::peer::PeerRecord> {
        match &self.discovery {
            Some(d) => d.peers(),
            None => Vec::new(),
        }
    }

    pub async fn discover_refresh(&self) -> crate::Result<()> {
        if let Some(d) = &self.discovery {
            d.refresh().await.map_err(crate::CoreError::Discovery)?;
        }
        self.discover_probe_known().await?;
        Ok(())
    }

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
