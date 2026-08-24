//! trust_store 仓库。

use crate::error::StorageError;

pub struct PeerTrust<'a> {
    pub device_fingerprint: &'a str,
    pub peer_spki: &'a [u8],
    pub peer_device_name: &'a str,
    pub share_with_peers: bool,
    pub first_paired_ts: i64,
    pub last_seen_ts: i64,
}

pub struct PeerAddress<'a> {
    pub subnet_cidr: &'a str,
    pub gateway_ip: Option<&'a str>,
    pub addr: &'a str,
    pub quic_port: u16,
    pub tcp_port: u16,
    pub source: &'a str,
    pub last_seen_ts: i64,
}

pub struct TrustRecord {
    pub device_fingerprint: String,
    pub peer_spki: Vec<u8>,
    pub peer_device_name: String,
    pub trust_state: String,
    pub share_with_peers: bool,
    pub first_paired_ts: i64,
    pub last_seen_ts: i64,
    pub revoked_ts: Option<i64>,
    pub revocation_reason: Option<String>,
}

/// 配对成功原子事务：INSERT trust_store + INSERT known_device_addresses 同 tx（P5 §5）。
pub fn insert_paired(
    conn: &rusqlite::Connection,
    trust: &PeerTrust,
    address: &PeerAddress,
) -> Result<(), StorageError> {
    let tx = conn.unchecked_transaction()?;
    let res = (|| -> Result<(), rusqlite::Error> {
        tx.execute(
            "INSERT INTO trust_store
               (device_fingerprint, peer_spki, peer_device_name, trust_state, share_with_peers,
                first_paired_ts, last_seen_ts)
             VALUES (?1, ?2, ?3, 'Trusted', ?4, ?5, ?6)",
            rusqlite::params![
                trust.device_fingerprint,
                trust.peer_spki,
                trust.peer_device_name,
                trust.share_with_peers as i64,
                trust.first_paired_ts,
                trust.last_seen_ts,
            ],
        )?;
        tx.execute(
            "INSERT INTO known_device_addresses
               (device_fingerprint, subnet_cidr, gateway_ip, addr, quic_port, tcp_port, source, last_seen_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                trust.device_fingerprint,
                address.subnet_cidr,
                address.gateway_ip,
                address.addr,
                address.quic_port,
                address.tcp_port,
                address.source,
                address.last_seen_ts,
            ],
        )?;
        Ok(())
    })();
    match res {
        Ok(()) => tx.commit().map_err(Into::into),
        Err(e) => {
            let _ = tx.rollback();
            Err(e.into())
        }
    }
}

/// 仅写 trust_store 行（不写占位地址行）；地址由 verified-success 路径单独写（§8.4）。
pub fn insert_trust(conn: &rusqlite::Connection, trust: &PeerTrust) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO trust_store
           (device_fingerprint, peer_spki, peer_device_name, trust_state, share_with_peers,
            first_paired_ts, last_seen_ts)
         VALUES (?1, ?2, ?3, 'Trusted', ?4, ?5, ?6)",
        rusqlite::params![
            trust.device_fingerprint,
            trust.peer_spki,
            trust.peer_device_name,
            trust.share_with_peers as i64,
            trust.first_paired_ts,
            trust.last_seen_ts,
        ],
    )?;
    Ok(())
}

pub fn get_trust(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
) -> Result<Option<TrustRecord>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT device_fingerprint, peer_spki, peer_device_name, trust_state, share_with_peers,
                first_paired_ts, last_seen_ts, revoked_ts, revocation_reason
         FROM trust_store WHERE device_fingerprint = ?1",
    )?;
    let mut rows = stmt.query(rusqlite::params![device_fingerprint])?;
    match rows.next()? {
        Some(r) => Ok(Some(TrustRecord {
            device_fingerprint: r.get(0)?,
            peer_spki: r.get(1)?,
            peer_device_name: r.get(2)?,
            trust_state: r.get(3)?,
            share_with_peers: r.get::<_, i64>(4)? != 0,
            first_paired_ts: r.get(5)?,
            last_seen_ts: r.get(6)?,
            revoked_ts: r.get(7)?,
            revocation_reason: r.get(8)?,
        })),
        None => Ok(None),
    }
}

pub fn revoke(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
    reason: &str,
    revoked_ts: i64,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE trust_store SET trust_state='Revoked', revoked_ts=?1, revocation_reason=?2
         WHERE device_fingerprint=?3",
        rusqlite::params![revoked_ts, reason, device_fingerprint],
    )?;
    Ok(())
}

/// 忘记设备：删 trust_store -> CASCADE 删 addresses；transfer_history.peer_device_fingerprint SET NULL（保留 peer_name）（P5 §6）。
pub fn forget(conn: &rusqlite::Connection, device_fingerprint: &str) -> Result<(), StorageError> {
    conn.execute(
        "DELETE FROM trust_store WHERE device_fingerprint=?1",
        rusqlite::params![device_fingerprint],
    )?;
    Ok(())
}

/// 每次 pinning 通过的已认证连接更新 last_seen + name（P5 §3.2 Q5）。
pub fn refresh_seen(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
    peer_device_name: &str,
    last_seen_ts: i64,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE trust_store SET last_seen_ts=?1, peer_device_name=?2 WHERE device_fingerprint=?3",
        rusqlite::params![last_seen_ts, peer_device_name, device_fingerprint],
    )?;
    Ok(())
}

/// 陈旧信任 GC 候选：last_seen_ts < now - stale_days*86400（P5 §6，测试 9）。
pub fn gc_stale_candidates(
    conn: &rusqlite::Connection,
    now_ts: i64,
    stale_days: i64,
) -> Result<Vec<String>, StorageError> {
    let threshold = now_ts - stale_days * 86400;
    let mut stmt = conn.prepare("SELECT device_fingerprint FROM trust_store WHERE last_seen_ts < ?1")?;
    let rows = stmt.query_map(rusqlite::params![threshold], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// 列出全部信任记录（Trusted + Revoked；P5 §3.2，CLI list-trusted 用）。
pub fn list_all(conn: &rusqlite::Connection) -> Result<Vec<TrustRecord>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT device_fingerprint, peer_spki, peer_device_name, trust_state, share_with_peers,
                first_paired_ts, last_seen_ts, revoked_ts, revocation_reason
         FROM trust_store ORDER BY peer_device_name COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(TrustRecord {
            device_fingerprint: r.get(0)?,
            peer_spki: r.get(1)?,
            peer_device_name: r.get(2)?,
            trust_state: r.get(3)?,
            share_with_peers: r.get::<_, i64>(4)? != 0,
            first_paired_ts: r.get(5)?,
            last_seen_ts: r.get(6)?,
            revoked_ts: r.get(7)?,
            revocation_reason: r.get(8)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> rusqlite::Connection {
        let conn = crate::db::open_in_memory().unwrap();
        crate::migration::run_migrations(&conn, crate::migration::MIGRATIONS).unwrap();
        conn
    }

    fn sample_trust<'a>(id: &'a str) -> PeerTrust<'a> {
        PeerTrust {
            device_fingerprint: id,
            peer_spki: &[1, 2, 3],
            peer_device_name: "peer",
            share_with_peers: false,
            first_paired_ts: 100,
            last_seen_ts: 100,
        }
    }
    fn sample_addr<'a>() -> PeerAddress<'a> {
        PeerAddress {
            subnet_cidr: "10.0.0.0/24",
            gateway_ip: Some("10.0.0.1"),
            addr: "10.0.0.5",
            quic_port: 47808,
            tcp_port: 47810,
            source: "self",
            last_seen_ts: 100,
        }
    }

    #[test]
    fn insert_paired_then_get_matches() {
        let conn = db();
        insert_paired(&conn, &sample_trust("dev1"), &sample_addr()).unwrap();
        let r = get_trust(&conn, "dev1").unwrap().unwrap();
        assert_eq!(r.device_fingerprint, "dev1");
        assert_eq!(r.peer_spki, vec![1, 2, 3]);
        assert_eq!(r.trust_state, "Trusted");
        assert!(!r.share_with_peers);
    }

    #[test]
    fn insert_paired_atomic_rollback_on_dup() {
        let conn = db();
        insert_paired(&conn, &sample_trust("dev1"), &sample_addr()).unwrap();
        // 重复 device_fingerprint -> trust_store PK 冲突 -> 整 tx 回滚（address 也不增）
        let err = insert_paired(&conn, &sample_trust("dev1"), &sample_addr());
        assert!(err.is_err());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM known_device_addresses", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 1); // 仍只有第一条
    }

    #[test]
    fn revoke_flips_state_and_sets_revoked_ts() {
        let conn = db();
        insert_paired(&conn, &sample_trust("dev1"), &sample_addr()).unwrap();
        revoke(&conn, "dev1", "user_request", 999).unwrap();
        let r = get_trust(&conn, "dev1").unwrap().unwrap();
        assert_eq!(r.trust_state, "Revoked");
        assert_eq!(r.revoked_ts, Some(999));
        assert_eq!(r.revocation_reason.as_deref(), Some("user_request"));
    }

    #[test]
    fn forget_cascades_addresses_and_nulls_history_peer() {
        let conn = db();
        insert_paired(&conn, &sample_trust("dev1"), &sample_addr()).unwrap();
        // 建一条历史引用 dev1
        conn.execute(
            "INSERT INTO transfer_history(transfer_id,direction,peer_device_fingerprint,peer_name,file_count,total_bytes,status,started_ts,send_intent)
             VALUES('t1','receive','dev1','peer',1,10,'partial',100,'{}')",
            [],
        )
        .unwrap();
        forget(&conn, "dev1").unwrap();
        // addresses 已 CASCADE 删
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM known_device_addresses", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 0);
        // trust_store 已删
        assert!(get_trust(&conn, "dev1").unwrap().is_none());
        // 历史保留，peer_device_fingerprint=NULL，peer_name 保留
        let (pid, pname): (Option<String>, String) = conn
            .query_row(
                "SELECT peer_device_fingerprint, peer_name FROM transfer_history WHERE transfer_id='t1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(pid.is_none());
        assert_eq!(pname, "peer");
    }

    #[test]
    fn refresh_seen_updates_last_seen_and_name() {
        let conn = db();
        insert_paired(&conn, &sample_trust("dev1"), &sample_addr()).unwrap();
        refresh_seen(&conn, "dev1", "peer-renamed", 200).unwrap();
        let r = get_trust(&conn, "dev1").unwrap().unwrap();
        assert_eq!(r.peer_device_name, "peer-renamed");
        assert_eq!(r.last_seen_ts, 200);
    }

    #[test]
    fn gc_stale_returns_only_stale() {
        let conn = db();
        let now: i64 = 1_000_000_000;
        let day = 86_400i64;
        insert_paired(
            &conn,
            &PeerTrust {
                device_fingerprint: "fresh",
                peer_spki: &[1],
                peer_device_name: "f",
                share_with_peers: false,
                first_paired_ts: 0,
                last_seen_ts: now,
            },
            &sample_addr(),
        )
        .unwrap();
        insert_paired(
            &conn,
            &PeerTrust {
                device_fingerprint: "stale",
                peer_spki: &[2],
                peer_device_name: "s",
                share_with_peers: false,
                first_paired_ts: 0,
                last_seen_ts: now - 200 * day,
            },
            &sample_addr(),
        )
        .unwrap();
        let cands = gc_stale_candidates(&conn, now, 180).unwrap();
        assert!(cands.contains(&"stale".to_string()));
        assert!(!cands.contains(&"fresh".to_string()));
    }

    #[test]
    fn list_all_returns_all_trusted_and_revoked() {
        let conn = db();
        insert_paired(&conn, &sample_trust("a"), &sample_addr()).unwrap();
        insert_paired(&conn, &sample_trust("b"), &sample_addr()).unwrap();
        revoke(&conn, "b", "user", 5).unwrap();
        let all = list_all(&conn).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all
            .iter()
            .any(|r| r.device_fingerprint == "a" && r.trust_state == "Trusted"));
        assert!(all
            .iter()
            .any(|r| r.device_fingerprint == "b" && r.trust_state == "Revoked"));
    }

    #[test]
    fn insert_trust_writes_trust_row_only() {
        let conn = db();
        insert_trust(&conn, &sample_trust("dev1")).unwrap();
        let r = get_trust(&conn, "dev1").unwrap().unwrap();
        assert_eq!(r.trust_state, "Trusted");
        // 不再写占位地址行。
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM known_device_addresses WHERE device_fingerprint='dev1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }
}
