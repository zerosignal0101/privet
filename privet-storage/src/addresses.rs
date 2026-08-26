
use crate::constants::EVICT_FAILS;
use crate::error::StorageError;
use crate::trust::PeerAddress;

#[derive(Debug, Clone)]
pub struct AddressRecord {
    pub device_fingerprint: String,
    pub subnet_cidr: String,
    pub gateway_ip: Option<String>,
    pub addr: String,
    pub quic_port: u16,
    pub tcp_port: u16,
    pub source: String,
    pub last_seen_ts: i64,
    pub success_count: u32,
    pub fail_count: u32,
}

pub fn upsert_address(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
    a: &PeerAddress,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO known_device_addresses
           (device_fingerprint, subnet_cidr, gateway_ip, addr, quic_port, tcp_port, source, last_seen_ts,
            success_count, fail_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0)
         ON CONFLICT(device_fingerprint, subnet_cidr, addr) DO UPDATE SET
           gateway_ip=excluded.gateway_ip, quic_port=excluded.quic_port,
           tcp_port=excluded.tcp_port, last_seen_ts=excluded.last_seen_ts",
        rusqlite::params![
            device_fingerprint,
            a.subnet_cidr,
            a.gateway_ip,
            a.addr,
            a.quic_port,
            a.tcp_port,
            a.source,
            a.last_seen_ts,
        ],
    )?;
    Ok(())
}

pub fn recent_n(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
    n: usize,
) -> Result<Vec<AddressRecord>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT device_fingerprint, subnet_cidr, gateway_ip, addr, quic_port, tcp_port, source,
                last_seen_ts, success_count, fail_count
         FROM known_device_addresses
         WHERE device_fingerprint=?1 AND success_count>0
         ORDER BY last_seen_ts DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![device_fingerprint, n as i64], |r| {
        Ok(AddressRecord {
            device_fingerprint: r.get(0)?,
            subnet_cidr: r.get(1)?,
            gateway_ip: r.get(2)?,
            addr: r.get(3)?,
            quic_port: r.get(4)?,
            tcp_port: r.get(5)?,
            source: r.get(6)?,
            last_seen_ts: r.get(7)?,
            success_count: r.get::<_, i64>(8)? as u32,
            fail_count: r.get::<_, i64>(9)? as u32,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn inc_success(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
    subnet_cidr: &str,
    addr: &str,
    now_ts: i64,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE known_device_addresses SET success_count=success_count+1, last_seen_ts=?1
         WHERE device_fingerprint=?2 AND subnet_cidr=?3 AND addr=?4",
        rusqlite::params![now_ts, device_fingerprint, subnet_cidr, addr],
    )?;
    Ok(())
}

pub fn inc_fail(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
    subnet_cidr: &str,
    addr: &str,
    now_ts: i64,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE known_device_addresses SET fail_count=fail_count+1, last_seen_ts=?1
         WHERE device_fingerprint=?2 AND subnet_cidr=?3 AND addr=?4",
        rusqlite::params![now_ts, device_fingerprint, subnet_cidr, addr],
    )?;
    Ok(())
}

const EVICT_AGING_SECS: i64 = 86_400 * 30;

pub fn recent_known(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
    n: usize,
) -> Result<Vec<AddressRecord>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT device_fingerprint, subnet_cidr, gateway_ip, addr, quic_port, tcp_port, source,
                last_seen_ts, success_count, fail_count
         FROM known_device_addresses
         WHERE device_fingerprint=?1
         ORDER BY last_seen_ts DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![device_fingerprint, n as i64], |r| {
        Ok(AddressRecord {
            device_fingerprint: r.get(0)?,
            subnet_cidr: r.get(1)?,
            gateway_ip: r.get(2)?,
            addr: r.get(3)?,
            quic_port: r.get(4)?,
            tcp_port: r.get(5)?,
            source: r.get(6)?,
            last_seen_ts: r.get(7)?,
            success_count: r.get::<_, i64>(8)? as u32,
            fail_count: r.get::<_, i64>(9)? as u32,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn list_known(
    conn: &rusqlite::Connection,
    n: usize,
) -> Result<Vec<(String, AddressRecord)>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT device_fingerprint, subnet_cidr, gateway_ip, addr, quic_port, tcp_port, source,
                last_seen_ts, success_count, fail_count
         FROM known_device_addresses
         ORDER BY last_seen_ts DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            AddressRecord {
                device_fingerprint: r.get(0)?,
                subnet_cidr: r.get(1)?,
                gateway_ip: r.get(2)?,
                addr: r.get(3)?,
                quic_port: r.get(4)?,
                tcp_port: r.get(5)?,
                source: r.get(6)?,
                last_seen_ts: r.get(7)?,
                success_count: r.get::<_, i64>(8)? as u32,
                fail_count: r.get::<_, i64>(9)? as u32,
            },
        ))
    })?;
    let mut by_dev: std::collections::HashMap<String, Vec<AddressRecord>> = Default::default();
    let mut order: Vec<String> = Vec::new();
    for r in rows {
        let (d, rec) = r?;
        if !by_dev.contains_key(&d) {
            order.push(d.clone());
        }
        by_dev.entry(d).or_default().push(rec);
    }
    let mut out = Vec::new();
    for d in order {
        if let Some(v) = by_dev.get_mut(&d) {
            for rec in v.iter().take(n) {
                out.push((d.clone(), rec.clone()));
            }
        }
    }
    Ok(out)
}

pub fn evict_failed(conn: &rusqlite::Connection, now_ts: i64) -> Result<usize, StorageError> {
    let threshold = now_ts - EVICT_AGING_SECS;
    let n = conn.execute(
        "DELETE FROM known_device_addresses WHERE fail_count >= ?1 AND last_seen_ts < ?2",
        rusqlite::params![EVICT_FAILS as i64, threshold],
    )?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::RECENT_N;
    use crate::trust::{insert_paired, PeerTrust};

    fn db() -> rusqlite::Connection {
        let conn = crate::db::open_in_memory().unwrap();
        crate::migration::run_migrations(&conn, crate::migration::MIGRATIONS).unwrap();
        conn
    }

    fn addr<'a>(a: &'a str, ts: i64) -> PeerAddress<'a> {
        PeerAddress {
            subnet_cidr: "10.0.0.0/24",
            gateway_ip: Some("10.0.0.1"),
            addr: a,
            quic_port: 47808,
            tcp_port: 47810,
            source: "self",
            last_seen_ts: ts,
        }
    }

    #[test]
    fn recent_n_returns_top_success_sorted() {
        let conn = db();
        insert_paired(
            &conn,
            &PeerTrust {
                device_fingerprint: "d",
                peer_spki: &[1],
                peer_device_name: "n",
                share_with_peers: false,
                first_paired_ts: 0,
                last_seen_ts: 0,
            },
            &addr("10.0.0.1", 10),
        )
        .unwrap();
        for i in 1..=10u8 {
            let s = format!("10.0.0.{i}");
            upsert_address(&conn, "d", &addr(&s, i as i64 * 10)).unwrap();
            if i % 2 == 0 {
                inc_success(&conn, "d", "10.0.0.0/24", &s, i as i64 * 10).unwrap();
            }
        }
        let r = recent_n(&conn, "d", RECENT_N).unwrap();
        assert_eq!(r.len(), 5);
        assert_eq!(r[0].addr, "10.0.0.10");
        assert_eq!(r[4].addr, "10.0.0.2");
    }

    #[test]
    fn evict_removes_aged_failures_not_single() {
        let conn = db();
        insert_paired(
            &conn,
            &PeerTrust {
                device_fingerprint: "d",
                peer_spki: &[1],
                peer_device_name: "n",
                share_with_peers: false,
                first_paired_ts: 0,
                last_seen_ts: 0,
            },
            &addr("10.0.0.1", 10),
        )
        .unwrap();
        upsert_address(&conn, "d", &addr("10.0.0.2", 5)).unwrap();
        upsert_address(&conn, "d", &addr("10.0.0.3", 1_000_000 * 30)).unwrap();
        for _ in 0..EVICT_FAILS {
            inc_fail(&conn, "d", "10.0.0.0/24", "10.0.0.2", 5).unwrap();
            inc_fail(&conn, "d", "10.0.0.0/24", "10.0.0.3", 1_000_000 * 30).unwrap();
        }
        inc_fail(&conn, "d", "10.0.0.0/24", "10.0.0.1", 10).unwrap();
        let removed = evict_failed(&conn, 1_000_000 * 30).unwrap();
        assert_eq!(removed, 1);
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM known_device_addresses WHERE device_fingerprint='d'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn recent_known_includes_zero_success() {
        let conn = db();
        insert_paired(
            &conn,
            &PeerTrust {
                device_fingerprint: "d",
                peer_spki: &[1],
                peer_device_name: "n",
                share_with_peers: false,
                first_paired_ts: 0,
                last_seen_ts: 0,
            },
            &addr("10.0.0.1", 10),
        )
        .unwrap();
        upsert_address(&conn, "d", &addr("10.0.0.9", 99)).unwrap();
        let r = recent_known(&conn, "d", RECENT_N).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].addr, "10.0.0.9");
    }

    #[test]
    fn list_known_crosses_devices() {
        let conn = db();
        for d in ["a", "b"] {
            insert_paired(
                &conn,
                &PeerTrust {
                    device_fingerprint: d,
                    peer_spki: &[1],
                    peer_device_name: "n",
                    share_with_peers: false,
                    first_paired_ts: 0,
                    last_seen_ts: 0,
                },
                &addr("10.0.0.1", 10),
            )
            .unwrap();
            upsert_address(&conn, d, &addr("10.0.0.9", 50)).unwrap();
        }
        let all = list_known(&conn, RECENT_N).unwrap();
        assert_eq!(all.len(), 4); // 2 devices x 2 addrs
        assert!(all.iter().any(|(d, _)| d == "a"));
        assert!(all.iter().any(|(d, _)| d == "b"));
    }
}
