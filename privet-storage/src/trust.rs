
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

/// Upsert a fresh pairing into the trust store. Re-pairing a peer that already
/// has a row — e.g. one the user revoked earlier — must RE-TRUST it, not fail on
/// the `device_fingerprint` UNIQUE constraint: a fresh, human-gated pairing code
/// is a new authorization, so the revoked state is cleared and the (possibly
/// rotated) key is recorded. This is what lets a user "Remove Trust" (forget)
/// and then pair again on the initiator side.
fn upsert_trust_sql() -> &'static str {
    "INSERT INTO trust_store
       (device_fingerprint, peer_spki, peer_device_name, trust_state, share_with_peers,
        first_paired_ts, last_seen_ts)
     VALUES (?1, ?2, ?3, 'Trusted', ?4, ?5, ?6)
     ON CONFLICT(device_fingerprint) DO UPDATE SET
       peer_spki = excluded.peer_spki,
       peer_device_name = excluded.peer_device_name,
       trust_state = 'Trusted',
       share_with_peers = excluded.share_with_peers,
       first_paired_ts = excluded.first_paired_ts,
       last_seen_ts = excluded.last_seen_ts,
       revoked_ts = NULL,
       revocation_reason = NULL"
}

pub fn insert_paired(
    conn: &rusqlite::Connection,
    trust: &PeerTrust,
    address: &PeerAddress,
) -> Result<(), StorageError> {
    let tx = conn.unchecked_transaction()?;
    let res = (|| -> Result<(), rusqlite::Error> {
        tx.execute(
            upsert_trust_sql(),
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
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(device_fingerprint, subnet_cidr, addr) DO UPDATE SET
               gateway_ip = excluded.gateway_ip,
               quic_port = excluded.quic_port,
               tcp_port = excluded.tcp_port,
               source = excluded.source,
               last_seen_ts = excluded.last_seen_ts",
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

pub fn insert_trust(conn: &rusqlite::Connection, trust: &PeerTrust) -> Result<(), StorageError> {
    conn.execute(
        upsert_trust_sql(),
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

/// The canonical comparison form of a fingerprint: ASCII-trimmed and case-folded.
///
/// Fingerprints are produced by `privet_crypto::hash::fingerprint_hex` as
/// lowercase hex, so today every caller supplies the canonical form and this is
/// the identity function. It is not, however, the *only* form that can reach the
/// trust boundary: a peer sends its fingerprint on the wire, and a store row can
/// be written by an older build, a migration, or a direct database edit. A
/// trust decision must not silently flip because a value that denotes the same
/// device was spelled differently, so the decision boundary normalizes both
/// sides before comparing.
///
/// ASCII-only by design: a fingerprint is hex, so full Unicode case folding
/// would only invent equivalences between values that were never confusable.
pub fn normalize_fingerprint(device_fingerprint: &str) -> String {
    device_fingerprint.trim().to_ascii_lowercase()
}

/// Whether a `trust_state` value means "currently trusted", compared the same
/// way the fingerprint is: trimmed, case-insensitive.
///
/// Semantics are unchanged by that normalization — only `Trusted` is true, so a
/// `Revoked` or `Compromised` record (kept for history) is still refused.
pub fn state_is_trusted(trust_state: &str) -> bool {
    trust_state.trim().eq_ignore_ascii_case("Trusted")
}

/// Look up a trust record by fingerprint, matching on the normalized form.
///
/// [`get_trust`] keeps exact-match semantics for callers that depend on them
/// (and that want "this precise stored row"); this is the variant the trust
/// *decision* uses, so a device cannot be declared untrusted — or trusted —
/// purely by how its fingerprint happens to be written.
///
/// The SQL folds the stored column rather than trusting SQLite's `COLLATE
/// NOCASE`, which is ASCII-only as a subtlety rather than a guarantee, and it
/// would silently change the comparison of every other query on the column.
pub fn get_trust_normalized(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
) -> Result<Option<TrustRecord>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT device_fingerprint, peer_spki, peer_device_name, trust_state, share_with_peers,
                first_paired_ts, last_seen_ts, revoked_ts, revocation_reason
         FROM trust_store
         WHERE lower(trim(device_fingerprint)) = ?1
         ORDER BY rowid
         LIMIT 1",
    )?;
    let mut rows = stmt.query(rusqlite::params![normalize_fingerprint(device_fingerprint)])?;
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

pub fn forget(conn: &rusqlite::Connection, device_fingerprint: &str) -> Result<(), StorageError> {
    conn.execute(
        "DELETE FROM trust_store WHERE device_fingerprint=?1",
        rusqlite::params![device_fingerprint],
    )?;
    Ok(())
}

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
    fn insert_paired_is_idempotent_upsert() {
        // Re-recording a pairing for a device that already has a row (e.g. one
        // the user revoked and is now re-pairing) must re-trust it, not fail on
        // the fingerprint UNIQUE constraint, and must not duplicate addresses.
        let conn = db();
        insert_paired(&conn, &sample_trust("dev1"), &sample_addr()).unwrap();
        revoke(&conn, "dev1", "user_request", 999).unwrap();
        insert_paired(&conn, &sample_trust("dev1"), &sample_addr()).unwrap();
        let r = get_trust(&conn, "dev1").unwrap().unwrap();
        assert_eq!(r.trust_state, "Trusted");
        assert_eq!(r.revoked_ts, None);
        assert_eq!(r.revocation_reason, None);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM known_device_addresses", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn insert_trust_retrusts_after_revoke() {
        // The initiator/responder `commit_peer` path uses insert_trust; a
        // revoked peer that completes a fresh pairing must be re-trusted.
        let conn = db();
        insert_trust(&conn, &sample_trust("dev1")).unwrap();
        revoke(&conn, "dev1", "user_request", 999).unwrap();
        insert_trust(&conn, &sample_trust("dev1")).unwrap();
        let r = get_trust(&conn, "dev1").unwrap().unwrap();
        assert_eq!(r.trust_state, "Trusted");
        assert_eq!(r.revoked_ts, None);
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
        conn.execute(
            "INSERT INTO transfer_history(transfer_id,direction,peer_device_fingerprint,peer_name,file_count,total_bytes,status,started_ts,send_intent)
             VALUES('t1','receive','dev1','peer',1,10,'partial',100,'{}')",
            [],
        )
        .unwrap();
        forget(&conn, "dev1").unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM known_device_addresses", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 0);
        assert!(get_trust(&conn, "dev1").unwrap().is_none());
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
