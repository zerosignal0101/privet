//! The trust decision boundary must not depend on how a fingerprint is *written*.
//!
//! WP-R3 flipped a stored fingerprint to uppercase with plain SQL and watched
//! `is_trusted` answer `false` for a device that was, in every sense that
//! matters, the same paired peer. Nothing was broken at the time — both sides
//! were built canonically — but the decision was one byte of spelling away from
//! being wrong, and "we got lucky twice" is not the property we want from a
//! trust check. These tests pin the normalized comparison, and pin that it
//! changes nothing for canonical input.

use privet_core::{Engine, EngineConfig};
use privet_storage::trust::PeerTrust;
use tempfile::TempDir;

fn engine() -> (Engine, TempDir) {
    let dir = TempDir::new().unwrap();
    let cfg = EngineConfig {
        device_name: "alice".into(),
        db_path: dir.path().join("p.db"),
        save_dir: dir.path().to_path_buf(),
        identity_path: Some(dir.path().join("id.bin")),
        ..Default::default()
    };
    (Engine::new(cfg), dir)
}

/// A canonical fingerprint: lowercase, 64 hex characters, as
/// `privet_crypto::hash::fingerprint_hex` produces.
const CANON: &str = "89507b08a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6";

fn pair(e: &Engine, fingerprint: &str) {
    let db = e.db_conn().unwrap();
    privet_storage::trust::insert_trust(
        &db,
        &PeerTrust {
            device_fingerprint: fingerprint,
            peer_spki: &[1, 2, 3],
            peer_device_name: "bob",
            share_with_peers: false,
            first_paired_ts: 1,
            last_seen_ts: 1,
        },
    )
    .unwrap();
}

/// Rewrite the stored fingerprint the way an out-of-band edit would: not through
/// the write path, just SQL. This is the attacker-shaped setup the boundary has
/// to survive, so the tests do it the same way rather than through any API that
/// would normalize for us.
fn rewrite_stored_fp(e: &Engine, from: &str, to: &str) {
    let db = e.db_conn().unwrap();
    db.execute(
        "UPDATE trust_store SET device_fingerprint = ?2 WHERE device_fingerprint = ?1",
        rusqlite::params![from, to],
    )
    .unwrap();
}

#[test]
fn canonical_fingerprint_is_trusted() {
    let (e, _d) = engine();
    pair(&e, CANON);
    assert!(e.is_trusted(CANON).unwrap());
}

#[test]
fn uppercase_stored_fingerprint_is_still_trusted() {
    // The stored row was edited to uppercase; the canonical query must still
    // find it. Before normalization this returned false.
    let (e, _d) = engine();
    pair(&e, CANON);
    rewrite_stored_fp(&e, CANON, &CANON.to_ascii_uppercase());
    assert!(e.is_trusted(CANON).unwrap());
}

#[test]
fn padded_and_mixed_case_query_is_trusted() {
    // The *incoming* fingerprint is what a remote peer controls, so sloppy
    // spelling on that side must not downgrade a paired device.
    let (e, _d) = engine();
    pair(&e, CANON);
    assert!(e
        .is_trusted(&format!("  {}  ", CANON.to_ascii_uppercase()))
        .unwrap());
}

/// Recreate `trust_store` without its `CHECK (trust_state IN ('Trusted','Revoked'))`.
///
/// The shipped schema constrains the state column, so an odd spelling cannot
/// arrive on a database this build wrote — which is exactly why the boundary
/// should not *depend* on that being true. A store written by another build, an
/// older migration, or a hand edit can hold a state string the current schema
/// would reject, and `is_trusted` has to read it the same conservative way.
fn rebuild_store_without_state_check(e: &Engine) {
    let db = e.db_conn().unwrap();
    db.execute_batch(
        "DROP TABLE trust_store;
         CREATE TABLE trust_store (
           device_fingerprint          TEXT    PRIMARY KEY,
           peer_spki                   BLOB    NOT NULL,
           peer_device_name            TEXT    NOT NULL,
           trust_state                 TEXT    NOT NULL DEFAULT 'Trusted',
           share_with_peers            INTEGER NOT NULL DEFAULT 0,
           first_paired_ts             INTEGER NOT NULL,
           last_seen_ts                INTEGER NOT NULL,
           revoked_ts                  INTEGER,
           revocation_reason           TEXT
         );",
    )
    .unwrap();
}

#[test]
fn revoked_is_never_trusted_even_when_spelled_oddly() {
    // Normalizing the comparison must not normalize away the *meaning*: a
    // revoked device stays refused, including when the state string itself is
    // padded, mixed case, or a value the shipped CHECK constraint would reject.
    for state in ["Revoked", "REVOKED", "  rEvOkEd  ", "Compromised"] {
        let (e, _d) = engine();
        pair(&e, CANON);
        rebuild_store_without_state_check(&e);
        let db = e.db_conn().unwrap();
        db.execute(
            "UPDATE trust_store SET trust_state = ?2, revoked_ts = 999 WHERE device_fingerprint = ?1",
            rusqlite::params![CANON, state],
        )
        .unwrap();
        drop(db);
        assert!(
            !e.is_trusted(CANON).unwrap(),
            "{state:?} must not be trusted"
        );
        assert!(
            !e.is_trusted(&CANON.to_ascii_uppercase()).unwrap(),
            "{state:?} must not be trusted for an uppercase query"
        );
    }
}

#[test]
fn unknown_fingerprint_is_not_trusted() {
    let (e, _d) = engine();
    pair(&e, CANON);
    assert!(!e
        .is_trusted("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .unwrap());
}

#[test]
fn equivalent_spellings_give_the_same_answer() {
    // The whole point: one device, one answer. Whichever way the fingerprint is
    // written — and whatever the stored row looks like — the decision is
    // identical.
    let (e, _d) = engine();
    pair(&e, CANON);

    let forms = [
        CANON.to_string(),
        CANON.to_ascii_uppercase(),
        format!("  {}  ", CANON),
        format!("\t{}\n", CANON.to_ascii_uppercase()),
    ];
    for form in &forms {
        assert!(e.is_trusted(form).unwrap(), "{form:?} should be trusted");
    }

    // …and once the stored row itself is spelled differently, every form still
    // agrees with every other form.
    rewrite_stored_fp(&e, CANON, &CANON.to_ascii_uppercase());
    for form in &forms {
        assert!(e.is_trusted(form).unwrap(), "{form:?} should be trusted");
    }

    // An unknown device is equally spelling-independent: no spelling invents a
    // trust that is not there.
    let unknown = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    for form in [
        unknown.to_string(),
        unknown.to_ascii_uppercase(),
        format!("  {unknown}  "),
    ] {
        assert!(
            !e.is_trusted(&form).unwrap(),
            "{form:?} should not be trusted"
        );
    }
}
