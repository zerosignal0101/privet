
use std::sync::Arc;
use std::thread;

use privet_storage::history::{insert_history, NewTransfer, TransferDirection, TransferStatus};
use privet_storage::migration::open_and_migrate;
use privet_storage::trust::{insert_paired, PeerAddress, PeerTrust};

#[test]
fn n_readers_one_writer_no_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.db");
    {
        let conn = open_and_migrate(&path).unwrap();
        insert_paired(
            &conn,
            &PeerTrust {
                device_fingerprint: "dev1",
                peer_spki: &[1],
                peer_device_name: "n",
                share_with_peers: false,
                first_paired_ts: 0,
                last_seen_ts: 0,
            },
            &PeerAddress {
                subnet_cidr: "10.0.0.0/24",
                gateway_ip: None,
                addr: "10.0.0.1",
                quic_port: 47808,
                tcp_port: 47810,
                source: "self",
                last_seen_ts: 0,
            },
        )
        .unwrap();
    }

    let path = Arc::new(path.to_path_buf());
    let mut handles = Vec::new();

    let wp = Arc::clone(&path);
    handles.push(thread::spawn(move || {
        let conn = open_and_migrate(&*wp).unwrap();
        for i in 0..200u64 {
            insert_history(
                &conn,
                &NewTransfer {
                    transfer_id: &format!("t{i}"),
                    direction: TransferDirection::Send,
                    peer_device_fingerprint: Some("dev1"),
                    peer_name: Some("n"),
                    root_name: None,
                    file_count: 1,
                    total_bytes: i,
                    status: TransferStatus::Completed,
                    started_ts: i as i64,
                    save_dir: None,
                    send_intent: "{}".into()
                },
            )
            .unwrap();
        }
    }));

    for _ in 0..4 {
        let rp = Arc::clone(&path);
        handles.push(thread::spawn(move || {
            let conn = open_and_migrate(&*rp).unwrap();
            let mut last = 0u64;
            for _ in 0..50 {
                let n: i64 = conn
                    .query_row("SELECT COUNT(*) FROM transfer_history", [], |r| r.get(0))
                    .unwrap();
                assert!(n as u64 >= last, "count regressed: {n} < {last}");
                last = n as u64;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let conn = open_and_migrate(&*path).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM transfer_history", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 200);
}

#[test]
fn large_history_query_correct_via_index() {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_and_migrate(dir.path().join("big.db")).unwrap();
    for i in 0..10_000u64 {
        insert_history(
            &conn,
            &NewTransfer {
                transfer_id: &format!("t{i}"),
                direction: TransferDirection::Receive,
                peer_device_fingerprint: None,
                peer_name: None,
                root_name: None,
                file_count: 1,
                total_bytes: i,
                status: TransferStatus::Completed,
                started_ts: 10_000 - i as i64,
                save_dir: None,
                send_intent: "{}".into()
            },
        )
        .unwrap();
    }
    let mut stmt = conn
        .prepare("SELECT transfer_id FROM transfer_history ORDER BY started_ts DESC LIMIT 5")
        .unwrap();
    let ids: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(ids[0], "t0");
    assert_eq!(ids[4], "t4");
}
