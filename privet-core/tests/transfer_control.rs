use std::sync::Arc;

use privet_core::{
    AcceptPolicy, Engine, EngineConfig, OfferResolver, TransferCommand, TransferRegistry,
};
use tempfile::TempDir;

fn test_engine() -> (Engine, TempDir) {
    let dir = TempDir::new().unwrap();
    let cfg = EngineConfig {
        db_path: dir.path().join("test.db"),
        save_dir: dir.path().join("save"),
        device_name: "test".into(),
        platform: "linux".into(),
        ..Default::default()
    };
    (Engine::new(cfg), dir)
}

#[tokio::test]
async fn registry_delivers_command_to_registered_receiver() {
    let reg = TransferRegistry::new();
    let mut rx = reg.register("t-1");
    assert!(
        reg.send("t-1", TransferCommand::Pause),
        "registered tid must accept command"
    );
    let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
    assert!(matches!(got, Ok(Some(TransferCommand::Pause))));
    reg.unregister("t-1");
    assert!(
        !reg.send("t-1", TransferCommand::Cancel),
        "after unregister send returns false"
    );
}

#[tokio::test]
async fn offer_resolver_resolves_pending_decision() {
    let res = OfferResolver::new();
    let rx = res.await_decision("t-2");
    assert!(res.resolve("t-2", false), "pending tid must resolve");
    let decision = tokio::time::timeout(std::time::Duration::from_millis(200), rx)
        .await
        .expect("decision delivered")
        .expect("oneshot not cancelled");
    assert!(!decision, "decline decision delivered");
    assert!(!res.resolve("t-2", true), "already-resolved returns false");
}

#[test]
fn accept_policy_variants() {
    let _a = AcceptPolicy::AutoAccept;
    let res = Arc::new(OfferResolver::new());
    let _b = AcceptPolicy::Resolver(res);
}

#[tokio::test]
async fn send_to_unregistered_tid_returns_false() {
    let reg = TransferRegistry::new();
    assert!(!reg.send("nonexistent", TransferCommand::Cancel));
}

#[test]
fn offer_resolver_cancel_cleans_up() {
    let res = OfferResolver::new();
    let _rx = res.await_decision("t-clean");
    res.cancel("t-clean");
    assert!(!res.resolve("t-clean", true));
}

#[tokio::test]
async fn engine_has_registry_and_methods() {
    let (engine, _dir) = test_engine();
    let mut rx = engine.transfer_registry().register("t-e");
    // register a pending offer first so resolve_offer can resolve it
    let _pending_rx = engine.offer_resolver().await_decision("t-e");
    assert!(
        engine.resolve_offer("t-e", true),
        "resolve_offer must resolve pending offer"
    );
    engine.cancel_transfer("t-e").await.unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
    assert!(matches!(got, Ok(Some(TransferCommand::Cancel))));
    engine.pause_transfer("t-e").await.unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
    assert!(matches!(got, Ok(Some(TransferCommand::Pause))));
    engine.resume_transfer("t-e").await.unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
    assert!(matches!(got, Ok(Some(TransferCommand::Resume))));
    // 2nd cancel (resolved offer already consumed -> resolve returns false)
    assert!(!engine.resolve_offer("t-e", false));
}

#[tokio::test]
async fn engine_cancel_unknown_transfer_returns_error() {
    let (engine, _dir) = test_engine();
    let r = engine.cancel_transfer("no-such").await;
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("not active"));
}
