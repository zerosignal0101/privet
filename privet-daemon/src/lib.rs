//! Embeddable privetd: the daemon compiled as a cdylib (`libprivetd.so`) so a
//! mobile app can dlopen it and run it on a thread inside the app process.
//!
//! On Android (targetSdk >= 29) SELinux enforces W^X on `untrusted_app`, so an
//! app can no longer execve an ELF extracted into its own data directory. The
//! daemon therefore ships as a native library: the app dlopens it (allowed),
//! the embedded run body binds the unix socket exactly as the standalone
//! binary would, and the frontend talks to it over the same IPC protocol.

mod backend;
mod config;
mod events;
mod run;
mod server;

#[cfg(target_os = "android")]
mod android_bridge;

pub use run::{request_shutdown, reset_shutdown, run, run_blocking};

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use privet_ipc::{IpcClient, LocalEndpoint, Request, ResponsePayload, RuntimeConfigPatch};
    use tempfile::tempdir;

    use crate::run::{request_shutdown, run_blocking};

    fn write_config(dir: &Path, endpoint: &Path) -> PathBuf {
        let config = serde_json::json!({
            "device_name": "test-device",
            "data_dir": dir.join("data"),
            "save_dir": dir.join("save"),
            "ipc_endpoint": endpoint,
            // 0 disables the network listeners; this test only exercises IPC.
            "quic_port": 0,
            "tcp_port": 0,
            "discovery_port": 0,
        });
        let path = dir.join("config.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        path
    }

    #[test]
    fn run_blocking_serves_ipc_and_stops_on_shutdown() {
        let dir = tempdir().unwrap();
        // Unix IPC is a socket file; Windows IPC is a named pipe, whose name is
        // the endpoint path verbatim (see privet-ipc endpoint.rs).
        let endpoint = if cfg!(windows) {
            PathBuf::from(format!(r"\\.\pipe\privet-test-{}", std::process::id()))
        } else {
            dir.path().join("privet.sock")
        };
        let config_path = write_config(dir.path(), &endpoint);

        let (result_tx, result_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let thread = std::thread::spawn(move || {
            let result = run_blocking(Some(config_path), None);
            let _ = result_tx.send(result.clone());
            result
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let client = rt.block_on(async {
            let start = std::time::Instant::now();
            loop {
                if let Ok(client) = IpcClient::connect(&LocalEndpoint::new(endpoint.clone())).await {
                    break client;
                }
                if start.elapsed() >= Duration::from_secs(10) {
                    let daemon = result_rx.try_recv().ok();
                    panic!("daemon endpoint never became reachable (daemon: {daemon:?})");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let pong = rt.block_on(client.call(Request::Ping)).unwrap();
        assert!(matches!(pong, ResponsePayload::Pong { .. }));

        request_shutdown();
        let result = thread.join().expect("daemon thread panicked");
        assert!(result.is_ok(), "run_blocking returned {result:?}");
    }

    #[test]
    fn runtime_config_changes_persist_to_config_file() {
        let dir = tempdir().unwrap();
        // Unique pipe name: the sibling test also uses privet-test-<pid>.
        let endpoint = if cfg!(windows) {
            PathBuf::from(format!(
                r"\\.\pipe\privet-test-persist-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ))
        } else {
            dir.path().join("privet.sock")
        };
        let config_path = write_config(dir.path(), &endpoint);

        let (result_tx, result_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let thread = std::thread::spawn(move || {
            let result = run_blocking(Some(config_path), None);
            let _ = result_tx.send(result.clone());
            result
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let client = rt.block_on(async {
            let start = std::time::Instant::now();
            loop {
                if let Ok(client) = IpcClient::connect(&LocalEndpoint::new(endpoint.clone())).await {
                    break client;
                }
                if start.elapsed() >= Duration::from_secs(10) {
                    panic!("daemon endpoint never became reachable (daemon: {:?})", result_rx.try_recv().ok());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let new_save = dir.path().join("save-custom");
        let resp = rt
            .block_on(client.call(Request::SetRuntimeConfig(RuntimeConfigPatch {
                accept_all_trusted: Some(true),
                collision_policy: Some(privet_ipc::CollisionPolicyDto::Overwrite),
                save_dir: Some(new_save.clone()),
            })))
            .unwrap();
        assert!(matches!(resp, ResponsePayload::RuntimeConfig(_)));

        // The daemon writes asynchronously; give it a moment, then read the file.
        std::thread::sleep(Duration::from_millis(300));
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("config.json")).unwrap()).unwrap();
        assert_eq!(on_disk["accept_all_trusted"], serde_json::Value::Bool(true));
        assert_eq!(on_disk["collision_policy"], "overwrite");
        assert_eq!(on_disk["save_dir"], serde_json::Value::String(new_save.to_string_lossy().into_owned()));
        // Device name and network ports survive the write untouched.
        assert_eq!(on_disk["device_name"], "test-device");

        request_shutdown();
        thread.join().expect("daemon thread panicked").unwrap();
    }
}
