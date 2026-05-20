pub mod config;
pub mod discovery;
pub mod engine;
pub mod error;
pub mod known_device;
pub mod network;
pub mod peer;
pub mod protocol;
pub mod security;
pub mod session;
pub mod storage;
pub mod transfer;
pub mod transport;

pub use engine::{PrivetEngine, PrivetEvent};
pub use config::{PrivetConfig, SecurityMode};
pub use error::{PrivetError, Result};
pub use known_device::{KnownDevice, KnownDeviceStore, NetworkEntry};
pub use network::NetworkInfo;
pub use peer::{PeerId, PeerInfo};
pub use session::{SessionId, TransferSession, TransferProgress, FileManifest, FileToSend, ExpansionResult, SkippedPath, expand_paths};

static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Initialize logging and crypto. Idempotent — safe to call multiple times.
pub fn init() {
    INIT.get_or_init(|| {
        // On Android, use android_logger to output to logcat.
        // tracing events are forwarded to log via the "log" feature.
        #[cfg(target_os = "android")]
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("Privet"),
        );

        // On desktop, the application (CLI) sets up its own subscriber.
        #[cfg(not(target_os = "android"))]
        {
            // tracing_subscriber::fmt() is not available on non-Android builds
            // The CLI binary sets up its own tracing subscriber.
        }

        #[cfg(feature = "aws-lc-rs")]
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("failed to install aws-lc-rs crypto provider");
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("failed to install ring crypto provider");
    });
}
