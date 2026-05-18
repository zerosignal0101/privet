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
pub use session::{SessionId, TransferSession, TransferProgress, FileManifest};

static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Initialize logging and crypto. Idempotent — safe to call multiple times.
pub fn init() {
    INIT.get_or_init(|| {
        // On Android, set up tracing to stderr (captured by logcat).
        // On desktop, the application (CLI) sets up its own subscriber.
        #[cfg(target_os = "android")]
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::new("debug"),
                )
                .with_writer(std::io::stderr)
                .try_init();
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
