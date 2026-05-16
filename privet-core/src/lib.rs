pub mod config;
pub mod discovery;
pub mod engine;
pub mod error;
pub mod peer;
pub mod protocol;
pub mod security;
pub mod session;
pub mod storage;
pub mod transfer;
pub mod transport;

pub use engine::{PrivetEngine, PrivetEvent};
pub use config::PrivetConfig;
pub use error::{PrivetError, Result};
pub use peer::{PeerId, PeerInfo};
pub use session::{SessionId, TransferSession, TransferProgress, FileManifest};

static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Initialize the crypto provider. Idempotent — safe to call multiple times.
pub fn init() {
    INIT.get_or_init(|| {
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
