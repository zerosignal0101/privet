use std::time::Duration;

pub use privet_discovery::constants as discovery_constants;
pub use privet_security::constants as security_constants;
pub use privet_transfer::constants as transfer_constants;
pub use privet_transport::constants as transport_constants;

pub const BACKOFF_SCHEDULE: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(30),
];
pub const BACKOFF_MAX_ATTEMPTS: u32 = 6;
pub const BACKOFF_RESET_ON_SUCCESS: bool = true;
pub const NETWORK_SWITCH_IMMEDIATE_RETRY: bool = true;
