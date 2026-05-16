use std::time::Instant;

/// Tracks transfer progress and computes smoothed speed (EWMA).
pub struct ProgressTracker {
    total_bytes: u64,
    bytes_transferred: u64,
    last_update: Instant,
    last_bytes: u64,
    speed_ewma: f64,
    alpha: f64,
}

impl ProgressTracker {
    pub fn new(total_bytes: u64) -> Self {
        Self {
            total_bytes,
            bytes_transferred: 0,
            last_update: Instant::now(),
            last_bytes: 0,
            speed_ewma: 0.0,
            alpha: 0.3, // Smoothing factor
        }
    }

    pub fn record(&mut self, bytes: u64) {
        self.bytes_transferred += bytes;
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();

        if elapsed >= 0.1 {
            let delta_bytes = self.bytes_transferred - self.last_bytes;
            let instant_speed = delta_bytes as f64 / elapsed;
            self.speed_ewma = self.alpha * instant_speed + (1.0 - self.alpha) * self.speed_ewma;
            self.last_update = now;
            self.last_bytes = self.bytes_transferred;
        }
    }

    pub fn bytes_transferred(&self) -> u64 {
        self.bytes_transferred
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn speed_bps(&self) -> f64 {
        self.speed_ewma
    }

    pub fn percent(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.bytes_transferred as f64 / self.total_bytes as f64) * 100.0
    }

    pub fn is_complete(&self) -> bool {
        self.bytes_transferred >= self.total_bytes
    }
}
