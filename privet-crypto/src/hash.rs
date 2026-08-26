
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(data);
    h.finalize().into()
}

pub struct StreamingHasher {
    inner: blake3::Hasher,
}

impl StreamingHasher {
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
}

impl Default for StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

pub fn fingerprint_hex(spki_der: &[u8]) -> String {
    let h = blake3(spki_der);
    hex::encode(&h)
}
