//! BLAKE3 助手：一次性/流式哈希、设备指纹。

/// 一次性 BLAKE3 哈希（32 字节）。
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(data);
    h.finalize().into()
}

/// 流式 BLAKE3（大文件/段根）。
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

/// 设备指纹 = `BLAKE3(SPKI_DER)[0..FP_PREFIX_BYTES]` 的 hex（与 P1 beacon `fp` 一致）。
pub fn fingerprint_hex(spki_der: &[u8]) -> String {
    let h = blake3(spki_der);
    hex::encode(&h)
}
