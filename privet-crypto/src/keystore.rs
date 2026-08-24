//! 密钥库抽象：trait + FileKeyStore(0600) + InMemoryKeyStore。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// 可存储的身份形态（PKCS8 私钥 + SPKI + 证书）。
/// signing_key_pkcs8 用 Zeroizing 包装，drop 时清零。
#[derive(Serialize, Deserialize)]
pub struct StoredIdentity {
    pub signing_key_pkcs8: Zeroizing<Vec<u8>>,
    pub spki_der: Vec<u8>,
    pub cert_der: Vec<u8>,
}

/// 密钥库抽象（同步：keystore 操作短促；core 用 spawn_blocking 包裹平台后端）。
pub trait KeyStore: Send + Sync {
    fn store(&self, identity: &StoredIdentity) -> Result<(), CryptoError>;
    fn load(&self) -> Result<Option<StoredIdentity>, CryptoError>;
    fn delete(&self) -> Result<(), CryptoError>;
}

/// 文件密钥库：`0600` 原子写（私钥仅在此 0600 文件内）。
#[cfg_attr(not(unix), allow(dead_code))]
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl KeyStore for FileKeyStore {
    fn store(&self, identity: &StoredIdentity) -> Result<(), CryptoError> {
        #[cfg(unix)]
        {
            self.store_unix(identity)
        }
        #[cfg(windows)]
        {
            self.store_windows(identity)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (identity,);
            Err(CryptoError::KeyStore(
                "no keystore backend for this platform".into(),
            ))
        }
    }
    fn load(&self) -> Result<Option<StoredIdentity>, CryptoError> {
        #[cfg(unix)]
        {
            self.load_unix()
        }
        #[cfg(windows)]
        {
            self.load_windows()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(CryptoError::KeyStore(
                "no keystore backend for this platform".into(),
            ))
        }
    }
    fn delete(&self) -> Result<(), CryptoError> {
        #[cfg(unix)]
        {
            self.delete_unix()
        }
        #[cfg(windows)]
        {
            self.delete_windows()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(CryptoError::KeyStore(
                "no keystore backend for this platform".into(),
            ))
        }
    }
}

#[cfg(unix)]
impl FileKeyStore {
    fn store_unix(&self, identity: &StoredIdentity) -> Result<(), CryptoError> {
        let bytes =
            bincode::serialize(identity).map_err(|e| CryptoError::Encoding(e.to_string()))?;
        atomic_write_0600(&self.path, &bytes)?;
        Ok(())
    }
    fn load_unix(&self) -> Result<Option<StoredIdentity>, CryptoError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let id = bincode::deserialize(&bytes)
                    .map_err(|e| CryptoError::Encoding(e.to_string()))?;
                Ok(Some(id))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn delete_unix(&self) -> Result<(), CryptoError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Windows 文件密钥库实现。
/// 当前：与 Unix 同路径的文件 I/O；权限由 NTFS DACL 保护（`set_file_owner_only` 在
/// `privet-ipc` 侧可选调用，keystore 自身不做 0600 等价）。
#[cfg(windows)]
impl FileKeyStore {
    fn store_windows(&self, identity: &StoredIdentity) -> Result<(), CryptoError> {
        let bytes =
            bincode::serialize(identity).map_err(|e| CryptoError::Encoding(e.to_string()))?;
        atomic_write_0600(&self.path, &bytes)?;
        Ok(())
    }
    fn load_windows(&self) -> Result<Option<StoredIdentity>, CryptoError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let id = bincode::deserialize(&bytes)
                    .map_err(|e| CryptoError::Encoding(e.to_string()))?;
                Ok(Some(id))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn delete_windows(&self) -> Result<(), CryptoError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// 原子写 + 0600（unix）：写到同目录临时文件、设权限、fsync、rename。
/// cfg(not(unix)): only used by store_unix, which is cfg(unix).
#[cfg_attr(not(unix), allow(dead_code))]
fn atomic_write_0600(path: &Path, data: &[u8]) -> Result<(), CryptoError> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("privet");
    let tmp = dir.join(format!(".{file_name}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
