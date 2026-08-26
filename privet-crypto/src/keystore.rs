
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;

#[derive(Serialize, Deserialize)]
pub struct StoredIdentity {
    pub signing_key_pkcs8: Zeroizing<Vec<u8>>,
    pub spki_der: Vec<u8>,
    pub cert_der: Vec<u8>,
}

pub trait KeyStore: Send + Sync {
    fn store(&self, identity: &StoredIdentity) -> Result<(), CryptoError>;
    fn load(&self) -> Result<Option<StoredIdentity>, CryptoError>;
    fn delete(&self) -> Result<(), CryptoError>;
}

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
