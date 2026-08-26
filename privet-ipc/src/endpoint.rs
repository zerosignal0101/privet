use std::path::{Path, PathBuf};

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEndpoint(PathBuf);

impl LocalEndpoint {
    pub fn new(path: impl Into<PathBuf>) -> Self { Self(path.into()) }
    pub fn path(&self) -> &Path { &self.0 }
}

pub fn default_endpoint() -> LocalEndpoint {
    #[cfg(unix)]
    {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .or_else(|| dirs::runtime_dir())
            .or_else(|| dirs::cache_dir().map(|path| path.join("run")))
            .unwrap_or_else(|| {
                let user = std::env::var("USER")
                    .unwrap_or_else(|_| "unknown".into())
                    .replace(|character: char| !character.is_ascii_alphanumeric(), "_");
                std::env::temp_dir().join(format!("privet-{user}"))
            });
        LocalEndpoint::new(base.join("privet").join("privet.sock"))
    }
    #[cfg(windows)]
    {
        LocalEndpoint::new(r"\\.\pipe\privet-user-v1")
    }
}

#[cfg(unix)]
pub type LocalStream = tokio::net::UnixStream;

#[cfg(unix)]
pub struct LocalListener {
    inner: tokio::net::UnixListener,
    endpoint: LocalEndpoint,
}

#[cfg(unix)]
impl LocalListener {
    pub fn bind(endpoint: LocalEndpoint) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = endpoint.path().parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        if endpoint.path().exists() {
            if std::os::unix::net::UnixStream::connect(endpoint.path()).is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "another Privet daemon is already listening",
                ).into());
            }
            std::fs::remove_file(endpoint.path())?;
        }
        let inner = tokio::net::UnixListener::bind(endpoint.path())?;
        std::fs::set_permissions(endpoint.path(), std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { inner, endpoint })
    }

    pub async fn accept(&self) -> Result<LocalStream> { Ok(self.inner.accept().await?.0) }
}

#[cfg(unix)]
impl Drop for LocalListener {
    fn drop(&mut self) { let _ = std::fs::remove_file(self.endpoint.path()); }
}

#[cfg(windows)]
pub type LocalStream = tokio::net::windows::named_pipe::NamedPipeClient;

#[cfg(windows)]
pub struct LocalListener {
    endpoint: LocalEndpoint,
    next: tokio::net::windows::named_pipe::NamedPipeServer,
}

#[cfg(windows)]
impl LocalListener {
    pub fn bind(endpoint: LocalEndpoint) -> Result<Self> {
        let name = endpoint.path().to_string_lossy();
        let next = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&*name)?;
        Ok(Self { endpoint, next })
    }

    pub async fn accept(&mut self) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        self.next.connect().await?;
        let name = self.endpoint.path().to_string_lossy();
        let replacement = tokio::net::windows::named_pipe::ServerOptions::new().create(&*name)?;
        Ok(std::mem::replace(&mut self.next, replacement))
    }
}

pub async fn connect(endpoint: &LocalEndpoint) -> Result<LocalStream> {
    #[cfg(unix)]
    { Ok(tokio::net::UnixStream::connect(endpoint.path()).await?) }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        let name = endpoint.path().to_string_lossy();
        loop {
            match ClientOptions::new().open(&*name) {
                Ok(client) => return Ok(client),
                Err(error) if error.raw_os_error() == Some(231) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}
