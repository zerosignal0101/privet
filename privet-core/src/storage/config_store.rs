use std::path::Path;

use crate::config::PrivetConfig;

/// Persistent config store (TOML format).
pub struct ConfigStore {
    path: std::path::PathBuf,
}

impl ConfigStore {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self { path: path.to_owned() })
    }

    pub fn save(&self, config: &PrivetConfig) -> std::io::Result<()> {
        let toml_str = toml::to_string_pretty(config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&self.path, toml_str)
    }

    pub fn load(&self) -> std::io::Result<Option<PrivetConfig>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&self.path)?;
        let config: PrivetConfig = toml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(config))
    }
}
