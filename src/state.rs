use crate::fsutil::ensure_dir;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallState {
    pub lock_sha256: String,
    pub include_dev: bool,
    pub layout: String,
    #[serde(default)]
    pub link_mode: String,
    pub registry: String,
    pub vx_version: String,
}

pub fn state_path(node_modules: &Path) -> PathBuf {
    node_modules.join(".vx").join("state.json")
}

pub fn load(node_modules: &Path) -> Result<Option<InstallState>> {
    let path = state_path(node_modules);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let state: InstallState =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    Ok(Some(state))
}

pub fn save(node_modules: &Path, state: &InstallState) -> Result<()> {
    let path = state_path(node_modules);
    let dir = path.parent().unwrap();
    ensure_dir(dir)?;

    let mut tmp = tempfile::Builder::new()
        .prefix("vx-state-")
        .tempfile_in(dir)
        .context("create temp file")?;
    let bytes = serde_json::to_vec_pretty(state)?;
    use std::io::Write;
    tmp.as_file_mut().write_all(&bytes)?;
    tmp.as_file_mut().write_all(b"\n")?;
    tmp.as_file().sync_all().ok();
    if path.exists() {
        fs::remove_file(&path).ok();
    }
    tmp.persist(&path)
        .map_err(|e| anyhow!("persist {}: {}", path.display(), e))?;
    Ok(())
}
