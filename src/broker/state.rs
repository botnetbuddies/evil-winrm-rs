//! Broker discovery uses a private capability file, never credentials in process arguments.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct State {
    pub address: SocketAddr,
    pub token: String,
    pub pid: u32,
}
pub(super) fn path(selected: Option<&Path>) -> PathBuf {
    selected.map(Path::to_path_buf).unwrap_or_else(|| {
        dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("evil-winrm-rs/broker.json")
    })
}
pub(super) fn read(path: &Path) -> Result<State> {
    let metadata =
        std::fs::symlink_metadata(path).context("reading broker state; start --daemon first")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("broker state must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("broker state permissions must exclude other users (chmod 600)");
        }
    }
    let state: State = serde_json::from_slice(&std::fs::read(path)?)?;
    if !state.address.ip().is_loopback() {
        bail!("broker state must name a loopback address");
    }
    Ok(state)
}
pub(super) fn save(path: &Path, state: &State) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.flush()?;
    file.persist_noclobber(path).map_err(|_|anyhow::anyhow!("broker state already exists; verify that the previous daemon has stopped before removing it"))?;
    Ok(())
}
pub(super) fn remove_owned(path: &Path, state: &State) {
    if read(path).is_ok_and(|current| current.token == state.token) {
        let _ = std::fs::remove_file(path);
    }
}
