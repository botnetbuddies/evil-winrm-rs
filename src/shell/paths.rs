//! Shared local path expansion, file types and configured search directories.
use std::path::{Path, PathBuf};
pub(super) const SCRIPT_EXTENSIONS: &[&str] = &["ps1", "psm1", "psd1"];

pub(super) fn local_path(value: &str) -> PathBuf {
    if value == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from(value));
    }
    if let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        return dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join(rest);
    }
    PathBuf::from(value)
}

pub(super) fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| {
            extensions
                .iter()
                .any(|allowed| ext.eq_ignore_ascii_case(allowed))
        })
}

pub(super) fn resolve_local(file: &str, directory: Option<&Path>) -> PathBuf {
    let path = local_path(file);
    if path.exists() || path.is_absolute() {
        path
    } else {
        local_path(&directory.unwrap_or(Path::new(".")).to_string_lossy()).join(path)
    }
}
