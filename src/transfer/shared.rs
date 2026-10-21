use anyhow::{Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use md5::{Digest, Md5};
use serde::Deserialize;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub(super) const CHUNK: usize = 1024 * 1024;
// One input object fits inside the default SOAP envelope after both encodings.
pub(super) const UPLOAD_CHUNK: usize = 72 * 1024;

#[derive(Clone, Copy, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct Options {
    #[serde(default)]
    pub resume: bool,
    #[serde(default)]
    pub compress: bool,
}

pub(super) fn progress(size: u64) -> ProgressBar {
    let bar = ProgressBar::new(size);
    bar.set_style(
        ProgressStyle::with_template("{spinner} {bytes}/{total_bytes} {bytes_per_sec} ETA {eta}")
            .unwrap(),
    );
    bar
}

pub fn remote_basename(path: &str) -> Result<&str> {
    let name = path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("");
    if name.is_empty() || matches!(name, "." | "..") || name.contains([':', '*', '?']) {
        bail!("specify an explicit destination for this remote path");
    }
    Ok(name)
}

/// Validate remote-supplied names using both Windows and local path separators.
pub fn safe_relative(path: &str) -> Result<PathBuf> {
    if path.is_empty() || path.starts_with(['/', '\\']) || path.contains([':', '\0']) {
        bail!("unsafe remote filename: {path:?}");
    }
    let normalized = path.replace('\\', "/");
    if normalized
        .split('/')
        .any(|s| s.is_empty() || s == "." || s == "..")
    {
        bail!("unsafe remote filename: {path:?}");
    }
    let path = Path::new(&normalized);
    if path
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("unsafe remote filename");
    }
    Ok(path.to_path_buf())
}

pub(super) fn file_md5(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Md5::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[derive(Deserialize)]
pub(super) struct FileMetadata {
    pub(super) size: u64,
    pub(super) md5: String,
}

pub(super) fn resume_download_path(local: &Path, hash: &str) -> PathBuf {
    let mut name = local.as_os_str().to_os_string();
    name.push(format!(".{}.part", hash.to_ascii_lowercase()));
    name.into()
}
pub(super) fn file_md5_prefix(path: &Path, length: u64) -> Result<String> {
    let mut input = File::open(path)?.take(length);
    let mut hash = Md5::new();
    let mut buffer = [0; 65536];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
pub(super) fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}
pub(super) fn gunzip(bytes: &[u8], max: usize) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(max as u64 + 1)
        .read_to_end(&mut decoded)?;
    if decoded.len() > max {
        bail!("decompressed chunk exceeds requested length");
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_remote_path_traversal_on_both_platforms() {
        for name in [
            "../secret",
            "..\\secret",
            "/etc/passwd",
            "C:\\secret",
            "foo/../../secret",
            "foo\\..\\secret",
            "\\\\server\\share",
            "",
            "foo//bar",
            ".",
        ] {
            assert!(safe_relative(name).is_err(), "{name}");
        }
        assert_eq!(
            safe_relative("dir\\file with spaces").unwrap(),
            PathBuf::from("dir/file with spaces")
        );
    }
    #[test]
    fn remote_default_filename_uses_windows_separators() {
        assert_eq!(
            remote_basename("C:\\Users\\user\\data.bin").unwrap(),
            "data.bin"
        );
        assert!(remote_basename("C:\\*").is_err());
    }
}
