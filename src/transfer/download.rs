//! Download traversal, source snapshots, bounded decompression and atomic replacement.
use super::shared::{
    CHUNK, FileMetadata, Options, file_md5, gunzip, progress, remote_basename,
    resume_download_path, safe_relative,
};
use crate::session::Session;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use std::{
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
#[derive(Deserialize)]
struct RemoteEntry {
    path: String,
    relative: String,
    directory: bool,
}

pub async fn download(session: &Session, remote: &str, local: Option<&Path>) -> Result<()> {
    download_with_options(session, remote, local, Options::default()).await
}
pub async fn download_with_options(
    session: &Session,
    remote: &str,
    local: Option<&Path>,
    options: Options,
) -> Result<()> {
    let has_wildcard = remote.contains(['*', '?']);
    let listing = session
        .raw(&super::scripts::listing(remote, has_wildcard))
        .await?;
    let entries: Vec<RemoteEntry> =
        serde_json::from_str(listing.trim()).context("decoding remote directory listing")?;
    let single_file = !has_wildcard && entries.len() == 1 && !entries[0].directory;
    let destination = match local {
        Some(path) => path.to_path_buf(),
        None if has_wildcard => PathBuf::from("."),
        None => PathBuf::from(remote_basename(remote)?),
    };
    for entry in entries {
        let path = if single_file {
            if destination.is_dir() {
                destination.join(safe_relative(remote_basename(&entry.path)?)?)
            } else {
                destination.clone()
            }
        } else if entry.relative.is_empty() {
            destination.clone()
        } else {
            destination.join(safe_relative(&entry.relative)?)
        };
        if entry.directory {
            std::fs::create_dir_all(&path)?;
        } else {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            download_file(session, &entry.path, &path, options).await?;
        }
    }
    Ok(())
}

async fn download_file(
    session: &Session,
    remote: &str,
    local: &Path,
    options: Options,
) -> Result<()> {
    let metadata = session.raw(&super::scripts::metadata(remote)).await?;
    let metadata: FileMetadata = serde_json::from_str(metadata.trim())?;
    if metadata.md5.len() != 32 || !metadata.md5.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid remote checksum");
    }
    let parent = local
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    let resume_path = resume_download_path(local, &metadata.md5);
    let mut partial = if options.resume {
        if let Ok(info) = std::fs::symlink_metadata(&resume_path)
            && (!info.is_file() || info.file_type().is_symlink())
        {
            bail!("unsafe download staging path");
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        Some(options.open(&resume_path)?)
    } else {
        None
    };
    let bar = progress(metadata.size);
    let mut offset = partial
        .as_ref()
        .map(|f| f.metadata().map(|m| m.len()))
        .transpose()?
        .unwrap_or(0);
    if offset > metadata.size {
        bail!(
            "download partial exceeds source length; remove {} to restart",
            resume_path.display()
        );
    }
    if offset > 0 {
        let remote_hash = session
            .raw(&super::scripts::prefix_hash(remote, offset))
            .await?;
        if !file_md5(&resume_path)?.eq_ignore_ascii_case(remote_hash.trim()) {
            bail!(
                "download partial does not match the source; remove {} to restart",
                resume_path.display()
            );
        }
        partial.as_mut().unwrap().seek(SeekFrom::Start(offset))?;
    }
    bar.set_position(offset);
    while offset < metadata.size {
        let count = (metadata.size - offset).min(CHUNK as u64);
        let data = session
            .raw(&super::scripts::download_chunk(
                remote,
                offset,
                count,
                options.compress,
            ))
            .await?;
        let bytes = B64.decode(data.trim()).context("decoding file chunk")?;
        let bytes = if options.compress {
            gunzip(&bytes, count as usize)?
        } else {
            bytes
        };
        if bytes.is_empty() || bytes.len() as u64 > count {
            bail!("invalid chunk at offset {offset}; destination was not replaced");
        }
        if let Some(file) = &mut partial {
            file.write_all(&bytes)?;
            file.flush()?;
        } else {
            temp.write_all(&bytes)?;
        }
        offset += bytes.len() as u64;
        bar.set_position(offset);
    }
    temp.flush()?;
    if !file_md5(if options.resume {
        &resume_path
    } else {
        temp.path()
    })?
    .eq_ignore_ascii_case(&metadata.md5)
    {
        bail!("download checksum mismatch; destination was not replaced");
    }
    if let Some(file) = partial {
        file.sync_all()?;
        drop(file);
        std::fs::rename(&resume_path, local)?;
    } else {
        temp.persist(local)
            .map_err(|e| e.error)
            .with_context(|| format!("saving {}", local.display()))?;
    }
    bar.finish_with_message("verified");
    Ok(())
}
