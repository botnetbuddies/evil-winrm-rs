//! Upload traversal, persistent staging, input streaming and checksum promotion.
use super::shared::{
    FileMetadata, Options, UPLOAD_CHUNK, file_md5, file_md5_prefix, gzip, progress,
};
use crate::{command::quote, session::Session};
use anyhow::{Context, Result, bail};
use md5::{Digest, Md5};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};
pub async fn upload(session: &Session, local: &Path, remote: Option<&str>) -> Result<()> {
    upload_with_options(session, local, remote, Options::default()).await
}
pub async fn upload_with_options(
    session: &Session,
    local: &Path,
    remote: Option<&str>,
    options: Options,
) -> Result<()> {
    let remote = match remote {
        Some(p) => p.to_owned(),
        None => local
            .file_name()
            .context("local path has no filename")?
            .to_string_lossy()
            .into_owned(),
    };
    let mut pending = vec![(local.to_path_buf(), remote)];
    while let Some((local, remote)) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&local)
            .with_context(|| format!("reading {}", local.display()))?;
        if metadata.is_symlink() {
            bail!("symbolic links are not transferred: {}", local.display());
        }
        if metadata.is_dir() {
            session
                .raw(&format!(
                    "[IO.Directory]::CreateDirectory({}) | Out-Null",
                    quote(&remote)
                ))
                .await?;
            for entry in std::fs::read_dir(local)? {
                let entry = entry?;
                let child = session
                    .raw(&format!(
                        "Join-Path -Path {} -ChildPath {}",
                        quote(&remote),
                        quote(&entry.file_name().to_string_lossy()),
                    ))
                    .await?
                    .trim()
                    .to_owned();
                pending.push((entry.path(), child));
            }
        } else {
            upload_file(session, &local, &remote, options).await?;
        }
    }
    Ok(())
}

async fn upload_file(
    session: &Session,
    local: &Path,
    remote: &str,
    options: Options,
) -> Result<()> {
    let filename = local
        .file_name()
        .context("missing filename")?
        .to_string_lossy();
    let remote = session
        .raw(&super::scripts::destination(remote, &filename))
        .await?
        .trim()
        .to_owned();
    let full_hash = options.resume.then(|| file_md5(local)).transpose()?;
    let staging = format!(
        "{remote}.{}.part",
        full_hash
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    );
    let offset = if options.resume {
        let state = session
            .raw(&super::scripts::partial_state(&staging))
            .await?;
        let state: FileMetadata = serde_json::from_str(state.trim())?;
        let size = std::fs::metadata(local)?.len();
        if state.size > size
            || (state.size > 0
                && !file_md5_prefix(local, state.size)?.eq_ignore_ascii_case(&state.md5))
        {
            bail!("upload partial does not match the source; remove {staging} to restart");
        }
        state.size
    } else {
        0
    };
    let stream = format!("ewrUpload{}", uuid::Uuid::new_v4().simple());
    let task = async {
        let mut file = File::open(local)?;
        let size = file.metadata()?.len();
        let bar = progress(size);
        bar.set_position(offset);
        file.seek(SeekFrom::Start(offset))?;
        let (sender, input) = tokio::sync::mpsc::channel(2);
        let script = super::scripts::upload(&stream, &staging, offset, size, options);
        let send = async {
            let mut hash = Md5::new();
            let mut buffer = vec![0; UPLOAD_CHUNK];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
                let bytes = if options.compress {
                    gzip(&buffer[..n])?
                } else {
                    buffer[..n].to_vec()
                };
                sender
                    .send(psrp_rs::PsValue::Bytes(bytes))
                    .await
                    .context("upload input pipeline closed")?;
                bar.inc(n as u64);
            }
            drop(sender);
            Ok::<_, anyhow::Error>(hex::encode(hash.finalize()))
        };
        // Drain the remote stop acknowledgement before cleanup and retain its
        // cancellation error rather than the producer's closed-channel error.
        let (actual, expected) = tokio::join!(session.raw_with_input(&script, input), send);
        let actual = actual?;
        let expected = full_hash.as_deref().unwrap_or(&expected?).to_owned();
        if !expected.eq_ignore_ascii_case(actual.trim()) {
            bail!("upload checksum mismatch; destination was not replaced");
        }
        session
            .raw(&format!(
                "Move-Item -LiteralPath {} -Destination {} -Force -ErrorAction Stop",
                quote(&staging),
                quote(&remote)
            ))
            .await?;
        bar.finish_with_message("verified");
        Ok(())
    }
    .await;
    if task.is_err() {
        let remove_partial = if options.resume {
            String::new()
        } else {
            format!(
                "Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue",
                quote(&staging)
            )
        };
        let cleanup = format!(
            "if ($global:{stream}) {{ $global:{stream}.Dispose(); Remove-Variable -Name {stream} -Scope Global -ErrorAction SilentlyContinue }}; {remove_partial}"
        );
        let _ = session.raw(&cleanup).await;
    }
    task
}
