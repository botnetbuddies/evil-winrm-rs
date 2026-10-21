//! Opted-in session/authentication/transfer checks against a real Windows host.
use anyhow::{Context, Result, bail};
use evil_winrm_rs::{command::quote, transfer};
use tokio_util::sync::CancellationToken;
#[path = "support/windows.rs"]
mod windows;
use windows::connect;

#[tokio::test]
#[ignore = "requires an explicitly configured Windows lab"]
async fn authentication_and_persistent_session() -> Result<()> {
    let session = connect().await?;
    let test=async {
        if session.jea {
            assert!(!session.execute("Get-Command",CancellationToken::new()).await?.checked()?.trim().is_empty());
            return Ok(());
        }
        session.raw("$global:ewrLabValue = 'héllo 世界'; function global:Test-EwrLabFunction { 'retained' }").await.context("defining persistent state")?;
        assert_eq!(session.execute("$global:ewrLabValue",CancellationToken::new()).await.context("reading persistent variable")?.checked()?.trim(),"héllo 世界");
        assert_eq!(session.raw("Test-EwrLabFunction").await.context("calling persistent function")?.trim(),"retained");
        let output=session.execute("Clear-Host; Write-Host 'Hello World'; Get-Date -Format yyyy",CancellationToken::new()).await.context("Clear-Host and host output")?;
        assert!(!output.failed && output.errors.is_empty(),"{output:?}");
        assert!(output.stdout.starts_with("Hello World\n"),"{output:?}");
        assert_eq!(output.stdout.matches("Hello World").count(),1);
        assert!(output.information.is_empty(),"{output:?}");
        assert!(output.console.iter().any(|event|matches!(event,evil_winrm_rs::session::ConsoleEvent::ClearScreen)));
        let output=session.execute("Read-Host 'unsupported-input'",CancellationToken::new()).await.context("unsupported host input")?;
        assert!(output.failed || !output.errors.is_empty(),"{output:?}");
        let output=session.execute("Write-Error 'expected lab test error'",CancellationToken::new()).await.context("collecting a nonterminating error")?;
        assert!(!output.errors.is_empty());
        let output=session.execute("Write-Output 'before lab failure'; throw 'expected terminating lab error'",CancellationToken::new()).await.context("collecting a terminating error and preceding output")?;
        assert!(output.failed);
        assert!(output.stdout.contains("before lab failure"));
        assert!(output.errors.iter().any(|e|e.contains("expected terminating lab error")));
        let cancel=CancellationToken::new(); let token=cancel.clone();
        tokio::spawn(async move {tokio::time::sleep(std::time::Duration::from_secs(1)).await;token.cancel();});
        let error=session.execute("Start-Sleep -Seconds 60",cancel).await.expect_err("pipeline should be cancelled");
        assert!(matches!(error.downcast_ref::<psrp_rs::PsrpError>(),Some(psrp_rs::PsrpError::Cancelled|psrp_rs::PsrpError::Stopped)),"unexpected cancellation error: {error:#}");
        assert_eq!(session.raw("'usable after cancel'").await.context("using the session after cancellation")?.trim(),"usable after cancel");
        Ok::<_,anyhow::Error>(())
    }.await;
    let closed = session.close().await;
    test?;
    closed
}

#[tokio::test]
#[ignore = "requires an explicitly configured Windows lab; writes UUID-named temporary files"]
async fn binary_and_directory_transfers() -> Result<()> {
    let session = connect().await?;
    if session.jea {
        let _ = session.close().await;
        bail!("run transfer tests against a full-language endpoint");
    }
    let remote = session
        .raw(&format!(
            "Join-Path ([IO.Path]::GetTempPath()) 'ewr-lab-{}'",
            uuid::Uuid::new_v4()
        ))
        .await?
        .trim()
        .to_owned();
    let test = async {
        session
            .raw(&format!(
                "[IO.Directory]::CreateDirectory({}) | Out-Null",
                quote(&remote)
            ))
            .await?;
        let local = tempfile::tempdir()?;
        for size in [0, 49_153, 1_048_617] {
            let input = local.path().join(format!("input-{size}.bin"));
            let output = local.path().join(format!("output-{size}.bin"));
            let bytes: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            std::fs::write(&input, &bytes)?;
            let target = format!("{remote}\\a's 世界 {size}.bin");
            transfer::upload(&session, &input, Some(&target)).await?;
            transfer::download(&session, &target, Some(&output)).await?;
            assert_eq!(std::fs::read(output)?, bytes);
        }
        let tree = local.path().join("tree");
        std::fs::create_dir_all(tree.join("empty"))?;
        std::fs::create_dir_all(tree.join("sub"))?;
        std::fs::write(tree.join("sub/data.txt"), b"nested contents")?;
        let target = format!("{remote}\\tree");
        transfer::upload(&session, &tree, Some(&target)).await?;
        let result = local.path().join("downloaded");
        transfer::download(&session, &target, Some(&result)).await?;
        assert!(result.join("empty").is_dir());
        assert_eq!(
            std::fs::read(result.join("sub/data.txt"))?,
            b"nested contents"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let _ = session
        .raw(&format!(
            "Remove-Item -LiteralPath {} -Recurse -Force -ErrorAction SilentlyContinue",
            quote(&remote)
        ))
        .await;
    let closed = session.close().await;
    test?;
    closed
}
