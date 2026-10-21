//! Development-only WSMan fixture backed by a real local PowerShell process.
//! Authentication and Windows-specific helpers still need the Windows lab.
use anyhow::{Context, Result};
use evil_winrm_rs::session::Session;
use tokio_util::sync::CancellationToken;
use winrm_rs::{AuthMethod, WinrmConfig, WinrmCredentials};

use super::fixture::{fixture, fixture_session, fixture_with_configuration};
#[tokio::test]
#[ignore = "requires local pwsh; validates structured commands under actual NoLanguage policy"]
async fn structured_commands_with_no_language_policy() -> Result<()> {
    let run = async {
        let root = tempfile::tempdir()?;
        let configuration = root.path().join("restricted.pssc");
        std::fs::write(
            &configuration,
            "@{ SchemaVersion = '2.0.0.0'; SessionType = 'RestrictedRemoteServer'; LanguageMode = 'NoLanguage'; VisibleCmdlets = @('Write-Output', 'Get-Date', 'Select-Object', 'Get-Command') }",
        )?;
        // A restricted policy is detected even under the default endpoint name.
        let (probe_port, probe_server) =
            fixture_with_configuration("Microsoft.PowerShell", Some(&configuration)).await?;
        let probe = Session::connect(
            "127.0.0.1".into(),
            WinrmConfig {
                port: probe_port,
                auth_method: AuthMethod::Basic,
                endpoint_path: "/custom/wsman".into(),
                user_agent: Some("Ewr-Integration-Test".into()),
                ..Default::default()
            },
            WinrmCredentials::new("fixture", "fixture", ""),
            "Microsoft.PowerShell".into(),
        )
        .await?;
        let error = probe.raw("1 + 1").await.unwrap_err();
        assert!(probe.jea);
        assert!(format!("{error:#}").contains("JEA"), "{error:#}");
        probe.close().await?;
        probe_server.abort();
        let (port, server) =
            fixture_with_configuration("Ewr.Restricted", Some(&configuration)).await?;
        let session = Session::connect(
            "127.0.0.1".into(),
            WinrmConfig {
                port,
                auth_method: AuthMethod::Basic,
                endpoint_path: "/custom/wsman".into(),
                user_agent: Some("Ewr-Integration-Test".into()),
                ..Default::default()
            },
            WinrmCredentials::new("fixture", "fixture", ""),
            "Ewr.Restricted".into(),
        )
        .await?;
        let result = session
            .execute("Write-Output 'a|b;c'", CancellationToken::new())
            .await?
            .checked()?;
        assert_eq!(result.trim(), "a|b;c");
        let result = session
            .execute(
                "Get-Command -Name Get-Date | Select-Object -Property Name",
                CancellationToken::new(),
            )
            .await?
            .checked()?;
        assert!(result.contains("Get-Date"), "{result}");
        let result = session
            .execute(
                "Write-Output first; Write-Output second",
                CancellationToken::new(),
            )
            .await?
            .checked()?;
        assert_eq!(result.trim(), "first\nsecond");
        let blocked = session
            .execute(
                "Invoke-Expression -Command '1 + 1'",
                CancellationToken::new(),
            )
            .await?;
        assert!(
            blocked.failed || !blocked.errors.is_empty(),
            "endpoint accepted script text: {blocked:?}"
        );
        assert!(session.raw("1 + 1").await.is_err());
        assert_eq!(
            session
                .execute("Write-Output recovered", CancellationToken::new())
                .await?
                .checked()?
                .trim(),
            "recovered"
        );
        session.close().await?;
        server.abort();
        Ok(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), run)
        .await
        .context("NoLanguage integration timed out")?
}

#[tokio::test]
#[ignore = "requires local pwsh; checks actual remoting host callbacks and Clear-Host in compound scripts"]
async fn console_host_clear_and_output_order() -> Result<()> {
    let (port, server) = fixture().await?;
    let session = fixture_session(port, "Microsoft.PowerShell").await?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        // Use the Windows definition so this Linux fixture exercises RawUI,
        // rather than the local platform's external `clear` application.
        session.raw("function global:Clear-Host { $raw=$Host.UI.RawUI; $raw.CursorPosition=@{X=0;Y=0}; $raw.SetBufferContents(@{Top=-1;Bottom=-1;Right=-1;Left=-1},@{Character=' ';ForegroundColor=$raw.ForegroundColor;BackgroundColor=$raw.BackgroundColor}) }").await?;
        let output = session.execute("Clear-Host; Write-Host \"Hello World\"; Get-Date -Format yyyy", CancellationToken::new()).await?;
        assert!(!output.failed && output.errors.is_empty(), "{output:?}");
        assert!(output.stdout.starts_with("Hello World\n"), "{output:?}");
        assert_eq!(output.stdout.matches("Hello World").count(), 1, "{output:?}");
        assert!(output.information.is_empty(), "host output duplicated: {output:?}");
        assert!(matches!(output.console.first(), Some(evil_winrm_rs::session::ConsoleEvent::ClearScreen)));
        let output = session.execute("Write-Output 'before'; $Host.UI.RawUI.CursorPosition=New-Object Management.Automation.Host.Coordinates 0,0; $Host.UI.RawUI.SetBufferContents((New-Object Management.Automation.Host.Rectangle -1,-1,-1,-1),(New-Object Management.Automation.Host.BufferCell ' ',7,0,0)); $Host.UI.Write('no-'); $Host.UI.WriteLine('newline'); Write-Output 'after'", CancellationToken::new()).await?;
        assert!(!output.failed && output.errors.is_empty(), "{output:?}");
        assert_eq!(output.stdout, "before\nno-newline\nafter\n");
        assert!(output.console.iter().any(|event| matches!(event, evil_winrm_rs::session::ConsoleEvent::ClearScreen)));
        assert!(!output.stdout.contains('\x1b'));
        let output = session.execute("Read-Host 'unsupported-input'", CancellationToken::new()).await?;
        assert!(output.failed || !output.errors.is_empty(), "{output:?}");
        assert_eq!(session.raw("'usable-after-clear'").await?.trim(), "usable-after-clear");
        Ok::<_,anyhow::Error>(())
    }).await.context("console host callbacks timed out")?;
    let closed = session.close().await;
    server.abort();
    result?;
    closed
}

#[tokio::test]
#[ignore = "requires local pwsh; verifies policy detection on a named full-language endpoint"]
async fn named_full_language_endpoint_keeps_script_helpers() -> Result<()> {
    let (port, server) = fixture_with_configuration("PowerShell.7", None).await?;
    let session = fixture_session(port, "PowerShell.7").await?;
    assert!(
        !session.jea,
        "endpoint name incorrectly enabled JEA restrictions"
    );
    assert_eq!(session.raw("[Math]::Abs(-42)").await?.trim(), "42");
    session.close().await?;
    server.abort();
    Ok(())
}
