use super::fixture::fixture;
use anyhow::{Context, Result};
use evil_winrm_rs::session::Session;
use tokio_util::sync::CancellationToken;
use winrm_rs::{AuthMethod, WinrmConfig, WinrmCredentials};
#[tokio::test]
#[ignore = "requires local pwsh; caps pipeline output and host/error streams before collection"]
async fn output_limits_close_runaway_sessions_but_not_opening() -> Result<()> {
    for script in [
        "1..10000 | ForEach-Object { 'a' * 100 }",
        "1..10000 | ForEach-Object { Write-Host ('h' * 100) }",
        "1..10000 | ForEach-Object { Write-Warning ('w' * 100) }",
    ] {
        let (port, server) = fixture().await?;
        let session = Session::connect(
            "127.0.0.1".into(),
            WinrmConfig {
                port,
                auth_method: AuthMethod::Basic,
                endpoint_path: "/custom/wsman".into(),
                user_agent: Some("Ewr-Integration-Test".into()),
                max_output_bytes: Some(2048),
                ..Default::default()
            },
            WinrmCredentials::new("fixture", "fixture", ""),
            "Microsoft.PowerShell".into(),
        )
        .await?;
        assert_eq!(session.raw("'small'").await?.trim(), "small");
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            session.execute(script, CancellationToken::new()),
        )
        .await
        .context("output limit failed to stop runaway output")?
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("output exceeded"),
            "{error:#}"
        );
        assert!(!session.is_open());
        server.abort();
    }
    Ok(())
}
