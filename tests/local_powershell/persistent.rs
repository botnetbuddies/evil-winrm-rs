//! Development-only WSMan fixture backed by a real local PowerShell process.
//! Authentication and Windows-specific helpers still need the Windows lab.
use anyhow::{Context, Result};
use evil_winrm_rs::{command::quote, session::Session, transfer};
use tokio_util::sync::CancellationToken;
use winrm_rs::{AuthMethod, WinrmConfig, WinrmCredentials};

use super::fixture::fixture;
#[tokio::test]
#[ignore = "requires local pwsh; exercises actual PowerShell through a WSMan fixture"]
async fn powershell_runspace_and_file_transfers() -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let (port, server) = fixture().await?;
        let config = WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            endpoint_path: "/custom/wsman".into(),
            user_agent: Some("Ewr-Integration-Test".into()),
            ..Default::default()
        };
        let session = Session::connect(
            "127.0.0.1".into(),
            config,
            WinrmCredentials::new("fixture", "fixture", ""),
            "Microsoft.PowerShell".into(),
        )
        .await?;
        assert!(session.loaded_functions().await?.is_empty());
        session.raw("$global:ewrTest = 'héllo 世界'").await?;
        let output = session
            .execute("$global:ewrTest", CancellationToken::new())
            .await?
            .checked()?;
        assert_eq!(output.trim(), "héllo 世界");
        session
            .raw(". { function Test-EwrFunction { 'persisted' } }")
            .await?;
        assert_eq!(session.raw("Test-EwrFunction").await?.trim(), "persisted");
        let large = format!("#{}\n'large-script-ok'", "padding".repeat(40_000));
        assert_eq!(session.raw(&large).await?.trim(), "large-script-ok");
        let root = tempfile::tempdir()?;
        let script = root.path().join("script with spaces.ps1");
        std::fs::write(&script, "function Test-LoadedScript { 'script loaded' }")?;
        use clap::Parser;
        let args =
            evil_winrm_rs::cli::Cli::try_parse_from(["test", "-i", "unused", "--no-colors"])?;
        evil_winrm_rs::shell::execute_line(
            &session,
            &format!("loadps {}", quote(script.to_str().unwrap())),
            &args,
            &mut None,
        )
        .await?;
        assert_eq!(
            session.raw("Test-LoadedScript").await?.trim(),
            "script loaded"
        );
        assert_eq!(
            session.loaded_functions().await?,
            vec!["Test-EwrFunction", "Test-LoadedScript"]
        );
        let menu_path = root.path().join("menu.log");
        let mut menu_log = Some(std::fs::File::create(&menu_path)?);
        evil_winrm_rs::shell::execute_line(&session, "menu", &args, &mut menu_log).await?;
        let menu = std::fs::read_to_string(menu_path)?;
        assert!(menu.contains("upload <local> [remote]"));
        assert!(menu.contains(
            "Functions added in this session\n  Test-EwrFunction\n  Test-LoadedScript\n"
        ));
        assert!(
            !menu.contains("\n  prompt\n"),
            "startup functions leaked into menu: {menu}"
        );
        session
            .raw("Remove-Item Function:Test-EwrFunction,Function:Test-LoadedScript")
            .await?;
        assert!(session.loaded_functions().await?.is_empty());
        std::fs::write(&script, "$ewrRunScriptScope = 'local only'")?;
        evil_winrm_rs::shell::execute_line(
            &session,
            &format!("runps {}", quote(script.to_str().unwrap())),
            &args,
            &mut None,
        )
        .await?;
        assert_eq!(
            session
                .raw("$null -eq (Get-Variable ewrRunScriptScope -ErrorAction SilentlyContinue)")
                .await?
                .trim()
                .to_ascii_lowercase(),
            "true"
        );
        let scripts = root.path().join("scripts");
        std::fs::create_dir(&scripts)?;
        std::fs::write(
            scripts.join("local script.ps1"),
            "$global:ewrLocalScriptRan = 'local script'",
        )?;
        std::fs::write(
            root.path().join("remote-script.ps1"),
            "$global:ewrRemoteScriptRan = 'remote script'",
        )?;
        let search_args = evil_winrm_rs::cli::Cli::try_parse_from([
            "test",
            "-i",
            "unused",
            "--scripts",
            scripts.to_str().unwrap(),
        ])?;
        evil_winrm_rs::shell::execute_line(&session, "'local script.ps1'", &search_args, &mut None)
            .await?;
        assert_eq!(
            session.raw("$global:ewrLocalScriptRan").await?.trim(),
            "local script"
        );
        session
            .raw(&format!(
                "Set-Location {}",
                quote(root.path().to_str().unwrap())
            ))
            .await?;
        evil_winrm_rs::shell::execute_line(
            &session,
            "./remote-script.ps1",
            &search_args,
            &mut None,
        )
        .await?;
        assert_eq!(
            session.raw("$global:ewrRemoteScriptRan").await?.trim(),
            "remote script"
        );
        for size in [0, 147_713] {
            let source = root.path().join(format!("source-{size}.bin"));
            let remote = root.path().join(format!("remote's {size}.bin"));
            let result = root.path().join(format!("result-{size}.bin"));
            let bytes: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            std::fs::write(&source, &bytes)?;
            transfer::upload(&session, &source, Some(remote.to_str().unwrap())).await?;
            transfer::download(&session, remote.to_str().unwrap(), Some(&result)).await?;
            assert_eq!(std::fs::read(&result)?, bytes);
        }
        let tree = root.path().join("tree");
        std::fs::create_dir_all(tree.join("empty"))?;
        std::fs::create_dir_all(tree.join("sub"))?;
        std::fs::write(tree.join("sub/a's 世界.txt"), b"nested contents")?;
        let remote_tree = root.path().join("remote tree");
        transfer::upload(&session, &tree, Some(remote_tree.to_str().unwrap())).await?;
        let downloaded = root.path().join("downloaded tree");
        transfer::download(&session, remote_tree.to_str().unwrap(), Some(&downloaded)).await?;
        assert!(downloaded.join("empty").is_dir());
        assert_eq!(
            std::fs::read(downloaded.join("sub/a's 世界.txt"))?,
            b"nested contents"
        );
        let wildcard = root.path().join("wildcard results");
        transfer::download(
            &session,
            &format!("{}/*.txt", remote_tree.join("sub").display()),
            Some(&wildcard),
        )
        .await?;
        assert_eq!(
            std::fs::read(wildcard.join("a's 世界.txt"))?,
            b"nested contents"
        );
        let failures = session
            .execute(
                "Write-Error 'expected-test-error'",
                CancellationToken::new(),
            )
            .await?;
        assert!(!failures.errors.is_empty());
        let failure = session
            .execute(
                "Write-Output 'before-throw'; throw 'terminating-test-error'",
                CancellationToken::new(),
            )
            .await?;
        assert!(failure.failed);
        assert!(failure.stdout.contains("before-throw"));
        assert!(
            failure
                .errors
                .iter()
                .any(|e| e.contains("terminating-test-error")),
            "{failure:?}"
        );
        let literal = quote("a'; Write-Output injected; '");
        assert_eq!(
            session
                .raw(&format!("Write-Output {literal}"))
                .await?
                .trim(),
            "a'; Write-Output injected; '"
        );
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            token.cancel();
        });
        assert!(
            session
                .execute("Start-Sleep -Seconds 30", cancel)
                .await
                .is_err()
        );
        assert_eq!(
            session.raw("Write-Output 'after-cancel'").await?.trim(),
            "after-cancel"
        );
        session.close().await?;
        server.abort();
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("local PowerShell integration timed out")?
}
