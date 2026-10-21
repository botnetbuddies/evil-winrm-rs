//! Development-only WSMan fixture backed by a real local PowerShell process.
//! Authentication and Windows-specific helpers still need the Windows lab.
use anyhow::{Context, Result};
use evil_winrm_rs::{command::quote, session::Session};
use winrm_rs::{AuthMethod, WinrmConfig, WinrmCredentials};

use super::fixture::fixture;
#[tokio::test]
#[ignore = "requires local pwsh and .NET 8 SDK; executes a benign managed assembly"]
async fn managed_assembly_arguments_output_and_cleanup() -> Result<()> {
    let run = async {
        let root = tempfile::tempdir()?;
        let source = root.path().join("source");
        std::fs::create_dir(&source)?;
        std::fs::write(
            source.join("Probe.csproj"),
            include_str!("../fixtures/managed/Probe.csproj"),
        )?;
        std::fs::write(
            source.join("Program.cs"),
            include_str!("../fixtures/managed/Program.cs"),
        )?;
        let build = tokio::process::Command::new("dotnet")
            .args(["build", "--nologo", "--verbosity", "quiet", "--output"])
            .arg(root.path().join("out"))
            .arg(source.join("Probe.csproj"))
            .arg("-p:RestoreIgnoreFailedSources=true")
            .kill_on_drop(true)
            .output()
            .await
            .context(".NET 8 SDK is required for this ignored test")?;
        assert!(
            build.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );
        let assembly = root.path().join("out/EwrParityProbe.dll");
        let (port, server) = fixture().await?;
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
            "Microsoft.PowerShell".into(),
        )
        .await?;
        use clap::Parser;
        let args =
            evil_winrm_rs::cli::Cli::try_parse_from(["test", "-i", "unused", "--no-colors"])?;
        let transcript = root.path().join("transcript.txt");
        let mut log = Some(std::fs::File::create(&transcript)?);
        session.raw("$global:ewrPreviousOut = [Console]::Out; $global:ewrPreviousError = [Console]::Error").await?;
        let command = format!(
            "runexe {} 'a b' '' 'a|b;c' 'héllo 世界'",
            quote(assembly.to_str().unwrap())
        );
        evil_winrm_rs::shell::execute_line(&session, &command, &args, &mut log).await?;
        assert_eq!(
            session.raw("ConvertTo-Json -InputObject ([AppDomain]::CurrentDomain.GetData('ewrManagedArgs')) -Compress").await?.trim(),
            r#"["a b","","a|b;c","héllo 世界"]"#,
        );
        let text = std::fs::read_to_string(&transcript)?;
        assert!(text.contains("stdout:a b||a|b;c|héllo 世界"));
        assert!(text.contains("stderr:probe"));
        evil_winrm_rs::shell::execute_line(
            &session,
            &format!("loaddll {}", quote(assembly.to_str().unwrap())),
            &args,
            &mut log,
        )
        .await?;
        assert_eq!(
            session
                .raw("[EwrParityProbe.Program]::Echo('loaded')")
                .await?
                .trim(),
            "echo:loaded"
        );
        let error = evil_winrm_rs::shell::execute_line(
            &session,
            &format!("runexe {} throw", quote(assembly.to_str().unwrap())),
            &args,
            &mut log,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("managed-test-error"),
            "{error:#}"
        );
        assert_eq!(session.raw("[object]::ReferenceEquals($global:ewrPreviousOut, [Console]::Out) -and [object]::ReferenceEquals($global:ewrPreviousError, [Console]::Error)").await?.trim().to_ascii_lowercase(), "true");
        assert_eq!(session.raw("@(Get-Variable -Scope Global -Name 'ewr*' | Where-Object { $_.Value -is [IO.MemoryStream] }).Count").await?.trim(), "0");
        session.close().await?;
        server.abort();
        Ok(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(90), run)
        .await
        .context("managed assembly integration timed out")?
}
