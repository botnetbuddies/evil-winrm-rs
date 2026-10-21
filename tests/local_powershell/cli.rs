//! Development-only WSMan fixture backed by a real local PowerShell process.
//! Authentication and Windows-specific helpers still need the Windows lab.
use anyhow::{Context, Result};
use evil_winrm_rs::command::quote;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::fixture::{fixture, fixture_session};
#[tokio::test]
#[ignore = "requires local pwsh; checks numeric status without stale values or duplicate execution"]
async fn command_status_and_json_cli() -> Result<()> {
    let run = async {
        let (port, server) = fixture().await?;
        let session = fixture_session(port, "Microsoft.PowerShell").await?;
        for (script, expected) in [
            ("$global:counter=1; Write-Output 'once'", None),
            ("& /bin/sh -c 'exit 37'", Some(37)),
            ("Write-Output 'fresh'", None),
            ("Write-Output 'before-exit'; exit 42", Some(42)),
        ] {
            let output = session
                .execute_with_status(script, false, CancellationToken::new())
                .await?;
            assert_eq!(output.exit_code, expected, "{script}: {output:?}");
            assert!(!output.failed && output.errors.is_empty(), "{output:?}");
            assert!(
                !output.stdout.contains("37") && !output.stdout.contains("42"),
                "status contaminated stdout: {output:?}"
            );
        }
        assert_eq!(session.raw("$global:counter").await?.trim(), "1");
        let output = session
            .execute_with_status(
                "Write-Output 'retained'; throw 'expected-failure'",
                false,
                CancellationToken::new(),
            )
            .await?;
        assert!(
            output.failed && output.stdout.contains("retained") && !output.errors.is_empty(),
            "{output:?}"
        );
        session.close().await?;
        server.abort();

        async fn invoke(
            script: &str,
            remote_code: bool,
        ) -> Result<(std::process::Output, serde_json::Value)> {
            let (port, server) = fixture().await?;
            let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_evil-winrm-rs"));
            command.args([
                "-i",
                "127.0.0.1",
                "--auth",
                "basic",
                "-u",
                "fixture",
                "--password-stdin",
                "--port",
                &port.to_string(),
                "--uri",
                "/custom/wsman",
                "--user-agent",
                "Ewr-Integration-Test",
                "--command",
                script,
                "--json",
            ]);
            if remote_code {
                command.arg("--exit-code");
            }
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b" fixture password \r\n")
                .await?;
            let result = child.wait_with_output().await?;
            server.abort();
            let value: serde_json::Value =
                serde_json::from_slice(&result.stdout).with_context(|| {
                    format!(
                        "invalid JSON: {} / {}",
                        String::from_utf8_lossy(&result.stdout),
                        String::from_utf8_lossy(&result.stderr)
                    )
                })?;
            assert!(!String::from_utf8_lossy(&result.stderr).contains("fixture password"));
            Ok((result, value))
        }
        let (process, json) = invoke("Write-Output 'héllo 世界'; Write-Warning 'warn'; Write-Verbose 'verbose' -Verbose; Write-Information 'info' -InformationAction Continue", false).await?;
        assert!(process.status.success(), "{json:?}");
        assert!(json["stdout"].as_str().unwrap().contains("héllo 世界"));
        assert_eq!(json["exit_code"], 0);
        assert_eq!(json["success"], true);
        assert!(!json["warnings"].as_array().unwrap().is_empty());
        assert!(!json["verbose"].as_array().unwrap().is_empty());
        let (process, json) = invoke("Write-Output 'before'; exit 42", true).await?;
        assert_eq!(process.status.code(), Some(42));
        assert_eq!(json["exit_code"], 42);
        assert_eq!(json["success"], false);
        assert!(json["stdout"].as_str().unwrap().contains("before"));
        let (process, json) = invoke("& /bin/sh -c 'exit 37'", false).await?;
        assert_eq!(process.status.code(), Some(1));
        assert_eq!(json["exit_code"], 37);
        let (process, json) =
            invoke("Write-Output 'retained'; throw 'expected-failure'", true).await?;
        assert_eq!(process.status.code(), Some(1));
        assert!(json["stdout"].as_str().unwrap().contains("retained"));
        assert!(!json["errors"].as_array().unwrap().is_empty());
        let (process, json) = invoke("menu", false).await?;
        assert!(process.status.success());
        assert!(json["stdout"].as_str().unwrap().contains("Shell commands"));
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(90), run)
        .await
        .context("status/JSON integration timed out")?
}

#[tokio::test]
#[ignore = "requires local pwsh; exercises startup settings, password files and three script sources"]
async fn startup_settings_and_script_sources_cli() -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("working ' 世界");
        std::fs::create_dir(&directory)?;
        let password = root.path().join("password");
        std::fs::write(&password, " fixture password \r\n")?;
        let script = r#"param([string]$Name, [string]$Empty, [switch]$Flag)
Write-Output ('args:' + $Name + ':' + $Empty.Length + ':' + $Flag)
Write-Output ('env:' + $env:EWR_SCRIPT_TEST)
Write-Output ('cwd:' + $pwd.Path)
"#;
        let file = root.path().join("script file.ps1");
        std::fs::write(&file, script)?;
        // URL input also exercises BOM-aware UTF-16 decoding.
        let mut encoded = vec![0xff, 0xfe];
        encoded.extend(script.encode_utf16().flat_map(u16::to_le_bytes));
        let app = axum::Router::new().route(
            "/script.ps1",
            axum::routing::get(move || {
                let encoded = encoded.clone();
                async move { encoded }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!(
            "http://127.0.0.1:{}/script.ps1",
            listener.local_addr()?.port()
        );
        let url_server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        for source in [file.to_str().unwrap(), "-", &url] {
            let (port, server) = fixture().await?;
            let line = format!(
                "runps {} -Name 'a; ''quote'' 世界' -Empty '' -Flag:$true",
                quote(source)
            );
            let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_evil-winrm-rs"))
                .args([
                    "-i",
                    "127.0.0.1",
                    "--auth",
                    "basic",
                    "-u",
                    "fixture",
                    "--password-file",
                    password.to_str().unwrap(),
                    "--port",
                    &port.to_string(),
                    "--uri",
                    "/custom/wsman",
                    "--user-agent",
                    "Ewr-Integration-Test",
                    "--command",
                    &line,
                    "--json",
                    "--cd",
                    directory.to_str().unwrap(),
                    "--env",
                    "EWR_SCRIPT_TEST=value; ' 世界=ok",
                    "--operation-timeout",
                    "2",
                    "--connect-timeout",
                    "3",
                    "--idle-timeout",
                    "60",
                    "--max-envelope",
                    "131072",
                    "--retries",
                    "1",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            if source == "-" {
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(script.as_bytes())
                    .await?;
            } else {
                drop(child.stdin.take());
            }
            let result = child.wait_with_output().await?;
            server.abort();
            let json: serde_json::Value = serde_json::from_slice(&result.stdout)?;
            assert!(
                result.status.success(),
                "source {source}: {json} / {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let output = json["stdout"].as_str().unwrap();
            for expected in [
                "args:a; 'quote' 世界:0:True",
                "env:value; ' 世界=ok",
                directory.to_str().unwrap(),
            ] {
                assert!(output.contains(expected), "{source}: {json}");
            }
            assert!(!String::from_utf8_lossy(&result.stderr).contains("fixture password"));
        }
        url_server.abort();
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("startup/script-source integration timed out")?
}
