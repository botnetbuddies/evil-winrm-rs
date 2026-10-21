use super::{fixture::fixture, mcp_client::McpClient};
use anyhow::{Context, Result};
use evil_winrm_rs::{
    broker::{
        client::Client,
        models::{SessionId, SessionInfo},
    },
    command::quote,
};
use std::{path::Path, process::Stdio, time::Duration};
async fn wait_state(path: &Path) -> Result<()> {
    for _ in 0..100 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("daemon did not publish state")
}
async fn cli(state: &Path, line: &str, extra: &[&str]) -> Result<serde_json::Value> {
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_evil-winrm-rs"))
        .args([
            "--broker",
            "--daemon-state",
            state.to_str().unwrap(),
            "--command",
            line,
            "--json",
        ])
        .args(extra)
        .output()
        .await?;
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "{} / {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    assert!(
        output.status.success(),
        "{value} / {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(value)
}
#[tokio::test]
#[ignore = "requires local pwsh; CLI and MCP share one daemon-owned runspace, including streamed transfers"]
async fn broker_owns_session_across_cli_mcp_cancellation_and_transfers() -> Result<()> {
    let run = async {
        let root = tempfile::tempdir()?;
        let state = root.path().join("broker.json");
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_evil-winrm-rs"))
            .args(["--daemon", "--daemon-state", state.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        wait_state(&state).await?;
        let client = Client::from_file(Some(&state))?;
        let metadata: serde_json::Value = serde_json::from_slice(&std::fs::read(&state)?)?;
        let address = metadata["address"].as_str().unwrap();
        let token = metadata["token"].as_str().unwrap();
        let unauthorized = reqwest::Client::new()
            .get(format!("http://{address}/sessions"))
            .send()
            .await?;
        assert_eq!(unauthorized.status(), 401);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&state)?.permissions().mode() & 0o077, 0);
        }
        let (port, server) = fixture().await?;
        let report = cli(
            &state,
            "$global:brokerCounter=41; function Test-Broker { 'shared-function' }; 'created'",
            &[
                "-i",
                "127.0.0.1",
                "--auth",
                "basic",
                "-u",
                "fixture",
                "--no-pass",
                "--port",
                &port.to_string(),
                "--uri",
                "/custom/wsman",
                "--user-agent",
                "Ewr-Integration-Test",
            ],
        )
        .await?;
        assert!(report["stdout"].as_str().unwrap().contains("created"));
        let sessions: Vec<SessionInfo> = client.get("/sessions").await?;
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            cli(
                &state,
                "$global:brokerCounter+=1; $global:brokerCounter",
                &[]
            )
            .await?["stdout"]
                .as_str()
                .unwrap()
                .trim(),
            "42"
        );
        assert!(
            cli(&state, "menu", &[]).await?["stdout"]
                .as_str()
                .unwrap()
                .contains("Test-Broker")
        );
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse()?);
        let mut mcp = McpClient {
            http: reqwest::Client::builder()
                .default_headers(headers)
                .build()?,
            url: format!("http://{address}/mcp"),
            session: None,
            next_id: 0,
        };
        mcp.call("initialize",serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"broker-test","version":"1"}})).await?;
        let response = mcp
            .tool(
                "winrm_execute",
                serde_json::json!({"command":"$global:brokerCounter+=1; $global:brokerCounter"}),
            )
            .await?;
        assert_eq!(
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .trim(),
            "43"
        );
        let source = root.path().join("source.bin");
        let remote = root.path().join("remote.bin");
        let destination = root.path().join("destination.bin");
        let data: Vec<_> = (0..394_117).map(|i| (i % 251) as u8).collect();
        std::fs::write(&source, &data)?;
        cli(
            &state,
            &format!(
                "upload --resume --compress {} {}",
                quote(source.to_str().unwrap()),
                quote(remote.to_str().unwrap())
            ),
            &[],
        )
        .await?;
        cli(
            &state,
            &format!(
                "download --resume --compress {} {}",
                quote(remote.to_str().unwrap()),
                quote(destination.to_str().unwrap())
            ),
            &[],
        )
        .await?;
        assert_eq!(std::fs::read(destination)?, data);
        #[cfg(unix)]
        {
            let running = tokio::process::Command::new(env!("CARGO_BIN_EXE_evil-winrm-rs"))
                .args([
                    "--broker",
                    "--daemon-state",
                    state.to_str().unwrap(),
                    "--command",
                    "Start-Sleep -Seconds 60",
                    "--json",
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            tokio::time::sleep(Duration::from_millis(250)).await;
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(running.id().unwrap() as i32),
                nix::sys::signal::Signal::SIGINT,
            )?;
            let output =
                tokio::time::timeout(Duration::from_secs(5), running.wait_with_output()).await??;
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stdout).contains("cancelled"));
        }
        assert_eq!(
            cli(&state, "$global:brokerCounter", &[]).await?["stdout"]
                .as_str()
                .unwrap()
                .trim(),
            "43"
        );
        let _: serde_json::Value = client
            .post(
                "/logout",
                &SessionId {
                    session_id: Some(sessions[0].session_id),
                },
            )
            .await?;
        let _: serde_json::Value = client.post("/shutdown", &()).await?;
        tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        assert!(!state.exists());
        server.abort();
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(Duration::from_secs(45), run)
        .await
        .context("broker integration timed out")?
}
#[tokio::test]
#[ignore = "starts a detached local broker; verifies launcher exit, authentication and cleanup"]
async fn detached_broker_survives_launcher_and_stops_cleanly() -> Result<()> {
    let root = tempfile::tempdir()?;
    let state = root.path().join("broker.json");
    let mut launcher = tokio::process::Command::new(env!("CARGO_BIN_EXE_evil-winrm-rs"));
    launcher
        .args([
            "--daemon",
            "--detach",
            "--daemon-state",
            state.to_str().unwrap(),
        ])
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(10), launcher.output())
        .await
        .context("detached launcher retained its output pipes")??;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    wait_state(&state).await?;
    let client = Client::from_file(Some(&state))?;
    let health: serde_json::Value = client.get("/health").await?;
    assert_eq!(health["status"], "ok");
    let _: serde_json::Value = client.post("/shutdown", &()).await?;
    for _ in 0..100 {
        if !state.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("detached daemon did not remove its state")
}
