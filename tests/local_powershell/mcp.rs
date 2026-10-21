//! Development-only WSMan fixture backed by a real local PowerShell process.
//! Authentication and Windows-specific helpers still need the Windows lab.
use anyhow::{Context, Result};
#[cfg(unix)]
use evil_winrm_rs::command::quote;
#[cfg(unix)]
use std::process::Stdio;

use super::fixture::fixture;
use super::mcp_client::McpClient;
#[tokio::test]
#[ignore = "requires local pwsh; tests MCP over HTTP with two real PowerShell runspaces"]
async fn mcp_multiple_sessions_over_http() -> Result<()> {
    let run = async {
        use serde_json::json;
        let (port1, server1) = fixture().await?;
        let (port2, server2) = fixture().await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let http_server = tokio::spawn(async move {
            axum::serve(listener, evil_winrm_rs::mcp::router())
                .await
                .unwrap();
        });
        let mut client = McpClient {
            http: reqwest::Client::new(),
            url: format!("http://127.0.0.1:{port}/mcp"),
            session: None,
            next_id: 0,
        };
        let initialized=client.call("initialize",json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}})).await?;
        assert_eq!(initialized["result"]["serverInfo"]["name"], "evil-winrm-rs");
        let listed = client.call("tools/list", json!({})).await?;
        let tools = listed["result"]["tools"].as_array().unwrap();
        assert!(tools.len() >= 6);
        for name in ["winrm_upload", "winrm_download"] {
            assert!(tools.iter().any(|tool| tool["name"] == name));
        }
        assert_eq!(
            client.tool("winrm_execute", json!({"command":"1"})).await?["result"]["isError"],
            true
        );
        for port in [port1, port2] {
            let result=client.tool("winrm_login",json!({"ip":"127.0.0.1","username":"fixture","password":"fixture","port":port,"auth":"basic","uri":"/custom/wsman","ua":"Ewr-Integration-Test"})).await?;
            assert_ne!(result["result"]["isError"], true, "{result}");
        }
        assert_eq!(
            client.tool("winrm_execute", json!({"command":"1"})).await?["result"]["isError"],
            true
        );
        let result = client.tool("list_sessions", json!({})).await?;
        assert_eq!(
            result["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .lines()
                .count(),
            2
        );
        client
            .tool(
                "winrm_execute",
                json!({"command":"$global:ewrMcp = 42","session_id":1}),
            )
            .await?;
        let result = client
            .tool(
                "winrm_execute",
                json!({"command":"$global:ewrMcp","session_id":1}),
            )
            .await?;
        assert_eq!(
            result["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .trim(),
            "42"
        );
        let root = tempfile::tempdir()?;
        let source = root.path().join("source 世界.bin");
        let remote = root.path().join("remote ' folder").join("uploaded.bin");
        let destination = root.path().join("downloaded.bin");
        std::fs::create_dir_all(remote.parent().unwrap())?;
        let bytes: Vec<_> = (0..180_013).map(|i| (i % 251) as u8).collect();
        std::fs::write(&source, &bytes)?;
        // Ambiguous selection must fail before starting a transfer.
        assert_eq!(
            client
                .tool(
                    "winrm_upload",
                    json!({"local_path":source,"remote_path":remote})
                )
                .await?["result"]["isError"],
            true
        );
        let result = client
            .tool(
                "winrm_upload",
                json!({"session_id":1,"local_path":source,"remote_path":remote}),
            )
            .await?;
        assert_ne!(result["result"]["isError"], true, "{result}");
        let result = client
            .tool(
                "winrm_download",
                json!({"session_id":1,"remote_path":remote,"local_path":destination}),
            )
            .await?;
        assert_ne!(result["result"]["isError"], true, "{result}");
        assert_eq!(std::fs::read(destination)?, bytes);
        client.tool("winrm_logout", json!({"session_id":1})).await?;
        client.tool("winrm_logout", json!({})).await?;
        http_server.abort();
        server1.abort();
        server2.abort();
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(45), run)
        .await
        .context("MCP integration timed out")?
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires local pwsh; exercises real MCP process binding and graceful shutdown"]
async fn mcp_bind_and_shutdown_with_active_sessions() -> Result<()> {
    use serde_json::json;
    let interface =
        std::env::var("WINRM_MCP_TEST_INTERFACE").unwrap_or_else(|_| "127.0.0.2".into());
    for bind in [&interface, &"0.0.0.0".to_owned()] {
        let (port1, server1) = fixture().await?;
        let (port2, server2) = fixture().await?;
        let root = tempfile::tempdir()?;
        let marker = root.path().join("running.txt");
        let listener = std::net::TcpListener::bind((bind.as_str(), 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_evil-winrm-rs"))
            .args(["--mcp", "--mcp-host", bind, "--mcp-port", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let url = format!("http://{interface}:{port}/mcp");
        for _ in 0..100 {
            if tokio::net::TcpStream::connect((interface.as_str(), port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mut client = McpClient {
            http: reqwest::Client::builder().no_proxy().build()?,
            url,
            session: None,
            next_id: 0,
        };
        client.call("initialize", json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shutdown-test","version":"1"}})).await?;
        for port in [port1, port2] {
            let value = client.tool("winrm_login",json!({"ip":"127.0.0.1","port":port,"username":"fixture","password":"fixture","auth":"basic","uri":"/custom/wsman","ua":"Ewr-Integration-Test"})).await?;
            assert_ne!(value["result"]["isError"], true, "{value}");
        }
        let mut processes = Vec::new();
        for id in [1, 2] {
            let value = client
                .tool(
                    "winrm_execute",
                    json!({"session_id":id,"command":"[string]$PID"}),
                )
                .await?;
            processes.push(
                value["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .trim()
                    .parse::<u32>()?,
            );
        }
        let sse = client
            .http
            .get(&client.url)
            .header("Accept", "text/event-stream")
            .header("MCP-Session-Id", client.session.as_ref().unwrap())
            .header("MCP-Protocol-Version", "2025-06-18")
            .send()
            .await?;
        assert!(sse.status().is_success());
        let mut running = McpClient {
            http: client.http.clone(),
            url: client.url.clone(),
            session: client.session.clone(),
            next_id: 100,
        };
        let command = format!(
            "Set-Content -LiteralPath {} -Value running; Start-Sleep -Seconds 60",
            quote(marker.to_str().unwrap())
        );
        let request = tokio::spawn(async move {
            running
                .tool("winrm_execute", json!({"session_id":2,"command":command}))
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !marker.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await?;
        let signaled = tokio::process::Command::new("kill")
            .args(["-INT", &child.id().unwrap().to_string()])
            .status()
            .await?;
        assert!(signaled.success());
        let exited = tokio::time::timeout(std::time::Duration::from_secs(12), child.wait()).await;
        let result = match exited {
            Ok(status) => {
                anyhow::ensure!(status?.success(), "MCP process returned an error");
                Ok(())
            }
            Err(_) => {
                let _ = child.kill().await;
                Err(anyhow::anyhow!(
                    "MCP shutdown hung with an active command and open SSE stream"
                ))
            }
        };
        drop(sse);
        request.abort();
        server1.abort();
        server2.abort();
        result?;
        for pid in processes {
            let status = tokio::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stderr(Stdio::null())
                .status()
                .await?;
            assert!(
                !status.success(),
                "remote PowerShell process {pid} leaked after MCP shutdown"
            );
        }
    }
    Ok(())
}
