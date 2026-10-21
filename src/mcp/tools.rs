//! MCP tool adapters delegate session ownership to the local broker.
use super::Server;
impl Server {
    pub(super) fn new(broker: crate::broker::Broker) -> Self {
        Self {
            broker,
            tool_router: Self::tool_router(),
        }
    }
}
use crate::broker::models::{Download, Execute, Login, SessionId, SocksStart, SocksStop, Upload};
use anyhow::{Result, bail};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    tool, tool_router,
};
fn result(value: Result<String>) -> CallToolResult {
    match value {
        Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
        Err(error) => CallToolResult::error(vec![ContentBlock::text(format!("{error:#}"))]),
    }
}

#[tool_router]
impl Server {
    #[tool(description = "Authenticate to a Windows host over WinRM and return a session_id.")]
    async fn winrm_login(&self, Parameters(args): Parameters<Login>) -> CallToolResult {
        result(
            self.broker
                .login(args)
                .await
                .map(|info| format!("{}. session_id={}", info.description, info.session_id)),
        )
    }

    #[tool(description = "List active WinRM sessions and their session_id.")]
    async fn list_sessions(&self) -> String {
        let sessions = self.broker.list().await;
        if sessions.is_empty() {
            "No active sessions.".into()
        } else {
            sessions
                .iter()
                .map(|entry| format!("Session {}: {}", entry.session_id, entry.description))
                .collect::<Vec<_>>()
                .join("\n")
        }
    }

    #[tool(
        description = "Run a command in a persistent WinRM session. session_id is optional when exactly one session is active."
    )]
    async fn winrm_execute(&self, Parameters(args): Parameters<Execute>) -> CallToolResult {
        result(
            async {
                let (_, entry) = self.broker.resolve(args.session_id).await?;
                let _lease = entry.lease.lock().await;
                entry
                    .session
                    .execute(&args.command, self.broker.shutdown.child_token())
                    .await?
                    .checked()
            }
            .await,
        )
    }
    #[tool(
        description = "Upload a local file or directory from the MCP server machine to Windows, using chunked, checksum-verified transfer. session_id is optional with one session."
    )]
    async fn winrm_upload(&self, Parameters(args): Parameters<Upload>) -> CallToolResult {
        result(
            async {
                let (_, entry) = self.broker.resolve(args.session_id).await?;
                let _lease = entry.lease.lock().await;
                if entry.session.jea {
                    bail!("file transfers require a full-language PowerShell endpoint");
                }
                crate::transfer::upload_with_options(
                    &entry.session,
                    std::path::Path::new(&args.local_path),
                    args.remote_path.as_deref(),
                    crate::transfer::Options {
                        resume: args.resume,
                        compress: args.compress,
                    },
                )
                .await?;
                Ok("Upload completed; checksums verified.".into())
            }
            .await,
        )
    }
    #[tool(
        description = "Download a Windows file, directory or wildcard to local_path on the MCP server machine, using checksum-verified transfer. session_id is optional with one session."
    )]
    async fn winrm_download(&self, Parameters(args): Parameters<Download>) -> CallToolResult {
        result(
            async {
                let (_, entry) = self.broker.resolve(args.session_id).await?;
                let _lease = entry.lease.lock().await;
                if entry.session.jea {
                    bail!("file transfers require a full-language PowerShell endpoint");
                }
                crate::transfer::download_with_options(
                    &entry.session,
                    &args.remote_path,
                    Some(std::path::Path::new(&args.local_path)),
                    crate::transfer::Options {
                        resume: args.resume,
                        compress: args.compress,
                    },
                )
                .await?;
                Ok("Download completed; checksums verified.".into())
            }
            .await,
        )
    }
    #[tool(description = "Close a WinRM session and release remote resources.")]
    async fn winrm_logout(&self, Parameters(args): Parameters<SessionId>) -> CallToolResult {
        result(
            async {
                let id = self.broker.logout(args.session_id).await?;
                Ok(format!("WinRM session {id} closed."))
            }
            .await,
        )
    }
    #[tool(
        description = "Start a loopback SOCKS5 CONNECT listener routing through Windows. Each connection uses a separate runspace; names resolve on Windows."
    )]
    async fn winrm_socks_start(&self, Parameters(args): Parameters<SocksStart>) -> CallToolResult {
        result(
            async {
                Ok(serde_json::to_string(
                    &self.broker.start_socks(args).await?,
                )?)
            }
            .await,
        )
    }
    #[tool(description = "Stop a SOCKS listener and close its connections.")]
    async fn winrm_socks_stop(&self, Parameters(args): Parameters<SocksStop>) -> CallToolResult {
        result(
            async {
                self.broker.stop_socks(args).await?;
                Ok("SOCKS listener stopped.".into())
            }
            .await,
        )
    }
    #[tool(description = "List this broker's active SOCKS listeners.")]
    async fn winrm_socks_list(&self) -> String {
        serde_json::to_string(&self.broker.list_socks().await).unwrap()
    }
}
