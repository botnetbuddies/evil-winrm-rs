use anyhow::{Context, Result};
pub(super) struct McpClient {
    pub(super) http: reqwest::Client,
    pub(super) url: String,
    pub(super) session: Option<String>,
    pub(super) next_id: u64,
}

impl McpClient {
    pub(super) async fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.next_id += 1;
        let mut request=self.http.post(&self.url).header("Accept","application/json, text/event-stream").header("MCP-Protocol-Version","2025-06-18")
            .json(&serde_json::json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params}));
        if let Some(id) = &self.session {
            request = request.header("MCP-Session-Id", id);
        }
        let response = request.send().await?.error_for_status()?;
        if let Some(id) = response.headers().get("MCP-Session-Id") {
            self.session = Some(id.to_str()?.into());
        }
        let text = response.text().await?;
        if text.trim_start().starts_with('{') {
            return Ok(serde_json::from_str(&text)?);
        }
        text.lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .find_map(|l| serde_json::from_str(l).ok())
            .context("no JSON-RPC response in SSE stream")
    }
    pub(super) async fn tool(
        &mut self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.call(
            "tools/call",
            serde_json::json!({"name":name,"arguments":args}),
        )
        .await
    }
}
